package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	// DefaultMaxToolRounds caps consecutive MCP tool-calling rounds per user turn.
	DefaultMaxToolRounds = 8
	maxAutoTitleRunes    = 60
	maxErrorBodyBytes    = 256 * 1024

	headerProviderType  = "X-Headlamp-Provider-Type"
	headerUpstreamModel = "X-Headlamp-Upstream-Model"
)

// GuardrailInspector optionally inspects user chat input before persistence so blocked
// secrets never hit chat_messages and redacted content is persisted cleanly.
type GuardrailInspector interface {
	InspectText(ctx context.Context, text string) (action, redacted, reason string, err error)
}

// messageDeleter is an optional store capability used to roll back an orphaned user
// message if Round 0 fails at proxy.Gateway before any assistant output or tool call occurs.
type messageDeleter interface {
	DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error
}

// Authorizer checks which models a Principal may list and invoke.
// Satisfied directly by *policy.Evaluator.
type Authorizer interface {
	FilterModels(ctx context.Context, p *auth.Principal, models []string) ([]string, error)
	IsModelDenied(ctx context.Context, p *auth.Principal, model string) (bool, string, error)
}

// ToolSpec describes a single authorized MCP tool available to Web Chat.
type ToolSpec struct {
	Server      string          `json:"server,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// ServerTools describes an enabled MCP server and the caller's authorized tools on it.
type ServerTools struct {
	Name      string     `json:"name"`
	Transport string     `json:"transport"`
	Enabled   bool       `json:"enabled"`
	Tools     []ToolSpec `json:"tools"`
	Error     string     `json:"error,omitempty"`
}

// ToolResult captures the outcome of an MCP tool execution.
type ToolResult struct {
	Result     string `json:"result"`
	IsError    bool   `json:"is_error"`
	DurationMS int64  `json:"duration_ms"`
}

// MCPBridge decouples internal/chat from internal/mcp for tool discovery and execution.
type MCPBridge interface {
	ListAuthorizedTools(ctx context.Context, p *auth.Principal, serverNames []string) ([]ServerTools, error)
	CallTool(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error)
}

// ChatModel describes a model selectable in Team Web Chat (GET /api/v1/chat/models).
type ChatModel struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	ProviderType string `json:"provider_type"`
	IsAlias      bool   `json:"is_alias"`
}

// SendMessageRequest is the payload for POST /api/v1/chat/sessions/{id}/messages.
type SendMessageRequest struct {
	Content    string   `json:"content"`
	Model      string   `json:"model,omitempty"`
	MCPServers []string `json:"mcp_servers,omitempty"`
}

// Config configures the Web Chat Service.
type Config struct {
	Store         store.Store
	Authorizer    Authorizer
	Pricing       *metering.PricingTable
	Gateway       http.Handler
	MCP           MCPBridge
	Guardrails    GuardrailInspector
	MaxToolRounds int
	Logf          func(format string, args ...any)
}

type sessionLockEntry struct {
	sem  chan struct{}
	refs int
}

// Service orchestrates Team Web Chat sessions, model listing, MCP tool execution,
// and zero-bypass LLM streaming through Headlamp's own proxy.Gateway.
type Service struct {
	store          store.Store
	authorizer     Authorizer
	pricing        *metering.PricingTable
	gateway        http.Handler
	mcp            MCPBridge
	guardrails     GuardrailInspector
	maxToolRounds  int
	logf           func(format string, args ...any)
	sessionLocksMu sync.Mutex
	sessionLocks   map[string]*sessionLockEntry
}

// NewService constructs a Chat Service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("chat: store is required")
	}
	if cfg.Gateway == nil {
		return nil, errors.New("chat: gateway handler is required")
	}
	maxRounds := cfg.MaxToolRounds
	if maxRounds <= 0 {
		maxRounds = DefaultMaxToolRounds
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Service{
		store:         cfg.Store,
		authorizer:    cfg.Authorizer,
		pricing:       cfg.Pricing,
		gateway:       cfg.Gateway,
		mcp:           cfg.MCP,
		guardrails:    cfg.Guardrails,
		maxToolRounds: maxRounds,
		logf:          logf,
		sessionLocks:  make(map[string]*sessionLockEntry),
	}, nil
}

// lockSession serializes turns for a single (subject, sessionID) pair and cleans up
// idle entries via reference counting so the map never leaks memory.
func (s *Service) lockSession(ctx context.Context, key string) (func(), error) {
	s.sessionLocksMu.Lock()
	if s.sessionLocks == nil {
		s.sessionLocks = make(map[string]*sessionLockEntry)
	}
	entry, ok := s.sessionLocks[key]
	if !ok {
		entry = &sessionLockEntry{sem: make(chan struct{}, 1)}
		s.sessionLocks[key] = entry
	}
	entry.refs++
	s.sessionLocksMu.Unlock()

	select {
	case entry.sem <- struct{}{}:
		return func() {
			<-entry.sem
			s.sessionLocksMu.Lock()
			entry.refs--
			if entry.refs == 0 {
				delete(s.sessionLocks, key)
			}
			s.sessionLocksMu.Unlock()
		}, nil
	case <-ctx.Done():
		s.sessionLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.sessionLocks, key)
		}
		s.sessionLocksMu.Unlock()
		return nil, ctx.Err()
	}
}

// ListModels returns all enabled provider models and virtual aliases authorized for p
// across OpenAI, Anthropic, Ollama, and Gemini.
func (s *Service) ListModels(ctx context.Context, p *auth.Principal) ([]ChatModel, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}

	providers, err := s.store.ListProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("chat: list providers: %w", err)
	}
	byName := make(map[string]store.Provider, len(providers))
	for _, prov := range providers {
		if prov.Enabled {
			byName[prov.Name] = prov
		}
	}

	routes, err := s.store.ListModelRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("chat: list model routes: %w", err)
	}

	type catalogEntry struct {
		model      ChatModel
		candidates []routeCandidate
	}

	seen := make(map[string]struct{})
	var catalog []catalogEntry

	for _, r := range routes {
		if !r.Enabled || strings.TrimSpace(r.Alias) == "" {
			continue
		}
		var cands []routeCandidate
		if primary, ok := byName[r.ProviderName]; ok {
			cands = append(cands, routeCandidate{provider: primary, upstreamModel: r.UpstreamModel})
		}
		for _, fb := range r.Fallbacks {
			if fp, ok := byName[fb.Provider]; ok {
				cands = append(cands, routeCandidate{provider: fp, upstreamModel: fb.Model})
			}
		}
		if len(cands) == 0 {
			continue
		}
		if _, dup := seen[r.Alias]; dup {
			continue
		}
		seen[r.Alias] = struct{}{}
		catalog = append(catalog, catalogEntry{
			model: ChatModel{
				ID:           r.Alias,
				Provider:     cands[0].provider.Name,
				ProviderType: cands[0].provider.Type,
				IsAlias:      true,
			},
			candidates: cands,
		})
	}

	for _, prov := range providers {
		if !prov.Enabled {
			continue
		}
		for _, m := range prov.Models {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			id := prov.Name + "/" + m
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			catalog = append(catalog, catalogEntry{
				model: ChatModel{
					ID:           id,
					Provider:     prov.Name,
					ProviderType: prov.Type,
					IsAlias:      false,
				},
				candidates: []routeCandidate{{provider: prov, upstreamModel: m}},
			})
		}
	}

	sort.Slice(catalog, func(i, j int) bool {
		return catalog[i].model.ID < catalog[j].model.ID
	})

	if len(catalog) == 0 {
		return []ChatModel{}, nil
	}

	if s.authorizer == nil {
		out := make([]ChatModel, len(catalog))
		for i, entry := range catalog {
			out[i] = entry.model
		}
		return out, nil
	}

	ids := make([]string, len(catalog))
	for i, entry := range catalog {
		ids[i] = entry.model.ID
	}
	allowedIDs, err := s.authorizer.FilterModels(ctx, p, ids)
	if err != nil {
		return nil, fmt.Errorf("chat: filter models: %w", err)
	}
	allowedSet := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowedSet[id] = struct{}{}
	}

	out := make([]ChatModel, 0, len(allowedIDs))
	for _, entry := range catalog {
		if _, ok := allowedSet[entry.model.ID]; !ok {
			continue
		}
		if entry.model.IsAlias {
			hasAllowedCandidate := false
			for _, cand := range entry.candidates {
				target := cand.provider.Name + "/" + cand.upstreamModel
				denied, _, err := s.authorizer.IsModelDenied(ctx, p, target)
				if err != nil {
					return nil, fmt.Errorf("chat: check alias candidate deny %q: %w", target, err)
				}
				if !denied {
					hasAllowedCandidate = true
					break
				}
			}
			if !hasAllowedCandidate {
				continue
			}
		}
		out = append(out, entry.model)
	}
	return out, nil
}

// ListMCPServers lists enabled MCP servers and the caller's authorized tools via MCPBridge.
func (s *Service) ListMCPServers(ctx context.Context, p *auth.Principal) ([]ServerTools, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}
	if s.mcp == nil {
		return []ServerTools{}, nil
	}
	servers, err := s.mcp.ListAuthorizedTools(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	if servers == nil {
		return []ServerTools{}, nil
	}
	for i := range servers {
		if servers[i].Tools == nil {
			servers[i].Tools = []ToolSpec{}
		}
	}
	return servers, nil
}

// StreamMessage appends a user turn to sessionID, streams the assistant response (and any
// MCP tool-calling rounds) through Headlamp's proxy.Gateway as SSE events, and persists
// both messages to storage. Errors returned before SSE headers are written (such as
// store.ErrNotFound or invalid input) allow HTTP callers to respond with JSON 400/404.
func (s *Service) StreamMessage(ctx context.Context, w http.ResponseWriter, p *auth.Principal, sessionID string, req SendMessageRequest) error {
	if p == nil {
		return auth.ErrUnauthenticated
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		return errors.New("chat: message content is required")
	}

	unlockSession, err := s.lockSession(ctx, p.Subject+"\x00"+sessionID)
	if err != nil {
		return err
	}
	defer unlockSession()

	session, err := s.store.GetChatSession(ctx, p.Subject, sessionID)
	if err != nil {
		return err
	}

	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = strings.TrimSpace(session.Model)
	}
	if model == "" {
		return errors.New("chat: session model is required")
	}

	// Pre-persist guardrail inspection: prevent raw secrets from being stored in chat_messages
	// (or session titles) and ensure redacted prompts are stored in redacted form.
	// Round 0 still forwards rawUserContent to proxy.Gateway so guardrail.Engine fires
	// guardrail.triggered webhooks and records usage_logs guardrail telemetry once.
	rawUserContent := req.Content
	persistedContent := req.Content
	var (
		preBlocked  bool
		blockReason string
	)
	if s.guardrails != nil {
		action, redacted, reason, gErr := s.guardrails.InspectText(ctx, rawUserContent)
		if gErr != nil {
			return fmt.Errorf("chat: inspect message guardrails: %w", gErr)
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "block":
			preBlocked = true
			blockReason = strings.TrimSpace(reason)
		case "redact", "modify":
			if redacted != "" {
				persistedContent = redacted
			}
		}
	}

	if preBlocked {
		// Never persist blocked raw secrets to chat_messages or session.Title, and skip
		// message_start. Still dispatch Round 0 through proxy.Gateway so guardrail.Engine
		// emits the guardrail.triggered webhook and writes the blocked usage_logs entry +
		// [BLOCKED BY GUARDRAIL] audit payload stub before returning the SSE error.
		errType, errMsg := s.dispatchBlockedRound0(ctx, p, model, session.SystemPrompt, rawUserContent, blockReason)
		emitter := startSSE(w)
		_ = emitter.Emit("error", map[string]string{
			"type":    errType,
			"message": errMsg,
		})
		return nil
	}

	mcpServers := session.MCPServers
	sessionChanged := false
	if req.Model != "" && model != session.Model {
		session.Model = model
		sessionChanged = true
	}
	if req.MCPServers != nil {
		cleaned := cleanStringSlice(req.MCPServers)
		if !slices.Equal(cleaned, session.MCPServers) {
			session.MCPServers = cleaned
			mcpServers = cleaned
			sessionChanged = true
		}
	}

	trimmedTitle := strings.TrimSpace(session.Title)
	if trimmedTitle == "" || strings.EqualFold(trimmedTitle, "New Chat") {
		session.Title = deriveSessionTitle(strings.TrimSpace(persistedContent))
		sessionChanged = true
	}

	if sessionChanged {
		updated, err := s.store.UpdateChatSession(ctx, p.Subject, *session)
		if err != nil {
			return fmt.Errorf("chat: update session: %w", err)
		}
		session = updated
	}
	if session.MCPServers == nil {
		session.MCPServers = []string{}
	}

	history, err := s.store.ListChatMessages(ctx, p.Subject, session.ID)
	if err != nil {
		return fmt.Errorf("chat: list history: %w", err)
	}

	userMsg, err := s.store.InsertChatMessage(ctx, p.Subject, store.ChatMessage{
		ID:        uuid.NewString(),
		SessionID: session.ID,
		Role:      "user",
		Content:   persistedContent,
		Model:     model,
	})
	if err != nil {
		return fmt.Errorf("chat: insert user message: %w", err)
	}

	// Commit SSE headers and emit initial message_start frame.
	emitter := startSSE(w)
	_ = emitter.Emit("message_start", map[string]any{
		"user_message": userMsg,
		"session":      session,
	})

	// Discover authorized MCP tools for the session's attached servers.
	tools, toolLookup := s.resolveMCPTools(ctx, p, mcpServers)

	// Decide whether to dispatch via OpenAI /v1/chat/completions or pure Gemini endpoint.
	dispatch := s.resolveDispatchInfo(ctx, model)

	var (
		outcome *turnOutcome
		runErr  error
	)
	if dispatch.useGemini {
		outcome, runErr = s.runGeminiChatLoop(ctx, p, model, session.SystemPrompt, history, persistedContent, rawUserContent, tools, toolLookup, emitter)
	} else {
		outcome, runErr = s.runOpenAIChatLoop(ctx, p, model, session.SystemPrompt, history, persistedContent, rawUserContent, tools, toolLookup, emitter)
	}

	if runErr != nil {
		hasAssistantProgress := outcome != nil && (outcome.content != "" || len(outcome.toolEvents) > 0)
		if !hasAssistantProgress {
			// Roll back the orphaned user message when Round 0 fails (e.g. policy 403,
			// sync_review webhook block, quota 429, or pre-delta failure) so the session
			// is never permanently poisoned by an unanswered/blocked turn.
			s.rollbackOrphanUserMessage(p.Subject, session.ID, userMsg.ID)
		}

		// If canceled by caller (Stop button), persist any partial output already streamed.
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) || ctx.Err() != nil {
			if hasAssistantProgress {
				s.persistAssistantMessage(p.Subject, session.ID, model, dispatch, outcome)
			}
			return nil
		}

		// Gateway or stream error: emit structured SSE error event.
		errType, errMsg := classifyStreamError(runErr)
		_ = emitter.Emit("error", map[string]string{
			"type":    errType,
			"message": errMsg,
		})
		// If partial content or tool executions happened before the error, persist them so history stays intact.
		if hasAssistantProgress {
			s.persistAssistantMessage(p.Subject, session.ID, model, dispatch, outcome)
		}
		return nil
	}

	assistantMsg, persistErr := s.persistAssistantMessage(p.Subject, session.ID, model, dispatch, outcome)
	if persistErr != nil {
		s.logf("chat: persist assistant message for session %s failed: %v", session.ID, persistErr)
		_ = emitter.Emit("error", map[string]string{
			"type":    "server_error",
			"message": "failed to save assistant response",
		})
		return nil
	}

	if ctx.Err() == nil {
		_ = emitter.Emit("message_done", map[string]any{
			"assistant_message": assistantMsg,
		})
	}
	return nil
}

func startSSE(w http.ResponseWriter) *sseEmitter {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	return newSSEEmitter(w)
}

// dispatchBlockedRound0 forwards a pre-blocked prompt through proxy.Gateway on Round 0
// so guardrail.Engine emits the guardrail.triggered async webhook and logs the blocked
// usage_logs + [BLOCKED BY GUARDRAIL] audit payload stub. As defense-in-depth, if a
// custom/test Gateway without guardrails returns 2xx, the response stream is discarded
// immediately and guardrail_blocked is still returned.
func (s *Service) dispatchBlockedRound0(
	ctx context.Context,
	p *auth.Principal,
	model string,
	systemPrompt string,
	rawUserContent string,
	preBlockReason string,
) (errType, errMsg string) {
	fallbackMsg := strings.TrimSpace(preBlockReason)
	if fallbackMsg == "" {
		fallbackMsg = "message blocked by guardrail policy"
	}

	dispatch := s.resolveDispatchInfo(ctx, model)
	var (
		path     string
		reqBytes []byte
		err      error
	)
	if dispatch.useGemini {
		path = "/gemini/v1beta/models/" + strings.TrimPrefix(model, "/") + ":streamGenerateContent?alt=sse"
		reqPayload := map[string]any{
			"contents": buildGeminiContents(nil, rawUserContent),
		}
		if sp := strings.TrimSpace(systemPrompt); sp != "" {
			reqPayload["systemInstruction"] = map[string]any{
				"parts": []map[string]string{{"text": sp}},
			}
		}
		reqBytes, err = json.Marshal(reqPayload)
	} else {
		path = "/v1/chat/completions"
		reqPayload := map[string]any{
			"model":    model,
			"messages": buildOpenAIMessages(systemPrompt, nil, rawUserContent),
			"stream":   true,
			"stream_options": map[string]any{
				"include_usage": true,
			},
		}
		reqBytes, err = json.Marshal(reqPayload)
	}
	if err != nil {
		return "guardrail_blocked", fallbackMsg
	}

	_, _, closeStream, gwErr := s.invokeGatewayStream(ctx, p, path, reqBytes)
	if gwErr == nil {
		closeStream()
		return "guardrail_blocked", fallbackMsg
	}

	var httpErr *gatewayHTTPError
	if errors.As(gwErr, &httpErr) {
		msg := strings.TrimSpace(httpErr.Message)
		if msg == "" {
			msg = fallbackMsg
		}
		if httpErr.Type == "guardrail_blocked" || httpErr.StatusCode == http.StatusBadRequest {
			return "guardrail_blocked", msg
		}
		if httpErr.Type != "" {
			return httpErr.Type, msg
		}
		return "guardrail_blocked", msg
	}
	return "guardrail_blocked", fallbackMsg
}

func (s *Service) rollbackOrphanUserMessage(subject, sessionID, messageID string) {
	del, ok := s.store.(messageDeleter)
	if !ok || messageID == "" {
		return
	}
	delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := del.DeleteChatMessage(delCtx, subject, sessionID, messageID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logf("chat: rollback orphan user message %s for session %s failed: %v", messageID, sessionID, err)
	}
}
