package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

const (
	// DefaultMaxToolRounds caps consecutive MCP tool-calling rounds per user turn.
	DefaultMaxToolRounds = 8
	maxAutoTitleRunes    = 60
	maxErrorBodyBytes    = 256 * 1024
)

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
	MaxToolRounds int
	Logf          func(format string, args ...any)
}

// Service orchestrates Team Web Chat sessions, model listing, MCP tool execution,
// and zero-bypass LLM streaming through Headlamp's own proxy.Gateway.
type Service struct {
	store         store.Store
	authorizer    Authorizer
	pricing       *metering.PricingTable
	gateway       http.Handler
	mcp           MCPBridge
	maxToolRounds int
	logf          func(format string, args ...any)
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
		maxToolRounds: maxRounds,
		logf:          logf,
	}, nil
}

type routeCandidate struct {
	provider      store.Provider
	upstreamModel string
}

type modelDispatchInfo struct {
	useGemini     bool
	providerType  string
	upstreamModel string
	costOverride  *metering.PriceOverride
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
		session.Title = deriveSessionTitle(content)
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
		Content:   req.Content,
		Model:     model,
	})
	if err != nil {
		return fmt.Errorf("chat: insert user message: %w", err)
	}

	// Commit SSE headers and emit initial message_start frame.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	emitter := newSSEEmitter(w)
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
		outcome, runErr = s.runGeminiChatLoop(ctx, p, model, session.SystemPrompt, history, req.Content, tools, toolLookup, emitter)
	} else {
		outcome, runErr = s.runOpenAIChatLoop(ctx, p, model, session.SystemPrompt, history, req.Content, tools, toolLookup, emitter)
	}

	if runErr != nil {
		// If canceled by caller (Stop button), persist any partial output already streamed.
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) || ctx.Err() != nil {
			if outcome != nil && (outcome.content != "" || len(outcome.toolEvents) > 0) {
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
		if outcome != nil && (outcome.content != "" || len(outcome.toolEvents) > 0) {
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

type turnOutcome struct {
	content    string
	toolEvents []store.ChatToolEvent
	usage      metering.Usage
}

func (s *Service) persistAssistantMessage(subject, sessionID, model string, dispatch modelDispatchInfo, outcome *turnOutcome) (*store.ChatMessage, error) {
	if outcome == nil {
		outcome = &turnOutcome{}
	}

	var costUSD float64
	if s.pricing != nil {
		costUsage := outcome.usage
		// OpenAI /v1/chat/completions SSE reports prompt_tokens inclusive of cached_tokens
		// even when translated from Anthropic; adjust to Anthropic-exclusive input before pricing.
		if !dispatch.useGemini && dispatch.providerType == config.ProviderTypeAnthropic && costUsage.CacheReadTokens > 0 {
			if costUsage.InputTokens >= costUsage.CacheReadTokens {
				costUsage.InputTokens -= costUsage.CacheReadTokens
			} else {
				costUsage.InputTokens = 0
			}
		}
		costUSD = s.pricing.CalculateCost(dispatch.providerType, dispatch.upstreamModel, costUsage, dispatch.costOverride)
	}

	outputTokens := outcome.usage.OutputTokens
	if dispatch.providerType == config.ProviderTypeGemini {
		outputTokens += outcome.usage.ReasoningTokens
	}

	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.store.InsertChatMessage(saveCtx, subject, store.ChatMessage{
		ID:           uuid.NewString(),
		SessionID:    sessionID,
		Role:         "assistant",
		Content:      outcome.content,
		ToolEvents:   outcome.toolEvents,
		Model:        model,
		InputTokens:  outcome.usage.InputTokens,
		OutputTokens: outputTokens,
		CostUSD:      costUSD,
	})
}

type toolBinding struct {
	EncodedName string
	Server      string
	Tool        string
	Description string
	InputSchema json.RawMessage
}

func (s *Service) resolveMCPTools(ctx context.Context, p *auth.Principal, serverNames []string) ([]toolBinding, map[string]toolBinding) {
	if s.mcp == nil || len(serverNames) == 0 {
		return nil, nil
	}

	servers, err := s.mcp.ListAuthorizedTools(ctx, p, serverNames)
	if err != nil {
		s.logf("chat: list authorized MCP tools failed: %v", err)
		return nil, nil
	}

	lookup := make(map[string]toolBinding)
	var list []toolBinding
	for _, srv := range servers {
		if !srv.Enabled || srv.Error != "" {
			continue
		}
		for _, spec := range srv.Tools {
			srvName := spec.Server
			if srvName == "" {
				srvName = srv.Name
			}
			encoded := encodeToolName(srvName, spec.Name, lookup)
			binding := toolBinding{
				EncodedName: encoded,
				Server:      srvName,
				Tool:        spec.Name,
				Description: spec.Description,
				InputSchema: normalizeToolSchema(spec.InputSchema),
			}
			lookup[encoded] = binding
			list = append(list, binding)
		}
	}
	return list, lookup
}

func (s *Service) resolveDispatchInfo(ctx context.Context, modelID string) modelDispatchInfo {
	modelID = strings.TrimSpace(modelID)
	info := modelDispatchInfo{
		providerType:  config.ProviderTypeOpenAI,
		upstreamModel: modelID,
	}

	providers, err := s.store.ListProviders(ctx)
	if err != nil {
		info.useGemini = strings.HasPrefix(modelID, "gemini/")
		return info
	}
	byName := make(map[string]store.Provider, len(providers))
	enabled := make([]store.Provider, 0, len(providers))
	for _, prov := range providers {
		if prov.Enabled {
			byName[prov.Name] = prov
			enabled = append(enabled, prov)
		}
	}

	routes, _ := s.store.ListModelRoutes(ctx)

	// 1. Virtual alias route match.
	for _, r := range routes {
		if !r.Enabled || r.Alias != modelID {
			continue
		}
		var cands []routeCandidate
		if p, ok := byName[r.ProviderName]; ok {
			cands = append(cands, routeCandidate{provider: p, upstreamModel: r.UpstreamModel})
		}
		for _, fb := range r.Fallbacks {
			if p, ok := byName[fb.Provider]; ok {
				cands = append(cands, routeCandidate{provider: p, upstreamModel: fb.Model})
			}
		}
		if len(cands) == 0 {
			break
		}

		// Use OpenAI /v1/chat/completions if any candidate is non-Gemini; pure Gemini only if all candidates are Gemini.
		hasNonGemini := false
		chosen := cands[0]
		for _, c := range cands {
			if c.provider.Type != config.ProviderTypeGemini {
				if !hasNonGemini {
					chosen = c
				}
				hasNonGemini = true
				break
			}
		}
		rCopy := r
		return modelDispatchInfo{
			useGemini:     !hasNonGemini,
			providerType:  chosen.provider.Type,
			upstreamModel: chosen.upstreamModel,
			costOverride:  metering.PriceOverrideFromRoute(&rCopy),
		}
	}

	// 2. Explicit "<provider>/<model>" prefix match.
	if prefix, bareModel, hasSlash := strings.Cut(modelID, "/"); hasSlash && prefix != "" && bareModel != "" {
		if p, ok := byName[prefix]; ok {
			return modelDispatchInfo{
				useGemini:     p.Type == config.ProviderTypeGemini,
				providerType:  p.Type,
				upstreamModel: bareModel,
			}
		}
		for _, p := range enabled {
			if p.Type == prefix {
				return modelDispatchInfo{
					useGemini:     p.Type == config.ProviderTypeGemini,
					providerType:  p.Type,
					upstreamModel: bareModel,
				}
			}
		}
	}

	// 3. Bare model listed on an enabled provider (prefer non-Gemini first if listed on multiple).
	var geminiMatch *store.Provider
	for i := range enabled {
		p := &enabled[i]
		if !slices.Contains(p.Models, modelID) {
			continue
		}
		if p.Type != config.ProviderTypeGemini {
			return modelDispatchInfo{
				useGemini:     false,
				providerType:  p.Type,
				upstreamModel: modelID,
			}
		}
		if geminiMatch == nil {
			geminiMatch = p
		}
	}
	if geminiMatch != nil {
		return modelDispatchInfo{
			useGemini:     true,
			providerType:  config.ProviderTypeGemini,
			upstreamModel: modelID,
		}
	}

	// Fallback heuristic if wildcard provider is used.
	if strings.HasPrefix(modelID, "gemini/") {
		_, bare, _ := strings.Cut(modelID, "/")
		return modelDispatchInfo{
			useGemini:     true,
			providerType:  config.ProviderTypeGemini,
			upstreamModel: bare,
		}
	}
	return info
}

// gatewayHTTPError represents a non-2xx response returned by Headlamp's proxy.Gateway.
type gatewayHTTPError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *gatewayHTTPError) Error() string {
	return fmt.Sprintf("gateway http %d (%s): %s", e.StatusCode, e.Type, e.Message)
}

// invokeGatewayStream dispatches a synthetic HTTP POST directly into Headlamp's proxy.Gateway
// using an io.Pipe so streaming SSE chunks flow immediately without buffering while preserving
// the full policy, guardrail, quota, metering, and audit_payloads pipeline.
func (s *Service) invokeGatewayStream(ctx context.Context, p *auth.Principal, path string, body []byte) (io.Reader, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://headlamp.internal"+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("chat: build gateway request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.NodeIP != "" {
		req.RemoteAddr = p.NodeIP + ":0"
	} else {
		req.RemoteAddr = "127.0.0.1:0"
	}
	req = req.WithContext(auth.WithPrincipal(ctx, p))

	pr, pw := io.Pipe()
	rw := newPipeResponseWriter(pw)
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer rw.Finish()
		s.gateway.ServeHTTP(rw, req)
	}()

	closeStream := func() {
		_ = pr.Close()
		<-done
	}

	select {
	case <-rw.headerCh:
	case <-ctx.Done():
		closeStream()
		return nil, nil, ctx.Err()
	}

	status := rw.StatusCode()
	if status < 200 || status >= 300 {
		rawErr, _ := io.ReadAll(io.LimitReader(pr, maxErrorBodyBytes))
		closeStream()
		errType, errMsg := parseGatewayErrorBody(status, rawErr)
		return nil, nil, &gatewayHTTPError{
			StatusCode: status,
			Type:       errType,
			Message:    errMsg,
		}
	}

	return pr, closeStream, nil
}

type pipeResponseWriter struct {
	header      http.Header
	pw          *io.PipeWriter
	mu          sync.Mutex
	statusCode  int
	wroteHeader bool
	headerCh    chan struct{}
	headerOnce  sync.Once
}

func newPipeResponseWriter(pw *io.PipeWriter) *pipeResponseWriter {
	return &pipeResponseWriter{
		header:   make(http.Header),
		pw:       pw,
		headerCh: make(chan struct{}),
	}
}

func (w *pipeResponseWriter) Header() http.Header {
	return w.header
}

func (w *pipeResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	if !w.wroteHeader {
		w.statusCode = code
		w.wroteHeader = true
	}
	w.mu.Unlock()
	w.headerOnce.Do(func() { close(w.headerCh) })
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	needHeader := !w.wroteHeader
	if needHeader {
		w.statusCode = http.StatusOK
		w.wroteHeader = true
	}
	w.mu.Unlock()
	if needHeader {
		w.headerOnce.Do(func() { close(w.headerCh) })
	}
	return w.pw.Write(p)
}

// Flush satisfies http.Flusher so proxy.Gateway streams SSE chunks immediately.
func (w *pipeResponseWriter) Flush() {}

func (w *pipeResponseWriter) Finish() {
	w.mu.Lock()
	if !w.wroteHeader {
		w.statusCode = http.StatusOK
		w.wroteHeader = true
	}
	w.mu.Unlock()
	w.headerOnce.Do(func() { close(w.headerCh) })
	_ = w.pw.Close()
}

func (w *pipeResponseWriter) StatusCode() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.statusCode
}

type sseEmitter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	mu      sync.Mutex
}

func newSSEEmitter(w http.ResponseWriter) *sseEmitter {
	flusher, _ := w.(http.Flusher)
	return &sseEmitter{w: w, flusher: flusher}
}

func (e *sseEmitter) Emit(eventName string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := translate.WriteSSEEvent(e.w, eventName, data); err != nil {
		return err
	}
	if e.flusher != nil {
		e.flusher.Flush()
	}
	return nil
}

func parseGatewayErrorBody(status int, body []byte) (errType, message string) {
	var envelope struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &envelope); err == nil && envelope.Error.Message != "" {
		errType = envelope.Error.Type
		if errType == "" {
			errType = envelope.Error.Code
		}
		if errType == "" {
			errType = envelope.Error.Status
		}
		if errType == "" {
			errType = defaultErrorTypeForStatus(status)
		}
		return errType, envelope.Error.Message
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(status)
	}
	return defaultErrorTypeForStatus(status), msg
}

func defaultErrorTypeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusNotFound:
		return "not_found_error"
	default:
		return "upstream_error"
	}
}

func classifyStreamError(err error) (string, string) {
	var gwErr *gatewayHTTPError
	if errors.As(err, &gwErr) {
		return gwErr.Type, gwErr.Message
	}
	return "stream_error", err.Error()
}

func deriveSessionTitle(prompt string) string {
	collapsed := strings.Join(strings.Fields(prompt), " ")
	runes := []rune(collapsed)
	if len(runes) <= maxAutoTitleRunes {
		return collapsed
	}
	return strings.TrimSpace(string(runes[:maxAutoTitleRunes-3])) + "..."
}

func cleanStringSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" && !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	return out
}

func encodeToolName(server, tool string, existing map[string]toolBinding) string {
	base := "mcp__" + sanitizeToolSegment(server) + "__" + sanitizeToolSegment(tool)
	if len(base) > 60 {
		base = base[:60]
	}
	candidate := base
	for suffix := 2; ; suffix++ {
		if _, taken := existing[candidate]; !taken {
			return candidate
		}
		tail := fmt.Sprintf("_%d", suffix)
		prefix := base
		if len(prefix)+len(tail) > 64 {
			prefix = prefix[:64-len(tail)]
		}
		candidate = prefix + tail
	}
}

func sanitizeToolSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else if !unicode.IsSpace(r) {
			b.WriteByte('_')
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "tool"
	}
	return out
}

func normalizeToolSchema(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return trimmed
}

// sanitizeGeminiSchema strips JSON Schema fields rejected by Google's Gemini functionDeclarations
// validator (such as $schema, additionalProperties, title, and default).
func sanitizeGeminiSchema(raw json.RawMessage) any {
	var obj map[string]any
	if err := json.Unmarshal(normalizeToolSchema(raw), &obj); err != nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return cleanGeminiSchemaNode(obj)
}

func cleanGeminiSchemaNode(node any) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			switch k {
			case "$schema", "additionalProperties", "$defs", "definitions", "default":
				continue
			}
			out[k] = cleanGeminiSchemaNode(val)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cleanGeminiSchemaNode(item)
		}
		return out
	default:
		return v
	}
}
