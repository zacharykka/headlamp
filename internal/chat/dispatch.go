package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

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

type roundMetrics struct {
	providerType  string
	upstreamModel string
	usage         metering.Usage
}

type turnOutcome struct {
	content    string
	toolEvents []store.ChatToolEvent
	usage      metering.Usage
	rounds     []roundMetrics
}

func (s *Service) persistAssistantMessage(subject, sessionID, model string, dispatch modelDispatchInfo, outcome *turnOutcome) (*store.ChatMessage, error) {
	if outcome == nil {
		outcome = &turnOutcome{}
	}

	var (
		costUSD      float64
		outputTokens int64
	)

	if len(outcome.rounds) > 0 {
		for _, rm := range outcome.rounds {
			provType := strings.TrimSpace(rm.providerType)
			if provType == "" {
				provType = dispatch.providerType
			}
			upModel := strings.TrimSpace(rm.upstreamModel)
			if upModel == "" {
				upModel = dispatch.upstreamModel
			}
			if s.pricing != nil {
				costUsage := adjustUsageForPricing(dispatch.useGemini, provType, rm.usage)
				costUSD += s.pricing.CalculateCost(provType, upModel, costUsage, dispatch.costOverride)
			}
			outputTokens += rm.usage.OutputTokens
			if provType == config.ProviderTypeGemini {
				outputTokens += rm.usage.ReasoningTokens
			}
		}
	} else {
		if s.pricing != nil {
			costUsage := adjustUsageForPricing(dispatch.useGemini, dispatch.providerType, outcome.usage)
			costUSD = s.pricing.CalculateCost(dispatch.providerType, dispatch.upstreamModel, costUsage, dispatch.costOverride)
		}
		outputTokens = outcome.usage.OutputTokens
		if dispatch.providerType == config.ProviderTypeGemini {
			outputTokens += outcome.usage.ReasoningTokens
		}
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

func adjustUsageForPricing(useGemini bool, providerType string, usage metering.Usage) metering.Usage {
	// OpenAI /v1/chat/completions SSE reports prompt_tokens inclusive of cached_tokens
	// even when translated from Anthropic; adjust to Anthropic-exclusive input before pricing.
	if !useGemini && providerType == config.ProviderTypeAnthropic && usage.CacheReadTokens > 0 {
		if usage.InputTokens >= usage.CacheReadTokens {
			usage.InputTokens -= usage.CacheReadTokens
		} else {
			usage.InputTokens = 0
		}
	}
	return usage
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
func (s *Service) invokeGatewayStream(ctx context.Context, p *auth.Principal, path string, body []byte) (io.Reader, http.Header, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://headlamp.internal"+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("chat: build gateway request: %w", err)
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
		return nil, nil, nil, ctx.Err()
	}

	status := rw.StatusCode()
	respHeaders := rw.ResponseHeader()
	if status < 200 || status >= 300 {
		rawErr, _ := io.ReadAll(io.LimitReader(pr, maxErrorBodyBytes))
		closeStream()
		errType, errMsg := parseGatewayErrorBody(status, rawErr)
		return nil, nil, nil, &gatewayHTTPError{
			StatusCode: status,
			Type:       errType,
			Message:    errMsg,
		}
	}

	return pr, respHeaders, closeStream, nil
}

type pipeResponseWriter struct {
	header      http.Header
	headerSnap  http.Header
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
		w.headerSnap = w.header.Clone()
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
		w.headerSnap = w.header.Clone()
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
		w.headerSnap = w.header.Clone()
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

func (w *pipeResponseWriter) ResponseHeader() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.headerSnap == nil {
		return make(http.Header)
	}
	return w.headerSnap
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
