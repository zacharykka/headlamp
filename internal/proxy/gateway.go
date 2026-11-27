package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

const (
	defaultMaxRequestBodyBytes  = 32 << 20 // 32 MiB
	defaultMaxResponseBodyBytes = 32 << 20 // 32 MiB
	defaultAnthropicVersion     = "2023-06-01"
)

// GatewayConfig configures the multi-protocol LLM proxy Gateway.
type GatewayConfig struct {
	Store                store.Store
	Authorizer           Authorizer
	Telemetry            TelemetryFactory
	Quota                QuotaLimiter
	Guardrails           GuardrailInspector
	Events               EventDispatcher
	HTTPClient           *http.Client
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	Logf                 func(format string, args ...any)
}

// Gateway is an http.Handler implementing Headlamp's multi-protocol LLM proxy:
// OpenAI Chat Completions, OpenAI Responses, OpenAI Embeddings, Anthropic Messages,
// Google Gemini, and Ollama, with native passthrough first, on-demand cross-protocol
// translation, fallback retries, guardrails, quota enforcement, and streaming SSE telemetry hooks.
type Gateway struct {
	store                store.Store
	authorizer           Authorizer
	telemetry            TelemetryFactory
	quota                QuotaLimiter
	guardrails           GuardrailInspector
	events               EventDispatcher
	httpClient           *http.Client
	maxRequestBodyBytes  int64
	maxResponseBodyBytes int64
	logf                 func(format string, args ...any)
	mux                  *http.ServeMux
}

// NewGateway constructs a ready-to-serve LLM proxy Gateway.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Store == nil {
		return nil, errors.New("proxy: store is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}

	maxReq := cfg.MaxRequestBodyBytes
	if maxReq <= 0 {
		maxReq = defaultMaxRequestBodyBytes
	}
	maxResp := cfg.MaxResponseBodyBytes
	if maxResp <= 0 {
		maxResp = defaultMaxResponseBodyBytes
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}

	g := &Gateway{
		store:                cfg.Store,
		authorizer:           cfg.Authorizer,
		telemetry:            cfg.Telemetry,
		quota:                cfg.Quota,
		guardrails:           cfg.Guardrails,
		events:               cfg.Events,
		httpClient:           client,
		maxRequestBodyBytes:  maxReq,
		maxResponseBodyBytes: maxResp,
		logf:                 logf,
		mux:                  http.NewServeMux(),
	}
	g.registerRoutes()
	return g, nil
}

// ServeHTTP dispatches incoming requests across all LLM gateway endpoints.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isMutatingMethod(r.Method) {
		if err := checkSameOriginCSRF(r); err != nil {
			WriteError(w, ProtocolForPath(r.URL.Path), http.StatusForbidden, "csrf_blocked", err.Error())
			return
		}
	}
	g.mux.ServeHTTP(w, r)
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// checkSameOriginCSRF enforces same-origin validation whenever browser headers
// (Origin or Sec-Fetch-Site) are present on mutating requests, while leaving
// non-browser CLI/IDE SDK clients unaffected. Loopback dev-proxy aliases are
// allowed ONLY when RemoteAddr, Origin, and Host are all strictly loopback.
func checkSameOriginCSRF(r *http.Request) error {
	remoteLoopback := isLoopbackRemoteAddr(r.RemoteAddr)
	hostLoopback := isLoopbackHost(r.Host)
	loopbackDevEligible := remoteLoopback && hostLoopback

	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid Origin header %q", origin)
		}
		if !strings.EqualFold(u.Host, r.Host) {
			if !(loopbackDevEligible && isLoopbackHost(u.Hostname())) {
				return fmt.Errorf("cross-origin request blocked (origin=%q, host=%q)", u.Host, r.Host)
			}
		}
	}

	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" {
		switch sfs {
		case "same-origin", "none":
		case "same-site":
			if !loopbackDevEligible {
				return fmt.Errorf("cross-site request blocked (Sec-Fetch-Site=%q)", sfs)
			}
		default:
			return fmt.Errorf("cross-site request blocked (Sec-Fetch-Site=%q)", sfs)
		}
	}
	return nil
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

func isLoopbackHost(hostport string) bool {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

var (
	errBlockedUpstreamAddress = errors.New("proxy: blocked upstream IP address")
	awsIPv6IMDSAddr           = netip.MustParseAddr("fd00:ec2::254")
)

func defaultHTTPClient() *http.Client {
	// Never set http.Client.Timeout: that would abort long-running SSE streams.
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   upstreamDialControl,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 120 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func upstreamDialControl(_ string, address string, _ syscall.RawConn) error {
	return validateUpstreamDialAddr(address)
}

func validateUpstreamDialAddr(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid dial address %q", errBlockedUpstreamAddress, address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: invalid IP %q", errBlockedUpstreamAddress, host)
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.WithZone("") == awsIPv6IMDSAddr,
		addr.IsUnspecified(),
		addr.IsMulticast():
		return fmt.Errorf("%w: %s", errBlockedUpstreamAddress, addr)
	}
	return nil
}

func (g *Gateway) registerRoutes() {
	g.mux.HandleFunc("GET /healthz", g.handleHealthz)

	// OpenAI endpoints (default root alias + explicit /openai prefix).
	g.mux.HandleFunc("POST /v1/chat/completions", g.makeJSONLLMHandler(ProtocolOpenAIChat, "/v1/chat/completions"))
	g.mux.HandleFunc("POST /openai/v1/chat/completions", g.makeJSONLLMHandler(ProtocolOpenAIChat, "/v1/chat/completions"))
	g.mux.HandleFunc("POST /v1/responses", g.makeJSONLLMHandler(ProtocolOpenAIResponses, "/v1/responses"))
	g.mux.HandleFunc("POST /openai/v1/responses", g.makeJSONLLMHandler(ProtocolOpenAIResponses, "/v1/responses"))
	g.mux.HandleFunc("POST /v1/embeddings", g.makeJSONLLMHandler(ProtocolOpenAIEmbeddings, "/v1/embeddings"))
	g.mux.HandleFunc("POST /openai/v1/embeddings", g.makeJSONLLMHandler(ProtocolOpenAIEmbeddings, "/v1/embeddings"))
	g.mux.HandleFunc("GET /v1/models", g.makeModelsHandler(ProtocolOpenAIChat))
	g.mux.HandleFunc("GET /openai/v1/models", g.makeModelsHandler(ProtocolOpenAIChat))

	// Anthropic endpoints.
	g.mux.HandleFunc("POST /anthropic/v1/messages", g.makeJSONLLMHandler(ProtocolAnthropicMessages, "/v1/messages"))
	g.mux.HandleFunc("POST /anthropic/v1/messages/count_tokens", g.handleAnthropicCountTokens)
	g.mux.HandleFunc("GET /anthropic/v1/models", g.makeModelsHandler(ProtocolAnthropicMessages))

	// Google Gemini endpoints.
	g.mux.HandleFunc("POST /gemini/v1beta/models/{rest...}", g.handleGeminiGenerate)
	g.mux.HandleFunc("GET /gemini/v1beta/models", g.makeModelsHandler(ProtocolGemini))
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (g *Gateway) requirePrincipal(w http.ResponseWriter, r *http.Request, protocol string) (*auth.Principal, bool) {
	p, ok := auth.FromContext(r.Context())
	if !ok || p == nil {
		WriteError(w, protocol, http.StatusUnauthorized, "authentication_error", "unauthenticated request")
		return nil, false
	}
	return p, true
}

func (g *Gateway) makeModelsHandler(protocol string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := g.requirePrincipal(w, r, protocol)
		if !ok {
			return
		}

		catalog, err := listCatalogModels(r.Context(), g.store)
		if err != nil {
			WriteError(w, protocol, http.StatusInternalServerError, "server_error", "failed to list models")
			return
		}

		ids := make([]string, len(catalog))
		byID := make(map[string]catalogModel, len(catalog))
		for i, m := range catalog {
			ids[i] = m.ID
			byID[m.ID] = m
		}

		if g.authorizer != nil {
			ids, err = g.authorizer.FilterModels(r.Context(), principal, ids)
			if err != nil {
				WriteError(w, protocol, http.StatusInternalServerError, "server_error", "failed to authorize model list")
				return
			}
		}

		// Advertise only models with at least one protocol-compatible, non-denied candidate.
		eligible := make([]string, 0, len(ids))
		for _, id := range ids {
			m, exists := byID[id]
			if !exists {
				continue
			}
			hasUsableCandidate := false
			for _, cand := range m.Candidates {
				if !isNativeProtocolMatch(protocol, cand.provider.Type) && !canTranslateProtocol(protocol, cand.provider.Type) {
					continue
				}
				if m.IsAlias && g.authorizer != nil {
					candModel := cand.provider.Name + "/" + cand.upstreamModel
					denied, _, denyErr := g.authorizer.IsModelDenied(r.Context(), principal, candModel)
					if denyErr != nil {
						WriteError(w, protocol, http.StatusInternalServerError, "server_error", "failed to authorize model list")
						return
					}
					if denied {
						continue
					}
				}
				hasUsableCandidate = true
				break
			}
			if hasUsableCandidate {
				eligible = append(eligible, id)
			}
		}
		ids = eligible

		w.Header().Set("Content-Type", "application/json")
		switch protocol {
		case ProtocolAnthropicMessages:
			type anthropicModelItem struct {
				ID          string `json:"id"`
				Type        string `json:"type"`
				DisplayName string `json:"display_name"`
				CreatedAt   string `json:"created_at"`
			}
			items := make([]anthropicModelItem, 0, len(ids))
			for _, id := range ids {
				items = append(items, anthropicModelItem{
					ID:          id,
					Type:        "model",
					DisplayName: id,
					CreatedAt:   "2026-01-01T00:00:00Z",
				})
			}
			resp := map[string]any{
				"data":     items,
				"has_more": false,
			}
			if len(items) > 0 {
				resp["first_id"] = items[0].ID
				resp["last_id"] = items[len(items)-1].ID
			}
			_ = json.NewEncoder(w).Encode(resp)

		case ProtocolGemini:
			type geminiModelItem struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			}
			items := make([]geminiModelItem, 0, len(ids))
			for _, id := range ids {
				m := byID[id]
				name := id
				if _, after, ok := strings.Cut(id, "/"); ok && !m.IsAlias {
					name = after
				}
				items = append(items, geminiModelItem{
					Name:        "models/" + name,
					DisplayName: id,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": items})

		default:
			type openAIModelItem struct {
				ID      string `json:"id"`
				Object  string `json:"object"`
				Created int64  `json:"created"`
				OwnedBy string `json:"owned_by"`
			}
			items := make([]openAIModelItem, 0, len(ids))
			for _, id := range ids {
				owner := "headlamp"
				if m, exists := byID[id]; exists && m.ProviderName != "" {
					owner = m.ProviderName
				}
				items = append(items, openAIModelItem{
					ID:      id,
					Object:  "model",
					Created: 1700000000,
					OwnedBy: owner,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"data":   items,
			})
		}
	}
}

func (g *Gateway) readLimitedBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	lr := io.LimitReader(r.Body, g.maxRequestBodyBytes+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > g.maxRequestBodyBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

var errBodyTooLarge = errors.New("proxy: request body too large")

func (g *Gateway) makeJSONLLMHandler(ingressProtocol, upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := g.requirePrincipal(w, r, ingressProtocol)
		if !ok {
			return
		}

		reqBody, err := g.readLimitedBody(r)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				WriteError(w, ingressProtocol, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds gateway limit")
				return
			}
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "failed to read request body")
			return
		}

		var meta struct {
			Model         string `json:"model"`
			Stream        bool   `json:"stream"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		if err := json.Unmarshal(reqBody, &meta); err != nil {
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "invalid JSON request body")
			return
		}
		if strings.TrimSpace(meta.Model) == "" {
			WriteError(w, ingressProtocol, http.StatusBadRequest, "invalid_request", "field 'model' is required")
			return
		}

		clientIncludeUsage := meta.StreamOptions != nil && meta.StreamOptions.IncludeUsage
		g.executeLLMRequest(w, r, llmInvocation{
			principal:          principal,
			ingressProtocol:    ingressProtocol,
			upstreamPath:       upstreamPath,
			requestedModel:     meta.Model,
			stream:             meta.Stream,
			clientIncludeUsage: clientIncludeUsage,
			reqHeaders:         r.Header.Clone(),
			reqBody:            reqBody,
		})
	}
}

func (g *Gateway) handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := g.requirePrincipal(w, r, ProtocolAnthropicMessages)
	if !ok {
		return
	}

	reqBody, err := g.readLimitedBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			WriteError(w, ProtocolAnthropicMessages, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds gateway limit")
			return
		}
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}

	var meta struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(reqBody, &meta); err != nil || strings.TrimSpace(meta.Model) == "" {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request", "valid JSON body with 'model' is required")
		return
	}

	resolved, err := resolveRoute(r.Context(), g.store, ProtocolAnthropicMessages, meta.Model)
	if err != nil {
		if errors.Is(err, errModelNotFound) {
			WriteError(w, ProtocolAnthropicMessages, http.StatusNotFound, "not_found_error", fmt.Sprintf("model %q not found", meta.Model))
			return
		}
		WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "route resolution failed")
		return
	}

	if !g.authorizeModel(w, r, principal, ProtocolAnthropicMessages, resolved.canonicalModel) {
		return
	}

	var anthropicCands []routeCandidate
	for _, cand := range resolved.candidates {
		if cand.provider.Type == config.ProviderTypeAnthropic {
			anthropicCands = append(anthropicCands, cand)
		}
	}
	if len(anthropicCands) == 0 {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request_error", "count_tokens is only supported for Anthropic upstreams")
		return
	}

	if resolved.isAlias && g.authorizer != nil {
		filtered := make([]routeCandidate, 0, len(anthropicCands))
		var lastDenyReason string
		for _, cand := range anthropicCands {
			candModel := cand.provider.Name + "/" + cand.upstreamModel
			denied, reason, denyErr := g.authorizer.IsModelDenied(r.Context(), principal, candModel)
			if denyErr != nil {
				WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "authorization check failed")
				return
			}
			if denied {
				if reason == "" {
					reason = fmt.Sprintf("underlying model %q denied by policy", candModel)
				}
				lastDenyReason = reason
				continue
			}
			filtered = append(filtered, cand)
		}
		if len(filtered) == 0 {
			WriteError(w, ProtocolAnthropicMessages, http.StatusForbidden, "permission_error", lastDenyReason)
			return
		}
		anthropicCands = filtered
	}

	// Run guardrails before forwarding prompt messages to Anthropic's count_tokens endpoint.
	guardrailModified := false
	if g.guardrails != nil {
		requestID := uuid.NewString()
		decision, gErr := g.guardrails.Inspect(r.Context(), GuardrailRequest{
			RequestID: requestID,
			Principal: principal,
			Protocol:  ProtocolAnthropicMessages,
			Model:     resolved.canonicalModel,
			Body:      reqBody,
		})
		if gErr != nil {
			g.logf("headlamp proxy: count_tokens request_id=%s guardrail error: %v", requestID, gErr)
			WriteError(w, ProtocolAnthropicMessages, http.StatusInternalServerError, "api_error", "guardrail inspection failed")
			return
		}
		if decision != nil {
			if decision.Action == "block" {
				statusCode := decision.StatusCode
				if statusCode < 400 {
					statusCode = http.StatusBadRequest
				}
				reason := decision.Reason
				if reason == "" {
					reason = "request blocked by guardrail policy"
				}
				WriteError(w, ProtocolAnthropicMessages, statusCode, "guardrail_blocked", reason)
				return
			}
			if (decision.Action == "redact" || decision.Action == "modify") && len(decision.ModifiedBody) > 0 {
				reqBody = decision.ModifiedBody
				guardrailModified = true
			}
		}
	}

	var lastResp *http.Response
	for i, cand := range anthropicCands {
		bodyToSend := reqBody
		if cand.upstreamModel != meta.Model || guardrailModified {
			bodyToSend, _, err = patchJSONRequest(reqBody, cand.upstreamModel, false)
			if err != nil {
				if i+1 < len(anthropicCands) {
					continue
				}
				WriteError(w, ProtocolAnthropicMessages, http.StatusBadRequest, "invalid_request_error", "failed to rewrite model field")
				return
			}
		}

		targetURL := buildUpstreamURL(cand.provider, "/v1/messages/count_tokens", "")
		upReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(bodyToSend))
		if reqErr != nil {
			if i+1 < len(anthropicCands) {
				continue
			}
			WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "failed to construct upstream request")
			return
		}
		applyUpstreamHeaders(upReq, r, cand.provider, true)

		resp, doErr := g.httpClient.Do(upReq)
		if doErr != nil {
			safeErr := sanitizeUpstreamError(doErr)
			if i+1 < len(anthropicCands) {
				next := anthropicCands[i+1]
				g.logf("headlamp proxy: count_tokens model=%s candidate %s/%s failed (%s), falling back to %s/%s",
					meta.Model, cand.provider.Name, cand.upstreamModel, safeErr, next.provider.Name, next.upstreamModel)
				continue
			}
			WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "upstream request failed: "+safeErr)
			return
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i+1 < len(anthropicCands) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			next := anthropicCands[i+1]
			g.logf("headlamp proxy: count_tokens model=%s candidate %s/%s returned HTTP %d, falling back to %s/%s",
				meta.Model, cand.provider.Name, cand.upstreamModel, resp.StatusCode, next.provider.Name, next.upstreamModel)
			continue
		}

		lastResp = resp
		break
	}
	if lastResp == nil {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "no Anthropic upstream succeeded for count_tokens")
		return
	}
	defer lastResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(lastResp.Body, g.maxResponseBodyBytes))
	if err != nil {
		WriteError(w, ProtocolAnthropicMessages, http.StatusBadGateway, "api_error", "failed to read upstream response")
		return
	}
	copyResponseHeaders(w.Header(), lastResp.Header)
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(lastResp.StatusCode)
	_, _ = w.Write(respBody)
}

func (g *Gateway) handleGeminiGenerate(w http.ResponseWriter, r *http.Request) {
	principal, ok := g.requirePrincipal(w, r, ProtocolGemini)
	if !ok {
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/gemini/v1beta/models/")
	modelID, action, hasColon := strings.Cut(rest, ":")
	if !hasColon || modelID == "" || (action != "generateContent" && action != "streamGenerateContent") {
		WriteError(w, ProtocolGemini, http.StatusNotFound, "NOT_FOUND", "unsupported Gemini endpoint; expected :generateContent or :streamGenerateContent")
		return
	}
	if decoded, err := url.PathUnescape(modelID); err == nil {
		modelID = decoded
	}

	reqBody, err := g.readLimitedBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			WriteError(w, ProtocolGemini, http.StatusRequestEntityTooLarge, "INVALID_ARGUMENT", "request body exceeds gateway limit")
			return
		}
		WriteError(w, ProtocolGemini, http.StatusBadRequest, "INVALID_ARGUMENT", "failed to read request body")
		return
	}

	trimmedBody := bytes.TrimSpace(reqBody)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' || !json.Valid(trimmedBody) {
		WriteError(w, ProtocolGemini, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid JSON request body")
		return
	}

	g.executeLLMRequest(w, r, llmInvocation{
		principal:       principal,
		ingressProtocol: ProtocolGemini,
		requestedModel:  modelID,
		stream:          action == "streamGenerateContent",
		geminiAction:    action,
		rawQuery:        r.URL.RawQuery,
		reqHeaders:      r.Header.Clone(),
		reqBody:         reqBody,
	})
}

type llmInvocation struct {
	principal          *auth.Principal
	ingressProtocol    string
	upstreamPath       string
	requestedModel     string
	stream             bool
	clientIncludeUsage bool
	geminiAction       string
	rawQuery           string
	reqHeaders         http.Header
	reqBody            []byte
	guardrailAction    string
	guardrailHits      []string
	guardrailModified  bool
}

func (g *Gateway) authorizeModel(w http.ResponseWriter, r *http.Request, principal *auth.Principal, protocol, canonicalModel string) bool {
	if g.authorizer == nil {
		return true
	}
	allowed, reason, err := g.authorizer.AuthorizeModel(r.Context(), principal, canonicalModel)
	if err != nil {
		WriteError(w, protocol, http.StatusInternalServerError, "server_error", "authorization check failed")
		return false
	}
	if !allowed {
		if reason == "" {
			reason = fmt.Sprintf("access to model %q denied by policy", canonicalModel)
		}
		WriteError(w, protocol, http.StatusForbidden, "model_not_allowed", reason)
		return false
	}
	return true
}

func (g *Gateway) executeLLMRequest(w http.ResponseWriter, r *http.Request, inv llmInvocation) {
	resolved, err := resolveRoute(r.Context(), g.store, inv.ingressProtocol, inv.requestedModel)
	if err != nil {
		if errors.Is(err, errModelNotFound) {
			WriteError(w, inv.ingressProtocol, http.StatusNotFound, "model_not_found", fmt.Sprintf("model %q not found", inv.requestedModel))
			return
		}
		WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "route resolution failed")
		return
	}

	if !g.authorizeModel(w, r, inv.principal, inv.ingressProtocol, resolved.canonicalModel) {
		return
	}

	startTime := time.Now()
	requestID := uuid.NewString()

	type compatibleCandidate struct {
		cand         routeCandidate
		isNative     bool
		isTranslated bool
	}

	compatible := make([]compatibleCandidate, 0, len(resolved.candidates))
	var incompatErr error
	for _, cand := range resolved.candidates {
		isNative := isNativeProtocolMatch(inv.ingressProtocol, cand.provider.Type)
		isTranslated := !isNative && canTranslateProtocol(inv.ingressProtocol, cand.provider.Type)
		if !isNative && !isTranslated {
			if incompatErr == nil {
				incompatErr = fmt.Errorf("unsupported cross-protocol route from %s to %s", inv.ingressProtocol, cand.provider.Type)
			}
			continue
		}
		compatible = append(compatible, compatibleCandidate{
			cand:         cand,
			isNative:     isNative,
			isTranslated: isTranslated,
		})
	}
	if len(compatible) == 0 {
		msg := "no compatible upstream provider available"
		if incompatErr != nil {
			msg = incompatErr.Error()
		}
		WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", msg)
		return
	}

	// Enforce explicit DenyModels on concrete underlying candidates of a virtual route alias.
	if resolved.isAlias && g.authorizer != nil {
		allowedCands := make([]compatibleCandidate, 0, len(compatible))
		var lastDenyReason string
		for _, item := range compatible {
			candModel := item.cand.provider.Name + "/" + item.cand.upstreamModel
			denied, reason, denyErr := g.authorizer.IsModelDenied(r.Context(), inv.principal, candModel)
			if denyErr != nil {
				WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "authorization check failed")
				return
			}
			if denied {
				if reason == "" {
					reason = fmt.Sprintf("underlying model %q denied by policy", candModel)
				}
				lastDenyReason = reason
				continue
			}
			allowedCands = append(allowedCands, item)
		}
		if len(allowedCands) == 0 {
			WriteError(w, inv.ingressProtocol, http.StatusForbidden, "model_not_allowed", lastDenyReason)
			return
		}
		compatible = allowedCands
	}

	// Pre-request Guardrail inspection (local regex + sync_review webhooks).
	if g.guardrails != nil {
		decision, gErr := g.guardrails.Inspect(r.Context(), GuardrailRequest{
			RequestID: requestID,
			Principal: inv.principal,
			Protocol:  inv.ingressProtocol,
			Model:     resolved.canonicalModel,
			Body:      inv.reqBody,
		})
		if gErr != nil {
			g.logf("headlamp proxy: request_id=%s guardrail error: %v", requestID, gErr)
			WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "guardrail inspection failed")
			return
		}
		if decision != nil {
			if decision.Action != "" && decision.Action != "allow" {
				inv.guardrailAction = decision.Action
				inv.guardrailHits = decision.Hits
			}
			if decision.Action == "block" {
				statusCode := decision.StatusCode
				if statusCode < 400 {
					statusCode = http.StatusBadRequest
				}
				reason := decision.Reason
				if reason == "" {
					reason = "request blocked by guardrail policy"
				}
				// Never persist blocked raw secrets (e.g. PEM private keys) into audit_payloads.
				inv.reqBody = []byte("[BLOCKED BY GUARDRAIL]")
				obs := g.startTelemetry(r.Context(), requestID, startTime, inv, compatible[0].cand, resolved.costOverride, compatible[0].isTranslated)
				obs.Finish(TelemetryFinish{
					StatusCode:   statusCode,
					LatencyMS:    time.Since(startTime).Milliseconds(),
					ErrorMessage: reason,
				})
				WriteError(w, inv.ingressProtocol, statusCode, "guardrail_blocked", reason)
				return
			}
			if (decision.Action == "redact" || decision.Action == "modify") && len(decision.ModifiedBody) > 0 {
				inv.reqBody = decision.ModifiedBody
				inv.guardrailModified = true
			}
		}
	}

	// Quota & rate-limit acquisition (RPM / TPM / MaxConcurrent / Daily & Monthly USD).
	var (
		quotaTicket QuotaTicket
		usedTokens  int64
	)
	if g.quota != nil {
		ticket, rej, qErr := g.quota.Acquire(r.Context(), inv.principal)
		if qErr != nil {
			g.logf("headlamp proxy: request_id=%s quota error: %v", requestID, qErr)
			WriteError(w, inv.ingressProtocol, http.StatusInternalServerError, "server_error", "quota check failed")
			return
		}
		if rej != nil {
			if rej.RetryAfterSec > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(rej.RetryAfterSec))
			}
			reason := rej.Reason
			if reason == "" {
				reason = "quota or rate limit exceeded"
			}
			code := "rate_limit_exceeded"
			if rej.Metric == "daily_usd" || rej.Metric == "monthly_usd" {
				code = "insufficient_quota"
			}
			obs := g.startTelemetry(r.Context(), requestID, startTime, inv, compatible[0].cand, resolved.costOverride, compatible[0].isTranslated)
			obs.Finish(TelemetryFinish{
				StatusCode:   http.StatusTooManyRequests,
				LatencyMS:    time.Since(startTime).Milliseconds(),
				ErrorMessage: reason,
			})
			WriteError(w, inv.ingressProtocol, http.StatusTooManyRequests, code, reason)
			return
		}
		quotaTicket = ticket
	}
	if quotaTicket != nil {
		defer func() {
			quotaTicket.Release(usedTokens)
		}()
	}

	var (
		lastResp          *http.Response
		lastCand          routeCandidate
		lastTranslated    bool
		lastInjectedUsage bool
		lastAttemptStart  time.Time
		lastErr           error
	)

	for i, item := range compatible {
		cand := item.cand
		isNative := item.isNative
		isTranslated := item.isTranslated

		upBody, upURL, injectedIncludeUsage, err := g.prepareUpstreamRequestPayload(inv, cand, isNative)
		if err != nil {
			lastErr = err
			if i+1 < len(compatible) {
				next := compatible[i+1].cand
				g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s payload error (%v), falling back to %s/%s",
					requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, err, next.provider.Name, next.upstreamModel)
				g.emitFallbackEvent(requestID, inv, cand, next, 0, err.Error())
				continue
			}
			WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upURL, bytes.NewReader(upBody))
		if err != nil {
			lastErr = err
			if i+1 < len(compatible) {
				continue
			}
			WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to build upstream request")
			return
		}
		applyUpstreamHeaders(upReq, r, cand.provider, isNative)

		attemptStart := time.Now()
		resp, err := g.httpClient.Do(upReq)
		if err != nil {
			safeErr := sanitizeUpstreamError(err)
			lastErr = errors.New(safeErr)
			lastCand = cand
			lastTranslated = isTranslated
			if i+1 < len(compatible) {
				next := compatible[i+1].cand
				g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s network error (%s), falling back to %s/%s",
					requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, safeErr, next.provider.Name, next.upstreamModel)
				g.emitFallbackEvent(requestID, inv, cand, next, 0, safeErr)
				continue
			}
			// Network failure on last compatible candidate.
			g.emitUpstreamErrorEvent(requestID, inv, cand, http.StatusBadGateway, safeErr)
			obs := g.startTelemetry(r.Context(), requestID, startTime, inv, cand, resolved.costOverride, isTranslated)
			obs.Finish(TelemetryFinish{
				StatusCode:   http.StatusBadGateway,
				LatencyMS:    time.Since(startTime).Milliseconds(),
				TTFTMS:       time.Since(attemptStart).Milliseconds(),
				ErrorMessage: safeErr,
			})
			WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "upstream request failed: "+safeErr)
			return
		}

		// Retry fallback candidates on 429 or 5xx BEFORE writing any response headers to the client.
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i+1 < len(compatible) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			next := compatible[i+1].cand
			reason := fmt.Sprintf("HTTP %d", resp.StatusCode)
			g.logf("headlamp proxy: request_id=%s model=%s candidate %s/%s returned %s, falling back to %s/%s",
				requestID, inv.requestedModel, cand.provider.Name, cand.upstreamModel, reason, next.provider.Name, next.upstreamModel)
			g.emitFallbackEvent(requestID, inv, cand, next, resp.StatusCode, reason)
			lastErr = fmt.Errorf("upstream %s returned HTTP %d", cand.provider.Name, resp.StatusCode)
			continue
		}

		lastResp = resp
		lastCand = cand
		lastTranslated = isTranslated
		lastInjectedUsage = injectedIncludeUsage
		lastAttemptStart = attemptStart
		break
	}

	if lastResp == nil {
		msg := "no compatible upstream provider available"
		if lastErr != nil {
			msg = lastErr.Error()
		}
		WriteError(w, inv.ingressProtocol, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	defer lastResp.Body.Close()

	observer := g.startTelemetry(r.Context(), requestID, startTime, inv, lastCand, resolved.costOverride, lastTranslated)
	// Ensure token usage is tracked for quotaTicket.Release even when no TokenReporter is wired.
	var tokenTracker *fallbackTokenObserver
	if quotaTicket != nil {
		if _, hasReporter := observer.(TokenReporter); !hasReporter {
			tokenTracker = &fallbackTokenObserver{inner: observer}
			observer = tokenTracker
		}
		defer func() {
			if tr, ok := observer.(TokenReporter); ok {
				usedTokens = tr.TotalTokens()
			} else if tokenTracker != nil {
				usedTokens = tokenTracker.TotalTokens()
			}
		}()
	}
	observer.SetResponseHeaders(flattenHeaders(lastResp.Header))

	// Handle non-2xx upstream response (status + error envelope).
	if lastResp.StatusCode < 200 || lastResp.StatusCode >= 300 {
		errBody, readErr := io.ReadAll(io.LimitReader(lastResp.Body, g.maxResponseBodyBytes))
		if len(errBody) > 0 {
			observer.OnJSONResponse(errBody)
		}
		latency := time.Since(startTime).Milliseconds()
		ttft := time.Since(lastAttemptStart).Milliseconds()
		errMsg := extractUpstreamErrorMessage(errBody, fmt.Sprintf("upstream returned HTTP %d", lastResp.StatusCode))
		if readErr != nil {
			errMsg = readErr.Error()
		}
		if lastResp.StatusCode >= 500 {
			g.emitUpstreamErrorEvent(requestID, inv, lastCand, lastResp.StatusCode, errMsg)
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   lastResp.StatusCode,
			LatencyMS:    latency,
			TTFTMS:       ttft,
			ErrorMessage: errMsg,
		})
		if lastTranslated {
			WriteError(w, inv.ingressProtocol, lastResp.StatusCode, "", errMsg)
			return
		}
		copyResponseHeaders(w.Header(), lastResp.Header)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(lastResp.StatusCode)
		_, _ = w.Write(errBody)
		return
	}

	contentType := strings.ToLower(lastResp.Header.Get("Content-Type"))
	isEventStream := strings.Contains(contentType, "text/event-stream")
	isStreamingResp := isEventStream || inv.stream

	if isStreamingResp {
		g.handleStreamingResponse(w, lastResp, observer, startTime, lastAttemptStart, inv, lastCand, lastTranslated, isEventStream, lastInjectedUsage)
		return
	}

	g.handleJSONResponse(w, lastResp, observer, startTime, lastAttemptStart, inv, lastCand, lastTranslated)
}

func (g *Gateway) emitFallbackEvent(requestID string, inv llmInvocation, failed, next routeCandidate, statusCode int, reason string) {
	if g.events == nil {
		return
	}
	subject := ""
	if inv.principal != nil {
		subject = inv.principal.Subject
	}
	g.events.Emit(config.WebhookEventUpstreamFallback, map[string]any{
		"request_id":      requestID,
		"subject":         subject,
		"model":           inv.requestedModel,
		"failed_provider": failed.provider.Name,
		"failed_model":    failed.upstreamModel,
		"next_provider":   next.provider.Name,
		"next_model":      next.upstreamModel,
		"status_code":     statusCode,
		"reason":          reason,
	})
}

func (g *Gateway) emitUpstreamErrorEvent(requestID string, inv llmInvocation, cand routeCandidate, statusCode int, errMsg string) {
	if g.events == nil {
		return
	}
	subject := ""
	if inv.principal != nil {
		subject = inv.principal.Subject
	}
	g.events.Emit(config.WebhookEventUpstreamError, map[string]any{
		"request_id":     requestID,
		"subject":        subject,
		"model":          inv.requestedModel,
		"provider":       cand.provider.Name,
		"upstream_model": cand.upstreamModel,
		"status_code":    statusCode,
		"error":          errMsg,
	})
}

// fallbackTokenObserver wraps a StreamObserver that does not implement TokenReporter
// so QuotaTicket.Release still receives accurate total token counts.
type fallbackTokenObserver struct {
	inner     StreamObserver
	input     int64
	output    int64
	cacheRead int64
	cacheWr   int64
	thoughts  int64
	total     int64
}

func (f *fallbackTokenObserver) SetResponseHeaders(h map[string]string) { f.inner.SetResponseHeaders(h) }
func (f *fallbackTokenObserver) Finish(fin TelemetryFinish)             { f.inner.Finish(fin) }

func (f *fallbackTokenObserver) OnSSEEvent(eventName string, data []byte) {
	f.inner.OnSSEEvent(eventName, data)
	f.extractTokens(data)
}

func (f *fallbackTokenObserver) OnJSONResponse(body []byte) {
	f.inner.OnJSONResponse(body)
	f.extractTokens(body)
}

func (f *fallbackTokenObserver) TotalTokens() int64 {
	if f.total > 0 {
		return f.total
	}
	return f.input + f.output + f.cacheRead + f.cacheWr + f.thoughts
}

func (f *fallbackTokenObserver) extractTokens(data []byte) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return
	}
	var probe struct {
		Usage *struct {
			PromptTokens             int64 `json:"prompt_tokens"`
			CompletionTokens         int64 `json:"completion_tokens"`
			TotalTokens              int64 `json:"total_tokens"`
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
		Message *struct {
			Usage *struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Response *struct {
			Usage *struct {
				TotalTokens  int64 `json:"total_tokens"`
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
		UsageMetadata *struct {
			TotalTokenCount      int64 `json:"totalTokenCount"`
			PromptTokenCount     int64 `json:"promptTokenCount"`
			CandidatesTokenCount int64 `json:"candidatesTokenCount"`
			ThoughtsTokenCount   int64 `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return
	}
	if probe.Usage != nil {
		if probe.Usage.TotalTokens > 0 {
			f.total = probe.Usage.TotalTokens
		}
		if probe.Usage.PromptTokens > 0 {
			f.input = probe.Usage.PromptTokens
		}
		if probe.Usage.CompletionTokens > 0 {
			f.output = probe.Usage.CompletionTokens
		}
		if probe.Usage.InputTokens > 0 {
			f.input = probe.Usage.InputTokens
		}
		if probe.Usage.OutputTokens > 0 {
			f.output = probe.Usage.OutputTokens
		}
		if probe.Usage.CacheReadInputTokens > 0 {
			f.cacheRead = probe.Usage.CacheReadInputTokens
		}
		if probe.Usage.CacheCreationInputTokens > 0 {
			f.cacheWr = probe.Usage.CacheCreationInputTokens
		}
	}
	if probe.Message != nil && probe.Message.Usage != nil {
		u := probe.Message.Usage
		if u.InputTokens > 0 {
			f.input = u.InputTokens
		}
		if u.OutputTokens > 0 {
			f.output = u.OutputTokens
		}
		if u.CacheReadInputTokens > 0 {
			f.cacheRead = u.CacheReadInputTokens
		}
		if u.CacheCreationInputTokens > 0 {
			f.cacheWr = u.CacheCreationInputTokens
		}
	}
	if probe.Response != nil && probe.Response.Usage != nil {
		u := probe.Response.Usage
		if u.TotalTokens > 0 {
			f.total = u.TotalTokens
		} else if u.InputTokens+u.OutputTokens > 0 {
			f.total = u.InputTokens + u.OutputTokens
		}
	}
	if probe.UsageMetadata != nil {
		u := probe.UsageMetadata
		if u.TotalTokenCount > 0 {
			f.total = u.TotalTokenCount
		} else if u.PromptTokenCount+u.CandidatesTokenCount+u.ThoughtsTokenCount > 0 {
			f.total = u.PromptTokenCount + u.CandidatesTokenCount + u.ThoughtsTokenCount
		}
	}
}

func (g *Gateway) startTelemetry(
	ctx context.Context,
	requestID string,
	ts time.Time,
	inv llmInvocation,
	cand routeCandidate,
	costOverride *CostOverride,
	translated bool,
) StreamObserver {
	if g.telemetry == nil {
		return noopObserver{}
	}
	obs := g.telemetry.Start(ctx, TelemetryStart{
		RequestID:       requestID,
		Timestamp:       ts,
		Principal:       inv.principal,
		Protocol:        upstreamWireProtocol(inv.ingressProtocol, cand.provider.Type),
		IngressProtocol: inv.ingressProtocol,
		Endpoint:        inv.endpointPath(),
		Provider:        cand.provider.Name,
		ProviderType:    cand.provider.Type,
		RequestedModel:  inv.requestedModel,
		UpstreamModel:   cand.upstreamModel,
		Stream:          inv.stream,
		Translated:      translated,
		RequestHeaders:  inv.reqHeaders,
		RequestBody:     inv.reqBody,
		CostOverride:    costOverride,
		GuardrailAction: inv.guardrailAction,
		GuardrailHits:   inv.guardrailHits,
	})
	if obs == nil {
		return noopObserver{}
	}
	return obs
}

func (inv llmInvocation) endpointPath() string {
	if inv.ingressProtocol == ProtocolGemini {
		return "/gemini/v1beta/models/" + inv.requestedModel + ":" + inv.geminiAction
	}
	return inv.upstreamPath
}

func (g *Gateway) prepareUpstreamRequestPayload(inv llmInvocation, cand routeCandidate, isNative bool) (body []byte, targetURL string, injectedIncludeUsage bool, err error) {
	if isNative {
		switch inv.ingressProtocol {
		case ProtocolGemini:
			rawQuery := inv.rawQuery
			if !cand.provider.Passthrough {
				rawQuery = stripQueryParam(rawQuery, "key")
			}
			path := "/v1beta/models/" + url.PathEscape(cand.upstreamModel) + ":" + inv.geminiAction
			return inv.reqBody, buildUpstreamURL(cand.provider, path, rawQuery), false, nil

		case ProtocolOpenAIChat:
			needModelRewrite := cand.upstreamModel != inv.requestedModel || inv.guardrailModified
			needStreamOpts := inv.stream
			body = inv.reqBody
			if needModelRewrite || needStreamOpts {
				newModel := ""
				if needModelRewrite {
					newModel = cand.upstreamModel
				}
				var pinStream *bool
				if inv.guardrailModified {
					streamVal := inv.stream
					pinStream = &streamVal
				}
				body, injectedIncludeUsage, err = patchJSONRequestWithStream(inv.reqBody, newModel, needStreamOpts, pinStream)
				if err != nil {
					return nil, "", false, err
				}
			}
			return body, buildUpstreamURL(cand.provider, inv.upstreamPath, ""), injectedIncludeUsage, nil

		default:
			// OpenAI Responses, OpenAI Embeddings, Anthropic Messages:
			// zero JSON restructuring when model name matches and body was not rewritten by guardrails.
			body = inv.reqBody
			if cand.upstreamModel != inv.requestedModel || inv.guardrailModified {
				var pinStream *bool
				if inv.guardrailModified && inv.ingressProtocol != ProtocolOpenAIEmbeddings {
					streamVal := inv.stream
					pinStream = &streamVal
				}
				body, _, err = patchJSONRequestWithStream(inv.reqBody, cand.upstreamModel, false, pinStream)
				if err != nil {
					return nil, "", false, err
				}
			}
			return body, buildUpstreamURL(cand.provider, inv.upstreamPath, ""), false, nil
		}
	}

	// Cross-protocol translation: if guardrails modified the body, re-pin "stream"
	// before translating so a sync_review webhook cannot flip streaming mode.
	reqBody := inv.reqBody
	if inv.guardrailModified {
		streamVal := inv.stream
		reqBody, _, err = patchJSONRequestWithStream(reqBody, "", false, &streamVal)
		if err != nil {
			return nil, "", false, err
		}
	}

	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		// OpenAI Chat -> Anthropic Messages.
		translatedBody, err := translate.OpenAIRequestToAnthropic(reqBody, cand.upstreamModel)
		if err != nil {
			return nil, "", false, err
		}
		return translatedBody, buildUpstreamURL(cand.provider, "/v1/messages", ""), false, nil

	case ProtocolAnthropicMessages:
		// Anthropic Messages -> OpenAI Chat (OpenAI or Ollama).
		translatedBody, err := translate.AnthropicRequestToOpenAI(reqBody, cand.upstreamModel, cand.provider.Type)
		if err != nil {
			return nil, "", false, err
		}
		return translatedBody, buildUpstreamURL(cand.provider, "/v1/chat/completions", ""), false, nil

	default:
		return nil, "", false, fmt.Errorf("unsupported cross-protocol translation from %s to %s", inv.ingressProtocol, cand.provider.Type)
	}
}

func (g *Gateway) handleJSONResponse(
	w http.ResponseWriter,
	resp *http.Response,
	observer StreamObserver,
	startTime time.Time,
	attemptStart time.Time,
	inv llmInvocation,
	cand routeCandidate,
	translated bool,
) {
	upBody, err := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
	ttft := time.Since(attemptStart).Milliseconds()
	if err != nil {
		observer.Finish(TelemetryFinish{
			StatusCode:   http.StatusBadGateway,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: err.Error(),
		})
		WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
		return
	}

	// Feed raw upstream JSON to metering so provider-native usage fields are parsed losslessly.
	observer.OnJSONResponse(upBody)

	if !translated {
		copyResponseHeaders(w.Header(), resp.Header)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
		w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
		w.WriteHeader(resp.StatusCode)
		_, writeErr := w.Write(upBody)
		errMsg := ""
		if writeErr != nil {
			errMsg = writeErr.Error()
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   resp.StatusCode,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: errMsg,
		})
		return
	}

	var outBody []byte
	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		outBody, err = translate.AnthropicResponseToOpenAI(upBody, inv.requestedModel)
	case ProtocolAnthropicMessages:
		outBody, err = translate.OpenAIResponseToAnthropic(upBody, inv.requestedModel)
	default:
		err = fmt.Errorf("unsupported response translation for %s", inv.ingressProtocol)
	}
	if err != nil {
		observer.Finish(TelemetryFinish{
			StatusCode:   http.StatusBadGateway,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttft,
			ErrorMessage: err.Error(),
		})
		WriteError(w, inv.ingressProtocol, http.StatusBadGateway, "upstream_error", "failed to translate upstream response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
	w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
	w.WriteHeader(resp.StatusCode)
	_, writeErr := w.Write(outBody)
	errMsg := ""
	if writeErr != nil {
		errMsg = writeErr.Error()
	}
	observer.Finish(TelemetryFinish{
		StatusCode:   resp.StatusCode,
		LatencyMS:    time.Since(startTime).Milliseconds(),
		TTFTMS:       ttft,
		ErrorMessage: errMsg,
	})
}

func (g *Gateway) handleStreamingResponse(
	w http.ResponseWriter,
	resp *http.Response,
	observer StreamObserver,
	startTime time.Time,
	attemptStart time.Time,
	inv llmInvocation,
	cand routeCandidate,
	translated bool,
	isEventStream bool,
	suppressSyntheticUsage bool,
) {
	flusher, _ := w.(http.Flusher)

	copyResponseHeaders(w.Header(), resp.Header)
	if translated || isEventStream {
		w.Header().Set("Content-Type", "text/event-stream")
	} else if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Headlamp-Provider-Type", cand.provider.Type)
	w.Header().Set("X-Headlamp-Upstream-Model", cand.upstreamModel)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	var (
		ttftMS    int64
		gotFirst  bool
		streamErr error
	)
	recordFirstToken := func() {
		if !gotFirst {
			gotFirst = true
			ttftMS = time.Since(attemptStart).Milliseconds()
		}
	}

	defer func() {
		errMsg := ""
		if streamErr != nil {
			errMsg = streamErr.Error()
		}
		observer.Finish(TelemetryFinish{
			StatusCode:   resp.StatusCode,
			LatencyMS:    time.Since(startTime).Milliseconds(),
			TTFTMS:       ttftMS,
			ErrorMessage: errMsg,
		})
	}()

	if !translated {
		if isEventStream || (inv.ingressProtocol != ProtocolGemini && inv.stream) {
			streamErr = streamNativeSSE(resp.Body, w, flusher, observer, suppressSyntheticUsage, recordFirstToken)
			return
		}
		// Fallback for non-SSE streaming (e.g. Gemini :streamGenerateContent without ?alt=sse).
		streamErr = streamNativeJSONChunks(resp.Body, w, flusher, observer, g.maxResponseBodyBytes, recordFirstToken)
		return
	}

	opts := translate.StreamOptions{
		RequestedModel: inv.requestedModel,
		IncludeUsage:   inv.clientIncludeUsage,
		OnUpstreamEvent: func(eventName string, data []byte) {
			observer.OnSSEEvent(eventName, data)
		},
		OnFirstToken: recordFirstToken,
	}

	switch inv.ingressProtocol {
	case ProtocolOpenAIChat:
		streamErr = translate.StreamAnthropicToOpenAI(resp.Body, w, flusher, opts)
	case ProtocolAnthropicMessages:
		streamErr = translate.StreamOpenAIToAnthropic(resp.Body, w, flusher, opts)
	default:
		streamErr = fmt.Errorf("unsupported streaming translation for %s", inv.ingressProtocol)
	}
}

// streamNativeSSE relays upstream SSE bytes using bufio.Reader (no 64 KiB Scanner
// limit), flushing at every event boundary and delivering decoded (eventName, data)
// frames to observer.OnSSEEvent.
//
// When suppressSyntheticUsage is true (meaning Headlamp injected stream_options.include_usage
// on behalf of a client that did not ask for it), the pure usage-only chunk
// (choices: [] && usage != nil && error == nil) is still delivered to observer.OnSSEEvent
// for metering but withheld from the downstream client.
func streamNativeSSE(
	upstream io.Reader,
	downstream io.Writer,
	flusher http.Flusher,
	observer StreamObserver,
	suppressSyntheticUsage bool,
	onFirstFrame func(),
) error {
	reader := bufio.NewReaderSize(upstream, 64*1024)

	var (
		eventName string
		dataBuf   bytes.Buffer
		frameBuf  bytes.Buffer
		hasData   bool
		hasEvent  bool
	)

	flushAndDispatch := func() error {
		var (
			data   []byte
			evName string
			hasEv  = hasData || hasEvent
		)
		if hasEv {
			data = bytes.Clone(dataBuf.Bytes())
			evName = eventName
			eventName = ""
			dataBuf.Reset()
			hasData = false
			hasEvent = false

			trimmed := bytes.TrimSpace(data)
			if !bytes.Equal(trimmed, []byte("[DONE]")) {
				observer.OnSSEEvent(evName, data)
			}
		}

		if suppressSyntheticUsage {
			if frameBuf.Len() > 0 {
				skipDownstream := hasEv && isSyntheticUsageOnlyChunk(data)
				if !skipDownstream {
					if onFirstFrame != nil {
						onFirstFrame()
					}
					if _, writeErr := downstream.Write(frameBuf.Bytes()); writeErr != nil {
						frameBuf.Reset()
						return writeErr
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				frameBuf.Reset()
			}
			return nil
		}

		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	for {
		line, readErr := translate.ReadLineLimited(reader, translate.MaxSSELineBytes)
		if len(line) > 0 {
			if suppressSyntheticUsage {
				frameBuf.Write(line)
			} else {
				if onFirstFrame != nil {
					onFirstFrame()
				}
				if _, writeErr := downstream.Write(line); writeErr != nil {
					if hasData || hasEvent {
						data := bytes.Clone(dataBuf.Bytes())
						if !bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
							observer.OnSSEEvent(eventName, data)
						}
					}
					return writeErr
				}
			}

			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) == 0 {
				if writeErr := flushAndDispatch(); writeErr != nil {
					return writeErr
				}
			} else if trimmed[0] != ':' {
				colon := bytes.IndexByte(trimmed, ':')
				var field, value string
				if colon < 0 {
					field = string(trimmed)
				} else {
					field = string(trimmed[:colon])
					val := trimmed[colon+1:]
					if len(val) > 0 && val[0] == ' ' {
						val = val[1:]
					}
					value = string(val)
				}
				switch field {
				case "event":
					eventName = value
					hasEvent = true
				case "data":
					if hasData {
						dataBuf.WriteByte('\n')
					}
					dataBuf.WriteString(value)
					hasData = true
				}
			}
		}

		if readErr != nil {
			writeErr := flushAndDispatch()
			if writeErr != nil {
				return writeErr
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func isSyntheticUsageOnlyChunk(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var probe struct {
		Choices json.RawMessage `json:"choices"`
		Usage   json.RawMessage `json:"usage"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false
	}
	if isJSONEmptyOrNull(probe.Usage) || !isJSONEmptyOrNull(probe.Error) {
		return false
	}
	choicesRaw := bytes.TrimSpace(probe.Choices)
	if len(choicesRaw) == 0 || bytes.Equal(choicesRaw, []byte("null")) {
		return true
	}
	var choices []json.RawMessage
	return json.Unmarshal(choicesRaw, &choices) == nil && len(choices) == 0
}

func isJSONEmptyOrNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// streamNativeJSONChunks relays non-SSE streaming responses (such as Gemini
// :streamGenerateContent without ?alt=sse) chunk-by-chunk while extracting
// usageMetadata from the accumulated JSON payload when complete.
func streamNativeJSONChunks(
	upstream io.Reader,
	downstream io.Writer,
	flusher http.Flusher,
	observer StreamObserver,
	maxCaptureBytes int64,
	onFirstByte func(),
) error {
	if maxCaptureBytes <= 0 {
		maxCaptureBytes = defaultMaxResponseBodyBytes
	}
	var captured bytes.Buffer
	buf := make([]byte, 16*1024)
	for {
		n, readErr := upstream.Read(buf)
		if n > 0 {
			if onFirstByte != nil {
				onFirstByte()
			}
			chunk := buf[:n]
			if _, writeErr := downstream.Write(chunk); writeErr != nil {
				return writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
			if int64(captured.Len()) < maxCaptureBytes {
				captured.Write(chunk)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				feedJSONArrayOrObject(captured.Bytes(), observer)
				return nil
			}
			return readErr
		}
	}
}

func feedJSONArrayOrObject(raw []byte, observer StreamObserver) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err == nil {
			for _, item := range items {
				observer.OnSSEEvent("", item)
			}
			return
		}
	}
	observer.OnJSONResponse(trimmed)
}

// patchJSONRequest rewrites only top-level "model" and/or force-merges
// "stream_options":{"include_usage":true}, preserving all other JSON fields
// (including sibling keys inside "stream_options") untouched.
//
// injectedIncludeUsage is true whenever injectStreamOptions was requested and
// the client did not already supply "stream_options": {"include_usage": true}.
func patchJSONRequest(body []byte, newModel string, injectStreamOptions bool) ([]byte, bool, error) {
	return patchJSONRequestWithStream(body, newModel, injectStreamOptions, nil)
}

func patchJSONRequestWithStream(body []byte, newModel string, injectStreamOptions bool, pinStream *bool) ([]byte, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false, fmt.Errorf("invalid JSON object: %w", err)
	}
	if fields == nil {
		return nil, false, errors.New("JSON body must be an object")
	}

	modified := false
	injectedIncludeUsage := false
	if newModel != "" {
		encodedModel, err := json.Marshal(newModel)
		if err != nil {
			return nil, false, err
		}
		fields["model"] = encodedModel
		modified = true
	}

	if pinStream != nil {
		if *pinStream {
			fields["stream"] = json.RawMessage("true")
			modified = true
		} else {
			if _, hasStream := fields["stream"]; hasStream {
				fields["stream"] = json.RawMessage("false")
				modified = true
			}
			if _, hasOpts := fields["stream_options"]; hasOpts {
				delete(fields, "stream_options")
				modified = true
			}
		}
	}

	if injectStreamOptions {
		raw, exists := fields["stream_options"]
		trimmed := bytes.TrimSpace(raw)
		if !exists || len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			fields["stream_options"] = json.RawMessage(`{"include_usage":true}`)
			modified = true
			injectedIncludeUsage = true
		} else {
			var opts map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &opts); err != nil || opts == nil {
				fields["stream_options"] = json.RawMessage(`{"include_usage":true}`)
				modified = true
				injectedIncludeUsage = true
			} else {
				var alreadyTrue bool
				if incRaw, hasInc := opts["include_usage"]; hasInc {
					_ = json.Unmarshal(incRaw, &alreadyTrue)
				}
				if !alreadyTrue {
					opts["include_usage"] = json.RawMessage("true")
					encodedOpts, err := json.Marshal(opts)
					if err != nil {
						return nil, false, err
					}
					fields["stream_options"] = encodedOpts
					modified = true
					injectedIncludeUsage = true
				}
			}
		}
	}

	if !modified {
		return body, false, nil
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	return encoded, injectedIncludeUsage, nil
}

func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

// sanitizeUpstreamError strips query strings and userinfo from *url.Error URLs
// so passthrough credentials (such as Gemini ?key=...) never leak into
// usage_logs.error_message or HTTP 502 error envelopes.
func sanitizeUpstreamError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cleanURL := urlErr.URL
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.User = nil
			cleanURL = parsed.String()
		}
		return fmt.Sprintf("%s %q: %v", urlErr.Op, cleanURL, urlErr.Err)
	}
	return err.Error()
}

func buildUpstreamURL(provider store.Provider, endpointPath, rawQuery string) string {
	base := strings.TrimRight(strings.TrimSpace(provider.BaseURL), "/")
	if base == "" {
		base = strings.TrimRight(config.DefaultBaseURL(provider.Type), "/")
	}

	// Avoid duplicating version prefixes when BaseURL already includes /v1 or /v1beta.
	if strings.HasPrefix(endpointPath, "/v1/") && strings.HasSuffix(base, "/v1") {
		base = strings.TrimSuffix(base, "/v1")
	} else if strings.HasPrefix(endpointPath, "/v1beta/") && strings.HasSuffix(base, "/v1beta") {
		base = strings.TrimSuffix(base, "/v1beta")
	}

	target := base + endpointPath
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	return target
}

func stripQueryParam(rawQuery, name string) string {
	if rawQuery == "" {
		return ""
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	vals.Del(name)
	return vals.Encode()
}

func applyUpstreamHeaders(upReq, inReq *http.Request, provider store.Provider, isNative bool) {
	upReq.Header.Set("Content-Type", "application/json")
	if accept := inReq.Header.Get("Accept"); accept != "" {
		upReq.Header.Set("Accept", accept)
	}
	if ua := inReq.Header.Get("User-Agent"); ua != "" {
		upReq.Header.Set("User-Agent", ua)
	}

	// Forward provider-specific non-auth headers on native passthrough.
	if isNative {
		switch provider.Type {
		case config.ProviderTypeAnthropic:
			for _, h := range []string{"Anthropic-Version", "Anthropic-Beta"} {
				for _, v := range inReq.Header.Values(h) {
					upReq.Header.Add(h, v)
				}
			}
		case config.ProviderTypeOpenAI:
			for _, h := range []string{"OpenAI-Organization", "OpenAI-Project", "OpenAI-Beta"} {
				if v := inReq.Header.Get(h); v != "" {
					upReq.Header.Set(h, v)
				}
			}
		}
	}

	// Ensure Anthropic always receives anthropic-version even when translated or omitted.
	if provider.Type == config.ProviderTypeAnthropic && upReq.Header.Get("Anthropic-Version") == "" {
		upReq.Header.Set("Anthropic-Version", defaultAnthropicVersion)
	}

	// Auth headers: passthrough forwards client credentials; managed injects encrypted-at-rest key.
	if provider.Passthrough {
		for _, h := range []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key"} {
			if v := inReq.Header.Get(h); v != "" {
				upReq.Header.Set(h, v)
			}
		}
		return
	}

	if provider.APIKey == "" {
		return
	}
	switch provider.Type {
	case config.ProviderTypeOpenAI, config.ProviderTypeOllama:
		upReq.Header.Set("Authorization", "Bearer "+provider.APIKey)
	case config.ProviderTypeAnthropic:
		upReq.Header.Set("x-api-key", provider.APIKey)
	case config.ProviderTypeGemini:
		upReq.Header.Set("x-goog-api-key", provider.APIKey)
	}
}

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-encoding":    {},
	"content-length":      {},
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if _, skip := hopByHopHeaders[strings.ToLower(k)]; skip {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
