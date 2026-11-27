package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/store"
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
