package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/store"
)

const maxJSONBodyBytes = 1 << 20 // 1 MiB

var awsIPv6IMDSAddr = netip.MustParseAddr("fd00:ec2::254")

// AuditController manages live audit payload settings and manual retention purges.
// Satisfied directly by *metering.Recorder.
type AuditController interface {
	AuditConfig() config.AuditConfig
	UpdateAuditConfig(config.AuditConfig)
	PurgeNow(ctx context.Context) (int64, error)
	PurgeOlderThan(ctx context.Context, maxAge time.Duration) (int64, error)
}

// BudgetStatusItem is the per-scope budget view returned to callers on GET /api/v1/me.
type BudgetStatusItem struct {
	Scope           string   `json:"scope"`
	DailyUSD        *float64 `json:"daily_usd"`
	DailySpentUSD   float64  `json:"daily_spent_usd"`
	MonthlyUSD      *float64 `json:"monthly_usd"`
	MonthlySpentUSD float64  `json:"monthly_spent_usd"`
	RPM             int      `json:"rpm"`
	TPM             int64    `json:"tpm"`
	MaxConcurrent   int      `json:"max_concurrent"`
	SoftAlertPct    int      `json:"soft_alert_pct"`
}

// BudgetAdminItem is the full admin budget view returned by GET /api/v1/admin/budgets.
type BudgetAdminItem struct {
	Scope           string    `json:"scope"`
	RPM             int       `json:"rpm"`
	TPM             int64     `json:"tpm"`
	MaxConcurrent   int       `json:"max_concurrent"`
	DailyUSD        *float64  `json:"daily_usd"`
	MonthlyUSD      *float64  `json:"monthly_usd"`
	DailySpentUSD   float64   `json:"daily_spent_usd"`
	MonthlySpentUSD float64   `json:"monthly_spent_usd"`
	SoftAlertPct    int       `json:"soft_alert_pct"`
	Enabled         bool      `json:"enabled"`
	Source          string    `json:"source"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// BudgetReporter reports live daily/monthly spend against configured budget scopes.
type BudgetReporter interface {
	StatusForPrincipal(ctx context.Context, p *auth.Principal) ([]BudgetStatusItem, error)
	ListAllStatuses(ctx context.Context) ([]BudgetAdminItem, error)
}

// GuardrailMatch describes one rule hit from POST /api/v1/admin/guardrails/test.
type GuardrailMatch struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Action   string `json:"action"`
}

// GuardrailTestResult is the response payload of POST /api/v1/admin/guardrails/test.
type GuardrailTestResult struct {
	Action       string           `json:"action"`
	RedactedText string           `json:"redacted_text"`
	Matches      []GuardrailMatch `json:"matches"`
}

// GuardrailTester evaluates sample text against active guardrail rules.
type GuardrailTester interface {
	TestText(ctx context.Context, text string) (*GuardrailTestResult, error)
}

// WebhookTestResult is the response payload of POST /api/v1/admin/webhooks/{id}/test.
type WebhookTestResult struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code"`
	LatencyMS  int64  `json:"latency_ms"`
	Message    string `json:"message"`
}

// WebhookTester dispatches a live test ping to a configured webhook.
type WebhookTester interface {
	PingWebhook(ctx context.Context, wh store.Webhook) (*WebhookTestResult, error)
}

// Config configures the Headlamp Admin & User REST API handler and optional embedded SPA.
type Config struct {
	Store           store.Store
	Policy          *policy.Evaluator
	Pricing         *metering.PricingTable
	AuditController AuditController
	BudgetReporter  BudgetReporter
	GuardrailTester GuardrailTester
	WebhookTester   WebhookTester
	StaticFS        fs.FS
	HTTPClient      *http.Client
}

// Handler serves Headlamp's /api/v1/* endpoints and optional embedded React SPA.
type Handler struct {
	store           store.Store
	policy          *policy.Evaluator
	pricing         *metering.PricingTable
	auditController AuditController
	budgetReporter  BudgetReporter
	guardrailTester GuardrailTester
	webhookTester   WebhookTester
	staticFS        fs.FS
	httpClient      *http.Client
}

// NewHandler constructs a validated API Handler.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	eval := cfg.Policy
	if eval == nil {
		eval = policy.NewEvaluator()
	}
	pricing := cfg.Pricing
	if pricing == nil {
		var err error
		pricing, err = metering.LoadDefault()
		if err != nil {
			return nil, fmt.Errorf("api: load default pricing: %w", err)
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = newSafeProbeHTTPClient()
	}

	return &Handler{
		store:           cfg.Store,
		policy:          eval,
		pricing:         pricing,
		auditController: cfg.AuditController,
		budgetReporter:  cfg.BudgetReporter,
		guardrailTester: cfg.GuardrailTester,
		webhookTester:   cfg.WebhookTester,
		staticFS:        cfg.StaticFS,
		httpClient:      client,
	}, nil
}

// IsGatewayReservedPath reports whether reqPath belongs to Headlamp's LLM proxy or health/whoami
// endpoints so the embedded SPA never shadows them.
func IsGatewayReservedPath(reqPath string) bool {
	if reqPath == "/healthz" || reqPath == "/whoami" {
		return true
	}
	for _, prefix := range []string{"/v1", "/openai", "/anthropic", "/gemini"} {
		if reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/") {
			return true
		}
	}
	return false
}

// HandlesPath reports whether this handler owns reqPath (either /api/* or non-reserved UI paths when StaticFS is set).
func (h *Handler) HandlesPath(reqPath string) bool {
	if strings.HasPrefix(reqPath, "/api/") || reqPath == "/api" {
		return true
	}
	if h.staticFS != nil && !IsGatewayReservedPath(reqPath) {
		return true
	}
	return false
}

// ServeHTTP routes /api/v1/* endpoints (enforcing auth, CSRF, and admin RBAC) and optional SPA static assets.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
		h.serveAPI(w, r)
		return
	}
	if h.staticFS != nil && !IsGatewayReservedPath(r.URL.Path) {
		h.serveStatic(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "route not found")
}

func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_error", "unauthenticated")
		return
	}

	if isMutatingMethod(r.Method) {
		if err := checkSameOriginCSRF(r); err != nil {
			writeError(w, http.StatusForbidden, "csrf_error", err.Error())
			return
		}
	}

	pPath := r.URL.Path

	// Authenticated user endpoints (non-admin allowed).
	switch pPath {
	case "/api/v1/me":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleMe(w, r, p)
		return
	case "/api/v1/me/usage":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleMeUsage(w, r, p)
		return
	}

	// Admin endpoints require admin role.
	if strings.HasPrefix(pPath, "/api/v1/admin/") || pPath == "/api/v1/admin" {
		isAdmin, err := h.policy.IsAdmin(r.Context(), p)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if !isAdmin {
			writeError(w, http.StatusForbidden, "permission_error", "admin role required")
			return
		}
		h.serveAdmin(w, r, p)
		return
	}

	writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
}

func (h *Handler) serveAdmin(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/v1/admin")

	switch {
	case sub == "/overview":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleAdminOverview(w, r)

	case sub == "/providers":
		switch r.Method {
		case http.MethodGet:
			h.handleAdminListProviders(w, r)
		case http.MethodPost:
			h.handleAdminCreateProvider(w, r)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
		}

	case strings.HasPrefix(sub, "/providers/"):
		rest := strings.TrimPrefix(sub, "/providers/")
		if strings.HasSuffix(rest, "/test") {
			name := strings.TrimSuffix(rest, "/test")
			if name == "" {
				writeError(w, http.StatusNotFound, "not_found", "provider name required")
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			h.handleAdminTestProvider(w, r, name)
			return
		}
		switch r.Method {
		case http.MethodPut:
			h.handleAdminUpdateProvider(w, r, rest)
		case http.MethodDelete:
			h.handleAdminDeleteProvider(w, r, rest)
		default:
			writeMethodNotAllowed(w, http.MethodPut, http.MethodDelete)
		}

	case sub == "/routes" || strings.HasPrefix(sub, "/routes/"):
		pathAlias := strings.TrimPrefix(sub, "/routes")
		pathAlias = strings.TrimPrefix(pathAlias, "/")
		switch r.Method {
		case http.MethodGet:
			if pathAlias != "" {
				writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
				return
			}
			h.handleAdminListRoutes(w, r)
		case http.MethodPost:
			if pathAlias != "" {
				writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
				return
			}
			h.handleAdminCreateRoute(w, r)
		case http.MethodPut:
			alias := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("alias")), pathAlias)
			h.handleAdminUpdateRoute(w, r, alias)
		case http.MethodDelete:
			alias := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("alias")), pathAlias)
			h.handleAdminDeleteRoute(w, r, alias)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete)
		}

	case sub == "/pricing":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleAdminPricing(w, r)

	case sub == "/budgets" || strings.HasPrefix(sub, "/budgets/"):
		pathScope := strings.TrimPrefix(sub, "/budgets")
		pathScope = strings.TrimPrefix(pathScope, "/")
		switch r.Method {
		case http.MethodGet:
			if pathScope != "" {
				writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
				return
			}
			h.handleAdminListBudgets(w, r)
		case http.MethodPost:
			if pathScope != "" {
				writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
				return
			}
			h.handleAdminCreateBudget(w, r)
		case http.MethodPut:
			scope := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("scope")), pathScope)
			h.handleAdminUpdateBudget(w, r, scope)
		case http.MethodDelete:
			scope := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("scope")), pathScope)
			h.handleAdminDeleteBudget(w, r, scope)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete)
		}

	case sub == "/grants-guide":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleAdminGrantsGuide(w, r, p)

	case sub == "/logs":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		h.handleAdminLogs(w, r)

	case strings.HasPrefix(sub, "/logs/") && strings.HasSuffix(sub, "/payload"):
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(sub, "/logs/"), "/payload")
		h.handleAdminLogPayload(w, r, id)

	case sub == "/settings/audit":
		switch r.Method {
		case http.MethodGet:
			h.handleAdminGetAuditSettings(w, r)
		case http.MethodPut:
			h.handleAdminPutAuditSettings(w, r)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPut)
		}

	case sub == "/settings/audit/purge":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		h.handleAdminPurgeAudit(w, r)

	case sub == "/guardrails":
		switch r.Method {
		case http.MethodGet:
			h.handleAdminListGuardrails(w, r)
		case http.MethodPost:
			h.handleAdminCreateGuardrail(w, r)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
		}

	case sub == "/guardrails/test":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		h.handleAdminTestGuardrails(w, r)

	case strings.HasPrefix(sub, "/guardrails/"):
		id := strings.TrimPrefix(sub, "/guardrails/")
		switch r.Method {
		case http.MethodPut:
			h.handleAdminUpdateGuardrail(w, r, id)
		case http.MethodDelete:
			h.handleAdminDeleteGuardrail(w, r, id)
		default:
			writeMethodNotAllowed(w, http.MethodPut, http.MethodDelete)
		}

	case sub == "/webhooks":
		switch r.Method {
		case http.MethodGet:
			h.handleAdminListWebhooks(w, r)
		case http.MethodPost:
			h.handleAdminCreateWebhook(w, r)
		default:
			writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
		}

	case strings.HasPrefix(sub, "/webhooks/"):
		rest := strings.TrimPrefix(sub, "/webhooks/")
		if strings.HasSuffix(rest, "/test") {
			id := strings.TrimSuffix(rest, "/test")
			if id == "" {
				writeError(w, http.StatusNotFound, "not_found", "webhook id required")
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			h.handleAdminTestWebhook(w, r, id)
			return
		}
		switch r.Method {
		case http.MethodPut:
			h.handleAdminUpdateWebhook(w, r, rest)
		case http.MethodDelete:
			h.handleAdminDeleteWebhook(w, r, rest)
		default:
			writeMethodNotAllowed(w, http.MethodPut, http.MethodDelete)
		}

	default:
		writeError(w, http.StatusNotFound, "not_found", "admin endpoint not found")
	}
}

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeMethodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}

	cleaned := path.Clean("/" + r.URL.Path)
	rel := strings.TrimPrefix(cleaned, "/")
	if rel != "" {
		if info, err := fs.Stat(h.staticFS, rel); err == nil && !info.IsDir() {
			if strings.HasPrefix(rel, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.FileServerFS(h.staticFS).ServeHTTP(w, r)
			return
		}
	}

	indexBytes, err := fs.ReadFile(h.staticFS, "index.html")
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "ui bundle not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(indexBytes)
	}
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func newSafeProbeHTTPClient() *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   ssrfSafeDialControl,
	}
	base.DialContext = dialer.DialContext
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: base,
		// Never follow redirects on upstream probes so vendor auth headers
		// (x-api-key, x-goog-api-key, Authorization) cannot leak across hosts.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ssrfSafeDialControl blocks connections to cloud metadata and link-local/unspecified/multicast
// destinations after DNS resolution, preventing SSRF and DNS-rebinding probes against IMDS
// while still allowing local Ollama (127.0.0.1/::1), Tailnet peers, and public APIs.
func ssrfSafeDialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("probe dial blocked: invalid resolved address %q", address)
	}
	addr := ap.Addr().Unmap()
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() || addr.WithZone("") == awsIPv6IMDSAddr {
		return fmt.Errorf("probe dial blocked: destination IP %s is a restricted link-local, metadata, multicast, or unspecified address", addr)
	}
	return nil
}

// checkSameOriginCSRF enforces same-origin validation whenever browser fetch headers
// (Origin or Sec-Fetch-Site) are present, while permitting non-browser tailnet CLI calls.
// For local frontend development proxies (e.g. Vite on localhost:5173 -> 127.0.0.1:8080),
// cross-port/loopback-alias requests are allowed ONLY when RemoteAddr, Origin, and Host are
// all strictly loopback.
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

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is empty")
		}
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, errType, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"type":    errType,
			"message": message,
		},
	})
}

func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
