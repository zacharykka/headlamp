package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/store"
)

func configManagedConflictMessage(resource, id string) string {
	return fmt.Sprintf("%s %q is managed by headlamp.yaml (source=config) and is read-only via the API; edit headlamp.yaml and restart", resource, id)
}

// --- User Endpoints (/api/v1/me*) ---

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	ep, err := h.policy.Evaluate(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	budgetStatuses, err := h.budgetStatusesForPrincipal(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	tags := p.Tags
	if tags == nil {
		tags = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"principal": map[string]any{
			"subject":      p.Subject,
			"display_name": p.DisplayName,
			"node_name":    p.NodeName,
			"node_ip":      p.NodeIP,
			"tags":         tags,
			"auth_source":  p.AuthSource,
		},
		"is_admin":      ep.IsAdmin(),
		"policy":        normalizePolicyView(ep),
		"budget_status": budgetStatuses,
	})
}

func normalizePolicyView(ep *policy.EffectivePolicy) map[string]any {
	if ep == nil {
		return map[string]any{
			"subject":         "",
			"roles":           []string{},
			"allow_models":    []string{},
			"deny_models":     []string{},
			"allow_mcp_tools": []string{},
			"deny_mcp_tools":  []string{},
			"grants_applied":  false,
		}
	}
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return map[string]any{
		"subject":         ep.Subject,
		"roles":           nonNil(ep.Roles),
		"allow_models":    nonNil(ep.AllowModels),
		"deny_models":     nonNil(ep.DenyModels),
		"allow_mcp_tools": nonNil(ep.AllowMCPTools),
		"deny_mcp_tools":  nonNil(ep.DenyMCPTools),
		"grants_applied":  ep.GrantsApplied,
	}
}

func (h *Handler) handleMeUsage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	window, since, bucket := parseWindow(r.URL.Query().Get("window"))
	_ = window
	limit := parseIntQuery(r, "limit", 50, 1, 500)
	offset := parseIntQuery(r, "offset", 0, 0, 100000)

	baseFilter := store.UsageFilter{
		Subject: p.Subject,
		Since:   since,
	}
	summary, err := h.store.SummarizeUsageExtended(r.Context(), baseFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	series, err := h.store.QueryUsageSeries(r.Context(), baseFilter, bucket)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if series == nil {
		series = []store.UsageTimeBucket{}
	}

	logFilter := baseFilter
	logFilter.Limit = limit
	logFilter.Offset = offset
	logs, err := h.store.QueryUsageLogs(r.Context(), logFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	logs = normalizeUsageLogs(logs)

	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"series":  series,
		"logs":    logs,
	})
}

// --- Admin Overview ---

func (h *Handler) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	window, since, bucket := parseWindow(r.URL.Query().Get("window"))
	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	todaySum, err := h.store.SummarizeUsage(r.Context(), store.UsageFilter{Since: todayStart})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	monthSum, err := h.store.SummarizeUsage(r.Context(), store.UsageFilter{Since: monthStart})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	filter := store.UsageFilter{Since: since}
	summary, err := h.store.SummarizeUsageExtended(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	series, err := h.store.QueryUsageSeries(r.Context(), filter, bucket)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if series == nil {
		series = []store.UsageTimeBucket{}
	}
	topSubjects, err := h.store.QueryTopSubjects(r.Context(), filter, 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if topSubjects == nil {
		topSubjects = []store.SubjectUsageStat{}
	}
	topModels, err := h.store.QueryTopModels(r.Context(), filter, 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if topModels == nil {
		topModels = []store.ModelUsageStat{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window":         window,
		"today_cost_usd": todaySum.CostUSD,
		"month_cost_usd": monthSum.CostUSD,
		"summary":        summary,
		"series":         series,
		"top_subjects":   topSubjects,
		"top_models":     topModels,
	})
}

// --- Admin Providers ---

type providerResponse struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	BaseURL       string    `json:"base_url"`
	HasAPIKey     bool      `json:"has_api_key"`
	APIKeyPreview string    `json:"api_key_preview"`
	Passthrough   bool      `json:"passthrough"`
	Models        []string  `json:"models"`
	Enabled       bool      `json:"enabled"`
	Source        string    `json:"source"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func toProviderResponse(p store.Provider) providerResponse {
	models := p.Models
	if models == nil {
		models = []string{}
	}
	return providerResponse{
		Name:          p.Name,
		Type:          p.Type,
		BaseURL:       p.BaseURL,
		HasAPIKey:     p.APIKey != "",
		APIKeyPreview: maskSecret(p.APIKey),
		Passthrough:   p.Passthrough,
		Models:        models,
		Enabled:       p.Enabled,
		Source:        p.Source,
		UpdatedAt:     p.UpdatedAt,
	}
}

type providerRequest struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	BaseURL     string   `json:"base_url"`
	APIKey      string   `json:"api_key"`
	ClearAPIKey bool     `json:"clear_api_key"`
	Passthrough *bool    `json:"passthrough"`
	Models      []string `json:"models"`
	Enabled     *bool    `json:"enabled"`
}

func (h *Handler) handleAdminListProviders(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	out := make([]providerResponse, 0, len(list))
	for _, p := range list {
		out = append(out, toProviderResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (h *Handler) handleAdminCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req providerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	p, err := validateProviderPayload(req.Name, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if existing, err := h.store.GetProvider(r.Context(), p.Name); err == nil {
		if existing.Source == store.SourceConfig {
			writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("provider", p.Name))
			return
		}
		writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("provider %q already exists", p.Name))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := h.store.UpsertProvider(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetProvider(r.Context(), p.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toProviderResponse(*saved))
}

func (h *Handler) handleAdminUpdateProvider(w http.ResponseWriter, r *http.Request, name string) {
	existing, err := h.store.GetProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("provider %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("provider", name))
		return
	}
	var req providerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	p, err := validateProviderPayload(name, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertProvider(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetProvider(r.Context(), p.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toProviderResponse(*saved))
}

func (h *Handler) handleAdminDeleteProvider(w http.ResponseWriter, r *http.Request, name string) {
	existing, err := h.store.GetProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("provider %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("provider", name))
		return
	}
	if err := h.store.DeleteProvider(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("provider %q not found", name))
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("provider %q is referenced by existing routes", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (h *Handler) handleAdminTestProvider(w http.ResponseWriter, r *http.Request, name string) {
	p, err := h.store.GetProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("provider %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	probeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	probeURL, ok := buildProviderProbeURL(p.Type, p.BaseURL)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": 0,
			"message":    fmt.Sprintf("unsupported provider type %q", p.Type),
		})
		return
	}

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": 0,
			"message":    sanitizeNetError(err),
		})
		return
	}
	switch p.Type {
	case config.ProviderTypeOpenAI:
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}
	case config.ProviderTypeAnthropic:
		if p.APIKey != "" {
			req.Header.Set("x-api-key", p.APIKey)
		}
		req.Header.Set("anthropic-version", "2023-06-01")
	case config.ProviderTypeGemini:
		if p.APIKey != "" {
			req.Header.Set("x-goog-api-key", p.APIKey)
		}
	case config.ProviderTypeOllama:
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}
	}

	start := time.Now()
	resp, err := h.httpClient.Do(req)
	latencyMS := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": latencyMS,
			"message":    sanitizeNetError(err),
		})
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	probeOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	msg := fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         probeOK,
		"latency_ms": latencyMS,
		"message":    msg,
	})
}

func buildProviderProbeURL(providerType, baseURL string) (string, bool) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	switch providerType {
	case config.ProviderTypeOpenAI, config.ProviderTypeAnthropic:
		if strings.HasSuffix(base, "/v1") {
			return base + "/models", true
		}
		return base + "/v1/models", true
	case config.ProviderTypeGemini:
		if strings.HasSuffix(base, "/v1beta") {
			return base + "/models", true
		}
		return base + "/v1beta/models", true
	case config.ProviderTypeOllama:
		if strings.HasSuffix(base, "/v1") {
			return base + "/models", true
		}
		return base + "/api/tags", true
	default:
		return "", false
	}
}

func validateProviderPayload(name string, req providerRequest, existing *store.Provider) (store.Provider, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return store.Provider{}, errors.New("provider name is required")
	}
	if strings.Contains(name, "/") {
		return store.Provider{}, errors.New("provider name must not contain '/'")
	}
	pType := strings.ToLower(strings.TrimSpace(req.Type))
	if pType == "" && existing != nil {
		pType = existing.Type
	}
	switch pType {
	case config.ProviderTypeOpenAI, config.ProviderTypeAnthropic, config.ProviderTypeGemini, config.ProviderTypeOllama:
	default:
		return store.Provider{}, fmt.Errorf("type %q must be openai, anthropic, gemini, or ollama", pType)
	}
	baseURL := strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if baseURL == "" {
		if existing != nil && existing.Type == pType && existing.BaseURL != "" {
			baseURL = existing.BaseURL
		} else {
			baseURL = config.DefaultBaseURL(pType)
		}
	}
	if err := validateHTTPURL(baseURL); err != nil {
		return store.Provider{}, fmt.Errorf("base_url: %w", err)
	}

	apiKey := req.APIKey
	if existing != nil {
		if req.ClearAPIKey {
			apiKey = ""
		} else if apiKey == "" {
			apiKey = existing.APIKey
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	models := req.Models
	if models == nil {
		if existing != nil && existing.Models != nil {
			models = existing.Models
		} else {
			models = []string{}
		}
	}

	passthrough := false
	if req.Passthrough != nil {
		passthrough = *req.Passthrough
	} else if existing != nil {
		passthrough = existing.Passthrough
	}

	return store.Provider{
		Name:        name,
		Type:        pType,
		BaseURL:     baseURL,
		APIKey:      apiKey,
		Passthrough: passthrough,
		Models:      models,
		Enabled:     enabled,
		Source:      store.SourceLocal,
	}, nil
}

// --- Admin Routes & Pricing ---

type routeRequest struct {
	Alias                    string              `json:"alias"`
	ProviderName             string              `json:"provider_name"`
	UpstreamModel            string              `json:"upstream_model"`
	Fallbacks                []store.RouteTarget `json:"fallbacks"`
	InputCostPerMillion      *float64            `json:"input_cost_per_million"`
	OutputCostPerMillion     *float64            `json:"output_cost_per_million"`
	CacheReadCostPerMillion  *float64            `json:"cache_read_cost_per_million"`
	CacheWriteCostPerMillion *float64            `json:"cache_write_cost_per_million"`
	Enabled                  *bool               `json:"enabled"`
}

func (h *Handler) handleAdminListRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := h.store.ListModelRoutes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if routes == nil {
		routes = []store.ModelRoute{}
	}
	for i := range routes {
		if routes[i].Fallbacks == nil {
			routes[i].Fallbacks = []store.RouteTarget{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": routes})
}

func (h *Handler) handleAdminCreateRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	route, err := h.validateRoutePayload(r.Context(), req.Alias, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if existing, err := h.store.GetModelRoute(r.Context(), route.Alias); err == nil {
		if existing.Source == store.SourceConfig {
			writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("route", route.Alias))
			return
		}
		writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("route %q already exists", route.Alias))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := h.store.UpsertModelRoute(r.Context(), route); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetModelRoute(r.Context(), route.Alias)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (h *Handler) handleAdminUpdateRoute(w http.ResponseWriter, r *http.Request, alias string) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "route alias is required")
		return
	}
	existing, err := h.store.GetModelRoute(r.Context(), alias)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("route %q not found", alias))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("route", alias))
		return
	}
	var req routeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	route, err := h.validateRoutePayload(r.Context(), alias, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertModelRoute(r.Context(), route); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetModelRoute(r.Context(), route.Alias)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (h *Handler) handleAdminDeleteRoute(w http.ResponseWriter, r *http.Request, alias string) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "route alias is required")
		return
	}
	existing, err := h.store.GetModelRoute(r.Context(), alias)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("route %q not found", alias))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("route", alias))
		return
	}
	if err := h.store.DeleteModelRoute(r.Context(), alias); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("route %q not found", alias))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": alias})
}

func (h *Handler) validateRoutePayload(ctx context.Context, alias string, req routeRequest, existing *store.ModelRoute) (store.ModelRoute, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return store.ModelRoute{}, errors.New("alias is required")
	}
	provName := strings.TrimSpace(req.ProviderName)
	if provName == "" && existing != nil {
		provName = existing.ProviderName
	}
	if provName == "" {
		return store.ModelRoute{}, errors.New("provider_name is required")
	}
	if _, err := h.store.GetProvider(ctx, provName); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ModelRoute{}, fmt.Errorf("provider %q does not exist", provName)
		}
		return store.ModelRoute{}, err
	}
	model := strings.TrimSpace(req.UpstreamModel)
	if model == "" && existing != nil {
		model = existing.UpstreamModel
	}
	if model == "" {
		return store.ModelRoute{}, errors.New("upstream_model is required")
	}

	fallbacks := req.Fallbacks
	if fallbacks == nil {
		if existing != nil && existing.Fallbacks != nil {
			fallbacks = existing.Fallbacks
		} else {
			fallbacks = []store.RouteTarget{}
		}
	}
	for i, fb := range fallbacks {
		if strings.TrimSpace(fb.Provider) == "" || strings.TrimSpace(fb.Model) == "" {
			return store.ModelRoute{}, fmt.Errorf("fallbacks[%d] requires provider and model", i)
		}
		if _, err := h.store.GetProvider(ctx, fb.Provider); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return store.ModelRoute{}, fmt.Errorf("fallbacks[%d].provider %q does not exist", i, fb.Provider)
			}
			return store.ModelRoute{}, err
		}
	}

	for name, val := range map[string]*float64{
		"input_cost_per_million":       req.InputCostPerMillion,
		"output_cost_per_million":      req.OutputCostPerMillion,
		"cache_read_cost_per_million":  req.CacheReadCostPerMillion,
		"cache_write_cost_per_million": req.CacheWriteCostPerMillion,
	} {
		if val != nil && *val < 0 {
			return store.ModelRoute{}, fmt.Errorf("%s must be non-negative", name)
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	return store.ModelRoute{
		Alias:                    alias,
		ProviderName:             provName,
		UpstreamModel:            model,
		Fallbacks:                fallbacks,
		InputCostPerMillion:      req.InputCostPerMillion,
		OutputCostPerMillion:     req.OutputCostPerMillion,
		CacheReadCostPerMillion:  req.CacheReadCostPerMillion,
		CacheWriteCostPerMillion: req.CacheWriteCostPerMillion,
		Enabled:                  enabled,
		Source:                   store.SourceLocal,
	}, nil
}

func (h *Handler) handleAdminPricing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"exact":    h.pricing.ExactModels(),
		"patterns": h.pricing.Patterns(),
	})
}

// --- Admin Budgets ---

type budgetRequest struct {
	Scope         string   `json:"scope"`
	RPM           int      `json:"rpm"`
	TPM           int64    `json:"tpm"`
	MaxConcurrent int      `json:"max_concurrent"`
	DailyUSD      *float64 `json:"daily_usd"`
	MonthlyUSD    *float64 `json:"monthly_usd"`
	SoftAlertPct  int      `json:"soft_alert_pct"`
	Enabled       *bool    `json:"enabled"`
}

func (h *Handler) handleAdminListBudgets(w http.ResponseWriter, r *http.Request) {
	items, err := h.allBudgetStatuses(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"budgets": items})
}

func (h *Handler) handleAdminCreateBudget(w http.ResponseWriter, r *http.Request) {
	var req budgetRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	b, err := validateBudgetPayload(req.Scope, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if existing, err := h.store.GetBudget(r.Context(), b.Scope); err == nil {
		if existing.Source == store.SourceConfig {
			writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("budget", b.Scope))
			return
		}
		writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("budget for scope %q already exists", b.Scope))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := h.store.UpsertBudget(r.Context(), b); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetBudget(r.Context(), b.Scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	item, err := h.budgetAdminItemForBudget(r.Context(), *saved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *Handler) handleAdminUpdateBudget(w http.ResponseWriter, r *http.Request, scope string) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "budget scope is required")
		return
	}
	existing, err := h.store.GetBudget(r.Context(), scope)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("budget for scope %q not found", scope))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("budget", scope))
		return
	}
	var req budgetRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	b, err := validateBudgetPayload(scope, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertBudget(r.Context(), b); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetBudget(r.Context(), b.Scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	item, err := h.budgetAdminItemForBudget(r.Context(), *saved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) handleAdminDeleteBudget(w http.ResponseWriter, r *http.Request, scope string) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "budget scope is required")
		return
	}
	existing, err := h.store.GetBudget(r.Context(), scope)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("budget for scope %q not found", scope))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("budget", scope))
		return
	}
	if err := h.store.DeleteBudget(r.Context(), scope); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("budget for scope %q not found", scope))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": scope})
}

func (h *Handler) budgetAdminItemForBudget(ctx context.Context, b store.Budget) (BudgetAdminItem, error) {
	if h.budgetReporter != nil {
		items, err := h.budgetReporter.ListAllStatuses(ctx)
		if err != nil {
			return BudgetAdminItem{}, err
		}
		for _, item := range items {
			if item.Scope == b.Scope {
				return item, nil
			}
		}
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	daySpent, monthSpent, err := h.scopeSpendFromStore(ctx, b.Scope, dayStart, monthStart)
	if err != nil {
		return BudgetAdminItem{}, err
	}
	return BudgetAdminItem{
		Scope:           b.Scope,
		RPM:             b.RPM,
		TPM:             b.TPM,
		MaxConcurrent:   b.MaxConcurrent,
		DailyUSD:        b.DailyUSD,
		MonthlyUSD:      b.MonthlyUSD,
		DailySpentUSD:   daySpent,
		MonthlySpentUSD: monthSpent,
		SoftAlertPct:    b.SoftAlertPct,
		Enabled:         b.Enabled,
		Source:          b.Source,
		UpdatedAt:       b.UpdatedAt,
	}, nil
}

func validateBudgetPayload(scope string, req budgetRequest, existing *store.Budget) (store.Budget, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return store.Budget{}, errors.New("scope is required")
	}
	if req.RPM < 0 {
		return store.Budget{}, errors.New("rpm must be >= 0")
	}
	if req.TPM < 0 {
		return store.Budget{}, errors.New("tpm must be >= 0")
	}
	if req.MaxConcurrent < 0 {
		return store.Budget{}, errors.New("max_concurrent must be >= 0")
	}
	if req.DailyUSD != nil && *req.DailyUSD < 0 {
		return store.Budget{}, errors.New("daily_usd must be non-negative")
	}
	if req.MonthlyUSD != nil && *req.MonthlyUSD < 0 {
		return store.Budget{}, errors.New("monthly_usd must be non-negative")
	}
	softPct := req.SoftAlertPct
	if softPct == 0 {
		if existing != nil && existing.SoftAlertPct > 0 {
			softPct = existing.SoftAlertPct
		} else {
			softPct = 80
		}
	}
	if softPct < 1 || softPct > 100 {
		return store.Budget{}, errors.New("soft_alert_pct must be between 1 and 100")
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	return store.Budget{
		Scope:         scope,
		RPM:           req.RPM,
		TPM:           req.TPM,
		MaxConcurrent: req.MaxConcurrent,
		DailyUSD:      req.DailyUSD,
		MonthlyUSD:    req.MonthlyUSD,
		SoftAlertPct:  softPct,
		Enabled:       enabled,
		Source:        store.SourceLocal,
	}, nil
}

func (h *Handler) budgetStatusesForPrincipal(ctx context.Context, p *auth.Principal) ([]BudgetStatusItem, error) {
	if h.budgetReporter != nil {
		items, err := h.budgetReporter.StatusForPrincipal(ctx, p)
		if err != nil {
			return nil, err
		}
		if items == nil {
			return []BudgetStatusItem{}, nil
		}
		return items, nil
	}

	// Fallback when BudgetReporter is not wired: compute spend directly from store.
	budgets, err := h.store.ListBudgets(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	out := make([]BudgetStatusItem, 0)
	for _, b := range budgets {
		if !b.Enabled || !budgetAppliesToPrincipal(b.Scope, p) {
			continue
		}
		daySpent, monthSpent, err := h.scopeSpendFromStore(ctx, b.Scope, dayStart, monthStart)
		if err != nil {
			return nil, err
		}
		out = append(out, BudgetStatusItem{
			Scope:           b.Scope,
			DailyUSD:        b.DailyUSD,
			DailySpentUSD:   daySpent,
			MonthlyUSD:      b.MonthlyUSD,
			MonthlySpentUSD: monthSpent,
			RPM:             b.RPM,
			TPM:             b.TPM,
			MaxConcurrent:   b.MaxConcurrent,
			SoftAlertPct:    b.SoftAlertPct,
		})
	}
	return out, nil
}

func (h *Handler) allBudgetStatuses(ctx context.Context) ([]BudgetAdminItem, error) {
	if h.budgetReporter != nil {
		items, err := h.budgetReporter.ListAllStatuses(ctx)
		if err != nil {
			return nil, err
		}
		if items == nil {
			return []BudgetAdminItem{}, nil
		}
		return items, nil
	}

	budgets, err := h.store.ListBudgets(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	out := make([]BudgetAdminItem, 0, len(budgets))
	for _, b := range budgets {
		daySpent, monthSpent, err := h.scopeSpendFromStore(ctx, b.Scope, dayStart, monthStart)
		if err != nil {
			return nil, err
		}
		out = append(out, BudgetAdminItem{
			Scope:           b.Scope,
			RPM:             b.RPM,
			TPM:             b.TPM,
			MaxConcurrent:   b.MaxConcurrent,
			DailyUSD:        b.DailyUSD,
			MonthlyUSD:      b.MonthlyUSD,
			DailySpentUSD:   daySpent,
			MonthlySpentUSD: monthSpent,
			SoftAlertPct:    b.SoftAlertPct,
			Enabled:         b.Enabled,
			Source:          b.Source,
			UpdatedAt:       b.UpdatedAt,
		})
	}
	return out, nil
}

func (h *Handler) scopeSpendFromStore(ctx context.Context, scope string, dayStart, monthStart time.Time) (float64, float64, error) {
	filterFor := func(since time.Time) store.UsageFilter {
		f := store.UsageFilter{Since: since}
		switch {
		case scope == "*":
		case strings.HasPrefix(scope, "tag:"):
			f.Tag = scope
		default:
			f.Subject = scope
		}
		return f
	}
	daySum, err := h.store.SummarizeUsage(ctx, filterFor(dayStart))
	if err != nil {
		return 0, 0, err
	}
	monthSum, err := h.store.SummarizeUsage(ctx, filterFor(monthStart))
	if err != nil {
		return 0, 0, err
	}
	return daySum.CostUSD, monthSum.CostUSD, nil
}

func budgetAppliesToPrincipal(scope string, p *auth.Principal) bool {
	if scope == "*" {
		return true
	}
	if p == nil {
		return false
	}
	if strings.HasPrefix(scope, "tag:") {
		return p.Subject == scope || p.HasTag(scope)
	}
	return p.Subject == scope
}

// --- Admin Grants Guide ---

const headscaleGrantsExample = `{
  "groups": {
    "group:admins": ["alice@"],
    "group:engineering": ["alice@", "bob@"]
  },
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },
  "grants": [
    {
      "src": ["group:admins"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "admin",
            "models": ["**"],
            "mcp_tools": ["**"]
          }
        ]
      }
    },
    {
      "src": ["group:engineering"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["anthropic/*", "openai/gpt-5*", "gemini/*", "ollama/*", "team/*"],
            "deny_models": ["openai/o3*"],
            "mcp_tools": ["docs/*", "github/read_*"]
          }
        ]
      }
    }
  ]
}`

func (h *Handler) handleAdminGrantsGuide(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	ep, err := h.policy.Evaluate(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":            normalizePolicyView(ep),
		"headscale_example": headscaleGrantsExample,
	})
}

// --- Admin Logs, Payload & Audit Settings ---

func (h *Handler) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.UsageFilter{
		Subject:      strings.TrimSpace(q.Get("subject")),
		ProviderName: strings.TrimSpace(q.Get("provider")),
		Model:        strings.TrimSpace(q.Get("model")),
	}
	if statusStr := strings.TrimSpace(q.Get("status")); statusStr != "" {
		code, err := strconv.Atoi(statusStr)
		if err != nil || code < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid status query parameter")
			return
		}
		filter.StatusCode = code
	}
	if grStr := strings.TrimSpace(q.Get("guardrail_only")); grStr != "" {
		b, err := strconv.ParseBool(grStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid guardrail_only query parameter")
			return
		}
		filter.GuardrailOnly = b
	}
	if sinceStr := strings.TrimSpace(q.Get("since")); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "since must be RFC3339 timestamp")
			return
		}
		filter.Since = t
	}
	if untilStr := strings.TrimSpace(q.Get("until")); untilStr != "" {
		t, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "until must be RFC3339 timestamp")
			return
		}
		filter.Until = t
	}

	summary, err := h.store.SummarizeUsageExtended(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	filter.Limit = parseIntQuery(r, "limit", 50, 1, 500)
	filter.Offset = parseIntQuery(r, "offset", 0, 0, 100000)

	logs, err := h.store.QueryUsageLogs(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	logs = normalizeUsageLogs(logs)

	writeJSON(w, http.StatusOK, map[string]any{
		"logs":    logs,
		"summary": summary,
	})
}

func (h *Handler) handleAdminLogPayload(w http.ResponseWriter, r *http.Request, usageLogID string) {
	if strings.TrimSpace(usageLogID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "usage log id is required")
		return
	}
	payload, err := h.store.GetAuditPayloadByUsageLogID(r.Context(), usageLogID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "audit payload not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if payload.RequestHeaders == nil {
		payload.RequestHeaders = map[string]string{}
	}
	if payload.ResponseHeaders == nil {
		payload.ResponseHeaders = map[string]string{}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleAdminGetAuditSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.store.GetAuditSettings(r.Context())
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"store_payloads": settings.StorePayloads,
			"retention_days": settings.RetentionDays,
		})
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	cfg := config.AuditConfig{StorePayloads: false, RetentionDays: 7}
	if h.auditController != nil {
		cfg = h.auditController.AuditConfig()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"store_payloads": cfg.StorePayloads,
		"retention_days": cfg.RetentionDays,
	})
}

func (h *Handler) handleAdminPutAuditSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StorePayloads bool `json:"store_payloads"`
		RetentionDays int  `json:"retention_days"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.RetentionDays < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "retention_days must be >= 0")
		return
	}
	if err := h.store.SetAuditSettings(r.Context(), store.AuditSettings{
		StorePayloads: req.StorePayloads,
		RetentionDays: req.RetentionDays,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.auditController != nil {
		h.auditController.UpdateAuditConfig(config.AuditConfig{
			StorePayloads: req.StorePayloads,
			RetentionDays: req.RetentionDays,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"store_payloads": req.StorePayloads,
		"retention_days": req.RetentionDays,
	})
}

func (h *Handler) handleAdminPurgeAudit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RetentionDays *int `json:"retention_days"`
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("invalid json: %v", err))
			return
		}
	}

	var (
		purged int64
		err    error
	)
	if req.RetentionDays != nil {
		if *req.RetentionDays < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "retention_days must be >= 0")
			return
		}
		maxAge := time.Duration(*req.RetentionDays) * 24 * time.Hour
		if h.auditController != nil {
			purged, err = h.auditController.PurgeOlderThan(r.Context(), maxAge)
		} else {
			now := time.Now().UTC()
			cutoff := now.Add(-maxAge)
			if maxAge == 0 {
				cutoff = now.Add(time.Nanosecond)
			}
			purged, err = h.store.PurgeAuditPayloads(r.Context(), cutoff)
		}
	} else {
		days := 7
		if h.auditController != nil {
			days = h.auditController.AuditConfig().RetentionDays
		} else if s, getErr := h.store.GetAuditSettings(r.Context()); getErr == nil {
			days = s.RetentionDays
		} else if !errors.Is(getErr, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "server_error", getErr.Error())
			return
		}
		if days <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", `auto-purge is disabled (retention_days=0); pass {"retention_days": N} in request body or set retention_days > 0`)
			return
		}
		if h.auditController != nil {
			purged, err = h.auditController.PurgeNow(r.Context())
		} else {
			cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
			purged, err = h.store.PurgeAuditPayloads(r.Context(), cutoff)
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": purged})
}

// --- Admin Guardrails ---

type guardrailRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	Enabled  *bool  `json:"enabled"`
}

func (h *Handler) handleAdminListGuardrails(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListGuardrailRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if rules == nil {
		rules = []store.GuardrailRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (h *Handler) handleAdminCreateGuardrail(w http.ResponseWriter, r *http.Request) {
	var req guardrailRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rule, err := validateGuardrailPayload(req.ID, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if rule.ID != "" {
		if existing, err := h.store.GetGuardrailRule(r.Context(), rule.ID); err == nil {
			if existing.Source == store.SourceConfig {
				writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("guardrail rule", rule.ID))
				return
			}
			if existing.Builtin {
				writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("built-in guardrail rule %q already exists; update it via PUT instead", rule.ID))
				return
			}
			writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("guardrail rule %q already exists", rule.ID))
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
	}
	if err := h.store.UpsertGuardrailRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if rule.ID != "" {
		saved, err := h.store.GetGuardrailRule(r.Context(), rule.ID)
		if err == nil {
			writeJSON(w, http.StatusCreated, saved)
			return
		}
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handler) handleAdminUpdateGuardrail(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.store.GetGuardrailRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("guardrail rule %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	// Any rule explicitly declared in headlamp.yaml (source='config'), including a YAML-pinned
	// built-in ID, is read-only via the API. Default built-in presets (source='builtin'/'local')
	// allow toggling enabled and action only.
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("guardrail rule", id))
		return
	}
	var req guardrailRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rule, err := validateGuardrailPayload(id, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertGuardrailRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetGuardrailRule(r.Context(), rule.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (h *Handler) handleAdminDeleteGuardrail(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.store.GetGuardrailRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("guardrail rule %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("guardrail rule", id))
		return
	}
	if existing.Builtin {
		writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("built-in guardrail rule %q cannot be deleted; disable it with enabled=false instead", id))
		return
	}
	if err := h.store.DeleteGuardrailRule(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("guardrail rule %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (h *Handler) handleAdminTestGuardrails(w http.ResponseWriter, r *http.Request) {
	if h.guardrailTester == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "guardrail tester is not configured")
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.guardrailTester.TestText(r.Context(), req.Text)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if res.Matches == nil {
		res.Matches = []GuardrailMatch{}
	}
	writeJSON(w, http.StatusOK, res)
}

func validateGuardrailPayload(id string, req guardrailRequest, existing *store.GuardrailRule) (store.GuardrailRule, error) {
	id = strings.TrimSpace(id)
	if id == "" && existing == nil {
		id = uuid.NewString()
	}
	if strings.Contains(id, "/") {
		return store.GuardrailRule{}, errors.New("guardrail id must not contain '/'")
	}
	if strings.EqualFold(id, "test") {
		return store.GuardrailRule{}, errors.New("guardrail id \"test\" is reserved")
	}
	if existing != nil && existing.Builtin {
		reqName := strings.TrimSpace(req.Name)
		reqCat := strings.ToLower(strings.TrimSpace(req.Category))
		if (reqName != "" && reqName != existing.Name) ||
			(reqCat != "" && reqCat != existing.Category) ||
			(req.Pattern != "" && req.Pattern != existing.Pattern) {
			return store.GuardrailRule{}, errors.New("built-in guardrail rules only allow modifying action and enabled")
		}
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = existing.Action
		}
		switch action {
		case config.GuardrailActionLogOnly, config.GuardrailActionRedact, config.GuardrailActionBlock:
		default:
			return store.GuardrailRule{}, fmt.Errorf("action %q must be log_only, redact, or block", action)
		}
		enabled := existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		return store.GuardrailRule{
			ID:       id,
			Name:     existing.Name,
			Category: existing.Category,
			Pattern:  existing.Pattern,
			Action:   action,
			Builtin:  true,
			Enabled:  enabled,
			Source:   store.SourceLocal,
		}, nil
	}

	name := strings.TrimSpace(req.Name)
	if name == "" && existing != nil {
		name = existing.Name
	}
	if name == "" {
		return store.GuardrailRule{}, errors.New("name is required")
	}

	category := strings.ToLower(strings.TrimSpace(req.Category))
	if category == "" {
		if existing != nil {
			category = existing.Category
		} else {
			category = config.GuardrailCategoryCustom
		}
	}
	switch category {
	case config.GuardrailCategorySecret, config.GuardrailCategoryPII, config.GuardrailCategoryCustom:
	default:
		return store.GuardrailRule{}, fmt.Errorf("category %q must be secret, pii, or custom", category)
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		if existing != nil {
			action = existing.Action
		} else {
			action = config.GuardrailActionRedact
		}
	}
	switch action {
	case config.GuardrailActionLogOnly, config.GuardrailActionRedact, config.GuardrailActionBlock:
	default:
		return store.GuardrailRule{}, fmt.Errorf("action %q must be log_only, redact, or block", action)
	}

	pattern := req.Pattern
	if pattern == "" && existing != nil {
		pattern = existing.Pattern
	}
	if pattern == "" {
		return store.GuardrailRule{}, errors.New("pattern is required")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return store.GuardrailRule{}, fmt.Errorf("invalid regex pattern: %w", err)
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	builtin := false
	if existing != nil {
		builtin = existing.Builtin
	}

	return store.GuardrailRule{
		ID:       id,
		Name:     name,
		Category: category,
		Pattern:  pattern,
		Action:   action,
		Builtin:  builtin,
		Enabled:  enabled,
		Source:   store.SourceLocal,
	}, nil
}

// --- Admin Webhooks ---

type webhookResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	HasSecret bool      `json:"has_secret"`
	Events    []string  `json:"events"`
	TimeoutMS int       `json:"timeout_ms"`
	FailOpen  bool      `json:"fail_open"`
	Enabled   bool      `json:"enabled"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toWebhookResponse(w store.Webhook) webhookResponse {
	events := w.Events
	if events == nil {
		events = []string{}
	}
	return webhookResponse{
		ID:        w.ID,
		Name:      w.Name,
		URL:       w.URL,
		Type:      w.Type,
		HasSecret: w.Secret != "",
		Events:    events,
		TimeoutMS: w.TimeoutMS,
		FailOpen:  w.FailOpen,
		Enabled:   w.Enabled,
		Source:    w.Source,
		UpdatedAt: w.UpdatedAt,
	}
}

type webhookRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Type        string   `json:"type"`
	Secret      string   `json:"secret"`
	ClearSecret bool     `json:"clear_secret"`
	Events      []string `json:"events"`
	TimeoutMS   int      `json:"timeout_ms"`
	FailOpen    *bool    `json:"fail_open"`
	Enabled     *bool    `json:"enabled"`
}

func (h *Handler) handleAdminListWebhooks(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListWebhooks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	out := make([]webhookResponse, 0, len(list))
	for _, wh := range list {
		out = append(out, toWebhookResponse(wh))
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

func (h *Handler) handleAdminCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req webhookRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	wh, err := validateWebhookPayload(req.ID, req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if wh.ID != "" {
		if existing, err := h.store.GetWebhook(r.Context(), wh.ID); err == nil {
			if existing.Source == store.SourceConfig {
				writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("webhook", wh.ID))
				return
			}
			writeError(w, http.StatusConflict, "conflict", fmt.Sprintf("webhook %q already exists", wh.ID))
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
	}
	if err := h.store.UpsertWebhook(r.Context(), wh); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if wh.ID != "" {
		saved, err := h.store.GetWebhook(r.Context(), wh.ID)
		if err == nil {
			writeJSON(w, http.StatusCreated, toWebhookResponse(*saved))
			return
		}
	}
	writeJSON(w, http.StatusCreated, toWebhookResponse(wh))
}

func (h *Handler) handleAdminUpdateWebhook(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.store.GetWebhook(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("webhook %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("webhook", id))
		return
	}
	var req webhookRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	wh, err := validateWebhookPayload(id, req, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.store.UpsertWebhook(r.Context(), wh); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	saved, err := h.store.GetWebhook(r.Context(), wh.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toWebhookResponse(*saved))
}

func (h *Handler) handleAdminDeleteWebhook(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.store.GetWebhook(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("webhook %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if existing.Source == store.SourceConfig {
		writeError(w, http.StatusConflict, "conflict", configManagedConflictMessage("webhook", id))
		return
	}
	if err := h.store.DeleteWebhook(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("webhook %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (h *Handler) handleAdminTestWebhook(w http.ResponseWriter, r *http.Request, id string) {
	if h.webhookTester == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "webhook tester is not configured")
		return
	}
	wh, err := h.store.GetWebhook(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("webhook %q not found", id))
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	res, err := h.webhookTester.PingWebhook(r.Context(), *wh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func validateWebhookPayload(id string, req webhookRequest, existing *store.Webhook) (store.Webhook, error) {
	id = strings.TrimSpace(id)
	if id == "" && existing == nil {
		id = uuid.NewString()
	}
	if strings.Contains(id, "/") {
		return store.Webhook{}, errors.New("webhook id must not contain '/'")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" && existing != nil {
		name = existing.Name
	}
	if name == "" {
		return store.Webhook{}, errors.New("name is required")
	}

	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" && existing != nil {
		rawURL = existing.URL
	}
	if err := validateHTTPURL(rawURL); err != nil {
		return store.Webhook{}, fmt.Errorf("url: %w", err)
	}

	wType := strings.ToLower(strings.TrimSpace(req.Type))
	if wType == "" && existing != nil {
		wType = existing.Type
	}
	switch wType {
	case config.WebhookTypeSyncReview, config.WebhookTypeAsyncEvent:
	default:
		return store.Webhook{}, fmt.Errorf("type %q must be sync_review or async_event", wType)
	}

	secret := req.Secret
	if existing != nil {
		if req.ClearSecret {
			secret = ""
		} else if secret == "" {
			secret = existing.Secret
		}
	}

	events := req.Events
	if events == nil {
		if existing != nil && existing.Events != nil {
			events = existing.Events
		} else {
			events = []string{}
		}
	}
	cleanedEvents := make([]string, 0, len(events))
	for _, ev := range events {
		norm := strings.ToLower(strings.TrimSpace(ev))
		if norm == "" {
			continue
		}
		if !config.IsValidWebhookEvent(norm) {
			return store.Webhook{}, fmt.Errorf("unknown webhook event %q", ev)
		}
		cleanedEvents = append(cleanedEvents, norm)
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS == 0 {
		if existing != nil && existing.TimeoutMS > 0 {
			timeoutMS = existing.TimeoutMS
		} else {
			timeoutMS = 2000
		}
	}
	if timeoutMS < 0 {
		return store.Webhook{}, errors.New("timeout_ms must be > 0")
	}

	failOpen := true
	if req.FailOpen != nil {
		failOpen = *req.FailOpen
	} else if existing != nil {
		failOpen = existing.FailOpen
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}

	return store.Webhook{
		ID:        id,
		Name:      name,
		URL:       rawURL,
		Type:      wType,
		Secret:    secret,
		Events:    cleanedEvents,
		TimeoutMS: timeoutMS,
		FailOpen:  failOpen,
		Enabled:   enabled,
		Source:    store.SourceLocal,
	}, nil
}

// --- Utilities ---

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:6] + "...****"
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url %q must use http or https scheme", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("url %q must include a host", raw)
	}
	return nil
}

func sanitizeNetError(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.URL != "" {
		if parsed, parseErr := url.Parse(ue.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.User = nil
			return fmt.Sprintf("%s %q: %v", ue.Op, parsed.String(), ue.Err)
		}
	}
	return err.Error()
}

func parseWindow(raw string) (window string, since time.Time, bucket string) {
	now := time.Now().UTC()
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "7d":
		return "7d", now.Add(-7 * 24 * time.Hour), "day"
	case "30d":
		return "30d", now.Add(-30 * 24 * time.Hour), "day"
	default:
		return "24h", now.Add(-24 * time.Hour), "hour"
	}
}

func parseIntQuery(r *http.Request, key string, def, minVal, maxVal int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

func normalizeUsageLogs(logs []store.UsageLog) []store.UsageLog {
	if logs == nil {
		return []store.UsageLog{}
	}
	for i := range logs {
		if logs[i].Tags == nil {
			logs[i].Tags = []string{}
		}
		if logs[i].GuardrailHits == nil {
			logs[i].GuardrailHits = []string{}
		}
	}
	return logs
}
