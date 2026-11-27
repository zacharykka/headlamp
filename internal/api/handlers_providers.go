package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

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
