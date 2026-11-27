package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

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
