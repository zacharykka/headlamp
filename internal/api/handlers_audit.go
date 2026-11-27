package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

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
	if errStr := strings.TrimSpace(q.Get("errors_only")); errStr != "" {
		b, err := strconv.ParseBool(errStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid errors_only query parameter")
			return
		}
		filter.ErrorsOnly = b
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
