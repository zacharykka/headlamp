package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/store"
)

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
