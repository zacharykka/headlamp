package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
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
