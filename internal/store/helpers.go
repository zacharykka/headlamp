package store

import (
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

const runtimeSettingAuditKey = "audit"

type configSnapshot struct {
	providers        []Provider
	providersByName  map[string]Provider
	routes           []ModelRoute
	routesByAlias    map[string]ModelRoute
	budgets          []Budget
	budgetsByScope   map[string]Budget
	guardrails       []GuardrailRule
	guardrailsByID   map[string]GuardrailRule
	webhooks         []Webhook
	webhooksByID     map[string]Webhook
	mcpServers       []MCPServer
	mcpServersByName map[string]MCPServer
}

type scanner interface {
	Scan(dest ...any) error
}

func cloneProvider(p Provider) Provider {
	p.Models = slices.Clone(p.Models)
	return p
}

func cloneModelRoute(r ModelRoute) ModelRoute {
	r.Fallbacks = slices.Clone(r.Fallbacks)
	r.InputCostPerMillion = cloneFloatPtr(r.InputCostPerMillion)
	r.OutputCostPerMillion = cloneFloatPtr(r.OutputCostPerMillion)
	r.CacheReadCostPerMillion = cloneFloatPtr(r.CacheReadCostPerMillion)
	r.CacheWriteCostPerMillion = cloneFloatPtr(r.CacheWriteCostPerMillion)
	return r
}

func cloneBudget(b Budget) Budget {
	b.DailyUSD = cloneFloatPtr(b.DailyUSD)
	b.MonthlyUSD = cloneFloatPtr(b.MonthlyUSD)
	return b
}

func cloneWebhook(w Webhook) Webhook {
	w.Events = slices.Clone(w.Events)
	return w
}

func cloneMCPServer(m MCPServer) MCPServer {
	return m
}

func cloneFloatPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func checkAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}
		}
	}
	return t.UTC()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func defaultSource(s string) string {
	if strings.TrimSpace(s) == "" {
		return SourceLocal
	}
	return s
}

func nullableFloat(v *float64) sql.NullFloat64 {
	if v == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *v, Valid: true}
}

func fromNullFloat(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

func marshalStringSlice(in []string) (string, error) {
	if in == nil {
		in = []string{}
	}
	b, err := json.Marshal(in)
	return string(b), err
}

func unmarshalStringSlice(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalStringMap(in map[string]string) (string, error) {
	if in == nil {
		in = map[string]string{}
	}
	b, err := json.Marshal(in)
	return string(b), err
}

func unmarshalStringMap(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalChatToolEvents(events []ChatToolEvent) (string, error) {
	if events == nil {
		events = []ChatToolEvent{}
	}
	b, err := json.Marshal(events)
	return string(b), err
}

func unmarshalChatToolEvents(raw string) ([]ChatToolEvent, error) {
	if raw == "" {
		return []ChatToolEvent{}, nil
	}
	var out []ChatToolEvent
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []ChatToolEvent{}
	}
	return out, nil
}
