package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/config"
)

// --- Providers ---

func (s *SQLiteStore) UpsertProvider(ctx context.Context, p Provider) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("store: provider name is required")
	}

	apiKeyEnc := ""
	if p.APIKey != "" {
		var err error
		apiKeyEnc, err = s.cipher.EncryptString(p.APIKey)
		if err != nil {
			return fmt.Errorf("store: encrypt provider api_key: %w", err)
		}
	}
	modelsJSON, err := marshalStringSlice(p.Models)
	if err != nil {
		return fmt.Errorf("store: encode provider models: %w", err)
	}

	now := time.Now().UTC()
	source := defaultSource(p.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err = s.db.ExecContext(ctx, `
INSERT INTO providers (name, type, base_url, api_key_enc, passthrough, models_json, enabled, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	type = excluded.type,
	base_url = excluded.base_url,
	api_key_enc = excluded.api_key_enc,
	passthrough = excluded.passthrough,
	models_json = excluded.models_json,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		p.Name, p.Type, p.BaseURL, apiKeyEnc, boolToInt(p.Passthrough), modelsJSON,
		boolToInt(p.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert provider %q: %w", p.Name, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetProvider(ctx context.Context, name string) (*Provider, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	p, ok := snap.providersByName[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneProvider(p)
	return &cp, nil
}

func (s *SQLiteStore) ListProviders(ctx context.Context) ([]Provider, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.providers) == 0 {
		return nil, nil
	}
	out := make([]Provider, len(snap.providers))
	for i, p := range snap.providers {
		out[i] = cloneProvider(p)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteProvider(ctx context.Context, name string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete provider %q: %w", name, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) scanProvider(sc scanner) (Provider, error) {
	var (
		p            Provider
		apiKeyEnc    string
		passthrough  int
		modelsJSON   string
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&p.Name, &p.Type, &p.BaseURL, &apiKeyEnc, &passthrough,
		&modelsJSON, &enabled, &p.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return Provider{}, err
	}
	if apiKeyEnc != "" {
		dec, err := s.cipher.DecryptString(apiKeyEnc)
		if err != nil {
			return Provider{}, fmt.Errorf("store: decrypt api_key for provider %q: %w", p.Name, err)
		}
		p.APIKey = dec
	}
	models, err := unmarshalStringSlice(modelsJSON)
	if err != nil {
		return Provider{}, fmt.Errorf("store: decode models for provider %q: %w", p.Name, err)
	}
	p.Models = models
	p.Passthrough = passthrough != 0
	p.Enabled = enabled != 0
	p.CreatedAt = parseTime(createdAtStr)
	p.UpdatedAt = parseTime(updatedAtStr)
	return p, nil
}

// --- Model Routes ---

func (s *SQLiteStore) UpsertModelRoute(ctx context.Context, r ModelRoute) error {
	if strings.TrimSpace(r.Alias) == "" {
		return errors.New("store: model route alias is required")
	}
	fallbacks := r.Fallbacks
	if fallbacks == nil {
		fallbacks = []RouteTarget{}
	}
	fallbacksJSON, err := json.Marshal(fallbacks)
	if err != nil {
		return fmt.Errorf("store: encode route fallbacks: %w", err)
	}

	now := time.Now().UTC()
	source := defaultSource(r.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err = s.db.ExecContext(ctx, `
INSERT INTO model_routes (
	alias, provider_name, upstream_model, fallbacks_json,
	input_cost_per_million, output_cost_per_million,
	cache_read_cost_per_million, cache_write_cost_per_million,
	enabled, source, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(alias) DO UPDATE SET
	provider_name = excluded.provider_name,
	upstream_model = excluded.upstream_model,
	fallbacks_json = excluded.fallbacks_json,
	input_cost_per_million = excluded.input_cost_per_million,
	output_cost_per_million = excluded.output_cost_per_million,
	cache_read_cost_per_million = excluded.cache_read_cost_per_million,
	cache_write_cost_per_million = excluded.cache_write_cost_per_million,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		r.Alias, r.ProviderName, r.UpstreamModel, string(fallbacksJSON),
		nullableFloat(r.InputCostPerMillion), nullableFloat(r.OutputCostPerMillion),
		nullableFloat(r.CacheReadCostPerMillion), nullableFloat(r.CacheWriteCostPerMillion),
		boolToInt(r.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert model route %q: %w", r.Alias, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetModelRoute(ctx context.Context, alias string) (*ModelRoute, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := snap.routesByAlias[alias]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneModelRoute(r)
	return &cp, nil
}

func (s *SQLiteStore) ListModelRoutes(ctx context.Context) ([]ModelRoute, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.routes) == 0 {
		return nil, nil
	}
	out := make([]ModelRoute, len(snap.routes))
	for i, r := range snap.routes {
		out[i] = cloneModelRoute(r)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteModelRoute(ctx context.Context, alias string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM model_routes WHERE alias = ?`, alias)
	if err != nil {
		return fmt.Errorf("store: delete model route %q: %w", alias, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func scanModelRoute(sc scanner) (ModelRoute, error) {
	var (
		r             ModelRoute
		fallbacksJSON string
		inCost        sql.NullFloat64
		outCost       sql.NullFloat64
		cacheRead     sql.NullFloat64
		cacheWrite    sql.NullFloat64
		enabled       int
		createdAtStr  string
		updatedAtStr  string
	)
	if err := sc.Scan(
		&r.Alias, &r.ProviderName, &r.UpstreamModel, &fallbacksJSON,
		&inCost, &outCost, &cacheRead, &cacheWrite,
		&enabled, &r.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return ModelRoute{}, err
	}
	if fallbacksJSON != "" {
		if err := json.Unmarshal([]byte(fallbacksJSON), &r.Fallbacks); err != nil {
			return ModelRoute{}, fmt.Errorf("store: decode fallbacks for route %q: %w", r.Alias, err)
		}
	}
	r.InputCostPerMillion = fromNullFloat(inCost)
	r.OutputCostPerMillion = fromNullFloat(outCost)
	r.CacheReadCostPerMillion = fromNullFloat(cacheRead)
	r.CacheWriteCostPerMillion = fromNullFloat(cacheWrite)
	r.Enabled = enabled != 0
	r.CreatedAt = parseTime(createdAtStr)
	r.UpdatedAt = parseTime(updatedAtStr)
	return r, nil
}

// --- Budgets ---

func (s *SQLiteStore) UpsertBudget(ctx context.Context, b Budget) error {
	scope := strings.TrimSpace(b.Scope)
	if scope == "" {
		return errors.New("store: budget scope is required")
	}
	softPct := b.SoftAlertPct
	if softPct <= 0 {
		softPct = 80
	}
	now := time.Now().UTC()
	source := defaultSource(b.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO budgets (
	scope, rpm, tpm, max_concurrent, daily_usd, monthly_usd,
	soft_alert_pct, enabled, source, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scope) DO UPDATE SET
	rpm = excluded.rpm,
	tpm = excluded.tpm,
	max_concurrent = excluded.max_concurrent,
	daily_usd = excluded.daily_usd,
	monthly_usd = excluded.monthly_usd,
	soft_alert_pct = excluded.soft_alert_pct,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		scope, b.RPM, b.TPM, b.MaxConcurrent,
		nullableFloat(b.DailyUSD), nullableFloat(b.MonthlyUSD),
		softPct, boolToInt(b.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert budget %q: %w", scope, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetBudget(ctx context.Context, scope string) (*Budget, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	b, ok := snap.budgetsByScope[scope]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneBudget(b)
	return &cp, nil
}

func (s *SQLiteStore) ListBudgets(ctx context.Context) ([]Budget, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.budgets) == 0 {
		return nil, nil
	}
	out := make([]Budget, len(snap.budgets))
	for i, b := range snap.budgets {
		out[i] = cloneBudget(b)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteBudget(ctx context.Context, scope string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM budgets WHERE scope = ?`, scope)
	if err != nil {
		return fmt.Errorf("store: delete budget %q: %w", scope, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func scanBudget(sc scanner) (Budget, error) {
	var (
		b            Budget
		dailyUSD     sql.NullFloat64
		monthlyUSD   sql.NullFloat64
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&b.Scope, &b.RPM, &b.TPM, &b.MaxConcurrent,
		&dailyUSD, &monthlyUSD, &b.SoftAlertPct,
		&enabled, &b.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return Budget{}, err
	}
	b.DailyUSD = fromNullFloat(dailyUSD)
	b.MonthlyUSD = fromNullFloat(monthlyUSD)
	b.Enabled = enabled != 0
	b.CreatedAt = parseTime(createdAtStr)
	b.UpdatedAt = parseTime(updatedAtStr)
	return b, nil
}

// --- Guardrail Rules ---

func (s *SQLiteStore) UpsertGuardrailRule(ctx context.Context, r GuardrailRule) error {
	id := strings.TrimSpace(r.ID)
	if id == "" {
		id = uuid.NewString()
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("store: guardrail rule name is required")
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return errors.New("store: guardrail rule pattern is required")
	}
	category := strings.ToLower(strings.TrimSpace(r.Category))
	if category == "" {
		category = config.GuardrailCategoryCustom
	}
	action := strings.ToLower(strings.TrimSpace(r.Action))
	if action == "" {
		action = config.GuardrailActionRedact
	}

	now := time.Now().UTC()
	source := defaultSource(r.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO guardrail_rules (id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	category = excluded.category,
	pattern = excluded.pattern,
	action = excluded.action,
	builtin = excluded.builtin,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		id, r.Name, category, r.Pattern, action, boolToInt(r.Builtin),
		boolToInt(r.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert guardrail rule %q: %w", id, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetGuardrailRule(ctx context.Context, id string) (*GuardrailRule, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := snap.guardrailsByID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := r
	return &cp, nil
}

func (s *SQLiteStore) ListGuardrailRules(ctx context.Context) ([]GuardrailRule, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.guardrails) == 0 {
		return nil, nil
	}
	out := make([]GuardrailRule, len(snap.guardrails))
	copy(out, snap.guardrails)
	return out, nil
}

func (s *SQLiteStore) DeleteGuardrailRule(ctx context.Context, id string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM guardrail_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete guardrail rule %q: %w", id, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func scanGuardrailRule(sc scanner) (GuardrailRule, error) {
	var (
		r            GuardrailRule
		builtin      int
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&r.ID, &r.Name, &r.Category, &r.Pattern, &r.Action,
		&builtin, &enabled, &r.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return GuardrailRule{}, err
	}
	r.Builtin = builtin != 0
	r.Enabled = enabled != 0
	r.CreatedAt = parseTime(createdAtStr)
	r.UpdatedAt = parseTime(updatedAtStr)
	return r, nil
}

// --- Webhooks ---

func (s *SQLiteStore) UpsertWebhook(ctx context.Context, w Webhook) error {
	id := strings.TrimSpace(w.ID)
	if id == "" {
		id = uuid.NewString()
	}
	if strings.TrimSpace(w.Name) == "" {
		return errors.New("store: webhook name is required")
	}
	if strings.TrimSpace(w.URL) == "" {
		return errors.New("store: webhook url is required")
	}

	secretEnc := ""
	if w.Secret != "" {
		var err error
		secretEnc, err = s.cipher.EncryptString(w.Secret)
		if err != nil {
			return fmt.Errorf("store: encrypt webhook secret: %w", err)
		}
	}
	eventsJSON, err := marshalStringSlice(w.Events)
	if err != nil {
		return fmt.Errorf("store: encode webhook events: %w", err)
	}
	timeoutMS := w.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 2000
	}

	now := time.Now().UTC()
	source := defaultSource(w.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err = s.db.ExecContext(ctx, `
INSERT INTO webhooks (id, name, url, type, secret_enc, events_json, timeout_ms, fail_open, enabled, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	url = excluded.url,
	type = excluded.type,
	secret_enc = excluded.secret_enc,
	events_json = excluded.events_json,
	timeout_ms = excluded.timeout_ms,
	fail_open = excluded.fail_open,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		id, w.Name, w.URL, w.Type, secretEnc, eventsJSON, timeoutMS,
		boolToInt(w.FailOpen), boolToInt(w.Enabled), source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert webhook %q: %w", id, err)
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	w, ok := snap.webhooksByID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneWebhook(w)
	return &cp, nil
}

func (s *SQLiteStore) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.webhooks) == 0 {
		return nil, nil
	}
	out := make([]Webhook, len(snap.webhooks))
	for i, w := range snap.webhooks {
		out[i] = cloneWebhook(w)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteWebhook(ctx context.Context, id string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete webhook %q: %w", id, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *SQLiteStore) scanWebhook(sc scanner) (Webhook, error) {
	var (
		w            Webhook
		secretEnc    string
		eventsJSON   string
		failOpen     int
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&w.ID, &w.Name, &w.URL, &w.Type, &secretEnc, &eventsJSON,
		&w.TimeoutMS, &failOpen, &enabled, &w.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return Webhook{}, err
	}
	if secretEnc != "" {
		dec, err := s.cipher.DecryptString(secretEnc)
		if err != nil {
			return Webhook{}, fmt.Errorf("store: decrypt secret for webhook %q: %w", w.ID, err)
		}
		w.Secret = dec
	}
	events, err := unmarshalStringSlice(eventsJSON)
	if err != nil {
		return Webhook{}, fmt.Errorf("store: decode events for webhook %q: %w", w.ID, err)
	}
	w.Events = events
	w.FailOpen = failOpen != 0
	w.Enabled = enabled != 0
	w.CreatedAt = parseTime(createdAtStr)
	w.UpdatedAt = parseTime(updatedAtStr)
	return w, nil
}
