package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
)

// SyncConfig idempotently syncs YAML providers, model routes, budgets, guardrails, webhooks,
// and MCP servers into PostgreSQL within a single transaction, matching SQLiteStore semantics.
func (s *PostgresStore) SyncConfig(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: postgres sync config begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()

	// 1. Providers
	providerNames := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		providerNames = append(providerNames, p.Name)

		apiKeyEnc := ""
		if p.APIKey != "" {
			apiKeyEnc, err = s.cipher.EncryptString(p.APIKey)
			if err != nil {
				return fmt.Errorf("store: encrypt api key for provider %q: %w", p.Name, err)
			}
		} else {
			var existingEnc string
			err := tx.QueryRowContext(ctx, `SELECT api_key_enc FROM providers WHERE name = $1 AND source = $2`, p.Name, SourceConfig).Scan(&existingEnc)
			if err == nil {
				apiKeyEnc = existingEnc
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: lookup existing provider %q: %w", p.Name, err)
			}
		}

		modelsJSON, err := marshalStringSlice(p.Models)
		if err != nil {
			return fmt.Errorf("store: encode models for provider %q: %w", p.Name, err)
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO providers (name, type, base_url, api_key_enc, passthrough, models_json, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
ON CONFLICT(name) DO UPDATE SET
	type = excluded.type,
	base_url = excluded.base_url,
	api_key_enc = excluded.api_key_enc,
	passthrough = excluded.passthrough,
	models_json = excluded.models_json,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
			p.Name, p.Type, p.BaseURL, apiKeyEnc, p.Passthrough, modelsJSON,
			p.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync provider %q: %w", p.Name, err)
		}
	}

	// 2. Model routes
	routeAliases := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routeAliases = append(routeAliases, r.Alias)

		fallbacks := make([]RouteTarget, len(r.Fallbacks))
		for i, fb := range r.Fallbacks {
			fallbacks[i] = RouteTarget{Provider: fb.Provider, Model: fb.Model}
		}
		fallbacksJSON, err := json.Marshal(fallbacks)
		if err != nil {
			return fmt.Errorf("store: encode fallbacks for route %q: %w", r.Alias, err)
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO model_routes (
	alias, provider_name, upstream_model, fallbacks_json,
	input_cost_per_million, output_cost_per_million,
	cache_read_cost_per_million, cache_write_cost_per_million,
	enabled, source, created_at, updated_at
)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12)
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
			r.Alias, r.Provider, r.Model, string(fallbacksJSON),
			nullableFloat(r.InputCostPerMillion), nullableFloat(r.OutputCostPerMillion),
			nullableFloat(r.CacheReadCostPerMillion), nullableFloat(r.CacheWriteCostPerMillion),
			r.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync route %q: %w", r.Alias, err)
		}
	}

	// 3. Budgets
	budgetScopes := make([]string, 0, len(cfg.Budgets))
	for _, b := range cfg.Budgets {
		budgetScopes = append(budgetScopes, b.Scope)
		softPct := b.SoftAlertPct
		if softPct <= 0 {
			softPct = 80
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO budgets (scope, rpm, tpm, max_concurrent, daily_usd, monthly_usd, soft_alert_pct, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
			b.Scope, b.RPM, b.TPM, b.MaxConcurrent,
			nullableFloat(b.DailyUSD), nullableFloat(b.MonthlyUSD),
			softPct, b.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync budget %q: %w", b.Scope, err)
		}
	}

	// 4. Explicit YAML guardrail rules (source='config') + default built-in presets (source='builtin')
	builtins := DefaultBuiltinGuardrailRules()
	builtinIDs := make(map[string]bool, len(builtins))
	for _, br := range builtins {
		builtinIDs[br.ID] = true
	}

	configGuardrailIDs := make([]string, 0, len(cfg.Guardrails.Rules))
	for _, r := range cfg.Guardrails.Rules {
		configGuardrailIDs = append(configGuardrailIDs, r.ID)
		_, err = tx.ExecContext(ctx, `
INSERT INTO guardrail_rules (id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	category = excluded.category,
	pattern = excluded.pattern,
	action = excluded.action,
	builtin = excluded.builtin,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
			r.ID, r.Name, r.Category, r.Pattern, r.Action,
			builtinIDs[r.ID], r.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync guardrail rule %q: %w", r.ID, err)
		}
	}

	// 5. Webhooks
	webhookIDs := make([]string, 0, len(cfg.Webhooks))
	for _, w := range cfg.Webhooks {
		webhookIDs = append(webhookIDs, w.ID)

		secretEnc := ""
		if w.Secret != "" {
			secretEnc, err = s.cipher.EncryptString(w.Secret)
			if err != nil {
				return fmt.Errorf("store: encrypt secret for webhook %q: %w", w.ID, err)
			}
		} else {
			var existingEnc string
			err := tx.QueryRowContext(ctx, `SELECT secret_enc FROM webhooks WHERE id = $1 AND source = $2`, w.ID, SourceConfig).Scan(&existingEnc)
			if err == nil {
				secretEnc = existingEnc
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: lookup existing webhook %q: %w", w.ID, err)
			}
		}

		eventsJSON, err := marshalStringSlice(w.Events)
		if err != nil {
			return fmt.Errorf("store: encode events for webhook %q: %w", w.ID, err)
		}
		timeoutMS := w.TimeoutMS
		if timeoutMS <= 0 {
			timeoutMS = 2000
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO webhooks (id, name, url, type, secret_enc, events_json, timeout_ms, fail_open, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12)
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
			w.ID, w.Name, w.URL, w.Type, secretEnc, eventsJSON, timeoutMS,
			w.IsFailOpen(), w.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync webhook %q: %w", w.ID, err)
		}
	}

	// 6. MCP servers
	mcpServerNames := make([]string, 0, len(cfg.MCPServers))
	for _, m := range cfg.MCPServers {
		mcpServerNames = append(mcpServerNames, m.Name)

		transport := m.Transport
		if transport == "" {
			transport = config.MCPTransportStreamableHTTP
		}
		authType := strings.ToLower(strings.TrimSpace(m.AuthType))
		if authType == "" {
			authType = config.MCPAuthNone
		}

		tokenEnc := ""
		switch {
		case authType == config.MCPAuthNone:
			tokenEnc = ""
		case m.AuthToken != "":
			tokenEnc, err = s.cipher.EncryptString(m.AuthToken)
			if err != nil {
				return fmt.Errorf("store: encrypt auth token for mcp server %q: %w", m.Name, err)
			}
		default:
			var existingEnc string
			err := tx.QueryRowContext(
				ctx,
				`SELECT auth_token_enc FROM mcp_servers WHERE name = $1 AND source = $2`,
				m.Name, SourceConfig,
			).Scan(&existingEnc)
			if err == nil {
				tokenEnc = existingEnc
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: lookup existing mcp server %q: %w", m.Name, err)
			}
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO mcp_servers (name, url, transport, auth_type, auth_header, auth_token_enc, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT(name) DO UPDATE SET
	url = excluded.url,
	transport = excluded.transport,
	auth_type = excluded.auth_type,
	auth_header = excluded.auth_header,
	auth_token_enc = excluded.auth_token_enc,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
			m.Name, m.URL, transport, authType, m.AuthHeader, tokenEnc,
			m.IsEnabled(), SourceConfig, now, now,
		)
		if err != nil {
			return fmt.Errorf("store: sync mcp server %q: %w", m.Name, err)
		}
	}

	// Prune stale config-managed rows (delete model_routes BEFORE providers for FK safety).
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "model_routes", "alias", routeAliases); err != nil {
		return err
	}
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "providers", "name", providerNames); err != nil {
		return err
	}
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "budgets", "scope", budgetScopes); err != nil {
		return err
	}
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "guardrail_rules", "id", configGuardrailIDs); err != nil {
		return err
	}
	if cfg.Guardrails.UseBuiltinDefaults() {
		for _, br := range builtins {
			_, err = tx.ExecContext(ctx, `
INSERT INTO guardrail_rules (id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, $8, $9)
ON CONFLICT(id) DO NOTHING`,
				br.ID, br.Name, br.Category, br.Pattern, br.Action,
				br.Enabled, SourceBuiltin, now, now,
			)
			if err != nil {
				return fmt.Errorf("store: seed builtin guardrail %q: %w", br.ID, err)
			}
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM guardrail_rules WHERE source = $1`, SourceBuiltin); err != nil {
			return fmt.Errorf("store: prune uncustomized builtin guardrails: %w", err)
		}
	}
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "webhooks", "id", webhookIDs); err != nil {
		return err
	}
	if err := pgDeleteStaleConfigRowsTx(ctx, tx, "mcp_servers", "name", mcpServerNames); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: postgres sync config commit: %w", err)
	}

	s.cache = nil
	return nil
}

func pgDeleteStaleConfigRowsTx(ctx context.Context, tx *sql.Tx, table, keyCol string, keepKeys []string) error {
	if len(keepKeys) == 0 {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE source = $1`, table), SourceConfig); err != nil {
			return fmt.Errorf("store: delete stale config rows from %s: %w", table, err)
		}
		return nil
	}

	placeholders := make([]string, len(keepKeys))
	args := make([]any, 0, len(keepKeys)+1)
	args = append(args, SourceConfig)
	for i, k := range keepKeys {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, k)
	}
	query := fmt.Sprintf(
		`DELETE FROM %s WHERE source = $1 AND %s NOT IN (%s)`,
		table, keyCol, strings.Join(placeholders, ","),
	)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("store: delete stale config rows from %s: %w", table, err)
	}
	return nil
}

// --- Snapshot Cache ---

func (s *PostgresStore) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *PostgresStore) isCacheFreshLocked(now time.Time) bool {
	if s.cache == nil || s.cacheTTL <= 0 {
		return false
	}
	return now.Sub(s.cacheLoadedAt) < s.cacheTTL
}

func (s *PostgresStore) snapshot(ctx context.Context) (*configSnapshot, error) {
	now := s.currentTime()
	s.cacheMu.RLock()
	if s.isCacheFreshLocked(now) {
		snap := s.cache
		s.cacheMu.RUnlock()
		return snap, nil
	}
	s.cacheMu.RUnlock()

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	now = s.currentTime()
	if s.isCacheFreshLocked(now) {
		return s.cache, nil
	}

	loaded, err := s.loadSnapshotLocked(ctx)
	if err != nil {
		return nil, err
	}
	s.cache = loaded
	s.cacheLoadedAt = s.currentTime()
	s.cacheLoads.Add(1)
	return loaded, nil
}

func (s *PostgresStore) loadSnapshotLocked(ctx context.Context) (*configSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("store: begin postgres snapshot tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Providers
	provRows, err := tx.QueryContext(ctx, `
SELECT name, type, base_url, api_key_enc, passthrough, models_json::text, enabled, source, created_at, updated_at
FROM providers ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres providers snapshot: %w", err)
	}
	var providers []Provider
	for provRows.Next() {
		p, err := s.scanProvider(provRows)
		if err != nil {
			_ = provRows.Close()
			return nil, err
		}
		providers = append(providers, p)
	}
	if err := provRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close provider snapshot rows: %w", err)
	}
	if err := provRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate provider snapshot rows: %w", err)
	}

	// Model routes
	routeRows, err := tx.QueryContext(ctx, `
SELECT alias, provider_name, upstream_model, fallbacks_json::text,
       input_cost_per_million, output_cost_per_million,
       cache_read_cost_per_million, cache_write_cost_per_million,
       enabled, source, created_at, updated_at
FROM model_routes ORDER BY alias ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres model routes snapshot: %w", err)
	}
	var routes []ModelRoute
	for routeRows.Next() {
		r, err := pgScanModelRoute(routeRows)
		if err != nil {
			_ = routeRows.Close()
			return nil, err
		}
		routes = append(routes, r)
	}
	if err := routeRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close model routes snapshot rows: %w", err)
	}
	if err := routeRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate model routes snapshot rows: %w", err)
	}

	// Budgets
	budgetRows, err := tx.QueryContext(ctx, `
SELECT scope, rpm, tpm, max_concurrent, daily_usd, monthly_usd,
       soft_alert_pct, enabled, source, created_at, updated_at
FROM budgets ORDER BY scope ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres budgets snapshot: %w", err)
	}
	var budgets []Budget
	for budgetRows.Next() {
		b, err := pgScanBudget(budgetRows)
		if err != nil {
			_ = budgetRows.Close()
			return nil, err
		}
		budgets = append(budgets, b)
	}
	if err := budgetRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close budgets snapshot rows: %w", err)
	}
	if err := budgetRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate budgets snapshot rows: %w", err)
	}

	// Guardrail rules
	ruleRows, err := tx.QueryContext(ctx, `
SELECT id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at
FROM guardrail_rules ORDER BY builtin DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres guardrail rules snapshot: %w", err)
	}
	var guardrails []GuardrailRule
	for ruleRows.Next() {
		r, err := pgScanGuardrailRule(ruleRows)
		if err != nil {
			_ = ruleRows.Close()
			return nil, err
		}
		guardrails = append(guardrails, r)
	}
	if err := ruleRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close guardrail rules snapshot rows: %w", err)
	}
	if err := ruleRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate guardrail rules snapshot rows: %w", err)
	}

	// Webhooks
	whRows, err := tx.QueryContext(ctx, `
SELECT id, name, url, type, secret_enc, events_json::text, timeout_ms, fail_open, enabled, source, created_at, updated_at
FROM webhooks ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres webhooks snapshot: %w", err)
	}
	var webhooks []Webhook
	for whRows.Next() {
		w, err := s.scanWebhook(whRows)
		if err != nil {
			_ = whRows.Close()
			return nil, err
		}
		webhooks = append(webhooks, w)
	}
	if err := whRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close webhooks snapshot rows: %w", err)
	}
	if err := whRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate webhooks snapshot rows: %w", err)
	}

	// MCP servers
	mcpRows, err := tx.QueryContext(ctx, `
SELECT name, url, transport, auth_type, auth_header, auth_token_enc, enabled, source, created_at, updated_at
FROM mcp_servers ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load postgres mcp servers snapshot: %w", err)
	}
	var mcpServers []MCPServer
	for mcpRows.Next() {
		m, err := s.scanMCPServer(mcpRows)
		if err != nil {
			_ = mcpRows.Close()
			return nil, err
		}
		mcpServers = append(mcpServers, m)
	}
	if err := mcpRows.Close(); err != nil {
		return nil, fmt.Errorf("store: close mcp servers snapshot rows: %w", err)
	}
	if err := mcpRows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate mcp servers snapshot rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit postgres snapshot tx: %w", err)
	}

	byName := make(map[string]Provider, len(providers))
	for _, p := range providers {
		byName[p.Name] = p
	}
	byAlias := make(map[string]ModelRoute, len(routes))
	for _, r := range routes {
		byAlias[r.Alias] = r
	}
	byScope := make(map[string]Budget, len(budgets))
	for _, b := range budgets {
		byScope[b.Scope] = b
	}
	byRuleID := make(map[string]GuardrailRule, len(guardrails))
	for _, r := range guardrails {
		byRuleID[r.ID] = r
	}
	byWebhookID := make(map[string]Webhook, len(webhooks))
	for _, w := range webhooks {
		byWebhookID[w.ID] = w
	}
	byMCPName := make(map[string]MCPServer, len(mcpServers))
	for _, m := range mcpServers {
		byMCPName[m.Name] = m
	}

	return &configSnapshot{
		providers:        providers,
		providersByName:  byName,
		routes:           routes,
		routesByAlias:    byAlias,
		budgets:          budgets,
		budgetsByScope:   byScope,
		guardrails:       guardrails,
		guardrailsByID:   byRuleID,
		webhooks:         webhooks,
		webhooksByID:     byWebhookID,
		mcpServers:       mcpServers,
		mcpServersByName: byMCPName,
	}, nil
}
