package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
)

//go:embed migrations_pg/*.sql
var pgMigrationsFS embed.FS

// pgMigrationAdvisoryLockID prevents concurrent schema migration races when
// multiple Headlamp replicas start simultaneously against PostgreSQL.
const (
	pgMigrationAdvisoryLockID int64 = 72491827341
	defaultPostgresCacheTTL         = 5 * time.Second
)

// PostgresOption configures optional PostgresStore behavior.
type PostgresOption func(*PostgresStore)

// WithPostgresCacheTTL sets the maximum age of the in-memory config snapshot cache
// before PostgresStore refreshes from PostgreSQL (default 5s). A non-positive TTL
// disables cross-request snapshot caching so every read queries PostgreSQL.
func WithPostgresCacheTTL(ttl time.Duration) PostgresOption {
	return func(s *PostgresStore) {
		s.cacheTTL = ttl
	}
}

// PostgresStore implements Store backed by PostgreSQL using pure-Go jackc/pgx/v5 (zero CGO).
// Decrypted providers, model routes, budgets, guardrail rules, webhooks, and MCP servers are
// served from a short-TTL immutable in-memory snapshot cache invalidated on local mutations.
type PostgresStore struct {
	db     *sql.DB
	cipher *crypto.Cipher

	cacheMu       sync.RWMutex
	cache         *configSnapshot
	cacheLoadedAt time.Time
	cacheTTL      time.Duration
	now           func() time.Time
	cacheLoads    atomic.Int64
}

var _ Store = (*PostgresStore)(nil)

// NewPostgresStore validates dsn, opens a pgx/v5 connection pool, pings PostgreSQL,
// and applies all embedded PostgreSQL migrations under a transaction-scoped advisory lock.
func NewPostgresStore(ctx context.Context, dsn string, cipher *crypto.Cipher, opts ...PostgresOption) (*PostgresStore, error) {
	if cipher == nil {
		return nil, errors.New("store: cipher is required")
	}
	trimmedDSN := strings.TrimSpace(dsn)
	if trimmedDSN == "" {
		return nil, errors.New("store: postgres dsn is required")
	}
	if _, err := pgx.ParseConfig(trimmedDSN); err != nil {
		return nil, fmt.Errorf("store: invalid postgres dsn: %w", err)
	}

	db, err := sql.Open("pgx", trimmedDSN)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}

	s := &PostgresStore{
		db:       db,
		cipher:   cipher,
		cacheTTL: defaultPostgresCacheTTL,
		now:      time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the underlying *sql.DB for diagnostics or tests.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}

// Close closes the underlying PostgreSQL connection pool.
func (s *PostgresStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Migrate applies all unapplied embedded PostgreSQL migrations in ascending version order
// inside a single transaction protected by pg_advisory_xact_lock (compatible with PgBouncer/
// Supavisor transaction pooling).
func (s *PostgresStore) Migrate(ctx context.Context) error {
	list, err := readPGMigrations()
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin postgres migration tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, pgMigrationAdvisoryLockID); err != nil {
		return fmt.Errorf("store: acquire postgres migration lock: %w", err)
	}

	const createTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL
);`
	if _, err := tx.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("store: create postgres schema_migrations: %w", err)
	}

	applied := make(map[int]bool)
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: query postgres schema_migrations: %w", err)
	}
	for rows.Next() {
		var ver int
		if err := rows.Scan(&ver); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: scan postgres migration version: %w", err)
		}
		applied[ver] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: close postgres migration rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: iterate postgres migration rows: %w", err)
	}

	for _, m := range list {
		if applied[m.version] {
			continue
		}
		sqlBytes, err := pgMigrationsFS.ReadFile(m.path)
		if err != nil {
			return fmt.Errorf("store: read postgres migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("store: apply postgres migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
			m.version, m.name, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("store: record postgres migration %q: %w", m.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit postgres migrations: %w", err)
	}
	return nil
}

type pgMigrationFile struct {
	version int
	name    string
	path    string
}

func readPGMigrations() ([]pgMigrationFile, error) {
	entries, err := fs.ReadDir(pgMigrationsFS, "migrations_pg")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations_pg dir: %w", err)
	}
	var list []pgMigrationFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("store: invalid postgres migration filename %q", e.Name())
		}
		ver, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("store: parse postgres migration version %q: %w", e.Name(), err)
		}
		list = append(list, pgMigrationFile{
			version: ver,
			name:    e.Name(),
			path:    "migrations_pg/" + e.Name(),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].version < list[j].version })
	return list, nil
}

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
			err := tx.QueryRowContext(ctx, `SELECT api_key_enc FROM providers WHERE name = $1`, p.Name).Scan(&existingEnc)
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
			err := tx.QueryRowContext(ctx, `SELECT secret_enc FROM webhooks WHERE id = $1`, w.ID).Scan(&existingEnc)
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

// --- Providers ---

func (s *PostgresStore) UpsertProvider(ctx context.Context, p Provider) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("store: provider name is required")
	}
	apiKeyEnc := ""
	if p.APIKey != "" {
		var err error
		apiKeyEnc, err = s.cipher.EncryptString(p.APIKey)
		if err != nil {
			return fmt.Errorf("store: encrypt provider api key: %w", err)
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
		p.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert provider %q: %w", p.Name, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetProvider(ctx context.Context, name string) (*Provider, error) {
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

func (s *PostgresStore) ListProviders(ctx context.Context) ([]Provider, error) {
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

func (s *PostgresStore) DeleteProvider(ctx context.Context, name string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("store: delete provider %q: %w", name, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) scanProvider(sc scanner) (Provider, error) {
	var (
		p          Provider
		apiKeyEnc  string
		modelsJSON string
	)
	if err := sc.Scan(
		&p.Name, &p.Type, &p.BaseURL, &apiKeyEnc, &p.Passthrough,
		&modelsJSON, &p.Enabled, &p.Source, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return Provider{}, err
	}
	if apiKeyEnc != "" {
		dec, err := s.cipher.DecryptString(apiKeyEnc)
		if err != nil {
			return Provider{}, fmt.Errorf("store: decrypt api key for provider %q: %w", p.Name, err)
		}
		p.APIKey = dec
	}
	models, err := unmarshalStringSlice(modelsJSON)
	if err != nil {
		return Provider{}, fmt.Errorf("store: decode models for provider %q: %w", p.Name, err)
	}
	p.Models = models
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

// --- Model Routes ---

func (s *PostgresStore) UpsertModelRoute(ctx context.Context, r ModelRoute) error {
	if strings.TrimSpace(r.Alias) == "" {
		return errors.New("store: route alias is required")
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
		r.Alias, r.ProviderName, r.UpstreamModel, string(fallbacksJSON),
		nullableFloat(r.InputCostPerMillion), nullableFloat(r.OutputCostPerMillion),
		nullableFloat(r.CacheReadCostPerMillion), nullableFloat(r.CacheWriteCostPerMillion),
		r.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert model route %q: %w", r.Alias, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetModelRoute(ctx context.Context, alias string) (*ModelRoute, error) {
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

func (s *PostgresStore) ListModelRoutes(ctx context.Context) ([]ModelRoute, error) {
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

func (s *PostgresStore) DeleteModelRoute(ctx context.Context, alias string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM model_routes WHERE alias = $1`, alias)
	if err != nil {
		return fmt.Errorf("store: delete model route %q: %w", alias, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func pgScanModelRoute(sc scanner) (ModelRoute, error) {
	var (
		r             ModelRoute
		fallbacksJSON string
		inCost        sql.NullFloat64
		outCost       sql.NullFloat64
		cacheRead     sql.NullFloat64
		cacheWrite    sql.NullFloat64
	)
	if err := sc.Scan(
		&r.Alias, &r.ProviderName, &r.UpstreamModel, &fallbacksJSON,
		&inCost, &outCost, &cacheRead, &cacheWrite,
		&r.Enabled, &r.Source, &r.CreatedAt, &r.UpdatedAt,
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
	r.CreatedAt = r.CreatedAt.UTC()
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

// --- Budgets ---

func (s *PostgresStore) UpsertBudget(ctx context.Context, b Budget) error {
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
		scope, b.RPM, b.TPM, b.MaxConcurrent,
		nullableFloat(b.DailyUSD), nullableFloat(b.MonthlyUSD),
		softPct, b.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert budget %q: %w", scope, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetBudget(ctx context.Context, scope string) (*Budget, error) {
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

func (s *PostgresStore) ListBudgets(ctx context.Context) ([]Budget, error) {
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

func (s *PostgresStore) DeleteBudget(ctx context.Context, scope string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM budgets WHERE scope = $1`, scope)
	if err != nil {
		return fmt.Errorf("store: delete budget %q: %w", scope, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func pgScanBudget(sc scanner) (Budget, error) {
	var (
		b          Budget
		dailyUSD   sql.NullFloat64
		monthlyUSD sql.NullFloat64
	)
	if err := sc.Scan(
		&b.Scope, &b.RPM, &b.TPM, &b.MaxConcurrent, &dailyUSD, &monthlyUSD,
		&b.SoftAlertPct, &b.Enabled, &b.Source, &b.CreatedAt, &b.UpdatedAt,
	); err != nil {
		return Budget{}, err
	}
	b.DailyUSD = fromNullFloat(dailyUSD)
	b.MonthlyUSD = fromNullFloat(monthlyUSD)
	b.CreatedAt = b.CreatedAt.UTC()
	b.UpdatedAt = b.UpdatedAt.UTC()
	return b, nil
}

// --- Guardrail Rules ---

func (s *PostgresStore) UpsertGuardrailRule(ctx context.Context, r GuardrailRule) error {
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
		id, r.Name, category, r.Pattern, action, r.Builtin, r.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert guardrail rule %q: %w", id, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetGuardrailRule(ctx context.Context, id string) (*GuardrailRule, error) {
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

func (s *PostgresStore) ListGuardrailRules(ctx context.Context) ([]GuardrailRule, error) {
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

func (s *PostgresStore) DeleteGuardrailRule(ctx context.Context, id string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM guardrail_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete guardrail rule %q: %w", id, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func pgScanGuardrailRule(sc scanner) (GuardrailRule, error) {
	var r GuardrailRule
	if err := sc.Scan(
		&r.ID, &r.Name, &r.Category, &r.Pattern, &r.Action,
		&r.Builtin, &r.Enabled, &r.Source, &r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return GuardrailRule{}, err
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

// --- Webhooks ---

func (s *PostgresStore) UpsertWebhook(ctx context.Context, w Webhook) error {
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
		id, w.Name, w.URL, w.Type, secretEnc, eventsJSON, timeoutMS,
		w.FailOpen, w.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert webhook %q: %w", id, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
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

func (s *PostgresStore) ListWebhooks(ctx context.Context) ([]Webhook, error) {
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

func (s *PostgresStore) DeleteWebhook(ctx context.Context, id string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete webhook %q: %w", id, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) scanWebhook(sc scanner) (Webhook, error) {
	var (
		w          Webhook
		secretEnc  string
		eventsJSON string
	)
	if err := sc.Scan(
		&w.ID, &w.Name, &w.URL, &w.Type, &secretEnc, &eventsJSON,
		&w.TimeoutMS, &w.FailOpen, &w.Enabled, &w.Source, &w.CreatedAt, &w.UpdatedAt,
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
	w.CreatedAt = w.CreatedAt.UTC()
	w.UpdatedAt = w.UpdatedAt.UTC()
	return w, nil
}

// --- MCP Servers ---

func (s *PostgresStore) UpsertMCPServer(ctx context.Context, srv MCPServer) error {
	name := strings.TrimSpace(srv.Name)
	if name == "" {
		return errors.New("store: mcp server name is required")
	}
	if strings.Contains(name, "/") {
		return errors.New("store: mcp server name must not contain '/'")
	}
	transport := strings.ToLower(strings.TrimSpace(srv.Transport))
	if transport == "" {
		transport = config.MCPTransportStreamableHTTP
	}
	authType := strings.ToLower(strings.TrimSpace(srv.AuthType))
	if authType == "" {
		authType = config.MCPAuthNone
	}

	tokenEnc := ""
	if authType != config.MCPAuthNone && srv.AuthToken != "" {
		var err error
		tokenEnc, err = s.cipher.EncryptString(srv.AuthToken)
		if err != nil {
			return fmt.Errorf("store: encrypt auth token for mcp server %q: %w", name, err)
		}
	}

	now := time.Now().UTC()
	source := defaultSource(srv.Source)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	_, err := s.db.ExecContext(ctx, `
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
		name, strings.TrimSpace(srv.URL), transport, authType, strings.TrimSpace(srv.AuthHeader),
		tokenEnc, srv.Enabled, source, now, now,
	)
	if err != nil {
		return fmt.Errorf("store: upsert mcp server %q: %w", name, err)
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) GetMCPServer(ctx context.Context, name string) (*MCPServer, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	m, ok := snap.mcpServersByName[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := cloneMCPServer(m)
	return &cp, nil
}

func (s *PostgresStore) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(snap.mcpServers) == 0 {
		return nil, nil
	}
	out := make([]MCPServer, len(snap.mcpServers))
	for i, m := range snap.mcpServers {
		out[i] = cloneMCPServer(m)
	}
	return out, nil
}

func (s *PostgresStore) DeleteMCPServer(ctx context.Context, name string) error {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM mcp_servers WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("store: delete mcp server %q: %w", name, err)
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	s.cache = nil
	return nil
}

func (s *PostgresStore) scanMCPServer(sc scanner) (MCPServer, error) {
	var (
		m        MCPServer
		tokenEnc string
	)
	if err := sc.Scan(
		&m.Name, &m.URL, &m.Transport, &m.AuthType, &m.AuthHeader,
		&tokenEnc, &m.Enabled, &m.Source, &m.CreatedAt, &m.UpdatedAt,
	); err != nil {
		return MCPServer{}, err
	}
	if tokenEnc != "" {
		dec, err := s.cipher.DecryptString(tokenEnc)
		if err != nil {
			return MCPServer{}, fmt.Errorf("store: decrypt auth token for mcp server %q: %w", m.Name, err)
		}
		m.AuthToken = dec
	}
	m.CreatedAt = m.CreatedAt.UTC()
	m.UpdatedAt = m.UpdatedAt.UTC()
	return m, nil
}

// --- MCP Audit Logs ---

func (s *PostgresStore) InsertMCPAuditLog(ctx context.Context, log MCPAuditLog) error {
	if strings.TrimSpace(log.ID) == "" {
		log.ID = uuid.NewString()
	}
	createdAt := log.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	tagsJSON, err := marshalStringSlice(log.Tags)
	if err != nil {
		return fmt.Errorf("store: encode mcp audit tags: %w", err)
	}
	tagsJSON = string(stripPostgresJSONNUL([]byte(tagsJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO mcp_audit_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, server_name, method, tool_name, status,
	latency_ms, error_message, arguments_preview
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16)`,
		stripPostgresNUL(log.ID), createdAt, stripPostgresNUL(log.RequestID), stripPostgresNUL(log.Subject),
		stripPostgresNUL(log.DisplayName), stripPostgresNUL(log.NodeName), stripPostgresNUL(log.NodeIP),
		tagsJSON, stripPostgresNUL(log.AuthSource), stripPostgresNUL(log.ServerName),
		stripPostgresNUL(log.Method), stripPostgresNUL(log.ToolName), stripPostgresNUL(log.Status),
		log.LatencyMS, stripPostgresNUL(log.ErrorMessage), stripPostgresNUL(log.ArgumentsPreview),
	)
	if err != nil {
		return fmt.Errorf("store: insert mcp audit log %q: %w", log.ID, err)
	}
	return nil
}

func (s *PostgresStore) QueryMCPAuditLogs(ctx context.Context, filter MCPAuditFilter) ([]MCPAuditLog, error) {
	where, args := pgBuildMCPAuditWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, server_name, method, tool_name, status,
       latency_ms, error_message, arguments_preview
FROM mcp_audit_logs` + where + ` ORDER BY created_at DESC, id DESC`

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
		if filter.Offset > 0 {
			args = append(args, filter.Offset)
			query += fmt.Sprintf(` OFFSET $%d`, len(args))
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres mcp audit logs: %w", err)
	}
	defer rows.Close()

	var out []MCPAuditLog
	for rows.Next() {
		log, err := pgScanMCPAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func pgBuildMCPAuditWhere(filter MCPAuditFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(condFmt string, val any) {
		args = append(args, val)
		clauses = append(clauses, fmt.Sprintf(condFmt, len(args)))
	}

	if filter.ServerName != "" {
		add("server_name = $%d", filter.ServerName)
	}
	if filter.Subject != "" {
		add("subject = $%d", filter.Subject)
	}
	if filter.ToolName != "" {
		add("tool_name = $%d", filter.ToolName)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if !filter.Since.IsZero() {
		add("created_at >= $%d", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		add("created_at <= $%d", filter.Until.UTC())
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func pgScanMCPAuditLog(sc scanner) (MCPAuditLog, error) {
	var (
		log      MCPAuditLog
		tagsJSON string
	)
	if err := sc.Scan(
		&log.ID, &log.CreatedAt, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ServerName,
		&log.Method, &log.ToolName, &log.Status, &log.LatencyMS, &log.ErrorMessage,
		&log.ArgumentsPreview,
	); err != nil {
		return MCPAuditLog{}, err
	}
	tags, err := unmarshalStringSlice(tagsJSON)
	if err != nil {
		return MCPAuditLog{}, err
	}
	log.Tags = tags
	log.CreatedAt = log.CreatedAt.UTC()
	return log, nil
}

// --- Chat Sessions & Messages ---

func (s *PostgresStore) CreateChatSession(ctx context.Context, session ChatSession) (*ChatSession, error) {
	subject := strings.TrimSpace(session.Subject)
	if subject == "" {
		return nil, errors.New("store: chat session subject is required")
	}
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	session.Subject = subject
	if session.MCPServers == nil {
		session.MCPServers = []string{}
	}
	now := time.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	} else {
		session.CreatedAt = session.CreatedAt.UTC()
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = session.CreatedAt
	} else {
		session.UpdatedAt = session.UpdatedAt.UTC()
	}

	mcpJSON, err := marshalStringSlice(session.MCPServers)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat session mcp_servers: %w", err)
	}
	mcpJSON = string(stripPostgresJSONNUL([]byte(mcpJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO chat_sessions (id, subject, title, model, mcp_servers_json, system_prompt, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
		stripPostgresNUL(session.ID), stripPostgresNUL(session.Subject), stripPostgresNUL(session.Title),
		stripPostgresNUL(session.Model), mcpJSON, stripPostgresNUL(session.SystemPrompt),
		session.CreatedAt, session.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("store: create chat session %q: %w", session.ID, err)
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *PostgresStore) GetChatSession(ctx context.Context, subject, id string) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, subject, title, model, mcp_servers_json::text, system_prompt, created_at, updated_at
FROM chat_sessions WHERE id = $1 AND subject = $2`, id, subject)
	sess, err := pgScanChatSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get chat session %q: %w", id, err)
	}
	return &sess, nil
}

func (s *PostgresStore) ListChatSessions(ctx context.Context, subject string, limit, offset int) ([]ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, nil
	}
	query := `
SELECT id, subject, title, model, mcp_servers_json::text, system_prompt, created_at, updated_at
FROM chat_sessions WHERE subject = $1 ORDER BY updated_at DESC, created_at DESC, id DESC`
	args := []any{subject}
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
		if offset > 0 {
			args = append(args, offset)
			query += fmt.Sprintf(` OFFSET $%d`, len(args))
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list postgres chat sessions: %w", err)
	}
	defer rows.Close()

	var out []ChatSession
	for rows.Next() {
		sess, err := pgScanChatSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateChatSession(ctx context.Context, subject string, session ChatSession) (*ChatSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(session.ID) == "" {
		return nil, ErrNotFound
	}
	mcpJSON, err := marshalStringSlice(session.MCPServers)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat session mcp_servers: %w", err)
	}
	mcpJSON = string(stripPostgresJSONNUL([]byte(mcpJSON)))
	res, err := s.db.ExecContext(ctx, `
UPDATE chat_sessions
SET title = $1, model = $2, mcp_servers_json = $3::jsonb, system_prompt = $4, updated_at = $5
WHERE id = $6 AND subject = $7`,
		stripPostgresNUL(session.Title), stripPostgresNUL(session.Model), mcpJSON,
		stripPostgresNUL(session.SystemPrompt), time.Now().UTC(), session.ID, subject,
	)
	if err != nil {
		return nil, fmt.Errorf("store: update chat session %q: %w", session.ID, err)
	}
	if err := checkAffected(res); err != nil {
		return nil, err
	}
	return s.GetChatSession(ctx, subject, session.ID)
}

func (s *PostgresStore) DeleteChatSession(ctx context.Context, subject, id string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(id) == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM chat_sessions WHERE id = $1 AND subject = $2`, id, subject)
	if err != nil {
		return fmt.Errorf("store: delete chat session %q: %w", id, err)
	}
	return checkAffected(res)
}

func (s *PostgresStore) InsertChatMessage(ctx context.Context, subject string, msg ChatMessage) (*ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(msg.SessionID) == "" {
		return nil, ErrNotFound
	}
	if strings.TrimSpace(msg.ID) == "" {
		msg.ID = uuid.NewString()
	}
	msg.Role = stripPostgresNUL(msg.Role)
	msg.Content = stripPostgresNUL(msg.Content)
	msg.Model = stripPostgresNUL(msg.Model)
	if msg.ToolEvents == nil {
		msg.ToolEvents = []ChatToolEvent{}
	} else {
		cleaned := make([]ChatToolEvent, len(msg.ToolEvents))
		for i, ev := range msg.ToolEvents {
			ev.ID = stripPostgresNUL(ev.ID)
			ev.Server = stripPostgresNUL(ev.Server)
			ev.Tool = stripPostgresNUL(ev.Tool)
			ev.Result = stripPostgresNUL(ev.Result)
			if len(ev.Arguments) > 0 {
				ev.Arguments = stripPostgresJSONNUL(ev.Arguments)
			}
			cleaned[i] = ev
		}
		msg.ToolEvents = cleaned
	}
	createdAt := msg.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	msg.CreatedAt = createdAt

	eventsJSON, err := marshalChatToolEvents(msg.ToolEvents)
	if err != nil {
		return nil, fmt.Errorf("store: encode chat tool_events: %w", err)
	}
	eventsJSON = string(stripPostgresJSONNUL([]byte(eventsJSON)))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin insert chat message: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = $1 AND subject = $2`, msg.SessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO chat_messages (id, session_id, role, content, tool_events_json, model, input_tokens, output_tokens, cost_usd, created_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`,
		stripPostgresNUL(msg.ID), stripPostgresNUL(msg.SessionID), msg.Role, msg.Content, eventsJSON,
		msg.Model, msg.InputTokens, msg.OutputTokens, msg.CostUSD, createdAt,
	); err != nil {
		return nil, fmt.Errorf("store: insert chat message %q: %w", msg.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chat_sessions SET updated_at = $1 WHERE id = $2 AND subject = $3`,
		time.Now().UTC(), msg.SessionID, subject,
	); err != nil {
		return nil, fmt.Errorf("store: touch chat session %q: %w", msg.SessionID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit insert chat message: %w", err)
	}
	cp := msg
	cp.ToolEvents = slices.Clone(msg.ToolEvents)
	return &cp, nil
}

func (s *PostgresStore) ListChatMessages(ctx context.Context, subject, sessionID string) ([]ChatMessage, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" || strings.TrimSpace(sessionID) == "" {
		return nil, ErrNotFound
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM chat_sessions WHERE id = $1 AND subject = $2`, sessionID, subject).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: verify chat session ownership: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, role, content, tool_events_json::text, model, input_tokens, output_tokens, cost_usd, created_at
FROM chat_messages WHERE session_id = $1 ORDER BY created_at ASC, seq ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store: list postgres chat messages: %w", err)
	}
	defer rows.Close()

	var out []ChatMessage
	for rows.Next() {
		m, err := pgScanChatMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error {
	subject = strings.TrimSpace(subject)
	sessionID = strings.TrimSpace(sessionID)
	messageID = strings.TrimSpace(messageID)
	if subject == "" || sessionID == "" || messageID == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
DELETE FROM chat_messages
WHERE id = $1 AND session_id = $2
  AND EXISTS (SELECT 1 FROM chat_sessions WHERE id = $2 AND subject = $3)`,
		messageID, sessionID, subject,
	)
	if err != nil {
		return fmt.Errorf("store: delete postgres chat message %q: %w", messageID, err)
	}
	return checkAffected(res)
}

func pgScanChatSession(sc scanner) (ChatSession, error) {
	var (
		sess    ChatSession
		mcpJSON string
	)
	if err := sc.Scan(
		&sess.ID, &sess.Subject, &sess.Title, &sess.Model,
		&mcpJSON, &sess.SystemPrompt, &sess.CreatedAt, &sess.UpdatedAt,
	); err != nil {
		return ChatSession{}, err
	}
	servers, err := unmarshalStringSlice(mcpJSON)
	if err != nil {
		return ChatSession{}, fmt.Errorf("store: decode chat session mcp_servers: %w", err)
	}
	if servers == nil {
		servers = []string{}
	}
	sess.MCPServers = servers
	sess.CreatedAt = sess.CreatedAt.UTC()
	sess.UpdatedAt = sess.UpdatedAt.UTC()
	return sess, nil
}

func pgScanChatMessage(sc scanner) (ChatMessage, error) {
	var (
		msg        ChatMessage
		eventsJSON string
	)
	if err := sc.Scan(
		&msg.ID, &msg.SessionID, &msg.Role, &msg.Content, &eventsJSON,
		&msg.Model, &msg.InputTokens, &msg.OutputTokens, &msg.CostUSD, &msg.CreatedAt,
	); err != nil {
		return ChatMessage{}, err
	}
	events, err := unmarshalChatToolEvents(eventsJSON)
	if err != nil {
		return ChatMessage{}, fmt.Errorf("store: decode chat tool_events: %w", err)
	}
	msg.ToolEvents = events
	msg.CreatedAt = msg.CreatedAt.UTC()
	return msg, nil
}

// --- Runtime Settings ---

func (s *PostgresStore) GetAuditSettings(ctx context.Context) (*AuditSettings, error) {
	var (
		valueJSON string
		updatedAt time.Time
	)
	err := s.db.QueryRowContext(ctx, `
SELECT value_json::text, updated_at FROM runtime_settings WHERE key = $1`, runtimeSettingAuditKey).
		Scan(&valueJSON, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get postgres audit settings: %w", err)
	}
	var out AuditSettings
	if err := json.Unmarshal([]byte(valueJSON), &out); err != nil {
		return nil, fmt.Errorf("store: decode audit settings: %w", err)
	}
	out.UpdatedAt = updatedAt.UTC()
	return &out, nil
}

func (s *PostgresStore) SetAuditSettings(ctx context.Context, settings AuditSettings) error {
	if settings.RetentionDays < 0 {
		return fmt.Errorf("store: retention_days must be >= 0, got %d", settings.RetentionDays)
	}
	payload, err := json.Marshal(struct {
		StorePayloads bool `json:"store_payloads"`
		RetentionDays int  `json:"retention_days"`
	}{
		StorePayloads: settings.StorePayloads,
		RetentionDays: settings.RetentionDays,
	})
	if err != nil {
		return fmt.Errorf("store: encode audit settings: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES ($1, $2::jsonb, $3)
ON CONFLICT(key) DO UPDATE SET
	value_json = excluded.value_json,
	updated_at = excluded.updated_at`,
		runtimeSettingAuditKey, string(payload), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("store: set postgres audit settings: %w", err)
	}
	return nil
}

// --- Usage Logs & Dashboard Analytics ---

func (s *PostgresStore) InsertUsageLog(ctx context.Context, log UsageLog) error {
	if strings.TrimSpace(log.ID) == "" {
		log.ID = uuid.NewString()
	}
	createdAt := log.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	tagsJSON, err := marshalStringSlice(log.Tags)
	if err != nil {
		return fmt.Errorf("store: encode usage tags: %w", err)
	}
	tagsJSON = string(stripPostgresJSONNUL([]byte(tagsJSON)))
	hitsJSON, err := marshalStringSlice(log.GuardrailHits)
	if err != nil {
		return fmt.Errorf("store: encode guardrail hits: %w", err)
	}
	hitsJSON = string(stripPostgresJSONNUL([]byte(hitsJSON)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, provider_name, provider_type, requested_model,
	upstream_model, protocol, endpoint, stream, translated,
	input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
	reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
	status_code, error_message, guardrail_action, guardrail_hits_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30::jsonb)`,
		stripPostgresNUL(log.ID), createdAt, stripPostgresNUL(log.RequestID), stripPostgresNUL(log.Subject),
		stripPostgresNUL(log.DisplayName), stripPostgresNUL(log.NodeName), stripPostgresNUL(log.NodeIP),
		tagsJSON, stripPostgresNUL(log.AuthSource), stripPostgresNUL(log.ProviderName),
		stripPostgresNUL(log.ProviderType), stripPostgresNUL(log.RequestedModel), stripPostgresNUL(log.UpstreamModel),
		stripPostgresNUL(log.Protocol), stripPostgresNUL(log.Endpoint), log.Stream, log.Translated,
		log.InputTokens, log.OutputTokens, log.CacheReadTokens, log.CacheWriteTokens,
		log.ReasoningTokens, log.TotalTokens, log.CostUSD, log.LatencyMS, log.TTFTMS,
		log.StatusCode, stripPostgresNUL(log.ErrorMessage), stripPostgresNUL(log.GuardrailAction), hitsJSON,
	)
	if err != nil {
		return fmt.Errorf("store: insert postgres usage log %q: %w", log.ID, err)
	}
	return nil
}

func (s *PostgresStore) GetUsageLog(ctx context.Context, id string) (*UsageLog, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json::text
FROM usage_logs WHERE id = $1`, id)

	log, err := pgScanUsageLog(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &log, nil
}

func (s *PostgresStore) QueryUsageLogs(ctx context.Context, filter UsageFilter) ([]UsageLog, error) {
	where, args := pgBuildUsageWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json::text, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json::text
FROM usage_logs` + where + ` ORDER BY created_at DESC, id DESC`

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
		if filter.Offset > 0 {
			args = append(args, filter.Offset)
			query += fmt.Sprintf(` OFFSET $%d`, len(args))
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres usage logs: %w", err)
	}
	defer rows.Close()

	var out []UsageLog
	for rows.Next() {
		log, err := pgScanUsageLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SummarizeUsage(ctx context.Context, filter UsageFilter) (UsageSummary, error) {
	where, args := pgBuildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0)
FROM usage_logs` + where

	var sum UsageSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&sum.RequestCount, &sum.InputTokens, &sum.OutputTokens,
		&sum.CacheReadTokens, &sum.CacheWriteTokens, &sum.ReasoningTokens,
		&sum.TotalTokens, &sum.CostUSD,
	); err != nil {
		return UsageSummary{}, fmt.Errorf("store: summarize postgres usage: %w", err)
	}
	return sum, nil
}

func (s *PostgresStore) SummarizeUsageExtended(ctx context.Context, filter UsageFilter) (UsageExtendedSummary, error) {
	where, args := pgBuildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0),
       COALESCE((percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms))::bigint, 0)
FROM usage_logs` + where

	var ext UsageExtendedSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&ext.RequestCount, &ext.InputTokens, &ext.OutputTokens,
		&ext.CacheReadTokens, &ext.CacheWriteTokens, &ext.ReasoningTokens,
		&ext.TotalTokens, &ext.CostUSD, &ext.ErrorCount, &ext.P95LatencyMS,
	); err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: summarize postgres usage extended: %w", err)
	}
	return ext, nil
}

func (s *PostgresStore) QueryUsageSeries(ctx context.Context, filter UsageFilter, bucket string) ([]UsageTimeBucket, error) {
	var bucketExpr string
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "hour":
		bucketExpr = `to_char(date_trunc('hour', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:00:00"Z"')`
	case "", "day":
		bucketExpr = `to_char(date_trunc('day', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD')`
	default:
		return nil, fmt.Errorf("store: invalid usage series bucket %q (must be hour or day)", bucket)
	}

	where, args := pgBuildUsageWhere(filter)
	query := fmt.Sprintf(`
SELECT %s AS bucket,
       COUNT(*),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0)
FROM usage_logs%s
GROUP BY bucket
ORDER BY bucket ASC`, bucketExpr, where)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres usage series: %w", err)
	}
	defer rows.Close()

	var out []UsageTimeBucket
	for rows.Next() {
		var b UsageTimeBucket
		if err := rows.Scan(&b.Bucket, &b.Requests, &b.Tokens, &b.CostUSD, &b.Errors); err != nil {
			return nil, fmt.Errorf("store: scan postgres usage series bucket: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueryTopSubjects(ctx context.Context, filter UsageFilter, limit int) ([]SubjectUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := pgBuildUsageWhere(filter)
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT subject,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs%s
GROUP BY subject
ORDER BY total_cost DESC, req_count DESC, subject ASC
LIMIT $%d`, where, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres top subjects: %w", err)
	}
	defer rows.Close()

	var out []SubjectUsageStat
	for rows.Next() {
		var st SubjectUsageStat
		if err := rows.Scan(&st.Subject, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan postgres top subject: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueryTopModels(ctx context.Context, filter UsageFilter, limit int) ([]ModelUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := pgBuildUsageWhere(filter)
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT requested_model,
       provider_name,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs%s
GROUP BY requested_model, provider_name
ORDER BY total_cost DESC, req_count DESC, requested_model ASC
LIMIT $%d`, where, len(args))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query postgres top models: %w", err)
	}
	defer rows.Close()

	var out []ModelUsageStat
	for rows.Next() {
		var st ModelUsageStat
		if err := rows.Scan(&st.Model, &st.Provider, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan postgres top model: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func pgBuildUsageWhere(filter UsageFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.Subject != "" {
		args = append(args, filter.Subject)
		clauses = append(clauses, fmt.Sprintf("subject = $%d", len(args)))
	}
	if filter.Tag != "" {
		args = append(args, filter.Tag)
		p1 := len(args)
		args = append(args, filter.Tag)
		p2 := len(args)
		clauses = append(clauses, fmt.Sprintf("(subject = $%d OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(usage_logs.tags_json) AS elem WHERE elem = $%d))", p1, p2))
	}
	if filter.ProviderName != "" {
		args = append(args, filter.ProviderName)
		clauses = append(clauses, fmt.Sprintf("provider_name = $%d", len(args)))
	}
	if filter.Model != "" {
		args = append(args, filter.Model)
		p1 := len(args)
		args = append(args, filter.Model)
		p2 := len(args)
		clauses = append(clauses, fmt.Sprintf("(requested_model = $%d OR upstream_model = $%d)", p1, p2))
	}
	if filter.StatusCode > 0 {
		args = append(args, filter.StatusCode)
		clauses = append(clauses, fmt.Sprintf("status_code = $%d", len(args)))
	}
	if filter.ErrorsOnly {
		clauses = append(clauses, "(status_code >= 400 OR status_code = 0 OR error_message != '')")
	}
	if filter.GuardrailOnly {
		clauses = append(clauses, "guardrail_action != ''")
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !filter.Until.IsZero() {
		args = append(args, filter.Until.UTC())
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func pgScanUsageLog(sc scanner) (UsageLog, error) {
	var (
		log      UsageLog
		tagsJSON string
		hitsJSON string
	)
	if err := sc.Scan(
		&log.ID, &log.CreatedAt, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ProviderName,
		&log.ProviderType, &log.RequestedModel, &log.UpstreamModel, &log.Protocol,
		&log.Endpoint, &log.Stream, &log.Translated,
		&log.InputTokens, &log.OutputTokens, &log.CacheReadTokens, &log.CacheWriteTokens,
		&log.ReasoningTokens, &log.TotalTokens, &log.CostUSD, &log.LatencyMS, &log.TTFTMS,
		&log.StatusCode, &log.ErrorMessage, &log.GuardrailAction, &hitsJSON,
	); err != nil {
		return UsageLog{}, err
	}
	tags, err := unmarshalStringSlice(tagsJSON)
	if err != nil {
		return UsageLog{}, err
	}
	hits, err := unmarshalStringSlice(hitsJSON)
	if err != nil {
		return UsageLog{}, err
	}
	log.Tags = tags
	log.GuardrailHits = hits
	log.CreatedAt = log.CreatedAt.UTC()
	return log, nil
}

// --- Audit Payloads & Retention ---

func (s *PostgresStore) InsertAuditPayload(ctx context.Context, payload AuditPayload) error {
	if strings.TrimSpace(payload.UsageLogID) == "" {
		return errors.New("store: audit payload usage_log_id is required")
	}
	if strings.TrimSpace(payload.ID) == "" {
		payload.ID = uuid.NewString()
	}
	createdAt := payload.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	reqHeaders, err := marshalStringMap(payload.RequestHeaders)
	if err != nil {
		return fmt.Errorf("store: encode request headers: %w", err)
	}
	reqHeaders = string(stripPostgresJSONNUL([]byte(reqHeaders)))
	respHeaders, err := marshalStringMap(payload.ResponseHeaders)
	if err != nil {
		return fmt.Errorf("store: encode response headers: %w", err)
	}
	respHeaders = string(stripPostgresJSONNUL([]byte(respHeaders)))

	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_payloads (
	id, usage_log_id, created_at, request_headers_json, request_body,
	response_headers_json, response_body, redacted
)
VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8)`,
		stripPostgresNUL(payload.ID), stripPostgresNUL(payload.UsageLogID), createdAt, reqHeaders,
		stripPostgresNUL(payload.RequestBody), respHeaders, stripPostgresNUL(payload.ResponseBody), payload.Redacted,
	)
	if err != nil {
		return fmt.Errorf("store: insert postgres audit payload: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAuditPayloadByUsageLogID(ctx context.Context, usageLogID string) (*AuditPayload, error) {
	var (
		p           AuditPayload
		reqHeaders  string
		respHeaders string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, usage_log_id, created_at, request_headers_json::text, request_body,
       response_headers_json::text, response_body, redacted
FROM audit_payloads WHERE usage_log_id = $1`, usageLogID).
		Scan(&p.ID, &p.UsageLogID, &p.CreatedAt, &reqHeaders, &p.RequestBody,
			&respHeaders, &p.ResponseBody, &p.Redacted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get postgres audit payload for %q: %w", usageLogID, err)
	}
	if p.RequestHeaders, err = unmarshalStringMap(reqHeaders); err != nil {
		return nil, err
	}
	if p.ResponseHeaders, err = unmarshalStringMap(respHeaders); err != nil {
		return nil, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

func (s *PostgresStore) PurgeAuditPayloads(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_payloads WHERE created_at < $1`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: purge postgres audit payloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge postgres audit payloads rows affected: %w", err)
	}
	return n, nil
}

// stripPostgresNUL removes NUL (0x00) bytes which PostgreSQL TEXT columns reject (SQLSTATE 22P05).
func stripPostgresNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// stripPostgresJSONNUL removes raw NUL bytes (0x00) and unescaped JSON Unicode NUL escapes
// (\u0000 / \U0000) which PostgreSQL JSONB columns reject (SQLSTATE 22P05), while preserving
// escaped literal backslash sequences such as \\u0000.
func stripPostgresJSONNUL(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	needsScan := false
	for _, c := range b {
		if c == 0 || c == '\\' {
			needsScan = true
			break
		}
	}
	if !needsScan {
		return b
	}

	out := make([]byte, 0, len(b))
	backslashes := 0
	for i := 0; i < len(b); {
		c := b[i]
		if c == 0 {
			i++
			continue
		}
		if c == '\\' && backslashes%2 == 0 && i+5 < len(b) &&
			(b[i+1] == 'u' || b[i+1] == 'U') &&
			b[i+2] == '0' && b[i+3] == '0' && b[i+4] == '0' && b[i+5] == '0' {
			i += 6
			continue
		}
		out = append(out, c)
		if c == '\\' {
			backslashes++
		} else {
			backslashes = 0
		}
		i++
	}
	return out
}
