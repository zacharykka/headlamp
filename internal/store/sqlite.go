package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const runtimeSettingAuditKey = "audit"

type configSnapshot struct {
	providers       []Provider
	providersByName map[string]Provider
	routes          []ModelRoute
	routesByAlias   map[string]ModelRoute
	budgets         []Budget
	budgetsByScope  map[string]Budget
	guardrails      []GuardrailRule
	guardrailsByID  map[string]GuardrailRule
	webhooks        []Webhook
	webhooksByID    map[string]Webhook
}

// SQLiteStore implements Store backed by pure-Go modernc.org/sqlite.
// Decrypted providers, model routes, budgets, guardrail rules, and webhooks are
// served from an immutable in-memory snapshot cache that is atomically invalidated on mutations.
type SQLiteStore struct {
	db     *sql.DB
	cipher *crypto.Cipher

	cacheMu    sync.RWMutex
	cache      *configSnapshot
	cacheLoads atomic.Int64
}

// NewSQLiteStore opens a SQLite database with WAL mode, busy_timeout, and foreign_keys ON,
// tightens file-backed directory/file permissions (0700/0600), and runs all embedded SQL migrations.
func NewSQLiteStore(ctx context.Context, dsn string, cipher *crypto.Cipher) (*SQLiteStore, error) {
	if cipher == nil {
		return nil, errors.New("store: cipher is required")
	}
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("store: sqlite dsn is required")
	}

	connDSN, filePath, isMemory, err := prepareSQLiteDSN(dsn)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", connDSN)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite %q: %w", dsn, err)
	}

	// Bounding SQLite to a single open connection eliminates intra-process SQLITE_BUSY
	// contention while WAL still permits concurrent external readers and backups.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping sqlite: %w", err)
	}

	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
	if !isMemory {
		pragmas = append(pragmas,
			"PRAGMA journal_mode = WAL",
			"PRAGMA synchronous = NORMAL",
		)
	}
	for _, stmt := range pragmas {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: exec %q: %w", stmt, err)
		}
	}

	s := &SQLiteStore{
		db:     db,
		cipher: cipher,
	}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	if !isMemory && filePath != "" {
		if err := os.Chmod(filePath, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: chmod sqlite db %q: %w", filePath, err)
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if err := os.Chmod(filePath+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
				_ = db.Close()
				return nil, fmt.Errorf("store: chmod sqlite file %q: %w", filePath+suffix, err)
			}
		}
	}

	return s, nil
}

// DB exposes the underlying *sql.DB for diagnostics or tests.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// Close closes the underlying SQLite database connection.
func (s *SQLiteStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Migrate applies all unapplied embedded SQL migrations in ascending version order.
func (s *SQLiteStore) Migrate(ctx context.Context) error {
	const createTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at TEXT NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations dir: %w", err)
	}

	type migration struct {
		version int
		name    string
		path    string
	}
	var list []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return fmt.Errorf("store: invalid migration filename %q", e.Name())
		}
		ver, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("store: parse migration version %q: %w", e.Name(), err)
		}
		list = append(list, migration{
			version: ver,
			name:    e.Name(),
			path:    "migrations/" + e.Name(),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].version < list[j].version })

	applied := make(map[int]bool)
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: query schema_migrations: %w", err)
	}
	for rows.Next() {
		var ver int
		if err := rows.Scan(&ver); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: scan migration version: %w", err)
		}
		applied[ver] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: close migration rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: iterate migration rows: %w", err)
	}

	for _, m := range list {
		if applied[m.version] {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile(m.path)
		if err != nil {
			return fmt.Errorf("store: read migration %q: %w", m.name, err)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			m.version, m.name, formatTime(time.Now().UTC()),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %q: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %q: %w", m.name, err)
		}
	}

	return nil
}

// SyncConfig idempotently syncs YAML providers, model routes, budgets, built-in + custom
// guardrail rules, and webhooks into SQLite within a single transaction, pruning any stale
// source='config' rows removed from cfg while leaving source='local' UI rows untouched.
// Existing encrypted provider API keys and webhook secrets are preserved when YAML omits them.
func (s *SQLiteStore) SyncConfig(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: sync config begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	nowStr := formatTime(now)

	// 1. Providers
	providerNames := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		providerNames = append(providerNames, p.Name)

		apiKeyEnc := ""
		if p.APIKey != "" {
			apiKeyEnc, err = s.cipher.EncryptString(p.APIKey)
			if err != nil {
				return fmt.Errorf("store: encrypt api_key for provider %q: %w", p.Name, err)
			}
		} else {
			var existingEnc string
			err := tx.QueryRowContext(ctx, `SELECT api_key_enc FROM providers WHERE name = ?`, p.Name).Scan(&existingEnc)
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
			boolToInt(p.IsEnabled()), SourceConfig, nowStr, nowStr,
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
			r.Alias, r.Provider, r.Model, string(fallbacksJSON),
			nullableFloat(r.InputCostPerMillion), nullableFloat(r.OutputCostPerMillion),
			nullableFloat(r.CacheReadCostPerMillion), nullableFloat(r.CacheWriteCostPerMillion),
			boolToInt(r.IsEnabled()), SourceConfig, nowStr, nowStr,
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
		if softPct == 0 {
			softPct = 80
		}
		_, err = tx.ExecContext(ctx, `
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
			b.Scope, b.RPM, b.TPM, b.MaxConcurrent,
			nullableFloat(b.DailyUSD), nullableFloat(b.MonthlyUSD),
			softPct, boolToInt(b.IsEnabled()), SourceConfig, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("store: sync budget %q: %w", b.Scope, err)
		}
	}

	// 4. Built-in + YAML guardrail rules
	builtins := DefaultBuiltinGuardrailRules()
	builtinIDs := make(map[string]bool, len(builtins))
	for _, br := range builtins {
		builtinIDs[br.ID] = true
	}

	keepGuardrailIDs := make([]string, 0, len(builtins)+len(cfg.Guardrails.Rules))
	if cfg.Guardrails.UseBuiltinDefaults() {
		for _, br := range builtins {
			keepGuardrailIDs = append(keepGuardrailIDs, br.ID)
			// Seed built-in defaults without clobbering Admin UI customizations (source='local').
			_, err = tx.ExecContext(ctx, `
INSERT INTO guardrail_rules (id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
				br.ID, br.Name, br.Category, br.Pattern, br.Action,
				boolToInt(br.Enabled), SourceConfig, nowStr, nowStr,
			)
			if err != nil {
				return fmt.Errorf("store: seed builtin guardrail %q: %w", br.ID, err)
			}
		}
	}

	for _, r := range cfg.Guardrails.Rules {
		keepGuardrailIDs = append(keepGuardrailIDs, r.ID)
		_, err = tx.ExecContext(ctx, `
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
			r.ID, r.Name, r.Category, r.Pattern, r.Action,
			boolToInt(builtinIDs[r.ID]), boolToInt(r.IsEnabled()), SourceConfig, nowStr, nowStr,
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
			err := tx.QueryRowContext(ctx, `SELECT secret_enc FROM webhooks WHERE id = ?`, w.ID).Scan(&existingEnc)
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
			w.ID, w.Name, w.URL, w.Type, secretEnc, eventsJSON, timeoutMS,
			boolToInt(w.IsFailOpen()), boolToInt(w.IsEnabled()), SourceConfig, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("store: sync webhook %q: %w", w.ID, err)
		}
	}

	// Prune stale config-managed rows (delete model_routes BEFORE providers for FK safety).
	if err := deleteStaleConfigRowsTx(ctx, tx, "model_routes", "alias", routeAliases); err != nil {
		return err
	}
	if err := deleteStaleConfigRowsTx(ctx, tx, "providers", "name", providerNames); err != nil {
		return err
	}
	if err := deleteStaleConfigRowsTx(ctx, tx, "budgets", "scope", budgetScopes); err != nil {
		return err
	}
	if err := deleteStaleConfigRowsTx(ctx, tx, "guardrail_rules", "id", keepGuardrailIDs); err != nil {
		return err
	}
	if err := deleteStaleConfigRowsTx(ctx, tx, "webhooks", "id", webhookIDs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: sync config commit: %w", err)
	}

	s.cache = nil
	return nil
}

func deleteStaleConfigRowsTx(ctx context.Context, tx *sql.Tx, table, keyCol string, keepKeys []string) error {
	if len(keepKeys) == 0 {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE source = ?`, table), SourceConfig); err != nil {
			return fmt.Errorf("store: delete stale config rows from %s: %w", table, err)
		}
		return nil
	}

	placeholders := make([]string, len(keepKeys))
	args := make([]any, 0, len(keepKeys)+1)
	args = append(args, SourceConfig)
	for i, k := range keepKeys {
		placeholders[i] = "?"
		args = append(args, k)
	}
	query := fmt.Sprintf(
		`DELETE FROM %s WHERE source = ? AND %s NOT IN (%s)`,
		table, keyCol, strings.Join(placeholders, ","),
	)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("store: delete stale config rows from %s: %w", table, err)
	}
	return nil
}

// --- Snapshot Cache ---

func (s *SQLiteStore) snapshot(ctx context.Context) (*configSnapshot, error) {
	s.cacheMu.RLock()
	snap := s.cache
	s.cacheMu.RUnlock()
	if snap != nil {
		return snap, nil
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache != nil {
		return s.cache, nil
	}

	loaded, err := s.loadSnapshotLocked(ctx)
	if err != nil {
		return nil, err
	}
	s.cache = loaded
	s.cacheLoads.Add(1)
	return loaded, nil
}

func (s *SQLiteStore) loadSnapshotLocked(ctx context.Context) (*configSnapshot, error) {
	// Providers
	provRows, err := s.db.QueryContext(ctx, `
SELECT name, type, base_url, api_key_enc, passthrough, models_json, enabled, source, created_at, updated_at
FROM providers ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load providers snapshot: %w", err)
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
	routeRows, err := s.db.QueryContext(ctx, `
SELECT alias, provider_name, upstream_model, fallbacks_json,
       input_cost_per_million, output_cost_per_million,
       cache_read_cost_per_million, cache_write_cost_per_million,
       enabled, source, created_at, updated_at
FROM model_routes ORDER BY alias ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load model routes snapshot: %w", err)
	}
	var routes []ModelRoute
	for routeRows.Next() {
		r, err := scanModelRoute(routeRows)
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
	budgetRows, err := s.db.QueryContext(ctx, `
SELECT scope, rpm, tpm, max_concurrent, daily_usd, monthly_usd,
       soft_alert_pct, enabled, source, created_at, updated_at
FROM budgets ORDER BY scope ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load budgets snapshot: %w", err)
	}
	var budgets []Budget
	for budgetRows.Next() {
		b, err := scanBudget(budgetRows)
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
	ruleRows, err := s.db.QueryContext(ctx, `
SELECT id, name, category, pattern, action, builtin, enabled, source, created_at, updated_at
FROM guardrail_rules ORDER BY builtin DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load guardrail rules snapshot: %w", err)
	}
	var guardrails []GuardrailRule
	for ruleRows.Next() {
		r, err := scanGuardrailRule(ruleRows)
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
	whRows, err := s.db.QueryContext(ctx, `
SELECT id, name, url, type, secret_enc, events_json, timeout_ms, fail_open, enabled, source, created_at, updated_at
FROM webhooks ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: load webhooks snapshot: %w", err)
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

	return &configSnapshot{
		providers:       providers,
		providersByName: byName,
		routes:          routes,
		routesByAlias:   byAlias,
		budgets:         budgets,
		budgetsByScope:  byScope,
		guardrails:      guardrails,
		guardrailsByID:  byRuleID,
		webhooks:        webhooks,
		webhooksByID:    byWebhookID,
	}, nil
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

func cloneFloatPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

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

// --- Runtime Settings ---

func (s *SQLiteStore) GetAuditSettings(ctx context.Context) (*AuditSettings, error) {
	var (
		valueJSON    string
		updatedAtStr string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT value_json, updated_at FROM runtime_settings WHERE key = ?`, runtimeSettingAuditKey).
		Scan(&valueJSON, &updatedAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get audit settings: %w", err)
	}

	var out AuditSettings
	if err := json.Unmarshal([]byte(valueJSON), &out); err != nil {
		return nil, fmt.Errorf("store: decode audit settings: %w", err)
	}
	out.UpdatedAt = parseTime(updatedAtStr)
	return &out, nil
}

func (s *SQLiteStore) SetAuditSettings(ctx context.Context, settings AuditSettings) error {
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

	nowStr := formatTime(time.Now().UTC())
	_, err = s.db.ExecContext(ctx, `
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
	value_json = excluded.value_json,
	updated_at = excluded.updated_at`,
		runtimeSettingAuditKey, string(payload), nowStr,
	)
	if err != nil {
		return fmt.Errorf("store: set audit settings: %w", err)
	}
	return nil
}

// --- Usage Logs & Dashboard Analytics ---

func (s *SQLiteStore) InsertUsageLog(ctx context.Context, log UsageLog) error {
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
	hitsJSON, err := marshalStringSlice(log.GuardrailHits)
	if err != nil {
		return fmt.Errorf("store: encode guardrail hits: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, provider_name, provider_type, requested_model,
	upstream_model, protocol, endpoint, stream, translated,
	input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
	reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
	status_code, error_message, guardrail_action, guardrail_hits_json
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, formatTime(createdAt), log.RequestID, log.Subject, log.DisplayName,
		log.NodeName, log.NodeIP, tagsJSON, log.AuthSource, log.ProviderName,
		log.ProviderType, log.RequestedModel, log.UpstreamModel, log.Protocol,
		log.Endpoint, boolToInt(log.Stream), boolToInt(log.Translated),
		log.InputTokens, log.OutputTokens, log.CacheReadTokens, log.CacheWriteTokens,
		log.ReasoningTokens, log.TotalTokens, log.CostUSD, log.LatencyMS, log.TTFTMS,
		log.StatusCode, log.ErrorMessage, log.GuardrailAction, hitsJSON,
	)
	if err != nil {
		return fmt.Errorf("store: insert usage log %q: %w", log.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetUsageLog(ctx context.Context, id string) (*UsageLog, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json
FROM usage_logs WHERE id = ?`, id)

	log, err := scanUsageLog(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &log, nil
}

func (s *SQLiteStore) QueryUsageLogs(ctx context.Context, filter UsageFilter) ([]UsageLog, error) {
	where, args := buildUsageWhere(filter)
	query := `
SELECT id, created_at, request_id, subject, display_name, node_name, node_ip,
       tags_json, auth_source, provider_name, provider_type, requested_model,
       upstream_model, protocol, endpoint, stream, translated,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
       reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
       status_code, error_message, guardrail_action, guardrail_hits_json
FROM usage_logs` + where + ` ORDER BY created_at DESC`

	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query usage logs: %w", err)
	}
	defer rows.Close()

	var out []UsageLog
	for rows.Next() {
		log, err := scanUsageLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SummarizeUsage(ctx context.Context, filter UsageFilter) (UsageSummary, error) {
	where, args := buildUsageWhere(filter)
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
		return UsageSummary{}, fmt.Errorf("store: summarize usage: %w", err)
	}
	return sum, nil
}

func (s *SQLiteStore) SummarizeUsageExtended(ctx context.Context, filter UsageFilter) (UsageExtendedSummary, error) {
	where, args := buildUsageWhere(filter)
	query := `
SELECT COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cache_read_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COALESCE(SUM(reasoning_tokens), 0),
       COALESCE(SUM(total_tokens), 0),
       COALESCE(SUM(cost_usd), 0),
       COALESCE(SUM(CASE WHEN status_code >= 400 OR status_code = 0 OR error_message != '' THEN 1 ELSE 0 END), 0)
FROM usage_logs` + where

	var ext UsageExtendedSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&ext.RequestCount, &ext.InputTokens, &ext.OutputTokens,
		&ext.CacheReadTokens, &ext.CacheWriteTokens, &ext.ReasoningTokens,
		&ext.TotalTokens, &ext.CostUSD, &ext.ErrorCount,
	); err != nil {
		return UsageExtendedSummary{}, fmt.Errorf("store: summarize usage extended: %w", err)
	}

	if ext.RequestCount > 0 {
		offset := int64(math.Ceil(0.95*float64(ext.RequestCount))) - 1
		if offset < 0 {
			offset = 0
		}
		if offset >= ext.RequestCount {
			offset = ext.RequestCount - 1
		}
		p95Args := make([]any, 0, len(args)+1)
		p95Args = append(p95Args, args...)
		p95Args = append(p95Args, offset)
		p95Query := `SELECT latency_ms FROM usage_logs` + where + ` ORDER BY latency_ms ASC LIMIT 1 OFFSET ?`
		if err := s.db.QueryRowContext(ctx, p95Query, p95Args...).Scan(&ext.P95LatencyMS); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return UsageExtendedSummary{}, fmt.Errorf("store: compute p95 latency: %w", err)
		}
	}

	return ext, nil
}

func (s *SQLiteStore) QueryUsageSeries(ctx context.Context, filter UsageFilter, bucket string) ([]UsageTimeBucket, error) {
	var bucketExpr string
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "hour":
		bucketExpr = "substr(created_at, 1, 13) || ':00:00Z'"
	case "", "day":
		bucketExpr = "substr(created_at, 1, 10)"
	default:
		return nil, fmt.Errorf("store: invalid usage series bucket %q (must be hour or day)", bucket)
	}

	where, args := buildUsageWhere(filter)
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
		return nil, fmt.Errorf("store: query usage series: %w", err)
	}
	defer rows.Close()

	var out []UsageTimeBucket
	for rows.Next() {
		var b UsageTimeBucket
		if err := rows.Scan(&b.Bucket, &b.Requests, &b.Tokens, &b.CostUSD, &b.Errors); err != nil {
			return nil, fmt.Errorf("store: scan usage series bucket: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) QueryTopSubjects(ctx context.Context, filter UsageFilter, limit int) ([]SubjectUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildUsageWhere(filter)
	args = append(args, limit)
	query := `
SELECT subject,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs` + where + `
GROUP BY subject
ORDER BY total_cost DESC, req_count DESC, subject ASC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query top subjects: %w", err)
	}
	defer rows.Close()

	var out []SubjectUsageStat
	for rows.Next() {
		var st SubjectUsageStat
		if err := rows.Scan(&st.Subject, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan top subject: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) QueryTopModels(ctx context.Context, filter UsageFilter, limit int) ([]ModelUsageStat, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := buildUsageWhere(filter)
	args = append(args, limit)
	query := `
SELECT requested_model,
       provider_name,
       COUNT(*) AS req_count,
       COALESCE(SUM(total_tokens), 0) AS total_tokens,
       COALESCE(SUM(cost_usd), 0) AS total_cost
FROM usage_logs` + where + `
GROUP BY requested_model, provider_name
ORDER BY total_cost DESC, req_count DESC, requested_model ASC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query top models: %w", err)
	}
	defer rows.Close()

	var out []ModelUsageStat
	for rows.Next() {
		var st ModelUsageStat
		if err := rows.Scan(&st.Model, &st.Provider, &st.Requests, &st.Tokens, &st.CostUSD); err != nil {
			return nil, fmt.Errorf("store: scan top model: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func buildUsageWhere(filter UsageFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	if filter.Tag != "" {
		clauses = append(clauses, "(subject = ? OR EXISTS (SELECT 1 FROM json_each(usage_logs.tags_json) WHERE value = ?))")
		args = append(args, filter.Tag, filter.Tag)
	}
	if filter.ProviderName != "" {
		clauses = append(clauses, "provider_name = ?")
		args = append(args, filter.ProviderName)
	}
	if filter.Model != "" {
		clauses = append(clauses, "(requested_model = ? OR upstream_model = ?)")
		args = append(args, filter.Model, filter.Model)
	}
	if filter.StatusCode > 0 {
		clauses = append(clauses, "status_code = ?")
		args = append(args, filter.StatusCode)
	}
	if filter.GuardrailOnly {
		clauses = append(clauses, "guardrail_action != ''")
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, formatTime(filter.Since.UTC()))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "created_at <= ?")
		args = append(args, formatTime(filter.Until.UTC()))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func scanUsageLog(sc scanner) (UsageLog, error) {
	var (
		log          UsageLog
		createdAtStr string
		tagsJSON     string
		hitsJSON     string
		stream       int
		translated   int
	)
	if err := sc.Scan(
		&log.ID, &createdAtStr, &log.RequestID, &log.Subject, &log.DisplayName,
		&log.NodeName, &log.NodeIP, &tagsJSON, &log.AuthSource, &log.ProviderName,
		&log.ProviderType, &log.RequestedModel, &log.UpstreamModel, &log.Protocol,
		&log.Endpoint, &stream, &translated,
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
	log.CreatedAt = parseTime(createdAtStr)
	log.Stream = stream != 0
	log.Translated = translated != 0
	return log, nil
}

// --- Audit Payloads & Retention ---

func (s *SQLiteStore) InsertAuditPayload(ctx context.Context, payload AuditPayload) error {
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
	respHeaders, err := marshalStringMap(payload.ResponseHeaders)
	if err != nil {
		return fmt.Errorf("store: encode response headers: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_payloads (
	id, usage_log_id, created_at, request_headers_json, request_body,
	response_headers_json, response_body, redacted
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		payload.ID, payload.UsageLogID, formatTime(createdAt), reqHeaders,
		payload.RequestBody, respHeaders, payload.ResponseBody, boolToInt(payload.Redacted),
	)
	if err != nil {
		return fmt.Errorf("store: insert audit payload: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetAuditPayloadByUsageLogID(ctx context.Context, usageLogID string) (*AuditPayload, error) {
	var (
		p            AuditPayload
		createdAtStr string
		reqHeaders   string
		respHeaders  string
		redacted     int
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, usage_log_id, created_at, request_headers_json, request_body,
       response_headers_json, response_body, redacted
FROM audit_payloads WHERE usage_log_id = ?`, usageLogID).
		Scan(&p.ID, &p.UsageLogID, &createdAtStr, &reqHeaders, &p.RequestBody,
			&respHeaders, &p.ResponseBody, &redacted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get audit payload for %q: %w", usageLogID, err)
	}
	if p.RequestHeaders, err = unmarshalStringMap(reqHeaders); err != nil {
		return nil, err
	}
	if p.ResponseHeaders, err = unmarshalStringMap(respHeaders); err != nil {
		return nil, err
	}
	p.CreatedAt = parseTime(createdAtStr)
	p.Redacted = redacted != 0
	return &p, nil
}

func (s *SQLiteStore) PurgeAuditPayloads(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_payloads WHERE created_at < ?`, formatTime(olderThan.UTC()))
	if err != nil {
		return 0, fmt.Errorf("store: purge audit payloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge audit payloads rows affected: %w", err)
	}
	return n, nil
}

// --- Helpers ---

type scanner interface {
	Scan(dest ...any) error
}

func prepareSQLiteDSN(raw string) (dsn, filePath string, isMemory bool, err error) {
	trimmed := strings.TrimSpace(raw)
	isMemory = trimmed == ":memory:" || strings.Contains(trimmed, "mode=memory")

	if !isMemory {
		if strings.HasPrefix(trimmed, "file:") {
			pathPart := strings.TrimPrefix(trimmed, "file:")
			if idx := strings.IndexByte(pathPart, '?'); idx >= 0 {
				pathPart = pathPart[:idx]
			}
			filePath = pathPart
		} else {
			filePath = trimmed
			trimmed = "file:" + trimmed
		}
		if filePath != "" {
			dir := filepath.Dir(filePath)
			if dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return "", "", false, fmt.Errorf("store: create db directory %q: %w", dir, err)
				}
			}
		}
	}

	params := []string{"_pragma=busy_timeout(5000)", "_pragma=foreign_keys(ON)"}
	if !isMemory {
		params = append(params, "_pragma=journal_mode(WAL)", "_pragma=synchronous(NORMAL)")
	}

	sep := "?"
	if strings.Contains(trimmed, "?") {
		sep = "&"
	}
	return trimmed + sep + strings.Join(params, "&"), filePath, isMemory, nil
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

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
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
