package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteStore implements Store backed by pure-Go modernc.org/sqlite.
type SQLiteStore struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

// NewSQLiteStore opens a SQLite database with WAL mode, busy_timeout, and foreign_keys ON,
// then runs all embedded SQL migrations.
func NewSQLiteStore(ctx context.Context, dsn string, cipher *crypto.Cipher) (*SQLiteStore, error) {
	if cipher == nil {
		return nil, errors.New("store: cipher is required")
	}
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("store: sqlite dsn is required")
	}

	connDSN, isMemory, err := prepareSQLiteDSN(dsn)
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

// SyncConfig idempotently seeds/syncs YAML providers, routes, groups, bootstrap admins,
// and static policy rules into SQLite without disturbing local UI-created records.
// If a YAML provider omits api_key while a stored provider already exists, the existing encrypted key is preserved.
func (s *SQLiteStore) SyncConfig(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: sync config begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()

	for _, p := range cfg.Providers {
		apiKeyEnc := ""
		if p.APIKey != "" {
			apiKeyEnc, err = s.cipher.EncryptString(p.APIKey)
			if err != nil {
				return fmt.Errorf("store: encrypt api_key for provider %q: %w", p.Name, err)
			}
		} else {
			// Preserve an existing stored key when YAML omits api_key.
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
			boolToInt(p.IsEnabled()), SourceConfig, formatTime(now), formatTime(now),
		)
		if err != nil {
			return fmt.Errorf("store: sync provider %q: %w", p.Name, err)
		}
	}

	for _, r := range cfg.Routes {
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
			boolToInt(r.IsEnabled()), SourceConfig, formatTime(now), formatTime(now),
		)
		if err != nil {
			return fmt.Errorf("store: sync route %q: %w", r.Alias, err)
		}
	}

	for _, g := range cfg.Policy.Groups {
		_, err = tx.ExecContext(ctx, `
INSERT INTO groups (name, description, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	description = excluded.description,
	source = excluded.source,
	updated_at = excluded.updated_at`,
			g.Name, g.Description, SourceConfig, formatTime(now), formatTime(now),
		)
		if err != nil {
			return fmt.Errorf("store: sync group %q: %w", g.Name, err)
		}
		if err := replaceGroupMembersTx(ctx, tx, g.Name, g.Members, now); err != nil {
			return err
		}
	}

	for _, admin := range cfg.Policy.BootstrapAdmins {
		subject := strings.TrimSpace(admin)
		if subject == "" {
			continue
		}
		pol := Policy{
			ID:            "bootstrap-admin:" + subject,
			Name:          "bootstrap-admin:" + subject,
			Subject:       subject,
			Role:          "admin",
			AllowModels:   []string{"*"},
			AllowMCPTools: []string{"*"},
			Priority:      1000,
			Enabled:       true,
			Source:        SourceConfig,
		}
		if err := upsertPolicyTx(ctx, tx, pol, now); err != nil {
			return fmt.Errorf("store: sync bootstrap admin %q: %w", subject, err)
		}
	}

	for i, rule := range cfg.Policy.Rules {
		name := strings.TrimSpace(rule.Name)
		idSuffix := name
		if idSuffix == "" {
			idSuffix = fmt.Sprintf("rule-%d", i)
			name = idSuffix
		}
		pol := Policy{
			ID:            "cfg-rule:" + idSuffix,
			Name:          name,
			Subject:       rule.Subject,
			Role:          rule.Role,
			AllowModels:   rule.AllowModels,
			DenyModels:    rule.DenyModels,
			AllowMCPTools: rule.AllowMCPTools,
			DenyMCPTools:  rule.DenyMCPTools,
			Priority:      rule.Priority,
			Enabled:       true,
			Source:        SourceConfig,
		}
		if err := upsertPolicyTx(ctx, tx, pol, now); err != nil {
			return fmt.Errorf("store: sync policy rule %q: %w", name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: sync config commit: %w", err)
	}
	return nil
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
	return nil
}

func (s *SQLiteStore) GetProvider(ctx context.Context, name string) (*Provider, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT name, type, base_url, api_key_enc, passthrough, models_json, enabled, source, created_at, updated_at
FROM providers WHERE name = ?`, name)

	p, err := s.scanProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (s *SQLiteStore) ListProviders(ctx context.Context) ([]Provider, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name, type, base_url, api_key_enc, passthrough, models_json, enabled, source, created_at, updated_at
FROM providers ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list providers: %w", err)
	}
	defer rows.Close()

	var out []Provider
	for rows.Next() {
		p, err := s.scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate providers: %w", err)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteProvider(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete provider %q: %w", name, err)
	}
	return checkAffected(res)
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
	return nil
}

func (s *SQLiteStore) GetModelRoute(ctx context.Context, alias string) (*ModelRoute, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT alias, provider_name, upstream_model, fallbacks_json,
       input_cost_per_million, output_cost_per_million,
       cache_read_cost_per_million, cache_write_cost_per_million,
       enabled, source, created_at, updated_at
FROM model_routes WHERE alias = ?`, alias)

	r, err := scanModelRoute(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

func (s *SQLiteStore) ListModelRoutes(ctx context.Context) ([]ModelRoute, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT alias, provider_name, upstream_model, fallbacks_json,
       input_cost_per_million, output_cost_per_million,
       cache_read_cost_per_million, cache_write_cost_per_million,
       enabled, source, created_at, updated_at
FROM model_routes ORDER BY alias ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list model routes: %w", err)
	}
	defer rows.Close()

	var out []ModelRoute
	for rows.Next() {
		r, err := scanModelRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate model routes: %w", err)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteModelRoute(ctx context.Context, alias string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM model_routes WHERE alias = ?`, alias)
	if err != nil {
		return fmt.Errorf("store: delete model route %q: %w", alias, err)
	}
	return checkAffected(res)
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

// --- Groups & Members ---

func (s *SQLiteStore) UpsertGroup(ctx context.Context, g Group) error {
	if strings.TrimSpace(g.Name) == "" {
		return errors.New("store: group name is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert group begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	source := defaultSource(g.Source)

	_, err = tx.ExecContext(ctx, `
INSERT INTO groups (name, description, source, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	description = excluded.description,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		g.Name, g.Description, source, formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert group %q: %w", g.Name, err)
	}

	if g.Members != nil {
		if err := replaceGroupMembersTx(ctx, tx, g.Name, g.Members, now); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: upsert group commit: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetGroup(ctx context.Context, name string) (*Group, error) {
	var (
		g            Group
		createdAtStr string
		updatedAtStr string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT name, description, source, created_at, updated_at FROM groups WHERE name = ?`, name).
		Scan(&g.Name, &g.Description, &g.Source, &createdAtStr, &updatedAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get group %q: %w", name, err)
	}
	g.CreatedAt = parseTime(createdAtStr)
	g.UpdatedAt = parseTime(updatedAtStr)

	members, err := s.listMembersOfGroup(ctx, name)
	if err != nil {
		return nil, err
	}
	g.Members = members
	return &g, nil
}

func (s *SQLiteStore) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name, description, source, created_at, updated_at FROM groups ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}

	var groups []Group
	for rows.Next() {
		var (
			g            Group
			createdAtStr string
			updatedAtStr string
		)
		if err := rows.Scan(&g.Name, &g.Description, &g.Source, &createdAtStr, &updatedAtStr); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan group: %w", err)
		}
		g.CreatedAt = parseTime(createdAtStr)
		g.UpdatedAt = parseTime(updatedAtStr)
		groups = append(groups, g)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range groups {
		members, err := s.listMembersOfGroup(ctx, groups[i].Name)
		if err != nil {
			return nil, err
		}
		groups[i].Members = members
	}
	return groups, nil
}

func (s *SQLiteStore) DeleteGroup(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete group %q: %w", name, err)
	}
	return checkAffected(res)
}

func (s *SQLiteStore) SetGroupMembers(ctx context.Context, groupName string, members []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set group members begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := replaceGroupMembersTx(ctx, tx, groupName, members, time.Now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: set group members commit: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListGroupsForMember(ctx context.Context, members ...string) ([]string, error) {
	cleaned := make([]any, 0, len(members))
	placeholders := make([]string, 0, len(members))
	for _, m := range members {
		if trimmed := strings.TrimSpace(m); trimmed != "" {
			cleaned = append(cleaned, trimmed)
			placeholders = append(placeholders, "?")
		}
	}
	if len(cleaned) == 0 {
		return nil, nil
	}

	query := fmt.Sprintf(
		`SELECT DISTINCT group_name FROM group_members WHERE member IN (%s) ORDER BY group_name ASC`,
		strings.Join(placeholders, ","),
	)
	rows, err := s.db.QueryContext(ctx, query, cleaned...)
	if err != nil {
		return nil, fmt.Errorf("store: list groups for member: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var groupName string
		if err := rows.Scan(&groupName); err != nil {
			return nil, fmt.Errorf("store: scan group membership: %w", err)
		}
		out = append(out, groupName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) listMembersOfGroup(ctx context.Context, groupName string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT member FROM group_members WHERE group_name = ? ORDER BY member ASC`, groupName)
	if err != nil {
		return nil, fmt.Errorf("store: list members of group %q: %w", groupName, err)
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("store: scan group member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func replaceGroupMembersTx(ctx context.Context, tx *sql.Tx, groupName string, members []string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_members WHERE group_name = ?`, groupName); err != nil {
		return fmt.Errorf("store: clear members for group %q: %w", groupName, err)
	}
	seen := make(map[string]struct{}, len(members))
	for _, m := range members {
		trimmed := strings.TrimSpace(m)
		if trimmed == "" {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO group_members (group_name, member, created_at) VALUES (?, ?, ?)`,
			groupName, trimmed, formatTime(now),
		); err != nil {
			return fmt.Errorf("store: add member %q to group %q: %w", trimmed, groupName, err)
		}
	}
	return nil
}

// --- Policies ---

func (s *SQLiteStore) UpsertPolicy(ctx context.Context, p Policy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert policy begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertPolicyTx(ctx, tx, p, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertPolicyTx(ctx context.Context, tx *sql.Tx, p Policy, now time.Time) error {
	if strings.TrimSpace(p.Subject) == "" {
		return errors.New("store: policy subject is required")
	}
	if strings.TrimSpace(p.ID) == "" {
		p.ID = uuid.NewString()
	}

	allowModels, err := marshalStringSlice(p.AllowModels)
	if err != nil {
		return err
	}
	denyModels, err := marshalStringSlice(p.DenyModels)
	if err != nil {
		return err
	}
	allowMCP, err := marshalStringSlice(p.AllowMCPTools)
	if err != nil {
		return err
	}
	denyMCP, err := marshalStringSlice(p.DenyMCPTools)
	if err != nil {
		return err
	}

	source := defaultSource(p.Source)

	_, err = tx.ExecContext(ctx, `
INSERT INTO policies (
	id, name, subject, role, allow_models_json, deny_models_json,
	allow_mcp_tools_json, deny_mcp_tools_json, priority, enabled, source, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	subject = excluded.subject,
	role = excluded.role,
	allow_models_json = excluded.allow_models_json,
	deny_models_json = excluded.deny_models_json,
	allow_mcp_tools_json = excluded.allow_mcp_tools_json,
	deny_mcp_tools_json = excluded.deny_mcp_tools_json,
	priority = excluded.priority,
	enabled = excluded.enabled,
	source = excluded.source,
	updated_at = excluded.updated_at`,
		p.ID, p.Name, p.Subject, p.Role, allowModels, denyModels,
		allowMCP, denyMCP, p.Priority, boolToInt(p.Enabled), source,
		formatTime(now), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: upsert policy %q: %w", p.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, subject, role, allow_models_json, deny_models_json,
       allow_mcp_tools_json, deny_mcp_tools_json, priority, enabled, source, created_at, updated_at
FROM policies WHERE id = ?`, id)

	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (s *SQLiteStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, subject, role, allow_models_json, deny_models_json,
       allow_mcp_tools_json, deny_mcp_tools_json, priority, enabled, source, created_at, updated_at
FROM policies ORDER BY priority DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeletePolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete policy %q: %w", id, err)
	}
	return checkAffected(res)
}

func scanPolicy(sc scanner) (Policy, error) {
	var (
		p            Policy
		allowModels  string
		denyModels   string
		allowMCP     string
		denyMCP      string
		enabled      int
		createdAtStr string
		updatedAtStr string
	)
	if err := sc.Scan(
		&p.ID, &p.Name, &p.Subject, &p.Role, &allowModels, &denyModels,
		&allowMCP, &denyMCP, &p.Priority, &enabled, &p.Source, &createdAtStr, &updatedAtStr,
	); err != nil {
		return Policy{}, err
	}
	var err error
	if p.AllowModels, err = unmarshalStringSlice(allowModels); err != nil {
		return Policy{}, err
	}
	if p.DenyModels, err = unmarshalStringSlice(denyModels); err != nil {
		return Policy{}, err
	}
	if p.AllowMCPTools, err = unmarshalStringSlice(allowMCP); err != nil {
		return Policy{}, err
	}
	if p.DenyMCPTools, err = unmarshalStringSlice(denyMCP); err != nil {
		return Policy{}, err
	}
	p.Enabled = enabled != 0
	p.CreatedAt = parseTime(createdAtStr)
	p.UpdatedAt = parseTime(updatedAtStr)
	return p, nil
}

// --- Usage Logs ---

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

	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_logs (
	id, created_at, request_id, subject, display_name, node_name, node_ip,
	tags_json, auth_source, provider_name, provider_type, requested_model,
	upstream_model, protocol, endpoint, stream, translated,
	input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
	reasoning_tokens, total_tokens, cost_usd, latency_ms, ttft_ms,
	status_code, error_message
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, formatTime(createdAt), log.RequestID, log.Subject, log.DisplayName,
		log.NodeName, log.NodeIP, tagsJSON, log.AuthSource, log.ProviderName,
		log.ProviderType, log.RequestedModel, log.UpstreamModel, log.Protocol,
		log.Endpoint, boolToInt(log.Stream), boolToInt(log.Translated),
		log.InputTokens, log.OutputTokens, log.CacheReadTokens, log.CacheWriteTokens,
		log.ReasoningTokens, log.TotalTokens, log.CostUSD, log.LatencyMS, log.TTFTMS,
		log.StatusCode, log.ErrorMessage,
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
       status_code, error_message
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
       status_code, error_message
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

func buildUsageWhere(filter UsageFilter) (string, []any) {
	var clauses []string
	var args []any

	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	if filter.ProviderName != "" {
		clauses = append(clauses, "provider_name = ?")
		args = append(args, filter.ProviderName)
	}
	if filter.Model != "" {
		clauses = append(clauses, "(requested_model = ? OR upstream_model = ?)")
		args = append(args, filter.Model, filter.Model)
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
		&log.StatusCode, &log.ErrorMessage,
	); err != nil {
		return UsageLog{}, err
	}
	tags, err := unmarshalStringSlice(tagsJSON)
	if err != nil {
		return UsageLog{}, err
	}
	log.Tags = tags
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

func prepareSQLiteDSN(raw string) (dsn string, isMemory bool, err error) {
	trimmed := strings.TrimSpace(raw)
	isMemory = trimmed == ":memory:" || strings.Contains(trimmed, "mode=memory")

	if !isMemory && !strings.HasPrefix(trimmed, "file:") {
		dir := filepath.Dir(trimmed)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", false, fmt.Errorf("store: create db directory %q: %w", dir, err)
			}
		}
		trimmed = "file:" + trimmed
	}

	params := []string{"_pragma=busy_timeout(5000)", "_pragma=foreign_keys(ON)"}
	if !isMemory {
		params = append(params, "_pragma=journal_mode(WAL)", "_pragma=synchronous(NORMAL)")
	}

	sep := "?"
	if strings.Contains(trimmed, "?") {
		sep = "&"
	}
	return trimmed + sep + strings.Join(params, "&"), isMemory, nil
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
