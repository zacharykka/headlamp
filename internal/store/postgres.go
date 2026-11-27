package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
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
