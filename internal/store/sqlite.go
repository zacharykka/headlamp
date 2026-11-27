package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zacharykka/headlamp/internal/crypto"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var _ Store = (*SQLiteStore)(nil)

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
