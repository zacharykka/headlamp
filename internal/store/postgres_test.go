package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
)

func TestNewStoreFactoryAndPostgresValidation(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	ctx := context.Background()

	// SQLite factory path works cleanly.
	st, err := NewStore(ctx, config.StorageConfig{Driver: config.StorageDriverSQLite, DSN: ":memory:"}, cipher)
	if err != nil {
		t.Fatalf("NewStore(sqlite): %v", err)
	}
	_ = st.Close()

	// Unsupported driver fails cleanly.
	if _, err := NewStore(ctx, config.StorageConfig{Driver: "mysql", DSN: "dsn"}, cipher); err == nil || !strings.Contains(err.Error(), "unsupported storage driver") {
		t.Fatalf("expected unsupported driver error, got %v", err)
	}

	// Postgres validation checks.
	if _, err := NewPostgresStore(ctx, "postgres://user:pass@localhost/db", nil); err == nil {
		t.Fatal("expected error for nil cipher")
	}
	if _, err := NewPostgresStore(ctx, "   ", cipher); err == nil {
		t.Fatal("expected error for empty postgres dsn")
	}
	if _, err := NewStore(ctx, config.StorageConfig{Driver: config.StorageDriverPostgres, DSN: "://not-a-valid-dsn"}, cipher); err == nil || !strings.Contains(err.Error(), "invalid postgres dsn") {
		t.Fatalf("expected invalid postgres dsn error, got %v", err)
	}
}

func TestPostgresEmbeddedMigrationsAndQueryBuilders(t *testing.T) {
	migs, err := readPGMigrations()
	if err != nil {
		t.Fatalf("readPGMigrations: %v", err)
	}
	if len(migs) != 3 {
		t.Fatalf("expected 3 embedded postgres migrations, got %d: %+v", len(migs), migs)
	}
	wantNames := []string{
		"0001_initial.sql",
		"0002_m2_governance.sql",
		"0003_m3_mcp_and_chat.sql",
	}
	allSQL := strings.Builder{}
	for i, m := range migs {
		if m.version != i+1 || m.name != wantNames[i] {
			t.Fatalf("migration[%d] = (%d, %q), want (%d, %q)", i, m.version, m.name, i+1, wantNames[i])
		}
		raw, err := pgMigrationsFS.ReadFile(m.path)
		if err != nil || len(raw) == 0 {
			t.Fatalf("read %s: err=%v len=%d", m.path, err, len(raw))
		}
		allSQL.Write(raw)
		allSQL.WriteByte('\n')
	}

	combined := allSQL.String()
	for _, token := range []string{
		"CREATE TABLE IF NOT EXISTS providers",
		"CREATE TABLE IF NOT EXISTS model_routes",
		"CREATE TABLE IF NOT EXISTS usage_logs",
		"CREATE TABLE IF NOT EXISTS audit_payloads",
		"CREATE TABLE IF NOT EXISTS budgets",
		"CREATE TABLE IF NOT EXISTS guardrail_rules",
		"CREATE TABLE IF NOT EXISTS webhooks",
		"CREATE TABLE IF NOT EXISTS runtime_settings",
		"CREATE TABLE IF NOT EXISTS mcp_servers",
		"CREATE TABLE IF NOT EXISTS mcp_audit_logs",
		"CREATE TABLE IF NOT EXISTS chat_sessions",
		"CREATE TABLE IF NOT EXISTS chat_messages",
		"TIMESTAMPTZ",
		"JSONB",
		"DOUBLE PRECISION",
		"BOOLEAN",
	} {
		if !strings.Contains(combined, token) {
			t.Fatalf("postgres migrations missing expected DDL token %q", token)
		}
	}

	// Verify $1..$N parameter numbering in pgBuildUsageWhere.
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	where, args := pgBuildUsageWhere(UsageFilter{
		Subject:       "alice",
		Tag:           "tag:eng",
		ProviderName:  "anthropic",
		Model:         "claude-sonnet-4-6",
		StatusCode:    429,
		ErrorsOnly:    true,
		GuardrailOnly: true,
		Since:         now.Add(-time.Hour),
		Until:         now,
	})
	if len(args) != 9 {
		t.Fatalf("expected 9 args in pgBuildUsageWhere, got %d (%v)", len(args), args)
	}
	for _, snippet := range []string{
		"subject = $1",
		"subject = $2 OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(usage_logs.tags_json) AS elem WHERE elem = $3)",
		"provider_name = $4",
		"(requested_model = $5 OR upstream_model = $6)",
		"status_code = $7",
		"(status_code >= 400 OR status_code = 0 OR error_message != '')",
		"guardrail_action != ''",
		"created_at >= $8",
		"created_at <= $9",
	} {
		if !strings.Contains(where, snippet) {
			t.Fatalf("pgBuildUsageWhere missing %q in %q", snippet, where)
		}
	}

	mcpWhere, mcpArgs := pgBuildMCPAuditWhere(MCPAuditFilter{
		ServerName: "docs",
		Subject:    "alice",
		ToolName:   "search",
		Status:     "ok",
		Since:      now.Add(-time.Hour),
		Until:      now,
	})
	if len(mcpArgs) != 6 || !strings.Contains(mcpWhere, "server_name = $1") || !strings.Contains(mcpWhere, "created_at <= $6") {
		t.Fatalf("unexpected pgBuildMCPAuditWhere: %q (%v)", mcpWhere, mcpArgs)
	}
}

func TestPostgresStoreLiveIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HEADLAMP_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set HEADLAMP_TEST_POSTGRES_DSN to run live PostgreSQL integration tests")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := NewPostgresStore(ctx, dsn, cipher)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Idempotent re-migrate
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	// SyncConfig + encrypted provider/webhook/MCP server round-trip
	cfg, err := config.LoadFromBytes([]byte(`
providers:
  - name: pg-openai
    type: openai
    api_key: "sk-pg-secret"
    models: ["gpt-5"]
mcp_servers:
  - name: pg-docs
    url: "https://pg-docs.internal/mcp"
    auth_type: bearer
    auth_token: "mcp-pg-token"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if err := st.SyncConfig(ctx, cfg); err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	p, err := st.GetProvider(ctx, "pg-openai")
	if err != nil || p.APIKey != "sk-pg-secret" {
		t.Fatalf("GetProvider(pg-openai) = (%+v, %v)", p, err)
	}
	m, err := st.GetMCPServer(ctx, "pg-docs")
	if err != nil || m.AuthToken != "mcp-pg-token" {
		t.Fatalf("GetMCPServer(pg-docs) = (%+v, %v)", m, err)
	}

	// Usage analytics (P95, hour/day series, tag filter)
	base := time.Now().UTC().Truncate(time.Hour)
	_ = st.InsertUsageLog(ctx, UsageLog{
		ID: "pg-u1", CreatedAt: base, Subject: "pg-alice", Tags: []string{"tag:pg"},
		ProviderName: "pg-openai", RequestedModel: "gpt-5", TotalTokens: 1000, CostUSD: 0.05,
		LatencyMS: 250, StatusCode: 200,
	})
	ext, err := st.SummarizeUsageExtended(ctx, UsageFilter{Tag: "tag:pg"})
	if err != nil || ext.RequestCount < 1 || ext.P95LatencyMS <= 0 || math.Abs(ext.CostUSD) < 1e-9 {
		t.Fatalf("SummarizeUsageExtended(tag:pg) = (%+v, %v)", ext, err)
	}
	series, err := st.QueryUsageSeries(ctx, UsageFilter{Tag: "tag:pg"}, "hour")
	if err != nil || len(series) == 0 || !strings.HasSuffix(series[0].Bucket, ":00:00Z") {
		t.Fatalf("QueryUsageSeries(hour) = (%+v, %v)", series, err)
	}

	// Chat session isolation & tool event JSONB round-trip
	sess, err := st.CreateChatSession(ctx, ChatSession{
		Subject:    "pg-alice",
		Title:      "PG Chat",
		Model:      "gpt-5",
		MCPServers: []string{"pg-docs"},
	})
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}
	defer func() { _ = st.DeleteChatSession(ctx, "pg-alice", sess.ID) }()

	if _, err := st.GetChatSession(ctx, "pg-bob", sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-subject session read, got %v", err)
	}
	if _, err := st.InsertChatMessage(ctx, "pg-alice", ChatMessage{
		SessionID:  sess.ID,
		Role:       "assistant",
		Content:    "Done",
		ToolEvents: []ChatToolEvent{{ID: "t1", Server: "pg-docs", Tool: "search", Arguments: json.RawMessage(`{"q":"pg"}`), Result: "ok", DurationMS: 12}},
	}); err != nil {
		t.Fatalf("InsertChatMessage: %v", err)
	}
	msgs, err := st.ListChatMessages(ctx, "pg-alice", sess.ID)
	if err != nil || len(msgs) != 1 || len(msgs[0].ToolEvents) != 1 {
		t.Fatalf("ListChatMessages = (%+v, %v)", msgs, err)
	}
}
