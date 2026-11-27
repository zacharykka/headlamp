package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	if len(migs) != 4 {
		t.Fatalf("expected 4 embedded postgres migrations, got %d: %+v", len(migs), migs)
	}
	wantNames := []string{
		"0001_initial.sql",
		"0002_m2_governance.sql",
		"0003_m3_mcp_and_chat.sql",
		"0004_m3_upgrade_compat.sql",
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
		"seq BIGSERIAL NOT NULL",
		"ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS seq BIGSERIAL NOT NULL",
		"idx_chat_messages_session_seq",
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

func TestStripPostgresNULAndJSONNUL(t *testing.T) {
	if got := stripPostgresNUL("clean text"); got != "clean text" {
		t.Fatalf("stripPostgresNUL(clean) = %q", got)
	}
	if got := stripPostgresNUL("hello\x00world\x00!"); got != "helloworld!" {
		t.Fatalf("stripPostgresNUL(nul) = %q, want helloworld!", got)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain_json",
			in:   `{"ok":true,"text":"hello"}`,
			want: `{"ok":true,"text":"hello"}`,
		},
		{
			name: "raw_nul_and_lower_escape",
			in:   "{\"a\":\"hi\x00\\u0000there\"}",
			want: `{"a":"hithere"}`,
		},
		{
			name: "upper_escape",
			in:   `{"a":"foo\U0000bar"}`,
			want: `{"a":"foobar"}`,
		},
		{
			name: "escaped_backslash_before_u0000_preserved",
			in:   `{"a":"literal \\u0000 text"}`,
			want: `{"a":"literal \\u0000 text"}`,
		},
		{
			name: "escaped_backslash_plus_real_u0000",
			in:   `{"a":"\\\u0000"}`,
			want: `{"a":"\\"}`,
		},
		{
			name: "consecutive_real_u0000_after_escaped_backslash",
			in:   `{"a":"\\\u0000\u0000x"}`,
			want: `{"a":"\\x"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(stripPostgresJSONNUL([]byte(tc.in)))
			if got != tc.want {
				t.Fatalf("stripPostgresJSONNUL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !json.Valid([]byte(got)) {
				t.Fatalf("stripPostgresJSONNUL(%q) produced invalid JSON: %q", tc.in, got)
			}
		})
	}
}

func TestPostgresSnapshotCacheTTLOption(t *testing.T) {
	base := time.Date(2026, 11, 27, 16, 0, 0, 0, time.UTC)
	s := &PostgresStore{
		cacheTTL: defaultPostgresCacheTTL,
		cache:    &configSnapshot{},
	}
	if s.cacheTTL != 5*time.Second {
		t.Fatalf("default cacheTTL = %v, want 5s", s.cacheTTL)
	}

	WithPostgresCacheTTL(2 * time.Second)(s)
	if s.cacheTTL != 2*time.Second {
		t.Fatalf("WithPostgresCacheTTL(2s) = %v", s.cacheTTL)
	}
	s.cacheLoadedAt = base

	if !s.isCacheFreshLocked(base.Add(1999 * time.Millisecond)) {
		t.Fatal("expected cache to be fresh before TTL elapses")
	}
	if s.isCacheFreshLocked(base.Add(2 * time.Second)) {
		t.Fatal("expected cache to expire at TTL boundary")
	}

	WithPostgresCacheTTL(0)(s)
	if s.isCacheFreshLocked(base) {
		t.Fatal("expected TTL <= 0 to disable snapshot cache reuse")
	}

	WithPostgresCacheTTL(2 * time.Second)(s)
	s.cache = nil
	if s.isCacheFreshLocked(base) {
		t.Fatal("expected nil cache to report not fresh")
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

	prefix := "pgtest-" + uuid.NewString()[:8] + "-"
	providerName := prefix + "openai"
	mcpName := prefix + "docs"
	localMCPName := prefix + "local-mcp"
	ruleID := prefix + "rule"
	usageID := prefix + "u1"
	usageNULID := prefix + "u-nul"
	mcpAuditID := prefix + "m-nul"
	alice := prefix + "alice"
	bob := prefix + "bob"
	tag := "tag:" + prefix + "pg"

	st, err := NewPostgresStore(ctx, dsn, cipher, WithPostgresCacheTTL(40*time.Millisecond))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	stReplica, err := NewPostgresStore(ctx, dsn, cipher, WithPostgresCacheTTL(40*time.Millisecond))
	if err != nil {
		t.Fatalf("NewPostgresStore(replica): %v", err)
	}
	defer func() { _ = stReplica.Close() }()

	defer func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = st.DB().ExecContext(cleanCtx, `DELETE FROM usage_logs WHERE id IN ($1, $2)`, usageID, usageNULID)
		_, _ = st.DB().ExecContext(cleanCtx, `DELETE FROM mcp_audit_logs WHERE id = $1`, mcpAuditID)
		_, _ = st.DB().ExecContext(cleanCtx, `DELETE FROM guardrail_rules WHERE id = $1`, ruleID)
		_, _ = st.DB().ExecContext(cleanCtx, `DELETE FROM mcp_servers WHERE name IN ($1, $2)`, mcpName, localMCPName)
		_, _ = st.DB().ExecContext(cleanCtx, `DELETE FROM providers WHERE name = $1`, providerName)
	}()

	// Idempotent re-migrate (exercises pg_advisory_xact_lock transaction pooling path).
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	// SyncConfig + encrypted provider/MCP server round-trip + multi-replica TTL refresh.
	cfg, err := config.LoadFromBytes([]byte(fmt.Sprintf(`
providers:
  - name: %s
    type: openai
    api_key: "sk-pg-secret"
    models: ["gpt-5"]
mcp_servers:
  - name: %s
    url: "https://pg-docs.internal/mcp"
    auth_type: bearer
    auth_token: "mcp-pg-token"
`, providerName, mcpName)))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if err := st.SyncConfig(ctx, cfg); err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	p, err := st.GetProvider(ctx, providerName)
	if err != nil || p.APIKey != "sk-pg-secret" {
		t.Fatalf("GetProvider(%s) = (%+v, %v)", providerName, p, err)
	}
	m, err := st.GetMCPServer(ctx, mcpName)
	if err != nil || m.AuthToken != "mcp-pg-token" {
		t.Fatalf("GetMCPServer(%s) = (%+v, %v)", mcpName, m, err)
	}

	// Prime replica cache, mutate on primary, verify replica sees update after TTL.
	if mRep, err := stReplica.GetMCPServer(ctx, mcpName); err != nil || mRep.AuthToken != "mcp-pg-token" {
		t.Fatalf("replica initial GetMCPServer = (%+v, %v)", mRep, err)
	}
	// Seed a source='local' server, then sync YAML switching mcpName to auth_type=none
	// and taking over localMCPName without auth_token (must not inherit local secret).
	if err := st.UpsertMCPServer(ctx, MCPServer{
		Name: localMCPName, URL: "https://local.internal/mcp",
		Transport: config.MCPTransportStreamableHTTP, AuthType: config.MCPAuthBearer,
		AuthToken: "local-secret-must-not-leak", Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("UpsertMCPServer(local): %v", err)
	}
	cfgUpdated, err := config.LoadFromBytes([]byte(fmt.Sprintf(`
providers:
  - name: %s
    type: openai
    api_key: "sk-pg-secret"
    models: ["gpt-5"]
mcp_servers:
  - name: %s
    url: "https://pg-docs.internal/mcp"
    auth_type: none
  - name: %s
    url: "https://config.internal/mcp"
    auth_type: bearer
`, providerName, mcpName, localMCPName)))
	if err != nil {
		t.Fatalf("LoadFromBytes(updated): %v", err)
	}
	if err := st.SyncConfig(ctx, cfgUpdated); err != nil {
		t.Fatalf("SyncConfig(updated): %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	mRepUpdated, err := stReplica.GetMCPServer(ctx, mcpName)
	if err != nil || mRepUpdated.AuthType != config.MCPAuthNone || mRepUpdated.AuthToken != "" {
		t.Fatalf("replica TTL refresh failed or auth_type=none leaked secret: (%+v, %v)", mRepUpdated, err)
	}
	mTaken, err := stReplica.GetMCPServer(ctx, localMCPName)
	if err != nil || mTaken.Source != SourceConfig || mTaken.AuthToken != "" {
		t.Fatalf("expected source=config takeover not to inherit source=local token: (%+v, %v)", mTaken, err)
	}

	// Guardrail rule lowercase normalization.
	if err := st.UpsertGuardrailRule(ctx, GuardrailRule{
		ID: ruleID, Name: "Upper Case Rule", Category: " SECRET ", Pattern: "tok_[0-9]+",
		Action: " BLOCK ", Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("UpsertGuardrailRule: %v", err)
	}
	gotRule, err := st.GetGuardrailRule(ctx, ruleID)
	if err != nil || gotRule.Category != "secret" || gotRule.Action != "block" {
		t.Fatalf("expected lowercased category/action, got (%+v, %v)", gotRule, err)
	}

	// Usage analytics (P95, hour/day series, tag filter) + NUL byte sanitization.
	base := time.Now().UTC().Truncate(time.Hour)
	if err := st.InsertUsageLog(ctx, UsageLog{
		ID: usageID, CreatedAt: base, Subject: alice, Tags: []string{tag},
		ProviderName: providerName, RequestedModel: "gpt-5", TotalTokens: 1000, CostUSD: 0.05,
		LatencyMS: 250, StatusCode: 200,
	}); err != nil {
		t.Fatalf("InsertUsageLog(%s): %v", usageID, err)
	}
	if err := st.InsertUsageLog(ctx, UsageLog{
		ID: usageNULID, CreatedAt: base, Subject: alice, Tags: []string{tag, "bad\x00tag"},
		ProviderName: providerName, RequestedModel: "gpt-5", TotalTokens: 10, CostUSD: 0.01,
		LatencyMS: 100, StatusCode: 500, ErrorMessage: "upstream\x00err",
	}); err != nil {
		t.Fatalf("InsertUsageLog(nul): %v", err)
	}
	if err := st.InsertAuditPayload(ctx, AuditPayload{
		UsageLogID:      usageNULID,
		RequestHeaders:  map[string]string{"X-Test": "val\x00ue"},
		RequestBody:     "req\x00body",
		ResponseHeaders: map[string]string{"X-Resp": "ok\x00"},
		ResponseBody:    "resp\x00body",
	}); err != nil {
		t.Fatalf("InsertAuditPayload(nul): %v", err)
	}
	if err := st.InsertMCPAuditLog(ctx, MCPAuditLog{
		ID: mcpAuditID, CreatedAt: base, Subject: alice, Tags: []string{"t\x001"},
		ServerName: mcpName, Method: "tools/call", ToolName: "search", Status: "ok",
		ArgumentsPreview: "{\"q\":\"hi\x00there\"}", ErrorMessage: "warn\x00",
	}); err != nil {
		t.Fatalf("InsertMCPAuditLog(nul): %v", err)
	}

	ext, err := st.SummarizeUsageExtended(ctx, UsageFilter{Tag: tag})
	if err != nil || ext.RequestCount != 2 || ext.P95LatencyMS <= 0 || math.Abs(ext.CostUSD-0.06) > 1e-9 {
		t.Fatalf("SummarizeUsageExtended(%s) = (%+v, %v)", tag, ext, err)
	}
	series, err := st.QueryUsageSeries(ctx, UsageFilter{Tag: tag}, "hour")
	if err != nil || len(series) == 0 || !strings.HasSuffix(series[0].Bucket, ":00:00Z") {
		t.Fatalf("QueryUsageSeries(hour) = (%+v, %v)", series, err)
	}

	// Chat session isolation, same-microsecond seq ordering, NUL sanitization, and DeleteChatMessage rollback.
	sess, err := st.CreateChatSession(ctx, ChatSession{
		Subject:    alice,
		Title:      "PG Chat",
		Model:      "gpt-5",
		MCPServers: []string{mcpName},
	})
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}
	defer func() { _ = st.DeleteChatSession(ctx, alice, sess.ID) }()

	if _, err := st.GetChatSession(ctx, bob, sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-subject session read, got %v", err)
	}

	sameTS := time.Now().UTC().Truncate(time.Microsecond)
	userMsg, err := st.InsertChatMessage(ctx, alice, ChatMessage{
		ID:        prefix + "z-user",
		SessionID: sess.ID,
		Role:      "user",
		Content:   "hello\x00world",
		CreatedAt: sameTS,
	})
	if err != nil {
		t.Fatalf("InsertChatMessage(user): %v", err)
	}
	if _, err := st.InsertChatMessage(ctx, alice, ChatMessage{
		ID:         prefix + "a-assistant",
		SessionID:  sess.ID,
		Role:       "assistant",
		Content:    "Done\x00ok",
		ToolEvents: []ChatToolEvent{{ID: "t1", Server: mcpName, Tool: "search", Arguments: json.RawMessage(`{"q":"pg\u0000test"}`), Result: "ok\x00res", DurationMS: 12}},
		CreatedAt:  sameTS,
	}); err != nil {
		t.Fatalf("InsertChatMessage(assistant): %v", err)
	}

	msgs, err := st.ListChatMessages(ctx, alice, sess.ID)
	if err != nil || len(msgs) != 2 || msgs[0].ID != prefix+"z-user" || msgs[1].ID != prefix+"a-assistant" ||
		msgs[0].Content != "helloworld" || msgs[1].Content != "Doneok" ||
		len(msgs[1].ToolEvents) != 1 || msgs[1].ToolEvents[0].Result != "okres" {
		t.Fatalf("ListChatMessages same-microsecond seq order / NUL strip failed: (%+v, %v)", msgs, err)
	}

	// Cross-subject DeleteChatMessage denied; owner rollback succeeds.
	if err := st.DeleteChatMessage(ctx, bob, sess.ID, userMsg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-subject DeleteChatMessage, got %v", err)
	}
	if err := st.DeleteChatMessage(ctx, alice, sess.ID, userMsg.ID); err != nil {
		t.Fatalf("owner DeleteChatMessage: %v", err)
	}
	msgsAfter, err := st.ListChatMessages(ctx, alice, sess.ID)
	if err != nil || len(msgsAfter) != 1 || msgsAfter[0].ID != prefix+"a-assistant" {
		t.Fatalf("ListChatMessages after DeleteChatMessage = (%+v, %v)", msgsAfter, err)
	}
}
