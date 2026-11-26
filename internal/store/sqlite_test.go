package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
)

func newTestStore(t *testing.T, dsn string) (*SQLiteStore, *crypto.Cipher) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	st, err := NewSQLiteStore(context.Background(), dsn, cipher)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, cipher
}

func TestSQLitePragmasAndIdempotentMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "headlamp.db")
	st, _ := newTestStore(t, dbPath)
	ctx := context.Background()

	var journalMode string
	if err := st.DB().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if strings.ToLower(journalMode) != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}

	var busyTimeout int
	if err := st.DB().QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", busyTimeout)
	}

	var foreignKeys int
	if err := st.DB().QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}

	// Re-running Migrate must be a clean no-op.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestProvidersEncryptedAtRestAndRoutesCRUD(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	secret := "sk-ant-super-secret-value"
	if err := st.UpsertProvider(ctx, Provider{
		Name:        "anthropic",
		Type:        config.ProviderTypeAnthropic,
		BaseURL:     "https://api.anthropic.com",
		APIKey:      secret,
		Passthrough: false,
		Models:      []string{"claude-sonnet-4-20250514"},
		Enabled:     true,
	}); err != nil {
		t.Fatalf("UpsertProvider: %v", err)
	}

	// Verify raw SQL column is encrypted and never contains plaintext.
	var rawEnc string
	if err := st.DB().QueryRowContext(ctx, `SELECT api_key_enc FROM providers WHERE name = 'anthropic'`).Scan(&rawEnc); err != nil {
		t.Fatalf("select raw api_key_enc: %v", err)
	}
	if !crypto.IsEncrypted(rawEnc) || strings.Contains(rawEnc, secret) {
		t.Fatalf("expected encrypted api_key_enc, got %q", rawEnc)
	}

	got, err := st.GetProvider(ctx, "anthropic")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.APIKey != secret || len(got.Models) != 1 || !got.Enabled {
		t.Fatalf("unexpected provider: %+v", got)
	}

	zeroCost := 0.0
	inputCost := 3.0
	if err := st.UpsertModelRoute(ctx, ModelRoute{
		Alias:                "team/coding",
		ProviderName:         "anthropic",
		UpstreamModel:        "claude-sonnet-4-20250514",
		Fallbacks:            []RouteTarget{{Provider: "anthropic", Model: "claude-3-5-haiku-20241022"}},
		InputCostPerMillion:  &inputCost,
		OutputCostPerMillion: &zeroCost,
		Enabled:              true,
	}); err != nil {
		t.Fatalf("UpsertModelRoute: %v", err)
	}

	route, err := st.GetModelRoute(ctx, "team/coding")
	if err != nil {
		t.Fatalf("GetModelRoute: %v", err)
	}
	if route.ProviderName != "anthropic" || len(route.Fallbacks) != 1 {
		t.Fatalf("unexpected route: %+v", route)
	}
	if route.InputCostPerMillion == nil || *route.InputCostPerMillion != 3.0 {
		t.Fatalf("InputCostPerMillion = %v, want 3.0", route.InputCostPerMillion)
	}
	if route.OutputCostPerMillion == nil || *route.OutputCostPerMillion != 0.0 {
		t.Fatalf("OutputCostPerMillion = %v, want 0.0", route.OutputCostPerMillion)
	}
	if route.CacheReadCostPerMillion != nil {
		t.Fatalf("CacheReadCostPerMillion = %v, want nil", route.CacheReadCostPerMillion)
	}

	// Deleting the provider should cascade-delete dependent routes (proves foreign keys ON).
	if err := st.DeleteProvider(ctx, "anthropic"); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/coding"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after cascade delete, got %v", err)
	}
}

func TestGroupsAndPoliciesCRUD(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	if err := st.UpsertGroup(ctx, Group{
		Name:        "engineering",
		Description: "Core engineers",
		Members:     []string{"alice@example.com", "tag:dev-box"},
	}); err != nil {
		t.Fatalf("UpsertGroup: %v", err)
	}
	if err := st.UpsertGroup(ctx, Group{
		Name:    "ci",
		Members: []string{"tag:ci-runner"},
	}); err != nil {
		t.Fatalf("UpsertGroup ci: %v", err)
	}

	groups, err := st.ListGroupsForMember(ctx, "alice@example.com", "tag:ci-runner")
	if err != nil {
		t.Fatalf("ListGroupsForMember: %v", err)
	}
	if len(groups) != 2 || groups[0] != "ci" || groups[1] != "engineering" {
		t.Fatalf("groups = %#v, want [ci engineering]", groups)
	}

	if err := st.UpsertPolicy(ctx, Policy{
		ID:          "p-low",
		Name:        "default",
		Subject:     "*",
		Role:        "user",
		AllowModels: []string{"openai/gpt-4.1-mini"},
		Priority:    10,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("UpsertPolicy low: %v", err)
	}
	if err := st.UpsertPolicy(ctx, Policy{
		ID:          "p-high",
		Name:        "eng",
		Subject:     "group:engineering",
		Role:        "user",
		AllowModels: []string{"anthropic/*"},
		DenyModels:  []string{"anthropic/claude-opus*"},
		Priority:    100,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("UpsertPolicy high: %v", err)
	}

	list, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 2 || list[0].ID != "p-high" || list[1].ID != "p-low" {
		t.Fatalf("unexpected priority ordering: %+v", list)
	}
}

func TestUsageLogsAuditPayloadsAndRetentionPurge(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Millisecond)
	oldTime := now.Add(-10 * 24 * time.Hour)
	recentTime := now.Add(-2 * time.Hour)

	if err := st.InsertUsageLog(ctx, UsageLog{
		ID:               "u-old",
		CreatedAt:        oldTime,
		RequestID:        "req-1",
		Subject:          "alice@example.com",
		NodeName:         "alice-mac",
		NodeIP:           "100.64.0.10",
		Tags:             []string{"tag:laptop"},
		AuthSource:       "tsnet",
		ProviderName:     "anthropic",
		ProviderType:     "anthropic",
		RequestedModel:   "claude-sonnet-4-20250514",
		UpstreamModel:    "claude-sonnet-4-20250514",
		Protocol:         "anthropic",
		Endpoint:         "/anthropic/v1/messages",
		Stream:           true,
		InputTokens:      1000,
		OutputTokens:     500,
		CacheReadTokens:  200,
		CacheWriteTokens: 100,
		TotalTokens:      1800,
		CostUSD:          0.025,
		LatencyMS:        1200,
		TTFTMS:           250,
		StatusCode:       200,
	}); err != nil {
		t.Fatalf("InsertUsageLog old: %v", err)
	}

	if err := st.InsertUsageLog(ctx, UsageLog{
		ID:             "u-recent",
		CreatedAt:      recentTime,
		Subject:        "bob@example.com",
		ProviderName:   "openai",
		RequestedModel: "gpt-4.1",
		UpstreamModel:  "gpt-4.1",
		InputTokens:    400,
		OutputTokens:   100,
		TotalTokens:    500,
		CostUSD:        0.010,
		StatusCode:     200,
	}); err != nil {
		t.Fatalf("InsertUsageLog recent: %v", err)
	}

	logs, err := st.QueryUsageLogs(ctx, UsageFilter{Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("QueryUsageLogs: %v", err)
	}
	if len(logs) != 1 || logs[0].ID != "u-old" || logs[0].CacheReadTokens != 200 {
		t.Fatalf("unexpected usage query result: %+v", logs)
	}

	sum, err := st.SummarizeUsage(ctx, UsageFilter{})
	if err != nil {
		t.Fatalf("SummarizeUsage: %v", err)
	}
	if sum.RequestCount != 2 || sum.TotalTokens != 2300 || sum.CostUSD < 0.034 || sum.CostUSD > 0.036 {
		t.Fatalf("unexpected usage summary: %+v", sum)
	}

	if err := st.InsertAuditPayload(ctx, AuditPayload{
		UsageLogID:      "u-old",
		CreatedAt:       oldTime,
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     `{"prompt":"old"}`,
		ResponseHeaders: map[string]string{"content-type": "text/event-stream"},
		ResponseBody:    "data: ok",
		Redacted:        true,
	}); err != nil {
		t.Fatalf("InsertAuditPayload old: %v", err)
	}
	if err := st.InsertAuditPayload(ctx, AuditPayload{
		UsageLogID:   "u-recent",
		CreatedAt:    recentTime,
		RequestBody:  `{"prompt":"recent"}`,
		ResponseBody: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditPayload recent: %v", err)
	}

	// Purge payloads older than 7 days.
	purged, err := st.PurgeAuditPayloads(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeAuditPayloads: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	if _, err := st.GetAuditPayloadByUsageLogID(ctx, "u-old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old payload to be purged, got %v", err)
	}
	recentPayload, err := st.GetAuditPayloadByUsageLogID(ctx, "u-recent")
	if err != nil || recentPayload.RequestBody != `{"prompt":"recent"}` {
		t.Fatalf("expected recent payload retained, got (%+v, %v)", recentPayload, err)
	}
}

func TestSyncConfigIdempotentAndPreservesKeysAndLocalRecords(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// Seed a local UI-created policy to make sure SyncConfig never clobbers it.
	if err := st.UpsertPolicy(ctx, Policy{
		ID:          "ui-policy-1",
		Name:        "local-ui-rule",
		Subject:     "carol@example.com",
		AllowModels: []string{"gemini/*"},
		Enabled:     true,
		Source:      SourceLocal,
	}); err != nil {
		t.Fatalf("seed local policy: %v", err)
	}

	cfg, err := config.LoadFromBytes([]byte(`
policy:
  mode: hybrid
  bootstrap_admins: ["alice@example.com"]
  groups:
    - name: engineering
      members: ["alice@example.com", "bob@example.com"]
  rules:
    - name: eng-models
      subject: "group:engineering"
      role: user
      allow_models: ["anthropic/*"]
      priority: 50
providers:
  - name: anthropic
    type: anthropic
    api_key: "sk-ant-initial-key"
    models: ["claude-sonnet-4-20250514"]
routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-20250514"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}

	if err := st.SyncConfig(ctx, cfg); err != nil {
		t.Fatalf("first SyncConfig: %v", err)
	}

	// Second sync omits api_key in YAML; existing encrypted DB key must be preserved.
	cfg.Providers[0].APIKey = ""
	if err := st.SyncConfig(ctx, cfg); err != nil {
		t.Fatalf("second SyncConfig: %v", err)
	}

	p, err := st.GetProvider(ctx, "anthropic")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if p.APIKey != "sk-ant-initial-key" {
		t.Fatalf("expected preserved api_key, got %q", p.APIKey)
	}

	// Local policy must still exist alongside synced bootstrap admin and config rule.
	if _, err := st.GetPolicy(ctx, "ui-policy-1"); err != nil {
		t.Fatalf("local policy lost after SyncConfig: %v", err)
	}
	if _, err := st.GetPolicy(ctx, "bootstrap-admin:alice@example.com"); err != nil {
		t.Fatalf("bootstrap admin policy missing: %v", err)
	}
	if _, err := st.GetPolicy(ctx, "cfg-rule:eng-models"); err != nil {
		t.Fatalf("config rule policy missing: %v", err)
	}

	groups, err := st.ListGroupsForMember(ctx, "bob@example.com")
	if err != nil || len(groups) != 1 || groups[0] != "engineering" {
		t.Fatalf("expected bob in engineering, got (%#v, %v)", groups, err)
	}
}
