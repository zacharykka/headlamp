package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestSQLitePragmasPermissionsAndIdempotentMigration(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "nested")
	dbPath := filepath.Join(dbDir, "headlamp.db")
	st, _ := newTestStore(t, dbPath)
	ctx := context.Background()

	// P3: verify 0700 parent dir and 0600 SQLite DB file permissions.
	dirInfo, err := os.Stat(dbDir)
	if err != nil {
		t.Fatalf("stat dbDir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("db dir perm = %04o, want 0700", perm)
	}
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat dbPath: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db file perm = %04o, want 0600", perm)
	}

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

func TestProvidersEncryptedAtRestRoutesCRUDAndSnapshotCache(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	secret := "sk-ant-super-secret-value"
	if err := st.UpsertProvider(ctx, Provider{
		Name:        "anthropic",
		Type:        config.ProviderTypeAnthropic,
		BaseURL:     "https://api.anthropic.com",
		APIKey:      secret,
		Passthrough: false,
		Models:      []string{"claude-sonnet-4-6"},
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

	zeroCost := 0.0
	inputCost := 3.0
	if err := st.UpsertModelRoute(ctx, ModelRoute{
		Alias:                "team/coding",
		ProviderName:         "anthropic",
		UpstreamModel:        "claude-sonnet-4-6",
		Fallbacks:            []RouteTarget{{Provider: "anthropic", Model: "claude-haiku-4-5"}},
		InputCostPerMillion:  &inputCost,
		OutputCostPerMillion: &zeroCost,
		Enabled:              true,
	}); err != nil {
		t.Fatalf("UpsertModelRoute: %v", err)
	}

	// P2-1: first read loads snapshot once; subsequent reads hit memory cache with 0 DB reloads.
	got, err := st.GetProvider(ctx, "anthropic")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.APIKey != secret || len(got.Models) != 1 || !got.Enabled {
		t.Fatalf("unexpected provider: %+v", got)
	}
	if loads := st.cacheLoads.Load(); loads != 1 {
		t.Fatalf("cacheLoads = %d, want 1", loads)
	}

	// Mutating returned structs must NOT corrupt the cached snapshot.
	got.Models[0] = "mutated-model"
	list, err := st.ListProviders(ctx)
	if err != nil || len(list) != 1 || list[0].Models[0] != "claude-sonnet-4-6" {
		t.Fatalf("cache clone isolation failed: %+v (err=%v)", list, err)
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
	*route.InputCostPerMillion = 999.0
	routes, err := st.ListModelRoutes(ctx)
	if err != nil || len(routes) != 1 || *routes[0].InputCostPerMillion != 3.0 {
		t.Fatalf("route cache clone isolation failed: %+v (err=%v)", routes, err)
	}

	// All four reads above must have shared the single cached snapshot.
	if loads := st.cacheLoads.Load(); loads != 1 {
		t.Fatalf("expected 1 snapshot load across repeated reads, got %d", loads)
	}

	// Concurrent reads + writes under -race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = st.ListProviders(ctx)
				_, _ = st.ListModelRoutes(ctx)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			_ = st.UpsertProvider(ctx, Provider{
				Name:    "anthropic",
				Type:    config.ProviderTypeAnthropic,
				BaseURL: "https://api.anthropic.com",
				APIKey:  secret,
				Models:  []string{"claude-sonnet-4-6"},
				Enabled: true,
			})
		}
	}()
	wg.Wait()

	// Deleting the provider invalidates cache and cascade-deletes dependent routes.
	if err := st.DeleteProvider(ctx, "anthropic"); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/coding"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after cascade delete, got %v", err)
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
		RequestedModel:   "claude-sonnet-4-6",
		UpstreamModel:    "claude-sonnet-4-6",
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

func TestSyncConfigReconcilesRemovedEntriesAndPreservesKeysAndLocalRecords(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// Seed a local UI-created provider and route to ensure SyncConfig never deletes source='local'.
	if err := st.UpsertProvider(ctx, Provider{
		Name:    "local-ollama",
		Type:    config.ProviderTypeOllama,
		BaseURL: "http://127.0.0.1:11434",
		Models:  []string{"llama3"},
		Enabled: true,
		Source:  SourceLocal,
	}); err != nil {
		t.Fatalf("seed local provider: %v", err)
	}
	if err := st.UpsertModelRoute(ctx, ModelRoute{
		Alias:         "local/llama",
		ProviderName:  "local-ollama",
		UpstreamModel: "llama3",
		Enabled:       true,
		Source:        SourceLocal,
	}); err != nil {
		t.Fatalf("seed local route: %v", err)
	}

	cfg1, err := config.LoadFromBytes([]byte(`
providers:
  - name: anthropic
    type: anthropic
    api_key: "sk-ant-initial-key"
    models: ["claude-sonnet-4-6"]
  - name: openai
    type: openai
    api_key: "sk-openai-key"
    models: ["gpt-5"]
routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
  - alias: "team/openai"
    provider: openai
    model: "gpt-5"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg1: %v", err)
	}

	if err := st.SyncConfig(ctx, cfg1); err != nil {
		t.Fatalf("first SyncConfig: %v", err)
	}

	// Second sync:
	// - omits api_key on anthropic (must preserve stored encrypted key)
	// - removes provider "openai" and route "team/openai" (P0-1: stale source='config' MUST be deleted!)
	cfg2, err := config.LoadFromBytes([]byte(`
providers:
  - name: anthropic
    type: anthropic
    models: ["claude-sonnet-4-6"]
routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg2: %v", err)
	}

	if err := st.SyncConfig(ctx, cfg2); err != nil {
		t.Fatalf("second SyncConfig: %v", err)
	}

	p, err := st.GetProvider(ctx, "anthropic")
	if err != nil {
		t.Fatalf("GetProvider(anthropic): %v", err)
	}
	if p.APIKey != "sk-ant-initial-key" {
		t.Fatalf("expected preserved api_key, got %q", p.APIKey)
	}

	// Removed config-managed provider & route MUST be gone (P0-1).
	if _, err := st.GetProvider(ctx, "openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed config provider openai should return ErrNotFound, got %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed config route team/openai should return ErrNotFound, got %v", err)
	}

	// Local UI records MUST be preserved untouched.
	if _, err := st.GetProvider(ctx, "local-ollama"); err != nil {
		t.Fatalf("local provider lost after SyncConfig: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "local/llama"); err != nil {
		t.Fatalf("local route lost after SyncConfig: %v", err)
	}

	// Syncing an empty providers/routes config deletes all remaining source='config' entries
	// while still keeping source='local' entries.
	cfgEmpty, err := config.LoadFromBytes([]byte(``))
	if err != nil {
		t.Fatalf("LoadFromBytes empty: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgEmpty); err != nil {
		t.Fatalf("third SyncConfig empty: %v", err)
	}
	if _, err := st.GetProvider(ctx, "anthropic"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected anthropic deleted on empty config sync, got %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/coding"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected team/coding deleted on empty config sync, got %v", err)
	}
	if _, err := st.GetProvider(ctx, "local-ollama"); err != nil {
		t.Fatalf("local provider lost on empty config sync: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "local/llama"); err != nil {
		t.Fatalf("local route lost on empty config sync: %v", err)
	}
}
