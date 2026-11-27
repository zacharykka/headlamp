package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
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

func floatPtr(v float64) *float64 { return &v }

func TestSQLitePragmasPermissionsAndIdempotentMigration(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "nested")
	dbPath := filepath.Join(dbDir, "headlamp.db")
	st, _ := newTestStore(t, dbPath)
	ctx := context.Background()

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

	// Verify both migrations 1 and 2 are recorded.
	var migCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migCount != 2 {
		t.Fatalf("schema_migrations count = %d, want 2", migCount)
	}

	// Re-running Migrate must be a clean no-op.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigration0001To0002UpgradesExistingUsageLogs(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")

	// Simulate an M1 database that only applied 0001_initial.sql and has an existing usage_logs row.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	m1SQL, err := migrationsFS.ReadFile("migrations/0001_initial.sql")
	if err != nil {
		t.Fatalf("read 0001_initial.sql: %v", err)
	}
	if _, err := rawDB.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	if _, err := rawDB.ExecContext(ctx, string(m1SQL)); err != nil {
		t.Fatalf("exec 0001: %v", err)
	}
	if _, err := rawDB.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, '0001_initial.sql', '2026-11-26T00:00:00Z')`); err != nil {
		t.Fatalf("insert migration 1: %v", err)
	}
	if _, err := rawDB.ExecContext(ctx, `INSERT INTO usage_logs (id, created_at, subject, provider_name, requested_model, status_code) VALUES ('m1-row', '2026-11-26T01:00:00Z', 'alice', 'openai', 'gpt-5', 200)`); err != nil {
		t.Fatalf("insert m1 usage row: %v", err)
	}
	_ = rawDB.Close()

	// Opening with NewSQLiteStore must apply 0002 cleanly without losing existing M1 rows.
	st, _ := newTestStore(t, dbPath)
	got, err := st.GetUsageLog(ctx, "m1-row")
	if err != nil {
		t.Fatalf("GetUsageLog(m1-row) after 0002 upgrade: %v", err)
	}
	if got.Subject != "alice" || got.GuardrailAction != "" || len(got.GuardrailHits) != 0 {
		t.Fatalf("unexpected upgraded m1 row: %+v", got)
	}
}

func TestBuiltinGuardrailRulesCompileAndMatch(t *testing.T) {
	rules := DefaultBuiltinGuardrailRules()
	if len(rules) < 8 {
		t.Fatalf("expected at least 8 builtin rules, got %d", len(rules))
	}
	samples := map[string]string{
		"builtin-openai-key":      "key is sk-proj-abcdefghijklmnopqrstuvwxyz1234",
		"builtin-anthropic-key":   "key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234",
		"builtin-aws-access-key":  "aws AKIAIOSFODNN7EXAMPLE here",
		"builtin-github-token":    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"builtin-gcp-api-key":     "AIzaSyD-1234567890abcdefghij12345678901",
		"builtin-pem-private-key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
		"builtin-jwt":             "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"builtin-email":           "contact alice.smith@example.com please",
	}
	for _, r := range rules {
		rx, err := regexp.Compile(r.Pattern)
		if err != nil {
			t.Fatalf("builtin rule %q failed regex compile: %v", r.ID, err)
		}
		if sample, ok := samples[r.ID]; ok {
			if !rx.MatchString(sample) {
				t.Fatalf("builtin rule %q did not match expected sample %q", r.ID, sample)
			}
		}
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

	got.Models[0] = "mutated-model"
	list, err := st.ListProviders(ctx)
	if err != nil || len(list) != 1 || list[0].Models[0] != "claude-sonnet-4-6" {
		t.Fatalf("cache clone isolation failed: %+v (err=%v)", list, err)
	}

	route, err := st.GetModelRoute(ctx, "team/coding")
	if err != nil {
		t.Fatalf("GetModelRoute: %v", err)
	}
	*route.InputCostPerMillion = 999.0
	routes, err := st.ListModelRoutes(ctx)
	if err != nil || len(routes) != 1 || *routes[0].InputCostPerMillion != 3.0 {
		t.Fatalf("route cache clone isolation failed: %+v (err=%v)", routes, err)
	}
	if loads := st.cacheLoads.Load(); loads != 1 {
		t.Fatalf("expected 1 snapshot load across repeated reads, got %d", loads)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = st.ListProviders(ctx)
				_, _ = st.ListModelRoutes(ctx)
				_, _ = st.ListBudgets(ctx)
				_, _ = st.ListGuardrailRules(ctx)
				_, _ = st.ListWebhooks(ctx)
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

	if err := st.DeleteProvider(ctx, "anthropic"); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/coding"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after cascade delete, got %v", err)
	}
}

func TestGovernanceCRUDCacheAndEncryption(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// 1. Budgets CRUD + clone isolation
	if err := st.UpsertBudget(ctx, Budget{
		Scope:         "alice@example.com",
		RPM:           60,
		TPM:           100000,
		MaxConcurrent: 5,
		DailyUSD:      floatPtr(10.0),
		MonthlyUSD:    floatPtr(100.0),
		SoftAlertPct:  85,
		Enabled:       true,
	}); err != nil {
		t.Fatalf("UpsertBudget: %v", err)
	}

	// 2. Guardrail rules CRUD
	if err := st.UpsertGuardrailRule(ctx, GuardrailRule{
		ID:       "custom-ssn",
		Name:     "SSN Detector",
		Category: config.GuardrailCategoryPII,
		Pattern:  `\b\d{3}-\d{2}-\d{4}\b`,
		Action:   config.GuardrailActionBlock,
		Enabled:  true,
	}); err != nil {
		t.Fatalf("UpsertGuardrailRule: %v", err)
	}

	// 3. Webhooks CRUD + encrypted secret_enc at rest
	whSecret := "whsec_super_secret_hmac_key"
	if err := st.UpsertWebhook(ctx, Webhook{
		ID:        "wh-alerts",
		Name:      "Ops Alerts",
		URL:       "https://hooks.example.com/alerts",
		Type:      config.WebhookTypeAsyncEvent,
		Secret:    whSecret,
		Events:    []string{config.WebhookEventBudgetThreshold, config.WebhookEventGuardrailTriggered},
		TimeoutMS: 2500,
		FailOpen:  true,
		Enabled:   true,
	}); err != nil {
		t.Fatalf("UpsertWebhook: %v", err)
	}

	var rawSecret string
	if err := st.DB().QueryRowContext(ctx, `SELECT secret_enc FROM webhooks WHERE id = 'wh-alerts'`).Scan(&rawSecret); err != nil {
		t.Fatalf("select raw secret_enc: %v", err)
	}
	if !crypto.IsEncrypted(rawSecret) || strings.Contains(rawSecret, whSecret) {
		t.Fatalf("expected encrypted webhook secret_enc, got %q", rawSecret)
	}

	// Verify all three tables share ONE snapshot cache load.
	b, err := st.GetBudget(ctx, "alice@example.com")
	if err != nil || *b.DailyUSD != 10.0 || b.SoftAlertPct != 85 {
		t.Fatalf("GetBudget = (%+v, %v)", b, err)
	}
	*b.DailyUSD = 999.0 // mutate caller copy
	b2, _ := st.GetBudget(ctx, "alice@example.com")
	if *b2.DailyUSD != 10.0 {
		t.Fatalf("budget cache clone isolation failed: got %f", *b2.DailyUSD)
	}

	gr, err := st.GetGuardrailRule(ctx, "custom-ssn")
	if err != nil || gr.Action != config.GuardrailActionBlock {
		t.Fatalf("GetGuardrailRule = (%+v, %v)", gr, err)
	}

	wh, err := st.GetWebhook(ctx, "wh-alerts")
	if err != nil || wh.Secret != whSecret || len(wh.Events) != 2 {
		t.Fatalf("GetWebhook = (%+v, %v)", wh, err)
	}
	wh.Events[0] = "mutated"
	wh2, _ := st.GetWebhook(ctx, "wh-alerts")
	if wh2.Events[0] != config.WebhookEventBudgetThreshold {
		t.Fatalf("webhook cache clone isolation failed: %#v", wh2.Events)
	}
	if loads := st.cacheLoads.Load(); loads != 1 {
		t.Fatalf("expected 1 snapshot load across budget/guardrail/webhook reads, got %d", loads)
	}

	// 4. Runtime audit settings
	if _, err := st.GetAuditSettings(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound before SetAuditSettings, got %v", err)
	}
	if err := st.SetAuditSettings(ctx, AuditSettings{StorePayloads: true, RetentionDays: 14}); err != nil {
		t.Fatalf("SetAuditSettings: %v", err)
	}
	as, err := st.GetAuditSettings(ctx)
	if err != nil || !as.StorePayloads || as.RetentionDays != 14 || as.UpdatedAt.IsZero() {
		t.Fatalf("GetAuditSettings = (%+v, %v)", as, err)
	}

	// Delete operations invalidate cache cleanly.
	if err := st.DeleteBudget(ctx, "alice@example.com"); err != nil {
		t.Fatalf("DeleteBudget: %v", err)
	}
	if _, err := st.GetBudget(ctx, "alice@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteBudget, got %v", err)
	}
	if err := st.DeleteGuardrailRule(ctx, "custom-ssn"); err != nil {
		t.Fatalf("DeleteGuardrailRule: %v", err)
	}
	if err := st.DeleteWebhook(ctx, "wh-alerts"); err != nil {
		t.Fatalf("DeleteWebhook: %v", err)
	}
}

func TestDashboardAnalyticsQueriesAndFilters(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	base := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	rows := []UsageLog{
		{ID: "u1", CreatedAt: base, Subject: "alice", Tags: []string{"tag:eng"}, ProviderName: "anthropic", RequestedModel: "claude-sonnet-4-6", TotalTokens: 1000, CostUSD: 0.05, LatencyMS: 100, StatusCode: 200},
		{ID: "u2", CreatedAt: base.Add(15 * time.Minute), Subject: "alice", Tags: []string{"tag:eng"}, ProviderName: "anthropic", RequestedModel: "claude-sonnet-4-6", TotalTokens: 2000, CostUSD: 0.10, LatencyMS: 200, StatusCode: 200, GuardrailAction: "redact", GuardrailHits: []string{"builtin-aws-access-key"}},
		{ID: "u3", CreatedAt: base.Add(1 * time.Hour), Subject: "bob", Tags: []string{"tag:ops"}, ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 500, CostUSD: 0.03, LatencyMS: 400, StatusCode: 429, ErrorMessage: "rate limit"},
		{ID: "u4", CreatedAt: base.Add(1 * time.Hour), Subject: "tag:ci", Tags: []string{"tag:ci"}, ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 1500, CostUSD: 0.07, LatencyMS: 1000, StatusCode: 200},
		{ID: "u5", CreatedAt: base.Add(25 * time.Hour), Subject: "alice", Tags: []string{"tag:eng"}, ProviderName: "gemini", RequestedModel: "gemini-2.5-flash", TotalTokens: 800, CostUSD: 0.01, LatencyMS: 300, StatusCode: 400, GuardrailAction: "block", GuardrailHits: []string{"builtin-pem-private-key"}},
	}
	for _, r := range rows {
		if err := st.InsertUsageLog(ctx, r); err != nil {
			t.Fatalf("InsertUsageLog(%s): %v", r.ID, err)
		}
	}

	// Extended summary: 5 requests, 2 errors (429 + 400), latencies [100,200,300,400,1000] -> ceil(0.95*5)-1 = 4 -> 1000ms.
	ext, err := st.SummarizeUsageExtended(ctx, UsageFilter{})
	if err != nil {
		t.Fatalf("SummarizeUsageExtended: %v", err)
	}
	if ext.RequestCount != 5 || ext.ErrorCount != 2 || ext.P95LatencyMS != 1000 || math.Abs(ext.CostUSD-0.26) > 1e-9 {
		t.Fatalf("unexpected extended summary: %+v", ext)
	}

	// GuardrailOnly + StatusCode + Tag filters
	grLogs, err := st.QueryUsageLogs(ctx, UsageFilter{GuardrailOnly: true})
	if err != nil || len(grLogs) != 2 {
		t.Fatalf("GuardrailOnly logs = (%d, %v), want 2", len(grLogs), err)
	}
	status429, err := st.QueryUsageLogs(ctx, UsageFilter{StatusCode: 429})
	if err != nil || len(status429) != 1 || status429[0].ID != "u3" {
		t.Fatalf("StatusCode 429 logs = (%+v, %v)", status429, err)
	}
	engSummary, err := st.SummarizeUsage(ctx, UsageFilter{Tag: "tag:eng"})
	if err != nil || engSummary.RequestCount != 3 || math.Abs(engSummary.CostUSD-0.16) > 1e-9 {
		t.Fatalf("Tag filter summary = (%+v, %v)", engSummary, err)
	}
	ciSummary, err := st.SummarizeUsage(ctx, UsageFilter{Tag: "tag:ci"})
	if err != nil || ciSummary.RequestCount != 1 || math.Abs(ciSummary.CostUSD-0.07) > 1e-9 {
		t.Fatalf("Tag subject filter summary = (%+v, %v)", ciSummary, err)
	}

	// Time series (hour & day)
	hourSeries, err := st.QueryUsageSeries(ctx, UsageFilter{}, "hour")
	if err != nil {
		t.Fatalf("QueryUsageSeries(hour): %v", err)
	}
	if len(hourSeries) != 3 || hourSeries[0].Bucket != "2026-11-26T10:00:00Z" || hourSeries[0].Requests != 2 || hourSeries[1].Errors != 1 {
		t.Fatalf("unexpected hour series: %+v", hourSeries)
	}
	daySeries, err := st.QueryUsageSeries(ctx, UsageFilter{}, "day")
	if err != nil || len(daySeries) != 2 || daySeries[0].Bucket != "2026-11-26" || daySeries[0].Requests != 4 || daySeries[1].Bucket != "2026-11-27" {
		t.Fatalf("unexpected day series: %+v (err=%v)", daySeries, err)
	}

	// Top subjects (ordered by cost DESC: alice $0.16, tag:ci $0.07, bob $0.03)
	topSubs, err := st.QueryTopSubjects(ctx, UsageFilter{}, 2)
	if err != nil || len(topSubs) != 2 || topSubs[0].Subject != "alice" || topSubs[1].Subject != "tag:ci" {
		t.Fatalf("unexpected top subjects: %+v (err=%v)", topSubs, err)
	}

	// Top models (claude-sonnet-4-6 $0.15, gpt-5 $0.10, gemini-2.5-flash $0.01)
	topModels, err := st.QueryTopModels(ctx, UsageFilter{}, 2)
	if err != nil || len(topModels) != 2 || topModels[0].Model != "claude-sonnet-4-6" || topModels[0].Provider != "anthropic" || topModels[1].Model != "gpt-5" {
		t.Fatalf("unexpected top models: %+v (err=%v)", topModels, err)
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
		GuardrailAction:  "redact",
		GuardrailHits:    []string{"builtin-aws-access-key"},
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
	if len(logs) != 1 || logs[0].ID != "u-old" || logs[0].GuardrailAction != "redact" || len(logs[0].GuardrailHits) != 1 {
		t.Fatalf("unexpected usage query result: %+v", logs)
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

func TestSyncConfigReconcilesGovernanceAndPreservesLocalRecords(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// Seed local UI-created records across all governance tables.
	if err := st.UpsertProvider(ctx, Provider{
		Name: "local-ollama", Type: config.ProviderTypeOllama, BaseURL: "http://127.0.0.1:11434",
		Models: []string{"llama3"}, Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("seed local provider: %v", err)
	}
	if err := st.UpsertModelRoute(ctx, ModelRoute{
		Alias: "local/llama", ProviderName: "local-ollama", UpstreamModel: "llama3", Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("seed local route: %v", err)
	}
	if err := st.UpsertBudget(ctx, Budget{
		Scope: "ui-user@example.com", RPM: 10, Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("seed local budget: %v", err)
	}
	if err := st.UpsertGuardrailRule(ctx, GuardrailRule{
		ID: "ui-rule-1", Name: "UI Rule", Category: "custom", Pattern: "SECRET", Action: "block", Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("seed local guardrail: %v", err)
	}
	if err := st.UpsertWebhook(ctx, Webhook{
		ID: "ui-wh-1", Name: "UI Webhook", URL: "https://ui.example.com/hook", Type: config.WebhookTypeAsyncEvent, Enabled: true, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("seed local webhook: %v", err)
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
budgets:
  - scope: "*"
    rpm: 100
    daily_usd: 50.0
  - scope: "bob@example.com"
    rpm: 20
guardrails:
  builtin_defaults: true
  rules:
    - id: cfg-custom-1
      name: Custom Config Rule
      category: custom
      pattern: "CONFIDENTIAL"
      action: block
webhooks:
  - id: cfg-wh-1
    name: Config Alerts
    url: https://hooks.example.com/one
    type: async_event
    secret: "whsec_initial"
    events: ["budget.exceeded"]
  - id: cfg-wh-2
    name: Removed Later
    url: https://hooks.example.com/two
    type: async_event
    events: ["upstream.error"]
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg1: %v", err)
	}

	if err := st.SyncConfig(ctx, cfg1); err != nil {
		t.Fatalf("first SyncConfig: %v", err)
	}

	// Verify built-in guardrails were seeded with SourceBuiltin alongside custom rule.
	seededAWS, err := st.GetGuardrailRule(ctx, "builtin-aws-access-key")
	if err != nil || seededAWS.Source != SourceBuiltin || !seededAWS.Builtin {
		t.Fatalf("expected builtin-aws-access-key seeded with source=%q, got (%+v, %v)", SourceBuiltin, seededAWS, err)
	}

	// Simulate Admin UI customizing a built-in guardrail rule (flips source='local', action='block').
	if err := st.UpsertGuardrailRule(ctx, GuardrailRule{
		ID: "builtin-aws-access-key", Name: "AWS Access Key ID", Category: "secret",
		Pattern: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, Action: config.GuardrailActionBlock,
		Builtin: true, Enabled: false, Source: SourceLocal,
	}); err != nil {
		t.Fatalf("customize builtin rule via UI: %v", err)
	}

	// Second sync:
	// - omits api_key on anthropic & secret on cfg-wh-1 (must preserve stored encrypted secrets)
	// - removes openai, team/openai, bob budget, cfg-custom-1 guardrail, and cfg-wh-2 webhook
	// - keeps builtin_defaults: true (must NOT clobber Admin UI customization of builtin-aws-access-key!)
	cfg2, err := config.LoadFromBytes([]byte(`
providers:
  - name: anthropic
    type: anthropic
    models: ["claude-sonnet-4-6"]
routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
budgets:
  - scope: "*"
    rpm: 150
guardrails:
  builtin_defaults: true
webhooks:
  - id: cfg-wh-1
    name: Config Alerts Updated
    url: https://hooks.example.com/one
    type: async_event
    events: ["budget.exceeded"]
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg2: %v", err)
	}
	if err := st.SyncConfig(ctx, cfg2); err != nil {
		t.Fatalf("second SyncConfig: %v", err)
	}

	// Preserved secrets
	p, err := st.GetProvider(ctx, "anthropic")
	if err != nil || p.APIKey != "sk-ant-initial-key" {
		t.Fatalf("expected preserved provider api_key, got (%+v, %v)", p, err)
	}
	wh, err := st.GetWebhook(ctx, "cfg-wh-1")
	if err != nil || wh.Secret != "whsec_initial" || wh.Name != "Config Alerts Updated" {
		t.Fatalf("expected preserved webhook secret, got (%+v, %v)", wh, err)
	}

	// Admin UI customization of built-in rule preserved
	awsRule, err := st.GetGuardrailRule(ctx, "builtin-aws-access-key")
	if err != nil || awsRule.Enabled || awsRule.Action != config.GuardrailActionBlock {
		t.Fatalf("SyncConfig clobbered UI customization of builtin rule: %+v (err=%v)", awsRule, err)
	}

	// Pruned stale source='config' entries
	if _, err := st.GetProvider(ctx, "openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed provider openai deleted, got %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "team/openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed route team/openai deleted, got %v", err)
	}
	if _, err := st.GetBudget(ctx, "bob@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed budget bob deleted, got %v", err)
	}
	if _, err := st.GetGuardrailRule(ctx, "cfg-custom-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed guardrail cfg-custom-1 deleted, got %v", err)
	}
	if _, err := st.GetWebhook(ctx, "cfg-wh-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed webhook cfg-wh-2 deleted, got %v", err)
	}

	// Local UI records preserved across all tables
	if _, err := st.GetProvider(ctx, "local-ollama"); err != nil {
		t.Fatalf("local provider lost: %v", err)
	}
	if _, err := st.GetModelRoute(ctx, "local/llama"); err != nil {
		t.Fatalf("local route lost: %v", err)
	}
	if _, err := st.GetBudget(ctx, "ui-user@example.com"); err != nil {
		t.Fatalf("local budget lost: %v", err)
	}
	if _, err := st.GetGuardrailRule(ctx, "ui-rule-1"); err != nil {
		t.Fatalf("local guardrail lost: %v", err)
	}
	if _, err := st.GetWebhook(ctx, "ui-wh-1"); err != nil {
		t.Fatalf("local webhook lost: %v", err)
	}
}

func TestSyncConfigBuiltinOverrideAndRestore(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// 1. Pin builtin-email explicitly in YAML -> must become source='config' with builtin=true.
	cfgPinned, err := config.LoadFromBytes([]byte(`
guardrails:
  builtin_defaults: true
  rules:
    - id: builtin-email
      name: Email Strict
      category: pii
      pattern: 'custom-email-regex@example\.com'
      action: block
      enabled: true
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfgPinned: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgPinned); err != nil {
		t.Fatalf("SyncConfig cfgPinned: %v", err)
	}

	pinned, err := st.GetGuardrailRule(ctx, "builtin-email")
	if err != nil || !pinned.Builtin || pinned.Source != SourceConfig || pinned.Action != config.GuardrailActionBlock || !pinned.Enabled {
		t.Fatalf("expected YAML-pinned builtin-email with source=config, got (%+v, %v)", pinned, err)
	}
	untouched, err := st.GetGuardrailRule(ctx, "builtin-openai-key")
	if err != nil || !untouched.Builtin || untouched.Source != SourceBuiltin {
		t.Fatalf("expected unpinned builtin-openai-key with source=builtin, got (%+v, %v)", untouched, err)
	}

	// 2. Remove builtin-email from YAML rules while keeping builtin_defaults: true ->
	// stale source='config' override is pruned and default SourceBuiltin preset is restored in the same tx!
	cfgRestored, err := config.LoadFromBytes([]byte(`
guardrails:
  builtin_defaults: true
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfgRestored: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgRestored); err != nil {
		t.Fatalf("SyncConfig cfgRestored: %v", err)
	}

	restored, err := st.GetGuardrailRule(ctx, "builtin-email")
	if err != nil || !restored.Builtin || restored.Source != SourceBuiltin || restored.Action != config.GuardrailActionLogOnly || restored.Enabled {
		t.Fatalf("expected default builtin-email restored with source=builtin, got (%+v, %v)", restored, err)
	}
}
