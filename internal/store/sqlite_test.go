package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

	// Verify migrations 1, 2, and 3 are recorded.
	var migCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migCount != 3 {
		t.Fatalf("schema_migrations count = %d, want 3", migCount)
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

	// GuardrailOnly + StatusCode + ErrorsOnly + Tag filters
	grLogs, err := st.QueryUsageLogs(ctx, UsageFilter{GuardrailOnly: true})
	if err != nil || len(grLogs) != 2 {
		t.Fatalf("GuardrailOnly logs = (%d, %v), want 2", len(grLogs), err)
	}
	errLogs, err := st.QueryUsageLogs(ctx, UsageFilter{ErrorsOnly: true})
	if err != nil || len(errLogs) != 2 {
		t.Fatalf("ErrorsOnly logs = (%d, %v), want 2", len(errLogs), err)
	}
	for _, l := range errLogs {
		if l.StatusCode < 400 && l.StatusCode != 0 && l.ErrorMessage == "" {
			t.Fatalf("ErrorsOnly returned non-error row: %+v", l)
		}
	}
	errSummary, err := st.SummarizeUsageExtended(ctx, UsageFilter{ErrorsOnly: true})
	if err != nil || errSummary.RequestCount != 2 || errSummary.ErrorCount != 2 || math.Abs(errSummary.CostUSD-0.04) > 1e-9 {
		t.Fatalf("ErrorsOnly extended summary = (%+v, %v)", errSummary, err)
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

	// Regression: ErrorsOnly must match SummarizeUsageExtended / QueryUsageSeries on mid-stream
	// failures (StatusCode=200 + ErrorMessage!="") and zero-status errors (StatusCode=0).
	if err := st.InsertUsageLog(ctx, UsageLog{
		ID: "u6-midstream", CreatedAt: base.Add(26 * time.Hour), Subject: "alice", Tags: []string{"tag:eng"},
		ProviderName: "anthropic", RequestedModel: "claude-sonnet-4-6", TotalTokens: 300, CostUSD: 0.02,
		LatencyMS: 150, StatusCode: 200, ErrorMessage: "stream EOF",
	}); err != nil {
		t.Fatalf("InsertUsageLog(u6-midstream): %v", err)
	}
	if err := st.InsertUsageLog(ctx, UsageLog{
		ID: "u7-zero-status", CreatedAt: base.Add(26*time.Hour + time.Minute), Subject: "bob", Tags: []string{"tag:ops"},
		ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 0, CostUSD: 0,
		LatencyMS: 50, StatusCode: 0, ErrorMessage: "",
	}); err != nil {
		t.Fatalf("InsertUsageLog(u7-zero-status): %v", err)
	}
	errLogsAfter, err := st.QueryUsageLogs(ctx, UsageFilter{ErrorsOnly: true})
	if err != nil || len(errLogsAfter) != 4 {
		t.Fatalf("ErrorsOnly logs with midstream+zero status = (%d, %v), want 4", len(errLogsAfter), err)
	}
	allExtAfter, err := st.SummarizeUsageExtended(ctx, UsageFilter{})
	if err != nil || allExtAfter.ErrorCount != 4 {
		t.Fatalf("SummarizeUsageExtended ErrorCount = (%+v, %v), want 4", allExtAfter, err)
	}
	errExtAfter, err := st.SummarizeUsageExtended(ctx, UsageFilter{ErrorsOnly: true})
	if err != nil || errExtAfter.RequestCount != 4 || errExtAfter.ErrorCount != 4 {
		t.Fatalf("ErrorsOnly summary after midstream+zero status = (%+v, %v)", errExtAfter, err)
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

func TestM3MCPServersEncryptionSyncAuditAndChatIsolation(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// 1. Verify migration 0003 applied cleanly.
	var maxVer int
	if err := st.DB().QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&maxVer); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if maxVer < 3 {
		t.Fatalf("expected migration >= 3, got %d", maxVer)
	}

	// 2. MCPServer CRUD, AES-256-GCM encryption at rest, snapshot cache, and SyncConfig reconciliation.
	if err := st.UpsertMCPServer(ctx, MCPServer{
		Name:      "local-tools",
		URL:       "https://local-mcp.internal/mcp",
		Transport: config.MCPTransportStreamableHTTP,
		AuthType:  config.MCPAuthBearer,
		AuthToken: "mcp_local_secret_token",
		Enabled:   true,
		Source:    SourceLocal,
	}); err != nil {
		t.Fatalf("UpsertMCPServer(local-tools): %v", err)
	}

	var rawEnc string
	if err := st.DB().QueryRowContext(ctx, `SELECT auth_token_enc FROM mcp_servers WHERE name = ?`, "local-tools").Scan(&rawEnc); err != nil {
		t.Fatalf("query raw auth_token_enc: %v", err)
	}
	if rawEnc == "" || strings.Contains(rawEnc, "mcp_local_secret_token") {
		t.Fatalf("auth_token was not encrypted at rest: %q", rawEnc)
	}

	gotLocal, err := st.GetMCPServer(ctx, "local-tools")
	if err != nil || gotLocal.AuthToken != "mcp_local_secret_token" || gotLocal.Source != SourceLocal {
		t.Fatalf("GetMCPServer(local-tools) = (%+v, %v)", gotLocal, err)
	}

	// SyncConfig with two YAML servers, then second SyncConfig omitting auth_token on docs and removing github.
	cfg1, err := config.LoadFromBytes([]byte(`
mcp_servers:
  - name: docs
    url: "https://docs.internal/mcp"
    transport: streamable_http
    auth_type: bearer
    auth_token: "docs-yaml-secret"
  - name: github
    url: "https://github.internal/sse"
    transport: sse
    auth_type: header
    auth_header: "X-API-Key"
    auth_token: "gh-yaml-secret"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg1: %v", err)
	}
	if err := st.SyncConfig(ctx, cfg1); err != nil {
		t.Fatalf("SyncConfig cfg1: %v", err)
	}

	// Snapshot cache hit check on repeated reads.
	beforeLoads := st.cacheLoads.Load()
	if list, err := st.ListMCPServers(ctx); err != nil || len(list) != 3 {
		t.Fatalf("ListMCPServers = (%d, %v), want 3", len(list), err)
	}
	if _, err := st.GetMCPServer(ctx, "docs"); err != nil {
		t.Fatalf("GetMCPServer(docs): %v", err)
	}
	if st.cacheLoads.Load() != beforeLoads+1 {
		t.Fatalf("expected 1 snapshot load across List+Get, got %d", st.cacheLoads.Load()-beforeLoads)
	}

	cfg2, err := config.LoadFromBytes([]byte(`
mcp_servers:
  - name: docs
    url: "https://docs-v2.internal/mcp"
    transport: streamable_http
    auth_type: bearer
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfg2: %v", err)
	}
	if err := st.SyncConfig(ctx, cfg2); err != nil {
		t.Fatalf("SyncConfig cfg2: %v", err)
	}

	docs, err := st.GetMCPServer(ctx, "docs")
	if err != nil || docs.URL != "https://docs-v2.internal/mcp" || docs.AuthToken != "docs-yaml-secret" || docs.Source != SourceConfig {
		t.Fatalf("SyncConfig did not preserve docs token or update URL: (%+v, %v)", docs, err)
	}
	if _, err := st.GetMCPServer(ctx, "github"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected removed YAML mcp server github pruned, got %v", err)
	}
	if _, err := st.GetMCPServer(ctx, "local-tools"); err != nil {
		t.Fatalf("expected SourceLocal mcp server preserved, got %v", err)
	}
	if err := st.DeleteMCPServer(ctx, "local-tools"); err != nil {
		t.Fatalf("DeleteMCPServer: %v", err)
	}

	// 3. MCP Audit Logs insert & filtered queries.
	base := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	mcpLogs := []MCPAuditLog{
		{ID: "m1", CreatedAt: base, RequestID: "req-1", Subject: "alice@example.com", DisplayName: "Alice", NodeName: "alice-mac", NodeIP: "100.64.0.10", Tags: []string{"tag:eng"}, AuthSource: "tsnet", ServerName: "docs", Method: "tools/call", ToolName: "search", Status: "ok", LatencyMS: 42, ArgumentsPreview: `{"q":"tsnet"}`},
		{ID: "m2", CreatedAt: base.Add(time.Minute), RequestID: "req-2", Subject: "bob@example.com", DisplayName: "Bob", NodeName: "bob-mac", NodeIP: "100.64.0.11", Tags: []string{"tag:ops"}, AuthSource: "tsnet", ServerName: "github", Method: "tools/call", ToolName: "delete_repo", Status: "denied", LatencyMS: 3, ErrorMessage: "denied by grant"},
		{ID: "m3", CreatedAt: base.Add(2 * time.Minute), RequestID: "req-3", Subject: "alice@example.com", DisplayName: "Alice", NodeName: "alice-mac", NodeIP: "100.64.0.10", Tags: []string{"tag:eng"}, AuthSource: "tsnet", ServerName: "docs", Method: "tools/call", ToolName: "read_page", Status: "blocked", LatencyMS: 5, ErrorMessage: "pem key blocked"},
	}
	for _, ml := range mcpLogs {
		if err := st.InsertMCPAuditLog(ctx, ml); err != nil {
			t.Fatalf("InsertMCPAuditLog(%s): %v", ml.ID, err)
		}
	}
	byServer, err := st.QueryMCPAuditLogs(ctx, MCPAuditFilter{ServerName: "docs"})
	if err != nil || len(byServer) != 2 || byServer[0].ID != "m3" {
		t.Fatalf("QueryMCPAuditLogs(docs) = (%+v, %v)", byServer, err)
	}
	byStatus, err := st.QueryMCPAuditLogs(ctx, MCPAuditFilter{Status: "denied", ToolName: "delete_repo"})
	if err != nil || len(byStatus) != 1 || byStatus[0].ID != "m2" {
		t.Fatalf("QueryMCPAuditLogs(denied) = (%+v, %v)", byStatus, err)
	}
	byLimit, err := st.QueryMCPAuditLogs(ctx, MCPAuditFilter{Limit: 1, Offset: 1})
	if err != nil || len(byLimit) != 1 || byLimit[0].ID != "m2" {
		t.Fatalf("QueryMCPAuditLogs(limit=1,offset=1) = (%+v, %v)", byLimit, err)
	}

	// 4. Chat Sessions & Messages with strict per-subject ownership isolation and cascade delete.
	sAlice, err := st.CreateChatSession(ctx, ChatSession{
		Subject:      "alice@example.com",
		Title:        "Debug Headscale",
		Model:        "team/coding",
		MCPServers:   []string{"docs"},
		SystemPrompt: "Be concise.",
	})
	if err != nil || sAlice.ID == "" || sAlice.Title != "Debug Headscale" || len(sAlice.MCPServers) != 1 {
		t.Fatalf("CreateChatSession(alice) = (%+v, %v)", sAlice, err)
	}
	sBob, err := st.CreateChatSession(ctx, ChatSession{
		Subject: "bob@example.com",
		Title:   "Bob Private Chat",
		Model:   "gpt-5",
	})
	if err != nil {
		t.Fatalf("CreateChatSession(bob): %v", err)
	}

	// Bob MUST NOT read, update, insert into, list messages of, or delete Alice's session.
	if _, err := st.GetChatSession(ctx, "bob@example.com", sAlice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob GetChatSession(alice) = %v, want ErrNotFound", err)
	}
	if _, err := st.UpdateChatSession(ctx, "bob@example.com", ChatSession{ID: sAlice.ID, Title: "Hijacked"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob UpdateChatSession(alice) = %v, want ErrNotFound", err)
	}
	if _, err := st.InsertChatMessage(ctx, "bob@example.com", ChatMessage{SessionID: sAlice.ID, Role: "user", Content: "spoof"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob InsertChatMessage(alice) = %v, want ErrNotFound", err)
	}
	if _, err := st.ListChatMessages(ctx, "bob@example.com", sAlice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob ListChatMessages(alice) = %v, want ErrNotFound", err)
	}
	if err := st.DeleteChatSession(ctx, "bob@example.com", sAlice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob DeleteChatSession(alice) = %v, want ErrNotFound", err)
	}

	// Alice updates her session and inserts user + assistant messages with tool events.
	updatedAlice, err := st.UpdateChatSession(ctx, "alice@example.com", ChatSession{
		ID:           sAlice.ID,
		Title:        "Debug Headscale Grants",
		Model:        "anthropic/claude-sonnet-4-6",
		MCPServers:   []string{"docs"},
		SystemPrompt: "Be super concise.",
	})
	if err != nil || updatedAlice.Title != "Debug Headscale Grants" {
		t.Fatalf("UpdateChatSession(alice) = (%+v, %v)", updatedAlice, err)
	}

	if _, err := st.InsertChatMessage(ctx, "alice@example.com", ChatMessage{
		SessionID: sAlice.ID,
		Role:      "user",
		Content:   "Check docs for grants",
	}); err != nil {
		t.Fatalf("InsertChatMessage(user): %v", err)
	}
	if _, err := st.InsertChatMessage(ctx, "alice@example.com", ChatMessage{
		SessionID: sAlice.ID,
		Role:      "assistant",
		Content:   "Use headlamp.dev/cap/gateway.",
		Model:     "claude-sonnet-4-6",
		ToolEvents: []ChatToolEvent{{
			ID:         "tc-1",
			Server:     "docs",
			Tool:       "search",
			Arguments:  json.RawMessage(`{"q":"grants"}`),
			Result:     "Found 1 result",
			IsError:    false,
			DurationMS: 38,
		}},
		InputTokens:  120,
		OutputTokens: 45,
		CostUSD:      0.0012,
	}); err != nil {
		t.Fatalf("InsertChatMessage(assistant): %v", err)
	}

	msgs, err := st.ListChatMessages(ctx, "alice@example.com", sAlice.ID)
	if err != nil || len(msgs) != 2 || msgs[0].Role != "user" || msgs[1].Role != "assistant" ||
		len(msgs[1].ToolEvents) != 1 || msgs[1].ToolEvents[0].Tool != "search" || string(msgs[1].ToolEvents[0].Arguments) != `{"q":"grants"}` {
		t.Fatalf("ListChatMessages(alice) = (%+v, %v)", msgs, err)
	}

	aliceList, err := st.ListChatSessions(ctx, "alice@example.com", 20, 0)
	if err != nil || len(aliceList) != 1 || aliceList[0].ID != sAlice.ID {
		t.Fatalf("ListChatSessions(alice) = (%+v, %v)", aliceList, err)
	}
	bobList, err := st.ListChatSessions(ctx, "bob@example.com", 20, 0)
	if err != nil || len(bobList) != 1 || bobList[0].ID != sBob.ID {
		t.Fatalf("ListChatSessions(bob) = (%+v, %v)", bobList, err)
	}

	// Delete Alice's session -> chat_messages cascade deleted.
	if err := st.DeleteChatSession(ctx, "alice@example.com", sAlice.ID); err != nil {
		t.Fatalf("DeleteChatSession(alice): %v", err)
	}
	var orphanMsgs int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM chat_messages WHERE session_id = ?`, sAlice.ID).Scan(&orphanMsgs); err != nil {
		t.Fatalf("count orphan chat_messages: %v", err)
	}
	if orphanMsgs != 0 {
		t.Fatalf("expected cascade delete of chat_messages, found %d remaining", orphanMsgs)
	}
}

func TestSQLiteFixedWidthTimestampsMidnightComparison(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	dayStart := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	midSec := time.Date(2026, 11, 27, 0, 0, 0, 500_000_000, time.UTC)
	beforeMidnight := dayStart.Add(-time.Nanosecond)

	if got := formatTime(dayStart); got != "2026-11-27T00:00:00.000000000Z" {
		t.Fatalf("formatTime(dayStart) = %q, want fixed 9-digit nanoseconds", got)
	}
	if got := formatTime(midSec); got != "2026-11-27T00:00:00.500000000Z" {
		t.Fatalf("formatTime(midSec) = %q, want fixed 9-digit nanoseconds", got)
	}
	if !(formatTime(midSec) >= formatTime(dayStart)) {
		t.Fatalf("expected lexical comparison %q >= %q to be true", formatTime(midSec), formatTime(dayStart))
	}

	// parseTime must remain backward-compatible with legacy RFC3339 and variable-width RFC3339Nano.
	if got := parseTime("2026-11-27T00:00:00Z"); !got.Equal(dayStart) {
		t.Fatalf("parseTime(RFC3339) = %v, want %v", got, dayStart)
	}
	if got := parseTime("2026-11-27T00:00:00.5Z"); !got.Equal(midSec) {
		t.Fatalf("parseTime(RFC3339Nano) = %v, want %v", got, midSec)
	}
	if got := parseTime(formatTime(midSec)); !got.Equal(midSec) {
		t.Fatalf("parseTime(fixed) = %v, want %v", got, midSec)
	}

	for _, log := range []UsageLog{
		{ID: "u-prev", CreatedAt: beforeMidnight, Subject: "alice", ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 50, CostUSD: 0.01, StatusCode: 200},
		{ID: "u-zero", CreatedAt: dayStart, Subject: "alice", ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 100, CostUSD: 0.02, StatusCode: 200},
		{ID: "u-half", CreatedAt: midSec, Subject: "alice", ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 200, CostUSD: 0.03, StatusCode: 200},
	} {
		if err := st.InsertUsageLog(ctx, log); err != nil {
			t.Fatalf("InsertUsageLog(%s): %v", log.ID, err)
		}
	}

	sum, err := st.SummarizeUsage(ctx, UsageFilter{Subject: "alice", Since: dayStart})
	if err != nil {
		t.Fatalf("SummarizeUsage(Since=dayStart): %v", err)
	}
	if sum.RequestCount != 2 || sum.TotalTokens != 300 || math.Abs(sum.CostUSD-0.05) > 1e-9 {
		t.Fatalf("SummarizeUsage(Since=dayStart) = %+v, want 2 requests / 300 tokens / $0.05", sum)
	}

	// Same-second chat message ordering must keep .000000000Z before .200000000Z.
	sess, err := st.CreateChatSession(ctx, ChatSession{Subject: "alice", Title: "Order", Model: "gpt-5"})
	if err != nil {
		t.Fatalf("CreateChatSession: %v", err)
	}
	if _, err := st.InsertChatMessage(ctx, "alice", ChatMessage{
		ID: "msg-later", SessionID: sess.ID, Role: "assistant", Content: "second", CreatedAt: dayStart.Add(200 * time.Millisecond),
	}); err != nil {
		t.Fatalf("InsertChatMessage(later): %v", err)
	}
	if _, err := st.InsertChatMessage(ctx, "alice", ChatMessage{
		ID: "msg-exact", SessionID: sess.ID, Role: "user", Content: "first", CreatedAt: dayStart,
	}); err != nil {
		t.Fatalf("InsertChatMessage(exact): %v", err)
	}
	msgs, err := st.ListChatMessages(ctx, "alice", sess.ID)
	if err != nil || len(msgs) != 2 || msgs[0].ID != "msg-exact" || msgs[1].ID != "msg-later" {
		t.Fatalf("ListChatMessages same-second order = (%+v, %v), want [msg-exact, msg-later]", msgs, err)
	}
}

func TestDeleteChatMessageOwnershipAndRollback(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	sAlice, err := st.CreateChatSession(ctx, ChatSession{Subject: "alice", Title: "Alice", Model: "gpt-5"})
	if err != nil {
		t.Fatalf("CreateChatSession(alice): %v", err)
	}
	sBob, err := st.CreateChatSession(ctx, ChatSession{Subject: "bob", Title: "Bob", Model: "gpt-5"})
	if err != nil {
		t.Fatalf("CreateChatSession(bob): %v", err)
	}

	m1, err := st.InsertChatMessage(ctx, "alice", ChatMessage{SessionID: sAlice.ID, Role: "user", Content: "orphan-turn"})
	if err != nil {
		t.Fatalf("InsertChatMessage(m1): %v", err)
	}
	m2, err := st.InsertChatMessage(ctx, "alice", ChatMessage{SessionID: sAlice.ID, Role: "user", Content: "keep-turn"})
	if err != nil {
		t.Fatalf("InsertChatMessage(m2): %v", err)
	}

	// Cross-subject and wrong-session deletion must fail with ErrNotFound.
	if err := st.DeleteChatMessage(ctx, "bob", sAlice.ID, m1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob DeleteChatMessage(alice) = %v, want ErrNotFound", err)
	}
	if err := st.DeleteChatMessage(ctx, "alice", sBob.ID, m1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alice DeleteChatMessage(wrong session) = %v, want ErrNotFound", err)
	}
	if err := st.DeleteChatMessage(ctx, "alice", sAlice.ID, "missing-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alice DeleteChatMessage(missing) = %v, want ErrNotFound", err)
	}

	// Owner deletion succeeds and removes only the targeted message.
	if err := st.DeleteChatMessage(ctx, "alice", sAlice.ID, m1.ID); err != nil {
		t.Fatalf("alice DeleteChatMessage(m1): %v", err)
	}
	if err := st.DeleteChatMessage(ctx, "alice", sAlice.ID, m1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteChatMessage(m1) = %v, want ErrNotFound", err)
	}
	msgs, err := st.ListChatMessages(ctx, "alice", sAlice.ID)
	if err != nil || len(msgs) != 1 || msgs[0].ID != m2.ID {
		t.Fatalf("ListChatMessages after rollback = (%+v, %v), want only %s", msgs, err, m2.ID)
	}
}

func TestSyncConfigMCPAuthNoneClearsSecretAndIsolatesLocalToken(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	// 1. Seed config MCP server with bearer token, then switch to auth_type: none -> token must be cleared.
	cfgBearer, err := config.LoadFromBytes([]byte(`
mcp_servers:
  - name: docs
    url: "https://docs.internal/mcp"
    auth_type: bearer
    auth_token: "yaml-secret-token"
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfgBearer: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgBearer); err != nil {
		t.Fatalf("SyncConfig cfgBearer: %v", err)
	}
	got, err := st.GetMCPServer(ctx, "docs")
	if err != nil || got.AuthToken != "yaml-secret-token" {
		t.Fatalf("GetMCPServer(docs) = (%+v, %v)", got, err)
	}

	cfgNone, err := config.LoadFromBytes([]byte(`
mcp_servers:
  - name: docs
    url: "https://docs.internal/mcp"
    auth_type: none
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfgNone: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgNone); err != nil {
		t.Fatalf("SyncConfig cfgNone: %v", err)
	}
	gotNone, err := st.GetMCPServer(ctx, "docs")
	if err != nil || gotNone.AuthType != config.MCPAuthNone || gotNone.AuthToken != "" {
		t.Fatalf("expected cleared token when switching to auth_type=none, got (%+v, %v)", gotNone, err)
	}
	var rawEnc string
	if err := st.DB().QueryRowContext(ctx, `SELECT auth_token_enc FROM mcp_servers WHERE name = ?`, "docs").Scan(&rawEnc); err != nil {
		t.Fatalf("query raw auth_token_enc: %v", err)
	}
	if rawEnc != "" {
		t.Fatalf("expected empty auth_token_enc in DB when auth_type=none, got %q", rawEnc)
	}

	// 2. Existing source='local' server token MUST NOT be inherited when YAML takes over the same name without auth_token.
	if err := st.UpsertMCPServer(ctx, MCPServer{
		Name:      "shared-name",
		URL:       "https://local.internal/mcp",
		Transport: config.MCPTransportStreamableHTTP,
		AuthType:  config.MCPAuthBearer,
		AuthToken: "local-only-secret",
		Enabled:   true,
		Source:    SourceLocal,
	}); err != nil {
		t.Fatalf("UpsertMCPServer(shared-name): %v", err)
	}
	cfgTakeover, err := config.LoadFromBytes([]byte(`
mcp_servers:
  - name: shared-name
    url: "https://config.internal/mcp"
    auth_type: bearer
`))
	if err != nil {
		t.Fatalf("LoadFromBytes cfgTakeover: %v", err)
	}
	if err := st.SyncConfig(ctx, cfgTakeover); err != nil {
		t.Fatalf("SyncConfig cfgTakeover: %v", err)
	}
	taken, err := st.GetMCPServer(ctx, "shared-name")
	if err != nil || taken.Source != SourceConfig || taken.AuthToken != "" {
		t.Fatalf("expected source=config takeover NOT to inherit source=local token, got (%+v, %v)", taken, err)
	}
}

func TestPaginationTieBreakerAndExtendedSummaryTx(t *testing.T) {
	st, _ := newTestStore(t, ":memory:")
	ctx := context.Background()

	ts := time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC)
	for _, id := range []string{"id-a", "id-c", "id-b"} {
		if err := st.InsertUsageLog(ctx, UsageLog{
			ID: id, CreatedAt: ts, Subject: "alice", ProviderName: "openai",
			RequestedModel: "gpt-5", TotalTokens: 10, CostUSD: 0.01, LatencyMS: 100, StatusCode: 200,
		}); err != nil {
			t.Fatalf("InsertUsageLog(%s): %v", id, err)
		}
		if err := st.InsertMCPAuditLog(ctx, MCPAuditLog{
			ID: id, CreatedAt: ts, Subject: "alice", ServerName: "docs", Method: "tools/call", ToolName: "search", Status: "ok",
		}); err != nil {
			t.Fatalf("InsertMCPAuditLog(%s): %v", id, err)
		}
		if _, err := st.CreateChatSession(ctx, ChatSession{
			ID: id, Subject: "alice", Title: id, Model: "gpt-5", CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("CreateChatSession(%s): %v", id, err)
		}
	}

	wantOrder := []string{"id-c", "id-b", "id-a"}
	for i, wantID := range wantOrder {
		uPage, err := st.QueryUsageLogs(ctx, UsageFilter{Limit: 1, Offset: i})
		if err != nil || len(uPage) != 1 || uPage[0].ID != wantID {
			t.Fatalf("QueryUsageLogs page %d = (%+v, %v), want %s", i, uPage, err, wantID)
		}
		mPage, err := st.QueryMCPAuditLogs(ctx, MCPAuditFilter{Limit: 1, Offset: i})
		if err != nil || len(mPage) != 1 || mPage[0].ID != wantID {
			t.Fatalf("QueryMCPAuditLogs page %d = (%+v, %v), want %s", i, mPage, err, wantID)
		}
		cPage, err := st.ListChatSessions(ctx, "alice", 1, i)
		if err != nil || len(cPage) != 1 || cPage[0].ID != wantID {
			t.Fatalf("ListChatSessions page %d = (%+v, %v), want %s", i, cPage, err, wantID)
		}
	}

	ext, err := st.SummarizeUsageExtended(ctx, UsageFilter{Subject: "alice"})
	if err != nil || ext.RequestCount != 3 || ext.P95LatencyMS != 100 || math.Abs(ext.CostUSD-0.03) > 1e-9 {
		t.Fatalf("SummarizeUsageExtended = (%+v, %v)", ext, err)
	}
}
