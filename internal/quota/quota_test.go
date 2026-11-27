package quota

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/store"
)

func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	st, err := store.NewSQLiteStore(context.Background(), ":memory:", cipher)
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func floatPtr(v float64) *float64 { return &v }

func TestManager_RPMAndRetryAfter(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:   "alice@example.com",
		RPM:     2,
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	mgr := NewManager(st, WithNowFunc(func() time.Time { return now }))
	alice := &auth.Principal{Subject: "alice@example.com"}

	t1, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("req1 unexpected: rej=%+v err=%v", rej, err)
	}
	t1.Release(10)

	now = now.Add(10 * time.Second)
	t2, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("req2 unexpected: rej=%+v err=%v", rej, err)
	}
	t2.Release(10)

	// 3rd request within same minute must reject with RetryAfterSec ~50s.
	t3, rej, err := mgr.Acquire(ctx, alice)
	if err != nil {
		t.Fatalf("req3 error: %v", err)
	}
	if t3 != nil || rej == nil {
		t.Fatalf("expected RPM rejection on 3rd request, got ticket=%v rej=%+v", t3, rej)
	}
	if rej.Metric != MetricRPM || rej.Scope != "alice@example.com" {
		t.Errorf("unexpected rejection: %+v", rej)
	}
	if rej.RetryAfterSec < 49 || rej.RetryAfterSec > 51 {
		t.Errorf("RetryAfterSec = %d, want ~50", rej.RetryAfterSec)
	}

	// Advance past req1's 1-minute expiry -> allowed again.
	now = now.Add(51 * time.Second)
	t4, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("req4 after window slide failed: rej=%+v err=%v", rej, err)
	}
	t4.Release(0)
}

func TestManager_TPMAndIdempotentRelease(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:   "tag:ci-runner",
		TPM:     1000,
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	mgr := NewManager(st, WithNowFunc(func() time.Time { return now }))
	ci := &auth.Principal{Subject: "tag:ci-runner", Tags: []string{"tag:ci-runner"}}

	t1, rej, err := mgr.Acquire(ctx, ci)
	if err != nil || rej != nil {
		t.Fatalf("req1 failed: rej=%+v err=%v", rej, err)
	}
	// Release twice: second call must be a no-op (must NOT double-count 600 -> 1200).
	t1.Release(600)
	t1.Release(600)

	// Only 600 tokens recorded (< 1000), so req2 succeeds.
	t2, rej, err := mgr.Acquire(ctx, ci)
	if err != nil || rej != nil {
		t.Fatalf("req2 should succeed when 600/1000 TPM used: rej=%+v err=%v", rej, err)
	}
	t2.Release(500) // total 1100 >= 1000

	// req3 must be rejected for TPM.
	_, rej, err = mgr.Acquire(ctx, ci)
	if err != nil {
		t.Fatalf("req3 error: %v", err)
	}
	if rej == nil || rej.Metric != MetricTPM || rej.RetryAfterSec <= 0 {
		t.Fatalf("expected TPM rejection with RetryAfterSec>0, got %+v", rej)
	}

	// Advance 61s -> rolling window resets.
	now = now.Add(61 * time.Second)
	t4, rej, err := mgr.Acquire(ctx, ci)
	if err != nil || rej != nil {
		t.Fatalf("req4 after TPM window reset failed: rej=%+v err=%v", rej, err)
	}
	t4.Release(100)
}

func TestManager_MaxConcurrentAndAtomicMultiScopeRollback(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Global "*" allows 2 RPM & 2 concurrent; Alice allows only 1 concurrent.
	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:         "*",
		RPM:           2,
		MaxConcurrent: 2,
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:         "alice@example.com",
		MaxConcurrent: 1,
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	mgr := NewManager(st, WithNowFunc(func() time.Time { return now }))

	alice := &auth.Principal{Subject: "alice@example.com"}
	bob := &auth.Principal{Subject: "bob@example.com"}

	// Alice takes slot #1 globally and slot #1 for Alice.
	tAlice1, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("alice req1 failed: rej=%+v err=%v", rej, err)
	}

	// Alice's 2nd concurrent request is rejected by Alice's scope; MUST NOT consume global RPM or global concurrency.
	_, rej, err = mgr.Acquire(ctx, alice)
	if err != nil || rej == nil || rej.Metric != MetricMaxConcurrent || rej.Scope != "alice@example.com" {
		t.Fatalf("expected alice max_concurrent rejection, got rej=%+v err=%v", rej, err)
	}

	// Bob must still be able to use global RPM slot #2 and global concurrency slot #2!
	tBob1, rej, err := mgr.Acquire(ctx, bob)
	if err != nil || rej != nil {
		t.Fatalf("bob req1 should succeed (global slots must not leak on alice rejection): rej=%+v err=%v", rej, err)
	}

	// Releasing Alice's ticket frees her slot cleanly (and calling Release twice is safe).
	tAlice1.Release(0)
	tAlice1.Release(0)
	tBob1.Release(0)
}

func TestManager_SpendBudgetsSeedingLiveUpdatesAlertsAndRollover(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Date(2026, 11, 27, 14, 0, 0, 0, time.UTC)

	// Seed SQLite with:
	// - $3.00 today for alice (tag:eng)
	// - $12.00 earlier this month (Nov 10) for alice (tag:eng)
	// - $99.00 previous month (Oct 15) for alice (must NOT count toward Nov!)
	seedLogs := []store.UsageLog{
		{
			ID: "u-today", CreatedAt: time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC),
			RequestID: "r1", Subject: "alice@example.com", Tags: []string{"tag:eng"},
			ProviderName: "openai", ProviderType: "openai", RequestedModel: "gpt-5", UpstreamModel: "gpt-5",
			Protocol: "openai_chat", Endpoint: "/v1/chat/completions", CostUSD: 3.00, StatusCode: 200,
		},
		{
			ID: "u-month", CreatedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
			RequestID: "r2", Subject: "alice@example.com", Tags: []string{"tag:eng"},
			ProviderName: "openai", ProviderType: "openai", RequestedModel: "gpt-5", UpstreamModel: "gpt-5",
			Protocol: "openai_chat", Endpoint: "/v1/chat/completions", CostUSD: 12.00, StatusCode: 200,
		},
		{
			ID: "u-prev-month", CreatedAt: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC),
			RequestID: "r3", Subject: "alice@example.com", Tags: []string{"tag:eng"},
			ProviderName: "openai", ProviderType: "openai", RequestedModel: "gpt-5", UpstreamModel: "gpt-5",
			Protocol: "openai_chat", Endpoint: "/v1/chat/completions", CostUSD: 99.00, StatusCode: 200,
		},
	}
	for _, l := range seedLogs {
		if err := st.InsertUsageLog(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	// Configure global, tag, and user budgets.
	budgets := []store.Budget{
		{Scope: "*", MonthlyUSD: floatPtr(100.0), SoftAlertPct: 80, Enabled: true},
		{Scope: "tag:eng", DailyUSD: floatPtr(10.0), SoftAlertPct: 80, Enabled: true},
		{Scope: "alice@example.com", DailyUSD: floatPtr(5.0), MonthlyUSD: floatPtr(20.0), SoftAlertPct: 80, Enabled: true},
	}
	for _, b := range budgets {
		if err := st.UpsertBudget(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	var (
		alertMu sync.Mutex
		alerts  []AlertEvent
	)
	mgr := NewManager(st,
		WithNowFunc(func() time.Time { return now }),
		WithOnAlert(func(ev AlertEvent) {
			alertMu.Lock()
			alerts = append(alerts, ev)
			alertMu.Unlock()
		}),
	)

	alice := &auth.Principal{Subject: "alice@example.com", Tags: []string{"tag:eng"}}

	// Verify lazy seeding via StatusForPrincipal.
	statuses, err := mgr.StatusForPrincipal(ctx, alice)
	if err != nil {
		t.Fatalf("StatusForPrincipal: %v", err)
	}
	if len(statuses) != 3 {
		t.Fatalf("expected 3 matching scope statuses (*, tag:eng, alice), got %d", len(statuses))
	}
	aliceStatus := statuses[2]
	if aliceStatus.Scope != "alice@example.com" {
		t.Fatalf("expected alice scope at index 2, got %q", aliceStatus.Scope)
	}
	if math.Abs(aliceStatus.DailySpentUSD-3.00) > 1e-6 || math.Abs(aliceStatus.MonthlySpentUSD-15.00) > 1e-6 {
		t.Fatalf("seeded spend = (daily=%.4f, monthly=%.4f), want (3.00, 15.00)", aliceStatus.DailySpentUSD, aliceStatus.MonthlySpentUSD)
	}

	// Record +$1.10 -> daily $4.10 (82% >= 80%), monthly $16.10 (80.5% >= 80%): fires daily + monthly threshold alerts ONCE.
	record := func(id string, cost float64) {
		log := store.UsageLog{
			ID: id, CreatedAt: now, RequestID: id,
			Subject: "alice@example.com", Tags: []string{"tag:eng"},
			ProviderName: "openai", ProviderType: "openai", RequestedModel: "gpt-5", UpstreamModel: "gpt-5",
			Protocol: "openai_chat", Endpoint: "/v1/chat/completions", CostUSD: cost, StatusCode: 200,
		}
		if err := st.InsertUsageLog(ctx, log); err != nil {
			t.Fatal(err)
		}
		mgr.OnUsageRecorded(log)
	}

	record("u-live-1", 1.10)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 threshold alerts (daily + monthly for alice), got %+v", alerts)
	}
	for _, a := range alerts {
		if a.EventType != config.WebhookEventBudgetThreshold || a.Scope != "alice@example.com" {
			t.Errorf("unexpected threshold alert: %+v", a)
		}
	}

	// Record +$0.20 -> daily $4.30 (86%), monthly $16.30 (81.5%): threshold alerts MUST be deduplicated (still 2 total).
	record("u-live-2", 0.20)
	if len(alerts) != 2 {
		t.Fatalf("expected threshold alerts deduplicated (still 2), got %d: %+v", len(alerts), alerts)
	}

	// Record +$0.80 -> daily $5.10 (102% >= 100%): fires daily budget.exceeded ONCE.
	record("u-live-3", 0.80)
	if len(alerts) != 3 || alerts[2].EventType != config.WebhookEventBudgetExceeded || alerts[2].Window != WindowDaily {
		t.Fatalf("expected daily budget.exceeded alert #3, got %+v", alerts)
	}

	// Acquire must now reject with MetricDailyUSD and NOT emit a duplicate budget.exceeded alert.
	_, rej, err := mgr.Acquire(ctx, alice)
	if err != nil {
		t.Fatalf("Acquire error: %v", err)
	}
	if rej == nil || rej.Metric != MetricDailyUSD || rej.Scope != "alice@example.com" || rej.RetryAfterSec <= 0 {
		t.Fatalf("expected daily_usd rejection, got %+v", rej)
	}
	if len(alerts) != 3 {
		t.Fatalf("expected no duplicate budget.exceeded on Acquire, got %d alerts", len(alerts))
	}

	// Advance to next UTC day (2026-11-28 00:05): daily spend resets to $0 while monthly spend stays $17.10.
	now = time.Date(2026, 11, 28, 0, 5, 0, 0, time.UTC)
	ticket, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("Acquire after UTC day rollover failed: rej=%+v err=%v", rej, err)
	}
	ticket.Release(0)

	// Push monthly spend over $20.00 ($17.10 + $3.10 = $20.20) while daily stays under $5.00 ($3.10).
	record("u-next-day", 3.10)
	_, rej, err = mgr.Acquire(ctx, alice)
	if err != nil {
		t.Fatalf("Acquire monthly check error: %v", err)
	}
	if rej == nil || rej.Metric != MetricMonthlyUSD || rej.Scope != "alice@example.com" {
		t.Fatalf("expected monthly_usd rejection, got %+v", rej)
	}
}

func TestManager_DisabledBudgetAndConcurrencyRace(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:    "alice@example.com",
		RPM:      1,
		DailyUSD: floatPtr(0.0),
		Enabled:  false, // disabled must not block
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:         "*",
		RPM:           1000,
		TPM:           1_000_000,
		MaxConcurrent: 50,
		DailyUSD:      floatPtr(500.0),
		SoftAlertPct:  80,
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}

	mgr := NewManager(st)
	alice := &auth.Principal{Subject: "alice@example.com"}

	// Disabled budget excluded from StatusForPrincipal, included in ListAllStatuses.
	userStatuses, err := mgr.StatusForPrincipal(ctx, alice)
	if err != nil || len(userStatuses) != 1 || userStatuses[0].Scope != "*" {
		t.Fatalf("StatusForPrincipal = %+v (err=%v), want only enabled '*'", userStatuses, err)
	}
	allStatuses, err := mgr.ListAllStatuses(ctx)
	if err != nil || len(allStatuses) != 2 {
		t.Fatalf("ListAllStatuses = %+v (err=%v), want 2", allStatuses, err)
	}

	// Concurrent stress test under -race.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				tk, rej, err := mgr.Acquire(ctx, alice)
				if err != nil || rej != nil {
					t.Errorf("concurrent Acquire failed: rej=%+v err=%v", rej, err)
					return
				}
				mgr.OnUsageRecorded(store.UsageLog{
					CreatedAt: time.Now().UTC(),
					Subject:   "alice@example.com",
					CostUSD:   0.01,
				})
				tk.Release(25)
			}
		}()
	}
	wg.Wait()
}

func TestManager_NoDoubleCountBetweenSQLiteSeedAndOnUsageRecorded(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:        "alice@example.com",
		DailyUSD:     floatPtr(5.0),
		MonthlyUSD:   floatPtr(20.0),
		SoftAlertPct: 80,
		Enabled:      true,
	}); err != nil {
		t.Fatal(err)
	}

	mgr := NewManager(st, WithNowFunc(func() time.Time { return now }))
	alice := &auth.Principal{Subject: "alice@example.com"}

	// Simulate exact Recorder race:
	// 1. Recorder commits InsertUsageLog($3.00) to SQLite.
	logRow := store.UsageLog{
		ID: "u-race-1", CreatedAt: now, RequestID: "req-race-1",
		Subject: "alice@example.com", ProviderName: "openai", ProviderType: "openai",
		RequestedModel: "gpt-5", UpstreamModel: "gpt-5", Protocol: "openai_chat",
		Endpoint: "/v1/chat/completions", CostUSD: 3.00, StatusCode: 200,
	}
	if err := st.InsertUsageLog(ctx, logRow); err != nil {
		t.Fatal(err)
	}

	// 2. Concurrent Acquire seeds from SQLite BEFORE OnUsageRecorded fires (seeing $3.00).
	tk, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("Acquire expected allow at $3/$5, got rej=%+v err=%v", rej, err)
	}
	tk.Release(0)

	// 3. Recorder now invokes OnUsageRecorded for that same row — MUST NOT double-count to $6.00!
	mgr.OnUsageRecorded(logRow)

	statuses, err := mgr.StatusForPrincipal(ctx, alice)
	if err != nil || len(statuses) != 1 {
		t.Fatalf("StatusForPrincipal = %+v (err=%v)", statuses, err)
	}
	if math.Abs(statuses[0].DailySpentUSD-3.00) > 1e-6 || math.Abs(statuses[0].MonthlySpentUSD-3.00) > 1e-6 {
		t.Fatalf("double-counted spend! got (daily=%.4f, monthly=%.4f), want (3.00, 3.00)",
			statuses[0].DailySpentUSD, statuses[0].MonthlySpentUSD)
	}

	// Next Acquire must still succeed ($3.00 < $5.00), not falsely reject as $6.00 >= $5.00.
	tk2, rej, err := mgr.Acquire(ctx, alice)
	if err != nil || rej != nil {
		t.Fatalf("Acquire after OnUsageRecorded falsely rejected: rej=%+v err=%v", rej, err)
	}
	tk2.Release(0)
}

func TestManager_AlertMapBoundedAcrossDayRollovers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:        "alice@example.com",
		DailyUSD:     floatPtr(1.0),
		SoftAlertPct: 80,
		Enabled:      true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var alertCount int
	mgr := NewManager(st,
		WithNowFunc(func() time.Time { return now }),
		WithOnAlert(func(AlertEvent) { alertCount++ }),
	)

	// Cross threshold across 5 consecutive UTC days; alerts fire once per day while m.alerts stays O(1).
	for day := 1; day <= 5; day++ {
		now = time.Date(2026, 11, day, 12, 0, 0, 0, time.UTC)
		row := store.UsageLog{
			ID: "u-day-" + now.Format("02"), CreatedAt: now, RequestID: "r-" + now.Format("02"),
			Subject: "alice@example.com", ProviderName: "openai", ProviderType: "openai",
			RequestedModel: "gpt-5", UpstreamModel: "gpt-5", Protocol: "openai_chat",
			Endpoint: "/v1/chat/completions", CostUSD: 0.90, StatusCode: 200,
		}
		if err := st.InsertUsageLog(ctx, row); err != nil {
			t.Fatal(err)
		}
		mgr.OnUsageRecorded(row)
	}

	if alertCount != 5 {
		t.Fatalf("alertCount = %d, want 5 (1 per UTC day)", alertCount)
	}
	mgr.mu.Lock()
	mapLen := len(mgr.alerts)
	mgr.mu.Unlock()
	if mapLen != 1 {
		t.Fatalf("expected bounded alert map size 1 after 5 day rollovers, got %d", mapLen)
	}
}
