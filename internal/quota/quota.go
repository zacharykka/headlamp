package quota

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	MetricRPM           = "rpm"
	MetricTPM           = "tpm"
	MetricMaxConcurrent = "max_concurrent"
	MetricDailyUSD      = "daily_usd"
	MetricMonthlyUSD    = "monthly_usd"

	WindowDaily   = "daily"
	WindowMonthly = "monthly"
)

// Rejection describes why Acquire denied a request under an active budget rule.
type Rejection struct {
	Scope         string `json:"scope"`
	Metric        string `json:"metric"`
	Reason        string `json:"reason"`
	RetryAfterSec int    `json:"retry_after_sec"`
}

// AlertEvent is emitted when spend crosses SoftAlertPct or reaches 100% of a DailyUSD/MonthlyUSD cap.
type AlertEvent struct {
	EventType string    `json:"event_type"` // config.WebhookEventBudgetThreshold | config.WebhookEventBudgetExceeded
	Scope     string    `json:"scope"`
	Subject   string    `json:"subject"`
	Window    string    `json:"window"` // "daily" | "monthly"
	LimitUSD  float64   `json:"limit_usd"`
	SpentUSD  float64   `json:"spent_usd"`
	Pct       float64   `json:"pct"`
	Timestamp time.Time `json:"timestamp"`
}

// ScopeStatus reports a budget rule alongside live UTC daily and monthly spend.
// JSON tags align 1:1 with /api/v1/me and /api/v1/admin/budgets contracts.
type ScopeStatus struct {
	Scope           string    `json:"scope"`
	RPM             int       `json:"rpm"`
	TPM             int64     `json:"tpm"`
	MaxConcurrent   int       `json:"max_concurrent"`
	DailyUSD        *float64  `json:"daily_usd"`
	DailySpentUSD   float64   `json:"daily_spent_usd"`
	MonthlyUSD      *float64  `json:"monthly_usd"`
	MonthlySpentUSD float64   `json:"monthly_spent_usd"`
	SoftAlertPct    int       `json:"soft_alert_pct"`
	Enabled         bool      `json:"enabled"`
	Source          string    `json:"source"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Ticket represents acquired concurrency and rate slots for an in-flight request.
// Release must be called when the request finishes; it is safe and idempotent.
type Ticket struct {
	once   sync.Once
	mgr    *Manager
	scopes []acquiredScope
}

type acquiredScope struct {
	scope            string
	trackConcurrency bool
}

// Release decrements in-flight concurrency counters and records totalTokens against
// the rolling 1-minute TPM windows for every scope acquired by this ticket.
func (t *Ticket) Release(totalTokens int64) {
	if t == nil || t.mgr == nil {
		return
	}
	t.once.Do(func() {
		t.mgr.release(t.scopes, totalTokens)
	})
}

// Option customizes a Manager instance.
type Option func(*Manager)

// WithOnAlert registers a callback invoked asynchronously-safe (outside Manager locks)
// whenever a scope crosses its soft alert threshold or exceeds a daily/monthly USD limit.
func WithOnAlert(fn func(AlertEvent)) Option {
	return func(m *Manager) {
		m.onAlert = fn
	}
}

// WithNowFunc overrides the wall clock used for sliding windows and UTC day/month boundaries.
func WithNowFunc(fn func() time.Time) Option {
	return func(m *Manager) {
		if fn != nil {
			m.now = fn
		}
	}
}

type tokenSample struct {
	at     time.Time
	tokens int64
}

type alertKey struct {
	eventType string
	scope     string
	window    string
}

type scopeState struct {
	reqTimes     []time.Time
	tokenSamples []tokenSample
	tokenSum     int64
	inFlight     int

	dayKey     string
	dayValid   bool
	dayGen     uint64
	daySpent   float64
	monthKey   string
	monthValid bool
	monthGen   uint64
	monthSpent float64
}

// Manager enforces RPM, TPM, MaxConcurrent, DailyUSD, and MonthlyUSD budgets across
// global ("*"), node tag ("tag:<name>"), and user subject scopes.
type Manager struct {
	store   store.Store
	onAlert func(AlertEvent)
	now     func() time.Time

	mu     sync.Mutex
	states map[string]*scopeState
	alerts map[alertKey]string // maps (eventType, scope, window) -> last alerted windowKey (bounded size)
}

// NewManager creates a quota Manager backed by store.Store.
func NewManager(st store.Store, opts ...Option) *Manager {
	m := &Manager{
		store:  st,
		now:    time.Now,
		states: make(map[string]*scopeState),
		alerts: make(map[alertKey]string),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

// Acquire evaluates all enabled budgets matching p (Global "*", matched "tag:*", and User Subject).
// Checks are two-phase atomic: if any applicable scope rejects, no concurrency slot or RPM entry
// is consumed on any other scope.
func (m *Manager) Acquire(ctx context.Context, p *auth.Principal) (*Ticket, *Rejection, error) {
	if m == nil || m.store == nil || p == nil {
		return &Ticket{}, nil, nil
	}

	allBudgets, err := m.store.ListBudgets(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("quota: list budgets: %w", err)
	}
	applicable := matchingBudgets(allBudgets, p, true)
	if len(applicable) == 0 {
		return &Ticket{}, nil, nil
	}

	now := m.now().UTC()
	dayKey, dayStart, dayReset := utcDayWindow(now)
	monthKey, monthStart, monthReset := utcMonthWindow(now)

	// Lazily seed daily/monthly spend for any scope with USD limits before acquiring m.mu.
	for _, b := range applicable {
		if b.DailyUSD != nil {
			if err := m.ensureDaySeeded(ctx, b.Scope, dayKey, dayStart); err != nil {
				return nil, nil, err
			}
		}
		if b.MonthlyUSD != nil {
			if err := m.ensureMonthSeeded(ctx, b.Scope, monthKey, monthStart); err != nil {
				return nil, nil, err
			}
		}
	}

	var (
		pendingAlerts []AlertEvent
		rejection     *Rejection
		acquired      []acquiredScope
	)

	m.mu.Lock()
	// Phase 1: check every applicable scope without mutating counters.
	for _, b := range applicable {
		st := m.stateLocked(b.Scope)
		m.rolloverSpendLocked(st, dayKey, monthKey)
		pruneRequests(st, now)
		pruneTokens(st, now)

		if b.DailyUSD != nil && st.daySpent >= *b.DailyUSD {
			limit := *b.DailyUSD
			pct := spendPct(st.daySpent, limit)
			if ev, ok := m.recordAlertLocked(config.WebhookEventBudgetExceeded, b.Scope, p.Subject, WindowDaily, dayKey, limit, st.daySpent, pct, now); ok {
				pendingAlerts = append(pendingAlerts, ev)
			}
			rejection = &Rejection{
				Scope:         b.Scope,
				Metric:        MetricDailyUSD,
				Reason:        fmt.Sprintf("daily budget exceeded for scope %q ($%.4f / $%.4f)", b.Scope, st.daySpent, limit),
				RetryAfterSec: secondsUntil(now, dayReset),
			}
			break
		}

		if b.MonthlyUSD != nil && st.monthSpent >= *b.MonthlyUSD {
			limit := *b.MonthlyUSD
			pct := spendPct(st.monthSpent, limit)
			if ev, ok := m.recordAlertLocked(config.WebhookEventBudgetExceeded, b.Scope, p.Subject, WindowMonthly, monthKey, limit, st.monthSpent, pct, now); ok {
				pendingAlerts = append(pendingAlerts, ev)
			}
			rejection = &Rejection{
				Scope:         b.Scope,
				Metric:        MetricMonthlyUSD,
				Reason:        fmt.Sprintf("monthly budget exceeded for scope %q ($%.4f / $%.4f)", b.Scope, st.monthSpent, limit),
				RetryAfterSec: secondsUntil(now, monthReset),
			}
			break
		}

		if b.MaxConcurrent > 0 && st.inFlight >= b.MaxConcurrent {
			rejection = &Rejection{
				Scope:         b.Scope,
				Metric:        MetricMaxConcurrent,
				Reason:        fmt.Sprintf("max concurrent requests (%d) reached for scope %q", b.MaxConcurrent, b.Scope),
				RetryAfterSec: 1,
			}
			break
		}

		if b.RPM > 0 && len(st.reqTimes) >= b.RPM {
			retryAfter := 1
			if len(st.reqTimes) > 0 {
				retryAfter = secondsUntil(now, st.reqTimes[0].Add(time.Minute))
			}
			rejection = &Rejection{
				Scope:         b.Scope,
				Metric:        MetricRPM,
				Reason:        fmt.Sprintf("rate limit (%d RPM) exceeded for scope %q", b.RPM, b.Scope),
				RetryAfterSec: retryAfter,
			}
			break
		}

		if b.TPM > 0 && st.tokenSum >= b.TPM {
			retryAfter := 1
			if len(st.tokenSamples) > 0 {
				retryAfter = secondsUntil(now, st.tokenSamples[0].at.Add(time.Minute))
			}
			rejection = &Rejection{
				Scope:         b.Scope,
				Metric:        MetricTPM,
				Reason:        fmt.Sprintf("token rate limit (%d TPM) exceeded for scope %q", b.TPM, b.Scope),
				RetryAfterSec: retryAfter,
			}
			break
		}
	}

	// Phase 2: commit all scope acquisitions only when all checks passed.
	if rejection == nil {
		acquired = make([]acquiredScope, 0, len(applicable))
		for _, b := range applicable {
			st := m.stateLocked(b.Scope)
			if b.RPM > 0 {
				st.reqTimes = append(st.reqTimes, now)
			}
			trackConc := b.MaxConcurrent > 0
			if trackConc {
				st.inFlight++
			}
			acquired = append(acquired, acquiredScope{
				scope:            b.Scope,
				trackConcurrency: trackConc,
			})
		}
	}
	m.mu.Unlock()

	m.dispatchAlerts(pendingAlerts)

	if rejection != nil {
		return nil, rejection, nil
	}
	return &Ticket{
		mgr:    m,
		scopes: acquired,
	}, nil, nil
}

func (m *Manager) release(scopes []acquiredScope, totalTokens int64) {
	if len(scopes) == 0 {
		return
	}
	now := m.now().UTC()

	m.mu.Lock()
	for _, acq := range scopes {
		st := m.stateLocked(acq.scope)
		if acq.trackConcurrency && st.inFlight > 0 {
			st.inFlight--
		}
		if totalTokens > 0 {
			pruneTokens(st, now)
			st.tokenSamples = append(st.tokenSamples, tokenSample{at: now, tokens: totalTokens})
			st.tokenSum += totalTokens
		}
	}
	m.mu.Unlock()
}

// OnUsageRecorded invalidates cached UTC daily/monthly spend for scopes affected by log
// (preventing double-counting between SQLite SummarizeUsage seeding and live callbacks) and
// refreshes spend to emit deduplicated soft threshold / hard exceeded alerts.
// Wire directly into metering.WithOnRecorded (invoked after InsertUsageLog commits).
func (m *Manager) OnUsageRecorded(log store.UsageLog) {
	if m == nil || log.CostUSD <= 0 {
		return
	}

	now := m.now().UTC()
	ts := log.CreatedAt.UTC()
	if ts.IsZero() {
		ts = now
	}
	logDayKey, _, _ := utcDayWindow(ts)
	logMonthKey, _, _ := utcMonthWindow(ts)
	curDayKey, dayStart, _ := utcDayWindow(now)
	curMonthKey, monthStart, _ := utcMonthWindow(now)

	scopes := scopesForUsageLog(log)

	// Invalidate cached spend using generation counters so SQLite remains the single source of truth
	// and concurrent seed/refresh calls can never double-count a just-committed row.
	m.mu.Lock()
	for _, scope := range scopes {
		st, ok := m.states[scope]
		if !ok {
			continue
		}
		if logDayKey == curDayKey && st.dayKey == curDayKey {
			st.dayGen++
			st.dayValid = false
		}
		if logMonthKey == curMonthKey && st.monthKey == curMonthKey {
			st.monthGen++
			st.monthValid = false
		}
	}
	m.mu.Unlock()

	if m.store == nil || m.onAlert == nil {
		return
	}

	allBudgets, err := m.store.ListBudgets(context.Background())
	if err != nil {
		return
	}
	applicable := matchingBudgetsByScopes(allBudgets, scopes, true)
	if len(applicable) == 0 {
		return
	}

	// Refresh authoritative spend from SQLite so threshold/exceeded alerts fire accurately.
	ctx := context.Background()
	for _, b := range applicable {
		if b.DailyUSD != nil && logDayKey == curDayKey {
			_ = m.ensureDaySeeded(ctx, b.Scope, curDayKey, dayStart)
		}
		if b.MonthlyUSD != nil && logMonthKey == curMonthKey {
			_ = m.ensureMonthSeeded(ctx, b.Scope, curMonthKey, monthStart)
		}
	}

	var pendingAlerts []AlertEvent
	m.mu.Lock()
	for _, b := range applicable {
		st := m.stateLocked(b.Scope)
		m.rolloverSpendLocked(st, curDayKey, curMonthKey)
		softPct := b.SoftAlertPct
		if softPct <= 0 {
			softPct = 80
		}

		if b.DailyUSD != nil && *b.DailyUSD > 0 && logDayKey == curDayKey {
			pendingAlerts = append(pendingAlerts, m.evaluateSpendAlertsLocked(b.Scope, log.Subject, WindowDaily, curDayKey, *b.DailyUSD, st.daySpent, softPct, now)...)
		}
		if b.MonthlyUSD != nil && *b.MonthlyUSD > 0 && logMonthKey == curMonthKey {
			pendingAlerts = append(pendingAlerts, m.evaluateSpendAlertsLocked(b.Scope, log.Subject, WindowMonthly, curMonthKey, *b.MonthlyUSD, st.monthSpent, softPct, now)...)
		}
	}
	m.mu.Unlock()

	m.dispatchAlerts(pendingAlerts)
}

// StatusForPrincipal returns live budget status for every enabled budget applicable to p.
func (m *Manager) StatusForPrincipal(ctx context.Context, p *auth.Principal) ([]ScopeStatus, error) {
	if m == nil || m.store == nil || p == nil {
		return []ScopeStatus{}, nil
	}
	allBudgets, err := m.store.ListBudgets(ctx)
	if err != nil {
		return nil, fmt.Errorf("quota: list budgets: %w", err)
	}
	applicable := matchingBudgets(allBudgets, p, true)
	return m.buildStatuses(ctx, applicable)
}

// ListAllStatuses returns live budget status for all configured budgets (for Admin UI).
func (m *Manager) ListAllStatuses(ctx context.Context) ([]ScopeStatus, error) {
	if m == nil || m.store == nil {
		return []ScopeStatus{}, nil
	}
	allBudgets, err := m.store.ListBudgets(ctx)
	if err != nil {
		return nil, fmt.Errorf("quota: list budgets: %w", err)
	}
	return m.buildStatuses(ctx, allBudgets)
}

func (m *Manager) buildStatuses(ctx context.Context, budgets []store.Budget) ([]ScopeStatus, error) {
	if len(budgets) == 0 {
		return []ScopeStatus{}, nil
	}
	now := m.now().UTC()
	dayKey, dayStart, _ := utcDayWindow(now)
	monthKey, monthStart, _ := utcMonthWindow(now)

	out := make([]ScopeStatus, 0, len(budgets))
	for _, b := range budgets {
		if err := m.ensureDaySeeded(ctx, b.Scope, dayKey, dayStart); err != nil {
			return nil, err
		}
		if err := m.ensureMonthSeeded(ctx, b.Scope, monthKey, monthStart); err != nil {
			return nil, err
		}

		m.mu.Lock()
		st := m.stateLocked(b.Scope)
		m.rolloverSpendLocked(st, dayKey, monthKey)
		daySpent := st.daySpent
		monthSpent := st.monthSpent
		m.mu.Unlock()

		out = append(out, ScopeStatus{
			Scope:           b.Scope,
			RPM:             b.RPM,
			TPM:             b.TPM,
			MaxConcurrent:   b.MaxConcurrent,
			DailyUSD:        cloneFloatPtr(b.DailyUSD),
			DailySpentUSD:   daySpent,
			MonthlyUSD:      cloneFloatPtr(b.MonthlyUSD),
			MonthlySpentUSD: monthSpent,
			SoftAlertPct:    b.SoftAlertPct,
			Enabled:         b.Enabled,
			Source:          b.Source,
			UpdatedAt:       b.UpdatedAt,
		})
	}
	return out, nil
}

func (m *Manager) ensureDaySeeded(ctx context.Context, scope, dayKey string, dayStart time.Time) error {
	for attempt := 0; attempt < 3; attempt++ {
		m.mu.Lock()
		st := m.stateLocked(scope)
		if st.dayKey != dayKey {
			st.dayKey = dayKey
			st.dayValid = false
			st.dayGen++
			st.daySpent = 0
		}
		if st.dayValid {
			m.mu.Unlock()
			return nil
		}
		gen := st.dayGen
		m.mu.Unlock()

		sum, err := m.store.SummarizeUsage(ctx, filterForScope(scope, dayStart))
		if err != nil {
			return fmt.Errorf("quota: seed daily spend for %q: %w", scope, err)
		}

		m.mu.Lock()
		st = m.stateLocked(scope)
		if st.dayKey != dayKey {
			m.mu.Unlock()
			continue
		}
		// Always store the freshest authoritative total so concurrent invalidations
		// can never leave daySpent stuck at 0.
		st.daySpent = sum.CostUSD
		if st.dayGen == gen {
			st.dayValid = true
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
	}
	return nil
}

func (m *Manager) ensureMonthSeeded(ctx context.Context, scope, monthKey string, monthStart time.Time) error {
	for attempt := 0; attempt < 3; attempt++ {
		m.mu.Lock()
		st := m.stateLocked(scope)
		if st.monthKey != monthKey {
			st.monthKey = monthKey
			st.monthValid = false
			st.monthGen++
			st.monthSpent = 0
		}
		if st.monthValid {
			m.mu.Unlock()
			return nil
		}
		gen := st.monthGen
		m.mu.Unlock()

		sum, err := m.store.SummarizeUsage(ctx, filterForScope(scope, monthStart))
		if err != nil {
			return fmt.Errorf("quota: seed monthly spend for %q: %w", scope, err)
		}

		m.mu.Lock()
		st = m.stateLocked(scope)
		if st.monthKey != monthKey {
			m.mu.Unlock()
			continue
		}
		st.monthSpent = sum.CostUSD
		if st.monthGen == gen {
			st.monthValid = true
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
	}
	return nil
}

func (m *Manager) stateLocked(scope string) *scopeState {
	st, ok := m.states[scope]
	if !ok {
		st = &scopeState{}
		m.states[scope] = st
	}
	return st
}

func (m *Manager) rolloverSpendLocked(st *scopeState, dayKey, monthKey string) {
	if st.dayKey != dayKey {
		st.dayKey = dayKey
		st.dayValid = false
		st.dayGen++
		st.daySpent = 0
	}
	if st.monthKey != monthKey {
		st.monthKey = monthKey
		st.monthValid = false
		st.monthGen++
		st.monthSpent = 0
	}
}

func (m *Manager) evaluateSpendAlertsLocked(scope, subject, window, windowKey string, limit, spent float64, softPct int, now time.Time) []AlertEvent {
	pct := spendPct(spent, limit)
	var out []AlertEvent

	// If an admin raised the budget limit so spend is back below softPct, allow fresh future alerts.
	if pct < float64(softPct) {
		delete(m.alerts, alertKey{eventType: config.WebhookEventBudgetThreshold, scope: scope, window: window})
		delete(m.alerts, alertKey{eventType: config.WebhookEventBudgetExceeded, scope: scope, window: window})
		return nil
	}

	if pct >= float64(softPct) {
		if ev, ok := m.recordAlertLocked(config.WebhookEventBudgetThreshold, scope, subject, window, windowKey, limit, spent, pct, now); ok {
			out = append(out, ev)
		}
	}
	if spent >= limit {
		if ev, ok := m.recordAlertLocked(config.WebhookEventBudgetExceeded, scope, subject, window, windowKey, limit, spent, pct, now); ok {
			out = append(out, ev)
		}
	}
	return out
}

func (m *Manager) recordAlertLocked(eventType, scope, subject, window, windowKey string, limit, spent, pct float64, now time.Time) (AlertEvent, bool) {
	key := alertKey{eventType: eventType, scope: scope, window: window}
	if prevWindow, seen := m.alerts[key]; seen && prevWindow == windowKey {
		return AlertEvent{}, false
	}
	// Overwriting the previous windowKey keeps m.alerts bounded to O(scopes) across rollovers.
	m.alerts[key] = windowKey
	return AlertEvent{
		EventType: eventType,
		Scope:     scope,
		Subject:   subject,
		Window:    window,
		LimitUSD:  limit,
		SpentUSD:  spent,
		Pct:       pct,
		Timestamp: now,
	}, true
}

func (m *Manager) dispatchAlerts(alerts []AlertEvent) {
	if m.onAlert == nil || len(alerts) == 0 {
		return
	}
	for _, ev := range alerts {
		m.onAlert(ev)
	}
}

func matchingBudgets(all []store.Budget, p *auth.Principal, onlyEnabled bool) []store.Budget {
	scopes := scopesForPrincipal(p)
	return matchingBudgetsByScopes(all, scopes, onlyEnabled)
}

func matchingBudgetsByScopes(all []store.Budget, scopes []string, onlyEnabled bool) []store.Budget {
	byScope := make(map[string]store.Budget, len(all))
	for _, b := range all {
		if onlyEnabled && !b.Enabled {
			continue
		}
		byScope[strings.TrimSpace(b.Scope)] = b
	}

	out := make([]store.Budget, 0, len(scopes))
	for _, scope := range scopes {
		if b, ok := byScope[scope]; ok {
			out = append(out, b)
		}
	}
	return out
}

func scopesForPrincipal(p *auth.Principal) []string {
	scopes := []string{"*"}
	tags := make([]string, 0, len(p.Tags))
	for _, tag := range p.Tags {
		if t := strings.TrimSpace(tag); t != "" && !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)
	for _, t := range tags {
		if !slices.Contains(scopes, t) {
			scopes = append(scopes, t)
		}
	}
	if subj := strings.TrimSpace(p.Subject); subj != "" && !slices.Contains(scopes, subj) {
		scopes = append(scopes, subj)
	}
	return scopes
}

func scopesForUsageLog(log store.UsageLog) []string {
	scopes := []string{"*"}
	tags := make([]string, 0, len(log.Tags))
	for _, tag := range log.Tags {
		if t := strings.TrimSpace(tag); t != "" && !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)
	for _, t := range tags {
		if !slices.Contains(scopes, t) {
			scopes = append(scopes, t)
		}
	}
	if subj := strings.TrimSpace(log.Subject); subj != "" && !slices.Contains(scopes, subj) {
		scopes = append(scopes, subj)
	}
	return scopes
}

func filterForScope(scope string, since time.Time) store.UsageFilter {
	f := store.UsageFilter{Since: since}
	switch {
	case scope == "*":
		return f
	case strings.HasPrefix(scope, "tag:"):
		f.Tag = scope
		return f
	default:
		f.Subject = scope
		return f
	}
}

func pruneRequests(st *scopeState, now time.Time) {
	cutoff := now.Add(-time.Minute)
	keep := 0
	for keep < len(st.reqTimes) && !st.reqTimes[keep].After(cutoff) {
		keep++
	}
	if keep > 0 {
		st.reqTimes = st.reqTimes[keep:]
	}
}

func pruneTokens(st *scopeState, now time.Time) {
	cutoff := now.Add(-time.Minute)
	keep := 0
	for keep < len(st.tokenSamples) && !st.tokenSamples[keep].at.After(cutoff) {
		st.tokenSum -= st.tokenSamples[keep].tokens
		keep++
	}
	if keep > 0 {
		st.tokenSamples = st.tokenSamples[keep:]
		if st.tokenSum < 0 {
			st.tokenSum = 0
		}
	}
}

func utcDayWindow(now time.Time) (key string, start, reset time.Time) {
	u := now.UTC()
	start = time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	return start.Format("2006-01-02"), start, start.Add(24 * time.Hour)
}

func utcMonthWindow(now time.Time) (key string, start, reset time.Time) {
	u := now.UTC()
	start = time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start.Format("2006-01"), start, start.AddDate(0, 1, 0)
}

func secondsUntil(now, target time.Time) int {
	sec := int(math.Ceil(target.Sub(now).Seconds()))
	if sec < 1 {
		return 1
	}
	return sec
}

func spendPct(spent, limit float64) float64 {
	if limit <= 0 {
		return 100
	}
	return (spent / limit) * 100
}

func cloneFloatPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}
