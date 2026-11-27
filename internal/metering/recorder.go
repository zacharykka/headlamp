package metering

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	// DefaultQueueSize is the default buffered channel capacity for async usage writes.
	DefaultQueueSize = 1024
	// DefaultMaxAuditBodyBytes caps stored request/response bodies to bound memory and DB size.
	DefaultMaxAuditBodyBytes = 256 * 1024
	// DefaultPurgeInterval controls how often the background audit retention purge runs.
	DefaultPurgeInterval = time.Hour

	defaultWriteTimeout = 5 * time.Second
	truncationMarker    = "\n...[truncated]"
)

// RecorderOptions configures optional Recorder runtime parameters.
type RecorderOptions struct {
	QueueSize         int
	MaxAuditBodyBytes int
	PurgeInterval     time.Duration
	DisableAutoPurge  bool
	OnError           func(error)
	OnRecorded        func(store.UsageLog)
}

// RequestInfo captures request metadata available before proxying to an upstream provider.
type RequestInfo struct {
	RequestID       string
	Timestamp       time.Time
	Principal       *auth.Principal
	Protocol        string
	Endpoint        string
	Provider        string
	ProviderType    string
	RequestedModel  string
	UpstreamModel   string
	Stream          bool
	Translated      bool
	RequestHeaders  map[string]string
	RequestBody     []byte
	ResponseHeaders map[string]string
	PriceOverride   *PriceOverride
	GuardrailAction string
	GuardrailHits   []string
}

type recordJob struct {
	usageLog     store.UsageLog
	auditPayload *store.AuditPayload
}

// Recorder asynchronously persists usage logs and optional audit payloads into store.Store.
type Recorder struct {
	store             store.Store
	pricing           *PricingTable
	maxAuditBodyBytes int
	onError           func(error)

	mu         sync.RWMutex
	audit      config.AuditConfig
	onRecorded func(store.UsageLog)
	closed     bool
	jobs       chan recordJob
	dropped    atomic.Int64

	workerDone chan struct{}
	stopPurge  chan struct{}
	purgeDone  chan struct{}
	closeOnce  sync.Once
}

// NewRecorder creates a Recorder and starts its background persistence worker
// (plus an optional audit payload retention purge loop).
func NewRecorder(st store.Store, audit config.AuditConfig, pricing *PricingTable, opts ...RecorderOptions) *Recorder {
	var opt RecorderOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = DefaultQueueSize
	}
	if opt.MaxAuditBodyBytes <= 0 {
		opt.MaxAuditBodyBytes = DefaultMaxAuditBodyBytes
	}
	if opt.PurgeInterval <= 0 {
		opt.PurgeInterval = DefaultPurgeInterval
	}
	if pricing == nil {
		if def, err := LoadDefault(); err == nil {
			pricing = def
		}
	}

	r := &Recorder{
		store:             st,
		audit:             audit,
		pricing:           pricing,
		maxAuditBodyBytes: opt.MaxAuditBodyBytes,
		onError:           opt.OnError,
		onRecorded:        opt.OnRecorded,
		jobs:              make(chan recordJob, opt.QueueSize),
		workerDone:        make(chan struct{}),
	}

	go r.runWorker()

	if !opt.DisableAutoPurge && st != nil {
		r.stopPurge = make(chan struct{})
		r.purgeDone = make(chan struct{})
		go r.runPurgeLoop(opt.PurgeInterval)
	}

	return r
}

// WithOnRecorded registers a callback invoked after each UsageLog is persisted to storage.
// Safe to call before or during serving (for example, to feed live spend into the quota tracker).
func (r *Recorder) WithOnRecorded(fn func(store.UsageLog)) *Recorder {
	r.mu.Lock()
	r.onRecorded = fn
	r.mu.Unlock()
	return r
}

// AuditConfig returns the active runtime audit configuration.
func (r *Recorder) AuditConfig() config.AuditConfig {
	r.mu.RLock()
	cfg := r.audit
	r.mu.RUnlock()
	return cfg
}

// UpdateAuditConfig updates store_payloads and retention_days at runtime without restart.
func (r *Recorder) UpdateAuditConfig(cfg config.AuditConfig) {
	if cfg.RetentionDays < 0 {
		cfg.RetentionDays = 0
	}
	r.mu.Lock()
	r.audit = cfg
	r.mu.Unlock()
}

// Start begins observing a single LLM request. Call OnSSEEvent or OnJSONResponse as
// upstream data arrives, and Finish once the request completes or aborts.
func (r *Recorder) Start(_ context.Context, info RequestInfo) *RequestObserver {
	if info.Timestamp.IsZero() {
		info.Timestamp = time.Now().UTC()
	}
	if info.Principal != nil {
		info.Principal = info.Principal.Clone()
	}
	info.GuardrailHits = slices.Clone(info.GuardrailHits)

	storePayloads := r.AuditConfig().StorePayloads
	if storePayloads && len(info.RequestBody) > 0 {
		info.RequestBody = capBytes(info.RequestBody, r.maxAuditBodyBytes)
	} else {
		// Release reference to potentially large request payload when payload auditing is off.
		info.RequestBody = nil
	}

	var reqRedacted, respRedacted bool
	if len(info.RequestHeaders) > 0 {
		info.RequestHeaders, reqRedacted = sanitizeHeaders(info.RequestHeaders)
	}
	if len(info.ResponseHeaders) > 0 {
		info.ResponseHeaders, respRedacted = sanitizeHeaders(info.ResponseHeaders)
	}

	return &RequestObserver{
		recorder:      r,
		info:          info,
		parser:        NewSSEUsageParser(info.Protocol),
		storePayloads: storePayloads,
		reqRedacted:   reqRedacted,
		respRedacted:  respRedacted,
	}
}

// Record enqueues a completed request directly using pre-parsed Usage.
func (r *Recorder) Record(info RequestInfo, usage Usage, statusCode int, latencyMS, ttftMS int64, errMsg string, responseBody []byte) {
	if info.Timestamp.IsZero() {
		info.Timestamp = time.Now().UTC()
	}
	info.GuardrailHits = slices.Clone(info.GuardrailHits)
	storePayloads := r.AuditConfig().StorePayloads
	var reqBody []byte
	var respBody string
	if storePayloads {
		reqBody = capBytes(info.RequestBody, r.maxAuditBodyBytes)
		respBody = string(capBytes(responseBody, r.maxAuditBodyBytes))
	}
	info.RequestBody = reqBody
	var reqRedacted, respRedacted bool
	info.RequestHeaders, reqRedacted = sanitizeHeaders(info.RequestHeaders)
	info.ResponseHeaders, respRedacted = sanitizeHeaders(info.ResponseHeaders)
	r.enqueue(info, usage, statusCode, latencyMS, ttftMS, errMsg, respBody, reqRedacted || respRedacted, storePayloads)
}

// PurgeNow immediately deletes audit_payloads older than the active audit.RetentionDays.
func (r *Recorder) PurgeNow(ctx context.Context) (int64, error) {
	auditCfg := r.AuditConfig()
	if r.store == nil || auditCfg.RetentionDays <= 0 {
		return 0, nil
	}
	return r.PurgeOlderThan(ctx, time.Duration(auditCfg.RetentionDays)*24*time.Hour)
}

// PurgeOlderThan immediately deletes audit_payloads older than maxAge.
// A maxAge of 0 purges all audit_payloads recorded up to now.
func (r *Recorder) PurgeOlderThan(ctx context.Context, maxAge time.Duration) (int64, error) {
	if r.store == nil {
		return 0, nil
	}
	if maxAge < 0 {
		return 0, errors.New("metering: maxAge must be non-negative")
	}
	now := time.Now().UTC()
	cutoff := now.Add(-maxAge)
	if maxAge == 0 {
		// Store purge uses strict "<"; bump by 1ns so payloads recorded at the exact same timestamp are included.
		cutoff = now.Add(time.Nanosecond)
	}
	return r.store.PurgeAuditPayloads(ctx, cutoff)
}

// DroppedCount returns the number of usage records dropped due to a full queue or post-close calls.
func (r *Recorder) DroppedCount() int64 {
	return r.dropped.Load()
}

// Close stops background purge timers and drains all queued records into storage
// until flushed or ctx is canceled.
func (r *Recorder) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		if r.stopPurge != nil {
			close(r.stopPurge)
		}
		r.mu.Lock()
		r.closed = true
		close(r.jobs)
		r.mu.Unlock()
	})

	if r.purgeDone != nil {
		select {
		case <-r.purgeDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	select {
	case <-r.workerDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Recorder) enqueue(info RequestInfo, usage Usage, statusCode int, latencyMS, ttftMS int64, errMsg string, responseBody string, redacted bool, storePayloads bool) {
	if r == nil || r.store == nil {
		return
	}

	logID := uuid.NewString()
	createdAt := info.Timestamp.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	pricingProvider := info.ProviderType
	if pricingProvider == "" {
		pricingProvider = info.Provider
	}
	pricingModel := info.UpstreamModel
	if pricingModel == "" {
		pricingModel = info.RequestedModel
	}
	costUSD := r.pricing.CalculateCost(pricingProvider, pricingModel, usage, info.PriceOverride)

	usageLog := store.UsageLog{
		ID:               logID,
		CreatedAt:        createdAt,
		RequestID:        info.RequestID,
		ProviderName:     info.Provider,
		ProviderType:     info.ProviderType,
		RequestedModel:   info.RequestedModel,
		UpstreamModel:    info.UpstreamModel,
		Protocol:         info.Protocol,
		Endpoint:         info.Endpoint,
		Stream:           info.Stream,
		Translated:       info.Translated,
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		CacheWriteTokens: usage.CacheWriteTokens + usage.CacheWrite1hTokens,
		ReasoningTokens:  usage.ReasoningTokens,
		TotalTokens:      usage.NormalizedTotal(info.Protocol),
		CostUSD:          costUSD,
		LatencyMS:        latencyMS,
		TTFTMS:           ttftMS,
		StatusCode:       statusCode,
		ErrorMessage:     errMsg,
		GuardrailAction:  info.GuardrailAction,
		GuardrailHits:    slices.Clone(info.GuardrailHits),
	}
	if info.Principal != nil {
		usageLog.Subject = info.Principal.Subject
		usageLog.DisplayName = info.Principal.DisplayName
		usageLog.NodeName = info.Principal.NodeName
		usageLog.NodeIP = info.Principal.NodeIP
		usageLog.Tags = slices.Clone(info.Principal.Tags)
		usageLog.AuthSource = info.Principal.AuthSource
	}

	var auditPayload *store.AuditPayload
	if storePayloads {
		auditPayload = &store.AuditPayload{
			ID:              uuid.NewString(),
			UsageLogID:      logID,
			CreatedAt:       createdAt,
			RequestHeaders:  info.RequestHeaders,
			RequestBody:     string(info.RequestBody),
			ResponseHeaders: info.ResponseHeaders,
			ResponseBody:    responseBody,
			Redacted:        redacted,
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		r.dropped.Add(1)
		return
	}
	select {
	case r.jobs <- recordJob{usageLog: usageLog, auditPayload: auditPayload}:
	default:
		r.dropped.Add(1)
	}
}

func (r *Recorder) runWorker() {
	defer close(r.workerDone)
	for job := range r.jobs {
		// Use a detached context so client stream disconnects never abort persistence.
		ctx, cancel := context.WithTimeout(context.Background(), defaultWriteTimeout)
		if err := r.store.InsertUsageLog(ctx, job.usageLog); err != nil {
			r.reportError(err)
			cancel()
			continue
		}
		if job.auditPayload != nil {
			if err := r.store.InsertAuditPayload(ctx, *job.auditPayload); err != nil {
				r.reportError(err)
			}
		}
		cancel()

		r.mu.RLock()
		cb := r.onRecorded
		r.mu.RUnlock()
		if cb != nil {
			cb(job.usageLog)
		}
	}
}

func (r *Recorder) runPurgeLoop(interval time.Duration) {
	defer close(r.purgeDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopPurge:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), defaultWriteTimeout)
			if _, err := r.PurgeNow(ctx); err != nil {
				r.reportError(err)
			}
			cancel()
		}
	}
}

func (r *Recorder) reportError(err error) {
	if err != nil && r.onError != nil {
		r.onError(err)
	}
}

// RequestObserver tracks streaming or non-streaming usage for a single in-flight request.
// It is safe for concurrent use.
type RequestObserver struct {
	recorder      *Recorder
	info          RequestInfo
	parser        *SSEUsageParser
	storePayloads bool

	mu            sync.Mutex
	jsonUsage     Usage
	hasJSONUsage  bool
	reqRedacted   bool
	respRedacted  bool
	respBuf       bytes.Buffer
	respTruncated bool
	finished      bool
}

// OnSSEEvent parses usage from an incoming SSE frame and appends to the bounded audit buffer if enabled.
func (o *RequestObserver) OnSSEEvent(eventName string, data []byte) {
	if o == nil {
		return
	}
	o.parser.Feed(eventName, data)

	if o.recorder == nil || !o.storePayloads {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.respTruncated {
		return
	}
	if eventName != "" {
		o.appendAuditLocked("event: " + eventName + "\n")
	}
	o.appendAuditLocked("data: ")
	o.appendAuditBytesLocked(data)
	o.appendAuditLocked("\n\n")
}

// OnJSONResponse parses usage from a non-streaming JSON response body and captures a capped copy if audit payloads are enabled.
func (o *RequestObserver) OnJSONResponse(body []byte) {
	if o == nil {
		return
	}
	parsed := ParseJSONUsage(o.info.Protocol, body)

	o.mu.Lock()
	defer o.mu.Unlock()
	o.jsonUsage = parsed
	o.hasJSONUsage = true

	if o.recorder != nil && o.storePayloads {
		o.respBuf.Reset()
		o.respTruncated = false
		o.respBuf.Write(capBytes(body, o.recorder.maxAuditBodyBytes))
	}
}

// SetResponseHeaders attaches response headers to be stored if audit payloads are enabled.
func (o *RequestObserver) SetResponseHeaders(headers map[string]string) {
	if o == nil || len(headers) == 0 {
		return
	}
	clean, redacted := sanitizeHeaders(headers)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.info.ResponseHeaders = clean
	if redacted {
		o.respRedacted = true
	}
}

// Usage returns the latest parsed Usage for this request.
func (o *RequestObserver) Usage() Usage {
	if o == nil {
		return Usage{}
	}
	o.mu.Lock()
	hasJSON := o.hasJSONUsage
	jsonU := o.jsonUsage
	o.mu.Unlock()
	if hasJSON {
		return jsonU
	}
	return o.parser.Usage()
}

// Finish finalizes the request and enqueues usage/audit persistence.
// Calling Finish more than once is a safe no-op.
func (o *RequestObserver) Finish(statusCode int, latencyMS, ttftMS int64, errMsg string) {
	if o == nil || o.recorder == nil {
		return
	}
	o.mu.Lock()
	if o.finished {
		o.mu.Unlock()
		return
	}
	o.finished = true
	info := o.info
	hasJSON := o.hasJSONUsage
	usage := o.jsonUsage
	respBody := o.respBuf.String()
	redacted := o.reqRedacted || o.respRedacted
	storePayloads := o.storePayloads
	o.mu.Unlock()

	if !hasJSON {
		usage = o.parser.Usage()
	}
	o.recorder.enqueue(info, usage, statusCode, latencyMS, ttftMS, errMsg, respBody, redacted, storePayloads)
}

func (o *RequestObserver) appendAuditLocked(s string) {
	o.appendAuditBytesLocked([]byte(s))
}

func (o *RequestObserver) appendAuditBytesLocked(b []byte) {
	if o.respTruncated || len(b) == 0 {
		return
	}
	limit := o.recorder.maxAuditBodyBytes
	remaining := limit - o.respBuf.Len()
	if remaining <= 0 {
		o.respBuf.WriteString(truncationMarker)
		o.respTruncated = true
		return
	}
	if len(b) <= remaining {
		o.respBuf.Write(b)
		return
	}
	o.respBuf.Write(b[:remaining])
	o.respBuf.WriteString(truncationMarker)
	o.respTruncated = true
}

func capBytes(src []byte, limit int) []byte {
	if len(src) == 0 {
		return nil
	}
	if limit <= 0 || len(src) <= limit {
		out := make([]byte, len(src))
		copy(out, src)
		return out
	}
	out := make([]byte, 0, limit+len(truncationMarker))
	out = append(out, src[:limit]...)
	out = append(out, truncationMarker...)
	return out
}

func sanitizeHeaders(headers map[string]string) (map[string]string, bool) {
	if len(headers) == 0 {
		return nil, false
	}
	clean := maps.Clone(headers)
	redacted := false
	for k := range clean {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "cookie", "set-cookie":
			clean[k] = "[REDACTED]"
			redacted = true
		}
	}
	return clean, redacted
}
