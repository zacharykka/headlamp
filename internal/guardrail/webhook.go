package guardrail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	defaultSyncReviewTimeout = 2 * time.Second
	defaultAsyncTimeout      = 5 * time.Second
	defaultWebhookQueueSize  = 512
	defaultWebhookWorkers    = 2
	defaultRetryBackoff      = 150 * time.Millisecond
	maxWebhookResponseBytes  = 2 * 1024 * 1024 // 2 MiB
)

// SyncReviewRequest is the JSON payload POSTed to enabled sync_review webhooks.
type SyncReviewRequest struct {
	RequestID string          `json:"request_id"`
	Timestamp time.Time       `json:"timestamp"`
	Subject   string          `json:"subject"`
	NodeName  string          `json:"node_name"`
	Protocol  string          `json:"protocol"`
	Model     string          `json:"model"`
	Body      json.RawMessage `json:"body"`
}

// SyncReviewResponse is the JSON response returned by a sync_review webhook.
type SyncReviewResponse struct {
	Action       string          `json:"action"` // allow | block | modify
	Reason       string          `json:"reason,omitempty"`
	ModifiedBody json.RawMessage `json:"modified_body,omitempty"`
}

// SyncReviewOutcome summarizes the combined result of running all enabled sync_review webhooks.
type SyncReviewOutcome struct {
	Action       string // allow | modify | block
	ModifiedBody []byte
	Hits         []string
	Reason       string
	StatusCode   int // Set when blocked: 403 for explicit block, 503 for fail_closed error
}

// EventEnvelope wraps asynchronous webhook events delivered to async_event endpoints.
type EventEnvelope struct {
	ID        string    `json:"id"`
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// WebhookTestResult is returned by PingWebhook for the Admin UI webhook test endpoint.
type WebhookTestResult struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code"`
	LatencyMS  int64  `json:"latency_ms"`
	Message    string `json:"message"`
}

// SignPayload returns the X-Headlamp-Signature header value ("sha256=<hex>")
// computed as HMAC-SHA256(secret, payload).
func SignPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks an X-Headlamp-Signature header in constant time.
func VerifySignature(secret string, payload []byte, signature string) bool {
	if secret == "" || signature == "" {
		return false
	}
	expected := SignPayload(secret, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}

type asyncEventJob struct {
	eventType string
	envelope  EventEnvelope
}

// WebhookDispatcher handles synchronous pre-request review webhooks, buffered
// asynchronous post-event delivery, and Admin UI connectivity tests.
type WebhookDispatcher struct {
	store        store.Store
	httpClient   *http.Client
	retryBackoff time.Duration
	logf         func(format string, args ...any)

	mu        sync.RWMutex
	closed    bool
	queue     chan asyncEventJob
	dropped   atomic.Int64
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// ErrBlockedWebhookAddress is returned when a webhook target resolves to a
// blocked SSRF destination (cloud IMDS, link-local, unspecified, multicast, or
// loopback when BlockLoopback is enabled).
var ErrBlockedWebhookAddress = errors.New("guardrail: blocked webhook target IP address")

var awsIPv6IMDS = netip.MustParseAddr("fd00:ec2::254")

// WebhookDispatcherOptions tunes queue size, worker parallelism, retry backoff, and HTTP client.
type WebhookDispatcherOptions struct {
	HTTPClient    *http.Client
	BlockLoopback bool
	QueueSize     int
	Workers       int
	RetryBackoff  time.Duration
	Logf          func(format string, args ...any)
}

// NewWebhookDispatcher creates a WebhookDispatcher and starts its async delivery workers.
func NewWebhookDispatcher(st store.Store, opts WebhookDispatcherOptions) *WebhookDispatcher {
	client := opts.HTTPClient
	if client == nil {
		client = defaultWebhookHTTPClient(opts.BlockLoopback)
	}
	qSize := opts.QueueSize
	if qSize <= 0 {
		qSize = defaultWebhookQueueSize
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWebhookWorkers
	}
	backoff := opts.RetryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	d := &WebhookDispatcher{
		store:        st,
		httpClient:   client,
		retryBackoff: backoff,
		logf:         opts.Logf,
		queue:        make(chan asyncEventJob, qSize),
	}
	for range workers {
		d.wg.Add(1)
		go d.runWorker()
	}
	return d
}

// Review executes all enabled sync_review webhooks sequentially against req.
// Each webhook honors its own TimeoutMS and FailOpen policy.
func (d *WebhookDispatcher) Review(ctx context.Context, req SyncReviewRequest) (*SyncReviewOutcome, error) {
	if d.store == nil {
		return &SyncReviewOutcome{Action: ActionAllow, ModifiedBody: req.Body}, nil
	}
	webhooks, err := d.store.ListWebhooks(ctx)
	if err != nil {
		return nil, fmt.Errorf("guardrail: list webhooks: %w", err)
	}

	currentBody := req.Body
	outcome := &SyncReviewOutcome{
		Action:       ActionAllow,
		ModifiedBody: currentBody,
	}

	for _, wh := range webhooks {
		if !wh.Enabled || wh.Type != config.WebhookTypeSyncReview {
			continue
		}

		reqCopy := req
		if reqCopy.Timestamp.IsZero() {
			reqCopy.Timestamp = time.Now().UTC()
		}
		trimmedBody := bytes.TrimSpace(currentBody)
		switch {
		case len(trimmedBody) == 0:
			reqCopy.Body = json.RawMessage(`null`)
		case json.Valid(trimmedBody):
			reqCopy.Body = json.RawMessage(trimmedBody)
		default:
			quoted, _ := json.Marshal(string(currentBody))
			reqCopy.Body = json.RawMessage(quoted)
		}

		payload, err := json.Marshal(reqCopy)
		if err != nil {
			return nil, fmt.Errorf("guardrail: marshal sync review request: %w", err)
		}

		timeout := time.Duration(wh.TimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = defaultSyncReviewTimeout
		}

		callCtx, cancel := context.WithTimeout(ctx, timeout)
		statusCode, respBody, callErr := d.postSigned(callCtx, wh.URL, wh.Secret, "sync_review", payload)
		cancel()

		if callErr != nil || statusCode < 200 || statusCode >= 300 {
			reason := fmt.Sprintf("sync review webhook %q failed", wh.Name)
			if callErr != nil {
				reason = fmt.Sprintf("sync review webhook %q error: %s", wh.Name, sanitizeURLError(callErr))
			} else {
				reason = fmt.Sprintf("sync review webhook %q returned HTTP %d", wh.Name, statusCode)
			}
			if wh.FailOpen {
				if d.logf != nil {
					d.logf("headlamp guardrail: %s (fail_open, allowing request)", reason)
				}
				continue
			}
			return &SyncReviewOutcome{
				Action:       ActionBlock,
				ModifiedBody: currentBody,
				Hits:         append(outcome.Hits, "webhook:"+wh.ID),
				Reason:       reason + " (fail_closed)",
				StatusCode:   http.StatusServiceUnavailable,
			}, nil
		}

		var reviewResp SyncReviewResponse
		if err := json.Unmarshal(respBody, &reviewResp); err != nil {
			reason := fmt.Sprintf("sync review webhook %q returned invalid JSON", wh.Name)
			if wh.FailOpen {
				if d.logf != nil {
					d.logf("headlamp guardrail: %s (fail_open, allowing request)", reason)
				}
				continue
			}
			return &SyncReviewOutcome{
				Action:       ActionBlock,
				ModifiedBody: currentBody,
				Hits:         append(outcome.Hits, "webhook:"+wh.ID),
				Reason:       reason + " (fail_closed)",
				StatusCode:   http.StatusServiceUnavailable,
			}, nil
		}

		switch strings.ToLower(strings.TrimSpace(reviewResp.Action)) {
		case ActionBlock:
			reason := strings.TrimSpace(reviewResp.Reason)
			if reason == "" {
				reason = fmt.Sprintf("request blocked by review webhook %q", wh.Name)
			}
			return &SyncReviewOutcome{
				Action:       ActionBlock,
				ModifiedBody: currentBody,
				Hits:         append(outcome.Hits, "webhook:"+wh.ID),
				Reason:       reason,
				StatusCode:   http.StatusForbidden,
			}, nil

		case ActionModify:
			mod := bytes.TrimSpace(reviewResp.ModifiedBody)
			if len(mod) > 0 && mod[0] == '{' && json.Valid(mod) {
				currentBody = bytes.Clone(mod)
				outcome.ModifiedBody = currentBody
				outcome.Action = ActionModify
				outcome.Hits = append(outcome.Hits, "webhook:"+wh.ID)
			} else if !wh.FailOpen {
				return &SyncReviewOutcome{
					Action:       ActionBlock,
					ModifiedBody: currentBody,
					Hits:         append(outcome.Hits, "webhook:"+wh.ID),
					Reason:       fmt.Sprintf("sync review webhook %q returned non-object modified_body (fail_closed)", wh.Name),
					StatusCode:   http.StatusServiceUnavailable,
				}, nil
			} else if d.logf != nil {
				d.logf("headlamp guardrail: sync review webhook %q returned non-object modified_body (fail_open, ignoring modification)", wh.Name)
			}

		case ActionAllow, "":
			// Allowed; proceed to next webhook.

		default:
			if !wh.FailOpen {
				return &SyncReviewOutcome{
					Action:       ActionBlock,
					ModifiedBody: currentBody,
					Hits:         append(outcome.Hits, "webhook:"+wh.ID),
					Reason:       fmt.Sprintf("sync review webhook %q returned unknown action %q (fail_closed)", wh.Name, reviewResp.Action),
					StatusCode:   http.StatusServiceUnavailable,
				}, nil
			}
			if d.logf != nil {
				d.logf("headlamp guardrail: sync review webhook %q returned unknown action %q (fail_open, allowing request)", wh.Name, reviewResp.Action)
			}
		}
	}

	return outcome, nil
}

// Emit enqueues an asynchronous event for non-blocking delivery to matching
// enabled async_event webhooks. Safe to call concurrently and after Close.
func (d *WebhookDispatcher) Emit(eventType string, payload any) {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	if eventType == "" {
		return
	}

	job := asyncEventJob{
		eventType: eventType,
		envelope: EventEnvelope{
			ID:        uuid.NewString(),
			Event:     eventType,
			Timestamp: time.Now().UTC(),
			Data:      payload,
		},
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		d.dropped.Add(1)
		return
	}
	select {
	case d.queue <- job:
	default:
		d.dropped.Add(1)
	}
}

// DroppedCount returns the number of async events dropped due to queue saturation or post-close calls.
func (d *WebhookDispatcher) DroppedCount() int64 {
	return d.dropped.Load()
}

// Close stops accepting new async events and waits for all queued events to
// drain or ctx to expire. Safe to call multiple times.
func (d *WebhookDispatcher) Close(ctx context.Context) error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.queue)
		d.mu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PingWebhook sends a signed connectivity test POST to wh and reports status & latency.
func (d *WebhookDispatcher) PingWebhook(ctx context.Context, wh store.Webhook) (*WebhookTestResult, error) {
	if strings.TrimSpace(wh.URL) == "" {
		return &WebhookTestResult{
			OK:      false,
			Message: "webhook URL is empty",
		}, nil
	}

	env := EventEnvelope{
		ID:        uuid.NewString(),
		Event:     "webhook.test",
		Timestamp: time.Now().UTC(),
		Data: map[string]any{
			"webhook_id":   wh.ID,
			"webhook_name": wh.Name,
			"message":      "headlamp webhook connectivity test",
		},
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(wh.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultAsyncTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	statusCode, _, callErr := d.postSigned(callCtx, wh.URL, wh.Secret, "webhook.test", payload)
	latencyMS := time.Since(start).Milliseconds()

	if callErr != nil {
		return &WebhookTestResult{
			OK:         false,
			StatusCode: statusCode,
			LatencyMS:  latencyMS,
			Message:    sanitizeURLError(callErr),
		}, nil
	}
	ok := statusCode >= 200 && statusCode < 300
	msg := fmt.Sprintf("HTTP %d", statusCode)
	if ok {
		msg = fmt.Sprintf("webhook responded HTTP %d", statusCode)
	}
	return &WebhookTestResult{
		OK:         ok,
		StatusCode: statusCode,
		LatencyMS:  latencyMS,
		Message:    msg,
	}, nil
}

func (d *WebhookDispatcher) runWorker() {
	defer d.wg.Done()
	for job := range d.queue {
		d.deliverAsyncJob(job)
	}
}

func (d *WebhookDispatcher) deliverAsyncJob(job asyncEventJob) {
	if d.store == nil {
		return
	}
	webhooks, err := d.store.ListWebhooks(context.Background())
	if err != nil {
		if d.logf != nil {
			d.logf("headlamp webhook: list webhooks failed: %v", err)
		}
		return
	}

	payload, err := json.Marshal(job.envelope)
	if err != nil {
		return
	}

	for _, wh := range webhooks {
		if !wh.Enabled || wh.Type != config.WebhookTypeAsyncEvent {
			continue
		}
		if !webhookMatchesEvent(wh.Events, job.eventType) {
			continue
		}
		d.deliverWithRetry(wh, job.eventType, payload)
	}
}

func (d *WebhookDispatcher) deliverWithRetry(wh store.Webhook, eventType string, payload []byte) {
	timeout := time.Duration(wh.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultAsyncTimeout
	}

	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(d.retryBackoff)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		statusCode, _, err := d.postSigned(ctx, wh.URL, wh.Secret, eventType, payload)
		cancel()

		if err == nil && statusCode >= 200 && statusCode < 300 {
			return
		}
		// Retry once only on network error or 5xx.
		if err == nil && statusCode < 500 {
			if d.logf != nil {
				d.logf("headlamp webhook: async %q event=%s returned HTTP %d (no retry)", wh.ID, eventType, statusCode)
			}
			return
		}
		if attempt == 1 && d.logf != nil {
			if err != nil {
				d.logf("headlamp webhook: async %q event=%s failed after retry: %s", wh.ID, eventType, sanitizeURLError(err))
			} else {
				d.logf("headlamp webhook: async %q event=%s returned HTTP %d after retry", wh.ID, eventType, statusCode)
			}
		}
	}
}

func (d *WebhookDispatcher) postSigned(ctx context.Context, targetURL, secret, eventName string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Headlamp-Event", eventName)
	if secret != "" {
		req.Header.Set("X-Headlamp-Signature", SignPayload(secret, payload))
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxWebhookResponseBytes))
	if readErr != nil {
		return resp.StatusCode, nil, readErr
	}
	return resp.StatusCode, body, nil
}

func webhookMatchesEvent(subscribed []string, eventType string) bool {
	for _, ev := range subscribed {
		ev = strings.ToLower(strings.TrimSpace(ev))
		if ev == "*" || ev == eventType {
			return true
		}
	}
	return false
}

func sanitizeURLError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cleanURL := urlErr.URL
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.User = nil
			cleanURL = parsed.String()
		}
		return fmt.Sprintf("%s %q: %v", urlErr.Op, cleanURL, urlErr.Err)
	}
	return err.Error()
}

func defaultWebhookHTTPClient(blockLoopback bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   webhookDialControl(blockLoopback),
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          50,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func webhookDialControl(blockLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		return validateWebhookDialAddr(address, blockLoopback)
	}
}

func validateWebhookDialAddr(address string, blockLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid dial address %q", ErrBlockedWebhookAddress, address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: invalid IP %q", ErrBlockedWebhookAddress, host)
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.WithZone("") == awsIPv6IMDS,
		addr.IsUnspecified(),
		addr.IsMulticast(),
		blockLoopback && addr.IsLoopback():
		return fmt.Errorf("%w: %s", ErrBlockedWebhookAddress, addr)
	}
	return nil
}
