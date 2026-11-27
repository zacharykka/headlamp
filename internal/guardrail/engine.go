package guardrail

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

// EngineConfig configures the unified Guardrail + Webhook Engine.
type EngineConfig struct {
	Store         store.Store
	HTTPClient    *http.Client
	BlockLoopback bool
	QueueSize     int
	Workers       int
	RetryBackoff  time.Duration
	Logf          func(format string, args ...any)
}

// InspectInput provides request context and raw JSON payload for Engine.InspectRequest.
type InspectInput struct {
	RequestID string
	Subject   string
	NodeName  string
	Protocol  string
	Model     string
	Body      []byte
}

// Decision is the combined outcome of local regex rules and sync_review webhooks.
type Decision struct {
	Action       string   // allow | log_only | redact | modify | block
	ModifiedBody []byte   // Rewritten JSON payload when Action is redact/modify
	Hits         []string // Matched rule IDs and/or "webhook:<id>" entries
	Reason       string   // Populated when Action == "block"
	StatusCode   int      // HTTP status to return when Action == "block" (400 / 403 / 503)
}

// Engine coordinates local regex guardrails, synchronous pre-request review webhooks,
// and asynchronous event webhook dispatch.
type Engine struct {
	evaluator  *Evaluator
	dispatcher *WebhookDispatcher
}

// NewEngine creates a ready-to-use Guardrail + Webhook Engine.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("guardrail: store is required")
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Engine{
		evaluator: NewEvaluator(cfg.Store, logf),
		dispatcher: NewWebhookDispatcher(cfg.Store, WebhookDispatcherOptions{
			HTTPClient:    cfg.HTTPClient,
			BlockLoopback: cfg.BlockLoopback,
			QueueSize:     cfg.QueueSize,
			Workers:       cfg.Workers,
			RetryBackoff:  cfg.RetryBackoff,
			Logf:          logf,
		}),
	}, nil
}

// InspectRequest runs local regex inspection followed by enabled sync_review webhooks,
// emitting a guardrail.triggered async event whenever any rule or webhook acts on the request.
func (e *Engine) InspectRequest(ctx context.Context, in InspectInput) (*Decision, error) {
	localRes, err := e.evaluator.InspectJSONPayload(ctx, in.Body)
	if err != nil {
		return nil, err
	}

	hits := make([]string, 0, len(localRes.Matches))
	for _, m := range localRes.Matches {
		hits = append(hits, m.RuleID)
	}

	if localRes.Action == ActionBlock {
		e.emitGuardrailEvent(in, ActionBlock, hits, localRes.Reason)
		return &Decision{
			Action:       ActionBlock,
			ModifiedBody: in.Body,
			Hits:         hits,
			Reason:       localRes.Reason,
			StatusCode:   http.StatusBadRequest,
		}, nil
	}

	currentBody := localRes.ModifiedBody
	finalAction := localRes.Action

	reviewRes, err := e.dispatcher.Review(ctx, SyncReviewRequest{
		RequestID: in.RequestID,
		Timestamp: time.Now().UTC(),
		Subject:   in.Subject,
		NodeName:  in.NodeName,
		Protocol:  in.Protocol,
		Model:     in.Model,
		Body:      currentBody,
	})
	if err != nil {
		return nil, err
	}

	if len(reviewRes.Hits) > 0 {
		hits = append(hits, reviewRes.Hits...)
	}

	if reviewRes.Action == ActionBlock {
		statusCode := reviewRes.StatusCode
		if statusCode < 400 {
			statusCode = http.StatusForbidden
		}
		e.emitGuardrailEvent(in, ActionBlock, hits, reviewRes.Reason)
		return &Decision{
			Action:       ActionBlock,
			ModifiedBody: currentBody,
			Hits:         hits,
			Reason:       reviewRes.Reason,
			StatusCode:   statusCode,
		}, nil
	}

	if reviewRes.Action == ActionModify && len(reviewRes.ModifiedBody) > 0 {
		currentBody = reviewRes.ModifiedBody
		if finalAction == ActionAllow || finalAction == ActionLogOnly {
			finalAction = ActionModify
		}
	}

	if finalAction != ActionAllow {
		e.emitGuardrailEvent(in, finalAction, hits, "")
	}

	return &Decision{
		Action:       finalAction,
		ModifiedBody: currentBody,
		Hits:         hits,
	}, nil
}

// TestText tests enabled local regex rules against text (Admin UI test endpoint).
func (e *Engine) TestText(ctx context.Context, text string) (*TestResult, error) {
	return e.evaluator.TestText(ctx, text)
}

// PingWebhook sends a signed connectivity test POST to wh (Admin UI test endpoint).
func (e *Engine) PingWebhook(ctx context.Context, wh store.Webhook) (*WebhookTestResult, error) {
	return e.dispatcher.PingWebhook(ctx, wh)
}

// Emit enqueues an asynchronous webhook event (implements proxy.EventDispatcher
// and can also receive quota budget alerts).
func (e *Engine) Emit(eventType string, payload any) {
	e.dispatcher.Emit(eventType, payload)
}

// DroppedEvents returns the number of async webhook events dropped due to saturation or post-close calls.
func (e *Engine) DroppedEvents() int64 {
	return e.dispatcher.DroppedCount()
}

// Close gracefully drains queued async webhook events before shutdown.
func (e *Engine) Close(ctx context.Context) error {
	return e.dispatcher.Close(ctx)
}

func (e *Engine) emitGuardrailEvent(in InspectInput, action string, hits []string, reason string) {
	e.dispatcher.Emit(config.WebhookEventGuardrailTriggered, map[string]any{
		"request_id": in.RequestID,
		"subject":    in.Subject,
		"node_name":  in.NodeName,
		"protocol":   in.Protocol,
		"model":      in.Model,
		"action":     action,
		"hits":       hits,
		"reason":     reason,
	})
}
