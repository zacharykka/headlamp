package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
)

// Canonical wire protocol identifiers shared with metering and telemetry observers.
const (
	ProtocolOpenAIChat        = "openai_chat"
	ProtocolOpenAIResponses   = "openai_responses"
	ProtocolOpenAIEmbeddings  = "openai_embeddings"
	ProtocolAnthropicMessages = "anthropic_messages"
	ProtocolGemini            = "gemini"
	ProtocolOllama            = "ollama"
)

// Authorizer checks whether an authenticated Principal may access a model and
// filters model listings according to active policies/grants.
type Authorizer interface {
	AuthorizeModel(ctx context.Context, p *auth.Principal, model string) (allowed bool, reason string, err error)
	IsModelDenied(ctx context.Context, p *auth.Principal, model string) (denied bool, reason string, err error)
	FilterModels(ctx context.Context, p *auth.Principal, models []string) ([]string, error)
}

// CostOverride carries optional per-route USD-per-1M-token pricing overrides
// configured on a store.ModelRoute.
type CostOverride struct {
	Input      *float64
	Output     *float64
	CacheRead  *float64
	CacheWrite *float64
}

// TelemetryStart holds metadata captured when an upstream LLM call begins.
// Protocol identifies the wire protocol of the events delivered to StreamObserver
// (equal to the upstream protocol so metering parses lossless token usage that
// matches ProviderType's billing inclusivity rules).
type TelemetryStart struct {
	RequestID       string
	Timestamp       time.Time
	Principal       *auth.Principal
	Protocol        string
	IngressProtocol string
	Endpoint        string
	Provider        string
	ProviderType    string
	RequestedModel  string
	UpstreamModel   string
	Stream          bool
	Translated      bool
	RequestHeaders  http.Header
	RequestBody     []byte
	CostOverride    *CostOverride
	GuardrailAction string
	GuardrailHits   []string
}

// TelemetryFinish holds final outcome and timing metrics when a request completes.
type TelemetryFinish struct {
	StatusCode   int
	LatencyMS    int64
	TTFTMS       int64
	ErrorMessage string
}

// StreamObserver receives side-channel SSE frames or non-streaming JSON bodies
// from a single proxied request for token accounting and optional payload audit.
type StreamObserver interface {
	SetResponseHeaders(headers map[string]string)
	OnSSEEvent(eventName string, data []byte)
	OnJSONResponse(body []byte)
	Finish(TelemetryFinish)
}

// TokenReporter is an optional interface that a StreamObserver may implement
// to expose exact normalized total token usage for QuotaTicket.Release.
type TokenReporter interface {
	TotalTokens() int64
}

// TelemetryFactory creates a StreamObserver for each proxied LLM request.
type TelemetryFactory interface {
	Start(ctx context.Context, info TelemetryStart) StreamObserver
}

// QuotaTicket represents an acquired rate-limit and concurrency slot.
// Release MUST be invoked once when the request completes.
type QuotaTicket interface {
	Release(totalTokens int64)
}

// QuotaRejection describes why QuotaLimiter.Acquire rejected a request (HTTP 429).
type QuotaRejection struct {
	Scope         string
	Metric        string
	Reason        string
	RetryAfterSec int
}

// QuotaLimiter enforces RPM, TPM, max concurrency, and spend budgets before forwarding.
type QuotaLimiter interface {
	Acquire(ctx context.Context, p *auth.Principal) (QuotaTicket, *QuotaRejection, error)
}

// GuardrailRequest carries metadata and raw JSON body for pre-request inspection.
type GuardrailRequest struct {
	RequestID string
	Principal *auth.Principal
	Protocol  string
	Model     string
	Body      []byte
}

// GuardrailDecision is the outcome of local regex and/or sync_review webhook inspection.
type GuardrailDecision struct {
	Action       string   // allow | log_only | redact | modify | block
	ModifiedBody []byte   // Rewritten valid JSON when Action is redact or modify
	Hits         []string // Matched rule IDs / webhook IDs
	Reason       string   // Human-readable block reason when Action == "block"
	StatusCode   int      // Optional HTTP status when blocked (defaults to 400)
}

// GuardrailInspector inspects and optionally redacts or blocks incoming LLM request payloads.
type GuardrailInspector interface {
	Inspect(ctx context.Context, req GuardrailRequest) (*GuardrailDecision, error)
}

// EventDispatcher emits asynchronous governance/operational events (e.g. upstream.fallback, upstream.error).
type EventDispatcher interface {
	Emit(eventType string, payload any)
}

type noopObserver struct{}

func (noopObserver) SetResponseHeaders(map[string]string) {}
func (noopObserver) OnSSEEvent(string, []byte)            {}
func (noopObserver) OnJSONResponse([]byte)                {}
func (noopObserver) Finish(TelemetryFinish)               {}
