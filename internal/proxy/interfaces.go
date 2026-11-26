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

// TelemetryFactory creates a StreamObserver for each proxied LLM request.
type TelemetryFactory interface {
	Start(ctx context.Context, info TelemetryStart) StreamObserver
}

type noopObserver struct{}

func (noopObserver) SetResponseHeaders(map[string]string) {}
func (noopObserver) OnSSEEvent(string, []byte)            {}
func (noopObserver) OnJSONResponse([]byte)                {}
func (noopObserver) Finish(TelemetryFinish)               {}
