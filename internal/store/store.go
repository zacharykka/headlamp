package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
)

const (
	SourceConfig  = "config"
	SourceLocal   = "local"
	SourceBuiltin = "builtin"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// Provider represents an upstream LLM provider configuration.
// APIKey is held in plaintext in memory and always stored encrypted at rest.
type Provider struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	BaseURL     string    `json:"base_url"`
	APIKey      string    `json:"-"`
	Passthrough bool      `json:"passthrough"`
	Models      []string  `json:"models"`
	Enabled     bool      `json:"enabled"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RouteTarget identifies a concrete upstream provider and model ID.
type RouteTarget struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// ModelRoute maps an exposed virtual model alias to an upstream provider/model with optional fallbacks and pricing overrides.
type ModelRoute struct {
	Alias                    string        `json:"alias"`
	ProviderName             string        `json:"provider_name"`
	UpstreamModel            string        `json:"upstream_model"`
	Fallbacks                []RouteTarget `json:"fallbacks"`
	InputCostPerMillion      *float64      `json:"input_cost_per_million,omitempty"`
	OutputCostPerMillion     *float64      `json:"output_cost_per_million,omitempty"`
	CacheReadCostPerMillion  *float64      `json:"cache_read_cost_per_million,omitempty"`
	CacheWriteCostPerMillion *float64      `json:"cache_write_cost_per_million,omitempty"`
	Enabled                  bool          `json:"enabled"`
	Source                   string        `json:"source"`
	CreatedAt                time.Time     `json:"created_at"`
	UpdatedAt                time.Time     `json:"updated_at"`
}

// Budget configures rate limiting and USD spend limits for a scope ("*", "tag:<name>", or user subject).
type Budget struct {
	Scope         string    `json:"scope"`
	RPM           int       `json:"rpm"`
	TPM           int64     `json:"tpm"`
	MaxConcurrent int       `json:"max_concurrent"`
	DailyUSD      *float64  `json:"daily_usd"`
	MonthlyUSD    *float64  `json:"monthly_usd"`
	SoftAlertPct  int       `json:"soft_alert_pct"`
	Enabled       bool      `json:"enabled"`
	Source        string    `json:"source"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GuardrailRule defines a built-in or custom regex secret/PII detection rule.
type GuardrailRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"` // secret | pii | custom
	Pattern   string    `json:"pattern"`
	Action    string    `json:"action"` // log_only | redact | block
	Builtin   bool      `json:"builtin"`
	Enabled   bool      `json:"enabled"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Webhook represents a synchronous pre-request review or asynchronous event webhook.
// Secret is held in plaintext in memory and always stored encrypted at rest.
type Webhook struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Type      string    `json:"type"` // sync_review | async_event
	Secret    string    `json:"-"`
	Events    []string  `json:"events"`
	TimeoutMS int       `json:"timeout_ms"`
	FailOpen  bool      `json:"fail_open"`
	Enabled   bool      `json:"enabled"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditSettings holds runtime-editable audit payload retention settings persisted in runtime_settings.
type AuditSettings struct {
	StorePayloads bool      `json:"store_payloads"`
	RetentionDays int       `json:"retention_days"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// UsageLog records a single proxied LLM request for billing and telemetry.
type UsageLog struct {
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	RequestID        string    `json:"request_id"`
	Subject          string    `json:"subject"`
	DisplayName      string    `json:"display_name"`
	NodeName         string    `json:"node_name"`
	NodeIP           string    `json:"node_ip"`
	Tags             []string  `json:"tags"`
	AuthSource       string    `json:"auth_source"`
	ProviderName     string    `json:"provider_name"`
	ProviderType     string    `json:"provider_type"`
	RequestedModel   string    `json:"requested_model"`
	UpstreamModel    string    `json:"upstream_model"`
	Protocol         string    `json:"protocol"`
	Endpoint         string    `json:"endpoint"`
	Stream           bool      `json:"stream"`
	Translated       bool      `json:"translated"`
	InputTokens      int64     `json:"input_tokens"`
	OutputTokens     int64     `json:"output_tokens"`
	CacheReadTokens  int64     `json:"cache_read_tokens"`
	CacheWriteTokens int64     `json:"cache_write_tokens"`
	ReasoningTokens  int64     `json:"reasoning_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	CostUSD          float64   `json:"cost_usd"`
	LatencyMS        int64     `json:"latency_ms"`
	TTFTMS           int64     `json:"ttft_ms"`
	StatusCode       int       `json:"status_code"`
	ErrorMessage     string    `json:"error_message"`
	GuardrailAction  string    `json:"guardrail_action"`
	GuardrailHits    []string  `json:"guardrail_hits"`
}

// UsageFilter scopes usage log queries and aggregate summaries.
type UsageFilter struct {
	Subject       string
	Tag           string // Matches rows where subject == Tag or Tag is in tags_json
	ProviderName  string
	Model         string
	StatusCode    int
	ErrorsOnly    bool
	GuardrailOnly bool
	Since         time.Time
	Until         time.Time
	Limit         int
	Offset        int
}

// UsageSummary holds aggregated token and cost totals matching a UsageFilter.
type UsageSummary struct {
	RequestCount     int64   `json:"request_count"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

// UsageExtendedSummary extends UsageSummary with error counts and P95 latency for dashboards.
type UsageExtendedSummary struct {
	UsageSummary
	ErrorCount   int64 `json:"error_count"`
	P95LatencyMS int64 `json:"p95_latency_ms"`
}

// UsageTimeBucket holds time-series metrics for one hour or day bucket.
type UsageTimeBucket struct {
	Bucket   string  `json:"bucket"`
	Requests int64   `json:"requests"`
	Tokens   int64   `json:"tokens"`
	CostUSD  float64 `json:"cost_usd"`
	Errors   int64   `json:"errors"`
}

// SubjectUsageStat holds aggregated usage for a single subject (user or tag).
type SubjectUsageStat struct {
	Subject  string  `json:"subject"`
	Requests int64   `json:"requests"`
	Tokens   int64   `json:"tokens"`
	CostUSD  float64 `json:"cost_usd"`
}

// ModelUsageStat holds aggregated usage for a requested model and provider pair.
type ModelUsageStat struct {
	Model    string  `json:"model"`
	Provider string  `json:"provider"`
	Requests int64   `json:"requests"`
	Tokens   int64   `json:"tokens"`
	CostUSD  float64 `json:"cost_usd"`
}

// AuditPayload holds optional request/response bodies associated with a UsageLog.
type AuditPayload struct {
	ID              string            `json:"id"`
	UsageLogID      string            `json:"usage_log_id"`
	CreatedAt       time.Time         `json:"created_at"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	Redacted        bool              `json:"redacted"`
}

// MCPServer represents an upstream remote MCP server registered in Headlamp.
// AuthToken is held in plaintext in memory and always stored encrypted at rest.
type MCPServer struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Transport  string    `json:"transport"` // streamable_http | sse
	AuthType   string    `json:"auth_type"` // none | bearer | header | basic
	AuthHeader string    `json:"auth_header"`
	AuthToken  string    `json:"-"`
	Enabled    bool      `json:"enabled"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// MCPAuditLog records a single proxied or chat-triggered MCP tool or method invocation.
type MCPAuditLog struct {
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	RequestID        string    `json:"request_id"`
	Subject          string    `json:"subject"`
	DisplayName      string    `json:"display_name"`
	NodeName         string    `json:"node_name"`
	NodeIP           string    `json:"node_ip"`
	Tags             []string  `json:"tags"`
	AuthSource       string    `json:"auth_source"`
	ServerName       string    `json:"server_name"`
	Method           string    `json:"method"`
	ToolName         string    `json:"tool_name"`
	Status           string    `json:"status"` // ok | denied | blocked | error
	LatencyMS        int64     `json:"latency_ms"`
	ErrorMessage     string    `json:"error_message"`
	ArgumentsPreview string    `json:"arguments_preview"`
}

// MCPAuditFilter scopes MCP audit log queries.
type MCPAuditFilter struct {
	ServerName string
	Subject    string
	ToolName   string
	Status     string
	Since      time.Time
	Until      time.Time
	Limit      int
	Offset     int
}

// ChatToolEvent records one MCP tool invocation performed during an assistant turn.
type ChatToolEvent struct {
	ID         string          `json:"id"`
	Server     string          `json:"server"`
	Tool       string          `json:"tool"`
	Arguments  json.RawMessage `json:"arguments"`
	Result     string          `json:"result"`
	IsError    bool            `json:"is_error"`
	DurationMS int64           `json:"duration_ms"`
}

// ChatSession represents a user-owned conversation in Team Web Chat.
type ChatSession struct {
	ID           string    `json:"id"`
	Subject      string    `json:"subject"`
	Title        string    `json:"title"`
	Model        string    `json:"model"`
	MCPServers   []string  `json:"mcp_servers"`
	SystemPrompt string    `json:"system_prompt"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ChatMessage stores a single turn within a ChatSession.
type ChatMessage struct {
	ID           string          `json:"id"`
	SessionID    string          `json:"session_id"`
	Role         string          `json:"role"` // user | assistant | system | tool
	Content      string          `json:"content"`
	ToolEvents   []ChatToolEvent `json:"tool_events"`
	Model        string          `json:"model"`
	InputTokens  int64           `json:"input_tokens"`
	OutputTokens int64           `json:"output_tokens"`
	CostUSD      float64         `json:"cost_usd"`
	CreatedAt    time.Time       `json:"created_at"`
}

// NewStore opens a SQLite or PostgreSQL Store according to storageCfg.Driver.
func NewStore(ctx context.Context, storageCfg config.StorageConfig, cipher *crypto.Cipher) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(storageCfg.Driver)) {
	case "", config.StorageDriverSQLite:
		return NewSQLiteStore(ctx, storageCfg.DSN, cipher)
	case config.StorageDriverPostgres:
		return NewPostgresStore(ctx, storageCfg.DSN, cipher)
	default:
		return nil, fmt.Errorf("store: unsupported storage driver %q (expected sqlite or postgres)", storageCfg.Driver)
	}
}

// Store defines Headlamp's persistence interface.
type Store interface {
	Close() error
	Migrate(ctx context.Context) error
	SyncConfig(ctx context.Context, cfg *config.Config) error

	// Providers
	UpsertProvider(ctx context.Context, p Provider) error
	GetProvider(ctx context.Context, name string) (*Provider, error)
	ListProviders(ctx context.Context) ([]Provider, error)
	DeleteProvider(ctx context.Context, name string) error

	// Model routes
	UpsertModelRoute(ctx context.Context, r ModelRoute) error
	GetModelRoute(ctx context.Context, alias string) (*ModelRoute, error)
	ListModelRoutes(ctx context.Context) ([]ModelRoute, error)
	DeleteModelRoute(ctx context.Context, alias string) error

	// Budgets
	UpsertBudget(ctx context.Context, b Budget) error
	GetBudget(ctx context.Context, scope string) (*Budget, error)
	ListBudgets(ctx context.Context) ([]Budget, error)
	DeleteBudget(ctx context.Context, scope string) error

	// Guardrail rules
	UpsertGuardrailRule(ctx context.Context, r GuardrailRule) error
	GetGuardrailRule(ctx context.Context, id string) (*GuardrailRule, error)
	ListGuardrailRules(ctx context.Context) ([]GuardrailRule, error)
	DeleteGuardrailRule(ctx context.Context, id string) error

	// Webhooks
	UpsertWebhook(ctx context.Context, w Webhook) error
	GetWebhook(ctx context.Context, id string) (*Webhook, error)
	ListWebhooks(ctx context.Context) ([]Webhook, error)
	DeleteWebhook(ctx context.Context, id string) error

	// MCP servers
	UpsertMCPServer(ctx context.Context, srv MCPServer) error
	GetMCPServer(ctx context.Context, name string) (*MCPServer, error)
	ListMCPServers(ctx context.Context) ([]MCPServer, error)
	DeleteMCPServer(ctx context.Context, name string) error

	// MCP audit logs
	InsertMCPAuditLog(ctx context.Context, log MCPAuditLog) error
	QueryMCPAuditLogs(ctx context.Context, filter MCPAuditFilter) ([]MCPAuditLog, error)

	// Chat sessions & messages (strict per-subject ownership enforcement)
	CreateChatSession(ctx context.Context, session ChatSession) (*ChatSession, error)
	GetChatSession(ctx context.Context, subject, id string) (*ChatSession, error)
	ListChatSessions(ctx context.Context, subject string, limit, offset int) ([]ChatSession, error)
	UpdateChatSession(ctx context.Context, subject string, session ChatSession) (*ChatSession, error)
	DeleteChatSession(ctx context.Context, subject, id string) error
	InsertChatMessage(ctx context.Context, subject string, msg ChatMessage) (*ChatMessage, error)
	ListChatMessages(ctx context.Context, subject, sessionID string) ([]ChatMessage, error)
	DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error

	// Runtime settings
	GetAuditSettings(ctx context.Context) (*AuditSettings, error)
	SetAuditSettings(ctx context.Context, settings AuditSettings) error

	// Usage logs & dashboard analytics
	InsertUsageLog(ctx context.Context, log UsageLog) error
	GetUsageLog(ctx context.Context, id string) (*UsageLog, error)
	QueryUsageLogs(ctx context.Context, filter UsageFilter) ([]UsageLog, error)
	SummarizeUsage(ctx context.Context, filter UsageFilter) (UsageSummary, error)
	SummarizeUsageExtended(ctx context.Context, filter UsageFilter) (UsageExtendedSummary, error)
	QueryUsageSeries(ctx context.Context, filter UsageFilter, bucket string) ([]UsageTimeBucket, error)
	QueryTopSubjects(ctx context.Context, filter UsageFilter, limit int) ([]SubjectUsageStat, error)
	QueryTopModels(ctx context.Context, filter UsageFilter, limit int) ([]ModelUsageStat, error)

	// Audit payloads & retention
	InsertAuditPayload(ctx context.Context, payload AuditPayload) error
	GetAuditPayloadByUsageLogID(ctx context.Context, usageLogID string) (*AuditPayload, error)
	PurgeAuditPayloads(ctx context.Context, olderThan time.Time) (int64, error)
}
