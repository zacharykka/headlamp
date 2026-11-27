package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/store"
)

const (
	// ProtocolVersion is the MCP protocol version sent by Headlamp's programmatic client.
	ProtocolVersion = "2025-03-26"

	// JSON-RPC 2.0 error codes returned by Headlamp's MCP gateway.
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeInternalError  = -32603
	CodeUnauthorized   = -32001
	CodeToolDenied     = -32003

	// Audit log status values matching store.MCPAuditLog.Status.
	AuditStatusOK      = "ok"
	AuditStatusDenied  = "denied"
	AuditStatusBlocked = "blocked"
	AuditStatusError   = "error"

	defaultMaxRequestBodyBytes  = 16 << 20 // 16 MiB
	defaultMaxResponseBodyBytes = 16 << 20 // 16 MiB
	defaultClientTimeout        = 30 * time.Second
	maxAuditArgsPreviewBytes = 2048
	blockedArgsPlaceholder   = "[BLOCKED BY GUARDRAIL]"
	deniedArgsPlaceholder    = "[DENIED BY POLICY]"
	authErrorArgsPlaceholder = "[REDACTED]"
)

var (
	// ErrBlockedAddress is returned when an MCP upstream resolves to a blocked SSRF destination.
	ErrBlockedAddress = errors.New("mcp: blocked upstream IP address")
	// ErrServerNotFound is returned when the requested MCP server does not exist or is disabled.
	ErrServerNotFound = errors.New("mcp: server not found")
	// ErrToolDenied is returned when policy denies access to an MCP tool.
	ErrToolDenied = errors.New("mcp: tool denied by policy")
	// ErrToolBlocked is returned when guardrails block an MCP tool call.
	ErrToolBlocked = errors.New("mcp: tool blocked by guardrail")
)

// Authorizer checks whether a principal is permitted to view or invoke a namespaced
// MCP tool ("<server_name>/<tool_name>"). Satisfied directly by *policy.Evaluator.
type Authorizer interface {
	AuthorizeMCPTool(ctx context.Context, p *auth.Principal, tool string) (allowed bool, reason string, err error)
}

// GuardrailRequest carries an MCP tool call's arguments payload for pre-request inspection.
type GuardrailRequest struct {
	RequestID string
	Principal *auth.Principal
	Protocol  string // "mcp"
	Model     string // "<server_name>/<tool_name>"
	Body      []byte
}

// GuardrailDecision describes the outcome of pre-request guardrail inspection on MCP tool arguments.
type GuardrailDecision struct {
	Action       string   // allow | log_only | redact | modify | block
	ModifiedBody []byte   // Rewritten JSON payload when Action is redact/modify
	Hits         []string // Matched rule/webhook IDs
	Reason       string   // Human-readable reason when Action == "block"
	StatusCode   int      // Optional status hint (400 / 403 / 503)
}

// GuardrailInspector optionally inspects, redacts, or blocks MCP tools/call params.arguments.
type GuardrailInspector interface {
	Inspect(ctx context.Context, req GuardrailRequest) (*GuardrailDecision, error)
}

// GatewayConfig configures Headlamp's MCP reverse proxy and programmatic MCP client.
type GatewayConfig struct {
	Store                store.Store
	Authorizer           Authorizer
	Guardrails           GuardrailInspector
	HTTPClient           *http.Client
	BlockLoopback        bool
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	ClientTimeout        time.Duration
	Logf                 func(format string, args ...any)
}

// ToolDefinition describes a single MCP tool returned by tools/list.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// AuthorizedServerTools holds the enabled server metadata and policy-filtered tools for a principal.
type AuthorizedServerTools struct {
	Name      string           `json:"name"`
	Transport string           `json:"transport"`
	Enabled   bool             `json:"enabled"`
	Tools     []ToolDefinition `json:"tools"`
	Error     string           `json:"error,omitempty"`
}

// ToolCallResult holds the flattened text result of a programmatic tools/call invocation.
type ToolCallResult struct {
	Result     string `json:"result"`
	IsError    bool   `json:"is_error"`
	DurationMS int64  `json:"duration_ms"`
}

type jsonRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

func (m jsonRPCMessage) hasID() bool {
	trimmed := bytes.TrimSpace(m.ID)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func canonicalRPCID(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err == nil {
		return compact.String()
	}
	return string(trimmed)
}

func makeJSONRPCErrorBytes(id json.RawMessage, code int, message string) []byte {
	resp := jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
	if !resp.hasID() {
		resp.ID = json.RawMessage("null")
	}
	b, _ := json.Marshal(resp)
	return b
}
