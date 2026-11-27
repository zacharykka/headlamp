package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	TLSModeNone      = "none"
	TLSModeStatic    = "static"
	TLSModeACMEDNS01 = "acme_dns01"

	DNSProviderCloudflare = "cloudflare"
	DNSProviderWebhook    = "webhook"

	// DefaultACMEDirectoryURL is Let's Encrypt's production ACME v2 directory URL.
	DefaultACMEDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

	StorageDriverSQLite   = "sqlite"
	StorageDriverPostgres = "postgres"

	ProviderTypeOpenAI    = "openai"
	ProviderTypeAnthropic = "anthropic"
	ProviderTypeGemini    = "gemini"
	ProviderTypeOllama    = "ollama"

	GuardrailCategorySecret = "secret"
	GuardrailCategoryPII    = "pii"
	GuardrailCategoryCustom = "custom"

	GuardrailActionLogOnly = "log_only"
	GuardrailActionRedact  = "redact"
	GuardrailActionBlock   = "block"

	WebhookTypeSyncReview = "sync_review"
	WebhookTypeAsyncEvent = "async_event"

	WebhookEventBudgetThreshold    = "budget.threshold"
	WebhookEventBudgetExceeded     = "budget.exceeded"
	WebhookEventGuardrailTriggered = "guardrail.triggered"
	WebhookEventUpstreamFallback   = "upstream.fallback"
	WebhookEventUpstreamError      = "upstream.error"

	MCPTransportStreamableHTTP = "streamable_http"
	MCPTransportSSE            = "sse"

	MCPAuthNone   = "none"
	MCPAuthBearer = "bearer"
	MCPAuthHeader = "header"
	MCPAuthBasic  = "basic"
)

// Config holds the full Headlamp gateway configuration.
// Authorization is driven purely by Tailnet/Headscale grants (or synthesized grants for static API tokens and dev mode).
type Config struct {
	Server     ServerConfig      `yaml:"server"`
	Storage    StorageConfig     `yaml:"storage"`
	Providers  []ProviderConfig  `yaml:"providers"`
	Routes     []RouteConfig     `yaml:"routes"`
	Budgets    []BudgetConfig    `yaml:"budgets"`
	Guardrails GuardrailsConfig  `yaml:"guardrails"`
	Webhooks   []WebhookConfig   `yaml:"webhooks"`
	MCPServers []MCPServerConfig `yaml:"mcp_servers"`
	Audit      AuditConfig       `yaml:"audit"`

	// MasterKey is populated exclusively from HEADLAMP_MASTER_KEY (never from YAML).
	MasterKey string `yaml:"-"`
}

// ServerConfig controls Tailnet/local listeners, TLS, dev mock mode, and fallback API tokens.
type ServerConfig struct {
	TSNet                  TSNetConfig      `yaml:"tsnet"`
	TLS                    TLSConfig        `yaml:"tls"`
	LocalListen            string           `yaml:"local_listen"`
	DevMode                bool             `yaml:"dev_mode"`
	DevUser                string           `yaml:"dev_user"`
	DevRoles               []string         `yaml:"dev_roles"`
	DevAllowHeaderOverride bool             `yaml:"dev_allow_header_override"`
	APITokens              []APITokenConfig `yaml:"api_tokens"`
}

// TSNetConfig configures the embedded Tailscale/Headscale tsnet node.
type TSNetConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Hostname   string `yaml:"hostname"`
	ControlURL string `yaml:"control_url"`
	AuthKey    string `yaml:"auth_key"`
	StateDir   string `yaml:"state_dir"`
	Ephemeral  bool   `yaml:"ephemeral"`
	ListenPort int    `yaml:"listen_port"`
}

// TLSConfig configures optional HTTPS termination on the Tailnet listener.
type TLSConfig struct {
	Mode             string `yaml:"mode"` // none | static | acme_dns01
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	Domain           string `yaml:"domain"`
	ACMEEmail        string `yaml:"acme_email"`
	ACMEDirectoryURL string `yaml:"acme_directory_url"` // optional override; empty uses Let's Encrypt production
	DNSProvider      string `yaml:"dns_provider"`       // cloudflare | webhook
	DNSAPIToken      string `yaml:"dns_api_token"`      // env HEADLAMP_TLS_DNS_API_TOKEN
	DNSWebhookURL    string `yaml:"dns_webhook_url"`    // required when dns_provider == "webhook"
}

// APITokenConfig defines a static fallback API token for non-Tailnet callers.
// AllowModels defaults to ["*"] when omitted so simple tokens work out of the box.
type APITokenConfig struct {
	Name          string   `yaml:"name"`
	Token         string   `yaml:"token"`
	Subject       string   `yaml:"subject"`
	DisplayName   string   `yaml:"display_name"`
	Roles         []string `yaml:"roles"`
	Tags          []string `yaml:"tags"`
	AllowModels   []string `yaml:"allow_models"`
	DenyModels    []string `yaml:"deny_models"`
	AllowMCPTools []string `yaml:"allow_mcp_tools"`
	DenyMCPTools  []string `yaml:"deny_mcp_tools"`
}

// StorageConfig configures the backing database.
type StorageConfig struct {
	Driver string `yaml:"driver"` // sqlite | postgres
	DSN    string `yaml:"dsn"`
}

// ProviderConfig defines an upstream LLM provider.
type ProviderConfig struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"` // openai | anthropic | gemini | ollama
	BaseURL     string   `yaml:"base_url"`
	APIKey      string   `yaml:"api_key"`
	Passthrough bool     `yaml:"passthrough"`
	Models      []string `yaml:"models"`
	Enabled     *bool    `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the provider is enabled (defaults to true when omitted in YAML).
func (p ProviderConfig) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// RouteTarget identifies a concrete upstream provider and model ID.
type RouteTarget struct {
	Provider string `yaml:"provider" json:"provider"`
	Model    string `yaml:"model" json:"model"`
}

// RouteConfig maps a virtual model alias to a primary provider/model and optional fallbacks.
type RouteConfig struct {
	Alias                    string        `yaml:"alias"`
	Provider                 string        `yaml:"provider"`
	Model                    string        `yaml:"model"`
	Fallbacks                []RouteTarget `yaml:"fallbacks"`
	InputCostPerMillion      *float64      `yaml:"input_cost_per_million,omitempty"`
	OutputCostPerMillion     *float64      `yaml:"output_cost_per_million,omitempty"`
	CacheReadCostPerMillion  *float64      `yaml:"cache_read_cost_per_million,omitempty"`
	CacheWriteCostPerMillion *float64      `yaml:"cache_write_cost_per_million,omitempty"`
	Enabled                  *bool         `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the route is enabled (defaults to true when omitted in YAML).
func (r RouteConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// BudgetConfig configures rate limiting (RPM/TPM/concurrency) and USD spend caps for a scope.
// Scope may be "*" (global), "tag:<name>", or a specific user subject.
type BudgetConfig struct {
	Scope         string   `yaml:"scope"`
	RPM           int      `yaml:"rpm"`
	TPM           int64    `yaml:"tpm"`
	MaxConcurrent int      `yaml:"max_concurrent"`
	DailyUSD      *float64 `yaml:"daily_usd,omitempty"`
	MonthlyUSD    *float64 `yaml:"monthly_usd,omitempty"`
	SoftAlertPct  int      `yaml:"soft_alert_pct"`
	Enabled       *bool    `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the budget is enabled (defaults to true when omitted in YAML).
func (b BudgetConfig) IsEnabled() bool {
	if b.Enabled == nil {
		return true
	}
	return *b.Enabled
}

// GuardrailsConfig configures built-in detector seeding and custom regex guardrail rules.
type GuardrailsConfig struct {
	BuiltinDefaults *bool                 `yaml:"builtin_defaults,omitempty"`
	Rules           []GuardrailRuleConfig `yaml:"rules"`
}

// UseBuiltinDefaults reports whether Headlamp's built-in secret/PII detectors should be seeded (defaults to true).
func (g GuardrailsConfig) UseBuiltinDefaults() bool {
	if g.BuiltinDefaults == nil {
		return true
	}
	return *g.BuiltinDefaults
}

// GuardrailRuleConfig defines a regex guardrail rule.
type GuardrailRuleConfig struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Category string `yaml:"category"` // secret | pii | custom
	Pattern  string `yaml:"pattern"`
	Action   string `yaml:"action"` // log_only | redact | block
	Enabled  *bool  `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the guardrail rule is enabled (defaults to true when omitted in YAML).
func (r GuardrailRuleConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// WebhookConfig defines a synchronous pre-request review webhook or an asynchronous event webhook.
type WebhookConfig struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	URL       string   `yaml:"url"`
	Type      string   `yaml:"type"` // sync_review | async_event
	Secret    string   `yaml:"secret"`
	Events    []string `yaml:"events"`
	TimeoutMS int      `yaml:"timeout_ms"`
	FailOpen  *bool    `yaml:"fail_open,omitempty"`
	Enabled   *bool    `yaml:"enabled,omitempty"`
}

// IsFailOpen reports whether sync_review webhook errors allow requests through (defaults to true).
func (w WebhookConfig) IsFailOpen() bool {
	if w.FailOpen == nil {
		return true
	}
	return *w.FailOpen
}

// IsEnabled reports whether the webhook is enabled (defaults to true when omitted in YAML).
func (w WebhookConfig) IsEnabled() bool {
	if w.Enabled == nil {
		return true
	}
	return *w.Enabled
}

// MCPServerConfig defines an upstream remote MCP server proxied by Headlamp.
type MCPServerConfig struct {
	Name       string `yaml:"name"`
	URL        string `yaml:"url"`
	Transport  string `yaml:"transport"` // streamable_http | sse
	AuthType   string `yaml:"auth_type"` // none | bearer | header | basic
	AuthHeader string `yaml:"auth_header"`
	AuthToken  string `yaml:"auth_token"`
	Enabled    *bool  `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether the MCP server is enabled (defaults to true when omitted in YAML).
func (m MCPServerConfig) IsEnabled() bool {
	if m.Enabled == nil {
		return true
	}
	return *m.Enabled
}

// AuditConfig configures optional request/response body storage and retention.
type AuditConfig struct {
	StorePayloads bool `yaml:"store_payloads"`
	RetentionDays int  `yaml:"retention_days"`
}

// DefaultConfig returns a Config populated with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			TSNet: TSNetConfig{
				Enabled:  true,
				Hostname: "headlamp",
				StateDir: "./data",
			},
			TLS: TLSConfig{
				Mode: TLSModeNone,
			},
		},
		Storage: StorageConfig{
			Driver: StorageDriverSQLite,
			DSN:    "./data/headlamp.db",
		},
		Audit: AuditConfig{
			StorePayloads: false,
			RetentionDays: 7,
		},
	}
}

// DefaultBaseURL returns the canonical upstream base URL for a provider type.
func DefaultBaseURL(providerType string) string {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case ProviderTypeOpenAI:
		return "https://api.openai.com"
	case ProviderTypeAnthropic:
		return "https://api.anthropic.com"
	case ProviderTypeGemini:
		return "https://generativelanguage.googleapis.com"
	case ProviderTypeOllama:
		return "http://127.0.0.1:11434"
	default:
		return ""
	}
}

// IsValidWebhookEvent reports whether event is a supported async webhook event name.
func IsValidWebhookEvent(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case WebhookEventBudgetThreshold,
		WebhookEventBudgetExceeded,
		WebhookEventGuardrailTriggered,
		WebhookEventUpstreamFallback,
		WebhookEventUpstreamError,
		"*":
		return true
	default:
		return false
	}
}

// Load loads configuration from path (or HEADLAMP_CONFIG if path is empty),
// applies HEADLAMP_* environment overrides, fills derived defaults, and validates.
// If no config path is provided, Load starts from DefaultConfig() plus environment overrides.
func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		path = strings.TrimSpace(os.Getenv("HEADLAMP_CONFIG"))
	}

	var data []byte
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %q: %w", path, err)
		}
	}

	return parse(data, os.LookupEnv)
}

// LoadFromBytes parses YAML bytes, applies environment overrides and defaults, and validates.
func LoadFromBytes(data []byte) (*Config, error) {
	return parse(data, os.LookupEnv)
}

func parse(data []byte, lookupEnv func(string) (string, bool)) (*Config, error) {
	cfg := DefaultConfig()

	if len(bytes.TrimSpace(data)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: parse yaml: %w", err)
		}
	}

	if err := applyEnvOverrides(cfg, lookupEnv); err != nil {
		return nil, err
	}
	expandSecrets(cfg, lookupEnv)
	applyDerivedDefaults(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config, lookupEnv func(string) (string, bool)) error {
	if v, ok := lookupEnv("HEADLAMP_MASTER_KEY"); ok {
		cfg.MasterKey = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TSNET_ENABLED"); ok && strings.TrimSpace(v) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_TSNET_ENABLED %q: %w", v, err)
		}
		cfg.Server.TSNet.Enabled = b
	}
	if v, ok := lookupEnv("HEADLAMP_HOSTNAME"); ok && strings.TrimSpace(v) != "" {
		cfg.Server.TSNet.Hostname = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TSNET_HOSTNAME"); ok && strings.TrimSpace(v) != "" {
		cfg.Server.TSNet.Hostname = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_CONTROL_URL"); ok {
		cfg.Server.TSNet.ControlURL = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_AUTH_KEY"); ok {
		cfg.Server.TSNet.AuthKey = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_STATE_DIR"); ok && strings.TrimSpace(v) != "" {
		cfg.Server.TSNet.StateDir = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TSNET_EPHEMERAL"); ok && strings.TrimSpace(v) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_TSNET_EPHEMERAL %q: %w", v, err)
		}
		cfg.Server.TSNet.Ephemeral = b
	}
	if v, ok := lookupEnv("HEADLAMP_TSNET_LISTEN_PORT"); ok && strings.TrimSpace(v) != "" {
		port, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_TSNET_LISTEN_PORT %q: %w", v, err)
		}
		cfg.Server.TSNet.ListenPort = port
	}

	if v, ok := lookupEnv("HEADLAMP_TLS_MODE"); ok && strings.TrimSpace(v) != "" {
		cfg.Server.TLS.Mode = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_CERT_FILE"); ok {
		cfg.Server.TLS.CertFile = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_KEY_FILE"); ok {
		cfg.Server.TLS.KeyFile = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_DOMAIN"); ok {
		cfg.Server.TLS.Domain = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_ACME_EMAIL"); ok {
		cfg.Server.TLS.ACMEEmail = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_ACME_DIRECTORY_URL"); ok {
		cfg.Server.TLS.ACMEDirectoryURL = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_DNS_PROVIDER"); ok {
		cfg.Server.TLS.DNSProvider = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_DNS_API_TOKEN"); ok {
		cfg.Server.TLS.DNSAPIToken = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_TLS_DNS_WEBHOOK_URL"); ok {
		cfg.Server.TLS.DNSWebhookURL = strings.TrimSpace(v)
	}

	if v, ok := lookupEnv("HEADLAMP_LOCAL_LISTEN"); ok {
		cfg.Server.LocalListen = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_DEV_MODE"); ok && strings.TrimSpace(v) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_DEV_MODE %q: %w", v, err)
		}
		cfg.Server.DevMode = b
	}
	if v, ok := lookupEnv("HEADLAMP_DEV_USER"); ok && strings.TrimSpace(v) != "" {
		cfg.Server.DevUser = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_DEV_ALLOW_HEADER_OVERRIDE"); ok && strings.TrimSpace(v) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_DEV_ALLOW_HEADER_OVERRIDE %q: %w", v, err)
		}
		cfg.Server.DevAllowHeaderOverride = b
	}

	if v, ok := lookupEnv("HEADLAMP_STORAGE_DRIVER"); ok && strings.TrimSpace(v) != "" {
		cfg.Storage.Driver = strings.TrimSpace(v)
	}
	if v, ok := lookupEnv("HEADLAMP_STORAGE_DSN"); ok && strings.TrimSpace(v) != "" {
		cfg.Storage.DSN = strings.TrimSpace(v)
	}

	if v, ok := lookupEnv("HEADLAMP_AUDIT_STORE_PAYLOADS"); ok && strings.TrimSpace(v) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_AUDIT_STORE_PAYLOADS %q: %w", v, err)
		}
		cfg.Audit.StorePayloads = b
	}
	if v, ok := lookupEnv("HEADLAMP_AUDIT_RETENTION_DAYS"); ok && strings.TrimSpace(v) != "" {
		days, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("config: invalid HEADLAMP_AUDIT_RETENTION_DAYS %q: %w", v, err)
		}
		cfg.Audit.RetentionDays = days
	}

	return nil
}

var bracedEnvPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandBracedEnv expands ${VAR_NAME} placeholders while leaving literal '$' untouched.
func expandBracedEnv(s string, lookupEnv func(string) (string, bool)) string {
	return bracedEnvPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		if val, ok := lookupEnv(name); ok {
			return val
		}
		return ""
	})
}

func expandSecrets(cfg *Config, lookupEnv func(string) (string, bool)) {
	cfg.Server.TSNet.AuthKey = expandBracedEnv(cfg.Server.TSNet.AuthKey, lookupEnv)
	cfg.Server.TLS.DNSAPIToken = expandBracedEnv(cfg.Server.TLS.DNSAPIToken, lookupEnv)
	cfg.Storage.DSN = expandBracedEnv(cfg.Storage.DSN, lookupEnv)
	for i := range cfg.Server.APITokens {
		cfg.Server.APITokens[i].Token = expandBracedEnv(cfg.Server.APITokens[i].Token, lookupEnv)
	}
	for i := range cfg.Providers {
		cfg.Providers[i].APIKey = expandBracedEnv(cfg.Providers[i].APIKey, lookupEnv)
	}
	for i := range cfg.Webhooks {
		cfg.Webhooks[i].Secret = expandBracedEnv(cfg.Webhooks[i].Secret, lookupEnv)
	}
	for i := range cfg.MCPServers {
		cfg.MCPServers[i].AuthToken = expandBracedEnv(cfg.MCPServers[i].AuthToken, lookupEnv)
	}
}
