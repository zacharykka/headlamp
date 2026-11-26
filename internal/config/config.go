package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const (
	TLSModeNone      = "none"
	TLSModeStatic    = "static"
	TLSModeACMEDNS01 = "acme_dns01"

	StorageDriverSQLite   = "sqlite"
	StorageDriverPostgres = "postgres"

	ProviderTypeOpenAI    = "openai"
	ProviderTypeAnthropic = "anthropic"
	ProviderTypeGemini    = "gemini"
	ProviderTypeOllama    = "ollama"
)

// Config holds the full Headlamp gateway configuration.
// Authorization is driven purely by Tailnet/Headscale grants (or synthesized grants for static API tokens and dev mode).
type Config struct {
	Server    ServerConfig     `yaml:"server"`
	Storage   StorageConfig    `yaml:"storage"`
	Providers []ProviderConfig `yaml:"providers"`
	Routes    []RouteConfig    `yaml:"routes"`
	Audit     AuditConfig      `yaml:"audit"`

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
	Mode        string `yaml:"mode"` // none | static | acme_dns01
	CertFile    string `yaml:"cert_file"`
	KeyFile     string `yaml:"key_file"`
	Domain      string `yaml:"domain"`
	ACMEEmail   string `yaml:"acme_email"`
	DNSProvider string `yaml:"dns_provider"`
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

// AuditConfig configures optional request/response body storage and retention.
type AuditConfig struct {
	StorePayloads bool `yaml:"store_payloads"`
	RetentionDays int  `yaml:"retention_days"`
}

// DefaultConfig returns a Config populated with safe M1 defaults.
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
	if v, ok := lookupEnv("HEADLAMP_TLS_DNS_PROVIDER"); ok {
		cfg.Server.TLS.DNSProvider = strings.TrimSpace(v)
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
	for i := range cfg.Server.APITokens {
		cfg.Server.APITokens[i].Token = expandBracedEnv(cfg.Server.APITokens[i].Token, lookupEnv)
	}
	for i := range cfg.Providers {
		cfg.Providers[i].APIKey = expandBracedEnv(cfg.Providers[i].APIKey, lookupEnv)
	}
}

func applyDerivedDefaults(cfg *Config) {
	cfg.Server.TLS.Mode = strings.ToLower(strings.TrimSpace(cfg.Server.TLS.Mode))
	if cfg.Server.TLS.Mode == "" {
		cfg.Server.TLS.Mode = TLSModeNone
	}

	if cfg.Server.TSNet.ListenPort == 0 {
		if cfg.Server.TLS.Mode == TLSModeNone {
			cfg.Server.TSNet.ListenPort = 80
		} else {
			cfg.Server.TSNet.ListenPort = 443
		}
	}

	if cfg.Server.DevMode {
		if strings.TrimSpace(cfg.Server.DevUser) == "" {
			cfg.Server.DevUser = "dev@local"
		}
		if len(cfg.Server.DevRoles) == 0 {
			cfg.Server.DevRoles = []string{"admin", "user"}
		}
	}

	cfg.Storage.Driver = strings.ToLower(strings.TrimSpace(cfg.Storage.Driver))
	if cfg.Storage.Driver == "" {
		cfg.Storage.Driver = StorageDriverSQLite
	}

	for i := range cfg.Providers {
		cfg.Providers[i].Name = strings.TrimSpace(cfg.Providers[i].Name)
		cfg.Providers[i].Type = strings.ToLower(strings.TrimSpace(cfg.Providers[i].Type))
		cfg.Providers[i].BaseURL = strings.TrimRight(strings.TrimSpace(cfg.Providers[i].BaseURL), "/")
		if cfg.Providers[i].BaseURL == "" {
			cfg.Providers[i].BaseURL = DefaultBaseURL(cfg.Providers[i].Type)
		}
	}
	for i := range cfg.Routes {
		cfg.Routes[i].Alias = strings.TrimSpace(cfg.Routes[i].Alias)
		cfg.Routes[i].Provider = strings.TrimSpace(cfg.Routes[i].Provider)
		cfg.Routes[i].Model = strings.TrimSpace(cfg.Routes[i].Model)
	}
}

// Validate checks configuration invariants and returns a descriptive error on misconfiguration.
func (c *Config) Validate() error {
	var errs []string

	if !c.Server.TSNet.Enabled && strings.TrimSpace(c.Server.LocalListen) == "" {
		errs = append(errs, "at least one listener must be enabled (server.tsnet.enabled or server.local_listen)")
	}

	if c.Server.DevMode {
		if strings.TrimSpace(c.Server.LocalListen) == "" || !isLoopbackListenAddr(c.Server.LocalListen) {
			errs = append(errs, fmt.Sprintf("server.dev_mode requires server.local_listen to bind a loopback host (127.0.0.1, ::1, or localhost), got %q", c.Server.LocalListen))
		}
	}

	if c.Server.TSNet.Enabled {
		if strings.TrimSpace(c.Server.TSNet.Hostname) == "" {
			errs = append(errs, "server.tsnet.hostname is required when tsnet is enabled")
		}
		if strings.TrimSpace(c.Server.TSNet.StateDir) == "" {
			errs = append(errs, "server.tsnet.state_dir is required when tsnet is enabled")
		}
		if c.Server.TSNet.ListenPort < 1 || c.Server.TSNet.ListenPort > 65535 {
			errs = append(errs, fmt.Sprintf("server.tsnet.listen_port must be between 1 and 65535, got %d", c.Server.TSNet.ListenPort))
		}
		if c.Server.TSNet.ControlURL != "" {
			if err := validateHTTPURL(c.Server.TSNet.ControlURL); err != nil {
				errs = append(errs, fmt.Sprintf("server.tsnet.control_url: %v", err))
			}
		}
	}

	switch c.Server.TLS.Mode {
	case TLSModeNone:
	case TLSModeStatic:
		if strings.TrimSpace(c.Server.TLS.CertFile) == "" || strings.TrimSpace(c.Server.TLS.KeyFile) == "" {
			errs = append(errs, "server.tls.cert_file and server.tls.key_file are required when tls.mode is static")
		}
	case TLSModeACMEDNS01:
		if strings.TrimSpace(c.Server.TLS.Domain) == "" || strings.TrimSpace(c.Server.TLS.DNSProvider) == "" {
			errs = append(errs, "server.tls.domain and server.tls.dns_provider are required when tls.mode is acme_dns01")
		}
	default:
		errs = append(errs, fmt.Sprintf("server.tls.mode %q must be one of none, static, acme_dns01", c.Server.TLS.Mode))
	}

	seenTokens := make(map[string]struct{}, len(c.Server.APITokens))
	for i, tok := range c.Server.APITokens {
		if strings.TrimSpace(tok.Token) == "" {
			errs = append(errs, fmt.Sprintf("server.api_tokens[%d].token is required", i))
		} else {
			if _, dup := seenTokens[tok.Token]; dup {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].token is duplicated", i))
			}
			seenTokens[tok.Token] = struct{}{}
		}
		if strings.TrimSpace(tok.Subject) == "" {
			errs = append(errs, fmt.Sprintf("server.api_tokens[%d].subject is required", i))
		}
		for _, role := range tok.Roles {
			r := strings.ToLower(strings.TrimSpace(role))
			if r != "" && r != "user" && r != "admin" {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].roles contains invalid role %q (must be user or admin)", i, role))
			}
		}
		for _, pat := range tok.AllowModels {
			if !doublestar.ValidatePattern(pat) {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].allow_models invalid glob %q", i, pat))
			}
		}
		for _, pat := range tok.DenyModels {
			if !doublestar.ValidatePattern(pat) {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].deny_models invalid glob %q", i, pat))
			}
		}
		for _, pat := range tok.AllowMCPTools {
			if !doublestar.ValidatePattern(pat) {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].allow_mcp_tools invalid glob %q", i, pat))
			}
		}
		for _, pat := range tok.DenyMCPTools {
			if !doublestar.ValidatePattern(pat) {
				errs = append(errs, fmt.Sprintf("server.api_tokens[%d].deny_mcp_tools invalid glob %q", i, pat))
			}
		}
	}

	switch c.Storage.Driver {
	case StorageDriverSQLite, StorageDriverPostgres:
	default:
		errs = append(errs, fmt.Sprintf("storage.driver %q must be sqlite or postgres", c.Storage.Driver))
	}
	if strings.TrimSpace(c.Storage.DSN) == "" {
		errs = append(errs, "storage.dsn is required")
	}

	providersByName := make(map[string]ProviderConfig, len(c.Providers))
	for i, p := range c.Providers {
		if p.Name == "" {
			errs = append(errs, fmt.Sprintf("providers[%d].name is required", i))
			continue
		}
		if _, dup := providersByName[p.Name]; dup {
			errs = append(errs, fmt.Sprintf("providers[%d].name %q is duplicated", i, p.Name))
		}
		providersByName[p.Name] = p

		switch p.Type {
		case ProviderTypeOpenAI, ProviderTypeAnthropic, ProviderTypeGemini, ProviderTypeOllama:
		default:
			errs = append(errs, fmt.Sprintf("providers[%d].type %q must be one of openai, anthropic, gemini, ollama", i, p.Type))
		}
		if err := validateHTTPURL(p.BaseURL); err != nil {
			errs = append(errs, fmt.Sprintf("providers[%d].base_url: %v", i, err))
		}
	}

	seenAliases := make(map[string]struct{}, len(c.Routes))
	for i, r := range c.Routes {
		if r.Alias == "" {
			errs = append(errs, fmt.Sprintf("routes[%d].alias is required", i))
		} else {
			if _, dup := seenAliases[r.Alias]; dup {
				errs = append(errs, fmt.Sprintf("routes[%d].alias %q is duplicated", i, r.Alias))
			}
			seenAliases[r.Alias] = struct{}{}
		}
		if r.Provider == "" {
			errs = append(errs, fmt.Sprintf("routes[%d].provider is required", i))
		} else if _, ok := providersByName[r.Provider]; !ok {
			errs = append(errs, fmt.Sprintf("routes[%d].provider %q does not match any configured provider", i, r.Provider))
		}
		if r.Model == "" {
			errs = append(errs, fmt.Sprintf("routes[%d].model is required", i))
		}
		for j, fb := range r.Fallbacks {
			if strings.TrimSpace(fb.Provider) == "" {
				errs = append(errs, fmt.Sprintf("routes[%d].fallbacks[%d].provider is required", i, j))
			} else if _, ok := providersByName[fb.Provider]; !ok {
				errs = append(errs, fmt.Sprintf("routes[%d].fallbacks[%d].provider %q does not match any configured provider", i, j, fb.Provider))
			}
			if strings.TrimSpace(fb.Model) == "" {
				errs = append(errs, fmt.Sprintf("routes[%d].fallbacks[%d].model is required", i, j))
			}
		}
		for name, cost := range map[string]*float64{
			"input_cost_per_million":       r.InputCostPerMillion,
			"output_cost_per_million":      r.OutputCostPerMillion,
			"cache_read_cost_per_million":  r.CacheReadCostPerMillion,
			"cache_write_cost_per_million": r.CacheWriteCostPerMillion,
		} {
			if cost != nil && *cost < 0 {
				errs = append(errs, fmt.Sprintf("routes[%d].%s must be non-negative", i, name))
			}
		}
	}

	if c.Audit.RetentionDays < 0 {
		errs = append(errs, fmt.Sprintf("audit.retention_days must be >= 0, got %d", c.Audit.RetentionDays))
	}

	if len(errs) > 0 {
		return errors.New("config validation failed:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url %q must use http or https scheme", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("url %q must include a host", raw)
	}
	return nil
}
