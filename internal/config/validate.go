package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

func applyDerivedDefaults(cfg *Config) {
	cfg.Server.TLS.Mode = strings.ToLower(strings.TrimSpace(cfg.Server.TLS.Mode))
	if cfg.Server.TLS.Mode == "" {
		cfg.Server.TLS.Mode = TLSModeNone
	}
	cfg.Server.TLS.DNSProvider = strings.ToLower(strings.TrimSpace(cfg.Server.TLS.DNSProvider))
	cfg.Server.TLS.ACMEDirectoryURL = strings.TrimSpace(cfg.Server.TLS.ACMEDirectoryURL)
	cfg.Server.TLS.DNSWebhookURL = strings.TrimSpace(cfg.Server.TLS.DNSWebhookURL)

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
	for i := range cfg.Budgets {
		cfg.Budgets[i].Scope = strings.TrimSpace(cfg.Budgets[i].Scope)
		if cfg.Budgets[i].SoftAlertPct == 0 {
			cfg.Budgets[i].SoftAlertPct = 80
		}
	}
	for i := range cfg.Guardrails.Rules {
		cfg.Guardrails.Rules[i].ID = strings.TrimSpace(cfg.Guardrails.Rules[i].ID)
		cfg.Guardrails.Rules[i].Name = strings.TrimSpace(cfg.Guardrails.Rules[i].Name)
		cfg.Guardrails.Rules[i].Category = strings.ToLower(strings.TrimSpace(cfg.Guardrails.Rules[i].Category))
		if cfg.Guardrails.Rules[i].Category == "" {
			cfg.Guardrails.Rules[i].Category = GuardrailCategoryCustom
		}
		cfg.Guardrails.Rules[i].Action = strings.ToLower(strings.TrimSpace(cfg.Guardrails.Rules[i].Action))
		if cfg.Guardrails.Rules[i].Action == "" {
			cfg.Guardrails.Rules[i].Action = GuardrailActionRedact
		}
	}
	for i := range cfg.Webhooks {
		cfg.Webhooks[i].ID = strings.TrimSpace(cfg.Webhooks[i].ID)
		cfg.Webhooks[i].Name = strings.TrimSpace(cfg.Webhooks[i].Name)
		cfg.Webhooks[i].URL = strings.TrimSpace(cfg.Webhooks[i].URL)
		cfg.Webhooks[i].Type = strings.ToLower(strings.TrimSpace(cfg.Webhooks[i].Type))
		if cfg.Webhooks[i].TimeoutMS == 0 {
			cfg.Webhooks[i].TimeoutMS = 2000
		}
		for j := range cfg.Webhooks[i].Events {
			cfg.Webhooks[i].Events[j] = strings.ToLower(strings.TrimSpace(cfg.Webhooks[i].Events[j]))
		}
	}
	for i := range cfg.MCPServers {
		cfg.MCPServers[i].Name = strings.TrimSpace(cfg.MCPServers[i].Name)
		cfg.MCPServers[i].URL = strings.TrimSpace(cfg.MCPServers[i].URL)
		cfg.MCPServers[i].Transport = strings.ToLower(strings.TrimSpace(cfg.MCPServers[i].Transport))
		if cfg.MCPServers[i].Transport == "" {
			cfg.MCPServers[i].Transport = MCPTransportStreamableHTTP
		}
		cfg.MCPServers[i].AuthType = strings.ToLower(strings.TrimSpace(cfg.MCPServers[i].AuthType))
		if cfg.MCPServers[i].AuthType == "" {
			cfg.MCPServers[i].AuthType = MCPAuthNone
		}
		cfg.MCPServers[i].AuthHeader = strings.TrimSpace(cfg.MCPServers[i].AuthHeader)
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
		if strings.TrimSpace(c.Server.TLS.Domain) == "" {
			errs = append(errs, "server.tls.domain is required when tls.mode is acme_dns01")
		}
		switch c.Server.TLS.DNSProvider {
		case DNSProviderCloudflare:
		case DNSProviderWebhook:
			if c.Server.TLS.DNSWebhookURL == "" {
				errs = append(errs, "server.tls.dns_webhook_url is required when tls.dns_provider is webhook")
			} else if err := validateHTTPURL(c.Server.TLS.DNSWebhookURL); err != nil {
				errs = append(errs, fmt.Sprintf("server.tls.dns_webhook_url: %v", err))
			}
		default:
			errs = append(errs, fmt.Sprintf("server.tls.dns_provider %q must be cloudflare or webhook when tls.mode is acme_dns01", c.Server.TLS.DNSProvider))
		}
		if c.Server.TLS.ACMEDirectoryURL != "" {
			if err := validateHTTPURL(c.Server.TLS.ACMEDirectoryURL); err != nil {
				errs = append(errs, fmt.Sprintf("server.tls.acme_directory_url: %v", err))
			}
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

	seenScopes := make(map[string]struct{}, len(c.Budgets))
	for i, b := range c.Budgets {
		if b.Scope == "" {
			errs = append(errs, fmt.Sprintf("budgets[%d].scope is required", i))
		} else {
			if _, dup := seenScopes[b.Scope]; dup {
				errs = append(errs, fmt.Sprintf("budgets[%d].scope %q is duplicated", i, b.Scope))
			}
			seenScopes[b.Scope] = struct{}{}
		}
		if b.RPM < 0 {
			errs = append(errs, fmt.Sprintf("budgets[%d].rpm must be >= 0, got %d", i, b.RPM))
		}
		if b.TPM < 0 {
			errs = append(errs, fmt.Sprintf("budgets[%d].tpm must be >= 0, got %d", i, b.TPM))
		}
		if b.MaxConcurrent < 0 {
			errs = append(errs, fmt.Sprintf("budgets[%d].max_concurrent must be >= 0, got %d", i, b.MaxConcurrent))
		}
		if b.DailyUSD != nil && *b.DailyUSD < 0 {
			errs = append(errs, fmt.Sprintf("budgets[%d].daily_usd must be non-negative", i))
		}
		if b.MonthlyUSD != nil && *b.MonthlyUSD < 0 {
			errs = append(errs, fmt.Sprintf("budgets[%d].monthly_usd must be non-negative", i))
		}
		if b.SoftAlertPct < 1 || b.SoftAlertPct > 100 {
			errs = append(errs, fmt.Sprintf("budgets[%d].soft_alert_pct must be between 1 and 100, got %d", i, b.SoftAlertPct))
		}
	}

	seenGuardrailIDs := make(map[string]struct{}, len(c.Guardrails.Rules))
	for i, r := range c.Guardrails.Rules {
		if r.ID == "" {
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].id is required", i))
		} else {
			if _, dup := seenGuardrailIDs[r.ID]; dup {
				errs = append(errs, fmt.Sprintf("guardrails.rules[%d].id %q is duplicated", i, r.ID))
			}
			seenGuardrailIDs[r.ID] = struct{}{}
		}
		if r.Name == "" {
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].name is required", i))
		}
		switch r.Category {
		case GuardrailCategorySecret, GuardrailCategoryPII, GuardrailCategoryCustom:
		default:
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].category %q must be secret, pii, or custom", i, r.Category))
		}
		switch r.Action {
		case GuardrailActionLogOnly, GuardrailActionRedact, GuardrailActionBlock:
		default:
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].action %q must be log_only, redact, or block", i, r.Action))
		}
		if r.Pattern == "" {
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].pattern is required", i))
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			errs = append(errs, fmt.Sprintf("guardrails.rules[%d].pattern invalid regex: %v", i, err))
		}
	}

	seenWebhookIDs := make(map[string]struct{}, len(c.Webhooks))
	for i, w := range c.Webhooks {
		if w.ID == "" {
			errs = append(errs, fmt.Sprintf("webhooks[%d].id is required", i))
		} else {
			if _, dup := seenWebhookIDs[w.ID]; dup {
				errs = append(errs, fmt.Sprintf("webhooks[%d].id %q is duplicated", i, w.ID))
			}
			seenWebhookIDs[w.ID] = struct{}{}
		}
		if w.Name == "" {
			errs = append(errs, fmt.Sprintf("webhooks[%d].name is required", i))
		}
		if err := validateHTTPURL(w.URL); err != nil {
			errs = append(errs, fmt.Sprintf("webhooks[%d].url: %v", i, err))
		}
		switch w.Type {
		case WebhookTypeSyncReview, WebhookTypeAsyncEvent:
		default:
			errs = append(errs, fmt.Sprintf("webhooks[%d].type %q must be sync_review or async_event", i, w.Type))
		}
		if w.TimeoutMS <= 0 {
			errs = append(errs, fmt.Sprintf("webhooks[%d].timeout_ms must be > 0, got %d", i, w.TimeoutMS))
		}
		for _, ev := range w.Events {
			if !IsValidWebhookEvent(ev) {
				errs = append(errs, fmt.Sprintf("webhooks[%d].events contains unknown event %q", i, ev))
			}
		}
	}

	seenMCPServers := make(map[string]struct{}, len(c.MCPServers))
	for i, m := range c.MCPServers {
		if m.Name == "" {
			errs = append(errs, fmt.Sprintf("mcp_servers[%d].name is required", i))
		} else {
			if strings.Contains(m.Name, "/") {
				errs = append(errs, fmt.Sprintf("mcp_servers[%d].name %q must not contain '/'", i, m.Name))
			}
			if _, dup := seenMCPServers[m.Name]; dup {
				errs = append(errs, fmt.Sprintf("mcp_servers[%d].name %q is duplicated", i, m.Name))
			}
			seenMCPServers[m.Name] = struct{}{}
		}
		if err := validateHTTPURL(m.URL); err != nil {
			errs = append(errs, fmt.Sprintf("mcp_servers[%d].url: %v", i, err))
		}
		switch m.Transport {
		case MCPTransportStreamableHTTP, MCPTransportSSE:
		default:
			errs = append(errs, fmt.Sprintf("mcp_servers[%d].transport %q must be streamable_http or sse", i, m.Transport))
		}
		switch m.AuthType {
		case MCPAuthNone, MCPAuthBearer, MCPAuthBasic:
		case MCPAuthHeader:
			if m.AuthHeader == "" {
				errs = append(errs, fmt.Sprintf("mcp_servers[%d].auth_header is required when auth_type is header", i))
			}
		default:
			errs = append(errs, fmt.Sprintf("mcp_servers[%d].auth_type %q must be none, bearer, header, or basic", i, m.AuthType))
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
