package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExampleYAML(t *testing.T) {
	t.Setenv("HEADLAMP_AUTH_KEY", "tskey-auth-example")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-example")
	t.Setenv("OPENAI_API_KEY", "sk-openai-example")
	t.Setenv("GEMINI_API_KEY", "gemini-example")

	cfg, err := Load(filepath.Join("..", "..", "headlamp.example.yaml"))
	if err != nil {
		t.Fatalf("Load(headlamp.example.yaml): %v", err)
	}

	if cfg.Server.TSNet.Hostname != "headlamp" {
		t.Fatalf("hostname = %q, want headlamp", cfg.Server.TSNet.Hostname)
	}
	if cfg.Server.TSNet.AuthKey != "tskey-auth-example" {
		t.Fatalf("auth_key = %q, want tskey-auth-example", cfg.Server.TSNet.AuthKey)
	}
	if cfg.Server.DevAllowHeaderOverride {
		t.Fatal("expected dev_allow_header_override default false")
	}
	if len(cfg.Providers) != 4 {
		t.Fatalf("len(providers) = %d, want 4", len(cfg.Providers))
	}
	if cfg.Providers[0].APIKey != "sk-ant-example" {
		t.Fatalf("anthropic api_key = %q, want sk-ant-example", cfg.Providers[0].APIKey)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(cfg.Routes))
	}
	if cfg.Audit.StorePayloads {
		t.Fatal("expected audit.store_payloads default false")
	}
	if cfg.Audit.RetentionDays != 7 {
		t.Fatalf("retention_days = %d, want 7", cfg.Audit.RetentionDays)
	}
}

func TestEnvOverridesAndSecretExpansion(t *testing.T) {
	yamlContent := `
server:
  tsnet:
    enabled: true
    hostname: from-yaml
    control_url: https://yaml.headscale.local
  tls:
    mode: none
  api_tokens:
    - name: ci-runner
      token: "${MY_CI_TOKEN}"
      subject: "tag:ci-runner"
      roles: ["user"]
      allow_models: ["openai/gpt-4.1*"]
      deny_models: ["openai/o3*"]
storage:
  driver: sqlite
  dsn: ./yaml.db
providers:
  - name: openai
    type: openai
    api_key: "${MY_OPENAI_KEY}"
    models: ["gpt-4.1"]
`
	tmp := filepath.Join(t.TempDir(), "headlamp.yaml")
	if err := os.WriteFile(tmp, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	t.Setenv("HEADLAMP_CONFIG", tmp)
	t.Setenv("HEADLAMP_MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("HEADLAMP_CONTROL_URL", "https://env.headscale.local")
	t.Setenv("HEADLAMP_AUTH_KEY", "tskey-from-env")
	t.Setenv("HEADLAMP_LOCAL_LISTEN", "127.0.0.1:9090")
	t.Setenv("HEADLAMP_DEV_MODE", "true")
	t.Setenv("HEADLAMP_DEV_ALLOW_HEADER_OVERRIDE", "true")
	t.Setenv("HEADLAMP_STORAGE_DSN", "/tmp/override.db")
	t.Setenv("HEADLAMP_AUDIT_STORE_PAYLOADS", "true")
	t.Setenv("HEADLAMP_AUDIT_RETENTION_DAYS", "14")
	t.Setenv("MY_OPENAI_KEY", "sk-live-$literal")
	t.Setenv("MY_CI_TOKEN", "hl_ci_secret")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.MasterKey == "" {
		t.Fatal("expected HEADLAMP_MASTER_KEY to populate MasterKey")
	}
	if cfg.Server.TSNet.ControlURL != "https://env.headscale.local" {
		t.Fatalf("control_url = %q", cfg.Server.TSNet.ControlURL)
	}
	if cfg.Server.TSNet.AuthKey != "tskey-from-env" {
		t.Fatalf("auth_key = %q", cfg.Server.TSNet.AuthKey)
	}
	if cfg.Server.LocalListen != "127.0.0.1:9090" {
		t.Fatalf("local_listen = %q", cfg.Server.LocalListen)
	}
	if !cfg.Server.DevMode || cfg.Server.DevUser != "dev@local" || !cfg.Server.DevAllowHeaderOverride {
		t.Fatalf("dev mode defaults/override not applied: mode=%v user=%q allowHeader=%v",
			cfg.Server.DevMode, cfg.Server.DevUser, cfg.Server.DevAllowHeaderOverride)
	}
	if len(cfg.Server.APITokens) != 1 || cfg.Server.APITokens[0].Token != "hl_ci_secret" ||
		len(cfg.Server.APITokens[0].AllowModels) != 1 || len(cfg.Server.APITokens[0].DenyModels) != 1 {
		t.Fatalf("api_tokens = %#v", cfg.Server.APITokens)
	}
	if cfg.Storage.DSN != "/tmp/override.db" {
		t.Fatalf("storage.dsn = %q", cfg.Storage.DSN)
	}
	if !cfg.Audit.StorePayloads || cfg.Audit.RetentionDays != 14 {
		t.Fatalf("audit = %+v", cfg.Audit)
	}
	if cfg.Providers[0].BaseURL != "https://api.openai.com" {
		t.Fatalf("default base_url not applied: %q", cfg.Providers[0].BaseURL)
	}
	if cfg.Providers[0].APIKey != "sk-live-$literal" {
		t.Fatalf("api_key = %q, want sk-live-$literal", cfg.Providers[0].APIKey)
	}
	if !cfg.Providers[0].IsEnabled() {
		t.Fatal("expected provider to default to enabled")
	}
}

func TestDevModeLoopbackValidation(t *testing.T) {
	allowed := []string{
		"127.0.0.1:8080",
		"127.0.0.1:0",
		"[::1]:8080",
		"localhost:8080",
	}
	for _, addr := range allowed {
		cfg, err := LoadFromBytes([]byte("server:\n  tsnet:\n    enabled: false\n  local_listen: \"" + addr + "\"\n  dev_mode: true\n"))
		if err != nil {
			t.Fatalf("expected loopback %q to be allowed in dev_mode, got err: %v", addr, err)
		}
		if !cfg.Server.DevMode {
			t.Fatalf("expected DevMode true for %q", addr)
		}
	}

	rejected := []string{
		"",
		":8080",
		"0.0.0.0:8080",
		"[::]:8080",
		"192.168.1.50:8080",
		"100.64.0.10:8080",
	}
	for _, addr := range rejected {
		_, err := LoadFromBytes([]byte("server:\n  tsnet:\n    enabled: true\n  local_listen: \"" + addr + "\"\n  dev_mode: true\n"))
		if err == nil {
			t.Fatalf("expected non-loopback %q to be rejected when dev_mode=true", addr)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("error %q for %q does not mention loopback", err.Error(), addr)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name: "no listeners enabled",
			yaml: `
server:
  tsnet:
    enabled: false
  local_listen: ""
`,
			wantSub: "at least one listener",
		},
		{
			name: "static tls missing cert",
			yaml: `
server:
  tls:
    mode: static
`,
			wantSub: "cert_file",
		},
		{
			name: "acme tls missing domain",
			yaml: `
server:
  tls:
    mode: acme_dns01
`,
			wantSub: "dns_provider",
		},
		{
			name: "removed policy block rejected",
			yaml: `
policy:
  mode: hybrid
`,
			wantSub: "policy",
		},
		{
			name: "invalid provider type",
			yaml: `
providers:
  - name: weird
    type: bedrock
    base_url: https://example.com
`,
			wantSub: "providers[0].type",
		},
		{
			name: "route references missing provider",
			yaml: `
providers:
  - name: openai
    type: openai
routes:
  - alias: coding
    provider: nonexistent
    model: claude-sonnet
`,
			wantSub: "does not match any configured provider",
		},
		{
			name: "invalid api token allow_models glob",
			yaml: `
server:
  api_tokens:
    - token: tok-1
      subject: ci
      allow_models: ["[unclosed"]
`,
			wantSub: "invalid glob",
		},
		{
			name: "negative audit retention",
			yaml: `
audit:
  retention_days: -1
`,
			wantSub: "audit.retention_days",
		},
		{
			name: "unknown yaml field rejected",
			yaml: `
server:
  typo_field: 123
`,
			wantSub: "typo_field",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestTLSPortDefaulting(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(`
server:
  tls:
    mode: static
    cert_file: /etc/ssl/cert.pem
    key_file: /etc/ssl/key.pem
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if cfg.Server.TSNet.ListenPort != 443 {
		t.Fatalf("listen_port = %d, want 443 when TLS is enabled", cfg.Server.TSNet.ListenPort)
	}
}
