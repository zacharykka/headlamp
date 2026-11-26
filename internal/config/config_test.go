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
policy:
  mode: local_only
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
	t.Setenv("HEADLAMP_POLICY_MODE", "hybrid")
	t.Setenv("HEADLAMP_BOOTSTRAP_ADMINS", "alice@example.com, bob@example.com")
	t.Setenv("HEADLAMP_STORAGE_DSN", "/tmp/override.db")
	t.Setenv("HEADLAMP_AUDIT_STORE_PAYLOADS", "true")
	t.Setenv("HEADLAMP_AUDIT_RETENTION_DAYS", "14")
	t.Setenv("MY_OPENAI_KEY", "sk-live-$literal")

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
	if !cfg.Server.DevMode || cfg.Server.DevUser != "dev@local" {
		t.Fatalf("dev mode defaults not applied: mode=%v user=%q", cfg.Server.DevMode, cfg.Server.DevUser)
	}
	if cfg.Policy.Mode != PolicyModeHybrid {
		t.Fatalf("policy.mode = %q", cfg.Policy.Mode)
	}
	if len(cfg.Policy.BootstrapAdmins) != 2 || cfg.Policy.BootstrapAdmins[1] != "bob@example.com" {
		t.Fatalf("bootstrap_admins = %#v", cfg.Policy.BootstrapAdmins)
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
			name: "invalid policy mode",
			yaml: `
policy:
  mode: unknown
`,
			wantSub: "policy.mode",
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
			name: "invalid policy glob",
			yaml: `
policy:
  rules:
    - name: bad
      subject: "*"
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
