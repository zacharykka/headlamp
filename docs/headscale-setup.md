# Headlamp + Headscale v0.29.7 Setup Guide

**English** | [简体中文](./headscale-setup.zh-CN.md)

This guide walks through joining **Headlamp** to a self-hosted **Headscale v0.29.7** tailnet via `tsnet`, configuring Headscale `grants`, and pointing AI coding agents at Headlamp with zero client API keys.

---

## 1. Enable File Policy & MagicDNS in Headscale v0.29.7

In your Headscale `config.yaml`:

```yaml
policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: tailnet.internal
```

> **Note:** Headscale `dns.extra_records` only supports `A` and `AAAA` records (Tailscale clients ignore `CNAME`). With `magic_dns: true`, devices reach Headlamp directly at `http://headlamp` or `http://headlamp.tailnet.internal`.

---

## 2. Configure `tagOwners` and `grants` (`policy.hujson`)

Headscale v0.29.7 supports modern `grants` with both network rules (`ip`) and application capabilities (`app`).

> **Important:** An `app`-only grant does **not** open TCP ports in Headscale v0.29+. Always include `"ip": ["tcp:80", "tcp:443"]` alongside `"app"` (or in a companion grant).

Save as `/etc/headscale/policy.hujson`:

```jsonc
{
  "groups": {
    "group:admins": ["alice@example.com"],
    "group:engineering": ["alice@example.com", "bob@example.com"],
    "group:interns": ["carol@example.com"]
  },

  // Required before creating tagged pre-auth keys or advertising tags.
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },

  "grants": [
    // Admins: full model + MCP access
    {
      "src": ["group:admins"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "admin",
            "models": ["**"],
            "mcp_tools": ["**"]
          }
        ]
      }
    },

    // Engineering: Headlamp native capability
    {
      "src": ["group:engineering"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["anthropic/*", "openai/gpt-5*", "gemini/*", "ollama/*", "team/*"],
            "mcp_tools": ["docs/*", "github/read_*"]
          }
        ]
      }
    },

    // Multi-object array & single-string "models" syntax also work under headlamp.dev/cap/gateway.
    // Note: Headscale v0.29.7 rejects "tailscale.com/cap/*" capability names
    // ("capability name must not be in the tailscale.com domain"), so always use
    // "headlamp.dev/cap/gateway" on Headscale. ("tailscale.com/cap/aperture" is
    // supported by Headlamp for official Tailscale SaaS tailnets only.)
    {
      "src": ["group:interns"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          { "role": "user" },
          { "models": "ollama/**" },
          { "connectors": ["docs/**"] }
        ]
      }
    },

    // Headless tagged workload (e.g. CI runner)
    {
      "src": ["tag:ci-runner"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["openai/gpt-5-mini", "anthropic/claude-haiku-4-5*"],
            "mcp_tools": []
          }
        ]
      }
    }
  ]
}
```

Validate and reload the policy on your Headscale server:

```bash
headscale policy check -f /etc/headscale/policy.hujson
kill -HUP $(pidof headscale)
# Or, if using database policy mode:
# headscale policy set -f /etc/headscale/policy.hujson
```

---

## 3. Create a Headscale Pre-Auth Key

In Headscale v0.29+, tagged pre-auth keys register the node directly under `tag:headlamp` without binding it to a human user:

```bash
headscale preauthkeys create --reusable --expiration 24h --tags tag:headlamp
```

If you prefer not to tag Headlamp (for example, when targeting Headlamp by user in your Headscale `grants`), create a user-scoped key instead:

```bash
headscale preauthkeys create --user alice --reusable --expiration 24h
```

---

## 4. Configure and Run Headlamp

Headlamp uses pure **grants-only** authorization: Tailnet permissions come exclusively from Headscale `grants` (no local `policy:` block in `headlamp.yaml`).

Copy [`headlamp.example.yaml`](../headlamp.example.yaml) to `headlamp.yaml` and set:

```yaml
server:
  tsnet:
    enabled: true
    hostname: headlamp
    control_url: "https://headscale.example.com"
    state_dir: "./data"
  tls:
    mode: none # WireGuard already encrypts tailnet traffic; use mode: static for custom HTTPS certs
```

Start Headlamp with your Headscale auth key, master encryption key, and upstream provider keys:

```bash
export HEADLAMP_AUTH_KEY="<preauthkey-from-step-3>"
export HEADLAMP_MASTER_KEY="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."

make build
./bin/headlamp serve --config headlamp.yaml
```

Or run via Docker:

```bash
docker build -f deploy/Dockerfile -t headlamp:latest .
docker run -d --name headlamp \
  -v headlamp-data:/data \
  -v "$(pwd)/headlamp.yaml:/etc/headlamp/headlamp.yaml:ro" \
  -e HEADLAMP_CONFIG=/etc/headlamp/headlamp.yaml \
  -e HEADLAMP_AUTH_KEY="${HEADLAMP_AUTH_KEY}" \
  -e HEADLAMP_MASTER_KEY="${HEADLAMP_MASTER_KEY}" \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
  -e GEMINI_API_KEY="${GEMINI_API_KEY}" \
  headlamp:latest
```

> **State Persistence:** Keep `state_dir` (`/data`) on persistent storage. Once `tailscaled.state` is created, `tsnet` ignores `HEADLAMP_AUTH_KEY` on subsequent restarts and keeps the same node identity. If you wipe `state_dir`, delete the stale node in Headscale (`headscale nodes delete -i <id>`) to avoid a `headlamp-1` suffix.

---

## 5. Client Configuration (Zero Vendor API Keys)

On any device connected to your Headscale tailnet, point your tool at `http://headlamp` (or `https://<your-domain>` if `tls.mode: static` is configured) with any placeholder key:

### Claude Code / Anthropic SDK

```bash
export ANTHROPIC_BASE_URL="http://headlamp/anthropic"
export ANTHROPIC_API_KEY="headlamp"
claude
```

### Codex / OpenAI SDK / Cursor

```bash
export OPENAI_BASE_URL="http://headlamp/v1"
export OPENAI_API_KEY="headlamp"
```

### Google Gemini CLI / GenAI SDK

```bash
export GEMINI_API_BASE="http://headlamp/gemini"
export GEMINI_API_KEY="headlamp"
```

### Local Ollama Routing

Configure an `ollama` provider in `headlamp.yaml` (pointing at `http://127.0.0.1:11434` or another tailnet GPU host such as `http://gpu-box:11434`), then call it through either OpenAI-compatible or Anthropic endpoints:

```yaml
providers:
  - name: ollama
    type: ollama
    base_url: "http://gpu-box:11434"
    models:
      - "qwen2.5-coder:32b"

routes:
  - alias: "local/coder"
    provider: ollama
    model: "qwen2.5-coder:32b"
```

```bash
# OpenAI SDK / Codex using local Ollama (zero cost in usage_logs)
curl http://headlamp/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"local/coder","messages":[{"role":"user","content":"Hello"}]}'

# Claude Code routed to Ollama via Headlamp's Anthropic <-> OpenAI translation
ANTHROPIC_BASE_URL="http://headlamp/anthropic" \
ANTHROPIC_API_KEY="headlamp" \
ANTHROPIC_MODEL="local/coder" \
claude
```

---

## 6. Headscale v0.29.7 Troubleshooting Checklist

- **Connection refused / timeout to `http://headlamp`**: Verify your grant includes `"ip": ["tcp:80", "tcp:443"]` (not just `"app"`).
- **`capability name must not be in the tailscale.com domain`**: Headscale v0.29.7 forbids `tailscale.com/cap/*` capability names in policies. Use `"headlamp.dev/cap/gateway"` on Headscale (Headlamp's `"tailscale.com/cap/aperture"` compatibility is for official Tailscale SaaS only).
- **Tagged devices show `tagged-devices` in Headscale**: Expected in Headscale v0.28/v0.29+. Headlamp inspects `Node.IsTagged()` first and resolves the caller subject to `tag:<name>` (e.g. `tag:ci-runner`) rather than `tagged-devices`.
- **Non-OIDC local users**: In Headscale v0.29.7, policy `src` / `groups` entries use a trailing `@` (for example `"alice@"`), while `WhoIs.UserProfile.LoginName` (shown in `GET /whoami` and recorded in `usage_logs.subject`) reports `"alice"` without the trailing `@`. Run `curl http://headlamp/whoami` from a tailnet device to confirm the exact resolved `principal.subject` and effective grants.
- **HTTPS on Headscale**: Tailscale SaaS automatic `*.ts.net` certs (`ListenTLS`) are not available on Headscale. Use `tls.mode: none` inside WireGuard (default) or `tls.mode: static` with your own certificate and key.
