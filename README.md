# Headlamp

Headlamp is a self-hosted, single-binary private AI gateway built in Go that joins your Headscale (or Tailscale) tailnet as a first-class node via `tsnet`. Devices on your tailnet authenticate automatically with their tailnet identity—no vendor API keys distributed to developer machines.

## Key Capabilities (M1 Foundation)

- **Zero-Key Tailnet Identity**: Joins Headscale/Tailscale directly via `tsnet` and identifies callers using `WhoIs` (user, node name, IP, node tags, and Headscale v0.29+ `grants` capabilities).
- **Local Dev & Fallback Auth**: Supports a local HTTP listener with optional `dev_mock` mode and static fallback API tokens for CI runners or local debugging.
- **Encrypted Credential Store**: Upstream provider API keys are encrypted at rest with AES-256-GCM (`HEADLAMP_MASTER_KEY`, or an auto-generated `0600` key file in `state_dir`).
- **Zero-CGO Storage**: Ships with pure-Go SQLite (`modernc.org/sqlite`) in WAL mode with embedded SQL migrations and clean abstractions for future PostgreSQL support.
- **Multi-Protocol Routing & Accounting**: Supports OpenAI, Anthropic, Google Gemini, and Ollama providers, virtual model alias routing with fallbacks, dual-track policies (`hybrid`, `local_only`, `grants_only`), token/cost usage logs, and opt-in audit payloads with TTL retention purge.

## Configuration

Copy [`headlamp.example.yaml`](headlamp.example.yaml) to `headlamp.yaml` and customize it for your Headscale/Tailscale network and upstream providers:

```bash
cp headlamp.example.yaml headlamp.yaml
export HEADLAMP_MASTER_KEY=$(openssl rand -hex 32)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

Common environment overrides:

| Variable | Description |
| :--- | :--- |
| `HEADLAMP_CONFIG` | Path to YAML config file |
| `HEADLAMP_MASTER_KEY` | 32-byte AES-256-GCM key (64 hex chars or base64); auto-generated in `state_dir/master.key` if omitted |
| `HEADLAMP_CONTROL_URL` | Headscale control server URL (leave empty for official Tailscale) |
| `HEADLAMP_AUTH_KEY` | Pre-auth key for initial `tsnet` registration |
| `HEADLAMP_STATE_DIR` | Persistent directory for `tsnet` state and auto-generated master key |
| `HEADLAMP_LOCAL_LISTEN` | Optional local HTTP bind address (e.g. `127.0.0.1:8080`) |
| `HEADLAMP_DEV_MODE` | Enable local mock identity (`true`/`false`) |
| `HEADLAMP_DEV_USER` | Mock principal subject when `dev_mode` is enabled |
| `HEADLAMP_POLICY_MODE` | Policy mode: `hybrid`, `local_only`, or `grants_only` |
| `HEADLAMP_BOOTSTRAP_ADMINS` | Comma-separated bootstrap admin subjects |
| `HEADLAMP_STORAGE_DRIVER` | Storage backend: `sqlite` (default) or `postgres` |
| `HEADLAMP_STORAGE_DSN` | Database path or connection string |

## Client Quickstart

Once Headlamp is running on your tailnet (e.g. hostname `headlamp`):

```bash
# Claude Code / Anthropic SDK
export ANTHROPIC_BASE_URL="http://headlamp/anthropic"
export ANTHROPIC_API_KEY="headlamp"

# OpenAI SDK / Codex / Cursor
export OPENAI_BASE_URL="http://headlamp/v1"
export OPENAI_API_KEY="headlamp"

# Google Gemini CLI / GenAI SDK
export GEMINI_API_BASE="http://headlamp/gemini"
export GEMINI_API_KEY="headlamp"
```

## Headscale v0.29.7 `grants` Example

In `hybrid` or `grants_only` policy mode, Headlamp reads `headlamp.dev/cap/gateway` (and compatible alias `tailscale.com/cap/aperture`) from Headscale `WhoIs` capabilities:

```jsonc
{
  "grants": [
    {
      "src": ["group:engineering"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["anthropic/*", "openai/gpt-5*"],
            "mcp_tools": ["docs/*", "github/read_*"]
          }
        ]
      }
    }
  ]
}
```

See [`docs/headscale-setup.md`](docs/headscale-setup.md) and [`headlamp.example.yaml`](headlamp.example.yaml) for a full Headscale v0.29.7 setup and policy guide.

## Development

```bash
go test ./...
```

## Repository Structure

```text
headlamp/
├── cmd/headlamp/       # CLI entrypoint (serve, migrate, version)
├── internal/
│   ├── config/         # YAML loader, env overrides, validation
│   ├── crypto/         # AES-256-GCM encryption and master key management
│   ├── auth/           # Principal model, context helpers, dev & static token auth
│   ├── store/          # Store interface, pure-Go SQLite implementation, SQL migrations
│   ├── netts/          # tsnet node lifecycle, Headscale connection, TLS/ACME
│   ├── policy/         # Dual-track policy engine (local rules + Headscale grants)
│   ├── proxy/          # Native-first multi-protocol LLM reverse proxy
│   ├── translate/      # On-demand cross-protocol request & SSE translation
│   └── metering/       # Streaming SSE usage parser, pricing table, async persistence
└── docs/               # Protocol specs and deployment guides
```
