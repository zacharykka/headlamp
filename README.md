# Headlamp

Headlamp is a self-hosted, single-binary private AI gateway built in Go that joins your Headscale (or Tailscale) tailnet as a first-class node via `tsnet`. Devices on your tailnet authenticate automatically with their tailnet identity—no vendor API keys distributed to developer machines.

## Key Capabilities (M1 Core Gateway)

- **Zero-Key Tailnet Identity & Grants Authorization**: Joins Headscale v0.29+ (or Tailscale) directly via `tsnet`, identifies callers via `WhoIs`, and enforces pure **grants-only** authorization (`headlamp.dev/cap/gateway`, plus `tailscale.com/cap/aperture` on official Tailscale SaaS) with **Explicit Deny Wins**.
- **Local Dev & Static Fallback Tokens**: Supports an optional local HTTP listener with loopback-restricted `dev_mode` and static fallback API tokens (with inline `allow_models` / `deny_models` grant scopes) for non-Tailnet callers such as CI runners.
- **Encrypted Credential Store**: Upstream provider API keys are encrypted at rest with AES-256-GCM (`HEADLAMP_MASTER_KEY`, or an auto-generated `0600` key file in `state_dir`).
- **Zero-CGO Storage**: Ships with pure-Go SQLite (`modernc.org/sqlite`) in WAL mode with `0700`/`0600` permissions, embedded SQL migrations, and an in-memory snapshot cache for providers and routes.
- **Multi-Protocol Routing & Accounting**: Supports OpenAI (`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`), Anthropic (`/anthropic/v1/messages`), Google Gemini (`/gemini/v1beta/...`), and Ollama providers, virtual model alias routing with fallbacks, bidirectional OpenAI <-> Anthropic translation, token/cost usage logs, and opt-in audit payloads with TTL retention purge.

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
| `HEADLAMP_LOCAL_LISTEN` | Optional local HTTP bind address (must be loopback `127.0.0.1` / `::1` / `localhost` when `dev_mode: true`) |
| `HEADLAMP_DEV_MODE` | Enable local mock identity (`true`/`false`; requires loopback `local_listen`) |
| `HEADLAMP_DEV_USER` | Mock principal subject when `dev_mode` is enabled |
| `HEADLAMP_DEV_ALLOW_HEADER_OVERRIDE` | Allow `X-Headlamp-Dev-*` identity headers from loopback peers in `dev_mode` (default `false`) |
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

Headlamp authorization is **grants-only**. On Headscale v0.29.7, grant access using `headlamp.dev/cap/gateway` (note that Headscale v0.29.7 rejects `tailscale.com/cap/*` capability names; Headlamp also accepts `tailscale.com/cap/aperture` when connected to official Tailscale SaaS):

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
            "deny_models": ["openai/o3*"],
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
make test-race
make build
```

## Repository Structure

```text
headlamp/
├── cmd/headlamp/       # CLI entrypoint (serve, init, usage, version)
├── internal/
│   ├── config/         # YAML loader, env overrides, validation
│   ├── crypto/         # AES-256-GCM encryption and master key management
│   ├── auth/           # Principal model, context helpers, dev & static token auth
│   ├── store/          # Store interface, pure-Go SQLite implementation, SQL migrations
│   ├── netts/          # tsnet node lifecycle, Headscale connection, TLS listeners
│   ├── policy/         # Pure grants-only policy evaluator (Explicit Deny Wins)
│   ├── proxy/          # Native-first multi-protocol LLM reverse proxy
│   ├── translate/      # On-demand cross-protocol request & SSE translation
│   └── metering/       # Streaming SSE usage parser, pricing table, async persistence
├── deploy/             # Multi-stage static Dockerfile
└── docs/               # Headscale v0.29.7 setup guide and protocol specs
```
