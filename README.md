# Headlamp

**English** | [简体中文](./README.zh-CN.md)

Headlamp is a self-hosted, single-binary private AI gateway built in Go that joins your Headscale (or Tailscale) tailnet as a first-class node via `tsnet`. Devices on your tailnet authenticate automatically with their tailnet identity—no vendor API keys distributed to developer machines.

## Key Capabilities

- **Zero-Key Tailnet Identity & Grants Authorization**: Joins Headscale v0.29+ (or Tailscale) directly via `tsnet`, identifies callers via `WhoIs`, and enforces pure **grants-only** authorization (`headlamp.dev/cap/gateway`, plus `tailscale.com/cap/aperture` on official Tailscale SaaS) with **Explicit Deny Wins** for both LLM models (`models` / `deny_models`) and MCP tools (`mcp_tools` / `deny_mcp_tools`).
- **Team Web Chat with MCP Tool Calling**: Built-in browser chat workspace accessible to every authenticated tailnet user (with strict per-user session isolation). Streams responses through Headlamp's own proxy pipeline (full policy, guardrails, quotas, and metering with zero bypass), renders XSS-safe Markdown, and executes authorized remote MCP tool calls mid-conversation.
- **Remote MCP Proxy Gateway (`/mcp/<server>`)**: Proxies Streamable HTTP and SSE remote MCP servers with server-side encrypted credentials (`bearer`, custom `header`, `basic`), per-caller `tools/list` filtering, `tools/call` policy enforcement and argument guardrail inspection, and a dedicated `mcp_audit_logs` audit trail.
- **Embedded Admin Dashboard & Personal Usage UI**: Ships a single-binary React + TypeScript + Vite SPA (Geist typography, zero external CDN requests) embedded directly via `go:embed` (`web/dist`), authenticated automatically via Tailnet WhoIs SSO. Admins manage providers, virtual routes, MCP servers, budgets, guardrails, webhooks, usage analytics, audit logs, and grants snippets at `/`; standard users access Team Chat, personal usage, budgets, and SDK/MCP setup snippets.
- **Multi-Protocol Routing & Accounting**: Supports OpenAI (`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`), Anthropic (`/anthropic/v1/messages`), Google Gemini (`/gemini/v1beta/...`), and Ollama providers, virtual model alias routing with automatic fallbacks, bidirectional OpenAI <-> Anthropic translation, streaming SSE token/cost usage logs, and opt-in audit payloads with TTL retention purge.
- **Budgets, Rate Limits & Quotas**: Enforces per-scope (`*`, `tag:<name>`, user subject) RPM, TPM, max concurrency, and UTC daily/monthly USD spend caps (`429` with `Retry-After`) plus configurable soft-alert threshold notifications. Pair `tpm` and `daily_usd`/`monthly_usd` with `max_concurrent` to bound burst overspend while in-flight streaming responses finalize their token and USD totals.
- **Guardrails & Signed Webhooks**: Built-in zero-latency regex detectors (OpenAI, Anthropic, AWS, GitHub, and GCP secrets, PEM private keys, JWTs, credit cards, emails, and phone numbers) with `log_only`, `redact`, or `block` actions, custom regex rules, synchronous pre-request review webhooks (`sync_review`), and HMAC-SHA256 signed asynchronous event alerts (`guardrail.triggered`, `budget.threshold`, `budget.exceeded`, `upstream.fallback`, `upstream.error`).
- **Automated ACME DNS-01 HTTPS**: Supports automated TLS certificate issuance and renewal on private Headscale domains via Cloudflare API or custom DNS-01 webhook solvers (`server.tls.mode: acme_dns01`), alongside `static` cert/key and plaintext Tailnet HTTP (`none`).
- **Encrypted Credential Store & Zero-CGO Storage (SQLite + PostgreSQL)**: Upstream provider API keys, webhook secrets, and MCP auth tokens are encrypted at rest with AES-256-GCM (`HEADLAMP_MASTER_KEY`, or an auto-generated `0600` key file in `state_dir`), backed by either pure-Go SQLite (`modernc.org/sqlite`, WAL mode) or pure-Go PostgreSQL (`pgx/v5`) for multi-replica HA deployments.
- **Local Dev, Static Fallback Tokens & Release Automation**: Supports an optional local HTTP listener with loopback-restricted `dev_mode` and static fallback API tokens for CI runners, plus GitHub Actions CI, multi-arch `CGO_ENABLED=0` GitHub Releases, and GHCR Docker images.

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
| `HEADLAMP_TLS_MODE` | Tailnet TLS mode: `none`, `static`, or `acme_dns01` |
| `HEADLAMP_TLS_DOMAIN` | Certificate domain for `acme_dns01` |
| `HEADLAMP_TLS_ACME_EMAIL` | ACME account contact email for `acme_dns01` |
| `HEADLAMP_TLS_DNS_PROVIDER` | DNS-01 solver: `cloudflare` or `webhook` |
| `HEADLAMP_TLS_DNS_API_TOKEN` | Cloudflare API token or webhook bearer token for DNS-01 |
| `HEADLAMP_TLS_DNS_WEBHOOK_URL` | Custom DNS-01 webhook endpoint URL |
| `HEADLAMP_STARTUP_TIMEOUT` | Listener/tsnet/ACME startup timeout override (e.g. `3m`; defaults to `5m` for `acme_dns01`, `60s` otherwise) |

## Deployment (Docker Compose & systemd)

Ready-to-use production deployment templates are provided in `deploy/`:

- **Docker Compose (SQLite)**: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) + [`deploy/headlamp.env.example`](deploy/headlamp.env.example) using `ghcr.io/zacharykka/headlamp:latest` (`nonroot`, `read_only`, no `/dev/net/tun` required).
- **Docker Compose (PostgreSQL 17)**: [`deploy/docker-compose.postgres.yml`](deploy/docker-compose.postgres.yml) with healthchecked PostgreSQL 17.
- **Linux Binary + `systemd`**: Download static `linux_amd64` / `linux_arm64` binaries from GitHub Releases and manage them with [`deploy/headlamp.service`](deploy/headlamp.service).

See [`docs/deployment.md`](docs/deployment.md) for the step-by-step deployment, upgrade, and backup guide.

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

# Claude Code Remote MCP Server
claude mcp add --transport http headlamp-docs http://headlamp/mcp/docs
```

See [`docs/clients.md`](docs/clients.md) for full copy-pasteable setup recipes (Claude Code, Codex CLI, Gemini CLI, Cursor, Python/Node SDKs, Remote MCP Clients, and PostgreSQL HA deployments).

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

Building the single binary compiles the embedded React dashboard (`web/dist`) and packages it into `./bin/headlamp`:

```bash
make test-race
make build
```

For frontend UI development with hot reload against a local Headlamp backend:

```bash
make run-dev
npm --prefix web run dev
```

## Repository Structure

```text
headlamp/
├── .github/workflows/  # CI (web + Go race tests) and multi-arch binary/GHCR release pipeline
├── cmd/headlamp/       # CLI entrypoint (serve, init, usage, version) and runtime wiring
├── internal/
│   ├── api/            # Admin, User, Chat & MCP REST/SSE API (/api/v1/*), RBAC, CSRF, SPA serving
│   ├── auth/           # Principal model, context helpers, dev & static token auth
│   ├── chat/           # Team Web Chat orchestration, streaming SSE & multi-round MCP tool calling
│   ├── config/         # YAML loader, env overrides, validation
│   ├── crypto/         # AES-256-GCM encryption and master key management
│   ├── guardrail/      # Local regex detectors, sync review & signed async webhooks
│   ├── mcp/            # Remote MCP proxy (/mcp/*), tool filtering, guardrails & discovery client
│   ├── metering/       # Streaming SSE usage parser, pricing table, async persistence
│   ├── netts/          # tsnet node lifecycle, Headscale connection, ACME DNS-01 & TLS
│   ├── policy/         # Pure grants-only policy evaluator (Explicit Deny Wins)
│   ├── proxy/          # Native-first multi-protocol LLM reverse proxy
│   ├── quota/          # Per-scope RPM/TPM/concurrency & USD spend budget enforcement
│   ├── store/          # Store interface, pure-Go SQLite & PostgreSQL (pgx/v5) drivers + migrations
│   └── translate/      # On-demand cross-protocol request & SSE translation
├── web/                # Embedded React + TypeScript + Vite dashboard & Team Web Chat SPA
├── deploy/             # Dockerfile, Docker Compose (SQLite & PostgreSQL), env template & systemd unit
└── docs/               # Deployment guide, client recipes, Headscale v0.29.7 guide & specs (EN / zh-CN)
```
