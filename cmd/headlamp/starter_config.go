package main

const starterConfigTemplate = `# Headlamp starter configuration (grants-only authorization)
# Run locally in loopback dev mode:
#   headlamp serve -config headlamp.yaml
# To join Headscale v0.29+ / Tailscale, set server.tsnet.enabled: true, configure
# control_url + HEADLAMP_AUTH_KEY, and define headlamp.dev/cap/gateway grants in Headscale.

server:
  tsnet:
    enabled: false
    hostname: headlamp
    control_url: ""
    auth_key: "${HEADLAMP_AUTH_KEY}"
    state_dir: "./data"
  tls:
    # Supported modes: none | static | acme_dns01
    mode: none
    # For automated HTTPS on Headscale via ACME DNS-01:
    # mode: acme_dns01
    # domain: "headlamp.internal.example.com"
    # acme_email: "ops@example.com"
    # dns_provider: cloudflare # cloudflare | webhook
    # dns_api_token: "${HEADLAMP_TLS_DNS_API_TOKEN}"
  local_listen: "127.0.0.1:8080"
  dev_mode: true
  dev_user: "dev@local"
  dev_roles:
    - admin
    - user
  dev_allow_header_override: false
  # Optional fallback static API tokens for non-tailnet callers (e.g. CI):
  # api_tokens:
  #   - name: ci-runner
  #     token: "${HEADLAMP_CI_TOKEN}"
  #     subject: "tag:ci-runner"
  #     roles: ["user"]
  #     allow_models: ["openai/gpt-4.1*", "ollama/*"]
  #     deny_models: ["openai/o3*"]

storage:
  driver: sqlite
  dsn: "./data/headlamp.db"
  # For multi-replica PostgreSQL deployments:
  # driver: postgres
  # dsn: "postgres://headlamp:${HEADLAMP_PG_PASSWORD}@127.0.0.1:5432/headlamp?sslmode=disable"

providers:
  - name: anthropic
    type: anthropic
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"
    models:
      - "claude-sonnet-4-6"

  - name: openai
    type: openai
    base_url: "https://api.openai.com"
    api_key: "${OPENAI_API_KEY}"
    models:
      - "gpt-5"
      - "gpt-4.1"

  - name: gemini
    type: gemini
    base_url: "https://generativelanguage.googleapis.com"
    api_key: "${GEMINI_API_KEY}"
    models:
      - "gemini-2.5-flash"

  - name: ollama
    type: ollama
    base_url: "http://127.0.0.1:11434"
    models:
      - "qwen2.5-coder:32b"

routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
    fallbacks:
      - provider: openai
        model: "gpt-4.1"

# Optional rate limits & USD spend budgets (scopes: "*", "tag:<name>", or user subject):
# budgets:
#   - scope: "*"
#     rpm: 120
#     tpm: 200000
#     max_concurrent: 20
#     daily_usd: 50.0
#     monthly_usd: 500.0
#     soft_alert_pct: 80

guardrails:
  builtin_defaults: true
  # rules:
  #   - id: custom-internal-token
  #     name: Internal Service Token
  #     category: secret
  #     pattern: 'int_tok_[A-Za-z0-9]{24,}'
  #     action: redact # log_only | redact | block

# Optional sync_review or async_event webhooks (HMAC-SHA256 signed):
# webhooks:
#   - id: team-alerts
#     name: Team Alert Webhook
#     url: "https://hooks.example.com/headlamp"
#     type: async_event # sync_review | async_event
#     secret: "${HEADLAMP_WEBHOOK_SECRET}"
#     events:
#       - budget.threshold
#       - budget.exceeded
#       - guardrail.triggered
#       - upstream.fallback
#       - upstream.error
#     timeout_ms: 2000
#     fail_open: true

# Optional remote MCP servers proxied at /mcp/<name> and callable from Team Web Chat:
# mcp_servers:
#   - name: docs
#     url: "https://mcp-docs.internal.example.com/mcp"
#     transport: streamable_http # streamable_http | sse
#     auth_type: bearer          # none | bearer | header | basic
#     auth_token: "${DOCS_MCP_TOKEN}"

audit:
  store_payloads: false
  retention_days: 7
`
