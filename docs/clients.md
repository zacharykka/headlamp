# Headlamp Client & Deployment Recipes

Headlamp authenticates tailnet devices automatically via `tsnet` `WhoIs`. Replace `http://headlamp` with your HTTPS MagicDNS or ACME DNS-01 URL (for example `https://headlamp.internal.example.com`) when TLS is enabled.

When connecting over the tailnet, the API key environment variable is only a non-empty placeholder required by client SDKs—Headlamp ignores it and injects the encrypted upstream vendor key from its store. For non-tailnet callers (such as CI runners hitting `local_listen`), replace `"headlamp"` with your configured `server.api_tokens` value.

---

## Claude Code

```bash
export ANTHROPIC_BASE_URL="http://headlamp/anthropic"
export ANTHROPIC_API_KEY="headlamp"
claude
```

Attach a Headlamp-proxied remote MCP server (for example `docs`):

```bash
claude mcp add --transport http headlamp-docs http://headlamp/mcp/docs
```

---

## OpenAI Codex CLI

```bash
export OPENAI_BASE_URL="http://headlamp/v1"
export OPENAI_API_KEY="headlamp"
codex
```

Or persist it in `~/.codex/config.toml`:

```toml
model_provider = "headlamp"

[model_providers.headlamp]
name = "Headlamp"
base_url = "http://headlamp/v1"
env_key = "OPENAI_API_KEY"
```

---

## Google Gemini CLI

```bash
export GEMINI_API_BASE="http://headlamp/gemini"
export GOOGLE_GEMINI_BASE_URL="http://headlamp/gemini"
export GEMINI_API_KEY="headlamp"
gemini
```

---

## Cursor

1. Open **Settings → Models → OpenAI API Key**.
2. Set **API Key** to `headlamp`.
3. Enable **Override OpenAI Base URL** and set it to `http://headlamp/v1`.
4. Add virtual aliases (such as `team/coding`) or upstream models authorized by your tailnet grants.

To connect Cursor to a Headlamp-proxied remote MCP server, add `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "headlamp-docs": {
      "url": "http://headlamp/mcp/docs"
    },
    "headlamp-github": {
      "url": "http://headlamp/mcp/github"
    }
  }
}
```

---

## Official SDKs

### OpenAI (Python & Node.js)

```python
from openai import OpenAI

client = OpenAI(base_url="http://headlamp/v1", api_key="headlamp")
resp = client.chat.completions.create(
    model="team/coding",
    messages=[{"role": "user", "content": "Explain tsnet WhoIs in two sentences."}],
)
print(resp.choices[0].message.content)
```

```ts
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "http://headlamp/v1", apiKey: "headlamp" });
const resp = await client.chat.completions.create({
  model: "gpt-5",
  messages: [{ role: "user", content: "Hello from Headlamp" }],
});
console.log(resp.choices[0].message.content);
```

### Anthropic (Python & Node.js)

```python
import anthropic

client = anthropic.Anthropic(base_url="http://headlamp/anthropic", api_key="headlamp")
msg = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=512,
    messages=[{"role": "user", "content": "Hello Claude"}],
)
print(msg.content[0].text)
```

```ts
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ baseURL: "http://headlamp/anthropic", apiKey: "headlamp" });
const msg = await client.messages.create({
  model: "claude-sonnet-4-6",
  max_tokens: 512,
  messages: [{ role: "user", content: "Hello Claude" }],
});
console.log(msg.content);
```

### Google GenAI (Python & Node.js)

```python
from google import genai
from google.genai import types

client = genai.Client(
    api_key="headlamp",
    http_options=types.HttpOptions(base_url="http://headlamp/gemini"),
)
resp = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Summarize zero-trust tailnet networking.",
)
print(resp.text)
```

```ts
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: "headlamp",
  httpOptions: { baseUrl: "http://headlamp/gemini" },
});
const resp = await ai.models.generateContent({
  model: "gemini-2.5-flash",
  contents: "Summarize zero-trust tailnet networking.",
});
console.log(resp.text);
```

---

## Remote MCP Gateway (`/mcp/<server>`)

Headlamp proxies remote MCP servers over **Streamable HTTP** (`transport: streamable_http`) and **SSE** (`transport: sse`) at:

```text
http://headlamp/mcp/<server-name>
```

How authorization and auditing work:

1. Upstream credentials (`bearer`, custom `header`, or `basic`) are stored AES-256-GCM encrypted in Headlamp and injected server-side—developers never receive raw MCP tokens.
2. `tools/list` responses are filtered per caller using `mcp_tools` / `deny_mcp_tools` glob patterns (`<server>/<tool>`).
3. `tools/call` checks policy authorization (Explicit Deny Wins) and runs local guardrail inspection on tool arguments before forwarding to the upstream MCP server.
4. Every invocation is recorded in `mcp_audit_logs` and visible in the **MCP Gateway** admin view.

---

## Headscale v0.29.7 Grants (`models` + `mcp_tools`)

Headscale v0.29.7 requires the custom capability name `headlamp.dev/cap/gateway` (it rejects `tailscale.com/cap/*`) and explicit `"ip": ["tcp:80", "tcp:443"]` ports. Non-OIDC Headscale users require a trailing `@` in policy `groups`/`src` (e.g. `"alice@"`), while `WhoIs` and `/whoami` report `"alice"`.

```jsonc
{
  "groups": {
    "group:admins": ["alice@"],
    "group:engineering": ["alice@", "bob@"]
  },
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },
  "grants": [
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
    {
      "src": ["group:engineering"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["anthropic/*", "openai/gpt-5*", "gemini/*", "team/*"],
            "deny_models": ["openai/o3*"],
            "mcp_tools": ["docs/*", "github/read_*", "github/search_*"],
            "deny_mcp_tools": ["github/delete_*"]
          }
        ]
      }
    }
  ]
}
```

---

## PostgreSQL Multi-Replica Deployment

Headlamp ships with a pure-Go PostgreSQL driver (`pgx/v5`, zero CGO) and advisory-locked schema migrations so multiple stateless replicas can share one database:

```yaml
storage:
  driver: postgres
  dsn: "postgres://headlamp:${HEADLAMP_PG_PASSWORD}@pg.internal:5432/headlamp?sslmode=require"
```

Or via environment variables:

```bash
export HEADLAMP_MASTER_KEY="<shared-64-char-hex-key-across-all-replicas>"
export HEADLAMP_STORAGE_DRIVER="postgres"
export HEADLAMP_STORAGE_DSN="postgres://headlamp:secret@pg.internal:5432/headlamp?sslmode=require"
./bin/headlamp serve -config headlamp.yaml
```

> **Important**: All replicas sharing a PostgreSQL database must use the exact same `HEADLAMP_MASTER_KEY` so encrypted provider API keys, webhook secrets, and MCP auth tokens decrypt identically on every instance.
