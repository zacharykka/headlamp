# Headlamp 客户端与部署配置指南

[English](./clients.md) | **简体中文**

Headlamp 通过 `tsnet` 的 `WhoIs` 自动认证 tailnet 设备。如果启用了 TLS，请将下文中的 `http://headlamp` 替换为你的 HTTPS MagicDNS 或 ACME DNS-01 域名地址（例如 `https://headlamp.internal.example.com`）。

通过 tailnet 访问时，API Key 环境变量只是客户端 SDK 要求的非空占位符——Headlamp 会忽略该值，并从自身的加密存储中注入对应的上游厂商密钥。对于非 tailnet 调用方（例如访问 `local_listen` 的 CI Runner），请将 `"headlamp"` 替换为你配置的 `server.api_tokens` 令牌值。

---

## Claude Code

```bash
export ANTHROPIC_BASE_URL="http://headlamp/anthropic"
export ANTHROPIC_API_KEY="headlamp"
claude
```

挂载由 Headlamp 代理的远程 MCP 服务器（以 `docs` 为例）：

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

或者将配置持久化到 `~/.codex/config.toml`：

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

1. 打开 **Settings → Models → OpenAI API Key**。
2. 将 **API Key** 设为 `headlamp`。
3. 启用 **Override OpenAI Base URL**，并将其设为 `http://headlamp/v1`。
4. 添加你在 tailnet grants 中获得授权的虚拟模型别名（例如 `team/coding`）或上游模型名称。

如需在 Cursor 中连接由 Headlamp 代理的远程 MCP 服务器，可添加 `.cursor/mcp.json`：

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

## 官方 SDK

### OpenAI（Python & Node.js）

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

### Anthropic（Python & Node.js）

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
  messages: [{ role: "user", "content": "Hello Claude" }],
});
console.log(msg.content);
```

### Google GenAI（Python & Node.js）

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

## 远程 MCP 网关（`/mcp/<server>`）

Headlamp 通过 **Streamable HTTP**（`transport: streamable_http`）和 **SSE**（`transport: sse`）在以下路径代理远程 MCP 服务器：

```text
http://headlamp/mcp/<server-name>
```

授权与审计工作机制：

1. 上游凭据（`bearer`、自定义 `header` 或 `basic`）经 AES-256-GCM 加密后保存在 Headlamp 服务端并在转发时自动注入——开发者永远不会接触到原始 MCP 令牌。
2. `tools/list` 响应会依据调用方的 `mcp_tools` / `deny_mcp_tools` 通配规则（`<server>/<tool>`）按人过滤。
3. `tools/call` 会先执行策略权限校验（显式拒绝优先）并对工具参数运行本地安全护栏检测，通过后再转发至上游 MCP 服务器。
4. 每次调用均记录在 `mcp_audit_logs` 中，并可在管理控制台的 **MCP Gateway** 视图中查看。

---

## Headscale v0.29.7 Grants 配置（`models` + `mcp_tools`）

Headscale v0.29.7 要求使用自定义能力名 `headlamp.dev/cap/gateway`（会拒绝 `tailscale.com/cap/*`），并且必须显式声明 `"ip": ["tcp:80", "tcp:443"]` 端口规则。非 OIDC 的 Headscale 用户在策略 `groups`/`src` 中需要带尾随 `@`（例如 `"alice@"`），而 `WhoIs` 与 `/whoami` 返回的是不带 `@` 的 `"alice"`。

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

## PostgreSQL 多副本高可用部署

Headlamp 内置纯 Go PostgreSQL 驱动（`pgx/v5`，零 CGO）及基于咨询锁（advisory lock）的数据库结构迁移机制，支持多个无状态副本共享同一个数据库：

```yaml
storage:
  driver: postgres
  dsn: "postgres://headlamp:${HEADLAMP_PG_PASSWORD}@pg.internal:5432/headlamp?sslmode=require"
```

或通过环境变量配置：

```bash
export HEADLAMP_MASTER_KEY="<shared-64-char-hex-key-across-all-replicas>"
export HEADLAMP_STORAGE_DRIVER="postgres"
export HEADLAMP_STORAGE_DSN="postgres://headlamp:secret@pg.internal:5432/headlamp?sslmode=require"
./bin/headlamp serve -config headlamp.yaml
```

> **重要**：共享同一 PostgreSQL 数据库的所有副本必须使用完全相同的 `HEADLAMP_MASTER_KEY`，以确保加密存储的上游提供商 API Key、Webhook 密钥与 MCP 认证令牌在每个实例上都能正确解密。
