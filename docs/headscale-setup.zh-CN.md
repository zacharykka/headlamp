# Headlamp + Headscale v0.29.7 部署指南

[English](./headscale-setup.md) | **简体中文**

本指南逐步介绍如何通过 `tsnet` 将 **Headlamp** 接入自托管的 **Headscale v0.29.7** tailnet、配置 Headscale `grants` 授权策略，以及在无需客户端 API Key 的情况下将各类 AI 编程代理指向 Headlamp。

---

## 1. 在 Headscale v0.29.7 中启用文件策略与 MagicDNS

在 Headscale 的 `config.yaml` 中进行如下配置：

```yaml
policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: tailnet.internal
```

> **提示：** Headscale 的 `dns.extra_records` 仅支持 `A` 和 `AAAA` 记录（Tailscale 客户端会忽略 `CNAME`）。启用 `magic_dns: true` 后，tailnet 内的设备即可直接通过 `http://headlamp` 或 `http://headlamp.tailnet.internal` 访问 Headlamp。

---

## 2. 配置 `tagOwners` 与 `grants`（`policy.hujson`）

Headscale v0.29.7 支持现代 `grants` 语法，可同时定义网络访问规则（`ip`）和应用级能力（`app`）。

> **重要：** 在 Headscale v0.29+ 中，仅包含 `app` 字段的 grant **不会**放行 TCP 端口。请务必在 `"app"` 同级（或在配套的 grant 规则中）同时配置 `"ip": ["tcp:80", "tcp:443"]`。

将以下内容保存为 `/etc/headscale/policy.hujson`：

```jsonc
{
  "groups": {
    "group:admins": ["alice@example.com"],
    "group:engineering": ["alice@example.com", "bob@example.com"],
    "group:interns": ["carol@example.com"]
  },

  // 创建带标签的预认证密钥或声明节点标签前必须先定义 tagOwners。
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },

  "grants": [
    // 管理员：拥有全部模型与 MCP 工具访问权限
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

    // 研发团队：使用 Headlamp 原生能力声明
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

    // headlamp.dev/cap/gateway 同样支持多对象数组及单字符串 "models" 写法。
    // 注意：Headscale v0.29.7 会拒绝 "tailscale.com/cap/*" 能力名
    // （报错 "capability name must not be in the tailscale.com domain"），因此在 Headscale 上
    // 请始终使用 "headlamp.dev/cap/gateway"。（"tailscale.com/cap/aperture" 仅用于兼容
    // 官方 Tailscale SaaS tailnet。）
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

    // 无头带标签工作负载（例如 CI Runner）
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

在 Headscale 服务器上校验并重新加载策略：

```bash
headscale policy check -f /etc/headscale/policy.hujson
kill -HUP $(pidof headscale)
# 如果使用的是数据库策略模式，请执行：
# headscale policy set -f /etc/headscale/policy.hujson
```

---

## 3. 创建 Headscale 预认证密钥

在 Headscale v0.29+ 中，带标签的预认证密钥（pre-auth key）可以直接将节点注册到 `tag:headlamp` 下，而无需绑定到特定自然人用户：

```bash
headscale preauthkeys create --reusable --expiration 24h --tags tag:headlamp
```

如果你不希望为 Headlamp 打标签（例如在 Headscale `grants` 中按用户指定 Headlamp 目标节点），可以改为创建用户级预认证密钥：

```bash
headscale preauthkeys create --user alice --reusable --expiration 24h
```

---

## 4. 配置并运行 Headlamp

Headlamp 采用纯 **grants 授权（grants-only）**模式：Tailnet 访问权限完全由 Headscale `grants` 决定（`headlamp.yaml` 中不包含本地 `policy:` 配置块）。

将 [`headlamp.example.yaml`](../headlamp.example.yaml) 复制为 `headlamp.yaml` 并修改以下字段：

```yaml
server:
  tsnet:
    enabled: true
    hostname: headlamp
    control_url: "https://headscale.example.com"
    state_dir: "./data"
  tls:
    mode: none # WireGuard 已对 tailnet 流量加密；如需自定义 HTTPS 证书请使用 mode: static
```

配置 Headscale 预认证密钥、主加密密钥及上游提供商 API Key 后启动 Headlamp：

```bash
export HEADLAMP_AUTH_KEY="<preauthkey-from-step-3>"
export HEADLAMP_MASTER_KEY="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."

make build
./bin/headlamp serve --config headlamp.yaml
```

或者通过 Docker 运行：

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

> **状态持久化：** 请将 `state_dir`（`/data`）挂载到持久化存储上。一旦 `tailscaled.state` 生成，后续重启时 `tsnet` 会忽略 `HEADLAMP_AUTH_KEY` 并保持相同的节点身份。如果你清空了 `state_dir`，请在 Headscale 中删除旧节点（`headscale nodes delete -i <id>`），以避免节点名被自动加上 `headlamp-1` 后缀。

---

## 5. 客户端配置（零上游厂商 API Key）

在已接入 Headscale tailnet 的任意设备上，将你的工具指向 `http://headlamp`（若配置了 `tls.mode: static`，则使用 `https://<your-domain>`），并填写任意非空占位密钥即可：

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

### 本地 Ollama 路由

在 `headlamp.yaml` 中配置一个 `ollama` 提供商（指向 `http://127.0.0.1:11434` 或 tailnet 内的其他 GPU 主机，如 `http://gpu-box:11434`），随后即可通过 OpenAI 兼容接口或 Anthropic 接口调用：

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
# 使用 OpenAI SDK / Codex 调用本地 Ollama（在 usage_logs 中计费为零）
curl http://headlamp/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"local/coder","messages":[{"role":"user","content":"Hello"}]}'

# 通过 Headlamp 的 Anthropic <-> OpenAI 协议转换将 Claude Code 路由至 Ollama
ANTHROPIC_BASE_URL="http://headlamp/anthropic" \
ANTHROPIC_API_KEY="headlamp" \
ANTHROPIC_MODEL="local/coder" \
claude
```

---

## 6. Headscale v0.29.7 故障排查清单

- **访问 `http://headlamp` 时连接被拒绝或超时**：检查对应的 grant 规则是否包含 `"ip": ["tcp:80", "tcp:443"]`（不能只写 `"app"`）。
- **报错 `capability name must not be in the tailscale.com domain`**：Headscale v0.29.7 禁止在策略中使用 `tailscale.com/cap/*` 能力名。在 Headscale 上请统一使用 `"headlamp.dev/cap/gateway"`（Headlamp 对 `"tailscale.com/cap/aperture"` 的兼容仅面向官方 Tailscale SaaS）。
- **带标签设备在 Headscale 中显示为 `tagged-devices`**：这是 Headscale v0.28/v0.29+ 的预期行为。Headlamp 会优先检查 `Node.IsTagged()`，并将调用方主体解析为 `tag:<name>`（例如 `tag:ci-runner`），而非 `tagged-devices`。
- **非 OIDC 本地用户**：在 Headscale v0.29.7 中，策略里的 `src` / `groups` 条目需要带尾随 `@`（例如 `"alice@"`），但 `WhoIs.UserProfile.LoginName`（展示在 `GET /whoami` 并记录在 `usage_logs.subject` 中）返回的是不带 `@` 的 `"alice"`。可在 tailnet 设备上运行 `curl http://headlamp/whoami` 以确认最终解析出的 `principal.subject` 及生效的 grants 权限。
- **Headscale 上的 HTTPS**：Tailscale SaaS 的自动 `*.ts.net` 证书（`ListenTLS`）在 Headscale 上不可用。在 WireGuard 隧道内可使用 `tls.mode: none`（默认），或使用 `tls.mode: static` 加载自定义证书和私钥。
