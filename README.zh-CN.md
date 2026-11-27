# Headlamp

[English](./README.md) | **简体中文**

Headlamp 是一个基于 Go 构建的自托管、单二进制私有 AI 网关，通过 `tsnet` 作为一等节点直接加入你的 Headscale（或 Tailscale）tailnet。tailnet 中的设备会自动凭其 tailnet 身份完成认证——无需向开发者的机器分发任何上游厂商 API Key。

## 核心能力

- **零密钥 Tailnet 身份认证与 Grants 授权**：通过 `tsnet` 直接接入 Headscale v0.29+（或 Tailscale），借助 `WhoIs` 识别调用方身份，并执行纯 **grants 授权（grants-only）**策略（支持 `headlamp.dev/cap/gateway`，在官方 Tailscale SaaS 上同时兼容 `tailscale.com/cap/aperture`）；对大语言模型（`models` / `deny_models`）和 MCP 工具（`mcp_tools` / `deny_mcp_tools`）均遵循**显式拒绝优先（Explicit Deny Wins）**原则。
- **支持 MCP 工具调用的团队 Web 对话**：内置浏览器对话工作区，面向所有已认证的 tailnet 用户开放（具备严格的单用户会话隔离）。对话响应全程经由 Headlamp 自身的代理管道流式转发（完整应用策略、安全护栏、配额与计量，无任何绕过路径），支持防 XSS 的安全 Markdown 渲染，并可在对话中途调用经授权的远程 MCP 工具。
- **远程 MCP 代理网关（`/mcp/<server>`）**：代理基于 Streamable HTTP 和 SSE 的远程 MCP 服务器，提供服务端加密凭据存储（`bearer`、自定义 `header`、`basic`）、按调用方过滤 `tools/list` 响应、`tools/call` 策略校验与工具参数护栏检测，以及专用的 `mcp_audit_logs` 审计追踪。
- **内置管理控制台与个人用量界面**：单个二进制文件中通过 `go:embed`（`web/dist`）直接内嵌 React + TypeScript + Vite 单页应用（采用 Geist 字体，零外部 CDN 请求），借助 Tailnet WhoIs SSO 自动登录。管理员可在 `/` 管理上游提供商、虚拟路由、MCP 服务器、预算、护栏、Webhook、用量分析、审计日志与 grants 策略片段；普通用户可访问团队 Web 对话、个人用量、预算以及 SDK/MCP 配置片段。
- **多协议路由与用量计量**：支持 OpenAI（`/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`）、Anthropic（`/anthropic/v1/messages`）、Google Gemini（`/gemini/v1beta/...`）和 Ollama 提供商，具备带自动故障回退（fallback）的虚拟模型别名路由、OpenAI <-> Anthropic 双向协议转换、流式 SSE Token/费用用量日志，以及支持按 TTL 自动清理的可选审计载荷记录。
- **预算、限流与配额控制**：按作用域（`*`、`tag:<name>`、用户主体）实施 RPM、TPM、最大并发数以及 UTC 日/月美元消费上限控制（超限时返回 `429` 及 `Retry-After` 响应头），并支持可配置的软告警阈值通知。将 `tpm` 和 `daily_usd`/`monthly_usd` 与 `max_concurrent` 配合使用，可在进行中的流式响应尚未完成最终 Token 与费用结算时限制突发超支。
- **安全护栏与签名 Webhook**：内置零延迟正则检测器（覆盖 OpenAI、Anthropic、AWS、GitHub 与 GCP 密钥、PEM 私钥、JWT、信用卡号、电子邮箱与电话号码），支持 `log_only`、`redact` 或 `block` 处理动作；支持自定义正则规则、同步请求前审核 Webhook（`sync_review`），以及基于 HMAC-SHA256 签名的异步事件告警（`guardrail.triggered`、`budget.threshold`、`budget.exceeded`、`upstream.fallback`、`upstream.error`）。
- **自动化 ACME DNS-01 HTTPS**：支持通过 Cloudflare API 或自定义 DNS-01 Webhook 求解器在私有 Headscale 域名上自动签发与续期 TLS 证书（`server.tls.mode: acme_dns01`），同时也支持静态证书/私钥（`static`）与纯 Tailnet 明文 HTTP（`none`）。
- **加密凭据存储与零 CGO 存储引擎（SQLite + PostgreSQL）**：上游提供商 API Key、Webhook 密钥与 MCP 认证令牌均使用 AES-256-GCM 静态加密存储（密钥来自 `HEADLAMP_MASTER_KEY`，若未指定则在 `state_dir` 中自动生成 `0600` 权限密钥文件）；存储后端可选纯 Go 实现的 SQLite（`modernc.org/sqlite`，WAL 模式）或适用于多副本高可用部署的纯 Go PostgreSQL（`pgx/v5`）。
- **本地开发、静态兜底令牌与发布自动化**：支持可选的本地 HTTP 监听地址、仅限本地回环（loopback）访问的 `dev_mode` 以及供 CI Runner 使用的静态兜底 API 令牌，并配备 GitHub Actions CI、多架构 `CGO_ENABLED=0` GitHub Releases 与 GHCR Docker 镜像发布流程。

## 配置说明

将 [`headlamp.example.yaml`](headlamp.example.yaml) 复制为 `headlamp.yaml`，并根据你的 Headscale/Tailscale 网络与上游提供商进行调整：

```bash
cp headlamp.example.yaml headlamp.yaml
export HEADLAMP_MASTER_KEY=$(openssl rand -hex 32)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

常用环境变量覆盖项：

| 变量名 | 说明 |
| :--- | :--- |
| `HEADLAMP_CONFIG` | YAML 配置文件路径 |
| `HEADLAMP_MASTER_KEY` | 32 字节 AES-256-GCM 主密钥（64 位十六进制或 Base64）；若省略则自动生成于 `state_dir/master.key` |
| `HEADLAMP_CONTROL_URL` | Headscale 控制服务器地址（使用官方 Tailscale 时留空） |
| `HEADLAMP_AUTH_KEY` | 用于首次 `tsnet` 注册的预认证密钥（pre-auth key） |
| `HEADLAMP_STATE_DIR` | 存放 `tsnet` 状态及自动生成主密钥的持久化目录 |
| `HEADLAMP_LOCAL_LISTEN` | 可选的本地 HTTP 监听地址（当 `dev_mode: true` 时必须为回环地址 `127.0.0.1` / `::1` / `localhost`） |
| `HEADLAMP_DEV_MODE` | 启用本地模拟身份（`true`/`false`；要求 `local_listen` 为回环地址） |
| `HEADLAMP_DEV_USER` | 启用 `dev_mode` 时的模拟主体标识（subject） |
| `HEADLAMP_DEV_ALLOW_HEADER_OVERRIDE` | 在 `dev_mode` 下是否允许来自回环对端的 `X-Headlamp-Dev-*` 身份请求头（默认 `false`） |
| `HEADLAMP_STORAGE_DRIVER` | 存储后端驱动：`sqlite`（默认）或 `postgres` |
| `HEADLAMP_STORAGE_DSN` | 数据库文件路径或连接字符串 |
| `HEADLAMP_TLS_MODE` | Tailnet TLS 模式：`none`、`static` 或 `acme_dns01` |
| `HEADLAMP_TLS_DOMAIN` | `acme_dns01` 模式下申请证书的域名 |
| `HEADLAMP_TLS_ACME_EMAIL` | `acme_dns01` 模式下的 ACME 账号联系邮箱 |
| `HEADLAMP_TLS_DNS_PROVIDER` | DNS-01 校验求解器：`cloudflare` 或 `webhook` |
| `HEADLAMP_TLS_DNS_API_TOKEN` | 用于 DNS-01 校验的 Cloudflare API 令牌或 Webhook Bearer 令牌 |
| `HEADLAMP_TLS_DNS_WEBHOOK_URL` | 自定义 DNS-01 Webhook 接口地址 |
| `HEADLAMP_STARTUP_TIMEOUT` | 监听器 / `tsnet` / ACME 启动超时覆盖值（例如 `3m`；`acme_dns01` 默认 `5m`，其余模式默认 `60s`） |

## 客户端快速开始

Headlamp 在 tailnet 上启动并运行后（例如主机名为 `headlamp`）：

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

# Claude Code 远程 MCP 服务器
claude mcp add --transport http headlamp-docs http://headlamp/mcp/docs
```

完整的开箱即用配置示例（Claude Code、Codex CLI、Gemini CLI、Cursor、Python/Node SDK、远程 MCP 客户端以及 PostgreSQL 高可用部署）请参阅 [`docs/clients.zh-CN.md`](docs/clients.zh-CN.md)。

## Headscale v0.29.7 `grants` 策略示例

Headlamp 采用纯 **grants 授权（grants-only）**机制。在 Headscale v0.29.7 中，请使用 `headlamp.dev/cap/gateway` 授予访问权限（注意：Headscale v0.29.7 会拒绝 `tailscale.com/cap/*` 命名空间下的能力名；当接入官方 Tailscale SaaS 时，Headlamp 同样兼容 `tailscale.com/cap/aperture`）：

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

完整的 Headscale v0.29.7 部署与策略配置指南请参阅 [`docs/headscale-setup.zh-CN.md`](docs/headscale-setup.zh-CN.md) 与 [`headlamp.example.yaml`](headlamp.example.yaml)。

## 本地开发与构建

构建单二进制文件时会自动编译内嵌的 React 管理控制台（`web/dist`），并将其打包到 `./bin/headlamp`：

```bash
make test-race
make build
```

如需针对本地 Headlamp 后端进行带热重载的前端 UI 开发：

```bash
make run-dev
npm --prefix web run dev
```

## 仓库目录结构

```text
headlamp/
├── .github/workflows/  # CI（前端与 Go race 测试）及多架构二进制/GHCR 发布流水线
├── cmd/headlamp/       # CLI 入口（serve、init、usage、version）与运行时装配
├── internal/
│   ├── api/            # 管理、用户、对话与 MCP REST/SSE API（/api/v1/*）、RBAC、CSRF 与 SPA 托管
│   ├── auth/           # 主体身份模型、上下文辅助函数、开发模式与静态令牌认证
│   ├── chat/           # 团队 Web 对话编排、流式 SSE 与多轮 MCP 工具调用
│   ├── config/         # YAML 配置加载、环境变量覆盖与校验
│   ├── crypto/         # AES-256-GCM 加密与主密钥管理
│   ├── guardrail/      # 本地正则检测器、同步审核与签名异步 Webhook
│   ├── mcp/            # 远程 MCP 代理（/mcp/*）、工具过滤、安全护栏与发现客户端
│   ├── metering/       # 流式 SSE 用量解析、定价表与异步持久化
│   ├── netts/          # tsnet 节点生命周期、Headscale 连接、ACME DNS-01 与 TLS
│   ├── policy/         # 纯 grants 策略评估器（显式拒绝优先）
│   ├── proxy/          # 原生协议优先的多协议 LLM 反向代理
│   ├── quota/          # 按作用域实施的 RPM/TPM/并发数与美元预算配额控制
│   ├── store/          # 存储接口、纯 Go SQLite 与 PostgreSQL（pgx/v5）驱动及迁移
│   └── translate/      # 按需跨协议请求与 SSE 流式响应转换
├── web/                # 内嵌的 React + TypeScript + Vite 管理控制台与团队 Web 对话 SPA
├── deploy/             # 多阶段静态 Dockerfile（Node 前端构建 + Go 二进制）
└── docs/               # 客户端配置示例（docs/clients.zh-CN.md）、Headscale v0.29.7 指南与规范文档
```
