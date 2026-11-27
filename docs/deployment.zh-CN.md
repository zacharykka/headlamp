# 生产部署指南（Docker Compose 与 systemd 二进制）

[English](./deployment.md) | **简体中文**

本文介绍两种在生产环境部署 **Headlamp** 的标准方式：**Docker Compose**（官方 GHCR Distroless 容器镜像）以及 **Linux 静态二进制 + `systemd` 托管**。

> 如果你尚未在 Headscale 中配置 `grants` 与 `tagOwners`，请先阅读 [Headscale v0.29.7 部署与授权指南](./headscale-setup.zh-CN.md)，提前准备好预认证密钥（pre-auth key）与 ACL 策略后再启动 Headlamp。

---

## 部署前准备

1. **Tailnet 身份与 Grants 授权**：
   - 在 Headscale（例如带 `tag:headlamp` 标签）或 Tailscale 后台创建一个预认证密钥（pre-auth key）。
   - 确保策略中已放行 `"ip": ["tcp:80", "tcp:443"]` 并配置了 `headlamp.dev/cap/gateway` 授权规则（若接入官方 Tailscale SaaS 也可使用 `tailscale.com/cap/aperture`）。
2. **静态加密主密钥（`HEADLAMP_MASTER_KEY`）**：
   - 生成一次 32 字节主密钥并妥善保存到密钥库中：
     ```bash
     openssl rand -hex 32
     ```
   - Headlamp 使用该密钥通过 AES-256-GCM 对上游提供商 API Key、Webhook 密钥和 MCP 认证令牌做静态加密。如果丢失该密钥，数据库中已加密的凭据将无法解密；使用 PostgreSQL 多副本部署时，所有实例必须共享完全相同的 `HEADLAMP_MASTER_KEY`。
3. **选择存储后端**：
   - **SQLite（`sqlite`）**：零外部依赖的默认方案，数据文件位于 `state_dir/headlamp.db`（WAL 模式），适合单节点部署。
   - **PostgreSQL（`postgres`）**：基于纯 Go 驱动 `pgx/v5`（零 CGO），适合多副本高可用或集中式数据库备份场景。

---

## 方式一：Docker Compose 部署

Headlamp 在 GitHub Container Registry 发布多架构（`linux/amd64`、`linux/arm64`）Distroless 静态镜像（`gcr.io/distroless/static-debian12:nonroot`，运行用户 UID/GID 为 `65532:65532`）：

- `ghcr.io/zacharykka/headlamp:latest`
- 版本号标签，例如 `ghcr.io/zacharykka/headlamp:2026.11.27`

由于 `tsnet` 完全运行在用户态，容器**不需要** `/dev/net/tun` 设备、**不需要** `NET_ADMIN` 权限，也**不需要** root 权限。此外请注意 `distroless` 镜像内刻意不包含 Shell（`sh`）或 `curl`。

### 1. 准备配置文件与环境变量

在仓库 `deploy/` 目录下操作（或将 `deploy/docker-compose.yml` 与 `deploy/headlamp.env.example` 复制到 `/opt/headlamp/`）：

```bash
cd deploy
cp ../headlamp.example.yaml ./headlamp.yaml
cp ./headlamp.env.example ./headlamp.env
chmod 600 ./headlamp.env ./headlamp.yaml
```

编辑 `deploy/headlamp.yaml`：

- 设置 `server.tsnet.enabled: true`、`hostname: headlamp`、`control_url` 以及 `state_dir: /data`。
- 务必保持 `server.dev_mode: false`，除非你明确需要容器内的本地 HTTP 探活监听，否则 `server.local_listen` 留空即可。
- 保持 `storage.driver: sqlite` 与 `storage.dsn: /data/headlamp.db`（若使用 PostgreSQL 版 Compose 文件会自动覆盖）。

编辑 `deploy/headlamp.env`：

```dotenv
HEADLAMP_MASTER_KEY=<填入 openssl rand -hex 32 的输出>
HEADLAMP_CONTROL_URL=https://headscale.example.com
HEADLAMP_AUTH_KEY=<你的 Headscale 预认证密钥>
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

### 2A. 使用 SQLite 启动（单节点推荐）

使用 [`deploy/docker-compose.yml`](../deploy/docker-compose.yml)，已启用 `read_only: true`、`cap_drop: ["ALL"]`、`tmpfs: ["/tmp"]` 以及持久化命名卷 `headlamp_data:/data`：

```bash
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml logs -f headlamp
```

### 2B. 使用 PostgreSQL 启动（自带数据库栈）

使用 [`deploy/docker-compose.postgres.yml`](../deploy/docker-compose.postgres.yml)（内置 `postgres:17-alpine` 与健康检查）。先在 `deploy/headlamp.env` 中设置 `HEADLAMP_PG_PASSWORD`，再启动：

```bash
docker compose -f docker-compose.postgres.yml --env-file ./headlamp.env up -d
docker compose -f docker-compose.postgres.yml logs -f headlamp
```

> **宿主机目录挂载注意事项**：使用 Docker 命名卷（`headlamp_data`）时会自动继承镜像内 `/data` 的 `65532:65532` 属主；如果你将其改成了宿主机目录绑定挂载（如 `./data:/data`），请务必先执行 `mkdir -p ./data && chown -R 65532:65532 ./data`，否则非 root 容器会无权写入 `headlamp.db` 与 `tsnet` 状态文件。
>
> **本地监听安全提醒**：如果因健康检查或排障需要取消注释 `ports: ["127.0.0.1:8080:8080"]` 和 `HEADLAMP_LOCAL_LISTEN=0.0.0.0:8080`，请**始终保持 `dev_mode: false`**，并且仅在宿主机侧绑定 `127.0.0.1:8080:8080`。

### 3. 容器升级

生产环境建议在 `docker-compose.yml` 中锁定具体版本标签（例如 `ghcr.io/zacharykka/headlamp:2026.11.27`）：

```bash
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
```

如果想从本地源码构建而不拉取 GHCR 镜像，取消 `docker-compose.yml` 中 `build:` 块的注释并运行 `docker compose -f docker-compose.yml up -d --build` 即可。

---

## 方式二：Linux 静态二进制 + `systemd` 部署

Headlamp 编译为单个 `CGO_ENABLED=0` 静态二进制文件，React 管理控制台与团队 Web 对话前端已直接内嵌在二进制中。

### 1. 下载并校验二进制（或从源码编译）

从 GitHub Releases 下载对应架构（`linux_amd64` 或 `linux_arm64`）的压缩包并校验 SHA-256：

```bash
VERSION="v2026.11.27"
ARCH="amd64" # 或 arm64

curl -fsSLO "https://github.com/zacharykka/headlamp/releases/download/${VERSION}/headlamp_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "https://github.com/zacharykka/headlamp/releases/download/${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt

tar -xzf "headlamp_${VERSION}_linux_${ARCH}.tar.gz" headlamp
sudo install -m 0755 headlamp /usr/local/bin/headlamp
headlamp version
```

也可以在已安装 Node.js 22 与 Go 的机器上从源码自行构建：

```bash
make build
sudo install -m 0755 ./bin/headlamp /usr/local/bin/headlamp
```

### 2. 创建系统用户、目录与配置

```bash
sudo useradd --system --home-dir /var/lib/headlamp --shell /usr/sbin/nologin headlamp
sudo install -d -o root -g headlamp -m 0750 /etc/headlamp
sudo install -d -o headlamp -g headlamp -m 0700 /var/lib/headlamp

sudo install -o root -g headlamp -m 0640 headlamp.example.yaml /etc/headlamp/headlamp.yaml
sudo install -o root -g headlamp -m 0640 deploy/headlamp.env.example /etc/headlamp/headlamp.env
```

编辑 `/etc/headlamp/headlamp.yaml`（设置 `server.tsnet.enabled: true`、`control_url`、`state_dir: /var/lib/headlamp`、`dev_mode: false`、`storage.dsn: /var/lib/headlamp/headlamp.db`），并填写 `/etc/headlamp/headlamp.env`：

```dotenv
HEADLAMP_MASTER_KEY=<填入 openssl rand -hex 32 的输出>
HEADLAMP_CONTROL_URL=https://headscale.example.com
HEADLAMP_AUTH_KEY=<你的 Headscale 预认证密钥>
HEADLAMP_STATE_DIR=/var/lib/headlamp
HEADLAMP_STORAGE_DRIVER=sqlite
HEADLAMP_STORAGE_DSN=/var/lib/headlamp/headlamp.db
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

> **使用 ACME DNS-01 自动化 HTTPS 时**：首次签发证书和等待 DNS TXT 记录传播可能会超过 120 秒。请在 `/etc/headlamp/headlamp.env` 中设置 `HEADLAMP_STARTUP_TIMEOUT=5m`，并将 `headlamp.service` 中的 `TimeoutStartSec=120s` 调大到 `360s`。

### 3. 安装并启动 `systemd` 服务

复制模板文件 [`deploy/headlamp.service`](../deploy/headlamp.service) 并设为开机自启：

```bash
sudo cp deploy/headlamp.service /etc/systemd/system/headlamp.service
sudo systemctl daemon-reload
sudo systemctl enable --now headlamp
```

查看运行状态与实时日志：

```bash
sudo systemctl status headlamp
sudo journalctl -u headlamp -f
```

### 4. 平滑升级二进制

```bash
sudo install -m 0755 headlamp /usr/local/bin/headlamp
sudo systemctl restart headlamp
sudo systemctl status headlamp --no-pager
```

SQLite 与 PostgreSQL 的数据库结构迁移会在服务启动时自动执行。

---

## 部署后验证

1. **在 Headscale 上确认节点已上线**：
   ```bash
   headscale nodes list
   ```
   确认列表中出现 `headlamp` 节点、已分配的 tailnet IP（`100.64.x.x` / `fd7a:...`）以及对应标签（如 `tag:headlamp`）。
2. **从 tailnet 内已授权设备测试连通性与身份**：
   ```bash
   curl -fsS http://headlamp/healthz
   curl -fsS http://headlamp/whoami
   ```
   若启用了 `static` 或 `acme_dns01` HTTPS，请改用 `https://<你的域名>/healthz`。
3. **打开 Web 控制台**：
   在 tailnet 内的浏览器访问 `http://headlamp/`（或 `https://<你的域名>/`），即可通过 Tailnet WhoIs 自动登录管理后台或团队 Web 对话。
4. **接入编码客户端**：
   按照[客户端接入指南](./clients.zh-CN.md)配置 Claude Code、Codex CLI、Gemini CLI、Cursor 与远程 MCP。

---

## 备份、恢复与日常运维

- **必须备份的四项关键资产**：
  1. `HEADLAMP_MASTER_KEY`（位于 `headlamp.env` 或 `state_dir/master.key`）—— 解密已保存 API Key 与凭据的唯一主密钥。
  2. `state_dir/tsnet/tailscaled.state` —— 迁移或重建机器时保留它即可沿用相同的 tailnet 节点身份与 Tailscale IP。
  3. `/etc/headlamp/headlamp.yaml` —— YAML 声明式配置。
  4. 数据库 —— 使用安全的在线备份命令，避免直接拷贝正在写入的 WAL 文件：
     ```bash
     # systemd + SQLite
     sudo sqlite3 /var/lib/headlamp/headlamp.db ".backup '/var/backups/headlamp-$(date +%F).db'"

     # Docker Compose + PostgreSQL
     docker exec headlamp-postgres pg_dump -U headlamp headlamp > "headlamp-$(date +%F).sql"
     ```
- **清理一次性预认证密钥**：当 `tsnet` 成功注册并持久化 `tailscaled.state` 后，可按需从 `headlamp.env` 或 `headlamp.yaml` 中移除一次性的 `HEADLAMP_AUTH_KEY`，避免长期在环境文件中保留未使用的注册密钥。
