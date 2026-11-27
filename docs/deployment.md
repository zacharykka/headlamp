# Production Deployment Guide (Docker Compose & systemd Binary)

**English** | [简体中文](./deployment.zh-CN.md)

This guide covers deploying **Headlamp** in production using either **Docker Compose** (GHCR distroless container images) or a **standalone Linux binary managed by `systemd`**.

> If you have not configured Headscale `grants` and `tagOwners` yet, read the [Headscale v0.29.7 Setup Guide](./headscale-setup.md) first so your pre-auth key and ACLs are ready before starting Headlamp.

---

## Before You Deploy

1. **Tailnet identity & grants**:
   - Create a reusable or one-off **pre-auth key** in Headscale (for example tagged `tag:headlamp`) or Tailscale.
   - Ensure your Headscale policy allows `tcp:80` / `tcp:443` and defines `headlamp.dev/cap/gateway` grants (or `tailscale.com/cap/aperture` on Tailscale SaaS).
2. **Encryption key (`HEADLAMP_MASTER_KEY`)**:
   - Generate a 32-byte key once and keep it in a password manager or secret store:
     ```bash
     openssl rand -hex 32
     ```
   - Headlamp uses this key with AES-256-GCM to encrypt provider API keys, webhook secrets, and MCP auth tokens at rest. Losing it makes stored credentials unreadable; PostgreSQL HA replicas must share the exact same key.
3. **Storage backend**:
   - **SQLite (`sqlite`)**: Zero-dependency default in `state_dir/headlamp.db` (WAL mode). Best for single-node deployments.
   - **PostgreSQL (`postgres`)**: Recommended for multi-replica HA or centralized database backups (`pgx/v5`, zero CGO).

---

## Option 1: Docker Compose Deployment

Headlamp publishes multi-arch (`linux/amd64`, `linux/arm64`) distroless container images (`gcr.io/distroless/static-debian12:nonroot`, UID/GID `65532:65532`) to GitHub Container Registry:

- `ghcr.io/zacharykka/headlamp:latest`
- Release tags such as `ghcr.io/zacharykka/headlamp:2026.11.27`

Because `tsnet` runs in pure userspace, the container needs **no** `/dev/net/tun` device, **no** `NET_ADMIN` capability, and **no** root privileges. Note that `distroless` intentionally contains no shell (`sh`) or `curl`.

### 1. Prepare config and environment files

From the repository's `deploy/` directory (or copy `deploy/docker-compose.yml` and `deploy/headlamp.env.example` into `/opt/headlamp/`):

```bash
cd deploy
cp ../headlamp.example.yaml ./headlamp.yaml
cp ./headlamp.env.example ./headlamp.env
chmod 600 ./headlamp.env ./headlamp.yaml
```

Edit `deploy/headlamp.yaml`:

- Set `server.tsnet.enabled: true`, `hostname: headlamp`, `control_url`, and `state_dir: /data`.
- Set `server.dev_mode: false` and leave `server.local_listen` empty unless you explicitly need a container-exposed HTTP probe listener.
- Keep `storage.driver: sqlite` and `storage.dsn: /data/headlamp.db` (overridden automatically when using the PostgreSQL compose file).

Edit `deploy/headlamp.env`:

```dotenv
HEADLAMP_MASTER_KEY=<paste output from: openssl rand -hex 32>
HEADLAMP_CONTROL_URL=https://headscale.example.com
HEADLAMP_AUTH_KEY=<your-headscale-preauth-key>
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

### 2A. Start with SQLite (Single Node)

Uses [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) with `read_only: true`, `cap_drop: ["ALL"]`, `tmpfs: ["/tmp"]`, and a persistent named volume `headlamp_data:/data`:

```bash
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml logs -f headlamp
```

### 2B. Start with PostgreSQL (Bundled DB Stack)

Uses [`deploy/docker-compose.postgres.yml`](../deploy/docker-compose.postgres.yml) (`postgres:17-alpine` + healthcheck). Set `HEADLAMP_PG_PASSWORD` in `deploy/headlamp.env` first, then start:

```bash
docker compose -f docker-compose.postgres.yml --env-file ./headlamp.env up -d
docker compose -f docker-compose.postgres.yml logs -f headlamp
```

> **Bind mounts note**: Named volumes (`headlamp_data`) automatically inherit `65532:65532` ownership from the image. If you change `headlamp_data:/data` to a host path like `./data:/data`, run `mkdir -p ./data && chown -R 65532:65532 ./data` first so the non-root container can write `headlamp.db` and `tsnet` state.
>
> **Local listener security**: If you uncomment `ports: ["127.0.0.1:8080:8080"]` and `HEADLAMP_LOCAL_LISTEN=0.0.0.0:8080` for local scraping/debugging, keep `dev_mode: false` and bind only `127.0.0.1:8080:8080` on the host.

### 3. Upgrade the container

Pinning a release version tag in `docker-compose.yml` (for example `ghcr.io/zacharykka/headlamp:2026.11.27`) is recommended for production:

```bash
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
```

To build directly from a local checkout instead of pulling from GHCR, uncomment the `build:` block in `docker-compose.yml` and run `docker compose -f docker-compose.yml up -d --build`.

---

## Option 2: Linux Binary + `systemd` Deployment

Headlamp compiles to a single static `CGO_ENABLED=0` binary with the React admin & Web Chat UI embedded inside.

### 1. Download and verify the binary (or build from source)

Download the matching release tarball for `linux_amd64` or `linux_arm64` from GitHub Releases and verify its SHA-256 checksum:

```bash
VERSION="v2026.11.27"
ARCH="amd64" # or arm64

curl -fsSLO "https://github.com/zacharykka/headlamp/releases/download/${VERSION}/headlamp_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "https://github.com/zacharykka/headlamp/releases/download/${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt

tar -xzf "headlamp_${VERSION}_linux_${ARCH}.tar.gz" headlamp
sudo install -m 0755 headlamp /usr/local/bin/headlamp
headlamp version
```

Or build from source on a machine with Node.js 22 and Go installed:

```bash
make build
sudo install -m 0755 ./bin/headlamp /usr/local/bin/headlamp
```

### 2. Create service user, directories, and configuration

```bash
sudo useradd --system --home-dir /var/lib/headlamp --shell /usr/sbin/nologin headlamp
sudo install -d -o root -g headlamp -m 0750 /etc/headlamp
sudo install -d -o headlamp -g headlamp -m 0700 /var/lib/headlamp

sudo install -o root -g headlamp -m 0640 headlamp.example.yaml /etc/headlamp/headlamp.yaml
sudo install -o root -g headlamp -m 0640 deploy/headlamp.env.example /etc/headlamp/headlamp.env
```

Update `/etc/headlamp/headlamp.yaml` (`server.tsnet.enabled: true`, `control_url`, `state_dir: /var/lib/headlamp`, `dev_mode: false`, `storage.dsn: /var/lib/headlamp/headlamp.db`) and populate `/etc/headlamp/headlamp.env`:

```dotenv
HEADLAMP_MASTER_KEY=<paste output from: openssl rand -hex 32>
HEADLAMP_CONTROL_URL=https://headscale.example.com
HEADLAMP_AUTH_KEY=<your-headscale-preauth-key>
HEADLAMP_STATE_DIR=/var/lib/headlamp
HEADLAMP_STORAGE_DRIVER=sqlite
HEADLAMP_STORAGE_DSN=/var/lib/headlamp/headlamp.db
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

> **ACME DNS-01 TLS**: If you set `HEADLAMP_TLS_MODE=acme_dns01`, initial certificate issuance and DNS propagation can take more than 120 seconds. Set `HEADLAMP_STARTUP_TIMEOUT=5m` in `/etc/headlamp/headlamp.env` and set `TimeoutStartSec=360s` in `headlamp.service`.

### 3. Install and enable the `systemd` unit

Copy [`deploy/headlamp.service`](../deploy/headlamp.service) and start the service:

```bash
sudo cp deploy/headlamp.service /etc/systemd/system/headlamp.service
sudo systemctl daemon-reload
sudo systemctl enable --now headlamp
```

Check service health and live logs:

```bash
sudo systemctl status headlamp
sudo journalctl -u headlamp -f
```

### 4. Upgrade the binary cleanly

```bash
sudo install -m 0755 headlamp /usr/local/bin/headlamp
sudo systemctl restart headlamp
sudo systemctl status headlamp --no-pager
```

SQLite and PostgreSQL schema migrations run automatically on startup.

---

## Post-Deployment Verification

1. **Confirm the node joined your tailnet**:
   On your Headscale server:
   ```bash
   headscale nodes list
   ```
   You should see `headlamp` online with its assigned tailnet IP (`100.64.x.x` / `fd7a:...`) and tags (`tag:headlamp`).
2. **Test connectivity from an authorized tailnet client**:
   ```bash
   curl -fsS http://headlamp/healthz
   curl -fsS http://headlamp/whoami
   ```
   If TLS (`static` or `acme_dns01`) is enabled, use `https://<your-headlamp-domain>/healthz`.
3. **Open the Admin Console & Team Web Chat**:
   Visit `http://headlamp/` (or `https://<your-headlamp-domain>/`) in a browser on your tailnet.
4. **Configure coding clients**:
   Follow [Client Setup Recipes](./clients.md) for Claude Code, Codex CLI, Gemini CLI, Cursor, and Remote MCP clients.

---

## Backup, Restore & Day-2 Operations

- **What to back up**:
  1. `HEADLAMP_MASTER_KEY` (from `headlamp.env` or `state_dir/master.key`) — needed to decrypt stored API keys and secrets.
  2. `state_dir/tsnet/tailscaled.state` — preserves the node's tailnet identity and Tailscale IP across host migrations.
  3. `/etc/headlamp/headlamp.yaml` — declarative YAML configuration.
  4. Database — use online SQLite backup or `pg_dump`:
     ```bash
     # systemd + SQLite
     sudo sqlite3 /var/lib/headlamp/headlamp.db ".backup '/var/backups/headlamp-$(date +%F).db'"

     # Docker Compose + PostgreSQL
     docker exec headlamp-postgres pg_dump -U headlamp headlamp > "headlamp-$(date +%F).sql"
     ```
- **Clean up one-time auth key**: After Headlamp has successfully registered its `tsnet` state (`tailscaled.state`), you can remove `HEADLAMP_AUTH_KEY` from `headlamp.env` / `headlamp.yaml` so the pre-auth secret does not remain in environment config unnecessarily (though keeping a valid reusable key is helpful if you recreate state volumes intentionally).
