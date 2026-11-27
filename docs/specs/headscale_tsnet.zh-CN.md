# Headscale v0.29.7 与 Tailscale `tsnet` 集成规范

[English](./headscale_tsnet.md) | **简体中文**

Headlamp `internal/netts`、`internal/auth` 和 `internal/policy` 的实现参考。
下文所有 Go 类型与签名均直接针对 **`tailscale.com v1.106.1`**（由 `go.mod` 解析）以及 **Headscale v0.29.7** 核验。

---

## 1. Go 包与 `tsnet.Server` API

必需的导入：
```go
import (
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap" // 可选；tailcfg.PeerCapability 是 peercap.Cap 的类型别名
	"tailscale.com/tsnet"
)
```

### 1.1 `tsnet.Server` 核心导出字段（`tailscale.com/tsnet`）

| 字段 | 类型 | 行为与 Headlamp 用法 |
| :--- | :--- | :--- |
| `Hostname` | `string` | 向 Headscale 声明的机器名（例如 `"headlamp"`）。留空时默认使用二进制文件名。 |
| `ControlURL` | `string` | Headscale 地址（例如 `"https://hs.example.com"`）。留空时回退至 `TS_CONTROL_URL` 环境变量；若两者均为空，则连接至官方 Tailscale 控制平面。 |
| `AuthKey` | `string` | 首次注册节点使用的预认证密钥（pre-auth key）。留空时依次回退至 `TS_AUTHKEY`、`TS_AUTH_KEY`。**一旦 `Dir/tailscaled.state` 中已有状态文件，后续启动会忽略此字段。** |
| `Dir` | `string` | 持久化状态目录（存放 `tailscaled.state`）。**务必显式设置**（例如 `<state_dir>/tsnet`），确保重启后保持同一节点身份，而不会重复注册新节点。 |
| `Ephemeral` | `bool` | 持久化运行的 Headlamp 网关应保持 `false`；仅在临时测试运行时设为 `true`。 |
| `AdvertiseTags` | `[]string` | 可选，例如 `["tag:headlamp"]`，用于向控制服务器请求标签（服务端仍需配置 `tagOwners` 权限或使用带标签的预认证密钥）。 |
| `UserLogf` | `logger.Logf` | 面向运维人员的日志（认证 URL、启动状态）。为 `nil` 时默认使用 `log.Printf`。 |
| `Logf` | `logger.Logf` | 详尽的内部 backend/magicsock 日志。为 `nil` 时丢弃（除非启用调试日志，否则保持 `nil`）。 |
| `Port` | `uint16` | 保持 `0`（自动选择 UDP 端口）。 |

### 1.2 启动、监听与关闭生命周期

```go
srv := &tsnet.Server{
	Hostname:   cfg.Server.TSNet.Hostname,
	ControlURL: cfg.Server.TSNet.ControlURL,
	AuthKey:    cfg.Server.TSNet.AuthKey,
	Dir:        filepath.Join(cfg.Server.StateDir, "tsnet"),
	UserLogf:   userLogf,
	// 除非处于调试模式，否则 Logf 保持 nil
}
defer srv.Close()

// Up() 会调用 Start()，等待进入 ipn.Running 状态并分配 TailscaleIP，然后返回 *ipnstate.Status。
// 务必传入带启动超时的 context（例如 60s），以便在 ControlURL/AuthKey 配置有误时干净地失败。
status, err := srv.Up(startupCtx)
if err != nil {
	return err
}

lc, err := srv.LocalClient() // *local.Client
if err != nil {
	return err
}

// 使用 srv.Listen（对接 Headscale 时切勿使用 srv.ListenTLS —— 参见常见坑点 #5）。
ln, err := srv.Listen("tcp", ":80")
// 当 TLS 模式为 "static" 或 "acme_dns01" 时：
//   rawLn, err := srv.Listen("tcp", ":443")
//   ln := tls.NewListener(rawLn, tlsConfig)
```

---

## 2. `LocalClient.WhoIs` 与 `apitype.WhoIsResponse`

### 2.1 `tailscale.com/client/local` 方法

```go
func (lc *Client) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
func (lc *Client) WhoIsForIP(ctx context.Context, remoteAddr string, dst netip.Addr) (*apitype.WhoIsResponse, error)
func (lc *Client) WhoIsProto(ctx context.Context, proto, remoteAddr string) (*apitype.WhoIsResponse, error)
var ErrPeerNotFound = errors.New("peer not found")
```

* 调用 LocalAPI：`GET /localapi/v0/whois?addr=<remoteAddr>`。
* 支持的 `remoteAddr` 格式（已在 `ipn/localapi/localapi.go` 中核验）：
  * IPv4 `ip:port` —— 例如 `"100.64.0.12:51822"`（直接传入 `r.RemoteAddr`）
  * IPv6 `[ip]:port` —— 例如 `"[fd7a:115c:a1e0::12]:51822"`（直接传入 `r.RemoteAddr`）
  * 裸 IPv4 / IPv6 —— 例如 `"100.64.0.12"`（端口视为 `0`）
  * 节点公钥 —— `"nodekey:<hex>"`
* 若该地址不属于已知的 tailnet 对等节点，返回 `local.ErrPeerNotFound`（HTTP 404）。
* `LocalBackend.WhoIs` 会自动对 IPv4-mapped IPv6 地址（`::ffff:100.64.x.y`）执行解映射（unmap）。

### 2.2 精确结构体定义（`tailscale.com v1.106.1`）

```go
// package apitype ("tailscale.com/client/tailscale/apitype")
type WhoIsResponse struct {
	Node        *tailcfg.Node        // 当 err == nil 时始终非 nil
	UserProfile *tailcfg.UserProfile // 当 err == nil 时始终非 nil

	// CapMap 将能力（capability）名称映射到授予该对等节点的 JSON 值列表。
	CapMap tailcfg.PeerCapMap
}

// package tailcfg ("tailscale.com/tailcfg")
type PeerCapability = peercap.Cap              // peercap.Cap 的类型别名（底层类型为 string）
type PeerCapMap map[peercap.Cap][]RawMessage   // 等价于 map[PeerCapability][]RawMessage
type RawMessage string                         // 注意：是 string，而不是 []byte！实现了 json.Marshaler/Unmarshaler

func UnmarshalCapJSON[T any](cm PeerCapMap, cap peercap.Cap) ([]T, error)
func (c PeerCapMap) HasCapability(cap peercap.Cap) bool

type UserProfile struct {
	ID            UserID
	LoginName     string   // 例如 "alice@example.com"（在 Headscale 上可能为 "alice@" 或 "tagged-devices"）
	DisplayName   string   // 例如 "Alice Smith"
	ProfilePicURL string
	Groups        []string // 仅当控制服务器报告用户组时填充
}

type Node struct {
	ID           NodeID
	StableID     StableNodeID
	Name         string         // 带尾部点号的 MagicDNS FQDN，例如 "alice-mac.tail.internal."
	ComputedName string         // 不含域名和点号的短主机名（若未初始化可能为空）
	User         UserID         // 创建者用户 ID（如果节点带有 tag，则它不是 ACL 身份！）
	Sharer       UserID
	Addresses    []netip.Prefix // 例如 [100.64.0.12/32, fd7a:115c:a1e0::12/128]
	Tags         []string       // 例如 ["tag:ci-runner"]
	Hostinfo     HostinfoView
	// ...
}

func (n *Node) IsTagged() bool // 返回 len(n.Tags) > 0
```

### 2.3 将 `WhoIsResponse` 映射为 Headlamp `auth.Principal`

```go
const (
	CapHeadlampGateway tailcfg.PeerCapability = "headlamp.dev/cap/gateway"
	CapApertureCompat  tailcfg.PeerCapability = "tailscale.com/cap/aperture"
)

func principalFromWhoIs(who *apitype.WhoIsResponse) (*auth.Principal, error) {
	p := &auth.Principal{
		Tags:       slices.Clone(who.Node.Tags),
		AuthSource: "tsnet",
	}

	// 1. 节点名称与 IP
	if who.Node.ComputedName != "" {
		p.NodeName = who.Node.ComputedName
	} else {
		p.NodeName = strings.TrimSuffix(who.Node.Name, ".")
		if i := strings.IndexByte(p.NodeName, '.'); i > 0 {
			p.NodeName = p.NodeName[:i]
		}
	}
	if len(who.Node.Addresses) > 0 {
		p.NodeIP = who.Node.Addresses[0].Addr().String()
	}

	// 2. Subject 与 DisplayName —— 务必在读取 UserProfile 之前先检查 IsTagged()！
	if who.Node.IsTagged() {
		p.Subject = who.Node.Tags[0] // 例如 "tag:ci-runner"
		p.DisplayName = p.NodeName
	} else {
		p.Subject = normalizeLoginName(who.UserProfile.LoginName)
		p.DisplayName = cmp.Or(who.UserProfile.DisplayName, p.Subject)
	}

	// 3. 将每个能力键对应的全部条目保留为 JSON 数组存入 RawCaps[string(cap)]。
	// 关键：CapMap 的值是 []tailcfg.RawMessage（同一能力可能对应多条规则/多个对象！）。
	if len(who.CapMap) > 0 {
		p.RawCaps = make(map[string][]byte, len(who.CapMap))
		for capName, rawList := range who.CapMap {
			if encoded, err := json.Marshal(rawList); err == nil {
				p.RawCaps[string(capName)] = encoded // JSON 数组：[{...}, {...}]
			}
		}
	}
	return p, nil
}
```

---

## 3. Headscale v0.29.7 Grants 配置（HuJSON）

Headscale v0.29+ 在 HuJSON 策略文件（`policy.mode: file` 或通过 `headscale policy set` 管理的数据库策略）中实现了 Tailscale 的现代 `grants` 语法（包括 `ip`、`app`、`via` 与 `tests` 块）。

### 3.1 完整的 `policy.hujson` 示例

```jsonc
{
  // 用户组（Headscale 本地用户或 OIDC 邮箱）
  "groups": {
    "group:admins": ["alice@example.com"],
    "group:engineering": ["alice@example.com", "bob@example.com"],
    "group:interns": ["carol@example.com"]
  },

  // 在创建带标签的预认证密钥或宣告标签之前，必须先声明 tagOwners
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },

  "grants": [
    // 1. 管理员：网络访问 + Headlamp 管理员角色 + 全部模型与 MCP 工具
    {
      "src": ["group:admins"],
      "dst": ["tag:headlamp"],
      // 关键：仅配置 "app" 不会放行 TCP 端口！必须在此处或另一条规则中包含 "ip"。
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

    // 2. 研发团队：Headlamp 原生 capability
    {
      "src": ["group:engineering"],
      "dst": ["tag:headlamp"],
      "ip": ["tcp:80", "tcp:443"],
      "app": {
        "headlamp.dev/cap/gateway": [
          {
            "role": "user",
            "models": ["anthropic/*", "openai/gpt-5*", "gemini/*", "ollama/*"],
            "mcp_tools": ["docs/*", "github/read_*"]
          }
        ]
      }
    },

    // 3. 在 headlamp.dev/cap/gateway 下使用多对象数组与字符串形式 "models" 语法
    // 关键：Headscale v0.29.7 会拒绝 "tailscale.com/cap/*" 域名下的 capability 名称，
    // 并报错 "capability name must not be in the tailscale.com domain"。
    // 在 Headscale 上请使用 "headlamp.dev/cap/gateway"；当连接到官方 Tailscale SaaS 时，
    // Headlamp 同时也接受 "tailscale.com/cap/aperture"。
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

    // 4. 带标签的无头工作负载（CI runner）
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

### 3.2 Capability JSON 解析规则（`internal/policy`）

由于 `headlamp.dev/cap/gateway` 和 `tailscale.com/cap/aperture` 都可能出现在 `Principal.RawCaps` 中，因此需要将每个 `RawCaps[key]` 反序列化为对象数组，并对所有条目进行累加合并：

```go
// StringOrSlice 既可反序列化 "anthropic/**"（Aperture 风格），也可反序列化 ["anthropic/*", "openai/*"]（Headlamp 风格）。
type GrantCapability struct {
	Role       string        `json:"role"`
	Models     StringOrSlice `json:"models"`
	DenyModels StringOrSlice `json:"deny_models"` // 可选的 Headlamp 扩展字段
	MCPTools   StringOrSlice `json:"mcp_tools"`   // Headlamp 原生字段
	Connectors StringOrSlice `json:"connectors"`  // Aperture 兼容的 MCP 工具别名
}
```

* 若 `Principal.RawCaps` 中存在 `"headlamp.dev/cap/gateway"` 和 `"tailscale.com/cap/aperture"`，两者均需参与求值。
* 将 `"admin"` 角色视为 `"user"` 角色的超集。
* 鉴权严格采用**纯 grants 模式**：匹配到的 grant 对象按累加方式合并，且显式拒绝（`deny_models` / `deny_mcp_tools`）始终优先。非 Tailnet 调用方（`dev_mode` 和静态 `api_tokens`）会在 `Principal.RawCaps` 中合成等效的 `"headlamp.dev/cap/gateway"` 条目，使策略求值器能够统一处理所有调用方。

### 3.3 最小化 Headscale v0.29.7 服务端配置

```yaml
# headscale config.yaml 节选
policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: tailnet.internal
  # 注意：extra_records 仅支持 A 和 AAAA（Tailscale 客户端会忽略 CNAME）
```

为 Headlamp 引导创建带标签的预认证密钥：
```bash
# 在 Headscale v0.29+ 中，带标签的预认证密钥不会将节点绑定到人类用户：
headscale preauthkeys create --reusable --expiration 24h --tags tag:headlamp
# 编辑策略后执行校验并重载：
headscale policy check -f /etc/headscale/policy.hujson
kill -HUP $(pidof headscale) # 在数据库模式下请使用 `headscale policy set -f ...`
```

---

## 4. Headscale v0.29.7 与 `tsnet` 常见坑点清单

1. **仅含 `app` 的 Grant 会阻断流量**：在 Tailscale 和 Headscale v0.29+ 中，单独的 `app` 能力授权**不会**放行三层/四层数据包。每条指向 `tag:headlamp` 的 grant 都必须在同一条规则或配套的 `ip` grant/ACL 中包含 `"ip": ["tcp:80", "tcp:443"]`（或 `"ip": ["*"]`）。
2. **带标签节点的 `UserProfile` 返回 `tagged-devices`**：从 Headscale v0.28/v0.29 起，带标签节点已与人类用户分离，并会返回合成的 `tagged-devices` 用户档案。务必在读取 `who.UserProfile.LoginName` **之前**先检查 `who.Node.IsTagged()`（`len(who.Node.Tags) > 0`），切勿将 `"tagged-devices"` 当作人类主体（subject）。
3. **调用 `WhoIs` 时保留 `r.RemoteAddr` 中的端口**：始终将 `r.RemoteAddr` 原样传入 `lc.WhoIs(ctx, r.RemoteAddr)`（`ip:port` 或 `[ipv6]:port`）。剥离端口会禁用 netstack 的 `ProxyMapper` 回退逻辑（`WhoIsIPPort`）。切勿将不可信调用方发来的 `X-Forwarded-For` 传入 `WhoIs`。
4. **`CapMap` 的值是 `tailcfg.RawMessage`（字符串）切片**：`who.CapMap` 的类型是 `map[peercap.Cap][]tailcfg.RawMessage`，其中 `RawMessage` 定义为 `type RawMessage string`（并非 `[]byte`）。多条匹配的 grant 规则，以及 Aperture 的多对象数组格式 `[{"role":"user"}, {"models":"anthropic/**"}]`，都会产生多个切片元素。务必序列化并解析整个切片，切勿只读取索引 `[0]`。
5. **`tsnet.Server.ListenTLS` 在 Headscale 上会失败**：`ListenTLS` 会检查 `len(status.CertDomains) > 0`，而该字段仅由官方 Tailscale SaaS 的 MagicDNS HTTPS 证书签发流程填充。对接 Headscale 时，`ListenTLS` 必然报错。当 `tls.mode` 为 `static` 或 `acme_dns01` 时，务必使用 `srv.Listen("tcp", addr)` 并以 `tls.NewListener` 包装。
6. **MagicDNS 尾部点号与 `extra_records` 限制**：
   * `who.Node.Name` 始终带有尾部点号（例如 `"alice-mac.tailnet.internal."`），存储或展示前需去除。
   * Headscale 的 `dns.extra_records` 仅支持 `A` 和 `AAAA` 记录（Tailscale 客户端会静默丢弃 `CNAME`），且 v0.29 会将混合大小写的名称转为小写。
7. **非 OIDC Headscale `LoginName` 与策略语法差异**：对于没有 OIDC 邮箱的 Headscale v0.29.7 本地用户，策略中的 `src`/`groups` 条目带有尾部 `@`（例如 `"alice@"`），而 `WhoIs.UserProfile.LoginName` 返回的则是去掉尾部 `@` 的 `"alice"`（Headlamp 也会在存在尾部 `@` 时将其裁剪）。可通过 `GET /whoami` 确认最终解析的身份与 grants。
8. **Headscale v0.29.7 禁止 `tailscale.com/cap/*` 能力名**：在 Headscale v0.29.7 中应用包含 `"tailscale.com/cap/aperture"` 的策略会失败，并报错 `capability name must not be in the tailscale.com domain`。在 Headscale 上请一律使用 `"headlamp.dev/cap/gateway"`（多对象数组与字符串/切片形式的 `models` 在其下同样有效）；仅保留 `"tailscale.com/cap/aperture"` 解析以兼容官方 Tailscale SaaS。
9. **状态持久化与 `AuthKey` 复用**：务必设置 `tsnet.Server.Dir`。一旦 `tailscaled.state` 写入磁盘，`tsnet` 在重启时会忽略 `AuthKey`。如果你清空了 `Dir`，请同步在 Headscale 中删除旧节点，否则 MagicDNS 主机名将被追加 `-1` 后缀（`headlamp-1`）。
10. **Headscale v0.29.7 策略校验与限制**：策略中的 `tests` 块会在重载/设置时自动校验；格式错误的规则会导致整次重载被拒绝。待处理的交互式注册载荷上限为 64 KiB，且监控指标已严格隔离至 `metrics_listen_addr`（不再通过 Noise 暴露）。
