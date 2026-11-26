# Headscale v0.29.7 & Tailscale `tsnet` Integration Spec

Implementation reference for Headlamp `internal/netts`, `internal/auth`, and `internal/policy`.
All Go types and signatures below are verified directly against **`tailscale.com v1.106.1`** (resolved in `go.mod`) and **Headscale v0.29.7**.

---

## 1. Go Packages & `tsnet.Server` API

Required imports:
```go
import (
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap" // optional; tailcfg.PeerCapability aliases peercap.Cap
	"tailscale.com/tsnet"
)
```

### 1.1 `tsnet.Server` Key Exported Fields (`tailscale.com/tsnet`)

| Field | Type | Behavior & Headlamp Usage |
| :--- | :--- | :--- |
| `Hostname` | `string` | Machine name presented to Headscale (e.g. `"headlamp"`). Defaults to binary name if empty. |
| `ControlURL` | `string` | Headscale URL (e.g. `"https://hs.example.com"`). Falls back to `TS_CONTROL_URL` env var; if both empty, connects to official Tailscale control plane. |
| `AuthKey` | `string` | Pre-auth key for initial node registration. Falls back to `TS_AUTHKEY`, then `TS_AUTH_KEY`. **Ignored on subsequent runs once state exists in `Dir/tailscaled.state`.** |
| `Dir` | `string` | Persistent state directory (`tailscaled.state`). **Always set explicitly** (e.g. `<state_dir>/tsnet`) so restarts keep the same node identity and do not register duplicate nodes. |
| `Ephemeral` | `bool` | Leave `false` for persistent Headlamp gateway; set `true` only for ephemeral test runs. |
| `AdvertiseTags` | `[]string` | Optional `["tag:headlamp"]` to request tags from control server (server still requires `tagOwners` permission or a tagged pre-auth key). |
| `UserLogf` | `logger.Logf` | Logs intended for operator (auth URL, startup status). Defaults to `log.Printf` if nil. |
| `Logf` | `logger.Logf` | Verbose internal backend/magicsock logs. Discarded if nil (keep nil unless debug logging is enabled). |
| `Port` | `uint16` | Leave `0` (auto-select UDP port). |

### 1.2 Startup, Listening & Shutdown Lifecycle

```go
srv := &tsnet.Server{
	Hostname:   cfg.Server.TSNet.Hostname,
	ControlURL: cfg.Server.TSNet.ControlURL,
	AuthKey:    cfg.Server.TSNet.AuthKey,
	Dir:        filepath.Join(cfg.Server.StateDir, "tsnet"),
	UserLogf:   userLogf,
	// Logf left nil unless debug mode
}
defer srv.Close()

// Up() calls Start(), waits for ipn.Running + TailscaleIP assignment, and returns *ipnstate.Status.
// Always pass a context with a startup timeout (e.g. 60s) so misconfigured ControlURL/AuthKey fails cleanly.
status, err := srv.Up(startupCtx)
if err != nil {
	return err
}

lc, err := srv.LocalClient() // *local.Client
if err != nil {
	return err
}

// Use srv.Listen (NEVER srv.ListenTLS against Headscale — see Gotcha #5).
ln, err := srv.Listen("tcp", ":80")
// For TLS mode "static" or "acme_dns01":
//   rawLn, err := srv.Listen("tcp", ":443")
//   ln := tls.NewListener(rawLn, tlsConfig)
```

---

## 2. `LocalClient.WhoIs` & `apitype.WhoIsResponse`

### 2.1 `tailscale.com/client/local` Methods

```go
func (lc *Client) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
func (lc *Client) WhoIsForIP(ctx context.Context, remoteAddr string, dst netip.Addr) (*apitype.WhoIsResponse, error)
func (lc *Client) WhoIsProto(ctx context.Context, proto, remoteAddr string) (*apitype.WhoIsResponse, error)
var ErrPeerNotFound = errors.New("peer not found")
```

* Calls LocalAPI `GET /localapi/v0/whois?addr=<remoteAddr>`.
* Accepted `remoteAddr` formats (verified in `ipn/localapi/localapi.go`):
  * IPv4 `ip:port` — e.g. `"100.64.0.12:51822"` (direct `r.RemoteAddr`)
  * IPv6 `[ip]:port` — e.g. `"[fd7a:115c:a1e0::12]:51822"` (direct `r.RemoteAddr`)
  * Bare IPv4 / IPv6 — e.g. `"100.64.0.12"` (port treated as `0`)
  * Node public key — `"nodekey:<hex>"`
* Returns `local.ErrPeerNotFound` (HTTP 404) if the address is not a known tailnet peer.
* `LocalBackend.WhoIs` automatically unmaps IPv4-mapped IPv6 (`::ffff:100.64.x.y`).

### 2.2 Exact Struct Definitions (`tailscale.com v1.106.1`)

```go
// package apitype ("tailscale.com/client/tailscale/apitype")
type WhoIsResponse struct {
	Node        *tailcfg.Node        // Always non-nil when err == nil
	UserProfile *tailcfg.UserProfile // Always non-nil when err == nil

	// CapMap maps capability names to the list of JSON values granted to this peer.
	CapMap tailcfg.PeerCapMap
}

// package tailcfg ("tailscale.com/tailcfg")
type PeerCapability = peercap.Cap              // type alias for peercap.Cap (underlying string)
type PeerCapMap map[peercap.Cap][]RawMessage   // equivalently map[PeerCapability][]RawMessage
type RawMessage string                         // NOTE: string, NOT []byte! Implements json.Marshaler/Unmarshaler

func UnmarshalCapJSON[T any](cm PeerCapMap, cap peercap.Cap) ([]T, error)
func (c PeerCapMap) HasCapability(cap peercap.Cap) bool

type UserProfile struct {
	ID            UserID
	LoginName     string   // e.g. "alice@example.com" (or "alice@" / "tagged-devices" on Headscale)
	DisplayName   string   // e.g. "Alice Smith"
	ProfilePicURL string
	Groups        []string // populated only if control server reports groups
}

type Node struct {
	ID           NodeID
	StableID     StableNodeID
	Name         string         // MagicDNS FQDN WITH trailing dot, e.g. "alice-mac.tail.internal."
	ComputedName string         // Short hostname without domain/dot (may be empty if not initialized)
	User         UserID         // Creator user ID (NOT ACL identity if node is tagged!)
	Sharer       UserID
	Addresses    []netip.Prefix // e.g. [100.64.0.12/32, fd7a:115c:a1e0::12/128]
	Tags         []string       // e.g. ["tag:ci-runner"]
	Hostinfo     HostinfoView
	// ...
}

func (n *Node) IsTagged() bool // returns len(n.Tags) > 0
```

### 2.3 Mapping `WhoIsResponse` -> Headlamp `auth.Principal`

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

	// 1. Node name & IP
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

	// 2. Subject & DisplayName — ALWAYS check IsTagged() BEFORE UserProfile!
	if who.Node.IsTagged() {
		p.Subject = who.Node.Tags[0] // e.g. "tag:ci-runner"
		p.DisplayName = p.NodeName
	} else {
		p.Subject = normalizeLoginName(who.UserProfile.LoginName)
		p.DisplayName = cmp.Or(who.UserProfile.DisplayName, p.Subject)
	}

	// 3. Preserve ALL capability entries per key as a JSON array in RawCaps[string(cap)].
	// CRITICAL: CapMap values are []tailcfg.RawMessage (multiple rules/objects per cap!).
	if len(who.CapMap) > 0 {
		p.RawCaps = make(map[string][]byte, len(who.CapMap))
		for capName, rawList := range who.CapMap {
			if encoded, err := json.Marshal(rawList); err == nil {
				p.RawCaps[string(capName)] = encoded // JSON array: [{...}, {...}]
			}
		}
	}
	return p, nil
}
```

---

## 3. Headscale v0.29.7 Grants Configuration (HuJSON)

Headscale v0.29+ implements Tailscale's modern `grants` syntax (including `ip`, `app`, `via`, and `tests` blocks) in HuJSON policy files (`policy.mode: file` or database policy via `headscale policy set`).

### 3.1 Complete `policy.hujson` Example

```jsonc
{
  // User groups (Headscale local users or OIDC emails)
  "groups": {
    "group:admins": ["alice@example.com"],
    "group:engineering": ["alice@example.com", "bob@example.com"],
    "group:interns": ["carol@example.com"]
  },

  // Tag owners MUST be declared before creating tagged pre-auth keys or advertising tags
  "tagOwners": {
    "tag:headlamp": ["group:admins"],
    "tag:ci-runner": ["group:admins"]
  },

  "grants": [
    // 1. Admins: network access + Headlamp admin role + all models & MCP tools
    {
      "src": ["group:admins"],
      "dst": ["tag:headlamp"],
      // CRITICAL: "app" alone does NOT open TCP ports! Must include "ip" here or in another rule.
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

    // 2. Engineering: Headlamp native capability
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

    // 3. Multi-object array & string "models" syntax under headlamp.dev/cap/gateway
    // CRITICAL: Headscale v0.29.7 rejects capability names under "tailscale.com/cap/*"
    // with "capability name must not be in the tailscale.com domain".
    // Use "headlamp.dev/cap/gateway" on Headscale; Headlamp also accepts
    // "tailscale.com/cap/aperture" when connected to official Tailscale SaaS.
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

    // 4. Tagged headless workload (CI runner)
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

### 3.2 Capability JSON Parsing Rules (`internal/policy`)

Because both `headlamp.dev/cap/gateway` and `tailscale.com/cap/aperture` can appear in `Principal.RawCaps`, unmarshal each `RawCaps[key]` as a JSON array of objects and merge additively across all entries:

```go
// StringOrSlice unmarshals either "anthropic/**" (Aperture) or ["anthropic/*", "openai/*"] (Headlamp).
type GrantCapability struct {
	Role       string        `json:"role"`
	Models     StringOrSlice `json:"models"`
	DenyModels StringOrSlice `json:"deny_models"` // optional Headlamp extension
	MCPTools   StringOrSlice `json:"mcp_tools"`   // Headlamp native field
	Connectors StringOrSlice `json:"connectors"`  // Aperture compat alias for MCP tools
}
```

* Evaluate both `"headlamp.dev/cap/gateway"` and `"tailscale.com/cap/aperture"` if present in `Principal.RawCaps`.
* Treat `"admin"` role as a superset of `"user"`.
* Authorization is purely **grants-only**: matched grant objects are merged additively, and explicit denies (`deny_models` / `deny_mcp_tools`) always win. Non-Tailnet callers (`dev_mode` and static `api_tokens`) synthesize equivalent `"headlamp.dev/cap/gateway"` entries in `Principal.RawCaps` so the evaluator handles all callers uniformly.

### 3.3 Minimal Headscale v0.29.7 Server Setup

```yaml
# headscale config.yaml excerpts
policy:
  mode: file
  path: /etc/headscale/policy.hujson

dns:
  magic_dns: true
  base_domain: tailnet.internal
  # Note: extra_records only supports A and AAAA (Tailscale clients ignore CNAME)
```

Bootstrap a tagged pre-auth key for Headlamp:
```bash
# In Headscale v0.29+, tagged pre-auth keys do not bind the node to a human user:
headscale preauthkeys create --reusable --expiration 24h --tags tag:headlamp
# Validate and reload policy after edits:
headscale policy check -f /etc/headscale/policy.hujson
kill -HUP $(pidof headscale) # or `headscale policy set -f ...` in database mode
```

---

## 4. Headscale v0.29.7 & `tsnet` Gotchas Checklist

1. **`app`-Only Grants Block Traffic**: In Tailscale and Headscale v0.29+, an `app` capability grant does **not** permit Layer-3/4 packets by itself. Every grant targeting `tag:headlamp` must include `"ip": ["tcp:80", "tcp:443"]` (or `"ip": ["*"]`) either in the same grant or in a companion `ip` grant/ACL.
2. **Tagged Nodes Return `tagged-devices` in `UserProfile`**: Since Headscale v0.28/v0.29, tagged nodes are separated from human users and report a synthetic `tagged-devices` user profile. Always check `who.Node.IsTagged()` (`len(who.Node.Tags) > 0`) **before** reading `who.UserProfile.LoginName`. Never treat `"tagged-devices"` as a human subject.
3. **Preserve `r.RemoteAddr` Port for `WhoIs`**: Always pass `r.RemoteAddr` verbatim (`ip:port` or `[ipv6]:port`) to `lc.WhoIs(ctx, r.RemoteAddr)`. Stripping the port disables netstack's `ProxyMapper` fallback (`WhoIsIPPort`). Never pass `X-Forwarded-For` from untrusted callers into `WhoIs`.
4. **`CapMap` Values Are Slices of `tailcfg.RawMessage` (Strings)**: `who.CapMap` is `map[peercap.Cap][]tailcfg.RawMessage`, where `RawMessage` is `type RawMessage string` (not `[]byte`). Multiple matching grant rules — and Aperture's multi-object array format `[{"role":"user"}, {"models":"anthropic/**"}]` — produce multiple slice elements. Always serialize and parse the entire slice, never only index `[0]`.
5. **`tsnet.Server.ListenTLS` Fails on Headscale**: `ListenTLS` checks `len(status.CertDomains) > 0`, which is populated only by official Tailscale SaaS's MagicDNS HTTPS cert provisioning. Against Headscale, `ListenTLS` always returns an error. Always use `srv.Listen("tcp", addr)` and wrap with `tls.NewListener` when `tls.mode` is `static` or `acme_dns01`.
6. **MagicDNS Trailing Dot & `extra_records` Limits**:
   * `who.Node.Name` always has a trailing dot (e.g. `"alice-mac.tailnet.internal."`). Strip it before storing/displaying.
   * Headscale `dns.extra_records` only supports `A` and `AAAA` records (Tailscale clients silently drop `CNAME`), and mixed-case names are lowercased in v0.29.
7. **Non-OIDC Headscale `LoginName` vs Policy Syntax**: For local Headscale v0.29.7 users without an OIDC email, Headscale policy `src`/`groups` entries use a trailing `@` (e.g. `"alice@"`), whereas `WhoIs.UserProfile.LoginName` reports `"alice"` without the trailing `@` (and Headlamp trims any trailing `@` if present). Confirm resolved identity and grants via `GET /whoami`.
8. **Headscale v0.29.7 Forbids `tailscale.com/cap/*` Capabilities**: Applying a policy containing `"tailscale.com/cap/aperture"` fails in Headscale v0.29.7 with `capability name must not be in the tailscale.com domain`. Always use `"headlamp.dev/cap/gateway"` on Headscale (multi-object arrays and string-or-slice `models` work identically under it); keep `"tailscale.com/cap/aperture"` parsing strictly for official Tailscale SaaS compatibility.
9. **State Persistence & `AuthKey` Reuse**: Always set `tsnet.Server.Dir`. Once `tailscaled.state` is written, `tsnet` ignores `AuthKey` on restart. If you wipe `Dir`, remove the stale node from Headscale or expect a `-1` suffix on the MagicDNS hostname (`headlamp-1`).
10. **Headscale v0.29.7 Policy Validation & Limits**: Policy `tests` blocks are validated automatically on reload/set; malformed rules reject the entire reload. Pending interactive registration payloads are capped at 64 KiB, and metrics are strictly isolated to `metrics_listen_addr` (no longer exposed over Noise).
