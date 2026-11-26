package netts

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/zacharykka/headlamp/internal/auth"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// WhoIsClient is the minimal subset of *local.Client required to resolve Tailnet callers.
type WhoIsClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

var _ WhoIsClient = (*local.Client)(nil)

// TSNetAuthenticator authenticates incoming Tailnet HTTP requests via LocalClient.WhoIs.
type TSNetAuthenticator struct {
	client WhoIsClient
}

var _ auth.Authenticator = (*TSNetAuthenticator)(nil)

// NewTSNetAuthenticator returns an auth.Authenticator backed by WhoIsClient.
func NewTSNetAuthenticator(client WhoIsClient) *TSNetAuthenticator {
	return &TSNetAuthenticator{client: client}
}

// Authenticate resolves the remote Tailnet peer using r.RemoteAddr verbatim (preserving port
// so netstack's ProxyMapper fallback works). Non-Tailnet peers (local.ErrPeerNotFound) return
// (nil, nil) so ChainAuthenticator can continue to fallback authenticators on local listeners.
func (a *TSNetAuthenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	if a == nil || a.client == nil || r == nil || strings.TrimSpace(r.RemoteAddr) == "" {
		return nil, nil
	}

	who, err := a.client.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("netts: whois %q: %w", r.RemoteAddr, err)
	}

	return PrincipalFromWhoIs(who, r.RemoteAddr)
}

// PrincipalFromWhoIs converts a Tailscale/Headscale WhoIsResponse into a Headlamp Principal.
//
// Key Headscale v0.29 / Tailscale invariants enforced here:
//   - Tagged nodes are checked via who.Node.IsTagged() BEFORE inspecting UserProfile, because
//     Headscale v0.28+ reports a synthetic "tagged-devices" user for tagged nodes.
//   - Each CapMap entry ([]tailcfg.RawMessage) is marshaled as a JSON array into RawCaps so
//     multi-rule grants and Aperture's multi-object array format remain intact for internal/policy.
func PrincipalFromWhoIs(who *apitype.WhoIsResponse, remoteAddr string) (*auth.Principal, error) {
	if who == nil || who.Node == nil {
		return nil, errors.New("netts: whois response missing node")
	}

	nodeName := extractNodeName(who.Node)
	nodeIP := extractNodeIP(who.Node, remoteAddr)
	tags := cleanStrings(who.Node.Tags)

	p := &auth.Principal{
		NodeName:   nodeName,
		NodeIP:     nodeIP,
		Tags:       tags,
		AuthSource: auth.AuthSourceTSNet,
	}

	// Check IsTagged() BEFORE UserProfile: tagged nodes belong to service tags, never a human user.
	if who.Node.IsTagged() {
		subject := ""
		if len(tags) > 0 {
			subject = tags[0]
		}
		p.Subject = cmp.Or(subject, nodeName, string(who.Node.StableID))
		p.DisplayName = cmp.Or(nodeName, p.Subject)
	} else {
		var loginName, displayName string
		if who.UserProfile != nil {
			rawLogin := strings.TrimSpace(who.UserProfile.LoginName)
			if !isSyntheticTaggedUser(rawLogin) {
				loginName = rawLogin
				displayName = strings.TrimSpace(who.UserProfile.DisplayName)
			}
		}
		p.Subject = cmp.Or(loginName, nodeName, string(who.Node.StableID))
		p.DisplayName = cmp.Or(displayName, p.Subject, nodeName)
	}

	if p.Subject == "" {
		return nil, errors.New("netts: unable to determine subject from whois response")
	}

	if len(who.CapMap) > 0 {
		p.RawCaps = make(map[string][]byte, len(who.CapMap))
		for capName, rawList := range who.CapMap {
			encoded, err := encodeCapValues(rawList)
			if err != nil {
				return nil, fmt.Errorf("netts: encode capability %q: %w", capName, err)
			}
			p.RawCaps[string(capName)] = encoded
		}
	}

	return p, nil
}

func encodeCapValues(rawList []tailcfg.RawMessage) ([]byte, error) {
	if len(rawList) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(rawList)
}

func extractNodeName(n *tailcfg.Node) string {
	if name := strings.TrimSpace(n.ComputedName); name != "" {
		return name
	}
	if name := strings.TrimSpace(strings.TrimSuffix(n.Name, ".")); name != "" {
		if idx := strings.IndexByte(name, '.'); idx > 0 {
			return name[:idx]
		}
		return name
	}
	if n.Hostinfo.Valid() {
		if host := strings.TrimSpace(n.Hostinfo.Hostname()); host != "" {
			return host
		}
	}
	return ""
}

func extractNodeIP(n *tailcfg.Node, remoteAddr string) string {
	if len(n.Addresses) > 0 && n.Addresses[0].IsValid() {
		return n.Addresses[0].Addr().String()
	}
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func isSyntheticTaggedUser(loginName string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(loginName), "@"), "tagged-devices")
}

func cleanStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			if !slices.Contains(out, trimmed) {
				out = append(out, trimmed)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
