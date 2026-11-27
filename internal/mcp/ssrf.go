package mcp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

var awsIPv6IMDSAddr = netip.MustParseAddr("fd00:ec2::254")

func defaultMCPHTTPClient(blockLoopback bool) *http.Client {
	// Never set http.Client.Timeout: that would abort long-lived SSE notification streams.
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   mcpDialControl(blockLoopback),
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func mcpDialControl(blockLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		return validateDialAddr(address, blockLoopback)
	}
}

func validateDialAddr(address string, blockLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid dial address %q", ErrBlockedAddress, address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: invalid IP %q", ErrBlockedAddress, host)
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.WithZone("") == awsIPv6IMDSAddr,
		addr.IsUnspecified(),
		addr.IsMulticast(),
		blockLoopback && addr.IsLoopback():
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

// isMutatingMethod reports whether method can cause server-side state changes.
func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// checkSameOriginCSRF enforces same-origin validation whenever browser headers
// (Origin or Sec-Fetch-Site) are present on mutating requests, matching internal/api.
// Non-browser CLI/IDE MCP clients without Origin/Sec-Fetch-Site are unaffected.
func checkSameOriginCSRF(r *http.Request) error {
	remoteLoopback := isLoopbackRemoteAddr(r.RemoteAddr)
	hostLoopback := isLoopbackHost(r.Host)
	loopbackDevEligible := remoteLoopback && hostLoopback

	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid Origin header %q", origin)
		}
		if !strings.EqualFold(u.Host, r.Host) {
			if !(loopbackDevEligible && isLoopbackHost(u.Hostname())) {
				return fmt.Errorf("cross-origin request blocked (origin=%q, host=%q)", u.Host, r.Host)
			}
		}
	}

	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" {
		switch sfs {
		case "same-origin", "none":
		case "same-site":
			if !loopbackDevEligible {
				return fmt.Errorf("cross-site request blocked (Sec-Fetch-Site=%q)", sfs)
			}
		default:
			return fmt.Errorf("cross-site request blocked (Sec-Fetch-Site=%q)", sfs)
		}
	}
	return nil
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

func isLoopbackHost(hostport string) bool {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// applyUpstreamAuth strips caller credentials and injects decrypted upstream MCP auth headers.
func applyUpstreamAuth(upReq *http.Request, srv store.MCPServer) {
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Goog-Api-Key"} {
		upReq.Header.Del(h)
	}
	token := srv.AuthToken
	if token == "" {
		return
	}

	switch strings.ToLower(strings.TrimSpace(srv.AuthType)) {
	case config.MCPAuthBearer:
		upReq.Header.Set("Authorization", "Bearer "+token)
	case config.MCPAuthHeader:
		hdr := strings.TrimSpace(srv.AuthHeader)
		if hdr != "" {
			upReq.Header.Set(hdr, token)
		}
	case config.MCPAuthBasic:
		if strings.HasPrefix(strings.ToLower(token), "basic ") {
			upReq.Header.Set("Authorization", token)
		} else if strings.Contains(token, ":") {
			upReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(token)))
		} else {
			upReq.Header.Set("Authorization", "Basic "+token)
		}
	case config.MCPAuthNone, "":
		// Strip client auth headers only.
	}
}

// buildUpstreamBaseURL returns srv.URL strictly validated for http/https without
// allowing caller-supplied path overrides.
func buildUpstreamBaseURL(srv store.MCPServer, rawQuery string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("mcp: invalid upstream URL for server %q", srv.Name)
	}
	scheme := strings.ToLower(base.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("mcp: unsupported scheme %q for server %q", base.Scheme, srv.Name)
	}

	target := *base
	if rawQuery != "" {
		if target.RawQuery != "" {
			target.RawQuery = target.RawQuery + "&" + rawQuery
		} else {
			target.RawQuery = rawQuery
		}
	}
	return target.String(), nil
}

// buildUpstreamCallbackURL resolves a previously validated legacy SSE callback path
// (recorded from upstream's "event: endpoint") against srv.URL's origin.
func buildUpstreamCallbackURL(srv store.MCPServer, recordedCallbackPath string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("mcp: invalid upstream URL for server %q", srv.Name)
	}
	cb, err := url.Parse(recordedCallbackPath)
	if err != nil {
		return "", fmt.Errorf("mcp: invalid recorded SSE callback path: %w", err)
	}
	target := *base
	target.Path = path.Clean("/" + cb.Path)
	target.RawPath = ""
	target.RawQuery = cb.RawQuery
	return target.String(), nil
}

// resolveSameOriginEndpoint resolves a legacy SSE "event: endpoint" URL against
// srv.URL and ensures it stays on the exact same scheme and host (SSRF protection).
func resolveSameOriginEndpoint(srv store.MCPServer, rawEndpoint string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("mcp: invalid base URL for server %q", srv.Name)
	}
	ep, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil {
		return nil, fmt.Errorf("mcp: invalid SSE endpoint %q: %w", rawEndpoint, err)
	}
	resolved := base.ResolveReference(ep)
	if !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
		return nil, fmt.Errorf("%w: cross-origin SSE endpoint %q rejected", ErrBlockedAddress, resolved.Host)
	}
	return resolved, nil
}

func formatRecordedCallbackPath(resolved *url.URL) string {
	epPath := resolved.EscapedPath()
	if epPath == "" {
		epPath = "/"
	}
	if !strings.HasPrefix(epPath, "/") {
		epPath = "/" + epPath
	}
	if resolved.RawQuery != "" {
		return epPath + "?" + resolved.RawQuery
	}
	return epPath
}

func sanitizeURLError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cleanURL := urlErr.URL
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.User = nil
			cleanURL = parsed.String()
		}
		return fmt.Sprintf("%s %q: %v", urlErr.Op, cleanURL, urlErr.Err)
	}
	return err.Error()
}

// allowedResponseHeaders is the strict allowlist of upstream MCP response headers
// safe to copy to clients (stripping Set-Cookie, Location, CORS, Server, etc.).
// Mcp-Session-Id is handled explicitly via per-user session ID translation.
var allowedResponseHeaders = []string{
	"Content-Type",
	"Cache-Control",
	"MCP-Protocol-Version",
}

func copyResponseHeaders(dst, src http.Header) {
	for _, h := range allowedResponseHeaders {
		for _, v := range src.Values(h) {
			dst.Add(h, v)
		}
	}
}

// copyMCPRequestHeaders copies only safe protocol headers; Mcp-Session-Id and
// Last-Event-ID are handled explicitly after per-user session ownership checks.
func copyMCPRequestHeaders(dst, src http.Header) {
	for _, h := range []string{
		"Accept",
		"MCP-Protocol-Version",
		"User-Agent",
	} {
		for _, v := range src.Values(h) {
			dst.Add(h, v)
		}
	}
}
