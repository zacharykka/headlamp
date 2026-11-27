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

// buildUpstreamURL constructs the target URL for an upstream MCP server request,
// locking scheme and host strictly to srv.URL.
//
// When subpath is empty, srv.URL's exact path is preserved. When subpath is non-empty
// (e.g. a rewritten legacy SSE callback path like "/messages"), the cleaned subpath
// replaces the path on srv.URL's origin while merging query parameters.
func buildUpstreamURL(srv store.MCPServer, subpath, rawQuery string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("mcp: invalid upstream URL for server %q", srv.Name)
	}
	scheme := strings.ToLower(base.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("mcp: unsupported scheme %q for server %q", base.Scheme, srv.Name)
	}

	target := *base
	if subpath != "" {
		cleaned := path.Clean("/" + subpath)
		target.Path = cleaned
		target.RawPath = ""
		target.RawQuery = rawQuery
	} else if rawQuery != "" {
		if target.RawQuery != "" {
			target.RawQuery = target.RawQuery + "&" + rawQuery
		} else {
			target.RawQuery = rawQuery
		}
	}
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

// rewriteSSEEndpoint rewrites an upstream legacy SSE "event: endpoint" data payload
// so follow-up client POSTs route back through Headlamp's /mcp/{server_name}/... proxy.
func rewriteSSEEndpoint(srv store.MCPServer, rawEndpoint string) (string, error) {
	resolved, err := resolveSameOriginEndpoint(srv, rawEndpoint)
	if err != nil {
		return "", err
	}
	epPath := resolved.EscapedPath()
	if epPath == "" {
		epPath = "/"
	}
	if !strings.HasPrefix(epPath, "/") {
		epPath = "/" + epPath
	}
	rewritten := "/mcp/" + url.PathEscape(srv.Name) + epPath
	if resolved.RawQuery != "" {
		rewritten += "?" + resolved.RawQuery
	}
	return rewritten, nil
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

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-encoding":    {},
	"content-length":      {},
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if _, skip := hopByHopHeaders[strings.ToLower(k)]; skip {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func copyMCPRequestHeaders(dst, src http.Header) {
	for _, h := range []string{
		"Content-Type",
		"Accept",
		"Mcp-Session-Id",
		"MCP-Protocol-Version",
		"Last-Event-ID",
		"User-Agent",
	} {
		for _, v := range src.Values(h) {
			dst.Add(h, v)
		}
	}
}
