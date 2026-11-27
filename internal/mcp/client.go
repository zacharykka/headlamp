package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
)

const maxToolsListPages = 10

// DiscoverTools connects to srv using its configured transport (Streamable HTTP
// or Legacy SSE), executes initialize -> notifications/initialized -> tools/list,
// and returns the discovered ToolDefinitions alongside end-to-end latency.
func (g *Gateway) DiscoverTools(ctx context.Context, srv store.MCPServer) ([]ToolDefinition, int64, error) {
	callCtx, cancel := g.withClientTimeout(ctx)
	defer cancel()

	start := time.Now()
	sess, err := g.openClientSession(callCtx, srv)
	if err != nil {
		return nil, time.Since(start).Milliseconds(), err
	}
	defer sess.close()

	tools := make([]ToolDefinition, 0)
	cursor := ""
	for page := 0; page < maxToolsListPages; page++ {
		var params any
		if cursor != "" {
			params = map[string]string{"cursor": cursor}
		} else {
			params = map[string]any{}
		}
		resp, err := sess.call(callCtx, "tools/list", params)
		if err != nil {
			return nil, time.Since(start).Milliseconds(), err
		}
		if resp.Error != nil {
			return nil, time.Since(start).Milliseconds(), fmt.Errorf("mcp: tools/list error (%d): %s", resp.Error.Code, resp.Error.Message)
		}
		var pageResult struct {
			Tools      []ToolDefinition `json:"tools"`
			NextCursor string           `json:"nextCursor"`
		}
		if len(bytes.TrimSpace(resp.Result)) > 0 {
			if err := json.Unmarshal(resp.Result, &pageResult); err != nil {
				return nil, time.Since(start).Milliseconds(), fmt.Errorf("mcp: decode tools/list result: %w", err)
			}
		}
		tools = append(tools, pageResult.Tools...)
		if strings.TrimSpace(pageResult.NextCursor) == "" {
			break
		}
		cursor = pageResult.NextCursor
	}

	return tools, time.Since(start).Milliseconds(), nil
}

// ListAuthorizedToolsForPrincipal lists enabled MCP servers (filtered to serverNames
// when non-empty), discovers their tools, and filters out any tool denied by Authorizer.
// Per-server discovery errors are isolated in AuthorizedServerTools.Error without aborting
// other servers.
func (g *Gateway) ListAuthorizedToolsForPrincipal(ctx context.Context, p *auth.Principal, serverNames []string) ([]AuthorizedServerTools, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}

	allServers, err := g.store.ListMCPServers(ctx)
	if err != nil {
		return nil, err
	}

	var allowSet map[string]struct{}
	if len(serverNames) > 0 {
		allowSet = make(map[string]struct{}, len(serverNames))
		for _, name := range serverNames {
			allowSet[strings.TrimSpace(name)] = struct{}{}
		}
	}

	isAdmin := g.isAdminPrincipal(ctx, p)

	targets := make([]store.MCPServer, 0, len(allServers))
	for _, srv := range allServers {
		if !srv.Enabled {
			continue
		}
		if allowSet != nil {
			if _, ok := allowSet[srv.Name]; !ok {
				continue
			}
		}
		// P2-2: Never dial or probe MCP servers the caller has no grant for.
		if g.authorizer != nil {
			allowed, _, authErr := g.authorizer.AuthorizeMCPServer(ctx, p, srv.Name)
			if authErr != nil || !allowed {
				continue
			}
		}
		targets = append(targets, srv)
	}

	results := make([]AuthorizedServerTools, len(targets))
	var wg sync.WaitGroup
	for i, srv := range targets {
		wg.Add(1)
		go func(idx int, server store.MCPServer) {
			defer wg.Done()
			entry := AuthorizedServerTools{
				Name:      server.Name,
				Transport: server.Transport,
				Enabled:   server.Enabled,
				Tools:     []ToolDefinition{},
			}

			discovered, _, discoverErr := g.DiscoverTools(ctx, server)
			if discoverErr != nil {
				// P2-2: Redact internal upstream URL/IP details for non-admin callers.
				if isAdmin {
					entry.Error = sanitizeURLError(discoverErr)
				} else {
					entry.Error = "upstream MCP server unavailable"
				}
				results[idx] = entry
				return
			}

			for _, tool := range discovered {
				if g.authorizer != nil {
					ok, _, authErr := g.authorizer.AuthorizeMCPTool(ctx, p, server.Name+"/"+tool.Name)
					if authErr != nil || !ok {
						continue
					}
				}
				entry.Tools = append(entry.Tools, tool)
			}
			results[idx] = entry
		}(i, srv)
	}
	wg.Wait()

	return results, nil
}

func (g *Gateway) isAdminPrincipal(ctx context.Context, p *auth.Principal) bool {
	if p == nil {
		return false
	}
	if checker, ok := g.authorizer.(interface {
		IsAdmin(context.Context, *auth.Principal) (bool, error)
	}); ok {
		if admin, err := checker.IsAdmin(ctx, p); err == nil {
			return admin
		}
		return false
	}
	return p.IsAdmin()
}

// CallAuthorizedTool enforces policy + guardrails, invokes tools/call on the target
// MCP server, persists an MCPAuditLog entry, and returns the flattened tool output.
func (g *Gateway) CallAuthorizedTool(
	ctx context.Context,
	p *auth.Principal,
	serverName, toolName string,
	args json.RawMessage,
) (*ToolCallResult, error) {
	if p == nil {
		return nil, auth.ErrUnauthenticated
	}

	start := time.Now()
	requestID := uuid.NewString()

	srv, err := g.store.GetMCPServer(ctx, serverName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrServerNotFound, serverName)
		}
		return nil, err
	}
	if !srv.Enabled {
		return nil, fmt.Errorf("%w: %s is disabled", ErrServerNotFound, serverName)
	}

	effectiveArgs := bytes.TrimSpace(args)
	if len(effectiveArgs) == 0 || bytes.Equal(effectiveArgs, []byte("null")) {
		effectiveArgs = json.RawMessage(`{}`)
	}

	// 1. Policy authorization.
	if g.authorizer != nil {
		allowed, reason, authErr := g.authorizer.AuthorizeMCPTool(ctx, p, srv.Name+"/"+toolName)
		if authErr != nil {
			g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusError, time.Since(start).Milliseconds(), "authorization check failed", authErrorArgsPlaceholder)
			return nil, authErr
		}
		if !allowed {
			if reason == "" {
				reason = fmt.Sprintf("access to tool %q denied", srv.Name+"/"+toolName)
			}
			g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusDenied, time.Since(start).Milliseconds(), reason, deniedArgsPlaceholder)
			return nil, fmt.Errorf("%w: %s", ErrToolDenied, reason)
		}
	}

	// 2. Guardrail inspection on arguments.
	if g.guardrails != nil {
		action, modifiedArgs, blockReason, gErr := g.inspectToolArguments(ctx, requestID, p, srv.Name, toolName, effectiveArgs)
		if gErr != nil {
			g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusError, time.Since(start).Milliseconds(), "guardrail inspection failed", blockedArgsPlaceholder)
			return nil, gErr
		}
		if action == "block" {
			if blockReason == "" {
				blockReason = "tool call blocked by guardrail policy"
			}
			g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusBlocked, time.Since(start).Milliseconds(), blockReason, blockedArgsPlaceholder)
			return nil, fmt.Errorf("%w: %s", ErrToolBlocked, blockReason)
		}
		if (action == "redact" || action == "modify") && len(modifiedArgs) > 0 {
			effectiveArgs = modifiedArgs
		}
	}

	argsPreview := truncatePreview(effectiveArgs)

	// 3. Execute MCP session handshake + tools/call.
	callCtx, cancel := g.withClientTimeout(ctx)
	defer cancel()

	sess, err := g.openClientSession(callCtx, *srv)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusError, time.Since(start).Milliseconds(), safeErr, argsPreview)
		return nil, err
	}
	defer sess.close()

	resp, err := sess.call(callCtx, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": json.RawMessage(effectiveArgs),
	})
	durMS := time.Since(start).Milliseconds()
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusError, durMS, safeErr, argsPreview)
		return nil, err
	}

	if resp.Error != nil {
		errText := fmt.Sprintf("MCP error (%d): %s", resp.Error.Code, resp.Error.Message)
		g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, AuditStatusError, durMS, errText, argsPreview)
		return &ToolCallResult{
			Result:     errText,
			IsError:    true,
			DurationMS: durMS,
		}, nil
	}

	resultText, isErr := flattenToolCallResult(resp.Result)
	status := AuditStatusOK
	errMsg := ""
	if isErr {
		status = AuditStatusError
		errMsg = truncateString(resultText, 512)
	}
	g.recordAudit(p, srv.Name, "tools/call", toolName, requestID, status, durMS, errMsg, argsPreview)

	return &ToolCallResult{
		Result:     resultText,
		IsError:    isErr,
		DurationMS: durMS,
	}, nil
}

func (g *Gateway) withClientTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, g.clientTimeout)
}

type mcpClientSession struct {
	gw        *Gateway
	srv       store.MCPServer
	postURL   string
	sessionID string
	nextID    int

	// Legacy SSE session state (nil for Streamable HTTP).
	sseCancel context.CancelFunc
	sseResp   *http.Response
	sseMsgCh  chan jsonRPCMessage
	sseErrCh  chan error
	sseDone   chan struct{}
}

func (g *Gateway) openClientSession(ctx context.Context, srv store.MCPServer) (*mcpClientSession, error) {
	sess := &mcpClientSession{
		gw:      g,
		srv:     srv,
		postURL: strings.TrimSpace(srv.URL),
		nextID:  1,
	}

	if strings.EqualFold(strings.TrimSpace(srv.Transport), config.MCPTransportSSE) {
		if err := sess.connectLegacySSE(ctx); err != nil {
			return nil, err
		}
	}

	initParams := map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name":    "headlamp",
			"version": "1.0.0",
		},
	}
	resp, err := sess.call(ctx, "initialize", initParams)
	if err != nil {
		sess.close()
		return nil, fmt.Errorf("mcp: initialize %q: %w", srv.Name, err)
	}
	if resp.Error != nil {
		sess.close()
		return nil, fmt.Errorf("mcp: initialize %q error (%d): %s", srv.Name, resp.Error.Code, resp.Error.Message)
	}

	// Best-effort notifications/initialized per MCP lifecycle spec.
	_ = sess.notify(ctx, "notifications/initialized", nil)
	return sess, nil
}

func (s *mcpClientSession) connectLegacySSE(ctx context.Context) error {
	sseCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, s.srv.URL, nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	applyUpstreamAuth(req, s.srv)

	resp, err := s.gw.httpClient.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("mcp: SSE connect %q: %w", s.srv.Name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		return fmt.Errorf("mcp: SSE connect %q returned HTTP %d: %s", s.srv.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	var endpointURL string
	for {
		frame, readErr := readSSEFrame(reader)
		if readErr != nil {
			_ = resp.Body.Close()
			cancel()
			return fmt.Errorf("mcp: SSE awaiting endpoint from %q: %w", s.srv.Name, readErr)
		}
		if frame.Event == "endpoint" {
			resolved, resErr := resolveSameOriginEndpoint(s.srv, string(frame.Data))
			if resErr != nil {
				_ = resp.Body.Close()
				cancel()
				return resErr
			}
			endpointURL = resolved.String()
			break
		}
	}

	s.postURL = endpointURL
	s.sseCancel = cancel
	s.sseResp = resp
	s.sseMsgCh = make(chan jsonRPCMessage, 32)
	s.sseErrCh = make(chan error, 1)
	s.sseDone = make(chan struct{})

	go func() {
		defer close(s.sseDone)
		for {
			frame, readErr := readSSEFrame(reader)
			if readErr != nil {
				select {
				case s.sseErrCh <- readErr:
				default:
				}
				return
			}
			trimmed := bytes.TrimSpace(frame.Data)
			if len(trimmed) == 0 || trimmed[0] != '{' {
				continue
			}
			var msg jsonRPCMessage
			if err := json.Unmarshal(trimmed, &msg); err != nil {
				continue
			}
			select {
			case s.sseMsgCh <- msg:
			case <-sseCtx.Done():
				return
			}
		}
	}()

	return nil
}

func (s *mcpClientSession) call(ctx context.Context, method string, params any) (*jsonRPCMessage, error) {
	reqIDNum := s.nextID
	s.nextID++
	reqIDRaw := json.RawMessage(fmt.Sprintf("%d", reqIDNum))
	wantID := canonicalRPCID(reqIDRaw)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      reqIDNum,
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.postURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	applyUpstreamAuth(req, s.srv)

	resp, err := s.gw.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if sid := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); sid != "" {
		s.sessionID = sid
	}

	// Legacy SSE servers return 202 Accepted to POST and deliver the JSON-RPC response on the SSE GET stream.
	if resp.StatusCode == http.StatusAccepted && s.sseMsgCh != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return s.waitForSSEResponse(ctx, wantID)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mcp: %s returned HTTP %d: %s", method, resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		return readMatchingRPCFromSSE(resp.Body, wantID)
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, s.gw.maxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(respBytes)) > s.gw.maxResponseBodyBytes {
		return nil, fmt.Errorf("mcp: %s response exceeds gateway limit", method)
	}
	return parseMatchingRPCJSON(respBytes, wantID)
}

func (s *mcpClientSession) notify(ctx context.Context, method string, params any) error {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.postURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	applyUpstreamAuth(req, s.srv)

	resp, err := s.gw.httpClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return nil
}

func (s *mcpClientSession) waitForSSEResponse(ctx context.Context, wantID string) (*jsonRPCMessage, error) {
	for {
		select {
		case msg := <-s.sseMsgCh:
			if canonicalRPCID(msg.ID) == wantID {
				return &msg, nil
			}
		case err := <-s.sseErrCh:
			if err == nil || errors.Is(err, io.EOF) {
				return nil, errors.New("mcp: SSE stream closed before response arrived")
			}
			return nil, fmt.Errorf("mcp: SSE stream error: %w", err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *mcpClientSession) close() {
	if s.sseCancel != nil {
		s.sseCancel()
	}
	if s.sseResp != nil {
		_ = s.sseResp.Body.Close()
	}
	if s.sseDone != nil {
		<-s.sseDone
	}
	// Best-effort Streamable HTTP session cleanup when a session ID was assigned.
	if s.sessionID != "" && s.sseResp == nil {
		delCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if req, err := http.NewRequestWithContext(delCtx, http.MethodDelete, s.postURL, nil); err == nil {
			req.Header.Set("Mcp-Session-Id", s.sessionID)
			applyUpstreamAuth(req, s.srv)
			if resp, err := s.gw.httpClient.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
		}
	}
}

func readMatchingRPCFromSSE(r io.Reader, wantID string) (*jsonRPCMessage, error) {
	reader := bufio.NewReaderSize(r, 64*1024)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("mcp: SSE response ended without matching JSON-RPC result")
			}
			return nil, err
		}
		trimmed := bytes.TrimSpace(frame.Data)
		if len(trimmed) == 0 {
			continue
		}
		if msg, parseErr := parseMatchingRPCJSON(trimmed, wantID); parseErr == nil && msg != nil {
			return msg, nil
		}
	}
}

func parseMatchingRPCJSON(raw []byte, wantID string) (*jsonRPCMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("mcp: empty JSON-RPC response")
	}
	if trimmed[0] == '[' {
		var msgs []jsonRPCMessage
		if err := json.Unmarshal(trimmed, &msgs); err != nil {
			return nil, err
		}
		for i := range msgs {
			if canonicalRPCID(msgs[i].ID) == wantID {
				return &msgs[i], nil
			}
		}
		return nil, fmt.Errorf("mcp: no JSON-RPC response matched id %s", wantID)
	}
	var msg jsonRPCMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		return nil, err
	}
	if wantID != "" && msg.hasID() && canonicalRPCID(msg.ID) != wantID {
		return nil, fmt.Errorf("mcp: mismatched JSON-RPC response id %s (want %s)", canonicalRPCID(msg.ID), wantID)
	}
	return &msg, nil
}

func flattenToolCallResult(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}

	var parsed struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			MimeType string `json:"mimeType"`
			Resource *struct {
				URI  string `json:"uri"`
				Text string `json:"text"`
			} `json:"resource"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		return string(trimmed), false
	}

	parts := make([]string, 0, len(parsed.Content))
	for _, item := range parsed.Content {
		switch item.Type {
		case "text", "":
			if item.Text != "" {
				parts = append(parts, item.Text)
			}
		case "resource":
			if item.Resource != nil {
				if item.Resource.Text != "" {
					parts = append(parts, item.Resource.Text)
				} else if item.Resource.URI != "" {
					parts = append(parts, fmt.Sprintf("[resource: %s]", item.Resource.URI))
				}
			}
		case "image", "audio":
			if item.MimeType != "" {
				parts = append(parts, fmt.Sprintf("[%s: %s]", item.Type, item.MimeType))
			} else {
				parts = append(parts, fmt.Sprintf("[%s]", item.Type))
			}
		default:
			if item.Text != "" {
				parts = append(parts, item.Text)
			}
		}
	}

	if len(parts) > 0 {
		return strings.Join(parts, "\n"), parsed.IsError
	}
	if sc := bytes.TrimSpace(parsed.StructuredContent); len(sc) > 0 && !bytes.Equal(sc, []byte("null")) {
		var compact bytes.Buffer
		if err := json.Compact(&compact, sc); err == nil {
			return compact.String(), parsed.IsError
		}
		return string(sc), parsed.IsError
	}
	if !slices.Contains([]string{"{}", "null"}, string(trimmed)) {
		return string(trimmed), parsed.IsError
	}
	return "", parsed.IsError
}
