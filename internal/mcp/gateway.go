package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

// Gateway is Headlamp's MCP reverse proxy (Streamable HTTP + Legacy SSE) and
// programmatic MCP tool discovery/execution client.
type Gateway struct {
	store                store.Store
	authorizer           Authorizer
	guardrails           GuardrailInspector
	httpClient           *http.Client
	maxRequestBodyBytes  int64
	maxResponseBodyBytes int64
	clientTimeout        time.Duration
	logf                 func(format string, args ...any)
}

// NewGateway constructs a ready-to-serve MCP Gateway.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Store == nil {
		return nil, errors.New("mcp: store is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = defaultMCPHTTPClient(cfg.BlockLoopback)
	}
	maxReq := cfg.MaxRequestBodyBytes
	if maxReq <= 0 {
		maxReq = defaultMaxRequestBodyBytes
	}
	maxResp := cfg.MaxResponseBodyBytes
	if maxResp <= 0 {
		maxResp = defaultMaxResponseBodyBytes
	}
	clientTimeout := cfg.ClientTimeout
	if clientTimeout <= 0 {
		clientTimeout = defaultClientTimeout
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}

	return &Gateway{
		store:                cfg.Store,
		authorizer:           cfg.Authorizer,
		guardrails:           cfg.Guardrails,
		httpClient:           client,
		maxRequestBodyBytes:  maxReq,
		maxResponseBodyBytes: maxResp,
		clientTimeout:        clientTimeout,
		logf:                 logf,
	}, nil
}

// ServeHTTP handles incoming MCP requests mounted under /mcp/{server_name} and /mcp/{server_name}/{subpath...}.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok || principal == nil {
		writeJSONRPCStatus(w, http.StatusUnauthorized, nil, CodeUnauthorized, "unauthenticated request")
		return
	}

	serverName, subpath, ok := parseMCPPath(r.URL.Path)
	if !ok {
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "MCP server name is required in path /mcp/{server_name}")
		return
	}

	srv, err := g.store.GetMCPServer(r.Context(), serverName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, fmt.Sprintf("MCP server %q not found", serverName))
			return
		}
		g.logf("headlamp mcp: lookup server %q failed: %v", serverName, err)
		writeJSONRPCStatus(w, http.StatusInternalServerError, nil, CodeInternalError, "failed to look up MCP server")
		return
	}
	if !srv.Enabled {
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, fmt.Sprintf("MCP server %q is disabled", serverName))
		return
	}

	switch r.Method {
	case http.MethodPost:
		g.handleJSONRPC(w, r, principal, *srv, subpath)
	case http.MethodGet:
		g.handleSSEGet(w, r, principal, *srv, subpath)
	case http.MethodDelete:
		g.handleSessionDelete(w, r, *srv, subpath)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSONRPCStatus(w, http.StatusMethodNotAllowed, nil, CodeInvalidRequest, "method not allowed")
	}
}

func parseMCPPath(reqPath string) (serverName, subpath string, ok bool) {
	if !strings.HasPrefix(reqPath, "/mcp/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(reqPath, "/mcp/")
	if rest == "" {
		return "", "", false
	}
	rawName, tail, hasSlash := strings.Cut(rest, "/")
	if rawName == "" {
		return "", "", false
	}
	name, err := url.PathUnescape(rawName)
	if err != nil || strings.TrimSpace(name) == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	if hasSlash && tail != "" {
		return name, "/" + tail, true
	}
	return name, "", true
}

type trackedToolCall struct {
	requestID   string
	toolName    string
	argsPreview string
	startTime   time.Time
	recorded    bool
}

func (g *Gateway) handleJSONRPC(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	body, err := g.readLimitedBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeJSONRPCStatus(w, http.StatusRequestEntityTooLarge, nil, CodeInvalidRequest, "request body exceeds gateway limit")
			return
		}
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeParseError, "failed to read request body")
		return
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeParseError, "empty JSON-RPC request body")
		return
	}

	var (
		isBatch  bool
		rawItems []json.RawMessage
	)
	switch trimmed[0] {
	case '{':
		rawItems = []json.RawMessage{trimmed}
	case '[':
		isBatch = true
		if err := json.Unmarshal(trimmed, &rawItems); err != nil {
			writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeParseError, "invalid JSON-RPC batch array")
			return
		}
		if len(rawItems) == 0 {
			writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeInvalidRequest, "empty JSON-RPC batch")
			return
		}
	default:
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeParseError, "JSON-RPC payload must be an object or array")
		return
	}

	var (
		forwardItems    = make([]json.RawMessage, 0, len(rawItems))
		localErrors     = make([]json.RawMessage, 0)
		toolsListIDs    = make(map[string]struct{})
		trackedCalls    = make(map[string]*trackedToolCall)
		unkeyedCalls    = make([]*trackedToolCall, 0)
		anyBodyModified = false
	)

	for _, rawItem := range rawItems {
		var msg jsonRPCMessage
		if err := json.Unmarshal(rawItem, &msg); err != nil {
			localErrors = append(localErrors, makeJSONRPCErrorBytes(nil, CodeParseError, "invalid JSON-RPC message"))
			anyBodyModified = true
			continue
		}

		switch msg.Method {
		case "tools/list":
			if cid := canonicalRPCID(msg.ID); cid != "" {
				toolsListIDs[cid] = struct{}{}
			}
			forwardItems = append(forwardItems, rawItem)

		case "tools/call":
			callStart := time.Now()
			reqID := uuid.NewString()
			toolName, rawArgs, parseErr := extractToolCallParams(msg.Params)
			if parseErr != nil || toolName == "" {
				// Let upstream validate malformed params or return invalid params.
				forwardItems = append(forwardItems, rawItem)
				continue
			}

			// 1. Policy authorization BEFORE contacting upstream.
			if g.authorizer != nil {
				allowed, reason, authErr := g.authorizer.AuthorizeMCPTool(r.Context(), p, srv.Name+"/"+toolName)
				if authErr != nil {
					g.logf("headlamp mcp: authorize %s/%s failed: %v", srv.Name, toolName, authErr)
					g.recordAudit(p, srv.Name, "tools/call", toolName, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "authorization check failed", authErrorArgsPlaceholder)
					if msg.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(msg.ID, CodeInternalError, "authorization check failed"))
					}
					anyBodyModified = true
					continue
				}
				if !allowed {
					if reason == "" {
						reason = fmt.Sprintf("access to tool %q denied", srv.Name+"/"+toolName)
					}
					g.recordAudit(p, srv.Name, "tools/call", toolName, reqID, AuditStatusDenied, time.Since(callStart).Milliseconds(), reason, deniedArgsPlaceholder)
					if msg.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(msg.ID, CodeToolDenied, "tool not permitted by policy: "+reason))
					}
					anyBodyModified = true
					continue
				}
			}

			// 2. Guardrail inspection on params.arguments BEFORE contacting upstream.
			effectiveArgs := rawArgs
			updatedItem := rawItem
			if g.guardrails != nil && len(bytes.TrimSpace(rawArgs)) > 0 {
				action, modifiedArgs, blockReason, gErr := g.inspectToolArguments(r.Context(), reqID, p, srv.Name, toolName, rawArgs)
				if gErr != nil {
					g.logf("headlamp mcp: guardrail inspect %s/%s failed: %v", srv.Name, toolName, gErr)
					g.recordAudit(p, srv.Name, "tools/call", toolName, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "guardrail inspection failed", blockedArgsPlaceholder)
					if msg.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(msg.ID, CodeInternalError, "guardrail inspection failed"))
					}
					anyBodyModified = true
					continue
				}
				if action == "block" {
					if blockReason == "" {
						blockReason = "tool call blocked by guardrail policy"
					}
					g.recordAudit(p, srv.Name, "tools/call", toolName, reqID, AuditStatusBlocked, time.Since(callStart).Milliseconds(), blockReason, blockedArgsPlaceholder)
					if msg.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(msg.ID, CodeToolDenied, blockReason))
					}
					anyBodyModified = true
					continue
				}
				if (action == "redact" || action == "modify") && len(modifiedArgs) > 0 {
					rewritten, rwErr := replaceToolCallArguments(rawItem, modifiedArgs)
					if rwErr != nil {
						g.logf("headlamp mcp: rewrite redacted arguments for %s/%s failed: %v", srv.Name, toolName, rwErr)
						g.recordAudit(p, srv.Name, "tools/call", toolName, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "failed to apply guardrail redaction", blockedArgsPlaceholder)
						if msg.hasID() {
							localErrors = append(localErrors, makeJSONRPCErrorBytes(msg.ID, CodeInternalError, "failed to apply guardrail redaction"))
						}
						anyBodyModified = true
						continue
					}
					updatedItem = rewritten
					effectiveArgs = modifiedArgs
					anyBodyModified = true
				}
			}

			tc := &trackedToolCall{
				requestID:   reqID,
				toolName:    toolName,
				argsPreview: truncatePreview(effectiveArgs),
				startTime:   callStart,
			}
			if cid := canonicalRPCID(msg.ID); cid != "" {
				trackedCalls[cid] = tc
			} else {
				unkeyedCalls = append(unkeyedCalls, tc)
			}
			forwardItems = append(forwardItems, updatedItem)

		default:
			forwardItems = append(forwardItems, rawItem)
		}
	}

	// If every request item was rejected locally, reply directly without touching upstream.
	if len(forwardItems) == 0 {
		if len(localErrors) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if isBatch {
			_, _ = w.Write(marshalRawArray(localErrors))
		} else {
			_, _ = w.Write(localErrors[0])
		}
		return
	}

	// Reconstruct forwarded body only when items were filtered or redacted.
	var upBody []byte
	if !anyBodyModified {
		upBody = body
	} else if isBatch {
		upBody = marshalRawArray(forwardItems)
	} else {
		upBody = forwardItems[0]
	}

	targetURL, err := buildUpstreamURL(srv, subpath, r.URL.RawQuery)
	if err != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, err.Error())
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, err.Error())
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(upBody))
	if err != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, "failed to construct upstream request")
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	if upReq.Header.Get("Content-Type") == "" {
		upReq.Header.Set("Content-Type", "application/json")
	}
	if upReq.Header.Get("Accept") == "" {
		upReq.Header.Set("Accept", "application/json, text/event-stream")
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "upstream MCP request failed: "+safeErr)
		return
	}
	defer resp.Body.Close()

	// Accepted / No Content (e.g. MCP notifications or legacy SSE async callback POSTs).
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")
		if len(localErrors) > 0 && isBatch {
			copyResponseHeaders(w.Header(), resp.Header)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(marshalRawArray(localErrors))
			return
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if len(respBody) > 0 {
			_, _ = w.Write(respBody)
		}
		return
	}

	// Non-2xx upstream response (including non-followed 3xx redirects).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode))
		copyResponseHeaders(w.Header(), resp.Header)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		g.relayStreamableHTTPSSE(w, r.Context(), resp, p, srv, toolsListIDs, trackedCalls, unkeyedCalls, localErrors)
		return
	}

	// Standard application/json response.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
	if err != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, err.Error())
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to read upstream MCP response")
		return
	}

	outBody := g.processJSONRPCResponseBytes(r.Context(), respBody, p, srv.Name, toolsListIDs, trackedCalls, localErrors, isBatch)
	g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")

	copyResponseHeaders(w.Header(), resp.Header)
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(outBody)
}

func (g *Gateway) relayStreamableHTTPSSE(
	w http.ResponseWriter,
	ctx context.Context,
	resp *http.Response,
	p *auth.Principal,
	srv store.MCPServer,
	toolsListIDs map[string]struct{},
	trackedCalls map[string]*trackedToolCall,
	unkeyedCalls []*trackedToolCall,
	localErrors []json.RawMessage,
) {
	flusher, _ := w.(http.Flusher)
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	for _, localErr := range localErrors {
		_ = writeSSEFrame(w, sseFrame{Event: "message", Data: localErr})
		if flusher != nil {
			flusher.Flush()
		}
	}

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	var streamErr error
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				streamErr = err
			}
			break
		}
		if len(bytes.TrimSpace(frame.Data)) > 0 {
			frame.Data = g.processJSONRPCResponseBytes(ctx, frame.Data, p, srv.Name, toolsListIDs, trackedCalls, nil, false)
		}
		if writeErr := writeSSEFrame(w, frame); writeErr != nil {
			streamErr = writeErr
			break
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	if streamErr != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, streamErr.Error())
	} else {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")
	}
}

func (g *Gateway) handleSSEGet(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	targetURL, err := buildUpstreamURL(srv, subpath, r.URL.RawQuery)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, err.Error())
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream SSE request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	if upReq.Header.Get("Accept") == "" {
		upReq.Header.Set("Accept", "text/event-stream")
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "upstream MCP SSE failed: "+sanitizeURLError(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	flusher, _ := w.(http.Flusher)
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}

	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	for {
		frame, err := readSSEFrame(reader)
		if err != nil {
			return
		}
		if frame.Event == "endpoint" {
			rewritten, rwErr := rewriteSSEEndpoint(srv, string(frame.Data))
			if rwErr != nil {
				g.logf("headlamp mcp: rejected unsafe SSE endpoint from %q: %v", srv.Name, rwErr)
				return
			}
			frame.Data = []byte(rewritten)
		} else if len(bytes.TrimSpace(frame.Data)) > 0 {
			// Also filter tools/list responses delivered asynchronously over legacy SSE streams.
			frame.Data = g.processJSONRPCResponseBytes(r.Context(), frame.Data, p, srv.Name, nil, nil, nil, false)
		}
		if err := writeSSEFrame(w, frame); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (g *Gateway) handleSessionDelete(w http.ResponseWriter, r *http.Request, srv store.MCPServer, subpath string) {
	targetURL, err := buildUpstreamURL(srv, subpath, r.URL.RawQuery)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, err.Error())
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, targetURL, nil)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream DELETE request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "upstream MCP DELETE failed: "+sanitizeURLError(err))
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if len(respBody) > 0 {
		_, _ = w.Write(respBody)
	}
}

func (g *Gateway) processJSONRPCResponseBytes(
	ctx context.Context,
	raw []byte,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string]*trackedToolCall,
	localErrors []json.RawMessage,
	isBatchRequest bool,
) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if len(localErrors) > 0 && isBatchRequest {
			return marshalRawArray(localErrors)
		}
		return raw
	}

	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return raw
		}
		modified := false
		for i, item := range items {
			updated, changed := g.processSingleRPCResponse(ctx, item, p, serverName, toolsListIDs, trackedCalls)
			if changed {
				items[i] = updated
				modified = true
			}
		}
		if len(localErrors) > 0 {
			items = append(items, localErrors...)
			modified = true
		}
		if !modified {
			return raw
		}
		return marshalRawArray(items)
	}

	if trimmed[0] == '{' {
		updated, changed := g.processSingleRPCResponse(ctx, trimmed, p, serverName, toolsListIDs, trackedCalls)
		if len(localErrors) > 0 && isBatchRequest {
			merged := append([]json.RawMessage{updated}, localErrors...)
			return marshalRawArray(merged)
		}
		if !changed {
			return raw
		}
		return updated
	}

	return raw
}

func (g *Gateway) processSingleRPCResponse(
	ctx context.Context,
	rawItem json.RawMessage,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string]*trackedToolCall,
) (json.RawMessage, bool) {
	var msg jsonRPCMessage
	if err := json.Unmarshal(rawItem, &msg); err != nil {
		return rawItem, false
	}

	cid := canonicalRPCID(msg.ID)

	// Record audit outcome for tracked tools/call responses.
	if trackedCalls != nil && cid != "" {
		if tc, ok := trackedCalls[cid]; ok && !tc.recorded {
			tc.recorded = true
			status, errMsg := classifyToolCallResponse(msg)
			g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
		}
	}

	// Filter tools/list responses so unauthorized tools are completely invisible.
	if g.authorizer == nil || len(bytes.TrimSpace(msg.Result)) == 0 {
		return rawItem, false
	}
	shouldFilter := false
	if _, matchedID := toolsListIDs[cid]; matchedID {
		shouldFilter = true
	} else if resultHasToolsArray(msg.Result) {
		shouldFilter = true
	}
	if !shouldFilter {
		return rawItem, false
	}

	filteredItem, changed := g.filterToolsListResponse(ctx, rawItem, p, serverName)
	return filteredItem, changed
}

func (g *Gateway) filterToolsListResponse(ctx context.Context, rawItem json.RawMessage, p *auth.Principal, serverName string) (json.RawMessage, bool) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rawItem, &env); err != nil {
		return rawItem, false
	}
	rawResult, ok := env["result"]
	if !ok {
		return rawItem, false
	}
	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &resultObj); err != nil {
		return rawItem, false
	}
	rawTools, hasTools := resultObj["tools"]
	if !hasTools {
		return rawItem, false
	}

	var toolEntries []json.RawMessage
	if err := json.Unmarshal(rawTools, &toolEntries); err != nil {
		return rawItem, false
	}

	allowed := make([]json.RawMessage, 0, len(toolEntries))
	removed := false
	for _, entry := range toolEntries {
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(entry, &meta); err != nil || meta.Name == "" {
			removed = true
			continue
		}
		ok, _, err := g.authorizer.AuthorizeMCPTool(ctx, p, serverName+"/"+meta.Name)
		if err != nil || !ok {
			removed = true
			continue
		}
		allowed = append(allowed, entry)
	}
	if !removed {
		return rawItem, false
	}

	resultObj["tools"] = marshalRawArray(allowed)
	encodedResult, err := json.Marshal(resultObj)
	if err != nil {
		return rawItem, false
	}
	env["result"] = encodedResult
	encodedEnv, err := json.Marshal(env)
	if err != nil {
		return rawItem, false
	}
	return encodedEnv, true
}

func resultHasToolsArray(rawResult json.RawMessage) bool {
	trimmed := bytes.TrimSpace(rawResult)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var probe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false
	}
	t := bytes.TrimSpace(probe.Tools)
	return len(t) > 0 && t[0] == '['
}

func classifyToolCallResponse(msg jsonRPCMessage) (status, errMsg string) {
	if msg.Error != nil {
		return AuditStatusError, fmt.Sprintf("JSON-RPC error %d: %s", msg.Error.Code, msg.Error.Message)
	}
	if len(bytes.TrimSpace(msg.Result)) > 0 {
		var res struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msg.Result, &res); err == nil && res.IsError {
			var parts []string
			for _, c := range res.Content {
				if strings.TrimSpace(c.Text) != "" {
					parts = append(parts, c.Text)
				}
			}
			msgText := strings.Join(parts, "; ")
			if msgText == "" {
				msgText = "tool returned isError=true"
			}
			return AuditStatusError, truncateString(msgText, 512)
		}
	}
	return AuditStatusOK, ""
}

// inspectToolArguments wraps arguments inside {"arguments": <rawArgs>} before
// invoking GuardrailInspector so Headlamp's path-aware guardrail evaluator scans
// 100% of nested string keys (including "id", "name", "detail", "model", "role").
func (g *Gateway) inspectToolArguments(
	ctx context.Context,
	requestID string,
	p *auth.Principal,
	serverName, toolName string,
	rawArgs json.RawMessage,
) (action string, modifiedArgs json.RawMessage, reason string, err error) {
	trimmed := bytes.TrimSpace(rawArgs)
	if len(trimmed) == 0 {
		return "allow", rawArgs, "", nil
	}
	wrapped, err := json.Marshal(struct {
		Arguments json.RawMessage `json:"arguments"`
	}{Arguments: trimmed})
	if err != nil {
		return "", nil, "", err
	}

	dec, err := g.guardrails.Inspect(ctx, GuardrailRequest{
		RequestID: requestID,
		Principal: p,
		Protocol:  "mcp",
		Model:     serverName + "/" + toolName,
		Body:      wrapped,
	})
	if err != nil || dec == nil {
		return "allow", rawArgs, "", err
	}

	if dec.Action == "block" {
		return "block", nil, dec.Reason, nil
	}
	if (dec.Action == "redact" || dec.Action == "modify") && len(bytes.TrimSpace(dec.ModifiedBody)) > 0 {
		var unwrapped map[string]json.RawMessage
		if err := json.Unmarshal(dec.ModifiedBody, &unwrapped); err == nil {
			if modArgs, ok := unwrapped["arguments"]; ok && len(unwrapped) == 1 && json.Valid(modArgs) {
				return dec.Action, bytes.Clone(modArgs), "", nil
			}
		}
		if json.Valid(dec.ModifiedBody) {
			return dec.Action, bytes.Clone(dec.ModifiedBody), "", nil
		}
	}
	return dec.Action, rawArgs, dec.Reason, nil
}

func extractToolCallParams(rawParams json.RawMessage) (toolName string, args json.RawMessage, err error) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &p); err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(p.Name), p.Arguments, nil
}

func replaceToolCallArguments(rawMsg json.RawMessage, newArgs json.RawMessage) (json.RawMessage, error) {
	var msgMap map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &msgMap); err != nil {
		return nil, err
	}
	var paramsMap map[string]json.RawMessage
	if err := json.Unmarshal(msgMap["params"], &paramsMap); err != nil {
		return nil, err
	}
	if paramsMap == nil {
		paramsMap = make(map[string]json.RawMessage)
	}
	paramsMap["arguments"] = newArgs
	encodedParams, err := json.Marshal(paramsMap)
	if err != nil {
		return nil, err
	}
	msgMap["params"] = encodedParams
	encodedMsg, err := json.Marshal(msgMap)
	if err != nil {
		return nil, err
	}
	return encodedMsg, nil
}

func (g *Gateway) finalizePendingCalls(
	p *auth.Principal,
	serverName string,
	tracked map[string]*trackedToolCall,
	unkeyed []*trackedToolCall,
	status, errMsg string,
) {
	for _, tc := range tracked {
		if tc.recorded {
			continue
		}
		tc.recorded = true
		g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
	}
	for _, tc := range unkeyed {
		if tc.recorded {
			continue
		}
		tc.recorded = true
		g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
	}
}

func (g *Gateway) recordAudit(
	p *auth.Principal,
	serverName, method, toolName, requestID, status string,
	latencyMS int64,
	errMsg, argsPreview string,
) {
	if g.store == nil {
		return
	}
	entry := store.MCPAuditLog{
		ID:               uuid.NewString(),
		CreatedAt:        time.Now().UTC(),
		RequestID:        requestID,
		ServerName:       serverName,
		Method:           method,
		ToolName:         toolName,
		Status:           status,
		LatencyMS:        latencyMS,
		ErrorMessage:     errMsg,
		ArgumentsPreview: argsPreview,
	}
	if p != nil {
		entry.Subject = p.Subject
		entry.DisplayName = p.DisplayName
		entry.NodeName = p.NodeName
		entry.NodeIP = p.NodeIP
		entry.Tags = slices.Clone(p.Tags)
		entry.AuthSource = p.AuthSource
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.store.InsertMCPAuditLog(ctx, entry); err != nil {
		g.logf("headlamp mcp: persist audit log failed: %v", err)
	}
}

var errBodyTooLarge = errors.New("mcp: request body too large")

func (g *Gateway) readLimitedBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, g.maxRequestBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > g.maxRequestBodyBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func writeJSONRPCStatus(w http.ResponseWriter, statusCode int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(makeJSONRPCErrorBytes(id, code, message))
}

func marshalRawArray(items []json.RawMessage) []byte {
	if len(items) == 0 {
		return []byte("[]")
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func truncatePreview(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err == nil {
		return truncateString(compact.String(), maxAuditArgsPreviewBytes)
	}
	return truncateString(string(trimmed), maxAuditArgsPreviewBytes)
}

func truncateString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	const suffix = "...[truncated]"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return s[:maxBytes]
	}
	// Back up to a valid UTF-8 rune boundary.
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + suffix
}

// sseFrame preserves SSE event metadata (id, event, retry, data) using a
// 16 MiB-capable bufio.Reader (never 64 KiB bufio.Scanner).
type sseFrame struct {
	ID    string
	Event string
	Retry string
	Data  []byte
}

func readSSEFrame(r *bufio.Reader) (sseFrame, error) {
	var (
		frame   sseFrame
		dataBuf bytes.Buffer
		hasAny  bool
		hasData bool
	)

	for {
		line, err := translate.ReadLineLimited(r, translate.MaxSSELineBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return sseFrame{}, err
		}

		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			if hasAny {
				if hasData {
					frame.Data = bytes.Clone(dataBuf.Bytes())
				}
				return frame, nil
			}
			if errors.Is(err, io.EOF) {
				return sseFrame{}, io.EOF
			}
			continue
		}

		if trimmed[0] != ':' {
			colon := bytes.IndexByte(trimmed, ':')
			var field, value string
			if colon < 0 {
				field = string(trimmed)
			} else {
				field = string(trimmed[:colon])
				val := trimmed[colon+1:]
				if len(val) > 0 && val[0] == ' ' {
					val = val[1:]
				}
				value = string(val)
			}
			switch field {
			case "event":
				frame.Event = value
				hasAny = true
			case "id":
				frame.ID = value
				hasAny = true
			case "retry":
				frame.Retry = value
				hasAny = true
			case "data":
				if hasData {
					dataBuf.WriteByte('\n')
				}
				dataBuf.WriteString(value)
				hasData = true
				hasAny = true
			}
		}

		if errors.Is(err, io.EOF) {
			if hasAny {
				if hasData {
					frame.Data = bytes.Clone(dataBuf.Bytes())
				}
				return frame, nil
			}
			return sseFrame{}, io.EOF
		}
	}
}

func writeSSEFrame(w io.Writer, frame sseFrame) error {
	var buf bytes.Buffer
	if frame.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(frame.ID)
		buf.WriteByte('\n')
	}
	if frame.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(frame.Event)
		buf.WriteByte('\n')
	}
	if frame.Retry != "" {
		buf.WriteString("retry: ")
		buf.WriteString(frame.Retry)
		buf.WriteByte('\n')
	}
	if len(frame.Data) > 0 {
		lines := bytes.Split(frame.Data, []byte("\n"))
		for _, line := range lines {
			buf.WriteString("data: ")
			buf.Write(line)
			buf.WriteByte('\n')
		}
	} else {
		buf.WriteString("data: \n")
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}
