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
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
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
	sessions             *sessionStore
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
		sessions:             newSessionStore(cfg.SessionTTL),
		maxRequestBodyBytes:  maxReq,
		maxResponseBodyBytes: maxResp,
		clientTimeout:        clientTimeout,
		logf:                 logf,
	}, nil
}

// ServeHTTP handles incoming MCP requests mounted under /mcp/{server_name} and /mcp/{server_name}/{subpath...}.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// P0-2: Block cross-origin browser CSRF on mutating MCP requests.
	if isMutatingMethod(r.Method) {
		if err := checkSameOriginCSRF(r); err != nil {
			writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, err.Error())
			return
		}
	}

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

	// P1-1: Server-level access gate BEFORE forwarding any method/transport traffic.
	if g.authorizer != nil {
		allowed, reason, authErr := g.authorizer.AuthorizeMCPServer(r.Context(), principal, srv.Name)
		if authErr != nil {
			g.logf("headlamp mcp: authorize server %q failed: %v", srv.Name, authErr)
			writeJSONRPCStatus(w, http.StatusInternalServerError, nil, CodeInternalError, "authorization check failed")
			return
		}
		if !allowed {
			if reason == "" {
				reason = fmt.Sprintf("access to MCP server %q denied by policy", srv.Name)
			}
			writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, reason)
			return
		}
	}

	switch r.Method {
	case http.MethodPost:
		g.handleJSONRPC(w, r, principal, *srv, subpath)
	case http.MethodGet:
		g.handleSSEGet(w, r, principal, *srv, subpath)
	case http.MethodDelete:
		g.handleSessionDelete(w, r, principal, *srv, subpath)
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

func parseSSECallbackClientID(subpath string) (string, bool) {
	if !strings.HasPrefix(subpath, sseCallbackPathPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(subpath, sseCallbackPathPrefix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

type trackedToolCall struct {
	requestID   string
	toolName    string
	argsPreview string
	startTime   time.Time
	recorded    bool
}

func (g *Gateway) resolvePostUpstreamTarget(r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) (targetURL, incomingClientSID, upstreamSID string, allowLastEventID bool, statusCode int, errMsg string) {
	isSSE := strings.EqualFold(strings.TrimSpace(srv.Transport), config.MCPTransportSSE)

	// P1-1: Subpath lockdown — streamable_http forbids all subpaths; sse permits ONLY issued /_sse/<clientID>.
	if subpath != "" {
		if !isSSE {
			return "", "", "", false, http.StatusNotFound, "subpaths are not allowed on streamable_http MCP servers"
		}
		cbClientID, ok := parseSSECallbackClientID(subpath)
		if !ok {
			return "", "", "", false, http.StatusNotFound, "invalid MCP SSE callback path"
		}
		sess, err := g.sessions.lookup(cbClientID, p.Subject, srv.Name)
		if err != nil {
			if errors.Is(err, errSessionForbidden) {
				return "", "", "", false, http.StatusForbidden, "MCP SSE session does not belong to caller"
			}
			return "", "", "", false, http.StatusNotFound, "unknown or expired MCP SSE session"
		}
		if sess.sseCallbackPath == "" {
			return "", "", "", false, http.StatusNotFound, "session does not have an SSE callback endpoint"
		}
		u, err := buildUpstreamCallbackURL(srv, sess.sseCallbackPath)
		if err != nil {
			return "", "", "", false, http.StatusBadGateway, err.Error()
		}
		return u, cbClientID, sess.upstreamID, true, 0, ""
	}

	// Root /mcp/{server_name} POST: validate optional Mcp-Session-Id ownership.
	clientSID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if clientSID != "" {
		sess, err := g.sessions.lookup(clientSID, p.Subject, srv.Name)
		if err != nil {
			if errors.Is(err, errSessionForbidden) {
				return "", "", "", false, http.StatusForbidden, "MCP session does not belong to caller"
			}
			return "", "", "", false, http.StatusNotFound, "unknown or expired MCP session"
		}
		u, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
		if err != nil {
			return "", "", "", false, http.StatusBadGateway, err.Error()
		}
		return u, clientSID, sess.upstreamID, true, 0, ""
	}

	u, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
	if err != nil {
		return "", "", "", false, http.StatusBadGateway, err.Error()
	}
	return u, "", "", false, 0, ""
}

func (g *Gateway) handleJSONRPC(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	// P0-2: Require Content-Type: application/json on POST /mcp/* to block simple-request browser CSRF.
	ctHeader := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, ctErr := mime.ParseMediaType(ctHeader)
	if ctErr != nil || !strings.EqualFold(mediaType, "application/json") {
		writeJSONRPCStatus(w, http.StatusUnsupportedMediaType, nil, CodeInvalidRequest, "Content-Type must be application/json")
		return
	}

	targetURL, incomingClientSID, upstreamSID, allowLastEventID, targetStatus, targetErr := g.resolvePostUpstreamTarget(r, p, srv, subpath)
	if targetStatus != 0 {
		code := CodeInvalidRequest
		if targetStatus == http.StatusForbidden {
			code = CodeToolDenied
		} else if targetStatus >= 500 {
			code = CodeInternalError
		}
		writeJSONRPCStatus(w, targetStatus, nil, code, targetErr)
		return
	}

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
		forwardItems = make([]json.RawMessage, 0, len(rawItems))
		localErrors  = make([]json.RawMessage, 0)
		toolsListIDs = make(map[string]struct{})
		trackedCalls = make(map[string][]*trackedToolCall)
		unkeyedCalls = make([]*trackedToolCall, 0)
	)

	for _, rawItem := range rawItems {
		// P0-1: Strict JSON-RPC envelope parsing rejecting duplicate & case-folded colliding keys.
		env, envErr := parseStrictRPCRequest(rawItem)
		if envErr != nil {
			localErrors = append(localErrors, makeJSONRPCErrorBytes(nil, CodeInvalidRequest, envErr.Error()))
			continue
		}

		if env.IsResponse {
			canonical, err := env.marshalCanonical(nil)
			if err != nil {
				localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInvalidRequest, "failed to canonicalize JSON-RPC response"))
				continue
			}
			forwardItems = append(forwardItems, canonical)
			continue
		}

		switch {
		case env.Method == "tools/list":
			canonical, err := env.marshalCanonical(nil)
			if err != nil {
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "failed to encode tools/list request"))
				}
				continue
			}
			if cid := canonicalRPCID(env.ID); cid != "" {
				toolsListIDs[cid] = struct{}{}
			}
			forwardItems = append(forwardItems, canonical)

		case env.Method == "tools/call":
			callStart := time.Now()
			reqID := uuid.NewString()

			// P0-1: Fail-Closed strict params parsing (rejects case collisions, duplicates, empty/non-string name, non-object arguments).
			tcParams, paramErr := parseStrictToolCallParams(env.Params)
			if paramErr != nil {
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInvalidParams, paramErr.Error()))
				}
				continue
			}

			// 1. Policy authorization BEFORE contacting upstream.
			if g.authorizer != nil {
				allowed, reason, authErr := g.authorizer.AuthorizeMCPTool(r.Context(), p, srv.Name+"/"+tcParams.Name)
				if authErr != nil {
					g.logf("headlamp mcp: authorize %s/%s failed: %v", srv.Name, tcParams.Name, authErr)
					g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "authorization check failed", authErrorArgsPlaceholder)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "authorization check failed"))
					}
					continue
				}
				if !allowed {
					if reason == "" {
						reason = fmt.Sprintf("access to tool %q denied", srv.Name+"/"+tcParams.Name)
					}
					g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusDenied, time.Since(callStart).Milliseconds(), reason, deniedArgsPlaceholder)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeToolDenied, "tool not permitted by policy: "+reason))
					}
					continue
				}
			}

			// 2. Guardrail inspection on normalized params.arguments (P2-3: runs even when arguments was omitted!).
			effectiveArgs := tcParams.Arguments
			if g.guardrails != nil {
				action, modifiedArgs, blockReason, gErr := g.inspectToolArguments(r.Context(), reqID, p, srv.Name, tcParams.Name, effectiveArgs)
				if gErr != nil {
					g.logf("headlamp mcp: guardrail inspect %s/%s failed: %v", srv.Name, tcParams.Name, gErr)
					g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "guardrail inspection failed", blockedArgsPlaceholder)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "guardrail inspection failed"))
					}
					continue
				}
				if action == "block" {
					if blockReason == "" {
						blockReason = "tool call blocked by guardrail policy"
					}
					g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusBlocked, time.Since(callStart).Milliseconds(), blockReason, blockedArgsPlaceholder)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeToolDenied, blockReason))
					}
					continue
				}
				if (action == "redact" || action == "modify") && len(modifiedArgs) > 0 {
					effectiveArgs = modifiedArgs
				}
			}

			// P0-1: Always re-serialize validated tools/call canonically from checked lowercase fields.
			canonicalParams, err := tcParams.marshalCanonical(effectiveArgs)
			if err != nil {
				g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "failed to encode tool params", blockedArgsPlaceholder)
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "failed to encode tool params"))
				}
				continue
			}
			canonicalReq, err := env.marshalCanonical(canonicalParams)
			if err != nil {
				g.recordAudit(p, srv.Name, "tools/call", tcParams.Name, reqID, AuditStatusError, time.Since(callStart).Milliseconds(), "failed to encode tool request", blockedArgsPlaceholder)
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "failed to encode tool request"))
				}
				continue
			}

			tc := &trackedToolCall{
				requestID:   reqID,
				toolName:    tcParams.Name,
				argsPreview: truncatePreview(effectiveArgs),
				startTime:   callStart,
			}
			if cid := canonicalRPCID(env.ID); cid != "" {
				trackedCalls[cid] = append(trackedCalls[cid], tc)
			} else {
				unkeyedCalls = append(unkeyedCalls, tc)
			}
			forwardItems = append(forwardItems, canonicalReq)

		case strings.HasPrefix(env.Method, "resources/") || strings.HasPrefix(env.Method, "prompts/") || strings.HasPrefix(env.Method, "completion/"):
			// P1-1 & P3-2: Require server-wide tool grant (<server>/*) for resources/*, prompts/*, and completion/* methods.
			if g.authorizer != nil {
				allowed, reason, authErr := g.authorizer.AuthorizeMCPTool(r.Context(), p, srv.Name+"/*")
				if authErr != nil {
					g.logf("headlamp mcp: authorize %s %s failed: %v", srv.Name, env.Method, authErr)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "authorization check failed"))
					}
					continue
				}
				if !allowed {
					if reason == "" {
						reason = fmt.Sprintf("method %q requires %s/* grant", env.Method, srv.Name)
					}
					g.recordAudit(p, srv.Name, env.Method, "", uuid.NewString(), AuditStatusDenied, 0, reason, deniedArgsPlaceholder)
					if env.hasID() {
						localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeToolDenied, "method not permitted by policy: "+reason))
					}
					continue
				}
			}
			canonical, err := env.marshalCanonical(nil)
			if err != nil {
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "failed to encode request"))
				}
				continue
			}
			forwardItems = append(forwardItems, canonical)

		default:
			canonical, err := env.marshalCanonical(nil)
			if err != nil {
				if env.hasID() {
					localErrors = append(localErrors, makeJSONRPCErrorBytes(env.ID, CodeInternalError, "failed to encode request"))
				}
				continue
			}
			forwardItems = append(forwardItems, canonical)
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

	// P0-1: Always forward canonically re-serialized JSON bytes, never raw unvalidated client bytes.
	var upBody []byte
	if isBatch {
		upBody = marshalRawArray(forwardItems)
	} else {
		upBody = forwardItems[0]
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(upBody))
	if err != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, "failed to construct upstream request")
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to construct upstream request")
		return
	}
	copyMCPRequestHeaders(upReq.Header, r.Header)
	upReq.Header.Set("Content-Type", "application/json")
	if upReq.Header.Get("Accept") == "" {
		upReq.Header.Set("Accept", "application/json, text/event-stream")
	}
	if upstreamSID != "" {
		upReq.Header.Set("Mcp-Session-Id", upstreamSID)
	}
	if allowLastEventID {
		if lastEv := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastEv != "" {
			upReq.Header.Set("Last-Event-ID", lastEv)
		}
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.logf("headlamp mcp: upstream POST %s failed: %s", srv.Name, safeErr)
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, g.clientUpstreamErrorMessage(r.Context(), p, "upstream MCP request failed", safeErr))
		return
	}
	defer resp.Body.Close()

	// Translate upstream Mcp-Session-Id into a per-user opaque Headlamp session ID.
	setClientSessionHeader := func(dst http.Header) {
		if upRespSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); upRespSID != "" {
			clientSID := g.sessions.bindUpstreamID(incomingClientSID, p.Subject, srv.Name, upRespSID)
			dst.Set("Mcp-Session-Id", clientSID)
		}
	}

	// Accepted / No Content (e.g. MCP notifications or legacy SSE async callback POSTs).
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes))
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")
		if len(localErrors) > 0 && isBatch {
			copyResponseHeaders(w.Header(), resp.Header)
			setClientSessionHeader(w.Header())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(marshalRawArray(localErrors))
			return
		}
		copyResponseHeaders(w.Header(), resp.Header)
		setClientSessionHeader(w.Header())
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
		setClientSessionHeader(w.Header())
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		g.relayStreamableHTTPSSE(w, r.Context(), resp, p, srv, incomingClientSID, toolsListIDs, trackedCalls, unkeyedCalls, localErrors)
		return
	}

	// P1-2: Read with maxResponseBodyBytes+1 so oversized bodies fail closed (502) instead of silently truncating.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseBodyBytes+1))
	if err != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, err.Error())
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to read upstream MCP response")
		return
	}
	if int64(len(respBody)) > g.maxResponseBodyBytes {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, "upstream MCP response exceeds gateway limit")
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "upstream MCP response exceeds gateway limit")
		return
	}

	outBody, filterErr := g.processJSONRPCResponseBytes(r.Context(), respBody, p, srv.Name, toolsListIDs, trackedCalls, localErrors, isBatch)
	if filterErr != nil {
		g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusError, filterErr.Error())
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, "failed to filter upstream MCP response")
		return
	}
	g.finalizePendingCalls(p, srv.Name, trackedCalls, unkeyedCalls, AuditStatusOK, "")

	copyResponseHeaders(w.Header(), resp.Header)
	setClientSessionHeader(w.Header())
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
	incomingClientSID string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
	unkeyedCalls []*trackedToolCall,
	localErrors []json.RawMessage,
) {
	flusher, _ := w.(http.Flusher)
	copyResponseHeaders(w.Header(), resp.Header)
	if upRespSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); upRespSID != "" {
		clientSID := g.sessions.bindUpstreamID(incomingClientSID, p.Subject, srv.Name, upRespSID)
		w.Header().Set("Mcp-Session-Id", clientSID)
	}
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
			filtered, fErr := g.processJSONRPCResponseBytes(ctx, frame.Data, p, srv.Name, toolsListIDs, trackedCalls, nil, false)
			if fErr != nil {
				streamErr = fErr
				break
			}
			frame.Data = filtered
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
	// P1-1: GET never accepts arbitrary subpaths (neither streamable_http nor sse).
	if subpath != "" {
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "subpaths are not allowed on MCP GET endpoints")
		return
	}

	var (
		incomingClientSID string
		upstreamSID       string
		allowLastEventID  bool
	)
	if clientSID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); clientSID != "" {
		sess, err := g.sessions.lookup(clientSID, p.Subject, srv.Name)
		if err != nil {
			if errors.Is(err, errSessionForbidden) {
				writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP session does not belong to caller")
				return
			}
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP session")
			return
		}
		incomingClientSID = clientSID
		upstreamSID = sess.upstreamID
		allowLastEventID = true
	}

	targetURL, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
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
	if upstreamSID != "" {
		upReq.Header.Set("Mcp-Session-Id", upstreamSID)
	}
	if allowLastEventID {
		if lastEv := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastEv != "" {
			upReq.Header.Set("Last-Event-ID", lastEv)
		}
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.logf("headlamp mcp: upstream SSE %s failed: %s", srv.Name, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, g.clientUpstreamErrorMessage(r.Context(), p, "upstream MCP SSE failed", safeErr))
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
	if upRespSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); upRespSID != "" {
		clientSID := g.sessions.bindUpstreamID(incomingClientSID, p.Subject, srv.Name, upRespSID)
		w.Header().Set("Mcp-Session-Id", clientSID)
	}
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
			resolved, resErr := resolveSameOriginEndpoint(srv, string(frame.Data))
			if resErr != nil {
				g.logf("headlamp mcp: rejected unsafe SSE endpoint from %q: %v", srv.Name, resErr)
				return
			}
			cbPath := formatRecordedCallbackPath(resolved)
			clientID := g.sessions.createSSECallback(p.Subject, srv.Name, cbPath)
			rewritten := "/mcp/" + url.PathEscape(srv.Name) + sseCallbackPathPrefix + clientID
			frame.Data = []byte(rewritten)
		} else if len(bytes.TrimSpace(frame.Data)) > 0 {
			// Also filter tools/list responses delivered asynchronously over legacy SSE streams.
			filtered, fErr := g.processJSONRPCResponseBytes(r.Context(), frame.Data, p, srv.Name, nil, nil, nil, false)
			if fErr != nil {
				g.logf("headlamp mcp: aborting SSE stream on filter error for %q: %v", srv.Name, fErr)
				return
			}
			frame.Data = filtered
		}
		if err := writeSSEFrame(w, frame); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (g *Gateway) handleSessionDelete(w http.ResponseWriter, r *http.Request, p *auth.Principal, srv store.MCPServer, subpath string) {
	isSSE := strings.EqualFold(strings.TrimSpace(srv.Transport), config.MCPTransportSSE)

	if subpath != "" {
		if !isSSE {
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "subpaths are not allowed on streamable_http MCP servers")
			return
		}
		cbClientID, ok := parseSSECallbackClientID(subpath)
		if !ok {
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "invalid MCP SSE session path")
			return
		}
		if _, err := g.sessions.delete(cbClientID, p.Subject, srv.Name); err != nil {
			if errors.Is(err, errSessionForbidden) {
				writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP SSE session does not belong to caller")
				return
			}
			writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP SSE session")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	clientSID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if clientSID == "" {
		writeJSONRPCStatus(w, http.StatusBadRequest, nil, CodeInvalidRequest, "Mcp-Session-Id header is required")
		return
	}
	sess, err := g.sessions.delete(clientSID, p.Subject, srv.Name)
	if err != nil {
		if errors.Is(err, errSessionForbidden) {
			writeJSONRPCStatus(w, http.StatusForbidden, nil, CodeToolDenied, "MCP session does not belong to caller")
			return
		}
		writeJSONRPCStatus(w, http.StatusNotFound, nil, CodeInvalidRequest, "unknown or expired MCP session")
		return
	}

	targetURL, err := buildUpstreamBaseURL(srv, r.URL.RawQuery)
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
	if sess.upstreamID != "" {
		upReq.Header.Set("Mcp-Session-Id", sess.upstreamID)
	}
	applyUpstreamAuth(upReq, srv)

	resp, err := g.httpClient.Do(upReq)
	if err != nil {
		safeErr := sanitizeURLError(err)
		g.logf("headlamp mcp: upstream DELETE %s failed: %s", srv.Name, safeErr)
		writeJSONRPCStatus(w, http.StatusBadGateway, nil, CodeInternalError, g.clientUpstreamErrorMessage(r.Context(), p, "upstream MCP DELETE failed", safeErr))
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

// clientUpstreamErrorMessage returns a sanitized diagnostic error for admins while
// hiding internal upstream URLs/IPs from non-admin callers (matching /api/v1/chat/mcp-servers).
func (g *Gateway) clientUpstreamErrorMessage(ctx context.Context, p *auth.Principal, prefix, safeErr string) string {
	if g.isAdminPrincipal(ctx, p) {
		return prefix + ": " + safeErr
	}
	return "upstream MCP server unavailable"
}

func (g *Gateway) processJSONRPCResponseBytes(
	ctx context.Context,
	raw []byte,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
	localErrors []json.RawMessage,
	isBatchRequest bool,
) ([]byte, error) {
	mustFilterTools := g.authorizer != nil && len(toolsListIDs) > 0
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if mustFilterTools {
			return nil, errors.New("empty upstream response for tools/list")
		}
		if len(localErrors) > 0 && isBatchRequest {
			return marshalRawArray(localErrors), nil
		}
		return raw, nil
	}

	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			if mustFilterTools {
				return nil, fmt.Errorf("malformed batch JSON response for tools/list: %w", err)
			}
			return raw, nil
		}
		modified := false
		for i, item := range items {
			updated, changed, err := g.processSingleRPCResponse(ctx, item, p, serverName, toolsListIDs, trackedCalls)
			if err != nil {
				return nil, err
			}
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
			return raw, nil
		}
		return marshalRawArray(items), nil
	}

	if trimmed[0] == '{' {
		updated, changed, err := g.processSingleRPCResponse(ctx, trimmed, p, serverName, toolsListIDs, trackedCalls)
		if err != nil {
			return nil, err
		}
		if len(localErrors) > 0 && isBatchRequest {
			merged := append([]json.RawMessage{updated}, localErrors...)
			return marshalRawArray(merged), nil
		}
		if !changed {
			return raw, nil
		}
		return updated, nil
	}

	if mustFilterTools {
		return nil, errors.New("non-JSON upstream response for tools/list")
	}
	return raw, nil
}

func (g *Gateway) processSingleRPCResponse(
	ctx context.Context,
	rawItem json.RawMessage,
	p *auth.Principal,
	serverName string,
	toolsListIDs map[string]struct{},
	trackedCalls map[string][]*trackedToolCall,
) (json.RawMessage, bool, error) {
	var msg jsonRPCMessage
	if err := json.Unmarshal(rawItem, &msg); err != nil {
		if g.authorizer != nil && len(toolsListIDs) > 0 {
			return nil, false, fmt.Errorf("invalid JSON-RPC response for tools/list: %w", err)
		}
		return rawItem, false, nil
	}

	cid := canonicalRPCID(msg.ID)

	// P2-3: Pop FIFO tracked tools/call per id so duplicate IDs in a batch never clobber audit logs.
	if trackedCalls != nil && cid != "" {
		if queue := trackedCalls[cid]; len(queue) > 0 {
			tc := queue[0]
			trackedCalls[cid] = queue[1:]
			if !tc.recorded {
				tc.recorded = true
				status, errMsg := classifyToolCallResponse(msg)
				g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
			}
		}
	}

	// Filter tools/list responses so unauthorized tools are completely invisible (Fail-Closed).
	if g.authorizer == nil || len(bytes.TrimSpace(msg.Result)) == 0 {
		return rawItem, false, nil
	}
	_, matchedToolsListID := toolsListIDs[cid]
	hasToolsArr := resultHasToolsArray(msg.Result)
	if !matchedToolsListID && !hasToolsArr {
		return rawItem, false, nil
	}

	filteredItem, changed, err := g.filterToolsListResponse(ctx, rawItem, p, serverName, matchedToolsListID)
	if err != nil {
		return nil, false, err
	}
	return filteredItem, changed, nil
}

func (g *Gateway) filterToolsListResponse(
	ctx context.Context,
	rawItem json.RawMessage,
	p *auth.Principal,
	serverName string,
	strict bool,
) (json.RawMessage, bool, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rawItem, &env); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list envelope: %w", err)
		}
		return rawItem, false, nil
	}
	rawResult, ok := env["result"]
	if !ok {
		return rawItem, false, nil
	}
	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &resultObj); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list result object: %w", err)
		}
		return rawItem, false, nil
	}
	rawTools, hasTools := resultObj["tools"]
	if !hasTools {
		return rawItem, false, nil
	}

	var toolEntries []json.RawMessage
	if err := json.Unmarshal(rawTools, &toolEntries); err != nil {
		if strict {
			return nil, false, fmt.Errorf("failed to parse tools/list tools array: %w", err)
		}
		return rawItem, false, nil
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
		return rawItem, false, nil
	}

	resultObj["tools"] = marshalRawArray(allowed)
	encodedResult, err := json.Marshal(resultObj)
	if err != nil {
		return nil, false, err
	}
	env["result"] = encodedResult
	encodedEnv, err := json.Marshal(env)
	if err != nil {
		return nil, false, err
	}
	return encodedEnv, true, nil
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
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		trimmed = json.RawMessage(`{}`)
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
		return "allow", trimmed, "", err
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
	return dec.Action, trimmed, dec.Reason, nil
}

func (g *Gateway) finalizePendingCalls(
	p *auth.Principal,
	serverName string,
	tracked map[string][]*trackedToolCall,
	unkeyed []*trackedToolCall,
	status, errMsg string,
) {
	for _, queue := range tracked {
		for _, tc := range queue {
			if tc.recorded {
				continue
			}
			tc.recorded = true
			g.recordAudit(p, serverName, "tools/call", tc.toolName, tc.requestID, status, time.Since(tc.startTime).Milliseconds(), errMsg, tc.argsPreview)
		}
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
				// P1-2: Bound total multi-line data accumulation to MaxSSELineBytes to prevent OOM.
				extra := len(value)
				if hasData {
					extra++
				}
				if dataBuf.Len()+extra > translate.MaxSSELineBytes {
					return sseFrame{}, fmt.Errorf("%w (%d bytes)", translate.ErrSSELineTooLong, translate.MaxSSELineBytes)
				}
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
