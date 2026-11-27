package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/store"
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
