package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/guardrail"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/store"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "mcp.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func makePrincipal(subject string, allowTools, denyTools []string) *auth.Principal {
	capPayload, _ := json.Marshal([]map[string]any{{
		"role":           "user",
		"models":         []string{"*"},
		"mcp_tools":      allowTools,
		"deny_mcp_tools": denyTools,
	}})
	return &auth.Principal{
		Subject:     subject,
		DisplayName: "Alice Dev",
		NodeName:    "alice-mac",
		NodeIP:      "100.64.0.12",
		Tags:        []string{"tag:eng"},
		AuthSource:  auth.AuthSourceTSNet,
		RawCaps: map[string][]byte{
			auth.CapHeadlampGateway: capPayload,
		},
	}
}

type guardrailEngineAdapter struct {
	engine *guardrail.Engine
}

func (a guardrailEngineAdapter) Inspect(ctx context.Context, req GuardrailRequest) (*GuardrailDecision, error) {
	subject, nodeName := "", ""
	if req.Principal != nil {
		subject = req.Principal.Subject
		nodeName = req.Principal.NodeName
	}
	dec, err := a.engine.InspectRequest(ctx, guardrail.InspectInput{
		RequestID: req.RequestID,
		Subject:   subject,
		NodeName:  nodeName,
		Protocol:  req.Protocol,
		Model:     req.Model,
		Body:      req.Body,
	})
	if err != nil || dec == nil {
		return nil, err
	}
	return &GuardrailDecision{
		Action:       dec.Action,
		ModifiedBody: dec.ModifiedBody,
		Hits:         dec.Hits,
		Reason:       dec.Reason,
		StatusCode:   dec.StatusCode,
	}, nil
}

func authedReq(p *auth.Principal, method, path, body string) *http.Request {
	var rBody io.Reader
	if body != "" {
		rBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if p != nil {
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	}
	return req
}

func TestStreamableHTTPProxyToolsListFilterAndToolCallGovernance(t *testing.T) {
	var (
		mu              sync.Mutex
		seenAuthHeaders []string
		seenCustomHdr   string
		seenCallArgs    json.RawMessage
		seenDeleteSID   string
		callHits        atomic.Int32
		sseMode         atomic.Bool
	)

	// Large description (>100 KiB) proves SSE framing uses large-buffer bufio.Reader, never 64 KiB Scanner.
	bigDesc := strings.Repeat("x", 100*1024)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuthHeaders = append(seenAuthHeaders, r.Header.Get("Authorization"))
		if v := r.Header.Get("X-MCP-Key"); v != "" {
			seenCustomHdr = v
		}
		mu.Unlock()

		if r.Method == http.MethodDelete {
			mu.Lock()
			seenDeleteSID = r.Header.Get("Mcp-Session-Id")
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		raw, _ := io.ReadAll(r.Body)
		trimmed := bytes.TrimSpace(raw)
		isBatch := len(trimmed) > 0 && trimmed[0] == '['
		var reqs []jsonRPCMessage
		if isBatch {
			_ = json.Unmarshal(trimmed, &reqs)
		} else {
			var one jsonRPCMessage
			_ = json.Unmarshal(trimmed, &one)
			reqs = []jsonRPCMessage{one}
		}

		resps := make([]jsonRPCMessage, 0, len(reqs))
		for _, msg := range reqs {
			switch msg.Method {
			case "tools/list":
				resJSON, _ := json.Marshal(map[string]any{
					"tools": []map[string]any{
						{"name": "search", "description": bigDesc, "inputSchema": map[string]any{"type": "object"}},
						{"name": "get", "description": "get doc", "inputSchema": map[string]any{"type": "object"}},
						{"name": "delete_all", "description": "dangerous", "inputSchema": map[string]any{"type": "object"}},
					},
				})
				resps = append(resps, jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resJSON})
			case "tools/call":
				callHits.Add(1)
				_, args, _ := extractToolCallParams(msg.Params)
				mu.Lock()
				seenCallArgs = bytes.Clone(args)
				mu.Unlock()
				resJSON, _ := json.Marshal(map[string]any{
					"content": []map[string]any{{"type": "text", "text": "result:" + string(args)}},
				})
				resps = append(resps, jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resJSON})
			default:
				resps = append(resps, jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)})
			}
		}

		w.Header().Set("Mcp-Session-Id", "sess-up-1")
		if sseMode.Load() {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			for _, resp := range resps {
				b, _ := json.Marshal(resp)
				_, _ = w.Write([]byte("event: message\ndata: " + string(b) + "\n\n"))
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if isBatch {
			_ = json.NewEncoder(w).Encode(resps)
		} else {
			_ = json.NewEncoder(w).Encode(resps[0])
		}
	}))
	defer upstream.Close()

	st := newTestStore(t)
	for _, r := range store.DefaultBuiltinGuardrailRules() {
		if err := st.UpsertGuardrailRule(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "docs", URL: upstream.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthBearer, AuthToken: "upstream-bearer-secret", Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "hdr-srv", URL: upstream.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthHeader, AuthHeader: "X-MCP-Key", AuthToken: "custom-hdr-secret", Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "basic-srv", URL: upstream.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthBasic, AuthToken: "svc:pw123", Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "disabled-srv", URL: upstream.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthNone, Enabled: false, Source: store.SourceLocal,
	})

	grEng, err := guardrail.NewEngine(guardrail.EngineConfig{Store: st, RetryBackoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = grEng.Close(context.Background()) }()

	gw, err := NewGateway(GatewayConfig{
		Store:      st,
		Authorizer: policy.NewEvaluator(),
		Guardrails: guardrailEngineAdapter{engine: grEng},
	})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"docs/*", "hdr-srv/*", "basic-srv/*"}, []string{"docs/delete_*"})

	// 1. Unauthenticated -> 401; unknown/disabled server -> 404.
	rec401 := httptest.NewRecorder()
	gw.ServeHTTP(rec401, authedReq(nil, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec401.Code)
	}
	for _, p := range []string{"/mcp/", "/mcp/missing", "/mcp/disabled-srv"} {
		rec404 := httptest.NewRecorder()
		gw.ServeHTTP(rec404, authedReq(alice, http.MethodPost, p, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if rec404.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", p, rec404.Code)
		}
	}

	// 2. tools/list JSON response filters out denied "delete_all" & injects Bearer auth (never forwarding caller Authorization).
	reqList := authedReq(alice, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	reqList.Header.Set("Authorization", "Bearer caller-headlamp-token")
	recList := httptest.NewRecorder()
	gw.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK || recList.Header().Get("Mcp-Session-Id") != "sess-up-1" {
		t.Fatalf("tools/list failed: code=%d sid=%q body=%s", recList.Code, recList.Header().Get("Mcp-Session-Id"), recList.Body.String())
	}
	var listResp struct {
		Result struct {
			Tools []ToolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, td := range listResp.Result.Tools {
		names = append(names, td.Name)
	}
	if !slices.Equal(names, []string{"search", "get"}) {
		t.Fatalf("expected filtered tools [search get], got %v", names)
	}
	mu.Lock()
	if len(seenAuthHeaders) == 0 || seenAuthHeaders[len(seenAuthHeaders)-1] != "Bearer upstream-bearer-secret" {
		mu.Unlock()
		t.Fatalf("upstream did not receive injected bearer token: %v", seenAuthHeaders)
	}
	mu.Unlock()

	// 3. tools/list over Streamable HTTP SSE with >100 KiB single line still filters out "delete_all".
	sseMode.Store(true)
	recListSSE := httptest.NewRecorder()
	gw.ServeHTTP(recListSSE, authedReq(alice, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if recListSSE.Code != http.StatusOK || !strings.Contains(recListSSE.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("SSE tools/list failed: code=%d ct=%q", recListSSE.Code, recListSSE.Header().Get("Content-Type"))
	}
	if strings.Contains(recListSSE.Body.String(), "delete_all") || !strings.Contains(recListSSE.Body.String(), `"search"`) {
		t.Fatalf("SSE tools/list failed to filter delete_all or truncated >100KiB frame")
	}
	sseMode.Store(false)

	// 4. Custom header & Basic auth injection.
	recHdr := httptest.NewRecorder()
	gw.ServeHTTP(recHdr, authedReq(alice, http.MethodPost, "/mcp/hdr-srv", `{"jsonrpc":"2.0","id":3,"method":"ping"}`))
	recBasic := httptest.NewRecorder()
	gw.ServeHTTP(recBasic, authedReq(alice, http.MethodPost, "/mcp/basic-srv", `{"jsonrpc":"2.0","id":4,"method":"ping"}`))
	mu.Lock()
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:pw123"))
	if seenCustomHdr != "custom-hdr-secret" || seenAuthHeaders[len(seenAuthHeaders)-1] != wantBasic {
		mu.Unlock()
		t.Fatalf("header/basic auth mismatch: custom=%q auths=%v", seenCustomHdr, seenAuthHeaders)
	}
	mu.Unlock()

	// 5. tools/call DENIED by policy -> -32003 JSON-RPC error, zero upstream hit, audit status="denied"
	//    with placeholder ArgumentsPreview (embedded AWS secret must NEVER be persisted unredacted!).
	awsKey := "AKIA" + "0123456789ABCDEF"
	beforeDenied := callHits.Load()
	recDeny := httptest.NewRecorder()
	gw.ServeHTTP(recDeny, authedReq(alice, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"delete_all","arguments":{"force":true,"token":"`+awsKey+`"}}}`))
	if recDeny.Code != http.StatusOK {
		t.Fatalf("expected 200 JSON-RPC error envelope, got %d", recDeny.Code)
	}
	if callHits.Load() != beforeDenied {
		t.Fatalf("denied tool call must NEVER contact upstream")
	}
	var denyMsg jsonRPCMessage
	if err := json.Unmarshal(recDeny.Body.Bytes(), &denyMsg); err != nil || denyMsg.Error == nil || denyMsg.Error.Code != CodeToolDenied || !strings.Contains(denyMsg.Error.Message, "tool not permitted by policy") {
		t.Fatalf("unexpected denied JSON-RPC response: %s", recDeny.Body.String())
	}

	// 6. tools/call REDACTED by guardrails (even inside keys named "id" and "model"!) before upstream & audit.
	recRedact := httptest.NewRecorder()
	gw.ServeHTTP(recRedact, authedReq(alice, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"search","arguments":{"id":"`+awsKey+`","model":"`+awsKey+`","q":"find `+awsKey+`"}}}`))
	if recRedact.Code != http.StatusOK {
		t.Fatalf("redacted tools/call failed: %d %s", recRedact.Code, recRedact.Body.String())
	}
	mu.Lock()
	gotArgs := string(seenCallArgs)
	mu.Unlock()
	if strings.Contains(gotArgs, awsKey) || !strings.Contains(gotArgs, "[REDACTED:builtin-aws-access-key]") {
		t.Fatalf("upstream received unredacted secret in tool arguments: %s", gotArgs)
	}

	// 7. tools/call BLOCKED by guardrail (PEM private key) -> -32003, zero upstream hit, audit preview stubbed!
	beforeBlock := callHits.Load()
	pem := "-----BEGIN " + "PRIVATE KEY-----\\nSUPERSECRET\\n-----END " + "PRIVATE KEY-----"
	recBlock := httptest.NewRecorder()
	gw.ServeHTTP(recBlock, authedReq(alice, http.MethodPost, "/mcp/docs", `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"search","arguments":{"text":"`+pem+`"}}}`))
	if callHits.Load() != beforeBlock {
		t.Fatalf("guardrail-blocked tool call must NEVER contact upstream")
	}
	var blockMsg jsonRPCMessage
	if err := json.Unmarshal(recBlock.Body.Bytes(), &blockMsg); err != nil || blockMsg.Error == nil || blockMsg.Error.Code != CodeToolDenied {
		t.Fatalf("unexpected blocked JSON-RPC response: %s", recBlock.Body.String())
	}

	// 8. JSON-RPC batch mixing tools/list + allowed tools/call + denied tools/call.
	batchReq := `[
		{"jsonrpc":"2.0","id":"b1","method":"tools/list"},
		{"jsonrpc":"2.0","id":"b2","method":"tools/call","params":{"name":"get","arguments":{"doc":"readme"}}},
		{"jsonrpc":"2.0","id":"b3","method":"tools/call","params":{"name":"delete_all","arguments":{}}}
	]`
	recBatch := httptest.NewRecorder()
	gw.ServeHTTP(recBatch, authedReq(alice, http.MethodPost, "/mcp/docs", batchReq))
	if recBatch.Code != http.StatusOK {
		t.Fatalf("batch failed: %d %s", recBatch.Code, recBatch.Body.String())
	}
	var batchResps []jsonRPCMessage
	if err := json.Unmarshal(recBatch.Body.Bytes(), &batchResps); err != nil || len(batchResps) != 3 {
		t.Fatalf("expected 3 batch responses, got err=%v count=%d", err, len(batchResps))
	}
	byID := make(map[string]jsonRPCMessage, len(batchResps))
	for _, br := range batchResps {
		byID[canonicalRPCID(br.ID)] = br
	}
	if strings.Contains(string(byID[`"b1"`].Result), "delete_all") || !strings.Contains(string(byID[`"b1"`].Result), `"search"`) {
		t.Fatalf("batch b1 tools/list failed to filter delete_all")
	}
	if byID[`"b2"`].Error != nil || !strings.Contains(string(byID[`"b2"`].Result), "readme") {
		t.Fatalf("batch b2 allowed tool call failed: %+v", byID[`"b2"`])
	}
	if byID[`"b3"`].Error == nil || byID[`"b3"`].Error.Code != CodeToolDenied {
		t.Fatalf("batch b3 denied tool call expected -32003 error, got %+v", byID[`"b3"`])
	}

	// 9. DELETE forwards Mcp-Session-Id.
	reqDel := authedReq(alice, http.MethodDelete, "/mcp/docs", "")
	reqDel.Header.Set("Mcp-Session-Id", "sess-up-1")
	recDel := httptest.NewRecorder()
	gw.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on DELETE, got %d", recDel.Code)
	}
	mu.Lock()
	if seenDeleteSID != "sess-up-1" {
		mu.Unlock()
		t.Fatalf("DELETE did not forward Mcp-Session-Id, got %q", seenDeleteSID)
	}
	mu.Unlock()

	// 10. Verify SQLite MCPAuditLog persistence across ok, denied, blocked, and redacted arguments!
	logs, err := st.QueryMCPAuditLogs(context.Background(), store.MCPAuditFilter{ServerName: "docs", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]int)
	for _, entry := range logs {
		statuses[entry.Status]++
		if entry.Subject != "alice@example.com" || entry.NodeName != "alice-mac" {
			t.Fatalf("missing principal fields on audit log: %+v", entry)
		}
		if strings.Contains(entry.ArgumentsPreview, awsKey) || strings.Contains(entry.ArgumentsPreview, "SUPERSECRET") {
			t.Fatalf("raw secret leaked into mcp_audit_logs.arguments_preview: %+v", entry)
		}
		if entry.Status == AuditStatusBlocked && entry.ArgumentsPreview != blockedArgsPlaceholder {
			t.Fatalf("blocked audit preview must be %q, got %q", blockedArgsPlaceholder, entry.ArgumentsPreview)
		}
		if entry.Status == AuditStatusDenied && entry.ArgumentsPreview != deniedArgsPlaceholder {
			t.Fatalf("denied audit preview must be %q, got %q", deniedArgsPlaceholder, entry.ArgumentsPreview)
		}
	}
	if statuses[AuditStatusOK] < 2 || statuses[AuditStatusDenied] < 2 || statuses[AuditStatusBlocked] != 1 {
		t.Fatalf("unexpected audit status counts: %+v (logs=%+v)", statuses, logs)
	}
}

// mockLegacySSEServer implements MCP's legacy GET /sse + POST /messages?sessionId=... transport.
type mockLegacySSEServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	sessions map[string]chan string
	callHits atomic.Int32
}

func newMockLegacySSEServer(t *testing.T, customEndpoint string) *mockLegacySSEServer {
	t.Helper()
	m := &mockLegacySSEServer{sessions: make(map[string]chan string)}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			flusher, _ := w.(http.Flusher)
			sid := "sid-legacy-1"
			ch := make(chan string, 16)
			m.mu.Lock()
			m.sessions[sid] = ch
			m.mu.Unlock()
			defer func() {
				m.mu.Lock()
				delete(m.sessions, sid)
				m.mu.Unlock()
			}()

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			ep := customEndpoint
			if ep == "" {
				ep = "/messages?sessionId=" + sid
			}
			_, _ = w.Write([]byte("event: endpoint\ndata: " + ep + "\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
			for {
				select {
				case msg := <-ch:
					_, _ = w.Write([]byte("event: message\ndata: " + msg + "\n\n"))
					if flusher != nil {
						flusher.Flush()
					}
				case <-r.Context().Done():
					return
				}
			}

		case r.Method == http.MethodPost && r.URL.Path == "/messages":
			sid := r.URL.Query().Get("sessionId")
			raw, _ := io.ReadAll(r.Body)
			var msg jsonRPCMessage
			_ = json.Unmarshal(raw, &msg)

			var reply jsonRPCMessage
			switch msg.Method {
			case "initialize":
				reply = jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}`)}
			case "notifications/initialized":
				w.WriteHeader(http.StatusAccepted)
				return
			case "tools/list":
				reply = jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"tools":[{"name":"echo","description":"echo text"},{"name":"secret_admin","description":"denied"}]}`)}
			case "tools/call":
				m.callHits.Add(1)
				toolName, args, _ := extractToolCallParams(msg.Params)
				res, _ := json.Marshal(map[string]any{
					"content": []map[string]any{{"type": "text", "text": toolName + ":" + string(args)}},
				})
				reply = jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: res}
			}

			m.mu.Lock()
			ch := m.sessions[sid]
			m.mu.Unlock()
			if ch != nil && reply.JSONRPC != "" {
				b, _ := json.Marshal(reply)
				ch <- string(b)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func TestLegacySSETransportRewriteAndAsyncToolsFiltering(t *testing.T) {
	legacy := newMockLegacySSEServer(t, "")
	evilLegacy := newMockLegacySSEServer(t, "http://169.254.169.254/latest/meta-data/")

	st := newTestStore(t)
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "legacy", URL: legacy.srv.URL + "/sse", Transport: config.MCPTransportSSE,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "evil-sse", URL: evilLegacy.srv.URL + "/sse", Transport: config.MCPTransportSSE,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})

	gw, err := NewGateway(GatewayConfig{
		Store:      st,
		Authorizer: policy.NewEvaluator(),
	})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"legacy/*"}, []string{"legacy/secret_*"})

	// Host Gateway behind httptest.NewServer so streaming GET /mcp/legacy and follow-up POST work concurrently.
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gw.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), alice)))
	}))
	defer gwSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sseReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, gwSrv.URL+"/mcp/legacy", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	epFrame, err := readSSEFrame(reader)
	if err != nil {
		t.Fatalf("read endpoint frame: %v", err)
	}
	if epFrame.Event != "endpoint" || string(epFrame.Data) != "/mcp/legacy/messages?sessionId=sid-legacy-1" {
		t.Fatalf("unexpected rewritten SSE endpoint: event=%q data=%q", epFrame.Event, string(epFrame.Data))
	}

	// Follow-up POST tools/list to the rewritten endpoint -> response arrives on SSE stream with secret_admin filtered out!
	postResp, err := http.Post(gwSrv.URL+string(epFrame.Data), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 from legacy callback POST, got %d", postResp.StatusCode)
	}

	listFrame, err := readSSEFrame(reader)
	if err != nil {
		t.Fatalf("read tools/list SSE frame: %v", err)
	}
	if !strings.Contains(string(listFrame.Data), `"echo"`) || strings.Contains(string(listFrame.Data), "secret_admin") {
		t.Fatalf("legacy SSE tools/list did not filter secret_admin: %s", string(listFrame.Data))
	}

	// Follow-up POST for denied tool -> immediate JSON-RPC -32003, never hits upstream!
	denyResp, err := http.Post(gwSrv.URL+string(epFrame.Data), "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret_admin","arguments":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	denyBody, _ := io.ReadAll(denyResp.Body)
	_ = denyResp.Body.Close()
	if legacy.callHits.Load() != 0 || !strings.Contains(string(denyBody), fmt.Sprintf(`"code":%d`, CodeToolDenied)) {
		t.Fatalf("denied legacy tool call not blocked: hits=%d body=%s", legacy.callHits.Load(), string(denyBody))
	}

	// Cross-origin malicious SSE endpoint (169.254.169.254) must be rejected by DiscoverTools and proxy.
	_, _, evilErr := gw.DiscoverTools(ctx, store.MCPServer{
		Name: "evil-sse", URL: evilLegacy.srv.URL + "/sse", Transport: config.MCPTransportSSE, Enabled: true,
	})
	if !errors.Is(evilErr, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress on cross-origin SSE endpoint, got %v", evilErr)
	}
}

func TestProgrammaticHelpersDiscoverListAndCallAuthorizedTool(t *testing.T) {
	var (
		mu             sync.Mutex
		seenDeleteHTTP atomic.Int32
		seenCallArgs   json.RawMessage
		initCount      atomic.Int32
	)

	// Paginated Streamable HTTP server (returns JSON on page 1, SSE on page 2 + tools/call).
	streamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("Mcp-Session-Id") == "stream-sid-42" {
				seenDeleteHTTP.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var msg jsonRPCMessage
		_ = json.Unmarshal(raw, &msg)

		switch msg.Method {
		case "initialize":
			initCount.Add(1)
			w.Header().Set("Mcp-Session-Id", "stream-sid-42")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jsonRPCMessage{
				JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{"tools":{}}}`),
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			var p struct {
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			if p.Cursor == "" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(jsonRPCMessage{
					JSONRPC: "2.0", ID: msg.ID,
					Result: json.RawMessage(`{"tools":[{"name":"search","description":"search docs","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}`),
				})
				return
			}
			// Page 2 returned over SSE to test Streamable HTTP SSE client parsing too.
			w.Header().Set("Content-Type", "text/event-stream")
			resp := jsonRPCMessage{
				JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"tools":[{"name":"admin_wipe","description":"wipe"}]}`),
			}
			b, _ := json.Marshal(resp)
			_, _ = w.Write([]byte("event: message\ndata: " + string(b) + "\n\n"))
		case "tools/call":
			toolName, args, _ := extractToolCallParams(msg.Params)
			mu.Lock()
			seenCallArgs = bytes.Clone(args)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if toolName == "fail_tool" {
				_ = json.NewEncoder(w).Encode(jsonRPCMessage{
					JSONRPC: "2.0", ID: msg.ID,
					Result: json.RawMessage(`{"isError":true,"content":[{"type":"text","text":"query syntax error"}]}`),
				})
				return
			}
			_ = json.NewEncoder(w).Encode(jsonRPCMessage{
				JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"content":[{"type":"text","text":"line1"},{"type":"text","text":"line2"}]}`),
			})
		}
	}))
	defer streamSrv.Close()

	legacy := newMockLegacySSEServer(t, "")

	st := newTestStore(t)
	for _, r := range store.DefaultBuiltinGuardrailRules() {
		_ = st.UpsertGuardrailRule(context.Background(), r)
	}
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "docs", URL: streamSrv.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "legacy", URL: legacy.srv.URL + "/sse", Transport: config.MCPTransportSSE,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "broken", URL: "http://127.0.0.1:1/mcp?token=topsecret", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})

	grEng, err := guardrail.NewEngine(guardrail.EngineConfig{Store: st, RetryBackoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = grEng.Close(context.Background()) }()

	gw, err := NewGateway(GatewayConfig{
		Store:         st,
		Authorizer:    policy.NewEvaluator(),
		Guardrails:    guardrailEngineAdapter{engine: grEng},
		ClientTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. DiscoverTools across Streamable HTTP pagination (JSON + SSE) & DELETE cleanup.
	docsSrv, _ := st.GetMCPServer(context.Background(), "docs")
	tools, latencyMS, err := gw.DiscoverTools(context.Background(), *docsSrv)
	if err != nil {
		t.Fatalf("DiscoverTools(docs) failed: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "search" || tools[1].Name != "admin_wipe" || latencyMS < 0 {
		t.Fatalf("unexpected DiscoverTools result: tools=%+v latency=%d", tools, latencyMS)
	}
	if seenDeleteHTTP.Load() == 0 {
		t.Fatalf("expected DiscoverTools to send DELETE session cleanup for Mcp-Session-Id")
	}

	// 2. DiscoverTools over Legacy SSE transport.
	legacySrv, _ := st.GetMCPServer(context.Background(), "legacy")
	legacyTools, _, err := gw.DiscoverTools(context.Background(), *legacySrv)
	if err != nil || len(legacyTools) != 2 {
		t.Fatalf("DiscoverTools(legacy) failed: tools=%+v err=%v", legacyTools, err)
	}

	// 3. ListAuthorizedToolsForPrincipal filters denied tools & isolates broken server error without leaking ?token=.
	alice := makePrincipal("alice@example.com", []string{"docs/*", "legacy/*", "broken/*"}, []string{"docs/admin_*", "legacy/secret_*"})
	listed, err := gw.ListAuthorizedToolsForPrincipal(context.Background(), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 {
		t.Fatalf("expected 3 enabled servers, got %d", len(listed))
	}
	byName := make(map[string]AuthorizedServerTools)
	for _, s := range listed {
		byName[s.Name] = s
	}
	if len(byName["docs"].Tools) != 1 || byName["docs"].Tools[0].Name != "search" {
		t.Fatalf("expected only [search] on docs, got %+v", byName["docs"])
	}
	if len(byName["legacy"].Tools) != 1 || byName["legacy"].Tools[0].Name != "echo" {
		t.Fatalf("expected only [echo] on legacy, got %+v", byName["legacy"])
	}
	if byName["broken"].Error == "" || strings.Contains(byName["broken"].Error, "topsecret") {
		t.Fatalf("broken server should isolate sanitized error, got %+v", byName["broken"])
	}

	// Subset filter returns only requested server(s).
	subset, err := gw.ListAuthorizedToolsForPrincipal(context.Background(), alice, []string{"docs"})
	if err != nil || len(subset) != 1 || subset[0].Name != "docs" {
		t.Fatalf("subset filter failed: %+v err=%v", subset, err)
	}

	// 4. CallAuthorizedTool: allowed + redacted args, legacy SSE call, isError=true, denied, blocked!
	awsKey := "AKIA" + "9988776655443322"
	callRes, err := gw.CallAuthorizedTool(context.Background(), alice, "docs", "search", json.RawMessage(`{"q":"`+awsKey+`"}`))
	if err != nil {
		t.Fatalf("CallAuthorizedTool(docs/search) failed: %v", err)
	}
	if callRes.Result != "line1\nline2" || callRes.IsError {
		t.Fatalf("unexpected CallAuthorizedTool result: %+v", callRes)
	}
	mu.Lock()
	if strings.Contains(string(seenCallArgs), awsKey) || !strings.Contains(string(seenCallArgs), "[REDACTED:builtin-aws-access-key]") {
		mu.Unlock()
		t.Fatalf("CallAuthorizedTool did not redact AWS key: %s", string(seenCallArgs))
	}
	mu.Unlock()

	// Legacy SSE tool call
	legRes, err := gw.CallAuthorizedTool(context.Background(), alice, "legacy", "echo", json.RawMessage(`{"msg":"hi"}`))
	if err != nil || legRes.IsError || !strings.Contains(legRes.Result, `echo:{"msg":"hi"}`) {
		t.Fatalf("CallAuthorizedTool(legacy/echo) failed: res=%+v err=%v", legRes, err)
	}

	// Tool returns isError=true
	errRes, err := gw.CallAuthorizedTool(context.Background(), alice, "docs", "fail_tool", json.RawMessage(`{}`))
	if err != nil || !errRes.IsError || errRes.Result != "query syntax error" {
		t.Fatalf("expected IsError tool result, got res=%+v err=%v", errRes, err)
	}

	// Policy denied -> ErrToolDenied (embedded secret must never land in mcp_audit_logs!)
	if _, err := gw.CallAuthorizedTool(context.Background(), alice, "docs", "admin_wipe", json.RawMessage(`{"token":"`+awsKey+`"}`)); !errors.Is(err, ErrToolDenied) {
		t.Fatalf("expected ErrToolDenied, got %v", err)
	}

	// Guardrail blocked -> ErrToolBlocked
	pem := "-----BEGIN " + "PRIVATE KEY-----\\nBLOCKED\\n-----END " + "PRIVATE KEY-----"
	if _, err := gw.CallAuthorizedTool(context.Background(), alice, "docs", "search", json.RawMessage(`{"key":"`+pem+`"}`)); !errors.Is(err, ErrToolBlocked) {
		t.Fatalf("expected ErrToolBlocked, got %v", err)
	}

	// Verify audit logs persisted for programmatic calls too.
	auditLogs, err := st.QueryMCPAuditLogs(context.Background(), store.MCPAuditFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var gotStatuses []string
	for _, l := range auditLogs {
		gotStatuses = append(gotStatuses, l.Status)
		if strings.Contains(l.ArgumentsPreview, awsKey) || strings.Contains(l.ArgumentsPreview, "BLOCKED\\n") {
			t.Fatalf("secret leaked into programmatic audit log: %+v", l)
		}
		if l.Status == AuditStatusDenied && l.ArgumentsPreview != deniedArgsPlaceholder {
			t.Fatalf("denied programmatic audit preview must be %q, got %q", deniedArgsPlaceholder, l.ArgumentsPreview)
		}
	}
	for _, want := range []string{AuditStatusOK, AuditStatusError, AuditStatusDenied, AuditStatusBlocked} {
		if !slices.Contains(gotStatuses, want) {
			t.Fatalf("missing audit status %q in %v", want, gotStatuses)
		}
	}
}

func TestMCPSSRFAndRedirectBlocking(t *testing.T) {
	// 1. Dial-control IP allow/deny matrix.
	for _, addr := range []string{
		"169.254.169.254:80",
		"169.254.0.1:443",
		"[::ffff:169.254.169.254]:80",
		"[fe80::1]:80",
		"[fd00:ec2::254]:80",
		"[fd00:ec2::254%eth0]:80",
		"0.0.0.0:80",
		"[::]:80",
		"224.0.0.1:80",
		"[ff02::1]:80",
	} {
		if err := validateDialAddr(addr, false); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("expected %s blocked, got %v", addr, err)
		}
	}
	for _, addr := range []string{
		"127.0.0.1:8080",
		"[::1]:8080",
		"100.64.0.10:8080",
		"10.0.0.5:8080",
		"1.1.1.1:443",
	} {
		if err := validateDialAddr(addr, false); err != nil {
			t.Fatalf("expected %s allowed by default, got %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "[::ffff:127.0.0.1]:8080"} {
		if err := validateDialAddr(addr, true); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("expected %s blocked when BlockLoopback=true, got %v", addr, err)
		}
	}

	// 2. Live proxy & DiscoverTools block IMDS (IPv4 & IPv6) before TCP connect AND never follow 307 redirects.
	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	st := newTestStore(t)
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "redir", URL: redirector.URL + "/mcp", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthBearer, AuthToken: "secret-mcp-token", Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "imds-v4", URL: "http://169.254.169.254/latest/meta-data/", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})
	_ = st.UpsertMCPServer(context.Background(), store.MCPServer{
		Name: "imds-v6", URL: "http://[fd00:ec2::254]/latest/meta-data/", Transport: config.MCPTransportStreamableHTTP,
		AuthType: config.MCPAuthNone, Enabled: true, Source: store.SourceLocal,
	})

	gw, err := NewGateway(GatewayConfig{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	alice := makePrincipal("alice@example.com", []string{"*"}, nil)

	// Redirect is NOT followed.
	recRedir := httptest.NewRecorder()
	gw.ServeHTTP(recRedir, authedReq(alice, http.MethodPost, "/mcp/redir", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if recRedir.Code != http.StatusTemporaryRedirect || attackerHits.Load() != 0 {
		t.Fatalf("redirect should not be followed: code=%d attackerHits=%d", recRedir.Code, attackerHits.Load())
	}

	// IMDS IPv4 & IPv6 fail immediately with 502 containing ErrBlockedAddress.
	for _, name := range []string{"imds-v4", "imds-v6"} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, authedReq(alice, http.MethodPost, "/mcp/"+name, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), ErrBlockedAddress.Error()) {
			t.Fatalf("expected 502 blocked IP for %s, got %d: %s", name, rec.Code, rec.Body.String())
		}
		srv, _ := st.GetMCPServer(context.Background(), name)
		if _, _, err := gw.DiscoverTools(context.Background(), *srv); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("DiscoverTools(%s) expected ErrBlockedAddress, got %v", name, err)
		}
	}
}
