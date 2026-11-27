package chat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/quota"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	st, err := store.NewSQLiteStore(context.Background(), ":memory:", cipher)
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func makePrincipal(subject string, allowModels, denyModels []string) *auth.Principal {
	grant := map[string]any{
		"role":        "user",
		"models":      allowModels,
		"deny_models": denyModels,
		"mcp_tools":   []string{"*"},
	}
	raw, _ := json.Marshal([]any{grant})
	return &auth.Principal{
		Subject:     subject,
		DisplayName: subject,
		NodeName:    "test-node",
		NodeIP:      "100.64.0.10",
		AuthSource:  auth.AuthSourceTSNet,
		RawCaps: map[string][]byte{
			auth.CapHeadlampGateway: raw,
		},
	}
}

type mockMCPBridge struct {
	mu      sync.Mutex
	servers []ServerTools
	calls   []struct {
		Server string
		Tool   string
		Args   string
	}
	callFn func(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error)
}

func (m *mockMCPBridge) ListAuthorizedTools(ctx context.Context, p *auth.Principal, serverNames []string) ([]ServerTools, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(serverNames) == 0 {
		return slices.Clone(m.servers), nil
	}
	var out []ServerTools
	for _, s := range m.servers {
		if slices.Contains(serverNames, s.Name) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *mockMCPBridge) CallTool(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error) {
	m.mu.Lock()
	m.calls = append(m.calls, struct {
		Server string
		Tool   string
		Args   string
	}{Server: serverName, Tool: toolName, Args: string(args)})
	fn := m.callFn
	m.mu.Unlock()

	if fn != nil {
		return fn(ctx, p, serverName, toolName, args)
	}
	return &ToolResult{Result: "ok", DurationMS: 5}, nil
}

type quotaAdapter struct {
	mgr *quota.Manager
}

func (a quotaAdapter) Acquire(ctx context.Context, p *auth.Principal) (proxy.QuotaTicket, *proxy.QuotaRejection, error) {
	tk, rej, err := a.mgr.Acquire(ctx, p)
	if err != nil || rej != nil {
		var pRej *proxy.QuotaRejection
		if rej != nil {
			pRej = &proxy.QuotaRejection{
				Scope:         rej.Scope,
				Metric:        rej.Metric,
				Reason:        rej.Reason,
				RetryAfterSec: rej.RetryAfterSec,
			}
		}
		return nil, pRej, err
	}
	return tk, nil, nil
}

func parseSSEFrames(t *testing.T, raw []byte) []translate.SSEEvent {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(raw))
	var events []translate.SSEEvent
	for {
		ev, err := translate.ReadSSEEvent(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("ReadSSEEvent error: %v", err)
		}
		events = append(events, ev)
	}
	return events
}

func TestService_ListModelsAuthAndGeminiInclusion(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	for _, p := range []store.Provider{
		{Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "https://api.openai.com", Models: []string{"gpt-4.1", "o3"}, Enabled: true},
		{Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: "https://api.anthropic.com", Models: []string{"claude-sonnet-4-6"}, Enabled: true},
		{Name: "gemini", Type: config.ProviderTypeGemini, BaseURL: "https://generativelanguage.googleapis.com", Models: []string{"gemini-2.5-flash"}, Enabled: true},
		{Name: "ollama", Type: config.ProviderTypeOllama, BaseURL: "http://127.0.0.1:11434", Models: []string{"qwen2.5-coder"}, Enabled: false},
	} {
		if err := st.UpsertProvider(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []store.ModelRoute{
		{Alias: "team/coding", ProviderName: "anthropic", UpstreamModel: "claude-sonnet-4-6", Enabled: true},
		{Alias: "team/o3-only", ProviderName: "openai", UpstreamModel: "o3", Enabled: true},
	} {
		if err := st.UpsertModelRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st, Authorizer: ev})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Store: st, Authorizer: ev, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}

	// Allow openai/*, gemini/*, team/*, but explicitly deny openai/o3 -> team/o3-only must be filtered out!
	alice := makePrincipal("alice@example.com", []string{"openai/*", "gemini/*", "team/*"}, []string{"openai/o3"})

	models, err := svc.ListModels(ctx, alice)
	if err != nil {
		t.Fatalf("ListModels failed: %v", err)
	}

	gotIDs := make([]string, len(models))
	for i, m := range models {
		gotIDs[i] = m.ID
	}
	wantIDs := []string{"gemini/gemini-2.5-flash", "openai/gpt-4.1", "team/coding"}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("ListModels IDs = %v, want %v", gotIDs, wantIDs)
	}

	// Verify ListMCPServers returns non-nil empty slice when MCPBridge is nil.
	srvs, err := svc.ListMCPServers(ctx, alice)
	if err != nil || srvs == nil || len(srvs) != 0 {
		t.Fatalf("ListMCPServers(nil bridge) = (%v, %v), want empty non-nil slice", srvs, err)
	}
}

func TestService_StrictPerUserSessionIsolation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Store: st, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}

	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-alice-1",
		Subject: "alice@example.com",
		Title:   "Private Notes",
		Model:   "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	bob := makePrincipal("bob@example.com", []string{"*"}, nil)
	rec := httptest.NewRecorder()
	err = svc.StreamMessage(ctx, rec, bob, sess.ID, SendMessageRequest{Content: "sneak peek"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected store.ErrNotFound for cross-user session access, got %v", err)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected zero bytes written on ErrNotFound, got %q", rec.Body.String())
	}
}

func TestService_OpenAIPathStreamingAndMultiRoundMCPTools(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	var upstreamRound atomic.Int32
	var receivedAuthHeader string
	var secondRoundSawToolResult atomic.Bool

	fakeOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		receivedAuthHeader = r.Header.Get("Authorization")

		var reqBody struct {
			Model    string `json:"model"`
			Messages []struct {
				Role       string `json:"role"`
				Content    any    `json:"content"`
				ToolCallID string `json:"tool_call_id"`
			} `json:"messages"`
			Tools         []map[string]any `json:"tools"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if reqBody.StreamOptions == nil || !reqBody.StreamOptions.IncludeUsage {
			http.Error(w, "missing stream_options.include_usage", http.StatusBadRequest)
			return
		}

		round := upstreamRound.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)

		if round == 1 {
			if len(reqBody.Tools) != 1 {
				http.Error(w, "expected 1 MCP tool", http.StatusBadRequest)
				return
			}
			// Round 1: stream partial text + fragmented tool call arguments + usage.
			toolName := reqBody.Tools[0]["function"].(map[string]any)["name"].(string)
			chunks := []string{
				`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":"Checking docs... "},"finish_reason":null}]}`,
				fmt.Sprintf(`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":%q,"arguments":"{\"query\":"}}]},"finish_reason":null}]}`, toolName),
				`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"headscale\"}"}}]},"finish_reason":null}]}`,
				`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4.1","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120}}`,
			}
			for _, c := range chunks {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", c)
				if flusher != nil {
					flusher.Flush()
				}
			}
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}

		// Round 2: verify tool result message was appended and stream final answer.
		for _, m := range reqBody.Messages {
			if m.Role == "tool" && m.ToolCallID == "call_1" && strings.Contains(fmt.Sprint(m.Content), "Headscale v0.29.7") {
				secondRoundSawToolResult.Store(true)
			}
		}
		chunks := []string{
			`{"id":"chatcmpl-2","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{"role":"assistant","content":"Found it: "},"finish_reason":null}]}`,
			`{"id":"chatcmpl-2","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"Headscale v0.29.7 supports grants."},"finish_reason":null}]}`,
			`{"id":"chatcmpl-2","object":"chat.completion.chunk","model":"gpt-4.1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			`{"id":"chatcmpl-2","object":"chat.completion.chunk","model":"gpt-4.1","choices":[],"usage":{"prompt_tokens":200,"completion_tokens":30,"total_tokens":230}}`,
		}
		for _, c := range chunks {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", c)
			if flusher != nil {
				flusher.Flush()
			}
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer fakeOpenAI.Close()

	if err := st.UpsertProvider(ctx, store.Provider{
		Name:    "openai",
		Type:    config.ProviderTypeOpenAI,
		BaseURL: fakeOpenAI.URL,
		APIKey:  "sk-managed-test-key",
		Models:  []string{"gpt-4.1"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st, Authorizer: ev})
	if err != nil {
		t.Fatal(err)
	}

	mcpMock := &mockMCPBridge{
		servers: []ServerTools{
			{
				Name:      "docs",
				Transport: "streamable_http",
				Enabled:   true,
				Tools: []ToolSpec{
					{
						Server:      "docs",
						Name:        "search.pages",
						Description: "Search internal docs",
						InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
					},
				},
			},
		},
		callFn: func(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error) {
			return &ToolResult{
				Result:     "Doc hit: Headscale v0.29.7 supports grants.",
				IsError:    false,
				DurationMS: 12,
			}, nil
		},
	}

	svc, err := NewService(Config{
		Store:      st,
		Authorizer: ev,
		Pricing:    pricing,
		Gateway:    gw,
		MCP:        mcpMock,
	})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"openai/*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:           "sess-openai-1",
		Subject:      alice.Subject,
		Title:        "New Chat",
		Model:        "openai/gpt-4.1",
		MCPServers:   []string{"docs"},
		SystemPrompt: "Be concise.",
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	err = svc.StreamMessage(ctx, rec, alice, sess.ID, SendMessageRequest{
		Content: "Does Headscale support grants?",
	})
	if err != nil {
		t.Fatalf("StreamMessage failed: %v", err)
	}

	// Verify request flowed through real proxy.Gateway with managed key injection!
	if receivedAuthHeader != "Bearer sk-managed-test-key" {
		t.Fatalf("upstream Authorization = %q, want managed key", receivedAuthHeader)
	}
	if !secondRoundSawToolResult.Load() {
		t.Fatal("round 2 did not receive MCP tool result message")
	}

	events := parseSSEFrames(t, rec.Body.Bytes())
	var names []string
	var deltas strings.Builder
	for _, ev := range events {
		names = append(names, ev.Event)
		if ev.Event == "delta" {
			var d struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			deltas.WriteString(d.Text)
		}
	}

	if !slices.Contains(names, "message_start") ||
		!slices.Contains(names, "tool_start") ||
		!slices.Contains(names, "tool_result") ||
		!slices.Contains(names, "message_done") {
		t.Fatalf("missing expected SSE events, got sequence: %v", names)
	}

	wantText := "Checking docs... Found it: Headscale v0.29.7 supports grants."
	if deltas.String() != wantText {
		t.Fatalf("streamed text = %q, want %q", deltas.String(), wantText)
	}

	// Verify session auto-titled from first prompt.
	updatedSess, err := st.GetChatSession(ctx, alice.Subject, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedSess.Title != "Does Headscale support grants?" {
		t.Errorf("auto-title = %q, want %q", updatedSess.Title, "Does Headscale support grants?")
	}

	// Verify persisted user + assistant ChatMessages with ToolEvents, tokens, and USD cost.
	msgs, err := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("persisted messages = %d (err=%v), want 2", len(msgs), err)
	}
	asst := msgs[1]
	if asst.Role != "assistant" || asst.Content != wantText {
		t.Errorf("assistant msg = (%q, %q), want (assistant, %q)", asst.Role, asst.Content, wantText)
	}
	if len(asst.ToolEvents) != 1 || asst.ToolEvents[0].Server != "docs" || asst.ToolEvents[0].Tool != "search.pages" {
		t.Errorf("unexpected ToolEvents: %+v", asst.ToolEvents)
	}
	if asst.InputTokens != 300 || asst.OutputTokens != 50 {
		t.Errorf("tokens = (%d in, %d out), want (300, 50)", asst.InputTokens, asst.OutputTokens)
	}
	if asst.CostUSD <= 0 {
		t.Errorf("expected positive CostUSD for gpt-4.1, got %f", asst.CostUSD)
	}
}

func TestService_PureGeminiStreamingAndFunctionCalling(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	var round atomic.Int32
	var sawFuncResponse atomic.Bool

	fakeGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1beta/models/gemini-2.5-flash:streamGenerateContent") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("x-goog-api-key") != "gem-secret-key" {
			http.Error(w, "bad key", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		curRound := round.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)

		if curRound == 1 {
			toolsList := payload["tools"].([]any)
			decls := toolsList[0].(map[string]any)["functionDeclarations"].([]any)
			fnName := decls[0].(map[string]any)["name"].(string)

			chunk := fmt.Sprintf(`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":%q,"args":{"repo":"headlamp"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":120,"candidatesTokenCount":15,"thoughtsTokenCount":10,"totalTokenCount":145}}`, fnName)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		// Round 2: confirm functionResponse arrived in contents.
		rawPayload, _ := json.Marshal(payload)
		if strings.Contains(string(rawPayload), "functionResponse") && strings.Contains(string(rawPayload), "42 open stars") {
			sawFuncResponse.Store(true)
		}
		chunk1 := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Headlamp has "}]}}]}`
		chunk2 := `{"candidates":[{"content":{"role":"model","parts":[{"text":"42 stars."}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":180,"candidatesTokenCount":25,"thoughtsTokenCount":20,"totalTokenCount":225}}`
		_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk1)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk2)
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer fakeGemini.Close()

	if err := st.UpsertProvider(ctx, store.Provider{
		Name:    "gemini",
		Type:    config.ProviderTypeGemini,
		BaseURL: fakeGemini.URL,
		APIKey:  "gem-secret-key",
		Models:  []string{"gemini-2.5-flash"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st, Authorizer: ev})
	if err != nil {
		t.Fatal(err)
	}

	mcpMock := &mockMCPBridge{
		servers: []ServerTools{
			{
				Name:    "github",
				Enabled: true,
				Tools: []ToolSpec{
					{
						Server:      "github",
						Name:        "repo_stats",
						Description: "Get repo stars",
						InputSchema: json.RawMessage(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{"repo":{"type":"string"}}}`),
					},
				},
			},
		},
		callFn: func(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error) {
			return &ToolResult{Result: "42 open stars", DurationMS: 8}, nil
		},
	}

	svc, err := NewService(Config{Store: st, Authorizer: ev, Pricing: pricing, Gateway: gw, MCP: mcpMock})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"gemini/*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:         "sess-gem-1",
		Subject:    alice.Subject,
		Model:      "gemini/gemini-2.5-flash",
		MCPServers: []string{"github"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec, alice, sess.ID, SendMessageRequest{Content: "How many stars?"}); err != nil {
		t.Fatalf("StreamMessage Gemini failed: %v", err)
	}
	if !sawFuncResponse.Load() {
		t.Fatal("Gemini round 2 did not receive functionResponse")
	}

	msgs, err := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("expected 2 persisted messages, got %d (err=%v)", len(msgs), err)
	}
	asst := msgs[1]
	if asst.Content != "Headlamp has 42 stars." {
		t.Errorf("Gemini assistant content = %q, want %q", asst.Content, "Headlamp has 42 stars.")
	}
	if len(asst.ToolEvents) != 1 || asst.ToolEvents[0].Tool != "repo_stats" {
		t.Errorf("unexpected Gemini ToolEvents: %+v", asst.ToolEvents)
	}
	// Gemini billed output includes candidatesTokenCount (15+25=40) + thoughtsTokenCount (10+20=30) = 70.
	if asst.InputTokens != 300 || asst.OutputTokens != 70 {
		t.Errorf("Gemini tokens = (%d in, %d out), want (300, 70)", asst.InputTokens, asst.OutputTokens)
	}
	if asst.CostUSD <= 0 {
		t.Errorf("expected positive Gemini CostUSD, got %f", asst.CostUSD)
	}
}

func TestService_UpstreamErrors403And429PropagateAsSSEError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertProvider(ctx, store.Provider{
		Name:    "openai",
		Type:    config.ProviderTypeOpenAI,
		BaseURL: "http://127.0.0.1:1",
		APIKey:  "sk-unused",
		Models:  []string{"gpt-4.1", "o3"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	zero := 0.0
	if err := st.UpsertBudget(ctx, store.Budget{
		Scope:    "quota-user@example.com",
		DailyUSD: &zero,
		Enabled:  true,
	}); err != nil {
		t.Fatal(err)
	}

	ev := policy.NewEvaluator()
	qMgr := quota.NewManager(st)
	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: ev,
		Quota:      quotaAdapter{mgr: qMgr},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Store: st, Authorizer: ev, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("403 policy deny emits SSE error", func(t *testing.T) {
		p := makePrincipal("restricted@example.com", []string{"openai/gpt-4.1"}, []string{"openai/o3"})
		sess, err := st.CreateChatSession(ctx, store.ChatSession{
			ID: "sess-403", Subject: p.Subject, Model: "openai/o3",
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := svc.StreamMessage(ctx, rec, p, sess.ID, SendMessageRequest{Content: "hi"}); err != nil {
			t.Fatalf("unexpected error return after SSE headers: %v", err)
		}
		events := parseSSEFrames(t, rec.Body.Bytes())
		foundErr := false
		for _, e := range events {
			if e.Event == "error" {
				foundErr = true
				var body struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				}
				_ = json.Unmarshal(e.Data, &body)
				if body.Type == "" || body.Message == "" {
					t.Errorf("empty SSE error payload: %s", string(e.Data))
				}
			}
		}
		if !foundErr {
			t.Fatalf("expected SSE error event on 403, got %v", events)
		}
		msgs, _ := st.ListChatMessages(ctx, p.Subject, sess.ID)
		if len(msgs) != 1 { // only user message persisted, no empty assistant message
			t.Fatalf("expected 1 persisted message on 403 error, got %d", len(msgs))
		}
	})

	t.Run("429 quota exceeded emits SSE error", func(t *testing.T) {
		p := makePrincipal("quota-user@example.com", []string{"openai/*"}, nil)
		sess, err := st.CreateChatSession(ctx, store.ChatSession{
			ID: "sess-429", Subject: p.Subject, Model: "openai/gpt-4.1",
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := svc.StreamMessage(ctx, rec, p, sess.ID, SendMessageRequest{Content: "hi"}); err != nil {
			t.Fatalf("unexpected error return after SSE headers: %v", err)
		}
		events := parseSSEFrames(t, rec.Body.Bytes())
		foundErr := false
		for _, e := range events {
			if e.Event == "error" && strings.Contains(string(e.Data), "daily budget") {
				foundErr = true
			}
		}
		if !foundErr {
			t.Fatalf("expected SSE error mentioning daily budget on 429, got body=%s", rec.Body.String())
		}
	})
}

func TestService_ContextCancelStopButtonGracefulAbort(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	firstChunkSent := make(chan struct{})
	releaseUpstream := make(chan struct{})
	defer close(releaseUpstream)

	slowOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-slow\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Partial answer\"},\"finish_reason\":null}]}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-firstChunkSent:
		default:
			close(firstChunkSent)
		}
		select {
		case <-r.Context().Done():
		case <-releaseUpstream:
		}
	}))
	defer slowOpenAI.Close()

	if err := st.UpsertProvider(ctx, store.Provider{
		Name:    "openai",
		Type:    config.ProviderTypeOpenAI,
		BaseURL: slowOpenAI.URL,
		APIKey:  "sk-key",
		Models:  []string{"gpt-4.1"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st, Authorizer: ev})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{Store: st, Authorizer: ev, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"openai/*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID: "sess-cancel", Subject: alice.Subject, Model: "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancel as soon as the first delta chunk is written to the downstream response writer.
	deltaSeen := make(chan struct{})
	var deltaOnce sync.Once
	rec := &callbackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		onWrite: func(p []byte) {
			if bytes.Contains(p, []byte("Partial answer")) {
				deltaOnce.Do(func() {
					close(deltaSeen)
					cancel()
				})
			}
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- svc.StreamMessage(reqCtx, rec, alice, sess.ID, SendMessageRequest{Content: "write a novel"})
	}()

	select {
	case <-deltaSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for first delta")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil on graceful cancel, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StreamMessage hung after ctx cancel")
	}

	// Partial assistant output MUST still be persisted even though reqCtx was canceled.
	msgs, err := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("expected 2 persisted messages (user + partial assistant), got %d (err=%v)", len(msgs), err)
	}
	if msgs[1].Content != "Partial answer" {
		t.Errorf("persisted partial content = %q, want %q", msgs[1].Content, "Partial answer")
	}
}

type callbackResponseWriter struct {
	*httptest.ResponseRecorder
	onWrite func([]byte)
}

func (w *callbackResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	if w.onWrite != nil {
		w.onWrite(p)
	}
	return n, err
}

func (w *callbackResponseWriter) Flush() {
	w.ResponseRecorder.Flush()
}
