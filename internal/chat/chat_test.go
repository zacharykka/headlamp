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
	"github.com/zacharykka/headlamp/internal/guardrail"
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
		if _, canDelete := any(st).(messageDeleter); canDelete {
			if len(msgs) != 0 {
				t.Fatalf("expected orphan user message rolled back on 403 error, got %d messages", len(msgs))
			}
		} else if len(msgs) != 1 {
			t.Fatalf("expected 1 persisted message on 403 error without deleter, got %d", len(msgs))
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

type stubGuardrailInspector struct {
	fn func(ctx context.Context, text string) (action, redacted, reason string, err error)
}

func (s stubGuardrailInspector) InspectText(ctx context.Context, text string) (string, string, string, error) {
	return s.fn(ctx, text)
}

// rollbackTestStore wraps a store.Store and provides in-memory filtered DeleteChatMessage
// tracking so Round-0 rollback tests work deterministically regardless of backing store.
type rollbackTestStore struct {
	store.Store
	mu      sync.Mutex
	deleted map[string]bool
}

func newRollbackTestStore(inner store.Store) *rollbackTestStore {
	return &rollbackTestStore{
		Store:   inner,
		deleted: make(map[string]bool),
	}
}

func (w *rollbackTestStore) DeleteChatMessage(ctx context.Context, subject, sessionID, messageID string) error {
	w.mu.Lock()
	w.deleted[messageID] = true
	w.mu.Unlock()
	if del, ok := w.Store.(messageDeleter); ok {
		return del.DeleteChatMessage(ctx, subject, sessionID, messageID)
	}
	return nil
}

func (w *rollbackTestStore) ListChatMessages(ctx context.Context, subject, sessionID string) ([]store.ChatMessage, error) {
	msgs, err := w.Store.ListChatMessages(ctx, subject, sessionID)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]store.ChatMessage, 0, len(msgs))
	for _, m := range msgs {
		if !w.deleted[m.ID] {
			out = append(out, m)
		}
	}
	return out, nil
}

func TestService_GuardrailPreCheckBlockRedactAndRound0Rollback(t *testing.T) {
	ctx := context.Background()
	baseStore := newTestStore(t)
	st := newRollbackTestStore(baseStore)

	var gatewayCalls atomic.Int32
	var lastGatewayBody atomic.Value
	var forceStatus atomic.Int32

	mockGateway := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayCalls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		lastGatewayBody.Store(string(raw))

		if code := int(forceStatus.Load()); code != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = fmt.Fprintf(w, `{"error":{"type":"webhook_blocked","message":"blocked by sync_review"}}`)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"cmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Safe reply\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})

	inspector := stubGuardrailInspector{
		fn: func(ctx context.Context, text string) (string, string, string, error) {
			if strings.Contains(text, "BLOCK_SECRET") {
				return "block", "", "detected prohibited API key", nil
			}
			if strings.Contains(text, "REDACT_PII") {
				return "redact", strings.ReplaceAll(text, "REDACT_PII", "[REDACTED]"), "", nil
			}
			return "allow", text, "", nil
		},
	}

	svc, err := NewService(Config{
		Store:      st,
		Gateway:    mockGateway,
		Guardrails: inspector,
	})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-guard-1",
		Subject: alice.Subject,
		Title:   "New Chat",
		Model:   "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Blocked message must NOT persist to chat_messages, must NOT pollute session title,
	// and even if a custom test gateway returns 200 without guardrails, defense-in-depth still
	// discards the stream and emits guardrail_blocked SSE error.
	rec1 := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec1, alice, sess.ID, SendMessageRequest{Content: "My key is BLOCK_SECRET"}); err != nil {
		t.Fatalf("StreamMessage(block) returned error: %v", err)
	}
	if gatewayCalls.Load() != 1 {
		t.Fatalf("expected Round-0 gateway dispatch for guardrail telemetry/webhook, got %d calls", gatewayCalls.Load())
	}
	events1 := parseSSEFrames(t, rec1.Body.Bytes())
	if len(events1) != 1 || events1[0].Event != "error" || !strings.Contains(string(events1[0].Data), "detected prohibited API key") {
		t.Fatalf("expected single guardrail SSE error event, got %+v", events1)
	}
	msgs, _ := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if len(msgs) != 0 {
		t.Fatalf("blocked user message must not be persisted, got %d messages", len(msgs))
	}
	sessAfterBlock, _ := st.GetChatSession(ctx, alice.Subject, sess.ID)
	if sessAfterBlock.Title != "New Chat" {
		t.Fatalf("session title must not be derived from blocked secret, got %q", sessAfterBlock.Title)
	}

	// 2. Round-0 gateway block (e.g. 403 from sync_review webhook) must roll back orphaned user message.
	forceStatus.Store(http.StatusForbidden)
	rec2 := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec2, alice, sess.ID, SendMessageRequest{Content: "trigger webhook block"}); err != nil {
		t.Fatalf("StreamMessage(403) returned error: %v", err)
	}
	msgs, _ = st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if len(msgs) != 0 {
		t.Fatalf("Round-0 403 must roll back orphaned user message, got %d messages", len(msgs))
	}
	events2 := parseSSEFrames(t, rec2.Body.Bytes())
	foundErr := false
	for _, ev := range events2 {
		if ev.Event == "error" && strings.Contains(string(ev.Data), "blocked by sync_review") {
			foundErr = true
		}
	}
	if !foundErr {
		t.Fatalf("expected SSE error from sync_review block, got %+v", events2)
	}

	// 3. Redacted message persists redacted text in chat_messages and session.Title, while
	// Round 0 dispatches raw text to proxy.Gateway so guardrail.Engine logs & fires webhooks once.
	forceStatus.Store(0)
	// Reset title to verify auto-title uses redacted text.
	sess.Title = "New Chat"
	_, _ = st.UpdateChatSession(ctx, alice.Subject, *sess)

	rec3 := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec3, alice, sess.ID, SendMessageRequest{Content: "Help with REDACT_PII please"}); err != nil {
		t.Fatalf("StreamMessage(redact) returned error: %v", err)
	}
	msgs, _ = st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 persisted messages after redacted turn, got %d", len(msgs))
	}
	if msgs[0].Content != "Help with [REDACTED] please" {
		t.Errorf("persisted user content = %q, want redacted content", msgs[0].Content)
	}
	if !strings.Contains(lastGatewayBody.Load().(string), "REDACT_PII") {
		t.Errorf("expected Round 0 to pass raw user text into proxy.Gateway for guardrail telemetry/webhook, got: %s", lastGatewayBody.Load().(string))
	}
	sessAfterRedact, _ := st.GetChatSession(ctx, alice.Subject, sess.ID)
	if strings.Contains(sessAfterRedact.Title, "REDACT_PII") {
		t.Errorf("session title leaked unredacted secret: %q", sessAfterRedact.Title)
	}
}

type realTelemetryAdapter struct {
	recorder *metering.Recorder
}

func (a realTelemetryAdapter) Start(ctx context.Context, info proxy.TelemetryStart) proxy.StreamObserver {
	obs := a.recorder.Start(ctx, metering.RequestInfo{
		RequestID:       info.RequestID,
		Timestamp:       info.Timestamp,
		Principal:       info.Principal,
		Protocol:        info.Protocol,
		Endpoint:        info.Endpoint,
		Provider:        info.Provider,
		ProviderType:    info.ProviderType,
		RequestedModel:  info.RequestedModel,
		UpstreamModel:   info.UpstreamModel,
		Stream:          info.Stream,
		Translated:      info.Translated,
		RequestBody:     info.RequestBody,
		GuardrailAction: info.GuardrailAction,
		GuardrailHits:   info.GuardrailHits,
	})
	return realObserverAdapter{obs: obs, protocol: info.Protocol}
}

type realObserverAdapter struct {
	obs      *metering.RequestObserver
	protocol string
}

func (o realObserverAdapter) OnSSEEvent(eventName string, data []byte) {
	o.obs.OnSSEEvent(eventName, data)
}
func (o realObserverAdapter) OnJSONResponse(body []byte) { o.obs.OnJSONResponse(body) }
func (o realObserverAdapter) SetResponseHeaders(h map[string]string) {
	o.obs.SetResponseHeaders(h)
}
func (o realObserverAdapter) TotalTokens() int64 { return o.obs.Usage().NormalizedTotal(o.protocol) }
func (o realObserverAdapter) Finish(fin proxy.TelemetryFinish) {
	o.obs.Finish(fin.StatusCode, fin.LatencyMS, fin.TTFTMS, fin.ErrorMessage)
}

type realProxyGuardrailAdapter struct {
	engine *guardrail.Engine
}

func (a realProxyGuardrailAdapter) Inspect(ctx context.Context, req proxy.GuardrailRequest) (*proxy.GuardrailDecision, error) {
	in := guardrail.InspectInput{
		RequestID: req.RequestID,
		Protocol:  req.Protocol,
		Model:     req.Model,
		Body:      req.Body,
	}
	if req.Principal != nil {
		in.Subject = req.Principal.Subject
		in.NodeName = req.Principal.NodeName
	}
	dec, err := a.engine.InspectRequest(ctx, in)
	if err != nil || dec == nil {
		return nil, err
	}
	return &proxy.GuardrailDecision{
		Action:       dec.Action,
		ModifiedBody: dec.ModifiedBody,
		Hits:         dec.Hits,
		Reason:       dec.Reason,
		StatusCode:   dec.StatusCode,
	}, nil
}

type realChatGuardrailAdapter struct {
	engine *guardrail.Engine
}

func (a realChatGuardrailAdapter) InspectText(ctx context.Context, text string) (action, redacted, reason string, err error) {
	res, err := a.engine.TestText(ctx, text)
	if err != nil || res == nil {
		return "", text, "", err
	}
	if res.Action == guardrail.ActionBlock {
		var blocked []string
		for _, m := range res.Matches {
			if m.Action == guardrail.ActionBlock && m.RuleName != "" {
				blocked = append(blocked, m.RuleName)
			}
		}
		if len(blocked) > 0 {
			reason = "blocked by guardrail rule: " + strings.Join(blocked, ", ")
		} else {
			reason = "blocked by guardrail policy"
		}
	}
	return res.Action, res.RedactedText, reason, nil
}

func TestService_GuardrailRealEngineBlockAndRedactTelemetryAndWebhook(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.SetAuditSettings(ctx, store.AuditSettings{
		StorePayloads: true,
		RetentionDays: 7,
	}); err != nil {
		t.Fatal(err)
	}

	// Capture guardrail.triggered async webhook deliveries.
	type webhookEvent struct {
		Event string         `json:"event"`
		Data  map[string]any `json:"data"`
	}
	var (
		whMu     sync.Mutex
		whEvents []webhookEvent
		whSignal = make(chan struct{}, 16)
	)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env webhookEvent
		if err := json.NewDecoder(r.Body).Decode(&env); err == nil {
			whMu.Lock()
			whEvents = append(whEvents, env)
			whMu.Unlock()
			select {
			case whSignal <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	if err := st.UpsertWebhook(ctx, store.Webhook{
		ID:        "wh-guardrail",
		Name:      "Guardrail Alert",
		URL:       webhookSrv.URL,
		Type:      config.WebhookTypeAsyncEvent,
		Events:    []string{config.WebhookEventGuardrailTriggered},
		TimeoutMS: 2000,
		Enabled:   true,
	}); err != nil {
		t.Fatal(err)
	}

	// Configure explicit block and redact rules.
	for _, rule := range []store.GuardrailRule{
		{
			ID:       "rule-block-token",
			Name:     "Block Secret Token",
			Category: "secret",
			Pattern:  `SUPERSECRET_[A-Z0-9]{8}`,
			Action:   guardrail.ActionBlock,
			Enabled:  true,
		},
		{
			ID:       "rule-redact-pii",
			Name:     "Redact Internal ID",
			Category: "pii",
			Pattern:  `EMP-[0-9]{6}`,
			Action:   guardrail.ActionRedact,
			Enabled:  true,
		},
	} {
		if err := st.UpsertGuardrailRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}

	// Fake upstream OpenAI (supports 2-round tool call to verify Round 1+ doesn't double-fire webhooks)
	// and fake upstream Gemini.
	var (
		upstreamMu         sync.Mutex
		openAIBodies       []string
		geminiBodies       []string
		openAIRoundCounter atomic.Int32
	)
	fakeOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		openAIBodies = append(openAIBodies, string(raw))
		upstreamMu.Unlock()

		var req struct {
			Tools []map[string]any `json:"tools"`
		}
		_ = json.Unmarshal(raw, &req)

		w.Header().Set("Content-Type", "text/event-stream")
		round := openAIRoundCounter.Add(1)
		if round == 1 && len(req.Tools) > 0 {
			fnName := req.Tools[0]["function"].(map[string]any)["name"].(string)
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"cmpl-r1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_gr1\",\"type\":\"function\",\"function\":{\"name\":%q,\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":10,\"total_tokens\":30}}\n\n", fnName)
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"cmpl-r2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Redacted turn succeeded.\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":10,\"total_tokens\":40}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer fakeOpenAI.Close()

	fakeGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		geminiBodies = append(geminiBodies, string(raw))
		upstreamMu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini redacted reply.\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":25,\"candidatesTokenCount\":8,\"totalTokenCount\":33}}\n\n")
	}))
	defer fakeGemini.Close()

	for _, prov := range []store.Provider{
		{Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: fakeOpenAI.URL, APIKey: "sk-test", Models: []string{"gpt-4.1"}, Enabled: true},
		{Name: "gemini", Type: config.ProviderTypeGemini, BaseURL: fakeGemini.URL, APIKey: "gem-test", Models: []string{"gemini-2.5-flash"}, Enabled: true},
	} {
		if err := st.UpsertProvider(ctx, prov); err != nil {
			t.Fatal(err)
		}
	}

	grEngine, err := guardrail.NewEngine(guardrail.EngineConfig{
		Store:         st,
		BlockLoopback: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = grEngine.Close(context.Background()) }()

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	recorder := metering.NewRecorder(st, config.AuditConfig{
		StorePayloads: true,
		RetentionDays: 7,
	}, pricing)
	defer func() { _ = recorder.Close(context.Background()) }()

	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: ev,
		Telemetry:  realTelemetryAdapter{recorder: recorder},
		Guardrails: realProxyGuardrailAdapter{engine: grEngine},
		Events:     grEngine,
	})
	if err != nil {
		t.Fatal(err)
	}

	mcpMock := &mockMCPBridge{
		servers: []ServerTools{{
			Name:    "hr",
			Enabled: true,
			Tools: []ToolSpec{{
				Server:      "hr",
				Name:        "lookup",
				Description: "Lookup directory",
				InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			}},
		}},
	}

	svc, err := NewService(Config{
		Store:      st,
		Authorizer: ev,
		Gateway:    gw,
		MCP:        mcpMock,
		Guardrails: realChatGuardrailAdapter{engine: grEngine},
	})
	if err != nil {
		t.Fatal(err)
	}

	waitForWebhooks := func(wantCount int) []webhookEvent {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			whMu.Lock()
			got := len(whEvents)
			snap := slices.Clone(whEvents)
			whMu.Unlock()
			if got >= wantCount {
				return snap
			}
			select {
			case <-whSignal:
			case <-deadline:
				t.Fatalf("timed out waiting for %d webhook events, got %d: %+v", wantCount, got, snap)
			}
		}
	}

	alice := makePrincipal("alice@example.com", []string{"*"}, nil)

	// --- Case 1: BLOCK on OpenAI path ---
	blockSess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-gr-block",
		Subject: alice.Subject,
		Title:   "New Chat",
		Model:   "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	recBlock := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, recBlock, alice, blockSess.ID, SendMessageRequest{
		Content: "Leak SUPERSECRET_ABCD1234 please",
	}); err != nil {
		t.Fatalf("StreamMessage(block) failed: %v", err)
	}

	// Verify SSE error event has type guardrail_blocked and no message_start.
	blockEvents := parseSSEFrames(t, recBlock.Body.Bytes())
	if len(blockEvents) != 1 || blockEvents[0].Event != "error" || !strings.Contains(string(blockEvents[0].Data), `"type":"guardrail_blocked"`) {
		t.Fatalf("expected single guardrail_blocked SSE error, got %+v", blockEvents)
	}

	// Zero rows in chat_messages, session title untouched, zero calls to upstream OpenAI.
	if msgs, _ := st.ListChatMessages(ctx, alice.Subject, blockSess.ID); len(msgs) != 0 {
		t.Fatalf("expected 0 chat_messages on block, got %d", len(msgs))
	}
	if sAfter, _ := st.GetChatSession(ctx, alice.Subject, blockSess.ID); sAfter.Title != "New Chat" {
		t.Fatalf("session title mutated on block: %q", sAfter.Title)
	}
	upstreamMu.Lock()
	if len(openAIBodies) != 0 {
		t.Fatalf("blocked prompt reached upstream LLM! calls=%d", len(openAIBodies))
	}
	upstreamMu.Unlock()

	waitForUsageLogs := func(wantCount int) []store.UsageLog {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: alice.Subject, GuardrailOnly: true})
			if err == nil && len(logs) >= wantCount {
				return logs
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %d guardrail usage_logs, got %d (err=%v)", wantCount, len(logs), err)
			}
			time.Sleep(15 * time.Millisecond)
		}
	}

	// Webhook fired ONCE with action=block, usage_logs recorded block + hits, audit_payloads stored scrubbed stub.
	whAfterBlock := waitForWebhooks(1)
	if len(whAfterBlock) != 1 || whAfterBlock[0].Event != config.WebhookEventGuardrailTriggered || whAfterBlock[0].Data["action"] != guardrail.ActionBlock {
		t.Fatalf("unexpected webhook after block: %+v", whAfterBlock)
	}
	usageLogs := waitForUsageLogs(1)
	if len(usageLogs) != 1 {
		t.Fatalf("expected 1 guardrail usage_log after block, got %d", len(usageLogs))
	}
	if usageLogs[0].GuardrailAction != guardrail.ActionBlock || !slices.Contains(usageLogs[0].GuardrailHits, "rule-block-token") {
		t.Errorf("unexpected block usage_log: action=%q hits=%v", usageLogs[0].GuardrailAction, usageLogs[0].GuardrailHits)
	}
	auditPayload, err := st.GetAuditPayloadByUsageLogID(ctx, usageLogs[0].ID)
	if err != nil || auditPayload == nil || auditPayload.RequestBody != "[BLOCKED BY GUARDRAIL]" {
		t.Fatalf("expected [BLOCKED BY GUARDRAIL] audit payload stub, got %+v (err=%v)", auditPayload, err)
	}

	// --- Case 2: REDACT on OpenAI path with 2-round MCP tool call ---
	redactSess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:         "sess-gr-redact",
		Subject:    alice.Subject,
		Title:      "New Chat",
		Model:      "openai/gpt-4.1",
		MCPServers: []string{"hr"},
	})
	if err != nil {
		t.Fatal(err)
	}
	recRedact := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, recRedact, alice, redactSess.ID, SendMessageRequest{
		Content: "Check employee EMP-123456 status",
	}); err != nil {
		t.Fatalf("StreamMessage(redact) failed: %v", err)
	}

	// Persisted user message & session title must be redacted (no raw EMP-123456).
	redactMsgs, err := st.ListChatMessages(ctx, alice.Subject, redactSess.ID)
	if err != nil || len(redactMsgs) != 2 {
		t.Fatalf("expected 2 chat_messages on redact turn, got %d (err=%v)", len(redactMsgs), err)
	}
	if strings.Contains(redactMsgs[0].Content, "EMP-123456") || !strings.Contains(redactMsgs[0].Content, "[REDACTED:") {
		t.Errorf("persisted user message not redacted: %q", redactMsgs[0].Content)
	}
	if sAfter, _ := st.GetChatSession(ctx, alice.Subject, redactSess.ID); strings.Contains(sAfter.Title, "EMP-123456") {
		t.Errorf("session title leaked raw secret: %q", sAfter.Title)
	}

	// Upstream OpenAI saw 2 rounds (tool call + final synthesis) and NEVER saw raw EMP-123456.
	upstreamMu.Lock()
	if len(openAIBodies) != 2 {
		t.Fatalf("expected 2 upstream OpenAI rounds, got %d", len(openAIBodies))
	}
	for i, body := range openAIBodies {
		if strings.Contains(body, "EMP-123456") {
			t.Fatalf("upstream OpenAI round %d leaked raw secret: %s", i, body)
		}
		if !strings.Contains(body, "[REDACTED:") {
			t.Fatalf("upstream OpenAI round %d missing redacted marker: %s", i, body)
		}
	}
	upstreamMu.Unlock()

	// Webhook fired ONLY ONCE for the 2-round redacted turn (total webhooks == 2: 1 block + 1 redact).
	whAfterRedact := waitForWebhooks(2)
	// Brief wait to ensure Round 1 did not emit a duplicate webhook.
	time.Sleep(50 * time.Millisecond)
	whMu.Lock()
	totalWH := len(whEvents)
	whMu.Unlock()
	if totalWH != 2 || whAfterRedact[1].Data["action"] != guardrail.ActionRedact {
		t.Fatalf("expected exactly 2 total webhooks (1 block, 1 redact), got %d: %+v", totalWH, whAfterRedact)
	}

	usageLogs = waitForUsageLogs(2)
	if len(usageLogs) != 2 {
		t.Fatalf("expected 2 guardrail usage_logs (1 block + 1 redact), got %d", len(usageLogs))
	}
	foundRedactUsage := false
	for _, u := range usageLogs {
		if u.GuardrailAction == guardrail.ActionRedact && slices.Contains(u.GuardrailHits, "rule-redact-pii") {
			foundRedactUsage = true
		}
	}
	if !foundRedactUsage {
		t.Fatalf("missing redact usage_log with hit rule-redact-pii: %+v", usageLogs)
	}

	// --- Case 3: BLOCK + REDACT on pure Gemini path ---
	gemSess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-gr-gemini",
		Subject: alice.Subject,
		Title:   "New Chat",
		Model:   "gemini/gemini-2.5-flash",
	})
	if err != nil {
		t.Fatal(err)
	}

	recGemBlock := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, recGemBlock, alice, gemSess.ID, SendMessageRequest{
		Content: "Gemini SUPERSECRET_WXYZ9876",
	}); err != nil {
		t.Fatalf("StreamMessage(gemini block) failed: %v", err)
	}
	gemBlockEvents := parseSSEFrames(t, recGemBlock.Body.Bytes())
	if len(gemBlockEvents) != 1 || gemBlockEvents[0].Event != "error" || !strings.Contains(string(gemBlockEvents[0].Data), `"type":"guardrail_blocked"`) {
		t.Fatalf("expected single guardrail_blocked SSE error on Gemini block, got %+v", gemBlockEvents)
	}
	upstreamMu.Lock()
	if len(geminiBodies) != 0 {
		t.Fatalf("blocked Gemini prompt reached upstream! calls=%d", len(geminiBodies))
	}
	upstreamMu.Unlock()
	if msgs, _ := st.ListChatMessages(ctx, alice.Subject, gemSess.ID); len(msgs) != 0 {
		t.Fatalf("expected 0 chat_messages after Gemini block, got %d", len(msgs))
	}

	recGemRedact := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, recGemRedact, alice, gemSess.ID, SendMessageRequest{
		Content: "Gemini lookup EMP-654321",
	}); err != nil {
		t.Fatalf("StreamMessage(gemini redact) failed: %v", err)
	}
	upstreamMu.Lock()
	if len(geminiBodies) != 1 || strings.Contains(geminiBodies[0], "EMP-654321") || !strings.Contains(geminiBodies[0], "[REDACTED:") {
		t.Fatalf("unexpected upstream Gemini body on redact: %+v", geminiBodies)
	}
	upstreamMu.Unlock()

	waitForWebhooks(4) // 1 OpenAI block + 1 OpenAI redact + 1 Gemini block + 1 Gemini redact
	usageLogs = waitForUsageLogs(4)
	if len(usageLogs) != 4 {
		t.Fatalf("expected 4 guardrail usage_logs total across OpenAI + Gemini, got %d", len(usageLogs))
	}
}

func TestBuildGeminiContents_MergesConsecutiveSameRoleTurns(t *testing.T) {
	history := []store.ChatMessage{
		{Role: "user", Content: "first attempt"},
		{Role: "assistant", Content: ""}, // empty assistant turn skipped -> adjacent users!
		{Role: "user", Content: "second attempt"},
		{Role: "assistant", Content: "reply part 1"},
		{Role: "assistant", Content: "reply part 2"},
	}

	contents := buildGeminiContents(history, "third prompt")
	if len(contents) != 3 {
		t.Fatalf("expected 3 alternating Gemini turns, got %d: %+v", len(contents), contents)
	}
	if contents[0].Role != "user" || len(contents[0].Parts) != 2 ||
		contents[0].Parts[0].Text != "first attempt" || contents[0].Parts[1].Text != "second attempt" {
		t.Errorf("turn 0 mismatch: %+v", contents[0])
	}
	if contents[1].Role != "model" || len(contents[1].Parts) != 2 ||
		contents[1].Parts[0].Text != "reply part 1" || contents[1].Parts[1].Text != "reply part 2" {
		t.Errorf("turn 1 mismatch: %+v", contents[1])
	}
	if contents[2].Role != "user" || len(contents[2].Parts) != 1 || contents[2].Parts[0].Text != "third prompt" {
		t.Errorf("turn 2 mismatch: %+v", contents[2])
	}

	// Trailing orphaned user message in history merges with the new userPrompt.
	orphanHistory := []store.ChatMessage{
		{Role: "user", Content: "orphaned user message"},
	}
	merged := buildGeminiContents(orphanHistory, "retry message")
	if len(merged) != 1 || merged[0].Role != "user" || len(merged[0].Parts) != 2 {
		t.Fatalf("expected trailing orphan user merged with new prompt, got %+v", merged)
	}
}

func TestSanitizeGeminiSchema_PropertiesPreservedAndRefInlining(t *testing.T) {
	raw := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"$defs": {
			"Repo": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"owner": {"type": "string", "default": "acme"},
					"default": {"type": "boolean", "default": true}
				},
				"required": ["owner", "default"]
			},
			"CycleNode": {
				"type": "object",
				"properties": {
					"name": {"type": "string"},
					"child": {"$ref": "#/$defs/CycleNode"}
				}
			}
		},
		"definitions": {
			"Mode": {"type": "string", "enum": ["fast", "deep"]}
		},
		"properties": {
			"default": {"type": "string", "default": "main", "description": "Default branch"},
			"definitions": {"type": "array", "items": {"type": "string"}},
			"primary": {"$ref": "#/$defs/Repo", "description": "Primary repo"},
			"secondary": {"$ref": "#/$defs/Repo"},
			"mode": {"$ref": "#/definitions/Mode"},
			"tree": {"$ref": "#/$defs/CycleNode"},
			"dangling": {"$ref": "#/$defs/DoesNotExist"}
		},
		"required": ["default", "definitions", "primary"]
	}`)

	cleanedAny := sanitizeGeminiSchema(raw)
	cleaned, ok := cleanedAny.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", cleanedAny)
	}

	// Verify unsupported schema keywords stripped at root.
	for _, forbidden := range []string{"$schema", "additionalProperties", "$defs", "definitions"} {
		if _, exists := cleaned[forbidden]; exists {
			t.Errorf("forbidden keyword %q remained at root schema", forbidden)
		}
	}

	// Verify no "$ref" remains anywhere in serialized output.
	encoded, err := json.Marshal(cleaned)
	if err != nil {
		t.Fatalf("marshal cleaned schema: %v", err)
	}
	if strings.Contains(string(encoded), `"$ref"`) {
		t.Fatalf("dangling $ref remained in cleaned schema: %s", string(encoded))
	}

	props := cleaned["properties"].(map[string]any)

	// Parameter named "default" MUST remain in properties, while its inner schema keyword "default":"main" is stripped.
	defaultProp, ok := props["default"].(map[string]any)
	if !ok {
		t.Fatalf("property named \"default\" was wrongly stripped! props=%v", props)
	}
	if defaultProp["type"] != "string" || defaultProp["description"] != "Default branch" {
		t.Errorf("unexpected default property schema: %v", defaultProp)
	}
	if _, hasDefaultKeyword := defaultProp["default"]; hasDefaultKeyword {
		t.Errorf("inner schema keyword \"default\" should have been stripped: %v", defaultProp)
	}

	// Parameter named "definitions" MUST remain in properties.
	if _, ok := props["definitions"].(map[string]any); !ok {
		t.Fatalf("property named \"definitions\" was wrongly stripped! props=%v", props)
	}

	// Both shared $ref usages ("primary" and "secondary") must be fully inlined (DAG, not treated as cycle).
	for _, field := range []string{"primary", "secondary"} {
		repoObj, ok := props[field].(map[string]any)
		if !ok || repoObj["type"] != "object" {
			t.Fatalf("%s $ref was not inlined into object schema: %v", field, props[field])
		}
		repoProps := repoObj["properties"].(map[string]any)
		if _, hasDefault := repoProps["default"]; !hasDefault {
			t.Errorf("%s inlined repo lost property named \"default\": %v", field, repoProps)
		}
	}
	if props["primary"].(map[string]any)["description"] != "Primary repo" {
		t.Errorf("sibling description alongside $ref was not preserved: %v", props["primary"])
	}

	// #/definitions/Mode inlined.
	modeObj := props["mode"].(map[string]any)
	if modeObj["type"] != "string" || len(modeObj["enum"].([]any)) != 2 {
		t.Errorf("mode #/definitions/Mode was not inlined: %v", modeObj)
	}

	// Cyclic $ref terminated safely with {"type":"string"}.
	treeObj := props["tree"].(map[string]any)
	treeChild := treeObj["properties"].(map[string]any)["child"].(map[string]any)
	if treeChild["type"] != "string" {
		t.Errorf("cyclic $ref fallback = %v, want type=string", treeChild)
	}

	// Unresolvable $ref fell back safely to {"type":"string"}.
	danglingObj := props["dangling"].(map[string]any)
	if danglingObj["type"] != "string" {
		t.Errorf("unresolvable $ref fallback = %v, want type=string", danglingObj)
	}
}

func TestService_GeminiPreservesThoughtAndThoughtSignatureAcrossToolRounds(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	var round atomic.Int32
	var round2Contents []geminiContent

	fakeGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Contents []geminiContent `json:"contents"`
			Tools    []map[string]any `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		cur := round.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		if cur == 1 {
			decls := payload.Tools[0]["functionDeclarations"].([]any)
			fnName := decls[0].(map[string]any)["name"].(string)
			// Gemini 2.5/3 thinking turn: thought part + thoughtSignature + functionCall with thoughtSignature.
			chunk := fmt.Sprintf(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Internal reasoning...","thought":true,"thoughtSignature":"sig_thought_abc"},{"functionCall":{"name":%q,"args":{"default":"main"}},"thoughtSignature":"sig_fc_xyz"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":10,"thoughtsTokenCount":25,"totalTokenCount":135}}`, fnName)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
			return
		}

		round2Contents = payload.Contents
		chunk := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Branch main is healthy."}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":140,"candidatesTokenCount":12,"totalTokenCount":152}}`
		_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
	}))
	defer fakeGemini.Close()

	if err := st.UpsertProvider(ctx, store.Provider{
		Name:    "gemini",
		Type:    config.ProviderTypeGemini,
		BaseURL: fakeGemini.URL,
		APIKey:  "gem-key",
		Models:  []string{"gemini-2.5-pro"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	ev := policy.NewEvaluator()
	gw, err := proxy.NewGateway(proxy.GatewayConfig{Store: st, Authorizer: ev})
	if err != nil {
		t.Fatal(err)
	}
	mcpMock := &mockMCPBridge{
		servers: []ServerTools{{
			Name:    "git",
			Enabled: true,
			Tools: []ToolSpec{{
				Server:      "git",
				Name:        "branch_status",
				Description: "Check branch status",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"default":{"type":"string"}},"required":["default"]}`),
			}},
		}},
		callFn: func(ctx context.Context, p *auth.Principal, serverName, toolName string, args json.RawMessage) (*ToolResult, error) {
			return &ToolResult{Result: "ok", DurationMS: 3}, nil
		},
	}

	svc, err := NewService(Config{Store: st, Authorizer: ev, Gateway: gw, MCP: mcpMock})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"gemini/*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:         "sess-gem-think",
		Subject:    alice.Subject,
		Model:      "gemini/gemini-2.5-pro",
		MCPServers: []string{"git"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec, alice, sess.ID, SendMessageRequest{Content: "Check default branch"}); err != nil {
		t.Fatalf("StreamMessage failed: %v", err)
	}

	// Internal thought text MUST NOT leak into user-facing delta SSE or persisted assistant message.
	if strings.Contains(rec.Body.String(), "Internal reasoning...") {
		t.Fatalf("thought text leaked into SSE response: %s", rec.Body.String())
	}

	// Round 2 contents MUST include the model turn with both Thought+ThoughtSignature and FunctionCall+ThoughtSignature.
	if len(round2Contents) < 3 {
		t.Fatalf("expected at least 3 turns in round 2 contents, got %+v", round2Contents)
	}
	modelTurn := round2Contents[1]
	if modelTurn.Role != "model" || len(modelTurn.Parts) != 2 {
		t.Fatalf("expected model turn with 2 preserved parts, got %+v", modelTurn)
	}
	if !modelTurn.Parts[0].Thought || modelTurn.Parts[0].ThoughtSignature != "sig_thought_abc" || modelTurn.Parts[0].Text != "Internal reasoning..." {
		t.Errorf("thought part not preserved verbatim: %+v", modelTurn.Parts[0])
	}
	if modelTurn.Parts[1].FunctionCall == nil || modelTurn.Parts[1].ThoughtSignature != "sig_fc_xyz" {
		t.Errorf("functionCall thoughtSignature not preserved verbatim: %+v", modelTurn.Parts[1])
	}
}

func TestService_PerSessionConcurrencyMutexAndCleanup(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	turn1Entered := make(chan struct{})
	releaseTurn1 := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32
	var callNum atomic.Int32

	mockGateway := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curActive := active.Add(1)
		defer active.Add(-1)
		for {
			prev := maxActive.Load()
			if curActive <= prev || maxActive.CompareAndSwap(prev, curActive) {
				break
			}
		}

		n := callNum.Add(1)
		if n == 1 {
			close(turn1Entered)
			<-releaseTurn1
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: {\"id\":\"c-%d\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"reply-%d\"},\"finish_reason\":\"stop\"}]}\n\n", n, n)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})

	svc, err := NewService(Config{Store: st, Gateway: mockGateway})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-serial",
		Subject: alice.Subject,
		Model:   "openai/gpt-4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	go func() {
		defer wg.Done()
		errCh <- svc.StreamMessage(ctx, httptest.NewRecorder(), alice, sess.ID, SendMessageRequest{Content: "turn-1"})
	}()

	<-turn1Entered

	go func() {
		defer wg.Done()
		errCh <- svc.StreamMessage(ctx, httptest.NewRecorder(), alice, sess.ID, SendMessageRequest{Content: "turn-2"})
	}()

	// Give turn 2 a brief window to contend on the session mutex before releasing turn 1.
	time.Sleep(40 * time.Millisecond)
	if callNum.Load() != 1 {
		t.Fatalf("turn 2 entered gateway concurrently with turn 1! calls=%d", callNum.Load())
	}
	close(releaseTurn1)

	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatalf("concurrent StreamMessage returned error: %v", e)
		}
	}

	if maxActive.Load() != 1 {
		t.Fatalf("expected max 1 active turn per session, got %d", maxActive.Load())
	}

	// Messages must be strictly serialized: user1, assistant1, user2, assistant2.
	msgs, err := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if err != nil || len(msgs) != 4 {
		t.Fatalf("expected 4 serialized messages, got %d (err=%v)", len(msgs), err)
	}
	wantSeq := []struct{ role, content string }{
		{"user", "turn-1"},
		{"assistant", "reply-1"},
		{"user", "turn-2"},
		{"assistant", "reply-2"},
	}
	for i, w := range wantSeq {
		if msgs[i].Role != w.role || msgs[i].Content != w.content {
			t.Errorf("msg[%d] = (%s, %q), want (%s, %q)", i, msgs[i].Role, msgs[i].Content, w.role, w.content)
		}
	}

	// Ref-counted cleanup must leave sessionLocks empty.
	svc.sessionLocksMu.Lock()
	remaining := len(svc.sessionLocks)
	svc.sessionLocksMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected sessionLocks map cleaned up to 0 entries, got %d", remaining)
	}
}

func TestService_FallbackHeadersDriveCostCalculation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	for _, p := range []store.Provider{
		{Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "http://127.0.0.1:1", Models: []string{"gpt-4.1"}, Enabled: true},
		{Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: "http://127.0.0.1:1", Models: []string{"claude-haiku-4-5"}, Enabled: true},
	} {
		if err := st.UpsertProvider(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertModelRoute(ctx, store.ModelRoute{
		Alias:         "team/smart",
		ProviderName:  "openai",
		UpstreamModel: "gpt-4.1",
		Fallbacks:     []store.RouteTarget{{Provider: "anthropic", Model: "claude-haiku-4-5"}},
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate proxy.Gateway falling back from primary openai/gpt-4.1 to anthropic/claude-haiku-4-5
	// and reporting actual upstream provider/model via X-Headlamp-* headers.
	mockFallbackGateway := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Headlamp-Provider-Type", config.ProviderTypeAnthropic)
		w.Header().Set("X-Headlamp-Upstream-Model", "claude-haiku-4-5")
		_, _ = io.WriteString(w, "data: {\"id\":\"cmpl-fb\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Fallback answer\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1000000,\"completion_tokens\":100000,\"total_tokens\":1100000}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})

	svc, err := NewService(Config{
		Store:   st,
		Pricing: pricing,
		Gateway: mockFallbackGateway,
	})
	if err != nil {
		t.Fatal(err)
	}

	alice := makePrincipal("alice@example.com", []string{"*"}, nil)
	sess, err := st.CreateChatSession(ctx, store.ChatSession{
		ID:      "sess-fallback-cost",
		Subject: alice.Subject,
		Model:   "team/smart",
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	if err := svc.StreamMessage(ctx, rec, alice, sess.ID, SendMessageRequest{Content: "hello"}); err != nil {
		t.Fatalf("StreamMessage failed: %v", err)
	}

	msgs, err := st.ListChatMessages(ctx, alice.Subject, sess.ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d (err=%v)", len(msgs), err)
	}

	usage := metering.Usage{InputTokens: 1_000_000, OutputTokens: 100_000, TotalTokens: 1_100_000}
	wantFallbackCost := pricing.CalculateCost(config.ProviderTypeAnthropic, "claude-haiku-4-5", usage, nil)
	primaryCost := pricing.CalculateCost(config.ProviderTypeOpenAI, "gpt-4.1", usage, nil)
	if wantFallbackCost == primaryCost {
		t.Fatalf("test assumption invalid: expected distinct prices for haiku (%f) vs gpt-4.1 (%f)", wantFallbackCost, primaryCost)
	}
	if msgs[1].CostUSD != wantFallbackCost {
		t.Fatalf("persisted CostUSD = %.6f, want fallback claude-haiku-4-5 cost %.6f (primary gpt-4.1 would be %.6f)",
			msgs[1].CostUSD, wantFallbackCost, primaryCost)
	}
}
