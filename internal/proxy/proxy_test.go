package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/internal/translate"
)

// --- Test helpers ---

type mockAuthorizer struct {
	allowFn  func(p *auth.Principal, model string) (bool, string)
	denyFn   func(p *auth.Principal, model string) (bool, string)
	filterFn func(p *auth.Principal, models []string) []string
}

func (m *mockAuthorizer) AuthorizeModel(_ context.Context, p *auth.Principal, model string) (bool, string, error) {
	if m.allowFn != nil {
		allowed, reason := m.allowFn(p, model)
		return allowed, reason, nil
	}
	return true, "", nil
}

func (m *mockAuthorizer) IsModelDenied(_ context.Context, p *auth.Principal, model string) (bool, string, error) {
	if m.denyFn != nil {
		denied, reason := m.denyFn(p, model)
		return denied, reason, nil
	}
	return false, "", nil
}

func (m *mockAuthorizer) FilterModels(_ context.Context, p *auth.Principal, models []string) ([]string, error) {
	if m.filterFn != nil {
		return m.filterFn(p, models), nil
	}
	return models, nil
}

type recordedEvent struct {
	Event string
	Data  []byte
}

type recordedTelemetry struct {
	mu          sync.Mutex
	start       TelemetryStart
	respHeaders map[string]string
	events      []recordedEvent
	jsonBody    []byte
	finish      *TelemetryFinish
}

func (r *recordedTelemetry) SetResponseHeaders(headers map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.respHeaders = headers
}

func (r *recordedTelemetry) OnSSEEvent(eventName string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, recordedEvent{Event: eventName, Data: bytes.Clone(data)})
}

func (r *recordedTelemetry) OnJSONResponse(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jsonBody = bytes.Clone(body)
}

func (r *recordedTelemetry) Finish(f TelemetryFinish) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := f
	r.finish = &cp
}

type mockTelemetryFactory struct {
	mu      sync.Mutex
	records []*recordedTelemetry
}

func (f *mockTelemetryFactory) Start(_ context.Context, info TelemetryStart) StreamObserver {
	rec := &recordedTelemetry{start: info}
	f.mu.Lock()
	f.records = append(f.records, rec)
	f.mu.Unlock()
	return rec
}

func (f *mockTelemetryFactory) last() *recordedTelemetry {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) == 0 {
		return nil
	}
	return f.records[len(f.records)-1]
}

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
	dsn := filepath.Join(t.TempDir(), "test.db")
	st, err := store.NewSQLiteStore(context.Background(), dsn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:     "alice@example.com",
		DisplayName: "Alice",
		NodeName:    "alice-mac",
		NodeIP:      "100.64.0.10",
		Roles:       []string{auth.RoleUser},
		AuthSource:  auth.AuthSourceTSNet,
	}
}

func authedReq(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(auth.WithPrincipal(req.Context(), testPrincipal()))
}

// --- Tests ---

func TestNativePassthroughOpenAIChatStreamAndNonStream(t *testing.T) {
	largeChunk := strings.Repeat("X", 130*1024) // >128 KiB SSE frame
	var capturedAuth string
	var capturedBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		capturedAuth = r.Header.Get("Authorization")
		capturedBody, _ = io.ReadAll(r.Body)

		var req map[string]any
		_ = json.Unmarshal(capturedBody, &req)
		if req["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + largeChunk + "\"},\"finish_reason\":null}]}\n\n"))
			flusher.Flush()
			_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4.1\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":10,\"total_tokens\":60,\"prompt_tokens_details\":{\"cached_tokens\":20}}}\n\n"))
			flusher.Flush()
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			flusher.Flush()
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-ns","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}`))
	}))
	defer upstream.Close()

	st := newTestStore(t)
	if err := st.UpsertProvider(context.Background(), store.Provider{
		Name:    "openai",
		Type:    config.ProviderTypeOpenAI,
		BaseURL: upstream.URL,
		APIKey:  "sk-managed-openai",
		Models:  []string{"gpt-4.1"},
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	tel := &mockTelemetryFactory{}
	gw, err := NewGateway(GatewayConfig{Store: st, Telemetry: tel})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Streaming via /v1/chat/completions without stream_options -> gateway must inject stream_options.include_usage=true.
	req := authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4.1","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	req.Header.Set("Authorization", "Bearer placeholder-client-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if capturedAuth != "Bearer sk-managed-openai" {
		t.Fatalf("expected managed key injection, got %q", capturedAuth)
	}
	if !strings.Contains(string(capturedBody), `"include_usage":true`) {
		t.Fatalf("expected stream_options.include_usage injected, got: %s", string(capturedBody))
	}
	if !strings.Contains(rec.Body.String(), largeChunk) || !strings.Contains(rec.Body.String(), "data: [DONE]") {
		t.Fatalf("streaming body missing large chunk or [DONE]")
	}
	last := tel.last()
	if last == nil || last.finish == nil || last.finish.StatusCode != 200 {
		t.Fatalf("telemetry not finished cleanly: %+v", last)
	}
	if last.start.Protocol != ProtocolOpenAIChat || last.start.Translated {
		t.Fatalf("unexpected telemetry start: %+v", last.start)
	}
	if len(last.events) != 2 || !strings.Contains(string(last.events[1].Data), `"cached_tokens":20`) {
		t.Fatalf("expected 2 observed SSE events with usage, got %d", len(last.events))
	}

	// 2. Non-streaming via /openai/v1/chat/completions (byte-for-byte untouched body!).
	rawNonStream := `{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}],"custom_extra_field":123}`
	req2 := authedReq(http.MethodPost, "/openai/v1/chat/completions", rawNonStream)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	if string(capturedBody) != rawNonStream {
		t.Fatalf("native non-stream body should be untouched byte-for-byte, got: %s", string(capturedBody))
	}
	if last2 := tel.last(); !strings.Contains(string(last2.jsonBody), `"prompt_tokens":12`) {
		t.Fatalf("expected JSON response captured by telemetry, got: %s", string(last2.jsonBody))
	}
}

func TestNativePassthroughOpenAIResponses(t *testing.T) {
	var capturedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		frames := []string{
			"event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":1,\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n",
			"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"Hello\"}\n\n",
			"event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":3,\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":100,\"input_tokens_details\":{\"cached_tokens\":80},\"output_tokens\":25,\"output_tokens_details\":{\"reasoning_tokens\":15},\"total_tokens\":125}}}\n\n",
		}
		for _, f := range frames {
			_, _ = w.Write([]byte(f))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:    "openai",
		Type:    config.ProviderTypeOpenAI,
		BaseURL: upstream.URL,
		APIKey:  "sk-openai",
		Models:  []string{"gpt-5"},
		Enabled: true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	rawReq := `{"model":"gpt-5","stream":true,"reasoning":{"effort":"high"},"input":"explain"}`
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, authedReq(http.MethodPost, "/v1/responses", rawReq))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if string(capturedBody) != rawReq {
		t.Fatalf("Responses native passthrough mutated body: %s", string(capturedBody))
	}
	last := tel.last()
	if last.start.Protocol != ProtocolOpenAIResponses || len(last.events) != 3 {
		t.Fatalf("unexpected responses telemetry: start=%+v events=%d", last.start, len(last.events))
	}
	if last.events[2].Event != "response.completed" || !strings.Contains(string(last.events[2].Data), `"reasoning_tokens":15`) {
		t.Fatalf("expected response.completed event with reasoning_tokens, got %+v", last.events[2])
	}
}

func TestNativePassthroughAnthropicMessagesAndCountTokens(t *testing.T) {
	var capturedHeaders http.Header
	var capturedBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedBody, _ = io.ReadAll(r.Body)

		if r.URL.Path == "/v1/messages/count_tokens" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":42}`))
			return
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		sse := strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-6","usage":{"input_tokens":50,"cache_creation_input_tokens":200,"cache_read_input_tokens":1000,"output_tokens":1}}}`,
			``,
			`event: content_block_start`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig_verbatim"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":33}}`,
			``,
			`event: message_stop`,
			`data: {"type":"message_stop"}`,
			``,
		}, "\n")
		_, _ = w.Write([]byte(sse))
		flusher.Flush()
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:    "anthropic",
		Type:    config.ProviderTypeAnthropic,
		BaseURL: upstream.URL,
		APIKey:  "sk-ant-managed",
		Models:  []string{"claude-sonnet-4-6"},
		Enabled: true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	rawReq := `{"model":"claude-sonnet-4-6","max_tokens":4096,"stream":true,"thinking":{"type":"enabled","budget_tokens":1024},"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`
	req := authedReq(http.MethodPost, "/anthropic/v1/messages", rawReq)
	req.Header.Set("x-api-key", "none")
	req.Header.Set("Authorization", "Bearer should-be-stripped")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "interleaved-thinking-2025-05-14,prompt-caching-2024-07-31")

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if string(capturedBody) != rawReq {
		t.Fatalf("Anthropic native body must be byte-for-byte untouched")
	}
	if capturedHeaders.Get("x-api-key") != "sk-ant-managed" {
		t.Fatalf("expected managed x-api-key, got %q", capturedHeaders.Get("x-api-key"))
	}
	if capturedHeaders.Get("Authorization") != "" {
		t.Fatalf("client Authorization must be stripped in managed mode, got %q", capturedHeaders.Get("Authorization"))
	}
	if capturedHeaders.Get("anthropic-beta") != "interleaved-thinking-2025-05-14,prompt-caching-2024-07-31" {
		t.Fatalf("anthropic-beta not preserved: %q", capturedHeaders.Get("anthropic-beta"))
	}
	if !strings.Contains(rec.Body.String(), `"signature":"sig_verbatim"`) {
		t.Fatalf("signature_delta not preserved verbatim")
	}
	last := tel.last()
	if last.start.Protocol != ProtocolAnthropicMessages || len(last.events) != 5 {
		t.Fatalf("unexpected telemetry: start=%+v events=%d", last.start, len(last.events))
	}

	// Count tokens passthrough.
	reqCT := authedReq(http.MethodPost, "/anthropic/v1/messages/count_tokens", `{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`)
	recCT := httptest.NewRecorder()
	gw.ServeHTTP(recCT, reqCT)
	if recCT.Code != http.StatusOK || !strings.Contains(recCT.Body.String(), `"input_tokens":42`) {
		t.Fatalf("count_tokens failed: code=%d body=%s", recCT.Code, recCT.Body.String())
	}
}

func TestNativePassthroughGemini(t *testing.T) {
	var capturedPath, capturedQuery, capturedKeyHeader string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		capturedKeyHeader = r.Header.Get("x-goog-api-key")

		if strings.HasSuffix(r.URL.Path, ":streamGenerateContent") && r.URL.Query().Get("alt") == "sse" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hi\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":260,\"cachedContentTokenCount\":120,\"candidatesTokenCount\":45,\"thoughtsTokenCount\":22,\"totalTokenCount\":327}}\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`))
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:    "gemini",
		Type:    config.ProviderTypeGemini,
		BaseURL: upstream.URL,
		APIKey:  "goog-managed-secret",
		Models:  []string{"gemini-2.5-flash"},
		Enabled: true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	// Streaming SSE with client ?key=placeholder -> must strip ?key=, keep alt=sse, inject x-goog-api-key.
	req := authedReq(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=client-placeholder", `{"contents":[{"parts":[{"text":"hi"}]}]}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if capturedPath != "/v1beta/models/gemini-2.5-flash:streamGenerateContent" {
		t.Fatalf("unexpected upstream path: %q", capturedPath)
	}
	if strings.Contains(capturedQuery, "key=") || !strings.Contains(capturedQuery, "alt=sse") {
		t.Fatalf("expected ?key= stripped and alt=sse kept, got %q", capturedQuery)
	}
	if capturedKeyHeader != "goog-managed-secret" {
		t.Fatalf("expected managed x-goog-api-key, got %q", capturedKeyHeader)
	}
	last := tel.last()
	if last.start.Protocol != ProtocolGemini || len(last.events) != 1 || !strings.Contains(string(last.events[0].Data), `"thoughtsTokenCount":22`) {
		t.Fatalf("unexpected gemini telemetry: %+v", last)
	}

	// Non-streaming generateContent.
	req2 := authedReq(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:generateContent", `{"contents":[{"parts":[{"text":"hi"}]}]}`)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"OK"`) {
		t.Fatalf("gemini non-stream failed: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestNativePassthroughOllama(t *testing.T) {
	var capturedAuth string
	var capturedModel string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-ollama","object":"chat.completion","model":"qwen2.5-coder:32b","choices":[{"index":0,"message":{"role":"assistant","content":"local ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":8,"total_tokens":23}}`))
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:    "ollama",
		Type:    config.ProviderTypeOllama,
		BaseURL: upstream.URL,
		APIKey:  "",
		Models:  []string{"qwen2.5-coder:32b"},
		Enabled: true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	req := authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"ollama/qwen2.5-coder:32b","messages":[{"role":"user","content":"hi"}]}`)
	req.Header.Set("Authorization", "Bearer ollama")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if capturedModel != "qwen2.5-coder:32b" {
		t.Fatalf("expected provider prefix stripped to qwen2.5-coder:32b, got %q", capturedModel)
	}
	if capturedAuth != "" {
		t.Fatalf("expected no Authorization sent to keyless local Ollama, got %q", capturedAuth)
	}
	if last := tel.last(); last.start.ProviderType != config.ProviderTypeOllama {
		t.Fatalf("expected ProviderType ollama, got %q", last.start.ProviderType)
	}
}

func TestPassthroughAuthMode(t *testing.T) {
	var seenHeaders http.Header
	var seenQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:        "ant-pass",
		Type:        config.ProviderTypeAnthropic,
		BaseURL:     upstream.URL,
		APIKey:      "should-not-be-used",
		Passthrough: true,
		Models:      []string{"claude-sonnet-4-6"},
		Enabled:     true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:        "gem-pass",
		Type:        config.ProviderTypeGemini,
		BaseURL:     upstream.URL,
		Passthrough: true,
		Models:      []string{"gemini-2.5-pro"},
		Enabled:     true,
	})

	gw, _ := NewGateway(GatewayConfig{Store: st})

	// Anthropic OAuth Bearer passthrough.
	req := authedReq(http.MethodPost, "/anthropic/v1/messages", `{"model":"ant-pass/claude-sonnet-4-6","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)
	req.Header.Set("Authorization", "Bearer user-oauth-token")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || seenHeaders.Get("Authorization") != "Bearer user-oauth-token" || seenHeaders.Get("x-api-key") != "" {
		t.Fatalf("anthropic passthrough failed: code=%d auth=%q x-api-key=%q", rec.Code, seenHeaders.Get("Authorization"), seenHeaders.Get("x-api-key"))
	}

	// Gemini query ?key= passthrough.
	req2 := authedReq(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-pro:generateContent?key=user-gemini-key", `{}`)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || seenQuery != "key=user-gemini-key" {
		t.Fatalf("gemini passthrough failed: code=%d query=%q", rec2.Code, seenQuery)
	}
}

func TestFallbackRoutingOn5xx429AndNetworkError(t *testing.T) {
	var primaryHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"busy"}}`))
	}))
	defer primary.Close()

	var fallbackHits atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-fb","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"from fallback"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer fallback.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: primary.URL, APIKey: "k1", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: fallback.URL, APIKey: "k2", Enabled: true,
	})
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias:         "team/coding",
		ProviderName:  "anthropic",
		UpstreamModel: "claude-sonnet-4-6",
		Fallbacks:     []store.RouteTarget{{Provider: "openai", Model: "gpt-4.1"}},
		Enabled:       true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	// OpenAI client calls team/coding -> primary Anthropic 429s -> falls back to OpenAI natively -> 200 OK!
	req := authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"team/coding","messages":[{"role":"user","content":"hi"}]}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from fallback, got %d: %s", rec.Code, rec.Body.String())
	}
	if primaryHits.Load() != 1 || fallbackHits.Load() != 1 {
		t.Fatalf("expected 1 hit each, got primary=%d fallback=%d", primaryHits.Load(), fallbackHits.Load())
	}
	if !strings.Contains(rec.Body.String(), "from fallback") {
		t.Fatalf("expected fallback body, got: %s", rec.Body.String())
	}
	if last := tel.last(); last.start.Provider != "openai" || last.start.Translated {
		t.Fatalf("expected telemetry recorded against winning fallback openai, got %+v", last.start)
	}

	// Now shut down both upstreams to verify 502 error envelope on network error.
	primary.Close()
	fallback.Close()
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"team/coding","messages":[{"role":"user","content":"hi"}]}`))
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on all-upstreams network failure, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"upstream_error"`) {
		t.Fatalf("expected OpenAI error envelope, got: %s", rec2.Body.String())
	}
}

func TestAuthorizationDenialModelListAndProtocolErrors(t *testing.T) {
	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "http://127.0.0.1:1", Models: []string{"gpt-4.1", "gpt-5"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: "http://127.0.0.1:1", Models: []string{"claude-sonnet-4-6"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "gemini", Type: config.ProviderTypeGemini, BaseURL: "http://127.0.0.1:1", Models: []string{"gemini-2.5-flash"}, Enabled: true,
	})

	authz := &mockAuthorizer{
		allowFn: func(_ *auth.Principal, model string) (bool, string) {
			if model == "openai/gpt-4.1" {
				return true, ""
			}
			return false, "model " + model + " is restricted"
		},
		filterFn: func(_ *auth.Principal, models []string) []string {
			var out []string
			for _, m := range models {
				if m == "openai/gpt-4.1" || m == "anthropic/claude-sonnet-4-6" {
					out = append(out, m)
				}
			}
			return out
		},
	}

	gw, _ := NewGateway(GatewayConfig{Store: st, Authorizer: authz})

	// 1. /healthz works without Principal.
	recHealth := httptest.NewRecorder()
	gw.ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("healthz expected 200, got %d", recHealth.Code)
	}

	// 2. Unauthenticated -> 401 in protocol-specific schemas.
	rec401Anth := httptest.NewRecorder()
	gw.ServeHTTP(rec401Anth, httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`)))
	if rec401Anth.Code != http.StatusUnauthorized || !strings.Contains(rec401Anth.Body.String(), `"authentication_error"`) || !strings.Contains(rec401Anth.Body.String(), `"type":"error"`) {
		t.Fatalf("unexpected anthropic 401: %d %s", rec401Anth.Code, rec401Anth.Body.String())
	}

	rec401Gem := httptest.NewRecorder()
	gw.ServeHTTP(rec401Gem, httptest.NewRequest(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:generateContent", strings.NewReader(`{}`)))
	if rec401Gem.Code != http.StatusUnauthorized || !strings.Contains(rec401Gem.Body.String(), `"UNAUTHENTICATED"`) {
		t.Fatalf("unexpected gemini 401: %d %s", rec401Gem.Code, rec401Gem.Body.String())
	}

	// 3. Denied model -> 403 in protocol-specific schemas.
	rec403OAI := httptest.NewRecorder()
	gw.ServeHTTP(rec403OAI, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-5","messages":[]}`))
	if rec403OAI.Code != http.StatusForbidden || !strings.Contains(rec403OAI.Body.String(), `"permission_error"`) {
		t.Fatalf("unexpected openai 403: %d %s", rec403OAI.Code, rec403OAI.Body.String())
	}

	rec403Anth := httptest.NewRecorder()
	gw.ServeHTTP(rec403Anth, authedReq(http.MethodPost, "/anthropic/v1/messages", `{"model":"claude-sonnet-4-6","max_tokens":10,"messages":[]}`))
	if rec403Anth.Code != http.StatusForbidden || !strings.Contains(rec403Anth.Body.String(), `"permission_error"`) {
		t.Fatalf("unexpected anthropic 403: %d %s", rec403Anth.Code, rec403Anth.Body.String())
	}

	rec403Gem := httptest.NewRecorder()
	gw.ServeHTTP(rec403Gem, authedReq(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:generateContent", `{}`))
	if rec403Gem.Code != http.StatusForbidden || !strings.Contains(rec403Gem.Body.String(), `"PERMISSION_DENIED"`) {
		t.Fatalf("unexpected gemini 403: %d %s", rec403Gem.Code, rec403Gem.Body.String())
	}

	// 4. Unknown model -> 404.
	rec404 := httptest.NewRecorder()
	gw.ServeHTTP(rec404, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"nonexistent","messages":[]}`))
	if rec404.Code != http.StatusNotFound || !strings.Contains(rec404.Body.String(), `"model_not_found"`) {
		t.Fatalf("unexpected 404: %d %s", rec404.Code, rec404.Body.String())
	}

	// 5. Filtered model lists.
	recList := httptest.NewRecorder()
	gw.ServeHTTP(recList, authedReq(http.MethodGet, "/v1/models", ""))
	if recList.Code != http.StatusOK {
		t.Fatalf("GET /v1/models failed: %d", recList.Code)
	}
	var listResp struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range listResp.Data {
		ids = append(ids, d.ID)
	}
	if !slices.Equal(ids, []string{"anthropic/claude-sonnet-4-6", "openai/gpt-4.1"}) {
		t.Fatalf("unexpected filtered models: %v", ids)
	}

	recAnthList := httptest.NewRecorder()
	gw.ServeHTTP(recAnthList, authedReq(http.MethodGet, "/anthropic/v1/models", ""))
	if recAnthList.Code != http.StatusOK || !strings.Contains(recAnthList.Body.String(), `"has_more":false`) {
		t.Fatalf("GET /anthropic/v1/models failed: %d %s", recAnthList.Code, recAnthList.Body.String())
	}
}

func TestCrossProtocolEndToEndOpenAIAndAnthropic(t *testing.T) {
	// Mock Anthropic upstream (will receive translated OpenAI Chat requests).
	var anthGotVersion, anthGotKey string
	var anthGotBody []byte
	anthUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthGotVersion = r.Header.Get("anthropic-version")
		anthGotKey = r.Header.Get("x-api-key")
		anthGotBody, _ = io.ReadAll(r.Body)

		var req map[string]any
		_ = json.Unmarshal(anthGotBody, &req)
		if req["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			sse := strings.Join([]string{
				`event: message_start`,
				`data: {"type":"message_start","message":{"id":"msg_x1","model":"claude-sonnet-4-6","usage":{"input_tokens":80,"cache_read_input_tokens":200,"cache_creation_input_tokens":20,"output_tokens":1}}}`,
				``,
				`event: content_block_start`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}`,
				``,
				`event: content_block_delta`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"NYC\"}"}}`,
				``,
				`event: content_block_stop`,
				`data: {"type":"content_block_stop","index":0}`,
				``,
				`event: message_delta`,
				`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":19}}`,
				``,
				`event: message_stop`,
				`data: {"type":"message_stop"}`,
				``,
			}, "\n")
			_, _ = w.Write([]byte(sse))
			flusher.Flush()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_ns","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"hello from claude"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":4}}`))
	}))
	defer anthUpstream.Close()

	// Mock OpenAI/Ollama upstream (will receive translated Anthropic Messages requests).
	var oaiGotBody []byte
	oaiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oaiGotBody, _ = io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(oaiGotBody, &req)
		if req["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			sse := strings.Join([]string{
				`data: {"id":"chatcmpl-o1","object":"chat.completion.chunk","created":1,"model":"qwen2.5-coder:32b","choices":[{"index":0,"delta":{"role":"assistant","content":"hi "},"finish_reason":null}]}`,
				``,
				`data: {"id":"chatcmpl-o1","object":"chat.completion.chunk","created":1,"model":"qwen2.5-coder:32b","choices":[{"index":0,"delta":{"content":"claude client"},"finish_reason":null}]}`,
				``,
				`data: {"id":"chatcmpl-o1","object":"chat.completion.chunk","created":1,"model":"qwen2.5-coder:32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
				``,
				`data: {"id":"chatcmpl-o1","object":"chat.completion.chunk","created":1,"model":"qwen2.5-coder:32b","choices":[],"usage":{"prompt_tokens":40,"completion_tokens":12,"total_tokens":52}}`,
				``,
				`data: [DONE]`,
				``,
			}, "\n")
			_, _ = w.Write([]byte(sse))
			flusher.Flush()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-o2","object":"chat.completion","model":"qwen2.5-coder:32b","choices":[{"index":0,"message":{"role":"assistant","content":"hello from ollama"},"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":5,"total_tokens":20}}`))
	}))
	defer oaiUpstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: anthUpstream.URL, APIKey: "sk-ant-1", Models: []string{"claude-sonnet-4-6"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "ollama", Type: config.ProviderTypeOllama, BaseURL: oaiUpstream.URL, Models: []string{"qwen2.5-coder:32b"}, Enabled: true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	// 1. OpenAI Chat streaming -> Anthropic upstream (with tool calls + include_usage).
	req1 := authedReq(http.MethodPost, "/v1/chat/completions", `{
		"model":"anthropic/claude-sonnet-4-6",
		"stream":true,
		"stream_options":{"include_usage":true},
		"messages":[{"role":"system","content":"sys"},{"role":"user","content":"weather in NYC?"}],
		"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]
	}`)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("OpenAI->Anthropic stream failed: %d %s", rec1.Code, rec1.Body.String())
	}
	if anthGotVersion != "2023-06-01" || anthGotKey != "sk-ant-1" {
		t.Fatalf("missing anthropic headers: version=%q key=%q", anthGotVersion, anthGotKey)
	}
	if !strings.Contains(string(anthGotBody), `"max_tokens":4096`) {
		t.Fatalf("expected default max_tokens injected, got: %s", string(anthGotBody))
	}
	if !strings.Contains(rec1.Body.String(), `"get_weather"`) || !strings.Contains(rec1.Body.String(), `"finish_reason":"tool_calls"`) || !strings.Contains(rec1.Body.String(), `"prompt_tokens":300`) || !strings.Contains(rec1.Body.String(), "data: [DONE]") {
		t.Fatalf("unexpected translated OpenAI stream: %s", rec1.Body.String())
	}
	// Telemetry must receive lossless upstream Anthropic events with Protocol == anthropic_messages.
	last1 := tel.last()
	if !last1.start.Translated || last1.start.Protocol != ProtocolAnthropicMessages || last1.start.IngressProtocol != ProtocolOpenAIChat {
		t.Fatalf("unexpected telemetry start for OpenAI->Anthropic: %+v", last1.start)
	}
	if len(last1.events) != 6 || !strings.Contains(string(last1.events[0].Data), `"cache_creation_input_tokens":20`) {
		t.Fatalf("expected lossless upstream Anthropic events in telemetry, got %d", len(last1.events))
	}

	// 2. OpenAI Chat non-streaming -> Anthropic upstream.
	rec1ns := httptest.NewRecorder()
	gw.ServeHTTP(rec1ns, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`))
	if rec1ns.Code != http.StatusOK || !strings.Contains(rec1ns.Body.String(), `"hello from claude"`) {
		t.Fatalf("OpenAI->Anthropic non-stream failed: %d %s", rec1ns.Code, rec1ns.Body.String())
	}

	// 3. Anthropic Messages streaming -> Ollama OpenAI-compat upstream.
	req2 := authedReq(http.MethodPost, "/anthropic/v1/messages", `{
		"model":"ollama/qwen2.5-coder:32b",
		"max_tokens":256,
		"stream":true,
		"system":"Be terse",
		"messages":[{"role":"user","content":"say hi"}]
	}`)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Anthropic->Ollama stream failed: %d %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(string(oaiGotBody), `"include_usage":true`) || !strings.Contains(string(oaiGotBody), `"role":"system"`) {
		t.Fatalf("unexpected translated OpenAI request body: %s", string(oaiGotBody))
	}

	// Verify emitted Anthropic SSE frames.
	r := bufio.NewReader(bytes.NewReader(rec2.Body.Bytes()))
	var evNames []string
	for {
		ev, err := translate.ReadSSEEvent(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		evNames = append(evNames, ev.Event)
	}
	if len(evNames) < 5 || evNames[0] != "message_start" || evNames[len(evNames)-1] != "message_stop" {
		t.Fatalf("unexpected Anthropic SSE event sequence: %v", evNames)
	}
	last2 := tel.last()
	if !last2.start.Translated || last2.start.Protocol != ProtocolOpenAIChat || last2.start.ProviderType != config.ProviderTypeOllama {
		t.Fatalf("unexpected telemetry for Anthropic->Ollama: %+v", last2.start)
	}

	// 4. Anthropic Messages non-streaming -> Ollama upstream.
	rec2ns := httptest.NewRecorder()
	gw.ServeHTTP(rec2ns, authedReq(http.MethodPost, "/anthropic/v1/messages", `{"model":"ollama/qwen2.5-coder:32b","max_tokens":128,"messages":[{"role":"user","content":"hi"}]}`))
	if rec2ns.Code != http.StatusOK || !strings.Contains(rec2ns.Body.String(), `"hello from ollama"`) {
		t.Fatalf("Anthropic->Ollama non-stream failed: %d %s", rec2ns.Code, rec2ns.Body.String())
	}
}

func TestIncompatibleFallbackPreservesPrimary429AndTelemetry(t *testing.T) {
	gemini429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"quota exceeded","status":"RESOURCE_EXHAUSTED"}}`))
	}))
	defer gemini429.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "gemini", Type: config.ProviderTypeGemini, BaseURL: gemini429.URL, APIKey: "gkey", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "http://127.0.0.1:1", APIKey: "okey", Enabled: true,
	})
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias:         "team/fast",
		ProviderName:  "gemini",
		UpstreamModel: "gemini-2.5-flash",
		Fallbacks:     []store.RouteTarget{{Provider: "openai", Model: "gpt-4.1-mini"}},
		Enabled:       true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	req := authedReq(http.MethodPost, "/gemini/v1beta/models/team/fast:generateContent", `{"contents":[{"parts":[{"text":"hi"}]}]}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected primary Gemini 429 preserved (incompatible OpenAI fallback skipped), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "RESOURCE_EXHAUSTED") {
		t.Fatalf("expected Gemini 429 payload preserved, got: %s", rec.Body.String())
	}
	last := tel.last()
	if last == nil || last.finish == nil || last.finish.StatusCode != http.StatusTooManyRequests || last.start.Provider != "gemini" {
		t.Fatalf("expected 429 telemetry recorded against gemini, got: %+v", last)
	}
}

func TestGeminiPassthroughNetworkErrorSanitizesQueryKey(t *testing.T) {
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name:        "gemini",
		Type:        config.ProviderTypeGemini,
		BaseURL:     closedURL,
		Passthrough: true,
		Models:      []string{"gemini-2.5-flash"},
		Enabled:     true,
	})

	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	secretKey := "AIzaSySuperSecretUserKey999"
	req := authedReq(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:generateContent?key="+secretKey+"&alt=json", `{}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secretKey) {
		t.Fatalf("502 response leaked passthrough ?key= secret: %s", rec.Body.String())
	}
	last := tel.last()
	if last == nil || last.finish == nil {
		t.Fatalf("expected telemetry recorded on network error")
	}
	if strings.Contains(last.finish.ErrorMessage, secretKey) {
		t.Fatalf("telemetry error_message leaked passthrough ?key= secret: %s", last.finish.ErrorMessage)
	}
}

func TestPatchJSONRequestStreamOptionsMerge(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantInjected bool
		wantContains []string
	}{
		{
			name:         "absent",
			in:           `{"model":"gpt-4.1","stream":true,"messages":[]}`,
			wantInjected: true,
			wantContains: []string{`"include_usage":true`},
		},
		{
			name:         "null",
			in:           `{"model":"gpt-4.1","stream":true,"stream_options":null,"messages":[]}`,
			wantInjected: true,
			wantContains: []string{`"include_usage":true`},
		},
		{
			name:         "empty_object",
			in:           `{"model":"gpt-4.1","stream":true,"stream_options":{},"messages":[]}`,
			wantInjected: true,
			wantContains: []string{`"include_usage":true`},
		},
		{
			name:         "false_with_sibling_keys",
			in:           `{"model":"gpt-4.1","stream":true,"stream_options":{"include_usage":false,"other":1},"messages":[]}`,
			wantInjected: true,
			wantContains: []string{`"include_usage":true`, `"other":1`},
		},
		{
			name:         "already_true_preserves_bytes",
			in:           `{"model":"gpt-4.1","stream":true,"stream_options":{"include_usage":true,"other":1},"messages":[]}`,
			wantInjected: false,
			wantContains: []string{`"include_usage":true`, `"other":1`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, injected, err := patchJSONRequest([]byte(tc.in), "", true)
			if err != nil {
				t.Fatalf("patchJSONRequest failed: %v", err)
			}
			if injected != tc.wantInjected {
				t.Fatalf("injected=%v, want %v (out=%s)", injected, tc.wantInjected, string(out))
			}
			for _, sub := range tc.wantContains {
				if !strings.Contains(string(out), sub) {
					t.Fatalf("output missing %q: %s", sub, string(out))
				}
			}
		})
	}
}

func TestNativeSSEFiltersSyntheticUsageOnlyWhenInjected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"include_usage":true`) {
			t.Errorf("upstream expected merged include_usage:true, got %s", string(body))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		frames := []string{
			"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
			"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
			"data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\"total_tokens\":120}}\n\n",
			"data: [DONE]\n\n",
		}
		for _, f := range frames {
			_, _ = w.Write([]byte(f))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: upstream.URL, APIKey: "k", Models: []string{"gpt-4.1"}, Enabled: true,
	})
	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	// 1. Client sends stream_options: {"include_usage": false, "other": 1}:
	//    gateway injects include_usage:true, meters usage, and suppresses the synthetic choices:[] chunk from client.
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4.1","stream":true,"stream_options":{"include_usage":false,"other":1},"messages":[{"role":"user","content":"hi"}]}`))
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}
	if strings.Contains(rec1.Body.String(), `"prompt_tokens":100`) {
		t.Fatalf("synthetic usage-only chunk should have been suppressed from client: %s", rec1.Body.String())
	}
	if !strings.Contains(rec1.Body.String(), `"content":"hi"`) || !strings.Contains(rec1.Body.String(), "data: [DONE]") {
		t.Fatalf("missing content or [DONE] in filtered stream: %s", rec1.Body.String())
	}
	if last1 := tel.last(); len(last1.events) != 3 || !strings.Contains(string(last1.events[2].Data), `"prompt_tokens":100`) {
		t.Fatalf("metering observer must still receive usage chunk: %+v", last1.events)
	}

	// 2. Client explicitly sets stream_options: {"include_usage": true}:
	//    gateway forwards the usage chunk verbatim to the client.
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4.1","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`))
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"prompt_tokens":100`) {
		t.Fatalf("explicit include_usage:true must forward usage chunk to client: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestVirtualRouteEnforcesDenyModelsOnCandidates(t *testing.T) {
	var o3Hits atomic.Int32
	o3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o3Hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"o3","choices":[{"index":0,"message":{"role":"assistant","content":"o3"},"finish_reason":"stop"}]}`))
	}))
	defer o3Srv.Close()

	fbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fb","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"allowed fallback"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer fbSrv.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai-o3", Type: config.ProviderTypeOpenAI, BaseURL: o3Srv.URL, APIKey: "k", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai-fb", Type: config.ProviderTypeOpenAI, BaseURL: fbSrv.URL, APIKey: "k", Enabled: true,
	})
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias:         "team/coding",
		ProviderName:  "openai-o3",
		UpstreamModel: "o3",
		Fallbacks:     []store.RouteTarget{{Provider: "openai-fb", Model: "gpt-4.1"}},
		Enabled:       true,
	})
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias:         "team/o3-only",
		ProviderName:  "openai-o3",
		UpstreamModel: "o3",
		Enabled:       true,
	})

	authz := &mockAuthorizer{
		allowFn: func(_ *auth.Principal, model string) (bool, string) {
			return strings.HasPrefix(model, "team/"), ""
		},
		denyFn: func(_ *auth.Principal, model string) (bool, string) {
			if model == "openai-o3/o3" {
				return true, "explicitly denied by rule openai-o3/o3"
			}
			return false, ""
		},
	}

	gw, _ := NewGateway(GatewayConfig{Store: st, Authorizer: authz})

	// 1. Primary openai-o3/o3 is denied -> skips it and uses allowed fallback openai-fb/gpt-4.1.
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"team/coding","messages":[{"role":"user","content":"hi"}]}`))
	if rec1.Code != http.StatusOK || !strings.Contains(rec1.Body.String(), "allowed fallback") {
		t.Fatalf("expected fallback to allowed candidate, got %d: %s", rec1.Code, rec1.Body.String())
	}
	if o3Hits.Load() != 0 {
		t.Fatalf("denied primary candidate must never be called, hits=%d", o3Hits.Load())
	}

	// 2. All candidates denied -> returns HTTP 403 permission_error with deny reason.
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"team/o3-only","messages":[{"role":"user","content":"hi"}]}`))
	if rec2.Code != http.StatusForbidden || !strings.Contains(rec2.Body.String(), "explicitly denied by rule openai-o3/o3") {
		t.Fatalf("expected 403 with deny reason when all candidates denied, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestAuditResponseHeadersAndNon2xxBodyCaptured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-up-429")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limit hit","type":"requests","code":"rate_limit_exceeded"}}`))
	}))
	defer upstream.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: upstream.URL, APIKey: "k", Models: []string{"gpt-4.1"}, Enabled: true,
	})
	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{Store: st, Telemetry: tel})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}`))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	last := tel.last()
	if last == nil || last.respHeaders["X-Request-Id"] != "req-up-429" {
		t.Fatalf("expected SetResponseHeaders called with X-Request-Id, got %+v", last.respHeaders)
	}
	if !strings.Contains(string(last.jsonBody), "rate limit hit") {
		t.Fatalf("expected non-2xx body captured via OnJSONResponse, got %q", string(last.jsonBody))
	}
}

func TestPerAttemptTTFTAndFallbackWarningLog(t *testing.T) {
	slowPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"overloaded"}}`))
	}))
	defer slowPrimary.Close()

	fastFallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"fast"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer fastFallback.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "primary", Type: config.ProviderTypeOpenAI, BaseURL: slowPrimary.URL, APIKey: "k", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "fallback", Type: config.ProviderTypeOpenAI, BaseURL: fastFallback.URL, APIKey: "k", Enabled: true,
	})
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias:         "team/resilient",
		ProviderName:  "primary",
		UpstreamModel: "gpt-5",
		Fallbacks:     []store.RouteTarget{{Provider: "fallback", Model: "gpt-4.1"}},
		Enabled:       true,
	})

	var (
		logMu   sync.Mutex
		logMsgs []string
	)
	tel := &mockTelemetryFactory{}
	gw, _ := NewGateway(GatewayConfig{
		Store:     st,
		Telemetry: tel,
		Logf: func(format string, args ...any) {
			logMu.Lock()
			logMsgs = append(logMsgs, fmt.Sprintf(format, args...))
			logMu.Unlock()
		},
	})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, authedReq(http.MethodPost, "/v1/chat/completions", `{"model":"team/resilient","messages":[{"role":"user","content":"hi"}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from fallback, got %d", rec.Code)
	}

	last := tel.last()
	if last.finish.LatencyMS < 75 {
		t.Fatalf("expected total LatencyMS >= 75ms (including failed primary), got %dms", last.finish.LatencyMS)
	}
	if last.finish.TTFTMS >= last.finish.LatencyMS {
		t.Fatalf("expected per-attempt TTFTMS (%dms) < total LatencyMS (%dms)", last.finish.TTFTMS, last.finish.LatencyMS)
	}
	logMu.Lock()
	joinedLogs := strings.Join(logMsgs, "\n")
	logMu.Unlock()
	if !strings.Contains(joinedLogs, "primary/gpt-5") || !strings.Contains(joinedLogs, "HTTP 503") || !strings.Contains(joinedLogs, "fallback/gpt-4.1") {
		t.Fatalf("expected fallback warning log, got: %q", joinedLogs)
	}
}

func TestModelListProtocolCompatibilityAndDenyFiltering(t *testing.T) {
	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: "http://127.0.0.1:1", Models: []string{"claude-sonnet-4-6"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "http://127.0.0.1:1", Models: []string{"gpt-4.1", "o3"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "ollama", Type: config.ProviderTypeOllama, BaseURL: "http://127.0.0.1:1", Models: []string{"qwen2.5-coder:32b"}, Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "gemini", Type: config.ProviderTypeGemini, BaseURL: "http://127.0.0.1:1", Models: []string{"gemini-2.5-flash"}, Enabled: true,
	})
	// Anthropic + OpenAI fallback (compatible with OpenAI & Anthropic, incompatible with Gemini).
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/coding", ProviderName: "anthropic", UpstreamModel: "claude-sonnet-4-6",
		Fallbacks: []store.RouteTarget{{Provider: "openai", Model: "gpt-4.1"}}, Enabled: true,
	})
	// Gemini primary + OpenAI fallback (compatible with Gemini, OpenAI, and Anthropic).
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/fast", ProviderName: "gemini", UpstreamModel: "gemini-2.5-flash",
		Fallbacks: []store.RouteTarget{{Provider: "openai", Model: "gpt-4.1"}}, Enabled: true,
	})
	// Gemini-only alias (compatible ONLY with Gemini).
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/gemini-only", ProviderName: "gemini", UpstreamModel: "gemini-2.5-flash", Enabled: true,
	})
	// Alias whose only compatible OpenAI/Anthropic candidate is explicitly denied.
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/denied-o3", ProviderName: "openai", UpstreamModel: "o3", Enabled: true,
	})
	// Alias with Gemini primary (allowed) + denied OpenAI fallback -> visible on Gemini, hidden on OpenAI/Anthropic.
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/gem-plus-denied-o3", ProviderName: "gemini", UpstreamModel: "gemini-2.5-flash",
		Fallbacks: []store.RouteTarget{{Provider: "openai", Model: "o3"}}, Enabled: true,
	})

	authz := &mockAuthorizer{
		filterFn: func(_ *auth.Principal, models []string) []string {
			var out []string
			for _, m := range models {
				if m != "openai/o3" {
					out = append(out, m)
				}
			}
			return out
		},
		denyFn: func(_ *auth.Principal, model string) (bool, string) {
			if model == "openai/o3" {
				return true, "o3 denied"
			}
			return false, ""
		},
	}

	gw, _ := NewGateway(GatewayConfig{Store: st, Authorizer: authz})

	wantOpenAIAnthropic := []string{
		"anthropic/claude-sonnet-4-6",
		"ollama/qwen2.5-coder:32b",
		"openai/gpt-4.1",
		"team/coding",
		"team/fast",
	}

	// 1. OpenAI endpoints (/v1/models and /openai/v1/models) exclude pure Gemini models,
	// Gemini-only aliases, and aliases whose compatible candidates are all denied.
	for _, path := range []string{"/v1/models", "/openai/v1/models"} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, authedReq(http.MethodGet, path, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", path, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		var got []string
		for _, item := range resp.Data {
			got = append(got, item.ID)
		}
		if !slices.Equal(got, wantOpenAIAnthropic) {
			t.Fatalf("GET %s returned %v, want %v", path, got, wantOpenAIAnthropic)
		}
	}

	// 2. Anthropic endpoint (/anthropic/v1/models) applies the exact same protocol & deny rules.
	recAnth := httptest.NewRecorder()
	gw.ServeHTTP(recAnth, authedReq(http.MethodGet, "/anthropic/v1/models", ""))
	if recAnth.Code != http.StatusOK {
		t.Fatalf("GET /anthropic/v1/models failed: %d", recAnth.Code)
	}
	var anthResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recAnth.Body.Bytes(), &anthResp); err != nil {
		t.Fatal(err)
	}
	var gotAnth []string
	for _, item := range anthResp.Data {
		gotAnth = append(gotAnth, item.ID)
	}
	if !slices.Equal(gotAnth, wantOpenAIAnthropic) {
		t.Fatalf("GET /anthropic/v1/models returned %v, want %v", gotAnth, wantOpenAIAnthropic)
	}

	// 3. Gemini endpoint (/gemini/v1beta/models) includes Gemini models and aliases with >=1
	// non-denied Gemini candidate, and excludes OpenAI/Anthropic/Ollama-only models & aliases.
	recGem := httptest.NewRecorder()
	gw.ServeHTTP(recGem, authedReq(http.MethodGet, "/gemini/v1beta/models", ""))
	if recGem.Code != http.StatusOK {
		t.Fatalf("GET /gemini/v1beta/models failed: %d", recGem.Code)
	}
	var gemResp struct {
		Models []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"models"`
	}
	if err := json.Unmarshal(recGem.Body.Bytes(), &gemResp); err != nil {
		t.Fatal(err)
	}
	var gotGem []string
	for _, item := range gemResp.Models {
		gotGem = append(gotGem, item.DisplayName)
	}
	wantGem := []string{
		"gemini/gemini-2.5-flash",
		"team/fast",
		"team/gem-plus-denied-o3",
		"team/gemini-only",
	}
	if !slices.Equal(gotGem, wantGem) {
		t.Fatalf("GET /gemini/v1beta/models returned %v, want %v", gotGem, wantGem)
	}
}

func TestAnthropicCountTokensFallbackAndDenyModels(t *testing.T) {
	ant503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`))
	}))
	defer ant503.Close()

	antOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":77}`))
	}))
	defer antOK.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: "http://127.0.0.1:1", APIKey: "k", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "ant1", Type: config.ProviderTypeAnthropic, BaseURL: ant503.URL, APIKey: "k1", Enabled: true,
	})
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "ant2", Type: config.ProviderTypeAnthropic, BaseURL: antOK.URL, APIKey: "k2", Enabled: true,
	})
	// Primary is non-Anthropic (skipped), first Anthropic 503s (falls back), second Anthropic succeeds.
	_ = st.UpsertModelRoute(context.Background(), store.ModelRoute{
		Alias: "team/count", ProviderName: "openai", UpstreamModel: "gpt-4.1",
		Fallbacks: []store.RouteTarget{
			{Provider: "ant1", Model: "claude-sonnet-4-6"},
			{Provider: "ant2", Model: "claude-sonnet-4-6"},
		},
		Enabled: true,
	})

	var logged string
	gw, _ := NewGateway(GatewayConfig{
		Store: st,
		Logf:  func(f string, a ...any) { logged += fmt.Sprintf(f, a...) },
	})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, authedReq(http.MethodPost, "/anthropic/v1/messages/count_tokens", `{"model":"team/count","messages":[{"role":"user","content":"hi"}]}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"input_tokens":77`) {
		t.Fatalf("count_tokens fallback failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logged, "ant1/claude-sonnet-4-6") {
		t.Fatalf("expected fallback log on count_tokens, got %q", logged)
	}

	// Now deny both Anthropic candidates via IsModelDenied -> expect 403.
	gwDenied, _ := NewGateway(GatewayConfig{
		Store: st,
		Authorizer: &mockAuthorizer{
			denyFn: func(_ *auth.Principal, model string) (bool, string) {
				return strings.HasPrefix(model, "ant"), "anthropic denied"
			},
		},
	})
	recDenied := httptest.NewRecorder()
	gwDenied.ServeHTTP(recDenied, authedReq(http.MethodPost, "/anthropic/v1/messages/count_tokens", `{"model":"team/count","messages":[{"role":"user","content":"hi"}]}`))
	if recDenied.Code != http.StatusForbidden || !strings.Contains(recDenied.Body.String(), "anthropic denied") {
		t.Fatalf("expected 403 when count_tokens candidates denied, got %d %s", recDenied.Code, recDenied.Body.String())
	}
}

func TestAnthropicToOpenAICrossProtocolUsesMaxCompletionTokens(t *testing.T) {
	var seenBody []byte
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-o3","object":"chat.completion","model":"o3","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	}))
	defer oaiSrv.Close()

	st := newTestStore(t)
	_ = st.UpsertProvider(context.Background(), store.Provider{
		Name: "openai", Type: config.ProviderTypeOpenAI, BaseURL: oaiSrv.URL, APIKey: "sk-oai", Models: []string{"o3"}, Enabled: true,
	})
	gw, _ := NewGateway(GatewayConfig{Store: st})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, authedReq(http.MethodPost, "/anthropic/v1/messages", `{"model":"openai/o3","max_tokens":2048,"messages":[{"role":"user","content":"hi"}]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(seenBody), `"max_completion_tokens":2048`) || strings.Contains(string(seenBody), `"max_tokens"`) {
		t.Fatalf("expected max_completion_tokens=2048 (without max_tokens) for OpenAI upstream, got: %s", string(seenBody))
	}
}
