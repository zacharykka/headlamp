package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/netts"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/store"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeWhoIsClient struct {
	peers map[string]*apitype.WhoIsResponse
}

func (f *fakeWhoIsClient) WhoIs(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	if resp, ok := f.peers[remoteAddr]; ok {
		return resp, nil
	}
	// Allow matching on bare IP as well as ip:port.
	if host, _, found := strings.Cut(remoteAddr, ":"); found {
		if resp, ok := f.peers[host]; ok {
			return resp, nil
		}
	}
	return nil, local.ErrPeerNotFound
}

func TestEndToEndGatewayStack(t *testing.T) {
	// 1. Fake upstream servers for Anthropic, OpenAI, Gemini, and Ollama.
	var gotAnthropicKey, gotAnthropicBeta string
	anthropicUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAnthropicKey = r.Header.Get("x-api-key")
		gotAnthropicBeta = r.Header.Get("anthropic-beta")
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		events := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_e2e_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":1000,\"cache_read_input_tokens\":500,\"cache_creation_input_tokens\":300,\"cache_creation\":{\"ephemeral_5m_input_tokens\":200,\"ephemeral_1h_input_tokens\":100},\"output_tokens\":1}}}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig_abc123\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from Claude\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":200}}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for _, ev := range events {
			_, _ = io.WriteString(w, ev)
			flusher.Flush()
		}
	}))
	defer anthropicUpstream.Close()

	var gotOpenAIAuth string
	var gotOpenAIStreamOptions bool
	openAIUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOpenAIAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"include_usage":true`) {
			gotOpenAIStreamOptions = true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		chunks := []string{
			`data: {"id":"chatcmpl-e2e","object":"chat.completion.chunk","model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi from GPT"},"finish_reason":null}],"usage":null}` + "\n\n",
			`data: {"id":"chatcmpl-e2e","object":"chat.completion.chunk","model":"gpt-5","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n",
			`data: {"id":"chatcmpl-e2e","object":"chat.completion.chunk","model":"gpt-5","choices":[],"usage":{"prompt_tokens":2000,"completion_tokens":500,"total_tokens":2500,"prompt_tokens_details":{"cached_tokens":1000},"completion_tokens_details":{"reasoning_tokens":200}}}` + "\n\n",
			"data: [DONE]\n\n",
		}
		for _, ch := range chunks {
			_, _ = io.WriteString(w, ch)
			flusher.Flush()
		}
	}))
	defer openAIUpstream.Close()

	var gotGeminiKey, gotGeminiQueryKey string
	geminiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGeminiKey = r.Header.Get("x-goog-api-key")
		gotGeminiQueryKey = r.URL.Query().Get("key")
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, `data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hi from Gemini"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":2000,"cachedContentTokenCount":1000,"candidatesTokenCount":400,"thoughtsTokenCount":100,"totalTokenCount":2500}}`+"\n\n")
		flusher.Flush()
	}))
	defer geminiUpstream.Close()

	ollamaUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-ollama","object":"chat.completion","model":"qwen2.5-coder:32b","choices":[{"index":0,"message":{"role":"assistant","content":"Hi from Ollama"},"finish_reason":"stop"}],"usage":{"prompt_tokens":500,"completion_tokens":120,"total_tokens":620}}`)
	}))
	defer ollamaUpstream.Close()

	// 2. Write real config YAML & open SQLite + crypto + policy + metering + proxy.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "headlamp.db")
	cfgPath := filepath.Join(tmpDir, "headlamp.yaml")

	masterKeyBytes, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("HEADLAMP_MASTER_KEY", hex.EncodeToString(masterKeyBytes))

	yamlCfg := fmt.Sprintf(`
server:
  tsnet:
    enabled: false
    state_dir: %q
  local_listen: "127.0.0.1:0"
  dev_mode: false
policy:
  mode: hybrid
  rules:
    - name: deny-o3-global
      subject: "*"
      deny_models:
        - "openai/o3*"
      priority: 100
storage:
  driver: sqlite
  dsn: %q
providers:
  - name: anthropic
    type: anthropic
    base_url: %q
    api_key: "sk-ant-managed-secret"
    models: ["claude-sonnet-4-6"]
  - name: openai
    type: openai
    base_url: %q
    api_key: "sk-openai-managed-secret"
    models: ["gpt-5", "o3"]
  - name: gemini
    type: gemini
    base_url: %q
    api_key: "gemini-managed-secret"
    models: ["gemini-2.5-flash"]
  - name: ollama
    type: ollama
    base_url: %q
    models: ["qwen2.5-coder:32b"]
routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
audit:
  store_payloads: true
  retention_days: 7
`, tmpDir, dbPath, anthropicUpstream.URL, openAIUpstream.URL, geminiUpstream.URL, ollamaUpstream.URL)

	if err := os.WriteFile(cfgPath, []byte(yamlCfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	ctx := context.Background()
	st, _, _, err := openStore(ctx, cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer func() { _ = st.Close() }()

	if err := st.SyncConfig(ctx, cfg); err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	recorder := metering.NewRecorder(st, cfg.Audit, pricing, metering.RecorderOptions{
		DisableAutoPurge: true,
	})
	eval := policy.NewEvaluator(cfg.Policy, st)

	// Mock Tailnet WhoIs with Headscale v0.29.7 grants for Alice + tagged CI runner.
	whoIs := &fakeWhoIsClient{
		peers: map[string]*apitype.WhoIsResponse{
			"100.64.0.10": {
				Node: &tailcfg.Node{
					ComputedName: "alice-macbook",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName:   "alice@example.com",
					DisplayName: "Alice",
				},
				CapMap: tailcfg.PeerCapMap{
					policy.CapHeadlampGateway: []tailcfg.RawMessage{
						`{"role":"user","models":["anthropic/*","openai/*","gemini/*","ollama/*","team/*"]}`,
					},
				},
			},
			"100.64.0.20": {
				Node: &tailcfg.Node{
					ComputedName: "ci-runner-01",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")},
					Tags:         []string{"tag:ci-runner"},
				},
				// Headscale v0.29 reports synthetic tagged-devices profile for tagged nodes.
				UserProfile: &tailcfg.UserProfile{
					LoginName:   "tagged-devices",
					DisplayName: "tagged-devices",
				},
				CapMap: tailcfg.PeerCapMap{
					policy.CapHeadlampGateway: []tailcfg.RawMessage{
						`{"role":"user","models":["ollama/*"]}`,
					},
				},
			},
		},
	}

	authChain := buildAuthChain(cfg.Server, netts.NewTSNetAuthenticator(whoIs))
	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Telemetry:  &telemetryAdapter{recorder: recorder},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	handler := buildHandler(gw, eval, authChain)

	doReq := func(remoteAddr, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = remoteAddr
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// (a) Unauthenticated /healthz -> 200
	if rec := doReq("192.0.2.1:1234", http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}

	// (b) /whoami as Alice (Headscale grants applied)
	recWhoAlice := doReq("100.64.0.10:51234", http.MethodGet, "/whoami", "", nil)
	if recWhoAlice.Code != http.StatusOK {
		t.Fatalf("GET /whoami (alice) = %d: %s", recWhoAlice.Code, recWhoAlice.Body.String())
	}
	var whoAlice struct {
		Principal struct {
			Subject    string `json:"subject"`
			AuthSource string `json:"auth_source"`
		} `json:"principal"`
		Policy struct {
			GrantsApplied bool `json:"grants_applied"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(recWhoAlice.Body.Bytes(), &whoAlice); err != nil {
		t.Fatalf("decode /whoami alice: %v", err)
	}
	if whoAlice.Principal.Subject != "alice@example.com" || !whoAlice.Policy.GrantsApplied {
		t.Fatalf("unexpected /whoami alice: %+v", whoAlice)
	}

	// (c) /whoami as tagged CI runner -> subject MUST be tag:ci-runner, never tagged-devices
	recWhoCI := doReq("100.64.0.20:51235", http.MethodGet, "/whoami", "", nil)
	if recWhoCI.Code != http.StatusOK {
		t.Fatalf("GET /whoami (ci) = %d: %s", recWhoCI.Code, recWhoCI.Body.String())
	}
	if !strings.Contains(recWhoCI.Body.String(), `"subject":"tag:ci-runner"`) || strings.Contains(recWhoCI.Body.String(), `"tagged-devices"`) {
		t.Fatalf("unexpected /whoami ci body: %s", recWhoCI.Body.String())
	}

	// (d) Native Anthropic streaming passthrough (Claude Code)
	recAnth := doReq("100.64.0.10:51234", http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":1024,"stream":true,"messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{
			"x-api-key":         "placeholder-ignored",
			"anthropic-version": "2023-06-01",
			"anthropic-beta":    "prompt-caching-2024-07-31,interleaved-thinking-2025-05-14",
		},
	)
	if recAnth.Code != http.StatusOK {
		t.Fatalf("Anthropic stream = %d: %s", recAnth.Code, recAnth.Body.String())
	}
	if gotAnthropicKey != "sk-ant-managed-secret" {
		t.Fatalf("upstream x-api-key = %q, want managed key", gotAnthropicKey)
	}
	if gotAnthropicBeta != "prompt-caching-2024-07-31,interleaved-thinking-2025-05-14" {
		t.Fatalf("anthropic-beta mutated: %q", gotAnthropicBeta)
	}
	if !strings.Contains(recAnth.Body.String(), "sig_abc123") || !strings.Contains(recAnth.Body.String(), "Hello from Claude") {
		t.Fatalf("Anthropic SSE missing expected frames: %s", recAnth.Body.String())
	}

	// (e) Native OpenAI Chat streaming passthrough (verifies stream_options injection)
	recOAI := doReq("100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"Authorization": "Bearer dummy"},
	)
	if recOAI.Code != http.StatusOK {
		t.Fatalf("OpenAI stream = %d: %s", recOAI.Code, recOAI.Body.String())
	}
	if gotOpenAIAuth != "Bearer sk-openai-managed-secret" || !gotOpenAIStreamOptions {
		t.Fatalf("OpenAI upstream auth=%q include_usage=%v", gotOpenAIAuth, gotOpenAIStreamOptions)
	}

	// (f) Cross-protocol streaming translation: OpenAI client -> virtual route "team/coding" (Anthropic upstream)
	recXlat := doReq("100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"team/coding","stream":true,"messages":[{"role":"user","content":"write go"}]}`,
		map[string]string{"Authorization": "Bearer dummy"},
	)
	if recXlat.Code != http.StatusOK {
		t.Fatalf("Translated stream = %d: %s", recXlat.Code, recXlat.Body.String())
	}
	if !strings.Contains(recXlat.Body.String(), `"chat.completion.chunk"`) || !strings.Contains(recXlat.Body.String(), "Hello from Claude") {
		t.Fatalf("Translated OpenAI SSE unexpected: %s", recXlat.Body.String())
	}

	// (g) Native Gemini streaming (?key= stripped, x-goog-api-key injected)
	recGem := doReq("100.64.0.10:51234", http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=client-dummy",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil,
	)
	if recGem.Code != http.StatusOK {
		t.Fatalf("Gemini stream = %d: %s", recGem.Code, recGem.Body.String())
	}
	if gotGeminiKey != "gemini-managed-secret" || gotGeminiQueryKey != "" {
		t.Fatalf("Gemini upstream key=%q query_key=%q", gotGeminiKey, gotGeminiQueryKey)
	}

	// (h) Tagged CI runner allowed Ollama (zero cost), denied Anthropic (403)
	recCIAllow := doReq("100.64.0.20:51235", http.MethodPost, "/v1/chat/completions",
		`{"model":"ollama/qwen2.5-coder:32b","messages":[{"role":"user","content":"lint"}]}`,
		nil,
	)
	if recCIAllow.Code != http.StatusOK {
		t.Fatalf("CI Ollama = %d: %s", recCIAllow.Code, recCIAllow.Body.String())
	}

	recCIDeny := doReq("100.64.0.20:51235", http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":64,"messages":[{"role":"user","content":"nope"}]}`,
		nil,
	)
	if recCIDeny.Code != http.StatusForbidden {
		t.Fatalf("CI Anthropic = %d, want 403", recCIDeny.Code)
	}

	// (i) Explicit Deny Wins: Alice denied openai/o3 despite openai/* grant
	recDenyO3 := doReq("100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"o3","messages":[{"role":"user","content":"nope"}]}`,
		nil,
	)
	if recDenyO3.Code != http.StatusForbidden {
		t.Fatalf("Alice o3 = %d, want 403", recDenyO3.Code)
	}

	// (j) Flush async metering recorder and verify persisted usage_logs, USD costs, and audit payloads.
	if err := recorder.Close(ctx); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{})
	if err != nil {
		t.Fatalf("QueryUsageLogs: %v", err)
	}
	// 5 successful upstream calls: Anthropic native, OpenAI native, Translated team/coding, Gemini native, CI Ollama.
	if len(logs) != 5 {
		t.Fatalf("len(usage_logs) = %d, want 5", len(logs))
	}

	byModel := make(map[string]store.UsageLog, len(logs))
	for _, l := range logs {
		byModel[l.RequestedModel] = l
	}

	// Anthropic claude-sonnet-4-6:
	// (1000*3.0 + 500*0.30 + 200*3.75 + 100*6.00 + 200*15.0) / 1M = (3000+150+750+600+3000)/1M = 0.0075
	if got := byModel["claude-sonnet-4-6"]; math.Abs(got.CostUSD-0.0075) > 1e-9 || got.Subject != "alice@example.com" {
		t.Fatalf("anthropic usage log mismatch: %+v", got)
	}

	// Translated team/coding -> anthropic/claude-sonnet-4-6: same upstream tokens & cost, Translated=true
	if got := byModel["team/coding"]; !got.Translated || got.ProviderName != "anthropic" || math.Abs(got.CostUSD-0.0075) > 1e-9 {
		t.Fatalf("translated usage log mismatch: %+v", got)
	}

	// OpenAI gpt-5:
	// uncached_in = 1000*1.25 = 1250; cache_read = 1000*0.125 = 125; out = 500*10.0 = 5000 => 6375/1M = 0.006375
	if got := byModel["gpt-5"]; math.Abs(got.CostUSD-0.006375) > 1e-9 || got.ReasoningTokens != 200 {
		t.Fatalf("openai usage log mismatch: %+v", got)
	}

	// Gemini gemini-2.5-flash:
	// uncached_in = 1000*0.30 = 300; cache_read = 1000*0.03 = 30; billable_out = (400+100)*2.50 = 1250 => 1580/1M = 0.00158
	if got := byModel["gemini-2.5-flash"]; math.Abs(got.CostUSD-0.00158) > 1e-9 || got.ReasoningTokens != 100 {
		t.Fatalf("gemini usage log mismatch: %+v", got)
	}

	// Ollama qwen2.5-coder:32b: tagged CI runner, zero cost
	if got := byModel["ollama/qwen2.5-coder:32b"]; got.Subject != "tag:ci-runner" || got.CostUSD != 0 || got.InputTokens != 500 {
		t.Fatalf("ollama usage log mismatch: %+v", got)
	}

	// Verify audit payload stored with redacted Authorization header.
	payload, err := st.GetAuditPayloadByUsageLogID(ctx, byModel["gpt-5"].ID)
	if err != nil {
		t.Fatalf("GetAuditPayloadByUsageLogID(gpt-5): %v", err)
	}
	if payload.RequestHeaders["Authorization"] != "[REDACTED]" {
		t.Fatalf("expected redacted Authorization header in audit_payloads, got %+v", payload.RequestHeaders)
	}

	// (k) Run `headlamp usage` CLI command against the populated SQLite DB.
	var stdout, stderr bytes.Buffer
	if err := run([]string{"usage", "-config", cfgPath, "-limit", "10"}, &stdout, &stderr); err != nil {
		t.Fatalf("run usage: %v (stderr=%s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "alice@example.com") || !strings.Contains(out, "tag:ci-runner") || !strings.Contains(out, "Total: 5 requests") {
		t.Fatalf("unexpected usage CLI output:\n%s", out)
	}
}

func TestCLIInitAndVersion(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "headlamp.yaml")
	var stdout, stderr bytes.Buffer

	if err := run([]string{"init", "-out", outPath}, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	// Second init without -force must fail.
	if err := run([]string{"init", "-out", outPath}, &stdout, &stderr); err == nil {
		t.Fatal("expected init without -force to refuse overwrite")
	}
	// With -force must succeed.
	if err := run([]string{"init", "-out", outPath, "-force"}, &stdout, &stderr); err != nil {
		t.Fatalf("init -force failed: %v", err)
	}

	// Starter config must parse and validate cleanly via config.Load.
	if _, err := config.Load(outPath); err != nil {
		t.Fatalf("starter config failed config.Load: %v", err)
	}

	stdout.Reset()
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "headlamp ") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}
