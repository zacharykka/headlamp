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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/api"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/guardrail"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/netts"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/quota"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/web"
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
	if host, _, found := strings.Cut(remoteAddr, ":"); found {
		if resp, ok := f.peers[host]; ok {
			return resp, nil
		}
	}
	return nil, local.ErrPeerNotFound
}

func TestEndToEndGatewayStack(t *testing.T) {
	// 1. Fake upstream servers for Anthropic, OpenAI, Gemini, and Ollama.
	var (
		mu                        sync.Mutex
		gotAnthropicKey           string
		gotAnthropicBeta          string
		gotOpenAIAuth             string
		gotOpenAIStreamOptions    bool
		gotOpenAIAnthropicReqBody map[string]any
		gotGeminiKey              string
		gotGeminiQueryKey         string
	)

	anthropicUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAnthropicKey = r.Header.Get("x-api-key")
		gotAnthropicBeta = r.Header.Get("anthropic-beta")
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Upstream-Provider", "anthropic")
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

	openAIUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)

		mu.Lock()
		gotOpenAIAuth = r.Header.Get("Authorization")
		if strings.Contains(string(body), `"include_usage":true`) {
			gotOpenAIStreamOptions = true
		}
		if _, hasMCT := parsed["max_completion_tokens"]; hasMCT {
			gotOpenAIAnthropicReqBody = parsed
		}
		mu.Unlock()

		// Non-2xx error simulation for P1-5 audit body/header test.
		if model, _ := parsed["model"].(string); model == "gpt-4.1-err" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Err-Id", "err-req-42")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"upstream bad input","type":"invalid_request_error"}}`)
			return
		}

		// Non-streaming OpenAI response (used by P1-1 Anthropic->OpenAI & alias fallback check).
		if streamVal, _ := parsed["stream"].(bool); !streamVal {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Provider", "openai")
			_, _ = io.WriteString(w, `{"id":"chatcmpl-nonstream","object":"chat.completion","model":"gpt-5","choices":[{"index":0,"message":{"role":"assistant","content":"Non-stream GPT"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Upstream-Req-Id", "up-oai-999")
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

	geminiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotGeminiKey = r.Header.Get("x-goog-api-key")
		gotGeminiQueryKey = r.URL.Query().Get("key")
		mu.Unlock()
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

	// 2. Write real grants-only YAML config & initialize SQLite + crypto + policy + metering + proxy.
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
  dev_mode: true
  dev_user: "dev@local"
  dev_roles: ["user"]
  dev_allow_header_override: false
  api_tokens:
    - name: local-ci
      token: "hl_static_token_123"
      subject: "tag:local-ci"
      roles: ["user"]
      allow_models: ["ollama/*", "gemini/*"]
      deny_models: ["openai/*"]
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
    models: ["gpt-5", "o3", "gpt-4.1-err"]
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
  - alias: "team/oai-from-claude"
    provider: openai
    model: "gpt-5"
  - alias: "team/o3-only"
    provider: openai
    model: "o3"
  - alias: "team/o3-with-fallback"
    provider: openai
    model: "o3"
    fallbacks:
      - provider: openai
        model: "gpt-5"
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
	eval := policy.NewEvaluator()

	// Mock Tailnet WhoIs with Headscale v0.29.7 grants for Alice (with deny_models: ["openai/o3*"]) + tagged CI runner.
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
						`{"role":"user","models":["anthropic/*","openai/*","gemini/*","ollama/*","team/*"],"deny_models":["openai/o3*"]}`,
					},
				},
			},
			"100.64.0.20": {
				Node: &tailcfg.Node{
					ComputedName: "ci-runner-01",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")},
					Tags:         []string{"tag:ci-runner"},
				},
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

	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Telemetry:  &telemetryAdapter{recorder: recorder},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// P0-2 listener isolation: separate tailnetHandler (TSNet ONLY) vs localHandler (tokens + dev_mock).
	tailnetHandler := buildHandler(gw, nil, eval, netts.NewTSNetAuthenticator(whoIs))
	localHandler := buildHandler(gw, nil, eval, buildLocalAuthChain(cfg.Server))

	doReq := func(h http.Handler, remoteAddr, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
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
		h.ServeHTTP(rec, req)
		return rec
	}

	// (a) Unauthenticated /healthz -> 200 on both listeners
	if rec := doReq(tailnetHandler, "192.0.2.1:1234", http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz (tailnet) = %d, want 200", rec.Code)
	}

	// (b) P0-2 isolation: tailnetHandler MUST reject non-tailnet callers even with a valid static API token or dev headers.
	recIso := doReq(tailnetHandler, "192.0.2.1:1234", http.MethodGet, "/whoami", "", map[string]string{
		"Authorization":        "Bearer hl_static_token_123",
		"X-Headlamp-Dev-Roles": "admin",
	})
	if recIso.Code != http.StatusUnauthorized {
		t.Fatalf("P0-2: tailnetHandler must reject non-tailnet caller, got %d: %s", recIso.Code, recIso.Body.String())
	}

	// (c) P0-2 dev header spoofing blocked by default (dev_allow_header_override=false) on localHandler.
	recDevSpoof := doReq(localHandler, "127.0.0.1:54321", http.MethodGet, "/whoami", "", map[string]string{
		"X-Headlamp-Dev-User":  "spoofed-admin@example.com",
		"X-Headlamp-Dev-Roles": "admin",
	})
	if recDevSpoof.Code != http.StatusOK {
		t.Fatalf("localHandler dev /whoami = %d: %s", recDevSpoof.Code, recDevSpoof.Body.String())
	}
	var devWho struct {
		Principal struct {
			Subject string `json:"subject"`
		} `json:"principal"`
		IsAdmin bool `json:"is_admin"`
	}
	if err := json.Unmarshal(recDevSpoof.Body.Bytes(), &devWho); err != nil {
		t.Fatalf("decode local /whoami: %v", err)
	}
	if devWho.Principal.Subject != "dev@local" || devWho.IsAdmin {
		t.Fatalf("P0-2: X-Headlamp-Dev-* headers must be ignored by default, got %+v", devWho)
	}

	// (d) Static API token with synthesized grants on localHandler (including Gemini ?key= auth).
	recLocalTok := doReq(localHandler, "127.0.0.1:54321", http.MethodPost,
		"/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=hl_static_token_123",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil,
	)
	if recLocalTok.Code != http.StatusOK {
		t.Fatalf("localHandler Gemini ?key= token auth = %d: %s", recLocalTok.Code, recLocalTok.Body.String())
	}

	// (e) /whoami on tailnetHandler as Alice (Headscale grants applied) & tagged CI runner
	recWhoAlice := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodGet, "/whoami", "", nil)
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

	recWhoCI := doReq(tailnetHandler, "100.64.0.20:51235", http.MethodGet, "/whoami", "", nil)
	if recWhoCI.Code != http.StatusOK || !strings.Contains(recWhoCI.Body.String(), `"subject":"tag:ci-runner"`) || strings.Contains(recWhoCI.Body.String(), `"tagged-devices"`) {
		t.Fatalf("unexpected /whoami ci: %d %s", recWhoCI.Code, recWhoCI.Body.String())
	}

	// (f) Native Anthropic streaming passthrough (Claude Code)
	recAnth := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/anthropic/v1/messages",
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
	if gotAnthropicKey != "sk-ant-managed-secret" || gotAnthropicBeta != "prompt-caching-2024-07-31,interleaved-thinking-2025-05-14" {
		t.Fatalf("Anthropic upstream headers key=%q beta=%q", gotAnthropicKey, gotAnthropicBeta)
	}
	if !strings.Contains(recAnth.Body.String(), "sig_abc123") || !strings.Contains(recAnth.Body.String(), "Hello from Claude") {
		t.Fatalf("Anthropic SSE missing expected frames: %s", recAnth.Body.String())
	}

	// (g) Native OpenAI Chat streaming passthrough (verifies stream_options injection + audit headers/redacted)
	recOAI := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"Authorization": "Bearer dummy"},
	)
	if recOAI.Code != http.StatusOK {
		t.Fatalf("OpenAI stream = %d: %s", recOAI.Code, recOAI.Body.String())
	}
	if gotOpenAIAuth != "Bearer sk-openai-managed-secret" || !gotOpenAIStreamOptions {
		t.Fatalf("OpenAI upstream auth=%q include_usage=%v", gotOpenAIAuth, gotOpenAIStreamOptions)
	}

	// (h) Cross-protocol streaming translation: OpenAI client -> virtual route "team/coding" (Anthropic upstream)
	recXlat := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"team/coding","stream":true,"messages":[{"role":"user","content":"write go"}]}`,
		map[string]string{"Authorization": "Bearer dummy"},
	)
	if recXlat.Code != http.StatusOK || !strings.Contains(recXlat.Body.String(), "Hello from Claude") {
		t.Fatalf("Translated OpenAI->Anthropic stream = %d: %s", recXlat.Code, recXlat.Body.String())
	}

	// (i) P1-1: Anthropic client -> OpenAI upstream sends max_completion_tokens (not deprecated max_tokens)
	recAnthToOAI := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/anthropic/v1/messages",
		`{"model":"team/oai-from-claude","max_tokens":512,"messages":[{"role":"user","content":"hi gpt-5"}]}`,
		map[string]string{"anthropic-version": "2023-06-01"},
	)
	if recAnthToOAI.Code != http.StatusOK {
		t.Fatalf("P1-1 Anthropic->OpenAI = %d: %s", recAnthToOAI.Code, recAnthToOAI.Body.String())
	}
	if gotOpenAIAnthropicReqBody == nil || gotOpenAIAnthropicReqBody["max_completion_tokens"] != float64(512) {
		t.Fatalf("P1-1: expected max_completion_tokens=512 on OpenAI upstream, got %#v", gotOpenAIAnthropicReqBody)
	}
	if _, hasLegacy := gotOpenAIAnthropicReqBody["max_tokens"]; hasLegacy {
		t.Fatalf("P1-1: deprecated max_tokens must not be sent to OpenAI upstream: %#v", gotOpenAIAnthropicReqBody)
	}

	// (j) P1-2: Virtual alias pointing only to denied openai/o3 returns 403;
	// virtual alias with primary openai/o3 + fallback openai/gpt-5 skips denied o3 and succeeds on gpt-5!
	recAliasDeny := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"team/o3-only","messages":[{"role":"user","content":"bypass?"}]}`,
		nil,
	)
	if recAliasDeny.Code != http.StatusForbidden {
		t.Fatalf("P1-2: team/o3-only must be denied (403), got %d: %s", recAliasDeny.Code, recAliasDeny.Body.String())
	}
	recAliasFallback := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"team/o3-with-fallback","messages":[{"role":"user","content":"fallback please"}]}`,
		nil,
	)
	if recAliasFallback.Code != http.StatusOK || !strings.Contains(recAliasFallback.Body.String(), "Non-stream GPT") {
		t.Fatalf("P1-2: team/o3-with-fallback should skip denied o3 and succeed on gpt-5, got %d: %s", recAliasFallback.Code, recAliasFallback.Body.String())
	}

	// (k) Native Gemini streaming (?key= stripped, x-goog-api-key injected)
	recGem := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=client-dummy",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil,
	)
	if recGem.Code != http.StatusOK || gotGeminiKey != "gemini-managed-secret" || gotGeminiQueryKey != "" {
		t.Fatalf("Gemini stream = %d key=%q qkey=%q", recGem.Code, gotGeminiKey, gotGeminiQueryKey)
	}

	// (l) P1-5: Non-2xx upstream error stores error response body & headers in audit_payloads
	recErr := doReq(tailnetHandler, "100.64.0.10:51234", http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4.1-err","messages":[{"role":"user","content":"trigger 400"}]}`,
		map[string]string{"Authorization": "Bearer dummy"},
	)
	if recErr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 from gpt-4.1-err, got %d", recErr.Code)
	}

	// (m) Tagged CI runner allowed Ollama (zero cost), denied Anthropic (403)
	recCIAllow := doReq(tailnetHandler, "100.64.0.20:51235", http.MethodPost, "/v1/chat/completions",
		`{"model":"ollama/qwen2.5-coder:32b","messages":[{"role":"user","content":"lint"}]}`,
		nil,
	)
	if recCIAllow.Code != http.StatusOK {
		t.Fatalf("CI Ollama = %d: %s", recCIAllow.Code, recCIAllow.Body.String())
	}
	if recCIDeny := doReq(tailnetHandler, "100.64.0.20:51235", http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-sonnet-4-6","max_tokens":64,"messages":[{"role":"user","content":"nope"}]}`,
		nil,
	); recCIDeny.Code != http.StatusForbidden {
		t.Fatalf("CI Anthropic = %d, want 403", recCIDeny.Code)
	}

	// (n) Flush async metering recorder and verify usage_logs, USD costs, and P1-5 audit_payloads.
	if err := recorder.Close(ctx); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{})
	if err != nil {
		t.Fatalf("QueryUsageLogs: %v", err)
	}
	// 9 upstream invocations:
	// localToken Gemini, Anthropic native, OpenAI native, team/coding, team/oai-from-claude,
	// team/o3-with-fallback, Alice Gemini, gpt-4.1-err (400), CI Ollama.
	if len(logs) != 9 {
		t.Fatalf("len(usage_logs) = %d, want 9", len(logs))
	}

	byModel := make(map[string]store.UsageLog, len(logs))
	for _, l := range logs {
		if l.Subject == "alice@example.com" || l.Subject == "tag:ci-runner" {
			byModel[l.RequestedModel] = l
		}
	}

	if got := byModel["claude-sonnet-4-6"]; math.Abs(got.CostUSD-0.0075) > 1e-9 {
		t.Fatalf("anthropic usage log mismatch: %+v", got)
	}
	if got := byModel["team/coding"]; !got.Translated || got.ProviderName != "anthropic" || math.Abs(got.CostUSD-0.0075) > 1e-9 {
		t.Fatalf("translated usage log mismatch: %+v", got)
	}
	if got := byModel["gpt-5"]; math.Abs(got.CostUSD-0.006375) > 1e-9 || got.ReasoningTokens != 200 {
		t.Fatalf("openai usage log mismatch: %+v", got)
	}
	if got := byModel["team/o3-with-fallback"]; got.UpstreamModel != "gpt-5" {
		t.Fatalf("P1-2 fallback usage log expected upstream gpt-5, got %+v", got)
	}
	if got := byModel["gemini-2.5-flash"]; math.Abs(got.CostUSD-0.00158) > 1e-9 || got.ReasoningTokens != 100 {
		t.Fatalf("gemini usage log mismatch: %+v", got)
	}
	if got := byModel["ollama/qwen2.5-coder:32b"]; got.Subject != "tag:ci-runner" || got.CostUSD != 0 {
		t.Fatalf("ollama usage log mismatch: %+v", got)
	}

	// P1-5: verify 2xx audit payload has populated ResponseHeaders AND Redacted=true.
	oaiPayload, err := st.GetAuditPayloadByUsageLogID(ctx, byModel["gpt-5"].ID)
	if err != nil {
		t.Fatalf("GetAuditPayloadByUsageLogID(gpt-5): %v", err)
	}
	if oaiPayload.RequestHeaders["Authorization"] != "[REDACTED]" || !oaiPayload.Redacted {
		t.Fatalf("P1-5: expected Redacted=true and redacted Authorization, got %+v", oaiPayload)
	}
	if oaiPayload.ResponseHeaders["X-Upstream-Req-Id"] != "up-oai-999" {
		t.Fatalf("P1-5: expected populated ResponseHeaders, got %+v", oaiPayload.ResponseHeaders)
	}

	// P1-5: verify non-2xx audit payload stores error response body AND headers.
	errPayload, err := st.GetAuditPayloadByUsageLogID(ctx, byModel["gpt-4.1-err"].ID)
	if err != nil {
		t.Fatalf("GetAuditPayloadByUsageLogID(gpt-4.1-err): %v", err)
	}
	if !strings.Contains(errPayload.ResponseBody, "upstream bad input") {
		t.Fatalf("P1-5: expected non-2xx error body in audit_payloads, got %q", errPayload.ResponseBody)
	}
	if errPayload.ResponseHeaders["X-Upstream-Err-Id"] != "err-req-42" || !errPayload.Redacted {
		t.Fatalf("P1-5: expected non-2xx response headers and Redacted=true, got %+v", errPayload)
	}

	// (o) Run `headlamp usage` CLI command against the populated SQLite DB.
	var stdout, stderr bytes.Buffer
	if err := run([]string{"usage", "-config", cfgPath, "-limit", "10"}, &stdout, &stderr); err != nil {
		t.Fatalf("run usage: %v (stderr=%s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "alice@example.com") || !strings.Contains(out, "tag:ci-runner") || !strings.Contains(out, "Total: 9 requests") {
		t.Fatalf("unexpected usage CLI output:\n%s", out)
	}
}

func TestCLIInitAndVersion(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "headlamp.yaml")
	var stdout, stderr bytes.Buffer

	if err := run([]string{"init", "-out", outPath}, &stdout, &stderr); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if err := run([]string{"init", "-out", outPath}, &stdout, &stderr); err == nil {
		t.Fatal("expected init without -force to refuse overwrite")
	}
	if err := run([]string{"init", "-out", outPath, "-force"}, &stdout, &stderr); err != nil {
		t.Fatalf("init -force failed: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read starter config: %v", err)
	}
	if strings.Contains(string(raw), "\npolicy:") || strings.Contains(string(raw), "priority:") {
		t.Fatalf("starter config must not contain legacy policy/priority blocks:\n%s", string(raw))
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

func TestM2FullStackGovernanceAndUI(t *testing.T) {
	// 1. Mock OpenAI upstream capturing every forwarded request body.
	var (
		upstreamMu     sync.Mutex
		upstreamBodies []string
	)
	openAIUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		upstreamBodies = append(upstreamBodies, string(body))
		upstreamMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		// On gpt-5: 1000 input ($0.00125) + 500 output ($0.005) = $0.00625 per call.
		_, _ = io.WriteString(w, `{"id":"chatcmpl-m2","object":"chat.completion","model":"gpt-5","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`)
	}))
	defer openAIUpstream.Close()

	// 2. Mock webhook receiver verifying HMAC-SHA256 signatures on every delivery.
	const webhookSecret = "whsec_m2_e2e_signing_secret"
	type receivedWebhook struct {
		Event    string
		Body     string
		SigValid bool
	}
	var (
		whMu   sync.Mutex
		whEvts []receivedWebhook
	)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-Headlamp-Signature")
		whMu.Lock()
		whEvts = append(whEvts, receivedWebhook{
			Event:    r.Header.Get("X-Headlamp-Event"),
			Body:     string(raw),
			SigValid: guardrail.VerifySignature(webhookSecret, raw, sig),
		})
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer webhookServer.Close()

	// 3. Configure and assemble the complete M2 stack identically to runServe.
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
  dev_mode: true
  dev_user: "dev@local"
storage:
  driver: sqlite
  dsn: %q
providers:
  - name: openai
    type: openai
    base_url: %q
    api_key: "sk-openai-m2-secret"
    models: ["gpt-5"]
guardrails:
  builtin_defaults: true
audit:
  store_payloads: false
  retention_days: 7
`, tmpDir, dbPath, openAIUpstream.URL)

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

	activeAuditCfg, err := loadActiveAuditConfig(ctx, st, cfg.Audit)
	if err != nil {
		t.Fatalf("loadActiveAuditConfig: %v", err)
	}
	if activeAuditCfg.StorePayloads || activeAuditCfg.RetentionDays != 7 {
		t.Fatalf("initial activeAuditCfg = %+v, want StorePayloads=false RetentionDays=7", activeAuditCfg)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	grEngine, err := guardrail.NewEngine(guardrail.EngineConfig{Store: st})
	if err != nil {
		t.Fatalf("guardrail.NewEngine: %v", err)
	}
	quotaMgr := quota.NewManager(st, quota.WithOnAlert(func(ev quota.AlertEvent) {
		grEngine.Emit(ev.EventType, ev)
	}))
	recorder := metering.NewRecorder(st, activeAuditCfg, pricing, metering.RecorderOptions{
		DisableAutoPurge: true,
		OnRecorded:       quotaMgr.OnUsageRecorded,
	})
	eval := policy.NewEvaluator()

	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Telemetry:  &telemetryAdapter{recorder: recorder},
		Quota:      &quotaLimiterAdapter{mgr: quotaMgr},
		Guardrails: &guardrailInspectorAdapter{engine: grEngine},
		Events:     grEngine,
	})
	if err != nil {
		t.Fatalf("proxy.NewGateway: %v", err)
	}

	staticFS, err := web.DistFS()
	if err != nil {
		t.Fatalf("web.DistFS: %v", err)
	}
	apiHandler, err := api.NewHandler(api.Config{
		Store:           st,
		Policy:          eval,
		Pricing:         pricing,
		AuditController: recorder,
		BudgetReporter:  &budgetReporterAdapter{mgr: quotaMgr},
		GuardrailTester: &guardrailTesterAdapter{engine: grEngine},
		WebhookTester:   &webhookTesterAdapter{engine: grEngine},
		StaticFS:        staticFS,
	})
	if err != nil {
		t.Fatalf("api.NewHandler: %v", err)
	}

	whoIs := &fakeWhoIsClient{
		peers: map[string]*apitype.WhoIsResponse{
			"100.64.0.1": {
				Node: &tailcfg.Node{
					ComputedName: "admin-workstation",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName:   "admin@example.com",
					DisplayName: "Admin",
				},
				CapMap: tailcfg.PeerCapMap{
					policy.CapHeadlampGateway: []tailcfg.RawMessage{
						`{"role":"admin","models":["**"]}`,
					},
				},
			},
			"100.64.0.10": {
				Node: &tailcfg.Node{
					ComputedName: "alice-laptop",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName:   "alice@example.com",
					DisplayName: "Alice",
				},
				CapMap: tailcfg.PeerCapMap{
					policy.CapHeadlampGateway: []tailcfg.RawMessage{
						`{"role":"user","models":["openai/*"]}`,
					},
				},
			},
		},
	}

	handler := buildHandler(gw, apiHandler, eval, netts.NewTSNetAuthenticator(whoIs))

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

	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin"}

	// (a) Embedded SPA routing vs JSON API 404 vs unauthenticated protection.
	if rec := doReq("192.0.2.1:9999", http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz unauthenticated = %d, want 200", rec.Code)
	}
	if rec := doReq("192.0.2.1:9999", http.MethodGet, "/", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET / unauthenticated = %d, want 401", rec.Code)
	}
	recRoot := doReq("100.64.0.10:50001", http.MethodGet, "/", "", nil)
	if recRoot.Code != http.StatusOK || !strings.Contains(recRoot.Header().Get("Content-Type"), "text/html") || !strings.Contains(strings.ToLower(recRoot.Body.String()), "<html") {
		t.Fatalf("GET / SPA failed: code=%d ct=%q body=%q", recRoot.Code, recRoot.Header().Get("Content-Type"), recRoot.Body.String())
	}
	recRoute := doReq("100.64.0.1:50002", http.MethodGet, "/security", "", nil)
	if recRoute.Code != http.StatusOK || !strings.Contains(recRoute.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET /security SPA fallback failed: code=%d ct=%q", recRoute.Code, recRoute.Header().Get("Content-Type"))
	}
	recAPINotFound := doReq("100.64.0.1:50002", http.MethodGet, "/api/v1/unknown", "", nil)
	if recAPINotFound.Code != http.StatusNotFound || !strings.Contains(recAPINotFound.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("GET /api/v1/unknown must return 404 JSON, got code=%d ct=%q body=%q", recAPINotFound.Code, recAPINotFound.Header().Get("Content-Type"), recAPINotFound.Body.String())
	}

	// (b) User /api/v1/me, admin RBAC enforcement, and CSRF protection.
	recMe := doReq("100.64.0.10:50001", http.MethodGet, "/api/v1/me", "", nil)
	if recMe.Code != http.StatusOK || !strings.Contains(recMe.Body.String(), `"alice@example.com"`) || !strings.Contains(recMe.Body.String(), `"is_admin":false`) {
		t.Fatalf("GET /api/v1/me (alice) = %d: %s", recMe.Code, recMe.Body.String())
	}
	if recDeny := doReq("100.64.0.10:50001", http.MethodGet, "/api/v1/admin/overview", "", nil); recDeny.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET /api/v1/admin/overview = %d, want 403", recDeny.Code)
	}
	if recCSRF := doReq("100.64.0.1:50002", http.MethodPut, "/api/v1/admin/settings/audit", `{"store_payloads":true,"retention_days":14}`, map[string]string{"Sec-Fetch-Site": "cross-site"}); recCSRF.Code != http.StatusForbidden {
		t.Fatalf("cross-site PUT audit settings = %d, want 403", recCSRF.Code)
	}

	// (c) Enable audit payload storage live via Admin API and confirm runtime + DB persistence.
	recAudit := doReq("100.64.0.1:50002", http.MethodPut, "/api/v1/admin/settings/audit", `{"store_payloads":true,"retention_days":14}`, sameOrigin)
	if recAudit.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/admin/settings/audit = %d: %s", recAudit.Code, recAudit.Body.String())
	}
	if got := recorder.AuditConfig(); !got.StorePayloads || got.RetentionDays != 14 {
		t.Fatalf("live AuditConfig not updated: %+v", got)
	}
	reloadedAudit, err := loadActiveAuditConfig(ctx, st, cfg.Audit)
	if err != nil || !reloadedAudit.StorePayloads || reloadedAudit.RetentionDays != 14 {
		t.Fatalf("persisted audit settings reload failed: %+v err=%v", reloadedAudit, err)
	}

	// (d) Configure async webhook, custom guardrail rule, and Alice's daily USD budget via Admin API.
	whBody := fmt.Sprintf(`{"id":"m2-alerts","name":"M2 Alerts","url":%q,"type":"async_event","secret":%q,"events":["guardrail.triggered","budget.threshold","budget.exceeded"],"timeout_ms":2000,"fail_open":true,"enabled":true}`, webhookServer.URL, webhookSecret)
	if rec := doReq("100.64.0.1:50002", http.MethodPost, "/api/v1/admin/webhooks", whBody, sameOrigin); rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/admin/webhooks = %d: %s", rec.Code, rec.Body.String())
	}
	recPing := doReq("100.64.0.1:50002", http.MethodPost, "/api/v1/admin/webhooks/m2-alerts/test", `{}`, sameOrigin)
	if recPing.Code != http.StatusOK || !strings.Contains(recPing.Body.String(), `"ok":true`) {
		t.Fatalf("POST /api/v1/admin/webhooks/m2-alerts/test = %d: %s", recPing.Code, recPing.Body.String())
	}

	if rec := doReq("100.64.0.1:50002", http.MethodPost, "/api/v1/admin/guardrails", `{"id":"custom-corp-token","name":"Corp Token","category":"secret","pattern":"CORP_[0-9]{6}","action":"redact","enabled":true}`, sameOrigin); rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/admin/guardrails = %d: %s", rec.Code, rec.Body.String())
	}
	recGRTest := doReq("100.64.0.1:50002", http.MethodPost, "/api/v1/admin/guardrails/test", `{"text":"leak AKIAIOSFODNN7EXAMPLE and CORP_987654"}`, sameOrigin)
	if recGRTest.Code != http.StatusOK || !strings.Contains(recGRTest.Body.String(), `"action":"redact"`) || strings.Contains(recGRTest.Body.String(), "AKIAIOSFODNN7EXAMPLE") || strings.Contains(recGRTest.Body.String(), "CORP_987654") {
		t.Fatalf("POST /api/v1/admin/guardrails/test = %d: %s", recGRTest.Code, recGRTest.Body.String())
	}

	// Daily USD cap $0.005 (< $0.00625 cost of 1 gpt-5 request) with 50% soft alert.
	if rec := doReq("100.64.0.1:50002", http.MethodPost, "/api/v1/admin/budgets", `{"scope":"alice@example.com","rpm":20,"tpm":100000,"max_concurrent":5,"daily_usd":0.005,"soft_alert_pct":50,"enabled":true}`, sameOrigin); rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/admin/budgets = %d: %s", rec.Code, rec.Body.String())
	}

	// (e) Live LLM call with embedded AWS key + custom secret -> redacted BEFORE upstream, logged, webhook emitted.
	recRedact := doReq("100.64.0.10:50001", http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-5","messages":[{"role":"user","content":"use key AKIAIOSFODNN7EXAMPLE and CORP_987654"}]}`,
		nil,
	)
	if recRedact.Code != http.StatusOK {
		t.Fatalf("redacted LLM call = %d: %s", recRedact.Code, recRedact.Body.String())
	}
	upstreamMu.Lock()
	if len(upstreamBodies) != 1 {
		upstreamMu.Unlock()
		t.Fatalf("expected 1 upstream call, got %d", len(upstreamBodies))
	}
	seenUpstream := upstreamBodies[0]
	upstreamMu.Unlock()
	if strings.Contains(seenUpstream, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(seenUpstream, "CORP_987654") || !strings.Contains(seenUpstream, "[REDACTED") {
		t.Fatalf("upstream received unredacted secret: %s", seenUpstream)
	}

	// (f) Live LLM call with PEM private key -> blocked (400), upstream NOT called, raw key NOT stored in audit_payloads.
	const pemSecret = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890secretpemmaterial\n-----END RSA PRIVATE KEY-----"
	pemReq, _ := json.Marshal(map[string]any{
		"model":    "gpt-5",
		"messages": []map[string]string{{"role": "user", "content": pemSecret}},
	})
	recBlock := doReq("100.64.0.10:50001", http.MethodPost, "/v1/chat/completions", string(pemReq), nil)
	if recBlock.Code != http.StatusBadRequest {
		t.Fatalf("PEM private key request = %d, want 400: %s", recBlock.Code, recBlock.Body.String())
	}
	upstreamMu.Lock()
	if len(upstreamBodies) != 1 {
		upstreamMu.Unlock()
		t.Fatalf("blocked request must not reach upstream, got %d calls", len(upstreamBodies))
	}
	upstreamMu.Unlock()

	// (g) Wait until async metering flushes request (e) into quotaMgr (Alice's daily spend >= $0.005).
	deadline := time.Now().Add(3 * time.Second)
	var spent float64
	for time.Now().Before(deadline) {
		recMeCheck := doReq("100.64.0.10:50001", http.MethodGet, "/api/v1/me", "", nil)
		if recMeCheck.Code == http.StatusOK {
			var meResp struct {
				Budgets []api.BudgetStatusItem `json:"budget_status"`
			}
			if err := json.Unmarshal(recMeCheck.Body.Bytes(), &meResp); err == nil {
				for _, b := range meResp.Budgets {
					if b.Scope == "alice@example.com" && b.DailySpentUSD >= 0.005 {
						spent = b.DailySpentUSD
						break
					}
				}
			}
		}
		if spent >= 0.005 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if spent < 0.005 {
		t.Fatalf("timed out waiting for Alice daily spend to reach >= $0.005 (got $%.6f)", spent)
	}

	// (h) Next request by Alice is rejected with HTTP 429 + Retry-After due to daily_usd budget exceeded.
	recQuota := doReq("100.64.0.10:50001", http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-5","messages":[{"role":"user","content":"over budget"}]}`,
		nil,
	)
	if recQuota.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget request = %d, want 429: %s", recQuota.Code, recQuota.Body.String())
	}
	if recQuota.Header().Get("Retry-After") == "" {
		t.Fatalf("429 response missing Retry-After header")
	}

	// (i) Admin budgets endpoint reflects live spend.
	recAdminBudgets := doReq("100.64.0.1:50002", http.MethodGet, "/api/v1/admin/budgets", "", nil)
	if recAdminBudgets.Code != http.StatusOK || !strings.Contains(recAdminBudgets.Body.String(), `"alice@example.com"`) {
		t.Fatalf("GET /api/v1/admin/budgets = %d: %s", recAdminBudgets.Code, recAdminBudgets.Body.String())
	}

	// (j) Graceful shutdown order: flush recorder FIRST, then drain guardrail webhooks.
	if err := recorder.Close(ctx); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	if err := grEngine.Close(ctx); err != nil {
		t.Fatalf("grEngine.Close: %v", err)
	}
	if dropped := grEngine.DroppedEvents(); dropped != 0 {
		t.Fatalf("expected 0 dropped webhook events, got %d", dropped)
	}

	// (k) Verify usage_logs guardrail + quota metadata and audit_payloads safety.
	logs, err := st.QueryUsageLogs(ctx, store.UsageFilter{Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("QueryUsageLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("expected 3 usage_logs for alice (1 redact 200 + 1 block 400 + 1 quota 429), got %d", len(logs))
	}
	var sawRedact, sawBlock, sawQuota429 bool
	for _, l := range logs {
		if l.StatusCode == http.StatusTooManyRequests {
			sawQuota429 = true
		}
		switch l.GuardrailAction {
		case config.GuardrailActionRedact:
			sawRedact = true
			if !slices.Contains(l.GuardrailHits, "builtin-aws-access-key") || !slices.Contains(l.GuardrailHits, "custom-corp-token") {
				t.Fatalf("redact log missing expected hits: %+v", l.GuardrailHits)
			}
		case config.GuardrailActionBlock:
			sawBlock = true
			if !slices.Contains(l.GuardrailHits, "builtin-pem-private-key") {
				t.Fatalf("block log missing builtin-pem-private-key hit: %+v", l.GuardrailHits)
			}
			payload, err := st.GetAuditPayloadByUsageLogID(ctx, l.ID)
			if err != nil {
				t.Fatalf("GetAuditPayloadByUsageLogID(blocked): %v", err)
			}
			if payload.RequestBody != "[BLOCKED BY GUARDRAIL]" || strings.Contains(payload.RequestBody, "PRIVATE KEY") {
				t.Fatalf("blocked audit payload leaked raw secret or wrong sentinel: %q", payload.RequestBody)
			}
		}
	}
	if !sawRedact || !sawBlock || !sawQuota429 {
		t.Fatalf("expected redact, block, and 429 usage logs, sawRedact=%v sawBlock=%v sawQuota429=%v", sawRedact, sawBlock, sawQuota429)
	}

	// (l) Verify async webhooks delivered with valid HMAC-SHA256 signatures for guardrail.triggered, budget.threshold, and budget.exceeded.
	whMu.Lock()
	defer whMu.Unlock()
	var gotEvents []string
	for _, ev := range whEvts {
		if !ev.SigValid {
			t.Fatalf("webhook event %q failed HMAC-SHA256 signature verification (body=%s)", ev.Event, ev.Body)
		}
		gotEvents = append(gotEvents, ev.Event)
	}
	for _, want := range []string{
		config.WebhookEventGuardrailTriggered,
		config.WebhookEventBudgetThreshold,
		config.WebhookEventBudgetExceeded,
	} {
		if !slices.Contains(gotEvents, want) {
			t.Fatalf("expected async webhook event %q, got events: %v", want, gotEvents)
		}
	}
}
