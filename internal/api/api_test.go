package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/store"
)

type fakeGuardrailTester struct{}

func (fakeGuardrailTester) TestText(_ context.Context, text string) (*GuardrailTestResult, error) {
	if strings.Contains(text, "AKIA") {
		return &GuardrailTestResult{
			Action:       config.GuardrailActionRedact,
			RedactedText: strings.ReplaceAll(text, "AKIAIOSFODNN7EXAMPLE", "[REDACTED:AWS]"),
			Matches: []GuardrailMatch{
				{RuleID: "builtin-aws-access-key", RuleName: "AWS Access Key ID", Category: "secret", Action: "redact"},
			},
		}, nil
	}
	return &GuardrailTestResult{Action: "", RedactedText: text, Matches: []GuardrailMatch{}}, nil
}

type fakeWebhookTester struct {
	lastSecret string
}

func (f *fakeWebhookTester) PingWebhook(_ context.Context, wh store.Webhook) (*WebhookTestResult, error) {
	f.lastSecret = wh.Secret
	return &WebhookTestResult{OK: true, StatusCode: 200, LatencyMS: 12, Message: "HTTP 200 OK"}, nil
}

func setupTestAPI(t *testing.T) (*Handler, *store.SQLiteStore, *metering.Recorder, *fakeWebhookTester) {
	t.Helper()
	ctx := context.Background()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	st, err := store.NewSQLiteStore(ctx, ":memory:", c)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pt, err := metering.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	rec := metering.NewRecorder(st, config.AuditConfig{StorePayloads: false, RetentionDays: 7}, pt, metering.RecorderOptions{
		DisableAutoPurge: true,
	})
	t.Cleanup(func() { _ = rec.Close(context.Background()) })

	whTester := &fakeWebhookTester{}
	staticFS := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<!doctype html><html><body>Headlamp UI</body></html>")},
		"assets/app-123.js": &fstest.MapFile{Data: []byte("console.log('ok');")},
	}

	h, err := NewHandler(Config{
		Store:           st,
		Policy:          policy.NewEvaluator(),
		Pricing:         pt,
		AuditController: rec,
		GuardrailTester: fakeGuardrailTester{},
		WebhookTester:   whTester,
		StaticFS:        staticFS,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, st, rec, whTester
}

func adminPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:     "alice@example.com",
		DisplayName: "Alice",
		NodeName:    "alice-mac",
		NodeIP:      "100.64.0.10",
		Tags:        []string{"tag:eng"},
		Roles:       []string{auth.RoleAdmin, auth.RoleUser},
		RawCaps: map[string][]byte{
			auth.CapHeadlampGateway: []byte(`[{"role":"admin","models":["**"],"mcp_tools":["**"]}]`),
		},
		AuthSource: auth.AuthSourceTSNet,
	}
}

func userPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:     "bob@example.com",
		DisplayName: "Bob",
		NodeName:    "bob-mac",
		NodeIP:      "100.64.0.11",
		Tags:        []string{"tag:eng"},
		Roles:       []string{auth.RoleUser},
		RawCaps: map[string][]byte{
			auth.CapHeadlampGateway: []byte(`[{"role":"user","models":["anthropic/*"],"deny_models":["openai/o3*"]}]`),
		},
		AuthSource: auth.AuthSourceTSNet,
	}
}

func doAPIRequest(h http.Handler, p *auth.Principal, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "headlamp.tailnet.internal"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if p != nil {
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMeAndAdminRBACAndCSRF(t *testing.T) {
	h, st, _, _ := setupTestAPI(t)
	ctx := context.Background()

	// Seed usage for Alice and Bob so /api/v1/me/usage strictly isolates Bob's own rows.
	now := time.Now().UTC()
	_ = st.InsertUsageLog(ctx, store.UsageLog{ID: "u-alice", CreatedAt: now, Subject: "alice@example.com", ProviderName: "openai", RequestedModel: "gpt-5", TotalTokens: 500, CostUSD: 0.05, StatusCode: 200})
	_ = st.InsertUsageLog(ctx, store.UsageLog{ID: "u-bob", CreatedAt: now, Subject: "bob@example.com", ProviderName: "anthropic", RequestedModel: "claude-sonnet-4-6", TotalTokens: 200, CostUSD: 0.02, StatusCode: 200})

	// 1. Unauthenticated -> 401
	if rec := doAPIRequest(h, nil, http.MethodGet, "/api/v1/me", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/v1/me = %d, want 401", rec.Code)
	}

	// 2. Non-admin /api/v1/me & /api/v1/me/usage succeed and isolate data
	recMe := doAPIRequest(h, userPrincipal(), http.MethodGet, "/api/v1/me", "", nil)
	if recMe.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me = %d: %s", recMe.Code, recMe.Body.String())
	}
	var meResp struct {
		IsAdmin bool `json:"is_admin"`
		Policy  struct {
			AllowModels []string `json:"allow_models"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(recMe.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("decode /api/v1/me: %v", err)
	}
	if meResp.IsAdmin || len(meResp.Policy.AllowModels) != 1 || meResp.Policy.AllowModels[0] != "anthropic/*" {
		t.Fatalf("unexpected /api/v1/me: %+v", meResp)
	}

	recMeUsage := doAPIRequest(h, userPrincipal(), http.MethodGet, "/api/v1/me/usage?window=24h", "", nil)
	if recMeUsage.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me/usage = %d: %s", recMeUsage.Code, recMeUsage.Body.String())
	}
	if strings.Contains(recMeUsage.Body.String(), "alice@example.com") || !strings.Contains(recMeUsage.Body.String(), "bob@example.com") {
		t.Fatalf("/api/v1/me/usage leaked or missed rows: %s", recMeUsage.Body.String())
	}

	// 3. Non-admin blocked on /api/v1/admin/* with 403
	if rec := doAPIRequest(h, userPrincipal(), http.MethodGet, "/api/v1/admin/overview", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin /api/v1/admin/overview = %d, want 403", rec.Code)
	}

	// 4. CSRF blocks cross-site, same-site, and mismatched Origin on mutating methods
	for _, sfs := range []string{"cross-site", "same-site"} {
		recCSRF := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/settings/audit/purge", "", map[string]string{
			"Sec-Fetch-Site": sfs,
		})
		if recCSRF.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site=%q = %d, want 403", sfs, recCSRF.Code)
		}
	}
	recCSRF2 := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/settings/audit/purge", "", map[string]string{
		"Origin": "https://evil.example.com",
	})
	if recCSRF2.Code != http.StatusForbidden {
		t.Fatalf("cross-origin Origin = %d, want 403", recCSRF2.Code)
	}

	// Same-origin succeeds
	recSameOrigin := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/settings/audit/purge", "", map[string]string{
		"Origin":         "http://headlamp.tailnet.internal",
		"Sec-Fetch-Site": "same-origin",
	})
	if recSameOrigin.Code != http.StatusOK {
		t.Fatalf("same-origin purge = %d, want 200: %s", recSameOrigin.Code, recSameOrigin.Body.String())
	}
}

func TestAdminProvidersSecretMaskingPreserveAndTestProbe(t *testing.T) {
	h, st, _, _ := setupTestAPI(t)

	// Mock upstream for /test probe
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	// Create provider
	recCreate := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers",
		`{"name":"openai","type":"openai","base_url":"`+upstream.URL+`","api_key":"sk-proj-secret1234567890","models":["gpt-5"]}`,
		nil,
	)
	if recCreate.Code != http.StatusCreated {
		t.Fatalf("POST provider = %d: %s", recCreate.Code, recCreate.Body.String())
	}
	if strings.Contains(recCreate.Body.String(), "sk-proj-secret1234567890") {
		t.Fatalf("plaintext api_key leaked in POST response: %s", recCreate.Body.String())
	}
	if !strings.Contains(recCreate.Body.String(), `"has_api_key":true`) || !strings.Contains(recCreate.Body.String(), `"api_key_preview":"sk-pro...****"`) {
		t.Fatalf("unexpected masked provider response: %s", recCreate.Body.String())
	}

	// PUT without api_key preserves existing encrypted key
	recUpdate := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/providers/openai",
		`{"type":"openai","base_url":"`+upstream.URL+`","models":["gpt-5","gpt-4.1"]}`,
		nil,
	)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("PUT provider = %d: %s", recUpdate.Code, recUpdate.Body.String())
	}
	stored, err := st.GetProvider(context.Background(), "openai")
	if err != nil || stored.APIKey != "sk-proj-secret1234567890" {
		t.Fatalf("expected preserved APIKey, got (%+v, %v)", stored, err)
	}

	// POST /test hits upstream with stored key
	recTest := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers/openai/test", "", nil)
	if recTest.Code != http.StatusOK || !strings.Contains(recTest.Body.String(), `"ok":true`) || gotAuth != "Bearer sk-proj-secret1234567890" {
		t.Fatalf("provider test = %d body=%s gotAuth=%q", recTest.Code, recTest.Body.String(), gotAuth)
	}

	// PUT with clear_api_key: true clears stored key
	recClear := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/providers/openai",
		`{"type":"openai","base_url":"`+upstream.URL+`","clear_api_key":true,"models":["gpt-5"]}`,
		nil,
	)
	if recClear.Code != http.StatusOK || !strings.Contains(recClear.Body.String(), `"has_api_key":false`) {
		t.Fatalf("clear_api_key PUT = %d: %s", recClear.Code, recClear.Body.String())
	}

	// DELETE provider
	if recDel := doAPIRequest(h, adminPrincipal(), http.MethodDelete, "/api/v1/admin/providers/openai", "", nil); recDel.Code != http.StatusOK {
		t.Fatalf("DELETE provider = %d: %s", recDel.Code, recDel.Body.String())
	}
}

func TestAdminRoutesBudgetsOverviewLogsAuditGuardrailsWebhooksAndSPA(t *testing.T) {
	h, st, rec, whTester := setupTestAPI(t)
	ctx := context.Background()

	// Seed provider for route tests
	_ = st.UpsertProvider(ctx, store.Provider{
		Name: "anthropic", Type: config.ProviderTypeAnthropic, BaseURL: "https://api.anthropic.com",
		Models: []string{"claude-sonnet-4-6"}, Enabled: true,
	})

	// 1. Routes with slash alias ("team/coding") via query & path forms
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/routes",
		`{"alias":"team/coding","provider_name":"anthropic","upstream_model":"claude-sonnet-4-6","input_cost_per_million":2.5}`,
		nil,
	); r.Code != http.StatusCreated {
		t.Fatalf("POST route = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/routes?alias=team/coding",
		`{"provider_name":"anthropic","upstream_model":"claude-sonnet-4-6","output_cost_per_million":10.0}`,
		nil,
	); r.Code != http.StatusOK {
		t.Fatalf("PUT route via query = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/pricing", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"exact"`) || !strings.Contains(r.Body.String(), `"patterns"`) {
		t.Fatalf("GET pricing = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodDelete, "/api/v1/admin/routes/team/coding", "", nil); r.Code != http.StatusOK {
		t.Fatalf("DELETE route via path = %d: %s", r.Code, r.Body.String())
	}

	// 2. Budgets with "*" and "tag:ci" scopes
	for _, body := range []string{
		`{"scope":"*","rpm":120,"tpm":200000,"max_concurrent":10,"daily_usd":50.0,"monthly_usd":500.0,"soft_alert_pct":80}`,
		`{"scope":"tag:ci","rpm":30,"daily_usd":5.0}`,
	} {
		if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/budgets", body, nil); r.Code != http.StatusCreated {
			t.Fatalf("POST budget = %d: %s", r.Code, r.Body.String())
		}
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/budgets?scope=*", `{"rpm":200,"daily_usd":75.0}`, nil); r.Code != http.StatusOK {
		t.Fatalf("PUT budget * = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/budgets", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"daily_spent_usd"`) {
		t.Fatalf("GET budgets = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodDelete, "/api/v1/admin/budgets/tag:ci", "", nil); r.Code != http.StatusOK {
		t.Fatalf("DELETE budget tag:ci = %d: %s", r.Code, r.Body.String())
	}

	// 3. Grants guide
	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/grants-guide", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "headlamp.dev/cap/gateway") {
		t.Fatalf("GET grants-guide = %d: %s", r.Code, r.Body.String())
	}

	// 4. Overview, Logs, Payload, Audit Settings & Purge
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	_ = st.InsertUsageLog(ctx, store.UsageLog{
		ID: "log-1", CreatedAt: old, Subject: "alice@example.com", ProviderName: "anthropic",
		RequestedModel: "claude-sonnet-4-6", TotalTokens: 1000, CostUSD: 0.05, StatusCode: 200,
		GuardrailAction: "redact", GuardrailHits: []string{"builtin-aws-access-key"},
	})
	_ = st.InsertAuditPayload(ctx, store.AuditPayload{
		UsageLogID: "log-1", CreatedAt: old, RequestBody: `{"msg":"hi"}`, ResponseBody: `{"ok":true}`, Redacted: true,
	})

	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/overview?window=30d", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"top_subjects"`) {
		t.Fatalf("GET overview = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/logs?guardrail_only=true&status=200", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "log-1") {
		t.Fatalf("GET logs = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/logs/log-1/payload", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"redacted":true`) {
		t.Fatalf("GET log payload = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/settings/audit", `{"store_payloads":true,"retention_days":7}`, nil); r.Code != http.StatusOK {
		t.Fatalf("PUT audit settings = %d: %s", r.Code, r.Body.String())
	}
	if !rec.AuditConfig().StorePayloads || rec.AuditConfig().RetentionDays != 7 {
		t.Fatalf("Recorder AuditConfig not updated live: %+v", rec.AuditConfig())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/settings/audit/purge", "", nil); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"purged":1`) {
		t.Fatalf("POST audit purge = %d: %s", r.Code, r.Body.String())
	}

	// 5. Guardrails CRUD + Test
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/guardrails",
		`{"id":"custom-1","name":"Secret Token","category":"secret","pattern":"TOK_[0-9]+","action":"redact"}`,
		nil,
	); r.Code != http.StatusCreated {
		t.Fatalf("POST guardrail = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/guardrails/custom-1",
		`{"action":"block","enabled":false}`,
		nil,
	); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"action":"block"`) {
		t.Fatalf("PUT guardrail = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/guardrails/test",
		`{"text":"key=AKIAIOSFODNN7EXAMPLE"}`,
		nil,
	); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "[REDACTED:AWS]") {
		t.Fatalf("POST guardrail test = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodDelete, "/api/v1/admin/guardrails/custom-1", "", nil); r.Code != http.StatusOK {
		t.Fatalf("DELETE guardrail = %d: %s", r.Code, r.Body.String())
	}

	// 6. Webhooks CRUD, Secret Masking/Preserve + Test Ping
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/webhooks",
		`{"id":"wh-1","name":"Alerts","url":"https://hooks.example.com/e","type":"async_event","secret":"whsec_top_secret","events":["budget.threshold"]}`,
		nil,
	); r.Code != http.StatusCreated || strings.Contains(r.Body.String(), "whsec_top_secret") || !strings.Contains(r.Body.String(), `"has_secret":true`) {
		t.Fatalf("POST webhook = %d: %s", r.Code, r.Body.String())
	}
	// PUT without secret preserves existing secret
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPut, "/api/v1/admin/webhooks/wh-1",
		`{"name":"Alerts v2","events":["budget.threshold","budget.exceeded"]}`,
		nil,
	); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"has_secret":true`) {
		t.Fatalf("PUT webhook preserve secret = %d: %s", r.Code, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/webhooks/wh-1/test", "", nil); r.Code != http.StatusOK || whTester.lastSecret != "whsec_top_secret" {
		t.Fatalf("POST webhook test = %d secret=%q body=%s", r.Code, whTester.lastSecret, r.Body.String())
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodDelete, "/api/v1/admin/webhooks/wh-1", "", nil); r.Code != http.StatusOK {
		t.Fatalf("DELETE webhook = %d: %s", r.Code, r.Body.String())
	}

	// 7. SPA fallback vs API 404 vs Gateway reserved paths
	recRoot := doAPIRequest(h, nil, http.MethodGet, "/", "", nil)
	if recRoot.Code != http.StatusOK || !bytes.Contains(recRoot.Body.Bytes(), []byte("Headlamp UI")) {
		t.Fatalf("GET / SPA = %d: %s", recRoot.Code, recRoot.Body.String())
	}
	recClientRoute := doAPIRequest(h, nil, http.MethodGet, "/security/guardrails", "", nil)
	if recClientRoute.Code != http.StatusOK || !bytes.Contains(recClientRoute.Body.Bytes(), []byte("Headlamp UI")) {
		t.Fatalf("GET /security/guardrails SPA fallback = %d: %s", recClientRoute.Code, recClientRoute.Body.String())
	}
	recAsset := doAPIRequest(h, nil, http.MethodGet, "/assets/app-123.js", "", nil)
	if recAsset.Code != http.StatusOK || !strings.Contains(recAsset.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("GET /assets/app-123.js = %d cc=%q", recAsset.Code, recAsset.Header().Get("Cache-Control"))
	}
	recUnknownAPI := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/nonexistent", "", nil)
	if recUnknownAPI.Code != http.StatusNotFound || !strings.Contains(recUnknownAPI.Body.String(), `"not_found"`) {
		t.Fatalf("GET /api/v1/nonexistent = %d: %s", recUnknownAPI.Code, recUnknownAPI.Body.String())
	}
	if h.HandlesPath("/v1/chat/completions") || h.HandlesPath("/anthropic/v1/messages") || h.HandlesPath("/gemini/v1beta/models") || h.HandlesPath("/healthz") || h.HandlesPath("/whoami") {
		t.Fatal("HandlesPath must never claim gateway-reserved paths")
	}
}

func TestAuditRegressionFixes(t *testing.T) {
	h, st, _, _ := setupTestAPI(t)
	ctx := context.Background()

	// 1a. Provider probe avoids duplicate /v1 & /v1beta suffixes.
	var gotPath string
	v1Upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer v1Upstream.Close()

	_ = st.UpsertProvider(ctx, store.Provider{
		Name: "openrouter", Type: config.ProviderTypeOpenAI, BaseURL: v1Upstream.URL + "/v1",
		APIKey: "sk-or-test", Enabled: true,
	})
	if rec := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers/openrouter/test", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("openrouter /v1 probe failed: %d %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/v1/models" {
		t.Fatalf("expected /v1/models without duplicate /v1, got %q", gotPath)
	}

	_ = st.UpsertProvider(ctx, store.Provider{
		Name: "gem-v1beta", Type: config.ProviderTypeGemini, BaseURL: v1Upstream.URL + "/v1beta",
		APIKey: "AIza-test", Enabled: true,
	})
	if rec := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers/gem-v1beta/test", "", nil); rec.Code != http.StatusOK || gotPath != "/v1beta/models" {
		t.Fatalf("gemini /v1beta probe failed: code=%d gotPath=%q", rec.Code, gotPath)
	}

	// 1b. Provider probe does NOT follow redirects (prevents leaking x-api-key).
	redirectTargetHit := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirector.Close()

	_ = st.UpsertProvider(ctx, store.Provider{
		Name: "anth-redir", Type: config.ProviderTypeAnthropic, BaseURL: redirector.URL,
		APIKey: "sk-ant-secret", Enabled: true,
	})
	recRedir := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers/anth-redir/test", "", nil)
	if recRedir.Code != http.StatusOK || !strings.Contains(recRedir.Body.String(), `"ok":false`) || !strings.Contains(recRedir.Body.String(), "302") {
		t.Fatalf("expected 302 non-followed probe result, got %d %s", recRedir.Code, recRedir.Body.String())
	}
	if redirectTargetHit {
		t.Fatal("probe followed redirect and could leak x-api-key")
	}

	// 2. GET /api/v1/admin/grants-guide emits empty arrays [] instead of null for empty slices.
	recGuide := doAPIRequest(h, adminPrincipal(), http.MethodGet, "/api/v1/admin/grants-guide", "", nil)
	if recGuide.Code != http.StatusOK {
		t.Fatalf("grants-guide = %d: %s", recGuide.Code, recGuide.Body.String())
	}
	if strings.Contains(recGuide.Body.String(), `"deny_models":null`) || strings.Contains(recGuide.Body.String(), `"deny_mcp_tools":null`) {
		t.Fatalf("grants-guide emitted null slices instead of []: %s", recGuide.Body.String())
	}
	if !strings.Contains(recGuide.Body.String(), `"deny_models":[]`) || !strings.Contains(recGuide.Body.String(), `"deny_mcp_tools":[]`) {
		t.Fatalf("grants-guide missing normalized [] slices: %s", recGuide.Body.String())
	}

	// 4. Reject '/' in provider name, guardrail id, webhook id, and reserved guardrail id "test".
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/providers",
		`{"name":"bad/name","type":"openai","base_url":"https://api.openai.com"}`, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("provider with '/' = %d, want 400", r.Code)
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/guardrails",
		`{"id":"bad/id","name":"X","pattern":"foo","action":"redact"}`, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("guardrail with '/' = %d, want 400", r.Code)
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/guardrails",
		`{"id":"test","name":"Reserved","pattern":"foo","action":"redact"}`, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("guardrail with reserved id 'test' = %d, want 400", r.Code)
	}
	if r := doAPIRequest(h, adminPrincipal(), http.MethodPost, "/api/v1/admin/webhooks",
		`{"id":"bad/wh","name":"X","url":"https://hooks.example.com","type":"async_event"}`, nil); r.Code != http.StatusBadRequest {
		t.Fatalf("webhook with '/' = %d, want 400", r.Code)
	}
}
