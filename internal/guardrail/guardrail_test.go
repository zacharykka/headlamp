package guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
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
	st, err := store.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "guardrail.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedAllBuiltinRulesEnabled(t *testing.T, st store.Store) {
	t.Helper()
	for _, r := range store.DefaultBuiltinGuardrailRules() {
		r.Enabled = true
		if err := st.UpsertGuardrailRule(context.Background(), r); err != nil {
			t.Fatalf("seed rule %s: %v", r.ID, err)
		}
	}
}

func TestBuiltinPresetsAllTenRules(t *testing.T) {
	st := newTestStore(t)
	seedAllBuiltinRulesEnabled(t, st)
	eval := NewEvaluator(st, nil)

	// Build synthetic test samples dynamically so scanners never mistake test fixtures for live creds.
	samples := []struct {
		ruleID     string
		wantAction string
		sample     string
	}{
		{"builtin-openai-key", ActionRedact, "token is " + "sk-proj-" + strings.Repeat("aB12", 7)},
		{"builtin-anthropic-key", ActionRedact, "key=" + "sk-ant-api03-" + strings.Repeat("Xy90", 7)},
		{"builtin-aws-access-key", ActionRedact, "aws=" + "AKIA" + "IOSFODNN7EXAMPLE"},
		{"builtin-github-token", ActionRedact, "gh=" + "ghp_" + strings.Repeat("a1B2", 9)},
		{"builtin-gcp-api-key", ActionRedact, "gcp=" + "AIza" + strings.Repeat("SyD12", 7)},
		{"builtin-pem-private-key", ActionBlock, "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END " + "RSA PRIVATE KEY-----"},
		{"builtin-jwt", ActionLogOnly, "jwt=" + "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		{"builtin-credit-card", ActionRedact, "card=" + "4111" + "11111111" + "1111"},
		{"builtin-email", ActionLogOnly, "contact alice.dev@example.com please"},
		{"builtin-phone", ActionLogOnly, "call +1-415-555-0199 now"},
	}

	for _, tc := range samples {
		t.Run(tc.ruleID, func(t *testing.T) {
			res, err := eval.TestText(context.Background(), tc.sample)
			if err != nil {
				t.Fatalf("TestText failed: %v", err)
			}
			if res.Action != tc.wantAction {
				t.Fatalf("action=%q, want %q (matches=%+v)", res.Action, tc.wantAction, res.Matches)
			}
			var ids []string
			for _, m := range res.Matches {
				ids = append(ids, m.RuleID)
			}
			if !slices.Contains(ids, tc.ruleID) {
				t.Fatalf("expected match %q, got %v", tc.ruleID, ids)
			}
			if tc.wantAction == ActionRedact {
				wantPlaceholder := "[REDACTED:" + tc.ruleID + "]"
				if !strings.Contains(res.RedactedText, wantPlaceholder) {
					t.Fatalf("expected %q in redacted text, got %q", wantPlaceholder, res.RedactedText)
				}
			}
		})
	}
}

func TestJSONPayloadInspectionPreservesStructureMetadataAndPrecedence(t *testing.T) {
	st := newTestStore(t)
	seedAllBuiltinRulesEnabled(t, st)
	eval := NewEvaluator(st, nil)

	awsKey := "AKIA" + "1234567890ABCDEF"
	// 1. Redact AWS key inside prompt while preserving skipped metadata keys ("model", "role", "id", "tool_call_id")
	//    and preserving exact integer formatting ("max_tokens": 4096) and base64 image source data.
	payload := `{
		"model": "gpt-4.1",
		"max_tokens": 4096,
		"messages": [
			{"role": "user", "id": "` + awsKey + `", "content": [
				{"type": "text", "text": "Use key ` + awsKey + ` and mail bob@example.com"},
				{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "` + awsKey + `"}}
			]},
			{"role": "tool", "tool_call_id": "` + awsKey + `", "content": "ok"}
		]
	}`

	res, err := eval.InspectJSONPayload(context.Background(), []byte(payload))
	if err != nil {
		t.Fatalf("InspectJSONPayload failed: %v", err)
	}
	if res.Action != ActionRedact {
		t.Fatalf("expected action=redact (redact > log_only), got %q (matches=%+v)", res.Action, res.Matches)
	}
	if !json.Valid(res.ModifiedBody) {
		t.Fatalf("modified body is not valid JSON: %s", string(res.ModifiedBody))
	}

	var parsed map[string]any
	dec := json.NewDecoder(bytes.NewReader(res.ModifiedBody))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["max_tokens"].(json.Number).String() != "4096" {
		t.Fatalf("integer max_tokens altered: %v", parsed["max_tokens"])
	}
	msgs := parsed["messages"].([]any)
	u0 := msgs[0].(map[string]any)
	if u0["id"] != awsKey {
		t.Fatalf("skipped key 'id' must not be rewritten, got %v", u0["id"])
	}
	blocks := u0["content"].([]any)
	textVal := blocks[0].(map[string]any)["text"].(string)
	if !strings.Contains(textVal, "[REDACTED:builtin-aws-access-key]") || strings.Contains(textVal, awsKey) {
		t.Fatalf("prompt text not redacted properly: %q", textVal)
	}
	// base64 image source data must remain untouched.
	imgData := blocks[1].(map[string]any)["source"].(map[string]any)["data"].(string)
	if imgData != awsKey {
		t.Fatalf("base64 image source data must not be mutated, got %q", imgData)
	}
	// tool_call_id must remain untouched.
	if msgs[1].(map[string]any)["tool_call_id"] != awsKey {
		t.Fatalf("skipped key 'tool_call_id' must not be mutated")
	}

	// 2. Precedence: block > redact > log_only (contains PEM key + AWS key + email).
	pem := "-----BEGIN " + "PRIVATE KEY-----\nABC\n-----END " + "PRIVATE KEY-----"
	mixedBody, _ := json.Marshal(map[string]any{
		"model":    "claude-sonnet-4-6",
		"messages": []map[string]any{{"role": "user", "content": pem + " " + awsKey + " a@b.com"}},
	})
	blockRes, err := eval.InspectJSONPayload(context.Background(), mixedBody)
	if err != nil {
		t.Fatal(err)
	}
	if blockRes.Action != ActionBlock {
		t.Fatalf("expected action=block, got %q", blockRes.Action)
	}
	if !strings.Contains(blockRes.Reason, "builtin-pem-private-key") {
		t.Fatalf("expected block reason to name PEM rule, got %q", blockRes.Reason)
	}
	if string(blockRes.ModifiedBody) != string(mixedBody) {
		t.Fatalf("blocked payload must not be mutated")
	}

	// 3. Cache invalidation when a custom rule is added live.
	if err := st.UpsertGuardrailRule(context.Background(), store.GuardrailRule{
		ID:       "custom-secret-word",
		Name:     "Project Codename",
		Category: config.GuardrailCategoryCustom,
		Pattern:  `PROJECT-OMEGA`,
		Action:   ActionBlock,
		Enabled:  true,
		Source:   store.SourceLocal,
	}); err != nil {
		t.Fatal(err)
	}
	customRes, err := eval.TestText(context.Background(), "leaking PROJECT-OMEGA specs")
	if err != nil {
		t.Fatal(err)
	}
	if customRes.Action != ActionBlock || len(customRes.Matches) != 1 || customRes.Matches[0].RuleID != "custom-secret-word" {
		t.Fatalf("expected live custom rule to invalidate cache and block, got %+v", customRes)
	}
}

func TestWebhookHMACSigningAndVerification(t *testing.T) {
	payload := []byte(`{"event":"guardrail.triggered","data":{"ok":true}}`)
	sig := SignPayload("top-secret-key", payload)
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected sha256= prefix, got %q", sig)
	}
	if !VerifySignature("top-secret-key", payload, sig) {
		t.Fatalf("VerifySignature rejected valid signature")
	}
	if VerifySignature("wrong-secret", payload, sig) {
		t.Fatalf("VerifySignature accepted wrong secret")
	}
	if VerifySignature("top-secret-key", []byte(`{"tampered":true}`), sig) {
		t.Fatalf("VerifySignature accepted tampered payload")
	}
}

func TestSyncReviewWebhookAllowModifyBlockFailOpenFailClosed(t *testing.T) {
	secret := "review-hmac-secret"
	var (
		mu             sync.Mutex
		nextAction     = "allow"
		nextStatus     = http.StatusOK
		sleepDuration  time.Duration
		seenEventHdr   string
		seenSigValid   bool
		seenReviewBody SyncReviewRequest
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		action := nextAction
		status := nextStatus
		delay := sleepDuration
		seenEventHdr = r.Header.Get("X-Headlamp-Event")
		seenSigValid = VerifySignature(secret, raw, r.Header.Get("X-Headlamp-Signature"))
		_ = json.Unmarshal(raw, &seenReviewBody)
		mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("internal error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "allow":
			_, _ = w.Write([]byte(`{"action":"allow"}`))
		case "modify":
			_, _ = w.Write([]byte(`{"action":"modify","modified_body":{"model":"gpt-4.1","messages":[{"role":"user","content":"scrubbed by webhook"}]}}`))
		case "block":
			_, _ = w.Write([]byte(`{"action":"block","reason":"DLP policy violation"}`))
		}
	}))
	defer srv.Close()

	st := newTestStore(t)
	wh := store.Webhook{
		ID:        "dlp-review",
		Name:      "Corporate DLP",
		URL:       srv.URL,
		Type:      config.WebhookTypeSyncReview,
		Secret:    secret,
		TimeoutMS: 200,
		FailOpen:  true,
		Enabled:   true,
		Source:    store.SourceLocal,
	}
	if err := st.UpsertWebhook(context.Background(), wh); err != nil {
		t.Fatal(err)
	}

	disp := NewWebhookDispatcher(st, WebhookDispatcherOptions{RetryBackoff: 10 * time.Millisecond})
	defer func() { _ = disp.Close(context.Background()) }()

	req := SyncReviewRequest{
		RequestID: "req-1",
		Subject:   "alice@example.com",
		NodeName:  "alice-mac",
		Protocol:  "openai_chat",
		Model:     "openai/gpt-4.1",
		Body:      json.RawMessage(`{"model":"gpt-4.1","messages":[{"role":"user","content":"hello"}]}`),
	}

	// 1. allow + verify HMAC signature & header
	out, err := disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionAllow {
		t.Fatalf("allow failed: out=%+v err=%v", out, err)
	}
	mu.Lock()
	if seenEventHdr != "sync_review" || !seenSigValid || seenReviewBody.Subject != "alice@example.com" {
		mu.Unlock()
		t.Fatalf("unexpected webhook headers/payload: event=%q sigValid=%v body=%+v", seenEventHdr, seenSigValid, seenReviewBody)
	}
	mu.Unlock()

	// 2. modify
	mu.Lock()
	nextAction = "modify"
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionModify || !strings.Contains(string(out.ModifiedBody), "scrubbed by webhook") {
		t.Fatalf("modify failed: out=%+v err=%v", out, err)
	}
	if !slices.Contains(out.Hits, "webhook:dlp-review") {
		t.Fatalf("expected webhook hit recorded, got %v", out.Hits)
	}

	// 3. block
	mu.Lock()
	nextAction = "block"
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionBlock || out.StatusCode != http.StatusForbidden || out.Reason != "DLP policy violation" {
		t.Fatalf("block failed: out=%+v err=%v", out, err)
	}

	// 4. timeout with fail_open: true -> allows request
	mu.Lock()
	nextAction = "block"
	sleepDuration = 400 * time.Millisecond
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionAllow {
		t.Fatalf("fail_open timeout should allow, got out=%+v err=%v", out, err)
	}

	// 5. 500 error with fail_open: false -> blocks with 503
	wh.FailOpen = false
	_ = st.UpsertWebhook(context.Background(), wh)
	mu.Lock()
	sleepDuration = 0
	nextStatus = http.StatusInternalServerError
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionBlock || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("fail_closed 500 should block with 503, got out=%+v err=%v", out, err)
	}
}

func TestAsyncEventDispatcherRetryFilteringAndCloseDrain(t *testing.T) {
	secret := "async-secret"
	var (
		retryAttempts atomic.Int32
		mu            sync.Mutex
		whAEvents     []string
		whBEvents     []string
		whCEvents     []string
		allSigsValid  = true
	)

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !VerifySignature(secret, raw, r.Header.Get("X-Headlamp-Signature")) {
			mu.Lock()
			allSigsValid = false
			mu.Unlock()
		}
		if retryAttempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway) // Trigger 1 backoff retry.
			return
		}
		mu.Lock()
		whAEvents = append(whAEvents, r.Header.Get("X-Headlamp-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		whBEvents = append(whBEvents, r.Header.Get("X-Headlamp-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srvB.Close()

	srvC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		whCEvents = append(whCEvents, r.Header.Get("X-Headlamp-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srvC.Close()

	st := newTestStore(t)
	_ = st.UpsertWebhook(context.Background(), store.Webhook{
		ID: "wh-a", Name: "Guardrail Alerts", URL: srvA.URL, Type: config.WebhookTypeAsyncEvent,
		Secret: secret, Events: []string{config.WebhookEventGuardrailTriggered}, TimeoutMS: 1000, Enabled: true,
	})
	_ = st.UpsertWebhook(context.Background(), store.Webhook{
		ID: "wh-b", Name: "Wildcard SIEM", URL: srvB.URL, Type: config.WebhookTypeAsyncEvent,
		Events: []string{"*"}, TimeoutMS: 1000, Enabled: true,
	})
	_ = st.UpsertWebhook(context.Background(), store.Webhook{
		ID: "wh-c", Name: "Budget Only", URL: srvC.URL, Type: config.WebhookTypeAsyncEvent,
		Events: []string{config.WebhookEventBudgetExceeded}, TimeoutMS: 1000, Enabled: true,
	})

	disp := NewWebhookDispatcher(st, WebhookDispatcherOptions{
		Workers:      2,
		RetryBackoff: 10 * time.Millisecond,
	})

	disp.Emit(config.WebhookEventGuardrailTriggered, map[string]any{"rule": "builtin-aws-access-key"})
	disp.Emit(config.WebhookEventUpstreamFallback, map[string]any{"provider": "openai"})

	// Close must drain all queued events before returning.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Emitting after Close must not panic and must increment DroppedCount.
	disp.Emit(config.WebhookEventBudgetExceeded, map[string]any{})
	if disp.DroppedCount() != 1 {
		t.Fatalf("expected 1 dropped event after Close, got %d", disp.DroppedCount())
	}

	mu.Lock()
	defer mu.Unlock()
	if !allSigsValid {
		t.Fatalf("HMAC signature verification failed on async delivery")
	}
	if retryAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts (1 initial 502 + 1 retry) on wh-a, got %d", retryAttempts.Load())
	}
	if !slices.Equal(whAEvents, []string{config.WebhookEventGuardrailTriggered}) {
		t.Fatalf("wh-a expected only guardrail.triggered, got %v", whAEvents)
	}
	if len(whBEvents) != 2 {
		t.Fatalf("wildcard wh-b expected 2 events, got %v", whBEvents)
	}
	if len(whCEvents) != 0 {
		t.Fatalf("budget-only wh-c should not receive unrelated events, got %v", whCEvents)
	}
}

func TestPingWebhookAndUnifiedEngine(t *testing.T) {
	var asyncHits atomic.Int32
	asyncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Headlamp-Event") == config.WebhookEventGuardrailTriggered {
			asyncHits.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer asyncSrv.Close()

	st := newTestStore(t)
	seedAllBuiltinRulesEnabled(t, st)
	_ = st.UpsertWebhook(context.Background(), store.Webhook{
		ID: "siem", Name: "SIEM", URL: asyncSrv.URL, Type: config.WebhookTypeAsyncEvent,
		Secret: "s1", Events: []string{config.WebhookEventGuardrailTriggered}, TimeoutMS: 1000, Enabled: true,
	})

	engine, err := NewEngine(EngineConfig{Store: st, RetryBackoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	// PingWebhook success
	pingRes, err := engine.PingWebhook(context.Background(), store.Webhook{
		ID: "siem", Name: "SIEM", URL: asyncSrv.URL, Secret: "s1", TimeoutMS: 1000,
	})
	if err != nil || !pingRes.OK || pingRes.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected PingWebhook result: %+v err=%v", pingRes, err)
	}

	// PingWebhook unreachable
	badRes, err := engine.PingWebhook(context.Background(), store.Webhook{
		ID: "bad", Name: "Bad", URL: "http://127.0.0.1:1/hook?token=secret123", TimeoutMS: 200,
	})
	if err != nil || badRes.OK || strings.Contains(badRes.Message, "secret123") {
		t.Fatalf("unexpected bad PingWebhook result (or secret leaked): %+v err=%v", badRes, err)
	}

	// InspectRequest with AWS key triggers redact + async guardrail.triggered event.
	awsKey := "AKIA" + "9988776655443322"
	dec, err := engine.InspectRequest(context.Background(), InspectInput{
		RequestID: "req-eng-1",
		Subject:   "alice@example.com",
		NodeName:  "alice-mac",
		Protocol:  "openai_chat",
		Model:     "openai/gpt-4.1",
		Body:      []byte(`{"model":"gpt-4.1","messages":[{"role":"user","content":"key=` + awsKey + `"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != ActionRedact || !slices.Contains(dec.Hits, "builtin-aws-access-key") {
		t.Fatalf("unexpected engine decision: %+v", dec)
	}
	if strings.Contains(string(dec.ModifiedBody), awsKey) {
		t.Fatalf("raw key survived redaction: %s", string(dec.ModifiedBody))
	}

	if err := engine.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if asyncHits.Load() != 1 {
		t.Fatalf("expected 1 guardrail.triggered async webhook delivery, got %d", asyncHits.Load())
	}
}

func TestLiteralDollarRuleIDAndGeminiInlineMediaSkip(t *testing.T) {
	st := newTestStore(t)
	seedAllBuiltinRulesEnabled(t, st)
	// Custom rule ID containing $0 and $1 must NOT expand regex capture groups.
	if err := st.UpsertGuardrailRule(context.Background(), store.GuardrailRule{
		ID:       "custom-$0-$1-id",
		Name:     "Dollar Rule",
		Category: config.GuardrailCategoryCustom,
		Pattern:  `(SECRET-[0-9]+)`,
		Action:   ActionRedact,
		Enabled:  true,
		Source:   store.SourceLocal,
	}); err != nil {
		t.Fatal(err)
	}

	eval := NewEvaluator(st, nil)
	res, err := eval.TestText(context.Background(), "leak SECRET-9999 here")
	if err != nil {
		t.Fatal(err)
	}
	if res.RedactedText != "leak [REDACTED:custom-$0-$1-id] here" {
		t.Fatalf("expected literal $ in placeholder, got %q", res.RedactedText)
	}

	// Gemini inlineData (mimeType) and inline_data (mime_type) base64 data must be skipped,
	// while text parts in the same Gemini payload are still redacted.
	awsKey := "AKIA" + "9876543210FEDCBA"
	geminiPayload := `{
		"contents": [{
			"role": "user",
			"parts": [
				{"text": "use key ` + awsKey + `"},
				{"inlineData": {"mimeType": "image/png", "data": "` + awsKey + `"}},
				{"inline_data": {"mime_type": "image/jpeg", "data": "` + awsKey + `"}}
			]
		}]
	}`
	insp, err := eval.InspectJSONPayload(context.Background(), []byte(geminiPayload))
	if err != nil {
		t.Fatal(err)
	}
	if insp.Action != ActionRedact {
		t.Fatalf("expected redact, got %q", insp.Action)
	}
	var parsed map[string]any
	if err := json.Unmarshal(insp.ModifiedBody, &parsed); err != nil {
		t.Fatalf("modified Gemini JSON invalid: %v", err)
	}
	parts := parsed["contents"].([]any)[0].(map[string]any)["parts"].([]any)
	if !strings.Contains(parts[0].(map[string]any)["text"].(string), "[REDACTED:builtin-aws-access-key]") {
		t.Fatalf("Gemini text part not redacted: %+v", parts[0])
	}
	if parts[1].(map[string]any)["inlineData"].(map[string]any)["data"] != awsKey {
		t.Fatalf("Gemini inlineData.data must not be mutated: %+v", parts[1])
	}
	if parts[2].(map[string]any)["inline_data"].(map[string]any)["data"] != awsKey {
		t.Fatalf("Gemini inline_data.data must not be mutated: %+v", parts[2])
	}
}

func TestWebhookBlocksRedirectsAndNonObjectModifiedBody(t *testing.T) {
	var redirectTargetHits atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer redirectTarget.Close()

	var (
		mu       sync.Mutex
		mode     = "redirect"
		bodyResp = `{"action":"modify","modified_body":null}`
	)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		b := bodyResp
		mu.Unlock()
		if m == "redirect" {
			http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b))
	}))
	defer webhookSrv.Close()

	st := newTestStore(t)
	wh := store.Webhook{
		ID:        "sec-hook",
		Name:      "Security Hook",
		URL:       webhookSrv.URL,
		Type:      config.WebhookTypeSyncReview,
		Secret:    "s3cr3t",
		TimeoutMS: 1000,
		FailOpen:  false,
		Enabled:   true,
	}
	if err := st.UpsertWebhook(context.Background(), wh); err != nil {
		t.Fatal(err)
	}

	disp := NewWebhookDispatcher(st, WebhookDispatcherOptions{RetryBackoff: 10 * time.Millisecond})
	defer func() { _ = disp.Close(context.Background()) }()

	req := SyncReviewRequest{
		RequestID: "req-sec-1",
		Subject:   "alice@example.com",
		Protocol:  "openai_chat",
		Model:     "openai/gpt-4.1",
		Body:      json.RawMessage(`{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}`),
	}

	// 1. 307 redirect must NEVER be followed (target hits == 0) and fail_closed blocks with 503.
	out, err := disp.Review(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if redirectTargetHits.Load() != 0 {
		t.Fatalf("webhook client followed 307 redirect (%d hits), leaking signed payload", redirectTargetHits.Load())
	}
	if out.Action != ActionBlock || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected fail_closed 503 on 307 redirect, got %+v", out)
	}

	// 2. action=modify with null / scalar modified_body must be rejected (fail_closed -> 503).
	mu.Lock()
	mode = "body"
	bodyResp = `{"action":"modify","modified_body":null}`
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionBlock || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected fail_closed 503 on modified_body=null, got out=%+v err=%v", out, err)
	}

	mu.Lock()
	bodyResp = `{"action":"modify","modified_body":"just-a-string"}`
	mu.Unlock()
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionBlock || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected fail_closed 503 on scalar modified_body, got out=%+v err=%v", out, err)
	}

	// 3. Same non-object modified_body with fail_open=true ignores modification and preserves original body.
	wh.FailOpen = true
	_ = st.UpsertWebhook(context.Background(), wh)
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionAllow || string(out.ModifiedBody) != string(req.Body) {
		t.Fatalf("expected fail_open to ignore scalar modified_body and allow original body, got out=%+v err=%v", out, err)
	}
}

func TestPathAwareJSONSkippingScansToolPayloads(t *testing.T) {
	st := newTestStore(t)
	seedAllBuiltinRulesEnabled(t, st)
	eval := NewEvaluator(st, nil)

	awsKey := "AKIA" + "5566778899AABBCC"
	oaiKey := "sk-proj-" + strings.Repeat("z9Y8", 7)
	pemKey := "-----BEGIN " + "PRIVATE KEY-----\\nTOPSECRET\\n-----END " + "PRIVATE KEY-----"

	// 1. Anthropic tool_use.input containing keys named "id", "name", "detail", "type", "model", "role",
	//    and even a nested {"type":"base64","data":"..."} MUST ALL be scanned & redacted,
	//    while the enclosing tool_use envelope ("id", "name", "type") stays intact.
	anthropicToolPayload := `{
		"model": "claude-sonnet-4-6",
		"messages": [{
			"role": "assistant",
			"content": [{
				"type": "tool_use",
				"id": "` + awsKey + `",
				"name": "http_request",
				"input": {
					"id": "` + oaiKey + `",
					"name": "` + awsKey + `",
					"detail": "` + awsKey + `",
					"type": "` + awsKey + `",
					"model": "` + awsKey + `",
					"role": "` + awsKey + `",
					"nested_blob": {"type": "base64", "data": "` + awsKey + `"}
				}
			}]
		}]
	}`
	res, err := eval.InspectJSONPayload(context.Background(), []byte(anthropicToolPayload))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionRedact {
		t.Fatalf("expected redact on Anthropic tool_use.input, got %q", res.Action)
	}
	var parsedAnth map[string]any
	if err := json.Unmarshal(res.ModifiedBody, &parsedAnth); err != nil {
		t.Fatalf("invalid redacted JSON: %v", err)
	}
	toolBlock := parsedAnth["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if toolBlock["id"] != awsKey || toolBlock["name"] != "http_request" || toolBlock["type"] != "tool_use" {
		t.Fatalf("enclosing tool_use envelope metadata should remain intact: %+v", toolBlock)
	}
	inputObj := toolBlock["input"].(map[string]any)
	if inputObj["id"] != "[REDACTED:builtin-openai-key]" {
		t.Fatalf("tool_use.input.id was not redacted: %v", inputObj["id"])
	}
	for _, k := range []string{"name", "detail", "type", "model", "role"} {
		if inputObj[k] != "[REDACTED:builtin-aws-access-key]" {
			t.Fatalf("tool_use.input.%s was not redacted: %v", k, inputObj[k])
		}
	}
	if inputObj["nested_blob"].(map[string]any)["data"] != "[REDACTED:builtin-aws-access-key]" {
		t.Fatalf("nested base64-shaped map inside tool_use.input must still be redacted: %+v", inputObj["nested_blob"])
	}

	// 2. PEM private key inside Anthropic tool_use.input.detail MUST trigger ActionBlock.
	anthropicBlockPayload := `{
		"model": "claude-sonnet-4-6",
		"messages": [{
			"role": "assistant",
			"content": [{
				"type": "tool_use",
				"id": "toolu_01",
				"name": "write_file",
				"input": {"detail": "` + pemKey + `"}
			}]
		}]
	}`
	blockRes, err := eval.InspectJSONPayload(context.Background(), []byte(anthropicBlockPayload))
	if err != nil {
		t.Fatal(err)
	}
	if blockRes.Action != ActionBlock {
		t.Fatalf("expected ActionBlock for PEM inside tool_use.input.detail, got %q", blockRes.Action)
	}

	// 3. Gemini functionCall.args and functionResponse.response MUST scan "detail", "id", "name", "type"
	//    while leaving functionCall.name / functionResponse.name intact.
	geminiToolPayload := `{
		"contents": [
			{"role": "model", "parts": [{"functionCall": {"name": "deploy", "args": {"id": "` + oaiKey + `", "detail": "` + awsKey + `", "name": "` + awsKey + `"}}}]},
			{"role": "user", "parts": [{"functionResponse": {"name": "deploy", "response": {"id": "` + awsKey + `", "detail": "` + oaiKey + `", "type": "` + awsKey + `"}}}]}
		]
	}`
	gemRes, err := eval.InspectJSONPayload(context.Background(), []byte(geminiToolPayload))
	if err != nil {
		t.Fatal(err)
	}
	if gemRes.Action != ActionRedact {
		t.Fatalf("expected redact on Gemini functionCall/functionResponse, got %q", gemRes.Action)
	}
	if strings.Contains(string(gemRes.ModifiedBody), awsKey) || strings.Contains(string(gemRes.ModifiedBody), oaiKey) {
		t.Fatalf("raw secrets survived in Gemini tool payload: %s", string(gemRes.ModifiedBody))
	}
	var parsedGem map[string]any
	if err := json.Unmarshal(gemRes.ModifiedBody, &parsedGem); err != nil {
		t.Fatal(err)
	}
	fc := parsedGem["contents"].([]any)[0].(map[string]any)["parts"].([]any)[0].(map[string]any)["functionCall"].(map[string]any)
	if fc["name"] != "deploy" {
		t.Fatalf("functionCall.name envelope should stay intact, got %v", fc["name"])
	}

	// 4. OpenAI image_url.detail stays skipped, while non-image_url "detail" and non-string envelope values are scanned.
	openAIPayload := `{
		"model": "gpt-4.1",
		"messages": [{
			"role": "user",
			"detail": "` + awsKey + `",
			"content": [
				{"type": "image_url", "image_url": {"url": "https://example.com/a.png", "detail": "high"}}
			]
		}],
		"extra": {"id": "` + oaiKey + `", "role": "` + awsKey + `"}
	}`
	oaiRes, err := eval.InspectJSONPayload(context.Background(), []byte(openAIPayload))
	if err != nil {
		t.Fatal(err)
	}
	if oaiRes.Action != ActionRedact {
		t.Fatalf("expected redact on non-image_url detail & extra object, got %q", oaiRes.Action)
	}
	if strings.Contains(string(oaiRes.ModifiedBody), awsKey) || strings.Contains(string(oaiRes.ModifiedBody), oaiKey) {
		t.Fatalf("raw secret survived in non-envelope keys: %s", string(oaiRes.ModifiedBody))
	}
	if !strings.Contains(string(oaiRes.ModifiedBody), `"detail":"high"`) {
		t.Fatalf("image_url.detail should remain intact: %s", string(oaiRes.ModifiedBody))
	}
}

func TestSyncReviewUnknownActionFailClosedAndFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"deny","reason":"nope"}`))
	}))
	defer srv.Close()

	st := newTestStore(t)
	wh := store.Webhook{
		ID:        "strict-review",
		Name:      "Strict Review",
		URL:       srv.URL,
		Type:      config.WebhookTypeSyncReview,
		TimeoutMS: 1000,
		FailOpen:  false,
		Enabled:   true,
	}
	if err := st.UpsertWebhook(context.Background(), wh); err != nil {
		t.Fatal(err)
	}

	var (
		logMu sync.Mutex
		logs  []string
	)
	disp := NewWebhookDispatcher(st, WebhookDispatcherOptions{
		RetryBackoff: 10 * time.Millisecond,
		Logf: func(format string, args ...any) {
			logMu.Lock()
			logs = append(logs, format)
			logMu.Unlock()
		},
	})
	defer func() { _ = disp.Close(context.Background()) }()

	req := SyncReviewRequest{
		RequestID: "req-unk-1",
		Subject:   "alice@example.com",
		Protocol:  "openai_chat",
		Model:     "openai/gpt-4.1",
		Body:      json.RawMessage(`{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}`),
	}

	// 1. fail_closed (FailOpen=false): unknown action "deny" MUST block with 503.
	out, err := disp.Review(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != ActionBlock || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected fail_closed 503 on unknown action 'deny', got %+v", out)
	}
	if !strings.Contains(out.Reason, `unknown action "deny"`) || !slices.Contains(out.Hits, "webhook:strict-review") {
		t.Fatalf("unexpected unknown-action outcome: %+v", out)
	}

	// 2. fail_open (FailOpen=true): unknown action "deny" logs warning and allows.
	wh.FailOpen = true
	if err := st.UpsertWebhook(context.Background(), wh); err != nil {
		t.Fatal(err)
	}
	out, err = disp.Review(context.Background(), req)
	if err != nil || out.Action != ActionAllow {
		t.Fatalf("expected fail_open allow on unknown action 'deny', got out=%+v err=%v", out, err)
	}
	logMu.Lock()
	logCount := len(logs)
	logMu.Unlock()
	if logCount == 0 {
		t.Fatalf("expected warning log when fail_open encounters unknown action")
	}
}

func TestWebhookSSRFDialGuard(t *testing.T) {
	blockedDefault := []string{
		"169.254.169.254:80",
		"169.254.0.1:443",
		"[::ffff:169.254.169.254]:80",
		"[fe80::1]:80",
		"[fd00:ec2::254]:80",
		"0.0.0.0:80",
		"[::]:80",
		"224.0.0.1:80",
		"[ff02::1]:80",
	}
	for _, addr := range blockedDefault {
		err := validateWebhookDialAddr(addr, false)
		if !errors.Is(err, ErrBlockedWebhookAddress) {
			t.Fatalf("expected %s to be blocked by SSRF guard, got err=%v", addr, err)
		}
	}

	allowedDefault := []string{
		"127.0.0.1:8080",
		"[::1]:8080",
		"100.64.0.10:8080",
		"10.0.0.5:8080",
		"1.1.1.1:443",
	}
	for _, addr := range allowedDefault {
		if err := validateWebhookDialAddr(addr, false); err != nil {
			t.Fatalf("expected %s to be allowed by default, got err=%v", addr, err)
		}
	}

	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "[::ffff:127.0.0.1]:8080"} {
		if err := validateWebhookDialAddr(addr, true); !errors.Is(err, ErrBlockedWebhookAddress) {
			t.Fatalf("expected %s to be blocked when BlockLoopback=true, got err=%v", addr, err)
		}
	}

	// End-to-end live dial check against AWS IPv4 & IPv6 IMDS fails immediately before TCP connect.
	st := newTestStore(t)
	disp := NewWebhookDispatcher(st, WebhookDispatcherOptions{RetryBackoff: 10 * time.Millisecond})
	defer func() { _ = disp.Close(context.Background()) }()

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	} {
		pingRes, err := disp.PingWebhook(context.Background(), store.Webhook{
			ID: "imds", Name: "IMDS", URL: target, TimeoutMS: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if pingRes.OK || !strings.Contains(pingRes.Message, ErrBlockedWebhookAddress.Error()) {
			t.Fatalf("expected SSRF block for %s, got %+v", target, pingRes)
		}
	}

	// Verify BlockLoopback option blocks even local httptest server.
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer localSrv.Close()

	strictDisp := NewWebhookDispatcher(st, WebhookDispatcherOptions{
		BlockLoopback: true,
		RetryBackoff:  10 * time.Millisecond,
	})
	defer func() { _ = strictDisp.Close(context.Background()) }()

	pingLoop, err := strictDisp.PingWebhook(context.Background(), store.Webhook{
		ID: "loop", Name: "Loop", URL: localSrv.URL, TimeoutMS: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pingLoop.OK || !strings.Contains(pingLoop.Message, ErrBlockedWebhookAddress.Error()) {
		t.Fatalf("expected BlockLoopback=true to block %s, got %+v", localSrv.URL, pingLoop)
	}
}
