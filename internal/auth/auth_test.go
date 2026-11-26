package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeSynthesizedGrants(t *testing.T, rawCaps map[string][]byte) []synthesizedGrant {
	t.Helper()
	raw, ok := rawCaps[CapHeadlampGateway]
	if !ok {
		t.Fatalf("missing %s in RawCaps: %#v", CapHeadlampGateway, rawCaps)
	}
	var out []synthesizedGrant
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal RawCaps[%s]: %v (raw=%s)", CapHeadlampGateway, err, string(raw))
	}
	return out
}

func TestContextAndPrincipalHelpers(t *testing.T) {
	if p, ok := FromContext(context.Background()); ok || p != nil {
		t.Fatal("expected missing principal in empty context")
	}

	orig := &Principal{
		Subject:     "alice@example.com",
		DisplayName: "Alice",
		NodeName:    "alice-macbook",
		NodeIP:      "100.64.0.10",
		Tags:        []string{"tag:laptop"},
		Roles:       []string{RoleAdmin, RoleUser},
		RawCaps:     map[string][]byte{CapHeadlampGateway: []byte(`[{"role":"admin"}]`)},
		AuthSource:  AuthSourceTSNet,
	}

	ctx := WithPrincipal(context.Background(), orig)
	got, ok := FromContext(ctx)
	if !ok || got.Subject != "alice@example.com" {
		t.Fatalf("FromContext = (%+v, %v)", got, ok)
	}
	if !got.IsAdmin() || !got.HasRole(RoleUser) || !got.HasTag("tag:laptop") {
		t.Fatalf("helper predicates failed for %+v", got)
	}

	cp := orig.Clone()
	cp.Roles[0] = "mutated"
	cp.RawCaps[CapHeadlampGateway][0] = 'X'
	if orig.Roles[0] != RoleAdmin || orig.RawCaps[CapHeadlampGateway][0] != '[' {
		t.Fatal("Clone did not isolate slices/maps")
	}
}

func TestDevAuthenticatorHeaderOverrideAndGrantsSynthesis(t *testing.T) {
	// Default: allowHeaderOverride=false MUST ignore X-Headlamp-Dev-* headers even from loopback.
	devRestricted := NewDevAuthenticator("dev@local", []string{RoleUser}, false)
	reqLoopback := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	reqLoopback.RemoteAddr = "127.0.0.1:54321"
	reqLoopback.Header.Set("X-Headlamp-Dev-User", "attacker@example.com")
	reqLoopback.Header.Set("X-Headlamp-Dev-Roles", "admin")
	reqLoopback.Header.Set("X-Headlamp-Dev-Tags", "tag:pwned")

	p, err := devRestricted.Authenticate(reqLoopback)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "dev@local" || p.IsAdmin() || len(p.Tags) != 0 || p.AuthSource != AuthSourceDevMock {
		t.Fatalf("headers should be ignored when allowHeaderOverride=false, got: %+v", p)
	}
	grants := decodeSynthesizedGrants(t, p.RawCaps)
	if len(grants) != 1 || grants[0].Role != RoleUser || len(grants[0].Models) != 1 || grants[0].Models[0] != "*" || len(grants[0].MCPTools) != 1 || grants[0].MCPTools[0] != "*" {
		t.Fatalf("unexpected dev synthesized grants: %+v", grants)
	}

	// allowHeaderOverride=true STILL ignores headers from non-loopback peers.
	devOverride := NewDevAuthenticator("dev@local", []string{RoleUser}, true)
	reqRemote := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqRemote.RemoteAddr = "100.64.0.10:51234"
	reqRemote.Header.Set("X-Headlamp-Dev-User", "spoofed@example.com")
	reqRemote.Header.Set("X-Headlamp-Dev-Roles", "admin")
	pRemote, err := devOverride.Authenticate(reqRemote)
	if err != nil {
		t.Fatalf("Authenticate remote: %v", err)
	}
	if pRemote.Subject != "dev@local" || pRemote.IsAdmin() {
		t.Fatalf("headers should be ignored for non-loopback peer, got: %+v", pRemote)
	}

	// allowHeaderOverride=true honors headers from IPv4 & IPv6 loopback peers.
	for _, remoteAddr := range []string{"127.0.0.1:54321", "[::1]:54321"} {
		reqOverride := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		reqOverride.RemoteAddr = remoteAddr
		reqOverride.Header.Set("X-Headlamp-Dev-User", "bob@example.com")
		reqOverride.Header.Set("X-Headlamp-Dev-Roles", "admin, user")
		reqOverride.Header.Set("X-Headlamp-Dev-Tags", "tag:dev, tag:gpu")
		p2, err := devOverride.Authenticate(reqOverride)
		if err != nil {
			t.Fatalf("Authenticate override (%s): %v", remoteAddr, err)
		}
		if p2.Subject != "bob@example.com" || !p2.IsAdmin() || !p2.HasTag("tag:gpu") {
			t.Fatalf("unexpected override principal (%s): %+v", remoteAddr, p2)
		}
		grants2 := decodeSynthesizedGrants(t, p2.RawCaps)
		if len(grants2) != 1 || grants2[0].Role != RoleAdmin {
			t.Fatalf("expected admin role in synthesized grants (%s), got %+v", remoteAddr, grants2)
		}
	}
}

func TestTokenAuthenticatorHeadersGeminiQueryAndGrantsSynthesis(t *testing.T) {
	tokens := []StaticToken{
		{
			Name:          "ci-runner",
			Token:         "hl_tok_secret_123",
			Subject:       "tag:ci-runner",
			DisplayName:   "CI Runner",
			Roles:         []string{RoleUser},
			Tags:          []string{"tag:ci-runner"},
			AllowModels:   []string{"openai/gpt-4.1*", "gemini/*"},
			DenyModels:    []string{"openai/o3*"},
			AllowMCPTools: []string{"docs/*"},
			DenyMCPTools:  []string{"docs/delete_*"},
		},
		{
			Name:    "simple-token",
			Token:   "hl_tok_simple",
			Subject: "bot@example.com",
		},
	}

	strictAuth := NewTokenAuthenticator(tokens, false)

	// No token header -> (nil, nil) so chain can continue.
	reqNone := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if p, err := strictAuth.Authenticate(reqNone); p != nil || err != nil {
		t.Fatalf("expected (nil, nil) when no header, got (%+v, %v)", p, err)
	}

	// Bearer, x-api-key, and x-goog-api-key all work and synthesize explicit grants.
	headers := []struct {
		key string
		val string
	}{
		{"Authorization", "Bearer hl_tok_secret_123"},
		{"x-api-key", "hl_tok_secret_123"},
		{"x-goog-api-key", "hl_tok_secret_123"},
	}
	for _, h := range headers {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set(h.key, h.val)
		p, err := strictAuth.Authenticate(req)
		if err != nil {
			t.Fatalf("header %s failed: %v", h.key, err)
		}
		if p == nil || p.Subject != "tag:ci-runner" || p.AuthSource != AuthSourceAPIKey {
			t.Fatalf("header %s unexpected principal: %+v", h.key, p)
		}
		grants := decodeSynthesizedGrants(t, p.RawCaps)
		if len(grants) != 1 || len(grants[0].Models) != 2 || len(grants[0].DenyModels) != 1 ||
			len(grants[0].MCPTools) != 1 || len(grants[0].DenyMCPTools) != 1 {
			t.Fatalf("header %s unexpected synthesized grants: %+v", h.key, grants)
		}
	}

	// P2-4(2): Gemini ?key= query parameter fallback works ONLY on /gemini/* paths.
	reqGemQuery := httptest.NewRequest(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-flash:generateContent?key=hl_tok_secret_123", nil)
	pGem, err := strictAuth.Authenticate(reqGemQuery)
	if err != nil || pGem == nil || pGem.Subject != "tag:ci-runner" {
		t.Fatalf("gemini ?key= auth failed: (%+v, %v)", pGem, err)
	}

	// Non-Gemini path with ?key= must NOT authenticate via query parameter.
	reqNonGemQuery := httptest.NewRequest(http.MethodPost, "/v1/chat/completions?key=hl_tok_secret_123", nil)
	if p, err := strictAuth.Authenticate(reqNonGemQuery); p != nil || err != nil {
		t.Fatalf("non-gemini ?key= should be ignored, got (%+v, %v)", p, err)
	}

	// Simple token with empty AllowModels defaults synthesized models to ["*"].
	reqSimple := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqSimple.Header.Set("Authorization", "Bearer hl_tok_simple")
	pSimple, err := strictAuth.Authenticate(reqSimple)
	if err != nil {
		t.Fatalf("simple token failed: %v", err)
	}
	simpleGrants := decodeSynthesizedGrants(t, pSimple.RawCaps)
	if len(simpleGrants) != 1 || simpleGrants[0].Role != RoleUser || len(simpleGrants[0].Models) != 1 || simpleGrants[0].Models[0] != "*" {
		t.Fatalf("expected default models=[\"*\"] for simple token, got %+v", simpleGrants)
	}

	// Wrong token in strict mode returns ErrInvalidToken.
	reqBad := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	reqBad.Header.Set("Authorization", "Bearer wrong")
	if _, err := strictAuth.Authenticate(reqBad); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got err %v, want ErrInvalidToken", err)
	}

	// Wrong token in ignoreUnknown mode falls through for dev_mock chaining.
	lenientAuth := NewTokenAuthenticator(tokens, true)
	chain := NewChainAuthenticator(lenientAuth, NewDevAuthenticator("dev@local", nil, false))
	p, err := chain.Authenticate(reqBad)
	if err != nil {
		t.Fatalf("chain fallback failed: %v", err)
	}
	if p.AuthSource != AuthSourceDevMock || p.Subject != "dev@local" {
		t.Fatalf("expected dev fallback, got %+v", p)
	}
}

func TestMiddleware(t *testing.T) {
	chain := NewChainAuthenticator(NewTokenAuthenticator([]StaticToken{
		{Token: "good-token", Subject: "alice@example.com", Roles: []string{RoleUser}},
	}, false))

	var captured *Principal
	handler := Middleware(chain, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("missing principal in handler context")
		}
		captured = p
		w.WriteHeader(http.StatusOK)
	}))

	// Unauthorized without credentials.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	// Authorized with valid token.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req2.Header.Set("Authorization", "Bearer good-token")
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec2.Code)
	}
	if captured == nil || captured.Subject != "alice@example.com" {
		t.Fatalf("captured = %+v", captured)
	}
}
