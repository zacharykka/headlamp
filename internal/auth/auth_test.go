package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		Groups:      []string{"engineering"},
		Roles:       []string{RoleAdmin, RoleUser},
		RawCaps:     map[string][]byte{"headlamp.dev/cap/gateway": []byte(`[{"role":"admin"}]`)},
		AuthSource:  AuthSourceTSNet,
	}

	ctx := WithPrincipal(context.Background(), orig)
	got, ok := FromContext(ctx)
	if !ok || got.Subject != "alice@example.com" {
		t.Fatalf("FromContext = (%+v, %v)", got, ok)
	}
	if !got.IsAdmin() || !got.HasRole(RoleUser) || !got.HasGroup("engineering") || !got.HasTag("tag:laptop") {
		t.Fatalf("helper predicates failed for %+v", got)
	}

	cp := orig.Clone()
	cp.Roles[0] = "mutated"
	cp.RawCaps["headlamp.dev/cap/gateway"][0] = 'X'
	if orig.Roles[0] != RoleAdmin || orig.RawCaps["headlamp.dev/cap/gateway"][0] != '[' {
		t.Fatal("Clone did not isolate slices/maps")
	}
}

func TestDevAuthenticator(t *testing.T) {
	dev := NewDevAuthenticator("dev@local", []string{RoleUser})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	p, err := dev.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "dev@local" || p.AuthSource != AuthSourceDevMock || p.NodeIP != "127.0.0.1" {
		t.Fatalf("unexpected principal: %+v", p)
	}

	reqOverride := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqOverride.Header.Set("X-Headlamp-Dev-User", "bob@example.com")
	reqOverride.Header.Set("X-Headlamp-Dev-Roles", "admin, user")
	reqOverride.Header.Set("X-Headlamp-Dev-Tags", "tag:dev, tag:gpu")
	p2, err := dev.Authenticate(reqOverride)
	if err != nil {
		t.Fatalf("Authenticate override: %v", err)
	}
	if p2.Subject != "bob@example.com" || !p2.IsAdmin() || !p2.HasTag("tag:gpu") {
		t.Fatalf("unexpected override principal: %+v", p2)
	}
}

func TestTokenAuthenticator(t *testing.T) {
	tokens := []StaticToken{
		{
			Name:        "ci-runner",
			Token:       "hl_tok_secret_123",
			Subject:     "tag:ci-runner",
			DisplayName: "CI Runner",
			Groups:      []string{"automation"},
			Roles:       []string{RoleUser},
			Tags:        []string{"tag:ci-runner"},
		},
	}

	strictAuth := NewTokenAuthenticator(tokens, false)

	// No token header -> (nil, nil) so chain can continue.
	reqNone := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if p, err := strictAuth.Authenticate(reqNone); p != nil || err != nil {
		t.Fatalf("expected (nil, nil) when no header, got (%+v, %v)", p, err)
	}

	// Bearer, x-api-key, and x-goog-api-key all work.
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
		if p == nil || p.Subject != "tag:ci-runner" || p.AuthSource != AuthSourceAPIKey || !p.HasGroup("automation") {
			t.Fatalf("header %s unexpected principal: %+v", h.key, p)
		}
	}

	// Wrong token in strict mode returns ErrInvalidToken.
	reqBad := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	reqBad.Header.Set("Authorization", "Bearer wrong")
	if _, err := strictAuth.Authenticate(reqBad); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got err %v, want ErrInvalidToken", err)
	}

	// Wrong token in ignoreUnknown mode falls through for dev_mock chaining.
	lenientAuth := NewTokenAuthenticator(tokens, true)
	chain := NewChainAuthenticator(lenientAuth, NewDevAuthenticator("dev@local", nil))
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
