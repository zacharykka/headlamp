package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/netts"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestParseGrants_HeadlampAndApertureFormats(t *testing.T) {
	rawCaps := map[string][]byte{
		CapHeadlampGateway: []byte(`[
			{"role":"user","models":["openai/gpt-5*","ollama/*"],"deny_models":"openai/gpt-5-pro","mcp_tools":["docs/*"],"deny_mcp_tools":["docs/delete_*"]}
		]`),
		CapApertureCompat: []byte(`[
			{"role":"admin"},
			{"models":"anthropic/**"},
			{"connectors":["github/read_*","Tailnet/**"]}
		]`),
	}

	parsed, err := ParseGrants(rawCaps)
	if err != nil {
		t.Fatalf("ParseGrants failed: %v", err)
	}
	if !parsed.HasGrants {
		t.Fatal("expected HasGrants=true")
	}
	if !slices.Contains(parsed.Roles, auth.RoleAdmin) || !slices.Contains(parsed.Roles, auth.RoleUser) {
		t.Errorf("unexpected roles: %v", parsed.Roles)
	}
	wantAllow := []string{"openai/gpt-5*", "ollama/*", "anthropic/**"}
	if !slices.Equal(parsed.AllowModels, wantAllow) {
		t.Errorf("AllowModels = %v, want %v", parsed.AllowModels, wantAllow)
	}
	if !slices.Equal(parsed.DenyModels, []string{"openai/gpt-5-pro"}) {
		t.Errorf("DenyModels = %v, want [openai/gpt-5-pro]", parsed.DenyModels)
	}
	wantTools := []string{"docs/*", "github/read_*", "Tailnet/**"}
	if !slices.Equal(parsed.AllowMCPTools, wantTools) {
		t.Errorf("AllowMCPTools = %v, want %v", parsed.AllowMCPTools, wantTools)
	}
	if !slices.Equal(parsed.DenyMCPTools, []string{"docs/delete_*"}) {
		t.Errorf("DenyMCPTools = %v, want [docs/delete_*]", parsed.DenyMCPTools)
	}
}

func TestParseGrants_MalformedJSONFailsClosed(t *testing.T) {
	ev := NewEvaluator()
	badPrincipal := &auth.Principal{
		Subject: "alice@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[{"role": "admin", "models": 12345}]`),
		},
	}

	if _, err := ParseGrants(badPrincipal.RawCaps); err == nil {
		t.Fatal("expected ParseGrants error on malformed capability JSON")
	}
	if ok, _, err := ev.AuthorizeModel(context.Background(), badPrincipal, "openai/gpt-5"); err == nil || ok {
		t.Fatalf("expected AuthorizeModel fail-closed error, got ok=%v err=%v", ok, err)
	}
	if denied, _, err := ev.IsModelDenied(context.Background(), badPrincipal, "openai/gpt-5"); err == nil || denied {
		t.Fatalf("expected IsModelDenied fail-closed error, got denied=%v err=%v", denied, err)
	}
}

func TestEvaluator_NoGrantsAllowsNothing(t *testing.T) {
	ctx := context.Background()
	ev := NewEvaluator()

	// Even if Principal.Roles were populated out-of-band without RawCaps, grants-only allows nothing.
	noGrants := &auth.Principal{
		Subject:    "bob@example.com",
		Roles:      []string{auth.RoleAdmin, auth.RoleUser},
		AuthSource: auth.AuthSourceTSNet,
	}

	ep, err := ev.Evaluate(ctx, noGrants)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if ep.GrantsApplied {
		t.Error("expected GrantsApplied=false when RawCaps is empty")
	}
	if ep.IsAdmin() || len(ep.Roles) != 0 {
		t.Errorf("expected no roles without grants, got %v", ep.Roles)
	}
	if ok, reason, err := ev.AuthorizeModel(ctx, noGrants, "openai/gpt-5"); err != nil || ok || reason == "" {
		t.Fatalf("expected model denied with reason, got ok=%v reason=%q err=%v", ok, reason, err)
	}
	if denied, reason, err := ev.IsModelDenied(ctx, noGrants, "openai/gpt-5"); err != nil || denied || reason != "" {
		t.Fatalf("expected IsModelDenied=false with no deny rules, got denied=%v reason=%q err=%v", denied, reason, err)
	}
	if isAdmin, err := ev.IsAdmin(ctx, noGrants); err != nil || isAdmin {
		t.Fatalf("expected IsAdmin=false without grants, got %v, %v", isAdmin, err)
	}

	// Nil principal must return ErrUnauthenticated.
	if _, err := ev.Evaluate(ctx, nil); err != auth.ErrUnauthenticated {
		t.Fatalf("expected ErrUnauthenticated for nil principal, got %v", err)
	}
	if _, _, err := ev.IsModelDenied(ctx, nil, "openai/gpt-5"); err != auth.ErrUnauthenticated {
		t.Fatalf("expected ErrUnauthenticated from IsModelDenied for nil principal, got %v", err)
	}
}

func TestEvaluator_ExplicitDenyWinsAndIsModelDenied(t *testing.T) {
	ctx := context.Background()
	ev := NewEvaluator()

	// Principal is allowed virtual alias "team/*" and wildcard "*" via one grant,
	// while explicit deny rules block "openai/o3*" and bare "claude-opus-*".
	alice := &auth.Principal{
		Subject: "alice@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[
				{"role":"admin","models":["team/*","anthropic/*","openai/*"],"deny_models":["openai/o3*","claude-opus-*"],"mcp_tools":["docs/*"],"deny_mcp_tools":["docs/secret_*"]}
			]`),
		},
	}

	// AuthorizeModel checks: Explicit Deny Wins over allows.
	authCases := []struct {
		model string
		want  bool
	}{
		{"team/coding", true},
		{"anthropic/claude-sonnet-4-6", true},
		{"anthropic/claude-opus-4-6", false}, // bare deny pattern matches provider/model
		{"claude-opus-4-6", false},           // bare deny pattern matches bare model
		{"openai/o3", false},                 // provider/model deny wins over openai/*
		{"openai/o3-mini", false},
		{"openai/gpt-5-mini", true},
		{"gemini/gemini-2.5-flash", false}, // not allowed
	}
	for _, tc := range authCases {
		got, reason, err := ev.AuthorizeModel(ctx, alice, tc.model)
		if err != nil {
			t.Fatalf("AuthorizeModel(%q) error: %v", tc.model, err)
		}
		if got != tc.want {
			t.Errorf("AuthorizeModel(%q) = %v (%s), want %v", tc.model, got, reason, tc.want)
		}
	}

	// IsModelDenied checks (P1-2): catches concrete upstream candidates behind allowed virtual aliases.
	denyCases := []struct {
		model      string
		wantDenied bool
	}{
		{"team/coding", false},
		{"openai/o3", true},
		{"openai/o3-mini", true},
		{"anthropic/claude-opus-4-6", true},
		{"claude-opus-4-6", true},
		{"openai/gpt-5-mini", false},
		{"gemini/gemini-2.5-flash", false}, // not in AllowModels, also not in DenyModels
		{"", false},
	}
	for _, tc := range denyCases {
		got, reason, err := ev.IsModelDenied(ctx, alice, tc.model)
		if err != nil {
			t.Fatalf("IsModelDenied(%q) error: %v", tc.model, err)
		}
		if got != tc.wantDenied {
			t.Errorf("IsModelDenied(%q) = %v (%q), want %v", tc.model, got, reason, tc.wantDenied)
		}
		if tc.wantDenied && reason == "" {
			t.Errorf("IsModelDenied(%q) returned empty reason", tc.model)
		}
	}

	// MCP tool Explicit Deny Wins check.
	if ok, _, err := ev.AuthorizeMCPTool(ctx, alice, "docs/read"); err != nil || !ok {
		t.Fatalf("expected docs/read allowed, got ok=%v err=%v", ok, err)
	}
	if ok, _, err := ev.AuthorizeMCPTool(ctx, alice, "docs/secret_keys"); err != nil || ok {
		t.Fatalf("expected docs/secret_keys denied, got ok=%v err=%v", ok, err)
	}
}

func TestEvaluator_GlobMatchingAndFilterModels(t *testing.T) {
	ctx := context.Background()
	ev := NewEvaluator()

	ciPrincipal := &auth.Principal{
		Subject: "tag:ci-runner",
		Tags:    []string{"tag:ci-runner"},
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[
				{"role":"user","models":["anthropic/claude-haiku-*","gpt-4.1-mini","team/*"],"deny_models":["team/expensive"]}
			]`),
		},
	}

	candidates := []string{
		"anthropic/claude-haiku-4-5",
		"anthropic/claude-sonnet-4-6",
		"openai/gpt-4.1-mini", // matches bare pattern "gpt-4.1-mini"
		"gpt-4.1-mini",        // exact bare match
		"claude-haiku-4-5",    // does NOT match provider-qualified "anthropic/claude-haiku-*"
		"team/coding",
		"team/expensive",
	}

	filtered, err := ev.FilterModels(ctx, ciPrincipal, candidates)
	if err != nil {
		t.Fatalf("FilterModels failed: %v", err)
	}

	want := []string{
		"anthropic/claude-haiku-4-5",
		"openai/gpt-4.1-mini",
		"gpt-4.1-mini",
		"team/coding",
	}
	if !slices.Equal(filtered, want) {
		t.Fatalf("FilterModels = %v, want %v", filtered, want)
	}
}

func TestEvaluator_AdminRoleImpliesUserRole(t *testing.T) {
	ctx := context.Background()
	ev := NewEvaluator()

	grantAdmin := &auth.Principal{
		Subject: "admin@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[{"role":"admin","models":["*"]}]`),
		},
	}
	ep, err := ev.Evaluate(ctx, grantAdmin)
	if err != nil {
		t.Fatalf("Evaluate(grantAdmin) failed: %v", err)
	}
	if !ep.IsAdmin() || !ep.HasRole(auth.RoleUser) {
		t.Fatalf("grant admin must imply user role: roles=%v", ep.Roles)
	}
	if !slices.Equal(ep.Roles, []string{auth.RoleAdmin, auth.RoleUser}) {
		t.Errorf("grantAdmin Roles = %v, want [admin user]", ep.Roles)
	}

	manual := &EffectivePolicy{Roles: []string{auth.RoleAdmin}}
	if !manual.HasRole(auth.RoleUser) {
		t.Error("EffectivePolicy.HasRole(user) must be true when admin role is present")
	}
}

func TestEvaluator_SynthesizedDevAndTokenRawCaps(t *testing.T) {
	ctx := context.Background()
	ev := NewEvaluator()

	// 1. DevAuthenticator synthesizes headlamp.dev/cap/gateway allowing "*" with configured roles.
	devAuth := auth.NewDevAuthenticator("dev@local", []string{auth.RoleAdmin}, false)
	devReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/v1/models", nil)
	devReq.RemoteAddr = "127.0.0.1:54321"
	devPrincipal, err := devAuth.Authenticate(devReq)
	if err != nil {
		t.Fatalf("DevAuthenticator failed: %v", err)
	}
	if isAdmin, err := ev.IsAdmin(ctx, devPrincipal); err != nil || !isAdmin {
		t.Fatalf("expected dev principal IsAdmin=true via synthesized grant, got %v, %v", isAdmin, err)
	}
	if ok, _, err := ev.AuthorizeModel(ctx, devPrincipal, "anthropic/claude-sonnet-4-6"); err != nil || !ok {
		t.Fatalf("expected dev principal allowed via synthesized wildcard grant, got ok=%v err=%v", ok, err)
	}

	// 2. TokenAuthenticator synthesizes scoped allow/deny models & MCP tools into RawCaps.
	tokAuth := auth.NewTokenAuthenticator([]auth.StaticToken{
		{
			Name:          "ci-bot",
			Token:         "hl_secret_ci_token",
			Subject:       "tag:ci-runner",
			Roles:         []string{auth.RoleUser},
			AllowModels:   []string{"openai/*", "team/*"},
			DenyModels:    []string{"openai/o3*"},
			AllowMCPTools: []string{"github/read_*"},
		},
	}, false)
	tokReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/chat/completions", nil)
	tokReq.Header.Set("Authorization", "Bearer hl_secret_ci_token")
	tokPrincipal, err := tokAuth.Authenticate(tokReq)
	if err != nil {
		t.Fatalf("TokenAuthenticator failed: %v", err)
	}

	if isAdmin, err := ev.IsAdmin(ctx, tokPrincipal); err != nil || isAdmin {
		t.Fatalf("expected token principal IsAdmin=false, got %v, %v", isAdmin, err)
	}
	if ok, _, err := ev.AuthorizeModel(ctx, tokPrincipal, "openai/gpt-4.1"); err != nil || !ok {
		t.Fatalf("expected openai/gpt-4.1 allowed for static token, got ok=%v err=%v", ok, err)
	}
	if denied, _, err := ev.IsModelDenied(ctx, tokPrincipal, "openai/o3"); err != nil || !denied {
		t.Fatalf("expected openai/o3 explicitly denied for static token, got denied=%v err=%v", denied, err)
	}
	if ok, _, err := ev.AuthorizeModel(ctx, tokPrincipal, "anthropic/claude-sonnet-4-6"); err != nil || ok {
		t.Fatalf("expected anthropic denied for static token, got ok=%v err=%v", ok, err)
	}
	if ok, _, err := ev.AuthorizeMCPTool(ctx, tokPrincipal, "github/read_issue"); err != nil || !ok {
		t.Fatalf("expected github/read_issue allowed for static token, got ok=%v err=%v", ok, err)
	}
}

type stubWhoIs struct {
	resp *apitype.WhoIsResponse
}

func (s stubWhoIs) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return s.resp, nil
}

func TestEndToEnd_TSNetWhoIsToPolicyEvaluator(t *testing.T) {
	ctx := context.Background()

	tsAuth := netts.NewTSNetAuthenticator(stubWhoIs{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ComputedName: "dev-laptop",
				Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "dev@example.com",
				DisplayName: "Dev User",
			},
			CapMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapability(CapApertureCompat): {
					tailcfg.RawMessage(`{"role":"user"}`),
					tailcfg.RawMessage(`{"models":"anthropic/**"}`),
					tailcfg.RawMessage(`{"connectors":["docs/**"]}`),
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://headlamp/anthropic/v1/messages", nil)
	req.RemoteAddr = "100.64.0.7:55555"

	principal, err := tsAuth.Authenticate(req)
	if err != nil {
		t.Fatalf("tsAuth.Authenticate failed: %v", err)
	}

	ev := NewEvaluator()
	if ok, _, err := ev.AuthorizeModel(ctx, principal, "anthropic/claude-sonnet-4-6"); err != nil || !ok {
		t.Fatalf("expected anthropic model allowed via Aperture grant, got ok=%v err=%v", ok, err)
	}
	if ok, _, err := ev.AuthorizeModel(ctx, principal, "openai/gpt-5"); err != nil || ok {
		t.Fatalf("expected openai model denied, got ok=%v err=%v", ok, err)
	}
	if toolOK, _, err := ev.AuthorizeMCPTool(ctx, principal, "docs/search"); err != nil || !toolOK {
		t.Fatalf("expected docs/search MCP tool allowed via Aperture connectors, got ok=%v err=%v", toolOK, err)
	}
}
