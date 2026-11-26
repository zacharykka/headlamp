package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/netts"
	"github.com/zacharykka/headlamp/internal/store"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
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

func TestParseGrants_HeadlampAndApertureFormats(t *testing.T) {
	rawCaps := map[string][]byte{
		CapHeadlampGateway: []byte(`[
			{"role":"user","models":["openai/gpt-5*","ollama/*"],"deny_models":"openai/gpt-5-pro","mcp_tools":["docs/*"]}
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
}

func TestParseGrants_MalformedJSONFailsClosed(t *testing.T) {
	_, err := ParseGrants(map[string][]byte{
		CapHeadlampGateway: []byte(`[{"role": "admin", "models": 12345}]`),
	})
	if err == nil {
		t.Fatal("expected error on malformed capability JSON")
	}
}

func TestEvaluator_AllThreeModes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertGroup(ctx, store.Group{
		Name:    "engineering",
		Members: []string{"bob@example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPolicy(ctx, store.Policy{
		ID:          "eng-local",
		Name:        "eng-local",
		Subject:     "group:engineering",
		Role:        auth.RoleUser,
		AllowModels: []string{"openai/*"},
		DenyModels:  []string{"openai/o3*"},
		Enabled:     true,
	}); err != nil {
		t.Fatal(err)
	}

	bob := &auth.Principal{
		Subject: "bob@example.com",
		RawCaps: map[string][]byte{
			CapApertureCompat: []byte(`[{"role":"admin"},{"models":"anthropic/**"}]`),
		},
		AuthSource: auth.AuthSourceTSNet,
	}

	t.Run("hybrid merges local and grants with explicit deny wins", func(t *testing.T) {
		ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeHybrid}, st)

		ok, _, err := ev.AuthorizeModel(ctx, bob, "openai/gpt-5")
		if err != nil || !ok {
			t.Fatalf("expected local allow openai/gpt-5, got ok=%v err=%v", ok, err)
		}
		ok, _, err = ev.AuthorizeModel(ctx, bob, "anthropic/claude-sonnet-4-6")
		if err != nil || !ok {
			t.Fatalf("expected grant allow anthropic/claude-sonnet-4-6, got ok=%v err=%v", ok, err)
		}
		ok, reason, err := ev.AuthorizeModel(ctx, bob, "openai/o3")
		if err != nil || ok {
			t.Fatalf("expected explicit deny for openai/o3, got ok=%v reason=%q err=%v", ok, reason, err)
		}
		ok, _, err = ev.AuthorizeModel(ctx, bob, "gemini/gemini-2.5-pro")
		if err != nil || ok {
			t.Fatalf("expected default deny for gemini/gemini-2.5-pro, got ok=%v err=%v", ok, err)
		}
		isAdmin, err := ev.IsAdmin(ctx, bob)
		if err != nil || !isAdmin {
			t.Fatalf("expected admin role from Aperture grant in hybrid mode, got %v, %v", isAdmin, err)
		}
	})

	t.Run("local_only ignores Headscale grants completely", func(t *testing.T) {
		ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeLocalOnly}, st)

		ok, _, err := ev.AuthorizeModel(ctx, bob, "openai/gpt-5")
		if err != nil || !ok {
			t.Fatalf("expected local allow openai/gpt-5, got ok=%v err=%v", ok, err)
		}
		ok, _, err = ev.AuthorizeModel(ctx, bob, "anthropic/claude-sonnet-4-6")
		if err != nil || ok {
			t.Fatalf("expected anthropic denied when grants ignored in local_only, got ok=%v err=%v", ok, err)
		}
		isAdmin, err := ev.IsAdmin(ctx, bob)
		if err != nil || isAdmin {
			t.Fatalf("expected IsAdmin=false in local_only mode (grant admin ignored), got %v, %v", isAdmin, err)
		}
	})

	t.Run("grants_only ignores local policies completely", func(t *testing.T) {
		ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeGrantsOnly}, st)

		ok, _, err := ev.AuthorizeModel(ctx, bob, "anthropic/claude-sonnet-4-6")
		if err != nil || !ok {
			t.Fatalf("expected grant allow anthropic/claude-sonnet-4-6, got ok=%v err=%v", ok, err)
		}
		ok, _, err = ev.AuthorizeModel(ctx, bob, "openai/gpt-5")
		if err != nil || ok {
			t.Fatalf("expected local openai/gpt-5 denied in grants_only mode, got ok=%v err=%v", ok, err)
		}

		// User with no grants is denied cleanly.
		noGrants := &auth.Principal{Subject: "bob@example.com"}
		ok, reason, err := ev.AuthorizeModel(ctx, noGrants, "openai/gpt-5")
		if err != nil || ok || reason == "" {
			t.Fatalf("expected denied with reason when no grants present, got ok=%v reason=%q err=%v", ok, reason, err)
		}
	})
}

func TestEvaluator_ExplicitDenyWinsAcrossTracks(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Local deny-only rule blocking Opus models for everyone.
	if err := st.UpsertPolicy(ctx, store.Policy{
		ID:         "global-deny-opus",
		Name:       "global-deny-opus",
		Subject:    "*",
		DenyModels: []string{"anthropic/claude-opus-*", "o3*"},
		Enabled:    true,
	}); err != nil {
		t.Fatal(err)
	}
	// Disabled policy should have no effect.
	if err := st.UpsertPolicy(ctx, store.Policy{
		ID:          "disabled-allow",
		Name:        "disabled-allow",
		Subject:     "*",
		AllowModels: []string{"gemini/*"},
		Enabled:     false,
	}); err != nil {
		t.Fatal(err)
	}

	ev := NewEvaluator(config.PolicyConfig{
		Mode:            config.PolicyModeHybrid,
		BootstrapAdmins: []string{"alice@example.com"},
	}, st)

	// Bootstrap admin has wildcard allow, yet Explicit Deny still wins!
	alice := &auth.Principal{
		Subject: "alice@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[{"role":"admin","models":["**"],"deny_models":["openai/gpt-5.4"]}]`),
		},
	}

	isAdmin, err := ev.IsAdmin(ctx, alice)
	if err != nil || !isAdmin {
		t.Fatalf("expected bootstrap admin IsAdmin=true, got %v, %v", isAdmin, err)
	}

	cases := []struct {
		model string
		want  bool
	}{
		{"anthropic/claude-sonnet-4-6", true},
		{"anthropic/claude-opus-4-6", false}, // local deny overrides bootstrap & grant wildcard
		{"openai/o3-mini", false},            // bare deny pattern "o3*" matches "openai/o3-mini"
		{"o3", false},                        // bare deny pattern matches bare "o3"
		{"openai/gpt-5.4", false},            // grant deny_models overrides bootstrap wildcard
		{"openai/gpt-5-mini", true},
	}
	for _, tc := range cases {
		got, reason, err := ev.AuthorizeModel(ctx, alice, tc.model)
		if err != nil {
			t.Fatalf("AuthorizeModel(%q) err: %v", tc.model, err)
		}
		if got != tc.want {
			t.Errorf("AuthorizeModel(%q) = %v (%s), want %v", tc.model, got, reason, tc.want)
		}
	}

	// Regular user with grant allow still obeys disabled policy check (gemini not granted).
	carol := &auth.Principal{
		Subject: "carol@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[{"role":"user","models":["anthropic/*"]}]`),
		},
	}
	ok, _, err := ev.AuthorizeModel(ctx, carol, "gemini/gemini-2.5-flash")
	if err != nil || ok {
		t.Fatalf("disabled local policy should not allow gemini, got ok=%v err=%v", ok, err)
	}
}

func TestEvaluator_GlobMatchingAndFilterModels(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertGroup(ctx, store.Group{
		Name:    "ci",
		Members: []string{"tag:ci-runner"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPolicy(ctx, store.Policy{
		ID:          "ci-models",
		Name:        "ci-models",
		Subject:     "group:ci",
		AllowModels: []string{"anthropic/claude-haiku-*", "gpt-4.1-mini", "team/*"},
		DenyModels:  []string{"team/expensive"},
		Enabled:     true,
	}); err != nil {
		t.Fatal(err)
	}

	ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeHybrid}, st)
	ciPrincipal := &auth.Principal{
		Subject: "tag:ci-runner",
		Tags:    []string{"tag:ci-runner"},
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

func TestEvaluator_BootstrapAdminWithoutSyncConfig(t *testing.T) {
	ctx := context.Background()

	// nil store verifies Evaluator handles BootstrapAdmins directly even without SyncConfig.
	ev := NewEvaluator(config.PolicyConfig{
		Mode:            config.PolicyModeLocalOnly,
		BootstrapAdmins: []string{"alice@example.com"},
	}, nil)

	alice := &auth.Principal{Subject: "alice@example.com"}
	isAdmin, err := ev.IsAdmin(ctx, alice)
	if err != nil || !isAdmin {
		t.Fatalf("expected IsAdmin=true for bootstrap admin, got %v, %v", isAdmin, err)
	}
	ok, _, err := ev.AuthorizeModel(ctx, alice, "anthropic/claude-sonnet-4-6")
	if err != nil || !ok {
		t.Fatalf("expected bootstrap admin allowed in local_only mode, got ok=%v err=%v", ok, err)
	}

	// Nil principal must return ErrUnauthenticated.
	if _, err := ev.Evaluate(ctx, nil); err != auth.ErrUnauthenticated {
		t.Fatalf("expected ErrUnauthenticated for nil principal, got %v", err)
	}
}

func TestEvaluator_AdminRoleImpliesUserRole(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertPolicy(ctx, store.Policy{
		ID:          "local-admin",
		Name:        "local-admin",
		Subject:     "local-admin@example.com",
		Role:        auth.RoleAdmin,
		AllowModels: []string{"*"},
		Enabled:     true,
	}); err != nil {
		t.Fatal(err)
	}

	ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeHybrid}, st)

	// 1. Admin via Headscale grant only.
	grantAdmin := &auth.Principal{
		Subject: "grant-admin@example.com",
		RawCaps: map[string][]byte{
			CapHeadlampGateway: []byte(`[{"role":"admin","models":["anthropic/*"]}]`),
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

	// 2. Admin via local policy only.
	localAdmin := &auth.Principal{Subject: "local-admin@example.com"}
	ep, err = ev.Evaluate(ctx, localAdmin)
	if err != nil {
		t.Fatalf("Evaluate(localAdmin) failed: %v", err)
	}
	if !ep.IsAdmin() || !ep.HasRole(auth.RoleUser) {
		t.Fatalf("local policy admin must imply user role: roles=%v", ep.Roles)
	}
	if !slices.Equal(ep.Roles, []string{auth.RoleAdmin, auth.RoleUser}) {
		t.Errorf("localAdmin Roles = %v, want [admin user]", ep.Roles)
	}

	// 3. Direct EffectivePolicy.HasRole check when constructed manually with only RoleAdmin.
	manual := &EffectivePolicy{Roles: []string{auth.RoleAdmin}}
	if !manual.HasRole(auth.RoleUser) {
		t.Error("EffectivePolicy.HasRole(user) must be true when admin role is present")
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
	st := newTestStore(t)

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

	ev := NewEvaluator(config.PolicyConfig{Mode: config.PolicyModeHybrid}, st)
	ok, _, err := ev.AuthorizeModel(ctx, principal, "anthropic/claude-sonnet-4-6")
	if err != nil || !ok {
		t.Fatalf("expected anthropic model allowed via Aperture grant, got ok=%v err=%v", ok, err)
	}
	ok, _, err = ev.AuthorizeModel(ctx, principal, "openai/gpt-5")
	if err != nil || ok {
		t.Fatalf("expected openai model denied, got ok=%v err=%v", ok, err)
	}
	toolOK, _, err := ev.AuthorizeMCPTool(ctx, principal, "docs/search")
	if err != nil || !toolOK {
		t.Fatalf("expected docs/search MCP tool allowed via Aperture connectors, got ok=%v err=%v", toolOK, err)
	}
}
