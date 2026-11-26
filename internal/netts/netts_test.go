package netts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type mockWhoIsClient struct {
	fn       func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
	lastAddr string
}

func (m *mockWhoIsClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	m.lastAddr = remoteAddr
	if m.fn == nil {
		return nil, local.ErrPeerNotFound
	}
	return m.fn(ctx, remoteAddr)
}

func TestTSNetAuthenticator_UserNodeAndCapMap(t *testing.T) {
	mock := &mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ID:           101,
					StableID:     "node-stable-101",
					Name:         "alice-macbook.tailnet.internal.",
					ComputedName: "alice-macbook",
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.12/32"),
						netip.MustParsePrefix("fd7a:115c:a1e0::12/128"),
					},
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          1,
					LoginName:   "alice@example.com",
					DisplayName: "Alice Smith",
				},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapability("headlamp.dev/cap/gateway"): {
						tailcfg.RawMessage(`{"role":"admin","models":["anthropic/*","openai/gpt-5*"]}`),
					},
					tailcfg.PeerCapability("tailscale.com/cap/aperture"): {
						tailcfg.RawMessage(`{"role":"user"}`),
						tailcfg.RawMessage(`{"models":"anthropic/**"}`),
					},
					tailcfg.PeerCapability("example.com/cap/flag"): {},
				},
			}, nil
		},
	}

	authenticator := NewTSNetAuthenticator(mock)
	req := httptest.NewRequest(http.MethodPost, "http://headlamp/v1/chat/completions", nil)
	req.RemoteAddr = "100.64.0.12:51822"

	p, err := authenticator.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate returned unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil Principal")
	}

	// Verify r.RemoteAddr (including port!) was passed verbatim to WhoIs.
	if mock.lastAddr != "100.64.0.12:51822" {
		t.Fatalf("expected verbatim RemoteAddr %q, got %q", "100.64.0.12:51822", mock.lastAddr)
	}

	if p.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want %q", p.Subject, "alice@example.com")
	}
	if p.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName = %q, want %q", p.DisplayName, "Alice Smith")
	}
	if p.NodeName != "alice-macbook" {
		t.Errorf("NodeName = %q, want %q", p.NodeName, "alice-macbook")
	}
	if p.NodeIP != "100.64.0.12" {
		t.Errorf("NodeIP = %q, want %q", p.NodeIP, "100.64.0.12")
	}
	if p.AuthSource != auth.AuthSourceTSNet {
		t.Errorf("AuthSource = %q, want %q", p.AuthSource, auth.AuthSourceTSNet)
	}

	// Verify CapMap entries were marshaled as JSON arrays preserving all objects.
	rawAperture, ok := p.RawCaps["tailscale.com/cap/aperture"]
	if !ok {
		t.Fatal("expected tailscale.com/cap/aperture in RawCaps")
	}
	var apertureItems []map[string]any
	if err := json.Unmarshal(rawAperture, &apertureItems); err != nil {
		t.Fatalf("unmarshal RawCaps aperture array: %v (raw=%s)", err, string(rawAperture))
	}
	if len(apertureItems) != 2 {
		t.Fatalf("expected 2 aperture objects, got %d (%s)", len(apertureItems), string(rawAperture))
	}
	if apertureItems[0]["role"] != "user" || apertureItems[1]["models"] != "anthropic/**" {
		t.Errorf("unexpected aperture items: %+v", apertureItems)
	}

	rawFlag := p.RawCaps["example.com/cap/flag"]
	if string(rawFlag) != "[]" {
		t.Errorf("empty capability slice marshaled as %q, want %q", string(rawFlag), "[]")
	}
}

func TestTSNetAuthenticator_TaggedNodeNeverUsesTaggedDevicesUser(t *testing.T) {
	mock := &mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ID:       202,
					StableID: "node-ci-202",
					Name:     "ci-worker-01.tailnet.internal.",
					// ComputedName intentionally empty to exercise Name fallback stripping trailing dot & domain.
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.99/32"),
					},
					Tags: []string{"tag:ci-runner", "tag:build"},
				},
				// Headscale v0.28+ / Tailscale populates synthetic "tagged-devices" here.
				UserProfile: &tailcfg.UserProfile{
					ID:          2147455555,
					LoginName:   "tagged-devices",
					DisplayName: "Tagged Devices",
				},
			}, nil
		},
	}

	authenticator := NewTSNetAuthenticator(mock)
	req := httptest.NewRequest(http.MethodGet, "http://headlamp/v1/models", nil)
	req.RemoteAddr = "[fd7a:115c:a1e0::99]:44123"

	p, err := authenticator.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if mock.lastAddr != "[fd7a:115c:a1e0::99]:44123" {
		t.Errorf("expected IPv6 RemoteAddr preserved verbatim, got %q", mock.lastAddr)
	}
	if p.Subject == "tagged-devices" {
		t.Fatal("Subject must never be synthetic tagged-devices user")
	}
	if p.Subject != "tag:ci-runner" {
		t.Errorf("Subject = %q, want %q", p.Subject, "tag:ci-runner")
	}
	if p.NodeName != "ci-worker-01" {
		t.Errorf("NodeName = %q, want %q", p.NodeName, "ci-worker-01")
	}
	if p.DisplayName != "ci-worker-01" {
		t.Errorf("DisplayName = %q, want %q", p.DisplayName, "ci-worker-01")
	}
	if !slices.Equal(p.Tags, []string{"tag:ci-runner", "tag:build"}) {
		t.Errorf("Tags = %v, want [tag:ci-runner tag:build]", p.Tags)
	}
}

func TestTSNetAuthenticator_GuardsSyntheticTaggedDevicesWithoutTags(t *testing.T) {
	mock := &mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ID:           203,
					StableID:     "node-edge-203",
					ComputedName: "edge-box",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.100/32")},
					// Tags unexpectedly empty while LoginName is synthetic "tagged-devices".
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          2147455555,
					LoginName:   "tagged-devices@",
					DisplayName: "Tagged Devices",
				},
			}, nil
		},
	}

	authenticator := NewTSNetAuthenticator(mock)
	req := httptest.NewRequest(http.MethodGet, "http://headlamp/v1/models", nil)
	req.RemoteAddr = "100.64.0.100:44444"

	p, err := authenticator.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if strings.Contains(strings.ToLower(p.Subject), "tagged-devices") {
		t.Fatalf("Subject must never fall back to synthetic tagged-devices, got %q", p.Subject)
	}
	if p.Subject != "edge-box" {
		t.Errorf("Subject = %q, want %q", p.Subject, "edge-box")
	}
	if p.DisplayName != "edge-box" {
		t.Errorf("DisplayName = %q, want %q", p.DisplayName, "edge-box")
	}
}

func TestTSNetAuthenticator_PeerNotFoundFallsThroughChain(t *testing.T) {
	mock := &mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return nil, local.ErrPeerNotFound
		},
	}

	tsAuth := NewTSNetAuthenticator(mock)
	devAuth := auth.NewDevAuthenticator("dev@local", []string{auth.RoleAdmin}, false)
	chain := auth.NewChainAuthenticator(tsAuth, devAuth)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:50000"

	p, err := tsAuth.Authenticate(req)
	if err != nil || p != nil {
		t.Fatalf("expected (nil, nil) on ErrPeerNotFound, got (%+v, %v)", p, err)
	}

	p, err = chain.Authenticate(req)
	if err != nil {
		t.Fatalf("chain.Authenticate returned error: %v", err)
	}
	if p == nil || p.Subject != "dev@local" || p.AuthSource != auth.AuthSourceDevMock {
		t.Fatalf("expected fallback to dev authenticator, got %+v", p)
	}
}

func TestTSNetAuthenticator_UnexpectedWhoIsError(t *testing.T) {
	boom := errors.New("localapi unavailable")
	mock := &mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return nil, boom
		},
	}

	tsAuth := NewTSNetAuthenticator(mock)
	req := httptest.NewRequest(http.MethodGet, "http://headlamp/v1/models", nil)
	req.RemoteAddr = "100.64.0.5:12345"

	p, err := tsAuth.Authenticate(req)
	if p != nil || !errors.Is(err, boom) {
		t.Fatalf("expected wrapped error %v, got (%+v, %v)", boom, p, err)
	}
}

func TestWrapTLSListener_Modes(t *testing.T) {
	t.Run("none returns listener unmodified", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawLn.Close()

		got, err := WrapTLSListener(rawLn, config.TLSConfig{Mode: config.TLSModeNone})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != rawLn {
			t.Fatalf("expected original listener unchanged for tls.mode=none")
		}
	})

	t.Run("acme_dns01 returns clear M2 error", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawLn.Close()

		_, err = WrapTLSListener(rawLn, config.TLSConfig{
			Mode:        config.TLSModeACMEDNS01,
			Domain:      "ai.internal.example.com",
			DNSProvider: "cloudflare",
		})
		if err == nil {
			t.Fatal("expected error for acme_dns01 in M1")
		}
		if !strings.Contains(err.Error(), "M2") {
			t.Errorf("expected error to mention M2, got: %v", err)
		}
	})

	t.Run("static wraps listener and serves real TLS", func(t *testing.T) {
		certFile, keyFile, certPool := generateSelfSignedCertFiles(t)

		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		tlsLn, err := WrapTLSListener(rawLn, config.TLSConfig{
			Mode:     config.TLSModeStatic,
			CertFile: certFile,
			KeyFile:  keyFile,
		})
		if err != nil {
			_ = rawLn.Close()
			t.Fatalf("WrapTLSListener static failed: %v", err)
		}

		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("hello-tls"))
			}),
		}
		serveDone := make(chan error, 1)
		go func() {
			serveDone <- srv.Serve(tlsLn)
		}()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			<-serveDone
		}()

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					ServerName: "127.0.0.1",
				},
			},
			Timeout: 3 * time.Second,
		}

		resp, err := client.Get("https://" + tlsLn.Addr().String())
		if err != nil {
			t.Fatalf("HTTPS GET failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if string(body) != "hello-tls" {
			t.Fatalf("response body = %q, want %q", string(body), "hello-tls")
		}
	})

	t.Run("static with missing cert fails clearly", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawLn.Close()

		_, err = WrapTLSListener(rawLn, config.TLSConfig{
			Mode:     config.TLSModeStatic,
			CertFile: filepath.Join(t.TempDir(), "missing.crt"),
			KeyFile:  filepath.Join(t.TempDir(), "missing.key"),
		})
		if err == nil {
			t.Fatal("expected error for missing static cert/key files")
		}
	})
}

func TestServer_LocalListenerLifecycle(t *testing.T) {
	srv, err := NewServer(config.ServerConfig{
		TSNet: config.TSNetConfig{
			Enabled: false,
		},
		LocalListen: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if srv.Authenticator() != nil {
		t.Error("expected nil Authenticator when tsnet is disabled")
	}
	if _, err := srv.LocalClient(); err == nil {
		t.Error("expected LocalClient() error when tsnet is disabled")
	}
	if srv.TailnetAddr() != "" {
		t.Errorf("expected empty TailnetAddr, got %q", srv.TailnetAddr())
	}
	localAddr := srv.LocalAddr()
	if localAddr == "" {
		t.Fatal("expected non-empty LocalAddr after Start")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(handler)
	}()

	resp, err := http.Get("http://" + localAddr + "/healthz")
	if err != nil {
		t.Fatalf("GET local listener failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, string(body))
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer closeCancel()
	if err := srv.Close(closeCtx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Closing a second time must be idempotent.
	if err := srv.Close(closeCtx); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve returned unexpected error on graceful shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Serve to exit after Close")
	}
}

func TestNewServer_Validation(t *testing.T) {
	_, err := NewServer(config.ServerConfig{
		TSNet:       config.TSNetConfig{Enabled: false},
		LocalListen: "",
	})
	if err == nil {
		t.Fatal("expected error when neither tsnet nor local_listen is enabled")
	}

	_, err = NewServer(config.ServerConfig{
		TSNet: config.TSNetConfig{
			Enabled:  true,
			Hostname: "headlamp",
			StateDir: t.TempDir(),
		},
		TLS: config.TLSConfig{
			Mode:        config.TLSModeACMEDNS01,
			Domain:      "ai.example.com",
			DNSProvider: "cloudflare",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "M2") {
		t.Fatalf("expected M2 error for acme_dns01, got %v", err)
	}
}

func TestServer_ServeHandlersListenerIsolation(t *testing.T) {
	tailnetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tailnet mock: %v", err)
	}
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = tailnetLn.Close()
		t.Fatalf("listen local mock: %v", err)
	}

	srv := &Server{
		started:   true,
		tailnetLn: tailnetLn,
		localLn:   localLn,
	}

	// Nil handler for an active listener must fail before serving.
	if err := srv.ServeHandlers(nil, http.NotFoundHandler()); err == nil {
		t.Fatal("expected error when tailnetHandler is nil with active tailnet listener")
	}
	if err := srv.ServeHandlers(http.NotFoundHandler(), nil); err == nil {
		t.Fatal("expected error when localHandler is nil with active local listener")
	}

	// Tailnet listener enforces Tailnet-only WhoIs (never falls back to DevAuthenticator or tokens).
	tsOnlyAuth := NewTSNetAuthenticator(&mockWhoIsClient{
		fn: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return nil, local.ErrPeerNotFound
		},
	})
	tailnetHandler := auth.Middleware(tsOnlyAuth, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tailnet-ok"))
	}))

	// Local listener accepts loopback dev_mode / static token callers.
	localAuth := auth.NewDevAuthenticator("dev@local", []string{auth.RoleAdmin}, false)
	localHandler := auth.Middleware(localAuth, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.FromContext(r.Context())
		_, _ = w.Write([]byte("local:" + p.Subject))
	}))

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ServeHandlers(tailnetHandler, localHandler)
	}()

	// Non-tailnet caller hitting tailnet listener MUST receive 401 (never dev_mock).
	tailResp, err := http.Get("http://" + srv.TailnetAddr() + "/whoami")
	if err != nil {
		t.Fatalf("GET tailnet listener failed: %v", err)
	}
	_ = tailResp.Body.Close()
	if tailResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tailnet listener status = %d, want 401 Unauthorized", tailResp.StatusCode)
	}

	// Caller hitting local listener uses isolated local handler.
	localResp, err := http.Get("http://" + srv.LocalAddr() + "/whoami")
	if err != nil {
		t.Fatalf("GET local listener failed: %v", err)
	}
	localBody, _ := io.ReadAll(localResp.Body)
	_ = localResp.Body.Close()
	if localResp.StatusCode != http.StatusOK || string(localBody) != "local:dev@local" {
		t.Fatalf("local listener response = (%d, %q), want (200, %q)", localResp.StatusCode, string(localBody), "local:dev@local")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Close(closeCtx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("ServeHandlers returned error on graceful Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ServeHandlers to exit")
	}
}

func TestServer_ServeHandlersAllowsNilForInactiveListener(t *testing.T) {
	srv, err := NewServer(config.ServerConfig{
		TSNet:       config.TSNetConfig{Enabled: false},
		LocalListen: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		// tailnetHandler is nil because tsnet is disabled.
		serveErr <- srv.ServeHandlers(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("local-only"))
		}))
	}()

	resp, err := http.Get("http://" + srv.LocalAddr())
	if err != nil {
		t.Fatalf("GET local listener failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "local-only" {
		t.Fatalf("got (%d, %q), want (200, local-only)", resp.StatusCode, string(body))
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Close(closeCtx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeHandlers returned error: %v", err)
	}
}

func generateSelfSignedCertFiles(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add cert to pool")
	}
	return certFile, keyFile, pool
}
