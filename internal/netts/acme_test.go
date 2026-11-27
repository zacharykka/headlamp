package netts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
)

// mockACMEServer implements a minimal RFC 8555 ACME v2 server for DNS-01 tests.
type mockACMEServer struct {
	server    *httptest.Server
	caCert    *x509.Certificate
	caCertPEM []byte
	caKey     *ecdsa.PrivateKey
	certPool  *x509.CertPool

	mu               sync.Mutex
	nowFn            func() time.Time
	certValidity     time.Duration
	checkTXT         func(fqdn string) (string, bool)
	ordersCreated    atomic.Int32
	certsIssued      atomic.Int32
	accountsCreated  atomic.Int32
	orderDomains     map[string]string
	orderStatus      map[string]string
	orderAuthzStatus map[string]string
	orderCertPEM     map[string][]byte
	serialCounter    int64
}

func newMockACMEServer(t *testing.T, checkTXT func(fqdn string) (string, bool), nowFn func() time.Time, validity time.Duration) *mockACMEServer {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate mock CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Headlamp Mock ACME Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create mock CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse mock CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	if nowFn == nil {
		nowFn = time.Now
	}
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}

	m := &mockACMEServer{
		caCert:           caCert,
		caCertPEM:        caPEM,
		caKey:            caKey,
		certPool:         pool,
		nowFn:            nowFn,
		certValidity:     validity,
		checkTXT:         checkTXT,
		orderDomains:     make(map[string]string),
		orderStatus:      make(map[string]string),
		orderAuthzStatus: make(map[string]string),
		orderCertPEM:     make(map[string][]byte),
		serialCounter:    100,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", m.handleDirectory)
	mux.HandleFunc("/new-nonce", m.handleNewNonce)
	mux.HandleFunc("/new-account", m.handleNewAccount)
	mux.HandleFunc("/new-order", m.handleNewOrder)
	mux.HandleFunc("/order/", m.handleOrder)
	mux.HandleFunc("/authz/", m.handleAuthz)
	mux.HandleFunc("/chal/", m.handleChallenge)
	mux.HandleFunc("/finalize/", m.handleFinalize)
	mux.HandleFunc("/cert/", m.handleCert)

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockACMEServer) directoryURL() string {
	return m.server.URL + "/directory"
}

func (m *mockACMEServer) setNonce(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
}

func (m *mockACMEServer) decodeJWSPayload(r *http.Request, out any) error {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		return err
	}
	if env.Payload == "" || out == nil {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (m *mockACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"newNonce":   m.server.URL + "/new-nonce",
		"newAccount": m.server.URL + "/new-account",
		"newOrder":   m.server.URL + "/new-order",
		"revokeCert": m.server.URL + "/revoke",
		"keyChange":  m.server.URL + "/key-change",
	})
}

func (m *mockACMEServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	w.WriteHeader(http.StatusOK)
}

func (m *mockACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	m.accountsCreated.Add(1)
	w.Header().Set("Location", m.server.URL+"/acct/1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
}

func (m *mockACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	var req struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if err := m.decodeJWSPayload(r, &req); err != nil || len(req.Identifiers) == 0 {
		http.Error(w, "bad order", http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("%d", m.ordersCreated.Add(1))
	domain := req.Identifiers[0].Value

	m.mu.Lock()
	m.orderDomains[id] = domain
	m.orderStatus[id] = "pending"
	m.orderAuthzStatus[id] = "pending"
	m.mu.Unlock()

	orderURL := m.server.URL + "/order/" + id
	w.Header().Set("Location", orderURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "pending",
		"identifiers":    req.Identifiers,
		"authorizations": []string{m.server.URL + "/authz/" + id},
		"finalize":       m.server.URL + "/finalize/" + id,
	})
}

func (m *mockACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/authz/")

	m.mu.Lock()
	domain := m.orderDomains[id]
	status := m.orderAuthzStatus[id]
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     status,
		"identifier": map[string]string{"type": "dns", "value": domain},
		"challenges": []map[string]any{
			{
				"type":   "dns-01",
				"url":    m.server.URL + "/chal/" + id,
				"token":  "token-" + id,
				"status": status,
			},
		},
	})
}

func (m *mockACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/chal/")

	m.mu.Lock()
	domain := m.orderDomains[id]
	m.mu.Unlock()

	fqdn := "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	if m.checkTXT != nil {
		txtVal, ok := m.checkTXT(fqdn)
		if !ok || txtVal == "" {
			http.Error(w, "missing dns-01 TXT record for "+fqdn, http.StatusBadRequest)
			return
		}
	}

	m.mu.Lock()
	m.orderAuthzStatus[id] = "valid"
	m.orderStatus[id] = "ready"
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "dns-01",
		"url":    m.server.URL + "/chal/" + id,
		"token":  "token-" + id,
		"status": "valid",
	})
}

func (m *mockACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/order/")

	m.mu.Lock()
	domain := m.orderDomains[id]
	status := m.orderStatus[id]
	hasCert := len(m.orderCertPEM[id]) > 0
	m.mu.Unlock()

	body := map[string]any{
		"status":         status,
		"identifiers":    []map[string]string{{"type": "dns", "value": domain}},
		"authorizations": []string{m.server.URL + "/authz/" + id},
		"finalize":       m.server.URL + "/finalize/" + id,
	}
	if hasCert {
		body["certificate"] = m.server.URL + "/cert/" + id
	}

	w.Header().Set("Location", m.server.URL+"/order/"+id)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (m *mockACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")

	var req struct {
		CSR string `json:"csr"`
	}
	if err := m.decodeJWSPayload(r, &req); err != nil {
		http.Error(w, "invalid finalize payload", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr base64", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	m.serialCounter++
	serial := m.serialCounter
	now := m.nowFn()
	validity := m.certValidity
	domain := m.orderDomains[id]
	m.mu.Unlock()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     csr.DNSNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		http.Error(w, "sign cert failed", http.StatusInternalServerError)
		return
	}

	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), m.caCertPEM...)

	m.mu.Lock()
	m.orderCertPEM[id] = chainPEM
	m.orderStatus[id] = "valid"
	m.mu.Unlock()
	m.certsIssued.Add(1)

	w.Header().Set("Location", m.server.URL+"/order/"+id)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "valid",
		"identifiers":    []map[string]string{{"type": "dns", "value": domain}},
		"authorizations": []string{m.server.URL + "/authz/" + id},
		"finalize":       m.server.URL + "/finalize/" + id,
		"certificate":    m.server.URL + "/cert/" + id,
	})
}

func (m *mockACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	m.setNonce(w)
	id := strings.TrimPrefix(r.URL.Path, "/cert/")

	m.mu.Lock()
	chain := m.orderCertPEM[id]
	m.mu.Unlock()
	if len(chain) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(chain)
}

func TestACME_EndToEnd_CloudflareAndLiveTLS(t *testing.T) {
	const domain = "ai.internal.example.com"
	const cfToken = "cf-test-secret-token"

	var (
		dnsMu      sync.Mutex
		txtRecords = make(map[string]string) // fqdn -> value
		recByID    = make(map[string]string) // recordID -> fqdn
		createdCnt atomic.Int32
		deletedCnt atomic.Int32
	)

	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cfToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
			zoneName := r.URL.Query().Get("name")
			if zoneName == "example.com" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result":  []map[string]string{{"id": "zone-123", "name": "example.com"}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})

		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-123/dns_records":
			var body struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Content string `json:"content"`
				TTL     int    `json:"ttl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Type != "TXT" {
				http.Error(w, "bad record", http.StatusBadRequest)
				return
			}
			recID := fmt.Sprintf("rec-%d", createdCnt.Add(1))
			dnsMu.Lock()
			txtRecords[body.Name] = body.Content
			recByID[recID] = body.Name
			dnsMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]string{"id": recID},
			})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/client/v4/zones/zone-123/dns_records/"):
			recID := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone-123/dns_records/")
			dnsMu.Lock()
			if fqdn, ok := recByID[recID]; ok {
				delete(txtRecords, fqdn)
				delete(recByID, recID)
			}
			dnsMu.Unlock()
			deletedCnt.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})

		default:
			http.NotFound(w, r)
		}
	}))
	defer cfServer.Close()

	acmeSrv := newMockACMEServer(t, func(fqdn string) (string, bool) {
		dnsMu.Lock()
		defer dnsMu.Unlock()
		v, ok := txtRecords[fqdn]
		return v, ok
	}, nil, 90*24*time.Hour)

	cfSolver, err := NewCloudflareDNSSolver(cfToken,
		WithCloudflareAPIBase(cfServer.URL+"/client/v4"),
		WithCloudflareHTTPClient(cfServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewCloudflareDNSSolver: %v", err)
	}

	stateDir := t.TempDir()
	tlsCfg := config.TLSConfig{
		Mode:             config.TLSModeACMEDNS01,
		Domain:           domain,
		ACMEEmail:        "ops@example.com",
		ACMEDirectoryURL: acmeSrv.directoryURL(),
		DNSProvider:      config.DNSProviderCloudflare,
		DNSAPIToken:      cfToken,
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	tlsLn, acmeMgr, err := WrapTLSListenerWithACME(
		context.Background(),
		rawLn,
		tlsCfg,
		stateDir,
		WithACMESolver(cfSolver),
		WithACMEHTTPClient(acmeSrv.server.Client()),
		WithACMEPropagationDelay(0),
	)
	if err != nil {
		_ = rawLn.Close()
		t.Fatalf("WrapTLSListenerWithACME failed: %v", err)
	}
	defer func() { _ = acmeMgr.Close() }()

	// Verify DNS-01 record was presented and cleaned up after challenge validation.
	if createdCnt.Load() != 1 || deletedCnt.Load() != 1 {
		t.Fatalf("expected 1 Cloudflare TXT create and 1 delete, got created=%d deleted=%d", createdCnt.Load(), deletedCnt.Load())
	}
	dnsMu.Lock()
	remainingTXT := len(txtRecords)
	dnsMu.Unlock()
	if remainingTXT != 0 {
		t.Fatalf("expected all TXT records cleaned up, %d remain", remainingTXT)
	}

	// Verify 0700 directory and 0600 file permissions for account key, cert, and private key.
	acmeDir := filepath.Join(stateDir, "acme")
	if info, err := os.Stat(acmeDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("acme dir perm = %v (err=%v), want 0700", info, err)
	}
	for _, fn := range []string{acmeAccountKeyFilename, acmeCertFilename, acmeKeyFilename} {
		info, err := os.Stat(filepath.Join(acmeDir, fn))
		if err != nil {
			t.Fatalf("stat %s: %v", fn, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o, want 0600", fn, info.Mode().Perm())
		}
	}

	// Serve live HTTPS traffic over wrapped listener and verify TLS handshake + SNI domain.
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("acme-https-ok"))
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpSrv.Serve(tlsLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		<-serveDone
	}()

	httpsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    acmeSrv.certPool,
				ServerName: domain,
			},
		},
		Timeout: 3 * time.Second,
	}
	resp, err := httpsClient.Get("https://" + tlsLn.Addr().String())
	if err != nil {
		t.Fatalf("HTTPS GET against ACME listener failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "acme-https-ok" {
		t.Fatalf("HTTPS response body = %q, want %q", string(body), "acme-https-ok")
	}

	// Second ACMEManager pointing at the same stateDir must reuse cached cert (>30d remaining) with zero new ACME orders.
	mgr2, err := NewACMEManager(tlsCfg, stateDir,
		WithACMESolver(cfSolver),
		WithACMEHTTPClient(acmeSrv.server.Client()),
		WithACMEPropagationDelay(0),
	)
	if err != nil {
		t.Fatalf("NewACMEManager #2: %v", err)
	}
	defer func() { _ = mgr2.Close() }()

	if _, err := mgr2.EnsureCertificate(context.Background()); err != nil {
		t.Fatalf("EnsureCertificate #2: %v", err)
	}
	if acmeSrv.certsIssued.Load() != 1 {
		t.Fatalf("expected cached cert reuse (1 total issuance), got %d issuances", acmeSrv.certsIssued.Load())
	}
}

func TestACME_WebhookSolverAndBackgroundRenewal(t *testing.T) {
	const domain = "gw.tail.example.com"
	const hookToken = "webhook-bearer-secret"

	var (
		dnsMu      sync.Mutex
		txtRecords = make(map[string]string)
		presents   atomic.Int32
		cleanups   atomic.Int32
	)

	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+hookToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Action string `json:"action"`
			FQDN   string `json:"fqdn"`
			Value  string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		dnsMu.Lock()
		switch req.Action {
		case "present":
			txtRecords[req.FQDN] = req.Value
			presents.Add(1)
		case "cleanup":
			delete(txtRecords, req.FQDN)
			cleanups.Add(1)
		default:
			dnsMu.Unlock()
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		dnsMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hookServer.Close()

	var (
		clockMu sync.Mutex
		now     = time.Now().UTC()
	)
	getNow := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	// Issue 60-day certs so advancing 35 days leaves 25 days (<30d threshold) and triggers renewal.
	acmeSrv := newMockACMEServer(t, func(fqdn string) (string, bool) {
		dnsMu.Lock()
		defer dnsMu.Unlock()
		v, ok := txtRecords[fqdn]
		return v, ok
	}, getNow, 60*24*time.Hour)

	stateDir := t.TempDir()
	tlsCfg := config.TLSConfig{
		Mode:             config.TLSModeACMEDNS01,
		Domain:           domain,
		ACMEDirectoryURL: acmeSrv.directoryURL(),
		DNSProvider:      config.DNSProviderWebhook,
		DNSAPIToken:      hookToken,
		DNSWebhookURL:    hookServer.URL,
	}

	mgr, err := NewACMEManager(tlsCfg, stateDir,
		WithACMEHTTPClient(acmeSrv.server.Client()),
		WithACMEPropagationDelay(0),
		WithACMERenewCheckInterval(20*time.Millisecond),
		WithACMENowFunc(getNow),
	)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	firstCert, err := mgr.EnsureCertificate(context.Background())
	if err != nil {
		t.Fatalf("EnsureCertificate initial: %v", err)
	}
	firstSerial := firstCert.Leaf.SerialNumber.String()
	if presents.Load() != 1 || cleanups.Load() != 1 {
		t.Fatalf("expected 1 webhook present & cleanup, got present=%d cleanup=%d", presents.Load(), cleanups.Load())
	}

	mgr.StartRenewalLoop()

	// Advance clock by 35 days (25 days remaining < 30 days renew threshold) -> background renewal must issue a new cert.
	advance(35 * 24 * time.Hour)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := mgr.GetCertificate(nil)
		if err == nil && cur.Leaf.SerialNumber.String() != firstSerial {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	renewedCert, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after renewal: %v", err)
	}
	if renewedCert.Leaf.SerialNumber.String() == firstSerial {
		t.Fatalf("expected background renewal to rotate cert serial (still %s)", firstSerial)
	}
	if acmeSrv.certsIssued.Load() < 2 {
		t.Fatalf("expected >=2 issued certs after renewal, got %d", acmeSrv.certsIssued.Load())
	}
	if presents.Load() < 2 || cleanups.Load() < 2 {
		t.Fatalf("expected >=2 webhook presents & cleanups, got present=%d cleanup=%d", presents.Load(), cleanups.Load())
	}
}

func TestACME_EnsureCertificateFallsBackToValidExpiringDiskCert(t *testing.T) {
	const domain = "fallback.tail.example.com"

	var (
		clockMu sync.Mutex
		now     = time.Now().UTC()
	)
	getNow := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	// 1. Issue a valid 40-day cert and persist it to stateDir.
	acmeSrv := newMockACMEServer(t, nil, getNow, 40*24*time.Hour)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()

	stateDir := t.TempDir()
	tlsCfg := config.TLSConfig{
		Mode:             config.TLSModeACMEDNS01,
		Domain:           domain,
		ACMEDirectoryURL: acmeSrv.directoryURL(),
		DNSProvider:      config.DNSProviderWebhook,
		DNSWebhookURL:    hookSrv.URL,
	}

	mgr1, err := NewACMEManager(tlsCfg, stateDir,
		WithACMEHTTPClient(acmeSrv.server.Client()),
		WithACMEPropagationDelay(0),
		WithACMENowFunc(getNow),
	)
	if err != nil {
		t.Fatalf("NewACMEManager #1: %v", err)
	}
	issued, err := mgr1.EnsureCertificate(context.Background())
	if err != nil {
		t.Fatalf("EnsureCertificate #1: %v", err)
	}
	_ = mgr1.Close()

	// 2. Advance 25 days (15 days remaining <= 30d renewBefore) and break the ACME directory.
	// Startup MUST succeed by falling back to the still-unexpired cached cert!
	clockMu.Lock()
	now = now.Add(25 * 24 * time.Hour)
	clockMu.Unlock()

	brokenACME := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "acme outage", http.StatusInternalServerError)
	}))
	defer brokenACME.Close()

	tlsCfgBroken := tlsCfg
	tlsCfgBroken.ACMEDirectoryURL = brokenACME.URL + "/directory"

	mgr2, err := NewACMEManager(tlsCfgBroken, stateDir,
		WithACMEHTTPClient(brokenACME.Client()),
		WithACMEPropagationDelay(0),
		WithACMENowFunc(getNow),
	)
	if err != nil {
		t.Fatalf("NewACMEManager #2: %v", err)
	}
	defer func() { _ = mgr2.Close() }()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	fallbackCert, err := mgr2.EnsureCertificate(ctx2)
	if err != nil {
		t.Fatalf("expected fallback to valid expiring disk cert during ACME outage, got error: %v", err)
	}
	if fallbackCert.Leaf.SerialNumber.String() != issued.Leaf.SerialNumber.String() {
		t.Fatalf("expected fallback cert serial %s, got %s", issued.Leaf.SerialNumber, fallbackCert.Leaf.SerialNumber)
	}

	// 3. Advance past expiry (another 20 days -> expired) with broken ACME: MUST fail cleanly.
	clockMu.Lock()
	now = now.Add(20 * 24 * time.Hour)
	clockMu.Unlock()

	mgr3, err := NewACMEManager(tlsCfgBroken, stateDir,
		WithACMEHTTPClient(brokenACME.Client()),
		WithACMEPropagationDelay(0),
		WithACMENowFunc(getNow),
	)
	if err != nil {
		t.Fatalf("NewACMEManager #3: %v", err)
	}
	defer func() { _ = mgr3.Close() }()

	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	if _, err := mgr3.EnsureCertificate(ctx3); err == nil {
		t.Fatal("expected error when cached cert is already expired and ACME is unreachable")
	}
}

func TestCloudflareDNSSolver_CleanUpFallbackMatchesQuotedTXT(t *testing.T) {
	const cfToken = "cf-quoted-token"
	const txtVal = "abc123-digest-value"
	var deletedID string

	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
			if r.URL.Query().Get("name") == "example.com" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result":  []map[string]string{{"id": "z1", "name": "example.com"}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/z1/dns_records":
			// Ensure content query param is NOT required and return Cloudflare-quoted TXT value.
			if r.URL.Query().Get("content") != "" {
				t.Errorf("unexpected server-side content query param: %q", r.URL.Query().Get("content"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": []map[string]string{
					{"id": "rec-other", "content": `"other-value"`},
					{"id": "rec-quoted", "content": `"` + txtVal + `"`},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/client/v4/zones/z1/dns_records/"):
			deletedID = strings.TrimPrefix(r.URL.Path, "/client/v4/zones/z1/dns_records/")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer cfSrv.Close()

	// Fresh solver without prior Present() forces fallback lookup via findTXTRecordID.
	solver, err := NewCloudflareDNSSolver(cfToken,
		WithCloudflareAPIBase(cfSrv.URL+"/client/v4"),
		WithCloudflareHTTPClient(cfSrv.Client()),
	)
	if err != nil {
		t.Fatalf("NewCloudflareDNSSolver: %v", err)
	}

	if err := solver.CleanUp(context.Background(), "_acme-challenge.ai.example.com", txtVal); err != nil {
		t.Fatalf("CleanUp fallback failed: %v", err)
	}
	if deletedID != "rec-quoted" {
		t.Fatalf("deleted record ID = %q, want %q", deletedID, "rec-quoted")
	}
}
