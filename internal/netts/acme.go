package netts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zacharykka/headlamp/internal/config"
	"golang.org/x/crypto/acme"
)

const (
	defaultCloudflareAPIBase  = "https://api.cloudflare.com/client/v4"
	defaultACMERenewBefore    = 30 * 24 * time.Hour
	defaultACMERenewCheck     = 24 * time.Hour
	defaultDNSPropagationWait = 5 * time.Second
	defaultDNSHTTPTimeout     = 15 * time.Second
	acmeAccountKeyFilename    = "account.key"
	acmeCertFilename          = "cert.pem"
	acmeKeyFilename           = "key.pem"
)

// ACMEOption customizes ACMEManager.
type ACMEOption func(*ACMEManager)

// WithACMESolver injects a custom DNS01Solver (overrides Cloudflare/Webhook solver creation).
func WithACMESolver(solver DNS01Solver) ACMEOption {
	return func(m *ACMEManager) {
		m.solver = solver
	}
}

// WithACMEHTTPClient sets the HTTP client used for ACME directory requests.
func WithACMEHTTPClient(client *http.Client) ACMEOption {
	return func(m *ACMEManager) {
		m.httpClient = client
	}
}

// WithACMEPropagationDelay sets the wait duration after presenting a TXT record before accepting the challenge.
func WithACMEPropagationDelay(d time.Duration) ACMEOption {
	return func(m *ACMEManager) {
		if d >= 0 {
			m.propagationDelay = d
		}
	}
}

// WithACMERenewBefore sets how far before expiry a cached certificate is considered due for renewal (default 30 days).
func WithACMERenewBefore(d time.Duration) ACMEOption {
	return func(m *ACMEManager) {
		if d > 0 {
			m.renewBefore = d
		}
	}
}

// WithACMERenewCheckInterval sets how often the background renewal loop checks certificate expiry (default 24h).
func WithACMERenewCheckInterval(d time.Duration) ACMEOption {
	return func(m *ACMEManager) {
		if d > 0 {
			m.renewCheckInterval = d
		}
	}
}

// WithACMENowFunc overrides the clock used for certificate expiry checks (for testing).
func WithACMENowFunc(fn func() time.Time) ACMEOption {
	return func(m *ACMEManager) {
		if fn != nil {
			m.now = fn
		}
	}
}

// WithACMELogf sets the logger for ACME issuance and background renewal messages.
func WithACMELogf(fn LogFunc) ACMEOption {
	return func(m *ACMEManager) {
		m.logf = fn
	}
}

// ACMEManager obtains, caches, serves, and renews TLS certificates via RFC 8555 ACME DNS-01.
type ACMEManager struct {
	domain             string
	email              string
	directoryURL       string
	acmeDir            string
	solver             DNS01Solver
	httpClient         *http.Client
	propagationDelay   time.Duration
	renewBefore        time.Duration
	renewCheckInterval time.Duration
	now                func() time.Time
	logf               LogFunc

	certMu sync.RWMutex
	cert   *tls.Certificate

	opMu sync.Mutex // serializes certificate issuance/renewal

	loopMu     sync.Mutex
	loopCancel context.CancelFunc
	loopDone   chan struct{}
	closed     bool
}

// NewACMEManager constructs an ACMEManager persisting keys and certificates in <stateDir>/acme/.
func NewACMEManager(tlsCfg config.TLSConfig, stateDir string, opts ...ACMEOption) (*ACMEManager, error) {
	domain := strings.ToLower(strings.TrimSpace(tlsCfg.Domain))
	if domain == "" {
		return nil, errors.New("netts: tls.domain is required for acme_dns01")
	}
	if strings.TrimSpace(stateDir) == "" {
		return nil, errors.New("netts: state_dir is required for acme_dns01")
	}

	dirURL := strings.TrimSpace(tlsCfg.ACMEDirectoryURL)
	if dirURL == "" {
		dirURL = config.DefaultACMEDirectoryURL
	}

	m := &ACMEManager{
		domain:             domain,
		email:              strings.TrimSpace(tlsCfg.ACMEEmail),
		directoryURL:       dirURL,
		acmeDir:            filepath.Join(stateDir, "acme"),
		propagationDelay:   defaultDNSPropagationWait,
		renewBefore:        defaultACMERenewBefore,
		renewCheckInterval: defaultACMERenewCheck,
		now:                time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if m.solver == nil {
		solver, err := newDNS01SolverFromConfig(tlsCfg, m.httpClient)
		if err != nil {
			return nil, err
		}
		m.solver = solver
	}

	return m, nil
}

func newDNS01SolverFromConfig(tlsCfg config.TLSConfig, httpClient *http.Client) (DNS01Solver, error) {
	switch strings.ToLower(strings.TrimSpace(tlsCfg.DNSProvider)) {
	case config.DNSProviderCloudflare:
		return NewCloudflareDNSSolver(tlsCfg.DNSAPIToken, WithCloudflareHTTPClient(httpClient))
	case config.DNSProviderWebhook:
		return NewWebhookDNSSolver(tlsCfg.DNSWebhookURL, tlsCfg.DNSAPIToken, httpClient)
	default:
		return nil, fmt.Errorf("netts: unsupported tls.dns_provider %q (must be %q or %q)",
			tlsCfg.DNSProvider, config.DNSProviderCloudflare, config.DNSProviderWebhook)
	}
}

// EnsureCertificate loads a valid cached certificate (>30 days remaining) from <stateDir>/acme/
// or obtains a fresh certificate via ACME DNS-01 and persists it with 0600 permissions.
// If a cached certificate is still unexpired (matching domain) with <=30 days remaining and
// renewal fails transiently, EnsureCertificate logs a warning and falls back to serving the
// still-valid cached certificate so StartRenewalLoop can retry in the background.
func (m *ACMEManager) EnsureCertificate(ctx context.Context) (*tls.Certificate, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	if err := os.MkdirAll(m.acmeDir, 0o700); err != nil {
		return nil, fmt.Errorf("netts: create acme state dir %q: %w", m.acmeDir, err)
	}

	var fallback *tls.Certificate

	// Fast path: reuse valid in-memory certificate.
	m.certMu.RLock()
	current := m.cert
	m.certMu.RUnlock()
	if current != nil {
		if m.certValidForReuse(current) {
			return current, nil
		}
		if m.certCurrentlyValid(current) {
			fallback = current
		}
	}

	// Disk cache path: reuse persisted certificate if valid and >renewBefore remaining.
	if diskCert, err := m.loadCachedCert(); err == nil {
		if m.certValidForReuse(diskCert) {
			m.setCert(diskCert)
			m.log("netts: acme reusing cached certificate for %s (expires %s)", m.domain, diskCert.Leaf.NotAfter.UTC().Format(time.RFC3339))
			return diskCert, nil
		}
		if fallback == nil && m.certCurrentlyValid(diskCert) {
			fallback = diskCert
		}
	}

	// Obtain a new certificate via ACME DNS-01.
	cert, err := m.obtainCertificate(ctx)
	if err != nil {
		if fallback != nil {
			m.setCert(fallback)
			m.log("netts: acme renewal failed for %s (%v); falling back to valid cached certificate expiring %s",
				m.domain, err, fallback.Leaf.NotAfter.UTC().Format(time.RFC3339))
			return fallback, nil
		}
		return nil, err
	}
	m.setCert(cert)
	m.log("netts: acme obtained certificate for %s (expires %s)", m.domain, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return cert, nil
}

// StartRenewalLoop starts a background goroutine that periodically checks certificate expiry
// and renews whenever less than renewBefore (default 30 days) remains. Safe to call repeatedly.
func (m *ACMEManager) StartRenewalLoop() {
	m.loopMu.Lock()
	defer m.loopMu.Unlock()

	if m.closed || m.loopCancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.loopCancel = cancel
	m.loopDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(m.renewCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.checkAndRenew(ctx)
			}
		}
	}()
}

// Close stops the background renewal loop and waits for it to exit cleanly.
func (m *ACMEManager) Close() error {
	m.loopMu.Lock()
	m.closed = true
	cancel := m.loopCancel
	done := m.loopDone
	m.loopCancel = nil
	m.loopDone = nil
	m.loopMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}

// GetCertificate satisfies tls.Config.GetCertificate, returning the current cached certificate.
func (m *ACMEManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.certMu.RLock()
	cert := m.cert
	m.certMu.RUnlock()
	if cert == nil {
		return nil, errors.New("netts: acme certificate is not initialized")
	}
	return cert, nil
}

// TLSConfig returns a *tls.Config serving the dynamically managed ACME certificate.
func (m *ACMEManager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
	}
}

func (m *ACMEManager) checkAndRenew(ctx context.Context) {
	m.certMu.RLock()
	current := m.cert
	m.certMu.RUnlock()
	if current != nil && m.certValidForReuse(current) {
		return
	}

	renewCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	m.opMu.Lock()
	defer m.opMu.Unlock()

	// Re-check under opMu in case another caller renewed concurrently.
	m.certMu.RLock()
	current = m.cert
	m.certMu.RUnlock()
	if current != nil && m.certValidForReuse(current) {
		return
	}

	cert, err := m.obtainCertificate(renewCtx)
	if err != nil {
		m.log("netts: acme renewal failed for %s: %v", m.domain, err)
		return
	}
	m.setCert(cert)
	m.log("netts: acme renewed certificate for %s (expires %s)", m.domain, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

func (m *ACMEManager) obtainCertificate(ctx context.Context) (*tls.Certificate, error) {
	acctKey, err := m.loadOrCreateAccountKey()
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          acctKey,
		DirectoryURL: m.directoryURL,
		HTTPClient:   m.httpClient,
	}

	acct := &acme.Account{}
	if m.email != "" {
		acct.Contact = []string{"mailto:" + m.email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("netts: acme register account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.domain))
	if err != nil {
		return nil, fmt.Errorf("netts: acme authorize order for %q: %w", m.domain, err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := m.fulfillDNS01Authorization(ctx, client, authzURL); err != nil {
			return nil, err
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("netts: acme wait order for %q: %w", m.domain, err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("netts: acme generate leaf key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{m.domain},
	}, leafKey)
	if err != nil {
		return nil, fmt.Errorf("netts: acme create CSR for %q: %w", m.domain, err)
	}

	derChain, _, err := client.CreateCertFromOrder(ctx, order, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("netts: acme finalize order for %q: %w", m.domain, err)
	}
	if len(derChain) == 0 {
		return nil, fmt.Errorf("netts: acme returned empty certificate chain for %q", m.domain)
	}

	var certBuf bytes.Buffer
	for _, der := range derChain {
		if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return nil, fmt.Errorf("netts: acme encode cert pem: %w", err)
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("netts: acme marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := certBuf.Bytes()

	tlsCert, err := parseTLSCert(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("netts: acme parse issued cert: %w", err)
	}

	if err := writeFileAtomic0600(filepath.Join(m.acmeDir, acmeCertFilename), certPEM); err != nil {
		return nil, fmt.Errorf("netts: persist acme cert: %w", err)
	}
	if err := writeFileAtomic0600(filepath.Join(m.acmeDir, acmeKeyFilename), keyPEM); err != nil {
		return nil, fmt.Errorf("netts: persist acme key: %w", err)
	}

	return tlsCert, nil
}

func (m *ACMEManager) fulfillDNS01Authorization(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("netts: acme get authorization %q: %w", authzURL, err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}

	var dnsChallenge *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dnsChallenge = ch
			break
		}
	}
	if dnsChallenge == nil {
		return fmt.Errorf("netts: acme authorization for %q has no dns-01 challenge", authz.Identifier.Value)
	}

	txtValue, err := client.DNS01ChallengeRecord(dnsChallenge.Token)
	if err != nil {
		return fmt.Errorf("netts: acme compute dns-01 record: %w", err)
	}

	fqdn := "_acme-challenge." + strings.TrimPrefix(normalizeDNSName(authz.Identifier.Value), "*.")
	if err := m.solver.Present(ctx, fqdn, txtValue); err != nil {
		return fmt.Errorf("netts: dns-01 present %q: %w", fqdn, err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.solver.CleanUp(cleanupCtx, fqdn, txtValue); err != nil {
			m.log("netts: dns-01 cleanup %q failed: %v", fqdn, err)
		}
	}()

	if m.propagationDelay > 0 {
		timer := time.NewTimer(m.propagationDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	if _, err := client.Accept(ctx, dnsChallenge); err != nil {
		return fmt.Errorf("netts: acme accept dns-01 challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("netts: acme wait authorization %q: %w", authz.Identifier.Value, err)
	}
	return nil
}

func (m *ACMEManager) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(m.acmeDir, acmeAccountKeyFilename)
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("netts: invalid PEM in acme account key %q", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("netts: parse acme account key %q: %w", path, err)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("netts: read acme account key %q: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("netts: generate acme account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("netts: marshal acme account key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic0600(path, pemBytes); err != nil {
		return nil, fmt.Errorf("netts: persist acme account key: %w", err)
	}
	return key, nil
}

func (m *ACMEManager) loadCachedCert() (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(m.acmeDir, acmeCertFilename))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.acmeDir, acmeKeyFilename))
	if err != nil {
		return nil, err
	}
	return parseTLSCert(certPEM, keyPEM)
}

func (m *ACMEManager) certCurrentlyValid(cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}
	if !certMatchesDomain(cert.Leaf, m.domain) {
		return false
	}
	now := m.now()
	return !now.Before(cert.Leaf.NotBefore) && now.Before(cert.Leaf.NotAfter)
}

func (m *ACMEManager) certValidForReuse(cert *tls.Certificate) bool {
	if !m.certCurrentlyValid(cert) {
		return false
	}
	return cert.Leaf.NotAfter.Sub(m.now()) > m.renewBefore
}

func certMatchesDomain(leaf *x509.Certificate, domain string) bool {
	if leaf == nil {
		return false
	}
	if strings.HasPrefix(domain, "*.") {
		for _, san := range leaf.DNSNames {
			if strings.EqualFold(san, domain) {
				return true
			}
		}
		return false
	}
	if leaf.VerifyHostname(domain) == nil {
		return true
	}
	return slices.ContainsFunc(leaf.DNSNames, func(san string) bool {
		return strings.EqualFold(san, domain)
	})
}

func (m *ACMEManager) setCert(cert *tls.Certificate) {
	m.certMu.Lock()
	m.cert = cert
	m.certMu.Unlock()
}

func (m *ACMEManager) log(format string, args ...any) {
	if m.logf != nil {
		m.logf(format, args...)
	}
}

func parseTLSCert(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &cert, nil
}

func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanupTmp = false
	return os.Chmod(path, 0o600)
}
