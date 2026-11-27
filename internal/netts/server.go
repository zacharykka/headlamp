package netts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

const defaultReadHeaderTimeout = 30 * time.Second

// LogFunc matches Tailscale's logger.Logf signature (alias so callers can pass log.Printf directly).
type LogFunc = func(format string, args ...any)

// Option customizes a Server instance.
type Option func(*Server)

// WithUserLogf sets the operator-facing logger for tsnet startup messages (such as login URLs).
func WithUserLogf(fn LogFunc) Option {
	return func(s *Server) {
		s.userLogf = fn
	}
}

// WithDebugLogf enables verbose tsnet backend logging when non-nil.
func WithDebugLogf(fn LogFunc) Option {
	return func(s *Server) {
		s.debugLogf = fn
	}
}

// WithACMEOptions forwards ACME options (such as custom solvers or HTTP clients) when tls.mode is acme_dns01.
func WithACMEOptions(opts ...ACMEOption) Option {
	return func(s *Server) {
		s.acmeOpts = append(s.acmeOpts, opts...)
	}
}

// Server manages Headlamp's embedded Tailnet (tsnet) listener and optional local HTTP listener.
type Server struct {
	cfg       config.ServerConfig
	userLogf  LogFunc
	debugLogf LogFunc
	acmeOpts  []ACMEOption

	mu          sync.Mutex
	started     bool
	closed      bool
	tsSrv       *tsnet.Server
	localClient *local.Client
	status      *ipnstate.Status
	acmeMgr     *ACMEManager
	tailnetLn   net.Listener
	localLn     net.Listener
	tailnetHTTP *http.Server
	localHTTP   *http.Server
}

// NewServer validates server listener and TLS settings and constructs a Server ready to Start.
func NewServer(cfg config.ServerConfig, opts ...Option) (*Server, error) {
	if !cfg.TSNet.Enabled && strings.TrimSpace(cfg.LocalListen) == "" {
		return nil, errors.New("netts: at least one listener must be enabled (tsnet.enabled or local_listen)")
	}

	s := &Server{cfg: cfg}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if cfg.TSNet.Enabled {
		if strings.TrimSpace(cfg.TSNet.Hostname) == "" {
			return nil, errors.New("netts: tsnet.hostname is required when tsnet is enabled")
		}
		if strings.TrimSpace(cfg.TSNet.StateDir) == "" {
			return nil, errors.New("netts: tsnet.state_dir is required when tsnet is enabled")
		}
		if err := validateTLSConfig(cfg.TLS, len(s.acmeOpts) > 0); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// WrapTLSListener applies non-ACME TLS modes ("none" or "static") to an existing TCP listener.
// For tls.mode "acme_dns01", use WrapTLSListenerWithACME (or Server.Start), which also manages
// certificate persistence and background renewal.
//
// Headlamp intentionally never calls tsnet.Server.ListenTLS because Headscale does not provision
// Tailscale MagicDNS HTTPS certificates (CertDomains is empty).
func WrapTLSListener(ln net.Listener, tlsCfg config.TLSConfig) (net.Listener, error) {
	if ln == nil {
		return nil, errors.New("netts: nil listener")
	}

	mode := normalizedTLSMode(tlsCfg.Mode)
	switch mode {
	case config.TLSModeNone:
		return ln, nil
	case config.TLSModeStatic:
		tlsConfig, err := loadStaticTLSConfig(tlsCfg)
		if err != nil {
			return nil, err
		}
		return tls.NewListener(ln, tlsConfig), nil
	case config.TLSModeACMEDNS01:
		return nil, errors.New("netts: tls.mode acme_dns01 requires stateDir and context; use WrapTLSListenerWithACME")
	default:
		return nil, fmt.Errorf("netts: unsupported tls.mode %q", tlsCfg.Mode)
	}
}

// WrapTLSListenerWithACME applies Headlamp's configured TLS mode ("none", "static", or "acme_dns01")
// to an existing TCP listener. When tls.mode is "acme_dns01", it ensures a valid certificate is
// loaded/issued via DNS-01, starts the background renewal loop, and wraps ln with tls.NewListener
// using dynamic GetCertificate (never calling tsnet.Server.ListenTLS). Callers must Close the
// returned *ACMEManager (when non-nil) on shutdown.
func WrapTLSListenerWithACME(ctx context.Context, ln net.Listener, tlsCfg config.TLSConfig, stateDir string, opts ...ACMEOption) (net.Listener, *ACMEManager, error) {
	if ln == nil {
		return nil, nil, errors.New("netts: nil listener")
	}

	mode := normalizedTLSMode(tlsCfg.Mode)
	switch mode {
	case config.TLSModeNone, config.TLSModeStatic:
		wrapped, err := WrapTLSListener(ln, tlsCfg)
		return wrapped, nil, err
	case config.TLSModeACMEDNS01:
		mgr, err := NewACMEManager(tlsCfg, stateDir, opts...)
		if err != nil {
			return nil, nil, err
		}
		if _, err := mgr.EnsureCertificate(ctx); err != nil {
			_ = mgr.Close()
			return nil, nil, err
		}
		mgr.StartRenewalLoop()
		return tls.NewListener(ln, mgr.TLSConfig()), mgr, nil
	default:
		return nil, nil, fmt.Errorf("netts: unsupported tls.mode %q", tlsCfg.Mode)
	}
}

func validateTLSConfig(tlsCfg config.TLSConfig, hasCustomACMEOpts bool) error {
	mode := normalizedTLSMode(tlsCfg.Mode)
	switch mode {
	case config.TLSModeNone:
		return nil
	case config.TLSModeStatic:
		if strings.TrimSpace(tlsCfg.CertFile) == "" || strings.TrimSpace(tlsCfg.KeyFile) == "" {
			return errors.New("netts: tls.cert_file and tls.key_file are required when tls.mode is static")
		}
		return nil
	case config.TLSModeACMEDNS01:
		if strings.TrimSpace(tlsCfg.Domain) == "" {
			return errors.New("netts: tls.domain is required when tls.mode is acme_dns01")
		}
		if hasCustomACMEOpts {
			return nil
		}
		switch strings.ToLower(strings.TrimSpace(tlsCfg.DNSProvider)) {
		case config.DNSProviderCloudflare:
			if strings.TrimSpace(tlsCfg.DNSAPIToken) == "" {
				return errors.New("netts: tls.dns_api_token is required when tls.dns_provider is cloudflare")
			}
			return nil
		case config.DNSProviderWebhook:
			if strings.TrimSpace(tlsCfg.DNSWebhookURL) == "" {
				return errors.New("netts: tls.dns_webhook_url is required when tls.dns_provider is webhook")
			}
			return nil
		default:
			return fmt.Errorf("netts: tls.dns_provider %q must be %q or %q when tls.mode is acme_dns01",
				tlsCfg.DNSProvider, config.DNSProviderCloudflare, config.DNSProviderWebhook)
		}
	default:
		return fmt.Errorf("netts: unsupported tls.mode %q", tlsCfg.Mode)
	}
}

func loadStaticTLSConfig(tlsCfg config.TLSConfig) (*tls.Config, error) {
	certFile := strings.TrimSpace(tlsCfg.CertFile)
	keyFile := strings.TrimSpace(tlsCfg.KeyFile)
	if certFile == "" || keyFile == "" {
		return nil, errors.New("netts: tls.cert_file and tls.key_file are required when tls.mode is static")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("netts: load static TLS key pair (%q, %q): %w", certFile, keyFile, err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

func normalizedTLSMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return config.TLSModeNone
	}
	return m
}

// Start brings up the embedded tsnet node (when enabled) and opens all configured listeners.
// Call Start before Authenticator(), LocalClient(), or Serve()/ServeHandlers().
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("netts: server already closed")
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("netts: server already started")
	}
	s.mu.Unlock()

	var (
		tsSrv       *tsnet.Server
		localClient *local.Client
		status      *ipnstate.Status
		acmeMgr     *ACMEManager
		tailnetLn   net.Listener
		localLn     net.Listener
	)

	cleanup := func() {
		if localLn != nil {
			_ = localLn.Close()
		}
		if tailnetLn != nil {
			_ = tailnetLn.Close()
		}
		if acmeMgr != nil {
			_ = acmeMgr.Close()
		}
		if tsSrv != nil {
			_ = tsSrv.Close()
		}
	}

	if s.cfg.TSNet.Enabled {
		tlsMode := normalizedTLSMode(s.cfg.TLS.Mode)

		// Fail fast on TLS configuration/cert errors before contacting Headscale/Tailscale.
		if err := validateTLSConfig(s.cfg.TLS, len(s.acmeOpts) > 0); err != nil {
			return err
		}
		switch tlsMode {
		case config.TLSModeStatic:
			if _, err := loadStaticTLSConfig(s.cfg.TLS); err != nil {
				return err
			}
		case config.TLSModeACMEDNS01:
			opts := make([]ACMEOption, 0, len(s.acmeOpts)+1)
			if s.userLogf != nil {
				opts = append(opts, WithACMELogf(s.userLogf))
			}
			opts = append(opts, s.acmeOpts...)

			var err error
			acmeMgr, err = NewACMEManager(s.cfg.TLS, s.cfg.TSNet.StateDir, opts...)
			if err != nil {
				return err
			}
			if _, err := acmeMgr.EnsureCertificate(ctx); err != nil {
				cleanup()
				return err
			}
			acmeMgr.StartRenewalLoop()
		}

		tsDir := filepath.Join(s.cfg.TSNet.StateDir, "tsnet")
		if err := os.MkdirAll(tsDir, 0o700); err != nil {
			cleanup()
			return fmt.Errorf("netts: create tsnet state dir %q: %w", tsDir, err)
		}

		tsSrv = &tsnet.Server{
			Hostname:   s.cfg.TSNet.Hostname,
			ControlURL: strings.TrimSpace(s.cfg.TSNet.ControlURL),
			AuthKey:    s.cfg.TSNet.AuthKey,
			Dir:        tsDir,
			Ephemeral:  s.cfg.TSNet.Ephemeral,
			UserLogf:   s.userLogf,
			Logf:       s.debugLogf,
		}

		var err error
		status, err = tsSrv.Up(ctx)
		if err != nil {
			cleanup()
			return fmt.Errorf("netts: bring up tsnet node %q: %w", s.cfg.TSNet.Hostname, err)
		}

		localClient, err = tsSrv.LocalClient()
		if err != nil {
			cleanup()
			return fmt.Errorf("netts: obtain tsnet LocalClient: %w", err)
		}

		port := s.cfg.TSNet.ListenPort
		if port == 0 {
			if tlsMode == config.TLSModeNone {
				port = 80
			} else {
				port = 443
			}
		}

		// Always use tsSrv.Listen (never ListenTLS) so Headscale works without Tailscale SaaS certs.
		rawLn, err := tsSrv.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			cleanup()
			return fmt.Errorf("netts: listen on tailnet port %d: %w", port, err)
		}
		tailnetLn = rawLn

		if acmeMgr != nil {
			tailnetLn = tls.NewListener(rawLn, acmeMgr.TLSConfig())
		} else {
			wrappedLn, err := WrapTLSListener(rawLn, s.cfg.TLS)
			if err != nil {
				cleanup()
				return err
			}
			tailnetLn = wrappedLn
		}
	}

	if addr := strings.TrimSpace(s.cfg.LocalListen); addr != "" {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			cleanup()
			return fmt.Errorf("netts: listen local %q: %w", addr, err)
		}
		localLn = ln
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cleanup()
		return errors.New("netts: server closed during startup")
	}
	s.tsSrv = tsSrv
	s.localClient = localClient
	s.status = status
	s.acmeMgr = acmeMgr
	s.tailnetLn = tailnetLn
	s.localLn = localLn
	s.started = true
	s.mu.Unlock()

	return nil
}

// Serve serves handler on all active listeners (Tailnet and/or local) until Close is called
// or an unexpected listener error occurs. Returns nil on graceful shutdown.
// Prefer ServeHandlers when the Tailnet and local listeners need isolated auth chains.
func (s *Server) Serve(handler http.Handler) error {
	if handler == nil {
		return errors.New("netts: handler is required")
	}
	return s.ServeHandlers(handler, handler)
}

// ServeHandlers serves distinct handlers on the Tailnet and local listeners so each
// listener can enforce its own authentication chain (e.g. Tailnet-only TSNetAuthenticator
// on tailnetHandler, and static API tokens or loopback dev_mode on localHandler).
// A handler may be nil only when its corresponding listener is not active.
// Returns nil on graceful shutdown via Close.
func (s *Server) ServeHandlers(tailnetHandler, localHandler http.Handler) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return errors.New("netts: server must be started before Serve")
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	if s.tailnetLn != nil && tailnetHandler == nil {
		s.mu.Unlock()
		return errors.New("netts: tailnetHandler is required when tailnet listener is active")
	}
	if s.localLn != nil && localHandler == nil {
		s.mu.Unlock()
		return errors.New("netts: localHandler is required when local listener is active")
	}

	// Do not set WriteTimeout: LLM SSE streams can stay open for minutes.
	var servers []struct {
		name string
		srv  *http.Server
		ln   net.Listener
	}
	if s.tailnetLn != nil {
		s.tailnetHTTP = &http.Server{
			Handler:           tailnetHandler,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
		}
		servers = append(servers, struct {
			name string
			srv  *http.Server
			ln   net.Listener
		}{name: "tailnet", srv: s.tailnetHTTP, ln: s.tailnetLn})
	}
	if s.localLn != nil {
		s.localHTTP = &http.Server{
			Handler:           localHandler,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
		}
		servers = append(servers, struct {
			name string
			srv  *http.Server
			ln   net.Listener
		}{name: "local", srv: s.localHTTP, ln: s.localLn})
	}
	s.mu.Unlock()

	if len(servers) == 0 {
		return errors.New("netts: no active listeners to serve")
	}

	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, item := range servers {
		wg.Add(1)
		go func(name string, srv *http.Server, ln net.Listener) {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("netts: %s serve error: %w", name, err)
				// Stop sibling servers so Serve does not hang after one listener fails.
				_ = s.Close(context.Background())
			}
		}(item.name, item.srv, item.ln)
	}

	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Close gracefully shuts down all HTTP servers, stops ACME renewal, closes listeners, and stops tsnet.
// Close is safe to call multiple times and concurrently with Serve.
func (s *Server) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true

	tailnetHTTP := s.tailnetHTTP
	localHTTP := s.localHTTP
	tailnetLn := s.tailnetLn
	localLn := s.localLn
	acmeMgr := s.acmeMgr
	tsSrv := s.tsSrv
	s.mu.Unlock()

	var errs []error

	if tailnetHTTP != nil {
		if err := tailnetHTTP.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("netts: shutdown tailnet http: %w", err))
		}
	} else if tailnetLn != nil {
		if err := tailnetLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("netts: close tailnet listener: %w", err))
		}
	}

	if localHTTP != nil {
		if err := localHTTP.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("netts: shutdown local http: %w", err))
		}
	} else if localLn != nil {
		if err := localLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("netts: close local listener: %w", err))
		}
	}

	if acmeMgr != nil {
		if err := acmeMgr.Close(); err != nil {
			errs = append(errs, fmt.Errorf("netts: close acme manager: %w", err))
		}
	}

	if tsSrv != nil {
		if err := tsSrv.Close(); err != nil {
			errs = append(errs, fmt.Errorf("netts: close tsnet server: %w", err))
		}
	}

	return errors.Join(errs...)
}

// LocalClient returns the embedded tsnet node's LocalClient, or an error if tsnet is not enabled/started.
func (s *Server) LocalClient() (*local.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localClient == nil {
		return nil, errors.New("netts: tsnet LocalClient is not available")
	}
	return s.localClient, nil
}

// Authenticator returns a TSNetAuthenticator backed by this Server's LocalClient,
// or nil when tsnet is disabled (safe to pass directly to auth.NewChainAuthenticator).
func (s *Server) Authenticator() auth.Authenticator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localClient == nil {
		return nil
	}
	return NewTSNetAuthenticator(s.localClient)
}

// ACMEManager returns the active ACME DNS-01 certificate manager, or nil when not in acme_dns01 mode.
func (s *Server) ACMEManager() *ACMEManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acmeMgr
}

// TailnetStatus returns the ipnstate.Status captured when tsnet came up, or nil if tsnet is disabled.
func (s *Server) TailnetStatus() *ipnstate.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// TailnetAddr returns the bound Tailnet listener address, or "" if inactive.
func (s *Server) TailnetAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tailnetLn == nil {
		return ""
	}
	return s.tailnetLn.Addr().String()
}

// LocalAddr returns the bound local HTTP listener address, or "" if inactive.
func (s *Server) LocalAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localLn == nil {
		return ""
	}
	return s.localLn.Addr().String()
}
