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

// Server manages Headlamp's embedded Tailnet (tsnet) listener and optional local HTTP listener.
type Server struct {
	cfg       config.ServerConfig
	userLogf  LogFunc
	debugLogf LogFunc

	mu          sync.Mutex
	started     bool
	closed      bool
	tsSrv       *tsnet.Server
	localClient *local.Client
	status      *ipnstate.Status
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

	if cfg.TSNet.Enabled {
		if strings.TrimSpace(cfg.TSNet.Hostname) == "" {
			return nil, errors.New("netts: tsnet.hostname is required when tsnet is enabled")
		}
		if strings.TrimSpace(cfg.TSNet.StateDir) == "" {
			return nil, errors.New("netts: tsnet.state_dir is required when tsnet is enabled")
		}
		if err := validateTLSConfig(cfg.TLS); err != nil {
			return nil, err
		}
	}

	s := &Server{cfg: cfg}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

// WrapTLSListener applies Headlamp's configured TLS mode to an existing TCP listener.
//
// Headlamp intentionally never calls tsnet.Server.ListenTLS because Headscale does not provision
// Tailscale MagicDNS HTTPS certificates (CertDomains is empty). Instead, callers wrap a plain
// tsnet.Server.Listen("tcp", ...) listener via WrapTLSListener.
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
		return nil, fmt.Errorf(
			"netts: tls.mode %q (ACME DNS-01 automatic HTTPS) lands in M2 and is not yet available in M1; use %q or %q",
			config.TLSModeACMEDNS01, config.TLSModeNone, config.TLSModeStatic,
		)
	default:
		return nil, fmt.Errorf("netts: unsupported tls.mode %q", tlsCfg.Mode)
	}
}

func validateTLSConfig(tlsCfg config.TLSConfig) error {
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
		return fmt.Errorf(
			"netts: tls.mode %q (ACME DNS-01 automatic HTTPS) lands in M2 and is not yet available in M1; use %q or %q",
			config.TLSModeACMEDNS01, config.TLSModeNone, config.TLSModeStatic,
		)
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
// Call Start before Authenticator(), LocalClient(), or Serve().
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
		if tsSrv != nil {
			_ = tsSrv.Close()
		}
	}

	if s.cfg.TSNet.Enabled {
		// Fail fast on TLS configuration/cert errors before contacting Headscale/Tailscale.
		if err := validateTLSConfig(s.cfg.TLS); err != nil {
			return err
		}
		if normalizedTLSMode(s.cfg.TLS.Mode) == config.TLSModeStatic {
			if _, err := loadStaticTLSConfig(s.cfg.TLS); err != nil {
				return err
			}
		}

		tsDir := filepath.Join(s.cfg.TSNet.StateDir, "tsnet")
		if err := os.MkdirAll(tsDir, 0o700); err != nil {
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
			if normalizedTLSMode(s.cfg.TLS.Mode) == config.TLSModeNone {
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

		wrappedLn, err := WrapTLSListener(rawLn, s.cfg.TLS)
		if err != nil {
			cleanup()
			return err
		}
		tailnetLn = wrappedLn
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
	s.tailnetLn = tailnetLn
	s.localLn = localLn
	s.started = true
	s.mu.Unlock()

	return nil
}

// Serve serves handler on all active listeners (Tailnet and/or local) until Close is called
// or an unexpected listener error occurs. Returns nil on graceful shutdown.
func (s *Server) Serve(handler http.Handler) error {
	if handler == nil {
		return errors.New("netts: handler is required")
	}

	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return errors.New("netts: server must be started before Serve")
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	// Do not set WriteTimeout: LLM SSE streams can stay open for minutes.
	var servers []struct {
		name string
		srv  *http.Server
		ln   net.Listener
	}
	if s.tailnetLn != nil {
		s.tailnetHTTP = &http.Server{
			Handler:           handler,
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
			Handler:           handler,
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

// Close gracefully shuts down all HTTP servers, closes listeners, and stops tsnet.
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
