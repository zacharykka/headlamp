package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/zacharykka/headlamp/internal/api"
	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/chat"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/guardrail"
	"github.com/zacharykka/headlamp/internal/mcp"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/netts"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/quota"
	"github.com/zacharykka/headlamp/internal/store"
	"github.com/zacharykka/headlamp/web"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "headlamp: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServe(nil, stdout, stderr)
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "usage":
		return runUsage(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		return runVersion(stdout)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return runServe(args, stdout, stderr)
		}
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Headlamp — Private AI Gateway for Headscale & Tailscale

Usage:
  headlamp [command] [flags]

Commands:
  serve    Start the Headlamp gateway server (default)
  init     Write a starter headlamp.yaml configuration file
  usage    Display recent LLM usage logs and cost totals from storage
  version  Print version and build metadata
  help     Show this help message`)
}

func runVersion(stdout io.Writer) error {
	_, err := fmt.Fprintf(stdout, "headlamp %s (commit=%s, built=%s, go=%s)\n",
		version, commit, date, runtime.Version())
	return err
}

func runServe(args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to YAML configuration file (or HEADLAMP_CONFIG)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := log.New(stderr, "headlamp: ", log.LstdFlags)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, generatedKey, keyPath, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			logger.Printf("close store: %v", err)
		}
	}()
	if generatedKey {
		logger.Printf("generated new master encryption key at %s (0600) — back up this file or set HEADLAMP_MASTER_KEY", keyPath)
	}

	if err := st.SyncConfig(ctx, cfg); err != nil {
		return fmt.Errorf("sync config to store: %w", err)
	}

	activeAuditCfg, err := loadActiveAuditConfig(ctx, st, cfg.Audit)
	if err != nil {
		return fmt.Errorf("load audit settings: %w", err)
	}

	pricing, err := metering.LoadDefault()
	if err != nil {
		return fmt.Errorf("load default pricing: %w", err)
	}

	grEngine, err := guardrail.NewEngine(guardrail.EngineConfig{
		Store: st,
		Logf:  logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("init guardrail engine: %w", err)
	}
	// Shutdown order (LIFO defers): srv.Close -> recorder.Close -> grEngine.Close -> st.Close.
	// Closing recorder before grEngine ensures any budget alerts triggered during final
	// usage flushes are dispatched before the async webhook workers drain.
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := grEngine.Close(flushCtx); err != nil {
			logger.Printf("drain guardrail webhooks: %v", err)
		}
	}()

	quotaMgr := quota.NewManager(st, quota.WithOnAlert(func(ev quota.AlertEvent) {
		grEngine.Emit(ev.EventType, ev)
	}))

	recorder := metering.NewRecorder(st, activeAuditCfg, pricing, metering.RecorderOptions{
		OnError: func(err error) {
			logger.Printf("metering error: %v", err)
		},
		OnRecorded: quotaMgr.OnUsageRecorded,
	})
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := recorder.Close(flushCtx); err != nil {
			logger.Printf("flush metering recorder: %v", err)
		}
	}()

	eval := policy.NewEvaluator()

	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Telemetry:  &telemetryAdapter{recorder: recorder},
		Quota:      &quotaLimiterAdapter{mgr: quotaMgr},
		Guardrails: &guardrailInspectorAdapter{engine: grEngine},
		Events:     grEngine,
		Logf:       logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("init proxy gateway: %w", err)
	}

	mcpGw, err := mcp.NewGateway(mcp.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Guardrails: &mcpGuardrailAdapter{engine: grEngine},
		Logf:       logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("init mcp gateway: %w", err)
	}

	chatSvc, err := chat.NewService(chat.Config{
		Store:      st,
		Authorizer: eval,
		Pricing:    pricing,
		Gateway:    gw,
		MCP:        &chatMCPAdapter{gw: mcpGw},
		Guardrails: &chatGuardrailAdapter{engine: grEngine},
		Logf:       logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("init chat service: %w", err)
	}

	staticFS, err := web.DistFS()
	if err != nil {
		return fmt.Errorf("load embedded web assets: %w", err)
	}

	apiHandler, err := api.NewHandler(api.Config{
		Store:           st,
		Policy:          eval,
		Pricing:         pricing,
		AuditController: recorder,
		BudgetReporter:  &budgetReporterAdapter{mgr: quotaMgr},
		GuardrailTester: &guardrailTesterAdapter{engine: grEngine},
		WebhookTester:   &webhookTesterAdapter{engine: grEngine},
		MCPTester:       &mcpTesterAdapter{gw: mcpGw},
		ChatHandler:     &chatHandlerAdapter{svc: chatSvc},
		StaticFS:        staticFS,
	})
	if err != nil {
		return fmt.Errorf("init api handler: %w", err)
	}

	startupTimeout, err := resolveStartupTimeout(cfg)
	if err != nil {
		return err
	}

	srv, err := netts.NewServer(cfg.Server, netts.WithUserLogf(logger.Printf))
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	err = srv.Start(startupCtx)
	cancelStartup()
	if err != nil {
		return fmt.Errorf("start listeners: %w", err)
	}

	// P0-2 listener isolation:
	// - Tailnet listener ONLY accepts Tailnet WhoIs identity (never static tokens or dev_mock).
	// - Local listener ONLY uses static API tokens and/or loopback-restricted dev_mock.
	var tailnetHandler, localHandler http.Handler
	if cfg.Server.TSNet.Enabled {
		tailnetHandler = buildHandler(gw, mcpGw, apiHandler, eval, srv.Authenticator())
	}
	if strings.TrimSpace(cfg.Server.LocalListen) != "" {
		localHandler = buildHandler(gw, mcpGw, apiHandler, eval, buildLocalAuthChain(cfg.Server))
	}

	if addr := srv.TailnetAddr(); addr != "" {
		logger.Printf("listening on tailnet %s (hostname=%s, tls=%s)", addr, cfg.Server.TSNet.Hostname, cfg.Server.TLS.Mode)
	}
	if addr := srv.LocalAddr(); addr != "" {
		logger.Printf("listening on local HTTP %s (dev_mode=%v)", addr, cfg.Server.DevMode)
	}

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.ServeHandlers(tailnetHandler, localHandler)
	}()

	select {
	case err := <-serveErrCh:
		return err
	case <-ctx.Done():
		logger.Printf("shutdown signal received, draining connections...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Close(shutdownCtx); err != nil {
			logger.Printf("shutdown listeners: %v", err)
		}
		if err := <-serveErrCh; err != nil {
			return err
		}
		return nil
	}
}

func runInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", "headlamp.yaml", "output path for starter configuration")
	force := fs.Bool("force", false, "overwrite existing configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*force {
		if _, err := os.Stat(*outPath); err == nil {
			return fmt.Errorf("file %q already exists (use -force to overwrite)", *outPath)
		}
	}

	if dir := filepath.Dir(*outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(*outPath, []byte(starterConfigTemplate), 0o600); err != nil {
		return fmt.Errorf("write %q: %w", *outPath, err)
	}

	_, err := fmt.Fprintf(stdout, "Wrote starter Headlamp configuration to %s\n", *outPath)
	return err
}

func runUsage(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to YAML configuration file (or HEADLAMP_CONFIG)")
	limit := fs.Int("limit", 20, "maximum number of recent usage rows to display")
	subject := fs.String("subject", "", "filter by caller subject")
	provider := fs.String("provider", "", "filter by provider name")
	model := fs.String("model", "", "filter by requested or upstream model")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	st, _, _, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	filter := store.UsageFilter{
		Subject:      strings.TrimSpace(*subject),
		ProviderName: strings.TrimSpace(*provider),
		Model:        strings.TrimSpace(*model),
		Limit:        *limit,
	}

	logs, err := st.QueryUsageLogs(ctx, filter)
	if err != nil {
		return fmt.Errorf("query usage logs: %w", err)
	}
	summary, err := st.SummarizeUsage(ctx, store.UsageFilter{
		Subject:      filter.Subject,
		ProviderName: filter.ProviderName,
		Model:        filter.Model,
	})
	if err != nil {
		return fmt.Errorf("summarize usage: %w", err)
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIMESTAMP\tSUBJECT\tPROVIDER\tMODEL\tIN\tOUT\tCACHE_R\tCACHE_W\tCOST_USD\tSTATUS\tMS")
	for _, row := range logs {
		modelLabel := row.RequestedModel
		if row.UpstreamModel != "" && row.UpstreamModel != row.RequestedModel {
			modelLabel = row.RequestedModel + "->" + row.UpstreamModel
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t$%.6f\t%d\t%d\n",
			row.CreatedAt.UTC().Format(time.RFC3339),
			row.Subject,
			row.ProviderName,
			modelLabel,
			row.InputTokens,
			row.OutputTokens,
			row.CacheReadTokens,
			row.CacheWriteTokens,
			row.CostUSD,
			row.StatusCode,
			row.LatencyMS,
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "\nTotal: %d requests | in=%d out=%d cache_read=%d cache_write=%d reasoning=%d total=%d | cost=$%.6f\n",
		summary.RequestCount,
		summary.InputTokens,
		summary.OutputTokens,
		summary.CacheReadTokens,
		summary.CacheWriteTokens,
		summary.ReasoningTokens,
		summary.TotalTokens,
		summary.CostUSD,
	)
	return err
}

func openStore(ctx context.Context, cfg *config.Config) (store.Store, bool, string, error) {
	stateDir := cfg.Server.TSNet.StateDir
	if strings.TrimSpace(stateDir) == "" {
		if cfg.Storage.Driver == config.StorageDriverSQLite && cfg.Storage.DSN != "" && cfg.Storage.DSN != ":memory:" && !strings.Contains(cfg.Storage.DSN, "mode=memory") {
			stateDir = filepath.Dir(cfg.Storage.DSN)
		} else {
			stateDir = "./data"
		}
	}

	cipher, generated, keyPath, err := crypto.NewCipherFromEnvOrDir(cfg.MasterKey, stateDir)
	if err != nil {
		return nil, false, "", fmt.Errorf("init master key cipher: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.Storage, cipher)
	if err != nil {
		return nil, generated, keyPath, fmt.Errorf("open %s store: %w", cfg.Storage.Driver, err)
	}
	return st, generated, keyPath, nil
}

// resolveStartupTimeout returns the timeout budget for starting listeners, tsnet, and ACME DNS-01.
// ACME DNS-01 defaults to 5m to allow authoritative DNS TXT propagation and Let's Encrypt validation;
// all other modes default to 60s. Set HEADLAMP_STARTUP_TIMEOUT (e.g. "3m") to override.
func resolveStartupTimeout(cfg *config.Config) (time.Duration, error) {
	if raw := strings.TrimSpace(os.Getenv("HEADLAMP_STARTUP_TIMEOUT")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return 0, fmt.Errorf("invalid HEADLAMP_STARTUP_TIMEOUT %q: must be a positive duration (e.g. 90s, 3m)", raw)
		}
		return d, nil
	}
	if cfg != nil && cfg.Server.TLS.Mode == config.TLSModeACMEDNS01 {
		return 5 * time.Minute, nil
	}
	return 60 * time.Second, nil
}

// loadActiveAuditConfig restores persisted UI audit settings when present,
// falling back to YAML config defaults on first run.
func loadActiveAuditConfig(ctx context.Context, st store.Store, fallback config.AuditConfig) (config.AuditConfig, error) {
	saved, err := st.GetAuditSettings(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fallback, nil
		}
		return config.AuditConfig{}, err
	}
	if saved == nil {
		return fallback, nil
	}
	return config.AuditConfig{
		StorePayloads: saved.StorePayloads,
		RetentionDays: saved.RetentionDays,
	}, nil
}

// buildLocalAuthChain builds the authenticator chain for the optional local HTTP listener.
// It NEVER runs on the Tailnet listener.
func buildLocalAuthChain(cfg config.ServerConfig) auth.Authenticator {
	var chain []auth.Authenticator
	if len(cfg.APITokens) > 0 {
		tokens := make([]auth.StaticToken, len(cfg.APITokens))
		for i, t := range cfg.APITokens {
			tokens[i] = auth.StaticToken{
				Name:          t.Name,
				Token:         t.Token,
				Subject:       t.Subject,
				DisplayName:   t.DisplayName,
				Roles:         t.Roles,
				Tags:          t.Tags,
				AllowModels:   t.AllowModels,
				DenyModels:    t.DenyModels,
				AllowMCPTools: t.AllowMCPTools,
				DenyMCPTools:  t.DenyMCPTools,
			}
		}
		// In dev_mode, allow placeholder vendor keys (e.g. "headlamp") to fall through to dev_mock.
		chain = append(chain, auth.NewTokenAuthenticator(tokens, cfg.DevMode))
	}
	if cfg.DevMode {
		chain = append(chain, auth.NewDevAuthenticator(cfg.DevUser, cfg.DevRoles, cfg.DevAllowHeaderOverride))
	}
	return auth.NewChainAuthenticator(chain...)
}

func buildHandler(gw http.Handler, mcpGw http.Handler, apiHandler http.Handler, eval *policy.Evaluator, authenticator auth.Authenticator) http.Handler {
	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		p, ok := auth.FromContext(r.Context())
		if !ok {
			proxy.AuthErrorHandler(w, r, auth.ErrUnauthenticated)
			return
		}
		ep, err := eval.Evaluate(r.Context(), p)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{
					"type":    "server_error",
					"message": err.Error(),
				},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"principal": p,
			"is_admin":  ep.IsAdmin(),
			"policy":    ep,
		})
	})

	authedRouter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/whoami" {
			whoami.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/mcp" || strings.HasPrefix(r.URL.Path, "/mcp/") {
			if mcpGw != nil {
				mcpGw.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		if api.IsGatewayReservedPath(r.URL.Path) || apiHandler == nil {
			gw.ServeHTTP(w, r)
			return
		}
		apiHandler.ServeHTTP(w, r)
	})

	protected := auth.Middleware(authenticator, proxy.AuthErrorHandler)(authedRouter)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			gw.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}
