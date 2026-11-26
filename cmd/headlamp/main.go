package main

import (
	"context"
	"encoding/json"
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

	"github.com/zacharykka/headlamp/internal/auth"
	"github.com/zacharykka/headlamp/internal/config"
	"github.com/zacharykka/headlamp/internal/crypto"
	"github.com/zacharykka/headlamp/internal/metering"
	"github.com/zacharykka/headlamp/internal/netts"
	"github.com/zacharykka/headlamp/internal/policy"
	"github.com/zacharykka/headlamp/internal/proxy"
	"github.com/zacharykka/headlamp/internal/store"
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

	pricing, err := metering.LoadDefault()
	if err != nil {
		return fmt.Errorf("load default pricing: %w", err)
	}

	recorder := metering.NewRecorder(st, cfg.Audit, pricing, metering.RecorderOptions{
		OnError: func(err error) {
			logger.Printf("metering error: %v", err)
		},
	})
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := recorder.Close(flushCtx); err != nil {
			logger.Printf("flush metering recorder: %v", err)
		}
	}()

	eval := policy.NewEvaluator()

	srv, err := netts.NewServer(cfg.Server, netts.WithUserLogf(logger.Printf))
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	startupCtx, cancelStartup := context.WithTimeout(ctx, 60*time.Second)
	err = srv.Start(startupCtx)
	cancelStartup()
	if err != nil {
		return fmt.Errorf("start listeners: %w", err)
	}

	gw, err := proxy.NewGateway(proxy.GatewayConfig{
		Store:      st,
		Authorizer: eval,
		Telemetry:  &telemetryAdapter{recorder: recorder},
		Logf:       logger.Printf,
	})
	if err != nil {
		_ = srv.Close(context.Background())
		return fmt.Errorf("init proxy gateway: %w", err)
	}

	// P0-2 listener isolation:
	// - Tailnet listener ONLY accepts Tailnet WhoIs identity (never static tokens or dev_mock).
	// - Local listener ONLY uses static API tokens and/or loopback-restricted dev_mock.
	var tailnetHandler, localHandler http.Handler
	if cfg.Server.TSNet.Enabled {
		tailnetHandler = buildHandler(gw, eval, srv.Authenticator())
	}
	if strings.TrimSpace(cfg.Server.LocalListen) != "" {
		localHandler = buildHandler(gw, eval, buildLocalAuthChain(cfg.Server))
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
	if cfg.Storage.Driver != config.StorageDriverSQLite {
		return nil, false, "", fmt.Errorf("storage driver %q is not yet implemented in M1 (use sqlite)", cfg.Storage.Driver)
	}

	stateDir := cfg.Server.TSNet.StateDir
	if strings.TrimSpace(stateDir) == "" {
		if cfg.Storage.DSN != "" && cfg.Storage.DSN != ":memory:" && !strings.Contains(cfg.Storage.DSN, "mode=memory") {
			stateDir = filepath.Dir(cfg.Storage.DSN)
		} else {
			stateDir = "./data"
		}
	}

	cipher, generated, keyPath, err := crypto.NewCipherFromEnvOrDir(cfg.MasterKey, stateDir)
	if err != nil {
		return nil, false, "", fmt.Errorf("init master key cipher: %w", err)
	}

	st, err := store.NewSQLiteStore(ctx, cfg.Storage.DSN, cipher)
	if err != nil {
		return nil, generated, keyPath, fmt.Errorf("open sqlite store: %w", err)
	}
	return st, generated, keyPath, nil
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

func buildHandler(gw http.Handler, eval *policy.Evaluator, authenticator auth.Authenticator) http.Handler {
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

	authedMux := http.NewServeMux()
	authedMux.Handle("/whoami", whoami)
	authedMux.Handle("/", gw)

	protected := auth.Middleware(authenticator, proxy.AuthErrorHandler)(authedMux)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			gw.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

// telemetryAdapter bridges *metering.Recorder to proxy.TelemetryFactory.
type telemetryAdapter struct {
	recorder *metering.Recorder
}

func (a *telemetryAdapter) Start(ctx context.Context, info proxy.TelemetryStart) proxy.StreamObserver {
	if a == nil || a.recorder == nil {
		return nil
	}
	var override *metering.PriceOverride
	if info.CostOverride != nil {
		override = &metering.PriceOverride{
			Input:      info.CostOverride.Input,
			Output:     info.CostOverride.Output,
			CacheRead:  info.CostOverride.CacheRead,
			CacheWrite: info.CostOverride.CacheWrite,
		}
	}
	obs := a.recorder.Start(ctx, metering.RequestInfo{
		RequestID:      info.RequestID,
		Timestamp:      info.Timestamp,
		Principal:      info.Principal,
		Protocol:       info.Protocol,
		Endpoint:       info.Endpoint,
		Provider:       info.Provider,
		ProviderType:   info.ProviderType,
		RequestedModel: info.RequestedModel,
		UpstreamModel:  info.UpstreamModel,
		Stream:         info.Stream,
		Translated:     info.Translated,
		RequestHeaders: flattenHeaders(info.RequestHeaders),
		RequestBody:    info.RequestBody,
		PriceOverride:  override,
	})
	return &observerAdapter{obs: obs}
}

type observerAdapter struct {
	obs *metering.RequestObserver
}

func (o *observerAdapter) OnSSEEvent(eventName string, data []byte) {
	o.obs.OnSSEEvent(eventName, data)
}

func (o *observerAdapter) OnJSONResponse(body []byte) {
	o.obs.OnJSONResponse(body)
}

func (o *observerAdapter) SetResponseHeaders(headers map[string]string) {
	o.obs.SetResponseHeaders(headers)
}

func (o *observerAdapter) Finish(fin proxy.TelemetryFinish) {
	o.obs.Finish(fin.StatusCode, fin.LatencyMS, fin.TTFTMS, fin.ErrorMessage)
}

func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

const starterConfigTemplate = `# Headlamp starter configuration (grants-only authorization)
# Run locally in loopback dev mode:
#   headlamp serve -config headlamp.yaml
# To join Headscale v0.29+ / Tailscale, set server.tsnet.enabled: true, configure
# control_url + HEADLAMP_AUTH_KEY, and define headlamp.dev/cap/gateway grants in Headscale.

server:
  tsnet:
    enabled: false
    hostname: headlamp
    control_url: ""
    auth_key: "${HEADLAMP_AUTH_KEY}"
    state_dir: "./data"
  tls:
    mode: none
  local_listen: "127.0.0.1:8080"
  dev_mode: true
  dev_user: "dev@local"
  dev_roles:
    - admin
    - user
  dev_allow_header_override: false
  # Optional fallback static API tokens for non-tailnet callers (e.g. CI):
  # api_tokens:
  #   - name: ci-runner
  #     token: "${HEADLAMP_CI_TOKEN}"
  #     subject: "tag:ci-runner"
  #     roles: ["user"]
  #     allow_models: ["openai/gpt-4.1*", "ollama/*"]
  #     deny_models: ["openai/o3*"]

storage:
  driver: sqlite
  dsn: "./data/headlamp.db"

providers:
  - name: anthropic
    type: anthropic
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"
    models:
      - "claude-sonnet-4-6"

  - name: openai
    type: openai
    base_url: "https://api.openai.com"
    api_key: "${OPENAI_API_KEY}"
    models:
      - "gpt-5"
      - "gpt-4.1"

  - name: gemini
    type: gemini
    base_url: "https://generativelanguage.googleapis.com"
    api_key: "${GEMINI_API_KEY}"
    models:
      - "gemini-2.5-flash"

  - name: ollama
    type: ollama
    base_url: "http://127.0.0.1:11434"
    models:
      - "qwen2.5-coder:32b"

routes:
  - alias: "team/coding"
    provider: anthropic
    model: "claude-sonnet-4-6"
    fallbacks:
      - provider: openai
        model: "gpt-4.1"

audit:
  store_payloads: false
  retention_days: 7
`
