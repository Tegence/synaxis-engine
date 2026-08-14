// Command engine is the Synaxis MCP gateway: a Go-native MCP Streamable HTTP
// server (mcp-go) that aggregates every connected account from a persistent
// store behind a single-tenant OAuth Authorization Server (internal/oauthas),
// with an upstream MCP client that refresh-and-redials on 401 (internal/engine).
//
// See docs/DESIGN.md for the architecture and rationale.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/engine"
	"narthex/backend/internal/oauthas"
)

func main() {
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runEngine(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("engine: %v", err)
	}
}

// runEngine owns the Engine process lifecycle. Startup work and background
// refresh loops share rootCtx so a termination signal stops new work before
// HTTP begins its graceful drain.
func runEngine(rootCtx context.Context) error {
	if rootCtx == nil {
		rootCtx = context.Background()
	}
	runCtx, cancelRun := context.WithCancel(rootCtx)
	defer cancelRun()

	// Cloud Run provides PORT; ENGINE_PORT is the local override.
	port := envOr("PORT", envOr("ENGINE_PORT", "8080"))
	issuer := envOr("ENGINE_ISSUER", "http://localhost:"+port)
	security, err := startupSecurityConfigFromEnv()
	if err != nil {
		return fmt.Errorf("startup security configuration: %w", err)
	}
	encryptionKey, err := encryptionKeyFromEnv(security.hosted)
	if err != nil {
		return fmt.Errorf("startup encryption configuration: %w", err)
	}
	password := security.password
	secret := security.secret
	adminToken := adminTokenFromEnv()
	legacyAdmin := security.legacyAdmin
	localAdminAuth := security.localAdminAuth
	accountsPath := envOr("ACCOUNTS_PATH", "accounts.json")
	if security.generatedPassword {
		// Development mode intentionally avoids a compiled-in credential. This
		// value is useful only on the local terminal that launched the Engine.
		log.Printf("engine: DEVELOPMENT MODE generated temporary ENGINE_PASSWORD=%q", password)
	}
	if security.generatedSecret {
		log.Printf("engine: DEVELOPMENT MODE generated an ephemeral ENGINE_SECRET; sessions and OAuth grants will reset on restart")
	}

	// --- MCP server (Claude-facing) ---
	s := server.NewMCPServer("synaxis-engine", "0.1.0", server.WithToolCapabilities(true))
	s.AddTool(
		mcp.NewTool("engine_ping", mcp.WithDescription("Health check for Synaxis Engine.")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("synaxis-engine ok"), nil
		},
	)

	// --- aggregate every account from the store ---
	var store engine.AccountStore
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		pg, err := engine.NewPgStore(runCtx, dsn)
		if err != nil {
			return fmt.Errorf("postgres store: %w", err)
		}
		if enabled, err := configureStoreEncryption(runCtx, pg, encryptionKey); err != nil {
			// Continuing would either leave plaintext secrets behind or make an
			// encrypted row silently unavailable. The deployment must be fixed
			// before this Engine is allowed to serve traffic.
			pg.Close()
			return fmt.Errorf("token encryption migration: %w", err)
		} else if enabled {
			log.Printf("engine: token encryption at rest ENABLED")
		} else {
			log.Printf("engine: WARNING token encryption DISABLED for self-hosted development (set ENGINE_ENCRYPTION_KEY before storing real credentials)")
		}
		// Recover according to the persisted lifecycle. Calls whose deadline
		// genuinely elapsed are expired; still-live rows are explicitly cancelled
		// because their original MCP request died with the previous process and
		// generic tool calls must never be replayed from stored arguments.
		if recovery, err := pg.RecoverPendingApprovals(runCtx, time.Now()); err != nil {
			log.Printf("engine: recover interrupted pending approvals: %v", err)
		} else if recovery.Expired > 0 || recovery.Cancelled > 0 {
			log.Printf("engine: recovered pending approvals: expired=%d cancelled=%d", recovery.Expired, recovery.Cancelled)
		}
		store = pg
		log.Printf("engine: using Postgres account store")
	} else {
		fs, err := engine.LoadFileStore(accountsPath)
		if err != nil {
			return fmt.Errorf("load accounts (%s): %w", accountsPath, err)
		}
		store = fs
		log.Printf("engine: using file account store (%s)", accountsPath)
	}
	var watchDone <-chan struct{}
	// A future durable dependency (for example, the audit writer) can expose
	// Shutdown(context.Context) and be drained here without changing the
	// process lifecycle. PgStore currently exposes Close(), which remains the
	// compatibility fallback.
	defer func() {
		// A listener failure is also a terminal Engine condition. Cancel the
		// watcher before closing its store, not only when the OS sends SIGTERM.
		cancelRun()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), engineShutdownTimeout)
		defer cancel()
		if watchDone != nil {
			select {
			case <-watchDone:
			case <-shutdownCtx.Done():
				log.Printf("engine: background watcher did not stop before shutdown deadline")
			}
		}
		if err := shutdownEngineDependencies(shutdownCtx, store); err != nil {
			log.Printf("engine: dependency shutdown: %v", err)
		}
	}()
	gw := engine.NewGateway(store, s)
	if as, ok := store.(engine.AuditSink); ok {
		gw.SetAudit(as) // record every tool call
	}
	actx, cancel := context.WithTimeout(runCtx, 60*time.Second)
	n := gw.Aggregate(actx)
	cancel()
	log.Printf("engine: aggregated %d tools across %d account(s) from %s", n, len(store.Accounts()), accountsPath)

	// --- background reliability: refresh OAuth tokens before they expire, and
	//     alert on account down/recovered transitions ---
	gw.SetAlertWebhook(os.Getenv("ALERT_WEBHOOK_URL"))
	if v := os.Getenv("APPROVAL_TIMEOUT_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			gw.SetApprovalTimeout(time.Duration(secs) * time.Second)
		} else {
			log.Printf("engine: invalid APPROVAL_TIMEOUT_SECONDS %q — using default 180s", v)
		}
	}
	// --- flight recorder: payload recording for /mcp + audit retention ---
	recordDefault := os.Getenv("ENGINE_RECORD_PAYLOADS") == "true"
	gw.SetRecordPayloads(recordDefault)
	retentionDays := 30
	if v := os.Getenv("AUDIT_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d >= 0 {
			retentionDays = d
		} else {
			log.Printf("engine: invalid AUDIT_RETENTION_DAYS %q — using default 30", v)
		}
	}
	gw.SetAuditRetention(time.Duration(retentionDays) * 24 * time.Hour)
	log.Printf("engine: flight recorder — /mcp payload recording=%v, audit retention=%dd (0=keep forever)", recordDefault, retentionDays)

	watcherDone := make(chan struct{})
	watchDone = watcherDone
	go func() {
		defer close(watcherDone)
		gw.StartWatch(runCtx, 30*time.Minute)
	}()
	log.Printf("engine: refresh-ahead + alert watch started (every 30m; webhook configured=%v)", os.Getenv("ALERT_WEBHOOK_URL") != "")

	// --- OAuth AS protecting the MCP endpoint ---
	as := oauthas.New(issuer, password, secret)
	generationStore, ok := store.(oauthas.TokenGenerationStore)
	if !ok {
		return errors.New("account store does not support durable OAuth token generations")
	}
	generationCtx, generationCancel := context.WithTimeout(runCtx, 10*time.Second)
	err = as.ConfigureTokenGeneration(generationCtx, generationStore)
	generationCancel()
	if err != nil {
		return fmt.Errorf("initialize durable OAuth token generation: %w", err)
	}
	consentURL, consentPublicKey, err := hostedConsentConfigFromEnv()
	if err != nil {
		return fmt.Errorf("hosted consent configuration: %w", err)
	}
	if consentURL != "" {
		if err := as.ConfigureHostedConsent(consentURL, consentPublicKey); err != nil {
			return fmt.Errorf("hosted consent configuration: %w", err)
		}
		log.Printf("engine: hosted OAuth consent delegation enabled")
	}
	actorVerifier, err := hostedActorVerifierFromEnv(consentPublicKey, issuer)
	if err != nil {
		return fmt.Errorf("hosted actor assertion configuration: %w", err)
	}
	if actorVerifier != nil {
		if adminToken == "" {
			return errors.New("hosted actor assertions require SYNAXIS_ADMIN_TOKEN")
		}
		// A hosted Engine has one management entrypoint: the Platform proxy.
		// Never leave password/session or legacy query-string administration as a
		// configuration-dependent bypass around the signed actor boundary.
		localAdminAuth = false
		legacyAdmin = false
		log.Printf("engine: hosted Platform actor assertions enabled")
	}
	usageCtx, usageCancel := context.WithTimeout(runCtx, 10*time.Second)
	usageGate, err := hostedUsageGateFromEnv(usageCtx, store, consentPublicKey)
	usageCancel()
	if err != nil {
		return fmt.Errorf("hosted usage configuration: %w", err)
	}
	if usageGate != nil {
		gw.SetUsageGate(usageGate)
		log.Printf(
			"engine: hosted usage enforcement enabled for workspace %s generation %d",
			usageGate.Identity().WorkspaceID,
			usageGate.Identity().EngineGeneration,
		)
	}
	// Bind access tokens to the resource serving their path: /mcp is the
	// aggregate surface; /mcp/{slug} resolves to a live shared endpoint; and
	// /mcp/clients/{slug} is the separate subject-bound client namespace.
	// Client routes additionally perform a durable OAuth-client binding check
	// for every access/code/refresh use below, so revocation and reset fail
	// closed even before a replica has refreshed its endpoint projection.
	as.SetEpochLookup(func(path string) (string, bool) {
		if path == "/mcp" {
			return "narthex-root", true
		}
		if slug, ok := strings.CutPrefix(path, "/mcp/clients/"); ok && slug != "" && !strings.Contains(slug, "/") {
			return gw.MCPClientEpoch(slug)
		}
		if slug, ok := strings.CutPrefix(path, "/mcp/"); ok && slug != "" && !strings.Contains(slug, "/") {
			return gw.ConnectorEpoch(slug)
		}
		return "", false
	})
	as.SetClientResourceAuthorizer(gw.MCPClientAllowsOAuthClient)
	as.SetHostedConsentAuthorizer(gw.AuthorizeMCPConsent)
	// Self-hosted Engines have the same subject-bound delivery model, with their
	// established local administrator as the single durable identity. This keeps
	// a personal connection private even when Claude or Codex connects directly
	// to an open-source Engine.
	as.SetLocalConsentAuthorizer(gw.AuthorizeMCPConsent)
	// Deleting or rebinding an endpoint drops grants for its retiring epoch at
	// the AS. The path-only callback remains for compatibility; the epoch-aware
	// callback avoids sweeping a newly recreated endpoint's grants.
	gw.SetTokenRevoker(as.RevokeResource)
	gw.SetTokenEpochRevoker(as.RevokeResourceAtEpoch)
	mcpHandler := engine.LimitMCPRequestBody(
		server.NewStreamableHTTPServer(s, server.WithEndpointPath("/mcp")),
	)

	mux := http.NewServeMux()
	as.Routes(mux)
	mux.Handle("/mcp", as.RequireAuth(mcpHandler))

	// --- virtual connectors: each curated subset gets its own MCP endpoint at
	// /mcp/{slug}, protected by the same OAuth AS as /mcp ---
	mux.Handle("/mcp/{slug}", as.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := gw.ConnectorHandler(r.PathValue("slug"))
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"unknown connector %q"}`, r.PathValue("slug"))
			return
		}
		engine.LimitMCPRequestBody(h).ServeHTTP(w, r)
	})))

	// --- subject-bound AI-client endpoints: these deliberately live outside
	// the shared /mcp/{slug} namespace. Each route is rebuilt from durable
	// connection-folder ownership immediately before it serves, and oauthas
	// confirms its OAuth DCR client binding on every authenticated call. ---
	mux.Handle("/mcp/clients/{slug}", as.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := gw.MCPClientHandler(r.PathValue("slug"))
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"unknown MCP client %q"}`, r.PathValue("slug"))
			return
		}
		engine.LimitMCPRequestBody(h).ServeHTTP(w, r)
	})))

	// --- console management API (folded in; same process as /mcp so account
	//     changes reflect in the live aggregator immediately) ---
	consoleURL := envOr("CONSOLE_URL", "http://localhost:3000")
	consoleOrigin := envOr("CONSOLE_ORIGIN", consoleURL)
	gw.SetConsoleURL(consoleURL) // linked in approval webhook messages
	conn := engine.NewConnector(store, gw)
	consoleOptions := []engine.ConsoleOption{
		engine.WithAdminToken(adminToken),
		engine.WithLocalAdminAuth(localAdminAuth),
		engine.WithOAuthRevoker(as.RevokeAll),
		engine.WithUsageGate(usageGate),
		// CurrentTokenGeneration is a cheap durable read. On PgStore it proves
		// the database connection and initialized Engine state without probing
		// accounts or external providers; FileStore retains its local check.
		engine.WithReadinessCheck(func(ctx context.Context) error {
			_, err := generationStore.CurrentTokenGeneration(ctx)
			return err
		}),
		engine.WithLifecycleContext(runCtx),
	}
	if actorVerifier != nil {
		consoleOptions = append(consoleOptions, engine.WithPlatformActorVerifier(actorVerifier))
	}
	console := engine.NewConsoleAPI(
		store,
		gw,
		conn,
		password,
		secret,
		issuer,
		consoleURL,
		consoleOrigin,
		consoleOptions...,
	)
	console.Routes(mux)
	log.Printf("engine: machine control authentication enabled=%v local_admin_auth=%v", adminToken != "", localAdminAuth)

	registerLegacyAdminRoutes(mux, legacyAdmin, password, issuer, conn, store, gw)

	httpServer := newEngineHTTPServer(port, mux)
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", httpServer.Addr, err)
	}
	log.Printf("synaxis engine on :%s — issuer %s legacy_admin=%v", port, issuer, legacyAdmin)
	return serveEngineHTTP(runCtx, httpServer, listener)
}

const engineShutdownTimeout = 25 * time.Second

// newEngineHTTPServer intentionally leaves WriteTimeout unset. MCP Streamable
// HTTP responses may remain open while a model consumes a result, so a generic
// short write timeout would turn normal governed calls into spurious failures.
func newEngineHTTPServer(port string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// serveEngineHTTP accepts an already-bound listener to make the lifecycle
// testable and to keep listener ownership explicit. On termination it first
// stops accepting new requests, then lets active MCP streams drain within the
// platform-safe shutdown budget.
func serveEngineHTTP(ctx context.Context, httpServer *http.Server, listener net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		log.Printf("engine: shutdown requested; draining active HTTP requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), engineShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Shutdown timed out or encountered a listener failure. Force close so
			// the serving goroutine cannot outlive process teardown, but retain the
			// graceful-shutdown error for operators.
			_ = httpServer.Close()
			<-errCh
			return fmt.Errorf("graceful HTTP shutdown: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP during shutdown: %w", err)
		}
		return nil
	}
}

// engineShutdowner is an optional hook for dependencies that need to drain
// durable work before their connections close. Existing stores only need the
// close fallback; a future audit writer can implement Shutdown without
// coupling lifecycle control to PgStore internals.
type engineShutdowner interface {
	Shutdown(context.Context) error
}

type engineCloser interface {
	Close()
}

func shutdownEngineDependencies(ctx context.Context, dependencies ...any) error {
	var shutdownErr error
	for _, dependency := range dependencies {
		if dependency == nil {
			continue
		}
		if shutdowner, ok := dependency.(engineShutdowner); ok {
			shutdownErr = errors.Join(shutdownErr, shutdowner.Shutdown(ctx))
			continue
		}
		if closer, ok := dependency.(engineCloser); ok {
			closer.Close()
		}
	}
	return shutdownErr
}

// registerLegacyAdminRoutes deliberately registers nothing until a caller has
// explicitly opted in. Returning 404 instead of serving a password form makes
// the compatibility surface invisible on an unattended Engine.
func registerLegacyAdminRoutes(
	mux *http.ServeMux,
	enabled bool,
	password string,
	issuer string,
	conn *engine.Connector,
	store engine.AccountStore,
	gw *engine.Gateway,
) {
	if !enabled {
		return
	}

	// GET /admin/connect?name=&label=&group=&url=&password= bounces the
	// browser to the upstream's OAuth; the callback stores + aggregates.
	mux.HandleFunc("/admin/connect", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("password") != password {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name, url := q.Get("name"), q.Get("url")
		if name == "" || url == "" {
			http.Error(w, "name and url required", http.StatusBadRequest)
			return
		}
		authURL, err := conn.StartConnect(r.Context(), name, q.Get("label"), q.Get("group"), url, issuer+"/admin/oauth/callback", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})
	mux.HandleFunc("/admin/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "oauth error: "+e, http.StatusBadRequest)
			return
		}
		name, n, err := conn.FinishConnect(r.Context(), q.Get("state"), q.Get("code"))
		if err != nil {
			http.Error(w, "connect failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body style="font-family:system-ui;max-width:480px;margin:14vh auto;color:#222"><h2>Connected: %s</h2><p>Aggregated %d tools into Synaxis Engine. You can close this tab.</p></body></html>`, name, n)
	})

	// Token-auth connect (e.g. GitHub PAT): GET shows a form; POST stores the
	// account and aggregates it. It is intentionally a compatibility-only route.
	mux.HandleFunc("/admin/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, tokenFormHTML)
			return
		}
		r.ParseForm()
		if r.Form.Get("password") != password {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name, url, token := r.Form.Get("name"), r.Form.Get("url"), r.Form.Get("token")
		if name == "" || url == "" || token == "" {
			http.Error(w, "name, url and token are required", http.StatusBadRequest)
			return
		}
		a := engine.Account{
			Name: name, Label: r.Form.Get("label"), Group: r.Form.Get("group"),
			URL: url, AuthMode: "token", BearerToken: token,
		}
		if err := store.Upsert(r.Context(), a); err != nil {
			http.Error(w, "store: "+err.Error(), http.StatusBadGateway)
			return
		}
		n, err := gw.AddAccount(r.Context(), name)
		w.Header().Set("Content-Type", "text/html")
		if err != nil {
			fmt.Fprintf(w, `<html><body style="font-family:system-ui;max-width:480px;margin:14vh auto;color:#222"><h2>Saved %s, but couldn't list its tools</h2><p>%v — check the token is valid. The account is stored; re-submit with a working token to aggregate.</p></body></html>`, name, err)
			return
		}
		fmt.Fprintf(w, `<html><body style="font-family:system-ui;max-width:480px;margin:14vh auto;color:#222"><h2>Connected: %s</h2><p>Aggregated %d tools into Synaxis Engine. You can close this tab.</p></body></html>`, name, n)
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func adminTokenFromEnv() string {
	return envOr("SYNAXIS_ADMIN_TOKEN", os.Getenv("ENGINE_ADMIN_TOKEN"))
}

// encryptionKeyFromEnv makes encryption mandatory for Platform-managed
// workspaces while preserving the explicitly documented local self-hosted
// development path. A missing key must be caught before any Engine listener is
// created, even if another hosted configuration error would fail later.
func encryptionKeyFromEnv(hosted bool) (string, error) {
	key := strings.TrimSpace(os.Getenv("ENGINE_ENCRYPTION_KEY"))
	if hosted && key == "" {
		return "", errors.New("SYNAXIS_WORKSPACE_ID requires ENGINE_ENCRYPTION_KEY")
	}
	return key, nil
}

type encryptionStore interface {
	SetCipher(*engine.Cipher)
	EncryptExisting(context.Context) error
}

// configureStoreEncryption validates the configured key, enables encryption,
// and completes the in-place migration as one startup prerequisite. It is kept
// small and interface-based so migration failure behavior is unit-testable
// without a running Postgres instance.
func configureStoreEncryption(ctx context.Context, store encryptionStore, key string) (bool, error) {
	if key == "" {
		return false, nil
	}
	cipher, err := engine.NewCipher(key)
	if err != nil {
		return false, fmt.Errorf("invalid ENGINE_ENCRYPTION_KEY: %w", err)
	}
	store.SetCipher(cipher)
	if err := store.EncryptExisting(ctx); err != nil {
		return false, fmt.Errorf("encrypt existing data: %w", err)
	}
	return true, nil
}

// startupSecurityConfig keeps password-based administration fail-closed. A
// self-hosted Engine should be useful as an MCP runtime without silently
// publishing a browser login or legacy form protected by a source-known
// credential. Development mode is the only convenience exception, and even
// there credentials are generated per process rather than compiled in.
type startupSecurityConfig struct {
	password          string
	secret            string
	legacyAdmin       bool
	localAdminAuth    bool
	development       bool
	hosted            bool
	generatedPassword bool
	generatedSecret   bool
}

func startupSecurityConfigFromEnv() (startupSecurityConfig, error) {
	config := startupSecurityConfig{
		password: os.Getenv("ENGINE_PASSWORD"),
		secret:   os.Getenv("ENGINE_SECRET"),
		hosted:   strings.TrimSpace(os.Getenv("SYNAXIS_WORKSPACE_ID")) != "",
	}

	development, err := boolEnv("ENGINE_DEVELOPMENT_MODE", false)
	if err != nil {
		return startupSecurityConfig{}, err
	}
	if config.hosted && development {
		return startupSecurityConfig{}, errors.New("ENGINE_DEVELOPMENT_MODE cannot be enabled for a hosted workspace")
	}
	config.development = development

	if strings.TrimSpace(config.password) == "" && development {
		password, err := generatedStartupCredential(24)
		if err != nil {
			return startupSecurityConfig{}, fmt.Errorf("generate development password: %w", err)
		}
		config.password = password
		config.generatedPassword = true
	}
	if strings.TrimSpace(config.secret) == "" && development {
		secret, err := generatedStartupCredential(32)
		if err != nil {
			return startupSecurityConfig{}, fmt.Errorf("generate development secret: %w", err)
		}
		config.secret = secret
		config.generatedSecret = true
	}
	if strings.TrimSpace(config.password) == "" {
		return startupSecurityConfig{}, errors.New("ENGINE_PASSWORD is required; set a unique value or explicitly enable ENGINE_DEVELOPMENT_MODE for local development")
	}
	if strings.TrimSpace(config.secret) == "" {
		return startupSecurityConfig{}, errors.New("ENGINE_SECRET is required; set a unique value or explicitly enable ENGINE_DEVELOPMENT_MODE for local development")
	}

	// Standard self-hosted startup exposes neither password login nor legacy
	// query/form administration. Development mode may expose the local console
	// for a generated password; legacy forms still require their own opt-in.
	config.localAdminAuth = localAdminAuthEnabledWithDefault(development)
	config.legacyAdmin = legacyAdminEnabledFromEnv()
	if config.hosted {
		// Hosted Engine management is always the signed Platform actor plus
		// machine token boundary. Do not allow env drift to add a local bypass.
		config.localAdminAuth = false
		config.legacyAdmin = false
	}
	return config, nil
}

func generatedStartupCredential(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return value, nil
}

func legacyAdminEnabledFromEnv() bool {
	raw := envOr("SYNAXIS_ENABLE_LEGACY_ADMIN", envOr("ENGINE_ENABLE_LEGACY_ADMIN", "false"))
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}
	return enabled
}

func localAdminAuthEnabledFromEnv() bool {
	return localAdminAuthEnabledWithDefault(false)
}

func localAdminAuthEnabledWithDefault(developmentDefault bool) bool {
	fallback := "false"
	if developmentDefault {
		fallback = "true"
	}
	raw := envOr("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", fallback)
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}
	return enabled
}

func hostedConsentConfigFromEnv() (string, ed25519.PublicKey, error) {
	consentURL := strings.TrimSpace(os.Getenv("ENGINE_CONSENT_URL"))
	encodedKey := strings.TrimSpace(os.Getenv("ENGINE_CONSENT_PUBLIC_KEY"))
	if consentURL == "" && encodedKey == "" {
		return "", nil, nil
	}
	if consentURL == "" || encodedKey == "" {
		return "", nil, errors.New("ENGINE_CONSENT_URL and ENGINE_CONSENT_PUBLIC_KEY must be configured together")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encodedKey)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("ENGINE_CONSENT_PUBLIC_KEY must be base64-encoded Ed25519 public key (%d bytes)", ed25519.PublicKeySize)
	}
	return consentURL, ed25519.PublicKey(key), nil
}

func hostedActorVerifierFromEnv(
	publicKey ed25519.PublicKey,
	issuer string,
) (*engine.PlatformActorVerifier, error) {
	workspaceID := strings.TrimSpace(os.Getenv("SYNAXIS_WORKSPACE_ID"))
	if workspaceID == "" {
		return nil, nil // self-hosted Engines do not receive Platform assertions.
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("SYNAXIS_WORKSPACE_ID requires ENGINE_CONSENT_PUBLIC_KEY")
	}
	return engine.NewPlatformActorVerifier(workspaceID, issuer, publicKey)
}

func hostedUsageGateFromEnv(
	ctx context.Context,
	store engine.AccountStore,
	publicKey ed25519.PublicKey,
) (*engine.UsageGate, error) {
	workspaceID := strings.TrimSpace(os.Getenv("SYNAXIS_WORKSPACE_ID"))
	if workspaceID == "" {
		return nil, nil // self-hosted default: no subscription quota
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("SYNAXIS_WORKSPACE_ID requires ENGINE_CONSENT_PUBLIC_KEY")
	}
	rawGeneration := strings.TrimSpace(os.Getenv("SYNAXIS_PROVISION_GENERATION"))
	generation, err := strconv.ParseInt(rawGeneration, 10, 64)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != rawGeneration {
		return nil, errors.New("SYNAXIS_WORKSPACE_ID requires a positive canonical SYNAXIS_PROVISION_GENERATION")
	}
	usageStore, ok := store.(engine.UsageStore)
	if !ok {
		return nil, errors.New("hosted usage enforcement requires a durable usage store")
	}
	return engine.NewUsageGate(ctx, usageStore, workspaceID, generation, publicKey)
}

const tokenFormHTML = `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><title>Synaxis Engine — Add token backend</title>
<style>body{font-family:system-ui;max-width:440px;margin:8vh auto;padding:0 20px;color:#222}h2{font-weight:600}label{display:block;font-size:13px;color:#666;margin-top:12px}input{width:100%;padding:9px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;margin-top:4px}button{margin-top:18px;width:100%;padding:11px;background:#1a56db;color:#fff;border:none;border-radius:4px;font-size:15px}</style></head>
<body><h2>Add a token-auth backend</h2><p>For providers that use a token (e.g. a GitHub PAT) instead of OAuth.</p>
<form method=post>
<label>Name (tool prefix)</label><input name=name value=github>
<label>Label</label><input name=label value=GitHub>
<label>Workspace</label><input name=group value=Tools>
<label>Upstream MCP URL</label><input name=url value="https://api.githubcopilot.com/mcp/">
<label>Token (PAT)</label><input name=token type=password placeholder="ghp_...">
<label>Console password</label><input name=password type=password>
<button>Connect</button>
</form></body></html>`
