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
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/engine"
	"narthex/backend/internal/oauthas"
)

func main() {
	// Cloud Run provides PORT; ENGINE_PORT is the local override.
	port := envOr("PORT", envOr("ENGINE_PORT", "8080"))
	issuer := envOr("ENGINE_ISSUER", "http://localhost:"+port)
	password := envOr("ENGINE_PASSWORD", "spike-dev-password")
	secret := envOr("ENGINE_SECRET", "spike-dev-secret-change-me-0123456789")
	adminToken := adminTokenFromEnv()
	legacyAdmin := legacyAdminEnabledFromEnv()
	localAdminAuth := localAdminAuthEnabledFromEnv()
	accountsPath := envOr("ACCOUNTS_PATH", "accounts.json")

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
		pg, err := engine.NewPgStore(context.Background(), dsn)
		if err != nil {
			log.Fatalf("engine: postgres store: %v", err)
		}
		if k := os.Getenv("ENGINE_ENCRYPTION_KEY"); k != "" {
			cipher, err := engine.NewCipher(k)
			if err != nil {
				log.Fatalf("engine: encryption key: %v", err)
			}
			pg.SetCipher(cipher)
			if err := pg.EncryptExisting(context.Background()); err != nil {
				log.Printf("engine: encrypt-existing pass failed: %v", err)
			}
			log.Printf("engine: token encryption at rest ENABLED")
		} else {
			log.Printf("engine: WARNING token encryption DISABLED (set ENGINE_ENCRYPTION_KEY)")
		}
		// A pending approval row from a previous run can never be decided — its
		// in-process waiter died with that instance. Expire them so the console
		// doesn't show permanently stuck rows.
		if n, err := pg.ExpireOrphanedPending(context.Background()); err != nil {
			log.Printf("engine: expire orphaned pending approvals: %v", err)
		} else if n > 0 {
			log.Printf("engine: expired %d orphaned pending approval(s) from a previous run", n)
		}
		store = pg
		log.Printf("engine: using Postgres account store")
	} else {
		fs, err := engine.LoadFileStore(accountsPath)
		if err != nil {
			log.Fatalf("engine: load accounts (%s): %v", accountsPath, err)
		}
		store = fs
		log.Printf("engine: using file account store (%s)", accountsPath)
	}
	gw := engine.NewGateway(store, s)
	if as, ok := store.(engine.AuditSink); ok {
		gw.SetAudit(as) // record every tool call
	}
	actx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	go gw.StartWatch(context.Background(), 30*time.Minute)
	log.Printf("engine: refresh-ahead + alert watch started (every 30m; webhook configured=%v)", os.Getenv("ALERT_WEBHOOK_URL") != "")

	// --- OAuth AS protecting the MCP endpoint ---
	as := oauthas.New(issuer, password, secret)
	consentURL, consentPublicKey, err := hostedConsentConfigFromEnv()
	if err != nil {
		log.Fatalf("engine: hosted consent configuration: %v", err)
	}
	if consentURL != "" {
		if err := as.ConfigureHostedConsent(consentURL, consentPublicKey); err != nil {
			log.Fatalf("engine: hosted consent configuration: %v", err)
		}
		log.Printf("engine: hosted OAuth consent delegation enabled")
	}
	// Bind access tokens to the connector GENERATION serving their resource
	// path: /mcp is the stable aggregate surface; /mcp/{slug} resolves to the
	// live connector's epoch (fails closed for slugs that don't exist — no
	// pre-authorization — and deleting/recreating a slug rotates the epoch,
	// which invalidates every previously issued token for that path).
	as.SetEpochLookup(func(path string) (string, bool) {
		if path == "/mcp" {
			return "narthex-root", true
		}
		if slug, ok := strings.CutPrefix(path, "/mcp/"); ok && slug != "" && !strings.Contains(slug, "/") {
			return gw.ConnectorEpoch(slug)
		}
		return "", false
	})
	// Deleting a connector also drops its refresh grants at the AS.
	gw.SetTokenRevoker(as.RevokeResource)
	mcpHandler := server.NewStreamableHTTPServer(s, server.WithEndpointPath("/mcp"))

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
		h.ServeHTTP(w, r)
	})))

	// --- console management API (folded in; same process as /mcp so account
	//     changes reflect in the live aggregator immediately) ---
	consoleURL := envOr("CONSOLE_URL", "http://localhost:3000")
	consoleOrigin := envOr("CONSOLE_ORIGIN", consoleURL)
	gw.SetConsoleURL(consoleURL) // linked in approval webhook messages
	conn := engine.NewConnector(store, gw)
	console := engine.NewConsoleAPI(
		store,
		gw,
		conn,
		password,
		secret,
		issuer,
		consoleURL,
		consoleOrigin,
		engine.WithAdminToken(adminToken),
		engine.WithLocalAdminAuth(localAdminAuth),
	)
	console.Routes(mux)
	log.Printf("engine: machine control authentication enabled=%v local_admin_auth=%v", adminToken != "", localAdminAuth)

	// --- legacy admin forms (bootstrap; superseded by the console /api) ---
	// GET /admin/connect?name=&label=&group=&url=&password=  → bounces the
	// browser to the upstream's OAuth; the callback stores + aggregates.
	mux.HandleFunc("/admin/connect", func(w http.ResponseWriter, r *http.Request) {
		if !legacyAdmin {
			http.NotFound(w, r)
			return
		}
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
		if !legacyAdmin {
			http.NotFound(w, r)
			return
		}
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

	// --- token-auth connect (e.g. GitHub PAT): no OAuth, just store the token ---
	// GET shows a form; POST stores the account and aggregates it.
	mux.HandleFunc("/admin/token", func(w http.ResponseWriter, r *http.Request) {
		if !legacyAdmin {
			http.NotFound(w, r)
			return
		}
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

	httpServer := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("synaxis engine on :%s — issuer %s legacy_admin=%v", port, issuer, legacyAdmin)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("engine: %v", err)
	}
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

func legacyAdminEnabledFromEnv() bool {
	raw := envOr("SYNAXIS_ENABLE_LEGACY_ADMIN", envOr("ENGINE_ENABLE_LEGACY_ADMIN", "true"))
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false
	}
	return enabled
}

func localAdminAuthEnabledFromEnv() bool {
	raw := envOr("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "true")
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
