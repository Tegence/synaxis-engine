package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

// connector is the console's view of the OAuth connect flow — the subset of
// *Connector that handleConnect / handleOAuthCallback drive. It exists as an
// interface purely as a test seam: StartConnect's first step is network
// Discovery (SSRF-blocked against loopback), so a fake lets us assert what
// creds reach StartConnect without standing up a real authorization server.
// *Connector satisfies it, so production wiring is unchanged.
type connector interface {
	StartConnect(ctx context.Context, name, label, group, url, redirectURI string, sc *StaticCreds) (string, error)
	FinishConnect(ctx context.Context, state, code string) (name string, toolCount int, err error)
}

// ConsoleAPI is the management API the web console talks to — folded INTO the
// engine process so add/delete/rename/connect reflect in the live MCP server
// immediately (no separate service, no cross-process reload).
type ConsoleAPI struct {
	store            AccountStore
	connStore        ConnectorStore // store's connector facet; nil = connectors unsupported (501)
	apprLog          ApprovalLog    // store's approval facet; nil = approvals unsupported (501)
	audit            AuditSink      // store's audit facet; nil = call detail/replay unsupported (501)
	triage           AuditTriage    // store's triage facet; nil = flagged decisions unsupported (501)
	gw               *Gateway
	conn             connector
	passwordDigest   [sha256.Size]byte
	adminTokenDigest [sha256.Size]byte
	hasAdminToken    bool
	localAdminAuth   bool
	secret           []byte
	selfURL          string   // engine's own public base (issuer)
	consoleURL       string   // where to bounce the browser after OAuth
	origins          []string // CORS allowlist (comma-separated CONSOLE_ORIGIN)
}

// ConsoleOption configures optional management API behavior without forcing
// self-hosted callers to provide platform-only settings.
type ConsoleOption func(*ConsoleAPI)

// WithAdminToken enables machine-to-machine access to protected management
// endpoints. The raw token is not retained: only its SHA-256 digest is kept,
// and presented tokens are compared to that digest in constant time.
//
// An empty token leaves machine access disabled.
func WithAdminToken(token string) ConsoleOption {
	digest := sha256.Sum256([]byte(token))
	enabled := token != ""
	return func(c *ConsoleAPI) {
		if !enabled {
			return
		}
		c.adminTokenDigest = digest
		c.hasAdminToken = true
	}
}

// WithLocalAdminAuth controls the password-issued local management session.
// Hosted engines disable it and rely exclusively on the server-side machine
// credential; self-hosted engines keep it enabled by default.
func WithLocalAdminAuth(enabled bool) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.localAdminAuth = enabled
	}
}

func NewConsoleAPI(store AccountStore, gw *Gateway, conn *Connector, password, secret, selfURL, consoleURL, origin string, options ...ConsoleOption) *ConsoleAPI {
	var origins []string
	for _, o := range strings.Split(origin, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, strings.TrimRight(o, "/"))
		}
	}
	// Decide connector/approval support once: stores without the facet get
	// 501s from the corresponding endpoints instead of runtime surprises.
	connStore, _ := store.(ConnectorStore)
	apprLog, _ := store.(ApprovalLog)
	audit, _ := store.(AuditSink)
	triage, _ := store.(AuditTriage)
	api := &ConsoleAPI{
		store: store, connStore: connStore, apprLog: apprLog, audit: audit, triage: triage, gw: gw, conn: conn, passwordDigest: sha256.Sum256([]byte(password)), secret: []byte(secret),
		selfURL: strings.TrimRight(selfURL, "/"), consoleURL: strings.TrimRight(consoleURL, "/"), origins: origins, localAdminAuth: true,
	}
	for _, option := range options {
		if option != nil {
			option(api)
		}
	}
	return api
}

// serverDTO is the legacy self-hosted management transport. Management clients
// key accounts by uuid; the engine's unique key is Name, so uuid == Name.
type serverDTO struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Group       string `json:"group"`
	Transport   string `json:"transport"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	ErrorStatus string `json:"errorStatus"`
	Description string `json:"description"`
	AuthState   string `json:"authState"`
	ConnectURL  string `json:"connectUrl,omitempty"`
	// ReadOnly mirrors Account.ReadOnly for legacy management clients.
	ReadOnly bool `json:"readOnly"`
}

func toDTO(a Account) serverDTO {
	display := a.Label
	if display == "" {
		display = a.Name
	}
	auth := "needs_auth"
	switch {
	case a.AuthMode == "token":
		auth = "token"
	case a.AccessToken != "" || a.RefreshToken != "":
		auth = "connected"
	}
	return serverDTO{
		UUID: a.Name, Name: a.Name, DisplayName: display, Group: a.Group,
		Transport: "http", URL: a.URL, Status: "", ErrorStatus: "NONE", AuthState: auth,
		ReadOnly: a.ReadOnly,
	}
}

func (c *ConsoleAPI) Routes(mux *http.ServeMux) {
	pub := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if c.cors(w, r) {
				return
			}
			fn(w, r)
		}
	}
	sec := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if c.cors(w, r) {
				return
			}
			if !c.authed(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			fn(w, r)
		}
	}
	// Deliberately separate from /api/health: these public probes report only
	// process readiness and never expose account or upstream health details.
	mux.HandleFunc("/healthz", pub(c.handleProbe))
	mux.HandleFunc("/readyz", pub(c.handleProbe))
	mux.HandleFunc("/api/auth", pub(c.handleAuthStatus))
	if c.localAdminAuth {
		mux.HandleFunc("/api/login", pub(c.handleLogin))
	}
	mux.HandleFunc("/api/oauth/callback", pub(c.handleOAuthCallback)) // state-guarded, no bearer
	mux.HandleFunc("/api/gateway", sec(c.handleGateway))
	mux.HandleFunc("/api/health", sec(c.handleHealth))
	mux.HandleFunc("/api/logs", sec(c.handleLogs))
	mux.HandleFunc("/api/logs/{id}", sec(c.handleLogByID))
	mux.HandleFunc("/api/logs/{id}/replay", sec(c.handleLogReplay))
	mux.HandleFunc("/api/logs/{id}/triage", sec(c.handleLogTriage))
	mux.HandleFunc("/api/servers", sec(c.handleServers))
	mux.HandleFunc("/api/servers/{id}", sec(c.handleServerByID))
	mux.HandleFunc("/api/servers/{id}/connect", sec(c.handleConnect))
	mux.HandleFunc("/api/servers/{id}/token", sec(c.handleToken))
	mux.HandleFunc("/api/servers/{id}/tools", sec(c.handleTools))
	mux.HandleFunc("/api/servers/{id}/tools/{tool}", sec(c.handleToolPolicy))
	mux.HandleFunc("/api/connectors", sec(c.handleConnectors))
	mux.HandleFunc("/api/connectors/{slug}", sec(c.handleConnectorBySlug))
	mux.HandleFunc("/api/guardrails/test", sec(c.handleGuardrailTest))
	mux.HandleFunc("/api/config", sec(c.handlePortableConfig))
	mux.HandleFunc("/api/config/import", sec(c.handlePortableConfigImport))
	mux.HandleFunc("/api/approvals", sec(c.handleApprovals))
	mux.HandleFunc("/api/approvals/{id}/approve", sec(func(w http.ResponseWriter, r *http.Request) {
		c.handleApprovalDecision(w, r, "approved")
	}))
	mux.HandleFunc("/api/approvals/{id}/deny", sec(func(w http.ResponseWriter, r *http.Request) {
		c.handleApprovalDecision(w, r, "denied")
	}))
}

// --- virtual connectors: curated tool subsets served at /mcp/{slug} ---

// connectorDTO is what the frontend consumes: the connector definition plus
// its public MCP URL and exposure stats (tool count + tool-definition bytes
// vs. the full aggregated set — the token-savings story).
type connectorDTO struct {
	Slug     string              `json:"slug"`
	Label    string              `json:"label"`
	URL      string              `json:"url"`
	Tools    map[string][]string `json:"tools"`
	Approval map[string][]string `json:"approval"` // account -> BARE tools gated on human approval (⊆ tools)
	Record   bool                `json:"record"`   // flight recorder: capture call payloads on this endpoint
	// Response guardrails (connector-only; the raw /mcp endpoint has none).
	MaxResultBytes       int      `json:"maxResultBytes"` // cap on result TEXT bytes; 0 = off
	Redact               []string `json:"redact"`         // RE2 patterns replaced with "[redacted]" in result text
	DisableInjectionScan bool     `json:"disableInjectionScan"`
	ExposedTools         int      `json:"exposedTools"`
	TotalTools           int      `json:"totalTools"`
	ExposedBytes         int      `json:"exposedBytes"`
	TotalBytes           int      `json:"totalBytes"`
}

func (c *ConsoleAPI) connectorDTO(ctx context.Context, vc VirtualConnector) connectorDTO {
	d := connectorDTO{Slug: vc.Slug, Label: vc.Label, URL: c.selfURL + "/mcp/" + vc.Slug, Tools: vc.Tools, Approval: vc.Approval, Record: vc.Record,
		MaxResultBytes: vc.MaxResultBytes, Redact: vc.Redact, DisableInjectionScan: vc.DisableInjectionScan}
	if d.Tools == nil {
		d.Tools = map[string][]string{}
	}
	if d.Approval == nil {
		d.Approval = map[string][]string{}
	}
	if d.Redact == nil {
		d.Redact = []string{}
	}
	if st, err := c.gw.ConnectorStats(ctx, vc.Slug); err == nil {
		d.ExposedTools, d.TotalTools = st.ExposedTools, st.TotalTools
		d.ExposedBytes, d.TotalBytes = st.ExposedBytes, st.TotalBytes
	}
	return d
}

// connectorsSupported writes the 501 and returns false when the store lacks
// connector persistence (e.g. a custom AccountStore-only implementation).
func (c *ConsoleAPI) connectorsSupported(w http.ResponseWriter) bool {
	if c.connStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connectors not supported by this store"})
		return false
	}
	return true
}

// validateConnectorTools checks every account key against the store. Tool
// names are NOT validated against live toolsets — an allowlist may reference
// tools of an account that is temporarily down; unknown names simply never
// match (same forgiving semantics as DisabledTools).
func (c *ConsoleAPI) validateConnectorTools(tools map[string][]string) (string, bool) {
	for acct := range tools {
		if _, ok := c.store.Account(acct); !ok {
			return "unknown account " + strconv.Quote(acct), false
		}
	}
	return "", true
}

// validateApproval enforces approval ⊆ tools per account: a tool can only
// require approval if the connector exposes it in the first place (exclusion
// from the allowlist already denies — deny is not a policy value).
func validateApproval(approval, tools map[string][]string) (string, bool) {
	for acct, gated := range approval {
		allowed := toSet(tools[acct])
		for _, bare := range gated {
			if !allowed[bare] {
				return "approval tool " + strconv.Quote(bare) + " is not in the allowlist for account " + strconv.Quote(acct), false
			}
		}
	}
	return "", true
}

// pruneApproval drops approval entries no longer covered by tools — used when
// a PUT narrows the allowlist without resubmitting the approval map, so the
// approval ⊆ tools invariant survives without a surprise 400.
func pruneApproval(approval, tools map[string][]string) map[string][]string {
	if len(approval) == 0 {
		return approval
	}
	out := map[string][]string{}
	for acct, gated := range approval {
		allowed := toSet(tools[acct])
		var keep []string
		for _, bare := range gated {
			if allowed[bare] {
				keep = append(keep, bare)
			}
		}
		if len(keep) > 0 {
			out[acct] = keep
		}
	}
	return out
}

// maxResultBytesCeiling caps operator-supplied MaxResultBytes: a "cap" above
// 10MB is almost certainly a typo (and larger than any sane model context),
// so reject it rather than store a value that silently never fires.
const maxResultBytesCeiling = 10 << 20 // 10MB

// validateMaxResultBytes: 0 = off, negative = nonsense, absurd = typo.
func validateMaxResultBytes(n int) (string, bool) {
	if n < 0 {
		return "maxResultBytes must be >= 0 (0 disables the cap)", false
	}
	if n > maxResultBytesCeiling {
		return "maxResultBytes must be <= " + strconv.Itoa(maxResultBytesCeiling) + " (10MB)", false
	}
	return "", true
}

// validateRedact is the validation gate for redact patterns: every pattern
// must compile as RE2 here, at create/update time, so the gateway's
// compileGuards never has to fail a connector rebuild over a bad pattern.
func validateRedact(patterns []string) (string, bool) {
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return "invalid redact pattern " + strconv.Quote(p) + ": " + err.Error(), false
		}
	}
	return "", true
}

func (c *ConsoleAPI) handleConnectors(w http.ResponseWriter, r *http.Request) {
	if !c.connectorsSupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := c.connStore.Connectors(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		out := make([]connectorDTO, len(list))
		for i, vc := range list {
			out[i] = c.connectorDTO(r.Context(), vc)
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req struct {
			Label                string              `json:"label"`
			Slug                 string              `json:"slug"`
			Tools                map[string][]string `json:"tools"`
			Approval             map[string][]string `json:"approval"`
			Record               bool                `json:"record"`
			MaxResultBytes       int                 `json:"maxResultBytes"`
			Redact               []string            `json:"redact"`
			DisableInjectionScan bool                `json:"disableInjectionScan"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		label := strings.TrimSpace(req.Label)
		if label == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
			return
		}
		slug := slugify(req.Slug)
		if slug == "" {
			slug = slugify(label)
		}
		if slug == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug must contain letters or numbers"})
			return
		}
		if msg, ok := c.validateConnectorTools(req.Tools); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if msg, ok := validateApproval(req.Approval, req.Tools); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if msg, ok := validateMaxResultBytes(req.MaxResultBytes); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if msg, ok := validateRedact(req.Redact); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if _, exists := c.connStore.VirtualConnector(r.Context(), slug); exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "connector " + strconv.Quote(slug) + " already exists"})
			return
		}
		if req.Tools == nil {
			req.Tools = map[string][]string{}
		}
		vc := VirtualConnector{Slug: slug, Label: label, Tools: req.Tools, Approval: req.Approval, Record: req.Record,
			MaxResultBytes: req.MaxResultBytes, Redact: req.Redact, DisableInjectionScan: req.DisableInjectionScan}
		if err := c.gw.UpsertConnector(r.Context(), vc); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, c.connectorDTO(r.Context(), vc))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleConnectorBySlug(w http.ResponseWriter, r *http.Request) {
	if !c.connectorsSupported(w) {
		return
	}
	slug := r.PathValue("slug")
	switch r.Method {
	case http.MethodPut:
		vc, ok := c.connStore.VirtualConnector(r.Context(), slug)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		var req struct {
			Label                *string              `json:"label"`
			Tools                *map[string][]string `json:"tools"`
			Approval             *map[string][]string `json:"approval"`
			Record               *bool                `json:"record"`
			MaxResultBytes       *int                 `json:"maxResultBytes"`
			Redact               *[]string            `json:"redact"`
			DisableInjectionScan *bool                `json:"disableInjectionScan"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if req.Label != nil {
			l := strings.TrimSpace(*req.Label)
			if l == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label cannot be empty"})
				return
			}
			vc.Label = l
		}
		if req.Tools != nil {
			tools := *req.Tools
			if msg, ok := c.validateConnectorTools(tools); !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
				return
			}
			if tools == nil {
				tools = map[string][]string{}
			}
			vc.Tools = tools
		}
		if req.Approval != nil {
			// Explicit approval map: must be ⊆ the (possibly just-updated) tools.
			if msg, ok := validateApproval(*req.Approval, vc.Tools); !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
				return
			}
			vc.Approval = *req.Approval
		} else if req.Tools != nil {
			// Tools narrowed without resubmitting approval: prune the stored
			// approval map so the ⊆ invariant holds.
			vc.Approval = pruneApproval(vc.Approval, vc.Tools)
		}
		if req.Record != nil {
			vc.Record = *req.Record
		}
		if req.MaxResultBytes != nil {
			if msg, ok := validateMaxResultBytes(*req.MaxResultBytes); !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
				return
			}
			vc.MaxResultBytes = *req.MaxResultBytes
		}
		if req.Redact != nil {
			if msg, ok := validateRedact(*req.Redact); !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
				return
			}
			vc.Redact = *req.Redact
		}
		if req.DisableInjectionScan != nil {
			vc.DisableInjectionScan = *req.DisableInjectionScan
		}
		// Through the gateway, not the store: persists AND rebuilds the live
		// /mcp/{slug} server so the change is visible immediately.
		if err := c.gw.UpsertConnector(r.Context(), vc); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, c.connectorDTO(r.Context(), vc))
	case http.MethodDelete:
		if _, ok := c.connStore.VirtualConnector(r.Context(), slug); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err := c.gw.DeleteConnector(r.Context(), slug); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- approvals: pending (approval-gated) tool calls awaiting a decision ---

// approvalsSupported writes the 501 and returns false when the store lacks
// the ApprovalLog facet (same pattern as connectorsSupported).
func (c *ConsoleAPI) approvalsSupported(w http.ResponseWriter) bool {
	if c.apprLog == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "approvals not supported by this store"})
		return false
	}
	return true
}

// handleApprovals: GET lists approval records newest-first. ALL records are
// returned (status distinguishes pending from decided history) — the frontend
// filters status == "pending" for actionable rows.
func (c *ConsoleAPI) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if !c.approvalsSupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	calls, err := c.apprLog.PendingCalls(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if calls == nil {
		calls = []PendingCall{}
	}
	writeJSON(w, http.StatusOK, calls)
}

// handleApprovalDecision resolves a parked call via gw.Decide. 404 when the id
// was never recorded, 409 when it exists but is no longer awaiting a decision
// (already approved/denied/expired — or the waiter died with the process).
func (c *ConsoleAPI) handleApprovalDecision(w http.ResponseWriter, r *http.Request, status string) {
	if !c.approvalsSupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if err := c.gw.Decide(r.Context(), id, status); err != nil {
		// Decide only knows "no live waiter" — the audit record tells 404 vs 409.
		if calls, lerr := c.apprLog.PendingCalls(r.Context()); lerr == nil {
			for _, p := range calls {
				if p.ID == id {
					msg := "pending call already decided (status " + strconv.Quote(p.Status) + ")"
					if p.Status == "pending" { // row survived a restart; the in-process waiter did not
						msg = "pending call is no longer waiting (engine restarted?)"
					}
					writeJSON(w, http.StatusConflict, map[string]string{"error": msg})
					return
				}
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending call not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": status})
}

// handleTools: GET lists an account's tools with enabled/disabled + hints;
// PUT { "disabled": [...] } sets the disabled set and re-aggregates live.
func (c *ConsoleAPI) handleTools(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		tools, err := c.gw.ListAccountTools(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, tools)
	case http.MethodPut:
		var req struct {
			Disabled []string `json:"disabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if req.Disabled == nil {
			req.Disabled = []string{}
		}
		if err := c.store.SetDisabledTools(r.Context(), id, req.Disabled); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		c.gw.ReplaceAccount(r.Context(), id) // re-aggregate so /mcp reflects the curation immediately
		tools, _ := c.gw.ListAccountTools(r.Context(), id)
		writeJSON(w, http.StatusOK, tools)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- middleware helpers ---

func (c *ConsoleAPI) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	for _, o := range c.origins {
		if o == origin {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Vary", "Origin")
			break
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func (c *ConsoleAPI) authed(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	if c.hasAdminToken {
		digest := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(digest[:], c.adminTokenDigest[:]) == 1 {
			return true
		}
	}
	return c.localAdminAuth && c.validToken(token)
}

func (c *ConsoleAPI) signToken() string {
	exp := strconv.FormatInt(time.Now().Add(7*24*time.Hour).Unix(), 10)
	return exp + "." + c.mac(exp)
}

func (c *ConsoleAPI) validToken(tok string) bool {
	exp, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > n {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(c.mac(exp)))
}

func (c *ConsoleAPI) mac(msg string) string {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// --- handlers ---

func (c *ConsoleAPI) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"authRequired":      true,
		"localLoginEnabled": c.localAdminAuth,
	})
}

func (c *ConsoleAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	password := sha256.Sum256([]byte(req.Password))
	if subtle.ConstantTimeCompare(password[:], c.passwordDigest[:]) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": c.signToken()})
}

func (c *ConsoleAPI) handleProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ready":   true,
		"service": "synaxis-engine",
		"status":  "ok",
	})
}

func (c *ConsoleAPI) handleGateway(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"connectorUrl": c.selfURL + "/mcp",
		"endpoint":     "mcp",
		"namespace":    "narthex",
		"ready":        true,
	})
}

func (c *ConsoleAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, c.gw.Health(r.Context()))
}

func (c *ConsoleAPI) handleLogs(w http.ResponseWriter, r *http.Request) {
	calls, err := c.gw.RecentCalls(r.Context(), 100)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if calls == nil {
		calls = []CallRecord{}
	}
	writeJSON(w, http.StatusOK, calls)
}

// --- flight recorder: call inspector + replay ---

// auditSupported writes the 501 and returns false when the store lacks the
// AuditSink facet (CallDetail) — same pattern as connectorsSupported. The
// list endpoint stays soft (empty list) for backward compatibility; detail
// and replay are new surfaces and can be honest about the missing facet.
func (c *ConsoleAPI) auditSupported(w http.ResponseWriter) bool {
	if c.audit == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "call detail not supported by this store"})
		return false
	}
	return true
}

// handleLogByID: GET /api/logs/{id} → the full CallRecord including the
// recorded args/result payloads (empty strings mean recording was off).
func (c *ConsoleAPI) handleLogByID(w http.ResponseWriter, r *http.Request) {
	if !c.auditSupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid call id"})
		return
	}
	rec, ok, err := c.gw.CallDetail(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "call not found"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleLogReplay: POST /api/logs/{id}/replay with optional body
// {"force": bool} re-issues the recorded call through the live dispatch path.
// 200 → the NEW CallRecord (decision "replay", payloads included — OK=false
// with an error still means the replay itself ran); 404 unknown id; 409 the
// tool is (or may be) mutating and force was not set — the frontend confirms
// and retries with {"force": true}; 400 the row cannot be replayed (no
// recorded payload, or the account/tool is no longer live).
func (c *ConsoleAPI) handleLogReplay(w http.ResponseWriter, r *http.Request) {
	if !c.auditSupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid call id"})
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	// Existence check up front: Replay folds "unknown id" into a generic
	// error, but the console owes the frontend a clean 404.
	if _, ok, err := c.gw.CallDetail(r.Context(), id); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	} else if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "call not found"})
		return
	}
	rec, err := c.gw.Replay(r.Context(), id, req.Force)
	if err != nil {
		if errors.Is(err, ErrReplayForceRequired) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (c *ConsoleAPI) handleServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		accts := c.store.Accounts()
		out := make([]serverDTO, len(accts))
		for i, a := range accts {
			out[i] = toDTO(a)
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		c.create(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Group       string `json:"group"`
		Transport   string `json:"transport"`
		URL         string `json:"url"`
		BearerToken string `json:"bearerToken"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	friendly := strings.TrimSpace(req.Name)
	name := slugify(friendly)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must contain letters or numbers"})
		return
	}
	if err := upstreamoauth.ValidateUpstreamURL(strings.TrimSpace(req.URL)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be a valid https URL"})
		return
	}
	a := Account{Name: name, Label: friendly, Group: strings.TrimSpace(req.Group), URL: strings.TrimSpace(req.URL), AuthMode: "oauth"}
	if t := strings.TrimSpace(req.BearerToken); t != "" {
		a.AuthMode, a.BearerToken = "token", t
	}
	if err := c.store.Upsert(r.Context(), a); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if a.AuthMode == "token" {
		_, _ = c.gw.AddAccount(r.Context(), name) // aggregate immediately; tools appear live
	}
	writeJSON(w, http.StatusCreated, toDTO(a))
}

func (c *ConsoleAPI) handleServerByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodDelete:
		c.gw.RemoveAccount(id)
		if err := c.store.Delete(r.Context(), id); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		c.update(w, r, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) update(w http.ResponseWriter, r *http.Request, id string) {
	a, ok := c.store.Account(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var req struct {
		DisplayName *string `json:"displayName"`
		Group       *string `json:"group"`
		ReadOnly    *bool   `json:"readOnly"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	label, group := a.Label, a.Group
	if req.DisplayName != nil {
		d := strings.TrimSpace(*req.DisplayName)
		if d == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "displayName cannot be empty"})
			return
		}
		label = d
	}
	if req.Group != nil {
		group = strings.TrimSpace(*req.Group)
	}
	// ponytail: rename changes only the display Label, NOT Name — so Claude's
	// tool prefix (notion_lelapa__) stays stable instead of churning on rename.
	if err := c.store.SetMeta(r.Context(), id, label, group); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if req.ReadOnly != nil {
		if err := c.store.SetReadOnly(r.Context(), id, *req.ReadOnly); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		a.ReadOnly = *req.ReadOnly
	}
	// re-aggregate so tool titles reflect the new label and the registered
	// toolset honors a flipped ReadOnly immediately
	_, _ = c.gw.ReplaceAccount(r.Context(), id)
	a.Label, a.Group = label, group
	writeJSON(w, http.StatusOK, toDTO(a))
}

func (c *ConsoleAPI) handleConnect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := c.store.Account(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	// Optional body selects the connect path. No body / all-empty fields → DCR
	// (RFC 7591 Dynamic Client Registration), the original behavior. If ANY
	// static field is present → static-client path (pre-registered app), which
	// requires clientId AND scope; clientSecret MAY be empty (public client).
	// clientSecret is a credential: never logged, never echoed in a response.
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	clientSecret := strings.TrimSpace(req.ClientSecret)
	scope := strings.TrimSpace(req.Scope)

	var sc *StaticCreds
	if clientID != "" || clientSecret != "" || scope != "" {
		// Static mode requested — enforce the minimum viable set.
		if clientID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clientId is required for a pre-registered OAuth app"})
			return
		}
		if scope == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scope is required for a pre-registered OAuth app"})
			return
		}
		sc = &StaticCreds{ClientID: clientID, ClientSecret: clientSecret, Scope: scope}
	}

	label := a.Label
	if label == "" {
		label = a.Name
	}
	authURL, err := c.conn.StartConnect(r.Context(), a.Name, label, a.Group, a.URL, c.selfURL+"/api/oauth/callback", sc)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"authorizeUrl": authURL})
}

func (c *ConsoleAPI) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Redirect(w, r, c.consoleURL+"/?connect=error", http.StatusFound)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, c.consoleURL+"/?connect=error", http.StatusFound)
		return
	}
	if _, _, err := c.conn.FinishConnect(r.Context(), state, code); err != nil {
		http.Redirect(w, r, c.consoleURL+"/?connect=error", http.StatusFound)
		return
	}
	http.Redirect(w, r, c.consoleURL+"/?connect=ok", http.StatusFound)
}

func (c *ConsoleAPI) handleToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := c.store.Account(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var req struct{ Token string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	a.AuthMode, a.BearerToken = "token", strings.TrimSpace(req.Token)
	if err := c.store.Upsert(r.Context(), a); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	_, _ = c.gw.ReplaceAccount(r.Context(), id)
	writeJSON(w, http.StatusOK, toDTO(a))
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// slugify turns "Notion Lelapa" into "notion_lelapa" — lowercase, non-alnum
// collapsed to single underscores, trimmed.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prev := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prev = false
		} else if !prev {
			b.WriteByte('_')
			prev = true
		}
	}
	return strings.Trim(b.String(), "_")
}
