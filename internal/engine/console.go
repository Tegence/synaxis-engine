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

	"narthex/backend/internal/ratelimit"
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
	connStore        ConnectorStore      // store's connector facet; nil = connectors unsupported (501)
	nsStore          NamespaceStore      // store's endpoint-bundle facet; nil = endpoints unsupported (501)
	apprLog          ApprovalLog         // store's approval facet; nil = approvals unsupported (501)
	audit            AuditSink           // store's audit facet; nil = call detail/replay unsupported (501)
	triage           AuditTriage         // store's triage facet; nil = flagged decisions unsupported (501)
	usage            *UsageGate          // nil = self-hosted/unlimited
	skillStore       SkillStore          // store's skills facet; nil = skills unsupported (501)
	skillFetcher     SkillSourceFetcher  // git-fetch seam for skill-source sync; defaults to gitFetcher
	libraryStore     LibraryStore        // store's portable Library v2 facet; nil = library unsupported (501)
	memoryStore      LibraryMemoryStore  // durable, surface-scoped Library memory facet
	draftGenerator   SkillDraftGenerator // server-side only; nil = creator unavailable (503)
	gw               *Gateway
	conn             connector
	passwordDigest   [sha256.Size]byte
	adminTokenDigest [sha256.Size]byte
	hasAdminToken    bool
	localAdminAuth   bool
	actorVerifier    *PlatformActorVerifier
	revokeOAuth      func(context.Context) error
	secret           []byte
	selfURL          string   // engine's own public base (issuer)
	consoleURL       string   // where to bounce the browser after OAuth
	origins          []string // CORS allowlist (comma-separated CONSOLE_ORIGIN)
	// readinessCheck verifies the durable store backing this Engine. It is
	// intentionally separate from the authenticated account-health endpoint:
	// a readiness probe must not fan out to upstream providers or disclose
	// provider state.
	readinessCheck func(context.Context) error
	// loginThrottle bounds online brute-force attempts against the shared
	// console password. Denial is backoff-by-429, never a lockout: the engine
	// is single-user by design and the administrator must not be lockable.
	loginThrottle *ratelimit.Limiter
	// trustProxyHeaders switches loginThrottle's key from RemoteAddr to the
	// trusted last hop of X-Forwarded-For. See WithTrustProxyHeaders: this
	// must only be enabled behind an operator-controlled reverse proxy.
	trustProxyHeaders bool
	// lifecycleCtx is cancelled before graceful HTTP shutdown begins. /readyz
	// uses it to stop advertising a draining Engine as ready while /healthz
	// remains the small process-liveness probe.
	lifecycleCtx context.Context
	// engineVersion and provisionGeneration are reported verbatim on
	// GET /control/v1/meta. Both are opaque to the Engine: the version is a
	// build label and the generation is a hosted pinning number.
	engineVersion       string
	provisionGeneration int64
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

// WithTrustProxyHeaders switches the login-throttle rate-limit key from
// r.RemoteAddr to the last entry of a present X-Forwarded-For header (see
// ratelimit.ClientIP). Leaving it disabled (the default) preserves the
// original RemoteAddr-only behavior.
//
// Enable this ONLY when the Engine sits directly behind exactly one
// reverse-proxy hop the operator controls (nginx, Caddy, Traefik, Cloudflare
// Tunnel, ...). The Engine binary has no TLS of its own, so a self-hosted
// deployment almost always runs behind such a proxy — without this option,
// every request's RemoteAddr is the proxy's own fixed address, so every real
// client shares one rate-limit bucket and a single attacker can exhaust it to
// lock out the legitimate administrator. Enabling it when the Engine is
// otherwise directly reachable, or behind more than one untrusted hop, lets
// an attacker spoof X-Forwarded-For to pick their own rate-limit key instead.
func WithTrustProxyHeaders(enabled bool) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.trustProxyHeaders = enabled
	}
}

// WithPlatformActorVerifier enables the hosted Platform-to-Engine identity
// boundary. When configured, every protected management request must present
// both the Engine machine token and a valid request-bound Platform assertion.
// Leaving it unset retains self-hosted local-admin compatibility.
func WithPlatformActorVerifier(verifier *PlatformActorVerifier) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.actorVerifier = verifier
	}
}

// WithOAuthRevoker wires the workspace-wide MCP authorization revocation
// operation used by the closed Platform when a member loses Engine access.
func WithOAuthRevoker(revoke func(context.Context) error) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.revokeOAuth = revoke
	}
}

// WithUsageGate exposes the hosted usage report and signed-grant control
// endpoints. Leaving it unset preserves unlimited self-hosted behavior.
func WithUsageGate(gate *UsageGate) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.usage = gate
	}
}

// WithReadinessCheck configures the bounded durable-store check performed by
// the public /readyz probe. A nil check preserves the lightweight local test
// and embedded-server behavior; production supplies a query against the
// token-generation store, which also verifies Postgres connectivity.
func WithReadinessCheck(check func(context.Context) error) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.readinessCheck = check
	}
}

// WithLifecycleContext lets /readyz report an Engine as unavailable as soon
// as shutdown begins. Passing nil deliberately behaves like an uncancelled
// context so option callers cannot accidentally make a newly-created API
// permanently unready.
func WithLifecycleContext(ctx context.Context) ConsoleOption {
	if ctx == nil {
		ctx = context.Background()
	}
	return func(c *ConsoleAPI) {
		c.lifecycleCtx = ctx
	}
}

// WithSkillFetcher overrides the git-fetch seam used by skill-source sync
// (default: gitFetcher, which shells out to the system `git` binary). Tests
// use this to supply a fake fetcher with canned files, so skills console
// tests never touch a real repository or subprocess.
func WithSkillFetcher(f SkillSourceFetcher) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.skillFetcher = f
	}
}

// WithSkillDraftGenerator enables server-side LLM-backed draft creation. The
// generator receives a bounded prompt but no browser credentials, connection
// secrets, or ability to publish/bind a skill. A nil generator deliberately
// leaves POST /api/library/skill-drafts unavailable.
func WithSkillDraftGenerator(generator SkillDraftGenerator) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.draftGenerator = generator
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
	nsStore, _ := store.(NamespaceStore)
	apprLog, _ := store.(ApprovalLog)
	audit, _ := store.(AuditSink)
	triage, _ := store.(AuditTriage)
	skillStore, _ := store.(SkillStore)
	libraryStore, _ := store.(LibraryStore)
	memoryStore, _ := store.(LibraryMemoryStore)
	api := &ConsoleAPI{
		store: store, connStore: connStore, nsStore: nsStore, apprLog: apprLog, audit: audit, triage: triage, skillStore: skillStore, libraryStore: libraryStore, memoryStore: memoryStore, gw: gw, conn: conn, passwordDigest: sha256.Sum256([]byte(password)), secret: []byte(secret),
		selfURL: strings.TrimRight(selfURL, "/"), consoleURL: strings.TrimRight(consoleURL, "/"), origins: origins, localAdminAuth: true, lifecycleCtx: context.Background(),
		loginThrottle: ratelimit.New(10, 5*time.Minute),
		skillFetcher:  newGitFetcher(),
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
	UUID                  string `json:"uuid"`
	Name                  string `json:"name"`       // legacy alias for ToolPrefix
	Namespace             string `json:"namespace"`  // legacy alias for ToolPrefix
	ToolPrefix            string `json:"toolPrefix"` // stable tool/account key
	DisplayName           string `json:"displayName"`
	ConnectionNamespace   string `json:"connectionNamespace"` // display label for legacy clients
	ConnectionNamespaceID string `json:"connectionNamespaceId,omitempty"`
	ConnectionScope       string `json:"connectionScope,omitempty"`
	OwnerSubject          string `json:"ownerSubject,omitempty"`
	Revision              int64  `json:"revision,omitempty"`
	Group                 string `json:"group"` // legacy alias for ConnectionNamespace
	Transport             string `json:"transport"`
	URL                   string `json:"url"`
	Status                string `json:"status"`
	ErrorStatus           string `json:"errorStatus"`
	Description           string `json:"description"`
	AuthState             string `json:"authState"`
	ConnectURL            string `json:"connectUrl,omitempty"`
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
		UUID: a.Name, Name: a.Name, Namespace: a.Name, ToolPrefix: a.Name, DisplayName: display,
		ConnectionNamespace: a.Group, ConnectionNamespaceID: a.ConnectionNamespaceID,
		ConnectionScope: string(a.ConnectionScope), OwnerSubject: a.OwnerSubject, Revision: a.Revision, Group: a.Group,
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
			authorized, ok := c.authorize(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			fn(w, authorized)
		}
	}
	// Deliberately separate from /api/health: these public probes never expose
	// account or upstream health details. /healthz is process liveness, while
	// /readyz verifies the durable store and refuses traffic during draining.
	mux.HandleFunc("/healthz", pub(c.handleLiveness))
	mux.HandleFunc("/readyz", pub(c.handleReadiness))
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
	// Connection namespaces are credential ownership folders. They are wholly
	// distinct from /api/namespaces below, which remains the legacy endpoint
	// bundle API for shared MCP delivery.
	mux.HandleFunc("/api/connection-namespaces", sec(c.handleConnectionNamespaces))
	mux.HandleFunc("/api/connection-namespaces/{id}", sec(c.handleConnectionNamespaceByID))
	mux.HandleFunc("/api/connection-namespaces/{id}/managers", sec(c.handleConnectionNamespaceManagers))
	mux.HandleFunc("/api/connection-namespaces/{id}/managers/{subject}", sec(c.handleConnectionNamespaceManagerBySubject))
	// MCP clients are subject-bound registrations for scoped delivery. The
	// console never mints credentials or accepts an OAuth client ID directly;
	// binding remains in the signed consent path.
	mux.HandleFunc("/api/mcp-clients", sec(c.handleMCPClients))
	mux.HandleFunc("/api/mcp-clients/{id}", sec(c.handleMCPClientByID))
	mux.HandleFunc("/api/mcp-clients/{id}/namespaces", sec(c.handleMCPClientNamespaces))
	mux.HandleFunc("/api/mcp-clients/{id}/oauth-client/reset", sec(c.handleMCPClientOAuthReset))
	mux.HandleFunc("/api/mcp-clients/{id}/revoke", sec(c.handleMCPClientRevoke))
	// /control/v1 is the versioned machine-to-machine contract
	// (docs/CONTROL_V1.md). The routes share the handlers and stores above and
	// differ only at the wire boundary: the same CORS and credential chain as
	// sec, then problem-details failures, an echoed correlation ID, retry
	// convergence, and Idempotency-Key support. Every route added here must be
	// added to the contract document in the same change.
	mux.HandleFunc("/control/v1/meta", c.controlV1(c.handleControlMeta))
	mux.HandleFunc("/control/v1/mcp-clients", c.controlV1(c.handleControlMCPClients))
	mux.HandleFunc("/control/v1/mcp-clients/{id}", c.controlV1(c.handleControlMCPClientByID))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/namespaces", c.controlV1(c.handleControlMCPClientNamespaces))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/oauth-client/reset", c.controlV1(c.handleControlMCPClientOAuthReset))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/revoke", c.controlV1(c.handleControlMCPClientRevoke))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/profile-binding", c.controlV1(c.handleControlMCPClientProfileBinding))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/connection-evidence", c.controlV1(c.handleControlMCPClientConnectionEvidence))
	mux.HandleFunc("/control/v1/mcp-clients/{id}/activation-snapshot", c.controlV1(c.handleControlMCPClientActivationSnapshot))
	mux.HandleFunc("/control/v1/run-correlations", c.controlV1(c.handleControlRunCorrelations))
	// The subject-scoped Library group: a hosting control plane reads one
	// member's owned and granted artifacts, serves an exact version body only
	// under that scope, and manages exact-version grants. The subject travels
	// in X-Synaxis-Subject because a signed actor assertion binds a bare path.
	mux.HandleFunc("/control/v1/library/artifacts", c.controlV1(c.handleControlLibraryArtifacts))
	mux.HandleFunc("/control/v1/library/artifacts/{id}", c.controlV1(c.handleControlLibraryArtifactByID))
	mux.HandleFunc("/control/v1/library/artifacts/{id}/versions/{version}", c.controlV1(c.handleControlLibraryArtifactVersion))
	mux.HandleFunc("/control/v1/library/artifacts/{id}/grants", c.controlV1(c.handleControlLibraryArtifactGrants))
	mux.HandleFunc("/control/v1/library/artifacts/{id}/grants/{grant}/revoke", c.controlV1(c.handleControlLibraryArtifactGrantRevoke))
	mux.HandleFunc("/control/v1/library/recipients", c.controlV1(c.handleControlLibraryRecipients))
	// Any other shape or method under the group reaches the same auth
	// chain rather than Go's plain-text 404, so a wrong method, a bare
	// collection path, or a service-principal path outside its narrow
	// allowlist all converge on one problem-details response.
	mux.HandleFunc("/control/v1/", c.controlV1(c.handleControlNotFound))
	// Skill authoring is intentionally narrower than generic MCP-client
	// management: only an owner/admin can open or revoke a temporary window.
	mux.HandleFunc("/api/mcp-clients/{id}/skill-authoring-lease", sec(c.handleMCPClientSkillAuthoringLease))
	mux.HandleFunc("/api/mcp-clients/{id}/skill-authoring-adoption", sec(c.handleMCPClientSkillAuthoringAdoption))
	mux.HandleFunc("/api/mcp-clients/{id}/skill-authoring-lease/revoke", sec(c.handleMCPClientSkillAuthoringLeaseRevoke))
	mux.HandleFunc("/api/connectors", sec(c.handleConnectors))
	mux.HandleFunc("/api/connectors/{slug}", sec(c.handleConnectorBySlug))
	// Endpoint is the preferred product term for a reusable M:N account
	// bundle. The namespace routes remain exact aliases for rolling upgrades
	// and existing management clients.
	mux.HandleFunc("/api/endpoints", sec(c.handleNamespaces))
	mux.HandleFunc("/api/endpoints/{slug}", sec(c.handleNamespaceBySlug))
	mux.HandleFunc("/api/endpoints/{slug}/accounts/{account}", sec(c.handleNamespaceAccount))
	mux.HandleFunc("/api/namespaces", sec(c.handleNamespaces))
	mux.HandleFunc("/api/namespaces/{slug}", sec(c.handleNamespaceBySlug))
	mux.HandleFunc("/api/namespaces/{slug}/accounts/{account}", sec(c.handleNamespaceAccount))
	mux.HandleFunc("/api/guardrails/test", sec(c.handleGuardrailTest))
	mux.HandleFunc("/api/config", sec(c.handlePortableConfig))
	mux.HandleFunc("/api/config/import", sec(c.handlePortableConfigImport))
	mux.HandleFunc("/api/approvals", sec(c.handleApprovals))
	mux.HandleFunc("/api/oauth/revoke-all", sec(c.handleOAuthRevokeAll))
	// Activation is a deliberately narrow, credential-free control metric. In
	// hosted mode it is reserved for the Platform service actor; it must never
	// become a second way to enumerate connection metadata.
	mux.HandleFunc("/api/activation", sec(c.handleActivation))
	mux.HandleFunc("/api/usage", sec(c.handleUsage))
	mux.HandleFunc("/api/usage/grant", sec(c.handleUsageGrant))
	mux.HandleFunc("/api/approvals/{id}/approve", sec(func(w http.ResponseWriter, r *http.Request) {
		c.handleApprovalDecision(w, r, "approved")
	}))
	mux.HandleFunc("/api/approvals/{id}/deny", sec(func(w http.ResponseWriter, r *http.Request) {
		c.handleApprovalDecision(w, r, "denied")
	}))
	// Skills: versioned procedure files tracked from a git source and
	// delivered through the virtual-connector "carrier" they're attached to.
	// See skills_console.go for handlers/DTOs and skills.go for the domain
	// model and the design decisions made where the report flagged an open
	// question.
	mux.HandleFunc("/api/skill-sources", sec(c.handleSkillSources))
	mux.HandleFunc("/api/skill-sources/{id}", sec(c.handleSkillSourceByID))
	mux.HandleFunc("/api/skill-sources/{id}/sync", sec(c.handleSkillSourceSync))
	mux.HandleFunc("/api/skills", sec(c.handleSkills))
	mux.HandleFunc("/api/skills/{id}", sec(c.handleSkillByID))
	mux.HandleFunc("/api/skills/{id}/versions", sec(c.handleSkillVersions))
	mux.HandleFunc("/api/skills/{id}/checks", sec(c.handleSkillChecks))
	mux.HandleFunc("/api/skills/{id}/pins", sec(c.handleSkillPins))
	mux.HandleFunc("/api/skills/{id}/pins/{slug}", sec(c.handleSkillPinBySlug))
	// Library v2 is deliberately distinct from the legacy /api/skills Git
	// source surface above. Its binding scopes are generic opaque references,
	// never credential-owning connection namespaces.
	mux.HandleFunc("/api/library/resolve", sec(c.handleLibraryResolve))
	// Drafting availability tells the browser which generator paths exist
	// here; a hosted Engine always defers to Platform.
	mux.HandleFunc("/api/library/drafting", sec(c.handleLibraryDrafting))
	mux.HandleFunc("/api/library/skills", sec(c.handleLibrarySkills))
	mux.HandleFunc("/api/library/skills/{id}", sec(c.handleLibrarySkillByID))
	mux.HandleFunc("/api/library/skills/{id}/versions", sec(c.handleLibrarySkillVersions))
	mux.HandleFunc("/api/library/skills/{id}/versions/{versionId}/bundle", sec(c.handleLibrarySkillVersionBundle))
	mux.HandleFunc("/api/library/skills/{id}/versions/{versionId}/files/{path...}", sec(c.handleLibrarySkillVersionFile))
	mux.HandleFunc("/api/library/skills/{id}/bindings", sec(c.handleLibrarySkillBindings))
	mux.HandleFunc("/api/library/skills/{id}/bindings/{binding}", sec(c.handleLibrarySkillBindingByID))
	mux.HandleFunc("/api/library/skills/{id}/evaluations", sec(c.handleLibrarySkillEvaluations))
	mux.HandleFunc("/api/library/skills/{id}/evidence", sec(c.handleLibrarySkillEvidence))
	mux.HandleFunc("/api/library/skill-drafts", sec(c.handleLibrarySkillDrafts))
	// Platform-only handoff for hosted LLM drafting. This is intentionally not
	// an extension of the browser-facing skill-drafts route: the handler
	// requires a verified owner/admin actor assertion and remains outside the
	// Platform browser proxy allowlist.
	mux.HandleFunc("/api/library/skill-drafts/platform-import", sec(c.handleLibraryPlatformSkillDraftImport))
	mux.HandleFunc("/api/library/artifact-drafts", sec(c.handleLibraryArtifactDrafts))
	mux.HandleFunc("/api/library/artifact-drafts/platform-import", sec(c.handleLibraryPlatformArtifactDraftImport))
	mux.HandleFunc("/api/library/artifacts", sec(c.handleLibraryArtifacts))
	mux.HandleFunc("/api/library/artifacts/{id}", sec(c.handleLibraryArtifactByID))
	mux.HandleFunc("/api/library/artifacts/{id}/versions", sec(c.handleLibraryArtifactVersions))
	mux.HandleFunc("/api/library/artifacts/{id}/media/{versionId}", sec(c.handleLibraryArtifactMedia))
	mux.HandleFunc("/api/library/artifacts/{id}/grants", sec(c.handleLibraryArtifactGrants))
	mux.HandleFunc("/api/library/artifacts/{id}/grants/{grant}/revoke", sec(c.handleLibraryArtifactGrantRevoke))
	mux.HandleFunc("/api/library/artifacts/{id}/review", sec(c.handleLibraryArtifactReview))
	mux.HandleFunc("/api/library/artifacts/{id}/publication-candidate", sec(c.handleLibraryPublicationCandidate))
	mux.HandleFunc("/api/library/artifacts/{id}/publication-claim", sec(c.handleLibraryPublicationClaim))
	mux.HandleFunc("/api/library/runs", sec(c.handleLibraryRuns))
	mux.HandleFunc("/api/library/runs/{id}", sec(c.handleLibraryRunByID))
	mux.HandleFunc("/api/library/memories", sec(c.handleLibraryMemories))
	mux.HandleFunc("/api/library/memories/{id}", sec(c.handleLibraryMemoryByID))
	mux.HandleFunc("/api/library/memories/{id}/versions", sec(c.handleLibraryMemoryVersions))
	mux.HandleFunc("/api/library/memories/{id}/review", sec(c.handleLibraryMemoryReview))
	mux.HandleFunc("/api/library/memories/{id}/grants", sec(c.handleLibraryMemoryGrants))
	mux.HandleFunc("/api/library/memories/{id}/grants/{grant}/revoke", sec(c.handleLibraryMemoryGrantRevoke))
	// One-time decide link (MOBI-15): the "decide_url" carried on webhook-v2
	// call.parked events (notify.go) and, later, the approval email/Slack
	// buttons. Deliberately public/unauthenticated — knowledge of the
	// unguessable id (128-bit random hex) is the whole capability, same
	// trust model as a magic link. GET only renders a confirm page; the
	// actual decision requires a POST so an email link-scanner's GET
	// prefetch can never silently approve or deny a call.
	mux.HandleFunc("/a/{id}", pub(c.handleOneTimeDecide))
	mux.HandleFunc("/a/{id}/approve", pub(func(w http.ResponseWriter, r *http.Request) {
		c.handleOneTimeDecideAction(w, r, ApprovalApproved)
	}))
	mux.HandleFunc("/a/{id}/deny", pub(func(w http.ResponseWriter, r *http.Request) {
		c.handleOneTimeDecideAction(w, r, ApprovalDenied)
	}))
}

func (c *ConsoleAPI) handleUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.usage == nil {
		writeJSON(w, http.StatusOK, UsageReport{Mode: "unlimited", Status: "unlimited"})
		return
	}
	report, err := c.usage.Report(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "usage meter unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (c *ConsoleAPI) handleUsageGrant(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.usage == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "hosted usage enforcement is not configured"})
		return
	}
	var req struct {
		Grant string `json:"grant"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUsageGrantBytes+1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || strings.TrimSpace(req.Grant) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid signed grant is required"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid signed grant is required"})
		return
	}
	report, err := c.usage.ApplyGrant(r.Context(), req.Grant)
	if err != nil {
		// Signature/claim/revision details are useful to the trusted control
		// plane but never include the assertion itself or signing material.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (c *ConsoleAPI) handleOAuthRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.revokeOAuth == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "OAuth revocation unavailable"})
		return
	}
	if err := c.revokeOAuth(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "OAuth revocation unavailable"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
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
		if reservedEndpointSlugs[slug] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that slug is reserved"})
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
		if c.nsStore != nil {
			if _, exists := c.nsStore.Namespace(r.Context(), slug); exists {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "endpoint slug " + strconv.Quote(slug) + " is already used by a namespace"})
				return
			}
		}
		if req.Tools == nil {
			req.Tools = map[string][]string{}
		}
		vc := VirtualConnector{Slug: slug, Label: label, Tools: req.Tools, Approval: req.Approval, Record: req.Record,
			MaxResultBytes: req.MaxResultBytes, Redact: req.Redact, DisableInjectionScan: req.DisableInjectionScan}
		if err := c.gw.UpsertConnector(r.Context(), vc); err != nil {
			if errors.Is(err, ErrEndpointCollision) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, c.connectorDTO(r.Context(), vc))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleConnectorBySlug(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
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

// --- endpoint bundles: reusable provider-agnostic account collections ---
//
// Handler names retain "namespace" for source compatibility. Both the preferred
// /api/endpoints routes and legacy /api/namespaces routes call these exact
// handlers, so authentication, validation, CAS, and response schemas cannot
// drift between route families.

type namespaceDTO struct {
	Slug         string   `json:"slug"`
	Label        string   `json:"label"`
	URL          string   `json:"url"`
	Members      []string `json:"members"`
	Generation   string   `json:"generation"`
	Revision     int64    `json:"revision"`
	ExposedTools int      `json:"exposedTools"`
	TotalTools   int      `json:"totalTools"`
}

func (c *ConsoleAPI) namespaceDTO(ctx context.Context, ns Namespace) namespaceDTO {
	members := append([]string(nil), ns.Accounts...)
	if members == nil {
		members = []string{}
	}
	dto := namespaceDTO{
		Slug: ns.Slug, Label: ns.Label, URL: c.selfURL + "/mcp/" + ns.Slug,
		Members: members, Generation: ns.Epoch, Revision: ns.Revision,
	}
	if stats, err := c.gw.NamespaceStats(ctx, ns.Slug); err == nil {
		dto.ExposedTools, dto.TotalTools = stats.ExposedTools, stats.TotalTools
	}
	return dto
}

func (c *ConsoleAPI) namespacesSupported(w http.ResponseWriter) bool {
	if c.nsStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "namespaces not supported by this store"})
		return false
	}
	return true
}

func (c *ConsoleAPI) validateNamespaceAccounts(accounts []string) (string, bool) {
	for _, account := range normalizedNamespaceAccounts(accounts) {
		if _, ok := c.store.Account(account); !ok {
			return "unknown account " + strconv.Quote(account), false
		}
	}
	return "", true
}

func writeNamespaceMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNamespaceExists), errors.Is(err, ErrNamespaceRevision),
		errors.Is(err, ErrEndpointCollision), errors.Is(err, ErrEndpointGeneration):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNamespaceNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrAccountNotFound):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	}
}

func namespacePrecondition(w http.ResponseWriter, generation string, revision int64) (NamespacePrecondition, bool) {
	precondition := NamespacePrecondition{Generation: generation, Revision: revision}
	if precondition.Generation == "" || precondition.Revision < 1 {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "namespace generation and revision precondition required",
		})
		return NamespacePrecondition{}, false
	}
	return precondition, true
}

func (c *ConsoleAPI) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.namespacesSupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := c.nsStore.Namespaces(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		out := make([]namespaceDTO, len(list))
		for i, ns := range list {
			out[i] = c.namespaceDTO(r.Context(), ns)
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req struct {
			Slug    string   `json:"slug"`
			Label   string   `json:"label"`
			Members []string `json:"members"`
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
		if reservedEndpointSlugs[slug] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that slug is reserved"})
			return
		}
		if msg, ok := c.validateNamespaceAccounts(req.Members); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		ns, err := c.gw.CreateNamespace(r.Context(), Namespace{
			Slug: slug, Label: label, Accounts: normalizedNamespaceAccounts(req.Members),
		})
		if err != nil {
			writeNamespaceMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, c.namespaceDTO(r.Context(), ns))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleNamespaceBySlug(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.namespacesSupported(w) {
		return
	}
	slug := r.PathValue("slug")
	current, ok := c.nsStore.Namespace(r.Context(), slug)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "namespace not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, c.namespaceDTO(r.Context(), current))
	case http.MethodPut:
		var req struct {
			Label      *string   `json:"label"`
			Members    *[]string `json:"members"`
			Generation string    `json:"generation"`
			Revision   int64     `json:"revision"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				namespacePrecondition(w, "", 0)
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		precondition, ok := namespacePrecondition(w, req.Generation, req.Revision)
		if !ok {
			return
		}
		if !namespacePreconditionMatches(current, precondition) {
			writeNamespaceMutationError(w, ErrNamespaceRevision)
			return
		}
		label := current.Label
		if req.Label != nil {
			label = strings.TrimSpace(*req.Label)
			if label == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label cannot be empty"})
				return
			}
		}
		members := current.Accounts
		if req.Members != nil {
			members = normalizedNamespaceAccounts(*req.Members)
		}
		if msg, ok := c.validateNamespaceAccounts(members); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		updated, err := c.gw.UpdateNamespace(r.Context(), Namespace{
			Slug: slug, Label: label, Accounts: members,
		}, precondition)
		if err != nil {
			writeNamespaceMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c.namespaceDTO(r.Context(), updated))
	case http.MethodDelete:
		var req NamespacePrecondition
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				namespacePrecondition(w, "", 0)
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		precondition, ok := namespacePrecondition(w, req.Generation, req.Revision)
		if !ok {
			return
		}
		if !namespacePreconditionMatches(current, precondition) {
			writeNamespaceMutationError(w, ErrNamespaceRevision)
			return
		}
		if err := c.gw.DeleteNamespace(r.Context(), slug, precondition); err != nil {
			writeNamespaceMutationError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleNamespaceAccount(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.namespacesSupported(w) {
		return
	}
	slug, account := r.PathValue("slug"), r.PathValue("account")
	current, ok := c.nsStore.Namespace(r.Context(), slug)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "namespace not found"})
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req NamespacePrecondition
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			namespacePrecondition(w, "", 0)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	precondition, ok := namespacePrecondition(w, req.Generation, req.Revision)
	if !ok {
		return
	}
	if !namespacePreconditionMatches(current, precondition) {
		writeNamespaceMutationError(w, ErrNamespaceRevision)
		return
	}
	if _, ok := c.store.Account(account); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown account " + strconv.Quote(account)})
		return
	}
	var (
		ns  Namespace
		err error
	)
	switch r.Method {
	case http.MethodPut:
		ns, err = c.gw.AddNamespaceAccount(r.Context(), slug, account, precondition)
	case http.MethodDelete:
		ns, err = c.gw.RemoveNamespaceAccount(r.Context(), slug, account, precondition)
	}
	if err != nil {
		writeNamespaceMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.namespaceDTO(r.Context(), ns))
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
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	calls, err := c.apprLog.PendingCalls(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "approval records unavailable"})
		return
	}
	out := make([]PendingCall, 0, len(calls))
	for _, call := range calls {
		if c.visibleApproval(r.Context(), actor, call) {
			out = append(out, call)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type approvalDecisionRequest struct {
	Note string `json:"note"`
}

func (c *ConsoleAPI) approvalDecisionActor(r *http.Request) string {
	// The hosted Platform actor is available only after the Ed25519 assertion
	// has been checked against this exact request. Never recover it from raw
	// X-Synaxis-* headers: those are browser-controlled before the proxy strips
	// them and are not an authentication boundary.
	if actor, ok := PlatformActorFromContext(r.Context()); ok {
		return "platform:" + actor.UserID
	}
	if c.machineAuthed(r) {
		return "platform-admin"
	}
	return "local-admin"
}

// handleApprovalDecision resolves a parked call through a durable conditional
// transition. A retry of the same decision is deliberately idempotent; a
// contradictory decision gets 409 and never overwrites the audit history.
func (c *ConsoleAPI) handleApprovalDecision(w http.ResponseWriter, r *http.Request, status string) {
	if !c.approvalsSupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if _, _, ok := c.managedApprovalRecord(w, r, id); !ok {
		return
	}
	var req approvalDecisionRequest
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, int64(maxApprovalNoteBytes)+1024))
		if err := dec.Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid approval decision body"})
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid approval decision body"})
			return
		}
	}
	p, err := c.gw.DecideWithMetadata(r.Context(), id, ApprovalDecision{
		Status: status,
		Actor:  c.approvalDecisionActor(r),
		Note:   req.Note,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrApprovalNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending call not found"})
		case errors.Is(err, ErrApprovalExpired):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "pending call already decided (status \"expired\")"})
		case errors.Is(err, ErrApprovalNotPending):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "pending call already decided (status " + strconv.Quote(p.Status) + ")"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not record approval decision"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"id":            p.ID,
		"status":        p.Status,
		"decided_by":    p.DecidedBy,
		"decision_note": p.DecisionNote,
	})
}

// handleTools: GET lists an account's tools with enabled/disabled + hints;
// PUT { "disabled": [...] } sets the disabled set and re-aggregates live.
func (c *ConsoleAPI) handleTools(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	account, _, ok := c.managedAccount(w, r, id)
	if !ok {
		return
	}
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
		if _, err := c.store.UpdateAccountPolicy(r.Context(), id, accountPolicyPrecondition(account), AccountPolicyMutation{DisabledTools: &req.Disabled}); err != nil {
			writeAccountPolicyMutationError(w, err, "could not update connection policy")
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
	// Keyset cursors for Activity and Library lists use headers rather than
	// query strings deliberately: a hosted Platform-to-Engine actor assertion
	// binds and accepts only a bare path with no query string. These headers
	// therefore cross both the browser and Platform proxy without changing the
	// signed actor path.
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Synaxis-Logs-Before-Ts,X-Synaxis-Logs-Before-Id,X-Synaxis-Library-Cursor,X-Synaxis-Library-Limit")
	w.Header().Set("Access-Control-Expose-Headers", "X-Synaxis-Library-Next-Cursor")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func (c *ConsoleAPI) authed(r *http.Request) bool {
	_, ok := c.authorize(r)
	return ok
}

// authorize is the /api view of the shared authentication chain. The /control
// surface uses authorizeControl directly so it can name the failure class in
// its problem body; both surfaces accept exactly the same credentials.
func (c *ConsoleAPI) authorize(r *http.Request) (*http.Request, bool) {
	authorized, failure := c.authorizeControl(r)
	return authorized, failure == nil
}

func (c *ConsoleAPI) machineAuthed(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	if !c.hasAdminToken {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], c.adminTokenDigest[:]) == 1
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
	// Throttle by RemoteAddr host by default, so the limit cannot be bypassed
	// by spoofing X-Forwarded-For. WithTrustProxyHeaders opts into keying on
	// the trusted last X-Forwarded-For hop instead, for deployments behind an
	// operator-controlled reverse proxy where RemoteAddr is always the proxy.
	if !c.loginThrottle.Allow(ratelimit.ClientIP(r, c.trustProxyHeaders)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
		return
	}
	var req struct{ Password string }
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	password := sha256.Sum256([]byte(req.Password))
	if subtle.ConstantTimeCompare(password[:], c.passwordDigest[:]) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": c.signToken()})
}

const readinessCheckTimeout = 2 * time.Second

// beginProbe applies the common public-probe HTTP contract. It intentionally
// runs before any readiness work so unsupported methods cannot be used to
// trigger a store query.
func beginProbe(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func writeProbe(w http.ResponseWriter, r *http.Request, statusCode int, ready bool, status string) {
	if r.Method == http.MethodHead {
		w.WriteHeader(statusCode)
		return
	}
	writeJSON(w, statusCode, map[string]any{
		"ready":   ready,
		"service": "synaxis-engine",
		"status":  status,
	})
}

// handleLiveness is deliberately inexpensive: it only proves that this HTTP
// process can answer a request. It stays independent from Postgres and from
// the shutdown lifecycle, which lets an orchestrator distinguish a live but
// draining or dependency-unready Engine from a dead process.
func (c *ConsoleAPI) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if !beginProbe(w, r) {
		return
	}
	writeProbe(w, r, http.StatusOK, true, "ok")
}

// readinessContext joins a request cancellation, the Engine lifecycle, and a
// short bounded dependency check. HTTP Server.Shutdown waits for active
// requests rather than cancelling them, so joining lifecycleCtx prevents a
// concurrent /readyz request from returning a stale 200 after draining starts.
func (c *ConsoleAPI) readinessContext(requestCtx context.Context) (context.Context, func()) {
	ctx, cancelRequest := context.WithCancel(requestCtx)
	stopLifecycle := func() bool { return false }
	if c.lifecycleCtx != nil {
		stopLifecycle = context.AfterFunc(c.lifecycleCtx, cancelRequest)
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, readinessCheckTimeout)
	return ctx, func() {
		cancelTimeout()
		stopLifecycle()
		cancelRequest()
	}
}

// handleReadiness verifies the initialized durable store when a check was
// supplied by the Engine. Failure details are kept out of this public endpoint
// so provisioning health probes cannot become a database-error disclosure.
func (c *ConsoleAPI) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if !beginProbe(w, r) {
		return
	}
	if c.lifecycleCtx != nil && c.lifecycleCtx.Err() != nil {
		writeProbe(w, r, http.StatusServiceUnavailable, false, "shutting_down")
		return
	}
	if c.readinessCheck != nil {
		ctx, cancel := c.readinessContext(r.Context())
		err := c.readinessCheck(ctx)
		cancel()
		// Prefer the lifecycle result in the narrow race where shutdown begins
		// while the dependency check is returning.
		if c.lifecycleCtx != nil && c.lifecycleCtx.Err() != nil {
			writeProbe(w, r, http.StatusServiceUnavailable, false, "shutting_down")
			return
		}
		if err != nil {
			writeProbe(w, r, http.StatusServiceUnavailable, false, "unavailable")
			return
		}
	}
	writeProbe(w, r, http.StatusOK, true, "ok")
}

// auditPersistenceReporter is the concrete-store diagnostic facet for the
// durable audit writer. It deliberately stays off the AuditSink interface so
// file-backed development stores simply omit the field.
type auditPersistenceReporter interface {
	AuditPersistenceStats() AuditPersistenceStats
}

func (c *ConsoleAPI) handleGateway(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"connectorUrl":     c.selfURL + "/mcp",
		"oauthCallbackUrl": c.selfURL + "/api/oauth/callback",
		"endpoint":         "mcp",
		"namespace":        "narthex",
		"ready":            true,
	}
	// Audit drop counters make lossy-under-outage auditing visible to the
	// console. Only counts and the static drop-reason category cross this
	// boundary — never LastError, which can carry driver error text.
	if reporter, ok := c.store.(auditPersistenceReporter); ok {
		stats := reporter.AuditPersistenceStats()
		resp["auditPersistence"] = map[string]any{
			"enqueued":       stats.Enqueued,
			"persisted":      stats.Persisted,
			"dropped":        stats.Dropped,
			"failures":       stats.Failures,
			"retries":        stats.Retries,
			"queueDepth":     stats.QueueDepth,
			"lastDropReason": stats.LastDropReason,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *ConsoleAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	health := c.gw.Health(r.Context())
	out := make([]AccountHealth, 0, len(health))
	for _, item := range health {
		account, found := c.store.Account(item.UUID)
		if found && c.canReadAccount(r.Context(), actor, account) {
			out = append(out, publicAccountHealth(item))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// publicAccountHealth is a defense-in-depth boundary for /api/health. Gateway
// creates these rows, but the management API must never depend on a caller
// having remembered to redact a provider error before returning it to a
// browser. Normalize every status into the small safe presentation contract.
func publicAccountHealth(item AccountHealth) AccountHealth {
	item.Status, item.Detail, item.Recovery = healthPresentation(item.Status)
	item.internalErr = nil
	return item
}

// logsPageSize is the fixed page size for both the default (newest) and
// cursor-paged /api/logs reads. Kept in sync by convention with the
// console client's own page-size constant.
const logsPageSize = 100

// maxLogsFetchAttempts bounds how many raw store pages handleLogs will pull
// while backfilling a page short on VISIBLE rows (see below) — at most
// maxLogsFetchAttempts*logsPageSize raw rows read for one request, no matter
// how sparse this actor's visible history is within that window. Without a
// bound, a namespace-scoped operator whose account accounts for a tiny slice
// of a busy shared platform's audit volume could turn every 30s poll into an
// unbounded scan of the whole tool_calls table. The tradeoff: if more than
// maxLogsFetchAttempts*logsPageSize consecutive raw rows are invisible to
// this actor, the response can still come back short of logsPageSize even
// though more visible history exists further back — the same shape of
// staleness this change fixes, just pushed from "triggered by any one
// invisible row in the page" (the reported bug) to "triggered only by a
// deeply skewed run of thousands of consecutive invisible rows" (very
// unlikely for a real namespace's activity mix).
const maxLogsFetchAttempts = 20

// logsBeforeTSHeader and logsBeforeIDHeader carry the Activity "Load older"
// keyset cursor as request headers rather than a ?before_ts=&before_id=
// query string. This is deliberate, not stylistic: the hosted
// Platform-to-Engine actor assertion (actor_assertion.go,
// normalizedActorRequestPath) cryptographically binds and accepts only a
// bare request path with an EMPTY query string — any request carrying one is
// rejected outright (401) before handleLogs ever runs. Platform's reverse
// proxy also forwards the browser's original query string to the Engine
// unchanged while signing only the path, so a query-string cursor cannot be
// made to work without changing that cross-service signing contract. Every
// "operator"-role actor (the exact role this pagination fix targets) is
// authenticated through that hosted path — self-hosted mode never has an
// "operator" — so a query-string cursor would 401 for precisely the actors
// who most need "Load older". Headers are outside the assertion's bound
// claims and pass through the proxy unmodified, so they carry the cursor
// through both self-hosted and hosted deployments alike.
const (
	logsBeforeTSHeader = "X-Synaxis-Logs-Before-Ts"
	logsBeforeIDHeader = "X-Synaxis-Logs-Before-Id"
)

// handleLogs: GET /api/logs — the newest logsPageSize VISIBLE summary rows by
// default. Sending the logsBeforeTSHeader (RFC3339) + logsBeforeIDHeader
// request headers together pages backward from that keyset cursor instead
// (Activity "Load older"), e.g. from the oldest row of a previous page —
// both must be present, or neither. The FileStore audit sink is an
// in-memory ring bounded at 500 rows (see audit.go); paging past that bound
// on a self-hosted file store returns nothing older, even though
// Postgres-backed workspaces retain the full AUDIT_RETENTION_DAYS window.
//
// The store is read in raw pages of logsPageSize, and each raw page is
// visibility-filtered before joining the response. A raw page that mixes
// visible and invisible rows — a normal occurrence for the "operator" role,
// which is scoped to specific accounts via visibleCallPreloaded — would
// otherwise shrink the filtered response below logsPageSize even though more
// visible history sits just past the unfetched remainder. Since the frontend
// infers "more pages exist" purely from the response length equaling
// logsPageSize, that silently ends the "Load older" affordance for exactly
// the scoped, least-privileged actors who most need to page back through
// incident history — no error, no signal, the button just stops appearing.
// So when a raw page comes back full (meaning the store may hold more) but
// the response is still short of logsPageSize, the handler keeps advancing
// the cursor and pulling further raw pages, folding in only the newly
// visible rows, until the response reaches logsPageSize rows, or the store
// is genuinely exhausted (a raw fetch returns fewer than logsPageSize rows),
// or maxLogsFetchAttempts is reached. This preserves the existing
// bare-JSON-array response contract, so the frontend's length-based
// "hasMore" inference becomes correct again rather than needing its own
// signal.
func (c *ConsoleAPI) handleLogs(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	beforeTSRaw := strings.TrimSpace(r.Header.Get(logsBeforeTSHeader))
	beforeIDRaw := strings.TrimSpace(r.Header.Get(logsBeforeIDHeader))

	var cursorTS time.Time
	var cursorID int64
	haveCursor := false
	switch {
	case beforeTSRaw == "" && beforeIDRaw == "":
		// No cursor: the first raw fetch below reads from the newest row via
		// RecentCalls.
	case beforeTSRaw == "" || beforeIDRaw == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "before_ts and before_id headers must be provided together"})
		return
	default:
		beforeTS, parseErr := time.Parse(time.RFC3339, beforeTSRaw)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid before_ts header: must be RFC3339"})
			return
		}
		beforeID, parseErr := strconv.ParseInt(beforeIDRaw, 10, 64)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid before_id header: must be an integer"})
			return
		}
		cursorTS, cursorID = beforeTS, beforeID
		haveCursor = true
	}

	admin := connectionNamespaceAdministrator(actor)
	out := make([]CallRecord, 0, logsPageSize)
	for attempt := 0; attempt < maxLogsFetchAttempts && len(out) < logsPageSize; attempt++ {
		var raw []CallRecord
		var err error
		if haveCursor {
			raw, err = c.gw.RecentCallsBefore(r.Context(), cursorTS, cursorID, logsPageSize)
		} else {
			raw, err = c.gw.RecentCalls(r.Context(), logsPageSize)
		}
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "activity records unavailable"})
			return
		}
		if len(raw) == 0 {
			break
		}

		if admin {
			out = append(out, raw...)
		} else {
			// Operators pay one account list plus one lookup per distinct
			// namespace, not one account+namespace pair per record.
			accountsByName, namespacesByID := c.callVisibilityData(r.Context(), raw)
			for _, call := range raw {
				if visibleCallPreloaded(actor, call, accountsByName, namespacesByID) {
					out = append(out, call)
				}
			}
		}

		last := raw[len(raw)-1]
		cursorTS, cursorID = last.TS, last.ID
		haveCursor = true

		if len(raw) < logsPageSize {
			break // store genuinely exhausted past this point
		}
	}
	if len(out) > logsPageSize {
		out = out[:logsPageSize] // keep newest-first order; the trimmed tail is the next page's cursor
	}
	writeJSON(w, http.StatusOK, out)
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
	rec, _, ok := c.visibleCallRecord(w, r, id)
	if !ok {
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
	// Existence and namespace checks up front: Replay folds "unknown id" into
	// a generic error, while an ungranted record must remain undiscoverable.
	if _, _, ok := c.visibleCallRecord(w, r, id); !ok {
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
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		accts := c.store.Accounts()
		out := make([]serverDTO, 0, len(accts))
		for _, a := range accts {
			if c.canReadAccount(r.Context(), actor, a) {
				out = append(out, toDTO(a))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		c.create(w, r, actor)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// staticCredsFromRequest normalizes the credential-bearing portion of a
// pre-registered OAuth app request. It deliberately returns only a private
// engine value: callers must never include the resulting client secret in a
// management DTO, error response, or log entry.
func staticCredsFromRequest(clientID, clientSecret, scope string, authorizationExtras map[string]string) (*StaticCreds, error) {
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	scope = strings.TrimSpace(scope)
	extras, err := upstreamoauth.ValidateAuthorizationExtras(authorizationExtras)
	if err != nil {
		return nil, err
	}
	if clientID == "" && clientSecret == "" && scope == "" && len(extras) == 0 {
		return nil, nil
	}
	if clientID == "" {
		return nil, errors.New("clientId is required for a pre-registered OAuth app")
	}
	if scope == "" {
		return nil, errors.New("scope is required for a pre-registered OAuth app")
	}
	return &StaticCreds{
		ClientID:            clientID,
		ClientSecret:        clientSecret,
		Scope:               scope,
		AuthorizationExtras: extras,
	}, nil
}

func writeStaticOAuthConfigPersistenceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrConnectAccountDeleted):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
	case errors.Is(err, ErrConnectAccountURLChanged),
		errors.Is(err, ErrConnectAccountReplaced),
		errors.Is(err, ErrConnectAccountMoved),
		errors.Is(err, ErrAccountIncarnation):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; reload and try again"})
	default:
		// Store errors are intentionally not exposed: they may contain driver
		// context, while the incoming request included credential material.
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not save OAuth client configuration"})
	}
}

func (c *ConsoleAPI) create(w http.ResponseWriter, r *http.Request, actor PlatformActor) {
	var req struct {
		Name                  string           `json:"name"`
		Namespace             string           `json:"namespace"`
		ToolPrefix            string           `json:"toolPrefix"`
		ConnectionNamespace   *string          `json:"connectionNamespace"`
		ConnectionNamespaceID *string          `json:"connectionNamespaceId"`
		ConnectionScope       *ConnectionScope `json:"connectionScope"`
		OwnerSubject          *string          `json:"ownerSubject"`
		Group                 *string          `json:"group"`
		Transport             string           `json:"transport"`
		URL                   string           `json:"url"`
		BearerToken           string           `json:"bearerToken"`
		// OAuth app credentials are accepted only on account creation so the
		// Engine holds the static-client configuration before browser consent.
		// They are intentionally omitted from serverDTO and every response.
		OAuthClientID     string `json:"oauthClientId"`
		OAuthClientSecret string `json:"oauthClientSecret"`
		OAuthScope        string `json:"oauthScope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	friendly := strings.TrimSpace(req.Name)
	if friendly == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	toolPrefix := strings.TrimSpace(req.ToolPrefix)
	legacyNamespace := strings.TrimSpace(req.Namespace)
	if toolPrefix != "" && legacyNamespace != "" && slugify(toolPrefix) != slugify(legacyNamespace) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "toolPrefix and namespace must resolve to the same tool prefix"})
		return
	}
	if toolPrefix == "" {
		toolPrefix = legacyNamespace
	}
	if toolPrefix == "" {
		// Legacy clients supplied only name. Keep deriving the stable account
		// key exactly as before so existing integrations and imports continue
		// to work unchanged.
		toolPrefix = friendly
	}
	name := slugify(toolPrefix)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool prefix must contain letters or numbers"})
		return
	}
	upstreamURL := strings.TrimSpace(req.URL)
	if err := upstreamoauth.ValidateUpstreamURL(upstreamURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be a valid https URL"})
		return
	}
	staticCreds, err := staticCredsFromRequest(req.OAuthClientID, req.OAuthClientSecret, req.OAuthScope, nil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateStaticCredsForUpstream(staticCreds, upstreamURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if staticCreds != nil && strings.TrimSpace(req.BearerToken) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pre-registered OAuth credentials cannot be used with a bearer token"})
		return
	}
	if req.ConnectionNamespace != nil && req.Group != nil &&
		strings.TrimSpace(*req.ConnectionNamespace) != strings.TrimSpace(*req.Group) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connectionNamespace and group must match when both are provided"})
		return
	}
	connectionNamespace := ""
	if req.ConnectionNamespace != nil {
		connectionNamespace = strings.TrimSpace(*req.ConnectionNamespace)
	} else if req.Group != nil {
		connectionNamespace = strings.TrimSpace(*req.Group)
	}
	namespaceID := ""
	if req.ConnectionNamespaceID != nil {
		namespaceID = strings.TrimSpace(*req.ConnectionNamespaceID)
	}
	if connectionNamespace == "" && namespaceID == "" && actor.Role != "operator" {
		connectionNamespace = "General"
	}
	scope := ConnectionScopeShared
	if req.ConnectionScope != nil {
		var scopeErr error
		scope, scopeErr = normalizedConnectionScope(*req.ConnectionScope)
		if scopeErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connection scope"})
			return
		}
	}
	ownerSubject := ""
	if req.OwnerSubject != nil {
		ownerSubject = strings.TrimSpace(*req.OwnerSubject)
	}
	if actor.Role == "operator" {
		// An invited operator starts with a personal credential by default. A
		// shared credential is an explicit exception: it must name an existing
		// durable namespace for which this actor has a manager grant. This lets a
		// namespace owner delegate a team folder without turning every operator
		// into a workspace-wide connection administrator.
		if req.ConnectionScope == nil {
			scope = ConnectionScopePersonal
		}
		switch scope {
		case ConnectionScopePersonal:
			if ownerSubject != "" && ownerSubject != actor.UserID {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "a personal connection must be owned by its creator"})
				return
			}
			ownerSubject = actor.UserID
		case ConnectionScopeShared:
			// A label can be minted by an old console during a rolling upgrade;
			// it is not proof of a pre-existing delegated boundary. Require the
			// opaque ID so a shared connection is never created merely by typing a
			// new folder name.
			if namespaceID == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "choose a managed connection namespace before creating a shared connection"})
				return
			}
		case ConnectionScopeService:
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "operators may not create service connections"})
			return
		}
		if connectionNamespace != "" && namespaceID == "" {
			// Do not let the legacy label path create a folder on behalf of an
			// invited operator. Their Personal namespace is created automatically;
			// every other destination must be an already-delegated durable ID.
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "use your automatic Personal namespace or select a delegated connection namespace by ID"})
			return
		}
	}
	if scope == ConnectionScopePersonal && ownerSubject == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ownerSubject is required for a personal connection"})
		return
	}
	if scope != ConnectionScopePersonal {
		ownerSubject = ""
	}
	var namespace ConnectionNamespace
	if actor.Role == "operator" && scope == ConnectionScopePersonal && namespaceID == "" && connectionNamespace == "" {
		namespace, err = c.defaultPersonalConnectionNamespace(r.Context(), actor)
	} else {
		// A manager grant permits an operator to use an existing folder, never
		// to mint one. This also closes legacy-label paths that could otherwise
		// turn a personal creation into a future shared/root authority boundary.
		createIfMissing := actor.Role != "operator"
		namespace, err = c.resolveManagedConnectionNamespace(
			r.Context(), actor, namespaceID, connectionNamespace, createIfMissing,
		)
	}
	if err != nil {
		writeConnectionNamespaceResolutionError(w, err)
		return
	}
	a := Account{
		Name:                  name,
		Label:                 friendly,
		Group:                 namespace.Label,
		URL:                   upstreamURL,
		AuthMode:              "oauth",
		ConnectionNamespaceID: namespace.ID,
		ConnectionScope:       scope,
		OwnerSubject:          ownerSubject,
	}
	if staticCreds != nil {
		a.ClientID = staticCreds.ClientID
		a.ClientSecret = staticCreds.ClientSecret
		a.Scope = staticCreds.Scope
	}
	if t := strings.TrimSpace(req.BearerToken); t != "" {
		a.AuthMode, a.BearerToken = "token", t
	}
	if err := c.store.Create(r.Context(), a); err != nil {
		if errors.Is(err, ErrAccountExists) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "tool prefix " + strconv.Quote(name) + " already exists; choose a unique toolPrefix"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not save connection"})
		return
	}
	created, found := c.store.Account(name)
	if !found {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "connection could not be read after creation"})
		return
	}
	if a.AuthMode == "token" {
		_, _ = c.gw.AddAccount(r.Context(), name) // aggregate immediately; tools appear live
	}
	writeJSON(w, http.StatusCreated, toDTO(created))
}

func (c *ConsoleAPI) handleServerByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, actor, ok := c.managedAccount(w, r, id)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := c.store.Delete(r.Context(), id, a.IncarnationID, a.Revision); err != nil {
			if errors.Is(err, ErrAccountIncarnation) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; reload and try again"})
				return
			}
			if errors.Is(err, ErrConnectionNamespaceRevision) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; reload and try again"})
				return
			}
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not delete connection"})
			return
		}
		c.gw.RemoveAccount(id, a.IncarnationID)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		c.update(w, r, a, actor)
	default:
		w.Header().Set("Allow", "PATCH, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) update(w http.ResponseWriter, r *http.Request, a Account, actor PlatformActor) {
	var req struct {
		DisplayName           *string          `json:"displayName"`
		ConnectionNamespace   *string          `json:"connectionNamespace"`
		ConnectionNamespaceID *string          `json:"connectionNamespaceId"`
		ConnectionScope       *ConnectionScope `json:"connectionScope"`
		OwnerSubject          *string          `json:"ownerSubject"`
		Revision              *int64           `json:"revision"`
		Group                 *string          `json:"group"`
		ReadOnly              *bool            `json:"readOnly"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	label := a.Label
	labelPresent := req.DisplayName != nil
	namespacePresent := req.ConnectionNamespaceID != nil || req.ConnectionNamespace != nil || req.Group != nil
	assignmentPresent := namespacePresent || req.ConnectionScope != nil || req.OwnerSubject != nil
	if req.DisplayName != nil {
		d := strings.TrimSpace(*req.DisplayName)
		if d == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "displayName cannot be empty"})
			return
		}
		label = d
	}
	if req.ConnectionNamespace != nil && req.Group != nil &&
		strings.TrimSpace(*req.ConnectionNamespace) != strings.TrimSpace(*req.Group) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connectionNamespace and group must match when both are provided"})
		return
	}
	legacyNamespace := ""
	if req.ConnectionNamespace != nil {
		legacyNamespace = strings.TrimSpace(*req.ConnectionNamespace)
	} else if req.Group != nil {
		legacyNamespace = strings.TrimSpace(*req.Group)
	}
	requestedNamespaceID := ""
	if req.ConnectionNamespaceID != nil {
		requestedNamespaceID = strings.TrimSpace(*req.ConnectionNamespaceID)
	}
	// ponytail: rename changes only the display Label, NOT Name — so Claude's
	// tool prefix (tegence_notion__) stays stable instead of churning on rename.
	// Re-read immediately before mutating. This retains omitted fields and,
	// more importantly, prevents a stale manager from overwriting an ownership
	// transition which completed between the initial authorization check and
	// this request body being parsed.
	current, exists := c.store.Account(a.Name)
	if !exists || !c.canManageAccount(r.Context(), actor, current) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return
	}
	a = current
	if !labelPresent {
		label = a.Label
	}
	if assignmentPresent {
		targetID := a.ConnectionNamespaceID
		if actor.Role == "operator" && requestedNamespaceID == "" && legacyNamespace != "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "select a delegated connection namespace by ID"})
			return
		}
		if requestedNamespaceID != "" || legacyNamespace != "" {
			namespace, err := c.resolveManagedConnectionNamespace(
				r.Context(), actor, requestedNamespaceID, legacyNamespace,
				actor.Role != "operator",
			)
			if err != nil {
				writeConnectionNamespaceResolutionError(w, err)
				return
			}
			targetID = namespace.ID
		}
		scope := a.ConnectionScope
		if req.ConnectionScope != nil {
			var scopeErr error
			scope, scopeErr = normalizedConnectionScope(*req.ConnectionScope)
			if scopeErr != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connection scope"})
				return
			}
		}
		ownerSubject := a.OwnerSubject
		if req.OwnerSubject != nil {
			ownerSubject = strings.TrimSpace(*req.OwnerSubject)
		}
		if scope == ConnectionScopePersonal && ownerSubject == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ownerSubject is required for a personal connection"})
			return
		}
		if scope != ConnectionScopePersonal {
			ownerSubject = ""
		}
		if !connectionNamespaceAdministrator(actor) &&
			(scope != a.ConnectionScope || ownerSubject != a.OwnerSubject) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "only a workspace administrator may change connection scope"})
			return
		}
		if targetID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connection namespace is required"})
			return
		}
		target, found := c.connectionNamespaceStore()
		if !found {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connection namespaces are not supported by this store"})
			return
		}
		ns, found := target.ConnectionNamespace(r.Context(), targetID)
		if !found || !c.canManageConnectionNamespace(actor, ns) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace access is not permitted"})
			return
		}
		expectedRevision := a.Revision
		if req.Revision != nil {
			expectedRevision = *req.Revision
		}
		if expectedRevision < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision must be positive"})
			return
		}
		updated, err := c.gw.MoveAccountToConnectionNamespace(r.Context(), a.Name, a.IncarnationID, AccountConnectionAssignment{
			ConnectionNamespaceID: ns.ID,
			Scope:                 scope,
			OwnerSubject:          ownerSubject,
		}, expectedRevision)
		if err != nil {
			switch {
			case errors.Is(err, ErrConnectionNamespaceRevision), errors.Is(err, ErrAccountIncarnation):
				writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; refresh and try again"})
			case errors.Is(err, ErrConnectionNamespaceNotFound), errors.Is(err, ErrAccountNotFound):
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection or namespace not found"})
			case errors.Is(err, ErrInvalidConnectionScope):
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connection assignment"})
			default:
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not move connection"})
			}
			return
		}
		a = updated
	}
	if labelPresent || req.ReadOnly != nil {
		mutation := AccountPolicyMutation{ReadOnly: req.ReadOnly}
		if labelPresent {
			mutation.Label = &label
		}
		updated, err := c.store.UpdateAccountPolicy(r.Context(), a.Name, accountPolicyPrecondition(a), mutation)
		if err != nil {
			writeAccountPolicyMutationError(w, err, "could not update connection")
			return
		}
		a = updated
	}
	// A namespace-only move changes account ownership metadata, not live tool
	// identity or policy. Label/read-only fields always trigger reaggregation,
	// even when their persisted values already match: that makes retrying a
	// previous upstream failure repair the stale live cache.
	if labelPresent || req.ReadOnly != nil {
		if _, err := c.gw.ReplaceAccount(r.Context(), a.Name); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	}
	if persisted, found := c.store.Account(a.Name); found {
		a = persisted
	}
	writeJSON(w, http.StatusOK, toDTO(a))
}

func (c *ConsoleAPI) handleConnect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, _, ok := c.managedAccount(w, r, id)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Optional body selects the connect path. A no-body request reuses a static
	// client that was safely saved with the account, if one exists; otherwise it
	// takes the legacy RFC 7591 DCR path. If any static field or provider
	// authorization extra is present, this request supplies a pre-registered
	// client and is durably saved before browser authorization begins. The client
	// secret is credential material: it is never logged or echoed in a response.
	var req struct {
		ClientID            string            `json:"clientId"`
		ClientSecret        string            `json:"clientSecret"`
		Scope               string            `json:"scope"`
		AuthorizationExtras map[string]string `json:"authorizationExtras"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	sc, err := staticCredsFromRequest(req.ClientID, req.ClientSecret, req.Scope, req.AuthorizationExtras)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// A reauthorization has no browser-supplied credentials. Resolve the
	// existing static client here too, so a Gmail connection with a missing
	// confidential-client secret fails clearly before starting OAuth.
	if err := validateStaticCredsForUpstream(effectiveStaticCreds(sc, a, true, a.URL), a.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if sc != nil {
		configStore, ok := c.store.(StaticOAuthConfigStore)
		if !ok {
			// Do not begin a static OAuth flow unless its retry-critical client
			// configuration can be persisted. Falling back to DCR here would
			// silently break Gmail and other non-DCR providers after cancellation.
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "static OAuth configuration is not supported by this store"})
			return
		}
		persisted, err := configStore.SaveStaticOAuthConfig(r.Context(), a.Name, oauthCompletionPreconditionForAccount(a), StaticOAuthConfig{
			ClientID:     sc.ClientID,
			ClientSecret: sc.ClientSecret,
			Scope:        sc.Scope,
		})
		if err != nil {
			writeStaticOAuthConfigPersistenceError(w, err)
			return
		}
		a = persisted
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
		http.Redirect(w, r, c.consoleURL+"/?connect="+oauthConnectReturnState(err), http.StatusFound)
		return
	}
	http.Redirect(w, r, c.consoleURL+"/?connect=ok", http.StatusFound)
}

// oauthConnectReturnState maps only our durable stale-account outcomes to a
// safe recovery instruction. It deliberately never exposes an upstream OAuth
// provider response or credential detail in a browser redirect.
func oauthConnectReturnState(err error) string {
	switch {
	case errors.Is(err, ErrConnectAccountDeleted),
		errors.Is(err, ErrConnectAccountURLChanged),
		errors.Is(err, ErrConnectAccountReplaced),
		errors.Is(err, ErrConnectAccountMoved),
		errors.Is(err, ErrAccountIncarnation):
		return "changed"
	default:
		return "error"
	}
}

func (c *ConsoleAPI) handleToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, _, ok := c.managedAccount(w, r, id)
	if !ok {
		return
	}
	var req struct{ Token string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	updated, err := c.store.SetBearerToken(r.Context(), a.Name, a.IncarnationID, strings.TrimSpace(req.Token), a.Revision)
	if err != nil {
		switch {
		case errors.Is(err, ErrAccountNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		case errors.Is(err, ErrConnectionNamespaceRevision), errors.Is(err, ErrAccountIncarnation):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; refresh and try again"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not save connection token"})
		}
		return
	}
	_, _ = c.gw.ReplaceAccount(r.Context(), updated.Name)
	writeJSON(w, http.StatusOK, toDTO(updated))
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// reservedEndpointSlugs may never name a shared connector or endpoint bundle:
// `/mcp/clients/{slug}` is the subject-bound MCP client prefix — sharing the
// prefix would invite routing confusion.
var reservedEndpointSlugs = map[string]bool{"clients": true}

// slugify turns "Notion Tegence" into "notion_tegence" — lowercase, non-alnum
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
