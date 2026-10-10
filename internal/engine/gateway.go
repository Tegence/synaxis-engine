package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/upstreamoauth"
)

// Gateway aggregates every account's MCP tools into one MCP server (the
// MetaMCP replacement). One bad account is skipped, not fatal — and each
// upstream carries the refresh-and-redial guarantee from upstream.go.
type Gateway struct {
	store AccountStore
	mcp   *server.MCPServer
	audit AuditSink  // optional; records every tool call
	usage *UsageGate // optional; nil keeps self-hosted Engines quota-unlimited

	mu         sync.Mutex
	endpointMu sync.Mutex              // serializes connector/namespace slug mutations
	byAcct     map[string][]string     // account name -> registered (prefixed) tool names
	cached     map[string][]cachedTool // account name -> tools (post-rewrite) + handlers
	// projectedIncarnations binds every name-keyed live cache/root projection to
	// the immutable account row that produced it. Delete/recreate may reuse the
	// visible tool prefix, but stale aggregation/removal work may not cross this
	// boundary.
	projectedIncarnations map[string]string
	connectors            map[string]*connectorServer // slug -> per-connector MCP server
	// clientEndpoints is deliberately separate from connectors: the path
	// namespace is /mcp/clients/{slug}, not the shared /mcp/{slug} namespace.
	// Each endpoint is bound to one durable MCPClient subject and includes only
	// the connection-namespace grants held by that registration.
	clientEndpoints map[string]*connectorServer // slug -> subject-bound MCP server
	// projectionFailed records that the last RefreshConnectors could not read
	// durable state, so it is retried; projected records that one succeeded.
	// Together they are ProjectionReady.
	projectionFailed atomic.Bool
	projected        atomic.Bool
	refreshMu        map[string]*sync.Mutex // per-account refresh serialization
	// Health-alert state, owned by the watch loop (see evalAlerts). alertState
	// maps account -> status of its outstanding down alert; nil until loaded
	// from a HealthAlertStore. failStreak is deliberately in-memory only: a
	// restart must not count toward a transient-failure alert.
	alertMu    sync.Mutex
	alertState map[string]string
	failStreak map[string]int
	webhook    string // optional alert webhook URL
	consoleURL string // linked in approval webhook messages
	publicURL  string // this Engine's own public base; builds decide_url (see notify.go)
	// platformEventsURL/platformEventsToken: hosted-only Platform ingest
	// target + the shared admin-token credential (see SetPlatformEvents).
	platformEventsURL   string
	platformEventsToken string
	workspaceID         string // SYNAXIS_WORKSPACE_ID; empty for self-hosted (see notify_slack.go)

	// revokeResource is the legacy path-only OAuth cleanup hook. The
	// epoch-aware hook is used in production so cleanup cannot remove grants
	// minted for a newly recreated endpoint with the same slug.
	revokeResource      func(resourcePath string)
	revokeResourceEpoch func(resourcePath, retiringEpoch string)

	// Flight recorder knobs (set once at startup, before serving).
	recordDefault bool          // record payloads for calls on the default /mcp endpoint
	retention     time.Duration // purge audit rows older than this in the watch tick (0 = never)

	// Approval manager (in-process; the store row is the audit record).
	approveMu       sync.Mutex
	approveCh       map[string]chan string // pending approval id -> decision channel
	approvalTimeout time.Duration          // wait budget per approval (0 = default)

	// listTools is a test seam; nil means "dial the upstream" (production).
	listTools func(ctx context.Context, a Account) ([]mcp.Tool, error)
	// healthProbeTimeout bounds one control-plane tools/list observation. It is
	// intentionally separate from an MCP tool invocation timeout: health must
	// degrade quickly without shortening legitimate provider work.
	healthProbeTimeout time.Duration
	healthProbeMu      sync.Mutex
	// healthProbes tracks the underlying work rather than its caller contexts.
	// A cancellation-ignorant transport must not accumulate one stranded
	// goroutine per dashboard poll. The key includes an opaque credential /
	// upstream-config generation so a successful reauthorization can supersede
	// a stranded old probe. Per account identity, the small fixed limit below
	// keeps repeated reconfigurations from becoming a goroutine storm too.
	healthProbes map[string]*healthProbeFlight
	// healthCacheTTL bounds the console read-path cache below. A field (not the
	// const directly) so tests can shorten expiry, mirroring healthProbeTimeout.
	healthCacheTTL time.Duration
	// healthCacheMu guards only healthCache — deliberately not g.mu, so the
	// read cache introduces no new lock ordering.
	healthCacheMu sync.Mutex
	// healthCache holds the last completed probe row per account identity,
	// tagged with the credential generation that produced it. A credential or
	// endpoint change yields a new generation and therefore a cache miss, so
	// the console recovery flow still sees a live probe after a repair.
	healthCache map[string]cachedAccountHealth
	// refreshTokens is a test seam; nil uses upstreamoauth.Refresh.
	refreshTokens func(context.Context, *upstreamoauth.Metadata, string, string, string) (*upstreamoauth.Tokens, error)
	// beforeAccountDispatch is a test seam used to deterministically exercise
	// ownership-move races after a handler has passed its first snapshot check
	// but before it can dial the upstream.
	beforeAccountDispatch func()
}

// cachedTool is one registered tool (prefixed name, rewritten title) plus the
// exact handler closure registered on the main /mcp server — connector servers
// reuse it so audit/refresh behavior is identical on every endpoint.
type cachedTool struct {
	tool                 mcp.Tool
	sourceName           string // stable upstream bare name; tool.Name may be an operator alias
	accountIncarnationID string
	// accountRevision binds this cached dispatch closure to the credential's
	// ownership generation.  A namespace/scope/owner move keeps the stable
	// account name and incarnation intentionally, but increments Revision; an
	// old handler must therefore fail closed rather than send a request using
	// the newly reassigned credential.
	accountRevision int64
	accountURL      string
	handler         server.ToolHandlerFunc
}

// SetAlertWebhook configures where account-down/recovered alerts are POSTed.
func (g *Gateway) SetAlertWebhook(url string) { g.webhook = url }

func NewGateway(store AccountStore, mcpServer *server.MCPServer) *Gateway {
	return &Gateway{
		store:                 store,
		mcp:                   mcpServer,
		byAcct:                map[string][]string{},
		cached:                map[string][]cachedTool{},
		projectedIncarnations: map[string]string{},
		connectors:            map[string]*connectorServer{},
		clientEndpoints:       map[string]*connectorServer{},
		healthProbeTimeout:    defaultHealthProbeTimeout,
		healthCacheTTL:        defaultHealthCacheTTL,
		healthProbes:          map[string]*healthProbeFlight{},
		healthCache:           map[string]cachedAccountHealth{},
	}
}

// SetAudit attaches an audit sink so tool calls are recorded.
func (g *Gateway) SetAudit(a AuditSink) { g.audit = a }

// SetRecordPayloads opts the DEFAULT /mcp endpoint into payload recording
// (connector endpoints carry their own per-connector Record flag). Wired from
// ENGINE_RECORD_PAYLOADS in main.
func (g *Gateway) SetRecordPayloads(on bool) { g.recordDefault = on }

// SetAuditRetention sets how long audit rows are kept; the watch tick deletes
// older rows on stores with the AuditPurger facet. 0 disables purging. Wired
// from AUDIT_RETENTION_DAYS in main.
func (g *Gateway) SetAuditRetention(d time.Duration) { g.retention = d }

// RecentCalls returns the most recent tool-call records (for the console).
// Summary-only: Args/Result are always empty here — use CallDetail.
func (g *Gateway) RecentCalls(ctx context.Context, limit int) ([]CallRecord, error) {
	if g.audit == nil {
		return nil, nil
	}
	return g.audit.RecentCalls(ctx, limit)
}

// RecentCallsBefore pages backward from a keyset cursor (Activity "Load
// older") — same nil-audit fallback as RecentCalls.
func (g *Gateway) RecentCallsBefore(ctx context.Context, beforeTS time.Time, beforeID int64, limit int) ([]CallRecord, error) {
	if g.audit == nil {
		return nil, nil
	}
	return g.audit.RecentCallsBefore(ctx, beforeTS, beforeID, limit)
}

// CallDetail returns one full audit record including recorded payloads.
func (g *Gateway) CallDetail(ctx context.Context, id int64) (CallRecord, bool, error) {
	if g.audit == nil {
		return CallRecord{}, false, nil
	}
	return g.audit.CallDetail(ctx, id)
}

// AccountHealth is a live per-account status for the console.
type AccountHealth struct {
	UUID   string `json:"uuid"` // = account name (the console keys by this)
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Recovery is a stable, safe action identifier for the management UI.
	// It deliberately carries no provider response or transport diagnostic.
	// Current values are "connect", "reauthorize", and "retry".
	Recovery  string `json:"recovery,omitempty"`
	ToolCount int    `json:"toolCount"`
	LatencyMs int64  `json:"latencyMs"`
	CheckedAt string `json:"checkedAt"`

	// internalErr is retained only while the in-process watcher evaluates the
	// result. It must never leave the Engine: upstream error strings can expose
	// implementation details and occasionally provider-controlled content.
	internalErr error
}

const (
	healthStatusOK          = "ok"
	healthStatusNeedsAuth   = "needs_auth"
	healthStatusAuthExpired = "auth_expired"
	healthStatusTimeout     = "timeout"
	healthStatusUnreachable = "unreachable"

	healthRecoveryConnect     = "connect"
	healthRecoveryReauthorize = "reauthorize"
	healthRecoveryRetry       = "retry"

	// A health check is a control-plane observation, not a tool call. Keep its
	// budget well below the platform proxy timeout and the user-configurable
	// MCP call ceiling so one unavailable provider cannot hold the console or
	// watcher hostage.
	defaultHealthProbeTimeout = 10 * time.Second

	// defaultHealthCacheTTL bounds how long the console read path may serve a
	// completed probe result before re-probing. It exists to deduplicate the
	// N-viewers × M-accounts dashboard fan-out, not to stretch freshness; the
	// watch loop bypasses the cache so alerting always sees live probes.
	defaultHealthCacheTTL = 30 * time.Second
)

// upstreamFor builds a live Upstream for an account, wiring Token + Refresh
// against the store (refreshed tokens are persisted, and a rotated refresh
// token is re-read from the store on each refresh).
func (g *Gateway) upstreamFor(a Account) *Upstream {
	incarnationID := a.IncarnationID
	revision := a.Revision
	credential := func() (string, error) {
		current, ok := g.store.Account(a.Name)
		if !ok || incarnationID == "" || revision < 1 || current.IncarnationID != incarnationID || current.Revision != revision || !equalAccountSnapshotURL(current.URL, a.URL) {
			return "", ErrAccountIncarnation
		}
		if current.AuthMode == "token" {
			return current.BearerToken, nil
		}
		return current.AccessToken, nil
	}
	up := &Upstream{
		Name:       a.Name,
		URL:        a.URL,
		Credential: credential,
		Available: func() bool {
			_, err := credential()
			return err == nil
		},
		Token: func() string {
			token, _ := credential()
			return token
		},
	}
	if a.AuthMode == "oauth" && a.RefreshToken != "" {
		name := a.Name
		// Both reactive (on-401) and proactive (refresh-ahead) refresh route
		// through refreshAccount, which serializes per account so two refreshes
		// never burn the same rotating token (the bug that revokes the family).
		up.Refresh = func(ctx context.Context) error { return g.refreshAccount(ctx, name, incarnationID) }
	}
	return up
}

func (g *Gateway) refreshLock(name string) *sync.Mutex {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refreshMu == nil {
		g.refreshMu = map[string]*sync.Mutex{}
	}
	mu, ok := g.refreshMu[name]
	if !ok {
		mu = &sync.Mutex{}
		g.refreshMu[name] = mu
	}
	return mu
}

// refreshAccountTimeout bounds one provider refresh plus its persistence.
const refreshAccountTimeout = 30 * time.Second

// refreshAccount refreshes one OAuth account's tokens and persists them, under
// a per-account lock. Used by both the on-401 path and refresh-ahead.
func (g *Gateway) refreshAccount(ctx context.Context, name, expectedIncarnationID string) error {
	mu := g.refreshLock(name)
	mu.Lock()
	defer mu.Unlock()
	// A caller already gone (shutdown, a disconnected client) starts nothing.
	if err := ctx.Err(); err != nil {
		return err
	}
	// Providers that rotate refresh tokens spend the old one the moment they
	// accept the request. A caller that gives up once it is in flight (a
	// client disconnecting from a tool call, SIGTERM at scale-in) must not
	// abort between that and storing the replacement, or the account is dead
	// until reconnected.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshAccountTimeout)
	defer cancel()
	a, ok := g.store.Account(name)
	if !ok || expectedIncarnationID == "" || a.IncarnationID != expectedIncarnationID {
		return ErrAccountIncarnation
	}
	if a.AuthMode != "oauth" || a.RefreshToken == "" {
		return nil
	}
	meta := &upstreamoauth.Metadata{TokenEndpoint: a.TokenEndpoint, Resource: a.Resource}
	refresh := g.refreshTokens
	if refresh == nil {
		refresh = upstreamoauth.Refresh
	}
	nt, err := refresh(ctx, meta, a.RefreshToken, a.ClientID, a.ClientSecret)
	if err != nil {
		return err
	}
	return g.store.UpdateTokens(ctx, name, expectedIncarnationID, nt.AccessToken, nt.RefreshToken)
}

// CompleteOAuthLocked applies an OAuth (re)authorization under the same
// per-account lock as refreshAccount. Without it, a refresh already in flight
// when the user completes reauthorization could commit afterwards and
// overwrite the brand-new credentials with its stale token family — and
// providers that revoke the old family on re-authorization then leave the
// account dead despite a successful reconnect. With both writers serialized, a
// refresh that started earlier commits first (reauthorization wins); one that
// starts later re-reads the new credentials. The lock is held only for one
// fast store transaction.
func (g *Gateway) CompleteOAuthLocked(ctx context.Context, precondition OAuthCompletionPrecondition, completion Account) (Account, error) {
	mu := g.refreshLock(completion.Name)
	mu.Lock()
	defer mu.Unlock()
	return g.store.CompleteOAuth(ctx, precondition, completion)
}

// aggregateAccount connects to one account, lists its tools, and registers each
// (prefixed) tool with a handler that routes tools/call back to that upstream.
func (g *Gateway) aggregateAccount(ctx context.Context, a Account) (int, error) {
	up := g.upstreamFor(a)
	tools, err := g.listAccountTools(ctx, a)
	if err != nil {
		return 0, err
	}
	label := a.Label
	if label == "" {
		label = a.Name
	}
	disabled := toSet(a.DisabledTools)
	// names is the aggregate /mcp projection. Personal accounts are still
	// cached below so a subject-bound client endpoint can expose them to its
	// owner, but their names are intentionally never registered on root.
	names := make([]string, 0, len(tools))
	cached := make([]cachedTool, 0, len(tools))
	for _, t := range tools {
		bare := strings.TrimPrefix(t.Name, a.Name+"__")
		if disabled[bare] {
			continue // curated off — never register it, so Claude never sees it
		}
		if a.ReadOnly && !readOnlyTool(t, bare) {
			continue // read-only account: mutating tools are never registered
		}
		override := a.ToolOverrides[bare]
		governance, err := normalizedGovernancePreset(override.GovernancePreset)
		if err != nil {
			// A malformed value can exist only through an old/imported durable
			// record. Do not turn an unrecognised safety policy into a live
			// capability; a console edit can repair it after discovery.
			continue
		}
		if governance == GovernancePresetReadOnly && !readOnlyTool(t, bare) {
			// Read-only is an enforced contract, not an optimistic label. If an
			// upstream changes its metadata or name after the policy was saved,
			// fail closed until an administrator selects a suitable preset.
			continue
		}
		exposedName := bare
		if override.Alias != "" {
			exposedName = override.Alias
		}
		t.Name = a.Name + "__" + exposedName
		if override.Description != "" {
			t.Description = override.Description
		}
		// Stamp the account label into the DISPLAY title so multiple accounts of
		// the same provider (e.g. two Notion workspaces) are distinguishable in
		// the client UI — which shows Title, not the prefixed Name.
		disp := t.Title
		if disp == "" {
			disp = t.Annotations.Title
		}
		if disp == "" {
			disp = bare
		}
		t.Title = label + " · " + disp
		t.Annotations.Title = t.Title
		handler := g.accountToolHandler(a, up, bare)
		handler = g.governedAccountToolHandler(a, bare, readOnlyTool(t, bare), governance, handler)
		names = append(names, t.Name)
		// Cache tool + the SAME closure so connector endpoints dispatch (and
		// audit) identically without re-dialing the upstream.
		cached = append(cached, cachedTool{
			tool: t, sourceName: bare, accountIncarnationID: a.IncarnationID, accountRevision: a.Revision, accountURL: a.URL, handler: handler,
		})
	}
	// Only replace the live registration after the upstream list and all local
	// rewrites have succeeded. A transient upstream failure must leave the last
	// known-good account cache (and every endpoint built from it) intact.
	// store I/O stays outside g.mu; dispatch-time revision fences
	// (accountSnapshotLive) remain the authority.
	current, live := g.store.Account(a.Name)
	g.mu.Lock()
	if !live || a.IncarnationID == "" || a.Revision < 1 || current.IncarnationID != a.IncarnationID || current.Revision != a.Revision || !equalAccountSnapshotURL(current.URL, a.URL) {
		g.mu.Unlock()
		return 0, ErrAccountIncarnation
	}
	rootNames := names
	if a.IsPersonal() {
		rootNames = nil
		g.replaceRootToolsLocked(g.byAcct[a.Name], nil)
	} else {
		g.replaceRootToolsLocked(g.byAcct[a.Name], cached)
	}
	g.byAcct[a.Name] = rootNames
	g.cached[a.Name] = cached
	g.projectedIncarnations[a.Name] = a.IncarnationID
	g.mu.Unlock()
	return len(rootNames), nil // count tools registered on shared root, not cached personal tools
}

// replaceRootToolsLocked swaps one account's shared /mcp projection from the
// old names to tools: one deletion of only the names that disappear, then one
// batched registration (which replaces existing names in place). Connected
// clients get at most two tools/list_changed instead of one per tool, and no
// surviving tool is ever briefly missing. Callers hold g.mu.
func (g *Gateway) replaceRootToolsLocked(old []string, tools []cachedTool) {
	keep := make(map[string]bool, len(tools))
	for _, t := range tools {
		keep[t.tool.Name] = true
	}
	var removed []string
	for _, name := range old {
		if !keep[name] {
			removed = append(removed, name)
		}
	}
	if len(removed) > 0 {
		g.mcp.DeleteTools(removed...)
	}
	if len(tools) > 0 {
		g.mcp.AddTools(serverTools(tools)...)
	}
}

// accountToolHandler builds the dispatch closure shared by root, connector,
// and subject-bound client projections. Keeping it separate from aggregation
// lets an ownership-only move rebind cached tools to the new Account.Revision
// without re-listing an otherwise healthy upstream.
func (g *Gateway) accountToolHandler(a Account, upRef *Upstream, bareName string) server.ToolHandlerFunc {
	acct := a.Name
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !g.accountSnapshotLive(acct, a.IncarnationID, a.Revision, a.URL) {
			return mcp.NewToolResultError("this connection changed; refresh the MCP tool list"), nil
		}
		if beforeDispatch := g.beforeAccountDispatch; beforeDispatch != nil {
			beforeDispatch()
		}
		start := time.Now()
		meta := UsageCallMeta{Account: acct, Tool: bareName}
		if sc := auditScopeFrom(ctx); sc != nil {
			meta.Connector = sc.connector
		}
		execution := g.executeUpstream(
			ctx,
			meta,
			req.GetArguments(),
			func(callCtx context.Context) (*mcp.CallToolResult, error) {
				return upRef.CallTool(callCtx, bareName, req.GetArguments())
			},
		)
		res, err := execution.result, execution.callErr
		if execution.usageErr != nil {
			res, err = UsageToolResult(execution.usageErr), nil
		}
		// Response guardrails — CONNECTOR endpoints only. An account-level
		// governance policy may add an identity-free auditScope on default /mcp,
		// but it carries no guards, so the result still passes through raw. Order
		// matters: redact → cap → injection scan runs
		// BEFORE the audit row below, so recorded payloads never contain what
		// redaction removed. Protocol errors skip guards; isError tool results are
		// guarded like any other (their Error field isn't touched — only text).
		var guard string
		if sc := auditScopeFrom(ctx); sc != nil && sc.guards != nil && err == nil {
			res, guard = applyGuards(res, *sc.guards)
		}
		if g.audit != nil {
			rec := CallRecord{
				Account: acct, Tool: bareName, OK: err == nil,
				Ms:    time.Since(start).Milliseconds(),
				Guard: guard, // post-guard markers; "" on /mcp or when nothing fired
			}
			if err != nil {
				rec.Error = err.Error()
			}
			// This closure is shared byte-for-byte between /mcp and every
			// connector server; the endpoint identity (connector slug, approval
			// decision, record flag) is layered on by the scope wrapper via ctx.
			// No scope is an ordinary default /mcp call. A governed root call has
			// a scope with an intentionally empty endpoint identity.
			record := g.recordDefault
			if sc := auditScopeFrom(ctx); sc != nil {
				rec.Connector = sc.connector
				rec.EndpointKind = sc.kind
				rec.EndpointGeneration = sc.generation
				rec.Decision, record = sc.decision, sc.record
			}
			if record {
				rec.Args = marshalPayload(req.GetArguments())
				if res != nil {
					rec.Result = marshalPayload(res)
				}
			}
			g.audit.LogCall(rec)
		}
		return res, err
	}
}

func (g *Gateway) accountSnapshotLive(name, expectedIncarnationID string, expectedRevision int64, expectedURL string) bool {
	if expectedIncarnationID == "" || expectedRevision < 1 {
		return false
	}
	current, ok := g.store.Account(name)
	return ok && current.IncarnationID == expectedIncarnationID && current.Revision == expectedRevision && equalAccountSnapshotURL(current.URL, expectedURL)
}

// readOnlyTool reports whether a tool is safe to expose on a read-only
// account. Explicit annotations win; without a usable annotation we fall back
// to a conservative NAME HEURISTIC (a write verb anywhere vetoes; otherwise a
// read verb as an exact word passes). It is a guess — UI copy must label it
// as such.
func readOnlyTool(t mcp.Tool, bare string) bool {
	if t.Annotations.ReadOnlyHint != nil {
		return *t.Annotations.ReadOnlyHint
	}
	if t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
		return false
	}
	return readOnlyName(bare)
}

var readVerbs = []string{"get", "list", "search", "read", "query", "fetch", "describe", "find", "show", "count"}

// writeVerbs veto the read heuristic: names like create_list, delete_saved_search
// or update_query contain a read word but MUTATE — the veto must win, or a
// read-only account leaks mutating tools.
var writeVerbs = []string{
	"create", "delete", "update", "add", "set", "remove", "insert", "write",
	"put", "post", "patch", "move", "archive", "send", "upload", "execute",
	"run", "apply", "save", "push", "merge", "reset", "edit", "cancel",
}

// nameTokens splits a tool name into lowercase words on '_', '-', '.' and
// camelCase boundaries ("getIssue" → ["get","issue"]). Exact-word matching —
// no prefix guessing, so "getaway_x" never reads as "get".
func nameTokens(bare string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	prevLower := false
	for _, r := range bare {
		if r == '_' || r == '-' || r == '.' {
			flush()
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			flush()
		}
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
		cur.WriteRune(r)
	}
	flush()
	return tokens
}

func readOnlyName(bare string) bool {
	tokens := nameTokens(bare)
	for _, t := range tokens {
		for _, w := range writeVerbs {
			if t == w {
				return false // veto wins: any write verb marks the tool mutating
			}
		}
	}
	for _, t := range tokens {
		for _, v := range readVerbs {
			if t == v {
				return true
			}
		}
	}
	return false
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ToolInfo describes one upstream tool for the curation UI.
type ToolInfo struct {
	Name        string `json:"name"` // stable upstream bare name
	Alias       string `json:"alias,omitempty"`
	Title       string `json:"title"` // upstream display title
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	ReadOnly    bool   `json:"readOnly"`
	Destructive bool   `json:"destructive"`
	// GovernancePreset is empty when the account uses the backwards-compatible
	// standard policy. Console clients can keep that legacy state explicit
	// instead of silently tightening an existing tool on first edit.
	GovernancePreset GovernancePreset `json:"governancePreset,omitempty"`
	// SizeBytes is the tool definition's actual wire size: len(json.Marshal)
	// of the same mcp.Tool value sent to Claude (name/title/description/
	// inputSchema/annotations via Tool.MarshalJSON), at its real aggregated
	// (prefixed) name. -1 if marshaling failed, so callers can distinguish
	// "unknown" from a genuine zero-byte tool.
	SizeBytes int `json:"sizeBytes"`
}

// ListAccountTools live-lists every tool an account exposes upstream, marked
// with its current enabled/disabled state and its read-only/destructive hint.
func (g *Gateway) ListAccountTools(ctx context.Context, name string) ([]ToolInfo, error) {
	a, ok := g.store.Account(name)
	if !ok {
		return nil, fmt.Errorf("account %q not found", name)
	}
	tools, err := g.listAccountTools(ctx, a)
	if err != nil {
		return nil, err
	}
	disabled := toSet(a.DisabledTools)
	out := make([]ToolInfo, 0, len(tools))
	for _, t := range tools {
		bare := strings.TrimPrefix(t.Name, a.Name+"__")
		title := t.Title
		if title == "" {
			title = t.Annotations.Title
		}
		if title == "" {
			title = bare
		}
		override := a.ToolOverrides[bare]
		description := t.Description
		if override.Description != "" {
			description = override.Description
		}
		// Mirror the actual aggregation check rather than exposing only an
		// upstream annotation. A tool with no annotation can still be treated as
		// read-only by the conservative name heuristic, and the policy console
		// must not offer a conflicting classification.
		ro := readOnlyTool(t, bare)
		de := t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint
		preset, err := normalizedGovernancePreset(override.GovernancePreset)
		if err != nil {
			// Keep the management listing available so an administrator can
			// replace a malformed imported value. The live projection above is
			// still fail-closed.
			preset = ""
		}
		sizeBytes := -1
		if encoded, err := json.Marshal(t); err == nil {
			sizeBytes = len(encoded)
		}
		out = append(out, ToolInfo{Name: bare, Alias: override.Alias, Title: title, Description: description, Enabled: !disabled[bare], ReadOnly: ro, Destructive: de, GovernancePreset: preset, SizeBytes: sizeBytes})
	}
	return out, nil
}

// removeAccountLive unregisters an account without recursively rebuilding
// endpoints. Callers that need the full projection update call
// RefreshConnectors after batching removals.
func (g *Gateway) removeAccountLive(name, expectedIncarnationID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if expectedIncarnationID == "" || g.projectedIncarnations[name] != expectedIncarnationID {
		return false
	}
	names := g.byAcct[name]
	if len(names) > 0 {
		g.mcp.DeleteTools(names...)
	}
	delete(g.byAcct, name)
	delete(g.cached, name)
	delete(g.projectedIncarnations, name)
	return true
}

// removeRootProjectionLive removes only an account's shared /mcp projection.
// It intentionally retains the cached tool definitions: a personal account
// can still be served through an authorized /mcp/clients/{slug} endpoint.
// Actual connection deletion continues to use removeAccountLive above.
func (g *Gateway) removeRootProjectionLive(account Account) bool {
	// store I/O stays outside g.mu; dispatch-time revision fences
	// (accountSnapshotLive) remain the authority.
	current, ok := g.store.Account(account.Name)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !ok || account.IncarnationID == "" || current.IncarnationID != account.IncarnationID || !current.IsPersonal() {
		return false
	}
	names := g.byAcct[account.Name]
	if len(names) > 0 {
		g.mcp.DeleteTools(names...)
	}
	delete(g.byAcct, account.Name)
	if projected := g.projectedIncarnations[account.Name]; projected != "" && projected != account.IncarnationID {
		// The visible name was reused and only a stale prior incarnation is
		// cached. Personal endpoints must rebuild from the replacement instead.
		delete(g.cached, account.Name)
		delete(g.projectedIncarnations, account.Name)
	}
	return true
}

// RemoveAccount unregisters an account's tools from the live MCP server.
func (g *Gateway) RemoveAccount(name, expectedIncarnationID string) {
	g.removeAccountLive(name, expectedIncarnationID)
	g.RefreshConnectors(context.Background())
}

// ReplaceAccount re-aggregates one account (after a token/meta change) so its
// live tools — and their labels — reflect the current store. AddAccount lists
// and prepares the replacement before swapping it in, so a failed upstream
// list leaves the previous live cache and endpoint memberships untouched.
func (g *Gateway) ReplaceAccount(ctx context.Context, name string) (int, error) {
	return g.AddAccount(ctx, name)
}

// listAccountTools is the one live tool-discovery path shared by aggregation,
// curation, and health. Keeping the test seam here lets health exercise the
// same provider behavior as the production path.
func (g *Gateway) listAccountTools(ctx context.Context, a Account) ([]mcp.Tool, error) {
	if g.listTools != nil {
		return g.listTools(ctx, a)
	}
	return g.upstreamFor(a).ListTools(ctx)
}

type healthProbeResult struct {
	tools []mcp.Tool
	err   error
}

var errHealthProbeInFlight = errors.New("health probe is already in progress")

// errHealthProbeCallerAbandoned marks a caller that stopped waiting on
// someone else's in-flight probe because its OWN context ended first (e.g. an
// aborted console fetch) — not because the shared probe itself produced a
// result. The real flight is bound to a different, still-running context and
// may yet succeed or fail on its own terms. probeAccountsHealth must never
// let this reach the shared health cache: doing so would let one viewer's
// disconnect poison every other viewer's read of an otherwise-healthy
// account for the remainder of the TTL.
var errHealthProbeCallerAbandoned = errors.New("caller abandoned wait for in-flight health probe")

// Keep at most one normal live probe plus one prior-generation probe for an
// account. The latter is important when an upstream library has ignored its
// context forever: a credential or endpoint repair must still be able to
// prove the repaired account healthy. We cannot safely terminate arbitrary
// third-party goroutines, so this fixed cap prevents repeated repairs from
// creating unbounded background work.
const maxHealthProbesPerAccount = 2

// healthProbeFlight is one in-flight probe generation. Concurrent callers
// share its result through done instead of starting duplicate upstream probes.
type healthProbeFlight struct {
	accountKey string
	done       chan struct{}
	result     healthProbeResult
}

// cachedAccountHealth is the last completed probe row for one account
// identity, tagged with the credential generation that produced it.
type cachedAccountHealth struct {
	generation string
	row        AccountHealth
	probedAt   time.Time
}

func healthProbeAccountKey(a Account) string {
	// An account replacement gets a new incarnation and must not inherit a
	// stranded probe from the deleted credential. Older local stores may not
	// have an incarnation yet, in which case the name remains the best key.
	if a.IncarnationID == "" {
		return a.Name
	}
	return a.Name + "\x00" + a.IncarnationID
}

func healthProbeKey(a Account) string {
	// Do not retain credentials directly in an in-flight key. The digest covers
	// every upstream dial/refresh input so an OAuth completion, token rotation,
	// or endpoint reconfiguration gets a distinct health generation even where
	// a compatibility store intentionally leaves Account.Revision unchanged.
	h := sha256.New()
	for _, value := range [...]string{
		a.URL,
		a.AuthMode,
		a.ClientID,
		a.ClientSecret,
		a.AccessToken,
		a.RefreshToken,
		a.TokenEndpoint,
		a.Resource,
		a.Scope,
		a.BearerToken,
	} {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return healthProbeAccountKey(a) + "\x00" + hex.EncodeToString(h.Sum(nil))
}

func (g *Gateway) beginHealthProbe(a Account) (release func(), started bool) {
	_, releaseWithResult, started := g.beginHealthProbeFlight(a)
	if !started {
		return nil, false
	}
	return func() { releaseWithResult(healthProbeResult{}) }, true
}

// beginHealthProbeFlight registers a probe generation, or returns the existing
// flight when the same generation is already in flight so callers can share
// its result. A nil flight with started=false means the per-account generation
// cap rejected the probe; the caller must bound itself instead of waiting.
func (g *Gateway) beginHealthProbeFlight(a Account) (flight *healthProbeFlight, release func(healthProbeResult), started bool) {
	key := healthProbeKey(a)
	accountKey := healthProbeAccountKey(a)
	g.healthProbeMu.Lock()
	defer g.healthProbeMu.Unlock()
	if g.healthProbes == nil {
		g.healthProbes = map[string]*healthProbeFlight{}
	}
	if existing, exists := g.healthProbes[key]; exists {
		return existing, nil, false
	}
	active := 0
	for _, f := range g.healthProbes {
		if f.accountKey == accountKey {
			active++
		}
	}
	if active >= maxHealthProbesPerAccount {
		return nil, nil, false
	}
	flight = &healthProbeFlight{accountKey: accountKey, done: make(chan struct{})}
	g.healthProbes[key] = flight
	var releaseOnce sync.Once
	release = func(result healthProbeResult) {
		releaseOnce.Do(func() {
			flight.result = result
			close(flight.done)
			g.healthProbeMu.Lock()
			delete(g.healthProbes, key)
			g.healthProbeMu.Unlock()
		})
	}
	return flight, release, true
}

// listAccountToolsForHealth creates a cancellation boundary around provider
// discovery. Well-behaved transports observe ctx themselves; the result
// channel additionally lets the Engine control plane move on when a provider
// library ignores cancellation. Closing the flight's done channel makes a late
// return safe without leaving that goroutine blocked on a send.
func (g *Gateway) listAccountToolsForHealth(ctx context.Context, a Account) ([]mcp.Tool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flight, release, started := g.beginHealthProbeFlight(a)
	if !started {
		if flight == nil {
			// The per-account generation cap rejected a new probe.
			return nil, errHealthProbeInFlight
		}
		// This exact credential generation is already being probed; share the
		// in-flight result (bounded by this caller's own deadline) so
		// concurrent console viewers neither duplicate the upstream round trip
		// nor see a spurious in-flight timeout row.
		select {
		case <-flight.done:
			return flight.result.tools, flight.result.err
		case <-ctx.Done():
			// Only THIS caller gave up; the flight we were sharing belongs to a
			// different, still-running context and has not produced a result.
			// Returning the bare ctx.Err() here would let probeAccountsHealth
			// mistake an abandoned wait for a genuine probe outcome and cache
			// it — poisoning every other viewer's read for the account. The
			// sentinel lets probeAccountsHealth tell the two apart while still
			// answering this caller's own request with a "no answer yet" row.
			return nil, errHealthProbeCallerAbandoned
		}
	}
	go func() {
		tools, err := g.listAccountTools(ctx, a)
		// Release before waking callers. The registry represents active
		// provider work, which ends once listAccountTools returns; doing this
		// first also makes a completed recovery generation immediately visible
		// to a subsequent poll.
		release(healthProbeResult{tools: tools, err: err})
	}()
	select {
	case <-flight.done:
		return flight.result.tools, flight.result.err
	case <-ctx.Done():
		// Unlike the sharer above, this ctx is the one actually bounding the
		// listAccountTools call started above: its expiry genuinely describes
		// why the flight has not produced a result, so ctx.Err() here is a
		// real outcome for this generation and remains safe to cache.
		return nil, ctx.Err()
	}
}

func (g *Gateway) accountHealthProbeTimeout() time.Duration {
	if g.healthProbeTimeout > 0 {
		return g.healthProbeTimeout
	}
	return defaultHealthProbeTimeout
}

// healthPresentation is the complete public contract for a failed health
// probe. Never pass an upstream error string through this function: it may be
// provider-controlled and is not safe for a browser or an alert webhook.
func healthPresentation(status string) (normalized, detail, recovery string) {
	switch status {
	case healthStatusOK:
		return healthStatusOK, "", ""
	case healthStatusNeedsAuth:
		return healthStatusNeedsAuth, "This connection has not been authorized yet.", healthRecoveryConnect
	case healthStatusAuthExpired:
		return healthStatusAuthExpired, "This connection needs to be authorized again.", healthRecoveryReauthorize
	case healthStatusTimeout:
		return healthStatusTimeout, "The provider did not respond before the health check timed out.", healthRecoveryRetry
	case healthStatusUnreachable:
		return healthStatusUnreachable, "The provider could not be reached. Check its service and try again.", healthRecoveryRetry
	default:
		// Treat an unexpected state as unavailable rather than echoing an
		// arbitrary error/status supplied by an integration.
		return healthStatusUnreachable, "The provider could not be reached. Check its service and try again.", healthRecoveryRetry
	}
}

func classifyHealthProbeError(err error, probeCtx context.Context) string {
	if errors.Is(err, errHealthProbeInFlight) || errors.Is(err, context.DeadlineExceeded) || errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
		return healthStatusTimeout
	}
	if looksLikeAuthFailure(err) {
		return healthStatusAuthExpired
	}
	return healthStatusUnreachable
}

// looksLikeAuthFailure is the HEALTH-CLASSIFIER-ONLY auth check. It is
// deliberately broader than isUnauthorized (upstream.go), which the
// refresh-and-redial retry path uses and which must stay typed-401-only:
// there, a false positive burns a rotating refresh token and re-executes a
// possibly-mutating tool call, so substring matching on arbitrary error text
// is unsafe. Here, the only consequence of a false positive is a console
// label — "needs reauthorization" instead of "unreachable, retry" — so the
// broader pre-typed-401 heuristic is safe to keep for this call site alone.
//
// This match matters most for TOKEN-mode (PAT) accounts: upstreamFor only
// wires automatic refresh for OAuth accounts, so a PAT has no refresh path at
// all, and "reauthorize" (go rotate the token) is the one actionable message
// that fixes a revoked PAT. Many upstreams signal a revoked/expired
// credential through a tool-level JSON-RPC error or a proxy diagnostic rather
// than a literal transport 401, and that message must not silently degrade to
// generic "unreachable" just because it isn't mcp-go's typed sentinel.
func looksLikeAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	if isUnauthorized(err) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "401") ||
		strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "authorization required") ||
		strings.Contains(s, "invalid_token") ||
		strings.Contains(s, "invalid access token") ||
		// A provider that rejects the stored refresh token has revoked the
		// grant: retrying cannot help, only reauthorizing can.
		strings.Contains(s, "invalid_grant")
}

// Health live-checks every account concurrently, with an independent bounded
// context for each provider. A slow or cancellation-ignorant upstream becomes
// one timeout row; it cannot block healthy accounts or the watcher loop.
// Results probed within healthCacheTTL are served from the per-account cache
// so N concurrent console viewers share one upstream probe per account; the
// cache key covers the credential generation, so a repair always gets a fresh
// probe. Cached rows keep their original CheckedAt/LatencyMs — they show
// their real age.
func (g *Gateway) Health(ctx context.Context) []AccountHealth {
	return g.probeAccountsHealth(ctx, g.healthCacheTTL)
}

// liveHealth is the uncached variant for the watch loop: alerting must
// evaluate fresh probes on every tick so a recovery is detected on the next
// interval, not after the read cache expires.
func (g *Gateway) liveHealth(ctx context.Context) []AccountHealth {
	return g.probeAccountsHealth(ctx, 0)
}

// cachedHealthRow returns the cached row for this exact account snapshot when
// it was probed within ttl. A credential or endpoint change is a different
// generation and therefore a miss, even inside the TTL.
func (g *Gateway) cachedHealthRow(a Account, ttl time.Duration) (AccountHealth, bool) {
	if ttl <= 0 {
		return AccountHealth{}, false
	}
	g.healthCacheMu.Lock()
	defer g.healthCacheMu.Unlock()
	entry, ok := g.healthCache[healthProbeAccountKey(a)]
	if !ok || entry.generation != healthProbeKey(a) || time.Since(entry.probedAt) >= ttl {
		return AccountHealth{}, false
	}
	return entry.row, true
}

func (g *Gateway) cacheHealthRow(a Account, row AccountHealth, probedAt time.Time, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	g.healthCacheMu.Lock()
	defer g.healthCacheMu.Unlock()
	if g.healthCache == nil {
		g.healthCache = map[string]cachedAccountHealth{}
	}
	g.healthCache[healthProbeAccountKey(a)] = cachedAccountHealth{
		generation: healthProbeKey(a),
		row:        row,
		probedAt:   probedAt,
	}
}

func (g *Gateway) probeAccountsHealth(ctx context.Context, cacheTTL time.Duration) []AccountHealth {
	accts := g.store.Accounts()
	out := make([]AccountHealth, len(accts))
	var wg sync.WaitGroup
	for i, a := range accts {
		wg.Add(1)
		go func(i int, a Account) {
			defer wg.Done()
			if row, ok := g.cachedHealthRow(a, cacheTTL); ok {
				out[i] = row
				return
			}
			started := time.Now()
			h := AccountHealth{UUID: a.Name, CheckedAt: started.UTC().Format(time.RFC3339)}
			if a.AuthMode == "oauth" && a.AccessToken == "" && a.RefreshToken == "" {
				h.Status, h.Detail, h.Recovery = healthPresentation(healthStatusNeedsAuth)
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, g.accountHealthProbeTimeout())
				tools, err := g.listAccountToolsForHealth(probeCtx, a)
				if err != nil {
					h.internalErr = err
					h.Status, h.Detail, h.Recovery = healthPresentation(classifyHealthProbeError(err, probeCtx))
				} else {
					h.Status, h.Detail, h.Recovery = healthPresentation(healthStatusOK)
					h.ToolCount = len(tools)
				}
				cancel()
			}
			h.LatencyMs = time.Since(started).Milliseconds()
			// Never let a caller that merely gave up waiting on someone else's
			// in-flight probe write to the shared cache: that reflects this
			// caller's own deadline/cancellation, not a genuine outcome for the
			// account. Still return the row for this one caller's own response.
			if !errors.Is(h.internalErr, errHealthProbeCallerAbandoned) {
				g.cacheHealthRow(a, h, started, cacheTTL)
			}
			out[i] = h
		}(i, a)
	}
	wg.Wait()
	return out
}

const (
	// aggregateAccountTimeout bounds one account's discovery (dial, a possible
	// refresh-and-redial, paginated tools/list) so one slow or hung upstream
	// cannot spend the whole startup budget for every other account.
	aggregateAccountTimeout = dialTimeout
	// aggregateParallelism bounds concurrent upstream discovery at startup.
	aggregateParallelism = 4
	// projectionTimeout is the endpoint projection's own budget. It must never
	// inherit an aggregation context that slow upstreams may have exhausted.
	projectionTimeout = 15 * time.Second
	// projectionRetryInterval paces retries of a failed endpoint projection.
	projectionRetryInterval = 10 * time.Second
)

// Aggregate registers tools for every account. One bad account is skipped,
// and reconcileProjection retries it later.
func (g *Gateway) Aggregate(ctx context.Context) int {
	var (
		wg    sync.WaitGroup
		total atomic.Int64
	)
	slots := make(chan struct{}, aggregateParallelism)
	for _, a := range g.store.Accounts() {
		wg.Add(1)
		go func(a Account) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				log.Printf("engine: account %q skipped (list tools failed): %v", a.Name, ctx.Err())
				return
			}
			started := time.Now()
			actx, cancel := context.WithTimeout(ctx, aggregateAccountTimeout)
			n, err := g.aggregateAccount(actx, a)
			cancel()
			if err != nil {
				log.Printf("engine: account %q skipped (list tools failed after %s): %v", a.Name, time.Since(started).Round(time.Millisecond), err)
				return
			}
			total.Add(int64(n))
			log.Printf("engine: aggregated %d tools from %q in %s", n, a.Name, time.Since(started).Round(time.Millisecond))
		}(a)
	}
	wg.Wait()
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), projectionTimeout)
	defer cancel()
	g.RefreshConnectors(pctx)
	return int(total.Load())
}

// ProjectionReady reports that connector, bundle and client endpoints have
// been projected from durable state and the last refresh succeeded. Until
// then a token for an endpoint missing from memory may be valid, so the OAuth
// server answers it with a retryable 503 instead of revoking-style errors.
// Lock-free: the OAuth server calls it while holding its own lock.
func (g *Gateway) ProjectionReady() bool {
	return g.projected.Load() && !g.projectionFailed.Load()
}

// listAccounts reads every account, reporting a failed read as an error where
// the store can (see accountLister) instead of as an empty list.
func (g *Gateway) listAccounts(ctx context.Context) ([]Account, error) {
	if lister, ok := g.store.(accountLister); ok {
		return lister.ListAccounts(ctx)
	}
	return g.store.Accounts(), nil
}

// reconcileProjection repairs what a transient failure left behind: accounts
// whose discovery failed (skipped at startup, or a re-list after a policy edit
// that did not complete) are aggregated again, and a failed endpoint
// projection is retried. Before this, both stayed broken for the rest of the
// process lifetime — tools missing everywhere, or every connector and client
// endpoint answering 401 — while the console reported the account healthy.
// A non-nil healthy limits the retry to accounts whose fresh health probe just
// succeeded, so a hung or broken provider is never dialled a second time.
func (g *Gateway) reconcileProjection(ctx context.Context, healthy map[string]bool) {
	accounts, err := g.listAccounts(ctx)
	if err != nil {
		log.Printf("engine: reconcile projection: list accounts: %v", err)
		return
	}
	restored := 0
	for _, a := range accounts {
		if g.accountProjected(a) || (a.AuthMode == "oauth" && a.AccessToken == "" && a.RefreshToken == "") {
			continue // current, or never authorized: nothing a retry can fix
		}
		if healthy != nil && !healthy[a.Name] {
			continue
		}
		actx, cancel := context.WithTimeout(ctx, aggregateAccountTimeout)
		n, err := g.aggregateAccount(actx, a)
		cancel()
		if err != nil {
			log.Printf("engine: reconcile account %q: %v", a.Name, err)
			continue
		}
		restored++
		log.Printf("engine: reconcile restored %d tools from %q", n, a.Name)
	}
	if restored > 0 || g.projectionFailed.Load() {
		pctx, cancel := context.WithTimeout(ctx, projectionTimeout)
		defer cancel()
		g.RefreshConnectors(pctx)
	}
}

// accountProjected reports whether the live cache was built from this exact
// account incarnation, revision and URL.
func (g *Gateway) accountProjected(a Account) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a.IncarnationID == "" || g.projectedIncarnations[a.Name] != a.IncarnationID {
		return false
	}
	for _, t := range g.cached[a.Name] {
		if t.accountRevision != a.Revision || !equalAccountSnapshotURL(t.accountURL, a.URL) {
			return false
		}
	}
	return true
}

// AddAccount registers a single account's tools at runtime. It intentionally
// resolves the account at call time for ordinary console changes.
func (g *Gateway) AddAccount(ctx context.Context, name string) (int, error) {
	a, ok := g.store.Account(name)
	if !ok {
		return 0, fmt.Errorf("account %q not found", name)
	}
	return g.addAccountSnapshot(ctx, a)
}

// AddAccountForIncarnation is the OAuth-completion variant of AddAccount. A
// provider callback has already proved and updated one exact account row; if
// that row was deleted and recreated before tools are registered, fail closed
// instead of treating the replacement as a successful completion.
func (g *Gateway) AddAccountForIncarnation(ctx context.Context, name, expectedIncarnationID string) (int, error) {
	a, ok := g.store.Account(name)
	if !ok || expectedIncarnationID == "" || a.IncarnationID != expectedIncarnationID {
		return 0, ErrAccountIncarnation
	}
	return g.addAccountSnapshot(ctx, a)
}

func (g *Gateway) addAccountSnapshot(ctx context.Context, a Account) (int, error) {
	n, err := g.aggregateAccount(ctx, a)
	if err == nil {
		g.RefreshConnectors(ctx)
	}
	return n, err
}

// rebindCachedAccount updates only the closure identity for an ownership-only
// account move. Tool discovery, aliases, and policy are unchanged by that
// operation, so re-listing an upstream here would make an already-committed
// move depend on an unrelated network round trip. Returning false means the
// cache was absent or no longer represented expectedPreviousRevision; callers
// should then fall back to a full aggregation.
func (g *Gateway) rebindCachedAccount(a Account, expectedPreviousRevision int64) bool {
	if a.IncarnationID == "" || a.Revision < 1 || expectedPreviousRevision < 1 {
		return false
	}
	up := g.upstreamFor(a)
	// store I/O stays outside g.mu; dispatch-time revision fences
	// (accountSnapshotLive) remain the authority.
	current, live := g.store.Account(a.Name)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !live || current.IncarnationID != a.IncarnationID || current.Revision != a.Revision || !equalAccountSnapshotURL(current.URL, a.URL) {
		return false
	}
	cached, cachedOK := g.cached[a.Name]
	if !cachedOK {
		return false
	}
	for _, tool := range cached {
		if tool.accountIncarnationID == "" || tool.accountIncarnationID != a.IncarnationID || tool.accountRevision != expectedPreviousRevision || !equalAccountSnapshotURL(tool.accountURL, a.URL) {
			return false
		}
	}

	updated := make([]cachedTool, 0, len(cached))
	rootNames := make([]string, 0, len(cached))
	for _, tool := range cached {
		tool.accountRevision = a.Revision
		tool.accountURL = a.URL
		tool.handler = g.accountToolHandler(a, up, tool.sourceName)
		updated = append(updated, tool)
		if !a.IsPersonal() {
			rootNames = append(rootNames, tool.tool.Name)
		}
	}
	if a.IsPersonal() {
		g.replaceRootToolsLocked(g.byAcct[a.Name], nil)
	} else {
		g.replaceRootToolsLocked(g.byAcct[a.Name], updated)
	}
	g.cached[a.Name] = updated
	g.byAcct[a.Name] = rootNames
	g.projectedIncarnations[a.Name] = a.IncarnationID
	return true
}

// StartWatch runs the background reliability loop: refresh-ahead for OAuth
// accounts (so tokens never reach expiry), then a health sweep that fires an
// alert on each down/recovered transition.
func (g *Gateway) StartWatch(ctx context.Context, interval time.Duration) {
	// Repair anything startup could not project soon after boot (a
	// scale-to-zero instance often lives for less than one interval), then
	// tick: first soon after boot, then on the interval. A failed endpoint
	// projection is retried every projectionRetryInterval until it succeeds,
	// because until then client endpoints answer 503.
	reconcile := time.After(15 * time.Second)
	firstTick := time.After(60 * time.Second)
	retry := time.NewTicker(projectionRetryInterval)
	defer retry.Stop()
	var ticks <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcile:
			g.reconcileProjection(ctx, nil)
		case <-firstTick:
			g.tick(ctx)
			t := time.NewTicker(interval)
			defer t.Stop()
			ticks = t.C
		case <-ticks:
			g.tick(ctx)
		case <-retry.C:
			if g.projectionFailed.Load() {
				pctx, cancel := context.WithTimeout(ctx, projectionTimeout)
				g.RefreshConnectors(pctx)
				cancel()
			}
		}
	}
}

func (g *Gateway) tick(ctx context.Context) {
	refreshed := 0
	for _, a := range g.store.Accounts() {
		if ctx.Err() != nil {
			return // shutting down: never start another provider refresh
		}
		if a.AuthMode == "oauth" && a.RefreshToken != "" {
			if err := g.refreshAccount(ctx, a.Name, a.IncarnationID); err != nil {
				log.Printf("engine: refresh-ahead %q: %v", a.Name, err)
			} else {
				refreshed++
			}
		}
	}
	if refreshed > 0 {
		log.Printf("engine: refresh-ahead refreshed %d oauth account(s)", refreshed)
	}
	rows := g.liveHealth(ctx) // health sweep covers token accounts too; alerts need fresh probes, not the console read cache
	healthy := map[string]bool{}
	for _, h := range rows {
		if h.internalErr != nil && !errors.Is(h.internalErr, errHealthProbeInFlight) {
			// Preserve the real cause only in Engine-controlled diagnostics.
			// Browser responses and outbound alerts use healthPresentation.
			log.Printf("engine: health probe account=%q status=%s err=%v", h.UUID, h.Status, h.internalErr)
		}
		healthy[h.UUID] = h.Status == healthStatusOK
	}
	g.evalAlerts(ctx, rows)
	g.reconcileProjection(ctx, healthy)
	g.purgeAudit(ctx)
}

// purgeAudit applies audit retention: rows older than the window are deleted.
// No-op when retention is disabled, no audit sink is attached, or the sink
// has no purger facet (FileStore's ring self-bounds anyway).
func (g *Gateway) purgeAudit(ctx context.Context) {
	if g.retention <= 0 || g.audit == nil {
		return
	}
	p, ok := g.audit.(AuditPurger)
	if !ok {
		return
	}
	n, err := p.PurgeCalls(ctx, g.retention)
	if err != nil {
		log.Printf("engine: audit purge failed: %v", err)
		return
	}
	if n > 0 {
		log.Printf("engine: audit purge deleted %d call row(s) older than %s", n, g.retention)
	}
}

// evalAlerts turns one health sweep into down/recovered alerts; each fires
// only on a state change, so a sustained outage alerts once. Managed Engines
// boot on throttled CPU, where probes time out en masse, so:
//   - a transient failure (timeout/unreachable) alerts only on its second
//     consecutive failed probe;
//   - a sweep in which every probed account timed out says nothing about the
//     providers, so its timeouts are ignored;
//   - outstanding alerts persist through a HealthAlertStore, so a restart does
//     not re-announce a known-down account (e.g. one never authorized).
func (g *Gateway) evalAlerts(ctx context.Context, rows []AccountHealth) {
	g.alertMu.Lock()
	defer g.alertMu.Unlock()
	if g.alertState == nil {
		state := map[string]string{}
		if s, ok := g.store.(HealthAlertStore); ok {
			loaded, err := s.HealthAlerts(ctx)
			if err != nil {
				// Without the prior state every known-down account would
				// re-alert; skip this sweep and retry on the next one.
				log.Printf("engine: load health alert state: %v", err)
				return
			}
			for account, status := range loaded {
				state[account] = status
			}
		}
		g.alertState, g.failStreak = state, map[string]int{}
	}
	probed, timedOut := 0, 0
	for _, h := range rows {
		status, _, _ := healthPresentation(h.Status)
		if status == healthStatusNeedsAuth { // decided from stored credentials, never probed
			continue
		}
		probed++
		if status == healthStatusTimeout {
			timedOut++
		}
	}
	// ponytail: one probed account cannot tell an Engine stall from a provider
	// outage, so it falls back to the two-probe rule alone.
	stalled := probed >= 2 && timedOut == probed
	if stalled {
		log.Printf("engine: every probed account (%d) timed out; treating the sweep as an Engine stall, not alerting", probed)
	}
	seen := make(map[string]bool, len(rows))
	for _, h := range rows {
		seen[h.UUID] = true
		if status, _, _ := healthPresentation(h.Status); !(stalled && status == healthStatusTimeout) {
			g.evalAlertLocked(ctx, h)
		}
	}
	for account := range g.failStreak {
		if !seen[account] {
			delete(g.failStreak, account)
		}
	}
	for account := range g.alertState {
		if !seen[account] { // deleted account: drop its state so a re-created one starts clean
			g.setAlertStateLocked(ctx, account, "")
		}
	}
}

func (g *Gateway) evalAlertLocked(ctx context.Context, h AccountHealth) {
	status, detail, recovery := healthPresentation(h.Status)
	was := g.alertState[h.UUID] != ""
	if status == healthStatusOK {
		delete(g.failStreak, h.UUID)
		if was {
			message := fmt.Sprintf("✅ Synaxis: account %q recovered", h.UUID)
			g.fireEvent(WebhookEvent{
				Event: EventUpstreamRecovered, ID: h.UUID, Account: accountDisplay(g.store, h.UUID),
				Summary: "The probe succeeded again.", Text: message, Content: message,
			})
			g.setAlertStateLocked(ctx, h.UUID, "")
		}
		return
	}
	g.failStreak[h.UUID]++
	transient := status == healthStatusTimeout || status == healthStatusUnreachable
	if was || (transient && g.failStreak[h.UUID] < 2) {
		return
	}
	// Do not interpolate h.Detail here. AccountHealth is public and may be
	// assembled by callers/tests; outbound alerts must remain safe even if a
	// future caller accidentally supplies an upstream error string.
	message := fmt.Sprintf("⚠️ Synaxis: account %q needs attention (%s). %s", h.UUID, status, detail)
	if recovery != "" {
		message += fmt.Sprintf(" Recommended recovery: %s.", recovery)
	}
	summary := fmt.Sprintf("A probe failed and the account is marked down (%s). %s", status, detail)
	if recovery != "" {
		summary += fmt.Sprintf(" Recommended recovery: %s.", recovery)
	}
	g.fireEvent(WebhookEvent{
		Event: EventUpstreamDown, ID: h.UUID, Account: accountDisplay(g.store, h.UUID),
		Summary: summary, Text: message, Content: message,
	})
	g.setAlertStateLocked(ctx, h.UUID, status)
}

// setAlertStateLocked records an alert transition ("" = no outstanding alert).
// It runs after fireEvent: a failed write costs at most one duplicate alert
// after a restart, never a lost one.
func (g *Gateway) setAlertStateLocked(ctx context.Context, account, status string) {
	if status == "" {
		delete(g.alertState, account)
	} else {
		g.alertState[account] = status
	}
	if s, ok := g.store.(HealthAlertStore); ok {
		if err := s.SetHealthAlert(ctx, account, status); err != nil {
			log.Printf("engine: persist health alert state account=%q: %v", account, err)
		}
	}
}
