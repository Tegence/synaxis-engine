package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/mark3labs/mcp-go/server"
)

const (
	endpointKindConnector = "connector"
	endpointKindNamespace = "namespace"
	endpointKindClient    = "client"
)

// connectorServer is one virtual connector's live MCP endpoint: its own
// MCPServer (mcp-go answers tools/list from the registered set, so a curated
// subset needs its own instance) plus the Streamable HTTP transport for it.
// The MCPServer instance is stable across rebuilds — toolset changes mutate it
// via AddTool/DeleteTools so in-flight sessions survive.
type connectorServer struct {
	mcp     *server.MCPServer
	handler http.Handler // StreamableHTTPServer for /mcp/{slug}
	names   []string     // currently registered (prefixed) tool names
	epoch   string       // endpoint token generation; read by the OAuth AS
	// revision is used by subject-bound client endpoints. It lets the request
	// wrapper fail closed when a CAS mutation has committed but this replica has
	// not yet rebuilt its static MCPServer projection.
	revision int64
	kind     string // "connector" | "namespace"
	// guards is this connector's compiled response-guardrail config (redact
	// patterns + size cap; injection scan is always on). Rebuilt with the
	// toolset; also read by Replay so a replayed call re-applies the
	// connector's CURRENT guards. Accessed under Gateway.mu.
	guards *compiledGuards
}

// connectorStore returns the store's ConnectorStore facet, if it has one.
// Stores without connector support make every connector operation a no-op
// (same pattern as the AuditSink type-assert in main.go).
func (g *Gateway) connectorStore() (ConnectorStore, bool) {
	cs, ok := g.store.(ConnectorStore)
	return cs, ok
}

func (g *Gateway) namespaceStore() (NamespaceStore, bool) {
	ns, ok := g.store.(NamespaceStore)
	return ns, ok
}

// buildConnector creates (or refreshes) the per-connector MCP server for vc by
// filtering the cached tools: for each account in vc.Tools, a cached tool is
// included iff its BARE name (prefix stripped) is in that account's allowlist.
// Unknown accounts and empty allowlists contribute nothing. Tools also listed
// in vc.Approval get the approval-parking wrapper — rebuilds always re-wrap
// from the CURRENT store state, since vc comes from the store on every refresh.
func (g *Gateway) buildConnector(vc VirtualConnector) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[vc.Slug]
	if ok && cs.kind != endpointKindConnector {
		// Durable storage is the authority for the globally shared slug domain.
		// A different live kind here means this replica has not yet projected a
		// delete+reuse committed elsewhere; replace the stale local server.
		ok = false
	}
	if !ok {
		m := server.NewMCPServer("narthex-"+vc.Slug, "0.1.0", server.WithToolCapabilities(true))
		cs = &connectorServer{
			mcp:     m,
			handler: server.NewStreamableHTTPServer(m, server.WithEndpointPath("/mcp/"+vc.Slug)),
			kind:    endpointKindConnector,
		}
		g.connectors[vc.Slug] = cs
	}
	// Compile this connector's response guards ONCE per rebuild; every handler
	// registered below shares them via the audit scope. Invalid redact
	// patterns are logged + skipped inside compileGuards (the console is the
	// validation gate) — a bad pattern never breaks a rebuild. Guards are a
	// CONNECTOR feature: the default /mcp endpoint below stays a raw
	// passthrough because its handlers never get scope-wrapped at all.
	cg := compileGuards(vc)
	cs.guards = &cg
	cs.epoch = vc.Epoch
	var names []string
	var add []cachedTool
	for acct, allow := range vc.Tools {
		account, exists := g.store.Account(acct)
		if !exists || account.IsPersonal() {
			// Storage mutation paths reject this, but old/corrupt durable rows
			// must not turn a personal credential into a shared endpoint while
			// a replica is catching up.
			continue
		}
		allowSet := toSet(allow)
		if len(allowSet) == 0 {
			continue // account listed but nothing enabled — contributes nothing
		}
		approvalSet := toSet(vc.Approval[acct]) // source BARE names, intersected with the allowlist
		for _, ct := range g.cached[acct] {
			if ct.accountIncarnationID == "" || ct.accountIncarnationID != account.IncarnationID || ct.accountRevision != account.Revision || !equalAccountSnapshotURL(ct.accountURL, account.URL) {
				continue
			}
			bare := ct.sourceName
			if !allowSet[bare] {
				continue
			}
			preset, presetErr := normalizedGovernancePreset(
				account.ToolOverrides[bare].GovernancePreset,
			)
			if approvalSet[bare] && (presetErr != nil || !preset.requiresApproval()) {
				// require_approval: park the call for a human decision first.
				// ct is a copy — the cached (main /mcp) handler stays unwrapped;
				// that's safe because access tokens are bound to the endpoint
				// path they were authorized for (oauthas), so a connector token
				// cannot reach the ungated /mcp surface.
				ct.handler = g.approvalHandler(vc.Slug, account, bare, ct.handler)
			}
			// Outermost: stamp every call on this endpoint with the connector
			// name, its Record flag, and its compiled guards (read by the
			// shared dispatch closure — and by the approval wrapper — via
			// ctx). Full composition: scope → approval parks → dispatch →
			// guards (redact → cap → injection scan) → audit → return. The
			// cached (main /mcp) handler stays unscoped: it logs with
			// connector "", follows the gateway-wide recordDefault, and runs
			// NO guards (raw passthrough by design).
			ct.handler = g.scopedHandler(
				vc.Slug,
				endpointKindConnector,
				vc.Epoch,
				vc.Record,
				&cg,
				ct.handler,
			)
			add = append(add, ct)
			names = append(names, ct.tool.Name)
		}
	}
	// Mutate the stable MCPServer instance in place.
	if len(cs.names) > 0 {
		cs.mcp.DeleteTools(cs.names...)
	}
	for _, ct := range add {
		cs.mcp.AddTool(ct.tool, ct.handler)
	}
	cs.names = names
	return nil
}

// buildNamespace creates or refreshes an endpoint bundle from every
// enabled cached tool belonging to each member account. The cached definitions
// already reflect account-level disabled/read-only/override policy, and their
// <account>__<tool> names are reused unchanged.
func (g *Gateway) buildNamespace(ns Namespace) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[ns.Slug]
	if ok && cs.kind != endpointKindNamespace {
		// Converge a stale replica after a cross-kind delete+reuse committed in
		// durable storage. Store mutation paths already reject a real collision.
		ok = false
	}
	if !ok {
		m := server.NewMCPServer("narthex-"+ns.Slug, "0.1.0", server.WithToolCapabilities(true))
		cs = &connectorServer{
			mcp:     m,
			handler: server.NewStreamableHTTPServer(m, server.WithEndpointPath("/mcp/"+ns.Slug)),
			kind:    endpointKindNamespace,
		}
		g.connectors[ns.Slug] = cs
	}
	cs.epoch = ns.Epoch
	cs.guards = nil
	var names []string
	var add []cachedTool
	for _, account := range ns.Accounts {
		stored, exists := g.store.Account(account)
		if !exists || stored.IsPersonal() {
			continue
		}
		for _, cached := range g.cached[account] {
			if cached.accountIncarnationID == "" || cached.accountIncarnationID != stored.IncarnationID || !equalAccountSnapshotURL(cached.accountURL, stored.URL) {
				continue
			}
			ct := cached
			// Endpoint bundles are provider/account groupings, not curated
			// policy connectors. They add endpoint attribution for audit/usage
			// while leaving the already-filtered tool handler otherwise raw.
			ct.handler = g.scopedHandler(
				ns.Slug,
				endpointKindNamespace,
				ns.Epoch,
				false,
				nil,
				ct.handler,
			)
			add = append(add, ct)
			names = append(names, ct.tool.Name)
		}
	}
	if len(cs.names) > 0 {
		cs.mcp.DeleteTools(cs.names...)
	}
	for _, ct := range add {
		cs.mcp.AddTool(ct.tool, ct.handler)
	}
	cs.names = names
	return nil
}

// RefreshConnectors rebuilds every legacy connector and endpoint-bundle
// endpoint from the store (called after any account change so both projections
// track the live tool cache). Existing legacy connectors win if corrupted
// storage somehow contains a cross-kind slug collision; all mutation paths
// reject such collisions before persistence.
func (g *Gateway) RefreshConnectors(ctx context.Context) {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	// A scope change can arrive through durable store APIs before a live
	// gateway refresh. Prune the aggregate first so no root /mcp tool outlives
	// a move to personal, while retaining its cached tools for the owner's
	// subject-bound client endpoint. Then rebuild every shared endpoint from
	// the current store state below.
	for _, account := range g.store.Accounts() {
		if account.IsPersonal() {
			g.removeRootProjectionLive(account)
		}
	}
	var connectors []VirtualConnector
	if cs, ok := g.connectorStore(); ok {
		list, err := cs.Connectors(ctx)
		if err != nil {
			log.Printf("engine: refresh connectors: %v", err)
			return
		}
		connectors = list
	}
	var namespaces []Namespace
	if ns, ok := g.namespaceStore(); ok {
		list, err := ns.Namespaces(ctx)
		if err != nil {
			log.Printf("engine: refresh namespaces: %v", err)
			return
		}
		namespaces = list
	}
	seen := make(map[string]bool, len(connectors)+len(namespaces))
	for _, vc := range connectors {
		if err := g.buildConnector(vc); err != nil {
			log.Printf("engine: refresh connector %q: %v", vc.Slug, err)
			continue
		}
		seen[vc.Slug] = true
	}
	for _, ns := range namespaces {
		if seen[ns.Slug] {
			log.Printf("engine: namespace %q conflicts with a legacy connector; connector endpoint kept", ns.Slug)
			continue
		}
		if err := g.buildNamespace(ns); err != nil {
			log.Printf("engine: refresh namespace %q: %v", ns.Slug, err)
			continue
		}
		seen[ns.Slug] = true
	}
	g.mu.Lock() // drop servers whose connector no longer exists in the store
	for slug := range g.connectors {
		if !seen[slug] {
			delete(g.connectors, slug)
		}
	}
	g.mu.Unlock()
	// Subject-bound client endpoints are projected from the same cache, but
	// live in a separate path namespace. Refreshing them alongside the shared
	// surfaces makes ownership/scope moves take effect immediately.
	g.refreshMCPClientsLocked(ctx)
}

// UpsertConnector writes vc through the store, then (re)builds its live server.
// A connector without an epoch gets one: preserved from the stored row on
// update, freshly minted on create — so recreating a deleted slug invalidates
// every access token issued for the previous incarnation (the AS bakes the
// epoch into the token HMAC).
func (g *Gateway) UpsertConnector(ctx context.Context, vc VirtualConnector) error {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	cs, ok := g.connectorStore()
	if !ok {
		return fmt.Errorf("store does not support connectors")
	}
	if err := g.rejectPersonalEndpointAccounts(accountNamesInToolMap(vc.Tools)); err != nil {
		return err
	}
	if err := g.rejectPersonalEndpointAccounts(accountNamesInToolMap(vc.Approval)); err != nil {
		return err
	}
	if ns, ok := g.namespaceStore(); ok {
		if _, found := ns.Namespace(ctx, vc.Slug); found {
			return fmt.Errorf("%w: %s", ErrEndpointCollision, vc.Slug)
		}
	}
	if vc.Epoch == "" {
		if existing, found := cs.VirtualConnector(ctx, vc.Slug); found {
			vc.Epoch = existing.Epoch
		} else {
			vc.Epoch = newEpoch()
		}
	}
	if err := cs.UpsertConnector(ctx, vc); err != nil {
		return err
	}
	return g.buildConnector(vc)
}

func (g *Gateway) rejectPersonalEndpointAccounts(accounts []string) error {
	for _, name := range accounts {
		if account, found := g.store.Account(name); found && account.IsPersonal() {
			return fmt.Errorf("%w: %s", ErrPersonalAccountExposure, name)
		}
	}
	return nil
}

// MoveAccountToConnectionNamespace is the live-safe ownership transition for
// console callers. The durable store performs the CAS and prunes persisted
// shared memberships first; this wrapper immediately removes a newly personal
// account from the aggregate server (or aggregates an account that becomes
// shared). Callers should prefer it over invoking the store directly whenever
// a Gateway is serving traffic.
func (g *Gateway) MoveAccountToConnectionNamespace(ctx context.Context, account, expectedIncarnationID string, assignment AccountConnectionAssignment, expectedRevision int64) (Account, error) {
	store, ok := g.store.(ConnectionNamespaceStore)
	if !ok {
		return Account{}, fmt.Errorf("store does not support connection namespaces")
	}
	before, found := g.store.Account(account)
	if !found {
		return Account{}, ErrAccountNotFound
	}
	if expectedIncarnationID == "" || before.IncarnationID != expectedIncarnationID {
		return Account{}, ErrAccountIncarnation
	}
	updated, err := store.MoveAccountToConnectionNamespace(ctx, account, expectedIncarnationID, assignment, expectedRevision)
	if err != nil {
		return Account{}, err
	}
	if updated.IsPersonal() {
		// Remove root visibility before the potentially slow re-aggregation below.
		// The previous cached closures are revision-bound and already fail closed,
		// but tool discovery should not briefly advertise a newly personal account.
		g.removeRootProjectionLive(updated)
	}
	// An ownership move deliberately preserves Name and IncarnationID but rotates
	// Account.Revision. Rebind an already-current cache without touching the
	// upstream; if no safe cache exists, fall back to a full aggregation.
	if g.rebindCachedAccount(updated, before.Revision) {
		g.RefreshConnectors(ctx)
		return updated, nil
	}
	if _, err := g.AddAccount(ctx, updated.Name); err != nil {
		return updated, fmt.Errorf("connection moved but live aggregation failed: %w", err)
	}
	return updated, nil
}

// DeleteConnector removes vc from the store and tears down its live server
// (subsequent requests to /mcp/{slug} 404). It also revokes AS state for the
// endpoint: outstanding access tokens die via the epoch check (the slug no
// longer resolves, and a recreated slug gets a fresh epoch), and the wired
// revoker drops the endpoint's refresh grants so they can't mint new tokens.
func (g *Gateway) DeleteConnector(ctx context.Context, slug string) error {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	cs, ok := g.connectorStore()
	if !ok {
		return fmt.Errorf("store does not support connectors")
	}
	connector, found := cs.VirtualConnector(ctx, slug)
	if !found {
		return ErrConnectorNotFound
	}
	if err := cs.DeleteConnector(ctx, slug, connector.Epoch); err != nil {
		return err
	}
	g.retireEndpoint(slug, endpointKindConnector, connector.Epoch)
	return nil
}

// CreateNamespace persists and serves an endpoint bundle. Bundle and
// legacy connector slugs share the /mcp/{slug} routing space.
func (g *Gateway) CreateNamespace(ctx context.Context, ns Namespace) (Namespace, error) {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	store, ok := g.namespaceStore()
	if !ok {
		return Namespace{}, fmt.Errorf("store does not support namespaces")
	}
	if err := g.rejectPersonalEndpointAccounts(normalizedNamespaceAccounts(ns.Accounts)); err != nil {
		return Namespace{}, err
	}
	if cs, ok := g.connectorStore(); ok {
		if _, found := cs.VirtualConnector(ctx, ns.Slug); found {
			return Namespace{}, fmt.Errorf("%w: %s", ErrEndpointCollision, ns.Slug)
		}
	}
	if ns.Epoch == "" {
		ns.Epoch = newEpoch()
	}
	if ns.Revision < 1 {
		ns.Revision = 1
	}
	if err := store.CreateNamespace(ctx, ns); err != nil {
		return Namespace{}, err
	}
	stored, ok := store.Namespace(ctx, ns.Slug)
	if !ok {
		return Namespace{}, fmt.Errorf("namespace %q disappeared after create", ns.Slug)
	}
	if err := g.buildNamespace(stored); err != nil {
		return Namespace{}, err
	}
	return stored, nil
}

func (g *Gateway) UpdateNamespace(ctx context.Context, update Namespace, precondition NamespacePrecondition) (Namespace, error) {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	store, ok := g.namespaceStore()
	if !ok {
		return Namespace{}, fmt.Errorf("store does not support namespaces")
	}
	if err := g.rejectPersonalEndpointAccounts(normalizedNamespaceAccounts(update.Accounts)); err != nil {
		return Namespace{}, err
	}
	ns, err := store.UpdateNamespace(ctx, update, precondition)
	if err != nil {
		return Namespace{}, err
	}
	if err := g.buildNamespace(ns); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

func (g *Gateway) AddNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	store, ok := g.namespaceStore()
	if !ok {
		return Namespace{}, fmt.Errorf("store does not support namespaces")
	}
	if err := g.rejectPersonalEndpointAccounts([]string{account}); err != nil {
		return Namespace{}, err
	}
	ns, err := store.AddNamespaceAccount(ctx, slug, account, precondition)
	if err != nil {
		return Namespace{}, err
	}
	if err := g.buildNamespace(ns); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

func (g *Gateway) RemoveNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	store, ok := g.namespaceStore()
	if !ok {
		return Namespace{}, fmt.Errorf("store does not support namespaces")
	}
	ns, err := store.RemoveNamespaceAccount(ctx, slug, account, precondition)
	if err != nil {
		return Namespace{}, err
	}
	if err := g.buildNamespace(ns); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

// DeleteNamespace revokes only the endpoint bundle. Member accounts and
// their credentials remain intact and continue to be served from root /mcp and
// any other namespace/connector memberships.
func (g *Gateway) DeleteNamespace(ctx context.Context, slug string, precondition NamespacePrecondition) error {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	store, ok := g.namespaceStore()
	if !ok {
		return fmt.Errorf("store does not support namespaces")
	}
	if err := store.DeleteNamespace(ctx, slug, precondition); err != nil {
		return err
	}
	g.retireEndpoint(slug, endpointKindNamespace, precondition.Generation)
	return nil
}

// retireEndpoint removes and revokes only the endpoint incarnation whose
// store row was just compare-and-swap deleted. A stale replica must never tear
// down a connector/namespace that has already reused the slug with a different
// kind or generation.
func (g *Gateway) retireEndpoint(slug, kind, generation string) {
	g.mu.Lock()
	live, exists := g.connectors[slug]
	reused := exists && (live.kind != kind || live.epoch != generation)
	if exists && !reused {
		delete(g.connectors, slug)
	}
	revoke := g.revokeResource
	revokeEpoch := g.revokeResourceEpoch
	g.mu.Unlock()
	if !reused {
		if revokeEpoch != nil && generation != "" {
			revokeEpoch("/mcp/"+slug, generation)
		} else if revoke != nil {
			revoke("/mcp/" + slug)
		}
	}
}

// SetTokenRevoker wires the OAuth AS callback that drops refresh grants (and
// pending auth codes) for a resource path when its connector is deleted. An
// injected func rather than an oauthas import keeps the seam one-directional.
func (g *Gateway) SetTokenRevoker(fn func(resourcePath string)) {
	g.mu.Lock()
	g.revokeResource = fn
	g.mu.Unlock()
}

// SetTokenEpochRevoker installs the precise revocation callback used by the
// durable OAuth store. `retiringEpoch` is the endpoint generation removed or
// replaced by this Gateway refresh, never the replacement's generation.
func (g *Gateway) SetTokenEpochRevoker(fn func(resourcePath, retiringEpoch string)) {
	g.mu.Lock()
	g.revokeResourceEpoch = fn
	g.mu.Unlock()
}

// ConnectorEpoch resolves a slug to the epoch of its LIVE connector or
// namespace server — the AS-side lookup that binds access tokens to an endpoint
// generation. ok=false for a missing endpoint, so authorization fails closed.
func (g *Gateway) ConnectorEpoch(slug string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[slug]
	if !ok {
		return "", false
	}
	return cs.epoch, true
}

// newEpoch mints a random connector token generation.
func newEpoch() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ConnectorHandler returns the live Streamable HTTP handler for a legacy
// connector or endpoint-bundle slug.
func (g *Gateway) ConnectorHandler(slug string) (http.Handler, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[slug]
	if !ok {
		return nil, false
	}
	return cs.handler, true
}

// ConnectorStats quantifies the token savings of a curated connector: how many
// tool definitions (and how many JSON bytes of them) it exposes vs. the full
// aggregated set. Bytes are len(json.Marshal) of each cached tool definition.
type ConnectorStats struct {
	ExposedTools int `json:"exposedTools"`
	TotalTools   int `json:"totalTools"`
	ExposedBytes int `json:"exposedBytes"`
	TotalBytes   int `json:"totalBytes"`
}

func (g *Gateway) ConnectorStats(ctx context.Context, slug string) (ConnectorStats, error) {
	cs, ok := g.connectorStore()
	if !ok {
		return ConnectorStats{}, fmt.Errorf("store does not support connectors")
	}
	vc, ok := cs.VirtualConnector(ctx, slug)
	if !ok {
		return ConnectorStats{}, fmt.Errorf("connector %q not found", slug)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var st ConnectorStats
	for acct, tools := range g.cached {
		if account, found := g.store.Account(acct); !found || account.IsPersonal() {
			continue
		}
		allow := toSet(vc.Tools[acct])
		for _, ct := range tools {
			b, err := json.Marshal(ct.tool)
			if err != nil {
				continue
			}
			st.TotalTools++
			st.TotalBytes += len(b)
			if allow[ct.sourceName] {
				st.ExposedTools++
				st.ExposedBytes += len(b)
			}
		}
	}
	return st, nil
}

// NamespaceStats compares the enabled tool surface contributed by namespace
// members with the complete enabled root surface.
func (g *Gateway) NamespaceStats(ctx context.Context, slug string) (ConnectorStats, error) {
	store, ok := g.namespaceStore()
	if !ok {
		return ConnectorStats{}, fmt.Errorf("store does not support namespaces")
	}
	ns, ok := store.Namespace(ctx, slug)
	if !ok {
		return ConnectorStats{}, fmt.Errorf("namespace %q not found", slug)
	}
	members := toSet(ns.Accounts)
	g.mu.Lock()
	defer g.mu.Unlock()
	var st ConnectorStats
	for account, tools := range g.cached {
		if stored, found := g.store.Account(account); !found || stored.IsPersonal() {
			continue
		}
		for _, ct := range tools {
			b, err := json.Marshal(ct.tool)
			if err != nil {
				continue
			}
			st.TotalTools++
			st.TotalBytes += len(b)
			if members[account] {
				st.ExposedTools++
				st.ExposedBytes += len(b)
			}
		}
	}
	return st, nil
}
