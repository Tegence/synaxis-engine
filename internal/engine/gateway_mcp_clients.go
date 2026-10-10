package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/oauthas"
)

// mcpClientProjectionTTL bounds how long a subject-bound client endpoint may
// serve requests without re-deriving itself from durable state. Every
// mutation that can affect a client's projection (console handlers via
// refreshMCPClientProjection/RefreshMCPClients, and account/namespace changes
// via RefreshConnectors) already calls buildMCPClient synchronously — for
// every active client — before the mutating request returns, which resets
// this window. So in the steady state this TTL only bounds staleness from a
// source OTHER than an in-process mutation (e.g. a durable write this replica
// has not yet been told to refresh for); it is not the primary freshness
// mechanism.
const mcpClientProjectionTTL = 5 * time.Second

// errMCPClientConsentRefused is the one refusal AuthorizeMCPConsent gives an
// actor who may not consent for a client-bound resource. The OAuth server
// maps any refusal to the same generic access_denied, and keeping a single
// error here keeps the Engine side just as uninformative.
var errMCPClientConsentRefused = errors.New("actor cannot authorize this MCP client")

// mcpClientStore returns the durable subject-bound delivery registry. It is a
// facet rather than a requirement of AccountStore so older self-hosted store
// implementations keep compiling, but production FileStore and PgStore both
// implement it.
func (g *Gateway) mcpClientStore() (MCPClientStore, bool) {
	store, ok := g.store.(MCPClientStore)
	return store, ok
}

// mcpClientLookup is the error-aware slug lookup. ActiveMCPClient folds a
// failed read into "not found", which on the OAuth path became a 401 or a
// terminal invalid_grant for a perfectly healthy agent.
type mcpClientLookup interface {
	LookupActiveMCPClient(ctx context.Context, slug string) (MCPClient, bool, error)
}

func lookupActiveMCPClient(ctx context.Context, store MCPClientStore, slug string) (MCPClient, bool, error) {
	if lookup, ok := store.(mcpClientLookup); ok {
		return lookup.LookupActiveMCPClient(ctx, slug)
	}
	client, found := store.ActiveMCPClient(ctx, slug)
	return client, found, nil
}

// buildMCPClient projects one durable client registration into its dedicated
// /mcp/clients/{slug} surface. The registry itself owns authorization; this
// method builds only the tool projection and therefore rechecks every account
// boundary defensively rather than trusting a human-readable folder label.
// accounts must come from one successful durable listing: projecting from a
// failed read would silently drop every upstream tool.
func (g *Gateway) buildMCPClient(client MCPClient, accounts []Account) error {
	if client.Status != MCPClientStatusActive || client.Slug == "" || client.Epoch == "" {
		return fmt.Errorf("MCP client is not live")
	}
	namespaceIDs := toSet(client.ConnectionNamespaceIDs)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.clientEndpoints == nil {
		g.clientEndpoints = map[string]*connectorServer{}
	}
	endpoint, ok := g.clientEndpoints[client.Slug]
	if !ok {
		_, libraryAvailable := g.store.(LibraryStore)
		_, memoryAvailable := g.store.(LibraryMemoryStore)
		m := newSynaxisMCPServer("narthex-client-"+client.Slug, mcpBootstrapSurfaceClient, mcpBootstrapFeatures{
			library: libraryAvailable,
			memory:  libraryAvailable && memoryAvailable,
		})
		endpoint = &connectorServer{
			mcp:     m,
			handler: NewStreamableMCPHandler(m, "/mcp/clients/"+client.Slug),
			kind:    endpointKindClient,
		}
		g.clientEndpoints[client.Slug] = endpoint
	}
	endpoint.kind = endpointKindClient
	endpoint.epoch = client.Epoch
	endpoint.revision = client.Revision
	endpoint.guards = nil
	endpoint.refreshedAt = time.Now()

	var tools []cachedTool
	for _, account := range accounts {
		if !namespaceIDs[account.ConnectionNamespaceID] {
			continue
		}
		// Shared and service accounts can be delegated through a selected
		// credential folder. A personal account is only eligible when its
		// durable owner is this exact client subject. The stores enforce this
		// invariant transactionally too; this runtime check keeps corrupted or
		// lagging projections fail-closed.
		if account.IsPersonal() && account.OwnerSubject != client.Subject {
			continue
		}
		for _, cached := range g.cached[account.Name] {
			if cached.accountIncarnationID == "" || cached.accountIncarnationID != account.IncarnationID || cached.accountRevision != account.Revision || !equalAccountSnapshotURL(cached.accountURL, account.URL) {
				continue
			}
			tool := cached
			// Recheck the durable client/account boundary immediately before an
			// upstream call. A static MCPServer can briefly retain a prior tools
			// list on another Engine replica, but it must never turn that stale
			// list into credential access after a folder/account mutation.
			tool.handler = g.clientAccountHandler(client.Slug, account.Name, account.IncarnationID, tool.handler)
			tool.handler = g.scopedHandler(
				client.Slug,
				endpointKindClient,
				client.Epoch,
				false,
				nil,
				tool.handler,
			)
			tools = append(tools, tool)
		}
	}
	projected := serverTools(tools)
	// The root /mcp server retains its owner/admin Library projection. A
	// subject-bound client endpoint instead gets a small, independently
	// guarded projection whose identity is derived from this durable client
	// record. It is part of the same atomic tool set, so a refresh cannot
	// leave a stale built-in behind.
	if libraryStore, ok := g.store.(LibraryStore); ok {
		// The Library helpers register onto an MCPServer. A private scratch
		// server with no sessions collects their definitions and closures
		// without notifying anyone.
		scratch := server.NewMCPServer("narthex-client-library", synaxisMCPServerVersion)
		registerMCPClientLibraryTools(
			scratch,
			libraryStore,
			g.audit,
			client,
			func(ctx context.Context) bool {
				return g.mcpClientMayUseLibrary(ctx, client.Slug, client.ID, client.Subject, client.Epoch)
			},
		)
		for _, tool := range scratch.ListTools() {
			projected = append(projected, *tool)
		}
	}
	endpoint.setTools(projected)
	return nil
}

// RefreshMCPClients synchronizes every active, subject-bound delivery
// endpoint from durable state. Console mutations call it after a successful
// CAS write; account ownership and tool changes reach it via
// RefreshConnectors. It returns an error rather than leaving an endpoint
// newly authorizable without a live projection.
func (g *Gateway) RefreshMCPClients(ctx context.Context) error {
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	accounts, err := g.listAccounts(ctx)
	if err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	return g.refreshMCPClientsLocked(ctx, accounts)
}

// refreshMCPClientsLocked requires endpointMu. It intentionally keeps the
// OAuth revoker outside Gateway.mu: revocation can acquire OAuth locks and
// must never run while a request handler is holding the live endpoint map.
func (g *Gateway) refreshMCPClientsLocked(ctx context.Context, accounts []Account) error {
	store, ok := g.mcpClientStore()
	if !ok {
		g.mu.Lock()
		stale := make(map[string]string, len(g.clientEndpoints))
		for slug, endpoint := range g.clientEndpoints {
			stale[slug] = endpoint.epoch
		}
		g.clientEndpoints = map[string]*connectorServer{}
		revoke := g.revokeResource
		revokeEpoch := g.revokeResourceEpoch
		g.mu.Unlock()
		for slug, epoch := range stale {
			if revokeEpoch != nil && epoch != "" {
				revokeEpoch("/mcp/clients/"+slug, epoch)
			} else if revoke != nil {
				revoke("/mcp/clients/" + slug)
			}
		}
		return nil
	}
	clients, err := store.ActiveMCPClients(ctx)
	if err != nil {
		return fmt.Errorf("list MCP clients: %w", err)
	}
	g.mu.Lock()
	previousEpochs := make(map[string]string, len(g.clientEndpoints))
	for slug, endpoint := range g.clientEndpoints {
		previousEpochs[slug] = endpoint.epoch
	}
	g.mu.Unlock()

	seen := make(map[string]string, len(clients))
	for _, client := range clients {
		if err := g.buildMCPClient(client, accounts); err != nil {
			return fmt.Errorf("build MCP client %q: %w", client.Slug, err)
		}
		seen[client.Slug] = client.Epoch
	}

	g.mu.Lock()
	revoked := make(map[string]string)
	for slug := range g.clientEndpoints {
		epoch, live := seen[slug]
		if !live {
			delete(g.clientEndpoints, slug)
			revoked[slug] = previousEpochs[slug]
			continue
		}
		// If a previous endpoint generation was served before this refresh,
		// discard pending OAuth code/refresh state for its path as a faster
		// complement to the epoch check in RequireAuth.
		if previousEpochs[slug] != "" && previousEpochs[slug] != epoch {
			revoked[slug] = previousEpochs[slug]
		}
	}
	revoke := g.revokeResource
	revokeEpoch := g.revokeResourceEpoch
	g.mu.Unlock()
	for slug, epoch := range revoked {
		if revokeEpoch != nil && epoch != "" {
			revokeEpoch("/mcp/clients/"+slug, epoch)
		} else if revoke != nil {
			revoke("/mcp/clients/" + slug)
		}
	}
	return nil
}

// MCPClientEpoch resolves only a currently-projected, active client endpoint.
// It performs a short durable lookup before trusting the live map, so a
// revoked or reassigned record cannot be served by a stale Engine replica.
func (g *Gateway) MCPClientEpoch(slug string) (string, bool) {
	g.mu.Lock()
	endpoint, live := g.clientEndpoints[normalizeMCPClientSlug(slug)]
	if !live || endpoint.kind != endpointKindClient || endpoint.epoch == "" {
		g.mu.Unlock()
		return "", false
	}
	// oauthas calls its epoch resolver while holding its own generation lock.
	// Keep this lookup memory-only. Revocation/rebinding is checked durably by
	// MCPClientAllowsOAuthClient outside that lock on every token/code/refresh
	// use, while a refreshed local projection immediately rotates this endpoint
	// generation without globally stalling OAuth on a database round-trip.
	epoch := endpoint.epoch
	g.mu.Unlock()
	return epoch, true
}

// MCPClientHandler returns a projected subject-bound endpoint. The caller
// must still wrap it in OAuth RequireAuth; this lookup deliberately does not
// turn a server handle into a bearer capability.
func (g *Gateway) MCPClientHandler(slug string) (http.Handler, bool) {
	slug = normalizeMCPClientSlug(slug)
	g.mu.Lock()
	endpoint, ok := g.clientEndpoints[slug]
	live := ok && endpoint.kind == endpointKindClient
	g.mu.Unlock()
	if !live {
		return nil, false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rebuild from durable state only when the cached projection is older
		// than mcpClientProjectionTTL (or has disappeared/changed kind). A
		// mutation-triggered rebuild — console handlers, account/namespace
		// changes — already refreshed it well within that window (see
		// mcpClientProjectionTTL's doc comment), so this bounds worst-case
		// staleness rather than driving freshness on every request.
		g.mu.Lock()
		current, found := g.clientEndpoints[slug]
		stale := !found || current.kind != endpointKindClient || time.Since(current.refreshedAt) >= mcpClientProjectionTTL
		g.mu.Unlock()
		refreshFailed := false
		if stale {
			if err := g.refreshMCPClientRequest(r.Context(), slug); err != nil {
				if errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
					http.NotFound(w, r)
					return
				}
				// A failed durable read is no verdict on the client: answering
				// 404 here told Streamable HTTP clients their session was gone.
				// Keep serving the last good projection instead; every tool call
				// still re-checks the durable client/account boundary and fails
				// closed on its own (clientAccountHandler, mcpClientMayUseLibrary).
				log.Printf("engine: refresh MCP client %q: %v (serving last projection)", slug, err)
				refreshFailed = true
			}
		}
		g.mu.Lock()
		live, found := g.clientEndpoints[slug]
		var handler http.Handler
		if found && live.kind == endpointKindClient {
			handler = live.handler
		}
		g.mu.Unlock()
		if handler == nil && refreshFailed {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "MCP client endpoint unavailable", http.StatusServiceUnavailable)
			return
		}
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}), true
}

// MCPClientAllowsOAuthClient is the per-token callback used by oauthas. It is
// checked for every client-bound access-token, authorization-code, and refresh
// redemption; an epoch alone would revoke stale tokens but could not prevent a
// new token being minted for a rebound OAuth client. It returns an error, not
// false, when durable state could not be read, so the OAuth server answers a
// database hiccup with a retryable 503 rather than a 401 or invalid_grant.
func (g *Gateway) MCPClientAllowsOAuthClient(oauthClientID, resource string) (bool, error) {
	slug, ok := mcpClientSlugFromResource(resource)
	if !ok || strings.TrimSpace(oauthClientID) == "" {
		return false, nil
	}
	store, ok := g.mcpClientStore()
	if !ok {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, ok, err := lookupActiveMCPClient(ctx, store, slug)
	if err != nil {
		return false, fmt.Errorf("load MCP client: %w", err)
	}
	if !ok || client.OAuthClientID != oauthClientID {
		return false, nil
	}
	// A matching binding must also be the kind of binding the client may
	// hold: a workload client only its reserved workload identity, an
	// interactive client never one. The stores never write anything else, so
	// this only makes a corrupt record fail closed.
	if !mcpClientOAuthBindingConsistent(client) {
		return false, nil
	}
	if g.mcpClientProjectionMatches(client) {
		return true, nil
	}
	// This callback runs outside oauthas's generation lock. A replica that has
	// observed a durable reset/rebind but not the corresponding console refresh
	// repairs its own projection before it can authorize the DCR identity.
	// Failure remains fail-closed: an old refresh grant must never be upgraded
	// against a stale endpoint epoch.
	if err := g.RefreshMCPClients(ctx); err != nil {
		return false, err
	}
	return g.mcpClientProjectionMatches(client), nil
}

func (g *Gateway) mcpClientProjectionMatches(client MCPClient) bool {
	g.mu.Lock()
	endpoint, ok := g.clientEndpoints[client.Slug]
	matched := ok && endpoint.kind == endpointKindClient &&
		endpoint.epoch == client.Epoch && endpoint.revision == client.Revision
	g.mu.Unlock()
	return matched
}

// AuthorizeMCPConsent is the durable Engine-side half of a Platform consent.
// Platform's query resource only chooses which member can open its UI; this
// method sees the actual OAuth resource and signed role, so it is the final
// authority against browser query tampering.
//
// For shared root/connector resources only owners and admins can authorize.
// For /mcp/clients/{slug}, an owner, admin, or operator may authorize only a
// registration owned by their exact subject. The first approved OAuth DCR
// client binds through a CAS mutation; a different DCR client never silently
// replaces it. A workload client is refused for every actor, before any
// binding, with the same error as a subject mismatch: its OAuth identity is
// brokered by the control plane and never claimed through browser consent.
// Both the hosted and the self-hosted password consent paths call this.
func (g *Gateway) AuthorizeMCPConsent(ctx context.Context, subject, role, oauthClientID, resource string) error {
	return g.authorizeMCPConsent(ctx, subject, role, oauthClientID, resource, false)
}

// ReplaceMCPConsent is AuthorizeMCPConsent for the member's explicit "Replace
// sign-in" choice: when the subject-bound endpoint is already bound to another
// DCR client, the same member that may bind it moves the binding to this one
// in one revision-checked write. The epoch rotates and the previous epoch's
// grants are revoked, so the app that held the old binding is signed out.
// Every other check is identical; a workload client is still never claimable.
func (g *Gateway) ReplaceMCPConsent(ctx context.Context, subject, role, oauthClientID, resource string) error {
	return g.authorizeMCPConsent(ctx, subject, role, oauthClientID, resource, true)
}

func (g *Gateway) authorizeMCPConsent(ctx context.Context, subject, role, oauthClientID, resource string, replace bool) error {
	subject = strings.TrimSpace(subject)
	role = strings.TrimSpace(role)
	oauthClientID = strings.TrimSpace(oauthClientID)
	if subject == "" || oauthClientID == "" {
		return errors.New("consent actor or OAuth client is missing")
	}
	slug, clientResource := mcpClientSlugFromResource(resource)
	if !clientResource {
		switch role {
		case "owner", "admin":
			return nil
		default:
			return errors.New("only a workspace owner or admin may authorize shared MCP access")
		}
	}

	store, ok := g.mcpClientStore()
	if !ok {
		return errors.New("MCP client registry is unavailable")
	}
	client, found, err := lookupActiveMCPClient(ctx, store, slug)
	if err != nil {
		return fmt.Errorf("%w: load MCP client: %w", oauthas.ErrAuthorizationStateUnavailable, err)
	}
	if !found {
		return errors.New("MCP client endpoint is unavailable")
	}
	actor := PlatformActor{UserID: subject, Role: role}
	// MCPClientAllowsActor never admits a workload client, whatever the
	// actor, so this single refusal covers both cases indistinguishably.
	if !MCPClientAllowsActor(client, actor) {
		return errMCPClientConsentRefused
	}
	if client.OAuthClientID != "" && client.OAuthClientID != oauthClientID && !replace {
		// The actor is entitled to this endpoint; only the app differs. Say so,
		// so consent can offer to replace the sign-in instead of reporting a
		// generic failure.
		return fmt.Errorf("%w: %w", ErrMCPClientOAuthBinding, oauthas.ErrClientBoundToOtherApp)
	}
	if client.OAuthClientID != oauthClientID {
		bind := store.BindMCPClientOAuthClient
		if replace {
			bind = store.ReplaceMCPClientOAuthClient
		}
		previous := client.OAuthClientID
		bound, err := bind(ctx, client.ID, oauthClientID, MCPClientPrecondition{
			ID: client.ID, Revision: client.Revision,
		}, actor)
		if err != nil {
			// A duplicate approval of the same DCR registration is harmless. A
			// different binding is not: reload only to distinguish that safe
			// idempotency case from a genuine concurrent takeover attempt.
			if errors.Is(err, ErrMCPClientRevision) {
				if current, ok := store.ActiveMCPClient(ctx, client.ID); ok &&
					MCPClientAllowsActor(current, actor) && current.OAuthClientID == oauthClientID {
					bound = current
				} else {
					return fmt.Errorf("%w: %w", ErrMCPClientOAuthBinding, oauthas.ErrClientBoundToOtherApp)
				}
			} else {
				return err
			}
		}
		if previous != "" && bound.OAuthClientID == oauthClientID {
			log.Printf("engine: MCP client %q sign-in replaced by its member; the previous app's tokens are revoked", client.Slug)
		}
		client = bound
	}
	if err := g.RefreshMCPClients(ctx); err != nil {
		return err
	}
	if epoch, live := g.MCPClientEpoch(client.Slug); !live || epoch != client.Epoch {
		return errors.New("MCP client endpoint could not be refreshed")
	}
	return nil
}

// refreshMCPClientRequest serializes a one-client rebuild against account and
// folder mutations. Its data-plane caller deliberately uses the request
// context, then the per-tool guard below repeats the policy immediately before
// a potentially long upstream call.
func (g *Gateway) refreshMCPClientRequest(ctx context.Context, slug string) error {
	store, ok := g.mcpClientStore()
	if !ok {
		return ErrMCPClientNotFound
	}
	g.endpointMu.Lock()
	defer g.endpointMu.Unlock()
	// Parallel requests that all found the projection stale queue here; only
	// the first needs to rebuild.
	g.mu.Lock()
	current, found := g.clientEndpoints[slug]
	fresh := found && current.kind == endpointKindClient && time.Since(current.refreshedAt) < mcpClientProjectionTTL
	g.mu.Unlock()
	if fresh {
		return nil
	}
	// Read only after acquiring the projection mutex. Reading first leaves a
	// window in which a console mutation publishes a newer epoch/toolset and
	// this request then overwrites it with a stale client snapshot.
	client, found, err := lookupActiveMCPClient(ctx, store, slug)
	if err != nil {
		return fmt.Errorf("load MCP client: %w", err)
	}
	if !found {
		return ErrMCPClientNotFound
	}
	accounts, err := g.listAccounts(ctx)
	if err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	return g.buildMCPClient(client, accounts)
}

// clientAccountHandler is a final authorization gate around each cached tool
// closure. It is intentionally independent of a prior tools/list projection:
// an account moved out of a selected folder, made personal for another member,
// or a revoked client cannot dispatch a call just because a stream established
// before the mutation still knows the tool name.
func (g *Gateway) clientAccountHandler(slug, accountName, accountIncarnationID string, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !g.mcpClientMayUseAccount(ctx, slug, accountName, accountIncarnationID) {
			return mcp.NewToolResultError("this connection is no longer available to this MCP client"), nil
		}
		return inner(ctx, req)
	}
}

func (g *Gateway) mcpClientMayUseAccount(ctx context.Context, slug, accountName, accountIncarnationID string) bool {
	store, ok := g.mcpClientStore()
	if !ok {
		return false
	}
	client, ok, err := lookupActiveMCPClient(ctx, store, slug)
	if err != nil || !ok {
		return false
	}
	account, ok := g.store.Account(accountName)
	if !ok || accountIncarnationID == "" || account.IncarnationID != accountIncarnationID ||
		!toSet(client.ConnectionNamespaceIDs)[account.ConnectionNamespaceID] {
		return false
	}
	return !account.IsPersonal() || account.OwnerSubject == client.Subject
}

// mcpClientMayUseLibrary is the final durable guard for a direct-agent
// Library built-in. Unlike connection delivery it intentionally does not
// consult ConnectionNamespaceIDs: Library scopes are generic records and must
// never inherit or reinterpret a credential-owning connection namespace.
// Matching the immutable registration ID, subject, and current epoch prevents
// a stale stream (or another client registered by the same subject) from
// inheriting this endpoint's private artifact surface after a refresh,
// authorization reset, or revocation.
func (g *Gateway) mcpClientMayUseLibrary(ctx context.Context, slug, clientID, subject, epoch string) bool {
	store, ok := g.mcpClientStore()
	if !ok {
		return false
	}
	client, ok, err := lookupActiveMCPClient(ctx, store, slug)
	return err == nil && ok && client.ID == clientID && client.Subject == subject && client.Epoch == epoch
}

func mcpClientSlugFromResource(resource string) (string, bool) {
	const prefix = "/mcp/clients/"
	slug, ok := strings.CutPrefix(strings.TrimRight(strings.TrimSpace(resource), "/"), prefix)
	if !ok || slug == "" || strings.Contains(slug, "/") || normalizeMCPClientSlug(slug) != slug {
		return "", false
	}
	return slug, true
}

// logMCPClientRefresh is a small shared helper for console mutation paths:
// the durable write remains authoritative, but the caller receives a useful
// failure rather than pretending its endpoint is already usable.
func (g *Gateway) logMCPClientRefresh(ctx context.Context) error {
	if err := g.RefreshMCPClients(ctx); err != nil {
		log.Printf("engine: refresh MCP client endpoints: %v", err)
		return err
	}
	return nil
}
