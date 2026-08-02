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
)

// mcpClientStore returns the durable subject-bound delivery registry. It is a
// facet rather than a requirement of AccountStore so older self-hosted store
// implementations keep compiling, but production FileStore and PgStore both
// implement it.
func (g *Gateway) mcpClientStore() (MCPClientStore, bool) {
	store, ok := g.store.(MCPClientStore)
	return store, ok
}

// buildMCPClient projects one durable client registration into its dedicated
// /mcp/clients/{slug} surface. The registry itself owns authorization; this
// method builds only the tool projection and therefore rechecks every account
// boundary defensively rather than trusting a human-readable folder label.
func (g *Gateway) buildMCPClient(client MCPClient) error {
	if client.Status != MCPClientStatusActive || client.Slug == "" || client.Epoch == "" {
		return fmt.Errorf("MCP client is not live")
	}
	namespaceIDs := toSet(client.ConnectionNamespaceIDs)
	accounts := g.store.Accounts()

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.clientEndpoints == nil {
		g.clientEndpoints = map[string]*connectorServer{}
	}
	endpoint, ok := g.clientEndpoints[client.Slug]
	if !ok {
		m := server.NewMCPServer("narthex-client-"+client.Slug, "0.1.0", server.WithToolCapabilities(true))
		endpoint = &connectorServer{
			mcp:     m,
			handler: server.NewStreamableHTTPServer(m, server.WithEndpointPath("/mcp/clients/"+client.Slug)),
			kind:    endpointKindClient,
		}
		g.clientEndpoints[client.Slug] = endpoint
	}
	endpoint.kind = endpointKindClient
	endpoint.epoch = client.Epoch
	endpoint.revision = client.Revision
	endpoint.guards = nil

	var names []string
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
			names = append(names, tool.tool.Name)
		}
	}
	if len(endpoint.names) > 0 {
		endpoint.mcp.DeleteTools(endpoint.names...)
	}
	for _, tool := range tools {
		endpoint.mcp.AddTool(tool.tool, tool.handler)
	}
	endpoint.names = names
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
	return g.refreshMCPClientsLocked(ctx)
}

// refreshMCPClientsLocked requires endpointMu. It intentionally keeps the
// OAuth revoker outside Gateway.mu: revocation can acquire OAuth locks and
// must never run while a request handler is holding the live endpoint map.
func (g *Gateway) refreshMCPClientsLocked(ctx context.Context) error {
	store, ok := g.mcpClientStore()
	if !ok {
		g.mu.Lock()
		stale := make([]string, 0, len(g.clientEndpoints))
		for slug := range g.clientEndpoints {
			stale = append(stale, slug)
		}
		g.clientEndpoints = map[string]*connectorServer{}
		revoke := g.revokeResource
		g.mu.Unlock()
		if revoke != nil {
			for _, slug := range stale {
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
		if err := g.buildMCPClient(client); err != nil {
			return fmt.Errorf("build MCP client %q: %w", client.Slug, err)
		}
		seen[client.Slug] = client.Epoch
	}

	g.mu.Lock()
	var revoked []string
	for slug := range g.clientEndpoints {
		epoch, live := seen[slug]
		if !live {
			delete(g.clientEndpoints, slug)
			revoked = append(revoked, slug)
			continue
		}
		// If a previous endpoint generation was served before this refresh,
		// discard pending OAuth code/refresh state for its path as a faster
		// complement to the epoch check in RequireAuth.
		if previousEpochs[slug] != "" && previousEpochs[slug] != epoch {
			revoked = append(revoked, slug)
		}
	}
	revoke := g.revokeResource
	g.mu.Unlock()
	if revoke != nil {
		for _, slug := range revoked {
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
		// Rebuild directly from durable state at the request boundary. This
		// keeps tools/list as fresh as the current folder/account assignment on
		// every replica, rather than relying on console process affinity.
		if err := g.refreshMCPClientRequest(r.Context(), slug); err != nil {
			if errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "MCP client endpoint unavailable", http.StatusServiceUnavailable)
			return
		}
		g.mu.Lock()
		live, found := g.clientEndpoints[slug]
		var handler http.Handler
		if found && live.kind == endpointKindClient {
			handler = live.handler
		}
		g.mu.Unlock()
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
// new token being minted for a rebound OAuth client.
func (g *Gateway) MCPClientAllowsOAuthClient(oauthClientID, resource string) bool {
	slug, ok := mcpClientSlugFromResource(resource)
	if !ok || strings.TrimSpace(oauthClientID) == "" {
		return false
	}
	store, ok := g.mcpClientStore()
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, ok := store.ActiveMCPClient(ctx, slug)
	if !ok || client.OAuthClientID != oauthClientID {
		return false
	}
	if g.mcpClientProjectionMatches(client) {
		return true
	}
	// This callback runs outside oauthas's generation lock. A replica that has
	// observed a durable reset/rebind but not the corresponding console refresh
	// repairs its own projection before it can authorize the DCR identity.
	// Failure remains fail-closed: an old refresh grant must never be upgraded
	// against a stale endpoint epoch.
	if err := g.RefreshMCPClients(ctx); err != nil {
		return false
	}
	return g.mcpClientProjectionMatches(client)
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
// replaces it.
func (g *Gateway) AuthorizeMCPConsent(ctx context.Context, subject, role, oauthClientID, resource string) error {
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
	client, found := store.ActiveMCPClient(ctx, slug)
	if !found {
		return errors.New("MCP client endpoint is unavailable")
	}
	actor := PlatformActor{UserID: subject, Role: role}
	if !MCPClientAllowsActor(client, actor) {
		return errors.New("actor cannot authorize this MCP client")
	}
	if client.OAuthClientID != "" && client.OAuthClientID != oauthClientID {
		return ErrMCPClientOAuthBinding
	}
	if client.OAuthClientID == "" {
		bound, err := store.BindMCPClientOAuthClient(ctx, client.ID, oauthClientID, MCPClientPrecondition{
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
					return ErrMCPClientOAuthBinding
				}
			} else {
				return err
			}
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
	// Read only after acquiring the projection mutex. Reading first leaves a
	// window in which a console mutation publishes a newer epoch/toolset and
	// this request then overwrites it with a stale client snapshot.
	client, found := store.ActiveMCPClient(ctx, slug)
	if !found {
		return ErrMCPClientNotFound
	}
	if err := g.buildMCPClient(client); err != nil {
		return err
	}
	return nil
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
	client, ok := store.ActiveMCPClient(ctx, slug)
	if !ok {
		return false
	}
	account, ok := g.store.Account(accountName)
	if !ok || accountIncarnationID == "" || account.IncarnationID != accountIncarnationID ||
		!toSet(client.ConnectionNamespaceIDs)[account.ConnectionNamespaceID] {
		return false
	}
	return !account.IsPersonal() || account.OwnerSubject == client.Subject
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
