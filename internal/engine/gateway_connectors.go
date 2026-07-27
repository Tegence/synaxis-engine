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

// connectorServer is one virtual connector's live MCP endpoint: its own
// MCPServer (mcp-go answers tools/list from the registered set, so a curated
// subset needs its own instance) plus the Streamable HTTP transport for it.
// The MCPServer instance is stable across rebuilds — toolset changes mutate it
// via AddTool/DeleteTools so in-flight sessions survive.
type connectorServer struct {
	mcp     *server.MCPServer
	handler http.Handler // StreamableHTTPServer for /mcp/{slug}
	names   []string     // currently registered (prefixed) tool names
	epoch   string       // token generation (VirtualConnector.Epoch); read by the OAuth AS
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

// buildConnector creates (or refreshes) the per-connector MCP server for vc by
// filtering the cached tools: for each account in vc.Tools, a cached tool is
// included iff its BARE name (prefix stripped) is in that account's allowlist.
// Unknown accounts and empty allowlists contribute nothing. Tools also listed
// in vc.Approval get the approval-parking wrapper — rebuilds always re-wrap
// from the CURRENT store state, since vc comes from the store on every refresh.
func (g *Gateway) buildConnector(vc VirtualConnector) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[vc.Slug]
	if !ok {
		m := server.NewMCPServer("narthex-"+vc.Slug, "0.1.0", server.WithToolCapabilities(true))
		cs = &connectorServer{
			mcp:     m,
			handler: server.NewStreamableHTTPServer(m, server.WithEndpointPath("/mcp/"+vc.Slug)),
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
		allowSet := toSet(allow)
		if len(allowSet) == 0 {
			continue // account listed but nothing enabled — contributes nothing
		}
		approvalSet := toSet(vc.Approval[acct]) // source BARE names, intersected with the allowlist
		for _, ct := range g.cached[acct] {
			bare := ct.sourceName
			if !allowSet[bare] {
				continue
			}
			if approvalSet[bare] {
				// require_approval: park the call for a human decision first.
				// ct is a copy — the cached (main /mcp) handler stays unwrapped;
				// that's safe because access tokens are bound to the endpoint
				// path they were authorized for (oauthas), so a connector token
				// cannot reach the ungated /mcp surface.
				ct.handler = g.approvalHandler(vc.Slug, acct, bare, ct.handler)
			}
			// Outermost: stamp every call on this endpoint with the connector
			// name, its Record flag, and its compiled guards (read by the
			// shared dispatch closure — and by the approval wrapper — via
			// ctx). Full composition: scope → approval parks → dispatch →
			// guards (redact → cap → injection scan) → audit → return. The
			// cached (main /mcp) handler stays unscoped: it logs with
			// connector "", follows the gateway-wide recordDefault, and runs
			// NO guards (raw passthrough by design).
			ct.handler = g.scopedHandler(vc.Slug, vc.Record, &cg, ct.handler)
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
}

// RefreshConnectors rebuilds every connector server from the store (called
// after any account change so curated subsets track the live tool cache).
// No-op when the store has no connector support.
func (g *Gateway) RefreshConnectors(ctx context.Context) {
	cs, ok := g.connectorStore()
	if !ok {
		return
	}
	list, err := cs.Connectors(ctx)
	if err != nil {
		log.Printf("engine: refresh connectors: %v", err)
		return
	}
	seen := make(map[string]bool, len(list))
	for _, vc := range list {
		g.buildConnector(vc)
		seen[vc.Slug] = true
	}
	g.mu.Lock() // drop servers whose connector no longer exists in the store
	for slug := range g.connectors {
		if !seen[slug] {
			delete(g.connectors, slug)
		}
	}
	g.mu.Unlock()
}

// UpsertConnector writes vc through the store, then (re)builds its live server.
// A connector without an epoch gets one: preserved from the stored row on
// update, freshly minted on create — so recreating a deleted slug invalidates
// every access token issued for the previous incarnation (the AS bakes the
// epoch into the token HMAC).
func (g *Gateway) UpsertConnector(ctx context.Context, vc VirtualConnector) error {
	cs, ok := g.connectorStore()
	if !ok {
		return fmt.Errorf("store does not support connectors")
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
	g.buildConnector(vc)
	return nil
}

// DeleteConnector removes vc from the store and tears down its live server
// (subsequent requests to /mcp/{slug} 404). It also revokes AS state for the
// endpoint: outstanding access tokens die via the epoch check (the slug no
// longer resolves, and a recreated slug gets a fresh epoch), and the wired
// revoker drops the endpoint's refresh grants so they can't mint new tokens.
func (g *Gateway) DeleteConnector(ctx context.Context, slug string) error {
	cs, ok := g.connectorStore()
	if !ok {
		return fmt.Errorf("store does not support connectors")
	}
	if err := cs.DeleteConnector(ctx, slug); err != nil {
		return err
	}
	g.mu.Lock()
	delete(g.connectors, slug)
	revoke := g.revokeResource
	g.mu.Unlock()
	if revoke != nil {
		revoke("/mcp/" + slug)
	}
	return nil
}

// SetTokenRevoker wires the OAuth AS callback that drops refresh grants (and
// pending auth codes) for a resource path when its connector is deleted. An
// injected func rather than an oauthas import keeps the seam one-directional.
func (g *Gateway) SetTokenRevoker(fn func(resourcePath string)) {
	g.mu.Lock()
	g.revokeResource = fn
	g.mu.Unlock()
}

// ConnectorEpoch resolves a slug to the epoch of its LIVE connector server —
// the AS-side lookup that binds access tokens to a connector generation.
// ok=false when no such connector is currently served (deleted or never
// created), which makes the AS fail closed for that path.
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

// ConnectorHandler returns the live Streamable HTTP handler for a slug.
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
