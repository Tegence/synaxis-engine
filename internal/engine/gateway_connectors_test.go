package engine

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// newConnectorTestGateway builds a Gateway over a FileStore (which satisfies
// both AccountStore and ConnectorStore) with the upstream dial replaced by the
// listTools seam: tools[account] = bare names, returned prefixed exactly like
// Upstream.ListTools does in production.
func newConnectorTestGateway(t *testing.T, tools map[string][]string) *Gateway {
	t.Helper()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	for name := range tools {
		if err := fs.Upsert(context.Background(), Account{Name: name, URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
			t.Fatalf("upsert account: %v", err)
		}
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		var out []mcp.Tool
		for _, bare := range tools[a.Name] {
			out = append(out, mcp.NewTool(a.Name+"__"+bare, mcp.WithDescription("test tool "+bare)))
		}
		return out, nil
	}
	return g
}

func connectorNames(t *testing.T, g *Gateway, slug string) []string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	cs, ok := g.connectors[slug]
	if !ok {
		t.Fatalf("connector %q has no server", slug)
	}
	out := append([]string(nil), cs.names...)
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConnectorFilteringBareVsPrefixed(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue", "save_issue"},
		"notion": {"search", "fetch"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)

	// Allowlists are BARE names; a prefixed entry must NOT match.
	err := g.UpsertConnector(ctx, VirtualConnector{
		Slug:  "work",
		Label: "Work",
		Tools: map[string][]string{
			"linear": {"get_issue", "linear__save_issue"}, // 2nd is wrongly prefixed → ignored
			"notion": {"search"},
		},
	})
	if err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	want := []string{"linear__get_issue", "notion__search"}
	if got := connectorNames(t, g, "work"); !eq(got, want) {
		t.Fatalf("connector tools = %v, want %v", got, want)
	}
}

func TestConnectorEmptyAllowlistAndUnknownAccount(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)

	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "empty",
		Tools: map[string][]string{
			"linear": {},           // listed but empty → contributes nothing
			"ghost":  {"anything"}, // account not aggregated → contributes nothing
		},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if got := connectorNames(t, g, "empty"); len(got) != 0 {
		t.Fatalf("expected no tools, got %v", got)
	}
	// The endpoint still exists (serves an empty toolset), it isn't a 404.
	if _, ok := g.ConnectorHandler("empty"); !ok {
		t.Fatal("expected a live handler for an empty connector")
	}
}

func TestConnectorRebuildOnReplaceAccount(t *testing.T) {
	tools := map[string][]string{
		"linear": {"get_issue", "old_tool"},
	}
	g := newConnectorTestGateway(t, tools)
	ctx := context.Background()
	g.Aggregate(ctx)

	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug:  "lin",
		Tools: map[string][]string{"linear": {"get_issue", "old_tool", "new_tool"}},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if got, want := connectorNames(t, g, "lin"), []string{"linear__get_issue", "linear__old_tool"}; !eq(got, want) {
		t.Fatalf("before replace: %v, want %v", got, want)
	}

	// Upstream toolset changes; ReplaceAccount must refresh the connector.
	tools["linear"] = []string{"get_issue", "new_tool"}
	if _, err := g.ReplaceAccount(ctx, "linear"); err != nil {
		t.Fatalf("replace account: %v", err)
	}
	if got, want := connectorNames(t, g, "lin"), []string{"linear__get_issue", "linear__new_tool"}; !eq(got, want) {
		t.Fatalf("after replace: %v, want %v", got, want)
	}

	// MCPServer instance must be the same one across the rebuild.
	g.mu.Lock()
	before := g.connectors["lin"].mcp
	g.mu.Unlock()
	if _, err := g.ReplaceAccount(ctx, "linear"); err != nil {
		t.Fatalf("second replace: %v", err)
	}
	g.mu.Lock()
	after := g.connectors["lin"].mcp
	g.mu.Unlock()
	if before != after {
		t.Fatal("connector MCPServer instance was replaced; must stay stable for in-flight sessions")
	}
}

func TestConnectorDeleteAndHandlerLookup(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"linear": {"get_issue"}})
	ctx := context.Background()
	g.Aggregate(ctx)

	if _, ok := g.ConnectorHandler("nope"); ok {
		t.Fatal("unknown slug should have no handler")
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "x", Tools: map[string][]string{"linear": {"get_issue"}}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, ok := g.ConnectorHandler("x"); !ok {
		t.Fatal("expected handler after upsert")
	}
	if err := g.DeleteConnector(ctx, "x"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := g.ConnectorHandler("x"); ok {
		t.Fatal("handler should be gone after delete")
	}
	// And it must not resurrect on the next account-change refresh.
	if _, err := g.ReplaceAccount(ctx, "linear"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, ok := g.ConnectorHandler("x"); ok {
		t.Fatal("deleted connector resurrected by refresh")
	}
}

// The epoch is the revocation seam with the OAuth AS: minted on create,
// preserved across updates, gone (lookup fails) after delete, FRESH on
// recreate — and delete fires the wired refresh-grant revoker for the path.
func TestConnectorEpochLifecycle(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"linear": {"get_issue"}})
	ctx := context.Background()
	g.Aggregate(ctx)

	var revoked []string
	g.SetTokenRevoker(func(path string) { revoked = append(revoked, path) })

	if _, ok := g.ConnectorEpoch("team"); ok {
		t.Fatal("nonexistent connector must not resolve an epoch (pre-authorization)")
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "team", Tools: map[string][]string{"linear": {"get_issue"}}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	e1, ok := g.ConnectorEpoch("team")
	if !ok || e1 == "" {
		t.Fatalf("create must mint a nonempty epoch, got %q ok=%v", e1, ok)
	}
	// Update (console PUT round-trips the stored row; a bare update with no
	// epoch must also preserve it, not rotate it).
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "team", Label: "Team", Tools: map[string][]string{"linear": {"get_issue"}}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if e, _ := g.ConnectorEpoch("team"); e != e1 {
		t.Fatalf("update rotated the epoch: %q -> %q (would invalidate live tokens)", e1, e)
	}

	if err := g.DeleteConnector(ctx, "team"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := g.ConnectorEpoch("team"); ok {
		t.Fatal("deleted connector must not resolve an epoch")
	}
	if len(revoked) != 1 || revoked[0] != "/mcp/team" {
		t.Fatalf("delete must revoke refresh grants for /mcp/team, got %v", revoked)
	}

	// Recreating the slug mints a DIFFERENT epoch — old tokens stay dead.
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "team", Tools: map[string][]string{"linear": {"get_issue"}}}); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if e2, _ := g.ConnectorEpoch("team"); e2 == e1 {
		t.Fatal("recreated slug must not reuse the deleted connector's epoch")
	}
}

func TestConnectorStats(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue", "save_issue"},
		"notion": {"search", "fetch"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "s", Tools: map[string][]string{"linear": {"get_issue"}}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	st, err := g.ConnectorStats(ctx, "s")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.ExposedTools != 1 || st.TotalTools != 4 {
		t.Fatalf("tools = %d/%d, want 1/4", st.ExposedTools, st.TotalTools)
	}
	if st.ExposedBytes <= 0 || st.TotalBytes <= st.ExposedBytes {
		t.Fatalf("bytes = %d/%d, want 0 < exposed < total", st.ExposedBytes, st.TotalBytes)
	}
	if _, err := g.ConnectorStats(ctx, "missing"); err == nil {
		t.Fatal("expected error for unknown slug")
	}
}
