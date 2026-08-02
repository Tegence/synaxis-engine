package engine

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/upstreamoauth"
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

func TestSameProviderAccountsKeepDistinctToolNamespaces(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"notion_work":     {"search", "fetch"},
		"notion_personal": {"search", "fetch"},
	})
	ctx := context.Background()
	workAccount, ok := g.store.Account("notion_work")
	if !ok {
		t.Fatal("work account missing")
	}
	if err := g.store.SetMeta(ctx, "notion_work", "Notion · Work", workAccount.Group); err != nil {
		t.Fatalf("label work account: %v", err)
	}
	personalAccount, ok := g.store.Account("notion_personal")
	if !ok {
		t.Fatal("personal account missing")
	}
	if err := g.store.SetMeta(ctx, "notion_personal", "Notion · Personal", personalAccount.Group); err != nil {
		t.Fatalf("label personal account: %v", err)
	}
	g.Aggregate(ctx)

	g.mu.Lock()
	defer g.mu.Unlock()
	work := g.cached["notion_work"]
	personal := g.cached["notion_personal"]
	if len(work) != 2 || len(personal) != 2 {
		t.Fatalf("cached tool counts = %d/%d; want 2/2", len(work), len(personal))
	}
	if work[0].tool.Name == personal[0].tool.Name {
		t.Fatalf("same-provider tool collision: %q", work[0].tool.Name)
	}
	if work[0].tool.Name != "notion_work__search" || personal[0].tool.Name != "notion_personal__search" {
		t.Fatalf("tool identities = %q/%q; want account-prefix names", work[0].tool.Name, personal[0].tool.Name)
	}
	if work[0].tool.Title != "Notion · Work · search" || personal[0].tool.Title != "Notion · Personal · search" {
		t.Fatalf("tool titles = %q/%q; want account labels", work[0].tool.Title, personal[0].tool.Title)
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

func TestReplaceAccountFailureKeepsLastKnownGoodToolsAndEndpoints(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue", "old_tool"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Tools: map[string][]string{"linear": {"get_issue", "old_tool"}},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	ns, err := g.CreateNamespace(ctx, Namespace{
		Slug: "all_tools", Label: "All tools", Accounts: []string{"linear"},
	})
	if err != nil {
		t.Fatalf("create endpoint bundle: %v", err)
	}

	g.mu.Lock()
	beforeCached := append([]cachedTool(nil), g.cached["linear"]...)
	beforeRoot := append([]string(nil), g.byAcct["linear"]...)
	g.mu.Unlock()
	g.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		return nil, errors.New("temporary upstream failure")
	}

	if _, err := g.ReplaceAccount(ctx, "linear"); err == nil {
		t.Fatal("ReplaceAccount succeeded despite failed upstream list")
	}
	g.mu.Lock()
	afterCached := append([]cachedTool(nil), g.cached["linear"]...)
	afterRoot := append([]string(nil), g.byAcct["linear"]...)
	g.mu.Unlock()
	if !eq(afterRoot, beforeRoot) || len(afterCached) != len(beforeCached) {
		t.Fatalf("failed replacement changed root cache: names %v -> %v, cached %d -> %d",
			beforeRoot, afterRoot, len(beforeCached), len(afterCached))
	}
	if got := connectorNames(t, g, "curated"); !eq(got, []string{"linear__get_issue", "linear__old_tool"}) {
		t.Fatalf("failed replacement changed curated endpoint: %v", got)
	}
	if got := connectorNames(t, g, "all_tools"); !eq(got, []string{"linear__get_issue", "linear__old_tool"}) {
		t.Fatalf("failed replacement changed bundle endpoint: %v", got)
	}
	stored, ok := g.store.(NamespaceStore).Namespace(ctx, "all_tools")
	if !ok || stored.Epoch != ns.Epoch || !sameStrings(stored.Accounts, []string{"linear"}) {
		t.Fatalf("failed replacement changed endpoint membership: %+v ok=%v", stored, ok)
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

func TestStaleAccountHandlerCannotUseReplacementCredentials(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{"notion": {"search"}})
	first, _ := g.store.Account("notion")
	first.URL = "https://notion.example/mcp"
	first.BearerToken = "first-token"
	if err := g.store.Upsert(ctx, first); err != nil {
		t.Fatalf("seed first account: %v", err)
	}
	first, _ = g.store.Account("notion")
	if count := g.Aggregate(ctx); count != 1 {
		t.Fatalf("aggregate count = %d", count)
	}
	g.mu.Lock()
	staleHandler := g.cached[first.Name][0].handler
	g.mu.Unlock()

	if err := g.store.Delete(ctx, first.Name, first.IncarnationID, first.Revision); err != nil {
		t.Fatalf("delete first account: %v", err)
	}
	if err := g.store.Create(ctx, Account{
		Name: first.Name, URL: first.URL, AuthMode: "token", BearerToken: "replacement-secret",
	}); err != nil {
		t.Fatalf("create replacement: %v", err)
	}
	replacement, _ := g.store.Account(first.Name)
	if replacement.IncarnationID == first.IncarnationID {
		t.Fatal("test replacement reused the first incarnation")
	}
	staleUpstream := g.upstreamFor(first)
	if staleUpstream.Available() || staleUpstream.Token() != "" {
		t.Fatal("stale upstream resolved the replacement account or its credential")
	}

	result, err := staleHandler(ctx, mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("stale handler protocol error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("stale handler result = %+v, want fail-closed tool error", result)
	}
}

func TestStaleAggregationAndRemovalCannotOverwriteReplacementProjection(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{"notion": {}})
	first, _ := g.store.Account("notion")
	started := make(chan struct{})
	release := make(chan struct{})
	g.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		if account.IncarnationID == first.IncarnationID {
			close(started)
			<-release
			return []mcp.Tool{mcp.NewTool(account.Name + "__old_tool")}, nil
		}
		return []mcp.Tool{mcp.NewTool(account.Name + "__new_tool")}, nil
	}

	staleResult := make(chan error, 1)
	go func() {
		_, err := g.AddAccount(ctx, first.Name)
		staleResult <- err
	}()
	<-started
	if err := g.store.Delete(ctx, first.Name, first.IncarnationID, first.Revision); err != nil {
		t.Fatalf("delete first account: %v", err)
	}
	if err := g.store.Create(ctx, Account{
		Name: first.Name, URL: first.URL, AuthMode: "token", BearerToken: "replacement",
	}); err != nil {
		t.Fatalf("create replacement: %v", err)
	}
	replacement, _ := g.store.Account(first.Name)
	if _, err := g.AddAccount(ctx, replacement.Name); err != nil {
		t.Fatalf("aggregate replacement: %v", err)
	}
	close(release)
	if err := <-staleResult; !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale aggregation error = %v, want ErrAccountIncarnation", err)
	}

	// A delayed teardown for the deleted row must not unregister the replacement
	// that now owns the same model-visible tool prefix.
	g.RemoveAccount(first.Name, first.IncarnationID)
	g.mu.Lock()
	projected := g.projectedIncarnations[first.Name]
	rootNames := append([]string(nil), g.byAcct[first.Name]...)
	cached := append([]cachedTool(nil), g.cached[first.Name]...)
	g.mu.Unlock()
	if projected != replacement.IncarnationID || len(rootNames) != 1 || rootNames[0] != "notion__new_tool" ||
		len(cached) != 1 || cached[0].accountIncarnationID != replacement.IncarnationID {
		t.Fatalf("replacement projection was overwritten/removed: projected=%q root=%v cached=%+v", projected, rootNames, cached)
	}
}

func TestRefreshAccountCannotPersistIntoReplacementIncarnation(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{"notion": {}})
	first, _ := g.store.Account("notion")
	first.URL = "https://notion.example/mcp"
	first.AuthMode = "oauth"
	first.ClientID = "first-client"
	first.RefreshToken = "first-refresh"
	first.AccessToken = "first-access"
	first.TokenEndpoint = "https://notion.example/token"
	if err := g.store.Upsert(ctx, first); err != nil {
		t.Fatalf("seed OAuth account: %v", err)
	}
	first, _ = g.store.Account(first.Name)
	g.refreshTokens = func(context.Context, *upstreamoauth.Metadata, string, string, string) (*upstreamoauth.Tokens, error) {
		if err := g.store.Delete(ctx, first.Name, first.IncarnationID, first.Revision); err != nil {
			t.Fatalf("delete during refresh: %v", err)
		}
		if err := g.store.Create(ctx, Account{
			Name: first.Name, URL: first.URL, AuthMode: "token", BearerToken: "replacement-secret",
		}); err != nil {
			t.Fatalf("create replacement during refresh: %v", err)
		}
		return &upstreamoauth.Tokens{AccessToken: "stale-access", RefreshToken: "stale-refresh"}, nil
	}

	if err := g.refreshAccount(ctx, first.Name, first.IncarnationID); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("refresh error = %v, want ErrAccountIncarnation", err)
	}
	replacement, ok := g.store.Account(first.Name)
	if !ok || replacement.IncarnationID == first.IncarnationID || replacement.AuthMode != "token" ||
		replacement.BearerToken != "replacement-secret" || replacement.AccessToken != "" || replacement.RefreshToken != "" {
		t.Fatalf("stale refresh mutated replacement: %+v, ok=%v", replacement, ok)
	}
}
