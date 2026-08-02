package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func connectionNamespacePrecondition(ns ConnectionNamespace) ConnectionNamespacePrecondition {
	return ConnectionNamespacePrecondition{ID: ns.ID, Revision: ns.Revision}
}

func TestFileStoreBackfillsLegacyGroupsAsSharedConnectionNamespaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	legacy := []Account{{
		Name: "notion_legacy", Label: "Notion · Lelapa", Group: "Lelapa",
		URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "secret",
	}}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("load legacy store: %v", err)
	}
	account, ok := store.Account("notion_legacy")
	if !ok {
		t.Fatal("legacy account missing")
	}
	if account.ConnectionScope != ConnectionScopeShared || account.ConnectionNamespaceID == "" || account.Revision != 1 || account.IncarnationID == "" {
		t.Fatalf("legacy account ownership = %+v; want explicitly shared with namespace and revision", account)
	}
	if account.Group != "Lelapa" || account.BearerToken != "secret" {
		t.Fatalf("legacy account data changed during backfill: %+v", account)
	}
	ns, ok := store.ConnectionNamespace(context.Background(), account.ConnectionNamespaceID)
	if !ok || ns.Label != "Lelapa" || ns.Slug != "lelapa" || ns.Revision != 1 || ns.CreatedAt.IsZero() || ns.UpdatedAt.IsZero() {
		t.Fatalf("legacy namespace = %+v, ok=%v", ns, ok)
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	again, ok := reopened.Account("notion_legacy")
	if !ok || again.ConnectionNamespaceID != account.ConnectionNamespaceID || again.ConnectionScope != ConnectionScopeShared || again.IncarnationID != account.IncarnationID {
		t.Fatalf("migrated account did not persist: %+v", again)
	}
}

func TestConnectionNamespaceCASCreatorGrantCanBeRevokedAndStableAccountPrefix(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Private research", CreatedBy: "user:alice",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "user:bob"}},
	})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	if ns.ID == "" || ns.Slug != "private-research" || ns.CreatedAt.IsZero() || ns.UpdatedAt.IsZero() {
		t.Fatalf("generated namespace fields = %+v", ns)
	}
	if !sameManagerGrants(ns.ManagerGrants, []ConnectionNamespaceManagerGrant{{Subject: "user:alice"}, {Subject: "user:bob"}}) {
		t.Fatalf("creator must receive a durable manager grant: %+v", ns.ManagerGrants)
	}

	if err := store.Create(ctx, Account{
		Name: "notion_labs", Label: "Notion Labs", Group: "General", URL: "https://notion.example/mcp",
		AuthMode: "token", BearerToken: "credential-must-survive",
	}); err != nil {
		t.Fatalf("create shared account: %v", err)
	}
	before, _ := store.Account("notion_labs")
	moved, err := store.MoveAccountToConnectionNamespace(ctx, "notion_labs", before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: ns.ID, Scope: ConnectionScopePersonal, OwnerSubject: "user:alice",
	}, before.Revision)
	if err != nil {
		t.Fatalf("move account: %v", err)
	}
	if moved.Name != "notion_labs" || moved.BearerToken != "credential-must-survive" || moved.ConnectionNamespaceID != ns.ID ||
		moved.ConnectionScope != ConnectionScopePersonal || moved.OwnerSubject != "user:alice" || moved.Group != ns.Label || moved.Revision != before.Revision+1 {
		t.Fatalf("move changed more than ownership fields: before=%+v after=%+v", before, moved)
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, "notion_labs", before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: ns.ID, Scope: ConnectionScopePersonal, OwnerSubject: "user:alice",
	}, before.Revision); !errors.Is(err, ErrConnectionNamespaceRevision) {
		t.Fatalf("stale move = %v; want revision conflict", err)
	}
	// Legacy whole-account writers omit the new ownership fields. They must
	// not accidentally declassify a personal connection back to shared.
	if err := store.Upsert(ctx, Account{Name: "notion_labs", Label: "Renamed", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "credential-must-survive"}); err != nil {
		t.Fatalf("legacy upsert: %v", err)
	}
	preserved, _ := store.Account("notion_labs")
	if preserved.ConnectionScope != ConnectionScopePersonal || preserved.ConnectionNamespaceID != ns.ID || preserved.OwnerSubject != "user:alice" {
		t.Fatalf("legacy upsert declassified personal account: %+v", preserved)
	}

	updated, err := store.SetConnectionNamespaceManagers(ctx, ns.ID, nil, connectionNamespacePrecondition(ns))
	if err != nil {
		t.Fatalf("replace managers: %v", err)
	}
	if len(updated.ManagerGrants) != 0 || connectionNamespaceManager(updated, "user:alice") {
		t.Fatalf("creator manager grant remained after revocation: %+v", updated.ManagerGrants)
	}
	renamed, err := store.UpdateConnectionNamespace(ctx, ConnectionNamespace{
		ID: ns.ID, Label: "Archived research", ManagerGrants: updated.ManagerGrants,
	}, connectionNamespacePrecondition(updated))
	if err != nil {
		t.Fatalf("rename after manager revocation: %v", err)
	}
	if len(renamed.ManagerGrants) != 0 || connectionNamespaceManager(renamed, "user:alice") {
		t.Fatalf("namespace update restored revoked creator manager: %+v", renamed.ManagerGrants)
	}
	if _, err := store.UpdateConnectionNamespace(ctx, ConnectionNamespace{ID: ns.ID, Label: "stale", ManagerGrants: updated.ManagerGrants}, connectionNamespacePrecondition(ns)); !errors.Is(err, ErrConnectionNamespaceRevision) {
		t.Fatalf("stale namespace update = %v; want revision conflict", err)
	}
}

func TestPersonalAccountsCannotEnterSharedDataPlane(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	sharedNS, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	personalNS, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Alice private", CreatedBy: "user:alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{Name: "team_notion", ConnectionNamespaceID: sharedNS.ID, ConnectionScope: ConnectionScopeShared, URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team"},
		{Name: "alice_notion", ConnectionNamespaceID: personalNS.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "user:alice", URL: "https://alice.example/mcp", AuthMode: "token", BearerToken: "alice"},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatalf("create %s: %v", account.Name, err)
		}
	}
	if err := store.CreateNamespace(ctx, Namespace{Slug: "team-endpoint", Label: "Team", Accounts: []string{"alice_notion"}}); !errors.Is(err, ErrPersonalAccountExposure) {
		t.Fatalf("endpoint bundle admitted personal account: %v", err)
	}
	if err := store.UpsertConnector(ctx, VirtualConnector{Slug: "team-tools", Tools: map[string][]string{"alice_notion": {"search"}}}); !errors.Is(err, ErrPersonalAccountExposure) {
		t.Fatalf("virtual connector admitted personal account: %v", err)
	}

	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}
	g.Aggregate(ctx)
	g.mu.Lock()
	_, sharedCached := g.cached["team_notion"]
	_, personalCached := g.cached["alice_notion"]
	personalRoot := append([]string(nil), g.byAcct["alice_notion"]...)
	g.mu.Unlock()
	if !sharedCached || !personalCached || len(personalRoot) != 0 {
		t.Fatalf("aggregate shared=%v personalCached=%v personalRoot=%v; personal account leaked into /mcp", sharedCached, personalCached, personalRoot)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{Slug: "still-no-personal", Tools: map[string][]string{"alice_notion": {"search"}}}); !errors.Is(err, ErrPersonalAccountExposure) {
		t.Fatalf("gateway connector admitted personal account: %v", err)
	}
}

func TestPersonalMovePrunesExistingSharedExposure(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: "notion", Group: "Team", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "x"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("notion")
	if err := store.CreateNamespace(ctx, Namespace{Slug: "team", Label: "Team", Accounts: []string{"notion"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertConnector(ctx, VirtualConnector{Slug: "connector", Tools: map[string][]string{"notion": {"search"}}, Approval: map[string][]string{"notion": {"search"}}}); err != nil {
		t.Fatal(err)
	}
	personal, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Personal", CreatedBy: "user:alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, "notion", account.IncarnationID, AccountConnectionAssignment{ConnectionNamespaceID: personal.ID, Scope: ConnectionScopePersonal, OwnerSubject: "user:alice"}, account.Revision); err != nil {
		t.Fatalf("move personal: %v", err)
	}
	endpoint, _ := store.Namespace(ctx, "team")
	if len(endpoint.Accounts) != 0 || endpoint.Revision != 2 {
		t.Fatalf("personal move did not remove endpoint membership: %+v", endpoint)
	}
	connector, _ := store.VirtualConnector(ctx, "connector")
	if _, found := connector.Tools["notion"]; found {
		t.Fatalf("personal move did not remove connector tools: %+v", connector.Tools)
	}
	if _, found := connector.Approval["notion"]; found {
		t.Fatalf("personal move did not remove connector approval map: %+v", connector.Approval)
	}
}

func TestGatewayMoveToPersonalRemovesLiveRootProjection(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: "notion", Group: "Team", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "x"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("notion")
	personal, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Private", CreatedBy: "user:alice"})
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	g.Aggregate(ctx)
	g.mu.Lock()
	_, before := g.cached["notion"]
	g.mu.Unlock()
	if !before {
		t.Fatal("precondition: shared account was not aggregated")
	}
	if _, err := g.MoveAccountToConnectionNamespace(ctx, "notion", account.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: personal.ID, Scope: ConnectionScopePersonal, OwnerSubject: "user:alice",
	}, account.Revision); err != nil {
		t.Fatalf("gateway move: %v", err)
	}
	g.mu.Lock()
	_, after := g.cached["notion"]
	rootTools := append([]string(nil), g.byAcct["notion"]...)
	g.mu.Unlock()
	if !after || len(rootTools) != 0 {
		t.Fatalf("personal move cache=%v rootTools=%v; personal tool leaked into root /mcp", after, rootTools)
	}
}
