package engine

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// callerDelegatedFixture stores one caller-delegated account and one ordinary
// shared account in the same folder, aggregates both, and returns the folder.
// Both list a single "search" tool through the gateway's listTools seam.
func callerDelegatedFixture(t *testing.T) (*FileStore, *Gateway, ConnectionNamespace) {
	t.Helper()
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Delegated", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "delegated", Label: "Delegated", URL: "https://delegated.example/api/v1/mcp", AuthMode: "token", BearerToken: "listing-key",
		ConnectionNamespaceID: folder.ID, CallerDelegated: true,
		ClientID: "client_test", ClientSecret: "secret_0123456789abcdef0123456789abcdef",
		TokenEndpoint: "https://delegated.example/api/v1/mcp/token", Resource: "https://delegated.example/api/v1/mcp",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "plain", Label: "Plain", URL: "https://plain.example/mcp", AuthMode: "token", BearerToken: "plain-token",
		ConnectionNamespaceID: folder.ID,
	}); err != nil {
		t.Fatal(err)
	}
	gateway.Aggregate(ctx)
	return store, gateway, folder
}

func TestCallerDelegatedAccountNotDeliveredByFolder(t *testing.T) {
	ctx := context.Background()
	store, gateway, folder := callerDelegatedFixture(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Folder agent", Subject: "agt_folder", Kind: MCPClientKindWorkload, ConnectionNamespaceIDs: []string{folder.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	names := clientEndpointToolNames(t, gateway, client.Slug)
	if !slices.Contains(names, "plain__search") {
		t.Fatalf("folder grant lost its ordinary account: %v", names)
	}
	if slices.Contains(names, "delegated__search") {
		t.Fatalf("folder grant listed a caller-delegated account: %v", names)
	}
	delegated, _ := store.Account("delegated")
	if mcpClientDeliversAccount(client, delegated) {
		t.Fatal("delivery predicate admitted a caller-delegated account through its folder")
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, client.Slug, delegated.Name, delegated.IncarnationID); ok {
		t.Fatal("dispatch admitted a caller-delegated account through its folder")
	}
}

func TestCallerDelegatedAccountNotOnRootMCP(t *testing.T) {
	ctx := context.Background()
	store, gateway, _ := callerDelegatedFixture(t)
	rootNames := func() []string {
		var names []string
		for name := range gateway.mcp.ListTools() {
			names = append(names, name)
		}
		return names
	}
	if names := rootNames(); slices.Contains(names, "delegated__search") || !slices.Contains(names, "plain__search") {
		t.Fatalf("root /mcp projection = %v; want plain only", names)
	}
	gateway.mu.Lock()
	byAccount := append([]string(nil), gateway.byAcct["delegated"]...)
	cachedTools := len(gateway.cached["delegated"])
	gateway.mu.Unlock()
	if len(byAccount) != 0 {
		t.Fatalf("root names recorded for a caller-delegated account: %v", byAccount)
	}
	if cachedTools == 0 {
		t.Fatal("caller-delegated tools must stay cached for exact client delivery")
	}

	// An ownership-only move rebinds the cache without re-listing; it must not
	// publish the account on root either.
	other, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Elsewhere", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Account("delegated")
	if _, err := gateway.MoveAccountToConnectionNamespace(ctx, before.Name, before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: other.ID, Scope: ConnectionScopeShared,
	}, before.Revision); err != nil {
		t.Fatal(err)
	}
	if names := rootNames(); slices.Contains(names, "delegated__search") {
		t.Fatalf("account move published a caller-delegated account on root: %v", names)
	}
}

func TestCallerDelegatedAccountNotThroughConnector(t *testing.T) {
	ctx := context.Background()
	store, gateway, _ := callerDelegatedFixture(t)
	if err := gateway.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Label: "Curated", Tools: map[string][]string{"delegated": {"search"}, "plain": {"search"}},
	}); !errors.Is(err, ErrCallerDelegatedAccountExposure) {
		t.Fatalf("connector naming a caller-delegated account: err=%v, want %v", err, ErrCallerDelegatedAccountExposure)
	}
	// A row that reached durable storage some other way (an older replica, an
	// import before this check) still projects nothing for the account.
	if err := store.UpsertConnector(ctx, VirtualConnector{
		Slug: "legacy", Label: "Legacy", Epoch: newEpoch(), Tools: map[string][]string{"delegated": {"search"}, "plain": {"search"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshConnectors(ctx); err != nil {
		t.Fatal(err)
	}
	if got := connectorNames(t, gateway, "legacy"); !slices.Equal(got, []string{"plain__search"}) {
		t.Fatalf("connector projection = %v; want plain only", got)
	}
}

func TestCallerDelegatedAccountNotThroughBundle(t *testing.T) {
	ctx := context.Background()
	store, gateway, _ := callerDelegatedFixture(t)
	if _, err := gateway.CreateNamespace(ctx, Namespace{Slug: "bundle", Label: "Bundle", Accounts: []string{"delegated", "plain"}}); !errors.Is(err, ErrCallerDelegatedAccountExposure) {
		t.Fatalf("bundle naming a caller-delegated account: err=%v, want %v", err, ErrCallerDelegatedAccountExposure)
	}
	created, err := gateway.CreateNamespace(ctx, Namespace{Slug: "bundle", Label: "Bundle", Accounts: []string{"plain"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.AddNamespaceAccount(ctx, created.Slug, "delegated", NamespacePrecondition{Generation: created.Epoch, Revision: created.Revision}); !errors.Is(err, ErrCallerDelegatedAccountExposure) {
		t.Fatalf("adding a caller-delegated account to a bundle: err=%v", err)
	}
	if _, err := gateway.UpdateNamespace(ctx, Namespace{Slug: created.Slug, Label: "Bundle", Accounts: []string{"plain", "delegated"}}, NamespacePrecondition{Generation: created.Epoch, Revision: created.Revision}); !errors.Is(err, ErrCallerDelegatedAccountExposure) {
		t.Fatalf("updating a bundle to a caller-delegated account: err=%v", err)
	}
	if err := store.CreateNamespace(ctx, Namespace{Slug: "legacy-bundle", Label: "Legacy", Epoch: newEpoch(), Revision: 1, Accounts: []string{"delegated", "plain"}}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshConnectors(ctx); err != nil {
		t.Fatal(err)
	}
	if got := connectorNames(t, gateway, "legacy-bundle"); !slices.Equal(got, []string{"plain__search"}) {
		t.Fatalf("bundle projection = %v; want plain only", got)
	}
}

func TestCallerDelegatedAccountNotThroughSharedToolGrant(t *testing.T) {
	ctx := context.Background()
	store, gateway, _ := callerDelegatedFixture(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Grant agent", Subject: "agt_grant", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	delegated, _ := store.Account("delegated")
	if _, err := store.CreateConnectionGrant(ctx, ConnectionGrant{
		Name: "Share", ConnectionID: delegated.Name, IncarnationID: delegated.IncarnationID, OwnerSubject: delegated.OwnerSubject,
		CreatedBy: "usr_owner", RecipientKind: "subject", RecipientRef: client.Subject, RecipientSubjects: []string{client.Subject},
		Tools: []string{"search"}, ExpiresAt: time.Now().Add(time.Hour),
	}, accountPolicyPrecondition(delegated)); err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if names := clientEndpointToolNames(t, gateway, client.Slug); slices.Contains(names, "delegated__search") {
		t.Fatalf("shared tool grant listed a caller-delegated account: %v", names)
	}
	grants, err := store.ConnectionGrants(ctx)
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants=%v err=%v", grants, err)
	}
	if connectionGrantAllows(grants[0], delegated, client.Subject, "search", time.Now()) {
		t.Fatal("dispatch would admit a caller-delegated account through a shared tool grant")
	}
}

func TestCallerDelegatedAccountDeliveredByExactGrant(t *testing.T) {
	ctx := context.Background()
	store, gateway, _ := callerDelegatedFixture(t)
	workload, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Exact agent", Subject: "agt_exact", Kind: MCPClientKindWorkload, ConnectionIDs: []string{"delegated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// An interactive client can be given the exact grant, but the account acts
	// only for whoever started a job, so it is never delivered to it.
	interactive, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Desktop app", Subject: "usr_owner", ConnectionIDs: []string{"delegated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	delegated, _ := store.Account("delegated")
	if names := clientEndpointToolNames(t, gateway, workload.Slug); !slices.Contains(names, "delegated__search") {
		t.Fatalf("exact grant did not deliver the caller-delegated account: %v", names)
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, workload.Slug, delegated.Name, delegated.IncarnationID); !ok {
		t.Fatal("exact grant refused at dispatch")
	}
	if names := clientEndpointToolNames(t, gateway, interactive.Slug); slices.Contains(names, "delegated__search") {
		t.Fatalf("interactive client received a caller-delegated account: %v", names)
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, interactive.Slug, delegated.Name, delegated.IncarnationID); ok {
		t.Fatal("interactive client admitted at dispatch")
	}
	if !accountDeliveredOnlyByExactGrant(delegated) {
		t.Fatal("accountDeliveredOnlyByExactGrant must hold for a caller-delegated account")
	}
	plain, _ := store.Account("plain")
	if accountDeliveredOnlyByExactGrant(plain) {
		t.Fatal("an ordinary account is not exact-only")
	}
	// A recreated account is a new incarnation: the old exact grant no longer
	// names it.
	if err := store.Delete(ctx, delegated.Name, delegated.IncarnationID, delegated.Revision); err != nil {
		t.Fatal(err)
	}
	replacement := delegated
	replacement.IncarnationID, replacement.Revision = "", 0
	if err := store.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	recreated, _ := store.Account("delegated")
	durable, _ := store.MCPClient(ctx, workload.ID)
	if mcpClientDeliversAccount(durable, recreated) {
		t.Fatal("a recreated caller-delegated account inherited an old exact grant")
	}
}
