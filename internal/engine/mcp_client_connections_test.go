package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

type directConnectionStore interface {
	AccountStore
	MCPClientStore
	MCPClientAccessStore
	ConnectionNamespaceStore
}

func directConnectionContract(t *testing.T, store directConnectionStore, suffix string) (MCPClient, []string, ConnectionNamespace) {
	t.Helper()
	ctx := context.Background()
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Direct " + suffix, CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"direct_one_" + suffix, "direct_two_" + suffix, "direct_personal_" + suffix}
	for i, name := range names {
		account := Account{Name: name, URL: "https://direct.example/mcp", AuthMode: "token", BearerToken: "test", ConnectionNamespaceID: folder.ID}
		if i == 2 {
			account.ConnectionScope = ConnectionScopePersonal
			account.OwnerSubject = "usr_other"
		}
		if err := store.Create(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Exact " + suffix, Subject: "usr_owner", ConnectionIDs: []string{names[0]}})
	if err != nil {
		t.Fatal(err)
	}
	one, _ := store.Account(names[0])
	two, _ := store.Account(names[1])
	if len(client.ConnectionNamespaceIDs) != 0 || !mcpClientDeliversAccount(client, one) || mcpClientDeliversAccount(client, two) {
		t.Fatalf("exact grant expanded into its folder: %+v", client)
	}
	gateway := NewGateway(store, server.NewMCPServer("direct-test", "1"))
	if _, ok := gateway.mcpClientMayUseAccount(ctx, client.Slug, names[0], one.IncarnationID); !ok {
		t.Fatal("exact grant unavailable at dispatch")
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, client.Slug, names[1], two.IncarnationID); ok {
		t.Fatal("unselected sibling admitted at dispatch")
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Unsafe", Subject: "usr_owner", ConnectionIDs: []string{names[2]}}); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("cross-subject personal connection admitted: %v", err)
	}
	if _, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{names[1]}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision + 1}); !errors.Is(err, ErrMCPClientRevision) {
		t.Fatalf("stale access mutation accepted: %v", err)
	}
	// Older namespace-only writes cannot silently erase exact grants.
	preserved, err := store.SetMCPClientNamespaces(ctx, client.ID, nil, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
	if err != nil || preserved.Epoch != client.Epoch || !mcpClientDeliversAccount(preserved, one) {
		t.Fatalf("legacy edit changed exact grants: %+v %v", preserved, err)
	}
	updated, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{names[1]}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Epoch == client.Epoch || mcpClientDeliversAccount(updated, one) || !mcpClientDeliversAccount(updated, two) {
		t.Fatal("scope switch did not rotate and narrow the grant")
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, client.Slug, names[0], one.IncarnationID); ok {
		t.Fatal("stale projected tool remained usable")
	}
	if err := store.Delete(ctx, two.Name, two.IncarnationID, two.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: two.Name, URL: two.URL, AuthMode: "token", BearerToken: "replacement", ConnectionNamespaceID: folder.ID}); err != nil {
		t.Fatal(err)
	}
	replacement, _ := store.Account(two.Name)
	if replacement.IncarnationID == two.IncarnationID {
		t.Fatal("test needs a new incarnation")
	}
	durable, _ := store.MCPClient(ctx, client.ID)
	if mcpClientDeliversAccount(durable, replacement) {
		t.Fatal("recreated connection inherited an old exact grant")
	}
	if _, ok := gateway.mcpClientMayUseAccount(ctx, client.Slug, replacement.Name, replacement.IncarnationID); ok {
		t.Fatal("recreated connection admitted at dispatch")
	}
	if _, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{replacement.Name}, MCPClientPrecondition{ID: client.ID, Revision: updated.Revision}); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("automatic reconciliation regranted a replacement: %v", err)
	}
	removed, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{}, MCPClientPrecondition{ID: client.ID, Revision: updated.Revision})
	if err != nil {
		t.Fatal(err)
	}
	regranted, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{replacement.Name}, MCPClientPrecondition{ID: client.ID, Revision: removed.Revision})
	if err != nil || regranted.Epoch == updated.Epoch || !mcpClientDeliversAccount(regranted, replacement) {
		t.Fatalf("explicit regrant failed: %+v %v", regranted, err)
	}
	// Returned maps must not alias durable authorization state.
	regranted.ConnectionGrants[replacement.Name] = "forged"
	durable, _ = store.MCPClient(ctx, client.ID)
	if !mcpClientDeliversAccount(durable, replacement) {
		t.Fatal("returned record aliases stored grant map")
	}
	cleared, err := store.SetMCPClientAccess(ctx, client.ID, nil, []string{}, MCPClientPrecondition{ID: client.ID, Revision: durable.Revision})
	if err != nil || len(cleared.ConnectionIDs) != 0 || mcpClientDeliversAccount(cleared, replacement) {
		t.Fatalf("explicit clear failed: %+v %v", cleared, err)
	}
	return cleared, names, folder
}

func TestFileStoreMCPClientExactConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	client, names, _ := directConnectionContract(t, store, "file")
	// Persist a nonempty exact grant before reopening the store.
	client, err = store.SetMCPClientAccess(context.Background(), client.ID, nil, []string{names[0]}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reopened.MCPClient(context.Background(), client.ID)
	account, _ := reopened.Account(names[0])
	if !ok || loaded.Epoch != client.Epoch || !mcpClientDeliversAccount(loaded, account) {
		t.Fatalf("exact grant lost at reopen: %+v", loaded)
	}
}

func TestPgStoreMCPClientExactConnections(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for Postgres contract")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	suffix := newPgFixtureSuffix()
	client, names, folder := directConnectionContract(t, store, suffix)
	defer func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=ANY($1)`, names)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, folder.ID)
	}()
	// Exercise persisted JSONB reads via a fresh pool, not just mutation results.
	client, err = store.SetMCPClientAccess(ctx, client.ID, nil, []string{names[0]}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, ok := reopened.MCPClient(ctx, client.ID)
	account, _ := reopened.Account(names[0])
	if !ok || loaded.Epoch != client.Epoch || !mcpClientDeliversAccount(loaded, account) {
		t.Fatalf("exact grant lost at reopen: %+v", loaded)
	}
}
