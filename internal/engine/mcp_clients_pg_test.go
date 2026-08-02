package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests are intentionally integration-gated: the registry's most
// important guarantees are relational (durable OAuth binding, namespace
// foreign keys, and a cross-transaction personal-account boundary).
func TestPgStoreMCPClientLifecycleAndNamespaceDelete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	suffix := strings.ToLower(newEpoch())
	var (
		team        ConnectionNamespace
		personal    ConnectionNamespace
		clientID    string
		accountName = "pg_mcp_client_personal_" + suffix
	)
	cleanup := func() {
		if clientID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, clientID)
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		if personal.ID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, personal.ID)
		}
		if team.ID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, team.ID)
		}
	}
	defer cleanup()

	team, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG MCP Team " + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("create shared namespace: %v", err)
	}
	personal, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG MCP Alice " + suffix, CreatedBy: "usr_pg_alice",
	})
	if err != nil {
		t.Fatalf("create personal namespace: %v", err)
	}
	if err := store.Create(ctx, Account{
		Name: accountName, URL: "https://pg-mcp-personal.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: personal.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_pg_alice",
	}); err != nil {
		t.Fatalf("create Alice personal account: %v", err)
	}

	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "PG Codex " + suffix, Subject: "usr_pg_bob", ConnectionNamespaceIDs: []string{team.ID},
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	clientID = client.ID
	if _, err := store.SetMCPClientNamespaces(ctx, client.ID, []string{personal.ID}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("cross-subject personal grant = %v; want ownership rejection", err)
	}

	bound, err := store.BindMCPClientOAuthClient(ctx, client.ID, "pg-dcr-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: "usr_pg_bob", Role: "operator"})
	if err != nil {
		t.Fatalf("bind OAuth client: %v", err)
	}
	if found, ok := store.ActiveMCPClientByOAuthClientID(ctx, bound.OAuthClientID); !ok || found.ID != client.ID {
		t.Fatalf("OAuth binding lookup = %+v ok=%v", found, ok)
	}
	reset, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: bound.Revision})
	if err != nil {
		t.Fatalf("reset OAuth client: %v", err)
	}
	if _, ok := store.ActiveMCPClientByOAuthClientID(ctx, bound.OAuthClientID); ok {
		t.Fatal("reset OAuth client ID remained live")
	}
	if reset.Epoch == bound.Epoch || reset.Revision != bound.Revision+1 {
		t.Fatalf("reset did not invalidate client generation: reset=%+v bound=%+v", reset, bound)
	}

	// An active registration is itself an authorization grant: deleting its
	// folder would make a stale client endpoint ambiguous, so it must be
	// rejected before the client is revoked.
	if err := store.DeleteConnectionNamespace(ctx, team.ID, ConnectionNamespacePrecondition{ID: team.ID, Revision: team.Revision}); !errors.Is(err, ErrConnectionNamespaceInUse) {
		t.Fatalf("delete active client namespace = %v; want in use", err)
	}
	revoked, err := store.RevokeMCPClient(ctx, client.ID, "usr_pg_bob", MCPClientPrecondition{ID: client.ID, Revision: reset.Revision})
	if err != nil {
		t.Fatalf("revoke client: %v", err)
	}
	if err := store.DeleteConnectionNamespace(ctx, team.ID, ConnectionNamespacePrecondition{ID: team.ID, Revision: team.Revision}); err != nil {
		t.Fatalf("delete revoked client namespace: %v", err)
	}
	team = ConnectionNamespace{} // deletion succeeded; skip it in deferred cleanup.
	stored, ok := store.MCPClient(ctx, client.ID)
	if !ok || stored.Status != MCPClientStatusRevoked || len(stored.ConnectionNamespaceIDs) != 0 || stored.Revision != revoked.Revision+1 {
		t.Fatalf("revoked client after namespace delete = %+v ok=%v", stored, ok)
	}

	// A new store must read the same durable registry state rather than a
	// process-local projection.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	persisted, ok := reopened.MCPClient(ctx, client.ID)
	if !ok || persisted.Status != MCPClientStatusRevoked || len(persisted.ConnectionNamespaceIDs) != 0 || persisted.Epoch != stored.Epoch {
		t.Fatalf("persisted revoked client = %+v ok=%v", persisted, ok)
	}
}

func TestPgStoreMCPClientPersonalBoundarySerializesConcurrentWrites(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	suffix := strings.ToLower(newEpoch())
	space, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG MCP race " + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("create race namespace: %v", err)
	}
	accountName := "pg_mcp_race_account_" + suffix
	var client MCPClient
	cleanup := func() {
		if client.ID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, space.ID)
	}
	defer cleanup()

	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var clientErr, accountErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		client, clientErr = store.CreateMCPClient(runCtx, MCPClient{
			Name: "PG race Codex " + suffix, Subject: "usr_pg_bob", ConnectionNamespaceIDs: []string{space.ID},
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		accountErr = store.Create(runCtx, Account{
			Name: accountName, URL: "https://pg-mcp-race.example/mcp", AuthMode: "token", BearerToken: "secret",
			ConnectionNamespaceID: space.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_pg_alice",
		})
	}()
	close(start)
	wg.Wait()

	if (clientErr == nil) == (accountErr == nil) {
		t.Fatalf("exactly one conflicting write must win: clientErr=%v accountErr=%v", clientErr, accountErr)
	}
	if clientErr != nil && !errors.Is(clientErr, ErrMCPClientNamespaceSubject) {
		t.Fatalf("client race failure = %v; want personal boundary rejection", clientErr)
	}
	if accountErr != nil && !errors.Is(accountErr, ErrMCPClientNamespaceSubject) {
		t.Fatalf("account race failure = %v; want personal boundary rejection", accountErr)
	}

	// Query the durable records rather than relying on which goroutine won.
	// It must never contain a live Bob client that can reach Alice's personal
	// account in the same credential namespace.
	if account, ok := store.Account(accountName); ok && account.IsPersonal() {
		for _, active := range mustActiveMCPClients(t, store, ctx) {
			if active.Subject == account.OwnerSubject {
				continue
			}
			for _, namespaceID := range active.ConnectionNamespaceIDs {
				if namespaceID == space.ID {
					t.Fatalf("durable race violation: client=%+v personalAccount=%+v", active, account)
				}
			}
		}
	}
}

func TestPgStoreAccountMoveRotatesOnlyMCPClientsWithChangedDelivery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	suffix := strings.ToLower(newEpoch())
	var (
		source      ConnectionNamespace
		target      ConnectionNamespace
		unrelated   ConnectionNamespace
		clientIDs   []string
		accountName = "pg_mcp_move_" + suffix
	)
	cleanup := func() {
		for _, id := range clientIDs {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, id)
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		for _, ns := range []ConnectionNamespace{source, target, unrelated} {
			if ns.ID != "" {
				_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, ns.ID)
			}
		}
	}
	defer cleanup()

	createNamespace := func(label string) ConnectionNamespace {
		t.Helper()
		ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: label + " " + suffix})
		if err != nil {
			t.Fatalf("create %s namespace: %v", label, err)
		}
		return ns
	}
	source = createNamespace("PG MCP source")
	target = createNamespace("PG MCP target")
	unrelated = createNamespace("PG MCP unrelated")
	if err := store.Create(ctx, Account{
		Name: accountName, URL: "https://pg-mcp-move.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	createClient := func(name, subject string, namespaceIDs []string) MCPClient {
		t.Helper()
		client, err := store.CreateMCPClient(ctx, MCPClient{
			Name: name + " " + suffix, Subject: subject, ConnectionNamespaceIDs: namespaceIDs,
		})
		if err != nil {
			t.Fatalf("create %s client: %v", name, err)
		}
		clientIDs = append(clientIDs, client.ID)
		return client
	}
	loses := createClient("PG Source Codex", "usr_pg_source", []string{source.ID})
	gains := createClient("PG Target Codex", "usr_pg_target", []string{target.ID})
	keeps := createClient("PG Both Codex", "usr_pg_both", []string{source.ID, target.ID})
	untouched := createClient("PG Unrelated Codex", "usr_pg_unrelated", []string{unrelated.ID})
	revoked := createClient("PG Revoked Target Codex", "usr_pg_revoked", []string{target.ID})

	gains, err = store.BindMCPClientOAuthClient(ctx, gains.ID, "pg-move-dcr-"+suffix, MCPClientPrecondition{
		ID: gains.ID, Revision: gains.Revision,
	}, PlatformActor{UserID: gains.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("bind target OAuth client: %v", err)
	}
	revoked, err = store.RevokeMCPClient(ctx, revoked.ID, "usr_pg_revoked", MCPClientPrecondition{
		ID: revoked.ID, Revision: revoked.Revision,
	})
	if err != nil {
		t.Fatalf("revoke client: %v", err)
	}

	beforeClients := map[string]MCPClient{
		"loses": loses, "gains": gains, "keeps": keeps, "untouched": untouched, "revoked": revoked,
	}
	beforeAccount, ok := store.Account(accountName)
	if !ok {
		t.Fatal("account missing before move")
	}
	moved, err := store.MoveAccountToConnectionNamespace(ctx, beforeAccount.Name, beforeAccount.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, beforeAccount.Revision)
	if err != nil {
		t.Fatalf("move account: %v", err)
	}
	if moved.Name != beforeAccount.Name || moved.URL != beforeAccount.URL || moved.IncarnationID != beforeAccount.IncarnationID || moved.Revision != beforeAccount.Revision+1 {
		t.Fatalf("account move changed stable identity: before=%+v after=%+v", beforeAccount, moved)
	}

	for name, changed := range map[string]bool{
		"loses": true, "gains": true, "keeps": false, "untouched": false, "revoked": false,
	} {
		before := beforeClients[name]
		after, ok := store.MCPClient(ctx, before.ID)
		if !ok {
			t.Fatalf("%s client missing after move", name)
		}
		if after.ID != before.ID || after.Slug != before.Slug || after.OAuthClientID != before.OAuthClientID {
			t.Fatalf("%s client identity changed: before=%+v after=%+v", name, before, after)
		}
		if changed {
			if after.Epoch == before.Epoch || after.Revision != before.Revision+1 {
				t.Fatalf("%s client was not invalidated for delivery change: before=%+v after=%+v", name, before, after)
			}
		} else if after.Epoch != before.Epoch || after.Revision != before.Revision {
			t.Fatalf("%s client rotated without a delivery change: before=%+v after=%+v", name, before, after)
		}
	}
	if bound, ok := store.ActiveMCPClientByOAuthClientID(ctx, "pg-move-dcr-"+suffix); !ok || bound.ID != gains.ID || bound.Epoch == gains.Epoch {
		t.Fatalf("bound target client did not preserve its DCR identity with a new epoch: %+v ok=%v", bound, ok)
	}
}

func TestPgStoreLegacyGroupUpsertRotatesScopedClientEpochAndSetMetaRejectsOwnership(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres legacy ownership integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	suffix := strings.ToLower(newEpoch())
	accountName := "pg_mcp_legacy_group_" + suffix
	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG legacy source " + suffix})
	if err != nil {
		t.Fatal(err)
	}
	var clientID, targetID string
	cleanup := func() {
		if clientID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, clientID)
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		if targetID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, targetID)
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, source.ID)
	}
	defer cleanup()

	if err := store.Create(ctx, Account{
		Name: accountName, Label: "Legacy source", URL: "https://pg-legacy.example/mcp", AuthMode: "token", BearerToken: "source-token",
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "PG legacy Codex " + suffix, Subject: "usr_pg_legacy", ConnectionNamespaceIDs: []string{source.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientID = client.ID
	before, ok := store.Account(accountName)
	if !ok {
		t.Fatal("account missing before legacy Upsert")
	}

	// Mirrors the self-hosted /admin/token POST: a legacy Group is supplied
	// without first-class ownership fields.
	if err := store.Upsert(ctx, Account{
		Name: accountName, Label: "Legacy target", Group: "PG legacy target " + suffix,
		URL: before.URL, AuthMode: "token", BearerToken: "target-token",
	}); err != nil {
		t.Fatalf("legacy group Upsert: %v", err)
	}
	moved, ok := store.Account(accountName)
	if !ok || moved.ConnectionNamespaceID == source.ID || moved.ConnectionNamespaceID == "" {
		t.Fatalf("legacy group Upsert did not move account: before=%+v after=%+v", before, moved)
	}
	targetID = moved.ConnectionNamespaceID
	afterClient, ok := store.MCPClient(ctx, client.ID)
	if !ok || afterClient.Epoch == client.Epoch || afterClient.Revision != client.Revision+1 {
		t.Fatalf("legacy group Upsert did not rotate scoped client epoch: before=%+v after=%+v", client, afterClient)
	}

	if err := store.SetMeta(ctx, accountName, "Stale label", source.Label); !errors.Is(err, ErrConnectionNamespaceRevision) {
		t.Fatalf("stale SetMeta group = %v, want ErrConnectionNamespaceRevision", err)
	}
	if updated, err := store.UpdatePortableAccountConfig(ctx, accountName, PortableAccountConfig{
		Label: "Imported label", URL: moved.URL, ReadOnly: true,
	}); err != nil || updated.ConnectionNamespaceID != targetID || updated.Group != moved.Group || !updated.ReadOnly {
		t.Fatalf("portable metadata update after move = %+v err=%v; moved=%+v", updated, err, moved)
	}
	final, _ := store.Account(accountName)
	if final.ConnectionNamespaceID != targetID || final.Group != moved.Group || final.Label != "Imported label" {
		t.Fatalf("stale metadata changed durable ownership: final=%+v moved=%+v", final, moved)
	}
}

func mustActiveMCPClients(t *testing.T, store MCPClientStore, ctx context.Context) []MCPClient {
	t.Helper()
	clients, err := store.ActiveMCPClients(ctx)
	if err != nil {
		t.Fatalf("list active MCP clients: %v", err)
	}
	return clients
}
