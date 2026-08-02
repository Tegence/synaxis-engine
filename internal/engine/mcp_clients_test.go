package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreMCPClientLifecycleBindsResetsAndRevokes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Operations", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name:                   "Codex Desktop",
		Subject:                "usr_operator",
		CreatedBy:              "usr_operator",
		ConnectionNamespaceIDs: []string{team.ID, team.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.ID == "" || client.Slug != "codex-desktop" || client.Status != MCPClientStatusActive || client.Epoch == "" || client.Revision != 1 {
		t.Fatalf("created MCP client = %+v", client)
	}
	if !sameStrings(client.ConnectionNamespaceIDs, []string{team.ID}) {
		t.Fatalf("namespace grants = %#v, want [%s]", client.ConnectionNamespaceIDs, team.ID)
	}
	if byID, ok := store.ActiveMCPClient(ctx, client.ID); !ok || byID.Subject != "usr_operator" {
		t.Fatalf("active lookup by ID = %+v ok=%v", byID, ok)
	}
	if bySlug, ok := store.ActiveMCPClient(ctx, client.Slug); !ok || bySlug.ID != client.ID {
		t.Fatalf("active lookup by slug = %+v ok=%v", bySlug, ok)
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Smuggled OAuth", Subject: "usr_operator", OAuthClientID: "not-allowed",
	}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("create with OAuth binding = %v; want invalid client", err)
	}

	firstOAuthID := strings.Repeat("x", maxMCPClientOAuthClientIDBytes)
	bound, err := store.BindMCPClientOAuthClient(ctx, client.ID, firstOAuthID, MCPClientPrecondition{
		ID: client.ID, Revision: client.Revision,
	}, PlatformActor{UserID: "usr_operator", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if bound.OAuthClientID != firstOAuthID || bound.Revision != client.Revision+1 || bound.Epoch == client.Epoch {
		t.Fatalf("bound MCP client = %+v; pre-bind=%+v", bound, client)
	}
	if lookup, ok := store.ActiveMCPClientByOAuthClientID(ctx, firstOAuthID); !ok || lookup.ID != client.ID {
		t.Fatalf("OAuth lookup = %+v ok=%v", lookup, ok)
	}
	if _, err := store.BindMCPClientOAuthClient(ctx, client.ID, firstOAuthID, MCPClientPrecondition{
		ID: client.ID, Revision: bound.Revision,
	}, PlatformActor{UserID: "usr_other", Role: "operator"}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("cross-subject bind = %v; want invalid client", err)
	}
	if !MCPClientAllowsActor(bound, PlatformActor{UserID: "usr_operator", Role: "owner"}) ||
		MCPClientAllowsActor(bound, PlatformActor{UserID: "usr_operator", Role: "viewer"}) ||
		MCPClientAllowsActor(bound, PlatformActor{UserID: "usr_other", Role: "admin"}) {
		t.Fatalf("unexpected subject-bound actor predicate for %+v", bound)
	}

	reset, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: bound.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if reset.OAuthClientID != "" || reset.Revision != bound.Revision+1 || reset.Epoch == bound.Epoch || !sameStrings(reset.ConnectionNamespaceIDs, []string{team.ID}) {
		t.Fatalf("reset MCP client = %+v; bound=%+v", reset, bound)
	}
	if _, ok := store.ActiveMCPClientByOAuthClientID(ctx, firstOAuthID); ok {
		t.Fatal("OAuth lookup remained live after explicit reset")
	}

	secondOAuthID := "codex-after-reset"
	boundAgain, err := store.BindMCPClientOAuthClient(ctx, client.ID, secondOAuthID, MCPClientPrecondition{ID: client.ID, Revision: reset.Revision}, PlatformActor{UserID: "usr_operator", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	changedScopes, err := store.SetMCPClientNamespaces(ctx, client.ID, []string{operations.ID, team.ID}, MCPClientPrecondition{ID: client.ID, Revision: boundAgain.Revision})
	if err != nil {
		t.Fatal(err)
	}
	expectedScopes, err := normalizeMCPClientNamespaceIDs([]string{operations.ID, team.ID})
	if err != nil {
		t.Fatal(err)
	}
	if changedScopes.Epoch == boundAgain.Epoch || !sameStrings(changedScopes.ConnectionNamespaceIDs, expectedScopes) {
		t.Fatalf("scope update = %+v; previous=%+v", changedScopes, boundAgain)
	}

	revoked, err := store.RevokeMCPClient(ctx, client.ID, "usr_operator", MCPClientPrecondition{ID: client.ID, Revision: changedScopes.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != MCPClientStatusRevoked || revoked.RevokedAt == nil || revoked.Epoch == changedScopes.Epoch {
		t.Fatalf("revoked client = %+v", revoked)
	}
	if _, ok := store.ActiveMCPClient(ctx, client.Slug); ok {
		t.Fatal("revoked client remained resolvable by endpoint slug")
	}
	if _, ok := store.ActiveMCPClientByOAuthClientID(ctx, secondOAuthID); ok {
		t.Fatal("revoked client remained resolvable by OAuth client ID")
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok := reopened.MCPClient(ctx, client.ID)
	if !ok || persisted.Status != MCPClientStatusRevoked || persisted.OAuthClientID != secondOAuthID || persisted.Epoch != revoked.Epoch {
		t.Fatalf("persisted client = %+v ok=%v", persisted, ok)
	}
}

func TestMCPClientGrantProtectsPersonalConnectionSubjectBoundary(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	personal, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Alice private", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "alice_notion", URL: "https://alice.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: personal.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_alice",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Bob Codex", Subject: "usr_bob", ConnectionNamespaceIDs: []string{personal.ID},
	}); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("cross-subject personal grant = %v; want ownership rejection", err)
	}

	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Bob Codex", Subject: "usr_bob", ConnectionNamespaceIDs: []string{team.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMCPClientNamespaces(ctx, bob.ID, []string{personal.ID}, MCPClientPrecondition{ID: bob.ID, Revision: bob.Revision}); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("scope update cross-subject personal grant = %v; want ownership rejection", err)
	}

	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Source"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "move_me", URL: "https://move.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Account("move_me")
	if _, err := store.MoveAccountToConnectionNamespace(ctx, before.Name, before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: team.ID, Scope: ConnectionScopePersonal, OwnerSubject: "usr_alice",
	}, before.Revision); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("personal move into Bob-granted namespace = %v; want ownership rejection", err)
	}
	after, _ := store.Account("move_me")
	if after.ConnectionNamespaceID != source.ID || after.ConnectionScope != ConnectionScopeShared {
		t.Fatalf("rejected personal move mutated account: %+v", after)
	}
}

func TestFileStoreAccountMoveRotatesOnlyMCPClientsWithChangedDelivery(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Target"})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Unrelated"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "team_notion", URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatal(err)
	}

	create := func(name, subject string, namespaceIDs []string) MCPClient {
		t.Helper()
		client, err := store.CreateMCPClient(ctx, MCPClient{
			Name: name, Subject: subject, CreatedBy: subject, ConnectionNamespaceIDs: namespaceIDs,
		})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return client
	}
	loses := create("Source Codex", "usr_source", []string{source.ID})
	gains := create("Target Codex", "usr_target", []string{target.ID})
	keeps := create("Both Codex", "usr_both", []string{source.ID, target.ID})
	untouched := create("Unrelated Codex", "usr_unrelated", []string{unrelated.ID})
	revoked := create("Revoked Target Codex", "usr_revoked", []string{target.ID})

	// A move must preserve a bound DCR identity while changing its token epoch;
	// the client reconnects, rather than receiving a new endpoint or prefix.
	gains, err = store.BindMCPClientOAuthClient(ctx, gains.ID, "file-move-dcr", MCPClientPrecondition{
		ID: gains.ID, Revision: gains.Revision,
	}, PlatformActor{UserID: gains.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err = store.RevokeMCPClient(ctx, revoked.ID, "usr_revoked", MCPClientPrecondition{
		ID: revoked.ID, Revision: revoked.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}

	beforeClients := map[string]MCPClient{
		"loses": loses, "gains": gains, "keeps": keeps, "untouched": untouched, "revoked": revoked,
	}
	beforeAccount, ok := store.Account("team_notion")
	if !ok {
		t.Fatal("account missing before move")
	}
	moved, err := store.MoveAccountToConnectionNamespace(ctx, beforeAccount.Name, beforeAccount.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, beforeAccount.Revision)
	if err != nil {
		t.Fatal(err)
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
	if bound, ok := store.ActiveMCPClientByOAuthClientID(ctx, "file-move-dcr"); !ok || bound.ID != gains.ID || bound.Epoch == gains.Epoch {
		t.Fatalf("bound target client did not preserve its DCR identity with a new epoch: %+v ok=%v", bound, ok)
	}
}

func TestFileStoreMCPClientBackfillRevokesUnsafePersonalGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-clients.json")
	now := time.Now().UTC().Add(-time.Hour)
	data := fileStoreData{
		Accounts: []*Account{{
			Name: "alice_notion", URL: "https://alice.example/mcp", AuthMode: "token", BearerToken: "secret",
			ConnectionNamespaceID: "cns_alice", ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_alice", Revision: 1,
		}},
		ConnectionNamespaces: []*ConnectionNamespace{{
			ID: "cns_alice", Slug: "alice-private", Label: "Alice private", Revision: 1, CreatedBy: "usr_alice", CreatedAt: now, UpdatedAt: now,
		}},
		MCPClients: []*MCPClient{{
			ID: "mcpcli_legacy", Slug: "bob-codex", Name: "Bob Codex", Subject: "usr_bob",
			ConnectionNamespaceIDs: []string{"cns_alice"}, Status: MCPClientStatusActive, Epoch: "old-epoch", Revision: 1, CreatedAt: now, UpdatedAt: now,
		}},
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := store.MCPClient(context.Background(), "mcpcli_legacy")
	if !ok || client.Status != MCPClientStatusRevoked || client.RevokedAt == nil || len(client.ConnectionNamespaceIDs) != 0 || client.Epoch == "old-epoch" {
		t.Fatalf("unsafe legacy client was not revoked fail-closed: %+v ok=%v", client, ok)
	}
	if _, ok := store.ActiveMCPClient(context.Background(), "bob-codex"); ok {
		t.Fatal("unsafe legacy client remained an active endpoint")
	}
}
