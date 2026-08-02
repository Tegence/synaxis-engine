package engine

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreUpdateAccountPolicyPreservesOwnershipAndRejectsMovedSnapshot(t *testing.T) {
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
	if err := store.Create(ctx, Account{
		Name: "notion", Label: "Notion", Group: source.Label,
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "secret",
	}); err != nil {
		t.Fatal(err)
	}

	before, ok := store.Account("notion")
	if !ok {
		t.Fatal("account missing")
	}
	label := "Notion · curated"
	readOnly := true
	disabled := []string{"write"}
	overrides := map[string]ToolOverride{"search": {Alias: "find"}}
	updated, err := store.UpdateAccountPolicy(ctx, before.Name, accountPolicyPrecondition(before), AccountPolicyMutation{
		Label: &label, ReadOnly: &readOnly, DisabledTools: &disabled, ToolOverrides: &overrides,
	})
	if err != nil {
		t.Fatalf("UpdateAccountPolicy: %v", err)
	}
	if updated.ConnectionNamespaceID != source.ID || updated.ConnectionScope != before.ConnectionScope ||
		updated.OwnerSubject != before.OwnerSubject || updated.Group != source.Label || updated.Revision != before.Revision+1 {
		t.Fatalf("policy update changed ownership or revision unexpectedly: before=%+v after=%+v", before, updated)
	}

	stale := updated
	if _, err := store.MoveAccountToConnectionNamespace(ctx, updated.Name, updated.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, updated.Revision); err != nil {
		t.Fatalf("move: %v", err)
	}
	attemptedLabel := "Former manager update"
	attemptedDisabled := []string{"delete"}
	if _, err := store.UpdateAccountPolicy(ctx, stale.Name, accountPolicyPrecondition(stale), AccountPolicyMutation{
		Label: &attemptedLabel, DisabledTools: &attemptedDisabled,
	}); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("stale policy after move = %v, want ErrAccountPolicyPrecondition", err)
	}
	after, ok := store.Account(stale.Name)
	if !ok || after.ConnectionNamespaceID != target.ID || after.Group != target.Label ||
		after.Label != label || !after.ReadOnly || !sameStrings(after.DisabledTools, disabled) ||
		after.ToolOverrides["search"].Alias != "find" {
		t.Fatalf("stale policy write mutated moved account: %+v", after)
	}
}

// moveBeforePolicyStore is a deterministic race seam: the first policy write
// moves the account after ConsoleAPI has authorized its snapshot but before
// FileStore evaluates that snapshot's CAS precondition.
type moveBeforePolicyStore struct {
	*FileStore
	beforePolicy func() error
}

func (s *moveBeforePolicyStore) UpdateAccountPolicy(ctx context.Context, name string, precondition AccountPolicyPrecondition, mutation AccountPolicyMutation) (Account, error) {
	if before := s.beforePolicy; before != nil {
		s.beforePolicy = nil
		if err := before(); err != nil {
			return Account{}, err
		}
	}
	return s.FileStore.UpdateAccountPolicy(ctx, name, precondition, mutation)
}

func hostedPolicyRaceConsole(t *testing.T) (*http.ServeMux, *moveBeforePolicyStore, ed25519.PrivateKey, time.Time, ConnectionNamespace, ConnectionNamespace) {
	t.Helper()
	ctx := context.Background()
	fileStore, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	team, err := fileStore.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner", ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	private, err := fileStore.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Private", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.Create(ctx, Account{
		Name: "team_notion", Label: "Team Notion", Group: team.Label,
		ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "secret",
	}); err != nil {
		t.Fatal(err)
	}
	store := &moveBeforePolicyStore{FileStore: fileStore}
	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	api := NewConsoleAPI(store, gateway, nil, "local-password", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, store, key, now, team, private
}

func TestHostedPolicyWriteConflictsWhenManagerLosesNamespaceDuringRequest(t *testing.T) {
	mux, store, key, now, _, private := hostedPolicyRaceConsole(t)
	before, ok := store.Account("team_notion")
	if !ok {
		t.Fatal("account missing")
	}
	store.beforePolicy = func() error {
		current, ok := store.Account(before.Name)
		if !ok {
			return ErrAccountNotFound
		}
		_, err := store.FileStore.MoveAccountToConnectionNamespace(context.Background(), current.Name, current.IncarnationID, AccountConnectionAssignment{
			ConnectionNamespaceID: private.ID, Scope: ConnectionScopeShared,
		}, current.Revision)
		return err
	}

	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut,
		"/api/servers/team_notion/tools", `{"disabled":["search"]}`)
	if response.Code != http.StatusConflict || response.Body.String() != "{\"error\":\"connection changed; refresh and try again\"}\n" {
		t.Fatalf("stale manager PUT tools = %d body=%s; want safe 409", response.Code, response.Body)
	}
	after, ok := store.Account(before.Name)
	if !ok || after.ConnectionNamespaceID != private.ID || len(after.DisabledTools) != 0 {
		t.Fatalf("stale manager policy mutated moved account: %+v", after)
	}

	// A subsequent request is evaluated against the new durable boundary, so
	// the former Team manager cannot probe or mutate the Private connection.
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPatch,
		"/api/servers/team_notion", `{"displayName":"Former manager"}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("former manager PATCH after move = %d body=%s; want 404", response.Code, response.Body)
	}
}
