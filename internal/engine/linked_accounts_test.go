package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type linkedAccountTestStore interface {
	AccountStore
	ConnectionNamespaceStore
	LinkedAccountStore
}

func linkedAccountFixture(t *testing.T, store linkedAccountTestStore) Account {
	t.Helper()
	suffix := newPgFixtureSuffix()
	ns, err := store.CreateConnectionNamespace(t.Context(), ConnectionNamespace{Label: "Linked " + suffix, CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	name := "linked_" + suffix
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, name, ns.Label) })
	}
	if err := store.Create(t.Context(), Account{Name: name, Label: "Original MCP", ConnectionNamespaceID: ns.ID, URL: "https://tools.example/mcp", AuthMode: "token", BearerToken: "legacy-credential", ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	parent, _ := store.Account(name)
	return parent
}

func TestFileLinkedAccountLifecycle(t *testing.T) {
	testLinkedAccountLifecycle(t, newLibraryFileStore(t))
}
func TestPgLinkedAccountLifecycle(t *testing.T) {
	testLinkedAccountLifecycle(t, newPgConnectionsStore(t))
}

func testLinkedAccountLifecycle(t *testing.T, store linkedAccountTestStore) {
	t.Helper()
	ctx := t.Context()
	parent := linkedAccountFixture(t, store)
	p := accountPolicyPrecondition(parent)
	create := func(subject string) LinkedAccountRecord {
		t.Helper()
		record, err := store.CreateLinkedAccount(ctx, LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: subject, DisplayName: "My publishing account", BearerToken: "private-linked-token"}, p)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	alice, bob := create("usr_alice"), create("usr_bob")
	if alice.ID == bob.ID || alice.Revision != 1 || alice.CredentialRevision != 1 {
		t.Fatal("invalid account identity or initial revisions")
	}
	list, err := store.LinkedAccounts(ctx, "usr_alice")
	if err != nil || len(list) != 1 || list[0].ID != alice.ID {
		t.Fatalf("owner isolation: %+v %v", list, err)
	}
	if _, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_bob", alice.Revision, p, LinkedAccountMutation{Remove: true}); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatalf("coworker removed private account: %v", err)
	}
	stale := p
	stale.Revision++
	if _, err := store.CreateLinkedAccount(ctx, LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "Stale", BearerToken: "token"}, stale); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("stale connection accepted: %v", err)
	}
	rotated := "private-rotated-token"
	updated, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", alice.Revision, p, LinkedAccountMutation{BearerToken: &rotated})
	if err != nil || updated.ID != alice.ID || updated.CredentialRevision != 2 {
		t.Fatalf("rotation: %+v %v", updated, err)
	}
	if _, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", alice.Revision, p, LinkedAccountMutation{Remove: true}); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatalf("stale edit accepted: %v", err)
	}
	name := "Renamed private account"
	renamed, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", updated.Revision, p, LinkedAccountMutation{DisplayName: &name})
	if err != nil || renamed.DisplayName != name || renamed.CredentialRevision != updated.CredentialRevision {
		t.Fatalf("rename changed credentials: %v", err)
	}
	empty := ""
	disconnected, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", renamed.Revision, p, LinkedAccountMutation{BearerToken: &empty})
	if err != nil || disconnected.BearerToken != "" || linkedAccountDTO(disconnected, parent).Status != "disconnected" {
		t.Fatalf("disconnect: %v", err)
	}
	if _, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", renamed.Revision, p, LinkedAccountMutation{BearerToken: &rotated}); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatalf("stale rotation restored disconnected credentials: %v", err)
	}
	reconnected, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", disconnected.Revision, p, LinkedAccountMutation{BearerToken: &rotated})
	if err != nil || reconnected.ID != alice.ID || linkedAccountDTO(reconnected, parent).Status != "linked" {
		t.Fatalf("reconnect: %v", err)
	}
	current, _ := store.Account(parent.Name)
	if !reflect.DeepEqual(parent, current) || store.Token(parent.Name) != "legacy-credential" {
		t.Fatal("linking mutated legacy MCP routing, policy or credentials")
	}
	if pg, ok := store.(*PgStore); ok {
		var raw string
		if err := pg.pool.QueryRow(ctx, `SELECT payload FROM narthex_linked_accounts WHERE id=$1`, alice.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, name) || strings.Contains(raw, rotated) {
			t.Fatal("private linked account was not encrypted")
		}
		plain, _ := json.Marshal(reconnected)
		if _, err := pg.pool.Exec(ctx, `UPDATE narthex_linked_accounts SET payload=$2 WHERE id=$1`, alice.ID, string(plain)); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := pg.encryptExistingLinkedAccounts(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := pg.pool.QueryRow(ctx, `SELECT payload FROM narthex_linked_accounts WHERE id=$1`, alice.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) {
			t.Fatal("plaintext credential migration failed")
		}
	}
	ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Moved " + newPgFixtureSuffix(), CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, parent.Name, ns.Label) })
	}
	moved, err := store.MoveAccountToConnectionNamespace(ctx, parent.Name, parent.IncarnationID, AccountConnectionAssignment{ConnectionNamespaceID: ns.ID, Scope: parent.ConnectionScope}, parent.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if linkedAccountDTO(reconnected, moved).Status != "connection_changed" {
		t.Fatal("ownership move silently rebound authorization")
	}
	if _, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", reconnected.Revision, p, LinkedAccountMutation{BearerToken: &rotated}); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("stale ownership write accepted: %v", err)
	}
	parent, p = moved, accountPolicyPrecondition(moved)
	reconnected, err = store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", reconnected.Revision, p, LinkedAccountMutation{BearerToken: &rotated})
	if err != nil || linkedAccountDTO(reconnected, parent).Status != "linked" {
		t.Fatalf("explicit reconnection failed: %v", err)
	}
	// The same connection name is insufficient to resurrect an old binding.
	if err := store.Delete(ctx, parent.Name, parent.IncarnationID, parent.Revision); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"usr_alice", "usr_bob"} {
		list, err = store.LinkedAccounts(ctx, subject)
		if err != nil || len(list) != 0 {
			t.Fatalf("connection deletion retained linked credentials: %v", err)
		}
	}
	parent.IncarnationID = ""
	if err := store.Create(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MutateLinkedAccount(ctx, parent.Name, alice.ID, "usr_alice", reconnected.Revision, p, LinkedAccountMutation{BearerToken: &rotated}); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("old incarnation accepted: %v", err)
	}
}

func TestFileLinkedAccountConcurrentEdits(t *testing.T) {
	testLinkedAccountConcurrentEdits(t, newLibraryFileStore(t))
}
func TestPgLinkedAccountConcurrentEdits(t *testing.T) {
	testLinkedAccountConcurrentEdits(t, newPgConnectionsStore(t))
}

func testLinkedAccountConcurrentEdits(t *testing.T, store linkedAccountTestStore) {
	parent := linkedAccountFixture(t, store)
	p := accountPolicyPrecondition(parent)
	record, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "Concurrent", BearerToken: "original"}, p)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			token := "replacement"
			_, err := store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, "usr_alice", record.Revision, p, LinkedAccountMutation{BearerToken: &token})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLinkedAccountRevision) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent edits: %d successes, %d conflicts", success, conflict)
	}
}

func TestLinkedAccountFilePersistenceAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	parent := linkedAccountFixture(t, store)
	p := accountPolicyPrecondition(parent)
	record, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "Persistent", BearerToken: "private"}, p)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	list, err := reopened.LinkedAccounts(t.Context(), "usr_alice")
	if err != nil || len(list) != 1 || !reflect.DeepEqual(record, list[0]) {
		t.Fatalf("restart lost account: %v", err)
	}
	store.path = filepath.Join(path, "missing", "store.json")
	token := "unsaved"
	if _, err := store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, "usr_alice", record.Revision, p, LinkedAccountMutation{BearerToken: &token}); err == nil {
		t.Fatal("save failure was ignored")
	}
	list, _ = store.LinkedAccounts(t.Context(), "usr_alice")
	if !reflect.DeepEqual(list[0], record) {
		t.Fatal("failed write changed in-memory credential")
	}
	if err := store.Delete(t.Context(), parent.Name, parent.IncarnationID, parent.Revision); err == nil {
		t.Fatal("delete save failure was ignored")
	}
	list, _ = store.LinkedAccounts(t.Context(), "usr_alice")
	if len(list) != 1 {
		t.Fatal("failed connection delete removed account")
	}
}

func TestLinkedAccountHTTPPrivacyAndCompatibility(t *testing.T) {
	store := newLibraryFileStore(t)
	parent := linkedAccountFixture(t, store)
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	path := "/api/connections/" + parent.Name + "/accounts"
	anonymous := httptest.NewRecorder()
	mux.ServeHTTP(anonymous, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatal("anonymous account linking allowed")
	}
	body := map[string]any{"connectionIncarnationId": parent.IncarnationID, "connectionRevision": parent.Revision, "displayName": "Private label", "token": "private-token"}
	encode := func(body any) string {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, dialect := range []string{path, strings.Replace(path, "/api/", "/control/v1/", 1)} {
		keyed := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_alice", "operator", http.MethodPost, dialect, encode(body), map[string]string{controlIdempotencyKeyHeader: "private-link-key"})
		if keyed.Code != http.StatusBadRequest {
			t.Fatalf("private account entered replay cache: %d %s", keyed.Code, keyed.Body)
		}
	}
	created := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(body))
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	var account ConnectedAccount
	if err := json.Unmarshal(created.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	if account.Source != "linked" || account.IdentityStatus != "opaque" || account.BindingMode != AccountBindingExplicit || strings.Contains(created.Body.String(), "private-token") {
		t.Fatalf("unsafe DTO: %s", created.Body)
	}
	for _, dialect := range []string{"/api/connection-model", "/control/v1/connection-model"} {
		for _, who := range []string{"usr_alice", "usr_bob"} {
			got := hostedNamespaceRequest(t, mux, key, now, who, "admin", http.MethodGet, dialect, "")
			if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "private-token") || strings.Contains(got.Body.String(), "legacy-credential") {
				t.Fatalf("read: %d %s", got.Code, got.Body)
			}
			if strings.Contains(got.Body.String(), account.ID) != (who == "usr_alice") {
				t.Fatal("administrator read another member's linked account")
			}
			var model ConnectionModel
			if err := json.Unmarshal(got.Body.Bytes(), &model); err != nil {
				t.Fatal(err)
			}
			connection := findModelConnection(t, model, parent.Name)
			if len(connection.AccountBinding.AccountIDs) != 1 || connection.AccountBinding.AccountIDs[0] == account.ID {
				t.Fatal("linked account replaced the legacy MCP binding")
			}
			if who == "usr_alice" {
				// The write response and the model entry are one projection.
				for _, entry := range model.ConnectedAccounts {
					if entry.ID == account.ID && !reflect.DeepEqual(entry, account) {
						t.Fatalf("model entry differs from the create response:\n model %+v\n write %+v", entry, account)
					}
				}
				if account.IntegrationID != integrationTokenAPI || account.OwnerKind != "linked" || account.UsableBy == nil || *account.UsableBy != (ConnectedAccountUsableBy{}) {
					t.Fatalf("create response lacks descriptive fields: %+v", account)
				}
			}
		}
	}
	mutation := map[string]any{"connectionIncarnationId": parent.IncarnationID, "connectionRevision": parent.Revision, "revision": account.Revision}
	other := hostedNamespaceRequest(t, mux, key, now, "usr_bob", "admin", http.MethodDelete, path+"/"+account.ID, encode(mutation))
	if other.Code != http.StatusNotFound {
		t.Fatalf("admin removed another member's account: %d", other.Code)
	}
	for _, role := range []string{"viewer", "service"} {
		got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", role, http.MethodPost, path, encode(body))
		if got.Code != http.StatusForbidden && got.Code != http.StatusUnauthorized {
			t.Fatalf("%s linked an account: %d", role, got.Code)
		}
	}
	body["ownerSubject"] = "usr_bob"
	forged := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(body))
	if forged.Code != http.StatusBadRequest {
		t.Fatal("accepted a forged owner")
	}
	delete(body, "ownerSubject")
	body["connectionIncarnationId"] = "stale"
	stale := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(body))
	if stale.Code != http.StatusConflict {
		t.Fatal("accepted stale connection incarnation")
	}
	control := "/control/v1/connections/" + parent.Name + "/accounts/" + account.ID + "/token"
	disconnected := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodDelete, control, encode(mutation))
	if disconnected.Code != http.StatusOK || !strings.Contains(disconnected.Body.String(), `"status":"disconnected"`) {
		t.Fatalf("control disconnect: %d %s", disconnected.Code, disconnected.Body)
	}
	if store.Token(parent.Name) != "legacy-credential" {
		t.Fatal("disconnect changed existing MCP authentication")
	}
}

func TestFileLinkedAccountLimits(t *testing.T) { testLinkedAccountLimits(t, newLibraryFileStore(t)) }
func TestPgLinkedAccountLimits(t *testing.T)   { testLinkedAccountLimits(t, newPgConnectionsStore(t)) }

func testLinkedAccountLimits(t *testing.T, store linkedAccountTestStore) {
	parent := linkedAccountFixture(t, store)
	p := accountPolicyPrecondition(parent)
	input := LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "Named", BearerToken: "token"}
	for _, token := range []string{"", "with space", "line\nbreak", "\x00", strings.Repeat("x", 16385)} {
		invalid := input
		invalid.BearerToken = token
		if _, err := store.CreateLinkedAccount(t.Context(), invalid, p); !errors.Is(err, ErrLinkedAccountInvalid) {
			t.Fatalf("invalid token accepted: %v", err)
		}
	}
	var first LinkedAccountRecord
	for i := range maxLinkedAccountsPerConnection {
		record, err := store.CreateLinkedAccount(t.Context(), input, p)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = record
		}
	}
	if _, err := store.CreateLinkedAccount(t.Context(), input, p); !errors.Is(err, ErrLinkedAccountLimit) {
		t.Fatalf("quota ignored: %v", err)
	}
	input.OwnerSubject = "usr_bob"
	if _, err := store.CreateLinkedAccount(t.Context(), input, p); err != nil {
		t.Fatalf("another owner consumed quota: %v", err)
	}
	if _, err := store.MutateLinkedAccount(t.Context(), parent.Name, first.ID, first.OwnerSubject, first.Revision, p, LinkedAccountMutation{Remove: true}); err != nil {
		t.Fatal(err)
	}
	input.OwnerSubject = "usr_alice"
	if _, err := store.CreateLinkedAccount(t.Context(), input, p); err != nil {
		t.Fatalf("removal did not release quota: %v", err)
	}
}

func TestLinkedAccountEligibility(t *testing.T) {
	parent := Account{Name: "mcp", IncarnationID: "inc", ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_alice"}
	input := LinkedAccountRecord{OwnerSubject: "usr_bob", DisplayName: "Personal", BearerToken: "token"}
	if _, err := newLinkedAccount(input, parent); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatal("another person's personal connection accepted")
	}
	input.OwnerSubject = "usr_alice"
	parent.CallerDelegated = true
	if _, err := newLinkedAccount(input, parent); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatal("caller-delegated linking accepted")
	}
}

type failingLinkedAccountReads struct{ *FileStore }

func (s failingLinkedAccountReads) LinkedAccounts(context.Context, string) ([]LinkedAccountRecord, error) {
	return nil, errors.New("private-storage-detail")
}

func TestLinkedAccountReadFailureIsClosed(t *testing.T) {
	store := newLibraryFileStore(t)
	linkedAccountFixture(t, store)
	api := NewConsoleAPI(failingLinkedAccountReads{store}, nil, nil, "", "secret", "", "", "")
	model, err := api.connectionModel(t.Context(), PlatformActor{UserID: "usr_alice", Role: "owner"})
	if !errors.Is(err, errConnectionModelUnavailable) || len(model.Connections) != 0 || strings.Contains(err.Error(), "private-storage-detail") {
		t.Fatal("failed account read returned partial or sensitive data")
	}
}
