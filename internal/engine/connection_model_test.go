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
	"testing"
)

type connectionModelStore interface {
	AccountStore
	ConnectionNamespaceStore
	MemberCredentialStore
}

func TestFileConnectionModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connections.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	testConnectionModel(t, store)
	actor := PlatformActor{UserID: "local-admin", Role: "owner"}
	before, err := (&ConsoleAPI{store: store}).connectionModel(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := (&ConsoleAPI{store: reopened}).connectionModel(t.Context(), actor)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("restart changed model identity: %v", err)
	}
}

func TestPgConnectionModel(t *testing.T) {
	testConnectionModel(t, newPgConnectionsStore(t))
}

func testConnectionModel(t *testing.T, store connectionModelStore) {
	t.Helper()
	ctx := t.Context()
	suffix := newPgFixtureSuffix()
	subject := "usr_model_" + suffix
	ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Model " + suffix, CreatedBy: subject})
	if err != nil {
		t.Fatal(err)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, "", ns.Label) })
	}
	fixtures := []Account{
		{Name: "oauth_" + suffix, AuthMode: "oauth", AccessToken: "private-access", RefreshToken: "private-refresh", ClientSecret: "private-client-secret"},
		{Name: "token_" + suffix, AuthMode: "token", BearerToken: "private-bearer"},
		{Name: "missing_" + suffix, AuthMode: "token"},
		{Name: "member_" + suffix, AuthMode: "token", BearerToken: "private-discovery-token", MemberCredentials: true},
		{Name: "delegated_" + suffix, AuthMode: "token", CallerDelegated: true, BearerToken: "private-listing-token",
			ClientID: "private-service-client", ClientSecret: testDelegatedClientSecret,
			TokenEndpoint: "https://tools.example.com/token", Resource: "https://tools.example.com/mcp"},
	}
	for i := range fixtures {
		a := &fixtures[i]
		a.URL = "https://tools.example.com/mcp"
		a.ConnectionNamespaceID = ns.ID
		if err := store.Create(ctx, *a); err != nil {
			t.Fatal(err)
		}
		*a, _ = store.Account(a.Name)
		if pg, ok := store.(*PgStore); ok {
			name := a.Name
			t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, name, "") })
		}
	}
	member := fixtures[3]
	for _, who := range []string{subject, "usr_coworker"} {
		if err := store.PutMemberCredential(ctx, MemberCredential{
			Account: member.Name, IncarnationID: member.IncarnationID, Subject: who, BearerToken: "private-token-for-" + who,
		}); err != nil {
			t.Fatal(err)
		}
	}
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, NewGateway(store, nil), nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	before := store.Accounts()
	read := func(path, user, role string) ConnectionModel {
		t.Helper()
		response := hostedNamespaceRequest(t, mux, key, now, user, role, http.MethodGet, path, "")
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s: %d %s", path, response.Code, response.Body)
		}
		for _, secret := range []string{"private-access", "private-refresh", "private-client-secret", "private-bearer", "private-discovery-token", "private-listing-token", "private-service-client", "private-token-for-", testDelegatedClientSecret, "usr_coworker"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatalf("model exposed credential or another member's identity")
			}
		}
		var model ConnectionModel
		if err := json.Unmarshal(response.Body.Bytes(), &model); err != nil {
			t.Fatal(err)
		}
		return model
	}
	model := read("/api/connection-model", subject, "operator")
	control := read("/control/v1/connection-model", subject, "operator")
	if !reflect.DeepEqual(model, control) || !reflect.DeepEqual(before, store.Accounts()) {
		t.Fatal("projection changed stored MCP connections or differs across API dialects")
	}
	if model.ContractVersion != ConnectionModelContractVersion || len(model.Integrations) != 1 || len(model.Connections) != 5 || len(model.ConnectedAccounts) != 3 {
		t.Fatalf("unexpected model: %+v", model)
	}
	for _, a := range fixtures {
		connection := findModelConnection(t, model, a.Name)
		if connection.ID != a.Name || connection.ToolPrefix != a.Name || connection.IncarnationID != a.IncarnationID || connection.Revision != a.Revision || connection.ConnectionNamespaceID != ns.ID {
			t.Fatalf("connection identity changed: %+v", connection)
		}
	}
	if got := findModelConnection(t, model, fixtures[2].Name).AccountBinding; got.Mode != AccountBindingConnection || got.CredentialState != "missing" || len(got.AccountIDs) != 0 {
		t.Fatalf("missing credentials became anonymous or connected: %+v", got)
	}
	if got := findModelConnection(t, model, fixtures[4].Name).AccountBinding; got.Mode != AccountBindingCallerDelegated || got.CredentialState != "requires_caller_grant" || len(got.AccountIDs) != 0 {
		t.Fatalf("delegated listing credential became an execution account: %+v", got)
	}
	memberID := findModelConnection(t, model, member.Name).AccountBinding.AccountIDs[0]
	for _, account := range model.ConnectedAccounts {
		if account.IdentityStatus != "opaque" || account.ConnectionIncarnationID == "" {
			t.Fatalf("invented provider identity: %+v", account)
		}
	}
	// An administrator sees connection metadata, never other members' bindings.
	admin := read("/api/connection-model", "usr_admin_without_credential", "admin")
	if got := findModelConnection(t, admin, member.Name).AccountBinding; got.CredentialState != "missing" || len(got.AccountIDs) != 0 {
		t.Fatalf("admin inherited another member or discovery credential: %+v", got)
	}
	other := read("/api/connection-model", "usr_unrelated", "operator")
	if len(other.Connections) != 0 || len(other.ConnectedAccounts) != 0 {
		t.Fatal("operator discovered an unowned connection")
	}
	for _, path := range []string{"/api/connection-model", "/control/v1/connection-model"} {
		if got := hostedNamespaceRequest(t, mux, key, now, subject, "viewer", http.MethodGet, path, ""); got.Code != http.StatusForbidden {
			t.Fatalf("viewer read %s: %d", path, got.Code)
		}
		if got := hostedNamespaceRequest(t, mux, key, now, subject, "operator", http.MethodPost, path, `{}`); got.Code != http.StatusMethodNotAllowed {
			t.Fatalf("model accepted mutation: %d", got.Code)
		}
		if got := hostedNamespaceRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, path, ""); got.Code != http.StatusUnauthorized {
			t.Fatalf("service authority was widened: %d", got.Code)
		}
		unauth := httptest.NewRecorder()
		mux.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, path, nil))
		if unauth.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous read: %d", unauth.Code)
		}
	}
	// Token rotation changes no model identity; disconnect does not fall back
	// to the shared discovery credential or another member's authorization.
	if err := store.PutMemberCredential(ctx, MemberCredential{Account: member.Name, IncarnationID: member.IncarnationID, Subject: subject, BearerToken: "private-rotated"}); err != nil {
		t.Fatal(err)
	}
	rotated := read("/api/connection-model", subject, "operator")
	if findModelConnection(t, rotated, member.Name).AccountBinding.AccountIDs[0] != memberID {
		t.Fatal("token rotation changed account identity")
	}
	if err := store.DeleteMemberCredential(ctx, member.Name, subject); err != nil {
		t.Fatal(err)
	}
	disconnected := read("/api/connection-model", subject, "operator")
	if got := findModelConnection(t, disconnected, member.Name).AccountBinding; got.CredentialState != "missing" || len(got.AccountIDs) != 0 {
		t.Fatal("disconnected member received fallback credentials")
	}
	// Recreating the same legacy name is a new connection and account identity.
	token := fixtures[1]
	oldID := findModelConnection(t, model, token.Name).AccountBinding.AccountIDs[0]
	if err := store.Delete(ctx, token.Name, token.IncarnationID, token.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: token.Name, ConnectionNamespaceID: ns.ID, URL: token.URL, AuthMode: "token", BearerToken: "private-replacement"}); err != nil {
		t.Fatal(err)
	}
	recreated := read("/api/connection-model", subject, "operator")
	if findModelConnection(t, recreated, token.Name).AccountBinding.AccountIDs[0] == oldID {
		t.Fatal("recreated connection inherited old account identity")
	}
}

func findModelConnection(t *testing.T, model ConnectionModel, id string) Connection {
	t.Helper()
	for _, connection := range model.Connections {
		if connection.ID == id {
			return connection
		}
	}
	t.Fatalf("connection %s missing", id)
	return Connection{}
}

func TestConnectedAccountIdentityDoesNotDependOnSecretsOrLabels(t *testing.T) {
	a := Account{Name: "stable_prefix", IncarnationID: "incarnation-one", Label: "Original", AuthMode: "oauth", AccessToken: "before"}
	original := projectConnectedAccount(a, AccountBindingConnection, "")
	a.Label, a.AccessToken, a.ConnectionNamespaceID, a.Revision = "Renamed", "after", "new-folder", 99
	if got := projectConnectedAccount(a, AccountBindingConnection, ""); !reflect.DeepEqual(got, original) {
		t.Fatal("display, namespace, revision or token changed the credential-slot identity")
	}
	if projectConnectedAccount(a, AccountBindingMember, "alice").ID == projectConnectedAccount(a, AccountBindingMember, "bob").ID {
		t.Fatal("members share a projected account ID")
	}
	a.Name = "separate_connection_same_provider"
	if projectConnectedAccount(a, AccountBindingConnection, "").ID == original.ID {
		t.Fatal("separate connections were merged")
	}
}

type brokenModelMemberStore struct{ *FileStore }

func (s brokenModelMemberStore) MemberCredential(context.Context, string, string) (MemberCredential, bool, error) {
	return MemberCredential{}, false, errors.New("sensitive-driver-error")
}

type brokenModelListStore struct{ *FileStore }

func (s brokenModelListStore) ListAccounts(context.Context) ([]Account, error) {
	return s.Accounts(), errors.New("sensitive-driver-error")
}

func TestConnectionModelFailsClosedOnAccountListError(t *testing.T) {
	store := newLibraryFileStore(t)
	if err := store.Create(t.Context(), Account{Name: "connected", URL: "https://tools.example/mcp", AuthMode: "token", BearerToken: "private-token"}); err != nil {
		t.Fatal(err)
	}
	api := &ConsoleAPI{store: brokenModelListStore{store}}
	w := httptest.NewRecorder()
	api.handleConnectionModel(w, httptest.NewRequest(http.MethodGet, "/api/connection-model", nil))
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "sensitive-driver-error") || strings.Contains(w.Body.String(), "connectedAccounts") {
		t.Fatalf("failed account listing exposed an empty or partial model: %d %s", w.Code, w.Body)
	}
}

func TestConnectionModelFailsClosedOnMemberReadError(t *testing.T) {
	s := newLibraryFileStore(t)
	if err := s.Create(t.Context(), Account{Name: "member", URL: "https://tools.example/mcp", AuthMode: "token", BearerToken: "listing-token", MemberCredentials: true}); err != nil {
		t.Fatal(err)
	}
	api := NewConsoleAPI(brokenModelMemberStore{s}, nil, nil, "", "secret", "", "", "")
	w := httptest.NewRecorder()
	api.handleConnectionModel(w, httptest.NewRequest(http.MethodGet, "/api/connection-model", nil))
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "sensitive-driver-error") || strings.Contains(w.Body.String(), "listing-token") || strings.Contains(w.Body.String(), "connectedAccounts") {
		t.Fatalf("failed member lookup exposed partial data: %d %s", w.Code, w.Body)
	}
}

type modelMemberFixtureStore struct {
	*FileStore
	credential MemberCredential
}

func (s modelMemberFixtureStore) MemberCredential(context.Context, string, string) (MemberCredential, bool, error) {
	return s.credential, true, nil
}

func TestConnectionModelRejectsMismatchedMemberBinding(t *testing.T) {
	store := newLibraryFileStore(t)
	if err := store.Create(t.Context(), Account{Name: "member", URL: "https://tools.example/mcp", AuthMode: "token", BearerToken: "listing-token", MemberCredentials: true}); err != nil {
		t.Fatal(err)
	}
	a, _ := store.Account("member")
	for _, credential := range []MemberCredential{
		{Account: a.Name, IncarnationID: "previous-incarnation", Subject: "alice", BearerToken: "stale"},
		{Account: a.Name, IncarnationID: a.IncarnationID, Subject: "bob", BearerToken: "coworker"},
		{Account: "another-connection", IncarnationID: a.IncarnationID, Subject: "alice", BearerToken: "other"},
	} {
		api := &ConsoleAPI{store: modelMemberFixtureStore{store, credential}}
		model, err := api.connectionModel(t.Context(), PlatformActor{UserID: "alice", Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		binding := findModelConnection(t, model, a.Name).AccountBinding
		if len(model.ConnectedAccounts) != 0 || len(binding.AccountIDs) != 0 || binding.CredentialState != "missing" {
			t.Fatal("mismatched member credential or discovery token became an account")
		}
	}
}
