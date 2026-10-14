package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// hostedNamespaceConsole assembles two credential folders and a hosted Engine
// actor boundary. The operator is delegated only the Team folder; Private is
// intentionally ungranted. This gives the handler tests a realistic
// cross-namespace authorization target without relying on browser headers.
func hostedNamespaceConsole(t *testing.T) (*http.ServeMux, *FileStore, *Gateway, ed25519.PrivateKey, time.Time, ConnectionNamespace, ConnectionNamespace) {
	t.Helper()
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
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
	private, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Private", CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{
			Name: "team_notion", Label: "Team Notion", Group: team.Label,
			URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team-secret",
			ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
		},
		{
			Name: "private_notion", Label: "Private Notion", Group: private.Label,
			URL: "https://private.example/mcp", AuthMode: "token", BearerToken: "private-secret",
			ConnectionNamespaceID: private.ID, ConnectionScope: ConnectionScopeShared,
		},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	gateway.SetAudit(store)
	api := NewConsoleAPI(
		store,
		gateway,
		nil,
		"local-password",
		"local-secret",
		"https://engine.example",
		"https://app.example",
		"",
		WithAdminToken("machine-token"),
		WithLocalAdminAuth(false),
		WithPlatformActorVerifier(verifier),
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, store, gateway, key, now, team, private
}

func hostedNamespaceRequest(
	t *testing.T,
	mux *http.ServeMux,
	key ed25519.PrivateKey,
	now time.Time,
	userID, role, method, requestPath, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes := []byte(body)
	claims := actorClaimsForTest(now, method, requestPath, bodyBytes)
	claims.UserID, claims.Role = userID, role
	request := actorRequest(method, requestPath, bodyBytes, signActorAssertionForTest(t, key, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

func TestHostedOperatorNamespaceBoundaryCoversEveryPerAccountControlRoute(t *testing.T) {
	mux, store, gateway, key, now, team, private := hostedNamespaceConsole(t)
	ctx := context.Background()
	if err := store.LogPending(ctx, PendingCall{ID: "team-approval", Account: "team_notion", Tool: "save", Status: ApprovalPending}); err != nil {
		t.Fatal(err)
	}
	if err := store.LogPending(ctx, PendingCall{ID: "private-approval", Account: "private_notion", Tool: "save", Status: ApprovalPending}); err != nil {
		t.Fatal(err)
	}
	store.LogCall(CallRecord{Account: "team_notion", Tool: "search"})
	store.LogCall(CallRecord{Account: "private_notion", Tool: "search"})

	// An operator sees only the one explicitly delegated folder and account.
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/connection-namespaces", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET connection namespaces = %d: %s", response.Code, response.Body)
	}
	var namespaces []connectionNamespaceDTO
	if err := json.Unmarshal(response.Body.Bytes(), &namespaces); err != nil || len(namespaces) != 1 || namespaces[0].ID != team.ID {
		t.Fatalf("operator namespace list = %#v, err=%v; want Team only", namespaces, err)
	}

	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/servers", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET accounts = %d: %s", response.Code, response.Body)
	}
	var accounts []serverDTO
	if err := json.Unmarshal(response.Body.Bytes(), &accounts); err != nil || len(accounts) != 1 || accounts[0].UUID != "team_notion" {
		t.Fatalf("operator account list = %#v, err=%v; want Team Notion only", accounts, err)
	}

	// Every account-specific control surface uses the same durable manager
	// check. A guessed prefix must not reveal whether the other credential
	// exists, much less update it or begin OAuth.
	for _, attempt := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/servers/private_notion/connect", `{}`},
		{http.MethodPost, "/api/servers/private_notion/token", `{"token":"attacker"}`},
		{http.MethodGet, "/api/servers/private_notion/tools", ""},
		{http.MethodPut, "/api/servers/private_notion/tools/search", `{"enabled":false}`},
	} {
		response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", attempt.method, attempt.path, attempt.body)
		if response.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d body=%s; want 404", attempt.method, attempt.path, response.Code, response.Body)
		}
	}
	if account, _ := store.Account("private_notion"); account.BearerToken != "private-secret" {
		t.Fatalf("ungranted token route changed private credential: %+v", account)
	}

	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/approvals", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET approvals = %d: %s", response.Code, response.Body)
	}
	var approvals []PendingCall
	if err := json.Unmarshal(response.Body.Bytes(), &approvals); err != nil || len(approvals) != 1 || approvals[0].ID != "team-approval" {
		t.Fatalf("operator approvals = %#v, err=%v; want Team only", approvals, err)
	}
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/approvals/private-approval/approve", `{}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("ungranted approval decision = %d body=%s; want 404", response.Code, response.Body)
	}

	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/logs", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET logs = %d: %s", response.Code, response.Body)
	}
	var calls []CallRecord
	if err := json.Unmarshal(response.Body.Bytes(), &calls); err != nil || len(calls) != 1 || calls[0].Account != "team_notion" {
		t.Fatalf("operator logs = %#v, err=%v; want Team only", calls, err)
	}

	// Shared endpoint composition and membership delegation are a different
	// authority from a credential folder. Operators cannot make an arbitrary
	// managed credential visible through a workspace-wide delivery endpoint.
	for _, path := range []string{
		"/api/connectors",
		"/api/endpoints",
		"/api/connection-namespaces/" + team.ID + "/managers",
	} {
		response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, path, "")
		if response.Code != http.StatusForbidden {
			t.Errorf("operator GET %s = %d body=%s; want 403", path, response.Code, response.Body)
		}
	}

	// Shared folders are created by an owner/admin and then delegated. An
	// invited operator must not be able to manufacture a new manager boundary
	// simply by POSTing a folder label.
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/connection-namespaces", `{"label":"Operator-owned shared folder"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator shared folder create = %d body=%s; want 403", response.Code, response.Body)
	}
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/servers", `{"name":"Typed personal folder","toolPrefix":"typed_personal_folder","connectionScope":"personal","connectionNamespace":"Operator-owned shared folder","group":"Operator-owned shared folder","url":"https://typed-personal.example/mcp","bearerToken":"typed-personal-token"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator typed personal folder create = %d body=%s; want 403", response.Code, response.Body)
	}
	if _, found := store.Account("typed_personal_folder"); found {
		t.Fatal("operator personal create minted a reusable shared folder")
	}

	// A newly invited operator gets a private, durable starting place rather
	// than silently attaching their credential to General/root MCP exposure.
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/servers", `{"name":"My Notion","toolPrefix":"my_notion","url":"https://mine.example/mcp","bearerToken":"personal-token"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("operator personal create = %d: %s", response.Code, response.Body)
	}
	var created serverDTO
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ConnectionScope != string(ConnectionScopePersonal) || created.OwnerSubject != "usr_operator" || created.ConnectionNamespaceID == "" {
		t.Fatalf("operator personal account = %+v; want owned personal namespace", created)
	}
	if ns, ok := store.ConnectionNamespace(ctx, created.ConnectionNamespaceID); !ok || ns.Label != "Personal" || ns.CreatedBy != "usr_operator" {
		t.Fatalf("operator personal namespace = %+v ok=%v", ns, ok)
	}
	if account, _ := store.Account("my_notion"); !account.IsPersonal() || account.OwnerSubject != "usr_operator" {
		t.Fatalf("operator account was not private by default: %+v", account)
	}

	// A namespace manager can deliberately contribute a shared credential to
	// the folder they manage. The request must opt into shared scope and name
	// the durable namespace ID; this is intentionally not a workspace-wide
	// operator capability.
	response = hostedNamespaceRequest(
		t,
		mux,
		key,
		now,
		"usr_operator",
		"operator",
		http.MethodPost,
		"/api/servers",
		`{"name":"Team Linear","toolPrefix":"team_linear","connectionScope":"shared","connectionNamespaceId":"`+team.ID+`","connectionNamespace":"Team","group":"Team","url":"https://linear.example/mcp","bearerToken":"team-token"}`,
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("delegated shared create = %d: %s", response.Code, response.Body)
	}
	var shared serverDTO
	if err := json.Unmarshal(response.Body.Bytes(), &shared); err != nil {
		t.Fatal(err)
	}
	if shared.ConnectionScope != string(ConnectionScopeShared) || shared.OwnerSubject != "" || shared.ConnectionNamespaceID != team.ID {
		t.Fatalf("delegated shared account = %+v; want shared Team assignment", shared)
	}

	// The same durable manager grant controls moves. A label-only move cannot
	// mint a new folder, while a move into another owner-created, delegated
	// folder succeeds without changing the shared account's scope.
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPatch, "/api/servers/team_notion", `{"connectionNamespace":"Operator move target","group":"Operator move target"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator typed move target = %d body=%s; want 403", response.Code, response.Body)
	}
	delegatedTarget, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Delegated target", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture inserts credentials directly rather than probing a real
	// upstream. Mark its existing root projection as cached so this handler
	// exercise verifies the move policy without attempting a network dial.
	gateway.mu.Lock()
	gateway.cached["team_notion"] = []cachedTool{}
	gateway.mu.Unlock()
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPatch, "/api/servers/team_notion", `{"connectionNamespaceId":"`+delegatedTarget.ID+`","connectionNamespace":"Delegated target","group":"Delegated target"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("operator delegated move = %d body=%s", response.Code, response.Body)
	}
	if moved, found := store.Account("team_notion"); !found || moved.ConnectionNamespaceID != delegatedTarget.ID || moved.ConnectionScope != ConnectionScopeShared {
		t.Fatalf("operator delegated move stored %+v found=%v; want shared delegated target", moved, found)
	}

	// A label alone is never enough to mint a new shared authority boundary,
	// and a manager grant for Team cannot be used to attach a credential to a
	// different folder.
	for _, input := range []struct {
		name string
		body string
	}{
		{
			name: "missing durable namespace id",
			body: `{"name":"Typed folder","toolPrefix":"typed_folder","connectionScope":"shared","connectionNamespace":"Typed folder","group":"Typed folder","url":"https://typed.example/mcp","bearerToken":"typed-token"}`,
		},
		{
			name: "ungranted namespace",
			body: `{"name":"Private Linear","toolPrefix":"private_linear","connectionScope":"shared","connectionNamespaceId":"` + private.ID + `","connectionNamespace":"Private","group":"Private","url":"https://private-linear.example/mcp","bearerToken":"private-token"}`,
		},
	} {
		response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/servers", input.body)
		if response.Code != http.StatusForbidden {
			t.Errorf("%s shared create = %d body=%s; want 403", input.name, response.Code, response.Body)
		}
	}
	if _, found := store.Account("typed_folder"); found {
		t.Fatal("operator created a shared account by inventing a namespace label")
	}
	if _, found := store.Account("private_linear"); found {
		t.Fatal("operator created a shared account in an ungranted namespace")
	}
	if private.ID == "" { // keep the fixture's second folder meaningfully used.
		t.Fatal("private namespace fixture missing")
	}
}

func TestHostedOwnerCanRevokeCreatorManagerGrant(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	ctx := context.Background()
	ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Revocable creator", CreatedBy: "usr_operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sameManagerGrants(ns.ManagerGrants, []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}}) {
		t.Fatalf("creator did not receive an explicit initial manager grant: %+v", ns.ManagerGrants)
	}

	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/connection-namespaces/"+ns.ID, "")
	if response.Code != http.StatusOK {
		t.Fatalf("creator GET before revocation = %d body=%s; want 200", response.Code, response.Body)
	}
	var before connectionNamespaceDTO
	if err := json.Unmarshal(response.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before.CanDelete {
		t.Fatal("creator attribution granted delete permission")
	}

	response = hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodDelete, "/api/connection-namespaces/"+ns.ID+"/managers/usr_operator", `{"revision":1}`)
	if response.Code != http.StatusOK {
		t.Fatalf("owner revoke creator manager grant = %d body=%s; want 200", response.Code, response.Body)
	}
	stored, found := store.ConnectionNamespace(ctx, ns.ID)
	if !found || stored.CreatedBy != "usr_operator" || len(stored.ManagerGrants) != 0 {
		t.Fatalf("creator audit attribution or revoked grant persisted incorrectly: %+v found=%v", stored, found)
	}

	for _, attempt := range []struct {
		method string
		body   string
	}{
		{method: http.MethodGet},
		{method: http.MethodPatch, body: `{"label":"should not change","revision":2}`},
		{method: http.MethodDelete, body: `{"revision":2}`},
	} {
		response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", attempt.method, "/api/connection-namespaces/"+ns.ID, attempt.body)
		if response.Code != http.StatusNotFound {
			t.Errorf("revoked creator %s namespace = %d body=%s; want 404", attempt.method, response.Code, response.Body)
		}
	}
}

func TestSetBearerTokenUsesOwnershipRevisionCAS(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	from, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "From", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	to, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "To", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "notion", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "old-token",
		ConnectionNamespaceID: from.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Account("notion")
	if _, err := store.MoveAccountToConnectionNamespace(ctx, "notion", before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: to.ID, Scope: ConnectionScopeShared,
	}, before.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetBearerToken(ctx, "notion", before.IncarnationID, "attacker-token", before.Revision); !errors.Is(err, ErrConnectionNamespaceRevision) {
		t.Fatalf("stale token update = %v; want revision conflict", err)
	}
	after, _ := store.Account("notion")
	if after.ConnectionNamespaceID != to.ID || after.BearerToken != "old-token" {
		t.Fatalf("stale token update restored old assignment or changed token: %+v", after)
	}
}

// accountQueryCountingStore counts per-row Account and ConnectionNamespace
// lookups, and whole account listings, so list tests can prove their
// visibility checks are batched.
type accountQueryCountingStore struct {
	*FileStore
	accountQueries   atomic.Int32
	accountListings  atomic.Int32
	namespaceQueries atomic.Int32
}

func (s *accountQueryCountingStore) Account(name string) (Account, bool) {
	s.accountQueries.Add(1)
	return s.FileStore.Account(name)
}

func (s *accountQueryCountingStore) Accounts() []Account {
	s.accountListings.Add(1)
	return s.FileStore.Accounts()
}

func (s *accountQueryCountingStore) ConnectionNamespace(ctx context.Context, id string) (ConnectionNamespace, bool) {
	s.namespaceQueries.Add(1)
	return s.FileStore.ConnectionNamespace(ctx, id)
}

func (s *accountQueryCountingStore) resetCounts() {
	s.accountQueries.Store(0)
	s.accountListings.Store(0)
	s.namespaceQueries.Store(0)
}

// countingNamespaceConsole is hostedNamespaceConsole over a counting store,
// with a third account in the delegated Team folder and a provider seam that
// records every account it lists tools for.
func countingNamespaceConsole(t *testing.T) (*http.ServeMux, *accountQueryCountingStore, ed25519.PrivateKey, time.Time, func() []string) {
	t.Helper()
	ctx := context.Background()
	base, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &accountQueryCountingStore{FileStore: base}
	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	private, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Private", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{Name: "team_notion", ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared, URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "t"},
		{Name: "team_linear", ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared, URL: "https://linear.example/mcp", AuthMode: "token", BearerToken: "t"},
		{Name: "private_notion", ConnectionNamespaceID: private.ID, ConnectionScope: ConnectionScopeShared, URL: "https://private.example/mcp", AuthMode: "token", BearerToken: "t"},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	gateway.SetAudit(store)
	var mu sync.Mutex
	var listed []string
	gateway.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		mu.Lock()
		listed = append(listed, a.Name)
		mu.Unlock()
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	api := NewConsoleAPI(store, gateway, nil, "local-password", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, store, key, now, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), listed...)
		sort.Strings(out)
		return out
	}
}

// TestOwnerConsoleListsReadNothingPerAccount: an administrator sees every
// account, so the list routes decide visibility without any per-account
// store read (the account check used to look the namespace up first).
func TestOwnerConsoleListsReadNothingPerAccount(t *testing.T) {
	mux, store, key, now, _ := countingNamespaceConsole(t)
	store.LogCall(CallRecord{Account: "team_notion", Tool: "search"})
	store.LogCall(CallRecord{Account: "private_notion", Tool: "search"})
	for _, path := range []string{"/api/servers", "/api/health", "/api/logs"} {
		store.resetCounts()
		response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("owner GET %s = %d: %s", path, response.Code, response.Body)
		}
		if accounts, namespaces := store.accountQueries.Load(), store.namespaceQueries.Load(); accounts != 0 || namespaces != 0 {
			t.Fatalf("owner GET %s made %d account and %d namespace reads, want none", path, accounts, namespaces)
		}
	}
}

// TestOperatorHealthProbesOnlyAccountsItCanSee: an operator's health request
// is answered for, and probes, only the accounts in its delegated folder,
// with one lookup per namespace rather than one per account.
func TestOperatorHealthProbesOnlyAccountsItCanSee(t *testing.T) {
	mux, store, key, now, listed := countingNamespaceConsole(t)
	store.resetCounts()
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/health", "")
	if response.Code != http.StatusOK {
		t.Fatalf("operator GET /api/health = %d: %s", response.Code, response.Body)
	}
	var rows []AccountHealth
	if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("operator health = %s (err %v), want the two Team accounts", response.Body, err)
	}
	if got := listed(); len(got) != 2 || got[0] != "team_linear" || got[1] != "team_notion" {
		t.Fatalf("operator health listed tools for %v, want only the Team accounts", got)
	}
	if accounts, namespaces := store.accountQueries.Load(), store.namespaceQueries.Load(); accounts != 0 || namespaces != 2 {
		t.Fatalf("operator health made %d account and %d namespace reads, want 0 and one per namespace (2)", accounts, namespaces)
	}

	store.resetCounts()
	response = hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/servers", "")
	var servers []serverDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &servers) != nil || len(servers) != 2 {
		t.Fatalf("operator GET /api/servers = %d: %s", response.Code, response.Body)
	}
	if accounts, namespaces := store.accountQueries.Load(), store.namespaceQueries.Load(); accounts != 0 || namespaces != 2 {
		t.Fatalf("operator servers made %d account and %d namespace reads, want 0 and 2", accounts, namespaces)
	}
}

// TestOperatorActivityPagingListsAccountsOnce: when visible rows are sparse,
// the activity list pages through several raw store pages; it lists the
// accounts once per request, not once per page.
func TestOperatorActivityPagingListsAccountsOnce(t *testing.T) {
	mux, store, key, now, _ := countingNamespaceConsole(t)
	for i := 0; i < 250; i++ {
		account := "private_notion"
		if i%5 == 0 {
			account = "team_notion"
		}
		store.LogCall(CallRecord{Account: account, Tool: "search"})
	}
	store.resetCounts()
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/logs", "")
	var calls []CallRecord
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &calls) != nil || len(calls) != 50 {
		t.Fatalf("operator GET /api/logs = %d with %d rows, want the 50 Team rows", response.Code, len(calls))
	}
	if listings, accounts, namespaces := store.accountListings.Load(), store.accountQueries.Load(), store.namespaceQueries.Load(); listings != 1 || accounts != 0 || namespaces > 2 {
		t.Fatalf("three raw pages made %d account listings, %d account reads and %d namespace reads; want 1, 0 and at most 2", listings, accounts, namespaces)
	}
}

func TestHostedOperatorActivityListBatchesVisibilityChecks(t *testing.T) {
	ctx := context.Background()
	base, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &accountQueryCountingStore{FileStore: base}
	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	private, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Private", CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{
			Name: "team_notion", Label: "Team Notion", Group: team.Label,
			URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team-secret",
			ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
		},
		{
			Name: "private_notion", Label: "Private Notion", Group: private.Label,
			URL: "https://private.example/mcp", AuthMode: "token", BearerToken: "private-secret",
			ConnectionNamespaceID: private.ID, ConnectionScope: ConnectionScopeShared,
		},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	gateway.SetAudit(store)
	api := NewConsoleAPI(
		store,
		gateway,
		nil,
		"local-password",
		"local-secret",
		"https://engine.example",
		"https://app.example",
		"",
		WithAdminToken("machine-token"),
		WithLocalAdminAuth(false),
		WithPlatformActorVerifier(verifier),
	)
	mux := http.NewServeMux()
	api.Routes(mux)

	// A full activity page of mixed visible/hidden records.
	for i := 0; i < 100; i++ {
		account := "team_notion"
		if i%2 == 1 {
			account = "private_notion"
		}
		store.LogCall(CallRecord{Account: account, Tool: "search"})
	}

	// The per-row reference behavior, evaluated through the live single-record
	// path before any counting begins.
	operator := PlatformActor{UserID: "usr_operator", Role: "operator"}
	calls, err := store.RecentCalls(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]CallRecord, 0, len(calls))
	for _, call := range calls {
		if api.visibleCall(ctx, operator, call) {
			expected = append(expected, call)
		}
	}
	if len(expected) != 50 {
		t.Fatalf("reference partitioning kept %d records, want the 50 Team records", len(expected))
	}
	var wantBody bytes.Buffer
	if err := json.NewEncoder(&wantBody).Encode(expected); err != nil {
		t.Fatal(err)
	}

	store.accountQueries.Store(0)
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/logs", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/logs = %d: %s", response.Code, response.Body)
	}
	if got := store.accountQueries.Load(); got != 0 {
		t.Fatalf("operator /api/logs issued %d per-row Account queries, want none (batched read)", got)
	}
	if !bytes.Equal(response.Body.Bytes(), wantBody.Bytes()) {
		t.Fatalf("batched activity response differs from per-row behavior:\n got: %s\nwant: %s", response.Body, wantBody.String())
	}
}
