package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/oauthas"
)

func clientEndpointToolNames(t *testing.T, gateway *Gateway, slug string) []string {
	t.Helper()
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	endpoint, ok := gateway.clientEndpoints[slug]
	if !ok || endpoint.kind != endpointKindClient {
		t.Fatalf("client endpoint %q is not projected", slug)
	}
	names := append([]string(nil), endpoint.names...)
	sort.Strings(names)
	return names
}

func newMCPClientGateway(t *testing.T) (*FileStore, *Gateway) {
	t.Helper()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}
	return store, gateway
}

// TestLegacyGroupOnlyUpsertRevokesScopedOAuthAccess exercises the exact
// persistence shape submitted by the self-hosted /admin/token form: an
// existing token account arrives with a new legacy Group but no first-class
// ownership fields. The compatibility write may move the account, but must
// atomically rotate the scoped client epoch before the old bearer token can
// observe the different tool set.
func TestLegacyGroupOnlyUpsertRevokesScopedOAuthAccess(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	if err := store.Create(ctx, Account{
		Name: "legacy_notion", Label: "Legacy Notion", Group: "Source folder",
		URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "source-token",
	}); err != nil {
		t.Fatalf("create source account: %v", err)
	}
	account, ok := store.Account("legacy_notion")
	if !ok || account.ConnectionNamespaceID == "" {
		t.Fatalf("source account = %+v ok=%v", account, ok)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Local legacy Codex", Subject: "local-admin", CreatedBy: "local-admin",
		ConnectionNamespaceIDs: []string{account.ConnectionNamespaceID},
	})
	if err != nil {
		t.Fatalf("create scoped client: %v", err)
	}
	if n := gateway.Aggregate(ctx); n != 1 {
		t.Fatalf("aggregate = %d, want 1", n)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatalf("refresh scoped clients: %v", err)
	}

	const issuer = "https://engine.example"
	authorization := oauthas.New(issuer, "pw", "test-secret")
	if err := authorization.ConfigureTokenGeneration(ctx, store); err != nil {
		t.Fatalf("configure token generation: %v", err)
	}
	authorization.SetEpochLookup(func(path string) (string, bool) {
		slug, ok := mcpClientSlugFromResource(path)
		if !ok {
			return "", false
		}
		return gateway.MCPClientEpoch(slug)
	})
	authorization.SetClientResourceAuthorizer(gateway.MCPClientAllowsOAuthClient)
	authorization.SetLocalConsentAuthorizer(gateway.AuthorizeMCPConsent)
	mux := http.NewServeMux()
	authorization.Routes(mux)
	protectedCalls := 0
	mux.Handle("/mcp/clients/{slug}", authorization.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		w.WriteHeader(http.StatusNoContent)
	})))

	redirectURI := "https://client.example/callback"
	registrationBody, err := json.Marshal(map[string]any{
		"client_name":   "legacy token regression",
		"redirect_uris": []string{redirectURI},
	})
	if err != nil {
		t.Fatal(err)
	}
	registration := httptest.NewRecorder()
	mux.ServeHTTP(registration, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(registrationBody))))
	if registration.Code != http.StatusCreated {
		t.Fatalf("register = %d, body %s", registration.Code, registration.Body)
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(registration.Body.Bytes(), &registered); err != nil || registered.ClientID == "" {
		t.Fatalf("decode registration: client=%q err=%v", registered.ClientID, err)
	}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	resource := issuer + "/mcp/clients/" + client.Slug
	authorizeForm := url.Values{
		"client_id":             {registered.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"resource":              {resource},
		"password":              {"pw"},
	}
	authorize := httptest.NewRecorder()
	authorizeRequest := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(authorizeForm.Encode()))
	authorizeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(authorize, authorizeRequest)
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize = %d, body %s", authorize.Code, authorize.Body)
	}
	location, err := url.Parse(authorize.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorize redirect = %q err=%v", authorize.Header().Get("Location"), err)
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {location.Query().Get("code")},
		"client_id":     {registered.ClientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"resource":      {resource},
	}
	token := httptest.NewRecorder()
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(token, tokenRequest)
	if token.Code != http.StatusOK {
		t.Fatalf("token = %d, body %s", token.Code, token.Body)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(token.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("decode access token: token=%q err=%v", tokens.AccessToken, err)
	}
	beforeRequest := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+client.Slug, nil)
	beforeRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	before := httptest.NewRecorder()
	mux.ServeHTTP(before, beforeRequest)
	if before.Code != http.StatusNoContent || protectedCalls != 1 {
		t.Fatalf("pre-move scoped access = %d calls=%d, want 204/1; body %s", before.Code, protectedCalls, before.Body)
	}

	// This is the legacy /admin/token write shape. It intentionally changes
	// only the human-readable Group; Upsert derives the new durable folder.
	if err := store.Upsert(ctx, Account{
		Name: account.Name, Label: "Moved through legacy token form", Group: "Target folder",
		URL: account.URL, AuthMode: "token", BearerToken: "target-token",
	}); err != nil {
		t.Fatalf("legacy group-only Upsert: %v", err)
	}
	moved, ok := store.Account(account.Name)
	if !ok || moved.ConnectionNamespaceID == account.ConnectionNamespaceID {
		t.Fatalf("legacy Upsert did not change durable ownership: before=%+v after=%+v", account, moved)
	}
	if _, err := gateway.AddAccount(ctx, account.Name); err != nil {
		t.Fatalf("aggregate legacy replacement: %v", err)
	}
	afterClient, ok := store.MCPClient(ctx, client.ID)
	if !ok || afterClient.Epoch == client.Epoch || afterClient.Revision != client.Revision+2 { // bind + move
		t.Fatalf("legacy move did not rotate scoped client epoch: before=%+v after=%+v", client, afterClient)
	}

	afterRequest := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+client.Slug, nil)
	afterRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	after := httptest.NewRecorder()
	mux.ServeHTTP(after, afterRequest)
	if after.Code != http.StatusUnauthorized || protectedCalls != 1 {
		t.Fatalf("stale scoped access after legacy group move = %d calls=%d, want 401/1; body %s", after.Code, protectedCalls, after.Body)
	}
}

func TestMCPClientEndpointsKeepPersonalConnectionsSubjectBound(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	shared, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Shared", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	aliceFolder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Alice private", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	bobFolder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Bob private", CreatedBy: "usr_bob"})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{Name: "team_notion", ConnectionNamespaceID: shared.ID, ConnectionScope: ConnectionScopeShared, URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team"},
		{Name: "alice_notion", ConnectionNamespaceID: aliceFolder.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_alice", URL: "https://alice.example/mcp", AuthMode: "token", BearerToken: "alice"},
		{Name: "bob_notion", ConnectionNamespaceID: bobFolder.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_bob", URL: "https://bob.example/mcp", AuthMode: "token", BearerToken: "bob"},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatalf("create %s: %v", account.Name, err)
		}
	}

	if n := gateway.Aggregate(ctx); n != 1 {
		t.Fatalf("aggregate root projection count=%d, want only the shared account", n)
	}
	gateway.mu.Lock()
	rootAlice := append([]string(nil), gateway.byAcct["alice_notion"]...)
	rootBob := append([]string(nil), gateway.byAcct["bob_notion"]...)
	rootShared := append([]string(nil), gateway.byAcct["team_notion"]...)
	gateway.mu.Unlock()
	if len(rootAlice) != 0 || len(rootBob) != 0 || len(rootShared) != 1 {
		t.Fatalf("aggregate root projection shared=%v alice=%v bob=%v", rootShared, rootAlice, rootBob)
	}

	alice, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice",
		ConnectionNamespaceIDs: []string{shared.ID, aliceFolder.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Bob Claude", Subject: "usr_bob", CreatedBy: "usr_bob",
		ConnectionNamespaceIDs: []string{shared.ID, bobFolder.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := clientEndpointToolNames(t, gateway, alice.Slug), []string{"alice_notion__search", "team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("alice client tools=%v want=%v", got, want)
	}
	if got, want := clientEndpointToolNames(t, gateway, bob.Slug), []string{"bob_notion__search", "team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("bob client tools=%v want=%v", got, want)
	}

	// Moving a connection out of the granted folder invalidates the final
	// account guard immediately, then a rebuild removes it from tools/list.
	extra, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Elsewhere", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	team, _ := store.Account("team_notion")
	if _, err := store.MoveAccountToConnectionNamespace(ctx, team.Name, team.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: extra.ID, Scope: ConnectionScopeShared,
	}, team.Revision); err != nil {
		t.Fatal(err)
	}
	if gateway.mcpClientMayUseAccount(ctx, alice.Slug, team.Name, team.IncarnationID) {
		t.Fatal("moved account remained callable through a stale client endpoint")
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := clientEndpointToolNames(t, gateway, alice.Slug), []string{"alice_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("alice tools after folder move=%v want=%v", got, want)
	}
}

func TestGatewayAccountMoveRotatesAffectedMCPClientDeliveryEpochs(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Target"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "team_notion", ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team",
	}); err != nil {
		t.Fatal(err)
	}
	if n := gateway.Aggregate(ctx); n != 1 {
		t.Fatalf("aggregate count=%d want=1", n)
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
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := clientEndpointToolNames(t, gateway, loses.Slug), []string{"team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("source endpoint tools before move=%v want=%v", got, want)
	}
	if got := clientEndpointToolNames(t, gateway, gains.Slug); len(got) != 0 {
		t.Fatalf("target endpoint unexpectedly had tools before move: %v", got)
	}
	if got, want := clientEndpointToolNames(t, gateway, keeps.Slug), []string{"team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("both endpoint tools before move=%v want=%v", got, want)
	}

	var revoked []string
	gateway.SetTokenRevoker(func(path string) { revoked = append(revoked, path) })
	account, ok := store.Account("team_notion")
	if !ok {
		t.Fatal("account missing before gateway move")
	}
	if _, err := gateway.MoveAccountToConnectionNamespace(ctx, account.Name, account.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, account.Revision); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		before  MCPClient
		changed bool
	}{
		{name: "source", before: loses, changed: true},
		{name: "target", before: gains, changed: true},
		{name: "both", before: keeps, changed: false},
	} {
		after, ok := store.MCPClient(ctx, test.before.ID)
		if !ok {
			t.Fatalf("%s client missing after move", test.name)
		}
		if test.changed {
			if after.Epoch == test.before.Epoch || after.Revision != test.before.Revision+1 {
				t.Fatalf("%s delivery epoch did not rotate: before=%+v after=%+v", test.name, test.before, after)
			}
			if liveEpoch, live := gateway.MCPClientEpoch(after.Slug); !live || liveEpoch != after.Epoch {
				t.Fatalf("%s live endpoint did not publish its durable new epoch: epoch=%q live=%v", test.name, liveEpoch, live)
			}
		} else if after.Epoch != test.before.Epoch || after.Revision != test.before.Revision {
			t.Fatalf("%s client rotated without changing delivery: before=%+v after=%+v", test.name, test.before, after)
		}
	}
	sort.Strings(revoked)
	wantRevoked := []string{"/mcp/clients/" + gains.Slug, "/mcp/clients/" + loses.Slug}
	sort.Strings(wantRevoked)
	if !sameStrings(revoked, wantRevoked) {
		t.Fatalf("OAuth refresh grants revoked=%v want=%v", revoked, wantRevoked)
	}
	if got := clientEndpointToolNames(t, gateway, loses.Slug); len(got) != 0 {
		t.Fatalf("source endpoint retained moved tool: %v", got)
	}
	if got, want := clientEndpointToolNames(t, gateway, gains.Slug), []string{"team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("target endpoint tools after move=%v want=%v", got, want)
	}
	if got, want := clientEndpointToolNames(t, gateway, keeps.Slug), []string{"team_notion__search"}; !sameStrings(got, want) {
		t.Fatalf("both endpoint tools after move=%v want=%v", got, want)
	}
}

func TestMCPClientStaleHandlerRejectsSameNameReplacement(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Alice private", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "alice_notion", ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopePersonal,
		OwnerSubject: "usr_alice", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "first",
	}); err != nil {
		t.Fatal(err)
	}
	first, _ := store.Account("alice_notion")
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice", ConnectionNamespaceIDs: []string{folder.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	innerCalled := false
	guarded := gateway.clientAccountHandler(client.Slug, first.Name, first.IncarnationID,
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			innerCalled = true
			return mcp.NewToolResultText("unexpected"), nil
		})

	if err := store.Delete(ctx, first.Name, first.IncarnationID, first.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: first.Name, ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopePersonal,
		OwnerSubject: "usr_alice", URL: first.URL, AuthMode: "token", BearerToken: "replacement",
	}); err != nil {
		t.Fatal(err)
	}
	result, err := guarded(ctx, mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("stale client handler protocol error: %v", err)
	}
	if innerCalled || result == nil || !result.IsError {
		t.Fatalf("stale client handler reached replacement: innerCalled=%v result=%+v", innerCalled, result)
	}
}

func TestMCPClientOAuthBindingRequiresItsOwnerAndDiesOnReset(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Personal", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "alice_notion", ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopePersonal,
		OwnerSubject: "usr_alice", URL: "https://alice.example/mcp", AuthMode: "token", BearerToken: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	gateway.Aggregate(ctx)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice", ConnectionNamespaceIDs: []string{folder.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	resource := "/mcp/clients/" + client.Slug
	if gateway.MCPClientAllowsOAuthClient("dcr-alice", resource) {
		t.Fatal("unbound OAuth registration was accepted")
	}
	if err := gateway.AuthorizeMCPConsent(ctx, "usr_bob", "operator", "dcr-alice", resource); err == nil {
		t.Fatal("another member authorized Alice's MCP client")
	}
	if err := gateway.AuthorizeMCPConsent(ctx, "usr_alice", "operator", "dcr-alice", resource); err != nil {
		t.Fatalf("owner consent: %v", err)
	}
	if !gateway.MCPClientAllowsOAuthClient("dcr-alice", resource) {
		t.Fatal("bound OAuth registration was not accepted")
	}
	if gateway.MCPClientAllowsOAuthClient("dcr-other", resource) {
		t.Fatal("different OAuth registration was accepted")
	}

	bound, ok := store.ActiveMCPClient(ctx, client.ID)
	if !ok {
		t.Fatal("bound client missing")
	}
	if _, err := store.ResetMCPClientOAuthClient(ctx, bound.ID, MCPClientPrecondition{ID: bound.ID, Revision: bound.Revision}); err != nil {
		t.Fatal(err)
	}
	if gateway.MCPClientAllowsOAuthClient("dcr-alice", resource) {
		t.Fatal("pre-reset OAuth registration remained valid")
	}
	if _, live := gateway.MCPClientEpoch(client.Slug); !live {
		t.Fatal("active client endpoint disappeared instead of rotating after reset")
	}
	if err := gateway.AuthorizeMCPConsent(ctx, "usr_alice", "operator", "dcr-new", resource); err != nil {
		t.Fatalf("rebind after explicit reset: %v", err)
	}
	if !gateway.MCPClientAllowsOAuthClient("dcr-new", resource) {
		t.Fatal("rebound OAuth registration was not accepted")
	}
	if err := gateway.AuthorizeMCPConsent(ctx, "usr_alice", "operator", "dcr-third", resource); !errors.Is(err, ErrMCPClientOAuthBinding) {
		t.Fatalf("silent OAuth rebind = %v, want binding conflict", err)
	}
}
