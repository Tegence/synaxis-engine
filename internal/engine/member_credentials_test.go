package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/upstreamoauth"
)

type memberCredentialTestStore interface {
	AccountStore
	ConnectionNamespaceStore
	MemberCredentialStore
}

func TestFileStoreMemberCredentials(t *testing.T) {
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	testMemberCredentialStore(t, store, "file")
}

func TestPgStoreMemberCredentials(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	cipher, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)
	name := testMemberCredentialStore(t, store, "pg_"+newPgFixtureSuffix())

	// Tokens are encrypted at rest. The account row is gone by now, so
	// write one more credential to look at.
	if err := store.Create(ctx, Account{Name: name, URL: "https://github.example/mcp", AuthMode: "token", BearerToken: "owner"}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		a, _ := store.Account(name)
		_ = store.Delete(ctx, name, a.IncarnationID, a.Revision)
	}()
	a, _ := store.Account(name)
	if err := store.PutMemberCredential(ctx, MemberCredential{Account: name, IncarnationID: a.IncarnationID, Subject: "usr_alice", BearerToken: "alice-secret"}); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := store.pool.QueryRow(ctx, `SELECT bearer_token FROM narthex_account_member_credentials WHERE account_name=$1`, name).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "alice-secret") {
		t.Fatal("a member token was stored in plaintext")
	}
}

// testMemberCredentialStore returns the account name it used, deleted.
func testMemberCredentialStore(t *testing.T, store memberCredentialTestStore, suffix string) string {
	t.Helper()
	ctx := context.Background()
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Team " + suffix, CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	name := "team_github_" + suffix
	if err := store.Create(ctx, Account{Name: name, ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopeShared, URL: "https://github.example/mcp", AuthMode: "token", BearerToken: "owner"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account(name)

	on := true
	updated, err := store.UpdateAccountPolicy(ctx, name, accountPolicyPrecondition(account), AccountPolicyMutation{MemberCredentials: &on})
	if err != nil || !updated.MemberCredentials || updated.Revision != account.Revision+1 {
		t.Fatalf("toggle = %+v, %v", updated, err)
	}
	if reread, _ := store.Account(name); !reread.MemberCredentials {
		t.Fatal("the toggle did not persist")
	}

	alice := MemberCredential{Account: name, IncarnationID: account.IncarnationID, Subject: "usr_alice", BearerToken: "alice-1"}
	if err := store.PutMemberCredential(ctx, alice); err != nil {
		t.Fatal(err)
	}
	alice.BearerToken = "alice-2"
	if err := store.PutMemberCredential(ctx, alice); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.MemberCredential(ctx, name, "usr_alice")
	if err != nil || !found || got.BearerToken != "alice-2" || got.IncarnationID != account.IncarnationID {
		t.Fatalf("alice = %+v found=%v err=%v", got, found, err)
	}
	if _, found, _ := store.MemberCredential(ctx, name, "usr_bob"); found {
		t.Fatal("bob has alice's credential")
	}
	stale := alice
	stale.IncarnationID = "accti_other"
	if err := store.PutMemberCredential(ctx, stale); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("a credential for another incarnation = %v", err)
	}

	if err := store.DeleteMemberCredential(ctx, name, "usr_alice"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.MemberCredential(ctx, name, "usr_alice"); found {
		t.Fatal("a disconnected credential remained")
	}

	// Deleting the account deletes its member credentials.
	if err := store.PutMemberCredential(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, name, updated.IncarnationID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.MemberCredential(ctx, name, "usr_alice"); found {
		t.Fatal("a credential outlived its account")
	}
	return name
}

func TestMemberCredentialsActAsTheCallingMember(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	ctx := context.Background()
	var mu sync.Mutex
	valid := "alice-token" // the only token the upstream accepts
	mock := newMockUpstream(t, &valid, &mu)
	defer mock.Close()

	store, gateway := newMCPClientGateway(t)
	shared, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Shared", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: "team_github", Label: "GitHub", ConnectionNamespaceID: shared.ID, ConnectionScope: ConnectionScopeShared, URL: mock.URL, AuthMode: "token", BearerToken: "owner-token"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("team_github")
	on := true
	if account, err = store.UpdateAccountPolicy(ctx, account.Name, accountPolicyPrecondition(account), AccountPolicyMutation{MemberCredentials: &on}); err != nil {
		t.Fatal(err)
	}
	var clients []MCPClient
	for _, subject := range []string{"usr_alice", "usr_bob"} {
		client, err := store.CreateMCPClient(ctx, MCPClient{Name: subject, Subject: subject, CreatedBy: subject, ConnectionNamespaceIDs: []string{shared.ID}})
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	gateway.Aggregate(ctx)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	alice, bob := clients[0], clients[1]

	// Before Alice connects, her call fails closed instead of acting as the
	// account's owner.
	if out := callSubjectClientTool(t, gateway, alice.Slug, "team_github__search"); !strings.Contains(out, "Connect your own GitHub account") {
		t.Fatalf("unconnected call = %s", out)
	}
	if err := gateway.PutMemberCredentialLocked(ctx, MemberCredential{Account: "team_github", IncarnationID: account.IncarnationID, Subject: "usr_alice", BearerToken: "alice-token"}); err != nil {
		t.Fatal(err)
	}
	if out := callSubjectClientTool(t, gateway, alice.Slug, "team_github__search"); !strings.Contains(out, "mock result") {
		t.Fatalf("alice's call = %s", out)
	}
	if out := callSubjectClientTool(t, gateway, bob.Slug, "team_github__search"); !strings.Contains(out, "Connect your own GitHub account") {
		t.Fatalf("bob's call = %s", out)
	}
	// An endpoint with no member behind it has no one to act as.
	if out := callRootTool(t, gateway, "team_github__search"); !strings.Contains(out, "Call it from your own MCP client") {
		t.Fatalf("root call = %s", out)
	}
}

func TestMemberCredentialRefreshUsesTheMembersToken(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	shared, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Shared", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: "team_notion", ConnectionNamespaceID: shared.ID, ConnectionScope: ConnectionScopeShared, URL: "https://notion.example/mcp", AuthMode: "oauth", ClientID: "cid", AccessToken: "owner-access", RefreshToken: "owner-refresh", TokenEndpoint: "https://notion.example/token"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("team_notion")
	if err := gateway.PutMemberCredentialLocked(ctx, MemberCredential{Account: account.Name, IncarnationID: account.IncarnationID, Subject: "usr_alice", AccessToken: "alice-1", RefreshToken: "alice-refresh"}); err != nil {
		t.Fatal(err)
	}
	gateway.refreshTokens = func(_ context.Context, _ *upstreamoauth.Metadata, refreshToken, clientID, _ string) (*upstreamoauth.Tokens, error) {
		if refreshToken != "alice-refresh" || clientID != "cid" {
			t.Fatalf("refreshed with %q and client %q", refreshToken, clientID)
		}
		return &upstreamoauth.Tokens{AccessToken: "alice-2"}, nil // no rotation
	}
	if err := gateway.refreshAccount(ctx, account.Name, account.IncarnationID, "usr_alice"); err != nil {
		t.Fatal(err)
	}
	got, _, _ := store.MemberCredential(ctx, account.Name, "usr_alice")
	if got.AccessToken != "alice-2" || got.RefreshToken != "alice-refresh" {
		t.Fatalf("alice after refresh = %+v", got)
	}
	if owner, _ := store.Account(account.Name); owner.AccessToken != "owner-access" {
		t.Fatalf("the account's own token changed: %+v", owner)
	}
	if err := gateway.refreshAccount(ctx, account.Name, account.IncarnationID, "usr_bob"); !errors.Is(err, ErrMemberCredentialMissing) {
		t.Fatalf("refresh without a credential = %v", err)
	}
}

// callRootTool sends a tools/call to the aggregate /mcp server.
func callRootTool(t *testing.T, g *Gateway, tool string) string {
	t.Helper()
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": map[string]any{}},
	})
	out, err := json.Marshal(g.mcp.HandleMessage(context.Background(), req))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestMemberCredentialConsole(t *testing.T) {
	ctx := context.Background()
	mux, store, gateway, key, now, team, private := hostedNamespaceConsole(t)
	// The toggle re-aggregates the account, which this harness cannot do
	// without an MCP server and an upstream.
	gateway.mcp = server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true))
	gateway.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}
	request := func(userID, role, method, path, body string) *httptest.ResponseRecorder {
		return hostedNamespaceRequest(t, mux, key, now, userID, role, method, path, body)
	}

	// An admin switches the private folder's shared connection to members'
	// own accounts. The switch rebinds the listed tools without asking the
	// upstream again, so it works while the upstream is down. A personal
	// connection cannot be switched.
	gateway.Aggregate(ctx)
	gateway.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		return nil, errors.New("upstream down")
	}
	if response := request("usr_owner", "owner", http.MethodPatch, "/api/servers/private_notion", `{"memberCredentials":true}`); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"memberCredentials":true`) {
		t.Fatalf("toggle = %d %s", response.Code, response.Body)
	}
	if err := store.Create(ctx, Account{Name: "op_personal", URL: "https://op.example/mcp", AuthMode: "token", BearerToken: "op", ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_operator"}); err != nil {
		t.Fatal(err)
	}
	if response := request("usr_operator", "operator", http.MethodPatch, "/api/servers/op_personal", `{"memberCredentials":true}`); response.Code != http.StatusBadRequest {
		t.Fatalf("personal toggle = %d %s", response.Code, response.Body)
	}

	// Alice manages neither folder, but her own MCP client may use the
	// private one, so she sees that connection and connects her own token.
	if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_owner", ConnectionNamespaceIDs: []string{private.ID}}); err != nil {
		t.Fatal(err)
	}
	if response := request("usr_alice", "operator", http.MethodGet, "/api/member-credentials", ""); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"account":"private_notion"`) || !strings.Contains(response.Body.String(), `"connected":false`) {
		t.Fatalf("alice's list = %d %s", response.Code, response.Body)
	}
	if response := request("usr_alice", "operator", http.MethodPost, "/api/member-credentials/private_notion/connect", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("OAuth connect on a token connection = %d", response.Code)
	}
	if response := request("usr_alice", "operator", http.MethodPut, "/api/member-credentials/private_notion/token", `{"token":"alice-pat"}`); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"connected":true`) {
		t.Fatalf("alice's token = %d %s", response.Code, response.Body)
	}
	if got, found, _ := store.MemberCredential(ctx, "private_notion", "usr_alice"); !found || got.BearerToken != "alice-pat" {
		t.Fatalf("stored = %+v found=%v", got, found)
	}
	if response := request("usr_alice", "operator", http.MethodGet, "/api/servers/private_notion", ""); response.Code == http.StatusOK {
		t.Fatal("connecting her own account let alice manage the connection")
	}

	// Carol's agents cannot use that folder: she sees nothing and can set nothing.
	if response := request("usr_carol", "operator", http.MethodGet, "/api/member-credentials", ""); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "[]" {
		t.Fatalf("carol's list = %d %s", response.Code, response.Body)
	}
	if response := request("usr_carol", "operator", http.MethodPut, "/api/member-credentials/private_notion/token", `{"token":"carol"}`); response.Code != http.StatusNotFound {
		t.Fatalf("carol's token = %d", response.Code)
	}

	if response := request("usr_alice", "operator", http.MethodDelete, "/api/member-credentials/private_notion", ""); response.Code != http.StatusNoContent {
		t.Fatalf("disconnect = %d %s", response.Code, response.Body)
	}
	if _, found, _ := store.MemberCredential(ctx, "private_notion", "usr_alice"); found {
		t.Fatal("disconnect left the credential")
	}
}

func TestMemberCredentialConsoleExactClientScopes(t *testing.T) {
	ctx := context.Background()
	mux, store, _, key, now, _, private := hostedNamespaceConsole(t)
	for _, name := range []string{"exact_chosen", "exact_sibling"} {
		if err := store.Create(ctx, Account{Name: name, URL: "https://member.example/mcp", AuthMode: "token", BearerToken: "owner-token", MemberCredentials: true, ConnectionNamespaceID: private.ID}); err != nil {
			t.Fatal(err)
		}
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice exact tools", Subject: "usr_alice", CreatedBy: "usr_owner", ConnectionIDs: []string{"exact_chosen"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bob workload", Subject: "usr_bob", Kind: MCPClientKindWorkload, ConnectionIDs: []string{"exact_sibling"}}); err != nil {
		t.Fatal(err)
	}
	request := func(subject, method, path, body string) *httptest.ResponseRecorder {
		return hostedNamespaceRequest(t, mux, key, now, subject, "operator", method, path, body)
	}
	response := request("usr_alice", http.MethodGet, "/api/member-credentials", "")
	var accounts []memberCredentialDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &accounts) != nil || len(accounts) != 1 || accounts[0].Account != "exact_chosen" {
		t.Fatalf("exact credential discovery=%d %s", response.Code, response.Body)
	}
	if response := request("usr_alice", http.MethodPut, "/api/member-credentials/exact_chosen/token", `{"token":"alice-token"}`); response.Code != http.StatusOK {
		t.Fatalf("own exact credential connect=%d %s", response.Code, response.Body)
	}
	if response := request("usr_alice", http.MethodPut, "/api/member-credentials/exact_sibling/token", `{"token":"not-allowed"}`); response.Code != http.StatusNotFound {
		t.Fatalf("exact scope exposed sibling credential enrollment=%d %s", response.Code, response.Body)
	}
	if response := request("usr_bob", http.MethodGet, "/api/member-credentials", ""); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "[]" {
		t.Fatalf("workload scope exposed member credential enrollment=%d %s", response.Code, response.Body)
	}
	chosen, _ := store.Account("exact_chosen")
	if err := store.Delete(ctx, chosen.Name, chosen.IncarnationID, chosen.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: chosen.Name, URL: chosen.URL, AuthMode: "token", BearerToken: "replacement", MemberCredentials: true, ConnectionNamespaceID: private.ID}); err != nil {
		t.Fatal(err)
	}
	if response := request("usr_alice", http.MethodGet, "/api/member-credentials", ""); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "[]" {
		t.Fatalf("replacement inherited old credential discovery=%d %s", response.Code, response.Body)
	}
	if _, err := store.RevokeMCPClient(ctx, client.ID, "usr_owner", MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatal(err)
	}
	if response := request("usr_alice", http.MethodPut, "/api/member-credentials/exact_chosen/token", `{"token":"not-allowed"}`); response.Code != http.StatusNotFound {
		t.Fatalf("revoked scope allowed member credential enrollment=%d %s", response.Code, response.Body)
	}
}

func TestFinishConnectStoresTheMembersOwnTokens(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	if err := store.Create(ctx, Account{Name: "team_notion", URL: "https://notion.example/mcp", AuthMode: "oauth", ClientID: "cid", AccessToken: "owner-access", RefreshToken: "owner-refresh"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("team_notion")
	connector := NewConnector(store, gateway)
	connector.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
		return &upstreamoauth.Tokens{AccessToken: "alice-access", RefreshToken: "alice-refresh"}, nil
	}
	connector.pend["state"] = &pendingConnect{
		name: account.Name, url: account.URL, clientID: "cid", meta: &upstreamoauth.Metadata{},
		created: time.Now(), memberSubject: "usr_alice", incarnationID: account.IncarnationID,
	}
	if _, _, err := connector.FinishConnect(ctx, "state", "code"); err != nil {
		t.Fatal(err)
	}
	got, found, _ := store.MemberCredential(ctx, account.Name, "usr_alice")
	if !found || got.AccessToken != "alice-access" || got.RefreshToken != "alice-refresh" {
		t.Fatalf("alice = %+v found=%v", got, found)
	}
	if owner, _ := store.Account(account.Name); owner.AccessToken != "owner-access" {
		t.Fatalf("the account's own token changed: %+v", owner)
	}
}

func TestReplayRefusesMemberCredentialAccounts(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)
	g.SetRecordPayloads(true)
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "42"})
	orig := callRows(t, fs, "get_issue")[0]
	account, _ := fs.Account("linear")
	on := true
	if _, err := fs.UpdateAccountPolicy(context.Background(), "linear", accountPolicyPrecondition(account), AccountPolicyMutation{MemberCredentials: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Replay(context.Background(), orig.ID, false); err == nil || !strings.Contains(err.Error(), "each member's own account") {
		t.Fatalf("replay = %v", err)
	}
}
