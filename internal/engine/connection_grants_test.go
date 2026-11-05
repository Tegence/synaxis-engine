package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mark3labs/mcp-go/server/servertest"

	"narthex/backend/internal/oauthas"
)

type governedConnectionStore interface {
	AccountStore
	ConnectionNamespaceStore
	MCPClientStore
	ConnectionGrantStore
	ApprovalLifecycle
	oauthas.TokenGenerationStore
}

func governedGrantFixture(t *testing.T, store governedConnectionStore, suffix string) (*Gateway, Account, MCPClient, *atomic.Int32) {
	t.Helper()
	useLoopbackUpstreamTransport(t)
	ctx := context.Background()
	writes := &atomic.Int32{}
	upstream := server.NewMCPServer("grant-upstream", "1")
	for _, name := range []string{"get_item", "get_private"} {
		upstream.AddTool(mcp.NewTool(name, mcp.WithReadOnlyHintAnnotation(true)), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("upstream-read"), nil
		})
	}
	upstream.AddTool(mcp.NewTool("update_item", mcp.WithReadOnlyHintAnnotation(false)), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		writes.Add(1)
		return mcp.NewToolResultText("upstream-write"), nil
	})
	remote := servertest.NewTestStreamableHTTPServer(upstream)
	t.Cleanup(remote.Close)
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Personal " + suffix, CreatedBy: "usr_grant_owner_" + suffix, OwnerSubject: "usr_grant_owner_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	account := Account{Name: "governed_" + suffix, URL: remote.URL, AuthMode: "token", BearerToken: "never-shared", ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopePersonal, OwnerSubject: folder.OwnerSubject}
	if err := store.Create(ctx, account); err != nil {
		t.Fatal(err)
	}
	account, _ = store.Account(account.Name)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Recipient " + suffix, Subject: "usr_recipient_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(store, server.NewMCPServer("grant-root", "1"))
	gateway.Aggregate(ctx)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	return gateway, account, client, writes
}

func exerciseGovernedGrant(t *testing.T, store governedConnectionStore, suffix string) {
	t.Helper()
	ctx := context.Background()
	g, a, client, writes := governedGrantFixture(t, store, suffix)
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, g, nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	ownerRequest := func(method, path, body string, want int) string {
		t.Helper()
		response := hostedNamespaceRequest(t, mux, key, now, a.OwnerSubject, "owner", method, path, body)
		if response.Code != want {
			t.Fatalf("owner %s %s = %d: %s; want %d", method, path, response.Code, response.Body, want)
		}
		return response.Body.String()
	}
	if names := clientEndpointToolNames(t, g, client.Slug); slices.Contains(names, a.Name+"__get_item") {
		t.Fatal("unshared connection available before grant")
	}
	share, _ := json.Marshal(map[string]any{"name": "Selected project tools", "connectionId": a.Name, "recipientKind": "subject", "recipientRef": client.Subject, "recipientSubjects": []string{client.Subject}, "tools": []string{"get_item", "update_item"}, "expiresAt": time.Now().Add(time.Hour)})
	var grant ConnectionGrant
	if err := json.Unmarshal([]byte(ownerRequest(http.MethodPost, "/control/v1/connection-grants", string(share), http.StatusCreated)), &grant); err != nil || grant.ID == "" {
		t.Fatalf("decode created grant: %v", err)
	}
	names := clientEndpointToolNames(t, g, client.Slug)
	if !slices.Contains(names, a.Name+"__get_item") || slices.Contains(names, a.Name+"__get_private") {
		t.Fatalf("selected tools widened: %v", names)
	}
	if body := callSubjectClientTool(t, g, client.Slug, a.Name+"__get_private"); strings.Contains(body, "upstream-read") || !strings.Contains(body, "error") {
		t.Fatalf("guessed unshared tool dispatched: %s", body)
	}
	// Exercise the production RequireAuth -> scoped MCP HTTP -> upstream path.
	// Token minting uses the same issuer as workload tokens after the live
	// interactive consent authorizer binds this Operator's exact endpoint.
	authorization := oauthas.New("https://engine.example", "pw", "grant-test-secret")
	if err := authorization.ConfigureTokenGeneration(ctx, store); err != nil {
		t.Fatal(err)
	}
	authorization.SetEpochLookup(func(path string) (string, bool) {
		slug, ok := mcpClientSlugFromResource(path)
		if !ok {
			return "", false
		}
		return g.MCPClientEpoch(slug)
	})
	authorization.SetClientResourceAuthorizer(g.MCPClientAllowsOAuthClient)
	resource, oauthClientID := "/mcp/clients/"+client.Slug, "grant-recipient-"+suffix
	if err := g.AuthorizeMCPConsent(ctx, client.Subject, "operator", oauthClientID, resource); err != nil {
		t.Fatal(err)
	}
	token, _, err := authorization.IssueResourceAccess(ctx, oauthClientID, resource, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/mcp/clients/{slug}", authorization.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := g.MCPClientHandler(r.PathValue("slug"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		LimitMCPRequestBody(handler).ServeHTTP(w, r)
	})))
	sessionID := ""
	mcpRequest := func(bearer, method string, params any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, resource, strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if sessionID != "" {
			request.Header.Set("Mcp-Session-Id", sessionID)
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}
	initialized := mcpRequest(token, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "sharing-test", "version": "1"}})
	if initialized.Code != http.StatusOK {
		t.Fatalf("authenticated MCP initialization = %d: %s", initialized.Code, initialized.Body)
	}
	sessionID = initialized.Header().Get("Mcp-Session-Id")
	readParams := map[string]any{"name": a.Name + "__get_item", "arguments": map[string]any{}}
	if read := mcpRequest(token, "tools/call", readParams); read.Code != http.StatusOK || !strings.Contains(read.Body.String(), "upstream-read") {
		t.Fatalf("authenticated shared read = %d: %s", read.Code, read.Body)
	}
	if unshared := mcpRequest(token, "tools/call", map[string]any{"name": a.Name + "__get_private", "arguments": map[string]any{}}); strings.Contains(unshared.Body.String(), "upstream-read") || !strings.Contains(unshared.Body.String(), "error") {
		t.Fatalf("authenticated unshared tool dispatched = %d: %s", unshared.Code, unshared.Body)
	}
	if unsigned := mcpRequest("", "tools/call", readParams); unsigned.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned shared read = %d: %s", unsigned.Code, unsigned.Body)
	}
	// Capture after consent has settled the endpoint epoch. Prove this exact
	// closure works now before holding it across the signed revocation below.
	g.mu.Lock()
	staleRead := (*g.clientEndpoints[client.Slug].dispatch.Load())[a.Name+"__get_item"]
	g.mu.Unlock()
	if staleRead == nil {
		t.Fatal("shared read dispatch missing")
	}
	staleRequest := mcp.CallToolRequest{}
	staleRequest.Params.Name = a.Name + "__get_item"
	staleRequest.Params.Arguments = map[string]any{}
	beforeRevoke, err := staleRead(ctx, staleRequest)
	beforeBody, _ := json.Marshal(beforeRevoke)
	if err != nil || beforeRevoke == nil || beforeRevoke.IsError || !strings.Contains(string(beforeBody), "upstream-read") {
		t.Fatalf("captured live dispatch did not execute: %+v %v", beforeRevoke, err)
	}
	// A successful grant permits execution, not credential management. Exercise
	// the hosted control handlers with the actual recipient's signed identity.
	request := func(method, path, body string, want int) string {
		t.Helper()
		response := hostedNamespaceRequest(t, mux, key, now, client.Subject, "operator", method, path, body)
		if response.Code != want {
			t.Fatalf("recipient %s %s = %d: %s; want %d", method, path, response.Code, response.Body, want)
		}
		if strings.Contains(response.Body.String(), a.BearerToken) {
			t.Fatal("recipient response exposed source credentials")
		}
		return response.Body.String()
	}
	if body := request(http.MethodGet, "/api/servers", "", http.StatusOK); strings.Contains(body, a.Name) {
		t.Fatalf("tool grant exposed source connection management: %s", body)
	}
	request(http.MethodGet, "/api/servers/"+a.Name+"/tools", "", http.StatusNotFound)
	request(http.MethodPost, "/api/servers/"+a.Name+"/token", `{"bearerToken":"replacement"}`, http.StatusNotFound)
	if body := request(http.MethodGet, "/api/connection-grants", "", http.StatusOK); !strings.Contains(body, grant.ID) || strings.Contains(body, a.OwnerSubject) {
		t.Fatalf("recipient grant missing or reveals owner identity: %s", body)
	}
	reshare, _ := json.Marshal(map[string]any{"name": "Reshare attempt", "connectionId": a.Name, "recipientKind": "subject", "recipientRef": "usr_other_" + suffix, "recipientSubjects": []string{"usr_other_" + suffix}, "tools": []string{"get_item"}, "expiresAt": time.Now().Add(time.Hour)})
	request(http.MethodPost, "/api/connection-grants", string(reshare), http.StatusNotFound)
	request(http.MethodPost, "/api/connection-grants/"+grant.ID+"/revoke", fmt.Sprintf(`{"revision":%d}`, grant.Revision), http.StatusNotFound)
	if _, ok := g.mcpClientMayUseAccount(ctx, client.Slug, a.Name, a.IncarnationID); ok {
		t.Fatal("tool grant became whole connection access")
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "No reshare " + suffix, Subject: "usr_other_" + suffix, ConnectionIDs: []string{a.Name}}); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("recipient gained connection credential grant: %v", err)
	}
	if _, err := store.CreateConnectionGrant(ctx, grant, AccountPolicyPrecondition{}); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("stale account accepted: %v", err)
	}
	startWrite := func() (<-chan string, PendingCall) {
		t.Helper()
		result := make(chan string, 1)
		go func() { result <- callSubjectClientTool(t, g, client.Slug, a.Name+"__update_item") }()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			calls, err := store.PendingCalls(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range calls {
				if p.Account == a.Name && p.Status == ApprovalPending {
					return result, p
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("write did not require approval")
		return nil, PendingCall{}
	}
	result, pending := startWrite()
	if writes.Load() != 0 {
		t.Fatal("write dispatched before approval")
	}
	if _, err := g.DecideWithMetadata(ctx, pending.ID, ApprovalDecision{Status: ApprovalApproved, Actor: a.OwnerSubject}); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-result:
		if !strings.Contains(body, "upstream-write") || writes.Load() != 1 {
			t.Fatalf("approved shared write did not reach upstream exactly once: %s; writes=%d", body, writes.Load())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approved shared write did not finish")
	}
	result, pending = startWrite()
	ownerRequest(http.MethodPost, "/control/v1/connection-grants/"+grant.ID+"/revoke", fmt.Sprintf(`{"revision":%d}`, grant.Revision), http.StatusOK)
	if _, err := g.DecideWithMetadata(ctx, pending.ID, ApprovalDecision{Status: ApprovalApproved, Actor: a.OwnerSubject}); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-result:
		if !strings.Contains(body, "no longer available") {
			t.Fatalf("revoked parked call: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval did not finish")
	}
	if writes.Load() != 1 {
		t.Fatal("revoked grant dispatched after approval")
	}
	staleResult, err := staleRead(ctx, staleRequest)
	staleBody, _ := json.Marshal(staleResult)
	if err != nil || staleResult == nil || !staleResult.IsError || !strings.Contains(string(staleBody), "no longer available") {
		t.Fatalf("stale projection bypassed revoke: %+v %v", staleResult, err)
	}
	if read := mcpRequest(token, "tools/call", readParams); strings.Contains(read.Body.String(), "upstream-read") || (read.Code != http.StatusUnauthorized && !strings.Contains(read.Body.String(), "error")) {
		t.Fatalf("existing authenticated session bypassed revoke = %d: %s", read.Code, read.Body)
	}
	for _, name := range clientEndpointToolNames(t, g, client.Slug) {
		if strings.HasPrefix(name, a.Name+"__") {
			t.Fatalf("revoked shared tool remained advertised: %s", name)
		}
	}
	// An allowed recipient is insufficient after the source owner is offboarded.
	grant.ID = ""
	grant, err = store.CreateConnectionGrant(ctx, grant, accountPolicyPrecondition(a))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubjectAllowed(ctx, a.OwnerSubject, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.clientMayUseGrantedTool(ctx, client.Slug, grant.ID, a, "get_item"); ok {
		t.Fatal("offboarded owner credential still shared")
	}
	if err := store.SetSubjectAllowed(ctx, a.OwnerSubject, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubjectAllowed(ctx, client.Subject, false); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := lookupActiveMCPClient(ctx, store, client.Slug); err != nil || ok {
		t.Fatalf("offboarded recipient retained MCP: %v %v", ok, err)
	}
	if err := store.SetSubjectAllowed(ctx, client.Subject, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnectionGrantRecipients(ctx, grant.ID, grant.Revision, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.clientMayUseGrantedTool(ctx, client.Slug, grant.ID, a, "get_item"); ok {
		t.Fatal("removed team recipient retained grant")
	}
	// New grants cannot transfer a replacement connection at the same routing key.
	grant.ID = ""
	grant, err = store.CreateConnectionGrant(ctx, grant, accountPolicyPrecondition(a))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, a.Name, a.IncarnationID, a.Revision); err != nil {
		t.Fatal(err)
	}
	a.IncarnationID = ""
	a.Revision = 0
	if err := store.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	replacement, _ := store.Account(a.Name)
	if connectionGrantAllows(grant, replacement, client.Subject, "get_item", time.Now()) {
		t.Fatal("grant inherited replacement credential")
	}
	self := grant
	self.ID = "cgr_self_" + suffix
	self.IncarnationID, self.SourceRevision = replacement.IncarnationID, replacement.Revision
	self.PersonalWorkload, self.ExpiresAt = true, time.Time{}
	self, err = store.CreateConnectionGrant(ctx, self, accountPolicyPrecondition(replacement))
	if err != nil {
		t.Fatalf("durable personal grant: %v", err)
	}
	saved, err := store.ConnectionGrants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var persisted ConnectionGrant
	for _, candidate := range saved {
		if candidate.ID == self.ID {
			persisted = candidate
		}
	}
	if !persisted.PersonalWorkload || !persisted.ExpiresAt.IsZero() || !connectionGrantAllows(persisted, replacement, client.Subject, "get_item", time.Now().Add(2*365*24*time.Hour)) {
		t.Fatalf("personal persistence lost: %+v", persisted)
	}
}

func TestFileGovernedConnectionGrantDispatchAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	exerciseGovernedGrant(t, store, "file")
	if err := store.SetSubjectAllowed(context.Background(), "usr_retired", false); err != nil {
		t.Fatal(err)
	}
	before, err := store.ConnectionGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.ConnectionGrants(context.Background())
	if err != nil || len(after) != len(before) || after[0].IncarnationID != before[0].IncarnationID || after[0].RevokedAt == nil {
		t.Fatalf("grant persistence lost: %+v %v", after, err)
	}
	if allowed, err := reopened.SubjectAllowed(context.Background(), "usr_retired"); err != nil || allowed {
		t.Fatal("subject deny not durable")
	}
	if last := after[len(after)-1]; !last.PersonalWorkload || !last.ExpiresAt.IsZero() {
		t.Fatalf("personal grant lifetime lost after reopen: %+v", last)
	}
}
func TestPgGovernedConnectionGrantDispatch(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup callbacks run after defers. Keep the pool open until this
	// fixture's rows are removed, before later tests select another cipher.
	t.Cleanup(store.Close)
	suffix := newPgFixtureSuffix()
	t.Cleanup(func() {
		ctx := context.Background()
		remove := func(query string, args ...any) {
			if _, err := store.pool.Exec(ctx, query, args...); err != nil {
				t.Errorf("remove governed grant fixture: %v", err)
			}
		}
		grants, err := store.ConnectionGrants(ctx)
		if err != nil {
			t.Errorf("read governed grant fixture for cleanup: %v", err)
		}
		for _, grant := range grants {
			if grant.ConnectionID == "governed_"+suffix {
				remove(`DELETE FROM narthex_connection_grants WHERE id=$1`, grant.ID)
			}
		}
		remove(`DELETE FROM tool_calls WHERE account=$1`, "governed_"+suffix)
		remove(`DELETE FROM pending_calls WHERE account=$1`, "governed_"+suffix)
		remove(`DELETE FROM narthex_mcp_clients WHERE subject=$1`, "usr_recipient_"+suffix)
		remove(`DELETE FROM narthex_accounts WHERE name=$1`, "governed_"+suffix)
		remove(`DELETE FROM narthex_connection_namespaces WHERE owner_subject=$1`, "usr_grant_owner_"+suffix)
		remove(`DELETE FROM narthex_subject_access WHERE subject=ANY($1)`, []string{"usr_recipient_" + suffix, "usr_grant_owner_" + suffix})
	})
	exerciseGovernedGrant(t, store, suffix)
}

func TestPersonalFolderAndGrantManagementBoundaries(t *testing.T) {
	mux, store, g, key, now, _, _ := hostedNamespaceConsole(t)
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/connection-namespaces", `{"label":"My research","scope":"personal"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("personal folder: %d %s", response.Code, response.Body)
	}
	var folder connectionNamespaceDTO
	if err := json.Unmarshal(response.Body.Bytes(), &folder); err != nil {
		t.Fatal(err)
	}
	if folder.Scope != "personal" || folder.OwnerSubject != "usr_operator" || folder.CanManageMembership {
		t.Fatalf("wrong personal boundary: %+v", folder)
	}
	body := `{"name":"Shared exploit","toolPrefix":"shared_exploit","connectionScope":"shared","connectionNamespaceId":"` + folder.ID + `","url":"https://example.com/mcp","bearerToken":"secret"}`
	if response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/servers", body); response.Code != http.StatusForbidden {
		t.Fatalf("shared credential in personal folder: %d %s", response.Code, response.Body)
	}
	ns, _ := store.ConnectionNamespace(context.Background(), folder.ID)
	if err := store.Create(context.Background(), Account{Name: "store_exploit", URL: "https://example.com/mcp", ConnectionNamespaceID: ns.ID, ConnectionScope: ConnectionScopeShared}); !errors.Is(err, ErrInvalidConnectionScope) {
		t.Fatalf("store bypass: %v", err)
	}
	if _, err := store.SetConnectionNamespaceManagers(context.Background(), ns.ID, []ConnectionNamespaceManagerGrant{{Subject: "usr_other"}}, ConnectionNamespacePrecondition{ID: ns.ID, Revision: ns.Revision}); err == nil {
		t.Fatal("personal folder manager changed")
	}
	// Being a grant recipient must never authorize another grant or revocation.
	a, _ := store.Account("private_notion")
	g.mu.Lock()
	g.cached[a.Name] = []cachedTool{{tool: mcp.NewTool(a.Name + "__get_item"), sourceName: "get_item", accountIncarnationID: a.IncarnationID, accountRevision: a.Revision, accountURL: a.URL}}
	g.mu.Unlock()
	create := map[string]any{"id": "cgr_test_api", "name": "Read one tool", "connectionId": a.Name, "recipientKind": "subject", "recipientRef": "usr_operator", "recipientSubjects": []string{"usr_operator"}, "tools": []string{"get_item"}, "expiresAt": time.Now().Add(time.Hour).UTC()}
	raw, _ := json.Marshal(create)
	for _, attempt := range []int{1, 2} {
		response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/connection-grants", string(raw))
		want := http.StatusCreated
		if attempt == 2 {
			want = http.StatusOK
		}
		if response.Code != want {
			t.Fatalf("create retry %d: %d %s", attempt, response.Code, response.Body)
		}
	}
	if response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/connection-grants", string(raw)); response.Code != http.StatusNotFound {
		t.Fatalf("recipient reshared: %d", response.Code)
	}
	if response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/connection-grants/cgr_test_api/revoke", `{"revision":1}`); response.Code != http.StatusNotFound {
		t.Fatalf("recipient revoked another owner's grant: %d", response.Code)
	}
	create["id"], create["expiresAt"], create["personalWorkload"] = "cgr_no_expiry", time.Time{}, true
	raw, _ = json.Marshal(create)
	if response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/connection-grants", string(raw)); response.Code != http.StatusBadRequest {
		t.Fatalf("delegation bypassed expiry using service-only flag: %d", response.Code)
	}
	create["id"], create["expiresAt"] = "cgr_self_spoof", time.Now().Add(time.Hour)
	raw, _ = json.Marshal(create)
	if response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/connection-grants", string(raw)); response.Code != http.StatusBadRequest {
		t.Fatalf("delegation used reserved self identifier: %d", response.Code)
	}
}

func TestConnectionGrantExpiryAndNarrowToolIdentity(t *testing.T) {
	now := time.Now()
	a := Account{Name: "source", IncarnationID: "inc", OwnerSubject: "usr_owner", Revision: 1}
	g := ConnectionGrant{SourceRevision: a.Revision, ConnectionID: a.Name, IncarnationID: a.IncarnationID, OwnerSubject: a.OwnerSubject, RecipientSubjects: []string{"usr_recipient"}, Tools: []string{"get_item"}, ExpiresAt: now.Add(time.Second)}
	if !connectionGrantAllows(g, a, "usr_recipient", "get_item", now) {
		t.Fatal("valid grant refused")
	}
	if connectionGrantAllows(g, a, "usr_recipient", "get_item", g.ExpiresAt) || connectionGrantAllows(g, a, "usr_recipient", "get_private", now) || connectionGrantAllows(g, a, "usr_other", "get_item", now) {
		t.Fatal("expiry/tool/subject boundary bypassed")
	}
}
