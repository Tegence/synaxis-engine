package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func integrationTokenFixture(owner string) LinkedAccountRecord {
	return LinkedAccountRecord{IntegrationID: integrationTokenAPI, OwnerSubject: owner, DisplayName: "My API", BearerToken: "private-standalone-token"}
}

func integrationOAuthFixture(owner string) LinkedAccountRecord {
	return LinkedAccountRecord{IntegrationID: "oauth.linkedin", OwnerSubject: owner, DisplayName: "My social", OAuth: &LinkedOAuthCredential{
		Provider: "linkedin", ClientID: "li-app", Subject: "member", ProviderName: "Member", AccessToken: "private-standalone-oauth", ExpiresAt: time.Now().Add(time.Hour),
	}}
}

func TestFileIntegrationAccountWithoutConnection(t *testing.T) {
	testIntegrationAccountWithoutConnection(t, newLibraryFileStore(t))
}

func TestPgIntegrationAccountWithoutConnection(t *testing.T) {
	testIntegrationAccountWithoutConnection(t, newPgConnectionsStore(t))
}

func testIntegrationAccountWithoutConnection(t *testing.T, store browserTestStore) {
	t.Helper()
	ctx := t.Context()
	owner := "usr_integration_" + newPgFixtureSuffix()
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_integration_accounts WHERE owner_subject=$1`, owner)
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
		})
	}
	token, err := store.CreateLinkedAccount(ctx, integrationTokenFixture(owner), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatalf("standalone token account must save without an MCP connection: %v", err)
	}
	if token.ConnectionID != "" || token.IntegrationID != integrationTokenAPI || token.Boundary != (OAuthCompletionPrecondition{}) || token.Revision != 1 || !token.isIntegrationAccount() {
		t.Fatalf("invalid standalone token account: %+v", token)
	}
	oauth, err := store.CreateLinkedAccount(ctx, integrationOAuthFixture(owner), AccountPolicyPrecondition{})
	if err != nil || oauth.IntegrationID != "oauth.linkedin" || linkedAccountDTO(oauth, Account{}).AuthMode != "oauth" {
		t.Fatalf("standalone OAuth account: %+v %v", oauth, err)
	}
	website, err := store.CreateLinkedAccount(ctx, websiteAccountFixture(owner), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	// Mismatched integration IDs, partial parents and parent-bound records with
	// an integration ID are all refused.
	mismatched := integrationTokenFixture(owner)
	mismatched.IntegrationID = "oauth.linkedin"
	wrongProvider := integrationOAuthFixture(owner)
	wrongProvider.IntegrationID = "oauth.instagram"
	browserWithIntegration := websiteAccountFixture(owner)
	browserWithIntegration.IntegrationID = integrationTokenAPI
	for _, input := range []LinkedAccountRecord{mismatched, wrongProvider, browserWithIntegration} {
		if _, err := store.CreateLinkedAccount(ctx, input, AccountPolicyPrecondition{}); !errors.Is(err, ErrLinkedAccountInvalid) {
			t.Fatalf("invalid standalone account accepted: %+v %v", input, err)
		}
	}
	if _, err := store.CreateLinkedAccount(ctx, integrationTokenFixture(owner), AccountPolicyPrecondition{Revision: 1}); err == nil {
		t.Fatal("partial parent boundary accepted")
	}
	parent := linkedAccountFixture(t, store)
	bound := integrationTokenFixture(owner)
	bound.ConnectionID = parent.Name
	if _, err := store.CreateLinkedAccount(ctx, bound, accountPolicyPrecondition(parent)); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatalf("connection-bound account carried an integration ID: %v", err)
	}
	rows, err := store.LinkedAccounts(ctx, owner)
	if err != nil || len(rows) != 3 {
		t.Fatalf("owner list: %+v %v", rows, err)
	}
	if err := store.Delete(ctx, parent.Name, parent.IncarnationID, parent.Revision); err != nil {
		t.Fatal(err)
	}
	if rows, err = store.LinkedAccounts(ctx, owner); err != nil || len(rows) != 3 {
		t.Fatal("unrelated connection deletion removed a standalone account", err)
	}
	integration := LinkedAccountMutation{Integration: true, Remove: true}
	if _, err := store.MutateLinkedAccount(ctx, "", token.ID, "usr_other", token.Revision, AccountPolicyPrecondition{}, integration); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatalf("another owner changed a standalone account: %v", err)
	}
	// The website and integration families never reach each other's rows.
	if _, err := store.MutateLinkedAccount(ctx, "", token.ID, owner, token.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Remove: true}); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatalf("website mutation reached a token account: %v", err)
	}
	if _, err := store.MutateLinkedAccount(ctx, "", website.ID, owner, website.Revision, AccountPolicyPrecondition{}, integration); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatalf("integration mutation reached a website account: %v", err)
	}
	if _, err := store.MutateLinkedAccount(ctx, "missing", token.ID, owner, token.Revision, accountPolicyPrecondition(parent), integration); err == nil {
		t.Fatal("integration mutation accepted a connection")
	}
	name := "Renamed API"
	updated, err := store.MutateLinkedAccount(ctx, "", token.ID, owner, token.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Integration: true, DisplayName: &name})
	if err != nil || updated.DisplayName != name || updated.IntegrationID != integrationTokenAPI {
		t.Fatalf("rename: %+v %v", updated, err)
	}
	if _, err := store.MutateLinkedAccount(ctx, "", token.ID, owner, token.Revision, AccountPolicyPrecondition{}, integration); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatalf("stale revision changed a standalone account: %v", err)
	}
	rotated := "private-rotated-standalone"
	updated, err = store.MutateLinkedAccount(ctx, "", token.ID, owner, updated.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Integration: true, BearerToken: &rotated})
	if err != nil || updated.CredentialRevision != 2 || updated.BearerToken != rotated {
		t.Fatalf("rotate: %+v %v", updated, err)
	}
	empty := ""
	updated, err = store.MutateLinkedAccount(ctx, "", token.ID, owner, updated.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Integration: true, BearerToken: &empty})
	if err != nil || linkedAccountDTO(updated, Account{}).Status != "disconnected" || !updated.isIntegrationAccount() {
		t.Fatalf("disconnect: %+v %v", updated, err)
	}
	pasted := "pasted"
	if _, err := store.MutateLinkedAccount(ctx, "", oauth.ID, owner, oauth.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Integration: true, BearerToken: &pasted}); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatalf("OAuth identity downgraded to a pasted token: %v", err)
	}
	reconnect := *integrationOAuthFixture(owner).OAuth
	reconnect.AccessToken = "private-reconnected-oauth"
	again, err := store.MutateLinkedAccount(ctx, "", oauth.ID, owner, oauth.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Integration: true, OAuth: &reconnect})
	if err != nil || again.OAuth.AccessToken != reconnect.AccessToken || again.CredentialRevision != 2 || !again.isIntegrationAccount() {
		t.Fatalf("OAuth reconnect: %+v %v", again, err)
	}
	if pg, ok := store.(*PgStore); ok {
		var raw, integrationID string
		if err := pg.pool.QueryRow(ctx, `SELECT integration_id,payload FROM narthex_integration_accounts WHERE id=$1`, oauth.ID).Scan(&integrationID, &raw); err != nil {
			t.Fatal(err)
		}
		if integrationID != "oauth.linkedin" || !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, "private-reconnected-oauth") || strings.Contains(raw, "My social") {
			t.Fatal("standalone payload is not encrypted or integration column is wrong")
		}
		var websiteRows int
		if err := pg.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_website_accounts WHERE id=$1 OR id=$2`, token.ID, oauth.ID).Scan(&websiteRows); err != nil || websiteRows != 0 {
			t.Fatal("standalone account written to the website table", err)
		}
	}
	for _, record := range []LinkedAccountRecord{updated, again} {
		if _, err := store.MutateLinkedAccount(ctx, "", record.ID, owner, record.Revision, AccountPolicyPrecondition{}, integration); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	if rows, err = store.LinkedAccounts(ctx, owner); err != nil || len(rows) != 1 || rows[0].ID != website.ID {
		t.Fatalf("remove left rows: %+v %v", rows, err)
	}
}

func TestFileIntegrationAccountOwnerLimit(t *testing.T) {
	testIntegrationAccountOwnerLimit(t, newLibraryFileStore(t))
}

func TestPgIntegrationAccountOwnerLimit(t *testing.T) {
	testIntegrationAccountOwnerLimit(t, newPgConnectionsStore(t))
}

func testIntegrationAccountOwnerLimit(t *testing.T, store browserTestStore) {
	t.Helper()
	owner := "usr_integration_limit_" + newPgFixtureSuffix()
	other := "usr_other_" + newPgFixtureSuffix()
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_integration_accounts WHERE owner_subject=$1 OR owner_subject=$2`, owner, other)
		})
	}
	var wg sync.WaitGroup
	results := make(chan error, maxLinkedAccountsPerConnection+4)
	for range maxLinkedAccountsPerConnection + 4 {
		wg.Go(func() {
			_, err := store.CreateLinkedAccount(t.Context(), integrationTokenFixture(owner), AccountPolicyPrecondition{})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	created, limited := 0, 0
	for err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrLinkedAccountLimit):
			limited++
		default:
			t.Fatal(err)
		}
	}
	if created != maxLinkedAccountsPerConnection || limited != 4 {
		t.Fatalf("per-owner cap: created=%d limited=%d", created, limited)
	}
	if _, err := store.CreateLinkedAccount(t.Context(), integrationTokenFixture(other), AccountPolicyPrecondition{}); err != nil {
		t.Fatalf("another owner shares the cap: %v", err)
	}
}

func TestIntegrationAccountFilePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.CreateLinkedAccount(t.Context(), integrationTokenFixture("usr_alice"), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.integrationAccounts) != 1 || len(reopened.websiteAccounts) != 0 || len(reopened.linkedAccounts) != 0 {
		t.Fatal("standalone account was not saved under integration_accounts")
	}
	rows, err := reopened.LinkedAccounts(t.Context(), "usr_alice")
	if err != nil || len(rows) != 1 || rows[0].ID != record.ID || !rows[0].isIntegrationAccount() {
		t.Fatalf("restart lost standalone account: %+v %v", rows, err)
	}
	store.path = filepath.Join(path, "bad", "state.json")
	if _, err := store.CreateLinkedAccount(t.Context(), integrationTokenFixture("usr_alice"), AccountPolicyPrecondition{}); err == nil {
		t.Fatal("failed save ignored")
	}
	if len(store.integrationAccounts) != 1 {
		t.Fatal("failed save kept a standalone account")
	}
}

func TestIntegrationAccountHTTPLifecycle(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		t.Run(prefix, func(t *testing.T) { testIntegrationAccountHTTPLifecycle(t, prefix) })
	}
}

func testIntegrationAccountHTTPLifecycle(t *testing.T, prefix string) {
	store := newLibraryFileStore(t)
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	path := prefix + "/linked-accounts"
	body := map[string]any{"integrationId": integrationTokenAPI, "displayName": "Private API label", "token": "private-standalone-token"}
	keyed := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(body), map[string]string{controlIdempotencyKeyHeader: "replay"})
	if keyed.Code != http.StatusBadRequest {
		t.Fatalf("standalone account entered replay cache: %d %s", keyed.Code, keyed.Body)
	}
	for _, role := range []string{"viewer", "service"} {
		if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", role, http.MethodPost, path, encode(body)); got.Code != http.StatusForbidden && got.Code != http.StatusUnauthorized {
			t.Fatalf("%s linked a standalone account: %d", role, got.Code)
		}
	}
	for _, invalid := range []map[string]any{
		{"integrationId": "oauth.linkedin", "displayName": "x", "token": "t"},
		{"integrationId": "mcp.streamable-http", "displayName": "x", "token": "t"},
		{"displayName": "x", "token": "t"},
		{"integrationId": integrationTokenAPI, "displayName": "x"},
		{"integrationId": integrationTokenAPI, "displayName": "x", "token": "has space"},
		{"integrationId": integrationTokenAPI, "displayName": "x", "token": "t", "ownerSubject": "usr_bob"},
		{"integrationId": integrationTokenAPI, "displayName": "x", "token": "t", "connectionId": "anything"},
	} {
		if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(invalid)); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid create %v: %d %s", invalid, got.Code, got.Body)
		}
	}
	created := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, path, encode(body))
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "private-standalone-token") {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	var account ConnectedAccount
	if err := json.Unmarshal(created.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	if account.ConnectionID != "" || account.IntegrationID != integrationTokenAPI || account.OwnerKind != "linked" || account.BindingMode != AccountBindingExplicit ||
		account.Status != "linked" || account.UsableBy == nil || *account.UsableBy != (ConnectedAccountUsableBy{}) {
		t.Fatalf("unsafe or wrong standalone DTO: %s", created.Body)
	}
	for _, who := range []string{"usr_alice", "usr_bob"} {
		got := hostedNamespaceRequest(t, mux, key, now, who, "admin", http.MethodGet, prefix+"/connection-model", "")
		if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "private-standalone-token") {
			t.Fatalf("model: %d %s", got.Code, got.Body)
		}
		var model ConnectionModel
		if err := json.Unmarshal(got.Body.Bytes(), &model); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(model.Capabilities, controlCapabilityAccountStandalone) {
			t.Fatalf("standalone capability missing: %v", model.Capabilities)
		}
		tokenAPI, _ := findModelIntegration(model, integrationTokenAPI)
		if tokenAPI.RequiresConnection {
			t.Fatal("token integration still requires a connection")
		}
		listed := slices.ContainsFunc(model.ConnectedAccounts, func(a ConnectedAccount) bool {
			return a.ID == account.ID && a.IntegrationID == integrationTokenAPI && a.UsableBy != nil && *a.UsableBy == (ConnectedAccountUsableBy{})
		})
		if listed != (who == "usr_alice") {
			t.Fatalf("%s listed=%v", who, listed)
		}
	}
	item := path + "/" + account.ID
	rev := func(revision int64, extra map[string]any) string {
		out := map[string]any{"revision": revision}
		for k, v := range extra {
			out[k] = v
		}
		return encode(out)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_bob", "owner", http.MethodDelete, item, rev(account.Revision, nil)); got.Code != http.StatusNotFound {
		t.Fatalf("another member removed a standalone account: %d", got.Code)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodDelete, prefix+"/website-accounts/"+account.ID, rev(account.Revision, nil)); got.Code != http.StatusNotFound {
		t.Fatalf("website route reached a standalone token account: %d", got.Code)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPatch, item, rev(account.Revision, map[string]any{"integrationId": "oauth.linkedin", "displayName": "x"})); got.Code != http.StatusBadRequest {
		t.Fatalf("integration change accepted: %d", got.Code)
	}
	renamed := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPatch, item, rev(account.Revision, map[string]any{"displayName": "Renamed"}))
	if renamed.Code != http.StatusOK || !strings.Contains(renamed.Body.String(), `"displayName":"Renamed"`) {
		t.Fatalf("rename: %d %s", renamed.Code, renamed.Body)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPut, item+"/token", rev(account.Revision, map[string]any{"token": "next"})); got.Code != http.StatusConflict {
		t.Fatalf("stale revision rotated: %d", got.Code)
	}
	rotated := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPut, item+"/token", rev(account.Revision+1, map[string]any{"token": "private-next-token"}))
	if rotated.Code != http.StatusOK || !strings.Contains(rotated.Body.String(), `"credentialRevision":2`) || strings.Contains(rotated.Body.String(), "private-next-token") {
		t.Fatalf("rotate: %d %s", rotated.Code, rotated.Body)
	}
	disconnected := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodDelete, item+"/token", rev(account.Revision+2, nil))
	if disconnected.Code != http.StatusOK || !strings.Contains(disconnected.Body.String(), `"status":"disconnected"`) {
		t.Fatalf("disconnect: %d %s", disconnected.Code, disconnected.Body)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, item, rev(account.Revision+3, nil)); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on an account: %d", got.Code)
	}
	removed := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodDelete, item, rev(account.Revision+3, nil))
	if removed.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", removed.Code, removed.Body)
	}
	if rows, _ := store.LinkedAccounts(t.Context(), "usr_alice"); len(rows) != 0 {
		t.Fatal("remove left the account")
	}
}

func TestIntegrationAccountHTTPOwnerCap(t *testing.T) {
	store := newLibraryFileStore(t)
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	for range maxLinkedAccountsPerConnection {
		if _, err := store.CreateLinkedAccount(t.Context(), integrationTokenFixture("usr_alice"), AccountPolicyPrecondition{}); err != nil {
			t.Fatal(err)
		}
	}
	got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, "/api/linked-accounts", `{"integrationId":"token_api.bearer","displayName":"One more","token":"t"}`)
	if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), controlCodeCapacityLimited) {
		t.Fatalf("cap: %d %s", got.Code, got.Body)
	}
}

func TestStandaloneLinkedOAuthHTTP(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		t.Run(prefix, func(t *testing.T) { testStandaloneLinkedOAuthHTTP(t, prefix) })
	}
}

func testStandaloneLinkedOAuthHTTP(t *testing.T, prefix string) {
	store := newLibraryFileStore(t)
	service := oauthServiceFixture(t)
	service.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/userinfo" {
			return oauthJSON(`{"sub":"member","name":"Provider name"}`), nil
		}
		return oauthJSON(`{"access_token":"private-oauth-token","expires_in":3600}`), nil
	})
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithLinkedAccountOAuth(service))
	mux := http.NewServeMux()
	api.Routes(mux)
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	base := prefix + "/account-oauth/linkedin"
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, base+"/start", encode(map[string]any{"displayName": "Social", "connectionRevision": 1})); got.Code != http.StatusBadRequest {
		t.Fatalf("standalone start accepted a parent revision: %d", got.Code)
	}
	start := func(extra map[string]any) map[string]string {
		t.Helper()
		body := map[string]any{"connectionId": "", "displayName": "Social"}
		for k, v := range extra {
			body[k] = v
		}
		res := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, base+"/start", encode(body))
		if res.Code != http.StatusOK {
			t.Fatalf("standalone start: %d %s", res.Code, res.Body)
		}
		var out map[string]string
		_ = json.Unmarshal(res.Body.Bytes(), &out)
		if u, err := url.Parse(out["authorizationUrl"]); err != nil || u.Query().Get("state") != out["state"] {
			t.Fatal("unexpected authorization URL")
		}
		return out
	}
	pending := start(nil)
	completion := map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "code": "code"}
	if other := hostedNamespaceRequest(t, mux, key, now, "usr_bob", "admin", http.MethodPost, base+"/complete", encode(completion)); other.Code != http.StatusConflict {
		t.Fatal("coworker completed a standalone sign-in")
	}
	done := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, base+"/complete", encode(completion))
	if done.Code != http.StatusOK || strings.Contains(done.Body.String(), "private-oauth-token") {
		t.Fatalf("standalone completion: %d %s", done.Code, done.Body)
	}
	var account ConnectedAccount
	if err := json.Unmarshal(done.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	if account.ConnectionID != "" || account.IntegrationID != "oauth.linkedin" || account.IdentityStatus != "provider_confirmed" || account.UsableBy == nil || *account.UsableBy != (ConnectedAccountUsableBy{}) {
		t.Fatalf("standalone OAuth DTO: %s", done.Body)
	}
	rows, err := store.LinkedAccounts(t.Context(), "usr_alice")
	if err != nil || len(rows) != 1 || !rows[0].isIntegrationAccount() || len(store.integrationAccounts) != 1 {
		t.Fatalf("standalone OAuth record: %+v %v", rows, err)
	}
	// Reconnecting names the account and its revision; a stale revision is refused.
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, base+"/start", encode(map[string]any{"displayName": "Social", "accountId": account.ID, "revision": account.Revision + 1})); got.Code != http.StatusConflict {
		t.Fatalf("stale reconnect started: %d", got.Code)
	}
	pending = start(map[string]any{"accountId": account.ID, "revision": account.Revision})
	completion = map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "code": "code"}
	again := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, base+"/complete", encode(completion))
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"credentialRevision":2`) || !strings.Contains(again.Body.String(), account.ID) {
		t.Fatalf("standalone reconnect: %d %s", again.Code, again.Body)
	}
	// The same /linked-accounts routes manage it, but never swap in a token.
	item := prefix + "/linked-accounts/" + account.ID
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPut, item+"/token", encode(map[string]any{"revision": account.Revision + 1, "token": "pasted"})); got.Code != http.StatusBadRequest {
		t.Fatalf("pasted token replaced OAuth identity: %d", got.Code)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodDelete, item, encode(map[string]any{"revision": account.Revision + 1})); got.Code != http.StatusNoContent {
		t.Fatalf("remove standalone OAuth: %d %s", got.Code, got.Body)
	}
}

// noStandaloneStore hides the standalone marker, as an Engine whose store
// predates narthex_integration_accounts would.
type noStandaloneStore struct {
	AccountStore
	LinkedAccountStore
	LinkedOAuthFlowStore
}

func TestStandaloneLinkingNeedsStoreSupport(t *testing.T) {
	file := newLibraryFileStore(t)
	store := noStandaloneStore{file, file, file}
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithLinkedAccountOAuth(oauthServiceFixture(t)))
	mux := http.NewServeMux()
	api.Routes(mux)
	if slices.Contains(api.controlCapabilities(), controlCapabilityAccountStandalone) {
		t.Fatal("standalone capability advertised without store support")
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, "/api/linked-accounts", `{"integrationId":"token_api.bearer","displayName":"x","token":"t"}`); got.Code != http.StatusNotImplemented {
		t.Fatalf("create without store support: %d", got.Code)
	}
	if got := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", http.MethodPost, "/api/account-oauth/linkedin/start", `{"displayName":"Social"}`); got.Code != http.StatusNotFound {
		t.Fatalf("standalone OAuth start without store support: %d", got.Code)
	}
}

func TestFileStandaloneLinkedOAuthFlow(t *testing.T) {
	testStandaloneLinkedOAuthFlow(t, newLibraryFileStore(t))
}

func TestPgStandaloneLinkedOAuthFlow(t *testing.T) {
	testStandaloneLinkedOAuthFlow(t, newPgConnectionsStore(t))
}

func testStandaloneLinkedOAuthFlow(t *testing.T, store linkedOAuthTestStore) {
	t.Helper()
	subject := "usr_flow_" + newPgFixtureSuffix()
	flow := LinkedOAuthFlow{StateHash: oauthLinkHash(newEpoch()), ProofHash: oauthLinkHash("proof"), Subject: subject, Provider: "linkedin", DisplayName: "Social", ExpiresAt: time.Now().Add(linkedOAuthLifetime)}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_linked_oauth_flows WHERE owner_subject=$1`, subject)
		})
	}
	partial := flow
	partial.StateHash = oauthLinkHash(newEpoch())
	partial.Parent = AccountPolicyPrecondition{Revision: 1}
	if err := store.PutLinkedOAuthFlow(t.Context(), partial); err == nil {
		t.Fatal("standalone flow with a partial parent stored")
	}
	if err := store.PutLinkedOAuthFlow(t.Context(), flow); err != nil {
		t.Fatalf("standalone flow: %v", err)
	}
	got, err := store.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, subject, "linkedin", "proof")
	if err != nil || got.ConnectionID != "" || got.Parent != (AccountPolicyPrecondition{}) {
		t.Fatalf("consume standalone flow: %+v %v", got, err)
	}
}
