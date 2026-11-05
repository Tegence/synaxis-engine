package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// The connections group of /control/v1 (docs/CONTROL_V1.md, "Connections").
// Every scenario is written once against AccountStore and runs on FileStore
// here and on PgStore in control_v1_connections_pg_test.go.

const (
	testDelegatedClientSecret = "secret-delegated-0123456789abcdefghijklmnop"
	testDelegatedListingToken = "listing-token-0123456789abcdef"
)

type testCallerDelegatedDTO struct {
	TokenEndpoint   string `json:"tokenEndpoint"`
	ClientID        string `json:"clientId"`
	Resource        string `json:"resource"`
	ClientSecretSet bool   `json:"clientSecretSet"`
}

type testConnectionDTO struct {
	ToolPrefix            string                  `json:"toolPrefix"`
	DisplayName           string                  `json:"displayName"`
	Group                 string                  `json:"group"`
	ConnectionNamespaceID string                  `json:"connectionNamespaceId"`
	ConnectionScope       string                  `json:"connectionScope"`
	URL                   string                  `json:"url"`
	AuthMode              string                  `json:"authMode"`
	TokenSet              bool                    `json:"tokenSet"`
	Revision              int64                   `json:"revision"`
	CallerDelegated       *testCallerDelegatedDTO `json:"callerDelegated"`
}

type connectionsTestHarness struct {
	t      *testing.T
	store  AccountStore
	mux    *http.ServeMux
	key    ed25519.PrivateKey
	now    time.Time
	name   string
	group  string
	listed atomic.Int32
	// dialled records every account re-aggregation listed, as it was handed
	// to the upstream client.
	dialledMu sync.Mutex
	dialled   []Account
}

func newConnectionsTestHarness(t *testing.T, store AccountStore) *connectionsTestHarness {
	t.Helper()
	verifier, key, now := newActorVerifier(t)
	suffix := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(newEpoch()))
	h := &connectionsTestHarness{t: t, store: store, key: key, now: now, name: "delegated_" + suffix, group: "Delegated " + suffix}
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	// No test reaches a network upstream: re-aggregation lists one fake tool.
	gateway.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		h.listed.Add(1)
		h.dialledMu.Lock()
		h.dialled = append(h.dialled, copyAccount(account))
		h.dialledMu.Unlock()
		return []mcp.Tool{mcp.NewTool("search_records", mcp.WithDescription("Search records"))}, nil
	}
	api := NewConsoleAPI(store, gateway, nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	h.mux = http.NewServeMux()
	api.Routes(h.mux)
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, h.name, h.group) })
	}
	return h
}

func newFileConnectionsStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func (h *connectionsTestHarness) request(user, role, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	return hostedNamespaceRequestWithHeaders(h.t, h.mux, h.key, h.now, user, role, method, path, body, headers)
}

func (h *connectionsTestHarness) service(method, path, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(platformServiceActorID, "service", method, path, body, nil)
}

func (h *connectionsTestHarness) path() string { return "/control/v1/connections/" + h.name }

func (h *connectionsTestHarness) createBody(mutate func(body map[string]any, delegated map[string]any)) string {
	h.t.Helper()
	delegated := map[string]any{
		"tokenEndpoint": "https://tools.example.com/hosted/h1/oauth/token",
		"clientId":      "client_delegated_1",
		"clientSecret":  testDelegatedClientSecret,
		"resource":      "https://tools.example.com/mcp",
	}
	body := map[string]any{
		"toolPrefix":      h.name,
		"displayName":     "Delegated tools",
		"group":           h.group,
		"connectionScope": "service",
		"url":             "https://tools.example.com/hosted/h1/mcp",
		"authMode":        "token",
		"callerDelegated": delegated,
	}
	if mutate != nil {
		mutate(body, delegated)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(encoded)
}

func decodeTestConnection(t *testing.T, response *httptest.ResponseRecorder, want int) testConnectionDTO {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status=%d body=%s; want %d", response.Code, response.Body, want)
	}
	if response.Header().Get(controlRequestIDHeader) == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("control response missing envelope headers: %v", response.Header())
	}
	assertNoConnectionSecrets(t, response.Body.String())
	var dto testConnectionDTO
	if err := json.Unmarshal(response.Body.Bytes(), &dto); err != nil {
		t.Fatalf("decode connection: %v body=%s", err, response.Body)
	}
	return dto
}

// assertNoConnectionSecrets is the DTO rule: a response may say a secret is
// set, never what it is.
func assertNoConnectionSecrets(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{testDelegatedClientSecret, testDelegatedListingToken, "rotated-secret-0123456789abcdefghijklmn", "clientSecret\"", "bearerToken", "bearer_token", "client_secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
}

// plainBody is a create body for a plain token connection: no
// callerDelegated block.
func (h *connectionsTestHarness) plainBody() string {
	return h.createBody(func(b, _ map[string]any) { delete(b, "callerDelegated") })
}

// putToken sets the listing token as actor and returns the new revision.
func (h *connectionsTestHarness) putToken(user, role string, revision int64, token string) int64 {
	h.t.Helper()
	body := `{"token":"` + token + `","revision":` + itoa64(revision) + `}`
	return decodeTestConnection(h.t, h.request(user, role, http.MethodPut, h.path()+"/token", body, nil), http.StatusOK).Revision
}

// assertNoCredentialDialledAt fails when re-aggregation handed any stored
// credential of the account to an upstream on host.
func (h *connectionsTestHarness) assertNoCredentialDialledAt(t *testing.T, host string, credentials ...string) {
	t.Helper()
	h.dialledMu.Lock()
	defer h.dialledMu.Unlock()
	for _, account := range h.dialled {
		if !strings.Contains(account.URL, host) && !strings.Contains(account.TokenEndpoint, host) {
			continue
		}
		for _, credential := range credentials {
			for _, held := range []string{account.BearerToken, account.ClientSecret, account.AccessToken, account.RefreshToken} {
				if credential != "" && held == credential {
					t.Fatalf("re-aggregation dialled %s (token endpoint %s) holding a credential stored for the old destination", account.URL, account.TokenEndpoint)
				}
			}
		}
	}
}

func (h *connectionsTestHarness) mustCreate() testConnectionDTO {
	h.t.Helper()
	return decodeTestConnection(h.t, h.service(http.MethodPost, "/control/v1/connections", h.createBody(nil)), http.StatusCreated)
}

func TestControlConnectionsCreateIdenticalRetryReturns200(t *testing.T) {
	store := newFileConnectionsStore(t)
	testControlConnectionsCreateIdenticalRetry(t, store)
	// FileStore persists the flag and the delegation fields in its JSON state.
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range reloaded.Accounts() {
		if strings.HasPrefix(account.Name, "delegated_") && (!account.CallerDelegated || account.ClientSecret != testDelegatedClientSecret || account.Resource != "https://tools.example.com/mcp") {
			t.Fatalf("reloaded account=%+v", account)
		}
	}
}

func testControlConnectionsCreateIdenticalRetry(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	if created.ToolPrefix != h.name || created.DisplayName != "Delegated tools" || created.Group != h.group ||
		created.ConnectionNamespaceID == "" || created.ConnectionScope != "service" || created.AuthMode != "token" ||
		created.URL != "https://tools.example.com/hosted/h1/mcp" || created.TokenSet || created.Revision < 1 {
		t.Fatalf("created=%+v", created)
	}
	if created.CallerDelegated == nil || *created.CallerDelegated != (testCallerDelegatedDTO{
		TokenEndpoint: "https://tools.example.com/hosted/h1/oauth/token", ClientID: "client_delegated_1",
		Resource: "https://tools.example.com/mcp", ClientSecretSet: true,
	}) {
		t.Fatalf("callerDelegated=%+v", created.CallerDelegated)
	}
	stored, found := store.Account(h.name)
	if !found || !stored.CallerDelegated || !stored.IsCallerDelegated() || stored.ClientSecret != testDelegatedClientSecret ||
		stored.ClientID != "client_delegated_1" || stored.TokenEndpoint != "https://tools.example.com/hosted/h1/oauth/token" ||
		stored.Resource != "https://tools.example.com/mcp" || stored.AuthMode != "token" || stored.BearerToken != "" ||
		stored.ConnectionScope != ConnectionScopeService || stored.Label != "Delegated tools" || stored.Group != h.group {
		t.Fatalf("stored=%+v found=%v", stored, found)
	}

	// The natural key converges: an identical retry (a lost response) is the
	// existing connection with 200, not a second account or a 409.
	retried := decodeTestConnection(t, h.service(http.MethodPost, "/control/v1/connections", h.createBody(nil)), http.StatusOK)
	if !reflect.DeepEqual(retried, created) {
		t.Fatalf("retried=%+v created=%+v", retried, created)
	}
	// A retry after the listing token was set still converges.
	decodeTestConnection(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`), http.StatusOK)
	retried = decodeTestConnection(t, h.service(http.MethodPost, "/control/v1/connections", h.createBody(nil)), http.StatusOK)
	if retried.Revision != created.Revision+1 || !retried.TokenSet {
		t.Fatalf("retry after token=%+v", retried)
	}
	read := decodeTestConnection(t, h.service(http.MethodGet, h.path(), ""), http.StatusOK)
	if !reflect.DeepEqual(read, retried) {
		t.Fatalf("read=%+v retried=%+v", read, retried)
	}
}

func TestControlConnectionsDifferentBodyConflicts(t *testing.T) {
	testControlConnectionsDifferentBodyConflicts(t, newFileConnectionsStore(t))
}

func testControlConnectionsDifferentBodyConflicts(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"display name":   func(b, _ map[string]any) { b["displayName"] = "Other tools" },
		"folder":         func(b, _ map[string]any) { b["group"] = h.group + " other" },
		"url":            func(b, _ map[string]any) { b["url"] = "https://tools.example.com/hosted/h2/mcp" },
		"client id":      func(_, d map[string]any) { d["clientId"] = "client_delegated_2" },
		"client secret":  func(_, d map[string]any) { d["clientSecret"] = "rotated-secret-0123456789abcdefghijklmn" },
		"token endpoint": func(_, d map[string]any) { d["tokenEndpoint"] = "https://tools.example.com/hosted/h1/oauth/token2" },
		"not delegated":  func(b, _ map[string]any) { delete(b, "callerDelegated") },
		"scope":          func(b, _ map[string]any) { b["connectionScope"] = "shared" },
	} {
		response := h.service(http.MethodPost, "/control/v1/connections", h.createBody(mutate))
		expectControlProblem(t, response, http.StatusConflict, controlCodeAlreadyExists)
		assertNoConnectionSecrets(t, response.Body.String())
		stored, _ := store.Account(h.name)
		if stored.Label != "Delegated tools" || stored.ClientSecret != testDelegatedClientSecret || stored.Revision != created.Revision {
			t.Fatalf("%s conflict changed the account: %+v", name, stored)
		}
	}
	if folder := h.group + " other"; store != nil {
		if namespaces, ok := store.(ConnectionNamespaceStore); ok {
			list, err := namespaces.ConnectionNamespaces(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, ns := range list {
				if ns.Label == folder {
					t.Fatalf("a refused create minted folder %q", folder)
				}
			}
		}
	}

	// An account that was not created through this route (here: a plain
	// token connection under the same prefix) is never adopted.
	h2 := newConnectionsTestHarness(t, store)
	if err := store.Create(context.Background(), Account{Name: h2.name, Label: "Existing", Group: h2.group, URL: "https://tools.example.com/hosted/h1/mcp", AuthMode: "token", BearerToken: "existing-token"}); err != nil {
		t.Fatal(err)
	}
	expectControlProblem(t, h2.service(http.MethodPost, "/control/v1/connections", h2.createBody(nil)), http.StatusConflict, controlCodeAlreadyExists)
	if stored, _ := store.Account(h2.name); stored.CallerDelegated || stored.BearerToken != "existing-token" {
		t.Fatalf("existing account was adopted: %+v", stored)
	}
}

func TestControlConnectionsIdempotencyKeyReplays(t *testing.T) {
	testControlConnectionsIdempotencyKeyReplays(t, newFileConnectionsStore(t))
}

func testControlConnectionsIdempotencyKeyReplays(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	key := map[string]string{controlIdempotencyKeyHeader: "create-" + h.name}
	first := h.request(platformServiceActorID, "service", http.MethodPost, "/control/v1/connections", h.createBody(nil), key)
	created := decodeTestConnection(t, first, http.StatusCreated)
	replayed := h.request(platformServiceActorID, "service", http.MethodPost, "/control/v1/connections", h.createBody(nil), key)
	if replayed.Header().Get(controlIdempotentReplayHeader) != "true" {
		t.Fatalf("replay header missing: %v", replayed.Header())
	}
	if got := decodeTestConnection(t, replayed, http.StatusCreated); !reflect.DeepEqual(got, created) {
		t.Fatalf("replayed=%+v created=%+v", got, created)
	}
	conflict := h.request(platformServiceActorID, "service", http.MethodPost, "/control/v1/connections",
		h.createBody(func(b, _ map[string]any) { b["displayName"] = "Changed" }), key)
	expectControlProblem(t, conflict, http.StatusConflict, controlCodeIdempotencyKeyConflict)
	if stored, _ := store.Account(h.name); stored.Label != "Delegated tools" {
		t.Fatalf("key conflict changed the account: %+v", stored)
	}
}

func TestControlConnectionsPatchRevisionFence(t *testing.T) {
	testControlConnectionsPatchRevisionFence(t, newFileConnectionsStore(t))
}

func testControlConnectionsPatchRevisionFence(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	stale := `{"revision":` + itoa64(created.Revision+7) + `,"displayName":"Renamed"}`
	expectControlProblem(t, h.service(http.MethodPatch, h.path(), stale), http.StatusConflict, controlCodeRevisionMismatch)
	expectControlProblem(t, h.service(http.MethodPatch, h.path(), `{"displayName":"Renamed"}`), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, h.service(http.MethodPatch, "/control/v1/connections/missing_"+h.name, `{"revision":1,"displayName":"Renamed"}`), http.StatusNotFound, controlCodeNotFound)

	before := h.listed.Load()
	patch := `{"revision":` + itoa64(created.Revision) + `,"displayName":"Renamed tools","url":"https://tools.example.com/hosted/h9/mcp",` +
		`"callerDelegated":{"tokenEndpoint":"https://tools.example.com/hosted/h9/oauth/token","clientSecret":"rotated-secret-0123456789abcdefghijklmn"}}`
	patched := decodeTestConnection(t, h.service(http.MethodPatch, h.path(), patch), http.StatusOK)
	if patched.Revision <= created.Revision || patched.DisplayName != "Renamed tools" || patched.URL != "https://tools.example.com/hosted/h9/mcp" ||
		patched.CallerDelegated == nil || patched.CallerDelegated.TokenEndpoint != "https://tools.example.com/hosted/h9/oauth/token" ||
		patched.CallerDelegated.ClientID != "client_delegated_1" || !patched.CallerDelegated.ClientSecretSet {
		t.Fatalf("patched=%+v", patched)
	}
	stored, _ := store.Account(h.name)
	if stored.ClientSecret != "rotated-secret-0123456789abcdefghijklmn" || stored.Label != "Renamed tools" || stored.Revision != patched.Revision {
		t.Fatalf("stored after patch=%+v", stored)
	}
	if h.listed.Load() == before {
		t.Fatal("a patched connection was not re-aggregated")
	}
	// The revision the patch consumed is now stale.
	expectControlProblem(t, h.service(http.MethodPatch, h.path(), `{"revision":`+itoa64(created.Revision)+`,"displayName":"Again"}`), http.StatusConflict, controlCodeRevisionMismatch)

	// A patch is validated as a whole: a URL off the resource's origin is refused
	// and changes nothing.
	invalid := `{"revision":` + itoa64(patched.Revision) + `,"url":"https://elsewhere.example.com/hosted/h9/mcp"}`
	expectControlProblem(t, h.service(http.MethodPatch, h.path(), invalid), http.StatusBadRequest, controlCodeValidationFailed)
	// The folder moves by label, creating it when missing.
	moved := decodeTestConnection(t, h.service(http.MethodPatch, h.path(), `{"revision":`+itoa64(patched.Revision)+`,"group":"`+h.group+` moved"}`), http.StatusOK)
	if moved.Group != h.group+" moved" || moved.ConnectionNamespaceID == created.ConnectionNamespaceID || moved.Revision <= patched.Revision {
		t.Fatalf("moved=%+v", moved)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgConnectionFixture(t, pg, "", h.group+" moved") })
	}
}

func TestControlConnectionsTokenPutRevisionFence(t *testing.T) {
	testControlConnectionsTokenPutRevisionFence(t, newFileConnectionsStore(t))
}

func testControlConnectionsTokenPutRevisionFence(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	expectControlProblem(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision+1)+`}`), http.StatusConflict, controlCodeRevisionMismatch)
	expectControlProblem(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`"}`), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"","revision":`+itoa64(created.Revision)+`}`), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, h.service(http.MethodPut, "/control/v1/connections/missing_"+h.name+"/token", `{"token":"x-token-value","revision":1}`), http.StatusNotFound, controlCodeNotFound)
	if stored, _ := store.Account(h.name); stored.BearerToken != "" {
		t.Fatalf("refused token PUT wrote a token: %+v", stored)
	}

	before := h.listed.Load()
	updated := decodeTestConnection(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`), http.StatusOK)
	if updated.Revision != created.Revision+1 || !updated.TokenSet || updated.CallerDelegated == nil {
		t.Fatalf("updated=%+v", updated)
	}
	if h.listed.Load() == before {
		t.Fatal("token PUT did not re-aggregate the connection")
	}
	stored, _ := store.Account(h.name)
	if stored.BearerToken != testDelegatedListingToken || stored.AuthMode != "token" || stored.Revision != updated.Revision {
		t.Fatalf("stored=%+v", stored)
	}
	// Every re-PUT bumps the revision, so the previous one is stale.
	expectControlProblem(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`), http.StatusConflict, controlCodeRevisionMismatch)
	again := decodeTestConnection(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(updated.Revision)+`}`), http.StatusOK)
	if again.Revision != updated.Revision+1 {
		t.Fatalf("re-PUT revision=%d; want %d", again.Revision, updated.Revision+1)
	}
}

func TestControlConnectionsDeleteIdempotent(t *testing.T) {
	testControlConnectionsDeleteIdempotent(t, newFileConnectionsStore(t))
}

func testControlConnectionsDeleteIdempotent(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	h.mustCreate()
	for attempt := 0; attempt < 2; attempt++ {
		response := h.service(http.MethodDelete, h.path(), "")
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 || response.Header().Get(controlRequestIDHeader) == "" {
			t.Fatalf("delete attempt %d status=%d body=%s", attempt, response.Code, response.Body)
		}
		if _, found := store.Account(h.name); found {
			t.Fatalf("delete attempt %d left the account", attempt)
		}
	}
	if response := h.service(http.MethodDelete, "/control/v1/connections/never_"+h.name, ""); response.Code != http.StatusNoContent {
		t.Fatalf("missing connection delete status=%d body=%s", response.Code, response.Body)
	}
	expectControlProblem(t, h.service(http.MethodGet, h.path(), ""), http.StatusNotFound, controlCodeNotFound)
	// Re-enabling creates a new incarnation under the same natural key.
	recreated := h.mustCreate()
	if recreated.ToolPrefix != h.name {
		t.Fatalf("recreated=%+v", recreated)
	}
}

func TestControlConnectionsProblemDetails(t *testing.T) {
	testControlConnectionsProblemDetails(t, newFileConnectionsStore(t))
}

func testControlConnectionsProblemDetails(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	echo := map[string]string{controlRequestIDHeader: "req-connections.1"}
	for _, tc := range []struct {
		name, user, role, method, path, body string
		status                               int
		code                                 string
	}{
		{"invalid body", platformServiceActorID, "service", http.MethodPost, "/control/v1/connections", `{"toolPrefix":`, http.StatusBadRequest, controlCodeValidationFailed},
		{"unknown field", platformServiceActorID, "service", http.MethodPost, "/control/v1/connections", h.createBody(func(b, _ map[string]any) { b["bearerToken"] = "x" }), http.StatusBadRequest, controlCodeValidationFailed},
		{"non-canonical prefix", platformServiceActorID, "service", http.MethodPost, "/control/v1/connections", h.createBody(func(b, _ map[string]any) { b["toolPrefix"] = "Delegated Tools" }), http.StatusBadRequest, controlCodeValidationFailed},
		{"unknown connection", platformServiceActorID, "service", http.MethodGet, h.path(), "", http.StatusNotFound, controlCodeNotFound},
		{"operator", "usr_operator", "operator", http.MethodPost, "/control/v1/connections", h.createBody(nil), http.StatusForbidden, controlCodeForbidden},
		{"viewer", "usr_viewer", "viewer", http.MethodGet, h.path(), "", http.StatusForbidden, controlCodeForbidden},
		{"wrong method", "usr_owner", "owner", http.MethodPut, h.path(), `{}`, http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable},
		// The service actor's closed allowlist has no list route.
		{"service list", platformServiceActorID, "service", http.MethodGet, "/control/v1/connections", "", http.StatusUnauthorized, controlCodeActorAssertionInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.request(tc.user, tc.role, tc.method, tc.path, tc.body, echo)
			problem := expectControlProblem(t, response, tc.status, tc.code)
			if problem.RequestID != "req-connections.1" || response.Header().Get(controlRequestIDHeader) != "req-connections.1" {
				t.Fatalf("request id not echoed: problem=%+v headers=%v", problem, response.Header())
			}
		})
	}
	if _, found := store.Account(h.name); found {
		t.Fatal("a refused request created the connection")
	}
	// Owners and admins manage plain connections on this surface too; a
	// caller-delegated one is the service actor's
	// (testControlConnectionsCallerDelegatedWritesServiceOnly).
	created := decodeTestConnection(t, h.request("usr_owner", "owner", http.MethodPost, "/control/v1/connections", h.plainBody(), nil), http.StatusCreated)
	read := decodeTestConnection(t, h.request("usr_admin", "admin", http.MethodGet, h.path(), "", nil), http.StatusOK)
	if !reflect.DeepEqual(read, created) || read.CallerDelegated != nil {
		t.Fatalf("admin read=%+v created=%+v", read, created)
	}
}

func TestCallerDelegatedValidation(t *testing.T) {
	store := newFileConnectionsStore(t)
	h := newConnectionsTestHarness(t, store)
	refused := map[string]func(b, d map[string]any){
		"oauth mode":        func(b, _ map[string]any) { b["authMode"] = "oauth" },
		"missing auth mode": func(b, _ map[string]any) { delete(b, "authMode") },
		"http url":          func(b, _ map[string]any) { b["url"] = "http://tools.example.com/hosted/h1/mcp" },
		"loopback http without seam": func(b, d map[string]any) {
			b["url"], d["tokenEndpoint"], d["resource"] = "http://127.0.0.1:8080/hosted/h1/mcp", "http://127.0.0.1:8080/oauth/token", "http://127.0.0.1:8080/mcp"
		},
		"token endpoint other host": func(_, d map[string]any) { d["tokenEndpoint"] = "https://auth.example.com/oauth/token" },
		"resource other origin":     func(_, d map[string]any) { d["resource"] = "https://tools.example.com:8443/mcp" },
		"resource other scheme":     func(_, d map[string]any) { d["resource"] = "http://tools.example.com/mcp" },
		"url outside resource":      func(b, _ map[string]any) { b["url"] = "https://tools.example.com/hosted/h1/other" },
		"url suffix not a segment":  func(b, _ map[string]any) { b["url"] = "https://tools.example.com/hosted/h1xmcp" },
		"resource query":            func(_, d map[string]any) { d["resource"] = "https://tools.example.com/mcp?x=1" },
		"resource fragment":         func(_, d map[string]any) { d["resource"] = "https://tools.example.com/mcp#x" },
		"url credentials":           func(b, _ map[string]any) { b["url"] = "https://user:pass@tools.example.com/hosted/h1/mcp" },
		"url dot segment":           func(b, _ map[string]any) { b["url"] = "https://tools.example.com/hosted/../mcp" },
		"private address": func(b, d map[string]any) {
			b["url"], d["tokenEndpoint"], d["resource"] = "https://10.0.0.1/mcp", "https://10.0.0.1/token", "https://10.0.0.1/mcp"
		},
		"personal scope":         func(b, _ map[string]any) { b["connectionScope"] = "personal" },
		"member credentials":     func(b, _ map[string]any) { b["memberCredentials"] = true },
		"empty client id":        func(_, d map[string]any) { d["clientId"] = "" },
		"long client id":         func(_, d map[string]any) { d["clientId"] = strings.Repeat("c", 129) },
		"client id with space":   func(_, d map[string]any) { d["clientId"] = "client one" },
		"client id control byte": func(_, d map[string]any) { d["clientId"] = "client\u0001" },
		"short secret":           func(_, d map[string]any) { d["clientSecret"] = strings.Repeat("s", 31) },
		"long secret":            func(_, d map[string]any) { d["clientSecret"] = strings.Repeat("s", 257) },
		"secret with newline":    func(_, d map[string]any) { d["clientSecret"] = strings.Repeat("s", 40) + "\n" },
		"missing token endpoint": func(_, d map[string]any) { delete(d, "tokenEndpoint") },
		"missing resource":       func(_, d map[string]any) { delete(d, "resource") },
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			response := h.service(http.MethodPost, "/control/v1/connections", h.createBody(mutate))
			expectControlProblem(t, response, http.StatusBadRequest, controlCodeValidationFailed)
			assertNoConnectionSecrets(t, response.Body.String())
			if _, found := store.Account(h.name); found {
				t.Fatal("refused body created the connection")
			}
		})
	}

	accepted := map[string]func(b, d map[string]any){
		// Shared hosting: the reachable URL carries a path prefix the
		// canonical resource lacks; the token endpoint shares the origin.
		"path prefix":       nil,
		"exact resource":    func(b, _ map[string]any) { b["url"] = "https://tools.example.com/mcp" },
		"explicit port 443": func(_, d map[string]any) { d["resource"] = "https://tools.example.com:443/mcp" },
		"shared scope":      func(b, _ map[string]any) { b["connectionScope"] = "shared" },
		"bounds": func(_, d map[string]any) {
			d["clientId"] = strings.Repeat("c", 128)
			d["clientSecret"] = strings.Repeat("s", 32)
		},
		"long secret bound": func(_, d map[string]any) { d["clientSecret"] = strings.Repeat("s", 256) },
	}
	for name, mutate := range accepted {
		t.Run(name, func(t *testing.T) {
			hh := newConnectionsTestHarness(t, store)
			response := hh.service(http.MethodPost, "/control/v1/connections", hh.createBody(mutate))
			decodeTestConnection(t, response, http.StatusCreated)
		})
	}

	t.Run("loopback http with test seam", func(t *testing.T) {
		callerDelegatedAllowLoopbackHTTP = true
		t.Cleanup(func() { callerDelegatedAllowLoopbackHTTP = false })
		hh := newConnectionsTestHarness(t, store)
		body := hh.createBody(func(b, d map[string]any) {
			b["url"], d["tokenEndpoint"], d["resource"] = "http://127.0.0.1:8080/hosted/h1/mcp", "http://127.0.0.1:8080/oauth/token", "http://127.0.0.1:8080/mcp"
		})
		decodeTestConnection(t, hh.service(http.MethodPost, "/control/v1/connections", body), http.StatusCreated)
		// Loopback is the only HTTP exception, even under the seam.
		other := newConnectionsTestHarness(t, store)
		body = other.createBody(func(b, d map[string]any) {
			b["url"], d["tokenEndpoint"], d["resource"] = "http://tools.example.com/hosted/h1/mcp", "http://tools.example.com/oauth/token", "http://tools.example.com/mcp"
		})
		expectControlProblem(t, other.service(http.MethodPost, "/control/v1/connections", body), http.StatusBadRequest, controlCodeValidationFailed)
	})
}

func TestCallerDelegatedDTOHasNoSecrets(t *testing.T) {
	testCallerDelegatedDTOHasNoSecrets(t, newFileConnectionsStore(t))
}

func testCallerDelegatedDTOHasNoSecrets(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	responses := []*httptest.ResponseRecorder{
		h.service(http.MethodPost, "/control/v1/connections", h.createBody(nil)),
		h.service(http.MethodGet, h.path(), ""),
		h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`),
	}
	read := decodeTestConnection(t, h.service(http.MethodGet, h.path(), ""), http.StatusOK)
	responses = append(responses,
		h.service(http.MethodPatch, h.path(), `{"revision":`+itoa64(read.Revision)+`,"callerDelegated":{"clientSecret":"rotated-secret-0123456789abcdefghijklmn"}}`),
		h.service(http.MethodPost, "/control/v1/connections", h.createBody(func(b, _ map[string]any) { b["displayName"] = "Conflict" })),
		// The self-hosted console listing shares the account; it never
		// serialized secrets and must not start now.
		h.request("usr_owner", "owner", http.MethodGet, "/api/servers", "", nil),
	)
	for i, response := range responses {
		body := response.Body.String()
		assertNoConnectionSecrets(t, body)
		if i < 4 {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
				t.Fatalf("response %d: %v body=%s", i, err, body)
			}
			var delegated map[string]json.RawMessage
			if err := json.Unmarshal(raw["callerDelegated"], &delegated); err != nil {
				t.Fatalf("response %d callerDelegated: %v body=%s", i, err, body)
			}
			if len(delegated) != 4 || string(delegated["clientSecretSet"]) != "true" || delegated["tokenEndpoint"] == nil || delegated["clientId"] == nil || delegated["resource"] == nil {
				t.Fatalf("response %d callerDelegated keys=%s", i, raw["callerDelegated"])
			}
		}
	}
	if stored, _ := store.Account(h.name); stored.ClientSecret != "rotated-secret-0123456789abcdefghijklmn" || stored.BearerToken != testDelegatedListingToken {
		t.Fatalf("stored secrets=%q/%q", stored.ClientSecret, stored.BearerToken)
	}
}

func TestControlConnectionsPatchCannotRetargetStoredSecrets(t *testing.T) {
	testControlConnectionsPatchCannotRetargetStoredSecrets(t, newFileConnectionsStore(t))
}

// testControlConnectionsPatchCannotRetargetStoredSecrets: a PATCH never moves
// a credential the Engine already holds to another destination. A
// caller-delegated connection changes url, token endpoint or resource only
// when the same PATCH supplies the client secret, and then drops its listing
// token; any other connection that holds credentials keeps its URL. The
// refusal holds for every actor, and again at the store under its lock.
func testControlConnectionsPatchCannotRetargetStoredSecrets(t *testing.T, store AccountStore) {
	ctx := context.Background()
	const collector = "collector.example.net"
	const movedSecret = "moved-secret-0123456789abcdefghijklmnopq"
	actors := []struct{ user, role string }{{platformServiceActorID, "service"}, {"usr_admin", "admin"}, {"usr_owner", "owner"}}
	patch := func(h *connectionsTestHarness, user, role string, revision int64, fields string) *httptest.ResponseRecorder {
		return h.request(user, role, http.MethodPatch, h.path(), `{"revision":`+itoa64(revision)+`,`+fields+`}`, nil)
	}
	unchanged := func(t *testing.T, h *connectionsTestHarness, before Account, credentials ...string) {
		t.Helper()
		after, found := store.Account(h.name)
		if !found || after.URL != before.URL || after.TokenEndpoint != before.TokenEndpoint || after.Resource != before.Resource ||
			after.ClientID != before.ClientID || after.ClientSecret != before.ClientSecret || after.BearerToken != before.BearerToken ||
			after.AccessToken != before.AccessToken || after.RefreshToken != before.RefreshToken || after.Revision != before.Revision ||
			after.Label != before.Label || after.IncarnationID != before.IncarnationID {
			t.Fatalf("a refused retarget changed the account:\nbefore=%+v\nafter=%+v", before, after)
		}
		h.assertNoCredentialDialledAt(t, collector, credentials...)
	}
	// On a caller-delegated connection an owner or admin is refused before
	// the body is looked at (403); the service actor gets the retarget rule
	// (400).
	refusal := func(t *testing.T, response *httptest.ResponseRecorder, role string) {
		t.Helper()
		if role == "service" {
			expectControlProblem(t, response, http.StatusBadRequest, controlCodeValidationFailed)
		} else {
			expectControlProblem(t, response, http.StatusForbidden, controlCodeForbidden)
		}
		assertNoConnectionSecrets(t, response.Body.String())
	}

	t.Run("caller-delegated without the client secret", func(t *testing.T) {
		h := newConnectionsTestHarness(t, store)
		created := h.mustCreate()
		h.putToken(platformServiceActorID, "service", created.Revision, testDelegatedListingToken)
		before, _ := store.Account(h.name)
		for name, fields := range map[string]string{
			"whole origin": `"url":"https://collector.example.net/mcp","callerDelegated":{"tokenEndpoint":"https://collector.example.net/token","resource":"https://collector.example.net/mcp"}`,
			// One host can serve several tenants under path prefixes, so a
			// path is a destination too.
			"url path on the same host":  `"url":"https://tools.example.com/hosted/h2/mcp"`,
			"token endpoint path":        `"callerDelegated":{"tokenEndpoint":"https://tools.example.com/hosted/h2/oauth/token"}`,
			"resource with url":          `"url":"https://tools.example.com/other/mcp","callerDelegated":{"resource":"https://tools.example.com/other/mcp"}`,
			"client id stays, url moves": `"url":"https://tools.example.com/hosted/h3/mcp","callerDelegated":{"clientId":"client_delegated_9"}`,
		} {
			for _, actor := range actors {
				t.Run(name+"/"+actor.role, func(t *testing.T) {
					refusal(t, patch(h, actor.user, actor.role, before.Revision, fields), actor.role)
					unchanged(t, h, before, testDelegatedClientSecret, testDelegatedListingToken)
				})
			}
		}
		// The store refuses it under its lock as well, whoever calls it.
		updater, ok := store.(accountConnectionUpdater)
		if !ok {
			t.Fatal("store has no accountConnectionUpdater facet")
		}
		moved, endpoint, resource := "https://collector.example.net/mcp", "https://collector.example.net/token", "https://collector.example.net/mcp"
		if _, err := updater.UpdateAccountConnection(ctx, h.name, before.IncarnationID, before.Revision, accountConnectionUpdate{URL: &moved, TokenEndpoint: &endpoint, Resource: &resource}); err == nil || !isCallerDelegatedValidationError(err) {
			t.Fatalf("store retarget err=%v; want a validation error", err)
		}
		unchanged(t, h, before, testDelegatedClientSecret, testDelegatedListingToken)

		// With the client secret in the same PATCH, the service actor moves
		// the connection; the listing token stays behind and is PUT again.
		fields := `"url":"https://collector.example.net/mcp","callerDelegated":{"tokenEndpoint":"https://collector.example.net/token","resource":"https://collector.example.net/mcp","clientSecret":"` + movedSecret + `"}`
		response := patch(h, platformServiceActorID, "service", before.Revision, fields)
		if strings.Contains(response.Body.String(), movedSecret) {
			t.Fatalf("response leaked the new secret: %s", response.Body)
		}
		movedDTO := decodeTestConnection(t, response, http.StatusOK)
		if movedDTO.URL != "https://collector.example.net/mcp" || movedDTO.TokenSet || movedDTO.Revision <= before.Revision ||
			movedDTO.CallerDelegated == nil || movedDTO.CallerDelegated.TokenEndpoint != "https://collector.example.net/token" {
			t.Fatalf("moved=%+v", movedDTO)
		}
		after, _ := store.Account(h.name)
		if after.ClientSecret != movedSecret || after.BearerToken != "" || after.URL != "https://collector.example.net/mcp" {
			t.Fatalf("stored after move: secret moved=%v bearer kept=%v url=%s", after.ClientSecret == movedSecret, after.BearerToken != "", after.URL)
		}
		h.assertNoCredentialDialledAt(t, collector, testDelegatedClientSecret, testDelegatedListingToken)
	})

	t.Run("plain token connection", func(t *testing.T) {
		h := newConnectionsTestHarness(t, store)
		created := decodeTestConnection(t, h.request("usr_admin", "admin", http.MethodPost, "/control/v1/connections", h.plainBody(), nil), http.StatusCreated)
		const plainToken = "plain-token-0123456789abcdef"
		h.putToken("usr_admin", "admin", created.Revision, plainToken)
		before, _ := store.Account(h.name)
		for _, fields := range []string{`"url":"https://collector.example.net/mcp"`, `"url":"https://tools.example.com/hosted/h2/mcp"`} {
			for _, actor := range actors {
				expectControlProblem(t, patch(h, actor.user, actor.role, before.Revision, fields), http.StatusBadRequest, controlCodeValidationFailed)
				unchanged(t, h, before, plainToken)
			}
		}
		moved := "https://collector.example.net/mcp"
		if _, err := store.(accountConnectionUpdater).UpdateAccountConnection(ctx, h.name, before.IncarnationID, before.Revision, accountConnectionUpdate{URL: &moved}); err == nil || !isCallerDelegatedValidationError(err) {
			t.Fatalf("store retarget err=%v; want a validation error", err)
		}
		unchanged(t, h, before, plainToken)
		// Other edits still apply.
		renamed := decodeTestConnection(t, patch(h, "usr_admin", "admin", before.Revision, `"displayName":"Renamed tools"`), http.StatusOK)
		if renamed.DisplayName != "Renamed tools" || renamed.URL != before.URL || !renamed.TokenSet {
			t.Fatalf("renamed=%+v", renamed)
		}
	})

	t.Run("member credentials connection", func(t *testing.T) {
		h := newConnectionsTestHarness(t, store)
		body := h.createBody(func(b, _ map[string]any) { delete(b, "callerDelegated"); b["memberCredentials"] = true })
		decodeTestConnection(t, h.request("usr_admin", "admin", http.MethodPost, "/control/v1/connections", body, nil), http.StatusCreated)
		before, _ := store.Account(h.name)
		for _, actor := range actors {
			expectControlProblem(t, patch(h, actor.user, actor.role, before.Revision, `"url":"https://collector.example.net/mcp"`), http.StatusBadRequest, controlCodeValidationFailed)
			unchanged(t, h, before)
		}
	})

	t.Run("oauth connection", func(t *testing.T) {
		h := newConnectionsTestHarness(t, store)
		const accessToken, refreshToken, clientSecret = "oauth-access-0123456789", "oauth-refresh-0123456789", "oauth-client-secret-0123456789"
		if err := store.Create(ctx, Account{
			Name: h.name, Label: "Mail", Group: h.group, URL: "https://mail.example.com/mcp", AuthMode: "oauth",
			ClientID: "oauth_client", ClientSecret: clientSecret, AccessToken: accessToken, RefreshToken: refreshToken,
			TokenEndpoint: "https://mail.example.com/oauth/token",
		}); err != nil {
			t.Fatal(err)
		}
		before, _ := store.Account(h.name)
		for _, actor := range actors {
			expectControlProblem(t, patch(h, actor.user, actor.role, before.Revision, `"url":"https://collector.example.net/mcp"`), http.StatusBadRequest, controlCodeValidationFailed)
			unchanged(t, h, before, accessToken, refreshToken, clientSecret)
		}
	})

	t.Run("plain connection without credentials", func(t *testing.T) {
		h := newConnectionsTestHarness(t, store)
		created := decodeTestConnection(t, h.request("usr_admin", "admin", http.MethodPost, "/control/v1/connections", h.plainBody(), nil), http.StatusCreated)
		moved := decodeTestConnection(t, patch(h, "usr_admin", "admin", created.Revision, `"url":"https://tools.example.com/hosted/h2/mcp"`), http.StatusOK)
		if moved.URL != "https://tools.example.com/hosted/h2/mcp" || moved.Revision <= created.Revision {
			t.Fatalf("moved=%+v", moved)
		}
	})
}

func TestControlConnectionsCallerDelegatedWritesServiceOnly(t *testing.T) {
	testControlConnectionsCallerDelegatedWritesServiceOnly(t, newFileConnectionsStore(t))
}

// testControlConnectionsCallerDelegatedWritesServiceOnly: on a hosted Engine
// only the service actor writes a caller-delegated connection (create,
// patch, token, delete); owners and admins may read it.
func testControlConnectionsCallerDelegatedWritesServiceOnly(t *testing.T, store AccountStore) {
	h := newConnectionsTestHarness(t, store)
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}} {
		response := h.request(actor.user, actor.role, http.MethodPost, "/control/v1/connections", h.createBody(nil), nil)
		expectControlProblem(t, response, http.StatusForbidden, controlCodeForbidden)
		assertNoConnectionSecrets(t, response.Body.String())
		if _, found := store.Account(h.name); found {
			t.Fatalf("%s created a caller-delegated connection", actor.role)
		}
	}
	created := h.mustCreate()
	revision := h.putToken(platformServiceActorID, "service", created.Revision, testDelegatedListingToken)
	before, _ := store.Account(h.name)
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}} {
		for _, write := range []struct{ method, path, body string }{
			{http.MethodPost, "/control/v1/connections", h.createBody(nil)},
			{http.MethodPatch, h.path(), `{"revision":` + itoa64(revision) + `,"displayName":"Renamed"}`},
			{http.MethodPatch, h.path(), `{"revision":` + itoa64(revision) + `,"callerDelegated":{"clientSecret":"rotated-secret-0123456789abcdefghijklmn"}}`},
			{http.MethodPut, h.path() + "/token", `{"token":"other-token-0123456789","revision":` + itoa64(revision) + `}`},
			{http.MethodDelete, h.path(), ""},
		} {
			response := h.request(actor.user, actor.role, write.method, write.path, write.body, nil)
			expectControlProblem(t, response, http.StatusForbidden, controlCodeForbidden)
			after, found := store.Account(h.name)
			if !found || after.Revision != before.Revision || after.Label != before.Label || after.ClientSecret != before.ClientSecret || after.BearerToken != before.BearerToken {
				t.Fatalf("%s %s %s changed the connection: %+v", actor.role, write.method, write.path, after)
			}
		}
		read := decodeTestConnection(t, h.request(actor.user, actor.role, http.MethodGet, h.path(), "", nil), http.StatusOK)
		if read.CallerDelegated == nil || read.Revision != before.Revision {
			t.Fatalf("%s read=%+v", actor.role, read)
		}
	}
	// The service actor still writes it.
	renamed := decodeTestConnection(t, h.service(http.MethodPatch, h.path(), `{"revision":`+itoa64(revision)+`,"displayName":"Renamed"}`), http.StatusOK)
	if renamed.DisplayName != "Renamed" {
		t.Fatalf("renamed=%+v", renamed)
	}
	if response := h.service(http.MethodDelete, h.path(), ""); response.Code != http.StatusNoContent {
		t.Fatalf("service delete status=%d body=%s", response.Code, response.Body)
	}
}

// TestControlConnectionsSelfHostedAdminWritesCallerDelegated: a self-hosted
// Engine has no service actor; its one local administrator manages
// caller-delegated connections.
func TestControlConnectionsSelfHostedAdminWritesCallerDelegated(t *testing.T) {
	store := newFileConnectionsStore(t)
	h := newConnectionsTestHarness(t, store)
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(context.Context, Account) ([]mcp.Tool, error) { return nil, nil }
	api := NewConsoleAPI(store, gateway, nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false))
	mux := http.NewServeMux()
	api.Routes(mux)
	local := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer machine-token")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}
	created := decodeTestConnection(t, local(http.MethodPost, "/control/v1/connections", h.createBody(nil)), http.StatusCreated)
	updated := decodeTestConnection(t, local(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`), http.StatusOK)
	renamed := decodeTestConnection(t, local(http.MethodPatch, h.path(), `{"revision":`+itoa64(updated.Revision)+`,"displayName":"Renamed"}`), http.StatusOK)
	if renamed.DisplayName != "Renamed" || renamed.CallerDelegated == nil {
		t.Fatalf("renamed=%+v", renamed)
	}
	if response := local(http.MethodDelete, h.path(), ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body)
	}
}

func TestControlMetaListsCallerDelegatedConnections(t *testing.T) {
	h := newConnectionsTestHarness(t, newFileConnectionsStore(t))
	for _, actor := range []struct{ user, role string }{{platformServiceActorID, "service"}, {"usr_owner", "owner"}} {
		response := h.request(actor.user, actor.role, http.MethodGet, "/control/v1/meta", "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("meta status=%d body=%s", response.Code, response.Body)
		}
		var meta struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &meta); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, capability := range meta.Capabilities {
			found = found || capability == "caller-delegated-connections"
		}
		if !found {
			t.Fatalf("%s meta capabilities=%v; want caller-delegated-connections", actor.role, meta.Capabilities)
		}
	}
}

func itoa64(value int64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// cleanupPgConnectionFixture removes one test account and folder so rows
// written under this test's cipher never reach a test holding another key.
func cleanupPgConnectionFixture(t *testing.T, pg *PgStore, account, folderLabel string) {
	t.Helper()
	ctx := context.Background()
	if account != "" {
		if _, err := pg.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, account); err != nil {
			t.Errorf("cleanup account %s: %v", account, err)
		}
	}
	if folderLabel != "" {
		if _, err := pg.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE label=$1 AND NOT EXISTS (SELECT 1 FROM narthex_accounts WHERE connection_namespace_id=narthex_connection_namespaces.id)`, folderLabel); err != nil {
			t.Errorf("cleanup folder %s: %v", folderLabel, err)
		}
	}
}

// TestControlConnectionsServiceAllowlist pins the service actor's closed set
// on this group and on artifact erasure: exactly the listed method and path
// shapes pass the assertion boundary; everything else is 401
// actor_assertion_invalid before any handler runs.
func TestControlConnectionsServiceAllowlist(t *testing.T) {
	h := newConnectionsTestHarness(t, newFileConnectionsStore(t))
	for _, allowed := range []struct{ method, path string }{
		{http.MethodPost, "/control/v1/connections"},
		{http.MethodGet, h.path()},
		{http.MethodPatch, h.path()},
		{http.MethodDelete, h.path()},
		{http.MethodPut, h.path() + "/token"},
		{http.MethodDelete, "/control/v1/library/artifacts/libart_unknown"},
	} {
		if response := h.service(allowed.method, allowed.path, `{}`); response.Code == http.StatusUnauthorized {
			t.Fatalf("service %s %s was refused at the assertion boundary: %s", allowed.method, allowed.path, response.Body)
		}
	}
	for _, denied := range []struct{ method, path string }{
		{http.MethodGet, "/control/v1/connections"},
		{http.MethodPut, "/control/v1/connections"},
		{http.MethodPost, h.path()},
		{http.MethodPut, h.path()},
		{http.MethodGet, h.path() + "/token"},
		{http.MethodDelete, h.path() + "/token"},
		{http.MethodPost, h.path() + "/oauth"},
		{http.MethodGet, h.path() + "/tools"},
		{http.MethodPatch, "/control/v1/connections/bad%20name"},
		{http.MethodDelete, "/control/v1/library/artifacts"},
		{http.MethodDelete, "/control/v1/library/artifacts/libart_unknown/versions/libver_unknown"},
	} {
		expectControlProblem(t, h.service(denied.method, denied.path, `{}`), http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	}
}
