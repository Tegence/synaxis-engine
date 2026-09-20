package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newHostedControlConsole is the /control/v1 counterpart of
// hostedNamespaceConsole: one delegated Team folder, a hosted actor boundary,
// and any extra ConsoleOption the test needs (version/generation reporting).
func newHostedControlConsole(t *testing.T, options ...ConsoleOption) (*http.ServeMux, *FileStore, ed25519.PrivateKey, time.Time, ConnectionNamespace) {
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
	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	gateway.SetAudit(store)
	api := NewConsoleAPI(
		store, gateway, nil, "local-password", "local-secret", "https://engine.example", "https://app.example", "",
		append([]ConsoleOption{WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier)}, options...)...,
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, store, key, now, team
}

func controlRequest(t *testing.T, mux *http.ServeMux, key ed25519.PrivateKey, now time.Time, userID, role, method, requestPath, body string) *httptest.ResponseRecorder {
	t.Helper()
	return hostedNamespaceRequestWithHeaders(t, mux, key, now, userID, role, method, requestPath, body, nil)
}

func decodeControlProblem(t *testing.T, response *httptest.ResponseRecorder) controlProblem {
	t.Helper()
	if got := response.Header().Get("Content-Type"); got != controlProblemContentType {
		t.Fatalf("problem Content-Type=%q body=%s", got, response.Body)
	}
	var problem controlProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v body=%s", err, response.Body)
	}
	if problem.Type != "about:blank" || problem.Status != response.Code || problem.RequestID == "" || problem.RequestID != response.Header().Get(controlRequestIDHeader) {
		t.Fatalf("problem envelope=%+v headers=%v", problem, response.Header())
	}
	return problem
}

func expectControlProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) controlProblem {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d body=%s; want %d", response.Code, response.Body, status)
	}
	problem := decodeControlProblem(t, response)
	if problem.Code != code {
		t.Fatalf("problem=%+v; want code %q", problem, code)
	}
	return problem
}

func decodeControlClient(t *testing.T, response *httptest.ResponseRecorder, want int) mcpClientDTO {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status=%d body=%s; want %d", response.Code, response.Body, want)
	}
	if response.Header().Get(controlRequestIDHeader) == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("control response missing envelope headers: %v", response.Header())
	}
	var dto mcpClientDTO
	if err := json.Unmarshal(response.Body.Bytes(), &dto); err != nil {
		t.Fatalf("decode client: %v body=%s", err, response.Body)
	}
	return dto
}

func TestControlV1MetaReportsContractVersionAndCapabilities(t *testing.T) {
	mux, _, key, now, _ := newHostedControlConsole(t, WithEngineVersion(" 2026.09.1 "), WithProvisionGeneration(7))

	for _, actor := range []struct{ user, role string }{
		{"usr_viewer", "viewer"}, {"usr_operator", "operator"}, {"usr_owner", "owner"}, {platformServiceActorID, "service"},
	} {
		response := hostedNamespaceRequestWithHeaders(t, mux, key, now, actor.user, actor.role, http.MethodGet, "/control/v1/meta", "", map[string]string{
			controlRequestIDHeader: "req-" + actor.role + ".1",
		})
		if response.Code != http.StatusOK {
			t.Fatalf("%s meta status=%d body=%s", actor.role, response.Code, response.Body)
		}
		if got := response.Header().Get(controlRequestIDHeader); got != "req-"+actor.role+".1" {
			t.Fatalf("%s request id echo=%q", actor.role, got)
		}
		var meta controlMetaDTO
		if err := json.Unmarshal(response.Body.Bytes(), &meta); err != nil {
			t.Fatal(err)
		}
		if meta.ControlContract != "v1" || meta.EngineVersion != "2026.09.1" || meta.ProvisionGeneration != 7 ||
			strings.Join(meta.Capabilities, ",") != "mcp-clients,profile-binding,activation-snapshot,run-correlations,library-artifacts,connection-evidence" {
			t.Fatalf("%s meta=%+v", actor.role, meta)
		}
	}

	// A malformed caller ID is replaced rather than echoed, and every
	// response carries one even when the caller sent none.
	response := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/meta", "", map[string]string{
		controlRequestIDHeader: "bad id\r\nX-Injected: 1",
	})
	if got := response.Header().Get(controlRequestIDHeader); !strings.HasPrefix(got, "req_") || len(response.Header().Values("X-Injected")) != 0 {
		t.Fatalf("unsafe request id was echoed: %v", response.Header())
	}
	response = controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/meta", "")
	if !strings.HasPrefix(response.Header().Get(controlRequestIDHeader), "req_") {
		t.Fatalf("generated request id missing: %v", response.Header())
	}

	// Method errors are problem details too, using the capability code the
	// contract reserves for unimplemented routes/methods.
	response = controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/meta", "{}")
	expectControlProblem(t, response, http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable)
}

func TestControlV1MetaDefaultsForSelfHostedEngine(t *testing.T) {
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := NewConsoleAPI(store, NewGateway(store, nil), nil, "pw", "secret", "https://engine.example", "https://app.example", "", WithAdminToken("machine-token"))
	mux := http.NewServeMux()
	api.Routes(mux)

	request := httptest.NewRequest(http.MethodGet, "/control/v1/meta", nil)
	request.Header.Set("Authorization", "Bearer machine-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	var meta controlMetaDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &meta) != nil || meta.EngineVersion != "dev" || meta.ProvisionGeneration != 0 {
		t.Fatalf("self-hosted meta status=%d body=%s", response.Code, response.Body)
	}

	request = httptest.NewRequest(http.MethodGet, "/control/v1/meta", nil)
	request.Header.Set("Authorization", "Bearer wrong-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	expectControlProblem(t, response, http.StatusUnauthorized, controlCodeUnauthorized)
}

func TestControlV1AuthenticationFailuresAreProblemDetails(t *testing.T) {
	mux, _, key, now, _ := newHostedControlConsole(t)

	// Wrong machine token: credential code, indistinguishable 401 title.
	body := []byte("")
	claims := actorClaimsForTest(now, http.MethodGet, "/control/v1/mcp-clients", body)
	claims.UserID, claims.Role = "usr_owner", "owner"
	request := actorRequest(http.MethodGet, "/control/v1/mcp-clients", body, signActorAssertionForTest(t, key, claims))
	request.Header.Set("Authorization", "Bearer not-the-machine-token")
	request.Header.Set(controlRequestIDHeader, "req-cred")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	problem := expectControlProblem(t, response, http.StatusUnauthorized, controlCodeUnauthorized)
	if problem.Title != "unauthorized" || problem.RequestID != "req-cred" {
		t.Fatalf("credential problem=%+v", problem)
	}

	// Right token, tampered assertion: assertion code, same title.
	assertion := signActorAssertionForTest(t, key, claims)
	tampered := assertion[:len(assertion)-1] + map[bool]string{true: "B", false: "A"}[assertion[len(assertion)-1] == 'A']
	request = actorRequest(http.MethodGet, "/control/v1/mcp-clients", body, tampered)
	request.Header.Set("Authorization", "Bearer machine-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	problem = expectControlProblem(t, response, http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	if problem.Title != "unauthorized" || strings.Contains(strings.ToLower(response.Body.String()), "assertion\"") {
		t.Fatalf("assertion problem leaked detail: %+v body=%s", problem, response.Body)
	}

	// An assertion signed for the /api twin of the route does not authorize
	// the /control/v1 route.
	crossClaims := actorClaimsForTest(now, http.MethodGet, "/api/mcp-clients", body)
	crossClaims.UserID, crossClaims.Role = "usr_owner", "owner"
	request = actorRequest(http.MethodGet, "/control/v1/mcp-clients", body, signActorAssertionForTest(t, key, crossClaims))
	request.Header.Set("Authorization", "Bearer machine-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	expectControlProblem(t, response, http.StatusUnauthorized, controlCodeActorAssertionInvalid)

	// A verified viewer is authenticated but not permitted.
	response = controlRequest(t, mux, key, now, "usr_viewer", "viewer", http.MethodGet, "/control/v1/mcp-clients", "")
	expectControlProblem(t, response, http.StatusForbidden, controlCodeForbidden)

	// The service principal's v1 allowlist is closed: listing or registering
	// clients is rejected at the assertion boundary, not by a role check.
	for _, denied := range []struct{ method, path, body string }{
		{http.MethodGet, "/control/v1/mcp-clients", ""},
		{http.MethodPost, "/control/v1/mcp-clients", `{"name":"Service Codex","subject":"usr_operator"}`},
		{http.MethodPost, "/control/v1/mcp-clients/mcpcli_x/revoke", `{"revision":1}`},
	} {
		response = controlRequest(t, mux, key, now, platformServiceActorID, "service", denied.method, denied.path, denied.body)
		expectControlProblem(t, response, http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	}

	// A query string is never part of a signed control path.
	response = controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients?x=1", "")
	expectControlProblem(t, response, http.StatusUnauthorized, controlCodeActorAssertionInvalid)
}

func TestControlV1MCPClientLifecycleConvergesOnRetries(t *testing.T) {
	mux, store, key, now, team := newHostedControlConsole(t)
	ctx := context.Background()
	createBody := `{"name":"Codex","slug":"codex","subject":"usr_operator","connectionNamespaceIds":["` + team.ID + `"]}`

	created := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", createBody), http.StatusCreated)
	if created.Slug != "codex" || created.Subject != "usr_operator" || created.Revision != 1 || created.AgentProfileBinding != nil {
		t.Fatalf("created=%+v", created)
	}
	if got := controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients/"+created.ID, ""); got.Code != http.StatusOK {
		t.Fatalf("read=%d body=%s", got.Code, got.Body)
	}

	// Exact replay converges on the stored registration with 200 instead of
	// registering a suffixed second client.
	replayed := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", createBody), http.StatusOK)
	if replayed.ID != created.ID {
		t.Fatalf("replay created a second client: %+v vs %+v", replayed, created)
	}
	if clients, err := store.MCPClients(ctx); err != nil || len(clients) != 1 {
		t.Fatalf("clients=%d err=%v; want exactly one", len(clients), err)
	}
	// The same slug with a different definition is a conflict, not a
	// silently suffixed registration.
	response := controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Other","slug":"codex","subject":"usr_operator"}`)
	expectControlProblem(t, response, http.StatusConflict, controlCodeAlreadyExists)
	// The legacy /api surface keeps suffixing so self-hosted consoles are
	// unchanged.
	legacy := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients", `{"name":"Other","slug":"codex","subject":"usr_operator"}`)
	var legacyClient mcpClientDTO
	if legacy.Code != http.StatusCreated || json.Unmarshal(legacy.Body.Bytes(), &legacyClient) != nil || legacyClient.Slug != "codex-2" {
		t.Fatalf("legacy create=%d body=%s", legacy.Code, legacy.Body)
	}

	// Validation and lookup failures carry registry codes.
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":`), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients/mcpcli_missing", ""), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Not mine","subject":"usr_owner"}`), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Renamed","revision":9}`), http.StatusConflict, controlCodeRevisionMismatch)

	renamed := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Renamed","revision":1}`), http.StatusOK)
	if renamed.Name != "Renamed" || renamed.Revision != 2 {
		t.Fatalf("renamed=%+v", renamed)
	}
	scoped := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, "/control/v1/mcp-clients/"+created.ID+"/namespaces", `{"revision":2,"connectionNamespaceIds":[]}`), http.StatusOK)
	if len(scoped.ConnectionNamespaceIDs) != 0 || scoped.Revision != 3 {
		t.Fatalf("scoped=%+v", scoped)
	}
	reset := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+created.ID+"/oauth-client/reset", `{"revision":3}`), http.StatusOK)
	if reset.Revision != 4 || reset.OAuthBound {
		t.Fatalf("reset=%+v", reset)
	}

	revoked := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+created.ID+"/revoke", `{"revision":4}`), http.StatusOK)
	if revoked.Status != MCPClientStatusRevoked || revoked.Revision != 5 {
		t.Fatalf("revoked=%+v", revoked)
	}
	// A retried revoke with the stale revision converges on the terminal
	// record under v1; the legacy surface keeps its revision fence.
	again := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+created.ID+"/revoke", `{"revision":4}`), http.StatusOK)
	if again.Status != MCPClientStatusRevoked || again.Revision != 5 {
		t.Fatalf("second revoke=%+v", again)
	}
	if legacy := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+created.ID+"/revoke", `{"revision":4}`); legacy.Code != http.StatusConflict {
		t.Fatalf("legacy second revoke=%d body=%s; want 409", legacy.Code, legacy.Body)
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Zombie","revision":5}`), http.StatusConflict, controlCodeClientRevoked)

	// The list is ACL filtered exactly like /api.
	list := controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/control/v1/mcp-clients", "")
	var listed []mcpClientDTO
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &listed) != nil || len(listed) != 2 {
		t.Fatalf("operator list=%d body=%s", list.Code, list.Body)
	}
}

func TestControlV1IdempotencyKeyReplaysFirstResultAndDetectsConflicts(t *testing.T) {
	mux, store, key, now, team := newHostedControlConsole(t)
	ctx := context.Background()
	body := `{"name":"Keyed Codex","subject":"usr_operator","connectionNamespaceIds":["` + team.ID + `"]}`
	keyed := func(user, role, method, requestPath, body, idempotencyKey string) *httptest.ResponseRecorder {
		return hostedNamespaceRequestWithHeaders(t, mux, key, now, user, role, method, requestPath, body, map[string]string{controlIdempotencyKeyHeader: idempotencyKey})
	}

	first := keyed("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", body, "create-1")
	created := decodeControlClient(t, first, http.StatusCreated)
	if first.Header().Get(controlIdempotentReplayHeader) != "" {
		t.Fatalf("first result marked as replay: %v", first.Header())
	}
	replay := keyed("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", body, "create-1")
	replayed := decodeControlClient(t, replay, http.StatusCreated)
	if replay.Header().Get(controlIdempotentReplayHeader) != "true" || replayed.ID != created.ID {
		t.Fatalf("replay=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body)
	}
	if clients, err := store.MCPClients(ctx); err != nil || len(clients) != 1 {
		t.Fatalf("keyed retry registered %d clients err=%v; want 1", len(clients), err)
	}
	// Same key, different body: conflict. Same key and body, different
	// principal: conflict rather than replaying another member's result.
	expectControlProblem(t, keyed("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Different","subject":"usr_operator"}`, "create-1"), http.StatusConflict, controlCodeIdempotencyKeyConflict)
	expectControlProblem(t, keyed("usr_admin", "admin", http.MethodPost, "/control/v1/mcp-clients", body, "create-1"), http.StatusConflict, controlCodeIdempotencyKeyConflict)
	// Same key on another resource path is a distinct identity.
	if response := keyed("usr_owner", "owner", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Keyed rename","revision":1}`, "create-1"); response.Code != http.StatusOK {
		t.Fatalf("key reuse on another path=%d body=%s", response.Code, response.Body)
	}
	// Failed attempts are never pinned: the stale-revision conflict is not
	// replayed once the caller fixes the revision.
	expectControlProblem(t, keyed("usr_owner", "owner", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Stale","revision":1}`, "rename-2"), http.StatusConflict, controlCodeRevisionMismatch)
	if response := keyed("usr_owner", "owner", http.MethodPatch, "/control/v1/mcp-clients/"+created.ID, `{"name":"Stale","revision":2}`, "rename-2"); response.Code != http.StatusOK || response.Header().Get(controlIdempotentReplayHeader) != "" {
		t.Fatalf("fixed retry after failed keyed attempt=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	// Key validation and GET handling.
	expectControlProblem(t, keyed("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", body, strings.Repeat("k", maxControlIdempotencyKeyBytes+1)), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, keyed("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", body, "has space"), http.StatusBadRequest, controlCodeValidationFailed)
	if response := keyed("usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients", "", "create-1"); response.Code != http.StatusOK || response.Header().Get(controlIdempotentReplayHeader) != "" {
		t.Fatalf("GET with key=%d headers=%v", response.Code, response.Header())
	}

	// Records persist across a reload, hold the same DTO the caller received,
	// and expire after the horizon.
	record, found, err := store.ControlIdempotencyRecord(ctx, "create-1", "/control/v1/mcp-clients", time.Now().UTC())
	if err != nil || !found || record.Status != http.StatusCreated || !strings.Contains(string(record.Body), created.ID) || record.ActorRef == "" || record.ExpiresAt.Sub(record.CreatedAt) != controlIdempotencyHorizon {
		t.Fatalf("stored record=%+v found=%t err=%v", record, found, err)
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, "create-1", "/control/v1/mcp-clients", record.ExpiresAt.Add(time.Second)); err != nil || found {
		t.Fatalf("expired record still served: found=%t err=%v", found, err)
	}
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := reloaded.ControlIdempotencyRecord(ctx, "create-1", "/control/v1/mcp-clients", time.Now().UTC()); err != nil || !found {
		t.Fatalf("record did not survive reload: found=%t err=%v", found, err)
	}
	// Storing again under an existing identity keeps the first record.
	winner, stored, err := reloaded.StoreControlIdempotencyRecord(ctx, ControlIdempotencyRecord{
		Key: "create-1", ResourcePath: "/control/v1/mcp-clients", ActorRef: "other", BodyDigest: strings.Repeat("a", 64),
		Status: http.StatusOK, Body: []byte("{}"), CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil || stored || winner.ActorRef == "other" {
		t.Fatalf("duplicate store winner=%+v stored=%t err=%v", winner, stored, err)
	}
	// Expired identities are pruned on the next store so a key can be reused.
	expiredKey := ControlIdempotencyRecord{
		Key: "expired", ResourcePath: "/control/v1/mcp-clients", ActorRef: "a", BodyDigest: strings.Repeat("b", 64),
		Status: http.StatusOK, Body: []byte("{}"), CreatedAt: time.Now().UTC().Add(-2 * controlIdempotencyHorizon), ExpiresAt: time.Now().UTC().Add(-controlIdempotencyHorizon),
	}
	if _, stored, err := reloaded.StoreControlIdempotencyRecord(ctx, expiredKey); err != nil || !stored {
		t.Fatalf("store expired fixture stored=%t err=%v", stored, err)
	}
	fresh := expiredKey
	fresh.ActorRef, fresh.CreatedAt, fresh.ExpiresAt = "b", time.Now().UTC(), time.Now().UTC().Add(time.Hour)
	if winner, stored, err := reloaded.StoreControlIdempotencyRecord(ctx, fresh); err != nil || !stored || winner.ActorRef != "b" {
		t.Fatalf("expired identity was not reusable: winner=%+v stored=%t err=%v", winner, stored, err)
	}
}

func TestControlV1ProfileBindingIsOpaqueRevisionFencedAndRotatesEpoch(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	created := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Bound Codex","subject":"usr_operator"}`), http.StatusCreated)
	path := "/control/v1/mcp-clients/" + created.ID + "/profile-binding"
	digestA := libraryDigest("policy A")
	digestB := libraryDigest("policy B")
	storedAt := func() MCPClient {
		t.Helper()
		client, ok := store.MCPClient(ctx, created.ID)
		if !ok {
			t.Fatal("client missing")
		}
		return client
	}
	initial := storedAt()

	// Only owner/admin/service may install the policy reference — an
	// operator managing its own client cannot choose what it runs under.
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, path, `{"revision":1,"profileId":"aap_1","profileRevision":1,"policyDigest":"`+digestA+`"}`), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_viewer", "viewer", http.MethodPut, path, `{"revision":1,"profileId":"aap_1","profileRevision":1,"policyDigest":"`+digestA+`"}`), http.StatusForbidden, controlCodeForbidden)
	for _, invalid := range []string{
		`{"revision":1,"profileId":"aap_1","profileRevision":1,"policyDigest":"not-a-digest"}`,
		`{"revision":1,"profileId":"aap 1","profileRevision":1,"policyDigest":"` + digestA + `"}`,
		`{"revision":1,"profileId":"aap_1","profileRevision":0,"policyDigest":"` + digestA + `"}`,
		`{"profileId":"aap_1","profileRevision":1,"policyDigest":"` + digestA + `"}`,
	} {
		expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, invalid), http.StatusBadRequest, controlCodeValidationFailed)
	}
	if after := storedAt(); after.Revision != 1 || after.AgentProfileBinding != nil {
		t.Fatalf("rejected binds changed the client: %+v", after)
	}

	bound := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":1,"profileId":"aap_1","profileRevision":1,"policyDigest":"`+digestA+`"}`), http.StatusOK)
	if bound.Revision != 2 || bound.AgentProfileBinding == nil || bound.AgentProfileBinding.ProfileID != "aap_1" || bound.AgentProfileBinding.ProfileRevision != 1 || bound.AgentProfileBinding.PolicyDigest != digestA || bound.AgentProfileBinding.BoundAt == "" {
		t.Fatalf("bound=%+v", bound)
	}
	afterBind := storedAt()
	if afterBind.Epoch == initial.Epoch || afterBind.Revision != 2 {
		t.Fatalf("bind did not rotate epoch: before=%+v after=%+v", initial, afterBind)
	}
	// The /api DTO exposes the same opaque reference.
	legacy := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/api/mcp-clients/"+created.ID, "")
	var legacyDTO mcpClientDTO
	if legacy.Code != http.StatusOK || json.Unmarshal(legacy.Body.Bytes(), &legacyDTO) != nil || legacyDTO.AgentProfileBinding == nil || legacyDTO.AgentProfileBinding.PolicyDigest != digestA {
		t.Fatalf("legacy DTO=%d body=%s", legacy.Code, legacy.Body)
	}

	// Identical replay is a no-op: same revision, same epoch.
	same := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":2,"profileId":"aap_1","profileRevision":1,"policyDigest":"`+digestA+`"}`), http.StatusOK)
	if same.Revision != 2 || storedAt().Epoch != afterBind.Epoch {
		t.Fatalf("identical rebind rotated state: %+v", same)
	}
	// A new revision of the same profile is not a conflict but does rotate.
	bumped := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":2,"profileId":"aap_1","profileRevision":2,"policyDigest":"`+digestB+`"}`), http.StatusOK)
	if bumped.Revision != 3 || bumped.AgentProfileBinding.ProfileRevision != 2 || storedAt().Epoch == afterBind.Epoch {
		t.Fatalf("profile revision bump=%+v", bumped)
	}
	// A different profile requires replace; a stale revision with replace is
	// still fenced.
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":3,"profileId":"aap_2","profileRevision":1,"policyDigest":"`+digestB+`"}`), http.StatusConflict, controlCodeProfileBindingConflict)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":2,"profileId":"aap_2","profileRevision":1,"policyDigest":"`+digestB+`","replace":true}`), http.StatusConflict, controlCodeRevisionMismatch)
	replaced := decodeControlClient(t, controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPut, path, `{"revision":3,"profileId":"aap_2","profileRevision":1,"policyDigest":"`+digestB+`","replace":true}`), http.StatusOK)
	if replaced.Revision != 4 || replaced.AgentProfileBinding.ProfileID != "aap_2" {
		t.Fatalf("replaced=%+v", replaced)
	}

	// Unbind rotates once and then converges.
	beforeUnbind := storedAt()
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodDelete, path, `{"revision":4}`), http.StatusForbidden, controlCodeForbidden)
	unbound := decodeControlClient(t, controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodDelete, path, `{"revision":4}`), http.StatusOK)
	if unbound.Revision != 5 || unbound.AgentProfileBinding != nil || storedAt().Epoch == beforeUnbind.Epoch {
		t.Fatalf("unbound=%+v", unbound)
	}
	again := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_admin", "admin", http.MethodDelete, path, `{"revision":5}`), http.StatusOK)
	if again.Revision != 5 || again.AgentProfileBinding != nil {
		t.Fatalf("second unbind=%+v", again)
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, path, `{"revision":5}`), http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable)

	// A revoked client rejects binds with the terminal-state code.
	if response := controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+created.ID+"/revoke", `{"revision":5}`); response.Code != http.StatusOK {
		t.Fatalf("revoke=%d body=%s", response.Code, response.Body)
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPut, path, `{"revision":6,"profileId":"aap_1","profileRevision":1,"policyDigest":"`+digestA+`"}`), http.StatusConflict, controlCodeClientRevoked)
}

func TestControlV1ActivationSnapshotOmitsInstructionBodies(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	created := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Snapshot Codex","subject":"usr_operator"}`), http.StatusCreated)
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: created.ID,
		Mode: LibraryBindingModePin, PinnedVersionID: version.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := "/control/v1/mcp-clients/" + created.ID + "/activation-snapshot"

	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, path, ""), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients/mcpcli_missing/activation-snapshot", ""), http.StatusNotFound, controlCodeNotFound)
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}, {platformServiceActorID, "service"}} {
		response := controlRequest(t, mux, key, now, actor.user, actor.role, http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s snapshot=%d body=%s", actor.role, response.Code, response.Body)
		}
		var snapshot controlActivationSnapshotDTO
		if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.ContractVersion != LibrarySkillActivationContractVersion || snapshot.BundleDigest != bundle.BundleDigest || len(snapshot.Skills) != 1 ||
			snapshot.Skills[0].SkillID != skill.ID || snapshot.Skills[0].SkillSlug != skill.Slug || snapshot.Skills[0].VersionID != version.ID ||
			snapshot.Skills[0].Version != version.Version || snapshot.Skills[0].ContentDigest != version.Digest || snapshot.Skills[0].BindingID != binding.ID {
			t.Fatalf("%s snapshot=%+v bundle=%+v", actor.role, snapshot, bundle)
		}
		body := response.Body.String()
		if strings.Contains(body, "instructions") || strings.Contains(body, "Inspect the incident") || strings.Contains(body, "authorityNotice") || strings.Contains(body, "capabilityCeiling") {
			t.Fatalf("snapshot leaked bundle content: %s", body)
		}
	}
}

func TestControlV1RunCorrelationFeedIsSanitizedAndPaginated(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, store)
	base := time.Now().UTC().Truncate(time.Millisecond)
	total := controlRunCorrelationPageLimit + 1
	for i := 0; i < total; i++ {
		at := base.Add(time.Duration(i) * time.Millisecond)
		raw := runCorrelationBody(t, fixture, "run_"+strconv.Itoa(i), "greq_"+strconv.Itoa(i), map[bool]string{true: "exec_" + strconv.Itoa(i), false: ""}[i%2 == 0],
			runCorrelationNonce(byte(i)), at.Add(5*time.Minute).Format(time.RFC3339Nano))
		if _, replayed, err := store.RecordLibraryRunCorrelation(ctx, fixture.client, raw, at); err != nil || replayed {
			t.Fatalf("record %d: replayed=%t err=%v", i, replayed, err)
		}
	}

	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/control/v1/run-correlations", ""), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_viewer", "viewer", http.MethodGet, "/control/v1/run-correlations", ""), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/run-correlations", "", map[string]string{controlCursorHeader: "not-a-cursor"}), http.StatusBadRequest, controlCodeValidationFailed)

	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {platformServiceActorID, "service"}} {
		first := controlRequest(t, mux, key, now, actor.user, actor.role, http.MethodGet, "/control/v1/run-correlations", "")
		if first.Code != http.StatusOK {
			t.Fatalf("%s feed=%d body=%s", actor.role, first.Code, first.Body)
		}
		var page []controlRunCorrelationDTO
		if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		cursor := first.Header().Get(controlCursorHeader)
		if len(page) != controlRunCorrelationPageLimit || cursor == "" || page[0].RunID != "run_"+strconv.Itoa(total-1) || page[len(page)-1].RunID != "run_1" {
			t.Fatalf("%s first page len=%d cursor=%q first=%+v", actor.role, len(page), cursor, page[0])
		}
		wantExecutionAttested := (total-1)%2 == 0
		if page[0].ClientID != fixture.client.ID || page[0].ClientEpoch != fixture.client.Epoch || page[0].BundleDigest != fixture.bundle.BundleDigest ||
			page[0].GatewayRequestID != "greq_"+strconv.Itoa(total-1) || page[0].ExecutionAttested != wantExecutionAttested || page[0].CreatedAt == "" || !strings.HasPrefix(page[0].CorrelationID, "lrc_") {
			t.Fatalf("%s feed record=%+v", actor.role, page[0])
		}
		var rawPage []map[string]any
		if err := json.Unmarshal(first.Body.Bytes(), &rawPage); err != nil {
			t.Fatal(err)
		}
		for field := range rawPage[0] {
			switch field {
			case "correlationId", "clientId", "clientEpoch", "runId", "gatewayRequestId", "bundleDigest", "executionAttested", "createdAt":
			default:
				t.Fatalf("%s feed exposed field %q", actor.role, field)
			}
		}
		second := hostedNamespaceRequestWithHeaders(t, mux, key, now, actor.user, actor.role, http.MethodGet, "/control/v1/run-correlations", "", map[string]string{controlCursorHeader: cursor})
		var rest []controlRunCorrelationDTO
		if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &rest) != nil || len(rest) != 1 || rest[0].RunID != "run_0" || second.Header().Get(controlCursorHeader) != "" {
			t.Fatalf("%s second page=%d body=%s headers=%v", actor.role, second.Code, second.Body, second.Header())
		}
	}
}

func TestControlV1RequestIDIsNotAffectedByBase64Padding(t *testing.T) {
	// Cursor tokens are raw base64url; a padded or otherwise non-canonical
	// token is rejected rather than silently normalized.
	cursor := encodeControlRunCorrelationCursor(LibraryRunCorrelationCursor{CreatedAt: time.Unix(0, 1234).UTC(), ID: "lrc_abc"})
	decoded, err := decodeControlRunCorrelationCursor(cursor)
	if err != nil || decoded.ID != "lrc_abc" || decoded.CreatedAt.UnixNano() != 1234 {
		t.Fatalf("cursor round trip=%+v err=%v", decoded, err)
	}
	for _, bad := range []string{cursor + "=", base64.RawURLEncoding.EncodeToString([]byte("nonsense")), base64.RawURLEncoding.EncodeToString([]byte("12:")), base64.RawURLEncoding.EncodeToString([]byte("01:x"))} {
		if _, err := decodeControlRunCorrelationCursor(bad); err == nil {
			t.Fatalf("cursor %q was accepted", bad)
		}
	}
}
