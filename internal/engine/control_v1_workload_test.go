package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"narthex/backend/internal/oauthas"
)

// workloadConsole is a hosted Engine wired the way cmd/engine wires it: the
// console with the Platform actor boundary and the OAuth server's
// IssueResourceAccess, and /mcp/clients/{slug} behind RequireAuth with the
// gateway's epoch lookup and client-resource authorizer.
type workloadConsole struct {
	t       *testing.T
	mux     *http.ServeMux
	store   *FileStore
	gateway *Gateway
	key     ed25519.PrivateKey
	now     time.Time
	team    ConnectionNamespace
	ops     ConnectionNamespace
}

func newWorkloadConsole(t *testing.T) *workloadConsole {
	t.Helper()
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	gateway.SetAudit(store)
	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Operations", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "team_notion", URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team-secret",
		ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatal(err)
	}
	gateway.Aggregate(ctx)

	const issuer = "https://engine.example"
	authorization := oauthas.New(issuer, "pw", "workload-console-secret")
	if err := authorization.ConfigureTokenGeneration(ctx, store); err != nil {
		t.Fatal(err)
	}
	authorization.SetEpochLookup(func(path string) (string, bool) {
		if slug, ok := strings.CutPrefix(path, "/mcp/clients/"); ok && slug != "" && !strings.Contains(slug, "/") {
			return gateway.MCPClientEpoch(slug)
		}
		return "", false
	})
	authorization.SetClientResourceAuthorizer(gateway.MCPClientAllowsOAuthClient)
	authorization.SetHostedConsentAuthorizer(gateway.AuthorizeMCPConsent)
	gateway.SetTokenRevoker(authorization.RevokeResource)
	gateway.SetTokenEpochRevoker(authorization.RevokeResourceAtEpoch)

	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(
		store, gateway, nil, "local-password", "local-secret", issuer, "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier),
		WithWorkloadTokenIssuer(authorization.IssueResourceAccess),
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	mux.Handle("/mcp/clients/{slug}", authorization.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := gateway.MCPClientHandler(r.PathValue("slug"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		LimitMCPRequestBody(handler).ServeHTTP(w, r)
	})))
	return &workloadConsole{t: t, mux: mux, store: store, gateway: gateway, key: key, now: now, team: team, ops: ops}
}

func (h *workloadConsole) control(user, role, method, requestPath, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	return controlRequest(h.t, h.mux, h.key, h.now, user, role, method, requestPath, body)
}

func (h *workloadConsole) createWorkload(name, slug, subject string, namespaceIDs ...string) mcpClientDTO {
	h.t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": name, "slug": slug, "subject": subject, "kind": "workload", "connectionNamespaceIds": append([]string{}, namespaceIDs...),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	created := decodeControlClient(h.t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", string(body)), http.StatusCreated)
	if created.Kind != MCPClientKindWorkload || created.OAuthBound {
		h.t.Fatalf("created workload client=%+v", created)
	}
	return created
}

func (h *workloadConsole) stored(id string) MCPClient {
	h.t.Helper()
	client, ok := h.store.MCPClient(context.Background(), id)
	if !ok {
		h.t.Fatalf("client %s missing", id)
	}
	return client
}

func workloadTokenPath(clientID string) string {
	return "/control/v1/mcp-clients/" + clientID + "/workload-token"
}

func (h *workloadConsole) mint(clientID string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.control(platformServiceActorID, "service", http.MethodPost, workloadTokenPath(clientID), "{}")
}

func (h *workloadConsole) mintToken(clientID string) controlWorkloadTokenDTO {
	h.t.Helper()
	response := h.mint(clientID)
	if response.Code != http.StatusOK {
		h.t.Fatalf("workload token=%d body=%s", response.Code, response.Body)
	}
	var token controlWorkloadTokenDTO
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil {
		h.t.Fatal(err)
	}
	return token
}

// mcpInitialize sends a real MCP initialize request through RequireAuth and
// the projected client endpoint.
func (h *workloadConsole) mcpInitialize(token, slug string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+slug, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cloud-runner-test","version":"1.0.0"}}}`,
	))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	h.mux.ServeHTTP(response, request)
	return response
}

func (h *workloadConsole) expectMCPAccess(token, slug string) {
	h.t.Helper()
	response := h.mcpInitialize(token, slug)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "narthex-client-"+slug) {
		h.t.Fatalf("MCP initialize with a workload token=%d body=%s; want 200 from the client endpoint", response.Code, response.Body)
	}
}

func (h *workloadConsole) expectMCPRejected(token, slug string) {
	h.t.Helper()
	if response := h.mcpInitialize(token, slug); response.Code != http.StatusUnauthorized {
		h.t.Fatalf("MCP initialize=%d body=%s; want 401", response.Code, response.Body)
	}
}

func TestControlV1WorkloadClientCreationRequiresOwnerOrAdmin(t *testing.T) {
	h := newWorkloadConsole(t)
	workloadBody := func(slug, subject string) string {
		return `{"name":"Agent ` + slug + `","slug":"` + slug + `","subject":"` + subject + `","kind":"workload","connectionNamespaceIds":["` + h.team.ID + `"]}`
	}

	owned := h.createWorkload("Owner agent", "owner-agent", "agt_owner", h.team.ID)
	admin := decodeControlClient(t, h.control("usr_admin", "admin", http.MethodPost, "/control/v1/mcp-clients", workloadBody("admin-agent", "agt_admin")), http.StatusCreated)
	if admin.Kind != MCPClientKindWorkload || admin.Subject != "agt_admin" {
		t.Fatalf("admin-created workload client=%+v", admin)
	}
	// An operator may still register its own interactive client, but never a
	// workload one, even for its own subject.
	expectControlProblem(t, h.control("usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", workloadBody("operator-agent", "usr_operator")), http.StatusForbidden, controlCodeForbidden)
	interactive := decodeControlClient(t, h.control("usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Operator Codex","kind":"interactive","connectionNamespaceIds":["`+h.team.ID+`"]}`), http.StatusCreated)
	if interactive.Kind != MCPClientKindInteractive || interactive.Subject != "usr_operator" {
		t.Fatalf("operator interactive client=%+v", interactive)
	}
	expectControlProblem(t, h.control("usr_viewer", "viewer", http.MethodPost, "/control/v1/mcp-clients", workloadBody("viewer-agent", "agt_viewer")), http.StatusForbidden, controlCodeForbidden)
	// The service principal is refused at the assertion boundary, before any
	// role check: registering clients is outside its closed route set.
	expectControlProblem(t, h.control(platformServiceActorID, "service", http.MethodPost, "/control/v1/mcp-clients", workloadBody("service-agent", "agt_service")), http.StatusUnauthorized, controlCodeActorAssertionInvalid)

	// Unknown or near-miss kinds and a workload without a named subject are
	// validation failures.
	for _, body := range []string{
		`{"name":"Robot","subject":"agt_robot","kind":"robot"}`,
		`{"name":"Shout","subject":"agt_shout","kind":"WORKLOAD"}`,
		`{"name":"Anonymous agent","kind":"workload"}`,
		`{"name":"Numeric","subject":"agt_numeric","kind":7}`,
	} {
		expectControlProblem(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", body), http.StatusBadRequest, controlCodeValidationFailed)
	}
	defaulted := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Default kind","subject":"usr_owner"}`), http.StatusCreated)
	if defaulted.Kind != MCPClientKindInteractive {
		t.Fatalf("omitted kind=%q; want interactive", defaulted.Kind)
	}

	// The /api console shares the rule and its own error shape.
	legacy := hostedNamespaceRequest(t, h.mux, h.key, h.now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients", workloadBody("api-agent", "agt_api"))
	var legacyClient mcpClientDTO
	if legacy.Code != http.StatusCreated || json.Unmarshal(legacy.Body.Bytes(), &legacyClient) != nil || legacyClient.Kind != MCPClientKindWorkload {
		t.Fatalf("/api workload create=%d body=%s", legacy.Code, legacy.Body)
	}
	if response := hostedNamespaceRequest(t, h.mux, h.key, h.now, "usr_operator", "operator", http.MethodPost, "/api/mcp-clients", workloadBody("api-operator", "usr_operator")); response.Code != http.StatusForbidden {
		t.Fatalf("/api operator workload create=%d body=%s; want 403", response.Code, response.Body)
	}
	if response := hostedNamespaceRequest(t, h.mux, h.key, h.now, platformServiceActorID, "service", http.MethodPost, "/api/mcp-clients", workloadBody("api-service", "agt_api_service")); response.Code != http.StatusUnauthorized {
		t.Fatalf("/api service workload create=%d body=%s; want 401", response.Code, response.Body)
	}

	// Every read on both surfaces carries kind.
	for _, surface := range []string{"/control/v1/mcp-clients", "/api/mcp-clients"} {
		list := hostedNamespaceRequest(t, h.mux, h.key, h.now, "usr_owner", "owner", http.MethodGet, surface, "")
		var rows []map[string]any
		if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &rows) != nil || len(rows) != 5 {
			t.Fatalf("%s list=%d body=%s", surface, list.Code, list.Body)
		}
		for _, row := range rows {
			want := "interactive"
			if row["id"] == owned.ID || row["id"] == admin.ID || row["id"] == legacyClient.ID {
				want = "workload"
			}
			if row["kind"] != want {
				t.Fatalf("%s row %v kind=%v; want %s", surface, row["id"], row["kind"], want)
			}
		}
		read := hostedNamespaceRequest(t, h.mux, h.key, h.now, "usr_owner", "owner", http.MethodGet, surface+"/"+owned.ID, "")
		var single map[string]any
		if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &single) != nil || single["kind"] != "workload" {
			t.Fatalf("%s read=%d body=%s", surface, read.Code, read.Body)
		}
	}
}

func TestControlV1WorkloadClientNaturalKeyIncludesKindAndKindIsImmutable(t *testing.T) {
	h := newWorkloadConsole(t)
	definition := func(kind string) string {
		return `{"name":"Cloud agent","slug":"cloud-agent","subject":"agt_1","connectionNamespaceIds":["` + h.team.ID + `"]` + kind + `}`
	}
	created := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", definition(`,"kind":"workload"`)), http.StatusCreated)
	replayed := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", definition(`,"kind":"workload"`)), http.StatusOK)
	if replayed.ID != created.ID || replayed.Kind != MCPClientKindWorkload {
		t.Fatalf("identical workload retry=%+v; want the stored %+v", replayed, created)
	}
	// The same slug and fields under another kind are a different definition.
	expectControlProblem(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", definition(`,"kind":"interactive"`)), http.StatusConflict, controlCodeAlreadyExists)
	expectControlProblem(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", definition("")), http.StatusConflict, controlCodeAlreadyExists)

	path := "/control/v1/mcp-clients/" + created.ID
	for _, kind := range []string{"interactive", "robot", ""} {
		expectControlProblem(t, h.control("usr_owner", "owner", http.MethodPatch, path, `{"name":"Renamed","revision":1,"kind":"`+kind+`"}`), http.StatusBadRequest, controlCodeValidationFailed)
	}
	if legacy := hostedNamespaceRequest(t, h.mux, h.key, h.now, "usr_owner", "owner", http.MethodPatch, "/api/mcp-clients/"+created.ID, `{"name":"Renamed","revision":1,"kind":"interactive"}`); legacy.Code != http.StatusBadRequest || !strings.Contains(legacy.Body.String(), "kind is immutable") {
		t.Fatalf("/api kind change=%d body=%s; want 400", legacy.Code, legacy.Body)
	}
	if stored := h.stored(created.ID); stored.Kind != MCPClientKindWorkload || stored.Revision != 1 || stored.Name != "Cloud agent" {
		t.Fatalf("refused kind changes modified the client: %+v", stored)
	}
	echoed := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPatch, path, `{"name":"Renamed","revision":1,"kind":"workload"}`), http.StatusOK)
	if echoed.Kind != MCPClientKindWorkload || echoed.Name != "Renamed" || echoed.Revision != 2 {
		t.Fatalf("rename echoing the current kind=%+v", echoed)
	}
	omitted := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPatch, path, `{"name":"Renamed again","revision":2}`), http.StatusOK)
	if omitted.Kind != MCPClientKindWorkload {
		t.Fatalf("rename without kind=%+v", omitted)
	}
}

func TestControlV1WorkloadTokenIsServiceOnlyAndHidesInteractiveClients(t *testing.T) {
	h := newWorkloadConsole(t)
	workload := h.createWorkload("Cloud agent", "cloud-agent", "agt_1", h.team.ID)
	interactive := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Owner Codex","subject":"usr_owner"}`), http.StatusCreated)

	// Every human role, including an owner, is refused by role; only the
	// service principal may mint.
	for _, actor := range []struct{ user, role string }{
		{"usr_owner", "owner"}, {"usr_admin", "admin"}, {"usr_operator", "operator"}, {"usr_viewer", "viewer"},
	} {
		expectControlProblem(t, h.control(actor.user, actor.role, http.MethodPost, workloadTokenPath(workload.ID), "{}"), http.StatusForbidden, controlCodeForbidden)
	}
	// The service's route set admits exactly POST here.
	expectControlProblem(t, h.control(platformServiceActorID, "service", http.MethodGet, workloadTokenPath(workload.ID), ""), http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	if stored := h.stored(workload.ID); stored.OAuthClientID != "" || stored.Revision != 1 {
		t.Fatalf("refused callers changed the workload client: %+v", stored)
	}

	// Unknown and interactive clients are indistinguishable, with no side
	// effect on the interactive registration.
	expectControlProblem(t, h.mint("mcpcli_missing"), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, h.mint(interactive.ID), http.StatusNotFound, controlCodeNotFound)
	if stored := h.stored(interactive.ID); stored.OAuthClientID != "" || stored.Revision != 1 {
		t.Fatalf("workload-token call changed an interactive client: %+v", stored)
	}
	decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+interactive.ID+"/revoke", `{"revision":1}`), http.StatusOK)
	expectControlProblem(t, h.mint(interactive.ID), http.StatusNotFound, controlCodeNotFound)

	// A revoked workload client is terminal and says so.
	retired := h.createWorkload("Retired agent", "retired-agent", "agt_2")
	decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+retired.ID+"/revoke", `{"revision":1}`), http.StatusOK)
	expectControlProblem(t, h.mint(retired.ID), http.StatusConflict, controlCodeClientRevoked)

	expectControlProblem(t, h.control(platformServiceActorID, "service", http.MethodPost, workloadTokenPath(workload.ID), `{`), http.StatusBadRequest, controlCodeValidationFailed)
}

func TestControlV1WorkloadTokenBindsReservedIdentityAndAuthorizesTheClientEndpoint(t *testing.T) {
	h := newWorkloadConsole(t)
	ctx := context.Background()
	workload := h.createWorkload("Cloud agent", "cloud-agent", "agt_1", h.team.ID)
	other := h.createWorkload("Other agent", "other-agent", "agt_2", h.team.ID)
	before := h.stored(workload.ID)

	start := time.Now()
	response := h.mint(workload.ID)
	finish := time.Now()
	if response.Code != http.StatusOK {
		t.Fatalf("workload token=%d body=%s", response.Code, response.Body)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" || response.Header().Get(controlRequestIDHeader) == "" {
		t.Fatalf("workload token headers=%v", response.Header())
	}
	var raw map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for field := range raw {
		switch field {
		case "accessToken", "tokenType", "expiresIn", "expiresAt", "resource":
		default:
			t.Fatalf("workload token response has unexpected field %q (no refresh token may be issued)", field)
		}
	}
	var token controlWorkloadTokenDTO
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.TokenType != "Bearer" || token.ExpiresIn != 3600 || token.Resource != "/mcp/clients/"+workload.Slug {
		t.Fatalf("workload token=%+v", token)
	}
	// One hour, not the interactive week: the RFC 3339 expiry is the token's
	// own encoded expiry and lies one hour after issue.
	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		t.Fatalf("expiresAt %q: %v", token.ExpiresAt, err)
	}
	if expiresAt.Before(start.Add(time.Hour).Add(-time.Second)) || expiresAt.After(finish.Add(time.Hour)) {
		t.Fatalf("expiresAt=%s; want one hour after %s", expiresAt, start)
	}
	if encoded := strings.SplitN(token.AccessToken, ".", 2)[0]; encoded != strconv.FormatInt(expiresAt.Unix(), 10) {
		t.Fatalf("token encodes expiry %s; response says %d", encoded, expiresAt.Unix())
	}

	// The first mint durably binds the reserved identity, bumping revision
	// but not epoch.
	bound := h.stored(workload.ID)
	if bound.OAuthClientID != "workload:"+workload.ID || bound.Revision != before.Revision+1 || bound.Epoch != before.Epoch {
		t.Fatalf("after first mint=%+v; before=%+v", bound, before)
	}
	if read := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodGet, "/control/v1/mcp-clients/"+workload.ID, ""), http.StatusOK); !read.OAuthBound || read.Revision != bound.Revision {
		t.Fatalf("client DTO after first mint=%+v", read)
	}

	h.expectMCPAccess(token.AccessToken, workload.Slug)
	h.expectMCPRejected("", workload.Slug)
	h.expectMCPRejected(token.AccessToken, other.Slug)

	// Later mints reuse the binding without touching the record.
	second := h.mintToken(workload.ID)
	if after := h.stored(workload.ID); after.Revision != bound.Revision || after.Epoch != bound.Epoch {
		t.Fatalf("second mint changed the client: %+v", after)
	}
	h.expectMCPAccess(second.AccessToken, workload.Slug)
	h.expectMCPAccess(token.AccessToken, workload.Slug)

	// A credential is never pinned to an Idempotency-Key: the header is
	// ignored, nothing is stored, and a repeat is a fresh mint.
	for i := 0; i < 2; i++ {
		keyed := hostedNamespaceRequestWithHeaders(t, h.mux, h.key, h.now, platformServiceActorID, "service", http.MethodPost, workloadTokenPath(workload.ID), "{}", map[string]string{controlIdempotencyKeyHeader: "mint-1"})
		if keyed.Code != http.StatusOK || keyed.Header().Get(controlIdempotentReplayHeader) != "" {
			t.Fatalf("keyed mint %d=%d headers=%v body=%s", i, keyed.Code, keyed.Header(), keyed.Body)
		}
	}
	if _, found, err := h.store.ControlIdempotencyRecord(ctx, "mint-1", workloadTokenPath(workload.ID), time.Now().UTC()); err != nil || found {
		t.Fatalf("workload token stored under an idempotency key: found=%t err=%v", found, err)
	}
}

func TestControlV1WorkloadTokensDieWithEpochRotationResetAndRevoke(t *testing.T) {
	h := newWorkloadConsole(t)
	workload := h.createWorkload("Cloud agent", "cloud-agent", "agt_1", h.team.ID)
	clientPath := "/control/v1/mcp-clients/" + workload.ID
	revision := func() string { return strconv.FormatInt(h.stored(workload.ID).Revision, 10) }

	token := h.mintToken(workload.ID).AccessToken
	h.expectMCPAccess(token, workload.Slug)

	// A profile binding change (installed by the service itself) rotates
	// the epoch.
	epoch := h.stored(workload.ID).Epoch
	decodeControlClient(t, h.control(platformServiceActorID, "service", http.MethodPut, clientPath+"/profile-binding",
		`{"revision":`+revision()+`,"profileId":"aap_cloud","profileRevision":1,"policyDigest":"`+libraryDigest("cloud policy")+`"}`), http.StatusOK)
	if h.stored(workload.ID).Epoch == epoch {
		t.Fatal("profile binding did not rotate the epoch")
	}
	h.expectMCPRejected(token, workload.Slug)
	token = h.mintToken(workload.ID).AccessToken
	h.expectMCPAccess(token, workload.Slug)

	// A connection-folder grant change rotates the epoch.
	decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPut, clientPath+"/namespaces",
		`{"revision":`+revision()+`,"connectionNamespaceIds":["`+h.team.ID+`","`+h.ops.ID+`"]}`), http.StatusOK)
	h.expectMCPRejected(token, workload.Slug)
	token = h.mintToken(workload.ID).AccessToken
	h.expectMCPAccess(token, workload.Slug)

	// An OAuth reset clears the reserved identity and rotates the epoch; the
	// next mint binds it again.
	reset := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, clientPath+"/oauth-client/reset", `{"revision":`+revision()+`}`), http.StatusOK)
	if reset.OAuthBound || h.stored(workload.ID).OAuthClientID != "" {
		t.Fatalf("reset left a binding: %+v", reset)
	}
	h.expectMCPRejected(token, workload.Slug)
	token = h.mintToken(workload.ID).AccessToken
	if rebound := h.stored(workload.ID); rebound.OAuthClientID != "workload:"+workload.ID || rebound.Revision != reset.Revision+1 {
		t.Fatalf("mint after reset=%+v", rebound)
	}
	h.expectMCPAccess(token, workload.Slug)

	// Revocation kills the token and every later mint.
	decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, clientPath+"/revoke", `{"revision":`+revision()+`}`), http.StatusOK)
	h.expectMCPRejected(token, workload.Slug)
	expectControlProblem(t, h.mint(workload.ID), http.StatusConflict, controlCodeClientRevoked)
}

func TestControlV1WorkloadTokenReportsForeignBindingsAndFailsClosed(t *testing.T) {
	h := newWorkloadConsole(t)
	ctx := context.Background()
	workload := h.createWorkload("Cloud agent", "cloud-agent", "agt_1", h.team.ID)
	token := h.mintToken(workload.ID).AccessToken
	h.expectMCPAccess(token, workload.Slug)

	// No store write produces a foreign binding on a workload client, so
	// corrupt the record directly: the route reports the conflict instead of
	// silently rebinding, and the earlier token stops working.
	corrupt := func(id, oauthClientID string) {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		client, ok := h.store.mcpClientByIDLocked(id)
		if !ok {
			t.Fatalf("client %s missing", id)
		}
		client.OAuthClientID = oauthClientID
	}
	corrupt(workload.ID, "mcp_v1.foreign")
	expectControlProblem(t, h.mint(workload.ID), http.StatusConflict, controlCodeWorkloadBindingConflict)
	h.expectMCPRejected(token, workload.Slug)
	// An explicit reset is the recovery.
	decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients/"+workload.ID+"/oauth-client/reset",
		`{"revision":`+strconv.FormatInt(h.stored(workload.ID).Revision, 10)+`}`), http.StatusOK)
	h.expectMCPAccess(h.mintToken(workload.ID).AccessToken, workload.Slug)

	// The runtime check also refuses an interactive client holding a
	// reserved identity, even though the identity matches its binding.
	interactive := decodeControlClient(t, h.control("usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Owner Codex","subject":"usr_owner"}`), http.StatusCreated)
	corrupt(interactive.ID, "workload:"+interactive.ID)
	if h.gateway.MCPClientAllowsOAuthClient("workload:"+interactive.ID, "/mcp/clients/"+interactive.Slug) {
		t.Fatal("an interactive client authorized a reserved workload identity")
	}
	if current, _ := h.store.MCPClient(ctx, interactive.ID); current.Kind != MCPClientKindInteractive {
		t.Fatalf("interactive client=%+v", current)
	}
}

func TestControlV1MetaAdvertisesWorkloadClientsOnlyWhenTokensCanBeMinted(t *testing.T) {
	h := newWorkloadConsole(t)
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {platformServiceActorID, "service"}} {
		response := h.control(actor.user, actor.role, http.MethodGet, "/control/v1/meta", "")
		var meta controlMetaDTO
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &meta) != nil {
			t.Fatalf("%s meta=%d body=%s", actor.role, response.Code, response.Body)
		}
		if got := strings.Join(meta.Capabilities, ","); got != "mcp-clients,profile-binding,activation-snapshot,run-correlations,library-artifacts,connection-evidence,workload-clients" {
			t.Fatalf("%s capabilities=%s", actor.role, got)
		}
	}

	// An Engine without an issuer neither advertises nor serves the group.
	mux, store, key, now, _ := newHostedControlConsole(t)
	response := controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/meta", "")
	var meta controlMetaDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &meta) != nil {
		t.Fatalf("meta=%d body=%s", response.Code, response.Body)
	}
	for _, capability := range meta.Capabilities {
		if capability == controlCapabilityWorkloadClients {
			t.Fatalf("capability advertised without an issuer: %v", meta.Capabilities)
		}
	}
	created := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Agent","subject":"agt_1","kind":"workload"}`), http.StatusCreated)
	expectControlProblem(t, controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, workloadTokenPath(created.ID), "{}"), http.StatusNotImplemented, controlCodeCapabilityUnavailable)
	if stored, _ := store.MCPClient(context.Background(), created.ID); stored.OAuthClientID != "" {
		t.Fatalf("unavailable route bound the client: %+v", stored)
	}
}

// TestSelfHostedLocalAdminCreatesWorkloadClientsButCannotMintTokens covers the
// self-hosted surface: the local admin acts as owner for registration, but
// workload tokens remain a hosted service-principal operation.
func TestSelfHostedLocalAdminCreatesWorkloadClientsButCannotMintTokens(t *testing.T) {
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	api := NewConsoleAPI(store, NewGateway(store, nil), nil, "pw", "secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"),
		WithWorkloadTokenIssuer(func(context.Context, string, string, time.Duration) (string, time.Time, error) {
			issued++
			return "unexpected", time.Now().Add(time.Hour), nil
		}),
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	request := func(method, requestPath, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, requestPath, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	created := decodeControlClient(t, request(http.MethodPost, "/control/v1/mcp-clients", `{"name":"Local agent","subject":"agt_local","kind":"workload"}`), http.StatusCreated)
	if created.Kind != MCPClientKindWorkload {
		t.Fatalf("local admin workload client=%+v", created)
	}
	legacy := request(http.MethodPost, "/api/mcp-clients", `{"name":"Local agent two","subject":"agt_local_two","kind":"workload"}`)
	var legacyClient mcpClientDTO
	if legacy.Code != http.StatusCreated || json.Unmarshal(legacy.Body.Bytes(), &legacyClient) != nil || legacyClient.Kind != MCPClientKindWorkload {
		t.Fatalf("/api local admin workload create=%d body=%s", legacy.Code, legacy.Body)
	}
	expectControlProblem(t, request(http.MethodPost, workloadTokenPath(created.ID), "{}"), http.StatusForbidden, controlCodeForbidden)
	if issued != 0 {
		t.Fatalf("issuer called %d times for a non-service actor", issued)
	}
}
