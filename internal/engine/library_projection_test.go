package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// privateOutputsKeptTools is SPEC §7.1.4's "Kept" column: the client's own
// outputs, conversation replay of them, and its assigned skills.
var privateOutputsKeptTools = []string{
	"library_artifact_create",
	"library_artifact_read",
	"library_artifact_version_create",
	"library_skill_activation",
	"library_skill_file_read",
	"library_skill_read",
	"library_skill_resolve",
}

func setLibraryProjectionForTest(t *testing.T, store MCPClientStore, client MCPClient, projection string) MCPClient {
	t.Helper()
	updated, err := store.UpdateMCPClient(context.Background(), MCPClient{
		ID: client.ID, Name: client.Name, LibraryProjection: projection, libraryProjectionSet: true,
	}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
	if err != nil {
		t.Fatalf("set library projection %q: %v", projection, err)
	}
	return updated
}

func toolCallFailed(response string) bool {
	return strings.Contains(response, `"isError":true`) || strings.Contains(response, `"error":{`)
}

func TestPrivateOutputsProjectionHasNoOutboundLibraryTools(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Private outputs agent", Subject: "agt_private", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	if client.LibraryProjection != "" || effectiveLibraryProjection(client.LibraryProjection) != LibraryProjectionFull {
		t.Fatalf("new client projection = %q; want the full default", client.LibraryProjection)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	full := append([]string(nil), mcpClientLibraryToolNames...)
	sort.Strings(full)
	if got := clientEndpointToolNames(t, gateway, client.Slug); !slices.Equal(got, full) {
		t.Fatalf("full projection = %v; want %v", got, full)
	}
	// Keep the handler closures this gateway built for the full projection.
	// They stand in for a replica that has not refreshed yet: the endpoint's
	// advertised dispatchers resolve the current map at call time, so only
	// the captured closures show what a not-yet-refreshed replica would run.
	gateway.mu.Lock()
	stale := *gateway.clientEndpoints[client.Slug].dispatch.Load()
	gateway.mu.Unlock()

	reduced := setLibraryProjectionForTest(t, store, client, LibraryProjectionPrivateOutputs)
	if reduced.LibraryProjection != LibraryProjectionPrivateOutputs || reduced.Epoch == client.Epoch || reduced.Revision != client.Revision+1 {
		t.Fatalf("projection change must persist and rotate the epoch: %+v", reduced)
	}
	// Before any refresh, every removed tool's built handler refuses the call
	// on the durable projection alone.
	for _, name := range mcpClientLibraryToolNames {
		if slices.Contains(privateOutputsKeptTools, name) {
			continue
		}
		handler := stale[name]
		if handler == nil {
			t.Fatalf("full projection did not register %s", name)
		}
		result, err := handler(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: map[string]any{}}})
		encoded, _ := json.Marshal(result)
		if err != nil || result == nil || !result.IsError || !strings.Contains(string(encoded), libraryProjectionRefusal) {
			t.Fatalf("unrefreshed full-projection handler for removed %s = %s, %v; want the projection refusal", name, encoded, err)
		}
	}
	// Even a retained tool cannot use an already-open full-projection
	// handler after the authorization epoch changes. This fences pre-connect
	// non-owner work at the actual Library read, not just at token refresh.
	result, readErr := stale["library_artifact_read"](ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name: "library_artifact_read", Arguments: map[string]any{"artifactId": "art_previous_reply"},
	}})
	encoded, _ := json.Marshal(result)
	if readErr != nil || result == nil || !result.IsError || !strings.Contains(string(encoded), "this Library surface is no longer available") {
		t.Fatalf("stale retained Library read survived projection change: %s, %v", encoded, readErr)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got := clientEndpointToolNames(t, gateway, client.Slug); !slices.Equal(got, privateOutputsKeptTools) {
		t.Fatalf("private_outputs projection = %v; want exactly %v", got, privateOutputsKeptTools)
	}
	endpoint := clientLibraryServer(t, gateway, client.Slug)
	listed, err := json.Marshal(endpoint.HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range mcpClientLibraryToolNames {
		kept := slices.Contains(privateOutputsKeptTools, name)
		if strings.Contains(string(listed), `"name":"`+name+`"`) != kept {
			t.Fatalf("tools/list advertised %s=%t; want %t: %s", name, !kept, kept, listed)
		}
		if kept {
			continue
		}
		if got := callLibraryTool(t, endpoint, name, map[string]any{}); !toolCallFailed(got) {
			t.Fatalf("direct tools/call of removed %s succeeded: %s", name, got)
		}
	}
	// Every removed name is in exactly one place: the full list minus kept.
	removed := 0
	for _, name := range mcpClientLibraryToolNames {
		if !libraryProjectionAllowsTool(LibraryProjectionPrivateOutputs, name) {
			removed++
		}
	}
	if removed != len(mcpClientLibraryToolNames)-len(privateOutputsKeptTools) {
		t.Fatalf("removed=%d kept=%d of %d", removed, len(privateOutputsKeptTools), len(mcpClientLibraryToolNames))
	}

	// Back to full restores today's surface.
	restored := setLibraryProjectionForTest(t, store, reduced, LibraryProjectionFull)
	if restored.LibraryProjection != "" || restored.Epoch == reduced.Epoch {
		t.Fatalf("full is stored as the empty default and rotates the epoch: %+v", restored)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got := clientEndpointToolNames(t, gateway, client.Slug); !slices.Equal(got, full) {
		t.Fatalf("restored projection = %v", got)
	}
	if _, err := store.UpdateMCPClient(ctx, MCPClient{ID: client.ID, Name: client.Name, LibraryProjection: "everything", libraryProjectionSet: true},
		MCPClientPrecondition{ID: client.ID, Revision: restored.Revision}); err == nil {
		t.Fatal("unknown projection accepted")
	}
}

func TestPrivateOutputsArtifactReadLimitedToOwnArtifacts(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	agent, err := store.CreateMCPClient(ctx, MCPClient{Name: "Agent", Subject: "agt_agent", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	// Version appends require the client's bound workload identity.
	if agent, err = store.BindMCPClientWorkloadIdentity(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateMCPClient(ctx, MCPClient{Name: "Other agent", Subject: "agt_other", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	otherOutput := callLibraryTool(t, clientLibraryServer(t, gateway, other.Slug), "library_artifact_create", map[string]any{
		"title": "Other output", "body": "# Someone else's reply",
	})
	if toolCallFailed(otherOutput) {
		t.Fatalf("other client create=%s", otherOutput)
	}
	human, humanVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Shared research", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Shared with the agent", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	var otherArtifact LibraryArtifact
	artifacts, err := store.LibraryArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		if artifact.Title == "Other output" {
			otherArtifact = artifact
		}
	}
	otherVersion, found := latestLibraryArtifactVersion(ctx, store, otherArtifact.ID)
	if otherArtifact.ID == "" || !found {
		t.Fatal("other client's artifact not stored")
	}
	type granted struct {
		artifact LibraryArtifact
		version  LibraryArtifactVersion
		body     string
	}
	grants := []granted{{human, humanVersion, "# Shared with the agent"}, {otherArtifact, otherVersion, "# Someone else's reply"}}
	for _, g := range grants {
		if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
			ArtifactID: g.artifact.ID, ArtifactVersionID: g.version.ID, ArtifactVersionDigest: g.version.Digest,
			AgentSurfaceID: agent.ID, CreatedBy: "usr_owner",
		}); err != nil {
			t.Fatalf("grant %s: %v", g.artifact.Title, err)
		}
	}
	// With the full projection a live grant is readable (the control case).
	fullServer := clientLibraryServer(t, gateway, agent.Slug)
	for _, g := range grants {
		if got := callLibraryTool(t, fullServer, "library_artifact_read", map[string]any{"artifactId": g.artifact.ID}); !strings.Contains(got, strings.TrimPrefix(g.body, "# ")) {
			t.Fatalf("full projection could not read granted %s: %s", g.artifact.Title, got)
		}
	}

	setLibraryProjectionForTest(t, store, agent, LibraryProjectionPrivateOutputs)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	private := clientLibraryServer(t, gateway, agent.Slug)
	own := callLibraryTool(t, private, "library_artifact_create", map[string]any{"title": "My reply", "body": "# Mine"})
	if toolCallFailed(own) {
		t.Fatalf("private_outputs client could not save its own output: %s", own)
	}
	var created struct {
		ArtifactID string `json:"artifactId"`
		VersionID  string `json:"artifactVersionId"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, own)), &created); err != nil || created.ArtifactID == "" {
		t.Fatalf("create result=%s err=%v", own, err)
	}
	if got := callLibraryTool(t, private, "library_artifact_read", map[string]any{"artifactId": created.ArtifactID}); !strings.Contains(got, "# Mine") || !strings.Contains(got, `\"access\":\"owned\"`) {
		t.Fatalf("own output not replayable: %s", got)
	}
	appended := callLibraryTool(t, private, "library_artifact_version_create", map[string]any{
		"requestId": "req-1", "artifactId": created.ArtifactID, "expectedArtifactVersionId": created.VersionID, "expectedDigest": created.Digest, "body": "# Mine, revised",
	})
	if toolCallFailed(appended) {
		t.Fatalf("own output version append failed: %s", appended)
	}
	for _, g := range grants {
		got := callLibraryTool(t, private, "library_artifact_read", map[string]any{"artifactId": g.artifact.ID})
		if !strings.Contains(got, "artifact not found") || strings.Contains(got, strings.TrimPrefix(g.body, "# ")) {
			t.Fatalf("private_outputs read granted %s: %s", g.artifact.Title, got)
		}
		got = callLibraryTool(t, private, "library_artifact_read", map[string]any{"artifactId": g.artifact.ID, "artifactVersionId": g.version.ID})
		if !strings.Contains(got, "artifact not found") {
			t.Fatalf("private_outputs exact-version read of granted %s: %s", g.artifact.Title, got)
		}
		cited := callLibraryTool(t, private, "library_artifact_create", map[string]any{
			"title": "Derived", "body": "# Derived",
			"sourceArtifactId": g.artifact.ID, "sourceArtifactVersionId": g.version.ID, "sourceArtifactDigest": g.version.Digest,
		})
		if !strings.Contains(cited, "source artifact not found") {
			t.Fatalf("private_outputs cited granted %s as a source: %s", g.artifact.Title, cited)
		}
	}
	if got := callLibraryTool(t, private, "library_artifact_read", map[string]any{"artifactId": "art_missing"}); !strings.Contains(got, "artifact not found") {
		t.Fatalf("unknown artifact read=%s", got)
	}
}

func TestControlMCPClientPatchLibraryProjection(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	created := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients",
		`{"name":"Agent","kind":"workload","subject":"agt_projection"}`), http.StatusCreated)
	if created.LibraryProjection != LibraryProjectionFull {
		t.Fatalf("default libraryProjection=%q; want full", created.LibraryProjection)
	}
	path := "/control/v1/mcp-clients/" + created.ID
	before, _ := store.MCPClient(ctx, created.ID)

	reduced := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"libraryProjection":"private_outputs","revision":1}`), http.StatusOK)
	if reduced.LibraryProjection != LibraryProjectionPrivateOutputs || reduced.Revision != 2 || reduced.Name != "Agent" {
		t.Fatalf("PATCH libraryProjection=%+v", reduced)
	}
	after, _ := store.MCPClient(ctx, created.ID)
	if after.Epoch == before.Epoch {
		t.Fatal("projection change kept the client epoch")
	}
	// Same value again converges without a new revision.
	same := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"libraryProjection":"private_outputs","revision":2}`), http.StatusOK)
	if same.Revision != 2 {
		t.Fatalf("no-op PATCH bumped revision: %+v", same)
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"libraryProjection":"everything","revision":2}`), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"libraryProjection":"full","revision":1}`), http.StatusConflict, controlCodeRevisionMismatch)
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"revision":2}`), http.StatusBadRequest, controlCodeValidationFailed)
	// A rename keeps the projection.
	renamed := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, path,
		`{"name":"Renamed agent","revision":2}`), http.StatusOK)
	if renamed.LibraryProjection != LibraryProjectionPrivateOutputs || renamed.Name != "Renamed agent" {
		t.Fatalf("rename reset the projection: %+v", renamed)
	}
	if got := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, path, ""), http.StatusOK); got.LibraryProjection != LibraryProjectionPrivateOutputs {
		t.Fatalf("GET libraryProjection=%q", got.LibraryProjection)
	}
	// The value survives a reload of the durable store.
	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, ok := reopened.MCPClient(ctx, created.ID); !ok || loaded.LibraryProjection != LibraryProjectionPrivateOutputs {
		t.Fatalf("reloaded client=%+v", loaded)
	}
	// The self-hosted console shares the handler.
	restored := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPatch, "/api/mcp-clients/"+created.ID,
		fmt.Sprintf(`{"libraryProjection":"full","revision":%d}`, renamed.Revision))
	if restored.Code != http.StatusOK || !strings.Contains(restored.Body.String(), `"libraryProjection":"full"`) {
		t.Fatalf("console PATCH=%d %s", restored.Code, restored.Body)
	}
}

func TestControlMCPClientPatchLibraryProjectionServiceActor(t *testing.T) {
	mux, store, key, now, team := newHostedControlConsole(t)
	ctx := context.Background()
	if err := store.Create(ctx, Account{
		Name: "delegated", URL: "https://delegated.example/api/v1/mcp", AuthMode: "token", BearerToken: "listing-key",
		ConnectionNamespaceID: team.ID, CallerDelegated: true,
		ClientID: "client_test", ClientSecret: "secret_0123456789abcdef0123456789abcdef",
		TokenEndpoint: "https://delegated.example/api/v1/mcp/token", Resource: "https://delegated.example/api/v1/mcp",
	}); err != nil {
		t.Fatal(err)
	}
	workload := decodeControlClient(t, controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, "/control/v1/workload-clients",
		`{"name":"Personal agent","kind":"workload","subject":"agt_personal"}`), http.StatusCreated)
	interactive := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/mcp-clients",
		`{"name":"Desktop","subject":"usr_operator"}`), http.StatusCreated)
	service := func(method, path, body string) *httptest.ResponseRecorder {
		return controlRequest(t, mux, key, now, platformServiceActorID, "service", method, path, body)
	}

	// PATCH: libraryProjection and revision only, on workload clients only.
	patched := decodeControlClient(t, service(http.MethodPatch, "/control/v1/mcp-clients/"+workload.ID,
		fmt.Sprintf(`{"libraryProjection":"private_outputs","revision":%d}`, workload.Revision)), http.StatusOK)
	if patched.LibraryProjection != LibraryProjectionPrivateOutputs {
		t.Fatalf("service PATCH=%+v", patched)
	}
	expectControlProblem(t, service(http.MethodPatch, "/control/v1/mcp-clients/"+workload.ID,
		fmt.Sprintf(`{"name":"Renamed","libraryProjection":"private_outputs","revision":%d}`, patched.Revision)), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, service(http.MethodPatch, "/control/v1/mcp-clients/"+workload.ID,
		fmt.Sprintf(`{"runtimeAttestorPublicKey":"","libraryProjection":"full","revision":%d}`, patched.Revision)), http.StatusForbidden, controlCodeForbidden)
	expectControlProblem(t, service(http.MethodPatch, "/control/v1/mcp-clients/"+interactive.ID,
		fmt.Sprintf(`{"libraryProjection":"private_outputs","revision":%d}`, interactive.Revision)), http.StatusNotFound, controlCodeNotFound)

	// PUT /namespaces: the existing body, on workload clients only.
	connected := decodeControlClient(t, service(http.MethodPut, "/control/v1/mcp-clients/"+workload.ID+"/namespaces",
		fmt.Sprintf(`{"connectionNamespaceIds":[],"connectionIds":["delegated"],"revision":%d}`, patched.Revision)), http.StatusOK)
	if !slices.Equal(connected.ConnectionIDs, []string{"delegated"}) || len(connected.ConnectionNamespaceIDs) != 0 {
		t.Fatalf("service PUT /namespaces=%+v", connected)
	}
	expectControlProblem(t, service(http.MethodPut, "/control/v1/mcp-clients/"+workload.ID+"/namespaces",
		fmt.Sprintf(`{"connectionNamespaceIds":[],"connectionIds":["delegated"],"revision":%d}`, patched.Revision)), http.StatusConflict, controlCodeRevisionMismatch)
	expectControlProblem(t, service(http.MethodPut, "/control/v1/mcp-clients/"+interactive.ID+"/namespaces",
		fmt.Sprintf(`{"connectionNamespaceIds":[],"connectionIds":["delegated"],"revision":%d}`, interactive.Revision)), http.StatusNotFound, controlCodeNotFound)
	stored, _ := store.MCPClient(ctx, interactive.ID)
	if len(stored.ConnectionIDs) != 0 {
		t.Fatalf("service changed an interactive client: %+v", stored)
	}

	// Nothing else opened up for the service actor.
	for _, denied := range []struct{ method, path, body string }{
		{http.MethodGet, "/control/v1/mcp-clients/" + workload.ID, ""},
		{http.MethodPost, "/control/v1/mcp-clients/" + workload.ID + "/revoke", `{"revision":3}`},
		{http.MethodPost, "/control/v1/mcp-clients/" + workload.ID + "/oauth-client/reset", `{"revision":3}`},
		{http.MethodPatch, "/control/v1/mcp-clients/" + workload.ID + "/namespaces", `{"revision":3}`},
		{http.MethodPut, "/control/v1/mcp-clients/" + workload.ID, `{"revision":3}`},
		{http.MethodPatch, "/control/v1/mcp-clients/" + workload.ID + "%2Fnamespaces", `{"revision":3}`},
	} {
		if got := service(denied.method, denied.path, denied.body); got.Code != http.StatusUnauthorized {
			t.Fatalf("service %s %s = %d %s; want 401", denied.method, denied.path, got.Code, got.Body)
		}
	}
	if !platformServiceControlRoute(http.MethodPatch, "/control/v1/mcp-clients/"+workload.ID) ||
		!platformServiceControlRoute(http.MethodPut, "/control/v1/mcp-clients/"+workload.ID+"/namespaces") ||
		platformServiceControlRoute(http.MethodPatch, "/control/v1/mcp-clients/bad id") ||
		platformServiceControlRoute(http.MethodPatch, "/control/v1/mcp-clients/"+workload.ID+"/extra") {
		t.Fatal("service route allowlist does not match exactly the two new operations")
	}
}
