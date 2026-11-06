package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlLibraryCollaborationBindsActorAndDoesNotReplayTokens(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	a, _ := collaborationFixture(t, store)
	path := "/control/v1/library/collaboration"
	body := `{"operation":"grant","artifactId":"` + a.ID + `","kind":"subject","recipient":"usr_member","label":"Member","role":"comment"}`
	denied := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", "POST", path, body, "usr_member")
	if denied.Code != 403 {
		t.Fatalf("service became administrator: %d %s", denied.Code, denied.Body)
	}
	granted := controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", "POST", path, body, "")
	if granted.Code != 200 {
		t.Fatalf("grant: %d %s", granted.Code, granted.Body)
	}
	read := `{"operation":"read","artifactId":"` + a.ID + `"}`
	for _, tc := range []struct {
		subject string
		status  int
	}{{"usr_member", 200}, {"usr_other", 404}, {"", 404}} {
		result := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", "POST", path, read, tc.subject)
		if result.Code != tc.status {
			t.Fatalf("subject=%q status=%d body=%s", tc.subject, result.Code, result.Body)
		}
	}
	denied = controlLibraryRequest(t, mux, key, now, "usr_member", "viewer", "POST", path, read, "usr_member")
	if denied.Code != 403 {
		t.Fatalf("member accessed privileged control route: %d", denied.Code)
	}
	guestBody := `{"operation":"grant","artifactId":"` + a.ID + `","kind":"guest","label":"Guest","role":"view"}`
	created := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", "POST", path, guestBody, map[string]string{"Idempotency-Key": "secret-must-not-be-persisted"})
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var result LibraryCollaborationResult
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	raw, _ := json.Marshal(store.controlIdempotencyRecords)
	if result.Token == "" || strings.Contains(string(raw), result.Token) {
		t.Fatal("control idempotency persisted a bearer")
	}
}

func TestLibraryCollaborationExternalMCPIsOneArtifactAndLive(t *testing.T) {
	store := newLibraryFileStore(t)
	a, _ := collaborationFixture(t, store)
	other, _ := collaborationFixture(t, store)
	grant, err := store.Collaborate(context.Background(), LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}, LibraryCollaborationRequest{Operation: "grant", ArtifactID: a.ID, Kind: "external_agent", Label: "Outside agent", Role: "comment"})
	if err != nil {
		t.Fatal(err)
	}
	console := &ConsoleAPI{libraryStore: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public/artifacts/mcp/{artifact}/{grant}", console.handleCollaborationMCP)
	invoke := func(artifact, method, args string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/public/artifacts/mcp/"+artifact+"/"+grant.Grant.ID, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+args+`}`))
		r.Header.Set("Authorization", "Bearer "+grant.Token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	result := invoke(a.ID, "initialize", `{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`)
	if result.Code != 200 || !strings.Contains(result.Body.String(), "Synaxis shared output") {
		t.Fatal(result.Code, result.Body.String())
	}
	result = invoke(a.ID, "tools/list", `{}`)
	if result.Code != 200 || !strings.Contains(result.Body.String(), "artifact_collaborate") || strings.Contains(result.Body.String(), "library_artifact_list") {
		t.Fatal(result.Code, result.Body.String())
	}
	result = invoke(a.ID, "tools/call", `{"name":"artifact_collaborate","arguments":{"operation":"read","artifactId":"`+other.ID+`"}}`)
	if result.Code != 200 || !strings.Contains(result.Body.String(), a.ID) || strings.Contains(result.Body.String(), other.ID) {
		t.Fatal("MCP escaped artifact", result.Code, result.Body.String())
	}
	if result = invoke(other.ID, "tools/list", `{}`); result.Code != 401 {
		t.Fatal("token used on another output", result.Code)
	}
	_, err = store.Collaborate(context.Background(), LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}, LibraryCollaborationRequest{Operation: "revoke", ArtifactID: a.ID, GrantID: grant.Grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result = invoke(a.ID, "tools/list", `{}`); result.Code != 401 {
		t.Fatal("revoked MCP still available", result.Code)
	}
}

func TestCollaborationCapabilityCannotInheritLocalAdmin(t *testing.T) {
	store := newLibraryFileStore(t)
	artifact, _ := collaborationFixture(t, store)
	granted, err := store.Collaborate(context.Background(), LibraryCollaborationActor{Kind: "admin", Ref: "local-admin"}, LibraryCollaborationRequest{Operation: "grant", ArtifactID: artifact.ID, Kind: "guest", Label: "Reader", Role: "view"})
	if err != nil {
		t.Fatal(err)
	}
	console := &ConsoleAPI{libraryStore: store}
	raw, _ := json.Marshal(collaborationEnvelope{LibraryCollaborationRequest: LibraryCollaborationRequest{Operation: "read", ArtifactID: artifact.ID, GrantID: granted.Grant.ID}, Token: granted.Token})
	r := httptest.NewRequest("POST", "/control/v1/library/collaboration", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	console.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "admin", Ref: "local-admin"})
	var result LibraryCollaborationResult
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result.Role != "view" {
		t.Fatal("capability inherited admin", w.Code, result.Role)
	}
	raw, _ = json.Marshal(collaborationEnvelope{LibraryCollaborationRequest: LibraryCollaborationRequest{Operation: "grant", ArtifactID: artifact.ID, GrantID: granted.Grant.ID, Kind: "guest", Label: "Escalation", Role: "edit"}, Token: granted.Token})
	r = httptest.NewRequest("POST", "/control/v1/library/collaboration", strings.NewReader(string(raw)))
	w = httptest.NewRecorder()
	console.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "admin", Ref: "local-admin"})
	if w.Code != 403 {
		t.Fatal("capability could manage access", w.Code, w.Body.String())
	}
}
