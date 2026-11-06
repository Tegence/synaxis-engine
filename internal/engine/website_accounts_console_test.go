package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWebsiteSignInStartsWithoutConnections(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		for _, method := range []string{"browser", "credentials"} {
			t.Run(prefix+"/"+method, func(t *testing.T) {
				store := newLibraryFileStore(t)
				service := &BrowserSignInService{provider: &fakeSignInBrowser{}, managedProvider: &managedBrowserFake{}, flows: store, accounts: store, store: store}
				verifier, key, now := newActorVerifier(t)
				api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithBrowserSignIn(service))
				mux := http.NewServeMux()
				api.Routes(mux)
				body, _ := json.Marshal(map[string]any{"displayName": "My website", "websiteUrl": "https://example.com/login", "method": method})
				response := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", prefix+"/browser-sign-ins/start", string(body))
				if response.Code != http.StatusCreated {
					t.Fatalf("website sign-in without a connection: got %d, want 201: %s", response.Code, response.Body.String())
				}
				var flow browserSignInDTO
				if err := json.Unmarshal(response.Body.Bytes(), &flow); err != nil || flow.ConnectionID != "" || flow.ID == "" {
					t.Fatal("invalid standalone sign-in response", err)
				}
				if len(store.Accounts()) != 0 {
					t.Fatal("website sign-in created an MCP connection")
				}
			})
		}
	}
}

type websiteHTTPTestRequest func(subject, role, method, path string, body any) *httptest.ResponseRecorder

func websiteHTTPFixture(t *testing.T, prefix string) (*FileStore, *BrowserSignInService, *fakeSignInBrowser, *managedBrowserFake, websiteHTTPTestRequest) {
	t.Helper()
	store := newLibraryFileStore(t)
	interactive := &fakeSignInBrowser{}
	managed := &managedBrowserFake{status: ManagedBrowserStatus{State: "input", InteractionID: "login-1", Fields: []ManagedBrowserField{{ID: "user", Label: "Username", Type: "text", Required: true}, {ID: "pass", Label: "Password", Type: "password", Required: true}}}}
	service := &BrowserSignInService{provider: interactive, managedProvider: managed, flows: store, accounts: store, store: store}
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithBrowserSignIn(service))
	mux := http.NewServeMux()
	api.Routes(mux)
	request := func(subject, role, method, path string, body any) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		return hostedNamespaceRequest(t, mux, key, now, subject, role, method, prefix+path, string(raw))
	}
	return store, service, interactive, managed, request
}

func TestWebsiteAccountHTTPLifecycleAndOwnership(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		for _, method := range []string{"browser", "credentials"} {
			t.Run(prefix+"/"+method, func(t *testing.T) {
				store, service, _, managed, request := websiteHTTPFixture(t, prefix)
				start := map[string]any{"displayName": "My website", "websiteUrl": "https://example.com/login", "method": method}
				for _, actor := range []struct {
					subject, role string
					status        int
				}{{"usr_alice", "viewer", 403}, {platformServiceActorID, "service", 401}} {
					if response := request(actor.subject, actor.role, "POST", "/browser-sign-ins/start", start); response.Code != actor.status {
						t.Fatalf("%s started a website sign-in: %d", actor.role, response.Code)
					}
				}
				response := request("usr_alice", "operator", "POST", "/browser-sign-ins/start", start)
				var dto browserSignInDTO
				if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &dto) != nil {
					t.Fatal("start", response.Code, response.Body.String())
				}
				flow, err := service.lookup(t.Context(), dto.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, operation := range []string{"view", "save", "cancel", "submit"} {
					if response := request("usr_bob", "admin", "POST", "/browser-sign-ins/"+flow.ID+"/"+operation, map[string]any{"revision": flow.Revision, "confirmed": operation == "save"}); response.Code != 404 {
						t.Fatalf("coworker accessed %s: %d", operation, response.Code)
					}
				}
				listed := request("usr_alice", "operator", "GET", "/browser-sign-ins", nil)
				if listed.Code != 200 || !strings.Contains(listed.Body.String(), flow.ID) || strings.Contains(listed.Body.String(), flow.ProfileID) {
					t.Fatal("private sign-in listing", listed.Code, listed.Body.String())
				}
				if response := request("usr_bob", "admin", "GET", "/browser-sign-ins", nil); response.Code != 200 || strings.Contains(response.Body.String(), flow.ID) {
					t.Fatal("coworker listed private flow")
				}
				if method == "credentials" {
					if response := request("usr_alice", "operator", "POST", "/browser-sign-ins/"+flow.ID+"/save", map[string]any{"revision": flow.Revision, "confirmed": true}); response.Code != 409 {
						t.Fatal("incomplete managed login saved", response.Code)
					}
					for _, challenge := range []struct {
						id     string
						fields map[string]string
					}{{"login-1", map[string]string{"user": "private-user-marker", "pass": "private-password-marker"}}, {"code-2", map[string]string{"code": "private-code-marker"}}} {
						response = request("usr_alice", "operator", "POST", "/browser-sign-ins/"+flow.ID+"/submit", map[string]any{"revision": flow.Revision, "interactionId": challenge.id, "fields": challenge.fields})
						if response.Code != 202 {
							t.Fatal("submit", response.Code, response.Body.String())
						}
						flow, _ = service.lookup(t.Context(), flow.ID)
					}
					if managed.submissions != 2 {
						t.Fatal("managed credential challenge not submitted exactly once")
					}
				}
				response = request("usr_alice", "operator", "POST", "/browser-sign-ins/"+flow.ID+"/save", map[string]any{"revision": flow.Revision, "confirmed": true})
				if response.Code != 202 {
					t.Fatal("save should wait for browser synchronization", response.Code, response.Body.String())
				}
				flow, _ = service.lookup(t.Context(), flow.ID)
				flow.SyncAfter = time.Now().Add(-time.Second)
				flow = writeTestBrowser(t, service, flow)
				response = request("usr_alice", "operator", "POST", "/browser-sign-ins/"+flow.ID+"/save", map[string]any{"revision": flow.Revision, "confirmed": true})
				var account ConnectedAccount
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &account) != nil || account.ConnectionID != "" || account.ConnectionIncarnationID != "" || account.AuthMode != "browser" || account.Status != "linked" {
					t.Fatal("standalone profile save", response.Code, response.Body.String())
				}
				modelResponse := request("usr_alice", "operator", "GET", "/connection-model", nil)
				var model ConnectionModel
				if modelResponse.Code != 200 || json.Unmarshal(modelResponse.Body.Bytes(), &model) != nil || len(model.Connections) != 0 || len(model.ConnectedAccounts) != 1 || model.ConnectedAccounts[0].ID != account.ID || !slices.Contains(model.Capabilities, controlCapabilityAccountWebsite) {
					t.Fatal("website account absent from empty-connection model", modelResponse.Code, modelResponse.Body.String())
				}
				if response := request("usr_bob", "admin", "GET", "/connection-model", nil); response.Code != 200 || strings.Contains(response.Body.String(), account.ID) {
					t.Fatal("coworker listed private website account")
				}
				records, _ := store.LinkedAccounts(t.Context(), "usr_alice")
				if len(records) != 1 || len(records[0].BrowserGrants) != 0 {
					t.Fatal("saving unexpectedly granted browser access")
				}
				path := "/website-accounts/" + account.ID
				for _, extra := range []string{"token", "connectionId", "ownerSubject"} {
					if response := request("usr_alice", "operator", "PATCH", path, map[string]any{"revision": account.Revision, "displayName": "Rejected", extra: "untrusted"}); response.Code != 400 {
						t.Fatal("website mutation accepted unrequested authority or credential", extra, response.Code)
					}
				}
				for _, subject := range []string{"usr_bob", "usr_admin"} {
					for _, operation := range []struct{ method, suffix string }{{"PATCH", ""}, {"POST", "/disconnect"}, {"DELETE", ""}} {
						body := map[string]any{"revision": account.Revision}
						if operation.method == "PATCH" {
							body["displayName"] = "Stolen"
						}
						if response := request(subject, "admin", operation.method, path+operation.suffix, body); response.Code != 404 {
							t.Fatal("coworker mutated website account", operation.method, response.Code)
						}
					}
				}
				response = request("usr_alice", "operator", "PATCH", path, map[string]any{"revision": account.Revision, "displayName": "Renamed website"})
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &account) != nil || account.DisplayName != "Renamed website" {
					t.Fatal("rename", response.Code, response.Body.String())
				}
				if response := request("usr_alice", "operator", "POST", path+"/disconnect", map[string]any{"revision": account.Revision - 1}); response.Code != 409 {
					t.Fatal("stale revision disconnected account", response.Code)
				}
				// Cancelling a reconnect must retain the original saved profile.
				start["accountId"], start["revision"] = account.ID, account.Revision
				response = request("usr_alice", "operator", "POST", "/browser-sign-ins/start", start)
				var replacement browserSignInDTO
				if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &replacement) != nil {
					t.Fatal("reconnect", response.Code, response.Body.String())
				}
				if response := request("usr_alice", "operator", "POST", "/browser-sign-ins/"+replacement.ID+"/cancel", map[string]any{"revision": replacement.Revision}); response.Code != 202 {
					t.Fatal("cancel reconnect", response.Code)
				}
				records, _ = store.LinkedAccounts(t.Context(), "usr_alice")
				if len(records) != 1 || records[0].Browser.ProfileID != flow.ProfileID {
					t.Fatal("cancelled reconnect replaced original profile")
				}
				response = request("usr_alice", "operator", "POST", path+"/disconnect", map[string]any{"revision": account.Revision})
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &account) != nil || account.Status != "disconnected" {
					t.Fatal("disconnect", response.Code, response.Body.String())
				}
				if response := request("usr_alice", "operator", "DELETE", path, map[string]any{"revision": account.Revision}); response.Code != 204 {
					t.Fatal("remove", response.Code, response.Body.String())
				}
				records, _ = store.LinkedAccounts(t.Context(), "usr_alice")
				if len(records) != 0 || len(store.Accounts()) != 0 {
					t.Fatal("website lifecycle left an account or created an MCP connection")
				}
			})
		}
	}
}

func TestWebsiteManagedSignInRejectsCancellationDuringProviderCall(t *testing.T) {
	for _, operation := range []string{"submit", "save"} {
		t.Run(operation, func(t *testing.T) {
			store, service, _, managed, request := websiteHTTPFixture(t, "/control/v1")
			response := request("usr_alice", "operator", "POST", "/browser-sign-ins/start", map[string]any{"displayName": "Website", "websiteUrl": "https://example.com/", "method": "credentials"})
			var dto browserSignInDTO
			if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &dto) != nil {
				t.Fatal("start", response.Code, response.Body.String())
			}
			body := map[string]any{"revision": dto.Revision}
			if operation == "submit" {
				body["interactionId"] = "login-1"
				body["fields"] = map[string]string{"user": "owner", "pass": "private-password-marker"}
			} else {
				managed.status = ManagedBrowserStatus{State: "succeeded"}
				body["confirmed"] = true
			}
			managed.onStatus = func() {
				flow, err := service.lookup(t.Context(), dto.ID)
				if err != nil {
					t.Fatal(err)
				}
				flow.State = "cleanup"
				writeTestBrowser(t, service, flow)
			}
			response = request("usr_alice", "operator", "POST", "/browser-sign-ins/"+dto.ID+"/"+operation, body)
			if response.Code != 409 || managed.submissions != 0 {
				t.Fatal("cancelled request submitted or saved", response.Code, response.Body.String())
			}
			records, _ := store.LinkedAccounts(t.Context(), "usr_alice")
			if len(records) != 0 {
				t.Fatal("cancelled request committed an account")
			}
		})
	}
}

func TestWebsiteMutationCannotReachConnectionBoundAccount(t *testing.T) {
	store, _, _, _, request := websiteHTTPFixture(t, "/control/v1")
	parent := linkedAccountFixture(t, store)
	account, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "MCP token", BearerToken: "private-token"}, accountPolicyPrecondition(parent))
	if err != nil {
		t.Fatal(err)
	}
	response := request("usr_alice", "operator", "PATCH", "/website-accounts/"+account.ID, map[string]any{"revision": account.Revision, "displayName": "Changed"})
	if response.Code != 404 {
		t.Fatal("website route mutated a connection-bound account", response.Code, response.Body.String())
	}
	records, _ := store.LinkedAccounts(t.Context(), "usr_alice")
	if len(records) != 1 || records[0].DisplayName != account.DisplayName || records[0].BearerToken != account.BearerToken {
		t.Fatal("connection-bound credentials changed")
	}
}

func TestWebsiteSignInRejectsPartialBindingAndSupersededViewer(t *testing.T) {
	_, service, interactive, _, request := websiteHTTPFixture(t, "/control/v1")
	for _, binding := range []map[string]any{{"connectionIncarnationId": "stale"}, {"connectionRevision": 1}} {
		binding["displayName"], binding["websiteUrl"] = "Website", "https://example.com/"
		if response := request("usr_alice", "operator", "POST", "/browser-sign-ins/start", binding); response.Code != 400 {
			t.Fatal("accepted partial connection binding", response.Code)
		}
	}
	if interactive.profiles != 0 {
		t.Fatal("malformed request allocated a browser")
	}
	response := request("usr_alice", "operator", "POST", "/browser-sign-ins/start", map[string]any{"displayName": "Website", "websiteUrl": "https://example.com/"})
	var dto browserSignInDTO
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &dto) != nil {
		t.Fatal("start", response.Code, response.Body.String())
	}
	interactive.onView = func() {
		flow, err := service.lookup(t.Context(), dto.ID)
		if err != nil {
			t.Fatal(err)
		}
		flow.State = "cleanup"
		writeTestBrowser(t, service, flow)
	}
	response = request("usr_alice", "operator", "POST", "/browser-sign-ins/"+dto.ID+"/view", map[string]any{"revision": dto.Revision})
	if response.Code != 409 || strings.Contains(response.Body.String(), "viewerUrl") {
		t.Fatal("returned viewer after concurrent cancellation", response.Code, response.Body.String())
	}
}
