package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// The console's /api/servers routes reach the same accounts as the control
// v1 connections group. A caller-delegated account keeps the group's rules
// there too: on a hosted Engine only the service actor writes it (which it
// does through /control/v1/connections), and no edit may turn it into a
// personal or member-credentials connection.

func TestConsoleServersCallerDelegatedWritesServiceOnly(t *testing.T) {
	store := newFileConnectionsStore(t)
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	h.putToken(platformServiceActorID, "service", created.Revision, testDelegatedListingToken)
	before, _ := store.Account(h.name)
	server := "/api/servers/" + h.name
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}} {
		for _, write := range []struct{ method, path, body string }{
			{http.MethodPatch, server, `{"displayName":"Renamed"}`},
			{http.MethodPatch, server, `{"memberCredentials":true}`},
			{http.MethodPatch, server, `{"connectionScope":"personal","ownerSubject":"` + actor.user + `"}`},
			{http.MethodPut, server + "/token", `{"token":"other-token-0123456789"}`},
			{http.MethodPost, server + "/token", `{"token":"other-token-0123456789"}`},
			{http.MethodDelete, server, ""},
		} {
			response := h.request(actor.user, actor.role, write.method, write.path, write.body, nil)
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s %s %s status=%d body=%s; want 403", actor.role, write.method, write.path, response.Code, response.Body)
			}
			assertNoConnectionSecrets(t, response.Body.String())
			after, found := store.Account(h.name)
			if !found || after.Revision != before.Revision || after.Label != before.Label ||
				after.ConnectionScope != before.ConnectionScope || after.MemberCredentials || !after.CallerDelegated ||
				after.BearerToken != before.BearerToken || after.ClientSecret != before.ClientSecret {
				t.Fatalf("%s %s %s changed the caller-delegated account: %+v", actor.role, write.method, write.path, after)
			}
		}
	}
	// Plain connections keep the console's owner and admin writes.
	plain := newConnectionsTestHarness(t, store)
	plainCreated := decodeTestConnection(t, plain.service(http.MethodPost, "/control/v1/connections", plain.plainBody()), http.StatusCreated)
	renamed := plain.request("usr_admin", "admin", http.MethodPatch, "/api/servers/"+plain.name, `{"displayName":"Renamed"}`, nil)
	if renamed.Code != http.StatusOK || !strings.Contains(renamed.Body.String(), `"displayName":"Renamed"`) {
		t.Fatalf("plain rename status=%d body=%s (created %+v)", renamed.Code, renamed.Body, plainCreated)
	}
}

// TestConsoleServersKeepCallerDelegatedAccountValid: a self-hosted Engine's
// local administrator writes caller-delegated accounts, but an /api/servers
// edit still cannot make one personal or give it member credentials, which
// the connections group refuses at create.
func TestConsoleServersKeepCallerDelegatedAccountValid(t *testing.T) {
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
	decodeTestConnection(t, local(http.MethodPost, "/control/v1/connections", h.createBody(nil)), http.StatusCreated)
	before, _ := store.Account(h.name)
	server := "/api/servers/" + h.name
	for _, body := range []string{
		`{"memberCredentials":true}`,
		`{"connectionScope":"personal","ownerSubject":"usr_owner"}`,
	} {
		response := local(http.MethodPatch, server, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("PATCH %s status=%d body=%s; want 400", body, response.Code, response.Body)
		}
		after, _ := store.Account(h.name)
		if after.Revision != before.Revision || after.MemberCredentials || after.IsPersonal() || !after.CallerDelegated {
			t.Fatalf("PATCH %s changed the account: %+v", body, after)
		}
	}
	renamed := local(http.MethodPatch, server, `{"displayName":"Renamed"}`)
	if renamed.Code != http.StatusOK || !strings.Contains(renamed.Body.String(), `"callerDelegated"`) {
		t.Fatalf("local rename status=%d body=%s", renamed.Code, renamed.Body)
	}
}
