package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestControlMCPClientIndividualConnectionsStayScoped(t *testing.T) {
	mux, store, key, now, team := newHostedControlConsole(t)
	ctx := context.Background()
	for _, name := range []string{"chosen", "sibling"} {
		if err := store.Create(ctx, Account{Name: name, URL: "https://connections.example/mcp", AuthMode: "token", BearerToken: "secret", ConnectionNamespaceID: team.ID}); err != nil {
			t.Fatal(err)
		}
	}
	response := controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Scoped","connectionIds":["chosen"]}`)
	client := decodeControlClient(t, response, http.StatusCreated)
	if !sameStrings(client.ConnectionIDs, []string{"chosen"}) || len(client.ConnectionNamespaceIDs) != 0 {
		t.Fatalf("unexpected grants: %+v", client)
	}
	if strings.Contains(response.Body.String(), "connection_grants") || strings.Contains(response.Body.String(), "accti_") || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("internal grant identity leaked: %s", response.Body)
	}
	stored, _ := store.MCPClient(ctx, client.ID)
	chosen, _ := store.Account("chosen")
	sibling, _ := store.Account("sibling")
	if !mcpClientDeliversAccount(stored, chosen) || mcpClientDeliversAccount(stored, sibling) {
		t.Fatal("single-connection request exposed its sibling")
	}
	path := "/control/v1/mcp-clients/" + client.ID + "/namespaces"
	body, _ := json.Marshal(map[string]any{"connectionNamespaceIds": []string{}, "connectionIds": []string{"sibling"}, "revision": client.Revision})
	next := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, path, string(body)), http.StatusOK)
	changed, _ := store.MCPClient(ctx, client.ID)
	if next.Revision != client.Revision+1 || changed.Epoch == stored.Epoch || mcpClientDeliversAccount(changed, chosen) || !mcpClientDeliversAccount(changed, sibling) {
		t.Fatal("atomic exact-scope update failed")
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, path, string(body)), http.StatusConflict, controlCodeRevisionMismatch)
	// A connection outside the actor's delegated folders remains unreadable.
	private, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Private", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: "private", URL: "https://private.example/mcp", AuthMode: "token", BearerToken: "hidden", ConnectionNamespaceID: private.ID}); err != nil {
		t.Fatal(err)
	}
	expectControlProblem(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", `{"name":"No","connectionIds":["private"]}`), http.StatusNotFound, controlCodeNotFound)
	// Namespace-only old clients preserve exact grants; explicit [] clears them.
	legacy := fmt.Sprintf(`{"connectionNamespaceIds":[],"revision":%d}`, next.Revision)
	preserved := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, path, legacy), http.StatusOK)
	if !sameStrings(preserved.ConnectionIDs, []string{"sibling"}) {
		t.Fatal("old namespace client erased exact grants")
	}
	clear := fmt.Sprintf(`{"connectionNamespaceIds":[],"connectionIds":[],"revision":%d}`, preserved.Revision)
	cleared := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, path, clear), http.StatusOK)
	if len(cleared.ConnectionIDs) != 0 {
		t.Fatal("explicit empty exact scope was not cleared")
	}
}
