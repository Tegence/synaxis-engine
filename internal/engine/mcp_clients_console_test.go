package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestHostedMCPClientConsoleScopesRegistrationsBySubjectAndNamespace(t *testing.T) {
	mux, store, _, key, now, team, private := hostedNamespaceConsole(t)

	// An administrator may register a client for another platform subject,
	// which is useful for delegated setup; the registration remains bound to
	// that subject rather than the administrator who created it.
	ownerResponse := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients", `{"name":"Owner Claude","subject":"usr_owner","connectionNamespaceIds":["`+private.ID+`"]}`)
	if ownerResponse.Code != http.StatusCreated {
		t.Fatalf("owner client create = %d: %s", ownerResponse.Code, ownerResponse.Body)
	}
	var ownerClient mcpClientDTO
	if err := json.Unmarshal(ownerResponse.Body.Bytes(), &ownerClient); err != nil {
		t.Fatal(err)
	}

	operatorResponse := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/mcp-clients", `{"name":"My Codex","connectionNamespaceIds":["`+team.ID+`"]}`)
	if operatorResponse.Code != http.StatusCreated {
		t.Fatalf("operator client create = %d: %s", operatorResponse.Code, operatorResponse.Body)
	}
	var client mcpClientDTO
	if err := json.Unmarshal(operatorResponse.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	if client.Subject != "usr_operator" || client.Status != MCPClientStatusActive || !client.CanManage || len(client.ConnectionNamespaceIDs) != 1 || client.ConnectionNamespaceIDs[0] != team.ID {
		t.Fatalf("operator client = %+v", client)
	}

	// An operator cannot impersonate another Platform user nor discover an
	// ungranted credential folder by attempting to assign it to their client.
	for _, attempt := range []struct {
		body string
		want int
	}{
		{`{"name":"Other","subject":"usr_owner","connectionNamespaceIds":["` + team.ID + `"]}`, http.StatusForbidden},
		{`{"name":"Private","connectionNamespaceIds":["` + private.ID + `"]}`, http.StatusNotFound},
	} {
		response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/mcp-clients", attempt.body)
		if response.Code != attempt.want {
			t.Errorf("operator client create %s = %d body=%s; want %d", attempt.body, response.Code, response.Body, attempt.want)
		}
	}

	list := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/mcp-clients", "")
	if list.Code != http.StatusOK {
		t.Fatalf("operator client list = %d: %s", list.Code, list.Body)
	}
	var clients []mcpClientDTO
	if err := json.Unmarshal(list.Body.Bytes(), &clients); err != nil || len(clients) != 1 || clients[0].ID != client.ID {
		t.Fatalf("operator client list = %#v err=%v; want only own client", clients, err)
	}
	guessed := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/mcp-clients/"+ownerClient.ID, "")
	if guessed.Code != http.StatusNotFound {
		t.Fatalf("operator read of another client = %d: %s; want 404", guessed.Code, guessed.Body)
	}

	// The OAuth binding is intentionally not browser supplied. Simulate the
	// signed consent path, then prove a console reset clears it and rotates the
	// durable generation before a fresh DCR bind.
	stored, ok := store.MCPClient(context.Background(), client.ID)
	if !ok {
		t.Fatal("operator client did not persist")
	}
	bound, err := store.BindMCPClientOAuthClient(context.Background(), stored.ID, "dcr-codex", MCPClientPrecondition{ID: stored.ID, Revision: stored.Revision}, PlatformActor{UserID: "usr_operator", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	reset := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/mcp-clients/"+client.ID+"/oauth-client/reset", `{"revision":`+jsonNumber(bound.Revision)+`}`)
	if reset.Code != http.StatusOK {
		t.Fatalf("OAuth reset = %d: %s", reset.Code, reset.Body)
	}
	var resetClient mcpClientDTO
	if err := json.Unmarshal(reset.Body.Bytes(), &resetClient); err != nil {
		t.Fatal(err)
	}
	if resetClient.OAuthBound || resetClient.Revision != bound.Revision+1 {
		t.Fatalf("reset client DTO = %+v; bound=%+v", resetClient, bound)
	}
	resetStored, _ := store.MCPClient(context.Background(), client.ID)
	if resetStored.Epoch == bound.Epoch || resetStored.OAuthClientID != "" {
		t.Fatalf("OAuth reset did not rotate durable generation: before=%+v after=%+v", bound, resetStored)
	}

	// The namespace route keeps the existing authorization guard, even after
	// the client was successfully registered.
	badScope := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPut, "/api/mcp-clients/"+client.ID+"/namespaces", `{"revision":`+jsonNumber(resetClient.Revision)+`,"connectionNamespaceIds":["`+private.ID+`"]}`)
	if badScope.Code != http.StatusNotFound {
		t.Fatalf("ungranted namespace assignment = %d: %s; want 404", badScope.Code, badScope.Body)
	}

	revoke := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/mcp-clients/"+client.ID+"/revoke", `{"revision":`+jsonNumber(resetClient.Revision)+`}`)
	if revoke.Code != http.StatusOK {
		t.Fatalf("client revoke = %d: %s", revoke.Code, revoke.Body)
	}
	var revoked mcpClientDTO
	if err := json.Unmarshal(revoke.Body.Bytes(), &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Status != MCPClientStatusRevoked || revoked.RevokedAt == "" {
		t.Fatalf("revoked DTO = %+v", revoked)
	}
	if _, ok := store.ActiveMCPClient(context.Background(), client.Slug); ok {
		t.Fatal("revoked console client remained live")
	}
}

func jsonNumber(v int64) string {
	// Local helper keeps signed test request bodies exact without importing fmt.
	return strconv.FormatInt(v, 10)
}
