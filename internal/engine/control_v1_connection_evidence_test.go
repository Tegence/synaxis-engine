package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestControlConnectionEvidenceUsesOnlySuccessfulCurrentClientCalls(t *testing.T) {
	mux, store, key, now, team := newHostedControlConsole(t)
	client := decodeControlClient(t, controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/control/v1/mcp-clients", `{"name":"Evidence","connectionNamespaceIds":["`+team.ID+`"]}`), http.StatusCreated)
	stored, _ := store.MCPClient(context.Background(), client.ID)
	call := CallRecord{TS: now.Add(-time.Minute), Connector: client.Slug, EndpointKind: endpointKindClient, EndpointGeneration: stored.Epoch, Tool: "library_skill_activation", OK: true, Args: "private-args", Result: "private-result"}
	store.LogCall(call)
	call.Tool = "library_memory_recall"
	call.TS = now.Add(-30 * time.Second)
	store.LogCall(call)
	for _, variant := range []string{"other-client", "old-epoch", "connector", "failed"} {
		invalid := call
		invalid.TS = now
		switch variant {
		case "other-client":
			invalid.Connector = "other"
		case "old-epoch":
			invalid.EndpointGeneration = "old"
		case "connector":
			invalid.EndpointKind = endpointKindConnector
		case "failed":
			invalid.OK = false
		}
		store.LogCall(invalid)
	}
	path := "/control/v1/mcp-clients/" + client.ID + "/connection-evidence"
	response := controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, path, "")
	if response.Code != 200 {
		t.Fatalf("%d %s", response.Code, response.Body)
	}
	var got controlConnectionEvidence
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ToolCallAt == nil || !got.ToolCallAt.Equal(now.Add(-30*time.Second)) || got.SkillsRetrievedAt == nil || !got.SkillsRetrievedAt.Equal(now.Add(-time.Minute)) || got.MemoryRecalledAt == nil || !got.MemoryRecalledAt.Equal(now.Add(-30*time.Second)) {
		t.Fatalf("wrong evidence %+v", got)
	}
	if strings.Contains(response.Body.String(), "private-") || strings.Contains(response.Body.String(), "library_memory") {
		t.Fatal("payload or tool names exposed")
	}
	for _, actor := range []struct {
		user, role string
		status     int
	}{{"usr_other", "operator", 404}, {"usr_operator", "viewer", 403}} {
		denied := controlRequest(t, mux, key, now, actor.user, actor.role, http.MethodGet, path, "")
		if denied.Code != actor.status {
			t.Errorf("%s: %d %s", actor.role, denied.Code, denied.Body)
		}
	}
	response = controlRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, path, "{}")
	if response.Code != 405 {
		t.Errorf("method status %d", response.Code)
	}
}
