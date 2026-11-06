package engine

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The console account list tells a management UI which accounts are
// caller-delegated (so it can say approvals happen at the upstream instead of
// offering an approval switch the Engine refuses), with the same block as the
// control-v1 connection DTO and never a secret.
func TestConsoleServerListMarksCallerDelegatedAccounts(t *testing.T) {
	mux, token, _, _ := newCallerDelegatedConsole(t)
	rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/servers", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/servers = %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, secret := range []string{"secret_0123456789abcdef0123456789abcdef", "listing-key"} {
		if strings.Contains(body, secret) {
			t.Fatalf("account list leaks a credential: %s", body)
		}
	}
	var accounts []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("decode account list: %v", err)
	}
	byName := map[string]map[string]any{}
	for _, account := range accounts {
		byName[account["toolPrefix"].(string)] = account
	}
	delegated, ok := byName["delegated"]["callerDelegated"].(map[string]any)
	if !ok {
		t.Fatalf("delegated account has no callerDelegated block: %+v", byName["delegated"])
	}
	want := map[string]any{
		"tokenEndpoint":   "https://delegated.example/api/v1/mcp/token",
		"clientId":        "client_test",
		"resource":        "https://delegated.example/api/v1/mcp",
		"clientSecretSet": true,
	}
	if len(delegated) != len(want) {
		t.Fatalf("callerDelegated = %+v; want exactly %+v", delegated, want)
	}
	for key, value := range want {
		if delegated[key] != value {
			t.Fatalf("callerDelegated.%s = %v; want %v", key, delegated[key], value)
		}
	}
	if _, present := byName["plain"]["callerDelegated"]; present {
		t.Fatalf("plain account carries callerDelegated: %+v", byName["plain"])
	}
}
