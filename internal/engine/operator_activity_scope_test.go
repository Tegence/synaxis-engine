package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorActivityIsCallerScopedEvenForManagedSharedFolders(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	for _, call := range []CallRecord{
		{Account: "team_notion", CallerSubject: "usr_operator", Tool: "own-human"},
		{Account: "team_notion", CallerSubject: "agt_owned", Tool: "own-agent"},
		{Account: "team_notion", CallerSubject: "usr_other", Tool: "other-human"},
		{Account: "team_notion", CallerSubject: "agt_other", Tool: "other-agent"},
		{Account: "team_notion", Tool: "unknown-caller"},
	} {
		store.LogCall(call)
	}
	request := func(path, signedSubjects string) (int, string) {
		claims := actorClaimsForTest(now, http.MethodGet, path, nil)
		claims.UserID, claims.Role, claims.WorkSubjects = "usr_operator", "operator", signedSubjects
		r := actorRequest(http.MethodGet, path, nil, signActorAssertionForTest(t, key, claims))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("X-Synaxis-Work-Subjects", "agt_other,usr_other")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, r)
		return response.Code, response.Body.String()
	}
	code, body := request("/api/logs", "usr_operator,agt_owned")
	var calls []CallRecord
	if code != http.StatusOK || json.Unmarshal([]byte(body), &calls) != nil || len(calls) != 2 || calls[0].Tool != "own-agent" || calls[1].Tool != "own-human" {
		t.Fatalf("operator activity=%d %s", code, body)
	}
	for _, path := range []string{"/api/logs/3", "/api/logs/4", "/api/logs/5"} {
		code, body = request(path, "usr_operator,agt_owned")
		if code != http.StatusNotFound || strings.Contains(body, "other-") {
			t.Fatalf("foreign detail=%d %s", code, body)
		}
	}
	code, body = request("/api/logs", "")
	if code != http.StatusOK || strings.Contains(body, "own-agent") || strings.Contains(body, "other-") || !strings.Contains(body, "own-human") {
		t.Fatalf("unsigned agent scope accepted=%d %s", code, body)
	}
}
