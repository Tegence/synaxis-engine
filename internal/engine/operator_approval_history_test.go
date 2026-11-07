package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOperatorApprovalHistoryExcludesOtherCallersInManagedFolders(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	account, _ := store.Account("team_notion")
	for _, call := range []PendingCall{
		{ID: "own-human", CallerSubject: "usr_operator", Status: ApprovalApproved},
		{ID: "own-agent", CallerSubject: "agt_owned", Status: ApprovalDenied},
		{ID: "foreign-approved", CallerSubject: "usr_other", Status: ApprovalApproved},
		{ID: "foreign-denied", CallerSubject: "agt_other", Status: ApprovalDenied},
		{ID: "unknown-caller", Status: ApprovalExpired},
		{ID: "delegated-pending", CallerSubject: "agt_other", Status: ApprovalPending},
	} {
		status := call.Status
		call.Status = ApprovalPending
		expires := time.Now().Add(time.Hour)
		if status == ApprovalExpired {
			expires = time.Now().Add(-time.Hour)
		}
		call.ExpiresAt = &expires
		call.TS = expires.Add(-time.Hour)
		call.Account, call.Tool = account.Name, "write"
		call.AccountIncarnationID, call.AccountRevision = account.IncarnationID, account.Revision
		call.Args = map[string]any{"text": call.ID}
		if err := store.LogPending(t.Context(), call); err != nil {
			t.Fatal(err)
		}
		if status == ApprovalExpired {
			if _, err := store.ExpirePending(t.Context(), call.ID, time.Now()); err != nil {
				t.Fatal(err)
			}
		} else if status != ApprovalPending {
			if _, err := store.DecidePending(t.Context(), call.ID, ApprovalDecision{Status: status, Actor: "platform:usr_operator"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	claims := actorClaimsForTest(now, http.MethodGet, "/api/approvals", nil)
	claims.UserID, claims.Role, claims.WorkSubjects = "usr_operator", "operator", "usr_operator,agt_owned"
	r := actorRequest(http.MethodGet, "/api/approvals", nil, signActorAssertionForTest(t, key, claims))
	r.Header.Set("Authorization", "Bearer machine-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var calls []PendingCall
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &calls) != nil {
		t.Fatalf("approvals=%d %s", w.Code, w.Body)
	}
	want := map[string]bool{"own-human": true, "own-agent": true, "delegated-pending": true}
	for _, call := range calls {
		if !want[call.ID] {
			t.Errorf("Operator received another caller's retained approval metadata: %s", call.ID)
		}
		delete(want, call.ID)
		if call.ID == "delegated-pending" && (call.CanDecide == nil || !*call.CanDecide) {
			t.Error("explicitly delegated pending approval must remain actionable")
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing own history or delegated approval: %v", want)
	}
	for _, id := range []string{"foreign-approved", "foreign-denied", "unknown-caller"} {
		for _, action := range []string{"approve", "deny"} {
			response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodPost, "/api/approvals/"+id+"/"+action, "{}")
			if response.Code != http.StatusNotFound {
				t.Errorf("foreign history action %s/%s: %d %s", id, action, response.Code, response.Body)
			}
		}
	}
}
