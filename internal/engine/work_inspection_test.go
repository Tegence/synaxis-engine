package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateToolPayloadsRequireSignedInspectionAndNeverDelegateDecisions(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	ctx := t.Context()
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Member private", CreatedBy: "usr_member", OwnerSubject: "usr_member"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Create(ctx, Account{Name: "personal", URL: "https://invalid.example/mcp", ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_member", ConnectionNamespaceID: folder.ID, AuthMode: "token", BearerToken: "test-secret"}); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account("personal")
	store.LogCall(CallRecord{CallerSubject: "usr_member", AccountIncarnationID: account.IncarnationID, AccountOwnerSubject: account.OwnerSubject, Account: "personal", Tool: "read", Args: "PRIVATE-ARGS", Result: "PRIVATE-RESULT"})
	request := func(actor, role, method, path, body, event string) *httptest.ResponseRecorder {
		claims := actorClaimsForTest(now, method, path, []byte(body))
		claims.UserID = actor
		claims.Role = role
		claims.InspectionEventID = event
		r := actorRequest(method, path, []byte(body), signActorAssertionForTest(t, key, claims))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("X-Synaxis-Inspection-Reason", "browser spoof")
		r.Header.Set("X-Synaxis-Inspection-Event", "spoof")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	denied := request("usr_admin", "admin", http.MethodGet, "/api/logs/1", "", "")
	if denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), "PRIVATE-") || !strings.Contains(denied.Body.String(), "inspection_required") {
		t.Fatalf("unlogged=%d %s", denied.Code, denied.Body)
	}
	own := request("usr_member", "operator", http.MethodGet, "/api/logs/1", "", "")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), "PRIVATE-RESULT") {
		t.Fatalf("own=%d %s", own.Code, own.Body)
	}
	read := request("usr_admin", "admin", http.MethodGet, "/api/logs/1", "", "aev_recorded")
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), "PRIVATE-RESULT") {
		t.Fatalf("inspection=%d %s", read.Code, read.Body)
	}
	metadata := request("usr_admin", "admin", http.MethodPost, "/control/v1/work-inspection", `{"kind":"call","id":"1"}`, "")
	if metadata.Code != http.StatusOK || metadata.Body.String() != "{\"inspectionRequired\":true}\n" {
		t.Fatalf("metadata=%d %s", metadata.Code, metadata.Body)
	}
	replay := request("usr_admin", "admin", http.MethodPost, "/api/logs/1/replay", "{}", "")
	if replay.Code != http.StatusForbidden {
		t.Fatalf("foreign replay=%d %s", replay.Code, replay.Body)
	}
	for _, call := range []PendingCall{{ID: "private", Account: "personal", Tool: "write", Status: ApprovalPending, Args: map[string]any{"secret": "PRIVATE-ARG"}, DecisionNote: "PRIVATE-NOTE"}, {ID: "shared", Account: "team_notion", Tool: "write", Status: ApprovalPending, Args: map[string]any{"shared": "body"}}} {
		source, _ := store.Account(call.Account)
		call.AccountIncarnationID = source.IncarnationID
		call.AccountRevision = source.Revision
		if err := store.LogPending(ctx, call); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range []string{"", "aev_recorded"} {
		response := request("usr_admin", "admin", http.MethodGet, "/api/approvals", "", event)
		var rows []PendingCall
		if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
			t.Fatalf("rows=%d %s", response.Code, response.Body)
		}
		for _, row := range rows {
			if row.Account == "personal" {
				if row.CanDecide == nil || *row.CanDecide {
					t.Fatal("inspection delegated personal decision")
				}
				if event == "" && (!row.InspectionRequired || row.Args != nil || row.DecisionNote != "") {
					t.Fatal("private approval leaked")
				}
				if event != "" && row.Args["secret"] != "PRIVATE-ARG" {
					t.Fatal("logged inspection omitted body")
				}
			} else if row.CanDecide == nil || !*row.CanDecide || row.Args == nil {
				t.Fatal("shared approval no longer actionable")
			}
		}
	}
	ownApprovals := request("usr_member", "operator", http.MethodGet, "/api/approvals", "", "")
	if ownApprovals.Code != http.StatusOK || !strings.Contains(ownApprovals.Body.String(), `"canDecide":true`) || !strings.Contains(ownApprovals.Body.String(), "PRIVATE-ARG") {
		t.Fatalf("owner approvals=%s", ownApprovals.Body)
	}
	// Reusing the public account name cannot change historical body ownership.
	if err := store.Delete(ctx, account.Name, account.IncarnationID, account.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{Name: account.Name, URL: "https://replacement.example/mcp", ConnectionScope: ConnectionScopeShared, AuthMode: "token", BearerToken: "replacement"}); err != nil {
		t.Fatal(err)
	}
	replaced := request("usr_admin", "admin", http.MethodGet, "/api/logs/1", "", "")
	if replaced.Code != http.StatusForbidden || strings.Contains(replaced.Body.String(), "PRIVATE-RESULT") {
		t.Fatalf("replacement exposed history: %d %s", replaced.Code, replaced.Body)
	}
	staleApprovals := request("usr_admin", "admin", http.MethodGet, "/api/approvals", "", "")
	if strings.Contains(staleApprovals.Body.String(), "PRIVATE-ARG") {
		t.Fatal("replacement exposed pending history")
	}
	store.LogCall(CallRecord{Account: "team_notion", Tool: "legacy", Args: "LEGACY-PRIVATE", Result: "LEGACY-RESULT"})
	legacy := request("usr_admin", "admin", http.MethodGet, "/api/logs/2", "", "")
	if legacy.Code != http.StatusForbidden || strings.Contains(legacy.Body.String(), "LEGACY-") {
		t.Fatalf("legacy unknown ownership=%d %s", legacy.Code, legacy.Body)
	}
	action := request("usr_admin", "admin", http.MethodPost, "/api/approvals/private/approve", "{}", "")
	if action.Code != http.StatusForbidden {
		t.Fatalf("foreign approval=%d %s", action.Code, action.Body)
	}
}

func TestInspectionAssertionCannotAuthorizeOtherRoutesOrOperators(t *testing.T) {
	verifier, key, now := newActorVerifier(t)
	for _, test := range []struct{ method, path, role string }{{http.MethodGet, "/api/servers", "admin"}, {http.MethodPost, "/api/logs/1/replay", "admin"}, {http.MethodGet, "/api/logs/1", "operator"}, {http.MethodGet, "/api/logs/1/other", "admin"}} {
		claims := actorClaimsForTest(now, test.method, test.path, nil)
		claims.Role = test.role
		claims.InspectionEventID = "aev_audit"
		if _, err := verifier.VerifyRequest(actorRequest(test.method, test.path, nil, signActorAssertionForTest(t, key, claims))); err == nil {
			t.Fatalf("inspection widened %s %s %s", test.role, test.method, test.path)
		}
	}
}

func TestSharedConnectionRetainedPayloadBelongsToOriginalCaller(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	source, _ := store.Account("team_notion")
	store.LogCall(CallRecord{Account: "team_notion", AccountIncarnationID: source.IncarnationID, CallerSubject: "agt_personal", Tool: "read", Args: "PERSONAL-ARGS", Result: "PERSONAL-RESULT", Error: "PRIVATE-UPSTREAM-ERROR"})
	request := func(actor, role, path, subjects, event string) *httptest.ResponseRecorder {
		claims := actorClaimsForTest(now, http.MethodGet, path, nil)
		claims.UserID, claims.Role, claims.WorkSubjects, claims.InspectionEventID = actor, role, subjects, event
		r := actorRequest(http.MethodGet, path, nil, signActorAssertionForTest(t, key, claims))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("X-Synaxis-Work-Subjects", "agt_personal")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, actor := range []string{"usr_admin", "usr_member"} {
		response := request(actor, "admin", "/api/logs/1", "", "")
		if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "PERSONAL-") {
			t.Fatalf("shared source leaked to %s: %d %s", actor, response.Code, response.Body)
		}
	}
	summaries := request("usr_admin", "admin", "/api/logs", "", "")
	if summaries.Code != http.StatusOK || strings.Contains(summaries.Body.String(), "PRIVATE-UPSTREAM-ERROR") {
		t.Fatalf("summary leaked body: %d %s", summaries.Code, summaries.Body)
	}
	own := request("usr_member", "operator", "/api/logs/1", "usr_member,agt_personal", "")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), "PERSONAL-RESULT") {
		t.Fatalf("own agent=%d %s", own.Code, own.Body)
	}
	inspected := request("usr_admin", "admin", "/api/logs/1", "", "aev_inspection")
	if inspected.Code != http.StatusOK || !strings.Contains(inspected.Body.String(), "PERSONAL-RESULT") {
		t.Fatalf("inspected=%d %s", inspected.Code, inspected.Body)
	}
	pending := PendingCall{ID: "shared-private-caller", Account: "team_notion", AccountIncarnationID: source.IncarnationID, AccountRevision: source.Revision, CallerSubject: "agt_personal", Tool: "write", Status: ApprovalPending, Args: map[string]any{"body": "PERSONAL-ARGS"}}
	if err := store.LogPending(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	open := request("usr_admin", "admin", "/api/approvals", "", "")
	if !strings.Contains(open.Body.String(), "PERSONAL-ARGS") || !strings.Contains(open.Body.String(), `"canDecide":true`) {
		t.Fatalf("owner pending approval=%s", open.Body)
	}
	if _, err := store.DecidePending(t.Context(), pending.ID, ApprovalDecision{Status: ApprovalDenied, Actor: "usr_admin"}); err != nil {
		t.Fatal(err)
	}
	history := request("usr_admin", "admin", "/api/approvals", "", "")
	if strings.Contains(history.Body.String(), "PERSONAL-ARGS") || !strings.Contains(history.Body.String(), `"inspectionRequired":true`) {
		t.Fatalf("history leaked=%s", history.Body)
	}
	ownHistory := request("usr_member", "operator", "/api/approvals", "usr_member,agt_personal", "")
	if !strings.Contains(ownHistory.Body.String(), "PERSONAL-ARGS") || strings.Contains(ownHistory.Body.String(), `"canDecide":true`) {
		t.Fatalf("own history=%s", ownHistory.Body)
	}
}

func TestWorkSubjectAssertionsAreBoundedAndRouteScoped(t *testing.T) {
	verifier, key, now := newActorVerifier(t)
	for _, test := range []struct{ method, path, subjects string }{
		{http.MethodGet, "/api/servers", "agt_a"},
		{http.MethodPost, "/api/logs/0/replay", "agt_a"},
		{http.MethodGet, "/api/logs/1", "agt_a,agt_a"},
		{http.MethodGet, "/api/logs/1", "agt_a,,agt_b"},
	} {
		claims := actorClaimsForTest(now, test.method, test.path, nil)
		claims.WorkSubjects = test.subjects
		if _, err := verifier.VerifyRequest(actorRequest(test.method, test.path, nil, signActorAssertionForTest(t, key, claims))); err == nil {
			t.Fatalf("accepted invalid work subjects: %+v", test)
		}
	}
}

func TestRecordedCallCapturesOriginalMemberSubject(t *testing.T) {
	g, store, _ := newRecorderGateway(t)
	g.SetRecordPayloads(true)
	ctx := withMemberCaller(t.Context(), memberCaller{subject: "agt_private", workload: true})
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"linear__get_issue","arguments":{"id":"private"}}}`)
	response, _ := json.Marshal(g.mcp.HandleMessage(ctx, request))
	if !strings.Contains(string(response), "got-upstream") {
		t.Fatalf("call=%s", response)
	}
	rows := callRows(t, store, "get_issue")
	if len(rows) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	record := detail(t, store, rows[0].ID)
	if record.CallerSubject != "agt_private" || record.AccountIncarnationID == "" || record.Result == "" {
		t.Fatalf("caller provenance missing: %+v", record)
	}
}

func TestOwnedAgentCallMutationsKeepSourceAndCallerBoundaries(t *testing.T) {
	mux, store, _, key, now, _, _ := hostedNamespaceConsole(t)
	source, _ := store.Account("team_notion")
	for _, subject := range []string{"agt_owned", "agt_foreign"} {
		store.LogCall(CallRecord{Account: "team_notion", AccountIncarnationID: source.IncarnationID, AccountOwnerSubject: source.OwnerSubject, CallerSubject: subject, Tool: "search", Guard: "flagged:injection"})
	}
	request := func(path, body string) *httptest.ResponseRecorder {
		claims := actorClaimsForTest(now, http.MethodPost, path, []byte(body))
		claims.UserID, claims.Role, claims.WorkSubjects = "usr_operator", "operator", "usr_operator,agt_owned"
		r := actorRequest(http.MethodPost, path, []byte(body), signActorAssertionForTest(t, key, claims))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("X-Synaxis-Work-Subjects", "agt_foreign")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	own := request("/api/logs/1/triage", `{"action":"false_positive"}`)
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), `"triage":"false_positive"`) {
		t.Fatalf("own triage=%d %s", own.Code, own.Body)
	}
	// A record without captured arguments cannot execute, even with ownership.
	replay := request("/api/logs/1/replay", `{}`)
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "recorded payload") {
		t.Fatalf("replay bypassed live guard or lost ownership=%d %s", replay.Code, replay.Body)
	}
	for _, action := range []string{"triage", "replay"} {
		foreign := request("/api/logs/2/"+action, `{}`)
		if foreign.Code != http.StatusNotFound {
			t.Fatalf("foreign %s=%d %s", action, foreign.Code, foreign.Body)
		}
	}
	// Revoking/replacing the connection still prevents mutating retained work.
	if err := store.Delete(t.Context(), source.Name, source.IncarnationID, source.Revision); err != nil {
		t.Fatal(err)
	}
	stale := request("/api/logs/1/triage", `{"action":"false_positive"}`)
	if stale.Code != http.StatusForbidden {
		t.Fatalf("stale source=%d %s", stale.Code, stale.Body)
	}
}

// A private browser profile may belong to a shared MCP connection. The shared
// connection's managers must never inherit the profile owner's draft or decision.
func TestBrowserApprovalRemainsPrivateOnSharedConnection(t *testing.T) {
	mux, store, gateway, key, now, _, _ := hostedNamespaceConsole(t)
	source, _ := store.Account("team_notion")
	call := PendingCall{ID: "private_" + newApprovalID(), CallerSubject: "usr_member", PrivateOwnerSubject: "usr_member", Connector: "browser", Account: source.Name, AccountIncarnationID: source.IncarnationID, AccountRevision: source.Revision, ConnectionNamespaceID: source.ConnectionNamespaceID, Tool: "browser_click", Args: map[string]any{"draftText": "PRIVATE-BROWSER-DRAFT"}}
	if err := store.LogPending(t.Context(), call); err != nil {
		t.Fatal(err)
	}
	request := func(actor, role, method, path, event string) *httptest.ResponseRecorder {
		claims := actorClaimsForTest(now, method, path, nil)
		claims.UserID, claims.Role, claims.InspectionEventID = actor, role, event
		r := actorRequest(method, path, nil, signActorAssertionForTest(t, key, claims))
		r.Header.Set("Authorization", "Bearer machine-token")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	manager := request("usr_operator", "operator", "GET", "/api/approvals", "")
	if manager.Code != 200 || strings.Contains(manager.Body.String(), call.ID) || strings.Contains(manager.Body.String(), "PRIVATE-BROWSER") {
		t.Fatalf("manager inherited private approval: %d %s", manager.Code, manager.Body)
	}
	for _, event := range []string{"", "aev_logged"} {
		admin := request("usr_admin", "admin", "GET", "/api/approvals", event)
		if admin.Code != 200 || !strings.Contains(admin.Body.String(), `"canDecide":false`) {
			t.Fatalf("admin decision capability: %d %s", admin.Code, admin.Body)
		}
		if strings.Contains(admin.Body.String(), "PRIVATE-BROWSER-DRAFT") != (event != "") {
			t.Fatalf("admin inspection boundary: %s", admin.Body)
		}
	}
	for _, actor := range []struct {
		user, role string
		status     int
	}{{"usr_operator", "operator", 404}, {"usr_admin", "admin", 403}} {
		denied := request(actor.user, actor.role, "POST", "/api/approvals/"+call.ID+"/approve", "")
		if denied.Code != actor.status {
			t.Fatalf("foreign decision: %d %s", denied.Code, denied.Body)
		}
	}
	for _, route := range []struct{ method, path string }{{"GET", "/a/" + call.ID}, {"POST", "/a/" + call.ID + "/approve"}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
		if w.Code != 404 || strings.Contains(w.Body.String(), "PRIVATE-BROWSER") {
			t.Fatalf("capability link exposed private action: %d %s", w.Code, w.Body)
		}
	}
	if _, err := gateway.DecideWithMetadata(t.Context(), call.ID, ApprovalDecision{Status: ApprovalApproved, Actor: "usr_member"}); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("unverified owner label accepted: %v", err)
	}
	own := request("usr_member", "operator", "GET", "/api/approvals", "")
	if own.Code != 200 || !strings.Contains(own.Body.String(), "PRIVATE-BROWSER-DRAFT") || !strings.Contains(own.Body.String(), `"canDecide":true`) {
		t.Fatalf("owner cannot review: %d %s", own.Code, own.Body)
	}
	decided := request("usr_member", "operator", "POST", "/api/approvals/"+call.ID+"/approve", "")
	if decided.Code != 200 {
		t.Fatalf("owner cannot decide: %d %s", decided.Code, decided.Body)
	}
}
