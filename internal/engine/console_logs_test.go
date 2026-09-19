package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// newRecorderConsole puts the ConsoleAPI mux on top of the recorder gateway
// from gateway_record_test.go: real streamable-HTTP upstream with get_issue
// (read-only) + save_issue (mutating), FileStore as the audit sink.
func newRecorderConsole(t *testing.T) (*http.ServeMux, string, *Gateway, *FileStore, *int32) {
	t.Helper()
	g, fs, saves := newRecorderGateway(t)
	api := NewConsoleAPI(fs, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), g, fs, saves
}

// TestLogsAPIListAndDetail: the list stays summary-only (id/connector/decision
// present, payloads never), the detail endpoint carries args+result, and an
// unknown or malformed id maps to 404/400.
func TestLogsAPIListAndDetail(t *testing.T) {
	mux, tok, g, _, _ := newRecorderConsole(t)
	g.SetRecordPayloads(true)
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "42"})

	// LIST: summary rows now carry id; payloads are omitted entirely.
	rec, _ := doJSON(t, mux, tok, http.MethodGet, "/api/logs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/logs = %d, body %s", rec.Code, rec.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	row := list[0]
	id, ok := row["id"].(float64)
	if !ok || id <= 0 {
		t.Fatalf("list row must carry a positive id: %v", row)
	}
	for _, k := range []string{"args", "result", "connector", "decision"} {
		if _, present := row[k]; present {
			t.Fatalf("summary row must omit %q (omitempty): %v", k, row)
		}
	}
	if row["account"] != "linear" || row["tool"] != "get_issue" || row["ok"] != true {
		t.Fatalf("summary row mismatch: %v", row)
	}

	// DETAIL: full payloads.
	rec, got := doJSON(t, mux, tok, http.MethodGet, fmt.Sprintf("/api/logs/%d", int64(id)), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET detail = %d, body %s", rec.Code, rec.Body)
	}
	if got["id"] != id || got["tool"] != "get_issue" {
		t.Fatalf("detail mismatch: %v", got)
	}
	args, _ := got["args"].(string)
	result, _ := got["result"].(string)
	if !strings.Contains(args, `"id":"42"`) || !strings.Contains(result, "got-upstream") {
		t.Fatalf("detail must carry payloads: args=%q result=%q", args, result)
	}

	// Unknown id → 404; malformed id → 400.
	rec, got = doJSON(t, mux, tok, http.MethodGet, "/api/logs/999999", "")
	if rec.Code != http.StatusNotFound || got["error"] != "call not found" {
		t.Fatalf("unknown id = %d %v, want 404", rec.Code, got)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/logs/nope", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed id = %d, want 400", rec.Code)
	}
	// Wrong method → 405.
	rec, _ = doJSON(t, mux, tok, http.MethodDelete, fmt.Sprintf("/api/logs/%d", int64(id)), "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE detail = %d, want 405", rec.Code)
	}
}

// doJSONWithHeaders is doJSON plus arbitrary extra request headers — used for
// the Activity "Load older" keyset cursor, which travels as request headers
// rather than query parameters (see logsBeforeTSHeader/logsBeforeIDHeader in
// console.go for why: the hosted Platform actor assertion rejects any
// request carrying a query string).
func doJSONWithHeaders(t *testing.T, mux *http.ServeMux, token, method, path, body string, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	if b := rec.Body.Bytes(); len(b) > 0 && b[0] == '{' {
		_ = json.Unmarshal(b, &out)
	}
	return rec, out
}

// TestLogsAPICursorPaging: the default (no-cursor) response is unaffected by
// the new cursor headers, a valid before-ts/before-id cursor pages backward
// to the next older rows, and a malformed or partial cursor is a 400 via the
// existing error shape.
func TestLogsAPICursorPaging(t *testing.T) {
	mux, tok, _, fs, _ := newRecorderConsole(t)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const total = 5
	for i := 0; i < total; i++ {
		fs.LogCall(CallRecord{
			Account: "linear", Tool: fmt.Sprintf("t%d", i), OK: true,
			TS: base.Add(time.Duration(i) * time.Second),
		})
	}

	// No cursor: newest-first, byte-compatible default shape (a JSON array).
	rec, _ := doJSON(t, mux, tok, http.MethodGet, "/api/logs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/logs = %d, body %s", rec.Code, rec.Body)
	}
	var page1 []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &page1); err != nil || len(page1) != total {
		t.Fatalf("default list = %s (err %v)", rec.Body, err)
	}
	if page1[0]["tool"] != "t4" || page1[total-1]["tool"] != "t0" {
		t.Fatalf("default list not newest-first: %v", page1)
	}

	// A cursor off the 3rd-newest row (t2) pages to the 2 older rows (t1, t0).
	cursor := page1[2]
	cursorTS, _ := cursor["ts"].(string)
	cursorID := int64(cursor["id"].(float64))
	cursorHeaders := map[string]string{
		logsBeforeTSHeader: cursorTS,
		logsBeforeIDHeader: fmt.Sprint(cursorID),
	}
	rec, _ = doJSONWithHeaders(t, mux, tok, http.MethodGet, "/api/logs", "", cursorHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/logs with cursor headers = %d, body %s", rec.Code, rec.Body)
	}
	var page2 []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &page2); err != nil || len(page2) != 2 {
		t.Fatalf("cursor page = %s (err %v)", rec.Body, err)
	}
	if page2[0]["tool"] != "t1" || page2[1]["tool"] != "t0" {
		t.Fatalf("cursor page not the expected older rows: %v", page2)
	}

	// Garbage or partial cursors → 400, with the existing error shape.
	for name, headers := range map[string]map[string]string{
		"garbage ts":        {logsBeforeTSHeader: "not-a-time", logsBeforeIDHeader: fmt.Sprint(cursorID)},
		"garbage id":        {logsBeforeTSHeader: cursorTS, logsBeforeIDHeader: "nope"},
		"missing before_id": {logsBeforeTSHeader: cursorTS},
		"missing before_ts": {logsBeforeIDHeader: fmt.Sprint(cursorID)},
	} {
		rec, got := doJSONWithHeaders(t, mux, tok, http.MethodGet, "/api/logs", "", headers)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: GET /api/logs = %d, want 400 (body %s)", name, rec.Code, rec.Body)
		}
		if _, present := got["error"]; !present {
			t.Fatalf("%s: 400 missing error field: %v", name, got)
		}
	}
}

// hostedNamespaceRequestWithHeaders is hostedNamespaceRequest plus arbitrary
// extra request headers — used for the Activity "Load older" keyset cursor,
// which travels as headers, not query parameters (see
// logsBeforeTSHeader/logsBeforeIDHeader in console.go for why). Headers are
// outside what the signed actor assertion binds (Method+Path+Body only), so
// adding them after signing does not invalidate the assertion.
func hostedNamespaceRequestWithHeaders(
	t *testing.T,
	mux *http.ServeMux,
	key ed25519.PrivateKey,
	now time.Time,
	userID, role, method, requestPath, body string,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes := []byte(body)
	claims := actorClaimsForTest(now, method, requestPath, bodyBytes)
	claims.UserID, claims.Role = userID, role
	request := actorRequest(method, requestPath, bodyBytes, signActorAssertionForTest(t, key, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

// TestHostedOperatorLogsPaginationBackfillsPastInvisibleRows is the
// regression test for the "Load older" silent-truncation bug: a
// namespace-scoped operator's visible accounts are a strict subset of a
// busier shared platform's audit volume, so a raw store page routinely mixes
// visible and invisible rows. Before the fix, handleLogs filtered exactly one
// raw page and returned whatever survived — a raw page with, say, 80 visible
// rows out of 100 came back as an 80-row response, and the frontend's
// hasMoreLogs (items.length === LOGS_PAGE_SIZE) reads anything short of a
// full page as "no more history," silently hiding "Load older" even though
// substantially more visible history exists just past the unfetched
// remainder.
//
// This seeds 320 rows on a 1-in-5 "private" (invisible to the operator)
// cadence, so every 100-row raw window contains a real mix, and proves:
//  1. the first page backfills past the invisible rows to a FULL 100-row
//     page instead of returning short;
//  2. a "Load older" continuation (the same cursor request the frontend
//     issues off the oldest loaded row) also backfills to a full page, with
//     the correct next 100 visible rows — i.e. the cursor path shares the
//     same backfill behavior as the first page, not a separate code path;
//  3. both pages are exactly the visible rows in newest-first order, with no
//     gaps or duplicates across the page boundary;
//  4. across both requests — each internally issuing multiple raw store
//     fetches to backfill past the invisible rows — visibility stays
//     batched: zero per-row Account() store lookups. This is the same bound
//     TestHostedOperatorActivityListBatchesVisibilityChecks proves for a
//     single page; here it must also hold across handleLogs' internal
//     multi-fetch backfill loop and across the cursor ("Load older") branch,
//     proving the rebase onto PR #42's batched-visibility helpers did not
//     reintroduce a per-row store call anywhere in the paginated path.
//  5. the "Load older" cursor request — signed and routed exactly as the
//     hosted Platform proxy does for a real operator — succeeds. It travels
//     as logsBeforeTSHeader/logsBeforeIDHeader request headers rather than a
//     query string: the hosted actor assertion binds Method+Path+Body and
//     unconditionally rejects any request whose path carries a query string
//     (normalizedActorRequestPath in actor_assertion.go), and "operator" is
//     reachable ONLY through that hosted assertion path (self-hosted mode
//     has no operator role at all — connectionNamespaceActor always returns
//     "owner" there). A query-string cursor would therefore 401 for every
//     operator, in the only place operators exist — this test's use of the
//     real hosted request-signing helper is what proves the header-based
//     transport actually clears that boundary.
func TestHostedOperatorLogsPaginationBackfillsPastInvisibleRows(t *testing.T) {
	ctx := context.Background()
	base, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &accountQueryCountingStore{FileStore: base}
	team, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Team", CreatedBy: "usr_owner",
		ManagerGrants: []ConnectionNamespaceManagerGrant{{Subject: "usr_operator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	private, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "Private", CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{
			Name: "team_notion", Label: "Team Notion", Group: team.Label,
			URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team-secret",
			ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
		},
		{
			Name: "private_notion", Label: "Private Notion", Group: private.Label,
			URL: "https://private.example/mcp", AuthMode: "token", BearerToken: "private-secret",
			ConnectionNamespaceID: private.ID, ConnectionScope: ConnectionScopeShared,
		},
	} {
		if err := store.Create(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	verifier, key, now := newActorVerifier(t)
	gateway := NewGateway(store, nil)
	gateway.SetAudit(store)
	api := NewConsoleAPI(
		store,
		gateway,
		nil,
		"local-password",
		"local-secret",
		"https://engine.example",
		"https://app.example",
		"",
		WithAdminToken("machine-token"),
		WithLocalAdminAuth(false),
		WithPlatformActorVerifier(verifier),
	)
	mux := http.NewServeMux()
	api.Routes(mux)

	// 320 rows, oldest to newest; every 5th belongs to the invisible Private
	// account, so every 100-row raw window mixes visible and invisible rows.
	const total = 320
	baseTS := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	toolName := func(i int) string { return fmt.Sprintf("t%d", i) }
	for i := 0; i < total; i++ {
		account := "team_notion"
		if i%5 == 0 {
			account = "private_notion"
		}
		store.LogCall(CallRecord{Account: account, Tool: toolName(i), TS: baseTS.Add(time.Duration(i) * time.Second)})
	}
	var wantVisible []string // tool names, newest-first
	for i := total - 1; i >= 0; i-- {
		if i%5 != 0 {
			wantVisible = append(wantVisible, toolName(i))
		}
	}
	if len(wantVisible) < 2*logsPageSize {
		t.Fatalf("fixture too small: only %d visible rows, want >= %d", len(wantVisible), 2*logsPageSize)
	}
	toolNamesOf := func(recs []CallRecord) []string {
		out := make([]string, len(recs))
		for i, r := range recs {
			out[i] = r.Tool
		}
		return out
	}

	store.accountQueries.Store(0)
	response := hostedNamespaceRequest(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/logs", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/logs = %d: %s", response.Code, response.Body)
	}
	var page1 []CallRecord
	if err := json.Unmarshal(response.Body.Bytes(), &page1); err != nil {
		t.Fatalf("decode page1: %v", err)
	}
	if len(page1) != logsPageSize {
		t.Fatalf("page1 = %d rows, want a FULL page of %d (must backfill past invisible rows, not return short): %v",
			len(page1), logsPageSize, toolNamesOf(page1))
	}
	wantPage1 := wantVisible[:logsPageSize]
	for i, rec := range page1 {
		if rec.Tool != wantPage1[i] {
			t.Fatalf("page1 mismatch at row %d: got=%v want=%v", i, toolNamesOf(page1), wantPage1)
		}
	}

	// "Load older": cursor off the oldest row of page1, exactly as the
	// frontend's loadOlderLogs does. The cursor travels as request headers,
	// not query parameters: the hosted actor assertion signed below binds
	// Method+Path+Body only (see actorClaimsForTest), so this — unlike a
	// ?before_ts= query string — is not rejected by
	// normalizedActorRequestPath's empty-RawQuery requirement.
	oldest := page1[len(page1)-1]
	response = hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_operator", "operator", http.MethodGet, "/api/logs", "", map[string]string{
		logsBeforeTSHeader: oldest.TS.Format(time.RFC3339Nano),
		logsBeforeIDHeader: fmt.Sprint(oldest.ID),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/logs with cursor headers = %d: %s", response.Code, response.Body)
	}
	var page2 []CallRecord
	if err := json.Unmarshal(response.Body.Bytes(), &page2); err != nil {
		t.Fatalf("decode page2: %v", err)
	}
	if len(page2) != logsPageSize {
		t.Fatalf("page2 (\"Load older\") = %d rows, want a FULL page of %d: %v", len(page2), logsPageSize, toolNamesOf(page2))
	}
	wantPage2 := wantVisible[logsPageSize : 2*logsPageSize]
	for i, rec := range page2 {
		if rec.Tool != wantPage2[i] {
			t.Fatalf("page2 mismatch at row %d: got=%v want=%v", i, toolNamesOf(page2), wantPage2)
		}
	}

	if got := store.accountQueries.Load(); got != 0 {
		t.Fatalf("paginated operator /api/logs issued %d per-row Account queries across the backfill, want none (batched read)", got)
	}
}

// TestLogsAPIReplayForceGating: replaying a mutating tool without force is a
// 409 (and must not dispatch upstream); with {"force": true} it dispatches and
// returns the fresh record with payloads. Unknown id → 404.
func TestLogsAPIReplayForceGating(t *testing.T) {
	mux, tok, g, fs, saves := newRecorderConsole(t)
	g.SetRecordPayloads(true)
	callMainTool(t, g, "linear__save_issue", map[string]any{"k": "v"})
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("setup call did not dispatch, saves=%d", atomic.LoadInt32(saves))
	}
	origID := callRows(t, fs, "save_issue")[0].ID

	// No force (empty body works too) → 409, nothing dispatched.
	rec, got := doJSON(t, mux, tok, http.MethodPost, fmt.Sprintf("/api/logs/%d/replay", origID), `{}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replay without force = %d %v, want 409", rec.Code, got)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatal("409 replay must not dispatch upstream")
	}

	// Force → 200 with the NEW record (decision replay, payloads included).
	rec, got = doJSON(t, mux, tok, http.MethodPost, fmt.Sprintf("/api/logs/%d/replay", origID), `{"force":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("forced replay = %d, body %s", rec.Code, rec.Body)
	}
	if atomic.LoadInt32(saves) != 2 {
		t.Fatalf("forced replay must dispatch upstream, saves=%d", atomic.LoadInt32(saves))
	}
	if got["decision"] != "replay" || got["ok"] != true || got["account"] != "linear" || got["tool"] != "save_issue" {
		t.Fatalf("replay record mismatch: %v", got)
	}
	args, _ := got["args"].(string)
	result, _ := got["result"].(string)
	if !strings.Contains(args, `"k":"v"`) || !strings.Contains(result, "saved-upstream") {
		t.Fatalf("replay response must carry payloads: args=%q result=%q", args, result)
	}
	// A fresh audit row landed for the replay.
	if rows := callRows(t, fs, "save_issue"); len(rows) != 2 {
		t.Fatalf("want 2 audit rows (original + replay), got %d", len(rows))
	}

	// Read-only tool replays without force straight to 200.
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "7"})
	getID := callRows(t, fs, "get_issue")[0].ID
	rec, got = doJSON(t, mux, tok, http.MethodPost, fmt.Sprintf("/api/logs/%d/replay", getID), "")
	if rec.Code != http.StatusOK || got["decision"] != "replay" {
		t.Fatalf("read-only replay = %d %v, want 200", rec.Code, got)
	}

	// Unknown id → 404; summary-only row (no payload) → 400.
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/logs/999999/replay", `{"force":true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id replay = %d, want 404", rec.Code)
	}
	g.SetRecordPayloads(false)
	callMainTool(t, g, "linear__get_issue", nil)
	bareID := callRows(t, fs, "get_issue")[0].ID
	rec, got = doJSON(t, mux, tok, http.MethodPost, fmt.Sprintf("/api/logs/%d/replay", bareID), "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(got["error"].(string), "no recorded payload") {
		t.Fatalf("unrecorded replay = %d %v, want 400 'no recorded payload'", rec.Code, got)
	}
}

// TestLogsAPI501WithoutAuditSink mirrors the ConnectorStore 501 test: a store
// without the AuditSink facet gets 501 from detail and replay (the list
// endpoint stays a soft empty 200 for backward compatibility).
func TestLogsAPI501WithoutAuditSink(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	g := NewGateway(accountsOnly{fs}, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	api := NewConsoleAPI(accountsOnly{fs}, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	tok := api.signToken()

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/api/logs/1"},
		{http.MethodPost, "/api/logs/1/replay"},
	} {
		rec, got := doJSON(t, mux, tok, req.method, req.path, `{}`)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501", req.method, req.path, rec.Code)
		}
		if got["error"] != "call detail not supported by this store" {
			t.Errorf("%s %s error = %v", req.method, req.path, got["error"])
		}
	}
}

// TestConnectorRecordFlagRoundTrip: the record flag survives POST → GET → PUT,
// and a label-only PUT leaves it untouched.
func TestConnectorRecordFlagRoundTrip(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{"linear": {"get_issue"}})

	// POST with record:true.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Recorded","tools":{"linear":["get_issue"]},"record":true}`)
	if rec.Code != http.StatusCreated || got["record"] != true {
		t.Fatalf("POST record=true → %d %v", rec.Code, got)
	}

	// GET list reflects it.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/connectors", "")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	if list[0]["record"] != true {
		t.Fatalf("GET list record = %v, want true", list[0]["record"])
	}

	// Label-only PUT leaves record untouched.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/recorded", `{"label":"Still Recorded"}`)
	if rec.Code != http.StatusOK || got["record"] != true {
		t.Fatalf("label-only PUT flipped record: %d %v", rec.Code, got)
	}

	// Explicit PUT record:false turns it off.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/recorded", `{"record":false}`)
	if rec.Code != http.StatusOK || got["record"] != false {
		t.Fatalf("PUT record=false → %d %v", rec.Code, got)
	}

	// POST without the field defaults to false.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Plain","tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusCreated || got["record"] != false {
		t.Fatalf("POST default record → %d %v", rec.Code, got)
	}
}

// TestLogsAPIGuardField: the guard markers written by the response-guardrail
// pipeline surface verbatim on BOTH log surfaces — the /api/logs summary rows
// (the Activity UI chips on it) and the /api/logs/{id} detail — and rows with
// no guard omit the field entirely (omitempty).
func TestLogsAPIGuardField(t *testing.T) {
	mux, tok, _, fs, _ := newRecorderConsole(t)
	fs.LogCall(CallRecord{Account: "linear", Tool: "get_issue", OK: true,
		Connector: "work", Guard: "truncated,redacted:2,flagged:injection"})
	fs.LogCall(CallRecord{Account: "linear", Tool: "get_issue", OK: true}) // unguarded

	rec, _ := doJSON(t, mux, tok, http.MethodGet, "/api/logs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/logs = %d, body %s", rec.Code, rec.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	// Newest first: list[0] is the unguarded row, list[1] the guarded one.
	if _, present := list[0]["guard"]; present {
		t.Fatalf("unguarded row must omit guard: %v", list[0])
	}
	if list[1]["guard"] != "truncated,redacted:2,flagged:injection" {
		t.Fatalf("guarded summary row = %v", list[1])
	}

	// Detail carries the same field.
	id := int64(list[1]["id"].(float64))
	rec, got := doJSON(t, mux, tok, http.MethodGet, fmt.Sprintf("/api/logs/%d", id), "")
	if rec.Code != http.StatusOK || got["guard"] != "truncated,redacted:2,flagged:injection" {
		t.Fatalf("detail guard = %d %v", rec.Code, got)
	}
}
