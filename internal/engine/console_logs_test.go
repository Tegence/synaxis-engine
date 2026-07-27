package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
