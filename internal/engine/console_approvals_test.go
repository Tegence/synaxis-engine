package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// seedPending registers an in-process waiter AND writes the audit record —
// the same two steps approvalHandler performs before parking, so the console
// endpoints see exactly what a live gated call produces.
func seedPending(t *testing.T, g *Gateway, id, connector, account, tool string) {
	t.Helper()
	al, ok := g.approvalLog()
	if !ok {
		t.Fatal("store has no ApprovalLog facet")
	}
	g.registerWait(id)
	if err := al.LogPending(context.Background(), PendingCall{
		ID: id, Connector: connector, Account: account, Tool: tool,
		Args: map[string]any{"n": "1"}, Status: "pending",
	}); err != nil {
		t.Fatalf("LogPending %s: %v", id, err)
	}
}

func TestApprovalAPIListAndDecide(t *testing.T) {
	mux, tok, g := newConnectorConsole(t, map[string][]string{"linear": {"get_issue", "save_issue"}})

	seedPending(t, g, "ap1", "eng", "linear", "save_issue")
	seedPending(t, g, "ap2", "eng", "linear", "save_issue")

	// LIST: newest first, pending status.
	rec, _ := doJSON(t, mux, tok, http.MethodGet, "/api/approvals", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/approvals = %d, body %s", rec.Code, rec.Body)
	}
	var list []PendingCall
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	if list[0].ID != "ap2" || list[1].ID != "ap1" {
		t.Fatalf("want newest-first [ap2 ap1], got [%s %s]", list[0].ID, list[1].ID)
	}
	if list[0].Status != "pending" || list[1].Args["n"] != "1" {
		t.Fatalf("record fields wrong: %+v", list)
	}

	// APPROVE ap1 — happy path.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/approvals/ap1/approve", "")
	if rec.Code != http.StatusOK || got["id"] != "ap1" || got["status"] != "approved" {
		t.Fatalf("approve = %d %v", rec.Code, got)
	}
	// DENY ap2 — happy path.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/approvals/ap2/deny", "")
	if rec.Code != http.StatusOK || got["status"] != "denied" {
		t.Fatalf("deny = %d %v", rec.Code, got)
	}

	// Decisions are recorded in the audit list.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/approvals", "")
	list = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("relist: %v", err)
	}
	byID := map[string]PendingCall{}
	for _, p := range list {
		byID[p.ID] = p
	}
	if byID["ap1"].Status != "approved" || byID["ap1"].DecidedAt == nil {
		t.Fatalf("ap1 decision not recorded: %+v", byID["ap1"])
	}
	if byID["ap2"].Status != "denied" {
		t.Fatalf("ap2 decision not recorded: %+v", byID["ap2"])
	}

	// DOUBLE-DECIDE: already decided → 409 (both verbs).
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/approvals/ap1/approve", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("double approve = %d, want 409 (body %s)", rec.Code, rec.Body)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/approvals/ap1/deny", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("deny after approve = %d, want 409", rec.Code)
	}

	// Unknown id → 404.
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/approvals/ghost/approve", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404 (body %s)", rec.Code, rec.Body)
	}

	// sec() applies: no bearer → 401.
	rec, _ = doJSON(t, mux, "", http.MethodGet, "/api/approvals", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d", rec.Code)
	}
	// Wrong methods → 405.
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/approvals", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/approvals = %d, want 405", rec.Code)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/approvals/ap1/approve", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET approve = %d, want 405", rec.Code)
	}
}

// TestApprovalAPI501WithoutApprovalLog mirrors the ConnectorStore 501 test:
// a store without the ApprovalLog facet gets 501 from every approval endpoint.
func TestApprovalAPI501WithoutApprovalLog(t *testing.T) {
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
		{http.MethodGet, "/api/approvals"},
		{http.MethodPost, "/api/approvals/x/approve"},
		{http.MethodPost, "/api/approvals/x/deny"},
	} {
		rec, got := doJSON(t, mux, tok, req.method, req.path, "")
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501", req.method, req.path, rec.Code)
		}
		if got["error"] != "approvals not supported by this store" {
			t.Errorf("%s %s error = %v", req.method, req.path, got["error"])
		}
	}
}

// TestConnectorAPIApprovalField: connectorDTO round-trips the approval map,
// approval ⊄ tools is a 400 on both POST and PUT, and narrowing tools without
// resubmitting approval prunes the stored map (invariant survives).
func TestConnectorAPIApprovalField(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{
		"linear": {"get_issue", "save_issue", "delete_issue"},
	})

	// POST with approval ⊄ tools → 400.
	rec, _ := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Bad","tools":{"linear":["get_issue"]},"approval":{"linear":["save_issue"]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST approval superset = %d, want 400 (body %s)", rec.Code, rec.Body)
	}
	// Approval for an account not in tools at all → 400 too.
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Bad2","tools":{},"approval":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST approval w/o tools = %d, want 400", rec.Code)
	}

	// POST happy path: approval ⊆ tools.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Gated","tools":{"linear":["get_issue","save_issue","delete_issue"]},"approval":{"linear":["save_issue","delete_issue"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, body %s", rec.Code, rec.Body)
	}
	appr, ok := got["approval"].(map[string]any)
	if !ok || len(appr["linear"].([]any)) != 2 {
		t.Fatalf("created DTO approval = %v", got["approval"])
	}

	// PUT approval ⊄ tools → 400; connector unchanged.
	rec, _ = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/gated",
		`{"approval":{"linear":["not_allowed"]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad approval = %d, want 400", rec.Code)
	}

	// PUT approval-only update.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/gated",
		`{"approval":{"linear":["delete_issue"]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT approval = %d, body %s", rec.Code, rec.Body)
	}
	appr = got["approval"].(map[string]any)
	if l := appr["linear"].([]any); len(l) != 1 || l[0] != "delete_issue" {
		t.Fatalf("PUT approval DTO = %v", got["approval"])
	}

	// PUT narrowing tools WITHOUT approval: stored approval pruned to ⊆ tools.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/gated",
		`{"tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT narrow tools = %d, body %s", rec.Code, rec.Body)
	}
	if appr := got["approval"].(map[string]any); len(appr) != 0 {
		t.Fatalf("approval not pruned after narrowing tools: %v", got["approval"])
	}
}

// TestServerPatchReadOnly: PATCH {"readOnly": bool} flips the DTO + store and
// the live aggregation drops mutating tools while the flag is on.
func TestServerPatchReadOnly(t *testing.T) {
	mux, tok, g := newConnectorConsole(t, map[string][]string{
		"linear": {"get_issue", "save_issue"},
	})
	// newConnectorConsole's seam uses mcp.NewTool, which stamps a non-nil
	// ReadOnlyHint=false on everything. Use bare Tool structs (nil hints) so
	// the read-name heuristic decides: get_issue stays, save_issue drops.
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{
			{Name: a.Name + "__get_issue"},
			{Name: a.Name + "__save_issue"},
		}, nil
	}
	g.Aggregate(context.Background())

	cachedCount := func() int {
		g.mu.Lock()
		defer g.mu.Unlock()
		return len(g.cached["linear"])
	}
	if n := cachedCount(); n != 2 {
		t.Fatalf("pre: cached tools = %d, want 2", n)
	}

	// Flip on.
	rec, got := doJSON(t, mux, tok, http.MethodPatch, "/api/servers/linear", `{"readOnly":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH readOnly = %d, body %s", rec.Code, rec.Body)
	}
	if got["readOnly"] != true {
		t.Fatalf("DTO readOnly = %v, want true", got["readOnly"])
	}
	if a, _ := g.store.Account("linear"); !a.ReadOnly {
		t.Fatal("store ReadOnly not persisted")
	}
	// ReplaceAccount ran: save_issue (mutating) no longer registered.
	if n := cachedCount(); n != 1 {
		t.Fatalf("cached tools after readOnly = %d, want 1 (get_issue only)", n)
	}

	// GET /api/servers reflects it too.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/servers", "")
	var servers []serverDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &servers); err != nil || len(servers) != 1 {
		t.Fatalf("servers = %s (err %v)", rec.Body, err)
	}
	if !servers[0].ReadOnly {
		t.Fatal("GET /api/servers lost readOnly")
	}

	// Flip off: full toolset returns.
	rec, got = doJSON(t, mux, tok, http.MethodPatch, "/api/servers/linear", `{"readOnly":false}`)
	if rec.Code != http.StatusOK || got["readOnly"] != false {
		t.Fatalf("PATCH readOnly=false = %d %v", rec.Code, got)
	}
	if n := cachedCount(); n != 2 {
		t.Fatalf("cached tools after un-readOnly = %d, want 2", n)
	}

	// Other PATCH fields still work alongside (label untouched when omitted).
	rec, got = doJSON(t, mux, tok, http.MethodPatch, "/api/servers/linear", `{"displayName":"Linear RO","readOnly":true}`)
	if rec.Code != http.StatusOK || got["displayName"] != "Linear RO" || got["readOnly"] != true {
		t.Fatalf("combined PATCH = %d %v", rec.Code, got)
	}
}
