package engine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ---- read-only heuristic ----

func boolPtr(b bool) *bool { return &b }

func TestReadOnlyToolHeuristic(t *testing.T) {
	annotated := func(ro, de *bool) mcp.Tool {
		return mcp.Tool{Annotations: mcp.ToolAnnotation{ReadOnlyHint: ro, DestructiveHint: de}}
	}
	cases := []struct {
		name string
		tool mcp.Tool
		bare string
		want bool
	}{
		// Explicit annotations win, regardless of name.
		{"readonly hint true", annotated(boolPtr(true), nil), "delete_everything", true},
		{"readonly hint false", annotated(boolPtr(false), nil), "get_issue", false},
		{"destructive hint true", annotated(nil, boolPtr(true)), "get_issue", false},
		// No usable annotation → conservative name heuristic.
		{"get prefix", mcp.Tool{}, "get_issue", true},
		{"camelCase get prefix", mcp.Tool{}, "getIssue", true},
		{"list prefix", mcp.Tool{}, "list_issues", true},
		{"search word", mcp.Tool{}, "notion-search", true},
		{"query word", mcp.Tool{}, "issues_query", true},
		{"fetch bare", mcp.Tool{}, "fetch", true},
		{"describe prefix", mcp.Tool{}, "describe_table", true},
		{"find word", mcp.Tool{}, "find_user", true},
		{"show word", mcp.Tool{}, "show_config", true},
		{"count word", mcp.Tool{}, "row_count", true},
		{"read prefix", mcp.Tool{}, "read_file", true},
		// Mutating names fall through to false.
		{"save", mcp.Tool{}, "save_issue", false},
		{"create", mcp.Tool{}, "create_page", false},
		{"delete", mcp.Tool{}, "delete_comment", false},
		{"update", mcp.Tool{}, "update_event", false},
		{"push", mcp.Tool{}, "push_files", false},
		{"merge", mcp.Tool{}, "merge_pull_request", false},
		// Write verb + read word: the veto must win, or a read-only account
		// leaks mutating tools (create_list etc. are common real MCP names).
		{"create with list word", mcp.Tool{}, "create_list", false},
		{"delete with search word", mcp.Tool{}, "delete_saved_search", false},
		{"update with query word", mcp.Tool{}, "update_query", false},
		{"add with list word", mcp.Tool{}, "add_to_list", false},
		{"camelCase write with read word", mcp.Tool{}, "createSearchIndex", false},
		// Plain read names still pass.
		{"list items", mcp.Tool{}, "list_items", true},
		{"get page", mcp.Tool{}, "get_page", true},
		{"search threads", mcp.Tool{}, "search_threads", true},
		// Exact-word matching: no loose prefix guessing.
		{"getaway is not get", mcp.Tool{}, "getaway_x", false},
		{"counter_reset is not count", mcp.Tool{}, "counter_reset", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := readOnlyTool(c.tool, c.bare); got != c.want {
				t.Fatalf("readOnlyTool(%q) = %v, want %v", c.bare, got, c.want)
			}
		})
	}
}

func TestReadOnlyAccountRegistersOnlyReadTools(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	ctx := context.Background()
	if err := fs.Upsert(ctx, Account{Name: "gh", URL: "http://unused", AuthMode: "token", BearerToken: "t", ReadOnly: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		mk := func(bare string, ro, de *bool) mcp.Tool {
			tl := mcp.NewTool(a.Name+"__"+bare, mcp.WithDescription("t"))
			tl.Annotations.ReadOnlyHint = ro
			tl.Annotations.DestructiveHint = de
			return tl
		}
		return []mcp.Tool{
			mk("get_issue", nil, nil),                 // heuristic read → kept
			mk("save_issue", nil, nil),                // heuristic mutate → dropped
			mk("annotated_write", boolPtr(true), nil), // ReadOnlyHint wins → kept
			mk("get_bomb", nil, boolPtr(true)),        // DestructiveHint wins → dropped
		}, nil
	}
	g.Aggregate(ctx)

	g.mu.Lock()
	got := append([]string(nil), g.byAcct["gh"]...)
	g.mu.Unlock()
	want := map[string]bool{"gh__get_issue": true, "gh__annotated_write": true}
	if len(got) != len(want) {
		t.Fatalf("registered %v, want exactly %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("registered %v, want exactly %v", got, want)
		}
	}
}

// ---- approval flow ----

// newApprovalTestGateway builds a Gateway over a FileStore with a REAL
// upstream MCP server (httptest, streamable HTTP), one connector "work"
// exposing get_issue + save_issue with save_issue gated behind approval.
// Returns the gateway and a counter of upstream save_issue dispatches.
func newApprovalTestGateway(t *testing.T) (*Gateway, *int32) {
	t.Helper()
	var saves int32
	up := server.NewMCPServer("up", "0.0.0", server.WithToolCapabilities(true))
	up.AddTool(mcp.NewTool("save_issue", mcp.WithDescription("mutates")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			atomic.AddInt32(&saves, 1)
			return mcp.NewToolResultText("saved-upstream"), nil
		})
	up.AddTool(mcp.NewTool("get_issue", mcp.WithDescription("reads")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("got-upstream"), nil
		})
	ts := server.NewTestStreamableHTTPServer(up)
	t.Cleanup(ts.Close)

	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	ctx := context.Background()
	if err := fs.Upsert(ctx, Account{Name: "linear", URL: ts.URL, AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.SetAudit(fs)
	if n := g.Aggregate(ctx); n != 2 {
		t.Fatalf("aggregated %d tools, want 2", n)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug:     "work",
		Label:    "Work",
		Tools:    map[string][]string{"linear": {"get_issue", "save_issue"}},
		Approval: map[string][]string{"linear": {"save_issue"}},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	return g, &saves
}

// callConnectorTool sends a tools/call to the connector's MCP server and
// returns the raw JSON of the JSON-RPC response (string-matched by callers).
func callConnectorTool(t *testing.T, g *Gateway, slug, tool string) string {
	t.Helper()
	g.mu.Lock()
	cs, ok := g.connectors[slug]
	g.mu.Unlock()
	if !ok {
		t.Fatalf("connector %q has no server", slug)
	}
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": map[string]any{"key": "val"}},
	})
	resp := cs.mcp.HandleMessage(context.Background(), req)
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return string(out)
}

// callSubjectClientTool sends a tools/call directly to a projected,
// subject-bound client MCP server. OAuth resource authorization is exercised
// elsewhere; this helper deliberately targets the delivery projection so this
// package can assert handler composition consistently across MCP surfaces.
func callSubjectClientTool(t *testing.T, g *Gateway, slug, tool string) string {
	t.Helper()
	g.mu.Lock()
	endpoint, ok := g.clientEndpoints[slug]
	g.mu.Unlock()
	if !ok {
		t.Fatalf("client endpoint %q has no server", slug)
	}
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": map[string]any{"key": "val"}},
	})
	resp := endpoint.mcp.HandleMessage(context.Background(), req)
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return string(out)
}

func applyGovernancePreset(t *testing.T, g *Gateway, tool string, preset GovernancePreset) *FileStore {
	t.Helper()
	store, ok := g.store.(*FileStore)
	if !ok {
		t.Fatal("governance test gateway must use FileStore")
	}
	account, ok := store.Account("linear")
	if !ok {
		t.Fatal("governance test account missing")
	}
	overrides := make(map[string]ToolOverride, len(account.ToolOverrides)+1)
	for name, override := range account.ToolOverrides {
		overrides[name] = override
	}
	overrides[tool] = ToolOverride{GovernancePreset: preset}
	if _, err := store.UpdateAccountPolicy(context.Background(), account.Name, accountPolicyPrecondition(account), AccountPolicyMutation{
		ToolOverrides: &overrides,
	}); err != nil {
		t.Fatalf("save governance preset: %v", err)
	}
	if _, err := g.ReplaceAccount(context.Background(), account.Name); err != nil {
		t.Fatalf("refresh governed account: %v", err)
	}
	return store
}

// waitPendingID polls the approval log until a pending record shows up.
func waitPendingID(t *testing.T, g *Gateway) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ps, err := g.PendingApprovals(context.Background())
		if err != nil {
			t.Fatalf("pending approvals: %v", err)
		}
		for _, p := range ps {
			if p.Status == "pending" {
				return p.ID
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no pending approval appeared")
	return ""
}

func approvalRecord(t *testing.T, g *Gateway, id string) PendingCall {
	t.Helper()
	ps, err := g.PendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("pending approvals: %v", err)
	}
	for _, p := range ps {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("approval record %q not found", id)
	return PendingCall{}
}

func TestApprovalApprovePathDispatchesUpstream(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()

	id := waitPendingID(t, g)
	rec := approvalRecord(t, g, id)
	if rec.Connector != "work" || rec.Account != "linear" || rec.Tool != "save_issue" {
		t.Fatalf("pending record = %+v, want work/linear/save_issue", rec)
	}
	if rec.Args["key"] != "val" {
		t.Fatalf("pending args = %v, want the original call arguments", rec.Args)
	}
	if err := g.Decide(context.Background(), id, "approved"); err != nil {
		t.Fatalf("decide approved: %v", err)
	}

	resp := <-done
	if !strings.Contains(resp, "saved-upstream") {
		t.Fatalf("approved call should return the upstream result, got: %s", resp)
	}
	if strings.Contains(resp, `"isError":true`) {
		t.Fatalf("approved call must not be an error result: %s", resp)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("upstream dispatched %d times, want 1", atomic.LoadInt32(saves))
	}
	if rec := approvalRecord(t, g, id); rec.Status != "approved" || rec.DecidedAt == nil {
		t.Fatalf("record after approve = %+v, want status approved + decided_at", rec)
	}
	// Deciding again must fail — the wait is gone.
	if err := g.Decide(context.Background(), id, "denied"); err == nil {
		t.Fatal("second decide on the same id must error")
	}
}

func approvalMoveTarget(t *testing.T, g *Gateway) (Account, ConnectionNamespace) {
	t.Helper()
	store, ok := g.store.(*FileStore)
	if !ok {
		t.Fatal("approval test gateway must use FileStore")
	}
	account, found := store.Account("linear")
	if !found {
		t.Fatal("approval test account missing")
	}
	target, err := store.CreateConnectionNamespace(context.Background(), ConnectionNamespace{
		Label: "Private", CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("create move target: %v", err)
	}
	return account, target
}

// TestApprovalMoveCancelsPendingBeforeDecision verifies the common TOCTOU:
// a namespace manager opens an approval row, then an administrator moves that
// credential into a different (here personal) ownership boundary. The move
// atomically cancels the pending row, so a stale Approve cannot release it.
func TestApprovalMoveCancelsPendingBeforeDecision(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	account, target := approvalMoveTarget(t, g)
	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()

	id := waitPendingID(t, g)
	parked := approvalRecord(t, g, id)
	if parked.AccountIncarnationID != account.IncarnationID || parked.AccountRevision != account.Revision || parked.ConnectionNamespaceID != account.ConnectionNamespaceID {
		t.Fatalf("pending ownership binding = %+v, want current account %+v", parked, account)
	}
	if _, err := g.MoveAccountToConnectionNamespace(context.Background(), account.Name, account.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID,
		Scope:                 ConnectionScopePersonal,
		OwnerSubject:          "usr_private",
	}, account.Revision); err != nil {
		t.Fatalf("move account: %v", err)
	}
	if cancelled := approvalRecord(t, g, id); cancelled.Status != ApprovalCancelled {
		t.Fatalf("pending status after move = %+v, want cancelled", cancelled)
	}
	if err := g.Decide(context.Background(), id, ApprovalApproved); !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("stale approve after move = %v, want ErrApprovalNotPending", err)
	}

	resp := <-done
	if !strings.Contains(resp, "approval cancelled") || strings.Contains(resp, "saved-upstream") {
		t.Fatalf("moved pending call response = %s; want a cancelled, undispatched result", resp)
	}
	if got := atomic.LoadInt32(saves); got != 0 {
		t.Fatalf("moved pending call dispatched %d times, want 0", got)
	}
}

// TestApprovedCallCannotDispatchAfterConcurrentOwnershipMove covers the
// narrower ordering where an approval commits first and the ownership move
// commits while the request is between the handler's first validation and the
// upstream dial. The revision-bound credential lookup is the final guard: the
// old closure may finish, but it cannot send a request using the new owner's
// credential.
func TestApprovedCallCannotDispatchAfterConcurrentOwnershipMove(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	account, target := approvalMoveTarget(t, g)
	entered := make(chan struct{})
	release := make(chan struct{})
	g.beforeAccountDispatch = func() {
		close(entered)
		<-release
	}

	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()
	id := waitPendingID(t, g)
	if err := g.Decide(context.Background(), id, ApprovalApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	<-entered
	if _, err := g.MoveAccountToConnectionNamespace(context.Background(), account.Name, account.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID,
		Scope:                 ConnectionScopePersonal,
		OwnerSubject:          "usr_private",
	}, account.Revision); err != nil {
		t.Fatalf("move account after approve: %v", err)
	}
	close(release)

	resp := <-done
	if strings.Contains(resp, "saved-upstream") {
		t.Fatalf("approved stale call reached upstream after move: %s", resp)
	}
	if got := atomic.LoadInt32(saves); got != 0 {
		t.Fatalf("approved stale call dispatched %d times, want 0", got)
	}
}

func TestApprovalDenyPathReturnsIsError(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()

	id := waitPendingID(t, g)
	if err := g.Decide(context.Background(), id, "denied"); err != nil {
		t.Fatalf("decide denied: %v", err)
	}
	resp := <-done
	if !strings.Contains(resp, `"isError":true`) || !strings.Contains(resp, "approval denied") {
		t.Fatalf("denied call should be an isError result mentioning approval denied, got: %s", resp)
	}
	if atomic.LoadInt32(saves) != 0 {
		t.Fatal("denied call must never reach the upstream")
	}
	if rec := approvalRecord(t, g, id); rec.Status != "denied" {
		t.Fatalf("record status = %q, want denied", rec.Status)
	}
	// Denials are audited as failed calls.
	calls, err := g.RecentCalls(context.Background(), 10)
	if err != nil {
		t.Fatalf("recent calls: %v", err)
	}
	found := false
	for _, c := range calls {
		if c.Tool == "save_issue" && !c.OK && strings.Contains(c.Error, "approval denied") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an audit row for the denial, got %+v", calls)
	}
}

func TestApprovalTimeoutExpires(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	g.SetApprovalTimeout(60 * time.Millisecond)

	resp := callConnectorTool(t, g, "work", "linear__save_issue") // nobody decides
	if !strings.Contains(resp, `"isError":true`) || !strings.Contains(resp, "approval expired") {
		t.Fatalf("timed-out call should be an isError result mentioning approval expired, got: %s", resp)
	}
	if atomic.LoadInt32(saves) != 0 {
		t.Fatal("expired call must never reach the upstream")
	}
	ps, err := g.PendingApprovals(context.Background())
	if err != nil || len(ps) != 1 {
		t.Fatalf("pending approvals = %v (err %v), want exactly 1", ps, err)
	}
	if ps[0].Status != "expired" {
		t.Fatalf("record status = %q, want expired", ps[0].Status)
	}
	// The channel was cleaned up: a late decision errors.
	if err := g.Decide(context.Background(), ps[0].ID, "approved"); err == nil {
		t.Fatal("decide after expiry must error")
	}
}

func TestApprovalOnlyGatedToolParks(t *testing.T) {
	g, _ := newApprovalTestGateway(t)
	g.SetApprovalTimeout(60 * time.Millisecond)

	// get_issue is allowlisted but NOT in the approval map — it dispatches
	// immediately and leaves no pending record.
	resp := callConnectorTool(t, g, "work", "linear__get_issue")
	if !strings.Contains(resp, "got-upstream") || strings.Contains(resp, `"isError":true`) {
		t.Fatalf("ungated call should return the upstream result directly, got: %s", resp)
	}
	if ps, _ := g.PendingApprovals(context.Background()); len(ps) != 0 {
		t.Fatalf("ungated call must not create approval records, got %v", ps)
	}
}

func TestHighRiskGovernanceAppliesAcrossEveryMCPDeliverySurface(t *testing.T) {
	g, saves := newApprovalTestGateway(t)
	store := applyGovernancePreset(t, g, "save_issue", GovernancePresetHighRisk)
	ctx := context.Background()
	account, ok := store.Account("linear")
	if !ok {
		t.Fatal("governed account missing")
	}
	if _, err := g.CreateNamespace(ctx, Namespace{
		Slug: "bundle", Label: "Bundle", Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("create endpoint bundle: %v", err)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Label: "Curated", Tools: map[string][]string{"linear": {"save_issue"}},
		// This duplicates the connector-level policy that high risk supersedes.
		// The call must still park exactly once rather than nesting two waits.
		Approval: map[string][]string{"linear": {"save_issue"}},
	}); err != nil {
		t.Fatalf("create curated connector: %v", err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Governed Codex", Subject: "usr_governed", CreatedBy: "usr_governed",
		ConnectionNamespaceIDs: []string{account.ConnectionNamespaceID},
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}
	if err := g.RefreshMCPClients(ctx); err != nil {
		t.Fatalf("refresh MCP clients: %v", err)
	}
	g.SetApprovalTimeout(500 * time.Millisecond)

	calls := []struct {
		name              string
		approvalConnector string
		call              func() string
	}{
		{
			name:              "aggregate",
			approvalConnector: governancePolicyScope,
			call:              func() string { return callMainTool(t, g, "linear__save_issue", map[string]any{"key": "val"}) },
		},
		{
			name:              "endpoint bundle",
			approvalConnector: "bundle",
			call:              func() string { return callConnectorTool(t, g, "bundle", "linear__save_issue") },
		},
		{
			name:              "curated connector",
			approvalConnector: "curated",
			call:              func() string { return callConnectorTool(t, g, "curated", "linear__save_issue") },
		},
		{
			name:              "subject-bound client",
			approvalConnector: client.Slug,
			call:              func() string { return callSubjectClientTool(t, g, client.Slug, "linear__save_issue") },
		},
	}
	for index, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan string, 1)
			go func() { done <- tc.call() }()
			id := waitPendingID(t, g)
			pending := approvalRecord(t, g, id)
			if pending.Connector != tc.approvalConnector || pending.Account != "linear" || pending.Tool != "save_issue" {
				t.Fatalf("pending %s call = %+v", tc.name, pending)
			}
			if err := g.Decide(ctx, id, ApprovalApproved); err != nil {
				t.Fatalf("approve %s call: %v", tc.name, err)
			}
			if response := <-done; !strings.Contains(response, "saved-upstream") || strings.Contains(response, `"isError":true`) {
				t.Fatalf("approved %s response = %s", tc.name, response)
			}
			if got := atomic.LoadInt32(saves); got != int32(index+1) {
				t.Fatalf("upstream dispatches after %s = %d, want %d", tc.name, got, index+1)
			}
		})
	}

	rows := callRows(t, store, "save_issue")
	if len(rows) != len(calls) {
		t.Fatalf("high-risk audit rows = %d, want %d: %+v", len(rows), len(calls), rows)
	}
	for _, row := range rows {
		full := detail(t, store, row.ID)
		if full.Args == "" || full.Result == "" || !strings.Contains(full.Result, "saved-upstream") {
			t.Fatalf("high-risk call did not record its payloads: %+v", full)
		}
	}
}

func TestApprovalWrappingSurvivesRebuild(t *testing.T) {
	g, _ := newApprovalTestGateway(t)
	g.SetApprovalTimeout(60 * time.Millisecond)

	// An account change triggers RefreshConnectors — the approval wrapper must
	// be rebuilt from the CURRENT store state, not lost.
	if _, err := g.ReplaceAccount(context.Background(), "linear"); err != nil {
		t.Fatalf("replace account: %v", err)
	}
	resp := callConnectorTool(t, g, "work", "linear__save_issue")
	if !strings.Contains(resp, "approval expired") {
		t.Fatalf("gated tool lost its approval wrapper after rebuild: %s", resp)
	}
}

func TestDecideValidation(t *testing.T) {
	g, _ := newApprovalTestGateway(t)
	if err := g.Decide(context.Background(), "nope", "approved"); err == nil {
		t.Fatal("deciding an unknown id must error")
	}
	if err := g.Decide(context.Background(), "nope", "maybe"); err == nil {
		t.Fatal("an invalid status must error")
	}
}
