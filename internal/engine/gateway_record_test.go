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

// newRecorderGateway builds a Gateway over a FileStore audit sink with a REAL
// streamable-HTTP upstream exposing get_issue (read) + save_issue (mutating).
// Returns the gateway, the FileStore (= the audit sink), and a counter of
// upstream save_issue dispatches.
func newRecorderGateway(t *testing.T) (*Gateway, *FileStore, *int32) {
	t.Helper()
	var saves int32
	up := server.NewMCPServer("up", "0.0.0", server.WithToolCapabilities(true))
	up.AddTool(mcp.NewTool("save_issue", mcp.WithDescription("mutates")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			atomic.AddInt32(&saves, 1)
			return mcp.NewToolResultText("saved-upstream"), nil
		})
	// NB: mcp.NewTool defaults ReadOnlyHint=false — annotate the read tool
	// explicitly so replay's annotation-first check sees it as read-only.
	up.AddTool(mcp.NewTool("get_issue", mcp.WithDescription("reads"), mcp.WithReadOnlyHintAnnotation(true)),
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
	return g, fs, &saves
}

// callMainTool sends a tools/call to the DEFAULT /mcp server.
func callMainTool(t *testing.T, g *Gateway, tool string, args map[string]any) string {
	t.Helper()
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	resp := g.mcp.HandleMessage(context.Background(), req)
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return string(out)
}

// callRows returns the audit rows for one bare tool name, newest first.
func callRows(t *testing.T, fs *FileStore, tool string) []CallRecord {
	t.Helper()
	list, err := fs.RecentCalls(context.Background(), 100)
	if err != nil {
		t.Fatalf("recent calls: %v", err)
	}
	var out []CallRecord
	for _, c := range list {
		if c.Tool == tool {
			out = append(out, c)
		}
	}
	return out
}

func detail(t *testing.T, fs *FileStore, id int64) CallRecord {
	t.Helper()
	d, ok, err := fs.CallDetail(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("CallDetail(%d): ok=%v err=%v", id, ok, err)
	}
	return d
}

// ---- recording ----

func TestRecordingDefaultEndpointOffThenOn(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)

	// Off (the default): exactly one summary row, no payloads.
	if resp := callMainTool(t, g, "linear__get_issue", map[string]any{"id": "42"}); !strings.Contains(resp, "got-upstream") {
		t.Fatalf("call failed: %s", resp)
	}
	rows := callRows(t, fs, "get_issue")
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 audit row, got %d", len(rows))
	}
	if rows[0].Connector != "" || rows[0].Decision != "" {
		t.Fatalf("default endpoint row must have no connector/decision: %+v", rows[0])
	}
	d := detail(t, fs, rows[0].ID)
	if d.Args != "" || d.Result != "" {
		t.Fatalf("recording off: payloads must be empty, got args=%q result=%q", d.Args, d.Result)
	}

	// On (ENGINE_RECORD_PAYLOADS): payloads captured, still one row per call.
	g.SetRecordPayloads(true)
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "43"})
	rows = callRows(t, fs, "get_issue")
	if len(rows) != 2 {
		t.Fatalf("want 2 rows after second call, got %d", len(rows))
	}
	d = detail(t, fs, rows[0].ID)
	if !strings.Contains(d.Args, `"id":"43"`) {
		t.Fatalf("recorded args missing: %q", d.Args)
	}
	if !strings.Contains(d.Result, "got-upstream") {
		t.Fatalf("recorded result missing: %q", d.Result)
	}
}

func TestRecordingPerConnectorFlag(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)
	ctx := context.Background()
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "rec", Label: "Recording",
		Tools: map[string][]string{"linear": {"get_issue"}}, Record: true,
	}); err != nil {
		t.Fatalf("upsert rec: %v", err)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "norec", Label: "Plain",
		Tools: map[string][]string{"linear": {"get_issue"}},
	}); err != nil {
		t.Fatalf("upsert norec: %v", err)
	}

	callConnectorTool(t, g, "rec", "linear__get_issue")
	callConnectorTool(t, g, "norec", "linear__get_issue")

	rows := callRows(t, fs, "get_issue")
	if len(rows) != 2 {
		t.Fatalf("want exactly 1 row per call (2 total), got %d: %+v", len(rows), rows)
	}
	byConn := map[string]CallRecord{}
	for _, r := range rows {
		byConn[r.Connector] = detail(t, fs, r.ID)
	}
	rec, ok := byConn["rec"]
	if !ok {
		t.Fatalf("no row attributed to connector rec: %+v", rows)
	}
	recConfig, _ := g.store.(ConnectorStore).VirtualConnector(ctx, "rec")
	if rec.EndpointKind != endpointKindConnector || rec.EndpointGeneration != recConfig.Epoch {
		t.Fatalf("recording connector row lost endpoint identity: %+v", rec)
	}
	if !strings.Contains(rec.Args, `"key":"val"`) || !strings.Contains(rec.Result, "got-upstream") {
		t.Fatalf("recording connector must capture payloads: args=%q result=%q", rec.Args, rec.Result)
	}
	norec, ok := byConn["norec"]
	if !ok {
		t.Fatalf("no row attributed to connector norec: %+v", rows)
	}
	if norec.Args != "" || norec.Result != "" {
		t.Fatalf("non-recording connector must stay summary-only: args=%q result=%q", norec.Args, norec.Result)
	}
	norecConfig, _ := g.store.(ConnectorStore).VirtualConnector(ctx, "norec")
	if norec.EndpointKind != endpointKindConnector || norec.EndpointGeneration != norecConfig.Epoch {
		t.Fatalf("summary connector row lost endpoint identity: %+v", norec)
	}

	// The connector Record flag must not leak onto the default /mcp endpoint.
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "1"})
	rows = callRows(t, fs, "get_issue")
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	d := detail(t, fs, rows[0].ID)
	if d.Connector != "" || d.Args != "" || d.Result != "" {
		t.Fatalf("default endpoint call polluted by connector scope: %+v", d)
	}
}

func TestRecordingComposesWithApproval(t *testing.T) {
	g, fs, saves := newRecorderGateway(t)
	ctx := context.Background()
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "work", Label: "Work",
		Tools:    map[string][]string{"linear": {"save_issue"}},
		Approval: map[string][]string{"linear": {"save_issue"}},
		Record:   true,
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}

	// Approved call: ONE row, decision approved, payloads captured.
	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()
	id := waitPendingID(t, g)
	if err := g.Decide(ctx, id, "approved"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp := <-done; !strings.Contains(resp, "saved-upstream") {
		t.Fatalf("approved call should reach upstream: %s", resp)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("upstream dispatched %d times, want 1", atomic.LoadInt32(saves))
	}
	rows := callRows(t, fs, "save_issue")
	if len(rows) != 1 {
		t.Fatalf("approved call must write exactly 1 audit row, got %d: %+v", len(rows), rows)
	}
	d := detail(t, fs, rows[0].ID)
	if d.Connector != "work" || d.Decision != "approved" || !d.OK {
		t.Fatalf("approved row mismatch: %+v", d)
	}
	if !strings.Contains(d.Args, `"key":"val"`) || !strings.Contains(d.Result, "saved-upstream") {
		t.Fatalf("approved row missing payloads: args=%q result=%q", d.Args, d.Result)
	}

	// Denied call: ONE row, decision denied, args recorded (record is on),
	// no result (never dispatched).
	go func() { done <- callConnectorTool(t, g, "work", "linear__save_issue") }()
	id = waitPendingID(t, g)
	if err := g.Decide(ctx, id, "denied"); err != nil {
		t.Fatalf("decide denied: %v", err)
	}
	if resp := <-done; !strings.Contains(resp, "approval denied") {
		t.Fatalf("expected denial result: %s", resp)
	}
	rows = callRows(t, fs, "save_issue")
	if len(rows) != 2 {
		t.Fatalf("denied call must add exactly 1 row, got %d total", len(rows))
	}
	d = detail(t, fs, rows[0].ID)
	if d.Connector != "work" || d.Decision != "denied" || d.OK {
		t.Fatalf("denied row mismatch: %+v", d)
	}
	if !strings.Contains(d.Args, `"key":"val"`) || d.Result != "" {
		t.Fatalf("denied row: want recorded args and no result, got args=%q result=%q", d.Args, d.Result)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatal("denied call must not reach upstream")
	}
}

// ---- replay ----

func TestReplayReadOnlyTool(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)
	g.SetRecordPayloads(true)
	callMainTool(t, g, "linear__get_issue", map[string]any{"id": "42"})
	orig := callRows(t, fs, "get_issue")[0]

	rec, err := g.Replay(context.Background(), orig.ID, false)
	if err != nil {
		t.Fatalf("replay read-only tool without force: %v", err)
	}
	if rec.Decision != "replay" || rec.Account != "linear" || rec.Tool != "get_issue" || !rec.OK {
		t.Fatalf("replay record mismatch: %+v", rec)
	}
	if !strings.Contains(rec.Args, `"id":"42"`) || !strings.Contains(rec.Result, "got-upstream") {
		t.Fatalf("replay record must carry payloads: args=%q result=%q", rec.Args, rec.Result)
	}
	// A fresh audit row landed, itself carrying payloads.
	rows := callRows(t, fs, "get_issue")
	if len(rows) != 2 {
		t.Fatalf("replay must write a new row, got %d rows", len(rows))
	}
	d := detail(t, fs, rows[0].ID)
	if d.Decision != "replay" || !strings.Contains(d.Result, "got-upstream") {
		t.Fatalf("stored replay row mismatch: %+v", d)
	}
}

func TestReplayMutatingRequiresForce(t *testing.T) {
	g, fs, saves := newRecorderGateway(t)
	ctx := context.Background()
	// Record through a connector so the row has a connector name to inherit.
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "w", Label: "W",
		Tools: map[string][]string{"linear": {"save_issue"}}, Record: true,
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	callConnectorTool(t, g, "w", "linear__save_issue")
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("setup call did not dispatch")
	}
	orig := callRows(t, fs, "save_issue")[0]

	if _, err := g.Replay(ctx, orig.ID, false); !errors.Is(err, ErrReplayForceRequired) {
		t.Fatalf("mutating replay without force: want ErrReplayForceRequired, got %v", err)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatal("refused replay must not dispatch upstream")
	}

	rec, err := g.Replay(ctx, orig.ID, true)
	if err != nil {
		t.Fatalf("forced replay: %v", err)
	}
	if atomic.LoadInt32(saves) != 2 {
		t.Fatalf("forced replay must dispatch upstream, saves=%d", atomic.LoadInt32(saves))
	}
	if rec.Decision != "replay" || rec.Connector != "w" || !strings.Contains(rec.Result, "saved-upstream") {
		t.Fatalf("forced replay record mismatch: %+v", rec)
	}
	// Replay records payloads even though it went nowhere near the connector
	// endpoint — an explicit replay is an explicit ask.
	rows := callRows(t, fs, "save_issue")
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (original + replay), got %d", len(rows))
	}
}

func TestReplayRejectsDeletedOrCrossKindReusedEndpoint(t *testing.T) {
	g, fs, saves := newRecorderGateway(t)
	ctx := context.Background()
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "shared", Label: "Connector",
		Tools: map[string][]string{"linear": {"save_issue"}}, Record: true,
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	callConnectorTool(t, g, "shared", "linear__save_issue")
	original := callRows(t, fs, "save_issue")[0]
	if original.EndpointKind != endpointKindConnector || original.EndpointGeneration == "" {
		t.Fatalf("original audit row lacks endpoint identity: %+v", original)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("setup dispatch count = %d, want 1", atomic.LoadInt32(saves))
	}

	if err := g.DeleteConnector(ctx, "shared"); err != nil {
		t.Fatalf("delete connector: %v", err)
	}
	if _, err := g.CreateNamespace(ctx, Namespace{
		Slug: "shared", Label: "Namespace reuse", Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("reuse slug as namespace: %v", err)
	}
	if _, err := g.Replay(ctx, original.ID, true); err == nil ||
		!strings.Contains(err.Error(), `connector "shared" was deleted or replaced`) {
		t.Fatalf("replay across endpoint reuse = %v, want identity error", err)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatal("identity-rejected replay dispatched upstream")
	}
}

func TestReplayRejectsToolRemovedFromCurrentConnectorAllowlist(t *testing.T) {
	g, fs, saves := newRecorderGateway(t)
	ctx := context.Background()
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Label: "Curated",
		Tools: map[string][]string{"linear": {"save_issue"}}, Record: true,
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	callConnectorTool(t, g, "curated", "linear__save_issue")
	original := callRows(t, fs, "save_issue")[0]
	if atomic.LoadInt32(saves) != 1 {
		t.Fatalf("setup dispatch count = %d, want 1", atomic.LoadInt32(saves))
	}

	// Upsert preserves the connector generation but removes this tool from its
	// current authorization boundary.
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Label: "Curated", Tools: map[string][]string{}, Record: true,
	}); err != nil {
		t.Fatalf("remove tool from connector: %v", err)
	}
	if _, err := g.Replay(ctx, original.ID, true); err == nil ||
		!strings.Contains(err.Error(), "no longer exposes linear/save_issue") {
		t.Fatalf("replay after allowlist removal = %v, want fail-closed error", err)
	}
	if atomic.LoadInt32(saves) != 1 {
		t.Fatal("allowlist-rejected replay dispatched upstream")
	}
}

func TestReplayErrors(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)
	ctx := context.Background()

	// Unknown id.
	if _, err := g.Replay(ctx, 999999, false); err == nil {
		t.Fatal("replay of an unknown id must error")
	}

	// Row without a recorded payload (recording was off).
	callMainTool(t, g, "linear__get_issue", nil)
	bare := callRows(t, fs, "get_issue")[0]
	if _, err := g.Replay(ctx, bare.ID, false); err == nil || !strings.Contains(err.Error(), "no recorded payload") {
		t.Fatalf("unrecorded row: want 'no recorded payload' error, got %v", err)
	}

	// Account gone: a recorded row whose account has no live tools.
	fs.LogCall(CallRecord{Account: "ghost", Tool: "get_issue", OK: true, Args: `{"a":1}`})
	rows, _ := fs.RecentCalls(ctx, 10)
	var ghostID int64
	for _, r := range rows {
		if r.Account == "ghost" {
			ghostID = r.ID
		}
	}
	if ghostID == 0 {
		t.Fatal("ghost row missing")
	}
	if _, err := g.Replay(ctx, ghostID, true); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("missing account: want error naming the account, got %v", err)
	}

	// Legacy connector-attributed rows predate endpoint kind/generation. They
	// cannot safely distinguish a current endpoint from a reused slug.
	fs.LogCall(CallRecord{
		Account: "linear", Tool: "get_issue", Connector: "legacy", OK: true, Args: `{"a":1}`,
	})
	rows, _ = fs.RecentCalls(ctx, 10)
	var legacyID int64
	for _, r := range rows {
		if r.Connector == "legacy" {
			legacyID = r.ID
			break
		}
	}
	if _, err := g.Replay(ctx, legacyID, true); err == nil ||
		!strings.Contains(err.Error(), "no endpoint generation") {
		t.Fatalf("legacy attributed replay = %v, want fail-closed generation error", err)
	}
}

// ---- retention plumbing ----

// TestPurgeAuditPlumbing: the tick-side purge honors the retention setting and
// the AuditPurger facet without touching live rows (FileStore purge is a no-op
// ring — this exercises the gateway wiring, not SQL).
func TestPurgeAuditPlumbing(t *testing.T) {
	g, fs, _ := newRecorderGateway(t)
	fs.LogCall(CallRecord{Account: "a", Tool: "t", OK: true})
	// retention unset (0) → no purge attempted; then set → purge runs (no-op).
	g.purgeAudit(context.Background())
	g.SetAuditRetention(30 * 24 * time.Hour)
	g.purgeAudit(context.Background())
	if rows, _ := fs.RecentCalls(context.Background(), 10); len(rows) == 0 {
		t.Fatal("purge must not eat the ring")
	}
}
