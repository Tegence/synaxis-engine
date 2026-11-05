package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type runtimeBrowserFake struct {
	fakeSignInBrowser
	mu    sync.Mutex
	calls []string
	fail  bool
}

func (p *runtimeBrowserFake) CreateRuntimeSession(context.Context, BrowserProfile) (string, string, error) {
	return "private-runtime-session", "private-runtime-connect", nil
}
func (p *runtimeBrowserFake) BrowserAction(_ context.Context, _, site string, a BrowserAction) (*BrowserSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, a.Operation)
	if p.fail {
		return nil, errBrowserSignIn
	}
	if a.Operation == "snapshot" {
		return &BrowserSnapshot{ID: "snapshot_one", URL: site, Title: "Posting page", Text: "Private page text", Elements: []BrowserElement{{ID: 1, Role: "button", Label: "Publish"}}}, nil
	}
	return nil, nil
}

type browserRuntimeTestStore interface {
	browserTestStore
	BrowserRunStore
	MCPClientStore
	ApprovalLifecycle
}
type browserRuntimeFixture struct {
	t         *testing.T
	store     browserRuntimeTestStore
	c         *ConsoleAPI
	p         *runtimeBrowserFake
	parent    Account
	account   LinkedAccountRecord
	client    MCPClient
	execution string
}

func newBrowserRuntimeFixture(t *testing.T, store browserRuntimeTestStore) *browserRuntimeFixture {
	t.Helper()
	parent := linkedAccountFixture(t, store)
	p := &runtimeBrowserFake{}
	account, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "My publishing account", Browser: &BrowserProfile{Provider: p.Kind(), ConfigurationID: p.ConfigurationID(), FlowID: "flow", ProfileID: "profile_" + newEpoch(), WebsiteURL: "https://www.linkedin.com/feed"}}, accountPolicyPrecondition(parent))
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(t.Context(), MCPClient{Name: "Agent", Slug: "browser_" + newEpoch(), Subject: "agt_browser", Kind: MCPClientKindWorkload, CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(store, nil)
	service := &BrowserSignInService{provider: p, flows: store, accounts: store, store: store}
	c := NewConsoleAPI(store, gw, nil, "pw", "secret", "https://engine.example", "https://app.example", "", WithBrowserSignIn(service))
	f := &browserRuntimeFixture{t: t, store: store, c: c, p: p, parent: parent, account: account, client: client, execution: "run_" + newEpoch()}
	if pg, ok := store.(*PgStore); ok {
		first := f.execution
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_browser_runs WHERE id=$1 OR id=$2`, browserRunID(first, account.ID), browserRunID(f.execution, account.ID))
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_private_pending_calls WHERE account=$1`, parent.Name)
		})
	}
	return f
}
func (f *browserRuntimeFixture) request(in BrowserControlRequest) *httptest.ResponseRecorder {
	f.t.Helper()
	in.Owner = "usr_alice"
	in.OwnerRole = "owner"
	in.ClientID = f.client.ID
	in.Subject = f.client.Subject
	if in.AccountID == "" {
		in.AccountID = f.account.ID
	}
	if in.ExecutionID == "" {
		in.ExecutionID = f.execution
	}
	in.AuthorizedUntil = time.Now().Add(40 * time.Second)
	raw, _ := json.Marshal(in)
	r := httptest.NewRequest("POST", "/control/v1/browser-runtime", strings.NewReader(string(raw)))
	r = r.WithContext(withPlatformActor(r.Context(), PlatformActor{UserID: platformServiceActorID, Role: "service"}))
	w := httptest.NewRecorder()
	f.c.browserRuntimeHandler(w, r)
	return w
}
func (f *browserRuntimeFixture) call(op string, a BrowserAction) (BrowserControlResult, int) {
	w := f.request(BrowserControlRequest{Operation: "execute", CallID: op, Action: a})
	var out BrowserControlResult
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out, w.Code
}
func (f *browserRuntimeFixture) grant(mode string) {
	f.t.Helper()
	rows, _ := f.store.LinkedAccounts(f.t.Context(), "usr_alice")
	for _, a := range rows {
		if a.ID == f.account.ID {
			f.account = a
		}
	}
	w := f.request(BrowserControlRequest{Operation: "grant", Revision: f.account.Revision, Mode: mode})
	if w.Code != 200 {
		f.t.Fatalf("grant %s: %d %s", mode, w.Code, w.Body.String())
	}
}
func TestFileBrowserRuntimeLifecycle(t *testing.T) {
	testBrowserRuntimeLifecycle(t, newLibraryFileStore(t))
}
func TestPgBrowserRuntimeLifecycle(t *testing.T) {
	testBrowserRuntimeLifecycle(t, newPgConnectionsStore(t))
}
func testBrowserRuntimeLifecycle(t *testing.T, store browserRuntimeTestStore) {
	f := newBrowserRuntimeFixture(t, store)
	if _, code := f.call("no_grant", BrowserAction{Operation: "open"}); code != 403 {
		t.Fatalf("ungranted open: %d", code)
	}
	f.grant("read")
	if _, code := f.call("open", BrowserAction{Operation: "open"}); code != 200 {
		t.Fatalf("open: %d", code)
	}
	snap, code := f.call("snapshot", BrowserAction{Operation: "snapshot"})
	if code != 200 || snap.Snapshot == nil {
		t.Fatalf("snapshot: %+v %d", snap, code)
	}
	if _, code = f.call("click", BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}); code != 409 {
		t.Fatal("read grant allowed click")
	}
	if _, code = f.call("offsite", BrowserAction{Operation: "navigate", URL: "https://evil.example/"}); code != 403 {
		t.Fatal("offsite navigation allowed")
	}
	// Changing the grant invalidates an existing session, even for the same owner.
	f.grant("automatic")
	if _, code = f.call("stale", BrowserAction{Operation: "snapshot"}); code != 409 {
		t.Fatal("old session survived grant replacement")
	}
	f.c.browserSignIn.Reconcile(t.Context())
	rows, _ := store.BrowserRuns(t.Context())
	for _, r := range rows {
		if r.ID == browserRunID(f.execution, f.account.ID) && (r.State != "closed" || r.ConnectURL != "" || r.Snapshot != nil) {
			t.Fatal("revoked session not cleaned")
		}
	}
	f.execution = "run_" + newEpoch()
	if _, code = f.call("open_new", BrowserAction{Operation: "open"}); code != 200 {
		t.Fatalf("new execution: %d", code)
	}
	snap, _ = f.call("snapshot_new", BrowserAction{Operation: "snapshot"})
	action := BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}
	if _, code = f.call("publish", action); code != 200 {
		t.Fatalf("automatic click: %d", code)
	}
	before := len(f.p.calls)
	again, code := f.call("publish", action)
	if code != 200 || again.Status != "already_dispatched" || len(f.p.calls) != before {
		t.Fatal("replayed an issued publication")
	}
	// Reconnect/disconnect invalidates every grant without touching legacy MCP.
	linked, _ := store.LinkedAccounts(t.Context(), "usr_alice")
	var current LinkedAccountRecord
	for _, a := range linked {
		if a.ID == f.account.ID {
			current = a
		}
	}
	empty := ""
	_, err := store.MutateLinkedAccount(t.Context(), current.ConnectionID, current.ID, current.OwnerSubject, current.Revision, accountPolicyPrecondition(f.parent), LinkedAccountMutation{BearerToken: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if _, code = f.call("disconnected", BrowserAction{Operation: "snapshot"}); code != 403 {
		t.Fatal("disconnected account remained usable")
	}
	parent, _ := store.Account(f.parent.Name)
	if parent.BearerToken != "legacy-credential" {
		t.Fatal("MCP credential changed")
	}
}
func TestBrowserRuntimeApprovalAndRevocation(t *testing.T) {
	for _, decision := range []string{"approved", "denied", "revoked"} {
		t.Run(decision, func(t *testing.T) {
			f := newBrowserRuntimeFixture(t, newLibraryFileStore(t))
			f.grant("approval")
			f.call("open", BrowserAction{Operation: "open"})
			snap, _ := f.call("snapshot", BrowserAction{Operation: "snapshot"})
			action := BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}
			pending, code := f.call("action", action)
			if code != 200 || pending.Status != "pending" || len(f.p.calls) != 2 {
				t.Fatalf("approval was bypassed: %+v %d", pending, code)
			}
			p, found, _ := f.store.ApprovalCall(t.Context(), pending.ApprovalID)
			if !found || p.Args["target"] == nil || p.PrivateOwnerSubject != "usr_alice" {
				t.Fatal("missing reviewable target")
			}
			if _, code = f.call("other", BrowserAction{Operation: "navigate", URL: "https://www.linkedin.com/elsewhere"}); code != 409 {
				t.Fatal("changed page while approval pending")
			}
			if decision == "revoked" {
				f.grant("read")
			} else {
				if err := f.c.gw.Decide(withPlatformActor(t.Context(), PlatformActor{UserID: "usr_alice", Role: "owner"}), p.ID, decision); err != nil {
					t.Fatal(err)
				}
			}
			out, code := f.call("action", action)
			if decision == "approved" {
				if code != 200 || out.Status != "ok" || len(f.p.calls) != 3 {
					t.Fatalf("approved: %+v %d", out, code)
				}
			} else if len(f.p.calls) != 2 {
				t.Fatal("denied/revoked action dispatched")
			}
		})
	}
}
func TestBrowserRuntimeConcurrentClaimAndUnknownOutcome(t *testing.T) {
	f := newBrowserRuntimeFixture(t, newLibraryFileStore(t))
	f.grant("automatic")
	f.call("open", BrowserAction{Operation: "open"})
	snap, _ := f.call("snapshot", BrowserAction{Operation: "snapshot"})
	f.p.fail = true
	a := BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); f.call("publish", a) }()
	}
	wg.Wait()
	if len(f.p.calls) != 3 {
		t.Fatalf("uncertain action repeated: %v", f.p.calls)
	}
	if _, code := f.call("new_publish", a); code != 409 {
		t.Fatal("uncertain session accepted more actions")
	}
}
func TestBrowserRuntimeServiceBoundary(t *testing.T) {
	if !platformServiceControlRoute("POST", "/control/v1/browser-runtime") || platformServiceControlRoute("GET", "/control/v1/browser-runtime") {
		t.Fatal("service allowlist")
	}
	f := newBrowserRuntimeFixture(t, newLibraryFileStore(t))
	for _, actor := range []PlatformActor{{UserID: "usr_alice", Role: "owner"}, {UserID: platformServiceActorID, Role: "owner"}} {
		req := httptest.NewRequest(http.MethodPost, "/control/v1/browser-runtime", strings.NewReader(`{}`))
		req = req.WithContext(withPlatformActor(req.Context(), actor))
		w := httptest.NewRecorder()
		f.c.browserRuntimeHandler(w, req)
		if w.Code != 403 {
			t.Fatal("non-service runtime allowed")
		}
	}
}

func TestBrowserRunFileRestartAndSnapshotBudget(t *testing.T) {
	store := newLibraryFileStore(t)
	f := newBrowserRuntimeFixture(t, store)
	f.grant("read")
	f.call("open", BrowserAction{Operation: "open"})
	f.call("snapshot", BrowserAction{Operation: "snapshot"})
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reloaded.BrowserRuns(t.Context())
	if err != nil || len(rows) != 1 || rows[0].ConnectURL != "private-runtime-connect" {
		t.Fatal("runtime ledger lost on restart", err)
	}
	rows[0].Actions["open"] = BrowserActionReceipt{}
	again, _ := reloaded.BrowserRuns(t.Context())
	if again[0].Actions["open"].State != "done" {
		t.Fatal("caller mutated durable receipts")
	}
	accounts, _ := reloaded.LinkedAccounts(t.Context(), "usr_alice")
	if len(accounts[0].BrowserGrants) != 1 {
		t.Fatal("grant lost on restart")
	}
	accounts[0].BrowserGrants[0].Mode = "automatic"
	accounts, _ = reloaded.LinkedAccounts(t.Context(), "usr_alice")
	if accounts[0].BrowserGrants[0].Mode != "read" {
		t.Fatal("caller mutated durable grant")
	}
	snapshot := &BrowserSnapshot{ID: "snapshot", URL: "https://www.linkedin.com/feed", Text: strings.Repeat("日本語", 16000)}
	for i := 1; i <= 200; i++ {
		snapshot.Elements = append(snapshot.Elements, BrowserElement{ID: i, Label: strings.Repeat("日本語", 200)})
	}
	if !boundBrowserSnapshot(snapshot) {
		t.Fatal("snapshot failed bounds")
	}
	raw, _ := json.Marshal(snapshot)
	if len(raw) > 24<<10 {
		t.Fatal("snapshot exceeds tool budget")
	}
}

func TestBrowserRuntimePrivateApprovalDoesNotNotifySharedChannels(t *testing.T) {
	f := newBrowserRuntimeFixture(t, newLibraryFileStore(t))
	webhook, events := captureWebhook(t)
	defer webhook.Close()
	f.c.gw.SetAlertWebhook(webhook.URL)
	f.grant("approval")
	f.call("open", BrowserAction{Operation: "open"})
	snap, _ := f.call("snapshot", BrowserAction{Operation: "snapshot"})
	pending, code := f.call("action", BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1})
	if code != 200 || pending.Status != "pending" {
		t.Fatalf("park: %d %+v", code, pending)
	}
	ctx := withPlatformActor(t.Context(), PlatformActor{UserID: "usr_alice", Role: "owner"})
	if err := f.c.gw.Decide(ctx, pending.ApprovalID, ApprovalApproved); err != nil {
		t.Fatal(err)
	}
	select {
	case evt := <-events:
		t.Fatalf("private browser approval reached shared webhook: %s", evt.Event)
	case <-time.After(100 * time.Millisecond):
	}
}
