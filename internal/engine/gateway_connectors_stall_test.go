package engine

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// blockingAccountStore wraps FileStore so a test can hold a single Account
// read open indefinitely — once armed, the first call blocks until the test
// closes release. Used to prove that a slow/stalled durable read during a
// projection rebuild no longer holds Gateway.mu (Plan 012 Step 1): if it
// did, every other g.mu-guarded call (ConnectorEpoch on the OAuth AS's hot
// path, for every /mcp* request) would queue behind it too.
type blockingAccountStore struct {
	*FileStore
	mu      sync.Mutex
	armed   bool
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newBlockingAccountStore(fs *FileStore) *blockingAccountStore {
	return &blockingAccountStore{
		FileStore: fs,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
}

// arm enables blocking for the NEXT Account call only (setup calls made
// before arm run unblocked, so the test can populate the store first).
func (b *blockingAccountStore) arm() {
	b.mu.Lock()
	b.armed = true
	b.mu.Unlock()
}

func (b *blockingAccountStore) Account(name string) (Account, bool) {
	b.mu.Lock()
	armed := b.armed
	b.mu.Unlock()
	if armed {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.FileStore.Account(name)
}

// TestConnectorEpochDoesNotStallBehindABlockedStoreRead is the plan's Step 4
// no-stall regression test: while a connector rebuild is blocked mid-read on
// a durable Account lookup, ConnectorEpoch for an ALREADY-LIVE connector —
// the lookup the OAuth AS makes on every token/code/refresh validation —
// must still return promptly instead of queuing behind Gateway.mu.
func TestConnectorEpochDoesNotStallBehindABlockedStoreRead(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := newBlockingAccountStore(fs)
	ctx := context.Background()
	if err := store.Upsert(ctx, Account{Name: "linear", URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(a.Name + "__get_issue")}, nil
	}

	// Unarmed setup: aggregate the account and stand up a live connector so
	// ConnectorEpoch has something to resolve.
	if n := g.Aggregate(ctx); n != 1 {
		t.Fatalf("aggregate count=%d, want 1", n)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug:  "work",
		Label: "Work",
		Tools: map[string][]string{"linear": {"get_issue"}},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	epochBefore, live := g.ConnectorEpoch("work")
	if !live || epochBefore == "" {
		t.Fatal("connector epoch not live after setup")
	}

	// Arm the store, then start a rebuild in the background that will block
	// mid-read inside buildConnector, well before it reaches g.mu.Lock().
	// RefreshConnectors (not a hand-built buildConnector call) re-reads the
	// connector from durable storage first, so its epoch is the real one —
	// mirroring how a rebuild is actually triggered in production (e.g. by
	// any account mutation).
	store.arm()
	rebuildDone := make(chan error, 1)
	go func() {
		g.RefreshConnectors(ctx)
		rebuildDone <- nil
	}()

	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the blocked rebuild to start its store read")
	}

	// The rebuild is now blocked INSIDE the store read. If that read ran
	// under g.mu (the bug this plan fixes), ConnectorEpoch would queue behind
	// it. Bound the call so a regression fails fast instead of hanging CI.
	epochResult := make(chan struct{})
	var epochAfter string
	var epochLive bool
	go func() {
		epochAfter, epochLive = g.ConnectorEpoch("work")
		close(epochResult)
	}()
	select {
	case <-epochResult:
	case <-time.After(2 * time.Second):
		close(store.release) // unblock the rebuild so the leaked goroutine can exit
		<-rebuildDone
		t.Fatal("ConnectorEpoch stalled behind a blocked store read — store I/O leaked back under g.mu")
	}
	if !epochLive || epochAfter != epochBefore {
		close(store.release)
		<-rebuildDone
		t.Fatalf("ConnectorEpoch during blocked rebuild = (%q, %v), want (%q, true)", epochAfter, epochLive, epochBefore)
	}

	close(store.release)
	if err := <-rebuildDone; err != nil {
		t.Fatalf("blocked rebuild returned an error after release: %v", err)
	}

	// The connector must still be intact and correctly rebuilt.
	if epoch, live := g.ConnectorEpoch("work"); !live || epoch != epochBefore {
		t.Fatalf("connector epoch after rebuild = (%q, %v), want (%q, true)", epoch, live, epochBefore)
	}
}
