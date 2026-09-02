package engine

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// staleReadAccountStore wraps FileStore to reproduce the exact interleaving
// the ghost-resurrection bug depends on: aggregateAccount and
// rebindCachedAccount snapshot g.store.Account(name) BEFORE acquiring g.mu
// (store I/O intentionally stays outside the lock), so a goroutine that is
// merely slow to reach g.mu.Lock() afterward — plausible under real lock
// contention — can still be holding a pre-delete "live" snapshot once a
// concurrent delete has already fully completed.
//
// Once armed, the NEXT Account call captures its result from the underlying
// store IMMEDIATELY (exactly what aggregateAccount's hoisted read would
// observe at that instant) but withholds returning it until release closes.
// This stands in for the delay between that snapshot and the caller's later
// g.mu.Lock() — unlike blockingAccountStore (gateway_connectors_stall_test.go),
// which re-reads the store only after unblocking and is built to prove the
// opposite property (no store I/O runs under g.mu at all).
type staleReadAccountStore struct {
	*FileStore
	mu      sync.Mutex
	armed   bool
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newStaleReadAccountStore(fs *FileStore) *staleReadAccountStore {
	return &staleReadAccountStore{
		FileStore: fs,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
}

func (s *staleReadAccountStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *staleReadAccountStore) Account(name string) (Account, bool) {
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if !armed {
		return s.FileStore.Account(name)
	}
	account, live := s.FileStore.Account(name)
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return account, live
}

// mainToolNames issues a real tools/list JSON-RPC request against the
// gateway's default /mcp server and returns the sorted set of registered
// (prefixed) tool names — the same surface an MCP client sees.
func mainToolNames(t *testing.T, g *Gateway) []string {
	t.Helper()
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
		"params": map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal tools/list request: %v", err)
	}
	resp := g.mcp.HandleMessage(context.Background(), req)
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal tools/list response: %v", err)
	}
	var parsed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal tools/list response: %v (raw=%s)", err, out)
	}
	names := make([]string, 0, len(parsed.Result.Tools))
	for _, tool := range parsed.Result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// TestRefreshConnectorsPrunesGhostAfterHoistedReadLosesDeleteRace reproduces
// the resurrection bug the g.mu lock-scope hoist can otherwise cause:
//
//  1. Goroutine A begins refreshing account "ghost" (addAccountSnapshot ->
//     aggregateAccount). Its hoisted read (current, live :=
//     g.store.Account(a.Name), immediately before g.mu.Lock()) captures a
//     pre-delete, live=true snapshot, then stalls — standing in for A being
//     stuck on real g.mu contention before it can act on that snapshot.
//  2. While A is stalled, goroutine B fully deletes "ghost": a durable
//     store.Delete followed by gw.RemoveAccount (live cleanup +
//     RefreshConnectors), mirroring the console DELETE handler.
//  3. A is released. It writes its stale snapshot back, resurrecting
//     "ghost" into g.byAcct/g.cached/g.projectedIncarnations (and onto the
//     shared /mcp server) — then addAccountSnapshot's own trailing
//     RefreshConnectors call must prune that ghost in the same cycle.
//
// A second account, "keeper", stays live throughout: it proves the fix
// prunes only the actual orphan and (via the len(accounts)>0 guard in
// RefreshConnectors, deliberate — see its comment) that pruning engages at
// all whenever the store still has at least one account to report.
//
// The regression this guards against: without pruning, nothing ever diffs
// the in-memory maps against the store, so the ghost tool registration would
// stay visible in tools/list until process restart or name reuse.
func TestRefreshConnectorsPrunesGhostAfterHoistedReadLosesDeleteRace(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := newStaleReadAccountStore(fs)
	ctx := context.Background()
	if err := store.Upsert(ctx, Account{Name: "ghost", URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatalf("seed ghost account: %v", err)
	}
	if err := store.Upsert(ctx, Account{Name: "keeper", URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatalf("seed keeper account: %v", err)
	}

	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(a.Name + "__do_thing")}, nil
	}

	// Unarmed baseline: both accounts start out live, cached, and visible.
	if n := g.Aggregate(ctx); n != 2 {
		t.Fatalf("aggregate count=%d, want 2", n)
	}
	if names := mainToolNames(t, g); !sameStrings(names, []string{"ghost__do_thing", "keeper__do_thing"}) {
		t.Fatalf("tools/list before race = %v, want [ghost__do_thing keeper__do_thing]", names)
	}

	a, ok := store.Account("ghost")
	if !ok {
		t.Fatal("seeded account missing")
	}

	// Arm, then start goroutine A: a refresh of "ghost" using the
	// already-captured snapshot above, exactly like AddAccount/
	// AddAccountForIncarnation would pass to addAccountSnapshot. Its
	// internal hoisted read captures live=true right now, then stalls.
	store.arm()
	addDone := make(chan error, 1)
	go func() {
		_, err := g.addAccountSnapshot(ctx, a)
		addDone <- err
	}()

	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for goroutine A's hoisted read")
	}

	// Goroutine B: a full, concurrent delete of "ghost" — durable delete
	// then live cleanup — completes entirely while A is still stalled
	// holding its pre-delete snapshot.
	if err := store.Delete(ctx, "ghost", a.IncarnationID, a.Revision); err != nil {
		close(store.release)
		<-addDone
		t.Fatalf("delete: %v", err)
	}
	g.RemoveAccount("ghost", a.IncarnationID)

	g.mu.Lock()
	_, stillCached := g.cached["ghost"]
	g.mu.Unlock()
	if stillCached {
		close(store.release)
		<-addDone
		t.Fatal("account still cached immediately after a completed delete")
	}

	// Release A. It resurrects "ghost" from its stale snapshot, then (still
	// inside addAccountSnapshot) runs RefreshConnectors, which must prune
	// the ghost it just wrote back within this same cycle.
	close(store.release)
	if err := <-addDone; err != nil {
		t.Fatalf("goroutine A returned an error: %v", err)
	}

	g.mu.Lock()
	_, byAcct := g.byAcct["ghost"]
	_, cached := g.cached["ghost"]
	_, incarnation := g.projectedIncarnations["ghost"]
	_, keeperByAcct := g.byAcct["keeper"]
	_, keeperCached := g.cached["keeper"]
	_, keeperIncarnation := g.projectedIncarnations["keeper"]
	g.mu.Unlock()
	if byAcct || cached || incarnation {
		t.Fatalf("ghost account resurrected after delete: byAcct=%v cached=%v projectedIncarnations=%v", byAcct, cached, incarnation)
	}
	if !keeperByAcct || !keeperCached || !keeperIncarnation {
		t.Fatalf("unrelated live account pruned too: byAcct=%v cached=%v projectedIncarnations=%v", keeperByAcct, keeperCached, keeperIncarnation)
	}
	if names := mainToolNames(t, g); !sameStrings(names, []string{"keeper__do_thing"}) {
		t.Fatalf("tools/list after race = %v, want only [keeper__do_thing]", names)
	}
}
