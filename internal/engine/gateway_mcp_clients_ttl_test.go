package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// countingMCPClientStore wraps FileStore to count calls to ActiveMCPClient —
// the durable read refreshMCPClientRequest performs on the request path — so
// tests can prove MCPClientHandler's per-request rebuild is TTL-gated rather
// than unconditional.
type countingMCPClientStore struct {
	*FileStore
	mu    sync.Mutex
	reads int
}

func (c *countingMCPClientStore) ActiveMCPClient(ctx context.Context, id string) (MCPClient, bool) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.FileStore.ActiveMCPClient(ctx, id)
}

func (c *countingMCPClientStore) activeMCPClientReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func newCountingMCPClientGateway(t *testing.T) (*countingMCPClientStore, *Gateway) {
	t.Helper()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &countingMCPClientStore{FileStore: fs}
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}
	return store, gateway
}

// TestMCPClientHandlerRebuildsOnlyWhenStale proves Step 3: a client endpoint
// projection built within mcpClientProjectionTTL (as every mutation path
// already does synchronously via RefreshMCPClients) serves requests directly
// without a redundant durable rebuild, while a projection older than the TTL
// triggers exactly one rebuild before serving.
func TestMCPClientHandlerRebuildsOnlyWhenStale(t *testing.T) {
	ctx := context.Background()
	store, gateway := newCountingMCPClientGateway(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Codex", Subject: "usr_alice", CreatedBy: "usr_alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}

	handler, ok := gateway.MCPClientHandler(client.Slug)
	if !ok {
		t.Fatal("client endpoint has no handler")
	}
	serve := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+client.Slug, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// RefreshMCPClients above just built this endpoint, well inside the TTL:
	// these requests must be served without a redundant durable rebuild.
	serve()
	if got := store.activeMCPClientReads(); got != 0 {
		t.Fatalf("fresh-projection request performed %d durable rebuild reads, want 0", got)
	}
	serve()
	if got := store.activeMCPClientReads(); got != 0 {
		t.Fatalf("second fresh-projection request performed %d durable rebuild reads, want still 0", got)
	}

	// Age the projection past the TTL directly (white-box, same package) so
	// the next request must rebuild exactly once.
	gateway.mu.Lock()
	gateway.clientEndpoints[client.Slug].refreshedAt = time.Now().Add(-2 * mcpClientProjectionTTL)
	gateway.mu.Unlock()

	serve()
	if got := store.activeMCPClientReads(); got != 1 {
		t.Fatalf("stale-projection request performed %d durable rebuild reads, want 1", got)
	}

	// The rebuilt projection is fresh again: an immediate follow-up request
	// must not rebuild a second time.
	serve()
	if got := store.activeMCPClientReads(); got != 1 {
		t.Fatalf("request after rebuild performed %d durable rebuild reads, want still 1", got)
	}
}

// TestMCPClientHandlerRevocation404sImmediatelyRegardlessOfTTL proves the
// plan's "preserve the 404-on-not-found/revoked behavior exactly" guard:
// revoking a client removes it from the live projection synchronously (via
// RefreshMCPClients), so the very next request 404s even though it lands
// well inside what would otherwise be a warm TTL window.
func TestMCPClientHandlerRevocation404sImmediatelyRegardlessOfTTL(t *testing.T) {
	ctx := context.Background()
	store, gateway := newCountingMCPClientGateway(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Codex", Subject: "usr_alice", CreatedBy: "usr_alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	handler, ok := gateway.MCPClientHandler(client.Slug)
	if !ok {
		t.Fatal("client endpoint has no handler")
	}

	if _, err := store.RevokeMCPClient(ctx, client.ID, "usr_alice", MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+client.Slug, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoked client endpoint = %d, want 404", rec.Code)
	}
}
