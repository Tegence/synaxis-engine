package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// newMockUpstream returns an MCP server (one "search" tool) fronted by a Bearer
// check that 401s unless the presented token equals *validToken. Flipping
// *validToken simulates a token rotation that only a re-dial can pick up.
func newMockUpstream(t *testing.T, validToken *string, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	s := server.NewMCPServer("mock", "1.0", server.WithToolCapabilities(true))
	s.AddTool(
		mcp.NewTool("search", mcp.WithDescription("mock search")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("mock result"), nil
		},
	)
	streamable := server.NewStreamableHTTPServer(s, server.WithEndpointPath("/"))
	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		want := "Bearer " + *validToken
		mu.Unlock()
		if r.Header.Get("Authorization") != want {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_token","error_description":"Invalid access token"}`))
			return
		}
		streamable.ServeHTTP(w, r)
	})
	return httptest.NewServer(authed)
}

// TestRefreshAndRedial is the M3 proof: starting with a STALE token the first
// dial 401s; the upstream refreshes (rotating the token) and RE-DIALS, and the
// connection recovers — listing the tool. This is exactly what MetaMCP fails to
// do (it refreshes the stored token but keeps the dead pooled connection).
func TestRefreshAndRedial(t *testing.T) {
	var mu sync.Mutex
	valid := "TOKEN_FRESH" // the only token the upstream currently accepts

	mock := newMockUpstream(t, &valid, &mu)
	defer mock.Close()

	// The engine starts out holding a STALE token.
	var current atomic.Value
	current.Store("TOKEN_STALE")

	var refreshes int32
	up := &Upstream{
		Name:  "mock",
		URL:   mock.URL,
		Token: func() string { return current.Load().(string) },
		Refresh: func(ctx context.Context) error {
			atomic.AddInt32(&refreshes, 1)
			// A successful refresh yields the token the upstream now accepts.
			current.Store("TOKEN_FRESH")
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tools, err := up.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools after refresh-and-redial should succeed, got: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "mock__search" {
		t.Fatalf("want one prefixed tool mock__search, got: %v", tools)
	}
	if n := atomic.LoadInt32(&refreshes); n != 1 {
		t.Fatalf("expected exactly one refresh, got %d", n)
	}
}

// TestNoRefreshWhenHealthy: a valid token from the start needs no refresh.
func TestNoRefreshWhenHealthy(t *testing.T) {
	var mu sync.Mutex
	valid := "GOOD"
	mock := newMockUpstream(t, &valid, &mu)
	defer mock.Close()

	var refreshes int32
	up := &Upstream{
		Name:    "n",
		URL:     mock.URL,
		Token:   func() string { return "GOOD" },
		Refresh: func(ctx context.Context) error { atomic.AddInt32(&refreshes, 1); return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tools, err := up.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools should succeed with a good token: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(tools))
	}
	if n := atomic.LoadInt32(&refreshes); n != 0 {
		t.Fatalf("expected no refresh with a healthy token, got %d", n)
	}
}
