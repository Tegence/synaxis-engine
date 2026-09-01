package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"narthex/backend/internal/upstreamoauth"
)

// useLoopbackUpstreamTransport is restricted to tests that exercise local
// httptest MCP servers. Production Upstreams always construct the hardened
// transport; each test restores that default before it exits.
func useLoopbackUpstreamTransport(t *testing.T) {
	t.Helper()
	previous := newUpstreamTransport
	newUpstreamTransport = func() http.RoundTripper { return http.DefaultTransport }
	t.Cleanup(func() { newUpstreamTransport = previous })
}

func TestUpstreamRejectsLoopbackByDefault(t *testing.T) {
	upstream := &Upstream{Name: "blocked", URL: "http://127.0.0.1:65535/mcp"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := upstream.ListTools(ctx)
	if !errors.Is(err, upstreamoauth.ErrUnsafeOutboundAddress) {
		t.Fatalf("loopback upstream error = %v, want ErrUnsafeOutboundAddress", err)
	}
}

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
	useLoopbackUpstreamTransport(t)
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
	useLoopbackUpstreamTransport(t)
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

// TestToolLevelErrorMentioning401NeverRefreshesOrReexecutes guards the fix
// for the substring-matching hazard: a TOOL-LEVEL JSON-RPC error whose text
// happens to contain "401"/"invalid_token" is not a transport 401. The engine
// must surface it to the caller without burning a rotating refresh token and
// without re-executing the (possibly mutating) tool call.
func TestToolLevelErrorMentioning401NeverRefreshesOrReexecutes(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	upstream := server.NewMCPServer("flaky", "1.0", server.WithToolCapabilities(true))
	upstream.AddTool(
		mcp.NewTool("mutate", mcp.WithDescription("mutating tool")),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("done"), nil
		},
	)
	streamable := server.NewStreamableHTTPServer(upstream, server.WithEndpointPath("/"))

	var toolCallRequests int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			streamable.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(raw, &request); err != nil ||
			request.Method != string(mcp.MethodToolsCall) {
			streamable.ServeHTTP(w, r)
			return
		}
		// HTTP 200 — the transport is fine. The TOOL failed, and its protocol-
		// level error text mentions auth material, exactly the phrasing the old
		// substring matcher mistook for a transport 401.
		atomic.AddInt32(&toolCallRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":`+
			`"tool failed: upstream returned 401 unauthorized (invalid_token: invalid access token)"}}`,
			request.ID, mcp.INTERNAL_ERROR)
	}))
	defer mock.Close()

	var refreshes int32
	up := &Upstream{
		Name:  "flaky",
		URL:   mock.URL,
		Token: func() string { return "" },
		Refresh: func(ctx context.Context) error {
			atomic.AddInt32(&refreshes, 1)
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := up.CallTool(ctx, "mutate", nil); err == nil {
		t.Fatal("tool-level JSON-RPC error should propagate to the caller")
	}
	if n := atomic.LoadInt32(&refreshes); n != 0 {
		t.Fatalf("tool-level error mentioning 401 triggered %d refreshes, want 0", n)
	}
	if n := atomic.LoadInt32(&toolCallRequests); n != 1 {
		t.Fatalf("tools/call reached the upstream %d times, want exactly 1 (no re-execution)", n)
	}
}

func newOversizedResponseUpstream(
	t *testing.T,
	mediaType string,
	chunked bool,
	compressed ...bool,
) *httptest.Server {
	t.Helper()
	upstream := server.NewMCPServer("oversized", "1.0", server.WithToolCapabilities(true))
	upstream.AddTool(
		mcp.NewTool("run", mcp.WithDescription("return a hostile response")),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Fatal("oversized tools/call should be intercepted before the MCP handler")
			return nil, nil
		},
	)
	streamable := server.NewStreamableHTTPServer(upstream, server.WithEndpointPath("/"))
	hugeText := strings.Repeat("x", int(maxUpstreamMCPResponseBytes)+1024)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			streamable.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))

		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(raw, &request); err != nil ||
			request.Method != string(mcp.MethodToolsCall) {
			streamable.ServeHTTP(w, r)
			return
		}

		var response bytes.Buffer
		response.Grow(len(hugeText) + 256)
		if mediaType == "text/event-stream" {
			response.WriteString("event: message\ndata: ")
		}
		response.WriteString(`{"jsonrpc":"2.0","id":`)
		response.Write(request.ID)
		response.WriteString(`,"result":{"content":[{"type":"text","text":"`)
		response.WriteString(hugeText)
		response.WriteString(`"}]}}`)
		if mediaType == "text/event-stream" {
			response.WriteString("\n\n")
		}

		responseBody := response.Bytes()
		if len(compressed) > 0 && compressed[0] {
			var encoded bytes.Buffer
			writer := gzip.NewWriter(&encoded)
			if _, err := writer.Write(responseBody); err != nil {
				t.Errorf("compress upstream response: %v", err)
				http.Error(w, "compress response", http.StatusInternalServerError)
				return
			}
			if err := writer.Close(); err != nil {
				t.Errorf("close upstream compressor: %v", err)
				http.Error(w, "compress response", http.StatusInternalServerError)
				return
			}
			responseBody = encoded.Bytes()
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Header().Set("Content-Type", mediaType)
		if chunked {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write(responseBody)
	}))
}

func TestUpstreamCapsResponsesBeforeJSONAndSSEDecode(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	for _, tc := range []struct {
		name       string
		mediaType  string
		chunked    bool
		compressed bool
	}{
		{name: "JSON with content length", mediaType: "application/json"},
		{name: "gzip JSON", mediaType: "application/json", compressed: true},
		{name: "chunked SSE", mediaType: "text/event-stream", chunked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newOversizedResponseUpstream(t, tc.mediaType, tc.chunked, tc.compressed)
			defer mock.Close()
			upstream := &Upstream{
				Name: "hostile", URL: mock.URL,
				Token: func() string { return "" },
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := upstream.CallTool(ctx, "run", nil)
			if !errors.Is(err, ErrUpstreamResponseTooLarge) {
				t.Fatalf("oversized %s response error = %v", tc.mediaType, err)
			}
		})
	}
}

func TestUpstreamBoundsCumulativePaginatedToolDiscovery(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	upstream := server.NewMCPServer("paginated", "1.0", server.WithToolCapabilities(true))
	streamable := server.NewStreamableHTTPServer(upstream, server.WithEndpointPath("/"))
	description := strings.Repeat("d", int(maxUpstreamMCPResponseBytes/2)+1024)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			streamable.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(raw, &request); err != nil ||
			request.Method != string(mcp.MethodToolsList) {
			streamable.ServeHTTP(w, r)
			return
		}
		var response bytes.Buffer
		response.Grow(len(description) + 256)
		response.WriteString(`{"jsonrpc":"2.0","id":`)
		response.Write(request.ID)
		response.WriteString(`,"result":{"tools":[{"name":"run","description":"`)
		response.WriteString(description)
		response.WriteString(`","inputSchema":{"type":"object"}}],"nextCursor":"again"}}`)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(response.Len()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response.Bytes())
	}))
	defer mock.Close()

	client := &Upstream{
		Name: "paginated", URL: mock.URL,
		Token: func() string { return "" },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.ListTools(ctx); !errors.Is(err, ErrUpstreamResponseTooLarge) {
		t.Fatalf("cumulative paginated discovery error = %v", err)
	}
}

func TestGatewayMapsPreDecodeCapToStructuredToolError(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	mock := newOversizedResponseUpstream(t, "application/json", false)
	defer mock.Close()
	fileStore, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.Upsert(context.Background(), Account{
		Name: "hostile", URL: mock.URL, AuthMode: "token", BearerToken: "token",
	}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(
		fileStore,
		server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)),
	)
	if count := gateway.Aggregate(context.Background()); count != 1 {
		t.Fatalf("aggregate count = %d", count)
	}
	usageStore := &stubUsageStore{}
	gateway.SetUsageGate(activeStubGate(t, usageStore, StarterMaxCallSeconds))

	response := callMainTool(t, gateway, "hostile__run", nil)
	if !strings.Contains(response, `"isError":true`) ||
		!strings.Contains(response, `"code":"result_too_large"`) {
		t.Fatalf("pre-decode cap response = %s", response)
	}
	if usageStore.admissions != 1 || usageStore.settlements != 1 ||
		usageStore.lastBytes <= MaxMCPResultBytes {
		t.Fatalf(
			"pre-decode cap usage admissions=%d settlements=%d bytes=%d",
			usageStore.admissions,
			usageStore.settlements,
			usageStore.lastBytes,
		)
	}
}

func TestUpstreamBoundedBodyNeverReturnsMoreThanLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), int(maxUpstreamMCPResponseBytes)+1024)
	source := &trackingReadCloser{Reader: bytes.NewReader(payload)}
	exceeded := false
	body := &upstreamBoundedBody{
		source: source, remaining: maxUpstreamMCPResponseBytes,
		onExceeded: func() { exceeded = true },
	}
	consumed, err := io.ReadAll(body)
	if !errors.Is(err, ErrUpstreamResponseTooLarge) {
		t.Fatalf("bounded body error = %v", err)
	}
	if !exceeded ||
		int64(len(consumed)) > maxUpstreamMCPResponseBytes ||
		source.read > maxUpstreamMCPResponseBytes+1 {
		t.Fatalf(
			"bounded body consumed=%d source_read=%d exceeded=%v",
			len(consumed),
			source.read,
			exceeded,
		)
	}
}

type trackingReadCloser struct {
	io.Reader
	read int64
}

func (r *trackingReadCloser) Read(destination []byte) (int, error) {
	n, err := r.Reader.Read(destination)
	r.read += int64(n)
	return n, err
}

func (*trackingReadCloser) Close() error { return nil }
