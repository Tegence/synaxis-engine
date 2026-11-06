package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func modernMCPRequest(t *testing.T, ctx context.Context, endpoint string, method mcp.MCPMethod, params map[string]any) *http.Request {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		mcp.MetaKeyProtocolVersion:    mcp.ProtocolVersion20260728,
		mcp.MetaKeyClientCapabilities: map[string]any{},
		mcp.MetaKeyClientInfo:         map[string]any{"name": "protocol-upgrade-test", "version": "1.0"},
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion20260728)
	request.Header.Set(mcp.HeaderMethod, string(method))
	if name, ok := params["name"].(string); ok {
		request.Header.Set(mcp.HeaderName, name)
	}
	return request
}

func TestMCP2026DiscoverTracksClientLibraryProjection(t *testing.T) {
	ctx := t.Context()
	store, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Dynamic bootstrap", Subject: "agt_bootstrap", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(store, NewRootMCPServer())
	if err := gateway.buildMCPClient(client, nil); err != nil {
		t.Fatal(err)
	}
	endpoint := gateway.clientEndpoints[client.Slug]
	httpServer := httptest.NewServer(endpoint.handler)
	defer httpServer.Close()

	for _, projection := range []string{LibraryProjectionFull, LibraryProjectionPrivateOutputs, LibraryProjectionFull} {
		client, err = store.UpdateMCPClient(ctx, MCPClient{
			ID: client.ID, Name: client.Name, LibraryProjection: projection, libraryProjectionSet: true,
		}, MCPClientPrecondition{ID: client.ID, Revision: client.Revision})
		if err != nil {
			t.Fatal(err)
		}
		if err := gateway.buildMCPClient(client, nil); err != nil {
			t.Fatal(err)
		}
		if gateway.clientEndpoints[client.Slug] != endpoint {
			t.Fatal("projection change replaced the stable endpoint")
		}
		request := modernMCPRequest(t, ctx, httpServer.URL+"/mcp/clients/"+client.Slug, mcp.MethodServerDiscover, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var message struct {
			Result mcp.DiscoverResult `json:"result"`
			Error  json.RawMessage    `json:"error"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&message)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil || len(message.Error) > 0 {
			t.Fatalf("discover status=%d decode=%v error=%s", response.StatusCode, decodeErr, message.Error)
		}
		wantMemory := projection == LibraryProjectionFull
		want := mcpBootstrapInstructions(mcpBootstrapSurfaceClient, mcpBootstrapFeatures{library: true, memory: wantMemory})
		if message.Result.Instructions != want {
			t.Fatalf("discover instructions after %s projection = %q, want %q", projection, message.Result.Instructions, want)
		}
		// Legacy clients must observe the same current features.
		if got := mcpInitializeResult(t, endpoint.mcp).Instructions; got != want {
			t.Fatalf("initialize instructions after %s projection = %q, want %q", projection, got, want)
		}
	}
}

func TestMCP2026ListeningStreamEndsBeforeHostTimeout(t *testing.T) {
	previous := mcpListenStreamMaxAge
	mcpListenStreamMaxAge = 50 * time.Millisecond
	t.Cleanup(func() { mcpListenStreamMaxAge = previous })
	mcpServer := server.NewMCPServer("listen-test", "1.0", server.WithToolCapabilities(true))
	endpoint := httptest.NewServer(NewStreamableMCPHandler(mcpServer, "/mcp"))
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	request := modernMCPRequest(t, ctx, endpoint.URL+"/mcp", mcp.MethodSubscriptionsListen, map[string]any{
		"notifications": map[string]any{"toolsListChanged": true},
	})
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("listen status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("listen stream did not end cleanly before the caller's timeout: %v", err)
	}
	if !strings.Contains(string(body), string(mcp.MethodNotificationSubscriptionsAcknowledged)) {
		t.Fatalf("listen stream did not acknowledge the subscription: %s", body)
	}
	if ctx.Err() != nil {
		t.Fatal("listen stream lasted until the caller's timeout")
	}
}

func TestMCP2026ToolCallRetainsCallerDeadline(t *testing.T) {
	previous := mcpListenStreamMaxAge
	mcpListenStreamMaxAge = 25 * time.Millisecond
	t.Cleanup(func() { mcpListenStreamMaxAge = previous })
	mcpServer := server.NewMCPServer("tool-test", "1.0", server.WithToolCapabilities(true))
	mcpServer.AddTool(mcp.NewTool("slow"), func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		select {
		case <-time.After(4 * mcpListenStreamMaxAge):
			return mcp.NewToolResultText("completed"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	endpoint := httptest.NewServer(NewStreamableMCPHandler(mcpServer, "/mcp"))
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	request := modernMCPRequest(t, ctx, endpoint.URL+"/mcp", mcp.MethodToolsCall, map[string]any{"name": "slow", "arguments": map[string]any{}})
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"text":"completed"`) {
		t.Fatalf("ordinary tool call was cut short: status=%d error=%v body=%s", response.StatusCode, err, body)
	}
}

func TestUpstreamKeepsLegacyInitializeWithoutDiscoveryProbe(t *testing.T) {
	useLoopbackUpstreamTransport(t)
	mcpServer := server.NewMCPServer("legacy-upstream", "1.0", server.WithToolCapabilities(true))
	mcpServer.AddTool(mcp.NewTool("search"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("found"), nil
	})
	transport := server.NewStreamableHTTPServer(mcpServer, server.WithEndpointPath("/mcp"))
	var mu sync.Mutex
	var methods, offeredVersions []string
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer expected-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read failed", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var message struct {
				Method string `json:"method"`
				Params struct {
					ProtocolVersion string `json:"protocolVersion"`
				} `json:"params"`
			}
			if err := json.Unmarshal(body, &message); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			mu.Lock()
			methods = append(methods, message.Method)
			if message.Method == "initialize" {
				offeredVersions = append(offeredVersions, message.Params.ProtocolVersion)
			}
			mu.Unlock()
		}
		transport.ServeHTTP(w, r)
	}))
	defer endpoint.Close()
	upstream := &Upstream{Name: "legacy", URL: endpoint.URL + "/mcp", Token: func() string { return "expected-token" }}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if tools, err := upstream.ListTools(ctx); err != nil || len(tools) != 1 {
		t.Fatalf("list tools = %v, %v", tools, err)
	}
	if result, err := upstream.CallTool(ctx, "search", nil); err != nil || result == nil || result.IsError {
		t.Fatalf("call tool = %+v, %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(methods) == 0 || methods[0] != "initialize" || len(offeredVersions) != 2 {
		t.Fatalf("fresh dials did not begin with initialize: methods=%v versions=%v", methods, offeredVersions)
	}
	for _, method := range methods {
		if method == string(mcp.MethodServerDiscover) {
			t.Fatalf("legacy adapter sent a modern discovery probe: %v", methods)
		}
	}
	for _, version := range offeredVersions {
		if version != "2025-11-25" {
			t.Fatalf("offered protocol=%q, want stable legacy contract 2025-11-25", version)
		}
	}
}
