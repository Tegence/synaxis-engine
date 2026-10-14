package engine

import (
	"context"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// mcpListenStreamMaxAge ends a client's GET listening stream cleanly before
// the host cuts the request mid-response. Platform-managed Engines run on
// Cloud Run with a 930s request timeout (platform provision
// managedEngineRequestTimeout), which otherwise truncates every idle stream at
// 931s. Clients reopen the stream on the same session either way; an ordinary
// end-of-stream is simply not an error to them. A var so tests can shorten it.
var mcpListenStreamMaxAge = 14 * time.Minute

// mcpSessionIdleTTL sweeps sessions a client abandoned without DELETE.
// Session IDs are format-validated only, so a swept session's next request
// still works. It must stay above mcpListenStreamMaxAge so an open stream is
// always touched (by its reconnect) before it could be swept.
const mcpSessionIdleTTL = 30 * time.Minute

// NewStreamableMCPHandler is the one Streamable HTTP construction for every
// Engine MCP surface (root, connector, bundle, client).
func NewStreamableMCPHandler(m *server.MCPServer, path string) http.Handler {
	return &streamableMCPHandler{transport: server.NewStreamableHTTPServer(
		m,
		server.WithEndpointPath(path),
		server.WithSessionIdleTTL(mcpSessionIdleTTL),
	)}
}

// streamableMCPHandler is a pointer type so an endpoint's handler keeps a
// stable, comparable identity across rebuilds.
type streamableMCPHandler struct {
	transport *server.StreamableHTTPServer
}

func (h *streamableMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ctx, cancel := context.WithTimeout(r.Context(), mcpListenStreamMaxAge)
		defer cancel()
		r = r.WithContext(ctx)
	}
	h.transport.ServeHTTP(w, r)
}
