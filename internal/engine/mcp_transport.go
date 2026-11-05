package engine

import (
	"context"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// mcpListenStreamMaxAge ends a client's listening stream cleanly before
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
	return newStreamableMCPHandler(m, path)
}

// newCallerGrantStreamableMCPHandler is NewStreamableMCPHandler for a
// workload client's /mcp/clients/{slug}: it also lifts X-Synaxis-Caller-Grant
// into the request context (liftCallerGrants). No other surface reads the
// header.
func newCallerGrantStreamableMCPHandler(m *server.MCPServer, path string) http.Handler {
	return newStreamableMCPHandler(m, path, server.WithHTTPContextFunc(liftCallerGrants))
}

func newStreamableMCPHandler(m *server.MCPServer, path string, extra ...server.StreamableHTTPOption) http.Handler {
	options := append([]server.StreamableHTTPOption{
		server.WithEndpointPath(path),
		server.WithSessionIdleTTL(mcpSessionIdleTTL),
	}, extra...)
	return &streamableMCPHandler{transport: server.NewStreamableHTTPServer(m, options...)}
}

// streamableMCPHandler is a pointer type so an endpoint's handler keeps a
// stable, comparable identity across rebuilds.
type streamableMCPHandler struct {
	transport *server.StreamableHTTPServer
}

func (h *streamableMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Legacy clients listen through GET; the stateless 2026 protocol uses a
	// subscriptions/listen POST instead. Its required Mcp-Method header is
	// checked against the body by the transport. Ordinary tool-call POSTs
	// retain their caller's deadline rather than the listening-stream limit.
	modernListen := r.Method == http.MethodPost &&
		mcp.IsModernProtocol(r.Header.Get(mcp.HeaderProtocolVersion)) &&
		r.Header.Get(mcp.HeaderMethod) == string(mcp.MethodSubscriptionsListen)
	if r.Method == http.MethodGet || modernListen {
		ctx, cancel := context.WithTimeout(r.Context(), mcpListenStreamMaxAge)
		defer cancel()
		r = r.WithContext(ctx)
	}
	h.transport.ServeHTTP(w, r)
}
