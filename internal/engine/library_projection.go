package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Library projection decides which first-party Library tools a scoped MCP
// client receives. "full" (the default, and the meaning of an empty value)
// is the complete client Library surface. "private_outputs" keeps only the
// tools that write or read the client's own outputs and read its assigned
// skills: nothing that writes where another person reads.
const (
	LibraryProjectionFull           = "full"
	LibraryProjectionPrivateOutputs = "private_outputs"
)

// libraryPrivateOutputsTools is the whole private_outputs surface (SPEC
// §7.1.4 "Kept"): the client's own output and its new versions, a read that
// is limited to artifacts this client created (conversation replay), and the
// read side of the skills assigned to it. Every other client Library tool is
// removed: collaboration, artifact listing, image tools, memory, and skill
// authoring and runtime receipts. It is an allowlist, so a Library tool added
// later is removed from private_outputs clients until it is listed here.
var libraryPrivateOutputsTools = []string{
	"library_artifact_create",
	"library_artifact_version_create",
	"library_artifact_read",
	"library_skill_activation",
	"library_skill_read",
	"library_skill_resolve",
	"library_skill_file_read",
}

// normalizeLibraryProjection returns the stored form: "" for full (so
// records written before projections existed need no rewrite) and
// LibraryProjectionPrivateOutputs. Anything else is invalid.
func normalizeLibraryProjection(value string) (string, error) {
	switch value {
	case "", LibraryProjectionFull:
		return "", nil
	case LibraryProjectionPrivateOutputs:
		return LibraryProjectionPrivateOutputs, nil
	default:
		return "", fmt.Errorf("%w: libraryProjection must be %q or %q", ErrInvalidMCPClient, LibraryProjectionFull, LibraryProjectionPrivateOutputs)
	}
}

// effectiveLibraryProjection is the wire and runtime value. An unreadable
// stored value fails closed to the narrower projection.
func effectiveLibraryProjection(stored string) string {
	normalized, err := normalizeLibraryProjection(stored)
	if err != nil || normalized == LibraryProjectionPrivateOutputs {
		return LibraryProjectionPrivateOutputs
	}
	return LibraryProjectionFull
}

// libraryProjectionAllowsTool reports whether a client Library tool belongs
// to the projection.
func libraryProjectionAllowsTool(projection, tool string) bool {
	if effectiveLibraryProjection(projection) == LibraryProjectionFull {
		return true
	}
	return slices.Contains(libraryPrivateOutputsTools, tool)
}

// updatedMCPClientLibraryProjection is the stored projection after a generic
// client update: unchanged unless the update carries the presence bit.
func updatedMCPClientLibraryProjection(current, update MCPClient) (string, error) {
	if !update.libraryProjectionSet {
		return current.LibraryProjection, nil
	}
	return normalizeLibraryProjection(update.LibraryProjection)
}

// serviceMCPClientPatchFields is everything the Platform service actor may
// send on PATCH /control/v1/mcp-clients/{id}: it sets a workload client's
// Library projection under the revision fence and nothing else.
var serviceMCPClientPatchFields = map[string]bool{"libraryProjection": true, "revision": true}

// serviceActorOutsideWorkloadClient reports a Platform service request for a
// client it may not change. The service connects members' workload clients
// (PUT …/namespaces, PATCH libraryProjection) and never an interactive one;
// the refusal reads like an unknown client, as other kind-refused routes do.
func serviceActorOutsideWorkloadClient(actor PlatformActor, client MCPClient) bool {
	return actor.Role == "service" && mcpClientKind(client) != MCPClientKindWorkload
}

// serviceMCPClientPatchFailure limits the service actor's PATCH to a workload
// client and to libraryProjection plus revision; any other field is 403.
func serviceMCPClientPatchFailure(actor PlatformActor, client MCPClient, fields map[string]json.RawMessage) *consoleFailure {
	if actor.Role != "service" {
		return nil
	}
	if serviceActorOutsideWorkloadClient(actor, client) {
		return mcpClientFailure(ErrMCPClientKind)
	}
	if _, ok := fields["libraryProjection"]; !ok {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "libraryProjection and revision are required")
	}
	for field := range fields {
		if !serviceMCPClientPatchFields[field] {
			return newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "the service may change only libraryProjection")
		}
	}
	return nil
}

// decodeMCPClientPatch decodes the PATCH body once into both the typed
// request and its raw top-level fields, so the service-actor check sees
// exactly which fields were sent.
func decodeMCPClientPatch(w http.ResponseWriter, r *http.Request, request any, fields *map[string]json.RawMessage) *consoleFailure {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || json.Unmarshal(body, fields) != nil || json.Unmarshal(body, request) != nil {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid JSON body")
	}
	return nil
}

// platformServiceControlMCPClientConnectRoute recognizes exactly
// PUT /control/v1/mcp-clients/{id}/namespaces and
// PATCH /control/v1/mcp-clients/{id} for the Platform service actor.
func platformServiceControlMCPClientConnectRoute(method, requestPath string) bool {
	if method == http.MethodPut {
		return platformServiceControlMCPClientRoute(requestPath, "namespaces")
	}
	if method != http.MethodPatch {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")
	return len(parts) == 4 && parts[0] == "control" && parts[1] == "v1" && parts[2] == "mcp-clients" && validActorIdentifier(parts[3])
}

// projectMCPClientLibraryTools applies the client's Library projection to the
// client Library tools registered on s and returns the names that remain.
// For private_outputs it deletes every removed tool. For full it wraps each
// tool that private_outputs would remove with a durable re-check, because an
// Engine replica can keep serving handlers it built earlier: once the client
// is reduced, such a cached handler refuses the call even before the replica
// rebuilds its projection (the epoch rotation fences most tools already; this
// also covers the authoring tools that defer their own check to the store).
func projectMCPClientLibraryTools(s *server.MCPServer, store LibraryStore, client MCPClient) []string {
	projection := effectiveLibraryProjection(client.LibraryProjection)
	kept := make([]string, 0, len(mcpClientLibraryToolNames))
	var removed []string
	for _, name := range mcpClientLibraryToolNames {
		if libraryProjectionAllowsTool(projection, name) {
			kept = append(kept, name)
		} else {
			removed = append(removed, name)
		}
	}
	if projection == LibraryProjectionPrivateOutputs {
		s.DeleteTools(removed...)
		return kept
	}
	clients, ok := store.(MCPClientStore)
	if !ok {
		return kept
	}
	for name, tool := range s.ListTools() {
		if !slices.Contains(mcpClientLibraryToolNames, name) || libraryProjectionAllowsTool(LibraryProjectionPrivateOutputs, name) {
			continue
		}
		s.AddTool(tool.Tool, libraryProjectionGuard(clients, client.ID, name, tool.Handler))
	}
	return kept
}

// libraryProjectionRefusal is the tool error a guarded handler returns once
// the client's projection no longer includes the tool.
const libraryProjectionRefusal = "this Library tool is not available to this MCP client"

// libraryProjectionGuard refuses a call when the durable client's current
// projection no longer includes the tool. A missing client is left to the
// tool's own availability check.
func libraryProjectionGuard(clients MCPClientStore, clientID, tool string, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if current, found := clients.MCPClient(ctx, clientID); found && !libraryProjectionAllowsTool(current.LibraryProjection, tool) {
			return mcp.NewToolResultError(libraryProjectionRefusal), nil
		}
		return inner(ctx, request)
	}
}
