package engine

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Authorization wraps both approval and final dispatch. Revocation or expiry
// during an approval wait must not release a call.
func (g *Gateway) connectionGrantHandler(slug, grantID string, account Account, bare string, readOnly bool, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	guarded := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		client, ok := g.clientMayUseGrantedTool(ctx, slug, grantID, account, bare)
		if !ok {
			return mcp.NewToolResultError("this shared tool grant is no longer available"), nil
		}
		return inner(withMemberCaller(ctx, memberCaller{subject: client.Subject, workload: client.Kind == MCPClientKindWorkload}), req)
	}
	var dispatch server.ToolHandlerFunc = guarded
	if !readOnly {
		dispatch = g.approvalHandler(slug, account, bare, false, dispatch)
	}
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		client, ok := g.clientMayUseGrantedTool(ctx, slug, grantID, account, bare)
		if !ok {
			return mcp.NewToolResultError("this shared tool grant is no longer available"), nil
		}
		return dispatch(withMemberCaller(ctx, memberCaller{subject: client.Subject, workload: client.Kind == MCPClientKindWorkload}), req)
	}
}
func (g *Gateway) clientMayUseGrantedTool(ctx context.Context, slug, grantID string, snapshot Account, bare string) (MCPClient, bool) {
	clients, ok := g.mcpClientStore()
	if !ok {
		return MCPClient{}, false
	}
	client, found, err := lookupActiveMCPClient(ctx, clients, slug)
	if err != nil || !found {
		return MCPClient{}, false
	}
	account, found := g.store.Account(snapshot.Name)
	if !found || account.IncarnationID != snapshot.IncarnationID || account.Revision != snapshot.Revision {
		return MCPClient{}, false
	}
	store, ok := g.store.(ConnectionGrantStore)
	if !ok {
		return MCPClient{}, false
	}
	if account.OwnerSubject != "" {
		allowed, err := store.SubjectAllowed(ctx, account.OwnerSubject)
		if err != nil || !allowed {
			return MCPClient{}, false
		}
	}
	grants, err := store.ConnectionGrants(ctx)
	if err != nil {
		return MCPClient{}, false
	}
	for _, grant := range grants {
		if grant.ID == grantID && connectionGrantAllows(grant, account, client.Subject, bare, time.Now()) {
			return client, true
		}
	}
	return MCPClient{}, false
}
