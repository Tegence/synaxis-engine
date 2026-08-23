package engine

import "github.com/mark3labs/mcp-go/mcp"

// skillLiveTools returns every currently registered tool across all
// accounts, keyed by its full prefixed name (e.g.
// "pagerduty__list_incidents"), for skill drift/check resolution.
//
// ASSUMPTION: skill manifests reference tools by that same prefixed name —
// the engine's real routing key (see Account.Name+"__"+bare in gateway.go) —
// not the dotted display form used cosmetically in the Figma mock
// ("pagerduty.list_incidents", "linear.create_issue"). The dotted form reads
// naturally in a design mock but does not correspond to any name the engine
// actually registers; using the real prefixed name means references_resolve
// and drift detection check against tools that truly exist, rather than a
// cosmetic alias the frontend would have to invent a mapping for.
func (g *Gateway) skillLiveTools() map[string]mcp.Tool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]mcp.Tool)
	for _, tools := range g.cached {
		for _, ct := range tools {
			out[ct.tool.Name] = ct.tool
		}
	}
	return out
}
