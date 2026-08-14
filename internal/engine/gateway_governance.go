package engine

import "github.com/mark3labs/mcp-go/server"

// governancePolicyScope identifies approvals/audit rows created by a durable
// tool policy rather than a manually-curated connector. It is deliberately not
// an MCP route: the policy follows a tool across the aggregate, endpoint
// bundles, curated connectors, and subject-bound clients.
const governancePolicyScope = "workspace-policy"

// governedAccountToolHandler applies the account-level governance preset to
// the one cached handler shared by every MCP delivery surface. Connector
// policies can add stricter controls, but cannot bypass this one.
func (g *Gateway) governedAccountToolHandler(
	account Account,
	bare string,
	preset GovernancePreset,
	inner server.ToolHandlerFunc,
) server.ToolHandlerFunc {
	if !preset.requiresApproval() {
		return inner
	}

	// Audit scope has to wrap approval so an approved call carries its decision
	// into the single dispatch audit row. scopedHandler merges this with an
	// outer connector/client scope, preserving the real endpoint attribution
	// while retaining a high-risk record requirement.
	// The aggregate endpoint is still the aggregate endpoint: leave its audit
	// delivery identity empty so a recorded high-risk root call remains a valid
	// root replay. approvalHandler uses governancePolicyScope as its fallback
	// label when this otherwise identity-free scope needs a human decision.
	return g.scopedHandler(
		"",
		"",
		"",
		preset.recordsPayloads(),
		nil,
		g.approvalHandler(governancePolicyScope, account, bare, inner),
	)
}
