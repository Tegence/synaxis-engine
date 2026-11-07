package engine

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// accountDeliveredOnlyByExactGrant reports whether an account may reach a
// scoped MCP client only through that client's exact connection grant
// (ConnectionGrants[name] == IncarnationID). A caller-delegated account acts
// for whoever started a job, so listing its tools through a folder grant, the
// root /mcp, a connector or an endpoint bundle would hand them to clients no
// one chose for it. Those projections all consult this predicate.
func accountDeliveredOnlyByExactGrant(a Account) bool {
	return a.IsCallerDelegated()
}

// ErrCallerDelegatedAccountExposure refuses a shared endpoint (a connector or
// an endpoint bundle) that names a caller-delegated account. Such an account
// reaches a client only through that client's exact connection grant.
var ErrCallerDelegatedAccountExposure = errors.New("a caller-delegated connection is delivered only by an exact connection grant")

// removeExactOnlyRootProjectionLive drops any root /mcp registration of an
// exact-only account while keeping its cached tools for exact client
// delivery. aggregateAccount never registers such an account on root; this
// covers a durable row whose flag changed under a replica that had already
// projected it.
func (g *Gateway) removeExactOnlyRootProjectionLive(account Account) {
	current, ok := g.store.Account(account.Name)
	if !ok || current.IncarnationID != account.IncarnationID || !accountDeliveredOnlyByExactGrant(current) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if names := g.byAcct[account.Name]; len(names) > 0 {
		g.mcp.DeleteTools(names...)
	}
	delete(g.byAcct, account.Name)
}

// controlCodeApprovalNotSupportedForDelegated refuses an approval policy (a
// tool-governance preset that requires approval, a connector's
// require_approval list, or a shared tool grant, whose writes always wait for
// approval) on a caller-delegated account. A parked call would store the
// tool arguments for a Synaxis approver to read, and only the person who
// started the job may see them.
const controlCodeApprovalNotSupportedForDelegated = "approval_not_supported_for_delegated"

const approvalNotSupportedForDelegatedMessage = "approval policies are not supported for a caller-delegated connection"

// writeApprovalNotSupportedForDelegated answers 400 with the stable code on
// both wire surfaces: problem details on /control/v1, and the console's
// {"error"} body (plus "code") on /api.
func writeApprovalNotSupportedForDelegated(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, controlV1PathPrefix) {
		writeControlProblem(w, http.StatusBadRequest, controlCodeApprovalNotSupportedForDelegated, approvalNotSupportedForDelegatedMessage)
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"code": controlCodeApprovalNotSupportedForDelegated, "error": approvalNotSupportedForDelegatedMessage})
}

// callerDelegatedApprovalTarget reports the first account in an approval map
// (account name -> bare tool names) that is caller-delegated and has at least
// one tool listed.
func callerDelegatedApprovalTarget(store AccountStore, approval map[string][]string) (string, bool) {
	for name, tools := range approval {
		if len(tools) == 0 {
			continue
		}
		if account, found := store.Account(name); found && accountDeliveredOnlyByExactGrant(account) {
			return name, true
		}
	}
	return "", false
}

// callerDelegatedEndpointMember reports the first caller-delegated account a
// shared endpoint (connector tools or bundle members) names.
func callerDelegatedEndpointMember(store AccountStore, names []string) (string, bool) {
	for _, name := range names {
		if account, found := store.Account(name); found && accountDeliveredOnlyByExactGrant(account) {
			return name, true
		}
	}
	return "", false
}

// refuseCallerDelegatedConnectorPolicy is the console gate for a connector
// create or update: an approval list on a caller-delegated account is 400
// approval_not_supported_for_delegated, and listing one at all is 400
// because such an account is delivered only by an exact grant.
func (c *ConsoleAPI) refuseCallerDelegatedConnectorPolicy(w http.ResponseWriter, r *http.Request, tools, approval map[string][]string) bool {
	if _, found := callerDelegatedApprovalTarget(c.store, approval); found {
		writeApprovalNotSupportedForDelegated(w, r)
		return true
	}
	if name, found := callerDelegatedEndpointMember(c.store, accountNamesInToolMap(tools)); found {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%s: %q", ErrCallerDelegatedAccountExposure.Error(), name)})
		return true
	}
	return false
}

// callerDelegatedApprovalRefusal is the tool error for a call that some older
// policy would park for approval on a caller-delegated account.
const callerDelegatedApprovalRefusal = "this connection acts for the person who started the job and cannot wait for an approval; the call was not sent upstream"
