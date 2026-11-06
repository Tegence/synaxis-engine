package engine

import "net/http"

// The console's /api/servers routes reach the same accounts as the control v1
// connections group (control_v1_connections.go). These two checks keep a
// caller-delegated account under that group's rules when it is written
// through the console.

// refuseCallerDelegatedConsoleWrite answers 403 and reports true when a
// console write (PATCH, DELETE, token) targets a caller-delegated account
// that actor may not write. On a hosted Engine only the hosting control
// plane's service actor writes one, through /control/v1/connections; owners
// and admins still read it in the console.
func (c *ConsoleAPI) refuseCallerDelegatedConsoleWrite(w http.ResponseWriter, a Account, actor PlatformActor) bool {
	if !a.CallerDelegated || c.callerDelegatedWriter(actor) {
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "caller-delegated connections are written only by the Platform service"})
	return true
}

// callerDelegatedConsoleEditProblem is the reason a console edit may not be
// applied to a caller-delegated account, or "" when it may: such an account
// never becomes personal and never uses member credentials
// (validateCallerDelegatedAccount).
func callerDelegatedConsoleEditProblem(a Account, scope *ConnectionScope, memberCredentials *bool) string {
	if !a.CallerDelegated {
		return ""
	}
	if memberCredentials != nil && *memberCredentials {
		return "a caller-delegated connection cannot use member credentials"
	}
	if scope != nil {
		if normalized, err := normalizedConnectionScope(*scope); err == nil && normalized == ConnectionScopePersonal {
			return "a caller-delegated connection cannot be personal"
		}
	}
	return ""
}
