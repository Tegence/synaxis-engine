package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (c *ConsoleAPI) browserRuntimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int, code, detail string) {
		controlWire.writeFailure(w, newConsoleFailure(status, code, detail))
	}
	actor, ok := PlatformActorFromContext(r.Context())
	if !ok || actor.UserID != platformServiceActorID || actor.Role != "service" {
		fail(403, controlCodeForbidden, "browser runtime requires Platform authority")
		return
	}
	if r.Method != "POST" {
		controlWire.writeMethodNotAllowed(w, "POST")
		return
	}
	if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
		fail(400, controlCodeValidationFailed, "browser actions use their own dispatch receipts")
		return
	}
	var in BrowserControlRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF || !validActorIdentifier(in.Owner) || !validActorIdentifier(in.Subject) {
		fail(400, controlCodeValidationFailed, "invalid browser request")
		return
	}
	service := c.browserSignIn
	if service == nil || (service.provider == nil && service.managedProvider == nil) {
		fail(501, controlCodeCapabilityUnavailable, "browser runtime is not configured")
		return
	}
	_, primaryRuntime := service.provider.(browserRuntimeProvider)
	_, managedRuntime := service.managedProvider.(browserRuntimeProvider)
	if !primaryRuntime && !managedRuntime {
		fail(501, controlCodeCapabilityUnavailable, "browser provider does not support agent sessions")
		return
	}
	if _, ok := c.store.(BrowserRunStore); !ok {
		fail(501, controlCodeCapabilityUnavailable, "browser session storage unavailable")
		return
	}
	clients, ok := c.store.(MCPClientStore)
	if !ok {
		fail(501, controlCodeCapabilityUnavailable, "workload clients unavailable")
		return
	}
	client, found := clients.MCPClient(r.Context(), in.ClientID)
	if !found || client.Kind != MCPClientKindWorkload || client.Subject != in.Subject {
		fail(404, controlCodeNotFound, "workload client not found")
		return
	}
	live := client.Status == MCPClientStatusActive && linkedMCPClientSourceActive(r.Context(), clients, client)
	records, err := service.accounts.LinkedAccounts(r.Context(), in.Owner)
	if err != nil {
		fail(502, controlCodeEngineUnavailable, "could not load browser accounts")
		return
	}
	owner := PlatformActor{UserID: in.Owner, Role: in.OwnerRole}
	choices := []BrowserAccountChoice{}
	var selected LinkedAccountRecord
	var parent Account
	var grant BrowserAccountGrant
	for _, a := range records {
		p, exists := c.store.Account(a.ConnectionID)
		if a.Browser == nil || !exists || !c.canManageAccount(r.Context(), owner, p) {
			continue
		}
		available := live && validBrowserProfile(*a.Browser) && linkedAccountBoundaryMatches(a, p) && service.runtimeProvider(*a.Browser) != nil
		var g BrowserAccountGrant
		for _, v := range a.BrowserGrants {
			if v.ClientID == client.ID || v.Subject == client.Subject {
				g = v
				break
			}
		}
		mode := ""
		if g.ID != "" {
			mode = g.Mode
		}
		if g.ID != "" && (g.ClientID != client.ID || g.ClientEpoch != client.Epoch || g.CredentialRevision != a.CredentialRevision) {
			mode = "stale"
		}
		if in.Operation == "list" || mode != "" && mode != "stale" && available {
			choices = append(choices, BrowserAccountChoice{ID: a.ID, Name: a.DisplayName, WebsiteURL: a.Browser.WebsiteURL, Revision: a.Revision, Mode: mode, Available: available})
		}
		if a.ID == in.AccountID {
			selected = a
			parent = p
			grant = g
		}
	}
	if in.Operation == "list" || in.Operation == "available" {
		writeJSON(w, 200, BrowserControlResult{Status: "ok", Accounts: choices})
		return
	}
	if in.Operation == "touch-execution" {
		if !validActorIdentifier(in.ExecutionID) || !in.AuthorizedUntil.After(time.Now()) || in.AuthorizedUntil.After(time.Now().Add(2*time.Minute)) || !live {
			fail(403, controlCodeForbidden, "browser execution expired")
			return
		}
		service.touchBrowserExecution(r.Context(), in, choices)
		writeJSON(w, 200, BrowserControlResult{Status: "ok"})
		return
	}
	if in.Operation == "close-execution" {
		if !validActorIdentifier(in.ExecutionID) {
			fail(400, controlCodeValidationFailed, "invalid execution")
			return
		}
		service.closeBrowserExecution(r.Context(), in.Owner, in.ClientID, in.ExecutionID)
		writeJSON(w, 200, BrowserControlResult{Status: "closed"})
		return
	}
	if selected.ID == "" {
		fail(404, controlCodeNotFound, "browser account not found")
		return
	}
	if in.Operation == "grant" || in.Operation == "revoke" {
		mutation := LinkedAccountMutation{RevokeBrowserClient: client.ID, RevokeBrowserSubject: client.Subject}
		if in.Operation == "grant" {
			g := BrowserAccountGrant{ID: "bgrant_" + newEpoch(), ClientID: client.ID, Subject: client.Subject, ClientEpoch: client.Epoch, CredentialRevision: selected.CredentialRevision, Mode: in.Mode, CreatedAt: time.Now().UTC()}
			if service.runtimeProvider(*selected.Browser) == nil || !live || !validBrowserGrant(g) || !validBrowserProfile(*selected.Browser) || !linkedAccountBoundaryMatches(selected, parent) {
				fail(409, controlCodeRevisionMismatch, "browser account or agent changed")
				return
			}
			mutation.BrowserGrant = &g
		}
		if _, err = service.accounts.MutateLinkedAccount(r.Context(), selected.ConnectionID, selected.ID, in.Owner, in.Revision, accountPolicyPrecondition(parent), mutation); err != nil {
			fail(409, controlCodeRevisionMismatch, "browser account changed; refresh before retrying")
			return
		}
		writeJSON(w, 200, BrowserControlResult{Status: "ok"})
		return
	}
	if in.Operation != "execute" || !live || !browserGrantLive(selected, grant, client) || !linkedAccountBoundaryMatches(selected, parent) || !validActorIdentifier(in.ExecutionID) || !browserResourceID(in.CallID) || !in.AuthorizedUntil.After(time.Now()) || in.AuthorizedUntil.After(time.Now().Add(2*time.Minute)) || !browserActionValid(in.Action, selected.Browser.WebsiteURL) {
		fail(403, controlCodeForbidden, "browser action is not authorized")
		return
	}
	out, err := c.executeBrowser(r.Context(), in, selected, parent, grant)
	if err != nil {
		fail(409, "browser_action_unavailable", "browser action unavailable or outcome unknown; inspect the page before another action")
		return
	}
	writeJSON(w, 200, out)
}

func browserGrantLive(a LinkedAccountRecord, g BrowserAccountGrant, client MCPClient) bool {
	return a.Browser != nil && validBrowserProfile(*a.Browser) && validBrowserGrant(g) && g.ClientID == client.ID && g.Subject == client.Subject && g.ClientEpoch == client.Epoch && g.CredentialRevision == a.CredentialRevision
}

func (s *BrowserSignInService) browserRunAuthorized(ctx context.Context, run BrowserRun) bool {
	if s.runtimeProvider(run.Profile) == nil {
		return false
	}
	clients, ok := s.store.(MCPClientStore)
	if !ok {
		return false
	}
	client, ok := clients.MCPClient(ctx, run.ClientID)
	if !ok || client.Status != MCPClientStatusActive || !linkedMCPClientSourceActive(ctx, clients, client) {
		return false
	}
	records, err := s.accounts.LinkedAccounts(ctx, run.Owner)
	if err != nil {
		return false
	}
	for _, a := range records {
		if a.ID == run.AccountID && a.Browser != nil && a.Browser.ProfileID == run.Profile.ProfileID {
			p, found := s.store.Account(a.ConnectionID)
			if !found || !linkedAccountBoundaryMatches(a, p) {
				return false
			}
			for _, g := range a.BrowserGrants {
				if g.ID == run.GrantID {
					return browserGrantLive(a, g, client)
				}
			}
		}
	}
	return false
}
