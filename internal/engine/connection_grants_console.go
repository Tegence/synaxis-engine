package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
)

func (c *ConsoleAPI) grantActor(w http.ResponseWriter, r *http.Request) (ConnectionGrantStore, PlatformActor, bool) {
	store, ok := c.store.(ConnectionGrantStore)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connection grants are unavailable"})
		return nil, PlatformActor{}, false
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return nil, actor, false
	}
	if actor.Role != "operator" && !connectionNamespaceAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection grant access is not permitted"})
		return nil, actor, false
	}
	return store, actor, true
}
func canIssueConnectionGrant(actor PlatformActor, a Account) bool {
	// Even an administrator must not silently delegate a member's private token.
	return !a.IsPersonal() || actor.UserID == a.OwnerSubject
}
func (c *ConsoleAPI) handleConnectionGrants(w http.ResponseWriter, r *http.Request) {
	store, actor, ok := c.grantActor(w, r)
	if !ok {
		return
	}
	grants, err := store.ConnectionGrants(r.Context())
	if err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := []ConnectionGrant{}
		for _, g := range grants {
			if connectionNamespaceAdministrator(actor) || g.CreatedBy == actor.UserID || g.OwnerSubject == actor.UserID || slices.Contains(g.RecipientSubjects, actor.UserID) {
				// A recipient learns their own grant, not the other recipients' identities.
				if !connectionNamespaceAdministrator(actor) && g.CreatedBy != actor.UserID && g.OwnerSubject != actor.UserID {
					g.RecipientSubjects = []string{actor.UserID}
					g.CreatedBy = ""
					g.OwnerSubject = ""
				}
				out = append(out, g)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var request struct {
			ID                string    `json:"id"`
			Name              string    `json:"name"`
			ConnectionID      string    `json:"connectionId"`
			RecipientKind     string    `json:"recipientKind"`
			RecipientRef      string    `json:"recipientRef"`
			RecipientSubjects []string  `json:"recipientSubjects"`
			Tools             []string  `json:"tools"`
			ExpiresAt         time.Time `json:"expiresAt"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeConnectionGrantError(w, ErrConnectionGrantInvalid)
			return
		}
		if request.ID != "" && (!strings.HasPrefix(request.ID, "cgr_") || strings.HasPrefix(request.ID, "cgr_self_") || !validActorIdentifier(request.ID)) {
			writeConnectionGrantError(w, ErrConnectionGrantInvalid)
			return
		}
		a, found := c.store.Account(request.ConnectionID)
		if !found || !c.canManageAccount(r.Context(), actor, a) || !canIssueConnectionGrant(actor, a) {
			writeConnectionGrantError(w, ErrConnectionGrantNotFound)
			return
		}
		if a.MemberCredentials {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "member credentials cannot be shared"})
			return
		}
		if accountDeliveredOnlyByExactGrant(a) {
			// A shared tool grant parks every write for approval and delivers
			// outside the exact client grant; neither applies to this account.
			writeApprovalNotSupportedForDelegated(w, r)
			return
		}
		// The catalog is the exact current account projection; no wildcard or
		// future tool automatically joins a grant.
		if c.gw == nil {
			writeConnectionGrantError(w, errors.New("gateway unavailable"))
			return
		}
		c.gw.mu.Lock()
		known := map[string]bool{}
		for _, t := range c.gw.cached[a.Name] {
			if t.accountIncarnationID == a.IncarnationID && t.accountRevision == a.Revision {
				known[t.sourceName] = true
			}
		}
		c.gw.mu.Unlock()
		for _, tool := range request.Tools {
			if !known[tool] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "select currently enabled tools from this connection"})
				return
			}
		}
		candidate := ConnectionGrant{ID: request.ID, Name: request.Name, ConnectionID: a.Name, IncarnationID: a.IncarnationID, OwnerSubject: a.OwnerSubject, SourceRevision: a.Revision, CreatedBy: actor.UserID, RecipientKind: request.RecipientKind, RecipientRef: request.RecipientRef, RecipientSubjects: request.RecipientSubjects, Tools: request.Tools, ExpiresAt: request.ExpiresAt}
		normalized, err := normalizeConnectionGrant(candidate)
		if err != nil {
			writeConnectionGrantError(w, err)
			return
		}
		if request.ID != "" {
			for _, old := range grants {
				if old.ID == request.ID {
					compare := normalized
					compare.CreatedAt = old.CreatedAt
					compare.Revision = old.Revision
					if old.RevokedAt == nil && reflect.DeepEqual(compare, old) {
						writeJSON(w, http.StatusOK, old)
						return
					}
					writeConnectionGrantError(w, ErrConnectionGrantRevision)
					return
				}
			}
		}
		created, err := store.CreateConnectionGrant(r.Context(), normalized, accountPolicyPrecondition(a))
		if err != nil {
			writeConnectionGrantError(w, err)
			return
		}
		c.refreshMCPClientProjection(r.Context())
		writeJSON(w, http.StatusCreated, created)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func (c *ConsoleAPI) handleConnectionGrantRevoke(w http.ResponseWriter, r *http.Request) {
	store, actor, ok := c.grantActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	grants, err := store.ConnectionGrants(r.Context())
	if err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	var found *ConnectionGrant
	for _, g := range grants {
		if g.ID == r.PathValue("id") && (connectionNamespaceAdministrator(actor) || g.CreatedBy == actor.UserID || g.OwnerSubject == actor.UserID) {
			copy := g
			found = &copy
			break
		}
	}
	if found == nil {
		writeConnectionGrantError(w, ErrConnectionGrantNotFound)
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeConnectionGrantError(w, ErrConnectionGrantInvalid)
		return
	}
	if found.RevokedAt != nil {
		writeJSON(w, http.StatusOK, found)
		return
	}
	updated, err := store.RevokeConnectionGrant(r.Context(), found.ID, request.Revision)
	if err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, updated)
}
func (c *ConsoleAPI) handleConnectionGrantRecipients(w http.ResponseWriter, r *http.Request) {
	store, actor, ok := c.grantActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "service" || actor.UserID != platformServiceActorID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "recipient reconciliation requires Platform"})
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Revision          int64    `json:"revision"`
		RecipientSubjects []string `json:"recipientSubjects"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeConnectionGrantError(w, ErrConnectionGrantInvalid)
		return
	}
	updated, err := store.SetConnectionGrantRecipients(r.Context(), r.PathValue("id"), request.Revision, request.RecipientSubjects)
	if err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, updated)
}
func (c *ConsoleAPI) handleSubjectAccess(w http.ResponseWriter, r *http.Request) {
	store, actor, ok := c.grantActor(w, r)
	if !ok {
		return
	}
	if !connectionNamespaceAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required"})
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Allowed *bool `json:"allowed"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil || request.Allowed == nil {
		writeConnectionGrantError(w, ErrConnectionGrantInvalid)
		return
	}
	if err := store.SetSubjectAllowed(r.Context(), r.PathValue("subject"), *request.Allowed); err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"subject": r.PathValue("subject"), "allowed": *request.Allowed})
}
func writeConnectionGrantError(w http.ResponseWriter, err error) {
	status, message := http.StatusBadGateway, "connection grant operation unavailable"
	switch {
	case errors.Is(err, ErrConnectionGrantInvalid):
		status, message = http.StatusBadRequest, "select named recipients, explicit tools and a future expiry within one year"
	case errors.Is(err, ErrConnectionGrantNotFound):
		status, message = http.StatusNotFound, "connection grant not found"
	case errors.Is(err, ErrConnectionGrantRevision), errors.Is(err, ErrAccountPolicyPrecondition):
		status, message = http.StatusConflict, "connection or grant changed; refresh and try again"
	}
	writeJSON(w, status, map[string]string{"error": message})
}
