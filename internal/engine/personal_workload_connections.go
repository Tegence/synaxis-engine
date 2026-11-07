package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Platform has already verified that the human owns this workload. Engine only
// accepts that assertion from its service principal, and independently checks
// every source's opaque owner. A folder is a snapshot, never a future grant.
func (c *ConsoleAPI) handlePersonalWorkloadConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	store, actor, ok := c.grantActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "service" || actor.UserID != platformServiceActorID {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	clients, ok := c.mcpClientStore()
	if !ok {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	client, found := clients.MCPClient(r.Context(), r.PathValue("id"))
	if !found || client.Status != MCPClientStatusActive || mcpClientKind(client) != MCPClientKindWorkload {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var in struct {
		ScopeRevision int64     `json:"scopeRevision"`
		OwnerSubject  string    `json:"ownerSubject"`
		ConnectionIDs []string  `json:"connectionIds"`
		NamespaceIDs  []string  `json:"namespaceIds"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || !validActorIdentifier(in.OwnerSubject) || in.OwnerSubject == "" || in.ScopeRevision < 1 || len(in.ConnectionIDs) > 64 || len(in.NamespaceIDs) > 32 || (!in.ExpiresAt.IsZero() && !in.ExpiresAt.After(time.Now())) {
		writeConnectionGrantError(w, ErrConnectionGrantInvalid)
		return
	}
	allowed, err := store.SubjectAllowed(r.Context(), in.OwnerSubject)
	if err != nil || !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	allowed, err = store.SubjectAllowed(r.Context(), client.Subject)
	if err != nil || !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	nsStore, ok := c.connectionNamespaceStore()
	if !ok {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	for _, id := range in.NamespaceIDs {
		ns, found := nsStore.ConnectionNamespace(r.Context(), id)
		if !found || ns.OwnerSubject != in.OwnerSubject {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	selected := slices.Clone(in.ConnectionIDs)
	for _, a := range c.store.Accounts() {
		if slices.Contains(in.NamespaceIDs, a.ConnectionNamespaceID) {
			selected = append(selected, a.Name)
		}
	}
	slices.Sort(selected)
	selected = slices.Compact(selected)
	wanted := map[string]ConnectionGrant{}
	sources := map[string]Account{}
	for _, id := range selected {
		a, found := c.store.Account(id)
		if !found || !a.IsPersonal() || a.OwnerSubject != in.OwnerSubject || a.MemberCredentials {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if c.gw == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		c.gw.mu.Lock()
		tools := []string{}
		for _, t := range c.gw.cached[a.Name] {
			if t.accountIncarnationID == a.IncarnationID && t.accountRevision == a.Revision {
				tools = append(tools, t.sourceName)
			}
		}
		c.gw.mu.Unlock()
		if len(tools) == 0 {
			writeConnectionGrantError(w, ErrConnectionGrantInvalid)
			return
		}
		slices.Sort(tools)
		fingerprint, _ := json.Marshal([]any{client.ID, in.ScopeRevision, a.Name, a.IncarnationID, a.Revision, tools, in.ExpiresAt.UTC()})
		hash := sha256.Sum256(fingerprint)
		id := "cgr_self_" + hex.EncodeToString(hash[:16])
		sources[id] = a
		wanted[id] = ConnectionGrant{ID: id, Name: "Personal agent tools", ConnectionID: a.Name, IncarnationID: a.IncarnationID, SourceRevision: a.Revision, OwnerSubject: a.OwnerSubject, CreatedBy: in.OwnerSubject, RecipientKind: "subject", RecipientRef: client.Subject, RecipientSubjects: []string{client.Subject}, Tools: tools, ExpiresAt: in.ExpiresAt, PersonalWorkload: true}
	}
	grants, err := store.ConnectionGrants(r.Context())
	if err != nil {
		writeConnectionGrantError(w, err)
		return
	}
	existing := map[string]bool{}
	for _, g := range grants {
		if !strings.HasPrefix(g.ID, "cgr_self_") || g.RecipientRef != client.Subject || g.OwnerSubject != in.OwnerSubject {
			continue
		}
		if _, keep := wanted[g.ID]; keep {
			if g.RevokedAt != nil {
				writeConnectionGrantError(w, ErrConnectionGrantRevision)
				return
			}
			existing[g.ID] = true
			continue
		}
		if g.RevokedAt == nil {
			if _, err := store.RevokeConnectionGrant(r.Context(), g.ID, g.Revision); err != nil {
				writeConnectionGrantError(w, err)
				return
			}
		}
	}
	for id, g := range wanted {
		if existing[id] {
			continue
		}
		a := sources[id]
		if _, err := store.CreateConnectionGrant(r.Context(), g, accountPolicyPrecondition(a)); err != nil {
			writeConnectionGrantError(w, err)
			return
		}
	}
	if c.gw != nil {
		c.gw.RefreshMCPClients(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// The service's workload-only collection is deliberately separate from the
// human MCP registry. It cannot register, inspect or revoke interactive apps.
func (c *ConsoleAPI) handleServiceWorkloadClients(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || actor.Role != "service" || actor.UserID != platformServiceActorID {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if id := r.PathValue("id"); id != "" {
		store, ok := c.mcpClientStore()
		if !ok {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		client, found := store.MCPClient(r.Context(), id)
		if !found || mcpClientKind(client) != MCPClientKindWorkload {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/revoke") {
			c.handleControlMCPClientRevoke(w, r)
		} else {
			c.handleControlMCPClientByID(w, r)
		}
		return
	}
	c.handleControlMCPClients(w, r)
}
