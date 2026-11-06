package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// "Accounts your agents use": the console side of member credentials. A
// member sees each account in member-credential mode that one of their own
// MCP clients may use, or that they manage, and connects or disconnects their
// own credential for it. Nobody reads or changes another member's credential.

type memberCredentialDTO struct {
	Account     string     `json:"account"`
	DisplayName string     `json:"displayName"`
	AuthMode    string     `json:"authMode"`
	Connected   bool       `json:"connected"`
	UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
}

// memberAccounts lists the member-credential accounts actor's agents can use.
func (c *ConsoleAPI) memberAccounts(ctx context.Context, actor PlatformActor) ([]Account, error) {
	if strings.TrimSpace(actor.UserID) == "" {
		return nil, nil
	}
	var accounts []Account
	for _, a := range c.store.Accounts() {
		if a.MemberCredentials && !a.IsPersonal() {
			accounts = append(accounts, a)
		}
	}
	if len(accounts) == 0 {
		return nil, nil
	}
	available := map[string]bool{}
	if clients, ok := c.store.(MCPClientStore); ok {
		active, err := clients.ActiveMCPClients(ctx)
		if err != nil {
			return nil, err
		}
		for _, client := range active {
			if client.Subject == actor.UserID && client.Kind != MCPClientKindWorkload {
				for _, account := range accounts {
					if mcpClientDeliversAccount(client, account) {
						available[account.Name] = true
					}
				}
			}
		}
	}
	namespaces := newNamespaceCache()
	c.loadOwnershipNamespaces(ctx, namespaces, accounts)
	out := accounts[:0]
	for _, a := range accounts {
		if available[a.Name] || canManageAccountPreloaded(actor, a, namespaces.byID) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (c *ConsoleAPI) memberCredentialDTO(ctx context.Context, store MemberCredentialStore, a Account, subject string) memberCredentialDTO {
	dto := memberCredentialDTO{Account: a.Name, DisplayName: a.Label, AuthMode: a.AuthMode}
	if dto.DisplayName == "" {
		dto.DisplayName = a.Name
	}
	if stored, found, err := store.MemberCredential(ctx, a.Name, subject); err == nil && found && stored.IncarnationID == a.IncarnationID {
		dto.Connected = true
		dto.UpdatedAt = &stored.UpdatedAt
	}
	return dto
}

// memberAccount resolves {id} to one account actor's agents can use, with
// the store that holds actor's credential for it.
func (c *ConsoleAPI) memberAccount(w http.ResponseWriter, r *http.Request) (Account, PlatformActor, MemberCredentialStore, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return Account{}, PlatformActor{}, nil, false
	}
	store, ok := c.store.(MemberCredentialStore)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "member credentials are not supported by this store"})
		return Account{}, PlatformActor{}, nil, false
	}
	accounts, err := c.memberAccounts(r.Context(), actor)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not load connections"})
		return Account{}, PlatformActor{}, nil, false
	}
	for _, a := range accounts {
		if a.Name == r.PathValue("id") {
			return a, actor, store, true
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
	return Account{}, PlatformActor{}, nil, false
}

func (c *ConsoleAPI) handleMemberCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	store, ok := c.store.(MemberCredentialStore)
	if !ok {
		writeJSON(w, http.StatusOK, []memberCredentialDTO{})
		return
	}
	accounts, err := c.memberAccounts(r.Context(), actor)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not load connections"})
		return
	}
	out := make([]memberCredentialDTO, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, c.memberCredentialDTO(r.Context(), store, a, actor.UserID))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleMemberCredential disconnects actor's own credential.
func (c *ConsoleAPI) handleMemberCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a, actor, store, ok := c.memberAccount(w, r)
	if !ok {
		return
	}
	if err := store.DeleteMemberCredential(r.Context(), a.Name, actor.UserID); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not disconnect your account"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ConsoleAPI) handleMemberCredentialConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a, actor, _, ok := c.memberAccount(w, r)
	if !ok {
		return
	}
	if a.AuthMode == "token" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this connection uses access tokens; add your own token instead"})
		return
	}
	authURL, err := c.conn.StartMemberConnect(r.Context(), a, actor.UserID, c.selfURL+"/api/oauth/callback")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"authorizeUrl": authURL})
}

func (c *ConsoleAPI) handleMemberCredentialToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a, actor, store, ok := c.memberAccount(w, r)
	if !ok {
		return
	}
	if a.AuthMode != "token" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this connection uses OAuth; connect your account instead"})
		return
	}
	var req struct{ Token string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	err := c.gw.PutMemberCredentialLocked(r.Context(), MemberCredential{
		Account: a.Name, IncarnationID: a.IncarnationID, Subject: actor.UserID,
		BearerToken: strings.TrimSpace(req.Token),
	})
	if errors.Is(err, ErrAccountIncarnation) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; refresh and try again"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not save your token"})
		return
	}
	writeJSON(w, http.StatusOK, c.memberCredentialDTO(r.Context(), store, a, actor.UserID))
}
