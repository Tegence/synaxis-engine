package engine

import (
	"context"
	"errors"
	"net/http"
	"sort"
)

var errConnectionModelUnavailable = errors.New("connection model unavailable")

func (c *ConsoleAPI) handleConnectionModel(w http.ResponseWriter, r *http.Request) {
	c.serveConnectionModel(w, r, apiWire)
}

func (c *ConsoleAPI) handleControlConnectionModel(w http.ResponseWriter, r *http.Request) {
	c.serveConnectionModel(w, r, controlWire)
}

func (c *ConsoleAPI) serveConnectionModel(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		wire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || (actor.Role != "owner" && actor.Role != "admin" && actor.Role != "operator") {
		wire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connection access is not permitted"))
		return
	}
	model, err := c.connectionModel(r.Context(), actor)
	if err != nil {
		// Neither storage errors nor partially built credential metadata leave
		// the Engine. In particular, a failed member read cannot fall back to
		// the connection's discovery credential.
		wire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "could not load connection model"))
		return
	}
	writeJSON(w, http.StatusOK, model)
}

func (c *ConsoleAPI) connectionModel(ctx context.Context, actor PlatformActor) (ConnectionModel, error) {
	model := newConnectionModel()
	var accounts []Account
	if lister, ok := c.store.(accountLister); ok {
		var err error
		accounts, err = lister.ListAccounts(ctx)
		if err != nil {
			return ConnectionModel{}, errConnectionModelUnavailable
		}
	} else {
		accounts = c.store.Accounts()
	}
	// This is the same management visibility as /api/servers. It does not
	// enumerate connections merely because the actor can use shared tools.
	accounts = c.readableAccounts(ctx, actor, accounts)
	linkedStore, linkingSupported := c.store.(LinkedAccountStore)
	if linkingSupported {
		model.Capabilities = append(model.Capabilities, controlCapabilityAccountLinking)
		if c.browserSignIn != nil {
			model.Capabilities = append(model.Capabilities, controlCapabilityAccountBrowser, controlCapabilityAccountWebsite)
			model.BrowserSignIn = c.browserSignIn.availability()
		}
	}
	if _, ok := c.store.(LinkedOAuthFlowStore); ok && linkingSupported && c.accountOAuth != nil {
		model.Capabilities = append(model.Capabilities, controlCapabilityAccountOAuth)
		model.OAuthProviders = c.accountOAuth.metadata()
	}
	visible := make(map[string]Account, len(accounts))
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	for _, a := range accounts {
		if a.Name == "" || a.IncarnationID == "" || (a.CallerDelegated && a.MemberCredentials) {
			return ConnectionModel{}, errConnectionModelUnavailable
		}
		if _, err := normalizedConnectionScope(a.ConnectionScope); err != nil {
			return ConnectionModel{}, errConnectionModelUnavailable
		}
		connection := projectConnection(a)
		connection.AccountLinking = linkingSupported && !a.CallerDelegated && (!a.IsPersonal() || a.OwnerSubject == actor.UserID)
		visible[a.Name] = a
		present := false
		subject := ""
		switch connection.AccountBinding.Mode {
		case AccountBindingCallerDelegated:
			// Tool-listing service credentials are not an execution account.
		case AccountBindingMember:
			subject = actor.UserID
			if memberStore, ok := c.store.(MemberCredentialStore); ok && subject != "" {
				credential, found, err := memberStore.MemberCredential(ctx, a.Name, subject)
				if err != nil {
					return ConnectionModel{}, errConnectionModelUnavailable
				}
				present = found && credential.Account == a.Name && credential.Subject == subject &&
					credential.IncarnationID == a.IncarnationID &&
					connectionCredentialPresent(a.AuthMode, credential.AccessToken, credential.RefreshToken, credential.BearerToken)
			} else {
				connection.AccountBinding.CredentialState = "unavailable"
			}
		case AccountBindingConnection:
			present = connectionCredentialPresent(a.AuthMode, a.AccessToken, a.RefreshToken, a.BearerToken)
		}
		if present {
			account := projectConnectedAccount(a, connection.AccountBinding.Mode, subject)
			connection.AccountBinding.CredentialState = "present"
			connection.AccountBinding.AccountIDs = append(connection.AccountBinding.AccountIDs, account.ID)
			model.ConnectedAccounts = append(model.ConnectedAccounts, account)
		}
		model.Connections = append(model.Connections, connection)
	}
	if linkingSupported && actor.UserID != "" {
		records, err := linkedStore.LinkedAccounts(ctx, actor.UserID)
		if err != nil {
			return ConnectionModel{}, errConnectionModelUnavailable
		}
		for _, record := range records {
			if record.isWebsiteAccount() && record.OwnerSubject == actor.UserID {
				model.ConnectedAccounts = append(model.ConnectedAccounts, linkedAccountDTO(record, Account{}))
				continue
			}
			parent, found := visible[record.ConnectionID]
			if found && record.OwnerSubject == actor.UserID && record.Boundary.IncarnationID == parent.IncarnationID {
				model.ConnectedAccounts = append(model.ConnectedAccounts, linkedAccountDTO(record, parent))
			}
		}
	}
	return model, nil
}
