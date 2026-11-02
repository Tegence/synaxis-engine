package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// OAuth endpoints never use the generic replay cache: authorization URLs,
// state and browser proofs are ephemeral credentials, and completion must
// recheck current management access even after a prior success.
func (c *ConsoleAPI) linkedOAuthHandler(wire consoleWire, complete bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int, code, detail string) {
			if wire.control {
				wire.writeFailure(w, newConsoleFailure(status, code, detail))
			} else {
				writeJSON(w, status, map[string]string{"error": detail, "code": code})
			}
		}
		if r.Method != http.MethodPost {
			wire.writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		actor, ok := c.connectionNamespaceActor(r)
		if !ok || actor.UserID == "" || (actor.Role != "owner" && actor.Role != "admin" && actor.Role != "operator") {
			fail(403, controlCodeForbidden, "account sign-in is not permitted")
			return
		}
		flows, supported := c.store.(LinkedOAuthFlowStore)
		accounts, linksSupported := c.store.(LinkedAccountStore)
		if !supported || !linksSupported || c.accountOAuth == nil {
			fail(501, controlCodeCapabilityUnavailable, "OAuth account linking requires an Engine update")
			return
		}
		provider := r.PathValue("provider")
		app, configured := c.accountOAuth.apps[provider]
		adapter, known := c.accountOAuth.providers[provider]
		if !known || !configured {
			fail(409, controlCodeCapabilityUnavailable, "this provider needs application setup")
			return
		}
		if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
			fail(400, controlCodeValidationFailed, "sign-in does not support replay keys")
			return
		}
		var body struct {
			ConnectionID            string `json:"connectionId"`
			ConnectionIncarnationID string `json:"connectionIncarnationId"`
			ConnectionRevision      int64  `json:"connectionRevision"`
			DisplayName             string `json:"displayName"`
			AccountID               string `json:"accountId"`
			Revision                int64  `json:"revision"`
			State                   string `json:"state"`
			BrowserProof            string `json:"browserProof"`
			Code                    string `json:"code"`
			Denied                  bool   `json:"denied"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			fail(400, controlCodeValidationFailed, "invalid sign-in request")
			return
		}
		if !complete {
			if body.State != "" || body.Code != "" || body.BrowserProof != "" || body.Denied {
				fail(400, controlCodeValidationFailed, "invalid sign-in request")
				return
			}
			parent, found := c.store.Account(body.ConnectionID)
			if !found || !c.canManageAccount(r.Context(), actor, parent) {
				fail(404, controlCodeNotFound, "connection not found")
				return
			}
			if parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != actor.UserID) {
				fail(403, controlCodeForbidden, "connection does not support account linking")
				return
			}
			if body.ConnectionIncarnationID != parent.IncarnationID || body.ConnectionRevision != parent.Revision {
				fail(409, controlCodeRevisionMismatch, "connection changed; refresh before signing in")
				return
			}
			label, err := normalizeLinkedAccountName(body.DisplayName)
			if err != nil {
				fail(400, controlCodeValidationFailed, "an account label is required")
				return
			}
			if body.AccountID != "" {
				records, err := accounts.LinkedAccounts(r.Context(), actor.UserID)
				if err != nil {
					fail(502, controlCodeEngineUnavailable, "could not check account")
					return
				}
				found := false
				for _, record := range records {
					if record.ID == body.AccountID && record.ConnectionID == parent.Name && record.Boundary.IncarnationID == parent.IncarnationID && record.OAuth != nil && record.OAuth.Provider == provider && record.Revision == body.Revision {
						found = true
					}
				}
				if !found {
					fail(409, controlCodeRevisionMismatch, "account changed; refresh before signing in")
					return
				}
			} else if body.Revision != 0 {
				fail(400, controlCodeValidationFailed, "invalid sign-in request")
				return
			}
			state, proof := newEpoch()+newEpoch(), newEpoch()+newEpoch()
			flow := LinkedOAuthFlow{StateHash: oauthLinkHash(state), ProofHash: oauthLinkHash(proof), Subject: actor.UserID, ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), Provider: provider, AppFingerprint: c.accountOAuth.fingerprint(provider), DisplayName: label, AccountID: body.AccountID, AccountRevision: body.Revision, ExpiresAt: time.Now().UTC().Add(linkedOAuthLifetime)}
			if err := flows.PutLinkedOAuthFlow(r.Context(), flow); err != nil {
				if errors.Is(err, ErrLinkedAccountLimit) {
					fail(429, controlCodeCapacityLimited, "too many sign-in attempts; wait ten minutes and try again")
				} else {
					fail(502, controlCodeEngineUnavailable, "could not start sign-in")
				}
				return
			}
			writeJSON(w, 200, map[string]string{"authorizationUrl": c.accountOAuth.authorizationURL(provider, state), "state": state, "browserProof": proof, "redirectUri": c.accountOAuth.redirectURI(provider)})
			return
		}
		if body.State == "" || len(body.State) > 256 || body.BrowserProof == "" || len(body.BrowserProof) > 256 || len(body.Code) > 8192 || (body.Code == "" && !body.Denied) || (body.Denied && body.Code != "") || body.ConnectionID != "" || body.DisplayName != "" || body.AccountID != "" || body.ConnectionIncarnationID != "" || body.ConnectionRevision != 0 || body.Revision != 0 {
			fail(400, controlCodeValidationFailed, "invalid sign-in result")
			return
		}
		flow, err := flows.ConsumeLinkedOAuthFlow(r.Context(), oauthLinkHash(body.State), actor.UserID, provider, body.BrowserProof)
		if err != nil {
			fail(409, controlCodeRevisionMismatch, "sign-in expired or already used; start again")
			return
		}
		if body.Denied {
			writeJSON(w, 200, map[string]string{"status": "cancelled"})
			return
		}
		parent, found := c.store.Account(flow.ConnectionID)
		if !found || !c.canManageAccount(r.Context(), actor, parent) {
			fail(404, controlCodeNotFound, "connection not found")
			return
		}
		if !flow.Parent.matches(parent) || flow.AppFingerprint != c.accountOAuth.fingerprint(provider) {
			fail(409, controlCodeRevisionMismatch, "connection or application changed; start sign-in again")
			return
		}
		credential, err := adapter.exchange(r.Context(), c.accountOAuth, app, body.Code, c.accountOAuth.redirectURI(provider))
		if err != nil {
			fail(502, controlCodeEngineUnavailable, "provider sign-in failed; start again")
			return
		}
		// Re-check current access after the network exchange. Store CAS below also
		// fences parent movement and account disconnect/rotation during consent.
		current, found := c.store.Account(parent.Name)
		if !found || !c.canManageAccount(r.Context(), actor, current) || !flow.Parent.matches(current) {
			fail(409, controlCodeRevisionMismatch, "connection changed during sign-in; start again")
			return
		}
		var record LinkedAccountRecord
		if flow.AccountID == "" {
			record, err = accounts.CreateLinkedAccount(r.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: actor.UserID, DisplayName: flow.DisplayName, OAuth: &credential}, flow.Parent)
		} else {
			record, err = accounts.MutateLinkedAccount(r.Context(), parent.Name, flow.AccountID, actor.UserID, flow.AccountRevision, flow.Parent, LinkedAccountMutation{OAuth: &credential})
		}
		if err != nil {
			if errors.Is(err, ErrLinkedAccountInvalid) {
				fail(409, "account_identity_mismatch", "sign in to the original provider account, or link a new account")
			} else if errors.Is(err, ErrLinkedAccountLimit) {
				fail(409, controlCodeCapacityLimited, "remove an unused account before linking another")
			} else if errors.Is(err, ErrLinkedAccountRevision) || errors.Is(err, ErrLinkedAccountNotFound) || errors.Is(err, ErrAccountPolicyPrecondition) {
				fail(409, controlCodeRevisionMismatch, "account changed during sign-in; start again")
			} else {
				fail(502, controlCodeEngineUnavailable, "could not confirm account linking; refresh to check its state")
			}
			return
		}
		writeJSON(w, 200, linkedAccountDTO(record, current))
	}
}
