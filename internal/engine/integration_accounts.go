package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// controlCapabilityAccountStandalone says this Engine stores token and OAuth
// linked accounts without an MCP parent. Such an account belongs to its
// authenticated owner only; linking it never grants agent access and no
// execution path reads it.
const controlCapabilityAccountStandalone = "account-linking-standalone"

// standaloneLinkedAccountStore marks a LinkedAccountStore that persists
// standalone integration accounts in their own table or file field.
type standaloneLinkedAccountStore interface {
	LinkedAccountStore
	supportsStandaloneLinkedAccounts()
}

func (*FileStore) supportsStandaloneLinkedAccounts() {}
func (*PgStore) supportsStandaloneLinkedAccounts()   {}

func (c *ConsoleAPI) standaloneLinkedAccounts() (standaloneLinkedAccountStore, bool) {
	store, ok := c.store.(standaloneLinkedAccountStore)
	return store, ok
}

// isIntegrationAccount identifies an owner-private token or OAuth account
// without an MCP parent. A disconnected account keeps its integration ID (and
// OAuth identity), so it stays an integration account.
func (record LinkedAccountRecord) isIntegrationAccount() bool {
	if record.ConnectionID != "" || record.Boundary != (OAuthCompletionPrecondition{}) || record.Browser != nil ||
		len(record.BrowserGrants) != 0 || !validActorIdentifier(record.OwnerSubject) {
		return false
	}
	switch {
	case record.IntegrationID == integrationTokenAPI:
		return record.OAuth == nil
	case record.OAuth != nil:
		return record.BearerToken == "" && record.OAuth.Provider != "" && record.IntegrationID == integrationOAuthPrefix+record.OAuth.Provider
	default:
		return false
	}
}

// integrationAccountHandler serves /linked-accounts: standalone token accounts
// are created here, and standalone token or OAuth accounts are renamed,
// rotated, disconnected and removed here. Owner-only, no replay keys, revision
// CAS on every mutation, and 404 for anything the caller does not own.
func (c *ConsoleAPI) integrationAccountHandler(wire consoleWire, operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		allowed := map[string]string{"create": http.MethodPost, "account": "PATCH, DELETE", "token": "PUT, DELETE"}[operation]
		if !(operation == "create" && r.Method == http.MethodPost || operation == "account" && (r.Method == http.MethodPatch || r.Method == http.MethodDelete) || operation == "token" && (r.Method == http.MethodPut || r.Method == http.MethodDelete)) {
			wire.writeMethodNotAllowed(w, allowed)
			return
		}
		fail := func(status int, code, detail string) {
			if wire.control {
				wire.writeFailure(w, newConsoleFailure(status, code, detail))
				return
			}
			writeJSON(w, status, map[string]string{"error": detail, "code": code})
		}
		actor, ok := c.connectionNamespaceActor(r)
		if !ok || !validWebsiteAccountActor(actor) {
			fail(http.StatusForbidden, controlCodeForbidden, "account linking is not permitted")
			return
		}
		if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "account linking does not support replay keys; inspect current state before retrying")
			return
		}
		store, ok := c.standaloneLinkedAccounts()
		if !ok {
			fail(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "standalone accounts require an Engine update")
			return
		}
		var body struct {
			IntegrationID *string `json:"integrationId"`
			Revision      int64   `json:"revision"`
			DisplayName   *string `json:"displayName"`
			Token         *string `json:"token"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "invalid account linking request")
			return
		}
		var record LinkedAccountRecord
		var err error
		if operation == "create" {
			if body.IntegrationID == nil || *body.IntegrationID != integrationTokenAPI {
				if body.IntegrationID != nil && strings.HasPrefix(*body.IntegrationID, integrationOAuthPrefix) {
					fail(http.StatusBadRequest, controlCodeValidationFailed, "OAuth accounts are linked through provider sign-in")
				} else {
					fail(http.StatusBadRequest, controlCodeValidationFailed, "use integration "+integrationTokenAPI)
				}
				return
			}
			if body.DisplayName == nil || body.Token == nil || body.Revision != 0 || !validLinkedAccountToken(*body.Token, false) {
				fail(http.StatusBadRequest, controlCodeValidationFailed, "a label and access token are required")
				return
			}
			record, err = store.CreateLinkedAccount(r.Context(), LinkedAccountRecord{IntegrationID: integrationTokenAPI, OwnerSubject: actor.UserID, DisplayName: *body.DisplayName, BearerToken: *body.Token}, AccountPolicyPrecondition{})
		} else {
			mutation := LinkedAccountMutation{Integration: true}
			switch {
			case body.IntegrationID != nil:
				err = ErrLinkedAccountInvalid
			case operation == "account" && r.Method == http.MethodPatch:
				if body.DisplayName == nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				}
				mutation.DisplayName = body.DisplayName
			case operation == "account":
				if body.DisplayName != nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				}
				mutation.Remove = true
			case r.Method == http.MethodPut:
				if body.DisplayName != nil || body.Token == nil || !validLinkedAccountToken(*body.Token, false) {
					err = ErrLinkedAccountInvalid
				}
				mutation.BearerToken = body.Token
			default:
				if body.DisplayName != nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				}
				empty := ""
				mutation.BearerToken = &empty
			}
			if err == nil {
				record, err = store.MutateLinkedAccount(r.Context(), "", r.PathValue("accountId"), actor.UserID, body.Revision, AccountPolicyPrecondition{}, mutation)
			}
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrLinkedAccountInvalid):
				fail(http.StatusBadRequest, controlCodeValidationFailed, "use a label up to 160 bytes and a nonempty access token without whitespace")
			case errors.Is(err, ErrLinkedAccountNotFound):
				fail(http.StatusNotFound, controlCodeNotFound, "linked account not found")
			case errors.Is(err, ErrLinkedAccountRevision), errors.Is(err, ErrAccountPolicyPrecondition):
				fail(http.StatusConflict, controlCodeRevisionMismatch, "account changed; refresh before trying again")
			case errors.Is(err, ErrLinkedAccountLimit):
				fail(http.StatusConflict, controlCodeCapacityLimited, "remove an unused linked account before adding another")
			default:
				fail(http.StatusBadGateway, controlCodeEngineUnavailable, "could not save linked account; refresh to check its state")
			}
			return
		}
		if operation == "account" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		status := http.StatusOK
		if operation == "create" {
			status = http.StatusCreated
		}
		writeJSON(w, status, modelLinkedAccount(record, Account{}))
	}
}
