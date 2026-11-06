package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Linked-account writes are distinct resources, not aliases of legacy token
// writes. Neither a successful link nor knowing its ID grants agent access.
func (c *ConsoleAPI) linkedAccountHandler(wire consoleWire, operation string) http.HandlerFunc {
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
		if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "account linking does not support replay keys; inspect current state before retrying")
			return
		}
		actor, ok := c.connectionNamespaceActor(r)
		if !ok || actor.UserID == "" || (actor.Role != "owner" && actor.Role != "admin" && actor.Role != "operator") {
			fail(http.StatusForbidden, controlCodeForbidden, "account linking is not permitted")
			return
		}
		store, ok := c.store.(LinkedAccountStore)
		if !ok {
			fail(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "account linking requires an Engine update")
			return
		}
		parent, found := c.store.Account(r.PathValue("id"))
		if !found || !c.canManageAccount(r.Context(), actor, parent) {
			fail(http.StatusNotFound, controlCodeNotFound, "connection not found")
			return
		}
		var body struct {
			ConnectionIncarnationID string  `json:"connectionIncarnationId"`
			ConnectionRevision      int64   `json:"connectionRevision"`
			Revision                int64   `json:"revision"`
			DisplayName             *string `json:"displayName"`
			Token                   *string `json:"token"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "invalid account linking request")
			return
		}
		if body.ConnectionIncarnationID != parent.IncarnationID || body.ConnectionRevision != parent.Revision || body.ConnectionRevision < 1 {
			fail(http.StatusConflict, controlCodeRevisionMismatch, "connection changed; refresh before trying again")
			return
		}
		var record LinkedAccountRecord
		var err error
		if operation == "create" {
			if body.DisplayName == nil || body.Token == nil || body.Revision != 0 || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != actor.UserID) {
				fail(http.StatusBadRequest, controlCodeValidationFailed, "a label and access token are required for an eligible connection")
				return
			}
			record, err = store.CreateLinkedAccount(r.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: actor.UserID, DisplayName: *body.DisplayName, BearerToken: *body.Token}, accountPolicyPrecondition(parent))
		} else {
			mutation := LinkedAccountMutation{}
			switch {
			case operation == "account" && r.Method == http.MethodPatch:
				if body.DisplayName == nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				} else {
					mutation.DisplayName = body.DisplayName
				}
			case operation == "account":
				if body.DisplayName != nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				}
				mutation.Remove = true
			case r.Method == http.MethodPut:
				if body.DisplayName != nil || body.Token == nil || !validLinkedAccountToken(*body.Token, false) || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != actor.UserID) {
					err = ErrLinkedAccountInvalid
				} else {
					mutation.BearerToken = body.Token
				}
			default:
				if body.DisplayName != nil || body.Token != nil {
					err = ErrLinkedAccountInvalid
				}
				empty := ""
				mutation.BearerToken = &empty
			}
			if err == nil {
				record, err = store.MutateLinkedAccount(r.Context(), parent.Name, r.PathValue("accountId"), actor.UserID, body.Revision, accountPolicyPrecondition(parent), mutation)
			}
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrLinkedAccountInvalid):
				fail(http.StatusBadRequest, controlCodeValidationFailed, "use a label up to 160 bytes and a nonempty access token without whitespace")
			case errors.Is(err, ErrLinkedAccountNotFound):
				fail(http.StatusNotFound, controlCodeNotFound, "linked account not found")
			case errors.Is(err, ErrLinkedAccountRevision), errors.Is(err, ErrAccountPolicyPrecondition):
				fail(http.StatusConflict, controlCodeRevisionMismatch, "account or connection changed; refresh before trying again")
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
		writeJSON(w, status, linkedAccountDTO(record, parent))
	}
}
