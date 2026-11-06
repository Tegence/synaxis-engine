package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const controlCapabilityAccountWebsite = "account-linking-website"

func validWebsiteAccountActor(actor PlatformActor) bool {
	return validActorIdentifier(actor.UserID) && (actor.Role == "owner" || actor.Role == "admin" || actor.Role == "operator")
}

// A website sign-in is owned directly by its authenticated human. Existing
// connection-bound flows retain their connection-management authorization.
func (c *ConsoleAPI) browserSignInParent(ctx context.Context, actor PlatformActor, f BrowserSignIn) (Account, bool) {
	if !validWebsiteAccountActor(actor) || f.OwnerSubject != actor.UserID {
		return Account{}, false
	}
	if f.isWebsiteSignIn() {
		return Account{}, true
	}
	parent, found := c.store.Account(f.ConnectionID)
	return parent, found && c.canManageAccount(ctx, actor, parent)
}

func browserSignInParentMatches(f BrowserSignIn, parent Account) bool {
	if f.isWebsiteSignIn() {
		return parent.Name == "" && parent.URL == "" && !parent.CallerDelegated && accountPolicyPrecondition(parent) == (AccountPolicyPrecondition{})
	}
	return f.Parent.matches(parent)
}

func (s *BrowserSignInService) browserSignInParent(f BrowserSignIn) (Account, bool) {
	if f.isWebsiteSignIn() {
		return Account{}, true
	}
	parent, found := s.store.Account(f.ConnectionID)
	return parent, found && f.Parent.matches(parent)
}

// Website-account writes never accept a connection or caller-supplied owner.
// Their store mutation is fenced to the authenticated owner and account revision.
func (c *ConsoleAPI) websiteAccountHandler(wire consoleWire, disconnect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		allowed := "PATCH, DELETE"
		if disconnect {
			allowed = http.MethodPost
		}
		if disconnect && r.Method != http.MethodPost || !disconnect && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
			wire.writeMethodNotAllowed(w, allowed)
			return
		}
		fail := func(status int, code, detail string) {
			if wire.control {
				wire.writeFailure(w, newConsoleFailure(status, code, detail))
			} else {
				writeJSON(w, status, map[string]string{"error": detail, "code": code})
			}
		}
		actor, ok := c.connectionNamespaceActor(r)
		if !ok || !validWebsiteAccountActor(actor) {
			fail(http.StatusForbidden, controlCodeForbidden, "website account access is not permitted")
			return
		}
		if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "website accounts do not support replay keys; inspect current state before retrying")
			return
		}
		store, ok := c.store.(LinkedAccountStore)
		if !ok {
			fail(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "website accounts require an Engine update")
			return
		}
		var body struct {
			Revision    int64   `json:"revision"`
			DisplayName *string `json:"displayName"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || body.Revision < 1 ||
			(disconnect || r.Method == http.MethodDelete) && body.DisplayName != nil ||
			!disconnect && r.Method == http.MethodPatch && body.DisplayName == nil {
			fail(http.StatusBadRequest, controlCodeValidationFailed, "use the current account revision and a label for renaming")
			return
		}
		mutation := LinkedAccountMutation{DisplayName: body.DisplayName, Remove: !disconnect && r.Method == http.MethodDelete}
		if disconnect {
			empty := ""
			mutation.BearerToken = &empty
		}
		record, err := store.MutateLinkedAccount(r.Context(), "", r.PathValue("accountId"), actor.UserID, body.Revision, AccountPolicyPrecondition{}, mutation)
		if err != nil {
			switch {
			case errors.Is(err, ErrLinkedAccountInvalid):
				fail(http.StatusBadRequest, controlCodeValidationFailed, "use an account label up to 160 bytes")
			case errors.Is(err, ErrLinkedAccountNotFound):
				fail(http.StatusNotFound, controlCodeNotFound, "website account not found")
			case errors.Is(err, ErrLinkedAccountRevision), errors.Is(err, ErrAccountPolicyPrecondition):
				fail(http.StatusConflict, controlCodeRevisionMismatch, "account changed; refresh before trying again")
			default:
				fail(http.StatusBadGateway, controlCodeEngineUnavailable, "could not save website account; refresh to check its state")
			}
			return
		}
		if mutation.Remove {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, linkedAccountDTO(record, Account{}))
	}
}
