package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

type browserSignInDTO struct {
	ID           string    `json:"id"`
	Revision     int64     `json:"revision"`
	State        string    `json:"state"`
	DisplayName  string    `json:"displayName"`
	WebsiteURL   string    `json:"websiteUrl"`
	ConnectionID string    `json:"connectionId"`
	AccountID    string    `json:"accountId,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
	CanSave      bool      `json:"canSave"`
	Available    bool      `json:"available"`
}

func (s *BrowserSignInService) dto(f BrowserSignIn) browserSignInDTO {
	return browserSignInDTO{ID: f.ID, Revision: f.Revision, State: f.State, DisplayName: f.DisplayName, WebsiteURL: f.WebsiteURL, ConnectionID: f.ConnectionID, AccountID: f.AccountID, ExpiresAt: f.ExpiresAt, CanSave: f.State == "saving" && !f.SyncAfter.IsZero() && !time.Now().Before(f.SyncAfter), Available: s.configured(f)}
}
func (c *ConsoleAPI) browserSignInHandler(wire consoleWire, operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int, code, detail string) {
			if wire.control {
				wire.writeFailure(w, newConsoleFailure(status, code, detail))
			} else {
				writeJSON(w, status, map[string]string{"error": detail, "code": code})
			}
		}
		method := http.MethodPost
		if operation == "list" {
			method = http.MethodGet
		}
		if r.Method != method {
			wire.writeMethodNotAllowed(w, method)
			return
		}
		actor, ok := c.connectionNamespaceActor(r)
		if !ok || actor.UserID == "" || (actor.Role != "owner" && actor.Role != "admin" && actor.Role != "operator") {
			fail(403, controlCodeForbidden, "browser sign-in is not permitted")
			return
		}
		s := c.browserSignIn
		if s == nil {
			fail(501, controlCodeCapabilityUnavailable, "browser sign-in requires an Engine update")
			return
		}
		if len(r.Header.Values(controlIdempotencyKeyHeader)) != 0 {
			fail(400, controlCodeValidationFailed, "browser sign-in does not accept replay keys")
			return
		}
		if operation == "list" {
			flows, err := s.flows.BrowserSignIns(r.Context())
			if err != nil {
				fail(502, controlCodeEngineUnavailable, "could not load browser sign-ins")
				return
			}
			records, err := s.accounts.LinkedAccounts(r.Context(), actor.UserID)
			if err != nil {
				fail(502, controlCodeEngineUnavailable, "could not load browser sign-ins")
				return
			}
			out := []browserSignInDTO{}
			for _, f := range flows {
				if f.OwnerSubject != actor.UserID {
					continue
				}
				if f.State == "saved" {
					if browserProfileRetained(f, records) {
						continue
					}
					// Show queued deletion immediately, before the reaper's next tick.
					f.State = "cleanup"
				}
				out = append(out, s.dto(f))
			}
			writeJSON(w, 200, out)
			return
		}
		var body struct {
			ConnectionID            string `json:"connectionId"`
			ConnectionIncarnationID string `json:"connectionIncarnationId"`
			ConnectionRevision      int64  `json:"connectionRevision"`
			DisplayName             string `json:"displayName"`
			WebsiteURL              string `json:"websiteUrl"`
			AccountID               string `json:"accountId"`
			Revision                int64  `json:"revision"`
			Confirmed               bool   `json:"confirmed"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		d.DisallowUnknownFields()
		if d.Decode(&body) != nil || d.Decode(&struct{}{}) != io.EOF {
			fail(400, controlCodeValidationFailed, "invalid browser sign-in request")
			return
		}
		failError := func(err error) {
			if browserConflict(err) {
				fail(409, controlCodeRevisionMismatch, "account or sign-in changed; refresh to check its state")
			} else if errors.Is(err, ErrLinkedAccountLimit) {
				fail(409, controlCodeCapacityLimited, "finish or cancel another sign-in, or remove an unused account")
			} else {
				fail(502, controlCodeEngineUnavailable, "could not confirm browser sign-in; refresh to check its state")
			}
		}
		if operation == "start" {
			parent, found := c.store.Account(body.ConnectionID)
			if !found || !c.canManageAccount(r.Context(), actor, parent) {
				fail(404, controlCodeNotFound, "connection not found")
				return
			}
			if !s.availability().Available {
				fail(409, controlCodeCapabilityUnavailable, "browser sign-in needs provider setup")
				return
			}
			label, err := normalizeLinkedAccountName(body.DisplayName)
			if err != nil || !validBrowserWebsite(body.WebsiteURL) || body.Confirmed || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != actor.UserID) {
				fail(400, controlCodeValidationFailed, "use an account label and a public HTTPS website URL without query or fragment")
				return
			}
			if parent.IncarnationID != body.ConnectionIncarnationID || parent.Revision != body.ConnectionRevision {
				failError(ErrAccountPolicyPrecondition)
				return
			}
			if body.AccountID != "" {
				records, err := s.accounts.LinkedAccounts(r.Context(), actor.UserID)
				if err != nil {
					failError(err)
					return
				}
				found := false
				for _, record := range records {
					if record.ID == body.AccountID && record.Revision == body.Revision && record.ConnectionID == parent.Name && record.Boundary.IncarnationID == parent.IncarnationID && record.Browser != nil && record.Browser.WebsiteURL == body.WebsiteURL && record.Browser.Provider == s.provider.Kind() && record.Browser.ConfigurationID == s.provider.ConfigurationID() {
						found = true
					}
				}
				if !found {
					failError(ErrLinkedAccountRevision)
					return
				}
			} else if body.Revision != 0 {
				fail(400, controlCodeValidationFailed, "invalid account revision")
				return
			}
			f, err := s.start(r.Context(), BrowserSignIn{OwnerSubject: actor.UserID, ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), AccountID: body.AccountID, AccountRevision: body.Revision, DisplayName: label, WebsiteURL: body.WebsiteURL})
			if err != nil {
				failError(err)
				return
			}
			writeJSON(w, 201, s.dto(f))
			return
		}
		if body.ConnectionID != "" || body.ConnectionIncarnationID != "" || body.ConnectionRevision != 0 || body.DisplayName != "" || body.WebsiteURL != "" || body.AccountID != "" || (operation != "save" && body.Confirmed) {
			fail(400, controlCodeValidationFailed, "invalid sign-in action")
			return
		}
		f, err := s.lookup(r.Context(), r.PathValue("flowId"))
		if err != nil || f.OwnerSubject != actor.UserID {
			fail(404, controlCodeNotFound, "sign-in not found")
			return
		}
		if body.Revision != f.Revision {
			failError(errBrowserRevision)
			return
		}
		if operation == "cancel" {
			if f.State == "saved" || f.State == "starting" {
				failError(errBrowserRevision)
				return
			}
			f.State = "cleanup"
			f, err = s.write(r.Context(), f)
			if err != nil {
				failError(err)
				return
			}
			writeJSON(w, 202, s.dto(f))
			return
		}
		parent, found := c.store.Account(f.ConnectionID)
		if !found || !c.canManageAccount(r.Context(), actor, parent) {
			fail(404, controlCodeNotFound, "connection not found")
			return
		}
		if !s.configured(f) {
			fail(409, controlCodeCapabilityUnavailable, "browser provider configuration is unavailable")
			return
		}
		if !f.Parent.matches(parent) || time.Now().After(f.ExpiresAt) {
			failError(errBrowserRevision)
			return
		}
		switch operation {
		case "view":
			if f.State != "ready" {
				failError(errBrowserRevision)
				return
			}
			viewer, err := s.provider.View(r.Context(), f.SessionID)
			if err != nil {
				failError(err)
				return
			}
			current, err := s.lookup(r.Context(), f.ID)
			parent, found = c.store.Account(f.ConnectionID)
			if err != nil || current.Revision != f.Revision || !found || !f.Parent.matches(parent) || !c.canManageAccount(r.Context(), actor, parent) || time.Now().After(f.ExpiresAt) {
				failError(errBrowserRevision)
				return
			}
			writeJSON(w, 200, map[string]string{"viewerUrl": viewer})
		case "save":
			if !body.Confirmed {
				fail(400, controlCodeValidationFailed, "confirm that you finished signing in")
				return
			}
			if f.State == "ready" {
				f.State = "saving"
				f, err = s.write(r.Context(), f)
				if err != nil {
					failError(err)
					return
				}
			}
			if f.State != "saving" {
				failError(errBrowserRevision)
				return
			}
			f, err = s.advance(r.Context(), f)
			if err != nil {
				failError(err)
				return
			}
			if f.State != "saving" {
				failError(errBrowserRevision)
				return
			}
			if f.SyncAfter.IsZero() || time.Now().Before(f.SyncAfter) {
				writeJSON(w, 202, s.dto(f))
				return
			}
			current, found := c.store.Account(parent.Name)
			if !found || !c.canManageAccount(r.Context(), actor, current) || !f.Parent.matches(current) {
				failError(ErrAccountPolicyPrecondition)
				return
			}
			record, err := s.flows.CommitBrowserSignIn(r.Context(), f.ID, f.Revision)
			if err != nil {
				failError(err)
				return
			}
			writeJSON(w, 200, linkedAccountDTO(record, current))
		default:
			fail(404, controlCodeNotFound, "not found")
		}
	}
}
