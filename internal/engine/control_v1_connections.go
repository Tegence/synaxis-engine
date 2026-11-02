package engine

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"narthex/backend/internal/upstreamoauth"
)

// The connections group of /control/v1 (docs/CONTROL_V1.md, "Connections").
// These routes are v1 shims over the same internals as /api/servers*: the
// account store, connection-namespace resolution, SetBearerToken with its
// revision bump, and gateway re-aggregation. Only the wire boundary differs:
// camelCase bodies, problem details, natural-key convergence on toolPrefix,
// revision fences, and secret-free responses.
//
// The implemented subset is create, read, patch, token and delete. It serves
// workspace owners, admins and the hosting control plane's service actor;
// operators keep the /api/servers folder-delegation rules. On a hosted Engine
// a caller-delegated connection is written only by the service actor
// (callerDelegatedWriter); owners and admins may read it.

const (
	controlConnectionsBodyLimit     = 64 << 10
	controlConnectionToolPrefixMax  = 64
	controlConnectionDisplayNameMax = 200
	controlConnectionTokenMax       = 4096
	controlConnectionDefaultFolder  = "General"
	controlConnectionDeleteAttempts = 3
)

// controlConnectionDTO is the v1 connection projection. It never carries a
// credential: tokenSet and callerDelegated.clientSecretSet only say whether
// one is stored.
type controlConnectionDTO struct {
	ToolPrefix            string              `json:"toolPrefix"`
	DisplayName           string              `json:"displayName"`
	Group                 string              `json:"group"`
	ConnectionNamespaceID string              `json:"connectionNamespaceId,omitempty"`
	ConnectionScope       string              `json:"connectionScope"`
	OwnerSubject          string              `json:"ownerSubject,omitempty"`
	URL                   string              `json:"url"`
	AuthMode              string              `json:"authMode"`
	TokenSet              bool                `json:"tokenSet"`
	Revision              int64               `json:"revision"`
	ReadOnly              bool                `json:"readOnly"`
	MemberCredentials     bool                `json:"memberCredentials"`
	CallerDelegated       *callerDelegatedDTO `json:"callerDelegated,omitempty"`
}

func newControlConnectionDTO(a Account) controlConnectionDTO {
	display := a.Label
	if display == "" {
		display = a.Name
	}
	scope, err := normalizedConnectionScope(a.ConnectionScope)
	if err != nil {
		scope = a.ConnectionScope
	}
	tokenSet := a.AccessToken != "" || a.RefreshToken != ""
	if a.AuthMode == "token" {
		tokenSet = a.BearerToken != ""
	}
	return controlConnectionDTO{
		ToolPrefix: a.Name, DisplayName: display, Group: a.Group, ConnectionNamespaceID: a.ConnectionNamespaceID,
		ConnectionScope: string(scope), OwnerSubject: a.OwnerSubject, URL: a.URL, AuthMode: a.AuthMode,
		TokenSet: tokenSet, Revision: a.Revision, ReadOnly: a.ReadOnly, MemberCredentials: a.MemberCredentials,
		CallerDelegated: newCallerDelegatedDTO(a),
	}
}

type controlCallerDelegatedRequest struct {
	TokenEndpoint *string `json:"tokenEndpoint"`
	ClientID      *string `json:"clientId"`
	ClientSecret  *string `json:"clientSecret"`
	Resource      *string `json:"resource"`
}

type controlConnectionCreateRequest struct {
	ToolPrefix        string                         `json:"toolPrefix"`
	DisplayName       string                         `json:"displayName"`
	Group             *string                        `json:"group"`
	ConnectionScope   *string                        `json:"connectionScope"`
	URL               string                         `json:"url"`
	AuthMode          string                         `json:"authMode"`
	MemberCredentials bool                           `json:"memberCredentials"`
	CallerDelegated   *controlCallerDelegatedRequest `json:"callerDelegated"`
}

type controlConnectionPatchRequest struct {
	Revision        *int64                         `json:"revision"`
	DisplayName     *string                        `json:"displayName"`
	Group           *string                        `json:"group"`
	URL             *string                        `json:"url"`
	CallerDelegated *controlCallerDelegatedRequest `json:"callerDelegated"`
}

type controlConnectionTokenRequest struct {
	Token    string `json:"token"`
	Revision *int64 `json:"revision"`
}

// decodeControlConnectionJSON is strict: these bodies carry credentials, so a
// misspelled or unsupported field is refused rather than silently ignored.
func decodeControlConnectionJSON(w http.ResponseWriter, r *http.Request, destination any) *consoleFailure {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, controlConnectionsBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid connection request body")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid connection request body")
	}
	return nil
}

func controlConnectionValidation(message string) *consoleFailure {
	return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, message)
}

func controlConnectionNotFound() *consoleFailure {
	return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "connection not found")
}

func controlConnectionRevisionMismatch() *consoleFailure {
	return newConsoleFailure(http.StatusConflict, controlCodeRevisionMismatch, "connection revision does not match; read it again")
}

func controlConnectionUnavailable(message string) *consoleFailure {
	return newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, message)
}

// callerDelegatedWriter reports whether actor may create, edit, set the token
// of or delete a caller-delegated connection. On a hosted Engine only the
// hosting control plane's service actor may: it alone holds the client
// credentials such a connection exchanges caller grants with. A self-hosted
// Engine has no service actor and one local administrator, who keeps them.
func (c *ConsoleAPI) callerDelegatedWriter(actor PlatformActor) bool {
	return c.actorVerifier == nil || (actor.Role == "service" && actor.UserID == platformServiceActorID)
}

func controlConnectionDelegationForbidden() *consoleFailure {
	return newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "caller-delegated connections are written only by the Platform service")
}

// controlConnectionsAdministration is the gate shared by every route in the
// group: a verified owner, admin or the service actor, on a store with
// connection namespaces.
func (c *ConsoleAPI) controlConnectionsAdministration(r *http.Request) (PlatformActor, *consoleFailure) {
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || !connectionNamespaceAdministrator(actor) {
		return PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connections require a workspace owner, admin, or the Platform service")
	}
	if _, ok := c.connectionNamespaceStore(); !ok {
		return PlatformActor{}, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "connection namespaces are not supported by this store")
	}
	return actor, nil
}

// handleControlConnections serves POST /control/v1/connections.
func (c *ConsoleAPI) handleControlConnections(w http.ResponseWriter, r *http.Request) {
	actor, failure := c.controlConnectionsAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPost {
		controlWire.writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request controlConnectionCreateRequest
	if failure := decodeControlConnectionJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if request.CallerDelegated != nil && !c.callerDelegatedWriter(actor) {
		controlWire.writeFailure(w, controlConnectionDelegationForbidden())
		return
	}
	desired, folder, failure := controlConnectionFromCreate(request)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	// The natural key converges before anything is written: an identical retry
	// answers with the existing connection, a different body under the same
	// key is a conflict, and neither mints a folder.
	if existing, found := c.store.Account(desired.Name); found {
		c.writeControlConnectionConvergence(w, r, existing, desired, folder)
		return
	}
	namespace, err := c.resolveManagedConnectionNamespace(r.Context(), actor, "", folder, true)
	if failure := controlConnectionFolderFailure(namespace, err); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	desired.Group = namespace.Label
	desired.ConnectionNamespaceID = namespace.ID
	if err := c.store.Create(r.Context(), desired); err != nil {
		if errors.Is(err, ErrAccountExists) {
			if existing, found := c.store.Account(desired.Name); found {
				c.writeControlConnectionConvergence(w, r, existing, desired, folder)
				return
			}
		}
		if isCallerDelegatedValidationError(err) {
			controlWire.writeFailure(w, controlConnectionValidation(err.Error()))
			return
		}
		controlWire.writeFailure(w, controlConnectionUnavailable("could not save connection"))
		return
	}
	created, found := c.store.Account(desired.Name)
	if !found {
		controlWire.writeFailure(w, controlConnectionUnavailable("connection could not be read after creation"))
		return
	}
	writeJSON(w, http.StatusCreated, newControlConnectionDTO(created))
}

// controlConnectionFromCreate validates a create body and returns the account
// it asks for (without its folder) and the folder label.
func controlConnectionFromCreate(request controlConnectionCreateRequest) (Account, string, *consoleFailure) {
	name := request.ToolPrefix
	if name == "" || len(name) > controlConnectionToolPrefixMax || slugify(name) != name {
		return Account{}, "", controlConnectionValidation("toolPrefix must be 1 to 64 lowercase letters, digits or underscores")
	}
	display := strings.TrimSpace(request.DisplayName)
	if display == "" || len(display) > controlConnectionDisplayNameMax {
		return Account{}, "", controlConnectionValidation("displayName is required and at most 200 bytes")
	}
	folder := controlConnectionDefaultFolder
	if request.Group != nil {
		folder = strings.TrimSpace(*request.Group)
		if folder == "" || len(folder) > controlConnectionDisplayNameMax {
			return Account{}, "", controlConnectionValidation("group must be a folder label of at most 200 bytes")
		}
	}
	scope := ConnectionScopeShared
	if request.ConnectionScope != nil {
		normalized, err := normalizedConnectionScope(ConnectionScope(*request.ConnectionScope))
		if err != nil || normalized == ConnectionScopePersonal {
			return Account{}, "", controlConnectionValidation("connectionScope must be shared or service")
		}
		scope = normalized
	}
	if request.AuthMode != "token" {
		return Account{}, "", controlConnectionValidation("authMode must be token")
	}
	account := Account{
		Name: name, Label: display, URL: strings.TrimSpace(request.URL), AuthMode: "token",
		ConnectionScope: scope, MemberCredentials: request.MemberCredentials,
	}
	if request.CallerDelegated == nil {
		if err := upstreamoauth.ValidateUpstreamURL(account.URL); err != nil {
			return Account{}, "", controlConnectionValidation("url must be a valid https URL")
		}
		return account, folder, nil
	}
	delegated := request.CallerDelegated
	account.CallerDelegated = true
	account.TokenEndpoint = stringValue(delegated.TokenEndpoint)
	account.ClientID = stringValue(delegated.ClientID)
	account.ClientSecret = stringValue(delegated.ClientSecret)
	account.Resource = stringValue(delegated.Resource)
	if err := validateCallerDelegatedAccount(account); err != nil {
		return Account{}, "", controlConnectionValidation(err.Error())
	}
	return account, folder, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func controlConnectionFolderFailure(namespace ConnectionNamespace, err error) *consoleFailure {
	switch {
	case err == nil && namespace.OwnerSubject != "":
		return controlConnectionValidation("group names a personal folder")
	case err == nil:
		return nil
	case errors.Is(err, errConnectionNamespaceAccess):
		return newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connection namespace access is not permitted")
	case errors.Is(err, errConnectionNamespaceAmbiguous):
		return controlConnectionValidation("group matches more than one folder")
	case errors.Is(err, ErrConnectionNamespaceNotFound):
		return controlConnectionValidation("group folder was not found")
	default:
		return controlConnectionUnavailable("could not resolve the connection folder")
	}
}

// writeControlConnectionConvergence answers a create whose natural key is
// already taken: 200 with the existing connection when the stored state is
// what the body asks for, otherwise 409 already_exists. A connection whose
// listing token has since been set, or whose revision moved, still matches.
func (c *ConsoleAPI) writeControlConnectionConvergence(w http.ResponseWriter, r *http.Request, existing, desired Account, folder string) {
	if !c.controlConnectionMatches(r.Context(), existing, desired, folder) {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusConflict, controlCodeAlreadyExists, "a different connection already uses this toolPrefix"))
		return
	}
	writeJSON(w, http.StatusOK, newControlConnectionDTO(existing))
}

func (c *ConsoleAPI) controlConnectionMatches(ctx context.Context, existing, desired Account, folder string) bool {
	existingScope, err := normalizedConnectionScope(existing.ConnectionScope)
	if err != nil {
		return false
	}
	label := existing.Group
	if store, ok := c.connectionNamespaceStore(); ok && existing.ConnectionNamespaceID != "" {
		if namespace, found := store.ConnectionNamespace(ctx, existing.ConnectionNamespaceID); found {
			label = namespace.Label
		}
	}
	return existing.Label == desired.Label &&
		strings.EqualFold(strings.TrimSpace(label), folder) &&
		existingScope == desired.ConnectionScope &&
		existing.OwnerSubject == "" &&
		existing.URL == desired.URL &&
		existing.AuthMode == desired.AuthMode &&
		existing.MemberCredentials == desired.MemberCredentials &&
		existing.CallerDelegated == desired.CallerDelegated &&
		existing.TokenEndpoint == desired.TokenEndpoint &&
		existing.ClientID == desired.ClientID &&
		existing.Resource == desired.Resource &&
		subtle.ConstantTimeCompare([]byte(existing.ClientSecret), []byte(desired.ClientSecret)) == 1
}

// handleControlConnectionByName serves GET, PATCH and DELETE
// /control/v1/connections/{name}.
func (c *ConsoleAPI) handleControlConnectionByName(w http.ResponseWriter, r *http.Request) {
	actor, failure := c.controlConnectionsAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	name := r.PathValue("name")
	switch r.Method {
	case http.MethodGet:
		account, found := c.store.Account(name)
		if !found {
			controlWire.writeFailure(w, controlConnectionNotFound())
			return
		}
		writeJSON(w, http.StatusOK, newControlConnectionDTO(account))
	case http.MethodPatch:
		c.patchControlConnection(w, r, actor, name)
	case http.MethodDelete:
		c.deleteControlConnection(w, r, actor, name)
	default:
		controlWire.writeMethodNotAllowed(w, "GET, PATCH, DELETE")
	}
}

func (c *ConsoleAPI) patchControlConnection(w http.ResponseWriter, r *http.Request, actor PlatformActor, name string) {
	var request controlConnectionPatchRequest
	if failure := decodeControlConnectionJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if request.Revision == nil || *request.Revision < 1 {
		controlWire.writeFailure(w, controlConnectionValidation("revision is required"))
		return
	}
	current, found := c.store.Account(name)
	if !found {
		controlWire.writeFailure(w, controlConnectionNotFound())
		return
	}
	if current.CallerDelegated && !c.callerDelegatedWriter(actor) {
		controlWire.writeFailure(w, controlConnectionDelegationForbidden())
		return
	}
	if current.Revision != *request.Revision {
		controlWire.writeFailure(w, controlConnectionRevisionMismatch())
		return
	}
	update, failure := controlConnectionUpdateFromPatch(current, request)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	// Validate the whole result before any write, so a refused patch never
	// leaves a half-applied move behind. The stores apply the same rule again
	// under their lock.
	next, changed, err := applyAccountConnectionUpdate(current, update)
	if err != nil {
		controlWire.writeFailure(w, controlConnectionWriteFailure(err, "could not update connection"))
		return
	}
	if !next.CallerDelegated && next.URL != current.URL {
		if err := upstreamoauth.ValidateUpstreamURL(next.URL); err != nil {
			controlWire.writeFailure(w, controlConnectionValidation("url must be a valid https URL"))
			return
		}
	}
	if request.Group != nil {
		folder := strings.TrimSpace(*request.Group)
		if folder == "" || len(folder) > controlConnectionDisplayNameMax {
			controlWire.writeFailure(w, controlConnectionValidation("group must be a folder label of at most 200 bytes"))
			return
		}
		namespace, err := c.resolveManagedConnectionNamespace(r.Context(), actor, "", folder, true)
		if failure := controlConnectionFolderFailure(namespace, err); failure != nil {
			controlWire.writeFailure(w, failure)
			return
		}
		if namespace.ID != current.ConnectionNamespaceID {
			moved, err := c.gw.MoveAccountToConnectionNamespace(r.Context(), current.Name, current.IncarnationID, AccountConnectionAssignment{
				ConnectionNamespaceID: namespace.ID,
				Scope:                 current.ConnectionScope,
				OwnerSubject:          current.OwnerSubject,
			}, current.Revision)
			if failure := controlConnectionWriteFailure(err, "could not move connection"); failure != nil {
				controlWire.writeFailure(w, failure)
				return
			}
			current = moved
		}
	}
	if changed {
		updater, ok := c.store.(accountConnectionUpdater)
		if !ok {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "connection edits are not supported by this store"))
			return
		}
		updated, err := updater.UpdateAccountConnection(r.Context(), current.Name, current.IncarnationID, current.Revision, update)
		if failure := controlConnectionWriteFailure(err, "could not update connection"); failure != nil {
			controlWire.writeFailure(w, failure)
			return
		}
		current = updated
		// As with a token PUT, the durable write already advanced Revision, so
		// cached handlers fail closed until this re-aggregation succeeds.
		c.gw.replaceAccountListingSoon(r.Context(), current.Name)
	}
	if persisted, found := c.store.Account(name); found {
		current = persisted
	}
	writeJSON(w, http.StatusOK, newControlConnectionDTO(current))
}

func controlConnectionUpdateFromPatch(current Account, request controlConnectionPatchRequest) (accountConnectionUpdate, *consoleFailure) {
	var update accountConnectionUpdate
	if request.DisplayName != nil {
		display := strings.TrimSpace(*request.DisplayName)
		if display == "" || len(display) > controlConnectionDisplayNameMax {
			return update, controlConnectionValidation("displayName is required and at most 200 bytes")
		}
		update.Label = &display
	}
	if request.URL != nil {
		value := strings.TrimSpace(*request.URL)
		update.URL = &value
	}
	if request.CallerDelegated != nil {
		if !current.CallerDelegated {
			return update, controlConnectionValidation("callerDelegated is set when a connection is created")
		}
		delegated := request.CallerDelegated
		update.TokenEndpoint = delegated.TokenEndpoint
		update.ClientID = delegated.ClientID
		update.ClientSecret = delegated.ClientSecret
		update.Resource = delegated.Resource
	}
	return update, nil
}

func controlConnectionWriteFailure(err error, message string) *consoleFailure {
	switch {
	case err == nil:
		return nil
	case isCallerDelegatedValidationError(err):
		return controlConnectionValidation(err.Error())
	case errors.Is(err, ErrConnectionNamespaceRevision), errors.Is(err, ErrAccountIncarnation), errors.Is(err, ErrAccountPolicyPrecondition):
		return controlConnectionRevisionMismatch()
	case errors.Is(err, ErrAccountNotFound), errors.Is(err, ErrConnectionNamespaceNotFound):
		return controlConnectionNotFound()
	case errors.Is(err, ErrInvalidConnectionScope):
		return controlConnectionValidation("invalid connection assignment")
	default:
		return controlConnectionUnavailable(message)
	}
}

// deleteControlConnection is idempotent: a missing connection is already in
// the requested state. It deletes the exact incarnation it read, re-reading
// when a concurrent write moved the revision.
func (c *ConsoleAPI) deleteControlConnection(w http.ResponseWriter, r *http.Request, actor PlatformActor, name string) {
	for attempt := 0; attempt < controlConnectionDeleteAttempts; attempt++ {
		current, found := c.store.Account(name)
		if !found {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if current.CallerDelegated && !c.callerDelegatedWriter(actor) {
			controlWire.writeFailure(w, controlConnectionDelegationForbidden())
			return
		}
		err := c.store.Delete(r.Context(), name, current.IncarnationID, current.Revision)
		if err == nil {
			c.gw.RemoveAccount(name, current.IncarnationID)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !errors.Is(err, ErrAccountIncarnation) && !errors.Is(err, ErrConnectionNamespaceRevision) && !errors.Is(err, ErrAccountNotFound) {
			controlWire.writeFailure(w, controlConnectionUnavailable("could not delete connection"))
			return
		}
	}
	controlWire.writeFailure(w, controlConnectionRevisionMismatch())
}

// handleControlConnectionToken serves PUT /control/v1/connections/{name}/token:
// the account's own bearer token, revision-fenced. Every PUT advances the
// revision and re-aggregates the account, exactly as /api/servers/{id}/token.
func (c *ConsoleAPI) handleControlConnectionToken(w http.ResponseWriter, r *http.Request) {
	actor, failure := c.controlConnectionsAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPut {
		controlWire.writeMethodNotAllowed(w, http.MethodPut)
		return
	}
	var request controlConnectionTokenRequest
	if failure := decodeControlConnectionJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if !callerDelegatedPrintable(request.Token, 1, controlConnectionTokenMax) {
		controlWire.writeFailure(w, controlConnectionValidation("token must be 1 to 4096 printable characters"))
		return
	}
	if request.Revision == nil || *request.Revision < 1 {
		controlWire.writeFailure(w, controlConnectionValidation("revision is required"))
		return
	}
	name := r.PathValue("name")
	current, found := c.store.Account(name)
	if !found {
		controlWire.writeFailure(w, controlConnectionNotFound())
		return
	}
	if current.CallerDelegated && !c.callerDelegatedWriter(actor) {
		controlWire.writeFailure(w, controlConnectionDelegationForbidden())
		return
	}
	updated, err := c.store.SetBearerToken(r.Context(), name, current.IncarnationID, request.Token, *request.Revision)
	if failure := controlConnectionWriteFailure(err, "could not save connection token"); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	c.gw.replaceAccountListingSoon(r.Context(), updated.Name)
	if persisted, found := c.store.Account(name); found && persisted.IncarnationID == updated.IncarnationID {
		updated = persisted
	}
	writeJSON(w, http.StatusOK, newControlConnectionDTO(updated))
}

// platformServiceControlConnectionRoute is the service actor's closed set on
// the connections group: POST /control/v1/connections,
// GET|PATCH|DELETE /control/v1/connections/{name} and
// PUT /control/v1/connections/{name}/token. The name is constrained to the
// actor identifier alphabet so a differently encoded path cannot alias a
// signed one.
func platformServiceControlConnectionRoute(method, requestPath string) bool {
	if requestPath == controlV1PathPrefix+"connections" {
		return method == http.MethodPost
	}
	parts := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")
	if len(parts) < 4 || len(parts) > 5 || parts[0] != "control" || parts[1] != "v1" || parts[2] != "connections" || !validActorIdentifier(parts[3]) {
		return false
	}
	if len(parts) == 4 {
		return method == http.MethodGet || method == http.MethodPatch || method == http.MethodDelete
	}
	return parts[4] == "token" && method == http.MethodPut
}
