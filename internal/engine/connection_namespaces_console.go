package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// connectionNamespaceDTO is intentionally separate from NamespaceDTO. A
// connection namespace owns a credential boundary; an endpoint bundle merely
// chooses a shared delivery surface. Keeping the two shapes separate prevents
// a console client from accidentally treating an endpoint membership as
// authority to manage a credential.
type connectionNamespaceDTO struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Label     string `json:"label"`
	Revision  int64  `json:"revision"`
	CreatedBy string `json:"createdBy,omitempty"`

	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`

	// Managers is visible only to workspace administrators. A delegated
	// operator learns that they can manage a namespace through CanManage, not
	// who else was granted access.
	Managers            []string `json:"managers,omitempty"`
	CanManage           bool     `json:"canManage"`
	CanManageMembership bool     `json:"canManageMembership"`
	CanDelete           bool     `json:"canDelete"`
}

func (c *ConsoleAPI) connectionNamespaceStore() (ConnectionNamespaceStore, bool) {
	store, ok := c.store.(ConnectionNamespaceStore)
	return store, ok
}

func (c *ConsoleAPI) connectionNamespacesSupported(w http.ResponseWriter) (ConnectionNamespaceStore, bool) {
	store, ok := c.connectionNamespaceStore()
	if ok {
		return store, true
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "connection namespaces are not supported by this store",
	})
	return nil, false
}

// connectionNamespaceActor returns the verified Platform actor in hosted
// mode. Self-hosted Engines deliberately retain their single local-admin
// model, but a hosted Engine never falls back to that local identity.
func (c *ConsoleAPI) connectionNamespaceActor(r *http.Request) (PlatformActor, bool) {
	if c.actorVerifier == nil {
		return PlatformActor{UserID: "local-admin", Role: "owner"}, true
	}
	return PlatformActorFromContext(r.Context())
}

func connectionNamespaceAdministrator(actor PlatformActor) bool {
	switch actor.Role {
	case "owner", "admin", "service":
		return true
	default:
		return false
	}
}

func connectionNamespaceManager(ns ConnectionNamespace, subject string) bool {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return false
	}
	for _, grant := range ns.ManagerGrants {
		if grant.Subject == subject {
			return true
		}
	}
	return false
}

func (c *ConsoleAPI) canReadConnectionNamespace(actor PlatformActor, ns ConnectionNamespace) bool {
	return connectionNamespaceAdministrator(actor) ||
		(actor.Role == "operator" && connectionNamespaceManager(ns, actor.UserID))
}

func (c *ConsoleAPI) canManageConnectionNamespace(actor PlatformActor, ns ConnectionNamespace) bool {
	return c.canReadConnectionNamespace(actor, ns)
}

func (c *ConsoleAPI) canManageConnectionNamespaceMembership(actor PlatformActor) bool {
	return connectionNamespaceAdministrator(actor)
}

func (c *ConsoleAPI) canDeleteConnectionNamespace(actor PlatformActor, _ ConnectionNamespace) bool {
	// Creation attribution is audit-only. Deleting a credential ownership
	// boundary remains a workspace-administration action; the store separately
	// rejects a namespace which still owns an account.
	return connectionNamespaceAdministrator(actor)
}

func (c *ConsoleAPI) canManageAccount(ctx context.Context, actor PlatformActor, a Account) bool {
	if connectionNamespaceAdministrator(actor) {
		return true
	}
	if actor.Role != "operator" {
		return false
	}
	if a.IsPersonal() {
		return a.OwnerSubject != "" && a.OwnerSubject == actor.UserID
	}
	store, ok := c.connectionNamespaceStore()
	if !ok || a.ConnectionNamespaceID == "" {
		return false
	}
	ns, ok := store.ConnectionNamespace(ctx, a.ConnectionNamespaceID)
	return ok && connectionNamespaceManager(ns, actor.UserID)
}

// canReadAccount is intentionally the same boundary as management for now.
// The console contains token/auth state and upstream URLs, which are not safe
// to disclose merely because someone may call a shared MCP endpoint.
func (c *ConsoleAPI) canReadAccount(ctx context.Context, actor PlatformActor, a Account) bool {
	return c.canManageAccount(ctx, actor, a)
}

func (c *ConsoleAPI) toConnectionNamespaceDTO(actor PlatformActor, ns ConnectionNamespace) connectionNamespaceDTO {
	dto := connectionNamespaceDTO{
		ID:                  ns.ID,
		Slug:                ns.Slug,
		Label:               ns.Label,
		Revision:            ns.Revision,
		CanManage:           c.canManageConnectionNamespace(actor, ns),
		CanManageMembership: c.canManageConnectionNamespaceMembership(actor),
		CanDelete:           c.canDeleteConnectionNamespace(actor, ns),
	}
	if !ns.CreatedAt.IsZero() {
		dto.CreatedAt = ns.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !ns.UpdatedAt.IsZero() {
		dto.UpdatedAt = ns.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	if connectionNamespaceAdministrator(actor) {
		dto.CreatedBy = ns.CreatedBy
		dto.Managers = make([]string, 0, len(ns.ManagerGrants))
		for _, grant := range ns.ManagerGrants {
			dto.Managers = append(dto.Managers, grant.Subject)
		}
	}
	return dto
}

func (c *ConsoleAPI) requireConnectionNamespaceActor(w http.ResponseWriter, r *http.Request) (PlatformActor, bool) {
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace access is not permitted"})
	}
	return actor, ok
}

func (c *ConsoleAPI) requireConnectionNamespaceAdministrator(w http.ResponseWriter, r *http.Request) (PlatformActor, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return PlatformActor{}, false
	}
	if !connectionNamespaceAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required"})
		return PlatformActor{}, false
	}
	return actor, true
}

// managedAccount returns a credential only after the signed actor boundary is
// checked against the account's durable ownership namespace. Deliberately use
// a 404 for an ungranted account: an operator should not be able to enumerate
// another folder's account keys simply by probing console routes.
func (c *ConsoleAPI) managedAccount(w http.ResponseWriter, r *http.Request, id string) (Account, PlatformActor, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return Account{}, PlatformActor{}, false
	}
	a, found := c.store.Account(id)
	if !found || !c.canManageAccount(r.Context(), actor, a) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return Account{}, PlatformActor{}, false
	}
	return a, actor, true
}

func (c *ConsoleAPI) readableAccount(w http.ResponseWriter, r *http.Request, id string) (Account, PlatformActor, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return Account{}, PlatformActor{}, false
	}
	a, found := c.store.Account(id)
	if !found || !c.canReadAccount(r.Context(), actor, a) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return Account{}, PlatformActor{}, false
	}
	return a, actor, true
}

func (c *ConsoleAPI) visibleCall(ctx context.Context, actor PlatformActor, call CallRecord) bool {
	if connectionNamespaceAdministrator(actor) {
		return true
	}
	if actor.Role != "operator" || strings.TrimSpace(call.Account) == "" {
		return false
	}
	a, found := c.store.Account(call.Account)
	return found && c.canReadAccount(ctx, actor, a)
}

func (c *ConsoleAPI) visibleApproval(ctx context.Context, actor PlatformActor, call PendingCall) bool {
	if connectionNamespaceAdministrator(actor) {
		return true
	}
	if actor.Role != "operator" || strings.TrimSpace(call.Account) == "" {
		return false
	}
	a, found := c.store.Account(call.Account)
	return found && c.canManageAccount(ctx, actor, a)
}

// visibleCallRecord loads a flight-recorder row only after checking the
// caller's namespace boundary.  The record can include request/result payloads
// and upstream errors, so a caller must never be able to probe another
// namespace through an otherwise-valid numeric audit ID.
func (c *ConsoleAPI) visibleCallRecord(w http.ResponseWriter, r *http.Request, id int64) (CallRecord, PlatformActor, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return CallRecord{}, PlatformActor{}, false
	}
	record, found, err := c.gw.CallDetail(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "call record unavailable"})
		return CallRecord{}, PlatformActor{}, false
	}
	if !found || !c.visibleCall(r.Context(), actor, record) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "call not found"})
		return CallRecord{}, PlatformActor{}, false
	}
	return record, actor, true
}

// managedApprovalRecord is the durable approval counterpart to
// visibleCallRecord.  Deciding a parked call may release a mutating upstream
// request, so a namespace manager may decide only calls made through an
// account they are allowed to manage.
func (c *ConsoleAPI) managedApprovalRecord(w http.ResponseWriter, r *http.Request, id string) (PendingCall, PlatformActor, bool) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return PendingCall{}, PlatformActor{}, false
	}
	lifecycle, ok := c.apprLog.(ApprovalLifecycle)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "durable approvals are not supported by this store"})
		return PendingCall{}, PlatformActor{}, false
	}
	call, found, err := lifecycle.ApprovalCall(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "approval record unavailable"})
		return PendingCall{}, PlatformActor{}, false
	}
	if !found || !c.visibleApproval(r.Context(), actor, call) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pending call not found"})
		return PendingCall{}, PlatformActor{}, false
	}
	return call, actor, true
}

func connectionNamespaceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrConnectionNamespaceNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection namespace not found"})
	case errors.Is(err, ErrConnectionNamespaceRevision):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "connection namespace changed; refresh and try again"})
	case errors.Is(err, ErrConnectionNamespaceExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a connection namespace with that identifier already exists"})
	case errors.Is(err, ErrConnectionNamespaceInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "move or delete its connections before deleting this namespace"})
	default:
		// Store/provider errors may contain database or infrastructure detail;
		// never turn them into a browser-visible management API response.
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "connection namespace operation failed"})
	}
}

var (
	errConnectionNamespaceAccess    = errors.New("connection namespace access is not permitted")
	errConnectionNamespaceAmbiguous = errors.New("connection namespace label is ambiguous")
)

// resolveManagedConnectionNamespace accepts the durable ID used by current
// clients and a narrow label fallback for rolling upgrades from the former
// Group-only console. Labels are never an authorization key: after resolving
// one, the signed actor must still be a manager. Only a workspace
// administrator may mint a new shared folder from a legacy label. An invited
// operator receives a Personal folder through defaultPersonalConnectionNamespace
// instead; they must use a durable ID for a folder an administrator explicitly
// delegated to them.
func (c *ConsoleAPI) resolveManagedConnectionNamespace(
	ctx context.Context,
	actor PlatformActor,
	id string,
	legacyLabel string,
	createIfMissing bool,
) (ConnectionNamespace, error) {
	store, ok := c.connectionNamespaceStore()
	if !ok {
		return ConnectionNamespace{}, errors.New("connection namespaces are not supported by this store")
	}
	id = strings.TrimSpace(id)
	legacyLabel = strings.TrimSpace(legacyLabel)
	if id != "" {
		ns, found := store.ConnectionNamespace(ctx, id)
		if !found {
			return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
		}
		if legacyLabel != "" && !strings.EqualFold(legacyLabel, ns.Label) {
			return ConnectionNamespace{}, errConnectionNamespaceAmbiguous
		}
		if !c.canManageConnectionNamespace(actor, ns) {
			return ConnectionNamespace{}, errConnectionNamespaceAccess
		}
		return ns, nil
	}
	if legacyLabel == "" {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	namespaces, err := store.ConnectionNamespaces(ctx)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	var match *ConnectionNamespace
	for _, ns := range namespaces {
		if !strings.EqualFold(strings.TrimSpace(ns.Label), legacyLabel) {
			continue
		}
		if match != nil {
			return ConnectionNamespace{}, errConnectionNamespaceAmbiguous
		}
		copy := ns
		match = &copy
	}
	if match != nil {
		if !c.canManageConnectionNamespace(actor, *match) {
			return ConnectionNamespace{}, errConnectionNamespaceAccess
		}
		return *match, nil
	}
	if !createIfMissing || !connectionNamespaceAdministrator(actor) {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	return store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label:     legacyLabel,
		CreatedBy: actor.UserID,
	})
}

// defaultPersonalConnectionNamespace gives an invited operator a safe place to
// start without making them type or guess a workspace-owned folder.  It is a
// credential folder, not an MCP endpoint: the resulting personal account
// remains absent from all shared delivery surfaces until an administrator
// deliberately promotes it.
func (c *ConsoleAPI) defaultPersonalConnectionNamespace(ctx context.Context, actor PlatformActor) (ConnectionNamespace, error) {
	store, ok := c.connectionNamespaceStore()
	if !ok {
		return ConnectionNamespace{}, errors.New("connection namespaces are not supported by this store")
	}
	namespaces, err := store.ConnectionNamespaces(ctx)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	for _, ns := range namespaces {
		if strings.EqualFold(strings.TrimSpace(ns.Label), "Personal") &&
			c.canManageConnectionNamespace(actor, ns) {
			return ns, nil
		}
	}
	return store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		// The opaque random suffix makes "Personal" safe for many different
		// users while the human-facing label remains simple.  The namespace ID,
		// rather than this slug or label, is the API authority key.
		Slug:      "personal-" + newEpoch(),
		Label:     "Personal",
		CreatedBy: actor.UserID,
	})
}

func writeConnectionNamespaceResolutionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errConnectionNamespaceAccess):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace access is not permitted"})
	case errors.Is(err, errConnectionNamespaceAmbiguous):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "connection namespace label is ambiguous; select it by ID"})
	case strings.Contains(err.Error(), "not supported"):
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connection namespaces are not supported by this store"})
	default:
		connectionNamespaceError(w, err)
	}
}

func (c *ConsoleAPI) handleConnectionNamespaces(w http.ResponseWriter, r *http.Request) {
	store, ok := c.connectionNamespacesSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		namespaces, err := store.ConnectionNamespaces(r.Context())
		if err != nil {
			connectionNamespaceError(w, err)
			return
		}
		out := make([]connectionNamespaceDTO, 0, len(namespaces))
		for _, ns := range namespaces {
			if c.canReadConnectionNamespace(actor, ns) {
				out = append(out, c.toConnectionNamespaceDTO(actor, ns))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		c.createConnectionNamespace(w, r, store, actor)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) createConnectionNamespace(w http.ResponseWriter, r *http.Request, store ConnectionNamespaceStore, actor PlatformActor) {
	if !connectionNamespaceAdministrator(actor) {
		// An operator's automatic Personal folder is intentionally created only
		// by defaultPersonalConnectionNamespace. Creating any other folder here
		// would make the operator its manager and let them manufacture a new
		// shared/root-exposed authority boundary without an admin delegation.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required to create shared connection namespaces"})
		return
	}
	var request struct {
		Label    string   `json:"label"`
		Slug     string   `json:"slug"`
		Managers []string `json:"managers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	label := strings.TrimSpace(request.Label)
	if label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
		return
	}
	grants := make([]ConnectionNamespaceManagerGrant, 0, len(request.Managers))
	if len(request.Managers) > 0 && !connectionNamespaceAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only a workspace administrator may grant namespace access"})
		return
	}
	for _, subject := range request.Managers {
		if subject = strings.TrimSpace(subject); subject != "" {
			grants = append(grants, ConnectionNamespaceManagerGrant{Subject: subject})
		}
	}
	ns, err := store.CreateConnectionNamespace(r.Context(), ConnectionNamespace{
		Slug:          strings.TrimSpace(request.Slug),
		Label:         label,
		CreatedBy:     actor.UserID,
		ManagerGrants: grants,
	})
	if err != nil {
		connectionNamespaceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c.toConnectionNamespaceDTO(actor, ns))
}

func (c *ConsoleAPI) handleConnectionNamespaceByID(w http.ResponseWriter, r *http.Request) {
	store, ok := c.connectionNamespacesSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	ns, found := store.ConnectionNamespace(r.Context(), id)
	if !found || !c.canReadConnectionNamespace(actor, ns) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection namespace not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, c.toConnectionNamespaceDTO(actor, ns))
	case http.MethodPatch:
		c.updateConnectionNamespace(w, r, store, actor, ns)
	case http.MethodDelete:
		c.deleteConnectionNamespace(w, r, store, actor, ns)
	default:
		w.Header().Set("Allow", "GET, PATCH, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) updateConnectionNamespace(w http.ResponseWriter, r *http.Request, store ConnectionNamespaceStore, actor PlatformActor, current ConnectionNamespace) {
	if !c.canManageConnectionNamespace(actor, current) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace management is not permitted"})
		return
	}
	var request struct {
		Label    string `json:"label"`
		Revision int64  `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(request.Label) == "" || request.Revision < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label and revision are required"})
		return
	}
	current.Label = strings.TrimSpace(request.Label)
	updated, err := store.UpdateConnectionNamespace(r.Context(), current, ConnectionNamespacePrecondition{
		ID: current.ID, Revision: request.Revision,
	})
	if err != nil {
		connectionNamespaceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.toConnectionNamespaceDTO(actor, updated))
}

func (c *ConsoleAPI) deleteConnectionNamespace(w http.ResponseWriter, r *http.Request, store ConnectionNamespaceStore, actor PlatformActor, current ConnectionNamespace) {
	if !c.canDeleteConnectionNamespace(actor, current) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace deletion is not permitted"})
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if request.Revision < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision is required"})
		return
	}
	if err := store.DeleteConnectionNamespace(r.Context(), current.ID, ConnectionNamespacePrecondition{
		ID: current.ID, Revision: request.Revision,
	}); err != nil {
		connectionNamespaceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ConsoleAPI) handleConnectionNamespaceManagers(w http.ResponseWriter, r *http.Request) {
	store, ok := c.connectionNamespacesSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if !c.canManageConnectionNamespaceMembership(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace membership management is not permitted"})
		return
	}
	ns, found := store.ConnectionNamespace(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection namespace not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, c.toConnectionNamespaceDTO(actor, ns))
	case http.MethodPut:
		var request struct {
			Revision int64    `json:"revision"`
			Managers []string `json:"managers"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if request.Revision < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision is required"})
			return
		}
		managers := make([]ConnectionNamespaceManagerGrant, 0, len(request.Managers))
		for _, subject := range request.Managers {
			if subject = strings.TrimSpace(subject); subject != "" {
				managers = append(managers, ConnectionNamespaceManagerGrant{Subject: subject})
			}
		}
		updated, err := store.SetConnectionNamespaceManagers(r.Context(), ns.ID, managers, ConnectionNamespacePrecondition{ID: ns.ID, Revision: request.Revision})
		if err != nil {
			connectionNamespaceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c.toConnectionNamespaceDTO(actor, updated))
	default:
		w.Header().Set("Allow", "GET, PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleConnectionNamespaceManagerBySubject(w http.ResponseWriter, r *http.Request) {
	store, ok := c.connectionNamespacesSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if !c.canManageConnectionNamespaceMembership(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "connection namespace membership management is not permitted"})
		return
	}
	ns, found := store.ConnectionNamespace(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection namespace not found"})
		return
	}
	subject := strings.TrimSpace(r.PathValue("subject"))
	if subject == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "manager subject is required"})
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if request.Revision < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision is required"})
		return
	}
	managers := append([]ConnectionNamespaceManagerGrant(nil), ns.ManagerGrants...)
	switch r.Method {
	case http.MethodPut:
		present := false
		for _, grant := range managers {
			if grant.Subject == subject {
				present = true
				break
			}
		}
		if !present {
			managers = append(managers, ConnectionNamespaceManagerGrant{Subject: subject})
		}
	case http.MethodDelete:
		kept := managers[:0]
		for _, grant := range managers {
			if grant.Subject != subject {
				kept = append(kept, grant)
			}
		}
		managers = kept
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	updated, err := store.SetConnectionNamespaceManagers(r.Context(), ns.ID, managers, ConnectionNamespacePrecondition{ID: ns.ID, Revision: request.Revision})
	if err != nil {
		connectionNamespaceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.toConnectionNamespaceDTO(actor, updated))
}
