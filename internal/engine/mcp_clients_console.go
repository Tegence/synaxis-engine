package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// mcpClientDTO intentionally leaves out Epoch and OAuthClientID. Neither is a
// browser-management field: Epoch is a token-generation value and the OAuth
// ID is consumed by the signed consent/DCR path. The console gets the
// useful status signal without becoming a second credential-binding surface.
type mcpClientDTO struct {
	ID                           string                      `json:"id"`
	Slug                         string                      `json:"slug"`
	Name                         string                      `json:"name"`
	Subject                      string                      `json:"subject"`
	Kind                         MCPClientKind               `json:"kind"` // "interactive" or "workload"; fixed at creation
	ConnectionNamespaceIDs       []string                    `json:"connectionNamespaceIds"`
	Status                       MCPClientStatus             `json:"status"`
	OAuthBound                   bool                        `json:"oauthBound"`
	RuntimeAttestationConfigured bool                        `json:"runtimeAttestationConfigured"`
	AgentProfileBinding          *mcpClientProfileBindingDTO `json:"agentProfileBinding,omitempty"`
	Revision                     int64                       `json:"revision"`
	CreatedAt                    string                      `json:"createdAt,omitempty"`
	UpdatedAt                    string                      `json:"updatedAt,omitempty"`
	RevokedAt                    string                      `json:"revokedAt,omitempty"`
	CanManage                    bool                        `json:"canManage"`
}

// mcpClientProfileBindingDTO mirrors the opaque stored reference exactly. It
// is informational: the Engine never interprets the policy behind it.
type mcpClientProfileBindingDTO struct {
	ProfileID       string `json:"profileId"`
	ProfileRevision int64  `json:"profileRevision"`
	PolicyDigest    string `json:"policyDigest"`
	BoundAt         string `json:"boundAt"`
}

// consoleFailure is a wire-independent management failure. The self-hosted
// /api surface serializes it as {"error": message}; /control/v1 serializes
// RFC 9457 problem details carrying the stable code. Keeping one failure
// value lets both surfaces share handler logic without duplicating the
// authorization and validation decisions.
type consoleFailure struct {
	status  int
	code    string
	message string
}

func (f *consoleFailure) Error() string { return f.message }

func newConsoleFailure(status int, code, message string) *consoleFailure {
	return &consoleFailure{status: status, code: code, message: message}
}

// consoleWire selects the response dialect (and the v1 idempotency
// conveniences) for a shared management handler.
type consoleWire struct {
	control bool
}

var (
	apiWire     = consoleWire{}
	controlWire = consoleWire{control: true}
)

func (wire consoleWire) writeFailure(w http.ResponseWriter, failure *consoleFailure) {
	if wire.control {
		writeControlProblem(w, failure.status, failure.code, failure.message)
		return
	}
	writeJSON(w, failure.status, map[string]string{"error": failure.message})
}

func (wire consoleWire) writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	if wire.control {
		writeControlProblem(w, http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable, "method not allowed")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// decodeJSON keeps the lenient console decoder shared by both surfaces: a
// caller may send fields the Engine does not know so an older Engine keeps
// accepting a newer control plane's bodies.
func (wire consoleWire) decodeJSON(w http.ResponseWriter, r *http.Request, destination any) *consoleFailure {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(destination); err != nil {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid JSON body")
	}
	return nil
}

func (c *ConsoleAPI) mcpClientStore() (MCPClientStore, bool) {
	store, ok := c.store.(MCPClientStore)
	return store, ok
}

func (c *ConsoleAPI) mcpClientSkillAuthoringStore() (LibraryMCPClientSkillAuthoringStore, bool) {
	store, ok := c.store.(LibraryMCPClientSkillAuthoringStore)
	return store, ok
}

// refreshMCPClientProjection is intentionally best-effort after a durable
// write. Registry reads fail closed even if a Main-owned handler refresh is
// momentarily unavailable, and the next mutation/startup refresh retries it;
// returning an error after persistence would invite a browser to duplicate a
// client registration that already succeeded.
func (c *ConsoleAPI) refreshMCPClientProjection(ctx context.Context) {
	if c.gw != nil {
		_ = c.gw.RefreshMCPClients(ctx)
	}
}

func (c *ConsoleAPI) mcpClientsSupported(w http.ResponseWriter) (MCPClientStore, bool) {
	store, ok := c.mcpClientStore()
	if ok {
		return store, true
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "MCP client registry is not supported by this store",
	})
	return nil, false
}

func mcpClientRegistryAdministrator(actor PlatformActor) bool {
	return connectionNamespaceAdministrator(actor)
}

// Unlike ordinary MCP-client registration, a temporary skill authoring lease
// is owner/admin-only. In particular, service and operator roles must not be
// able to mint an authoring window for a client credential they can manage.
func mcpClientSkillAuthoringAdministrator(actor PlatformActor) bool {
	return actor.Role == "owner" || actor.Role == "admin"
}

// mcpClientWorkloadAdministrator gates creating a workload client: an owner
// or admin (the self-hosted local admin acts as owner). Unlike
// mcpClientRegistryAdministrator it excludes the service principal, which may
// mint a workload client's tokens but never define one.
func mcpClientWorkloadAdministrator(actor PlatformActor) bool {
	return actor.Role == "owner" || actor.Role == "admin"
}

func canReadMCPClient(actor PlatformActor, client MCPClient) bool {
	if mcpClientRegistryAdministrator(actor) {
		return true
	}
	return actor.Role == "operator" && actor.UserID != "" && actor.UserID == client.Subject
}

func canManageMCPClient(actor PlatformActor, client MCPClient) bool {
	return canReadMCPClient(actor, client)
}

func (c *ConsoleAPI) toMCPClientDTO(actor PlatformActor, client MCPClient) mcpClientDTO {
	dto := mcpClientDTO{
		ID:                           client.ID,
		Slug:                         client.Slug,
		Name:                         client.Name,
		Subject:                      client.Subject,
		Kind:                         mcpClientKind(client),
		ConnectionNamespaceIDs:       append([]string(nil), client.ConnectionNamespaceIDs...),
		Status:                       client.Status,
		OAuthBound:                   client.OAuthClientID != "",
		RuntimeAttestationConfigured: client.RuntimeAttestorPublicKey != "",
		Revision:                     client.Revision,
		CanManage:                    canManageMCPClient(actor, client),
	}
	if !client.CreatedAt.IsZero() {
		dto.CreatedAt = client.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !client.UpdatedAt.IsZero() {
		dto.UpdatedAt = client.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	if client.RevokedAt != nil && !client.RevokedAt.IsZero() {
		dto.RevokedAt = client.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	if binding := client.AgentProfileBinding; binding != nil {
		dto.AgentProfileBinding = &mcpClientProfileBindingDTO{
			ProfileID:       binding.ProfileID,
			ProfileRevision: binding.ProfileRevision,
			PolicyDigest:    binding.PolicyDigest,
			BoundAt:         binding.BoundAt.UTC().Format(time.RFC3339Nano),
		}
	}
	return dto
}

// mcpClientFailure maps registry errors to one status/code/message triple so
// the self-hosted console and the versioned control contract cannot drift.
func mcpClientFailure(err error) *consoleFailure {
	switch {
	case errors.Is(err, ErrMCPClientNotFound):
		return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "MCP client not found")
	case errors.Is(err, ErrMCPClientRevision):
		return newConsoleFailure(http.StatusConflict, controlCodeRevisionMismatch, "MCP client changed; refresh and try again")
	case errors.Is(err, ErrMCPClientRevoked):
		return newConsoleFailure(http.StatusConflict, controlCodeClientRevoked, "MCP client is revoked")
	case errors.Is(err, ErrMCPClientOAuthBinding):
		return newConsoleFailure(http.StatusConflict, controlCodeAlreadyExists, "OAuth client binding is unavailable")
	case errors.Is(err, ErrMCPClientLimit), errors.Is(err, ErrMCPClientNamespaceLimit):
		return newConsoleFailure(http.StatusTooManyRequests, controlCodeCapacityLimited, "MCP client capacity limit reached")
	case errors.Is(err, ErrMCPClientNamespaceSubject):
		return newConsoleFailure(http.StatusUnprocessableEntity, controlCodeValidationFailed, "the selected namespace contains a personal connection for another member")
	case errors.Is(err, ErrConnectionNamespaceNotFound):
		// Keep a folder identifier from becoming an enumeration oracle.
		return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "connection namespace not found")
	case errors.Is(err, ErrMCPClientProfileBindingConflict):
		return newConsoleFailure(http.StatusConflict, controlCodeProfileBindingConflict, "MCP client is bound to a different agent profile; pass replace to rebind")
	case errors.Is(err, ErrMCPClientKind):
		// An operation refused for the client's kind reads exactly like an
		// unknown client, so a kind-specific route is not a kind oracle.
		return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "MCP client not found")
	case errors.Is(err, ErrMCPClientWorkloadBinding):
		return newConsoleFailure(http.StatusConflict, controlCodeWorkloadBindingConflict, "workload MCP client is bound to a different OAuth identity; reset its OAuth client first")
	case errors.Is(err, ErrInvalidMCPClient):
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid MCP client")
	default:
		return newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "MCP client registry is unavailable")
	}
}

func mcpClientError(w http.ResponseWriter, err error) {
	apiWire.writeFailure(w, mcpClientFailure(err))
}

// validateMCPClientNamespaceAccess checks both actor authority and personal
// connection ownership before the store writes a grant. The store repeats the
// invariant transactionally, so a direct/internal caller cannot bypass it.
func (c *ConsoleAPI) validateMCPClientNamespaceAccess(ctx context.Context, actor PlatformActor, subject string, namespaceIDs []string) error {
	store, ok := c.connectionNamespaceStore()
	if !ok {
		return errors.New("connection namespaces are not supported by this store")
	}
	for _, namespaceID := range namespaceIDs {
		namespace, found := store.ConnectionNamespace(ctx, namespaceID)
		if !found || !c.canManageConnectionNamespace(actor, namespace) {
			return ErrConnectionNamespaceNotFound
		}
		for _, account := range c.store.Accounts() {
			if account.ConnectionNamespaceID == namespace.ID && account.IsPersonal() && account.OwnerSubject != subject {
				return ErrMCPClientNamespaceSubject
			}
		}
	}
	return nil
}

func mcpClientNamespaceAccessFailure(err error) *consoleFailure {
	if strings.Contains(err.Error(), "not supported") {
		return newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "connection namespaces are not supported by this store")
	}
	return mcpClientFailure(err)
}

// mcpClientManagement resolves the registry facet, the verified actor, and
// the shared role gate for every registry route on both wire surfaces. The
// order (facet, actor, role) is the historical /api order and is preserved so
// existing callers observe identical statuses.
func (c *ConsoleAPI) mcpClientManagement(r *http.Request) (MCPClientStore, PlatformActor, *consoleFailure) {
	store, ok := c.mcpClientStore()
	if !ok {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "MCP client registry is not supported by this store")
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connection namespace access is not permitted")
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "MCP client management is not permitted")
	}
	return store, actor, nil
}

// mcpClientAdministration is the narrower owner/admin/service gate used by
// the profile-binding and activation-snapshot routes. An operator may manage
// its own registration but never installs the policy reference it runs under.
func (c *ConsoleAPI) mcpClientAdministration(r *http.Request) (MCPClientStore, PlatformActor, *consoleFailure) {
	store, ok := c.mcpClientStore()
	if !ok {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "MCP client registry is not supported by this store")
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connection namespace access is not permitted")
	}
	if !mcpClientRegistryAdministrator(actor) {
		return nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "MCP client administration requires a workspace owner, admin, or the Platform service")
	}
	return store, actor, nil
}

func (c *ConsoleAPI) handleMCPClients(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClients(w, r, apiWire)
}

func (c *ConsoleAPI) serveMCPClients(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	switch r.Method {
	case http.MethodGet:
		clients, err := store.MCPClients(r.Context())
		if err != nil {
			wire.writeFailure(w, mcpClientFailure(err))
			return
		}
		out := make([]mcpClientDTO, 0, len(clients))
		for _, client := range clients {
			if canReadMCPClient(actor, client) {
				out = append(out, c.toMCPClientDTO(actor, client))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		c.createMCPClient(w, r, wire, store, actor)
	default:
		wire.writeMethodNotAllowed(w, "GET, POST")
	}
}

func (c *ConsoleAPI) createMCPClient(w http.ResponseWriter, r *http.Request, wire consoleWire, store MCPClientStore, actor PlatformActor) {
	var request struct {
		Name                     string        `json:"name"`
		Slug                     string        `json:"slug"`
		Subject                  string        `json:"subject"`
		Kind                     MCPClientKind `json:"kind"`
		ConnectionNamespaceIDs   []string      `json:"connectionNamespaceIds"`
		RuntimeAttestorPublicKey string        `json:"runtimeAttestorPublicKey"`
	}
	if failure := wire.decodeJSON(w, r, &request); failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	kind, err := normalizeMCPClientKind(request.Kind)
	if err != nil {
		wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, `kind must be "interactive" or "workload"`))
		return
	}
	if kind == MCPClientKindWorkload {
		// A workload client's tokens are brokered by the control plane with no
		// consent step, so creating one is a workspace-administration act.
		if !mcpClientWorkloadAdministrator(actor) {
			wire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "workload MCP clients require a workspace owner or admin"))
			return
		}
		// Its subject is the non-human principal the control plane names; it
		// never defaults to the creating member.
		if strings.TrimSpace(request.Subject) == "" {
			wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "a workload MCP client requires an explicit subject"))
			return
		}
	}
	subject := strings.TrimSpace(request.Subject)
	if subject == "" {
		subject = actor.UserID
	}
	if actor.Role == "operator" && subject != actor.UserID {
		wire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "operators may register only their own MCP clients"))
		return
	}
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(request.ConnectionNamespaceIDs)
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	if err := c.validateMCPClientNamespaceAccess(r.Context(), actor, subject, namespaceIDs); err != nil {
		wire.writeFailure(w, mcpClientNamespaceAccessFailure(err))
		return
	}
	name := strings.TrimSpace(request.Name)
	if wire.control {
		// The control contract treats the caller-chosen slug as a natural key:
		// a retried create whose body matches the stored active registration
		// converges on it, and a disagreeing body is a conflict rather than a
		// silently suffixed second client.
		if slug := normalizeMCPClientSlug(request.Slug); slug != "" {
			if existing, found := store.MCPClientBySlug(r.Context(), slug); found && existing.Status == MCPClientStatusActive {
				if canReadMCPClient(actor, existing) && existing.Name == name && existing.Subject == subject && mcpClientKind(existing) == kind &&
					sameStrings(existing.ConnectionNamespaceIDs, namespaceIDs) && existing.RuntimeAttestorPublicKey == request.RuntimeAttestorPublicKey {
					writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, existing))
					return
				}
				wire.writeFailure(w, newConsoleFailure(http.StatusConflict, controlCodeAlreadyExists, "an MCP client with this slug already exists with a different definition"))
				return
			}
		}
	}
	client, err := store.CreateMCPClient(r.Context(), MCPClient{
		Name:                   name,
		Slug:                   strings.TrimSpace(request.Slug),
		Subject:                subject,
		Kind:                   kind,
		ConnectionNamespaceIDs: namespaceIDs,
		// Keep the key byte-for-byte so the core canonical-key validator rejects
		// accidental whitespace instead of silently configuring a different
		// attestor identity.
		RuntimeAttestorPublicKey: request.RuntimeAttestorPublicKey,
		CreatedBy:                actor.UserID,
	})
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusCreated, c.toMCPClientDTO(actor, client))
}

func (c *ConsoleAPI) mcpClientForManagement(w http.ResponseWriter, r *http.Request, store MCPClientStore, actor PlatformActor) (MCPClient, bool) {
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		apiWire.writeFailure(w, failure)
		return MCPClient{}, false
	}
	return client, true
}

// managedMCPClient resolves the {id} path value with the same 404-on-unreadable
// posture on both surfaces so a guessed identifier reveals nothing.
func (c *ConsoleAPI) managedMCPClient(r *http.Request, store MCPClientStore, actor PlatformActor) (MCPClient, *consoleFailure) {
	client, found := store.MCPClient(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found || !canReadMCPClient(actor, client) {
		return MCPClient{}, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "MCP client not found")
	}
	return client, nil
}

func (c *ConsoleAPI) handleMCPClientByID(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientByID(w, r, apiWire)
}

func (c *ConsoleAPI) serveMCPClientByID(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, client))
	case http.MethodPatch:
		var request struct {
			Name                     string         `json:"name"`
			Revision                 int64          `json:"revision"`
			RuntimeAttestorPublicKey *string        `json:"runtimeAttestorPublicKey"`
			Kind                     *MCPClientKind `json:"kind"`
		}
		if failure := wire.decodeJSON(w, r, &request); failure != nil {
			wire.writeFailure(w, failure)
			return
		}
		if strings.TrimSpace(request.Name) == "" || request.Revision < 1 {
			wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "name and revision are required"))
			return
		}
		update := MCPClient{ID: client.ID, Name: strings.TrimSpace(request.Name)}
		if request.Kind != nil {
			// Kind is fixed at creation. Echoing the current kind is harmless;
			// asking for another is refused rather than silently ignored.
			kind, err := normalizeMCPClientKind(*request.Kind)
			if err != nil || kind != mcpClientKind(client) {
				wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "kind is immutable"))
				return
			}
			update.Kind = kind
		}
		if request.RuntimeAttestorPublicKey != nil {
			update.RuntimeAttestorPublicKey = *request.RuntimeAttestorPublicKey
			update.runtimeAttestorKeySet = true
		}
		updated, err := store.UpdateMCPClient(r.Context(), update, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
		if err != nil {
			wire.writeFailure(w, mcpClientFailure(err))
			return
		}
		c.refreshMCPClientProjection(r.Context())
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
	default:
		wire.writeMethodNotAllowed(w, "GET, PATCH")
	}
}

func (c *ConsoleAPI) handleMCPClientNamespaces(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientNamespaces(w, r, apiWire)
}

func (c *ConsoleAPI) serveMCPClientNamespaces(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPut {
		wire.writeMethodNotAllowed(w, "PUT")
		return
	}
	var request struct {
		ConnectionNamespaceIDs []string `json:"connectionNamespaceIds"`
		Revision               int64    `json:"revision"`
	}
	if failure := wire.decodeJSON(w, r, &request); failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if request.Revision < 1 {
		wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "revision is required"))
		return
	}
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(request.ConnectionNamespaceIDs)
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	if err := c.validateMCPClientNamespaceAccess(r.Context(), actor, client.Subject, namespaceIDs); err != nil {
		wire.writeFailure(w, mcpClientNamespaceAccessFailure(err))
		return
	}
	updated, err := store.SetMCPClientNamespaces(r.Context(), client.ID, namespaceIDs, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
}

func (c *ConsoleAPI) handleMCPClientRevoke(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientRevoke(w, r, apiWire)
}

func (c *ConsoleAPI) serveMCPClientRevoke(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPost {
		wire.writeMethodNotAllowed(w, "POST")
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if failure := wire.decodeJSON(w, r, &request); failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if request.Revision < 1 {
		wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "revision is required"))
		return
	}
	if wire.control && client.Status == MCPClientStatusRevoked {
		// Revocation is terminal, so a repeated revoke converges on the stored
		// record regardless of which revision the retry carried.
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, client))
		return
	}
	revoked, err := store.RevokeMCPClient(r.Context(), client.ID, actor.UserID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, revoked))
}

// handleMCPClientOAuthReset is a deliberate reconnect boundary. It is kept
// separate from PATCH so a stale browser cannot accidentally replace a DCR
// identity while renaming a client; callers must present the current revision
// and then complete a fresh signed OAuth bind.
func (c *ConsoleAPI) handleMCPClientOAuthReset(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientOAuthReset(w, r, apiWire)
}

func (c *ConsoleAPI) serveMCPClientOAuthReset(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPost {
		wire.writeMethodNotAllowed(w, "POST")
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if failure := wire.decodeJSON(w, r, &request); failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if request.Revision < 1 {
		wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "revision is required"))
		return
	}
	updated, err := store.ResetMCPClientOAuthClient(r.Context(), client.ID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		wire.writeFailure(w, mcpClientFailure(err))
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
}

// serveMCPClientProfileBinding installs or clears the opaque Agent Access
// Profile reference. It is exposed only on /control/v1: the reference is a
// hosting control plane's fact about the client, not a self-hosted console
// concept, and the Engine never interprets the policy it names.
func (c *ConsoleAPI) serveMCPClientProfileBinding(w http.ResponseWriter, r *http.Request, wire consoleWire) {
	store, actor, failure := c.mcpClientAdministration(r)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var request struct {
			Revision        int64  `json:"revision"`
			ProfileID       string `json:"profileId"`
			ProfileRevision int64  `json:"profileRevision"`
			PolicyDigest    string `json:"policyDigest"`
			Replace         bool   `json:"replace"`
		}
		if failure := wire.decodeJSON(w, r, &request); failure != nil {
			wire.writeFailure(w, failure)
			return
		}
		if request.Revision < 1 {
			wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "revision is required"))
			return
		}
		binding, err := normalizeMCPClientProfileBinding(MCPClientProfileBinding{
			ProfileID: request.ProfileID, ProfileRevision: request.ProfileRevision, PolicyDigest: request.PolicyDigest,
		})
		if err != nil {
			wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "profileId, profileRevision, and a SHA-256 policyDigest are required"))
			return
		}
		if current := client.AgentProfileBinding; current != nil && current.ProfileID != binding.ProfileID && !request.Replace {
			// The revision fence makes this check race-safe: a concurrent bind
			// changes the revision, so a stale caller receives revision_mismatch
			// from the store instead of silently replacing the newer binding.
			wire.writeFailure(w, mcpClientFailure(ErrMCPClientProfileBindingConflict))
			return
		}
		bound, err := store.BindMCPClientProfile(r.Context(), MCPClientPrecondition{ID: client.ID, Revision: request.Revision}, binding)
		if err != nil {
			wire.writeFailure(w, mcpClientFailure(err))
			return
		}
		c.refreshMCPClientProjection(r.Context())
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, bound))
	case http.MethodDelete:
		var request struct {
			Revision int64 `json:"revision"`
		}
		if failure := wire.decodeJSON(w, r, &request); failure != nil {
			wire.writeFailure(w, failure)
			return
		}
		if request.Revision < 1 {
			wire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "revision is required"))
			return
		}
		unbound, err := store.UnbindMCPClientProfile(r.Context(), MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
		if err != nil {
			wire.writeFailure(w, mcpClientFailure(err))
			return
		}
		c.refreshMCPClientProjection(r.Context())
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, unbound))
	default:
		wire.writeMethodNotAllowed(w, "PUT, DELETE")
	}
}

type mcpClientSkillAuthoringLeaseDTO struct {
	LeaseID          string `json:"leaseId"`
	ClientID         string `json:"clientId"`
	Kind             string `json:"kind,omitempty"`
	SkillID          string `json:"skillId,omitempty"`
	BindingID        string `json:"bindingId,omitempty"`
	GrantedAt        string `json:"grantedAt"`
	ExpiresAt        string `json:"expiresAt"`
	RemainingCreates int    `json:"remainingCreates"`
	RemainingUploads int    `json:"remainingUploads"`
	RevokedAt        string `json:"revokedAt,omitempty"`
	Status           string `json:"status"`
}

func toMCPClientSkillAuthoringLeaseDTO(lease LibraryMCPClientSkillAuthoringLease) mcpClientSkillAuthoringLeaseDTO {
	dto := mcpClientSkillAuthoringLeaseDTO{
		LeaseID:          lease.ID,
		ClientID:         lease.MCPClientID,
		Kind:             libraryMCPClientSkillAuthoringLeaseKind(lease),
		SkillID:          lease.TargetSkillID,
		BindingID:        lease.TargetBindingID,
		GrantedAt:        lease.GrantedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:        lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RemainingCreates: lease.RemainingCreates,
		RemainingUploads: lease.RemainingUploads,
		Status:           lease.Status,
	}
	if lease.RevokedAt != nil && !lease.RevokedAt.IsZero() {
		dto.RevokedAt = lease.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	return dto
}

func (c *ConsoleAPI) mcpClientSkillAuthoringLeaseSupported(w http.ResponseWriter) (LibraryMCPClientSkillAuthoringStore, bool) {
	store, ok := c.mcpClientSkillAuthoringStore()
	if ok {
		return store, true
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "MCP client skill authoring leases are not supported by this store",
	})
	return nil, false
}

func mcpClientSkillAuthoringLeaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrMCPClientNotFound), errors.Is(err, ErrMCPClientRevision), errors.Is(err, ErrMCPClientRevoked):
		mcpClientError(w, err)
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill authoring lease not found"})
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseActive):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an active skill authoring lease must be revoked before another can be granted"})
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringClientUnavailable):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MCP client must be active and OAuth-bound"})
	case errors.Is(err, ErrLibrarySkillNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "skill changed; refresh it before delegating a temporary revision"})
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this client already has a pinned or incompatible binding for the skill"})
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "MCP client skill authoring lease is unavailable"})
	}
}

func decodeMCPClientSkillAuthoringLeaseRequest(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (c *ConsoleAPI) mcpClientForSkillAuthoringLease(w http.ResponseWriter, r *http.Request) (MCPClient, LibraryMCPClientSkillAuthoringStore, PlatformActor, bool) {
	registry, ok := c.mcpClientsSupported(w)
	if !ok {
		return MCPClient{}, nil, PlatformActor{}, false
	}
	leaseStore, ok := c.mcpClientSkillAuthoringLeaseSupported(w)
	if !ok {
		return MCPClient{}, nil, PlatformActor{}, false
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return MCPClient{}, nil, PlatformActor{}, false
	}
	if !mcpClientSkillAuthoringAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "skill authoring leases require a workspace owner or admin"})
		return MCPClient{}, nil, PlatformActor{}, false
	}
	client, ok := c.mcpClientForManagement(w, r, registry, actor)
	if !ok {
		return MCPClient{}, nil, PlatformActor{}, false
	}
	return client, leaseStore, actor, true
}

func (c *ConsoleAPI) handleMCPClientSkillAuthoringLease(w http.ResponseWriter, r *http.Request) {
	client, store, actor, ok := c.mcpClientForSkillAuthoringLease(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		lease, found, err := store.MCPClientSkillAuthoringLease(r.Context(), client.ID)
		if err != nil {
			mcpClientSkillAuthoringLeaseError(w, err)
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill authoring lease not found"})
			return
		}
		writeJSON(w, http.StatusOK, toMCPClientSkillAuthoringLeaseDTO(lease))
	case http.MethodPost:
		var request struct {
			Revision int64 `json:"revision"`
		}
		if !decodeMCPClientSkillAuthoringLeaseRequest(w, r, &request) {
			return
		}
		if request.Revision < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision is required"})
			return
		}
		lease, err := store.GrantMCPClientSkillAuthoringLease(
			r.Context(), client.ID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision}, libraryActorRef(actor),
		)
		if err != nil {
			mcpClientSkillAuthoringLeaseError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, toMCPClientSkillAuthoringLeaseDTO(lease))
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleMCPClientSkillAuthoringAdoption is intentionally a separate Console
// action from generic authoring windows and ordinary Add binding. It grants
// no credentials or generic skill-create authority: it creates/adopts one
// exact client-surface track binding plus a short, target-specific revision
// lease.
func (c *ConsoleAPI) handleMCPClientSkillAuthoringAdoption(w http.ResponseWriter, r *http.Request) {
	client, store, actor, ok := c.mcpClientForSkillAuthoringLease(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Revision              int64  `json:"revision"`
		SkillID               string `json:"skillId"`
		ExpectedVersionID     string `json:"expectedVersionId"`
		ExpectedVersionDigest string `json:"expectedVersionDigest"`
	}
	if !decodeMCPClientSkillAuthoringLeaseRequest(w, r, &request) {
		return
	}
	adoption, err := normalizeLibraryMCPClientSkillAuthoringAdoptionRequest(LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: request.SkillID, ExpectedVersionID: request.ExpectedVersionID, ExpectedVersionDigest: request.ExpectedVersionDigest,
	})
	if request.Revision < 1 || err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision, skillId, expectedVersionId, and expectedVersionDigest are required"})
		return
	}
	lease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(
		r.Context(), client.ID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision}, adoption, libraryActorRef(actor),
	)
	if err != nil {
		mcpClientSkillAuthoringLeaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toMCPClientSkillAuthoringLeaseDTO(lease))
}

func (c *ConsoleAPI) handleMCPClientSkillAuthoringLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	client, store, actor, ok := c.mcpClientForSkillAuthoringLease(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Revision int64  `json:"revision"`
		LeaseID  string `json:"leaseId"`
	}
	if !decodeMCPClientSkillAuthoringLeaseRequest(w, r, &request) {
		return
	}
	if request.Revision < 1 || validateLibraryOpaqueRef("skill authoring lease", request.LeaseID, false) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision and leaseId are required"})
		return
	}
	lease, err := store.RevokeMCPClientSkillAuthoringLease(
		r.Context(), client.ID, request.LeaseID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision}, libraryActorRef(actor),
	)
	if err != nil {
		mcpClientSkillAuthoringLeaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toMCPClientSkillAuthoringLeaseDTO(lease))
}
