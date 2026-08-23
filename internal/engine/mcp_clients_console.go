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
	ID                           string          `json:"id"`
	Slug                         string          `json:"slug"`
	Name                         string          `json:"name"`
	Subject                      string          `json:"subject"`
	ConnectionNamespaceIDs       []string        `json:"connectionNamespaceIds"`
	Status                       MCPClientStatus `json:"status"`
	OAuthBound                   bool            `json:"oauthBound"`
	RuntimeAttestationConfigured bool            `json:"runtimeAttestationConfigured"`
	Revision                     int64           `json:"revision"`
	CreatedAt                    string          `json:"createdAt,omitempty"`
	UpdatedAt                    string          `json:"updatedAt,omitempty"`
	RevokedAt                    string          `json:"revokedAt,omitempty"`
	CanManage                    bool            `json:"canManage"`
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
	return dto
}

func mcpClientError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrMCPClientNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP client not found"})
	case errors.Is(err, ErrMCPClientRevision):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MCP client changed; refresh and try again"})
	case errors.Is(err, ErrMCPClientRevoked):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MCP client is revoked"})
	case errors.Is(err, ErrMCPClientOAuthBinding):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "OAuth client binding is unavailable"})
	case errors.Is(err, ErrMCPClientLimit), errors.Is(err, ErrMCPClientNamespaceLimit):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "MCP client capacity limit reached"})
	case errors.Is(err, ErrMCPClientNamespaceSubject):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "the selected namespace contains a personal connection for another member"})
	case errors.Is(err, ErrConnectionNamespaceNotFound):
		// Keep a folder identifier from becoming an enumeration oracle.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection namespace not found"})
	case errors.Is(err, ErrInvalidMCPClient):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid MCP client"})
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "MCP client registry is unavailable"})
	}
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

func (c *ConsoleAPI) handleMCPClients(w http.ResponseWriter, r *http.Request) {
	store, ok := c.mcpClientsSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP client management is not permitted"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		clients, err := store.MCPClients(r.Context())
		if err != nil {
			mcpClientError(w, err)
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
		c.createMCPClient(w, r, store, actor)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) createMCPClient(w http.ResponseWriter, r *http.Request, store MCPClientStore, actor PlatformActor) {
	var request struct {
		Name                     string   `json:"name"`
		Slug                     string   `json:"slug"`
		Subject                  string   `json:"subject"`
		ConnectionNamespaceIDs   []string `json:"connectionNamespaceIds"`
		RuntimeAttestorPublicKey string   `json:"runtimeAttestorPublicKey"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	subject := strings.TrimSpace(request.Subject)
	if subject == "" {
		subject = actor.UserID
	}
	if actor.Role == "operator" && subject != actor.UserID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "operators may register only their own MCP clients"})
		return
	}
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(request.ConnectionNamespaceIDs)
	if err != nil {
		mcpClientError(w, err)
		return
	}
	if err := c.validateMCPClientNamespaceAccess(r.Context(), actor, subject, namespaceIDs); err != nil {
		if strings.Contains(err.Error(), "not supported") {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connection namespaces are not supported by this store"})
		} else {
			mcpClientError(w, err)
		}
		return
	}
	client, err := store.CreateMCPClient(r.Context(), MCPClient{
		Name:                   strings.TrimSpace(request.Name),
		Slug:                   strings.TrimSpace(request.Slug),
		Subject:                subject,
		ConnectionNamespaceIDs: namespaceIDs,
		// Keep the key byte-for-byte so the core canonical-key validator rejects
		// accidental whitespace instead of silently configuring a different
		// attestor identity.
		RuntimeAttestorPublicKey: request.RuntimeAttestorPublicKey,
		CreatedBy:                actor.UserID,
	})
	if err != nil {
		mcpClientError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusCreated, c.toMCPClientDTO(actor, client))
}

func (c *ConsoleAPI) mcpClientForManagement(w http.ResponseWriter, r *http.Request, store MCPClientStore, actor PlatformActor) (MCPClient, bool) {
	client, found := store.MCPClient(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found || !canReadMCPClient(actor, client) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP client not found"})
		return MCPClient{}, false
	}
	return client, true
}

func (c *ConsoleAPI) handleMCPClientByID(w http.ResponseWriter, r *http.Request) {
	store, ok := c.mcpClientsSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP client management is not permitted"})
		return
	}
	client, ok := c.mcpClientForManagement(w, r, store, actor)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, client))
	case http.MethodPatch:
		var request struct {
			Name                     string  `json:"name"`
			Revision                 int64   `json:"revision"`
			RuntimeAttestorPublicKey *string `json:"runtimeAttestorPublicKey"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if strings.TrimSpace(request.Name) == "" || request.Revision < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and revision are required"})
			return
		}
		update := MCPClient{ID: client.ID, Name: strings.TrimSpace(request.Name)}
		if request.RuntimeAttestorPublicKey != nil {
			update.RuntimeAttestorPublicKey = *request.RuntimeAttestorPublicKey
			update.runtimeAttestorKeySet = true
		}
		updated, err := store.UpdateMCPClient(r.Context(), update, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
		if err != nil {
			mcpClientError(w, err)
			return
		}
		c.refreshMCPClientProjection(r.Context())
		writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
	default:
		w.Header().Set("Allow", "GET, PATCH")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleMCPClientNamespaces(w http.ResponseWriter, r *http.Request) {
	store, ok := c.mcpClientsSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP client management is not permitted"})
		return
	}
	client, ok := c.mcpClientForManagement(w, r, store, actor)
	if !ok {
		return
	}
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		ConnectionNamespaceIDs []string `json:"connectionNamespaceIds"`
		Revision               int64    `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if request.Revision < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revision is required"})
		return
	}
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(request.ConnectionNamespaceIDs)
	if err != nil {
		mcpClientError(w, err)
		return
	}
	if err := c.validateMCPClientNamespaceAccess(r.Context(), actor, client.Subject, namespaceIDs); err != nil {
		if strings.Contains(err.Error(), "not supported") {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connection namespaces are not supported by this store"})
		} else {
			mcpClientError(w, err)
		}
		return
	}
	updated, err := store.SetMCPClientNamespaces(r.Context(), client.ID, namespaceIDs, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		mcpClientError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
}

func (c *ConsoleAPI) handleMCPClientRevoke(w http.ResponseWriter, r *http.Request) {
	store, ok := c.mcpClientsSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP client management is not permitted"})
		return
	}
	client, ok := c.mcpClientForManagement(w, r, store, actor)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
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
	revoked, err := store.RevokeMCPClient(r.Context(), client.ID, actor.UserID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		mcpClientError(w, err)
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
	store, ok := c.mcpClientsSupported(w)
	if !ok {
		return
	}
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if actor.Role != "operator" && !mcpClientRegistryAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP client management is not permitted"})
		return
	}
	client, ok := c.mcpClientForManagement(w, r, store, actor)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
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
	updated, err := store.ResetMCPClientOAuthClient(r.Context(), client.ID, MCPClientPrecondition{ID: client.ID, Revision: request.Revision})
	if err != nil {
		mcpClientError(w, err)
		return
	}
	c.refreshMCPClientProjection(r.Context())
	writeJSON(w, http.StatusOK, c.toMCPClientDTO(actor, updated))
}

type mcpClientSkillAuthoringLeaseDTO struct {
	LeaseID          string `json:"leaseId"`
	ClientID         string `json:"clientId"`
	GrantedAt        string `json:"grantedAt"`
	ExpiresAt        string `json:"expiresAt"`
	RemainingCreates int    `json:"remainingCreates"`
	RevokedAt        string `json:"revokedAt,omitempty"`
	Status           string `json:"status"`
}

func toMCPClientSkillAuthoringLeaseDTO(lease LibraryMCPClientSkillAuthoringLease) mcpClientSkillAuthoringLeaseDTO {
	dto := mcpClientSkillAuthoringLeaseDTO{
		LeaseID:          lease.ID,
		ClientID:         lease.MCPClientID,
		GrantedAt:        lease.GrantedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:        lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RemainingCreates: lease.RemainingCreates,
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
