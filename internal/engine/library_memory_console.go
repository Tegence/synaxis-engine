package engine

import (
	"net/http"
	"time"
)

func (c *ConsoleAPI) libraryMemorySupported(w http.ResponseWriter) bool {
	if c.memoryStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "library memory is not supported by this store"})
		return false
	}
	return true
}

func (c *ConsoleAPI) requireLibraryMemoryAdministrator(w http.ResponseWriter, r *http.Request) (PlatformActor, bool) {
	// Every memory management response may carry private authored content,
	// provenance, or sharing metadata. Apply the cache boundary centrally so
	// success and error responses across all subresources remain non-cacheable.
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.libraryMemorySupported(w) {
		return PlatformActor{}, false
	}
	return actor, true
}

type libraryMemoryCreateRequest struct {
	Kind                    string     `json:"kind"`
	Content                 string     `json:"content"`
	AgentSurfaceID          string     `json:"agentSurfaceId"`
	ExpiresAt               *time.Time `json:"expiresAt"`
	ReviewAfter             *time.Time `json:"reviewAfter"`
	SourceRunID             string     `json:"sourceRunId"`
	SourceArtifactID        string     `json:"sourceArtifactId"`
	SourceArtifactVersionID string     `json:"sourceArtifactVersionId"`
	SourceDigest            string     `json:"sourceDigest"`
}

type libraryMemoryVersionCreateRequest struct {
	Content                 string `json:"content"`
	SourceRunID             string `json:"sourceRunId"`
	SourceArtifactID        string `json:"sourceArtifactId"`
	SourceArtifactVersionID string `json:"sourceArtifactVersionId"`
	SourceDigest            string `json:"sourceDigest"`
}

func libraryOptionalTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}

func validateNewLibraryMemoryFreshness(now time.Time, expiresAt, reviewAfter *time.Time) error {
	if expiresAt != nil && !expiresAt.After(now) {
		return &libraryMemoryRequestError{"expiresAt must be in the future"}
	}
	if reviewAfter != nil && !reviewAfter.After(now) {
		return &libraryMemoryRequestError{"reviewAfter must be in the future"}
	}
	return nil
}

type libraryMemoryRequestError struct{ message string }

func (e *libraryMemoryRequestError) Error() string { return e.message }

func (c *ConsoleAPI) handleLibraryMemories(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryMemoryAdministrator(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := libraryConsolePageRequest(r, libraryConsolePageKindMemories)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid library memory page"})
			return
		}
		page, err := c.memoryStore.LibraryConsoleMemoryPage(r.Context(), cursor, limit)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeLibraryConsolePageHeaders(w, page.NextCursor, libraryConsolePageKindMemories)
		writeJSON(w, http.StatusOK, page.Memories)
	case http.MethodPost:
		var request libraryMemoryCreateRequest
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		now := time.Now().UTC()
		if err := validateNewLibraryMemoryFreshness(now, request.ExpiresAt, request.ReviewAfter); err != nil {
			writeLibraryError(w, err)
			return
		}
		clientStore, supported := c.mcpClientStore()
		if !supported {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "MCP client registry is not supported by this store"})
			return
		}
		client, live := clientStore.ActiveMCPClient(r.Context(), request.AgentSurfaceID)
		if !live || client.ID != request.AgentSurfaceID {
			writeLibraryError(w, ErrMCPClientNotFound)
			return
		}
		createdBy := libraryActorRef(actor)
		memory, version, err := c.memoryStore.CreateLibraryMemoryWithInitialVersion(r.Context(), LibraryMemory{
			Kind: request.Kind, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
			AgentSurfaceID: client.ID, CreatedBy: createdBy, ExpiresAt: libraryOptionalTime(request.ExpiresAt), ReviewAfter: libraryOptionalTime(request.ReviewAfter),
		}, LibraryMemoryVersion{
			Content: request.Content, SourceRunID: request.SourceRunID, SourceArtifactID: request.SourceArtifactID,
			SourceArtifactVersionID: request.SourceArtifactVersionID, SourceDigest: request.SourceDigest, CreatedBy: createdBy,
		})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Memory  LibraryMemory        `json:"memory"`
			Version LibraryMemoryVersion `json:"version"`
		}{memory, version})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryMemoryByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryMemoryAdministrator(w, r); !ok {
		return
	}
	memoryID := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		memory, found := c.memoryStore.LibraryMemory(r.Context(), memoryID)
		if !found {
			writeLibraryError(w, ErrLibraryMemoryNotFound)
			return
		}
		versions, err := c.memoryStore.LibraryMemoryVersions(r.Context(), memoryID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Memory   LibraryMemory          `json:"memory"`
			Versions []LibraryMemoryVersion `json:"versions"`
		}{memory, versions})
	case http.MethodDelete:
		if err := c.memoryStore.ForgetLibraryMemory(r.Context(), memoryID); err != nil {
			writeLibraryError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryMemoryVersions(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryMemoryAdministrator(w, r)
	if !ok {
		return
	}
	memoryID := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		versions, err := c.memoryStore.LibraryMemoryVersions(r.Context(), memoryID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, versions)
	case http.MethodPost:
		var request libraryMemoryVersionCreateRequest
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		memory, version, err := c.memoryStore.CreateLibraryMemoryVersion(r.Context(), memoryID, LibraryMemoryVersion{
			Content: request.Content, SourceRunID: request.SourceRunID, SourceArtifactID: request.SourceArtifactID,
			SourceArtifactVersionID: request.SourceArtifactVersionID, SourceDigest: request.SourceDigest,
		}, libraryActorRef(actor))
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Memory  LibraryMemory        `json:"memory"`
			Version LibraryMemoryVersion `json:"version"`
		}{memory, version})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryMemoryReview(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryMemoryAdministrator(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		MemoryVersionID      string     `json:"memoryVersionId"`
		State                string     `json:"state"`
		Trust                string     `json:"trust"`
		ExpiresAt            *time.Time `json:"expiresAt"`
		ReviewAfter          *time.Time `json:"reviewAfter"`
		SupersededByMemoryID string     `json:"supersededByMemoryId"`
	}
	if !decodeLibraryBody(w, r, &request) {
		return
	}
	if !validLibraryMemoryAdministrativeReview(request.State, request.Trust) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid memory review state or trust"})
		return
	}
	memory, err := c.memoryStore.ReviewLibraryMemory(r.Context(), r.PathValue("id"), LibraryMemoryReview{
		MemoryVersionID: request.MemoryVersionID, State: request.State, Trust: request.Trust,
		ExpiresAt: request.ExpiresAt, ReviewAfter: request.ReviewAfter,
		SupersededByMemoryID: request.SupersededByMemoryID,
		ReviewedBy:           libraryActorRef(actor), ReviewedAt: time.Now().UTC(),
	})
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, memory)
}

func (c *ConsoleAPI) handleLibraryMemoryGrants(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryMemoryAdministrator(w, r)
	if !ok {
		return
	}
	memoryID := r.PathValue("id")
	if _, found := c.memoryStore.LibraryMemory(r.Context(), memoryID); !found {
		writeLibraryError(w, ErrLibraryMemoryNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		grants, err := c.memoryStore.LibraryMemoryGrants(r.Context(), memoryID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, grants)
	case http.MethodPost:
		var request struct {
			MemoryVersionID string `json:"memoryVersionId"`
			AgentSurfaceID  string `json:"agentSurfaceId"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		version, found := c.memoryStore.LibraryMemoryVersion(r.Context(), memoryID, request.MemoryVersionID)
		if !found {
			writeLibraryError(w, ErrLibraryMemoryVersionNotFound)
			return
		}
		clientStore, supported := c.mcpClientStore()
		if !supported {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "MCP client registry is not supported by this store"})
			return
		}
		client, live := clientStore.ActiveMCPClient(r.Context(), request.AgentSurfaceID)
		if !live || client.ID != request.AgentSurfaceID {
			writeLibraryError(w, ErrMCPClientNotFound)
			return
		}
		grant, err := c.memoryStore.CreateLibraryMemoryGrant(r.Context(), LibraryMemoryGrant{
			MemoryID: memoryID, MemoryVersionID: version.ID, MemoryVersionDigest: version.Digest,
			AgentSurfaceID: client.ID, CreatedBy: libraryActorRef(actor),
		})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, grant)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryMemoryGrantRevoke(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryMemoryAdministrator(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	grant, err := c.memoryStore.RevokeLibraryMemoryGrant(r.Context(), r.PathValue("id"), r.PathValue("grant"), libraryActorRef(actor), time.Now().UTC())
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}
