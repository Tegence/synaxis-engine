package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The subject-scoped Library group of /control/v1 (docs/CONTROL_V1.md,
// "Library, subject-scoped"). A hosting control plane derives the subject from
// its own session and sends it in X-Synaxis-Subject; a signed actor assertion
// binds a bare path, so the scope can never travel in a query string. The
// Engine resolves the subject to its active subject-bound registrations and
// answers only from those registrations' ownership keys and live
// exact-version grants. Every list projection is metadata-only; a version body
// is served solely by the exact-version read after the same authorization.
const (
	controlSubjectHeader             = "X-Synaxis-Subject"
	controlLibraryArtifactPageLimit  = libraryControlArtifactPageMax
	controlLibraryGrantReasonMaxSize = 1024
	controlLibraryNotFoundTitle      = "library artifact not found"
)

// controlLibraryAdministration is the owner/admin/service gate shared by the
// library control routes, resolved in the historical (facet, actor, role)
// order. An operator manages its own registration on the client routes but
// never reads another member's Library scope.
func (c *ConsoleAPI) controlLibraryAdministration(r *http.Request) (LibraryStore, MCPClientStore, PlatformActor, *consoleFailure) {
	if c.libraryStore == nil {
		return nil, nil, PlatformActor{}, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "library is not supported by this store")
	}
	clients, ok := c.mcpClientStore()
	if !ok {
		return nil, nil, PlatformActor{}, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "MCP client registry is not supported by this store")
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		return nil, nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "library access is not permitted")
	}
	if !mcpClientRegistryAdministrator(actor) {
		return nil, nil, PlatformActor{}, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "library control requires a workspace owner, admin, or the Platform service")
	}
	return c.libraryStore, clients, actor, nil
}

// controlSubject reads the optional subject scope. The value must be exactly
// one well-formed actor identifier; the service principal's own identifier is
// never a Library subject.
func controlSubject(r *http.Request) (subject string, scoped bool, failure *consoleFailure) {
	values := r.Header.Values(controlSubjectHeader)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || validateMCPClientSubject(values[0]) != nil {
		return "", false, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid "+controlSubjectHeader)
	}
	return values[0], true, nil
}

// controlSubjectSurfaces resolves a subject to the IDs of its active
// subject-bound registrations. Revoked registrations drop out, so an artifact
// they owned or were granted stops appearing in the subject's scope.
func controlSubjectSurfaces(ctx context.Context, clients MCPClientStore, subject string) ([]string, *consoleFailure) {
	active, err := clients.ActiveMCPClients(ctx)
	if err != nil {
		return nil, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "MCP client registry is unavailable")
	}
	surfaces := make([]string, 0, 2)
	for _, client := range active {
		if client.Subject == subject {
			surfaces = append(surfaces, client.ID)
		}
	}
	return surfaces, nil
}

func containsSurface(surfaces []string, id string) bool {
	if id == "" {
		return false
	}
	for _, surface := range surfaces {
		if surface == id {
			return true
		}
	}
	return false
}

// controlLibraryAccess classifies one artifact relative to a subject's
// surfaces from already-loaded versions and grants: direct ownership first,
// otherwise the highest-numbered live grant whose pinned version still carries
// the recorded digest.
func controlLibraryAccess(artifact LibraryArtifact, versions []LibraryArtifactVersion, grants []LibraryArtifactGrant, surfaces []string) (string, *LibraryArtifactVersion) {
	if containsSurface(surfaces, artifact.AgentSurfaceID) {
		return LibraryControlArtifactAccessOwned, nil
	}
	var granted *LibraryArtifactVersion
	for _, grant := range grants {
		if !grant.RevokedAt.IsZero() || !containsSurface(surfaces, grant.AgentSurfaceID) {
			continue
		}
		for i := range versions {
			version := &versions[i]
			if version.ID != grant.ArtifactVersionID || version.Digest != grant.ArtifactVersionDigest {
				continue
			}
			if granted == nil || version.Version > granted.Version {
				granted = version
			}
		}
	}
	if granted == nil {
		return "", nil
	}
	metadata := libraryArtifactVersionMetadata(*granted)
	return LibraryControlArtifactAccessGranted, &metadata
}

func libraryArtifactHead(versions []LibraryArtifactVersion) *LibraryArtifactVersion {
	var head *LibraryArtifactVersion
	for i := range versions {
		if head == nil || versions[i].Version > head.Version {
			head = &versions[i]
		}
	}
	return head
}

type controlLibraryVersionRefDTO struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	Digest    string `json:"digest"`
	CreatedAt string `json:"createdAt"`
}

func newControlLibraryVersionRefDTO(version LibraryArtifactVersion) controlLibraryVersionRefDTO {
	return controlLibraryVersionRefDTO{ID: version.ID, Version: version.Version, Digest: version.Digest, CreatedAt: version.CreatedAt.UTC().Format(time.RFC3339Nano)}
}

// controlLibraryArtifactDTO is the list row. It deliberately carries the
// agent-surface key (a structural projection reference, not an actor
// identity) and never a version body.
type controlLibraryArtifactDTO struct {
	ID             string                       `json:"id"`
	Title          string                       `json:"title"`
	Summary        string                       `json:"summary"`
	Format         string                       `json:"format"`
	Origin         string                       `json:"origin"`
	AgentSurfaceID string                       `json:"agentSurfaceId,omitempty"`
	Access         string                       `json:"access,omitempty"`
	LatestVersion  controlLibraryVersionRefDTO  `json:"latestVersion"`
	GrantedVersion *controlLibraryVersionRefDTO `json:"grantedVersion,omitempty"`
	CreatedAt      string                       `json:"createdAt"`
	UpdatedAt      string                       `json:"updatedAt"`
}

func newControlLibraryArtifactDTO(item LibraryControlArtifact) controlLibraryArtifactDTO {
	dto := controlLibraryArtifactDTO{
		ID:             item.Artifact.ID,
		Title:          item.Artifact.Title,
		Summary:        item.Artifact.Summary,
		Format:         item.LatestVersion.Format,
		Origin:         item.Artifact.Origin,
		AgentSurfaceID: item.Artifact.AgentSurfaceID,
		Access:         item.Access,
		LatestVersion:  newControlLibraryVersionRefDTO(item.LatestVersion),
		CreatedAt:      item.Artifact.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      item.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if item.GrantedVersion != nil {
		granted := newControlLibraryVersionRefDTO(*item.GrantedVersion)
		dto.GrantedVersion = &granted
	}
	return dto
}

type controlLibraryArtifactPageDTO struct {
	Artifacts  []controlLibraryArtifactDTO `json:"artifacts"`
	NextCursor string                      `json:"nextCursor,omitempty"`
}

// controlLibraryVersionDTO is version metadata: never the body, author, or
// reviewer.
type controlLibraryVersionDTO struct {
	ID              string `json:"id"`
	Version         int    `json:"version"`
	Format          string `json:"format"`
	Digest          string `json:"digest"`
	SizeBytes       int64  `json:"sizeBytes"`
	RedactionStatus string `json:"redactionStatus"`
	CreatedAt       string `json:"createdAt"`
}

func newControlLibraryVersionDTO(version LibraryArtifactVersion) controlLibraryVersionDTO {
	return controlLibraryVersionDTO{
		ID: version.ID, Version: version.Version, Format: version.Format, Digest: version.Digest,
		SizeBytes: version.SizeBytes, RedactionStatus: version.RedactionStatus,
		CreatedAt: version.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

type controlLibraryGrantDTO struct {
	ID                string `json:"id"`
	RecipientClientID string `json:"recipientClientId"`
	VersionID         string `json:"versionId"`
	Digest            string `json:"digest"`
	State             string `json:"state"`
	CreatedAt         string `json:"createdAt"`
	RevokedAt         string `json:"revokedAt,omitempty"`
}

func newControlLibraryGrantDTO(grant LibraryArtifactGrant) controlLibraryGrantDTO {
	dto := controlLibraryGrantDTO{
		ID: grant.ID, RecipientClientID: grant.AgentSurfaceID, VersionID: grant.ArtifactVersionID, Digest: grant.ArtifactVersionDigest,
		State: "active", CreatedAt: grant.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if !grant.RevokedAt.IsZero() {
		dto.State = "revoked"
		dto.RevokedAt = grant.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	return dto
}

type controlLibraryArtifactDetailDTO struct {
	controlLibraryArtifactDTO
	Versions []controlLibraryVersionDTO `json:"versions"`
	Grants   []controlLibraryGrantDTO   `json:"grants"`
}

type controlLibraryVersionBodyDTO struct {
	Version controlLibraryVersionDTO `json:"version"`
	Body    string                   `json:"body"`
}

type controlLibraryRecipientDTO struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Subject string `json:"subject"`
}

func encodeControlLibraryArtifactCursor(cursor LibraryControlArtifactCursor) string {
	return encodeControlKeysetCursor(cursor.UpdatedAt, cursor.ID)
}

func decodeControlLibraryArtifactCursor(raw string) (LibraryControlArtifactCursor, error) {
	updatedAt, id, err := decodeControlKeysetCursor(raw)
	if err != nil {
		return LibraryControlArtifactCursor{}, err
	}
	cursor := LibraryControlArtifactCursor{UpdatedAt: updatedAt, ID: id}
	if err := validateLibraryControlArtifactCursor(cursor); err != nil {
		return LibraryControlArtifactCursor{}, errors.New("invalid cursor")
	}
	return cursor, nil
}

// controlLibraryFailure maps Library and registry errors to one
// status/code/message triple for the control routes.
func controlLibraryFailure(err error) *consoleFailure {
	switch {
	case errors.Is(err, ErrLibraryArtifactNotFound), errors.Is(err, ErrLibraryArtifactGrantNotFound):
		return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle)
	case errors.Is(err, ErrLibraryArtifactVersionNotFound):
		// The store re-reads the version and its digest under its own lock; a
		// miss after the handler's precheck means the source it was asked to
		// pin no longer matches.
		return newConsoleFailure(http.StatusConflict, controlCodeGrantSourceChanged, "artifact version or digest changed; review the artifact again")
	case errors.Is(err, ErrLibraryArtifactGrantExists):
		return newConsoleFailure(http.StatusConflict, controlCodeAlreadyExists, "this recipient already holds a live grant for another version of this artifact; revoke it first")
	case errors.Is(err, ErrMCPClientNotFound):
		return newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "recipient MCP client not found")
	case errors.Is(err, ErrMCPClientRevoked):
		return newConsoleFailure(http.StatusConflict, controlCodeClientRevoked, "recipient MCP client is revoked")
	default:
		return newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "library is unavailable")
	}
}

// handleControlLibraryArtifacts serves GET /control/v1/library/artifacts.
// With X-Synaxis-Subject the page is the subject's scope; without it an
// owner, admin, or the service principal reads the whole catalog's metadata.
func (c *ConsoleAPI) handleControlLibraryArtifacts(w http.ResponseWriter, r *http.Request) {
	library, clients, _, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	store, ok := library.(LibraryControlArtifactStore)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "library control projection is not supported by this store"))
		return
	}
	subject, scoped, failure := controlSubject(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	scope := LibraryControlArtifactScope{Everything: true}
	if scoped {
		surfaces, failure := controlSubjectSurfaces(r.Context(), clients, subject)
		if failure != nil {
			controlWire.writeFailure(w, failure)
			return
		}
		scope = LibraryControlArtifactScope{AgentSurfaceIDs: surfaces}
	}
	var cursor LibraryControlArtifactCursor
	if raw := r.Header.Get(controlCursorHeader); raw != "" {
		var err error
		if cursor, err = decodeControlLibraryArtifactCursor(raw); err != nil {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid "+controlCursorHeader))
			return
		}
	}
	page, err := store.LibraryControlArtifactPage(r.Context(), scope, cursor, controlLibraryArtifactPageLimit)
	if err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "library artifacts are unavailable"))
		return
	}
	dto := controlLibraryArtifactPageDTO{Artifacts: make([]controlLibraryArtifactDTO, 0, len(page.Artifacts))}
	for _, item := range page.Artifacts {
		dto.Artifacts = append(dto.Artifacts, newControlLibraryArtifactDTO(item))
	}
	if page.NextCursor.ID != "" {
		dto.NextCursor = encodeControlLibraryArtifactCursor(page.NextCursor)
		w.Header().Set(controlCursorHeader, dto.NextCursor)
	}
	writeJSON(w, http.StatusOK, dto)
}

// handleControlLibraryArtifactByID serves GET /control/v1/library/artifacts/{id}:
// artifact metadata, version metadata, and grants. With X-Synaxis-Subject the
// artifact must be owned by or granted to the subject (404 otherwise), and a
// mere grantee sees only the grants held by its own registrations.
func (c *ConsoleAPI) handleControlLibraryArtifactByID(w http.ResponseWriter, r *http.Request) {
	library, clients, _, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	subject, scoped, failure := controlSubject(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	artifact, found := library.LibraryArtifact(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	versions, err := library.LibraryArtifactVersions(r.Context(), artifact.ID)
	if err != nil {
		controlWire.writeFailure(w, controlLibraryFailure(err))
		return
	}
	grants, err := library.LibraryArtifactGrants(r.Context(), artifact.ID)
	if err != nil {
		controlWire.writeFailure(w, controlLibraryFailure(err))
		return
	}
	head := libraryArtifactHead(versions)
	if head == nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	item := LibraryControlArtifact{
		Artifact:      libraryControlArtifactMetadata(artifact),
		LatestVersion: libraryArtifactVersionMetadata(*head),
		UpdatedAt:     head.CreatedAt,
	}
	if scoped {
		surfaces, failure := controlSubjectSurfaces(r.Context(), clients, subject)
		if failure != nil {
			controlWire.writeFailure(w, failure)
			return
		}
		access, granted := controlLibraryAccess(artifact, versions, grants, surfaces)
		if access == "" {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
			return
		}
		item.Access, item.GrantedVersion = access, granted
		if access == LibraryControlArtifactAccessGranted {
			visible := grants[:0]
			for _, grant := range grants {
				if containsSurface(surfaces, grant.AgentSurfaceID) {
					visible = append(visible, grant)
				}
			}
			grants = visible
		}
	}
	dto := controlLibraryArtifactDetailDTO{
		controlLibraryArtifactDTO: newControlLibraryArtifactDTO(item),
		Versions:                  make([]controlLibraryVersionDTO, 0, len(versions)),
		Grants:                    make([]controlLibraryGrantDTO, 0, len(grants)),
	}
	for _, version := range versions {
		dto.Versions = append(dto.Versions, newControlLibraryVersionDTO(version))
	}
	for _, grant := range grants {
		dto.Grants = append(dto.Grants, newControlLibraryGrantDTO(grant))
	}
	writeJSON(w, http.StatusOK, dto)
}

// handleControlLibraryArtifactVersion serves
// GET /control/v1/library/artifacts/{id}/versions/{version}: the exact
// immutable version with its body, only for a subject that owns the artifact
// or holds a live grant pinned to exactly that version and digest. Unknown
// artifact, unknown version, and missing authorization are the same 404 so
// the route is not an enumeration oracle.
func (c *ConsoleAPI) handleControlLibraryArtifactVersion(w http.ResponseWriter, r *http.Request) {
	library, clients, _, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	subject, scoped, failure := controlSubject(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if !scoped {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, controlSubjectHeader+" is required"))
		return
	}
	surfaces, failure := controlSubjectSurfaces(r.Context(), clients, subject)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	notFound := newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle)
	artifact, found := library.LibraryArtifact(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found {
		controlWire.writeFailure(w, notFound)
		return
	}
	version, found := library.LibraryArtifactVersion(r.Context(), artifact.ID, strings.TrimSpace(r.PathValue("version")))
	if !found {
		controlWire.writeFailure(w, notFound)
		return
	}
	allowed := containsSurface(surfaces, artifact.AgentSurfaceID)
	for _, surface := range surfaces {
		if allowed {
			break
		}
		grant, live := library.ActiveLibraryArtifactGrant(r.Context(), artifact.ID, surface)
		allowed = live && grant.ArtifactVersionID == version.ID && grant.ArtifactVersionDigest == version.Digest
	}
	if !allowed {
		controlWire.writeFailure(w, notFound)
		return
	}
	writeJSON(w, http.StatusOK, controlLibraryVersionBodyDTO{Version: newControlLibraryVersionDTO(version), Body: version.Body})
}

// handleControlLibraryArtifactGrants serves
// POST /control/v1/library/artifacts/{id}/grants. The caller names the exact
// version and the digest it reviewed; the Engine refuses to pin anything else.
// Unless allowNonHead is set the version must still be the artifact's head, so
// a review is never silently retargeted after the artifact moved on.
func (c *ConsoleAPI) handleControlLibraryArtifactGrants(w http.ResponseWriter, r *http.Request) {
	library, clients, actor, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPost {
		controlWire.writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	artifact, found := library.LibraryArtifact(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if !found {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	var request struct {
		RecipientClientID string `json:"recipientClientId"`
		VersionID         string `json:"versionId"`
		Digest            string `json:"digest"`
		CreatedBy         string `json:"createdBy"`
		AllowNonHead      bool   `json:"allowNonHead"`
	}
	if failure := controlWire.decodeJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	request.RecipientClientID = strings.TrimSpace(request.RecipientClientID)
	request.VersionID = strings.TrimSpace(request.VersionID)
	request.Digest = strings.ToLower(strings.TrimSpace(request.Digest))
	request.CreatedBy = strings.TrimSpace(request.CreatedBy)
	if request.RecipientClientID == "" || request.VersionID == "" || request.Digest == "" {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "recipientClientId, versionId, and digest are required"))
		return
	}
	if validateLibraryDigest("artifact version", request.Digest, false) != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "digest must be a lowercase SHA-256 hex value"))
		return
	}
	createdBy := libraryActorRef(actor)
	if request.CreatedBy != "" {
		if !validActorIdentifier(request.CreatedBy) {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "createdBy must be an actor identifier"))
			return
		}
		createdBy = request.CreatedBy
	}
	version, found := library.LibraryArtifactVersion(r.Context(), artifact.ID, request.VersionID)
	if !found {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, "library artifact version not found"))
		return
	}
	if version.Digest != request.Digest {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusConflict, controlCodeGrantSourceChanged, "artifact version digest does not match; review the artifact again"))
		return
	}
	if !request.AllowNonHead {
		versions, err := library.LibraryArtifactVersions(r.Context(), artifact.ID)
		if err != nil {
			controlWire.writeFailure(w, controlLibraryFailure(err))
			return
		}
		if head := libraryArtifactHead(versions); head == nil || head.ID != version.ID {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusConflict, controlCodeGrantSourceChanged, "artifact head moved past the reviewed version; review the artifact again or pass allowNonHead"))
			return
		}
	}
	// The durable store repeats this check transactionally. The route makes
	// the contract explicit: a recipient is the exact opaque registration ID,
	// never an endpoint slug or a subject.
	recipient, found := clients.MCPClient(r.Context(), request.RecipientClientID)
	if !found || recipient.ID != request.RecipientClientID {
		controlWire.writeFailure(w, controlLibraryFailure(ErrMCPClientNotFound))
		return
	}
	if recipient.Status != MCPClientStatusActive {
		controlWire.writeFailure(w, controlLibraryFailure(ErrMCPClientRevoked))
		return
	}
	grant, err := library.CreateLibraryArtifactGrant(r.Context(), LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
		AgentSurfaceID: recipient.ID, CreatedBy: createdBy,
	})
	if err != nil {
		if errors.Is(err, ErrLibraryArtifactGrantExists) {
			// Natural-key convergence: the same exact version already delegated
			// to the same recipient is the resource the caller asked for.
			if existing, live := library.ActiveLibraryArtifactGrant(r.Context(), artifact.ID, recipient.ID); live &&
				existing.ArtifactVersionID == version.ID && existing.ArtifactVersionDigest == version.Digest {
				writeJSON(w, http.StatusOK, newControlLibraryGrantDTO(existing))
				return
			}
		}
		controlWire.writeFailure(w, controlLibraryFailure(err))
		return
	}
	writeJSON(w, http.StatusCreated, newControlLibraryGrantDTO(grant))
}

// handleControlLibraryArtifactGrantRevoke serves
// POST /control/v1/library/artifacts/{id}/grants/{grant}/revoke. Revocation
// converges: a second call returns the already-revoked record with its
// original revoker and time. The Engine grant record carries no reason field;
// the body's reason is validated for the contract and kept by the caller's own
// review record.
func (c *ConsoleAPI) handleControlLibraryArtifactGrantRevoke(w http.ResponseWriter, r *http.Request) {
	library, _, actor, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodPost {
		controlWire.writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if failure := controlWire.decodeJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if len(request.Reason) > controlLibraryGrantReasonMaxSize {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "reason is too long"))
		return
	}
	grant, err := library.RevokeLibraryArtifactGrant(r.Context(), strings.TrimSpace(r.PathValue("id")), strings.TrimSpace(r.PathValue("grant")), libraryActorRef(actor), time.Now().UTC())
	if err != nil {
		controlWire.writeFailure(w, controlLibraryFailure(err))
		return
	}
	writeJSON(w, http.StatusOK, newControlLibraryGrantDTO(grant))
}

// handleControlLibraryRecipients serves GET /control/v1/library/recipients:
// the active subject-bound registrations a grant may name. Subject is the
// opaque actor identifier a hosting control plane already owns.
func (c *ConsoleAPI) handleControlLibraryRecipients(w http.ResponseWriter, r *http.Request) {
	_, clients, _, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	active, err := clients.ActiveMCPClients(r.Context())
	if err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "MCP client registry is unavailable"))
		return
	}
	out := make([]controlLibraryRecipientDTO, 0, len(active))
	for _, client := range active {
		out = append(out, controlLibraryRecipientDTO{ID: client.ID, Slug: client.Slug, Name: client.Name, Subject: client.Subject})
	}
	writeJSON(w, http.StatusOK, out)
}
