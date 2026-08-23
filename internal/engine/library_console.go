package engine

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	libraryConsoleBodyLimit            = libraryMaxContentBytes + 32<<10
	libraryConsolePageCursorHeader     = "X-Synaxis-Library-Cursor"
	libraryConsolePageLimitHeader      = "X-Synaxis-Library-Limit"
	libraryConsolePageNextCursorHeader = "X-Synaxis-Library-Next-Cursor"
	libraryConsolePageCursorMaxBytes   = 1024

	libraryConsolePageKindSkills    = "skills"
	libraryConsolePageKindArtifacts = "artifacts"
	libraryConsolePageKindRuns      = "runs"
)

func (c *ConsoleAPI) librarySupported(w http.ResponseWriter) bool {
	if c.libraryStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "library is not supported by this store"})
		return false
	}
	return true
}

// Library management is administratively protected, but its records are not
// related to connection namespaces. In hosted mode Platform supplies the
// verified actor; in self-hosted mode the local administrator owns the Library.
func (c *ConsoleAPI) requireLibraryAdministrator(w http.ResponseWriter, r *http.Request) (PlatformActor, bool) {
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "library access is not permitted"})
		return PlatformActor{}, false
	}
	if !connectionNamespaceAdministrator(actor) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required"})
		return PlatformActor{}, false
	}
	return actor, true
}

func libraryActorRef(actor PlatformActor) string {
	if actor.UserID != "" {
		return actor.UserID
	}
	return "engine-admin"
}

func decodeLibraryBody(w http.ResponseWriter, r *http.Request, destination any) bool {
	if r.Body == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON body is required"})
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, libraryConsoleBodyLimit))
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

func writeLibraryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLibrarySkillNotFound),
		errors.Is(err, ErrLibrarySkillVersionNotFound),
		errors.Is(err, ErrLibrarySkillDraftNotFound),
		errors.Is(err, ErrLibraryBindingNotFound),
		errors.Is(err, ErrLibraryArtifactNotFound),
		errors.Is(err, ErrLibraryArtifactVersionNotFound),
		errors.Is(err, ErrLibraryArtifactGrantNotFound),
		errors.Is(err, ErrLibraryRunNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "library resource not found"})
	case errors.Is(err, ErrLibrarySkillExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a skill with that slug already exists"})
	case errors.Is(err, ErrLibraryArtifactGrantExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this artifact already has a live grant for that MCP client"})
	case errors.Is(err, ErrMCPClientNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MCP client is unavailable"})
	case errors.Is(err, ErrMCPClientRevoked):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MCP client is revoked"})
	case errors.Is(err, ErrLibraryDraftImportConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "skill draft request conflicts with an existing import"})
	case errors.Is(err, ErrLibraryPublicationNotReady):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the latest artifact version is not approved for publication"})
	case errors.Is(err, ErrLibraryPublicationClaimConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the artifact changed before publication could be claimed"})
	case errors.Is(err, ErrLibraryArtifactPublicationClaimed):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a publication-claimed artifact version cannot be re-reviewed"})
	case errors.Is(err, ErrLibraryDraftGeneratorUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "skill draft creator is not configured"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}

type libraryConsolePageCursorWire struct {
	Version   int    `json:"v"`
	Kind      string `json:"kind"`
	Timestamp string `json:"timestamp"`
	ID        string `json:"id"`
}

func libraryConsolePageHeader(r *http.Request, name string) (string, bool, error) {
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false, errors.New("invalid library page header")
	}
	return values[0], true, nil
}

func decodeLibraryConsolePageCursor(raw, expectedKind string) (LibraryConsolePageCursor, error) {
	if raw == "" || len(raw) > libraryConsolePageCursorMaxBytes {
		return LibraryConsolePageCursor{}, errors.New("invalid library page cursor")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return LibraryConsolePageCursor{}, err
	}
	var wire libraryConsolePageCursorWire
	if err := json.Unmarshal(data, &wire); err != nil || wire.Version != 1 || wire.Kind != expectedKind || wire.Timestamp == "" || wire.ID == "" {
		return LibraryConsolePageCursor{}, errors.New("invalid library page cursor")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp)
	if err != nil {
		return LibraryConsolePageCursor{}, err
	}
	cursor := LibraryConsolePageCursor{Timestamp: timestamp.UTC(), ID: wire.ID}
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsolePageCursor{}, err
	}
	return cursor, nil
}

func encodeLibraryConsolePageCursor(cursor LibraryConsolePageCursor, kind string) string {
	if cursor.Timestamp.IsZero() || cursor.ID == "" {
		return ""
	}
	data, err := json.Marshal(libraryConsolePageCursorWire{
		Version: 1, Kind: kind, Timestamp: cursor.Timestamp.UTC().Format(time.RFC3339Nano), ID: cursor.ID,
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func libraryConsolePageRequest(r *http.Request, kind string) (LibraryConsolePageCursor, int, error) {
	if r.URL == nil || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return LibraryConsolePageCursor{}, 0, errors.New("library pages use request headers")
	}
	cursorRaw, hasCursor, err := libraryConsolePageHeader(r, libraryConsolePageCursorHeader)
	if err != nil {
		return LibraryConsolePageCursor{}, 0, err
	}
	var cursor LibraryConsolePageCursor
	if hasCursor {
		cursor, err = decodeLibraryConsolePageCursor(cursorRaw, kind)
		if err != nil {
			return LibraryConsolePageCursor{}, 0, err
		}
	}

	limitRaw, hasLimit, err := libraryConsolePageHeader(r, libraryConsolePageLimitHeader)
	if err != nil {
		return LibraryConsolePageCursor{}, 0, err
	}
	limit := 0
	if hasLimit {
		limit, err = strconv.Atoi(limitRaw)
		if err != nil || limit <= 0 {
			return LibraryConsolePageCursor{}, 0, errors.New("invalid library page limit")
		}
	}
	limit, err = normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsolePageCursor{}, 0, err
	}
	return cursor, limit, nil
}

func writeLibraryConsolePageHeaders(w http.ResponseWriter, cursor LibraryConsolePageCursor, kind string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", libraryConsolePageCursorHeader)
	w.Header().Add("Vary", libraryConsolePageLimitHeader)
	if next := encodeLibraryConsolePageCursor(cursor, kind); next != "" {
		w.Header().Set(libraryConsolePageNextCursorHeader, next)
	}
}

type librarySkillDTO struct {
	LibrarySkill
	LatestVersion *librarySkillVersionSummary `json:"latestVersion,omitempty"`
}

type librarySkillVersionSummary struct {
	ID                    string    `json:"id"`
	Version               int       `json:"version"`
	Digest                string    `json:"digest"`
	RequestedCapabilities []string  `json:"requestedCapabilities"`
	CreatedAt             time.Time `json:"createdAt"`
}

func (c *ConsoleAPI) handleLibrarySkills(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := libraryConsolePageRequest(r, libraryConsolePageKindSkills)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid library skill page"})
			return
		}
		page, err := c.libraryStore.LibraryConsoleSkillPage(r.Context(), cursor, limit)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		out := make([]librarySkillDTO, 0, len(page.Skills))
		for _, skill := range page.Skills {
			dto := librarySkillDTO{LibrarySkill: skill.Skill}
			if latest := skill.LatestVersion; latest != nil {
				summary := librarySkillVersionSummary{
					ID: latest.ID, Version: latest.Version, Digest: latest.Digest,
					RequestedCapabilities: append([]string(nil), latest.RequestedCapabilities...), CreatedAt: latest.CreatedAt,
				}
				dto.LatestVersion = &summary
			}
			out = append(out, dto)
		}
		writeLibraryConsolePageHeaders(w, page.NextCursor, libraryConsolePageKindSkills)
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var request struct {
			Name                  string   `json:"name"`
			Slug                  string   `json:"slug"`
			Description           string   `json:"description"`
			Content               string   `json:"content"`
			RequestedCapabilities []string `json:"requestedCapabilities"`
			DraftID               string   `json:"draftId"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		if request.DraftID != "" {
			draft, found := c.libraryStore.LibrarySkillDraft(r.Context(), request.DraftID)
			if !found {
				writeLibraryError(w, ErrLibrarySkillDraftNotFound)
				return
			}
			if request.Name == "" {
				request.Name = draft.Name
			}
			if request.Description == "" {
				request.Description = draft.Description
			}
			if request.Content == "" {
				request.Content = draft.Content
			}
			if len(request.RequestedCapabilities) == 0 {
				request.RequestedCapabilities = draft.RequestedCapabilities
			}
		}
		if request.Slug == "" {
			request.Slug = librarySlugFromName(request.Name)
		}
		skill, version, err := c.libraryStore.CreateLibrarySkillWithInitialVersion(r.Context(), LibrarySkill{
			Slug: request.Slug, Name: request.Name, Description: request.Description, CreatedBy: libraryActorRef(actor),
		}, LibrarySkillVersion{Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: libraryActorRef(actor)})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Skill   LibrarySkill        `json:"skill"`
			Version LibrarySkillVersion `json:"version"`
		}{skill, version})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleLibraryResolve is the protected HTTP counterpart of the read-only MCP
// resolver. It intentionally uses POST for a logically read-only operation:
// hosted Platform actor assertions bind a JSON body and reject query strings.
// Platform or a self-hosted administrator may supply opaque runtime context,
// but this endpoint neither executes a skill nor turns a binding into a
// credential or permission grant.
func (c *ConsoleAPI) handleLibraryResolve(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryAdministrator(w, r); !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request LibrarySkillResolutionRequest
	if !decodeLibraryBody(w, r, &request) {
		return
	}
	resolution, err := ResolveLibrarySkills(r.Context(), c.libraryStore, request)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resolution)
}

func (c *ConsoleAPI) handleLibrarySkillByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryAdministrator(w, r); !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	skill, found := c.libraryStore.LibrarySkill(r.Context(), r.PathValue("id"))
	if !found {
		writeLibraryError(w, ErrLibrarySkillNotFound)
		return
	}
	versions, err := c.libraryStore.LibrarySkillVersions(r.Context(), skill.ID)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	bindings, err := c.libraryStore.LibrarySkillBindings(r.Context(), skill.ID)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	evaluations, err := c.libraryStore.LibrarySkillEvaluations(r.Context(), skill.ID)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		LibrarySkill
		Versions    []LibrarySkillVersion    `json:"versions"`
		Bindings    []LibrarySkillBinding    `json:"bindings"`
		Evaluations []LibrarySkillEvaluation `json:"evaluations"`
	}{skill, versions, bindings, evaluations})
}

func (c *ConsoleAPI) handleLibrarySkillVersions(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	skillID := r.PathValue("id")
	if _, found := c.libraryStore.LibrarySkill(r.Context(), skillID); !found {
		writeLibraryError(w, ErrLibrarySkillNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		versions, err := c.libraryStore.LibrarySkillVersions(r.Context(), skillID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, versions)
	case http.MethodPost:
		var request struct {
			Content               string   `json:"content"`
			RequestedCapabilities []string `json:"requestedCapabilities"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		version, err := c.libraryStore.CreateLibrarySkillVersion(r.Context(), LibrarySkillVersion{SkillID: skillID, Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: libraryActorRef(actor)})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, version)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibrarySkillBindings(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	skillID := r.PathValue("id")
	if _, found := c.libraryStore.LibrarySkill(r.Context(), skillID); !found {
		writeLibraryError(w, ErrLibrarySkillNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		bindings, err := c.libraryStore.LibrarySkillBindings(r.Context(), skillID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, bindings)
	case http.MethodPost:
		var request struct {
			ScopeKind         string   `json:"scopeKind"`
			ScopeID           string   `json:"scopeId"`
			Mode              string   `json:"mode"`
			PinnedVersionID   string   `json:"pinnedVersionId"`
			CapabilityCeiling []string `json:"capabilityCeiling"`
			Priority          int      `json:"priority"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		binding, err := c.libraryStore.UpsertLibrarySkillBinding(r.Context(), LibrarySkillBinding{
			SkillID: skillID, ScopeKind: request.ScopeKind, ScopeID: request.ScopeID, Mode: request.Mode,
			PinnedVersionID: request.PinnedVersionID, CapabilityCeiling: request.CapabilityCeiling, Priority: request.Priority, CreatedBy: libraryActorRef(actor),
		})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, binding)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibrarySkillBindingByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryAdministrator(w, r); !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := c.libraryStore.DeleteLibrarySkillBinding(r.Context(), r.PathValue("id"), r.PathValue("binding")); err != nil {
		writeLibraryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ConsoleAPI) handleLibrarySkillEvaluations(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	skillID := r.PathValue("id")
	if _, found := c.libraryStore.LibrarySkill(r.Context(), skillID); !found {
		writeLibraryError(w, ErrLibrarySkillNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		evaluations, err := c.libraryStore.LibrarySkillEvaluations(r.Context(), skillID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, evaluations)
	case http.MethodPost:
		var request struct {
			SkillVersionID string `json:"skillVersionId"`
			Evaluator      string `json:"evaluator"`
			Score          int    `json:"score"`
			Passed         bool   `json:"passed"`
			Summary        string `json:"summary"`
			EvidenceDigest string `json:"evidenceDigest"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		evaluation, err := c.libraryStore.CreateLibrarySkillEvaluation(r.Context(), LibrarySkillEvaluation{
			SkillID: skillID, SkillVersionID: request.SkillVersionID, Evaluator: request.Evaluator, Score: request.Score,
			Passed: request.Passed, Summary: request.Summary, EvidenceDigest: request.EvidenceDigest, CreatedBy: libraryActorRef(actor),
		})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, evaluation)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibrarySkillDrafts(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	// Hosted Engines never call an LLM provider directly. The Platform broker
	// owns provider credentials and invokes the separately asserted import
	// route, preventing a tenant Engine environment from becoming a second
	// provider-key trust boundary.
	if c.actorVerifier != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "hosted skill drafting is provided by the Platform"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if c.draftGenerator == nil {
		writeLibraryError(w, ErrLibraryDraftGeneratorUnavailable)
		return
	}
	var request struct {
		Name                  string   `json:"name"`
		Description           string   `json:"description"`
		Prompt                string   `json:"prompt"`
		RequestedCapabilities []string `json:"requestedCapabilities"`
	}
	if !decodeLibraryBody(w, r, &request) {
		return
	}
	if len(strings.TrimSpace(request.Prompt)) == 0 || len(request.Prompt) > libraryMaxContentBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a bounded draft prompt is required"})
		return
	}
	generation, err := c.draftGenerator.GenerateSkillDraft(r.Context(), SkillDraftGenerationRequest{
		Name: request.Name, Description: request.Description, Prompt: request.Prompt, RequestedCapabilities: request.RequestedCapabilities,
	})
	if err != nil {
		if errors.Is(err, ErrLibraryDraftGeneratorUnavailable) {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "skill draft generation failed"})
		return
	}
	draft, err := c.libraryStore.CreateLibrarySkillDraft(r.Context(), LibrarySkillDraft{
		Name: generation.Name, Description: generation.Description, Content: generation.Content,
		RequestedCapabilities: generation.RequestedCapabilities, Origin: LibraryDraftOriginGenerated,
		Generator: generation.Generator, Model: generation.Model, PromptDigest: libraryDigest(request.Prompt), CreatedBy: libraryActorRef(actor),
	})
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, draft)
}

func (c *ConsoleAPI) handleLibraryArtifacts(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := libraryConsolePageRequest(r, libraryConsolePageKindArtifacts)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid library artifact page"})
			return
		}
		page, err := c.libraryStore.LibraryConsoleArtifactPage(r.Context(), cursor, limit)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeLibraryConsolePageHeaders(w, page.NextCursor, libraryConsolePageKindArtifacts)
		writeJSON(w, http.StatusOK, page.Artifacts)
	case http.MethodPost:
		var request struct {
			Title          string `json:"title"`
			Summary        string `json:"summary"`
			Origin         string `json:"origin"`
			RunID          string `json:"runId"`
			SkillID        string `json:"skillId"`
			SkillVersionID string `json:"skillVersionId"`
			BindingID      string `json:"bindingId"`
			Format         string `json:"format"`
			Body           string `json:"body"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		artifact, version, err := c.libraryStore.CreateLibraryArtifactWithInitialVersion(r.Context(), LibraryArtifact{
			Title: request.Title, Summary: request.Summary, Origin: request.Origin, RunID: request.RunID,
			SkillID: request.SkillID, SkillVersionID: request.SkillVersionID, BindingID: request.BindingID, CreatedBy: libraryActorRef(actor),
		}, LibraryArtifactVersion{Format: request.Format, Body: request.Body, CreatedBy: libraryActorRef(actor)})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Artifact LibraryArtifact        `json:"artifact"`
			Version  LibraryArtifactVersion `json:"version"`
		}{artifact, version})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryArtifactByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryAdministrator(w, r); !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	artifact, found := c.libraryStore.LibraryArtifact(r.Context(), r.PathValue("id"))
	if !found {
		writeLibraryError(w, ErrLibraryArtifactNotFound)
		return
	}
	versions, err := c.libraryStore.LibraryArtifactVersions(r.Context(), artifact.ID)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		LibraryArtifact
		Versions []LibraryArtifactVersion `json:"versions"`
	}{artifact, versions})
}

func (c *ConsoleAPI) handleLibraryArtifactVersions(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	artifactID := r.PathValue("id")
	if _, found := c.libraryStore.LibraryArtifact(r.Context(), artifactID); !found {
		writeLibraryError(w, ErrLibraryArtifactNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		versions, err := c.libraryStore.LibraryArtifactVersions(r.Context(), artifactID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, versions)
	case http.MethodPost:
		var request struct {
			Format string `json:"format"`
			Body   string `json:"body"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		version, err := c.libraryStore.CreateLibraryArtifactVersion(r.Context(), LibraryArtifactVersion{ArtifactID: artifactID, Format: request.Format, Body: request.Body, CreatedBy: libraryActorRef(actor)})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, version)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleLibraryArtifactGrants manages delegated private reads for a durable,
// subject-bound MCP client. A browser supplies an exact artifact version ID;
// the Engine reads and stores its digest, so a grant can never mean "latest".
func (c *ConsoleAPI) handleLibraryArtifactGrants(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	artifactID := r.PathValue("id")
	if _, found := c.libraryStore.LibraryArtifact(r.Context(), artifactID); !found {
		writeLibraryError(w, ErrLibraryArtifactNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		grants, err := c.libraryStore.LibraryArtifactGrants(r.Context(), artifactID)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, grants)
	case http.MethodPost:
		var request struct {
			ArtifactVersionID string `json:"artifactVersionId"`
			AgentSurfaceID    string `json:"agentSurfaceId"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		version, found := c.libraryStore.LibraryArtifactVersion(r.Context(), artifactID, request.ArtifactVersionID)
		if !found {
			writeLibraryError(w, ErrLibraryArtifactVersionNotFound)
			return
		}
		// The durable store repeats this check transactionally. The console
		// makes the external contract explicit: a target must be the exact
		// opaque registration ID, never a public endpoint slug or a subject.
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
		grant, err := c.libraryStore.CreateLibraryArtifactGrant(r.Context(), LibraryArtifactGrant{
			ArtifactID: artifactID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
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

func (c *ConsoleAPI) handleLibraryArtifactGrantRevoke(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	grant, err := c.libraryStore.RevokeLibraryArtifactGrant(r.Context(), r.PathValue("id"), r.PathValue("grant"), libraryActorRef(actor), time.Now().UTC())
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (c *ConsoleAPI) handleLibraryArtifactReview(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		ArtifactVersionID string `json:"artifactVersionId"`
		Status            string `json:"status"`
	}
	if !decodeLibraryBody(w, r, &request) {
		return
	}
	version, err := c.libraryStore.ReviewLibraryArtifactVersion(r.Context(), r.PathValue("id"), request.ArtifactVersionID, request.Status, libraryActorRef(actor), time.Now().UTC())
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, version)
}

func (c *ConsoleAPI) handleLibraryPublicationCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// A hosted candidate contains the artifact body after it has passed the
	// Engine review gate. It is an Engine-to-Platform handoff, never a browser
	// management read: Platform alone decides whether to mint or revoke a
	// public link. Self-hosted engines retain their local-admin behavior.
	if c.actorVerifier != nil && (actor.Role != "service" || actor.UserID != platformServiceActorID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "publication candidates require the Platform service"})
		return
	}
	candidate, err := c.libraryStore.LibraryPublicationCandidate(r.Context(), r.PathValue("id"))
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}

func (c *ConsoleAPI) handleLibraryPublicationClaim(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// This is deliberately narrower than a general Platform Library write.
	// The service may only compare-and-claim the version/digest it just read
	// through the candidate route, then receive the safe snapshot to persist.
	if c.actorVerifier != nil && (actor.Role != "service" || actor.UserID != platformServiceActorID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "publication claims require the Platform service"})
		return
	}
	var request struct {
		ArtifactVersionID string `json:"artifactVersionId"`
		Digest            string `json:"digest"`
	}
	if !decodeLibraryBody(w, r, &request) {
		return
	}
	candidate, err := c.libraryStore.ClaimLibraryPublicationCandidate(
		r.Context(),
		r.PathValue("id"),
		request.ArtifactVersionID,
		request.Digest,
	)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}

func (c *ConsoleAPI) handleLibraryRuns(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok || !c.librarySupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := libraryConsolePageRequest(r, libraryConsolePageKindRuns)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid library run page"})
			return
		}
		page, err := c.libraryStore.LibraryConsoleRunPage(r.Context(), cursor, limit)
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeLibraryConsolePageHeaders(w, page.NextCursor, libraryConsolePageKindRuns)
		writeJSON(w, http.StatusOK, page.Runs)
	case http.MethodPost:
		var request struct {
			Origin                string   `json:"origin"`
			SkillID               string   `json:"skillId"`
			SkillVersionID        string   `json:"skillVersionId"`
			BindingID             string   `json:"bindingId"`
			SurfaceRef            string   `json:"surfaceRef"`
			EffectiveCapabilities []string `json:"effectiveCapabilities"`
			Status                string   `json:"status"`
			InputDigest           string   `json:"inputDigest"`
			OutputDigest          string   `json:"outputDigest"`
		}
		if !decodeLibraryBody(w, r, &request) {
			return
		}
		// This browser/admin endpoint is a manual provenance ledger, not an
		// execution runtime. In particular, accepting a caller-supplied
		// skill/version/binding tuple here would let an administrator fabricate
		// a trusted skill execution record. A future runtime adapter must have
		// a distinct, authenticated ingestion boundary before it may create
		// skill_run provenance.
		switch request.Origin {
		case LibraryRunOriginHuman, LibraryRunOriginAutomation:
			// These source classes are useful for recording a manual action or
			// an external automation, but they are not a claim about a Library
			// skill or a credential-bearing runtime.
		case LibraryRunOriginSkillRun, LibraryRunOriginAgentDirect:
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this run provenance is reserved for a trusted runtime"})
			return
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "run origin must be human or automation"})
			return
		}
		if request.SkillID != "" || request.SkillVersionID != "" || request.BindingID != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "manual runs cannot claim skill provenance"})
			return
		}
		if len(request.EffectiveCapabilities) != 0 {
			// Effective capabilities are evidence from a trusted runtime that
			// independently authorized each action. A browser/API caller has no
			// such authority, so rejecting rather than silently dropping them
			// makes the provenance boundary explicit.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "manual runs cannot claim effective capabilities"})
			return
		}
		run, err := c.libraryStore.CreateLibraryRun(r.Context(), LibraryRun{
			Origin: request.Origin, SkillID: request.SkillID, SkillVersionID: request.SkillVersionID, BindingID: request.BindingID,
			ActorRef: libraryActorRef(actor), SurfaceRef: request.SurfaceRef,
			Status: request.Status, InputDigest: request.InputDigest, OutputDigest: request.OutputDigest,
		})
		if err != nil {
			writeLibraryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, run)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleLibraryRunByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireLibraryAdministrator(w, r); !ok || !c.librarySupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	run, found := c.libraryStore.LibraryRun(r.Context(), r.PathValue("id"))
	if !found {
		writeLibraryError(w, ErrLibraryRunNotFound)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
