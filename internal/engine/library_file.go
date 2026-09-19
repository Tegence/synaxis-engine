package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// FileStore implements LibraryStore for self-hosted/local Engines. It uses the
// same single-file, single-instance durability posture as the existing account
// and legacy SkillStore facets. PgStore encrypts Library content when an
// encryption key is configured; FileStore intentionally follows its existing
// documented plaintext development posture.
var _ LibraryStore = (*FileStore)(nil)

func (s *FileStore) librarySkillLocked(id string) *LibrarySkill {
	for _, skill := range s.librarySkills {
		if skill != nil && skill.ID == id {
			return skill
		}
	}
	return nil
}

func (s *FileStore) librarySkillVersionLocked(skillID, id string) *LibrarySkillVersion {
	for _, version := range s.librarySkillVersions {
		if version != nil && version.SkillID == skillID && version.ID == id {
			return version
		}
	}
	return nil
}

func (s *FileStore) librarySkillDraftLocked(id string) *LibrarySkillDraft {
	for _, draft := range s.librarySkillDrafts {
		if draft != nil && draft.ID == id {
			return draft
		}
	}
	return nil
}

func (s *FileStore) libraryBindingLocked(skillID, id string) *LibrarySkillBinding {
	for _, binding := range s.librarySkillBindings {
		if binding != nil && binding.SkillID == skillID && binding.ID == id {
			return binding
		}
	}
	return nil
}

// librarySkillBindingGenerationLocked is deliberately a raw lookup: an
// authorization read must never initialize a missing generation, because
// legacy or malformed receipts must fail closed rather than repair themselves.
func (s *FileStore) librarySkillBindingGenerationLocked(skillID string) int64 {
	if s.librarySkillBindingGenerations == nil {
		return 0
	}
	return s.librarySkillBindingGenerations[skillID]
}

func copyLibrarySkillBindingGenerations(in map[string]int64) map[string]int64 {
	if in == nil {
		return nil
	}
	out := make(map[string]int64, len(in))
	for skillID, generation := range in {
		out[skillID] = generation
	}
	return out
}

// ensureLibrarySkillBindingGenerationLocked establishes a durable baseline
// while holding FileStore's one write lock. It is used when a pre-generation
// FileStore has existing bindings and a new authorization lease captures the
// current binding state.
func (s *FileStore) ensureLibrarySkillBindingGenerationLocked(skillID string) int64 {
	if s.librarySkillBindingGenerations == nil {
		s.librarySkillBindingGenerations = make(map[string]int64)
	}
	if generation := s.librarySkillBindingGenerations[skillID]; generation > 0 {
		return generation
	}
	s.librarySkillBindingGenerations[skillID] = 1
	return 1
}

// bumpLibrarySkillBindingGenerationLocked must accompany every successful
// binding create, update, or delete. A generation is never reconstructed from
// the current binding set: that would allow add/remove restoration to regain
// a temporary client authoring permission.
func (s *FileStore) bumpLibrarySkillBindingGenerationLocked(skillID string) (int64, error) {
	if s.librarySkillBindingGenerations == nil {
		s.librarySkillBindingGenerations = make(map[string]int64)
	}
	generation := s.librarySkillBindingGenerations[skillID]
	if generation == int64(^uint64(0)>>1) {
		return 0, ErrLibraryBindingGenerationExhausted
	}
	generation++
	s.librarySkillBindingGenerations[skillID] = generation
	return generation, nil
}

func (s *FileStore) libraryArtifactLocked(id string) *LibraryArtifact {
	for _, artifact := range s.libraryArtifacts {
		if artifact != nil && artifact.ID == id {
			return artifact
		}
	}
	return nil
}

func (s *FileStore) libraryArtifactVersionLocked(artifactID, id string) *LibraryArtifactVersion {
	for _, version := range s.libraryArtifactVersions {
		if version != nil && version.ArtifactID == artifactID && version.ID == id {
			return version
		}
	}
	return nil
}

func (s *FileStore) libraryArtifactGrantLocked(artifactID, id string) *LibraryArtifactGrant {
	for _, grant := range s.libraryArtifactGrants {
		if grant != nil && grant.ArtifactID == artifactID && grant.ID == id {
			return grant
		}
	}
	return nil
}

func (s *FileStore) activeLibraryArtifactGrantLocked(artifactID, agentSurfaceID string) *LibraryArtifactGrant {
	for _, grant := range s.libraryArtifactGrants {
		if grant != nil && grant.ArtifactID == artifactID && grant.AgentSurfaceID == agentSurfaceID && grant.RevokedAt.IsZero() {
			return grant
		}
	}
	return nil
}

func (s *FileStore) libraryRunLocked(id string) *LibraryRun {
	for _, run := range s.libraryRuns {
		if run != nil && run.ID == id {
			return run
		}
	}
	return nil
}

// libraryArtifactSurfaceIDsLocked is the FileStore persistence counterpart to
// PgStore's queryable agent_surface_id column. The artifact's exported JSON
// intentionally omits this structural delivery key, so the local JSON file
// stores it in a separate projection map.
func (s *FileStore) libraryArtifactSurfaceIDsLocked() map[string]string {
	ids := make(map[string]string)
	for _, artifact := range s.libraryArtifacts {
		if artifact != nil && artifact.AgentSurfaceID != "" {
			ids[artifact.ID] = artifact.AgentSurfaceID
		}
	}
	return ids
}

// backfillLibraryArtifactSurfaceIDsLocked preserves subject-bound direct
// artifact visibility after upgrading a FileStore written before the
// projection key existed. It only accepts records whose immutable direct-run
// provenance still exactly matches a durable MCP client registration.
func (s *FileStore) backfillLibraryArtifactSurfaceIDsLocked() bool {
	changed := false
	for _, artifact := range s.libraryArtifacts {
		if artifact == nil || artifact.AgentSurfaceID != "" || artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.RunID == "" {
			continue
		}
		run := s.libraryRunLocked(artifact.RunID)
		if run == nil || run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != artifact.CreatedBy || run.SurfaceRef == "" {
			continue
		}
		client, found := s.mcpClientByIDLocked(run.SurfaceRef)
		if !found || client.Subject != run.ActorRef {
			continue
		}
		artifact.AgentSurfaceID = run.SurfaceRef
		changed = true
	}
	return changed
}

func (s *FileStore) LibrarySkills(_ context.Context) ([]LibrarySkill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibrarySkill, 0, len(s.librarySkills))
	for _, skill := range s.librarySkills {
		if skill != nil {
			out = append(out, copyLibrarySkill(*skill))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// LibraryConsoleSkillPage returns a most-recently-updated, metadata-only page
// for the management Console. It inspects immutable versions only to identify
// the latest summary; instruction Content never leaves this store method.
func (s *FileStore) LibraryConsoleSkillPage(_ context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleSkillPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleSkillPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleSkillPage{}, err
	}

	latestBySkill := make(map[string]*LibrarySkillVersion)
	for _, version := range s.librarySkillVersions {
		if version == nil {
			continue
		}
		latest := latestBySkill[version.SkillID]
		if latest == nil || version.Version > latest.Version {
			latestBySkill[version.SkillID] = version
		}
	}
	items := make([]LibraryConsoleSkill, 0, len(s.librarySkills))
	for _, skill := range s.librarySkills {
		if skill == nil {
			continue
		}
		if !cursor.Timestamp.IsZero() && !(skill.UpdatedAt.Before(cursor.Timestamp) || (skill.UpdatedAt.Equal(cursor.Timestamp) && skill.ID < cursor.ID)) {
			continue
		}
		item := LibraryConsoleSkill{Skill: copyLibrarySkill(*skill)}
		if latest := latestBySkill[skill.ID]; latest != nil {
			item.LatestVersion = &LibraryConsoleSkillVersionSummary{
				ID: latest.ID, Version: latest.Version, Digest: latest.Digest,
				RequestedCapabilities: append([]string(nil), latest.RequestedCapabilities...), CreatedAt: latest.CreatedAt,
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Skill.UpdatedAt.Equal(items[j].Skill.UpdatedAt) {
			return items[i].Skill.ID > items[j].Skill.ID
		}
		return items[i].Skill.UpdatedAt.After(items[j].Skill.UpdatedAt)
	})
	page := LibraryConsoleSkillPage{Skills: make([]LibraryConsoleSkill, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1].Skill
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.UpdatedAt, ID: last.ID}
		items = items[:limit]
	}
	page.Skills = append(page.Skills, items...)
	return page, nil
}

// LibraryMCPRootSkillPage builds the root MCP metadata projection under one
// FileStore lock. It scans immutable versions once to identify each latest
// version, rather than loading every version body separately per skill.
func (s *FileStore) LibraryMCPRootSkillPage(_ context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootSkillPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryMCPRootPageCursor(cursor); err != nil {
		return LibraryMCPRootSkillPage{}, err
	}
	limit, err := normalizeLibraryMCPRootPageLimit(limit)
	if err != nil {
		return LibraryMCPRootSkillPage{}, err
	}

	latestBySkill := make(map[string]*LibrarySkillVersion)
	for _, version := range s.librarySkillVersions {
		if version == nil {
			continue
		}
		latest := latestBySkill[version.SkillID]
		if latest == nil || version.Version > latest.Version {
			latestBySkill[version.SkillID] = version
		}
	}
	items := make([]LibraryMCPRootSkill, 0, len(s.librarySkills))
	for _, skill := range s.librarySkills {
		if skill == nil {
			continue
		}
		latest := latestBySkill[skill.ID]
		if latest == nil {
			continue
		}
		if !cursor.CreatedAt.IsZero() && !(skill.CreatedAt.Before(cursor.CreatedAt) || (skill.CreatedAt.Equal(cursor.CreatedAt) && skill.ID < cursor.ID)) {
			continue
		}
		items = append(items, LibraryMCPRootSkill{
			ID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
			LatestVersion: latest.Version, LatestVersionID: latest.ID, CreatedAt: skill.CreatedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	page := LibraryMCPRootSkillPage{Skills: make([]LibraryMCPRootSkill, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1]
		page.NextCursor = LibraryMCPRootPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
		items = items[:limit]
	}
	page.Skills = append(page.Skills, items...)
	return page, nil
}

func (s *FileStore) LibrarySkill(_ context.Context, id string) (LibrarySkill, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	skill := s.librarySkillLocked(id)
	if skill == nil {
		return LibrarySkill{}, false
	}
	return copyLibrarySkill(*skill), true
}

func (s *FileStore) CreateLibrarySkillWithInitialVersion(_ context.Context, skill LibrarySkill, version LibrarySkillVersion) (LibrarySkill, LibrarySkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isReservedBuiltInLibrarySkillIdentity(skill.ID, skill.Slug) || isReservedBuiltInLibraryVersionID(version.ID) {
		return LibrarySkill{}, LibrarySkillVersion{}, ErrLibraryBuiltInManaged
	}
	if skill.ID == "" {
		skill.ID = newLibrarySkillID()
	}
	if err := validateLibrarySkill(skill); err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	for _, existing := range s.librarySkills {
		if existing != nil && existing.Slug == skill.Slug {
			return LibrarySkill{}, LibrarySkillVersion{}, ErrLibrarySkillExists
		}
	}
	now := time.Now().UTC()
	skill.CreatedAt, skill.UpdatedAt = now, now
	version.SkillID = skill.ID
	version.Version = 1
	version.CreatedBy = firstNonEmpty(version.CreatedBy, skill.CreatedBy)
	normalized, err := normalizedLibraryVersion(version)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillVersionID()
	}
	skillCopy, versionCopy := copyLibrarySkill(skill), copyLibrarySkillVersion(normalized)
	s.librarySkills = append(s.librarySkills, &skillCopy)
	s.librarySkillVersions = append(s.librarySkillVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.librarySkills = s.librarySkills[:len(s.librarySkills)-1]
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	return copyLibrarySkill(skillCopy), copyLibrarySkillVersion(versionCopy), nil
}

func (s *FileStore) LibrarySkillVersions(_ context.Context, skillID string) ([]LibrarySkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibrarySkillVersion, 0)
	for _, version := range s.librarySkillVersions {
		if version != nil && version.SkillID == skillID {
			out = append(out, copyLibrarySkillVersion(*version))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func (s *FileStore) LibrarySkillVersion(_ context.Context, skillID, id string) (LibrarySkillVersion, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.librarySkillVersionLocked(skillID, id)
	if version == nil {
		return LibrarySkillVersion{}, false
	}
	return copyLibrarySkillVersion(*version), true
}

func (s *FileStore) CreateLibrarySkillVersion(_ context.Context, version LibrarySkillVersion) (LibrarySkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isBuiltInLibrarySkillID(version.SkillID) || isReservedBuiltInLibraryVersionID(version.ID) {
		return LibrarySkillVersion{}, ErrLibraryBuiltInManaged
	}
	skill := s.librarySkillLocked(version.SkillID)
	if skill == nil {
		return LibrarySkillVersion{}, ErrLibrarySkillNotFound
	}
	normalized, err := normalizedLibraryVersion(version)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillVersionID()
	}
	for _, existing := range s.librarySkillVersions {
		if existing != nil && existing.SkillID == normalized.SkillID && existing.ID == normalized.ID {
			return LibrarySkillVersion{}, ErrLibrarySkillVersionNotFound
		}
		if existing != nil && existing.SkillID == normalized.SkillID && existing.Version >= normalized.Version {
			normalized.Version = existing.Version + 1
		}
	}
	if normalized.Version <= 0 {
		normalized.Version = 1
	}
	copy := copyLibrarySkillVersion(normalized)
	previousUpdatedAt := skill.UpdatedAt
	skill.UpdatedAt = normalized.CreatedAt
	s.librarySkillVersions = append(s.librarySkillVersions, &copy)
	if err := s.saveLocked(); err != nil {
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		skill.UpdatedAt = previousUpdatedAt
		return LibrarySkillVersion{}, err
	}
	return copyLibrarySkillVersion(copy), nil
}

func (s *FileStore) CreateLibrarySkillDraft(_ context.Context, draft LibrarySkillDraft) (LibrarySkillDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if draft.ID == "" {
		draft.ID = newLibrarySkillDraftID()
	}
	if err := validateLibrarySkillDraft(draft); err != nil {
		return LibrarySkillDraft{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(draft.RequestedCapabilities)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	draft.RequestedCapabilities = capabilities
	assumptions, err := normalizeLibraryDraftAssumptions(draft.Assumptions)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	draft.Assumptions = assumptions
	if draft.CreatedAt.IsZero() {
		draft.CreatedAt = time.Now().UTC()
	}
	copy := copyLibrarySkillDraft(draft)
	s.librarySkillDrafts = append(s.librarySkillDrafts, &copy)
	if err := s.saveLocked(); err != nil {
		s.librarySkillDrafts = s.librarySkillDrafts[:len(s.librarySkillDrafts)-1]
		return LibrarySkillDraft{}, err
	}
	return copyLibrarySkillDraft(copy), nil
}

func (s *FileStore) LibrarySkillDraft(_ context.Context, id string) (LibrarySkillDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, draft := range s.librarySkillDrafts {
		if draft != nil && draft.ID == id {
			return copyLibrarySkillDraft(*draft), true
		}
	}
	return LibrarySkillDraft{}, false
}

// ImportPlatformLibrarySkillDraft atomically records an editable generated
// draft with its opaque Platform request identity. FileStore serializes this
// check-and-create under the same mutex and writes both records in one file
// replacement, so a retry after a lost response cannot create a second draft.
func (s *FileStore) ImportPlatformLibrarySkillDraft(_ context.Context, request LibraryPlatformSkillDraftImport, createdBy string) (LibrarySkillDraft, bool, error) {
	normalized, err := normalizeLibraryPlatformSkillDraftImport(request, createdBy)
	if err != nil {
		return LibrarySkillDraft{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.librarySkillDraftImports {
		if existing == nil || existing.RequestIDHash != normalized.record.RequestIDHash {
			continue
		}
		if existing.PayloadDigest != normalized.record.PayloadDigest {
			return LibrarySkillDraft{}, false, ErrLibraryDraftImportConflict
		}
		draft := s.librarySkillDraftLocked(existing.DraftID)
		if draft == nil {
			return LibrarySkillDraft{}, false, errors.New("platform draft import record references a missing draft")
		}
		return copyLibrarySkillDraft(*draft), true, nil
	}

	draft := normalized.draft
	draft.ID = newLibrarySkillDraftID()
	draft.CreatedAt = time.Now().UTC()
	record := normalized.record
	record.DraftID = draft.ID
	draftCopy := copyLibrarySkillDraft(draft)
	recordCopy := record
	s.librarySkillDrafts = append(s.librarySkillDrafts, &draftCopy)
	s.librarySkillDraftImports = append(s.librarySkillDraftImports, &recordCopy)
	if err := s.saveLocked(); err != nil {
		s.librarySkillDrafts = s.librarySkillDrafts[:len(s.librarySkillDrafts)-1]
		s.librarySkillDraftImports = s.librarySkillDraftImports[:len(s.librarySkillDraftImports)-1]
		return LibrarySkillDraft{}, false, err
	}
	return copyLibrarySkillDraft(draftCopy), false, nil
}

func (s *FileStore) libraryArtifactDraftLocked(id string) *LibraryArtifactDraft {
	for _, draft := range s.libraryArtifactDrafts {
		if draft != nil && draft.ID == id {
			return draft
		}
	}
	return nil
}

// CreateLibraryArtifactDraft stores an editable output candidate. A cited
// source must already be a stored version with the stated digest, checked
// under the same mutex that commits the draft.
func (s *FileStore) CreateLibraryArtifactDraft(_ context.Context, draft LibraryArtifactDraft) (LibraryArtifactDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if draft.ID == "" {
		draft.ID = newLibraryArtifactDraftID()
	}
	normalized, err := normalizedLibraryArtifactDraft(draft)
	if err != nil {
		return LibraryArtifactDraft{}, err
	}
	if err := s.validateLibraryArtifactSourceLocked(normalized.SourceArtifactID, normalized.SourceArtifactVersionID, normalized.SourceArtifactDigest); err != nil {
		return LibraryArtifactDraft{}, err
	}
	copy := copyLibraryArtifactDraft(normalized)
	s.libraryArtifactDrafts = append(s.libraryArtifactDrafts, &copy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactDrafts = s.libraryArtifactDrafts[:len(s.libraryArtifactDrafts)-1]
		return LibraryArtifactDraft{}, err
	}
	return copyLibraryArtifactDraft(copy), nil
}

func (s *FileStore) LibraryArtifactDraft(_ context.Context, id string) (LibraryArtifactDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft := s.libraryArtifactDraftLocked(id)
	if draft == nil {
		return LibraryArtifactDraft{}, false
	}
	return copyLibraryArtifactDraft(*draft), true
}

// ImportPlatformLibraryArtifactDraft mirrors the skill import: the hashed
// request identity and the draft are written in one file replacement, so a
// retry after a lost response replays the same draft.
func (s *FileStore) ImportPlatformLibraryArtifactDraft(_ context.Context, request LibraryPlatformArtifactDraftImport, createdBy string) (LibraryArtifactDraft, bool, error) {
	normalized, err := normalizeLibraryPlatformArtifactDraftImport(request, createdBy)
	if err != nil {
		return LibraryArtifactDraft{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.libraryArtifactDraftImports {
		if existing == nil || existing.RequestIDHash != normalized.record.RequestIDHash {
			continue
		}
		if existing.PayloadDigest != normalized.record.PayloadDigest {
			return LibraryArtifactDraft{}, false, ErrLibraryDraftImportConflict
		}
		draft := s.libraryArtifactDraftLocked(existing.DraftID)
		if draft == nil {
			return LibraryArtifactDraft{}, false, errors.New("platform draft import record references a missing draft")
		}
		return copyLibraryArtifactDraft(*draft), true, nil
	}
	if err := s.validateLibraryArtifactSourceLocked(normalized.draft.SourceArtifactID, normalized.draft.SourceArtifactVersionID, normalized.draft.SourceArtifactDigest); err != nil {
		return LibraryArtifactDraft{}, false, err
	}

	draft := normalized.draft
	draft.ID = newLibraryArtifactDraftID()
	draft.CreatedAt = time.Now().UTC()
	record := normalized.record
	record.DraftID = draft.ID
	draftCopy := copyLibraryArtifactDraft(draft)
	recordCopy := record
	s.libraryArtifactDrafts = append(s.libraryArtifactDrafts, &draftCopy)
	s.libraryArtifactDraftImports = append(s.libraryArtifactDraftImports, &recordCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactDrafts = s.libraryArtifactDrafts[:len(s.libraryArtifactDrafts)-1]
		s.libraryArtifactDraftImports = s.libraryArtifactDraftImports[:len(s.libraryArtifactDraftImports)-1]
		return LibraryArtifactDraft{}, false, err
	}
	return copyLibraryArtifactDraft(draftCopy), false, nil
}

// LibrarySkillRuns returns the newest skill_run provenance for a skill. It
// deliberately ignores which version ran: evidence that a skill was used at
// all is what the Console shows.
func (s *FileStore) LibrarySkillRuns(_ context.Context, skillID string, limit int) ([]LibraryRun, error) {
	if limit <= 0 {
		return []LibraryRun{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryRun, 0)
	for _, run := range s.libraryRuns {
		if run != nil && run.Origin == LibraryRunOriginSkillRun && run.SkillID == skillID {
			out = append(out, copyLibraryRun(*run))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// LibraryArtifactCitations lists the newest artifacts whose immutable source
// tuple names this artifact. VersionID is the cited source version.
func (s *FileStore) LibraryArtifactCitations(_ context.Context, artifactID string, limit int) ([]LibraryArtifactCitation, error) {
	if limit <= 0 {
		return []LibraryArtifactCitation{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryArtifactCitation, 0)
	for _, artifact := range s.libraryArtifacts {
		if artifact != nil && artifact.SourceArtifactID == artifactID {
			out = append(out, LibraryArtifactCitation{ArtifactID: artifact.ID, Title: artifact.Title, VersionID: artifact.SourceArtifactVersionID, CreatedAt: artifact.CreatedAt})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ArtifactID > out[j].ArtifactID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *FileStore) LibrarySkillBindings(_ context.Context, skillID string) ([]LibrarySkillBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibrarySkillBinding, 0)
	for _, binding := range s.librarySkillBindings {
		if binding != nil && binding.SkillID == skillID {
			out = append(out, copyLibrarySkillBinding(*binding))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Priority > out[j].Priority
	})
	return out, nil
}

// LibrarySkillResolutionSelections snapshots the full generic resolution view
// under one FileStore lock. A tracking binding must not escape that lock and
// then pick up a version created after the binding was deleted or replaced.
func (s *FileStore) LibrarySkillResolutionSelections(_ context.Context, request LibrarySkillResolutionRequest) ([]LibraryResolvedSkill, error) {
	if err := validateLibraryResolutionRequest(request); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	skills := make([]LibrarySkill, 0, len(s.librarySkills))
	for _, skill := range s.librarySkills {
		if skill != nil {
			skills = append(skills, copyLibrarySkill(*skill))
		}
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].CreatedAt.Before(skills[j].CreatedAt) })

	bindingsBySkill := make(map[string][]LibrarySkillBinding, len(skills))
	for _, binding := range s.librarySkillBindings {
		if binding != nil {
			bindingsBySkill[binding.SkillID] = append(bindingsBySkill[binding.SkillID], copyLibrarySkillBinding(*binding))
		}
	}
	versionsBySkill := make(map[string][]LibrarySkillVersion, len(skills))
	for _, version := range s.librarySkillVersions {
		if version != nil {
			versionsBySkill[version.SkillID] = append(versionsBySkill[version.SkillID], copyLibrarySkillVersion(*version))
		}
	}
	return resolveLibrarySkillSnapshot(request, skills, bindingsBySkill, versionsBySkill)
}

// LibraryAgentSurfaceSkillSelections captures each explicit client binding and
// its resolved pin/track version under one FileStore lock. The resolver must
// not first list a binding, release the lock, then separately fetch a newer
// tracked version after an administrator has changed the surface assignment.
func (s *FileStore) LibraryAgentSurfaceSkillSelections(_ context.Context, agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.libraryAgentSurfaceSkillSelectionsLocked(agentSurfaceID)
}

func (s *FileStore) libraryAgentSurfaceSkillSelectionsLocked(agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	selected := make(map[string]LibraryAgentSurfaceSkillSelection)
	for _, binding := range s.librarySkillBindings {
		if binding == nil || binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != agentSurfaceID {
			continue
		}
		skill := s.librarySkillLocked(binding.SkillID)
		if skill == nil {
			return nil, ErrLibrarySkillNotFound
		}
		var version *LibrarySkillVersion
		switch binding.Mode {
		case LibraryBindingModePin:
			version = s.librarySkillVersionLocked(binding.SkillID, binding.PinnedVersionID)
		case LibraryBindingModeTrack:
			for _, candidate := range s.librarySkillVersions {
				if candidate != nil && candidate.SkillID == binding.SkillID && (version == nil || candidate.Version > version.Version) {
					version = candidate
				}
			}
		default:
			return nil, fmt.Errorf("invalid library binding mode %q", binding.Mode)
		}
		if version == nil {
			return nil, ErrLibrarySkillVersionNotFound
		}
		candidate := LibraryAgentSurfaceSkillSelection{
			Skill: copyLibrarySkill(*skill), Binding: copyLibrarySkillBinding(*binding), Version: copyLibrarySkillVersion(*version),
		}
		current, exists := selected[skill.ID]
		if !exists || candidate.Binding.Priority > current.Binding.Priority || (candidate.Binding.Priority == current.Binding.Priority && candidate.Binding.ID < current.Binding.ID) {
			selected[skill.ID] = candidate
		}
	}
	out := make([]LibraryAgentSurfaceSkillSelection, 0, len(selected))
	for _, selection := range selected {
		out = append(out, selection)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Binding.Priority != out[j].Binding.Priority {
			return out[i].Binding.Priority > out[j].Binding.Priority
		}
		if out[i].Skill.Slug != out[j].Skill.Slug {
			return out[i].Skill.Slug < out[j].Skill.Slug
		}
		return out[i].Skill.ID < out[j].Skill.ID
	})
	return out, nil
}

func (s *FileStore) UpsertLibrarySkillBinding(_ context.Context, binding LibrarySkillBinding) (LibrarySkillBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isBuiltInLibrarySkillID(binding.SkillID) || isReservedBuiltInLibraryBindingID(binding.ID) {
		return LibrarySkillBinding{}, ErrLibraryBuiltInManaged
	}
	normalized, err := normalizedLibraryBinding(binding)
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	if s.librarySkillLocked(normalized.SkillID) == nil {
		return LibrarySkillBinding{}, ErrLibrarySkillNotFound
	}
	if normalized.Mode == LibraryBindingModePin && s.librarySkillVersionLocked(normalized.SkillID, normalized.PinnedVersionID) == nil {
		return LibrarySkillBinding{}, ErrLibrarySkillVersionNotFound
	}
	for _, existing := range s.librarySkillBindings {
		if existing == nil || existing.SkillID != normalized.SkillID || existing.ScopeKind != normalized.ScopeKind || existing.ScopeID != normalized.ScopeID {
			continue
		}
		before := copyLibrarySkillBinding(*existing)
		beforeGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
		normalized.ID, normalized.CreatedAt = existing.ID, existing.CreatedAt
		*existing = copyLibrarySkillBinding(normalized)
		if _, err := s.bumpLibrarySkillBindingGenerationLocked(normalized.SkillID); err != nil {
			*existing = before
			s.librarySkillBindingGenerations = beforeGenerations
			return LibrarySkillBinding{}, err
		}
		if err := s.saveLocked(); err != nil {
			*existing = before
			s.librarySkillBindingGenerations = beforeGenerations
			return LibrarySkillBinding{}, err
		}
		return copyLibrarySkillBinding(*existing), nil
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillBindingID()
	}
	copy := copyLibrarySkillBinding(normalized)
	beforeGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
	if _, err := s.bumpLibrarySkillBindingGenerationLocked(normalized.SkillID); err != nil {
		s.librarySkillBindingGenerations = beforeGenerations
		return LibrarySkillBinding{}, err
	}
	s.librarySkillBindings = append(s.librarySkillBindings, &copy)
	if err := s.saveLocked(); err != nil {
		s.librarySkillBindings = s.librarySkillBindings[:len(s.librarySkillBindings)-1]
		s.librarySkillBindingGenerations = beforeGenerations
		return LibrarySkillBinding{}, err
	}
	return copyLibrarySkillBinding(copy), nil
}

func (s *FileStore) DeleteLibrarySkillBinding(_ context.Context, skillID, bindingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isBuiltInLibrarySkillID(skillID) {
		return ErrLibraryBuiltInManaged
	}
	for i, binding := range s.librarySkillBindings {
		if binding == nil || binding.SkillID != skillID || binding.ID != bindingID {
			continue
		}
		removed := binding
		beforeGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
		if _, err := s.bumpLibrarySkillBindingGenerationLocked(skillID); err != nil {
			s.librarySkillBindingGenerations = beforeGenerations
			return err
		}
		s.librarySkillBindings = append(s.librarySkillBindings[:i], s.librarySkillBindings[i+1:]...)
		if err := s.saveLocked(); err != nil {
			s.librarySkillBindings = append(s.librarySkillBindings, nil)
			copy(s.librarySkillBindings[i+1:], s.librarySkillBindings[i:])
			s.librarySkillBindings[i] = removed
			s.librarySkillBindingGenerations = beforeGenerations
			return err
		}
		return nil
	}
	return ErrLibraryBindingNotFound
}

func (s *FileStore) LibrarySkillEvaluations(_ context.Context, skillID string) ([]LibrarySkillEvaluation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibrarySkillEvaluation, 0)
	for _, evaluation := range s.librarySkillEvaluations {
		if evaluation != nil && evaluation.SkillID == skillID {
			out = append(out, copyLibrarySkillEvaluation(*evaluation))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) CreateLibrarySkillEvaluation(_ context.Context, evaluation LibrarySkillEvaluation) (LibrarySkillEvaluation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.librarySkillLocked(evaluation.SkillID) == nil {
		return LibrarySkillEvaluation{}, ErrLibrarySkillNotFound
	}
	if s.librarySkillVersionLocked(evaluation.SkillID, evaluation.SkillVersionID) == nil {
		return LibrarySkillEvaluation{}, ErrLibrarySkillVersionNotFound
	}
	if evaluation.ID == "" {
		evaluation.ID = newLibrarySkillEvaluationID()
	}
	if err := validateLibraryEvaluation(evaluation); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	if evaluation.CreatedAt.IsZero() {
		evaluation.CreatedAt = time.Now().UTC()
	}
	copy := copyLibrarySkillEvaluation(evaluation)
	s.librarySkillEvaluations = append(s.librarySkillEvaluations, &copy)
	if err := s.saveLocked(); err != nil {
		s.librarySkillEvaluations = s.librarySkillEvaluations[:len(s.librarySkillEvaluations)-1]
		return LibrarySkillEvaluation{}, err
	}
	return copyLibrarySkillEvaluation(copy), nil
}

func (s *FileStore) LibraryRuns(_ context.Context) ([]LibraryRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryRun, 0, len(s.libraryRuns))
	for _, run := range s.libraryRuns {
		if run != nil {
			out = append(out, copyLibraryRun(*run))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

// LibraryConsoleRunPage returns one newest-first management page. It keeps
// the legacy full run API intact for explicit reads, while bounding the list
// response that grows with every execution.
func (s *FileStore) LibraryConsoleRunPage(_ context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleRunPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleRunPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleRunPage{}, err
	}

	items := make([]LibraryRun, 0, len(s.libraryRuns))
	for _, run := range s.libraryRuns {
		if run == nil {
			continue
		}
		if !cursor.Timestamp.IsZero() && !(run.StartedAt.Before(cursor.Timestamp) || (run.StartedAt.Equal(cursor.Timestamp) && run.ID < cursor.ID)) {
			continue
		}
		items = append(items, copyLibraryRun(*run))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].StartedAt.Equal(items[j].StartedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	page := LibraryConsoleRunPage{Runs: make([]LibraryRun, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1]
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.StartedAt, ID: last.ID}
		items = items[:limit]
	}
	page.Runs = append(page.Runs, items...)
	return page, nil
}

func (s *FileStore) LibraryRun(_ context.Context, id string) (LibraryRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.libraryRunLocked(id)
	if run == nil {
		return LibraryRun{}, false
	}
	return copyLibraryRun(*run), true
}

func (s *FileStore) CreateLibraryRun(_ context.Context, run LibraryRun) (LibraryRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := normalizedLibraryRun(run)
	if err != nil {
		return LibraryRun{}, err
	}
	if normalized.Attestation == LibraryRunAttestationHost {
		return LibraryRun{}, ErrLibraryRuntimeAttestationInvalid
	}
	if normalized.Origin == LibraryRunOriginSkillRun {
		if s.librarySkillLocked(normalized.SkillID) == nil || s.librarySkillVersionLocked(normalized.SkillID, normalized.SkillVersionID) == nil || s.libraryBindingLocked(normalized.SkillID, normalized.BindingID) == nil {
			return LibraryRun{}, ErrLibrarySkillVersionNotFound
		}
	}
	if err := s.validateLibraryArtifactSourceLocked(normalized.SourceArtifactID, normalized.SourceArtifactVersionID, normalized.SourceArtifactDigest); err != nil {
		return LibraryRun{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryRunID()
	}
	if s.libraryRunLocked(normalized.ID) != nil {
		return LibraryRun{}, ErrLibraryRunNotFound
	}
	copy := copyLibraryRun(normalized)
	s.libraryRuns = append(s.libraryRuns, &copy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		return LibraryRun{}, err
	}
	return copyLibraryRun(copy), nil
}

// validateLibraryArtifactSourceLocked proves that a persisted direct-run
// citation names the exact immutable body digest. Access policy is enforced
// by the subject-bound MCP ingress before this store call; this durable check
// prevents a trusted/internal caller from persisting a dangling or forged
// version reference.
func (s *FileStore) validateLibraryArtifactSourceLocked(artifactID, versionID, digest string) error {
	if artifactID == "" {
		return nil
	}
	if s.libraryArtifactLocked(artifactID) == nil {
		return ErrLibraryArtifactNotFound
	}
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if version == nil || version.Digest != digest {
		return ErrLibraryArtifactVersionNotFound
	}
	return nil
}

func (s *FileStore) LibraryArtifacts(_ context.Context) ([]LibraryArtifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryArtifact, 0, len(s.libraryArtifacts))
	for _, artifact := range s.libraryArtifacts {
		if artifact != nil {
			out = append(out, copyLibraryArtifact(*artifact))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// LibraryConsoleArtifactPage returns the bounded metadata list used by the
// management Console. Immutable version bodies remain explicit detail reads.
func (s *FileStore) LibraryConsoleArtifactPage(_ context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleArtifactPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleArtifactPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleArtifactPage{}, err
	}

	items := make([]LibraryConsoleArtifact, 0, len(s.libraryArtifacts))
	for _, artifact := range s.libraryArtifacts {
		if artifact == nil {
			continue
		}
		if !cursor.Timestamp.IsZero() && !(artifact.CreatedAt.Before(cursor.Timestamp) || (artifact.CreatedAt.Equal(cursor.Timestamp) && artifact.ID < cursor.ID)) {
			continue
		}
		items = append(items, LibraryConsoleArtifact{Artifact: copyLibraryArtifact(*artifact)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Artifact.CreatedAt.Equal(items[j].Artifact.CreatedAt) {
			return items[i].Artifact.ID > items[j].Artifact.ID
		}
		return items[i].Artifact.CreatedAt.After(items[j].Artifact.CreatedAt)
	})
	page := LibraryConsoleArtifactPage{Artifacts: make([]LibraryConsoleArtifact, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1].Artifact
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.CreatedAt, ID: last.ID}
		items = items[:limit]
	}
	// Only the page's artifacts get a latest-version summary. Bodies stay in
	// the version records; an image's MIME type comes from blob metadata.
	for index := range items {
		if latest := s.latestLibraryArtifactVersionLocked(items[index].Artifact.ID); latest != nil {
			items[index].LatestVersion = s.libraryConsoleArtifactVersionSummaryLocked(*latest)
		}
	}
	page.Artifacts = append(page.Artifacts, items...)
	return page, nil
}

func (s *FileStore) libraryConsoleArtifactVersionSummaryLocked(version LibraryArtifactVersion) *LibraryConsoleArtifactVersionSummary {
	summary := &LibraryConsoleArtifactVersionSummary{
		ID: version.ID, Version: version.Version, Format: version.Format, Digest: version.Digest, SizeBytes: version.SizeBytes,
		RedactionStatus: version.RedactionStatus, ReviewedAt: version.ReviewedAt, CreatedAt: version.CreatedAt,
	}
	if version.Format == LibraryArtifactFormatImage {
		if blob := s.libraryArtifactMediaBlobLocked(version.ID); blob != nil {
			summary.MIMEType = blob.MIMEType
		}
	}
	return summary
}

// LibraryMCPRootArtifactPage is the root MCP's bounded artifact metadata
// projection. It intentionally excludes version bodies and provenance fields;
// callers must use the explicit artifact read tool for a body.
func (s *FileStore) LibraryMCPRootArtifactPage(_ context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootArtifactPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryMCPRootPageCursor(cursor); err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}
	limit, err := normalizeLibraryMCPRootPageLimit(limit)
	if err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}

	items := make([]LibraryMCPRootArtifact, 0, len(s.libraryArtifacts))
	for _, artifact := range s.libraryArtifacts {
		if artifact == nil {
			continue
		}
		if !cursor.CreatedAt.IsZero() && !(artifact.CreatedAt.Before(cursor.CreatedAt) || (artifact.CreatedAt.Equal(cursor.CreatedAt) && artifact.ID < cursor.ID)) {
			continue
		}
		items = append(items, LibraryMCPRootArtifact{
			ID: artifact.ID, Title: artifact.Title, Summary: artifact.Summary, Origin: artifact.Origin, CreatedAt: artifact.CreatedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	page := LibraryMCPRootArtifactPage{Artifacts: make([]LibraryMCPRootArtifact, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1]
		page.NextCursor = LibraryMCPRootPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
		items = items[:limit]
	}
	page.Artifacts = append(page.Artifacts, items...)
	return page, nil
}

func (s *FileStore) LibraryArtifact(_ context.Context, id string) (LibraryArtifact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	artifact := s.libraryArtifactLocked(id)
	if artifact == nil {
		return LibraryArtifact{}, false
	}
	return copyLibraryArtifact(*artifact), true
}

func (s *FileStore) validateLibraryArtifactProvenanceLocked(artifact LibraryArtifact) error {
	if err := validateLibraryArtifact(artifact); err != nil {
		return err
	}
	if artifact.RunID != "" {
		run := s.libraryRunLocked(artifact.RunID)
		if run == nil {
			return ErrLibraryRunNotFound
		}
		if run.Origin != artifact.Origin || (artifact.Origin == LibraryArtifactOriginSkillRun && (run.SkillID != artifact.SkillID || run.SkillVersionID != artifact.SkillVersionID || run.BindingID != artifact.BindingID || (artifact.AgentSurfaceID != "" && (run.Attestation != LibraryRunAttestationHost || run.ActorRef != artifact.CreatedBy || run.SurfaceRef != artifact.AgentSurfaceID)))) || (artifact.Origin == LibraryArtifactOriginAgentDirect && (run.SourceArtifactID != artifact.SourceArtifactID || run.SourceArtifactVersionID != artifact.SourceArtifactVersionID || run.SourceArtifactDigest != artifact.SourceArtifactDigest || (artifact.AgentSurfaceID != "" && (run.ActorRef != artifact.CreatedBy || run.SurfaceRef != artifact.AgentSurfaceID)))) {
			return errorsNewLibraryProvenanceMismatch()
		}
	}
	if err := s.validateLibraryArtifactSourceLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return err
	}
	if artifact.Origin == LibraryArtifactOriginSkillRun {
		if s.librarySkillLocked(artifact.SkillID) == nil || s.librarySkillVersionLocked(artifact.SkillID, artifact.SkillVersionID) == nil || s.libraryBindingLocked(artifact.SkillID, artifact.BindingID) == nil {
			return ErrLibrarySkillVersionNotFound
		}
	}
	return nil
}

func errorsNewLibraryProvenanceMismatch() error {
	return errors.New("artifact provenance does not match run")
}

func (s *FileStore) CreateLibraryArtifactWithInitialVersion(_ context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if artifact.ID == "" {
		artifact.ID = newLibraryArtifactID()
	}
	if err := s.validateLibraryArtifactProvenanceLocked(artifact); err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	version.ArtifactID, version.Version = artifact.ID, 1
	version.CreatedBy = firstNonEmpty(version.CreatedBy, artifact.CreatedBy)
	normalized, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryArtifactVersionID()
	}
	artifactCopy, versionCopy := copyLibraryArtifact(artifact), copyLibraryArtifactVersion(normalized)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// CreateLibraryHumanArtifactWithInitialVersion records a Console-created
// human artifact together with the run that carries its source citation.
// The citation is re-checked under the same mutex that commits all three
// records, so a stale digest cannot slip in between validation and save.
func (s *FileStore) CreateLibraryHumanArtifactWithInitialVersion(_ context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	run, artifact, version, err := prepareLibraryHumanArtifact(artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if err := s.validateLibraryArtifactSourceLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// CreateLibraryRootMCPArtifactWithInitialVersion records a root-MCP direct
// artifact and its provenance run in one FileStore mutex/save cycle. Source
// access is rechecked under that same lock, and a failed save rolls every
// appended record back together.
func (s *FileStore) CreateLibraryRootMCPArtifactWithInitialVersion(_ context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	run, artifact, version, err := prepareLibraryRootMCPArtifact(artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if artifact.SourceArtifactID != "" && !s.libraryRootMCPMayUseArtifactVersionLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// libraryRootMCPMayUseArtifactVersionLocked permits a source citation only
// when it is one exact immutable version of a prior root-MCP direct artifact.
// Root MCP has no durable subject-bound client registration and therefore
// cannot use grants or another client's private artifact.
func (s *FileStore) libraryRootMCPMayUseArtifactVersionLocked(artifactID, versionID, digest string) bool {
	artifact := s.libraryArtifactLocked(artifactID)
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if artifact == nil || version == nil || version.Digest != digest {
		return false
	}
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.CreatedBy != libraryRootMCPActorRef || artifact.AgentSurfaceID != "" || artifact.RunID == "" {
		return false
	}
	run := s.libraryRunLocked(artifact.RunID)
	return run != nil && run.Origin == LibraryRunOriginAgentDirect && run.ActorRef == libraryRootMCPActorRef && run.SurfaceRef == libraryRootMCPSurfaceRef
}

// CreateLibraryMCPClientArtifactWithInitialVersion records a subject-bound
// direct artifact and its provenance run in one FileStore mutex/save cycle.
// A revocation or source-grant change cannot interleave between the client
// lookup, access decision, and durable write.
func (s *FileStore) CreateLibraryMCPClientArtifactWithInitialVersion(_ context.Context, client MCPClient, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	storedClient, found := s.mcpClientByIDLocked(client.ID)
	if !found || storedClient.Subject != client.Subject {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if storedClient.Status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientRevoked
	}
	run, artifact, version, err := prepareLibraryMCPClientArtifact(*storedClient, artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if artifact.SourceArtifactID != "" && !s.libraryMCPClientMayUseArtifactVersionLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, *storedClient) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	if err := s.validateLibraryArtifactSourceLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// IngestLibraryRuntimeAttestation is the only FileStore write path for a
// host-attested skill result. It replays every cryptographic and selection
// check while holding the same mutex used to commit the run, artifact, first
// immutable version, and idempotency record.
func (s *FileStore) IngestLibraryRuntimeAttestation(_ context.Context, attestation LibraryRuntimeAttestation) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, found := s.mcpClientByIDLocked(attestation.ClientID)
	if !found {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrMCPClientNotFound
	}
	if client.Status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrMCPClientRevoked
	}
	now := time.Now().UTC()
	parsed, err := verifyLibraryRuntimeAttestation(*client, attestation, now)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	currentBuiltInVersionID, builtInManifestInstalled := s.builtInLibraryCurrentVersionLocked(usingSynaxisSkillID)
	selections, err := s.libraryAgentSurfaceSkillSelectionsLocked(client.ID)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if err := validateLibraryRuntimeAttestationSelection(*client, parsed, selections, currentBuiltInVersionID, builtInManifestInstalled); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	executionHash := libraryRuntimeAttestationExecutionHash(client.ID, client.Epoch, parsed.Request.ExecutionID)
	nonceHash := libraryRuntimeAttestationNonceHash(client.ID, client.Epoch, parsed.Request.Nonce)
	for _, record := range s.libraryRuntimeAttestations {
		if record == nil || record.ClientID != client.ID || record.ClientEpoch != client.Epoch {
			continue
		}
		if record.ExecutionHash == executionHash {
			if record.RequestDigest != parsed.RequestDigest {
				return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationConflict
			}
			run := s.libraryRunLocked(record.RunID)
			if run == nil || run.Origin != LibraryRunOriginSkillRun || run.Attestation != LibraryRunAttestationHost || run.ActorRef != client.Subject || run.SurfaceRef != client.ID {
				return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
			}
			for _, artifact := range s.libraryArtifacts {
				if artifact == nil || artifact.RunID != run.ID || artifact.Origin != LibraryArtifactOriginSkillRun || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject {
					continue
				}
				for _, version := range s.libraryArtifactVersions {
					if version != nil && version.ArtifactID == artifact.ID && version.Version == 1 {
						return copyLibraryRun(*run), copyLibraryArtifact(*artifact), copyLibraryArtifactVersion(*version), true, nil
					}
				}
			}
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
		}
		if record.NonceHash == nonceHash {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationReplay
		}
	}

	run, artifact, version, err := prepareLibraryRuntimeAttestationOutput(*client, parsed, now)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
	}
	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	record := libraryRuntimeAttestationRecord{RunID: run.ID, ClientID: client.ID, ClientEpoch: client.Epoch, ExecutionHash: executionHash, NonceHash: nonceHash, RequestDigest: parsed.RequestDigest}
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryRuntimeAttestations = append(s.libraryRuntimeAttestations, &record)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryRuntimeAttestations = s.libraryRuntimeAttestations[:len(s.libraryRuntimeAttestations)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), false, nil
}

func (s *FileStore) libraryMCPClientMayUseArtifactVersionLocked(artifactID, versionID, digest string, client MCPClient) bool {
	artifact := s.libraryArtifactLocked(artifactID)
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if artifact == nil || version == nil || version.Digest != digest {
		return false
	}
	if artifact.Origin == LibraryArtifactOriginAgentDirect && artifact.AgentSurfaceID == client.ID && artifact.CreatedBy == client.Subject && artifact.RunID != "" {
		run := s.libraryRunLocked(artifact.RunID)
		if run != nil && run.Origin == LibraryRunOriginAgentDirect && run.ActorRef == client.Subject && run.SurfaceRef == client.ID {
			return true
		}
	}
	grant := s.activeLibraryArtifactGrantLocked(artifactID, client.ID)
	return grant != nil && grant.ArtifactVersionID == versionID && grant.ArtifactVersionDigest == digest
}

// LibraryMCPClientArtifactPage projects one live client surface directly from
// its ownership key and grants. It deliberately avoids LibraryArtifacts plus
// a per-artifact run/grant lookup, which scaled with the entire workspace.
func (s *FileStore) LibraryMCPClientArtifactPage(_ context.Context, client MCPClient, cursor LibraryMCPClientArtifactCursor, limit int) (LibraryMCPClientArtifactPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	storedClient, found := s.mcpClientByIDLocked(client.ID)
	if !found || storedClient.Subject != client.Subject {
		return LibraryMCPClientArtifactPage{}, ErrMCPClientNotFound
	}
	if storedClient.Status != MCPClientStatusActive {
		return LibraryMCPClientArtifactPage{}, ErrMCPClientRevoked
	}
	if cursor.CreatedAt.IsZero() != (cursor.ArtifactID == "") {
		return LibraryMCPClientArtifactPage{}, errors.New("invalid artifact page cursor")
	}
	if cursor.ArtifactID != "" {
		if err := validateLibraryOpaqueRef("artifact page cursor", cursor.ArtifactID, false); err != nil {
			return LibraryMCPClientArtifactPage{}, err
		}
	}
	limit, err := normalizeLibraryMCPClientArtifactPageLimit(limit)
	if err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}

	byID := make(map[string]LibraryMCPClientArtifact)
	for _, grant := range s.libraryArtifactGrants {
		if grant == nil || grant.AgentSurfaceID != storedClient.ID || !grant.RevokedAt.IsZero() {
			continue
		}
		artifact := s.libraryArtifactLocked(grant.ArtifactID)
		version := s.libraryArtifactVersionLocked(grant.ArtifactID, grant.ArtifactVersionID)
		if artifact == nil || version == nil || version.Digest != grant.ArtifactVersionDigest {
			continue
		}
		byID[artifact.ID] = LibraryMCPClientArtifact{Artifact: libraryArtifactMetadata(*artifact), Version: libraryArtifactVersionMetadata(*version), Access: "granted"}
	}
	for _, artifact := range s.libraryArtifacts {
		if artifact == nil || artifact.AgentSurfaceID != storedClient.ID || artifact.CreatedBy != storedClient.Subject || artifact.RunID == "" {
			continue
		}
		run := s.libraryRunLocked(artifact.RunID)
		if run == nil || run.ActorRef != storedClient.Subject || run.SurfaceRef != storedClient.ID ||
			!((artifact.Origin == LibraryArtifactOriginAgentDirect && run.Origin == LibraryRunOriginAgentDirect) ||
				(artifact.Origin == LibraryArtifactOriginSkillRun && run.Origin == LibraryRunOriginSkillRun && run.Attestation == LibraryRunAttestationHost)) {
			continue
		}
		var latest *LibraryArtifactVersion
		for _, version := range s.libraryArtifactVersions {
			if version != nil && version.ArtifactID == artifact.ID && (latest == nil || version.Version > latest.Version) {
				latest = version
			}
		}
		if latest != nil {
			byID[artifact.ID] = LibraryMCPClientArtifact{Artifact: libraryArtifactMetadata(*artifact), Version: libraryArtifactVersionMetadata(*latest), Access: "owned"}
		}
	}

	items := make([]LibraryMCPClientArtifact, 0, len(byID))
	for _, item := range byID {
		if cursor.CreatedAt.IsZero() || item.Artifact.CreatedAt.Before(cursor.CreatedAt) || (item.Artifact.CreatedAt.Equal(cursor.CreatedAt) && item.Artifact.ID < cursor.ArtifactID) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Artifact.CreatedAt.Equal(items[j].Artifact.CreatedAt) {
			return items[i].Artifact.ID > items[j].Artifact.ID
		}
		return items[i].Artifact.CreatedAt.After(items[j].Artifact.CreatedAt)
	})
	page := LibraryMCPClientArtifactPage{Artifacts: make([]LibraryMCPClientArtifact, 0, min(limit, len(items)))}
	if len(items) > limit {
		last := items[limit-1].Artifact
		page.NextCursor = LibraryMCPClientArtifactCursor{CreatedAt: last.CreatedAt, ArtifactID: last.ID}
		items = items[:limit]
	}
	page.Artifacts = append(page.Artifacts, items...)
	return page, nil
}

func (s *FileStore) LibraryArtifactVersions(_ context.Context, artifactID string) ([]LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryArtifactVersion, 0)
	for _, version := range s.libraryArtifactVersions {
		if version != nil && version.ArtifactID == artifactID {
			out = append(out, copyLibraryArtifactVersion(*version))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func (s *FileStore) LibraryArtifactVersion(_ context.Context, artifactID, id string) (LibraryArtifactVersion, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.libraryArtifactVersionLocked(artifactID, id)
	if version == nil {
		return LibraryArtifactVersion{}, false
	}
	return copyLibraryArtifactVersion(*version), true
}

func (s *FileStore) CreateLibraryArtifactVersion(_ context.Context, version LibraryArtifactVersion) (LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.libraryArtifactLocked(version.ArtifactID) == nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	normalized, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryArtifactVersionID()
	}
	// A text revision never follows an image head; the image path enforces
	// the reverse. History stays in one media class per artifact.
	if latest := s.latestLibraryArtifactVersionLocked(normalized.ArtifactID); latest != nil && latest.Format == LibraryArtifactFormatImage {
		return LibraryArtifactVersion{}, ErrLibraryArtifactFormatMismatch
	}
	for _, existing := range s.libraryArtifactVersions {
		if existing != nil && existing.ArtifactID == normalized.ArtifactID && existing.ID == normalized.ID {
			return LibraryArtifactVersion{}, ErrLibraryArtifactVersionNotFound
		}
		if existing != nil && existing.ArtifactID == normalized.ArtifactID && existing.Version >= normalized.Version {
			normalized.Version = existing.Version + 1
		}
	}
	if normalized.Version <= 0 {
		normalized.Version = 1
	}
	copy := copyLibraryArtifactVersion(normalized)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &copy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		return LibraryArtifactVersion{}, err
	}
	return copyLibraryArtifactVersion(copy), nil
}

func (s *FileStore) LibraryArtifactGrants(_ context.Context, artifactID string) ([]LibraryArtifactGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryArtifactGrant, 0)
	for _, grant := range s.libraryArtifactGrants {
		if grant != nil && grant.ArtifactID == artifactID {
			out = append(out, copyLibraryArtifactGrant(*grant))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) ActiveLibraryArtifactGrantsForAgentSurface(_ context.Context, agentSurfaceID string) ([]LibraryArtifactGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryArtifactGrant, 0)
	for _, grant := range s.libraryArtifactGrants {
		if grant != nil && grant.AgentSurfaceID == agentSurfaceID && grant.RevokedAt.IsZero() {
			out = append(out, copyLibraryArtifactGrant(*grant))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) ActiveLibraryArtifactGrant(_ context.Context, artifactID, agentSurfaceID string) (LibraryArtifactGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant := s.activeLibraryArtifactGrantLocked(artifactID, agentSurfaceID)
	if grant == nil {
		return LibraryArtifactGrant{}, false
	}
	return copyLibraryArtifactGrant(*grant), true
}

func (s *FileStore) CreateLibraryArtifactGrant(_ context.Context, grant LibraryArtifactGrant) (LibraryArtifactGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if grant.ID == "" {
		grant.ID = newLibraryArtifactGrantID()
	}
	normalized, err := normalizedLibraryArtifactGrant(grant)
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	grant = normalized
	if !grant.RevokedAt.IsZero() {
		return LibraryArtifactGrant{}, errors.New("new artifact grant must be live")
	}
	if s.libraryArtifactLocked(grant.ArtifactID) == nil {
		return LibraryArtifactGrant{}, ErrLibraryArtifactNotFound
	}
	client, found := s.mcpClientByIDLocked(grant.AgentSurfaceID)
	if !found {
		return LibraryArtifactGrant{}, ErrMCPClientNotFound
	}
	if client.Status != MCPClientStatusActive {
		return LibraryArtifactGrant{}, ErrMCPClientRevoked
	}
	version := s.libraryArtifactVersionLocked(grant.ArtifactID, grant.ArtifactVersionID)
	if version == nil || version.Digest != grant.ArtifactVersionDigest {
		return LibraryArtifactGrant{}, ErrLibraryArtifactVersionNotFound
	}
	if s.activeLibraryArtifactGrantLocked(grant.ArtifactID, grant.AgentSurfaceID) != nil {
		return LibraryArtifactGrant{}, ErrLibraryArtifactGrantExists
	}
	copy := copyLibraryArtifactGrant(grant)
	s.libraryArtifactGrants = append(s.libraryArtifactGrants, &copy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactGrants = s.libraryArtifactGrants[:len(s.libraryArtifactGrants)-1]
		return LibraryArtifactGrant{}, err
	}
	return copyLibraryArtifactGrant(copy), nil
}

func (s *FileStore) RevokeLibraryArtifactGrant(_ context.Context, artifactID, grantID, revokedBy string, revokedAt time.Time) (LibraryArtifactGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateLibraryOpaqueRef("revoked by", revokedBy, false); err != nil {
		return LibraryArtifactGrant{}, err
	}
	if s.libraryArtifactLocked(artifactID) == nil {
		return LibraryArtifactGrant{}, ErrLibraryArtifactNotFound
	}
	grant := s.libraryArtifactGrantLocked(artifactID, grantID)
	if grant == nil {
		return LibraryArtifactGrant{}, ErrLibraryArtifactGrantNotFound
	}
	// Revocation is retry-safe. Preserve the original actor/time so an
	// accidental repeated browser submission cannot rewrite audit evidence.
	if !grant.RevokedAt.IsZero() {
		return copyLibraryArtifactGrant(*grant), nil
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	before := copyLibraryArtifactGrant(*grant)
	grant.RevokedBy, grant.RevokedAt = revokedBy, revokedAt
	if err := s.saveLocked(); err != nil {
		*grant = before
		return LibraryArtifactGrant{}, err
	}
	return copyLibraryArtifactGrant(*grant), nil
}

func (s *FileStore) ReviewLibraryArtifactVersion(ctx context.Context, artifactID, versionID, status, reviewedBy string, reviewedAt time.Time) (LibraryArtifactVersion, error) {
	return s.ReviewLibraryArtifactVersionWithComment(ctx, artifactID, versionID, status, reviewedBy, "", reviewedAt)
}

func (s *FileStore) ReviewLibraryArtifactVersionWithComment(_ context.Context, artifactID, versionID, status, reviewedBy, comment string, reviewedAt time.Time) (LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.libraryArtifactLocked(artifactID) == nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	if status != LibraryRedactionApproved && status != LibraryRedactionRejected {
		return LibraryArtifactVersion{}, errors.New("redaction review status must be approved or rejected")
	}
	if err := validateLibraryOpaqueRef("reviewer", reviewedBy, false); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := validateLibraryReviewComment(comment); err != nil {
		return LibraryArtifactVersion{}, err
	}
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if version == nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactVersionNotFound
	}
	if !version.PublicationClaimedAt.IsZero() {
		return LibraryArtifactVersion{}, ErrLibraryArtifactPublicationClaimed
	}
	before := copyLibraryArtifactVersion(*version)
	version.RedactionStatus, version.ReviewedBy, version.ReviewComment = status, reviewedBy, comment
	if reviewedAt.IsZero() {
		reviewedAt = time.Now().UTC()
	}
	version.ReviewedAt = reviewedAt
	if err := s.saveLocked(); err != nil {
		*version = before
		return LibraryArtifactVersion{}, err
	}
	return copyLibraryArtifactVersion(*version), nil
}

// libraryPublicationCandidateLocked projects the current artifact head while
// FileStore's single-instance mutex is held. Both ordinary reads and the
// Platform claim CAS use this exact projection so their reviewed-latest rule
// cannot diverge.
func (s *FileStore) libraryPublicationCandidateLocked(artifactID string) (LibraryPublicationCandidate, error) {
	artifact := s.libraryArtifactLocked(artifactID)
	if artifact == nil {
		return LibraryPublicationCandidate{}, ErrLibraryArtifactNotFound
	}
	var latest *LibraryArtifactVersion
	for _, version := range s.libraryArtifactVersions {
		if version != nil && version.ArtifactID == artifactID && (latest == nil || version.Version > latest.Version) {
			latest = version
		}
	}
	if latest == nil {
		return LibraryPublicationCandidate{}, ErrLibraryArtifactVersionNotFound
	}
	// Public publication remains a reviewed text/Markdown snapshot contract.
	// Do not silently omit a private image or turn its blob into a Platform
	// media URL; a dedicated public-media design is required first.
	if latest.Format == LibraryArtifactFormatImage {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationNotReady
	}
	if latest.RedactionStatus != LibraryRedactionApproved || latest.ReviewedAt.IsZero() {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationNotReady
	}
	candidate := LibraryPublicationCandidate{
		ArtifactID: artifact.ID, ArtifactVersionID: latest.ID, Digest: latest.Digest,
		Title: artifact.Title, Summary: artifact.Summary, Format: latest.Format, Body: latest.Body,
		ArtifactCreatedAt: artifact.CreatedAt, RedactionStatus: latest.RedactionStatus, ReviewedAt: latest.ReviewedAt,
		Provenance: LibraryPublicationProvenance{Origin: artifact.Origin, RunID: artifact.RunID},
	}
	if artifact.SkillID != "" {
		if skill := s.librarySkillLocked(artifact.SkillID); skill != nil {
			candidate.Provenance.SkillName = skill.Name
		}
		if version := s.librarySkillVersionLocked(artifact.SkillID, artifact.SkillVersionID); version != nil {
			candidate.Provenance.SkillVersion = version.Version
		}
	}
	return candidate, nil
}

func (s *FileStore) LibraryPublicationCandidate(_ context.Context, artifactID string) (LibraryPublicationCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.libraryPublicationCandidateLocked(artifactID)
}

// ClaimLibraryPublicationCandidate is the FileStore side of the Platform's
// reviewed-latest CAS. A version body/digest is immutable, but a later
// version can become the head between the initial candidate read and public
// link creation. Holding the same mutex used by version/review writes makes
// the comparison and returned projection one atomic Engine observation.
func (s *FileStore) ClaimLibraryPublicationCandidate(_ context.Context, artifactID, expectedVersionID, expectedDigest string) (LibraryPublicationCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := s.libraryPublicationCandidateLocked(artifactID)
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	if candidate.ArtifactVersionID != expectedVersionID || candidate.Digest != expectedDigest {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationClaimConflict
	}
	latest := s.libraryArtifactVersionLocked(artifactID, candidate.ArtifactVersionID)
	if latest == nil {
		return LibraryPublicationCandidate{}, ErrLibraryArtifactVersionNotFound
	}
	if latest.PublicationClaimedAt.IsZero() {
		before := copyLibraryArtifactVersion(*latest)
		latest.PublicationClaimedAt = time.Now().UTC()
		if err := s.saveLocked(); err != nil {
			*latest = before
			return LibraryPublicationCandidate{}, err
		}
	}
	return candidate, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
