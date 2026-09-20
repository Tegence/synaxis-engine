package engine

import (
	"context"
	"fmt"
	"time"
)

var _ BuiltInLibraryStore = (*FileStore)(nil)
var _ BuiltInLibraryCurrentVersionStore = (*FileStore)(nil)

func cloneBuiltInLibrarySkills(values []*LibrarySkill) []*LibrarySkill {
	out := make([]*LibrarySkill, len(values))
	for index, value := range values {
		if value == nil {
			continue
		}
		copy := copyLibrarySkill(*value)
		out[index] = &copy
	}
	return out
}

func cloneBuiltInLibrarySkillVersions(values []*LibrarySkillVersion) []*LibrarySkillVersion {
	out := make([]*LibrarySkillVersion, len(values))
	for index, value := range values {
		if value == nil {
			continue
		}
		copy := copyLibrarySkillVersion(*value)
		out[index] = &copy
	}
	return out
}

func cloneBuiltInLibraryCurrentVersions(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for skillID, versionID := range values {
		out[skillID] = versionID
	}
	return out
}

func (s *FileStore) builtInLibraryCurrentVersionLocked(skillID string) (string, bool) {
	versionID, found := s.libraryBuiltInCurrentVersions[skillID]
	return versionID, found
}

func (s *FileStore) BuiltInLibraryCurrentVersion(ctx context.Context, skillID string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	versionID, found := s.builtInLibraryCurrentVersionLocked(skillID)
	return versionID, found, nil
}

// ReconcileBuiltInLibrary installs the code-owned manifest and exact
// agent-surface bindings under FileStore's one lock and one atomic file
// replacement. A malformed reserved row is never silently adopted.
func (s *FileStore) ReconcileBuiltInLibrary(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	definition := usingSynaxisDefinition()
	if err := definition.validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	beforeSkills := cloneBuiltInLibrarySkills(s.librarySkills)
	beforeVersions := cloneBuiltInLibrarySkillVersions(s.librarySkillVersions)
	beforeBindings := copyLibrarySkillBindings(s.librarySkillBindings)
	beforeGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
	beforeCurrentVersions := cloneBuiltInLibraryCurrentVersions(s.libraryBuiltInCurrentVersions)
	changed, err := s.reconcileBuiltInLibraryDefinitionLocked(definition)
	if err != nil {
		s.librarySkills = beforeSkills
		s.librarySkillVersions = beforeVersions
		s.librarySkillBindings = beforeBindings
		s.librarySkillBindingGenerations = beforeGenerations
		s.libraryBuiltInCurrentVersions = beforeCurrentVersions
		return err
	}
	if !changed {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		s.librarySkills = beforeSkills
		s.librarySkillVersions = beforeVersions
		s.librarySkillBindings = beforeBindings
		s.librarySkillBindingGenerations = beforeGenerations
		s.libraryBuiltInCurrentVersions = beforeCurrentVersions
		return err
	}
	return nil
}

func (s *FileStore) reconcileBuiltInLibraryDefinitionLocked(definition builtInLibrarySkillDefinition) (bool, error) {
	if err := definition.validate(); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	changed := false

	var persistedSkill *LibrarySkill
	for _, skill := range s.librarySkills {
		if skill == nil || (skill.ID != definition.SkillID && skill.Slug != definition.Slug) {
			continue
		}
		if persistedSkill != nil || !builtInSkillMatches(*skill, definition) {
			return false, fmt.Errorf("%w: reserved skill identity or metadata", ErrLibraryBuiltInConflict)
		}
		persistedSkill = skill
	}
	if persistedSkill == nil {
		skill := definition.skill(now)
		s.librarySkills = append(s.librarySkills, &skill)
		persistedSkill = &skill
		changed = true
	}

	for _, candidate := range definition.Versions {
		var persistedVersion *LibrarySkillVersion
		for _, version := range s.librarySkillVersions {
			if version == nil || (version.ID != candidate.VersionID && (version.SkillID != definition.SkillID || version.Version != candidate.Revision)) {
				continue
			}
			if persistedVersion != nil || !builtInVersionMatches(*version, definition, candidate) {
				return false, fmt.Errorf("%w: reserved skill version identity or digest", ErrLibraryBuiltInConflict)
			}
			persistedVersion = version
		}
		if persistedVersion == nil {
			version := definition.version(candidate, now)
			s.librarySkillVersions = append(s.librarySkillVersions, &version)
			persistedSkill.UpdatedAt = now
			changed = true
		}
	}
	persistedVersions := make([]LibrarySkillVersion, 0, len(s.librarySkillVersions))
	for _, version := range s.librarySkillVersions {
		if version != nil {
			persistedVersions = append(persistedVersions, copyLibrarySkillVersion(*version))
		}
	}
	managedVersions, err := validateBuiltInPersistedVersions(definition, persistedVersions)
	if err != nil {
		return false, err
	}

	clientIDs := make(map[string]struct{}, len(s.mcpClients))
	for _, client := range s.mcpClients {
		if client != nil {
			clientIDs[client.ID] = struct{}{}
		}
	}
	persistedBindings := make([]LibrarySkillBinding, 0, len(s.librarySkillBindings))
	for _, binding := range s.librarySkillBindings {
		if binding != nil {
			persistedBindings = append(persistedBindings, copyLibrarySkillBinding(*binding))
		}
	}
	if err := validateBuiltInPersistedBindings(definition, clientIDs, managedVersions, persistedBindings); err != nil {
		return false, err
	}
	if currentVersionID, found := s.builtInLibraryCurrentVersionLocked(definition.SkillID); found {
		if _, valid := managedVersions[currentVersionID]; !valid {
			return false, fmt.Errorf("%w: authoritative built-in version is invalid", ErrLibraryBuiltInConflict)
		}
	}
	if s.libraryBuiltInCurrentVersions == nil {
		s.libraryBuiltInCurrentVersions = map[string]string{}
	}
	if s.libraryBuiltInCurrentVersions[definition.SkillID] != definition.CurrentVersionID {
		s.libraryBuiltInCurrentVersions[definition.SkillID] = definition.CurrentVersionID
		changed = true
	}

	for _, client := range s.mcpClients {
		if client == nil {
			continue
		}
		bindingChanged, err := s.reconcileBuiltInLibraryBindingLocked(definition, client.ID, definition.CurrentVersionID, now)
		if err != nil {
			return false, err
		}
		changed = changed || bindingChanged
	}
	return changed, nil
}

func (s *FileStore) reconcileBuiltInLibraryBindingLocked(definition builtInLibrarySkillDefinition, clientID, targetVersionID string, now time.Time) (bool, error) {
	expectedID := usingSynaxisBindingID(clientID)
	var persisted *LibrarySkillBinding
	for _, binding := range s.librarySkillBindings {
		if binding == nil || (binding.ID != expectedID && (binding.SkillID != definition.SkillID || binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != clientID)) {
			continue
		}
		if persisted != nil || !builtInBindingShapeMatches(*binding, definition, clientID) {
			return false, fmt.Errorf("%w: reserved binding for agent surface %q", ErrLibraryBuiltInConflict, clientID)
		}
		pinned := s.librarySkillVersionLocked(definition.SkillID, binding.PinnedVersionID)
		if pinned == nil || !builtInPersistedVersionMayBePinned(*pinned, definition) {
			return false, fmt.Errorf("%w: reserved binding has an invalid pinned version", ErrLibraryBuiltInConflict)
		}
		persisted = binding
	}
	if persisted == nil {
		binding := definition.binding(clientID, now)
		binding.PinnedVersionID = targetVersionID
		if _, err := s.bumpLibrarySkillBindingGenerationLocked(definition.SkillID); err != nil {
			return false, err
		}
		s.librarySkillBindings = append(s.librarySkillBindings, &binding)
		return true, nil
	}
	if persisted.PinnedVersionID != targetVersionID {
		if _, err := s.bumpLibrarySkillBindingGenerationLocked(definition.SkillID); err != nil {
			return false, err
		}
		persisted.PinnedVersionID = targetVersionID
		persisted.UpdatedAt = now
		return true, nil
	}
	if s.librarySkillBindingGenerationLocked(definition.SkillID) == 0 {
		s.ensureLibrarySkillBindingGenerationLocked(definition.SkillID)
		return true, nil
	}
	return false, nil
}

func (s *FileStore) validateInstalledBuiltInLibraryLocked(definition builtInLibrarySkillDefinition) (map[string]LibrarySkillVersion, []LibrarySkillBinding, error) {
	var persistedSkill *LibrarySkill
	for _, skill := range s.librarySkills {
		if skill == nil || (skill.ID != definition.SkillID && skill.Slug != definition.Slug) {
			continue
		}
		if persistedSkill != nil || !builtInSkillMatches(*skill, definition) {
			return nil, nil, fmt.Errorf("%w: reserved skill identity or metadata", ErrLibraryBuiltInConflict)
		}
		persistedSkill = skill
	}
	if persistedSkill == nil {
		return nil, nil, fmt.Errorf("%w: authoritative built-in marker has no skill", ErrLibraryBuiltInConflict)
	}

	persistedVersions := make([]LibrarySkillVersion, 0, len(s.librarySkillVersions))
	for _, version := range s.librarySkillVersions {
		if version != nil {
			persistedVersions = append(persistedVersions, copyLibrarySkillVersion(*version))
		}
	}
	managedVersions, err := validateBuiltInPersistedVersions(definition, persistedVersions)
	if err != nil {
		return nil, nil, err
	}

	clientIDs := make(map[string]struct{}, len(s.mcpClients))
	for _, client := range s.mcpClients {
		if client != nil {
			clientIDs[client.ID] = struct{}{}
		}
	}
	persistedBindings := make([]LibrarySkillBinding, 0, len(s.librarySkillBindings))
	for _, binding := range s.librarySkillBindings {
		if binding != nil {
			persistedBindings = append(persistedBindings, copyLibrarySkillBinding(*binding))
		}
	}
	if err := validateBuiltInPersistedBindings(definition, clientIDs, managedVersions, persistedBindings); err != nil {
		return nil, nil, err
	}
	return managedVersions, persistedBindings, nil
}

// reconcileInstalledBuiltInLibraryForNewClientLocked is called only from the
// MCP-client create critical section. Bare/custom store fixtures keep their
// historical behavior until the manifest is explicitly installed, while a
// production store cannot commit a new client without its managed binding.
func (s *FileStore) reconcileInstalledBuiltInLibraryForNewClientLocked() (bool, error) {
	return s.reconcileInstalledBuiltInLibraryForNewClientDefinitionLocked(usingSynaxisDefinition())
}

func (s *FileStore) reconcileInstalledBuiltInLibraryForNewClientDefinitionLocked(definition builtInLibrarySkillDefinition) (bool, error) {
	if err := definition.validate(); err != nil {
		return false, err
	}
	currentVersionID, markerFound := s.builtInLibraryCurrentVersionLocked(definition.SkillID)
	if s.librarySkillLocked(definition.SkillID) == nil && !markerFound {
		return false, nil
	}
	if !markerFound {
		return false, fmt.Errorf("%w: installed built-in skill has no authoritative version", ErrLibraryBuiltInConflict)
	}
	managedVersions, persistedBindings, err := s.validateInstalledBuiltInLibraryLocked(definition)
	if err != nil {
		return false, err
	}
	currentVersion, persisted := managedVersions[currentVersionID]
	if !persisted || !builtInPersistedVersionMayBePinned(currentVersion, definition) {
		return false, fmt.Errorf("%w: authoritative built-in version is invalid", ErrLibraryBuiltInConflict)
	}
	for _, binding := range persistedBindings {
		if binding.SkillID == definition.SkillID && binding.PinnedVersionID != currentVersionID {
			return false, fmt.Errorf("%w: managed binding diverges from the authoritative version", ErrLibraryBuiltInConflict)
		}
	}

	now := time.Now().UTC()
	changed := false
	for _, client := range s.mcpClients {
		if client == nil {
			continue
		}
		bindingChanged, err := s.reconcileBuiltInLibraryBindingLocked(definition, client.ID, currentVersionID, now)
		if err != nil {
			return false, err
		}
		changed = changed || bindingChanged
	}
	return changed, nil
}
