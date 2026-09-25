package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// LibrarySkillResolutionRequest is opaque runtime context used to find
// portable skills. Callers that need automatic applicability must source these
// values from a trusted runtime integration. Every ID is opaque: the Engine
// does not infer folder hierarchy, repository ownership, membership, or
// credential access from it, and a match never authorizes an action.
//
// ExplicitBindingID selects one existing binding and takes precedence over all
// scope fields. An explicit *binding*, rather than an unbound skill ID, keeps
// the selected version and capability ceiling reviewable and auditable.
//
// Project and agent-surface bindings are valid Library records but are not
// resolved here until their hierarchy and precedence are explicitly designed.
// Silently assigning them a precedence would make a future authorization
// decision accidental.
type LibrarySkillResolutionRequest struct {
	ExplicitBindingID string `json:"bindingId,omitempty"`
	FolderID          string `json:"folderId,omitempty"`
	RepositoryID      string `json:"repositoryId,omitempty"`
	NamespaceID       string `json:"namespaceId,omitempty"`
	WorkspaceID       string `json:"workspaceId,omitempty"`
}

// LibraryResolvedSkill is an instruction bundle selected by a matching
// binding. It deliberately contains no connector, credential, OAuth, tool,
// permission, or runtime-grant data. RequestedCapabilities and
// CapabilityCeiling describe constraints only; the caller must intersect them
// with an independently authenticated runtime grant immediately before a tool
// call via ResolveLibraryCapabilities.
type LibraryResolvedSkill struct {
	SkillID               string   `json:"skillId"`
	SkillSlug             string   `json:"skillSlug"`
	SkillName             string   `json:"skillName"`
	VersionID             string   `json:"versionId"`
	Version               int      `json:"version"`
	Content               string   `json:"content"`
	Digest                string   `json:"digest"`
	BindingID             string   `json:"bindingId"`
	BindingMode           string   `json:"bindingMode"`
	ScopeKind             string   `json:"scopeKind"`
	ScopeID               string   `json:"scopeId"`
	ResolutionSource      string   `json:"resolutionSource"`
	Priority              int      `json:"priority"`
	RequestedCapabilities []string `json:"requestedCapabilities"`
	CapabilityCeiling     []string `json:"capabilityCeiling"`
	// Files and ManifestDigest describe the selected version's bundle. They
	// are metadata only; file bytes are fetched on demand and verified.
	Files          []LibrarySkillFile `json:"files,omitempty"`
	ManifestDigest string             `json:"manifestDigest,omitempty"`
}

// LibrarySkillResolution is a read-only result appropriate for an agent to
// load instructions from. AuthorityNotice is deliberately part of the result
// so consumers that render this JSON cannot mistake a selected skill for an
// authorization grant.
type LibrarySkillResolution struct {
	Skills          []LibraryResolvedSkill `json:"skills"`
	AuthorityNotice string                 `json:"authorityNotice"`
	// Activation and host-attestation builders accept only agent-surface
	// resolutions that passed the running binary's managed-guide checks. Keeping
	// this state on the snapshot avoids a store callback from an open native
	// transaction.
	builtInRuntimeValidated bool
}

const libraryResolutionAuthorityNotice = "Resolved skills are instructions only. Bindings can narrow requested capabilities but do not grant credentials, OAuth scopes, permissions, tools, or connection access. Enforce runtime policy independently for every action."

var (
	ErrLibraryResolutionContextInvalid = errors.New("invalid library resolution context")
	errLibraryBuiltInRuntimeIntegrity  = errors.New("built-in library runtime integrity check failed")
)

type libraryResolutionScope struct {
	kind       string
	id         string
	source     string
	precedence int
}

const (
	libraryResolutionExplicitPrecedence   = 0
	libraryResolutionFolderPrecedence     = 1
	libraryResolutionRepositoryPrecedence = 2
	libraryResolutionNamespacePrecedence  = 3
	libraryResolutionWorkspacePrecedence  = 4
)

func validateLibraryResolutionRequest(request LibrarySkillResolutionRequest) error {
	for _, field := range []struct {
		label string
		value string
	}{
		{label: "explicit binding", value: request.ExplicitBindingID},
		{label: "folder", value: request.FolderID},
		{label: "repository", value: request.RepositoryID},
		{label: "namespace", value: request.NamespaceID},
		{label: "workspace", value: request.WorkspaceID},
	} {
		if err := validateLibraryOpaqueRef(field.label, field.value, true); err != nil {
			return fmt.Errorf("%w: %v", ErrLibraryResolutionContextInvalid, err)
		}
	}
	return nil
}

func libraryResolutionScopes(request LibrarySkillResolutionRequest) []libraryResolutionScope {
	scopes := make([]libraryResolutionScope, 0, 4)
	if request.FolderID != "" {
		scopes = append(scopes, libraryResolutionScope{kind: LibraryScopeFolder, id: request.FolderID, source: LibraryScopeFolder, precedence: libraryResolutionFolderPrecedence})
	}
	if request.RepositoryID != "" {
		scopes = append(scopes, libraryResolutionScope{kind: LibraryScopeRepository, id: request.RepositoryID, source: LibraryScopeRepository, precedence: libraryResolutionRepositoryPrecedence})
	}
	if request.NamespaceID != "" {
		scopes = append(scopes, libraryResolutionScope{kind: LibraryScopeNamespace, id: request.NamespaceID, source: LibraryScopeNamespace, precedence: libraryResolutionNamespacePrecedence})
	}
	if request.WorkspaceID != "" {
		scopes = append(scopes, libraryResolutionScope{kind: LibraryScopeWorkspace, id: request.WorkspaceID, source: LibraryScopeWorkspace, precedence: libraryResolutionWorkspacePrecedence})
	}
	return scopes
}

type libraryResolutionCandidate struct {
	skill      LibrarySkill
	binding    LibrarySkillBinding
	source     string
	precedence int
}

func betterLibraryResolutionCandidate(candidate, current libraryResolutionCandidate) bool {
	if candidate.precedence != current.precedence {
		return candidate.precedence < current.precedence
	}
	if candidate.binding.Priority != current.binding.Priority {
		return candidate.binding.Priority > current.binding.Priority
	}
	return candidate.binding.ID < current.binding.ID
}

func newLibraryResolvedSkill(candidate libraryResolutionCandidate, version LibrarySkillVersion) LibraryResolvedSkill {
	return LibraryResolvedSkill{
		SkillID: candidate.skill.ID, SkillSlug: candidate.skill.Slug, SkillName: candidate.skill.Name,
		VersionID: version.ID, Version: version.Version, Content: version.Content, Digest: version.Digest,
		Files: copyLibrarySkillFiles(version.Files), ManifestDigest: version.ManifestDigest,
		BindingID: candidate.binding.ID, BindingMode: candidate.binding.Mode,
		ScopeKind: candidate.binding.ScopeKind, ScopeID: candidate.binding.ScopeID,
		ResolutionSource: candidate.source, Priority: candidate.binding.Priority,
		RequestedCapabilities: append([]string(nil), version.RequestedCapabilities...),
		CapabilityCeiling:     append([]string(nil), candidate.binding.CapabilityCeiling...),
	}
}

// ResolveLibrarySkills selects a single best binding per skill. The generic
// precedence is explicit binding, folder, repository, namespace, then
// workspace. At a shared precedence, a binding's declared priority is the
// deterministic tie-breaker. Different skills can all apply; only duplicate
// bindings for the same skill are shadowed by a more-specific scope.
//
// The resolver is read-only. It intentionally does not accept a caller's
// claimed permissions or return an effective authorized capability set. Tool
// execution must still obtain trusted runtime grants and intersect them with
// the selected request and ceiling through ResolveLibraryCapabilities.
func ResolveLibrarySkills(ctx context.Context, store LibraryStore, request LibrarySkillResolutionRequest) (LibrarySkillResolution, error) {
	result := LibrarySkillResolution{Skills: []LibraryResolvedSkill{}, AuthorityNotice: libraryResolutionAuthorityNotice}
	if store == nil {
		return result, errors.New("library store is unavailable")
	}
	if err := validateLibraryResolutionRequest(request); err != nil {
		return result, err
	}
	selections, err := store.LibrarySkillResolutionSelections(ctx, request)
	if err != nil {
		return result, err
	}
	result.Skills = append(result.Skills, selections...)
	return result, nil
}

// resolveLibrarySkillSnapshot is shared by FileStore and PgStore after each
// has captured one internally consistent view of the matching Library rows.
// Keeping candidate precedence and version selection here prevents the two
// stores from gradually interpreting a portable binding differently.
func resolveLibrarySkillSnapshot(request LibrarySkillResolutionRequest, skills []LibrarySkill, bindingsBySkill map[string][]LibrarySkillBinding, versionsBySkill map[string][]LibrarySkillVersion) ([]LibraryResolvedSkill, error) {
	if err := validateLibraryResolutionRequest(request); err != nil {
		return nil, err
	}
	candidates, err := libraryResolutionCandidates(request, skills, bindingsBySkill)
	if err != nil {
		return nil, err
	}
	resolved := make([]LibraryResolvedSkill, 0, len(candidates))
	for _, candidate := range candidates {
		version, err := libraryResolvedSnapshotVersion(versionsBySkill, candidate.binding)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, newLibraryResolvedSkill(candidate, version))
	}
	return resolved, nil
}

func libraryResolutionCandidates(request LibrarySkillResolutionRequest, skills []LibrarySkill, bindingsBySkill map[string][]LibrarySkillBinding) ([]libraryResolutionCandidate, error) {
	if request.ExplicitBindingID != "" {
		for _, skill := range skills {
			for _, binding := range bindingsBySkill[skill.ID] {
				if binding.SkillID != skill.ID {
					return nil, errors.New("library store returned a binding for a mismatched skill")
				}
				if binding.ID == request.ExplicitBindingID {
					return []libraryResolutionCandidate{{
						skill: skill, binding: binding, source: "explicit", precedence: libraryResolutionExplicitPrecedence,
					}}, nil
				}
			}
		}
		return nil, ErrLibraryBindingNotFound
	}

	scopes := libraryResolutionScopes(request)
	if len(scopes) == 0 {
		return []libraryResolutionCandidate{}, nil
	}
	candidates := make(map[string]libraryResolutionCandidate, len(skills))
	for _, skill := range skills {
		for _, binding := range bindingsBySkill[skill.ID] {
			if binding.SkillID != skill.ID {
				return nil, errors.New("library store returned a binding for a mismatched skill")
			}
			for _, scope := range scopes {
				if binding.ScopeKind != scope.kind || binding.ScopeID != scope.id {
					continue
				}
				candidate := libraryResolutionCandidate{skill: skill, binding: binding, source: scope.source, precedence: scope.precedence}
				current, found := candidates[skill.ID]
				if !found || betterLibraryResolutionCandidate(candidate, current) {
					candidates[skill.ID] = candidate
				}
				break
			}
		}
	}

	ordered := make([]libraryResolutionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].precedence != ordered[j].precedence {
			return ordered[i].precedence < ordered[j].precedence
		}
		if ordered[i].binding.Priority != ordered[j].binding.Priority {
			return ordered[i].binding.Priority > ordered[j].binding.Priority
		}
		if ordered[i].skill.Slug != ordered[j].skill.Slug {
			return ordered[i].skill.Slug < ordered[j].skill.Slug
		}
		return ordered[i].skill.ID < ordered[j].skill.ID
	})
	return ordered, nil
}

func libraryResolvedSnapshotVersion(versionsBySkill map[string][]LibrarySkillVersion, binding LibrarySkillBinding) (LibrarySkillVersion, error) {
	versions := versionsBySkill[binding.SkillID]
	var version LibrarySkillVersion
	switch binding.Mode {
	case LibraryBindingModePin:
		for _, candidate := range versions {
			if candidate.ID == binding.PinnedVersionID {
				version = candidate
				break
			}
		}
	case LibraryBindingModeTrack:
		for _, candidate := range versions {
			if version.ID == "" || candidate.Version > version.Version {
				version = candidate
			}
		}
	default:
		return LibrarySkillVersion{}, fmt.Errorf("invalid library binding mode %q", binding.Mode)
	}
	if version.ID == "" {
		return LibrarySkillVersion{}, ErrLibrarySkillVersionNotFound
	}
	if version.SkillID != binding.SkillID {
		return LibrarySkillVersion{}, errors.New("library binding returned a mismatched skill version")
	}
	return version, nil
}

// ResolveLibrarySkillsForAgentSurface resolves only the bindings that were
// explicitly assigned to one durable agent surface. It is deliberately
// separate from ResolveLibrarySkills: generic resolution does not infer an
// agent-surface hierarchy or precedence, while a subject-bound MCP client can
// safely supply its own immutable client ID as that surface.
//
// The surface ID comes from the trusted endpoint projection, never from MCP
// tool arguments. As with the generic resolver, this returns instruction and
// constraint data only; it grants no credential, OAuth scope, tool, or other
// runtime authority.
func ResolveLibrarySkillsForAgentSurface(ctx context.Context, store LibraryStore, agentSurfaceID string) (LibrarySkillResolution, error) {
	result := LibrarySkillResolution{Skills: []LibraryResolvedSkill{}, AuthorityNotice: libraryResolutionAuthorityNotice}
	if store == nil {
		return result, errors.New("library store is unavailable")
	}
	if err := validateLibraryOpaqueRef("agent surface", agentSurfaceID, false); err != nil {
		return result, fmt.Errorf("%w: %v", ErrLibraryResolutionContextInvalid, err)
	}

	selections, err := store.LibraryAgentSurfaceSkillSelections(ctx, agentSurfaceID)
	if err != nil {
		return result, err
	}
	currentVersionID := ""
	manifestInstalled := false
	if markerStore, ok := store.(BuiltInLibraryCurrentVersionStore); ok {
		currentVersionID, manifestInstalled, err = markerStore.BuiltInLibraryCurrentVersion(ctx, usingSynaxisSkillID)
		if err != nil {
			return result, err
		}
	}
	return libraryResolutionForAgentSurfaceSelections(agentSurfaceID, selections, currentVersionID, manifestInstalled)
}

// libraryResolutionForAgentSurfaceSelections applies the portable resolver's
// validation and deterministic ordering to a store-native atomic selection.
// FileStore and PgStore use it while they still hold their own lock/transaction
// for host-attested runtime ingestion.
func libraryResolutionForAgentSurfaceSelections(agentSurfaceID string, selections []LibraryAgentSurfaceSkillSelection, currentBuiltInVersionID string, builtInManifestInstalled bool) (LibrarySkillResolution, error) {
	result := LibrarySkillResolution{Skills: []LibraryResolvedSkill{}, AuthorityNotice: libraryResolutionAuthorityNotice}
	if err := validateBuiltInLibraryAgentSurfaceSelections(usingSynaxisDefinition(), agentSurfaceID, selections, currentBuiltInVersionID, builtInManifestInstalled); err != nil {
		return result, err
	}
	for _, selection := range selections {
		if selection.Skill.ID == "" || selection.Binding.SkillID != selection.Skill.ID || selection.Version.SkillID != selection.Skill.ID ||
			selection.Binding.ScopeKind != LibraryScopeAgentSurface || selection.Binding.ScopeID != agentSurfaceID {
			return result, errors.New("library store returned an invalid agent-surface selection")
		}
		if selection.Binding.Mode == LibraryBindingModePin && selection.Binding.PinnedVersionID != selection.Version.ID {
			return result, errors.New("library store returned a mismatched pinned agent-surface version")
		}
		if selection.Binding.Mode != LibraryBindingModePin && selection.Binding.Mode != LibraryBindingModeTrack {
			return result, fmt.Errorf("invalid library binding mode %q", selection.Binding.Mode)
		}
		if !isBuiltInLibrarySkillID(selection.Skill.ID) &&
			(selection.Binding.Priority < libraryMinAuthoredBindingPriority || selection.Binding.Priority > libraryMaxAuthoredBindingPriority) {
			return result, fmt.Errorf("%w: authored binding priority is outside the portable range", errLibraryBuiltInRuntimeIntegrity)
		}
		result.Skills = append(result.Skills, newLibraryResolvedSkill(libraryResolutionCandidate{
			skill: selection.Skill, binding: selection.Binding, source: LibraryScopeAgentSurface,
			precedence: libraryResolutionExplicitPrecedence,
		}, selection.Version))
	}
	sort.Slice(result.Skills, func(i, j int) bool {
		if result.Skills[i].Priority != result.Skills[j].Priority {
			return result.Skills[i].Priority > result.Skills[j].Priority
		}
		if result.Skills[i].SkillSlug != result.Skills[j].SkillSlug {
			return result.Skills[i].SkillSlug < result.Skills[j].SkillSlug
		}
		return result.Skills[i].SkillID < result.Skills[j].SkillID
	})
	result.builtInRuntimeValidated = true
	return result, nil
}

func libraryAgentSurfaceSelectionClaimsBuiltIn(selection LibraryAgentSurfaceSkillSelection) bool {
	return isBuiltInLibrarySkillID(selection.Skill.ID) || selection.Skill.Slug == usingSynaxisSkillSlug ||
		isBuiltInLibrarySkillID(selection.Binding.SkillID) || isReservedBuiltInLibraryBindingID(selection.Binding.ID) ||
		isBuiltInLibrarySkillID(selection.Version.SkillID) || isReservedBuiltInLibraryVersionID(selection.Version.ID)
}

func validateBuiltInLibraryAgentSurfaceSelections(definition builtInLibrarySkillDefinition, agentSurfaceID string, selections []LibraryAgentSurfaceSkillSelection, currentVersionID string, manifestInstalled bool) error {
	var managed *LibraryAgentSurfaceSkillSelection
	for index := range selections {
		if !libraryAgentSurfaceSelectionClaimsBuiltIn(selections[index]) {
			continue
		}
		if managed != nil {
			return fmt.Errorf("%w: duplicate or aliased managed selection", errLibraryBuiltInRuntimeIntegrity)
		}
		managed = &selections[index]
	}
	if !manifestInstalled {
		if currentVersionID != "" || managed != nil {
			return fmt.Errorf("%w: managed selection exists without an authoritative current version", errLibraryBuiltInRuntimeIntegrity)
		}
		return nil
	}

	current, known := builtInLibraryKnownVersion(definition, currentVersionID)
	if !known {
		return fmt.Errorf("%w: authoritative current version %q is unknown to this binary", errLibraryBuiltInRuntimeIntegrity, currentVersionID)
	}
	if managed == nil {
		return fmt.Errorf("%w: managed selection is missing", errLibraryBuiltInRuntimeIntegrity)
	}
	if !builtInSkillMatches(managed.Skill, definition) {
		return fmt.Errorf("%w: managed skill metadata changed", errLibraryBuiltInRuntimeIntegrity)
	}
	if !builtInBindingShapeMatches(managed.Binding, definition, agentSurfaceID) || managed.Binding.PinnedVersionID != currentVersionID {
		return fmt.Errorf("%w: managed binding is not the authoritative exact-version pin", errLibraryBuiltInRuntimeIntegrity)
	}
	if !builtInVersionMatches(managed.Version, definition, current) {
		return fmt.Errorf("%w: managed current version changed", errLibraryBuiltInRuntimeIntegrity)
	}
	return nil
}

// libraryAgentSurfaceBindings filters the record set before it reaches an
// agent. It intentionally does not accept an arbitrary generic scope kind or
// connection namespace; an agent surface is an explicit Library binding with
// a durable MCP-client ID as its opaque scope ID.
func libraryAgentSurfaceBindings(ctx context.Context, store LibraryStore, skillID, agentSurfaceID string) ([]LibrarySkillBinding, error) {
	bindings, err := store.LibrarySkillBindings(ctx, skillID)
	if err != nil {
		return nil, err
	}
	matched := make([]LibrarySkillBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.SkillID != skillID {
			return nil, errors.New("library store returned a binding for a mismatched skill")
		}
		if binding.ScopeKind == LibraryScopeAgentSurface && binding.ScopeID == agentSurfaceID {
			matched = append(matched, binding)
		}
	}
	return matched, nil
}
