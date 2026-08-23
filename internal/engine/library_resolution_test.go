package engine

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func createLibraryResolutionSkill(t *testing.T, store LibraryStore, slug, name, content string, requested []string) (LibrarySkill, LibrarySkillVersion) {
	t.Helper()
	skill, version, err := store.CreateLibrarySkillWithInitialVersion(context.Background(), LibrarySkill{
		Slug: slug, Name: name, Description: "Portable runtime procedure", CreatedBy: "resolution-test",
	}, LibrarySkillVersion{Content: content, RequestedCapabilities: requested, CreatedBy: "resolution-test"})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion(%s): %v", slug, err)
	}
	return skill, version
}

func bindLibraryResolutionSkill(t *testing.T, store LibraryStore, binding LibrarySkillBinding) LibrarySkillBinding {
	t.Helper()
	created, err := store.UpsertLibrarySkillBinding(context.Background(), binding)
	if err != nil {
		t.Fatalf("UpsertLibrarySkillBinding(%s/%s): %v", binding.ScopeKind, binding.ScopeID, err)
	}
	return created
}

func TestResolveLibrarySkillsUsesSpecificScopeBeforePriorityAndTracksVersions(t *testing.T) {
	store := newLibraryFileStore(t)
	primary, first := createLibraryResolutionSkill(t, store, "release-check", "Release check", "# Version one", []string{"alerts.read", "tickets.read"})
	latest, err := store.CreateLibrarySkillVersion(context.Background(), LibrarySkillVersion{
		SkillID: primary.ID, Content: "# Version two", RequestedCapabilities: []string{"alerts.read", "tickets.read"}, CreatedBy: "resolution-test",
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillVersion: %v", err)
	}

	workspaceBinding := bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: primary.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "wsp_alpha", Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"alerts.read", "tickets.read"}, Priority: 999, CreatedBy: "resolution-test",
	})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: primary.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "ns_eng", Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"tickets.read"}, Priority: 99, CreatedBy: "resolution-test",
	})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: primary.ID, ScopeKind: LibraryScopeRepository, ScopeID: "repo_api", Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"alerts.read"}, Priority: 9, CreatedBy: "resolution-test",
	})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: primary.ID, ScopeKind: LibraryScopeFolder, ScopeID: "folder_release", Mode: LibraryBindingModePin,
		PinnedVersionID: first.ID, CapabilityCeiling: []string{"alerts.read"}, Priority: -99, CreatedBy: "resolution-test",
	})

	workspaceOnly, workspaceOnlyVersion := createLibraryResolutionSkill(t, store, "workspace-only", "Workspace only", "# Workspace procedure", []string{"catalog.read"})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: workspaceOnly.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "wsp_alpha", Mode: LibraryBindingModePin,
		PinnedVersionID: workspaceOnlyVersion.ID, CapabilityCeiling: []string{"catalog.read"}, Priority: 1, CreatedBy: "resolution-test",
	})

	resolution, err := ResolveLibrarySkills(context.Background(), store, LibrarySkillResolutionRequest{
		FolderID: "folder_release", RepositoryID: "repo_api", NamespaceID: "ns_eng", WorkspaceID: "wsp_alpha",
	})
	if err != nil {
		t.Fatalf("ResolveLibrarySkills: %v", err)
	}
	if len(resolution.Skills) != 2 {
		t.Fatalf("resolved skills=%#v, want primary plus workspace-only", resolution.Skills)
	}
	primaryResult := resolution.Skills[0]
	if primaryResult.SkillID != primary.ID || primaryResult.ResolutionSource != LibraryScopeFolder || primaryResult.BindingMode != LibraryBindingModePin || primaryResult.VersionID != first.ID || primaryResult.Version != first.Version || primaryResult.Content != first.Content {
		t.Fatalf("primary resolution=%+v, want most-specific pinned folder version", primaryResult)
	}
	if !reflect.DeepEqual(primaryResult.CapabilityCeiling, []string{"alerts.read"}) {
		t.Fatalf("primary capability ceiling=%v", primaryResult.CapabilityCeiling)
	}
	workspaceResult := resolution.Skills[1]
	if workspaceResult.SkillID != workspaceOnly.ID || workspaceResult.ResolutionSource != LibraryScopeWorkspace || workspaceResult.VersionID != workspaceOnlyVersion.ID {
		t.Fatalf("workspace-only resolution=%+v", workspaceResult)
	}

	// An explicitly selected binding overrides all ambient scope context. The
	// binding tracks the immutable latest version, even though the folder one
	// above pins the original version.
	explicit, err := ResolveLibrarySkills(context.Background(), store, LibrarySkillResolutionRequest{
		ExplicitBindingID: workspaceBinding.ID, FolderID: "folder_release", RepositoryID: "repo_api", NamespaceID: "ns_eng", WorkspaceID: "wsp_alpha",
	})
	if err != nil {
		t.Fatalf("explicit ResolveLibrarySkills: %v", err)
	}
	if len(explicit.Skills) != 1 || explicit.Skills[0].SkillID != primary.ID || explicit.Skills[0].ResolutionSource != "explicit" || explicit.Skills[0].VersionID != latest.ID || explicit.Skills[0].Content != latest.Content {
		t.Fatalf("explicit resolution=%+v, want explicit tracked binding", explicit.Skills)
	}
}

func TestResolveLibrarySkillsReturnsConstraintsButNeverAuthorization(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, _ := createLibraryResolutionSkill(t, store, "safe-resolution", "Safe resolution", "# Read alerts", []string{"alerts.read", "tickets.read"})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "ns_security", Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "resolution-test",
	})

	resolution, err := ResolveLibrarySkills(context.Background(), store, LibrarySkillResolutionRequest{NamespaceID: "ns_security"})
	if err != nil {
		t.Fatalf("ResolveLibrarySkills: %v", err)
	}
	if len(resolution.Skills) != 1 {
		t.Fatalf("resolved=%+v", resolution)
	}
	got := resolution.Skills[0]
	if !reflect.DeepEqual(got.RequestedCapabilities, []string{"alerts.read", "tickets.read"}) || !reflect.DeepEqual(got.CapabilityCeiling, []string{"alerts.read"}) {
		t.Fatalf("constraints=%+v", got)
	}
	// The resolver has no runtime grant input. Only the separate execution-time
	// intersection can yield an effective set, and it can only reduce access.
	effective := ResolveLibraryCapabilities(got.RequestedCapabilities, got.CapabilityCeiling, []string{"alerts.read", "tickets.read", "admin.write"})
	if !reflect.DeepEqual(effective, []string{"alerts.read"}) {
		t.Fatalf("effective runtime capabilities=%v, want [alerts.read]", effective)
	}
	payload, err := json.Marshal(resolution)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "effectiveCapabilities") || strings.Contains(string(payload), "createdBy") {
		t.Fatalf("resolution leaked an authorization or actor field: %s", payload)
	}
	if !strings.Contains(resolution.AuthorityNotice, "do not grant credentials") {
		t.Fatalf("authority notice=%q", resolution.AuthorityNotice)
	}
}

func TestResolveLibrarySkillsRejectsUnknownExplicitBindingAndInvalidOpaqueContext(t *testing.T) {
	store := newLibraryFileStore(t)
	if _, err := ResolveLibrarySkills(context.Background(), store, LibrarySkillResolutionRequest{ExplicitBindingID: "missing-binding"}); !errors.Is(err, ErrLibraryBindingNotFound) {
		t.Fatalf("unknown explicit binding error=%v", err)
	}
	if _, err := ResolveLibrarySkills(context.Background(), store, LibrarySkillResolutionRequest{FolderID: "   "}); !errors.Is(err, ErrLibraryResolutionContextInvalid) {
		t.Fatalf("blank opaque scope error=%v", err)
	}
}

// atomicGenericResolutionSnapshotStore models the one consistent snapshot a
// generic host must receive while an administrator changes an ambient tracking
// binding or writes a later version. The resolver must not rebuild that
// selection from independently visible rows after accepting this snapshot.
type atomicGenericResolutionSnapshotStore struct {
	LibraryStore
	selections []LibraryResolvedSkill
}

func (s atomicGenericResolutionSnapshotStore) LibrarySkillResolutionSelections(_ context.Context, _ LibrarySkillResolutionRequest) ([]LibraryResolvedSkill, error) {
	return append([]LibraryResolvedSkill(nil), s.selections...), nil
}

func (s atomicGenericResolutionSnapshotStore) LibrarySkills(context.Context) ([]LibrarySkill, error) {
	return nil, errors.New("generic resolver must not split-read skills")
}

func (s atomicGenericResolutionSnapshotStore) LibrarySkillBindings(context.Context, string) ([]LibrarySkillBinding, error) {
	return nil, errors.New("generic resolver must not split-read bindings")
}

func (s atomicGenericResolutionSnapshotStore) LibrarySkillVersions(context.Context, string) ([]LibrarySkillVersion, error) {
	return nil, errors.New("generic resolver must not split-read versions")
}

func TestResolveLibrarySkillsUsesOneAtomicGenericSelection(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	skill, first := createLibraryResolutionSkill(t, store, "generic-atomic-snapshot", "Generic atomic snapshot", "# First observed version", []string{"repo.read"})
	binding := bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "namespace_atomic",
		Mode: LibraryBindingModeTrack, CapabilityCeiling: []string{"repo.read"}, CreatedBy: "resolution-test",
	})
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: skill.ID, Content: "# Later version", RequestedCapabilities: []string{"repo.read"}, CreatedBy: "resolution-test",
	}); err != nil {
		t.Fatalf("create later version: %v", err)
	}

	// Simulate a snapshot taken before the later version was committed. A
	// split-read resolver could pair this still-selected tracking binding with
	// the newer head even if an administrator revoked it between reads.
	selection := newLibraryResolvedSkill(libraryResolutionCandidate{
		skill: skill, binding: binding, source: LibraryScopeNamespace, precedence: libraryResolutionNamespacePrecedence,
	}, first)
	resolution, err := ResolveLibrarySkills(ctx, atomicGenericResolutionSnapshotStore{
		LibraryStore: store,
		selections:   []LibraryResolvedSkill{selection},
	}, LibrarySkillResolutionRequest{NamespaceID: "namespace_atomic"})
	if err != nil {
		t.Fatalf("ResolveLibrarySkills: %v", err)
	}
	if len(resolution.Skills) != 1 || resolution.Skills[0].BindingID != binding.ID || resolution.Skills[0].VersionID != first.ID || resolution.Skills[0].Content != first.Content {
		t.Fatalf("atomic generic resolution=%+v, want binding %s and observed version %s", resolution.Skills, binding.ID, first.ID)
	}
}

// atomicAgentSurfaceSnapshotStore models the only safe contract an adapter can
// provide while an administrator changes a tracked binding or creates a newer
// version: one consistent selection, rather than independently readable
// binding and version tables. The resolver must not fall back to those split
// reads after accepting the snapshot.
type atomicAgentSurfaceSnapshotStore struct {
	LibraryStore
	selections []LibraryAgentSurfaceSkillSelection
}

func (s atomicAgentSurfaceSnapshotStore) LibraryAgentSurfaceSkillSelections(_ context.Context, _ string) ([]LibraryAgentSurfaceSkillSelection, error) {
	return append([]LibraryAgentSurfaceSkillSelection(nil), s.selections...), nil
}

func (s atomicAgentSurfaceSnapshotStore) LibrarySkills(context.Context) ([]LibrarySkill, error) {
	return nil, errors.New("agent-surface resolver must not split-read skills")
}

func (s atomicAgentSurfaceSnapshotStore) LibrarySkillBindings(context.Context, string) ([]LibrarySkillBinding, error) {
	return nil, errors.New("agent-surface resolver must not split-read bindings")
}

func (s atomicAgentSurfaceSnapshotStore) LibrarySkillVersions(context.Context, string) ([]LibrarySkillVersion, error) {
	return nil, errors.New("agent-surface resolver must not split-read versions")
}

func TestResolveLibrarySkillsForAgentSurfaceUsesOneAtomicSelection(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	skill, first := createLibraryResolutionSkill(t, store, "atomic-snapshot", "Atomic snapshot", "# First observed version", []string{"repo.read"})
	binding := bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: "mcpcli_atomic",
		Mode: LibraryBindingModeTrack, CapabilityCeiling: []string{"repo.read"}, CreatedBy: "resolution-test",
	})
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: skill.ID, Content: "# Later version", RequestedCapabilities: []string{"repo.read"}, CreatedBy: "resolution-test",
	}); err != nil {
		t.Fatalf("create later version: %v", err)
	}

	// Simulate a store snapshot taken before the later version became visible
	// to this client. A pre-fix resolver would independently call
	// LibrarySkillVersions and pair this binding with the later head.
	resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, atomicAgentSurfaceSnapshotStore{
		LibraryStore: store,
		selections:   []LibraryAgentSurfaceSkillSelection{{Skill: skill, Binding: binding, Version: first}},
	}, "mcpcli_atomic")
	if err != nil {
		t.Fatalf("ResolveLibrarySkillsForAgentSurface: %v", err)
	}
	if len(resolution.Skills) != 1 || resolution.Skills[0].BindingID != binding.ID || resolution.Skills[0].VersionID != first.ID || resolution.Skills[0].Content != first.Content {
		t.Fatalf("atomic resolution=%+v, want binding %s and observed version %s", resolution.Skills, binding.ID, first.ID)
	}
}
