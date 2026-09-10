package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"narthex/backend/pkg/libraryruntime"
)

func createBuiltInTestMCPClient(t *testing.T, store *FileStore, name, subject string) MCPClient {
	t.Helper()
	client, err := store.CreateMCPClient(context.Background(), MCPClient{
		Name: name, Subject: subject, CreatedBy: subject,
	})
	if err != nil {
		t.Fatalf("CreateMCPClient(%q): %v", name, err)
	}
	return client
}

func createBuiltInTestMCPClientWithDefinition(t *testing.T, store *FileStore, name, subject string, definition builtInLibrarySkillDefinition) MCPClient {
	t.Helper()
	client := MCPClient{Name: name, Subject: subject, CreatedBy: subject}
	if err := prepareMCPClientForCreate(&client); err != nil {
		t.Fatalf("prepare MCP client %q: %v", name, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	copy := copyMCPClient(client)
	store.mcpClients = append(store.mcpClients, &copy)
	if _, err := store.reconcileInstalledBuiltInLibraryForNewClientDefinitionLocked(definition); err != nil {
		store.mcpClients = store.mcpClients[:len(store.mcpClients)-1]
		t.Fatalf("reconcile MCP client %q with supplied definition: %v", name, err)
	}
	if err := store.saveLocked(); err != nil {
		store.mcpClients = store.mcpClients[:len(store.mcpClients)-1]
		t.Fatalf("save MCP client %q: %v", name, err)
	}
	return copyMCPClient(copy)
}

func reconcileBuiltInDefinitionForTest(t *testing.T, store *FileStore, definition builtInLibrarySkillDefinition) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	changed, err := store.reconcileBuiltInLibraryDefinitionLocked(definition)
	if err != nil {
		t.Fatalf("reconcile built-in definition: %v", err)
	}
	if changed {
		if err := store.saveLocked(); err != nil {
			t.Fatalf("save reconciled built-in definition: %v", err)
		}
	}
}

func requireUsingSynaxisBinding(t *testing.T, store *FileStore, clientID, versionID string) LibrarySkillBinding {
	t.Helper()
	bindings, err := store.LibrarySkillBindings(context.Background(), usingSynaxisSkillID)
	if err != nil {
		t.Fatalf("LibrarySkillBindings: %v", err)
	}
	for _, binding := range bindings {
		if binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != clientID {
			continue
		}
		if binding.ID != usingSynaxisBindingID(clientID) || binding.Mode != LibraryBindingModePin ||
			binding.PinnedVersionID != versionID || binding.Priority != usingSynaxisBindingPriority ||
			binding.CreatedBy != libraryBuiltInManager || len(binding.CapabilityCeiling) != 0 {
			t.Fatalf("managed binding for %q = %+v", clientID, binding)
		}
		return binding
	}
	t.Fatalf("no managed binding for client %q in %#v", clientID, bindings)
	return LibrarySkillBinding{}
}

func requireUsingSynaxisCurrentVersion(t *testing.T, store BuiltInLibraryCurrentVersionStore, versionID string) {
	t.Helper()
	currentVersionID, found, err := store.BuiltInLibraryCurrentVersion(context.Background(), usingSynaxisSkillID)
	if err != nil || !found || currentVersionID != versionID {
		t.Fatalf("authoritative built-in version = %q, found=%t, err=%v; want %q", currentVersionID, found, err, versionID)
	}
}

func requireBuiltInReconcileConflictPreservesFile(t *testing.T, store *FileStore) {
	t.Helper()
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileBuiltInLibrary(context.Background()); !errors.Is(err, ErrLibraryBuiltInConflict) {
		t.Fatalf("reconcile error = %v, want ErrLibraryBuiltInConflict", err)
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed reconciliation changed durable FileStore state")
	}
}

func TestUsingSynaxisBuiltInManifestContract(t *testing.T) {
	definition := usingSynaxisDefinition()
	if err := definition.validate(); err != nil {
		t.Fatalf("usingSynaxisDefinition.validate: %v", err)
	}
	if definition.SkillID != "libsk_synaxis_using_synaxis" ||
		definition.Slug != "synaxis-using-synaxis" ||
		definition.Name != "Using Synaxis" ||
		definition.Description != "Core operating guidance for agents using a subject-bound Synaxis MCP endpoint." ||
		definition.CreatedBy != "synaxis-engine" || definition.Priority != 2_147_483_647 {
		t.Fatalf("built-in identity changed: %+v", definition)
	}
	if librarySkillManagedBy(definition.SkillID) != libraryBuiltInManager || librarySkillManagedBy("libsk_authored") != "" {
		t.Fatalf("managed-by projection changed for built-in identity")
	}
	if len(definition.Versions) != 1 {
		t.Fatalf("manifest versions = %d, want one shipped v1", len(definition.Versions))
	}
	versionDefinition := definition.Versions[0]
	if versionDefinition.Revision != 1 || versionDefinition.VersionID != "libskv_synaxis_using_synaxis_v1" ||
		definition.CurrentVersionID != versionDefinition.VersionID || definition.VersionIDPrefix != "libskv_synaxis_using_synaxis_v" {
		t.Fatalf("built-in version identity changed: definition=%+v version=%+v", definition, versionDefinition)
	}
	const expectedDigest = "e9e8a2f1d6955d9b78d099edbe012270397566128cb2e0b11c302ffff03e5a46"
	if versionDefinition.Content != usingSynaxisSkillContent || len(versionDefinition.Content) != 3231 ||
		versionDefinition.ContentDigest != expectedDigest || libraryDigest(versionDefinition.Content) != expectedDigest ||
		!strings.HasSuffix(versionDefinition.Content, "\n") {
		t.Fatalf("built-in v1 content contract changed: bytes=%d manifestDigest=%q calculatedDigest=%q", len(versionDefinition.Content), versionDefinition.ContentDigest, libraryDigest(versionDefinition.Content))
	}
	for _, required := range []string{
		"## Discover the live surface", "`library_skill_activation`", "## Call safely",
		"## Use governed memory deliberately", "`library_memory_recall`", "`library_memory_propose`",
		"## Recover without bypassing policy", "## Preserve the authority boundary",
		"not credentials, permissions, or proof of execution",
	} {
		if !strings.Contains(versionDefinition.Content, required) {
			t.Fatalf("built-in v1 is missing required guidance %q", required)
		}
	}

	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	version := definition.version(versionDefinition, now)
	if version.Digest != expectedDigest || len(version.RequestedCapabilities) != 0 || version.CreatedBy != libraryBuiltInManager {
		t.Fatalf("built-in immutable version is not capability-free: %+v", version)
	}
	binding := definition.binding("mcpcli_manifest", now)
	if binding.Mode != LibraryBindingModePin || binding.PinnedVersionID != version.ID ||
		len(binding.CapabilityCeiling) != 0 || binding.Priority != usingSynaxisBindingPriority {
		t.Fatalf("built-in binding contract changed: %+v", binding)
	}
	if effective := ResolveLibraryCapabilities(version.RequestedCapabilities, binding.CapabilityCeiling, []string{"tools.read", "tools.write"}); len(effective) != 0 {
		t.Fatalf("capability-free built-in resolved authority from a live grant: %v", effective)
	}
	if got := libraryruntime.DefaultLimits().MaxSkills; got != 33 {
		t.Fatalf("portable activation skill limit = %d, want built-in plus 32 assigned skills", got)
	}
	if got := libraryruntime.DefaultLimits().MaxContextBytes; got != 132<<10 {
		t.Fatalf("portable activation context limit = %d, want prior 128 KiB budget plus managed-guide reserve", got)
	}
}

func TestFileStoreReconcileUsingSynaxisForExistingRevokedAndNewClients(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	existing := createBuiltInTestMCPClient(t, store, "Existing agent", "usr_existing")
	revoked := createBuiltInTestMCPClient(t, store, "Revoked agent", "usr_revoked")
	revoked, err := store.RevokeMCPClient(ctx, revoked.ID, "usr_owner", MCPClientPrecondition{ID: revoked.ID, Revision: revoked.Revision})
	if err != nil {
		t.Fatalf("RevokeMCPClient: %v", err)
	}
	if revoked.Status != MCPClientStatusRevoked {
		t.Fatalf("revoked client status = %q", revoked.Status)
	}

	if err := ReconcileBuiltInLibrary(ctx, store); err != nil {
		t.Fatalf("ReconcileBuiltInLibrary: %v", err)
	}
	requireUsingSynaxisCurrentVersion(t, store, usingSynaxisSkillVersionID)
	skill, found := store.LibrarySkill(ctx, usingSynaxisSkillID)
	if !found || !builtInSkillMatches(skill, usingSynaxisDefinition()) {
		t.Fatalf("persisted built-in skill = %+v, found=%t", skill, found)
	}
	version, found := store.LibrarySkillVersion(ctx, usingSynaxisSkillID, usingSynaxisSkillVersionID)
	if !found || !builtInVersionMatches(version, usingSynaxisDefinition(), usingSynaxisDefinition().Versions[0]) {
		t.Fatalf("persisted built-in version = %+v, found=%t", version, found)
	}
	requireUsingSynaxisBinding(t, store, existing.ID, usingSynaxisSkillVersionID)
	requireUsingSynaxisBinding(t, store, revoked.ID, usingSynaxisSkillVersionID)

	newClient := createBuiltInTestMCPClient(t, store, "Created after install", "usr_new")
	requireUsingSynaxisBinding(t, store, newClient.ID, usingSynaxisSkillVersionID)
	bindings, err := store.LibrarySkillBindings(ctx, usingSynaxisSkillID)
	if err != nil || len(bindings) != 3 {
		t.Fatalf("managed bindings after new-client create = %#v, err=%v", bindings, err)
	}
	for _, client := range []MCPClient{existing, revoked, newClient} {
		selections, err := store.LibraryAgentSurfaceSkillSelections(ctx, client.ID)
		if err != nil || len(selections) != 1 || selections[0].Skill.ID != usingSynaxisSkillID || selections[0].Version.ID != usingSynaxisSkillVersionID {
			t.Fatalf("client %q selections = %#v, err=%v", client.ID, selections, err)
		}
	}
}

func TestFileStoreUsingSynaxisZeroClientReconcilePersistsAuthoritativeVersion(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("zero-client reconcile: %v", err)
	}
	requireUsingSynaxisCurrentVersion(t, store, usingSynaxisSkillVersionID)
	clients, err := store.MCPClients(ctx)
	if err != nil || len(clients) != 0 {
		t.Fatalf("zero-client reconcile created clients = %#v, err=%v", clients, err)
	}

	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatalf("reload zero-client FileStore: %v", err)
	}
	requireUsingSynaxisCurrentVersion(t, reloaded, usingSynaxisSkillVersionID)
	client := createBuiltInTestMCPClient(t, reloaded, "Created after zero-client install", "usr_zero_client")
	requireUsingSynaxisBinding(t, reloaded, client.ID, usingSynaxisSkillVersionID)
}

func TestFileStoreUsingSynaxisReconcileIsIdempotentAcrossReload(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createBuiltInTestMCPClient(t, store, "Durable agent", "usr_durable")
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	requireUsingSynaxisCurrentVersion(t, store, usingSynaxisSkillVersionID)
	initial, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read initial FileStore: %v", err)
	}
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("repeat reconcile: %v", err)
	}
	repeated, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read repeated FileStore: %v", err)
	}
	if !bytes.Equal(initial, repeated) {
		t.Fatal("idempotent reconcile rewrote durable FileStore state")
	}

	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatalf("reload FileStore: %v", err)
	}
	if err := reloaded.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("reconcile after reload: %v", err)
	}
	afterReload, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read reloaded FileStore: %v", err)
	}
	if !bytes.Equal(initial, afterReload) {
		t.Fatal("reload plus idempotent reconcile changed durable FileStore state")
	}
	requireUsingSynaxisCurrentVersion(t, reloaded, usingSynaxisSkillVersionID)
	versions, err := reloaded.LibrarySkillVersions(ctx, usingSynaxisSkillID)
	if err != nil || len(versions) != 1 || versions[0].ID != usingSynaxisSkillVersionID {
		t.Fatalf("reloaded built-in versions = %#v, err=%v", versions, err)
	}
	bindings, err := reloaded.LibrarySkillBindings(ctx, usingSynaxisSkillID)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("reloaded built-in bindings = %#v, err=%v", bindings, err)
	}
	requireUsingSynaxisBinding(t, reloaded, client.ID, usingSynaxisSkillVersionID)
}

func TestUsingSynaxisActivationIsHighestPriorityAndReferenceVerified(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createBuiltInTestMCPClient(t, store, "Activation agent", "usr_activation")
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("reconcile built-in: %v", err)
	}
	authored, authoredVersion, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "workspace-guide", Name: "Workspace guide", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{
		Content: "# Workspace guide\nUse current workspace evidence.", RequestedCapabilities: []string{"workspace.read"}, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("create authored skill: %v", err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: authored.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
		Mode: LibraryBindingModePin, PinnedVersionID: authoredVersion.ID,
		CapabilityCeiling: []string{"workspace.read"}, Priority: usingSynaxisBindingPriority - 1, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatalf("bind authored skill: %v", err)
	}

	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}
	if len(bundle.Skills) != 2 || bundle.Skills[0].SkillID != usingSynaxisSkillID || bundle.Skills[1].SkillID != authored.ID {
		t.Fatalf("activation order = %+v, want managed guide before assigned skill", bundle.Skills)
	}
	builtIn := bundle.Skills[0]
	if builtIn.SkillSlug != usingSynaxisSkillSlug || builtIn.VersionID != usingSynaxisSkillVersionID ||
		builtIn.Instructions != usingSynaxisSkillContent || builtIn.ContentDigest != usingSynaxisExpectedContentDigest ||
		builtIn.Binding.ID != usingSynaxisBindingID(client.ID) || builtIn.Binding.Mode != LibraryBindingModePin ||
		builtIn.Binding.Priority != usingSynaxisBindingPriority || len(builtIn.Constraints.RequestedCapabilities) != 0 ||
		len(builtIn.Constraints.CapabilityCeiling) != 0 {
		t.Fatalf("managed activation selection = %+v", builtIn)
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal activation bundle: %v", err)
	}
	verified, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewReader(payload), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("reference adapter rejected managed activation: %v", err)
	}
	verifiedSkills := verified.Skills()
	if verified.BundleDigest() != bundle.BundleDigest || len(verifiedSkills) != 2 ||
		verifiedSkills[0].SkillID != usingSynaxisSkillID || verifiedSkills[0].Instructions != usingSynaxisSkillContent {
		t.Fatalf("reference-verified activation = digest %q skills %+v", verified.BundleDigest(), verifiedSkills)
	}
	if _, err := libraryruntime.BuildContext(verified, libraryruntime.Limits{}); err != nil {
		t.Fatalf("reference adapter could not build bounded context: %v", err)
	}
}

func TestUsingSynaxisContextReservePreservesPriorWorkspaceBudget(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createBuiltInTestMCPClient(t, store, "Context budget agent", "usr_context_budget")
	for index := 0; index < 4; index++ {
		suffix := string(rune('a' + index))
		skill, version, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: "context-budget-" + suffix, Name: "Context budget " + suffix, CreatedBy: "usr_owner",
		}, LibrarySkillVersion{Content: strings.Repeat(suffix, 31<<10), CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatalf("create prior-budget skill %d: %v", index, err)
		}
		if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
			SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
			Mode: LibraryBindingModePin, PinnedVersionID: version.ID, Priority: index, CreatedBy: "usr_owner",
		}); err != nil {
			t.Fatalf("bind prior-budget skill %d: %v", index, err)
		}
	}

	priorBundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("build prior-budget activation: %v", err)
	}
	priorPayload, err := json.Marshal(priorBundle)
	if err != nil {
		t.Fatal(err)
	}
	priorLimits := libraryruntime.Limits{MaxSkills: 32, MaxInstructionBytes: 32 << 10, MaxContextBytes: 128 << 10}
	priorVerified, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewReader(priorPayload), priorLimits)
	if err != nil {
		t.Fatalf("previous adapter rejected previously valid workspace bundle: %v", err)
	}
	priorContext, err := libraryruntime.BuildContext(priorVerified, priorLimits)
	if err != nil {
		t.Fatalf("previous 128 KiB workspace context did not fit: %v", err)
	}

	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("add managed guide: %v", err)
	}
	managedBundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("build activation with managed guide: %v", err)
	}
	managedPayload, err := json.Marshal(managedBundle)
	if err != nil {
		t.Fatal(err)
	}
	managedVerified, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewReader(managedPayload), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("current adapter rejected preserved workspace budget plus guide: %v", err)
	}
	managedContext, err := libraryruntime.BuildContext(managedVerified, libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("managed guide consumed the prior workspace context budget: %v", err)
	}
	addedBytes := len(managedContext.Document) - len(priorContext.Document)
	if addedBytes <= 0 || addedBytes > 4<<10 {
		t.Fatalf("managed guide canonical context cost = %d bytes, reserve is 4096", addedBytes)
	}
}

func TestFileStoreUsingSynaxisUpgradeAndRollbackRepinWithoutDeletingVersions(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createBuiltInTestMCPClient(t, store, "Upgrade agent", "usr_upgrade")
	v1 := usingSynaxisDefinition()
	reconcileBuiltInDefinitionForTest(t, store, v1)
	requireUsingSynaxisCurrentVersion(t, store, usingSynaxisSkillVersionID)
	requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)

	v2Content := usingSynaxisSkillContent + "\n## Engine v2 note\nRefresh the verified activation after an Engine upgrade.\n"
	v2ID := usingSynaxisSkillVersionIDPrefix + "2"
	v2 := v1
	v2.Versions = append(append([]builtInLibrarySkillVersionDefinition(nil), v1.Versions...), builtInLibrarySkillVersionDefinition{
		Revision: 2, VersionID: v2ID, Content: v2Content, ContentDigest: libraryDigest(v2Content),
	})
	v2.CurrentVersionID = v2ID
	if err := v2.validate(); err != nil {
		t.Fatalf("v2 manifest validation: %v", err)
	}
	reconcileBuiltInDefinitionForTest(t, store, v2)
	requireUsingSynaxisCurrentVersion(t, store, v2ID)
	requireUsingSynaxisBinding(t, store, client.ID, v2ID)
	// CreateMCPClient is compiled against v1 in this test binary. It must still
	// follow a v2 marker written by a newer replica instead of splitting the
	// durable client set onto its local manifest head.
	v1ReplicaClient := createBuiltInTestMCPClient(t, store, "Created by v1 replica under v2", "usr_mixed_v1")
	requireUsingSynaxisBinding(t, store, v1ReplicaClient.ID, v2ID)
	versions, err := store.LibrarySkillVersions(ctx, usingSynaxisSkillID)
	if err != nil || len(versions) != 2 || versions[0].ID != usingSynaxisSkillVersionID || versions[1].ID != v2ID {
		t.Fatalf("versions after v2 rollout = %#v, err=%v", versions, err)
	}

	// A rollback uses the older binary's known manifest. It repins to v1 but
	// retains the immutable v2 row so a later re-upgrade remains auditable.
	reconcileBuiltInDefinitionForTest(t, store, v1)
	requireUsingSynaxisCurrentVersion(t, store, usingSynaxisSkillVersionID)
	requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)
	requireUsingSynaxisBinding(t, store, v1ReplicaClient.ID, usingSynaxisSkillVersionID)
	// Conversely, a v2 process can create against an intentional v1 rollback.
	// Storage follows the durable marker; runtime activation independently
	// proves whether that exact version is compiled into the serving binary.
	v2ReplicaClient := createBuiltInTestMCPClientWithDefinition(t, store, "Created by v2 replica under v1", "usr_mixed_v2", v2)
	requireUsingSynaxisBinding(t, store, v2ReplicaClient.ID, usingSynaxisSkillVersionID)
	versions, err = store.LibrarySkillVersions(ctx, usingSynaxisSkillID)
	if err != nil || len(versions) != 2 || versions[1].ID != v2ID || versions[1].Content != v2Content {
		t.Fatalf("rollback deleted or changed a shipped version: %#v, err=%v", versions, err)
	}

	reconcileBuiltInDefinitionForTest(t, store, v2)
	requireUsingSynaxisCurrentVersion(t, store, v2ID)
	requireUsingSynaxisBinding(t, store, client.ID, v2ID)
	requireUsingSynaxisBinding(t, store, v1ReplicaClient.ID, v2ID)
	requireUsingSynaxisBinding(t, store, v2ReplicaClient.ID, v2ID)
	versions, err = store.LibrarySkillVersions(ctx, usingSynaxisSkillID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("re-upgrade duplicated immutable versions: %#v, err=%v", versions, err)
	}
	store.mu.Lock()
	generation := store.librarySkillBindingGenerationLocked(usingSynaxisSkillID)
	store.mu.Unlock()
	if generation != 9 {
		t.Fatalf("managed binding generation = %d, want three creates plus six repins", generation)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	reconcileBuiltInDefinitionForTest(t, store, v2)
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent v2 reconciliation rewrote durable FileStore state")
	}
}

func TestFileStoreUsingSynaxisTamperFailsClosedAndRollsBack(t *testing.T) {
	t.Run("manifest digest", func(t *testing.T) {
		definition := usingSynaxisDefinition()
		definition.Versions = append([]builtInLibrarySkillVersionDefinition(nil), definition.Versions...)
		definition.Versions[0].Content += "tampered"
		if err := definition.validate(); !errors.Is(err, ErrLibraryBuiltInConflict) {
			t.Fatalf("changed content under v1 error = %v, want built-in conflict", err)
		}
	})

	t.Run("persisted version", func(t *testing.T) {
		ctx := context.Background()
		store := newLibraryFileStore(t)
		client := createBuiltInTestMCPClient(t, store, "Tamper agent", "usr_tamper")
		if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
			t.Fatalf("initial reconcile: %v", err)
		}
		store.mu.Lock()
		version := store.librarySkillVersionLocked(usingSynaxisSkillID, usingSynaxisSkillVersionID)
		version.Content += "\nmalicious but internally digested change"
		version.Digest = libraryDigest(version.Content)
		if err := store.saveLocked(); err != nil {
			store.mu.Unlock()
			t.Fatalf("persist tamper fixture: %v", err)
		}
		store.mu.Unlock()
		before, err := os.ReadFile(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ReconcileBuiltInLibrary(ctx); !errors.Is(err, ErrLibraryBuiltInConflict) {
			t.Fatalf("tampered reconcile error = %v, want built-in conflict", err)
		}
		after, err := os.ReadFile(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("failed reconcile rewrote tampered durable state")
		}
		persisted, found := store.LibrarySkillVersion(ctx, usingSynaxisSkillID, usingSynaxisSkillVersionID)
		if !found || persisted.Content == usingSynaxisSkillContent || persisted.Digest != libraryDigest(persisted.Content) {
			t.Fatalf("failed reconcile silently repaired or further corrupted tampered row: %+v, found=%t", persisted, found)
		}
		beforeClients, err := store.MCPClients(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Must roll back", Subject: "usr_blocked", CreatedBy: "usr_blocked"}); !errors.Is(err, ErrLibraryBuiltInConflict) {
			t.Fatalf("new-client create against tampered manifest error = %v, want built-in conflict", err)
		}
		afterClients, err := store.MCPClients(ctx)
		if err != nil || len(afterClients) != len(beforeClients) {
			t.Fatalf("failed new-client reconcile committed client: before=%d after=%d err=%v", len(beforeClients), len(afterClients), err)
		}
		if _, found := store.MCPClientBySlug(ctx, "must-roll-back"); found {
			t.Fatal("failed new-client reconcile left a durable registration")
		}
		requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)
	})

	t.Run("partial install", func(t *testing.T) {
		ctx := context.Background()
		store := newLibraryFileStore(t)
		client := createBuiltInTestMCPClient(t, store, "Conflict agent", "usr_conflict")
		definition := usingSynaxisDefinition()
		malformed := definition.binding(client.ID, time.Now().UTC())
		malformed.CreatedBy = "attacker"
		store.mu.Lock()
		store.librarySkillBindings = append(store.librarySkillBindings, &malformed)
		if err := store.saveLocked(); err != nil {
			store.mu.Unlock()
			t.Fatalf("persist malformed binding fixture: %v", err)
		}
		store.mu.Unlock()
		before, err := os.ReadFile(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ReconcileBuiltInLibrary(ctx); !errors.Is(err, ErrLibraryBuiltInConflict) {
			t.Fatalf("malformed reserved binding reconcile error = %v, want built-in conflict", err)
		}
		after, err := os.ReadFile(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("failed install changed durable FileStore state")
		}
		if _, found := store.LibrarySkill(ctx, usingSynaxisSkillID); found {
			t.Fatal("failed install left an in-memory built-in skill")
		}
		versions, err := store.LibrarySkillVersions(ctx, usingSynaxisSkillID)
		if err != nil || len(versions) != 0 {
			t.Fatalf("failed install left in-memory versions = %#v, err=%v", versions, err)
		}
	})

	t.Run("generic and orphan bindings", func(t *testing.T) {
		store := newLibraryFileStore(t)
		client := createBuiltInTestMCPClient(t, store, "Reserved binding agent", "usr_binding_conflict")
		if err := store.ReconcileBuiltInLibrary(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		now := time.Now().UTC()
		workspaceBinding := LibrarySkillBinding{
			ID: "libskb_unmanaged_workspace", SkillID: usingSynaxisSkillID,
			ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace_conflict", Mode: LibraryBindingModeTrack,
			CreatedBy: "usr_owner", CreatedAt: now, UpdatedAt: now,
		}
		orphanBinding := usingSynaxisDefinition().binding("mcpcli_missing", now)
		store.librarySkillBindings = append(store.librarySkillBindings, &workspaceBinding, &orphanBinding)
		if err := store.saveLocked(); err != nil {
			store.mu.Unlock()
			t.Fatal(err)
		}
		store.mu.Unlock()
		beforeClients, err := store.MCPClients(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateMCPClient(context.Background(), MCPClient{
			Name: "Blocked by malformed binding", Subject: "usr_binding_blocked", CreatedBy: "usr_binding_blocked",
		}); !errors.Is(err, ErrLibraryBuiltInConflict) {
			t.Fatalf("new-client create against malformed global binding error = %v, want built-in conflict", err)
		}
		afterClients, err := store.MCPClients(context.Background())
		if err != nil || len(afterClients) != len(beforeClients) {
			t.Fatalf("malformed global binding committed client: before=%d after=%d err=%v", len(beforeClients), len(afterClients), err)
		}
		if _, found := store.MCPClientBySlug(context.Background(), "blocked-by-malformed-binding"); found {
			t.Fatal("malformed global binding left a durable client registration")
		}
		requireBuiltInReconcileConflictPreservesFile(t, store)
		requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)
	})

	t.Run("unmanaged built-in version", func(t *testing.T) {
		store := newLibraryFileStore(t)
		if err := store.ReconcileBuiltInLibrary(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		content := "# Unauthorized managed head"
		version := LibrarySkillVersion{
			ID: "libskv_unmanaged_head", SkillID: usingSynaxisSkillID, Version: 2,
			Content: content, Digest: libraryDigest(content), RequestedCapabilities: []string{},
			CreatedBy: libraryBuiltInManager, CreatedAt: time.Now().UTC(),
		}
		store.librarySkillVersions = append(store.librarySkillVersions, &version)
		if err := store.saveLocked(); err != nil {
			store.mu.Unlock()
			t.Fatal(err)
		}
		store.mu.Unlock()
		requireBuiltInReconcileConflictPreservesFile(t, store)
	})

	t.Run("reserved future id on another skill", func(t *testing.T) {
		ctx := context.Background()
		store := newLibraryFileStore(t)
		skill, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: "reserved-id-squat", Name: "Reserved ID squat", CreatedBy: "usr_owner",
		}, LibrarySkillVersion{Content: "# Ordinary v1", CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		content := "# Squatted future ID"
		version := LibrarySkillVersion{
			ID: usingSynaxisSkillVersionIDPrefix + "2", SkillID: skill.ID, Version: 2,
			Content: content, Digest: libraryDigest(content), RequestedCapabilities: []string{},
			CreatedBy: "usr_owner", CreatedAt: time.Now().UTC(),
		}
		store.librarySkillVersions = append(store.librarySkillVersions, &version)
		if err := store.saveLocked(); err != nil {
			store.mu.Unlock()
			t.Fatal(err)
		}
		store.mu.Unlock()
		requireBuiltInReconcileConflictPreservesFile(t, store)
	})
}

func TestFileStoreUsingSynaxisReservedMutationAndAuthoringLeaseProtections(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("install built-in: %v", err)
	}
	normal, normalVersion, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "normal-skill", Name: "Normal skill", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Normal", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatalf("create normal skill: %v", err)
	}

	createCases := []struct {
		name    string
		skill   LibrarySkill
		version LibrarySkillVersion
	}{
		{"skill id", LibrarySkill{ID: usingSynaxisSkillID, Slug: "reserved-id", Name: "Reserved ID"}, LibrarySkillVersion{Content: "# no"}},
		{"skill slug", LibrarySkill{Slug: usingSynaxisSkillSlug, Name: "Reserved slug"}, LibrarySkillVersion{Content: "# no"}},
		{"version id", LibrarySkill{Slug: "reserved-version", Name: "Reserved version"}, LibrarySkillVersion{ID: usingSynaxisSkillVersionIDPrefix + "99", Content: "# no"}},
	}
	for _, testCase := range createCases {
		t.Run("create "+testCase.name, func(t *testing.T) {
			if _, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, testCase.skill, testCase.version); !errors.Is(err, ErrLibraryBuiltInManaged) {
				t.Fatalf("error = %v, want managed built-in", err)
			}
		})
	}
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: usingSynaxisSkillID, Content: "# unauthorized v2", CreatedBy: "usr_owner",
	}); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("append built-in version error = %v, want managed built-in", err)
	}
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		ID: usingSynaxisSkillVersionIDPrefix + "99", SkillID: normal.ID, Content: "# reserved id", CreatedBy: "usr_owner",
	}); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("append reserved version id error = %v, want managed built-in", err)
	}

	client := newAuthoringLeaseMCPClient(t, store, "usr_lease_guard")
	managedBinding := usingSynaxisDefinition().binding(client.ID, time.Now().UTC())
	if _, err := store.UpsertLibrarySkillBinding(ctx, managedBinding); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("upsert built-in binding error = %v, want managed built-in", err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		ID: usingSynaxisBindingIDPrefix + "reserved", SkillID: normal.ID,
		ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModeTrack,
	}); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("upsert reserved binding id error = %v, want managed built-in", err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, usingSynaxisSkillID, usingSynaxisBindingID(client.ID)); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("delete built-in binding error = %v, want managed built-in", err)
	}
	requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)

	lease, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner")
	if err != nil {
		t.Fatalf("grant generic authoring lease: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "reserved-create", Name: "Reserved", Slug: usingSynaxisSkillSlug, Content: "# unauthorized",
	}); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("leased reserved-slug create error = %v, want managed built-in", err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "reserved-update", SkillID: usingSynaxisSkillID,
		ExpectedVersionID: usingSynaxisSkillVersionID, ExpectedVersionDigest: usingSynaxisExpectedContentDigest,
		Content: "# unauthorized",
	}); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("leased built-in update error = %v, want managed built-in", err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: usingSynaxisSkillID, ExpectedVersionID: usingSynaxisSkillVersionID, ExpectedVersionDigest: usingSynaxisExpectedContentDigest,
	}, "usr_owner"); !errors.Is(err, ErrLibraryBuiltInManaged) {
		t.Fatalf("built-in adoption lease error = %v, want managed built-in", err)
	}
	auditEvents, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationCreate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationUpdate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationAdopt) != 1 {
		t.Fatalf("managed authoring rejections were not durably audited: events=%+v err=%v", auditEvents, err)
	}
	currentLease, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || currentLease.ID != lease.ID || currentLease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("managed write attempts consumed or replaced lease: lease=%+v found=%t err=%v", currentLease, found, err)
	}
	versions, err := store.LibrarySkillVersions(ctx, usingSynaxisSkillID)
	if err != nil || len(versions) != 1 || versions[0].ID != usingSynaxisSkillVersionID {
		t.Fatalf("managed write attempts changed built-in versions: %#v, err=%v", versions, err)
	}
	if persistedNormal, found := store.LibrarySkillVersion(ctx, normal.ID, normalVersion.ID); !found || !reflect.DeepEqual(persistedNormal, normalVersion) {
		t.Fatalf("reserved write tests changed normal immutable version: %+v, found=%t", persistedNormal, found)
	}
}

type optionalBuiltInReconcileStore struct {
	calls int
	ctx   context.Context
	err   error
}

func (store *optionalBuiltInReconcileStore) ReconcileBuiltInLibrary(ctx context.Context) error {
	store.calls++
	store.ctx = ctx
	return store.err
}

func TestReconcileBuiltInLibraryOptionalStoreBoundary(t *testing.T) {
	if err := ReconcileBuiltInLibrary(context.Background(), nil); err != nil {
		t.Fatalf("nil optional store: %v", err)
	}
	if err := ReconcileBuiltInLibrary(context.Background(), struct{}{}); err != nil {
		t.Fatalf("store without built-in facet: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ReconcileBuiltInLibrary(canceled, struct{}{}); err != nil {
		t.Fatalf("optional no-op consulted context: %v", err)
	}

	sentinel := errors.New("reconcile failed")
	spy := &optionalBuiltInReconcileStore{err: sentinel}
	if err := ReconcileBuiltInLibrary(nil, spy); !errors.Is(err, sentinel) {
		t.Fatalf("reconciler error = %v, want sentinel", err)
	}
	if spy.calls != 1 || spy.ctx == nil {
		t.Fatalf("optional reconciler calls=%d ctx=%v", spy.calls, spy.ctx)
	}

	store := newLibraryFileStore(t)
	if err := ReconcileBuiltInLibrary(canceled, store); !errors.Is(err, context.Canceled) {
		t.Fatalf("FileStore canceled reconcile = %v, want context cancellation", err)
	}
	if _, found := store.LibrarySkill(context.Background(), usingSynaxisSkillID); found {
		t.Fatal("canceled reconcile installed the built-in skill")
	}
}
