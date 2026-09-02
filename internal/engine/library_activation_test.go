package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"narthex/backend/pkg/libraryruntime"
)

func TestBuildLibrarySkillActivationBundleForAgentSurfaceIsDeterministicAndContextOnly(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	agentSurfaceID := "mcpcli_runtime_activation"

	incident, first := createLibraryResolutionSkill(t, store, "incident-triage", "Incident triage", "# Inspect alerts before acting", []string{"tickets.read", "alerts.read"})
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: incident.ID, Content: "# Newer incident draft", RequestedCapabilities: []string{"alerts.read"}, CreatedBy: "activation-test",
	}); err != nil {
		t.Fatalf("create newer incident version: %v", err)
	}
	release, releaseVersion := createLibraryResolutionSkill(t, store, "release-check", "Release check", "# Verify release evidence", []string{"releases.read"})
	ignored, _ := createLibraryResolutionSkill(t, store, "generic-only", "Generic only", "# This must not reach the agent surface", []string{"repository.read"})

	incidentBinding := bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: incident.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: agentSurfaceID,
		Mode: LibraryBindingModePin, PinnedVersionID: first.ID,
		CapabilityCeiling: []string{"tickets.read", "alerts.read"}, Priority: 10, CreatedBy: "activation-test",
	})
	releaseBinding := bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: release.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: agentSurfaceID,
		Mode: LibraryBindingModeTrack, CapabilityCeiling: []string{"releases.read"}, Priority: 1, CreatedBy: "activation-test",
	})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: ignored.ID, ScopeKind: LibraryScopeRepository, ScopeID: "repo_private",
		Mode: LibraryBindingModeTrack, CreatedBy: "activation-test",
	})

	firstBundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, agentSurfaceID)
	if err != nil {
		t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}
	secondBundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, agentSurfaceID)
	if err != nil {
		t.Fatalf("repeat BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}
	if !reflect.DeepEqual(firstBundle, secondBundle) {
		t.Fatalf("activation bundle changed without state change:\nfirst=%+v\nsecond=%+v", firstBundle, secondBundle)
	}
	if firstBundle.ContractVersion != LibrarySkillActivationContractVersion || firstBundle.AgentSurface.Kind != "mcp_client" || firstBundle.AgentSurface.ID != agentSurfaceID {
		t.Fatalf("activation contract context=%+v", firstBundle)
	}
	if len(firstBundle.Skills) != 2 {
		t.Fatalf("activation skills=%+v, want exactly two explicit agent-surface selections", firstBundle.Skills)
	}
	if firstBundle.Skills[0].SkillID != incident.ID || firstBundle.Skills[0].VersionID != first.ID || firstBundle.Skills[0].Instructions != first.Content ||
		firstBundle.Skills[0].ContentDigest != first.Digest || firstBundle.Skills[0].Binding.ID != incidentBinding.ID || firstBundle.Skills[0].Binding.Mode != LibraryBindingModePin {
		t.Fatalf("pinned activation skill=%+v", firstBundle.Skills[0])
	}
	if !reflect.DeepEqual(firstBundle.Skills[0].Constraints.RequestedCapabilities, []string{"alerts.read", "tickets.read"}) ||
		!reflect.DeepEqual(firstBundle.Skills[0].Constraints.CapabilityCeiling, []string{"alerts.read", "tickets.read"}) {
		t.Fatalf("pinned activation constraints=%+v", firstBundle.Skills[0].Constraints)
	}
	if firstBundle.Skills[1].SkillID != release.ID || firstBundle.Skills[1].VersionID != releaseVersion.ID ||
		firstBundle.Skills[1].Binding.ID != releaseBinding.ID || firstBundle.Skills[1].Instructions != releaseVersion.Content {
		t.Fatalf("tracked activation skill=%+v", firstBundle.Skills[1])
	}
	for _, skill := range firstBundle.Skills {
		if skill.ContentDigest != libraryDigest(skill.Instructions) {
			t.Fatalf("skill content digest does not cover exact instructions: %+v", skill)
		}
	}
	calculatedDigest, err := librarySkillActivationBundleDigest(firstBundle)
	if err != nil {
		t.Fatal(err)
	}
	if firstBundle.BundleDigest != calculatedDigest || !libraryDigestPattern.MatchString(firstBundle.BundleDigest) {
		t.Fatalf("activation bundle digest=%q calculated=%q", firstBundle.BundleDigest, calculatedDigest)
	}
	if !strings.Contains(firstBundle.AuthorityNotice, "grants no credentials") || len(firstBundle.HostResponsibilities) != 3 || !strings.Contains(firstBundle.HostResponsibilities[0], "does not inject") {
		t.Fatalf("activation contract did not state host/authority boundary: %+v", firstBundle)
	}

	payload, err := json.Marshal(firstBundle)
	if err != nil {
		t.Fatal(err)
	}
	verifiedByReferenceAdapter, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewReader(payload), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("open libraryruntime adapter rejected Engine activation bundle: %v", err)
	}
	if verifiedByReferenceAdapter.BundleDigest() != firstBundle.BundleDigest || len(verifiedByReferenceAdapter.Skills()) != len(firstBundle.Skills) {
		t.Fatalf("reference adapter changed Engine activation selection: digest=%q skills=%+v", verifiedByReferenceAdapter.BundleDigest(), verifiedByReferenceAdapter.Skills())
	}
	if _, err := libraryruntime.BuildContext(verifiedByReferenceAdapter, libraryruntime.Limits{}); err != nil {
		t.Fatalf("open libraryruntime adapter could not build bounded Engine context: %v", err)
	}
	for _, forbidden := range []string{`"createdBy"`, `"effectiveCapabilities"`, `"actorRef"`, `"subject"`, `"oauthClientId"`, `"connectionNamespace`, `"scopeId"`, "repo_private", "Generic only"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("activation bundle leaked forbidden %q: %s", forbidden, payload)
		}
	}
}

type corruptActivationVersionStore struct{ LibraryStore }

func (s corruptActivationVersionStore) LibraryAgentSurfaceSkillSelections(ctx context.Context, agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	selections, err := s.LibraryStore.LibraryAgentSurfaceSkillSelections(ctx, agentSurfaceID)
	if err == nil && len(selections) > 0 {
		selections[0].Version.Digest = strings.Repeat("0", 64)
	}
	return selections, err
}

func TestBuildLibrarySkillActivationBundleRejectsMismatchedInstructionDigest(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	skill, version := createLibraryResolutionSkill(t, store, "digest-check", "Digest check", "# Exact instructions", []string{"alerts.read"})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: "mcpcli_digest",
		Mode: LibraryBindingModePin, PinnedVersionID: version.ID, CreatedBy: "activation-test",
	})

	_, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, corruptActivationVersionStore{LibraryStore: store}, "mcpcli_digest")
	if !errors.Is(err, ErrLibrarySkillActivationIntegrity) {
		t.Fatalf("activation bundle integrity error=%v, want %v", err, ErrLibrarySkillActivationIntegrity)
	}
}

type invalidUTF8ActivationVersionStore struct{ LibraryStore }

func (s invalidUTF8ActivationVersionStore) LibraryAgentSurfaceSkillSelections(ctx context.Context, agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	selections, err := s.LibraryStore.LibraryAgentSurfaceSkillSelections(ctx, agentSurfaceID)
	if err == nil && len(selections) > 0 {
		selections[0].Version.Content = string([]byte{0xff})
		selections[0].Version.Digest = libraryDigest(selections[0].Version.Content)
	}
	return selections, err
}

func TestBuildLibrarySkillActivationBundleRejectsInstructionsThatCannotRoundTripJSON(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	skill, version := createLibraryResolutionSkill(t, store, "utf8-check", "UTF-8 check", "# Valid stored instructions", []string{"alerts.read"})
	bindLibraryResolutionSkill(t, store, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: "mcpcli_utf8",
		Mode: LibraryBindingModePin, PinnedVersionID: version.ID, CreatedBy: "activation-test",
	})

	_, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, invalidUTF8ActivationVersionStore{LibraryStore: store}, "mcpcli_utf8")
	if !errors.Is(err, ErrLibrarySkillActivationIntegrity) {
		t.Fatalf("activation bundle UTF-8 integrity error=%v, want %v", err, ErrLibrarySkillActivationIntegrity)
	}
}

type fixedActivationSelectionStore struct {
	LibraryStore
	selections []LibraryAgentSurfaceSkillSelection
}

func (s fixedActivationSelectionStore) LibraryAgentSurfaceSkillSelections(_ context.Context, _ string) ([]LibraryAgentSurfaceSkillSelection, error) {
	return append([]LibraryAgentSurfaceSkillSelection(nil), s.selections...), nil
}

func activationLimitSelection(agentSurfaceID string, index int, content string) LibraryAgentSurfaceSkillSelection {
	suffix := fmt.Sprintf("%02d", index)
	skillID := "sk_activation_limit_" + suffix
	return LibraryAgentSurfaceSkillSelection{
		Skill: LibrarySkill{ID: skillID, Slug: "activation-limit-" + suffix, Name: "Activation limit " + suffix},
		Binding: LibrarySkillBinding{
			ID: "bind_activation_limit_" + suffix, SkillID: skillID,
			ScopeKind: LibraryScopeAgentSurface, ScopeID: agentSurfaceID, Mode: LibraryBindingModeTrack,
			CapabilityCeiling: []string{}, Priority: index,
		},
		Version: LibrarySkillVersion{
			ID: "ver_activation_limit_" + suffix, SkillID: skillID, Version: 1, Content: content,
			Digest: libraryDigest(content), RequestedCapabilities: []string{},
		},
	}
}

func activationLimitSelections(agentSurfaceID string, count int, content string) []LibraryAgentSurfaceSkillSelection {
	selections := make([]LibraryAgentSurfaceSkillSelection, 0, count)
	for index := 0; index < count; index++ {
		selections = append(selections, activationLimitSelection(agentSurfaceID, index, content))
	}
	return selections
}

func TestBuildLibrarySkillActivationBundleEnforcesPortableRuntimeBounds(t *testing.T) {
	const agentSurfaceID = "mcpcli_activation_limits"
	maximumInstruction := strings.Repeat("x", 32<<10)
	tests := []struct {
		name       string
		selections []LibraryAgentSurfaceSkillSelection
	}{
		{
			name:       "selected skill count",
			selections: activationLimitSelections(agentSurfaceID, libraryruntime.DefaultLimits().MaxSkills+1, "# bounded"),
		},
		{
			name:       "individual instruction bytes",
			selections: activationLimitSelections(agentSurfaceID, 1, maximumInstruction+"x"),
		},
		{
			name:       "combined instruction bytes",
			selections: activationLimitSelections(agentSurfaceID, 5, strings.Repeat("x", 27<<10)),
		},
		{
			// Four 32 KiB bodies plus one 4 KiB body fit the raw byte counter
			// exactly, but their metadata must still fit the portable 132 KiB
			// canonical context.
			name:       "canonical context bytes",
			selections: append(activationLimitSelections(agentSurfaceID, 4, maximumInstruction), activationLimitSelection(agentSurfaceID, 4, strings.Repeat("x", 4<<10))),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(context.Background(), fixedActivationSelectionStore{selections: test.selections}, agentSurfaceID)
			if !errors.Is(err, ErrLibrarySkillActivationLimit) {
				t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface error=%v, want %v", err, ErrLibrarySkillActivationLimit)
			}
			if len(bundle.Skills) != 0 || bundle.BundleDigest != "" {
				t.Fatalf("limit failure returned a partial activation bundle: %+v", bundle)
			}
		})
	}
}

func TestMCPClientActivationLimitFailsClosedWithoutInstructions(t *testing.T) {
	const agentSurfaceID = "mcpcli_activation_limit_tool"
	marker := "must-not-appear-in-tool-error"
	store := fixedActivationSelectionStore{selections: activationLimitSelections(agentSurfaceID, 1, strings.Repeat(marker, 2<<10))}
	mcpServer := server.NewMCPServer("library-activation-limit-test", "1.0.0", server.WithToolCapabilities(true))
	registerMCPClientLibraryTools(mcpServer, store, nil, MCPClient{
		ID: agentSurfaceID, Subject: "usr_activation_limit", Slug: "activation-limit",
	}, func(context.Context) bool { return true })

	response := callLibraryTool(t, mcpServer, "library_skill_activation", nil)
	if !strings.Contains(response, `"isError":true`) || !strings.Contains(response, "assigned skills exceed the activation safety limit") {
		t.Fatalf("activation limit tool response=%s", response)
	}
	if strings.Contains(response, marker) || strings.Contains(response, LibrarySkillActivationContractVersion) {
		t.Fatalf("activation limit tool leaked an activation body: %s", response)
	}
}

func TestRootLibraryMCPDoesNotExposeVerifiedAgentActivation(t *testing.T) {
	store := newLibraryFileStore(t)
	mcpServer := server.NewMCPServer("library-activation-root-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, store, nil)
	if _, found := mcpServer.ListTools()["library_skill_activation"]; found {
		t.Fatal("owner/admin root MCP projection exposed a client-verified activation contract")
	}
}
