package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

func callLibraryTool(t *testing.T, mcpServer *server.MCPServer, tool string, arguments map[string]any) string {
	t.Helper()
	request, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := mcpServer.HandleMessage(context.Background(), request)
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

type rootMCPArtifactAtomicStore struct {
	LibraryStore
	createRunCalls  int
	rootCreateCalls int
}

type rootMCPPageStore struct {
	LibraryStore
	skillPageCalls        int
	artifactPageCalls     int
	fullSkillListCalls    int
	fullArtifactListCalls int
}

func (s *rootMCPPageStore) LibraryMCPRootSkillPage(ctx context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootSkillPage, error) {
	s.skillPageCalls++
	return s.LibraryStore.LibraryMCPRootSkillPage(ctx, cursor, limit)
}

func (s *rootMCPPageStore) LibraryMCPRootArtifactPage(ctx context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootArtifactPage, error) {
	s.artifactPageCalls++
	return s.LibraryStore.LibraryMCPRootArtifactPage(ctx, cursor, limit)
}

func (s *rootMCPPageStore) LibrarySkills(context.Context) ([]LibrarySkill, error) {
	s.fullSkillListCalls++
	return nil, errors.New("unbounded skill list must not be used by root MCP")
}

func (s *rootMCPPageStore) LibraryArtifacts(context.Context) ([]LibraryArtifact, error) {
	s.fullArtifactListCalls++
	return nil, errors.New("unbounded artifact list must not be used by root MCP")
}

func TestLibraryMCPRootPageLimits(t *testing.T) {
	if got, err := normalizeLibraryMCPRootPageLimit(0); err != nil || got != 50 {
		t.Fatalf("default root page limit=%d err=%v, want 50", got, err)
	}
	if got, err := normalizeLibraryMCPRootPageLimit(100); err != nil || got != 100 {
		t.Fatalf("maximum root page limit=%d err=%v, want 100", got, err)
	}
	for _, limit := range []int{-1, 101} {
		if _, err := normalizeLibraryMCPRootPageLimit(limit); err == nil {
			t.Fatalf("invalid root page limit %d was accepted", limit)
		}
	}
}

func (s *rootMCPArtifactAtomicStore) CreateLibraryRun(ctx context.Context, run LibraryRun) (LibraryRun, error) {
	s.createRunCalls++
	return s.LibraryStore.CreateLibraryRun(ctx, run)
}

func (s *rootMCPArtifactAtomicStore) CreateLibraryRootMCPArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.rootCreateCalls++
	return s.LibraryStore.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, artifact, version)
}

func TestLibraryBuiltinMCPToolsExposeInstructionsAndDirectArtifactsWithoutAuthority(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, _ := createLibrarySkillForTest(t, store)
	if _, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "engineering", Mode: LibraryBindingModeTrack, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "owner",
	}); err != nil {
		t.Fatal(err)
	}
	mcpServer := server.NewMCPServer("library-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, store, nil)

	listSkills := callLibraryTool(t, mcpServer, "library_skill_list", nil)
	if !strings.Contains(listSkills, "Incident triage") || strings.Contains(listSkills, "# Triage") {
		t.Fatalf("skill list response=%s", listSkills)
	}
	readSkill := callLibraryTool(t, mcpServer, "library_skill_read", map[string]any{"skillId": skill.ID})
	if !strings.Contains(readSkill, "# Triage") || !strings.Contains(readSkill, "Requested capabilities and bindings describe intent") {
		t.Fatalf("skill read response=%s", readSkill)
	}

	created := callLibraryTool(t, mcpServer, "library_artifact_create", map[string]any{
		"title": "Direct agent note", "summary": "Created outside a skill", "format": "markdown", "body": "# Private note",
	})
	if strings.Contains(created, "isError\":true") || !strings.Contains(created, "artifactId") {
		t.Fatalf("artifact create response=%s", created)
	}
	runs, err := store.LibraryRuns(context.Background())
	if err != nil || len(runs) != 1 || runs[0].Origin != LibraryRunOriginAgentDirect || runs[0].SkillID != "" || runs[0].OutputDigest != libraryDigest("# Private note") {
		t.Fatalf("direct artifact run=%#v err=%v", runs, err)
	}
	artifacts, err := store.LibraryArtifacts(context.Background())
	if err != nil || len(artifacts) != 1 || artifacts[0].Origin != LibraryArtifactOriginAgentDirect || artifacts[0].RunID != runs[0].ID {
		t.Fatalf("direct artifact=%#v err=%v", artifacts, err)
	}
	readArtifact := callLibraryTool(t, mcpServer, "library_artifact_read", map[string]any{"artifactId": artifacts[0].ID})
	if !strings.Contains(readArtifact, "# Private note") {
		t.Fatalf("artifact read response=%s", readArtifact)
	}
}

func TestLibraryBuiltinMCPArtifactCreateUsesOneAtomicStoreWrite(t *testing.T) {
	base := newLibraryFileStore(t)
	store := &rootMCPArtifactAtomicStore{LibraryStore: base}
	mcpServer := server.NewMCPServer("library-root-atomic-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, store, nil)

	created := callLibraryTool(t, mcpServer, "library_artifact_create", map[string]any{
		"title": "Atomic root note", "format": "text", "body": "one durable operation",
	})
	if strings.Contains(created, "isError\":true") || store.rootCreateCalls != 1 || store.createRunCalls != 0 {
		t.Fatalf("root artifact write response=%s rootCreates=%d separateRunCreates=%d", created, store.rootCreateCalls, store.createRunCalls)
	}
	runs, err := base.LibraryRuns(context.Background())
	if err != nil || len(runs) != 1 {
		t.Fatalf("root atomic write runs=%#v err=%v", runs, err)
	}
	artifacts, err := base.LibraryArtifacts(context.Background())
	if err != nil || len(artifacts) != 1 || artifacts[0].RunID != runs[0].ID {
		t.Fatalf("root atomic write artifacts=%#v runs=%#v err=%v", artifacts, runs, err)
	}
}

func TestLibraryBuiltinMCPListsUseBoundedMetadataPages(t *testing.T) {
	ctx := context.Background()
	base := newLibraryFileStore(t)
	type expectedSkill struct {
		id      string
		version LibrarySkillVersion
	}
	expectedSkills := make([]expectedSkill, 0, 3)
	for _, definition := range []struct {
		slug string
		name string
	}{
		{slug: "root-list-alpha", name: "Root list alpha"},
		{slug: "root-list-bravo", name: "Root list bravo"},
		{slug: "root-list-charlie", name: "Root list charlie"},
	} {
		skill, version, err := base.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: definition.slug, Name: definition.name, Description: definition.name + " summary", CreatedBy: "owner",
		}, LibrarySkillVersion{Content: "# root-skill-body " + definition.slug, CreatedBy: "owner"})
		if err != nil {
			t.Fatalf("create root list skill %q: %v", definition.slug, err)
		}
		if definition.slug == "root-list-charlie" {
			version, err = base.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
				SkillID: skill.ID, Content: "# root-skill-body " + definition.slug + " v2", CreatedBy: "owner",
			})
			if err != nil {
				t.Fatalf("create latest root list skill version: %v", err)
			}
		}
		expectedSkills = append(expectedSkills, expectedSkill{id: skill.ID, version: version})
	}

	artifactIDs := make([]string, 0, 3)
	for _, definition := range []struct {
		title string
		body  string
	}{
		{title: "Root list alpha artifact", body: "root-artifact-body alpha"},
		{title: "Root list bravo artifact", body: "root-artifact-body bravo"},
		{title: "Root list charlie artifact", body: "root-artifact-body charlie"},
	} {
		artifact, _, err := base.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: definition.title, Origin: LibraryArtifactOriginHuman, CreatedBy: "owner",
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: definition.body, CreatedBy: "owner"})
		if err != nil {
			t.Fatalf("create root list artifact %q: %v", definition.title, err)
		}
		artifactIDs = append(artifactIDs, artifact.ID)
	}

	store := &rootMCPPageStore{LibraryStore: base}
	mcpServer := server.NewMCPServer("library-root-page-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, store, nil)

	type skillSummary struct {
		ID              string `json:"id"`
		LatestVersion   int    `json:"latestVersion"`
		LatestVersionID string `json:"latestVersionId"`
	}
	type skillPage struct {
		Skills     []skillSummary `json:"skills"`
		NextCursor string         `json:"nextCursor"`
	}
	seenSkills := make(map[string]skillSummary)
	cursor := ""
	firstSkillCursor := ""
	for {
		arguments := map[string]any{"limit": 1}
		if cursor != "" {
			arguments["cursor"] = cursor
		}
		response := callLibraryTool(t, mcpServer, "library_skill_list", arguments)
		if strings.Contains(response, "root-skill-body") {
			t.Fatalf("skill metadata page exposed instruction content: %s", response)
		}
		var page skillPage
		if err := json.Unmarshal([]byte(libraryToolJSONText(t, response)), &page); err != nil {
			t.Fatalf("decode skill page: %v", err)
		}
		if len(page.Skills) != 1 {
			t.Fatalf("skill page=%+v, want one item", page)
		}
		if _, exists := seenSkills[page.Skills[0].ID]; exists {
			t.Fatalf("skill page repeated %q", page.Skills[0].ID)
		}
		seenSkills[page.Skills[0].ID] = page.Skills[0]
		if firstSkillCursor == "" {
			firstSkillCursor = page.NextCursor
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seenSkills) != len(expectedSkills) {
		t.Fatalf("paged skills=%+v, want %d unique skills", seenSkills, len(expectedSkills))
	}
	for _, expected := range expectedSkills {
		got, found := seenSkills[expected.id]
		if !found || got.LatestVersion != expected.version.Version || got.LatestVersionID != expected.version.ID {
			t.Fatalf("paged skill id=%q got=%+v found=%t want latest=%+v", expected.id, got, found, expected.version)
		}
	}

	type artifactSummary struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		CreatedAt string `json:"createdAt"`
	}
	type artifactPage struct {
		Artifacts  []artifactSummary `json:"artifacts"`
		NextCursor string            `json:"nextCursor"`
	}
	seenArtifacts := make(map[string]artifactSummary)
	cursor = ""
	for {
		arguments := map[string]any{"limit": 1}
		if cursor != "" {
			arguments["cursor"] = cursor
		}
		response := callLibraryTool(t, mcpServer, "library_artifact_list", arguments)
		if strings.Contains(response, "root-artifact-body") || strings.Contains(response, "createdBy") || strings.Contains(response, "sourceArtifact") {
			t.Fatalf("artifact metadata page exposed content or provenance: %s", response)
		}
		var page artifactPage
		if err := json.Unmarshal([]byte(libraryToolJSONText(t, response)), &page); err != nil {
			t.Fatalf("decode artifact page: %v", err)
		}
		if len(page.Artifacts) != 1 || page.Artifacts[0].CreatedAt == "" {
			t.Fatalf("artifact page=%+v, want one timestamped item", page)
		}
		if _, exists := seenArtifacts[page.Artifacts[0].ID]; exists {
			t.Fatalf("artifact page repeated %q", page.Artifacts[0].ID)
		}
		seenArtifacts[page.Artifacts[0].ID] = page.Artifacts[0]
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seenArtifacts) != len(artifactIDs) {
		t.Fatalf("paged artifacts=%+v, want %d unique artifacts", seenArtifacts, len(artifactIDs))
	}
	for _, id := range artifactIDs {
		if _, found := seenArtifacts[id]; !found {
			t.Fatalf("artifact %q absent from root metadata pages", id)
		}
	}

	if invalid := callLibraryTool(t, mcpServer, "library_artifact_list", map[string]any{"cursor": firstSkillCursor}); !strings.Contains(invalid, `"isError":true`) || !strings.Contains(invalid, "invalid artifact page") {
		t.Fatalf("cross-list cursor was accepted: %s", invalid)
	}
	if invalid := callLibraryTool(t, mcpServer, "library_skill_list", map[string]any{"limit": 101}); !strings.Contains(invalid, `"isError":true`) || !strings.Contains(invalid, "invalid skill page") {
		t.Fatalf("oversize skill page was accepted: %s", invalid)
	}
	if read := callLibraryTool(t, mcpServer, "library_skill_read", map[string]any{"skillId": expectedSkills[0].id}); !strings.Contains(read, "root-skill-body") {
		t.Fatalf("explicit skill read did not retain instructions: %s", read)
	}
	if read := callLibraryTool(t, mcpServer, "library_artifact_read", map[string]any{"artifactId": artifactIDs[0]}); !strings.Contains(read, "root-artifact-body") {
		t.Fatalf("explicit artifact read did not retain body: %s", read)
	}
	if store.skillPageCalls == 0 || store.artifactPageCalls == 0 || store.fullSkillListCalls != 0 || store.fullArtifactListCalls != 0 {
		t.Fatalf("root list storage calls pages=(%d,%d) unbounded=(%d,%d)", store.skillPageCalls, store.artifactPageCalls, store.fullSkillListCalls, store.fullArtifactListCalls)
	}
}

func TestLibraryBuiltinMCPResolverReturnsBoundInstructionsWithoutRuntimeAuthority(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeFolder, ScopeID: "folder_incidents", Mode: LibraryBindingModePin,
		PinnedVersionID: version.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	mcpServer := server.NewMCPServer("library-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, store, nil)

	resolved := callLibraryTool(t, mcpServer, "library_skill_resolve", map[string]any{
		"bindingId": binding.ID, "workspaceId": "wsp_should_not_override",
	})
	if !strings.Contains(resolved, "# Triage") || !strings.Contains(resolved, `"resolutionSource":"explicit"`) || !strings.Contains(resolved, `"capabilityCeiling":["alerts.read"]`) {
		t.Fatalf("skill resolve response=%s", resolved)
	}
	if strings.Contains(resolved, "effectiveCapabilities") || strings.Contains(resolved, "createdBy") || !strings.Contains(resolved, "do not grant credentials") {
		t.Fatalf("skill resolve authority boundary=%s", resolved)
	}
}
