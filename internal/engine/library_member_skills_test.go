package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"narthex/backend/pkg/libraryruntime"
)

type memberSkillTestStore interface {
	LibraryStore
	LibraryMemberSkillStore
	MCPClientStore
}

func TestFileMemberSkillsIsolationAndLifecycle(t *testing.T) {
	testMemberSkillsIsolationAndLifecycle(t, newLibraryFileStore(t))
}
func TestPgMemberSkillsIsolationAndLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	s, e := NewPgStore(context.Background(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	testMemberSkillsIsolationAndLifecycle(t, s)
}
func testMemberSkillsIsolationAndLifecycle(t *testing.T, s memberSkillTestStore) {
	ctx := context.Background()
	suffix := newEpoch()
	owner := "usr_owner_" + suffix
	other := "usr_other_" + suffix
	agent := "agt_owned_" + suffix
	client, err := s.CreateMCPClient(ctx, MCPClient{Name: "Own " + suffix, Subject: agent, CreatedBy: owner})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := s.CreateMCPClient(ctx, MCPClient{Name: "Other " + suffix, Subject: other, CreatedBy: other})
	if err != nil {
		t.Fatal(err)
	}
	r := LibraryMemberSkillRequest{Subject: owner, SubjectIDs: []string{owner, agent}, Operation: "create", Name: "My private instructions", Instructions: "Private v1"}
	created, err := s.MemberLibrarySkills(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if created.Skill == nil || created.Skill.Access != "owned" || !created.Skill.CanEdit || len(created.Versions) != 1 {
		t.Fatalf("create=%+v", created)
	}
	id := created.Skill.ID
	v1 := created.Versions[0].ID
	stored, ok := s.LibrarySkill(ctx, id)
	if !ok || !stored.Private || stored.CreatedBy != owner {
		t.Fatal("private ownership not durable")
	}
	cleanupIDs := []string{id}
	t.Cleanup(func() {
		if pg, ok := s.(*PgStore); ok {
			for _, skillID := range cleanupIDs {
				for _, q := range []string{`DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, `DELETE FROM narthex_library_skills WHERE id=$1`} {
					if _, err := pg.pool.Exec(ctx, q, skillID); err != nil {
						t.Errorf("cleanup skill: %v", err)
					}
				}
			}
			if _, err := pg.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=ANY($1)`, []string{client.ID, foreign.ID}); err != nil {
				t.Errorf("cleanup clients: %v", err)
			}
		}
	})
	r.Operation = "bind"
	r.SkillID = id
	r.AgentSurfaceID = client.ID
	r.VersionID = v1
	bound, err := s.MemberLibrarySkills(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.Skill.Bindings) != 1 || bound.Skill.Bindings[0].Managed {
		t.Fatalf("binding=%+v", bound.Skill.Bindings)
	}
	bindingID := bound.Skill.Bindings[0].ID
	r.AgentSurfaceID = foreign.ID
	if _, e := s.MemberLibrarySkills(ctx, r); !errors.Is(e, ErrLibraryMemberSkillAccess) {
		t.Fatalf("foreign attach=%v", e)
	}
	r.AgentSurfaceID = client.ID
	otherR := LibraryMemberSkillRequest{Subject: other, SubjectIDs: []string{other}, Operation: "get", SkillID: id}
	if _, e := s.MemberLibrarySkills(ctx, otherR); !errors.Is(e, ErrLibrarySkillNotFound) {
		t.Fatalf("foreign read=%v", e)
	}
	otherR.Operation = "list"
	otherR.SkillID = ""
	listed, e := s.MemberLibrarySkills(ctx, otherR)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range listed.Skills {
		if v.ID == id {
			t.Fatal("private skill leaked to coworker")
		}
	}
	otherR.Operation = "version"
	otherR.SkillID = id
	otherR.BaseVersionID = v1
	otherR.Instructions = "stolen"
	if _, e := s.MemberLibrarySkills(ctx, otherR); !errors.Is(e, ErrLibrarySkillNotFound) {
		t.Fatalf("foreign append=%v", e)
	}
	// Two concurrent editors cannot silently rebase over each other.
	r.Operation = "version"
	r.BaseVersionID = v1
	r.Instructions = "Private v2"
	description := "Updated"
	r.Description = &description
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.MemberLibrarySkills(ctx, r); results <- e }()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrLibraryMemberSkillConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("append success=%d conflict=%d", success, conflict)
	}
	r.Operation = "get"
	read, e := s.MemberLibrarySkills(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if len(read.Versions) != 2 || read.Skill.Description != "Updated" || read.Skill.Bindings[0].VersionID != v1 {
		t.Fatalf("version/pin %+v", read)
	}
	selected, e := s.LibraryAgentSurfaceSkillSelections(ctx, client.ID)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range selected {
		if v.Skill.ID == id {
			found = true
			if !v.Skill.Private || v.Version.ID != v1 {
				t.Fatal("runtime lost marker or exact pin")
			}
		}
	}
	if !found {
		t.Fatal("own agent cannot use skill")
	}
	root, e := s.LibraryMCPRootSkillPage(ctx, LibraryMCPRootPageCursor{}, 100)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range root.Skills {
		if v.ID == id {
			t.Fatal("private skill exposed by root MCP list")
		}
	}
	mcpServer := server.NewMCPServer("private-skill-test", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(mcpServer, s, nil)
	for _, tool := range []string{"library_skill_read", "library_skill_file_read"} {
		result := callLibraryTool(t, mcpServer, tool, map[string]any{"skillId": id, "versionId": v1, "path": "SKILL.md"})
		if !strings.Contains(result, `"isError":true`) || strings.Contains(result, "Private v1") {
			t.Fatalf("root private read leaked: %s", result)
		}
	}
	if _, e := s.LibrarySkillResolutionSelections(ctx, LibrarySkillResolutionRequest{ExplicitBindingID: bindingID}); !errors.Is(e, ErrLibraryBindingNotFound) {
		t.Fatalf("generic resolution exposed private skill: %v", e)
	}
	if _, e := s.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{SkillID: id, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace", Mode: LibraryBindingModePin, PinnedVersionID: v1, CreatedBy: owner}); !errors.Is(e, ErrLibraryMemberSkillAccess) {
		t.Fatalf("generic scope widened private skill: %v", e)
	}
	r.Operation = "unbind"
	r.BindingID = bindingID
	detached, e := s.MemberLibrarySkills(ctx, r)
	if e != nil || len(detached.Skill.Bindings) != 0 {
		t.Fatalf("detach=%+v %v", detached, e)
	}
	// Same display name is valid for another member without slug collisions.
	otherR.Operation = "create"
	otherR.Name = r.Name
	otherR.Instructions = "Other member private skill"
	duplicate, e := s.MemberLibrarySkills(ctx, otherR)
	if e != nil || duplicate.Skill.ID == id {
		t.Fatalf("duplicate name %+v %v", duplicate, e)
	}
	cleanupIDs = append(cleanupIDs, duplicate.Skill.ID)
	// A formerly privileged author cannot reclaim an administrator-managed skill.
	legacy, first, e := s.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{Slug: "shared-" + strings.ReplaceAll(strings.ToLower(suffix), "_", "-"), Name: "Assigned shared", CreatedBy: owner}, LibrarySkillVersion{Content: "Allowed v1"})
	if e != nil {
		t.Fatal(e)
	}
	cleanupIDs = append(cleanupIDs, legacy.ID)
	second, e := s.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{SkillID: legacy.ID, Content: "Unassigned v2"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{SkillID: legacy.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin, PinnedVersionID: first.ID, CreatedBy: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	r.Operation = "get"
	r.SkillID = legacy.ID
	assigned, e := s.MemberLibrarySkills(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if assigned.Skill.Access != "assigned" || assigned.Skill.CanEdit || assigned.Skill.CanAssign || len(assigned.Versions) != 1 || assigned.Versions[0].ID == second.ID || !assigned.Skill.Bindings[0].Managed {
		t.Fatalf("assigned leaked/authorized %+v", assigned)
	}
	r.Operation = "version"
	r.BaseVersionID = first.ID
	if _, e := s.MemberLibrarySkills(ctx, r); !errors.Is(e, ErrLibrarySkillNotFound) {
		t.Fatalf("former admin mutation=%v", e)
	}
	if e := s.DeleteLibrarySkillBinding(ctx, legacy.ID, b.ID); e != nil {
		t.Fatal(e)
	}
	r.Operation = "get"
	if _, e := s.MemberLibrarySkills(ctx, r); !errors.Is(e, ErrLibrarySkillNotFound) {
		t.Fatalf("revoked binding retained access=%v", e)
	}
	if _, e := s.RevokeMCPClient(ctx, client.ID, owner, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); e != nil {
		t.Fatal(e)
	}
	r.Operation = "bind"
	r.SkillID = id
	r.VersionID = v1
	if _, e := s.MemberLibrarySkills(ctx, r); !errors.Is(e, ErrLibraryMemberSkillAccess) {
		t.Fatalf("revoked agent attach=%v", e)
	}
}
func TestControlMemberSkillsServiceOnlyAndScope(t *testing.T) {
	mux, _, key, now, _ := newHostedControlConsole(t)
	path := "/control/v1/library/member-skills"
	body := `{"operation":"create","subjectIds":["usr_member"],"name":"Private","instructions":"Hello"}`
	for _, actor := range []struct{ user, role string }{{"usr_member", "operator"}, {"usr_owner", "owner"}} {
		r := controlLibraryRequest(t, mux, key, now, actor.user, actor.role, http.MethodPost, path, body, "usr_member")
		if r.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d %s", actor.role, r.Code, r.Body)
		}
	}
	response := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, body, "usr_member")
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d %s", response.Code, response.Body)
	}
	var result LibraryMemberSkillResponse
	if e := json.Unmarshal(response.Body.Bytes(), &result); e != nil || result.Skill == nil {
		t.Fatalf("result=%+v %v", result, e)
	}
	missing := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, body, "")
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing subject=%d", missing.Code)
	}
	wrong := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, body, "usr_other")
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("subject mismatch=%d %s", wrong.Code, wrong.Body)
	}
}

func TestMemberPrivateSkillRuntimeOnlyOwnBinding(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	own, err := store.CreateMCPClient(ctx, MCPClient{Name: "My private agent", Subject: "agt_member_skill", CreatedBy: "usr_member_skill"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateMCPClient(ctx, MCPClient{Name: "Coworker private agent", Subject: "agt_other_skill", CreatedBy: "usr_other_skill"})
	if err != nil {
		t.Fatal(err)
	}
	r := LibraryMemberSkillRequest{Operation: "create", Subject: "usr_member_skill", SubjectIDs: []string{"usr_member_skill", "agt_member_skill"}, Name: "Confidential skill", Instructions: "Private instructions runtime secret"}
	created, err := store.MemberLibrarySkills(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.SkillID = created.Skill.ID
	r.VersionID = created.Versions[0].ID
	r.AgentSurfaceID = own.ID
	r.Operation = "bind"
	bound, err := store.MemberLibrarySkills(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	ownMCP := clientLibraryServer(t, gateway, own.Slug)
	otherMCP := clientLibraryServer(t, gateway, other.Slug)
	for _, tool := range []string{"library_skill_read", "library_skill_resolve", "library_skill_activation"} {
		args := map[string]any{"skillId": r.SkillID}
		if tool == "library_skill_activation" {
			args = nil
		}
		ownResult := callLibraryTool(t, ownMCP, tool, args)
		if !strings.Contains(ownResult, "Private instructions runtime secret") {
			t.Fatalf("own %s unavailable: %s", tool, ownResult)
		}
		otherResult := callLibraryTool(t, otherMCP, tool, args)
		if strings.Contains(otherResult, "Private instructions runtime secret") || strings.Contains(otherResult, "Confidential skill") {
			t.Fatalf("other %s leaked: %s", tool, otherResult)
		}
	}
	r.Operation = "unbind"
	r.BindingID = bound.Skill.Bindings[0].ID
	if _, err := store.MemberLibrarySkills(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := callLibraryTool(t, ownMCP, "library_skill_read", map[string]any{"skillId": r.SkillID}); strings.Contains(got, "Private instructions runtime secret") {
		t.Fatalf("detached skill still usable: %s", got)
	}
}

func TestFileAssignedMemberSkillRevocationRemovesRuntimeAndFiles(t *testing.T) {
	testAssignedMemberSkillRevocationRemovesRuntimeAndFiles(t, newLibraryFileStore(t))
}

func TestPgAssignedMemberSkillRevocationRemovesRuntimeAndFiles(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	store.SetCipher(testCipher(t, 167))
	testAssignedMemberSkillRevocationRemovesRuntimeAndFiles(t, store)
}

// An administrator assigns an exact skill version to a member's agent. Keep
// the existing MCP server alive through removal so cached endpoint handlers
// must recheck the binding, rather than merely disappearing after a refresh.
func testAssignedMemberSkillRevocationRemovesRuntimeAndFiles(t *testing.T, store interface {
	memberSkillTestStore
	AccountStore
	LibrarySkillBundleStore
}) {
	t.Helper()
	ctx := context.Background()
	suffix := newPgFixtureSuffix()
	member := "usr_shared_skill_" + suffix
	agent := "agt_shared_skill_" + suffix
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Assigned skill " + suffix, Subject: agent, CreatedBy: member})
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateMCPClient(ctx, MCPClient{Name: "Unassigned skill " + suffix, Subject: "agt_unassigned_" + suffix, CreatedBy: "usr_unassigned_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	var skillID string
	var blobDigests []string
	t.Cleanup(func() {
		if pg, ok := store.(*PgStore); ok {
			exec := func(query string, args ...any) {
				if _, err := pg.pool.Exec(ctx, query, args...); err != nil {
					t.Errorf("cleanup assigned skill: %v", err)
				}
			}
			exec(`DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1 OR scope_id=ANY($2::text[])`, skillID, []string{client.ID, other.ID})
			exec(`DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, skillID)
			exec(`DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, skillID)
			exec(`DELETE FROM narthex_library_skills WHERE id=$1`, skillID)
			exec(`DELETE FROM narthex_library_skill_blobs WHERE digest=ANY($1::text[])`, blobDigests)
			exec(`DELETE FROM narthex_mcp_clients WHERE id=ANY($1::text[])`, []string{client.ID, other.ID})
		}
	})
	slug := "shared-skill-" + suffix
	const description = "Shared procedural instructions."
	allowedMarker := "assigned-instructions-" + suffix
	fileMarker := "assigned-reference-" + suffix
	unassignedMarker := "unassigned-instructions-" + suffix
	content, bundle, err := normalizeLibrarySkillBundle("", []LibrarySkillFileContent{
		{Path: "SKILL.md", Data: []byte(testSkillBundleFrontMatter(slug, description, allowedMarker))},
		{Path: "references/guide.md", Data: []byte(fileMarker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for digest := range bundle.Blobs {
		blobDigests = append(blobDigests, digest)
	}
	skill, first, err := store.CreateLibrarySkillWithInitialBundle(ctx, LibrarySkill{Slug: slug, Name: "Shared skill " + suffix, Description: description, CreatedBy: "usr_admin"}, LibrarySkillVersion{Content: content, CreatedBy: "usr_admin"}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	skillID = skill.ID
	secondContent, secondBundle, err := normalizeLibrarySkillBundle("", []LibrarySkillFileContent{
		{Path: "SKILL.md", Data: []byte(testSkillBundleFrontMatter(slug, description, unassignedMarker))},
		{Path: "references/guide.md", Data: []byte(unassignedMarker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for digest := range secondBundle.Blobs {
		blobDigests = append(blobDigests, digest)
	}
	second, err := store.CreateLibrarySkillBundleVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: secondContent, CreatedBy: "usr_admin"}, secondBundle)
	if err != nil {
		t.Fatal(err)
	}
	request := LibraryMemberSkillRequest{Operation: "get", Subject: member, SubjectIDs: []string{member, agent}, SkillID: skill.ID}
	if _, err := store.MemberLibrarySkills(ctx, request); !errors.Is(err, ErrLibrarySkillNotFound) {
		t.Fatalf("unassigned member read = %v", err)
	}
	binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin, PinnedVersionID: first.ID, CreatedBy: "usr_admin"})
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := store.MemberLibrarySkills(ctx, request)
	if err != nil || assigned.Skill == nil || assigned.Skill.Access != "assigned" || assigned.Skill.CanEdit || assigned.Skill.CanAssign || len(assigned.Versions) != 1 || assigned.Versions[0].ID != first.ID || !strings.Contains(assigned.Versions[0].Instructions, allowedMarker) {
		t.Fatalf("assigned member read = %+v, %v", assigned, err)
	}
	gateway := NewGateway(store, server.NewMCPServer("assigned-skill-test", "1.0.0", server.WithToolCapabilities(true)))
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	otherMCP := clientLibraryServer(t, gateway, other.Slug)
	readArgs := map[string]any{"skillId": skill.ID}
	fileArgs := map[string]any{"skillId": skill.ID, "versionId": first.ID, "path": "references/guide.md"}
	activationArgs := map[string]any{"contractVersion": LibrarySkillActivationContractVersionV2}
	for _, check := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"library_skill_list", nil, skill.ID},
		{"library_skill_read", readArgs, allowedMarker},
		{"library_skill_file_read", fileArgs, fileMarker},
		{"library_skill_resolve", map[string]any{"explicitBindingId": binding.ID}, allowedMarker},
		{"library_skill_activation", activationArgs, allowedMarker},
	} {
		got := callLibraryTool(t, mcpServer, check.tool, check.args)
		if strings.Contains(got, `"isError":true`) || !strings.Contains(got, check.want) || strings.Contains(got, second.ID) || strings.Contains(got, unassignedMarker) {
			t.Fatalf("assigned %s = %s", check.tool, got)
		}
		foreign := callLibraryTool(t, otherMCP, check.tool, check.args)
		if strings.Contains(foreign, skill.ID) || strings.Contains(foreign, allowedMarker) || strings.Contains(foreign, fileMarker) {
			t.Fatalf("unassigned client %s leaked: %s", check.tool, foreign)
		}
	}
	if got := callLibraryTool(t, mcpServer, "library_skill_file_read", map[string]any{"skillId": skill.ID, "versionId": second.ID, "path": "SKILL.md"}); !strings.Contains(got, `"isError":true`) || strings.Contains(got, unassignedMarker) {
		t.Fatalf("unassigned version read = %s", got)
	}
	before := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_activation", activationArgs))
	verified, err := libraryruntime.DecodeAndVerifyActivationBundle(strings.NewReader(before), libraryruntime.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := libraryruntime.BuildContext(verified, libraryruntime.Limits{}); err != nil {
		t.Fatalf("shared activation could not build host context: %v", err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, skill.ID, binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MemberLibrarySkills(ctx, request); !errors.Is(err, ErrLibrarySkillNotFound) {
		t.Fatalf("revoked member saved ID = %v", err)
	}
	request.Operation, request.SkillID = "list", ""
	listed, err := store.MemberLibrarySkills(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range listed.Skills {
		if item.ID == skill.ID {
			t.Fatal("revoked skill remains in member Library")
		}
	}
	// No gateway refresh occurs here. Every previously retained handle and ID
	// must lose instructions, manifests and files on its next request.
	for _, check := range []struct {
		tool string
		args map[string]any
	}{
		{"library_skill_list", nil}, {"library_skill_read", readArgs},
		{"library_skill_file_read", fileArgs},
		{"library_skill_resolve", map[string]any{"explicitBindingId": binding.ID}},
		{"library_skill_activation", activationArgs},
	} {
		got := callLibraryTool(t, mcpServer, check.tool, check.args)
		for _, forbidden := range []string{skill.ID, first.ID, binding.ID, allowedMarker, fileMarker, bundle.ManifestDigest} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("revoked %s leaked %s: %s", check.tool, forbidden, got)
			}
		}
		if (check.tool == "library_skill_read" || check.tool == "library_skill_file_read") && !strings.Contains(got, `"isError":true`) {
			t.Fatalf("revoked saved ID read succeeded: %s", got)
		}
	}
	after := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_activation", activationArgs))
	current, err := libraryruntime.DecodeAndVerifyActivationBundle(strings.NewReader(after), libraryruntime.Limits{})
	if err != nil || verified.BundleDigest() == current.BundleDigest() {
		t.Fatalf("revocation did not produce a new valid activation: %v", err)
	}
}
