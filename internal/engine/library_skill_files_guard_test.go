package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLibrarySkillFilesGuardRuleAndPayloadDigests pins the rule itself: only
// a write that sends no file list at all is refused, only against a head with
// bundle files, and an explicit empty list is a distinct idempotent payload
// while every other update keeps the payload digest it had before the guard.
func TestLibrarySkillFilesGuardRuleAndPayloadDigests(t *testing.T) {
	skillOnly := LibrarySkillVersion{Version: 3, Files: []LibrarySkillFile{{Path: LibrarySkillInstructionsPath}}}
	oneFile := LibrarySkillVersion{Version: 2, Files: []LibrarySkillFile{{Path: LibrarySkillInstructionsPath}, {Path: "references/guide.md"}}}
	twoFiles := LibrarySkillVersion{Version: 4, Files: []LibrarySkillFile{{Path: LibrarySkillInstructionsPath}, {Path: "references/guide.md"}, {Path: "scripts/build.py"}}}
	for _, test := range []struct {
		name     string
		head     *LibrarySkillVersion
		declared bool
		want     string
	}{
		{name: "no head", head: nil},
		{name: "legacy head accepts text-only", head: &skillOnly},
		{name: "declared keeps or removes", head: &twoFiles, declared: true},
		{name: "one file omitted", head: &oneFile, want: "version 2 has 1 bundle file besides SKILL.md"},
		{name: "two files omitted", head: &twoFiles, want: "version 4 has 2 bundle files besides SKILL.md"},
	} {
		err := requireLibrarySkillFilesDeclared(test.head, test.declared)
		if test.want == "" {
			if err != nil {
				t.Fatalf("%s: err=%v", test.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrLibrarySkillFilesOmitted) || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "empty files list") {
			t.Fatalf("%s: err=%v", test.name, err)
		}
	}

	for _, test := range []struct {
		name   string
		bundle *LibrarySkillBundle
		want   bool
	}{
		{name: "legacy single document", bundle: nil},
		{name: "description-only bundle", bundle: &LibrarySkillBundle{Files: []LibrarySkillFile{{Path: LibrarySkillInstructionsPath}}}},
		{name: "explicit empty list", bundle: &LibrarySkillBundle{Files: []LibrarySkillFile{{Path: LibrarySkillInstructionsPath}}, FilesDeclared: true}, want: true},
		{name: "files present", bundle: &LibrarySkillBundle{Files: oneFile.Files}, want: true},
	} {
		if got := libraryBundleDeclaresFiles(test.bundle); got != test.want {
			t.Fatalf("%s: declared=%t", test.name, got)
		}
	}

	for _, test := range []struct {
		name     string
		inputs   []LibrarySkillFileInput
		declared bool
		authored bool
	}{
		{name: "omitted", inputs: nil},
		{name: "empty list", inputs: []LibrarySkillFileInput{}, declared: true},
		{name: "SKILL.md only", inputs: []LibrarySkillFileInput{{Path: LibrarySkillInstructionsPath, Content: "# body"}}, declared: true, authored: true},
		{name: "one file", inputs: []LibrarySkillFileInput{{Path: "references/guide.md", Content: "# Guide"}}, declared: true, authored: true},
	} {
		_, bundle, err := normalizeLibrarySkillAuthoringFiles("# body", test.inputs)
		if err != nil || bundle.declared != test.declared || bundle.authored != test.authored {
			t.Fatalf("%s: declared=%t authored=%t err=%v", test.name, bundle.declared, bundle.authored, err)
		}
	}

	base := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "digest-1", SkillID: "libsk_digest", ExpectedVersionID: "libskv_digest",
		ExpectedVersionDigest: strings.Repeat("a", 64), Content: "# body", RequestedCapabilities: []string{"repository.read"},
	}
	digestOf := func(files []LibrarySkillFileInput) string {
		t.Helper()
		request := base
		request.Files = files
		_, digest, err := normalizeLibraryMCPClientSkillAuthoringUpdateRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	// The canonical material exactly as it was encoded before the guard.
	previousDigestOf := func(files []LibrarySkillFileInput) string {
		t.Helper()
		_, bundle, err := normalizeLibrarySkillAuthoringFiles(base.Content, files)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(struct {
			SkillID               string   `json:"skillId"`
			ExpectedVersionID     string   `json:"expectedVersionId"`
			ExpectedVersionDigest string   `json:"expectedVersionDigest"`
			Content               string   `json:"content"`
			RequestedCapabilities []string `json:"requestedCapabilities"`
			Files                 []string `json:"files,omitempty"`
		}{base.SkillID, base.ExpectedVersionID, base.ExpectedVersionDigest, base.Content, base.RequestedCapabilities,
			librarySkillFileInputsPayloadMaterial(bundle.inline, bundle.refs)})
		if err != nil {
			t.Fatal(err)
		}
		return libraryDigest(string(canonical))
	}
	withFile := []LibrarySkillFileInput{{Path: "references/guide.md", Content: "# Guide"}}
	omitted, empty := digestOf(nil), digestOf([]LibrarySkillFileInput{})
	if omitted == empty {
		t.Fatal("an omitted files list and an explicit empty list must not replay as each other")
	}
	if omitted != previousDigestOf(nil) || digestOf(withFile) != previousDigestOf(withFile) {
		t.Fatal("the guard changed the payload digest of an update that does not declare an empty list")
	}
	if skillOnlyList := digestOf([]LibrarySkillFileInput{{Path: LibrarySkillInstructionsPath, Content: base.Content}}); skillOnlyList != empty {
		t.Fatal("a SKILL.md-only list declares the same manifest as an empty list")
	}
}

// TestMCPClientSkillUpdateRefusesToDropBundleFilesUnlessDeclared drives the
// leased FileStore update: an update that omits files against a bundled head
// is refused, audited, and consumes no write; the complete list keeps the
// files; an explicit empty list removes them; replays stay exact; and skills
// without bundle files accept text-only updates exactly as before.
func TestMCPClientSkillUpdateRefusesToDropBundleFilesUnlessDeclared(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_guard")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	instructions := testSkillBundleFrontMatter("guarded-skill", "A guarded skill.", "# Guarded\n")
	bundleFiles := []LibrarySkillFileInput{
		{Path: "references/guide.md", Content: "# Guide\n"},
		{Path: "scripts/build.py", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("print('build')\n"))},
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "guard-create", Name: "Guarded skill", Description: "A guarded skill.", Content: instructions, Files: bundleFiles,
	})
	if err != nil || len(created.Version.Files) != 3 || created.Lease.RemainingCreates != 2 {
		t.Fatalf("create = %+v err=%v", created, err)
	}

	revised := testSkillBundleFrontMatter("guarded-skill", "A guarded skill.", "# Guarded v2\n")
	omit := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "guard-omit", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: revised,
	}
	_, err = store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, omit)
	if !errors.Is(err, ErrLibrarySkillFilesOmitted) || !strings.Contains(err.Error(), "version 1 has 2 bundle files") {
		t.Fatalf("text-only update over a bundle err=%v", err)
	}
	lease, _, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || lease.RemainingCreates != 2 {
		t.Fatalf("refused update consumed a write: %+v err=%v", lease, err)
	}
	if versions, err := store.LibrarySkillVersions(ctx, created.Skill.ID); err != nil || len(versions) != 1 {
		t.Fatalf("refused update appended a version: %d err=%v", len(versions), err)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || len(events) == 0 {
		t.Fatalf("audit events = %+v err=%v", events, err)
	}
	if last := events[len(events)-1]; last.Action != LibraryMCPClientSkillAuthoringAuditActionRejected || last.Operation != LibraryMCPClientSkillAuthoringAuditOperationUpdate {
		t.Fatalf("refused update was not audited as a rejection: %+v", last)
	}

	// The complete list keeps every file.
	keep := omit
	keep.RequestID, keep.Files = "guard-keep", bundleFiles
	kept, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, keep)
	if err != nil || kept.Version.Version != 2 || len(kept.Version.Files) != 3 || kept.Lease.RemainingCreates != 1 {
		t.Fatalf("complete-list update = %+v err=%v", kept, err)
	}

	// An explicit empty list is a deliberate removal.
	remove := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "guard-remove", SkillID: created.Skill.ID, ExpectedVersionID: kept.Version.ID,
		ExpectedVersionDigest: kept.Version.Digest, Content: revised, Files: []LibrarySkillFileInput{},
	}
	removed, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, remove)
	if err != nil || removed.Version.Version != 3 || len(removed.Version.Files) != 1 || removed.Version.Files[0].Path != LibrarySkillInstructionsPath {
		t.Fatalf("empty-list update = %+v err=%v", removed, err)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, remove); err != nil || !replay.Replayed || replay.Version.ID != removed.Version.ID {
		t.Fatalf("empty-list replay = %+v err=%v", replay, err)
	}
	retried := remove
	retried.Files = nil
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, retried); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("retry that dropped the empty list replayed as the removal: err=%v", err)
	}
	// Nothing is destroyed: the earlier versions keep their files.
	if data, _, found, err := store.LibrarySkillFileBytes(ctx, created.Skill.ID, created.Version.ID, "scripts/build.py"); err != nil || !found || string(data) != "print('build')\n" {
		t.Fatalf("version 1 lost its file: found=%t err=%v", found, err)
	}

	// A skill without bundle files keeps accepting text-only updates.
	plainClient := newAuthoringLeaseMCPClient(t, store, "usr_guard_plain")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, plainClient.ID, MCPClientPrecondition{ID: plainClient.ID, Revision: plainClient.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	plain, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, plainClient, LibraryMCPClientSkillAuthoringRequest{RequestID: "plain-create", Name: "Plain guarded", Content: "# Plain"})
	if err != nil {
		t.Fatal(err)
	}
	plainUpdate, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, plainClient, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "plain-update", SkillID: plain.Skill.ID, ExpectedVersionID: plain.Version.ID, ExpectedVersionDigest: plain.Version.Digest, Content: "# Plain v2",
	})
	if err != nil || plainUpdate.Version.Version != 2 || len(plainUpdate.Version.Files) != 1 {
		t.Fatalf("legacy text-only update = %+v err=%v", plainUpdate, err)
	}
}

// TestMCPClientSkillUpdateToolDistinguishesOmittedFromEmptyFiles proves the
// tool boundary keeps an omitted files key apart from an explicit empty list
// and hands the agent an actionable refusal.
func TestMCPClientSkillUpdateToolDistinguishesOmittedFromEmptyFiles(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_guard_tools")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	instructions := testSkillBundleFrontMatter("tool-guarded", "Tool guarded.", "# Tool\n")
	created := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-guard-create", "name": "tool-guarded", "description": "Tool guarded.", "content": instructions,
		"files": []map[string]any{{"path": "references/guide.md", "content": "# Guide\n"}},
	})
	if strings.Contains(created, `"isError":true`) {
		t.Fatalf("create: %s", created)
	}
	var result struct {
		SkillID        string `json:"skillId"`
		SkillVersionID string `json:"skillVersionId"`
		Digest         string `json:"digest"`
		FileCount      int    `json:"fileCount"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, created)), &result); err != nil || result.FileCount != 2 {
		t.Fatalf("create result = %+v err=%v", result, err)
	}
	update := map[string]any{
		"requestId": "tool-guard-update", "skillId": result.SkillID, "expectedVersionId": result.SkillVersionID,
		"expectedVersionDigest": result.Digest, "content": testSkillBundleFrontMatter("tool-guarded", "Tool guarded.", "# Tool v2\n"),
	}
	refused := callLibraryTool(t, mcpServer, "library_skill_update", update)
	if !strings.Contains(refused, `"isError":true`) || !strings.Contains(refused, "version 1 has 1 bundle file besides SKILL.md") {
		t.Fatalf("omitted files were not refused with guidance: %s", refused)
	}
	update["files"] = []any{}
	accepted := callLibraryTool(t, mcpServer, "library_skill_update", update)
	if strings.Contains(accepted, `"isError":true`) {
		t.Fatalf("explicit empty list: %s", accepted)
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, accepted)), &result); err != nil || result.FileCount != 1 {
		t.Fatalf("empty-list result = %+v err=%v", result, err)
	}
}

// TestLibrarySkillConsoleVersionRefusesToDropBundleFiles covers the owner
// Console routes and the store method behind them: a content-only or
// description-only version is refused against a bundled head, an explicit
// empty list removes the files, single-document skills are unaffected, and a
// store refusal on either bundle branch is returned instead of an empty 201.
func TestLibrarySkillConsoleVersionRefusesToDropBundleFiles(t *testing.T) {
	mux, token, store := newLibraryConsole(t)
	do := func(method, target string, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		var reader io.Reader
		if payload != nil {
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(body)
		}
		request := httptest.NewRequest(method, target, reader)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}
	instructions := testSkillBundleFrontMatter("console-guarded", "Console guarded.", "# Console\n")
	response := do(http.MethodPost, "/api/library/skills", map[string]any{
		"name": "console-guarded", "files": []map[string]any{
			{"path": "SKILL.md", "content": instructions},
			{"path": "references/guide.md", "content": "# Guide\n"},
		},
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("bundle create status=%d body=%s", response.Code, response.Body)
	}
	var created struct {
		Skill LibrarySkill `json:"skill"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	// A store refusal on the bundle branch reaches the caller rather than a
	// 201 with an empty body.
	response = do(http.MethodPost, "/api/library/skills", map[string]any{
		"name": "console-guarded", "files": []map[string]any{{"path": "SKILL.md", "content": instructions}},
	})
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate bundle create status=%d body=%s", response.Code, response.Body)
	}
	versions := "/api/library/skills/" + created.Skill.ID + "/versions"
	revised := testSkillBundleFrontMatter("console-guarded", "Console guarded.", "# Console v2\n")

	response = do(http.MethodPost, versions, map[string]any{"content": revised})
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "version 1 has 1 bundle file besides SKILL.md") {
		t.Fatalf("content-only version status=%d body=%s", response.Code, response.Body)
	}
	response = do(http.MethodPost, versions, map[string]any{
		"content": testSkillBundleFrontMatter("console-guarded", "Console guarded, revised.", "# Console v2\n"), "description": "Console guarded, revised.",
	})
	if response.Code != http.StatusConflict {
		t.Fatalf("description-only version status=%d body=%s", response.Code, response.Body)
	}
	if skill, _ := store.LibrarySkill(context.Background(), created.Skill.ID); skill.Description != "Console guarded." {
		t.Fatalf("refused version still changed the description to %q", skill.Description)
	}
	if _, err := store.CreateLibrarySkillVersion(context.Background(), LibrarySkillVersion{SkillID: created.Skill.ID, Content: revised}); !errors.Is(err, ErrLibrarySkillFilesOmitted) {
		t.Fatalf("store text-only append over a bundle err=%v", err)
	}

	response = do(http.MethodPost, versions, map[string]any{"content": revised, "files": []any{}})
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"version":2`) || strings.Contains(response.Body.String(), "references/guide.md") {
		t.Fatalf("empty-list version status=%d body=%s", response.Code, response.Body)
	}
	// With the files gone, text-only versions work as they always have.
	response = do(http.MethodPost, versions, map[string]any{"content": testSkillBundleFrontMatter("console-guarded", "Console guarded.", "# Console v3\n")})
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"version":3`) {
		t.Fatalf("text-only version after removal status=%d body=%s", response.Code, response.Body)
	}
	response = do(http.MethodPost, "/api/library/skills", map[string]any{"name": "Console plain", "content": "# Plain"})
	if response.Code != http.StatusCreated {
		t.Fatalf("legacy create status=%d body=%s", response.Code, response.Body)
	}
	var plain struct {
		Skill LibrarySkill `json:"skill"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	if response := do(http.MethodPost, "/api/library/skills/"+plain.Skill.ID+"/versions", map[string]any{"content": "# Plain v2"}); response.Code != http.StatusCreated {
		t.Fatalf("legacy version status=%d body=%s", response.Code, response.Body)
	}
}
