package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestPgLibrarySkillFilesGuard is the PostgreSQL half of the guard: the
// Console append (single-document and bundle) and the leased MCP update both
// read the head under the skill row lock, refuse a write that omits files
// against a bundled head, and accept an explicit empty list.
func TestPgLibrarySkillFilesGuard(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library files guard test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	store.SetCipher(testCipher(t, 139))
	suffix := newPgFixtureSuffix()
	exec := func(query string, args ...any) {
		if _, err := store.pool.Exec(context.Background(), query, args...); err != nil {
			t.Errorf("cleanup %q: %v", query, err)
		}
	}
	var skillIDs, clientIDs, blobDigests []string
	defer func() {
		for _, clientID := range clientIDs {
			exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_requests WHERE client_id=$1`, clientID)
			exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_audit_events WHERE client_id=$1`, clientID)
			exec(`DELETE FROM narthex_library_skill_blob_stagings WHERE client_id=$1`, clientID)
			exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_leases WHERE client_id=$1`, clientID)
			exec(`DELETE FROM narthex_library_skill_bindings WHERE scope_id=$1`, clientID)
		}
		exec(`DELETE FROM narthex_library_skill_bindings WHERE skill_id = ANY($1::text[])`, skillIDs)
		exec(`DELETE FROM narthex_library_skill_binding_generations WHERE skill_id = ANY($1::text[])`, skillIDs)
		exec(`DELETE FROM narthex_library_skill_versions WHERE skill_id = ANY($1::text[])`, skillIDs)
		exec(`DELETE FROM narthex_library_skills WHERE id = ANY($1::text[])`, skillIDs)
		exec(`DELETE FROM narthex_library_skill_blobs WHERE digest = ANY($1::text[])`, blobDigests)
		for _, clientID := range clientIDs {
			exec(`DELETE FROM narthex_mcp_clients WHERE id=$1`, clientID)
		}
		if err := cleanupPgBuiltInLibraryTestRows(context.Background(), store); err != nil {
			t.Errorf("cleanup built-in rows: %v", err)
		}
	}()

	// Console path: a bundled skill created with one reference file.
	slug := "pg-guarded-" + suffix
	instructions := testSkillBundleFrontMatter(slug, "PG guarded.", "# Guarded\n")
	content, bundle, err := normalizeLibrarySkillBundle("", []LibrarySkillFileContent{
		{Path: LibrarySkillInstructionsPath, Data: []byte(instructions)},
		{Path: "references/guide.md", Data: []byte("# Guide " + suffix + "\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	skill, first, err := store.CreateLibrarySkillWithInitialBundle(ctx, LibrarySkill{
		Slug: slug, Name: slug, Description: "PG guarded.", CreatedBy: "usr_pg_guard",
	}, LibrarySkillVersion{Content: content, CreatedBy: "usr_pg_guard"}, bundle)
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	skillIDs = append(skillIDs, skill.ID)
	for digest := range bundle.Blobs {
		blobDigests = append(blobDigests, digest)
	}
	revised := testSkillBundleFrontMatter(slug, "PG guarded.", "# Guarded v2\n")
	if _, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: revised, CreatedBy: "usr_pg_guard"}); !errors.Is(err, ErrLibrarySkillFilesOmitted) || !strings.Contains(err.Error(), "version 1 has 1 bundle file") {
		t.Fatalf("single-document append over a bundle err=%v", err)
	}
	_, undeclared, err := normalizeLibrarySkillBundle(revised, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibrarySkillBundleVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: revised, CreatedBy: "usr_pg_guard"}, undeclared); !errors.Is(err, ErrLibrarySkillFilesOmitted) {
		t.Fatalf("undeclared SKILL.md-only bundle append err=%v", err)
	}
	if versions, err := store.LibrarySkillVersions(ctx, skill.ID); err != nil || len(versions) != 1 {
		t.Fatalf("refused appends left versions=%d err=%v", len(versions), err)
	}
	declared := undeclared
	declared.FilesDeclared = true
	second, err := store.CreateLibrarySkillBundleVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: revised, CreatedBy: "usr_pg_guard"}, declared)
	if err != nil || second.Version != 2 || len(second.Files) != 1 {
		t.Fatalf("declared empty append = %+v err=%v", second, err)
	}
	third, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: instructions, CreatedBy: "usr_pg_guard"})
	if err != nil || third.Version != 3 {
		t.Fatalf("single-document append after removal = %+v err=%v", third, err)
	}
	if data, _, found, err := store.LibrarySkillFileBytes(ctx, skill.ID, first.ID, "references/guide.md"); err != nil || !found || string(data) != "# Guide "+suffix+"\n" {
		t.Fatalf("version 1 lost its file: found=%t err=%v", found, err)
	}

	// Leased MCP path.
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Guard client " + suffix, Subject: "usr_pg_guard_" + suffix, CreatedBy: "usr_pg_guard"})
	if err != nil {
		t.Fatal(err)
	}
	clientIDs = append(clientIDs, client.ID)
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-guard-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); err != nil {
		t.Fatal(err)
	}
	leasedSlug := "pg-leased-guarded-" + suffix
	leasedInstructions := testSkillBundleFrontMatter(leasedSlug, "PG leased guarded.", "# Leased\n")
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "pg-guard-create", Name: leasedSlug, Slug: leasedSlug, Description: "PG leased guarded.", Content: leasedInstructions,
		Files: []LibrarySkillFileInput{{Path: "references/guide.md", Content: "# Leased guide " + suffix + "\n"}},
	})
	if err != nil {
		t.Fatalf("leased create: %v", err)
	}
	skillIDs = append(skillIDs, created.Skill.ID)
	blobDigests = append(blobDigests, librarySkillFileDigest([]byte("# Leased guide "+suffix+"\n")))
	update := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-guard-omit", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID, ExpectedVersionDigest: created.Version.Digest,
		Content: testSkillBundleFrontMatter(leasedSlug, "PG leased guarded.", "# Leased v2\n"),
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update); !errors.Is(err, ErrLibrarySkillFilesOmitted) {
		t.Fatalf("leased text-only update over a bundle err=%v", err)
	}
	lease, _, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates-1 {
		t.Fatalf("refused leased update consumed a write: %+v err=%v", lease, err)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || len(events) == 0 || events[len(events)-1].Action != LibraryMCPClientSkillAuthoringAuditActionRejected {
		t.Fatalf("refused leased update was not audited: %+v err=%v", events, err)
	}
	update.RequestID, update.Files = "pg-guard-remove", []LibrarySkillFileInput{}
	removed, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update)
	if err != nil || removed.Version.Version != 2 || len(removed.Version.Files) != 1 {
		t.Fatalf("leased empty-list update = %+v err=%v", removed, err)
	}
	retried := update
	retried.Files = nil
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, retried); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("retry without the empty list err=%v", err)
	}
}
