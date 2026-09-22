package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestPgLibrarySkillBundlesRoundTripLeaseAndBackfill covers the PostgreSQL
// half of the bundle contract: encrypted blobs and manifests, byte-exact
// reads, staged uploads under a lease with idempotent replay, and the startup
// backfill that gives pre-bundle rows (including the Engine-managed seed
// skill) their derived one-file manifest without touching content or digest.
func TestPgLibrarySkillBundlesRoundTripLeaseAndBackfill(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library bundle integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	store.SetCipher(testCipher(t, 137))
	suffix := newPgFixtureSuffix()
	exec := func(query string, args ...any) {
		if _, err := store.pool.Exec(context.Background(), query, args...); err != nil {
			t.Errorf("cleanup %q: %v", query, err)
		}
	}
	// Every row this test creates is removed in dependency order at the end,
	// so the shared test database (and its Engine-managed seed skill) is left
	// exactly as other PgStore tests expect it.
	var skillIDs, clientIDs, blobDigests []string
	cleanupSkill := func(id string) { skillIDs = append(skillIDs, id) }
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
		// The explicit reconcile below installs the Engine-managed seed skill;
		// remove it again so later tests start from the same empty registry as
		// the built-in lifecycle test leaves behind.
		if err := cleanupPgBuiltInLibraryTestRows(context.Background(), store); err != nil {
			t.Errorf("cleanup built-in rows: %v", err)
		}
	}()

	files := testElevenFileBundle(t, "commit-poc-loe-"+suffix, "Build a PoC level-of-effort workbook on the standard template.")
	content, bundle, err := normalizeLibrarySkillBundle("", files)
	if err != nil {
		t.Fatal(err)
	}
	skill, version, err := store.CreateLibrarySkillWithInitialBundle(ctx, LibrarySkill{
		Slug: "commit-poc-loe-" + suffix, Name: "Commit PoC LOE " + suffix, Description: "Build a PoC level-of-effort workbook on the standard template.", CreatedBy: "usr_pg_bundle",
	}, LibrarySkillVersion{Content: content, CreatedBy: "usr_pg_bundle"}, bundle)
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	cleanupSkill(skill.ID)
	for digest := range bundle.Blobs {
		blobDigests = append(blobDigests, digest)
	}
	if version.ManifestDigest != bundle.ManifestDigest || len(version.Files) != 11 {
		t.Fatalf("stored version = %+v", version)
	}
	var storedManifest, storedDigest string
	if err := store.pool.QueryRow(ctx, `SELECT manifest,manifest_digest FROM narthex_library_skill_versions WHERE id=$1`, version.ID).Scan(&storedManifest, &storedDigest); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(storedManifest, encPrefix) || strings.Contains(storedManifest, "template.xlsx") || storedDigest != bundle.ManifestDigest {
		t.Fatalf("manifest at rest = %q digest=%s", storedManifest[:12], storedDigest)
	}
	var storedBlob []byte
	if err := store.pool.QueryRow(ctx, `SELECT encrypted_data FROM narthex_library_skill_blobs WHERE digest=$1`, librarySkillFileDigest(files[10].Data)).Scan(&storedBlob); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedBlob, files[10].Data) {
		t.Fatal("blob bytes were stored in plaintext")
	}
	reloaded, found := store.LibrarySkillVersion(ctx, skill.ID, version.ID)
	if !found || reloaded.ManifestDigest != bundle.ManifestDigest || len(reloaded.Files) != 11 {
		t.Fatalf("reloaded version = %+v found=%t", reloaded, found)
	}
	for _, file := range files {
		data, entry, found, err := store.LibrarySkillFileBytes(ctx, skill.ID, version.ID, file.Path)
		if err != nil || !found || !bytes.Equal(data, file.Data) || entry.Digest != librarySkillFileDigest(file.Data) {
			t.Fatalf("%s did not round-trip: found=%t err=%v", file.Path, found, err)
		}
	}
	// A second version dedupes identical blobs by digest.
	version2, err := store.CreateLibrarySkillBundleVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: content, CreatedBy: "usr_pg_bundle"}, bundle)
	if err != nil || version2.Version != 2 || version2.ManifestDigest != version.ManifestDigest {
		t.Fatalf("second version = %+v err=%v", version2, err)
	}
	var blobCount int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM narthex_library_skill_blobs WHERE digest = ANY($1::text[])`, func() []string {
		digests := make([]string, 0, len(bundle.Blobs))
		for digest := range bundle.Blobs {
			digests = append(digests, digest)
		}
		return digests
	}()).Scan(&blobCount); err != nil {
		t.Fatal(err)
	}
	if blobCount != len(bundle.Blobs) {
		t.Fatalf("blob rows = %d, want %d", blobCount, len(bundle.Blobs))
	}

	// Leased staging: replay is free, a changed payload conflicts, and the
	// create consumes the staged blob only for the staging client/epoch.
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bundle client " + suffix, Subject: "usr_pg_bundle_" + suffix, CreatedBy: "usr_pg_bundle"})
	if err != nil {
		t.Fatal(err)
	}
	clientIDs = append(clientIDs, client.ID)
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); err != nil {
		t.Fatal(err)
	}
	upload := LibraryMCPClientSkillBlobUploadRequest{RequestID: "pg-upload-1", Path: "assets/template.xlsx", DataBase64: base64.StdEncoding.EncodeToString(files[10].Data)}
	staged, err := store.StageLibraryMCPClientSkillBlob(ctx, client, upload)
	if err != nil || staged.Replayed || staged.Lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates || staged.Lease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads-1 {
		t.Fatalf("stage = %+v err=%v", staged, err)
	}
	if replay, err := store.StageLibraryMCPClientSkillBlob(ctx, client, upload); err != nil || !replay.Replayed || replay.BlobID != staged.BlobID || replay.Lease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads-1 {
		t.Fatalf("stage replay = %+v err=%v", replay, err)
	}
	changed := upload
	changed.DataBase64 = base64.StdEncoding.EncodeToString(testOOXMLBlob(t, 512))
	if _, err := store.StageLibraryMCPClientSkillBlob(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("changed stage replay err=%v", err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "pg-create-1", Name: "Leased bundle " + suffix, Slug: "leased-bundle-" + suffix, Description: "Leased bundle.",
		Content: testSkillBundleFrontMatter("leased-bundle-"+suffix, "Leased bundle.", "# Leased\n"),
		Files: []LibrarySkillFileInput{
			{Path: "references/guide.md", Content: "# Guide\n"},
			{Path: "assets/template.xlsx", BlobID: staged.BlobID},
		},
	})
	if err != nil {
		t.Fatalf("leased bundle create: %v", err)
	}
	cleanupSkill(created.Skill.ID)
	if len(created.Version.Files) != 3 || created.Lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates-1 || created.Lease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads-1 {
		t.Fatalf("leased create = %+v", created)
	}
	data, _, found, err := store.LibrarySkillFileBytes(ctx, created.Skill.ID, created.Version.ID, "assets/template.xlsx")
	if err != nil || !found || !bytes.Equal(data, files[10].Data) {
		t.Fatalf("staged blob missing from leased version: found=%t err=%v", found, err)
	}
	items, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || len(items) != 1 || items[0].LatestManifestDigest != created.Version.ManifestDigest {
		t.Fatalf("authoring list = %+v err=%v", items, err)
	}

	// Backfill: strip the manifest columns from a stored row (simulating a
	// pre-bundle deployment) and from the managed seed skill, then run the
	// startup migration and prove both derive the one-file manifest without
	// changing content or digest. The seed skill is shared with every other
	// PgStore test in this database, so this part runs in the plaintext
	// posture: a test-only cipher must never leave the managed rows encrypted
	// for the next test.
	store.SetCipher(nil)
	plain, plainVersion, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "plain-" + suffix, Name: "Plain " + suffix, CreatedBy: "usr_pg_bundle",
	}, LibrarySkillVersion{Content: "# Plain instructions\n", CreatedBy: "usr_pg_bundle"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupSkill(plain.ID)
	exec(`UPDATE narthex_library_skill_versions SET manifest='',manifest_digest='' WHERE id=$1`, plainVersion.ID)
	if err := ReconcileBuiltInLibrary(ctx, store); err != nil {
		t.Fatalf("reconcile seed skill: %v", err)
	}
	exec(`UPDATE narthex_library_skill_versions SET manifest='',manifest_digest='' WHERE id=$1`, usingSynaxisSkillVersionID)
	derived, found := store.LibrarySkillVersion(ctx, plain.ID, plainVersion.ID)
	if !found || len(derived.Files) != 1 || derived.ManifestDigest != plainVersion.ManifestDigest || derived.Digest != plainVersion.Digest {
		t.Fatalf("derived-on-read legacy version = %+v", derived)
	}
	if err := store.backfillLibrarySkillVersionManifests(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	for _, id := range []string{plainVersion.ID, usingSynaxisSkillVersionID} {
		var manifest, digest, contentDigest string
		if err := store.pool.QueryRow(ctx, `SELECT manifest,manifest_digest,digest FROM narthex_library_skill_versions WHERE id=$1`, id).Scan(&manifest, &digest, &contentDigest); err != nil {
			t.Fatalf("read backfilled %s: %v", id, err)
		}
		if manifest == "" || digest == "" {
			t.Fatalf("backfill left %s without a manifest", id)
		}
		if id == usingSynaxisSkillVersionID && contentDigest != usingSynaxisExpectedContentDigest {
			t.Fatalf("seed content digest changed to %s", contentDigest)
		}
	}
	seed, found := store.LibrarySkillVersion(ctx, usingSynaxisSkillID, usingSynaxisSkillVersionID)
	wantSeed, err := librarySkillManifestDigest(legacyLibrarySkillManifest(usingSynaxisSkillContent, usingSynaxisExpectedContentDigest))
	if err != nil {
		t.Fatal(err)
	}
	if !found || seed.ManifestDigest != wantSeed || seed.Content != usingSynaxisSkillContent {
		t.Fatalf("seed after backfill = %+v found=%t", seed, found)
	}
	// Running the backfill again is a no-op.
	if err := store.backfillLibrarySkillVersionManifests(ctx); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
}
