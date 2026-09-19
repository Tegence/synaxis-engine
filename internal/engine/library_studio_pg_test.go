package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgLibraryStudioDraftsProvenanceMediaAndEvidence covers the Postgres
// half of the studio contract: encrypted draft review aids, version
// provenance columns, the artifact-draft import receipt, Console human
// artifacts with citations and images, review comments, and skill evidence.
// It stays gated like the rest of the PgStore contract tests.
func TestPgLibraryStudioDraftsProvenanceMediaAndEvidence(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library studio integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	store.SetCipher(testCipher(t, 91))
	suffix := newPgFixtureSuffix()
	const actor = "usr_pg_studio"

	var cleanup []func()
	defer func() {
		for index := len(cleanup) - 1; index >= 0; index-- {
			cleanup[index]()
		}
	}()
	exec := func(query string, args ...any) {
		_, _ = store.pool.Exec(context.Background(), query, args...)
	}
	cleanupArtifact := func(id string) {
		cleanup = append(cleanup, func() {
			exec(`DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id IN (SELECT id FROM narthex_library_artifact_versions WHERE artifact_id=$1)`, id)
			exec(`DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, id)
			exec(`DELETE FROM narthex_library_artifacts WHERE id=$1`, id)
		})
	}
	cleanupRun := func(id string) {
		cleanup = append(cleanup, func() { exec(`DELETE FROM narthex_library_runs WHERE id=$1`, id) })
	}
	assertEncrypted := func(label, stored string, plain ...string) {
		t.Helper()
		if !strings.HasPrefix(stored, encPrefix) {
			t.Fatalf("%s was not encrypted at rest: %q", label, stored)
		}
		for _, value := range plain {
			if value != "" && strings.Contains(stored, value) {
				t.Fatalf("%s leaked plaintext %q", label, value)
			}
		}
	}

	// Skill drafts keep their review aids encrypted and intact.
	draft, err := store.CreateLibrarySkillDraft(ctx, LibrarySkillDraft{
		Name: "PG studio draft", Content: "## When to use\nAlways.", RequestedCapabilities: []string{"repo.read"},
		Rationale: "why this shape", Assumptions: []string{"alpha", "beta"}, Origin: LibraryDraftOriginGenerated,
		Generator: "fake", Model: "fake-model", PromptDigest: libraryDigest("prompt"), CreatedBy: actor,
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillDraft: %v", err)
	}
	cleanup = append(cleanup, func() { exec(`DELETE FROM narthex_library_skill_drafts WHERE id=$1`, draft.ID) })
	var rationale, assumptions string
	if err := store.pool.QueryRow(ctx, `SELECT rationale,assumptions FROM narthex_library_skill_drafts WHERE id=$1`, draft.ID).Scan(&rationale, &assumptions); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("skill draft rationale", rationale, "why this shape")
	assertEncrypted("skill draft assumptions", assumptions, "alpha", "beta")
	if reloaded, found := store.LibrarySkillDraft(ctx, draft.ID); !found || reloaded.Rationale != "why this shape" || len(reloaded.Assumptions) != 2 || reloaded.Assumptions[1] != "beta" {
		t.Fatalf("reloaded skill draft=%+v found=%v", reloaded, found)
	}

	// Version provenance columns: private labels encrypted, structure plain.
	skill, first, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{Slug: "pg-studio-" + suffix, Name: "PG studio", CreatedBy: actor},
		LibrarySkillVersion{Content: "# v1", Changelog: "first cut", Provenance: libraryVersionProvenanceFromSkillDraft(draft), CreatedBy: actor})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion: %v", err)
	}
	cleanup = append(cleanup, func() {
		exec(`DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, skill.ID)
		exec(`DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, skill.ID)
		exec(`DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, skill.ID)
		exec(`DELETE FROM narthex_library_skills WHERE id=$1`, skill.ID)
	})
	var changelog, origin, generator, draftID string
	if err := store.pool.QueryRow(ctx, `SELECT changelog,origin,generator,draft_id FROM narthex_library_skill_versions WHERE id=$1`, first.ID).Scan(&changelog, &origin, &generator, &draftID); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("skill version changelog", changelog, "first cut")
	assertEncrypted("skill version generator", generator, "fake")
	if origin != LibraryVersionOriginGenerated || draftID != draft.ID {
		t.Fatalf("skill version provenance columns origin=%q draft=%q", origin, draftID)
	}
	if reloaded, found := store.LibrarySkillVersion(ctx, skill.ID, first.ID); !found || reloaded.Changelog != "first cut" || reloaded.Provenance == nil ||
		reloaded.Provenance.Origin != LibraryVersionOriginGenerated || reloaded.Provenance.DraftID != draft.ID || reloaded.Provenance.Model != "fake-model" {
		t.Fatalf("reloaded generated version=%+v found=%v", reloaded, found)
	}
	second, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{SkillID: skill.ID, Content: "# v2", Provenance: &LibraryVersionProvenance{Origin: LibraryVersionOriginImported}, CreatedBy: actor})
	if err != nil {
		t.Fatalf("CreateLibrarySkillVersion: %v", err)
	}
	if reloaded, found := store.LibrarySkillVersion(ctx, skill.ID, second.ID); !found || reloaded.Provenance == nil || reloaded.Provenance.Origin != LibraryVersionOriginImported {
		t.Fatalf("reloaded imported version=%+v found=%v", reloaded, found)
	}
	// A row written before provenance existed reads back with none.
	if _, err := store.pool.Exec(ctx, `UPDATE narthex_library_skill_versions SET origin='' WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	if reloaded, found := store.LibrarySkillVersion(ctx, skill.ID, second.ID); !found || reloaded.Provenance != nil {
		t.Fatalf("legacy version=%+v found=%v", reloaded, found)
	}

	// Artifact draft import: idempotent, encrypted, prefixed digest accepted.
	source, sourceVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{Title: "PG source", Origin: LibraryArtifactOriginHuman, CreatedBy: actor},
		LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# source", CreatedBy: actor})
	if err != nil {
		t.Fatalf("create source artifact: %v", err)
	}
	cleanupArtifact(source.ID)
	request := LibraryPlatformArtifactDraftImport{
		RequestID: "ardr_pg_" + suffix + "_0123456789", Format: LibraryArtifactFormatMarkdown,
		SourceArtifactID: source.ID, SourceArtifactVersionID: sourceVersion.ID, SourceArtifactDigest: "sha256:" + sourceVersion.Digest,
		Candidate: LibraryPlatformArtifactDraftCandidate{
			Title: "PG weekly", Summary: "what shipped", Content: "# weekly", Provider: "kimi-platform", Model: "kimi-k2.7-code",
			PromptDigest: libraryDigest("brief"), Rationale: "followed the source", Assumptions: []string{"week ends friday"},
		},
	}
	imported, replayed, err := store.ImportPlatformLibraryArtifactDraft(ctx, request, actor)
	if err != nil || replayed {
		t.Fatalf("first artifact draft import draft=%+v replayed=%v err=%v", imported, replayed, err)
	}
	cleanup = append(cleanup, func() {
		exec(`DELETE FROM narthex_library_artifact_draft_imports WHERE draft_id=$1`, imported.ID)
		exec(`DELETE FROM narthex_library_artifact_drafts WHERE id=$1`, imported.ID)
	})
	if again, replayed, err := store.ImportPlatformLibraryArtifactDraft(ctx, request, actor); err != nil || !replayed || again.ID != imported.ID {
		t.Fatalf("replayed artifact draft import draft=%+v replayed=%v err=%v", again, replayed, err)
	}
	conflict := request
	conflict.Candidate.Content = "# changed"
	if _, _, err := store.ImportPlatformLibraryArtifactDraft(ctx, conflict, actor); !errors.Is(err, ErrLibraryDraftImportConflict) {
		t.Fatalf("conflicting artifact draft import err=%v", err)
	}
	stale := request
	stale.RequestID, stale.SourceArtifactDigest = "ardr_pg_stale_"+suffix+"_0123456789", libraryDigest("moved")
	if _, _, err := store.ImportPlatformLibraryArtifactDraft(ctx, stale, actor); !errors.Is(err, ErrLibraryArtifactVersionNotFound) {
		t.Fatalf("stale source artifact draft import err=%v", err)
	}
	var title, content, draftRationale, draftAssumptions, sourceID string
	if err := store.pool.QueryRow(ctx, `SELECT title,content,rationale,assumptions,source_artifact_id FROM narthex_library_artifact_drafts WHERE id=$1`, imported.ID).Scan(&title, &content, &draftRationale, &draftAssumptions, &sourceID); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("artifact draft title", title, "PG weekly")
	assertEncrypted("artifact draft content", content, "# weekly")
	assertEncrypted("artifact draft rationale", draftRationale, "followed the source")
	assertEncrypted("artifact draft assumptions", draftAssumptions, "week ends friday")
	assertEncrypted("artifact draft source", sourceID, source.ID)
	if reloaded, found := store.LibraryArtifactDraft(ctx, imported.ID); !found || reloaded.SourceArtifactDigest != sourceVersion.Digest || len(reloaded.Assumptions) != 1 || reloaded.Generator != "kimi-platform" {
		t.Fatalf("reloaded artifact draft=%+v found=%v", reloaded, found)
	}

	// Human artifact with a citation commits run, artifact, and version together.
	run, artifact, version, err := store.CreateLibraryHumanArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: imported.Title, Summary: imported.Summary, Origin: LibraryArtifactOriginHuman,
		SourceArtifactID: source.ID, SourceArtifactVersionID: sourceVersion.ID, SourceArtifactDigest: sourceVersion.Digest, CreatedBy: actor,
	}, LibraryArtifactVersion{Format: imported.Format, Body: imported.Content, Changelog: "from draft", Provenance: libraryVersionProvenanceFromArtifactDraft(imported), CreatedBy: actor})
	if err != nil {
		t.Fatalf("CreateLibraryHumanArtifactWithInitialVersion: %v", err)
	}
	cleanupArtifact(artifact.ID)
	cleanupRun(run.ID)
	if run.Origin != LibraryRunOriginHuman || run.SourceArtifactID != source.ID || artifact.RunID != run.ID || version.Provenance == nil || version.Provenance.Origin != LibraryVersionOriginGenerated {
		t.Fatalf("human artifact run=%+v artifact=%+v version=%+v", run, artifact, version)
	}
	var versionChangelog, versionOrigin string
	if err := store.pool.QueryRow(ctx, `SELECT changelog,origin FROM narthex_library_artifact_versions WHERE id=$1`, version.ID).Scan(&versionChangelog, &versionOrigin); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("artifact version changelog", versionChangelog, "from draft")
	if versionOrigin != LibraryVersionOriginGenerated {
		t.Fatalf("artifact version origin=%q", versionOrigin)
	}
	if reloaded, found := store.LibraryArtifactVersion(ctx, artifact.ID, version.ID); !found || reloaded.Changelog != "from draft" || reloaded.Provenance == nil || reloaded.Provenance.DraftID != imported.ID {
		t.Fatalf("reloaded artifact version=%+v found=%v", reloaded, found)
	}
	if _, _, _, err := store.CreateLibraryHumanArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "stale", Origin: LibraryArtifactOriginHuman, SourceArtifactID: source.ID, SourceArtifactVersionID: sourceVersion.ID, SourceArtifactDigest: libraryDigest("moved"), CreatedBy: actor,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "x", CreatedBy: actor}); !errors.Is(err, ErrLibraryArtifactVersionNotFound) {
		t.Fatalf("stale human citation err=%v", err)
	}
	citations, err := store.LibraryArtifactCitations(ctx, source.ID, libraryArtifactCitedByLimit)
	if err != nil || len(citations) != 1 || citations[0].ArtifactID != artifact.ID || citations[0].VersionID != sourceVersion.ID || citations[0].Title != imported.Title {
		t.Fatalf("citations=%+v err=%v", citations, err)
	}
	if none, err := store.LibraryArtifactCitations(ctx, artifact.ID, libraryArtifactCitedByLimit); err != nil || len(none) != 0 {
		t.Fatalf("uncited citations=%+v err=%v", none, err)
	}

	// Review comments are encrypted and returned on the version.
	reviewed, err := store.ReviewLibraryArtifactVersionWithComment(ctx, artifact.ID, version.ID, LibraryRedactionRejected, "usr_reviewer", "Remove the names", time.Now().UTC())
	if err != nil || reviewed.ReviewComment != "Remove the names" || reviewed.RedactionStatus != LibraryRedactionRejected {
		t.Fatalf("review with comment=%+v err=%v", reviewed, err)
	}
	var reviewComment string
	if err := store.pool.QueryRow(ctx, `SELECT review_comment FROM narthex_library_artifact_versions WHERE id=$1`, version.ID).Scan(&reviewComment); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("review comment", reviewComment, "Remove the names")

	// Console image create/version: one media class per artifact.
	canonical, _ := libraryArtifactTestPNG(t)
	imageRun, image, imageVersion, err := store.CreateLibraryHumanImageArtifactWithInitialVersion(ctx, LibraryArtifact{Title: "PG image", Origin: LibraryArtifactOriginHuman, CreatedBy: actor}, canonical, "two pixels")
	if err != nil {
		t.Fatalf("CreateLibraryHumanImageArtifactWithInitialVersion: %v", err)
	}
	cleanupArtifact(image.ID)
	cleanupRun(imageRun.ID)
	if imageRun.Origin != LibraryRunOriginHuman || imageRun.OutputDigest != canonical.Digest || imageVersion.Format != LibraryArtifactFormatImage {
		t.Fatalf("image run=%+v version=%+v", imageRun, imageVersion)
	}
	if _, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: image.ID, Format: LibraryArtifactFormatText, Body: "x", CreatedBy: actor}); !errors.Is(err, ErrLibraryArtifactFormatMismatch) {
		t.Fatalf("text after image err=%v", err)
	}
	appended, err := store.CreateLibraryHumanImageArtifactVersion(ctx, LibraryHumanImageArtifactVersionCreateRequest{
		ArtifactID: image.ID, Image: canonical, AltText: "again", CreatedBy: actor, Changelog: "re-exported", Provenance: &LibraryVersionProvenance{Origin: LibraryVersionOriginManual},
	})
	if err != nil || appended.Version != 2 || appended.Changelog != "re-exported" || appended.Format != LibraryArtifactFormatImage {
		t.Fatalf("image version=%+v err=%v", appended, err)
	}
	if bytes, found, err := store.LibraryArtifactImageBytes(ctx, image.ID, appended.ID); err != nil || !found || len(bytes) != len(canonical.Bytes) {
		t.Fatalf("appended image bytes found=%v len=%d err=%v", found, len(bytes), err)
	}
	if _, err := store.CreateLibraryHumanImageArtifactVersion(ctx, LibraryHumanImageArtifactVersionCreateRequest{ArtifactID: artifact.ID, Image: canonical, CreatedBy: actor}); !errors.Is(err, ErrLibraryArtifactFormatMismatch) {
		t.Fatalf("image after text err=%v", err)
	}
	page, err := store.LibraryConsoleArtifactPage(ctx, LibraryConsolePageCursor{}, libraryConsolePageMax)
	if err != nil {
		t.Fatalf("LibraryConsoleArtifactPage: %v", err)
	}
	var sawImage bool
	for _, item := range page.Artifacts {
		if item.Artifact.ID != image.ID {
			continue
		}
		sawImage = true
		if item.LatestVersion == nil || item.LatestVersion.ID != appended.ID || item.LatestVersion.MIMEType != libraryArtifactImageMIMEPNG || item.LatestVersion.Format != LibraryArtifactFormatImage {
			t.Fatalf("image page summary=%+v", item.LatestVersion)
		}
	}
	if !sawImage {
		t.Fatalf("image artifact absent from Console page of %d rows", len(page.Artifacts))
	}

	// Skill evidence: only skill_run provenance for this skill, newest first.
	binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "ws-" + suffix, Mode: LibraryBindingModePin, PinnedVersionID: first.ID, CreatedBy: actor})
	if err != nil {
		t.Fatalf("UpsertLibrarySkillBinding: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	var newest LibraryRun
	for index := 0; index < 3; index++ {
		newest, err = store.CreateLibraryRun(ctx, LibraryRun{
			Origin: LibraryRunOriginSkillRun, SkillID: skill.ID, SkillVersionID: first.ID, BindingID: binding.ID,
			ActorRef: "usr_host", SurfaceRef: "mcpc_host", Status: "succeeded", StartedAt: base.Add(time.Duration(index) * time.Second),
		})
		if err != nil {
			t.Fatalf("create skill run %d: %v", index, err)
		}
		cleanupRun(newest.ID)
	}
	humanRun, err := store.CreateLibraryRun(ctx, LibraryRun{Origin: LibraryRunOriginHuman, ActorRef: actor, SurfaceRef: "console", Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupRun(humanRun.ID)
	runs, err := store.LibrarySkillRuns(ctx, skill.ID, 2)
	if err != nil || len(runs) != 2 || runs[0].ID != newest.ID || runs[1].Origin != LibraryRunOriginSkillRun {
		t.Fatalf("skill runs=%+v err=%v", runs, err)
	}
	if correlations, err := store.LibraryRunCorrelationsForRuns(ctx, []string{newest.ID, humanRun.ID}); err != nil || len(correlations) != 0 {
		t.Fatalf("correlations for runs=%+v err=%v", correlations, err)
	}
}
