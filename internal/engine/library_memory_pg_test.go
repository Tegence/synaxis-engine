package engine

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPgLibraryMemoryParityEncryptionAndHardForget(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library memory integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	suffix := newPgFixtureSuffix()
	owner, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG memory owner " + suffix, Subject: "usr_pg_memory_owner_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG memory reader " + suffix, Subject: "usr_pg_memory_reader_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	sourceRun, err := store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginAgentDirect, ActorRef: owner.Subject, SurfaceRef: owner.ID, Status: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceArtifact, sourceArtifactVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "PG memory source " + suffix, Origin: LibraryArtifactOriginHuman, CreatedBy: "pg-memory-source-author",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "source body", CreatedBy: "pg-memory-source-author"})
	if err != nil {
		t.Fatal(err)
	}
	var memoryID, referrerID string
	t.Cleanup(func() {
		if memoryID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_memories WHERE id=$1`, memoryID)
		}
		if referrerID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_memories WHERE id=$1`, referrerID)
		}
		// Versions and grants reference the artifact; deleting the artifact
		// first fails silently and leaks an encrypted row into the shared
		// database, where a later test without this key cannot read it.
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_grants WHERE artifact_id=$1`, sourceArtifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, sourceArtifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, sourceArtifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, sourceRun.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1 OR id=$2`, owner.ID, reader.ID)
	})

	plaintext := "Remember this encrypted PG statement."
	memory, first, err := store.CreateLibraryMemoryWithInitialVersion(ctx, LibraryMemory{
		Kind: LibraryMemoryKindLesson, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
		AgentSurfaceID: owner.ID, CreatedBy: "pg-memory-author",
	}, LibraryMemoryVersion{
		Content: plaintext, SourceRunID: sourceRun.ID, SourceArtifactID: sourceArtifact.ID,
		SourceArtifactVersionID: sourceArtifactVersion.ID, SourceDigest: sourceArtifactVersion.Digest, CreatedBy: "pg-memory-author",
		CreatedAt: time.Date(2026, 8, 31, 10, 0, 0, 123456789, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	memoryID = memory.ID
	assertLibraryMemoryVersionTimes(t, store, memory, first, time.Date(2026, 8, 31, 10, 0, 0, 123456000, time.UTC))
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: reader.ID, CreatedBy: "pg-memory-grantor",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("PG proposed memory grant error=%v", err)
	}
	var rawContent, rawSourceRun, rawSourceArtifact, rawSourceArtifactVersion, rawSourceDigest, rawMemoryCreator, rawVersionCreator string
	if err := store.pool.QueryRow(ctx, `SELECT v.content,v.source_run_id,v.source_artifact_id,v.source_artifact_version_id,v.source_digest,m.created_by,v.created_by FROM narthex_library_memories m JOIN narthex_library_memory_versions v ON v.memory_id=m.id WHERE m.id=$1 AND v.id=$2`, memory.ID, first.ID).Scan(&rawContent, &rawSourceRun, &rawSourceArtifact, &rawSourceArtifactVersion, &rawSourceDigest, &rawMemoryCreator, &rawVersionCreator); err != nil {
		t.Fatal(err)
	}
	if rawContent != plaintext || rawSourceRun != sourceRun.ID || rawSourceArtifact != sourceArtifact.ID || rawSourceArtifactVersion != sourceArtifactVersion.ID || rawSourceDigest != sourceArtifactVersion.Digest || rawMemoryCreator != "pg-memory-author" || rawVersionCreator != "pg-memory-author" {
		t.Fatalf("unexpected pre-migration plaintext row: content=%q run=%q artifact=%q version=%q digest=%q memoryCreator=%q versionCreator=%q", rawContent, rawSourceRun, rawSourceArtifact, rawSourceArtifactVersion, rawSourceDigest, rawMemoryCreator, rawVersionCreator)
	}

	store.SetCipher(testCipher(t, 47))
	if err := store.EncryptExisting(ctx); err != nil {
		t.Fatalf("EncryptExisting memory migration: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT v.content,v.source_run_id,v.source_artifact_id,v.source_artifact_version_id,v.source_digest,m.created_by,v.created_by FROM narthex_library_memories m JOIN narthex_library_memory_versions v ON v.memory_id=m.id WHERE m.id=$1 AND v.id=$2`, memory.ID, first.ID).Scan(&rawContent, &rawSourceRun, &rawSourceArtifact, &rawSourceArtifactVersion, &rawSourceDigest, &rawMemoryCreator, &rawVersionCreator); err != nil {
		t.Fatal(err)
	}
	for label, value := range map[string]string{
		"content": rawContent, "source run": rawSourceRun, "source artifact": rawSourceArtifact,
		"source artifact version": rawSourceArtifactVersion, "source digest": rawSourceDigest,
		"memory creator": rawMemoryCreator, "version creator": rawVersionCreator,
	} {
		if !strings.HasPrefix(value, encPrefix) || strings.Contains(value, plaintext) {
			t.Fatalf("%s was not encrypted at rest: %q", label, value)
		}
	}
	loaded, found := store.LibraryMemoryVersion(ctx, memory.ID, first.ID)
	if !found || loaded.Content != plaintext || loaded.SourceRunID != sourceRun.ID || loaded.SourceArtifactID != sourceArtifact.ID || loaded.SourceArtifactVersionID != sourceArtifactVersion.ID || loaded.SourceDigest != sourceArtifactVersion.Digest || loaded.CreatedBy != "pg-memory-author" {
		t.Fatalf("encrypted memory read=%+v found=%t", loaded, found)
	}

	memory, err = store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateActive, LibraryMemoryTrustWorkspaceApproved, time.Time{}, time.Now().UTC().Add(time.Hour), "", "pg-memory-reviewer", time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	var rawReviewer string
	if err := store.pool.QueryRow(ctx, `SELECT reviewed_by FROM narthex_library_memories WHERE id=$1`, memory.ID).Scan(&rawReviewer); err != nil || !strings.HasPrefix(rawReviewer, encPrefix) {
		t.Fatalf("reviewer encryption=%q err=%v", rawReviewer, err)
	}
	if selections, err := store.LibraryMemoryRecallSelections(ctx, owner, time.Now().UTC()); err != nil || len(selections) != 1 || selections[0].Version.ID != first.ID {
		t.Fatalf("PG owner recall=%+v err=%v", selections, err)
	}
	grant, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: reader.ID, CreatedBy: "pg-memory-grantor",
	})
	if err != nil {
		t.Fatal(err)
	}
	var rawGrantor string
	if err := store.pool.QueryRow(ctx, `SELECT created_by FROM narthex_library_memory_grants WHERE id=$1`, grant.ID).Scan(&rawGrantor); err != nil || !strings.HasPrefix(rawGrantor, encPrefix) {
		t.Fatalf("grant creator encryption=%q err=%v", rawGrantor, err)
	}
	if selections, err := store.LibraryMemoryRecallSelections(ctx, reader, time.Now().UTC()); err != nil || len(selections) != 1 || selections[0].Access != LibraryMemoryAccessGranted || selections[0].Version.ID != first.ID {
		t.Fatalf("PG granted recall=%+v err=%v", selections, err)
	}

	correctionTime := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	corrected, second, err := store.CreateLibraryMemoryVersion(ctx, memory.ID, LibraryMemoryVersion{
		Content: "Corrected encrypted PG statement.", SourceRunID: sourceRun.ID, SourceArtifactID: sourceArtifact.ID,
		SourceArtifactVersionID: sourceArtifactVersion.ID, SourceDigest: sourceArtifactVersion.Digest,
		CreatedAt: correctionTime,
	}, "pg-memory-editor")
	if err != nil || corrected.State != LibraryMemoryStateProposed || second.Version != 2 {
		t.Fatalf("PG correction memory=%+v version=%+v err=%v", corrected, second, err)
	}
	var rawSecond, rawSecondSourceRun, rawSecondSourceArtifact, rawSecondSourceArtifactVersion, rawSecondSourceDigest, rawSecondCreator string
	if err := store.pool.QueryRow(ctx, `SELECT content,source_run_id,source_artifact_id,source_artifact_version_id,source_digest,created_by FROM narthex_library_memory_versions WHERE id=$1`, second.ID).Scan(&rawSecond, &rawSecondSourceRun, &rawSecondSourceArtifact, &rawSecondSourceArtifactVersion, &rawSecondSourceDigest, &rawSecondCreator); err != nil {
		t.Fatal(err)
	}
	for label, value := range map[string]string{
		"corrected content": rawSecond, "corrected source run": rawSecondSourceRun, "corrected source artifact": rawSecondSourceArtifact,
		"corrected source artifact version": rawSecondSourceArtifactVersion, "corrected source digest": rawSecondSourceDigest, "corrected creator": rawSecondCreator,
	} {
		if !strings.HasPrefix(value, encPrefix) {
			t.Fatalf("%s was not encrypted under configured cipher: %q", label, value)
		}
	}
	loadedSecond, found := store.LibraryMemoryVersion(ctx, memory.ID, second.ID)
	if !found || loadedSecond.SourceRunID != sourceRun.ID || loadedSecond.SourceArtifactID != sourceArtifact.ID || loadedSecond.SourceArtifactVersionID != sourceArtifactVersion.ID || loadedSecond.SourceDigest != sourceArtifactVersion.Digest {
		t.Fatalf("configured-cipher source tuple round-trip=%+v found=%t", loadedSecond, found)
	}
	assertLibraryMemoryVersionTimes(t, store, corrected, second, correctionTime.Add(-789*time.Nanosecond))
	var rawAutoRevoker string
	if err := store.pool.QueryRow(ctx, `SELECT revoked_by FROM narthex_library_memory_grants WHERE id=$1`, grant.ID).Scan(&rawAutoRevoker); err != nil || !strings.HasPrefix(rawAutoRevoker, encPrefix) {
		t.Fatalf("automatic correction revoker encryption=%q err=%v", rawAutoRevoker, err)
	}
	grants, err := store.LibraryMemoryGrants(ctx, memory.ID)
	if err != nil || len(grants) != 1 || grants[0].ID != grant.ID || grants[0].RevokedBy != "pg-memory-editor" || !grants[0].RevokedAt.Equal(second.CreatedAt) {
		t.Fatalf("PG correction did not preserve+revoke grant: grants=%+v versionCreatedAt=%s loadedVersionCreatedAt=%s memoryUpdatedAt=%s err=%v", grants, second.CreatedAt.Format(time.RFC3339Nano), loadedSecond.CreatedAt.Format(time.RFC3339Nano), corrected.UpdatedAt.Format(time.RFC3339Nano), err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "reviewer", time.Now().UTC())); !errors.Is(err, ErrLibraryMemoryVersionConflict) {
		t.Fatalf("PG stale review error=%v", err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "reviewer", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if selections, err := store.LibraryMemoryRecallSelections(ctx, reader, time.Now().UTC()); err != nil || len(selections) != 0 {
		t.Fatalf("PG v2 approval reactivated stale v1 grant=%+v err=%v", selections, err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: reader.ID, CreatedBy: "pg-memory-grantor",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("PG non-current grant error=%v", err)
	}
	secondGrant, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: second.ID, MemoryVersionDigest: second.Digest, AgentSurfaceID: reader.ID, CreatedBy: "pg-memory-grantor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if selections, err := store.LibraryMemoryRecallSelections(ctx, reader, time.Now().UTC()); err != nil || len(selections) != 1 || selections[0].Version.ID != second.ID {
		t.Fatalf("PG current-head grant recall=%+v err=%v", selections, err)
	}
	if _, err := store.RevokeLibraryMemoryGrant(ctx, memory.ID, secondGrant.ID, "pg-memory-revoker", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var rawRevoker string
	if err := store.pool.QueryRow(ctx, `SELECT revoked_by FROM narthex_library_memory_grants WHERE id=$1`, secondGrant.ID).Scan(&rawRevoker); err != nil || !strings.HasPrefix(rawRevoker, encPrefix) {
		t.Fatalf("grant revoker encryption=%q err=%v", rawRevoker, err)
	}
	referrer, referrerVersion, err := store.CreateLibraryMemoryWithInitialVersion(ctx, LibraryMemory{
		Kind: LibraryMemoryKindDecision, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
		AgentSurfaceID: owner.ID, CreatedBy: "pg-referrer-author",
	}, LibraryMemoryVersion{Content: "This decision was replaced.", CreatedBy: "pg-referrer-author"})
	if err != nil {
		t.Fatal(err)
	}
	referrerID = referrer.ID
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, referrer.ID, "pg-memory-reviewer", time.Now().UTC())); !errors.Is(err, ErrLibraryMemorySupersessionIneligible) {
		t.Fatalf("PG proposed replacement error=%v", err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, referrer.ID, libraryMemoryReviewForTest(referrerVersion.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, memory.ID, "pg-referrer-reviewer", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, referrer.ID, "pg-memory-reviewer", time.Now().UTC())); !errors.Is(err, ErrLibraryMemorySupersessionIneligible) {
		t.Fatalf("PG sequential supersession cycle error=%v", err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, time.Now().UTC().Add(-time.Second), time.Time{}, "", "reviewer", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if selections, err := store.LibraryMemoryRecallSelections(ctx, owner, time.Now().UTC()); err != nil || len(selections) != 0 {
		t.Fatalf("PG expired recall=%+v err=%v", selections, err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: second.ID, MemoryVersionDigest: second.Digest, AgentSurfaceID: reader.ID, CreatedBy: "pg-memory-grantor",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("PG effectively expired memory grant error=%v", err)
	}

	if err := store.ForgetLibraryMemory(ctx, memory.ID); err != nil {
		t.Fatal(err)
	}
	memoryID = ""
	referrer, found = store.LibraryMemory(ctx, referrer.ID)
	if !found || referrer.State != LibraryMemoryStateExpired || referrer.SupersededByMemoryID != "" {
		t.Fatalf("PG forget left incoming supersession reference: memory=%+v found=%t", referrer, found)
	}
	for table := range map[string]struct{}{"narthex_library_memories": {}, "narthex_library_memory_versions": {}, "narthex_library_memory_grants": {}} {
		var count int
		column := "id"
		if table != "narthex_library_memories" {
			column = "memory_id"
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, memory.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("hard forget left %d rows in %s (err=%v)", count, table, err)
		}
	}
}

func TestPgLibraryMemoryProposalEvidenceIsBoundToExactClientSurface(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library memory integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	suffix := newPgFixtureSuffix()
	alice, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG evidence Alice " + suffix, Subject: "usr_pg_evidence_alice_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG evidence Bob " + suffix, Subject: "usr_pg_evidence_bob_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	run, artifact, artifactVersion, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, alice, LibraryArtifact{
		Title: "PG private evidence " + suffix, Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "private PG evidence"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_memories WHERE agent_surface_id=$1 OR agent_surface_id=$2`, alice.ID, bob.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_grants WHERE artifact_id=$1`, artifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1 OR id=$2`, alice.ID, bob.ID)
	})
	propose := func(client MCPClient, source LibraryMemoryVersion) error {
		source.Content = "PG evidence-bound observation."
		_, _, err := store.CreateLibraryMCPClientMemoryProposal(ctx, client, LibraryMemory{Kind: LibraryMemoryKindFact}, source)
		return err
	}

	if err := propose(bob, LibraryMemoryVersion{SourceRunID: run.ID}); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("PG cross-surface run evidence error=%v, want generic unavailable", err)
	}
	if err := propose(alice, LibraryMemoryVersion{SourceRunID: run.ID}); err != nil {
		t.Fatalf("PG owner run evidence: %v", err)
	}
	evidence := LibraryMemoryVersion{
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: artifactVersion.ID, SourceDigest: artifactVersion.Digest,
	}
	if err := propose(bob, evidence); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("PG ungranted artifact evidence error=%v, want generic unavailable", err)
	}
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: artifactVersion.ID, ArtifactVersionDigest: artifactVersion.Digest,
		AgentSurfaceID: bob.ID, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := propose(bob, evidence); err != nil {
		t.Fatalf("PG granted artifact evidence: %v", err)
	}
	if _, err := store.RevokeLibraryArtifactGrant(ctx, artifact.ID, grant.ID, "owner", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := propose(bob, evidence); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("PG revoked artifact evidence error=%v, want generic unavailable", err)
	}
}

func TestPgLibraryConsoleMemoryPageStableKeyset(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library memory integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	suffix := newPgFixtureSuffix()
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG paged memory " + suffix, Subject: "usr_pg_paged_memory_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_memories WHERE agent_surface_id=$1`, client.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
	})
	stamp := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	// Exercise byte-order differences from locale collation on every run.
	idSuffixes := []string{"a", "Z", "_", "A", "z", "-", "0", "9", "AA", "aA"}
	expected := make([]string, 0, len(idSuffixes))
	wanted := make(map[string]struct{}, len(idSuffixes))
	for _, idSuffix := range idSuffixes {
		memory, _, err := store.CreateLibraryMemoryWithInitialVersion(ctx, LibraryMemory{
			Kind: LibraryMemoryKindFact, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
			ID:             "libmem_page_" + suffix + "_" + idSuffix,
			AgentSurfaceID: client.ID, CreatedBy: "owner", CreatedAt: stamp,
		}, LibraryMemoryVersion{Content: "PG paged memory content", CreatedBy: "owner", CreatedAt: stamp})
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, memory.ID)
		wanted[memory.ID] = struct{}{}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(expected)))
	seen := make([]string, 0, len(expected))
	seenSet := make(map[string]struct{})
	var cursor LibraryConsolePageCursor
	for pageNumber := 0; pageNumber < 1000; pageNumber++ {
		page, err := store.LibraryConsoleMemoryPage(ctx, cursor, 2)
		if err != nil || len(page.Memories) > 2 {
			t.Fatalf("PG page=%+v err=%v", page, err)
		}
		for _, memory := range page.Memories {
			if _, ours := wanted[memory.ID]; !ours {
				continue
			}
			if _, duplicate := seenSet[memory.ID]; duplicate {
				t.Fatalf("PG duplicate memory across pages: %s", memory.ID)
			}
			seenSet[memory.ID] = struct{}{}
			seen = append(seen, memory.ID)
			if memory.Preview != "PG paged memory content" {
				t.Fatalf("PG bounded preview=%q", memory.Preview)
			}
		}
		if page.NextCursor.ID == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(expected) {
		t.Fatalf("PG paged IDs=%v want=%v", seen, expected)
	}
	for index := range expected {
		if seen[index] != expected[index] {
			t.Fatalf("PG paged IDs=%v want stable order=%v", seen, expected)
		}
	}
}

func TestPgLibraryMemoryCrossedSupersessionDoesNotDeadlockOrCycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library memory integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	suffix := newPgFixtureSuffix()
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG crossed supersession " + suffix, Subject: "usr_pg_crossed_" + suffix, CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	a, aVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Decision A", time.Time{})
	b, bVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Decision B", time.Time{})
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_memories WHERE agent_surface_id=$1`, client.ID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	run := func(memory LibraryMemory, version LibraryMemoryVersion, replacement LibraryMemory) {
		ready.Done()
		<-start
		_, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(version.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, replacement.ID, "owner", time.Now().UTC()))
		results <- err
	}
	go run(a, aVersion, b)
	go run(b, bVersion, a)
	ready.Wait()
	close(start)
	firstErr, secondErr := <-results, <-results
	for _, reviewErr := range []error{firstErr, secondErr} {
		var pgErr *pgconn.PgError
		if errors.As(reviewErr, &pgErr) && pgErr.Code == "40P01" {
			t.Fatalf("crossed supersession deadlocked: %v / %v", firstErr, secondErr)
		}
	}
	if firstErr == nil && secondErr == nil {
		t.Fatalf("crossed supersession created two successful reviews")
	}
	loadedA, foundA := store.LibraryMemory(ctx, a.ID)
	loadedB, foundB := store.LibraryMemory(ctx, b.ID)
	if !foundA || !foundB || (loadedA.SupersededByMemoryID == b.ID && loadedB.SupersededByMemoryID == a.ID) {
		t.Fatalf("crossed supersession left a cycle: A=%+v B=%+v", loadedA, loadedB)
	}
}
