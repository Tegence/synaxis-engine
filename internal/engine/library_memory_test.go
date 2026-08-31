package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func createMemoryTestClient(t *testing.T, store *FileStore, name, subject string) MCPClient {
	t.Helper()
	client, err := store.CreateMCPClient(context.Background(), MCPClient{Name: name, Subject: subject, CreatedBy: "owner"})
	if err != nil {
		t.Fatalf("CreateMCPClient(%s): %v", name, err)
	}
	return client
}

func libraryMemoryReviewForTest(versionID, state, trust string, expiresAt, reviewAfter time.Time, supersededBy, reviewedBy string, reviewedAt time.Time) LibraryMemoryReview {
	return LibraryMemoryReview{
		MemoryVersionID: versionID, State: state, Trust: trust,
		ExpiresAt: &expiresAt, ReviewAfter: &reviewAfter, SupersededByMemoryID: supersededBy,
		ReviewedBy: reviewedBy, ReviewedAt: reviewedAt,
	}
}

func createActiveMemoryForTest(t *testing.T, store LibraryMemoryStore, client MCPClient, kind, content string, expiresAt time.Time) (LibraryMemory, LibraryMemoryVersion) {
	t.Helper()
	memory, version, err := store.CreateLibraryMemoryWithInitialVersion(context.Background(), LibraryMemory{
		Kind: kind, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
		AgentSurfaceID: client.ID, CreatedBy: "owner", ExpiresAt: expiresAt,
	}, LibraryMemoryVersion{Content: content, CreatedBy: "owner"})
	if err != nil {
		t.Fatalf("CreateLibraryMemoryWithInitialVersion: %v", err)
	}
	memory, err = store.ReviewLibraryMemory(context.Background(), memory.ID, libraryMemoryReviewForTest(version.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, expiresAt, time.Time{}, "", "owner", time.Now().UTC()))
	if err != nil {
		t.Fatalf("ReviewLibraryMemory: %v", err)
	}
	return memory, version
}

func TestFileLibraryMemoryLifecycleIsolationGrantExpiryCorrectionAndForget(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/store.json"
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	alice := createMemoryTestClient(t, store, "Alice memory", "usr_alice_memory")
	bob := createMemoryTestClient(t, store, "Bob memory", "usr_bob_memory")

	memory, first, err := store.CreateLibraryMCPClientMemoryProposal(ctx, alice, LibraryMemory{
		Kind: LibraryMemoryKindDecision,
	}, LibraryMemoryVersion{Content: "Use the versioned gateway contract."})
	if err != nil {
		t.Fatal(err)
	}
	if memory.AgentSurfaceID != alice.ID || memory.CreatedBy != alice.Subject || memory.State != LibraryMemoryStateProposed || memory.Trust != LibraryMemoryTrustAgentObserved || first.CreatedBy != alice.Subject {
		t.Fatalf("proposal was not endpoint-derived: memory=%+v version=%+v", memory, first)
	}
	if got, err := store.LibraryMemoryRecallSelections(ctx, alice, time.Now().UTC()); err != nil || len(got) != 0 {
		t.Fatalf("proposed memory recalled: selections=%+v err=%v", got, err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("proposed memory grant error=%v, want %v", err, ErrLibraryMemoryGrantIneligible)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateProposed, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err == nil {
		t.Fatal("review restored a memory to proposed")
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateActive, LibraryMemoryTrustHostAttested, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err == nil {
		t.Fatal("administrator review minted host_attested trust")
	}
	memory, err = store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateDisputed, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("disputed memory grant error=%v, want %v", err, ErrLibraryMemoryGrantIneligible)
	}
	memory, err = store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(first.ID, LibraryMemoryStateActive, LibraryMemoryTrustWorkspaceApproved, time.Time{}, time.Time{}, "", "owner", time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.LibraryMemoryRecallSelections(ctx, alice, time.Now().UTC()); err != nil || len(got) != 1 || got[0].Version.ID != first.ID || got[0].Access != LibraryMemoryAccessOwnSurface {
		t.Fatalf("owner recall=%+v err=%v", got, err)
	}
	if got, err := store.LibraryMemoryRecallSelections(ctx, bob, time.Now().UTC()); err != nil || len(got) != 0 {
		t.Fatalf("ungranted cross-surface recall=%+v err=%v", got, err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: alice.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantOwner) {
		t.Fatalf("owner grant error=%v want %v", err, ErrLibraryMemoryGrantOwner)
	}
	grant, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.LibraryMemoryRecallSelections(ctx, bob, time.Now().UTC()); err != nil || len(got) != 1 || got[0].Version.ID != first.ID || got[0].Access != LibraryMemoryAccessGranted {
		t.Fatalf("granted recall=%+v err=%v", got, err)
	}

	corrected, second, err := store.CreateLibraryMemoryVersion(ctx, memory.ID, LibraryMemoryVersion{Content: "Use control contract v2."}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if corrected.State != LibraryMemoryStateProposed || corrected.Trust != LibraryMemoryTrustHumanConfirmed || second.Version != 2 {
		t.Fatalf("correction did not reset review: memory=%+v version=%+v", corrected, second)
	}
	grants, err := store.LibraryMemoryGrants(ctx, memory.ID)
	if err != nil || len(grants) != 1 || grants[0].ID != grant.ID || grants[0].RevokedBy != "owner" || !grants[0].RevokedAt.Equal(second.CreatedAt) {
		t.Fatalf("correction did not atomically preserve+revoke old grant: grants=%+v err=%v", grants, err)
	}
	for _, client := range []MCPClient{alice, bob} {
		if got, err := store.LibraryMemoryRecallSelections(ctx, client, time.Now().UTC()); err != nil || len(got) != 0 {
			t.Fatalf("proposed correction recalled by %s: %+v err=%v", client.ID, got, err)
		}
	}
	corrected, err = store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := store.LibraryMemoryRecallSelections(ctx, alice, time.Now().UTC()); len(got) != 1 || got[0].Version.ID != second.ID {
		t.Fatalf("owner correction recall=%+v", got)
	}
	if got, _ := store.LibraryMemoryRecallSelections(ctx, bob, time.Now().UTC()); len(got) != 0 {
		t.Fatalf("v2 approval reactivated stale v1 grant: %+v", got)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: first.ID, MemoryVersionDigest: first.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("non-current v1 grant error=%v, want %v", err, ErrLibraryMemoryGrantIneligible)
	}
	secondGrant, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: second.ID, MemoryVersionDigest: second.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := store.LibraryMemoryRecallSelections(ctx, bob, time.Now().UTC()); len(got) != 1 || got[0].Version.ID != second.ID {
		t.Fatalf("new current-head grant recall=%+v", got)
	}
	if _, err := store.RevokeLibraryMemoryGrant(ctx, memory.ID, secondGrant.ID, "owner", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, corrected.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateExpired, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: second.ID, MemoryVersionDigest: second.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("expired-state memory grant error=%v, want %v", err, ErrLibraryMemoryGrantIneligible)
	}

	past := time.Now().UTC().Add(-time.Minute)
	if _, err := store.ReviewLibraryMemory(ctx, corrected.ID, libraryMemoryReviewForTest(second.ID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, past, time.Time{}, "", "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryMemoryGrant(ctx, LibraryMemoryGrant{
		MemoryID: memory.ID, MemoryVersionID: second.ID, MemoryVersionDigest: second.Digest, AgentSurfaceID: bob.ID, CreatedBy: "owner",
	}); !errors.Is(err, ErrLibraryMemoryGrantIneligible) {
		t.Fatalf("effectively expired memory grant error=%v, want %v", err, ErrLibraryMemoryGrantIneligible)
	}
	if got, _ := store.LibraryMemoryRecallSelections(ctx, alice, time.Now().UTC()); len(got) != 0 {
		t.Fatalf("expired memory recalled=%+v", got)
	}
	if selection, found, err := store.LibraryMemoryReadSelection(ctx, alice, memory.ID, second.ID, time.Time{}); err != nil || found {
		t.Fatalf("zero-now exact read returned expired memory: selection=%+v found=%t err=%v", selection, found, err)
	}

	if err := store.ForgetLibraryMemory(ctx, memory.ID); err != nil {
		t.Fatal(err)
	}
	if _, found := store.LibraryMemory(ctx, memory.ID); found {
		t.Fatal("forgotten logical memory remains")
	}
	if _, err := store.LibraryMemoryVersions(ctx, memory.ID); !errors.Is(err, ErrLibraryMemoryNotFound) {
		t.Fatalf("forgotten versions error=%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), first.Content) || strings.Contains(string(raw), second.Content) || strings.Contains(string(raw), first.ID) || strings.Contains(string(raw), grant.ID) || strings.Contains(string(raw), secondGrant.ID) {
		t.Fatalf("forgotten content/version/grant remains in FileStore: %s", raw)
	}
	reloaded, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if page, err := reloaded.LibraryConsoleMemoryPage(ctx, LibraryConsolePageCursor{}, 10); err != nil || len(page.Memories) != 0 {
		t.Fatalf("reloaded forgotten memories=%+v err=%v", page.Memories, err)
	}
}

func TestFileLibraryMemoryProposalEvidenceIsBoundToExactClientSurface(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	alice := createMemoryTestClient(t, store, "Alice evidence", "usr_alice_evidence")
	bob := createMemoryTestClient(t, store, "Bob evidence", "usr_bob_evidence")

	run, artifact, artifactVersion, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, alice, LibraryArtifact{
		Title: "Alice evidence", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "private evidence"})
	if err != nil {
		t.Fatal(err)
	}
	propose := func(client MCPClient, source LibraryMemoryVersion) error {
		source.Content = "Evidence-bound observation."
		_, _, err := store.CreateLibraryMCPClientMemoryProposal(ctx, client, LibraryMemory{Kind: LibraryMemoryKindFact}, source)
		return err
	}

	if err := propose(bob, LibraryMemoryVersion{SourceRunID: run.ID}); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("cross-surface run evidence error=%v, want generic unavailable", err)
	}
	if err := propose(alice, LibraryMemoryVersion{SourceRunID: run.ID}); err != nil {
		t.Fatalf("owner run evidence: %v", err)
	}
	nonDirectRun, err := store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginHuman, ActorRef: alice.Subject, SurfaceRef: alice.ID, Status: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := propose(alice, LibraryMemoryVersion{SourceRunID: nonDirectRun.ID}); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("non-direct run evidence error=%v, want generic unavailable", err)
	}
	evidence := LibraryMemoryVersion{
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: artifactVersion.ID, SourceDigest: artifactVersion.Digest,
	}
	if err := propose(bob, evidence); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("ungranted artifact evidence error=%v, want generic unavailable", err)
	}
	if err := propose(alice, evidence); err != nil {
		t.Fatalf("owner artifact evidence: %v", err)
	}
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: artifactVersion.ID, ArtifactVersionDigest: artifactVersion.Digest,
		AgentSurfaceID: bob.ID, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := propose(bob, evidence); err != nil {
		t.Fatalf("granted artifact evidence: %v", err)
	}
	if _, err := store.RevokeLibraryArtifactGrant(ctx, artifact.ID, grant.ID, "owner", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := propose(bob, evidence); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("revoked artifact evidence error=%v, want generic unavailable", err)
	}
	if err := propose(bob, LibraryMemoryVersion{
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: artifactVersion.ID, SourceDigest: libraryDigest("wrong"),
	}); !errors.Is(err, ErrLibraryMemoryEvidenceUnavailable) {
		t.Fatalf("mismatched artifact evidence error=%v, want generic unavailable", err)
	}

	page, err := store.LibraryConsoleMemoryPage(ctx, LibraryConsolePageCursor{}, 10)
	if err != nil || len(page.Memories) != 3 {
		t.Fatalf("failed proposals mutated store: memories=%+v err=%v", page.Memories, err)
	}
}

func TestFileLibraryMemoryForgetExpiresIncomingSupersessionReferences(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createMemoryTestClient(t, store, "Supersession memory", "usr_supersession_memory")
	older, olderVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Use the older design.", time.Time{})
	replacement, _ := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Use the replacement design.", time.Time{})
	proposed, _, err := store.CreateLibraryMemoryWithInitialVersion(ctx, LibraryMemory{
		Kind: LibraryMemoryKindDecision, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
		AgentSurfaceID: client.ID, CreatedBy: "owner",
	}, LibraryMemoryVersion{Content: "Still proposed.", CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	disputed, disputedVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Disputed replacement.", time.Time{})
	if _, err := store.ReviewLibraryMemory(ctx, disputed.ID, libraryMemoryReviewForTest(disputedVersion.ID, LibraryMemoryStateDisputed, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	expired, expiredVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Expired replacement.", time.Time{})
	if _, err := store.ReviewLibraryMemory(ctx, expired.ID, libraryMemoryReviewForTest(expiredVersion.ID, LibraryMemoryStateExpired, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	temporallyExpired, _ := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Stale replacement.", time.Now().UTC().Add(-time.Minute))
	superseded, supersededVersion := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Already superseded.", time.Time{})
	anchor, _ := createActiveMemoryForTest(t, store, client, LibraryMemoryKindDecision, "Anchor replacement.", time.Time{})
	if _, err := store.ReviewLibraryMemory(ctx, superseded.ID, libraryMemoryReviewForTest(supersededVersion.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, anchor.ID, "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	for _, ineligible := range []LibraryMemory{proposed, disputed, expired, temporallyExpired, superseded} {
		if _, err := store.ReviewLibraryMemory(ctx, older.ID, libraryMemoryReviewForTest(olderVersion.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, ineligible.ID, "owner", time.Now().UTC())); !errors.Is(err, ErrLibraryMemorySupersessionIneligible) {
			t.Fatalf("ineligible replacement state=%s id=%s error=%v", ineligible.State, ineligible.ID, err)
		}
	}

	older, err = store.ReviewLibraryMemory(ctx, older.ID, libraryMemoryReviewForTest(olderVersion.ID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, replacement.ID, "owner", time.Now().UTC()))
	if err != nil || older.SupersededByMemoryID != replacement.ID {
		t.Fatalf("supersede memory=%+v err=%v", older, err)
	}
	if _, err := store.ReviewLibraryMemory(ctx, replacement.ID, libraryMemoryReviewForTest(replacement.CurrentVersionID, LibraryMemoryStateSuperseded, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, older.ID, "owner", time.Now().UTC())); !errors.Is(err, ErrLibraryMemorySupersessionIneligible) {
		t.Fatalf("sequential supersession cycle error=%v", err)
	}
	if err := store.ForgetLibraryMemory(ctx, replacement.ID); err != nil {
		t.Fatal(err)
	}
	older, found := store.LibraryMemory(ctx, older.ID)
	if !found || older.State != LibraryMemoryStateExpired || older.SupersededByMemoryID != "" {
		t.Fatalf("incoming supersession reference survived forget: memory=%+v found=%t", older, found)
	}
	if _, found := store.LibraryMemoryVersion(ctx, older.ID, olderVersion.ID); !found {
		t.Fatal("forget removed the referring memory's own immutable content")
	}
	selections, err := store.LibraryMemoryRecallSelections(ctx, client, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range selections {
		if selection.Memory.ID == older.ID {
			t.Fatalf("expired superseded referrer was recalled: selections=%+v", selections)
		}
	}
}

func TestFileLibraryConsoleMemoryPageStableKeyset(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := createMemoryTestClient(t, store, "Paged memory", "usr_paged_memory")
	stamp := time.Date(2026, 8, 31, 9, 30, 0, 0, time.UTC)
	expected := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		memory, _, err := store.CreateLibraryMemoryWithInitialVersion(ctx, LibraryMemory{
			Kind: LibraryMemoryKindFact, State: LibraryMemoryStateProposed, Trust: LibraryMemoryTrustHumanConfirmed,
			AgentSurfaceID: client.ID, CreatedBy: "owner", CreatedAt: stamp,
		}, LibraryMemoryVersion{Content: "paged memory content", CreatedBy: "owner", CreatedAt: stamp})
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, memory.ID)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(expected)))
	seen := make([]string, 0, len(expected))
	seenSet := make(map[string]struct{})
	var cursor LibraryConsolePageCursor
	for {
		page, err := store.LibraryConsoleMemoryPage(ctx, cursor, 2)
		if err != nil || len(page.Memories) > 2 {
			t.Fatalf("page=%+v err=%v", page, err)
		}
		for _, memory := range page.Memories {
			if _, duplicate := seenSet[memory.ID]; duplicate {
				t.Fatalf("duplicate memory across keyset pages: %s", memory.ID)
			}
			seenSet[memory.ID] = struct{}{}
			seen = append(seen, memory.ID)
			if memory.Preview != "paged memory content" {
				t.Fatalf("bounded page preview=%q", memory.Preview)
			}
		}
		if page.NextCursor.ID == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(expected) {
		t.Fatalf("paged IDs=%v want=%v", seen, expected)
	}
	for index := range expected {
		if seen[index] != expected[index] {
			t.Fatalf("paged IDs=%v want stable order=%v", seen, expected)
		}
	}
}

func TestLibraryMemoryRecallBundleBudgetDigestAndFailClosedAccess(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	client := MCPClient{ID: "mcpcl_memory_bundle", Subject: "usr_memory_bundle", Epoch: "epoch"}
	selection := func(id, content, trust string, updated time.Time) LibraryMemorySelection {
		version := LibraryMemoryVersion{ID: "libmemv_" + id, MemoryID: "libmem_" + id, Version: 1, Content: content, Digest: libraryDigest(content), CreatedAt: updated}
		return LibraryMemorySelection{Memory: LibraryMemory{
			ID: version.MemoryID, Kind: LibraryMemoryKindFact, State: LibraryMemoryStateActive, Trust: trust,
			AgentSurfaceID: client.ID, CurrentVersionID: version.ID, CurrentVersionDigest: version.Digest,
			CreatedAt: updated, UpdatedAt: updated,
		}, Version: version, Access: LibraryMemoryAccessOwnSurface}
	}
	large := selection("large", "target "+strings.Repeat("x", 3000), LibraryMemoryTrustWorkspaceApproved, now)
	small := selection("small", "target compact", LibraryMemoryTrustHumanConfirmed, now.Add(-time.Second))
	input := libraryMemoryRecallInput{Query: "target", Limit: 20, MaxBytes: 1024}
	bundle, err := buildLibraryMemoryRecallBundle(client, input, []LibraryMemorySelection{small, large}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Truncated || len(bundle.Memories) != 1 || bundle.Memories[0].MemoryID != small.Memory.ID {
		t.Fatalf("budgeted bundle=%+v", bundle)
	}
	again, err := buildLibraryMemoryRecallBundle(client, input, []LibraryMemorySelection{large, small}, now)
	if err != nil || again.BundleDigest != bundle.BundleDigest {
		t.Fatalf("bundle digest is not deterministic: first=%q second=%q err=%v", bundle.BundleDigest, again.BundleDigest, err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > input.MaxBytes {
		t.Fatalf("bundle size=%d err=%v max=%d", len(encoded), err, input.MaxBytes)
	}
	invalid := small
	invalid.Access = "caller_claimed"
	if _, err := buildLibraryMemoryRecallBundle(client, libraryMemoryRecallInput{Limit: 5, MaxBytes: 4096}, []LibraryMemorySelection{invalid}, now); err == nil {
		t.Fatal("custom-store selection with unknown access mode was emitted")
	}
}

func TestMCPClientMemoryToolsAreSurfaceBoundAndAbsentFromRoot(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	alice := createMemoryTestClient(t, store, "Alice MCP memory", "usr_alice_mcp_memory")
	bob := createMemoryTestClient(t, store, "Bob MCP memory", "usr_bob_mcp_memory")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	aliceMCP := clientLibraryServer(t, gateway, alice.Slug)
	for _, tool := range mcpClientMemoryToolNames {
		if _, found := aliceMCP.ListTools()[tool]; !found {
			t.Fatalf("client endpoint omitted %s", tool)
		}
		if _, found := gateway.mcp.ListTools()[tool]; found {
			t.Fatalf("root MCP exposed client-only %s", tool)
		}
	}
	proposedRaw := callLibraryTool(t, aliceMCP, "library_memory_propose", map[string]any{
		"kind": LibraryMemoryKindConstraint, "content": "Engine code remains tenant-blind.",
		"agentSurfaceId": bob.ID, "trust": LibraryMemoryTrustWorkspaceApproved,
	})
	if strings.Contains(proposedRaw, `"isError":true`) {
		t.Fatalf("proposal response=%s", proposedRaw)
	}
	var proposed struct {
		MemoryID        string `json:"memoryId"`
		MemoryVersionID string `json:"memoryVersionId"`
		State           string `json:"state"`
		Trust           string `json:"trust"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, proposedRaw)), &proposed); err != nil {
		t.Fatal(err)
	}
	memory, found := store.LibraryMemory(ctx, proposed.MemoryID)
	if !found || memory.AgentSurfaceID != alice.ID || memory.CreatedBy != alice.Subject || proposed.State != LibraryMemoryStateProposed || proposed.Trust != LibraryMemoryTrustAgentObserved {
		t.Fatalf("MCP proposal accepted caller identity/trust: memory=%+v response=%+v", memory, proposed)
	}
	if _, err := store.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(proposed.MemoryVersionID, LibraryMemoryStateActive, LibraryMemoryTrustHumanConfirmed, time.Time{}, time.Time{}, "", "owner", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	recallRaw := callLibraryTool(t, aliceMCP, "library_memory_recall", map[string]any{"query": "tenant blind", "limit": 5, "maxBytes": 4096})
	if strings.Contains(recallRaw, `"isError":true`) {
		t.Fatalf("recall response=%s", recallRaw)
	}
	var bundle LibraryMemoryRecallBundle
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, recallRaw)), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Contract != libraryMemoryContract || bundle.AgentSurface.ID != alice.ID || len(bundle.Memories) != 1 || bundle.Memories[0].MemoryID != memory.ID || bundle.BundleDigest == "" || bundle.ConflictPolicy != libraryMemoryConflictPolicy {
		t.Fatalf("recall bundle=%+v", bundle)
	}
	bobMCP := clientLibraryServer(t, gateway, bob.Slug)
	if got := callLibraryTool(t, bobMCP, "library_memory_recall", map[string]any{"query": "tenant"}); strings.Contains(got, memory.ID) || strings.Contains(got, "tenant-blind") {
		t.Fatalf("other surface recalled private memory: %s", got)
	}
	_, evidenceArtifact, evidenceVersion, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, alice, LibraryArtifact{
		Title: "Alice-only memory evidence", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "private source"})
	if err != nil {
		t.Fatal(err)
	}
	deniedEvidence := callLibraryTool(t, bobMCP, "library_memory_propose", map[string]any{
		"kind": LibraryMemoryKindFact, "content": "I should not be able to cite this.",
		"sourceArtifactId": evidenceArtifact.ID, "sourceArtifactVersionId": evidenceVersion.ID, "sourceDigest": evidenceVersion.Digest,
	})
	if !strings.Contains(deniedEvidence, "memory evidence is unavailable") || strings.Contains(deniedEvidence, "artifact not found") {
		t.Fatalf("cross-surface proposal leaked evidence lookup details: %s", deniedEvidence)
	}
	read := callLibraryTool(t, aliceMCP, "library_memory_read", map[string]any{"memoryId": memory.ID, "memoryVersionId": proposed.MemoryVersionID})
	if !strings.Contains(read, "tenant-blind") || !strings.Contains(read, libraryMemoryAuthorityNotice) {
		t.Fatalf("exact memory read=%s", read)
	}
	if got := callLibraryTool(t, aliceMCP, "library_memory_read", map[string]any{"memoryId": memory.ID, "memoryVersionId": "libmemv_wrong"}); !strings.Contains(got, "memory not found") {
		t.Fatalf("non-exact memory read=%s", got)
	}
}

type libraryMemoryNoPrereadStore struct {
	*FileStore
	memoryReads int
}

func (s *libraryMemoryNoPrereadStore) LibraryMemory(ctx context.Context, id string) (LibraryMemory, bool) {
	s.memoryReads++
	return s.FileStore.LibraryMemory(ctx, id)
}

func TestLibraryMemoryReviewOmissionPreservesTransactionalFreshnessWithoutPreread(t *testing.T) {
	ctx := context.Background()
	fileStore := newLibraryFileStore(t)
	store := &libraryMemoryNoPrereadStore{FileStore: fileStore}
	api := NewConsoleAPI(store, nil, nil, "pw", "memory-review-secret", "https://engine.example", "https://console.example", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	client := createMemoryTestClient(t, fileStore, "Freshness memory", "usr_freshness_memory")
	initialExpiry := time.Now().UTC().Add(time.Hour)
	memory, version := createActiveMemoryForTest(t, fileStore, client, LibraryMemoryKindFact, "Freshness must not be lost.", initialExpiry)
	updatedExpiry := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	updatedReviewAfter := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	if _, err := fileStore.ReviewLibraryMemory(ctx, memory.ID, libraryMemoryReviewForTest(version.ID, LibraryMemoryStateDisputed, LibraryMemoryTrustHumanConfirmed, updatedExpiry, updatedReviewAfter, "", "interleaving-reviewer", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	store.memoryReads = 0
	body, _ := json.Marshal(map[string]any{
		"memoryVersionId": version.ID, "state": LibraryMemoryStateActive, "trust": LibraryMemoryTrustHumanConfirmed,
	})
	recorder, response := doJSON(t, mux, api.signToken(), http.MethodPost, "/api/library/memories/"+memory.ID+"/review", string(body))
	if recorder.Code != http.StatusOK || store.memoryReads != 0 {
		t.Fatalf("review status=%d prereads=%d body=%s", recorder.Code, store.memoryReads, recorder.Body)
	}
	if response["expiresAt"] != updatedExpiry.Format(time.RFC3339) || response["reviewAfter"] != updatedReviewAfter.Format(time.RFC3339) {
		t.Fatalf("omitted freshness overwrote interleaved values: response=%v", response)
	}
}

func TestLibraryMemoryConsoleReviewFreshnessPreviewPaginationAndForget(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	client := createMemoryTestClient(t, store, "Console memory", "usr_console_memory")
	expiresAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	reviewAfter := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	content := strings.Repeat("é", 170)
	body, _ := json.Marshal(map[string]any{
		"kind": LibraryMemoryKindPreference, "content": content, "agentSurfaceId": client.ID,
		"expiresAt": expiresAt, "reviewAfter": reviewAfter,
	})
	createdRecorder, created := doJSON(t, mux, token, http.MethodPost, "/api/library/memories", string(body))
	if createdRecorder.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createdRecorder.Code, createdRecorder.Body)
	}
	if got := createdRecorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("private memory response Cache-Control=%q, want no-store", got)
	}
	memoryMap := created["memory"].(map[string]any)
	versionMap := created["version"].(map[string]any)
	memoryID, versionID := memoryMap["id"].(string), versionMap["id"].(string)
	listRecorder, rows := doLibraryConsoleList(t, mux, token, "/api/library/memories", map[string]string{libraryConsolePageLimitHeader: "1"})
	if listRecorder.Code != http.StatusOK || len(rows) != 1 {
		t.Fatalf("memory list status=%d rows=%v body=%s", listRecorder.Code, rows, listRecorder.Body)
	}
	preview, _ := rows[0]["preview"].(string)
	if got := []rune(preview); len(got) != 161 || got[160] != '…' {
		t.Fatalf("UTF-8 preview=%q runes=%d", preview, len(got))
	}
	for _, invalid := range []map[string]any{
		{"memoryVersionId": versionID, "state": LibraryMemoryStateProposed, "trust": LibraryMemoryTrustHumanConfirmed},
		{"memoryVersionId": versionID, "state": LibraryMemoryStateActive, "trust": LibraryMemoryTrustHostAttested},
		{"memoryVersionId": versionID, "state": LibraryMemoryStateActive, "trust": LibraryMemoryTrustAgentObserved},
	} {
		invalidBody, _ := json.Marshal(invalid)
		recorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/memories/"+memoryID+"/review", string(invalidBody))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid review %v status=%d body=%s", invalid, recorder.Code, recorder.Body)
		}
	}
	reviewBody, _ := json.Marshal(map[string]any{"memoryVersionId": versionID, "state": LibraryMemoryStateActive, "trust": LibraryMemoryTrustWorkspaceApproved})
	reviewRecorder, reviewed := doJSON(t, mux, token, http.MethodPost, "/api/library/memories/"+memoryID+"/review", string(reviewBody))
	if reviewRecorder.Code != http.StatusOK || reviewed["expiresAt"] != expiresAt.Format(time.RFC3339) || reviewed["reviewAfter"] != reviewAfter.Format(time.RFC3339) {
		t.Fatalf("review did not preserve freshness: status=%d response=%v", reviewRecorder.Code, reviewed)
	}
	correctRecorder, corrected := doJSON(t, mux, token, http.MethodPost, "/api/library/memories/"+memoryID+"/versions", `{"content":"corrected preference"}`)
	if correctRecorder.Code != http.StatusCreated || corrected["memory"].(map[string]any)["state"] != LibraryMemoryStateProposed {
		t.Fatalf("correction status=%d response=%v", correctRecorder.Code, corrected)
	}
	staleRecorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/memories/"+memoryID+"/review", string(reviewBody))
	if staleRecorder.Code != http.StatusConflict {
		t.Fatalf("stale review status=%d body=%s", staleRecorder.Code, staleRecorder.Body)
	}
	forgetRecorder, _ := doJSON(t, mux, token, http.MethodDelete, "/api/library/memories/"+memoryID, "")
	if forgetRecorder.Code != http.StatusNoContent {
		t.Fatalf("forget status=%d body=%s", forgetRecorder.Code, forgetRecorder.Body)
	}
	detailRecorder, _ := doJSON(t, mux, token, http.MethodGet, "/api/library/memories/"+memoryID, "")
	if detailRecorder.Code != http.StatusNotFound {
		t.Fatalf("forgotten detail status=%d body=%s", detailRecorder.Code, detailRecorder.Body)
	}
	if _, err := store.LibraryMemoryVersions(ctx, memoryID); !errors.Is(err, ErrLibraryMemoryNotFound) {
		t.Fatalf("forgotten console memory versions error=%v", err)
	}
}
