package engine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newLibraryFileStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "library.json"))
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}
	return store
}

func createLibrarySkillForTest(t *testing.T, store LibraryStore) (LibrarySkill, LibrarySkillVersion) {
	t.Helper()
	skill, version, err := store.CreateLibrarySkillWithInitialVersion(context.Background(), LibrarySkill{
		Slug: "incident-triage", Name: "Incident triage", Description: "Resolve incidents", CreatedBy: "actor-a",
	}, LibrarySkillVersion{Content: "# Triage\nInspect the incident before acting.", RequestedCapabilities: []string{"tickets.read", "alerts.read"}, CreatedBy: "actor-a"})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion: %v", err)
	}
	return skill, version
}

func TestLibraryFileStorePortableVersionsAndNamespaceBinding(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, first := createLibrarySkillForTest(t, store)
	if first.Version != 1 || first.Digest != libraryDigest(first.Content) {
		t.Fatalf("initial version = %+v", first)
	}
	second, err := store.CreateLibrarySkillVersion(context.Background(), LibrarySkillVersion{
		SkillID: skill.ID, Content: "# Triage v2\nEscalate only after verifying impact.", RequestedCapabilities: []string{"alerts.read", "tickets.read"}, CreatedBy: "actor-b",
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillVersion: %v", err)
	}
	if second.Version != 2 || second.ID == first.ID {
		t.Fatalf("second immutable version = %+v", second)
	}
	versions, err := store.LibrarySkillVersions(context.Background(), skill.ID)
	if err != nil || len(versions) != 2 || versions[0].Content == versions[1].Content {
		t.Fatalf("versions = %#v, err=%v", versions, err)
	}

	binding, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "scope_engineering", Mode: LibraryBindingModePin,
		PinnedVersionID: first.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "actor-a",
	})
	if err != nil {
		t.Fatalf("namespace binding: %v", err)
	}
	if binding.ScopeKind != LibraryScopeNamespace || binding.PinnedVersionID != first.ID {
		t.Fatalf("binding = %+v", binding)
	}
	if _, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: "connection_namespace", ScopeID: "secret-folder", Mode: LibraryBindingModeTrack,
	}); err == nil {
		t.Fatal("connection namespace was accepted as a Library scope")
	}
	got := ResolveLibraryCapabilities([]string{"alerts.read", "tickets.read"}, binding.CapabilityCeiling, []string{"alerts.read", "tickets.read", "write"})
	if len(got) != 1 || got[0] != "alerts.read" {
		t.Fatalf("effective capabilities = %v, want [alerts.read]", got)
	}
}

func TestLibraryFileStoreSkillVersionRefreshesConsoleTimestampAndOrder(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	older, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "older-skill", Name: "Older skill", CreatedBy: "actor-a",
	}, LibrarySkillVersion{Content: "# Older", CreatedBy: "actor-a"})
	if err != nil {
		t.Fatalf("create older skill: %v", err)
	}
	if _, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "newer-skill", Name: "Newer skill", CreatedBy: "actor-a",
	}, LibrarySkillVersion{Content: "# Newer", CreatedBy: "actor-a"}); err != nil {
		t.Fatalf("create newer skill: %v", err)
	}

	// A supplied timestamp keeps this regression test deterministic while
	// exercising the same immutable-version path used by Console and MCP
	// authors. The skill row's timestamp must move in the same FileStore save.
	writtenAt := time.Now().UTC().Add(time.Hour)
	version, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: older.ID, Content: "# Older, revised", CreatedBy: "actor-a", CreatedAt: writtenAt,
	})
	if err != nil {
		t.Fatalf("create revised version: %v", err)
	}
	if !version.CreatedAt.Equal(writtenAt) {
		t.Fatalf("version timestamp = %s, want %s", version.CreatedAt, writtenAt)
	}
	refreshed, found := store.LibrarySkill(ctx, older.ID)
	if !found || !refreshed.UpdatedAt.Equal(writtenAt) {
		t.Fatalf("refreshed skill = %+v, found=%v; want updatedAt %s", refreshed, found, writtenAt)
	}
	page, err := store.LibraryConsoleSkillPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(page.Skills) != 1 || page.Skills[0].Skill.ID != older.ID {
		t.Fatalf("Console skill page = %+v, err=%v; want revised skill first", page, err)
	}
}

func TestLibraryDirectArtifactProvenanceAndPublicationCandidate(t *testing.T) {
	store := newLibraryFileStore(t)
	run, err := store.CreateLibraryRun(context.Background(), LibraryRun{
		Origin: LibraryRunOriginAgentDirect, ActorRef: "agent-opaque", SurfaceRef: "mcp-client", Status: "succeeded", EffectiveCapabilities: []string{"artifact.write"},
	})
	if err != nil {
		t.Fatalf("CreateLibraryRun: %v", err)
	}
	if run.SkillID != "" || run.BindingID != "" {
		t.Fatalf("direct run claimed a skill: %+v", run)
	}
	artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Incident summary", Summary: "Sanitized incident notes", Origin: LibraryArtifactOriginAgentDirect, RunID: run.ID, CreatedBy: "agent-opaque",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Summary\nNo secrets."})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactWithInitialVersion: %v", err)
	}
	if artifact.SkillID != "" || version.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("direct artifact = %+v / %+v", artifact, version)
	}
	if _, err := store.LibraryPublicationCandidate(context.Background(), artifact.ID); !errors.Is(err, ErrLibraryPublicationNotReady) {
		t.Fatalf("unreviewed candidate error = %v, want publication not ready", err)
	}
	approved, err := store.ReviewLibraryArtifactVersion(context.Background(), artifact.ID, version.ID, LibraryRedactionApproved, "reviewer-opaque", timeNowForTest(t))
	if err != nil {
		t.Fatalf("ReviewLibraryArtifactVersion: %v", err)
	}
	candidate, err := store.LibraryPublicationCandidate(context.Background(), artifact.ID)
	if err != nil {
		t.Fatalf("LibraryPublicationCandidate: %v", err)
	}
	if candidate.Body != version.Body || candidate.RedactionStatus != LibraryRedactionApproved || candidate.Provenance.Origin != LibraryArtifactOriginAgentDirect || candidate.ReviewedAt.IsZero() || approved.ReviewedBy != "reviewer-opaque" {
		t.Fatalf("candidate = %+v approved=%+v", candidate, approved)
	}

	// A subsequent immutable revision is pending again; it cannot silently
	// inherit the prior review/publication eligibility.
	second, err := store.CreateLibraryArtifactVersion(context.Background(), LibraryArtifactVersion{ArtifactID: artifact.ID, Format: LibraryArtifactFormatText, Body: "Updated private body"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactVersion: %v", err)
	}
	if second.Version != 2 || second.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("second artifact version = %+v", second)
	}
	if _, err := store.LibraryPublicationCandidate(context.Background(), artifact.ID); !errors.Is(err, ErrLibraryPublicationNotReady) {
		t.Fatalf("latest unreviewed version became public: %v", err)
	}
}

func TestLibraryMCPClientArtifactCreationIsAtomicAndPaged(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Paged client", Subject: "usr_paged", CreatedBy: "usr_paged"})
	if err != nil {
		t.Fatal(err)
	}

	// The atomic method must validate before mutating either collection: an
	// invalid artifact cannot leave an orphaned run behind.
	if _, _, _, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{Origin: LibraryArtifactOriginAgentDirect}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# invalid"}); err == nil {
		t.Fatal("invalid scoped artifact was accepted")
	}
	runs, err := store.LibraryRuns(ctx)
	if err != nil || len(runs) != 0 {
		t.Fatalf("invalid scoped artifact left runs=%#v err=%v", runs, err)
	}
	artifacts, err := store.LibraryArtifacts(ctx)
	if err != nil || len(artifacts) != 0 {
		t.Fatalf("invalid scoped artifact left artifacts=%#v err=%v", artifacts, err)
	}

	// A queryable surface projection is valid only when it agrees with the
	// private direct-run provenance. This is the same fence used by the PgStore
	// migration before it assigns a legacy artifact to a client page.
	mismatchedRun, err := store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginAgentDirect, ActorRef: "usr_creator", SurfaceRef: client.ID, Status: "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "mismatched legacy projection", Origin: LibraryArtifactOriginAgentDirect, RunID: mismatchedRun.ID,
		CreatedBy: "usr_other", AgentSurfaceID: client.ID,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "must not project"}); err == nil {
		t.Fatal("artifact with mismatched creator/run provenance received a surface projection")
	}

	created := make(map[string]LibraryArtifact)
	for _, title := range []string{"first direct", "second direct", "third direct"} {
		run, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{
			Title: title, Origin: LibraryArtifactOriginAgentDirect,
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# " + title})
		if err != nil {
			t.Fatalf("create %q: %v", title, err)
		}
		if artifact.RunID != run.ID || artifact.CreatedBy != client.Subject || artifact.AgentSurfaceID != client.ID || run.ActorRef != client.Subject || run.SurfaceRef != client.ID || version.CreatedBy != client.Subject {
			t.Fatalf("derived scoped provenance run=%+v artifact=%+v version=%+v", run, artifact, version)
		}
		created[artifact.ID] = artifact
	}

	shared, sharedVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "granted source", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "pinned body", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: shared.ID, ArtifactVersionID: sharedVersion.ID, ArtifactVersionDigest: sharedVersion.Digest,
		AgentSurfaceID: client.ID, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]LibraryMCPClientArtifact)
	var cursor LibraryMCPClientArtifactCursor
	for {
		page, err := store.LibraryMCPClientArtifactPage(ctx, client, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Artifacts) > 2 {
			t.Fatalf("page exceeded requested limit: %#v", page)
		}
		for _, item := range page.Artifacts {
			if _, duplicate := seen[item.Artifact.ID]; duplicate {
				t.Fatalf("duplicate artifact across pages: %q", item.Artifact.ID)
			}
			seen[item.Artifact.ID] = item
		}
		if page.NextCursor.CreatedAt.IsZero() {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 4 {
		t.Fatalf("paged surface projection=%#v", seen)
	}
	for id := range created {
		if item, found := seen[id]; !found || item.Access != "owned" || item.Version.ArtifactID != id {
			t.Fatalf("direct artifact projection id=%q item=%+v found=%t", id, item, found)
		}
	}
	if item, found := seen[shared.ID]; !found || item.Access != "granted" || item.Version.ID != sharedVersion.ID || item.Version.Digest != sharedVersion.Digest {
		t.Fatalf("pinned grant projection item=%+v found=%t", item, found)
	}

	other, err := store.CreateMCPClient(ctx, MCPClient{Name: "Other client", Subject: "usr_other", CreatedBy: "usr_other"})
	if err != nil {
		t.Fatal(err)
	}
	otherPage, err := store.LibraryMCPClientArtifactPage(ctx, other, LibraryMCPClientArtifactCursor{}, 2)
	if err != nil || len(otherPage.Artifacts) != 0 {
		t.Fatalf("other client page=%#v err=%v", otherPage, err)
	}
}

func TestLibraryRootMCPArtifactCreationIsAtomic(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)

	// The root write derives the run itself. A source access failure therefore
	// exercises the point where the old two-call MCP path could have stranded a
	// run before its artifact was accepted.
	if _, _, _, err := store.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "missing source", Origin: LibraryArtifactOriginAgentDirect,
		SourceArtifactID: "libart_missing", SourceArtifactVersionID: "libartv_missing", SourceArtifactDigest: libraryDigest("missing"),
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "must not persist"}); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("missing root source error=%v, want artifact not found", err)
	}
	runs, err := store.LibraryRuns(ctx)
	if err != nil || len(runs) != 0 {
		t.Fatalf("failed root artifact left runs=%#v err=%v", runs, err)
	}
	artifacts, err := store.LibraryArtifacts(ctx)
	if err != nil || len(artifacts) != 0 {
		t.Fatalf("failed root artifact left artifacts=%#v err=%v", artifacts, err)
	}

	run, artifact, version, err := store.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "root direct artifact", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Root artifact"})
	if err != nil {
		t.Fatalf("CreateLibraryRootMCPArtifactWithInitialVersion: %v", err)
	}
	if artifact.RunID != run.ID || artifact.CreatedBy != libraryRootMCPActorRef || artifact.AgentSurfaceID != "" || version.CreatedBy != libraryRootMCPActorRef || run.ActorRef != libraryRootMCPActorRef || run.SurfaceRef != libraryRootMCPSurfaceRef {
		t.Fatalf("derived root provenance run=%+v artifact=%+v version=%+v", run, artifact, version)
	}

	// Root MCP may cite its own exact immutable source, but the follow-up write
	// still creates the run, artifact, and version as one operation.
	childRun, child, _, err := store.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "root derived artifact", Origin: LibraryArtifactOriginAgentDirect,
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: version.ID, SourceArtifactDigest: version.Digest,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "derived"})
	if err != nil {
		t.Fatalf("root source citation: %v", err)
	}
	if child.RunID != childRun.ID || child.SourceArtifactID != artifact.ID || childRun.SourceArtifactVersionID != version.ID || childRun.SourceArtifactDigest != version.Digest {
		t.Fatalf("root child provenance run=%+v artifact=%+v", childRun, child)
	}
}

func TestLibraryPublicationClaimCASRequiresCurrentReviewedHead(t *testing.T) {
	store := newLibraryFileStore(t)
	artifact, first, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Claimed report", Origin: LibraryArtifactOriginHuman, CreatedBy: "owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Reviewed first version"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactWithInitialVersion: %v", err)
	}
	if _, err := store.ReviewLibraryArtifactVersion(context.Background(), artifact.ID, first.ID, LibraryRedactionApproved, "reviewer", timeNowForTest(t)); err != nil {
		t.Fatalf("ReviewLibraryArtifactVersion: %v", err)
	}
	observed, err := store.LibraryPublicationCandidate(context.Background(), artifact.ID)
	if err != nil {
		t.Fatalf("LibraryPublicationCandidate: %v", err)
	}
	claimed, err := store.ClaimLibraryPublicationCandidate(context.Background(), artifact.ID, observed.ArtifactVersionID, observed.Digest)
	if err != nil || claimed.ArtifactVersionID != observed.ArtifactVersionID || claimed.Digest != observed.Digest {
		t.Fatalf("initial publication claim=%+v err=%v", claimed, err)
	}
	claimedVersion, found := store.LibraryArtifactVersion(context.Background(), artifact.ID, first.ID)
	if !found || claimedVersion.PublicationClaimedAt.IsZero() {
		t.Fatalf("publication claim was not durably marked: %+v found=%v", claimedVersion, found)
	}
	if _, err := store.ReviewLibraryArtifactVersion(context.Background(), artifact.ID, first.ID, LibraryRedactionRejected, "reviewer", timeNowForTest(t)); !errors.Is(err, ErrLibraryArtifactPublicationClaimed) {
		t.Fatalf("claimed version review error=%v, want claimed conflict", err)
	}

	second, err := store.CreateLibraryArtifactVersion(context.Background(), LibraryArtifactVersion{
		ArtifactID: artifact.ID, Format: LibraryArtifactFormatText, Body: "Reviewed second version",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactVersion: %v", err)
	}
	if _, err := store.ReviewLibraryArtifactVersion(context.Background(), artifact.ID, second.ID, LibraryRedactionApproved, "reviewer", timeNowForTest(t)); err != nil {
		t.Fatalf("ReviewLibraryArtifactVersion second: %v", err)
	}
	if _, err := store.ClaimLibraryPublicationCandidate(context.Background(), artifact.ID, observed.ArtifactVersionID, observed.Digest); !errors.Is(err, ErrLibraryPublicationClaimConflict) {
		t.Fatalf("stale publication claim error=%v, want claim conflict", err)
	}

	newest, err := store.LibraryPublicationCandidate(context.Background(), artifact.ID)
	if err != nil {
		t.Fatalf("newest publication candidate: %v", err)
	}
	if newest.ArtifactVersionID != second.ID || newest.Digest != second.Digest {
		t.Fatalf("newest candidate=%+v, want version=%s digest=%s", newest, second.ID, second.Digest)
	}
}

func TestLibraryNonSkillOriginsCannotClaimSkillProvenance(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, version := createLibrarySkillForTest(t, store)
	if _, err := store.CreateLibraryRun(context.Background(), LibraryRun{
		Origin: LibraryRunOriginAutomation, SkillID: skill.ID, SkillVersionID: version.ID, Status: "succeeded",
	}); err == nil {
		t.Fatal("automation run was allowed to claim a Skill parent")
	}
	if _, _, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Misattributed artifact", Origin: LibraryArtifactOriginHuman, SkillID: skill.ID, SkillVersionID: version.ID, CreatedBy: "owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Nope"}); err == nil {
		t.Fatal("human artifact was allowed to claim a Skill parent")
	}
	wrongRun, err := store.CreateLibraryRun(context.Background(), LibraryRun{Origin: LibraryRunOriginHuman, ActorRef: "owner", Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Mismatched run", Origin: LibraryArtifactOriginAgentDirect, RunID: wrongRun.ID, CreatedBy: "agent",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Nope"}); err == nil {
		t.Fatal("artifact was allowed to claim a run of another origin")
	}
}

func TestLibraryProvenanceFieldsAcceptDigestsNotRawPayloads(t *testing.T) {
	store := newLibraryFileStore(t)
	if _, err := store.CreateLibrarySkillDraft(context.Background(), LibrarySkillDraft{
		Name: "Unsafe draft", Content: "# Draft", Origin: LibraryDraftOriginGenerated, Generator: "test", PromptDigest: "raw user brief", CreatedBy: "owner",
	}); err == nil {
		t.Fatal("raw draft prompt was accepted in a digest field")
	}
	if _, err := store.CreateLibraryRun(context.Background(), LibraryRun{
		Origin: LibraryRunOriginAgentDirect, Status: "succeeded", InputDigest: "raw tool arguments",
	}); err == nil {
		t.Fatal("raw run input was accepted in a digest field")
	}
	skill, version := createLibrarySkillForTest(t, store)
	if _, err := store.CreateLibrarySkillEvaluation(context.Background(), LibrarySkillEvaluation{
		SkillID: skill.ID, SkillVersionID: version.ID, Evaluator: "test", Score: 100, Passed: true, EvidenceDigest: "raw evidence", CreatedBy: "owner",
	}); err == nil {
		t.Fatal("raw evaluation evidence was accepted in a digest field")
	}
}

func TestLibraryFileStorePersistsDraftsAndArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "library.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := store.CreateLibrarySkillDraft(context.Background(), LibrarySkillDraft{
		Name: "Release notes", Content: "# Draft", Origin: LibraryDraftOriginGenerated, Generator: "test", Model: "test-model", PromptDigest: libraryDigest("brief"), CreatedBy: "actor",
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillDraft: %v", err)
	}
	artifact, _, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Notes", Origin: LibraryArtifactOriginHuman, CreatedBy: "actor",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Hello"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifact: %v", err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, found := reopened.LibrarySkillDraft(context.Background(), draft.ID); !found || got.Content != "# Draft" || got.PromptDigest == "brief" {
		t.Fatalf("draft after restart = %+v found=%v", got, found)
	}
	if versions, err := reopened.LibraryArtifactVersions(context.Background(), artifact.ID); err != nil || len(versions) != 1 || versions[0].Body != "Hello" {
		t.Fatalf("artifact after restart = %#v err=%v", versions, err)
	}
}

func TestLibraryFileStorePersistsArtifactGrantsAndRejectsRevokedTargets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "library.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Pinned source", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "immutable source", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactWithInitialVersion: %v", err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Source reader", Subject: "usr_reader", CreatedBy: "usr_reader"})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
		AgentSurfaceID: client.ID, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	active, found := reopened.ActiveLibraryArtifactGrant(ctx, artifact.ID, client.ID)
	if !found || active.ID != grant.ID || active.ArtifactVersionID != version.ID || active.ArtifactVersionDigest != version.Digest {
		t.Fatalf("grant after restart=%+v found=%v", active, found)
	}
	if _, err := reopened.RevokeMCPClient(ctx, client.ID, client.Subject, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatalf("RevokeMCPClient: %v", err)
	}
	if _, err := reopened.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
		AgentSurfaceID: client.ID, CreatedBy: "usr_owner",
	}); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("grant to revoked target error=%v, want %v", err, ErrMCPClientRevoked)
	}
}

func timeNowForTest(t *testing.T) time.Time {
	t.Helper()
	return time.Now().UTC()
}
