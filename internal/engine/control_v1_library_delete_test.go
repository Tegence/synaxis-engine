package engine

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// DELETE /control/v1/library/artifacts/{id} (docs/CONTROL_V1.md, "Library
// artifact erasure"). Each scenario is written once against the store facets
// it needs and runs on FileStore here and on PgStore in
// library_artifact_delete_pg_test.go.

type libraryDeleteTestStore interface {
	AccountStore
	LibraryStore
	MCPClientStore
	LibraryArtifactMediaStore
	LibraryChatArtifactStore
	LibraryCollaborationStore
	LibraryMCPClientArtifactVersionStore
}

// libraryDeleteResidue reports the names of any rows the store still holds
// for an erased artifact, its versions or its run, beyond what the public
// read methods show.
type libraryDeleteResidue func(t *testing.T, artifactID string, versionIDs []string, runID string) []string

type libraryDeleteFixture struct {
	owner, other MCPClient

	target         LibraryArtifact
	targetVersions []LibraryArtifactVersion
	targetRunID    string

	image        LibraryArtifact
	imageVersion LibraryArtifactVersion
	imageRunID   string

	reply        LibraryArtifact
	replyVersion LibraryArtifactVersion
	replyRunID   string
	savedCopyID  string

	kept        LibraryArtifact
	keptVersion LibraryArtifactVersion
	keptRunID   string
}

func newLibraryDeleteFixture(t *testing.T, store libraryDeleteTestStore) libraryDeleteFixture {
	t.Helper()
	ctx := context.Background()
	suffix := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(newEpoch()))
	var f libraryDeleteFixture
	client := func(name, subject string) MCPClient {
		t.Helper()
		created, err := store.CreateMCPClient(ctx, MCPClient{Name: name + " " + suffix, Subject: subject + suffix, CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatalf("CreateMCPClient %s: %v", name, err)
		}
		// Client writes need an active registration bound to its OAuth client.
		bound, err := store.BindMCPClientOAuthClient(ctx, created.ID, "oauth-"+created.ID, MCPClientPrecondition{ID: created.ID, Revision: created.Revision}, PlatformActor{UserID: created.Subject, Role: "operator"})
		if err != nil {
			t.Fatalf("BindMCPClientOAuthClient %s: %v", name, err)
		}
		return bound
	}
	f.owner = client("Delegated agent", "usr_erase_owner_")
	f.other = client("Other agent", "usr_erase_other_")
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() { cleanupPgLibraryDeleteFixture(t, pg, f) })
	}
	agentArtifact := func(title, kind, body string) (string, LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		run, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, f.owner, LibraryArtifact{
			Title: title, Origin: LibraryArtifactOriginAgentDirect, ContentKind: kind,
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: body})
		if err != nil {
			t.Fatalf("CreateLibraryMCPClientArtifactWithInitialVersion %s: %v", title, err)
		}
		return run.ID, artifact, version
	}

	var first LibraryArtifactVersion
	f.targetRunID, f.target, first = agentArtifact("Erased output", "", "# first private body")
	revised, err := store.CreateLibraryMCPClientArtifactVersion(ctx, f.owner, LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "revise-" + suffix, ArtifactID: f.target.ID, ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest,
		Body: "# second private body",
	})
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientArtifactVersion: %v", err)
	}
	f.targetVersions = []LibraryArtifactVersion{first, revised.Version}
	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: f.target.ID, ArtifactVersionID: revised.Version.ID, ArtifactVersionDigest: revised.Version.Digest,
		AgentSurfaceID: f.other.ID, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}
	admin := LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}
	if _, err := store.Collaborate(ctx, admin, LibraryCollaborationRequest{Operation: "grant", ArtifactID: f.target.ID, Kind: "guest", Label: "Reviewer", Role: "comment"}); err != nil {
		t.Fatalf("Collaborate grant: %v", err)
	}
	if _, err := store.Collaborate(ctx, admin, LibraryCollaborationRequest{Operation: "comment", ArtifactID: f.target.ID, RequestID: "comment-" + suffix, VersionID: revised.Version.ID, Quote: "second", Body: "private comment"}); err != nil {
		t.Fatalf("Collaborate comment: %v", err)
	}

	canonical, _ := libraryArtifactTestPNG(t)
	imageRun, image, imageVersion, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, f.owner, LibraryArtifact{
		Title: "Erased chart", Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, "private chart")
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactWithInitialVersion: %v", err)
	}
	f.imageRunID, f.image, f.imageVersion = imageRun.ID, image, imageVersion

	f.replyRunID, f.reply, f.replyVersion = agentArtifact("Reply", LibraryContentChatReply, "private reply")
	saved, err := store.SaveLibraryChatReply(ctx, LibraryChatSaveRequest{LibraryChatReplyReference: LibraryChatReplyReference{
		ArtifactID: f.reply.ID, ArtifactVersionID: f.replyVersion.ID, AgentSurfaceID: f.owner.ID, Subject: f.owner.Subject,
	}, Title: "Saved reply"})
	if err != nil {
		t.Fatalf("SaveLibraryChatReply: %v", err)
	}
	f.savedCopyID = saved.Artifact.ArtifactID

	f.keptRunID, f.kept, f.keptVersion = agentArtifact("Kept output", "", "# kept body")
	return f
}

func versionIDs(versions ...LibraryArtifactVersion) []string {
	ids := make([]string, 0, len(versions))
	for _, version := range versions {
		ids = append(ids, version.ID)
	}
	return ids
}

func assertLibraryArtifactErased(t *testing.T, store libraryDeleteTestStore, residue libraryDeleteResidue, artifactID string, versions []LibraryArtifactVersion, runID string) {
	t.Helper()
	ctx := context.Background()
	if _, found := store.LibraryArtifact(ctx, artifactID); found {
		t.Fatalf("artifact %s survived", artifactID)
	}
	if remaining, err := store.LibraryArtifactVersions(ctx, artifactID); err != nil || len(remaining) != 0 {
		t.Fatalf("versions survived: %+v err=%v", remaining, err)
	}
	for _, version := range versions {
		if _, found := store.LibraryArtifactVersion(ctx, artifactID, version.ID); found {
			t.Fatalf("version %s survived", version.ID)
		}
	}
	if grants, err := store.LibraryArtifactGrants(ctx, artifactID); err != nil || len(grants) != 0 {
		t.Fatalf("grants survived: %+v err=%v", grants, err)
	}
	if _, found := store.LibraryRun(ctx, runID); found {
		t.Fatalf("provenance run %s survived", runID)
	}
	if leftover := residue(t, artifactID, versionIDs(versions...), runID); len(leftover) != 0 {
		t.Fatalf("erased artifact left records: %v", leftover)
	}
}

func TestControlLibraryArtifactDeleteRemovesVersionsMediaGrantsProvenance(t *testing.T) {
	store := newFileConnectionsStore(t)
	testControlLibraryArtifactDeleteRemoves(t, store, fileLibraryDeleteResidue(store))
}

func testControlLibraryArtifactDeleteRemoves(t *testing.T, store libraryDeleteTestStore, residue libraryDeleteResidue) {
	ctx := context.Background()
	h := newConnectionsTestHarness(t, store)
	f := newLibraryDeleteFixture(t, store)
	path := func(id string) string { return "/control/v1/library/artifacts/" + id }

	// Versions, the exact-version grant, collaboration grants and comments,
	// the revision receipt and the producing run.
	if response := h.service(http.MethodDelete, path(f.target.ID), ""); response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body)
	}
	assertLibraryArtifactErased(t, store, residue, f.target.ID, f.targetVersions, f.targetRunID)
	if _, err := store.Collaborate(ctx, LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}, LibraryCollaborationRequest{Operation: "read", ArtifactID: f.target.ID}); err == nil {
		t.Fatal("collaboration survived the artifact")
	}
	page, err := store.LibraryMCPClientArtifactPage(ctx, f.other, LibraryMCPClientArtifactCursor{}, 10)
	if err != nil || len(page.Artifacts) != 0 {
		t.Fatalf("grantee still sees the erased artifact: %+v err=%v", page, err)
	}
	expectControlProblem(t, h.service(http.MethodGet, path(f.target.ID), ""), http.StatusNotFound, controlCodeNotFound)

	// The private image blob goes with its version.
	if response := h.service(http.MethodDelete, path(f.image.ID), ""); response.Code != http.StatusNoContent {
		t.Fatalf("image delete status=%d body=%s", response.Code, response.Body)
	}
	if _, found, err := store.LibraryArtifactMedia(ctx, f.image.ID, f.imageVersion.ID); found || err != nil {
		t.Fatalf("media survived: found=%v err=%v", found, err)
	}
	if bytes, found, err := store.LibraryArtifactImageBytes(ctx, f.image.ID, f.imageVersion.ID); found || len(bytes) != 0 || err != nil {
		t.Fatalf("image bytes survived: found=%v err=%v", found, err)
	}
	assertLibraryArtifactErased(t, store, residue, f.image.ID, []LibraryArtifactVersion{f.imageVersion}, f.imageRunID)

	// A chat reply loses its run and its save record; the member's saved copy
	// is a separate artifact the control plane erases by its own ID.
	if response := h.service(http.MethodDelete, path(f.reply.ID), ""); response.Code != http.StatusNoContent {
		t.Fatalf("reply delete status=%d body=%s", response.Code, response.Body)
	}
	assertLibraryArtifactErased(t, store, residue, f.reply.ID, []LibraryArtifactVersion{f.replyVersion}, f.replyRunID)
	if _, err := store.SaveLibraryChatReply(ctx, LibraryChatSaveRequest{LibraryChatReplyReference: LibraryChatReplyReference{
		ArtifactID: f.reply.ID, ArtifactVersionID: f.replyVersion.ID, AgentSurfaceID: f.owner.ID, Subject: f.owner.Subject,
	}, Title: "Saved again"}); err == nil {
		t.Fatal("an erased reply could be saved again")
	}
	if _, found := store.LibraryArtifact(ctx, f.savedCopyID); !found {
		t.Fatal("erasing the reply removed the separately saved copy")
	}
	copyVersions, err := store.LibraryArtifactVersions(ctx, f.savedCopyID)
	if err != nil || len(copyVersions) != 1 {
		t.Fatalf("copy versions=%+v err=%v", copyVersions, err)
	}
	if response := h.service(http.MethodDelete, path(f.savedCopyID), ""); response.Code != http.StatusNoContent {
		t.Fatalf("copy delete status=%d body=%s", response.Code, response.Body)
	}
	if leftover := residue(t, f.savedCopyID, versionIDs(copyVersions...), ""); len(leftover) != 0 {
		t.Fatalf("erased copy left records: %v", leftover)
	}

	// Nothing else is touched.
	if _, found := store.LibraryArtifact(ctx, f.kept.ID); !found {
		t.Fatal("unrelated artifact was removed")
	}
	if _, found := store.LibraryArtifactVersion(ctx, f.kept.ID, f.keptVersion.ID); !found {
		t.Fatal("unrelated version was removed")
	}
	if _, found := store.LibraryRun(ctx, f.keptRunID); !found {
		t.Fatal("unrelated run was removed")
	}
}

func TestControlLibraryArtifactDeleteServiceOnly(t *testing.T) {
	testControlLibraryArtifactDeleteServiceOnly(t, newFileConnectionsStore(t))
}

func testControlLibraryArtifactDeleteServiceOnly(t *testing.T, store libraryDeleteTestStore) {
	h := newConnectionsTestHarness(t, store)
	f := newLibraryDeleteFixture(t, store)
	for _, actor := range []struct{ user, role string }{
		{"usr_owner", "owner"}, {"usr_admin", "admin"}, {"usr_operator", "operator"}, {"usr_viewer", "viewer"},
	} {
		response := h.request(actor.user, actor.role, http.MethodDelete, "/control/v1/library/artifacts/"+f.target.ID, "", nil)
		expectControlProblem(t, response, http.StatusForbidden, controlCodeForbidden)
	}
	if _, found := store.LibraryArtifact(context.Background(), f.target.ID); !found {
		t.Fatal("a refused delete removed the artifact")
	}
	if versions, err := store.LibraryArtifactVersions(context.Background(), f.target.ID); err != nil || len(versions) != 2 {
		t.Fatalf("a refused delete removed versions: %+v err=%v", versions, err)
	}
}

func TestControlLibraryArtifactDeleteIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadFileStore(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := testControlLibraryArtifactDeleteIdempotent(t, store)
	// The tombstone is durable: a restarted Engine still answers 204.
	restarted, err := LoadFileStore(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := newConnectionsTestHarness(t, restarted)
	if response := h.service(http.MethodDelete, "/control/v1/library/artifacts/"+id, ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete after restart status=%d body=%s", response.Code, response.Body)
	}
}

func testControlLibraryArtifactDeleteIdempotent(t *testing.T, store libraryDeleteTestStore) string {
	h := newConnectionsTestHarness(t, store)
	f := newLibraryDeleteFixture(t, store)
	for attempt := 0; attempt < 2; attempt++ {
		response := h.service(http.MethodDelete, "/control/v1/library/artifacts/"+f.target.ID, "")
		if response.Code != http.StatusNoContent || response.Header().Get(controlRequestIDHeader) == "" {
			t.Fatalf("delete attempt %d status=%d body=%s", attempt, response.Code, response.Body)
		}
	}
	expectControlProblem(t, h.service(http.MethodDelete, "/control/v1/library/artifacts/libart_never_"+f.owner.ID, ""), http.StatusNotFound, controlCodeNotFound)
	// The existing read route is unchanged beside the new method.
	if response := h.service(http.MethodGet, "/control/v1/library/artifacts/"+f.kept.ID, ""); response.Code != http.StatusOK {
		t.Fatalf("read beside delete status=%d body=%s", response.Code, response.Body)
	}
	return f.target.ID
}

// fileLibraryDeleteResidue inspects FileStore state the read methods do not
// expose: media blobs, revision receipts, collaboration state and chat saves.
func fileLibraryDeleteResidue(store *FileStore) libraryDeleteResidue {
	return func(t *testing.T, artifactID string, versionIDs []string, runID string) []string {
		t.Helper()
		store.mu.Lock()
		defer store.mu.Unlock()
		versions := map[string]bool{}
		for _, id := range versionIDs {
			versions[id] = true
		}
		var leftover []string
		for _, blob := range store.libraryArtifactMediaBlobs {
			if blob != nil && versions[blob.ArtifactVersionID] {
				leftover = append(leftover, "media "+blob.ArtifactVersionID)
			}
		}
		for _, version := range store.libraryArtifactVersions {
			if version != nil && (version.ArtifactID == artifactID || versions[version.ID]) {
				leftover = append(leftover, "version "+version.ID)
			}
		}
		for _, grant := range store.libraryArtifactGrants {
			if grant != nil && grant.ArtifactID == artifactID {
				leftover = append(leftover, "grant "+grant.ID)
			}
		}
		for _, receipt := range store.libraryMCPClientArtifactVersionRequests {
			if receipt != nil && receipt.ArtifactID == artifactID {
				leftover = append(leftover, "receipt "+receipt.ArtifactVersionID)
			}
		}
		if _, ok := store.libraryCollaborations[artifactID]; ok {
			leftover = append(leftover, "collaboration")
		}
		for _, record := range store.libraryChatSaves {
			if record != nil && (record.SourceArtifactID == artifactID || record.ArtifactID == artifactID) {
				leftover = append(leftover, "chat save "+record.SourceArtifactID+">"+record.ArtifactID)
			}
		}
		for _, run := range store.libraryRuns {
			if run != nil && runID != "" && run.ID == runID {
				leftover = append(leftover, "run "+run.ID)
			}
		}
		return leftover
	}
}
