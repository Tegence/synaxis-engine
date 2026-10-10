package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func collaborationFixture(t *testing.T, library LibraryStore) (LibraryArtifact, LibraryArtifactVersion) {
	t.Helper()
	a, v, err := library.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{Title: "Shared research", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner"}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Research\nVersion one", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	return a, v
}

func exerciseCollaboration(t *testing.T, library LibraryStore, store LibraryCollaborationStore) {
	t.Helper()
	ctx := context.Background()
	a, first := collaborationFixture(t, library)
	if pg, ok := library.(*PgStore); ok {
		t.Cleanup(func() {
			for _, query := range []string{
				`DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`,
				`DELETE FROM narthex_library_artifacts WHERE id=$1`,
			} {
				if _, err := pg.pool.Exec(ctx, query, a.ID); err != nil {
					t.Errorf("clean up collaboration fixture: %v", err)
				}
			}
		})
	}
	admin := LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}
	call := func(actor LibraryCollaborationActor, req LibraryCollaborationRequest) (LibraryCollaborationResult, error) {
		req.ArtifactID = a.ID
		return store.Collaborate(ctx, actor, req)
	}
	grant, err := call(admin, LibraryCollaborationRequest{Operation: "grant", Kind: "guest", Label: "Design reviewer", Role: "edit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(grant.Token) != 43 {
		t.Fatal("missing one-time capability")
	}
	guest := LibraryCollaborationActor{Kind: "capability", Ref: grant.Grant.ID, Token: grant.Token}
	read, err := call(guest, LibraryCollaborationRequest{Operation: "read"})
	if err != nil || read.Version.Body != first.Body || read.Role != "edit" || read.Version.CreatedBy != "" {
		t.Fatalf("read=%+v err=%v", read, err)
	}
	if _, err = call(LibraryCollaborationActor{Kind: "capability", Ref: grant.Grant.ID, Token: strings.Repeat("x", 43)}, LibraryCollaborationRequest{Operation: "read"}); !errors.Is(err, ErrCollaborationUnavailable) {
		t.Fatal("wrong token read succeeded", err)
	}
	if _, err = call(guest, LibraryCollaborationRequest{Operation: "grants"}); !errors.Is(err, ErrCollaborationForbidden) {
		t.Fatal("guest listed grants", err)
	}
	if _, err = call(guest, LibraryCollaborationRequest{Operation: "grant", Kind: "guest", Label: "Escalation", Role: "edit"}); !errors.Is(err, ErrCollaborationForbidden) {
		t.Fatal("guest granted access", err)
	}
	comment := LibraryCollaborationRequest{Operation: "comment", RequestID: "comment-one", VersionID: first.ID, Quote: "Version one", Body: "Please include the support owner."}
	if _, err = call(guest, comment); err != nil {
		t.Fatal(err)
	}
	if result, err := call(guest, comment); err != nil || !result.Replayed {
		t.Fatal("comment retry duplicated", err)
	}
	read, _ = call(guest, LibraryCollaborationRequest{Operation: "read"})
	if len(read.Threads) != 1 || read.Threads[0].VersionID != first.ID || read.Threads[0].Comments[0].AuthorKind != "guest" {
		t.Fatalf("thread=%+v", read.Threads)
	}
	for _, req := range []LibraryCollaborationRequest{{Operation: "reply", RequestID: "reply-one", ThreadID: read.Threads[0].ID, Body: "Confirmed."}, {Operation: "resolve", RequestID: "resolve-one", ThreadID: read.Threads[0].ID, Resolved: true}} {
		if _, err = call(guest, req); err != nil {
			t.Fatal(err)
		}
	}
	edit := LibraryCollaborationRequest{Operation: "edit", RequestID: "edit-one", VersionID: first.ID, ExpectedDigest: first.Digest, Body: "# Research\nVersion two"}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := edit
			req.RequestID += string(rune('a' + i))
			_, err := call(guest, req)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrCollaborationConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("CAS success=%d conflict=%d", success, conflict)
	}
	versions, err := library.LibraryArtifactVersions(ctx, a.ID)
	if err != nil || len(versions) != 2 || versions[0].Body != first.Body || versions[1].RedactionStatus != LibraryRedactionPending || !strings.Contains(versions[1].Changelog, "Design reviewer") {
		t.Fatalf("immutable versions=%+v err=%v", versions, err)
	}
	for _, suffix := range []string{"a", "b"} {
		retry := edit
		retry.RequestID += suffix
		result, err := call(guest, retry)
		if err == nil && (!result.Replayed || result.Version.Version != 2) {
			t.Fatal("edit replay lost its saved version")
		}
		if err != nil && !errors.Is(err, ErrCollaborationConflict) {
			t.Fatal(err)
		}
	}
	read, _ = call(guest, LibraryCollaborationRequest{Operation: "read"})
	if read.Version.Version != 2 || read.Threads[0].Version != 1 || read.Threads[0].ResolvedAt == nil {
		t.Fatalf("live read=%+v", read)
	}
	if _, err = call(admin, LibraryCollaborationRequest{Operation: "grant", Kind: "subject", Recipient: "usr_commenter", Label: "Commenter", Role: "comment"}); err != nil {
		t.Fatal(err)
	}
	subject := LibraryCollaborationActor{Kind: "subject", Ref: "usr_commenter"}
	if _, err = call(subject, LibraryCollaborationRequest{Operation: "edit", RequestID: "forbidden-edit"}); !errors.Is(err, ErrCollaborationForbidden) {
		t.Fatal("commenter edited", err)
	}
	listed, err := store.CollaborationArtifacts(ctx, subject)
	if err != nil || len(listed) != 1 || listed[0].ArtifactID != a.ID {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	if pg, ok := store.(*PgStore); ok {
		var raw string
		if err = pg.pool.QueryRow(ctx, `SELECT state FROM narthex_library_collaborations WHERE artifact_id=$1`, a.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, "Design reviewer") || strings.Contains(raw, "support owner") || strings.Contains(raw, grant.Token) {
			t.Fatal("sensitive collaboration state is plaintext")
		}
	}
	grants, _ := call(admin, LibraryCollaborationRequest{Operation: "grants"})
	raw, _ := json.Marshal(grants)
	if strings.Contains(string(raw), grant.Token) || strings.Contains(string(raw), "tokenHash") {
		t.Fatal("list exposed capability material")
	}
	if _, err = call(admin, LibraryCollaborationRequest{Operation: "revoke", GrantID: grant.Grant.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = call(guest, comment); !errors.Is(err, ErrCollaborationUnavailable) {
		t.Fatal("revoked retry succeeded", err)
	}
	if _, err = call(guest, LibraryCollaborationRequest{Operation: "read"}); !errors.Is(err, ErrCollaborationUnavailable) {
		t.Fatal("revoked read succeeded", err)
	}
}

func TestLibraryCollaborationFileContract(t *testing.T) {
	store := newLibraryFileStore(t)
	exerciseCollaboration(t, store, store)
}

func TestPgLibraryCollaborationContract(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Register the pool first so fixture cleanup runs before it closes.
	t.Cleanup(store.Close)
	cipher, err := NewCipher(base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)
	exerciseCollaboration(t, store, store)
}

func TestLibraryCollaborationExpiryAndClientEpoch(t *testing.T) {
	now := time.Now().UTC()
	expiry := now
	state := libraryCollaborationState{Grants: []libraryCollaborationGrantRecord{{LibraryCollaborationGrant: LibraryCollaborationGrant{Kind: "subject", Recipient: "usr_member", Role: "edit", ExpiresAt: &expiry}}}}
	if _, _, _, ok := collaborationAccess(state, LibraryCollaborationActor{Kind: "subject", Ref: "usr_member"}, now); ok {
		t.Fatal("expiry boundary allowed")
	}
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_agent")
	a, _ := collaborationFixture(t, store)
	admin := LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}
	_, err := store.Collaborate(context.Background(), admin, LibraryCollaborationRequest{Operation: "grant", ArtifactID: a.ID, Kind: "client", Recipient: client.ID, Label: "Local agent", Role: "edit"})
	if err != nil {
		t.Fatal(err)
	}
	actor := LibraryCollaborationActor{Kind: "client", Ref: client.ID, Subject: client.Subject, Epoch: client.Epoch}
	if _, err = store.Collaborate(context.Background(), actor, LibraryCollaborationRequest{Operation: "read", ArtifactID: a.ID}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	durable, _ := store.mcpClientByIDLocked(client.ID)
	durable.Epoch = "rotated-epoch"
	store.mu.Unlock()
	if _, err = store.Collaborate(context.Background(), actor, LibraryCollaborationRequest{Operation: "read", ArtifactID: a.ID}); !errors.Is(err, ErrCollaborationUnavailable) {
		t.Fatal("stale endpoint accepted", err)
	}
	actor.Epoch = "rotated-epoch"
	if _, err = store.Collaborate(context.Background(), actor, LibraryCollaborationRequest{Operation: "read", ArtifactID: a.ID}); !errors.Is(err, ErrCollaborationUnavailable) {
		t.Fatal("new epoch inherited old grant", err)
	}
}

func TestLibraryCollaborationPersistenceAndRollback(t *testing.T) {
	store := newLibraryFileStore(t)
	a, v := collaborationFixture(t, store)
	admin := LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}
	ctx := context.Background()
	created, err := store.Collaborate(ctx, admin, LibraryCollaborationRequest{Operation: "grant", ArtifactID: a.ID, Kind: "guest", Label: "Saved guest", Role: "edit"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), created.Token) {
		t.Fatal("raw bearer persisted")
	}
	restarted, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	guest := LibraryCollaborationActor{Kind: "capability", Ref: created.Grant.ID, Token: created.Token}
	if _, err = restarted.Collaborate(ctx, guest, LibraryCollaborationRequest{Operation: "read", ArtifactID: a.ID}); err != nil {
		t.Fatal(err)
	}
	restarted.path = t.TempDir()
	if _, err = restarted.Collaborate(ctx, guest, LibraryCollaborationRequest{Operation: "edit", ArtifactID: a.ID, RequestID: "failed-write", VersionID: v.ID, ExpectedDigest: v.Digest, Body: "must not persist"}); err == nil {
		t.Fatal("failed disk write succeeded")
	}
	read, err := restarted.Collaborate(ctx, guest, LibraryCollaborationRequest{Operation: "read", ArtifactID: a.ID})
	if err != nil || read.Version.ID != v.ID {
		t.Fatal("failed save mutated state", err)
	}
}
