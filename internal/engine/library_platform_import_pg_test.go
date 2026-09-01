package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestPgPlatformDraftImportIsIdempotentAndEncryptsCandidate is gated like the
// rest of the PgStore contract tests. It covers the extra durable import
// mapping, including concurrent retries after a transport failure, rather than
// treating FileStore's mutex as evidence for production behavior.
func TestPgPlatformDraftImportIsIdempotentAndEncryptsCandidate(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetCipher(testCipher(t, 83))
	request := LibraryPlatformSkillDraftImport{
		RequestID:             "draftreq_pg_import_0123456789",
		RequestedCapabilities: []string{"repo.read", "repo.read"},
		Candidate: LibraryPlatformSkillDraftCandidate{
			Name: "Private repository review", Description: "Review a private repository", Content: "# Review\nInspect the diff before acting.",
			Provider: "openai", Model: "gpt-4.1-mini", PromptDigest: libraryDigest("private platform prompt"),
		},
	}

	var mu sync.Mutex
	var draftIDs []string
	var replayCount int
	var importErr error
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			draft, replayed, err := store.ImportPlatformLibrarySkillDraft(ctx, request, "usr_owner")
			mu.Lock()
			defer mu.Unlock()
			if err != nil && importErr == nil {
				importErr = err
				return
			}
			if err == nil {
				draftIDs = append(draftIDs, draft.ID)
				if replayed {
					replayCount++
				}
			}
		}()
	}
	group.Wait()
	if importErr != nil {
		t.Fatalf("concurrent platform import: %v", importErr)
	}
	if len(draftIDs) != 4 || replayCount != 3 {
		t.Fatalf("draft IDs=%v replayCount=%d", draftIDs, replayCount)
	}
	for _, id := range draftIDs[1:] {
		if id != draftIDs[0] {
			t.Fatalf("concurrent retry created multiple drafts: %v", draftIDs)
		}
	}
	draftID := draftIDs[0]
	defer func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_draft_imports WHERE draft_id=$1`, draftID)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_drafts WHERE id=$1`, draftID)
	}()

	var name, description, content, provider, model, createdBy string
	if err := store.pool.QueryRow(ctx, `SELECT name,description,content,generator,model,created_by FROM narthex_library_skill_drafts WHERE id=$1`, draftID).Scan(&name, &description, &content, &provider, &model, &createdBy); err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct {
		label  string
		stored string
		plain  string
	}{
		{label: "name", stored: name, plain: request.Candidate.Name},
		{label: "description", stored: description, plain: request.Candidate.Description},
		{label: "content", stored: content, plain: request.Candidate.Content},
		{label: "provider", stored: provider, plain: request.Candidate.Provider},
		{label: "model", stored: model, plain: request.Candidate.Model},
		{label: "created by", stored: createdBy, plain: "usr_owner"},
	} {
		if !strings.HasPrefix(field.stored, encPrefix) || strings.Contains(field.stored, field.plain) {
			t.Fatalf("platform draft %s was not encrypted at rest", field.label)
		}
	}
	var requestHash, payloadDigest, mappedDraftID string
	if err := store.pool.QueryRow(ctx, `SELECT request_id_hash,payload_digest,draft_id FROM narthex_library_skill_draft_imports WHERE draft_id=$1`, draftID).Scan(&requestHash, &payloadDigest, &mappedDraftID); err != nil {
		t.Fatal(err)
	}
	if requestHash != libraryDigest(request.RequestID) || requestHash == request.RequestID || !libraryDigestPattern.MatchString(payloadDigest) || mappedDraftID != draftID {
		t.Fatalf("stored platform import hashes request=%q payload=%q draft=%q", requestHash, payloadDigest, mappedDraftID)
	}
	storedDraft, found := store.LibrarySkillDraft(ctx, draftID)
	if !found || storedDraft.Content != request.Candidate.Content || storedDraft.Generator != request.Candidate.Provider || storedDraft.Model != request.Candidate.Model || storedDraft.CreatedBy != "usr_owner" {
		t.Fatalf("decrypted platform draft=%+v found=%v", storedDraft, found)
	}

	conflict := request
	conflict.Candidate.Content = "# Different candidate"
	if _, _, err := store.ImportPlatformLibrarySkillDraft(ctx, conflict, "usr_owner"); !errors.Is(err, ErrLibraryDraftImportConflict) {
		t.Fatalf("conflicting request id error=%v, want conflict", err)
	}
}
