package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newHostedLibraryImportConsole(t *testing.T, options ...ConsoleOption) (*http.ServeMux, *FileStore, ed25519.PrivateKey, time.Time) {
	t.Helper()
	store := newLibraryFileStore(t)
	verifier, privateKey, now := newActorVerifier(t)
	baseOptions := []ConsoleOption{
		WithAdminToken("machine-token"),
		WithLocalAdminAuth(false),
		WithPlatformActorVerifier(verifier),
	}
	baseOptions = append(baseOptions, options...)
	api := NewConsoleAPI(store, nil, nil, "pw", "hosted-library-secret", "https://engine.example", "https://console.example", "", baseOptions...)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, store, privateKey, now
}

func platformDraftImportRequest(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, body []byte, userID, role string) *http.Request {
	t.Helper()
	path := "/api/library/skill-drafts/platform-import"
	claims := actorClaimsForTest(now, http.MethodPost, path, body)
	claims.UserID, claims.Role = userID, role
	request := actorRequest(http.MethodPost, path, body, signActorAssertionForTest(t, privateKey, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	return request
}

func TestHostedPlatformDraftImportPersistsOnlyEditableIdempotentDraft(t *testing.T) {
	mux, store, privateKey, now := newHostedLibraryImportConsole(t)
	promptDigest := libraryDigest("private broker prompt")
	body := []byte(`{"requestId":"draftreq_0123456789","requestedCapabilities":["tickets.read","alerts.read","tickets.read"],"candidate":{"name":"Incident responder","description":"Triage incidents","content":"# Incident response\nCheck impact first.","provider":"openai","model":"gpt-4.1-mini","promptDigest":"` + promptDigest + `"}}`)

	first := httptest.NewRecorder()
	mux.ServeHTTP(first, platformDraftImportRequest(t, privateKey, now, body, "usr_owner", "owner"))
	if first.Code != http.StatusCreated {
		t.Fatalf("first platform import = %d body=%s", first.Code, first.Body)
	}
	if first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", first.Header().Get("Cache-Control"))
	}
	var firstResponse struct {
		Draft    LibrarySkillDraft `json:"draft"`
		Replayed bool              `json:"replayed"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	if firstResponse.Replayed || firstResponse.Draft.ID == "" {
		t.Fatalf("first response=%+v", firstResponse)
	}
	if firstResponse.Draft.Origin != LibraryDraftOriginGenerated ||
		firstResponse.Draft.Generator != "openai" || firstResponse.Draft.Model != "gpt-4.1-mini" ||
		firstResponse.Draft.PromptDigest != promptDigest || firstResponse.Draft.CreatedBy != "usr_owner" {
		t.Fatalf("imported draft provenance=%+v", firstResponse.Draft)
	}
	if got := firstResponse.Draft.RequestedCapabilities; len(got) != 2 || got[0] != "alerts.read" || got[1] != "tickets.read" {
		t.Fatalf("caller capability intent=%v", got)
	}
	if len(store.librarySkills) != 0 || len(store.librarySkillBindings) != 0 || len(store.libraryRuns) != 0 || len(store.libraryArtifacts) != 0 {
		t.Fatalf("draft import created an unauthorized library resource: skills=%d bindings=%d runs=%d artifacts=%d", len(store.librarySkills), len(store.librarySkillBindings), len(store.libraryRuns), len(store.libraryArtifacts))
	}

	// Equivalent capability intent in a different order is the same canonical
	// request. A retry cannot create a second editable draft after a lost
	// Platform-to-Engine response.
	replayBody := []byte(`{"requestId":"draftreq_0123456789","requestedCapabilities":["alerts.read","tickets.read"],"candidate":{"name":"Incident responder","description":"Triage incidents","content":"# Incident response\nCheck impact first.","provider":"openai","model":"gpt-4.1-mini","promptDigest":"` + promptDigest + `"}}`)
	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, platformDraftImportRequest(t, privateKey, now, replayBody, "usr_owner", "owner"))
	if replay.Code != http.StatusOK {
		t.Fatalf("replayed platform import = %d body=%s", replay.Code, replay.Body)
	}
	var replayResponse struct {
		Draft    LibrarySkillDraft `json:"draft"`
		Replayed bool              `json:"replayed"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResponse); err != nil {
		t.Fatal(err)
	}
	if !replayResponse.Replayed || replayResponse.Draft.ID != firstResponse.Draft.ID || len(store.librarySkillDrafts) != 1 || len(store.librarySkillDraftImports) != 1 {
		t.Fatalf("replay response=%+v drafts=%d imports=%d", replayResponse, len(store.librarySkillDrafts), len(store.librarySkillDraftImports))
	}

	conflictingBody := bytes.Replace(replayBody, []byte("Check impact first."), []byte("Escalate immediately."), 1)
	conflict := httptest.NewRecorder()
	mux.ServeHTTP(conflict, platformDraftImportRequest(t, privateKey, now, conflictingBody, "usr_owner", "owner"))
	if conflict.Code != http.StatusConflict || len(store.librarySkillDrafts) != 1 {
		t.Fatalf("conflicting platform import = %d body=%s drafts=%d", conflict.Code, conflict.Body, len(store.librarySkillDrafts))
	}
}

func TestHostedPlatformDraftImportRequiresActualAdministratorAndStrictCandidate(t *testing.T) {
	mux, store, privateKey, now := newHostedLibraryImportConsole(t)
	promptDigest := libraryDigest("private broker prompt")
	valid := []byte(`{"requestId":"draftreq_abcdefghij","requestedCapabilities":["repo.read"],"candidate":{"name":"Repository review","description":"Review code","content":"# Review","provider":"openai","model":"gpt-4.1-mini","promptDigest":"` + promptDigest + `"}}`)

	operator := httptest.NewRecorder()
	mux.ServeHTTP(operator, platformDraftImportRequest(t, privateKey, now, valid, "usr_operator", "operator"))
	if operator.Code != http.StatusForbidden {
		t.Fatalf("operator platform import = %d body=%s", operator.Code, operator.Body)
	}

	service := httptest.NewRecorder()
	mux.ServeHTTP(service, platformDraftImportRequest(t, privateKey, now, valid, platformServiceActorID, "service"))
	if service.Code != http.StatusUnauthorized {
		t.Fatalf("service-only platform import = %d body=%s", service.Code, service.Body)
	}

	unknown := bytes.Replace(valid, []byte(`"promptDigest"`), []byte(`"unexpected":"nope","promptDigest"`), 1)
	strict := httptest.NewRecorder()
	mux.ServeHTTP(strict, platformDraftImportRequest(t, privateKey, now, unknown, "usr_admin", "admin"))
	if strict.Code != http.StatusBadRequest || len(store.librarySkillDrafts) != 0 {
		t.Fatalf("unknown field import = %d body=%s drafts=%d", strict.Code, strict.Body, len(store.librarySkillDrafts))
	}

	shortID := bytes.Replace(valid, []byte("draftreq_abcdefghij"), []byte("short"), 1)
	invalidID := httptest.NewRecorder()
	mux.ServeHTTP(invalidID, platformDraftImportRequest(t, privateKey, now, shortID, "usr_admin", "admin"))
	if invalidID.Code != http.StatusBadRequest || len(store.librarySkillDrafts) != 0 {
		t.Fatalf("short request id import = %d body=%s drafts=%d", invalidID.Code, invalidID.Body, len(store.librarySkillDrafts))
	}
}

func TestHostedDirectDraftGeneratorCannotBypassPlatformImport(t *testing.T) {
	generator := &fakeLibraryDraftGenerator{result: SkillDraftGeneration{
		Name: "Unsafe", Content: "# Unsafe", Generator: "test", Model: "test",
	}}
	mux, store, privateKey, now := newHostedLibraryImportConsole(t, WithSkillDraftGenerator(generator))
	body := []byte(`{"prompt":"Call the provider directly"}`)
	path := "/api/library/skill-drafts"
	claims := actorClaimsForTest(now, http.MethodPost, path, body)
	claims.UserID, claims.Role = "usr_owner", "owner"
	request := actorRequest(http.MethodPost, path, body, signActorAssertionForTest(t, privateKey, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || generator.request.Prompt != "" || len(store.librarySkillDrafts) != 0 {
		t.Fatalf("hosted direct drafting = %d prompt=%q drafts=%d body=%s", recorder.Code, generator.request.Prompt, len(store.librarySkillDrafts), recorder.Body)
	}
}

func TestFileStorePlatformDraftImportSurvivesRestartWithoutRawRequestID(t *testing.T) {
	store := newLibraryFileStore(t)
	request := LibraryPlatformSkillDraftImport{
		RequestID:             "draftreq_persist_012345",
		RequestedCapabilities: []string{"repo.read"},
		Candidate: LibraryPlatformSkillDraftCandidate{
			Name: "Repository review", Content: "# Review", Provider: "openai", Model: "gpt-4.1-mini", PromptDigest: libraryDigest("prompt"),
		},
	}
	draft, replayed, err := store.ImportPlatformLibrarySkillDraft(context.Background(), request, "usr_owner")
	if err != nil || replayed {
		t.Fatalf("initial import draft=%+v replayed=%v err=%v", draft, replayed, err)
	}
	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	replayedDraft, replayed, err := reopened.ImportPlatformLibrarySkillDraft(context.Background(), request, "usr_owner")
	if err != nil || !replayed || replayedDraft.ID != draft.ID {
		t.Fatalf("reopened replay draft=%+v replayed=%v err=%v", replayedDraft, replayed, err)
	}
	if len(reopened.librarySkillDraftImports) != 1 || reopened.librarySkillDraftImports[0].RequestIDHash == request.RequestID || reopened.librarySkillDraftImports[0].RequestIDHash != libraryDigest(request.RequestID) {
		t.Fatalf("stored import record=%+v", reopened.librarySkillDraftImports)
	}
}
