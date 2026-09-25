package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLibraryStudioGenerator implements both draft generators so the Console
// can be exercised with skill and artifact drafting available at once.
type fakeLibraryStudioGenerator struct {
	fakeLibraryDraftGenerator
	artifactRequest ArtifactDraftGenerationRequest
	artifactResult  ArtifactDraftGeneration
	artifactErr     error
}

func (f *fakeLibraryStudioGenerator) GenerateArtifactDraft(_ context.Context, request ArtifactDraftGenerationRequest) (ArtifactDraftGeneration, error) {
	f.artifactRequest = request
	return f.artifactResult, f.artifactErr
}

func libraryStudioArtifactDraftResult() ArtifactDraftGeneration {
	return ArtifactDraftGeneration{
		Title: "Weekly summary", Summary: "What shipped this week", Content: "# Weekly\nShipped v2.", Format: LibraryArtifactFormatMarkdown,
		Rationale: "Followed the source notes", Assumptions: []string{"The week ends on Friday"}, Generator: "fake", Model: "fake-model",
	}
}

func libraryStudioAvailability(t *testing.T, body map[string]any, key string) (bool, string, string) {
	t.Helper()
	section, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("drafting availability %q missing: %v", key, body)
	}
	available, _ := section["available"].(bool)
	mode, _ := section["mode"].(string)
	reason, _ := section["reason"].(string)
	return available, mode, reason
}

func TestLibraryConsoleDraftingAvailabilityFollowsGeneratorAndHosting(t *testing.T) {
	mux, token, _ := newLibraryConsole(t)
	recorder, body := doJSON(t, mux, token, http.MethodGet, "/api/library/drafting", "")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unconfigured drafting = %d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body)
	}
	for _, key := range []string{"skills", "artifacts"} {
		if available, mode, reason := libraryStudioAvailability(t, body, key); available || mode != "unavailable" || reason != "not_configured" {
			t.Fatalf("unconfigured %s availability=%v", key, body[key])
		}
	}

	mux, token, _ = newLibraryConsole(t, WithSkillDraftGenerator(&fakeLibraryDraftGenerator{}))
	_, body = doJSON(t, mux, token, http.MethodGet, "/api/library/drafting", "")
	if available, mode, reason := libraryStudioAvailability(t, body, "skills"); !available || mode != "direct" || reason != "" {
		t.Fatalf("skill-only skills availability=%v", body["skills"])
	}
	if available, mode, reason := libraryStudioAvailability(t, body, "artifacts"); available || mode != "unavailable" || reason != "not_configured" {
		t.Fatalf("skill-only artifacts availability=%v", body["artifacts"])
	}

	mux, token, _ = newLibraryConsole(t, WithSkillDraftGenerator(&fakeLibraryStudioGenerator{}))
	_, body = doJSON(t, mux, token, http.MethodGet, "/api/library/drafting", "")
	for _, key := range []string{"skills", "artifacts"} {
		if available, mode, _ := libraryStudioAvailability(t, body, key); !available || mode != "direct" {
			t.Fatalf("studio %s availability=%v", key, body[key])
		}
	}

	// A hosted Engine never generates directly even when a generator is wired.
	hostedMux, _, privateKey, now := newHostedLibraryImportConsole(t, WithSkillDraftGenerator(&fakeLibraryStudioGenerator{}))
	hosted := hostedNamespaceRequestWithHeaders(t, hostedMux, privateKey, now, "usr_owner", "owner", http.MethodGet, "/api/library/drafting", "", nil)
	if hosted.Code != http.StatusOK {
		t.Fatalf("hosted drafting = %d body=%s", hosted.Code, hosted.Body)
	}
	var hostedBody map[string]any
	if err := json.Unmarshal(hosted.Body.Bytes(), &hostedBody); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"skills", "artifacts"} {
		if available, mode, reason := libraryStudioAvailability(t, hostedBody, key); available || mode != "hosted" || reason != "platform" {
			t.Fatalf("hosted %s availability=%v", key, hostedBody[key])
		}
	}
}

func TestLibraryConsoleSkillDraftCarriesRationaleAndVersionProvenance(t *testing.T) {
	ctx := context.Background()
	prompt := "Draft a release notes skill."
	generator := &fakeLibraryDraftGenerator{result: SkillDraftGeneration{
		Name: "Release notes", Description: "Use when a release ships", Content: "## When to use\nAfter a release.\n## Inputs\n## Steps\n## Output\n## Guardrails",
		RequestedCapabilities: []string{"repo.read"}, Rationale: "Kept the outline short", Assumptions: []string{"Weekly releases", "English only"},
		Generator: "fake", Model: "fake-model",
	}}
	mux, token, store := newLibraryConsole(t, WithSkillDraftGenerator(generator))
	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/skill-drafts", `{"prompt":"`+prompt+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST skill draft = %d body=%s", recorder.Code, recorder.Body)
	}
	draftID, _ := response["id"].(string)
	assumptions, _ := response["assumptions"].([]any)
	if draftID == "" || response["rationale"] != "Kept the outline short" || len(assumptions) != 2 || assumptions[1] != "English only" {
		t.Fatalf("draft response=%v", response)
	}
	if stored, found := store.LibrarySkillDraft(ctx, draftID); !found || len(stored.Assumptions) != 2 || stored.Rationale != "Kept the outline short" {
		t.Fatalf("stored draft=%+v found=%v", stored, found)
	}

	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/skills", `{"draftId":"`+draftID+`","changelog":"Initial generated version"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST skill from draft = %d body=%s", recorder.Code, recorder.Body)
	}
	version, _ := response["version"].(map[string]any)
	provenance, _ := version["provenance"].(map[string]any)
	if version["changelog"] != "Initial generated version" || provenance["origin"] != "generated" || provenance["generator"] != "fake" ||
		provenance["model"] != "fake-model" || provenance["draftId"] != draftID || provenance["promptDigest"] != libraryDigest(prompt) {
		t.Fatalf("generated version=%v", version)
	}
	skill, _ := response["skill"].(map[string]any)
	skillID, _ := skill["id"].(string)

	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/versions", `{"content":"# v2","origin":"imported","changelog":"Imported from the wiki"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST imported version = %d body=%s", recorder.Code, recorder.Body)
	}
	provenance, _ = response["provenance"].(map[string]any)
	if provenance["origin"] != "imported" || response["changelog"] != "Imported from the wiki" {
		t.Fatalf("imported version=%v", response)
	}
	if _, hasDraft := provenance["draftId"]; hasDraft {
		t.Fatalf("imported version claims a draft: %v", provenance)
	}

	// A caller can never claim "generated" without naming a draft, and an
	// oversize changelog is rejected rather than truncated.
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/versions", `{"content":"# v3","origin":"generated"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("claimed generated origin = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/versions", `{"content":"# v3","changelog":"`+strings.Repeat("x", libraryMaxChangelogBytes+1)+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversize changelog = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/versions", `{"draftId":"libskd_missing","content":"# v3"}`)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing draft = %d body=%s", recorder.Code, recorder.Body)
	}

	// A version written without provenance keeps its legacy shape.
	legacy, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{SkillID: skillID, Content: "# legacy", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	recorder, response = doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+skillID, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET skill = %d body=%s", recorder.Code, recorder.Body)
	}
	versions, _ := response["versions"].([]any)
	var sawLegacy bool
	for _, raw := range versions {
		item, _ := raw.(map[string]any)
		if item["id"] != legacy.ID {
			continue
		}
		sawLegacy = true
		if _, has := item["provenance"]; has {
			t.Fatalf("legacy version reports provenance: %v", item)
		}
		if _, has := item["changelog"]; has {
			t.Fatalf("legacy version reports a changelog: %v", item)
		}
	}
	if !sawLegacy {
		t.Fatalf("legacy version absent from detail: %v", versions)
	}
}

func TestLibraryConsoleArtifactDraftUsesBoundedSourceContext(t *testing.T) {
	ctx := context.Background()
	generator := &fakeLibraryStudioGenerator{artifactResult: libraryStudioArtifactDraftResult()}
	mux, token, store := newLibraryConsole(t, WithSkillDraftGenerator(generator))
	source, sourceVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Source notes", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Notes\nShipped v2.", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}

	recorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize","sourceArtifactId":"`+source.ID+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("partial source tuple = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize","sourceArtifactId":"`+source.ID+`","sourceArtifactVersionId":"`+sourceVersion.ID+`","sourceArtifactDigest":"`+libraryDigest("other")+`"}`)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale source digest = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize","sourceArtifactId":"`+source.ID+`","sourceArtifactVersionId":"libartv_missing","sourceArtifactDigest":"`+sourceVersion.Digest+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown source version = %d body=%s", recorder.Code, recorder.Body)
	}
	if generator.artifactRequest.Prompt != "" {
		t.Fatalf("generator was called before the source was validated: %+v", generator.artifactRequest)
	}

	prompt := "Summarize the notes"
	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts",
		`{"title":"Weekly summary","prompt":"`+prompt+`","format":"markdown","sourceArtifactId":"`+source.ID+`","sourceArtifactVersionId":"`+sourceVersion.ID+`","sourceArtifactDigest":"sha256:`+sourceVersion.Digest+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST artifact draft = %d body=%s", recorder.Code, recorder.Body)
	}
	draftID, _ := response["id"].(string)
	assumptions, _ := response["assumptions"].([]any)
	if !strings.HasPrefix(draftID, "libad_") || response["origin"] != "generated" || response["generator"] != "fake" || response["format"] != "markdown" ||
		response["rationale"] != "Followed the source notes" || len(assumptions) != 1 || response["promptDigest"] != libraryDigest(prompt) ||
		response["sourceArtifactDigest"] != sourceVersion.Digest || response["sourceArtifactVersionId"] != sourceVersion.ID {
		t.Fatalf("artifact draft response=%v", response)
	}
	if generator.artifactRequest.SourceTitle != "Source notes" || generator.artifactRequest.SourceBody != "# Notes\nShipped v2." || generator.artifactRequest.Prompt != prompt || generator.artifactRequest.Format != LibraryArtifactFormatMarkdown {
		t.Fatalf("generator request=%+v", generator.artifactRequest)
	}
	if len(store.libraryRuns) != 0 || len(store.libraryArtifacts) != 1 {
		t.Fatalf("drafting created a run or artifact: runs=%d artifacts=%d", len(store.libraryRuns), len(store.libraryArtifacts))
	}

	// Creating from the draft copies its fields and citation, and records the
	// citation on a derived human run.
	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"draftId":"`+draftID+`","changelog":"From draft"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST artifact from draft = %d body=%s", recorder.Code, recorder.Body)
	}
	artifact, _ := response["artifact"].(map[string]any)
	version, _ := response["version"].(map[string]any)
	provenance, _ := version["provenance"].(map[string]any)
	runID, _ := artifact["runId"].(string)
	if artifact["origin"] != LibraryArtifactOriginHuman || artifact["title"] != "Weekly summary" || artifact["summary"] != "What shipped this week" ||
		artifact["sourceArtifactId"] != source.ID || artifact["sourceArtifactVersionId"] != sourceVersion.ID || runID == "" {
		t.Fatalf("artifact from draft=%v", artifact)
	}
	if version["body"] != "# Weekly\nShipped v2." || version["format"] != "markdown" || version["changelog"] != "From draft" ||
		provenance["origin"] != "generated" || provenance["draftId"] != draftID || provenance["model"] != "fake-model" {
		t.Fatalf("version from draft=%v", version)
	}
	run, found := store.LibraryRun(ctx, runID)
	if !found || run.Origin != LibraryRunOriginHuman || run.SourceArtifactID != source.ID || run.SourceArtifactDigest != sourceVersion.Digest ||
		run.SurfaceRef != libraryHumanConsoleSurfaceRef || run.ActorRef != "local-admin" || len(run.EffectiveCapabilities) != 0 {
		t.Fatalf("derived human run=%+v found=%v", run, found)
	}
	artifactID, _ := artifact["id"].(string)

	recorder, response = doJSON(t, mux, token, http.MethodGet, "/api/library/artifacts/"+source.ID, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET source = %d body=%s", recorder.Code, recorder.Body)
	}
	citedBy, _ := response["citedBy"].([]any)
	if len(citedBy) != 1 {
		t.Fatalf("citedBy=%v", response["citedBy"])
	}
	citation, _ := citedBy[0].(map[string]any)
	if citation["artifactId"] != artifactID || citation["versionId"] != sourceVersion.ID || citation["title"] != "Weekly summary" {
		t.Fatalf("citation=%v", citation)
	}
	recorder, response = doJSON(t, mux, token, http.MethodGet, "/api/library/artifacts/"+artifactID, "")
	if cited, _ := response["citedBy"].([]any); recorder.Code != http.StatusOK || len(cited) != 0 {
		t.Fatalf("uncited artifact detail = %d citedBy=%v", recorder.Code, response["citedBy"])
	}

	// An oversize source is refused as context rather than cut.
	large, largeVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Large", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: strings.Repeat("a", libraryArtifactDraftSourceContextMaxBytes+1), CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize","sourceArtifactId":"`+large.ID+`","sourceArtifactVersionId":"`+largeVersion.ID+`","sourceArtifactDigest":"`+largeVersion.Digest+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversize source context = %d body=%s", recorder.Code, recorder.Body)
	}

	// Oversize generator output is rejected, never truncated.
	generator.artifactResult.Rationale = strings.Repeat("r", libraryMaxRationaleBytes+1)
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize"}`)
	if recorder.Code != http.StatusBadRequest || len(store.libraryArtifactDrafts) != 1 {
		t.Fatalf("oversize rationale = %d drafts=%d body=%s", recorder.Code, len(store.libraryArtifactDrafts), recorder.Body)
	}

	// A skill-only generator leaves artifact drafting unavailable; a hosted
	// Engine defers to Platform.
	skillOnlyMux, skillOnlyToken, _ := newLibraryConsole(t, WithSkillDraftGenerator(&fakeLibraryDraftGenerator{}))
	recorder, _ = doJSON(t, skillOnlyMux, skillOnlyToken, http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize"}`)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("skill-only artifact draft = %d body=%s", recorder.Code, recorder.Body)
	}
	hostedMux, hostedStore, privateKey, now := newHostedLibraryImportConsole(t, WithSkillDraftGenerator(&fakeLibraryStudioGenerator{artifactResult: libraryStudioArtifactDraftResult()}))
	hosted := hostedNamespaceRequestWithHeaders(t, hostedMux, privateKey, now, "usr_owner", "owner", http.MethodPost, "/api/library/artifact-drafts", `{"prompt":"Summarize"}`, nil)
	if hosted.Code != http.StatusForbidden || len(hostedStore.libraryArtifactDrafts) != 0 {
		t.Fatalf("hosted direct artifact draft = %d drafts=%d body=%s", hosted.Code, len(hostedStore.libraryArtifactDrafts), hosted.Body)
	}
}

func TestLibraryConsoleHumanSourceCitationIsValidatedAgainstTheLibrary(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	source, sourceVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Source", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "source body", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	cite := func(versionID, digest, origin string) (*httptest.ResponseRecorder, map[string]any) {
		return doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Cites","origin":"`+origin+`","format":"text","body":"derived","sourceArtifactId":"`+source.ID+`","sourceArtifactVersionId":"`+versionID+`","sourceArtifactDigest":"`+digest+`"}`)
	}
	if recorder, _ := cite("libartv_missing", sourceVersion.Digest, LibraryArtifactOriginHuman); recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown version = %d body=%s", recorder.Code, recorder.Body)
	}
	if recorder, _ := cite(sourceVersion.ID, libraryDigest("moved"), LibraryArtifactOriginHuman); recorder.Code != http.StatusConflict {
		t.Fatalf("digest mismatch = %d body=%s", recorder.Code, recorder.Body)
	}
	if recorder, _ := cite(sourceVersion.ID, sourceVersion.Digest, LibraryArtifactOriginAutomation); recorder.Code != http.StatusBadRequest {
		t.Fatalf("automation citation = %d body=%s", recorder.Code, recorder.Body)
	}
	if len(store.libraryArtifacts) != 1 || len(store.libraryRuns) != 0 {
		t.Fatalf("rejected citations persisted state: artifacts=%d runs=%d", len(store.libraryArtifacts), len(store.libraryRuns))
	}
	recorder, response := cite(sourceVersion.ID, "SHA256:"+strings.ToUpper(sourceVersion.Digest), LibraryArtifactOriginHuman)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("valid citation = %d body=%s", recorder.Code, recorder.Body)
	}
	artifact, _ := response["artifact"].(map[string]any)
	runID, _ := artifact["runId"].(string)
	run, found := store.LibraryRun(ctx, runID)
	if !found || run.Origin != LibraryRunOriginHuman || run.SourceArtifactVersionID != sourceVersion.ID || run.SourceArtifactDigest != sourceVersion.Digest {
		t.Fatalf("human run=%+v found=%v", run, found)
	}
	if artifact["sourceArtifactDigest"] != sourceVersion.Digest {
		t.Fatalf("stored digest was not normalized: %v", artifact)
	}

	// The plain human path is unchanged: no derived run, manual provenance.
	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Plain","format":"text","body":"plain"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("plain artifact = %d body=%s", recorder.Code, recorder.Body)
	}
	artifact, _ = response["artifact"].(map[string]any)
	version, _ := response["version"].(map[string]any)
	provenance, _ := version["provenance"].(map[string]any)
	if _, hasRun := artifact["runId"]; hasRun || artifact["origin"] != LibraryArtifactOriginHuman || provenance["origin"] != "manual" {
		t.Fatalf("plain artifact=%v version=%v", artifact, version)
	}
}

func libraryStudioMediaRequest(t *testing.T, mux *http.ServeMux, token, artifactID, versionID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/library/artifacts/"+artifactID+"/media/"+versionID, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

func TestLibraryConsoleImageArtifactsUseMediaCanonicalisation(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	canonical, transport := libraryArtifactTestPNG(t)

	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Diagram","summary":"Two pixels","mimeType":"image/png","dataBase64":"`+transport+`","altText":"Two pixels"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST image artifact = %d body=%s", recorder.Code, recorder.Body)
	}
	artifact, _ := response["artifact"].(map[string]any)
	version, _ := response["version"].(map[string]any)
	artifactID, _ := artifact["id"].(string)
	versionID, _ := version["id"].(string)
	runID, _ := artifact["runId"].(string)
	if artifact["origin"] != LibraryArtifactOriginHuman || runID == "" || version["format"] != LibraryArtifactFormatImage || version["digest"] != canonical.Digest || version["body"] != "" {
		t.Fatalf("image artifact=%v version=%v", artifact, version)
	}
	if run, found := store.LibraryRun(ctx, runID); !found || run.Origin != LibraryRunOriginHuman || run.OutputDigest != canonical.Digest {
		t.Fatalf("image run=%+v found=%v", run, found)
	}
	media, found, err := store.LibraryArtifactMedia(ctx, artifactID, versionID)
	if err != nil || !found || media.AltText != "Two pixels" || media.MIMEType != libraryArtifactImageMIMEPNG {
		t.Fatalf("stored media=%+v found=%v err=%v", media, found, err)
	}

	// The list DTO names the media type and latest-version review state
	// without a body, and never exposes a maker for a human artifact.
	listRecorder, rows := doLibraryConsoleList(t, mux, token, "/api/library/artifacts", nil)
	if listRecorder.Code != http.StatusOK || len(rows) != 1 {
		t.Fatalf("artifact list = %d rows=%v", listRecorder.Code, rows)
	}
	row := rows[0]
	if row["format"] != "image" || row["mimeType"] != "image/png" || row["latestVersionId"] != versionID || row["redactionStatus"] != LibraryRedactionPending ||
		row["origin"] != LibraryArtifactOriginHuman || row["updatedAt"] == nil || row["createdAt"] == nil {
		t.Fatalf("list row=%v", row)
	}
	if _, has := row["agentSurfaceId"]; has {
		t.Fatalf("human artifact row names an agent surface: %v", row)
	}
	if _, has := row["reviewedAt"]; has {
		t.Fatalf("unreviewed row reports reviewedAt: %v", row)
	}
	latest, _ := row["latestVersion"].(map[string]any)
	if latest["id"] != versionID || latest["mimeType"] != "image/png" {
		t.Fatalf("list latest summary=%v", latest)
	}
	if _, has := latest["body"]; has {
		t.Fatalf("list leaked a body: %v", latest)
	}

	download := libraryStudioMediaRequest(t, mux, token, artifactID, versionID)
	if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(download.Header().Get("Content-Disposition"), "inline;") ||
		download.Header().Get("Cache-Control") != "private, no-store" || !bytes.Equal(download.Body.Bytes(), canonical.Bytes) {
		t.Fatalf("PNG download = %d headers=%v", download.Code, download.Header())
	}

	// Text never follows an image head and an image never follows text.
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+artifactID+"/versions", `{"format":"text","body":"not an image"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("text after image = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+artifactID+"/versions", `{"mimeType":"image/png","dataBase64":"`+transport+`","altText":"Again","changelog":"Re-exported"}`)
	if recorder.Code != http.StatusCreated || response["version"] != float64(2) || response["changelog"] != "Re-exported" || response["format"] != LibraryArtifactFormatImage {
		t.Fatalf("image version = %d body=%s", recorder.Code, recorder.Body)
	}
	if provenance, _ := response["provenance"].(map[string]any); provenance["origin"] != "manual" {
		t.Fatalf("image version provenance=%v", response["provenance"])
	}
	text, textVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{Title: "Text", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin"},
		LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "text", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+text.ID+"/versions", `{"mimeType":"image/png","dataBase64":"`+transport+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("image after text = %d body=%s", recorder.Code, recorder.Body)
	}
	if media := libraryStudioMediaRequest(t, mux, token, text.ID, textVersion.ID); media.Code != http.StatusNotFound {
		t.Fatalf("media for text version = %d", media.Code)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Broken","mimeType":"image/png","dataBase64":"not base64!"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid image bytes = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Mixed","mimeType":"image/png","dataBase64":"`+transport+`","body":"text too"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("image with body = %d body=%s", recorder.Code, recorder.Body)
	}

	// SVG is stored sanitized and only ever leaves as an attachment.
	svg := base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0, 0, 24, 24" fill="#ABC"><path d="M0 0 L24 24 Z"/></svg>`))
	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts", `{"title":"Icon","mimeType":"image/svg+xml","dataBase64":"`+svg+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST SVG artifact = %d body=%s", recorder.Code, recorder.Body)
	}
	artifact, _ = response["artifact"].(map[string]any)
	version, _ = response["version"].(map[string]any)
	svgID, _ := artifact["id"].(string)
	svgVersionID, _ := version["id"].(string)
	download = libraryStudioMediaRequest(t, mux, token, svgID, svgVersionID)
	if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(download.Header().Get("Content-Disposition"), "attachment;") ||
		!strings.Contains(download.Header().Get("Content-Security-Policy"), "sandbox") || !bytes.Contains(download.Body.Bytes(), []byte("#abc")) {
		t.Fatalf("SVG download = %d headers=%v body=%s", download.Code, download.Header(), download.Body)
	}
}

func TestLibraryConsoleReviewStoresBoundedComment(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{Title: "Reviewed", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin"},
		LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "customer name inside", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	recorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+artifact.ID+"/review", `{"artifactVersionId":"`+version.ID+`","status":"rejected","comment":"`+strings.Repeat("c", libraryMaxReviewCommentBytes+1)+`"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversize comment = %d body=%s", recorder.Code, recorder.Body)
	}
	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+artifact.ID+"/review", `{"artifactVersionId":"`+version.ID+`","status":"rejected","comment":"Remove the customer name"}`)
	if recorder.Code != http.StatusOK || response["redactionStatus"] != LibraryRedactionRejected || response["reviewComment"] != "Remove the customer name" || response["reviewedAt"] == nil {
		t.Fatalf("review = %d body=%s", recorder.Code, recorder.Body)
	}
	stored, found := store.LibraryArtifactVersion(ctx, artifact.ID, version.ID)
	if !found || stored.ReviewComment != "Remove the customer name" || stored.ReviewedBy != "local-admin" {
		t.Fatalf("stored review=%+v found=%v", stored, found)
	}
	if projected := libraryArtifactVersionMetadata(stored); projected.ReviewComment != "" || projected.Provenance != nil {
		t.Fatalf("metadata projection leaked review data: %+v", projected)
	}
	// Approving again without a comment clears the earlier note.
	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/artifacts/"+artifact.ID+"/review", `{"artifactVersionId":"`+version.ID+`","status":"approved"}`)
	if _, has := response["reviewComment"]; recorder.Code != http.StatusOK || has {
		t.Fatalf("re-review = %d body=%s", recorder.Code, recorder.Body)
	}
}

func TestLibraryConsoleSkillEvidenceListsNewestRunsAndTheirCorrelations(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-evidence", Mode: LibraryBindingModePin, PinnedVersionID: version.ID, CreatedBy: "actor-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder, response := doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+skill.ID+"/evidence", "")
	runs, _ := response["runs"].([]any)
	correlations, _ := response["correlations"].([]any)
	if recorder.Code != http.StatusOK || runs == nil || correlations == nil || len(runs) != 0 || len(correlations) != 0 {
		t.Fatalf("empty evidence = %d body=%s", recorder.Code, recorder.Body)
	}

	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	var newest LibraryRun
	for index := 0; index < librarySkillEvidenceRunLimit+2; index++ {
		newest, err = store.CreateLibraryRun(ctx, LibraryRun{
			Origin: LibraryRunOriginSkillRun, SkillID: skill.ID, SkillVersionID: version.ID, BindingID: binding.ID,
			ActorRef: "usr_host", SurfaceRef: "mcpc_host", Status: "succeeded", StartedAt: base.Add(time.Duration(index) * time.Second),
		})
		if err != nil {
			t.Fatalf("create skill run %d: %v", index, err)
		}
	}
	if _, err := store.CreateLibraryRun(ctx, LibraryRun{Origin: LibraryRunOriginHuman, ActorRef: "local-admin", SurfaceRef: "console", Status: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.libraryRunCorrelations = append(store.libraryRunCorrelations, &LibraryRunCorrelation{
		ID: "lrc_evidence", ClientID: "mcpc_host", ClientEpoch: "epoch-1", RunID: newest.ID, GatewayRequestID: "req_evidence",
		NonceHash: libraryDigest("nonce"), BundleDigest: libraryDigest("bundle"), RequestDigest: libraryDigest("request"), CreatedAt: time.Now().UTC(),
	})
	store.mu.Unlock()

	recorder, response = doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+skill.ID+"/evidence", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("evidence = %d body=%s", recorder.Code, recorder.Body)
	}
	runs, _ = response["runs"].([]any)
	if len(runs) != librarySkillEvidenceRunLimit {
		t.Fatalf("evidence runs=%d", len(runs))
	}
	first, _ := runs[0].(map[string]any)
	if first["id"] != newest.ID {
		t.Fatalf("evidence is not newest-first: %v", first)
	}
	for _, raw := range runs {
		run, _ := raw.(map[string]any)
		if run["origin"] != LibraryRunOriginSkillRun || run["skillId"] != skill.ID {
			t.Fatalf("evidence run=%v", run)
		}
	}
	correlations, _ = response["correlations"].([]any)
	if len(correlations) != 1 {
		t.Fatalf("correlations=%v", response["correlations"])
	}
	correlation, _ := correlations[0].(map[string]any)
	if correlation["runId"] != newest.ID || correlation["clientId"] != "mcpc_host" || correlation["clientEpoch"] != "epoch-1" || correlation["bundleDigest"] != libraryDigest("bundle") || correlation["createdAt"] == nil {
		t.Fatalf("correlation=%v", correlation)
	}
	for _, leaked := range []string{"nonce_hash", "nonceHash", "request_digest", "requestDigest"} {
		if _, has := correlation[leaked]; has {
			t.Fatalf("correlation leaked %s: %v", leaked, correlation)
		}
	}
	if recorder, _ := doJSON(t, mux, token, http.MethodGet, "/api/library/skills/libsk_missing/evidence", ""); recorder.Code != http.StatusNotFound {
		t.Fatalf("missing skill evidence = %d", recorder.Code)
	}
}

func TestLibraryConsoleArtifactDetailNamesTheMakingAgentSurface(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Maker", Subject: "usr_maker", CreatedBy: "usr_maker"})
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, _, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{Title: "Agent made", Origin: LibraryArtifactOriginAgentDirect},
		LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# by agent"})
	if err != nil {
		t.Fatal(err)
	}
	recorder, response := doJSON(t, mux, token, http.MethodGet, "/api/library/artifacts/"+artifact.ID, "")
	if recorder.Code != http.StatusOK || response["agentSurfaceId"] != client.ID || response["origin"] != LibraryArtifactOriginAgentDirect {
		t.Fatalf("detail = %d body=%s", recorder.Code, recorder.Body)
	}
	_, rows := doLibraryConsoleList(t, mux, token, "/api/library/artifacts", nil)
	if len(rows) != 1 || rows[0]["agentSurfaceId"] != client.ID || rows[0]["latestVersionId"] == nil {
		t.Fatalf("list rows=%v", rows)
	}
}

func platformArtifactDraftImportRequest(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, body []byte, userID, role string) *http.Request {
	t.Helper()
	path := "/api/library/artifact-drafts/platform-import"
	claims := actorClaimsForTest(now, http.MethodPost, path, body)
	claims.UserID, claims.Role = userID, role
	request := actorRequest(http.MethodPost, path, body, signActorAssertionForTest(t, privateKey, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	return request
}

func TestHostedPlatformArtifactDraftImportIsIdempotentAndBounded(t *testing.T) {
	ctx := context.Background()
	mux, store, privateKey, now := newHostedLibraryImportConsole(t)
	source, sourceVersion, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{Title: "Source", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner"},
		LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Source", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	promptDigest := libraryDigest("private broker prompt")
	body := []byte(`{"requestId":"ardr_0123456789abcdef","format":"markdown","sourceArtifactId":"` + source.ID + `","sourceArtifactVersionId":"` + sourceVersion.ID + `","sourceArtifactDigest":"sha256:` + sourceVersion.Digest + `","candidate":{"title":"Weekly","summary":"Sum","content":"# Weekly","provider":"kimi-platform","model":"kimi-k2.7-code","promptDigest":"` + promptDigest + `","rationale":"Short","assumptions":["Week ends Friday"]}}`)

	first := httptest.NewRecorder()
	mux.ServeHTTP(first, platformArtifactDraftImportRequest(t, privateKey, now, body, "usr_owner", "owner"))
	if first.Code != http.StatusCreated || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first artifact import = %d headers=%v body=%s", first.Code, first.Header(), first.Body)
	}
	var firstResponse struct {
		Draft    LibraryArtifactDraft `json:"draft"`
		Replayed bool                 `json:"replayed"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	draft := firstResponse.Draft
	if firstResponse.Replayed || draft.ID == "" || draft.Origin != LibraryDraftOriginGenerated || draft.Generator != "kimi-platform" || draft.Model != "kimi-k2.7-code" ||
		draft.Format != LibraryArtifactFormatMarkdown || draft.PromptDigest != promptDigest || draft.SourceArtifactDigest != sourceVersion.Digest ||
		draft.Rationale != "Short" || len(draft.Assumptions) != 1 || draft.CreatedBy != "usr_owner" {
		t.Fatalf("imported artifact draft=%+v", draft)
	}
	// The wire contract is closed: the draft object carries only these keys.
	var raw struct {
		Draft map[string]any `json:"draft"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{}
	for _, key := range []string{"id", "title", "summary", "content", "format", "rationale", "assumptions", "origin", "generator", "model", "promptDigest", "sourceArtifactId", "sourceArtifactVersionId", "sourceArtifactDigest", "createdBy", "createdAt"} {
		allowed[key] = struct{}{}
	}
	for key := range raw.Draft {
		if _, ok := allowed[key]; !ok {
			t.Fatalf("artifact draft response carries unexpected key %q", key)
		}
	}
	if len(store.libraryArtifacts) != 1 || len(store.libraryRuns) != 0 || len(store.libraryArtifactDrafts) != 1 {
		t.Fatalf("import created unauthorized state: artifacts=%d runs=%d drafts=%d", len(store.libraryArtifacts), len(store.libraryRuns), len(store.libraryArtifactDrafts))
	}

	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, platformArtifactDraftImportRequest(t, privateKey, now, body, "usr_owner", "owner"))
	var replayResponse struct {
		Draft    LibraryArtifactDraft `json:"draft"`
		Replayed bool                 `json:"replayed"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResponse); err != nil {
		t.Fatal(err)
	}
	if replay.Code != http.StatusOK || !replayResponse.Replayed || replayResponse.Draft.ID != draft.ID || len(store.libraryArtifactDrafts) != 1 || len(store.libraryArtifactDraftImports) != 1 {
		t.Fatalf("replay = %d body=%s drafts=%d imports=%d", replay.Code, replay.Body, len(store.libraryArtifactDrafts), len(store.libraryArtifactDraftImports))
	}

	conflict := httptest.NewRecorder()
	mux.ServeHTTP(conflict, platformArtifactDraftImportRequest(t, privateKey, now, bytes.Replace(body, []byte("# Weekly"), []byte("# Changed"), 1), "usr_owner", "owner"))
	if conflict.Code != http.StatusConflict || len(store.libraryArtifactDrafts) != 1 {
		t.Fatalf("conflicting import = %d body=%s", conflict.Code, conflict.Body)
	}
	strict := httptest.NewRecorder()
	mux.ServeHTTP(strict, platformArtifactDraftImportRequest(t, privateKey, now, bytes.Replace(body, []byte(`"rationale"`), []byte(`"surprise":1,"rationale"`), 1), "usr_owner", "owner"))
	if strict.Code != http.StatusBadRequest {
		t.Fatalf("unknown field import = %d body=%s", strict.Code, strict.Body)
	}
	stale := httptest.NewRecorder()
	mux.ServeHTTP(stale, platformArtifactDraftImportRequest(t, privateKey, now, bytes.Replace(bytes.Replace(body, []byte(sourceVersion.Digest), []byte(libraryDigest("moved")), 1), []byte("ardr_0123456789abcdef"), []byte("ardr_stale_0123456789"), 1), "usr_owner", "owner"))
	if stale.Code != http.StatusNotFound || len(store.libraryArtifactDrafts) != 1 {
		t.Fatalf("stale source import = %d body=%s", stale.Code, stale.Body)
	}

	// Self-hosted Engines have no Platform to import from.
	localMux, localToken, _ := newLibraryConsole(t)
	if recorder, _ := doJSON(t, localMux, localToken, http.MethodPost, "/api/library/artifact-drafts/platform-import", string(body)); recorder.Code != http.StatusForbidden {
		t.Fatalf("self-hosted artifact import = %d body=%s", recorder.Code, recorder.Body)
	}

	// A skill candidate now carries rationale and assumptions through the
	// same strict decoder and idempotency digest.
	skillBody := []byte(`{"requestId":"draftreq_rationale_0123","requestedCapabilities":["repo.read"],"candidate":{"name":"Review","description":"Use when reviewing","content":"## When to use","provider":"kimi-platform","model":"kimi-k2.7-code","promptDigest":"` + promptDigest + `","rationale":"Because","assumptions":["One","Two"]}}`)
	skillImport := httptest.NewRecorder()
	mux.ServeHTTP(skillImport, platformDraftImportRequest(t, privateKey, now, skillBody, "usr_owner", "owner"))
	var skillResponse struct {
		Draft LibrarySkillDraft `json:"draft"`
	}
	if err := json.Unmarshal(skillImport.Body.Bytes(), &skillResponse); err != nil {
		t.Fatal(err)
	}
	if skillImport.Code != http.StatusCreated || skillResponse.Draft.Rationale != "Because" || len(skillResponse.Draft.Assumptions) != 2 {
		t.Fatalf("skill import with rationale = %d body=%s", skillImport.Code, skillImport.Body)
	}
	skillConflict := httptest.NewRecorder()
	mux.ServeHTTP(skillConflict, platformDraftImportRequest(t, privateKey, now, bytes.Replace(skillBody, []byte(`"Two"`), []byte(`"Three"`), 1), "usr_owner", "owner"))
	if skillConflict.Code != http.StatusConflict {
		t.Fatalf("skill import with changed assumptions = %d body=%s", skillConflict.Code, skillConflict.Body)
	}
}
