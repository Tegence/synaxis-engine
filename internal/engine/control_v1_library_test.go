package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// controlLibraryFixture is the FileStore scenario behind the HTTP tests: two
// registrations for usr_operator, one for usr_other, an artifact each side
// owns directly, a human-authored artifact granted to usr_operator at v1
// while its head moved to v2, a revoked grant, and a grant to the other
// subject only.
type controlLibraryFixture struct {
	codex, codex2, other MCPClient

	owned, othersOwned, shared, stale, othersGranted LibraryArtifact

	ownedV1, othersV1, sharedV1, sharedV2, staleV1, othersGrantedV1 LibraryArtifactVersion

	sharedGrant, staleGrant, othersGrant LibraryArtifactGrant
}

func newControlLibraryFixture(t *testing.T, store *FileStore) controlLibraryFixture {
	t.Helper()
	ctx := context.Background()
	var f controlLibraryFixture
	client := func(name, subject string) MCPClient {
		t.Helper()
		created, err := store.CreateMCPClient(ctx, MCPClient{Name: name, Subject: subject, CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatalf("CreateMCPClient %s: %v", name, err)
		}
		return created
	}
	f.codex = client("Codex", "usr_operator")
	f.codex2 = client("Codex Two", "usr_operator")
	f.other = client("Other Agent", "usr_other")

	agentArtifact := func(owner MCPClient, title, body string) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		_, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{
			Title: title, Summary: "summary of " + title, Origin: LibraryArtifactOriginAgentDirect,
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: body})
		if err != nil {
			t.Fatalf("CreateLibraryMCPClientArtifactWithInitialVersion %s: %v", title, err)
		}
		return artifact, version
	}
	humanArtifact := func(title, body string) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: title, Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: body, CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatalf("CreateLibraryArtifactWithInitialVersion %s: %v", title, err)
		}
		return artifact, version
	}
	grant := func(artifact LibraryArtifact, version LibraryArtifactVersion, recipient MCPClient) LibraryArtifactGrant {
		t.Helper()
		created, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
			ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
			AgentSurfaceID: recipient.ID, CreatedBy: "usr_owner",
		})
		if err != nil {
			t.Fatalf("CreateLibraryArtifactGrant %s: %v", artifact.Title, err)
		}
		return created
	}

	f.owned, f.ownedV1 = agentArtifact(f.codex, "Owned notes", "# owned body")
	f.othersOwned, f.othersV1 = agentArtifact(f.other, "Other notes", "# other body")
	f.shared, f.sharedV1 = humanArtifact("Shared brief", "shared v1 body")
	var err error
	f.sharedV2, err = store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: f.shared.ID, Format: LibraryArtifactFormatText, Body: "shared v2 body", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactVersion: %v", err)
	}
	f.sharedGrant = grant(f.shared, f.sharedV1, f.codex)
	f.stale, f.staleV1 = humanArtifact("Stale brief", "stale body")
	f.staleGrant = grant(f.stale, f.staleV1, f.codex)
	if f.staleGrant, err = store.RevokeLibraryArtifactGrant(ctx, f.stale.ID, f.staleGrant.ID, "usr_owner", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeLibraryArtifactGrant: %v", err)
	}
	f.othersGranted, f.othersGrantedV1 = humanArtifact("Other brief", "other brief body")
	f.othersGrant = grant(f.othersGranted, f.othersGrantedV1, f.other)
	return f
}

func controlLibraryRequest(t *testing.T, mux *http.ServeMux, key ed25519.PrivateKey, now time.Time, userID, role, method, requestPath, body, subject string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if subject != "" {
		headers[controlSubjectHeader] = subject
	}
	return hostedNamespaceRequestWithHeaders(t, mux, key, now, userID, role, method, requestPath, body, headers)
}

func decodeControlLibraryPage(t *testing.T, response *httptest.ResponseRecorder) controlLibraryArtifactPageDTO {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", response.Code, response.Body)
	}
	if response.Header().Get(controlRequestIDHeader) == "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("control response missing envelope headers: %v", response.Header())
	}
	var page controlLibraryArtifactPageDTO
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v body=%s", err, response.Body)
	}
	return page
}

func controlLibraryPageByID(page controlLibraryArtifactPageDTO) map[string]controlLibraryArtifactDTO {
	out := make(map[string]controlLibraryArtifactDTO, len(page.Artifacts))
	for _, artifact := range page.Artifacts {
		out[artifact.ID] = artifact
	}
	return out
}

func decodeControlLibraryGrant(t *testing.T, response *httptest.ResponseRecorder, want int) controlLibraryGrantDTO {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status=%d body=%s; want %d", response.Code, response.Body, want)
	}
	var dto controlLibraryGrantDTO
	if err := json.Unmarshal(response.Body.Bytes(), &dto); err != nil {
		t.Fatalf("decode grant: %v body=%s", err, response.Body)
	}
	return dto
}

func TestControlV1LibraryArtifactsSubjectScopeShowsOwnedAndGranted(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	f := newControlLibraryFixture(t, store)
	list := "/control/v1/library/artifacts"

	page := decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, list, "", "usr_operator"))
	if len(page.Artifacts) != 2 || page.NextCursor != "" {
		t.Fatalf("operator scope=%+v", page)
	}
	// The shared artifact's head moved after the owned artifact was written,
	// so it is the most recently updated row.
	if page.Artifacts[0].ID != f.shared.ID || page.Artifacts[1].ID != f.owned.ID {
		t.Fatalf("scope order=%+v", page.Artifacts)
	}
	shared, owned := page.Artifacts[0], page.Artifacts[1]
	if shared.Access != LibraryControlArtifactAccessGranted || shared.AgentSurfaceID != "" || shared.Format != LibraryArtifactFormatText || shared.Origin != LibraryArtifactOriginHuman ||
		shared.LatestVersion.ID != f.sharedV2.ID || shared.LatestVersion.Version != 2 || shared.LatestVersion.Digest != f.sharedV2.Digest ||
		shared.GrantedVersion == nil || shared.GrantedVersion.ID != f.sharedV1.ID || shared.GrantedVersion.Version != 1 || shared.GrantedVersion.Digest != f.sharedV1.Digest ||
		shared.UpdatedAt != f.sharedV2.CreatedAt.UTC().Format(time.RFC3339Nano) || shared.Title != "Shared brief" {
		t.Fatalf("shared row=%+v", shared)
	}
	if owned.Access != LibraryControlArtifactAccessOwned || owned.AgentSurfaceID != f.codex.ID || owned.GrantedVersion != nil || owned.Format != LibraryArtifactFormatMarkdown ||
		owned.LatestVersion.ID != f.ownedV1.ID || owned.Summary != "summary of Owned notes" || owned.UpdatedAt != f.ownedV1.CreatedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("owned row=%+v", owned)
	}
	// Never a body, author, or provenance identifier; only the documented keys.
	raw := controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", "usr_operator").Body.String()
	for _, leaked := range []string{"owned body", "shared v1 body", "shared v2 body", "createdBy", "runId", "\"body\""} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("scoped list leaked %q: %s", leaked, raw)
		}
	}
	var rawPage struct {
		Artifacts []map[string]any `json:"artifacts"`
	}
	if err := json.Unmarshal([]byte(raw), &rawPage); err != nil {
		t.Fatal(err)
	}
	for _, row := range rawPage.Artifacts {
		for field := range row {
			switch field {
			case "id", "title", "summary", "format", "origin", "agentSurfaceId", "access", "latestVersion", "grantedVersion", "createdAt", "updatedAt":
			default:
				t.Fatalf("scoped list exposed field %q in %v", field, row)
			}
		}
	}

	// The other subject sees only its own registration's artifacts; a
	// subject without registrations sees nothing.
	otherPage := controlLibraryPageByID(decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, "usr_admin", "admin", http.MethodGet, list, "", "usr_other")))
	if len(otherPage) != 2 || otherPage[f.othersOwned.ID].Access != LibraryControlArtifactAccessOwned || otherPage[f.othersGranted.ID].Access != LibraryControlArtifactAccessGranted {
		t.Fatalf("other scope=%+v", otherPage)
	}
	if empty := decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", "usr_nobody")); len(empty.Artifacts) != 0 || empty.NextCursor != "" {
		t.Fatalf("unknown subject scope=%+v", empty)
	}

	// Without a subject an administrator reads the whole catalog's metadata:
	// no access class, but the surface key on surface-owned artifacts.
	full := controlLibraryPageByID(decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", "")))
	if len(full) != 5 || full[f.owned.ID].Access != "" || full[f.owned.ID].AgentSurfaceID != f.codex.ID || full[f.shared.ID].GrantedVersion != nil || full[f.stale.ID].ID == "" {
		t.Fatalf("unscoped list=%+v", full)
	}

	// The subject header must be exactly one actor identifier, and the
	// service principal's own identifier is never a Library subject.
	for _, bad := range []string{"bad subject", " usr_operator", platformServiceActorID, strings.Repeat("u", 201)} {
		expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", bad), http.StatusBadRequest, controlCodeValidationFailed)
	}
	doubled := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", nil)
	if doubled.Code != http.StatusOK {
		t.Fatalf("baseline=%d", doubled.Code)
	}
	request := httptest.NewRequest(http.MethodGet, list, nil)
	claims := actorClaimsForTest(now, http.MethodGet, list, nil)
	claims.UserID, claims.Role = "usr_owner", "owner"
	request = actorRequest(http.MethodGet, list, nil, signActorAssertionForTest(t, key, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	request.Header.Add(controlSubjectHeader, "usr_operator")
	request.Header.Add(controlSubjectHeader, "usr_other")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	expectControlProblem(t, response, http.StatusBadRequest, controlCodeValidationFailed)

	// Revoking the registration that owned and was granted the artifacts
	// removes them from the subject's scope even though a second, active
	// registration for the same subject still exists.
	if _, err := store.RevokeMCPClient(context.Background(), f.codex.ID, "usr_owner", MCPClientPrecondition{ID: f.codex.ID, Revision: f.codex.Revision}); err != nil {
		t.Fatalf("RevokeMCPClient: %v", err)
	}
	if after := decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, list, "", "usr_operator")); len(after.Artifacts) != 0 {
		t.Fatalf("scope after revocation=%+v", after)
	}
}

func TestControlV1LibraryArtifactDetailAndVersionBodyHonorSubjectScope(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	f := newControlLibraryFixture(t, store)
	detail := func(user, role, artifactID, subject string) *httptest.ResponseRecorder {
		return controlLibraryRequest(t, mux, key, now, user, role, http.MethodGet, "/control/v1/library/artifacts/"+artifactID, "", subject)
	}
	decodeDetail := func(response *httptest.ResponseRecorder) controlLibraryArtifactDetailDTO {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("detail status=%d body=%s", response.Code, response.Body)
		}
		var dto controlLibraryArtifactDetailDTO
		if err := json.Unmarshal(response.Body.Bytes(), &dto); err != nil {
			t.Fatal(err)
		}
		return dto
	}

	// A grantee sees the artifact, its version metadata, and only the grants
	// held by its own registrations.
	response := detail(platformServiceActorID, "service", f.shared.ID, "usr_operator")
	shared := decodeDetail(response)
	if shared.Access != LibraryControlArtifactAccessGranted || shared.GrantedVersion == nil || shared.GrantedVersion.ID != f.sharedV1.ID || shared.LatestVersion.ID != f.sharedV2.ID ||
		len(shared.Versions) != 2 || shared.Versions[0].ID != f.sharedV1.ID || shared.Versions[0].Digest != f.sharedV1.Digest || shared.Versions[0].SizeBytes != f.sharedV1.SizeBytes ||
		shared.Versions[0].RedactionStatus != LibraryRedactionPending || shared.Versions[0].Format != LibraryArtifactFormatText || shared.Versions[1].Version != 2 ||
		len(shared.Grants) != 1 || shared.Grants[0].ID != f.sharedGrant.ID || shared.Grants[0].RecipientClientID != f.codex.ID || shared.Grants[0].VersionID != f.sharedV1.ID ||
		shared.Grants[0].Digest != f.sharedV1.Digest || shared.Grants[0].State != "active" || shared.Grants[0].RevokedAt != "" {
		t.Fatalf("shared detail=%+v", shared)
	}
	if body := response.Body.String(); strings.Contains(body, "shared v1 body") || strings.Contains(body, "shared v2 body") || strings.Contains(body, "\"body\"") || strings.Contains(body, "createdBy") {
		t.Fatalf("detail leaked content: %s", body)
	}
	// Unscoped administrators read every grant, including revoked ones.
	stale := decodeDetail(detail("usr_owner", "owner", f.stale.ID, ""))
	if stale.Access != "" || len(stale.Grants) != 1 || stale.Grants[0].State != "revoked" || stale.Grants[0].RevokedAt == "" || stale.Grants[0].ID != f.staleGrant.ID {
		t.Fatalf("stale detail=%+v", stale)
	}
	owned := decodeDetail(detail("usr_admin", "admin", f.owned.ID, "usr_operator"))
	if owned.Access != LibraryControlArtifactAccessOwned || owned.AgentSurfaceID != f.codex.ID || owned.GrantedVersion != nil || len(owned.Versions) != 1 {
		t.Fatalf("owned detail=%+v", owned)
	}
	// Out-of-scope and unknown artifacts are the same 404 to a scoped read;
	// the unscoped read still resolves the artifact.
	problemOther := expectControlProblem(t, detail("usr_owner", "owner", f.othersOwned.ID, "usr_operator"), http.StatusNotFound, controlCodeNotFound)
	problemStale := expectControlProblem(t, detail("usr_owner", "owner", f.stale.ID, "usr_operator"), http.StatusNotFound, controlCodeNotFound)
	problemMissing := expectControlProblem(t, detail("usr_owner", "owner", "libart_missing", "usr_operator"), http.StatusNotFound, controlCodeNotFound)
	if problemOther.Title != problemMissing.Title || problemStale.Title != problemMissing.Title {
		t.Fatalf("scoped 404 titles differ: %q %q %q", problemOther.Title, problemStale.Title, problemMissing.Title)
	}
	if got := decodeDetail(detail("usr_owner", "owner", f.othersOwned.ID, "")); got.AgentSurfaceID != f.other.ID {
		t.Fatalf("unscoped other detail=%+v", got)
	}

	version := func(user, role, artifactID, versionID, subject string) *httptest.ResponseRecorder {
		return controlLibraryRequest(t, mux, key, now, user, role, http.MethodGet, "/control/v1/library/artifacts/"+artifactID+"/versions/"+versionID, "", subject)
	}
	// Exact grant: the pinned version is readable, the newer head is not.
	response = version(platformServiceActorID, "service", f.shared.ID, f.sharedV1.ID, "usr_operator")
	if response.Code != http.StatusOK {
		t.Fatalf("granted version=%d body=%s", response.Code, response.Body)
	}
	var read controlLibraryVersionBodyDTO
	if err := json.Unmarshal(response.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if read.Body != "shared v1 body" || read.Version.ID != f.sharedV1.ID || read.Version.Digest != f.sharedV1.Digest || read.Version.Version != 1 || read.Version.Format != LibraryArtifactFormatText {
		t.Fatalf("granted read=%+v", read)
	}
	if strings.Contains(response.Body.String(), "createdBy") || strings.Contains(response.Body.String(), "reviewedBy") {
		t.Fatalf("version read leaked actor refs: %s", response.Body)
	}
	if response = version("usr_owner", "owner", f.owned.ID, f.ownedV1.ID, "usr_operator"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "# owned body") {
		t.Fatalf("owned version=%d body=%s", response.Code, response.Body)
	}
	titles := map[string]struct{}{}
	for name, denied := range map[string]*httptest.ResponseRecorder{
		"newer head":        version("usr_owner", "owner", f.shared.ID, f.sharedV2.ID, "usr_operator"),
		"other's artifact":  version("usr_owner", "owner", f.othersOwned.ID, f.othersV1.ID, "usr_operator"),
		"revoked grant":     version("usr_owner", "owner", f.stale.ID, f.staleV1.ID, "usr_operator"),
		"foreign subject":   version("usr_owner", "owner", f.shared.ID, f.sharedV1.ID, "usr_other"),
		"unknown version":   version("usr_owner", "owner", f.shared.ID, "libartv_missing", "usr_operator"),
		"unknown artifact":  version("usr_owner", "owner", "libart_missing", f.sharedV1.ID, "usr_operator"),
		"no registrations":  version("usr_owner", "owner", f.shared.ID, f.sharedV1.ID, "usr_nobody"),
		"version of other":  version("usr_owner", "owner", f.shared.ID, f.ownedV1.ID, "usr_operator"),
		"unscoped admin":    version("usr_owner", "owner", f.shared.ID, f.sharedV1.ID, ""),
		"service unscoped ": version(platformServiceActorID, "service", f.shared.ID, f.sharedV1.ID, ""),
	} {
		if strings.Contains(name, "unscoped") {
			expectControlProblem(t, denied, http.StatusBadRequest, controlCodeValidationFailed)
			continue
		}
		problem := expectControlProblem(t, denied, http.StatusNotFound, controlCodeNotFound)
		titles[problem.Title] = struct{}{}
		if strings.Contains(denied.Body.String(), "body") && strings.Contains(denied.Body.String(), "shared") {
			t.Fatalf("%s leaked content: %s", name, denied.Body)
		}
	}
	if len(titles) != 1 {
		t.Fatalf("version 404 titles form an oracle: %v", titles)
	}
}

func TestControlV1LibraryGrantCreateValidatesSourceAndConverges(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	f := newControlLibraryFixture(t, store)
	ctx := context.Background()
	grants := "/control/v1/library/artifacts/" + f.shared.ID + "/grants"
	post := func(user, role, body string) *httptest.ResponseRecorder {
		return controlLibraryRequest(t, mux, key, now, user, role, http.MethodPost, grants, body, "")
	}
	revokedClient, err := store.CreateMCPClient(ctx, MCPClient{Name: "Retired", Subject: "usr_retired", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeMCPClient(ctx, revokedClient.ID, "usr_owner", MCPClientPrecondition{ID: revokedClient.ID, Revision: revokedClient.Revision}); err != nil {
		t.Fatal(err)
	}
	body := func(recipient, versionID, digest string, extra string) string {
		return `{"recipientClientId":"` + recipient + `","versionId":"` + versionID + `","digest":"` + digest + `"` + extra + `}`
	}

	// Source fences: a reviewed version that is no longer the head, or a
	// digest that does not describe the version, cannot be granted.
	expectControlProblem(t, post("usr_owner", "owner", body(f.codex2.ID, f.sharedV1.ID, f.sharedV1.Digest, "")), http.StatusConflict, controlCodeGrantSourceChanged)
	expectControlProblem(t, post("usr_owner", "owner", body(f.codex2.ID, f.sharedV2.ID, f.sharedV1.Digest, "")), http.StatusConflict, controlCodeGrantSourceChanged)
	// Shape failures and lookups.
	for _, invalid := range []string{
		body(f.codex2.ID, f.sharedV2.ID, "not-a-digest", ""),
		body("", f.sharedV2.ID, f.sharedV2.Digest, ""),
		body(f.codex2.ID, "", f.sharedV2.Digest, ""),
		body(f.codex2.ID, f.sharedV2.ID, f.sharedV2.Digest, `,"createdBy":"has space"`),
		`{"recipientClientId":`,
	} {
		expectControlProblem(t, post("usr_owner", "owner", invalid), http.StatusBadRequest, controlCodeValidationFailed)
	}
	expectControlProblem(t, post("usr_owner", "owner", body(f.codex2.ID, "libartv_missing", f.sharedV2.Digest, "")), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, post("usr_owner", "owner", body("mcpcli_missing", f.sharedV2.ID, f.sharedV2.Digest, "")), http.StatusNotFound, controlCodeNotFound)
	// A recipient is the exact registration ID, never its endpoint slug.
	expectControlProblem(t, post("usr_owner", "owner", body(f.codex2.Slug, f.sharedV2.ID, f.sharedV2.Digest, "")), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, post("usr_owner", "owner", body(revokedClient.ID, f.sharedV2.ID, f.sharedV2.Digest, "")), http.StatusConflict, controlCodeClientRevoked)
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/library/artifacts/libart_missing/grants", body(f.codex2.ID, f.sharedV2.ID, f.sharedV2.Digest, ""), ""), http.StatusNotFound, controlCodeNotFound)
	if stored, err := store.LibraryArtifactGrants(ctx, f.shared.ID); err != nil || len(stored) != 1 {
		t.Fatalf("rejected requests created grants: %d err=%v", len(stored), err)
	}

	// The head version with the recorded digest is granted; the reviewer the
	// caller names is recorded as the creator.
	created := decodeControlLibraryGrant(t, post(platformServiceActorID, "service", body(f.codex2.ID, f.sharedV2.ID, f.sharedV2.Digest, `,"createdBy":"usr_reviewer"`)), http.StatusCreated)
	if !strings.HasPrefix(created.ID, "libartg_") || created.RecipientClientID != f.codex2.ID || created.VersionID != f.sharedV2.ID || created.Digest != f.sharedV2.Digest || created.State != "active" || created.CreatedAt == "" || created.RevokedAt != "" {
		t.Fatalf("created grant=%+v", created)
	}
	if stored, err := store.LibraryArtifactGrants(ctx, f.shared.ID); err != nil || len(stored) != 2 || stored[1].ID != created.ID || stored[1].CreatedBy != "usr_reviewer" {
		t.Fatalf("stored grants=%+v err=%v", stored, err)
	}
	// A keyless retry of the identical request converges on the stored grant.
	if replayed := decodeControlLibraryGrant(t, post(platformServiceActorID, "service", body(f.codex2.ID, f.sharedV2.ID, f.sharedV2.Digest, `,"createdBy":"usr_reviewer"`)), http.StatusOK); replayed.ID != created.ID {
		t.Fatalf("keyless replay=%+v; want %+v", replayed, created)
	}
	// A different version for the same recipient is a conflict, even when
	// the caller allows a non-head version.
	expectControlProblem(t, post("usr_owner", "owner", body(f.codex2.ID, f.sharedV1.ID, f.sharedV1.Digest, `,"allowNonHead":true`)), http.StatusConflict, controlCodeAlreadyExists)
	// allowNonHead permits pinning an older version for a recipient without
	// a live grant; without it the same request stays fenced.
	older := decodeControlLibraryGrant(t, post("usr_admin", "admin", body(f.other.ID, f.sharedV1.ID, f.sharedV1.Digest, `,"allowNonHead":true`)), http.StatusCreated)
	if older.VersionID != f.sharedV1.ID || older.RecipientClientID != f.other.ID {
		t.Fatalf("older grant=%+v", older)
	}

	// Idempotency-Key replay returns the first result verbatim; a different
	// body under the same key is a conflict.
	keyed := func(body, idempotencyKey string) *httptest.ResponseRecorder {
		return hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/library/artifacts/"+f.owned.ID+"/grants", body, map[string]string{controlIdempotencyKeyHeader: idempotencyKey})
	}
	ownedBody := body(f.other.ID, f.ownedV1.ID, f.ownedV1.Digest, "")
	first := decodeControlLibraryGrant(t, keyed(ownedBody, "grant-1"), http.StatusCreated)
	replay := keyed(ownedBody, "grant-1")
	if replay.Code != http.StatusCreated || replay.Header().Get(controlIdempotentReplayHeader) != "true" || !strings.Contains(replay.Body.String(), first.ID) {
		t.Fatalf("keyed replay=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body)
	}
	expectControlProblem(t, keyed(body(f.codex2.ID, f.ownedV1.ID, f.ownedV1.Digest, ""), "grant-1"), http.StatusConflict, controlCodeIdempotencyKeyConflict)
	if stored, err := store.LibraryArtifactGrants(ctx, f.owned.ID); err != nil || len(stored) != 1 {
		t.Fatalf("keyed retry created %d grants err=%v", len(stored), err)
	}

	// Two registrations of one subject now hold different pinned versions;
	// the scope reports the highest one and the head separately.
	scoped := controlLibraryPageByID(decodeControlLibraryPage(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/library/artifacts", "", "usr_operator")))
	if row := scoped[f.shared.ID]; row.Access != LibraryControlArtifactAccessGranted || row.GrantedVersion == nil || row.GrantedVersion.ID != f.sharedV2.ID || row.LatestVersion.ID != f.sharedV2.ID {
		t.Fatalf("scope after second grant=%+v", row)
	}
	versionPath := "/control/v1/library/artifacts/" + f.shared.ID + "/versions/" + f.sharedV2.ID
	if response := controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, versionPath, "", "usr_operator"); response.Code != http.StatusOK {
		t.Fatalf("v2 read after grant=%d body=%s", response.Code, response.Body)
	}

	// Revocation converges and keeps the original revoker and time.
	revokePath := grants + "/" + created.ID + "/revoke"
	revoked := decodeControlLibraryGrant(t, controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, revokePath, `{"reason":"review reopened"}`, ""), http.StatusOK)
	if revoked.ID != created.ID || revoked.State != "revoked" || revoked.RevokedAt == "" {
		t.Fatalf("revoked=%+v", revoked)
	}
	again := decodeControlLibraryGrant(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, revokePath, `{}`, ""), http.StatusOK)
	if again.RevokedAt != revoked.RevokedAt || again.State != "revoked" {
		t.Fatalf("second revoke=%+v; want %+v", again, revoked)
	}
	if stored, err := store.LibraryArtifactGrants(ctx, f.shared.ID); err != nil || stored[1].RevokedBy != platformServiceActorID {
		t.Fatalf("revoker=%+v err=%v", stored, err)
	}
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, grants+"/libartg_missing/revoke", `{"reason":"x"}`, ""), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/library/artifacts/libart_missing/grants/"+created.ID+"/revoke", `{"reason":"x"}`, ""), http.StatusNotFound, controlCodeNotFound)
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, revokePath, `{"reason":"`+strings.Repeat("r", controlLibraryGrantReasonMaxSize+1)+`"}`, ""), http.StatusBadRequest, controlCodeValidationFailed)
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, revokePath, ``, ""), http.StatusBadRequest, controlCodeValidationFailed)
	// The revoked pin no longer authorizes the head; the older pin still does.
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, versionPath, "", "usr_operator"), http.StatusNotFound, controlCodeNotFound)
	if response := controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/library/artifacts/"+f.shared.ID+"/versions/"+f.sharedV1.ID, "", "usr_operator"); response.Code != http.StatusOK {
		t.Fatalf("v1 read after revoke=%d body=%s", response.Code, response.Body)
	}
	// After revocation the same recipient can be granted the head again.
	if regranted := decodeControlLibraryGrant(t, post("usr_owner", "owner", body(f.codex2.ID, f.sharedV2.ID, f.sharedV2.Digest, "")), http.StatusCreated); regranted.ID == created.ID {
		t.Fatalf("regrant reused the revoked record: %+v", regranted)
	}
}

func TestControlV1LibraryRecipientsListsActiveClients(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	f := newControlLibraryFixture(t, store)
	if _, err := store.RevokeMCPClient(context.Background(), f.other.ID, "usr_owner", MCPClientPrecondition{ID: f.other.ID, Revision: f.other.Revision}); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []struct{ user, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}, {platformServiceActorID, "service"}} {
		response := controlLibraryRequest(t, mux, key, now, actor.user, actor.role, http.MethodGet, "/control/v1/library/recipients", "", "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s recipients=%d body=%s", actor.role, response.Code, response.Body)
		}
		var recipients []controlLibraryRecipientDTO
		if err := json.Unmarshal(response.Body.Bytes(), &recipients); err != nil {
			t.Fatal(err)
		}
		if len(recipients) != 2 || recipients[0].ID != f.codex.ID || recipients[0].Slug != f.codex.Slug || recipients[0].Name != "Codex" || recipients[0].Subject != "usr_operator" || recipients[1].ID != f.codex2.ID {
			t.Fatalf("%s recipients=%+v", actor.role, recipients)
		}
		var raw []map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for field := range raw[0] {
			switch field {
			case "id", "slug", "name", "subject":
			default:
				t.Fatalf("recipients exposed field %q", field)
			}
		}
	}
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/library/recipients", "{}", ""), http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable)
}

func TestControlV1LibraryAuthorizationAndServiceAllowlist(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	f := newControlLibraryFixture(t, store)
	artifact := "/control/v1/library/artifacts/" + f.shared.ID
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/control/v1/library/artifacts", ""},
		{http.MethodGet, artifact, ""},
		{http.MethodGet, artifact + "/versions/" + f.sharedV1.ID, ""},
		{http.MethodPost, artifact + "/grants", `{"recipientClientId":"` + f.codex2.ID + `","versionId":"` + f.sharedV2.ID + `","digest":"` + f.sharedV2.Digest + `"}`},
		{http.MethodPost, artifact + "/grants/" + f.sharedGrant.ID + "/revoke", `{"reason":"done"}`},
		{http.MethodGet, "/control/v1/library/recipients", ""},
	}
	// Viewers and operators are authenticated but never permitted, even an
	// operator asking for its own subject.
	for _, route := range routes {
		for _, actor := range []struct{ user, role string }{{"usr_viewer", "viewer"}, {"usr_operator", "operator"}} {
			expectControlProblem(t, controlLibraryRequest(t, mux, key, now, actor.user, actor.role, route.method, route.path, route.body, "usr_operator"), http.StatusForbidden, controlCodeForbidden)
		}
	}
	// The service principal reaches every route in the group.
	for _, route := range routes {
		response := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", route.method, route.path, route.body, "usr_operator")
		if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
			t.Fatalf("service %s %s=%d body=%s", route.method, route.path, response.Code, response.Body)
		}
	}
	// Its allowlist is closed to any other shape or method on the group.
	for _, denied := range []struct{ method, path, body string }{
		{http.MethodPost, "/control/v1/library/artifacts", "{}"},
		{http.MethodGet, artifact + "/versions", ""},
		{http.MethodGet, artifact + "/grants", ""},
		{http.MethodDelete, artifact + "/grants/" + f.sharedGrant.ID, ""},
		{http.MethodGet, artifact + "/grants/" + f.sharedGrant.ID + "/revoke", ""},
		{http.MethodGet, "/control/v1/library", ""},
		{http.MethodGet, "/control/v1/library/artifacts/bad%20id", ""},
		{http.MethodPost, "/control/v1/library/recipients", "{}"},
	} {
		expectControlProblem(t, controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", denied.method, denied.path, denied.body, ""), http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	}
	// Credential and assertion failures, and a query string on a signed
	// path.
	request := actorRequest(http.MethodGet, "/control/v1/library/artifacts", nil, "not-an-assertion")
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	expectControlProblem(t, response, http.StatusUnauthorized, controlCodeUnauthorized)
	request = actorRequest(http.MethodGet, "/control/v1/library/artifacts", nil, "not-an-assertion")
	request.Header.Set("Authorization", "Bearer machine-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	expectControlProblem(t, response, http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	expectControlProblem(t, controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/control/v1/library/artifacts?subject=usr_operator", "", ""), http.StatusUnauthorized, controlCodeActorAssertionInvalid)
	// Wrong methods for permitted principals are method problems with an
	// Allow header.
	for _, wrong := range []struct{ method, path, allow string }{
		{http.MethodPost, "/control/v1/library/artifacts", http.MethodGet},
		{http.MethodDelete, artifact, http.MethodGet},
		{http.MethodPost, artifact + "/versions/" + f.sharedV1.ID, http.MethodGet},
		{http.MethodGet, artifact + "/grants", http.MethodPost},
		{http.MethodGet, artifact + "/grants/" + f.sharedGrant.ID + "/revoke", http.MethodPost},
	} {
		response := controlLibraryRequest(t, mux, key, now, "usr_owner", "owner", wrong.method, wrong.path, "{}", "usr_operator")
		expectControlProblem(t, response, http.StatusMethodNotAllowed, controlCodeCapabilityUnavailable)
		if response.Header().Get("Allow") != wrong.allow {
			t.Fatalf("%s %s Allow=%q", wrong.method, wrong.path, response.Header().Get("Allow"))
		}
	}
}

func TestControlV1LibraryArtifactsCursorPaging(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Paged", Subject: "usr_paged", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	total := controlLibraryArtifactPageLimit + 1
	artifacts := make([]LibraryArtifact, 0, total)
	for i := 0; i < total; i++ {
		_, artifact, _, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{
			Title: "Paged " + strconv.Itoa(i), Origin: LibraryArtifactOriginAgentDirect,
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# " + strconv.Itoa(i)})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		artifacts = append(artifacts, artifact)
	}
	list := "/control/v1/library/artifacts"
	page := func(cursor, subject string) (*httptest.ResponseRecorder, controlLibraryArtifactPageDTO) {
		t.Helper()
		headers := map[string]string{controlSubjectHeader: subject}
		if cursor != "" {
			headers[controlCursorHeader] = cursor
		}
		response := hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", headers)
		return response, decodeControlLibraryPage(t, response)
	}

	first, firstPage := page("", "usr_paged")
	if len(firstPage.Artifacts) != controlLibraryArtifactPageLimit || firstPage.NextCursor == "" || first.Header().Get(controlCursorHeader) != firstPage.NextCursor {
		t.Fatalf("first page len=%d cursor=%q header=%q", len(firstPage.Artifacts), firstPage.NextCursor, first.Header().Get(controlCursorHeader))
	}
	if firstPage.Artifacts[0].ID != artifacts[total-1].ID || firstPage.Artifacts[len(firstPage.Artifacts)-1].ID != artifacts[1].ID {
		t.Fatalf("first page order first=%s last=%s", firstPage.Artifacts[0].Title, firstPage.Artifacts[len(firstPage.Artifacts)-1].Title)
	}
	second, secondPage := page(firstPage.NextCursor, "usr_paged")
	if len(secondPage.Artifacts) != 1 || secondPage.Artifacts[0].ID != artifacts[0].ID || secondPage.NextCursor != "" || second.Header().Get(controlCursorHeader) != "" {
		t.Fatalf("second page=%+v headers=%v", secondPage, second.Header())
	}
	seen := map[string]struct{}{}
	for _, row := range append(firstPage.Artifacts, secondPage.Artifacts...) {
		if _, duplicate := seen[row.ID]; duplicate {
			t.Fatalf("artifact %s appeared twice", row.ID)
		}
		seen[row.ID] = struct{}{}
	}
	if len(seen) != total {
		t.Fatalf("paged %d distinct artifacts; want %d", len(seen), total)
	}
	// A cursor is scoped again by the subject: it cannot cross into another
	// subject's artifacts.
	if _, foreign := page(firstPage.NextCursor, "usr_other"); len(foreign.Artifacts) != 0 {
		t.Fatalf("cursor crossed subject scope: %+v", foreign)
	}
	// Appending a version moves the oldest artifact to the top of the feed.
	bumped, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: artifacts[0].ID, Format: LibraryArtifactFormatMarkdown, Body: "# bumped", CreatedBy: "usr_paged"})
	if err != nil {
		t.Fatal(err)
	}
	if _, after := page("", "usr_paged"); after.Artifacts[0].ID != artifacts[0].ID || after.Artifacts[0].LatestVersion.ID != bumped.ID || after.Artifacts[0].UpdatedAt != bumped.CreatedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("bumped artifact not first: %+v", after.Artifacts[0])
	}
	// Malformed cursors are validation failures, never silently reset.
	for _, bad := range []string{"not-a-cursor", firstPage.NextCursor + "=", encodeControlKeysetCursor(time.Unix(0, 5), " ")} {
		expectControlProblem(t, hostedNamespaceRequestWithHeaders(t, mux, key, now, "usr_owner", "owner", http.MethodGet, list, "", map[string]string{controlSubjectHeader: "usr_paged", controlCursorHeader: bad}), http.StatusBadRequest, controlCodeValidationFailed)
	}
}

// libraryControlArtifactTestStore is the store shape the control projection
// parity suite needs on both backends.
type libraryControlArtifactTestStore interface {
	LibraryStore
	MCPClientStore
	LibraryControlArtifactStore
}

// libraryControlArtifactFixture records everything the parity suite creates
// so a PgStore test can remove it again.
type libraryControlArtifactFixture struct {
	subject, otherSubject string

	primary, secondary, other MCPClient

	ownedA, ownedB, ownedC, shared, revokedShared, othersOnly LibraryArtifact

	ownedAV1, sharedV1, sharedV2 LibraryArtifactVersion

	runIDs []string
}

func (f *libraryControlArtifactFixture) artifactIDs() []string {
	ids := make([]string, 0, 6)
	for _, artifact := range []LibraryArtifact{f.ownedA, f.ownedB, f.ownedC, f.shared, f.revokedShared, f.othersOnly} {
		if artifact.ID != "" {
			ids = append(ids, artifact.ID)
		}
	}
	return ids
}

func (f *libraryControlArtifactFixture) clientIDs() []string {
	ids := make([]string, 0, 3)
	for _, client := range []MCPClient{f.primary, f.secondary, f.other} {
		if client.ID != "" {
			ids = append(ids, client.ID)
		}
	}
	return ids
}

func buildLibraryControlArtifactFixture(t *testing.T, ctx context.Context, store libraryControlArtifactTestStore, f *libraryControlArtifactFixture, suffix string) {
	t.Helper()
	f.subject, f.otherSubject = "usr_ctl_"+suffix, "usr_ctl_other_"+suffix
	client := func(name, subject string) MCPClient {
		t.Helper()
		created, err := store.CreateMCPClient(ctx, MCPClient{Name: name + " " + suffix, Subject: subject, CreatedBy: "usr_ctl_owner"})
		if err != nil {
			t.Fatalf("CreateMCPClient %s: %v", name, err)
		}
		return created
	}
	f.primary = client("Control primary", f.subject)
	f.secondary = client("Control secondary", f.subject)
	f.other = client("Control other", f.otherSubject)

	agentArtifact := func(owner MCPClient, title string) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		run, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{
			Title: title, Summary: "control summary", Origin: LibraryArtifactOriginAgentDirect,
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# " + title})
		if err != nil {
			t.Fatalf("CreateLibraryMCPClientArtifactWithInitialVersion %s: %v", title, err)
		}
		f.runIDs = append(f.runIDs, run.ID)
		return artifact, version
	}
	humanArtifact := func(title string) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: title, Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_ctl_owner",
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: title + " v1", CreatedBy: "usr_ctl_owner"})
		if err != nil {
			t.Fatalf("CreateLibraryArtifactWithInitialVersion %s: %v", title, err)
		}
		return artifact, version
	}
	grant := func(artifact LibraryArtifact, version LibraryArtifactVersion, recipient MCPClient) LibraryArtifactGrant {
		t.Helper()
		created, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
			ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
			AgentSurfaceID: recipient.ID, CreatedBy: "usr_ctl_owner",
		})
		if err != nil {
			t.Fatalf("CreateLibraryArtifactGrant %s: %v", artifact.Title, err)
		}
		return created
	}

	f.ownedA, f.ownedAV1 = agentArtifact(f.primary, "control owned A")
	f.ownedB, _ = agentArtifact(f.primary, "control owned B")
	f.ownedC, _ = agentArtifact(f.secondary, "control owned C")
	f.shared, f.sharedV1 = humanArtifact("control shared")
	var err error
	if f.sharedV2, err = store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: f.shared.ID, Format: LibraryArtifactFormatText, Body: "control shared v2", CreatedBy: "usr_ctl_owner"}); err != nil {
		t.Fatalf("CreateLibraryArtifactVersion: %v", err)
	}
	grant(f.shared, f.sharedV1, f.primary)
	grant(f.shared, f.sharedV1, f.other)
	// The secondary registration is granted an artifact its own subject
	// already owns through the primary registration: ownership must win.
	grant(f.ownedA, f.ownedAV1, f.secondary)
	var revokedV1 LibraryArtifactVersion
	f.revokedShared, revokedV1 = humanArtifact("control revoked")
	revoked := grant(f.revokedShared, revokedV1, f.secondary)
	if _, err := store.RevokeLibraryArtifactGrant(ctx, f.revokedShared.ID, revoked.ID, "usr_ctl_owner", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeLibraryArtifactGrant: %v", err)
	}
	f.othersOnly, _ = agentArtifact(f.other, "control others only")
}

func sameInstant(a, b time.Time) bool {
	// PostgreSQL keeps microseconds; compare at that precision on both backends.
	return a.UTC().Truncate(time.Microsecond).Equal(b.UTC().Truncate(time.Microsecond))
}

// exerciseLibraryControlArtifactStore asserts the projection invariants shared
// by FileStore and PgStore against a fixture built by
// buildLibraryControlArtifactFixture.
func exerciseLibraryControlArtifactStore(t *testing.T, ctx context.Context, store libraryControlArtifactTestStore, f *libraryControlArtifactFixture) {
	t.Helper()
	subjectScope := LibraryControlArtifactScope{AgentSurfaceIDs: []string{f.secondary.ID, f.primary.ID, f.primary.ID}}

	page, err := store.LibraryControlArtifactPage(ctx, subjectScope, LibraryControlArtifactCursor{}, 0)
	if err != nil {
		t.Fatalf("scoped page: %v", err)
	}
	if page.NextCursor.ID != "" || len(page.Artifacts) != 4 {
		t.Fatalf("scoped page=%+v", page)
	}
	order := []string{f.shared.ID, f.ownedC.ID, f.ownedB.ID, f.ownedA.ID}
	for i, want := range order {
		if page.Artifacts[i].Artifact.ID != want {
			t.Fatalf("scoped order[%d]=%s; want %s (page=%+v)", i, page.Artifacts[i].Artifact.ID, want, page.Artifacts)
		}
	}
	byID := map[string]LibraryControlArtifact{}
	for _, item := range page.Artifacts {
		byID[item.Artifact.ID] = item
		if item.LatestVersion.Body != "" || item.LatestVersion.CreatedBy != "" || item.LatestVersion.ReviewedBy != "" || (item.GrantedVersion != nil && (item.GrantedVersion.Body != "" || item.GrantedVersion.CreatedBy != "")) {
			t.Fatalf("projection carried private version fields: %+v", item)
		}
		if item.Artifact.CreatedBy != "" || item.Artifact.RunID != "" || item.Artifact.Title == "" {
			t.Fatalf("projection carried provenance or lost metadata: %+v", item.Artifact)
		}
		if !sameInstant(item.UpdatedAt, item.LatestVersion.CreatedAt) {
			t.Fatalf("updatedAt %v is not the head's creation %v", item.UpdatedAt, item.LatestVersion.CreatedAt)
		}
	}
	shared := byID[f.shared.ID]
	if shared.Access != LibraryControlArtifactAccessGranted || shared.Artifact.AgentSurfaceID != "" || shared.LatestVersion.ID != f.sharedV2.ID || shared.LatestVersion.Version != 2 ||
		shared.GrantedVersion == nil || shared.GrantedVersion.ID != f.sharedV1.ID || shared.GrantedVersion.Digest != f.sharedV1.Digest || !sameInstant(shared.UpdatedAt, f.sharedV2.CreatedAt) {
		t.Fatalf("shared=%+v", shared)
	}
	ownedA := byID[f.ownedA.ID]
	if ownedA.Access != LibraryControlArtifactAccessOwned || ownedA.GrantedVersion != nil || ownedA.Artifact.AgentSurfaceID != f.primary.ID || ownedA.LatestVersion.ID != f.ownedAV1.ID || ownedA.Artifact.Summary != "control summary" {
		t.Fatalf("ownedA=%+v", ownedA)
	}
	if byID[f.ownedC.ID].Artifact.AgentSurfaceID != f.secondary.ID || byID[f.ownedC.ID].Access != LibraryControlArtifactAccessOwned {
		t.Fatalf("ownedC=%+v", byID[f.ownedC.ID])
	}

	// Keyset paging is stable across pages and scoped again by the store.
	firstPage, err := store.LibraryControlArtifactPage(ctx, subjectScope, LibraryControlArtifactCursor{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Artifacts) != 2 || firstPage.Artifacts[0].Artifact.ID != order[0] || firstPage.Artifacts[1].Artifact.ID != order[1] ||
		firstPage.NextCursor.ID != order[1] || !sameInstant(firstPage.NextCursor.UpdatedAt, firstPage.Artifacts[1].UpdatedAt) {
		t.Fatalf("first page=%+v", firstPage)
	}
	secondPage, err := store.LibraryControlArtifactPage(ctx, subjectScope, firstPage.NextCursor, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Artifacts) != 2 || secondPage.Artifacts[0].Artifact.ID != order[2] || secondPage.Artifacts[1].Artifact.ID != order[3] || secondPage.NextCursor.ID != "" {
		t.Fatalf("second page=%+v", secondPage)
	}
	if crossed, err := store.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{AgentSurfaceIDs: []string{f.other.ID}}, firstPage.NextCursor, 2); err != nil || len(crossed.Artifacts) != 0 {
		t.Fatalf("cursor crossed scope: %+v err=%v", crossed, err)
	}

	// Only the secondary registration: it owns C and is granted A at v1;
	// the revoked grant does not count.
	secondaryOnly, err := store.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{AgentSurfaceIDs: []string{f.secondary.ID}}, LibraryControlArtifactCursor{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondaryOnly.Artifacts) != 2 || secondaryOnly.Artifacts[0].Artifact.ID != f.ownedC.ID || secondaryOnly.Artifacts[1].Artifact.ID != f.ownedA.ID ||
		secondaryOnly.Artifacts[1].Access != LibraryControlArtifactAccessGranted || secondaryOnly.Artifacts[1].GrantedVersion == nil || secondaryOnly.Artifacts[1].GrantedVersion.ID != f.ownedAV1.ID {
		t.Fatalf("secondary scope=%+v", secondaryOnly)
	}
	// An empty surface set selects nothing; the explicit catalog switch
	// selects everything without an access class.
	if none, err := store.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{}, LibraryControlArtifactCursor{}, 0); err != nil || len(none.Artifacts) != 0 || none.Artifacts == nil {
		t.Fatalf("empty scope=%+v err=%v", none, err)
	}
	everything := map[string]LibraryControlArtifact{}
	var cursor LibraryControlArtifactCursor
	for {
		catalog, err := store.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{Everything: true}, cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range catalog.Artifacts {
			if _, duplicate := everything[item.Artifact.ID]; duplicate {
				t.Fatalf("catalog paging repeated %s", item.Artifact.ID)
			}
			everything[item.Artifact.ID] = item
		}
		if catalog.NextCursor.ID == "" {
			break
		}
		cursor = catalog.NextCursor
	}
	for _, id := range f.artifactIDs() {
		item, ok := everything[id]
		if !ok || item.Access != "" || item.GrantedVersion != nil {
			t.Fatalf("catalog row for %s=%+v ok=%t", id, item, ok)
		}
	}
	if everything[f.ownedA.ID].Artifact.AgentSurfaceID != f.primary.ID || everything[f.othersOnly.ID].Artifact.AgentSurfaceID != f.other.ID {
		t.Fatalf("catalog lost surface keys: %+v %+v", everything[f.ownedA.ID], everything[f.othersOnly.ID])
	}

	// Appending a version moves an artifact to the top of the scope.
	bumped, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: f.ownedA.ID, Format: LibraryArtifactFormatMarkdown, Body: "# control owned A v2", CreatedBy: f.subject})
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.LibraryControlArtifactPage(ctx, subjectScope, LibraryControlArtifactCursor{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if after.Artifacts[0].Artifact.ID != f.ownedA.ID || after.Artifacts[0].LatestVersion.ID != bumped.ID || after.Artifacts[0].LatestVersion.Version != 2 || !sameInstant(after.Artifacts[0].UpdatedAt, bumped.CreatedAt) {
		t.Fatalf("after append=%+v", after.Artifacts[0])
	}
	// The secondary registration's grant on A still pins v1 while the head
	// is v2.
	secondaryAfter, err := store.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{AgentSurfaceIDs: []string{f.secondary.ID}}, LibraryControlArtifactCursor{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if secondaryAfter.Artifacts[0].Artifact.ID != f.ownedA.ID || secondaryAfter.Artifacts[0].GrantedVersion.ID != f.ownedAV1.ID || secondaryAfter.Artifacts[0].LatestVersion.ID != bumped.ID {
		t.Fatalf("secondary after append=%+v", secondaryAfter.Artifacts[0])
	}

	// Input validation.
	for name, bad := range map[string]struct {
		scope  LibraryControlArtifactScope
		cursor LibraryControlArtifactCursor
		limit  int
	}{
		"cursor without time":     {subjectScope, LibraryControlArtifactCursor{ID: f.ownedA.ID}, 0},
		"cursor without id":       {subjectScope, LibraryControlArtifactCursor{UpdatedAt: time.Now()}, 0},
		"limit above max":         {subjectScope, LibraryControlArtifactCursor{}, libraryControlArtifactPageMax + 1},
		"negative limit":          {subjectScope, LibraryControlArtifactCursor{}, -1},
		"everything with surface": {LibraryControlArtifactScope{Everything: true, AgentSurfaceIDs: []string{f.primary.ID}}, LibraryControlArtifactCursor{}, 0},
		"blank surface":           {LibraryControlArtifactScope{AgentSurfaceIDs: []string{"  "}}, LibraryControlArtifactCursor{}, 0},
	} {
		if _, err := store.LibraryControlArtifactPage(ctx, bad.scope, bad.cursor, bad.limit); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestLibraryControlArtifactPageFileStoreParity(t *testing.T) {
	store := newLibraryFileStore(t)
	ctx := context.Background()
	var fixture libraryControlArtifactFixture
	buildLibraryControlArtifactFixture(t, ctx, store, &fixture, "file")
	exerciseLibraryControlArtifactStore(t, ctx, store, &fixture)

	// A reloaded FileStore serves the same projection from its persisted
	// surface-key map.
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reloaded.LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{AgentSurfaceIDs: []string{fixture.primary.ID}}, LibraryControlArtifactCursor{}, 0)
	if err != nil || len(page.Artifacts) != 3 {
		t.Fatalf("reloaded scope=%+v err=%v", page, err)
	}
	for _, item := range page.Artifacts {
		if item.Artifact.ID == fixture.shared.ID {
			if item.Access != LibraryControlArtifactAccessGranted {
				t.Fatalf("reloaded shared=%+v", item)
			}
		} else if item.Access != LibraryControlArtifactAccessOwned || item.Artifact.AgentSurfaceID != fixture.primary.ID {
			t.Fatalf("reloaded owned=%+v", item)
		}
	}
}
