package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type libraryConsoleMarkerOverrideStore struct {
	*FileStore
	versionID string
	found     bool
	err       error
}

func (s *libraryConsoleMarkerOverrideStore) BuiltInLibraryCurrentVersion(context.Context, string) (string, bool, error) {
	return s.versionID, s.found, s.err
}

type fakeLibraryDraftGenerator struct {
	request SkillDraftGenerationRequest
	result  SkillDraftGeneration
	err     error
}

func (f *fakeLibraryDraftGenerator) GenerateSkillDraft(_ context.Context, request SkillDraftGenerationRequest) (SkillDraftGeneration, error) {
	f.request = request
	return f.result, f.err
}

func newLibraryConsole(t *testing.T, options ...ConsoleOption) (*http.ServeMux, string, *FileStore) {
	t.Helper()
	store := newLibraryFileStore(t)
	api := NewConsoleAPI(store, nil, nil, "pw", "library-console-secret", "https://engine.example", "https://console.example", "", options...)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), store
}

func doLibraryConsoleList(t *testing.T, mux *http.ServeMux, token, path string, headers map[string]string) (*httptest.ResponseRecorder, []map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	var rows []map[string]any
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &rows); err != nil {
			t.Fatalf("decode %s list: %v (body %s)", path, err, recorder.Body)
		}
	}
	return recorder, rows
}

func collectLibraryConsolePages(t *testing.T, mux *http.ServeMux, token, path string) ([]map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	var first *httptest.ResponseRecorder
	rows := make([]map[string]any, 0)
	seen := make(map[string]struct{})
	cursor := ""
	for page := 0; page < 16; page++ {
		headers := map[string]string{libraryConsolePageLimitHeader: "1"}
		if cursor != "" {
			headers[libraryConsolePageCursorHeader] = cursor
		}
		recorder, items := doLibraryConsoleList(t, mux, token, path, headers)
		if first == nil {
			first = recorder
		}
		if recorder.Code != http.StatusOK || len(items) != 1 {
			t.Fatalf("GET %s page %d = %d rows=%v body=%s", path, page, recorder.Code, items, recorder.Body)
		}
		id, _ := items[0]["id"].(string)
		if id == "" {
			t.Fatalf("GET %s page %d omitted row id: %v", path, page, items[0])
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("GET %s page traversal repeated id %q", path, id)
		}
		seen[id] = struct{}{}
		rows = append(rows, items[0])
		cursor = recorder.Header().Get(libraryConsolePageNextCursorHeader)
		if cursor == "" {
			return rows, first
		}
	}
	t.Fatalf("GET %s did not terminate its bounded page traversal", path)
	return nil, nil
}

func TestLibraryConsoleListPagesAreBoundedMetadata(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)

	const skillBodyMarker = "console-page-skill-body"
	const artifactBodyMarker = "console-page-artifact-body"
	skillIDs := make(map[string]struct{}, 3)
	artifactIDs := make(map[string]struct{}, 3)
	runIDs := make(map[string]struct{}, 3)
	var latestSkillID, latestVersionID string
	var detailArtifactID string
	for _, suffix := range []string{"alpha", "bravo", "charlie"} {
		skill, version, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: "console-page-" + suffix, Name: "Console page " + suffix, Description: "metadata only", CreatedBy: "local-admin",
		}, LibrarySkillVersion{Content: "# " + skillBodyMarker + " " + suffix, RequestedCapabilities: []string{"artifact.read"}, CreatedBy: "local-admin"})
		if err != nil {
			t.Fatalf("create %s skill: %v", suffix, err)
		}
		skillIDs[skill.ID] = struct{}{}
		if suffix == "charlie" {
			version, err = store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
				SkillID: skill.ID, Content: "# " + skillBodyMarker + " " + suffix + " v2", RequestedCapabilities: []string{"artifact.read", "artifact.write"}, CreatedBy: "local-admin",
			})
			if err != nil {
				t.Fatalf("create latest %s skill version: %v", suffix, err)
			}
			latestSkillID, latestVersionID = skill.ID, version.ID
		}

		artifact, _, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: "Console page artifact " + suffix, Summary: "metadata only", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin",
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# " + artifactBodyMarker + " " + suffix, CreatedBy: "local-admin"})
		if err != nil {
			t.Fatalf("create %s artifact: %v", suffix, err)
		}
		artifactIDs[artifact.ID] = struct{}{}
		if suffix == "charlie" {
			detailArtifactID = artifact.ID
		}

		run, err := store.CreateLibraryRun(ctx, LibraryRun{
			Origin: LibraryRunOriginHuman, ActorRef: "local-admin", SurfaceRef: "console-page-" + suffix, Status: "succeeded",
			InputDigest: libraryDigest("input " + suffix), OutputDigest: libraryDigest("output " + suffix),
		})
		if err != nil {
			t.Fatalf("create %s run: %v", suffix, err)
		}
		runIDs[run.ID] = struct{}{}
	}

	skillRows, skillFirst := collectLibraryConsolePages(t, mux, token, "/api/library/skills")
	if len(skillRows) != len(skillIDs) {
		t.Fatalf("skill page rows=%v", skillRows)
	}
	if skillFirst.Header().Get("Cache-Control") != "no-store" || skillFirst.Header().Get(libraryConsolePageNextCursorHeader) == "" {
		t.Fatalf("skill page headers=%v", skillFirst.Header())
	}
	vary := strings.Join(skillFirst.Header().Values("Vary"), ",")
	if !strings.Contains(vary, libraryConsolePageCursorHeader) || !strings.Contains(vary, libraryConsolePageLimitHeader) {
		t.Fatalf("skill page Vary=%q", vary)
	}
	if strings.Contains(skillFirst.Body.String(), skillBodyMarker) {
		t.Fatalf("skill list leaked instruction content: %s", skillFirst.Body)
	}
	var foundLatest bool
	for _, row := range skillRows {
		id, _ := row["id"].(string)
		if _, found := skillIDs[id]; !found {
			t.Fatalf("unexpected skill page row=%v", row)
		}
		if id != latestSkillID {
			continue
		}
		latest, ok := row["latestVersion"].(map[string]any)
		if !ok || latest["id"] != latestVersionID {
			t.Fatalf("latest skill page summary=%v", row)
		}
		if _, leaked := latest["content"]; leaked {
			t.Fatalf("skill list leaked version content: %v", latest)
		}
		foundLatest = true
	}
	if !foundLatest {
		t.Fatal("latest skill was absent from page traversal")
	}

	artifactRows, artifactFirst := collectLibraryConsolePages(t, mux, token, "/api/library/artifacts")
	if len(artifactRows) != len(artifactIDs) || strings.Contains(artifactFirst.Body.String(), artifactBodyMarker) {
		t.Fatalf("artifact page rows=%v body=%s", artifactRows, artifactFirst.Body)
	}
	for _, row := range artifactRows {
		id, _ := row["id"].(string)
		if _, found := artifactIDs[id]; !found {
			t.Fatalf("unexpected artifact page row=%v", row)
		}
	}

	runRows, _ := collectLibraryConsolePages(t, mux, token, "/api/library/runs")
	if len(runRows) != len(runIDs) {
		t.Fatalf("run page rows=%v", runRows)
	}
	for _, row := range runRows {
		id, _ := row["id"].(string)
		if _, found := runIDs[id]; !found {
			t.Fatalf("unexpected run page row=%v", row)
		}
	}

	// The cursor is type-bound, so a page token from one management list cannot
	// become a cross-list data probe. Limits are explicit positive bounded ints,
	// and hosted-compatible pages never accept a query string.
	for name, scenario := range map[string]struct {
		path    string
		headers map[string]string
	}{
		"foreign cursor":   {"/api/library/artifacts", map[string]string{libraryConsolePageCursorHeader: skillFirst.Header().Get(libraryConsolePageNextCursorHeader)}},
		"malformed cursor": {"/api/library/skills", map[string]string{libraryConsolePageCursorHeader: "not-a-cursor"}},
		"zero limit":       {"/api/library/skills", map[string]string{libraryConsolePageLimitHeader: "0"}},
		"too large limit":  {"/api/library/skills", map[string]string{libraryConsolePageLimitHeader: "101"}},
	} {
		recorder, _ := doLibraryConsoleList(t, mux, token, scenario.path, scenario.headers)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d body=%s", name, recorder.Code, recorder.Body)
		}
	}
	queryRecorder, _ := doLibraryConsoleList(t, mux, token, "/api/library/skills?limit=1", nil)
	if queryRecorder.Code != http.StatusBadRequest {
		t.Fatalf("library list query string = %d body=%s", queryRecorder.Code, queryRecorder.Body)
	}

	// Detail reads intentionally remain the opt-in body-bearing endpoints.
	skillDetail, _ := doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+latestSkillID, "")
	if skillDetail.Code != http.StatusOK || !strings.Contains(skillDetail.Body.String(), skillBodyMarker) {
		t.Fatalf("skill detail = %d body=%s", skillDetail.Code, skillDetail.Body)
	}
	artifactDetail, _ := doJSON(t, mux, token, http.MethodGet, "/api/library/artifacts/"+detailArtifactID, "")
	if artifactDetail.Code != http.StatusOK || !strings.Contains(artifactDetail.Body.String(), artifactBodyMarker) {
		t.Fatalf("artifact detail = %d body=%s", artifactDetail.Code, artifactDetail.Body)
	}

	options := httptest.NewRequest(http.MethodOptions, "/api/library/skills", nil)
	options.Header.Set("Origin", "https://console.example")
	optionsRecorder := httptest.NewRecorder()
	mux.ServeHTTP(optionsRecorder, options)
	if optionsRecorder.Code != http.StatusNoContent || !strings.Contains(optionsRecorder.Header().Get("Access-Control-Allow-Headers"), libraryConsolePageCursorHeader) || !strings.Contains(optionsRecorder.Header().Get("Access-Control-Allow-Headers"), libraryConsolePageLimitHeader) || !strings.Contains(optionsRecorder.Header().Get("Access-Control-Expose-Headers"), libraryConsolePageNextCursorHeader) {
		t.Fatalf("library CORS preflight = %d headers=%v", optionsRecorder.Code, optionsRecorder.Header())
	}
}

func TestLibraryConsolePageLimitBounds(t *testing.T) {
	for input, want := range map[int]int{0: libraryConsolePageDefault, 1: 1, libraryConsolePageMax: libraryConsolePageMax} {
		got, err := normalizeLibraryConsolePageLimit(input)
		if err != nil || got != want {
			t.Fatalf("normalize library Console limit %d = %d, %v", input, got, err)
		}
	}
	for _, input := range []int{-1, libraryConsolePageMax + 1} {
		if _, err := normalizeLibraryConsolePageLimit(input); err == nil {
			t.Fatalf("normalize library Console limit %d unexpectedly succeeded", input)
		}
	}
}

func TestLibraryConsoleExposesBuiltInManagerAndRejectsManagedMutations(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Managed skill client", Subject: "usr_managed", CreatedBy: "local-admin",
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}
	if err := ReconcileBuiltInLibrary(ctx, store); err != nil {
		t.Fatalf("reconcile built-in Library: %v", err)
	}

	recorder, rows := doLibraryConsoleList(t, mux, token, "/api/library/skills", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET managed skills = %d body=%s", recorder.Code, recorder.Body)
	}
	var managed map[string]any
	for _, row := range rows {
		if row["id"] == usingSynaxisSkillID {
			managed = row
			break
		}
	}
	if managed == nil || managed["managedBy"] != libraryBuiltInManager || managed["slug"] != usingSynaxisSkillSlug {
		t.Fatalf("managed list row = %v", managed)
	}

	detail, response := doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+usingSynaxisSkillID, "")
	if detail.Code != http.StatusOK || response["managedBy"] != libraryBuiltInManager {
		t.Fatalf("GET managed skill = %d body=%s", detail.Code, detail.Body)
	}
	bindings, ok := response["bindings"].([]any)
	if !ok || len(bindings) != 1 {
		t.Fatalf("managed detail bindings = %v", response["bindings"])
	}
	binding, ok := bindings[0].(map[string]any)
	if !ok || binding["scopeId"] != client.ID || binding["mode"] != LibraryBindingModePin || binding["pinnedVersionId"] != usingSynaxisSkillVersionID {
		t.Fatalf("managed detail binding = %v", bindings[0])
	}

	versionWrite, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+usingSynaxisSkillID+"/versions", `{"content":"# unauthorized replacement"}`)
	if versionWrite.Code != http.StatusConflict {
		t.Fatalf("POST managed version = %d body=%s", versionWrite.Code, versionWrite.Body)
	}
	bindingWrite, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+usingSynaxisSkillID+"/bindings", `{"scopeKind":"agent_surface","scopeId":"`+client.ID+`","mode":"track"}`)
	if bindingWrite.Code != http.StatusConflict {
		t.Fatalf("POST managed binding = %d body=%s", bindingWrite.Code, bindingWrite.Body)
	}
	bindingDelete, _ := doJSON(t, mux, token, http.MethodDelete, "/api/library/skills/"+usingSynaxisSkillID+"/bindings/"+usingSynaxisBindingID(client.ID), "")
	if bindingDelete.Code != http.StatusConflict {
		t.Fatalf("DELETE managed binding = %d body=%s", bindingDelete.Code, bindingDelete.Body)
	}
}

func TestLibraryConsoleManagedCurrentVersionFollowsRollbackMarker(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Rollback audit client", Subject: "usr_rollback_audit", CreatedBy: "local-admin",
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}

	v1 := usingSynaxisDefinition()
	reconcileBuiltInDefinitionForTest(t, store, v1)
	v2Content := usingSynaxisSkillContent + "\n## Engine v2 audit fixture\nRetain this version across rollback.\n"
	v2ID := usingSynaxisSkillVersionIDPrefix + "2"
	v2 := v1
	v2.Versions = append(append([]builtInLibrarySkillVersionDefinition(nil), v1.Versions...), builtInLibrarySkillVersionDefinition{
		Revision: 2, VersionID: v2ID, Content: v2Content, ContentDigest: libraryDigest(v2Content),
	})
	v2.CurrentVersionID = v2ID
	reconcileBuiltInDefinitionForTest(t, store, v2)
	reconcileBuiltInDefinitionForTest(t, store, v1)
	requireUsingSynaxisBinding(t, store, client.ID, usingSynaxisSkillVersionID)

	recorder, rows := doLibraryConsoleList(t, mux, token, "/api/library/skills", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET managed skill list = %d body=%s", recorder.Code, recorder.Body)
	}
	var managed map[string]any
	for _, row := range rows {
		if row["id"] == usingSynaxisSkillID {
			managed = row
			break
		}
	}
	latest, _ := managed["latestVersion"].(map[string]any)
	current, _ := managed["currentVersion"].(map[string]any)
	if managed == nil || latest["id"] != v2ID || latest["version"] != float64(2) ||
		managed["currentVersionId"] != usingSynaxisSkillVersionID || current["id"] != usingSynaxisSkillVersionID ||
		current["version"] != float64(usingSynaxisSkillRevision) || current["digest"] != usingSynaxisExpectedContentDigest {
		t.Fatalf("managed rollback list projection = %v", managed)
	}
	if _, leaked := current["content"]; leaked {
		t.Fatalf("managed current list summary leaked content: %v", current)
	}

	detail, response := doJSON(t, mux, token, http.MethodGet, "/api/library/skills/"+usingSynaxisSkillID, "")
	current, _ = response["currentVersion"].(map[string]any)
	versions, _ := response["versions"].([]any)
	bindings, _ := response["bindings"].([]any)
	if detail.Code != http.StatusOK || response["currentVersionId"] != usingSynaxisSkillVersionID ||
		current["id"] != usingSynaxisSkillVersionID || len(versions) != 2 || len(bindings) != 1 {
		t.Fatalf("managed rollback detail projection = %d %v", detail.Code, response)
	}
	binding, _ := bindings[0].(map[string]any)
	if binding["pinnedVersionId"] != usingSynaxisSkillVersionID {
		t.Fatalf("managed rollback binding = %v", binding)
	}
}

func TestLibraryConsoleManagedCurrentVersionDoesNotFallBackToLatest(t *testing.T) {
	ctx := context.Background()
	base := newLibraryFileStore(t)
	if err := ReconcileBuiltInLibrary(ctx, base); err != nil {
		t.Fatalf("reconcile built-in Library: %v", err)
	}
	for name, marker := range map[string]struct {
		versionID string
		found     bool
		err       error
	}{
		"absent": {},
		"error":  {err: errors.New("marker unavailable")},
		"dangling": {
			versionID: usingSynaxisSkillVersionIDPrefix + "999", found: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &libraryConsoleMarkerOverrideStore{
				FileStore: base, versionID: marker.versionID, found: marker.found, err: marker.err,
			}
			api := NewConsoleAPI(store, nil, nil, "pw", "library-console-secret", "https://engine.example", "https://console.example", "")
			mux := http.NewServeMux()
			api.Routes(mux)
			recorder, rows := doLibraryConsoleList(t, mux, api.signToken(), "/api/library/skills", nil)
			if recorder.Code != http.StatusOK || len(rows) != 1 {
				t.Fatalf("GET managed skills = %d rows=%v body=%s", recorder.Code, rows, recorder.Body)
			}
			if _, ok := rows[0]["latestVersion"].(map[string]any); !ok {
				t.Fatalf("managed history head was omitted: %v", rows[0])
			}
			if _, exists := rows[0]["currentVersion"]; exists || rows[0]["currentVersionId"] != nil {
				t.Fatalf("unresolved marker fell back to retained history: %v", rows[0])
			}
		})
	}
}

func TestLibraryConsoleCreatesGeneratedDraftAndPortableSkill(t *testing.T) {
	generator := &fakeLibraryDraftGenerator{result: SkillDraftGeneration{
		Name: "Incident responder", Description: "Triage incidents", Content: "# Incident response\nCheck impact first.",
		RequestedCapabilities: []string{"alerts.read", "tickets.read"}, Generator: "fake", Model: "fake-model",
	}}
	mux, token, store := newLibraryConsole(t, WithSkillDraftGenerator(generator))
	brief := "Create a focused incident response procedure."
	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/skill-drafts", `{"name":"Incident responder","description":"Triage incidents","prompt":"`+brief+`","requestedCapabilities":["tickets.read","alerts.read"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST skill draft = %d body=%s", recorder.Code, recorder.Body)
	}
	draftID, _ := response["id"].(string)
	if draftID == "" || generator.request.Prompt != brief {
		t.Fatalf("draft response=%v generator request=%+v", response, generator.request)
	}
	draft, found := store.LibrarySkillDraft(context.Background(), draftID)
	if !found || draft.PromptDigest != libraryDigest(brief) || draft.PromptDigest == brief || draft.Generator != "fake" {
		t.Fatalf("stored generated draft=%+v found=%v", draft, found)
	}

	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/skills", `{"draftId":"`+draftID+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST skill from draft = %d body=%s", recorder.Code, recorder.Body)
	}
	skill, ok := response["skill"].(map[string]any)
	if !ok {
		t.Fatalf("skill response=%v", response)
	}
	skillID, _ := skill["id"].(string)
	if skillID == "" || skill["slug"] != "incident-responder" {
		t.Fatalf("created skill=%v", skill)
	}

	recorder, response = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/bindings", `{"scopeKind":"namespace","scopeId":"product-engineering","mode":"track","capabilityCeiling":["alerts.read"]}`)
	if recorder.Code != http.StatusCreated || response["scopeKind"] != LibraryScopeNamespace {
		t.Fatalf("POST generic namespace binding = %d body=%s", recorder.Code, recorder.Body)
	}
	if response["scopeId"] != "product-engineering" || response["mode"] != LibraryBindingModeTrack {
		t.Fatalf("binding response=%v", response)
	}

	// A generic Library scope must not accept a credential-ownership namespace
	// as an alias; the two concepts are intentionally disjoint.
	recorder, _ = doJSON(t, mux, token, http.MethodPost, "/api/library/skills/"+skillID+"/bindings", `{"scopeKind":"connection_namespace","scopeId":"cns_secret","mode":"track"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("connection namespace binding status=%d body=%s", recorder.Code, recorder.Body)
	}
}

func TestLibraryConsoleDraftCreatorIsUnavailableWithoutServerGenerator(t *testing.T) {
	mux, token, _ := newLibraryConsole(t)
	recorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/skill-drafts", `{"prompt":"Create a skill"}`)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured draft creator = %d body=%s", recorder.Code, recorder.Body)
	}
}

func TestLibraryConsoleRunCreationReservesTrustedProvenance(t *testing.T) {
	mux, token, store := newLibraryConsole(t)
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-console", Mode: LibraryBindingModePin,
		PinnedVersionID: version.ID, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, attempt := range []struct {
		name string
		body string
		want int
	}{
		{
			name: "skill run",
			body: `{"origin":"skill_run","skillId":"` + skill.ID + `","skillVersionId":"` + version.ID + `","bindingId":"` + binding.ID + `","effectiveCapabilities":["repository.write"],"status":"succeeded"}`,
			want: http.StatusForbidden,
		},
		{
			name: "direct agent",
			body: `{"origin":"agent_direct","status":"succeeded"}`,
			want: http.StatusForbidden,
		},
		{
			name: "manual capability claim",
			body: `{"origin":"human","effectiveCapabilities":["repository.write"],"status":"succeeded"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "manual skill claim",
			body: `{"origin":"automation","skillId":"` + skill.ID + `","status":"succeeded"}`,
			want: http.StatusBadRequest,
		},
	} {
		recorder, _ := doJSON(t, mux, token, http.MethodPost, "/api/library/runs", attempt.body)
		if recorder.Code != attempt.want {
			t.Fatalf("%s run status=%d want=%d body=%s", attempt.name, recorder.Code, attempt.want, recorder.Body)
		}
	}
	if runs, err := store.LibraryRuns(context.Background()); err != nil || len(runs) != 0 {
		t.Fatalf("rejected console runs persisted=%#v err=%v", runs, err)
	}

	inputDigest := libraryDigest("manual input")
	outputDigest := libraryDigest("manual output")
	recorder, human := doJSON(t, mux, token, http.MethodPost, "/api/library/runs", `{"origin":"human","surfaceRef":"console","status":"succeeded","inputDigest":"`+inputDigest+`","outputDigest":"`+outputDigest+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("human run = %d body=%s", recorder.Code, recorder.Body)
	}
	if capabilities, ok := human["effectiveCapabilities"].([]any); ok && len(capabilities) != 0 {
		t.Fatalf("human run claimed capabilities=%v", human)
	}
	if human["origin"] != LibraryRunOriginHuman || human["actorRef"] != "local-admin" {
		t.Fatalf("human run response=%v", human)
	}

	recorder, automation := doJSON(t, mux, token, http.MethodPost, "/api/library/runs", `{"origin":"automation","surfaceRef":"external-job","status":"succeeded"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("automation run = %d body=%s", recorder.Code, recorder.Body)
	}
	if capabilities, ok := automation["effectiveCapabilities"].([]any); ok && len(capabilities) != 0 {
		t.Fatalf("automation run claimed capabilities=%v", automation)
	}
	if automation["origin"] != LibraryRunOriginAutomation || automation["actorRef"] != "local-admin" {
		t.Fatalf("automation run response=%v", automation)
	}
	if runs, err := store.LibraryRuns(context.Background()); err != nil || len(runs) != 2 {
		t.Fatalf("valid manual runs=%#v err=%v", runs, err)
	}
}

func TestLibraryConsoleResolvesTrustedOpaqueContextReadOnly(t *testing.T) {
	mux, token, store := newLibraryConsole(t)
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeRepository, ScopeID: "repo_console", Mode: LibraryBindingModePin,
		PinnedVersionID: version.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}

	recorder, response := doJSON(t, mux, token, http.MethodPost, "/api/library/resolve", `{"repositoryId":"repo_console"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST library resolve = %d body=%s", recorder.Code, recorder.Body)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("library resolve Cache-Control=%q", recorder.Header().Get("Cache-Control"))
	}
	skills, ok := response["skills"].([]any)
	if !ok || len(skills) != 1 {
		t.Fatalf("library resolve response=%v", response)
	}
	resolved, ok := skills[0].(map[string]any)
	if !ok || resolved["bindingId"] != binding.ID || resolved["versionId"] != version.ID || resolved["resolutionSource"] != LibraryScopeRepository || resolved["content"] != version.Content {
		t.Fatalf("resolved skill=%v", resolved)
	}
	if _, leaked := resolved["createdBy"]; leaked {
		t.Fatalf("resolver leaked actor identity: %v", resolved)
	}

	denied, _ := doJSON(t, mux, "", http.MethodPost, "/api/library/resolve", `{"repositoryId":"repo_console"}`)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated library resolve = %d body=%s", denied.Code, denied.Body)
	}
	method, _ := doJSON(t, mux, token, http.MethodGet, "/api/library/resolve", "")
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET library resolve = %d body=%s", method.Code, method.Body)
	}
}

func TestHostedLibraryResolverAcceptsActorBoundJSONContext(t *testing.T) {
	store := newLibraryFileStore(t)
	skill, version := createLibrarySkillForTest(t, store)
	if _, err := store.UpsertLibrarySkillBinding(context.Background(), LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "ns_hosted", Mode: LibraryBindingModePin,
		PinnedVersionID: version.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "owner",
	}); err != nil {
		t.Fatal(err)
	}
	verifier, privateKey, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "pw", "hosted-library-secret", "https://engine.example", "https://console.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	path := "/api/library/resolve"
	body := []byte(`{"namespaceId":"ns_hosted"}`)
	claims := actorClaimsForTest(now, http.MethodPost, path, body)
	claims.UserID, claims.Role = "usr_owner", "owner"
	request := actorRequest(http.MethodPost, path, body, signActorAssertionForTest(t, privateKey, claims))
	request.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), version.ID) {
		t.Fatalf("hosted resolver = %d body=%s", recorder.Code, recorder.Body)
	}
}

func TestHostedLibraryPagesUseHeaderPagination(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	for _, suffix := range []string{"first", "second"} {
		if _, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: "hosted-library-page-" + suffix, Name: "Hosted library page " + suffix, CreatedBy: "usr_owner",
		}, LibrarySkillVersion{Content: "# hosted page " + suffix, CreatedBy: "usr_owner"}); err != nil {
			t.Fatalf("create %s hosted page skill: %v", suffix, err)
		}
	}
	verifier, privateKey, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "pw", "hosted-library-page-secret", "https://engine.example", "https://console.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	path := "/api/library/skills"

	first := hostedNamespaceRequestWithHeaders(t, mux, privateKey, now, "usr_owner", "owner", http.MethodGet, path, "", map[string]string{
		libraryConsolePageLimitHeader: "1",
	})
	if first.Code != http.StatusOK || first.Header().Get(libraryConsolePageNextCursorHeader) == "" {
		t.Fatalf("hosted first library page = %d headers=%v body=%s", first.Code, first.Header(), first.Body)
	}
	var firstRows []map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &firstRows); err != nil || len(firstRows) != 1 {
		t.Fatalf("hosted first library page rows=%s err=%v", first.Body, err)
	}

	second := hostedNamespaceRequestWithHeaders(t, mux, privateKey, now, "usr_owner", "owner", http.MethodGet, path, "", map[string]string{
		libraryConsolePageLimitHeader:  "1",
		libraryConsolePageCursorHeader: first.Header().Get(libraryConsolePageNextCursorHeader),
	})
	if second.Code != http.StatusOK {
		t.Fatalf("hosted cursor library page = %d body=%s", second.Code, second.Body)
	}
	var secondRows []map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &secondRows); err != nil || len(secondRows) != 1 || secondRows[0]["id"] == firstRows[0]["id"] {
		t.Fatalf("hosted cursor library page rows=%s err=%v", second.Body, err)
	}

	// The same actor assertion is valid for header pagination, but a query
	// string is rejected before the handler. Platform signs the bare path.
	claims := actorClaimsForTest(now, http.MethodGet, path, nil)
	claims.UserID, claims.Role = "usr_owner", "owner"
	query := actorRequest(http.MethodGet, path+"?limit=1", nil, signActorAssertionForTest(t, privateKey, claims))
	query.Header.Set("Authorization", "Bearer machine-token")
	queryRecorder := httptest.NewRecorder()
	mux.ServeHTTP(queryRecorder, query)
	if queryRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("hosted query library page = %d body=%s", queryRecorder.Code, queryRecorder.Body)
	}
}

func TestLibraryArtifactGrantConsolePinsVersionToExactActiveMCPClient(t *testing.T) {
	ctx := context.Background()
	mux, token, store := newLibraryConsole(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Design Codex", Subject: "usr_design", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Design handoff", Origin: LibraryArtifactOriginHuman, CreatedBy: "local-admin",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Exact reviewed input", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	grantsPath := "/api/library/artifacts/" + artifact.ID + "/grants"
	recorder, response := doJSON(t, mux, token, http.MethodPost, grantsPath, `{"artifactVersionId":"`+version.ID+`","agentSurfaceId":"`+client.ID+`"}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST artifact grant = %d body=%s", recorder.Code, recorder.Body)
	}
	grantID, _ := response["id"].(string)
	if grantID == "" || response["artifactVersionId"] != version.ID || response["artifactVersionDigest"] != version.Digest || response["agentSurfaceId"] != client.ID {
		t.Fatalf("grant response=%v", response)
	}
	if _, present := response["revokedAt"]; present {
		t.Fatalf("live artifact grant must omit revokedAt, got response=%v", response)
	}

	// A slug is public endpoint routing metadata, not the durable grant key.
	recorder, _ = doJSON(t, mux, token, http.MethodPost, grantsPath, `{"artifactVersionId":"`+version.ID+`","agentSurfaceId":"`+client.Slug+`"}`)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("slug grant target status=%d body=%s", recorder.Code, recorder.Body)
	}
	listRequest := httptest.NewRequest(http.MethodGet, grantsPath, nil)
	listRequest.Header.Set("Authorization", "Bearer "+token)
	listRecorder := httptest.NewRecorder()
	mux.ServeHTTP(listRecorder, listRequest)
	var grants []map[string]any
	if listRecorder.Code != http.StatusOK || json.Unmarshal(listRecorder.Body.Bytes(), &grants) != nil || len(grants) != 1 || grants[0]["id"] != grantID {
		t.Fatalf("GET artifact grants = %d body=%s", listRecorder.Code, listRecorder.Body)
	}
	if _, present := grants[0]["revokedAt"]; present {
		t.Fatalf("live artifact grant list must omit revokedAt, got grants=%v", grants)
	}

	recorder, revoked := doJSON(t, mux, token, http.MethodPost, grantsPath+"/"+grantID+"/revoke", "{}")
	revokedAt, isTimestamp := revoked["revokedAt"].(string)
	if recorder.Code != http.StatusOK || revoked["id"] != grantID || !isTimestamp || revokedAt == "" || revokedAt == "0001-01-01T00:00:00Z" {
		t.Fatalf("POST artifact grant revoke = %d body=%s", recorder.Code, recorder.Body)
	}
	// Retry preserves the original revocation evidence rather than creating a
	// new sharing decision.
	recorder, retried := doJSON(t, mux, token, http.MethodPost, grantsPath+"/"+grantID+"/revoke", "{}")
	if recorder.Code != http.StatusOK || retried["revokedAt"] != revoked["revokedAt"] || retried["revokedBy"] != revoked["revokedBy"] {
		t.Fatalf("retry grant revoke=%d body=%s", recorder.Code, recorder.Body)
	}
}

func TestHostedLibraryPublicationCandidateRequiresPlatformService(t *testing.T) {
	store := newLibraryFileStore(t)
	artifact, version, err := store.CreateLibraryArtifactWithInitialVersion(context.Background(), LibraryArtifact{
		Title: "Reviewed summary", Summary: "Safe public summary", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReviewLibraryArtifactVersion(context.Background(), artifact.ID, version.ID, LibraryRedactionApproved, "reviewer", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	verifier, privateKey, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "pw", "hosted-library-secret", "https://engine.example", "https://console.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	candidatePath := "/api/library/artifacts/" + artifact.ID + "/publication-candidate"
	claimPath := "/api/library/artifacts/" + artifact.ID + "/publication-claim"

	requestFor := func(method, path, body, userID, role string) *http.Request {
		claims := actorClaimsForTest(now, method, path, []byte(body))
		claims.UserID, claims.Role = userID, role
		request := actorRequest(method, path, []byte(body), signActorAssertionForTest(t, privateKey, claims))
		request.Header.Set("Authorization", "Bearer machine-token")
		return request
	}
	adminRecorder := httptest.NewRecorder()
	mux.ServeHTTP(adminRecorder, requestFor(http.MethodGet, candidatePath, "", "usr_owner", "owner"))
	if adminRecorder.Code != http.StatusForbidden {
		t.Fatalf("hosted browser admin candidate = %d body=%s", adminRecorder.Code, adminRecorder.Body)
	}

	serviceRecorder := httptest.NewRecorder()
	mux.ServeHTTP(serviceRecorder, requestFor(http.MethodGet, candidatePath, "", platformServiceActorID, "service"))
	if serviceRecorder.Code != http.StatusOK {
		t.Fatalf("hosted service candidate = %d body=%s", serviceRecorder.Code, serviceRecorder.Body)
	}
	var candidate map[string]any
	if err := json.Unmarshal(serviceRecorder.Body.Bytes(), &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate["artifactId"] != artifact.ID || candidate["redactionStatus"] != LibraryRedactionApproved || candidate["body"] != "# Safe" {
		t.Fatalf("publication candidate=%v", candidate)
	}
	if _, exposedReviewer := candidate["reviewedBy"]; exposedReviewer {
		t.Fatalf("candidate leaked reviewer identity: %v", candidate)
	}
	versionID, _ := candidate["artifactVersionId"].(string)
	digest, _ := candidate["digest"].(string)
	claimBody := `{"artifactVersionId":"` + versionID + `","digest":"` + digest + `"}`

	adminClaim := httptest.NewRecorder()
	mux.ServeHTTP(adminClaim, requestFor(http.MethodPost, claimPath, claimBody, "usr_owner", "owner"))
	if adminClaim.Code != http.StatusForbidden {
		t.Fatalf("hosted browser admin claim = %d body=%s", adminClaim.Code, adminClaim.Body)
	}
	serviceClaim := httptest.NewRecorder()
	mux.ServeHTTP(serviceClaim, requestFor(http.MethodPost, claimPath, claimBody, platformServiceActorID, "service"))
	if serviceClaim.Code != http.StatusOK || !strings.Contains(serviceClaim.Body.String(), versionID) {
		t.Fatalf("hosted service publication claim = %d body=%s", serviceClaim.Code, serviceClaim.Body)
	}
	staleClaim := httptest.NewRecorder()
	mux.ServeHTTP(staleClaim, requestFor(http.MethodPost, claimPath, `{"artifactVersionId":"libartv_stale","digest":"`+digest+`"}`, platformServiceActorID, "service"))
	if staleClaim.Code != http.StatusConflict {
		t.Fatalf("stale service publication claim = %d body=%s", staleClaim.Code, staleClaim.Body)
	}
}
