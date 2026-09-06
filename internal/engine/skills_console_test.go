package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// fakeSkillFetcher is the SkillSourceFetcher test seam: canned files, no git
// subprocess or network involved (see WithSkillFetcher in console.go).
type fakeSkillFetcher struct {
	commit, author string
	files          []SkillFile
	err            error
}

func (f *fakeSkillFetcher) Fetch(_ context.Context, _, _, _, _ string) (string, string, []SkillFile, error) {
	if f.err != nil {
		return "", "", nil, f.err
	}
	return f.commit, f.author, f.files, nil
}

const incidentTriageManifestV1 = `---
name: incident-triage
tools:
  - pagerduty__list_incidents
---
# Incident Triage
Look up open incidents before paging anyone.
`

// newSkillsConsole builds the same stack as newConnectorConsole
// (console_connectors_test.go) plus a fake skill fetcher, and pre-registers a
// "pagerduty" account exposing one tool so drift/checks have something real
// to resolve against.
func newSkillsConsole(t *testing.T, fetcher *fakeSkillFetcher, requiredArgs []string) (*http.ServeMux, string, *Gateway, *FileStore) {
	t.Helper()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	if err := fs.Upsert(context.Background(), Account{Name: "pagerduty", URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		if a.Name != "pagerduty" {
			return nil, nil
		}
		tool := mcp.NewTool(a.Name + "__list_incidents")
		tool.InputSchema.Required = requiredArgs
		tool.InputSchema.Properties = map[string]any{}
		for _, arg := range requiredArgs {
			tool.InputSchema.Properties[arg] = map[string]any{"type": "string"}
		}
		// mcp.NewTool defaults DestructiveHint=true/ReadOnlyHint=false
		// regardless of name; set the annotation explicitly so this fixture's
		// deliberately-read-shaped "list_incidents" tool actually reads as
		// read-only for the "no destructive tools referenced" check.
		readOnly := true
		tool.Annotations.ReadOnlyHint = &readOnly
		return []mcp.Tool{tool}, nil
	}
	g.Aggregate(context.Background())

	api := NewConsoleAPI(fs, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "", WithSkillFetcher(fetcher))
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), g, fs
}

func TestSkillsAddFromRepoAndListHappyPath(t *testing.T) {
	fetcher := &fakeSkillFetcher{
		commit: "a1c9f2", author: "Jane Doe",
		files: []SkillFile{{Path: "skills/incident-triage.md", Content: incidentTriageManifestV1}},
	}
	mux, tok, _, _ := newSkillsConsole(t, fetcher, nil)

	// ADD FROM REPO: creates the source and syncs immediately.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/skill-sources",
		`{"repo":"tegence/skills","url":"https://example.com/tegence/skills.git","branch":"main","path":"skills"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/skill-sources = %d, body %s", rec.Code, rec.Body)
	}
	if got["skillCount"] != float64(1) {
		t.Fatalf("skillCount = %v, want 1", got["skillCount"])
	}
	if got["lastSyncError"] != nil && got["lastSyncError"] != "" {
		t.Fatalf("lastSyncError = %v, want empty", got["lastSyncError"])
	}
	sourceID, _ := got["id"].(string)
	if sourceID == "" {
		t.Fatal("created source has no id")
	}

	// LIST: the synced skill shows up with version 1 and state "current".
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/skills", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/skills = %d, body %s", rec.Code, rec.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	sk := list[0]
	if sk["name"] != "incident-triage" {
		t.Errorf("name = %v, want incident-triage", sk["name"])
	}
	if sk["version"] != float64(1) || sk["latestVersion"] != float64(1) {
		t.Errorf("version/latestVersion = %v/%v, want 1/1", sk["version"], sk["latestVersion"])
	}
	if sk["state"] != "current" {
		t.Errorf("state = %v, want current", sk["state"])
	}
	if sk["commit"] != "a1c9f2" {
		t.Errorf("commit = %v, want a1c9f2", sk["commit"])
	}
	skillID, _ := sk["id"].(string)
	if skillID == "" {
		t.Fatal("skill has no id")
	}

	// DETAIL: version 1 carries the referenced tool and a positive token count.
	rec, got = doJSON(t, mux, tok, http.MethodGet, "/api/skills/"+skillID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/skills/{id} = %d, body %s", rec.Code, rec.Body)
	}
	versions, _ := got["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("versions = %v, want 1 entry", got["versions"])
	}
	v0 := versions[0].(map[string]any)
	if tools, _ := v0["tools"].([]any); len(tools) != 1 || tools[0] != "pagerduty__list_incidents" {
		t.Errorf("version tools = %v, want [pagerduty__list_incidents]", v0["tools"])
	}
	if ct, _ := got["contextTokens"].(float64); ct <= 0 {
		t.Errorf("contextTokens = %v, want > 0", got["contextTokens"])
	}

	// PIN: attach the skill to a connector.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"On-call","slug":"oncall","tools":{"pagerduty":["list_incidents"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/connectors = %d, body %s", rec.Code, rec.Body)
	}

	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/skills/"+skillID+"/pins",
		`{"connectorSlug":"oncall","mode":"track","surfaces":["claude-code","slack"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/skills/{id}/pins = %d, body %s", rec.Code, rec.Body)
	}
	if got["mode"] != "track" || got["connectorLabel"] != "On-call" {
		t.Fatalf("carrier DTO = %v", got)
	}
	if got["toolCount"] != float64(1) {
		t.Errorf("toolCount = %v, want 1 (from the connector's exposed tools)", got["toolCount"])
	}

	// RUN CHECKS: all green, since the live tool matches the pinned snapshot.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/skills/"+skillID+"/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/skills/{id}/checks = %d, body %s", rec.Code, rec.Body)
	}
	if got["failed"] != float64(0) {
		t.Fatalf("checks failed = %v, want 0: %v", got["failed"], got["results"])
	}

	// DETACH: remove the pin.
	rec, _ = doJSON(t, mux, tok, http.MethodDelete, "/api/skills/"+skillID+"/pins/oncall", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE pin = %d, body %s", rec.Code, rec.Body)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/skills/"+skillID+"/pins", "")
	var carriers []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &carriers)
	if len(carriers) != 0 {
		t.Fatalf("carriers after detach = %v, want none", carriers)
	}

	// DELETE SOURCE cascades: the skill disappears too.
	rec, _ = doJSON(t, mux, tok, http.MethodDelete, "/api/skill-sources/"+sourceID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE skill-source = %d, body %s", rec.Code, rec.Body)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/skills", "")
	var afterDelete []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &afterDelete)
	if len(afterDelete) != 0 {
		t.Fatalf("skills after source delete = %v, want none (cascade)", afterDelete)
	}
}

// TestSkillsDriftDetectionAndFilter exercises the drift path end to end: a
// skill is synced against a tool with no required args, the live tool then
// grows a new required argument, and "+ Run checks" both fails the
// "required arguments present" check AND flips the skill's list-screen state
// to "drifted" — matching the design's "You find out when it rots" story.
func TestSkillsDriftDetectionAndFilter(t *testing.T) {
	fetcher := &fakeSkillFetcher{
		commit: "4b7e10", author: "Samiat A.",
		files: []SkillFile{{Path: "skills/incident-triage.md", Content: incidentTriageManifestV1}},
	}
	mux, tok, g, fs := newSkillsConsole(t, fetcher, nil) // starts with NO required args

	_, got := doJSON(t, mux, tok, http.MethodPost, "/api/skill-sources",
		`{"url":"https://example.com/tegence/skills.git","branch":"main","path":"skills"}`)
	skills, _ := fs.SkillsBySource(context.Background(), got["id"].(string))
	if len(skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(skills))
	}
	skillID := skills[0].ID

	// Sanity: nothing drifted yet.
	rec, _ := doJSON(t, mux, tok, http.MethodGet, "/api/skills?state=drifted", "")
	var drifted []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &drifted)
	if len(drifted) != 0 {
		t.Fatalf("drifted list before the live tool changed = %v, want none", drifted)
	}

	// The live tool now requires "urgency" — a change the pinned version's
	// snapshot never saw.
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		tool := mcp.NewTool(a.Name + "__list_incidents")
		tool.InputSchema.Required = []string{"urgency"}
		tool.InputSchema.Properties = map[string]any{"urgency": map[string]any{"type": "string"}}
		return []mcp.Tool{tool}, nil
	}
	g.Aggregate(context.Background())

	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/skills/"+skillID+"/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST checks = %d, body %s", rec.Code, rec.Body)
	}
	if got["failed"] == float64(0) {
		t.Fatalf("expected a failing check after the live tool grew a required arg: %v", got["results"])
	}

	rec, got = doJSON(t, mux, tok, http.MethodGet, "/api/skills/"+skillID, "")
	if got["state"] != "drifted" {
		t.Fatalf("state = %v, want drifted", got["state"])
	}
	driftRows, _ := got["drift"].([]any)
	if len(driftRows) != 1 {
		t.Fatalf("drift = %v, want 1 finding", got["drift"])
	}
	finding := driftRows[0].(map[string]any)
	if finding["change"] != "new required field `urgency`" {
		t.Errorf("drift change = %v, want \"new required field `urgency`\"", finding["change"])
	}

	// The "Drift · N" tab filter surfaces exactly this skill.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/skills?state=drifted", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &drifted)
	if len(drifted) != 1 || drifted[0]["id"] != skillID {
		t.Fatalf("drifted filter = %v, want exactly skill %q", drifted, skillID)
	}
}

func TestSkillSourceSyncFailureIsNonFatal(t *testing.T) {
	fetcher := &fakeSkillFetcher{err: context.DeadlineExceeded}
	mux, tok, _, _ := newSkillsConsole(t, fetcher, nil)

	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/skill-sources",
		`{"url":"https://example.com/unreachable.git"}`)
	// The source row still gets created — a bad first sync is not fatal,
	// mirroring how a newly connected account with a failed probe still
	// persists (see console.go's connect flow).
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/skill-sources = %d, body %s", rec.Code, rec.Body)
	}
	if got["lastSyncError"] == nil || got["lastSyncError"] == "" {
		t.Fatalf("lastSyncError = %v, want a non-empty error", got["lastSyncError"])
	}
	if got["skillCount"] != float64(0) {
		t.Fatalf("skillCount = %v, want 0 (fetch failed before any skill was discovered)", got["skillCount"])
	}
}
