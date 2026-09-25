package engine

import (
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestEstimateTokens(t *testing.T) {
	cases := []struct {
		content string
		want    int
	}{
		{"", 0},
		{"abcd", 1},
		{"abcde", 2},
		{"a very small skill file with about forty chars", 12}, // 48 runes -> ceil(48/4)=12
	}
	for _, tc := range cases {
		if got := estimateTokens(tc.content); got != tc.want {
			t.Errorf("estimateTokens(%q) = %d, want %d", tc.content, got, tc.want)
		}
	}
}

func TestParseSkillManifest(t *testing.T) {
	content := `---
name: incident-triage
tools:
  - pagerduty__list_incidents
  - linear__create_issue
  - slack__post_message
---
# Incident Triage
Body content here.
`
	m, err := parseSkillManifest(content)
	if err != nil {
		t.Fatalf("parseSkillManifest: %v", err)
	}
	if m.Name != "incident-triage" {
		t.Errorf("Name = %q, want incident-triage", m.Name)
	}
	want := []string{"pagerduty__list_incidents", "linear__create_issue", "slack__post_message"}
	if !equalStringSlices(m.Tools, want) {
		t.Errorf("Tools = %v, want %v", m.Tools, want)
	}
}

func TestParseSkillManifestNoFrontmatter(t *testing.T) {
	if _, err := parseSkillManifest("# just a heading\nno frontmatter here"); err == nil {
		t.Fatal("expected errNoFrontmatter for a file with no frontmatter block")
	}
}

func TestParseSkillManifestUnterminated(t *testing.T) {
	if _, err := parseSkillManifest("---\nname: x\ntools:\n  - a\n"); err == nil {
		t.Fatal("expected an error for an unterminated frontmatter block")
	}
}

func TestClassifySkillState(t *testing.T) {
	cases := []struct {
		name          string
		latestVersion int
		carriers      []SkillCarrier
		driftCount    int
		want          SkillState
	}{
		{"no carriers, no drift", 3, nil, 0, SkillStateCurrent},
		{"tracking latest only", 3, []SkillCarrier{{Mode: SkillCarrierModeTrack}}, 0, SkillStateCurrent},
		{"pinned at latest", 3, []SkillCarrier{{Mode: SkillCarrierModePin, PinnedVersion: 3}}, 0, SkillStateCurrent},
		{"pinned below latest", 4, []SkillCarrier{{Mode: SkillCarrierModePin, PinnedVersion: 2}}, 0, SkillStateBehind},
		{"drift wins over pin-behind", 4, []SkillCarrier{{Mode: SkillCarrierModePin, PinnedVersion: 2}}, 1, SkillStateDrifted},
		{"drift with no carriers", 7, nil, 3, SkillStateDrifted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySkillState(tc.latestVersion, tc.carriers, tc.driftCount); got != tc.want {
				t.Errorf("classifySkillState() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMostBehindPinnedVersion(t *testing.T) {
	carriers := []SkillCarrier{
		{Mode: SkillCarrierModePin, PinnedVersion: 9},
		{Mode: SkillCarrierModeTrack},
		{Mode: SkillCarrierModePin, PinnedVersion: 5},
	}
	v, ok := mostBehindPinnedVersion(11, carriers)
	if !ok || v != 5 {
		t.Fatalf("mostBehindPinnedVersion = (%d,%v), want (5,true)", v, ok)
	}
	if _, ok := mostBehindPinnedVersion(11, []SkillCarrier{{Mode: SkillCarrierModeTrack}}); ok {
		t.Fatal("expected ok=false when nothing is behind")
	}
}

func toolWithSchema(name string, required []string, props []string) mcp.Tool {
	tool := mcp.NewTool(name)
	tool.InputSchema.Required = required
	if len(props) > 0 {
		tool.InputSchema.Properties = map[string]any{}
		for _, p := range props {
			tool.InputSchema.Properties[p] = map[string]any{"type": "string"}
		}
	}
	return tool
}

func TestDiffToolSchemaNewRequiredField(t *testing.T) {
	prior := skillToolSchema{Properties: []string{"title"}, Required: []string{"title"}}
	current := snapshotToolSchema(toolWithSchema("linear__create_issue", []string{"title", "teamId"}, []string{"title", "teamId"}))
	got := diffToolSchema(prior, current)
	want := "new required field `teamId`"
	if got != want {
		t.Errorf("diffToolSchema = %q, want %q", got, want)
	}
}

func TestDiffToolSchemaArgumentRemoved(t *testing.T) {
	prior := skillToolSchema{Properties: []string{"incident_id", "urgency"}, Required: nil}
	current := snapshotToolSchema(toolWithSchema("pagerduty__list_incidents", nil, []string{"incident_id"}))
	got := diffToolSchema(prior, current)
	want := "argument `urgency` was removed"
	if got != want {
		t.Errorf("diffToolSchema = %q, want %q", got, want)
	}
}

func TestDiffToolSchemaNoChange(t *testing.T) {
	prior := skillToolSchema{Properties: []string{"channel", "text"}, Required: []string{"channel"}}
	current := snapshotToolSchema(toolWithSchema("slack__post_message", []string{"channel"}, []string{"channel", "text"}))
	if got := diffToolSchema(prior, current); got != "" {
		t.Errorf("diffToolSchema = %q, want \"\" (no drift)", got)
	}
}

func TestComputeSkillDriftToolRemoved(t *testing.T) {
	v := SkillVersion{
		Tools:       []string{"pagerduty__list_incidents"},
		ToolSchemas: map[string]skillToolSchema{"pagerduty__list_incidents": {Properties: []string{"urgency"}}},
	}
	findings := computeSkillDrift(v, map[string]mcp.Tool{}) // tool no longer live
	if len(findings) != 1 || findings[0].Change != "tool is no longer available" {
		t.Fatalf("findings = %+v, want one 'tool is no longer available' finding", findings)
	}
}

func TestReconcileDriftFindingsPreservesDetectedAt(t *testing.T) {
	old := time.Now().Add(-4 * 24 * time.Hour)
	existing := []SkillDriftFinding{{ID: "drift_1", SkillID: "skl_1", Tool: "pagerduty__list_incidents", Change: "argument `urgency` was removed", DetectedAt: old}}
	fresh := []SkillDriftFinding{
		{Tool: "pagerduty__list_incidents", Change: "argument `urgency` was removed"}, // same finding, should keep old DetectedAt
		{Tool: "linear__create_issue", Change: "new required field `teamId`"},         // new finding, should get now()
	}
	now := time.Now()
	out := reconcileDriftFindings("skl_1", fresh, existing, now)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	byTool := map[string]SkillDriftFinding{}
	for _, f := range out {
		byTool[f.Tool] = f
	}
	if !byTool["pagerduty__list_incidents"].DetectedAt.Equal(old) {
		t.Errorf("existing finding's DetectedAt was reset: got %v, want %v", byTool["pagerduty__list_incidents"].DetectedAt, old)
	}
	if byTool["pagerduty__list_incidents"].ID != "drift_1" {
		t.Errorf("existing finding's ID changed: got %q, want drift_1", byTool["pagerduty__list_incidents"].ID)
	}
	if !byTool["linear__create_issue"].DetectedAt.Equal(now) {
		t.Errorf("new finding's DetectedAt = %v, want %v", byTool["linear__create_issue"].DetectedAt, now)
	}
	if byTool["linear__create_issue"].ID == "" {
		t.Error("new finding did not get an ID")
	}
}

func TestRunSkillChecks(t *testing.T) {
	live := map[string]mcp.Tool{
		"linear__create_issue": toolWithSchema("linear__create_issue", []string{"title", "teamId"}, []string{"title", "teamId"}),
	}
	v := SkillVersion{
		SkillID: "skl_1", Version: 7,
		Tools:         []string{"linear__create_issue", "pagerduty__list_incidents"}, // pagerduty no longer live
		ToolSchemas:   map[string]skillToolSchema{"linear__create_issue": {Properties: []string{"title"}, Required: []string{"title"}}},
		ContextTokens: 3400,
	}
	run := runSkillChecks(v, live)
	if run.SkillID != "skl_1" || run.Version != 7 {
		t.Fatalf("run identity = %+v", run)
	}
	byName := map[string]SkillCheckResult{}
	for _, res := range run.Results {
		byName[res.Name] = res
	}
	if r := byName["references resolve"]; r.Passed {
		t.Errorf("references resolve should fail: pagerduty tool is missing; got %+v", r)
	}
	if r := byName["required arguments present"]; r.Passed {
		t.Errorf("required arguments present should fail: teamId is newly required; got %+v", r)
	}
	if r := byName["token budget under 4k"]; !r.Passed {
		t.Errorf("token budget should pass at 3400 tokens; got %+v", r)
	}
	if run.Passed()+run.Failed() != len(run.Results) {
		t.Errorf("Passed()+Failed() = %d, want %d", run.Passed()+run.Failed(), len(run.Results))
	}
	if run.Failed() == 0 {
		t.Error("expected at least one failing check")
	}
}

func TestRunSkillChecksAllPass(t *testing.T) {
	// "list_messages" is deliberately a READ-verb name (see readOnlyName's
	// write-verb-veto heuristic in gateway.go — "post_message" would fail the
	// "no destructive tools referenced" check, which is correct behavior, not
	// what this test is verifying). mcp.NewTool defaults DestructiveHint=true
	// / ReadOnlyHint=false regardless of name, so the explicit annotation
	// hint is set here to exercise the "annotation wins over name heuristic"
	// branch of readOnlyTool (gateway.go) the way a real upstream would.
	tool := toolWithSchema("slack__list_messages", []string{"channel"}, []string{"channel", "text"})
	readOnly := true
	tool.Annotations.ReadOnlyHint = &readOnly
	live := map[string]mcp.Tool{"slack__list_messages": tool}
	v := SkillVersion{
		SkillID: "skl_2", Version: 1,
		Tools:         []string{"slack__list_messages"},
		ToolSchemas:   map[string]skillToolSchema{"slack__list_messages": {Properties: []string{"channel", "text"}, Required: []string{"channel"}}},
		ContextTokens: 1100,
	}
	run := runSkillChecks(v, live)
	if run.Failed() != 0 {
		t.Fatalf("expected all checks to pass, got %d failures: %+v", run.Failed(), run.Results)
	}
}

func TestBareToolName(t *testing.T) {
	if got := bareToolName("pagerduty__list_incidents"); got != "list_incidents" {
		t.Errorf("bareToolName = %q, want list_incidents", got)
	}
	if got := bareToolName("no_prefix"); got != "no_prefix" {
		t.Errorf("bareToolName with no prefix = %q, want no_prefix", got)
	}
}

func TestDigestContentStableAndSensitive(t *testing.T) {
	a := digestContent("hello world")
	b := digestContent("hello world")
	c := digestContent("hello world!")
	if a != b {
		t.Error("digestContent is not stable for identical input")
	}
	if a == c {
		t.Error("digestContent did not change for different input")
	}
}
