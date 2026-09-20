package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// Skills domain
//
// A skill is a versioned procedure file (Markdown + a small frontmatter
// manifest) tracked from a git repository ("skill source"), delivered to
// agents through the connector(s) it is attached to. See
// docs/design-upgrades/08-skills.md for the product spec this implements.
// That report explicitly flags several modeling questions as open design
// decisions rather than settled spec; the choices made below are documented
// inline at the point each one is made, per the report's own instruction to
// pick the simplest choice consistent with how the rest of the engine already
// models similar concepts, rather than block on missing design.
//
// ASSUMPTION (open question: "which connector concept carries a skill" —
// report line ~231): a skill is attached to a VirtualConnector (the existing
// curated `/api/connectors` resource, see gateway_connectors.go), identified
// by SkillCarrier.ConnectorSlug. VirtualConnector is already the layer that
// owns tool exposure + approval policy, which is exactly what the design's
// "Bounded by the connector: 9 tools, 2 ask-first" footer describes (compare
// connectorDTO.Tools / connectorDTO.Approval in console.go). EndpointBundle
// carries no approval/guardrail policy and MCPClient is a subject-bound
// registration — neither matches the design's narrative as well.
// ---------------------------------------------------------------------------

// SkillSource is a git repository Synaxis watches for skill files.
type SkillSource struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Repo string `json:"repo"` // display form, e.g. "tegence/skills"
	URL  string `json:"url"`  // clone URL (git remote)
	// Token is optional credential material for a private repository (a PAT,
	// mirroring how a GitHub PAT account already works via Account.BearerToken
	// elsewhere in this engine). Tagged so FileStore can round-trip it to
	// disk like every other FileStore-held secret (plaintext JSON, same as
	// Account credentials — see store.go's dev-only-plaintext posture); it is
	// PgStore-encrypted at rest (skills_pg.go) and skills_console.go's DTO
	// never includes it in a console response.
	Token  string `json:"token,omitempty"`
	Branch string `json:"branch"` // watched branch
	// Path is the repo-relative directory scanned for skill files. v1
	// recognizes exactly "*.md" files found anywhere under Path (one skill per
	// file), matching the design's example paths ("skills/incident-triage.md").
	Path           string    `json:"path"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	LastSyncedAt   time.Time `json:"lastSyncedAt,omitempty"`
	LastSyncCommit string    `json:"lastSyncCommit,omitempty"`
	LastSyncError  string    `json:"lastSyncError,omitempty"`
}

// Skill is one tracked procedure file discovered under a SkillSource.
type Skill struct {
	ID        string    `json:"id"`
	SourceID  string    `json:"sourceId"`
	Name      string    `json:"name"` // derived from the file name, e.g. "incident-triage"
	Path      string    `json:"path"` // repo-relative path
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// skillToolSchema is a shallow snapshot of a referenced tool's input-schema
// shape — just enough to explain WHAT changed (new required field / removed
// argument) without storing or diffing full JSON Schema semantics.
type skillToolSchema struct {
	Properties []string `json:"properties"`
	Required   []string `json:"required"`
}

// SkillVersion is one synced snapshot of a skill file's content.
type SkillVersion struct {
	ID      string `json:"id"`
	SkillID string `json:"skillId"`
	Version int    `json:"version"` // 1-based, monotonically increasing per skill
	// Commit/Author identify the sync that produced this version.
	//
	// v1 SIMPLIFICATION (documented rather than blocking, per the task's
	// instruction to leave a clear comment on a deliberate shortcut): the
	// engine does not walk `git log` per path. Every skill version produced by
	// the same source sync carries that sync's source-HEAD commit/author, not
	// a precise per-file last-touch commit. A real per-path git-blame walk
	// (more `git log -1 -- <path>` calls per sync) is straightforward to add
	// later but is not needed for a v1 that only needs *a* trackable, stable
	// version identity per skill snapshot.
	Commit string `json:"commit"`
	Author string `json:"author"`
	// Digest/Content/ToolSchemas are internal storage fields (FileStore
	// round-trips domain structs directly to JSON on disk, so these DO need
	// real tags to persist — PgStore instead maps them to explicit columns).
	// Neither is ever written into a console response: skills_console.go's
	// DTOs are built field-by-field and never json.Marshal a SkillVersion
	// wholesale.
	Digest        string                     `json:"digest,omitempty"`
	Content       string                     `json:"content,omitempty"`
	ContextTokens int                        `json:"contextTokens"`
	Tools         []string                   `json:"tools"`                 // referenced tool names, from frontmatter
	ToolSchemas   map[string]skillToolSchema `json:"toolSchemas,omitempty"` // live schema snapshot at sync time, keyed by tool name
	CreatedAt     time.Time                  `json:"createdAt"`
}

const (
	SkillCarrierModePin   = "pin"
	SkillCarrierModeTrack = "track"
)

// SkillCarrier attaches a skill to the connector that delivers it, with
// pin/track semantics: a "pin" carrier is locked to PinnedVersion; a "track"
// carrier always serves the skill's latest synced version.
type SkillCarrier struct {
	ID            string `json:"id"`
	SkillID       string `json:"skillId"`
	ConnectorSlug string `json:"connectorSlug"`
	Mode          string `json:"mode"`                    // SkillCarrierModePin | SkillCarrierModeTrack
	PinnedVersion int    `json:"pinnedVersion,omitempty"` // meaningful only when Mode == pin
	// Surfaces is a free-form, operator-supplied list of client-type labels
	// (e.g. "claude-code", "slack", "cron").
	//
	// ASSUMPTION (open question: the "surfaces" data model — report line
	// ~232 — does not exist anywhere in the engine; nothing today records what
	// client type consumes an endpoint): rather than invent a client-type
	// taxonomy tied into MCPClient (a much bigger, security-relevant change to
	// an unrelated subsystem), v1 treats surfaces as plain operator-entered
	// labels stored on the pin/track record itself. This is enough to power
	// the design's "REACHES" chip row and the "N surfaces" stat without
	// widening MCPClient's contract.
	Surfaces  []string  `json:"surfaces,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SkillDriftFinding is one detected mismatch between a skill's latest synced
// version and the live tool it references. Drift is evaluated against the
// LATEST version only (not per-pin) — see classifySkillState's doc comment
// for why, and computeSkillDrift for how findings are produced.
type SkillDriftFinding struct {
	ID         string    `json:"id"`
	SkillID    string    `json:"skillId"`
	Tool       string    `json:"tool"`
	Change     string    `json:"change"`
	DetectedAt time.Time `json:"detectedAt"`
}

// SkillCheckResult is the outcome of one check in a checks run.
type SkillCheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// SkillCheckRun is the result of one "Run checks" execution. v1 keeps only
// the LATEST run per skill (one row, upserted) rather than a full history —
// the design's "History" tab has no frame to build against (report line
// ~236), so there is nothing yet that would consume older runs.
type SkillCheckRun struct {
	SkillID string             `json:"skillId"`
	Version int                `json:"version"`
	RanAt   time.Time          `json:"ranAt"`
	Results []SkillCheckResult `json:"results"`
}

// Passed/Failed count check results for the "N passed / N failed" pills.
func (r SkillCheckRun) Passed() int { return r.countWhere(true) }
func (r SkillCheckRun) Failed() int { return r.countWhere(false) }

func (r SkillCheckRun) countWhere(passed bool) int {
	n := 0
	for _, res := range r.Results {
		if res.Passed == passed {
			n++
		}
	}
	return n
}

// SkillState is the single-pill classification shown on the list screen.
type SkillState string

const (
	SkillStateCurrent SkillState = "current"
	SkillStateDrifted SkillState = "drifted"
	SkillStateBehind  SkillState = "behind"
)

// classifySkillState picks ONE state for the list-screen pill.
//
// ASSUMPTION (the Figma list table shows one state per skill row, but a skill
// can be pinned at different versions on different connectors — see the
// Versions/Delivered-by cards in the detail frame, where "On-call connector"
// is pinned v7 while "Support connector" tracks latest): drift takes
// precedence over "behind a pin" because an active drift finding means
// something is factually broken right now, whereas a lagging pin merely
// hasn't been advanced yet. This also matches the sample detail data:
// incident-triage is Drifted while sitting AT its latest version (v7) — drift
// is evaluated against latest, independent of any connector's pin.
func classifySkillState(latestVersion int, carriers []SkillCarrier, driftCount int) SkillState {
	if driftCount > 0 {
		return SkillStateDrifted
	}
	for _, c := range carriers {
		if c.Mode == SkillCarrierModePin && c.PinnedVersion > 0 && c.PinnedVersion < latestVersion {
			return SkillStateBehind
		}
	}
	return SkillStateCurrent
}

// mostBehindPinnedVersion returns the lowest version any "pin" carrier is
// stuck on, for the list row's "vN · latest vM" display. ok=false means no
// carrier is behind (the caller should show the latest version instead).
func mostBehindPinnedVersion(latestVersion int, carriers []SkillCarrier) (int, bool) {
	best := latestVersion
	found := false
	for _, c := range carriers {
		if c.Mode == SkillCarrierModePin && c.PinnedVersion > 0 && c.PinnedVersion < best {
			best = c.PinnedVersion
			found = true
		}
	}
	return best, found
}

// estimateTokens is a measured-cost ESTIMATE for "context-cost accounting",
// not a call to a real tokenizer: ~4 characters per token is the standard
// rough heuristic for English text (cited by both OpenAI's and Anthropic's
// own docs for ballpark sizing). Keeping this a pure, swappable function
// means a real tokenizer can replace it later without touching call sites.
func estimateTokens(content string) int {
	n := len([]rune(content))
	if n == 0 {
		return 0
	}
	return (n + 3) / 4
}

// digestContent returns a stable content hash used only to detect whether a
// skill file changed between syncs (i.e. whether a new SkillVersion is
// needed) — never displayed to the console.
func digestContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// skillManifest is the minimal frontmatter this engine understands.
type skillManifest struct {
	Name  string
	Tools []string
}

var errNoFrontmatter = errors.New("skill file has no YAML frontmatter block")

// parseSkillManifest extracts a skill file's frontmatter.
//
// v1 SIMPLIFICATION (documented, no new dependency added — go.mod carries no
// YAML library today and adding one purely for two flat keys would be the
// kind of speculative dependency this project's own conventions avoid): this
// is a deliberately narrow parser for exactly two flat forms —
//
//	---
//	name: incident-triage
//	tools:
//	  - pagerduty__list_incidents
//	  - linear__create_issue
//	---
//
// "name: <string>" and a "tools:" block of "  - <item>" lines. Nested maps,
// multi-line strings, flow sequences ("[a, b]"), and quoting edge cases are
// NOT supported. A skill file that needs richer frontmatter is out of scope
// for v1; this is enough to drive tool-reference drift/checks, which is the
// only thing the manifest is used for.
func parseSkillManifest(content string) (skillManifest, error) {
	var m skillManifest
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return m, errNoFrontmatter
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return m, errNoFrontmatter
	}
	inTools := false
	for _, raw := range lines[1:end] {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if inTools && strings.HasPrefix(trimmed, "- ") {
			item := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")), `"' `)
			if item != "" {
				m.Tools = append(m.Tools, item)
			}
			continue
		}
		inTools = false
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "name":
			m.Name = strings.Trim(val, `"'`)
		case "tools":
			inTools = val == "" // "tools:" with nothing after the colon starts a list block
		}
	}
	return m, nil
}

// snapshotToolSchema captures the shallow shape of a live tool's input schema
// for later drift comparison.
func snapshotToolSchema(t mcp.Tool) skillToolSchema {
	props := make([]string, 0, len(t.InputSchema.Properties))
	for k := range t.InputSchema.Properties {
		props = append(props, k)
	}
	sort.Strings(props)
	req := append([]string(nil), t.InputSchema.Required...)
	sort.Strings(req)
	return skillToolSchema{Properties: props, Required: req}
}

// diffToolSchema explains what changed between a pinned snapshot and a tool's
// current live schema, in the design's own vocabulary ("argument `urgency`
// was removed", "new required field `teamId`"). Returns "" when nothing
// worth surfacing changed.
func diffToolSchema(prior, current skillToolSchema) string {
	curProps := toSet(current.Properties)
	priorRequired := toSet(prior.Required)
	for _, name := range current.Required {
		if !priorRequired[name] {
			return "new required field `" + name + "`"
		}
	}
	for _, name := range prior.Properties {
		if !curProps[name] {
			return "argument `" + name + "` was removed"
		}
	}
	if !equalStringSlices(prior.Properties, current.Properties) || !equalStringSlices(prior.Required, current.Required) {
		return "response shape changed"
	}
	return ""
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeSkillDrift compares a version's tool-schema snapshot against the
// live tool set and returns freshly detected findings (no IDs / DetectedAt
// yet — see reconcileDriftFindings, which assigns those against the
// previously persisted set so ages are preserved across repeated runs).
func computeSkillDrift(v SkillVersion, live map[string]mcp.Tool) []SkillDriftFinding {
	var findings []SkillDriftFinding
	for _, name := range v.Tools {
		tool, ok := live[name]
		prior, hadSnapshot := v.ToolSchemas[name]
		switch {
		case !ok:
			findings = append(findings, SkillDriftFinding{Tool: name, Change: "tool is no longer available"})
		case hadSnapshot:
			if change := diffToolSchema(prior, snapshotToolSchema(tool)); change != "" {
				findings = append(findings, SkillDriftFinding{Tool: name, Change: change})
			}
		}
	}
	return findings
}

// reconcileDriftFindings merges freshly computed findings with the
// previously persisted set: a finding matching an existing (tool, change)
// pair keeps its original ID/DetectedAt, so the console shows genuine
// "detected N days ago" ages instead of resetting on every check/sync run.
func reconcileDriftFindings(skillID string, fresh, existing []SkillDriftFinding, now time.Time) []SkillDriftFinding {
	existingByKey := make(map[string]SkillDriftFinding, len(existing))
	for _, f := range existing {
		existingByKey[f.Tool+"\x00"+f.Change] = f
	}
	out := make([]SkillDriftFinding, 0, len(fresh))
	for _, f := range fresh {
		f.SkillID = skillID
		if prior, ok := existingByKey[f.Tool+"\x00"+f.Change]; ok {
			f.ID, f.DetectedAt = prior.ID, prior.DetectedAt
		} else {
			f.ID, f.DetectedAt = "drift_"+newEpoch(), now
		}
		out = append(out, f)
	}
	return out
}

// defaultSkillTokenBudget is the "token budget under Nk" check threshold —
// matches the design's own example ("token budget under 4k").
const defaultSkillTokenBudget = 4000

// bareToolName strips the "<account>__" prefix the aggregator adds, for
// reuse with the existing readOnlyTool heuristic (gateway.go), which expects
// the bare upstream name.
func bareToolName(prefixed string) string {
	if _, bare, ok := strings.Cut(prefixed, "__"); ok {
		return bare
	}
	return prefixed
}

// runSkillChecks executes the v1 checks runner.
//
// ASSUMPTION (report explicitly asks for "what checks means concretely...
// keep it lean, this is v1"): the design's six example check rows are
// narrowed to five verifiable checks here. "output schema matches" and
// "example run completes" are DROPPED for v1 — MCP tools generally carry no
// output schema to diff (mcp.Tool.OutputSchema is rarely populated by
// upstreams in practice), and there is no example-args fixture anywhere in
// the manifest format to execute against a live connector; building either
// would mean inventing more product surface than a lean v1 checks runner
// warrants. The five kept checks are deterministic, computable purely from
// data the sync pipeline already gathers, and cover the same failure classes
// the report's examples demonstrate: a missing/renamed tool, a newly required
// argument, an over-budget skill, and an unsafe tool reference.
func runSkillChecks(v SkillVersion, live map[string]mcp.Tool) SkillCheckRun {
	run := SkillCheckRun{SkillID: v.SkillID, Version: v.Version, RanAt: time.Now().UTC()}

	if len(v.Tools) == 0 {
		run.Results = append(run.Results, SkillCheckResult{Name: "manifest declares tools", Passed: false, Detail: "no tools: list found in frontmatter"})
	} else {
		run.Results = append(run.Results, SkillCheckResult{Name: "manifest declares tools", Passed: true})
	}

	var missing []string
	for _, name := range v.Tools {
		if _, ok := live[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		run.Results = append(run.Results, SkillCheckResult{Name: "references resolve", Passed: true, Detail: fmt.Sprintf("%d tools found", len(v.Tools))})
	} else {
		run.Results = append(run.Results, SkillCheckResult{Name: "references resolve", Passed: false, Detail: strings.Join(missing, ", ") + " not found"})
	}

	argFail := ""
	for _, name := range v.Tools {
		tool, ok := live[name]
		if !ok {
			continue // already reported by "references resolve"
		}
		prior := v.ToolSchemas[name]
		required := toSet(prior.Required)
		for _, req := range snapshotToolSchema(tool).Required {
			if !required[req] {
				argFail = name + " missing " + req
				break
			}
		}
		if argFail != "" {
			break
		}
	}
	run.Results = append(run.Results, SkillCheckResult{Name: "required arguments present", Passed: argFail == "", Detail: argFail})

	run.Results = append(run.Results, SkillCheckResult{
		Name:   fmt.Sprintf("token budget under %dk", defaultSkillTokenBudget/1000),
		Passed: v.ContextTokens < defaultSkillTokenBudget,
		Detail: fmt.Sprintf("%.1fk", float64(v.ContextTokens)/1000),
	})

	var destructive []string
	for _, name := range v.Tools {
		if tool, ok := live[name]; ok && !readOnlyTool(tool, bareToolName(name)) {
			destructive = append(destructive, name)
		}
	}
	run.Results = append(run.Results, SkillCheckResult{Name: "no destructive tools referenced", Passed: len(destructive) == 0, Detail: strings.Join(destructive, ", ")})

	return run
}

// ---- SkillStore: the persistence facet ------------------------------------
//
// Mirrors ConnectorStore/NamespaceStore: an optional AccountStore facet,
// discovered by type assertion in NewConsoleAPI. A store without this facet
// makes every skills endpoint answer 501, exactly like connectors/namespaces
// on a bare AccountStore-only implementation.
type SkillStore interface {
	SkillSources(ctx context.Context) ([]SkillSource, error)
	SkillSource(ctx context.Context, id string) (SkillSource, bool)
	CreateSkillSource(ctx context.Context, src SkillSource) (SkillSource, error)
	DeleteSkillSource(ctx context.Context, id string) error
	UpdateSkillSourceSync(ctx context.Context, id string, syncedAt time.Time, commit, syncErr string) error

	Skills(ctx context.Context) ([]Skill, error)
	Skill(ctx context.Context, id string) (Skill, bool)
	SkillsBySource(ctx context.Context, sourceID string) ([]Skill, error)
	// UpsertSkill creates the (sourceID, path) row if absent, or returns the
	// existing one unchanged otherwise (a skill's Name/Path never silently
	// rewrite once created — a path rename is modeled as delete+recreate).
	UpsertSkill(ctx context.Context, sk Skill) (Skill, error)
	// PruneSkills deletes every skill of sourceID whose ID is not in keepIDs —
	// used after a sync to drop skills whose file no longer exists in the repo.
	PruneSkills(ctx context.Context, sourceID string, keepIDs []string) error

	SkillVersions(ctx context.Context, skillID string) ([]SkillVersion, error)
	LatestSkillVersion(ctx context.Context, skillID string) (SkillVersion, bool)
	CreateSkillVersion(ctx context.Context, v SkillVersion) (SkillVersion, error)

	SkillCarriers(ctx context.Context, skillID string) ([]SkillCarrier, error)
	UpsertSkillCarrier(ctx context.Context, c SkillCarrier) (SkillCarrier, error)
	DeleteSkillCarrier(ctx context.Context, skillID, connectorSlug string) error

	SkillDriftFindings(ctx context.Context, skillID string) ([]SkillDriftFinding, error)
	ReplaceSkillDriftFindings(ctx context.Context, skillID string, findings []SkillDriftFinding) error

	SkillCheckRun(ctx context.Context, skillID string) (SkillCheckRun, bool)
	SaveSkillCheckRun(ctx context.Context, run SkillCheckRun) error
}

var (
	ErrSkillSourceNotFound = errors.New("skill source not found")
	ErrSkillNotFound       = errors.New("skill not found")
	ErrSkillCarrierExists  = errors.New("skill is already attached to that connector")
	ErrSkillVersionInvalid = errors.New("invalid skill version")
)

func newSkillSourceID() string  { return "sksrc_" + newEpoch() }
func newSkillID() string        { return "skl_" + newEpoch() }
func newSkillVersionID() string { return "sklv_" + newEpoch() }
func newSkillCarrierID() string { return "sklc_" + newEpoch() }

// skillVersionByNumber finds a specific version within an already-loaded list
// (avoids a dedicated store lookup method for what is always a small slice).
func skillVersionByNumber(versions []SkillVersion, n int) (SkillVersion, bool) {
	for _, v := range versions {
		if v.Version == n {
			return v, true
		}
	}
	return SkillVersion{}, false
}

// latestOf returns the highest-Version entry in versions.
func latestOf(versions []SkillVersion) (SkillVersion, bool) {
	var best SkillVersion
	found := false
	for _, v := range versions {
		if !found || v.Version > best.Version {
			best, found = v, true
		}
	}
	return best, found
}
