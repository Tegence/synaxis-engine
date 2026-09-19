package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Skills console handlers. Auth mirrors handleConnectors/handleNamespaces
// exactly: skills are global engine configuration (not scoped to one
// connection namespace), so every route — reads included — requires
// c.requireConnectionNamespaceAdministrator, the same boundary virtual
// connectors already use. See skills.go for the domain model/store and
// skills_sync.go for the git-sync orchestration these handlers call into.
// ---------------------------------------------------------------------------

func (c *ConsoleAPI) skillsSupported(w http.ResponseWriter) bool {
	if c.skillStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "skills not supported by this store"})
		return false
	}
	return true
}

// ---- DTOs -------------------------------------------------------------

type skillSourceDTO struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	Repo           string `json:"repo"`
	URL            string `json:"url"`
	Branch         string `json:"branch"`
	Path           string `json:"path"`
	HasToken       bool   `json:"hasToken"`
	SkillCount     int    `json:"skillCount"`
	CreatedAt      string `json:"createdAt,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	LastSyncedAt   string `json:"lastSyncedAt,omitempty"`
	LastSyncCommit string `json:"lastSyncCommit,omitempty"`
	LastSyncError  string `json:"lastSyncError,omitempty"`
}

func (c *ConsoleAPI) skillSourceDTO(src SkillSource, skillCount int) skillSourceDTO {
	dto := skillSourceDTO{
		ID: src.ID, Slug: src.Slug, Repo: src.Repo, URL: src.URL, Branch: src.Branch, Path: src.Path,
		HasToken: src.Token != "", SkillCount: skillCount,
		LastSyncCommit: src.LastSyncCommit, LastSyncError: src.LastSyncError,
	}
	if !src.CreatedAt.IsZero() {
		dto.CreatedAt = src.CreatedAt.Format(time.RFC3339Nano)
	}
	if !src.UpdatedAt.IsZero() {
		dto.UpdatedAt = src.UpdatedAt.Format(time.RFC3339Nano)
	}
	if !src.LastSyncedAt.IsZero() {
		dto.LastSyncedAt = src.LastSyncedAt.Format(time.RFC3339Nano)
	}
	return dto
}

// skillDTO is the 7-column list-row shape.
type skillDTO struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	SourceID       string   `json:"sourceId"`
	SourceRepo     string   `json:"sourceRepo"`
	SourceBranch   string   `json:"sourceBranch"`
	Version        int      `json:"version"` // the version this row displays (latest, or the most-behind pin — see mostBehindPinnedVersion)
	Commit         string   `json:"commit"`
	LatestVersion  int      `json:"latestVersion"`
	State          string   `json:"state"` // SkillState: current | drifted | behind
	ContextTokens  int      `json:"contextTokens"`
	ConnectorCount int      `json:"connectorCount"`
	Surfaces       []string `json:"surfaces"`
	DriftCount     int      `json:"driftCount"`
	SyncedAt       string   `json:"syncedAt,omitempty"`
}

type skillVersionDTO struct {
	Version       int      `json:"version"`
	Commit        string   `json:"commit"`
	Author        string   `json:"author"`
	ContextTokens int      `json:"contextTokens"`
	Tools         []string `json:"tools"`
	CreatedAt     string   `json:"createdAt"`
}

func toSkillVersionDTO(v SkillVersion) skillVersionDTO {
	tools := v.Tools
	if tools == nil {
		tools = []string{}
	}
	return skillVersionDTO{
		Version: v.Version, Commit: v.Commit, Author: v.Author, ContextTokens: v.ContextTokens,
		Tools: tools, CreatedAt: v.CreatedAt.Format(time.RFC3339Nano),
	}
}

type skillCarrierDTO struct {
	ConnectorSlug  string   `json:"connectorSlug"`
	ConnectorLabel string   `json:"connectorLabel,omitempty"`
	Mode           string   `json:"mode"`
	PinnedVersion  int      `json:"pinnedVersion,omitempty"`
	Surfaces       []string `json:"surfaces"`
	ToolCount      int      `json:"toolCount"`     // "Bounded by the connector: N tools"
	ApprovalCount  int      `json:"approvalCount"` // "...N ask-first"
}

type skillCheckRunDTO struct {
	Version int                `json:"version"`
	RanAt   string             `json:"ranAt"`
	Passed  int                `json:"passed"`
	Failed  int                `json:"failed"`
	Results []SkillCheckResult `json:"results"`
}

func toSkillCheckRunDTO(run SkillCheckRun) skillCheckRunDTO {
	return skillCheckRunDTO{Version: run.Version, RanAt: run.RanAt.Format(time.RFC3339Nano), Passed: run.Passed(), Failed: run.Failed(), Results: run.Results}
}

type skillDetailDTO struct {
	skillDTO
	Versions []skillVersionDTO   `json:"versions"`
	Drift    []SkillDriftFinding `json:"drift"`
	Checks   *skillCheckRunDTO   `json:"checks,omitempty"`
	Carriers []skillCarrierDTO   `json:"carriers"`
}

// unionSurfaces collects every distinct surface label across a skill's
// carriers, sorted for stable output.
func unionSurfaces(carriers []SkillCarrier) []string {
	set := map[string]struct{}{}
	for _, cr := range carriers {
		for _, s := range cr.Surfaces {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// buildSkillRollup loads every piece of data one skill's DTOs need (versions,
// carriers, drift) exactly once, so both the list and detail handlers share
// one code path instead of drifting apart.
type skillRollup struct {
	skill    Skill
	source   SkillSource
	versions []SkillVersion
	latest   SkillVersion
	carriers []SkillCarrier
	drift    []SkillDriftFinding
	state    SkillState
}

func (c *ConsoleAPI) loadSkillRollup(r *http.Request, sk Skill) (skillRollup, error) {
	ctx := r.Context()
	versions, err := c.skillStore.SkillVersions(ctx, sk.ID)
	if err != nil {
		return skillRollup{}, err
	}
	carriers, err := c.skillStore.SkillCarriers(ctx, sk.ID)
	if err != nil {
		return skillRollup{}, err
	}
	drift, err := c.skillStore.SkillDriftFindings(ctx, sk.ID)
	if err != nil {
		return skillRollup{}, err
	}
	latest, _ := latestOf(versions)
	source, _ := c.skillStore.SkillSource(ctx, sk.SourceID)
	return skillRollup{
		skill: sk, source: source, versions: versions, latest: latest, carriers: carriers, drift: drift,
		state: classifySkillState(latest.Version, carriers, len(drift)),
	}, nil
}

func (roll skillRollup) toDTO() skillDTO {
	version, commit := roll.latest.Version, roll.latest.Commit
	if roll.state == SkillStateBehind {
		if v, found := mostBehindPinnedVersion(roll.latest.Version, roll.carriers); found {
			version = v
			if vv, ok := skillVersionByNumber(roll.versions, v); ok {
				commit = vv.Commit
			}
		}
	}
	dto := skillDTO{
		ID: roll.skill.ID, Name: roll.skill.Name, Path: roll.skill.Path,
		SourceID: roll.skill.SourceID, SourceRepo: roll.source.Repo, SourceBranch: roll.source.Branch,
		Version: version, Commit: commit, LatestVersion: roll.latest.Version,
		State: string(roll.state), ContextTokens: roll.latest.ContextTokens,
		ConnectorCount: len(roll.carriers), Surfaces: unionSurfaces(roll.carriers), DriftCount: len(roll.drift),
	}
	if !roll.latest.CreatedAt.IsZero() {
		dto.SyncedAt = roll.latest.CreatedAt.Format(time.RFC3339Nano)
	}
	return dto
}

func (c *ConsoleAPI) toSkillCarrierDTOs(ctx context.Context, carriers []SkillCarrier) []skillCarrierDTO {
	out := make([]skillCarrierDTO, len(carriers))
	for i, cr := range carriers {
		dto := skillCarrierDTO{ConnectorSlug: cr.ConnectorSlug, Mode: cr.Mode, PinnedVersion: cr.PinnedVersion, Surfaces: cr.Surfaces}
		if dto.Surfaces == nil {
			dto.Surfaces = []string{}
		}
		if c.connStore != nil {
			if vc, ok := c.connStore.VirtualConnector(ctx, cr.ConnectorSlug); ok {
				dto.ConnectorLabel = vc.Label
				dto.ToolCount = sumToolMapLen(vc.Tools)
				dto.ApprovalCount = sumToolMapLen(vc.Approval)
			}
		}
		out[i] = dto
	}
	return out
}

func sumToolMapLen(m map[string][]string) int {
	n := 0
	for _, tools := range m {
		n += len(tools)
	}
	return n
}

// ---- skill sources ------------------------------------------------------

func (c *ConsoleAPI) handleSkillSources(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		sources, err := c.skillStore.SkillSources(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		out := make([]skillSourceDTO, len(sources))
		for i, src := range sources {
			skills, _ := c.skillStore.SkillsBySource(r.Context(), src.ID)
			out[i] = c.skillSourceDTO(src, len(skills))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		c.handleCreateSkillSource(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleCreateSkillSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Slug   string `json:"slug"`
		Repo   string `json:"repo"`
		URL    string `json:"url"`
		Token  string `json:"token"`
		Branch string `json:"branch"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	url := strings.TrimSpace(req.URL)
	if url == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	repo := strings.TrimSpace(req.Repo)
	if repo == "" {
		repo = deriveRepoLabel(url)
	}
	branch := strings.TrimSpace(req.Branch)
	if branch == "" {
		branch = "main"
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "skills"
	}
	slug := slugify(req.Slug)
	if slug == "" {
		slug = slugify(repo)
	}
	if slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug must contain letters or numbers"})
		return
	}
	src, err := c.skillStore.CreateSkillSource(r.Context(), SkillSource{
		Slug: slug, Repo: repo, URL: url, Token: req.Token, Branch: branch, Path: path,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	// Best-effort initial sync: the source row persists even if the first
	// sync fails (e.g. bad credentials, unreachable host) — same tolerance
	// the rest of the engine gives a newly connected account. The operator
	// sees the failure via LastSyncError on the returned DTO and can retry
	// with POST .../sync once the source is reachable.
	if synced, syncErr := syncSkillSource(r.Context(), c.skillStore, c.gw, c.skillFetcher, src); syncErr == nil {
		src = synced
	} else {
		src.LastSyncError = syncErr.Error()
	}
	skills, _ := c.skillStore.SkillsBySource(r.Context(), src.ID)
	writeJSON(w, http.StatusCreated, c.skillSourceDTO(src, len(skills)))
}

// deriveRepoLabel turns a clone URL into a short "org/repo" display label,
// e.g. "https://github.com/tegence/skills.git" -> "tegence/skills".
func deriveRepoLabel(gitURL string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(gitURL), ".git")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}
	if idx := strings.Index(trimmed, "@"); idx != -1 && strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "/") {
		trimmed = trimmed[idx+1:] // scp-like ssh form: git@host:org/repo
		trimmed = strings.Replace(trimmed, ":", "/", 1)
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return trimmed
}

func (c *ConsoleAPI) handleSkillSourceByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	id := r.PathValue("id")
	src, ok := c.skillStore.SkillSource(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill source not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		skills, _ := c.skillStore.SkillsBySource(r.Context(), src.ID)
		writeJSON(w, http.StatusOK, c.skillSourceDTO(src, len(skills)))
	case http.MethodDelete:
		if err := c.skillStore.DeleteSkillSource(r.Context(), id); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleSkillSourceSync(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	src, ok := c.skillStore.SkillSource(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill source not found"})
		return
	}
	synced, err := syncSkillSource(r.Context(), c.skillStore, c.gw, c.skillFetcher, src)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "sync failed: " + err.Error()})
		return
	}
	skills, _ := c.skillStore.SkillsBySource(r.Context(), synced.ID)
	writeJSON(w, http.StatusOK, c.skillSourceDTO(synced, len(skills)))
}

// ---- skills ---------------------------------------------------------------

func (c *ConsoleAPI) handleSkills(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	skills, err := c.skillStore.Skills(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	// "Drift · N" tab / ?state= filter (implied interaction from the list
	// screen's tab pair — see docs/design-upgrades/08-skills.md).
	stateFilter := SkillState(strings.TrimSpace(r.URL.Query().Get("state")))
	out := make([]skillDTO, 0, len(skills))
	for _, sk := range skills {
		roll, err := c.loadSkillRollup(r, sk)
		if err != nil {
			continue
		}
		if stateFilter != "" && roll.state != stateFilter {
			continue
		}
		out = append(out, roll.toDTO())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (c *ConsoleAPI) handleSkillByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sk, ok := c.skillStore.Skill(r.Context(), r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
		return
	}
	roll, err := c.loadSkillRollup(r, sk)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	versions := make([]skillVersionDTO, len(roll.versions))
	for i, v := range roll.versions {
		versions[i] = toSkillVersionDTO(v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })
	drift := roll.drift
	if drift == nil {
		drift = []SkillDriftFinding{}
	}
	detail := skillDetailDTO{
		skillDTO: roll.toDTO(), Versions: versions, Drift: drift, Carriers: c.toSkillCarrierDTOs(r.Context(), roll.carriers),
	}
	if run, ok := c.skillStore.SkillCheckRun(r.Context(), sk.ID); ok {
		dto := toSkillCheckRunDTO(run)
		detail.Checks = &dto
	}
	writeJSON(w, http.StatusOK, detail)
}

func (c *ConsoleAPI) handleSkillVersions(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if _, ok := c.skillStore.Skill(r.Context(), id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
		return
	}
	versions, err := c.skillStore.SkillVersions(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	out := make([]skillVersionDTO, len(versions))
	for i, v := range versions {
		out[i] = toSkillVersionDTO(v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	writeJSON(w, http.StatusOK, out)
}

// handleSkillChecks runs the checks runner (see runSkillChecks, skills.go)
// against the skill's latest version and the live tool set, persists the
// result as the skill's latest run, and — since the design gives no separate
// frame/flow for "Review drift" (report line ~236) — also refreshes the
// skill's drift findings so both cards on the detail screen advance together
// from the single "+ Run checks" action.
func (c *ConsoleAPI) handleSkillChecks(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if _, ok := c.skillStore.Skill(r.Context(), id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
		return
	}
	latest, ok := c.skillStore.LatestSkillVersion(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "skill has no synced version yet"})
		return
	}
	live := c.gw.skillLiveTools()
	run := runSkillChecks(latest, live)
	if err := c.skillStore.SaveSkillCheckRun(r.Context(), run); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if err := refreshSkillDrift(r.Context(), c.skillStore, live, id, time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, toSkillCheckRunDTO(run))
}

// ---- pin / track ------------------------------------------------------

func (c *ConsoleAPI) handleSkillPins(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	id := r.PathValue("id")
	sk, ok := c.skillStore.Skill(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		carriers, err := c.skillStore.SkillCarriers(r.Context(), sk.ID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, c.toSkillCarrierDTOs(r.Context(), carriers))
	case http.MethodPost:
		c.handleUpsertSkillPin(w, r, sk)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *ConsoleAPI) handleUpsertSkillPin(w http.ResponseWriter, r *http.Request, sk Skill) {
	var req struct {
		ConnectorSlug string   `json:"connectorSlug"`
		Mode          string   `json:"mode"`
		Version       int      `json:"version"`
		Surfaces      []string `json:"surfaces"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	slug := strings.TrimSpace(req.ConnectorSlug)
	if slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connectorSlug is required"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != SkillCarrierModePin && mode != SkillCarrierModeTrack {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be \"pin\" or \"track\""})
		return
	}
	if c.connStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "connectors not supported by this store"})
		return
	}
	if _, ok := c.connStore.VirtualConnector(r.Context(), slug); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown connector " + strconv.Quote(slug)})
		return
	}
	pinnedVersion := 0
	if mode == SkillCarrierModePin {
		if req.Version < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version is required when mode is \"pin\""})
			return
		}
		if _, ok := c.skillStore.LatestSkillVersion(r.Context(), sk.ID); !ok {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "skill has no synced version yet"})
			return
		}
		versions, err := c.skillStore.SkillVersions(r.Context(), sk.ID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if _, ok := skillVersionByNumber(versions, req.Version); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown skill version"})
			return
		}
		pinnedVersion = req.Version
	}
	existing, _ := c.skillStore.SkillCarriers(r.Context(), sk.ID)
	status := http.StatusCreated
	for _, e := range existing {
		if e.ConnectorSlug == slug {
			status = http.StatusOK
			break
		}
	}
	carrier, err := c.skillStore.UpsertSkillCarrier(r.Context(), SkillCarrier{
		SkillID: sk.ID, ConnectorSlug: slug, Mode: mode, PinnedVersion: pinnedVersion, Surfaces: req.Surfaces,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	dtos := c.toSkillCarrierDTOs(r.Context(), []SkillCarrier{carrier})
	writeJSON(w, status, dtos[0])
}

func (c *ConsoleAPI) handleSkillPinBySlug(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if !c.skillsSupported(w) {
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, slug := r.PathValue("id"), r.PathValue("slug")
	if _, ok := c.skillStore.Skill(r.Context(), id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill not found"})
		return
	}
	if err := c.skillStore.DeleteSkillCarrier(r.Context(), id, slug); err != nil {
		if errors.Is(err, ErrSkillNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "skill is not attached to that connector"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
