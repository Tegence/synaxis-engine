package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- PgStore: SkillStore ----------------------------------------------------
//
// Same idempotent-DDL "migration" style as every other PgStore facet (see
// connectorsSchema/namespacesSchema in store_pg.go): CREATE TABLE IF NOT
// EXISTS plus ALTER TABLE ... ADD COLUMN IF NOT EXISTS for anything added
// later. `commit` is a reserved SQL keyword, so the column is commit_sha.

const skillSourcesSchema = `
CREATE TABLE IF NOT EXISTS narthex_skill_sources (
    id               TEXT PRIMARY KEY,
    slug             TEXT NOT NULL UNIQUE,
    repo             TEXT NOT NULL DEFAULT '',
    url              TEXT NOT NULL,
    token            TEXT NOT NULL DEFAULT '',
    branch           TEXT NOT NULL DEFAULT 'main',
    path             TEXT NOT NULL DEFAULT 'skills',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at   TIMESTAMPTZ,
    last_sync_commit TEXT NOT NULL DEFAULT '',
    last_sync_error  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS narthex_skills (
    id         TEXT PRIMARY KEY,
    source_id  TEXT NOT NULL REFERENCES narthex_skill_sources(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, path)
);
CREATE INDEX IF NOT EXISTS narthex_skills_source_idx ON narthex_skills (source_id);

CREATE TABLE IF NOT EXISTS narthex_skill_versions (
    id             TEXT PRIMARY KEY,
    skill_id       TEXT NOT NULL REFERENCES narthex_skills(id) ON DELETE CASCADE,
    version        INT NOT NULL,
    commit_sha     TEXT NOT NULL DEFAULT '',
    author         TEXT NOT NULL DEFAULT '',
    digest         TEXT NOT NULL DEFAULT '',
    content        TEXT NOT NULL DEFAULT '',
    context_tokens INT NOT NULL DEFAULT 0,
    tools          JSONB NOT NULL DEFAULT '[]'::jsonb,
    tool_schemas   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (skill_id, version)
);
CREATE INDEX IF NOT EXISTS narthex_skill_versions_skill_idx ON narthex_skill_versions (skill_id, version DESC);

CREATE TABLE IF NOT EXISTS narthex_skill_carriers (
    id             TEXT PRIMARY KEY,
    skill_id       TEXT NOT NULL REFERENCES narthex_skills(id) ON DELETE CASCADE,
    connector_slug TEXT NOT NULL,
    mode           TEXT NOT NULL DEFAULT 'track',
    pinned_version INT NOT NULL DEFAULT 0,
    surfaces       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (skill_id, connector_slug),
    CONSTRAINT narthex_skill_carriers_mode_check CHECK (mode IN ('pin','track'))
);

CREATE TABLE IF NOT EXISTS narthex_skill_drift_findings (
    id          TEXT PRIMARY KEY,
    skill_id    TEXT NOT NULL REFERENCES narthex_skills(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    change      TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (skill_id, tool, change)
);
CREATE INDEX IF NOT EXISTS narthex_skill_drift_skill_idx ON narthex_skill_drift_findings (skill_id);

CREATE TABLE IF NOT EXISTS narthex_skill_check_runs (
    skill_id TEXT PRIMARY KEY REFERENCES narthex_skills(id) ON DELETE CASCADE,
    version  INT NOT NULL,
    ran_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    results  JSONB NOT NULL DEFAULT '[]'::jsonb
);`

var _ SkillStore = (*PgStore)(nil)

func (s *PgStore) SkillSources(ctx context.Context) ([]SkillSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,slug,repo,url,token,branch,path,created_at,updated_at,last_synced_at,last_sync_commit,last_sync_error FROM narthex_skill_sources ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillSource
	for rows.Next() {
		src, err := s.scanSkillSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

type skillSourceScanner interface {
	Scan(dest ...any) error
}

func (s *PgStore) scanSkillSource(row skillSourceScanner) (SkillSource, error) {
	var src SkillSource
	var lastSyncedAt *time.Time
	var tokenCipher string
	if err := row.Scan(&src.ID, &src.Slug, &src.Repo, &src.URL, &tokenCipher, &src.Branch, &src.Path,
		&src.CreatedAt, &src.UpdatedAt, &lastSyncedAt, &src.LastSyncCommit, &src.LastSyncError); err != nil {
		return SkillSource{}, err
	}
	token, err := s.dec(tokenCipher)
	if err != nil {
		return SkillSource{}, fmt.Errorf("decrypt skill source %q token: %w", src.ID, err)
	}
	src.Token = token
	if lastSyncedAt != nil {
		src.LastSyncedAt = *lastSyncedAt
	}
	return src, nil
}

func (s *PgStore) SkillSource(ctx context.Context, id string) (SkillSource, bool) {
	row := s.pool.QueryRow(ctx, `SELECT id,slug,repo,url,token,branch,path,created_at,updated_at,last_synced_at,last_sync_commit,last_sync_error FROM narthex_skill_sources WHERE id=$1`, id)
	src, err := s.scanSkillSource(row)
	if err != nil {
		return SkillSource{}, false
	}
	return src, true
}

func (s *PgStore) CreateSkillSource(ctx context.Context, src SkillSource) (SkillSource, error) {
	if src.ID == "" {
		src.ID = newSkillSourceID()
	}
	tokenCipher, err := s.enc(src.Token)
	if err != nil {
		return SkillSource{}, fmt.Errorf("encrypt skill source token: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO narthex_skill_sources (id,slug,repo,url,token,branch,path)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		src.ID, src.Slug, src.Repo, src.URL, tokenCipher, src.Branch, src.Path)
	if err != nil {
		return SkillSource{}, err
	}
	created, ok := s.SkillSource(ctx, src.ID)
	if !ok {
		return SkillSource{}, fmt.Errorf("skill source %q disappeared after create", src.ID)
	}
	return created, nil
}

func (s *PgStore) DeleteSkillSource(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM narthex_skill_sources WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSkillSourceNotFound
	}
	return nil
}

func (s *PgStore) UpdateSkillSourceSync(ctx context.Context, id string, syncedAt time.Time, commit, syncErr string) error {
	tag, err := s.pool.Exec(ctx, `
UPDATE narthex_skill_sources SET last_synced_at=$2, last_sync_commit=$3, last_sync_error=$4, updated_at=$2
WHERE id=$1`, id, syncedAt, commit, syncErr)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSkillSourceNotFound
	}
	return nil
}

func scanSkill(row skillSourceScanner) (Skill, error) {
	var sk Skill
	err := row.Scan(&sk.ID, &sk.SourceID, &sk.Name, &sk.Path, &sk.CreatedAt, &sk.UpdatedAt)
	return sk, err
}

const skillCols = `id,source_id,name,path,created_at,updated_at`

func (s *PgStore) Skills(ctx context.Context) ([]Skill, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+skillCols+` FROM narthex_skills ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Skill
	for rows.Next() {
		sk, err := scanSkill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sk)
	}
	return out, rows.Err()
}

func (s *PgStore) Skill(ctx context.Context, id string) (Skill, bool) {
	sk, err := scanSkill(s.pool.QueryRow(ctx, `SELECT `+skillCols+` FROM narthex_skills WHERE id=$1`, id))
	if err != nil {
		return Skill{}, false
	}
	return sk, true
}

func (s *PgStore) SkillsBySource(ctx context.Context, sourceID string) ([]Skill, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+skillCols+` FROM narthex_skills WHERE source_id=$1 ORDER BY path`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Skill
	for rows.Next() {
		sk, err := scanSkill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sk)
	}
	return out, rows.Err()
}

func (s *PgStore) UpsertSkill(ctx context.Context, sk Skill) (Skill, error) {
	if existing, err := scanSkill(s.pool.QueryRow(ctx, `SELECT `+skillCols+` FROM narthex_skills WHERE source_id=$1 AND path=$2`, sk.SourceID, sk.Path)); err == nil {
		return existing, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Skill{}, err
	}
	if sk.ID == "" {
		sk.ID = newSkillID()
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO narthex_skills (id,source_id,name,path) VALUES ($1,$2,$3,$4)
ON CONFLICT (source_id, path) DO NOTHING`, sk.ID, sk.SourceID, sk.Name, sk.Path); err != nil {
		return Skill{}, err
	}
	created, err := scanSkill(s.pool.QueryRow(ctx, `SELECT `+skillCols+` FROM narthex_skills WHERE source_id=$1 AND path=$2`, sk.SourceID, sk.Path))
	if err != nil {
		return Skill{}, err
	}
	return created, nil
}

func (s *PgStore) PruneSkills(ctx context.Context, sourceID string, keepIDs []string) error {
	if len(keepIDs) == 0 {
		_, err := s.pool.Exec(ctx, `DELETE FROM narthex_skills WHERE source_id=$1`, sourceID)
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM narthex_skills WHERE source_id=$1 AND NOT (id = ANY($2))`, sourceID, keepIDs)
	return err
}

func scanSkillVersion(row skillSourceScanner) (SkillVersion, error) {
	var v SkillVersion
	var tools, schemas []byte
	if err := row.Scan(&v.ID, &v.SkillID, &v.Version, &v.Commit, &v.Author, &v.Digest, &v.Content, &v.ContextTokens, &tools, &schemas, &v.CreatedAt); err != nil {
		return SkillVersion{}, err
	}
	if err := json.Unmarshal(tools, &v.Tools); err != nil {
		return SkillVersion{}, fmt.Errorf("skill version %q tools: %w", v.ID, err)
	}
	if err := json.Unmarshal(schemas, &v.ToolSchemas); err != nil {
		return SkillVersion{}, fmt.Errorf("skill version %q tool schemas: %w", v.ID, err)
	}
	return v, nil
}

const skillVersionCols = `id,skill_id,version,commit_sha,author,digest,content,context_tokens,tools,tool_schemas,created_at`

func (s *PgStore) SkillVersions(ctx context.Context, skillID string) ([]SkillVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+skillVersionCols+` FROM narthex_skill_versions WHERE skill_id=$1 ORDER BY version`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillVersion
	for rows.Next() {
		v, err := scanSkillVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PgStore) LatestSkillVersion(ctx context.Context, skillID string) (SkillVersion, bool) {
	v, err := scanSkillVersion(s.pool.QueryRow(ctx, `SELECT `+skillVersionCols+` FROM narthex_skill_versions WHERE skill_id=$1 ORDER BY version DESC LIMIT 1`, skillID))
	if err != nil {
		return SkillVersion{}, false
	}
	return v, true
}

func (s *PgStore) CreateSkillVersion(ctx context.Context, v SkillVersion) (SkillVersion, error) {
	if v.ID == "" {
		v.ID = newSkillVersionID()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	tools, err := json.Marshal(orEmptySlice(v.Tools))
	if err != nil {
		return SkillVersion{}, err
	}
	schemas, err := json.Marshal(orEmptySchemaMap(v.ToolSchemas))
	if err != nil {
		return SkillVersion{}, err
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO narthex_skill_versions (id,skill_id,version,commit_sha,author,digest,content,context_tokens,tools,tool_schemas,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		v.ID, v.SkillID, v.Version, v.Commit, v.Author, v.Digest, v.Content, v.ContextTokens, tools, schemas, v.CreatedAt); err != nil {
		return SkillVersion{}, err
	}
	return v, nil
}

func orEmptySchemaMap(m map[string]skillToolSchema) map[string]skillToolSchema {
	if m == nil {
		return map[string]skillToolSchema{}
	}
	return m
}

func scanSkillCarrier(row skillSourceScanner) (SkillCarrier, error) {
	var c SkillCarrier
	var surfaces []byte
	if err := row.Scan(&c.ID, &c.SkillID, &c.ConnectorSlug, &c.Mode, &c.PinnedVersion, &surfaces, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return SkillCarrier{}, err
	}
	if err := json.Unmarshal(surfaces, &c.Surfaces); err != nil {
		return SkillCarrier{}, fmt.Errorf("skill carrier %q surfaces: %w", c.ID, err)
	}
	return c, nil
}

const skillCarrierCols = `id,skill_id,connector_slug,mode,pinned_version,surfaces,created_at,updated_at`

func (s *PgStore) SkillCarriers(ctx context.Context, skillID string) ([]SkillCarrier, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+skillCarrierCols+` FROM narthex_skill_carriers WHERE skill_id=$1 ORDER BY created_at`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillCarrier
	for rows.Next() {
		c, err := scanSkillCarrier(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PgStore) UpsertSkillCarrier(ctx context.Context, c SkillCarrier) (SkillCarrier, error) {
	if c.ID == "" {
		c.ID = newSkillCarrierID()
	}
	surfaces, err := json.Marshal(orEmptySlice(c.Surfaces))
	if err != nil {
		return SkillCarrier{}, err
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO narthex_skill_carriers (id,skill_id,connector_slug,mode,pinned_version,surfaces)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (skill_id, connector_slug) DO UPDATE SET
    mode=$4, pinned_version=$5, surfaces=$6, updated_at=now()`,
		c.ID, c.SkillID, c.ConnectorSlug, c.Mode, c.PinnedVersion, surfaces); err != nil {
		return SkillCarrier{}, err
	}
	updated, err := scanSkillCarrier(s.pool.QueryRow(ctx, `SELECT `+skillCarrierCols+` FROM narthex_skill_carriers WHERE skill_id=$1 AND connector_slug=$2`, c.SkillID, c.ConnectorSlug))
	if err != nil {
		return SkillCarrier{}, err
	}
	return updated, nil
}

func (s *PgStore) DeleteSkillCarrier(ctx context.Context, skillID, connectorSlug string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM narthex_skill_carriers WHERE skill_id=$1 AND connector_slug=$2`, skillID, connectorSlug)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSkillNotFound
	}
	return nil
}

func (s *PgStore) SkillDriftFindings(ctx context.Context, skillID string) ([]SkillDriftFinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,skill_id,tool,change,detected_at FROM narthex_skill_drift_findings WHERE skill_id=$1 ORDER BY detected_at`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkillDriftFinding
	for rows.Next() {
		var f SkillDriftFinding
		if err := rows.Scan(&f.ID, &f.SkillID, &f.Tool, &f.Change, &f.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ReplaceSkillDriftFindings overwrites the full finding set for one skill in
// a transaction: simplest correct semantics for a small per-skill set (a
// handful of findings), matching the size/shape of the "3 drift rows" the
// design shows. reconcileDriftFindings (skills.go) already preserved the
// right IDs/DetectedAt before this is called — this just makes the durable
// set match exactly what the caller computed.
func (s *PgStore) ReplaceSkillDriftFindings(ctx context.Context, skillID string, findings []SkillDriftFinding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_skill_drift_findings WHERE skill_id=$1`, skillID); err != nil {
		return err
	}
	for _, f := range findings {
		if f.ID == "" {
			f.ID = "drift_" + newEpoch()
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_skill_drift_findings (id,skill_id,tool,change,detected_at) VALUES ($1,$2,$3,$4,$5)`,
			f.ID, skillID, f.Tool, f.Change, f.DetectedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PgStore) SkillCheckRun(ctx context.Context, skillID string) (SkillCheckRun, bool) {
	var run SkillCheckRun
	var results []byte
	run.SkillID = skillID
	err := s.pool.QueryRow(ctx, `SELECT version,ran_at,results FROM narthex_skill_check_runs WHERE skill_id=$1`, skillID).
		Scan(&run.Version, &run.RanAt, &results)
	if err != nil {
		return SkillCheckRun{}, false
	}
	if err := json.Unmarshal(results, &run.Results); err != nil {
		return SkillCheckRun{}, false
	}
	return run, true
}

func (s *PgStore) SaveSkillCheckRun(ctx context.Context, run SkillCheckRun) error {
	results, err := json.Marshal(run.Results)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO narthex_skill_check_runs (skill_id,version,ran_at,results) VALUES ($1,$2,$3,$4)
ON CONFLICT (skill_id) DO UPDATE SET version=$2, ran_at=$3, results=$4`,
		run.SkillID, run.Version, run.RanAt, results)
	return err
}
