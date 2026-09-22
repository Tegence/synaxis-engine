package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ LibraryStore = (*PgStore)(nil)
var _ LibraryRuntimeAttestationStore = (*PgStore)(nil)

type libraryRowScanner interface{ Scan(...any) error }

const librarySkillColumns = `id,slug,name,description,created_by,created_at,updated_at`
const librarySkillVersionColumns = `id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at,changelog,origin,generator,model,prompt_digest,draft_id,manifest,manifest_digest`
const libraryDraftColumns = `id,name,description,content,requested_capabilities,origin,generator,model,prompt_digest,created_by,created_at,rationale,assumptions`
const libraryArtifactDraftColumns = `id,title,summary,content,format,rationale,assumptions,origin,generator,model,prompt_digest,source_artifact_id,source_artifact_version_id,source_artifact_digest,created_by,created_at`
const libraryBindingColumns = `id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at`
const libraryEvaluationColumns = `id,skill_id,skill_version_id,evaluator,score,passed,summary,evidence_digest,created_by,created_at`
const libraryRunColumns = `id,origin,attestation,skill_id,skill_version_id,binding_id,actor_ref,surface_ref,effective_capabilities,status,input_digest,output_digest,source_artifact_id,source_artifact_version_id,source_artifact_digest,started_at,completed_at`
const libraryArtifactColumns = `id,title,summary,origin,run_id,skill_id,skill_version_id,binding_id,agent_surface_id,source_artifact_id,source_artifact_version_id,source_artifact_digest,created_by,created_at`
const libraryArtifactVersionColumns = `id,artifact_id,version_number,format,body,digest,size_bytes,redaction_status,created_by,reviewed_by,reviewed_at,publication_claimed_at,created_at,changelog,origin,generator,model,prompt_digest,draft_id,review_comment`
const libraryArtifactGrantColumns = `id,artifact_id,artifact_version_id,artifact_version_digest,agent_surface_id,created_by,created_at,revoked_by,revoked_at`

func libraryJSONCapabilities(values []string) ([]byte, error) {
	if values == nil {
		values = []string{}
	}
	return json.Marshal(values)
}

// decryptLibraryText keeps decryption errors safe to return from a store
// boundary: record IDs and field names are operational metadata, while the
// encrypted value itself is never included in an error.
func (s *PgStore) decryptLibraryText(kind, id, field, value string) (string, error) {
	plain, err := s.dec(value)
	if err != nil {
		return "", fmt.Errorf("decrypt library %s %q %s: %w", kind, id, field, err)
	}
	return plain, nil
}

func (s *PgStore) scanLibrarySkill(row libraryRowScanner) (LibrarySkill, error) {
	var skill LibrarySkill
	var name, description, createdBy string
	if err := row.Scan(&skill.ID, &skill.Slug, &name, &description, &createdBy, &skill.CreatedAt, &skill.UpdatedAt); err != nil {
		return LibrarySkill{}, err
	}
	var err error
	if skill.Name, err = s.decryptLibraryText("skill", skill.ID, "name", name); err != nil {
		return LibrarySkill{}, err
	}
	if skill.Description, err = s.decryptLibraryText("skill", skill.ID, "description", description); err != nil {
		return LibrarySkill{}, err
	}
	if skill.CreatedBy, err = s.decryptLibraryText("skill", skill.ID, "created by", createdBy); err != nil {
		return LibrarySkill{}, err
	}
	return skill, nil
}

// libraryVersionProvenanceStorage is the encrypted column set shared by skill
// and artifact versions. Origin, prompt digest, and draft ID are structural
// metadata; the changelog and generator/model labels are private text.
type libraryVersionProvenanceStorage struct {
	changelog, origin, generator, model, promptDigest, draftID string
}

func (s *PgStore) encryptLibraryVersionProvenance(changelog string, provenance *LibraryVersionProvenance) (libraryVersionProvenanceStorage, error) {
	var out libraryVersionProvenanceStorage
	var err error
	if out.changelog, err = s.enc(changelog); err != nil {
		return libraryVersionProvenanceStorage{}, fmt.Errorf("encrypt library version changelog: %w", err)
	}
	if provenance == nil {
		return out, nil
	}
	out.origin, out.promptDigest, out.draftID = provenance.Origin, provenance.PromptDigest, provenance.DraftID
	if out.generator, err = s.enc(provenance.Generator); err != nil {
		return libraryVersionProvenanceStorage{}, fmt.Errorf("encrypt library version generator: %w", err)
	}
	if out.model, err = s.enc(provenance.Model); err != nil {
		return libraryVersionProvenanceStorage{}, fmt.Errorf("encrypt library version model: %w", err)
	}
	return out, nil
}

// decryptLibraryVersionProvenance returns nil provenance for rows written
// before an origin was recorded, so legacy versions keep their shape.
func (s *PgStore) decryptLibraryVersionProvenance(kind, id string, stored libraryVersionProvenanceStorage) (string, *LibraryVersionProvenance, error) {
	changelog, err := s.decryptLibraryText(kind, id, "changelog", stored.changelog)
	if err != nil {
		return "", nil, err
	}
	if stored.origin == "" {
		return changelog, nil, nil
	}
	provenance := &LibraryVersionProvenance{Origin: stored.origin, PromptDigest: stored.promptDigest, DraftID: stored.draftID}
	if provenance.Generator, err = s.decryptLibraryText(kind, id, "generator", stored.generator); err != nil {
		return "", nil, err
	}
	if provenance.Model, err = s.decryptLibraryText(kind, id, "model", stored.model); err != nil {
		return "", nil, err
	}
	return changelog, provenance, nil
}

// libraryJSONAssumptions encodes a draft's assumptions before encryption.
// The list is private authored text, so it is stored as ciphertext rather
// than as queryable JSONB.
func libraryJSONAssumptions(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (s *PgStore) encryptLibraryAssumptions(values []string) (string, error) {
	encoded, err := libraryJSONAssumptions(values)
	if err != nil {
		return "", err
	}
	stored, err := s.enc(encoded)
	if err != nil {
		return "", fmt.Errorf("encrypt library draft assumptions: %w", err)
	}
	return stored, nil
}

func (s *PgStore) decryptLibraryAssumptions(kind, id, stored string) ([]string, error) {
	plain, err := s.decryptLibraryText(kind, id, "assumptions", stored)
	if err != nil {
		return nil, err
	}
	if plain == "" {
		return []string{}, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(plain), &values); err != nil {
		return nil, fmt.Errorf("decode library %s %q assumptions: %w", kind, id, err)
	}
	if values == nil {
		values = []string{}
	}
	return values, nil
}

func (s *PgStore) scanLibrarySkillVersion(row libraryRowScanner) (LibrarySkillVersion, error) {
	var version LibrarySkillVersion
	var content, createdBy, manifest string
	var capabilities []byte
	var stored libraryVersionProvenanceStorage
	if err := row.Scan(&version.ID, &version.SkillID, &version.Version, &content, &version.Digest, &capabilities, &createdBy, &version.CreatedAt,
		&stored.changelog, &stored.origin, &stored.generator, &stored.model, &stored.promptDigest, &stored.draftID, &manifest, &version.ManifestDigest); err != nil {
		return LibrarySkillVersion{}, err
	}
	plain, err := s.dec(content)
	if err != nil {
		return LibrarySkillVersion{}, fmt.Errorf("decrypt library skill version %q: %w", version.ID, err)
	}
	version.Content = plain
	if version.CreatedBy, err = s.decryptLibraryText("skill version", version.ID, "created by", createdBy); err != nil {
		return LibrarySkillVersion{}, err
	}
	if version.Changelog, version.Provenance, err = s.decryptLibraryVersionProvenance("skill version", version.ID, stored); err != nil {
		return LibrarySkillVersion{}, err
	}
	if err := json.Unmarshal(capabilities, &version.RequestedCapabilities); err != nil {
		return LibrarySkillVersion{}, fmt.Errorf("decode library skill version %q capabilities: %w", version.ID, err)
	}
	if version.Files, err = s.decryptLibrarySkillManifest(version.ID, manifest); err != nil {
		return LibrarySkillVersion{}, err
	}
	// A row written before bundles (or by a reduced-column insert) carries no
	// manifest; it is exactly the one-file manifest and is derived here.
	if version, err = librarySkillVersionWithManifest(version); err != nil {
		return LibrarySkillVersion{}, fmt.Errorf("library skill version %q manifest: %w", version.ID, err)
	}
	return version, nil
}

func (s *PgStore) scanLibraryArtifactDraft(row libraryRowScanner) (LibraryArtifactDraft, error) {
	var draft LibraryArtifactDraft
	var title, summary, content, rationale, assumptions, generator, model, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest, createdBy string
	if err := row.Scan(&draft.ID, &title, &summary, &content, &draft.Format, &rationale, &assumptions, &draft.Origin, &generator, &model, &draft.PromptDigest,
		&sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest, &createdBy, &draft.CreatedAt); err != nil {
		return LibraryArtifactDraft{}, err
	}
	var err error
	fields := []struct {
		label  string
		stored string
		target *string
	}{
		{"title", title, &draft.Title}, {"summary", summary, &draft.Summary}, {"content", content, &draft.Content},
		{"rationale", rationale, &draft.Rationale}, {"generator", generator, &draft.Generator}, {"model", model, &draft.Model},
		{"source artifact", sourceArtifactID, &draft.SourceArtifactID}, {"source artifact version", sourceArtifactVersionID, &draft.SourceArtifactVersionID},
		{"source artifact digest", sourceArtifactDigest, &draft.SourceArtifactDigest}, {"created by", createdBy, &draft.CreatedBy},
	}
	for _, field := range fields {
		if *field.target, err = s.decryptLibraryText("artifact draft", draft.ID, field.label, field.stored); err != nil {
			return LibraryArtifactDraft{}, err
		}
	}
	if draft.Assumptions, err = s.decryptLibraryAssumptions("artifact draft", draft.ID, assumptions); err != nil {
		return LibraryArtifactDraft{}, err
	}
	return draft, nil
}

func (s *PgStore) scanLibrarySkillDraft(row libraryRowScanner) (LibrarySkillDraft, error) {
	var draft LibrarySkillDraft
	var name, description, content, generator, model, createdBy, rationale, assumptions string
	var capabilities []byte
	if err := row.Scan(&draft.ID, &name, &description, &content, &capabilities, &draft.Origin, &generator, &model, &draft.PromptDigest, &createdBy, &draft.CreatedAt, &rationale, &assumptions); err != nil {
		return LibrarySkillDraft{}, err
	}
	var err error
	if draft.Rationale, err = s.decryptLibraryText("skill draft", draft.ID, "rationale", rationale); err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.Assumptions, err = s.decryptLibraryAssumptions("skill draft", draft.ID, assumptions); err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.Name, err = s.decryptLibraryText("skill draft", draft.ID, "name", name); err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.Description, err = s.decryptLibraryText("skill draft", draft.ID, "description", description); err != nil {
		return LibrarySkillDraft{}, err
	}
	draft.Content, err = s.decryptLibraryText("skill draft", draft.ID, "content", content)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.CreatedBy, err = s.decryptLibraryText("skill draft", draft.ID, "created by", createdBy); err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.Generator, err = s.decryptLibraryText("skill draft", draft.ID, "generator", generator); err != nil {
		return LibrarySkillDraft{}, err
	}
	if draft.Model, err = s.decryptLibraryText("skill draft", draft.ID, "model", model); err != nil {
		return LibrarySkillDraft{}, err
	}
	if err := json.Unmarshal(capabilities, &draft.RequestedCapabilities); err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("decode library skill draft %q capabilities: %w", draft.ID, err)
	}
	return draft, nil
}

func (s *PgStore) scanLibrarySkillBinding(row libraryRowScanner) (LibrarySkillBinding, error) {
	var binding LibrarySkillBinding
	var capabilities []byte
	var createdBy string
	if err := row.Scan(&binding.ID, &binding.SkillID, &binding.ScopeKind, &binding.ScopeID, &binding.Mode, &binding.PinnedVersionID, &capabilities, &binding.Priority, &createdBy, &binding.CreatedAt, &binding.UpdatedAt); err != nil {
		return LibrarySkillBinding{}, err
	}
	var err error
	if binding.CreatedBy, err = s.decryptLibraryText("skill binding", binding.ID, "created by", createdBy); err != nil {
		return LibrarySkillBinding{}, err
	}
	if err := json.Unmarshal(capabilities, &binding.CapabilityCeiling); err != nil {
		return LibrarySkillBinding{}, fmt.Errorf("decode library binding %q capabilities: %w", binding.ID, err)
	}
	return binding, nil
}

// ensureLibrarySkillBindingGenerationForUpdateTx creates the first durable
// marker for a legacy skill only while its parent skill row is already locked
// by the caller. It intentionally does not derive a marker from binding rows:
// an add/remove cycle can restore those rows byte-for-byte.
func (s *PgStore) ensureLibrarySkillBindingGenerationForUpdateTx(ctx context.Context, tx pgx.Tx, skillID string) (int64, error) {
	var generation int64
	err := tx.QueryRow(ctx, `
INSERT INTO narthex_library_skill_binding_generations (skill_id,generation,updated_at)
VALUES ($1,1,$2)
ON CONFLICT (skill_id) DO NOTHING
RETURNING generation`, skillID, time.Now().UTC()).Scan(&generation)
	if err == nil {
		return generation, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if err := tx.QueryRow(ctx, `
SELECT generation
FROM narthex_library_skill_binding_generations
WHERE skill_id=$1
FOR UPDATE`, skillID).Scan(&generation); err != nil {
		return 0, err
	}
	if generation <= 0 {
		return 0, fmt.Errorf("invalid library skill binding generation for %q", skillID)
	}
	return generation, nil
}

// bumpLibrarySkillBindingGenerationForUpdateTx is the only PgStore mutation
// path for the generation facet. The parent skill lock taken by callers
// serializes it with bindings and leased authoring updates.
func (s *PgStore) bumpLibrarySkillBindingGenerationForUpdateTx(ctx context.Context, tx pgx.Tx, skillID string) (int64, error) {
	var generation int64
	if err := tx.QueryRow(ctx, `
INSERT INTO narthex_library_skill_binding_generations (skill_id,generation,updated_at)
VALUES ($1,1,$2)
ON CONFLICT (skill_id) DO UPDATE
SET generation=narthex_library_skill_binding_generations.generation+1,
    updated_at=EXCLUDED.updated_at
RETURNING generation`, skillID, time.Now().UTC()).Scan(&generation); err != nil {
		return 0, err
	}
	if generation <= 0 {
		return 0, fmt.Errorf("invalid library skill binding generation for %q", skillID)
	}
	return generation, nil
}

func (s *PgStore) scanLibrarySkillEvaluation(row libraryRowScanner) (LibrarySkillEvaluation, error) {
	var evaluation LibrarySkillEvaluation
	var evaluator, summary, createdBy string
	if err := row.Scan(&evaluation.ID, &evaluation.SkillID, &evaluation.SkillVersionID, &evaluator, &evaluation.Score, &evaluation.Passed, &summary, &evaluation.EvidenceDigest, &createdBy, &evaluation.CreatedAt); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	var err error
	if evaluation.Evaluator, err = s.decryptLibraryText("skill evaluation", evaluation.ID, "evaluator", evaluator); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	if evaluation.Summary, err = s.decryptLibraryText("skill evaluation", evaluation.ID, "summary", summary); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	if evaluation.CreatedBy, err = s.decryptLibraryText("skill evaluation", evaluation.ID, "created by", createdBy); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	return evaluation, nil
}

func (s *PgStore) scanLibraryRun(row libraryRowScanner) (LibraryRun, error) {
	var run LibraryRun
	var capabilities []byte
	var actorRef, surfaceRef, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest string
	if err := row.Scan(&run.ID, &run.Origin, &run.Attestation, &run.SkillID, &run.SkillVersionID, &run.BindingID, &actorRef, &surfaceRef, &capabilities, &run.Status, &run.InputDigest, &run.OutputDigest, &sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest, &run.StartedAt, &run.CompletedAt); err != nil {
		return LibraryRun{}, err
	}
	var err error
	if run.ActorRef, err = s.decryptLibraryText("run", run.ID, "actor reference", actorRef); err != nil {
		return LibraryRun{}, err
	}
	if run.SurfaceRef, err = s.decryptLibraryText("run", run.ID, "surface reference", surfaceRef); err != nil {
		return LibraryRun{}, err
	}
	if run.SourceArtifactID, err = s.decryptLibraryText("run", run.ID, "source artifact", sourceArtifactID); err != nil {
		return LibraryRun{}, err
	}
	if run.SourceArtifactVersionID, err = s.decryptLibraryText("run", run.ID, "source artifact version", sourceArtifactVersionID); err != nil {
		return LibraryRun{}, err
	}
	if run.SourceArtifactDigest, err = s.decryptLibraryText("run", run.ID, "source artifact digest", sourceArtifactDigest); err != nil {
		return LibraryRun{}, err
	}
	if err := json.Unmarshal(capabilities, &run.EffectiveCapabilities); err != nil {
		return LibraryRun{}, fmt.Errorf("decode library run %q capabilities: %w", run.ID, err)
	}
	return run, nil
}

func (s *PgStore) scanLibraryArtifact(row libraryRowScanner) (LibraryArtifact, error) {
	var artifact LibraryArtifact
	var title, summary, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest, createdBy string
	if err := row.Scan(&artifact.ID, &title, &summary, &artifact.Origin, &artifact.RunID, &artifact.SkillID, &artifact.SkillVersionID, &artifact.BindingID, &artifact.AgentSurfaceID, &sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest, &createdBy, &artifact.CreatedAt); err != nil {
		return LibraryArtifact{}, err
	}
	var err error
	if artifact.Title, err = s.decryptLibraryText("artifact", artifact.ID, "title", title); err != nil {
		return LibraryArtifact{}, err
	}
	if artifact.Summary, err = s.decryptLibraryText("artifact", artifact.ID, "summary", summary); err != nil {
		return LibraryArtifact{}, err
	}
	if artifact.CreatedBy, err = s.decryptLibraryText("artifact", artifact.ID, "created by", createdBy); err != nil {
		return LibraryArtifact{}, err
	}
	if artifact.SourceArtifactID, err = s.decryptLibraryText("artifact", artifact.ID, "source artifact", sourceArtifactID); err != nil {
		return LibraryArtifact{}, err
	}
	if artifact.SourceArtifactVersionID, err = s.decryptLibraryText("artifact", artifact.ID, "source artifact version", sourceArtifactVersionID); err != nil {
		return LibraryArtifact{}, err
	}
	if artifact.SourceArtifactDigest, err = s.decryptLibraryText("artifact", artifact.ID, "source artifact digest", sourceArtifactDigest); err != nil {
		return LibraryArtifact{}, err
	}
	return artifact, nil
}

func (s *PgStore) scanLibraryArtifactVersion(row libraryRowScanner) (LibraryArtifactVersion, error) {
	var version LibraryArtifactVersion
	var body, createdBy, reviewedBy, reviewComment string
	var reviewedAt, publicationClaimedAt *time.Time
	var stored libraryVersionProvenanceStorage
	if err := row.Scan(&version.ID, &version.ArtifactID, &version.Version, &version.Format, &body, &version.Digest, &version.SizeBytes, &version.RedactionStatus, &createdBy, &reviewedBy, &reviewedAt, &publicationClaimedAt, &version.CreatedAt,
		&stored.changelog, &stored.origin, &stored.generator, &stored.model, &stored.promptDigest, &stored.draftID, &reviewComment); err != nil {
		return LibraryArtifactVersion{}, err
	}
	plain, err := s.dec(body)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("decrypt library artifact version %q: %w", version.ID, err)
	}
	version.Body = plain
	if version.CreatedBy, err = s.decryptLibraryText("artifact version", version.ID, "created by", createdBy); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if version.ReviewedBy, err = s.decryptLibraryText("artifact version", version.ID, "reviewed by", reviewedBy); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if version.ReviewComment, err = s.decryptLibraryText("artifact version", version.ID, "review comment", reviewComment); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if version.Changelog, version.Provenance, err = s.decryptLibraryVersionProvenance("artifact version", version.ID, stored); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if reviewedAt != nil {
		version.ReviewedAt = *reviewedAt
	}
	if publicationClaimedAt != nil {
		version.PublicationClaimedAt = *publicationClaimedAt
	}
	return version, nil
}

func (s *PgStore) scanLibraryArtifactGrant(row libraryRowScanner) (LibraryArtifactGrant, error) {
	var grant LibraryArtifactGrant
	var createdBy, revokedBy string
	var revokedAt *time.Time
	if err := row.Scan(&grant.ID, &grant.ArtifactID, &grant.ArtifactVersionID, &grant.ArtifactVersionDigest, &grant.AgentSurfaceID, &createdBy, &grant.CreatedAt, &revokedBy, &revokedAt); err != nil {
		return LibraryArtifactGrant{}, err
	}
	var err error
	if grant.CreatedBy, err = s.decryptLibraryText("artifact grant", grant.ID, "created by", createdBy); err != nil {
		return LibraryArtifactGrant{}, err
	}
	if grant.RevokedBy, err = s.decryptLibraryText("artifact grant", grant.ID, "revoked by", revokedBy); err != nil {
		return LibraryArtifactGrant{}, err
	}
	if revokedAt != nil {
		grant.RevokedAt = *revokedAt
	}
	return grant, nil
}

func (s *PgStore) LibrarySkills(ctx context.Context) ([]LibrarySkill, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var skills []LibrarySkill
	for rows.Next() {
		skill, err := s.scanLibrarySkill(rows)
		if err != nil {
			return nil, err
		}
		skills = append(skills, skill)
	}
	return skills, rows.Err()
}

// LibraryConsoleSkillPage selects the latest immutable version's metadata in
// the same bounded query as its skill, ordered by the most recent immutable
// version write. It deliberately omits Content so a Console list cannot turn
// into a bulk instruction download.
func (s *PgStore) LibraryConsoleSkillPage(ctx context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleSkillPage, error) {
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleSkillPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleSkillPage{}, err
	}
	var afterTimestamp *time.Time
	if !cursor.Timestamp.IsZero() {
		ts := cursor.Timestamp.UTC()
		afterTimestamp = &ts
	}

	rows, err := s.pool.Query(ctx, `
SELECT s.id,s.slug,s.name,s.description,s.created_by,s.created_at,s.updated_at,
       latest.id,latest.version_number,latest.digest,latest.requested_capabilities,latest.created_at
FROM narthex_library_skills s
LEFT JOIN LATERAL (
    SELECT id,version_number,digest,requested_capabilities,created_at
    FROM narthex_library_skill_versions
    WHERE skill_id=s.id
    ORDER BY version_number DESC
    LIMIT 1
) latest ON TRUE
WHERE ($1::timestamptz IS NULL OR s.updated_at < $1 OR (s.updated_at = $1 AND s.id < $2))
ORDER BY s.updated_at DESC,s.id DESC
LIMIT $3`, afterTimestamp, cursor.ID, limit+1)
	if err != nil {
		return LibraryConsoleSkillPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryConsoleSkill, 0, limit+1)
	for rows.Next() {
		var item LibraryConsoleSkill
		var name, description, createdBy string
		var latestID, latestDigest *string
		var latestVersion *int
		var latestCapabilities []byte
		var latestCreatedAt *time.Time
		if err := rows.Scan(
			&item.Skill.ID, &item.Skill.Slug, &name, &description, &createdBy, &item.Skill.CreatedAt, &item.Skill.UpdatedAt,
			&latestID, &latestVersion, &latestDigest, &latestCapabilities, &latestCreatedAt,
		); err != nil {
			return LibraryConsoleSkillPage{}, err
		}
		if item.Skill.Name, err = s.decryptLibraryText("skill", item.Skill.ID, "name", name); err != nil {
			return LibraryConsoleSkillPage{}, err
		}
		if item.Skill.Description, err = s.decryptLibraryText("skill", item.Skill.ID, "description", description); err != nil {
			return LibraryConsoleSkillPage{}, err
		}
		if item.Skill.CreatedBy, err = s.decryptLibraryText("skill", item.Skill.ID, "created by", createdBy); err != nil {
			return LibraryConsoleSkillPage{}, err
		}
		if latestID != nil {
			if latestVersion == nil || latestDigest == nil || latestCreatedAt == nil {
				return LibraryConsoleSkillPage{}, errors.New("invalid latest library skill version projection")
			}
			var capabilities []string
			if err := json.Unmarshal(latestCapabilities, &capabilities); err != nil {
				return LibraryConsoleSkillPage{}, fmt.Errorf("decode library skill version %q capabilities: %w", *latestID, err)
			}
			item.LatestVersion = &LibraryConsoleSkillVersionSummary{
				ID: *latestID, Version: *latestVersion, Digest: *latestDigest,
				RequestedCapabilities: capabilities, CreatedAt: *latestCreatedAt,
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return LibraryConsoleSkillPage{}, err
	}
	page := LibraryConsoleSkillPage{Skills: items}
	if len(page.Skills) > limit {
		last := page.Skills[limit-1].Skill
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.UpdatedAt, ID: last.ID}
		page.Skills = page.Skills[:limit]
	}
	return page, nil
}

// LibraryMCPRootSkillPage reads only root-list metadata plus a latest-version
// identity. It never selects encrypted instruction Content while listing.
func (s *PgStore) LibraryMCPRootSkillPage(ctx context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootSkillPage, error) {
	if err := validateLibraryMCPRootPageCursor(cursor); err != nil {
		return LibraryMCPRootSkillPage{}, err
	}
	limit, err := normalizeLibraryMCPRootPageLimit(limit)
	if err != nil {
		return LibraryMCPRootSkillPage{}, err
	}
	var afterCreatedAt *time.Time
	if !cursor.CreatedAt.IsZero() {
		ts := cursor.CreatedAt.UTC()
		afterCreatedAt = &ts
	}

	rows, err := s.pool.Query(ctx, `
SELECT s.id,s.slug,s.name,s.description,s.created_at,latest.id,latest.version_number
FROM narthex_library_skills s
JOIN LATERAL (
    SELECT id,version_number
    FROM narthex_library_skill_versions
    WHERE skill_id=s.id
    ORDER BY version_number DESC
    LIMIT 1
) latest ON TRUE
WHERE ($1::timestamptz IS NULL OR s.created_at < $1 OR (s.created_at = $1 AND s.id < $2))
ORDER BY s.created_at DESC,s.id DESC
LIMIT $3`, afterCreatedAt, cursor.ID, limit+1)
	if err != nil {
		return LibraryMCPRootSkillPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryMCPRootSkill, 0, limit+1)
	for rows.Next() {
		var skill LibraryMCPRootSkill
		var name, description string
		if err := rows.Scan(&skill.ID, &skill.Slug, &name, &description, &skill.CreatedAt, &skill.LatestVersionID, &skill.LatestVersion); err != nil {
			return LibraryMCPRootSkillPage{}, err
		}
		if skill.Name, err = s.decryptLibraryText("skill", skill.ID, "name", name); err != nil {
			return LibraryMCPRootSkillPage{}, err
		}
		if skill.Description, err = s.decryptLibraryText("skill", skill.ID, "description", description); err != nil {
			return LibraryMCPRootSkillPage{}, err
		}
		items = append(items, skill)
	}
	if err := rows.Err(); err != nil {
		return LibraryMCPRootSkillPage{}, err
	}
	page := LibraryMCPRootSkillPage{Skills: items}
	if len(page.Skills) > limit {
		last := page.Skills[limit-1]
		page.NextCursor = LibraryMCPRootPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
		page.Skills = page.Skills[:limit]
	}
	return page, nil
}

func (s *PgStore) LibrarySkill(ctx context.Context, id string) (LibrarySkill, bool) {
	skill, err := s.scanLibrarySkill(s.pool.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1`, id))
	if err != nil {
		return LibrarySkill{}, false
	}
	return skill, true
}

func (s *PgStore) CreateLibrarySkillWithInitialVersion(ctx context.Context, skill LibrarySkill, version LibrarySkillVersion) (LibrarySkill, LibrarySkillVersion, error) {
	return s.createLibrarySkillWithInitialVersion(ctx, skill, version, nil)
}

// createLibrarySkillWithInitialVersion commits the skill, its first immutable
// version, and (for a bundle) the referenced blobs in one transaction. A nil
// bundle is the legacy single-document write.
func (s *PgStore) createLibrarySkillWithInitialVersion(ctx context.Context, skill LibrarySkill, version LibrarySkillVersion, bundle *LibrarySkillBundle) (LibrarySkill, LibrarySkillVersion, error) {
	if isReservedBuiltInLibrarySkillIdentity(skill.ID, skill.Slug) || isReservedBuiltInLibraryVersionID(version.ID) {
		return LibrarySkill{}, LibrarySkillVersion{}, ErrLibraryBuiltInManaged
	}
	if skill.ID == "" {
		skill.ID = newLibrarySkillID()
	}
	if err := validateLibrarySkill(skill); err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	version.SkillID, version.Version = skill.ID, 1
	version.CreatedBy = firstNonEmpty(version.CreatedBy, skill.CreatedBy)
	if bundle != nil {
		version.Files = copyLibrarySkillFiles(bundle.Files)
		version.ManifestDigest = bundle.ManifestDigest
	}
	normalized, err := normalizedLibraryVersion(version)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillVersionID()
	}
	manifest, err := s.encryptLibrarySkillManifest(normalized.Files)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	name, err := s.enc(skill.Name)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, fmt.Errorf("encrypt library skill name: %w", err)
	}
	description, err := s.enc(skill.Description)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, fmt.Errorf("encrypt library skill description: %w", err)
	}
	createdBy, err := s.enc(skill.CreatedBy)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, fmt.Errorf("encrypt library skill created by: %w", err)
	}
	content, err := s.enc(normalized.Content)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, fmt.Errorf("encrypt library skill content: %w", err)
	}
	versionCreatedBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, fmt.Errorf("encrypt library skill version created by: %w", err)
	}
	capabilities, err := libraryJSONCapabilities(normalized.RequestedCapabilities)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	provenance, err := s.encryptLibraryVersionProvenance(normalized.Changelog, normalized.Provenance)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skills (id,slug,name,description,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`, skill.ID, skill.Slug, name, description, createdBy, now); err != nil {
		if isUniqueViolation(err) {
			return LibrarySkill{}, LibrarySkillVersion{}, ErrLibrarySkillExists
		}
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	normalized.CreatedAt = now
	if bundle != nil {
		if err := s.insertLibrarySkillBlobsTx(ctx, tx, bundle.Blobs, now); err != nil {
			return LibrarySkill{}, LibrarySkillVersion{}, err
		}
		if err := s.requireLibrarySkillBlobsTx(ctx, tx, *bundle); err != nil {
			return LibrarySkill{}, LibrarySkillVersion{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_versions (`+librarySkillVersionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		normalized.ID, normalized.SkillID, normalized.Version, content, normalized.Digest, capabilities, versionCreatedBy, normalized.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID, manifest, normalized.ManifestDigest); err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibrarySkill{}, LibrarySkillVersion{}, err
	}
	skill.CreatedAt, skill.UpdatedAt = now, now
	return skill, normalized, nil
}

func (s *PgStore) LibrarySkillVersions(ctx context.Context, skillID string) ([]LibrarySkillVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 ORDER BY version_number`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []LibrarySkillVersion
	for rows.Next() {
		version, err := s.scanLibrarySkillVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (s *PgStore) LibrarySkillVersion(ctx context.Context, skillID, id string) (LibrarySkillVersion, bool) {
	version, err := s.scanLibrarySkillVersion(s.pool.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2`, skillID, id))
	if err != nil {
		return LibrarySkillVersion{}, false
	}
	return version, true
}

func (s *PgStore) CreateLibrarySkillVersion(ctx context.Context, version LibrarySkillVersion) (LibrarySkillVersion, error) {
	return s.createLibrarySkillVersion(ctx, version, nil)
}

func (s *PgStore) createLibrarySkillVersion(ctx context.Context, version LibrarySkillVersion, bundle *LibrarySkillBundle) (LibrarySkillVersion, error) {
	if isBuiltInLibrarySkillID(version.SkillID) || isReservedBuiltInLibraryVersionID(version.ID) {
		return LibrarySkillVersion{}, ErrLibraryBuiltInManaged
	}
	if bundle != nil {
		if bundle.SkillDescription != nil {
			if err := validateLibrarySkillDescriptionUpdate(*bundle.SkillDescription); err != nil {
				return LibrarySkillVersion{}, err
			}
		}
		version.Files = copyLibrarySkillFiles(bundle.Files)
		version.ManifestDigest = bundle.ManifestDigest
	}
	normalized, err := normalizedLibraryVersion(version)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillVersionID()
	}
	manifest, err := s.encryptLibrarySkillManifest(normalized.Files)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	content, err := s.enc(normalized.Content)
	if err != nil {
		return LibrarySkillVersion{}, fmt.Errorf("encrypt library skill content: %w", err)
	}
	createdBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibrarySkillVersion{}, fmt.Errorf("encrypt library skill version created by: %w", err)
	}
	capabilities, err := libraryJSONCapabilities(normalized.RequestedCapabilities)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	provenance, err := s.encryptLibraryVersionProvenance(normalized.Changelog, normalized.Provenance)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	defer tx.Rollback(ctx)
	var skillID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, normalized.SkillID).Scan(&skillID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LibrarySkillVersion{}, ErrLibrarySkillNotFound
		}
		return LibrarySkillVersion{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version_number),0)+1 FROM narthex_library_skill_versions WHERE skill_id=$1`, normalized.SkillID).Scan(&normalized.Version); err != nil {
		return LibrarySkillVersion{}, err
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	}
	if bundle != nil {
		if err := s.insertLibrarySkillBlobsTx(ctx, tx, bundle.Blobs, normalized.CreatedAt); err != nil {
			return LibrarySkillVersion{}, err
		}
		if err := s.requireLibrarySkillBlobsTx(ctx, tx, *bundle); err != nil {
			return LibrarySkillVersion{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_versions (`+librarySkillVersionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		normalized.ID, normalized.SkillID, normalized.Version, content, normalized.Digest, capabilities, createdBy, normalized.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID, manifest, normalized.ManifestDigest); err != nil {
		return LibrarySkillVersion{}, err
	}
	if bundle != nil && bundle.SkillDescription != nil {
		description, err := s.enc(*bundle.SkillDescription)
		if err != nil {
			return LibrarySkillVersion{}, fmt.Errorf("encrypt library skill description: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE narthex_library_skills SET description=$2,updated_at=$3 WHERE id=$1`, normalized.SkillID, description, normalized.CreatedAt); err != nil {
			return LibrarySkillVersion{}, err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE narthex_library_skills SET updated_at=$2 WHERE id=$1`, normalized.SkillID, normalized.CreatedAt); err != nil {
		return LibrarySkillVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibrarySkillVersion{}, err
	}
	return normalized, nil
}

func (s *PgStore) CreateLibrarySkillDraft(ctx context.Context, draft LibrarySkillDraft) (LibrarySkillDraft, error) {
	if draft.ID == "" {
		draft.ID = newLibrarySkillDraftID()
	}
	if err := validateLibrarySkillDraft(draft); err != nil {
		return LibrarySkillDraft{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(draft.RequestedCapabilities)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	draft.RequestedCapabilities = capabilities
	if draft.CreatedAt.IsZero() {
		draft.CreatedAt = time.Now().UTC()
	}
	name, err := s.enc(draft.Name)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft name: %w", err)
	}
	description, err := s.enc(draft.Description)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft description: %w", err)
	}
	content, err := s.enc(draft.Content)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library draft content: %w", err)
	}
	createdBy, err := s.enc(draft.CreatedBy)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft created by: %w", err)
	}
	generator, err := s.enc(draft.Generator)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft generator: %w", err)
	}
	model, err := s.enc(draft.Model)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft model: %w", err)
	}
	jsonCapabilities, err := libraryJSONCapabilities(capabilities)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	assumptions, err := normalizeLibraryDraftAssumptions(draft.Assumptions)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	draft.Assumptions = assumptions
	rationale, err := s.enc(draft.Rationale)
	if err != nil {
		return LibrarySkillDraft{}, fmt.Errorf("encrypt library skill draft rationale: %w", err)
	}
	storedAssumptions, err := s.encryptLibraryAssumptions(assumptions)
	if err != nil {
		return LibrarySkillDraft{}, err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO narthex_library_skill_drafts (`+libraryDraftColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, draft.ID, name, description, content, jsonCapabilities, draft.Origin, generator, model, draft.PromptDigest, createdBy, draft.CreatedAt, rationale, storedAssumptions); err != nil {
		return LibrarySkillDraft{}, err
	}
	return draft, nil
}

func (s *PgStore) LibrarySkillDraft(ctx context.Context, id string) (LibrarySkillDraft, bool) {
	draft, err := s.scanLibrarySkillDraft(s.pool.QueryRow(ctx, `SELECT `+libraryDraftColumns+` FROM narthex_library_skill_drafts WHERE id=$1`, id))
	if err != nil {
		return LibrarySkillDraft{}, false
	}
	return draft, true
}

// ImportPlatformLibrarySkillDraft is deliberately a persistence primitive, not
// a generic draft-creation shortcut. The caller supplies only a typed broker
// result and an already-verified opaque actor reference. The request ID is
// hashed before storage; repeated IDs return the original editable draft only
// when every canonical candidate field still matches.
func (s *PgStore) ImportPlatformLibrarySkillDraft(ctx context.Context, request LibraryPlatformSkillDraftImport, createdBy string) (LibrarySkillDraft, bool, error) {
	normalized, err := normalizeLibraryPlatformSkillDraftImport(request, createdBy)
	if err != nil {
		return LibrarySkillDraft{}, false, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		draft, replayed, retry, err := s.importPlatformLibrarySkillDraft(ctx, normalized)
		if err != nil {
			return LibrarySkillDraft{}, false, err
		}
		if retry {
			continue
		}
		return draft, replayed, nil
	}
	return LibrarySkillDraft{}, false, errors.New("platform draft import could not establish idempotency")
}

// importPlatformLibrarySkillDraft keeps the draft and its idempotency record in
// the same transaction. A conflicting concurrent insert rolls its unreferenced
// draft back, then the outer retry reads the committed winner.
func (s *PgStore) importPlatformLibrarySkillDraft(ctx context.Context, normalized normalizedLibraryPlatformSkillDraftImport) (LibrarySkillDraft, bool, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkillDraft{}, false, false, err
	}
	defer tx.Rollback(ctx)

	var existing librarySkillDraftImportRecord
	err = tx.QueryRow(ctx, `SELECT request_id_hash,payload_digest,draft_id FROM narthex_library_skill_draft_imports WHERE request_id_hash=$1`, normalized.record.RequestIDHash).Scan(&existing.RequestIDHash, &existing.PayloadDigest, &existing.DraftID)
	switch {
	case err == nil:
		if existing.PayloadDigest != normalized.record.PayloadDigest {
			return LibrarySkillDraft{}, false, false, ErrLibraryDraftImportConflict
		}
		draft, err := s.scanLibrarySkillDraft(tx.QueryRow(ctx, `SELECT `+libraryDraftColumns+` FROM narthex_library_skill_drafts WHERE id=$1`, existing.DraftID))
		if errors.Is(err, pgx.ErrNoRows) {
			return LibrarySkillDraft{}, false, false, errors.New("platform draft import record references a missing draft")
		}
		if err != nil {
			return LibrarySkillDraft{}, false, false, err
		}
		return draft, true, false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return LibrarySkillDraft{}, false, false, err
	}

	draft := normalized.draft
	draft.ID = newLibrarySkillDraftID()
	draft.CreatedAt = time.Now().UTC()
	name, err := s.enc(draft.Name)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft name: %w", err)
	}
	description, err := s.enc(draft.Description)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft description: %w", err)
	}
	content, err := s.enc(draft.Content)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft content: %w", err)
	}
	createdBy, err := s.enc(draft.CreatedBy)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft actor: %w", err)
	}
	provider, err := s.enc(draft.Generator)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft provider: %w", err)
	}
	model, err := s.enc(draft.Model)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft model: %w", err)
	}
	capabilities, err := libraryJSONCapabilities(draft.RequestedCapabilities)
	if err != nil {
		return LibrarySkillDraft{}, false, false, err
	}
	rationale, err := s.enc(draft.Rationale)
	if err != nil {
		return LibrarySkillDraft{}, false, false, fmt.Errorf("encrypt platform draft rationale: %w", err)
	}
	assumptions, err := s.encryptLibraryAssumptions(draft.Assumptions)
	if err != nil {
		return LibrarySkillDraft{}, false, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_drafts (`+libraryDraftColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, draft.ID, name, description, content, capabilities, draft.Origin, provider, model, draft.PromptDigest, createdBy, draft.CreatedAt, rationale, assumptions); err != nil {
		return LibrarySkillDraft{}, false, false, err
	}
	record := normalized.record
	record.DraftID = draft.ID
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_draft_imports (request_id_hash,payload_digest,draft_id) VALUES ($1,$2,$3)`, record.RequestIDHash, record.PayloadDigest, record.DraftID); err != nil {
		if isUniqueViolation(err) {
			return LibrarySkillDraft{}, false, true, nil
		}
		return LibrarySkillDraft{}, false, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibrarySkillDraft{}, false, false, err
	}
	return draft, false, false, nil
}

// encryptLibraryArtifactDraft returns the encrypted column values for one
// artifact draft in libraryArtifactDraftColumns order after the ID.
func (s *PgStore) encryptLibraryArtifactDraft(draft LibraryArtifactDraft) ([]any, error) {
	assumptions, err := s.encryptLibraryAssumptions(draft.Assumptions)
	if err != nil {
		return nil, err
	}
	values := []any{draft.ID}
	for _, field := range []struct {
		label string
		plain string
	}{
		{"title", draft.Title}, {"summary", draft.Summary}, {"content", draft.Content},
	} {
		encrypted, err := s.enc(field.plain)
		if err != nil {
			return nil, fmt.Errorf("encrypt library artifact draft %s: %w", field.label, err)
		}
		values = append(values, encrypted)
	}
	values = append(values, draft.Format)
	rationale, err := s.enc(draft.Rationale)
	if err != nil {
		return nil, fmt.Errorf("encrypt library artifact draft rationale: %w", err)
	}
	values = append(values, rationale, assumptions, draft.Origin)
	for _, field := range []struct {
		label string
		plain string
	}{
		{"generator", draft.Generator}, {"model", draft.Model},
	} {
		encrypted, err := s.enc(field.plain)
		if err != nil {
			return nil, fmt.Errorf("encrypt library artifact draft %s: %w", field.label, err)
		}
		values = append(values, encrypted)
	}
	values = append(values, draft.PromptDigest)
	for _, field := range []struct {
		label string
		plain string
	}{
		{"source artifact", draft.SourceArtifactID}, {"source artifact version", draft.SourceArtifactVersionID},
		{"source artifact digest", draft.SourceArtifactDigest}, {"created by", draft.CreatedBy},
	} {
		encrypted, err := s.enc(field.plain)
		if err != nil {
			return nil, fmt.Errorf("encrypt library artifact draft %s: %w", field.label, err)
		}
		values = append(values, encrypted)
	}
	values = append(values, draft.CreatedAt)
	return values, nil
}

const libraryArtifactDraftInsert = `INSERT INTO narthex_library_artifact_drafts (` + libraryArtifactDraftColumns + `) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

func (s *PgStore) CreateLibraryArtifactDraft(ctx context.Context, draft LibraryArtifactDraft) (LibraryArtifactDraft, error) {
	if draft.ID == "" {
		draft.ID = newLibraryArtifactDraftID()
	}
	normalized, err := normalizedLibraryArtifactDraft(draft)
	if err != nil {
		return LibraryArtifactDraft{}, err
	}
	if err := s.validateLibraryArtifactSource(ctx, normalized.SourceArtifactID, normalized.SourceArtifactVersionID, normalized.SourceArtifactDigest); err != nil {
		return LibraryArtifactDraft{}, err
	}
	values, err := s.encryptLibraryArtifactDraft(normalized)
	if err != nil {
		return LibraryArtifactDraft{}, err
	}
	if _, err := s.pool.Exec(ctx, libraryArtifactDraftInsert, values...); err != nil {
		return LibraryArtifactDraft{}, err
	}
	return normalized, nil
}

func (s *PgStore) LibraryArtifactDraft(ctx context.Context, id string) (LibraryArtifactDraft, bool) {
	draft, err := s.scanLibraryArtifactDraft(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactDraftColumns+` FROM narthex_library_artifact_drafts WHERE id=$1`, id))
	if err != nil {
		return LibraryArtifactDraft{}, false
	}
	return draft, true
}

// ImportPlatformLibraryArtifactDraft mirrors the skill import's retry loop:
// a concurrent duplicate rolls back its draft and re-reads the winner.
func (s *PgStore) ImportPlatformLibraryArtifactDraft(ctx context.Context, request LibraryPlatformArtifactDraftImport, createdBy string) (LibraryArtifactDraft, bool, error) {
	normalized, err := normalizeLibraryPlatformArtifactDraftImport(request, createdBy)
	if err != nil {
		return LibraryArtifactDraft{}, false, err
	}
	if err := s.validateLibraryArtifactSource(ctx, normalized.draft.SourceArtifactID, normalized.draft.SourceArtifactVersionID, normalized.draft.SourceArtifactDigest); err != nil {
		return LibraryArtifactDraft{}, false, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		draft, replayed, retry, err := s.importPlatformLibraryArtifactDraft(ctx, normalized)
		if err != nil {
			return LibraryArtifactDraft{}, false, err
		}
		if retry {
			continue
		}
		return draft, replayed, nil
	}
	return LibraryArtifactDraft{}, false, errors.New("platform draft import could not establish idempotency")
}

func (s *PgStore) importPlatformLibraryArtifactDraft(ctx context.Context, normalized normalizedLibraryPlatformArtifactDraftImport) (LibraryArtifactDraft, bool, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactDraft{}, false, false, err
	}
	defer tx.Rollback(ctx)

	var existing librarySkillDraftImportRecord
	err = tx.QueryRow(ctx, `SELECT request_id_hash,payload_digest,draft_id FROM narthex_library_artifact_draft_imports WHERE request_id_hash=$1`, normalized.record.RequestIDHash).Scan(&existing.RequestIDHash, &existing.PayloadDigest, &existing.DraftID)
	switch {
	case err == nil:
		if existing.PayloadDigest != normalized.record.PayloadDigest {
			return LibraryArtifactDraft{}, false, false, ErrLibraryDraftImportConflict
		}
		draft, err := s.scanLibraryArtifactDraft(tx.QueryRow(ctx, `SELECT `+libraryArtifactDraftColumns+` FROM narthex_library_artifact_drafts WHERE id=$1`, existing.DraftID))
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryArtifactDraft{}, false, false, errors.New("platform draft import record references a missing draft")
		}
		if err != nil {
			return LibraryArtifactDraft{}, false, false, err
		}
		return draft, true, false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return LibraryArtifactDraft{}, false, false, err
	}

	draft := normalized.draft
	draft.ID = newLibraryArtifactDraftID()
	draft.CreatedAt = time.Now().UTC()
	values, err := s.encryptLibraryArtifactDraft(draft)
	if err != nil {
		return LibraryArtifactDraft{}, false, false, err
	}
	if _, err := tx.Exec(ctx, libraryArtifactDraftInsert, values...); err != nil {
		return LibraryArtifactDraft{}, false, false, err
	}
	record := normalized.record
	record.DraftID = draft.ID
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_artifact_draft_imports (request_id_hash,payload_digest,draft_id) VALUES ($1,$2,$3)`, record.RequestIDHash, record.PayloadDigest, record.DraftID); err != nil {
		if isUniqueViolation(err) {
			return LibraryArtifactDraft{}, false, true, nil
		}
		return LibraryArtifactDraft{}, false, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactDraft{}, false, false, err
	}
	return draft, false, false, nil
}

func (s *PgStore) LibrarySkillRuns(ctx context.Context, skillID string, limit int) ([]LibraryRun, error) {
	if limit <= 0 {
		return []LibraryRun{}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE origin=$1 AND skill_id=$2 ORDER BY started_at DESC,id DESC LIMIT $3`, LibraryRunOriginSkillRun, skillID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LibraryRun, 0)
	for rows.Next() {
		run, err := s.scanLibraryRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// LibraryArtifactCitations scans only artifacts that carry a source
// citation, newest first, and decrypts the citation to match. Source
// references are private text, so they are not indexable; the scan is
// bounded by the number of cited artifacts, not by the whole Library.
func (s *PgStore) LibraryArtifactCitations(ctx context.Context, artifactID string, limit int) ([]LibraryArtifactCitation, error) {
	out := make([]LibraryArtifactCitation, 0)
	if limit <= 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id,title,source_artifact_id,source_artifact_version_id,created_at FROM narthex_library_artifacts WHERE source_artifact_id <> '' ORDER BY created_at DESC,id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var citation LibraryArtifactCitation
		var title, sourceArtifactID, sourceArtifactVersionID string
		if err := rows.Scan(&citation.ArtifactID, &title, &sourceArtifactID, &sourceArtifactVersionID, &citation.CreatedAt); err != nil {
			return nil, err
		}
		source, err := s.decryptLibraryText("artifact", citation.ArtifactID, "source artifact", sourceArtifactID)
		if err != nil {
			return nil, err
		}
		if source != artifactID {
			continue
		}
		if citation.Title, err = s.decryptLibraryText("artifact", citation.ArtifactID, "title", title); err != nil {
			return nil, err
		}
		if citation.VersionID, err = s.decryptLibraryText("artifact", citation.ArtifactID, "source artifact version", sourceArtifactVersionID); err != nil {
			return nil, err
		}
		out = append(out, citation)
		if len(out) == limit {
			break
		}
	}
	return out, rows.Err()
}

func (s *PgStore) LibrarySkillBindings(ctx context.Context, skillID string) ([]LibrarySkillBinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE skill_id=$1 ORDER BY priority DESC, created_at`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []LibrarySkillBinding
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

// LibrarySkillResolutionSelections reads generic bindings and their selected
// versions through one repeatable-read PostgreSQL snapshot. Read Committed
// would give each query a newer view, allowing a previously read tracking
// binding to resolve a version created after the binding was removed.
func (s *PgStore) LibrarySkillResolutionSelections(ctx context.Context, request LibrarySkillResolutionRequest) ([]LibraryResolvedSkill, error) {
	if err := validateLibraryResolutionRequest(request); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	skills := make([]LibrarySkill, 0)
	rows, err := tx.Query(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		skill, err := s.scanLibrarySkill(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		skills = append(skills, skill)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	bindingsBySkill := make(map[string][]LibrarySkillBinding, len(skills))
	rows, err = tx.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		bindingsBySkill[binding.SkillID] = append(bindingsBySkill[binding.SkillID], binding)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	candidates, err := libraryResolutionCandidates(request, skills, bindingsBySkill)
	if err != nil {
		return nil, err
	}
	versionsBySkill := make(map[string][]LibrarySkillVersion, len(candidates))
	if len(candidates) > 0 {
		skillIDs := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			skillIDs = append(skillIDs, candidate.skill.ID)
		}
		rows, err = tx.Query(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id = ANY($1::text[]) ORDER BY skill_id, version_number`, skillIDs)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			version, err := s.scanLibrarySkillVersion(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			versionsBySkill[version.SkillID] = append(versionsBySkill[version.SkillID], version)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	resolved, err := resolveLibrarySkillSnapshot(request, skills, bindingsBySkill, versionsBySkill)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return resolved, nil
}

// LibraryAgentSurfaceSkillSelections resolves explicit agent-surface bindings
// in one PostgreSQL statement. PostgreSQL gives a single statement one MVCC
// snapshot, so a track binding and its selected head cannot be assembled from
// different before/after views of a concurrent binding/version update.
func (s *PgStore) LibraryAgentSurfaceSkillSelections(ctx context.Context, agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	const query = `
WITH ranked_bindings AS (
    SELECT b.*, ROW_NUMBER() OVER (PARTITION BY b.skill_id ORDER BY b.priority DESC, b.id) AS selection_rank
    FROM narthex_library_skill_bindings b
    WHERE b.scope_kind=$1 AND b.scope_id=$2
), selected_bindings AS (
    SELECT * FROM ranked_bindings WHERE selection_rank=1
)
SELECT
    s.id,s.slug,s.name,s.description,s.created_by,s.created_at,s.updated_at,
    b.id,b.skill_id,b.scope_kind,b.scope_id,b.mode,b.pinned_version_id,b.capability_ceiling,b.priority,b.created_by,b.created_at,b.updated_at,
    v.id,v.skill_id,v.version_number,v.content,v.digest,v.requested_capabilities,v.created_by,v.created_at,v.manifest,v.manifest_digest
FROM selected_bindings b
JOIN narthex_library_skills s ON s.id=b.skill_id
JOIN LATERAL (
    SELECT id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at,manifest,manifest_digest
    FROM narthex_library_skill_versions
    WHERE skill_id=b.skill_id
      AND ((b.mode='pin' AND id=b.pinned_version_id) OR b.mode='track')
    ORDER BY version_number DESC
    LIMIT 1
) v ON true
ORDER BY b.priority DESC, s.slug, s.id`
	rows, err := s.pool.Query(ctx, query, LibraryScopeAgentSurface, agentSurfaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	selections := make([]LibraryAgentSurfaceSkillSelection, 0)
	for rows.Next() {
		var selection LibraryAgentSurfaceSkillSelection
		var skillName, skillDescription, skillCreatedBy, bindingCreatedBy, versionContent, versionCreatedBy, versionManifest string
		var bindingCapabilities, versionCapabilities []byte
		if err := rows.Scan(
			&selection.Skill.ID, &selection.Skill.Slug, &skillName, &skillDescription, &skillCreatedBy, &selection.Skill.CreatedAt, &selection.Skill.UpdatedAt,
			&selection.Binding.ID, &selection.Binding.SkillID, &selection.Binding.ScopeKind, &selection.Binding.ScopeID, &selection.Binding.Mode, &selection.Binding.PinnedVersionID, &bindingCapabilities, &selection.Binding.Priority, &bindingCreatedBy, &selection.Binding.CreatedAt, &selection.Binding.UpdatedAt,
			&selection.Version.ID, &selection.Version.SkillID, &selection.Version.Version, &versionContent, &selection.Version.Digest, &versionCapabilities, &versionCreatedBy, &selection.Version.CreatedAt, &versionManifest, &selection.Version.ManifestDigest,
		); err != nil {
			return nil, err
		}
		if selection.Skill.Name, err = s.decryptLibraryText("skill", selection.Skill.ID, "name", skillName); err != nil {
			return nil, err
		}
		if selection.Skill.Description, err = s.decryptLibraryText("skill", selection.Skill.ID, "description", skillDescription); err != nil {
			return nil, err
		}
		if selection.Skill.CreatedBy, err = s.decryptLibraryText("skill", selection.Skill.ID, "created by", skillCreatedBy); err != nil {
			return nil, err
		}
		if selection.Binding.CreatedBy, err = s.decryptLibraryText("skill binding", selection.Binding.ID, "created by", bindingCreatedBy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(bindingCapabilities, &selection.Binding.CapabilityCeiling); err != nil {
			return nil, fmt.Errorf("decode library binding %q capabilities: %w", selection.Binding.ID, err)
		}
		if selection.Version.Content, err = s.decryptLibraryText("skill version", selection.Version.ID, "content", versionContent); err != nil {
			return nil, err
		}
		if selection.Version.CreatedBy, err = s.decryptLibraryText("skill version", selection.Version.ID, "created by", versionCreatedBy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(versionCapabilities, &selection.Version.RequestedCapabilities); err != nil {
			return nil, fmt.Errorf("decode library skill version %q capabilities: %w", selection.Version.ID, err)
		}
		if selection.Version.Files, err = s.decryptLibrarySkillManifest(selection.Version.ID, versionManifest); err != nil {
			return nil, err
		}
		if selection.Version, err = librarySkillVersionWithManifest(selection.Version); err != nil {
			return nil, fmt.Errorf("library skill version %q manifest: %w", selection.Version.ID, err)
		}
		if selection.Skill.ID != selection.Binding.SkillID || selection.Version.SkillID != selection.Binding.SkillID {
			return nil, errors.New("library agent-surface snapshot returned mismatched skill records")
		}
		selections = append(selections, selection)
	}
	return selections, rows.Err()
}

// libraryAgentSurfaceSkillSelectionsForUpdateTx is the commit-time variant of
// the read-only resolver. It locks skills before their bindings (the same
// order used by binding/version writers), then resolves each pin/track version
// while that skill lock prevents a new tracked head from racing the signed
// attestation commit.
func (s *PgStore) libraryAgentSurfaceSkillSelectionsForUpdateTx(ctx context.Context, tx pgx.Tx, agentSurfaceID string) ([]LibraryAgentSurfaceSkillSelection, error) {
	rows, err := tx.Query(ctx, `
SELECT DISTINCT skill_id
FROM narthex_library_skill_bindings
WHERE scope_kind=$1 AND scope_id=$2
ORDER BY skill_id`, LibraryScopeAgentSurface, agentSurfaceID)
	if err != nil {
		return nil, err
	}
	skillIDs := make([]string, 0)
	for rows.Next() {
		var skillID string
		if err := rows.Scan(&skillID); err != nil {
			rows.Close()
			return nil, err
		}
		skillIDs = append(skillIDs, skillID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(skillIDs) == 0 {
		return []LibraryAgentSurfaceSkillSelection{}, nil
	}
	locked, err := tx.Query(ctx, `SELECT id FROM narthex_library_skills WHERE id=ANY($1::text[]) ORDER BY id FOR UPDATE`, skillIDs)
	if err != nil {
		return nil, err
	}
	for locked.Next() {
		var ignored string
		if err := locked.Scan(&ignored); err != nil {
			locked.Close()
			return nil, err
		}
	}
	if err := locked.Err(); err != nil {
		locked.Close()
		return nil, err
	}
	locked.Close()

	rows, err = tx.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE scope_kind=$1 AND scope_id=$2 ORDER BY skill_id,id FOR UPDATE`, LibraryScopeAgentSurface, agentSurfaceID)
	if err != nil {
		return nil, err
	}
	// pgx permits only one active result reader on a transaction connection.
	// Materialize the locked bindings before resolving their encrypted records
	// and selected versions with additional queries below.
	bindings := make([]LibrarySkillBinding, 0, len(skillIDs))
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	selections := make([]LibraryAgentSurfaceSkillSelection, 0, len(bindings))
	for _, binding := range bindings {
		skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, binding.SkillID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLibrarySkillNotFound
		}
		if err != nil {
			return nil, err
		}
		var version LibrarySkillVersion
		switch binding.Mode {
		case LibraryBindingModePin:
			version, err = s.scanLibrarySkillVersion(tx.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2 FOR SHARE`, binding.SkillID, binding.PinnedVersionID))
		case LibraryBindingModeTrack:
			version, err = s.scanLibrarySkillVersion(tx.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 ORDER BY version_number DESC LIMIT 1 FOR SHARE`, binding.SkillID))
		default:
			return nil, fmt.Errorf("invalid library binding mode %q", binding.Mode)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLibrarySkillVersionNotFound
		}
		if err != nil {
			return nil, err
		}
		selections = append(selections, LibraryAgentSurfaceSkillSelection{Skill: skill, Binding: binding, Version: version})
	}
	return selections, nil
}

func (s *PgStore) UpsertLibrarySkillBinding(ctx context.Context, binding LibrarySkillBinding) (LibrarySkillBinding, error) {
	if isBuiltInLibrarySkillID(binding.SkillID) || isReservedBuiltInLibraryBindingID(binding.ID) {
		return LibrarySkillBinding{}, ErrLibraryBuiltInManaged
	}
	normalized, err := normalizedLibraryBinding(binding)
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibrarySkillBindingID()
	}
	capabilities, err := libraryJSONCapabilities(normalized.CapabilityCeiling)
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	createdBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibrarySkillBinding{}, fmt.Errorf("encrypt library skill binding created by: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	defer tx.Rollback(ctx)
	var skillID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, normalized.SkillID).Scan(&skillID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LibrarySkillBinding{}, ErrLibrarySkillNotFound
		}
		return LibrarySkillBinding{}, err
	}
	if normalized.Mode == LibraryBindingModePin {
		var versionID string
		if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, normalized.PinnedVersionID, normalized.SkillID).Scan(&versionID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return LibrarySkillBinding{}, ErrLibrarySkillVersionNotFound
			}
			return LibrarySkillBinding{}, err
		}
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_bindings (id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (skill_id,scope_kind,scope_id) DO UPDATE SET
    mode=EXCLUDED.mode,
    pinned_version_id=EXCLUDED.pinned_version_id,
    capability_ceiling=EXCLUDED.capability_ceiling,
    priority=EXCLUDED.priority,
    created_by=EXCLUDED.created_by,
    updated_at=EXCLUDED.updated_at`,
		normalized.ID, normalized.SkillID, normalized.ScopeKind, normalized.ScopeID, normalized.Mode, normalized.PinnedVersionID, capabilities, normalized.Priority, createdBy, normalized.CreatedAt, normalized.UpdatedAt); err != nil {
		return LibrarySkillBinding{}, err
	}
	if _, err := s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, normalized.SkillID); err != nil {
		return LibrarySkillBinding{}, err
	}
	updated, err := s.scanLibrarySkillBinding(tx.QueryRow(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE skill_id=$1 AND scope_kind=$2 AND scope_id=$3`, normalized.SkillID, normalized.ScopeKind, normalized.ScopeID))
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibrarySkillBinding{}, err
	}
	return updated, nil
}

func (s *PgStore) DeleteLibrarySkillBinding(ctx context.Context, skillID, bindingID string) error {
	if isBuiltInLibrarySkillID(skillID) {
		return ErrLibraryBuiltInManaged
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lockedSkillID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, skillID).Scan(&lockedSkillID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLibraryBindingNotFound
		}
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1 AND id=$2`, skillID, bindingID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLibraryBindingNotFound
	}
	if _, err := s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, skillID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PgStore) LibrarySkillEvaluations(ctx context.Context, skillID string) ([]LibrarySkillEvaluation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryEvaluationColumns+` FROM narthex_library_skill_evaluations WHERE skill_id=$1 ORDER BY created_at`, skillID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evaluations []LibrarySkillEvaluation
	for rows.Next() {
		evaluation, err := s.scanLibrarySkillEvaluation(rows)
		if err != nil {
			return nil, err
		}
		evaluations = append(evaluations, evaluation)
	}
	return evaluations, rows.Err()
}

func (s *PgStore) CreateLibrarySkillEvaluation(ctx context.Context, evaluation LibrarySkillEvaluation) (LibrarySkillEvaluation, error) {
	if evaluation.ID == "" {
		evaluation.ID = newLibrarySkillEvaluationID()
	}
	if err := validateLibraryEvaluation(evaluation); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	if evaluation.CreatedAt.IsZero() {
		evaluation.CreatedAt = time.Now().UTC()
	}
	var versionID string
	err := s.pool.QueryRow(ctx, `SELECT id FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, evaluation.SkillVersionID, evaluation.SkillID).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, found := s.LibrarySkill(ctx, evaluation.SkillID); !found {
			return LibrarySkillEvaluation{}, ErrLibrarySkillNotFound
		}
		return LibrarySkillEvaluation{}, ErrLibrarySkillVersionNotFound
	}
	if err != nil {
		return LibrarySkillEvaluation{}, err
	}
	evaluator, err := s.enc(evaluation.Evaluator)
	if err != nil {
		return LibrarySkillEvaluation{}, fmt.Errorf("encrypt library skill evaluation evaluator: %w", err)
	}
	summary, err := s.enc(evaluation.Summary)
	if err != nil {
		return LibrarySkillEvaluation{}, fmt.Errorf("encrypt library skill evaluation summary: %w", err)
	}
	createdBy, err := s.enc(evaluation.CreatedBy)
	if err != nil {
		return LibrarySkillEvaluation{}, fmt.Errorf("encrypt library skill evaluation created by: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO narthex_library_skill_evaluations (id,skill_id,skill_version_id,evaluator,score,passed,summary,evidence_digest,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, evaluation.ID, evaluation.SkillID, evaluation.SkillVersionID, evaluator, evaluation.Score, evaluation.Passed, summary, evaluation.EvidenceDigest, createdBy, evaluation.CreatedAt); err != nil {
		return LibrarySkillEvaluation{}, err
	}
	return evaluation, nil
}

func (s *PgStore) LibraryRuns(ctx context.Context) ([]LibraryRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs ORDER BY started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []LibraryRun
	for rows.Next() {
		run, err := s.scanLibraryRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

// LibraryConsoleRunPage bounds the Console run history with a newest-first
// keyset. It retains the established run metadata shape without scanning the
// workspace's entire provenance ledger on every page refresh.
func (s *PgStore) LibraryConsoleRunPage(ctx context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleRunPage, error) {
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleRunPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleRunPage{}, err
	}
	var afterTimestamp *time.Time
	if !cursor.Timestamp.IsZero() {
		ts := cursor.Timestamp.UTC()
		afterTimestamp = &ts
	}

	rows, err := s.pool.Query(ctx, `
SELECT `+libraryRunColumns+`
FROM narthex_library_runs
WHERE ($1::timestamptz IS NULL OR started_at < $1 OR (started_at = $1 AND id < $2))
ORDER BY started_at DESC,id DESC
LIMIT $3`, afterTimestamp, cursor.ID, limit+1)
	if err != nil {
		return LibraryConsoleRunPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryRun, 0, limit+1)
	for rows.Next() {
		run, err := s.scanLibraryRun(rows)
		if err != nil {
			return LibraryConsoleRunPage{}, err
		}
		items = append(items, run)
	}
	if err := rows.Err(); err != nil {
		return LibraryConsoleRunPage{}, err
	}
	page := LibraryConsoleRunPage{Runs: items}
	if len(page.Runs) > limit {
		last := page.Runs[limit-1]
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.StartedAt, ID: last.ID}
		page.Runs = page.Runs[:limit]
	}
	return page, nil
}

func (s *PgStore) LibraryRun(ctx context.Context, id string) (LibraryRun, bool) {
	run, err := s.scanLibraryRun(s.pool.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1`, id))
	if err != nil {
		return LibraryRun{}, false
	}
	return run, true
}

func (s *PgStore) CreateLibraryRun(ctx context.Context, run LibraryRun) (LibraryRun, error) {
	normalized, err := normalizedLibraryRun(run)
	if err != nil {
		return LibraryRun{}, err
	}
	if normalized.Attestation == LibraryRunAttestationHost {
		return LibraryRun{}, ErrLibraryRuntimeAttestationInvalid
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryRunID()
	}
	capabilities, err := libraryJSONCapabilities(normalized.EffectiveCapabilities)
	if err != nil {
		return LibraryRun{}, err
	}
	actorRef, err := s.enc(normalized.ActorRef)
	if err != nil {
		return LibraryRun{}, fmt.Errorf("encrypt library run actor reference: %w", err)
	}
	surfaceRef, err := s.enc(normalized.SurfaceRef)
	if err != nil {
		return LibraryRun{}, fmt.Errorf("encrypt library run surface reference: %w", err)
	}
	sourceArtifactID, err := s.enc(normalized.SourceArtifactID)
	if err != nil {
		return LibraryRun{}, fmt.Errorf("encrypt library run source artifact: %w", err)
	}
	sourceArtifactVersionID, err := s.enc(normalized.SourceArtifactVersionID)
	if err != nil {
		return LibraryRun{}, fmt.Errorf("encrypt library run source artifact version: %w", err)
	}
	sourceArtifactDigest, err := s.enc(normalized.SourceArtifactDigest)
	if err != nil {
		return LibraryRun{}, fmt.Errorf("encrypt library run source artifact digest: %w", err)
	}
	if normalized.Origin == LibraryRunOriginSkillRun {
		var versionID, bindingID string
		err := s.pool.QueryRow(ctx, `SELECT id FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, normalized.SkillVersionID, normalized.SkillID).Scan(&versionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryRun{}, ErrLibrarySkillVersionNotFound
		}
		if err != nil {
			return LibraryRun{}, err
		}
		err = s.pool.QueryRow(ctx, `SELECT id FROM narthex_library_skill_bindings WHERE id=$1 AND skill_id=$2`, normalized.BindingID, normalized.SkillID).Scan(&bindingID)
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryRun{}, ErrLibraryBindingNotFound
		}
		if err != nil {
			return LibraryRun{}, err
		}
	}
	if err := s.validateLibraryArtifactSource(ctx, normalized.SourceArtifactID, normalized.SourceArtifactVersionID, normalized.SourceArtifactDigest); err != nil {
		return LibraryRun{}, err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO narthex_library_runs (id,origin,attestation,skill_id,skill_version_id,binding_id,actor_ref,surface_ref,effective_capabilities,status,input_digest,output_digest,source_artifact_id,source_artifact_version_id,source_artifact_digest,started_at,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, normalized.ID, normalized.Origin, normalized.Attestation, normalized.SkillID, normalized.SkillVersionID, normalized.BindingID, actorRef, surfaceRef, capabilities, normalized.Status, normalized.InputDigest, normalized.OutputDigest, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest, normalized.StartedAt, normalized.CompletedAt); err != nil {
		return LibraryRun{}, err
	}
	return normalized, nil
}

// validateLibraryArtifactSource provides the durable half of a source
// citation. Subject-bound MCP ingress separately proves the caller owns this
// version or has a live grant; this check ensures the persisted source cannot
// point at a different artifact/version/body than the immutable digest claims.
func (s *PgStore) validateLibraryArtifactSource(ctx context.Context, artifactID, versionID, digest string) error {
	if artifactID == "" {
		return nil
	}
	var foundDigest string
	err := s.pool.QueryRow(ctx, `SELECT digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID).Scan(&foundDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, found := s.LibraryArtifact(ctx, artifactID); !found {
			return ErrLibraryArtifactNotFound
		}
		return ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return err
	}
	if foundDigest != digest {
		return ErrLibraryArtifactVersionNotFound
	}
	return nil
}

func (s *PgStore) LibraryArtifacts(ctx context.Context) ([]LibraryArtifact, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var artifacts []LibraryArtifact
	for rows.Next() {
		artifact, err := s.scanLibraryArtifact(rows)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, rows.Err()
}

// LibraryConsoleArtifactPage bounds the Console's artifact metadata history.
// It uses the established metadata scanner but never selects immutable version
// bodies, which remain behind an explicit artifact read.
func (s *PgStore) LibraryConsoleArtifactPage(ctx context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleArtifactPage, error) {
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleArtifactPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleArtifactPage{}, err
	}
	var afterTimestamp *time.Time
	if !cursor.Timestamp.IsZero() {
		ts := cursor.Timestamp.UTC()
		afterTimestamp = &ts
	}

	// The lateral join reads only latest-version metadata (never body) and,
	// for an image head, the blob's MIME type from its metadata row.
	rows, err := s.pool.Query(ctx, `
SELECT a.id,a.title,a.summary,a.origin,a.run_id,a.skill_id,a.skill_version_id,a.binding_id,a.agent_surface_id,a.source_artifact_id,a.source_artifact_version_id,a.source_artifact_digest,a.created_by,a.created_at,
       latest.id,latest.version_number,latest.format,latest.digest,latest.size_bytes,latest.redaction_status,latest.reviewed_at,latest.created_at,blob.mime_type
FROM narthex_library_artifacts a
LEFT JOIN LATERAL (
    SELECT id,version_number,format,digest,size_bytes,redaction_status,reviewed_at,created_at
    FROM narthex_library_artifact_versions
    WHERE artifact_id=a.id
    ORDER BY version_number DESC
    LIMIT 1
) latest ON TRUE
LEFT JOIN narthex_library_artifact_media_blobs blob ON blob.artifact_version_id=latest.id AND latest.format='image'
WHERE ($1::timestamptz IS NULL OR a.created_at < $1 OR (a.created_at = $1 AND a.id < $2))
ORDER BY a.created_at DESC,a.id DESC
LIMIT $3`, afterTimestamp, cursor.ID, limit+1)
	if err != nil {
		return LibraryConsoleArtifactPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryConsoleArtifact, 0, limit+1)
	for rows.Next() {
		var item LibraryConsoleArtifact
		var title, summary, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest, createdBy string
		var latestID, latestFormat, latestDigest, latestRedaction, latestMIME *string
		var latestVersion *int
		var latestSize *int64
		var latestReviewedAt, latestCreatedAt *time.Time
		artifact := &item.Artifact
		if err := rows.Scan(
			&artifact.ID, &title, &summary, &artifact.Origin, &artifact.RunID, &artifact.SkillID, &artifact.SkillVersionID, &artifact.BindingID, &artifact.AgentSurfaceID,
			&sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest, &createdBy, &artifact.CreatedAt,
			&latestID, &latestVersion, &latestFormat, &latestDigest, &latestSize, &latestRedaction, &latestReviewedAt, &latestCreatedAt, &latestMIME,
		); err != nil {
			return LibraryConsoleArtifactPage{}, err
		}
		for _, field := range []struct {
			label  string
			stored string
			target *string
		}{
			{"title", title, &artifact.Title}, {"summary", summary, &artifact.Summary}, {"created by", createdBy, &artifact.CreatedBy},
			{"source artifact", sourceArtifactID, &artifact.SourceArtifactID}, {"source artifact version", sourceArtifactVersionID, &artifact.SourceArtifactVersionID},
			{"source artifact digest", sourceArtifactDigest, &artifact.SourceArtifactDigest},
		} {
			if *field.target, err = s.decryptLibraryText("artifact", artifact.ID, field.label, field.stored); err != nil {
				return LibraryConsoleArtifactPage{}, err
			}
		}
		if latestID != nil {
			if latestVersion == nil || latestFormat == nil || latestDigest == nil || latestSize == nil || latestRedaction == nil || latestCreatedAt == nil {
				return LibraryConsoleArtifactPage{}, errors.New("invalid latest library artifact version projection")
			}
			item.LatestVersion = &LibraryConsoleArtifactVersionSummary{
				ID: *latestID, Version: *latestVersion, Format: *latestFormat, Digest: *latestDigest, SizeBytes: *latestSize,
				RedactionStatus: *latestRedaction, CreatedAt: *latestCreatedAt,
			}
			if latestReviewedAt != nil {
				item.LatestVersion.ReviewedAt = *latestReviewedAt
			}
			if latestMIME != nil {
				item.LatestVersion.MIMEType = *latestMIME
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return LibraryConsoleArtifactPage{}, err
	}
	page := LibraryConsoleArtifactPage{Artifacts: items}
	if len(page.Artifacts) > limit {
		last := page.Artifacts[limit-1].Artifact
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.CreatedAt, ID: last.ID}
		page.Artifacts = page.Artifacts[:limit]
	}
	return page, nil
}

// LibraryMCPRootArtifactPage reads only root-list artifact metadata. Body and
// provenance columns remain behind the explicit read-by-ID workflow.
func (s *PgStore) LibraryMCPRootArtifactPage(ctx context.Context, cursor LibraryMCPRootPageCursor, limit int) (LibraryMCPRootArtifactPage, error) {
	if err := validateLibraryMCPRootPageCursor(cursor); err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}
	limit, err := normalizeLibraryMCPRootPageLimit(limit)
	if err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}
	var afterCreatedAt *time.Time
	if !cursor.CreatedAt.IsZero() {
		ts := cursor.CreatedAt.UTC()
		afterCreatedAt = &ts
	}

	rows, err := s.pool.Query(ctx, `
SELECT id,title,summary,origin,created_at
FROM narthex_library_artifacts
WHERE ($1::timestamptz IS NULL OR created_at < $1 OR (created_at = $1 AND id < $2))
ORDER BY created_at DESC,id DESC
LIMIT $3`, afterCreatedAt, cursor.ID, limit+1)
	if err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryMCPRootArtifact, 0, limit+1)
	for rows.Next() {
		var artifact LibraryMCPRootArtifact
		var title, summary string
		if err := rows.Scan(&artifact.ID, &title, &summary, &artifact.Origin, &artifact.CreatedAt); err != nil {
			return LibraryMCPRootArtifactPage{}, err
		}
		if artifact.Title, err = s.decryptLibraryText("artifact", artifact.ID, "title", title); err != nil {
			return LibraryMCPRootArtifactPage{}, err
		}
		if artifact.Summary, err = s.decryptLibraryText("artifact", artifact.ID, "summary", summary); err != nil {
			return LibraryMCPRootArtifactPage{}, err
		}
		items = append(items, artifact)
	}
	if err := rows.Err(); err != nil {
		return LibraryMCPRootArtifactPage{}, err
	}
	page := LibraryMCPRootArtifactPage{Artifacts: items}
	if len(page.Artifacts) > limit {
		last := page.Artifacts[limit-1]
		page.NextCursor = LibraryMCPRootPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
		page.Artifacts = page.Artifacts[:limit]
	}
	return page, nil
}

func (s *PgStore) LibraryArtifact(ctx context.Context, id string) (LibraryArtifact, bool) {
	artifact, err := s.scanLibraryArtifact(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1`, id))
	if err != nil {
		return LibraryArtifact{}, false
	}
	return artifact, true
}

func (s *PgStore) validateLibraryArtifactProvenance(ctx context.Context, artifact LibraryArtifact) error {
	if err := validateLibraryArtifact(artifact); err != nil {
		return err
	}
	if artifact.RunID != "" {
		run, found := s.LibraryRun(ctx, artifact.RunID)
		if !found {
			return ErrLibraryRunNotFound
		}
		if run.Origin != artifact.Origin || (artifact.Origin == LibraryArtifactOriginSkillRun && (run.SkillID != artifact.SkillID || run.SkillVersionID != artifact.SkillVersionID || run.BindingID != artifact.BindingID || (artifact.AgentSurfaceID != "" && (run.Attestation != LibraryRunAttestationHost || run.ActorRef != artifact.CreatedBy || run.SurfaceRef != artifact.AgentSurfaceID)))) || (artifact.Origin == LibraryArtifactOriginAgentDirect && (run.SourceArtifactID != artifact.SourceArtifactID || run.SourceArtifactVersionID != artifact.SourceArtifactVersionID || run.SourceArtifactDigest != artifact.SourceArtifactDigest || (artifact.AgentSurfaceID != "" && (run.ActorRef != artifact.CreatedBy || run.SurfaceRef != artifact.AgentSurfaceID)))) {
			return errors.New("artifact provenance does not match run")
		}
	}
	if err := s.validateLibraryArtifactSource(ctx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return err
	}
	if artifact.Origin == LibraryArtifactOriginSkillRun {
		var versionID, bindingID string
		err := s.pool.QueryRow(ctx, `SELECT id FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, artifact.SkillVersionID, artifact.SkillID).Scan(&versionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLibrarySkillVersionNotFound
		}
		if err != nil {
			return err
		}
		err = s.pool.QueryRow(ctx, `SELECT id FROM narthex_library_skill_bindings WHERE id=$1 AND skill_id=$2`, artifact.BindingID, artifact.SkillID).Scan(&bindingID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLibraryBindingNotFound
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *PgStore) CreateLibraryArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryArtifact, LibraryArtifactVersion, error) {
	if artifact.ID == "" {
		artifact.ID = newLibraryArtifactID()
	}
	if err := s.validateLibraryArtifactProvenance(ctx, artifact); err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	version.ArtifactID, version.Version = artifact.ID, 1
	version.CreatedBy = firstNonEmpty(version.CreatedBy, artifact.CreatedBy)
	normalized, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryArtifactVersionID()
	}
	title, err := s.enc(artifact.Title)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact title: %w", err)
	}
	summary, err := s.enc(artifact.Summary)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact summary: %w", err)
	}
	createdBy, err := s.enc(artifact.CreatedBy)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact created by: %w", err)
	}
	sourceArtifactID, err := s.enc(artifact.SourceArtifactID)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact source artifact: %w", err)
	}
	sourceArtifactVersionID, err := s.enc(artifact.SourceArtifactVersionID)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact source artifact version: %w", err)
	}
	sourceArtifactDigest, err := s.enc(artifact.SourceArtifactDigest)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact source artifact digest: %w", err)
	}
	body, err := s.enc(normalized.Body)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact body: %w", err)
	}
	versionCreatedBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version created by: %w", err)
	}
	reviewedBy, err := s.enc(normalized.ReviewedBy)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version reviewed by: %w", err)
	}
	provenance, err := s.encryptLibraryVersionProvenance(normalized.Changelog, normalized.Provenance)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_artifacts (id,title,summary,origin,run_id,skill_id,skill_version_id,binding_id,agent_surface_id,source_artifact_id,source_artifact_version_id,source_artifact_digest,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, artifact.ID, title, summary, artifact.Origin, artifact.RunID, artifact.SkillID, artifact.SkillVersionID, artifact.BindingID, artifact.AgentSurfaceID, sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest, createdBy, artifact.CreatedAt); err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := tx.Exec(ctx, libraryArtifactVersionInsert, normalized.ID, normalized.ArtifactID, normalized.Version, normalized.Format, body, normalized.Digest, normalized.SizeBytes, normalized.RedactionStatus, versionCreatedBy, reviewedBy, normalized.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID); err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return artifact, normalized, nil
}

// libraryArtifactVersionInsert is the version insert used by every Engine
// write path that records provenance. review_comment starts empty; only the
// review update sets it.
const libraryArtifactVersionInsert = `INSERT INTO narthex_library_artifact_versions (id,artifact_id,version_number,format,body,digest,size_bytes,redaction_status,created_by,reviewed_by,created_at,changelog,origin,generator,model,prompt_digest,draft_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`

// CreateLibraryHumanArtifactWithInitialVersion commits the derived human
// run, artifact, and first version in one transaction. The source citation
// is verified inside that transaction so the run can never name a version
// whose digest changed between the Console check and the write.
func (s *PgStore) CreateLibraryHumanArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	run, artifact, version, err := prepareLibraryHumanArtifact(artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.validateLibraryArtifactSourceTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// validateLibraryArtifactSourceTx is the transactional twin of
// validateLibraryArtifactSource; it key-shares the cited version row so it
// cannot disappear before the citing record commits.
func (s *PgStore) validateLibraryArtifactSourceTx(ctx context.Context, tx pgx.Tx, artifactID, versionID, digest string) error {
	if artifactID == "" {
		return nil
	}
	var foundDigest string
	err := tx.QueryRow(ctx, `SELECT digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, artifactID, versionID).Scan(&foundDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1)`, artifactID).Scan(&exists); lookupErr != nil {
			return lookupErr
		}
		if !exists {
			return ErrLibraryArtifactNotFound
		}
		return ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return err
	}
	if foundDigest != digest {
		return ErrLibraryArtifactVersionNotFound
	}
	return nil
}

// CreateLibraryRootMCPArtifactWithInitialVersion is the PostgreSQL
// counterpart to FileStore's single-save root-MCP direct-artifact operation.
// The source-access decision, run insert, artifact insert, and first-version
// insert share one transaction, so a failed artifact write cannot leave an
// orphaned root-MCP provenance run behind.
func (s *PgStore) CreateLibraryRootMCPArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)

	run, artifact, version, err := prepareLibraryRootMCPArtifact(artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.SourceArtifactID != "" {
		allowed, err := s.libraryRootMCPMayUseArtifactVersionTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest)
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
		}
		if !allowed {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// libraryRootMCPMayUseArtifactVersionTx permits a source citation only for an
// exact immutable version created by the root MCP resource. Root MCP does not
// have a durable subject-bound client registration, so it cannot use grants or
// another client's private artifact.
func (s *PgStore) libraryRootMCPMayUseArtifactVersionTx(ctx context.Context, tx pgx.Tx, artifactID, versionID, digest string) (bool, error) {
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR KEY SHARE`, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, artifactID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if version.Digest != digest || artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.CreatedBy != libraryRootMCPActorRef || artifact.AgentSurfaceID != "" || artifact.RunID == "" {
		return false, nil
	}
	run, err := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, artifact.RunID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return run.Origin == LibraryRunOriginAgentDirect && run.ActorRef == libraryRootMCPActorRef && run.SurfaceRef == libraryRootMCPSurfaceRef, nil
}

// insertLibraryRunArtifactWithInitialVersionTx persists already-derived direct
// provenance in the caller's transaction. It is deliberately kept separate
// from policy checks so root and subject-bound MCP writers can each enforce
// their own source-access rule before the same three immutable records are
// written.
func (s *PgStore) insertLibraryRunArtifactWithInitialVersionTx(ctx context.Context, tx pgx.Tx, run LibraryRun, artifact LibraryArtifact, version LibraryArtifactVersion) error {
	capabilities, err := libraryJSONCapabilities(run.EffectiveCapabilities)
	if err != nil {
		return err
	}
	actorRef, err := s.enc(run.ActorRef)
	if err != nil {
		return fmt.Errorf("encrypt library run actor reference: %w", err)
	}
	surfaceRef, err := s.enc(run.SurfaceRef)
	if err != nil {
		return fmt.Errorf("encrypt library run surface reference: %w", err)
	}
	runSourceArtifactID, err := s.enc(run.SourceArtifactID)
	if err != nil {
		return fmt.Errorf("encrypt library run source artifact: %w", err)
	}
	runSourceArtifactVersionID, err := s.enc(run.SourceArtifactVersionID)
	if err != nil {
		return fmt.Errorf("encrypt library run source artifact version: %w", err)
	}
	runSourceArtifactDigest, err := s.enc(run.SourceArtifactDigest)
	if err != nil {
		return fmt.Errorf("encrypt library run source artifact digest: %w", err)
	}
	title, err := s.enc(artifact.Title)
	if err != nil {
		return fmt.Errorf("encrypt library artifact title: %w", err)
	}
	summary, err := s.enc(artifact.Summary)
	if err != nil {
		return fmt.Errorf("encrypt library artifact summary: %w", err)
	}
	createdBy, err := s.enc(artifact.CreatedBy)
	if err != nil {
		return fmt.Errorf("encrypt library artifact created by: %w", err)
	}
	artifactSourceID, err := s.enc(artifact.SourceArtifactID)
	if err != nil {
		return fmt.Errorf("encrypt library artifact source artifact: %w", err)
	}
	artifactSourceVersionID, err := s.enc(artifact.SourceArtifactVersionID)
	if err != nil {
		return fmt.Errorf("encrypt library artifact source artifact version: %w", err)
	}
	artifactSourceDigest, err := s.enc(artifact.SourceArtifactDigest)
	if err != nil {
		return fmt.Errorf("encrypt library artifact source artifact digest: %w", err)
	}
	body, err := s.enc(version.Body)
	if err != nil {
		return fmt.Errorf("encrypt library artifact body: %w", err)
	}
	versionCreatedBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return fmt.Errorf("encrypt library artifact version created by: %w", err)
	}
	provenance, err := s.encryptLibraryVersionProvenance(version.Changelog, version.Provenance)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_runs (id,origin,attestation,skill_id,skill_version_id,binding_id,actor_ref,surface_ref,effective_capabilities,status,input_digest,output_digest,source_artifact_id,source_artifact_version_id,source_artifact_digest,started_at,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, run.ID, run.Origin, run.Attestation, run.SkillID, run.SkillVersionID, run.BindingID, actorRef, surfaceRef, capabilities, run.Status, run.InputDigest, run.OutputDigest, runSourceArtifactID, runSourceArtifactVersionID, runSourceArtifactDigest, run.StartedAt, run.CompletedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_artifacts (id,title,summary,origin,run_id,skill_id,skill_version_id,binding_id,agent_surface_id,source_artifact_id,source_artifact_version_id,source_artifact_digest,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, artifact.ID, title, summary, artifact.Origin, artifact.RunID, artifact.SkillID, artifact.SkillVersionID, artifact.BindingID, artifact.AgentSurfaceID, artifactSourceID, artifactSourceVersionID, artifactSourceDigest, createdBy, artifact.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, libraryArtifactVersionInsert, version.ID, version.ArtifactID, version.Version, version.Format, body, version.Digest, version.SizeBytes, version.RedactionStatus, versionCreatedBy, "", version.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID); err != nil {
		return err
	}
	return nil
}

// CreateLibraryMCPClientArtifactWithInitialVersion is the PostgreSQL
// counterpart to FileStore's single-save direct-artifact operation. The live
// client check, source authorization, run insert, artifact insert, and first
// version insert share one transaction, so no failed artifact write leaves an
// orphaned subject-bound provenance run behind.
func (s *PgStore) CreateLibraryMCPClientArtifactWithInitialVersion(ctx context.Context, client MCPClient, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)

	var subject string
	var status MCPClientStatus
	err = tx.QueryRow(ctx, `SELECT subject,status FROM narthex_mcp_clients WHERE id=$1 FOR UPDATE`, client.ID).Scan(&subject, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if subject != client.Subject {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientRevoked
	}
	run, artifact, version, err := prepareLibraryMCPClientArtifact(MCPClient{ID: client.ID, Subject: subject}, artifact, version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.SourceArtifactID != "" {
		allowed, err := s.libraryMCPClientMayUseArtifactVersionTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, client.ID, subject)
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
		}
		if !allowed {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
	}

	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// IngestLibraryRuntimeAttestation is the PostgreSQL counterpart of FileStore's
// host-attested write. Locking the client row serializes key/epoch rotation and
// all per-client idempotency decisions. The selected binding/version is then
// re-read under locks before the run, artifact, version, and verifier record
// are committed together.
func (s *PgStore) IngestLibraryRuntimeAttestation(ctx context.Context, attestation LibraryRuntimeAttestation) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, bool, error) {
	// Keep bundle validation and the durable result in one consistency
	// snapshot. The selected skill/binding row locks below reject a concurrent
	// rebind or selected-version change; any serialization failure is safe
	// because the host retries with a fresh current-selection receipt.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	defer tx.Rollback(ctx)
	var client MCPClient
	err = tx.QueryRow(ctx, `
SELECT id,slug,subject,status,epoch,runtime_attestor_public_key
FROM narthex_mcp_clients
WHERE id=$1
FOR UPDATE`, attestation.ClientID).Scan(&client.ID, &client.Slug, &client.Subject, &client.Status, &client.Epoch, &client.RuntimeAttestorPublicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrMCPClientNotFound
	}
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if client.Status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrMCPClientRevoked
	}
	now := time.Now().UTC()
	parsed, err := verifyLibraryRuntimeAttestation(client, attestation, now)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	currentBuiltInVersionID, builtInManifestInstalled, err := s.builtInLibraryCurrentVersionTx(ctx, tx, usingSynaxisSkillID, false)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	selections, err := s.libraryAgentSurfaceSkillSelectionsForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if err := validateLibraryRuntimeAttestationSelection(client, parsed, selections, currentBuiltInVersionID, builtInManifestInstalled); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	executionHash := libraryRuntimeAttestationExecutionHash(client.ID, client.Epoch, parsed.Request.ExecutionID)
	nonceHash := libraryRuntimeAttestationNonceHash(client.ID, client.Epoch, parsed.Request.Nonce)
	var existingRunID, existingDigest string
	err = tx.QueryRow(ctx, `
SELECT run_id,request_digest
FROM narthex_library_runtime_attestations
WHERE client_id=$1 AND client_epoch=$2 AND execution_hash=$3
FOR UPDATE`, client.ID, client.Epoch, executionHash).Scan(&existingRunID, &existingDigest)
	if err == nil {
		if existingDigest != parsed.RequestDigest {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationConflict
		}
		run, err := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, existingRunID))
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
		}
		artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE run_id=$1 AND origin=$2 AND agent_surface_id=$3 FOR KEY SHARE`, run.ID, LibraryArtifactOriginSkillRun, client.ID))
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
		}
		version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND version_number=1 FOR KEY SHARE`, artifact.ID))
		if err != nil || run.Origin != LibraryRunOriginSkillRun || run.Attestation != LibraryRunAttestationHost || run.ActorRef != client.Subject || run.SurfaceRef != client.ID || artifact.CreatedBy != client.Subject {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationInvalid
		}
		if err := tx.Commit(ctx); err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
		}
		return run, artifact, version, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	var reusedRunID string
	err = tx.QueryRow(ctx, `
SELECT run_id
FROM narthex_library_runtime_attestations
WHERE client_id=$1 AND client_epoch=$2 AND nonce_hash=$3
FOR UPDATE`, client.ID, client.Epoch, nonceHash).Scan(&reusedRunID)
	if err == nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, ErrLibraryRuntimeAttestationReplay
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}

	run, artifact, version, err := prepareLibraryRuntimeAttestationOutput(client, parsed, now)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_runtime_attestations (run_id,client_id,client_epoch,execution_hash,nonce_hash,request_digest)
VALUES ($1,$2,$3,$4,$5,$6)`, run.ID, client.ID, client.Epoch, executionHash, nonceHash, parsed.RequestDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, false, err
	}
	return run, artifact, version, false, nil
}

// libraryMCPClientMayUseArtifactVersionTx evaluates direct ownership or a
// pinned live grant under the same transaction used for a derived artifact.
// The grant row is locked so revocation cannot race the authorization decision
// after a client handler's optimistic precheck.
func (s *PgStore) libraryMCPClientMayUseArtifactVersionTx(ctx context.Context, tx pgx.Tx, artifactID, versionID, digest, clientID, subject string) (bool, error) {
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR KEY SHARE`, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, artifactID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if version.Digest != digest {
		return false, nil
	}
	if artifact.Origin == LibraryArtifactOriginAgentDirect && artifact.AgentSurfaceID == clientID && artifact.CreatedBy == subject && artifact.RunID != "" {
		run, err := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, artifact.RunID))
		if err == nil && run.Origin == LibraryRunOriginAgentDirect && run.ActorRef == subject && run.SurfaceRef == clientID {
			return true, nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
	}
	var grantID string
	err = tx.QueryRow(ctx, `SELECT id FROM narthex_library_artifact_grants WHERE artifact_id=$1 AND agent_surface_id=$2 AND artifact_version_id=$3 AND artifact_version_digest=$4 AND revoked_at IS NULL FOR UPDATE`, artifactID, clientID, versionID, digest).Scan(&grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return grantID != "", nil
}

const libraryMCPClientArtifactProjectionColumns = `a.id,a.title,a.summary,a.origin,a.created_at,v.id,v.artifact_id,v.version_number,v.format,v.digest,v.size_bytes,v.redaction_status,v.created_at,selected.access,a.created_by,COALESCE(run.id,''),COALESCE(run.origin,''),COALESCE(run.attestation,''),COALESCE(run.actor_ref,''),COALESCE(run.surface_ref,'')`

func (s *PgStore) scanLibraryMCPClientArtifact(row libraryRowScanner, client MCPClient) (LibraryMCPClientArtifact, error) {
	var artifact LibraryArtifact
	var version LibraryArtifactVersion
	var access string
	var title, summary, artifactCreatedBy, runID, runOrigin, runAttestation, runActorRef, runSurfaceRef string
	if err := row.Scan(
		&artifact.ID, &title, &summary, &artifact.Origin, &artifact.CreatedAt,
		&version.ID, &version.ArtifactID, &version.Version, &version.Format, &version.Digest, &version.SizeBytes, &version.RedactionStatus, &version.CreatedAt, &access,
		&artifactCreatedBy, &runID, &runOrigin, &runAttestation, &runActorRef, &runSurfaceRef,
	); err != nil {
		return LibraryMCPClientArtifact{}, err
	}
	var err error
	if artifact.Title, err = s.decryptLibraryText("artifact", artifact.ID, "title", title); err != nil {
		return LibraryMCPClientArtifact{}, err
	}
	if artifact.Summary, err = s.decryptLibraryText("artifact", artifact.ID, "summary", summary); err != nil {
		return LibraryMCPClientArtifact{}, err
	}
	if access != "owned" && access != "granted" {
		return LibraryMCPClientArtifact{}, errors.New("invalid MCP client artifact access projection")
	}
	if access == "owned" {
		createdBy, err := s.decryptLibraryText("artifact", artifact.ID, "created by", artifactCreatedBy)
		if err != nil {
			return LibraryMCPClientArtifact{}, err
		}
		actorRef, err := s.decryptLibraryText("run", runID, "actor reference", runActorRef)
		if err != nil {
			return LibraryMCPClientArtifact{}, err
		}
		surfaceRef, err := s.decryptLibraryText("run", runID, "surface reference", runSurfaceRef)
		if err != nil {
			return LibraryMCPClientArtifact{}, err
		}
		validOrigin := (artifact.Origin == LibraryArtifactOriginAgentDirect && runOrigin == LibraryRunOriginAgentDirect) ||
			(artifact.Origin == LibraryArtifactOriginSkillRun && runOrigin == LibraryRunOriginSkillRun && runAttestation == LibraryRunAttestationHost)
		if runID == "" || !validOrigin || createdBy != client.Subject || actorRef != client.Subject || surfaceRef != client.ID {
			return LibraryMCPClientArtifact{}, errors.New("invalid MCP client owned artifact provenance")
		}
	}
	return LibraryMCPClientArtifact{Artifact: artifact, Version: version, Access: access}, nil
}

// LibraryMCPClientArtifactPage is a bounded, keyset-paged projection. Its
// query starts at an exact client surface's indexed direct artifacts and live
// grants; it does not fetch every workspace artifact and then authorize each
// one in Go.
func (s *PgStore) LibraryMCPClientArtifactPage(ctx context.Context, client MCPClient, cursor LibraryMCPClientArtifactCursor, limit int) (LibraryMCPClientArtifactPage, error) {
	if err := validateLibraryOpaqueRef("agent surface", client.ID, false); err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}
	if err := validateLibraryOpaqueRef("client subject", client.Subject, false); err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}
	if cursor.CreatedAt.IsZero() != (cursor.ArtifactID == "") {
		return LibraryMCPClientArtifactPage{}, errors.New("invalid artifact page cursor")
	}
	if cursor.ArtifactID != "" {
		if err := validateLibraryOpaqueRef("artifact page cursor", cursor.ArtifactID, false); err != nil {
			return LibraryMCPClientArtifactPage{}, err
		}
	}
	limit, err := normalizeLibraryMCPClientArtifactPageLimit(limit)
	if err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}
	var afterCreatedAt *time.Time
	if !cursor.CreatedAt.IsZero() {
		ts := cursor.CreatedAt.UTC()
		afterCreatedAt = &ts
	}

	rows, err := s.pool.Query(ctx, `
WITH candidates AS (
    SELECT a.id AS artifact_id, latest.id AS artifact_version_id, 'owned'::TEXT AS access, a.created_at
    FROM narthex_library_artifacts a
	JOIN narthex_library_runs run ON run.id=a.run_id
    JOIN LATERAL (
        SELECT id FROM narthex_library_artifact_versions
        WHERE artifact_id=a.id
        ORDER BY version_number DESC
        LIMIT 1
    ) latest ON TRUE
	WHERE a.agent_surface_id=$1 AND (
        (a.origin='agent_direct' AND run.origin='agent_direct') OR
        (a.origin='skill_run' AND run.origin='skill_run' AND run.attestation='host_attested')
    )
    UNION ALL
    SELECT a.id AS artifact_id, v.id AS artifact_version_id, 'granted'::TEXT AS access, a.created_at
    FROM narthex_library_artifact_grants g
    JOIN narthex_library_artifacts a ON a.id=g.artifact_id
    JOIN narthex_library_artifact_versions v ON v.artifact_id=g.artifact_id AND v.id=g.artifact_version_id AND v.digest=g.artifact_version_digest
    WHERE g.agent_surface_id=$1 AND g.revoked_at IS NULL
), selected AS (
    SELECT DISTINCT ON (artifact_id) artifact_id, artifact_version_id, access, created_at
    FROM candidates
    ORDER BY artifact_id, CASE access WHEN 'owned' THEN 0 ELSE 1 END
)
SELECT `+libraryMCPClientArtifactProjectionColumns+`
FROM selected
JOIN narthex_library_artifacts a ON a.id=selected.artifact_id
JOIN narthex_library_artifact_versions v ON v.artifact_id=selected.artifact_id AND v.id=selected.artifact_version_id
JOIN narthex_mcp_clients c ON c.id=$1 AND c.subject=$4 AND c.status='active'
LEFT JOIN narthex_library_runs run ON run.id=a.run_id
WHERE ($2::timestamptz IS NULL OR selected.created_at < $2 OR (selected.created_at = $2 AND selected.artifact_id < $3))
ORDER BY selected.created_at DESC, selected.artifact_id DESC
LIMIT $5`, client.ID, afterCreatedAt, cursor.ArtifactID, client.Subject, limit+1)
	if err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryMCPClientArtifact, 0, limit+1)
	for rows.Next() {
		item, err := s.scanLibraryMCPClientArtifact(rows, client)
		if err != nil {
			return LibraryMCPClientArtifactPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return LibraryMCPClientArtifactPage{}, err
	}
	page := LibraryMCPClientArtifactPage{Artifacts: items}
	if len(page.Artifacts) > limit {
		last := page.Artifacts[limit-1].Artifact
		page.NextCursor = LibraryMCPClientArtifactCursor{CreatedAt: last.CreatedAt, ArtifactID: last.ID}
		page.Artifacts = page.Artifacts[:limit]
	}
	return page, nil
}

func (s *PgStore) LibraryArtifactVersions(ctx context.Context, artifactID string) ([]LibraryArtifactVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 ORDER BY version_number`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []LibraryArtifactVersion
	for rows.Next() {
		version, err := s.scanLibraryArtifactVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (s *PgStore) LibraryArtifactVersion(ctx context.Context, artifactID, id string) (LibraryArtifactVersion, bool) {
	version, err := s.scanLibraryArtifactVersion(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, id))
	if err != nil {
		return LibraryArtifactVersion{}, false
	}
	return version, true
}

func (s *PgStore) CreateLibraryArtifactVersion(ctx context.Context, version LibraryArtifactVersion) (LibraryArtifactVersion, error) {
	normalized, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if normalized.ID == "" {
		normalized.ID = newLibraryArtifactVersionID()
	}
	body, err := s.enc(normalized.Body)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact body: %w", err)
	}
	createdBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version created by: %w", err)
	}
	reviewedBy, err := s.enc(normalized.ReviewedBy)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version reviewed by: %w", err)
	}
	provenance, err := s.encryptLibraryVersionProvenance(normalized.Changelog, normalized.Provenance)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	var artifactID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, normalized.ArtifactID).Scan(&artifactID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
		return LibraryArtifactVersion{}, err
	}
	// The artifact row lock above serializes head reads; a text revision
	// never follows an image head.
	var latestFormat string
	err = tx.QueryRow(ctx, `SELECT format FROM narthex_library_artifact_versions WHERE artifact_id=$1 ORDER BY version_number DESC LIMIT 1`, normalized.ArtifactID).Scan(&latestFormat)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return LibraryArtifactVersion{}, err
	}
	if latestFormat == LibraryArtifactFormatImage {
		return LibraryArtifactVersion{}, ErrLibraryArtifactFormatMismatch
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version_number),0)+1 FROM narthex_library_artifact_versions WHERE artifact_id=$1`, normalized.ArtifactID).Scan(&normalized.Version); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if _, err := tx.Exec(ctx, libraryArtifactVersionInsert, normalized.ID, normalized.ArtifactID, normalized.Version, normalized.Format, body, normalized.Digest, normalized.SizeBytes, normalized.RedactionStatus, createdBy, reviewedBy, normalized.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactVersion{}, err
	}
	return normalized, nil
}

func (s *PgStore) LibraryArtifactGrants(ctx context.Context, artifactID string) ([]LibraryArtifactGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryArtifactGrantColumns+` FROM narthex_library_artifact_grants WHERE artifact_id=$1 ORDER BY created_at`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make([]LibraryArtifactGrant, 0)
	for rows.Next() {
		grant, err := s.scanLibraryArtifactGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *PgStore) ActiveLibraryArtifactGrantsForAgentSurface(ctx context.Context, agentSurfaceID string) ([]LibraryArtifactGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+libraryArtifactGrantColumns+` FROM narthex_library_artifact_grants WHERE agent_surface_id=$1 AND revoked_at IS NULL ORDER BY created_at`, agentSurfaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make([]LibraryArtifactGrant, 0)
	for rows.Next() {
		grant, err := s.scanLibraryArtifactGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *PgStore) ActiveLibraryArtifactGrant(ctx context.Context, artifactID, agentSurfaceID string) (LibraryArtifactGrant, bool) {
	grant, err := s.scanLibraryArtifactGrant(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactGrantColumns+` FROM narthex_library_artifact_grants WHERE artifact_id=$1 AND agent_surface_id=$2 AND revoked_at IS NULL`, artifactID, agentSurfaceID))
	if err != nil {
		return LibraryArtifactGrant{}, false
	}
	return grant, true
}

func (s *PgStore) CreateLibraryArtifactGrant(ctx context.Context, grant LibraryArtifactGrant) (LibraryArtifactGrant, error) {
	if grant.ID == "" {
		grant.ID = newLibraryArtifactGrantID()
	}
	normalized, err := normalizedLibraryArtifactGrant(grant)
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	if !normalized.RevokedAt.IsZero() {
		return LibraryArtifactGrant{}, errors.New("new artifact grant must be live")
	}
	createdBy, err := s.enc(normalized.CreatedBy)
	if err != nil {
		return LibraryArtifactGrant{}, fmt.Errorf("encrypt library artifact grant created by: %w", err)
	}
	revokedBy, err := s.enc("")
	if err != nil {
		return LibraryArtifactGrant{}, fmt.Errorf("encrypt library artifact grant revoked by: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	defer tx.Rollback(ctx)
	var versionDigest string
	err = tx.QueryRow(ctx, `SELECT digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, normalized.ArtifactID, normalized.ArtifactVersionID).Scan(&versionDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		var artifactExists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1)`, normalized.ArtifactID).Scan(&artifactExists); lookupErr != nil {
			return LibraryArtifactGrant{}, lookupErr
		}
		if !artifactExists {
			return LibraryArtifactGrant{}, ErrLibraryArtifactNotFound
		}
		return LibraryArtifactGrant{}, ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	if versionDigest != normalized.ArtifactVersionDigest {
		return LibraryArtifactGrant{}, ErrLibraryArtifactVersionNotFound
	}
	var status MCPClientStatus
	// Take the same parent-row lock used by RevokeMCPClient. A weaker key-share
	// lock permits a concurrent status-only revocation to commit after we read
	// "active" but before we insert the grant. With FOR UPDATE, grant creation
	// and client revocation linearize on this durable registration: a request
	// that observes a revoked client cannot create a new live grant for it.
	err = tx.QueryRow(ctx, `SELECT status FROM narthex_mcp_clients WHERE id=$1 FOR UPDATE`, normalized.AgentSurfaceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryArtifactGrant{}, ErrMCPClientNotFound
	}
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	if status != MCPClientStatusActive {
		return LibraryArtifactGrant{}, ErrMCPClientRevoked
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_artifact_grants (id,artifact_id,artifact_version_id,artifact_version_digest,agent_surface_id,created_by,created_at,revoked_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, normalized.ID, normalized.ArtifactID, normalized.ArtifactVersionID, normalized.ArtifactVersionDigest, normalized.AgentSurfaceID, createdBy, normalized.CreatedAt, revokedBy); err != nil {
		if isUniqueViolation(err) {
			return LibraryArtifactGrant{}, ErrLibraryArtifactGrantExists
		}
		return LibraryArtifactGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactGrant{}, err
	}
	return normalized, nil
}

func (s *PgStore) RevokeLibraryArtifactGrant(ctx context.Context, artifactID, grantID, revokedBy string, revokedAt time.Time) (LibraryArtifactGrant, error) {
	if err := validateLibraryOpaqueRef("revoked by", revokedBy, false); err != nil {
		return LibraryArtifactGrant{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	defer tx.Rollback(ctx)
	grant, err := s.scanLibraryArtifactGrant(tx.QueryRow(ctx, `SELECT `+libraryArtifactGrantColumns+` FROM narthex_library_artifact_grants WHERE artifact_id=$1 AND id=$2 FOR UPDATE`, artifactID, grantID))
	if errors.Is(err, pgx.ErrNoRows) {
		var artifactExists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1)`, artifactID).Scan(&artifactExists); lookupErr != nil {
			return LibraryArtifactGrant{}, lookupErr
		}
		if !artifactExists {
			return LibraryArtifactGrant{}, ErrLibraryArtifactNotFound
		}
		return LibraryArtifactGrant{}, ErrLibraryArtifactGrantNotFound
	}
	if err != nil {
		return LibraryArtifactGrant{}, err
	}
	if !grant.RevokedAt.IsZero() {
		if err := tx.Commit(ctx); err != nil {
			return LibraryArtifactGrant{}, err
		}
		return grant, nil
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	encryptedRevokedBy, err := s.enc(revokedBy)
	if err != nil {
		return LibraryArtifactGrant{}, fmt.Errorf("encrypt library artifact grant revoked by: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_artifact_grants SET revoked_by=$3, revoked_at=$4 WHERE artifact_id=$1 AND id=$2`, artifactID, grantID, encryptedRevokedBy, revokedAt); err != nil {
		return LibraryArtifactGrant{}, err
	}
	grant.RevokedBy, grant.RevokedAt = revokedBy, revokedAt
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactGrant{}, err
	}
	return grant, nil
}

func (s *PgStore) ReviewLibraryArtifactVersion(ctx context.Context, artifactID, versionID, status, reviewedBy string, reviewedAt time.Time) (LibraryArtifactVersion, error) {
	return s.ReviewLibraryArtifactVersionWithComment(ctx, artifactID, versionID, status, reviewedBy, "", reviewedAt)
}

func (s *PgStore) ReviewLibraryArtifactVersionWithComment(ctx context.Context, artifactID, versionID, status, reviewedBy, comment string, reviewedAt time.Time) (LibraryArtifactVersion, error) {
	if status != LibraryRedactionApproved && status != LibraryRedactionRejected {
		return LibraryArtifactVersion{}, errors.New("redaction review status must be approved or rejected")
	}
	if err := validateLibraryOpaqueRef("reviewer", reviewedBy, false); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := validateLibraryReviewComment(comment); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if reviewedAt.IsZero() {
		reviewedAt = time.Now().UTC()
	}
	encryptedReviewedBy, err := s.enc(reviewedBy)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version reviewed by: %w", err)
	}
	encryptedComment, err := s.enc(comment)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt library artifact version review comment: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	var publicationClaimedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT publication_claimed_at FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR UPDATE`, artifactID, versionID).Scan(&publicationClaimedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1)`, artifactID).Scan(&exists); lookupErr != nil {
			return LibraryArtifactVersion{}, lookupErr
		}
		if !exists {
			return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
		return LibraryArtifactVersion{}, ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if publicationClaimedAt != nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactPublicationClaimed
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_artifact_versions SET redaction_status=$3, reviewed_by=$4, reviewed_at=$5, review_comment=$6 WHERE artifact_id=$1 AND id=$2`, artifactID, versionID, status, encryptedReviewedBy, reviewedAt, encryptedComment); err != nil {
		return LibraryArtifactVersion{}, err
	}
	version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID))
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactVersion{}, err
	}
	return version, nil
}

// libraryPublicationCandidateTx reads the artifact and its newest version
// under the artifact-head lock. CreateLibraryArtifactVersion takes the same
// artifact row lock before allocating a version number, and review updates
// lock the selected version row, so this gives the Platform claim endpoint a
// single consistent reviewed-latest observation.
func (s *PgStore) libraryPublicationCandidateTx(ctx context.Context, tx pgx.Tx, artifactID string) (LibraryPublicationCandidate, error) {
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryPublicationCandidate{}, ErrLibraryArtifactNotFound
	}
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 ORDER BY version_number DESC LIMIT 1 FOR UPDATE`, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryPublicationCandidate{}, ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	// Platform's public snapshot contract is deliberately text/Markdown only.
	// Private image blobs must never become public merely because their parent
	// version was reviewed; public-media delivery has its own future boundary.
	if version.Format == LibraryArtifactFormatImage {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationNotReady
	}
	if version.RedactionStatus != LibraryRedactionApproved || version.ReviewedAt.IsZero() {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationNotReady
	}
	candidate := LibraryPublicationCandidate{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, Digest: version.Digest,
		Title: artifact.Title, Summary: artifact.Summary, Format: version.Format, Body: version.Body,
		ArtifactCreatedAt: artifact.CreatedAt, RedactionStatus: version.RedactionStatus, ReviewedAt: version.ReviewedAt,
		Provenance: LibraryPublicationProvenance{Origin: artifact.Origin, RunID: artifact.RunID},
	}
	if artifact.SkillID != "" {
		skill, skillErr := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1`, artifact.SkillID))
		if skillErr == nil {
			candidate.Provenance.SkillName = skill.Name
		} else if !errors.Is(skillErr, pgx.ErrNoRows) {
			return LibraryPublicationCandidate{}, skillErr
		}
		var skillVersion int
		if err := tx.QueryRow(ctx, `SELECT version_number FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, artifact.SkillVersionID, artifact.SkillID).Scan(&skillVersion); err == nil {
			candidate.Provenance.SkillVersion = skillVersion
		}
	}
	return candidate, nil
}

func (s *PgStore) LibraryPublicationCandidate(ctx context.Context, artifactID string) (LibraryPublicationCandidate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	defer tx.Rollback(ctx)
	candidate, err := s.libraryPublicationCandidateTx(ctx, tx, artifactID)
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryPublicationCandidate{}, err
	}
	return candidate, nil
}

// ClaimLibraryPublicationCandidate compares the Platform-observed immutable
// version/digest to the newest reviewed artifact version in the same database
// transaction. The artifact row lock fences concurrent version creation and
// the selected version lock fences a concurrent review decision until the
// claimed snapshot has been projected.
func (s *PgStore) ClaimLibraryPublicationCandidate(ctx context.Context, artifactID, expectedVersionID, expectedDigest string) (LibraryPublicationCandidate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	defer tx.Rollback(ctx)
	candidate, err := s.libraryPublicationCandidateTx(ctx, tx, artifactID)
	if err != nil {
		return LibraryPublicationCandidate{}, err
	}
	if candidate.ArtifactVersionID != expectedVersionID || candidate.Digest != expectedDigest {
		return LibraryPublicationCandidate{}, ErrLibraryPublicationClaimConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_artifact_versions SET publication_claimed_at=COALESCE(publication_claimed_at,$3) WHERE artifact_id=$1 AND id=$2`, artifactID, candidate.ArtifactVersionID, time.Now().UTC()); err != nil {
		return LibraryPublicationCandidate{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryPublicationCandidate{}, err
	}
	return candidate, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
