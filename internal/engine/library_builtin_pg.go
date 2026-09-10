package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ BuiltInLibraryStore = (*PgStore)(nil)
var _ BuiltInLibraryCurrentVersionStore = (*PgStore)(nil)

const libraryBuiltInReconcileLock = "narthex-library-builtins:v1"

func (s *PgStore) BuiltInLibraryCurrentVersion(ctx context.Context, skillID string) (string, bool, error) {
	var versionID string
	err := s.pool.QueryRow(ctx, `
SELECT current_version_id
FROM narthex_library_builtin_current_versions
WHERE skill_id=$1`, skillID).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return versionID, true, nil
}

func (s *PgStore) builtInLibraryCurrentVersionTx(ctx context.Context, tx pgx.Tx, skillID string, forUpdate bool) (string, bool, error) {
	query := `
SELECT current_version_id
FROM narthex_library_builtin_current_versions
WHERE skill_id=$1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var versionID string
	err := tx.QueryRow(ctx, query, skillID).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return versionID, true, nil
}

func lockBuiltInLibraryClientsTx(ctx context.Context, tx pgx.Tx) ([]string, map[string]struct{}, error) {
	clientRows, err := tx.Query(ctx, `SELECT id FROM narthex_mcp_clients ORDER BY id FOR UPDATE`)
	if err != nil {
		return nil, nil, err
	}
	clientIDs := make([]string, 0)
	clientSet := make(map[string]struct{})
	for clientRows.Next() {
		var clientID string
		if err := clientRows.Scan(&clientID); err != nil {
			clientRows.Close()
			return nil, nil, err
		}
		clientIDs = append(clientIDs, clientID)
		clientSet[clientID] = struct{}{}
	}
	if err := clientRows.Err(); err != nil {
		clientRows.Close()
		return nil, nil, err
	}
	clientRows.Close()
	return clientIDs, clientSet, nil
}

// ReconcileBuiltInLibrary serializes the client registry and code-owned
// manifest in the same lock order used by client creation. Every existing
// durable client receives its exact pin before this transaction commits.
func (s *PgStore) ReconcileBuiltInLibrary(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	definition := usingSynaxisDefinition()
	if err := definition.validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, libraryBuiltInReconcileLock); err != nil {
		return err
	}
	if err := s.reconcileBuiltInLibraryDefinitionTx(ctx, tx, definition); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PgStore) reconcileBuiltInLibraryDefinitionTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition) error {
	if err := definition.validate(); err != nil {
		return err
	}
	// Runtime attestation and authoring paths lock their durable client before
	// any selected skill. Lock every client first here as well; holding a skill
	// while waiting for a client would create a client<->skill deadlock cycle.
	clientIDs, clientSet, err := lockBuiltInLibraryClientsTx(ctx, tx)
	if err != nil {
		return err
	}
	persistedCurrentVersionID, markerFound, err := s.builtInLibraryCurrentVersionTx(ctx, tx, definition.SkillID, true)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	managedVersions, err := s.reconcileBuiltInLibraryManifestTx(ctx, tx, definition, now)
	if err != nil {
		return err
	}
	persistedBindings, err := s.validateBuiltInLibraryBindingsTx(ctx, tx, definition, clientSet, managedVersions)
	if err != nil {
		return err
	}
	_ = persistedBindings
	if markerFound {
		if _, valid := managedVersions[persistedCurrentVersionID]; !valid {
			return fmt.Errorf("%w: authoritative built-in version is invalid", ErrLibraryBuiltInConflict)
		}
		if persistedCurrentVersionID != definition.CurrentVersionID {
			if _, err := tx.Exec(ctx, `
UPDATE narthex_library_builtin_current_versions
SET current_version_id=$2,updated_at=$3
WHERE skill_id=$1`, definition.SkillID, definition.CurrentVersionID, now); err != nil {
				return err
			}
		}
	} else {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_builtin_current_versions (skill_id,current_version_id,updated_at)
VALUES ($1,$2,$3)`, definition.SkillID, definition.CurrentVersionID, now); err != nil {
			return err
		}
	}
	for _, clientID := range clientIDs {
		if err := s.reconcileBuiltInLibraryBindingTx(ctx, tx, definition, clientID, definition.CurrentVersionID, now); err != nil {
			return err
		}
	}
	return nil
}

// reconcileBuiltInLibraryManifestTx validates or installs only the reserved
// skill and its immutable version lineage. Callers establish their client-row
// lock scope before entering this skill->version lock order.
func (s *PgStore) reconcileBuiltInLibraryManifestTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition, now time.Time) (map[string]LibrarySkillVersion, error) {
	rows, err := tx.Query(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 OR slug=$2 ORDER BY id FOR UPDATE`, definition.SkillID, definition.Slug)
	if err != nil {
		return nil, err
	}
	var skills []LibrarySkill
	for rows.Next() {
		skill, scanErr := s.scanLibrarySkill(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		skills = append(skills, skill)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(skills) > 1 || (len(skills) == 1 && !builtInSkillMatches(skills[0], definition)) {
		return nil, fmt.Errorf("%w: reserved skill identity or metadata", ErrLibraryBuiltInConflict)
	}
	if len(skills) == 0 {
		name, err := s.enc(definition.Name)
		if err != nil {
			return nil, fmt.Errorf("encrypt built-in library skill name: %w", err)
		}
		description, err := s.enc(definition.Description)
		if err != nil {
			return nil, fmt.Errorf("encrypt built-in library skill description: %w", err)
		}
		createdBy, err := s.enc(definition.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("encrypt built-in library skill creator: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skills (id,slug,name,description,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`,
			definition.SkillID, definition.Slug, name, description, createdBy, now); err != nil {
			return nil, fmt.Errorf("insert built-in library skill: %w", err)
		}
	}

	versionInserted := false
	for _, candidate := range definition.Versions {
		rows, err = tx.Query(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE id=$1 OR (skill_id=$2 AND version_number=$3) ORDER BY id FOR UPDATE`, candidate.VersionID, definition.SkillID, candidate.Revision)
		if err != nil {
			return nil, err
		}
		var versions []LibrarySkillVersion
		for rows.Next() {
			version, scanErr := s.scanLibrarySkillVersion(rows)
			if scanErr != nil {
				rows.Close()
				return nil, scanErr
			}
			versions = append(versions, version)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		if len(versions) > 1 || (len(versions) == 1 && !builtInVersionMatches(versions[0], definition, candidate)) {
			return nil, fmt.Errorf("%w: reserved skill version identity or digest", ErrLibraryBuiltInConflict)
		}
		if len(versions) != 0 {
			continue
		}
		content, err := s.enc(candidate.Content)
		if err != nil {
			return nil, fmt.Errorf("encrypt built-in library skill content: %w", err)
		}
		createdBy, err := s.enc(definition.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("encrypt built-in library skill version creator: %w", err)
		}
		capabilities, err := libraryJSONCapabilities([]string{})
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_versions (id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			candidate.VersionID, definition.SkillID, candidate.Revision, content, candidate.ContentDigest, capabilities, createdBy, now); err != nil {
			return nil, fmt.Errorf("insert built-in library skill version: %w", err)
		}
		versionInserted = true
	}
	if versionInserted {
		if _, err := tx.Exec(ctx, `UPDATE narthex_library_skills SET updated_at=$2 WHERE id=$1`, definition.SkillID, now); err != nil {
			return nil, err
		}
	}

	return s.validateBuiltInLibraryVersionsTx(ctx, tx, definition)
}

func (s *PgStore) validateBuiltInLibraryVersionsTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition) (map[string]LibrarySkillVersion, error) {
	rows, err := tx.Query(ctx, `SELECT `+librarySkillVersionColumns+`
FROM narthex_library_skill_versions
WHERE skill_id=$1 OR left(id,length($2::text))=$2::text
ORDER BY skill_id,version_number,id
FOR UPDATE`, definition.SkillID, definition.VersionIDPrefix)
	if err != nil {
		return nil, err
	}
	persistedVersions := make([]LibrarySkillVersion, 0, len(definition.Versions))
	for rows.Next() {
		version, scanErr := s.scanLibrarySkillVersion(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		persistedVersions = append(persistedVersions, version)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return validateBuiltInPersistedVersions(definition, persistedVersions)
}

func (s *PgStore) validateInstalledBuiltInLibraryManifestTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition) (map[string]LibrarySkillVersion, error) {
	rows, err := tx.Query(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 OR slug=$2 ORDER BY id FOR UPDATE`, definition.SkillID, definition.Slug)
	if err != nil {
		return nil, err
	}
	var skills []LibrarySkill
	for rows.Next() {
		skill, scanErr := s.scanLibrarySkill(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		skills = append(skills, skill)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(skills) != 1 || !builtInSkillMatches(skills[0], definition) {
		return nil, fmt.Errorf("%w: installed built-in skill identity or metadata", ErrLibraryBuiltInConflict)
	}
	return s.validateBuiltInLibraryVersionsTx(ctx, tx, definition)
}

func (s *PgStore) validateBuiltInLibraryBindingsTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition, clientSet map[string]struct{}, managedVersions map[string]LibrarySkillVersion) ([]LibrarySkillBinding, error) {
	rows, err := tx.Query(ctx, `SELECT `+libraryBindingColumns+`
FROM narthex_library_skill_bindings
WHERE skill_id=$1 OR left(id,length($2::text))=$2::text
ORDER BY skill_id,scope_kind,scope_id,id
FOR UPDATE`, definition.SkillID, usingSynaxisBindingIDPrefix)
	if err != nil {
		return nil, err
	}
	persistedBindings := make([]LibrarySkillBinding, 0, len(clientSet))
	for rows.Next() {
		binding, scanErr := s.scanLibrarySkillBinding(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		persistedBindings = append(persistedBindings, binding)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if err := validateBuiltInPersistedBindings(definition, clientSet, managedVersions, persistedBindings); err != nil {
		return nil, err
	}
	return persistedBindings, nil
}

func (s *PgStore) reconcileBuiltInLibraryBindingTx(ctx context.Context, tx pgx.Tx, definition builtInLibrarySkillDefinition, clientID, targetVersionID string, now time.Time) error {
	expectedID := usingSynaxisBindingID(clientID)
	rows, err := tx.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE id=$1 OR (skill_id=$2 AND scope_kind=$3 AND scope_id=$4) ORDER BY id FOR UPDATE`,
		expectedID, definition.SkillID, LibraryScopeAgentSurface, clientID)
	if err != nil {
		return err
	}
	var bindings []LibrarySkillBinding
	for rows.Next() {
		binding, scanErr := s.scanLibrarySkillBinding(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(bindings) > 1 || (len(bindings) == 1 && !builtInBindingShapeMatches(bindings[0], definition, clientID)) {
		return fmt.Errorf("%w: reserved binding for agent surface %q", ErrLibraryBuiltInConflict, clientID)
	}
	if len(bindings) == 0 {
		binding := definition.binding(clientID, now)
		binding.PinnedVersionID = targetVersionID
		capabilities, err := libraryJSONCapabilities(binding.CapabilityCeiling)
		if err != nil {
			return err
		}
		createdBy, err := s.enc(binding.CreatedBy)
		if err != nil {
			return fmt.Errorf("encrypt built-in library binding creator: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_skill_bindings (id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`,
			binding.ID, binding.SkillID, binding.ScopeKind, binding.ScopeID, binding.Mode, binding.PinnedVersionID,
			capabilities, binding.Priority, createdBy, binding.CreatedAt); err != nil {
			return fmt.Errorf("insert built-in library binding: %w", err)
		}
		_, err = s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, definition.SkillID)
		return err
	}

	binding := bindings[0]
	pinned, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2 FOR SHARE`, definition.SkillID, binding.PinnedVersionID))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !builtInPersistedVersionMayBePinned(pinned, definition)) {
		return fmt.Errorf("%w: reserved binding has an invalid pinned version", ErrLibraryBuiltInConflict)
	}
	if err != nil {
		return err
	}
	if binding.PinnedVersionID != targetVersionID {
		if _, err := tx.Exec(ctx, `UPDATE narthex_library_skill_bindings SET pinned_version_id=$2,updated_at=$3 WHERE id=$1`, binding.ID, targetVersionID, now); err != nil {
			return err
		}
		_, err = s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, definition.SkillID)
		return err
	}
	_, err = s.ensureLibrarySkillBindingGenerationForUpdateTx(ctx, tx, definition.SkillID)
	return err
}

// reconcileInstalledBuiltInLibraryForNewClientTx preserves compatibility for
// bare store fixtures: client creation only acquires the new invariant after
// startup has installed the reserved manifest. In production the enclosing
// registry transaction therefore commits the client and binding together.
func (s *PgStore) reconcileInstalledBuiltInLibraryForNewClientTx(ctx context.Context, tx pgx.Tx, clientID string) error {
	return s.reconcileInstalledBuiltInLibraryForNewClientDefinitionTx(ctx, tx, clientID, usingSynaxisDefinition())
}

func (s *PgStore) reconcileInstalledBuiltInLibraryForNewClientDefinitionTx(ctx context.Context, tx pgx.Tx, clientID string, definition builtInLibrarySkillDefinition) error {
	if err := definition.validate(); err != nil {
		return err
	}
	var skillExists, markerExists bool
	if err := tx.QueryRow(ctx, `
SELECT
    EXISTS(SELECT 1 FROM narthex_library_skills WHERE id=$1),
    EXISTS(SELECT 1 FROM narthex_library_builtin_current_versions WHERE skill_id=$1)`, definition.SkillID).Scan(&skillExists, &markerExists); err != nil {
		return err
	}
	if !skillExists && !markerExists {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, libraryBuiltInReconcileLock); err != nil {
		return err
	}
	clientIDs, clientSet, err := lockBuiltInLibraryClientsTx(ctx, tx)
	if err != nil {
		return err
	}
	if _, found := clientSet[clientID]; !found {
		return fmt.Errorf("%w: new durable client is absent during built-in reconciliation", ErrLibraryBuiltInConflict)
	}
	currentVersionID, markerFound, err := s.builtInLibraryCurrentVersionTx(ctx, tx, definition.SkillID, true)
	if err != nil {
		return err
	}
	if !markerFound {
		return fmt.Errorf("%w: installed built-in skill has no authoritative version", ErrLibraryBuiltInConflict)
	}
	managedVersions, err := s.validateInstalledBuiltInLibraryManifestTx(ctx, tx, definition)
	if err != nil {
		return err
	}
	persistedBindings, err := s.validateBuiltInLibraryBindingsTx(ctx, tx, definition, clientSet, managedVersions)
	if err != nil {
		return err
	}
	currentVersion, persisted := managedVersions[currentVersionID]
	if !persisted || !builtInPersistedVersionMayBePinned(currentVersion, definition) {
		return fmt.Errorf("%w: authoritative built-in version is invalid", ErrLibraryBuiltInConflict)
	}
	for _, binding := range persistedBindings {
		if binding.SkillID == definition.SkillID && binding.PinnedVersionID != currentVersionID {
			return fmt.Errorf("%w: managed binding diverges from the authoritative version", ErrLibraryBuiltInConflict)
		}
	}
	now := time.Now().UTC()
	for _, durableClientID := range clientIDs {
		if err := s.reconcileBuiltInLibraryBindingTx(ctx, tx, definition, durableClientID, currentVersionID, now); err != nil {
			return err
		}
	}
	return nil
}
