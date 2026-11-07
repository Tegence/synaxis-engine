package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var _ LibraryArtifactEraser = (*PgStore)(nil)

// libraryArtifactTombstonesSchema keeps the minimum an idempotent erasure
// needs: the artifact ID and when it was erased. No title, body or actor.
const libraryArtifactTombstonesSchema = `
CREATE TABLE IF NOT EXISTS narthex_library_artifact_tombstones (
    artifact_id TEXT PRIMARY KEY,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// DeleteLibraryArtifact erases one artifact in one transaction, children
// first because the Library references are ON DELETE RESTRICT: revision
// receipts, chat-save records in either direction, exact-version grants,
// private media blobs, collaboration state, versions, the artifact, and the
// producing run when no other artifact or runtime attestation still names it.
// The artifact row is locked first, so a concurrent version, grant, save or
// collaboration write either commits before the erasure or finds nothing.
func (s *PgStore) DeleteLibraryArtifact(ctx context.Context, id string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var runID string
	err = tx.QueryRow(ctx, `SELECT run_id FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, id).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		var deleted bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM narthex_library_artifact_tombstones WHERE artifact_id=$1)`, id).Scan(&deleted); err != nil {
			return false, err
		}
		return deleted, nil
	}
	if err != nil {
		return false, err
	}
	for _, statement := range []string{
		`DELETE FROM narthex_library_mcp_client_artifact_version_requests WHERE artifact_id=$1`,
		`DELETE FROM narthex_library_chat_saves WHERE source_artifact_id=$1 OR artifact_id=$1`,
		`DELETE FROM narthex_library_artifact_grants WHERE artifact_id=$1`,
		`DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id IN (SELECT id FROM narthex_library_artifact_versions WHERE artifact_id=$1)`,
		`DELETE FROM narthex_library_collaboration_principals WHERE artifact_id=$1`,
		`DELETE FROM narthex_library_collaborations WHERE artifact_id=$1`,
		`DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`,
		`DELETE FROM narthex_library_artifacts WHERE id=$1`,
		`INSERT INTO narthex_library_artifact_tombstones (artifact_id) VALUES ($1) ON CONFLICT (artifact_id) DO NOTHING`,
	} {
		if _, err := tx.Exec(ctx, statement, id); err != nil {
			return true, err
		}
	}
	if runID != "" {
		if _, err := tx.Exec(ctx, `
DELETE FROM narthex_library_runs
WHERE id=$1
  AND NOT EXISTS (SELECT 1 FROM narthex_library_artifacts WHERE run_id=$1)
  AND NOT EXISTS (SELECT 1 FROM narthex_library_runtime_attestations WHERE run_id=$1)`, runID); err != nil {
			return true, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return true, err
	}
	return true, nil
}
