package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Run correlations store what the Engine observed a signed host claim, keyed
// on the (client, epoch, run, request) tuple. Only scoped hashes of the
// host-chosen execution ID and nonce are kept; the signature and raw body are
// never written. The client FK is RESTRICT so an observation can never
// outlive the registration it names without an explicit decision.
const libraryRunCorrelationsSchema = `
CREATE TABLE IF NOT EXISTS narthex_library_run_correlations (
    id                 TEXT PRIMARY KEY,
    client_id          TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch       TEXT NOT NULL,
    run_id             TEXT NOT NULL,
    gateway_request_id TEXT NOT NULL,
    execution_hash     TEXT NOT NULL DEFAULT '',
    nonce_hash         TEXT NOT NULL,
    bundle_digest      TEXT NOT NULL,
    request_digest     TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_run_correlations_execution_hash_check CHECK (execution_hash = '' OR execution_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_run_correlations_nonce_hash_check CHECK (nonce_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_run_correlations_bundle_digest_check CHECK (bundle_digest ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_run_correlations_request_digest_check CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_run_correlations_tuple_unique UNIQUE (client_id, client_epoch, run_id, gateway_request_id),
    CONSTRAINT narthex_library_run_correlations_nonce_unique UNIQUE (client_id, client_epoch, nonce_hash)
);
CREATE INDEX IF NOT EXISTS narthex_library_run_correlations_created_idx
    ON narthex_library_run_correlations (created_at DESC, id DESC);`

var _ LibraryRunCorrelationStore = (*PgStore)(nil)

const libraryRunCorrelationColumns = `id,client_id,client_epoch,run_id,gateway_request_id,execution_hash,nonce_hash,bundle_digest,request_digest,created_at`

func scanLibraryRunCorrelation(row pgx.Row) (LibraryRunCorrelation, error) {
	var record LibraryRunCorrelation
	if err := row.Scan(
		&record.ID, &record.ClientID, &record.ClientEpoch, &record.RunID, &record.GatewayRequestID,
		&record.ExecutionHash, &record.NonceHash, &record.BundleDigest, &record.RequestDigest, &record.CreatedAt,
	); err != nil {
		return LibraryRunCorrelation{}, err
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

// RecordLibraryRunCorrelation locks the client row so epoch/key rotation and
// every per-client idempotency decision serialize, then resolves the current
// selection under the same skill locks the attestation path uses before it
// compares the claimed bundle digest.
func (s *PgStore) RecordLibraryRunCorrelation(ctx context.Context, client MCPClient, raw []byte, now time.Time) (LibraryRunCorrelation, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	defer tx.Rollback(ctx)
	current, err := loadMCPClientForUpdate(ctx, tx, client.ID)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	currentBuiltInVersionID, builtInManifestInstalled, err := s.builtInLibraryCurrentVersionTx(ctx, tx, usingSynaxisSkillID, false)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	selections, err := s.libraryAgentSurfaceSkillSelectionsForUpdateTx(ctx, tx, current.ID)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	parsed, err := verifyLibraryRunCorrelationForClient(current, raw, now, selections, currentBuiltInVersionID, builtInManifestInstalled)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	existing, err := scanLibraryRunCorrelation(tx.QueryRow(ctx, `
SELECT `+libraryRunCorrelationColumns+`
FROM narthex_library_run_correlations
WHERE client_id=$1 AND client_epoch=$2 AND run_id=$3 AND gateway_request_id=$4
FOR UPDATE`, current.ID, current.Epoch, parsed.Request.RunID, parsed.Request.GatewayRequestID))
	if err == nil {
		if existing.RequestDigest != parsed.RequestDigest {
			return LibraryRunCorrelation{}, false, ErrLibraryRunCorrelationConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return LibraryRunCorrelation{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LibraryRunCorrelation{}, false, err
	}
	record := newLibraryRunCorrelationRecord(current, parsed, now)
	var nonceReused bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1 FROM narthex_library_run_correlations
    WHERE client_id=$1 AND client_epoch=$2 AND nonce_hash=$3
)`, current.ID, current.Epoch, record.NonceHash).Scan(&nonceReused); err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	if nonceReused {
		return LibraryRunCorrelation{}, false, ErrLibraryRunCorrelationReplay
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_run_correlations (`+libraryRunCorrelationColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		record.ID, record.ClientID, record.ClientEpoch, record.RunID, record.GatewayRequestID,
		record.ExecutionHash, record.NonceHash, record.BundleDigest, record.RequestDigest, record.CreatedAt); err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	return record, false, nil
}

func (s *PgStore) LibraryRunCorrelations(ctx context.Context, cursor LibraryRunCorrelationCursor, limit int) ([]LibraryRunCorrelation, error) {
	if limit <= 0 {
		return []LibraryRunCorrelation{}, nil
	}
	var (
		cursorAt *time.Time
		cursorID string
	)
	if cursor.ID != "" || !cursor.CreatedAt.IsZero() {
		at := cursor.CreatedAt.UTC()
		cursorAt = &at
		cursorID = cursor.ID
	}
	rows, err := s.pool.Query(ctx, `
SELECT `+libraryRunCorrelationColumns+`
FROM narthex_library_run_correlations
WHERE $1::timestamptz IS NULL OR (created_at, id) < ($1::timestamptz, $2::text)
ORDER BY created_at DESC, id DESC
LIMIT $3`, cursorAt, cursorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LibraryRunCorrelation, 0)
	for rows.Next() {
		record, err := scanLibraryRunCorrelation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}
