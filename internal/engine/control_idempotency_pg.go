package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// The idempotency table stores the first completed result of a keyed control
// mutation. Bodies are the same DTOs the caller received; the table never
// holds a credential, epoch, or OAuth identity.
const controlIdempotencySchema = `
CREATE TABLE IF NOT EXISTS narthex_control_idempotency (
    idempotency_key TEXT NOT NULL,
    resource_path   TEXT NOT NULL,
    actor_ref       TEXT NOT NULL DEFAULT '',
    body_digest     TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body   BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (idempotency_key, resource_path),
    CONSTRAINT narthex_control_idempotency_body_digest_check CHECK (body_digest ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_control_idempotency_status_check CHECK (response_status BETWEEN 200 AND 299),
    CONSTRAINT narthex_control_idempotency_expiry_check CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS narthex_control_idempotency_expires_idx
    ON narthex_control_idempotency (expires_at);`

var _ ControlIdempotencyStore = (*PgStore)(nil)

func scanControlIdempotencyRecord(row pgx.Row) (ControlIdempotencyRecord, error) {
	var record ControlIdempotencyRecord
	if err := row.Scan(
		&record.Key, &record.ResourcePath, &record.ActorRef, &record.BodyDigest,
		&record.Status, &record.Body, &record.CreatedAt, &record.ExpiresAt,
	); err != nil {
		return ControlIdempotencyRecord{}, err
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.ExpiresAt = record.ExpiresAt.UTC()
	return record, nil
}

const controlIdempotencyColumns = `idempotency_key,resource_path,actor_ref,body_digest,response_status,response_body,created_at,expires_at`

func (s *PgStore) ControlIdempotencyRecord(ctx context.Context, key, resourcePath string, now time.Time) (ControlIdempotencyRecord, bool, error) {
	record, err := scanControlIdempotencyRecord(s.pool.QueryRow(ctx, `
SELECT `+controlIdempotencyColumns+`
FROM narthex_control_idempotency
WHERE idempotency_key=$1 AND resource_path=$2 AND expires_at > $3`, key, resourcePath, now.UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlIdempotencyRecord{}, false, nil
	}
	if err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	return record, true, nil
}

func (s *PgStore) StoreControlIdempotencyRecord(ctx context.Context, record ControlIdempotencyRecord) (ControlIdempotencyRecord, bool, error) {
	if !validControlIdempotencyRecord(record) {
		return ControlIdempotencyRecord{}, false, ErrInvalidControlIdempotencyRecord
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	// Expired identities may be reused: prune before the insert so a stale row
	// under the same key cannot shadow a fresh mutation for another day.
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_control_idempotency WHERE expires_at <= $1`, record.CreatedAt.UTC()); err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO narthex_control_idempotency
    (`+controlIdempotencyColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (idempotency_key, resource_path) DO NOTHING`,
		record.Key, record.ResourcePath, record.ActorRef, record.BodyDigest,
		record.Status, record.Body, record.CreatedAt.UTC(), record.ExpiresAt.UTC())
	if err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	stored := tag.RowsAffected() == 1
	winner, err := scanControlIdempotencyRecord(tx.QueryRow(ctx, `
SELECT `+controlIdempotencyColumns+`
FROM narthex_control_idempotency
WHERE idempotency_key=$1 AND resource_path=$2`, record.Key, record.ResourcePath))
	if err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ControlIdempotencyRecord{}, false, err
	}
	return winner, stored, nil
}
