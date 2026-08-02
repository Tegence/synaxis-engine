package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const usageSchema = `
CREATE TABLE IF NOT EXISTS narthex_usage_periods (
    period_start         TIMESTAMPTZ PRIMARY KEY,
    period_end           TIMESTAMPTZ NOT NULL,
    workspace_id         TEXT NOT NULL,
    engine_generation    BIGINT NOT NULL,
    revision             BIGINT NOT NULL,
    plan_id              TEXT NOT NULL,
    status               TEXT NOT NULL,
    calls_limit          BIGINT NOT NULL,
    runtime_seconds_limit BIGINT NOT NULL,
    transfer_bytes_limit BIGINT NOT NULL,
    concurrency_limit    BIGINT NOT NULL,
    rate_per_minute      BIGINT NOT NULL,
    burst_limit          BIGINT NOT NULL,
    max_call_seconds     BIGINT NOT NULL,
    grant_issued_at      TIMESTAMPTZ NOT NULL,
    grant_expires_at     TIMESTAMPTZ NOT NULL,
    grant_digest         TEXT NOT NULL,
    calls_used           BIGINT NOT NULL DEFAULT 0,
    runtime_milliseconds BIGINT NOT NULL DEFAULT 0,
    transfer_bytes_used  BIGINT NOT NULL DEFAULT 0,
    rate_tokens          DOUBLE PRECISION NOT NULL,
    rate_updated_at      TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (period_end > period_start),
    CHECK (calls_used >= 0),
    CHECK (runtime_milliseconds >= 0),
    CHECK (transfer_bytes_used >= 0)
);

CREATE TABLE IF NOT EXISTS narthex_usage_reservations (
    id               TEXT PRIMARY KEY,
    period_start     TIMESTAMPTZ NOT NULL REFERENCES narthex_usage_periods(period_start),
    admitted_at      TIMESTAMPTZ NOT NULL,
    settled_at       TIMESTAMPTZ,
    runtime_milliseconds BIGINT NOT NULL DEFAULT 0,
    transfer_bytes   BIGINT NOT NULL DEFAULT 0,
    account          TEXT NOT NULL DEFAULT '',
    tool             TEXT NOT NULL DEFAULT '',
    connector        TEXT NOT NULL DEFAULT '',
    replay           BOOLEAN NOT NULL DEFAULT false,
    max_call_seconds BIGINT NOT NULL,
    settlement       TEXT NOT NULL DEFAULT '',
    CHECK (runtime_milliseconds >= 0),
    CHECK (transfer_bytes >= 0)
);

CREATE INDEX IF NOT EXISTS narthex_usage_reservations_open_idx
ON narthex_usage_reservations (period_start, admitted_at)
WHERE settled_at IS NULL;
`

const usageMigrate = `
ALTER TABLE narthex_usage_reservations
    ADD COLUMN IF NOT EXISTS max_call_seconds BIGINT NOT NULL DEFAULT 120;
ALTER TABLE narthex_usage_reservations
    ALTER COLUMN max_call_seconds DROP DEFAULT;
`

const usagePeriodSelectColumns = `
period_start,period_end,workspace_id,engine_generation,revision,plan_id,status,
calls_limit,runtime_seconds_limit,transfer_bytes_limit,concurrency_limit,
rate_per_minute,burst_limit,max_call_seconds,grant_issued_at,grant_expires_at,
grant_digest,calls_used,runtime_milliseconds,transfer_bytes_used,updated_at`

type rowScanner interface {
	Scan(...any) error
}

func scanUsagePeriod(row rowScanner) (UsagePeriod, error) {
	var period UsagePeriod
	err := row.Scan(
		&period.Grant.PeriodStart,
		&period.Grant.PeriodEnd,
		&period.Grant.Identity.WorkspaceID,
		&period.Grant.Identity.EngineGeneration,
		&period.Grant.Revision,
		&period.Grant.PlanID,
		&period.Grant.Status,
		&period.Grant.Limits.Calls,
		&period.Grant.Limits.RuntimeSeconds,
		&period.Grant.Limits.TransferBytes,
		&period.Grant.Limits.Concurrency,
		&period.Grant.Limits.RatePerMinute,
		&period.Grant.Limits.Burst,
		&period.Grant.Limits.MaxCallSeconds,
		&period.Grant.IssuedAt,
		&period.Grant.ExpiresAt,
		&period.Grant.Digest,
		&period.CallsUsed,
		&period.RuntimeMilliseconds,
		&period.TransferBytesUsed,
		&period.UpdatedAt,
	)
	return period, err
}

func (s *PgStore) ApplyUsageGrant(ctx context.Context, grant UsageGrant) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Different period starts do not share a row lock. Serialize the rare
	// control-plane grant writes so two concurrent inserts cannot both pass
	// the overlap check and create intersecting billing periods.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('narthex_usage_grant'))`,
	); err != nil {
		return err
	}

	existing, err := scanUsagePeriod(tx.QueryRow(ctx,
		`SELECT `+usagePeriodSelectColumns+`
FROM narthex_usage_periods WHERE period_start=$1 FOR UPDATE`, grant.PeriodStart))
	switch {
	case err == nil:
		if existing.Grant.Identity.WorkspaceID != grant.Identity.WorkspaceID {
			return errors.New("usage period belongs to a different workspace")
		}
		if existing.Grant.Identity.EngineGeneration > grant.Identity.EngineGeneration {
			return errors.New("usage grant generation is older than the stored generation")
		}
		if grant.Revision == existing.Grant.Revision {
			if !sameUsageGrantPolicy(existing.Grant, grant) {
				return errors.New("usage grant revision was already used by a different allowance")
			}
			// Platform refreshes a short-lived signature for the same durable
			// entitlement revision. Accept a newer assertion without resetting
			// tokens or counters; never let an older retry shorten validity.
			if !grant.IssuedAt.After(existing.Grant.IssuedAt) ||
				!grant.ExpiresAt.After(existing.Grant.ExpiresAt) {
				return tx.Commit(ctx)
			}
			if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_periods
SET grant_issued_at=$2,grant_expires_at=$3,grant_digest=$4,updated_at=now()
WHERE period_start=$1`,
				grant.PeriodStart, grant.IssuedAt, grant.ExpiresAt, grant.Digest,
			); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
		if grant.Revision < existing.Grant.Revision {
			return errors.New("usage grant revision is stale")
		}
		var overlap bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM narthex_usage_periods
    WHERE period_start <> $1
      AND period_start < $2
      AND period_end > $1
)`, grant.PeriodStart, grant.PeriodEnd).Scan(&overlap); err != nil {
			return err
		}
		if overlap {
			return errors.New("usage grant overlaps an existing billing period")
		}
		if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_periods SET
    period_end=$2,workspace_id=$3,engine_generation=$4,revision=$5,plan_id=$6,status=$7,
    calls_limit=$8,runtime_seconds_limit=$9,transfer_bytes_limit=$10,
    concurrency_limit=$11,rate_per_minute=$12,burst_limit=$13::bigint,max_call_seconds=$14,
    grant_issued_at=$15,grant_expires_at=$16,grant_digest=$17,
    rate_tokens=LEAST(rate_tokens,$13::double precision),updated_at=now()
WHERE period_start=$1`,
			grant.PeriodStart, grant.PeriodEnd, grant.Identity.WorkspaceID,
			grant.Identity.EngineGeneration, grant.Revision, grant.PlanID, grant.Status,
			grant.Limits.Calls, grant.Limits.RuntimeSeconds, grant.Limits.TransferBytes,
			grant.Limits.Concurrency, grant.Limits.RatePerMinute, grant.Limits.Burst,
			grant.Limits.MaxCallSeconds, grant.IssuedAt, grant.ExpiresAt, grant.Digest,
		); err != nil {
			return err
		}
	case errors.Is(err, pgx.ErrNoRows):
		var overlap bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM narthex_usage_periods
    WHERE period_start < $2 AND period_end > $1
)`, grant.PeriodStart, grant.PeriodEnd).Scan(&overlap); err != nil {
			return err
		}
		if overlap {
			return errors.New("usage grant overlaps an existing billing period")
		}
		var maxRevision int64
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(revision),0) FROM narthex_usage_periods`,
		).Scan(&maxRevision); err != nil {
			return err
		}
		if grant.Revision <= maxRevision {
			return errors.New("usage grant revision is stale")
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_usage_periods (
    period_start,period_end,workspace_id,engine_generation,revision,plan_id,status,
    calls_limit,runtime_seconds_limit,transfer_bytes_limit,concurrency_limit,
    rate_per_minute,burst_limit,max_call_seconds,grant_issued_at,grant_expires_at,
    grant_digest,rate_tokens,rate_updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::bigint,$14,$15,$16,$17,$13::double precision,$15
)`,
			grant.PeriodStart, grant.PeriodEnd, grant.Identity.WorkspaceID,
			grant.Identity.EngineGeneration, grant.Revision, grant.PlanID, grant.Status,
			grant.Limits.Calls, grant.Limits.RuntimeSeconds, grant.Limits.TransferBytes,
			grant.Limits.Concurrency, grant.Limits.RatePerMinute, grant.Limits.Burst,
			grant.Limits.MaxCallSeconds, grant.IssuedAt, grant.ExpiresAt, grant.Digest,
		); err != nil {
			return err
		}
	default:
		return err
	}
	return tx.Commit(ctx)
}

func sameUsageGrantPolicy(left, right UsageGrant) bool {
	return left.Identity == right.Identity &&
		left.PeriodStart.Equal(right.PeriodStart) &&
		left.PeriodEnd.Equal(right.PeriodEnd) &&
		left.Revision == right.Revision &&
		left.PlanID == right.PlanID &&
		left.Status == right.Status &&
		left.Limits == right.Limits
}

func (s *PgStore) CurrentUsage(
	ctx context.Context,
	identity UsageIdentity,
	_ time.Time,
) (UsagePeriod, bool, error) {
	period, err := scanUsagePeriod(s.pool.QueryRow(ctx,
		`SELECT `+usagePeriodSelectColumns+`
FROM narthex_usage_periods
WHERE workspace_id=$1 AND engine_generation=$2
ORDER BY period_start DESC LIMIT 1`,
		identity.WorkspaceID, identity.EngineGeneration,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return UsagePeriod{}, false, nil
	}
	if err != nil {
		return UsagePeriod{}, false, err
	}
	if err := s.pool.QueryRow(ctx, `
SELECT COUNT(*) FROM narthex_usage_reservations
WHERE period_start=$1 AND settled_at IS NULL`, period.Grant.PeriodStart).
		Scan(&period.ActiveReservations); err != nil {
		return UsagePeriod{}, false, err
	}
	return period, true, nil
}

func (s *PgStore) AdmitUsage(
	ctx context.Context,
	identity UsageIdentity,
	now time.Time,
	meta UsageCallMeta,
) (UsageReservation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return UsageReservation{}, err
	}
	defer tx.Rollback(ctx)

	// Expired reservations are conservatively charged their full deadline.
	// Recent reservations are left alone: during a Cloud Run rolling handoff
	// the old instance may still be finishing them.
	if _, err := recoverUsageReservationsTx(ctx, tx, identity, now); err != nil {
		return UsageReservation{}, err
	}

	var period UsagePeriod
	var rateTokens float64
	var rateUpdatedAt time.Time
	row := tx.QueryRow(ctx, `SELECT `+usagePeriodSelectColumns+`,
rate_tokens,rate_updated_at
FROM narthex_usage_periods
WHERE workspace_id=$1 AND engine_generation=$2
  AND period_start <= $3 AND period_end > $3 AND grant_expires_at > $3
ORDER BY period_start DESC LIMIT 1 FOR UPDATE`,
		identity.WorkspaceID, identity.EngineGeneration, now,
	)
	err = row.Scan(
		&period.Grant.PeriodStart, &period.Grant.PeriodEnd,
		&period.Grant.Identity.WorkspaceID, &period.Grant.Identity.EngineGeneration,
		&period.Grant.Revision, &period.Grant.PlanID, &period.Grant.Status,
		&period.Grant.Limits.Calls, &period.Grant.Limits.RuntimeSeconds,
		&period.Grant.Limits.TransferBytes, &period.Grant.Limits.Concurrency,
		&period.Grant.Limits.RatePerMinute, &period.Grant.Limits.Burst,
		&period.Grant.Limits.MaxCallSeconds, &period.Grant.IssuedAt,
		&period.Grant.ExpiresAt, &period.Grant.Digest, &period.CallsUsed,
		&period.RuntimeMilliseconds, &period.TransferBytesUsed, &period.UpdatedAt,
		&rateTokens, &rateUpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UsageReservation{}, usageError(
			"usage_grant_required",
			"This hosted Engine has no active usage allowance. Refresh billing or contact the workspace owner.",
		)
	}
	if err != nil {
		return UsageReservation{}, err
	}
	resetAt := period.Grant.PeriodEnd
	switch {
	case period.CallsUsed >= period.Grant.Limits.Calls:
		e := usageError("usage_calls_exhausted", "The workspace has used its current tool-call allowance.")
		e.Limit, e.Used, e.ResetAt = period.Grant.Limits.Calls, period.CallsUsed, &resetAt
		return UsageReservation{}, e
	case period.RuntimeMilliseconds >= period.Grant.Limits.RuntimeSeconds*1000:
		e := usageError("usage_runtime_exhausted", "The workspace has used its current tool-runtime allowance.")
		e.Limit, e.Used, e.ResetAt = period.Grant.Limits.RuntimeSeconds,
			ceilMilliseconds(period.RuntimeMilliseconds), &resetAt
		return UsageReservation{}, e
	case period.TransferBytesUsed >= period.Grant.Limits.TransferBytes:
		e := usageError("usage_transfer_exhausted", "The workspace has used its current data-transfer allowance.")
		e.Limit, e.Used, e.ResetAt = period.Grant.Limits.TransferBytes,
			period.TransferBytesUsed, &resetAt
		return UsageReservation{}, e
	}

	var active int64
	if err := tx.QueryRow(ctx, `
SELECT COUNT(*) FROM narthex_usage_reservations
WHERE period_start=$1 AND settled_at IS NULL`,
		period.Grant.PeriodStart,
	).Scan(&active); err != nil {
		return UsageReservation{}, err
	}
	if active >= period.Grant.Limits.Concurrency {
		e := usageError("usage_concurrency_exhausted", "The workspace already has the maximum number of tool calls running.")
		e.Limit, e.Used, e.RetryAfterSeconds = period.Grant.Limits.Concurrency, active, 1
		return UsageReservation{}, e
	}

	elapsed := now.Sub(rateUpdatedAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	rateTokens = math.Min(
		float64(period.Grant.Limits.Burst),
		rateTokens+elapsed*float64(period.Grant.Limits.RatePerMinute)/60,
	)
	if rateTokens < 1 {
		ratePerSecond := float64(period.Grant.Limits.RatePerMinute) / 60
		retry := int64(math.Ceil((1 - rateTokens) / ratePerSecond))
		if retry < 1 {
			retry = 1
		}
		e := usageError("usage_rate_limited", "The workspace is sending tool calls too quickly. Retry shortly.")
		e.Limit, e.Used, e.RetryAfterSeconds = period.Grant.Limits.RatePerMinute,
			period.Grant.Limits.RatePerMinute, retry
		return UsageReservation{}, e
	}
	rateTokens--

	reservation := UsageReservation{
		ID: newUsageReservationID(), PeriodStart: period.Grant.PeriodStart,
		AdmittedAt: now, MaxCallSeconds: period.Grant.Limits.MaxCallSeconds,
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_usage_reservations
    (id,period_start,admitted_at,account,tool,connector,replay,max_call_seconds)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		reservation.ID, reservation.PeriodStart, reservation.AdmittedAt,
		clampUsageLabel(meta.Account), clampUsageLabel(meta.Tool),
		clampUsageLabel(meta.Connector), meta.Replay, reservation.MaxCallSeconds,
	); err != nil {
		return UsageReservation{}, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_periods
SET calls_used=calls_used+1,rate_tokens=$2,rate_updated_at=$3,updated_at=now()
WHERE period_start=$1`,
		period.Grant.PeriodStart, rateTokens, now,
	); err != nil {
		return UsageReservation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return UsageReservation{}, err
	}
	return reservation, nil
}

func (s *PgStore) SettleUsage(
	ctx context.Context,
	identity UsageIdentity,
	reservationID string,
	settledAt time.Time,
	runtimeMilliseconds int64,
	transferBytes int64,
) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var periodStart, admittedAt time.Time
	var existingSettlement *time.Time
	var maxCallSeconds int64
	err = tx.QueryRow(ctx, `
SELECT r.period_start,r.admitted_at,r.settled_at,r.max_call_seconds
FROM narthex_usage_reservations r
JOIN narthex_usage_periods p ON p.period_start=r.period_start
WHERE r.id=$1 AND p.workspace_id=$2 AND p.engine_generation=$3
FOR UPDATE OF r`,
		reservationID, identity.WorkspaceID, identity.EngineGeneration,
	).Scan(&periodStart, &admittedAt, &existingSettlement, &maxCallSeconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("usage reservation not found")
	}
	if err != nil {
		return err
	}
	if existingSettlement != nil {
		return tx.Commit(ctx) // retry after an uncertain response; never double-charge
	}
	if settledAt.Before(admittedAt) {
		settledAt = admittedAt
	}
	if runtimeMilliseconds < 0 {
		runtimeMilliseconds = 0
	}
	if max := maxCallSeconds * 1000; runtimeMilliseconds > max {
		runtimeMilliseconds = max
	}
	if transferBytes < 0 {
		transferBytes = 0
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_reservations
SET settled_at=$2,runtime_milliseconds=$3,transfer_bytes=$4,settlement='normal'
WHERE id=$1`,
		reservationID, settledAt, runtimeMilliseconds, transferBytes,
	); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
UPDATE narthex_usage_periods
SET runtime_milliseconds=CASE
        WHEN runtime_milliseconds > 9223372036854775807 - $2
            THEN 9223372036854775807
        ELSE runtime_milliseconds+$2
    END,
    transfer_bytes_used=CASE
        WHEN transfer_bytes_used > 9223372036854775807 - $3
            THEN 9223372036854775807
        ELSE transfer_bytes_used+$3
    END,
    updated_at=now()
WHERE period_start=$1 AND workspace_id=$4 AND engine_generation=$5`,
		periodStart, runtimeMilliseconds, transferBytes,
		identity.WorkspaceID, identity.EngineGeneration,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("usage reservation period no longer belongs to this Engine")
	}
	return tx.Commit(ctx)
}

func (s *PgStore) RecoverUsageReservations(
	ctx context.Context,
	identity UsageIdentity,
	now time.Time,
) (int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	recovered, err := recoverUsageReservationsTx(ctx, tx, identity, now)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return recovered, nil
}

type staleUsageReservation struct {
	id             string
	periodStart    time.Time
	maxCallSeconds int64
}

func recoverUsageReservationsTx(
	ctx context.Context,
	tx pgx.Tx,
	identity UsageIdentity,
	now time.Time,
) (int64, error) {
	rows, err := tx.Query(ctx, `
SELECT r.id,r.period_start,r.max_call_seconds
FROM narthex_usage_reservations r
JOIN narthex_usage_periods p ON p.period_start=r.period_start
WHERE r.settled_at IS NULL
  AND p.workspace_id=$1 AND p.engine_generation=$2
  AND r.admitted_at + make_interval(secs => r.max_call_seconds::double precision) <= $3
ORDER BY r.admitted_at
FOR UPDATE OF r`,
		identity.WorkspaceID, identity.EngineGeneration, now,
	)
	if err != nil {
		return 0, err
	}
	var stale []staleUsageReservation
	for rows.Next() {
		var item staleUsageReservation
		if err := rows.Scan(&item.id, &item.periodStart, &item.maxCallSeconds); err != nil {
			rows.Close()
			return 0, err
		}
		stale = append(stale, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	for _, item := range stale {
		runtimeMilliseconds := item.maxCallSeconds * 1000
		if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_reservations
SET settled_at=$2,runtime_milliseconds=$3,settlement='recovered'
WHERE id=$1 AND settled_at IS NULL`,
			item.id, now, runtimeMilliseconds,
		); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
UPDATE narthex_usage_periods
SET runtime_milliseconds=CASE
        WHEN runtime_milliseconds > 9223372036854775807 - $2
            THEN 9223372036854775807
        ELSE runtime_milliseconds+$2
    END,
    updated_at=now()
WHERE period_start=$1`,
			item.periodStart, runtimeMilliseconds,
		); err != nil {
			return 0, err
		}
	}
	return int64(len(stale)), nil
}

func newUsageReservationID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand failure is not realistically recoverable. The timestamp
		// plus nanosecond still keeps the primary key collision-resistant enough
		// for the error path, and a collision fails closed in Postgres.
		return fmt.Sprintf("usage-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func clampUsageLabel(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 200 {
		return value
	}
	return value[:runeBoundary(value, 200)]
}
