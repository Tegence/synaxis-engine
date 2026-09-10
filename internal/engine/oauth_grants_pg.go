package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"narthex/backend/internal/oauthas"
)

// oauthGrantSchema keeps browser-facing OAuth grants out of process memory so
// a code issued by one Cloud Run instance can be redeemed exactly once by
// another. Token hashes are one-way digests; raw authorization and refresh
// tokens are never persisted here.
const oauthGrantSchema = `
CREATE TABLE IF NOT EXISTS narthex_oauth_authorization_codes (
    token_hash     TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    challenge      TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT '',
    resource       TEXT NOT NULL,
    resource_epoch TEXT NOT NULL DEFAULT '',
    generation     TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS narthex_oauth_authorization_codes_expiry_idx
    ON narthex_oauth_authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS narthex_oauth_refresh_grants (
    token_hash     TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    resource       TEXT NOT NULL,
    resource_epoch TEXT NOT NULL DEFAULT '',
    generation     TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS narthex_oauth_refresh_grants_resource_idx
    ON narthex_oauth_refresh_grants (resource);
CREATE INDEX IF NOT EXISTS narthex_oauth_refresh_grants_expiry_idx
    ON narthex_oauth_refresh_grants (expires_at);

CREATE TABLE IF NOT EXISTS narthex_oauth_hosted_consent_replays (
    replay_key     TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    finalized      BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS narthex_oauth_hosted_consent_replays_expiry_idx
    ON narthex_oauth_hosted_consent_replays (expires_at);`

func (s *PgStore) ensureOAuthGrantSchema(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, oauthGrantSchema); err != nil {
		return err
	}
	return nil
}

var _ oauthas.OAuthGrantStore = (*PgStore)(nil)
var _ oauthas.OAuthGrantEpochStore = (*PgStore)(nil)

func validateOAuthGrantFields(tokenHash, clientID, resource, generation string, expiresAt time.Time) error {
	if len(tokenHash) < 32 || len(tokenHash) > 256 ||
		len(clientID) == 0 || len(clientID) > 1024 ||
		len(resource) == 0 || len(resource) > 2048 ||
		len(generation) == 0 || len(generation) > 512 ||
		expiresAt.IsZero() {
		return errors.New("invalid OAuth grant")
	}
	return nil
}

func (s *PgStore) StoreAuthorizationCode(ctx context.Context, grant oauthas.DurableAuthorizationCode) error {
	if err := validateOAuthGrantFields(grant.TokenHash, grant.ClientID, grant.Resource, grant.Generation, grant.ExpiresAt); err != nil ||
		len(grant.RedirectURI) == 0 || len(grant.RedirectURI) > 2048 ||
		len(grant.Challenge) == 0 || len(grant.Challenge) > 128 ||
		len(grant.Scope) > 1024 || len(grant.ResourceEpoch) > 2048 {
		return errors.New("invalid authorization code grant")
	}
	tag, err := s.pool.Exec(ctx, `
INSERT INTO narthex_oauth_authorization_codes (
  token_hash,client_id,redirect_uri,challenge,scope,resource,resource_epoch,generation,expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (token_hash) DO NOTHING`,
		grant.TokenHash, grant.ClientID, grant.RedirectURI, grant.Challenge,
		grant.Scope, grant.Resource, grant.ResourceEpoch, grant.Generation, grant.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store authorization code: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("authorization code collision")
	}
	return nil
}

// ConsumeAuthorizationCode deletes and returns a live code in one statement.
// This is the linearization point for single-use redemption across replicas.
func (s *PgStore) ConsumeAuthorizationCode(ctx context.Context, tokenHash string, now time.Time) (oauthas.DurableAuthorizationCode, bool, error) {
	if len(tokenHash) < 32 || len(tokenHash) > 256 || now.IsZero() {
		return oauthas.DurableAuthorizationCode{}, false, errors.New("invalid authorization code lookup")
	}
	var grant oauthas.DurableAuthorizationCode
	err := s.pool.QueryRow(ctx, `
DELETE FROM narthex_oauth_authorization_codes
WHERE token_hash=$1 AND expires_at > $2
RETURNING token_hash,client_id,redirect_uri,challenge,scope,resource,resource_epoch,generation,expires_at`, tokenHash, now).Scan(
		&grant.TokenHash, &grant.ClientID, &grant.RedirectURI, &grant.Challenge,
		&grant.Scope, &grant.Resource, &grant.ResourceEpoch, &grant.Generation, &grant.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauthas.DurableAuthorizationCode{}, false, nil
	}
	if err != nil {
		return oauthas.DurableAuthorizationCode{}, false, fmt.Errorf("consume authorization code: %w", err)
	}
	return grant, true, nil
}

func (s *PgStore) StoreRefreshGrant(ctx context.Context, grant oauthas.DurableRefreshGrant) error {
	if err := validateOAuthGrantFields(grant.TokenHash, grant.ClientID, grant.Resource, grant.Generation, grant.ExpiresAt); err != nil ||
		len(grant.ResourceEpoch) > 2048 {
		return errors.New("invalid refresh grant")
	}
	tag, err := s.pool.Exec(ctx, `
INSERT INTO narthex_oauth_refresh_grants (
  token_hash,client_id,resource,resource_epoch,generation,expires_at
) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (token_hash) DO NOTHING`,
		grant.TokenHash, grant.ClientID, grant.Resource, grant.ResourceEpoch, grant.Generation, grant.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store refresh grant: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("refresh token collision")
	}
	return nil
}

func (s *PgStore) LoadRefreshGrant(ctx context.Context, tokenHash string, now time.Time) (oauthas.DurableRefreshGrant, bool, error) {
	if len(tokenHash) < 32 || len(tokenHash) > 256 || now.IsZero() {
		return oauthas.DurableRefreshGrant{}, false, errors.New("invalid refresh grant lookup")
	}
	var grant oauthas.DurableRefreshGrant
	err := s.pool.QueryRow(ctx, `
SELECT token_hash,client_id,resource,resource_epoch,generation,expires_at
FROM narthex_oauth_refresh_grants
WHERE token_hash=$1 AND expires_at > $2`, tokenHash, now).Scan(
		&grant.TokenHash, &grant.ClientID, &grant.Resource,
		&grant.ResourceEpoch, &grant.Generation, &grant.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauthas.DurableRefreshGrant{}, false, nil
	}
	if err != nil {
		return oauthas.DurableRefreshGrant{}, false, fmt.Errorf("load refresh grant: %w", err)
	}
	return grant, true, nil
}

func (s *PgStore) RevokeOAuthGrantsForResource(ctx context.Context, resource string) error {
	if strings.TrimSpace(resource) == "" || len(resource) > 2048 {
		return errors.New("invalid OAuth resource")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin resource OAuth revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_oauth_authorization_codes WHERE resource=$1`, resource); err != nil {
		return fmt.Errorf("revoke authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_oauth_refresh_grants WHERE resource=$1`, resource); err != nil {
		return fmt.Errorf("revoke refresh grants: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit resource OAuth revocation: %w", err)
	}
	return nil
}

// RevokeOAuthGrantsForResourceEpoch removes only the retiring endpoint
// incarnation. A new connector with the same slug receives a fresh epoch, so
// its just-issued grants cannot be swept by a delayed cleanup from the old
// connector.
func (s *PgStore) RevokeOAuthGrantsForResourceEpoch(ctx context.Context, resource, resourceEpoch string) error {
	if strings.TrimSpace(resource) == "" || len(resource) > 2048 ||
		strings.TrimSpace(resourceEpoch) == "" || len(resourceEpoch) > 2048 {
		return errors.New("invalid OAuth resource epoch")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin epoch OAuth revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
DELETE FROM narthex_oauth_authorization_codes
WHERE resource=$1 AND (resource_epoch=$2 OR resource_epoch='')`, resource, resourceEpoch); err != nil {
		return fmt.Errorf("revoke epoch authorization codes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
DELETE FROM narthex_oauth_refresh_grants
WHERE resource=$1 AND (resource_epoch=$2 OR resource_epoch='')`, resource, resourceEpoch); err != nil {
		return fmt.Errorf("revoke epoch refresh grants: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit epoch OAuth revocation: %w", err)
	}
	return nil
}

func (s *PgStore) RevokeAllOAuthGrants(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	for _, table := range []string{
		"narthex_oauth_authorization_codes",
		"narthex_oauth_refresh_grants",
		"narthex_oauth_hosted_consent_replays",
	} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear OAuth state: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit OAuth revocation: %w", err)
	}
	return nil
}

// ReserveHostedConsentReplay atomically claims both a Platform approval JTI
// and the sealed request digest. A reservation is sufficient to prevent a
// replay; finalized only distinguishes committed decisions from a retryable
// authorizer/storage failure that calls ReleaseHostedConsentReplay.
func (s *PgStore) ReserveHostedConsentReplay(ctx context.Context, reservationID, approvalKey, requestKey string, expiresAt, now time.Time) (bool, error) {
	if len(reservationID) < 16 || len(reservationID) > 256 ||
		len(approvalKey) < 16 || len(approvalKey) > 512 ||
		len(requestKey) < 16 || len(requestKey) > 512 ||
		approvalKey == requestKey || expiresAt.IsZero() || now.IsZero() || !now.Before(expiresAt) {
		return false, errors.New("invalid hosted consent replay reservation")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin hosted consent reservation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_oauth_hosted_consent_replays WHERE expires_at <= $1`, now); err != nil {
		return false, fmt.Errorf("clean hosted consent replay state: %w", err)
	}
	for _, key := range []string{approvalKey, requestKey} {
		tag, err := tx.Exec(ctx, `
INSERT INTO narthex_oauth_hosted_consent_replays (replay_key,reservation_id,expires_at,finalized)
VALUES ($1,$2,$3,false)
ON CONFLICT (replay_key) DO NOTHING`, key, reservationID, expiresAt)
		if err != nil {
			return false, fmt.Errorf("reserve hosted consent replay: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return false, nil
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit hosted consent reservation: %w", err)
	}
	return true, nil
}

func (s *PgStore) FinalizeHostedConsentReplay(ctx context.Context, reservationID string) error {
	if len(reservationID) < 16 || len(reservationID) > 256 {
		return errors.New("invalid hosted consent replay reservation")
	}
	tag, err := s.pool.Exec(ctx, `
UPDATE narthex_oauth_hosted_consent_replays
SET finalized=true
WHERE reservation_id=$1 AND finalized=false`, reservationID)
	if err != nil {
		return fmt.Errorf("finalize hosted consent replay: %w", err)
	}
	if tag.RowsAffected() != 2 {
		return errors.New("hosted consent replay reservation is unavailable")
	}
	return nil
}

func (s *PgStore) ReleaseHostedConsentReplay(ctx context.Context, reservationID string) error {
	if len(reservationID) < 16 || len(reservationID) > 256 {
		return errors.New("invalid hosted consent replay reservation")
	}
	if _, err := s.pool.Exec(ctx, `
DELETE FROM narthex_oauth_hosted_consent_replays
WHERE reservation_id=$1 AND finalized=false`, reservationID); err != nil {
		return fmt.Errorf("release hosted consent replay: %w", err)
	}
	return nil
}
