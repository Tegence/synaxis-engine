package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const connectionGrantsSchema = `
CREATE TABLE IF NOT EXISTS narthex_connection_grants (
 id TEXT PRIMARY KEY,
 payload TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK (revision >= 1)
);
CREATE TABLE IF NOT EXISTS narthex_subject_access (
 subject TEXT PRIMARY KEY,
 allowed BOOLEAN NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

func (s *PgStore) encodeConnectionGrant(g ConnectionGrant) (string, error) {
	raw, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	return s.enc(string(raw))
}
func (s *PgStore) decodeConnectionGrant(raw string) (ConnectionGrant, error) {
	plain, err := s.dec(raw)
	if err != nil {
		return ConnectionGrant{}, err
	}
	var g ConnectionGrant
	err = json.Unmarshal([]byte(plain), &g)
	return g, err
}
func (s *PgStore) ConnectionGrants(ctx context.Context) ([]ConnectionGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT payload FROM narthex_connection_grants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConnectionGrant{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		g, err := s.decodeConnectionGrant(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *PgStore) CreateConnectionGrant(ctx context.Context, g ConnectionGrant, p AccountPolicyPrecondition) (ConnectionGrant, error) {
	g, err := normalizeConnectionGrant(g)
	if err != nil {
		return ConnectionGrant{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectionGrant{}, err
	}
	defer tx.Rollback(ctx)
	var a Account
	err = tx.QueryRow(ctx, `SELECT name,incarnation_id,revision,connection_namespace_id,connection_scope,owner_subject,member_credentials FROM narthex_accounts WHERE name=$1 FOR SHARE`, g.ConnectionID).Scan(&a.Name, &a.IncarnationID, &a.Revision, &a.ConnectionNamespaceID, &a.ConnectionScope, &a.OwnerSubject, &a.MemberCredentials)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionGrant{}, ErrAccountPolicyPrecondition
	}
	if err != nil {
		return ConnectionGrant{}, err
	}
	if !p.matches(a) || a.IncarnationID != g.IncarnationID || a.OwnerSubject != g.OwnerSubject || a.MemberCredentials || (g.PersonalWorkload && !a.IsPersonal()) {
		return ConnectionGrant{}, ErrAccountPolicyPrecondition
	}
	g.SourceRevision = a.Revision
	payload, err := s.encodeConnectionGrant(g)
	if err != nil {
		return ConnectionGrant{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO narthex_connection_grants(id,payload,revision) VALUES($1,$2,$3)`, g.ID, payload, g.Revision)
	if err != nil {
		return ConnectionGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionGrant{}, err
	}
	return g, nil
}
func (s *PgStore) mutateConnectionGrant(ctx context.Context, id string, revision int64, mutate func(*ConnectionGrant) error) (ConnectionGrant, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectionGrant{}, err
	}
	defer tx.Rollback(ctx)
	var raw string
	var current int64
	err = tx.QueryRow(ctx, `SELECT payload,revision FROM narthex_connection_grants WHERE id=$1 FOR UPDATE`, id).Scan(&raw, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionGrant{}, ErrConnectionGrantNotFound
	}
	if err != nil {
		return ConnectionGrant{}, err
	}
	if revision < 1 || current != revision {
		return ConnectionGrant{}, ErrConnectionGrantRevision
	}
	g, err := s.decodeConnectionGrant(raw)
	if err != nil {
		return ConnectionGrant{}, err
	}
	if err := mutate(&g); err != nil {
		return ConnectionGrant{}, err
	}
	g.Revision++
	payload, err := s.encodeConnectionGrant(g)
	if err != nil {
		return ConnectionGrant{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_connection_grants SET payload=$2,revision=$3 WHERE id=$1`, id, payload, g.Revision); err != nil {
		return ConnectionGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionGrant{}, err
	}
	return g, nil
}
func (s *PgStore) RevokeConnectionGrant(ctx context.Context, id string, revision int64) (ConnectionGrant, error) {
	return s.mutateConnectionGrant(ctx, id, revision, func(g *ConnectionGrant) error {
		if g.RevokedAt == nil {
			now := time.Now().UTC()
			g.RevokedAt = &now
		}
		return nil
	})
}
func (s *PgStore) SetConnectionGrantRecipients(ctx context.Context, id string, revision int64, subjects []string) (ConnectionGrant, error) {
	subjects, err := normalizeGrantSubjects(subjects)
	if err != nil {
		return ConnectionGrant{}, err
	}
	return s.mutateConnectionGrant(ctx, id, revision, func(g *ConnectionGrant) error {
		if g.RevokedAt != nil {
			return ErrConnectionGrantNotFound
		}
		g.RecipientSubjects = subjects
		return nil
	})
}
func (s *PgStore) SubjectAllowed(ctx context.Context, subject string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT allowed FROM narthex_subject_access WHERE subject=$1`, subject).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	return allowed, err
}
func (s *PgStore) SetSubjectAllowed(ctx context.Context, subject string, allowed bool) error {
	if subject == "" || !validActorIdentifier(subject) {
		return ErrConnectionGrantInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "subject-access:"+subject); err != nil {
		return err
	}
	var before bool
	err = tx.QueryRow(ctx, `SELECT allowed FROM narthex_subject_access WHERE subject=$1`, subject).Scan(&before)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !allowed && (errors.Is(err, pgx.ErrNoRows) || before) {
		if _, err := tx.Exec(ctx, `UPDATE narthex_mcp_clients SET epoch=$2,revision=revision+1,updated_at=now() WHERE subject=$1 AND status='active'`, subject, newEpoch()); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_subject_access(subject,allowed) VALUES($1,$2) ON CONFLICT(subject) DO UPDATE SET allowed=EXCLUDED.allowed,updated_at=now()`, subject, allowed); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
