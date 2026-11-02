package engine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

const linkedOAuthLifetime = 10 * time.Minute

var errLinkedOAuthState = errors.New("sign-in expired or unavailable")

type LinkedOAuthFlow struct {
	StateHash       string                    `json:"state_hash"`
	ProofHash       string                    `json:"proof_hash"`
	Subject         string                    `json:"subject"`
	ConnectionID    string                    `json:"connection_id"`
	Parent          AccountPolicyPrecondition `json:"parent"`
	Provider        string                    `json:"provider"`
	AppFingerprint  string                    `json:"app_fingerprint"`
	DisplayName     string                    `json:"display_name"`
	AccountID       string                    `json:"account_id,omitempty"`
	AccountRevision int64                     `json:"account_revision,omitempty"`
	ExpiresAt       time.Time                 `json:"expires_at"`
}
type LinkedOAuthFlowStore interface {
	PutLinkedOAuthFlow(context.Context, LinkedOAuthFlow) error
	ConsumeLinkedOAuthFlow(context.Context, string, string, string, string) (LinkedOAuthFlow, error)
}

func oauthLinkHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
func validLinkedOAuthFlow(f LinkedOAuthFlow) bool {
	return len(f.StateHash) == 64 && len(f.ProofHash) == 64 && validActorIdentifier(f.Subject) && f.ConnectionID != "" && f.Parent.IncarnationID != "" && f.Parent.Revision > 0 && f.Provider != "" && f.ExpiresAt.After(time.Now()) && f.ExpiresAt.Before(time.Now().Add(linkedOAuthLifetime+time.Minute))
}
func flowMatches(f LinkedOAuthFlow, hash, subject, provider, proof string) bool {
	return f.StateHash == hash && f.Subject == subject && f.Provider == provider && subtle.ConstantTimeCompare([]byte(f.ProofHash), []byte(oauthLinkHash(proof))) == 1 && f.ExpiresAt.After(time.Now())
}
func (s *FileStore) PutLinkedOAuthFlow(ctx context.Context, f LinkedOAuthFlow) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !validLinkedOAuthFlow(f) {
		return errLinkedOAuthState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.linkedOAuthFlows
	next := []LinkedOAuthFlow{}
	count := 0
	for _, existing := range before {
		if existing.ExpiresAt.After(time.Now()) {
			next = append(next, existing)
			if existing.Subject == f.Subject {
				count++
			}
		}
	}
	if count >= 32 {
		return ErrLinkedAccountLimit
	}
	s.linkedOAuthFlows = append(next, f)
	if err := s.saveLocked(); err != nil {
		s.linkedOAuthFlows = before
		return err
	}
	return nil
}
func (s *FileStore) ConsumeLinkedOAuthFlow(ctx context.Context, hash, subject, provider, proof string) (LinkedOAuthFlow, error) {
	if ctx.Err() != nil {
		return LinkedOAuthFlow{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.linkedOAuthFlows {
		if flowMatches(f, hash, subject, provider, proof) {
			before := s.linkedOAuthFlows
			s.linkedOAuthFlows = slices.Delete(slices.Clone(before), i, i+1)
			if err := s.saveLocked(); err != nil {
				s.linkedOAuthFlows = before
				return LinkedOAuthFlow{}, err
			}
			return f, nil
		}
	}
	return LinkedOAuthFlow{}, errLinkedOAuthState
}
func (s *PgStore) PutLinkedOAuthFlow(ctx context.Context, f LinkedOAuthFlow) error {
	if !validLinkedOAuthFlow(f) {
		return errLinkedOAuthState
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "linked-oauth:"+f.Subject); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM narthex_linked_oauth_flows WHERE expires_at <= now()`); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM narthex_linked_oauth_flows WHERE owner_subject=$1`, f.Subject).Scan(&count); err != nil {
		return err
	}
	if count >= 32 {
		return ErrLinkedAccountLimit
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	encrypted, err := s.enc(string(raw))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO narthex_linked_oauth_flows(state_hash,owner_subject,payload,expires_at) VALUES($1,$2,$3,$4)`, f.StateHash, f.Subject, encrypted, f.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *PgStore) ConsumeLinkedOAuthFlow(ctx context.Context, hash, subject, provider, proof string) (LinkedOAuthFlow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedOAuthFlow{}, err
	}
	defer tx.Rollback(ctx)
	var raw string
	err = tx.QueryRow(ctx, `SELECT payload FROM narthex_linked_oauth_flows WHERE state_hash=$1 AND owner_subject=$2 AND expires_at>now() FOR UPDATE`, hash, subject).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return LinkedOAuthFlow{}, errLinkedOAuthState
	}
	if err != nil {
		return LinkedOAuthFlow{}, err
	}
	plain, err := s.dec(raw)
	if err != nil {
		return LinkedOAuthFlow{}, err
	}
	var f LinkedOAuthFlow
	if json.Unmarshal([]byte(plain), &f) != nil || !flowMatches(f, hash, subject, provider, proof) {
		return LinkedOAuthFlow{}, errLinkedOAuthState
	}
	if _, err = tx.Exec(ctx, `DELETE FROM narthex_linked_oauth_flows WHERE state_hash=$1`, hash); err != nil {
		return LinkedOAuthFlow{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return LinkedOAuthFlow{}, err
	}
	return f, nil
}
