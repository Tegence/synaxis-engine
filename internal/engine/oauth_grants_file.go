package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"narthex/backend/internal/oauthas"
)

// The FileStore variant gives self-hosted, single-process development the same
// restart semantics as PgStore.  It relies on FileStore's existing mutex plus
// write-temp-then-rename save discipline; it is not a multi-writer backend.
type fileOAuthAuthorizationCode struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Challenge     string    `json:"challenge"`
	Scope         string    `json:"scope,omitempty"`
	Resource      string    `json:"resource"`
	ResourceEpoch string    `json:"resource_epoch,omitempty"`
	Generation    string    `json:"generation"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type fileOAuthRefreshGrant struct {
	ClientID      string    `json:"client_id"`
	Resource      string    `json:"resource"`
	ResourceEpoch string    `json:"resource_epoch,omitempty"`
	Generation    string    `json:"generation"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type fileOAuthHostedConsentReplay struct {
	ReservationID string    `json:"reservation_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	Finalized     bool      `json:"finalized"`
}

var _ oauthas.OAuthGrantStore = (*FileStore)(nil)
var _ oauthas.OAuthGrantEpochStore = (*FileStore)(nil)

func fileAuthorizationCodeFromDurable(grant oauthas.DurableAuthorizationCode) fileOAuthAuthorizationCode {
	return fileOAuthAuthorizationCode{
		ClientID: grant.ClientID, RedirectURI: grant.RedirectURI, Challenge: grant.Challenge,
		Scope: grant.Scope, Resource: grant.Resource, ResourceEpoch: grant.ResourceEpoch,
		Generation: grant.Generation, ExpiresAt: grant.ExpiresAt,
	}
}

func durableAuthorizationCodeFromFile(tokenHash string, grant fileOAuthAuthorizationCode) oauthas.DurableAuthorizationCode {
	return oauthas.DurableAuthorizationCode{
		TokenHash: tokenHash, ClientID: grant.ClientID, RedirectURI: grant.RedirectURI,
		Challenge: grant.Challenge, Scope: grant.Scope, Resource: grant.Resource,
		ResourceEpoch: grant.ResourceEpoch, Generation: grant.Generation, ExpiresAt: grant.ExpiresAt,
	}
}

func fileRefreshGrantFromDurable(grant oauthas.DurableRefreshGrant) fileOAuthRefreshGrant {
	return fileOAuthRefreshGrant{
		ClientID: grant.ClientID, Resource: grant.Resource, ResourceEpoch: grant.ResourceEpoch,
		Generation: grant.Generation, ExpiresAt: grant.ExpiresAt,
	}
}

func durableRefreshGrantFromFile(tokenHash string, grant fileOAuthRefreshGrant) oauthas.DurableRefreshGrant {
	return oauthas.DurableRefreshGrant{
		TokenHash: tokenHash, ClientID: grant.ClientID, Resource: grant.Resource,
		ResourceEpoch: grant.ResourceEpoch, Generation: grant.Generation, ExpiresAt: grant.ExpiresAt,
	}
}

func (s *FileStore) StoreAuthorizationCode(ctx context.Context, grant oauthas.DurableAuthorizationCode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFileOAuthAuthorizationCode(grant); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.oauthAuthorizationCodes == nil {
		s.oauthAuthorizationCodes = map[string]fileOAuthAuthorizationCode{}
	}
	if _, exists := s.oauthAuthorizationCodes[grant.TokenHash]; exists {
		return errors.New("authorization code collision")
	}
	s.oauthAuthorizationCodes[grant.TokenHash] = fileAuthorizationCodeFromDurable(grant)
	if err := s.saveLocked(); err != nil {
		delete(s.oauthAuthorizationCodes, grant.TokenHash)
		return fmt.Errorf("persist authorization code: %w", err)
	}
	return nil
}

func (s *FileStore) ConsumeAuthorizationCode(ctx context.Context, tokenHash string, now time.Time) (oauthas.DurableAuthorizationCode, bool, error) {
	if err := ctx.Err(); err != nil {
		return oauthas.DurableAuthorizationCode{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return oauthas.DurableAuthorizationCode{}, false, err
	}
	grant, found := s.oauthAuthorizationCodes[tokenHash]
	if !found {
		return oauthas.DurableAuthorizationCode{}, false, nil
	}
	if !now.Before(grant.ExpiresAt) {
		delete(s.oauthAuthorizationCodes, tokenHash)
		if err := s.saveLocked(); err != nil {
			s.oauthAuthorizationCodes[tokenHash] = grant
			return oauthas.DurableAuthorizationCode{}, false, fmt.Errorf("expire authorization code: %w", err)
		}
		return oauthas.DurableAuthorizationCode{}, false, nil
	}
	delete(s.oauthAuthorizationCodes, tokenHash)
	if err := s.saveLocked(); err != nil {
		s.oauthAuthorizationCodes[tokenHash] = grant
		return oauthas.DurableAuthorizationCode{}, false, fmt.Errorf("consume authorization code: %w", err)
	}
	return durableAuthorizationCodeFromFile(tokenHash, grant), true, nil
}

func (s *FileStore) StoreRefreshGrant(ctx context.Context, grant oauthas.DurableRefreshGrant) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFileOAuthRefreshGrant(grant); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.oauthRefreshGrants == nil {
		s.oauthRefreshGrants = map[string]fileOAuthRefreshGrant{}
	}
	if _, exists := s.oauthRefreshGrants[grant.TokenHash]; exists {
		return errors.New("refresh token collision")
	}
	s.oauthRefreshGrants[grant.TokenHash] = fileRefreshGrantFromDurable(grant)
	if err := s.saveLocked(); err != nil {
		delete(s.oauthRefreshGrants, grant.TokenHash)
		return fmt.Errorf("persist refresh grant: %w", err)
	}
	return nil
}

func (s *FileStore) LoadRefreshGrant(ctx context.Context, tokenHash string, now time.Time) (oauthas.DurableRefreshGrant, bool, error) {
	if err := ctx.Err(); err != nil {
		return oauthas.DurableRefreshGrant{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return oauthas.DurableRefreshGrant{}, false, err
	}
	grant, found := s.oauthRefreshGrants[tokenHash]
	if !found {
		return oauthas.DurableRefreshGrant{}, false, nil
	}
	if !now.Before(grant.ExpiresAt) {
		delete(s.oauthRefreshGrants, tokenHash)
		if err := s.saveLocked(); err != nil {
			s.oauthRefreshGrants[tokenHash] = grant
			return oauthas.DurableRefreshGrant{}, false, fmt.Errorf("expire refresh grant: %w", err)
		}
		return oauthas.DurableRefreshGrant{}, false, nil
	}
	return durableRefreshGrantFromFile(tokenHash, grant), true, nil
}

func (s *FileStore) RevokeOAuthGrantsForResource(ctx context.Context, resource string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	removedCodes := map[string]fileOAuthAuthorizationCode{}
	removedRefresh := map[string]fileOAuthRefreshGrant{}
	for tokenHash, grant := range s.oauthAuthorizationCodes {
		if grant.Resource == resource {
			removedCodes[tokenHash] = grant
			delete(s.oauthAuthorizationCodes, tokenHash)
		}
	}
	for tokenHash, grant := range s.oauthRefreshGrants {
		if grant.Resource == resource {
			removedRefresh[tokenHash] = grant
			delete(s.oauthRefreshGrants, tokenHash)
		}
	}
	if len(removedCodes) == 0 && len(removedRefresh) == 0 {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		for tokenHash, grant := range removedCodes {
			s.oauthAuthorizationCodes[tokenHash] = grant
		}
		for tokenHash, grant := range removedRefresh {
			s.oauthRefreshGrants[tokenHash] = grant
		}
		return fmt.Errorf("persist resource OAuth revocation: %w", err)
	}
	return nil
}

func (s *FileStore) RevokeOAuthGrantsForResourceEpoch(ctx context.Context, resource, resourceEpoch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if resource == "" || resourceEpoch == "" {
		return errors.New("invalid OAuth resource epoch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	removedCodes := map[string]fileOAuthAuthorizationCode{}
	removedRefresh := map[string]fileOAuthRefreshGrant{}
	for tokenHash, grant := range s.oauthAuthorizationCodes {
		if grant.Resource == resource && (grant.ResourceEpoch == resourceEpoch || grant.ResourceEpoch == "") {
			removedCodes[tokenHash] = grant
			delete(s.oauthAuthorizationCodes, tokenHash)
		}
	}
	for tokenHash, grant := range s.oauthRefreshGrants {
		if grant.Resource == resource && (grant.ResourceEpoch == resourceEpoch || grant.ResourceEpoch == "") {
			removedRefresh[tokenHash] = grant
			delete(s.oauthRefreshGrants, tokenHash)
		}
	}
	if len(removedCodes) == 0 && len(removedRefresh) == 0 {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		for tokenHash, grant := range removedCodes {
			s.oauthAuthorizationCodes[tokenHash] = grant
		}
		for tokenHash, grant := range removedRefresh {
			s.oauthRefreshGrants[tokenHash] = grant
		}
		return fmt.Errorf("persist epoch OAuth revocation: %w", err)
	}
	return nil
}

func (s *FileStore) RevokeAllOAuthGrants(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	codes, refresh, replays := s.oauthAuthorizationCodes, s.oauthRefreshGrants, s.oauthHostedConsentReplays
	s.oauthAuthorizationCodes = map[string]fileOAuthAuthorizationCode{}
	s.oauthRefreshGrants = map[string]fileOAuthRefreshGrant{}
	s.oauthHostedConsentReplays = map[string]fileOAuthHostedConsentReplay{}
	if err := s.saveLocked(); err != nil {
		s.oauthAuthorizationCodes, s.oauthRefreshGrants, s.oauthHostedConsentReplays = codes, refresh, replays
		return fmt.Errorf("persist OAuth revocation: %w", err)
	}
	return nil
}

func (s *FileStore) ReserveHostedConsentReplay(ctx context.Context, reservationID, approvalKey, requestKey string, expiresAt, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if reservationID == "" || approvalKey == "" || requestKey == "" || approvalKey == requestKey || !now.Before(expiresAt) {
		return false, errors.New("invalid hosted consent replay reservation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.oauthHostedConsentReplays == nil {
		s.oauthHostedConsentReplays = map[string]fileOAuthHostedConsentReplay{}
	}
	before := copyFileOAuthHostedConsentReplays(s.oauthHostedConsentReplays)
	for key, replay := range s.oauthHostedConsentReplays {
		if !now.Before(replay.ExpiresAt) {
			delete(s.oauthHostedConsentReplays, key)
		}
	}
	if _, exists := s.oauthHostedConsentReplays[approvalKey]; exists {
		s.oauthHostedConsentReplays = before
		return false, nil
	}
	if _, exists := s.oauthHostedConsentReplays[requestKey]; exists {
		s.oauthHostedConsentReplays = before
		return false, nil
	}
	replay := fileOAuthHostedConsentReplay{ReservationID: reservationID, ExpiresAt: expiresAt}
	s.oauthHostedConsentReplays[approvalKey] = replay
	s.oauthHostedConsentReplays[requestKey] = replay
	if err := s.saveLocked(); err != nil {
		s.oauthHostedConsentReplays = before
		return false, fmt.Errorf("persist hosted consent replay reservation: %w", err)
	}
	return true, nil
}

func (s *FileStore) FinalizeHostedConsentReplay(ctx context.Context, reservationID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	before := copyFileOAuthHostedConsentReplays(s.oauthHostedConsentReplays)
	updated := 0
	for key, replay := range s.oauthHostedConsentReplays {
		if replay.ReservationID == reservationID && !replay.Finalized {
			replay.Finalized = true
			s.oauthHostedConsentReplays[key] = replay
			updated++
		}
	}
	if updated != 2 {
		return errors.New("hosted consent replay reservation is unavailable")
	}
	if err := s.saveLocked(); err != nil {
		s.oauthHostedConsentReplays = before
		return fmt.Errorf("persist hosted consent replay finalization: %w", err)
	}
	return nil
}

func (s *FileStore) ReleaseHostedConsentReplay(ctx context.Context, reservationID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	before := copyFileOAuthHostedConsentReplays(s.oauthHostedConsentReplays)
	for key, replay := range s.oauthHostedConsentReplays {
		if replay.ReservationID == reservationID && !replay.Finalized {
			delete(s.oauthHostedConsentReplays, key)
		}
	}
	if err := s.saveLocked(); err != nil {
		s.oauthHostedConsentReplays = before
		return fmt.Errorf("persist hosted consent replay release: %w", err)
	}
	return nil
}

func validateFileOAuthAuthorizationCode(grant oauthas.DurableAuthorizationCode) error {
	if grant.TokenHash == "" || grant.ClientID == "" || grant.RedirectURI == "" || grant.Challenge == "" ||
		grant.Resource == "" || grant.Generation == "" || grant.ExpiresAt.IsZero() {
		return errors.New("invalid authorization code grant")
	}
	return nil
}

func validateFileOAuthRefreshGrant(grant oauthas.DurableRefreshGrant) error {
	if grant.TokenHash == "" || grant.ClientID == "" || grant.Resource == "" ||
		grant.Generation == "" || grant.ExpiresAt.IsZero() {
		return errors.New("invalid refresh grant")
	}
	return nil
}

func copyFileOAuthHostedConsentReplays(in map[string]fileOAuthHostedConsentReplay) map[string]fileOAuthHostedConsentReplay {
	if in == nil {
		return nil
	}
	out := make(map[string]fileOAuthHostedConsentReplay, len(in))
	for key, replay := range in {
		out[key] = replay
	}
	return out
}
