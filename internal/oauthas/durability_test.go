package oauthas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// memoryOAuthGrantStore is a deterministic stand-in for the PgStore contract.
// It deliberately has no per-Server state, so tests exercise restart and
// cross-replica behavior rather than merely a local map cache.
type memoryOAuthGrantStore struct {
	mu      sync.Mutex
	codes   map[string]DurableAuthorizationCode
	refresh map[string]DurableRefreshGrant
	replays map[string]memoryHostedReplay
}

type memoryHostedReplay struct {
	reservationID string
	expiresAt     time.Time
	finalized     bool
}

func newMemoryOAuthGrantStore() *memoryOAuthGrantStore {
	return &memoryOAuthGrantStore{
		codes:   map[string]DurableAuthorizationCode{},
		refresh: map[string]DurableRefreshGrant{},
		replays: map[string]memoryHostedReplay{},
	}
}

func (s *memoryOAuthGrantStore) StoreAuthorizationCode(_ context.Context, grant DurableAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.codes[grant.TokenHash]; exists {
		return errors.New("authorization code collision")
	}
	s.codes[grant.TokenHash] = grant
	return nil
}

func (s *memoryOAuthGrantStore) ConsumeAuthorizationCode(_ context.Context, tokenHash string, now time.Time) (DurableAuthorizationCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.codes[tokenHash]
	if !ok || !now.Before(grant.ExpiresAt) {
		return DurableAuthorizationCode{}, false, nil
	}
	delete(s.codes, tokenHash)
	return grant, true, nil
}

func (s *memoryOAuthGrantStore) StoreRefreshGrant(_ context.Context, grant DurableRefreshGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.refresh[grant.TokenHash]; exists {
		return errors.New("refresh token collision")
	}
	s.refresh[grant.TokenHash] = grant
	return nil
}

func (s *memoryOAuthGrantStore) LoadRefreshGrant(_ context.Context, tokenHash string, now time.Time) (DurableRefreshGrant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.refresh[tokenHash]
	if !ok || !now.Before(grant.ExpiresAt) {
		return DurableRefreshGrant{}, false, nil
	}
	return grant, true, nil
}

func (s *memoryOAuthGrantStore) RevokeOAuthGrantsForResource(_ context.Context, resource string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tokenHash, grant := range s.codes {
		if grant.Resource == resource {
			delete(s.codes, tokenHash)
		}
	}
	for tokenHash, grant := range s.refresh {
		if grant.Resource == resource {
			delete(s.refresh, tokenHash)
		}
	}
	return nil
}

func (s *memoryOAuthGrantStore) RevokeOAuthGrantsForResourceEpoch(_ context.Context, resource, resourceEpoch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tokenHash, grant := range s.codes {
		if grant.Resource == resource && (grant.ResourceEpoch == resourceEpoch || grant.ResourceEpoch == "") {
			delete(s.codes, tokenHash)
		}
	}
	for tokenHash, grant := range s.refresh {
		if grant.Resource == resource && (grant.ResourceEpoch == resourceEpoch || grant.ResourceEpoch == "") {
			delete(s.refresh, tokenHash)
		}
	}
	return nil
}

func (s *memoryOAuthGrantStore) RevokeAllOAuthGrants(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.codes)
	clear(s.refresh)
	clear(s.replays)
	return nil
}

func (s *memoryOAuthGrantStore) ReserveHostedConsentReplay(_ context.Context, reservationID, approvalKey, requestKey string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, replay := range s.replays {
		if !now.Before(replay.expiresAt) {
			delete(s.replays, key)
		}
	}
	if _, exists := s.replays[approvalKey]; exists {
		return false, nil
	}
	if _, exists := s.replays[requestKey]; exists {
		return false, nil
	}
	replay := memoryHostedReplay{reservationID: reservationID, expiresAt: expiresAt}
	s.replays[approvalKey] = replay
	s.replays[requestKey] = replay
	return true, nil
}

func (s *memoryOAuthGrantStore) FinalizeHostedConsentReplay(_ context.Context, reservationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := 0
	for key, replay := range s.replays {
		if replay.reservationID == reservationID && !replay.finalized {
			replay.finalized = true
			s.replays[key] = replay
			updated++
		}
	}
	if updated != 2 {
		return errors.New("hosted consent replay reservation is unavailable")
	}
	return nil
}

func (s *memoryOAuthGrantStore) ReleaseHostedConsentReplay(_ context.Context, reservationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, replay := range s.replays {
		if replay.reservationID == reservationID && !replay.finalized {
			delete(s.replays, key)
		}
	}
	return nil
}

var _ OAuthGrantStore = (*memoryOAuthGrantStore)(nil)
var _ OAuthGrantEpochStore = (*memoryOAuthGrantStore)(nil)

type memoryDurableOAuthStore struct {
	*memoryTokenGenerationStore
	*memoryOAuthGrantStore
}

func newMemoryDurableOAuthStore() *memoryDurableOAuthStore {
	return &memoryDurableOAuthStore{
		memoryTokenGenerationStore: &memoryTokenGenerationStore{},
		memoryOAuthGrantStore:      newMemoryOAuthGrantStore(),
	}
}

func newDurableOAuthServer(t *testing.T, store *memoryDurableOAuthStore, epochs map[string]string, now *time.Time) *Server {
	t.Helper()
	server := New("https://engine.example", "pw", "stable-engine-secret")
	server.SetEpochLookup(func(path string) (string, bool) {
		epoch, ok := epochs[path]
		return epoch, ok
	})
	server.now = func() time.Time { return *now }
	configureGeneration(t, server, store)
	return server
}

func createDurableCode(t *testing.T, server *Server, clientID, redirectURI, verifier, resource string) string {
	t.Helper()
	server.mu.Lock()
	request := authorizationRequest{
		clientID:     clientID,
		redirectURI:  redirectURI,
		challenge:    pkceChallenge(verifier),
		scope:        "mcp",
		resourceRaw:  server.issuer + resource,
		resourcePath: resource,
		generation:   server.tokenGeneration,
	}
	code, created, err := server.createAuthorizationCodeLocked(context.Background(), request)
	server.mu.Unlock()
	if err != nil || !created {
		t.Fatalf("create durable authorization code: created=%v err=%v", created, err)
	}
	return code
}

func tokenExchange(server *Server, values url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.handleToken(rec, req)
	return rec
}

func TestDurableOAuthGrantsSurviveRestartAndRemainBound(t *testing.T) {
	store := newMemoryDurableOAuthStore()
	epochs := map[string]string{"/mcp": "root-v1"}
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	first := newDurableOAuthServer(t, store, epochs, &now)
	const clientID = "mcp_durable_client"
	const redirectURI = "https://client.example/callback"
	verifier := strings.Repeat("v", 64)

	code := createDurableCode(t, first, clientID, redirectURI, verifier, "/mcp")
	second := newDurableOAuthServer(t, store, epochs, &now)
	firstExchange := tokenExchange(second, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if firstExchange.Code != http.StatusOK {
		t.Fatalf("cross-replica code redemption = %d, body %s", firstExchange.Code, firstExchange.Body)
	}
	_, refresh := decodeTokenResponse(t, firstExchange)
	if refresh == "" {
		t.Fatal("durable code redemption did not issue a refresh token")
	}
	if replay := tokenExchange(first, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}); replay.Code != http.StatusBadRequest {
		t.Fatalf("authorization code replay = %d, want 400; body %s", replay.Code, replay.Body)
	}

	third := newDurableOAuthServer(t, store, epochs, &now)
	if refreshExchange := tokenExchange(third, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}); refreshExchange.Code != http.StatusOK {
		t.Fatalf("cross-restart refresh redemption = %d, body %s", refreshExchange.Code, refreshExchange.Body)
	}

	// Endpoint recreation is a new security principal. The old grant must not
	// gain the replacement epoch even before cleanup has had a chance to run.
	staleCode := createDurableCode(t, first, clientID, redirectURI, verifier, "/mcp")
	epochs["/mcp"] = "root-v2"
	fourth := newDurableOAuthServer(t, store, epochs, &now)
	if stale := tokenExchange(fourth, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {staleCode},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}); stale.Code != http.StatusBadRequest {
		t.Fatalf("recreated-endpoint code redemption = %d, want 400; body %s", stale.Code, stale.Body)
	}
	if staleRefresh := tokenExchange(fourth, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}); staleRefresh.Code != http.StatusBadRequest {
		t.Fatalf("recreated-endpoint refresh redemption = %d, want 400; body %s", staleRefresh.Code, staleRefresh.Body)
	}

	now = now.Add(refreshTTL + time.Second)
	expired := newDurableOAuthServer(t, store, epochs, &now)
	if rec := tokenExchange(expired, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired refresh redemption = %d, want 400; body %s", rec.Code, rec.Body)
	}
}

func TestDurableOAuthRevocationsReachOtherReplicas(t *testing.T) {
	store := newMemoryDurableOAuthStore()
	epochs := map[string]string{"/mcp": "root-v1"}
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	first := newDurableOAuthServer(t, store, epochs, &now)
	const clientID = "mcp_durable_client"
	const redirectURI = "https://client.example/callback"
	verifier := strings.Repeat("v", 64)

	issueRefresh := func(server *Server) string {
		t.Helper()
		code := createDurableCode(t, server, clientID, redirectURI, verifier, "/mcp")
		rec := tokenExchange(server, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("issue refresh = %d, body %s", rec.Code, rec.Body)
		}
		_, refresh := decodeTokenResponse(t, rec)
		return refresh
	}

	refresh := issueRefresh(first)
	first.RevokeResource("/mcp")
	other := newDurableOAuthServer(t, store, epochs, &now)
	if rec := tokenExchange(other, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("resource-revoked refresh = %d, want 400; body %s", rec.Code, rec.Body)
	}

	refresh = issueRefresh(other)
	if err := first.RevokeAll(context.Background()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	afterAll := newDurableOAuthServer(t, store, epochs, &now)
	if rec := tokenExchange(afterAll, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("workspace-revoked refresh = %d, want 400; body %s", rec.Code, rec.Body)
	}
}

func TestEpochScopedResourceRevocationKeepsReplacementGrants(t *testing.T) {
	store := newMemoryDurableOAuthStore()
	epochs := map[string]string{"/mcp": "root-v1"}
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	first := newDurableOAuthServer(t, store, epochs, &now)
	const clientID = "mcp_durable_client"
	const redirectURI = "https://client.example/callback"
	verifier := strings.Repeat("v", 64)

	exchange := func(server *Server) string {
		t.Helper()
		code := createDurableCode(t, server, clientID, redirectURI, verifier, "/mcp")
		rec := tokenExchange(server, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifier},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("exchange = %d, body %s", rec.Code, rec.Body)
		}
		_, refresh := decodeTokenResponse(t, rec)
		return refresh
	}

	oldRefresh := exchange(first)
	epochs["/mcp"] = "root-v2"
	replacement := newDurableOAuthServer(t, store, epochs, &now)
	newRefresh := exchange(replacement)

	first.RevokeResourceAtEpoch("/mcp", "root-v1")
	if rec := tokenExchange(replacement, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {newRefresh},
		"client_id":     {clientID},
	}); rec.Code != http.StatusOK {
		t.Fatalf("replacement refresh after old-epoch cleanup = %d, body %s", rec.Code, rec.Body)
	}
	if _, found, err := store.LoadRefreshGrant(context.Background(), durableGrantTokenHash(oldRefresh), now); err != nil || found {
		t.Fatalf("retired-epoch refresh found=%v err=%v", found, err)
	}
}
