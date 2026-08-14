package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"narthex/backend/internal/oauthas"
)

func TestEnginePostgresPoolConfigIsCapacityBounded(t *testing.T) {
	config, err := enginePostgresPoolConfig(
		"postgres://engine:secret@127.0.0.1:5432/engine" +
			"?sslmode=disable&pool_max_conns=99&pool_min_conns=8",
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxConns != enginePostgresMaxConns {
		t.Fatalf("MaxConns = %d, want %d", config.MaxConns, enginePostgresMaxConns)
	}
	if config.MinConns != 0 {
		t.Fatalf("MinConns = %d, want 0", config.MinConns)
	}
	if config.MaxConnLifetime != enginePostgresMaxConnLifetime {
		t.Fatalf(
			"MaxConnLifetime = %s, want %s",
			config.MaxConnLifetime,
			enginePostgresMaxConnLifetime,
		)
	}
	if config.MaxConnIdleTime != enginePostgresMaxConnIdleTime {
		t.Fatalf(
			"MaxConnIdleTime = %s, want %s",
			config.MaxConnIdleTime,
			enginePostgresMaxConnIdleTime,
		)
	}
}

func TestPgStoreTokenGenerationPersistsAndUsesCASRotation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	first, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer first.Close()
	if _, err := first.pool.Exec(ctx, `DELETE FROM narthex_engine_state WHERE key='oauth_token_generation'`); err != nil {
		t.Fatalf("reset token generation: %v", err)
	}
	defer first.pool.Exec(ctx, `DELETE FROM narthex_engine_state WHERE key='oauth_token_generation'`)

	generation, err := first.LoadOrCreateTokenGeneration(ctx, "generation-one")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration: %v", err)
	}
	if generation != "generation-one" {
		t.Fatalf("initial generation = %q, want generation-one", generation)
	}

	second, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	generation, err = second.LoadOrCreateTokenGeneration(ctx, "must-not-replace")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration after restart: %v", err)
	}
	if generation != "generation-one" {
		t.Fatalf("restart replaced generation with %q", generation)
	}
	current, err := second.CurrentTokenGeneration(ctx)
	if err != nil {
		t.Fatalf("CurrentTokenGeneration after restart: %v", err)
	}
	if current != "generation-one" {
		t.Fatalf("current generation = %q, want generation-one", current)
	}
	generation, err = second.RotateTokenGeneration(ctx, "generation-one", "generation-two")
	if err != nil {
		t.Fatalf("RotateTokenGeneration: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("rotated generation = %q, want generation-two", generation)
	}

	// first is now a stale Engine instance. Its compare-and-swap must return
	// the newer value instead of overwriting the revocation.
	generation, err = first.RotateTokenGeneration(ctx, "generation-one", "stale-replacement")
	if err != nil {
		t.Fatalf("stale RotateTokenGeneration: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("stale rotation overwrote current generation with %q", generation)
	}

	third, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("second reopen: %v", err)
	}
	defer third.Close()
	generation, err = third.LoadOrCreateTokenGeneration(ctx, "must-not-resurrect")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration after rotation: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("rotated generation did not persist: %q", generation)
	}
}

func TestPgStoreOAuthGrantStateSurvivesRestartAndConsumesCodesOnce(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	first, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer first.Close()
	for _, table := range []string{
		"narthex_oauth_authorization_codes",
		"narthex_oauth_refresh_grants",
		"narthex_oauth_hosted_consent_replays",
	} {
		if _, err := first.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("reset %s: %v", table, err)
		}
	}
	defer func() {
		for _, table := range []string{
			"narthex_oauth_authorization_codes",
			"narthex_oauth_refresh_grants",
			"narthex_oauth_hosted_consent_replays",
		} {
			_, _ = first.pool.Exec(context.Background(), "DELETE FROM "+table)
		}
	}()

	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	code := oauthas.DurableAuthorizationCode{
		TokenHash: "pg-code-hash-that-is-long-enough-to-be-a-digest-0001",
		ClientID:  "client-1", RedirectURI: "https://client.example/callback",
		Challenge: "challenge", Scope: "mcp", Resource: "/mcp/team",
		ResourceEpoch: "team-v1", Generation: "workspace-v1", ExpiresAt: now.Add(time.Minute),
	}
	if err := first.StoreAuthorizationCode(ctx, code); err != nil {
		t.Fatalf("StoreAuthorizationCode: %v", err)
	}

	second, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore after restart: %v", err)
	}
	defer second.Close()
	got, found, err := second.ConsumeAuthorizationCode(ctx, code.TokenHash, now)
	if err != nil || !found || got.ClientID != code.ClientID || got.ResourceEpoch != code.ResourceEpoch {
		t.Fatalf("durable code consume = %+v found=%v err=%v", got, found, err)
	}
	if _, found, err := first.ConsumeAuthorizationCode(ctx, code.TokenHash, now); err != nil || found {
		t.Fatalf("authorization code replay found=%v err=%v", found, err)
	}

	refresh := oauthas.DurableRefreshGrant{
		TokenHash: "pg-refresh-hash-that-is-long-enough-to-be-a-digest-01",
		ClientID:  "client-1", Resource: "/mcp/team", ResourceEpoch: "team-v1",
		Generation: "workspace-v1", ExpiresAt: now.Add(time.Hour),
	}
	replacementRefresh := oauthas.DurableRefreshGrant{
		TokenHash: "pg-replacement-refresh-hash-long-enough-digest-002",
		ClientID:  "client-1", Resource: "/mcp/team", ResourceEpoch: "team-v2",
		Generation: "workspace-v1", ExpiresAt: now.Add(time.Hour),
	}
	if err := first.StoreRefreshGrant(ctx, refresh); err != nil {
		t.Fatalf("StoreRefreshGrant: %v", err)
	}
	if err := first.StoreRefreshGrant(ctx, replacementRefresh); err != nil {
		t.Fatalf("StoreRefreshGrant replacement: %v", err)
	}
	if got, found, err := second.LoadRefreshGrant(ctx, refresh.TokenHash, now); err != nil || !found || got.Generation != refresh.Generation {
		t.Fatalf("durable refresh = %+v found=%v err=%v", got, found, err)
	}

	reserved, err := first.ReserveHostedConsentReplay(
		ctx,
		"pg-reservation-opaque-identifier",
		"approval:pg-opaque-jti-0001",
		"request:pg-opaque-request-hash-0001",
		now.Add(time.Minute),
		now,
	)
	if err != nil || !reserved {
		t.Fatalf("ReserveHostedConsentReplay = %v, %v", reserved, err)
	}
	if reserved, err := second.ReserveHostedConsentReplay(
		ctx,
		"pg-second-reservation-opaque-id",
		"approval:pg-opaque-jti-0001",
		"request:pg-other-request-hash-0001",
		now.Add(time.Minute),
		now,
	); err != nil || reserved {
		t.Fatalf("replayed consent reservation = %v, %v", reserved, err)
	}
	if err := second.FinalizeHostedConsentReplay(ctx, "pg-reservation-opaque-identifier"); err != nil {
		t.Fatalf("FinalizeHostedConsentReplay: %v", err)
	}
	if err := second.RevokeOAuthGrantsForResourceEpoch(ctx, "/mcp/team", "team-v1"); err != nil {
		t.Fatalf("RevokeOAuthGrantsForResourceEpoch: %v", err)
	}
	if _, found, err := first.LoadRefreshGrant(ctx, refresh.TokenHash, now); err != nil || found {
		t.Fatalf("resource-revoked refresh found=%v err=%v", found, err)
	}
	if _, found, err := first.LoadRefreshGrant(ctx, replacementRefresh.TokenHash, now); err != nil || !found {
		t.Fatalf("replacement-epoch refresh found=%v err=%v", found, err)
	}
}

// TestPgStoreCRUD exercises the Postgres AccountStore against a real Postgres.
// Gated on TEST_DATABASE_URL so it only runs when a DB is provided (no Notion
// needed): proves Upsert, Accounts, Token, RefreshToken, and that UpdateTokens
// PERSISTS — the property that makes tokens survive Cloud Run restarts.
func TestPgStoreCRUD(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name='pgtest'`)

	// Upsert an oauth account.
	if err := s.Upsert(ctx, Account{
		Name: "pgtest", Label: "PG Test", Group: "W", URL: "https://x/mcp", AuthMode: "oauth",
		ClientID: "cid", ClientSecret: "csec", AccessToken: "A1", RefreshToken: "R1",
		TokenEndpoint: "https://x/token", Resource: "https://x/mcp", Scope: "channels:read chat:write",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := s.Create(ctx, Account{
		Name: "pgtest", Label: "Replacement", URL: "https://replacement.example/mcp", AuthMode: "token", BearerToken: "replacement",
	}); !errors.Is(err, ErrAccountExists) {
		t.Fatalf("Create duplicate = %v; want ErrAccountExists", err)
	}
	if got, ok := s.Account("pgtest"); !ok || got.Label != "PG Test" || got.URL != "https://x/mcp" || got.BearerToken != "" {
		t.Fatalf("Create duplicate mutated existing row: %+v ok=%v", got, ok)
	}

	if got := s.Token("pgtest"); got != "A1" {
		t.Fatalf("Token: want A1, got %q", got)
	}
	if got := s.RefreshToken("pgtest"); got != "R1" {
		t.Fatalf("RefreshToken: want R1, got %q", got)
	}
	refreshAccount, _ := s.Account("pgtest")

	// The load-bearing assertion: refreshed tokens persist.
	if err := s.UpdateTokens(ctx, "pgtest", refreshAccount.IncarnationID, "A2", "R2"); err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}
	// Re-open a fresh store to prove it's in the DB, not memory.
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if got := s2.Token("pgtest"); got != "A2" {
		t.Fatalf("persisted access token: want A2, got %q", got)
	}
	if got := s2.RefreshToken("pgtest"); got != "R2" {
		t.Fatalf("persisted refresh token: want R2, got %q", got)
	}

	// Upsert with empty refresh must NOT wipe the stored refresh token.
	if err := s.UpdateTokens(ctx, "pgtest", refreshAccount.IncarnationID, "A3", ""); err != nil {
		t.Fatalf("UpdateTokens (no refresh): %v", err)
	}
	if got := s.RefreshToken("pgtest"); got != "R2" {
		t.Fatalf("empty refresh should keep R2, got %q", got)
	}

	// Accounts() round-trips all fields.
	found := false
	for _, a := range s.Accounts() {
		if a.Name == "pgtest" {
			found = true
			if a.AuthMode != "oauth" || a.Group != "W" || a.ClientID != "cid" || a.AccessToken != "A3" {
				t.Fatalf("Accounts round-trip mismatch: %+v", a)
			}
			if a.Scope != "channels:read chat:write" {
				t.Fatalf("Accounts lost scope: %q", a.Scope)
			}
		}
	}
	if !found {
		t.Fatal("Accounts() did not return the upserted account")
	}

	// disabled_tools (text[]) round-trips.
	if err := s.SetDisabledTools(ctx, "pgtest", []string{"foo", "bar"}); err != nil {
		t.Fatalf("SetDisabledTools: %v", err)
	}
	got, _ := s.Account("pgtest")
	if len(got.DisabledTools) != 2 || got.DisabledTools[0] != "foo" || got.DisabledTools[1] != "bar" {
		t.Fatalf("disabled tools round-trip: want [foo bar], got %v", got.DisabledTools)
	}
	if got.Scope != "channels:read chat:write" {
		t.Fatalf("Account lost scope: %q", got.Scope)
	}

	// read_only defaults false, flips via SetReadOnly, and round-trips
	// through Account, Accounts, and Upsert.
	if got.ReadOnly {
		t.Fatal("fresh account should default to ReadOnly=false")
	}
	if err := s.SetReadOnly(ctx, "pgtest", true); err != nil {
		t.Fatalf("SetReadOnly: %v", err)
	}
	got, _ = s.Account("pgtest")
	if !got.ReadOnly {
		t.Fatal("SetReadOnly(true) not persisted")
	}
	for _, a := range s.Accounts() {
		if a.Name == "pgtest" && !a.ReadOnly {
			t.Fatal("Accounts() lost read_only")
		}
	}
	got.ReadOnly = false
	if err := s.Upsert(ctx, got); err != nil {
		t.Fatalf("Upsert (read_only=false): %v", err)
	}
	if a, _ := s.Account("pgtest"); a.ReadOnly {
		t.Fatal("Upsert did not update read_only")
	}

	// OAuth completion updates auth columns under a row lock while preserving
	// namespace/label/tool policy written during the browser consent window.
	if err := s.SetMeta(ctx, "pgtest", "Moved account", got.Group); err != nil {
		t.Fatalf("SetMeta before CompleteOAuth: %v", err)
	}
	if err := s.SetReadOnly(ctx, "pgtest", true); err != nil {
		t.Fatalf("SetReadOnly before CompleteOAuth: %v", err)
	}
	if err := s.SetToolOverride(ctx, "pgtest", "foo", ToolOverride{Alias: "find_foo"}); err != nil {
		t.Fatalf("SetToolOverride before CompleteOAuth: %v", err)
	}
	beforeCompletion, ok := s.Account("pgtest")
	if !ok {
		t.Fatal("pgtest missing before CompleteOAuth")
	}
	completionPrecondition := oauthCompletionPreconditionForAccount(beforeCompletion)
	completionPrecondition.URL = "https://X:443/mcp"
	completed, err := s.CompleteOAuth(ctx, completionPrecondition, Account{
		Name: "pgtest", ClientID: "cid", ClientSecret: "new-secret", AccessToken: "A4",
		TokenEndpoint: "https://x/new-token", Resource: "https://x/mcp", Scope: "new-scope",
	})
	if err != nil {
		t.Fatalf("CompleteOAuth: %v", err)
	}
	if completed.Label != "Moved account" || completed.Group != got.Group || !completed.ReadOnly ||
		len(completed.DisabledTools) != 2 || completed.ToolOverrides["foo"].Alias != "find_foo" {
		t.Fatalf("CompleteOAuth lost metadata/policy: %+v", completed)
	}
	if completed.AccessToken != "A4" || completed.RefreshToken != "R2" || completed.ClientSecret != "new-secret" {
		t.Fatalf("CompleteOAuth credentials = %+v", completed)
	}
	attackerPrecondition := oauthCompletionPreconditionForAccount(completed)
	attackerPrecondition.URL = "https://attacker.example/mcp"
	if _, err := s.CompleteOAuth(ctx, attackerPrecondition, Account{
		Name: "pgtest", ClientID: "cid", AccessToken: "attacker-token",
	}); !errors.Is(err, ErrConnectAccountURLChanged) {
		t.Fatalf("retargeted CompleteOAuth = %v, want ErrConnectAccountURLChanged", err)
	}
	if got := s.Token("pgtest"); got != "A4" {
		t.Fatalf("rejected CompleteOAuth changed access token to %q", got)
	}
}

func TestPgStoreAccountPolicyCASRejectsMovedSnapshot(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres account-policy integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	suffix := strings.ToLower(newEpoch())
	accountName := "pg_account_policy_" + suffix
	var source, target ConnectionNamespace
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		if target.ID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, target.ID)
		}
		if source.ID != "" {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, source.ID)
		}
	}
	defer cleanup()

	source, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG policy source " + suffix})
	if err != nil {
		t.Fatalf("create source namespace: %v", err)
	}
	target, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG policy target " + suffix})
	if err != nil {
		t.Fatalf("create target namespace: %v", err)
	}
	if err := store.Create(ctx, Account{
		Name: accountName, Label: "Policy source", Group: source.Label,
		URL: "https://pg-policy.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	before, ok := store.Account(accountName)
	if !ok {
		t.Fatal("created account missing")
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, before.Name, before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, before.Revision); err != nil {
		t.Fatalf("move account: %v", err)
	}
	label := "stale label"
	disabled := []string{"delete"}
	if _, err := store.UpdateAccountPolicy(ctx, before.Name, accountPolicyPrecondition(before), AccountPolicyMutation{
		Label: &label, DisabledTools: &disabled,
	}); !errors.Is(err, ErrAccountPolicyPrecondition) {
		t.Fatalf("stale policy write = %v, want ErrAccountPolicyPrecondition", err)
	}
	after, ok := store.Account(before.Name)
	if !ok || after.ConnectionNamespaceID != target.ID || after.Label != "Policy source" || len(after.DisabledTools) != 0 {
		t.Fatalf("stale policy write changed moved account: %+v", after)
	}
}

func TestPgStoreOAuthCompletionRejectsDeletedAndRecreatedAccount(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	const (
		accountName = "pg_oauth_incarnation"
		groupName   = "PG OAuth Incarnation"
	)
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE label=$1`, groupName)
	}
	cleanup()
	defer cleanup()

	if err := store.Create(ctx, Account{
		Name: accountName, Group: groupName, URL: "https://notion.example/mcp",
		AuthMode: "token", BearerToken: "first-token", IncarnationID: "caller-first",
	}); err != nil {
		t.Fatalf("Create first account: %v", err)
	}
	first, ok := store.Account(accountName)
	if !ok || first.IncarnationID == "" || first.IncarnationID == "caller-first" {
		t.Fatalf("first account incarnation = %+v, ok=%v", first, ok)
	}
	precondition := oauthCompletionPreconditionForAccount(first)

	if err := store.Delete(ctx, accountName, first.IncarnationID, first.Revision); err != nil {
		t.Fatalf("Delete first account: %v", err)
	}
	if err := store.Create(ctx, Account{
		Name: accountName, Group: groupName, URL: first.URL,
		AuthMode: "token", BearerToken: "replacement-token", IncarnationID: first.IncarnationID,
	}); err != nil {
		t.Fatalf("Create replacement account: %v", err)
	}
	replacement, ok := store.Account(accountName)
	if !ok || replacement.IncarnationID == "" || replacement.IncarnationID == first.IncarnationID {
		t.Fatalf("replacement account reused first incarnation: %+v, ok=%v", replacement, ok)
	}
	if err := store.UpdateTokens(ctx, accountName, first.IncarnationID, "stale-access", "stale-refresh"); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale UpdateTokens = %v, want ErrAccountIncarnation", err)
	}
	if err := store.Delete(ctx, accountName, first.IncarnationID, first.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale Delete = %v, want ErrAccountIncarnation", err)
	}
	if _, err := store.SetBearerToken(ctx, accountName, first.IncarnationID, "stale-bearer", replacement.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale SetBearerToken = %v, want ErrAccountIncarnation", err)
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, accountName, first.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: replacement.ConnectionNamespaceID,
		Scope:                 replacement.ConnectionScope,
		OwnerSubject:          replacement.OwnerSubject,
	}, replacement.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale MoveAccountToConnectionNamespace = %v, want ErrAccountIncarnation", err)
	}

	if _, err := store.CompleteOAuth(ctx, precondition, Account{
		Name: accountName, ClientID: "stale-client", AccessToken: "stale-access",
	}); !errors.Is(err, ErrConnectAccountReplaced) {
		t.Fatalf("stale CompleteOAuth = %v, want ErrConnectAccountReplaced", err)
	}
	current, _ := store.Account(accountName)
	if current.BearerToken != "replacement-token" || current.AccessToken != "" || current.AuthMode != "token" {
		t.Fatalf("stale callback mutated replacement account: %+v", current)
	}
}

func TestPgStoreConnectionNamespaceBackfillCASAndPersonalExposureGate(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const legacyAccount = "pg_connection_namespace_legacy"
	const personalAccount = "pg_connection_namespace_personal"
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug='pg-connection-namespace-tools'`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_namespaces WHERE slug='pg-connection-namespace-endpoint'`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name IN ($1,$2)`, legacyAccount, personalAccount)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE slug IN ('pg-connection-namespace-legacy','pg-connection-namespace-team','pg-connection-namespace-personal')`)
	}
	cleanup()
	defer cleanup()

	// Insert a Group-only row after the constructor's migration, then reopen:
	// this proves rolling data is backfilled as shared rather than guessing
	// that a label means personal.
	if _, err := store.pool.Exec(ctx, `
INSERT INTO narthex_accounts (name,workspace,url,auth_mode,bearer_token)
VALUES ($1,'PG Connection Namespace Legacy','https://legacy.example/mcp','token','legacy')`, legacyAccount); err != nil {
		t.Fatalf("insert legacy account: %v", err)
	}
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	legacy, ok := reopened.Account(legacyAccount)
	if !ok || legacy.ConnectionScope != ConnectionScopeShared || legacy.ConnectionNamespaceID == "" || legacy.Revision != 1 {
		t.Fatalf("legacy account after pg backfill = %+v, ok=%v", legacy, ok)
	}
	legacyNS, ok := reopened.ConnectionNamespace(ctx, legacy.ConnectionNamespaceID)
	if !ok || legacyNS.Label != "PG Connection Namespace Legacy" || legacyNS.CreatedAt.IsZero() || legacyNS.UpdatedAt.IsZero() {
		t.Fatalf("legacy connection namespace = %+v, ok=%v", legacyNS, ok)
	}

	team, err := reopened.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG Connection Namespace Team", CreatedBy: "user:owner"})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	if !sameManagerGrants(team.ManagerGrants, []ConnectionNamespaceManagerGrant{{Subject: "user:owner"}}) {
		t.Fatalf("creator manager grant = %+v", team.ManagerGrants)
	}
	team, err = reopened.SetConnectionNamespaceManagers(ctx, team.ID, nil, connectionNamespacePrecondition(team))
	if err != nil {
		t.Fatalf("revoke creator manager grant: %v", err)
	}
	if len(team.ManagerGrants) != 0 || connectionNamespaceManager(team, "user:owner") {
		t.Fatalf("creator manager grant remained after revocation: %+v", team.ManagerGrants)
	}
	if persisted, ok := reopened.ConnectionNamespace(ctx, team.ID); !ok || len(persisted.ManagerGrants) != 0 || persisted.CreatedBy != "user:owner" {
		t.Fatalf("persisted creator revocation = %+v ok=%v", persisted, ok)
	}
	personal, err := reopened.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG Connection Namespace Personal", CreatedBy: "user:alice"})
	if err != nil {
		t.Fatalf("create personal namespace: %v", err)
	}
	if err := reopened.Create(ctx, Account{
		Name: personalAccount, ConnectionNamespaceID: team.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://personal.example/mcp", AuthMode: "token", BearerToken: "personal",
	}); err != nil {
		t.Fatalf("create shared account: %v", err)
	}
	before, _ := reopened.Account(personalAccount)
	moved, err := reopened.MoveAccountToConnectionNamespace(ctx, personalAccount, before.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: personal.ID, Scope: ConnectionScopePersonal, OwnerSubject: "user:alice",
	}, before.Revision)
	if err != nil {
		t.Fatalf("move personal: %v", err)
	}
	if moved.Name != personalAccount || moved.ConnectionScope != ConnectionScopePersonal || moved.ConnectionNamespaceID != personal.ID || moved.Revision != before.Revision+1 {
		t.Fatalf("moved account = %+v", moved)
	}
	if err := reopened.CreateNamespace(ctx, Namespace{Slug: "pg-connection-namespace-endpoint", Accounts: []string{personalAccount}}); !errors.Is(err, ErrPersonalAccountExposure) {
		t.Fatalf("endpoint allowed personal account: %v", err)
	}
	if err := reopened.UpsertConnector(ctx, VirtualConnector{Slug: "pg-connection-namespace-tools", Tools: map[string][]string{personalAccount: {"search"}}}); !errors.Is(err, ErrPersonalAccountExposure) {
		t.Fatalf("connector allowed personal account: %v", err)
	}
}

func TestPgStoreUpsertOwnsRevisionMonotonicity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	const accountName = "pg_upsert_revision_acme"
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, accountName)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE slug IN ('pg-upsert-revision-source','pg-upsert-revision-target')`)
	}
	cleanup()
	defer cleanup()

	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG Upsert Revision Source"})
	if err != nil {
		t.Fatalf("create source namespace: %v", err)
	}
	target, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "PG Upsert Revision Target"})
	if err != nil {
		t.Fatalf("create target namespace: %v", err)
	}

	// The create path still honors an explicit positive revision.
	if err := store.Upsert(ctx, Account{
		Name: accountName, Group: source.Label,
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://acme.example/mcp", AuthMode: "token", BearerToken: "secret",
		Revision: 3,
	}); err != nil {
		t.Fatalf("create via Upsert: %v", err)
	}
	created, ok := store.Account(accountName)
	if !ok || created.Revision != 3 {
		t.Fatalf("create honoring explicit revision = %+v, want Revision 3", created)
	}

	// A caller-supplied regression is ignored: unchanged ownership preserves 3.
	stale := created
	stale.Revision = 1
	stale.Label = "Renamed"
	if err := store.Upsert(ctx, stale); err != nil {
		t.Fatalf("update via Upsert: %v", err)
	}
	after, _ := store.Account(accountName)
	if after.Revision != 3 || after.Label != "Renamed" {
		t.Fatalf("caller-supplied revision regressed the row: %+v", after)
	}

	// An ownership change bumps from the locked prior row, not the caller's value.
	moved := after
	moved.Revision = 1
	moved.ConnectionNamespaceID = target.ID
	moved.Group = target.Label
	if err := store.Upsert(ctx, moved); err != nil {
		t.Fatalf("ownership move via Upsert: %v", err)
	}
	afterMove, _ := store.Account(accountName)
	if afterMove.Revision != 4 || afterMove.ConnectionNamespaceID != target.ID {
		t.Fatalf("ownership move revision = %+v, want Revision 4 in target namespace", afterMove)
	}
}

func TestPgStoreNamespacesPersistCascadeAndShareSlugDomain(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pg_namespace_team','pg_namespace_connector')`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_namespaces WHERE slug IN ('pg_namespace_team','pg_namespace_second','pg_namespace_connector')`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name IN ('pg_namespace_linear','pg_namespace_notion')`)
	}
	cleanup()
	defer cleanup()

	for _, account := range []Account{
		{Name: "pg_namespace_linear", URL: "https://linear.example/mcp", AuthMode: "token", BearerToken: "linear-token"},
		{Name: "pg_namespace_notion", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "notion-token"},
	} {
		if err := store.Upsert(ctx, account); err != nil {
			t.Fatalf("upsert %s: %v", account.Name, err)
		}
	}
	if err := store.CreateNamespace(ctx, Namespace{
		Slug: "pg_namespace_team", Label: "Team", Epoch: "team-epoch",
		Accounts: []string{"pg_namespace_linear", "pg_namespace_notion"},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	if err := store.CreateNamespace(ctx, Namespace{
		Slug: "pg_namespace_second", Label: "Second", Epoch: "second-epoch",
		Accounts: []string{"pg_namespace_linear"},
	}); err != nil {
		t.Fatalf("create second namespace: %v", err)
	}
	teamBefore, _ := store.Namespace(ctx, "pg_namespace_team")
	team, err := store.AddNamespaceAccount(
		ctx,
		"pg_namespace_team",
		"pg_namespace_linear",
		preconditionOf(teamBefore),
	)
	if err != nil {
		t.Fatalf("idempotent membership: %v", err)
	}
	if team.Revision != 1 {
		t.Fatalf("idempotent membership revision = %d, want 1", team.Revision)
	}

	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	team, ok := reopened.Namespace(ctx, "pg_namespace_team")
	if !ok || team.Epoch != "team-epoch" ||
		!sameStrings(team.Accounts, []string{"pg_namespace_linear", "pg_namespace_notion"}) {
		t.Fatalf("reopened namespace = %+v, ok=%v", team, ok)
	}

	if err := reopened.UpsertConnector(ctx, VirtualConnector{Slug: "pg_namespace_team", Label: "Collision"}); !errors.Is(err, ErrEndpointCollision) {
		t.Fatalf("connector collision = %v, want ErrEndpointCollision", err)
	}
	if err := reopened.UpsertConnector(ctx, VirtualConnector{
		Slug: "pg_namespace_connector", Label: "Connector",
		Tools: map[string][]string{
			"pg_namespace_linear": {"get_issue", "save_issue"},
			"pg_namespace_notion": {"search"},
		},
		Approval: map[string][]string{
			"pg_namespace_linear": {"save_issue"},
			"pg_namespace_notion": {"search"},
		},
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	if err := reopened.CreateNamespace(ctx, Namespace{Slug: "pg_namespace_connector", Label: "Collision"}); !errors.Is(err, ErrEndpointCollision) {
		t.Fatalf("namespace collision = %v, want ErrEndpointCollision", err)
	}

	linear, _ := reopened.Account("pg_namespace_linear")
	if err := reopened.Delete(ctx, "pg_namespace_linear", linear.IncarnationID, linear.Revision); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	team, _ = reopened.Namespace(ctx, "pg_namespace_team")
	if team.Revision != 2 || !sameStrings(team.Accounts, []string{"pg_namespace_notion"}) {
		t.Fatalf("team after account cascade = %+v", team)
	}
	second, _ := reopened.Namespace(ctx, "pg_namespace_second")
	if second.Revision != 2 || len(second.Accounts) != 0 {
		t.Fatalf("second after account cascade = %+v", second)
	}
	if reopened.Token("pg_namespace_notion") != "notion-token" {
		t.Fatal("account cascade changed unrelated credentials")
	}
	connector, _ := reopened.VirtualConnector(ctx, "pg_namespace_connector")
	if _, exists := connector.Tools["pg_namespace_linear"]; exists {
		t.Fatalf("deleted account remains in connector tools: %+v", connector.Tools)
	}
	if _, exists := connector.Approval["pg_namespace_linear"]; exists {
		t.Fatalf("deleted account remains in connector approval: %+v", connector.Approval)
	}
	if !sameStrings(connector.Tools["pg_namespace_notion"], []string{"search"}) ||
		!sameStrings(connector.Approval["pg_namespace_notion"], []string{"search"}) {
		t.Fatalf("account delete changed unrelated connector entries: %+v", connector)
	}
	if err := reopened.DeleteNamespace(ctx, "pg_namespace_team", preconditionOf(team)); err != nil {
		t.Fatalf("delete namespace: %v", err)
	}
	if _, ok := reopened.Account("pg_namespace_notion"); !ok || reopened.Token("pg_namespace_notion") != "notion-token" {
		t.Fatal("namespace deletion removed its member account")
	}
}

func TestPgStoreNamespaceCASRejectsReplicaStalenessAndCrossKindReuse(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	first, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	defer first.Close()
	second, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	defer second.Close()
	const slug = "pg_namespace_cas"
	cleanup := func() {
		_, _ = first.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug=$1`, slug)
		_, _ = first.pool.Exec(ctx, `DELETE FROM narthex_namespaces WHERE slug=$1`, slug)
		_, _ = first.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name IN ('pg_namespace_cas_a','pg_namespace_cas_b')`)
	}
	cleanup()
	defer cleanup()
	for _, account := range []Account{
		{Name: "pg_namespace_cas_a", URL: "https://a.example/mcp", AuthMode: "token", BearerToken: "a"},
		{Name: "pg_namespace_cas_b", URL: "https://b.example/mcp", AuthMode: "token", BearerToken: "b"},
	} {
		if err := first.Upsert(ctx, account); err != nil {
			t.Fatalf("upsert %s: %v", account.Name, err)
		}
	}
	if err := first.CreateNamespace(ctx, Namespace{
		Slug: slug, Label: "First", Epoch: "namespace-generation-one",
		Accounts: []string{"pg_namespace_cas_a"},
	}); err != nil {
		t.Fatalf("create first namespace: %v", err)
	}
	old, _ := first.Namespace(ctx, slug)
	stale := preconditionOf(old)
	if err := second.DeleteNamespace(ctx, slug, stale); err != nil {
		t.Fatalf("replica delete first namespace: %v", err)
	}
	if err := second.CreateNamespace(ctx, Namespace{
		Slug: slug, Label: "Second", Epoch: "namespace-generation-two",
		Accounts: []string{"pg_namespace_cas_b"},
	}); err != nil {
		t.Fatalf("recreate namespace: %v", err)
	}
	current, _ := second.Namespace(ctx, slug)
	if current.Revision != stale.Revision {
		t.Fatalf("test requires recreated revision reset: old=%d new=%d", stale.Revision, current.Revision)
	}
	if _, err := first.UpdateNamespace(ctx, Namespace{
		Slug: slug, Label: "stale", Accounts: []string{"pg_namespace_cas_a"},
	}, stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale replica full update = %v, want ErrNamespaceRevision", err)
	}
	if _, err := first.AddNamespaceAccount(
		ctx, slug, "pg_namespace_cas_a", stale,
	); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale replica membership add = %v, want ErrNamespaceRevision", err)
	}
	if _, err := first.RemoveNamespaceAccount(
		ctx, slug, "pg_namespace_cas_b", stale,
	); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale replica membership delete = %v, want ErrNamespaceRevision", err)
	}
	if err := first.DeleteNamespace(ctx, slug, stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale replica namespace delete = %v, want ErrNamespaceRevision", err)
	}

	if err := second.DeleteNamespace(ctx, slug, preconditionOf(current)); err != nil {
		t.Fatalf("delete current namespace: %v", err)
	}
	if err := second.UpsertConnector(ctx, VirtualConnector{
		Slug: slug, Label: "Connector reuse", Epoch: "connector-generation",
		Tools: map[string][]string{"pg_namespace_cas_a": {"get"}},
	}); err != nil {
		t.Fatalf("reuse slug as connector: %v", err)
	}
	if err := first.DeleteNamespace(ctx, slug, stale); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("stale namespace delete after connector reuse = %v, want ErrNamespaceNotFound", err)
	}
	if connector, ok := first.VirtualConnector(ctx, slug); !ok || connector.Epoch != "connector-generation" {
		t.Fatalf("stale namespace delete removed reused connector: %+v ok=%v", connector, ok)
	}
	if err := first.DeleteConnector(ctx, slug, "wrong-generation"); !errors.Is(err, ErrEndpointGeneration) {
		t.Fatalf("wrong-generation connector delete = %v, want ErrEndpointGeneration", err)
	}
	if err := second.DeleteConnector(ctx, slug, "connector-generation"); err != nil {
		t.Fatalf("delete current connector: %v", err)
	}
	if err := second.CreateNamespace(ctx, Namespace{
		Slug: slug, Label: "Third", Epoch: "namespace-generation-three",
		Accounts: []string{"pg_namespace_cas_a"},
	}); err != nil {
		t.Fatalf("reuse slug as namespace: %v", err)
	}
	if err := first.DeleteConnector(ctx, slug, "connector-generation"); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("stale connector delete after namespace reuse = %v, want ErrConnectorNotFound", err)
	}
	if namespace, ok := first.Namespace(ctx, slug); !ok || namespace.Epoch != "namespace-generation-three" {
		t.Fatalf("stale connector delete removed reused namespace: %+v ok=%v", namespace, ok)
	}
}

func TestPgStoreEncryption(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	ctx := context.Background()
	c, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name='enctest'`)
	s.SetCipher(c)
	if err := s.Upsert(ctx, Account{Name: "enctest", URL: "u", AuthMode: "oauth", AccessToken: "secret-access", RefreshToken: "secret-refresh", ClientSecret: "csec"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// reads decrypt
	a, _ := s.Account("enctest")
	if a.AccessToken != "secret-access" || a.RefreshToken != "secret-refresh" || a.ClientSecret != "csec" {
		t.Fatalf("decrypt on read failed: %+v", a)
	}
	if s.RefreshToken("enctest") != "secret-refresh" {
		t.Fatal("RefreshToken did not decrypt")
	}
	// at rest it is encrypted, not plaintext
	var raw string
	s.pool.QueryRow(ctx, `SELECT access_token FROM narthex_accounts WHERE name='enctest'`).Scan(&raw)
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("not encrypted at rest: %q", raw)
	}
	if strings.Contains(raw, "secret-access") {
		t.Fatal("plaintext leaked into the column")
	}
	// legacy plaintext (no prefix) passes through
	legacy, err := c.Decrypt("legacy-plain")
	if err != nil || legacy != "legacy-plain" {
		t.Fatal("legacy plaintext not passed through")
	}
}

// TestPgStoreConnectorCRUD exercises the Postgres ConnectorStore: JSONB
// round-trip, upsert-updates-in-place, persistence across a fresh pool, and
// delete. Gated on TEST_DATABASE_URL like the other Pg tests.
func TestPgStoreConnectorCRUD(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgconn','pgconn-nil')`)

	vc := VirtualConnector{
		Slug:   "pgconn",
		Label:  "PG Connector",
		Tools:  map[string][]string{"acct1": {"list_issues", "get_issue"}, "acct2": {}},
		Record: true,
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgconn")
	if !ok {
		t.Fatal("VirtualConnector: not found after upsert")
	}
	if got.Label != "PG Connector" || len(got.Tools["acct1"]) != 2 || got.Tools["acct1"][0] != "list_issues" {
		t.Fatalf("JSONB round-trip mismatch: %+v", got)
	}
	if !got.Record {
		t.Fatalf("Record flag lost in round-trip: %+v", got)
	}

	// nil Tools must not write SQL null into the NOT NULL JSONB column.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgconn-nil", Label: "Nil Tools"}); err != nil {
		t.Fatalf("UpsertConnector (nil tools): %v", err)
	}
	if gotNil, ok := s.VirtualConnector(ctx, "pgconn-nil"); !ok {
		t.Fatal("nil-tools connector not readable back")
	} else if gotNil.Record {
		t.Fatal("Record must default to false")
	}

	// Same slug updates in place, and it persists across a fresh pool.
	vc.Label = "PG v2"
	vc.Tools["acct1"] = []string{"list_issues"}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector (update): %v", err)
	}
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got2, ok := s2.VirtualConnector(ctx, "pgconn")
	if !ok {
		t.Fatal("connector missing after reopen")
	}
	if got2.Label != "PG v2" || len(got2.Tools["acct1"]) != 1 {
		t.Fatalf("persisted update mismatch: %+v", got2)
	}

	// Connectors() lists what we wrote.
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range list {
		seen[c.Slug] = true
	}
	if !seen["pgconn"] || !seen["pgconn-nil"] {
		t.Fatalf("Connectors() missing rows: %+v", list)
	}

	// Delete is generation-bound and a second stale delete fails closed.
	if err := s2.DeleteConnector(ctx, "pgconn", got2.Epoch); err != nil {
		t.Fatalf("DeleteConnector: %v", err)
	}
	if _, ok := s2.VirtualConnector(ctx, "pgconn"); ok {
		t.Fatal("connector still present after delete")
	}
	if err := s2.DeleteConnector(ctx, "pgconn", got2.Epoch); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("DeleteConnector after removal = %v, want ErrConnectorNotFound", err)
	}
}

// TestPgStoreConnectorApproval proves the approval JSONB column round-trips
// (including nil → '{}', never SQL null) and persists across a fresh pool.
func TestPgStoreConnectorApproval(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgappr','pgappr-nil')`)

	vc := VirtualConnector{
		Slug:     "pgappr",
		Label:    "Approval",
		Tools:    map[string][]string{"acct1": {"list_issues", "delete_issue"}},
		Approval: map[string][]string{"acct1": {"delete_issue"}},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgappr")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if len(got.Approval["acct1"]) != 1 || got.Approval["acct1"][0] != "delete_issue" {
		t.Fatalf("approval JSONB round-trip mismatch: %+v", got.Approval)
	}

	// nil Approval must not write SQL null into the NOT NULL JSONB column.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgappr-nil", Label: "Nil Approval",
		Tools: map[string][]string{"acct1": {"t1"}}}); err != nil {
		t.Fatalf("UpsertConnector (nil approval): %v", err)
	}
	gotNil, ok := s.VirtualConnector(ctx, "pgappr-nil")
	if !ok {
		t.Fatal("nil-approval connector not readable back")
	}
	if len(gotNil.Approval) != 0 {
		t.Fatalf("nil approval should read back empty, got %+v", gotNil.Approval)
	}

	// Persists across a fresh pool (and Connectors() carries it too).
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	found := false
	for _, c := range list {
		if c.Slug == "pgappr" {
			found = true
			if len(c.Approval["acct1"]) != 1 || c.Approval["acct1"][0] != "delete_issue" {
				t.Fatalf("Connectors() approval mismatch: %+v", c.Approval)
			}
		}
	}
	if !found {
		t.Fatal("Connectors() missing pgappr")
	}
}

// TestPgStoreConnectorGuardrails proves max_result_bytes and redact round-trip
// through Postgres (including nil Redact → '[]', never SQL null) and persist
// across a fresh pool.
func TestPgStoreConnectorGuardrails(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgguard','pgguard-nil')`)

	vc := VirtualConnector{
		Slug:           "pgguard",
		Label:          "Guarded",
		Tools:          map[string][]string{"acct1": {"get_issue"}},
		MaxResultBytes: 8192,
		Redact:         []string{`\bsk-[A-Za-z0-9]+\b`, `(?i)password`},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgguard")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if got.MaxResultBytes != 8192 {
		t.Fatalf("max_result_bytes round-trip: want 8192, got %d", got.MaxResultBytes)
	}
	if len(got.Redact) != 2 || got.Redact[0] != `\bsk-[A-Za-z0-9]+\b` || got.Redact[1] != `(?i)password` {
		t.Fatalf("redact JSONB round-trip mismatch: %+v", got.Redact)
	}

	// nil Redact / zero MaxResultBytes must not write SQL null and read back
	// as zero values.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgguard-nil", Label: "Nil Guard",
		Tools: map[string][]string{"acct1": {"t1"}}}); err != nil {
		t.Fatalf("UpsertConnector (nil redact): %v", err)
	}
	gotNil, ok := s.VirtualConnector(ctx, "pgguard-nil")
	if !ok {
		t.Fatal("nil-guard connector not readable back")
	}
	if gotNil.MaxResultBytes != 0 || len(gotNil.Redact) != 0 {
		t.Fatalf("nil guard fields should read back zero, got %+v", gotNil)
	}

	// Persists across a fresh pool (and Connectors() carries the fields too).
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	found := false
	for _, c := range list {
		if c.Slug == "pgguard" {
			found = true
			if c.MaxResultBytes != 8192 || len(c.Redact) != 2 {
				t.Fatalf("Connectors() guardrail fields mismatch: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("Connectors() missing pgguard")
	}
}

// TestPgStorePendingCalls exercises the pending_calls ApprovalLog: insert,
// list newest-first, decide (status + decided_at), args JSONB round-trip.
func TestPgStorePendingCalls(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id IN ('pc1','pc2')`)

	base := time.Now().Truncate(time.Millisecond)
	if err := s.LogPending(ctx, PendingCall{ID: "pc1", TS: base.Add(-time.Minute), Connector: "eng",
		Account: "acct1", Tool: "delete_issue", Args: map[string]any{"id": "42"}, Status: "pending"}); err != nil {
		t.Fatalf("LogPending pc1: %v", err)
	}
	// Zero TS gets stamped server-side-of-Go (now).
	if err := s.LogPending(ctx, PendingCall{ID: "pc2", Connector: "eng", Account: "acct1",
		Tool: "save_issue", Status: "pending"}); err != nil {
		t.Fatalf("LogPending pc2: %v", err)
	}

	list, err := s.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls: %v", err)
	}
	byID := map[string]PendingCall{}
	idx := map[string]int{}
	for i, p := range list {
		byID[p.ID] = p
		idx[p.ID] = i
	}
	p1, ok1 := byID["pc1"]
	p2, ok2 := byID["pc2"]
	if !ok1 || !ok2 {
		t.Fatalf("inserted rows missing from PendingCalls: %+v", list)
	}
	if idx["pc2"] > idx["pc1"] {
		t.Fatal("PendingCalls should be newest-first (pc2 before pc1)")
	}
	if p1.Args["id"] != "42" || p1.Status != "pending" || p1.DecidedAt != nil || p1.TS.IsZero() {
		t.Fatalf("pc1 round-trip mismatch: %+v", p1)
	}
	if p2.TS.IsZero() {
		t.Fatal("zero TS should have been stamped")
	}

	// Decision persists across a fresh pool.
	if err := s.SetDecision(ctx, "pc1", "denied"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list2, err := s2.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls (reopen): %v", err)
	}
	for _, p := range list2 {
		if p.ID == "pc1" {
			if p.Status != "denied" || p.DecidedAt == nil {
				t.Fatalf("decision not persisted: %+v", p)
			}
			return
		}
	}
	t.Fatal("pc1 missing after reopen")
}

// TestPgStoreApprovalRecovery keeps the post-restart lifecycle honest: only
// truly overdue calls become expired. A non-expired call had its MCP request
// interrupted, so it is cancelled rather than implicitly replayed or called a
// timeout.
func TestPgStoreApprovalRecovery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id IN ('recovery-expired','recovery-cancelled','recovery-approved')`)

	now := time.Now().Truncate(time.Millisecond)
	for _, p := range []PendingCall{
		{ID: "recovery-expired", TS: now.Add(-2 * time.Minute), ExpiresAt: ptrTime(now.Add(-time.Second)), Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending},
		{ID: "recovery-cancelled", TS: now, ExpiresAt: ptrTime(now.Add(time.Minute)), Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending},
		{ID: "recovery-approved", TS: now, ExpiresAt: ptrTime(now.Add(time.Minute)), Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending},
	} {
		if err := s.LogPending(ctx, p); err != nil {
			t.Fatalf("LogPending %s: %v", p.ID, err)
		}
	}
	if _, err := s.DecidePending(ctx, "recovery-approved", ApprovalDecision{Status: ApprovalApproved, Actor: "platform:test"}); err != nil {
		t.Fatalf("approve pre-existing decision: %v", err)
	}

	recovery, err := s.RecoverPendingApprovals(ctx, now)
	if err != nil {
		t.Fatalf("RecoverPendingApprovals: %v", err)
	}
	if recovery.Expired != 1 || recovery.Cancelled != 1 {
		t.Fatalf("recovery = %+v, want one expired and one cancelled", recovery)
	}
	for wantID, wantStatus := range map[string]string{
		"recovery-expired":   ApprovalExpired,
		"recovery-cancelled": ApprovalCancelled,
		"recovery-approved":  ApprovalApproved,
	} {
		p, found, err := s.ApprovalCall(ctx, wantID)
		if err != nil || !found || p.Status != wantStatus {
			t.Fatalf("%s = found=%v err=%v row=%+v, want %s", wantID, found, err, p, wantStatus)
		}
	}
}

func ptrTime(v time.Time) *time.Time { return &v }

// TestPgStoreFlightRecorder exercises the payload columns: encrypted at rest,
// hidden from list reads, decrypted by CallDetail, and purged by retention.
func TestPgStoreFlightRecorder(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account='fr-test'`)
	c, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	s.SetCipher(c)

	s.LogCall(CallRecord{
		Account: "fr-test", Tool: "save_issue", OK: true, Ms: 12,
		Connector: "eng", EndpointKind: endpointKindConnector,
		EndpointGeneration: "eng-generation", Decision: "approved", Guard: "truncated,redacted:2",
		Args: `{"secret":"payload-in"}`, Result: `{"secret":"payload-out"}`,
	})

	// LogCall is fire-and-forget — poll for the row.
	var got CallRecord
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, err := s.RecentCalls(ctx, 50)
		if err != nil {
			t.Fatalf("RecentCalls: %v", err)
		}
		found := false
		for _, r := range list {
			if r.Account == "fr-test" {
				got, found = r, true
				break
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit row never appeared")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// List read: summary fields present (guard included — the Activity UI
	// chips on it), payloads absent.
	if got.ID == 0 || got.TS.IsZero() || got.Connector != "eng" || got.Decision != "approved" {
		t.Fatalf("summary fields mismatch: %+v", got)
	}
	if got.EndpointKind != endpointKindConnector || got.EndpointGeneration != "eng-generation" {
		t.Fatalf("summary endpoint identity mismatch: %+v", got)
	}
	if got.Guard != "truncated,redacted:2" {
		t.Fatalf("RecentCalls must include guard, got %q", got.Guard)
	}
	if got.Args != "" || got.Result != "" {
		t.Fatalf("RecentCalls must not return payloads: %+v", got)
	}

	// Detail read decrypts (and carries guard too).
	d, ok, err := s.CallDetail(ctx, got.ID)
	if err != nil || !ok {
		t.Fatalf("CallDetail: ok=%v err=%v", ok, err)
	}
	if d.Args != `{"secret":"payload-in"}` || d.Result != `{"secret":"payload-out"}` {
		t.Fatalf("payload round-trip mismatch: %+v", d)
	}
	if d.Guard != "truncated,redacted:2" {
		t.Fatalf("CallDetail guard mismatch: %q", d.Guard)
	}
	if d.EndpointKind != endpointKindConnector || d.EndpointGeneration != "eng-generation" {
		t.Fatalf("CallDetail endpoint identity mismatch: %+v", d)
	}

	// At rest the payloads are encrypted, not plaintext.
	var rawArgs, rawResult, rawKind, rawGeneration string
	if err := s.pool.QueryRow(ctx, `
SELECT args,result,endpoint_kind,endpoint_generation FROM tool_calls WHERE id=$1`, got.ID).
		Scan(&rawArgs, &rawResult, &rawKind, &rawGeneration); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if rawKind != endpointKindConnector || rawGeneration != "eng-generation" {
		t.Fatalf("endpoint identity not persisted: kind=%q generation=%q", rawKind, rawGeneration)
	}
	if !strings.HasPrefix(rawArgs, "enc:v1:") || strings.Contains(rawArgs, "payload-in") {
		t.Fatalf("args not encrypted at rest: %q", rawArgs)
	}
	if !strings.HasPrefix(rawResult, "enc:v1:") || strings.Contains(rawResult, "payload-out") {
		t.Fatalf("result not encrypted at rest: %q", rawResult)
	}

	// Unknown ID is a clean miss.
	if _, ok, err := s.CallDetail(ctx, -1); ok || err != nil {
		t.Fatalf("unknown id: want (false,nil), got ok=%v err=%v", ok, err)
	}

	// Retention: an old row is purged, the fresh one survives.
	if _, err := s.pool.Exec(ctx, `INSERT INTO tool_calls (ts,account,tool,ok,ms) VALUES (now() - interval '48 hours','fr-test','old_tool',true,1)`); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	n, err := s.PurgeCalls(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PurgeCalls: %v", err)
	}
	if n < 1 {
		t.Fatalf("purge should delete the 48h-old row, deleted %d", n)
	}
	if _, ok, _ := s.CallDetail(ctx, got.ID); !ok {
		t.Fatal("purge must not delete fresh rows")
	}
	var oldCount int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM tool_calls WHERE account='fr-test' AND tool='old_tool'`).Scan(&oldCount)
	if oldCount != 0 {
		t.Fatal("old row still present after purge")
	}
}

// TestPgStoreAuditFieldsEncryptedAtRest proves the audit error column goes
// through the same cipher as the payload columns without needing a live
// Postgres: encryptAuditFields is the exact value preparation persistAuditCall
// inserts.
func TestPgStoreAuditFieldsEncryptedAtRest(t *testing.T) {
	store := &PgStore{cipher: testCipher(t, 5)}
	const errorSecret = "upstream 401: https://api.example/mcp?token=secret-echo"
	args, result, auditErr, err := store.encryptAuditFields(CallRecord{
		Args:   `{"secret":"payload-in"}`,
		Result: `{"secret":"payload-out"}`,
		Error:  errorSecret,
	})
	if err != nil {
		t.Fatalf("encryptAuditFields: %v", err)
	}
	for name, value := range map[string]string{"args": args, "result": result, "error": auditErr} {
		if !strings.HasPrefix(value, encPrefix) {
			t.Fatalf("%s not encrypted: %q", name, value)
		}
	}
	if strings.Contains(auditErr, "secret-echo") {
		t.Fatalf("error ciphertext embeds plaintext: %q", auditErr)
	}
	plain, err := store.dec(auditErr)
	if err != nil || plain != errorSecret {
		t.Fatalf("error round-trip = %q, %v", plain, err)
	}

	// Clamping happens before encryption, so the stored ciphertext unwraps to
	// the bounded text rather than failing a size check on read.
	long := strings.Repeat("x", 600)
	_, _, clamped, err := store.encryptAuditFields(CallRecord{Error: long})
	if err != nil {
		t.Fatalf("encryptAuditFields long error: %v", err)
	}
	plain, err = store.dec(clamped)
	if err != nil || len(plain) > 500 {
		t.Fatalf("clamped error round-trip len=%d err=%v", len(plain), err)
	}

	// Legacy plaintext rows (written before encryption covered these columns)
	// keep reading through the passthrough.
	legacy, err := store.dec("plain legacy error")
	if err != nil || legacy != "plain legacy error" {
		t.Fatalf("legacy dec = %q, %v", legacy, err)
	}

	// No cipher configured (self-hosted development): values stay plaintext,
	// same as the token columns.
	plainStore := &PgStore{}
	_, _, auditErr, err = plainStore.encryptAuditFields(CallRecord{Error: errorSecret})
	if err != nil || auditErr != errorSecret {
		t.Fatalf("cipherless encryptAuditFields = %q, %v", auditErr, err)
	}
}

// fakePendingRow feeds scanPendingCall without a database, in pendingCallColumns
// order.
type fakePendingRow struct {
	id          string
	ts          time.Time
	connector   string
	account     string
	incarnation string
	revision    int64
	namespace   string
	tool        string
	args        string
	status      string
	expires     time.Time
	decidedAt   *time.Time
	decidedBy   string
	note        string
}

func (f fakePendingRow) Scan(dest ...any) error {
	if len(dest) != 14 {
		return errors.New("fake pending row column count mismatch")
	}
	*dest[0].(*string) = f.id
	*dest[1].(*time.Time) = f.ts
	*dest[2].(*string) = f.connector
	*dest[3].(*string) = f.account
	*dest[4].(*string) = f.incarnation
	*dest[5].(*int64) = f.revision
	*dest[6].(*string) = f.namespace
	*dest[7].(*string) = f.tool
	*dest[8].(*string) = f.args
	*dest[9].(*string) = f.status
	*dest[10].(*time.Time) = f.expires
	*dest[11].(**time.Time) = f.decidedAt
	*dest[12].(*string) = f.decidedBy
	*dest[13].(*string) = f.note
	return nil
}

func TestScanPendingCallDecryptsDecisionMetadata(t *testing.T) {
	store := &PgStore{cipher: testCipher(t, 6)}
	encActor, err := store.enc("platform:admin@example.com")
	if err != nil {
		t.Fatalf("enc actor: %v", err)
	}
	encNote, err := store.enc("approved while investigating token=secret-note")
	if err != nil {
		t.Fatalf("enc note: %v", err)
	}
	if !strings.HasPrefix(encActor, encPrefix) || !strings.HasPrefix(encNote, encPrefix) {
		t.Fatalf("decision metadata not encrypted: actor=%q note=%q", encActor, encNote)
	}
	decided := time.Now().Truncate(time.Second)
	p, err := store.scanPendingCall(fakePendingRow{
		id: "enc-1", ts: decided, connector: "work", account: "linear",
		incarnation: "inc-1", revision: 3, namespace: "ns-1",
		tool: "save", args: `{}`, status: ApprovalApproved,
		expires: decided.Add(time.Minute), decidedAt: &decided,
		decidedBy: encActor, note: encNote,
	})
	if err != nil {
		t.Fatalf("scanPendingCall encrypted: %v", err)
	}
	if p.DecidedBy != "platform:admin@example.com" || p.DecisionNote != "approved while investigating token=secret-note" {
		t.Fatalf("decision metadata mismatch: %+v", p)
	}

	// Rows decided before encryption covered these columns (including the
	// engine-written SQL literals) stay readable.
	p, err = store.scanPendingCall(fakePendingRow{
		id: "legacy-1", ts: decided, connector: "work", account: "linear",
		incarnation: "inc-1", revision: 3, namespace: "ns-1",
		tool: "save", args: `{}`, status: ApprovalExpired,
		expires: decided.Add(-time.Minute), decidedAt: &decided,
		decidedBy: "engine", note: "approval deadline elapsed",
	})
	if err != nil {
		t.Fatalf("scanPendingCall legacy: %v", err)
	}
	if p.DecidedBy != "engine" || p.DecisionNote != "approval deadline elapsed" {
		t.Fatalf("legacy decision metadata mismatch: %+v", p)
	}
}

// TestPgStoreAuditErrorAndDecisionMetadataEncrypted is the live-Postgres proof:
// encrypted at rest, decrypted on every read path, legacy plaintext intact.
func TestPgStoreAuditErrorAndDecisionMetadataEncrypted(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account='err-enc-test'`)
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id IN ('err-enc-decide','err-enc-cancel','err-enc-legacy')`)
	s.SetCipher(testCipher(t, 4))

	const errorSecret = "upstream 401: https://api.example/mcp?token=secret-echo"
	s.LogCall(CallRecord{Account: "err-enc-test", Tool: "save_issue", OK: false, Ms: 3, Error: errorSecret})

	// LogCall is fire-and-forget — poll for the row.
	var got CallRecord
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, err := s.RecentCalls(ctx, 50)
		if err != nil {
			t.Fatalf("RecentCalls: %v", err)
		}
		found := false
		for _, r := range list {
			if r.Account == "err-enc-test" && r.Tool == "save_issue" {
				got, found = r, true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit row never appeared")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got.Error != errorSecret {
		t.Fatalf("RecentCalls error = %q, want decrypted %q", got.Error, errorSecret)
	}
	var rawError string
	if err := s.pool.QueryRow(ctx, `SELECT error FROM tool_calls WHERE id=$1`, got.ID).Scan(&rawError); err != nil {
		t.Fatalf("raw error read: %v", err)
	}
	if !strings.HasPrefix(rawError, encPrefix) || strings.Contains(rawError, "secret-echo") {
		t.Fatalf("error not encrypted at rest: %q", rawError)
	}
	detail, ok, err := s.CallDetail(ctx, got.ID)
	if err != nil || !ok {
		t.Fatalf("CallDetail: ok=%v err=%v", ok, err)
	}
	if detail.Error != errorSecret {
		t.Fatalf("CallDetail error = %q, want decrypted %q", detail.Error, errorSecret)
	}

	// A legacy plaintext error row still reads through both surfaces.
	if _, err := s.pool.Exec(ctx, `
INSERT INTO tool_calls (ts,account,tool,ok,ms,error) VALUES (now(),'err-enc-test','legacy_tool',false,1,'legacy plain error')`); err != nil {
		t.Fatalf("insert legacy error row: %v", err)
	}
	list, err := s.RecentCalls(ctx, 50)
	if err != nil {
		t.Fatalf("RecentCalls legacy: %v", err)
	}
	legacyFound := false
	for _, r := range list {
		if r.Account == "err-enc-test" && r.Tool == "legacy_tool" {
			if r.Error != "legacy plain error" {
				t.Fatalf("legacy error via RecentCalls = %q", r.Error)
			}
			legacyFound = true
		}
	}
	if !legacyFound {
		t.Fatal("legacy plaintext error row missing from RecentCalls")
	}

	// Approval decision metadata: encrypted at rest, decrypted on read.
	now := time.Now()
	for _, id := range []string{"err-enc-decide", "err-enc-cancel", "err-enc-legacy"} {
		if err := s.LogPending(ctx, PendingCall{
			ID: id, TS: now, ExpiresAt: ptrTime(now.Add(time.Minute)),
			Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending,
		}); err != nil {
			t.Fatalf("LogPending %s: %v", id, err)
		}
	}
	if _, err := s.DecidePending(ctx, "err-enc-decide", ApprovalDecision{
		Status: ApprovalApproved, Actor: "platform:admin@example.com", Note: "approved with token=secret-note",
	}); err != nil {
		t.Fatalf("DecidePending: %v", err)
	}
	if _, err := s.CancelPending(ctx, "err-enc-cancel", "platform:admin@example.com", "cancelled with token=secret-note"); err != nil {
		t.Fatalf("CancelPending: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `
UPDATE pending_calls SET status='denied', decided_at=now(), decided_by='legacy-admin', decision_note='legacy plain note'
WHERE id='err-enc-legacy'`); err != nil {
		t.Fatalf("write legacy decision row: %v", err)
	}

	for id, want := range map[string][2]string{
		"err-enc-decide": {"platform:admin@example.com", "approved with token=secret-note"},
		"err-enc-cancel": {"platform:admin@example.com", "cancelled with token=secret-note"},
		"err-enc-legacy": {"legacy-admin", "legacy plain note"},
	} {
		p, found, err := s.ApprovalCall(ctx, id)
		if err != nil || !found {
			t.Fatalf("ApprovalCall %s: found=%v err=%v", id, found, err)
		}
		if p.DecidedBy != want[0] || p.DecisionNote != want[1] {
			t.Fatalf("%s decision = %q/%q, want %q/%q", id, p.DecidedBy, p.DecisionNote, want[0], want[1])
		}
	}
	var rawActor, rawNote string
	if err := s.pool.QueryRow(ctx, `SELECT decided_by, decision_note FROM pending_calls WHERE id='err-enc-decide'`).Scan(&rawActor, &rawNote); err != nil {
		t.Fatalf("raw decision read: %v", err)
	}
	if !strings.HasPrefix(rawActor, encPrefix) || !strings.HasPrefix(rawNote, encPrefix) ||
		strings.Contains(rawNote, "secret-note") {
		t.Fatalf("decision metadata not encrypted at rest: actor=%q note=%q", rawActor, rawNote)
	}
}

// TestPgStoreEncryptExistingBackfillsAuditAndDecisionMetadata proves the
// startup migration (EncryptExisting) covers the write-once tool_calls.error
// and pending_calls.decided_by/decision_note columns, not just args/result.
// Those columns are only ever written at insert/decision time and never
// UPDATEd again, so a row written before this backfill pass existed would
// otherwise stay plaintext-at-rest permanently, with no remediation path.
func TestPgStoreEncryptExistingBackfillsAuditAndDecisionMetadata(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account='backfill-test'`)
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id='backfill-pending'`)

	// Simulate rows written in production before this PR's cipher (and this
	// backfill pass) covered these columns: plain SQL inserts with no cipher
	// involved, exactly like real pre-existing rows.
	var callID int64
	if err := s.pool.QueryRow(ctx, `
INSERT INTO tool_calls (ts,account,tool,ok,ms,error)
VALUES (now(),'backfill-test','legacy_tool',false,1,'legacy error token=secret-err')
RETURNING id`).Scan(&callID); err != nil {
		t.Fatalf("insert legacy tool_calls row: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO pending_calls (id,ts,connector,account,tool,args,status,expires_at,decided_at,decided_by,decision_note)
VALUES ('backfill-pending',now(),'work','linear','save','{}','denied',now()+interval '1 minute',now(),'legacy-admin','legacy note token=secret-note')`); err != nil {
		t.Fatalf("insert legacy pending_calls row: %v", err)
	}

	// Precondition: both rows are plaintext at rest before any cipher exists.
	var rawErr, rawDecidedBy, rawNote string
	if err := s.pool.QueryRow(ctx, `SELECT error FROM tool_calls WHERE id=$1`, callID).Scan(&rawErr); err != nil {
		t.Fatalf("read raw error: %v", err)
	}
	if rawErr != "legacy error token=secret-err" {
		t.Fatalf("precondition: tool_calls.error not plaintext: %q", rawErr)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT decided_by,decision_note FROM pending_calls WHERE id='backfill-pending'`,
	).Scan(&rawDecidedBy, &rawNote); err != nil {
		t.Fatalf("read raw decision metadata: %v", err)
	}
	if rawDecidedBy != "legacy-admin" || rawNote != "legacy note token=secret-note" {
		t.Fatalf("precondition: pending_calls decision metadata not plaintext: %q / %q", rawDecidedBy, rawNote)
	}

	// Enable encryption and run the startup migration, exactly as
	// configureStoreEncryption does at boot when ENGINE_ENCRYPTION_KEY is set.
	s.SetCipher(testCipher(t, 8))
	if err := s.EncryptExisting(ctx); err != nil {
		t.Fatalf("EncryptExisting: %v", err)
	}

	if err := s.pool.QueryRow(ctx, `SELECT error FROM tool_calls WHERE id=$1`, callID).Scan(&rawErr); err != nil {
		t.Fatalf("read backfilled error: %v", err)
	}
	if !strings.HasPrefix(rawErr, encPrefix) || strings.Contains(rawErr, "secret-err") {
		t.Fatalf("tool_calls.error not encrypted at rest after backfill: %q", rawErr)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT decided_by,decision_note FROM pending_calls WHERE id='backfill-pending'`,
	).Scan(&rawDecidedBy, &rawNote); err != nil {
		t.Fatalf("read backfilled decision metadata: %v", err)
	}
	if !strings.HasPrefix(rawDecidedBy, encPrefix) || !strings.HasPrefix(rawNote, encPrefix) ||
		strings.Contains(rawNote, "secret-note") {
		t.Fatalf("pending_calls decision metadata not encrypted at rest after backfill: %q / %q", rawDecidedBy, rawNote)
	}

	// The backfilled values still read back correctly through the normal
	// decrypt-on-read paths.
	list, err := s.RecentCalls(ctx, 50)
	if err != nil {
		t.Fatalf("RecentCalls: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == callID {
			if r.Error != "legacy error token=secret-err" {
				t.Fatalf("RecentCalls error after backfill = %q", r.Error)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("backfilled tool_calls row missing from RecentCalls")
	}
	p, ok, err := s.ApprovalCall(ctx, "backfill-pending")
	if err != nil || !ok {
		t.Fatalf("ApprovalCall: ok=%v err=%v", ok, err)
	}
	if p.DecidedBy != "legacy-admin" || p.DecisionNote != "legacy note token=secret-note" {
		t.Fatalf("ApprovalCall decision metadata after backfill = %q / %q", p.DecidedBy, p.DecisionNote)
	}

	// Idempotent: re-running the migration (as happens on every boot) must not
	// change already-encrypted ciphertext, mirroring encryptExistingCallPayloads'
	// existing pattern for args/result.
	if err := s.EncryptExisting(ctx); err != nil {
		t.Fatalf("EncryptExisting (second run): %v", err)
	}
	var rawErrAgain, rawDecidedByAgain, rawNoteAgain string
	if err := s.pool.QueryRow(ctx, `SELECT error FROM tool_calls WHERE id=$1`, callID).Scan(&rawErrAgain); err != nil {
		t.Fatalf("read error after second run: %v", err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT decided_by,decision_note FROM pending_calls WHERE id='backfill-pending'`,
	).Scan(&rawDecidedByAgain, &rawNoteAgain); err != nil {
		t.Fatalf("read decision metadata after second run: %v", err)
	}
	if rawErrAgain != rawErr || rawDecidedByAgain != rawDecidedBy || rawNoteAgain != rawNote {
		t.Fatal("EncryptExisting is not idempotent: re-running changed already-encrypted ciphertext")
	}
}

// TestPgStoreRecentCallsOmitsUndecryptableErrorButKeepsRow proves a single
// row with a corrupted/undecryptable error field no longer takes down the
// whole RecentCalls response. Before the fix, s.dec failure on the error
// column did `continue`, dropping the entire row (id/ts/account/tool/etc,
// none of which needed decryption) with no log line — and since only
// non-empty errors are ever ciphertext, that disproportionately hid
// FAILED-call rows, exactly what an incident investigator needs most.
func TestPgStoreRecentCallsOmitsUndecryptableErrorButKeepsRow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account='recentcalls-undecryptable'`)
	s.SetCipher(testCipher(t, 12))

	s.LogCall(CallRecord{Account: "recentcalls-undecryptable", Tool: "good_call", OK: true, Ms: 1})
	s.LogCall(CallRecord{Account: "recentcalls-undecryptable", Tool: "bad_call", OK: false, Ms: 2, Error: "will be corrupted"})

	// LogCall is fire-and-forget — poll until both rows land.
	var badID int64
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, err := s.RecentCalls(ctx, 50)
		if err != nil {
			t.Fatalf("RecentCalls: %v", err)
		}
		goodFound, badFound := false, false
		for _, r := range list {
			if r.Account != "recentcalls-undecryptable" {
				continue
			}
			if r.Tool == "good_call" {
				goodFound = true
			}
			if r.Tool == "bad_call" {
				badFound, badID = true, r.ID
			}
		}
		if goodFound && badFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit rows never appeared")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Corrupt the bad row's ciphertext directly: a value this cipher can no
	// longer authenticate (wrong/rotated key, bit rot, truncation).
	if _, err := s.pool.Exec(ctx, `UPDATE tool_calls SET error=$2 WHERE id=$1`,
		badID, encPrefix+"not-valid-base64!!"); err != nil {
		t.Fatalf("corrupt error column: %v", err)
	}

	var logBuf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	list, err := s.RecentCalls(ctx, 50)
	if err != nil {
		t.Fatalf("RecentCalls with corrupted row: %v", err)
	}

	var good, bad *CallRecord
	for i := range list {
		if list[i].Account != "recentcalls-undecryptable" {
			continue
		}
		switch list[i].Tool {
		case "good_call":
			good = &list[i]
		case "bad_call":
			bad = &list[i]
		}
	}
	if good == nil {
		t.Fatal("unrelated good row was dropped from RecentCalls")
	}
	if bad == nil {
		t.Fatal("row with an undecryptable error field was dropped from RecentCalls instead of being kept")
	}
	if bad.Error != undecryptableAuditErrorPlaceholder {
		t.Fatalf("bad row error = %q, want placeholder %q", bad.Error, undecryptableAuditErrorPlaceholder)
	}
	if bad.ID != badID || bad.Tool != "bad_call" || bad.OK {
		t.Fatalf("bad row's non-error fields were not preserved intact: %+v", bad)
	}
	if !strings.Contains(logBuf.String(), fmt.Sprintf("%d", badID)) {
		t.Fatalf("omission was not logged with the row id %d: log=%q", badID, logBuf.String())
	}
}

// TestPgStorePendingCallsOmitsUndecryptableRowButKeepsRest proves a single
// pending_calls row with corrupted/undecryptable decision metadata no longer
// fails the whole PendingCalls list. Before the fix, scanPendingCall's error
// propagated straight out of PendingCalls, which console.go turns into an
// HTTP 502 for every user — hiding all pending and historical approvals, not
// just the one bad record.
func TestPgStorePendingCallsOmitsUndecryptableRowButKeepsRest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id IN ('pendingcalls-good','pendingcalls-bad')`)
	s.SetCipher(testCipher(t, 13))

	now := time.Now()
	if err := s.LogPending(ctx, PendingCall{
		ID: "pendingcalls-good", TS: now, ExpiresAt: ptrTime(now.Add(time.Minute)),
		Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending,
	}); err != nil {
		t.Fatalf("LogPending good: %v", err)
	}
	if err := s.LogPending(ctx, PendingCall{
		ID: "pendingcalls-bad", TS: now, ExpiresAt: ptrTime(now.Add(time.Minute)),
		Connector: "work", Account: "linear", Tool: "save", Status: ApprovalPending,
	}); err != nil {
		t.Fatalf("LogPending bad: %v", err)
	}
	if _, err := s.DecidePending(ctx, "pendingcalls-bad", ApprovalDecision{
		Status: ApprovalDenied, Actor: "admin", Note: "will be corrupted",
	}); err != nil {
		t.Fatalf("DecidePending: %v", err)
	}
	// Corrupt the decided row's decision_note ciphertext directly: a value
	// this cipher can no longer authenticate.
	if _, err := s.pool.Exec(ctx, `UPDATE pending_calls SET decision_note=$2 WHERE id=$1`,
		"pendingcalls-bad", encPrefix+"not-valid-base64!!"); err != nil {
		t.Fatalf("corrupt decision_note column: %v", err)
	}

	var logBuf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	list, err := s.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls with one corrupted row: %v", err)
	}
	var goodFound, badFound bool
	for _, p := range list {
		switch p.ID {
		case "pendingcalls-good":
			goodFound = true
		case "pendingcalls-bad":
			badFound = true
		}
	}
	if !goodFound {
		t.Fatal("unrelated good pending row was dropped from PendingCalls")
	}
	if badFound {
		t.Fatal("row with undecryptable decision metadata was returned instead of being skipped")
	}
	if !strings.Contains(logBuf.String(), "pendingcalls-bad") {
		t.Fatalf("omission was not logged with the row id: log=%q", logBuf.String())
	}
}
