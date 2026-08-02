package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
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
	if c.Decrypt("legacy-plain") != "legacy-plain" {
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
