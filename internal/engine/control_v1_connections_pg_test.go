package engine

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The PgStore half of the control v1 connections suite. Database-gated and
// named to match the PgStore integration filter.

func newPgConnectionsStore(t *testing.T) *PgStore {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres control v1 connections tests")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	// Secrets are written under this test's key; every fixture is removed
	// again so no row survives into a test that holds another key.
	store.SetCipher(testCipher(t, 0x5c))
	return store
}

func TestPgControlConnectionsCreateIdenticalRetryReturns200(t *testing.T) {
	testControlConnectionsCreateIdenticalRetry(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsDifferentBodyConflicts(t *testing.T) {
	testControlConnectionsDifferentBodyConflicts(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsIdempotencyKeyReplays(t *testing.T) {
	testControlConnectionsIdempotencyKeyReplays(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsPatchRevisionFence(t *testing.T) {
	testControlConnectionsPatchRevisionFence(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsTokenPutRevisionFence(t *testing.T) {
	testControlConnectionsTokenPutRevisionFence(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsDeleteIdempotent(t *testing.T) {
	testControlConnectionsDeleteIdempotent(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsProblemDetails(t *testing.T) {
	testControlConnectionsProblemDetails(t, newPgConnectionsStore(t))
}

func TestPgCallerDelegatedDTOHasNoSecrets(t *testing.T) {
	testCallerDelegatedDTOHasNoSecrets(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsPatchCannotRetargetStoredSecrets(t *testing.T) {
	testControlConnectionsPatchCannotRetargetStoredSecrets(t, newPgConnectionsStore(t))
}

func TestPgControlConnectionsCallerDelegatedWritesServiceOnly(t *testing.T) {
	testControlConnectionsCallerDelegatedWritesServiceOnly(t, newPgConnectionsStore(t))
}

// TestPgCallerDelegatedSecretsEncrypted reads the raw narthex_accounts row:
// the client secret and the listing token are ciphertext at rest, the
// caller_delegated column round-trips, and the DDL is idempotent.
func TestPgCallerDelegatedSecretsEncrypted(t *testing.T) {
	store := newPgConnectionsStore(t)
	ctx := context.Background()
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	decodeTestConnection(t, h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`), http.StatusOK)

	assertRaw := func(stage, wantSecret string) {
		t.Helper()
		var clientSecret, bearerToken, accessToken, refreshToken string
		var delegated bool
		if err := store.pool.QueryRow(ctx, `SELECT client_secret,bearer_token,access_token,refresh_token,caller_delegated FROM narthex_accounts WHERE name=$1`, h.name).
			Scan(&clientSecret, &bearerToken, &accessToken, &refreshToken, &delegated); err != nil {
			t.Fatalf("%s raw row: %v", stage, err)
		}
		if !delegated {
			t.Fatalf("%s caller_delegated=false", stage)
		}
		for column, value := range map[string]string{"client_secret": clientSecret, "bearer_token": bearerToken} {
			if !strings.HasPrefix(value, encPrefix) || strings.Contains(value, wantSecret) || strings.Contains(value, testDelegatedListingToken) {
				t.Fatalf("%s %s is not ciphertext: %q", stage, column, value)
			}
		}
		if accessToken != "" || refreshToken != "" {
			t.Fatalf("%s stored unexpected OAuth tokens", stage)
		}
		account, found := store.Account(h.name)
		if !found || !account.CallerDelegated || account.ClientSecret != wantSecret || account.BearerToken != testDelegatedListingToken {
			t.Fatalf("%s decrypted account=%+v found=%v", stage, account, found)
		}
	}
	assertRaw("after token", testDelegatedClientSecret)

	read := decodeTestConnection(t, h.service(http.MethodGet, h.path(), ""), http.StatusOK)
	const rotated = "rotated-secret-0123456789abcdefghijklmn"
	decodeTestConnection(t, h.service(http.MethodPatch, h.path(), `{"revision":`+itoa64(read.Revision)+`,"callerDelegated":{"clientSecret":"`+rotated+`"}}`), http.StatusOK)
	assertRaw("after rotation", rotated)

	// The DDL re-runs cleanly on a store that already has the column, and a
	// fresh store over the same database reads the flag back.
	if _, err := store.pool.Exec(ctx, accountsMigrate); err != nil {
		t.Fatalf("accounts DDL re-run: %v", err)
	}
	reopened, err := NewPgStore(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("NewPgStore re-run: %v", err)
	}
	defer reopened.Close()
	reopened.SetCipher(testCipher(t, 0x5c))
	if account, found := reopened.Account(h.name); !found || !account.CallerDelegated || account.ClientSecret != rotated {
		t.Fatalf("reopened account=%+v found=%v", account, found)
	}
	// A plain account written through the legacy column list defaults to
	// false.
	plain := h.name + "_plain"
	t.Cleanup(func() { cleanupPgConnectionFixture(t, store, plain, "") })
	if _, err := store.pool.Exec(ctx, `INSERT INTO narthex_accounts (name,workspace,url,auth_mode,bearer_token) VALUES ($1,'General','https://tools.example.com/mcp','token','')`, plain); err != nil {
		t.Fatal(err)
	}
	if account, found := store.Account(plain); !found || account.CallerDelegated || account.IsCallerDelegated() {
		t.Fatalf("legacy row account=%+v found=%v", account, found)
	}
}
