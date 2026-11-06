package engine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func websiteAccountFixture(owner string) LinkedAccountRecord {
	return LinkedAccountRecord{OwnerSubject: owner, DisplayName: "My website", Browser: &BrowserProfile{
		Provider: "kernel", ConfigurationID: "website-project", FlowID: "bsign_website", ProfileID: "private-profile", WebsiteURL: "https://example.com/login",
	}}
}

func TestFileWebsiteAccountWithoutConnection(t *testing.T) {
	testWebsiteAccountWithoutConnection(t, newLibraryFileStore(t))
}

func TestPgWebsiteAccountWithoutConnection(t *testing.T) {
	testWebsiteAccountWithoutConnection(t, newPgConnectionsStore(t))
}

func testWebsiteAccountWithoutConnection(t *testing.T, store browserTestStore) {
	t.Helper()
	owner := "usr_website_" + newPgFixtureSuffix()
	ctx := t.Context()
	account, err := store.CreateLinkedAccount(ctx, websiteAccountFixture(owner), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatalf("website account must save without an MCP connection: %v", err)
	}
	if account.ConnectionID != "" || account.Boundary != (OAuthCompletionPrecondition{}) || account.Revision != 1 || linkedAccountDTO(account, Account{}).Status != "linked" {
		t.Fatalf("invalid independent website account: %+v", account)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
		})
	}
	rows, err := store.LinkedAccounts(ctx, owner)
	if err != nil || len(rows) != 1 || rows[0].ID != account.ID {
		t.Fatalf("owner cannot list website account: %+v %v", rows, err)
	}
	unrelated := linkedAccountFixture(t, store)
	if err := store.Delete(ctx, unrelated.Name, unrelated.IncarnationID, unrelated.Revision); err != nil {
		t.Fatal(err)
	}
	rows, err = store.LinkedAccounts(ctx, owner)
	if err != nil || len(rows) != 1 || rows[0].ID != account.ID {
		t.Fatal("unrelated connection deletion removed website account", err)
	}
	if _, err := store.MutateLinkedAccount(ctx, "", account.ID, "usr_other", account.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Remove: true}); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatalf("another owner changed website account: %v", err)
	}
	name := "Renamed website"
	updated, err := store.MutateLinkedAccount(ctx, "", account.ID, owner, account.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{DisplayName: &name})
	if err != nil || updated.DisplayName != name {
		t.Fatalf("rename: %+v %v", updated, err)
	}
	if _, err := store.MutateLinkedAccount(ctx, "", account.ID, owner, account.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Remove: true}); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatalf("stale revision changed website account: %v", err)
	}
	empty := ""
	updated, err = store.MutateLinkedAccount(ctx, "", account.ID, owner, updated.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{BearerToken: &empty})
	if err != nil || updated.Browser.ProfileID != "" || linkedAccountDTO(updated, Account{}).Status != "disconnected" {
		t.Fatalf("disconnect: %+v %v", updated, err)
	}
	if _, err := store.CreateLinkedAccount(ctx, LinkedAccountRecord{OwnerSubject: owner, DisplayName: "Token", BearerToken: "secret"}, AccountPolicyPrecondition{}); err == nil {
		t.Fatal("standalone token account accepted")
	}
	if _, err := store.CreateLinkedAccount(ctx, websiteAccountFixture(owner), AccountPolicyPrecondition{Revision: 1}); err == nil {
		t.Fatal("partial parent boundary accepted")
	}
	if _, err := store.MutateLinkedAccount(ctx, "", account.ID, owner, updated.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Remove: true}); err != nil {
		t.Fatalf("remove website account: %v", err)
	}
}

func TestFileWebsiteSignInWithoutConnection(t *testing.T) {
	testWebsiteSignInWithoutConnection(t, newLibraryFileStore(t))
}

func TestPgWebsiteSignInWithoutConnection(t *testing.T) {
	testWebsiteSignInWithoutConnection(t, newPgConnectionsStore(t))
}

func testWebsiteSignInWithoutConnection(t *testing.T, store browserTestStore) {
	t.Helper()
	ctx := t.Context()
	owner := "usr_website_" + newPgFixtureSuffix()
	f := BrowserSignIn{ID: "bsign_" + newEpoch(), OwnerSubject: owner, DisplayName: "Website", WebsiteURL: "https://example.com/login", Provider: "kernel", ConfigurationID: "project", ProfileID: "profile", State: "saving", ExpiresAt: time.Now().Add(time.Minute), SyncAfter: time.Now().Add(-time.Second)}
	f, err := store.WriteBrowserSignIn(ctx, f, 0)
	if err != nil {
		t.Fatalf("website sign-in must start without an MCP connection: %v", err)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_sign_ins WHERE owner_subject=$1`, owner)
		})
	}
	account, err := store.CommitBrowserSignIn(ctx, f.ID, f.Revision)
	if err != nil || account.ConnectionID != "" || account.OwnerSubject != owner {
		t.Fatalf("website sign-in commit: %+v %v", account, err)
	}
	if _, err := store.CommitBrowserSignIn(ctx, f.ID, f.Revision); err == nil {
		t.Fatal("replayed website save committed twice")
	}
	flows, err := store.BrowserSignIns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, saved := range flows {
		if saved.ID == f.ID {
			if saved.State != "saved" || saved.AccountID != account.ID {
				t.Fatalf("save did not atomically update cleanup ledger: %+v", saved)
			}
			return
		}
	}
	t.Fatal("saved website ledger missing")
}

func TestWebsiteAccountFilePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.CreateLinkedAccount(t.Context(), websiteAccountFixture("usr_website"), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := store.WriteBrowserSignIn(t.Context(), BrowserSignIn{ID: "bsign_" + newEpoch(), OwnerSubject: "usr_website", DisplayName: "Website", WebsiteURL: "https://example.com/login", State: "starting", ExpiresAt: time.Now().Add(time.Minute)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reopened.LinkedAccounts(t.Context(), "usr_website")
	if err != nil || len(rows) != 1 || rows[0].ID != account.ID {
		t.Fatalf("website account lost on reopen: %+v %v", rows, err)
	}
	flows, err := reopened.BrowserSignIns(t.Context())
	if err != nil || len(flows) != 1 || flows[0].ID != f.ID {
		t.Fatal("website cleanup ledger lost on reopen", err)
	}
}

func TestWebsiteSignInFileSaveRollback(t *testing.T) {
	store := newLibraryFileStore(t)
	f, err := store.WriteBrowserSignIn(t.Context(), BrowserSignIn{ID: "bsign_" + newEpoch(), OwnerSubject: "usr_website", DisplayName: "Website", WebsiteURL: "https://example.com/login", Provider: "kernel", ConfigurationID: "project", ProfileID: "profile", State: "saving", ExpiresAt: time.Now().Add(time.Minute), SyncAfter: time.Now().Add(-time.Second)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(store.path, "impossible", "state.json")
	if _, err := store.CommitBrowserSignIn(t.Context(), f.ID, f.Revision); err == nil {
		t.Fatal("failed website save accepted")
	}
	rows, err := store.LinkedAccounts(t.Context(), f.OwnerSubject)
	if err != nil || len(rows) != 0 {
		t.Fatal("failed website save left account in memory", err)
	}
	flows, err := store.BrowserSignIns(t.Context())
	if err != nil || len(flows) != 1 || flows[0].Revision != f.Revision || flows[0].State != "saving" {
		t.Fatal("failed website save changed cleanup ledger", err)
	}
	f.State = "cleanup"
	if _, err := store.WriteBrowserSignIn(t.Context(), f, f.Revision); err == nil {
		t.Fatal("failed website ledger write accepted")
	}
	flows, err = store.BrowserSignIns(t.Context())
	if err != nil || flows[0].State != "saving" {
		t.Fatal("failed website ledger write changed memory", err)
	}
}

func TestFileWebsiteAccountConcurrentLimit(t *testing.T) {
	testWebsiteAccountConcurrentLimit(t, newLibraryFileStore(t))
}
func TestPgWebsiteAccountConcurrentLimit(t *testing.T) {
	testWebsiteAccountConcurrentLimit(t, newPgConnectionsStore(t))
}
func testWebsiteAccountConcurrentLimit(t *testing.T, store browserTestStore) {
	owner := "usr_website_" + newPgFixtureSuffix()
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
		})
	}
	for range maxLinkedAccountsPerConnection - 1 {
		if _, err := store.CreateLinkedAccount(t.Context(), websiteAccountFixture(owner), AccountPolicyPrecondition{}); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := store.CreateLinkedAccount(t.Context(), websiteAccountFixture(owner), AccountPolicyPrecondition{})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success, limited := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLinkedAccountLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || limited != 1 {
		t.Fatalf("website account limit raced: %d saved, %d limited", success, limited)
	}
}

func TestFileWebsiteAndLinkedSignInsShareLimit(t *testing.T) {
	testWebsiteAndLinkedSignInsShareLimit(t, newLibraryFileStore(t))
}
func TestPgWebsiteAndLinkedSignInsShareLimit(t *testing.T) {
	testWebsiteAndLinkedSignInsShareLimit(t, newPgConnectionsStore(t))
}
func testWebsiteAndLinkedSignInsShareLimit(t *testing.T, store browserTestStore) {
	parent := linkedAccountFixture(t, store)
	owner := "usr_website_" + newPgFixtureSuffix()
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_sign_ins WHERE owner_subject=$1`, owner)
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_browser_sign_ins WHERE owner_subject=$1`, owner)
		})
	}
	base := BrowserSignIn{OwnerSubject: owner, DisplayName: "Website", WebsiteURL: "https://example.com/login", State: "starting", ExpiresAt: time.Now().Add(time.Minute)}
	results := make(chan error, 3)
	var wg sync.WaitGroup
	for i := range 3 {
		f := base
		f.ID = "bsign_" + newEpoch()
		if i == 0 {
			f.ConnectionID, f.Parent = parent.Name, accountPolicyPrecondition(parent)
		}
		wg.Go(func() { _, err := store.WriteBrowserSignIn(t.Context(), f, 0); results <- err })
	}
	wg.Wait()
	close(results)
	success, limited := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLinkedAccountLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if success != 2 || limited != 1 {
		t.Fatalf("shared pending limit raced: %d started, %d limited", success, limited)
	}
}

func TestFileWebsiteReconnectAndConcurrentSave(t *testing.T) {
	testWebsiteReconnectAndConcurrentSave(t, newLibraryFileStore(t))
}
func TestPgWebsiteReconnectAndConcurrentSave(t *testing.T) {
	testWebsiteReconnectAndConcurrentSave(t, newPgConnectionsStore(t))
}
func testWebsiteReconnectAndConcurrentSave(t *testing.T, store browserTestStore) {
	owner := "usr_website_" + newPgFixtureSuffix()
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_website_sign_ins WHERE owner_subject=$1`, owner)
		})
	}
	account, err := store.CreateLinkedAccount(t.Context(), websiteAccountFixture(owner), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	f := BrowserSignIn{ID: "bsign_" + newEpoch(), OwnerSubject: owner, AccountID: account.ID, AccountRevision: account.Revision, DisplayName: account.DisplayName, WebsiteURL: account.Browser.WebsiteURL, Provider: account.Browser.Provider, ConfigurationID: account.Browser.ConfigurationID, ProfileID: "replacement-profile", State: "saving", ExpiresAt: time.Now().Add(time.Minute), SyncAfter: time.Now().Add(-time.Second)}
	f, err = store.WriteBrowserSignIn(t.Context(), f, 0)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { _, err := store.CommitBrowserSignIn(t.Context(), f.ID, f.Revision); results <- err })
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, errBrowserRevision) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("duplicate website save: %d saves, %d conflicts", success, conflict)
	}
	rows, err := store.LinkedAccounts(t.Context(), owner)
	if err != nil || len(rows) != 1 || rows[0].ID != account.ID || rows[0].CredentialRevision != account.CredentialRevision+1 || rows[0].Browser.ProfileID != "replacement-profile" {
		t.Fatalf("website reconnect: %+v %v", rows, err)
	}
}

func TestPgWebsiteDataIsEncryptedAndIsolatedFromLegacyCleanup(t *testing.T) {
	s := newPgConnectionsStore(t)
	owner := "usr_website_" + newPgFixtureSuffix()
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM narthex_website_accounts WHERE owner_subject=$1`, owner)
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM narthex_website_sign_ins WHERE owner_subject=$1`, owner)
	})
	account, err := s.CreateLinkedAccount(t.Context(), websiteAccountFixture(owner), AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.WriteBrowserSignIn(t.Context(), BrowserSignIn{ID: "bsign_" + newEpoch(), OwnerSubject: owner, DisplayName: "Private sign-in label", WebsiteURL: "https://example.com/login", ProfileID: "private-login-profile", State: "starting", ExpiresAt: time.Now().Add(time.Minute)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		table, id, secret string
		value             any
	}{
		{"narthex_website_accounts", account.ID, account.Browser.ProfileID, account},
		{"narthex_website_sign_ins", f.ID, f.ProfileID, f},
	} {
		var payload string
		if err := s.pool.QueryRow(t.Context(), `SELECT payload FROM `+item.table+` WHERE id=$1`, item.id).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(payload, encPrefix) || strings.Contains(payload, item.secret) {
			t.Fatal("website payload is not encrypted")
		}
		plain, _ := json.Marshal(item.value)
		if _, err := s.pool.Exec(t.Context(), `UPDATE `+item.table+` SET payload=$2 WHERE id=$1`, item.id, string(plain)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := s.encryptExistingLinkedAccounts(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var raw string
	if err := s.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_website_accounts WHERE id=$1`, account.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) {
		t.Fatal("website encryption migration failed", err)
	}
	var legacy int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM narthex_linked_accounts WHERE owner_subject=$1)+(SELECT count(*) FROM narthex_browser_sign_ins WHERE owner_subject=$1)`, owner).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatal("standalone state leaked into previous Engine cleanup tables", legacy, err)
	}
}
