package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSignInBrowser struct {
	deleted  []string
	profiles int
	failure  string
	onView   func()
}

func (*fakeSignInBrowser) Kind() string            { return "browserbase" }
func (*fakeSignInBrowser) ConfigurationID() string { return "project-config" }
func (p *fakeSignInBrowser) CreateProfile(_ context.Context, id string) (string, error) {
	p.profiles++
	return "profile-" + id, nil
}
func (p *fakeSignInBrowser) CreateSession(_ context.Context, id string) (string, string, error) {
	if p.failure == "session" {
		return "", "", errBrowserSignIn
	}
	return "session-" + id, "private-connect-url", nil
}
func (p *fakeSignInBrowser) Navigate(context.Context, string, string) error {
	if p.failure == "navigate" {
		return errBrowserSignIn
	}
	return nil
}
func (p *fakeSignInBrowser) View(context.Context, string) (string, error) {
	if p.onView != nil {
		p.onView()
	}
	return "https://www.browserbase.com/viewer/private", nil
}
func (p *fakeSignInBrowser) Stop(context.Context, string) (bool, error) {
	return p.failure != "running", nil
}
func (p *fakeSignInBrowser) ProfileReady(context.Context, string) error {
	if p.failure == "sync" {
		return errBrowserSignIn
	}
	return nil
}
func (p *fakeSignInBrowser) DeleteProfile(_ context.Context, id string) error {
	if p.failure == "delete" {
		return errBrowserSignIn
	}
	p.deleted = append(p.deleted, id)
	return nil
}

type browserTestStore interface {
	linkedAccountTestStore
	BrowserSignInStore
}

func browserTestService(t *testing.T, store browserTestStore) (*BrowserSignInService, *fakeSignInBrowser, Account) {
	t.Helper()
	parent := linkedAccountFixture(t, store)
	provider := &fakeSignInBrowser{}
	service := &BrowserSignInService{provider: provider, flows: store, accounts: store, store: store}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_browser_sign_ins WHERE payload IS NOT NULL AND id = ANY($1)`, browserFlowIDs(t, service, parent.Name))
		})
	}
	return service, provider, parent
}
func browserFlowIDs(t *testing.T, s *BrowserSignInService, parent string) []string {
	t.Helper()
	flows, err := s.flows.BrowserSignIns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, f := range flows {
		if f.ConnectionID == parent {
			ids = append(ids, f.ID)
		}
	}
	return ids
}
func startTestBrowser(t *testing.T, s *BrowserSignInService, p Account, target *LinkedAccountRecord) BrowserSignIn {
	t.Helper()
	input := BrowserSignIn{OwnerSubject: "usr_alice", ConnectionID: p.Name, Parent: accountPolicyPrecondition(p), DisplayName: "My website", WebsiteURL: "https://www.linkedin.com/login"}
	if target != nil {
		input.AccountID = target.ID
		input.AccountRevision = target.Revision
	}
	f, err := s.start(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func writeTestBrowser(t *testing.T, s *BrowserSignInService, f BrowserSignIn) BrowserSignIn {
	t.Helper()
	out, err := s.write(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func readyTestBrowser(t *testing.T, s *BrowserSignInService, f BrowserSignIn) BrowserSignIn {
	t.Helper()
	f.State = "saving"
	f.SyncAfter = time.Now().Add(-time.Second)
	return writeTestBrowser(t, s, f)
}
func commitTestBrowser(t *testing.T, s *BrowserSignInService, f BrowserSignIn) LinkedAccountRecord {
	t.Helper()
	r, err := s.flows.CommitBrowserSignIn(t.Context(), f.ID, f.Revision)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func cleanTestBrowser(t *testing.T, s *BrowserSignInService, id string) {
	t.Helper()
	s.Reconcile(t.Context())
	f, err := s.lookup(t.Context(), id)
	if errors.Is(err, ErrLinkedAccountNotFound) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if f.State != "cleanup" {
		t.Fatalf("expected cleanup, got %s", f.State)
	}
	f.SyncAfter = time.Now().Add(-time.Second)
	f.ExpiresAt = time.Now().Add(-2 * time.Minute)
	writeTestBrowser(t, s, f)
	s.Reconcile(t.Context())
	if _, err = s.lookup(t.Context(), id); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatal("cleanup ledger was not erased", err)
	}
}

func TestFileBrowserSignInLifecycle(t *testing.T) {
	testBrowserSignInLifecycle(t, newLibraryFileStore(t))
}
func TestPgBrowserSignInLifecycle(t *testing.T) {
	testBrowserSignInLifecycle(t, newPgConnectionsStore(t))
}
func testBrowserSignInLifecycle(t *testing.T, store browserTestStore) {
	s, provider, parent := browserTestService(t, store)
	token, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "Token", BearerToken: "kept-token"}, accountPolicyPrecondition(parent))
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "OAuth", OAuth: &LinkedOAuthCredential{Provider: "linkedin", ClientID: "app", Subject: "member", AccessToken: "kept-oauth", Scopes: []string{"openid", "profile"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}}, accountPolicyPrecondition(parent))
	if err != nil {
		t.Fatal(err)
	}
	f := startTestBrowser(t, s, parent, nil)
	if f.State != "ready" {
		t.Fatal("browser not ready")
	}
	if _, err = store.CommitBrowserSignIn(t.Context(), f.ID, f.Revision); err == nil {
		t.Fatal("unconfirmed profile saved")
	}
	f = readyTestBrowser(t, s, f)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, e := store.CommitBrowserSignIn(t.Context(), f.ID, f.Revision); results <- e })
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, errBrowserRevision) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal("save replay accepted")
	}
	records, err := store.LinkedAccounts(t.Context(), "usr_alice")
	if err != nil || len(records) != 3 {
		t.Fatal("lost accounts", err)
	}
	var saved LinkedAccountRecord
	for _, r := range records {
		switch r.ID {
		case token.ID:
			if !reflect.DeepEqual(token, r) {
				t.Fatal("changed access token account")
			}
		case oauth.ID:
			if !reflect.DeepEqual(oauth, r) {
				t.Fatal("changed OAuth account")
			}
		default:
			saved = r
		}
	}
	dto := linkedAccountDTO(saved, parent)
	raw, _ := json.Marshal(dto)
	if dto.AuthMode != "browser" || dto.IdentityStatus != "opaque" || dto.BindingMode != "explicit" || strings.Contains(string(raw), f.ProfileID) || strings.Contains(string(raw), f.SessionID) || strings.Contains(string(raw), f.ConfigurationID) {
		t.Fatal("unsafe browser account projection", string(raw))
	}
	saved.Browser.ProfileID = "mutated-client-copy"
	again, _ := store.LinkedAccounts(t.Context(), "usr_alice")
	for _, r := range again {
		if r.ID == saved.ID {
			saved = r
		}
	}
	if saved.Browser.ProfileID != f.ProfileID {
		t.Fatal("browser profile aliased stored state")
	}
	next := startTestBrowser(t, s, parent, &saved)
	if next.ProfileID == f.ProfileID {
		t.Fatal("reconnect reused active profile")
	}
	s.Reconcile(t.Context())
	if len(provider.deleted) != 0 {
		t.Fatal("reconnect deleted saved profile before replacement")
	}
	next = readyTestBrowser(t, s, next)
	replacement := commitTestBrowser(t, s, next)
	if replacement.ID != saved.ID || replacement.CredentialRevision != saved.CredentialRevision+1 {
		t.Fatal("reconnect identity/revision changed incorrectly")
	}
	cleanTestBrowser(t, s, f.ID)
	if len(provider.deleted) != 1 || provider.deleted[0] != f.ProfileID {
		t.Fatal("replaced profile not deleted")
	}
	empty := ""
	disconnected, err := store.MutateLinkedAccount(t.Context(), parent.Name, replacement.ID, replacement.OwnerSubject, replacement.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{BearerToken: &empty})
	if err != nil || disconnected.Browser.ProfileID != "" {
		t.Fatal("disconnect kept profile", err)
	}
	cleanTestBrowser(t, s, next.ID)
	if len(provider.deleted) != 2 || provider.deleted[1] != next.ProfileID {
		t.Fatal("disconnected profile not deleted")
	}
	current, _ := store.Account(parent.Name)
	if !reflect.DeepEqual(parent, current) || store.Token(parent.Name) != "legacy-credential" {
		t.Fatal("browser linking changed MCP connection")
	}
}

func TestFileBrowserSignInFences(t *testing.T) { testBrowserSignInFences(t, newLibraryFileStore(t)) }
func TestPgBrowserSignInFences(t *testing.T)   { testBrowserSignInFences(t, newPgConnectionsStore(t)) }
func testBrowserSignInFences(t *testing.T, store browserTestStore) {
	s, provider, parent := browserTestService(t, store)
	f := readyTestBrowser(t, s, startTestBrowser(t, s, parent, nil))
	saved := commitTestBrowser(t, s, f)
	late := readyTestBrowser(t, s, startTestBrowser(t, s, parent, &saved))
	empty := ""
	if _, err := store.MutateLinkedAccount(t.Context(), parent.Name, saved.ID, saved.OwnerSubject, saved.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{BearerToken: &empty}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitBrowserSignIn(t.Context(), late.ID, late.Revision); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatal("late sign-in restored disconnected account", err)
	}
	late.State = "cleanup"
	late = writeTestBrowser(t, s, late)
	if _, err := store.CommitBrowserSignIn(t.Context(), late.ID, late.Revision); err == nil {
		t.Fatal("cancelled flow saved")
	}
	cleanTestBrowser(t, s, late.ID)
	cleanTestBrowser(t, s, f.ID)
	expired := readyTestBrowser(t, s, startTestBrowser(t, s, parent, nil))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	expired = writeTestBrowser(t, s, expired)
	if _, err := store.CommitBrowserSignIn(t.Context(), expired.ID, expired.Revision); err == nil {
		t.Fatal("expired flow saved")
	}
	cleanTestBrowser(t, s, expired.ID)
	pending := startTestBrowser(t, s, parent, nil)
	if err := store.Delete(t.Context(), parent.Name, parent.IncarnationID, parent.Revision); err != nil {
		t.Fatal(err)
	}
	provider.failure = "delete"
	s.Reconcile(t.Context())
	flow, err := s.lookup(t.Context(), pending.ID)
	if err != nil || flow.ProfileID == "" {
		t.Fatal("parent deletion lost cleanup reference")
	}
	flow.SyncAfter = time.Now().Add(-time.Second)
	writeTestBrowser(t, s, flow)
	s.Reconcile(t.Context())
	if _, err = s.lookup(t.Context(), flow.ID); err != nil {
		t.Fatal("failed deletion erased ledger")
	}
	provider.failure = ""
	cleanTestBrowser(t, s, pending.ID)
}

func TestBrowserSignInInterruptedCreationAndRestart(t *testing.T) {
	for _, failure := range []string{"session", "navigate"} {
		t.Run(failure, func(t *testing.T) {
			store := newLibraryFileStore(t)
			s, p, parent := browserTestService(t, store)
			p.failure = failure
			_, err := s.start(t.Context(), BrowserSignIn{OwnerSubject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), DisplayName: "Interrupted", WebsiteURL: "https://instagram.com/"})
			if err == nil {
				t.Fatal("creation failure ignored")
			}
			reopened, e := LoadFileStore(store.path)
			if e != nil {
				t.Fatal(e)
			}
			flows, e := reopened.BrowserSignIns(t.Context())
			if e != nil || len(flows) != 1 || flows[0].State != "cleanup" || flows[0].ProfileID == "" {
				t.Fatal("restart lost acquired profile")
			}
			s.flows = reopened
			s.accounts = reopened
			s.store = reopened
			cleanTestBrowser(t, s, flows[0].ID)
		})
	}
}
func TestBrowserSignInFileSaveRollback(t *testing.T) {
	store := newLibraryFileStore(t)
	s, _, parent := browserTestService(t, store)
	f := readyTestBrowser(t, s, startTestBrowser(t, s, parent, nil))
	path := store.path
	store.path = filepath.Join(path, "impossible", "state.json")
	if _, err := store.CommitBrowserSignIn(t.Context(), f.ID, f.Revision); err == nil {
		t.Fatal("failed save accepted")
	}
	if len(store.linkedAccounts) != 0 || store.browserSignIns[0].State != "saving" {
		t.Fatal("failed persistence changed memory")
	}
	f.State = "cleanup"
	if _, err := s.write(t.Context(), f); err == nil {
		t.Fatal("failed ledger write accepted")
	}
	if store.browserSignIns[0].State != "saving" {
		t.Fatal("failed ledger write changed memory")
	}
	store.path = path
}
func TestPgBrowserSignInEncryptedPayload(t *testing.T) {
	store := newPgConnectionsStore(t)
	s, _, parent := browserTestService(t, store)
	f := readyTestBrowser(t, s, startTestBrowser(t, s, parent, nil))
	var raw string
	if err := store.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_browser_sign_ins WHERE id=$1`, f.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, f.ProfileID) {
		t.Fatal("browser ledger is not encrypted", err)
	}
	plain, _ := json.Marshal(f)
	if _, err := store.pool.Exec(t.Context(), `UPDATE narthex_browser_sign_ins SET payload=$2 WHERE id=$1`, f.ID, string(plain)); err != nil {
		t.Fatal(err)
	}
	if err := store.encryptExistingLinkedAccounts(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_browser_sign_ins WHERE id=$1`, f.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) {
		t.Fatal("ledger migration failed", err)
	}
	saved := commitTestBrowser(t, s, f)
	if err := store.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_linked_accounts WHERE id=$1`, saved.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, f.ProfileID) {
		t.Fatal("profile reference is not encrypted", err)
	}
}
func TestBrowserSignInHTTPBoundaries(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		t.Run(prefix, func(t *testing.T) {
			store := newLibraryFileStore(t)
			s, p, parent := browserTestService(t, store)
			verifier, key, now := newActorVerifier(t)
			api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithBrowserSignIn(s))
			mux := http.NewServeMux()
			api.Routes(mux)
			request := func(subject, role, path string, body any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				return hostedNamespaceRequest(t, mux, key, now, subject, role, "POST", prefix+"/browser-sign-ins/"+path, string(raw))
			}
			input := map[string]any{"connectionId": parent.Name, "connectionIncarnationId": parent.IncarnationID, "connectionRevision": parent.Revision, "displayName": "My website", "websiteUrl": "https://instagram.com/"}
			denied := request("usr_alice", "viewer", "start", input)
			if denied.Code != 403 || p.profiles != 0 {
				t.Fatal("viewer started browser")
			}
			started := request("usr_alice", "operator", "start", input)
			var f browserSignInDTO
			if started.Code != 201 || json.Unmarshal(started.Body.Bytes(), &f) != nil {
				t.Fatal("start", started.Code, started.Body.String())
			}
			private, _ := s.lookup(t.Context(), f.ID)
			if strings.Contains(started.Body.String(), private.ProfileID) || strings.Contains(started.Body.String(), private.SessionID) {
				t.Fatal("private refs leaked")
			}
			for _, op := range []string{"view", "save", "cancel"} {
				if res := request("usr_bob", "admin", f.ID+"/"+op, map[string]any{"revision": f.Revision, "confirmed": op == "save"}); res.Code != 404 {
					t.Fatal("coworker accessed browser", op, res.Code)
				}
			}
			if res := request("usr_alice", "operator", f.ID+"/save", map[string]any{"revision": f.Revision}); res.Code != 400 {
				t.Fatal("unconfirmed profile saved")
			}
			view := request("usr_alice", "operator", f.ID+"/view", map[string]any{"revision": f.Revision})
			if view.Code != 200 || view.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("view", view.Code)
			}
			res := request("usr_alice", "operator", f.ID+"/save", map[string]any{"revision": f.Revision, "confirmed": true})
			if res.Code != 202 {
				t.Fatal("save should wait for sync", res.Code, res.Body.String())
			}
			private, _ = s.lookup(t.Context(), f.ID)
			private.SyncAfter = time.Now().Add(-time.Second)
			private = writeTestBrowser(t, s, private)
			res = request("usr_alice", "operator", f.ID+"/save", map[string]any{"revision": private.Revision, "confirmed": true})
			if res.Code != 200 || !strings.Contains(res.Body.String(), `"authMode":"browser"`) {
				t.Fatal("save", res.Code, res.Body.String())
			}
			next := startTestBrowser(t, s, parent, nil)
			p.onView = func() {
				if err := store.Delete(t.Context(), parent.Name, parent.IncarnationID, parent.Revision); err != nil {
					t.Fatal(err)
				}
			}
			res = request("usr_alice", "operator", next.ID+"/view", map[string]any{"revision": next.Revision})
			if res.Code != 409 || strings.Contains(res.Body.String(), "viewerUrl") {
				t.Fatal("parent changed while obtaining viewer")
			}
		})
	}
}

func TestBrowserSignInRestartsSyncWaitIfSessionIsRunning(t *testing.T) {
	store := newLibraryFileStore(t)
	s, p, parent := browserTestService(t, store)
	f := readyTestBrowser(t, s, startTestBrowser(t, s, parent, nil))
	p.failure = "running"
	next, err := s.advance(t.Context(), f)
	if err != nil || !next.SyncAfter.IsZero() {
		t.Fatal("running browser retained save-ready timestamp", err)
	}
	if _, err = store.CommitBrowserSignIn(t.Context(), next.ID, next.Revision); err == nil {
		t.Fatal("running session saved")
	}
}
func TestBrowserSignInPendingQuota(t *testing.T) {
	store := newLibraryFileStore(t)
	s, p, parent := browserTestService(t, store)
	startTestBrowser(t, s, parent, nil)
	startTestBrowser(t, s, parent, nil)
	_, err := s.start(t.Context(), BrowserSignIn{OwnerSubject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), DisplayName: "Excess", WebsiteURL: "https://www.linkedin.com/"})
	if !errors.Is(err, ErrLinkedAccountLimit) || p.profiles != 2 {
		t.Fatal("pending quota did not prevent provider work", err)
	}
}
