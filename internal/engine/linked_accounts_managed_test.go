package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type managedBrowserFake struct {
	runtimeBrowserFake
	statusMu      sync.Mutex
	status        ManagedBrowserStatus
	submissions   int
	removed       int
	submitFailure bool
	onStatus      func()
}

func (*managedBrowserFake) Kind() string            { return "kernel" }
func (*managedBrowserFake) ConfigurationID() string { return "kernel-test-project" }
func (*managedBrowserFake) CreateLogin(_ context.Context, profile, _ string) (string, error) {
	return "auth-" + profile, nil
}
func (*managedBrowserFake) BeginLogin(context.Context, string) error { return nil }
func (p *managedBrowserFake) LoginStatus(context.Context, string) (ManagedBrowserStatus, error) {
	if p.onStatus != nil {
		p.onStatus()
	}
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	return p.status, nil
}
func (p *managedBrowserFake) SubmitLogin(_ context.Context, _, interaction string, _ map[string]string, _ string) error {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()
	p.submissions++
	if p.submitFailure {
		return errBrowserSignIn
	}
	if interaction == "login-1" {
		p.status = ManagedBrowserStatus{State: "input", InteractionID: "code-2", Fields: []ManagedBrowserField{{ID: "code", Label: "Verification code", Type: "otp", Required: true}}, BrowserSessionID: "private-login-browser"}
	} else {
		p.status = ManagedBrowserStatus{State: "succeeded", BrowserSessionID: "private-login-browser"}
	}
	return nil
}
func (p *managedBrowserFake) DeleteLogin(context.Context, string) error { p.removed++; return nil }

func managedFixture(t *testing.T, store browserTestStore) (*BrowserSignInService, *managedBrowserFake, Account, BrowserSignIn) {
	t.Helper()
	s, _, parent := browserTestService(t, store)
	p := &managedBrowserFake{status: ManagedBrowserStatus{State: "input", InteractionID: "login-1", Fields: []ManagedBrowserField{{ID: "user", Label: "Username", Type: "text", Required: true}, {ID: "pass", Label: "Password", Type: "password", Required: true}}, BrowserSessionID: "private-login-browser"}}
	s.managedProvider = p
	f, err := s.start(t.Context(), BrowserSignIn{OwnerSubject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), DisplayName: "Managed account", WebsiteURL: "https://example.com/login", Method: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	return s, p, parent, f
}

func TestFileManagedBrowserLogin(t *testing.T) { testManagedBrowserLogin(t, newLibraryFileStore(t)) }
func TestPgManagedBrowserLogin(t *testing.T)   { testManagedBrowserLogin(t, newPgConnectionsStore(t)) }
func testManagedBrowserLogin(t *testing.T, store browserTestStore) {
	s, p, _, f := managedFixture(t, store)
	if f.Provider != "kernel" || f.AuthConnectionID == "" || !s.availability(t.Context()).Available || !s.availability(t.Context()).ManagedAvailable {
		t.Fatal("both providers must remain available")
	}
	values := map[string]string{"user": "private-user-marker", "pass": "private-password-marker"}
	allowed := func() bool { return true }
	if _, err := s.submitManaged(t.Context(), f, "login-1", map[string]string{"unrequested": "private-password-marker"}, "", allowed); !errors.Is(err, errManagedInput) {
		t.Fatal("accepted unknown fields", err)
	}
	if _, err := s.submitManaged(t.Context(), f, "login-1", values, "", func() bool { return false }); !errors.Is(err, errBrowserRevision) {
		t.Fatal("submitted after access disappeared", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.submitManaged(t.Context(), f, "login-1", values, "", allowed)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || p.submissions != 1 {
		t.Fatal("concurrent form submitted more than once", succeeded, p.submissions)
	}
	f, _ = s.lookup(t.Context(), f.ID)
	dto, err := s.publicDTO(t.Context(), f)
	if err != nil || dto.Login == nil || dto.Login.InteractionID != "code-2" || dto.CanSave {
		t.Fatal("verification challenge missing", err)
	}
	encoded, _ := json.Marshal(dto)
	for _, private := range []string{values["user"], values["pass"], f.AuthConnectionID, f.ProfileID, "private-login-browser"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("private value in DTO")
		}
	}
	f, err = s.submitManaged(t.Context(), f, "code-2", map[string]string{"code": "private-code-marker"}, "", allowed)
	if err != nil {
		t.Fatal(err)
	}
	dto, err = s.publicDTO(t.Context(), f)
	if err != nil || !dto.CanSave || dto.Login.State != "succeeded" {
		t.Fatal("completed login not saveable", err)
	}
	rows, _ := store.BrowserSignIns(t.Context())
	encoded, _ = json.Marshal(rows)
	for _, private := range []string{values["user"], values["pass"], "private-code-marker"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("credential stored in flow")
		}
	}
	f.State = "saving"
	f = writeTestBrowser(t, s, f)
	f, err = s.advance(t.Context(), f)
	if err != nil || f.SessionID != "private-login-browser" || f.SyncAfter.IsZero() {
		t.Fatal("login cleanup lost its browser reference", err)
	}
	f.SyncAfter = time.Now().Add(-time.Second)
	f = writeTestBrowser(t, s, f)
	f, err = s.advance(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	a := commitTestBrowser(t, s, f)
	if a.Browser.Provider != "kernel" || len(a.BrowserGrants) != 0 {
		t.Fatal("saved profile incorrectly granted agent access")
	}
	if s.runtimeProvider(*a.Browser) != p {
		t.Fatal("managed account routed to legacy provider")
	}
	s.managedProvider = nil
	if s.runtimeProvider(*a.Browser) != nil || !s.availability(t.Context()).Available {
		t.Fatal("provider removal affected wrong accounts")
	}
}

func TestManagedBrowserSubmissionSurvivesRestartWithoutReplay(t *testing.T) {
	store := newLibraryFileStore(t)
	s, p, _, f := managedFixture(t, store)
	p.submitFailure = true
	_, err := s.submitManaged(t.Context(), f, "login-1", map[string]string{"user": "user", "pass": "secret"}, "", func() bool { return true })
	if err == nil {
		t.Fatal("uncertain submission succeeded")
	}
	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	s.flows = reopened
	s.accounts = reopened
	s.store = reopened
	f, _ = s.lookup(t.Context(), f.ID)
	if _, err = s.submitManaged(t.Context(), f, "login-1", map[string]string{"user": "user", "pass": "secret"}, "", func() bool { return true }); !errors.Is(err, errBrowserRevision) || p.submissions != 1 {
		t.Fatal("replayed uncertain credentials", err)
	}
	dto, err := s.publicDTO(t.Context(), f)
	if err != nil || dto.Login.State != "working" || len(dto.Login.Fields) != 0 {
		t.Fatal("offered uncertain interaction again", err)
	}
	f.State = "cleanup"
	f = writeTestBrowser(t, s, f)
	cleanTestBrowser(t, s, f.ID)
	if p.removed == 0 || len(p.deleted) == 0 {
		t.Fatal("cancelled login resources retained")
	}
}

func TestManagedBrowserHTTPPrivacyAndVerifiedSave(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		t.Run(prefix, func(t *testing.T) {
			store := newLibraryFileStore(t)
			s, p, _, f := managedFixture(t, store)
			verifier, key, now := newActorVerifier(t)
			api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithBrowserSignIn(s))
			mux := http.NewServeMux()
			api.Routes(mux)
			request := func(subject, role, op string, body any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				return hostedNamespaceRequest(t, mux, key, now, subject, role, "POST", prefix+"/browser-sign-ins/"+f.ID+"/"+op, string(raw))
			}
			body := map[string]any{"revision": f.Revision, "interactionId": "login-1", "fields": map[string]string{"user": "test", "pass": "password-leak-marker"}}
			if res := request("usr_bob", "admin", "submit", body); res.Code != 404 {
				t.Fatal("another member submitted credentials", res.Code)
			}
			if res := request("usr_alice", "viewer", "submit", body); res.Code != 403 {
				t.Fatal("viewer submitted credentials", res.Code)
			}
			if res := request("usr_alice", "operator", "save", map[string]any{"revision": f.Revision, "confirmed": true}); res.Code != 409 {
				t.Fatal("saved unverified login", res.Code)
			}
			if res := request("usr_alice", "operator", "view", map[string]any{"revision": f.Revision}); res.Code != 409 {
				t.Fatal("normal credentials exposed browser viewer", res.Code)
			}
			res := request("usr_alice", "operator", "submit", body)
			if res.Code != 202 || res.Header().Get("Cache-Control") != "no-store" || strings.Contains(res.Body.String(), "password-leak-marker") {
				t.Fatal("submit response", res.Code, res.Body.String())
			}
			f, _ = s.lookup(t.Context(), f.ID)
			p.status = ManagedBrowserStatus{State: "succeeded", BrowserSessionID: "private-login-browser"}
			res = request("usr_alice", "operator", "save", map[string]any{"revision": f.Revision, "confirmed": true})
			if res.Code != 202 {
				t.Fatal("successful login did not begin save", res.Code, res.Body.String())
			}
			f, _ = s.lookup(t.Context(), f.ID)
			f.SyncAfter = time.Now().Add(-time.Second)
			f = writeTestBrowser(t, s, f)
			res = request("usr_alice", "operator", "save", map[string]any{"revision": f.Revision, "confirmed": true})
			if res.Code != 200 || !strings.Contains(res.Body.String(), `"browserProvider":"kernel"`) {
				t.Fatal("saved account", res.Code, res.Body.String())
			}
		})
	}
}

func TestManagedBrowserSubmissionChoicesAndBounds(t *testing.T) {
	status := ManagedBrowserStatus{State: "input", InteractionID: "step", Choices: []ManagedBrowserChoice{{ID: "sms", Label: "Text message"}}, Fields: []ManagedBrowserField{{ID: "code", Required: true}}}
	if !validManagedSubmission(status, "step", nil, "sms") || validManagedSubmission(status, "stale", nil, "sms") || validManagedSubmission(status, "step", map[string]string{"code": "123"}, "sms") || validManagedSubmission(status, "step", map[string]string{"code": strings.Repeat("x", 4097)}, "") {
		t.Fatal("invalid challenge submission accepted")
	}
}

type uncertainManagedBrowser struct {
	managedBrowserFake
	service      *BrowserSignInService
	checkpointed bool
}

func (*uncertainManagedBrowser) ProfileReference(id string) string { return "named-profile-" + id }
func (*uncertainManagedBrowser) SessionReference(id string) string { return "named-session-" + id }
func (p *uncertainManagedBrowser) CreateProfile(ctx context.Context, id string) (string, error) {
	f, err := p.service.lookup(ctx, id)
	p.checkpointed = err == nil && f.ProfileID == p.ProfileReference(id)
	return p.ProfileReference(id), errBrowserSignIn
}
func (*uncertainManagedBrowser) CreateNamedSession(_ context.Context, _, name string) (string, string, error) {
	return name, "", errBrowserSignIn
}
func (*uncertainManagedBrowser) CreateNamedRuntimeSession(_ context.Context, _ BrowserProfile, name string) (string, string, error) {
	return name, "", errBrowserSignIn
}

func TestManagedBrowserUncertainAllocationRetainsNamedCleanup(t *testing.T) {
	store := newLibraryFileStore(t)
	s, _, parent := browserTestService(t, store)
	p := &uncertainManagedBrowser{service: s}
	s.managedProvider = p
	f, err := s.start(t.Context(), BrowserSignIn{OwnerSubject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), DisplayName: "Pending login", WebsiteURL: "https://example.com/login", Method: "credentials"})
	if err == nil || !p.checkpointed {
		t.Fatal("allocation was not checkpointed before provider I/O")
	}
	f, _ = s.lookup(t.Context(), f.ID)
	if f.State != "cleanup" || f.ProfileID == "" {
		t.Fatal("uncertain creation lost named resource")
	}
	f.SyncAfter = time.Now().Add(-time.Second)
	f = writeTestBrowser(t, s, f)
	// A successful delete may merely be a 404 before the remote create lands.
	for range 2 {
		s.Reconcile(t.Context())
	}
	if _, err = s.lookup(t.Context(), f.ID); err != nil || len(p.deleted) != 2 {
		t.Fatal("cleanup stopped before late creation could be reconciled", err)
	}
	f.ExpiresAt = time.Now().Add(-2 * time.Minute)
	writeTestBrowser(t, s, f)
	s.Reconcile(t.Context())
	if _, err = s.lookup(t.Context(), f.ID); !errors.Is(err, ErrLinkedAccountNotFound) {
		t.Fatal("bounded cleanup did not finish", err)
	}
}

func TestManagedBrowserListToleratesCleanupDuringProviderRead(t *testing.T) {
	for _, state := range []string{"cleanup", "closed"} {
		t.Run(state, func(t *testing.T) {
			store := newLibraryFileStore(t)
			s, p, _, f := managedFixture(t, store)
			verifier, key, now := newActorVerifier(t)
			api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithBrowserSignIn(s))
			mux := http.NewServeMux()
			api.Routes(mux)
			p.onStatus = func() { f.State = state; f = writeTestBrowser(t, s, f) }
			res := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "GET", "/api/browser-sign-ins", "")
			if res.Code != 200 {
				t.Fatal("background cleanup interrupted polling", res.Code, res.Body.String())
			}
			var rows []browserSignInDTO
			if json.Unmarshal(res.Body.Bytes(), &rows) != nil {
				t.Fatal("invalid list")
			}
			if state == "closed" && len(rows) != 0 {
				t.Fatal("removed flow still listed")
			}
			if state == "cleanup" && (len(rows) != 1 || rows[0].State != "cleanup" || rows[0].Login != nil) {
				t.Fatal("superseded challenge exposed")
			}
		})
	}
}
