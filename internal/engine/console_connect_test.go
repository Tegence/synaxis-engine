package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fakeConnector records the last StartConnect call so tests can assert exactly
// what path (DCR vs static) and creds handleConnect selected — WITHOUT the real
// Connector's network Discovery step (SSRF-blocked against loopback). It
// satisfies the console's `connector` seam interface.
type fakeConnector struct {
	gotSC       *StaticCreds
	sawStatic   bool // true if the last StartConnect got a non-nil *StaticCreds
	startCalled bool
	authURL     string
	startErr    error
}

func (f *fakeConnector) StartConnect(_ context.Context, _, _, _, _, _ string, sc *StaticCreds) (string, error) {
	f.startCalled = true
	f.gotSC = sc
	f.sawStatic = sc != nil
	if f.authURL == "" {
		f.authURL = "https://auth.example.com/authorize?client_id=x&state=y"
	}
	return f.authURL, f.startErr
}

func (f *fakeConnector) FinishConnect(_ context.Context, _, _ string) (string, int, error) {
	return "", 0, nil
}

// newConnectConsole builds a ConsoleAPI with a fakeConnector injected via the
// unexported conn seam, an account pre-seeded, a bearer minted like handleLogin.
func newConnectConsole(t *testing.T) (*http.ServeMux, string, *fakeConnector) {
	t.Helper()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	if err := fs.Upsert(context.Background(), Account{Name: "acme", Label: "Acme", URL: "https://acme.example/mcp", AuthMode: "oauth"}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}
	g := NewGateway(fs, nil)
	fake := &fakeConnector{}
	api := NewConsoleAPI(fs, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	api.conn = fake // inject the seam
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), fake
}

func doConnect(t *testing.T, mux *http.ServeMux, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/servers/acme/connect", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestConnectDCRPathNoBody: no body → DCR path (nil *StaticCreds), unchanged.
func TestConnectDCRPathNoBody(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !fake.startCalled {
		t.Fatal("StartConnect was not called")
	}
	if fake.sawStatic {
		t.Errorf("expected DCR path (nil *StaticCreds); got static creds %+v", fake.gotSC)
	}
	if !strings.Contains(rec.Body.String(), "authorizeUrl") {
		t.Errorf("response missing authorizeUrl: %s", rec.Body.String())
	}
}

// TestConnectDCRPathEmptyFields: a body with all-empty static fields is still
// the DCR path — backward compatible with any client that posts {}.
func TestConnectDCRPathEmptyFields(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"clientId":"","clientSecret":"","scope":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if fake.sawStatic {
		t.Errorf("expected DCR path for all-empty static fields; got %+v", fake.gotSC)
	}
}

// TestConnectStaticPath: clientId + secret + scope → non-nil *StaticCreds with
// exactly those values reaches StartConnect.
func TestConnectStaticPath(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"clientId":"pre-registered-id","clientSecret":"shhh","scope":"mcp:connect read"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !fake.sawStatic {
		t.Fatal("expected static path (non-nil *StaticCreds); got nil")
	}
	if fake.gotSC.ClientID != "pre-registered-id" {
		t.Errorf("ClientID = %q; want %q", fake.gotSC.ClientID, "pre-registered-id")
	}
	if fake.gotSC.ClientSecret != "shhh" {
		t.Errorf("ClientSecret = %q; want %q", fake.gotSC.ClientSecret, "shhh")
	}
	if fake.gotSC.Scope != "mcp:connect read" {
		t.Errorf("Scope = %q; want %q", fake.gotSC.Scope, "mcp:connect read")
	}
}

// TestConnectStaticPublicClient: clientId + scope, EMPTY secret → still static
// (public client). clientSecret may be empty.
func TestConnectStaticPublicClient(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"clientId":"public-id","scope":"read"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !fake.sawStatic {
		t.Fatal("expected static path for public client (empty secret); got nil *StaticCreds")
	}
	if fake.gotSC.ClientID != "public-id" || fake.gotSC.ClientSecret != "" || fake.gotSC.Scope != "read" {
		t.Errorf("unexpected StaticCreds %+v", fake.gotSC)
	}
}

// TestConnectStaticMissingScope: clientId present but scope empty → 400, and
// StartConnect is NEVER reached.
func TestConnectStaticMissingScope(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"clientId":"pre-registered-id","clientSecret":"shhh"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "scope") {
		t.Errorf("400 body should mention scope: %s", rec.Body.String())
	}
	if fake.startCalled {
		t.Error("StartConnect must not be called when static validation fails")
	}
}

// TestConnectStaticMissingClientID: scope present but clientId empty → 400,
// StartConnect never reached.
func TestConnectStaticMissingClientID(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"scope":"read","clientSecret":"shhh"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "clientId") {
		t.Errorf("400 body should mention clientId: %s", rec.Body.String())
	}
	if fake.startCalled {
		t.Error("StartConnect must not be called when static validation fails")
	}
}

// TestConnectSecretNeverInResponse: the client_secret must never appear in the
// response body — not on success, not on error.
func TestConnectSecretNeverInResponse(t *testing.T) {
	const secret = "TOPSECRET-do-not-echo"

	// Success path.
	mux, tok, _ := newConnectConsole(t)
	rec := doConnect(t, mux, tok, `{"clientId":"id","clientSecret":"`+secret+`","scope":"read"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("client_secret leaked into success response: %s", rec.Body.String())
	}

	// Error path: make StartConnect fail; the error response also must not leak.
	mux2, tok2, fake2 := newConnectConsole(t)
	fake2.startErr = errors.New("token exchange failed (check client_secret_post vs client_secret_basic)")
	rec2 := doConnect(t, mux2, tok2, `{"clientId":"id","clientSecret":"`+secret+`","scope":"read"}`)
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502 (body=%s)", rec2.Code, rec2.Body.String())
	}
	if strings.Contains(rec2.Body.String(), secret) {
		t.Errorf("client_secret leaked into error response: %s", rec2.Body.String())
	}
}

// TestConnectUnknownAccount: connecting an account that does not exist → 404.
func TestConnectUnknownAccount(t *testing.T) {
	mux, tok, fake := newConnectConsole(t)
	req := httptest.NewRequest(http.MethodPost, "/api/servers/nope/connect", strings.NewReader(`{"clientId":"id","scope":"read"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
	if fake.startCalled {
		t.Error("StartConnect must not be called for an unknown account")
	}
}
