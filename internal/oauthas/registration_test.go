package oauthas

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func registerClient(t *testing.T, server *Server, redirects []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"client_name":   "test client",
		"redirect_uris": redirects,
	})
	if err != nil {
		t.Fatalf("marshal registration: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRegister(rec, req)
	return rec
}

func TestRegisterRejectsUnsafeOrAmbiguousRedirectURIs(t *testing.T) {
	unsafe := []string{
		"javascript:alert(1)",
		"data:text/html,hello",
		"http://app.example/callback",
		"https://user:password@app.example/callback",
		"https://app.example/callback#fragment",
		"https://app.example/call\nback",
		"https://app.example/callback%0aheader",
		strings.Repeat("a", 2049),
	}
	for _, redirect := range unsafe {
		t.Run(redirect[:min(len(redirect), 40)], func(t *testing.T) {
			server := New("https://engine.example", "pw", "secret")
			rec := registerClient(t, server, []string{redirect})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("register unsafe redirect %q = %d, body %s", redirect, rec.Code, rec.Body)
			}
			if len(server.clients) != 0 {
				t.Fatalf("unsafe redirect %q created a client", redirect)
			}
		})
	}

	t.Run("canonical duplicate", func(t *testing.T) {
		server := New("https://engine.example", "pw", "secret")
		rec := registerClient(t, server, []string{
			"https://APP.example/callback",
			"https://app.example/callback",
		})
		if rec.Code != http.StatusBadRequest || len(server.clients) != 0 {
			t.Fatalf("duplicate redirects = %d clients=%d, body %s", rec.Code, len(server.clients), rec.Body)
		}
	})

	t.Run("too many redirects", func(t *testing.T) {
		server := New("https://engine.example", "pw", "secret")
		redirects := make([]string, 17)
		for i := range redirects {
			redirects[i] = "https://app.example/callback/" + string(rune('a'+i))
		}
		rec := registerClient(t, server, redirects)
		if rec.Code != http.StatusBadRequest || len(server.clients) != 0 {
			t.Fatalf("too many redirects = %d clients=%d", rec.Code, len(server.clients))
		}
	})
}

func TestRegisterAllowsHTTPSAndLoopbackHTTPRedirects(t *testing.T) {
	server := New("https://engine.example", "pw", "secret")
	redirects := []string{
		"https://app.example/oauth/callback?source=mcp",
		"http://localhost:3000/callback",
		"http://127.0.0.1:4567/callback",
		"http://[::1]:4567/callback",
	}
	rec := registerClient(t, server, redirects)
	if rec.Code != http.StatusCreated {
		t.Fatalf("safe redirect registration = %d, body %s", rec.Code, rec.Body)
	}
	var response struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.ClientID == "" {
		t.Fatalf("decode registration response: client=%q err=%v", response.ClientID, err)
	}
	if len(server.clients) != 0 {
		t.Fatalf("dynamic registration grew server-side client state: %d entries", len(server.clients))
	}
	for _, redirect := range redirects {
		if !server.clientAllowsRedirect(response.ClientID, redirect) {
			t.Fatalf("self-authenticating client ID rejected redirect %q", redirect)
		}
	}
}

func TestStatelessClientRegistrationSurvivesRestartAndRejectsTampering(t *testing.T) {
	const redirect = "https://app.example/oauth/callback"
	first := New("https://engine.example", "pw", "stable-engine-secret")
	rec := registerClient(t, first, []string{redirect})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d, body %s", rec.Code, rec.Body)
	}
	var response struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}

	restarted := New("https://engine.example", "pw", "stable-engine-secret")
	if !restarted.clientAllowsRedirect(response.ClientID, redirect) {
		t.Fatal("stateless client registration did not survive Engine restart")
	}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {response.ClientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"resource":              {"https://engine.example/mcp"},
	}
	authorize := httptest.NewRecorder()
	restarted.handleAuthorize(authorize, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if authorize.Code != http.StatusOK {
		t.Fatalf("restarted Engine authorize = %d, body %s", authorize.Code, authorize.Body)
	}
	if restarted.clientAllowsRedirect(response.ClientID, "https://attacker.example/callback") {
		t.Fatal("stateless client registration accepted an unregistered redirect")
	}
	tampered := response.ClientID[:len(response.ClientID)-1] + "A"
	if tampered == response.ClientID {
		tampered = response.ClientID[:len(response.ClientID)-1] + "B"
	}
	if restarted.clientAllowsRedirect(tampered, redirect) {
		t.Fatal("tampered stateless client ID was accepted")
	}
	wrongSecret := New("https://engine.example", "pw", "different-engine-secret")
	if wrongSecret.clientAllowsRedirect(response.ClientID, redirect) {
		t.Fatal("client ID was accepted under a different Engine secret")
	}
}

func TestRegistrationBodyIsBoundedAndRepeatedRegistrationsDoNotGrowMemory(t *testing.T) {
	server := New("https://engine.example", "pw", "secret")
	oversized := `{"redirect_uris":["https://app.example/` + strings.Repeat("a", maxRegistrationBody) + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleRegister(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized registration = %d, want 400", rec.Code)
	}

	for i := 0; i < 500; i++ {
		rec := registerClient(t, server, []string{"https://app.example/callback"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("registration %d = %d, body %s", i, rec.Code, rec.Body)
		}
	}
	if len(server.clients) != 0 {
		t.Fatalf("500 registrations left %d server-side client records", len(server.clients))
	}
}

func TestUnsafeRegisteredRedirectCannotReachHostedConsent(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	server := New("https://engine.example", "pw", "secret")
	if err := server.ConfigureHostedConsent("https://app.example/consent", publicKey); err != nil {
		t.Fatalf("configure hosted consent: %v", err)
	}
	server.clients["legacy_unsafe"] = client{redirectURIs: map[string]bool{
		"javascript:alert(1)": true,
	}}
	sum := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	q := url.Values{
		"client_id":             {"legacy_unsafe"},
		"redirect_uri":          {"javascript:alert(1)"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"resource":              {"https://engine.example/mcp"},
	}
	rec := httptest.NewRecorder()
	server.handleAuthorize(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsafe legacy redirect reached consent: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("unsafe legacy redirect created hosted flow: location=%q", rec.Header().Get("Location"))
	}
}
