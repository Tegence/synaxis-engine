package oauthas

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// passwordConsentServer returns a self-hosted server and the form values for a
// valid consent POST against it (password left unset).
func passwordConsentServer() (*Server, *http.ServeMux, url.Values) {
	server := New("https://engine.example", "self-hosted-password", "engine-secret")
	server.clients["mcp_self_hosted"] = client{redirectURIs: map[string]bool{
		"https://client.example/callback": true,
	}}
	sum := sha256.Sum256([]byte(strings.Repeat("s", 64)))
	values := url.Values{
		"client_id":             {"mcp_self_hosted"},
		"redirect_uri":          {"https://client.example/callback"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"resource":              {"https://engine.example/mcp"},
		"state":                 {"self-hosted-state"},
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	return server, mux, values
}

func consentPost(mux *http.ServeMux, values url.Values, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestConsentThrottleDeniesEleventhAttempt(t *testing.T) {
	_, mux, values := passwordConsentServer()
	values.Set("password", "wrong-password")

	for i := 0; i < 10; i++ {
		rec := consentPost(mux, values, "192.0.2.1:1111", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	rec := consentPost(mux, values, "192.0.2.1:1111", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th attempt = %d, want 429; body %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Too many attempts") {
		t.Fatalf("429 body = %q, want the consent page re-rendered with an error", rec.Body)
	}

	// A different client IP keeps its own budget.
	if rec := consentPost(mux, values, "192.0.2.2:2222", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fresh IP attempt = %d, want 401", rec.Code)
	}
}

// TestConsentThrottleIgnoresForwardedHeaderByDefault mirrors the engine
// console's login-throttle coverage: without opting in, a spoofed
// X-Forwarded-For must not let an attacker bypass another client's exhausted
// budget by rotating keys, and must not let an attacker key their own
// requests away from RemoteAddr either.
func TestConsentThrottleIgnoresForwardedHeaderByDefault(t *testing.T) {
	_, mux, values := passwordConsentServer()
	values.Set("password", "wrong-password")

	for i := 0; i < 10; i++ {
		consentPost(mux, values, "192.0.2.1:1111", nil)
	}
	rec := consentPost(mux, values, "192.0.2.1:3333", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For = %d, want 429 (RemoteAddr still exhausted)", rec.Code)
	}
}

// TestConsentThrottleTrustsForwardedHeaderWhenOptedIn proves the opt-in
// SetTrustProxyHeaders path: once enabled, the limiter keys on the trusted
// X-Forwarded-For hop instead of RemoteAddr, so requests arriving through a
// reverse proxy (which shares one fixed RemoteAddr for every real client)
// still get independent per-client budgets.
func TestConsentThrottleTrustsForwardedHeaderWhenOptedIn(t *testing.T) {
	server, mux, values := passwordConsentServer()
	server.SetTrustProxyHeaders(true)
	values.Set("password", "wrong-password")

	const proxyAddr = "192.0.2.250:9999"
	for i := 0; i < 10; i++ {
		rec := consentPost(mux, values, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.1"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := consentPost(mux, values, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.1"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted forwarded client = %d, want 429", rec.Code)
	}

	// A different forwarded client through the same proxy keeps its own
	// budget — this is the whole point of the opt-in.
	if rec := consentPost(mux, values, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.2"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fresh forwarded client = %d, want 401 (must not share the exhausted proxy RemoteAddr bucket)", rec.Code)
	}
}
