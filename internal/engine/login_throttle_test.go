package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func loginAttempt(mux *http.ServeMux, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"Password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestConsoleLoginThrottleDeniesEleventhAttempt(t *testing.T) {
	mux := newAuthTestConsole()

	for i := 0; i < 10; i++ {
		rec := loginAttempt(mux, "192.0.2.1:1111", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	rec := loginAttempt(mux, "192.0.2.1:1111", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th attempt = %d, want 429; body %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "too many attempts") {
		t.Fatalf("429 body = %q, want a plain error", rec.Body)
	}
}

func TestConsoleLoginThrottleKeysByRemoteIP(t *testing.T) {
	mux := newAuthTestConsole()

	for i := 0; i < 10; i++ {
		loginAttempt(mux, "192.0.2.1:1111", nil)
	}
	if rec := loginAttempt(mux, "192.0.2.1:1111", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted IP = %d, want 429", rec.Code)
	}

	// A second client IP keeps its own budget.
	if rec := loginAttempt(mux, "192.0.2.2:2222", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fresh IP attempt = %d, want 401", rec.Code)
	}

	// A spoofed forwarding header must not bypass the exhausted key: the
	// limiter keys on RemoteAddr only.
	rec := loginAttempt(mux, "192.0.2.1:3333", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For = %d, want 429 (RemoteAddr still exhausted)", rec.Code)
	}
}

// TestConsoleLoginThrottleTrustsForwardedHeaderWhenOptedIn proves the
// opt-in WithTrustProxyHeaders path: once enabled, the limiter keys on the
// trusted X-Forwarded-For hop instead of RemoteAddr, so requests arriving
// through a reverse proxy (which shares one fixed RemoteAddr for every real
// client) still get independent per-client budgets.
func TestConsoleLoginThrottleTrustsForwardedHeaderWhenOptedIn(t *testing.T) {
	mux := newAuthTestConsole(WithTrustProxyHeaders(true))

	// All requests share one proxy RemoteAddr, distinguished only by
	// X-Forwarded-For — simulating every real client passing through the
	// same reverse proxy.
	const proxyAddr = "192.0.2.250:9999"
	for i := 0; i < 10; i++ {
		rec := loginAttempt(mux, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.1"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := loginAttempt(mux, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.1"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted forwarded client = %d, want 429", rec.Code)
	}

	// A different forwarded client through the same proxy keeps its own
	// budget — this is the whole point of the opt-in.
	if rec := loginAttempt(mux, proxyAddr, map[string]string{"X-Forwarded-For": "203.0.113.2"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fresh forwarded client = %d, want 401 (must not share the exhausted proxy RemoteAddr bucket)", rec.Code)
	}
}
