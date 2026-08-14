package oauthas

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsentPageHasAntiFramingHeaders(t *testing.T) {
	_, mux, values := passwordConsentServer()

	assertHeaders := func(t *testing.T, rec *httptest.ResponseRecorder, what string) {
		t.Helper()
		if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
			t.Fatalf("%s CSP = %q, want frame-ancestors 'none'", what, got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Fatalf("%s X-Frame-Options = %q, want DENY", what, got)
		}
	}

	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET consent = %d, body %s", getRec.Code, getRec.Body)
	}
	assertHeaders(t, getRec, "GET consent")

	values.Set("password", "wrong-password")
	postRec := consentPost(mux, values, "192.0.2.1:1111", nil)
	if postRec.Code != http.StatusUnauthorized {
		t.Fatalf("failed POST = %d, want 401", postRec.Code)
	}
	assertHeaders(t, postRec, "failed POST")
	if !strings.Contains(postRec.Body.String(), "Enter your console password") {
		t.Fatalf("failed POST body = %q, want the consent page re-rendered", postRec.Body)
	}
}
