package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterDeniesAttemptBeyondLimit(t *testing.T) {
	limiter := New(10, 5*time.Minute)
	for i := 0; i < 10; i++ {
		if !limiter.Allow("192.0.2.1") {
			t.Fatalf("attempt %d denied, want allowed", i+1)
		}
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatal("11th attempt allowed, want denied")
	}
}

func TestLimiterSweepsEntriesOlderThanWindow(t *testing.T) {
	now := time.Now()
	limiter := New(10, 5*time.Minute)
	limiter.now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		limiter.Allow("192.0.2.1")
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatal("attempt within window allowed, want denied")
	}

	now = now.Add(6 * time.Minute)
	if !limiter.Allow("192.0.2.1") {
		t.Fatal("attempt after window denied, want allowed after sweep")
	}
	if len(limiter.attempts) != 1 {
		t.Fatalf("stale keys not swept: %d keys remain", len(limiter.attempts))
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	limiter := New(10, 5*time.Minute)
	for i := 0; i < 10; i++ {
		limiter.Allow("192.0.2.1")
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatal("exhausted key allowed, want denied")
	}
	if !limiter.Allow("192.0.2.2") {
		t.Fatal("fresh key denied, want allowed")
	}
}

func TestRemoteIPStripsPort(t *testing.T) {
	if got := RemoteIP("192.0.2.1:1234"); got != "192.0.2.1" {
		t.Fatalf("RemoteIP = %q, want host only", got)
	}
	if got := RemoteIP("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("RemoteIP = %q, want v6 host only", got)
	}
	if got := RemoteIP("192.0.2.1"); got != "192.0.2.1" {
		t.Fatalf("RemoteIP without port = %q, want unchanged", got)
	}
}

func newXFFRequest(remoteAddr, xff string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

func TestClientIPDefaultsToRemoteAddrWhenUntrusted(t *testing.T) {
	req := newXFFRequest("192.0.2.1:1111", "203.0.113.9")
	if got := ClientIP(req, false); got != "192.0.2.1" {
		t.Fatalf("ClientIP(trust=false) = %q, want RemoteAddr host 192.0.2.1 (X-Forwarded-For must be ignored)", got)
	}
}

func TestClientIPUsesForwardedHeaderWhenTrusted(t *testing.T) {
	req := newXFFRequest("192.0.2.1:1111", "203.0.113.9")
	if got := ClientIP(req, true); got != "203.0.113.9" {
		t.Fatalf("ClientIP(trust=true) = %q, want forwarded 203.0.113.9", got)
	}
}

func TestClientIPTrustsOnlyTheLastForwardedHop(t *testing.T) {
	// A client sitting in front of the one trusted proxy can set earlier
	// entries itself; only the last entry (appended by the trusted proxy) is
	// safe to use as the rate-limit key.
	req := newXFFRequest("192.0.2.1:1111", "9.9.9.9, 203.0.113.9")
	if got := ClientIP(req, true); got != "203.0.113.9" {
		t.Fatalf("ClientIP(trust=true) = %q, want the last hop 203.0.113.9, not the client-spoofable first entry", got)
	}
}

func TestClientIPFallsBackToRemoteAddrOnMalformedHeader(t *testing.T) {
	req := newXFFRequest("192.0.2.1:1111", "not-an-ip")
	if got := ClientIP(req, true); got != "192.0.2.1" {
		t.Fatalf("ClientIP(trust=true) with malformed header = %q, want RemoteAddr fallback 192.0.2.1", got)
	}
}

func TestClientIPFallsBackToRemoteAddrWhenHeaderAbsent(t *testing.T) {
	req := newXFFRequest("192.0.2.1:1111", "")
	if got := ClientIP(req, true); got != "192.0.2.1" {
		t.Fatalf("ClientIP(trust=true) without header = %q, want RemoteAddr fallback 192.0.2.1", got)
	}
}
