package engine

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Driven by scripts/test-browser-runtime-cdp.mjs; the test process routes only
// the provider WebSocket transport to a disposable local Chromium fixture.
func TestBrowserRuntimeChromium(t *testing.T) {
	endpoint := os.Getenv("SYNAXIS_TEST_BROWSER_CDP_URL")
	if endpoint == "" {
		t.Skip("run node scripts/test-browser-runtime-cdp.mjs")
	}
	local, err := url.Parse(endpoint)
	if err != nil || local.Scheme != "http" || local.Hostname() != "127.0.0.1" {
		t.Fatal("fixture must be local")
	}
	p := browserbaseTestProvider(t)
	transport := http.DefaultTransport
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = local.Host
		r.Host = local.Host
		return transport.RoundTrip(r)
	})
	connect := "wss://connect.browserbase.com" + local.Path
	site := "https://browser-runtime.example/"
	call := func(a BrowserAction) *BrowserSnapshot {
		t.Helper()
		out, err := p.BrowserAction(t.Context(), connect, site, a)
		if err != nil {
			t.Fatalf("%s: %v", a.Operation, err)
		}
		return out
	}
	call(BrowserAction{Operation: "open"})
	var snapshot *BrowserSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err = p.BrowserAction(t.Context(), connect, site, BrowserAction{Operation: "snapshot"})
		if err == nil && snapshot.Title == "Browser adapter fixture" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if snapshot == nil || snapshot.Title != "Browser adapter fixture" {
		t.Fatal("fixture did not load", err)
	}
	element := func(s *BrowserSnapshot, label string) int {
		t.Helper()
		for _, e := range s.Elements {
			if e.Label == label {
				return e.ID
			}
		}
		t.Fatalf("element %q absent: %+v", label, s.Elements)
		return 0
	}
	call(BrowserAction{Operation: "type", Snapshot: snapshot.ID, Element: element(snapshot, "Draft"), Text: "Hello from the saved profile adapter"})
	next := call(BrowserAction{Operation: "snapshot"})
	// Taking a new snapshot invalidates old handles even on the same document.
	if _, err = p.BrowserAction(t.Context(), connect, site, BrowserAction{Operation: "click", Snapshot: snapshot.ID, Element: element(snapshot, "Publish")}); err == nil {
		t.Fatal("old snapshot remained actionable")
	}
	call(BrowserAction{Operation: "click", Snapshot: next.ID, Element: element(next, "Publish")})
	final := call(BrowserAction{Operation: "snapshot"})
	if !strings.Contains(final.Text, "Published: Hello from the saved profile adapter") {
		t.Fatalf("type/click did not reach fixture: %q", final.Text)
	}
	if _, err = p.BrowserAction(t.Context(), connect, site, BrowserAction{Operation: "navigate", URL: "https://other.example/"}); err == nil {
		t.Fatal("off-site navigation accepted")
	}
}
