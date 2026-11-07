//go:build synaxis_e2e

package engine

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// The hosted broker callback still crosses the actual Web proxy. Only the
// exact fixture host maps to its loopback port, and the synthetic Kernel CDP
// endpoint uses the same deterministic page as the existing browser fixture.
func init() {
	port, err := strconv.Atoi(os.Getenv("SYNAXIS_E2E_MANAGED_BROWSER_WEB_PORT"))
	if os.Getenv("SYNAXIS_ENV") != "test" || err != nil || port < 1 || port > 65535 {
		return
	}
	managedBrowserClientFactory = func() *http.Client {
		client := newManagedBrowserHTTPClient()
		client.Transport = managedBrowserE2ETransport{
			address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			local:   &http.Transport{},
		}
		return client
	}
	kernelBrowserAction = func(ctx context.Context, _ *http.Client, connect, website string, action BrowserAction) (*BrowserSnapshot, error) {
		u, err := url.Parse(connect)
		if err != nil || u.Scheme != "wss" || u.Host != "synaxis-e2e.onkernel.com" || u.RawQuery != "" || !strings.HasPrefix(u.Path, "/fixture-browser-") || !browserResourceID(strings.TrimPrefix(u.Path, "/")) {
			return nil, errBrowserSignIn
		}
		return (e2eSignInBrowser{}).BrowserAction(ctx, connect, website, action)
	}
}

type managedBrowserE2ETransport struct {
	address string
	local   http.RoundTripper
}

func (t managedBrowserE2ETransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "synaxis-e2e.invalid" || !strings.HasPrefix(r.URL.Path, "/v1/internal/managed-browser/") {
		return nil, errBrowserSignIn
	}
	req := r.Clone(r.Context())
	req.URL.Scheme, req.URL.Host = "http", t.address
	req.Host = t.address
	return t.local.RoundTrip(req)
}
