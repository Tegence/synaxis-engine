package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type upstreamRedirectRoundTripper func(*http.Request) (*http.Response, error)

func (f upstreamRedirectRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// Exercise the real SDK initialization path: Go's default redirect policy may
// retain Authorization on a subdomain or changed port even though the resource
// origin has changed. No redirected request may reach the transport at all.
func TestUpstreamMCPRedirectRejectsCrossOrigin(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{
			"https://other.example/collect",
			"https://child.mcp.example/collect",
			"https://mcp.example:8443/collect",
		} {
			for _, credential := range []string{"Token", "Credential"} {
				t.Run(fmt.Sprintf("%d/%s/%s", status, target, credential), func(t *testing.T) {
					var requests []*http.Request
					previous := newUpstreamTransport
					newUpstreamTransport = func() http.RoundTripper {
						return upstreamRedirectRoundTripper(func(request *http.Request) (*http.Response, error) {
							requests = append(requests, request.Clone(request.Context()))
							if len(requests) > 1 {
								return nil, errors.New("test stopped an unsafe redirected request")
							}
							return &http.Response{StatusCode: status, Header: http.Header{"Location": {target}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
						})
					}
					t.Cleanup(func() { newUpstreamTransport = previous })
					upstream := &Upstream{Name: "redirect-test", URL: "https://mcp.example/mcp"}
					if credential == "Token" {
						upstream.Token = func() string { return "synthetic-current-token" }
					} else {
						upstream.Credential = func() (string, error) { return "synthetic-current-token", nil }
					}
					connection, err := upstream.dial(context.Background())
					if connection != nil {
						connection.client.Close()
					}
					if err == nil {
						t.Fatal("cross-origin redirect unexpectedly initialized an MCP client")
					}
					if len(requests) != 1 {
						t.Fatalf("redirect reached %s; Authorization attached: %t", requests[len(requests)-1].URL.Host, requests[len(requests)-1].Header.Get("Authorization") != "")
					}
					if requests[0].Header.Get("Authorization") != "Bearer synthetic-current-token" {
						t.Fatal("initial request did not use the current credential")
					}
				})
			}
		}
	}
}

func TestUpstreamMCPRedirectAllowsSameOrigin(t *testing.T) {
	for _, scenario := range []struct {
		target               string
		requireAuthorization bool
	}{
		{"/canonical", true},
		{"https://mcp.example/canonical", true},
		// Go 1.26 strips Authorization when the hostname's case changes;
		// later Go versions retain it. The origin policy allows this URL but
		// must not override net/http's stricter credential handling.
		{"https://MCP.EXAMPLE:443/canonical", false},
	} {
		t.Run(scenario.target, func(t *testing.T) {
			var redirected int
			previous := newUpstreamTransport
			newUpstreamTransport = func() http.RoundTripper {
				return upstreamRedirectRoundTripper(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/mcp" {
						return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": {scenario.target}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
					}
					redirected++
					if request.Method == http.MethodDelete {
						if request.Header.Get("Mcp-Session-Id") != "synthetic-session" {
							t.Error("same-origin close request lost its session")
						}
						return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
					}
					if scenario.requireAuthorization && request.Header.Get("Authorization") != "Bearer synthetic-current-token" {
						t.Error("same-origin request lost its credential")
					}
					var message struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
						return nil, err
					}
					if message.Method != "initialize" {
						return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
					}
					body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"redirect-test","version":"1"}}}`, message.ID)
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}, "Mcp-Session-Id": {"synthetic-session"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
				})
			}
			t.Cleanup(func() { newUpstreamTransport = previous })
			upstream := &Upstream{Name: "redirect-test", URL: "https://mcp.example/mcp", Credential: func() (string, error) { return "synthetic-current-token", nil }}
			connection, err := upstream.dial(context.Background())
			if err != nil {
				t.Fatalf("same-origin redirect failed initialization: %v", err)
			}
			connection.client.Close()
			if redirected == 0 {
				t.Fatal("test never reached the canonical MCP endpoint")
			}
		})
	}
}

func TestUpstreamMCPRedirectRetainsSafetyChecks(t *testing.T) {
	origin := &http.Request{URL: &url.URL{Scheme: "https", Host: "mcp.example", Path: "/mcp"}}
	for _, target := range []string{
		"http://mcp.example/canonical",
		"https://127.0.0.1/canonical",
		"https://user:password@mcp.example/canonical",
	} {
		t.Run(target, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkUpstreamMCPRedirect(request, []*http.Request{origin}); err == nil {
				t.Fatal("unsafe redirect accepted")
			}
		})
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = origin
	}
	if err := checkUpstreamMCPRedirect(origin, via); err == nil {
		t.Fatal("same-origin redirect limit was not enforced")
	}
	if err := checkUpstreamMCPRedirect(origin, nil); err == nil {
		t.Fatal("redirect without a trusted origin was accepted")
	}
}
