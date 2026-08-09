package upstreamoauth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// publicTestOrigin routes a public-looking TLS URL to an httptest server. The
// standard httptest certificate covers example.com, so discovery exercises the
// production URL checks without granting a loopback exception to those checks.
func publicTestOrigin(t *testing.T, server *httptest.Server) (string, *http.Client) {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	baseTransport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport type = %T, want *http.Transport", server.Client().Transport)
	}
	target := serverURL.Host
	dialer := &net.Dialer{}
	transport := baseTransport.Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target)
	}
	return "https://example.com:" + serverURL.Port(), &http.Client{Transport: transport}
}

func TestProtectedResourceMetadataURLs(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		wantURLs []string
	}{
		{
			name:   "path scoped resource precedes origin fallback",
			rawURL: "https://gmailmcp.googleapis.com/mcp/v1",
			wantURLs: []string{
				"https://gmailmcp.googleapis.com/.well-known/oauth-protected-resource/mcp/v1",
				"https://gmailmcp.googleapis.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:   "origin resource uses only origin metadata",
			rawURL: "https://mcp.example.com",
			wantURLs: []string{
				"https://mcp.example.com/.well-known/oauth-protected-resource",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			origin := u.Scheme + "://" + u.Host
			if got := protectedResourceMetadataURLs(origin, u); !reflect.DeepEqual(got, tc.wantURLs) {
				t.Errorf("protectedResourceMetadataURLs() = %#v, want %#v", got, tc.wantURLs)
			}
		})
	}
}

// TestDiscover_PathScopedProtectedResourceMetadataFallback models Gmail's
// remote MCP service: initialize succeeds without issuing an OAuth challenge,
// the origin-level metadata endpoint is absent, and RFC 9728 metadata lives at
// the path-scoped well-known URL. Discovery must still find its OAuth server.
func TestDiscover_PathScopedProtectedResourceMetadataFallback(t *testing.T) {
	var pathScopedMetadataRequests, originMetadataRequests int
	const authorizationEndpoint = "https://auth.example.test/authorize"
	const tokenEndpoint = "https://auth.example.test/token"
	var origin string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp/v1":
			if r.Method != http.MethodPost {
				t.Errorf("MCP probe method = %s, want POST", r.Method)
			}
			// An initialize response without WWW-Authenticate makes Discover use
			// its RFC 9728 well-known fallback.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		case "/.well-known/oauth-protected-resource/mcp/v1":
			pathScopedMetadataRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource":              origin + "/mcp/v1",
				"authorization_servers": []string{origin},
			})
		case "/.well-known/oauth-protected-resource":
			originMetadataRequests++
			http.NotFound(w, r)
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": authorizationEndpoint,
				"token_endpoint":         tokenEndpoint,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	origin, client := publicTestOrigin(t, server)
	originalClient := httpClient
	httpClient = client
	t.Cleanup(func() { httpClient = originalClient })

	metadata, err := Discover(context.Background(), origin+"/mcp/v1")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if pathScopedMetadataRequests != 1 {
		t.Errorf("path-scoped metadata requests = %d, want 1", pathScopedMetadataRequests)
	}
	if originMetadataRequests != 0 {
		t.Errorf("origin metadata requests = %d, want 0", originMetadataRequests)
	}
	if metadata.Resource != origin+"/mcp/v1" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, origin+"/mcp/v1")
	}
	if metadata.AuthorizationEndpoint != authorizationEndpoint {
		t.Errorf("AuthorizationEndpoint = %q", metadata.AuthorizationEndpoint)
	}
	if metadata.TokenEndpoint != tokenEndpoint {
		t.Errorf("TokenEndpoint = %q", metadata.TokenEndpoint)
	}
	if metadata.RegistrationEndpoint != "" {
		t.Errorf("RegistrationEndpoint = %q, want empty", metadata.RegistrationEndpoint)
	}
}

func TestDiscoverRejectsUnsafeOAuthEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		endpoint  string
		wantError string
	}{
		{
			name:      "cleartext authorization endpoint",
			field:     "authorization_endpoint",
			endpoint:  "http://public.example.test/authorize",
			wantError: "discovered authorization_endpoint rejected",
		},
		{
			name:      "cleartext token endpoint",
			field:     "token_endpoint",
			endpoint:  "http://public.example.test/token",
			wantError: "discovered token_endpoint rejected",
		},
		{
			name:      "private registration endpoint",
			field:     "registration_endpoint",
			endpoint:  "https://127.0.0.1/register",
			wantError: "discovered registration_endpoint rejected",
		},
		{
			name:      "token endpoint with userinfo",
			field:     "token_endpoint",
			endpoint:  "https://attacker@example.test/token",
			wantError: "discovered token_endpoint rejected",
		},
		{
			name:      "authorization endpoint with fragment",
			field:     "authorization_endpoint",
			endpoint:  "https://auth.example.test/authorize#fragment",
			wantError: "discovered authorization_endpoint rejected",
		},
		{
			name:      "relative token endpoint",
			field:     "token_endpoint",
			endpoint:  "/token",
			wantError: "discovered token_endpoint rejected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := map[string]string{
				"authorization_endpoint": "https://auth.example.test/authorize",
				"token_endpoint":         "https://auth.example.test/token",
				"registration_endpoint":  "https://auth.example.test/register",
			}
			endpoints[tc.field] = tc.endpoint

			var origin string
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/oauth-protected-resource":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"resource":              origin + "/mcp",
						"authorization_servers": []string{origin},
					})
				case "/.well-known/oauth-authorization-server":
					_ = json.NewEncoder(w).Encode(endpoints)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			origin, client := publicTestOrigin(t, server)
			originalClient := httpClient
			httpClient = client
			t.Cleanup(func() { httpClient = originalClient })

			_, err := Discover(context.Background(), origin+"/mcp")
			if err == nil {
				t.Fatalf("Discover accepted unsafe %s %q", tc.field, tc.endpoint)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Discover error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestGetJSONRejectsUnsafeMetadataURLsBeforeNetwork(t *testing.T) {
	originalClient := httpClient
	calls := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, nil
	})}
	t.Cleanup(func() { httpClient = originalClient })

	for _, rawURL := range []string{
		"http://metadata.example.test/resource",
		"/relative-resource-metadata",
		"https://attacker@metadata.example.test/resource",
		"https://metadata.example.test/resource#fragment",
		"https://127.0.0.1/resource",
	} {
		t.Run(rawURL, func(t *testing.T) {
			var out map[string]any
			if err := getJSON(context.Background(), rawURL, &out); err == nil {
				t.Fatalf("getJSON accepted unsafe metadata URL %q", rawURL)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("unsafe metadata URLs made %d network request(s)", calls)
	}
}

func TestDiscoverRejectsUnsafeAdvertisedResourceMetadataBeforeGET(t *testing.T) {
	const serverURL = "https://mcp.example.test/mcp"
	const advertisedMetadataURL = "http://metadata.example.test/resource"

	originalClient := httpClient
	calls := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.URL.String() != serverURL {
			t.Errorf("unexpected discovery request: %s %s", req.Method, req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Www-Authenticate": []string{
					`Bearer resource_metadata="` + advertisedMetadataURL + `"`,
				},
			},
			Body:    http.NoBody,
			Request: req,
		}, nil
	})}
	t.Cleanup(func() { httpClient = originalClient })

	_, err := Discover(context.Background(), serverURL)
	if err == nil {
		t.Fatal("Discover accepted a cleartext resource_metadata URL")
	}
	if !strings.Contains(err.Error(), "metadata URL rejected") {
		t.Fatalf("Discover error = %v, want metadata URL rejection", err)
	}
	if calls != 1 {
		t.Fatalf("unsafe resource_metadata caused %d request(s), want only the initial probe", calls)
	}
}
