package upstreamoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

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
				"resource":              server.URL + "/mcp/v1",
				"authorization_servers": []string{server.URL},
			})
		case "/.well-known/oauth-protected-resource":
			originMetadataRequests++
			http.NotFound(w, r)
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalClient := httpClient
	httpClient = server.Client()
	t.Cleanup(func() { httpClient = originalClient })

	metadata, err := Discover(context.Background(), server.URL+"/mcp/v1")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if pathScopedMetadataRequests != 1 {
		t.Errorf("path-scoped metadata requests = %d, want 1", pathScopedMetadataRequests)
	}
	if originMetadataRequests != 0 {
		t.Errorf("origin metadata requests = %d, want 0", originMetadataRequests)
	}
	if metadata.Resource != server.URL+"/mcp/v1" {
		t.Errorf("Resource = %q, want %q", metadata.Resource, server.URL+"/mcp/v1")
	}
	if metadata.AuthorizationEndpoint != server.URL+"/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", metadata.AuthorizationEndpoint)
	}
	if metadata.TokenEndpoint != server.URL+"/token" {
		t.Errorf("TokenEndpoint = %q", metadata.TokenEndpoint)
	}
	if metadata.RegistrationEndpoint != "" {
		t.Errorf("RegistrationEndpoint = %q, want empty", metadata.RegistrationEndpoint)
	}
}
