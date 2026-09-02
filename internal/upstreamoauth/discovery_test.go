package upstreamoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
				"scopes_supported":      []string{"read", "write"},
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
	if metadata.Scope != "read write" {
		t.Errorf("Scope = %q, want read write", metadata.Scope)
	}
}

func TestDiscoverCapturesFigmaStyleScopeAndConfidentialRegistration(t *testing.T) {
	const (
		authorizationEndpoint = "https://auth.example.test/authorize"
		tokenEndpoint         = "https://auth.example.test/token"
		registrationEndpoint  = "https://auth.example.test/register"
	)
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/.well-known/oauth-protected-resource",scope="mcp:connect"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource":              origin + "/mcp",
				"authorization_servers": []string{origin},
				"scopes_supported":      []string{"read", "write"},
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_endpoint":                authorizationEndpoint,
				"token_endpoint":                        tokenEndpoint,
				"registration_endpoint":                 registrationEndpoint,
				"scopes_supported":                      []string{"mcp:connect"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var client *http.Client
	origin, client = publicTestOrigin(t, server)
	originalClient := httpClient
	httpClient = client
	t.Cleanup(func() { httpClient = originalClient })

	metadata, err := Discover(context.Background(), origin+"/mcp")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if metadata.Scope != "mcp:connect" {
		t.Errorf("Scope = %q, want mcp:connect", metadata.Scope)
	}
	if got, err := metadata.DynamicRegistrationAuthMethod(); err != nil || got != "client_secret_post" {
		t.Fatalf("DynamicRegistrationAuthMethod() = %q, %v; want client_secret_post", got, err)
	}
}

func TestRegisterDiscoveredClientRequestsNegotiatedAuthMethod(t *testing.T) {
	const registrationEndpoint = "https://auth.example.test/register"
	var requestBody map[string]any
	originalClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode registration request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"client_id":"figma-client","client_secret":"figma-secret","token_endpoint_auth_method":"client_secret_post"}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { httpClient = originalClient })

	client, err := RegisterDiscoveredClient(context.Background(), &Metadata{
		RegistrationEndpoint:              registrationEndpoint,
		Scope:                             "mcp:connect",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
	}, "https://workspace.example/api/oauth/callback")
	if err != nil {
		t.Fatalf("RegisterDiscoveredClient: %v", err)
	}
	if client.ClientID != "figma-client" || client.ClientSecret != "figma-secret" {
		t.Fatalf("client = %+v", client)
	}
	if got := requestBody["token_endpoint_auth_method"]; got != "client_secret_post" {
		t.Errorf("token_endpoint_auth_method = %v, want client_secret_post", got)
	}
	if got := requestBody["scope"]; got != "mcp:connect" {
		t.Errorf("scope = %v, want mcp:connect", got)
	}
	if got := requestBody["client_uri"]; got != "https://synaxis.tools" {
		t.Errorf("client_uri = %v, want https://synaxis.tools", got)
	}
}

// TestFigmaDynamicOAuthComposition covers the dynamic segment StartConnect
// composes: protected-resource discovery, confidential DCR, PKCE generation,
// and a scoped authorization URL. Keeping the whole sequence in one test
// prevents the individual helpers from passing while their hand-off breaks.
func TestFigmaDynamicOAuthComposition(t *testing.T) {
	const redirectURI = "https://workspace.example/api/oauth/callback"
	registrationBodies := make(chan map[string]any, 1)
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/.well-known/oauth-protected-resource", scope="mcp:connect"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource":              origin + "/mcp",
				"authorization_servers": []string{origin},
				"scopes_supported":      []string{"ignored:scope"},
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_endpoint":                origin + "/authorize",
				"token_endpoint":                        origin + "/token",
				"registration_endpoint":                 origin + "/register",
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			})
		case "/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode registration request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			registrationBodies <- body
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"figma-client","client_secret":"figma-secret","token_endpoint_auth_method":"client_secret_post"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var client *http.Client
	origin, client = publicTestOrigin(t, server)
	originalClient := httpClient
	httpClient = client
	t.Cleanup(func() { httpClient = originalClient })

	metadata, err := Discover(context.Background(), origin+"/mcp")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	registered, err := RegisterDiscoveredClient(context.Background(), metadata, redirectURI)
	if err != nil {
		t.Fatalf("RegisterDiscoveredClient: %v", err)
	}
	pkce, state, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	authorizeURL := AuthorizeURL(metadata, registered.ClientID, redirectURI, pkce.Challenge, state, metadata.Scope, nil)

	registrationBody := <-registrationBodies
	if got := registrationBody["redirect_uris"]; !reflect.DeepEqual(got, []any{redirectURI}) {
		t.Errorf("registration redirect_uris = %#v, want [%q]", got, redirectURI)
	}
	for key, want := range map[string]string{
		"scope":                      "mcp:connect",
		"token_endpoint_auth_method": "client_secret_post",
		"client_uri":                 "https://synaxis.tools",
	} {
		if got := registrationBody[key]; got != want {
			t.Errorf("registration %s = %#v, want %q", key, got, want)
		}
	}

	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if got, want := parsed.Scheme+"://"+parsed.Host+parsed.Path, origin+"/authorize"; got != want {
		t.Errorf("authorization endpoint = %q, want %q", got, want)
	}
	sum := sha256.Sum256([]byte(pkce.Verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "figma-client",
		"redirect_uri":          redirectURI,
		"code_challenge":        wantChallenge,
		"code_challenge_method": "S256",
		"state":                 state,
		"resource":              origin + "/mcp",
		"scope":                 "mcp:connect",
	} {
		if got := parsed.Query().Get(key); got != want {
			t.Errorf("authorization query %s = %q, want %q", key, got, want)
		}
	}
	if parsed.Query().Get("client_secret") != "" {
		t.Error("authorization URL leaked the dynamically registered client secret")
	}
}

func TestDynamicRegistrationAuthMethod(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *Metadata
		want      string
		wantError string
	}{
		{name: "nil metadata", wantError: "OAuth metadata is required"},
		{name: "omitted advertisement keeps public DCR", metadata: &Metadata{}, want: "none"},
		{name: "public client is preferred", metadata: &Metadata{TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "none"}}, want: "none"},
		{name: "confidential post is supported", metadata: &Metadata{TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", " client_secret_post "}}, want: "client_secret_post"},
		{name: "basic only is rejected", metadata: &Metadata{TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"}}, wantError: "does not advertise a supported"},
		{name: "unknown method is rejected", metadata: &Metadata{TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"}}, wantError: "does not advertise a supported"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.metadata.DynamicRegistrationAuthMethod()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("DynamicRegistrationAuthMethod() = %q, %v; want error containing %q", got, err, tc.wantError)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("DynamicRegistrationAuthMethod() = %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestRegisterDiscoveredClientReportsProviderApprovalDenial(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			originalClient := httpClient
			httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"error":"unauthorized_client"}`)),
					Request:    req,
				}, nil
			})}
			t.Cleanup(func() { httpClient = originalClient })

			_, err := RegisterDiscoveredClient(context.Background(), &Metadata{
				RegistrationEndpoint:              "https://auth.example.test/register",
				Scope:                             "mcp:connect",
				TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
			}, "https://workspace.example/api/oauth/callback")
			if err == nil {
				t.Fatal("expected provider registration denial")
			}
			for _, want := range []string{
				fmt.Sprintf("register -> %d", status),
				"provider denied dynamic client registration",
				"may require provider approval",
				"unauthorized_client",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("registration error = %q, want %q", err, want)
				}
			}
		})
	}
}

func TestRegisterDiscoveredClientRejectsIncompatibleConfidentialResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantError string
	}{
		{
			name:      "missing client secret",
			response:  `{"client_id":"figma-client","token_endpoint_auth_method":"client_secret_post"}`,
			wantError: "no client_secret returned for client_secret_post",
		},
		{
			name:      "provider substitutes basic authentication",
			response:  `{"client_id":"figma-client","client_secret":"figma-secret","token_endpoint_auth_method":"client_secret_basic"}`,
			wantError: `provider returned unsupported token authentication method "client_secret_basic"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalClient := httpClient
			httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusCreated,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(tc.response)),
					Request:    req,
				}, nil
			})}
			t.Cleanup(func() { httpClient = originalClient })

			_, err := RegisterDiscoveredClient(context.Background(), &Metadata{
				RegistrationEndpoint:              "https://auth.example.test/register",
				TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
			}, "https://workspace.example/api/oauth/callback")
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("RegisterDiscoveredClient() error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestRegisterDiscoveredClientPreservesLegacyPublicRegistration(t *testing.T) {
	var requestBody map[string]any
	originalClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode registration request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"client_id":"legacy-public-client"}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { httpClient = originalClient })

	client, err := RegisterDiscoveredClient(context.Background(), &Metadata{
		RegistrationEndpoint: "https://auth.example.test/register",
	}, "https://workspace.example/api/oauth/callback")
	if err != nil {
		t.Fatalf("RegisterDiscoveredClient: %v", err)
	}
	if client.ClientID != "legacy-public-client" || client.ClientSecret != "" {
		t.Fatalf("client = %+v, want legacy public registration", client)
	}
	if got := requestBody["token_endpoint_auth_method"]; got != "none" {
		t.Errorf("registration token_endpoint_auth_method = %#v, want none", got)
	}
	if _, ok := requestBody["scope"]; ok {
		t.Errorf("legacy public registration unexpectedly sent scope: %#v", requestBody["scope"])
	}
	if got := client.Raw()["token_endpoint_auth_method"]; got != "none" {
		t.Errorf("normalized client auth method = %#v, want none", got)
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
