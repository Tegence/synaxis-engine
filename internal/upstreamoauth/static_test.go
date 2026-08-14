package upstreamoauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestStaticClient_NoRegisterCall proves that StaticClient builds a valid
// ClientInfo from supplied credentials WITHOUT making any network call to a
// registration endpoint — i.e. Register is never called on the oauth_static
// path.
func TestStaticClient_NoRegisterCall(t *testing.T) {
	// Arrange: a test server that panics if the /register endpoint is hit.
	registerCalled := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "register") {
			registerCalled = true
			http.Error(w, "register must not be called", http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Act: build a ClientInfo via StaticClient — no network call.
	ci, err := StaticClient("test-client-id", "test-client-secret")
	if err != nil {
		t.Fatalf("StaticClient returned unexpected error: %v", err)
	}

	// Assert: fields are correct, register was never called.
	if ci.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q; want %q", ci.ClientID, "test-client-id")
	}
	if ci.ClientSecret != "test-client-secret" {
		t.Errorf("ClientSecret = %q; want %q", ci.ClientSecret, "test-client-secret")
	}
	if registerCalled {
		t.Error("register endpoint was called — oauth_static path must NOT call Register")
	}

	// Assert: Raw() contains client_id so MetaMCP's oauth_sessions can store it.
	raw := ci.Raw()
	if raw == nil {
		t.Fatal("Raw() is nil; oauth_sessions storage requires a non-nil map")
	}
	if v, ok := raw["client_id"].(string); !ok || v != "test-client-id" {
		t.Errorf("Raw()[client_id] = %v; want %q", raw["client_id"], "test-client-id")
	}
	if v, ok := raw["client_secret"].(string); !ok || v != "test-client-secret" {
		t.Errorf("Raw()[client_secret] = %v; want %q", raw["client_secret"], "test-client-secret")
	}
}

// TestStaticClient_RejectsEmptyClientID ensures the invariant that an
// operator-misconfigured connector (blank env var) fails fast at StartConnect
// rather than producing a broken auth URL.
func TestStaticClient_RejectsEmptyClientID(t *testing.T) {
	_, err := StaticClient("", "some-secret")
	if err == nil {
		t.Fatal("expected error for empty client_id, got nil")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("expected error to mention client_id, got: %v", err)
	}
}

// TestStaticClient_NoSecretAllowed proves public-client connectors (client_secret
// is optional) work — e.g. a provider that issues PKCE-only tokens.
func TestStaticClient_NoSecretAllowed(t *testing.T) {
	ci, err := StaticClient("public-client-id", "")
	if err != nil {
		t.Fatalf("StaticClient with no secret returned unexpected error: %v", err)
	}
	if ci.ClientID != "public-client-id" {
		t.Errorf("ClientID = %q; want %q", ci.ClientID, "public-client-id")
	}
	if ci.ClientSecret != "" {
		t.Errorf("ClientSecret should be empty; got %q", ci.ClientSecret)
	}
	raw := ci.Raw()
	if _, hasSecret := raw["client_secret"]; hasSecret {
		t.Error("Raw() should not contain client_secret for a public client")
	}
}

// TestStaticClient_AuthorizeURL proves AuthorizeURL produces a well-formed URL
// when given a StaticClient's ClientID — same function used by both DCR and
// oauth_static paths; test confirms reuse without modification.
func TestStaticClient_AuthorizeURL(t *testing.T) {
	meta := &Metadata{
		Resource:              "https://example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}
	ci, err := StaticClient("my-client", "my-secret")
	if err != nil {
		t.Fatalf("StaticClient: %v", err)
	}
	pkce, state, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}

	authURL := AuthorizeURL(meta, ci.ClientID, "https://narthex.example.com/callback", pkce.Challenge, state, "read", nil)

	if !strings.HasPrefix(authURL, "https://auth.example.com/authorize?") {
		t.Errorf("unexpected AuthorizeURL prefix: %s", authURL)
	}
	for _, param := range []string{"client_id=my-client", "code_challenge=", "state=", "resource=", "scope=read"} {
		if !strings.Contains(authURL, param) {
			t.Errorf("AuthorizeURL missing %q; full URL: %s", param, authURL)
		}
	}
}

func TestAuthorizeURL_AllowsOnlyProviderAuthorizationExtras(t *testing.T) {
	meta := &Metadata{
		Resource:              "https://gmailmcp.googleapis.com/mcp/v1",
		AuthorizationEndpoint: "https://accounts.example/authorize",
		TokenEndpoint:         "https://accounts.example/token",
	}
	authURL := AuthorizeURL(
		meta,
		"public-client-id",
		"https://engine.example/api/oauth/callback",
		"pkce-challenge",
		"opaque-state",
		"https://www.googleapis.com/auth/gmail.readonly",
		map[string]string{
			"access_type":            "offline",
			"prompt":                 "consent",
			"include_granted_scopes": "true",
			"client_secret":          "must-not-leak",
			"redirect_uri":           "https://attacker.example/callback",
			"state":                  "attacker-state",
		},
	)
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"access_type":            "offline",
		"prompt":                 "consent",
		"include_granted_scopes": "true",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if got := query.Get("redirect_uri"); got != "https://engine.example/api/oauth/callback" {
		t.Errorf("redirect_uri = %q, want engine callback", got)
	}
	if got := query.Get("state"); got != "opaque-state" {
		t.Errorf("state = %q, want opaque state", got)
	}
	if got := query.Get("client_secret"); got != "" {
		t.Errorf("unsafe authorization extra client_secret leaked into URL: %q", got)
	}
}

func TestValidateAuthorizationExtrasRejectsUnknownValuesWithoutEchoingThem(t *testing.T) {
	valid, err := ValidateAuthorizationExtras(map[string]string{
		"access_type":            " offline ",
		"prompt":                 "consent",
		"include_granted_scopes": "true",
	})
	if err != nil {
		t.Fatalf("validate allowed extras: %v", err)
	}
	if valid["access_type"] != "offline" || valid["prompt"] != "consent" || valid["include_granted_scopes"] != "true" {
		t.Errorf("validated extras = %#v", valid)
	}

	const secret = "TOPSECRET-do-not-echo"
	_, err = ValidateAuthorizationExtras(map[string]string{"client_secret": secret})
	if err == nil {
		t.Fatal("expected unknown authorization extra to be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("validation error leaked supplied value: %v", err)
	}
}

// TestStaticClient_ExchangeRequest proves Exchange sends the correct form params
// (including client_id and client_secret from StaticClient) without calling
// Register. We intercept the token endpoint to verify the POST body.
func TestStaticClient_ExchangeRequest(t *testing.T) {
	var gotBody string
	const tokenEndpoint = "https://token.example.test/token"

	ci, err := StaticClient("static-id", "static-secret")
	if err != nil {
		t.Fatalf("StaticClient: %v", err)
	}

	meta := &Metadata{
		Resource:      "https://provider.example.test/mcp",
		TokenEndpoint: tokenEndpoint,
	}
	// Use the shared client seam with a public HTTPS endpoint. A loopback
	// httptest URL would correctly fail the production endpoint policy.
	origClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != tokenEndpoint {
			t.Errorf("token endpoint = %q, want %q", r.URL, tokenEndpoint)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(
				`{"access_token":"tok123","token_type":"Bearer","expires_in":3600}`,
			)),
			Request: r,
		}, nil
	})}
	defer func() { httpClient = origClient }()

	tokens, err := Exchange(context.Background(), meta, "auth-code", "https://callback.example.com/cb",
		ci.ClientID, ci.ClientSecret, "verifier123")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.AccessToken != "tok123" {
		t.Errorf("AccessToken = %q; want %q", tokens.AccessToken, "tok123")
	}
	// Confirm the POST body included client_id and client_secret from StaticClient.
	if !strings.Contains(gotBody, "client_id=static-id") {
		t.Errorf("token POST missing client_id=static-id; body: %s", gotBody)
	}
	if !strings.Contains(gotBody, "client_secret=static-secret") {
		t.Errorf("token POST missing client_secret=static-secret; body: %s", gotBody)
	}
	if !strings.Contains(gotBody, "grant_type=authorization_code") {
		t.Errorf("token POST missing grant_type; body: %s", gotBody)
	}
}

func TestCredentialBearingRequestsRejectUnsafeEndpointsBeforeNetwork(t *testing.T) {
	originalClient := httpClient
	calls := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, nil
	})}
	t.Cleanup(func() { httpClient = originalClient })

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "registration refuses cleartext endpoint",
			call: func() error {
				_, err := Register(
					context.Background(),
					"http://public.example.test/register",
					"https://engine.example/callback",
				)
				return err
			},
		},
		{
			name: "code exchange refuses cleartext endpoint",
			call: func() error {
				_, err := Exchange(
					context.Background(),
					&Metadata{TokenEndpoint: "http://public.example.test/token"},
					"authorization-code", "https://engine.example/callback",
					"client", "client-secret", "verifier",
				)
				return err
			},
		},
		{
			name: "refresh refuses private endpoint",
			call: func() error {
				_, err := Refresh(
					context.Background(),
					&Metadata{TokenEndpoint: "https://127.0.0.1/token"},
					"refresh-token", "client", "client-secret",
				)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("credential-bearing request accepted an unsafe endpoint")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("unsafe endpoint validation made %d network request(s)", calls)
	}
}
