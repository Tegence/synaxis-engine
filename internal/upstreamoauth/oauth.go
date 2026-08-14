// Package upstreamoauth implements the OAuth 2.1 + PKCE + RFC 9728/8414 flow a
// gateway runs as a *client* against an upstream MCP server (Notion, Linear,
// ...). Synaxis Engine drives this itself so the consent UX stays local; the
// resulting client registration + tokens are then handed to MetaMCP (which uses
// them to talk to the upstream).
package upstreamoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = NewHardenedHTTPClient(20 * time.Second)

// validateUpstreamURL validates an operator-configured upstream before it is
// persisted or probed. Do not allow URL userinfo here: besides being an
// accidental credential storage path, net/http would turn it into a Basic
// Authorization header on the discovery request.
func validateUpstreamURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("upstream url must be https")
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("upstream url must have a host")
	}
	if u.User != nil {
		return fmt.Errorf("upstream url must not include user credentials")
	}
	if u.Fragment != "" {
		return fmt.Errorf("upstream url must not include a fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isUnsafeOutboundIP(ip) {
		return fmt.Errorf("%w: %s", ErrUnsafeOutboundAddress, ip)
	}
	return nil
}

// ValidateUpstreamURL is the exported variant for use by the API layer.
func ValidateUpstreamURL(raw string) error {
	return validateUpstreamURL(raw)
}

// validateOAuthEndpoint is stricter than the configured upstream-resource
// check because these metadata values become credential-bearing destinations.
// In particular, a malicious or compromised authorization-server metadata
// document must not redirect a browser or send a client secret, authorization
// code, or refresh token to cleartext HTTP or a private network address.
//
// This intentionally permits public IP literals: the hardened transport uses
// the same public-address policy and TLS still authenticates the destination.
// There is no loopback development exception in this Engine path; production
// upstream OAuth endpoints are HTTPS-only and local tests use explicit client
// seams rather than weakening the runtime policy.
func validateOAuthEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("endpoint URL must be https")
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("endpoint URL must be absolute with a host")
	}
	if u.User != nil {
		return fmt.Errorf("endpoint URL must not include user credentials")
	}
	if u.Fragment != "" {
		return fmt.Errorf("endpoint URL must not include a fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isUnsafeOutboundIP(ip) {
		return fmt.Errorf("%w: %s", ErrUnsafeOutboundAddress, ip)
	}
	return nil
}

// Metadata is the subset of upstream OAuth discovery we need.
type Metadata struct {
	Resource              string // RFC 8707 resource indicator (the PRM "resource")
	AuthorizationEndpoint string
	TokenEndpoint         string
	RegistrationEndpoint  string
}

// Tokens mirrors MetaMCP's OAuthTokensSchema.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// authorizationExtraKeys is deliberately small. These are OAuth authorization
// request knobs used by known static-client providers; callers must never be
// able to override the redirect URI, PKCE state, resource, or client identity.
var authorizationExtraKeys = []string{
	"access_type",
	"prompt",
	"include_granted_scopes",
}

var allowedAuthorizationExtraKeys = map[string]struct{}{
	"access_type":            {},
	"prompt":                 {},
	"include_granted_scopes": {},
}

// ValidateAuthorizationExtras accepts only safe, provider-specific
// authorization parameters. Values are bounded and normalized before being
// copied so they can safely become URL query values. It intentionally reports
// only the key, never a supplied value.
func ValidateAuthorizationExtras(extras map[string]string) (map[string]string, error) {
	if len(extras) == 0 {
		return nil, nil
	}
	validated := make(map[string]string, len(extras))
	for key, value := range extras {
		if _, ok := allowedAuthorizationExtraKeys[key]; !ok {
			return nil, fmt.Errorf("unsupported authorization extra %q", key)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("authorization extra %q must not be empty", key)
		}
		if len(value) > 256 {
			return nil, fmt.Errorf("authorization extra %q is too long", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("authorization extra %q contains an invalid character", key)
		}
		validated[key] = value
	}
	return validated, nil
}

// Discover follows RFC 9728 (protected-resource metadata) then RFC 8414
// (authorization-server metadata) for the given MCP server URL.
func Discover(ctx context.Context, serverURL string) (*Metadata, error) {
	if err := validateUpstreamURL(serverURL); err != nil {
		return nil, fmt.Errorf("upstream url rejected: %w", err)
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server url: %w", err)
	}
	origin := u.Scheme + "://" + u.Host

	// RFC 9728: the protected-resource-metadata location is advertised in the
	// 401 WWW-Authenticate header (resource_metadata=...). When the challenge
	// is not available, a resource with a path uses the path-scoped well-known
	// location before the origin default. For example, Gmail's
	// /mcp/v1 resource publishes metadata at
	// /.well-known/oauth-protected-resource/mcp/v1.
	prmURL := probeResourceMetadata(ctx, serverURL)
	prmURLs := []string{prmURL}
	if prmURL == "" {
		prmURLs = protectedResourceMetadataURLs(origin, u)
	}

	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	var prmErr error
	foundPRM := false
	for _, candidate := range prmURLs {
		if err := getJSON(ctx, candidate, &prm); err != nil {
			prmErr = err
			continue
		}
		foundPRM = true
		break
	}
	if !foundPRM {
		return nil, fmt.Errorf("protected-resource metadata: %w", prmErr)
	}
	as := origin
	if len(prm.AuthorizationServers) > 0 {
		as = strings.TrimRight(prm.AuthorizationServers[0], "/")
		if err := validateUpstreamURL(as); err != nil {
			return nil, fmt.Errorf("discovered authorization_servers[0] rejected: %w", err)
		}
	}
	resource := prm.Resource
	if resource == "" {
		resource = origin
	}

	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
	}
	// Try the AS metadata at the advertised authorization server.
	if err := getJSON(ctx, as+"/.well-known/oauth-authorization-server", &asm); err != nil {
		return nil, fmt.Errorf("authorization-server metadata: %w", err)
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return nil, fmt.Errorf("authorization server missing authorize/token endpoints")
	}
	for _, endpoint := range []struct {
		field string
		url   string
	}{
		{field: "authorization_endpoint", url: asm.AuthorizationEndpoint},
		{field: "token_endpoint", url: asm.TokenEndpoint},
		{field: "registration_endpoint", url: asm.RegistrationEndpoint},
	} {
		if endpoint.url == "" && endpoint.field == "registration_endpoint" {
			continue
		}
		if err := validateOAuthEndpoint(endpoint.url); err != nil {
			return nil, fmt.Errorf("discovered %s rejected: %w", endpoint.field, err)
		}
	}
	return &Metadata{
		Resource:              resource,
		AuthorizationEndpoint: asm.AuthorizationEndpoint,
		TokenEndpoint:         asm.TokenEndpoint,
		RegistrationEndpoint:  asm.RegistrationEndpoint,
	}, nil
}

// protectedResourceMetadataURLs returns the RFC 9728 well-known locations to
// try when an upstream did not advertise one in a WWW-Authenticate challenge.
// A resource path belongs after /.well-known/oauth-protected-resource rather
// than after the host root. The unscoped origin location remains a fallback for
// providers that publish metadata for every resource there.
func protectedResourceMetadataURLs(origin string, resourceURL *url.URL) []string {
	path := resourceURL.EscapedPath()
	if path == "" || path == "/" {
		return []string{origin + "/.well-known/oauth-protected-resource"}
	}
	return []string{
		origin + "/.well-known/oauth-protected-resource" + path,
		origin + "/.well-known/oauth-protected-resource",
	}
}

// ClientInfo is the dynamic-client-registration result.
type ClientInfo struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	raw          map[string]any
}

// Raw returns the full DCR response (stored as MetaMCP client_information).
func (c ClientInfo) Raw() map[string]any { return c.raw }

// Register performs RFC 7591 dynamic client registration with our redirect URI.
func Register(ctx context.Context, regEndpoint, redirectURI string) (*ClientInfo, error) {
	if regEndpoint == "" {
		return nil, fmt.Errorf("upstream does not support dynamic client registration")
	}
	if err := validateOAuthEndpoint(regEndpoint); err != nil {
		return nil, fmt.Errorf("registration endpoint rejected: %w", err)
	}
	body := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                "Synaxis Engine",
		"client_uri":                 "https://github.com/narthex",
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regEndpoint, strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("register -> %d: %s", resp.StatusCode, snippet(data))
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("register decode: %w", err)
	}
	ci := &ClientInfo{raw: m}
	if v, ok := m["client_id"].(string); ok {
		ci.ClientID = v
	}
	if v, ok := m["client_secret"].(string); ok {
		ci.ClientSecret = v
	}
	if ci.ClientID == "" {
		return nil, fmt.Errorf("register: no client_id returned")
	}
	return ci, nil
}

// StaticClient builds a ClientInfo from a pre-registered client_id and
// client_secret, bypassing dynamic client registration (RFC 7591). Use this
// for providers that require an operator-registered OAuth app (Google,
// Microsoft, Slack, Atlassian) rather than DCR (Notion, Linear).
//
// The returned ClientInfo.Raw() is populated so it can be stored in MetaMCP's
// oauth_sessions.client_information column in the same format DCR uses.
func StaticClient(clientID, clientSecret string) (*ClientInfo, error) {
	if clientID == "" {
		return nil, fmt.Errorf("oauth_static: client_id is required")
	}
	raw := map[string]any{
		"client_id":                  clientID,
		"token_endpoint_auth_method": "client_secret_basic",
	}
	if clientSecret != "" {
		raw["client_secret"] = clientSecret
	}
	return &ClientInfo{ClientID: clientID, ClientSecret: clientSecret, raw: raw}, nil
}

// PKCE holds a verifier/challenge pair.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates an S256 PKCE pair and a random state.
func NewPKCE() (PKCE, string, error) {
	verifier, err := randB64(32)
	if err != nil {
		return PKCE{}, "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randB64(24)
	if err != nil {
		return PKCE{}, "", err
	}
	return PKCE{Verifier: verifier, Challenge: challenge}, state, nil
}

// AuthorizeURL builds the authorization redirect (RFC 8707 resource included).
// authorizationExtras may add only the fixed provider-safe allowlist above;
// arbitrary map entries are ignored as a defense in depth against a caller
// accidentally forwarding a secret or redirect override into a browser URL.
func AuthorizeURL(m *Metadata, clientID, redirectURI, challenge, state, scope string, authorizationExtras map[string]string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("resource", m.Resource)
	if scope != "" {
		q.Set("scope", scope)
	}
	for _, key := range authorizationExtraKeys {
		if value := strings.TrimSpace(authorizationExtras[key]); value != "" {
			q.Set(key, value)
		}
	}
	sep := "?"
	if strings.Contains(m.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return m.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange swaps an authorization code for tokens (PKCE + resource).
func Exchange(ctx context.Context, m *Metadata, code, redirectURI, clientID, clientSecret, verifier string) (*Tokens, error) {
	if m == nil {
		return nil, fmt.Errorf("OAuth metadata is required")
	}
	if err := validateOAuthEndpoint(m.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("token endpoint rejected: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	form.Set("resource", m.Resource)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("token -> %d: %s", resp.StatusCode, snippet(data))
	}
	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("token decode: %w", err)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("token: no access_token returned")
	}
	if t.TokenType == "" {
		t.TokenType = "Bearer"
	}
	return &t, nil
}

// Refresh exchanges a refresh token for a fresh access token. Providers may
// rotate the refresh token, so callers must persist the returned RefreshToken.
func Refresh(ctx context.Context, m *Metadata, refreshToken, clientID, clientSecret string) (*Tokens, error) {
	if m == nil {
		return nil, fmt.Errorf("OAuth metadata is required")
	}
	if err := validateOAuthEndpoint(m.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("token endpoint rejected: %w", err)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("resource", m.Resource)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("refresh -> %d: %s", resp.StatusCode, snippet(data))
	}
	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("refresh decode: %w", err)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("refresh: no access_token returned")
	}
	if t.TokenType == "" {
		t.TokenType = "Bearer"
	}
	// Keep the existing refresh token if the provider didn't rotate it.
	if t.RefreshToken == "" {
		t.RefreshToken = refreshToken
	}
	return &t, nil
}

// probeResourceMetadata makes an unauthenticated request and extracts the
// resource_metadata URL from the 401 WWW-Authenticate header (RFC 9728).
func probeResourceMetadata(ctx context.Context, serverURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	h := resp.Header.Get("WWW-Authenticate")
	const key = "resource_metadata="
	i := strings.Index(h, key)
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(h[i+len(key):])
	if c := strings.IndexByte(v, ','); c >= 0 {
		v = v[:c]
	}
	return strings.Trim(strings.TrimSpace(v), `"`)
}

func getJSON(ctx context.Context, u string, out any) error {
	// Both RFC 9728 resource metadata and RFC 8414 authorization-server
	// metadata can be supplied by an upstream response. Apply the same policy
	// used for OAuth endpoints before issuing either discovery request so a
	// challenge cannot induce an initial cleartext or local-network fetch.
	if err := validateOAuthEndpoint(u); err != nil {
		return fmt.Errorf("metadata URL rejected: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("create metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s -> %d", u, resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
