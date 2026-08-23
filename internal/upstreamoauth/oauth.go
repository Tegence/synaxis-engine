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
	Resource                          string // RFC 8707 resource indicator (the PRM "resource")
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	RegistrationEndpoint              string
	Scope                             string
	TokenEndpointAuthMethodsSupported []string
}

// DynamicRegistrationAuthMethod selects a token endpoint authentication mode
// the Engine can use for both registration and later token exchange. Existing
// DCR providers that omit the metadata retain the public-client behavior. A
// confidential registration uses client_secret_post because Exchange and
// Refresh deliberately send the returned secret in the form body.
func (m *Metadata) DynamicRegistrationAuthMethod() (string, error) {
	if m == nil {
		return "", fmt.Errorf("OAuth metadata is required")
	}
	if len(m.TokenEndpointAuthMethodsSupported) == 0 {
		return "none", nil
	}
	for _, method := range m.TokenEndpointAuthMethodsSupported {
		if strings.TrimSpace(method) == "none" {
			return "none", nil
		}
	}
	for _, method := range m.TokenEndpointAuthMethodsSupported {
		if strings.TrimSpace(method) == "client_secret_post" {
			return "client_secret_post", nil
		}
	}
	return "", fmt.Errorf("authorization server does not advertise a supported dynamic-client token authentication method")
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
	probe := probeResourceMetadata(ctx, serverURL)
	prmURLs := []string{probe.URL}
	if probe.URL == "" {
		prmURLs = protectedResourceMetadataURLs(origin, u)
	}

	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
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
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		RegistrationEndpoint              string   `json:"registration_endpoint"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
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
	scope := strings.TrimSpace(probe.Scope)
	if scope == "" {
		scope = supportedScopeSet(prm.ScopesSupported)
	}
	if len(scope) > 4096 || strings.ContainsAny(scope, "\r\n") {
		return nil, fmt.Errorf("discovered OAuth scope is invalid")
	}
	return &Metadata{
		Resource:                          resource,
		AuthorizationEndpoint:             asm.AuthorizationEndpoint,
		TokenEndpoint:                     asm.TokenEndpoint,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
		Scope:                             scope,
		TokenEndpointAuthMethodsSupported: append([]string(nil), asm.TokenEndpointAuthMethodsSupported...),
	}, nil
}

func supportedScopeSet(scopes []string) string {
	seen := make(map[string]struct{}, len(scopes))
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	return strings.Join(normalized, " ")
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
	return register(ctx, regEndpoint, redirectURI, "none", "")
}

// RegisterDiscoveredClient performs DCR using the authentication method
// negotiated from authorization-server metadata. This is required by
// providers such as Figma that issue a per-registration client secret and do
// not advertise public-client token authentication.
func RegisterDiscoveredClient(ctx context.Context, metadata *Metadata, redirectURI string) (*ClientInfo, error) {
	if metadata == nil {
		return nil, fmt.Errorf("OAuth metadata is required")
	}
	method, err := metadata.DynamicRegistrationAuthMethod()
	if err != nil {
		return nil, err
	}
	return register(ctx, metadata.RegistrationEndpoint, redirectURI, method, metadata.Scope)
}

func register(ctx context.Context, regEndpoint, redirectURI, tokenEndpointAuthMethod, scope string) (*ClientInfo, error) {
	if regEndpoint == "" {
		return nil, fmt.Errorf("upstream does not support dynamic client registration")
	}
	if err := validateOAuthEndpoint(regEndpoint); err != nil {
		return nil, fmt.Errorf("registration endpoint rejected: %w", err)
	}
	body := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": tokenEndpointAuthMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                "Synaxis Engine",
		"client_uri":                 "https://synaxis.tools",
	}
	if scope = strings.TrimSpace(scope); scope != "" {
		body["scope"] = scope
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
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("register -> %d: provider denied dynamic client registration; this client may require provider approval: %s", resp.StatusCode, snippet(data))
		}
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
	if tokenEndpointAuthMethod != "none" && ci.ClientSecret == "" {
		return nil, fmt.Errorf("register: no client_secret returned for %s", tokenEndpointAuthMethod)
	}
	if registeredMethod, ok := m["token_endpoint_auth_method"].(string); ok &&
		registeredMethod != "" && registeredMethod != tokenEndpointAuthMethod {
		return nil, fmt.Errorf("register: provider returned unsupported token authentication method %q", registeredMethod)
	}
	if _, ok := m["token_endpoint_auth_method"]; !ok {
		m["token_endpoint_auth_method"] = tokenEndpointAuthMethod
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
type resourceMetadataProbe struct {
	URL   string
	Scope string
}

func probeResourceMetadata(ctx context.Context, serverURL string) resourceMetadataProbe {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		return resourceMetadataProbe{}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := httpClient.Do(req)
	if err != nil {
		return resourceMetadataProbe{}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	h := resp.Header.Get("WWW-Authenticate")
	return resourceMetadataProbe{
		URL:   bearerChallengeParameter(h, "resource_metadata"),
		Scope: bearerChallengeParameter(h, "scope"),
	}
}

func bearerChallengeParameter(header, name string) string {
	lower := strings.ToLower(header)
	bearer := strings.Index(lower, "bearer ")
	if bearer < 0 {
		return ""
	}
	rest := header[bearer+len("bearer "):]
	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " \t,")
		equals := strings.IndexByte(rest, '=')
		if equals <= 0 {
			return ""
		}
		key := strings.TrimSpace(rest[:equals])
		rest = strings.TrimLeft(rest[equals+1:], " \t")
		var value string
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				return ""
			}
			value = rest[:end]
			rest = rest[end+1:]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				value, rest = strings.TrimSpace(rest), ""
			} else {
				value, rest = strings.TrimSpace(rest[:end]), rest[end+1:]
			}
		}
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
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
