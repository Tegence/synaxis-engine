package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

const controlCapabilityAccountOAuth = "account-linking-oauth"

var errLinkedOAuth = errors.New("account sign-in could not be completed")

// Provider adapters own protocol differences. Runtime configuration supplies
// application credentials only, never user-controlled endpoints or scopes.
type linkedOAuthProvider struct {
	id, label, authorizeURL, tokenURL, identityURL string
	scopes                                         []string
	exchange                                       func(context.Context, *LinkedAccountOAuth, linkedOAuthApp, string, string) (LinkedOAuthCredential, error)
}
type linkedOAuthApp struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}
type LinkedAccountOAuth struct {
	apps      map[string]linkedOAuthApp
	providers map[string]linkedOAuthProvider
	origin    string
	client    *http.Client
}
type LinkedOAuthProviderDTO struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Available bool     `json:"available"`
	Scopes    []string `json:"scopes"`
}
type LinkedOAuthCredential struct {
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	Subject      string    `json:"subject"`
	ProviderName string    `json:"provider_name"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes"`
}

// NewLinkedAccountOAuth does not contact providers. The callback is fixed to
// the configured Web origin; neither the browser nor a stored connection URL
// can choose an exchange endpoint or redirect destination.
func NewLinkedAccountOAuth(raw, consoleURL string) (*LinkedAccountOAuth, error) {
	u, err := url.Parse(consoleURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		if strings.TrimSpace(raw) != "" {
			return nil, errLinkedOAuth
		}
		u = &url.URL{}
	}
	service := &LinkedAccountOAuth{apps: map[string]linkedOAuthApp{}, origin: u.Scheme + "://" + u.Host, client: upstreamoauth.NewHardenedHTTPClient(20 * time.Second)}
	service.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	service.providers = map[string]linkedOAuthProvider{
		"instagram": {id: "instagram", label: "Instagram", authorizeURL: "https://www.instagram.com/oauth/authorize", tokenURL: "https://api.instagram.com/oauth/access_token", identityURL: "https://graph.instagram.com/me?fields=user_id,username", scopes: []string{"instagram_business_basic"}, exchange: exchangeInstagramAccount},
		"linkedin":  {id: "linkedin", label: "LinkedIn", authorizeURL: "https://www.linkedin.com/oauth/v2/authorization", tokenURL: "https://www.linkedin.com/oauth/v2/accessToken", identityURL: "https://api.linkedin.com/v2/userinfo", scopes: []string{"openid", "profile"}, exchange: exchangeLinkedInAccount},
	}
	if strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if len(raw) > 64<<10 || decoder.Decode(&service.apps) != nil || service.apps == nil || decoder.Decode(&struct{}{}) != io.EOF {
			return nil, errLinkedOAuth
		}
		for id, app := range service.apps {
			if _, ok := service.providers[id]; !ok || strings.TrimSpace(app.ClientID) == "" || strings.TrimSpace(app.ClientSecret) == "" || len(app.ClientID) > 1024 || len(app.ClientSecret) > 4096 {
				return nil, errLinkedOAuth
			}
		}
	}
	return service, nil
}
func WithLinkedAccountOAuth(service *LinkedAccountOAuth) ConsoleOption {
	return func(c *ConsoleAPI) { c.accountOAuth = service }
}
func (s *LinkedAccountOAuth) metadata() []LinkedOAuthProviderDTO {
	out := []LinkedOAuthProviderDTO{}
	if s == nil {
		return out
	}
	ids := make([]string, 0, len(s.providers))
	for id := range s.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := s.providers[id]
		_, available := s.apps[id]
		out = append(out, LinkedOAuthProviderDTO{ID: id, Label: p.label, Available: available, Scopes: p.scopes})
	}
	return out
}
func (s *LinkedAccountOAuth) redirectURI(provider string) string {
	return s.origin + "/oauth/accounts/" + provider
}
func (s *LinkedAccountOAuth) fingerprint(provider string) string {
	raw, _ := json.Marshal(struct {
		App      linkedOAuthApp
		Redirect string
		Provider string
		Scopes   []string
	}{s.apps[provider], s.redirectURI(provider), provider, s.providers[provider].scopes})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func (s *LinkedAccountOAuth) authorizationURL(provider, state string) string {
	p := s.providers[provider]
	u, _ := url.Parse(p.authorizeURL)
	q := u.Query()
	q.Set("client_id", s.apps[provider].ClientID)
	q.Set("redirect_uri", s.redirectURI(provider))
	q.Set("response_type", "code")
	q.Set("state", state)
	delimiter := " "
	if provider == "instagram" {
		delimiter = ","
		q.Set("force_reauth", "true")
	}
	q.Set("scope", strings.Join(p.scopes, delimiter))
	u.RawQuery = q.Encode()
	return u.String()
}

// Never propagate upstream bodies, request URLs (which can carry tokens), or
// transport errors into HTTP errors or logs. Bound all provider responses.
func (s *LinkedAccountOAuth) request(ctx context.Context, method, endpoint, bearer string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errLinkedOAuth
	}
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return errLinkedOAuth
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errLinkedOAuth
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (128<<10)+1))
	if err != nil || len(data) > 128<<10 || json.Unmarshal(data, out) != nil {
		return errLinkedOAuth
	}
	return nil
}
func codeForm(app linkedOAuthApp, code, redirect string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {app.ClientID}, "client_secret": {app.ClientSecret}, "code": {code}, "redirect_uri": {redirect}}
}
func validOAuthCredential(c LinkedOAuthCredential) bool {
	return (validActorIdentifier(c.Provider) && c.ClientID != "") && c.Subject != "" && len(c.Subject) <= 256 && validLinkedAccountToken(c.AccessToken, false) && validLinkedAccountToken(c.RefreshToken, true) && c.ExpiresAt.After(time.Now())
}
func exchangeLinkedInAccount(ctx context.Context, s *LinkedAccountOAuth, app linkedOAuthApp, code, redirect string) (LinkedOAuthCredential, error) {
	p := s.providers["linkedin"]
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	if s.request(ctx, "POST", p.tokenURL, "", codeForm(app, code, redirect), &token) != nil || token.ExpiresIn <= 0 || token.ExpiresIn > 366*86400 || (token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer")) || !validLinkedAccountToken(token.AccessToken, false) {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	var profile struct {
		Subject string `json:"sub"`
		Name    string `json:"name"`
	}
	if s.request(ctx, "GET", p.identityURL, token.AccessToken, nil, &profile) != nil {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	scopes := strings.Fields(token.Scope)

	credential := LinkedOAuthCredential{Provider: p.id, ClientID: app.ClientID, Subject: profile.Subject, ProviderName: profile.Name, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second), Scopes: scopes}
	if !validOAuthCredential(credential) {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	return credential, nil
}

// Meta has served both a single data entry and a flat token object. Ambiguous
// responses are refused rather than selecting a potentially different account.
func exchangeInstagramAccount(ctx context.Context, s *LinkedAccountOAuth, app linkedOAuthApp, code, redirect string) (LinkedOAuthCredential, error) {
	p := s.providers["instagram"]
	type instagramToken struct {
		AccessToken string          `json:"access_token"`
		UserID      json.RawMessage `json:"user_id"`
		Permissions string          `json:"permissions"`
	}
	var response struct {
		instagramToken
		Data []instagramToken `json:"data"`
	}
	if s.request(ctx, "POST", p.tokenURL, "", codeForm(app, code, redirect), &response) != nil {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	token := response.instagramToken
	if len(response.Data) > 0 {
		if len(response.Data) != 1 || token.AccessToken != "" {
			return LinkedOAuthCredential{}, errLinkedOAuth
		}
		token = response.Data[0]
	}
	if !validLinkedAccountToken(token.AccessToken, false) {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	var long struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	endpoint := "https://graph.instagram.com/access_token?" + url.Values{"grant_type": {"ig_exchange_token"}, "client_secret": {app.ClientSecret}, "access_token": {token.AccessToken}}.Encode()
	if s.request(ctx, "GET", endpoint, "", nil, &long) != nil || !validLinkedAccountToken(long.AccessToken, false) || long.ExpiresIn <= 0 || long.ExpiresIn > 366*86400 {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	var profile struct {
		UserID   json.RawMessage `json:"user_id"`
		Username string          `json:"username"`
	}
	if s.request(ctx, "GET", p.identityURL, long.AccessToken, nil, &profile) != nil {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	subject := instagramID(profile.UserID)
	if subject == "" {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	scopes := strings.FieldsFunc(token.Permissions, func(r rune) bool { return r == ',' || r == ' ' })

	credential := LinkedOAuthCredential{Provider: p.id, ClientID: app.ClientID, Subject: subject, ProviderName: profile.Username, AccessToken: long.AccessToken, ExpiresAt: time.Now().UTC().Add(time.Duration(long.ExpiresIn) * time.Second), Scopes: scopes}
	if !validOAuthCredential(credential) {
		return LinkedOAuthCredential{}, errLinkedOAuth
	}
	return credential, nil
}
func instagramID(raw json.RawMessage) string {
	value := string(raw)
	if len(value) > 1 && value[0] == '"' {
		if json.Unmarshal(raw, &value) != nil {
			return ""
		}
	}
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return value
}
