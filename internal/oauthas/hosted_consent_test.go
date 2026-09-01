package oauthas

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type hostedConsentHarness struct {
	server     *Server
	mux        *http.ServeMux
	privateKey ed25519.PrivateKey
	now        time.Time
	epochs     map[string]string
	clientID   string
	redirect   string
	verifier   string
	challenge  string
}

func newHostedConsentHarness(t *testing.T) *hostedConsentHarness {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	server := New("https://engine.example", "unused-hosted-password", "engine-secret-that-never-leaves")
	if err := server.ConfigureHostedConsent("https://app.example/oauth/consent?workspace=ws_1", publicKey); err != nil {
		t.Fatalf("configure hosted consent: %v", err)
	}
	epochs := map[string]string{"/mcp": "root", "/mcp/team": "team-1"}
	server.SetEpochLookup(func(path string) (string, bool) {
		epoch, ok := epochs[path]
		return epoch, ok
	})
	const clientID = "mcp_test_client"
	const redirect = "https://client.example/oauth/callback"
	server.clients[clientID] = client{redirectURIs: map[string]bool{redirect: true}}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	mux := http.NewServeMux()
	server.Routes(mux)
	harness := &hostedConsentHarness{
		server: server, mux: mux, privateKey: privateKey, now: now, epochs: epochs,
		clientID: clientID, redirect: redirect, verifier: verifier, challenge: challenge,
	}
	server.now = func() time.Time { return harness.now }
	return harness
}

func (h *hostedConsentHarness) authorize(t *testing.T, resource string) string {
	t.Helper()
	q := url.Values{
		"client_id":             {h.clientID},
		"redirect_uri":          {h.redirect},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {h.challenge},
		"scope":                 {"mcp"},
		"state":                 {"client-state"},
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d, body %s", rec.Code, rec.Body)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse consent redirect: %v", err)
	}
	if location.Scheme != "https" || location.Host != "app.example" || location.Path != "/oauth/consent" {
		t.Fatalf("authorize redirected to unexpected consent URL %q", location)
	}
	if location.Query().Get("workspace") != "ws_1" ||
		location.Query().Get("engine_issuer") != h.server.issuer ||
		location.Query().Get("completion_url") != h.server.issuer+"/authorize/complete" ||
		location.Query().Get("resource_path") != resourcePath(resource) {
		t.Fatalf("consent integration parameters missing: %s", location.RawQuery)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("authorize Cache-Control = %q, want no-store", got)
	}
	return location.Query().Get("request")
}

func approvalAssertion(t *testing.T, privateKey ed25519.PrivateKey, claims hostedApprovalClaims) string {
	t.Helper()
	headerJSON, err := json.Marshal(hostedAssertionHeader{Algorithm: "EdDSA", Type: hostedAssertionType})
	if err != nil {
		t.Fatalf("marshal assertion header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal assertion claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (h *hostedConsentHarness) claims(requestToken, jti string) hostedApprovalClaims {
	request, _, err := h.server.verifyHostedRequestToken(requestToken)
	if err != nil {
		h.panicInvalidRequestToken(err)
	}
	hash := sha256.Sum256([]byte(requestToken))
	return hostedApprovalClaims{
		Audience:      h.server.issuer,
		EngineIssuer:  h.server.issuer,
		ResourcePath:  request.resourcePath,
		RequestSHA256: base64.RawURLEncoding.EncodeToString(hash[:]),
		JTI:           jti,
		ExpiresAt:     h.now.Add(2 * time.Minute).Unix(),
		Approved:      true,
	}
}

func (h *hostedConsentHarness) panicInvalidRequestToken(err error) {
	panic("invalid hosted consent test request: " + err.Error())
}

func completeHostedConsent(mux *http.ServeMux, requestToken, assertion string, extra url.Values) *httptest.ResponseRecorder {
	form := url.Values{"request": {requestToken}, "assertion": {assertion}}
	for key, values := range extra {
		for _, value := range values {
			form.Add(key, value)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize/complete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHostedConsentHappyPathIssuesOAuthCode(t *testing.T) {
	h := newHostedConsentHarness(t)
	const resource = "https://engine.example/mcp/team"
	requestToken := h.authorize(t, resource)
	if requestToken == "" || strings.Contains(requestToken, "engine-secret") {
		t.Fatalf("opaque request token missing or leaked Engine secret: %q", requestToken)
	}
	assertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_0001"))
	rec := completeHostedConsent(h.mux, requestToken, assertion, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("complete = %d, body %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != h.redirect ||
		redirect.Query().Get("state") != "client-state" ||
		redirect.Query().Get("code") == "" {
		t.Fatalf("unexpected OAuth client redirect %q", redirect)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {redirect.Query().Get("code")},
		"client_id":     {h.clientID},
		"redirect_uri":  {h.redirect},
		"code_verifier": {h.verifier},
		"resource":      {resource},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("exchange hosted code = %d, body %s", tokenRec.Code, tokenRec.Body)
	}
	if tokenRec.Header().Get("Cache-Control") != "no-store" || tokenRec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token response cache headers=%#v", tokenRec.Header())
	}
	var tokenPayload map[string]any
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenPayload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, _ := tokenPayload["access_token"].(string)
	if !h.server.validAccess(accessToken, "/mcp/team") || h.server.validAccess(accessToken, "/mcp") {
		t.Fatal("hosted authorization code did not preserve resource binding")
	}
}

func TestHostedConsentBindsSignedSubjectBeforeIssuingClientEndpointCode(t *testing.T) {
	h := newHostedConsentHarness(t)
	const resource = "https://engine.example/mcp/clients/personal-work"
	h.epochs["/mcp/clients/personal-work"] = "client-epoch-1"
	type authorization struct {
		subject  string
		clientID string
		path     string
	}
	var got []authorization
	h.server.SetHostedSubjectAuthorizer(func(_ context.Context, subject, clientID, path string) error {
		if subject == "" {
			return errors.New("a client-bound resource requires a subject")
		}
		got = append(got, authorization{subject: subject, clientID: clientID, path: path})
		return nil
	})
	requestToken := h.authorize(t, resource)
	claims := h.claims(requestToken, "approval_jti_client_subject")
	claims.Subject = "usr_personal_owner"
	claims.Role = "operator"
	response := completeHostedConsent(
		h.mux,
		requestToken,
		approvalAssertion(t, h.privateKey, claims),
		nil,
	)
	if response.Code != http.StatusFound {
		t.Fatalf("client-bound completion=%d body=%s", response.Code, response.Body)
	}
	if len(got) != 1 || got[0] != (authorization{
		subject: "usr_personal_owner", clientID: h.clientID, path: "/mcp/clients/personal-work",
	}) {
		t.Fatalf("client authorizer calls=%#v", got)
	}

	requestToken = h.authorize(t, resource)
	claims = h.claims(requestToken, "approval_jti_client_without_subject")
	response = completeHostedConsent(
		h.mux,
		requestToken,
		approvalAssertion(t, h.privateKey, claims),
		nil,
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing-subject completion=%d body=%s", response.Code, response.Body)
	}
}

func TestClientBoundResourceRejectsStaleCodeRefreshAndAccessAfterRevocation(t *testing.T) {
	h := newHostedConsentHarness(t)
	const resource = "https://engine.example/mcp/clients/personal-work"
	const resourcePath = "/mcp/clients/personal-work"
	h.epochs[resourcePath] = "client-epoch-1"
	bound := true
	h.server.SetHostedSubjectAuthorizer(func(_ context.Context, subject, clientID, path string) error {
		if subject != "usr_personal_owner" || clientID != h.clientID || path != resourcePath {
			return errors.New("unexpected client binding")
		}
		return nil
	})
	h.server.SetClientResourceAuthorizer(func(clientID, path string) bool {
		return bound && clientID == h.clientID && path == resourcePath
	})
	requestToken := h.authorize(t, resource)
	claims := h.claims(requestToken, "approval_jti_client_revoke")
	claims.Subject = "usr_personal_owner"
	claims.Role = "operator"
	consent := completeHostedConsent(h.mux, requestToken, approvalAssertion(t, h.privateKey, claims), nil)
	if consent.Code != http.StatusFound {
		t.Fatalf("completion=%d body=%s", consent.Code, consent.Body)
	}
	redirect, err := url.Parse(consent.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {redirect.Query().Get("code")},
		"client_id":     {h.clientID},
		"redirect_uri":  {h.redirect},
		"code_verifier": {h.verifier},
		"resource":      {resource},
	}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	h.mux.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("initial token=%d body=%s", tokenResponse.Code, tokenResponse.Body)
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if !h.server.validAccess(tokens.AccessToken, resourcePath) {
		t.Fatal("fresh client token was not accepted")
	}

	bound = false
	if h.server.validAccess(tokens.AccessToken, resourcePath) {
		t.Fatal("revoked client token remained valid")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {h.clientID}, "resource": {resource}}
	refreshRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshForm.Encode()))
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshResponse := httptest.NewRecorder()
	h.mux.ServeHTTP(refreshResponse, refreshRequest)
	if refreshResponse.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh=%d body=%s", refreshResponse.Code, refreshResponse.Body)
	}
}

func TestClientBoundTokenExchangeRequiresExactSingleResource(t *testing.T) {
	h := newHostedConsentHarness(t)
	const resource = "https://engine.example/mcp/clients/personal-work"
	const resourcePath = "/mcp/clients/personal-work"
	h.epochs[resourcePath] = "client-epoch-1"
	h.server.SetHostedConsentAuthorizer(func(context.Context, string, string, string, string) error { return nil })
	h.server.SetClientResourceAuthorizer(func(clientID, path string) bool {
		return clientID == h.clientID && path == resourcePath
	})
	issueCode := func(t *testing.T) string {
		t.Helper()
		requestToken := h.authorize(t, resource)
		claims := h.claims(requestToken, "approval_jti_resource_"+strings.ReplaceAll(t.Name(), "/", "_"))
		claims.Subject, claims.Role = "usr_personal_owner", "operator"
		response := completeHostedConsent(h.mux, requestToken, approvalAssertion(t, h.privateKey, claims), nil)
		if response.Code != http.StatusFound {
			t.Fatalf("completion=%d body=%s", response.Code, response.Body)
		}
		redirect, err := url.Parse(response.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return redirect.Query().Get("code")
	}
	exchange := func(values url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		h.mux.ServeHTTP(response, request)
		return response
	}
	codeForm := func(code string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {h.clientID}, "redirect_uri": {h.redirect}, "code_verifier": {h.verifier},
		}
	}
	for name, mutate := range map[string]func(url.Values){
		"missing":          func(url.Values) {},
		"mismatch":         func(v url.Values) { v.Set("resource", "https://engine.example/mcp") },
		"duplicate":        func(v url.Values) { v.Add("resource", resource); v.Add("resource", resource) },
		"wrong_client":     func(v url.Values) { v.Set("client_id", "mcp_someone_else") },
		"duplicate_client": func(v url.Values) { v.Add("client_id", h.clientID) },
	} {
		t.Run("code_"+name, func(t *testing.T) {
			form := codeForm(issueCode(t))
			mutate(form)
			if response := exchange(form); response.Code != http.StatusBadRequest {
				t.Fatalf("code %s = %d body=%s", name, response.Code, response.Body)
			}
		})
	}

	valid := codeForm(issueCode(t))
	valid.Set("resource", resource)
	tokenResponse := exchange(valid)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("valid code = %d body=%s", tokenResponse.Code, tokenResponse.Body)
	}
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(url.Values){
		"missing":          func(url.Values) {},
		"mismatch":         func(v url.Values) { v.Set("resource", "https://engine.example/mcp") },
		"duplicate":        func(v url.Values) { v.Add("resource", resource); v.Add("resource", resource) },
		"missing_client":   func(v url.Values) { v.Del("client_id") },
		"wrong_client":     func(v url.Values) { v.Set("client_id", "mcp_someone_else") },
		"duplicate_client": func(v url.Values) { v.Add("client_id", h.clientID) },
	} {
		t.Run("refresh_"+name, func(t *testing.T) {
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {h.clientID}}
			mutate(form)
			if response := exchange(form); response.Code != http.StatusBadRequest {
				t.Fatalf("refresh %s = %d body=%s", name, response.Code, response.Body)
			}
		})
	}
}

func TestHostedConsentRejectsSignedApprovalForAnotherResource(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestToken := h.authorize(t, "https://engine.example/mcp/team")
	claims := h.claims(requestToken, "approval_jti_wrong_resource")
	claims.ResourcePath = "/mcp"
	rec := completeHostedConsent(h.mux, requestToken, approvalAssertion(t, h.privateKey, claims), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched signed resource = %d, want 401 body=%s", rec.Code, rec.Body)
	}
}

func TestHostedConsentRejectsTamperingAndInvalidApprovalClaims(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestToken := h.authorize(t, "https://engine.example/mcp")

	replacement := "A"
	if requestToken[len(requestToken)-1] == 'A' {
		replacement = "B"
	}
	tamperedToken := requestToken[:len(requestToken)-1] + replacement
	validAssertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_0002"))
	if rec := completeHostedConsent(h.mux, tamperedToken, validAssertion, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered request token = %d, want 400", rec.Code)
	}

	cases := []struct {
		name   string
		mutate func(*hostedApprovalClaims)
		key    ed25519.PrivateKey
	}{
		{"wrong audience", func(c *hostedApprovalClaims) { c.Audience = "https://other-engine.example" }, h.privateKey},
		{"wrong engine issuer", func(c *hostedApprovalClaims) { c.EngineIssuer = "https://other-engine.example" }, h.privateKey},
		{"wrong request hash", func(c *hostedApprovalClaims) { c.RequestSHA256 = strings.Repeat("A", 43) }, h.privateKey},
		{"expired", func(c *hostedApprovalClaims) { c.ExpiresAt = h.now.Add(-time.Second).Unix() }, h.privateKey},
		{"excessive lifetime", func(c *hostedApprovalClaims) { c.ExpiresAt = h.now.Add(10 * time.Minute).Unix() }, h.privateKey},
	}
	_, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	cases = append(cases, struct {
		name   string
		mutate func(*hostedApprovalClaims)
		key    ed25519.PrivateKey
	}{"wrong signing key", func(*hostedApprovalClaims) {}, wrongPrivateKey})

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := h.claims(requestToken, "approval_jti_invalid_"+strconv.Itoa(i))
			tc.mutate(&claims)
			assertion := approvalAssertion(t, tc.key, claims)
			if rec := completeHostedConsent(h.mux, requestToken, assertion, nil); rec.Code != http.StatusUnauthorized {
				t.Fatalf("invalid assertion = %d, body %s", rec.Code, rec.Body)
			}
		})
	}

	// A malformed/tampered compact signature is rejected as well.
	parts := strings.Split(validAssertion, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if rec := completeHostedConsent(h.mux, requestToken, strings.Join(parts, "."), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered assertion signature = %d, want 401", rec.Code)
	}
}

func TestHostedConsentSignedDenialReturnsAccessDeniedAndConsumesAssertion(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestToken := h.authorize(t, "https://engine.example/mcp")
	claims := h.claims(requestToken, "approval_jti_denied")
	claims.Approved = false
	assertion := approvalAssertion(t, h.privateKey, claims)
	rec := completeHostedConsent(h.mux, requestToken, assertion, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("denial completion = %d, body %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse denial redirect: %v", err)
	}
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != h.redirect ||
		redirect.Query().Get("error") != "access_denied" ||
		redirect.Query().Get("state") != "client-state" ||
		redirect.Query().Get("code") != "" {
		t.Fatalf("unexpected denial redirect %q", redirect)
	}
	if rec := completeHostedConsent(h.mux, requestToken, assertion, nil); rec.Code != http.StatusConflict {
		t.Fatalf("denied request replay = %d, want 409", rec.Code)
	}
	approveAfterDenial := h.claims(requestToken, "approval_jti_approve_after_denial")
	if rec := completeHostedConsent(
		h.mux,
		requestToken,
		approvalAssertion(t, h.privateKey, approveAfterDenial),
		nil,
	); rec.Code != http.StatusConflict {
		t.Fatalf("approve after denial = %d, want 409", rec.Code)
	}

	// A denied assertion consumes its jti exactly like an approval.
	requestTwo := h.authorize(t, "https://engine.example/mcp")
	claimsTwo := h.claims(requestTwo, claims.JTI)
	assertionTwo := approvalAssertion(t, h.privateKey, claimsTwo)
	if rec := completeHostedConsent(h.mux, requestTwo, assertionTwo, nil); rec.Code != http.StatusConflict {
		t.Fatalf("denial jti replay = %d, want 409", rec.Code)
	}
}

func TestHostedConsentExpiryAndReplayProtection(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestOne := h.authorize(t, "https://engine.example/mcp")
	claimsOne := h.claims(requestOne, "shared_approval_jti")
	assertionOne := approvalAssertion(t, h.privateKey, claimsOne)
	if rec := completeHostedConsent(h.mux, requestOne, assertionOne, nil); rec.Code != http.StatusFound {
		t.Fatalf("first completion = %d, body %s", rec.Code, rec.Body)
	}
	if rec := completeHostedConsent(h.mux, requestOne, assertionOne, nil); rec.Code != http.StatusConflict {
		t.Fatalf("request replay = %d, want 409", rec.Code)
	}
	freshJTI := h.claims(requestOne, "fresh_jti_same_request")
	if rec := completeHostedConsent(
		h.mux,
		requestOne,
		approvalAssertion(t, h.privateKey, freshJTI),
		nil,
	); rec.Code != http.StatusConflict {
		t.Fatalf("request replay with fresh jti = %d, want 409", rec.Code)
	}

	// A freshly signed assertion for a different request still cannot reuse the
	// first assertion's jti.
	requestTwo := h.authorize(t, "https://engine.example/mcp")
	claimsTwo := h.claims(requestTwo, claimsOne.JTI)
	assertionTwo := approvalAssertion(t, h.privateKey, claimsTwo)
	if rec := completeHostedConsent(h.mux, requestTwo, assertionTwo, nil); rec.Code != http.StatusConflict {
		t.Fatalf("jti replay = %d, body %s", rec.Code, rec.Body)
	}

	requestThree := h.authorize(t, "https://engine.example/mcp")
	assertionThree := approvalAssertion(t, h.privateKey, h.claims(requestThree, "approval_jti_expiry"))
	h.now = h.now.Add(hostedConsentTTL + time.Second)
	if rec := completeHostedConsent(h.mux, requestThree, assertionThree, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired request = %d, want 400", rec.Code)
	}
}

func TestHostedConsentCannotRebindRedirectResourceOrPKCE(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestToken := h.authorize(t, "https://engine.example/mcp/team")
	assertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_rebinding"))
	extra := url.Values{
		"redirect_uri":          {"https://attacker.example/callback"},
		"resource":              {"https://engine.example/mcp"},
		"code_challenge":        {strings.Repeat("A", 43)},
		"code_challenge_method": {"plain"},
		"state":                 {"attacker-state"},
	}
	rec := completeHostedConsent(h.mux, requestToken, assertion, extra)
	if rec.Code != http.StatusFound {
		t.Fatalf("complete with injected fields = %d, body %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != h.redirect ||
		redirect.Query().Get("state") != "client-state" {
		t.Fatalf("completion rebound redirect/state: %q", redirect)
	}
	code := redirect.Query().Get("code")
	h.server.mu.Lock()
	authCode := h.server.codes[code]
	h.server.mu.Unlock()
	if authCode.redirectURI != h.redirect ||
		authCode.resource != "/mcp/team" ||
		authCode.challenge != h.challenge {
		t.Fatalf("completion rebound stored OAuth request: %+v", authCode)
	}
}

func TestHostedConsentRevalidatesClientAndLiveResource(t *testing.T) {
	t.Run("registered redirect removed", func(t *testing.T) {
		h := newHostedConsentHarness(t)
		requestToken := h.authorize(t, "https://engine.example/mcp")
		assertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_redirect"))
		h.server.mu.Lock()
		delete(h.server.clients[h.clientID].redirectURIs, h.redirect)
		h.server.mu.Unlock()
		if rec := completeHostedConsent(h.mux, requestToken, assertion, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("completion after redirect removal = %d, want 400", rec.Code)
		}
	})
	t.Run("resource deleted", func(t *testing.T) {
		h := newHostedConsentHarness(t)
		requestToken := h.authorize(t, "https://engine.example/mcp/team")
		assertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_resource"))
		delete(h.epochs, "/mcp/team")
		if rec := completeHostedConsent(h.mux, requestToken, assertion, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("completion after resource deletion = %d, want 400", rec.Code)
		}
	})
	t.Run("redirect corrupted to unsafe scheme", func(t *testing.T) {
		h := newHostedConsentHarness(t)
		requestToken := h.authorize(t, "https://engine.example/mcp")
		request, expires, err := h.server.verifyHostedRequestToken(requestToken)
		if err != nil {
			t.Fatalf("open hosted request: %v", err)
		}
		request.redirectURI = "javascript:alert(1)"
		unsafeToken, err := h.server.hostedRequestToken(request, expires)
		if err != nil {
			t.Fatalf("seal unsafe test request: %v", err)
		}
		assertion := approvalAssertion(t, h.privateKey, h.claims(unsafeToken, "approval_jti_unsafe_redirect"))
		rec := completeHostedConsent(h.mux, unsafeToken, assertion, nil)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("completion with unsafe redirect = %d location=%q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

func TestHostedConsentRequestStateIsStatelessAndBounded(t *testing.T) {
	h := newHostedConsentHarness(t)
	const requestCount = 500
	tokens := make(map[string]struct{}, requestCount)
	for range requestCount {
		token := h.authorize(t, "https://engine.example/mcp")
		if len(token) > hostedRequestTokenLimit {
			t.Fatalf("request token length = %d, limit %d", len(token), hostedRequestTokenLimit)
		}
		if _, duplicate := tokens[token]; duplicate {
			t.Fatal("hosted consent request nonce was reused")
		}
		tokens[token] = struct{}{}
	}
	h.server.mu.RLock()
	approvalReplayRecords := len(h.server.usedApprovalJTIs)
	requestReplayRecords := len(h.server.usedConsentRequests)
	codeCount := len(h.server.codes)
	h.server.mu.RUnlock()
	if approvalReplayRecords != 0 || requestReplayRecords != 0 || codeCount != 0 {
		t.Fatalf(
			"anonymous hosted begins grew server state: approval_jtis=%d request_hashes=%d codes=%d",
			approvalReplayRecords,
			requestReplayRecords,
			codeCount,
		)
	}
}

func TestHostedConsentConcurrentDifferentJTICompletionIssuesOnce(t *testing.T) {
	h := newHostedConsentHarness(t)
	requestToken := h.authorize(t, "https://engine.example/mcp")
	assertions := []string{
		approvalAssertion(t, h.privateKey, h.claims(requestToken, "concurrent_jti_0001")),
		approvalAssertion(t, h.privateKey, h.claims(requestToken, "concurrent_jti_0002")),
	}
	start := make(chan struct{})
	results := make(chan int, len(assertions))
	var completions sync.WaitGroup
	for _, assertion := range assertions {
		completions.Add(1)
		go func() {
			defer completions.Done()
			<-start
			results <- completeHostedConsent(h.mux, requestToken, assertion, nil).Code
		}()
	}
	close(start)
	completions.Wait()
	close(results)

	statusCounts := map[int]int{}
	for status := range results {
		statusCounts[status]++
	}
	if statusCounts[http.StatusFound] != 1 || statusCounts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent completion statuses = %#v, want one 302 and one 409", statusCounts)
	}
	h.server.mu.RLock()
	codeCount := len(h.server.codes)
	h.server.mu.RUnlock()
	if codeCount != 1 {
		t.Fatalf("concurrent completion issued %d codes, want 1", codeCount)
	}
}

func TestHostedConsentRequestTokenStrictSizeAndRoundTrip(t *testing.T) {
	h := newHostedConsentHarness(t)
	request := authorizationRequest{
		clientID:     strings.Repeat("c", 750),
		redirectURI:  "https://client.example/" + strings.Repeat("r", 450),
		state:        strings.Repeat("s", 800),
		challenge:    strings.Repeat("p", 128),
		scope:        strings.Repeat("o", 550),
		resourceRaw:  "https://engine.example/" + strings.Repeat("u", 450),
		resourcePath: "/" + strings.Repeat("m", 450),
		generation:   serverGeneration(h.server),
	}
	token, err := h.server.hostedRequestToken(request, h.now.Add(hostedConsentTTL))
	if err != nil {
		t.Fatalf("seal large hosted request: %v", err)
	}
	if len(token) > hostedRequestTokenLimit {
		t.Fatalf("large request token length = %d, limit %d", len(token), hostedRequestTokenLimit)
	}
	opened, expires, err := h.server.verifyHostedRequestToken(token)
	if err != nil {
		t.Fatalf("open large hosted request: %v", err)
	}
	if opened != request || !expires.Equal(h.now.Add(hostedConsentTTL)) {
		t.Fatalf("hosted request round trip mismatch: request=%+v expiry=%v", opened, expires)
	}

	request.state = strings.Repeat("s", hostedRequestPlaintextLimit)
	if _, err := h.server.hostedRequestToken(request, h.now.Add(hostedConsentTTL)); err == nil {
		t.Fatal("oversized hosted request plaintext was accepted")
	}
	oversizedToken := hostedRequestVersion + "." + strings.Repeat("A", hostedRequestTokenLimit)
	if _, _, err := h.server.verifyHostedRequestToken(oversizedToken); err == nil {
		t.Fatal("oversized hosted request token was accepted")
	}
}

func TestHostedConsentOversizedAggregateAuthorizationFailsWithoutState(t *testing.T) {
	h := newHostedConsentHarness(t)
	largeClientID := strings.Repeat("c", 900)
	h.server.clients[largeClientID] = client{redirectURIs: map[string]bool{h.redirect: true}}
	q := url.Values{
		"client_id":             {largeClientID},
		"redirect_uri":          {h.redirect},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {h.challenge},
		"scope":                 {strings.Repeat("s", 1024)},
		"state":                 {strings.Repeat("x", 2048)},
		"resource":              {"https://engine.example/mcp"},
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("oversized aggregate authorize = %d, body %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse oversized aggregate redirect: %v", err)
	}
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != h.redirect ||
		redirect.Query().Get("error") != "invalid_request" ||
		redirect.Query().Get("code") != "" {
		t.Fatalf("oversized aggregate authorize redirect = %q", redirect)
	}
	h.server.mu.RLock()
	approvalReplayRecords := len(h.server.usedApprovalJTIs)
	requestReplayRecords := len(h.server.usedConsentRequests)
	codeCount := len(h.server.codes)
	h.server.mu.RUnlock()
	if approvalReplayRecords != 0 || requestReplayRecords != 0 || codeCount != 0 {
		t.Fatalf(
			"oversized authorize grew state: approval_jtis=%d request_hashes=%d codes=%d",
			approvalReplayRecords,
			requestReplayRecords,
			codeCount,
		)
	}
}

func TestHostedConsentRequestSurvivesRestartAndConsumedPairRemainsReplayed(t *testing.T) {
	h := newHostedConsentHarness(t)
	store := newMemoryDurableOAuthStore()
	configureGeneration(t, h.server, store)
	beforeCompletion := h.authorize(t, "https://engine.example/mcp")
	beforeAssertion := approvalAssertion(
		t,
		h.privateKey,
		h.claims(beforeCompletion, "approval_jti_before_restart"),
	)

	consumed := h.authorize(t, "https://engine.example/mcp")
	consumedAssertion := approvalAssertion(
		t,
		h.privateKey,
		h.claims(consumed, "approval_jti_consumed_before_restart"),
	)
	if rec := completeHostedConsent(h.mux, consumed, consumedAssertion, nil); rec.Code != http.StatusFound {
		t.Fatalf("consume request before restart = %d, body %s", rec.Code, rec.Body)
	}

	restarted := New(h.server.issuer, "unused-hosted-password", "engine-secret-that-never-leaves")
	restarted.now = func() time.Time { return h.now }
	restarted.SetEpochLookup(func(path string) (string, bool) {
		epoch, ok := h.epochs[path]
		return epoch, ok
	})
	restarted.clients[h.clientID] = client{redirectURIs: map[string]bool{h.redirect: true}}
	configureGeneration(t, restarted, store)
	if err := restarted.ConfigureHostedConsent(
		h.server.hosted.url.String(),
		h.server.hosted.publicKey,
	); err != nil {
		t.Fatalf("configure restarted hosted consent: %v", err)
	}
	restartedMux := http.NewServeMux()
	restarted.Routes(restartedMux)

	for name, pair := range map[string]struct {
		request   string
		assertion string
		wantCode  int
	}{
		"unconsumed": {request: beforeCompletion, assertion: beforeAssertion, wantCode: http.StatusFound},
		"consumed":   {request: consumed, assertion: consumedAssertion, wantCode: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			rec := completeHostedConsent(restartedMux, pair.request, pair.assertion, nil)
			if rec.Code != pair.wantCode {
				t.Fatalf(
					"post-restart pair = %d location=%q, want %d",
					rec.Code,
					rec.Header().Get("Location"),
					pair.wantCode,
				)
			}
			if pair.wantCode == http.StatusFound && rec.Header().Get("Location") == "" {
				t.Fatal("unconsumed request did not receive an OAuth redirect after restart")
			}
			if pair.wantCode != http.StatusFound && rec.Header().Get("Location") != "" {
				t.Fatalf("replayed approval redirected after restart: %q", rec.Header().Get("Location"))
			}
		})
	}
}

func TestPasswordConsentRemainsSelfHostedDefault(t *testing.T) {
	server := New("https://engine.example", "self-hosted-password", "engine-secret")
	server.clients["mcp_self_hosted"] = client{redirectURIs: map[string]bool{
		"https://client.example/callback": true,
	}}
	verifier := strings.Repeat("s", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	values := url.Values{
		"client_id":             {"mcp_self_hosted"},
		"redirect_uri":          {"https://client.example/callback"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {challenge},
		"resource":              {"https://engine.example/mcp"},
		"state":                 {"self-hosted-state"},
	}
	mux := http.NewServeMux()
	server.Routes(mux)

	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil))
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), "Enter your console password") {
		t.Fatalf("self-hosted GET consent = %d, body %s", getRec.Code, getRec.Body)
	}

	values.Set("password", "self-hosted-password")
	postReq := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(values.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("self-hosted password approval = %d, body %s", postRec.Code, postRec.Body)
	}
	location, err := url.Parse(postRec.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" || location.Query().Get("state") != "self-hosted-state" {
		t.Fatalf("self-hosted consent redirect = %q, err %v", postRec.Header().Get("Location"), err)
	}
	if rec := completeHostedConsent(mux, "request", "assertion", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("self-hosted completion endpoint = %d, want 404", rec.Code)
	}
}

func TestPasswordConsentCanBindASelfHostedClientEndpoint(t *testing.T) {
	server := New("https://engine.example", "self-hosted-password", "engine-secret")
	server.clients["mcp_self_hosted"] = client{redirectURIs: map[string]bool{
		"https://client.example/callback": true,
	}}
	server.SetEpochLookup(func(path string) (string, bool) {
		return map[string]string{"/mcp/clients/local-codex": "client-epoch-1"}[path], path == "/mcp/clients/local-codex"
	})
	var got struct{ subject, role, clientID, resource string }
	server.SetLocalConsentAuthorizer(func(_ context.Context, subject, role, clientID, resource string) error {
		got = struct{ subject, role, clientID, resource string }{subject, role, clientID, resource}
		return nil
	})
	verifier := strings.Repeat("s", 64)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {"mcp_self_hosted"},
		"redirect_uri":          {"https://client.example/callback"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"resource":              {"https://engine.example/mcp/clients/local-codex"},
		"password":              {"self-hosted-password"},
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("self-hosted client consent = %d body=%s", rec.Code, rec.Body)
	}
	if got != (struct{ subject, role, clientID, resource string }{"local-admin", "owner", "mcp_self_hosted", "/mcp/clients/local-codex"}) {
		t.Fatalf("local consent binding=%#v", got)
	}
}

func TestConfigureHostedConsentRejectsUnsafeConfiguration(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	server := New("https://engine.example", "pw", "secret")
	for _, consentURL := range []string{
		"http://app.example/consent",
		"//app.example/consent",
		"https://user@app.example/consent",
		"https://app.example/consent#fragment",
	} {
		if err := server.ConfigureHostedConsent(consentURL, publicKey); err == nil {
			t.Fatalf("ConfigureHostedConsent(%q) should fail", consentURL)
		}
	}
	if err := server.ConfigureHostedConsent("http://127.0.0.1:3000/consent", publicKey); err != nil {
		t.Fatalf("loopback HTTP should be allowed for development: %v", err)
	}
	if err := server.ConfigureHostedConsent("https://app.example/consent", publicKey[:8]); err == nil {
		t.Fatal("short Ed25519 public key should fail")
	}
}
