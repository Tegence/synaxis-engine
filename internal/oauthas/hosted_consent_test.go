package oauthas

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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
		location.Query().Get("completion_url") != h.server.issuer+"/authorize/complete" {
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
	hash := sha256.Sum256([]byte(requestToken))
	return hostedApprovalClaims{
		Audience:      h.server.issuer,
		EngineIssuer:  h.server.issuer,
		RequestSHA256: base64.RawURLEncoding.EncodeToString(hash[:]),
		JTI:           jti,
		ExpiresAt:     h.now.Add(2 * time.Minute).Unix(),
		Approved:      true,
	}
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
	requestToken := h.authorize(t, "https://engine.example/mcp/team")
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
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("exchange hosted code = %d, body %s", tokenRec.Code, tokenRec.Body)
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
	if rec := completeHostedConsent(h.mux, requestToken, assertion, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("denied request replay = %d, want 400", rec.Code)
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
	if rec := completeHostedConsent(h.mux, requestOne, assertionOne, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("request replay = %d, want 400", rec.Code)
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
		assertion := approvalAssertion(t, h.privateKey, h.claims(requestToken, "approval_jti_unsafe_redirect"))
		parts := strings.Split(requestToken, ".")
		h.server.mu.Lock()
		pending := h.server.pendingConsents[parts[2]]
		pending.request.redirectURI = "javascript:alert(1)"
		h.server.pendingConsents[parts[2]] = pending
		h.server.mu.Unlock()
		rec := completeHostedConsent(h.mux, requestToken, assertion, nil)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("completion with unsafe redirect = %d location=%q", rec.Code, rec.Header().Get("Location"))
		}
	})
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
