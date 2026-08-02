package oauthas

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	hostedConsentTTL            = 5 * time.Minute
	hostedAssertionType         = "synaxis-engine-consent+jwt"
	hostedRequestPlaintextLimit = 4 << 10
	hostedRequestTokenLimit     = 6 << 10
	hostedAssertionLimit        = 8 << 10
	hostedRequestVersion        = "v2"
	hostedRequestKeyDomain      = "synaxis-hosted-consent-request-key|v2"
	hostedRequestAADDomain      = "synaxis-hosted-consent-request|v2|"
	hostedRequestBootSaltSize   = 32
	hostedRequestDerivedKeySize = 32
)

var errHostedRequestTooLarge = errors.New("hosted consent request is too large")

// authorizationRequest is the exact OAuth request the Engine approved for
// consent. In hosted mode the browser receives only an opaque, short-lived
// authenticated-encrypted representation of this request.
type authorizationRequest struct {
	clientID     string
	redirectURI  string
	state        string
	challenge    string
	scope        string
	resourceRaw  string
	resourcePath string
	generation   string
}

func (r authorizationRequest) withinLimits() bool {
	return len(r.clientID) <= maxClientIDLength &&
		len(r.redirectURI) <= 2048 &&
		len(r.state) <= 2048 &&
		len(r.challenge) <= 128 &&
		len(r.scope) <= 1024 &&
		len(r.resourceRaw) <= 2048 &&
		len(r.resourcePath) <= 2048
}

type hostedConsent struct {
	url       *url.URL
	publicKey ed25519.PublicKey
}

type hostedRequestPayload struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
	Challenge    string `json:"challenge"`
	Scope        string `json:"scope"`
	ResourceRaw  string `json:"resource_raw"`
	ResourcePath string `json:"resource_path"`
	Generation   string `json:"generation"`
	ExpiresAt    int64  `json:"expires_at"`
}

// newHostedRequestAEAD derives an ephemeral per-process key from the stable
// Engine secret and fresh boot entropy. The boot salt is deliberately not
// persisted or encoded into request tokens, so consent requests cannot cross
// an Engine restart even though access tokens and dynamic registrations can.
func newHostedRequestAEAD(secret []byte) cipher.AEAD {
	bootSalt := make([]byte, hostedRequestBootSaltSize)
	if _, err := io.ReadFull(rand.Reader, bootSalt); err != nil {
		panic("oauthas: generate hosted consent boot salt: " + err.Error())
	}
	kdf := hmac.New(sha256.New, secret)
	_, _ = kdf.Write([]byte(hostedRequestKeyDomain))
	_, _ = kdf.Write([]byte{0})
	_, _ = kdf.Write(bootSalt)
	key := kdf.Sum(nil)
	if len(key) != hostedRequestDerivedKeySize {
		panic("oauthas: derive hosted consent key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("oauthas: initialize hosted consent cipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("oauthas: initialize hosted consent AEAD: " + err.Error())
	}
	return aead
}

// ConfigureHostedConsent delegates /authorize approval to a generic external
// consent UI. The external service is trusted only to approve a request: the
// Engine retains and revalidates every OAuth parameter before issuing a code.
//
// Call this before Routes or serving requests. consentURL must be HTTPS, except
// that loopback HTTP is accepted for local development.
func (s *Server) ConfigureHostedConsent(consentURL string, publicKey ed25519.PublicKey) error {
	u, err := url.Parse(consentURL)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("hosted consent URL must be an absolute URL without userinfo or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return errors.New("hosted consent URL must use HTTPS (loopback HTTP is allowed for development)")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("hosted consent Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	keyCopy := make(ed25519.PublicKey, len(publicKey))
	copy(keyCopy, publicKey)
	urlCopy := *u
	s.hosted = &hostedConsent{url: &urlCopy, publicKey: keyCopy}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) < 43 || len(challenge) > 128 {
		return false
	}
	for _, c := range challenge {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// authorizedResource normalizes an RFC 8707 resource indicator and ensures an
// explicit value names this exact Engine origin. This prevents a consent
// request for one origin from being rebound to an endpoint with the same path
// on another origin.
func (s *Server) authorizedResource(raw string) (string, bool) {
	if raw == "" {
		return "/mcp", true
	}
	resource, err := url.Parse(raw)
	if err != nil || !resource.IsAbs() || resource.Host == "" || resource.User != nil ||
		resource.Fragment != "" || resource.RawQuery != "" {
		return "", false
	}
	issuer, err := url.Parse(s.issuer)
	if err != nil || !issuer.IsAbs() || issuer.Host == "" {
		return "", false
	}
	if !strings.EqualFold(resource.Scheme, issuer.Scheme) || !strings.EqualFold(resource.Host, issuer.Host) {
		return "", false
	}
	path := strings.TrimRight(resource.Path, "/")
	if path == "" {
		return "", false
	}
	return path, true
}

func (s *Server) beginHostedConsent(w http.ResponseWriter, r *http.Request, request authorizationRequest) {
	now := s.now()
	expires := now.Add(hostedConsentTTL)

	s.mu.RLock()
	if request.generation == "" || request.generation != s.tokenGeneration {
		s.mu.RUnlock()
		s.redirectErr(w, r, request.redirectURI, request.state, "invalid_request", "authorization request was revoked")
		return
	}
	s.mu.RUnlock()

	token, err := s.hostedRequestToken(request, expires)
	if err != nil {
		if errors.Is(err, errHostedRequestTooLarge) {
			s.redirectErr(w, r, request.redirectURI, request.state, "invalid_request", "authorization request is too large")
			return
		}
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "could not create consent request")
		return
	}

	// Sealing does not hold the revocation barrier because entropy collection
	// must never stall RevokeAll. Recheck immediately before delivery; a revoke
	// after this point still makes the embedded generation unusable.
	s.mu.RLock()
	current := request.generation != "" && request.generation == s.tokenGeneration
	s.mu.RUnlock()
	if !current {
		s.redirectErr(w, r, request.redirectURI, request.state, "invalid_request", "authorization request was revoked")
		return
	}

	consentURL := *s.hosted.url
	q := consentURL.Query()
	q.Set("request", token)
	q.Set("engine_issuer", s.issuer)
	q.Set("completion_url", s.issuer+"/authorize/complete")
	// Platform uses this narrow, non-authoritative path hint to choose the
	// membership permission for the consent screen. The Engine retains the
	// encrypted request as authority and verifies the signed role against this
	// exact resource before it creates a code.
	q.Set("resource_path", request.resourcePath)
	consentURL.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, consentURL.String(), http.StatusFound)
}

func (s *Server) hostedRequestToken(request authorizationRequest, expires time.Time) (string, error) {
	payload := hostedRequestPayload{
		ClientID:     request.clientID,
		RedirectURI:  request.redirectURI,
		State:        request.state,
		Challenge:    request.challenge,
		Scope:        request.scope,
		ResourceRaw:  request.resourceRaw,
		ResourcePath: request.resourcePath,
		Generation:   request.generation,
		ExpiresAt:    expires.Unix(),
	}
	var plaintext bytes.Buffer
	encoder := json.NewEncoder(&plaintext)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return "", fmt.Errorf("encode hosted consent request: %w", err)
	}
	encodedPlaintext := bytes.TrimSuffix(plaintext.Bytes(), []byte{'\n'})
	if len(encodedPlaintext) == 0 || len(encodedPlaintext) > hostedRequestPlaintextLimit {
		return "", errHostedRequestTooLarge
	}

	nonce := make([]byte, s.hostedRequestAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate hosted consent nonce: %w", err)
	}
	sealed := make([]byte, len(nonce), len(nonce)+len(encodedPlaintext)+s.hostedRequestAEAD.Overhead())
	copy(sealed, nonce)
	sealed = s.hostedRequestAEAD.Seal(
		sealed,
		nonce,
		encodedPlaintext,
		[]byte(hostedRequestAADDomain+s.issuer),
	)
	token := hostedRequestVersion + "." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(token) > hostedRequestTokenLimit {
		return "", errHostedRequestTooLarge
	}
	return token, nil
}

func (s *Server) verifyHostedRequestToken(token string) (authorizationRequest, time.Time, error) {
	if len(token) == 0 || len(token) > hostedRequestTokenLimit {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] != hostedRequestVersion || parts[1] == "" {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(sealed) <= s.hostedRequestAEAD.NonceSize()+s.hostedRequestAEAD.Overhead() {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}
	nonce := sealed[:s.hostedRequestAEAD.NonceSize()]
	plaintext, err := s.hostedRequestAEAD.Open(
		nil,
		nonce,
		sealed[s.hostedRequestAEAD.NonceSize():],
		[]byte(hostedRequestAADDomain+s.issuer),
	)
	if err != nil || len(plaintext) == 0 || len(plaintext) > hostedRequestPlaintextLimit {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}

	var payload hostedRequestPayload
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return authorizationRequest{}, time.Time{}, errors.New("invalid hosted consent request")
	}
	request := authorizationRequest{
		clientID:     payload.ClientID,
		redirectURI:  payload.RedirectURI,
		state:        payload.State,
		challenge:    payload.Challenge,
		scope:        payload.Scope,
		resourceRaw:  payload.ResourceRaw,
		resourcePath: payload.ResourcePath,
		generation:   payload.Generation,
	}
	now := s.now()
	expires := time.Unix(payload.ExpiresAt, 0)
	if !request.withinLimits() || request.generation == "" ||
		!now.Before(expires) || expires.After(now.Add(hostedConsentTTL)) {
		return authorizationRequest{}, time.Time{}, errors.New("hosted consent request expired or invalid")
	}
	return request, expires, nil
}

type hostedAssertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type hostedApprovalClaims struct {
	Audience     string `json:"aud"`
	EngineIssuer string `json:"engine_issuer"`
	// ResourcePath must be signed by Platform and exactly match the sealed
	// request.  The browser-visible query parameter is only a display hint; it
	// is never sufficient authority for a delegated client endpoint.
	ResourcePath string `json:"resource_path"`
	// Subject is supplied exclusively by the Platform-signed approval. It is
	// optional for legacy shared resources, but required by the Engine callback
	// before a client-bound endpoint can be authorized.
	Subject string `json:"sub,omitempty"`
	// Role is the Platform workspace role that approved the request. The
	// Engine validates it against the resource class; a browser cannot upgrade
	// an operator's personal-client approval into broad root MCP access.
	Role          string `json:"role,omitempty"`
	RequestSHA256 string `json:"request_sha256"`
	JTI           string `json:"jti"`
	ExpiresAt     int64  `json:"exp"`
	Approved      bool   `json:"approved"`
}

func (s *Server) verifyHostedApproval(assertion, requestToken string) (hostedApprovalClaims, error) {
	var claims hostedApprovalClaims
	if len(assertion) == 0 || len(assertion) > hostedAssertionLimit {
		return claims, errors.New("invalid hosted consent approval")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return claims, errors.New("invalid hosted consent approval")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("invalid hosted consent approval")
	}
	var header hostedAssertionHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil ||
		header.Algorithm != "EdDSA" || header.Type != hostedAssertionType {
		return claims, errors.New("invalid hosted consent approval")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil {
		return claims, errors.New("invalid hosted consent approval")
	}
	var required struct {
		Approved *bool `json:"approved"`
	}
	if json.Unmarshal(claimsJSON, &required) != nil || required.Approved == nil {
		return claims, errors.New("invalid hosted consent approval")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(s.hosted.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("invalid hosted consent approval")
	}

	now := s.now()
	requestHash := sha256.Sum256([]byte(requestToken))
	expectedHash := base64.RawURLEncoding.EncodeToString(requestHash[:])
	if claims.Audience != s.issuer ||
		claims.EngineIssuer != s.issuer ||
		claims.ResourcePath == "" ||
		(claims.Subject != "" && !validHostedSubject(claims.Subject)) ||
		(claims.Role != "" && !validHostedRole(claims.Role)) ||
		subtle.ConstantTimeCompare([]byte(claims.RequestSHA256), []byte(expectedHash)) != 1 ||
		!validOpaqueID(claims.JTI) ||
		claims.ExpiresAt <= now.Unix() ||
		claims.ExpiresAt > now.Add(hostedConsentTTL).Unix() {
		return hostedApprovalClaims{}, errors.New("invalid hosted consent approval")
	}
	return claims, nil
}

func validHostedRole(role string) bool {
	switch role {
	case "owner", "admin", "operator", "viewer":
		return true
	default:
		return false
	}
}

func validHostedSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 200 || strings.TrimSpace(subject) != subject {
		return false
	}
	for _, c := range subject {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '@' {
			continue
		}
		return false
	}
	return true
}

func validOpaqueID(id string) bool {
	if len(id) < 16 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') &&
			c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (s *Server) handleHostedConsentComplete(w http.ResponseWriter, r *http.Request) {
	if s.hosted == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	r.Body = http.MaxBytesReader(w, r.Body, hostedAssertionLimit+hostedRequestTokenLimit+1024)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	requestToken := r.PostForm.Get("request")
	assertion := r.PostForm.Get("assertion")

	request, requestExpires, err := s.verifyHostedRequestToken(requestToken)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}

	claims, err := s.verifyHostedApproval(assertion, requestToken)
	if err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_approval", "approval assertion rejected")
		return
	}
	if claims.ResourcePath != request.resourcePath {
		oauthErr(w, http.StatusUnauthorized, "invalid_approval", "approval assertion rejected")
		return
	}
	if err := s.syncTokenGeneration(r.Context()); err != nil {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authorization state unavailable")
		return
	}
	if !s.revalidateHostedRequest(request) {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "authorization request is no longer valid")
		return
	}

	// Reserve the consent request before handing the client-bound authorization
	// decision to durable Engine state. This avoids binding two different
	// Platform users during a concurrent approval race while also keeping store
	// I/O outside oauthas's global generation lock.
	now := s.now()
	requestHash := sha256.Sum256([]byte(requestToken))
	requestReplayKey := base64.RawURLEncoding.EncodeToString(requestHash[:])
	s.mu.Lock()
	s.cleanupHostedStateLocked(now)
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		s.mu.Unlock()
		oauthErr(w, http.StatusUnauthorized, "invalid_approval", "approval assertion rejected")
		return
	}
	if request.generation == "" || request.generation != s.tokenGeneration ||
		!now.Before(requestExpires) {
		s.mu.Unlock()
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}
	if _, replayed := s.usedApprovalJTIs[claims.JTI]; replayed {
		s.mu.Unlock()
		oauthErr(w, http.StatusConflict, "approval_replayed", "approval assertion has already been used")
		return
	}
	if _, replayed := s.usedConsentRequests[requestReplayKey]; replayed {
		s.mu.Unlock()
		oauthErr(w, http.StatusConflict, "approval_replayed", "consent request has already been decided")
		return
	}
	if _, inFlight := s.hostedInFlightRequests[requestReplayKey]; inFlight {
		s.mu.Unlock()
		oauthErr(w, http.StatusConflict, "approval_replayed", "consent request is already being decided")
		return
	}
	s.hostedInFlightRequests[requestReplayKey] = struct{}{}
	s.mu.Unlock()

	// A denial has no client-bound side effect. An approval is checked by the
	// Engine callback before code issuance. For client-bound resources, that
	// callback is mandatory; for a shared resource it provides defense in depth
	// when a current hosted Engine has been configured with role-aware consent.
	if claims.Approved && s.hostedConsentAuthorizer != nil {
		if claims.Subject == "" || claims.Role == "" {
			s.mu.Lock()
			delete(s.hostedInFlightRequests, requestReplayKey)
			s.mu.Unlock()
			oauthErr(w, http.StatusForbidden, "access_denied", "the resource owner is not permitted to authorize this client")
			return
		}
		if err := s.hostedConsentAuthorizer(r.Context(), claims.Subject, claims.Role, request.clientID, request.resourcePath); err != nil {
			s.mu.Lock()
			delete(s.hostedInFlightRequests, requestReplayKey)
			s.mu.Unlock()
			oauthErr(w, http.StatusForbidden, "access_denied", "the resource owner is not permitted to authorize this client")
			return
		}
	} else if claims.Approved && clientBoundResource(request.resourcePath) {
		s.mu.Lock()
		delete(s.hostedInFlightRequests, requestReplayKey)
		s.mu.Unlock()
		oauthErr(w, http.StatusForbidden, "access_denied", "the resource owner is not permitted to authorize this client")
		return
	}

	// Consume the Platform assertion jti and sealed request hash, then create
	// the code under the generation barrier. Anonymous begins carry no
	// server-side pending state; replay records are created only after a valid
	// Platform signature and expire with the sealed request.
	s.mu.Lock()
	releaseInFlight := func() {
		delete(s.hostedInFlightRequests, requestReplayKey)
		s.mu.Unlock()
	}
	// The first reservation wins, but Revocation or a natural request expiry may
	// have happened while the durable authorizer ran. Revalidate every state
	// prerequisite before minting a code.
	now = s.now()
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) ||
		request.generation == "" || request.generation != s.tokenGeneration ||
		!now.Before(requestExpires) {
		releaseInFlight()
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}
	if _, replayed := s.usedApprovalJTIs[claims.JTI]; replayed {
		releaseInFlight()
		oauthErr(w, http.StatusConflict, "approval_replayed", "approval assertion has already been used")
		return
	}
	if _, replayed := s.usedConsentRequests[requestReplayKey]; replayed {
		releaseInFlight()
		oauthErr(w, http.StatusConflict, "approval_replayed", "consent request has already been decided")
		return
	}
	code := ""
	if claims.Approved {
		var created bool
		code, created = s.createAuthorizationCodeLocked(request)
		if !created {
			releaseInFlight()
			oauthErr(w, http.StatusBadRequest, "invalid_request", "authorization request was revoked")
			return
		}
	}
	s.usedApprovalJTIs[claims.JTI] = requestExpires
	s.usedConsentRequests[requestReplayKey] = requestExpires

	if !claims.Approved {
		releaseInFlight()
		s.redirectErr(
			w,
			r,
			request.redirectURI,
			request.state,
			"access_denied",
			"the resource owner denied the request",
		)
		return
	}
	releaseInFlight()
	// Delivery stays outside the barrier. If revocation wins before the client
	// receives this response, the code has already been cleared and cannot be
	// redeemed.
	s.redirectAuthorizationCode(w, r, request, code)
}

func (s *Server) revalidateHostedRequest(request authorizationRequest) bool {
	if !request.withinLimits() || !validPKCEChallenge(request.challenge) {
		return false
	}
	resource, ok := s.authorizedResource(request.resourceRaw)
	if !ok || resource != request.resourcePath {
		return false
	}
	s.mu.RLock()
	if request.generation == "" || request.generation != s.tokenGeneration {
		s.mu.RUnlock()
		return false
	}
	if _, ok := s.epochForLocked(resource); !ok {
		s.mu.RUnlock()
		return false
	}
	s.mu.RUnlock()
	_, validRedirect := validClientRedirectURI(request.redirectURI)
	return validRedirect && s.clientAllowsRedirect(request.clientID, request.redirectURI)
}

func (s *Server) cleanupHostedStateLocked(now time.Time) {
	for jti, expires := range s.usedApprovalJTIs {
		if !now.Before(expires) {
			delete(s.usedApprovalJTIs, jti)
		}
	}
	for requestHash, expires := range s.usedConsentRequests {
		if !now.Before(expires) {
			delete(s.usedConsentRequests, requestHash)
		}
	}
}
