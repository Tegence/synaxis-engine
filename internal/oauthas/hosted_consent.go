package oauthas

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	hostedConsentTTL        = 5 * time.Minute
	maxPendingConsents      = 2048
	hostedAssertionType     = "synaxis-engine-consent+jwt"
	hostedRequestTokenLimit = 512
	hostedAssertionLimit    = 8 << 10
)

// authorizationRequest is the exact OAuth request the Engine approved for
// consent. In hosted mode it stays inside the Engine; the browser receives
// only an opaque, short-lived HMAC token that identifies this record.
type authorizationRequest struct {
	clientID     string
	redirectURI  string
	state        string
	challenge    string
	scope        string
	resourceRaw  string
	resourcePath string
}

func (r authorizationRequest) withinLimits() bool {
	return len(r.clientID) <= 256 &&
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

type pendingConsent struct {
	request authorizationRequest
	expires time.Time
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
	id := randToken(24)
	token := s.hostedRequestToken(id, expires.Unix())

	s.mu.Lock()
	s.cleanupHostedStateLocked(now)
	if len(s.pendingConsents) >= maxPendingConsents {
		s.mu.Unlock()
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many pending consent requests")
		return
	}
	s.pendingConsents[id] = pendingConsent{request: request, expires: expires}
	s.mu.Unlock()

	consentURL := *s.hosted.url
	q := consentURL.Query()
	q.Set("request", token)
	q.Set("engine_issuer", s.issuer)
	q.Set("completion_url", s.issuer+"/authorize/complete")
	consentURL.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, consentURL.String(), http.StatusFound)
}

func (s *Server) hostedRequestToken(id string, expires int64) string {
	exp := strconv.FormatInt(expires, 10)
	signingInput := "v1." + exp + "." + id
	signature := s.sign("hosted-consent-request|" + s.issuer + "|" + signingInput)
	return signingInput + "." + signature
}

func (s *Server) verifyHostedRequestToken(token string) (string, error) {
	if len(token) == 0 || len(token) > hostedRequestTokenLimit {
		return "", errors.New("invalid hosted consent request")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" || !validOpaqueID(parts[2]) {
		return "", errors.New("invalid hosted consent request")
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || s.now().Unix() >= expires {
		return "", errors.New("hosted consent request expired")
	}
	signingInput := strings.Join(parts[:3], ".")
	expected := s.sign("hosted-consent-request|" + s.issuer + "|" + signingInput)
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(expected)) != 1 {
		return "", errors.New("invalid hosted consent request")
	}
	return parts[2], nil
}

type hostedAssertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type hostedApprovalClaims struct {
	Audience      string `json:"aud"`
	EngineIssuer  string `json:"engine_issuer"`
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
		subtle.ConstantTimeCompare([]byte(claims.RequestSHA256), []byte(expectedHash)) != 1 ||
		!validOpaqueID(claims.JTI) ||
		claims.ExpiresAt <= now.Unix() ||
		claims.ExpiresAt > now.Add(hostedConsentTTL).Unix() {
		return hostedApprovalClaims{}, errors.New("invalid hosted consent approval")
	}
	return claims, nil
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

	id, err := s.verifyHostedRequestToken(requestToken)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}

	s.mu.Lock()
	pending, exists := s.pendingConsents[id]
	s.mu.Unlock()
	if !exists || !s.now().Before(pending.expires) {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}

	claims, err := s.verifyHostedApproval(assertion, requestToken)
	if err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_approval", "approval assertion rejected")
		return
	}
	if !s.revalidateHostedRequest(pending.request) {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "authorization request is no longer valid")
		return
	}

	// Consume both the request and the Platform assertion jti atomically. The
	// second check closes the race between two simultaneous completion POSTs.
	now := s.now()
	s.mu.Lock()
	s.cleanupHostedStateLocked(now)
	pending, exists = s.pendingConsents[id]
	if !exists || !now.Before(pending.expires) {
		s.mu.Unlock()
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid or expired consent request")
		return
	}
	if _, replayed := s.usedApprovalJTIs[claims.JTI]; replayed {
		s.mu.Unlock()
		oauthErr(w, http.StatusConflict, "approval_replayed", "approval assertion has already been used")
		return
	}
	delete(s.pendingConsents, id)
	s.usedApprovalJTIs[claims.JTI] = time.Unix(claims.ExpiresAt, 0)
	s.mu.Unlock()

	if !claims.Approved {
		s.redirectErr(
			w,
			r,
			pending.request.redirectURI,
			pending.request.state,
			"access_denied",
			"the resource owner denied the request",
		)
		return
	}
	s.completeAuthorization(w, r, pending.request)
}

func (s *Server) revalidateHostedRequest(request authorizationRequest) bool {
	if !request.withinLimits() || !validPKCEChallenge(request.challenge) {
		return false
	}
	resource, ok := s.authorizedResource(request.resourceRaw)
	if !ok || resource != request.resourcePath {
		return false
	}
	if _, ok := s.epochFor(resource); !ok {
		return false
	}
	s.mu.Lock()
	client, ok := s.clients[request.clientID]
	s.mu.Unlock()
	_, validRedirect := validClientRedirectURI(request.redirectURI)
	return ok && validRedirect && client.redirectURIs[request.redirectURI]
}

func (s *Server) cleanupHostedStateLocked(now time.Time) {
	for id, pending := range s.pendingConsents {
		if !now.Before(pending.expires) {
			delete(s.pendingConsents, id)
		}
	}
	for jti, expires := range s.usedApprovalJTIs {
		if !now.Before(expires) {
			delete(s.usedApprovalJTIs, jti)
		}
	}
}
