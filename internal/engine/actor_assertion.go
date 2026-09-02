package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	platformActorAssertionHeader = "X-Synaxis-Actor-Assertion"
	platformActorAssertionType   = "synaxis-engine-actor+jwt"
	platformServiceActorID       = "platform-service"
	platformActorAssertionMaxAge = 2 * time.Minute
	platformActorClockSkew       = 10 * time.Second
	maxActorAssertionBytes       = 4096
	maxActorRequestBodyBytes     = 2 << 20
)

var ErrInvalidPlatformActorAssertion = errors.New("invalid Platform actor assertion")

// PlatformActor is the verified Platform identity responsible for a single
// hosted management request. It is deliberately carried only in request
// context: handlers must never recover identity from user-controlled headers.
// Connection-namespace ACL enforcement will consume this value directly.
type PlatformActor struct {
	WorkspaceID string
	UserID      string
	Role        string
}

type platformActorContextKey struct{}

// PlatformActorFromContext retrieves the actor only when the ConsoleAPI has
// verified a Platform-signed assertion for this request.
func PlatformActorFromContext(ctx context.Context) (PlatformActor, bool) {
	actor, ok := ctx.Value(platformActorContextKey{}).(PlatformActor)
	return actor, ok
}

func withPlatformActor(ctx context.Context, actor PlatformActor) context.Context {
	return context.WithValue(ctx, platformActorContextKey{}, actor)
}

// PlatformActorVerifier validates the short-lived Ed25519 assertions sent by
// the hosted Platform. The Engine holds only the public key and fails closed
// when any request binding differs.
type PlatformActorVerifier struct {
	workspaceID string
	audience    string
	publicKey   ed25519.PublicKey
	now         func() time.Time
}

type actorAssertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type actorAssertionClaims struct {
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
	WorkspaceID string `json:"workspace_id"`
	UserID      string `json:"user_id"`
	Role        string `json:"role"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	BodySHA256  string `json:"body_sha256"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	JTI         string `json:"jti"`
}

// NewPlatformActorVerifier configures hosted request verification. audience
// must be the Engine's canonical issuer/origin, which is also what Platform
// stores as the workspace Engine tenant URL.
func NewPlatformActorVerifier(
	workspaceID,
	audience string,
	publicKey ed25519.PublicKey,
) (*PlatformActorVerifier, error) {
	if !validActorIdentifier(workspaceID) {
		return nil, fmt.Errorf("hosted actor workspace ID is invalid")
	}
	normalizedAudience := normalizeActorAudience(audience)
	if normalizedAudience == "" {
		return nil, fmt.Errorf("hosted actor audience is invalid")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hosted actor public key is invalid")
	}
	return &PlatformActorVerifier{
		workspaceID: workspaceID,
		audience:    normalizedAudience,
		publicKey:   append(ed25519.PublicKey(nil), publicKey...),
		now:         time.Now,
	}, nil
}

// VerifyRequest validates the Platform actor assertion against every
// request-bound claim. It restores the request body after hashing so the
// selected ConsoleAPI handler receives precisely the bytes that were signed.
func (v *PlatformActorVerifier) VerifyRequest(r *http.Request) (PlatformActor, error) {
	if v == nil || r == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	values := r.Header.Values(platformActorAssertionHeader)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxActorAssertionBytes {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	header, claims, signingInput, signature, err := parseActorAssertion(values[0])
	if err != nil || header.Algorithm != "EdDSA" || header.Type != platformActorAssertionType ||
		!ed25519.Verify(v.publicKey, []byte(signingInput), signature) {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	if !validActorClaims(claims, v) {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	requestPath, ok := normalizedActorRequestPath(r)
	if !ok || claims.Method != r.Method || claims.Path != requestPath {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	body, err := readBoundedActorRequestBody(r)
	if err != nil {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	wantHash, err := base64.RawURLEncoding.Strict().DecodeString(claims.BodySHA256)
	if err != nil || len(wantHash) != sha256.Size {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	gotHash := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(wantHash, gotHash[:]) != 1 {
		return PlatformActor{}, ErrInvalidPlatformActorAssertion
	}
	return PlatformActor{
		WorkspaceID: claims.WorkspaceID,
		UserID:      claims.UserID,
		Role:        claims.Role,
	}, nil
}

func parseActorAssertion(raw string) (actorAssertionHeader, actorAssertionClaims, string, []byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(headerJSON) == 0 || len(headerJSON) > 1024 {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(claimsJSON) == 0 || len(claimsJSON) > 2048 {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	var header actorAssertionHeader
	if err := decodeStrictActorJSON(headerJSON, &header); err != nil {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	var claims actorAssertionClaims
	if err := decodeStrictActorJSON(claimsJSON, &claims); err != nil {
		return actorAssertionHeader{}, actorAssertionClaims{}, "", nil, ErrInvalidPlatformActorAssertion
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

func decodeStrictActorJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("actor assertion contains trailing JSON")
	}
	return nil
}

func validActorClaims(claims actorAssertionClaims, verifier *PlatformActorVerifier) bool {
	if claims.Issuer != "synaxis-platform" ||
		claims.Audience != verifier.audience ||
		claims.WorkspaceID != verifier.workspaceID ||
		!validActorIdentifier(claims.WorkspaceID) ||
		!validActorIdentifier(claims.UserID) ||
		!validActorRole(claims.Role) ||
		!validActorHTTPMethod(claims.Method) ||
		!validActorAPIPath(claims.Path) ||
		!validActorIdentifier(claims.JTI) {
		return false
	}
	if claims.Role == "service" {
		if claims.UserID != platformServiceActorID || !platformServiceControlRoute(claims.Method, claims.Path) {
			return false
		}
	} else if claims.UserID == platformServiceActorID {
		return false
	}
	now := time.Now
	if verifier.now != nil {
		now = verifier.now
	}
	nowUnix := now().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > int64(platformActorAssertionMaxAge/time.Second) ||
		claims.IssuedAt > nowUnix+int64(platformActorClockSkew/time.Second) ||
		claims.ExpiresAt <= nowUnix {
		return false
	}
	return true
}

// Platform background jobs need a principal for a few closed control-plane
// routes. Keep that principal narrower than a workspace member so future ACL
// checks cannot accidentally use it to mutate connections or approvals.
func platformServiceControlRoute(method, requestPath string) bool {
	switch {
	case method == http.MethodPost && requestPath == "/api/oauth/revoke-all":
		return true
	case method == http.MethodPut && requestPath == "/api/usage/grant":
		return true
	case method == http.MethodGet && requestPath == "/api/usage":
		return true
	case method == http.MethodGet && requestPath == "/api/activation":
		return true
	case method == http.MethodGet && platformServiceLibraryPublicationCandidateRoute(requestPath):
		return true
	case method == http.MethodPost && platformServiceLibraryPublicationClaimRoute(requestPath):
		return true
	default:
		return false
	}
}

// platformServiceLibraryPublicationCandidateRoute deliberately recognizes one
// dynamic resource route instead of making the entire Library API available
// to the Platform service principal. The opaque artifact ID is constrained to
// the same unescaped identifier alphabet as every actor assertion field, so a
// signed path cannot be confused with a differently encoded route.
func platformServiceLibraryPublicationCandidateRoute(requestPath string) bool {
	return platformServiceLibraryPublicationRoute(requestPath, "publication-candidate")
}

// platformServiceLibraryPublicationClaimRoute is intentionally separate from
// the candidate read. The Platform can only claim the exact reviewed artifact
// version/digest it just observed; it never receives general Library write
// authority through this service principal.
func platformServiceLibraryPublicationClaimRoute(requestPath string) bool {
	return platformServiceLibraryPublicationRoute(requestPath, "publication-claim")
}

func platformServiceLibraryPublicationRoute(requestPath, operation string) bool {
	parts := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")
	if len(parts) != 5 ||
		parts[0] != "api" ||
		parts[1] != "library" ||
		parts[2] != "artifacts" ||
		parts[4] != operation {
		return false
	}
	return validActorIdentifier(parts[3])
}

func readBoundedActorRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if r.ContentLength > maxActorRequestBodyBytes {
		return nil, errors.New("request body exceeds actor assertion limit")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxActorRequestBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || len(body) > maxActorRequestBodyBytes {
		return nil, errors.New("request body exceeds actor assertion limit")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

func normalizedActorRequestPath(r *http.Request) (string, bool) {
	if r.URL == nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" || !validActorAPIPath(r.URL.Path) {
		return "", false
	}
	return r.URL.Path, true
}

func validActorIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 200 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' || character == '@' {
			continue
		}
		return false
	}
	return true
}

func validActorRole(role string) bool {
	switch role {
	case "owner", "admin", "operator", "viewer", "service":
		return true
	default:
		return false
	}
}

func validActorHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validActorAPIPath(raw string) bool {
	if raw == "" || strings.Contains(raw, "\\") || strings.ContainsRune(raw, '\x00') ||
		strings.Contains(raw, "%") || !strings.HasPrefix(raw, "/api/") {
		return false
	}
	if path.Clean(raw) != raw || strings.HasSuffix(raw, "/") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(raw, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func normalizeActorAudience(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ""
	}
	return parsed.Scheme + "://" + strings.ToLower(parsed.Host)
}
