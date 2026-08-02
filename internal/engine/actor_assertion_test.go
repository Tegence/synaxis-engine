package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newActorVerifier(t *testing.T) (*PlatformActorVerifier, ed25519.PrivateKey, time.Time) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x7c}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	verifier, err := NewPlatformActorVerifier(
		"wsp_actor",
		"https://engine.example",
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 7, 0, 0, 0, time.UTC)
	verifier.now = func() time.Time { return now }
	return verifier, privateKey, now
}

func signActorAssertionForTest(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	claims actorAssertionClaims,
) string {
	t.Helper()
	headerJSON, err := json.Marshal(actorAssertionHeader{
		Algorithm: "EdDSA",
		Type:      platformActorAssertionType,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, []byte(signingInput)),
	)
}

func actorClaimsForTest(now time.Time, method, requestPath string, body []byte) actorAssertionClaims {
	hash := sha256.Sum256(body)
	return actorAssertionClaims{
		Issuer:      "synaxis-platform",
		Audience:    "https://engine.example",
		WorkspaceID: "wsp_actor",
		UserID:      "usr_actor",
		Role:        "operator",
		Method:      method,
		Path:        requestPath,
		BodySHA256:  base64.RawURLEncoding.EncodeToString(hash[:]),
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(90 * time.Second).Unix(),
		JTI:         "assertion_123",
	}
}

func actorRequest(method, requestPath string, body []byte, assertion string) *http.Request {
	request := httptest.NewRequest(method, requestPath, bytes.NewReader(body))
	request.Header.Set(platformActorAssertionHeader, assertion)
	return request
}

func TestPlatformActorVerifierBindsEveryRequestAttribute(t *testing.T) {
	verifier, privateKey, now := newActorVerifier(t)
	body := []byte(`{"name":"Linear","group":"operations"}`)
	claims := actorClaimsForTest(now, http.MethodPost, "/api/servers", body)
	request := actorRequest(http.MethodPost, "/api/servers", body, signActorAssertionForTest(t, privateKey, claims))
	// A browser-controlled header cannot replace or influence the signed actor.
	request.Header.Set("X-Synaxis-User-ID", "usr_browser_spoof")
	request.Header.Set("X-Synaxis-User-Role", "owner")

	actor, err := verifier.VerifyRequest(request)
	if err != nil {
		t.Fatalf("verify valid assertion: %v", err)
	}
	if actor != (PlatformActor{WorkspaceID: "wsp_actor", UserID: "usr_actor", Role: "operator"}) {
		t.Fatalf("verified actor=%+v", actor)
	}
	if got := request.Header.Get("X-Synaxis-User-ID"); got != "usr_browser_spoof" {
		t.Fatalf("test request unexpectedly altered raw header=%q", got)
	}
	if got := readRequestTestBody(t, request); !bytes.Equal(got, body) {
		t.Fatalf("handler body=%q, want signed body=%q", got, body)
	}
}

func TestPlatformActorVerifierRejectsTamperingAndMismatches(t *testing.T) {
	verifier, privateKey, now := newActorVerifier(t)
	body := []byte(`{"name":"Linear"}`)
	baseClaims := actorClaimsForTest(now, http.MethodPost, "/api/servers", body)

	tests := []struct {
		name   string
		claims actorAssertionClaims
		method string
		path   string
		body   []byte
		mutate func(string) string
	}{
		{
			name:   "signature",
			claims: baseClaims,
			method: http.MethodPost,
			path:   "/api/servers",
			body:   body,
			mutate: func(token string) string {
				if token[len(token)-1] == 'A' {
					return token[:len(token)-1] + "B"
				}
				return token[:len(token)-1] + "A"
			},
		},
		{
			name: "expired",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.IssuedAt = now.Add(-2 * time.Minute).Unix()
				claims.ExpiresAt = now.Add(-time.Second).Unix()
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
		{
			name: "audience",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.Audience = "https://other-engine.example"
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
		{
			name: "workspace",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.WorkspaceID = "wsp_other"
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
		{
			name: "path",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.Path = "/api/logs"
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
		{
			name: "method",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.Method = http.MethodGet
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
		{
			name:   "body",
			claims: baseClaims,
			method: http.MethodPost,
			path:   "/api/servers",
			body:   []byte(`{"name":"GitHub"}`),
		},
		{
			name: "service actor outside control route",
			claims: func() actorAssertionClaims {
				claims := baseClaims
				claims.UserID = platformServiceActorID
				claims.Role = "service"
				return claims
			}(),
			method: http.MethodPost, path: "/api/servers", body: body,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := signActorAssertionForTest(t, privateKey, test.claims)
			if test.mutate != nil {
				assertion = test.mutate(assertion)
			}
			_, err := verifier.VerifyRequest(actorRequest(test.method, test.path, test.body, assertion))
			if !errors.Is(err, ErrInvalidPlatformActorAssertion) {
				t.Fatalf("verify mismatch error=%v, want invalid assertion", err)
			}
		})
	}

	// A differently escaped request path is not the exact normalized Engine
	// operation Platform signed, even if a router could decode it to the same
	// visible endpoint.
	rawPathRequest := actorRequest(
		http.MethodPost,
		"/api/servers",
		body,
		signActorAssertionForTest(t, privateKey, baseClaims),
	)
	rawPathRequest.URL.RawPath = "/api/%73ervers"
	if _, err := verifier.VerifyRequest(rawPathRequest); !errors.Is(err, ErrInvalidPlatformActorAssertion) {
		t.Fatalf("escaped-path assertion error=%v, want invalid assertion", err)
	}
}

func TestHostedConsoleRequiresMachineTokenAndActorAssertion(t *testing.T) {
	verifier, privateKey, now := newActorVerifier(t)
	api := NewConsoleAPI(
		nil,
		nil,
		nil,
		"self-hosted-password",
		"test-session-secret",
		"https://engine.example",
		"https://app.example",
		"",
		WithAdminToken("machine-token"),
		WithLocalAdminAuth(true), // hosted verifier must still prevent this bypass.
		WithPlatformActorVerifier(verifier),
	)
	mux := http.NewServeMux()
	api.Routes(mux)

	claims := actorClaimsForTest(now, http.MethodGet, "/api/gateway", nil)
	validAssertion := signActorAssertionForTest(t, privateKey, claims)
	valid := actorRequest(http.MethodGet, "/api/gateway", nil, validAssertion)
	valid.Header.Set("Authorization", "Bearer machine-token")
	valid.Header.Set("X-Synaxis-User-ID", "usr_spoof")
	validResponse := httptest.NewRecorder()
	mux.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid hosted actor request=%d body=%s", validResponse.Code, validResponse.Body.String())
	}

	local := api.signToken()
	for name, request := range map[string]*http.Request{
		"machine token only": requestWithBearer(http.MethodGet, "/api/gateway", "machine-token"),
		"assertion only":     actorRequest(http.MethodGet, "/api/gateway", nil, validAssertion),
		"local session":      requestWithBearer(http.MethodGet, "/api/gateway", local),
		"raw spoof": func() *http.Request {
			request := requestWithBearer(http.MethodGet, "/api/gateway", "machine-token")
			request.Header.Set("X-Synaxis-User-ID", "usr_spoof")
			return request
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "assertion") {
				t.Fatalf("hosted %s status=%d body=%s", name, response.Code, response.Body.String())
			}
		})
	}

	authorized, ok := api.authorize(valid)
	if !ok {
		t.Fatal("valid assertion was not authorized")
	}
	actor, ok := PlatformActorFromContext(authorized.Context())
	if !ok || actor.UserID != "usr_actor" || actor.Role != "operator" || actor.WorkspaceID != "wsp_actor" {
		t.Fatalf("actor context=%+v ok=%v", actor, ok)
	}
	if got := api.approvalDecisionActor(authorized); got != "platform:usr_actor" {
		t.Fatalf("approval actor=%q", got)
	}
}

func requestWithBearer(method, requestPath, token string) *http.Request {
	request := httptest.NewRequest(method, requestPath, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func readRequestTestBody(t *testing.T, request *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
