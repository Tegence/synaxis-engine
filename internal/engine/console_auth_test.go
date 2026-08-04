package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAuthTestConsole(options ...ConsoleOption) *http.ServeMux {
	api := NewConsoleAPI(
		nil,
		nil,
		nil,
		"self-hosted-password",
		"test-session-secret",
		"https://engine.example",
		"http://localhost:3000",
		"",
		options...,
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux
}

func requestStatus(mux *http.ServeMux, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestConsoleMachineAdminAndSessionAuthentication(t *testing.T) {
	const adminToken = "platform-machine-secret"
	mux := newAuthTestConsole(WithAdminToken(adminToken))

	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("uncredentialed management request = %d, want 401", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", "wrong-machine-secret", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong machine token = %d, want 401", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", adminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("machine token = %d, body %s", rec.Code, rec.Body)
	}

	badLogin := requestStatus(mux, http.MethodPost, "/api/login", "", `{"Password":"wrong"}`)
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("wrong self-hosted password = %d, want 401", badLogin.Code)
	}
	login := requestStatus(mux, http.MethodPost, "/api/login", "", `{"Password":"self-hosted-password"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("self-hosted login = %d, body %s", login.Code, login.Body)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if payload.Token == "" || payload.Token == adminToken {
		t.Fatalf("login returned invalid session token %q", payload.Token)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", payload.Token, ""); rec.Code != http.StatusOK {
		t.Fatalf("existing bearer session = %d, body %s", rec.Code, rec.Body)
	}
}

func TestGatewayReportsOAuthCallbackURL(t *testing.T) {
	api := NewConsoleAPI(
		nil,
		nil,
		nil,
		"self-hosted-password",
		"test-session-secret",
		"https://engine.example/",
		"http://localhost:3000",
		"",
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	rec := requestStatus(mux, http.MethodGet, "/api/gateway", api.signToken(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		ConnectorURL     string `json:"connectorUrl"`
		OAuthCallbackURL string `json:"oauthCallbackUrl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode gateway response: %v", err)
	}
	if payload.ConnectorURL != "https://engine.example/mcp" {
		t.Errorf("connectorUrl = %q", payload.ConnectorURL)
	}
	if payload.OAuthCallbackURL != "https://engine.example/api/oauth/callback" {
		t.Errorf("oauthCallbackUrl = %q", payload.OAuthCallbackURL)
	}
}

func TestConsoleMachineAuthenticationDisabledWhenTokenEmpty(t *testing.T) {
	mux := newAuthTestConsole(WithAdminToken(""))
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", "platform-machine-secret", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("machine token with feature disabled = %d, want 401", rec.Code)
	}
}

func TestConsoleHostedModeDisablesLocalLoginButKeepsMachineAuth(t *testing.T) {
	const adminToken = "platform-machine-secret"
	api := NewConsoleAPI(
		nil,
		nil,
		nil,
		"unused-hosted-password",
		"test-session-secret",
		"https://engine.example",
		"https://app.example",
		"",
		WithAdminToken(adminToken),
		WithLocalAdminAuth(false),
	)
	// A previously minted/local-looking session must not remain a second path
	// into a hosted Engine after local authentication is disabled.
	localSession := api.signToken()
	mux := http.NewServeMux()
	api.Routes(mux)

	if rec := requestStatus(mux, http.MethodPost, "/api/login", "", `{"Password":"unused-hosted-password"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("hosted /api/login = %d, want 404", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", localSession, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("hosted local session = %d, want 401", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/gateway", adminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("hosted machine token = %d, body %s", rec.Code, rec.Body)
	}

	status := requestStatus(mux, http.MethodGet, "/api/auth", "", "")
	var payload map[string]bool
	if err := json.Unmarshal(status.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode auth status: %v", err)
	}
	if payload["localLoginEnabled"] {
		t.Fatalf("hosted auth status must report local login disabled: %v", payload)
	}
}

func TestConsoleMachineAdminCanRevokeWorkspaceOAuth(t *testing.T) {
	const adminToken = "platform-machine-secret"
	revokeCalls := 0
	mux := newAuthTestConsole(
		WithAdminToken(adminToken),
		WithOAuthRevoker(func(context.Context) error {
			revokeCalls++
			return nil
		}),
	)

	if rec := requestStatus(mux, http.MethodPost, "/api/oauth/revoke-all", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("uncredentialed revoke = %d, want 401", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodGet, "/api/oauth/revoke-all", adminToken, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET revoke = %d, want 405", rec.Code)
	}
	if rec := requestStatus(mux, http.MethodPost, "/api/oauth/revoke-all", adminToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("machine revoke = %d, body %s", rec.Code, rec.Body)
	}
	if revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", revokeCalls)
	}
}

func TestConsoleOAuthRevocationFailureIsFailClosed(t *testing.T) {
	const adminToken = "platform-machine-secret"
	mux := newAuthTestConsole(
		WithAdminToken(adminToken),
		WithOAuthRevoker(func(ctx context.Context) error {
			if ctx == nil {
				t.Fatal("revoker received nil request context")
			}
			return errors.New("generation store unavailable")
		}),
	)

	rec := requestStatus(mux, http.MethodPost, "/api/oauth/revoke-all", adminToken, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed revoke = %d, want 503; body %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "generation store unavailable") {
		t.Fatalf("failed revoke leaked internal storage error: %s", rec.Body)
	}
}

func TestConsolePublicProvisioningProbes(t *testing.T) {
	mux := newAuthTestConsole()

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := requestStatus(mux, http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, body %s", path, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("GET %s Cache-Control = %q, want no-store", path, got)
		}
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("GET %s decode: %v", path, err)
		}
		if payload["ready"] != true || payload["status"] != "ok" || payload["service"] != "synaxis-engine" {
			t.Fatalf("GET %s payload = %v", path, payload)
		}
		if len(payload) != 3 {
			t.Fatalf("GET %s leaked unexpected fields: %v", path, payload)
		}
	}

	head := requestStatus(mux, http.MethodHead, "/readyz", "", "")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD /readyz = %d with body %q", head.Code, head.Body.String())
	}
	post := requestStatus(mux, http.MethodPost, "/readyz", "", "")
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST /readyz = %d Allow=%q", post.Code, post.Header().Get("Allow"))
	}

	// Detailed upstream/account health remains private.
	if rec := requestStatus(mux, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/health without auth = %d, want 401", rec.Code)
	}
}
