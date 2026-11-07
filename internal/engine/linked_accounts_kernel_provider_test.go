package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func kernelTestProvider(t *testing.T) *kernelProvider {
	t.Helper()
	p, err := newManagedBrowserSignInProvider(`{"provider":"kernel","apiKey":"kernel-private-key","projectId":"private-project"}`)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*kernelProvider)
}

func TestKernelProviderConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"provider":"kernel","apiKey":"secret","projectId":"project","endpoint":"https://evil.example"}`,
		`{"provider":"kernel","apiKey":"secret","projectId":"project","managedAuth":{"provider":"kernel","apiKey":"secret","projectId":"project"}}`,
		`{"provider":"browserbase","apiKey":"secret","projectId":"project","managedAuth":{"provider":"other","apiKey":"secret","projectId":"project"}}`,
		`{"provider":"browserbase","apiKey":"secret","projectId":"project","managedAuth":{"provider":"kernel","apiKey":"secret","projectId":"../project"}}`,
	} {
		if _, err := newBrowserSignInProvider(raw); err == nil {
			t.Fatal("invalid provider configuration accepted")
		}
		if _, err := newManagedBrowserSignInProvider(raw); err == nil {
			t.Fatal("invalid managed provider configuration accepted")
		}
	}
	raw := `{"provider":"browserbase","apiKey":"bb-key","projectId":"bb-project","managedAuth":{"provider":"kernel","apiKey":"kernel-key","projectId":"kernel-project"}}`
	base, err := newBrowserSignInProvider(raw)
	if err != nil || base.Kind() != "browserbase" {
		t.Fatal("existing provider replaced", err)
	}
	managed, err := newManagedBrowserSignInProvider(raw)
	if err != nil || managed.Kind() != "kernel" {
		t.Fatal("managed provider missing", err)
	}
	if p, err := newManagedBrowserSignInProvider(""); err != nil || p != nil {
		t.Fatal("empty configuration not disabled")
	}
	if p, err := newManagedBrowserSignInProvider(`{"provider":"browserbase","apiKey":"key","projectId":"project"}`); err != nil || p != nil {
		t.Fatal("manual provider gained managed capability")
	}
	p := kernelTestProvider(t)
	identity := p.ConfigurationID()
	p.config.APIKey = "rotated"
	if p.ConfigurationID() != identity {
		t.Fatal("key rotation changed profile ownership")
	}
	p.config.ProjectID = "replacement"
	if p.ConfigurationID() == identity {
		t.Fatal("project replacement retained profile ownership")
	}
}

func TestKernelManagedLoginContract(t *testing.T) {
	p := kernelTestProvider(t)
	phase := "password"
	deleted := false
	var submission map[string]any
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.onkernel.com" || r.Header.Get("Authorization") != "Bearer kernel-private-key" {
			t.Fatal("request escaped fixed provider")
		}
		var body map[string]any
		if r.Body != nil && json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid provider request")
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /profiles":
			if body["name"] != "synaxis-flow" {
				t.Fatal("profile not bound to sign-in")
			}
			return oauthJSON(`{"id":"prof_1","name":"synaxis-flow"}`), nil
		case "GET /profiles/synaxis-flow":
			return oauthJSON(`{"id":"prof_1","name":"synaxis-flow"}`), nil
		case "POST /auth/connections":
			for _, flag := range []string{"save_credentials", "health_checks", "auto_reauth", "record_session"} {
				if body[flag] != false {
					t.Fatal("unexpected credential retention or background login", flag)
				}
			}
			browser := body["browser"].(map[string]any)
			if browser["stealth"] != false || browser["telemetry"].(map[string]any)["enabled"] != false {
				t.Fatal("unexpected browser capture or automation")
			}
			if body["domain"] != "accounts.example.com" || body["profile_name"] != "synaxis-flow" || body["login_url"] != "https://accounts.example.com/login" || body["allowed_domains"].([]any)[0] != "accounts.example.com" {
				t.Fatal("login scope changed")
			}
			return oauthJSON(`{"id":"ma_1","domain":"accounts.example.com","profile_name":"synaxis-flow"}`), nil
		case "POST /auth/connections/ma_1/login":
			if body["record_session"] != false || body["skill_mode"] != "disabled" {
				t.Fatal("login recording or learned skills enabled")
			}
			return oauthJSON(`{"id":"ma_1","hosted_url":"https://auth.kernel.com/private-login-token","handoff_code":"secret"}`), nil
		case "GET /auth/connections/ma_1":
			if deleted {
				response := oauthJSON(`{}`)
				response.StatusCode = 404
				return response, nil
			}
			if phase == "password" {
				return oauthJSON(`{"id":"ma_1","profile_name":"synaxis-flow","flow_status":"IN_PROGRESS","flow_step":"AWAITING_INPUT","interaction_id":"mai:password","browser_session_id":"bs_1","fields":[{"id":"email-field","type":"identifier","input_mode":"email","label":"Email","value":"do-not-return-me"},{"id":"password-field","type":"password","label":"Password","value":"private-password"}],"error_message":"never-return-this","live_view_url":"https://live.onkernel.com/private-token"}`), nil
			}
			if phase == "otp" {
				return oauthJSON(`{"id":"ma_1","profile_name":"synaxis-flow","flow_status":"IN_PROGRESS","flow_step":"AWAITING_INPUT","interaction_id":"mai:otp","fields":[{"id":"otp","type":"totp_code","label":"Authenticator code"}]}`), nil
			}
			return oauthJSON(`{"id":"ma_1","profile_name":"synaxis-flow","status":"AUTHENTICATED","flow_status":"SUCCESS","browser_session_id":"bs_1"}`), nil
		case "POST /auth/connections/ma_1/submit":
			submission = body
			return oauthJSON(`{"accepted":true}`), nil
		case "DELETE /auth/connections/ma_1":
			deleted = true
			return oauthJSON(`{}`), nil
		case "DELETE /browsers/bs_1":
			return oauthJSON(`{}`), nil
		case "GET /auth/connections":
			if r.URL.Query().Get("profile_name") != "synaxis-flow" {
				t.Fatal("cleanup not scoped to profile")
			}
			return oauthJSON(`[]`), nil
		case "GET /browsers":
			if r.URL.Query().Get("query") != "synaxis-flow" || r.URL.Query().Get("status") != "active" {
				t.Fatal("cleanup not scoped to active profile browsers")
			}
			return oauthJSON(`[]`), nil
		case "DELETE /profiles/synaxis-flow":
			return oauthJSON(`{}`), nil
		default:
			t.Fatal("unexpected provider operation", r.Method, r.URL.Path)
			return nil, errBrowserSignIn
		}
	})
	profile, err := p.CreateProfile(t.Context(), "flow")
	if err != nil || profile != "synaxis-flow" {
		t.Fatal("profile reference unavailable", err)
	}
	connection, err := p.CreateLogin(t.Context(), profile, "https://accounts.example.com/login")
	if err != nil || connection != "ma_1" {
		t.Fatal("login unavailable", err)
	}
	if err = p.BeginLogin(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	status, err := p.LoginStatus(t.Context(), connection)
	if err != nil || status.State != "input" || len(status.Fields) != 2 || status.Fields[0].Type != "email" || status.Fields[1].Type != "password" || !status.Fields[1].Required {
		t.Fatal("canonical login fields missing", status, err)
	}
	raw, _ := json.Marshal(status)
	for _, secret := range []string{"do-not-return-me", "private-password", "never-return-this", "private-token", "bs_1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private provider data exposed in status")
		}
	}
	if err = p.SubmitLogin(t.Context(), connection, status.InteractionID, map[string]string{"email-field": "person@example.com", "password-field": "private-password"}, ""); err != nil {
		t.Fatal(err)
	}
	if submission["interaction_id"] != "mai:password" || submission["field_values"].(map[string]any)["password-field"] != "private-password" || len(submission) != 2 {
		t.Fatal("credentials not submitted in canonical fields")
	}
	phase = "otp"
	status, err = p.LoginStatus(t.Context(), connection)
	if err != nil || len(status.Fields) != 1 || status.Fields[0].Type != "otp" || status.InteractionID != "mai:otp" {
		t.Fatal("MFA interaction lost", status, err)
	}
	if err = p.SubmitLogin(t.Context(), connection, status.InteractionID, map[string]string{"otp": "123456"}, ""); err != nil {
		t.Fatal(err)
	}
	phase = "done"
	status, err = p.LoginStatus(t.Context(), connection)
	if err != nil || status.State != "succeeded" {
		t.Fatal("successful authentication lost", status, err)
	}
	if err = p.DeleteLogin(t.Context(), connection); err != nil {
		t.Fatal("login browser cleanup failed", err)
	}
	if err = p.DeleteLogin(t.Context(), connection); err != nil {
		t.Fatal("login deletion is not idempotent", err)
	}
	if err = p.ProfileReady(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
	if err = p.DeleteProfile(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
}

func TestKernelLoginStatusRejectsAmbiguity(t *testing.T) {
	p := kernelTestProvider(t)
	for _, body := range []string{
		`{"id":"different","flow_status":"SUCCESS","status":"AUTHENTICATED"}`,
		`{"id":"ma_1","flow_status":"SUCCESS","status":"NEEDS_AUTH"}`,
		`{"id":"ma_1","flow_status":"IN_PROGRESS","flow_step":"AWAITING_INPUT","interaction_id":"i","fields":[{"id":"f","type":"unknown"}]}`,
		`{"id":"ma_1","flow_status":"IN_PROGRESS","flow_step":"AWAITING_INPUT","fields":[{"id":"f","type":"password"}]}`,
		`{"id":"ma_1","flow_status":"IN_PROGRESS","flow_step":"AWAITING_INPUT","interaction_id":"i","fields":[{"id":"f","type":"password"},{"id":"f","type":"text"}]}`,
		`{"id":"ma_1","flow_status":"IN_PROGRESS","flow_step":"UNKNOWN"}`,
		strings.Repeat("x", 257<<10),
	} {
		p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) { return oauthJSON(body), nil })
		if _, err := p.LoginStatus(t.Context(), "ma_1"); err == nil {
			t.Fatal("ambiguous provider status accepted")
		}
	}
	for _, step := range []string{"AWAITING_EXTERNAL_ACTION", "AWAITING_HUMAN_INTERVENTION"} {
		p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
			return oauthJSON(`{"id":"ma_1","flow_status":"IN_PROGRESS","flow_step":"` + step + `","external_action_message":"private-password","error_message":"private-password"}`), nil
		})
		status, err := p.LoginStatus(t.Context(), "ma_1")
		if err != nil || status.State != "external" || strings.Contains(status.Message, "private-password") {
			t.Fatal("unsafe external status", status, err)
		}
	}
}

func TestKernelUnknownAllocationsRetainCleanupReferences(t *testing.T) {
	p := kernelTestProvider(t)
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "POST /profiles", "POST /auth/connections":
			return nil, errors.New("response lost private-password")
		case "GET /auth/connections":
			return oauthJSON(`[{"id":"ma_recovered","profile_name":"synaxis-flow","domain":"accounts.example.com"}]`), nil
		default:
			t.Fatal("unexpected request", r.URL.Path)
			return nil, errBrowserSignIn
		}
	})
	profile, err := p.CreateProfile(t.Context(), "flow")
	if profile != "synaxis-flow" || !errors.Is(err, errBrowserSignIn) {
		t.Fatal("uncertain profile lost cleanup reference")
	}
	connection, err := p.CreateLogin(t.Context(), profile, "https://accounts.example.com/login")
	if connection != "ma_recovered" || err != nil {
		t.Fatal("uncertain connection not recovered", err)
	}
}

func TestKernelProviderNeverFollowsRedirectOrRetriesSubmission(t *testing.T) {
	p := kernelTestProvider(t)
	calls := 0
	p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
		calls++
		response := oauthJSON(`{"message":"private-password"}`)
		response.StatusCode = http.StatusTemporaryRedirect
		response.Header.Set("Location", "https://evil.example/credentials")
		return response, nil
	})
	err := p.SubmitLogin(t.Context(), "ma_1", "i", map[string]string{"password": "private-password"}, "")
	if calls != 1 || !errors.Is(err, errBrowserSignIn) || strings.Contains(err.Error(), "private-password") {
		t.Fatal("credential submission retried or provider error exposed")
	}
	if err = p.SubmitLogin(t.Context(), "ma_1", "i", map[string]string{"password": "private-password"}, "choice"); err == nil || calls != 1 {
		t.Fatal("mixed canonical submission accepted")
	}
}
