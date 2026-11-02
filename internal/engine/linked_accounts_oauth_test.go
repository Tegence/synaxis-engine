package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type linkedOAuthTestStore interface {
	linkedAccountTestStore
	LinkedOAuthFlowStore
}

func TestFileLinkedOAuthStore(t *testing.T) { testLinkedOAuthStore(t, newLibraryFileStore(t)) }
func TestPgLinkedOAuthStore(t *testing.T)   { testLinkedOAuthStore(t, newPgConnectionsStore(t)) }
func testLinkedOAuthStore(t *testing.T, store linkedOAuthTestStore) {
	parent := linkedAccountFixture(t, store)
	flow := LinkedOAuthFlow{StateHash: oauthLinkHash(newEpoch()), ProofHash: oauthLinkHash("browser-proof"), Subject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), Provider: "linkedin", DisplayName: "Private pending label", ExpiresAt: time.Now().Add(linkedOAuthLifetime)}
	if err := store.PutLinkedOAuthFlow(t.Context(), flow); err != nil {
		t.Fatal(err)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			_, _ = pg.pool.Exec(context.Background(), `DELETE FROM narthex_linked_oauth_flows WHERE state_hash=$1`, flow.StateHash)
		})
		var raw string
		if err := pg.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_linked_oauth_flows WHERE state_hash=$1`, flow.StateHash).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, flow.DisplayName) {
			t.Fatal("pending OAuth payload is not encrypted")
		}
	}
	for _, values := range [][3]string{{"usr_bob", "linkedin", "browser-proof"}, {"usr_alice", "instagram", "browser-proof"}, {"usr_alice", "linkedin", "wrong"}} {
		if _, err := store.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, values[0], values[1], values[2]); !errors.Is(err, errLinkedOAuthState) {
			t.Fatal("unbound callback consumed state")
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := store.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, "usr_alice", "linkedin", "browser-proof")
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, errLinkedOAuthState) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("callback replay was accepted")
	}
	// Reconnect must preserve the provider identity; a pasted token must not
	// downgrade identity continuity. Disconnect erases both OAuth secrets.
	credential := LinkedOAuthCredential{Provider: "linkedin", ClientID: "app", Subject: "provider-user", ProviderName: "Private provider name", AccessToken: "oauth-access", RefreshToken: "oauth-refresh", ExpiresAt: time.Now().Add(time.Hour)}
	record, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{ConnectionID: parent.Name, OwnerSubject: "usr_alice", DisplayName: "OAuth account", OAuth: &credential}, accountPolicyPrecondition(parent))
	if err != nil {
		t.Fatal(err)
	}
	// Neither inputs nor returned credentials may alias FileStore's records.
	credential.ProviderName = "changed outside store"
	record.OAuth.AccessToken = "changed outside store"
	saved, err := store.LinkedAccounts(t.Context(), "usr_alice")
	if err != nil || len(saved) != 1 || saved[0].OAuth.ProviderName != "Private provider name" || saved[0].OAuth.AccessToken != "oauth-access" {
		t.Fatal("credential alias changed stored OAuth account")
	}
	wrong := credential
	wrong.Subject = "different-user"
	if _, err = store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, record.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{OAuth: &wrong}); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatal("identity replacement accepted")
	}
	wrong = credential
	wrong.ClientID = "different-app"
	if _, err = store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, record.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{OAuth: &wrong}); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatal("identity from a different OAuth app accepted")
	}
	pasted := "pasted"
	if _, err = store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, record.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{BearerToken: &pasted}); !errors.Is(err, ErrLinkedAccountInvalid) {
		t.Fatal("OAuth identity downgraded")
	}
	empty := ""
	disconnected, err := store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, record.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{BearerToken: &empty})
	if err != nil || disconnected.OAuth.AccessToken != "" || disconnected.OAuth.RefreshToken != "" || disconnected.OAuth.Subject != credential.Subject {
		t.Fatal("disconnect failed to clear OAuth credentials")
	}
	if _, err = store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, record.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{OAuth: &credential}); !errors.Is(err, ErrLinkedAccountRevision) {
		t.Fatal("late callback restored disconnected authorization")
	}
	restored, err := store.MutateLinkedAccount(t.Context(), parent.Name, record.ID, record.OwnerSubject, disconnected.Revision, accountPolicyPrecondition(parent), LinkedAccountMutation{OAuth: &credential})
	if err != nil || restored.ID != record.ID || linkedAccountDTO(restored, parent).AuthMode != "oauth" {
		t.Fatal("same-account reconnection failed")
	}
	if store.Token(parent.Name) != "legacy-credential" {
		t.Fatal("OAuth changed MCP credentials")
	}
	expired := restored
	expired.OAuth = cloneOAuthCredential(expired.OAuth)
	expired.OAuth.ExpiresAt = time.Now().Add(-time.Second)
	if linkedAccountDTO(expired, parent).Status != "expired" {
		t.Fatal("expired token displayed as connected")
	}
}
func TestLinkedOAuthFileRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	parent := linkedAccountFixture(t, store)
	flow := LinkedOAuthFlow{StateHash: oauthLinkHash("state"), ProofHash: oauthLinkHash("proof"), Subject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), Provider: "linkedin", ExpiresAt: time.Now().Add(linkedOAuthLifetime)}
	if err = store.PutLinkedOAuthFlow(t.Context(), flow); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, flow.Subject, flow.Provider, "proof"); err != nil {
		t.Fatal("restart lost pending OAuth flow")
	}
	store.path = filepath.Join(path, "bad", "state.json")
	if _, err = store.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, flow.Subject, flow.Provider, "proof"); err == nil {
		t.Fatal("failed state consume save ignored")
	}
	if len(store.linkedOAuthFlows) != 1 {
		t.Fatal("failed save consumed OAuth flow")
	}
}

type linkedOAuthTransport func(*http.Request) (*http.Response, error)

func (f linkedOAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func oauthJSON(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func oauthServiceFixture(t *testing.T) *LinkedAccountOAuth {
	t.Helper()
	service, err := NewLinkedAccountOAuth(`{"instagram":{"clientId":"ig-app","clientSecret":"ig-secret"},"linkedin":{"clientId":"li-app","clientSecret":"li-secret"}}`, "https://synaxis.example/app/team")
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func TestLinkedOAuthProviderExchange(t *testing.T) {
	for _, provider := range []string{"instagram", "linkedin"} {
		t.Run(provider, func(t *testing.T) {
			service := oauthServiceFixture(t)
			requests := 0
			service.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
				requests++
				switch r.URL.Host + r.URL.Path {
				case "www.linkedin.com/oauth/v2/accessToken", "api.instagram.com/oauth/access_token":
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("code") != "code" || r.Form.Get("client_secret") != service.apps[provider].ClientSecret || r.Form.Get("redirect_uri") != service.redirectURI(provider) {
						t.Fatal("token exchange was not bound to app and redirect")
					}
					if provider == "instagram" {
						return oauthJSON(`{"data":[{"access_token":"short-token","user_id":123,"permissions":"instagram_business_basic"}]}`), nil
					}
					return oauthJSON(`{"access_token":"li-token","refresh_token":"refresh","expires_in":3600,"scope":"openid profile"}`), nil
				case "graph.instagram.com/access_token":
					if r.URL.Query().Get("grant_type") != "ig_exchange_token" || r.URL.Query().Get("access_token") != "short-token" {
						t.Fatal("invalid long-lived exchange")
					}
					return oauthJSON(`{"access_token":"ig-token","expires_in":5184000}`), nil
				case "graph.instagram.com/me":
					if r.Header.Get("Authorization") != "Bearer ig-token" {
						t.Fatal("wrong identity bearer")
					}
					return oauthJSON(`{"user_id":"456","username":"company"}`), nil
				case "api.linkedin.com/v2/userinfo":
					if r.Header.Get("Authorization") != "Bearer li-token" {
						t.Fatal("wrong identity bearer")
					}
					return oauthJSON(`{"sub":"member","name":"Member Name"}`), nil
				}
				t.Fatal("unexpected provider endpoint")
				return nil, errLinkedOAuth
			})
			result, err := service.providers[provider].exchange(t.Context(), service, service.apps[provider], "code", service.redirectURI(provider))
			if err != nil || result.Provider != provider || result.Subject == "" || requests < 2 {
				t.Fatalf("exchange failed: %v", err)
			}
			if strings.Contains(service.authorizationURL(provider, "state"), "secret") {
				t.Fatal("secret in authorization URL")
			}
			service.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
				return oauthJSON(`{"data":[{"access_token":"one"},{"access_token":"two"}]}`), nil
			})
			if _, err = service.providers[provider].exchange(t.Context(), service, service.apps[provider], "code", service.redirectURI(provider)); err == nil {
				t.Fatal("invalid token answer accepted")
			}
		})
	}
}
func TestLinkedOAuthHTTPBoundaries(t *testing.T) {
	for _, prefix := range []string{"/api", "/control/v1"} {
		t.Run(prefix, func(t *testing.T) { testLinkedOAuthHTTPBoundaries(t, prefix) })
	}
}
func testLinkedOAuthHTTPBoundaries(t *testing.T, prefix string) {
	store := newLibraryFileStore(t)
	parent := linkedAccountFixture(t, store)
	service := oauthServiceFixture(t)
	networkCalls := 0
	service.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		networkCalls++
		if r.URL.Path == "/v2/userinfo" {
			return oauthJSON(`{"sub":"member","name":"Provider name"}`), nil
		}
		return oauthJSON(`{"access_token":"private-oauth-token","expires_in":3600}`), nil
	})
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, nil, nil, "", "secret", "", "", "", WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier), WithLinkedAccountOAuth(service))
	mux := http.NewServeMux()
	api.Routes(mux)
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	base := prefix + "/account-oauth/linkedin"
	startBody := map[string]any{"connectionId": parent.Name, "connectionIncarnationId": parent.IncarnationID, "connectionRevision": parent.Revision, "displayName": "Social"}
	start := func() map[string]string {
		t.Helper()
		res := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/start", encode(startBody))
		if res.Code != 200 {
			t.Fatalf("start: %d %s", res.Code, res.Body)
		}
		var out map[string]string
		_ = json.Unmarshal(res.Body.Bytes(), &out)
		u, _ := url.Parse(out["authorizationUrl"])
		if u.Query().Get("scope") != "openid profile" || u.Query().Get("redirect_uri") != "https://synaxis.example/oauth/accounts/linkedin" {
			t.Fatal("unexpected auth URL")
		}
		return out
	}
	pending := start()
	completion := map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "code": "code"}
	other := hostedNamespaceRequest(t, mux, key, now, "usr_bob", "admin", "POST", base+"/complete", encode(completion))
	if other.Code != 409 || networkCalls != 0 {
		t.Fatal("coworker completed sign-in")
	}
	deniedProof := completion["browserProof"]
	completion["browserProof"] = "wrong"
	bad := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if bad.Code != 409 || networkCalls != 0 {
		t.Fatal("unbound browser completed sign-in")
	}
	completion["browserProof"] = deniedProof
	done := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if done.Code != 200 || strings.Contains(done.Body.String(), "private-oauth-token") || !strings.Contains(done.Body.String(), `"identityStatus":"provider_confirmed"`) {
		t.Fatalf("completion: %d %s", done.Code, done.Body)
	}
	replay := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if replay.Code != 409 || networkCalls != 2 {
		t.Fatal("replay exchanged a second code")
	}
	pending = start()
	completion = map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "denied": true}
	cancelled := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if cancelled.Code != 200 || networkCalls != 2 {
		t.Fatal("denial contacted provider")
	}
	pending = start()
	completion = map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "code": "code"}
	app := service.apps["linkedin"]
	service.apps["linkedin"] = linkedOAuthApp{ClientID: app.ClientID, ClientSecret: "rotated"}
	changed := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if changed.Code != 409 || networkCalls != 2 {
		t.Fatal("changed application accepted a pending callback")
	}
	service.apps["linkedin"] = app
	pending = start()
	completion = map[string]any{"state": pending["state"], "browserProof": pending["browserProof"], "code": "late-code"}
	if err := store.Delete(t.Context(), parent.Name, parent.IncarnationID, parent.Revision); err != nil {
		t.Fatal(err)
	}
	late := hostedNamespaceRequest(t, mux, key, now, "usr_alice", "operator", "POST", base+"/complete", encode(completion))
	if late.Code != 404 || networkCalls != 2 {
		t.Fatal("deleted connection accepted callback")
	}
}

func TestLinkedOAuthExpiredStateAndCapacity(t *testing.T) {
	store := newLibraryFileStore(t)
	parent := linkedAccountFixture(t, store)
	flow := LinkedOAuthFlow{StateHash: oauthLinkHash("state"), ProofHash: oauthLinkHash("proof"), Subject: "usr_alice", ConnectionID: parent.Name, Parent: accountPolicyPrecondition(parent), Provider: "linkedin", ExpiresAt: time.Now().Add(-time.Second)}
	if err := store.PutLinkedOAuthFlow(t.Context(), flow); err == nil {
		t.Fatal("expired sign-in stored")
	}
	store.linkedOAuthFlows = []LinkedOAuthFlow{flow}
	if _, err := store.ConsumeLinkedOAuthFlow(t.Context(), flow.StateHash, flow.Subject, flow.Provider, "proof"); !errors.Is(err, errLinkedOAuthState) {
		t.Fatal("expired sign-in consumed")
	}
	flow.ExpiresAt = time.Now().Add(linkedOAuthLifetime)
	for range 32 {
		flow.StateHash = oauthLinkHash(newEpoch())
		if err := store.PutLinkedOAuthFlow(t.Context(), flow); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutLinkedOAuthFlow(t.Context(), flow); !errors.Is(err, ErrLinkedAccountLimit) {
		t.Fatal("sign-in quota not enforced")
	}
}

func TestLinkedOAuthRejectsProviderFailuresWithoutLeakingSecrets(t *testing.T) {
	service := oauthServiceFixture(t)
	for _, transport := range []linkedOAuthTransport{
		func(*http.Request) (*http.Response, error) {
			return nil, errors.New("https://provider?access_token=secret")
		},
		func(*http.Request) (*http.Response, error) {
			r := oauthJSON(`{"error":"secret"}`)
			r.StatusCode = 400
			return r, nil
		},
		func(*http.Request) (*http.Response, error) { return oauthJSON(strings.Repeat("x", 129<<10)), nil },
	} {
		service.client.Transport = transport
		if _, err := exchangeLinkedInAccount(t.Context(), service, service.apps["linkedin"], "code", service.redirectURI("linkedin")); !errors.Is(err, errLinkedOAuth) {
			t.Fatal("provider failure not sanitized")
		}
	}
	calls := 0
	service.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
		calls++
		r := oauthJSON(`{}`)
		r.StatusCode = 302
		r.Header.Set("Location", "https://attacker.example/steal")
		return r, nil
	})
	if _, err := exchangeLinkedInAccount(t.Context(), service, service.apps["linkedin"], "code", service.redirectURI("linkedin")); err == nil || calls != 1 {
		t.Fatal("token exchange followed redirect")
	}
}

func TestLinkedOAuthConfigIsExplicitAndOptional(t *testing.T) {
	for _, raw := range []string{`null`, `{"unknown":{"clientId":"app","clientSecret":"secret"}}`, `{"linkedin":{"clientId":"app","clientSecret":"secret","url":"https://attacker.example"}}`, `{"linkedin":{"clientId":"app"}}`} {
		if _, err := NewLinkedAccountOAuth(raw, "https://web.example"); err == nil {
			t.Fatal("invalid application config accepted")
		}
	}
	service, err := NewLinkedAccountOAuth("", "")
	if err != nil || len(service.metadata()) != 2 {
		t.Fatal("unconfigured OAuth broke existing Engine startup")
	}
	for _, provider := range service.metadata() {
		if provider.Available {
			t.Fatal("unconfigured provider enabled")
		}
	}
	if _, err := NewLinkedAccountOAuth(`{"linkedin":{"clientId":"app","clientSecret":"secret"}}`, "http://public.example"); err == nil {
		t.Fatal("insecure callback origin accepted")
	}
}
