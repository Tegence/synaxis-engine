package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func browserbaseTestProvider(t *testing.T) *browserbaseProvider {
	t.Helper()
	p, err := newBrowserSignInProvider(`{"provider":"browserbase","apiKey":"private-key","projectId":"project"}`)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*browserbaseProvider)
}
func TestBrowserSignInProviderConfigAndWebsite(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"provider":"e2e"}`, `{"provider":"browserbase","apiKey":"secret","projectId":"project","endpoint":"https://evil.example"}`, `{"provider":"browserbase","apiKey":"secret","projectId":"../outside"}`} {
		if _, err := newBrowserSignInProvider(raw); err == nil {
			t.Fatal("invalid provider config accepted")
		}
	}
	if p, err := newBrowserSignInProvider(""); err != nil || p != nil {
		t.Fatal("disabled provider broke startup")
	}
	for _, site := range []string{"https://www.instagram.com/", "https://www.linkedin.com/login", "https://accounts.example.com:443/sign-in"} {
		if !validBrowserWebsite(site) {
			t.Fatal("public website rejected", site)
		}
	}
	for _, site := range []string{"http://instagram.com", "https://127.0.0.1/", "https://[::1]/", "https://metadata.internal/", "https://host.local/", "https://localhost/", "https://site.example:123/", "https://me:secret@site.example/", "https://site.example/?token=secret", "https://site.example/#secret"} {
		if validBrowserWebsite(site) {
			t.Fatal("unsafe website accepted", site)
		}
	}
	p := browserbaseTestProvider(t)
	old := p.ConfigurationID()
	p.config.APIKey = "rotated"
	if p.ConfigurationID() != old {
		t.Fatal("key rotation orphaned profiles")
	}
	p.config.ProjectID = "different"
	if p.ConfigurationID() == old {
		t.Fatal("project replacement accepted old profiles")
	}
}
func TestBrowserSignInProviderRequestContract(t *testing.T) {
	p := browserbaseTestProvider(t)
	calls := []string{}
	released := false
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.browserbase.com" || r.Header.Get("X-BB-API-Key") != "private-key" {
			t.Fatal("request escaped fixed provider")
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		var body map[string]any
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/contexts":
			if body["projectId"] != "project" || body["name"] != "synaxis-flow" {
				t.Fatal("context not bound to project")
			}
			return oauthJSON(`{"id":"profile"}`), nil
		case "POST /v1/sessions":
			settings := body["browserSettings"].(map[string]any)
			for _, flag := range []string{"recordSession", "logSession", "solveCaptchas", "advancedStealth", "verified"} {
				if settings[flag] != false {
					t.Fatal("browser telemetry or automation enabled", flag)
				}
			}
			binding := settings["context"].(map[string]any)
			if binding["id"] != "profile" || binding["persist"] != true || body["timeout"] != float64(600) || body["keepAlive"] != true || body["proxies"] != false {
				t.Fatal("invalid session policy")
			}
			return oauthJSON(`{"id":"session","projectId":"project","contextId":"profile","connectUrl":"wss://connect.browserbase.com/?apiKey=private-key"}`), nil
		case "GET /v1/sessions/session/debug":
			return oauthJSON(`{"debuggerFullscreenUrl":"https://www.browserbase.com/viewer/session"}`), nil
		case "GET /v1/sessions/session":
			if released {
				return oauthJSON(`{"projectId":"project","status":"COMPLETED"}`), nil
			}
			return oauthJSON(`{"projectId":"project","status":"RUNNING"}`), nil
		case "POST /v1/sessions/session":
			if body["projectId"] != "project" || body["status"] != "REQUEST_RELEASE" {
				t.Fatal("invalid release")
			}
			released = true
			return oauthJSON(`{}`), nil
		case "GET /v1/contexts/profile":
			return oauthJSON(`{"id":"profile","projectId":"project"}`), nil
		case "DELETE /v1/contexts/profile":
			response := oauthJSON(`{}`)
			response.StatusCode = 404
			return response, nil
		default:
			t.Fatal("unexpected provider request", r.Method, r.URL.Path)
			return nil, errBrowserSignIn
		}
	})
	ctx := t.Context()
	if _, err := p.CreateProfile(ctx, "flow"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.CreateSession(ctx, "profile"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.View(ctx, "session"); err != nil {
		t.Fatal(err)
	}
	if stopped, err := p.Stop(ctx, "session"); err != nil || stopped {
		t.Fatal("release did not wait for terminal status")
	}
	if stopped, err := p.Stop(ctx, "session"); err != nil || !stopped {
		t.Fatal("completed browser not recognized")
	}
	if err := p.ProfileReady(ctx, "profile"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteProfile(ctx, "profile"); err != nil {
		t.Fatal("idempotent delete failed")
	}
	if len(calls) != 8 {
		t.Fatal("unexpected request count", calls)
	}
}
func TestBrowserSignInProviderRejectsLeaksAndRedirects(t *testing.T) {
	p := browserbaseTestProvider(t)
	for _, body := range []string{`{"debuggerFullscreenUrl":"https://evil.example/view"}`, `{"debuggerFullscreenUrl":"https://browserbase.com.evil.example/view"}`, `{"debuggerFullscreenUrl":"https://www.browserbase.com/view?key=private-key"}`, strings.Repeat("x", 257<<10)} {
		p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) { return oauthJSON(body), nil })
		if _, err := p.View(t.Context(), "session"); !errors.Is(err, errBrowserSignIn) {
			t.Fatal("unsafe viewer exposed")
		}
	}
	calls := 0
	p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
		calls++
		r := oauthJSON(`{"error":"secret"}`)
		r.StatusCode = 302
		r.Header.Set("Location", "https://evil.example")
		return r, nil
	})
	if _, err := p.CreateProfile(t.Context(), "flow"); !errors.Is(err, errBrowserSignIn) || calls != 1 {
		t.Fatal("provider redirect followed")
	}
	p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("private-key") })
	if _, err := p.View(t.Context(), "session"); err == nil || strings.Contains(err.Error(), "private-key") {
		t.Fatal("provider error leaked credentials")
	}
}
func TestBrowserSignInCDPNavigationWaitsForActivation(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "activation rejected"}[reject], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer c.CloseNow()
				for {
					var request struct {
						ID      int            `json:"id"`
						Method  string         `json:"method"`
						Session string         `json:"sessionId"`
						Params  map[string]any `json:"params"`
					}
					if err = wsjson.Read(r.Context(), c, &request); err != nil {
						return
					}
					result := map[string]any{}
					switch request.Method {
					case "Target.getTargets":
						result["targetInfos"] = []map[string]string{{"targetId": "initial-tab", "type": "page"}}
					case "Target.attachToTarget":
						if request.Params["targetId"] != "initial-tab" || request.Params["flatten"] != true {
							t.Error("did not attach initial page")
						}
						result["sessionId"] = "attached"
					case "Page.navigate":
						if request.Params["url"] != "https://www.instagram.com/" || request.Session != "attached" {
							t.Error("wrong navigation")
						}
						result["frameId"] = "frame"
					case "Target.activateTarget":
						if request.Params["targetId"] != "initial-tab" {
							t.Error("wrong activation")
						}
					default:
						t.Error("unexpected CDP command", request.Method)
						return
					}
					response := map[string]any{"id": request.ID, "result": result}
					if request.Method == "Target.activateTarget" && reject {
						response["error"] = map[string]int{"code": -1}
					}
					if wsjson.Write(r.Context(), c, response) != nil {
						return
					}
				}
			}))
			defer server.Close()
			p := browserbaseTestProvider(t)
			client := server.Client()
			transport := client.Transport
			// Test-only routing keeps the production host validator exercised.
			client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
				r.URL.Host = strings.TrimPrefix(server.URL, "https://")
				return transport.RoundTrip(r)
			})
			p.client = client
			err := p.Navigate(context.Background(), "wss://connect.browserbase.com/", "https://www.instagram.com/")
			if (err != nil) != reject {
				t.Fatal("activation acknowledgement not respected", err)
			}
		})
	}
}

func TestBrowserSignInStopRejectsUnknownSessionState(t *testing.T) {
	p := browserbaseTestProvider(t)
	for _, body := range []string{`{}`, `{"projectId":"project","status":"UNKNOWN"}`, `{"projectId":"different","status":"COMPLETED"}`} {
		p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) { return oauthJSON(body), nil })
		if stopped, err := p.Stop(t.Context(), "session"); stopped || err == nil {
			t.Fatal("unconfirmed stop accepted", body)
		}
	}
	p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) { r := oauthJSON(`{}`); r.StatusCode = 404; return r, nil })
	if stopped, err := p.Stop(t.Context(), "session"); !stopped || err != nil {
		t.Fatal("deleted session not terminal")
	}
}
