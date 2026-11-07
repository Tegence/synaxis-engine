package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestBrowserRuntimeProviderSessionPolicy(t *testing.T) {
	p := browserbaseTestProvider(t)
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Timeout  int `json:"timeout"`
			Settings struct {
				Context struct {
					ID      string `json:"id"`
					Persist bool   `json:"persist"`
				} `json:"context"`
				Domains []string `json:"allowedDomains"`
				Record  bool     `json:"recordSession"`
				Log     bool     `json:"logSession"`
				Captcha bool     `json:"solveCaptchas"`
			} `json:"browserSettings"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Timeout != 600 || body.Settings.Context.ID != "profile" || body.Settings.Context.Persist || body.Settings.Record || body.Settings.Log || body.Settings.Captcha || len(body.Settings.Domains) != 1 || body.Settings.Domains[0] != "www.linkedin.com" {
			t.Error("unsafe runtime session policy")
		}
		return oauthJSON(`{"id":"session","projectId":"project","contextId":"profile","connectUrl":"wss://connect.browserbase.com/private"}`), nil
	})
	_, _, err := p.CreateRuntimeSession(t.Context(), BrowserProfile{Provider: p.Kind(), ConfigurationID: p.ConfigurationID(), FlowID: "flow", ProfileID: "profile", WebsiteURL: "https://www.linkedin.com/feed"})
	if err != nil {
		t.Fatal(err)
	}
}
func TestBrowserRuntimeProviderRefusesStaleElementAndForeignPage(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "foreign"}[foreign], func(t *testing.T) {
			evaluations := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer c.CloseNow()
				for {
					var req struct {
						ID     int            `json:"id"`
						Method string         `json:"method"`
						Params map[string]any `json:"params"`
					}
					if wsjson.Read(r.Context(), c, &req) != nil {
						return
					}
					out := map[string]any{}
					switch req.Method {
					case "Target.getTargets":
						out["targetInfos"] = []map[string]string{{"targetId": "page", "type": "page"}}
					case "Target.attachToTarget":
						out["sessionId"] = "session"
					case "Page.getFrameTree":
						site := "https://www.linkedin.com/feed"
						if foreign {
							site = "https://evil.example/"
						}
						out["frameTree"] = map[string]any{"frame": map[string]string{"id": "frame", "url": site}}
					case "Page.createIsolatedWorld":
						if req.Params["worldName"] != "synaxis-browser-runtime" {
							t.Error("page world used")
						}
						out["executionContextId"] = 1
					case "Runtime.evaluate":
						evaluations++
						expression, _ := req.Params["expression"].(string)
						if !strings.Contains(expression, "e.isConnected") || !strings.Contains(expression, "e.outerHTML!==") || !strings.Contains(expression, "s.id!==a.snapshot") {
							t.Error("missing stale element check")
						}
						out["result"] = map[string]any{"value": false}
					default:
						t.Error("unexpected dispatch", req.Method)
						return
					}
					if wsjson.Write(r.Context(), c, map[string]any{"id": req.ID, "result": out}) != nil {
						return
					}
				}
			}))
			defer srv.Close()
			p := browserbaseTestProvider(t)
			client := srv.Client()
			transport := client.Transport
			client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
				r.URL.Host = strings.TrimPrefix(srv.URL, "https://")
				return transport.RoundTrip(r)
			})
			p.client = client
			_, err := p.BrowserAction(t.Context(), "wss://connect.browserbase.com/", "https://www.linkedin.com/feed", BrowserAction{Operation: "type", Snapshot: "snapshot", Element: 1, Text: "draft"})
			if err == nil || foreign && evaluations != 0 {
				t.Fatal("unsafe page/element accepted")
			}
		})
	}
}
func TestPgBrowserRuntimeEncryptedAndMigrated(t *testing.T) {
	store := newPgConnectionsStore(t)
	f := newBrowserRuntimeFixture(t, store)
	f.grant("read")
	f.call("open", BrowserAction{Operation: "open"})
	f.call("snapshot", BrowserAction{Operation: "snapshot"})
	id := browserRunID(f.execution, f.account.ID)
	var raw string
	if err := store.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_browser_runs WHERE id=$1`, id).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, "private-runtime") {
		t.Fatal("runtime not encrypted", err)
	}
	run, _, _ := f.c.browserSignIn.browserRun(t.Context(), id)
	plain, _ := json.Marshal(run)
	if _, err := store.pool.Exec(t.Context(), `UPDATE narthex_browser_runs SET payload=$2 WHERE id=$1`, id, string(plain)); err != nil {
		t.Fatal(err)
	}
	if err := store.encryptExistingLinkedAccounts(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT payload FROM narthex_browser_runs WHERE id=$1`, id).Scan(&raw); err != nil || !strings.HasPrefix(raw, encPrefix) {
		t.Fatal("runtime migration", err)
	}
}
