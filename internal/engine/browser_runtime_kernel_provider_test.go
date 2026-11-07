package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type routedPrimaryBrowserFake struct {
	*runtimeBrowserFake
	stops int
}

func (p *routedPrimaryBrowserFake) Stop(context.Context, string) (bool, error) {
	p.stops++
	return true, nil
}

type routedManagedBrowserFake struct {
	managedBrowserFake
	configuration string
	stops         int
}

func (p *routedManagedBrowserFake) ConfigurationID() string { return p.configuration }
func (p *routedManagedBrowserFake) Stop(context.Context, string) (bool, error) {
	p.stops++
	return true, nil
}

func TestKernelRuntimeRoutesGrantedProfilesThroughTheirProvider(t *testing.T) {
	store := newLibraryFileStore(t)
	f := newBrowserRuntimeFixture(t, store)
	primary := &routedPrimaryBrowserFake{runtimeBrowserFake: f.p}
	managed := &routedManagedBrowserFake{configuration: "kernel-test-project"}
	service := f.c.browserSignIn
	service.provider, service.managedProvider = primary, managed
	f.grant("read")
	if _, code := f.call("primary-open", BrowserAction{Operation: "open"}); code != 200 {
		t.Fatalf("primary open: %d", code)
	}
	if out, code := f.call("primary-snapshot", BrowserAction{Operation: "snapshot"}); code != 200 || out.Snapshot == nil {
		t.Fatalf("primary snapshot: %d", code)
	}
	primaryAccount := f.account
	account, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{
		ConnectionID: f.parent.Name, OwnerSubject: "usr_alice", DisplayName: "Managed login",
		Browser: &BrowserProfile{Provider: managed.Kind(), ConfigurationID: managed.ConfigurationID(), FlowID: "managed-flow", ProfileID: "managed-profile", WebsiteURL: "https://www.linkedin.com/feed"},
	}, accountPolicyPrecondition(f.parent))
	if err != nil {
		t.Fatal(err)
	}
	f.account = account
	f.grant("read")
	if _, code := f.call("managed-open", BrowserAction{Operation: "open"}); code != 200 {
		t.Fatalf("managed open: %d", code)
	}
	if out, code := f.call("managed-snapshot", BrowserAction{Operation: "snapshot"}); code != 200 || out.Snapshot == nil {
		t.Fatalf("managed snapshot: %d", code)
	}
	if len(primary.calls) != 2 || len(managed.calls) != 2 {
		t.Fatal("profile dispatched through wrong provider", primary.calls, managed.calls)
	}
	service.managedProvider = nil
	if _, code := f.call("provider-removed", BrowserAction{Operation: "snapshot"}); code != 409 {
		t.Fatal("removed provider fell back to primary", code)
	}
	service.managedProvider = managed
	managed.configuration = "replacement-project"
	if _, code := f.call("provider-replaced", BrowserAction{Operation: "snapshot"}); code != 409 {
		t.Fatal("replacement provider accepted old profile", code)
	}
	if len(primary.calls) != 2 || len(managed.calls) != 2 {
		t.Fatal("unavailable profile dispatched a browser action")
	}
	managed.configuration = "kernel-test-project"
	f.account = primaryAccount
	if out, code := f.call("primary-still-available", BrowserAction{Operation: "snapshot"}); code != 200 || out.Snapshot == nil {
		t.Fatal("managed configuration broke primary browser", code)
	}
	if response := f.request(BrowserControlRequest{Operation: "close-execution"}); response.Code != 200 {
		t.Fatal("execution cleanup failed", response.Code)
	}
	if primary.stops != 1 || managed.stops != 1 {
		t.Fatal("teardown routed to wrong provider", primary.stops, managed.stops)
	}
	runs, err := store.BrowserRuns(t.Context())
	if err != nil || len(runs) != 2 {
		t.Fatal("missing durable runs", err)
	}
	for _, run := range runs {
		if run.State != "closed" || run.ConnectURL != "" {
			t.Fatal("provider session retained after teardown")
		}
	}
}

func TestKernelRuntimePreservesBrowserBoundary(t *testing.T) {
	p := kernelTestProvider(t)
	var allocatedName string
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.onkernel.com" {
			t.Fatal("runtime left fixed provider")
		}
		switch r.Method {
		case http.MethodPost:
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("invalid creation")
			}
			allocatedName = body["name"].(string)
			profile := body["profile"].(map[string]any)
			if profile["name"] != "synaxis-flow" || profile["save_changes"] != false || body["timeout_seconds"] != float64(600) || body["headless"] != true || body["stealth"] != false || body["telemetry"].(map[string]any)["enabled"] != false {
				t.Fatal("runtime session policy changed")
			}
			policy := body["chrome_policy"].(map[string]any)
			if policy["URLBlocklist"].([]any)[0] != "*" || policy["URLAllowlist"].([]any)[0] != "https://.accounts.example.com:443" {
				t.Fatal("navigation restriction missing")
			}
			if len(body["network"].(map[string]any)["private_hosts"].([]any)) != 0 {
				t.Fatal("private routes not disabled")
			}
			result := map[string]any{"session_id": "bs_1", "name": allocatedName, "profile": map[string]string{"id": "prof_1", "name": "synaxis-flow"}, "profile_save_changes": false, "cdp_ws_url": "wss://proxy.us-east.onkernel.com:8443/browser/cdp?jwt=private-transport", "chrome_policy": policy}
			raw, _ := json.Marshal(result)
			return oauthJSON(string(raw)), nil
		case http.MethodDelete:
			if r.URL.Path != "/browsers/"+allocatedName {
				t.Fatal("session not stopped by durable name")
			}
			return oauthJSON(`{}`), nil
		default:
			t.Fatal("unexpected runtime operation")
			return nil, errBrowserSignIn
		}
	})
	profile := BrowserProfile{Provider: "kernel", ConfigurationID: p.ConfigurationID(), FlowID: "flow", ProfileID: "synaxis-flow", WebsiteURL: "https://accounts.example.com/login"}
	session, connect, err := p.CreateRuntimeSession(t.Context(), profile)
	if err != nil || session != allocatedName || !kernelBrowserURL(connect, "wss") {
		t.Fatal("runtime session missing", err)
	}
	if stopped, err := p.Stop(t.Context(), session); err != nil || !stopped {
		t.Fatal("runtime session not stopped", err)
	}
	profile.ConfigurationID = "different"
	if _, _, err = p.CreateRuntimeSession(t.Context(), profile); err == nil {
		t.Fatal("different provider scope accepted")
	}
}

func TestKernelRuntimeUncertainResponseCanBeClosed(t *testing.T) {
	p := kernelTestProvider(t)
	var allocatedName string
	for _, outcome := range []string{"lost", "policy_missing", "profile_mismatch", "external_transport"} {
		t.Run(outcome, func(t *testing.T) {
			p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodDelete {
					if r.URL.Path != "/browsers/"+allocatedName {
						t.Fatal("uncertain browser cannot be closed")
					}
					return oauthJSON(`{}`), nil
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Fatal("invalid request")
				}
				allocatedName = body["name"].(string)
				if outcome == "lost" {
					return nil, errors.New("lost response")
				}
				response := map[string]any{"session_id": "bs_1", "name": allocatedName, "profile": map[string]string{"id": "prof_1", "name": "synaxis-flow"}, "profile_save_changes": false, "cdp_ws_url": "wss://api.onkernel.com/browser/cdp", "chrome_policy": body["chrome_policy"]}
				switch outcome {
				case "policy_missing":
					delete(response, "chrome_policy")
				case "profile_mismatch":
					response["profile"] = map[string]string{"name": "synaxis-another"}
				case "external_transport":
					response["cdp_ws_url"] = "wss://evil.example/cdp"
				}
				raw, _ := json.Marshal(response)
				return oauthJSON(string(raw)), nil
			})
			profile := BrowserProfile{Provider: "kernel", ConfigurationID: p.ConfigurationID(), FlowID: "flow", ProfileID: "synaxis-flow", WebsiteURL: "https://accounts.example.com/login"}
			preallocated := p.SessionReference("run_" + outcome)
			session, connect, err := p.CreateNamedRuntimeSession(t.Context(), profile, preallocated)
			if err == nil || session != preallocated || allocatedName != preallocated || connect != "" {
				t.Fatal("uncertain allocation lost cleanup reference", err)
			}
			if stopped, err := p.Stop(t.Context(), session); err != nil || !stopped {
				t.Fatal("uncertain allocation not closed", err)
			}
		})
	}
}

func TestKernelTransportURLsRejectUntrustedHosts(t *testing.T) {
	for _, value := range []string{"wss://api.onkernel.com/browser/cdp?jwt=x", "wss://proxy.us-east.onkernel.com:8443/browser/cdp?jwt=x", "wss://proxy.region.kernel.sh:8443/browser/cdp?jwt=x"} {
		if !kernelBrowserURL(value, "wss") {
			t.Fatal("provider transport rejected", value)
		}
	}
	for _, value := range []string{"ws://api.onkernel.com/cdp", "wss://api.onkernel.com.evil.example/cdp", "wss://evil-onkernel.com/cdp", "wss://user:secret@api.onkernel.com/cdp", "wss://api.onkernel.com:9000/cdp", "wss://api.onkernel.com/cdp#secret"} {
		if kernelBrowserURL(value, "wss") {
			t.Fatal("unsafe transport allowed", value)
		}
	}
	p := kernelTestProvider(t)
	for _, viewer := range []string{"https://evil.example/", "https://api.onkernel.com/?key=kernel-private-key", "https://api.onkernel.com:9000/browser/live"} {
		p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
			return oauthJSON(`{"session_id":"bs_1","browser_live_view_url":"` + viewer + `"}`), nil
		})
		if _, err := p.View(t.Context(), "bs_1"); err == nil {
			t.Fatal("unsafe viewer exposed")
		}
	}
	p.client.Transport = linkedOAuthTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid action reached provider")
		return nil, errBrowserSignIn
	})
	if _, err := p.BrowserAction(t.Context(), "wss://evil.example/cdp", "https://accounts.example.com", BrowserAction{Operation: "snapshot"}); err == nil {
		t.Fatal("untrusted CDP accepted")
	}
	if _, err := p.BrowserAction(t.Context(), "wss://api.onkernel.com/cdp", "https://accounts.example.com", BrowserAction{Operation: "navigate", URL: "https://other.example.com"}); err == nil {
		t.Fatal("cross-origin action accepted")
	}
}

func TestKernelProfileCleanupFindsOnlyItsResources(t *testing.T) {
	p := kernelTestProvider(t)
	var deleted []string
	p.client.Transport = linkedOAuthTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.URL.Path)
			response := oauthJSON(`{}`)
			if strings.HasPrefix(r.URL.Path, "/profiles/") {
				response.StatusCode = 404
			}
			return response, nil
		}
		switch r.URL.Path {
		case "/auth/connections":
			return oauthJSON(`[{"id":"ma_1","profile_name":"synaxis-flow"},{"id":"ma_other","profile_name":"synaxis-other"}]`), nil
		case "/auth/connections/ma_1":
			return oauthJSON(`{"id":"ma_1","profile_name":"synaxis-flow","browser_session_id":"bs_login"}`), nil
		case "/browsers":
			return oauthJSON(`[{"session_id":"bs_1","profile":{"name":"synaxis-flow"}},{"session_id":"bs_other","profile":{"name":"synaxis-other"}}]`), nil
		default:
			t.Fatal("unexpected cleanup read", r.URL.Path)
			return nil, errBrowserSignIn
		}
	})
	if err := p.DeleteProfile(t.Context(), "synaxis-flow"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(deleted, ",")
	if strings.Contains(joined, "other") || !strings.Contains(joined, "/browsers/bs_login") || !strings.Contains(joined, "/browsers/bs_1") || !strings.Contains(joined, "/auth/connections/ma_1") || !strings.HasSuffix(joined, "/profiles/synaxis-flow") {
		t.Fatal("cleanup crossed ownership or lost resources", joined)
	}
}
