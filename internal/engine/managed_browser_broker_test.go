package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostedBrowserEndpointUsesSameOriginAndWorkspace(t *testing.T) {
	const expected = "https://synaxis.example/v1/internal/managed-browser/wsp_demo"
	got, err := managedBrowserEndpoint("https://synaxis.example/v1/internal/engine-events/wsp_demo", "wsp_demo")
	if err != nil || got != expected {
		t.Fatalf("broker endpoint: %s, %v", got, err)
	}
	for _, value := range []string{
		"http://synaxis.example/v1/internal/engine-events/wsp_demo",
		"https://synaxis.example/v1/internal/engine-events/wsp_other",
		"https://synaxis.example/v1/internal/engine-events/wsp_demo?unexpected=1",
		"https://operator@synaxis.example/v1/internal/engine-events/wsp_demo",
		"https://synaxis.example/v1/internal/engine-events/wsp_demo/extra",
	} {
		if _, err := managedBrowserEndpoint(value, "wsp_demo"); err == nil {
			t.Errorf("accepted unbound event endpoint: %s", value)
		}
	}
}

func TestHostedBrowserHeadersRequireVerifiedPlatformActor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/control/v1/connections/model", nil)
	r.Header.Set(managedBrowserReadyHeader, "1")
	r.Header.Set(managedBrowserTicketHeader, "fixture-ticket")
	if got := managedBrowserRequestFrom(withManagedBrowserHeaders(r)); got != (managedBrowserRequest{}) {
		t.Fatal("unverified request reached the hosted browser boundary")
	}
	r = r.WithContext(withPlatformActor(t.Context(), PlatformActor{WorkspaceID: "wsp_demo", UserID: "usr_alice", Role: "owner"}))
	if got := managedBrowserRequestFrom(withManagedBrowserHeaders(r)); !got.ready || got.ticket != "fixture-ticket" {
		t.Fatal("trusted ready marker or ticket was lost")
	}
	r.Header.Add(managedBrowserTicketHeader, "second-ticket")
	r.Header.Add(managedBrowserReadyHeader, "1")
	if got := managedBrowserRequestFrom(withManagedBrowserHeaders(r)); got.ready || got.ticket != "" {
		t.Fatal("ambiguous readiness or ticket was accepted")
	}
}

func TestHostedKernelBrokerUsesTicketAndDurableCleanupOwner(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/internal/managed-browser/wsp_demo" || r.Header.Get("Authorization") != "Bearer engine-fixture-token" {
			t.Error("broker request used the wrong Engine authority")
		}
		var body struct {
			Operation string            `json:"operation"`
			Path      string            `json:"path"`
			Body      map[string]string `json:"body"`
			Owner     string            `json:"owner"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Error("invalid broker request JSON")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Operation == http.MethodPost && body.Path == "/profiles" {
			if body.Body["name"] != "synaxis-bsign_fixture" || body.Owner != "" || r.Header.Get(managedBrowserTicketHeader) != "fixture-ticket" {
				t.Error("interactive broker request changed its profile or authorization")
			}
			w.Header().Set(managedBrowserResponseHeader, "1")
			fmt.Fprint(w, `{"id":"vendor-fixture","name":"synaxis-bsign_fixture"}`)
			return
		}
		if body.Operation != http.MethodDelete || body.Owner != "usr_alice" || r.Header.Get(managedBrowserTicketHeader) != "" || body.Body != nil {
			t.Error("cleanup did not use its durable owner without an interactive ticket")
		}
		if body.Path == "/browsers/synaxis-browser-brun_fixture" {
			w.Header().Set(managedBrowserResponseHeader, "1")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	broker := managedBrowserBroker{endpoint: server.URL + "/v1/internal/managed-browser/wsp_demo", token: "engine-fixture-token", client: server.Client()}
	provider := &kernelProvider{apiRequest: broker.request}
	if _, err := provider.CreateProfile(t.Context(), "bsign_fixture"); err == nil || requests.Load() != 0 {
		t.Fatal("allocation reached the broker without a ticket")
	}
	active := context.WithValue(t.Context(), managedBrowserRequestKey{}, managedBrowserRequest{ticket: "fixture-ticket", ready: true})
	if got, err := provider.CreateProfile(active, "bsign_fixture"); err != nil || got != "synaxis-bsign_fixture" {
		t.Fatalf("hosted profile creation did not preserve its durable name: %s %v", got, err)
	}
	cleanup := withManagedBrowserCleanup(active, "usr_alice")
	if stopped, err := provider.Stop(cleanup, "synaxis-browser-brun_fixture"); !stopped || err != nil {
		t.Fatalf("confirmed provider absence did not reconcile cleanup: %v", err)
	}
	if stopped, err := provider.Stop(cleanup, "synaxis-browser-unmarked"); stopped || !errors.Is(err, errBrowserSignIn) {
		t.Fatal("an unmarked broker 404 was mistaken for provider cleanup")
	}
}

func TestHostedBrowserSelectionAndReconnectProjection(t *testing.T) {
	store := newLibraryFileStore(t)
	service, err := NewBrowserSignInService(`{"provider":"kernel","apiKey":"legacy-key-fixture","projectId":"legacy-project"}`, store)
	if err != nil {
		t.Fatal(err)
	}
	api := &ConsoleAPI{store: store, browserSignIn: service}
	if slices.Contains(api.controlCapabilities(), managedBrowserCapability) {
		t.Fatal("legacy provider advertised the hosted broker")
	}
	if err := service.ConfigureHostedBrowser("https://synaxis.example/v1/internal/engine-events/wsp_demo", "wsp_demo", "engine-fixture-token"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(api.controlCapabilities(), managedBrowserCapability) {
		t.Fatal("configured broker capability is missing")
	}
	if got := service.availability(t.Context()); !got.ManagedHosted || got.Available || got.ManagedAvailable {
		t.Fatal("a legacy Kernel key was offered for a new hosted sign-in")
	}
	ready := context.WithValue(t.Context(), managedBrowserRequestKey{}, managedBrowserRequest{ticket: "fixture-ticket", ready: true})
	if service.signInProvider(ready, "credentials") != service.hostedProvider || service.hostedProvider.config.APIKey != "" {
		t.Fatal("ready sign-in did not choose the keyless hosted broker")
	}
	legacyProfile := &BrowserProfile{Provider: "kernel", ConfigurationID: service.managedProvider.ConfigurationID(), ProfileID: "legacy-private-reference"}
	hostedProfile := &BrowserProfile{Provider: "kernel", ConfigurationID: service.hostedProvider.ConfigurationID(), ProfileID: "hosted-private-reference"}
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		profile *BrowserProfile
		want    bool
	}{
		{"legacy while hosted unavailable", t.Context(), legacyProfile, true},
		{"hosted unavailable", t.Context(), hostedProfile, false},
		{"hosted ready", ready, hostedProfile, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projected := api.linkedAccountModel(tc.ctx, LinkedAccountRecord{Browser: tc.profile}, Account{})
			if projected.BrowserSignInAvailable == nil || *projected.BrowserSignInAvailable != tc.want || projected.BrowserSignInMethod != "credentials" {
				t.Fatal("wrong reconnect state for the exact saved profile")
			}
			wire, err := json.Marshal(projected)
			if err != nil || strings.Contains(string(wire), tc.profile.ConfigurationID) || strings.Contains(string(wire), tc.profile.ProfileID) || strings.Contains(string(wire), "fixture-ticket") {
				t.Fatal("private browser references leaked in reconnect metadata")
			}
		})
	}
	service.hostedProvider.apiRequest = func(context.Context, string, string, any, any) error { return errBrowserSignIn }
	input := BrowserSignIn{OwnerSubject: "usr_alice", DisplayName: "Fixture", WebsiteURL: "https://example.com/login", Method: "credentials"}
	if _, err := service.start(t.Context(), input); !errors.Is(err, errBrowserSignIn) {
		t.Fatal("unavailable hosted sign-in fell back to the legacy Kernel key")
	}
	if _, err := service.start(ready, input); !errors.Is(err, errBrowserSignIn) {
		t.Fatal("failed broker allocation fell back to the legacy Kernel key")
	}
	flows, err := service.flows.BrowserSignIns(t.Context())
	if err != nil || len(flows) != 1 || flows[0].ConfigurationID != hostedProfile.ConfigurationID || flows[0].State != "cleanup" {
		t.Fatal("uncertain hosted allocation did not retain its scoped cleanup reference")
	}
	wire, err := json.Marshal(flows[0])
	if err != nil || strings.Contains(string(wire), "fixture-ticket") || strings.Contains(string(wire), "engine-fixture-token") {
		t.Fatal("authorization was persisted with the hosted sign-in")
	}
}

func TestHostedBrowserExistingRuntimeChecksTicketBeforeCDP(t *testing.T) {
	store := newLibraryFileStore(t)
	fixture := newBrowserRuntimeFixtureWithWebsite(t, store, true)
	service := fixture.c.browserSignIn
	provider := newKernelProvider(kernelConfig{})
	provider.configurationID = "hosted-runtime-fixture"
	var cdpCalls atomic.Int32
	provider.client.Transport = upstreamRedirectRoundTripper(func(*http.Request) (*http.Response, error) {
		cdpCalls.Add(1)
		return nil, errors.New("CDP fixture ends here")
	})
	service.hostedProvider = provider
	profile := BrowserProfile{Provider: provider.Kind(), ConfigurationID: provider.ConfigurationID(), FlowID: "bsign_fixture", ProfileID: "synaxis-bsign_fixture", WebsiteURL: "https://example.com"}
	account, err := store.CreateLinkedAccount(t.Context(), LinkedAccountRecord{OwnerSubject: "usr_alice", DisplayName: "Hosted profile", Browser: &profile}, AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.account = account
	fixture.grant("read")
	records, err := store.LinkedAccounts(t.Context(), account.OwnerSubject)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.ID == account.ID {
			account = record
			break
		}
	}
	if len(account.BrowserGrants) != 1 {
		t.Fatal("missing runtime grant")
	}
	grant := account.BrowserGrants[0]
	now := time.Now()
	run, err := store.WriteBrowserRun(t.Context(), BrowserRun{
		ID: browserRunID(fixture.execution, account.ID), Owner: account.OwnerSubject, ClientID: fixture.client.ID,
		ExecutionID: fixture.execution, AccountID: account.ID, GrantID: grant.ID, Profile: profile,
		SessionID: "synaxis-browser-brun_fixture", ConnectURL: "wss://fixture.onkernel.com/cdp", State: "ready",
		ExpiresAt: now.Add(time.Minute), AuthorizedUntil: now.Add(time.Minute), Actions: map[string]BrowserActionReceipt{},
	}, 0)
	if err != nil || !service.browserRunAuthorized(t.Context(), run) {
		t.Fatalf("runtime fixture is not usable: %v", err)
	}
	if pending, err := service.reconcileHostedBrowser(t.Context()); err != nil || !pending {
		t.Fatalf("active hosted session should keep its scheduled wake: pending=%t error=%v", pending, err)
	}
	in := BrowserControlRequest{Owner: account.OwnerSubject, ClientID: fixture.client.ID, ExecutionID: fixture.execution,
		CallID: "snapshot_fixture", AuthorizedUntil: now.Add(time.Minute), Action: BrowserAction{Operation: "snapshot"}}
	if _, err = fixture.c.executeBrowser(t.Context(), in, account, Account{}, grant); !errors.Is(err, errBrowserSignIn) || cdpCalls.Load() != 0 {
		t.Fatal("existing hosted runtime reached CDP without a ticket")
	}
	current, ok, err := service.browserRun(t.Context(), run.ID)
	if err != nil || !ok || current.Revision != run.Revision {
		t.Fatal("an unauthorized action changed the durable run")
	}
	activeWithoutCredits := context.WithValue(t.Context(), managedBrowserRequestKey{}, managedBrowserRequest{ticket: "fixture-ticket"})
	_, _ = fixture.c.executeBrowser(activeWithoutCredits, in, account, Account{}, grant)
	if cdpCalls.Load() != 1 {
		t.Fatal("an existing session with fresh authority was incorrectly gated on new allocation credits")
	}
}
