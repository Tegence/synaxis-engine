package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostedBrowserReconcileRequiresServiceAndNoInput(t *testing.T) {
	service := &BrowserSignInService{hostedProvider: &kernelProvider{}}
	mux, store, key, now, _ := newHostedControlConsole(t, WithBrowserSignIn(service))
	service.store, service.flows, service.accounts = store, store, store
	member := controlRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, managedBrowserReconcilePath, "")
	if member.Code != http.StatusForbidden {
		t.Fatalf("workspace member cleanup status=%d", member.Code)
	}
	unsigned := httptest.NewRequest(http.MethodPost, managedBrowserReconcilePath, nil)
	unsigned.Header.Set("Authorization", "Bearer machine-token")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, unsigned)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned machine cleanup status=%d", recorder.Code)
	}
	withBody := controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, managedBrowserReconcilePath, "{}")
	if withBody.Code != http.StatusBadRequest {
		t.Fatalf("service cleanup accepted body: %d", withBody.Code)
	}
	valid := controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, managedBrowserReconcilePath, "")
	if valid.Code != http.StatusOK || valid.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(valid.Body.String()) != `{"pending":false}` {
		t.Fatalf("valid service cleanup: %d %s", valid.Code, valid.Body.String())
	}
}

func TestHostedBrowserReconcileRetainsSavedProfilesAndRetriesCleanup(t *testing.T) {
	legacy := &fakeSignInBrowser{}
	provider := &kernelProvider{configurationID: "hosted-reconcile-fixture"}
	service := &BrowserSignInService{provider: legacy, hostedProvider: provider}
	mux, store, key, assertionTime, _ := newHostedControlConsole(t, WithBrowserSignIn(service))
	service.store, service.flows, service.accounts = store, store, store
	ctx := t.Context()
	now := time.Now().UTC()
	owner := "usr_owner"
	website := "https://example.com/login"
	saved := BrowserProfile{Provider: provider.Kind(), ConfigurationID: provider.ConfigurationID(), FlowID: "bsign_retained", ProfileID: "synaxis-bsign_retained", WebsiteURL: website}
	account, err := store.CreateLinkedAccount(ctx, LinkedAccountRecord{OwnerSubject: owner, DisplayName: "Saved profile", Browser: &saved}, AccountPolicyPrecondition{})
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []BrowserSignIn{
		{ID: saved.FlowID, OwnerSubject: owner, AccountID: account.ID, WebsiteURL: website, Provider: saved.Provider, ConfigurationID: saved.ConfigurationID, ProfileID: saved.ProfileID, Method: "credentials", State: "saved", ExpiresAt: now.Add(-2 * time.Minute)},
		{ID: "bsign_removed", OwnerSubject: owner, AccountID: "removed-account", WebsiteURL: website, Provider: saved.Provider, ConfigurationID: saved.ConfigurationID, ProfileID: "synaxis-bsign_removed", Method: "credentials", State: "saved", ExpiresAt: now.Add(-2 * time.Minute), SyncAfter: now.Add(-time.Second)},
		{ID: "bsign_legacy", OwnerSubject: owner, WebsiteURL: website, Provider: legacy.Kind(), ConfigurationID: legacy.ConfigurationID(), ProfileID: "legacy-profile", SessionID: "legacy-session", State: "cleanup", ExpiresAt: now.Add(-2 * time.Minute), SyncAfter: now.Add(-time.Second)},
	} {
		if _, err := store.WriteBrowserSignIn(ctx, flow, 0); err != nil {
			t.Fatal(err)
		}
	}
	var deletions int
	provider.apiRequest = func(ctx context.Context, method, path string, _, out any) error {
		request := managedBrowserRequestFrom(ctx)
		if request.cleanupOwner != owner || request.ticket != "" || !strings.Contains(path, "synaxis-bsign_removed") {
			t.Fatalf("unexpected cleanup authority or resource: %s %s", method, path)
		}
		if method == http.MethodGet {
			return json.Unmarshal([]byte("[]"), out)
		}
		if method != http.MethodDelete || path != "/profiles/synaxis-bsign_removed" {
			t.Fatalf("unexpected provider command: %s %s", method, path)
		}
		deletions++
		if deletions == 1 {
			return errBrowserSignIn
		}
		return nil
	}
	for _, expected := range []string{`{"pending":true}`, `{"pending":false}`} {
		response := controlRequest(t, mux, key, assertionTime, platformServiceActorID, "service", http.MethodPost, managedBrowserReconcilePath, "")
		if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != expected {
			t.Fatalf("cleanup outcome %d %s, want %s", response.Code, response.Body.String(), expected)
		}
	}
	rows, err := store.BrowserSignIns(ctx)
	if err != nil || len(rows) != 2 || deletions != 2 || len(legacy.deleted) != 0 {
		t.Fatalf("unexpected cleanup results: rows=%d deletions=%d legacy deletions=%d error=%v", len(rows), deletions, len(legacy.deleted), err)
	}
	for _, row := range rows {
		if row.ID == "bsign_removed" || row.Revision != 1 {
			t.Fatal("the sweep removed or modified the wrong profile")
		}
	}
}
