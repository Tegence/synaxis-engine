package engine

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFileWebsiteBrowserRuntime(t *testing.T) {
	testWebsiteBrowserRuntime(t, newLibraryFileStore(t))
}

func TestPgWebsiteBrowserRuntime(t *testing.T) {
	testWebsiteBrowserRuntime(t, newPgConnectionsStore(t))
}

func testWebsiteBrowserRuntime(t *testing.T, store browserRuntimeTestStore) {
	for _, mode := range []string{"read", "approval", "automatic"} {
		t.Run(mode, func(t *testing.T) {
			f := newBrowserRuntimeFixtureWithWebsite(t, store, true)
			if _, code := f.call("ungranted", BrowserAction{Operation: "open"}); code != 403 {
				t.Fatalf("ungranted website account: %d", code)
			}
			f.grant(mode)
			if _, code := f.call("open", BrowserAction{Operation: "open"}); code != 200 {
				t.Fatalf("standalone account cannot open: %d", code)
			}
			snap, code := f.call("snapshot", BrowserAction{Operation: "snapshot"})
			if code != 200 || snap.Snapshot == nil {
				t.Fatalf("standalone account cannot read: %d", code)
			}
			action := BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}
			out, code := f.call("click", action)
			switch mode {
			case "read":
				if code != 409 || len(f.p.calls) != 2 {
					t.Fatal("read permission allowed action")
				}
			case "automatic":
				if code != 200 || out.Status != "ok" || len(f.p.calls) != 3 {
					t.Fatalf("preauthorized action failed: %d %+v", code, out)
				}
			case "approval":
				if code != 200 || out.Status != "pending" || len(f.p.calls) != 2 {
					t.Fatalf("owner approval missing: %d %+v", code, out)
				}
				other := withPlatformActor(t.Context(), PlatformActor{UserID: "usr_bob", Role: "owner"})
				if err := f.c.gw.Decide(other, out.ApprovalID, ApprovalApproved); err == nil {
					t.Fatal("another owner approved private website action")
				}
				owner := withPlatformActor(t.Context(), PlatformActor{UserID: "usr_alice", Role: "owner"})
				if err := f.c.gw.Decide(owner, out.ApprovalID, ApprovalApproved); err != nil {
					t.Fatal(err)
				}
				out, code = f.call("click", action)
				if code != 200 || out.Status != "ok" || len(f.p.calls) != 3 {
					t.Fatalf("approved website action failed: %d %+v", code, out)
				}
			}
			rows, _ := store.LinkedAccounts(t.Context(), "usr_alice")
			for _, row := range rows {
				if row.ID == f.account.ID {
					empty := ""
					if _, err := store.MutateLinkedAccount(t.Context(), "", row.ID, row.OwnerSubject, row.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{BearerToken: &empty}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, code = f.call("after_disconnect", BrowserAction{Operation: "snapshot"}); code == 200 {
				t.Fatal("disconnected website profile remained available")
			}
		})
	}
}

func TestWebsiteBrowserRuntimeRequiresCurrentOwnerRole(t *testing.T) {
	f := newBrowserRuntimeFixtureWithWebsite(t, newLibraryFileStore(t), true)
	for _, role := range []string{"viewer", "member", "auditor", "service", ""} {
		in := BrowserControlRequest{Operation: "list", Owner: "usr_alice", OwnerRole: role, Subject: f.client.Subject, ClientID: f.client.ID}
		raw, _ := json.Marshal(in)
		req := httptest.NewRequest("POST", "/control/v1/browser-runtime", strings.NewReader(string(raw)))
		req = req.WithContext(withPlatformActor(t.Context(), PlatformActor{UserID: platformServiceActorID, Role: "service"}))
		w := httptest.NewRecorder()
		f.c.browserRuntimeHandler(w, req)
		var out BrowserControlResult
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if len(out.Accounts) != 0 {
			t.Fatalf("role %q can read website accounts", role)
		}
	}
}

func TestWebsiteApprovalInvalidatedByReconnect(t *testing.T) {
	f := newBrowserRuntimeFixtureWithWebsite(t, newLibraryFileStore(t), true)
	f.grant("approval")
	f.call("open", BrowserAction{Operation: "open"})
	snap, _ := f.call("snapshot", BrowserAction{Operation: "snapshot"})
	action := BrowserAction{Operation: "click", Snapshot: snap.Snapshot.ID, Element: 1}
	pending, code := f.call("publish", action)
	if code != 200 || pending.Status != "pending" {
		t.Fatalf("missing approval: %d %+v", code, pending)
	}
	accounts, _ := f.store.LinkedAccounts(t.Context(), "usr_alice")
	for _, account := range accounts {
		if account.ID == f.account.ID {
			profile := *account.Browser
			profile.FlowID, profile.ProfileID = "new_flow", "new_profile"
			if _, err := f.store.MutateLinkedAccount(t.Context(), "", account.ID, account.OwnerSubject, account.Revision, AccountPolicyPrecondition{}, LinkedAccountMutation{Browser: &profile}); err != nil {
				t.Fatal(err)
			}
		}
	}
	owner := withPlatformActor(t.Context(), PlatformActor{UserID: "usr_alice", Role: "owner"})
	if err := f.c.gw.Decide(owner, pending.ApprovalID, ApprovalApproved); err != ErrApprovalNotPending {
		t.Fatalf("stale website approval was not cancelled: %v", err)
	}
	approval, found, err := f.store.ApprovalCall(t.Context(), pending.ApprovalID)
	if err != nil || !found || approval.Status != ApprovalCancelled {
		t.Fatalf("stale approval state: %+v %v", approval, err)
	}
	f.call("publish", action)
	if len(f.p.calls) != 2 {
		t.Fatal("old approval dispatched against a reconnected profile")
	}
}
