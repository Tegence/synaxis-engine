package engine

import (
	"context"
	"testing"
)

// A whole-account write (the deprecated /admin/token form, on a self-hosted
// Engine with the legacy admin routes turned on) must not turn a
// caller-delegated connection into a plain one. The account keeps its
// incarnation across Upsert, so the agents given that exact connection would
// silently receive a shared credential at another URL.

func TestUpsertKeepsCallerDelegatedAccount(t *testing.T) {
	testUpsertKeepsCallerDelegatedAccount(t, newFileConnectionsStore(t))
}

func TestPgUpsertKeepsCallerDelegatedAccount(t *testing.T) {
	testUpsertKeepsCallerDelegatedAccount(t, newPgConnectionsStore(t))
}

func testUpsertKeepsCallerDelegatedAccount(t *testing.T, store AccountStore) {
	t.Helper()
	ctx := context.Background()
	h := newConnectionsTestHarness(t, store)
	created := h.mustCreate()
	h.putToken(platformServiceActorID, "service", created.Revision, testDelegatedListingToken)
	before, ok := store.Account(h.name)
	if !ok || !before.CallerDelegated {
		t.Fatalf("created account = %+v, %v; want a caller-delegated account", before, ok)
	}

	err := store.Upsert(ctx, Account{
		Name: h.name, Label: "Replaced", Group: h.group,
		URL: "https://collector.example.net/mcp", AuthMode: "token", BearerToken: "replacement-token",
	})
	if err == nil {
		t.Fatal("a whole-account write replaced a caller-delegated connection with a plain one")
	}
	after, ok := store.Account(h.name)
	if !ok || !after.CallerDelegated || after.URL != before.URL || after.IncarnationID != before.IncarnationID {
		t.Fatalf("after the refused write the account is %+v, %v; want it unchanged", after, ok)
	}
	if store.Token(h.name) != testDelegatedListingToken {
		t.Fatal("the refused write changed the listing token")
	}

	// Writing the same caller-delegated account whole again (PgStore's
	// encryption migration does this) is still accepted.
	if err := store.Upsert(ctx, after); err != nil {
		t.Fatalf("rewriting the caller-delegated account whole: %v", err)
	}
	if again, ok := store.Account(h.name); !ok || !again.CallerDelegated || again.ClientSecret != before.ClientSecret {
		t.Fatalf("after the identical whole write the account is %+v, %v; want it unchanged", again, ok)
	}

	// A plain account never becomes caller-delegated through a whole write
	// either: that path skips the connections group's validation.
	plainName := h.name + "_plain"
	if err := store.Upsert(ctx, Account{Name: plainName, Group: h.group, URL: "https://tools.example.com/mcp", AuthMode: "token", BearerToken: "plain-token"}); err != nil {
		t.Fatalf("creating a plain account: %v", err)
	}
	t.Cleanup(func() {
		if current, ok := store.Account(plainName); ok {
			_ = store.Delete(context.Background(), plainName, current.IncarnationID, current.Revision)
		}
	})
	promoted, _ := store.Account(plainName)
	promoted.CallerDelegated = true
	if err := store.Upsert(ctx, promoted); err == nil {
		t.Fatal("a whole-account write turned a plain connection into a caller-delegated one")
	}
	if current, _ := store.Account(plainName); current.CallerDelegated {
		t.Fatal("the refused write stored the caller-delegated flag")
	}
}
