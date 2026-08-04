package engine

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

func lifecycleFileStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}
	return s
}

func lifecyclePending(id string, expires time.Time) PendingCall {
	return PendingCall{
		ID: id, TS: expires.Add(-time.Minute), ExpiresAt: &expires,
		Connector: "work", Account: "linear", Tool: "save_issue",
		Args: map[string]any{"issue": "ENG-1"}, Status: ApprovalPending,
	}
}

func TestFileStoreApprovalDecisionIsConditionalAndIdempotent(t *testing.T) {
	s := lifecycleFileStore(t)
	if err := s.LogPending(context.Background(), lifecyclePending("cas", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}

	first, err := s.DecidePending(context.Background(), "cas", ApprovalDecision{
		Status: ApprovalApproved, Actor: "platform:operator-1", Note: "reviewed",
	})
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	if first.Status != ApprovalApproved || first.DecidedAt == nil || first.DecidedBy != "platform:operator-1" || first.DecisionNote != "reviewed" {
		t.Fatalf("first decision = %+v", first)
	}

	// Retrying the same action succeeds but cannot mutate its original audit
	// attribution or note.
	retry, err := s.DecidePending(context.Background(), "cas", ApprovalDecision{
		Status: ApprovalApproved, Actor: "platform:other", Note: "must not overwrite",
	})
	if err != nil {
		t.Fatalf("same decision retry: %v", err)
	}
	if retry.DecidedBy != first.DecidedBy || retry.DecisionNote != first.DecisionNote || retry.DecidedAt == nil {
		t.Fatalf("same decision retry rewrote history: %+v", retry)
	}
	if _, err := s.DecidePending(context.Background(), "cas", ApprovalDecision{Status: ApprovalDenied}); !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("contradictory decision err = %v, want ErrApprovalNotPending", err)
	}
}

func TestFileStoreLateDecisionExpiresInsteadOfRevivingCall(t *testing.T) {
	s := lifecycleFileStore(t)
	if err := s.LogPending(context.Background(), lifecyclePending("late", time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	p, err := s.DecidePending(context.Background(), "late", ApprovalDecision{Status: ApprovalApproved})
	if !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("late decision err = %v, want ErrApprovalExpired", err)
	}
	if p.Status != ApprovalExpired || p.DecidedBy != "engine" {
		t.Fatalf("late decision must persist expiry, got %+v", p)
	}
}

type decisionWriteFailStore struct{ *FileStore }

func (s decisionWriteFailStore) DecidePending(context.Context, string, ApprovalDecision) (PendingCall, error) {
	return PendingCall{}, errors.New("database unavailable")
}

func TestGatewayKeepsWaiterWhenDurableDecisionWriteFails(t *testing.T) {
	base := lifecycleFileStore(t)
	store := decisionWriteFailStore{FileStore: base}
	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	if err := base.LogPending(context.Background(), lifecyclePending("write-failure", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	ch := g.registerWait("write-failure")
	if _, err := g.DecideWithMetadata(context.Background(), "write-failure", ApprovalDecision{Status: ApprovalApproved}); err == nil {
		t.Fatal("decision should fail when durable write fails")
	}

	g.approveMu.Lock()
	got, live := g.approveCh["write-failure"]
	g.approveMu.Unlock()
	if !live || got != ch {
		t.Fatal("waiter was removed before its durable decision write succeeded")
	}
	p, found, err := base.ApprovalCall(context.Background(), "write-failure")
	if err != nil || !found || p.Status != ApprovalPending {
		t.Fatalf("failed decision mutated durable row: found=%v err=%v row=%+v", found, err, p)
	}
}

func TestGatewayWaitObservesDurableDecisionFromAnotherInstance(t *testing.T) {
	s := lifecycleFileStore(t)
	if err := s.LogPending(context.Background(), lifecyclePending("cross-instance", time.Now().Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	first := NewGateway(s, server.NewMCPServer("first", "0.0.0", server.WithToolCapabilities(true)))
	second := NewGateway(s, server.NewMCPServer("second", "0.0.0", server.WithToolCapabilities(true)))

	done := make(chan struct {
		approved bool
		reason   string
	}, 1)
	go func() {
		ok, reason := first.WaitDecision(context.Background(), "cross-instance", time.Second)
		done <- struct {
			approved bool
			reason   string
		}{ok, reason}
	}()
	time.Sleep(20 * time.Millisecond)
	if err := second.Decide(context.Background(), "cross-instance", ApprovalApproved); err != nil {
		t.Fatalf("second instance decision: %v", err)
	}
	select {
	case got := <-done:
		if !got.approved || got.reason != ApprovalApproved {
			t.Fatalf("waiter observed %+v, want approved", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first instance did not observe the durable decision")
	}
}

func TestGatewayCancelledRequestPersistsCancelledLifecycle(t *testing.T) {
	s := lifecycleFileStore(t)
	if err := s.LogPending(context.Background(), lifecyclePending("cancelled", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	g := NewGateway(s, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() {
		_, reason := g.WaitDecision(ctx, "cancelled", time.Second)
		done <- reason
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case reason := <-done:
		if reason != ApprovalCancelled {
			t.Fatalf("cancelled wait reason = %q, want %q", reason, ApprovalCancelled)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not finish")
	}
	p, found, err := s.ApprovalCall(context.Background(), "cancelled")
	if err != nil || !found || p.Status != ApprovalCancelled || p.DecidedBy != "engine" {
		t.Fatalf("cancelled lifecycle = found=%v err=%v row=%+v", found, err, p)
	}
}

func TestApprovalDecisionActorDoesNotTrustRawPlatformIdentityHeaders(t *testing.T) {
	api := NewConsoleAPI(nil, nil, nil, "pw", "secret", "https://engine.example", "", "", WithAdminToken("machine"))
	machine := httptest.NewRequest("POST", "/", nil)
	machine.Header.Set("Authorization", "Bearer machine")
	machine.Header.Set("X-Synaxis-User-ID", "operator@example.test")
	if got := api.approvalDecisionActor(machine); got != "platform-admin" {
		t.Fatalf("raw platform actor must not be trusted, got %q", got)
	}
	local := httptest.NewRequest("POST", "/", nil)
	local.Header.Set("Authorization", "Bearer a-local-session")
	local.Header.Set("X-Synaxis-User-ID", "spoofed")
	if got := api.approvalDecisionActor(local); got != "local-admin" {
		t.Fatalf("unverified platform actor = %q, want local-admin", got)
	}
	machine.Header.Set("X-Synaxis-User-ID", "bad identity!")
	if got := api.approvalDecisionActor(machine); got != "platform-admin" {
		t.Fatalf("raw platform actor = %q, want platform-admin", got)
	}
}
