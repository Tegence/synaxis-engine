package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func privateApprovalPgFixture(t *testing.T, s *PgStore) (string, func(time.Time, time.Time) PendingCall) {
	t.Helper()
	account := "private-approval-" + newApprovalID()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, table := range pendingCallTables {
			if _, err := s.pool.Exec(ctx, `DELETE FROM `+table+` WHERE account=$1`, account); err != nil {
				t.Error(err)
			}
		}
	})
	return account, func(created, expires time.Time) PendingCall {
		p := PendingCall{ID: "private_" + newApprovalID(), TS: created, ExpiresAt: &expires, Account: account, CallerSubject: "usr_owner", PrivateOwnerSubject: "usr_owner", Connector: "browser", Tool: "browser_type", Args: map[string]any{"draft": "private browser draft"}}
		if err := s.LogPending(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		return p
	}
}

func TestPgPrivateApprovalsIsolatedFromLegacyReaders(t *testing.T) {
	s := newPgConnectionsStore(t)
	account, create := privateApprovalPgFixture(t, s)
	now := time.Now().UTC()
	private := create(now, now.Add(time.Hour))
	public := PendingCall{ID: newApprovalID(), Account: account, Args: map[string]any{"shared": "public arguments"}}
	if err := s.LogPending(t.Context(), public); err != nil {
		t.Fatal(err)
	}
	// This is the projection an N-1 Engine uses: it cannot observe the private
	// row or obtain its ID, even though both approvals use one shared account.
	var count int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM pending_calls WHERE account=$1`, account).Scan(&count); err != nil || count != 1 {
		t.Fatalf("legacy count=%d err=%v", count, err)
	}
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM pending_calls WHERE id=$1 OR args LIKE '%private browser draft%'`, private.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("private approval reached legacy table: count=%d err=%v", count, err)
	}
	rows, err := s.PendingCalls(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.ID] = true
	}
	if !seen[private.ID] || !seen[public.ID] {
		t.Fatal("current Engine did not combine private and legacy approvals")
	}
	decided, err := s.DecidePending(t.Context(), private.ID, ApprovalDecision{Status: ApprovalApproved, Actor: "private-decider", Note: "private-decision-note"})
	if err != nil || decided.Status != ApprovalApproved || decided.PrivateOwnerSubject != private.PrivateOwnerSubject {
		t.Fatalf("decision=%+v err=%v", decided, err)
	}
	if _, err := s.DecidePending(t.Context(), private.ID, ApprovalDecision{Status: ApprovalDenied}); !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("opposite decision error=%v", err)
	}
	var args, actor, note string
	if err := s.pool.QueryRow(t.Context(), `SELECT args,decided_by,decision_note FROM narthex_private_pending_calls WHERE id=$1`, private.ID).Scan(&args, &actor, &note); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{args, actor, note} {
		if !strings.HasPrefix(raw, encPrefix) || strings.Contains(raw, "private-") || strings.Contains(raw, "private browser draft") {
			t.Fatal("private approval payload or decision metadata was not encrypted")
		}
	}
	reopened, err := NewPgStore(t.Context(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetCipher(s.cipher)
	got, found, err := reopened.ApprovalCall(t.Context(), private.ID)
	if err != nil || !found || got.Status != ApprovalApproved || got.Args["draft"] != "private browser draft" || got.DecidedBy != "private-decider" || got.DecisionNote != "private-decision-note" || got.PrivateOwnerSubject != "usr_owner" {
		t.Fatalf("private approval durability failed: found=%v err=%v", found, err)
	}
	// The plaintext migration includes private rows created without a cipher.
	if _, err := s.pool.Exec(t.Context(), `UPDATE narthex_private_pending_calls SET args=$2,decided_by=$3,decision_note=$4 WHERE id=$1`, private.ID, `{"draft":"private browser draft"}`, "private-decider", "private-decision-note"); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptExistingPendingCalls(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(t.Context(), `SELECT args,decided_by,decision_note FROM narthex_private_pending_calls WHERE id=$1`, private.ID).Scan(&args, &actor, &note); err != nil || !strings.HasPrefix(args, encPrefix) || !strings.HasPrefix(actor, encPrefix) || !strings.HasPrefix(note, encPrefix) {
		t.Fatalf("private approval migration failed: %v", err)
	}
}

func TestPgPrivateApprovalsLifecycleMaintenance(t *testing.T) {
	s := newPgConnectionsStore(t)
	_, create := privateApprovalPgFixture(t, s)
	now := time.Now().UTC()
	expired := create(now.Add(-2*time.Hour), now.Add(-time.Hour))
	stale := create(now, now.Add(time.Hour))
	live := create(now, now.Add(time.Hour))
	for _, p := range []PendingCall{stale, live} {
		if _, err := s.pool.Exec(t.Context(), `UPDATE narthex_private_pending_calls SET heartbeat_at=now()-interval '1 hour' WHERE id=$1`, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.HeartbeatPending(t.Context(), live.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecoverPendingApprovals(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	assertStatus := func(p PendingCall, want string) {
		t.Helper()
		got, found, err := s.ApprovalCall(t.Context(), p.ID)
		if err != nil || !found || got.Status != want || got.PrivateOwnerSubject != p.PrivateOwnerSubject {
			t.Fatalf("private lifecycle status: found=%v got=%s want=%s err=%v", found, got.Status, want, err)
		}
	}
	assertStatus(expired, ApprovalExpired)
	assertStatus(stale, ApprovalCancelled)
	assertStatus(live, ApprovalPending)
	if _, err := s.CancelPending(t.Context(), live.ID, "private-owner", "cancel private draft"); err != nil {
		t.Fatal(err)
	}
	assertStatus(live, ApprovalCancelled)
	manualExpiry := create(now, now.Add(time.Hour))
	if _, err := s.ExpirePending(t.Context(), manualExpiry.ID, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertStatus(manualExpiry, ApprovalExpired)
	swept := create(now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := s.ExpireTimedOutPending(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	assertStatus(swept, ApprovalExpired)
	moved := create(now, now.Add(time.Hour))
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := cancelPendingForAccountMoveTx(t.Context(), tx, moved.Account); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertStatus(moved, ApprovalCancelled)
	if _, err := s.PurgeCalls(t.Context(), 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.ApprovalCall(t.Context(), expired.ID); err != nil || found {
		t.Fatalf("private history did not expire under retention: found=%v err=%v", found, err)
	}
	assertStatus(moved, ApprovalCancelled)
}

func TestPgPrivateApprovalIDsCannotEnterLegacyTable(t *testing.T) {
	s := newPgConnectionsStore(t)
	for _, p := range []PendingCall{
		{ID: "private_" + newApprovalID()},
		{ID: newApprovalID(), PrivateOwnerSubject: "usr_owner"},
		{ID: "private_invalid", PrivateOwnerSubject: "usr_owner"},
	} {
		if err := s.LogPending(t.Context(), p); err == nil {
			t.Fatal("accepted mismatched private approval identity")
		}
	}
}
