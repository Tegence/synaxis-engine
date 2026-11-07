package engine

import (
	"os"
	"testing"
	"time"
)

func TestPgInspectionCallOwnershipPersists(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL")
	}
	s, err := NewPgStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const account = "inspection-original-source"
	defer s.pool.Exec(t.Context(), "DELETE FROM tool_calls WHERE account=$1", account)
	rec := CallRecord{CallerSubject: "agt_original", Account: account, AccountIncarnationID: "original-incarnation", AccountOwnerSubject: "usr_original", Tool: "read", TS: time.Now().UTC(), Args: "private-args", Result: "private-body"}
	if err := s.persistAuditCall(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := s.pool.QueryRow(t.Context(), "SELECT id FROM tool_calls WHERE account=$1 ORDER BY id DESC LIMIT 1", account).Scan(&id); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.CallDetail(t.Context(), id)
	if err != nil || !found || got.AccountIncarnationID != rec.AccountIncarnationID || got.AccountOwnerSubject != rec.AccountOwnerSubject || got.Result != rec.Result || got.CallerSubject != rec.CallerSubject {
		t.Fatalf("ownership roundtrip=%+v %v %v", got, found, err)
	}
}

func TestPgInspectionApprovalCallerPersists(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL")
	}
	s, err := NewPgStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := PendingCall{ID: "private_" + newApprovalID(), Account: "shared-source", CallerSubject: "agt_original", PrivateOwnerSubject: "usr_original", Tool: "write", Status: ApprovalPending, Args: map[string]any{"body": "PRIVATE"}}
	defer s.pool.Exec(t.Context(), "DELETE FROM narthex_private_pending_calls WHERE id=$1", p.ID)
	if err := s.LogPending(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.ApprovalCall(t.Context(), p.ID)
	if err != nil || !found || got.CallerSubject != p.CallerSubject || got.PrivateOwnerSubject != p.PrivateOwnerSubject {
		t.Fatalf("pending caller lost: %+v %v %v", got, found, err)
	}
	got, err = s.DecidePending(t.Context(), p.ID, ApprovalDecision{Status: ApprovalDenied, Actor: "usr_owner"})
	if err != nil || got.CallerSubject != p.CallerSubject || got.PrivateOwnerSubject != p.PrivateOwnerSubject {
		t.Fatalf("terminal caller lost: %+v %v", got, err)
	}
}
