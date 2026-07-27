package engine

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Interface conformance: both stores must satisfy the audit facets the
// gateway/main discover by type assertion.
var (
	_ AuditSink   = (*FileStore)(nil)
	_ AuditSink   = (*PgStore)(nil)
	_ AuditPurger = (*FileStore)(nil)
	_ AuditPurger = (*PgStore)(nil)
)

// TestRingPayloadListVsDetail is the core flight-recorder contract: payloads
// round-trip, but only CallDetail returns them — list reads stay summary-only.
func TestRingPayloadListVsDetail(t *testing.T) {
	s := &FileStore{}
	s.LogCall(CallRecord{
		Account: "acct1", Tool: "save_issue", OK: true, Ms: 42,
		Connector: "eng", Decision: "approved",
		Args:   `{"id":"42"}`,
		Result: `{"ok":true}`,
	})

	list, err := s.RecentCalls(context.Background(), 10)
	if err != nil {
		t.Fatalf("RecentCalls: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 record, got %d", len(list))
	}
	c := list[0]
	if c.ID == 0 {
		t.Fatal("list record must carry a synthetic ID")
	}
	if c.TS.IsZero() {
		t.Fatal("zero TS should have been stamped by the store")
	}
	if c.Connector != "eng" || c.Decision != "approved" || c.Account != "acct1" || c.Tool != "save_issue" || !c.OK || c.Ms != 42 {
		t.Fatalf("summary fields mismatch: %+v", c)
	}
	if c.Args != "" || c.Result != "" {
		t.Fatalf("list read must NOT include payloads, got args=%q result=%q", c.Args, c.Result)
	}

	// Detail carries the payloads.
	d, ok, err := s.CallDetail(context.Background(), c.ID)
	if err != nil || !ok {
		t.Fatalf("CallDetail(%d): ok=%v err=%v", c.ID, ok, err)
	}
	if d.Args != `{"id":"42"}` || d.Result != `{"ok":true}` {
		t.Fatalf("detail payload mismatch: args=%q result=%q", d.Args, d.Result)
	}

	// Unknown ID is a clean miss, not an error.
	if _, ok, err := s.CallDetail(context.Background(), 999999); ok || err != nil {
		t.Fatalf("unknown id: want (false,nil), got ok=%v err=%v", ok, err)
	}
}

// TestRingGuardRoundTrip: Guard is a summary field — unlike Args/Result it
// comes back on BOTH list reads (the Activity UI chips on it) and detail.
func TestRingGuardRoundTrip(t *testing.T) {
	s := &FileStore{}
	s.LogCall(CallRecord{
		Account: "acct1", Tool: "get_issue", OK: true, Ms: 5,
		Connector: "eng", Guard: "truncated,redacted:3,flagged:injection",
		Args: `{}`, Result: `{"ok":true}`,
	})
	list, err := s.RecentCalls(context.Background(), 5)
	if err != nil || len(list) != 1 {
		t.Fatalf("RecentCalls: len=%d err=%v", len(list), err)
	}
	if list[0].Guard != "truncated,redacted:3,flagged:injection" {
		t.Fatalf("list read must carry Guard, got %q", list[0].Guard)
	}
	if list[0].Args != "" || list[0].Result != "" {
		t.Fatal("Guard in list reads must not drag payloads along")
	}
	d, ok, err := s.CallDetail(context.Background(), list[0].ID)
	if err != nil || !ok {
		t.Fatalf("CallDetail: ok=%v err=%v", ok, err)
	}
	if d.Guard != "truncated,redacted:3,flagged:injection" {
		t.Fatalf("detail read Guard mismatch: %q", d.Guard)
	}
}

// TestRingLegacyMinimalRecord proves pre-flight-recorder call sites (no
// connector/decision/payloads, zero TS) still log cleanly.
func TestRingLegacyMinimalRecord(t *testing.T) {
	s := &FileStore{}
	s.LogCall(CallRecord{Account: "a", Tool: "t", OK: false, Ms: 7, Error: "boom"})
	list, _ := s.RecentCalls(context.Background(), 5)
	if len(list) != 1 {
		t.Fatalf("want 1 record, got %d", len(list))
	}
	c := list[0]
	if c.TS.IsZero() || c.ID != 1 {
		t.Fatalf("legacy record not stamped: %+v", c)
	}
	if c.Connector != "" || c.Decision != "" || c.Args != "" || c.Result != "" || c.Guard != "" {
		t.Fatalf("legacy record grew unexpected fields: %+v", c)
	}
	if c.Error != "boom" {
		t.Fatalf("error lost: %+v", c)
	}
}

// TestRingIDsSurviveEviction: IDs keep incrementing and CallDetail still finds
// live entries after the ring wraps.
func TestRingIDsSurviveEviction(t *testing.T) {
	r := &ring{cap: 3}
	for i := 0; i < 5; i++ {
		r.LogCall(CallRecord{Account: "a", Tool: "t"})
	}
	list, _ := r.RecentCalls(context.Background(), 10)
	if len(list) != 3 {
		t.Fatalf("ring cap not enforced: %d", len(list))
	}
	if list[0].ID != 5 || list[2].ID != 3 {
		t.Fatalf("IDs should be 5..3 newest-first, got %d..%d", list[0].ID, list[2].ID)
	}
	if _, ok, _ := r.CallDetail(context.Background(), 1); ok {
		t.Fatal("evicted entry should be gone")
	}
	if _, ok, _ := r.CallDetail(context.Background(), 4); !ok {
		t.Fatal("live entry should be findable by ID")
	}
}

func TestClampPayload(t *testing.T) {
	if got := clampPayload("short", 10); got != "short" {
		t.Fatalf("under-limit string must pass through, got %q", got)
	}
	exact := strings.Repeat("x", 10)
	if got := clampPayload(exact, 10); got != exact {
		t.Fatalf("exact-limit string must pass through, got %q", got)
	}
	got := clampPayload(strings.Repeat("x", 11), 10)
	if got != strings.Repeat("x", 10)+truncatedSuffix {
		t.Fatalf("over-limit clamp wrong: %q", got)
	}

	// The store applies the 32KB cap on write.
	s := &FileStore{}
	big := strings.Repeat("a", maxPayloadBytes+100)
	s.LogCall(CallRecord{Account: "a", Tool: "t", Args: big, Result: big})
	d, ok, _ := s.CallDetail(context.Background(), 1)
	if !ok {
		t.Fatal("record missing")
	}
	if !strings.HasSuffix(d.Args, truncatedSuffix) || len(d.Args) != maxPayloadBytes+len(truncatedSuffix) {
		t.Fatalf("args not clamped to 32KB+suffix: len=%d", len(d.Args))
	}
	if !strings.HasSuffix(d.Result, truncatedSuffix) {
		t.Fatal("result not clamped")
	}
}

// TestClampRuneBoundary: truncation must never split a multi-byte UTF-8 rune —
// Postgres rejects invalid-UTF-8 TEXT, silently dropping the whole audit row
// on the fire-and-forget insert path (masked when the cipher is set, since
// base64 ciphertext is always valid UTF-8).
func TestClampRuneBoundary(t *testing.T) {
	cjk := strings.Repeat("世", 20000) // 3 bytes each; 32768 % 3 != 0, so a naive slice splits a rune
	got := clampPayload(cjk, maxPayloadBytes)
	if !utf8.ValidString(got) {
		t.Fatal("clampPayload produced invalid UTF-8")
	}
	if len(got) > maxPayloadBytes+len(truncatedSuffix) {
		t.Fatalf("clamp exceeded cap: len=%d", len(got))
	}
	if !strings.HasSuffix(got, truncatedSuffix) {
		t.Fatal("truncation marker missing")
	}
	// 500 % 3 = 2, so a naive s[:500] over 3-byte runes splits one.
	if e := clampErr(strings.Repeat("世", 200)); !utf8.ValidString(e) || len(e) > 500 {
		t.Fatalf("clampErr produced invalid or over-long string: valid=%v len=%d", utf8.ValidString(e), len(e))
	}
}

// TestFileStorePurgeNoop: the in-memory ring self-bounds; purge reports 0 and
// deletes nothing.
func TestFileStorePurgeNoop(t *testing.T) {
	s := &FileStore{}
	s.LogCall(CallRecord{Account: "a", Tool: "t"})
	n, err := s.PurgeCalls(context.Background(), time.Hour)
	if err != nil || n != 0 {
		t.Fatalf("PurgeCalls: want (0,nil), got (%d,%v)", n, err)
	}
	if list, _ := s.RecentCalls(context.Background(), 5); len(list) != 1 {
		t.Fatal("no-op purge must not drop ring entries")
	}
}
