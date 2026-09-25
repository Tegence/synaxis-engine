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
		Connector: "eng", EndpointKind: endpointKindConnector,
		EndpointGeneration: "connector-generation", Decision: "approved",
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
	if c.EndpointKind != endpointKindConnector || c.EndpointGeneration != "connector-generation" {
		t.Fatalf("endpoint identity missing from summary: %+v", c)
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
	if d.EndpointKind != endpointKindConnector || d.EndpointGeneration != "connector-generation" {
		t.Fatalf("endpoint identity missing from detail: %+v", d)
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

// TestKeysetBefore is a table-driven check on the (ts,id) tuple comparator
// RecentCallsBefore relies on for both stores — same predicate as the SQL
// `WHERE (ts, id) < ($beforeTS, $beforeID)` — with explicit focus on the
// same-timestamp tie-break, which a wall-clock-driven fixture can't exercise
// deterministically.
func TestKeysetBefore(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Second)
	cases := []struct {
		name         string
		ts, beforeTS time.Time
		id, beforeID int64
		want         bool
	}{
		{"earlier ts is before", t0, t1, 5, 5, true},
		{"later ts is not before", t1, t0, 5, 5, false},
		{"same ts, lower id is before", t0, t0, 3, 5, true},
		{"same ts, equal id is not before", t0, t0, 5, 5, false},
		{"same ts, higher id is not before", t0, t0, 7, 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keysetBefore(tc.ts, tc.id, tc.beforeTS, tc.beforeID); got != tc.want {
				t.Fatalf("keysetBefore(%v,%d,%v,%d) = %v, want %v", tc.ts, tc.id, tc.beforeTS, tc.beforeID, got, tc.want)
			}
		})
	}
}

// TestRingRecentCallsBeforePagesCompleteAndOrdered pages a 250-row fixture in
// pages of 100 (RecentCalls for the first page, then RecentCallsBefore keyed
// off the oldest row of the previous page) and asserts the traversal is
// complete, newest-first, and gap-free — the Activity "Load older" contract.
func TestRingRecentCallsBeforePagesCompleteAndOrdered(t *testing.T) {
	s := &FileStore{}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const total = 250
	for i := 0; i < total; i++ {
		s.LogCall(CallRecord{
			Account: "a", Tool: "t",
			TS: base.Add(time.Duration(i) * time.Second),
		})
	}

	ctx := context.Background()
	page, err := s.RecentCalls(ctx, 100)
	if err != nil {
		t.Fatalf("RecentCalls: %v", err)
	}
	var all []CallRecord
	for len(page) > 0 {
		all = append(all, page...)
		if len(page) < 100 {
			break
		}
		last := page[len(page)-1]
		page, err = s.RecentCallsBefore(ctx, last.TS, last.ID, 100)
		if err != nil {
			t.Fatalf("RecentCallsBefore: %v", err)
		}
	}

	if len(all) != total {
		t.Fatalf("traversal visited %d rows, want %d", len(all), total)
	}
	seen := make(map[int64]bool, total)
	for i, c := range all {
		if seen[c.ID] {
			t.Fatalf("row id=%d visited more than once", c.ID)
		}
		seen[c.ID] = true
		if wantID := int64(total - i); c.ID != wantID {
			t.Fatalf("row %d: id=%d, want %d (newest-first, gap-free)", i, c.ID, wantID)
		}
	}

	// Paging one page past the true end returns empty, not an error.
	oldest := all[len(all)-1]
	tail, err := s.RecentCallsBefore(ctx, oldest.TS, oldest.ID, 100)
	if err != nil || len(tail) != 0 {
		t.Fatalf("paging past the oldest row: got %d rows, err=%v", len(tail), err)
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
