package engine

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgStoreCRUD exercises the Postgres AccountStore against a real Postgres.
// Gated on TEST_DATABASE_URL so it only runs when a DB is provided (no Notion
// needed): proves Upsert, Accounts, Token, RefreshToken, and that UpdateTokens
// PERSISTS — the property that makes tokens survive Cloud Run restarts.
func TestPgStoreCRUD(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name='pgtest'`)

	// Upsert an oauth account.
	if err := s.Upsert(ctx, Account{
		Name: "pgtest", Label: "PG Test", Group: "W", URL: "https://x/mcp", AuthMode: "oauth",
		ClientID: "cid", ClientSecret: "csec", AccessToken: "A1", RefreshToken: "R1",
		TokenEndpoint: "https://x/token", Resource: "https://x/mcp", Scope: "channels:read chat:write",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if got := s.Token("pgtest"); got != "A1" {
		t.Fatalf("Token: want A1, got %q", got)
	}
	if got := s.RefreshToken("pgtest"); got != "R1" {
		t.Fatalf("RefreshToken: want R1, got %q", got)
	}

	// The load-bearing assertion: refreshed tokens persist.
	if err := s.UpdateTokens("pgtest", "A2", "R2"); err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}
	// Re-open a fresh store to prove it's in the DB, not memory.
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if got := s2.Token("pgtest"); got != "A2" {
		t.Fatalf("persisted access token: want A2, got %q", got)
	}
	if got := s2.RefreshToken("pgtest"); got != "R2" {
		t.Fatalf("persisted refresh token: want R2, got %q", got)
	}

	// Upsert with empty refresh must NOT wipe the stored refresh token.
	if err := s.UpdateTokens("pgtest", "A3", ""); err != nil {
		t.Fatalf("UpdateTokens (no refresh): %v", err)
	}
	if got := s.RefreshToken("pgtest"); got != "R2" {
		t.Fatalf("empty refresh should keep R2, got %q", got)
	}

	// Accounts() round-trips all fields.
	found := false
	for _, a := range s.Accounts() {
		if a.Name == "pgtest" {
			found = true
			if a.AuthMode != "oauth" || a.Group != "W" || a.ClientID != "cid" || a.AccessToken != "A3" {
				t.Fatalf("Accounts round-trip mismatch: %+v", a)
			}
			if a.Scope != "channels:read chat:write" {
				t.Fatalf("Accounts lost scope: %q", a.Scope)
			}
		}
	}
	if !found {
		t.Fatal("Accounts() did not return the upserted account")
	}

	// disabled_tools (text[]) round-trips.
	if err := s.SetDisabledTools(ctx, "pgtest", []string{"foo", "bar"}); err != nil {
		t.Fatalf("SetDisabledTools: %v", err)
	}
	got, _ := s.Account("pgtest")
	if len(got.DisabledTools) != 2 || got.DisabledTools[0] != "foo" || got.DisabledTools[1] != "bar" {
		t.Fatalf("disabled tools round-trip: want [foo bar], got %v", got.DisabledTools)
	}
	if got.Scope != "channels:read chat:write" {
		t.Fatalf("Account lost scope: %q", got.Scope)
	}

	// read_only defaults false, flips via SetReadOnly, and round-trips
	// through Account, Accounts, and Upsert.
	if got.ReadOnly {
		t.Fatal("fresh account should default to ReadOnly=false")
	}
	if err := s.SetReadOnly(ctx, "pgtest", true); err != nil {
		t.Fatalf("SetReadOnly: %v", err)
	}
	got, _ = s.Account("pgtest")
	if !got.ReadOnly {
		t.Fatal("SetReadOnly(true) not persisted")
	}
	for _, a := range s.Accounts() {
		if a.Name == "pgtest" && !a.ReadOnly {
			t.Fatal("Accounts() lost read_only")
		}
	}
	got.ReadOnly = false
	if err := s.Upsert(ctx, got); err != nil {
		t.Fatalf("Upsert (read_only=false): %v", err)
	}
	if a, _ := s.Account("pgtest"); a.ReadOnly {
		t.Fatal("Upsert did not update read_only")
	}
}

func TestPgStoreEncryption(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	ctx := context.Background()
	c, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name='enctest'`)
	s.SetCipher(c)
	if err := s.Upsert(ctx, Account{Name: "enctest", URL: "u", AuthMode: "oauth", AccessToken: "secret-access", RefreshToken: "secret-refresh", ClientSecret: "csec"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// reads decrypt
	a, _ := s.Account("enctest")
	if a.AccessToken != "secret-access" || a.RefreshToken != "secret-refresh" || a.ClientSecret != "csec" {
		t.Fatalf("decrypt on read failed: %+v", a)
	}
	if s.RefreshToken("enctest") != "secret-refresh" {
		t.Fatal("RefreshToken did not decrypt")
	}
	// at rest it is encrypted, not plaintext
	var raw string
	s.pool.QueryRow(ctx, `SELECT access_token FROM narthex_accounts WHERE name='enctest'`).Scan(&raw)
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("not encrypted at rest: %q", raw)
	}
	if strings.Contains(raw, "secret-access") {
		t.Fatal("plaintext leaked into the column")
	}
	// legacy plaintext (no prefix) passes through
	if c.Decrypt("legacy-plain") != "legacy-plain" {
		t.Fatal("legacy plaintext not passed through")
	}
}

// TestPgStoreConnectorCRUD exercises the Postgres ConnectorStore: JSONB
// round-trip, upsert-updates-in-place, persistence across a fresh pool, and
// delete. Gated on TEST_DATABASE_URL like the other Pg tests.
func TestPgStoreConnectorCRUD(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgconn','pgconn-nil')`)

	vc := VirtualConnector{
		Slug:   "pgconn",
		Label:  "PG Connector",
		Tools:  map[string][]string{"acct1": {"list_issues", "get_issue"}, "acct2": {}},
		Record: true,
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgconn")
	if !ok {
		t.Fatal("VirtualConnector: not found after upsert")
	}
	if got.Label != "PG Connector" || len(got.Tools["acct1"]) != 2 || got.Tools["acct1"][0] != "list_issues" {
		t.Fatalf("JSONB round-trip mismatch: %+v", got)
	}
	if !got.Record {
		t.Fatalf("Record flag lost in round-trip: %+v", got)
	}

	// nil Tools must not write SQL null into the NOT NULL JSONB column.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgconn-nil", Label: "Nil Tools"}); err != nil {
		t.Fatalf("UpsertConnector (nil tools): %v", err)
	}
	if gotNil, ok := s.VirtualConnector(ctx, "pgconn-nil"); !ok {
		t.Fatal("nil-tools connector not readable back")
	} else if gotNil.Record {
		t.Fatal("Record must default to false")
	}

	// Same slug updates in place, and it persists across a fresh pool.
	vc.Label = "PG v2"
	vc.Tools["acct1"] = []string{"list_issues"}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector (update): %v", err)
	}
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got2, ok := s2.VirtualConnector(ctx, "pgconn")
	if !ok {
		t.Fatal("connector missing after reopen")
	}
	if got2.Label != "PG v2" || len(got2.Tools["acct1"]) != 1 {
		t.Fatalf("persisted update mismatch: %+v", got2)
	}

	// Connectors() lists what we wrote.
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range list {
		seen[c.Slug] = true
	}
	if !seen["pgconn"] || !seen["pgconn-nil"] {
		t.Fatalf("Connectors() missing rows: %+v", list)
	}

	// Delete, verify gone, and idempotent.
	if err := s2.DeleteConnector(ctx, "pgconn"); err != nil {
		t.Fatalf("DeleteConnector: %v", err)
	}
	if _, ok := s2.VirtualConnector(ctx, "pgconn"); ok {
		t.Fatal("connector still present after delete")
	}
	if err := s2.DeleteConnector(ctx, "pgconn"); err != nil {
		t.Fatalf("DeleteConnector (idempotent): %v", err)
	}
}

// TestPgStoreConnectorApproval proves the approval JSONB column round-trips
// (including nil → '{}', never SQL null) and persists across a fresh pool.
func TestPgStoreConnectorApproval(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgappr','pgappr-nil')`)

	vc := VirtualConnector{
		Slug:     "pgappr",
		Label:    "Approval",
		Tools:    map[string][]string{"acct1": {"list_issues", "delete_issue"}},
		Approval: map[string][]string{"acct1": {"delete_issue"}},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgappr")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if len(got.Approval["acct1"]) != 1 || got.Approval["acct1"][0] != "delete_issue" {
		t.Fatalf("approval JSONB round-trip mismatch: %+v", got.Approval)
	}

	// nil Approval must not write SQL null into the NOT NULL JSONB column.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgappr-nil", Label: "Nil Approval",
		Tools: map[string][]string{"acct1": {"t1"}}}); err != nil {
		t.Fatalf("UpsertConnector (nil approval): %v", err)
	}
	gotNil, ok := s.VirtualConnector(ctx, "pgappr-nil")
	if !ok {
		t.Fatal("nil-approval connector not readable back")
	}
	if len(gotNil.Approval) != 0 {
		t.Fatalf("nil approval should read back empty, got %+v", gotNil.Approval)
	}

	// Persists across a fresh pool (and Connectors() carries it too).
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	found := false
	for _, c := range list {
		if c.Slug == "pgappr" {
			found = true
			if len(c.Approval["acct1"]) != 1 || c.Approval["acct1"][0] != "delete_issue" {
				t.Fatalf("Connectors() approval mismatch: %+v", c.Approval)
			}
		}
	}
	if !found {
		t.Fatal("Connectors() missing pgappr")
	}
}

// TestPgStoreConnectorGuardrails proves max_result_bytes and redact round-trip
// through Postgres (including nil Redact → '[]', never SQL null) and persist
// across a fresh pool.
func TestPgStoreConnectorGuardrails(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug IN ('pgguard','pgguard-nil')`)

	vc := VirtualConnector{
		Slug:           "pgguard",
		Label:          "Guarded",
		Tools:          map[string][]string{"acct1": {"get_issue"}},
		MaxResultBytes: 8192,
		Redact:         []string{`\bsk-[A-Za-z0-9]+\b`, `(?i)password`},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "pgguard")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if got.MaxResultBytes != 8192 {
		t.Fatalf("max_result_bytes round-trip: want 8192, got %d", got.MaxResultBytes)
	}
	if len(got.Redact) != 2 || got.Redact[0] != `\bsk-[A-Za-z0-9]+\b` || got.Redact[1] != `(?i)password` {
		t.Fatalf("redact JSONB round-trip mismatch: %+v", got.Redact)
	}

	// nil Redact / zero MaxResultBytes must not write SQL null and read back
	// as zero values.
	if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "pgguard-nil", Label: "Nil Guard",
		Tools: map[string][]string{"acct1": {"t1"}}}); err != nil {
		t.Fatalf("UpsertConnector (nil redact): %v", err)
	}
	gotNil, ok := s.VirtualConnector(ctx, "pgguard-nil")
	if !ok {
		t.Fatal("nil-guard connector not readable back")
	}
	if gotNil.MaxResultBytes != 0 || len(gotNil.Redact) != 0 {
		t.Fatalf("nil guard fields should read back zero, got %+v", gotNil)
	}

	// Persists across a fresh pool (and Connectors() carries the fields too).
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list, err := s2.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	found := false
	for _, c := range list {
		if c.Slug == "pgguard" {
			found = true
			if c.MaxResultBytes != 8192 || len(c.Redact) != 2 {
				t.Fatalf("Connectors() guardrail fields mismatch: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("Connectors() missing pgguard")
	}
}

// TestPgStorePendingCalls exercises the pending_calls ApprovalLog: insert,
// list newest-first, decide (status + decided_at), args JSONB round-trip.
func TestPgStorePendingCalls(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE id IN ('pc1','pc2')`)

	base := time.Now().Truncate(time.Millisecond)
	if err := s.LogPending(ctx, PendingCall{ID: "pc1", TS: base.Add(-time.Minute), Connector: "eng",
		Account: "acct1", Tool: "delete_issue", Args: map[string]any{"id": "42"}, Status: "pending"}); err != nil {
		t.Fatalf("LogPending pc1: %v", err)
	}
	// Zero TS gets stamped server-side-of-Go (now).
	if err := s.LogPending(ctx, PendingCall{ID: "pc2", Connector: "eng", Account: "acct1",
		Tool: "save_issue", Status: "pending"}); err != nil {
		t.Fatalf("LogPending pc2: %v", err)
	}

	list, err := s.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls: %v", err)
	}
	byID := map[string]PendingCall{}
	idx := map[string]int{}
	for i, p := range list {
		byID[p.ID] = p
		idx[p.ID] = i
	}
	p1, ok1 := byID["pc1"]
	p2, ok2 := byID["pc2"]
	if !ok1 || !ok2 {
		t.Fatalf("inserted rows missing from PendingCalls: %+v", list)
	}
	if idx["pc2"] > idx["pc1"] {
		t.Fatal("PendingCalls should be newest-first (pc2 before pc1)")
	}
	if p1.Args["id"] != "42" || p1.Status != "pending" || p1.DecidedAt != nil || p1.TS.IsZero() {
		t.Fatalf("pc1 round-trip mismatch: %+v", p1)
	}
	if p2.TS.IsZero() {
		t.Fatal("zero TS should have been stamped")
	}

	// Decision persists across a fresh pool.
	if err := s.SetDecision(ctx, "pc1", "denied"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	s2, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	list2, err := s2.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls (reopen): %v", err)
	}
	for _, p := range list2 {
		if p.ID == "pc1" {
			if p.Status != "denied" || p.DecidedAt == nil {
				t.Fatalf("decision not persisted: %+v", p)
			}
			return
		}
	}
	t.Fatal("pc1 missing after reopen")
}

// TestPgStoreFlightRecorder exercises the payload columns: encrypted at rest,
// hidden from list reads, decrypted by CallDetail, and purged by retention.
func TestPgStoreFlightRecorder(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer s.Close()
	defer s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account='fr-test'`)
	c, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	s.SetCipher(c)

	s.LogCall(CallRecord{
		Account: "fr-test", Tool: "save_issue", OK: true, Ms: 12,
		Connector: "eng", Decision: "approved", Guard: "truncated,redacted:2",
		Args: `{"secret":"payload-in"}`, Result: `{"secret":"payload-out"}`,
	})

	// LogCall is fire-and-forget — poll for the row.
	var got CallRecord
	deadline := time.Now().Add(5 * time.Second)
	for {
		list, err := s.RecentCalls(ctx, 50)
		if err != nil {
			t.Fatalf("RecentCalls: %v", err)
		}
		found := false
		for _, r := range list {
			if r.Account == "fr-test" {
				got, found = r, true
				break
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit row never appeared")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// List read: summary fields present (guard included — the Activity UI
	// chips on it), payloads absent.
	if got.ID == 0 || got.TS.IsZero() || got.Connector != "eng" || got.Decision != "approved" {
		t.Fatalf("summary fields mismatch: %+v", got)
	}
	if got.Guard != "truncated,redacted:2" {
		t.Fatalf("RecentCalls must include guard, got %q", got.Guard)
	}
	if got.Args != "" || got.Result != "" {
		t.Fatalf("RecentCalls must not return payloads: %+v", got)
	}

	// Detail read decrypts (and carries guard too).
	d, ok, err := s.CallDetail(ctx, got.ID)
	if err != nil || !ok {
		t.Fatalf("CallDetail: ok=%v err=%v", ok, err)
	}
	if d.Args != `{"secret":"payload-in"}` || d.Result != `{"secret":"payload-out"}` {
		t.Fatalf("payload round-trip mismatch: %+v", d)
	}
	if d.Guard != "truncated,redacted:2" {
		t.Fatalf("CallDetail guard mismatch: %q", d.Guard)
	}

	// At rest the payloads are encrypted, not plaintext.
	var rawArgs, rawResult string
	if err := s.pool.QueryRow(ctx, `SELECT args,result FROM tool_calls WHERE id=$1`, got.ID).Scan(&rawArgs, &rawResult); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if !strings.HasPrefix(rawArgs, "enc:v1:") || strings.Contains(rawArgs, "payload-in") {
		t.Fatalf("args not encrypted at rest: %q", rawArgs)
	}
	if !strings.HasPrefix(rawResult, "enc:v1:") || strings.Contains(rawResult, "payload-out") {
		t.Fatalf("result not encrypted at rest: %q", rawResult)
	}

	// Unknown ID is a clean miss.
	if _, ok, err := s.CallDetail(ctx, -1); ok || err != nil {
		t.Fatalf("unknown id: want (false,nil), got ok=%v err=%v", ok, err)
	}

	// Retention: an old row is purged, the fresh one survives.
	if _, err := s.pool.Exec(ctx, `INSERT INTO tool_calls (ts,account,tool,ok,ms) VALUES (now() - interval '48 hours','fr-test','old_tool',true,1)`); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	n, err := s.PurgeCalls(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PurgeCalls: %v", err)
	}
	if n < 1 {
		t.Fatalf("purge should delete the 48h-old row, deleted %d", n)
	}
	if _, ok, _ := s.CallDetail(ctx, got.ID); !ok {
		t.Fatal("purge must not delete fresh rows")
	}
	var oldCount int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM tool_calls WHERE account='fr-test' AND tool='old_tool'`).Scan(&oldCount)
	if oldCount != 0 {
		t.Fatal("old row still present after purge")
	}
}
