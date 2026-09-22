package engine

import (
	"os"
	"testing"
	"time"
)

func TestPgUsageExplicitHandoffPreservesPriorCounters(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	s, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The caller supplies a disposable database, as with the other usage contracts.
	if _, err = s.pool.Exec(ctx, `DELETE FROM narthex_usage_reservations`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `DELETE FROM narthex_usage_periods`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := UsageGrant{Identity: UsageIdentity{WorkspaceID: "handoff-test", EngineGeneration: 1}, PeriodStart: now.Add(-30 * 24 * time.Hour), PeriodEnd: now.Add(48 * time.Hour), Revision: 1, PlanID: "basic-v1", Status: "active", Limits: UsageLimits{Calls: 10, RuntimeSeconds: 100, TransferBytes: 1000, Concurrency: 2, RatePerMinute: 10, Burst: 2, MaxCallSeconds: 10}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Digest: "old"}
	if err = s.ApplyUsageGrant(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE narthex_usage_periods SET calls_used=7 WHERE period_start=$1`, old.PeriodStart); err != nil {
		t.Fatal(err)
	}
	next := old
	next.PeriodStart = now
	next.PeriodEnd = now.Add(30 * 24 * time.Hour)
	next.Revision = 2
	next.Digest = "next"
	if err = s.ApplyUsageGrant(ctx, next); err == nil {
		t.Fatal("unsigned overlap accepted")
	}
	wrong := old.PeriodStart.Add(-time.Hour)
	next.SupersedesPeriodStart = &wrong
	if err = s.ApplyUsageGrant(ctx, next); err == nil {
		t.Fatal("wrong prior period accepted")
	}
	next.SupersedesPeriodStart = &old.PeriodStart
	if err = s.ApplyUsageGrant(ctx, next); err != nil {
		t.Fatal(err)
	}
	var end time.Time
	var used int64
	if err = s.pool.QueryRow(ctx, `SELECT period_end,calls_used FROM narthex_usage_periods WHERE period_start=$1`, old.PeriodStart).Scan(&end, &used); err != nil {
		t.Fatal(err)
	}
	if !end.Equal(now) || used != 7 {
		t.Fatal("handoff lost old counters or left overlap")
	}
	if err = s.ApplyUsageGrant(ctx, next); err != nil {
		t.Fatal("handoff replay was not idempotent")
	}
	current, ok, err := s.CurrentUsage(ctx, old.Identity, now)
	if err != nil || !ok || current.CallsUsed != 0 {
		t.Fatal("new allowance did not open")
	}
}
