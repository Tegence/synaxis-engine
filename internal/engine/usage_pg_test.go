package engine

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPgUsageStoreDurabilityAtomicLimitsAndCrashRecovery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres usage integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_usage_reservations`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_usage_periods`)
	}
	cleanup()
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Second)
	identity := UsageIdentity{WorkspaceID: "usage-integration", EngineGeneration: 7}
	grant := UsageGrant{
		Identity: identity, PeriodStart: now.Add(-time.Minute),
		PeriodEnd: now.Add(24 * time.Hour), Revision: 1,
		PlanID: usageGrantPlan, Status: "active",
		Limits: UsageLimits{
			Calls: 3, RuntimeSeconds: 3, TransferBytes: 1_000,
			Concurrency: 2, RatePerMinute: 60, Burst: 2, MaxCallSeconds: 1,
		},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour),
		Digest: "grant-one",
	}
	if err := store.ApplyUsageGrant(ctx, grant); err != nil {
		t.Fatalf("apply grant: %v", err)
	}
	if err := store.ApplyUsageGrant(ctx, grant); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	refresh := grant
	refresh.IssuedAt = now
	refresh.ExpiresAt = now.Add(25 * time.Hour)
	refresh.Digest = "refreshed-assertion"
	if err := store.ApplyUsageGrant(ctx, refresh); err != nil {
		t.Fatalf("same-revision expiry refresh: %v", err)
	}
	refreshed, ok, err := store.CurrentUsage(ctx, identity, now)
	if err != nil || !ok || !refreshed.Grant.ExpiresAt.Equal(refresh.ExpiresAt) {
		t.Fatalf("refreshed grant = %+v ok=%v err=%v", refreshed.Grant, ok, err)
	}
	conflict := refresh
	conflict.Limits.Calls++
	conflict.Digest = "different-allowance"
	if err := store.ApplyUsageGrant(ctx, conflict); err == nil {
		t.Fatal("same revision with another allowance was accepted")
	}

	first, err := store.AdmitUsage(ctx, identity, now, UsageCallMeta{Account: "a", Tool: "one"})
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}
	second, err := store.AdmitUsage(ctx, identity, now, UsageCallMeta{Account: "a", Tool: "two"})
	if err != nil {
		t.Fatalf("second admission: %v", err)
	}
	if _, err := store.AdmitUsage(ctx, identity, now, UsageCallMeta{}); usageErrorCode(err) != "usage_concurrency_exhausted" {
		t.Fatalf("third concurrent admission = %v", err)
	}
	if err := store.SettleUsage(ctx, identity, first.ID, now.Add(500*time.Millisecond), 500, 100); err != nil {
		t.Fatalf("settle first: %v", err)
	}
	if _, err := store.AdmitUsage(ctx, identity, now, UsageCallMeta{}); usageErrorCode(err) != "usage_rate_limited" {
		t.Fatalf("burst admission = %v", err)
	}
	if err := store.SettleUsage(ctx, identity, second.ID, now.Add(750*time.Millisecond), 750, 200); err != nil {
		t.Fatalf("settle second: %v", err)
	}
	third, err := store.AdmitUsage(ctx, identity, now.Add(time.Second), UsageCallMeta{Replay: true})
	if err != nil {
		t.Fatalf("refilled admission: %v", err)
	}
	if err := store.SettleUsage(ctx, identity, third.ID, now.Add(1500*time.Millisecond), 500, 300); err != nil {
		t.Fatalf("settle third: %v", err)
	}
	if _, err := store.AdmitUsage(ctx, identity, now.Add(2*time.Second), UsageCallMeta{}); usageErrorCode(err) != "usage_calls_exhausted" {
		t.Fatalf("call-limit admission = %v", err)
	}
	period, ok, err := store.CurrentUsage(ctx, identity, now.Add(2*time.Second))
	if err != nil || !ok {
		t.Fatalf("current usage: ok=%v err=%v", ok, err)
	}
	if period.CallsUsed != 3 || period.RuntimeMilliseconds != 1_750 ||
		period.TransferBytesUsed != 600 || period.ActiveReservations != 0 {
		t.Fatalf("settled period = %+v", period)
	}

	raised := grant
	raised.Revision = 2
	raised.Digest = "grant-two"
	raised.Limits.Calls = 10
	raised.Limits.RuntimeSeconds = 30
	raised.Limits.TransferBytes = 10_000
	raised.Limits.Concurrency = 4
	raised.Limits.Burst = 10
	if err := store.ApplyUsageGrant(ctx, raised); err != nil {
		t.Fatalf("raise allowance: %v", err)
	}
	if err := store.ApplyUsageGrant(ctx, grant); err == nil {
		t.Fatal("stale revision was accepted")
	}
	period, ok, err = store.CurrentUsage(ctx, identity, now.Add(2*time.Second))
	if err != nil || !ok || period.CallsUsed != 3 || period.RuntimeMilliseconds != 1_750 {
		t.Fatalf("revision reset usage: period=%+v ok=%v err=%v", period, ok, err)
	}

	// A recent open reservation may belong to an old Cloud Run instance still
	// draining, so recovery waits for its signed one-second deadline.
	open, err := store.AdmitUsage(ctx, identity, now.Add(3*time.Second), UsageCallMeta{Tool: "crash"})
	if err != nil {
		t.Fatalf("crash admission: %v", err)
	}
	if count, err := store.RecoverUsageReservations(ctx, identity, now.Add(3500*time.Millisecond)); err != nil || count != 0 {
		t.Fatalf("early recovery count=%d err=%v", count, err)
	}
	if count, err := store.RecoverUsageReservations(ctx, identity, now.Add(4100*time.Millisecond)); err != nil || count != 1 {
		t.Fatalf("expired recovery count=%d err=%v", count, err)
	}
	// The original instance can race back after recovery. Settlement is
	// idempotent and must not add the call a second time.
	if err := store.SettleUsage(ctx, identity, open.ID, now.Add(5*time.Second), 10, 10); err != nil {
		t.Fatalf("late settlement: %v", err)
	}
	period, _, _ = store.CurrentUsage(ctx, identity, now.Add(5*time.Second))
	if period.RuntimeMilliseconds != 2_750 || period.ActiveReservations != 0 {
		t.Fatalf("recovered period = %+v", period)
	}

	// Row locking makes the signed concurrency cap authoritative even when
	// many MCP requests arrive simultaneously.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var admitted []UsageReservation
	var denied []error
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reservation, err := store.AdmitUsage(
				ctx, identity, now.Add(30*time.Second), UsageCallMeta{Tool: "parallel"},
			)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				denied = append(denied, err)
			} else {
				admitted = append(admitted, reservation)
			}
		}()
	}
	wg.Wait()
	if len(admitted) != 4 || len(denied) != 4 {
		t.Fatalf("parallel admissions=%d denied=%d errors=%v", len(admitted), len(denied), denied)
	}
	for _, err := range denied {
		if usageErrorCode(err) != "usage_concurrency_exhausted" {
			t.Fatalf("parallel denial = %v", err)
		}
	}
	for _, reservation := range admitted {
		if err := store.SettleUsage(ctx, identity, reservation.ID, now.Add(31*time.Second), 100, 1); err != nil {
			t.Fatalf("settle parallel: %v", err)
		}
	}

	// Calls already in flight are allowed to finish. Their settlement may
	// cross a runtime/transfer limit; the next admission is what fails.
	runtimeExhausted := raised
	runtimeExhausted.Revision = 3
	runtimeExhausted.Digest = "runtime-exhausted"
	runtimeExhausted.Limits.RuntimeSeconds = 3
	if err := store.ApplyUsageGrant(ctx, runtimeExhausted); err != nil {
		t.Fatalf("lower runtime grant: %v", err)
	}
	if _, err := store.AdmitUsage(ctx, identity, now.Add(32*time.Second), UsageCallMeta{}); usageErrorCode(err) != "usage_runtime_exhausted" {
		t.Fatalf("runtime-limit admission = %v", err)
	}
	transferExhausted := runtimeExhausted
	transferExhausted.Revision = 4
	transferExhausted.Digest = "transfer-exhausted"
	transferExhausted.Limits.RuntimeSeconds = 30
	transferExhausted.Limits.TransferBytes = 600
	if err := store.ApplyUsageGrant(ctx, transferExhausted); err != nil {
		t.Fatalf("lower transfer grant: %v", err)
	}
	if _, err := store.AdmitUsage(ctx, identity, now.Add(32*time.Second), UsageCallMeta{}); usageErrorCode(err) != "usage_transfer_exhausted" {
		t.Fatalf("transfer-limit admission = %v", err)
	}

	// Counters survive a new pool/process.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	persisted, ok, err := reopened.CurrentUsage(ctx, identity, now.Add(31*time.Second))
	if err != nil || !ok || persisted.CallsUsed != 8 ||
		persisted.RuntimeMilliseconds != 3_150 {
		t.Fatalf("persisted usage = %+v ok=%v err=%v", persisted, ok, err)
	}

	// A higher provisioning generation may replace the row in place while
	// preserving usage. Old instances immediately lose admission authority.
	nextGeneration := transferExhausted
	nextGeneration.Identity.EngineGeneration = 8
	nextGeneration.Revision = 5
	nextGeneration.Digest = "grant-generation-eight"
	if err := reopened.ApplyUsageGrant(ctx, nextGeneration); err != nil {
		t.Fatalf("generation update: %v", err)
	}
	if _, ok, err := reopened.CurrentUsage(ctx, identity, now.Add(31*time.Second)); err != nil || ok {
		t.Fatalf("old generation remained active: ok=%v err=%v", ok, err)
	}
	newIdentity := UsageIdentity{WorkspaceID: identity.WorkspaceID, EngineGeneration: 8}
	if current, ok, err := reopened.CurrentUsage(ctx, newIdentity, now.Add(31*time.Second)); err != nil ||
		!ok || current.CallsUsed != 8 {
		t.Fatalf("new generation usage = %+v ok=%v err=%v", current, ok, err)
	}
	if latest, ok, err := reopened.CurrentUsage(ctx, newIdentity, now.Add(48*time.Hour)); err != nil ||
		!ok || latest.CallsUsed != 8 {
		t.Fatalf("ended period must remain reportable: usage=%+v ok=%v err=%v", latest, ok, err)
	}
	if _, err := reopened.AdmitUsage(ctx, newIdentity, now.Add(48*time.Hour), UsageCallMeta{}); usageErrorCode(err) != "usage_grant_required" {
		t.Fatalf("ended period admitted a call: %v", err)
	}

	overlap := nextGeneration
	overlap.PeriodStart = now.Add(time.Hour)
	overlap.PeriodEnd = now.Add(25 * time.Hour)
	overlap.Revision = 6
	overlap.Digest = "overlap"
	if err := reopened.ApplyUsageGrant(ctx, overlap); err == nil {
		t.Fatal("overlapping billing period was accepted")
	}

	// Grant writes with different primary keys still serialize their overlap
	// checks. Exactly one of two concurrently inserted, intersecting future
	// periods may commit.
	futureA := nextGeneration
	futureA.PeriodStart = now.Add(48 * time.Hour)
	futureA.PeriodEnd = now.Add(72 * time.Hour)
	futureA.Revision = 7
	futureA.ExpiresAt = now.Add(50 * time.Hour)
	futureA.Digest = "future-a"
	futureB := futureA
	futureB.PeriodStart = now.Add(60 * time.Hour)
	futureB.PeriodEnd = now.Add(84 * time.Hour)
	futureB.Revision = 8
	futureB.ExpiresAt = now.Add(62 * time.Hour)
	futureB.Digest = "future-b"
	var grantWG sync.WaitGroup
	var grantMu sync.Mutex
	var grantErrors []error
	var grantSuccesses int
	for _, candidate := range []UsageGrant{futureA, futureB} {
		candidate := candidate
		grantWG.Add(1)
		go func() {
			defer grantWG.Done()
			err := reopened.ApplyUsageGrant(ctx, candidate)
			grantMu.Lock()
			defer grantMu.Unlock()
			if err != nil {
				grantErrors = append(grantErrors, err)
			} else {
				grantSuccesses++
			}
		}()
	}
	grantWG.Wait()
	if grantSuccesses != 1 || len(grantErrors) != 1 {
		t.Fatalf("concurrent overlap successes=%d errors=%v", grantSuccesses, grantErrors)
	}
	extendedCurrent := nextGeneration
	extendedCurrent.PeriodEnd = now.Add(70 * time.Hour)
	extendedCurrent.Revision = 9
	extendedCurrent.Digest = "current-period-overlap"
	if err := reopened.ApplyUsageGrant(ctx, extendedCurrent); err == nil {
		t.Fatal("revision extending an existing period into a future period was accepted")
	}
}

func TestPgUsageStoreSaturatesInFlightSettlementAtBigintBoundary(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres usage integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	cleanup := func() {
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_usage_reservations`)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_usage_periods`)
	}
	cleanup()
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Second)
	identity := UsageIdentity{WorkspaceID: "usage-bigint", EngineGeneration: 1}
	const maxInt64 = int64(1<<63 - 1)
	grant := UsageGrant{
		Identity: identity, PeriodStart: now.Add(-time.Minute),
		PeriodEnd: now.Add(time.Hour), Revision: 1,
		PlanID: usageGrantPlan, Status: "active",
		Limits: UsageLimits{
			Calls: 2, RuntimeSeconds: maxRuntimeGrantSeconds,
			TransferBytes: maxInt64, Concurrency: 1,
			RatePerMinute: 1, Burst: 1, MaxCallSeconds: 1,
		},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Digest: "bigint-grant",
	}
	if err := store.ApplyUsageGrant(ctx, grant); err != nil {
		t.Fatalf("apply bigint grant: %v", err)
	}
	reservation, err := store.AdmitUsage(ctx, identity, now, UsageCallMeta{Tool: "boundary"})
	if err != nil {
		t.Fatalf("admit bigint call: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
UPDATE narthex_usage_periods
SET runtime_milliseconds=$2,transfer_bytes_used=$2
WHERE period_start=$1`, grant.PeriodStart, maxInt64-50); err != nil {
		t.Fatalf("seed bigint boundary: %v", err)
	}
	if err := store.SettleUsage(
		ctx, identity, reservation.ID, now.Add(100*time.Millisecond), 100, 100,
	); err != nil {
		t.Fatalf("settle bigint boundary: %v", err)
	}
	period, ok, err := store.CurrentUsage(ctx, identity, now)
	if err != nil || !ok {
		t.Fatalf("read bigint usage: ok=%v err=%v", ok, err)
	}
	if period.RuntimeMilliseconds != maxInt64 ||
		period.TransferBytesUsed != maxInt64 ||
		period.ActiveReservations != 0 {
		t.Fatalf("bigint settlement did not saturate: %+v", period)
	}
}

func usageErrorCode(err error) string {
	var usageErr *UsageError
	if errors.As(err, &usageErr) {
		return usageErr.Code
	}
	return ""
}
