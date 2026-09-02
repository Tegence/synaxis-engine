package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testAuditWriterConfig(queueCapacity int) auditWriterConfig {
	return auditWriterConfig{
		queueCapacity:  queueCapacity,
		maxAttempts:    3,
		attemptTimeout: time.Second,
		retryDelay:     func(int) time.Duration { return 0 },
		logf:           func(string, ...any) {},
	}
}

func TestAuditWriterRetriesTransientWritesThenPersists(t *testing.T) {
	var attempts atomic.Int32
	w := newAuditWriter(func(context.Context, CallRecord) error {
		if attempts.Add(1) < 3 {
			return errors.New("temporary database reset")
		}
		return nil
	}, testAuditWriterConfig(4))

	w.enqueue(CallRecord{Account: "linear", Tool: "get_issue"})
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Fatalf("write attempts = %d, want 3", got)
	}
	stats := w.stats()
	if stats.Enqueued != 1 || stats.Persisted != 1 || stats.Retries != 2 || stats.Dropped != 0 || stats.Failures != 0 {
		t.Fatalf("unexpected writer stats: %+v", stats)
	}
}

func TestAuditWriterQueueIsBoundedAndNonBlocking(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	w := newAuditWriter(func(context.Context, CallRecord) error {
		startOnce.Do(func() { close(started) })
		<-release
		return nil
	}, testAuditWriterConfig(1))

	w.enqueue(CallRecord{Account: "first", Tool: "tool"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start the first record")
	}
	w.enqueue(CallRecord{Account: "second", Tool: "tool"})

	before := time.Now()
	w.enqueue(CallRecord{Account: "dropped", Tool: "tool"})
	if elapsed := time.Since(before); elapsed > 250*time.Millisecond {
		t.Fatalf("enqueue blocked for %s while queue was full", elapsed)
	}
	stats := w.stats()
	if stats.Enqueued != 2 || stats.Dropped != 1 || stats.QueueDepth != 1 {
		t.Fatalf("bounded queue stats before drain: %+v", stats)
	}

	close(release)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	stats = w.stats()
	if stats.Persisted != 2 || stats.Dropped != 1 {
		t.Fatalf("bounded queue stats after drain: %+v", stats)
	}
}

func TestAuditWriterShutdownDrainsAcceptedRecordsAndRejectsNewOnes(t *testing.T) {
	var (
		mu      sync.Mutex
		written []string
	)
	w := newAuditWriter(func(_ context.Context, rec CallRecord) error {
		mu.Lock()
		written = append(written, rec.Account)
		mu.Unlock()
		return nil
	}, testAuditWriterConfig(8))

	for _, account := range []string{"first", "second", "third"} {
		w.enqueue(CallRecord{Account: account, Tool: "tool"})
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	w.enqueue(CallRecord{Account: "after-shutdown", Tool: "tool"})

	mu.Lock()
	gotWritten := append([]string(nil), written...)
	mu.Unlock()
	if want := []string{"first", "second", "third"}; len(gotWritten) != len(want) {
		t.Fatalf("written = %v, want %v", gotWritten, want)
	} else {
		for i := range want {
			if gotWritten[i] != want[i] {
				t.Fatalf("written = %v, want %v", gotWritten, want)
			}
		}
	}
	stats := w.stats()
	if stats.Enqueued != 3 || stats.Persisted != 3 || stats.Dropped != 1 || stats.QueueDepth != 0 {
		t.Fatalf("unexpected shutdown stats: %+v", stats)
	}
}

func TestAuditWriterShutdownDeadlineCancelsWriteAndAccountsForQueue(t *testing.T) {
	started := make(chan struct{})
	w := newAuditWriter(func(ctx context.Context, _ CallRecord) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return ctx.Err()
	}, testAuditWriterConfig(4))
	w.enqueue(CallRecord{Account: "in-flight", Tool: "tool"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("writer did not begin in-flight record")
	}
	w.enqueue(CallRecord{Account: "queued", Tool: "tool"})

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := w.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want context deadline", err)
	}
	select {
	case <-w.done:
	case <-time.After(time.Second):
		t.Fatal("writer did not exit after its shutdown cancellation")
	}
	stats := w.stats()
	if stats.Dropped < 2 || stats.QueueDepth != 0 || stats.LastError == "" {
		t.Fatalf("deadline shutdown must account for in-flight and queued records: %+v", stats)
	}
}

func TestAuditWriterShutdownIsSafeWithConcurrentProducers(t *testing.T) {
	w := newAuditWriter(func(context.Context, CallRecord) error { return nil }, testAuditWriterConfig(32))
	var producers sync.WaitGroup
	for i := 0; i < 12; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for j := 0; j < 100; j++ {
				w.enqueue(CallRecord{Account: "concurrent", Tool: "tool"})
			}
		}()
	}
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- w.Shutdown(shutdownCtx)
	}()
	producers.Wait()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if stats := w.stats(); stats.QueueDepth != 0 {
		t.Fatalf("queue depth after concurrent shutdown = %d", stats.QueueDepth)
	}
}

func TestRetryableAuditWrite(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "cipher unavailable", err: ErrCipherUnavailable, want: false},
		{name: "invalid ciphertext", err: ErrInvalidCiphertext, want: false},
		{name: "cancelled", err: context.Canceled, want: false},
		{name: "generic connection reset", err: errors.New("connection reset"), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryableAuditWrite(test.err); got != test.want {
				t.Fatalf("retryableAuditWrite(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

// TestPgStoreAuditShutdownDrains covers the production wiring as well as the
// unit-tested writer: a row accepted before shutdown survives the pool close.
// It remains opt-in because Engine integration tests share a real Postgres
// schema through TEST_DATABASE_URL.
func TestPgStoreAuditShutdownDrains(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()
	const account = "audit-shutdown-drain-test"
	if _, err := store.pool.Exec(ctx, `DELETE FROM tool_calls WHERE account=$1`, account); err != nil {
		t.Fatalf("clean audit rows: %v", err)
	}
	store.LogCall(CallRecord{Account: account, Tool: "shutdown_drain", OK: true, Args: `{"input":true}`})
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	verifier, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer verifier.Close()
	defer func() {
		_, _ = verifier.pool.Exec(context.Background(), `DELETE FROM tool_calls WHERE account=$1`, account)
	}()
	rows, err := verifier.RecentCalls(ctx, 100)
	if err != nil {
		t.Fatalf("RecentCalls: %v", err)
	}
	for _, row := range rows {
		if row.Account == account && row.Tool == "shutdown_drain" {
			return
		}
	}
	t.Fatal("accepted audit record was not persisted before shutdown")
}

// Concurrent cold starts are normal with managed revisions. This gated test
// proves the session advisory lock serializes all bootstrap work rather than
// letting two PgStore constructors race idempotent DDL/backfills.
func TestPgStoreBootstrapSerializesConcurrentReplicas(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			store, err := NewPgStore(context.Background(), dsn)
			if err == nil {
				store.Close()
			}
			errs <- err
		}()
	}
	close(start)
	for range 2 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent NewPgStore: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("concurrent PgStore bootstrap did not complete")
		}
	}
}

// TestAuditWriterStatsReportStaticDropReason: the surfaced drop reason is a
// static category, never a driver error or record metadata, so an
// authenticated diagnostics response can show it without leaking content.
func TestAuditWriterStatsReportStaticDropReason(t *testing.T) {
	// Queue-full drop.
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	w := newAuditWriter(func(context.Context, CallRecord) error {
		startOnce.Do(func() { close(started) })
		<-release
		return nil
	}, testAuditWriterConfig(1))
	w.enqueue(CallRecord{Account: "first", Tool: "tool"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start the first record")
	}
	w.enqueue(CallRecord{Account: "queued", Tool: "tool"})
	w.enqueue(CallRecord{Account: "dropped-account", Tool: "dropped_tool"})
	stats := w.stats()
	if stats.Dropped != 1 || stats.LastDropReason != auditDropQueueFull {
		t.Fatalf("queue-full stats = %+v, want one drop with reason %q", stats, auditDropQueueFull)
	}
	if strings.Contains(stats.LastDropReason, "dropped-account") || strings.Contains(stats.LastDropReason, "dropped_tool") {
		t.Fatalf("drop reason leaked record metadata: %q", stats.LastDropReason)
	}
	close(release)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Insert-failure drop: LastError keeps the driver detail for logs, while
	// LastDropReason stays a static category.
	failing := newAuditWriter(func(context.Context, CallRecord) error {
		return errors.New("db down near secret-table")
	}, testAuditWriterConfig(1))
	failing.enqueue(CallRecord{Account: "linear", Tool: "save_issue"})
	shutdownCtx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := failing.Shutdown(shutdownCtx2); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	stats = failing.stats()
	if stats.Dropped != 1 || stats.Failures != 1 || stats.LastDropReason != auditDropInsertFailed {
		t.Fatalf("insert-failure stats = %+v, want one drop with reason %q", stats, auditDropInsertFailed)
	}
	if !strings.Contains(stats.LastError, "db down") {
		t.Fatalf("LastError should retain the driver detail for logs: %q", stats.LastError)
	}
}
