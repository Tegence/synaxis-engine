package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// The audit writer has one worker on purpose. Engine stores are capped at two
// database connections so a burst of governed calls must not turn audit
// persistence into either an unbounded goroutine set or a second workload
// that starves the control path. The queue bounds both memory and the amount
// of activity that can be lost if the database remains unavailable.
const (
	engineAuditQueueCapacity       = 256
	engineAuditWriteAttempts       = 3
	engineAuditWriteAttemptTimeout = 2 * time.Second
	engineAuditRetryBaseDelay      = 100 * time.Millisecond
	engineAuditCloseTimeout        = 5 * time.Second
)

type auditWriteFunc func(context.Context, CallRecord) error

type auditWriterConfig struct {
	queueCapacity  int
	maxAttempts    int
	attemptTimeout time.Duration
	retryDelay     func(attempt int) time.Duration
	logf           func(string, ...any)
}

func defaultAuditWriterConfig() auditWriterConfig {
	return auditWriterConfig{
		queueCapacity:  engineAuditQueueCapacity,
		maxAttempts:    engineAuditWriteAttempts,
		attemptTimeout: engineAuditWriteAttemptTimeout,
		retryDelay: func(attempt int) time.Duration {
			// 100ms, 200ms, ... The attempt number is one-based and this
			// function is only called before a retry.
			return engineAuditRetryBaseDelay * time.Duration(attempt)
		},
		logf: log.Printf,
	}
}

func normalizeAuditWriterConfig(config auditWriterConfig) auditWriterConfig {
	defaults := defaultAuditWriterConfig()
	if config.queueCapacity <= 0 {
		config.queueCapacity = defaults.queueCapacity
	}
	if config.maxAttempts <= 0 {
		config.maxAttempts = defaults.maxAttempts
	}
	if config.attemptTimeout <= 0 {
		config.attemptTimeout = defaults.attemptTimeout
	}
	if config.retryDelay == nil {
		config.retryDelay = defaults.retryDelay
	}
	if config.logf == nil {
		config.logf = defaults.logf
	}
	return config
}

// AuditPersistenceStats is a snapshot of the bounded durable-audit writer.
// It intentionally contains no request payloads or credentials; it is safe to
// report to an operator or future metrics exporter.
type AuditPersistenceStats struct {
	Enqueued   uint64
	Persisted  uint64
	Dropped    uint64
	Failures   uint64
	Retries    uint64
	QueueDepth int
	LastError  string
	// LastDropReason is a static category string (one of the auditDrop*
	// constants), never a driver error or record metadata, so an authenticated
	// diagnostics surface can report it without leaking record content.
	LastDropReason string
}

// Drop-reason categories are static strings safe to surface to operators.
// The detailed reason (which may name an account/tool) stays in logs and
// LastError.
const (
	auditDropQueueFull        = "queue_full_or_shutting_down"
	auditDropShutdownDeadline = "shutdown_deadline_expired"
	auditDropShutdownCancel   = "shutdown_cancelled"
	auditDropInsertFailed     = "insert_failed"
)

// auditWriter isolates the non-blocking, bounded persistence behavior from
// PgStore so it can be tested without a live Postgres instance. Producers hold
// producerMu's read lock while attempting their non-blocking send; shutdown
// takes the write lock before closing the queue, which prevents send-on-closed
// channel races.
type auditWriter struct {
	queue  chan CallRecord
	write  auditWriteFunc
	config auditWriterConfig

	producerMu sync.RWMutex
	accepting  bool
	stopOnce   sync.Once

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	enqueued       atomic.Uint64
	persisted      atomic.Uint64
	dropped        atomic.Uint64
	failures       atomic.Uint64
	retries        atomic.Uint64
	lastError      atomic.Value // string
	lastDropReason atomic.Value // string — one of the auditDrop* categories
}

func newAuditWriter(write auditWriteFunc, config auditWriterConfig) *auditWriter {
	config = normalizeAuditWriterConfig(config)
	ctx, cancel := context.WithCancel(context.Background())
	w := &auditWriter{
		queue:     make(chan CallRecord, config.queueCapacity),
		write:     write,
		config:    config,
		accepting: true,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	w.lastError.Store("")
	w.lastDropReason.Store("")
	go w.run()
	return w
}

func (w *auditWriter) enqueue(rec CallRecord) {
	if w == nil {
		return
	}
	if rec.TS.IsZero() {
		rec.TS = time.Now()
	}

	accepted := false
	w.producerMu.RLock()
	if w.accepting {
		select {
		case w.queue <- rec:
			w.enqueued.Add(1)
			accepted = true
		default:
		}
	}
	w.producerMu.RUnlock()
	if accepted {
		return
	}

	// The governed call already completed. Do not make its request path wait
	// for database recovery or another caller to free queue capacity.
	w.recordDrop(auditDropQueueFull, "audit queue is full or shutting down", nil)
}

func (w *auditWriter) run() {
	defer close(w.done)
	for rec := range w.queue {
		if w.ctx.Err() != nil {
			w.recordDrop(auditDropShutdownDeadline, "audit shutdown deadline expired", w.ctx.Err())
			w.discardQueued()
			return
		}
		w.persist(rec)
	}
}

func (w *auditWriter) persist(rec CallRecord) {
	if w.write == nil {
		w.fail(rec, errors.New("audit persistence is not configured"), 0)
		return
	}

	var lastErr error
	for attempt := 1; attempt <= w.config.maxAttempts; attempt++ {
		if err := w.ctx.Err(); err != nil {
			w.recordDrop(auditDropShutdownCancel, "audit shutdown cancelled a pending record", err)
			return
		}

		attemptCtx, cancel := context.WithTimeout(w.ctx, w.config.attemptTimeout)
		err := w.write(attemptCtx, rec)
		cancel()
		if err == nil {
			w.persisted.Add(1)
			return
		}
		lastErr = err
		if !retryableAuditWrite(err) || attempt == w.config.maxAttempts {
			w.fail(rec, err, attempt)
			return
		}

		w.retries.Add(1)
		if !w.waitForRetry(attempt) {
			w.recordDrop(auditDropShutdownCancel, "audit shutdown cancelled a retry", w.ctx.Err())
			return
		}
	}

	// The loop always returns, but retain a defensive failure path if a future
	// config change makes its bounds non-obvious.
	w.fail(rec, lastErr, w.config.maxAttempts)
}

func (w *auditWriter) waitForRetry(attempt int) bool {
	delay := w.config.retryDelay(attempt)
	if delay <= 0 {
		return w.ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-w.ctx.Done():
		return false
	}
}

// retryableAuditWrite keeps deterministic data/configuration errors from
// filling the worker with pointless retries, while still retrying transient
// network, connection, lock, and serialization failures. Unknown driver
// errors are retried within the fixed attempt budget because they are commonly
// connection resets surfaced by a driver-specific wrapper.
func retryableAuditWrite(err error) bool {
	if err == nil || errors.Is(err, ErrCipherUnavailable) || errors.Is(err, ErrInvalidCiphertext) || errors.Is(err, context.Canceled) {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return true
	}
	if strings.HasPrefix(pgErr.Code, "08") || strings.HasPrefix(pgErr.Code, "40") {
		return true // connection exception, serialization failure, or deadlock
	}
	switch pgErr.Code {
	case "53300", // too_many_connections
		"55P03", // lock_not_available
		"57P01", // admin_shutdown
		"57P02", // crash_shutdown
		"57P03": // cannot_connect_now
		return true
	default:
		return false
	}
}

func (w *auditWriter) fail(rec CallRecord, err error, attempts int) {
	w.failures.Add(1)
	w.recordDrop(auditDropInsertFailed, fmt.Sprintf("audit insert failed after %d attempt(s) for %s/%s", attempts, rec.Account, rec.Tool), err)
}

func (w *auditWriter) recordDrop(category, reason string, err error) {
	n := w.dropped.Add(1)
	w.lastDropReason.Store(category)
	if err != nil {
		w.lastError.Store(err.Error())
	} else {
		w.lastError.Store(reason)
	}
	// A queue-full storm should be visible without turning an outage into a
	// second disk/CPU incident. The first drop and each hundredth are logged;
	// the exact total remains available through AuditPersistenceStats.
	if n == 1 || n%100 == 0 {
		if err != nil {
			w.config.logf("engine: audit record dropped (%s; total=%d): %v", reason, n, err)
			return
		}
		w.config.logf("engine: audit record dropped (%s; total=%d)", reason, n)
	}
}

func (w *auditWriter) discardQueued() {
	var discarded uint64
	for range w.queue {
		discarded++
	}
	if discarded == 0 {
		return
	}
	w.dropped.Add(discarded)
	w.lastError.Store("audit shutdown deadline expired")
	w.lastDropReason.Store(auditDropShutdownDeadline)
	w.config.logf("engine: audit shutdown discarded %d queued record(s) after its drain deadline", discarded)
}

func (w *auditWriter) beginShutdown() {
	w.stopOnce.Do(func() {
		w.producerMu.Lock()
		w.accepting = false
		close(w.queue)
		w.producerMu.Unlock()
	})
}

// Shutdown stops accepting records and drains the already-accepted bounded
// queue. If the caller's deadline expires, it cancels the in-flight database
// operation and accounts for the remaining queued records as deliberate,
// observable loss rather than leaking a worker past process shutdown.
func (w *auditWriter) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.beginShutdown()
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		w.cancel()
		return fmt.Errorf("drain audit queue: %w", ctx.Err())
	}
}

func (w *auditWriter) stats() AuditPersistenceStats {
	if w == nil {
		return AuditPersistenceStats{}
	}
	lastError, _ := w.lastError.Load().(string)
	lastDropReason, _ := w.lastDropReason.Load().(string)
	return AuditPersistenceStats{
		Enqueued:       w.enqueued.Load(),
		Persisted:      w.persisted.Load(),
		Dropped:        w.dropped.Load(),
		Failures:       w.failures.Load(),
		Retries:        w.retries.Load(),
		QueueDepth:     len(w.queue),
		LastError:      lastError,
		LastDropReason: lastDropReason,
	}
}
