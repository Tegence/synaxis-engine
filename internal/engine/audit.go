package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// CallRecord is one tool invocation through the gateway — the unit of "see what
// Claude actually did end to end". Args/Result are the (optional, size-capped)
// recorded payloads: list reads return them EMPTY; only CallDetail carries them.
type CallRecord struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	Account   string    `json:"account"`
	Tool      string    `json:"tool"`
	OK        bool      `json:"ok"`
	Ms        int64     `json:"ms"`
	Error     string    `json:"error,omitempty"`
	Connector string    `json:"connector,omitempty"` // "" = default /mcp endpoint
	Decision  string    `json:"decision,omitempty"`  // ""|approved|denied|expired|replay
	Args      string    `json:"args,omitempty"`      // detail-only (never in list reads)
	Result    string    `json:"result,omitempty"`    // detail-only (never in list reads)

	// Guard is the comma-joined response-guardrail markers applied to this
	// call's result ("truncated", "redacted:N", "flagged:injection"). Tiny,
	// so unlike Args/Result it IS included in list reads — the Activity UI
	// chips on it. Empty = no guardrail fired (or raw /mcp endpoint).
	Guard string `json:"guard,omitempty"`

	// Triage records the operator's durable disposition for a flagged result:
	// "blocked", "approval_required", or "false_positive". Empty means the
	// finding still needs attention.
	Triage string `json:"triage,omitempty"`
}

// AuditSink records and reads back tool-call activity. PgStore persists it;
// FileStore keeps an in-memory ring for local dev. LogCall stamps TS when it
// is zero. RecentCalls is summary-only (Args/Result always empty); CallDetail
// returns the full record including payloads.
type AuditSink interface {
	LogCall(rec CallRecord)
	RecentCalls(ctx context.Context, limit int) ([]CallRecord, error)
	CallDetail(ctx context.Context, id int64) (CallRecord, bool, error)
}

// AuditTriage is the optional mutation facet for durable flagged-result
// decisions. Both built-in stores implement it.
type AuditTriage interface {
	SetCallTriage(ctx context.Context, id int64, triage string) error
}

// AuditPurger is the retention facet — implemented by stores that can delete
// audit rows older than a cutoff. Discovered by type assertion, same as
// AuditSink (FileStore's ring self-bounds, so its purge is a no-op).
type AuditPurger interface {
	PurgeCalls(ctx context.Context, olderThan time.Duration) (int64, error)
}

func clampErr(s string) string {
	if len(s) > 500 {
		return s[:runeBoundary(s, 500)]
	}
	return s
}

// runeBoundary backs max up (at most 3 bytes) so s[:max] never splits a
// multi-byte UTF-8 rune — Postgres rejects invalid UTF-8 TEXT outright, which
// would silently drop the whole audit row on the fire-and-forget insert path.
func runeBoundary(s string, max int) int {
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return max
}

// maxPayloadBytes caps each recorded payload side (args, result) at 32KB.
const maxPayloadBytes = 32 * 1024

const truncatedSuffix = "...[truncated]"

// clampPayload truncates s to at most max bytes (on a rune boundary),
// appending a marker so the inspector shows the cut honestly (same spirit as
// clampErr, but visible).
func clampPayload(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:runeBoundary(s, max)] + truncatedSuffix
}

// ---- FileStore: in-memory ring (local dev) ----

type ring struct {
	mu     sync.Mutex
	buf    []CallRecord
	cap    int
	nextID int64 // synthetic incrementing ID for CallDetail lookups
}

func (r *ring) LogCall(rec CallRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cap == 0 {
		r.cap = 500
	}
	if rec.TS.IsZero() {
		rec.TS = time.Now()
	}
	r.nextID++
	rec.ID = r.nextID
	rec.Error = clampErr(rec.Error)
	rec.Args = clampPayload(rec.Args, maxPayloadBytes)
	rec.Result = clampPayload(rec.Result, maxPayloadBytes)
	r.buf = append(r.buf, rec)
	if len(r.buf) > r.cap {
		r.buf = r.buf[len(r.buf)-r.cap:]
	}
}

func (r *ring) RecentCalls(_ context.Context, limit int) ([]CallRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CallRecord, 0, limit)
	for i := len(r.buf) - 1; i >= 0 && len(out) < limit; i-- {
		c := r.buf[i]
		c.Args, c.Result = "", "" // summary only — payloads live behind CallDetail
		out = append(out, c)
	}
	return out, nil
}

func (r *ring) CallDetail(_ context.Context, id int64) (CallRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.buf) - 1; i >= 0; i-- {
		if r.buf[i].ID == id {
			return r.buf[i], true, nil
		}
	}
	return CallRecord{}, false, nil
}

func (r *ring) SetCallTriage(_ context.Context, id int64, triage string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.buf) - 1; i >= 0; i-- {
		if r.buf[i].ID == id {
			r.buf[i].Triage = triage
			return nil
		}
	}
	return fmt.Errorf("call %d not found", id)
}
