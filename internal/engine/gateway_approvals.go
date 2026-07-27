package engine

// Approval flow: a require_approval tool call PARKS — the connector handler
// records a PendingCall (the audit row), fires the alert webhook, and blocks
// on an in-process channel until the console decides or the timeout hits.
// Single-instance semantics on purpose: the DB row is the record, the wait
// lives in this process (same trade as the in-memory pending OAuth flows).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const defaultApprovalTimeout = 180 * time.Second

// approvalLog returns the store's ApprovalLog facet, if it has one (same
// pattern as the AuditSink / ConnectorStore type-asserts).
func (g *Gateway) approvalLog() (ApprovalLog, bool) {
	al, ok := g.store.(ApprovalLog)
	return al, ok
}

// SetApprovalTimeout overrides how long an approval-gated call waits for a
// decision (wired from APPROVAL_TIMEOUT_SECONDS; default 180s).
func (g *Gateway) SetApprovalTimeout(d time.Duration) { g.approvalTimeout = d }

// SetConsoleURL sets the console link included in approval webhook messages.
func (g *Gateway) SetConsoleURL(u string) { g.consoleURL = u }

func (g *Gateway) approvalWait() time.Duration {
	if g.approvalTimeout > 0 {
		return g.approvalTimeout
	}
	return defaultApprovalTimeout
}

// PendingApprovals lists recorded approval calls for the console (newest
// first). nil when the store has no approval support — mirrors RecentCalls.
func (g *Gateway) PendingApprovals(ctx context.Context) ([]PendingCall, error) {
	al, ok := g.approvalLog()
	if !ok {
		return nil, nil
	}
	return al.PendingCalls(ctx)
}

// registerWait creates the decision channel for id. Called BEFORE the pending
// row and webhook exist, so a fast console decision can never miss the waiter.
func (g *Gateway) registerWait(id string) {
	g.approveMu.Lock()
	defer g.approveMu.Unlock()
	if g.approveCh == nil {
		g.approveCh = map[string]chan string{}
	}
	g.approveCh[id] = make(chan string, 1) // buffered: Decide never blocks
}

// dropWait removes the channel without recording a decision (bookkeeping for
// the record-failed path).
func (g *Gateway) dropWait(id string) {
	g.approveMu.Lock()
	delete(g.approveCh, id)
	g.approveMu.Unlock()
}

// Decide resolves a pending approval: records the decision in the store AND
// signals the parked handler. Unknown or already-decided ids are an error.
func (g *Gateway) Decide(ctx context.Context, id, status string) error {
	if status != "approved" && status != "denied" {
		return fmt.Errorf("invalid decision %q (want \"approved\" or \"denied\")", status)
	}
	g.approveMu.Lock()
	ch, ok := g.approveCh[id]
	if ok {
		delete(g.approveCh, id)
	}
	g.approveMu.Unlock()
	if !ok {
		return fmt.Errorf("pending call %q unknown or already decided", id)
	}
	if al, has := g.approvalLog(); has {
		if err := al.SetDecision(ctx, id, status); err != nil {
			// The parked waiter matters more than the audit row — log, still signal.
			log.Printf("engine: approval %s decision %q not recorded: %v", id, status, err)
		}
	}
	ch <- status
	return nil
}

// WaitDecision parks until Decide signals id, the timeout lapses, or ctx is
// cancelled. Timeout/cancel mark the record expired (best-effort) and clean
// up the channel.
func (g *Gateway) WaitDecision(ctx context.Context, id string, timeout time.Duration) (approved bool, reason string) {
	g.approveMu.Lock()
	ch, ok := g.approveCh[id]
	if !ok { // not pre-registered (direct callers) — register now
		if g.approveCh == nil {
			g.approveCh = map[string]chan string{}
		}
		ch = make(chan string, 1)
		g.approveCh[id] = ch
	}
	g.approveMu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case status := <-ch:
		return status == "approved", status
	case <-timer.C:
	case <-ctx.Done():
	}
	// Timed out / cancelled. If Decide won the race (channel already removed
	// and signalled), honor its answer instead of expiring.
	g.approveMu.Lock()
	_, still := g.approveCh[id]
	if still {
		delete(g.approveCh, id)
	}
	g.approveMu.Unlock()
	if !still {
		// Only Decide removes the entry (dropWait runs before any wait, and the
		// id is unique to this waiter), and Decide ALWAYS sends on the buffered
		// channel after the delete — but its send can lag the delete by a full
		// store write. Block for it; a non-blocking drain here would drop a
		// granted approval and race an "expired" write against Decide's record.
		status := <-ch
		return status == "approved", status
	}
	if al, has := g.approvalLog(); has { // best-effort: the waiter is gone either way
		if err := al.SetDecision(context.Background(), id, "expired"); err != nil {
			log.Printf("engine: approval %s not marked expired: %v", id, err)
		}
	}
	return false, "expired"
}

func newApprovalID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano()) // rand never fails in practice
	}
	return hex.EncodeToString(b)
}

// approvalHandler wraps a cached tool handler so calls on this connector park
// for a human decision before dispatching upstream. Deny/timeout returns an
// MCP tool error result (isError), NOT a protocol error.
func (g *Gateway) approvalHandler(connector, account, bare string, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		al, ok := g.approvalLog()
		if !ok {
			// FAIL CLOSED: a gated tool must never dispatch without a record.
			return mcp.NewToolResultError("approval required, but this store does not support approvals — call blocked"), nil
		}
		id := newApprovalID()
		g.registerWait(id) // before the row/webhook: a fast decision must find the waiter
		p := PendingCall{
			ID: id, TS: time.Now(), Connector: connector, Account: account,
			Tool: bare, Args: req.GetArguments(), Status: "pending",
		}
		if err := al.LogPending(ctx, p); err != nil {
			g.dropWait(id)
			return mcp.NewToolResultError("approval required, but the pending call could not be recorded: " + err.Error()), nil
		}
		msg := fmt.Sprintf("⏸️ Synaxis: approval needed — %s: %s·%s.", connector, account, bare)
		if g.consoleURL != "" {
			msg += " Approve in console: " + g.consoleURL
		}
		g.fireAlert(msg)
		start := time.Now()
		ok, reason := g.WaitDecision(ctx, id, g.approvalWait())
		if !ok {
			outcome := "approval denied"
			if reason == "expired" {
				outcome = "approval expired"
			}
			if g.audit != nil {
				rec := CallRecord{
					Account: account, Tool: bare, OK: false,
					Ms: time.Since(start).Milliseconds(), Error: outcome,
					Connector: connector, Decision: reason,
				}
				// Recording connectors capture what WOULD have been sent, so
				// a denied/expired call is replayable (with force) later.
				if sc := auditScopeFrom(ctx); sc != nil && sc.record {
					rec.Args = marshalPayload(req.GetArguments())
				}
				g.audit.LogCall(rec)
			}
			return mcp.NewToolResultError(outcome + " — the call was not sent upstream"), nil
		}
		// Approved: the wrapped dispatch closure writes the (single) audit row;
		// stamp the decision into the scope so it lands there.
		if sc := auditScopeFrom(ctx); sc != nil {
			sc.decision = reason
		}
		return inner(ctx, req)
	}
}
