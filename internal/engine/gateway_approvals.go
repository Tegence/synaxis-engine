package engine

// Approval flow: a require_approval tool call PARKS — the connector handler
// records a PendingCall, fires the alert webhook, and waits for a durable human
// decision. The original MCP request remains the only thing that may dispatch
// upstream. We never replay a stored tool call after a restart: generic MCP
// arguments are not a safe durable command format.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	defaultApprovalTimeout       = 180 * time.Second
	approvalDecisionPollInterval = 250 * time.Millisecond
	approvalWriteTimeout         = 5 * time.Second
)

// approvalLog returns the store's ApprovalLog facet, if it has one (same
// pattern as the AuditSink / ConnectorStore type-asserts).
func (g *Gateway) approvalLog() (ApprovalLog, bool) {
	al, ok := g.store.(ApprovalLog)
	return al, ok
}

// approvalLifecycle is required for a gated call. The older ApprovalLog
// surface is intentionally insufficient: an Engine must not release a parked
// call until its decision has survived a conditional durable write.
func (g *Gateway) approvalLifecycle() (ApprovalLifecycle, bool) {
	al, ok := g.store.(ApprovalLifecycle)
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
func (g *Gateway) registerWait(id string) chan string {
	g.approveMu.Lock()
	defer g.approveMu.Unlock()
	if g.approveCh == nil {
		g.approveCh = map[string]chan string{}
	}
	ch := make(chan string, 1) // buffered: a persisted decision never blocks
	g.approveCh[id] = ch
	return ch
}

// waitFor returns the existing waiter, registering one for direct callers.
func (g *Gateway) waitFor(id string) chan string {
	g.approveMu.Lock()
	defer g.approveMu.Unlock()
	if g.approveCh == nil {
		g.approveCh = map[string]chan string{}
	}
	if ch, ok := g.approveCh[id]; ok {
		return ch
	}
	ch := make(chan string, 1)
	g.approveCh[id] = ch
	return ch
}

// dropWait is only used when LogPending failed, so there is no durable row to
// transition. All normal terminal paths call dropWaitIf only after observing a
// durable terminal state.
func (g *Gateway) dropWait(id string) {
	g.approveMu.Lock()
	delete(g.approveCh, id)
	g.approveMu.Unlock()
}

func (g *Gateway) dropWaitIf(id string, expected chan string) bool {
	g.approveMu.Lock()
	defer g.approveMu.Unlock()
	current, ok := g.approveCh[id]
	if !ok || current != expected {
		return false
	}
	delete(g.approveCh, id)
	return true
}

func (g *Gateway) takeWait(id string) (chan string, bool) {
	g.approveMu.Lock()
	defer g.approveMu.Unlock()
	ch, ok := g.approveCh[id]
	if ok {
		delete(g.approveCh, id)
	}
	return ch, ok
}

func approvalWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	// An MCP caller may disconnect at exactly the moment a terminal state must
	// be committed. Persist against a bounded detached context so an approved
	// or cancelled state is never skipped solely because the caller disappeared.
	return context.WithTimeout(context.WithoutCancel(ctx), approvalWriteTimeout)
}

// Decide resolves a pending approval using the backwards-compatible minimal
// call shape. Console callers that can provide audit metadata use
// DecideWithMetadata.
func (g *Gateway) Decide(ctx context.Context, id, status string) error {
	_, err := g.DecideWithMetadata(ctx, id, ApprovalDecision{Status: status})
	return err
}

// DecideWithMetadata commits a compare-and-swap decision BEFORE it removes or
// signals any local waiter. A second identical button press is idempotent; a
// contradictory decision gets ErrApprovalNotPending.
func (g *Gateway) DecideWithMetadata(ctx context.Context, id string, decision ApprovalDecision) (PendingCall, error) {
	al, ok := g.approvalLifecycle()
	if !ok {
		return PendingCall{}, fmt.Errorf("approvals require a durable lifecycle store")
	}
	writeCtx, cancel := approvalWriteContext(ctx)
	defer cancel()
	// Recheck the parked call's durable ownership binding before a decision is
	// committed. MoveAccountToConnectionNamespace also cancels pending calls in
	// its own store transaction, so either the move wins (and this returns a
	// terminal cancellation) or this decision wins before it. In the latter
	// case approvalHandler and the cached dispatch closure both revalidate again
	// immediately before upstream work, so an ownership move can never turn a
	// previously-authorized decision into credential access.
	if existing, found, readErr := al.ApprovalCall(writeCtx, id); readErr != nil {
		return PendingCall{}, readErr
	} else if found && existing.Status == ApprovalPending && !g.pendingCallBindingLive(existing) {
		cancelled, cancelErr := al.CancelPending(writeCtx, id, "engine", "connection ownership changed while approval was pending")
		if cancelErr == nil {
			if ch, live := g.takeWait(id); live {
				ch <- cancelled.Status
			}
			return cancelled, ErrApprovalNotPending
		}
		return cancelled, cancelErr
	}
	p, err := al.DecidePending(writeCtx, id, decision)
	if err != nil {
		// A move/cancel or another Engine's terminal decision may have won after
		// the pre-read above. Wake a local waiter promptly; otherwise it will
		// still observe the durable state on its polling interval.
		switch p.Status {
		case ApprovalApproved, ApprovalDenied, ApprovalExpired, ApprovalCancelled:
			if ch, live := g.takeWait(id); live {
				ch <- p.Status
			}
		}
		// Keep the visible lifecycle truthful when an Approve/Deny arrives
		// after the persisted deadline but before a waiter/sweeper marked it.
		if errors.Is(err, ErrApprovalExpired) {
			if expired, expireErr := al.ExpirePending(writeCtx, id, time.Now()); expireErr == nil {
				return expired, ErrApprovalExpired
			}
		}
		return p, err
	}

	// The row is terminal and durable at this point. It is safe to release a
	// local waiter, if this instance owns one. Waiters on another instance poll
	// the durable row and will see the same state.
	if ch, live := g.takeWait(id); live {
		ch <- p.Status
	}
	return p, nil
}

// pendingCallBindingLive verifies the credential generation captured when a
// request was parked. Unbound historical rows remain readable in approval
// history, but only Gateway-created calls reach this dispatch path and those
// always carry a complete binding.
func (g *Gateway) pendingCallBindingLive(p PendingCall) bool {
	if p.AccountIncarnationID == "" && p.AccountRevision == 0 && p.ConnectionNamespaceID == "" {
		return true // legacy audit-only record; it has no in-flight Gateway waiter
	}
	account, found := g.store.Account(p.Account)
	return found && pendingCallBoundToAccount(p, account)
}

// WaitDecision parks until a local signal, a durable decision from any Engine
// instance, the approval deadline, or caller cancellation. It never dispatches
// on a state that was only in memory.
func (g *Gateway) WaitDecision(ctx context.Context, id string, timeout time.Duration) (approved bool, reason string) {
	ch := g.waitFor(id)
	if timeout <= 0 {
		timeout = defaultApprovalTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	poll := time.NewTicker(approvalDecisionPollInterval)
	defer poll.Stop()

	for {
		select {
		case status := <-ch:
			return status == ApprovalApproved, status
		case <-poll.C:
			if resolved, approved, status := g.observeDurableDecision(ctx, id, ch); resolved {
				return approved, status
			}
		case <-timer.C:
			return g.finishWait(ctx, id, ch, ApprovalExpired)
		case <-ctx.Done():
			return g.finishWait(ctx, id, ch, ApprovalCancelled)
		}
	}
}

// observeDurableDecision allows a waiter running on one instance to observe a
// console decision written through another. Read failures deliberately keep
// the call parked; failure closed is safer than guessing a decision.
func (g *Gateway) observeDurableDecision(ctx context.Context, id string, ch chan string) (resolved, approved bool, status string) {
	al, ok := g.approvalLifecycle()
	if !ok {
		return true, false, "unavailable"
	}
	readCtx, cancel := approvalWriteContext(ctx)
	defer cancel()
	p, found, err := al.ApprovalCall(readCtx, id)
	if err != nil || !found {
		return false, false, ""
	}
	switch p.Status {
	case ApprovalApproved, ApprovalDenied, ApprovalExpired, ApprovalCancelled:
		// The durable transition happened before this bookkeeping deletion.
		g.dropWaitIf(id, ch)
		return true, p.Status == ApprovalApproved, p.Status
	default:
		return false, false, ""
	}
}

// finishWait reaches the terminal state through the store's conditional
// transition. If another actor won the race, the row returned with the error
// is inspected and honored. If persistence is unavailable at the terminal
// time we drop the waiter and fail closed: the durable row remains the
// authority, and the waiter map is only a wake-up optimization.
func (g *Gateway) finishWait(ctx context.Context, id string, ch chan string, wanted string) (approved bool, reason string) {
	al, ok := g.approvalLifecycle()
	if !ok {
		return false, "unavailable"
	}
	writeCtx, cancel := approvalWriteContext(ctx)
	defer cancel()
	now := time.Now()
	var (
		p   PendingCall
		err error
	)
	if wanted == ApprovalExpired {
		p, err = al.ExpirePending(writeCtx, id, now)
	} else {
		// If the actual persisted deadline elapsed while the request context
		// was being cancelled, expire rather than mislabel it cancelled.
		if existing, found, readErr := al.ApprovalCall(writeCtx, id); readErr == nil && found && approvalIsDue(existing, now) {
			p, err = al.ExpirePending(writeCtx, id, now)
		} else if readErr != nil {
			return false, "unavailable"
		} else {
			p, err = al.CancelPending(writeCtx, id, "engine", "MCP request cancelled before approval")
		}
	}
	if err == nil {
		g.dropWaitIf(id, ch)
		return p.Status == ApprovalApproved, p.Status
	}

	// A concurrent decision/expiry is not an infrastructure failure. The
	// returned record is authoritative, and was committed before it is used.
	switch p.Status {
	case ApprovalApproved, ApprovalDenied, ApprovalExpired, ApprovalCancelled:
		g.dropWaitIf(id, ch)
		return p.Status == ApprovalApproved, p.Status
	}
	g.dropWaitIf(id, ch)
	return false, "unavailable"
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
func (g *Gateway) approvalHandler(connector string, account Account, bare string, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// A global tool-governance policy can be nested inside a real connector
		// or client endpoint. Keep the approval/audit record attributed to that
		// outer delivery surface when one exists; otherwise the stable policy
		// scope makes the reason for the approval visible to operators.
		approvalConnector := connector
		if sc := auditScopeFrom(ctx); sc != nil && sc.connector != "" {
			approvalConnector = sc.connector
		}
		al, hasLog := g.approvalLog()
		if !hasLog {
			// FAIL CLOSED: a gated tool must never dispatch without a record.
			return mcp.NewToolResultError("approval required, but this store does not support approvals — call blocked"), nil
		}
		if _, durable := g.approvalLifecycle(); !durable {
			return mcp.NewToolResultError("approval required, but this store cannot durably transition approvals — call blocked"), nil
		}
		// A static connector server can briefly retain a tool from a prior
		// account projection. Never create a fresh pending action from that stale
		// surface: account name/incarnation alone are not enough because a move
		// deliberately preserves both.
		if !g.accountSnapshotLive(account.Name, account.IncarnationID, account.Revision, account.URL) {
			return mcp.NewToolResultError("this connection changed; refresh the MCP tool list"), nil
		}
		id := newApprovalID()
		g.registerWait(id) // before the row/webhook: a fast decision must find the waiter
		now := time.Now()
		expires := now.Add(g.approvalWait())
		p := PendingCall{
			ID: id, TS: now, ExpiresAt: &expires, Connector: approvalConnector, Account: account.Name,
			Tool: bare, Args: req.GetArguments(), Status: ApprovalPending,
			AccountIncarnationID: account.IncarnationID, AccountRevision: account.Revision,
			ConnectionNamespaceID: account.ConnectionNamespaceID,
		}
		if err := al.LogPending(ctx, p); err != nil {
			g.dropWait(id)
			return mcp.NewToolResultError("approval required, but the pending call could not be recorded: " + err.Error()), nil
		}
		msg := fmt.Sprintf("⏸️ Synaxis: approval needed — %s: %s·%s.", approvalConnector, account.Name, bare)
		if g.consoleURL != "" {
			msg += " Approve in console: " + g.consoleURL
		}
		g.fireAlert(msg)
		start := time.Now()
		ok, reason := g.WaitDecision(ctx, id, g.approvalWait())
		if !ok {
			outcome := "approval denied"
			switch reason {
			case ApprovalExpired:
				outcome = "approval expired"
			case ApprovalCancelled:
				outcome = "approval cancelled"
			case "unavailable":
				outcome = "approval could not be finalized safely"
			}
			if g.audit != nil {
				rec := CallRecord{
					Account: account.Name, Tool: bare, OK: false,
					Ms: time.Since(start).Milliseconds(), Error: outcome,
					Connector: approvalConnector, Decision: reason,
				}
				// Recording connectors capture what WOULD have been sent, so
				// a denied/expired call is replayable (with force) later.
				if sc := auditScopeFrom(ctx); sc != nil {
					rec.EndpointKind = sc.kind
					rec.EndpointGeneration = sc.generation
					if sc.record {
						rec.Args = marshalPayload(req.GetArguments())
					}
				}
				g.audit.LogCall(rec)
			}
			return mcp.NewToolResultError(outcome + " — the call was not sent upstream"), nil
		}
		if !g.pendingCallBindingLive(p) {
			const outcome = "connection ownership changed"
			if g.audit != nil {
				rec := CallRecord{
					Account: account.Name, Tool: bare, OK: false,
					Ms: time.Since(start).Milliseconds(), Error: outcome,
					Connector: approvalConnector, Decision: outcome,
				}
				if sc := auditScopeFrom(ctx); sc != nil {
					rec.EndpointKind = sc.kind
					rec.EndpointGeneration = sc.generation
					if sc.record {
						rec.Args = marshalPayload(req.GetArguments())
					}
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
