package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Approval lifecycle values are deliberately explicit. An approval only
// authorizes the *currently parked* MCP call; it is never a durable command
// to replay a tool invocation after that call has gone away.
const (
	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"
	ApprovalDenied    = "denied"
	ApprovalExpired   = "expired"
	ApprovalCancelled = "cancelled"
)

var (
	ErrApprovalNotFound   = errors.New("approval not found")
	ErrApprovalNotPending = errors.New("approval is no longer pending")
	ErrApprovalExpired    = errors.New("approval has expired")
	ErrApprovalNotDue     = errors.New("approval has not reached its deadline")
)

// PendingCall is the durable audit record of one approval-gated tool call.
// ExpiresAt is part of the record rather than inferred at read time, so all
// Engine instances agree on when a decision is no longer valid.
//
// A status of approved does not permit automatic replay after an Engine
// restart. The original MCP request is not a durable, replay-safe command.
type PendingCall struct {
	ID           string         `json:"id"`
	TS           time.Time      `json:"ts"`
	Connector    string         `json:"connector"`
	Account      string         `json:"account"`
	Tool         string         `json:"tool"` // BARE tool name
	Args         map[string]any `json:"args,omitempty"`
	Status       string         `json:"status"` // pending | approved | denied | expired | cancelled
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	DecidedAt    *time.Time     `json:"decided_at,omitempty"`
	DecidedBy    string         `json:"decided_by,omitempty"`
	DecisionNote string         `json:"decision_note,omitempty"`
	// Kind is "read" or "write", captured from the tool's annotations (or the
	// readOnlyTool name heuristic) at park time — the live mcp.Tool is not
	// necessarily reachable any more once the call is decided or has timed
	// out, so this is persisted rather than recomputed. Historical rows
	// logged before this field existed read back as "" (mobile-notifications
	// MOBI-13/MOBI-14: feeds the structured webhook/Slack/push "kind" field).
	Kind string `json:"kind,omitempty"`

	// AccountIncarnationID, AccountRevision, and ConnectionNamespaceID bind a
	// parked request to the exact credential ownership generation that presented
	// it.  Account.Name deliberately survives a namespace move, so a name alone
	// must never let an old approval dispatch through newly reassigned
	// credentials.  The fields are optional only to keep historical audit rows
	// readable; every Gateway-created pending call supplies all three.
	AccountIncarnationID  string `json:"account_incarnation_id,omitempty"`
	AccountRevision       int64  `json:"account_revision,omitempty"`
	ConnectionNamespaceID string `json:"connection_namespace_id,omitempty"`
}

// ApprovalDecision is the human decision metadata persisted with a terminal
// transition. Actor is a stable Engine-side label (for example
// "platform-admin"), not an unverified user-provided display name.
type ApprovalDecision struct {
	Status string
	Actor  string
	Note   string
}

// ApprovalLog preserves the historic store facet. SetDecision is retained for
// direct callers, but implementations must use the same conditional
// transition as DecidePending rather than blindly overwriting a row.
type ApprovalLog interface {
	LogPending(ctx context.Context, p PendingCall) error
	SetDecision(ctx context.Context, id, status string) error
	PendingCalls(ctx context.Context) ([]PendingCall, error)
}

// ApprovalLifecycle is the stronger facet required by Gateway. It makes the
// decision write conditional on the row still being pending and exposes a
// point lookup so a waiter on another Engine instance can observe a durable
// decision. Both FileStore and PgStore implement it.
type ApprovalLifecycle interface {
	ApprovalLog
	DecidePending(ctx context.Context, id string, decision ApprovalDecision) (PendingCall, error)
	ExpirePending(ctx context.Context, id string, now time.Time) (PendingCall, error)
	CancelPending(ctx context.Context, id, actor, note string) (PendingCall, error)
	ApprovalCall(ctx context.Context, id string) (PendingCall, bool, error)
}

// maxPendingRecords caps the FileStore slice, mirroring the audit ring.
const maxPendingRecords = 500

const (
	maxApprovalActorBytes = 128
	maxApprovalNoteBytes  = 2 << 10
)

func normalizePendingCall(p *PendingCall) error {
	p.ID = strings.TrimSpace(p.ID)
	if p.ID == "" {
		return errors.New("pending call id is required")
	}
	if p.Status == "" {
		p.Status = ApprovalPending
	}
	if p.Status != ApprovalPending {
		return fmt.Errorf("new pending call %q has invalid status %q", p.ID, p.Status)
	}
	if p.TS.IsZero() {
		p.TS = time.Now()
	}
	if p.ExpiresAt == nil {
		expires := p.TS.Add(defaultApprovalTimeout)
		p.ExpiresAt = &expires
	}
	if !p.ExpiresAt.After(p.TS) {
		return fmt.Errorf("pending call %q expiry must be after its creation time", p.ID)
	}
	p.DecidedAt = nil
	p.DecidedBy = ""
	p.DecisionNote = ""
	p.AccountIncarnationID = strings.TrimSpace(p.AccountIncarnationID)
	p.ConnectionNamespaceID = strings.TrimSpace(p.ConnectionNamespaceID)
	if p.AccountRevision < 0 {
		return fmt.Errorf("pending call %q account revision is invalid", p.ID)
	}
	return nil
}

// pendingCallBoundToAccount reports whether a current durable account is the
// exact ownership generation that created p.  It intentionally requires every
// binding component: historical/manual approval rows without a binding are
// audit-only and must never be used by a live Gateway dispatch closure.
func pendingCallBoundToAccount(p PendingCall, account Account) bool {
	return p.AccountIncarnationID != "" && p.AccountRevision >= 1 && p.ConnectionNamespaceID != "" &&
		p.Account == account.Name &&
		p.AccountIncarnationID == account.IncarnationID &&
		p.AccountRevision == account.Revision &&
		p.ConnectionNamespaceID == account.ConnectionNamespaceID
}

func normalizeHumanDecision(decision ApprovalDecision) (ApprovalDecision, error) {
	decision.Status = strings.TrimSpace(decision.Status)
	if decision.Status != ApprovalApproved && decision.Status != ApprovalDenied {
		return ApprovalDecision{}, fmt.Errorf("invalid decision %q (want %q or %q)", decision.Status, ApprovalApproved, ApprovalDenied)
	}
	decision.Actor = strings.TrimSpace(decision.Actor)
	if decision.Actor == "" {
		decision.Actor = "console"
	}
	if len(decision.Actor) > maxApprovalActorBytes {
		return ApprovalDecision{}, fmt.Errorf("approval actor exceeds %d bytes", maxApprovalActorBytes)
	}
	decision.Note = strings.TrimSpace(decision.Note)
	if len(decision.Note) > maxApprovalNoteBytes {
		return ApprovalDecision{}, fmt.Errorf("approval note exceeds %d bytes", maxApprovalNoteBytes)
	}
	return decision, nil
}

func copyPendingCall(p PendingCall) PendingCall {
	cp := p
	if p.Args != nil {
		cp.Args = make(map[string]any, len(p.Args))
		for k, v := range p.Args {
			cp.Args[k] = v
		}
	}
	if p.ExpiresAt != nil {
		t := *p.ExpiresAt
		cp.ExpiresAt = &t
	}
	if p.DecidedAt != nil {
		t := *p.DecidedAt
		cp.DecidedAt = &t
	}
	return cp
}

func approvalIsDue(p PendingCall, now time.Time) bool {
	return p.ExpiresAt != nil && !p.ExpiresAt.After(now)
}

func stampApprovalDecision(p *PendingCall, status, actor, note string, now time.Time) {
	p.Status = status
	p.DecidedAt = &now
	p.DecidedBy = actor
	p.DecisionNote = note
}

// ---- FileStore: in-memory lifecycle (local development / single instance) ----

func (s *FileStore) LogPending(_ context.Context, p PendingCall) error {
	if err := normalizePendingCall(&p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.pending {
		if existing.ID == p.ID {
			return fmt.Errorf("pending call %q already exists", p.ID)
		}
	}
	s.pending = append(s.pending, copyPendingCall(p))
	if len(s.pending) > maxPendingRecords {
		s.pending = s.pending[len(s.pending)-maxPendingRecords:]
	}
	return nil
}

// SetDecision is the compatibility wrapper for older direct store callers.
// It still has CAS semantics: only a pending, non-expired row can transition.
func (s *FileStore) SetDecision(ctx context.Context, id, status string) error {
	_, err := s.DecidePending(ctx, id, ApprovalDecision{Status: status})
	return err
}

func (s *FileStore) DecidePending(_ context.Context, id string, decision ApprovalDecision) (PendingCall, error) {
	decision, err := normalizeHumanDecision(decision)
	if err != nil {
		return PendingCall{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		p := &s.pending[i]
		if p.ID != id {
			continue
		}
		now := time.Now()
		if p.Status == ApprovalPending && approvalIsDue(*p, now) {
			stampApprovalDecision(p, ApprovalExpired, "engine", "approval deadline elapsed", now)
			return copyPendingCall(*p), ErrApprovalExpired
		}
		if p.Status != ApprovalPending {
			if p.Status == decision.Status { // safe retry of the same button press
				return copyPendingCall(*p), nil
			}
			return copyPendingCall(*p), ErrApprovalNotPending
		}
		stampApprovalDecision(p, decision.Status, decision.Actor, decision.Note, now)
		return copyPendingCall(*p), nil
	}
	return PendingCall{}, ErrApprovalNotFound
}

func (s *FileStore) ExpirePending(_ context.Context, id string, now time.Time) (PendingCall, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		p := &s.pending[i]
		if p.ID != id {
			continue
		}
		if p.Status == ApprovalExpired {
			return copyPendingCall(*p), nil
		}
		if p.Status != ApprovalPending {
			return copyPendingCall(*p), ErrApprovalNotPending
		}
		if !approvalIsDue(*p, now) {
			return copyPendingCall(*p), ErrApprovalNotDue
		}
		stampApprovalDecision(p, ApprovalExpired, "engine", "approval deadline elapsed", now)
		return copyPendingCall(*p), nil
	}
	return PendingCall{}, ErrApprovalNotFound
}

func (s *FileStore) CancelPending(_ context.Context, id, actor, note string) (PendingCall, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "engine"
	}
	note = strings.TrimSpace(note)
	if len(actor) > maxApprovalActorBytes || len(note) > maxApprovalNoteBytes {
		return PendingCall{}, errors.New("approval cancellation metadata is too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		p := &s.pending[i]
		if p.ID != id {
			continue
		}
		now := time.Now()
		if p.Status == ApprovalPending && approvalIsDue(*p, now) {
			stampApprovalDecision(p, ApprovalExpired, "engine", "approval deadline elapsed", now)
			return copyPendingCall(*p), ErrApprovalExpired
		}
		if p.Status == ApprovalCancelled {
			return copyPendingCall(*p), nil
		}
		if p.Status != ApprovalPending {
			return copyPendingCall(*p), ErrApprovalNotPending
		}
		stampApprovalDecision(p, ApprovalCancelled, actor, note, now)
		return copyPendingCall(*p), nil
	}
	return PendingCall{}, ErrApprovalNotFound
}

// cancelPendingForAccountMoveLocked invalidates every still-live parked call
// for an account whose credential ownership is changing. FileStore keeps
// approval rows in memory, so using the same mutex as the account move gives a
// single-instance decision and move a deterministic winner. PgStore performs
// the corresponding transition in its account-move transaction.
func (s *FileStore) cancelPendingForAccountMoveLocked(account string) {
	now := time.Now()
	for i := range s.pending {
		p := &s.pending[i]
		if p.Account != account || p.Status != ApprovalPending {
			continue
		}
		if approvalIsDue(*p, now) {
			stampApprovalDecision(p, ApprovalExpired, "engine", "approval deadline elapsed", now)
			continue
		}
		stampApprovalDecision(p, ApprovalCancelled, "engine", "connection ownership changed while approval was pending", now)
	}
}

func (s *FileStore) ApprovalCall(_ context.Context, id string) (PendingCall, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		if s.pending[i].ID == id {
			return copyPendingCall(s.pending[i]), true, nil
		}
	}
	return PendingCall{}, false, nil
}

func (s *FileStore) PendingCalls(_ context.Context) ([]PendingCall, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingCall, 0, len(s.pending))
	for i := len(s.pending) - 1; i >= 0; i-- { // newest first, like RecentCalls
		out = append(out, copyPendingCall(s.pending[i]))
	}
	return out, nil
}
