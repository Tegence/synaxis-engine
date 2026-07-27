package engine

import (
	"context"
	"fmt"
	"time"
)

// PendingCall is the audit record of one approval-gated tool call. The live
// wait (blocking the MCP handler until a decision) is in-process; the store
// only records what happened so the console can list and decide.
type PendingCall struct {
	ID        string         `json:"id"`
	TS        time.Time      `json:"ts"`
	Connector string         `json:"connector"`
	Account   string         `json:"account"`
	Tool      string         `json:"tool"` // BARE tool name
	Args      map[string]any `json:"args,omitempty"`
	Status    string         `json:"status"` // pending | approved | denied | expired
	DecidedAt *time.Time     `json:"decided_at,omitempty"`
}

// ApprovalLog records approval-gated calls and their outcomes. PgStore
// persists rows; FileStore keeps an in-memory slice (approvals are ephemeral
// — a restart drops the in-process waiters anyway).
type ApprovalLog interface {
	LogPending(ctx context.Context, p PendingCall) error
	SetDecision(ctx context.Context, id, status string) error
	PendingCalls(ctx context.Context) ([]PendingCall, error)
}

// maxPendingRecords caps the FileStore slice, mirroring the audit ring.
const maxPendingRecords = 500

func copyPendingCall(p PendingCall) PendingCall {
	cp := p
	if p.Args != nil {
		cp.Args = make(map[string]any, len(p.Args))
		for k, v := range p.Args {
			cp.Args[k] = v
		}
	}
	if p.DecidedAt != nil {
		t := *p.DecidedAt
		cp.DecidedAt = &t
	}
	return cp
}

// ---- FileStore: ApprovalLog (in-memory, not persisted to disk) ----

func (s *FileStore) LogPending(_ context.Context, p PendingCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.TS.IsZero() {
		p.TS = time.Now()
	}
	s.pending = append(s.pending, copyPendingCall(p))
	if len(s.pending) > maxPendingRecords {
		s.pending = s.pending[len(s.pending)-maxPendingRecords:]
	}
	return nil
}

func (s *FileStore) SetDecision(_ context.Context, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		if s.pending[i].ID == id {
			now := time.Now()
			s.pending[i].Status = status
			s.pending[i].DecidedAt = &now
			return nil
		}
	}
	return fmt.Errorf("pending call %q not found", id)
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
