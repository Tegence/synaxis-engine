package engine

import (
	"context"
	"encoding/json"
	"time"
)

func (s *BrowserSignInService) browserRun(ctx context.Context, id string) (BrowserRun, bool, error) {
	store, ok := s.store.(BrowserRunStore)
	if !ok {
		return BrowserRun{}, false, errBrowserSignIn
	}
	rows, err := store.BrowserRuns(ctx)
	if err != nil {
		return BrowserRun{}, false, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, true, nil
		}
	}
	return BrowserRun{}, false, nil
}

func (c *ConsoleAPI) executeBrowser(ctx context.Context, in BrowserControlRequest, a LinkedAccountRecord, parent Account, g BrowserAccountGrant) (BrowserControlResult, error) {
	s := c.browserSignIn
	store := s.store.(BrowserRunStore)
	provider := s.provider.(browserRuntimeProvider)
	out := BrowserControlResult{Status: "ok"}
	if g.Mode == "read" && browserActionWrites(in.Action) {
		return out, errBrowserSignIn
	}
	id := browserRunID(in.ExecutionID, a.ID)
	run, found, err := s.browserRun(ctx, id)
	if err != nil {
		return out, err
	}
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if !found {
		if in.Action.Operation != "open" {
			return out, errBrowserSignIn
		}
		run = BrowserRun{ID: id, Owner: in.Owner, ClientID: in.ClientID, ExecutionID: in.ExecutionID, AccountID: a.ID, GrantID: g.ID, Profile: *a.Browser, State: "starting", ExpiresAt: time.Now().Add(10 * time.Minute), AuthorizedUntil: in.AuthorizedUntil, Actions: map[string]BrowserActionReceipt{}}
		run, err = store.WriteBrowserRun(ctx, run, 0)
		if err != nil {
			return out, err
		}
		run.SessionID, run.ConnectURL, err = provider.CreateRuntimeSession(ctx, run.Profile)
		if err != nil {
			run.State = "closing"
			_, _ = store.WriteBrowserRun(checkpoint, run, run.Revision)
			return out, err
		}
		run.State = "ready"
		run, err = store.WriteBrowserRun(checkpoint, run, run.Revision)
		if err != nil {
			_, _ = s.provider.Stop(checkpoint, run.SessionID)
			return out, err
		}
	}
	if run.Owner != in.Owner || run.ClientID != in.ClientID || run.GrantID != g.ID || run.State != "ready" || time.Now().After(run.ExpiresAt) || !s.browserRunAuthorized(ctx, run) {
		return out, errBrowserSignIn
	}
	raw, _ := json.Marshal(in.Action)
	digest := oauthLinkHash(string(raw))
	receipt, exists := run.Actions[in.CallID]
	if exists && receipt.Digest != digest {
		return out, errBrowserRevision
	}
	if exists && receipt.State != "pending" {
		return BrowserControlResult{Status: "already_dispatched", Message: "This action was already dispatched. Its outcome may be unknown. Take a fresh snapshot; do not repeat a possible publication."}, nil
	}
	// One pending action owns the page. An approval cannot be bypassed by a
	// second request navigating or editing that same session in the meantime.
	for callID, other := range run.Actions {
		if callID != in.CallID && (other.State == "pending" || other.State == "issued") {
			return out, errBrowserRevision
		}
	}
	run.AuthorizedUntil = in.AuthorizedUntil
	if browserActionWrites(in.Action) && (!exists || receipt.State == "pending") {
		if run.Snapshot == nil || run.Snapshot.ID != in.Action.Snapshot || in.Action.Element > len(run.Snapshot.Elements) {
			return out, errBrowserRevision
		}
	}
	if !exists {
		if len(run.Actions) >= 128 {
			return out, errBrowserSignIn
		}
		receipt = BrowserActionReceipt{Digest: digest, State: "pending"}
		if g.Mode == "approval" && browserActionWrites(in.Action) {
			receipt.ApprovalID = "private_" + newApprovalID()
		}
		run.Actions[in.CallID] = receipt
		run, err = store.WriteBrowserRun(ctx, run, run.Revision)
		if err != nil {
			return out, err
		}
		if receipt.ApprovalID != "" {
			if c.gw == nil {
				return out, errBrowserSignIn
			}
			log, ok := c.gw.approvalLifecycle()
			if !ok {
				return out, errBrowserSignIn
			}
			expires := time.Now().Add(c.gw.approvalWait())
			if run.ExpiresAt.Before(expires) {
				expires = run.ExpiresAt
			}
			p := PendingCall{ID: receipt.ApprovalID, CallerSubject: in.Owner, PrivateOwnerSubject: in.Owner, TS: time.Now(), ExpiresAt: &expires, Connector: "browser", Account: parent.Name, AccountIncarnationID: parent.IncarnationID, AccountRevision: parent.Revision, ConnectionNamespaceID: parent.ConnectionNamespaceID, Tool: "browser_" + in.Action.Operation, Kind: "write", Status: ApprovalPending, Args: map[string]any{"account": a.DisplayName, "website": a.Browser.WebsiteURL, "execution": in.ExecutionID, "snapshot": in.Action.Snapshot, "element": in.Action.Element, "text": in.Action.Text, "key": in.Action.Key, "target": run.Snapshot.Elements[in.Action.Element-1], "page": run.Snapshot.URL, "pageTitle": run.Snapshot.Title, "draftText": run.DraftText}}
			if err = log.LogPending(ctx, p); err != nil {
				return out, err
			}
			// Private drafts are reviewed in the owner-authenticated Inbox.
			// Workspace webhook/Slack channels must not receive their payload or a decision capability.
		}
	}
	if receipt.ApprovalID != "" {
		if c.gw == nil {
			return out, errBrowserSignIn
		}
		log, ok := c.gw.approvalLifecycle()
		if !ok {
			return out, errBrowserSignIn
		}
		p, found, err := log.ApprovalCall(ctx, receipt.ApprovalID)
		if err != nil || !found {
			return out, errBrowserSignIn
		}
		if p.ExpiresAt == nil || !time.Now().Before(*p.ExpiresAt) {
			_, _ = log.ExpirePending(ctx, p.ID, time.Now())
			receipt.State = "done"
			run.Actions[in.CallID] = receipt
			_, _ = store.WriteBrowserRun(ctx, run, run.Revision)
			return BrowserControlResult{Status: "denied", Message: "Approval expired; no action was sent."}, nil
		}
		if p.Status == ApprovalPending {
			c.gw.heartbeatPending(ctx, p.ID)
			if _, err = store.WriteBrowserRun(ctx, run, run.Revision); err != nil {
				return out, err
			}
			return BrowserControlResult{Status: "pending", ApprovalID: p.ID, Message: "Waiting for approval."}, nil
		}
		if p.Status != ApprovalApproved {
			receipt.State = "done"
			run.Actions[in.CallID] = receipt
			_, _ = store.WriteBrowserRun(ctx, run, run.Revision)
			return BrowserControlResult{Status: "denied", Message: "Approval was denied or cancelled; no action was sent."}, nil
		}
		if !pendingCallBoundToAccount(p, parent) {
			return out, errBrowserRevision
		}
	}
	// Claim BEFORE external effects. A crash/lost response is never permission
	// to retry. A concurrent poll loses this durable compare-and-swap.
	receipt.State = "issued"
	run.Actions[in.CallID] = receipt
	run, err = store.WriteBrowserRun(ctx, run, run.Revision)
	if err != nil {
		return out, err
	}
	if !s.browserRunAuthorized(ctx, run) || !in.AuthorizedUntil.After(time.Now()) {
		return out, errBrowserSignIn
	}
	if in.Action.Operation == "close" {
		run.State = "closing"
	} else {
		out.Snapshot, err = provider.BrowserAction(ctx, run.ConnectURL, run.Profile.WebsiteURL, in.Action)
	}
	if out.Snapshot != nil {
		run.Snapshot = out.Snapshot
	}
	if in.Action.Operation == "type" && err == nil {
		run.DraftText = in.Action.Text
	}
	if browserActionWrites(in.Action) || in.Action.Operation == "navigate" {
		run.Snapshot = nil
	}
	receipt.State = "done"
	run.Actions[in.CallID] = receipt
	if err != nil {
		run.State = "closing"
	}
	_, writeErr := store.WriteBrowserRun(checkpoint, run, run.Revision)
	if c.gw != nil && c.gw.audit != nil {
		c.gw.audit.LogCall(CallRecord{CallerSubject: in.Owner, AccountOwnerSubject: in.Owner, Account: parent.Name, AccountIncarnationID: parent.IncarnationID, Tool: "browser_" + in.Action.Operation, Connector: "browser", OK: err == nil && writeErr == nil, Decision: g.Mode})
	}
	if err != nil {
		return out, err
	}
	if writeErr != nil {
		return out, writeErr
	}
	if run.State == "closing" {
		out.Status = "closed"
		s.reapBrowserRuns(checkpoint)
	}
	// Do not return content acquired while account access was being revoked.
	if !s.browserRunAuthorized(ctx, run) {
		return BrowserControlResult{}, errBrowserSignIn
	}
	return out, nil
}

func (s *BrowserSignInService) closeBrowserExecution(ctx context.Context, owner, client, execution string) {
	store, ok := s.store.(BrowserRunStore)
	if !ok {
		return
	}
	rows, err := store.BrowserRuns(ctx)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.Owner == owner && r.ClientID == client && r.ExecutionID == execution && r.State != "closed" {
			r.State = "closing"
			_, _ = store.WriteBrowserRun(ctx, r, r.Revision)
		}
	}
	s.reapBrowserRuns(ctx)
}
func (s *BrowserSignInService) reapBrowserRuns(ctx context.Context) {
	store, ok := s.store.(BrowserRunStore)
	if !ok || s.provider == nil {
		return
	}
	rows, err := store.BrowserRuns(ctx)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.State == "closed" {
			if time.Now().After(r.ExpiresAt.Add(24 * time.Hour)) {
				_, _ = store.WriteBrowserRun(ctx, r, r.Revision)
			}
			continue
		}
		if r.Profile.ConfigurationID != s.provider.ConfigurationID() || r.Profile.Provider != s.provider.Kind() {
			continue
		}
		if r.State != "closing" && time.Now().Before(r.ExpiresAt) && time.Now().Before(r.AuthorizedUntil) && s.browserRunAuthorized(ctx, r) {
			continue
		}
		if r.State != "closing" {
			r.State = "closing"
			r, err = store.WriteBrowserRun(ctx, r, r.Revision)
			if err != nil {
				continue
			}
		}
		// Unknown allocation outcomes are bounded by the provider's hard TTL.
		if r.SessionID == "" && time.Now().Before(r.ExpiresAt.Add(time.Minute)) {
			continue
		}
		stopped, err := s.provider.Stop(ctx, r.SessionID)
		if err != nil || !stopped {
			continue
		}
		if approvals, ok := s.store.(ApprovalLifecycle); ok {
			for _, a := range r.Actions {
				if a.ApprovalID != "" {
					_, _ = approvals.CancelPending(ctx, a.ApprovalID, "engine", "browser session ended")
				}
			}
		}
		r.State = "closed"
		r.ConnectURL = ""
		r.Snapshot = nil
		r.DraftText = ""
		_, _ = store.WriteBrowserRun(ctx, r, r.Revision)
	}
}
func (s *BrowserSignInService) browserProfileBusy(ctx context.Context, profile BrowserProfile) bool {
	store, ok := s.store.(BrowserRunStore)
	if !ok {
		return false
	}
	rows, err := store.BrowserRuns(ctx)
	if err != nil {
		return true
	}
	for _, r := range rows {
		if r.State != "closed" && r.Profile.ProfileID == profile.ProfileID && r.Profile.ConfigurationID == profile.ConfigurationID {
			return true
		}
	}
	return false
}

func (s *BrowserSignInService) touchBrowserExecution(ctx context.Context, in BrowserControlRequest, choices []BrowserAccountChoice) {
	store, ok := s.store.(BrowserRunStore)
	if !ok {
		return
	}
	rows, err := store.BrowserRuns(ctx)
	if err != nil {
		return
	}
	for _, r := range rows {
		allowed := false
		for _, a := range choices {
			if a.ID == r.AccountID && a.Available && a.Mode != "stale" && a.Mode != "" {
				allowed = true
			}
		}
		if allowed && r.Owner == in.Owner && r.ClientID == in.ClientID && r.ExecutionID == in.ExecutionID && r.State == "ready" && s.browserRunAuthorized(ctx, r) {
			busy := false
			for _, a := range r.Actions {
				if a.State == "pending" || a.State == "issued" {
					busy = true
				}
			}
			if busy {
				continue
			}
			r.AuthorizedUntil = in.AuthorizedUntil
			_, _ = store.WriteBrowserRun(ctx, r, r.Revision)
		}
	}
}
