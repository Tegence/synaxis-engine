package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func validInspectionRead(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	if path == "/api/approvals" {
		return true
	}
	id := strings.TrimPrefix(path, "/api/logs/")
	n, err := strconv.ParseInt(id, 10, 64)
	return strings.HasPrefix(path, "/api/logs/") && err == nil && n > 0 && strconv.FormatInt(n, 10) == id
}

// A deleted source has no trustworthy ownership projection. Its retained
// payload therefore requires explicit administration rather than guessing.
func (c *ConsoleAPI) privateToolPayload(actor PlatformActor, account string) bool {
	if c.actorVerifier == nil {
		return false
	}
	a, found := c.store.Account(account)
	return !found || (a.IsPersonal() && a.OwnerSubject != actor.UserID)
}
func (c *ConsoleAPI) privateCallPayload(actor PlatformActor, record CallRecord) bool {
	if c.actorVerifier == nil {
		return false
	}
	if record.CallerSubject != "" {
		return !actorOwnsCall(actor, record)
	}
	// Older rows do not prove source ownership. Empty payloads remain safe
	// metadata; retained bodies need explicit inspection until they expire.
	if record.AccountIncarnationID == "" {
		return record.Args != "" || record.Result != ""
	}
	return record.AccountOwnerSubject != "" && record.AccountOwnerSubject != actor.UserID
}
func (c *ConsoleAPI) privateApprovalPayload(actor PlatformActor, call PendingCall) bool {
	if call.PrivateOwnerSubject != "" {
		return actor.UserID != call.PrivateOwnerSubject
	}
	if c.actorVerifier == nil {
		return false
	}
	if call.Status != ApprovalPending {
		// Source managers need arguments to decide a live request. Once it is
		// terminal, retained arguments follow the original caller's privacy.
		return (call.CallerSubject == "" && len(call.Args) > 0) || (call.CallerSubject != "" && !actorOwnsCall(actor, CallRecord{CallerSubject: call.CallerSubject}))
	}
	a, found := c.store.Account(call.Account)
	if !found || (call.AccountIncarnationID != "" && (a.IncarnationID != call.AccountIncarnationID || a.Revision != call.AccountRevision)) {
		return true
	}
	return (call.AccountIncarnationID == "" && len(call.Args) > 0) || c.privateToolPayload(actor, call.Account)
}
func (c *ConsoleAPI) allowPrivateToolPayload(w http.ResponseWriter, r *http.Request, actor PlatformActor, record CallRecord) bool {
	private := c.privateCallPayload(actor, record)
	if r.Method == http.MethodGet {
		if !private || actor.InspectionEventID != "" {
			return true
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "inspection_required", "error": "Private tool payloads require an explicit, logged inspection."})
		return false
	}
	if c.actorVerifier != nil {
		a, found := c.store.Account(record.Account)
		if private || !found || record.AccountIncarnationID == "" || a.IncarnationID != record.AccountIncarnationID || a.OwnerSubject != record.AccountOwnerSubject || c.privateToolPayload(actor, record.Account) {
			writeJSON(w, http.StatusForbidden, map[string]string{"code": "forbidden", "error": "only the personal connection owner can replay or change a call with its original source"})
			return false
		}
	}
	return true
}

func (c *ConsoleAPI) approvalForActor(actor PlatformActor, call PendingCall) PendingCall {
	private := c.privateApprovalPayload(actor, call)
	canDecide := !private && call.Status == ApprovalPending
	call.CanDecide = &canDecide
	if private && actor.InspectionEventID == "" {
		call.Args = nil
		call.DecisionNote = ""
		call.InspectionRequired = true
	}
	return call
}

// Metadata only. Signed caller identity determines scope; no credentials,
// call arguments, results or approval notes cross this assessment boundary.
func (c *ConsoleAPI) handleControlWorkInspection(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireConnectionNamespaceActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid inspection resource"})
		return
	}
	required := false
	switch input.Kind {
	case "call":
		id, err := strconv.ParseInt(input.ID, 10, 64)
		if err != nil || id < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid call id"})
			return
		}
		if !c.auditSupported(w) {
			return
		}
		record, found, err := c.gw.CallDetail(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "call metadata unavailable"})
			return
		}
		if !found || !c.visibleCall(r.Context(), actor, record) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "call not found"})
			return
		}
		required = c.privateCallPayload(actor, record)
	case "approvals":
		if input.ID != "pending" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid approval collection"})
			return
		}
		if !c.approvalsSupported(w) {
			return
		}
		calls, err := c.apprLog.PendingCalls(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "approval metadata unavailable"})
			return
		}
		for _, call := range calls {
			if c.visibleApproval(r.Context(), actor, call) && c.privateApprovalPayload(actor, call) {
				required = true
				break
			}
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid inspection resource"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"inspectionRequired": required})
}

func auditCallerSubject(ctx context.Context) string {
	caller, _ := memberCallerFrom(ctx)
	return caller.subject
}
func actorOwnsCall(actor PlatformActor, record CallRecord) bool {
	if record.CallerSubject == "" {
		return false
	}
	if record.CallerSubject == actor.UserID {
		return true
	}
	for _, subject := range strings.Split(actor.WorkSubjects, ",") {
		if subject == record.CallerSubject {
			return true
		}
	}
	return false
}

// Ownership grants authorize only these existing call actions, never inspection
// authority or arbitrary writes. IDs must use their canonical positive form.
func validWorkCallMutation(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "api" || parts[2] != "logs" || (parts[4] != "replay" && parts[4] != "triage") {
		return false
	}
	id, err := strconv.ParseInt(parts[3], 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == parts[3]
}

func validWorkSubjects(subjects, method, path string) bool {
	if subjects == "" {
		return true
	}
	if len(subjects) > 16000 || (!validInspectionRead(method, path) && !validWorkCallMutation(method, path) && !(method == http.MethodGet && path == "/api/logs") && !(method == http.MethodPost && path == "/control/v1/work-inspection")) {
		return false
	}
	parts := strings.Split(subjects, ",")
	if len(parts) > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, subject := range parts {
		if !validActorIdentifier(subject) || seen[subject] {
			return false
		}
		seen[subject] = true
	}
	return true
}
