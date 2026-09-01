package engine

// console_decide.go: the unauthenticated one-time decide link (MOBI-15),
// GET /a/{id} + POST /a/{id}/approve|deny. This is what the structured
// webhook v2 event's decide_url (notify.go) resolves to, and it is also the
// mechanism the approval email's "Approve this call" / "Deny" buttons use
// (docs/design-upgrades/10-mobile-notifications.md, frame 94:2).
//
// Security model: the id is the capability. PendingCall ids are 128 bits of
// crypto/rand hex (newApprovalID) — unguessable, same trust model as any
// other magic/unsubscribe link. There is no bearer token requirement here by
// design: a channel recipient (email inbox, Slack message) is not expected
// to hold a console session. The CAS decision path (DecideWithMetadata) is
// exactly the one the authenticated console uses, so idempotency/expiry/
// contradiction semantics are identical.

import (
	"errors"
	"html"
	"net/http"
	"strings"
	"time"
)

// handleOneTimeDecide renders a small, self-contained confirmation page. It
// never mutates state — only the POST actions below do — so an email
// security scanner's GET prefetch of the link is harmless.
func (c *ConsoleAPI) handleOneTimeDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := internalApprovalID(r.PathValue("id"))
	p, found, err := c.gw.ApprovalByID(r.Context(), id)
	if err != nil || !found {
		writeDecidePage(w, http.StatusNotFound, decidePage{
			Title: "Link not found", Body: "This link is invalid, or the request it pointed to no longer exists.",
		})
		return
	}
	writeDecidePage(w, http.StatusOK, decideStatusPage(c.store, p))
}

// handleOneTimeDecideAction commits the decision through the SAME durable
// compare-and-swap path as the authenticated console (POST
// /api/approvals/{id}/approve|deny) — idempotent retry, 409 on
// contradiction, 404 unknown id, expiry-aware.
func (c *ConsoleAPI) handleOneTimeDecideAction(w http.ResponseWriter, r *http.Request, status string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.approvalsSupported(w) {
		return
	}
	id := internalApprovalID(r.PathValue("id"))
	p, err := c.gw.DecideWithMetadata(r.Context(), id, ApprovalDecision{
		Status: status,
		Actor:  "one-time-link",
	})
	switch {
	case err == nil, errors.Is(err, ErrApprovalNotPending), errors.Is(err, ErrApprovalExpired):
		// Idempotent retry or a contradiction/expiry that already resolved the
		// row: render whatever the durable state now says rather than a raw
		// error, since the person clicking a stale button just wants to know
		// what happened.
		writeDecidePage(w, http.StatusOK, decideStatusPage(c.store, p))
	case errors.Is(err, ErrApprovalNotFound):
		writeDecidePage(w, http.StatusNotFound, decidePage{
			Title: "Link not found", Body: "This link is invalid, or the request it pointed to no longer exists.",
		})
	default:
		writeDecidePage(w, http.StatusBadGateway, decidePage{
			Title: "Something went wrong", Body: "The decision could not be recorded. Please try again, or use the console.",
		})
	}
}

type decidePage struct {
	Title    string
	Body     string
	ShowForm bool
	ID       string // internal (unprefixed) id, used to build the form action
	Tool     string
	Account  string
	Summary  string
}

// decideStatusPage maps a PendingCall's current durable status to the page
// copy. Pending + not yet due is the only state that renders the
// Approve/Deny forms; every terminal state (or a pending row past its own
// deadline but not yet swept) is display-only, matching the design's "This
// link works once and expires with the 180 second window" contract.
func decideStatusPage(store AccountStore, p PendingCall) decidePage {
	base := decidePage{ID: p.ID, Tool: p.Tool, Account: accountDisplay(store, p.Account)}
	switch {
	case p.Status == ApprovalPending && !approvalIsDue(p, time.Now()):
		base.Title = "Decide: " + p.Tool
		base.Body = approvalSummary(p.Kind, p.Tool, base.Account)
		base.Summary = base.Body
		base.ShowForm = true
	case p.Status == ApprovalPending: // due but not yet swept by the sweeper/waiter
		base.Title = "This request expired"
		base.Body = "Nobody decided in time. Claude already received an error — there is nothing left to approve or deny."
	case p.Status == ApprovalApproved:
		base.Title = "Already approved"
		base.Body = "This call was approved" + decidedBySuffix(p) + ". The link has done its job."
	case p.Status == ApprovalDenied:
		base.Title = "Already denied"
		base.Body = "This call was denied" + decidedBySuffix(p) + ". The link has done its job."
	case p.Status == ApprovalExpired:
		base.Title = "This request expired"
		base.Body = "Nobody decided in time. Claude already received an error — there is nothing left to approve or deny."
	case p.Status == ApprovalCancelled:
		base.Title = "This request was cancelled"
		base.Body = "The original request ended before anyone decided — there is nothing left to approve or deny."
	default:
		base.Title = "Unknown status"
		base.Body = "This request is in an unexpected state. Use the console instead."
	}
	return base
}

func decidedBySuffix(p PendingCall) string {
	if p.DecidedBy == "" {
		return ""
	}
	return " by " + p.DecidedBy
}

// writeDecidePage renders a minimal, dependency-free confirmation page. This
// is intentionally NOT a pixel-accurate rendering of the console's design
// system (that lives in the product's web client, out of scope for this
// pipeline) — it is the smallest page that lets a person acting from an
// email or Slack link see what they're deciding and press one button.
func writeDecidePage(w http.ResponseWriter, statusCode int, page decidePage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta name=viewport content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>" + html.EscapeString(page.Title) + " — Synaxis</title>")
	b.WriteString(`<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:12vh auto;padding:0 20px;color:#1a1816;background:#fafaf8}
h1{font-size:20px;font-weight:600;margin-bottom:8px}
p{color:#3d3a35;line-height:1.5}
.meta{font-size:13px;color:#6e6b65;margin-bottom:18px}
.actions{display:flex;gap:10px;margin-top:22px}
button{flex:1;padding:12px;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer}
.approve{background:#1d3b6e;color:#fff}
.deny{background:#c23a2e;color:#fff}
</style></head><body>`)
	b.WriteString("<h1>" + html.EscapeString(page.Title) + "</h1>")
	if page.Account != "" || page.Tool != "" {
		b.WriteString("<div class=meta>" + html.EscapeString(page.Tool) + " on " + html.EscapeString(page.Account) + "</div>")
	}
	b.WriteString("<p>" + html.EscapeString(page.Body) + "</p>")
	if page.ShowForm {
		id := html.EscapeString(page.ID)
		b.WriteString(`<div class=actions>`)
		b.WriteString(`<form method=post action="/a/` + id + `/deny" style="flex:1"><button class=deny type=submit>Deny</button></form>`)
		b.WriteString(`<form method=post action="/a/` + id + `/approve" style="flex:1"><button class=approve type=submit>Approve</button></form>`)
		b.WriteString(`</div>`)
		b.WriteString(`<p style="margin-top:18px;font-size:12.5px;color:#92908b">This link works once and expires with the approval window. After that the call returns an error to Claude and nothing reaches the upstream provider.</p>`)
	}
	b.WriteString("</body></html>")
	w.Write([]byte(b.String()))
}
