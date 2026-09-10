package engine

// notify.go: the structured "webhook v2" event contract (design-upgrades
// MOBI-13). Transcribed verbatim from Figma node 94:24 — see
// docs/design-upgrades/10-mobile-notifications.md — and adjudicated as
// channel 1 of the layered notification pipeline in
// docs/design-upgrades/README.md §3.9 (webhook v2 → Slack Block Kit →
// one-time-link email → Web Push → FCM). This file owns event construction
// and the outbound fire-and-forget POST; gateway.go (health transitions) and
// gateway_approvals.go (park/decide/timeout) call fireEvent at the points
// where each transition already lands durably.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Structured event types. Exactly the five the design specifies — do not add
// more without a corresponding design frame.
const (
	EventCallParked        = "call.parked"
	EventCallDecided       = "call.decided"
	EventCallTimedOut      = "call.timed_out"
	EventUpstreamDown      = "upstream.down"
	EventUpstreamRecovered = "upstream.recovered"
)

// WebhookEvent is the structured "webhook v2" payload — field set and order
// transcribed verbatim from the design's payload sample:
//
//	{
//	  "event": "call.parked",
//	  "id": "prk_8f2a1c04",
//	  "tool": "notion_tegence__notion-create-pages",
//	  "account": "Notion · Tegence",
//	  "connector": "/writing",
//	  "kind": "write",
//	  "summary": "Creates 1 new page in the Tegence workspace.",
//	  "expires_at": "2026-08-16T09:44:00Z",
//	  "decide_url": "https://synaxis.tegence.dev/a/prk_8f2a1c04"
//	}
//
// Text/Content are NOT part of the design's contract; they are appended so
// this payload is a strict superset of the legacy {"text","content"}
// shape (gateway.go's old fireAlert). An existing Slack "Incoming Webhook"
// or Discord webhook integration pointed at ALERT_WEBHOOK_URL keeps
// rendering a readable line without any reconfiguration, while a webhook-v2
// consumer reads the structured fields.
type WebhookEvent struct {
	Event     string `json:"event"`
	ID        string `json:"id"`
	Tool      string `json:"tool,omitempty"`
	Account   string `json:"account,omitempty"`
	Connector string `json:"connector,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Summary   string `json:"summary,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	DecideURL string `json:"decide_url,omitempty"`

	// Text/Content: back-compat only (Slack reads "text", Discord "content").
	Text    string `json:"text"`
	Content string `json:"content"`

	// Blocks is a Slack Block Kit array (design-upgrades MOBI-16), populated
	// only for call.parked. It rides on the SAME webhook-v2 payload rather
	// than a separate Slack-specific delivery: an operator's existing
	// ALERT_WEBHOOK_URL already points at a Slack "Incoming Webhook" for the
	// legacy text alert, and Slack incoming webhooks render an included
	// "blocks" array — so this single POST upgrades that existing
	// integration to the rich interactive message (frame 93:3) with no new
	// configuration. (The button click callback itself needs a real Slack
	// App's Interactivity Request URL pointed at Platform's
	// /v1/webhooks/slack/interactions — see notify_slack.go.)
	Blocks []any `json:"blocks,omitempty"`
}

// SetPublicURL configures the Engine's own externally reachable base URL,
// used to build the one-time decide_url link (MOBI-15) carried on approval
// events. Deliberately distinct from consoleURL: consoleURL points at the
// frontend console app (still linked in the legacy Text/Content line),
// decide_url points at THIS Engine's own unauthenticated /a/{id} route,
// which is what an email button or Slack action ultimately needs to be able
// to resolve a decision without a browser session.
func (g *Gateway) SetPublicURL(u string) { g.publicURL = strings.TrimRight(strings.TrimSpace(u), "/") }

// decideURL builds the one-time link for a pending call id. Empty when no
// public URL has been configured (self-hosted Engines not reachable from
// the public internet — decide_url is simply omitted, same as the design's
// optional fields).
func (g *Gateway) decideURL(id string) string {
	if g.publicURL == "" || id == "" {
		return ""
	}
	return g.publicURL + "/a/" + approvalPublicID(id)
}

// approvalPublicID / internalApprovalID convert between the storage-layer
// PendingCall.ID (opaque hex, unprefixed) and the "prk_"-prefixed id the
// design's public contract uses. The prefix is cosmetic and public-facing
// only — the durable primary key is unchanged to avoid a data migration.
func approvalPublicID(id string) string { return "prk_" + id }

func internalApprovalID(publicID string) string {
	return strings.TrimPrefix(strings.TrimSpace(publicID), "prk_")
}

// SetPlatformEvents configures the hosted Platform's structured-event ingest
// (design-upgrades AND-09): url is Platform's per-workspace event-ingest
// endpoint (wired from ENGINE_EVENTS_URL, set at provisioning time), token
// is the SAME admin-token credential Platform already uses to call INTO this
// Engine (SYNAXIS_ADMIN_TOKEN) — reused here for the reverse direction
// rather than minting a second secret. Self-hosted Engines never call this,
// so url stays empty and fireEvent skips the second POST entirely.
func (g *Gateway) SetPlatformEvents(url, token string) {
	g.platformEventsURL = strings.TrimSpace(url)
	g.platformEventsToken = token
}

// SetWorkspaceID records SYNAXIS_WORKSPACE_ID for the Slack Block Kit
// button value (notify_slack.go) — Platform's interaction handler needs it
// to route a click back to the right Engine. Empty on self-hosted Engines,
// which never reach Platform's interaction endpoint anyway.
func (g *Gateway) SetWorkspaceID(id string) { g.workspaceID = strings.TrimSpace(id) }

// fireEvent POSTs the structured webhook-v2 payload to the configured alert
// webhook, and — when hosted — ALSO to Platform's engine-events ingest so
// Platform can fan out to devices/email/Slack-interactions (the channels
// that need a Platform-side identity; see notify_slack.go and
// docs/design-upgrades/README.md §3.9). Both deliveries share the exact same
// fire-and-forget semantics as the pre-MOBI-13 fireAlert: best effort, no
// retry, response discarded, 10s timeout each — the design's own spec for
// this surface ("Synaxis does not retry and does not wait for a 200").
func (g *Gateway) fireEvent(evt WebhookEvent) {
	log.Printf("ALERT: %s", evt.Text)
	if g.webhook != "" {
		go postWebhookEvent(g.webhook, "", evt)
	}
	if g.platformEventsURL != "" {
		go postWebhookEvent(g.platformEventsURL, g.platformEventsToken, evt)
	}
}

func postWebhookEvent(url, bearerToken string, evt WebhookEvent) {
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// accountDisplay renders an account the way the console/design does
// ("Notion · Tegence" = Label · Group), falling back to the bare stored key
// when the account can no longer be looked up (deleted between park and a
// later decided/timed_out event).
func accountDisplay(store AccountStore, name string) string {
	account, ok := store.Account(name)
	if !ok {
		return name
	}
	label := account.Label
	if label == "" {
		label = account.Name
	}
	if account.Group != "" {
		return label + " · " + account.Group
	}
	return label
}

// connectorField renders PendingCall.Connector as the design's leading-slash
// path form ("/writing"). The internal governancePolicyScope sentinel is not
// a real connector path, so it is left as-is.
func connectorField(connector string) string {
	connector = strings.TrimSpace(connector)
	if connector == "" || connector == governancePolicyScope || strings.HasPrefix(connector, "/") {
		return connector
	}
	return "/" + connector
}

// approvalKind maps the annotation/name-heuristic readOnlyTool result (see
// gateway.go) to the design's "read"/"write" kind chip.
func approvalKind(readOnly bool) string {
	if readOnly {
		return "read"
	}
	return "write"
}

// approvalSummary is the v1 consequence sentence: a generic template from
// kind + tool + account, in the same voice as the design's copy ("Synaxis
// cannot undo it."). MOBI-14 scopes a real per-tool consequence model
// (destructiveHint, resource counts, etc.) as later, larger work — this
// keeps the webhook/Slack/email/push channels shipping a real sentence
// today rather than blocking on that model.
func approvalSummary(kind, tool, account string) string {
	switch kind {
	case "read":
		return fmt.Sprintf("Reads via %s on %s. No changes will be made.", tool, account)
	default: // "write", or unknown — fail toward the more cautious framing
		return fmt.Sprintf("Runs %s on %s. This can make changes that Synaxis cannot undo.", tool, account)
	}
}

func formatExpiresAt(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// pendingCallEvent builds the base structured event for a PendingCall,
// common to every lifecycle stage (parked/decided/timed_out). legacyText is
// the pre-MOBI-13 alert line, preserved verbatim in Text/Content for
// existing consumers. summary overrides the generic consequence sentence —
// callers pass the event-appropriate copy (see the three build* helpers
// below), matching the design's per-event "EVENTS" table description.
func (g *Gateway) pendingCallEvent(eventType string, p PendingCall, summary, legacyText string) WebhookEvent {
	account := accountDisplay(g.store, p.Account)
	return WebhookEvent{
		Event:     eventType,
		ID:        approvalPublicID(p.ID),
		Tool:      p.Tool,
		Account:   account,
		Connector: connectorField(p.Connector),
		Kind:      p.Kind,
		Summary:   summary,
		ExpiresAt: formatExpiresAt(p.ExpiresAt),
		DecideURL: g.decideURL(p.ID),
		Text:      legacyText,
		Content:   legacyText,
	}
}

// buildCallParkedEvent: "A call is waiting. Carries decide_url and
// expires_at." (design EVENTS table). summary is the per-call consequence
// sentence, since that is what a human clicking decide_url needs to see.
func (g *Gateway) buildCallParkedEvent(p PendingCall, legacyText string) WebhookEvent {
	account := accountDisplay(g.store, p.Account)
	evt := g.pendingCallEvent(EventCallParked, p, approvalSummary(p.Kind, p.Tool, account), legacyText)
	evt.Blocks = blockKitParkedMessage(g, p, account)
	return evt
}

// buildCallDecidedEvent: "Approved or denied. Carries who and via which
// channel." The 9-field contract has no dedicated "who"/"channel" fields, so
// (per the literal transcribed contract — no new fields) that detail is
// folded into summary, the same way the console's audit trail already
// phrases a decision.
func (g *Gateway) buildCallDecidedEvent(p PendingCall, legacyText string) WebhookEvent {
	verb := "Approved"
	if p.Status == ApprovalDenied {
		verb = "Denied"
	}
	by := p.DecidedBy
	if by == "" {
		by = "console"
	}
	summary := fmt.Sprintf("%s by %s.", verb, by)
	return g.pendingCallEvent(EventCallDecided, p, summary, legacyText)
}

// buildCallTimedOutEvent: "Nobody decided. Claude received an error."
// (verbatim from the design's EVENTS table).
func (g *Gateway) buildCallTimedOutEvent(p PendingCall, legacyText string) WebhookEvent {
	const summary = "Nobody decided. Claude received an error."
	return g.pendingCallEvent(EventCallTimedOut, p, summary, legacyText)
}
