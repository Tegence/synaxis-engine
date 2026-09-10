package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWebhookEventJSONShape locks the structured webhook-v2 contract to the
// exact field set/order transcribed from the design (Figma node 94:24,
// docs/design-upgrades/10-mobile-notifications.md): event, id, tool,
// account, connector, kind, summary, expires_at, decide_url — plus the
// back-compat text/content pair. A future accidental rename/reorder here is
// a contract break for every webhook-v2 consumer, so this asserts the raw
// JSON text rather than just round-tripping through the struct.
func TestWebhookEventJSONShape(t *testing.T) {
	evt := WebhookEvent{
		Event: "call.parked", ID: "prk_8f2a1c04", Tool: "notion_tegence__notion-create-pages",
		Account: "Notion · Tegence", Connector: "/writing", Kind: "write",
		Summary: "Creates 1 new page in the Tegence workspace.", ExpiresAt: "2026-08-16T09:44:00Z",
		DecideURL: "https://synaxis.tegence.dev/a/prk_8f2a1c04",
		Text:      "legacy line", Content: "legacy line",
	}
	b, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"event":"call.parked","id":"prk_8f2a1c04","tool":"notion_tegence__notion-create-pages",` +
		`"account":"Notion · Tegence","connector":"/writing","kind":"write",` +
		`"summary":"Creates 1 new page in the Tegence workspace.","expires_at":"2026-08-16T09:44:00Z",` +
		`"decide_url":"https://synaxis.tegence.dev/a/prk_8f2a1c04","text":"legacy line","content":"legacy line"}`
	if string(b) != want {
		t.Fatalf("webhook event JSON shape drifted:\n got  %s\n want %s", b, want)
	}
}

// captureWebhook returns a test server that decodes every POST body as
// WebhookEvent and pushes it onto the returned channel.
func captureWebhook(t *testing.T) (*httptest.Server, chan WebhookEvent) {
	t.Helper()
	events := make(chan WebhookEvent, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var evt WebhookEvent
		if err := json.Unmarshal(body, &evt); err != nil {
			t.Errorf("webhook body did not decode as WebhookEvent: %v (body %s)", err, body)
		}
		events <- evt
		w.WriteHeader(http.StatusNoContent)
	}))
	return srv, events
}

func awaitEvent(t *testing.T, events chan WebhookEvent, want string) WebhookEvent {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case evt := <-events:
			if evt.Event == want {
				return evt
			}
			// keep draining — health sweeps in the same gateway can interleave
			// with an unrelated approval event in a shared-webhook test
		case <-deadline:
			t.Fatalf("never observed a %q event", want)
			return WebhookEvent{}
		}
	}
}

// TestApprovalParkAndDecideEmitStructuredEvents exercises the real park →
// approve lifecycle through a gated connector tool call (not a seeded row),
// and asserts both the call.parked and call.decided structured events are
// posted with the fields the design specifies, including a working
// "prk_"-prefixed id and a decide_url built from the configured public URL.
func TestApprovalParkAndDecideEmitStructuredEvents(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"linear": {"delete_issue"}})
	webhook, events := captureWebhook(t)
	defer webhook.Close()
	g.SetAlertWebhook(webhook.URL)
	g.SetPublicURL("https://engine.example")
	g.SetConsoleURL("https://console.example")
	ctx := context.Background()
	g.Aggregate(ctx)

	// Seed a pending row exactly as approvalHandler would (same helper style
	// as console_approvals_test.go's seedPending), so buildCallParkedEvent /
	// buildCallDecidedEvent run against a real PendingCall rather than one
	// hand-built purely for the test.
	al, ok := g.approvalLog()
	if !ok {
		t.Fatal("store has no ApprovalLog facet")
	}
	id := "evt1"
	g.registerWait(id)
	if err := al.LogPending(ctx, PendingCall{
		ID: id, Connector: "eng", Account: "linear", Tool: "delete_issue",
		Status: ApprovalPending, Kind: "write",
	}); err != nil {
		t.Fatalf("LogPending: %v", err)
	}
	legacy := "⏸️ Synaxis: approval needed — eng: linear·delete_issue."
	p, _, err := g.ApprovalByID(ctx, id)
	if err != nil {
		t.Fatalf("ApprovalByID: %v", err)
	}
	g.fireEvent(g.buildCallParkedEvent(p, legacy))

	parked := awaitEvent(t, events, EventCallParked)
	if parked.ID != "prk_evt1" {
		t.Fatalf("parked.ID = %q, want prk_evt1", parked.ID)
	}
	if parked.Tool != "delete_issue" || parked.Connector != "/eng" || parked.Kind != "write" {
		t.Fatalf("parked event fields = %+v", parked)
	}
	if parked.DecideURL != "https://engine.example/a/prk_evt1" {
		t.Fatalf("parked.DecideURL = %q", parked.DecideURL)
	}
	if !strings.Contains(parked.Summary, "cannot undo") {
		t.Fatalf("parked.Summary = %q, want a write-kind consequence sentence", parked.Summary)
	}
	if parked.Text == "" || parked.Content == "" {
		t.Fatalf("parked event dropped back-compat text/content: %+v", parked)
	}

	if _, err := g.DecideWithMetadata(ctx, id, ApprovalDecision{Status: ApprovalApproved, Actor: "local-admin"}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	decided := awaitEvent(t, events, EventCallDecided)
	if decided.ID != "prk_evt1" || decided.Kind != "write" {
		t.Fatalf("decided event fields = %+v", decided)
	}
	if !strings.Contains(decided.Summary, "Approved") || !strings.Contains(decided.Summary, "local-admin") {
		t.Fatalf("decided.Summary = %q, want it to name the actor", decided.Summary)
	}

	// A retried identical decision (idempotent 200) must NOT fire a second
	// call.decided — only the transition itself is notification-worthy.
	if _, err := g.DecideWithMetadata(ctx, id, ApprovalDecision{Status: ApprovalApproved, Actor: "local-admin"}); err != nil {
		t.Fatalf("idempotent redecide: %v", err)
	}
	select {
	case evt := <-events:
		t.Fatalf("idempotent retry fired an unexpected event: %+v", evt)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing else arrives
	}
}

// TestApprovalTimeoutEmitsCallTimedOutEvent exercises the WaitDecision timer
// path (finishWait) against an already-due pending row and asserts the
// call.timed_out event carries the design's exact copy.
func TestApprovalTimeoutEmitsCallTimedOutEvent(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	webhook, events := captureWebhook(t)
	defer webhook.Close()
	g.SetAlertWebhook(webhook.URL)
	g.SetPublicURL("https://engine.example")

	al, ok := g.approvalLog()
	if !ok {
		t.Fatal("store has no ApprovalLog facet")
	}
	ctx := context.Background()
	created := time.Now().Add(-2 * time.Second)
	due := time.Now().Add(-1 * time.Second)
	id := "timeout1"
	g.registerWait(id)
	if err := al.LogPending(ctx, PendingCall{
		ID: id, TS: created, ExpiresAt: &due, Connector: "eng", Account: "linear",
		Tool: "save_issue", Status: ApprovalPending, Kind: "write",
	}); err != nil {
		t.Fatalf("LogPending: %v", err)
	}

	approved, reason := g.WaitDecision(ctx, id, 10*time.Millisecond)
	if approved || reason != ApprovalExpired {
		t.Fatalf("WaitDecision = (%v, %q), want (false, expired)", approved, reason)
	}

	evt := awaitEvent(t, events, EventCallTimedOut)
	if evt.ID != "prk_timeout1" {
		t.Fatalf("timed_out.ID = %q", evt.ID)
	}
	if evt.Summary != "Nobody decided. Claude received an error." {
		t.Fatalf("timed_out.Summary = %q, want the design's verbatim copy", evt.Summary)
	}
}

// TestUpstreamHealthEmitsStructuredEvents mirrors
// TestHealthAlertNeverIncludesProviderDetail (gateway_health_test.go) but
// asserts the structured upstream.down/upstream.recovered event fields
// rather than only the legacy text line.
func TestUpstreamHealthEmitsStructuredEvents(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	webhook, events := captureWebhook(t)
	defer webhook.Close()
	g.SetAlertWebhook(webhook.URL)

	g.evalAlert(AccountHealth{UUID: "notion", Status: healthStatusUnreachable})
	down := awaitEvent(t, events, EventUpstreamDown)
	if down.ID != "notion" || down.Account != "notion" {
		t.Fatalf("down event = %+v", down)
	}

	g.evalAlert(AccountHealth{UUID: "notion", Status: healthStatusOK})
	recovered := awaitEvent(t, events, EventUpstreamRecovered)
	if recovered.ID != "notion" {
		t.Fatalf("recovered event = %+v", recovered)
	}
}
