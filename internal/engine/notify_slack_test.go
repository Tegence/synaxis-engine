package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBlockKitParkedMessageCarriesRoutableButtonValues asserts the Approve/
// Deny buttons' "value" field is exactly the JSON
// {"workspace_id":...,"approval_id":...} Platform's slack_interactions.go
// expects (design-upgrades MOBI-16), and that the message includes the
// design's required elements: header naming the tool, an Approve (primary)
// and Deny (danger) button, and the signature-verification footer line.
func TestBlockKitParkedMessageCarriesRoutableButtonValues(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	g.SetWorkspaceID("ws_123")
	g.SetConsoleURL("https://console.example")

	p := PendingCall{ID: "abc123", Tool: "delete_issue", Connector: "eng", Account: "linear", Kind: "write"}
	blocks := blockKitParkedMessage(g, p, "Linear · Tegence")

	raw, err := json.Marshal(blocks)
	if err != nil {
		t.Fatalf("marshal blocks: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "Claude is blocked on delete_issue") {
		t.Fatalf("blocks missing header: %s", body)
	}
	if !strings.Contains(body, `"action_id":"approve"`) || !strings.Contains(body, `"style":"primary"`) {
		t.Fatalf("blocks missing Approve button: %s", body)
	}
	if !strings.Contains(body, `"action_id":"deny"`) || !strings.Contains(body, `"style":"danger"`) {
		t.Fatalf("blocks missing Deny button: %s", body)
	}
	if !strings.Contains(body, "verifies the Slack request signature") {
		t.Fatalf("blocks missing signature-verification footer: %s", body)
	}

	// The button value must round-trip to exactly what the hosted control
	// plane's Slack interaction handler decodes.
	wantValue := `{"workspace_id":"ws_123","approval_id":"abc123"}`
	if !strings.Contains(body, strings.ReplaceAll(wantValue, `"`, `\"`)) {
		t.Fatalf("button value = %s, want it to embed %s", body, wantValue)
	}
}

// TestBlockKitParkedMessageOmittedWithoutWorkspaceID mirrors a self-hosted
// Engine (no SYNAXIS_WORKSPACE_ID): the buttons still render (a Slack
// Incoming Webhook shows them), but their value carries an empty
// workspace_id, so Platform's interaction handler — which self-hosted
// Engines never point a Slack App at anyway — would reject a click as
// missing routing information rather than silently misrouting it.
func TestBlockKitParkedMessageOmittedWithoutWorkspaceID(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	p := PendingCall{ID: "xyz789", Tool: "save_issue", Connector: "eng", Account: "linear", Kind: "write"}
	blocks := blockKitParkedMessage(g, p, "Linear · Tegence")
	raw, _ := json.Marshal(blocks)
	if !strings.Contains(string(raw), `\"workspace_id\":\"\"`) {
		t.Fatalf("expected empty workspace_id in button value: %s", raw)
	}
}

// TestWebhookEventCarriesBlocksOnlyForCallParked: the Blocks field must not
// leak onto decided/timed_out events (they have no interactive callback).
func TestWebhookEventCarriesBlocksOnlyForCallParked(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	g.SetConsoleURL("https://console.example")
	p := PendingCall{ID: "evt9", Tool: "save_issue", Connector: "eng", Account: "linear", Kind: "write", Status: ApprovalApproved, DecidedBy: "local-admin"}

	parked := g.buildCallParkedEvent(p, "legacy")
	if len(parked.Blocks) == 0 {
		t.Fatal("call.parked event has no Blocks")
	}
	decided := g.buildCallDecidedEvent(p, "legacy")
	if decided.Blocks != nil {
		t.Fatalf("call.decided event unexpectedly carries Blocks: %+v", decided.Blocks)
	}
}
