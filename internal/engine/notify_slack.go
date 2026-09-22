package engine

// notify_slack.go builds the Slack Block Kit message for a parked call
// (design-upgrades MOBI-16, transcribed from Figma node 93:3 —
// docs/design-upgrades/10-mobile-notifications.md). It rides on the SAME
// webhook-v2 POST as every other event (notify.go's WebhookEvent.Blocks) —
// an operator's existing ALERT_WEBHOOK_URL, if pointed at a Slack Incoming
// Webhook, already renders an included "blocks" array, so this upgrades
// that existing integration with no new configuration. The Approve/Deny
// buttons' click callback is handled by the hosted control plane's
// signature-verified Slack interaction webhook, which is why the button
// "value" below carries enough to route there.

import (
	"encoding/json"
	"fmt"
)

// slackActionValue is the exact JSON the Approve/Deny button's "value"
// carries. Platform's slack_interactions.go decodes this same shape.
type slackActionValue struct {
	WorkspaceID string `json:"workspace_id"`
	ApprovalID  string `json:"approval_id"`
}

func slackButtonValue(workspaceID, publicApprovalID string) string {
	b, _ := json.Marshal(slackActionValue{WorkspaceID: workspaceID, ApprovalID: publicApprovalID})
	return string(b)
}

// blockKitParkedMessage builds the Block Kit array per frame 93:3: header +
// context (account/connector/kind) + a warning-toned consequence callout +
// a one-line arguments preview + an actions row (Approve / Deny / Open in
// console) + a footer disclosing the signature-verification/expiry
// contract. Slack Block Kit has no colored-callout primitive, so the
// consequence line uses a warning-triangle glyph the same way the design's
// other plain-text surfaces (fireAlert's ⚠️/⏸️/✅) already do.
func blockKitParkedMessage(g *Gateway, p PendingCall, account string) []any {
	argsPreview := truncateForSlack(marshalPayload(p.Args), 200)
	actions := []any{
		map[string]any{
			"type": "button", "action_id": "approve", "style": "primary",
			"text":  map[string]any{"type": "plain_text", "text": "Approve", "emoji": true},
			"value": slackButtonValue(g.workspaceID, p.ID),
		},
		map[string]any{
			"type": "button", "action_id": "deny", "style": "danger",
			"text":  map[string]any{"type": "plain_text", "text": "Deny", "emoji": true},
			"value": slackButtonValue(g.workspaceID, p.ID),
		},
	}
	if g.consoleURL != "" {
		actions = append(actions, map[string]any{
			"type": "button", "action_id": "open_in_console",
			"text": map[string]any{"type": "plain_text", "text": "Open in console", "emoji": true},
			"url":  g.consoleURL,
		})
	}
	blocks := []any{
		map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": "Claude is blocked on " + p.Tool, "emoji": true},
		},
		map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("%s · %s · %s", account, connectorField(p.Connector), p.Kind)},
		},
		map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": ":warning: " + approvalSummary(p.Kind, p.Tool, account)},
		},
	}
	if argsPreview != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "```" + argsPreview + "```"},
		})
	}
	blocks = append(blocks,
		map[string]any{"type": "actions", "elements": actions},
		map[string]any{
			"type": "context",
			"elements": []any{
				map[string]any{"type": "mrkdwn", "text": "Synaxis verifies the Slack request signature before it acts. Buttons stop working when the window closes."},
			},
		},
	)
	return blocks
}

// truncateForSlack keeps a single-line preview short — the design's own
// spec is "single truncated line", not the full argument payload.
func truncateForSlack(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
