package engine

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const controlCapabilityBrowserRuntime = "browser-account-runtime"

// A grant is independent of MCP reach. Every replacement gets a fresh ID;
// changing mode, reconnecting, or rotating the client invalidates open runs.
type BrowserAccountGrant struct {
	ID                 string    `json:"id"`
	ClientID           string    `json:"clientId"`
	Subject            string    `json:"subject"`
	ClientEpoch        string    `json:"clientEpoch"`
	CredentialRevision int64     `json:"credentialRevision"`
	Mode               string    `json:"mode"` // read, approval, automatic
	CreatedAt          time.Time `json:"createdAt"`
}

func validBrowserGrant(g BrowserAccountGrant) bool {
	return g.ID != "" && validActorIdentifier(g.Subject) && g.ClientID != "" && g.ClientEpoch != "" && g.CredentialRevision > 0 && (g.Mode == "read" || g.Mode == "approval" || g.Mode == "automatic")
}

// BrowserRun is an encrypted, provider-private lease and dispatch ledger.
// It intentionally survives account deletion, for resource cleanup. Only the
// latest bounded snapshot and form inputs are kept for approval context.
// An issued action is never retried after a crash.
type BrowserRun struct {
	ID              string                          `json:"id"`
	Revision        int64                           `json:"revision"`
	Owner           string                          `json:"owner"`
	ClientID        string                          `json:"clientId"`
	ExecutionID     string                          `json:"executionId"`
	AccountID       string                          `json:"accountId"`
	GrantID         string                          `json:"grantId"`
	Profile         BrowserProfile                  `json:"profile"`
	SessionID       string                          `json:"sessionId"`
	ConnectURL      string                          `json:"connectUrl"`
	State           string                          `json:"state"` // starting, ready, closing, closed
	ExpiresAt       time.Time                       `json:"expiresAt"`
	AuthorizedUntil time.Time                       `json:"authorizedUntil"`
	Actions         map[string]BrowserActionReceipt `json:"actions"`
	Snapshot        *BrowserSnapshot                `json:"snapshot,omitempty"`
	DraftText       string                          `json:"draftText,omitempty"`
}
type BrowserActionReceipt struct {
	Digest     string `json:"digest"`
	State      string `json:"state"` // pending, issued, done
	ApprovalID string `json:"approvalId,omitempty"`
}
type BrowserRunStore interface {
	BrowserRuns(context.Context) ([]BrowserRun, error)
	WriteBrowserRun(context.Context, BrowserRun, int64) (BrowserRun, error)
}

func cloneBrowserRun(r BrowserRun) BrowserRun {
	raw, _ := json.Marshal(r)
	var copy BrowserRun
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// Only Platform's service actor can supply owner/client/execution authority.
// Model input is confined to Action. Engine never accepts a raw CDP command.
type BrowserControlRequest struct {
	Operation       string        `json:"operation"`
	Owner           string        `json:"owner"`
	OwnerRole       string        `json:"ownerRole"`
	ClientID        string        `json:"clientId"`
	Subject         string        `json:"subject"`
	AccountID       string        `json:"accountId"`
	Revision        int64         `json:"revision"`
	Mode            string        `json:"mode"`
	ExecutionID     string        `json:"executionId"`
	AuthorizedUntil time.Time     `json:"authorizedUntil"`
	CallID          string        `json:"callId"`
	Action          BrowserAction `json:"action"`
}
type BrowserAction struct {
	Operation string `json:"operation"`
	URL       string `json:"url,omitempty"`
	Snapshot  string `json:"snapshot,omitempty"`
	Element   int    `json:"element,omitempty"`
	Text      string `json:"text,omitempty"`
	Key       string `json:"key,omitempty"`
}
type BrowserElement struct {
	ID    int    `json:"id"`
	Role  string `json:"role"`
	Label string `json:"label"`
}
type BrowserSnapshot struct {
	ID       string           `json:"id"`
	URL      string           `json:"url"`
	Title    string           `json:"title"`
	Text     string           `json:"text"`
	Elements []BrowserElement `json:"elements"`
}
type BrowserAccountChoice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	WebsiteURL string `json:"websiteUrl"`
	Revision   int64  `json:"revision"`
	Mode       string `json:"mode"`
	Available  bool   `json:"available"`
}
type BrowserControlResult struct {
	Accounts   []BrowserAccountChoice `json:"accounts,omitempty"`
	Status     string                 `json:"status"`
	ApprovalID string                 `json:"approvalId,omitempty"`
	Snapshot   *BrowserSnapshot       `json:"snapshot,omitempty"`
	Message    string                 `json:"message,omitempty"`
}
type browserRuntimeProvider interface {
	CreateRuntimeSession(context.Context, BrowserProfile) (string, string, error)
	BrowserAction(context.Context, string, string, BrowserAction) (*BrowserSnapshot, error)
}

func browserOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return ""
	}
	return "https://" + strings.ToLower(u.Hostname())
}
func browserActionValid(a BrowserAction, website string) bool {
	switch a.Operation {
	case "open", "snapshot", "close", "scroll":
		return a.URL == "" && a.Text == "" && a.Key == "" && a.Element == 0 && a.Snapshot == ""
	case "navigate":
		return len(a.URL) <= 2048 && browserOrigin(a.URL) != "" && browserOrigin(a.URL) == browserOrigin(website) && !strings.ContainsAny(a.URL, "\r\n\t") && a.Text == "" && a.Element == 0 && a.Snapshot == "" && a.Key == ""
	case "click", "type", "press":
		return a.Element > 0 && a.Element <= 200 && browserResourceID(a.Snapshot) && a.URL == "" && len(a.Text) <= 8000 && (a.Operation == "type" || a.Text == "") && (a.Operation == "press" && (a.Key == "Enter" || a.Key == "Tab" || a.Key == "Escape") || a.Operation != "press" && a.Key == "")
	}
	return false
}
func browserActionWrites(a BrowserAction) bool {
	return a.Operation == "click" || a.Operation == "type" || a.Operation == "press"
}

func browserText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

// Leave room for the result envelope inside the runner's 32 KiB tool budget.
// Bounds apply to UTF-8 bytes, including pages in non-Latin scripts.
func boundBrowserSnapshot(s *BrowserSnapshot) bool {
	if s == nil || !browserResourceID(s.ID) || len(s.URL) > 2048 {
		return false
	}
	s.Title = browserText(s.Title, 300)
	s.Text = browserText(s.Text, 12000)
	if len(s.Elements) > 200 {
		s.Elements = s.Elements[:200]
	}
	for i := range s.Elements {
		if s.Elements[i].ID != i+1 {
			return false
		}
		s.Elements[i].Role = browserText(s.Elements[i].Role, 40)
		s.Elements[i].Label = browserText(s.Elements[i].Label, 160)
	}
	for {
		raw, err := json.Marshal(s)
		if err != nil {
			return false
		}
		if len(raw) <= 24<<10 {
			return true
		}
		if len(s.Elements) > 0 {
			s.Elements = s.Elements[:len(s.Elements)-1]
		} else {
			s.Text = browserText(s.Text, len(s.Text)/2)
		}
	}
}

func browserRunID(execution, account string) string {
	return "brun_" + oauthLinkHash(execution+":"+account)
}
