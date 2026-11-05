package engine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

const controlCapabilityAccountBrowser = "account-linking-browser"
const browserSignInLifetime = 10 * time.Minute

var errBrowserSignIn = errors.New("browser sign-in unavailable")
var errBrowserRevision = errors.New("browser sign-in changed")

// BrowserProfile is a private provider reference, never a cookie export or an
// execution grant. Each sign-in gets a fresh profile, including reconnects.
type BrowserProfile struct {
	Provider        string `json:"provider"`
	ConfigurationID string `json:"configuration_id"`
	FlowID          string `json:"flow_id"`
	ProfileID       string `json:"profile_id"`
	WebsiteURL      string `json:"website_url"`
}

func cloneBrowserProfile(p *BrowserProfile) *BrowserProfile {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
func validBrowserProfile(p BrowserProfile) bool {
	return p.Provider != "" && p.ConfigurationID != "" && p.FlowID != "" && p.ProfileID != "" && validBrowserWebsite(p.WebsiteURL)
}
func validBrowserWebsite(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".test", ".invalid"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return len(value) <= 2048 && !strings.ContainsAny(value, "\r\n\t")
}

// This durable ledger outlives its linked account. Removal and connection
// deletion cannot discard the only reference needed to erase a remote profile.
type BrowserSignIn struct {
	ID                string                    `json:"id"`
	Revision          int64                     `json:"revision"`
	OwnerSubject      string                    `json:"owner_subject"`
	ConnectionID      string                    `json:"connection_id"`
	Parent            AccountPolicyPrecondition `json:"parent"`
	AccountID         string                    `json:"account_id"`
	AccountRevision   int64                     `json:"account_revision"`
	DisplayName       string                    `json:"display_name"`
	WebsiteURL        string                    `json:"website_url"`
	Provider          string                    `json:"provider"`
	ConfigurationID   string                    `json:"configuration_id"`
	ProfileID         string                    `json:"profile_id"`
	SessionID         string                    `json:"session_id"`
	Method            string                    `json:"method,omitempty"`
	AuthConnectionID  string                    `json:"auth_connection_id,omitempty"`
	LastInteractionID string                    `json:"last_interaction_id,omitempty"`
	AllocationReady   bool                      `json:"allocation_ready,omitempty"`
	State             string                    `json:"state"` // starting, ready, saving, saved, cleanup, closed
	ExpiresAt         time.Time                 `json:"expires_at"`
	SyncAfter         time.Time                 `json:"sync_after"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}
type BrowserSignInStore interface {
	BrowserSignIns(context.Context) ([]BrowserSignIn, error)
	WriteBrowserSignIn(context.Context, BrowserSignIn, int64) (BrowserSignIn, error)
	CommitBrowserSignIn(context.Context, string, int64) (LinkedAccountRecord, error)
}

func browserFlowPending(f BrowserSignIn) bool {
	return f.State == "starting" || f.State == "ready" || f.State == "saving"
}
func prepareBrowserFlow(f BrowserSignIn, revision int64) (BrowserSignIn, error) {
	if f.Method != "" && f.Method != "browser" && f.Method != "credentials" {
		return f, errBrowserSignIn
	}
	if !validActorIdentifier(f.OwnerSubject) || f.ID == "" || f.ConnectionID == "" || f.Parent.IncarnationID == "" || f.Parent.Revision < 1 || !validBrowserWebsite(f.WebsiteURL) {
		return f, errBrowserSignIn
	}
	switch f.State {
	case "starting", "ready", "saving", "saved", "cleanup", "closed":
	default:
		return f, errBrowserSignIn
	}
	f.Revision = revision + 1
	f.UpdatedAt = time.Now().UTC()
	return f, nil
}
func browserFlowAccount(f BrowserSignIn, parent Account, records []LinkedAccountRecord) (LinkedAccountRecord, error) {
	if f.State != "saving" || time.Now().After(f.ExpiresAt) || f.ProfileID == "" || f.SyncAfter.IsZero() || time.Now().Before(f.SyncAfter) {
		return LinkedAccountRecord{}, errBrowserRevision
	}
	profile := &BrowserProfile{Provider: f.Provider, ConfigurationID: f.ConfigurationID, FlowID: f.ID, ProfileID: f.ProfileID, WebsiteURL: f.WebsiteURL}
	if f.AccountID == "" {
		count := 0
		for _, record := range records {
			if record.OwnerSubject == f.OwnerSubject && record.ConnectionID == f.ConnectionID && record.Boundary.IncarnationID == parent.IncarnationID {
				count++
			}
		}
		if count >= maxLinkedAccountsPerConnection {
			return LinkedAccountRecord{}, ErrLinkedAccountLimit
		}
		return newLinkedAccount(LinkedAccountRecord{ConnectionID: f.ConnectionID, OwnerSubject: f.OwnerSubject, DisplayName: f.DisplayName, Browser: profile}, parent)
	}
	for _, record := range records {
		if record.ID == f.AccountID && record.OwnerSubject == f.OwnerSubject && record.ConnectionID == f.ConnectionID && record.Boundary.IncarnationID == parent.IncarnationID {
			if record.Revision != f.AccountRevision {
				return LinkedAccountRecord{}, ErrLinkedAccountRevision
			}
			return mutateLinkedAccount(record, parent, LinkedAccountMutation{Browser: profile})
		}
	}
	return LinkedAccountRecord{}, ErrLinkedAccountNotFound
}
