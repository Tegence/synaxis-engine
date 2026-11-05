package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
)

const controlCapabilityAccountLinking = "account-linking-token"
const maxLinkedAccountsPerConnection = 32

var (
	ErrLinkedAccountNotFound = errors.New("linked account not found")
	ErrLinkedAccountRevision = errors.New("linked account changed")
	ErrLinkedAccountInvalid  = errors.New("invalid linked account")
	ErrLinkedAccountLimit    = errors.New("linked account limit reached")
)

// LinkedAccountRecord is Engine-private durable state. It never participates
// in legacy Account/MemberCredential selection or namespace delivery. A future
// dispatcher must require an explicit grant and independently verify identity.
// Serialize only through linkedAccountDTO at an HTTP boundary.
type LinkedAccountRecord struct {
	ID                 string                      `json:"id"`
	ConnectionID       string                      `json:"connection_id"`
	OwnerSubject       string                      `json:"owner_subject"`
	Boundary           OAuthCompletionPrecondition `json:"boundary"`
	DisplayName        string                      `json:"display_name"`
	BearerToken        string                      `json:"bearer_token"`
	Revision           int64                       `json:"revision"`
	CredentialRevision int64                       `json:"credential_revision"`
	BrowserGrants      []BrowserAccountGrant       `json:"browser_grants,omitempty"`
	Browser            *BrowserProfile             `json:"browser,omitempty"`
	OAuth              *LinkedOAuthCredential      `json:"oauth,omitempty"`
	CreatedAt          time.Time                   `json:"created_at"`
	UpdatedAt          time.Time                   `json:"updated_at"`
}

type LinkedAccountMutation struct {
	DisplayName *string
	// nil preserves the token; an empty string disconnects the account.
	BearerToken          *string
	Remove               bool
	Browser              *BrowserProfile
	OAuth                *LinkedOAuthCredential
	BrowserGrant         *BrowserAccountGrant
	RevokeBrowserSubject string
	RevokeBrowserClient  string
}

type LinkedAccountStore interface {
	LinkedAccounts(context.Context, string) ([]LinkedAccountRecord, error)
	CreateLinkedAccount(context.Context, LinkedAccountRecord, AccountPolicyPrecondition) (LinkedAccountRecord, error)
	MutateLinkedAccount(context.Context, string, string, string, int64, AccountPolicyPrecondition, LinkedAccountMutation) (LinkedAccountRecord, error)
}

func normalizeLinkedAccountName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 160 || strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrLinkedAccountInvalid
	}
	return name, nil
}

func validLinkedAccountToken(token string, allowEmpty bool) bool {
	return (allowEmpty || token != "") && len(token) <= 16384 && strings.TrimSpace(token) == token &&
		!strings.ContainsFunc(token, unicode.IsSpace) && !strings.ContainsFunc(token, unicode.IsControl)
}

func newLinkedAccount(record LinkedAccountRecord, parent Account) (LinkedAccountRecord, error) {
	name, err := normalizeLinkedAccountName(record.DisplayName)
	if err != nil || !validLinkedCredential(record) || record.OwnerSubject == "" || !validActorIdentifier(record.OwnerSubject) || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != record.OwnerSubject) {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	now := time.Now().UTC()
	return LinkedAccountRecord{
		ID: "lacc_" + newEpoch(), ConnectionID: parent.Name, OwnerSubject: record.OwnerSubject,
		Boundary: oauthCompletionPreconditionForAccount(parent), DisplayName: name, BearerToken: record.BearerToken,
		Revision: 1, CredentialRevision: 1, CreatedAt: now, UpdatedAt: now, OAuth: cloneOAuthCredential(record.OAuth), Browser: cloneBrowserProfile(record.Browser),
	}, nil
}

func linkedAccountBoundaryMatches(record LinkedAccountRecord, parent Account) bool {
	p := record.Boundary
	return p.IncarnationID == parent.IncarnationID && equalAccountURL(p.URL, parent.URL) &&
		p.ConnectionNamespaceID == parent.ConnectionNamespaceID && p.ConnectionScope == parent.ConnectionScope && p.OwnerSubject == parent.OwnerSubject && !parent.CallerDelegated
}

func mutateLinkedAccount(record LinkedAccountRecord, parent Account, mutation LinkedAccountMutation) (LinkedAccountRecord, error) {
	record.BrowserGrants = slices.Clone(record.BrowserGrants)
	if mutation.BrowserGrant != nil || mutation.RevokeBrowserClient != "" {
		if record.Browser == nil || !linkedAccountBoundaryMatches(record, parent) {
			return LinkedAccountRecord{}, ErrLinkedAccountInvalid
		}
		client := mutation.RevokeBrowserClient
		subject := mutation.RevokeBrowserSubject
		if mutation.BrowserGrant != nil {
			g := *mutation.BrowserGrant
			if !validBrowserGrant(g) || g.CredentialRevision != record.CredentialRevision || !validBrowserProfile(*record.Browser) {
				return LinkedAccountRecord{}, ErrLinkedAccountInvalid
			}
			client = g.ClientID
			subject = g.Subject
		}
		record.BrowserGrants = slices.DeleteFunc(record.BrowserGrants, func(g BrowserAccountGrant) bool { return g.ClientID == client || subject != "" && g.Subject == subject })
		if mutation.BrowserGrant != nil {
			if len(record.BrowserGrants) >= 32 {
				return LinkedAccountRecord{}, ErrLinkedAccountLimit
			}
			record.BrowserGrants = append(record.BrowserGrants, *mutation.BrowserGrant)
		}
	}
	if mutation.BearerToken != nil || mutation.OAuth != nil || mutation.Browser != nil {
		record.BrowserGrants = nil
	}
	if mutation.DisplayName != nil {
		name, err := normalizeLinkedAccountName(*mutation.DisplayName)
		if err != nil {
			return LinkedAccountRecord{}, err
		}
		record.DisplayName = name
	}
	if mutation.BearerToken != nil {
		token := *mutation.BearerToken
		if (token != "" && (record.OAuth != nil || record.Browser != nil)) || !validLinkedAccountToken(token, true) || (token != "" && (parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != record.OwnerSubject))) {
			return LinkedAccountRecord{}, ErrLinkedAccountInvalid
		}
		record.BearerToken = token
		if record.Browser != nil {
			record.Browser = cloneBrowserProfile(record.Browser)
			record.Browser.ProfileID = ""
		}
		if record.OAuth != nil {
			record.OAuth = cloneOAuthCredential(record.OAuth)
			record.OAuth.AccessToken = ""
			record.OAuth.RefreshToken = ""
		}
		record.CredentialRevision++
		// Re-entering a token explicitly acknowledges the current connection.
		// Metadata edits and disconnection never silently rebind authorization.
		if token != "" {
			record.Boundary = oauthCompletionPreconditionForAccount(parent)
		}
	}
	if mutation.OAuth != nil {
		if record.Browser != nil || record.OAuth == nil || record.OAuth.Provider != mutation.OAuth.Provider || record.OAuth.ClientID != mutation.OAuth.ClientID || record.OAuth.Subject != mutation.OAuth.Subject || !validOAuthCredential(*mutation.OAuth) || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != record.OwnerSubject) {
			return LinkedAccountRecord{}, ErrLinkedAccountInvalid
		}
		record.OAuth = cloneOAuthCredential(mutation.OAuth)
		record.Boundary = oauthCompletionPreconditionForAccount(parent)
		record.CredentialRevision++
	}
	if mutation.Browser != nil {
		if record.Browser == nil || record.OAuth != nil || !validBrowserProfile(*mutation.Browser) || record.Browser.Provider != mutation.Browser.Provider || record.Browser.ConfigurationID != mutation.Browser.ConfigurationID || record.Browser.WebsiteURL != mutation.Browser.WebsiteURL || parent.CallerDelegated || (parent.IsPersonal() && parent.OwnerSubject != record.OwnerSubject) {
			return LinkedAccountRecord{}, ErrLinkedAccountInvalid
		}
		record.Browser = cloneBrowserProfile(mutation.Browser)
		record.Boundary = oauthCompletionPreconditionForAccount(parent)
		record.CredentialRevision++
	}
	record.Revision++
	record.UpdatedAt = time.Now().UTC()
	return record, nil
}

func linkedAccountDTO(record LinkedAccountRecord, parent Account) ConnectedAccount {
	status := "linked"
	present := record.BearerToken != "" || record.OAuth != nil && record.OAuth.AccessToken != "" || record.Browser != nil && record.Browser.ProfileID != ""
	if !present {
		status = "disconnected"
	} else if !linkedAccountBoundaryMatches(record, parent) {
		status = "connection_changed"
	}
	account := ConnectedAccount{
		ID: record.ID, ConnectionID: record.ConnectionID, ConnectionIncarnationID: record.Boundary.IncarnationID,
		BindingMode: AccountBindingExplicit, IdentityStatus: "opaque", AuthMode: "token", Source: "linked",
		DisplayName: record.DisplayName, Status: status, Revision: record.Revision, CredentialRevision: record.CredentialRevision,
	}
	if record.OAuth != nil {
		account.AuthMode = "oauth"
		account.IdentityStatus = "provider_confirmed"
		account.Provider = record.OAuth.Provider
		account.ProviderSubject = record.OAuth.Subject
		account.ProviderName = record.OAuth.ProviderName
		account.GrantedScopes = append([]string{}, record.OAuth.Scopes...)
		account.ExpiresAt = record.OAuth.ExpiresAt.UTC().Format(time.RFC3339)
		if status == "linked" && !record.OAuth.ExpiresAt.After(time.Now()) {
			account.Status = "expired"
		}
	}
	if record.Browser != nil {
		account.AuthMode = "browser"
		account.WebsiteURL = record.Browser.WebsiteURL
		account.BrowserProvider = record.Browser.Provider
	}
	return account
}

func cloneOAuthCredential(value *LinkedOAuthCredential) *LinkedOAuthCredential {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Scopes = append([]string{}, value.Scopes...)
	return &clone
}

func validLinkedCredential(record LinkedAccountRecord) bool {
	if record.Browser != nil {
		return record.OAuth == nil && record.BearerToken == "" && validBrowserProfile(*record.Browser)
	}
	if record.OAuth != nil {
		return record.BearerToken == "" && validOAuthCredential(*record.OAuth)
	}
	return validLinkedAccountToken(record.BearerToken, false)
}
