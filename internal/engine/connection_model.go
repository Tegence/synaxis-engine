package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// ConnectionModelContractVersion describes a read projection, not a new
// credential store or an authorization/dispatch contract. Account remains the
// backing record for existing MCP connections.
const ConnectionModelContractVersion = "synaxis.connection-model.v1"

const controlCapabilityConnectionAccountModel = "connection-account-model"

// IntegrationDefinition describes a reusable execution mechanism. A definition
// never carries credentials or grants. This slice advertises only MCP; API and
// browser adapters must negotiate their own capabilities before use.
type IntegrationDefinition struct {
	ID        string `json:"id"`
	Mechanism string `json:"mechanism"`
	Protocol  string `json:"protocol"`
}

type AccountBindingMode string

const (
	AccountBindingConnection      AccountBindingMode = "connection"
	AccountBindingMember          AccountBindingMode = "member"
	AccountBindingCallerDelegated AccountBindingMode = "caller_delegated"
	AccountBindingExplicit        AccountBindingMode = "explicit"
)

// ConnectionAccountBinding explains how execution chooses a credential. The
// account IDs are references only; neither they nor credential presence prove
// permission, token validity, provider identity, or anonymous access.
type ConnectionAccountBinding struct {
	Mode            AccountBindingMode `json:"mode"`
	CredentialState string             `json:"credentialState"`
	AccountIDs      []string           `json:"accountIds"`
}

// Connection is a configured integration in an existing credential ownership
// namespace. ID and ToolPrefix deliberately preserve Account.Name.
type Connection struct {
	ID                    string                   `json:"id"`
	IncarnationID         string                   `json:"incarnationId"`
	Revision              int64                    `json:"revision"`
	IntegrationID         string                   `json:"integrationId"`
	DisplayName           string                   `json:"displayName"`
	ToolPrefix            string                   `json:"toolPrefix"`
	ConnectionNamespaceID string                   `json:"connectionNamespaceId,omitempty"`
	Scope                 ConnectionScope          `json:"scope"`
	OwnerSubject          string                   `json:"ownerSubject,omitempty"`
	ReadOnly              bool                     `json:"readOnly"`
	AccountBinding        ConnectionAccountBinding `json:"accountBinding"`
	AccountLinking        bool                     `json:"accountLinking"`
}

// ConnectedAccount represents a configured credential binding, not a verified
// provider user. Existing MCP credentials do not attest that user's identity or
// destinations, so neither is inferred from a URL, label, token or email.
type ConnectedAccount struct {
	ID                      string             `json:"id"`
	ConnectionID            string             `json:"connectionId"`
	ConnectionIncarnationID string             `json:"connectionIncarnationId"`
	BindingMode             AccountBindingMode `json:"bindingMode"`
	IdentityStatus          string             `json:"identityStatus"`
	AuthMode                string             `json:"authMode"`
	Source                  string             `json:"source"`
	DisplayName             string             `json:"displayName,omitempty"`
	Status                  string             `json:"status,omitempty"`
	Revision                int64              `json:"revision,omitempty"`
	WebsiteURL              string             `json:"websiteUrl,omitempty"`
	BrowserProvider         string             `json:"browserProvider,omitempty"`
	Provider                string             `json:"provider,omitempty"`
	ProviderSubject         string             `json:"providerSubject,omitempty"`
	ProviderName            string             `json:"providerName,omitempty"`
	GrantedScopes           []string           `json:"grantedScopes,omitempty"`
	ExpiresAt               string             `json:"expiresAt,omitempty"`
	CredentialRevision      int64              `json:"credentialRevision,omitempty"`
}

type ConnectionModel struct {
	ContractVersion   string                     `json:"contractVersion"`
	Integrations      []IntegrationDefinition    `json:"integrations"`
	Connections       []Connection               `json:"connections"`
	ConnectedAccounts []ConnectedAccount         `json:"connectedAccounts"`
	BrowserSignIn     *BrowserSignInAvailability `json:"browserSignIn,omitempty"`
	OAuthProviders    []LinkedOAuthProviderDTO   `json:"oauthProviders,omitempty"`
	Capabilities      []string                   `json:"capabilities"`
}

func newConnectionModel() ConnectionModel {
	return ConnectionModel{
		ContractVersion: ConnectionModelContractVersion,
		Integrations: []IntegrationDefinition{{
			ID: "mcp.streamable-http", Mechanism: "mcp", Protocol: "streamable-http",
		}},
		Connections: []Connection{}, ConnectedAccounts: []ConnectedAccount{}, Capabilities: []string{},
	}
}

func projectConnection(a Account) Connection {
	display := a.Label
	if display == "" {
		display = a.Name
	}
	scope, _ := normalizedConnectionScope(a.ConnectionScope)
	binding := ConnectionAccountBinding{
		Mode: AccountBindingConnection, CredentialState: "missing", AccountIDs: []string{},
	}
	switch {
	case a.CallerDelegated:
		binding.Mode, binding.CredentialState = AccountBindingCallerDelegated, "requires_caller_grant"
	case a.MemberCredentials:
		binding.Mode = AccountBindingMember
	}
	return Connection{
		ID: a.Name, IncarnationID: a.IncarnationID, Revision: a.Revision,
		IntegrationID: "mcp.streamable-http", DisplayName: display, ToolPrefix: a.Name,
		ConnectionNamespaceID: a.ConnectionNamespaceID, Scope: scope, OwnerSubject: a.OwnerSubject,
		ReadOnly: a.ReadOnly, AccountBinding: binding,
	}
}

func connectionCredentialPresent(authMode, access, refresh, bearer string) bool {
	switch authMode {
	case "oauth":
		return access != "" || refresh != ""
	case "token":
		return bearer != ""
	default:
		return false
	}
}

// The ID names the existing credential slot. It survives refresh, renaming and
// namespace moves, but cannot cross a connection incarnation or member subject.
// It is not a bearer, provider-identity proof or a future account-selection grant.
func projectConnectedAccount(a Account, mode AccountBindingMode, subject string) ConnectedAccount {
	identity, _ := json.Marshal([]string{"synaxis.connected-account.v1", a.Name, a.IncarnationID, string(mode), subject})
	digest := sha256.Sum256(identity)
	return ConnectedAccount{
		ID:           "cacc_" + base64.RawURLEncoding.EncodeToString(digest[:]),
		ConnectionID: a.Name, ConnectionIncarnationID: a.IncarnationID,
		BindingMode: mode, IdentityStatus: "opaque", AuthMode: a.AuthMode,
		Source: "legacy",
	}
}
