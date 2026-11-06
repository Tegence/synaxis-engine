package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ConnectionModelContractVersion describes a read projection, not a new
// credential store or an authorization/dispatch contract. Account remains the
// backing record for existing MCP connections.
const ConnectionModelContractVersion = "synaxis.connection-model.v1"

const controlCapabilityConnectionAccountModel = "connection-account-model"

// controlCapabilityConnectionIntegrations tells a client that integrations[]
// lists every mechanism this Engine serves, with availability, and that
// connections and accounts carry the optional integration fields below.
const controlCapabilityConnectionIntegrations = "connection-integrations"

const (
	integrationMCP          = "mcp.streamable-http"
	integrationTokenAPI     = "token_api.bearer"
	integrationBrowser      = "browser.website"
	integrationOAuthPrefix  = "oauth."
	integrationStateReady   = "ready"
	integrationStateSetup   = "setup_required"
	integrationStateUpdate  = "update_required"
	agentAccessMCPDelivery  = "mcp_delivery"
	agentAccessBrowserGrant = "browser_grant"
	agentAccessNotAvailable = "not_available"
)

// IntegrationAvailability is computed by the same functions the start
// handlers use for their 409/501 refusals, so a client never offers a method
// that the Engine would then refuse for lack of setup.
type IntegrationAvailability struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func readyIntegration() IntegrationAvailability {
	return IntegrationAvailability{State: integrationStateReady}
}

// IntegrationDefinition describes a reusable execution mechanism. A definition
// never carries credentials or grants. Each entry is listed only under the
// capability gate that serves it. AgentAccess is descriptive: it names the
// only path through which agents could reach an account, never an authority.
type IntegrationDefinition struct {
	ID                 string                   `json:"id"`
	Mechanism          string                   `json:"mechanism"`
	Protocol           string                   `json:"protocol"`
	Kind               string                   `json:"kind,omitempty"`
	DisplayName        string                   `json:"displayName,omitempty"`
	RequiresConnection bool                     `json:"requiresConnection"`
	BindingModes       []AccountBindingMode     `json:"bindingModes,omitempty"`
	Availability       *IntegrationAvailability `json:"availability,omitempty"`
	AgentAccess        string                   `json:"agentAccess,omitempty"`
	Methods            []LinkedOAuthProviderDTO `json:"methods,omitempty"`
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
	// AccountLinkingBlocked says why AccountLinking is false on an Engine that
	// supports linking: caller_delegated or personal_other_owner.
	AccountLinkingBlocked string `json:"accountLinkingBlocked,omitempty"`
}

const (
	accountLinkingBlockedCallerDelegated = "caller_delegated"
	accountLinkingBlockedPersonalOther   = "personal_other_owner"
)

// ConnectedAccountUsableBy is descriptive only. It names the execution paths
// that could use this credential and is never an authority input: dispatch,
// grants and refresh decide independently.
type ConnectedAccountUsableBy struct {
	MCPDispatch    bool `json:"mcpDispatch"`
	BrowserRuntime bool `json:"browserRuntime"`
	APIDispatch    bool `json:"apiDispatch"`
}

// BrowserGrantView is a read-only projection of a grant on the caller's own
// browser account. CredentialChanged means the account was reconnected after
// the grant, so the runtime will refuse it; client epoch is not checked here.
type BrowserGrantView struct {
	ID                string `json:"id"`
	ClientID          string `json:"clientId"`
	Mode              string `json:"mode"`
	CreatedAt         string `json:"createdAt,omitempty"`
	CredentialChanged bool   `json:"credentialChanged"`
}

// ConnectedAccount represents a configured credential binding, not a verified
// provider user. Existing MCP credentials do not attest that user's identity or
// destinations, so neither is inferred from a URL, label, token or email.
type ConnectedAccount struct {
	ID                      string                    `json:"id"`
	ConnectionID            string                    `json:"connectionId"`
	ConnectionIncarnationID string                    `json:"connectionIncarnationId"`
	BindingMode             AccountBindingMode        `json:"bindingMode"`
	IdentityStatus          string                    `json:"identityStatus"`
	AuthMode                string                    `json:"authMode"`
	Source                  string                    `json:"source"`
	DisplayName             string                    `json:"displayName,omitempty"`
	Status                  string                    `json:"status,omitempty"`
	Revision                int64                     `json:"revision,omitempty"`
	WebsiteURL              string                    `json:"websiteUrl,omitempty"`
	BrowserProvider         string                    `json:"browserProvider,omitempty"`
	Provider                string                    `json:"provider,omitempty"`
	ProviderSubject         string                    `json:"providerSubject,omitempty"`
	ProviderName            string                    `json:"providerName,omitempty"`
	GrantedScopes           []string                  `json:"grantedScopes,omitempty"`
	ExpiresAt               string                    `json:"expiresAt,omitempty"`
	CredentialRevision      int64                     `json:"credentialRevision,omitempty"`
	IntegrationID           string                    `json:"integrationId,omitempty"`
	OwnerKind               string                    `json:"ownerKind,omitempty"`
	UsableBy                *ConnectedAccountUsableBy `json:"usableBy,omitempty"`
	BrowserGrants           []BrowserGrantView        `json:"browserGrants,omitempty"`
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
		Integrations:    []IntegrationDefinition{mcpIntegration()},
		Connections:     []Connection{}, ConnectedAccounts: []ConnectedAccount{},
		Capabilities: []string{controlCapabilityConnectionIntegrations},
	}
}

func mcpIntegration() IntegrationDefinition {
	ready := readyIntegration()
	return IntegrationDefinition{
		ID: integrationMCP, Mechanism: "mcp", Protocol: "streamable-http", Kind: "mcp",
		DisplayName: "MCP server", RequiresConnection: true,
		BindingModes: []AccountBindingMode{AccountBindingConnection, AccountBindingMember, AccountBindingCallerDelegated, AccountBindingExplicit},
		Availability: &ready, AgentAccess: agentAccessMCPDelivery,
	}
}

// Token linked accounts are explicit bindings, on an MCP connection or, with
// account-linking-standalone, owned directly by their member. No API adapter
// dispatches them yet.
func tokenAPIIntegration(standalone bool) IntegrationDefinition {
	ready := readyIntegration()
	return IntegrationDefinition{
		ID: integrationTokenAPI, Mechanism: "token_api", Protocol: "bearer", Kind: "token_api",
		DisplayName: "API token", RequiresConnection: !standalone,
		BindingModes: []AccountBindingMode{AccountBindingExplicit},
		Availability: &ready, AgentAccess: agentAccessNotAvailable,
	}
}

var browserSignInMethods = []struct{ id, label string }{
	{"browser", "Sign in in a browser"},
	{"credentials", "Sign in with credentials"},
}

// Website accounts need no connection; agents reach them only through an
// explicit browser grant.
func (c *ConsoleAPI) browserIntegration() IntegrationDefinition {
	_, availability := c.browserSignInMethod("browser")
	methods := []LinkedOAuthProviderDTO{}
	for _, method := range browserSignInMethods {
		_, current := c.browserSignInMethod(method.id)
		if current.State == integrationStateReady {
			availability = current
		}
		methods = append(methods, LinkedOAuthProviderDTO{ID: method.id, Label: method.label, Available: current.State == integrationStateReady, Scopes: []string{}})
	}
	return IntegrationDefinition{
		ID: integrationBrowser, Mechanism: "browser", Protocol: "website", Kind: "website",
		DisplayName: "Website", RequiresConnection: false,
		BindingModes: []AccountBindingMode{AccountBindingExplicit},
		Availability: &availability, AgentAccess: agentAccessBrowserGrant, Methods: methods,
	}
}

// OAuth linked accounts are explicit bindings, on an MCP connection or, with
// account-linking-standalone, owned directly by their member. No execution
// path uses them yet.
func (c *ConsoleAPI) oauthIntegrations() []IntegrationDefinition {
	out := []IntegrationDefinition{}
	_, standalone := c.standaloneLinkedAccounts()
	for _, provider := range c.accountOAuth.metadata() {
		availability := c.linkedOAuthProviderAvailability(provider.ID)
		out = append(out, IntegrationDefinition{
			ID: integrationOAuthPrefix + provider.ID, Mechanism: "oauth", Protocol: "oauth2", Kind: "oauth_api",
			DisplayName: provider.Label, RequiresConnection: !standalone,
			BindingModes: []AccountBindingMode{AccountBindingExplicit},
			Availability: &availability, AgentAccess: agentAccessNotAvailable,
			Methods: []LinkedOAuthProviderDTO{provider},
		})
	}
	return out
}

// browserSignInMethod is the single predicate behind both the browser sign-in
// start refusal and the browser.website availability.
func (c *ConsoleAPI) browserSignInMethod(method string) (browserSignInProvider, IntegrationAvailability) {
	if c.browserSignIn == nil {
		return nil, IntegrationAvailability{State: integrationStateUpdate, Reason: "browser sign-in requires an Engine update"}
	}
	provider := c.browserSignIn.signInProvider(method)
	if provider == nil {
		return nil, IntegrationAvailability{State: integrationStateSetup, Reason: "browser sign-in needs provider setup"}
	}
	return provider, readyIntegration()
}

// linkedOAuthProviderAvailability is the single predicate behind both the
// OAuth start/complete refusals and the oauth.<provider> availability.
func (c *ConsoleAPI) linkedOAuthProviderAvailability(provider string) IntegrationAvailability {
	_, flows := c.store.(LinkedOAuthFlowStore)
	_, links := c.store.(LinkedAccountStore)
	if !flows || !links || c.accountOAuth == nil {
		return IntegrationAvailability{State: integrationStateUpdate, Reason: "OAuth account linking requires an Engine update"}
	}
	_, configured := c.accountOAuth.apps[provider]
	_, known := c.accountOAuth.providers[provider]
	if !known || !configured {
		return IntegrationAvailability{State: integrationStateSetup, Reason: "this provider needs application setup"}
	}
	return readyIntegration()
}

// linkedAccountIntegrationID maps an explicit binding to the integration it
// belongs to. It never changes where the account can be used.
func linkedAccountIntegrationID(account ConnectedAccount) string {
	switch account.AuthMode {
	case "browser":
		return integrationBrowser
	case "oauth":
		return integrationOAuthPrefix + account.Provider
	default:
		return integrationTokenAPI
	}
}

// modelLinkedAccount adds, for the caller's own browser accounts, a
// read-only view of their grants to the linked-account DTO.
func modelLinkedAccount(record LinkedAccountRecord, parent Account) ConnectedAccount {
	account := linkedAccountDTO(record, parent)
	account.BrowserGrants = projectBrowserGrants(record)
	return account
}

func projectBrowserGrants(record LinkedAccountRecord) []BrowserGrantView {
	if record.Browser == nil || len(record.BrowserGrants) == 0 {
		return nil
	}
	out := make([]BrowserGrantView, 0, len(record.BrowserGrants))
	for _, g := range record.BrowserGrants {
		view := BrowserGrantView{ID: g.ID, ClientID: g.ClientID, Mode: g.Mode, CredentialChanged: g.CredentialRevision != record.CredentialRevision}
		if !g.CreatedAt.IsZero() {
			view.CreatedAt = g.CreatedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, view)
	}
	return out
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
		IntegrationID: integrationMCP, DisplayName: display, ToolPrefix: a.Name,
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
		Source: "legacy", IntegrationID: integrationMCP, OwnerKind: legacyOwnerKind(a, mode),
		UsableBy: &ConnectedAccountUsableBy{MCPDispatch: true},
	}
}

// A connection-mode credential on a personal connection belongs to that
// connection's owner; on any other scope it is the workspace's.
func legacyOwnerKind(a Account, mode AccountBindingMode) string {
	if mode == AccountBindingMember || a.IsPersonal() {
		return "member"
	}
	return "workspace"
}
