package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Account is one connected backend (one provider account). Replaces MetaMCP's
// opaque oauth_sessions row + the \x1f-packed description hack with plain fields
// we own. Every account belongs to one owning connection namespace through
// Group; accounts in different namespaces keep independent credentials and
// stable tool prefixes even when they use the same provider and expose the same
// bare methods.
type Account struct {
	Name  string `json:"name"`  // tool prefix Claude sees: <Name>__<tool>
	Label string `json:"label"` // friendly display name
	// Group is the legacy, display-only alias for the owning connection
	// namespace's label. ConnectionNamespaceID is authoritative. Keeping this
	// field lets rolling upgrades and portable configs remain compatible, but
	// authorization and data-plane routing must never derive a boundary from a
	// human-readable group label.
	Group    string `json:"group"`
	URL      string `json:"url"`       // upstream MCP endpoint
	AuthMode string `json:"auth_mode"` // "oauth" | "token"

	// ConnectionNamespaceID identifies the first-class namespace that owns the
	// credential. It is deliberately unrelated to Namespace/EndpointBundle,
	// which is a shared delivery endpoint. Moving this value must not change
	// Name: the account name is the stable model-visible tool prefix.
	ConnectionNamespaceID string          `json:"connection_namespace_id,omitempty"`
	ConnectionScope       ConnectionScope `json:"connection_scope,omitempty"`
	OwnerSubject          string          `json:"owner_subject,omitempty"`
	Revision              int64           `json:"revision,omitempty"`
	// IncarnationID is minted once when this account row is created and is
	// never accepted from an update. OAuth browser flows capture it before
	// redirecting to the provider so a delayed callback cannot write credentials
	// into a deleted-and-recreated account that happens to reuse Name and URL.
	IncarnationID string `json:"incarnation_id,omitempty"`

	ClientID      string `json:"client_id,omitempty"`
	ClientSecret  string `json:"client_secret,omitempty"`
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	Resource      string `json:"resource,omitempty"`

	// Scope is the OAuth scope requested at connect. Only set on the
	// static-client (pre-registered app) path — DCR accounts leave it "".
	// Not a secret. Persisted so it's visible/re-usable; runtime refresh
	// doesn't re-send it.
	Scope string `json:"scope,omitempty"`

	BearerToken string `json:"bearer_token,omitempty"` // token-auth (e.g. a GitHub PAT)

	// DisabledTools are bare (un-prefixed) tool names the user has switched off
	// for this account — they are not registered into the aggregator, so Claude
	// never sees them. Curation: fewer, sharper tools.
	DisabledTools []string `json:"disabled_tools,omitempty"`

	// ToolOverrides rewrites the model-visible name and description of an
	// upstream tool without changing the source name used to dispatch calls.
	// Keys are the upstream's bare names. Connector allowlists and audit rows
	// deliberately keep using those stable source names.
	ToolOverrides map[string]ToolOverride `json:"tool_overrides,omitempty"`

	// ReadOnly restricts the account to read-only tools: only tools annotated
	// ReadOnlyHint (or, absent annotations, matching a conservative read-name
	// heuristic) are registered. Mutating tools are never exposed to Claude.
	ReadOnly bool `json:"readOnly,omitempty"`
}

// ConnectionScope describes how an account may be exposed. It is an account
// property rather than a label convention: old Account.Group values such as
// "Personal" are just labels and are backfilled as shared until explicitly
// migrated by an authorized actor.
type ConnectionScope string

const (
	ConnectionScopeShared   ConnectionScope = "shared"
	ConnectionScopePersonal ConnectionScope = "personal"
	ConnectionScopeService  ConnectionScope = "service"
)

func normalizedConnectionScope(scope ConnectionScope) (ConnectionScope, error) {
	switch ConnectionScope(strings.ToLower(strings.TrimSpace(string(scope)))) {
	case "", ConnectionScopeShared:
		return ConnectionScopeShared, nil
	case ConnectionScopePersonal:
		return ConnectionScopePersonal, nil
	case ConnectionScopeService:
		return ConnectionScopeService, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidConnectionScope, scope)
	}
}

// IsPersonal reports whether the account must remain out of all current
// shared MCP surfaces. A future subject-bound endpoint may expose such an
// account to its owner, but the aggregate /mcp, endpoint bundles, and virtual
// connectors are intentionally never that endpoint.
func (a Account) IsPersonal() bool {
	scope, err := normalizedConnectionScope(a.ConnectionScope)
	return err == nil && scope == ConnectionScopePersonal
}

// ConnectionNamespace is the durable ownership boundary for credentials.
// It is purposefully distinct from Namespace (the former narthex_namespaces
// endpoint-bundle abstraction). IDs are opaque/stable; Slug is a friendly
// stable handle for management clients and is never used as a tool prefix.
// CreatedBy is immutable audit attribution only; ManagerGrants is the sole
// source of namespace-management authority.
type ConnectionNamespace struct {
	ID            string                            `json:"id"`
	Slug          string                            `json:"slug"`
	Label         string                            `json:"label"`
	Revision      int64                             `json:"revision"`
	CreatedBy     string                            `json:"created_by,omitempty"`
	CreatedAt     time.Time                         `json:"created_at,omitempty"`
	UpdatedAt     time.Time                         `json:"updated_at,omitempty"`
	ManagerGrants []ConnectionNamespaceManagerGrant `json:"manager_grants,omitempty"`
}

// ConnectionNamespaceManagerGrant is an explicit subject grant. Actor
// authorization is enforced by the management layer; the store preserves the
// grants atomically so every Engine replica sees the same boundary.
type ConnectionNamespaceManagerGrant struct {
	Subject string `json:"subject"`
}

// ConnectionNamespacePrecondition is the optimistic-concurrency token for a
// connection-namespace mutation. IDs are never reused, so ID+revision is a
// complete compare-and-swap identity.
type ConnectionNamespacePrecondition struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// AccountConnectionAssignment is the mutable ownership portion of an account.
// The account Name is intentionally absent: moving an account must retain its
// existing model-visible prefix and provider credential.
type AccountConnectionAssignment struct {
	ConnectionNamespaceID string          `json:"connection_namespace_id"`
	Scope                 ConnectionScope `json:"scope"`
	OwnerSubject          string          `json:"owner_subject,omitempty"`
}

// AccountPolicyPrecondition binds a console policy write to the exact
// credential boundary which was authorized before the request began. The
// account incarnation prevents a delete/recreate from reusing Name, while the
// revision and assignment facts prevent a former namespace manager from
// changing policy after a concurrent move. Policy writes must never update
// any of these ownership fields themselves.
type AccountPolicyPrecondition struct {
	IncarnationID         string          `json:"incarnation_id"`
	Revision              int64           `json:"revision"`
	ConnectionNamespaceID string          `json:"connection_namespace_id"`
	ConnectionScope       ConnectionScope `json:"connection_scope"`
	OwnerSubject          string          `json:"owner_subject,omitempty"`
}

// accountPolicyPrecondition captures the durable identity and ownership
// generation from a just-authorized Account snapshot.
func accountPolicyPrecondition(a Account) AccountPolicyPrecondition {
	return AccountPolicyPrecondition{
		IncarnationID:         a.IncarnationID,
		Revision:              a.Revision,
		ConnectionNamespaceID: a.ConnectionNamespaceID,
		ConnectionScope:       a.ConnectionScope,
		OwnerSubject:          a.OwnerSubject,
	}
}

func (p AccountPolicyPrecondition) matches(a Account) bool {
	return p.IncarnationID != "" &&
		p.Revision >= 1 &&
		p.ConnectionNamespaceID != "" &&
		p.IncarnationID == a.IncarnationID &&
		p.Revision == a.Revision &&
		p.ConnectionNamespaceID == a.ConnectionNamespaceID &&
		p.ConnectionScope == a.ConnectionScope &&
		p.OwnerSubject == a.OwnerSubject
}

// AccountPolicyMutation contains only mutable curation/presentation fields.
// A nil field leaves that value untouched; a non-nil pointer intentionally
// permits setting a field to its zero value (for example, an empty disabled
// list or readOnly=false). It deliberately has no ownership or credential
// fields, so a stale console snapshot cannot restore either one.
type AccountPolicyMutation struct {
	Label         *string
	DisabledTools *[]string
	ToolOverrides *map[string]ToolOverride
	ReadOnly      *bool
}

// ToolOverride is the operator-owned presentation policy for one upstream
// tool. Alias is the bare name Claude sees after the account prefix;
// Description replaces the upstream description. Empty fields inherit the
// upstream definition.
type ToolOverride struct {
	Alias       string `json:"alias,omitempty"`
	Description string `json:"description,omitempty"`
}

// VirtualConnector is a named, curated subset of the aggregated tools, served
// at its own MCP endpoint /mcp/{slug}. Tools maps account name -> BARE tool
// names (no <account>__ prefix — same convention as Account.DisabledTools).
// An account with an empty/absent list contributes nothing; only explicitly
// listed tools are exposed.
type VirtualConnector struct {
	Slug  string              `json:"slug"`
	Label string              `json:"label"`
	Tools map[string][]string `json:"tools"`

	// Epoch is this connector's token generation: a random string minted once
	// at create (Gateway.UpsertConnector) and preserved across updates. The
	// OAuth AS bakes it into the HMAC of every access token issued for
	// /mcp/{slug}, so deleting the connector — and recreating the slug, which
	// mints a FRESH epoch — invalidates all previously issued tokens without
	// the AS having to persist any token state. Legacy records load as ""
	// (a valid, stable epoch for that connector's lifetime).
	Epoch string `json:"epoch,omitempty"`

	// Approval maps account name -> BARE tool names that require human
	// approval before a call on this connector dispatches. Semantically a
	// subset of Tools, but not hard-enforced here — enforcement intersects
	// with the allowlist at runtime. Legacy records without the field load
	// as empty (nothing requires approval).
	Approval map[string][]string `json:"approval,omitempty"`

	// Record opts this connector's endpoint into flight-recorder payload
	// capture: request args + result of every call are stored (size-capped,
	// encrypted at rest in Postgres) alongside the audit row. Legacy records
	// without the field load as false (summary-only auditing).
	Record bool `json:"record,omitempty"`

	// MaxResultBytes caps the total TEXT content of a tool RESULT served
	// through this connector's endpoint (0 = off). Response-side guardrail:
	// oversized results are rune-safely truncated with a visible marker
	// before they reach the model. The default /mcp endpoint is a raw
	// passthrough — guardrails are a connector feature. Legacy records
	// without the field load as 0 (no cap).
	MaxResultBytes int `json:"maxResultBytes,omitempty"`

	// Redact is a list of operator-supplied RE2 regex patterns applied to
	// every text content item of a tool RESULT on this connector's endpoint;
	// matches are replaced with "[redacted]" before the model (or the audit
	// recorder) sees them. Patterns are validated at create/update and
	// compiled at connector build time. Legacy records without the field
	// load as empty (no redaction). Connector-only — /mcp stays passthrough.
	Redact []string `json:"redact,omitempty"`

	// DisableInjectionScan turns off the built-in response injection scanner.
	// The negative form preserves the secure historical default for existing
	// connector rows that predate this setting.
	DisableInjectionScan bool `json:"disableInjectionScan,omitempty"`
}

// ConnectorStore persists virtual connectors. Both FileStore and PgStore
// satisfy it alongside AccountStore.
type ConnectorStore interface {
	Connectors(ctx context.Context) ([]VirtualConnector, error)
	VirtualConnector(ctx context.Context, slug string) (VirtualConnector, bool)
	UpsertConnector(ctx context.Context, c VirtualConnector) error
	DeleteConnector(ctx context.Context, slug, expectedGeneration string) error
}

// EndpointBundle is a reusable, provider-agnostic collection of connected
// accounts served at /mcp/{slug}. Every member contributes all of its currently
// enabled cached tools. Account names remain the stable tool prefixes;
// membership never changes account ownership, credentials, or tool names.
//
// This is distinct from Account.Group, which is the account's owning connection
// namespace. "Namespace" was the original product/storage name for endpoint
// bundles and remains below as a source-compatible alias.
type EndpointBundle struct {
	Slug  string `json:"slug"`
	Label string `json:"label"`
	// Epoch identifies the endpoint generation. Membership/config edits keep it
	// stable, so an already-authorized client sees the namespace's current
	// contents; delete + recreate rotates it and revokes the old resource.
	Epoch    string   `json:"epoch,omitempty"`
	Revision int64    `json:"revision"`
	Accounts []string `json:"accounts"`
}

// Namespace is the legacy source/storage name for EndpointBundle.
// Deprecated: prefer EndpointBundle in new product-facing code.
type Namespace = EndpointBundle

// NamespacePrecondition is the compare-and-swap identity required for every
// mutation of an existing namespace. Revision alone is insufficient because a
// deleted slug may be recreated with revision 1; Generation distinguishes
// those otherwise-identical incarnations.
type NamespacePrecondition struct {
	Generation string `json:"generation"`
	Revision   int64  `json:"revision"`
}

// NamespaceStore persists normalized many-to-many endpoint-bundle membership.
// Both built-in stores implement it alongside AccountStore and ConnectorStore.
// Its legacy name is retained so existing store implementations remain source
// compatible.
type NamespaceStore interface {
	Namespaces(ctx context.Context) ([]Namespace, error)
	Namespace(ctx context.Context, slug string) (Namespace, bool)
	CreateNamespace(ctx context.Context, ns Namespace) error
	UpdateNamespace(ctx context.Context, ns Namespace, precondition NamespacePrecondition) (Namespace, error)
	AddNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error)
	RemoveNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error)
	DeleteNamespace(ctx context.Context, slug string, precondition NamespacePrecondition) error
}

// EndpointBundleStore is the preferred product-facing name for NamespaceStore.
type EndpointBundleStore = NamespaceStore

// ConnectionNamespaceStore persists account-ownership namespaces. It is not
// an endpoint store: callers cannot use these records to create a shared MCP
// route. The management API will layer actor/role checks over these atomic
// operations rather than trusting a client-supplied namespace label.
type ConnectionNamespaceStore interface {
	ConnectionNamespaces(ctx context.Context) ([]ConnectionNamespace, error)
	ConnectionNamespace(ctx context.Context, id string) (ConnectionNamespace, bool)
	ConnectionNamespaceBySlug(ctx context.Context, slug string) (ConnectionNamespace, bool)
	CreateConnectionNamespace(ctx context.Context, ns ConnectionNamespace) (ConnectionNamespace, error)
	UpdateConnectionNamespace(ctx context.Context, ns ConnectionNamespace, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error)
	SetConnectionNamespaceManagers(ctx context.Context, id string, managers []ConnectionNamespaceManagerGrant, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error)
	DeleteConnectionNamespace(ctx context.Context, id string, precondition ConnectionNamespacePrecondition) error
	MoveAccountToConnectionNamespace(ctx context.Context, account, expectedIncarnationID string, assignment AccountConnectionAssignment, expectedRevision int64) (Account, error)
}

var (
	ErrNamespaceExists    = errors.New("namespace already exists")
	ErrNamespaceNotFound  = errors.New("namespace not found")
	ErrNamespaceRevision  = errors.New("namespace revision conflict")
	ErrAccountNotFound    = errors.New("account not found")
	ErrEndpointCollision  = errors.New("endpoint slug already exists")
	ErrConnectorNotFound  = errors.New("connector not found")
	ErrEndpointGeneration = errors.New("endpoint generation conflict")

	ErrConnectionNamespaceExists   = errors.New("connection namespace already exists")
	ErrConnectionNamespaceNotFound = errors.New("connection namespace not found")
	ErrConnectionNamespaceRevision = errors.New("connection namespace revision conflict")
	ErrConnectionNamespaceInUse    = errors.New("connection namespace still owns accounts")
	ErrInvalidConnectionScope      = errors.New("invalid connection scope")
	ErrPersonalAccountExposure     = errors.New("personal account cannot be exposed through a shared endpoint")
	// ErrAccountPolicyPrecondition is returned when an account changed between
	// console authorization and a curation/presentation write. Handlers map it
	// to a deliberately generic 409 so no newly-private namespace details leak.
	ErrAccountPolicyPrecondition = errors.New("account policy precondition conflict")
)

func copyAccount(a Account) Account {
	cp := a
	cp.DisabledTools = append([]string(nil), a.DisabledTools...)
	if a.ToolOverrides != nil {
		cp.ToolOverrides = make(map[string]ToolOverride, len(a.ToolOverrides))
		for name, override := range a.ToolOverrides {
			cp.ToolOverrides[name] = override
		}
	}
	return cp
}

func sameToolOverrides(a, b map[string]ToolOverride) bool {
	if len(a) != len(b) {
		return false
	}
	for name, left := range a {
		right, ok := b[name]
		if !ok || left != right {
			return false
		}
	}
	return true
}

func copyConnectionNamespace(ns ConnectionNamespace) ConnectionNamespace {
	cp := ns
	cp.ManagerGrants = append([]ConnectionNamespaceManagerGrant(nil), ns.ManagerGrants...)
	return cp
}

func normalizedManagerGrants(grants []ConnectionNamespaceManagerGrant) []ConnectionNamespaceManagerGrant {
	seen := make(map[string]struct{}, len(grants))
	for _, grant := range grants {
		subject := strings.TrimSpace(grant.Subject)
		if subject != "" {
			seen[subject] = struct{}{}
		}
	}
	out := make([]ConnectionNamespaceManagerGrant, 0, len(seen))
	for subject := range seen {
		out = append(out, ConnectionNamespaceManagerGrant{Subject: subject})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

// initialConnectionNamespaceManagerGrants records the creator as an explicit
// initial manager. Subsequent membership updates use normalizedManagerGrants
// directly, so an administrator can revoke that grant without it reappearing.
func initialConnectionNamespaceManagerGrants(grants []ConnectionNamespaceManagerGrant, createdBy string) []ConnectionNamespaceManagerGrant {
	initial := append([]ConnectionNamespaceManagerGrant(nil), grants...)
	if createdBy = strings.TrimSpace(createdBy); createdBy != "" {
		initial = append(initial, ConnectionNamespaceManagerGrant{Subject: createdBy})
	}
	return normalizedManagerGrants(initial)
}

func sameManagerGrants(a, b []ConnectionNamespaceManagerGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Subject != b[i].Subject {
			return false
		}
	}
	return true
}

func normalizeConnectionNamespaceSlug(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func defaultConnectionNamespaceLabel(a Account) string {
	if label := strings.TrimSpace(a.Group); label != "" {
		return label
	}
	switch a.ConnectionScope {
	case ConnectionScopePersonal:
		return "Personal"
	case ConnectionScopeService:
		return "Services"
	default:
		return "General"
	}
}

func newConnectionNamespaceID() string { return "cns_" + newEpoch() }

func newAccountIncarnationID() string { return "accti_" + newEpoch() }

func normalizeAccountConnection(a *Account) error {
	scope, err := normalizedConnectionScope(a.ConnectionScope)
	if err != nil {
		return err
	}
	a.ConnectionScope = scope
	a.ConnectionNamespaceID = strings.TrimSpace(a.ConnectionNamespaceID)
	a.OwnerSubject = strings.TrimSpace(a.OwnerSubject)
	if scope == ConnectionScopePersonal && a.OwnerSubject == "" {
		return fmt.Errorf("%w: personal accounts require an owner subject", ErrInvalidConnectionScope)
	}
	if a.Revision < 1 {
		a.Revision = 1
	}
	return nil
}

func connectionNamespacePreconditionMatches(ns ConnectionNamespace, precondition ConnectionNamespacePrecondition) bool {
	return precondition.ID != "" && precondition.ID == ns.ID && precondition.Revision >= 1 && precondition.Revision == ns.Revision
}

func namespacePreconditionMatches(ns Namespace, precondition NamespacePrecondition) bool {
	return precondition.Generation != "" &&
		precondition.Revision >= 1 &&
		ns.Epoch == precondition.Generation &&
		ns.Revision == precondition.Revision
}

func copyNamespace(ns Namespace) Namespace {
	cp := ns
	cp.Accounts = append([]string(nil), ns.Accounts...)
	return cp
}

func normalizedNamespaceAccounts(accounts []string) []string {
	if len(accounts) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(accounts))
	out := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if account == "" {
			continue
		}
		if _, ok := seen[account]; ok {
			continue
		}
		seen[account] = struct{}{}
		out = append(out, account)
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func accountNamesInToolMap(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for account := range m {
		if account != "" {
			out = append(out, account)
		}
	}
	sort.Strings(out)
	return out
}

// copyConnector deep-copies so callers can't mutate store-held state through
// the shared Tools/Approval maps or the Redact slice (scalar fields like
// Record/MaxResultBytes copy by value).
func copyConnector(c VirtualConnector) VirtualConnector {
	cp := c
	cp.Tools = copyToolMap(c.Tools)
	cp.Approval = copyToolMap(c.Approval)
	if c.Redact != nil {
		cp.Redact = append([]string(nil), c.Redact...)
	}
	return cp
}

func copyToolMap(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	cp := make(map[string][]string, len(m))
	for acct, tools := range m {
		cp[acct] = append([]string(nil), tools...)
	}
	return cp
}

// AccountStore is what the gateway needs: list accounts, read the current token,
// and persist refreshed tokens. FileStore (local) and PgStore (deploy) satisfy
// it — swapping storage never touches the gateway.
type AccountStore interface {
	Accounts() []Account
	Account(name string) (Account, bool)
	Token(name string) string        // current access (oauth) or bearer (token)
	RefreshToken(name string) string // current, possibly-rotated refresh token
	// UpdateTokens persists a provider refresh only if the named account is
	// still the exact durable incarnation that initiated the network request.
	UpdateTokens(ctx context.Context, name, expectedIncarnationID, access, refresh string) error
	// SetBearerToken changes only token-auth credential state under the account
	// ownership revision. It must not overwrite a namespace move which won
	// after the Console authorized the caller.
	SetBearerToken(ctx context.Context, name, expectedIncarnationID, token string, expectedRevision int64) (Account, error)
	Create(ctx context.Context, a Account) error
	Upsert(ctx context.Context, a Account) error
	// CompleteOAuth atomically applies only OAuth credential metadata to an
	// existing account whose immutable incarnation, URL, and ownership boundary
	// still match the values captured before provider consent. Implementations
	// must preserve display and tool-policy fields. An omitted refresh token
	// preserves the current one only when the OAuth client ID is unchanged.
	CompleteOAuth(ctx context.Context, precondition OAuthCompletionPrecondition, completion Account) (Account, error)
	// Delete removes only the exact incarnation authorized by the caller. A
	// stale console request must never delete a replacement that reused Name.
	Delete(ctx context.Context, name, expectedIncarnationID string, expectedRevision int64) error
	// UpdateAccountPolicy is the CAS-protected console policy path. It changes
	// only curation/presentation fields after checking the immutable account
	// identity and exact ownership assignment captured during authorization.
	UpdateAccountPolicy(ctx context.Context, name string, precondition AccountPolicyPrecondition, mutation AccountPolicyMutation) (Account, error)
	SetMeta(ctx context.Context, name, label, group string) error
	SetDisabledTools(ctx context.Context, name string, disabled []string) error
	SetToolOverride(ctx context.Context, name, tool string, override ToolOverride) error
	SetReadOnly(ctx context.Context, name string, ro bool) error
}

// PortableAccountConfig is the secret-free, non-ownership portion of an
// account accepted by a portable configuration import. It deliberately omits
// Group, namespace, scope, owner, and credentials: importing an old snapshot
// must never undo a connection move that committed after the snapshot was
// taken.
type PortableAccountConfig struct {
	Label         string
	URL           string
	ReadOnly      bool
	DisabledTools []string
	ToolOverrides map[string]ToolOverride
}

// PortableAccountConfigStore applies portable metadata to an existing account
// while preserving its current durable ownership and credentials. It is kept
// separate from AccountStore so older embedders need not implement another
// mutation API; the portable-config handler fails closed when unavailable.
type PortableAccountConfigStore interface {
	UpdatePortableAccountConfig(ctx context.Context, name string, update PortableAccountConfig) (Account, error)
}

// ErrAccountExists is returned by AccountStore.Create when the account name is
// already present. Explicit update and reconnect paths continue to use Upsert.
var ErrAccountExists = errors.New("account already exists")

var ErrAccountIncarnation = errors.New("account incarnation conflict")

var (
	ErrConnectAccountDeleted    = errors.New("connect account was deleted while authorization was pending")
	ErrConnectAccountURLChanged = errors.New("connect account URL changed while authorization was pending")
	ErrConnectAccountReplaced   = errors.New("connect account was replaced while authorization was pending")
	ErrConnectAccountMoved      = errors.New("connect account ownership changed while authorization was pending")
)

// OAuthCompletionPrecondition binds a provider callback to the exact durable
// account incarnation and ownership boundary that initiated it. Labels and
// tool policy may still change while the browser is open; namespace or owner
// changes require the user to begin a fresh connection flow.
type OAuthCompletionPrecondition struct {
	IncarnationID         string
	URL                   string
	ConnectionNamespaceID string
	ConnectionScope       ConnectionScope
	OwnerSubject          string
}

func oauthCompletionPreconditionForAccount(account Account) OAuthCompletionPrecondition {
	return OAuthCompletionPrecondition{
		IncarnationID:         account.IncarnationID,
		URL:                   account.URL,
		ConnectionNamespaceID: account.ConnectionNamespaceID,
		ConnectionScope:       account.ConnectionScope,
		OwnerSubject:          account.OwnerSubject,
	}
}

// ---- FileStore: thread-safe JSON file (local dev / single instance) ----

type FileStore struct {
	path                 string
	mu                   sync.Mutex
	accounts             []*Account
	connectors           []*VirtualConnector
	namespaces           []*Namespace
	connectionNamespaces []*ConnectionNamespace
	mcpClients           []*MCPClient
	oauthTokenGeneration string
	log                  ring          // in-memory audit ring
	pending              []PendingCall // approval records (ephemeral, not persisted)
}

var _ NamespaceStore = (*FileStore)(nil)
var _ ConnectionNamespaceStore = (*FileStore)(nil)

// fileStoreData is the on-disk shape. Older files were a bare JSON array of
// accounts; LoadFileStore still accepts that, and a missing "connectors"
// field simply loads as empty.
type fileStoreData struct {
	Accounts             []*Account             `json:"accounts"`
	Connectors           []*VirtualConnector    `json:"connectors,omitempty"`
	Namespaces           []*Namespace           `json:"namespaces,omitempty"`
	ConnectionNamespaces []*ConnectionNamespace `json:"connection_namespaces,omitempty"`
	MCPClients           []*MCPClient           `json:"mcp_clients,omitempty"`
	OAuthTokenGeneration string                 `json:"oauth_token_generation,omitempty"`
}

func (s *FileStore) LogCall(rec CallRecord) {
	s.log.LogCall(rec)
}
func (s *FileStore) RecentCalls(ctx context.Context, limit int) ([]CallRecord, error) {
	return s.log.RecentCalls(ctx, limit)
}
func (s *FileStore) CallDetail(ctx context.Context, id int64) (CallRecord, bool, error) {
	return s.log.CallDetail(ctx, id)
}
func (s *FileStore) SetCallTriage(ctx context.Context, id int64, triage string) error {
	return s.log.SetCallTriage(ctx, id, triage)
}

// PurgeCalls is a no-op for the in-memory ring — it self-bounds at its cap.
func (s *FileStore) PurgeCalls(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func LoadFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimLeftFunc(b, unicode.IsSpace)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// legacy format: bare account array (pre-connectors)
		if err := json.Unmarshal(b, &s.accounts); err != nil {
			return nil, fmt.Errorf("parse account store: %w", err)
		}
		connectionChanged, err := s.backfillConnectionNamespacesLocked()
		if err != nil {
			return nil, fmt.Errorf("migrate connection namespaces: %w", err)
		}
		clientChanged, err := s.backfillMCPClientsLocked()
		if err != nil {
			return nil, fmt.Errorf("migrate MCP clients: %w", err)
		}
		if connectionChanged || clientChanged {
			if err := s.saveLocked(); err != nil {
				return nil, fmt.Errorf("persist store migration: %w", err)
			}
		}
		return s, nil
	}
	var d fileStoreData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse account store: %w", err)
	}
	s.accounts, s.connectors, s.namespaces, s.connectionNamespaces, s.mcpClients, s.oauthTokenGeneration = d.Accounts, d.Connectors, d.Namespaces, d.ConnectionNamespaces, d.MCPClients, d.OAuthTokenGeneration
	connectionChanged, err := s.backfillConnectionNamespacesLocked()
	if err != nil {
		return nil, fmt.Errorf("migrate connection namespaces: %w", err)
	}
	clientChanged, err := s.backfillMCPClientsLocked()
	if err != nil {
		return nil, fmt.Errorf("migrate MCP clients: %w", err)
	}
	if connectionChanged || clientChanged {
		if err := s.saveLocked(); err != nil {
			return nil, fmt.Errorf("persist store migration: %w", err)
		}
	}
	return s, nil
}

func (s *FileStore) Accounts() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, len(s.accounts))
	for i, a := range s.accounts {
		out[i] = copyAccount(*a)
	}
	return out
}

func (s *FileStore) Token(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			if a.AuthMode == "token" {
				return a.BearerToken
			}
			return a.AccessToken
		}
	}
	return ""
}

func (s *FileStore) RefreshToken(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			return a.RefreshToken
		}
	}
	return ""
}

func (s *FileStore) UpdateTokens(_ context.Context, name, expectedIncarnationID, access, refresh string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			if expectedIncarnationID == "" || a.IncarnationID != expectedIncarnationID {
				return ErrAccountIncarnation
			}
			before := copyAccount(*a)
			a.AccessToken = access
			if refresh != "" {
				a.RefreshToken = refresh
			}
			if err := s.saveLocked(); err != nil {
				*a = before
				return err
			}
			return nil
		}
	}
	return ErrAccountIncarnation
}

func (s *FileStore) SetBearerToken(_ context.Context, name, expectedIncarnationID, token string, expectedRevision int64) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.accounts {
		if account == nil || account.Name != name {
			continue
		}
		if expectedIncarnationID == "" || account.IncarnationID != expectedIncarnationID {
			return Account{}, ErrAccountIncarnation
		}
		if expectedRevision < 1 || account.Revision != expectedRevision {
			return Account{}, ErrConnectionNamespaceRevision
		}
		before := copyAccount(*account)
		account.AuthMode = "token"
		account.BearerToken = token
		account.Revision++
		if err := s.saveLocked(); err != nil {
			*account = before
			return Account{}, err
		}
		return copyAccount(*account), nil
	}
	return Account{}, ErrAccountNotFound
}

func (s *FileStore) saveLocked() error {
	b, err := json.MarshalIndent(fileStoreData{
		Accounts:             s.accounts,
		Connectors:           s.connectors,
		Namespaces:           s.namespaces,
		ConnectionNamespaces: s.connectionNamespaces,
		MCPClients:           s.mcpClients,
		OAuthTokenGeneration: s.oauthTokenGeneration,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// LoadOrCreateTokenGeneration returns the durable workspace OAuth generation,
// creating it atomically with the rest of the file-store state when absent.
func (s *FileStore) LoadOrCreateTokenGeneration(ctx context.Context, candidate string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if candidate == "" {
		return "", errors.New("token generation candidate is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.oauthTokenGeneration != "" {
		return s.oauthTokenGeneration, nil
	}
	s.oauthTokenGeneration = candidate
	if err := s.saveLocked(); err != nil {
		s.oauthTokenGeneration = ""
		return "", fmt.Errorf("persist token generation: %w", err)
	}
	return s.oauthTokenGeneration, nil
}

func (s *FileStore) CurrentTokenGeneration(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.oauthTokenGeneration == "" {
		return "", errors.New("token generation is not initialized")
	}
	return s.oauthTokenGeneration, nil
}

// RotateTokenGeneration advances the durable workspace OAuth generation. A
// stale expected value means another revocation already won; return that newer
// durable value so the caller can adopt it without ever writing an old value
// back over the top.
func (s *FileStore) RotateTokenGeneration(ctx context.Context, expected, replacement string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if expected == "" || replacement == "" {
		return "", errors.New("expected and replacement token generations are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.oauthTokenGeneration == "" {
		return "", errors.New("token generation is not initialized")
	}
	if s.oauthTokenGeneration != expected {
		return s.oauthTokenGeneration, nil
	}
	s.oauthTokenGeneration = replacement
	if err := s.saveLocked(); err != nil {
		s.oauthTokenGeneration = expected
		return "", fmt.Errorf("persist rotated token generation: %w", err)
	}
	return s.oauthTokenGeneration, nil
}

func (s *FileStore) Account(name string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			return copyAccount(*a), true
		}
	}
	return Account{}, false
}

func (s *FileStore) Create(_ context.Context, a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.accounts {
		if existing.Name == a.Name {
			return ErrAccountExists
		}
	}
	oldConnectionNamespaces := copyConnectionNamespaces(s.connectionNamespaces)
	oldConnectors := copyVirtualConnectors(s.connectors)
	oldEndpointNamespaces := copyEndpointNamespaces(s.namespaces)
	cp := copyAccount(a)
	// Creation always starts a fresh incarnation. In particular, a caller may
	// not resurrect an identifier copied from an account that was deleted.
	cp.IncarnationID = newAccountIncarnationID()
	if _, err := s.ensureAccountConnectionNamespaceLocked(&cp); err != nil {
		return err
	}
	if err := s.validatePersonalAccountMCPClientGrantsLocked(cp); err != nil {
		// ensureAccountConnectionNamespaceLocked may have created a legacy
		// compatibility folder. A rejected personal ownership assignment must
		// not leave that ghost folder in memory to be persisted by a later
		// unrelated write.
		s.connectionNamespaces = oldConnectionNamespaces
		return err
	}
	s.accounts = append(s.accounts, &cp)
	if cp.IsPersonal() {
		s.removePersonalAccountExposureLocked(cp.Name)
	}
	if err := s.saveLocked(); err != nil {
		s.accounts = s.accounts[:len(s.accounts)-1]
		s.connectionNamespaces = oldConnectionNamespaces
		s.connectors = oldConnectors
		s.namespaces = oldEndpointNamespaces
		return err
	}
	return nil
}

func (s *FileStore) Upsert(_ context.Context, a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldConnectionNamespaces := copyConnectionNamespaces(s.connectionNamespaces)
	oldConnectors := copyVirtualConnectors(s.connectors)
	oldEndpointNamespaces := copyEndpointNamespaces(s.namespaces)
	oldMCPClients := copyMCPClients(s.mcpClients)
	cp := copyAccount(a)
	incomingRevision := cp.Revision
	var previous *Account
	var before Account
	for _, existing := range s.accounts {
		if existing != nil && existing.Name == cp.Name {
			previous = existing
			before = copyAccount(*existing)
			// Incarnation identity is store-owned and immutable across every
			// whole-account update.
			cp.IncarnationID = existing.IncarnationID
			if cp.IncarnationID == "" {
				cp.IncarnationID = newAccountIncarnationID()
			}
			// A legacy whole-account write that predates connection ownership
			// must never declassify an existing personal account merely because
			// it omitted the new fields. Explicit moves go through the CAS API.
			if strings.TrimSpace(cp.ConnectionNamespaceID) == "" && strings.TrimSpace(string(cp.ConnectionScope)) == "" && strings.TrimSpace(cp.OwnerSubject) == "" && existing.IsPersonal() {
				cp.ConnectionNamespaceID = existing.ConnectionNamespaceID
				cp.ConnectionScope = existing.ConnectionScope
				cp.OwnerSubject = existing.OwnerSubject
				cp.Group = existing.Group
			}
			break
		}
	}
	if previous == nil {
		cp.IncarnationID = newAccountIncarnationID()
	}
	if _, err := s.ensureAccountConnectionNamespaceLocked(&cp); err != nil {
		return err
	}
	if err := s.validatePersonalAccountMCPClientGrantsLocked(cp); err != nil {
		s.connectionNamespaces = oldConnectionNamespaces
		return err
	}
	if previous != nil && incomingRevision < 1 {
		if cp.ConnectionNamespaceID != previous.ConnectionNamespaceID || cp.ConnectionScope != previous.ConnectionScope || cp.OwnerSubject != previous.OwnerSubject {
			cp.Revision = previous.Revision + 1
		} else {
			cp.Revision = previous.Revision
		}
	}
	for i, x := range s.accounts {
		if x.Name == a.Name {
			old := s.accounts[i]
			s.accounts[i] = &cp
			if cp.IsPersonal() {
				s.removePersonalAccountExposureLocked(cp.Name)
			}
			// The legacy /admin/token form and historical callers submit a
			// whole Account with only Group populated. ensureAccountConnection-
			// NamespaceLocked above resolves that label to a durable folder, so
			// rotate every affected scoped-client epoch before this ownership
			// reassignment becomes durable. Otherwise an old OAuth token could
			// survive long enough to observe a different tool set.
			if accountOwnershipChanged(before, cp) {
				s.rotateMCPClientEpochsForAccountMoveLocked(before, cp)
			}
			if err := s.saveLocked(); err != nil {
				s.accounts[i] = old
				s.connectionNamespaces = oldConnectionNamespaces
				s.connectors = oldConnectors
				s.namespaces = oldEndpointNamespaces
				s.mcpClients = oldMCPClients
				return err
			}
			return nil
		}
	}
	s.accounts = append(s.accounts, &cp)
	if cp.IsPersonal() {
		s.removePersonalAccountExposureLocked(cp.Name)
	}
	if err := s.saveLocked(); err != nil {
		s.accounts = s.accounts[:len(s.accounts)-1]
		s.connectionNamespaces = oldConnectionNamespaces
		s.connectors = oldConnectors
		s.namespaces = oldEndpointNamespaces
		return err
	}
	return nil
}

func (s *FileStore) CompleteOAuth(_ context.Context, precondition OAuthCompletionPrecondition, completion Account) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.accounts {
		if current.Name != completion.Name {
			continue
		}
		if precondition.IncarnationID == "" || current.IncarnationID != precondition.IncarnationID {
			return Account{}, ErrConnectAccountReplaced
		}
		if !equalAccountURL(current.URL, precondition.URL) {
			return Account{}, ErrConnectAccountURLChanged
		}
		if current.ConnectionNamespaceID != precondition.ConnectionNamespaceID ||
			current.ConnectionScope != precondition.ConnectionScope ||
			current.OwnerSubject != precondition.OwnerSubject {
			return Account{}, ErrConnectAccountMoved
		}
		before := copyAccount(*current)
		sameClient := current.ClientID == completion.ClientID
		current.AuthMode = "oauth"
		current.ClientID, current.ClientSecret = completion.ClientID, completion.ClientSecret
		current.AccessToken = completion.AccessToken
		if completion.RefreshToken != "" || !sameClient {
			current.RefreshToken = completion.RefreshToken
		}
		current.TokenEndpoint, current.Resource, current.Scope = completion.TokenEndpoint, completion.Resource, completion.Scope
		current.BearerToken = ""
		if err := s.saveLocked(); err != nil {
			*current = before
			return Account{}, err
		}
		return copyAccount(*current), nil
	}
	return Account{}, ErrConnectAccountDeleted
}

func (s *FileStore) Delete(_ context.Context, name, expectedIncarnationID string, expectedRevision int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.accounts {
		if a.Name == name {
			if expectedIncarnationID == "" || a.IncarnationID != expectedIncarnationID {
				return ErrAccountIncarnation
			}
			if expectedRevision < 1 || a.Revision != expectedRevision {
				return ErrConnectionNamespaceRevision
			}
			oldAccounts := append([]*Account(nil), s.accounts...)
			oldConnectors := make([]*VirtualConnector, len(s.connectors))
			for i, connector := range s.connectors {
				cp := copyConnector(*connector)
				oldConnectors[i] = &cp
			}
			oldNamespaces := make([]*Namespace, len(s.namespaces))
			for i, ns := range s.namespaces {
				cp := copyNamespace(*ns)
				oldNamespaces[i] = &cp
			}
			s.accounts = append(s.accounts[:i], s.accounts[i+1:]...)
			for _, connector := range s.connectors {
				delete(connector.Tools, name)
				delete(connector.Approval, name)
			}
			for _, ns := range s.namespaces {
				kept := make([]string, 0, len(ns.Accounts))
				removed := false
				for _, account := range ns.Accounts {
					if account == name {
						removed = true
						continue
					}
					kept = append(kept, account)
				}
				if removed {
					ns.Accounts = kept
					ns.Revision++
				}
			}
			if err := s.saveLocked(); err != nil {
				s.accounts = oldAccounts
				s.connectors = oldConnectors
				s.namespaces = oldNamespaces
				return err
			}
			return nil
		}
	}
	return ErrAccountIncarnation
}

// UpdateAccountPolicy applies curation/presentation changes under the exact
// account snapshot which the console authorized. The mutex makes the
// precondition check and durable write one operation: a namespace move which
// wins first changes the revision/assignment and causes this write to fail
// without restoring any stale ownership value.
func (s *FileStore) UpdateAccountPolicy(_ context.Context, name string, precondition AccountPolicyPrecondition, mutation AccountPolicyMutation) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.accounts {
		if account == nil || account.Name != name {
			continue
		}
		if !precondition.matches(*account) {
			return Account{}, ErrAccountPolicyPrecondition
		}

		before := copyAccount(*account)
		changed := false
		if mutation.Label != nil {
			label := strings.TrimSpace(*mutation.Label)
			if account.Label != label {
				account.Label = label
				changed = true
			}
		}
		if mutation.DisabledTools != nil {
			disabled := append([]string(nil), (*mutation.DisabledTools)...)
			if !sameStrings(account.DisabledTools, disabled) {
				account.DisabledTools = disabled
				changed = true
			}
		}
		if mutation.ToolOverrides != nil {
			overrides := copyAccount(Account{ToolOverrides: *mutation.ToolOverrides}).ToolOverrides
			if !sameToolOverrides(account.ToolOverrides, overrides) {
				account.ToolOverrides = overrides
				changed = true
			}
		}
		if mutation.ReadOnly != nil && account.ReadOnly != *mutation.ReadOnly {
			account.ReadOnly = *mutation.ReadOnly
			changed = true
		}
		if !changed {
			return copyAccount(*account), nil
		}

		// Revision is the account's observable generation. Advancing it for
		// every durable policy change also makes a failed live rebuild fail
		// closed instead of letting an old cached handler outlive the write.
		account.Revision++
		if err := s.saveLocked(); err != nil {
			*account = before
			return Account{}, err
		}
		return copyAccount(*account), nil
	}
	// The caller held a snapshot of a visible account. If it disappeared
	// before this atomic write, do not reveal whether the name was deleted or
	// moved/recreated; it is the same stale-policy outcome.
	return Account{}, ErrAccountPolicyPrecondition
}

func (s *FileStore) SetMeta(_ context.Context, name, label, group string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			label, group = strings.TrimSpace(label), strings.TrimSpace(group)
			oldAccount := copyAccount(*a)
			// SetMeta is intentionally label-only. A stale label PATCH must not
			// recreate an older Group-derived namespace after a concurrent safe
			// MoveAccountToConnectionNamespace has completed. Legacy group-only
			// ownership changes remain supported through Upsert, which rotates
			// affected scoped-client epochs atomically.
			if group != strings.TrimSpace(oldAccount.Group) {
				return fmt.Errorf("%w: use MoveAccountToConnectionNamespace for ownership changes", ErrConnectionNamespaceRevision)
			}
			a.Label = label
			if a.Label != oldAccount.Label {
				a.Revision = oldAccount.Revision + 1
			}
			if err := s.saveLocked(); err != nil {
				*a = oldAccount
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("account %q not found", name)
}

// UpdatePortableAccountConfig atomically applies only secret-free portable
// metadata to an existing account. In particular, it ignores all ownership
// fields from the imported snapshot so a config export made before a move
// cannot later restore the old connection namespace.
func (s *FileStore) UpdatePortableAccountConfig(_ context.Context, name string, update PortableAccountConfig) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.accounts {
		if account == nil || account.Name != name {
			continue
		}
		before := copyAccount(*account)
		update.Label = strings.TrimSpace(update.Label)
		update.URL = strings.TrimSpace(update.URL)
		if (account.BearerToken != "" || account.AccessToken != "" || account.RefreshToken != "" || account.ClientSecret != "") &&
			!equalAccountURL(account.URL, update.URL) {
			return Account{}, ErrConnectAccountURLChanged
		}
		account.Label = update.Label
		account.URL = update.URL
		account.ReadOnly = update.ReadOnly
		account.DisabledTools = append([]string(nil), update.DisabledTools...)
		account.ToolOverrides = copyAccount(Account{ToolOverrides: update.ToolOverrides}).ToolOverrides
		if err := s.saveLocked(); err != nil {
			*account = before
			return Account{}, err
		}
		return copyAccount(*account), nil
	}
	return Account{}, ErrAccountNotFound
}

func (s *FileStore) SetReadOnly(_ context.Context, name string, ro bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			a.ReadOnly = ro
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account %q not found", name)
}

func (s *FileStore) SetDisabledTools(_ context.Context, name string, disabled []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			a.DisabledTools = disabled
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account %q not found", name)
}

func (s *FileStore) SetToolOverride(_ context.Context, name, tool string, override ToolOverride) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name != name {
			continue
		}
		if a.ToolOverrides == nil {
			a.ToolOverrides = map[string]ToolOverride{}
		}
		if override.Alias == "" && override.Description == "" {
			delete(a.ToolOverrides, tool)
		} else {
			a.ToolOverrides[tool] = override
		}
		return s.saveLocked()
	}
	return fmt.Errorf("account %q not found", name)
}

func copyConnectionNamespaces(in []*ConnectionNamespace) []*ConnectionNamespace {
	out := make([]*ConnectionNamespace, len(in))
	for i, ns := range in {
		if ns == nil {
			continue
		}
		cp := copyConnectionNamespace(*ns)
		out[i] = &cp
	}
	return out
}

func copyAccounts(in []*Account) []*Account {
	out := make([]*Account, len(in))
	for i, account := range in {
		if account == nil {
			continue
		}
		cp := copyAccount(*account)
		out[i] = &cp
	}
	return out
}

func copyEndpointNamespaces(in []*Namespace) []*Namespace {
	out := make([]*Namespace, len(in))
	for i, ns := range in {
		if ns == nil {
			continue
		}
		cp := copyNamespace(*ns)
		out[i] = &cp
	}
	return out
}

func copyVirtualConnectors(in []*VirtualConnector) []*VirtualConnector {
	out := make([]*VirtualConnector, len(in))
	for i, connector := range in {
		if connector == nil {
			continue
		}
		cp := copyConnector(*connector)
		out[i] = &cp
	}
	return out
}

func (s *FileStore) removePersonalAccountExposureLocked(name string) {
	for _, connector := range s.connectors {
		if connector == nil {
			continue
		}
		delete(connector.Tools, name)
		delete(connector.Approval, name)
	}
	for _, ns := range s.namespaces {
		if ns == nil {
			continue
		}
		kept := make([]string, 0, len(ns.Accounts))
		removed := false
		for _, member := range ns.Accounts {
			if member == name {
				removed = true
				continue
			}
			kept = append(kept, member)
		}
		if removed {
			ns.Accounts = kept
			ns.Revision++
		}
	}
}

func uniqueConnectionNamespaceSlug(base string, exists func(string) bool) string {
	base = normalizeConnectionNamespaceSlug(base)
	if base == "" {
		base = "general"
	}
	if !exists(base) {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if !exists(candidate) {
			return candidate
		}
	}
}

func (s *FileStore) connectionNamespaceByIDLocked(id string) (*ConnectionNamespace, bool) {
	for _, ns := range s.connectionNamespaces {
		if ns != nil && ns.ID == id {
			return ns, true
		}
	}
	return nil, false
}

func (s *FileStore) connectionNamespaceBySlugLocked(slug string) (*ConnectionNamespace, bool) {
	for _, ns := range s.connectionNamespaces {
		if ns != nil && ns.Slug == slug {
			return ns, true
		}
	}
	return nil, false
}

func (s *FileStore) connectionNamespaceForLegacyLabelLocked(label string) (*ConnectionNamespace, bool) {
	label = strings.TrimSpace(label)
	for _, ns := range s.connectionNamespaces {
		if ns != nil && strings.EqualFold(strings.TrimSpace(ns.Label), label) {
			return ns, true
		}
	}
	return nil, false
}

// ensureAccountConnectionNamespaceLocked normalizes account ownership and
// creates a durable namespace for the legacy Group-only path. Callers hold
// s.mu and roll back s.connectionNamespaces if their encompassing write fails.
func (s *FileStore) ensureAccountConnectionNamespaceLocked(a *Account) (bool, error) {
	if err := normalizeAccountConnection(a); err != nil {
		return false, err
	}
	if a.ConnectionNamespaceID != "" {
		ns, ok := s.connectionNamespaceByIDLocked(a.ConnectionNamespaceID)
		if !ok {
			return false, fmt.Errorf("%w: %s", ErrConnectionNamespaceNotFound, a.ConnectionNamespaceID)
		}
		if strings.TrimSpace(a.Group) == "" {
			a.Group = ns.Label
		}
		return false, nil
	}

	label := defaultConnectionNamespaceLabel(*a)
	// Legacy records are always shared. Explicit new personal accounts get a
	// dedicated namespace instead of being folded into a same-label group.
	if a.ConnectionScope != ConnectionScopePersonal {
		if ns, ok := s.connectionNamespaceForLegacyLabelLocked(label); ok {
			a.ConnectionNamespaceID = ns.ID
			return false, nil
		}
	}
	baseSlug := label
	if a.ConnectionScope == ConnectionScopePersonal {
		baseSlug = "personal"
	}
	ns := ConnectionNamespace{
		ID:        newConnectionNamespaceID(),
		Slug:      uniqueConnectionNamespaceSlug(baseSlug, func(slug string) bool { _, ok := s.connectionNamespaceBySlugLocked(slug); return ok }),
		Label:     label,
		Revision:  1,
		CreatedBy: a.OwnerSubject,
	}
	if err := prepareConnectionNamespaceForCreate(&ns); err != nil {
		return false, err
	}
	cp := copyConnectionNamespace(ns)
	s.connectionNamespaces = append(s.connectionNamespaces, &cp)
	a.ConnectionNamespaceID = ns.ID
	return true, nil
}

// backfillConnectionNamespacesLocked upgrades Group-only FileStore records to
// first-class shared connection namespaces. It deliberately does not infer
// "personal" from a display label: that would hide existing connections and
// could silently alter shared access semantics during an upgrade.
func (s *FileStore) backfillConnectionNamespacesLocked() (bool, error) {
	changed := false
	seenIDs := map[string]struct{}{}
	seenSlugs := map[string]struct{}{}
	seenAccountIncarnations := map[string]struct{}{}
	for _, ns := range s.connectionNamespaces {
		if ns == nil {
			continue
		}
		before := copyConnectionNamespace(*ns)
		ns.ID = strings.TrimSpace(ns.ID)
		if _, duplicate := seenIDs[ns.ID]; ns.ID == "" || duplicate {
			ns.ID = newConnectionNamespaceID()
		}
		seenIDs[ns.ID] = struct{}{}
		ns.Label = strings.TrimSpace(ns.Label)
		if ns.Label == "" {
			ns.Label = "General"
		}
		ns.Slug = normalizeConnectionNamespaceSlug(ns.Slug)
		if _, duplicate := seenSlugs[ns.Slug]; ns.Slug == "" || duplicate {
			ns.Slug = uniqueConnectionNamespaceSlug(ns.Label, func(slug string) bool {
				_, exists := seenSlugs[slug]
				return exists
			})
		}
		seenSlugs[ns.Slug] = struct{}{}
		ns.CreatedBy = strings.TrimSpace(ns.CreatedBy)
		ns.ManagerGrants = normalizedManagerGrants(ns.ManagerGrants)
		if ns.Revision < 1 {
			ns.Revision = 1
		}
		if ns.CreatedAt.IsZero() {
			ns.CreatedAt = time.Now().UTC()
		}
		if ns.UpdatedAt.IsZero() {
			ns.UpdatedAt = ns.CreatedAt
		}
		if before.ID != ns.ID || before.Slug != ns.Slug || before.Label != ns.Label || before.Revision != ns.Revision || before.CreatedBy != ns.CreatedBy || !before.CreatedAt.Equal(ns.CreatedAt) || !before.UpdatedAt.Equal(ns.UpdatedAt) || !sameManagerGrants(before.ManagerGrants, ns.ManagerGrants) {
			changed = true
		}
	}
	for _, a := range s.accounts {
		if a == nil {
			continue
		}
		before := copyAccount(*a)
		a.IncarnationID = strings.TrimSpace(a.IncarnationID)
		if _, duplicate := seenAccountIncarnations[a.IncarnationID]; a.IncarnationID == "" || duplicate {
			for {
				a.IncarnationID = newAccountIncarnationID()
				if _, exists := seenAccountIncarnations[a.IncarnationID]; !exists {
					break
				}
			}
		}
		seenAccountIncarnations[a.IncarnationID] = struct{}{}
		// An account from the legacy JSON shape has no connection fields. Its
		// owner/scope therefore cannot be inferred; make it shared explicitly.
		if strings.TrimSpace(a.ConnectionNamespaceID) == "" && strings.TrimSpace(string(a.ConnectionScope)) == "" {
			a.ConnectionScope = ConnectionScopeShared
		}
		if _, err := s.ensureAccountConnectionNamespaceLocked(a); err != nil {
			return false, fmt.Errorf("account %q: %w", a.Name, err)
		}
		if before.ConnectionNamespaceID != a.ConnectionNamespaceID || before.ConnectionScope != a.ConnectionScope || before.OwnerSubject != a.OwnerSubject || before.Revision != a.Revision || before.Group != a.Group || before.IncarnationID != a.IncarnationID {
			changed = true
		}
	}
	return changed, nil
}

// ---- FileStore: ConnectorStore ----

func (s *FileStore) Connectors(_ context.Context) ([]VirtualConnector, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]VirtualConnector, len(s.connectors))
	for i, c := range s.connectors {
		out[i] = copyConnector(*c)
	}
	return out, nil
}

func (s *FileStore) VirtualConnector(_ context.Context, slug string) (VirtualConnector, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.connectors {
		if c.Slug == slug {
			return copyConnector(*c), true
		}
	}
	return VirtualConnector{}, false
}

func (s *FileStore) UpsertConnector(_ context.Context, c VirtualConnector) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rejectPersonalConnectorAccountsLocked(c.Tools); err != nil {
		return err
	}
	if err := s.rejectPersonalConnectorAccountsLocked(c.Approval); err != nil {
		return err
	}
	for _, ns := range s.namespaces {
		if ns.Slug == c.Slug {
			return fmt.Errorf("%w: %s", ErrEndpointCollision, c.Slug)
		}
	}
	cp := copyConnector(c)
	for i, x := range s.connectors {
		if x.Slug == c.Slug {
			s.connectors[i] = &cp
			return s.saveLocked()
		}
	}
	s.connectors = append(s.connectors, &cp)
	return s.saveLocked()
}

func (s *FileStore) rejectPersonalConnectorAccountsLocked(m map[string][]string) error {
	for account := range m {
		for _, existing := range s.accounts {
			if existing.Name == account && existing.IsPersonal() {
				return fmt.Errorf("%w: %s", ErrPersonalAccountExposure, account)
			}
		}
	}
	return nil
}

func (s *FileStore) rejectPersonalNamespaceAccountsLocked(accounts []string) error {
	for _, account := range accounts {
		for _, existing := range s.accounts {
			if existing.Name == account && existing.IsPersonal() {
				return fmt.Errorf("%w: %s", ErrPersonalAccountExposure, account)
			}
		}
	}
	return nil
}

func (s *FileStore) DeleteConnector(_ context.Context, slug, expectedGeneration string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.connectors {
		if c.Slug == slug {
			if c.Epoch != expectedGeneration {
				return ErrEndpointGeneration
			}
			removed := c
			s.connectors = append(s.connectors[:i], s.connectors[i+1:]...)
			if err := s.saveLocked(); err != nil {
				s.connectors = append(s.connectors, nil)
				copy(s.connectors[i+1:], s.connectors[i:])
				s.connectors[i] = removed
				return err
			}
			return nil
		}
	}
	return ErrConnectorNotFound
}

// ---- FileStore: NamespaceStore ----

func (s *FileStore) Namespaces(_ context.Context) ([]Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Namespace, len(s.namespaces))
	for i, ns := range s.namespaces {
		out[i] = copyNamespace(*ns)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (s *FileStore) Namespace(_ context.Context, slug string) (Namespace, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ns := range s.namespaces {
		if ns.Slug == slug {
			return copyNamespace(*ns), true
		}
	}
	return Namespace{}, false
}

func (s *FileStore) CreateNamespace(_ context.Context, ns Namespace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, connector := range s.connectors {
		if connector.Slug == ns.Slug {
			return fmt.Errorf("%w: %s", ErrEndpointCollision, ns.Slug)
		}
	}
	for _, existing := range s.namespaces {
		if existing.Slug == ns.Slug {
			return ErrNamespaceExists
		}
	}
	known := make(map[string]struct{}, len(s.accounts))
	for _, account := range s.accounts {
		known[account.Name] = struct{}{}
	}
	ns.Accounts = normalizedNamespaceAccounts(ns.Accounts)
	if err := s.rejectPersonalNamespaceAccountsLocked(ns.Accounts); err != nil {
		return err
	}
	for _, account := range ns.Accounts {
		if _, ok := known[account]; !ok {
			return fmt.Errorf("%w: %s", ErrAccountNotFound, account)
		}
	}
	if ns.Revision < 1 {
		ns.Revision = 1
	}
	if ns.Epoch == "" {
		ns.Epoch = newEpoch()
	}
	cp := copyNamespace(ns)
	s.namespaces = append(s.namespaces, &cp)
	if err := s.saveLocked(); err != nil {
		s.namespaces = s.namespaces[:len(s.namespaces)-1]
		return err
	}
	return nil
}

func (s *FileStore) UpdateNamespace(_ context.Context, update Namespace, precondition NamespacePrecondition) (Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ns := range s.namespaces {
		if ns.Slug != update.Slug {
			continue
		}
		if !namespacePreconditionMatches(*ns, precondition) {
			return Namespace{}, ErrNamespaceRevision
		}
		known := make(map[string]struct{}, len(s.accounts))
		for _, account := range s.accounts {
			known[account.Name] = struct{}{}
		}
		accounts := normalizedNamespaceAccounts(update.Accounts)
		if err := s.rejectPersonalNamespaceAccountsLocked(accounts); err != nil {
			return Namespace{}, err
		}
		for _, account := range accounts {
			if _, ok := known[account]; !ok {
				return Namespace{}, fmt.Errorf("%w: %s", ErrAccountNotFound, account)
			}
		}
		if ns.Label == update.Label && sameStrings(ns.Accounts, accounts) {
			return copyNamespace(*ns), nil
		}
		oldLabel, oldAccounts, oldRevision := ns.Label, append([]string(nil), ns.Accounts...), ns.Revision
		ns.Label = update.Label
		ns.Accounts = accounts
		ns.Revision++
		if err := s.saveLocked(); err != nil {
			ns.Label, ns.Accounts, ns.Revision = oldLabel, oldAccounts, oldRevision
			return Namespace{}, err
		}
		return copyNamespace(*ns), nil
	}
	return Namespace{}, ErrNamespaceNotFound
}

func (s *FileStore) AddNamespaceAccount(_ context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ns := range s.namespaces {
		if ns.Slug != slug {
			continue
		}
		if !namespacePreconditionMatches(*ns, precondition) {
			return Namespace{}, ErrNamespaceRevision
		}
		accountExists := false
		for _, existing := range s.accounts {
			if existing.Name == account {
				accountExists = true
				break
			}
		}
		if !accountExists {
			return Namespace{}, fmt.Errorf("%w: %s", ErrAccountNotFound, account)
		}
		if err := s.rejectPersonalNamespaceAccountsLocked([]string{account}); err != nil {
			return Namespace{}, err
		}
		for _, member := range ns.Accounts {
			if member == account {
				return copyNamespace(*ns), nil
			}
		}
		oldAccounts, oldRevision := append([]string(nil), ns.Accounts...), ns.Revision
		ns.Accounts = normalizedNamespaceAccounts(append(ns.Accounts, account))
		ns.Revision++
		if err := s.saveLocked(); err != nil {
			ns.Accounts, ns.Revision = oldAccounts, oldRevision
			return Namespace{}, err
		}
		return copyNamespace(*ns), nil
	}
	return Namespace{}, ErrNamespaceNotFound
}

func (s *FileStore) RemoveNamespaceAccount(_ context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ns := range s.namespaces {
		if ns.Slug != slug {
			continue
		}
		if !namespacePreconditionMatches(*ns, precondition) {
			return Namespace{}, ErrNamespaceRevision
		}
		index := -1
		for i, member := range ns.Accounts {
			if member == account {
				index = i
				break
			}
		}
		if index < 0 {
			return copyNamespace(*ns), nil
		}
		oldAccounts, oldRevision := append([]string(nil), ns.Accounts...), ns.Revision
		ns.Accounts = append(ns.Accounts[:index:index], ns.Accounts[index+1:]...)
		ns.Revision++
		if err := s.saveLocked(); err != nil {
			ns.Accounts, ns.Revision = oldAccounts, oldRevision
			return Namespace{}, err
		}
		return copyNamespace(*ns), nil
	}
	return Namespace{}, ErrNamespaceNotFound
}

func (s *FileStore) DeleteNamespace(_ context.Context, slug string, precondition NamespacePrecondition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ns := range s.namespaces {
		if ns.Slug != slug {
			continue
		}
		if !namespacePreconditionMatches(*ns, precondition) {
			return ErrNamespaceRevision
		}
		removed := ns
		s.namespaces = append(s.namespaces[:i], s.namespaces[i+1:]...)
		if err := s.saveLocked(); err != nil {
			s.namespaces = append(s.namespaces, nil)
			copy(s.namespaces[i+1:], s.namespaces[i:])
			s.namespaces[i] = removed
			return err
		}
		return nil
	}
	return ErrNamespaceNotFound
}

// ---- FileStore: ConnectionNamespaceStore ----

func (s *FileStore) ConnectionNamespaces(_ context.Context) ([]ConnectionNamespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConnectionNamespace, 0, len(s.connectionNamespaces))
	for _, ns := range s.connectionNamespaces {
		if ns != nil {
			out = append(out, copyConnectionNamespace(*ns))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug == out[j].Slug {
			return out[i].ID < out[j].ID
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

func (s *FileStore) ConnectionNamespace(_ context.Context, id string) (ConnectionNamespace, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns, ok := s.connectionNamespaceByIDLocked(strings.TrimSpace(id))
	if !ok {
		return ConnectionNamespace{}, false
	}
	return copyConnectionNamespace(*ns), true
}

func (s *FileStore) ConnectionNamespaceBySlug(_ context.Context, slug string) (ConnectionNamespace, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns, ok := s.connectionNamespaceBySlugLocked(normalizeConnectionNamespaceSlug(slug))
	if !ok {
		return ConnectionNamespace{}, false
	}
	return copyConnectionNamespace(*ns), true
}

func prepareConnectionNamespaceForCreate(ns *ConnectionNamespace) error {
	now := time.Now().UTC()
	ns.ID = strings.TrimSpace(ns.ID)
	if ns.ID == "" {
		ns.ID = newConnectionNamespaceID()
	}
	ns.Label = strings.TrimSpace(ns.Label)
	if ns.Label == "" {
		return errors.New("connection namespace label is required")
	}
	ns.Slug = normalizeConnectionNamespaceSlug(ns.Slug)
	if ns.Slug == "" {
		ns.Slug = normalizeConnectionNamespaceSlug(ns.Label)
	}
	if ns.Slug == "" {
		return errors.New("connection namespace slug is required")
	}
	ns.CreatedBy = strings.TrimSpace(ns.CreatedBy)
	ns.ManagerGrants = initialConnectionNamespaceManagerGrants(ns.ManagerGrants, ns.CreatedBy)
	// Creation owns the initial CAS version. Accepting a caller-supplied
	// revision would let a management client manufacture a future precondition.
	ns.Revision = 1
	if ns.CreatedAt.IsZero() {
		ns.CreatedAt = now
	}
	if ns.UpdatedAt.IsZero() {
		ns.UpdatedAt = ns.CreatedAt
	}
	return nil
}

func (s *FileStore) CreateConnectionNamespace(_ context.Context, ns ConnectionNamespace) (ConnectionNamespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := prepareConnectionNamespaceForCreate(&ns); err != nil {
		return ConnectionNamespace{}, err
	}
	if _, exists := s.connectionNamespaceByIDLocked(ns.ID); exists {
		return ConnectionNamespace{}, ErrConnectionNamespaceExists
	}
	if _, exists := s.connectionNamespaceBySlugLocked(ns.Slug); exists {
		return ConnectionNamespace{}, ErrConnectionNamespaceExists
	}
	cp := copyConnectionNamespace(ns)
	s.connectionNamespaces = append(s.connectionNamespaces, &cp)
	if err := s.saveLocked(); err != nil {
		s.connectionNamespaces = s.connectionNamespaces[:len(s.connectionNamespaces)-1]
		return ConnectionNamespace{}, err
	}
	return copyConnectionNamespace(cp), nil
}

func (s *FileStore) UpdateConnectionNamespace(_ context.Context, update ConnectionNamespace, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns, ok := s.connectionNamespaceByIDLocked(strings.TrimSpace(update.ID))
	if !ok {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	if !connectionNamespacePreconditionMatches(*ns, precondition) {
		return ConnectionNamespace{}, ErrConnectionNamespaceRevision
	}
	if update.Slug != "" && normalizeConnectionNamespaceSlug(update.Slug) != ns.Slug {
		return ConnectionNamespace{}, errors.New("connection namespace slug is immutable")
	}
	if update.CreatedBy != "" && strings.TrimSpace(update.CreatedBy) != ns.CreatedBy {
		return ConnectionNamespace{}, errors.New("connection namespace creator is immutable")
	}
	label := strings.TrimSpace(update.Label)
	if label == "" {
		return ConnectionNamespace{}, errors.New("connection namespace label is required")
	}
	grants := normalizedManagerGrants(update.ManagerGrants)
	if ns.Label == label && sameManagerGrants(ns.ManagerGrants, grants) {
		return copyConnectionNamespace(*ns), nil
	}
	before := copyConnectionNamespace(*ns)
	oldAccounts := copyAccounts(s.accounts)
	ns.Label, ns.ManagerGrants, ns.Revision = label, grants, ns.Revision+1
	ns.UpdatedAt = time.Now().UTC()
	if before.Label != label {
		for _, account := range s.accounts {
			if account != nil && account.ConnectionNamespaceID == ns.ID {
				account.Group = label
			}
		}
	}
	if err := s.saveLocked(); err != nil {
		*ns = before
		s.accounts = oldAccounts
		return ConnectionNamespace{}, err
	}
	return copyConnectionNamespace(*ns), nil
}

func (s *FileStore) SetConnectionNamespaceManagers(ctx context.Context, id string, managers []ConnectionNamespaceManagerGrant, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error) {
	ns, ok := s.ConnectionNamespace(ctx, id)
	if !ok {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	ns.ManagerGrants = managers
	return s.UpdateConnectionNamespace(ctx, ns, precondition)
}

func (s *FileStore) DeleteConnectionNamespace(_ context.Context, id string, precondition ConnectionNamespacePrecondition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	for i, ns := range s.connectionNamespaces {
		if ns == nil || ns.ID != id {
			continue
		}
		if !connectionNamespacePreconditionMatches(*ns, precondition) {
			return ErrConnectionNamespaceRevision
		}
		for _, account := range s.accounts {
			if account != nil && account.ConnectionNamespaceID == id {
				return ErrConnectionNamespaceInUse
			}
		}
		// An active subject-bound client is an explicit authorization grant to
		// this credential folder. Refuse deletion until the grant is removed or
		// the client is revoked; silently cascading would leave an old client
		// revision looking valid to a future scoped endpoint.
		for _, client := range s.mcpClients {
			if client == nil || client.Status != MCPClientStatusActive {
				continue
			}
			for _, namespaceID := range client.ConnectionNamespaceIDs {
				if namespaceID == id {
					return ErrConnectionNamespaceInUse
				}
			}
		}
		oldClients := copyMCPClients(s.mcpClients)
		removed := ns
		s.connectionNamespaces = append(s.connectionNamespaces[:i], s.connectionNamespaces[i+1:]...)
		// Revoked registrations are inert. Drop their historical grant to the
		// deleted folder so FileStore mirrors PostgreSQL's ON DELETE CASCADE
		// behavior and cannot retain a dangling namespace ID on disk.
		for _, client := range s.mcpClients {
			if client == nil || client.Status != MCPClientStatusRevoked {
				continue
			}
			kept := make([]string, 0, len(client.ConnectionNamespaceIDs))
			for _, namespaceID := range client.ConnectionNamespaceIDs {
				if namespaceID != id {
					kept = append(kept, namespaceID)
				}
			}
			if len(kept) != len(client.ConnectionNamespaceIDs) {
				client.ConnectionNamespaceIDs = kept
				client.Revision++
				client.UpdatedAt = time.Now().UTC()
			}
		}
		if err := s.saveLocked(); err != nil {
			s.connectionNamespaces = append(s.connectionNamespaces, nil)
			copy(s.connectionNamespaces[i+1:], s.connectionNamespaces[i:])
			s.connectionNamespaces[i] = removed
			s.mcpClients = oldClients
			return err
		}
		return nil
	}
	return ErrConnectionNamespaceNotFound
}

func normalizeAccountConnectionAssignment(assignment AccountConnectionAssignment) (AccountConnectionAssignment, error) {
	assignment.ConnectionNamespaceID = strings.TrimSpace(assignment.ConnectionNamespaceID)
	assignment.OwnerSubject = strings.TrimSpace(assignment.OwnerSubject)
	scope, err := normalizedConnectionScope(assignment.Scope)
	if err != nil {
		return AccountConnectionAssignment{}, err
	}
	assignment.Scope = scope
	if assignment.ConnectionNamespaceID == "" {
		return AccountConnectionAssignment{}, fmt.Errorf("%w: a connection namespace is required", ErrConnectionNamespaceNotFound)
	}
	if assignment.Scope == ConnectionScopePersonal && assignment.OwnerSubject == "" {
		return AccountConnectionAssignment{}, fmt.Errorf("%w: personal accounts require an owner subject", ErrInvalidConnectionScope)
	}
	return assignment, nil
}

// MoveAccountToConnectionNamespace atomically changes only the ownership
// fields of an account. Name, URL, credentials, and tool policies survive, so
// every existing <account>__<tool> reference remains stable after a move.
func (s *FileStore) MoveAccountToConnectionNamespace(_ context.Context, name, expectedIncarnationID string, assignment AccountConnectionAssignment, expectedRevision int64) (Account, error) {
	assignment, err := normalizeAccountConnectionAssignment(assignment)
	if err != nil {
		return Account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.connectionNamespaceByIDLocked(assignment.ConnectionNamespaceID)
	if !ok {
		return Account{}, ErrConnectionNamespaceNotFound
	}
	for _, account := range s.accounts {
		if account == nil || account.Name != name {
			continue
		}
		if expectedIncarnationID == "" || account.IncarnationID != expectedIncarnationID {
			return Account{}, ErrAccountIncarnation
		}
		if expectedRevision < 1 || account.Revision != expectedRevision {
			return Account{}, ErrConnectionNamespaceRevision
		}
		if account.ConnectionNamespaceID == assignment.ConnectionNamespaceID && account.ConnectionScope == assignment.Scope && account.OwnerSubject == assignment.OwnerSubject {
			return copyAccount(*account), nil
		}
		proposed := copyAccount(*account)
		proposed.ConnectionNamespaceID = assignment.ConnectionNamespaceID
		proposed.ConnectionScope = assignment.Scope
		proposed.OwnerSubject = assignment.OwnerSubject
		proposed.Group = target.Label
		if err := s.validatePersonalAccountMCPClientGrantsLocked(proposed); err != nil {
			return Account{}, err
		}
		before := copyAccount(*account)
		oldConnectors := copyVirtualConnectors(s.connectors)
		oldEndpointNamespaces := copyEndpointNamespaces(s.namespaces)
		oldMCPClients := copyMCPClients(s.mcpClients)
		account.ConnectionNamespaceID = assignment.ConnectionNamespaceID
		account.ConnectionScope = assignment.Scope
		account.OwnerSubject = assignment.OwnerSubject
		account.Group = target.Label // keep legacy clients intelligible
		account.Revision++
		if assignment.Scope == ConnectionScopePersonal {
			s.removePersonalAccountExposureLocked(account.Name)
		}
		// The move can make this credential appear in or disappear from a
		// subject-bound client endpoint. Rotate just those client epochs in the
		// same durable write, so a token issued for the old tool set fails before
		// a Gateway replica can serve the new one.
		s.rotateMCPClientEpochsForAccountMoveLocked(before, *account)
		if err := s.saveLocked(); err != nil {
			*account = before
			s.connectors = oldConnectors
			s.namespaces = oldEndpointNamespaces
			s.mcpClients = oldMCPClients
			return Account{}, err
		}
		// A pending approval is authorization for the exact ownership
		// generation that created it. Resolve any still-parked request under
		// this same mutex so a concurrent decision cannot release it after the
		// move commits. The Gateway additionally binds dispatch to Revision for
		// the complementary decision-wins-first race.
		s.cancelPendingForAccountMoveLocked(account.Name)
		return copyAccount(*account), nil
	}
	return Account{}, ErrAccountNotFound
}
