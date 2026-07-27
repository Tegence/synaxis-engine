package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	"unicode"
)

// Account is one connected backend (one provider account). Replaces MetaMCP's
// opaque oauth_sessions row + the \x1f-packed description hack with plain fields
// we own.
type Account struct {
	Name     string `json:"name"`      // tool prefix Claude sees: <Name>__<tool>
	Label    string `json:"label"`     // friendly display name
	Group    string `json:"group"`     // workspace (real column, no separator hack)
	URL      string `json:"url"`       // upstream MCP endpoint
	AuthMode string `json:"auth_mode"` // "oauth" | "token"

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
	DeleteConnector(ctx context.Context, slug string) error
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
	UpdateTokens(name, access, refresh string) error
	Upsert(ctx context.Context, a Account) error
	Delete(ctx context.Context, name string) error
	SetMeta(ctx context.Context, name, label, group string) error
	SetDisabledTools(ctx context.Context, name string, disabled []string) error
	SetToolOverride(ctx context.Context, name, tool string, override ToolOverride) error
	SetReadOnly(ctx context.Context, name string, ro bool) error
}

// ---- FileStore: thread-safe JSON file (local dev / single instance) ----

type FileStore struct {
	path       string
	mu         sync.Mutex
	accounts   []*Account
	connectors []*VirtualConnector
	log        ring          // in-memory audit ring
	pending    []PendingCall // approval records (ephemeral, not persisted)
}

// fileStoreData is the on-disk shape. Older files were a bare JSON array of
// accounts; LoadFileStore still accepts that, and a missing "connectors"
// field simply loads as empty.
type fileStoreData struct {
	Accounts   []*Account          `json:"accounts"`
	Connectors []*VirtualConnector `json:"connectors,omitempty"`
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
		return s, nil
	}
	var d fileStoreData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse account store: %w", err)
	}
	s.accounts, s.connectors = d.Accounts, d.Connectors
	return s, nil
}

func (s *FileStore) Accounts() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, len(s.accounts))
	for i, a := range s.accounts {
		out[i] = *a
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

func (s *FileStore) UpdateTokens(name, access, refresh string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			a.AccessToken = access
			if refresh != "" {
				a.RefreshToken = refresh
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account %q not found", name)
}

func (s *FileStore) saveLocked() error {
	b, err := json.MarshalIndent(fileStoreData{Accounts: s.accounts, Connectors: s.connectors}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileStore) Account(name string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			return *a, true
		}
	}
	return Account{}, false
}

func (s *FileStore) Upsert(_ context.Context, a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.accounts {
		if x.Name == a.Name {
			cp := a
			s.accounts[i] = &cp
			return s.saveLocked()
		}
	}
	cp := a
	s.accounts = append(s.accounts, &cp)
	return s.saveLocked()
}

func (s *FileStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.accounts {
		if a.Name == name {
			s.accounts = append(s.accounts[:i], s.accounts[i+1:]...)
			return s.saveLocked()
		}
	}
	return nil // already gone
}

func (s *FileStore) SetMeta(_ context.Context, name, label, group string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Name == name {
			a.Label, a.Group = label, group
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account %q not found", name)
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

func (s *FileStore) DeleteConnector(_ context.Context, slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.connectors {
		if c.Slug == slug {
			s.connectors = append(s.connectors[:i], s.connectors[i+1:]...)
			return s.saveLocked()
		}
	}
	return nil // already gone
}
