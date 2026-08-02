package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"narthex/backend/internal/upstreamoauth"
)

var toolAliasPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// writeAccountPolicyMutationError keeps a concurrent ownership transition
// indistinguishable from any other stale console snapshot. In particular, a
// former namespace manager must not learn the destination folder through an
// error response after their authorization was revoked.
func writeAccountPolicyMutationError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, ErrAccountPolicyPrecondition) ||
		errors.Is(err, ErrAccountIncarnation) ||
		errors.Is(err, ErrConnectionNamespaceRevision) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed; refresh and try again"})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": fallback})
}

// handleToolPolicy persists one tool's model-visible alias/description and
// enabled state. Connector allowlists keep using the stable upstream name.
func (c *ConsoleAPI) handleToolPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, toolName := r.PathValue("id"), r.PathValue("tool")
	account, _, ok := c.managedAccount(w, r, accountID)
	if !ok {
		return
	}
	tools, err := c.gw.ListAccountTools(r.Context(), accountID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	var current ToolInfo
	found := false
	for _, tool := range tools {
		if tool.Name == toolName {
			current, found = tool, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tool not found"})
		return
	}

	var req struct {
		Alias       *string `json:"alias"`
		Description *string `json:"description"`
		Enabled     *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	override := account.ToolOverrides[toolName]
	if req.Alias != nil {
		override.Alias = strings.TrimSpace(*req.Alias)
		if override.Alias == toolName {
			override.Alias = ""
		}
		if override.Alias != "" && !toolAliasPattern.MatchString(override.Alias) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "alias must be 1-128 letters, numbers, dots, dashes, or underscores"})
			return
		}
		effective := override.Alias
		if effective == "" {
			effective = toolName
		}
		for _, other := range tools {
			if other.Name == toolName {
				continue
			}
			otherEffective := other.Alias
			if otherEffective == "" {
				otherEffective = other.Name
			}
			if otherEffective == effective {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "alias collides with tool " + strconv.Quote(other.Name)})
				return
			}
		}
	}
	if req.Description != nil {
		override.Description = strings.TrimSpace(*req.Description)
		if len(override.Description) > 8000 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "description must be at most 8000 bytes"})
			return
		}
	}

	disabled := append([]string(nil), account.DisabledTools...)
	if req.Enabled != nil {
		if *req.Enabled {
			disabled = without(disabled, toolName)
		} else {
			disabled = appendUnique(disabled, toolName)
		}
	}
	overrides := copyAccount(account).ToolOverrides
	if overrides == nil {
		overrides = map[string]ToolOverride{}
	}
	if override.Alias == "" && override.Description == "" {
		delete(overrides, toolName)
	} else {
		overrides[toolName] = override
	}
	if _, err := c.store.UpdateAccountPolicy(r.Context(), accountID, accountPolicyPrecondition(account), AccountPolicyMutation{
		DisabledTools: &disabled,
		ToolOverrides: &overrides,
	}); err != nil {
		writeAccountPolicyMutationError(w, err, "could not update connection policy")
		return
	}
	if _, err := c.gw.ReplaceAccount(r.Context(), accountID); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "policy saved, but live tool refresh failed: " + err.Error()})
		return
	}
	updated, err := c.gw.ListAccountTools(r.Context(), accountID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	for _, tool := range updated {
		if tool.Name == toolName {
			writeJSON(w, http.StatusOK, tool)
			return
		}
	}
	current.Alias, current.Description = override.Alias, override.Description
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	writeJSON(w, http.StatusOK, current)
}

type guardrailTestRequest struct {
	Input                string   `json:"input"`
	Redact               []string `json:"redact"`
	MaxResultBytes       int      `json:"maxResultBytes"`
	DisableInjectionScan bool     `json:"disableInjectionScan"`
}

func (c *ConsoleAPI) handleGuardrailTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req guardrailTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if msg, ok := validateMaxResultBytes(req.MaxResultBytes); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	if msg, ok := validateRedact(req.Redact); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	result, markers := applyGuards(mcp.NewToolResultText(req.Input), compileGuards(VirtualConnector{
		Slug: "console-test", Redact: req.Redact, MaxResultBytes: req.MaxResultBytes,
		DisableInjectionScan: req.DisableInjectionScan,
	}))
	var output []string
	for _, item := range result.Content {
		if text, ok := getGuardableText(item); ok {
			output = append(output, text)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": strings.Join(output, "\n"), "markers": splitMarkers(markers)})
}

// handleLogTriage applies the selected durable policy and records the
// disposition on the audit row so resolved findings stay out of the queue.
func (c *ConsoleAPI) handleLogTriage(w http.ResponseWriter, r *http.Request) {
	if c.triage == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "flagged triage not supported by this store"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid call id"})
		return
	}
	rec, actor, ok := c.visibleCallRecord(w, r, id)
	if !ok {
		return
	}
	if !strings.Contains(rec.Guard, "flagged:injection") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "call is not flagged for injection"})
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	var triage string
	switch req.Action {
	case "block":
		account, found := c.store.Account(rec.Account)
		if !found || !c.canManageAccount(r.Context(), actor, account) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
			return
		}
		disabled := appendUnique(account.DisabledTools, rec.Tool)
		if _, err := c.store.UpdateAccountPolicy(r.Context(), rec.Account, accountPolicyPrecondition(account), AccountPolicyMutation{DisabledTools: &disabled}); err != nil {
			writeAccountPolicyMutationError(w, err, "could not block tool")
			return
		}
		if _, err := c.gw.ReplaceAccount(r.Context(), rec.Account); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "tool blocked, but live refresh failed: " + err.Error()})
			return
		}
		triage = "blocked"
	case "require_approval":
		if !connectionNamespaceAdministrator(actor) {
			// Connector approval policy changes a shared delivery endpoint,
			// potentially for several credential namespaces.  Keep that
			// workspace-wide policy decision with administrators.
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required"})
			return
		}
		if !c.connectorsSupported(w) {
			return
		}
		if rec.Connector == "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "raw /mcp calls have no connector policy to update"})
			return
		}
		connector, exists := c.connStore.VirtualConnector(r.Context(), rec.Connector)
		if !exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "connector no longer exists"})
			return
		}
		if !toSet(connector.Tools[rec.Account])[rec.Tool] {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "tool is no longer exposed by that connector"})
			return
		}
		if connector.Approval == nil {
			connector.Approval = map[string][]string{}
		}
		connector.Approval[rec.Account] = appendUnique(connector.Approval[rec.Account], rec.Tool)
		if err := c.gw.UpsertConnector(r.Context(), connector); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		triage = "approval_required"
	case "false_positive":
		triage = "false_positive"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be block, require_approval, or false_positive"})
		return
	}
	if err := c.triage.SetCallTriage(r.Context(), id, triage); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	rec.Triage = triage
	writeJSON(w, http.StatusOK, rec)
}

type portableAccount struct {
	Name                string                  `json:"name"`
	DisplayName         string                  `json:"displayName"`
	ConnectionNamespace string                  `json:"connectionNamespace,omitempty"`
	Group               string                  `json:"group,omitempty"` // legacy alias
	URL                 string                  `json:"url"`
	ReadOnly            bool                    `json:"readOnly"`
	DisabledTools       []string                `json:"disabledTools,omitempty"`
	ToolOverrides       map[string]ToolOverride `json:"toolOverrides,omitempty"`
}

type portableConnector struct {
	Slug                 string              `json:"slug"`
	Label                string              `json:"label"`
	Tools                map[string][]string `json:"tools"`
	Approval             map[string][]string `json:"approval,omitempty"`
	Record               bool                `json:"record"`
	MaxResultBytes       int                 `json:"maxResultBytes"`
	Redact               []string            `json:"redact,omitempty"`
	DisableInjectionScan bool                `json:"disableInjectionScan"`
}

type portableNamespace struct {
	Slug    string   `json:"slug"`
	Label   string   `json:"label"`
	Members []string `json:"members"`
}

type portableConfig struct {
	Version    int                 `json:"version"`
	Issuer     string              `json:"issuer,omitempty"`
	Accounts   []portableAccount   `json:"accounts"`
	Connectors []portableConnector `json:"connectors"`
	Namespaces []portableNamespace `json:"namespaces,omitempty"`
}

func (c *ConsoleAPI) handlePortableConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	config := portableConfig{Version: 1, Issuer: c.selfURL, Accounts: []portableAccount{}, Connectors: []portableConnector{}}
	for _, account := range c.store.Accounts() {
		label := account.Label
		if label == "" {
			label = account.Name
		}
		config.Accounts = append(config.Accounts, portableAccount{
			Name: account.Name, DisplayName: label,
			ConnectionNamespace: account.Group, Group: account.Group, URL: account.URL,
			ReadOnly: account.ReadOnly, DisabledTools: account.DisabledTools, ToolOverrides: account.ToolOverrides,
		})
	}
	if c.connStore != nil {
		connectors, err := c.connStore.Connectors(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		for _, connector := range connectors {
			config.Connectors = append(config.Connectors, portableConnector{
				Slug: connector.Slug, Label: connector.Label, Tools: connector.Tools, Approval: connector.Approval,
				Record: connector.Record, MaxResultBytes: connector.MaxResultBytes, Redact: connector.Redact,
				DisableInjectionScan: connector.DisableInjectionScan,
			})
		}
	}
	if c.nsStore != nil {
		namespaces, err := c.nsStore.Namespaces(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		for _, ns := range namespaces {
			config.Namespaces = append(config.Namespaces, portableNamespace{
				Slug: ns.Slug, Label: ns.Label, Members: append([]string(nil), ns.Accounts...),
			})
		}
	}
	writeJSON(w, http.StatusOK, config)
}

// handlePortableConfigImport safely merges a versioned, secret-free config.
// Existing account credentials are preserved; new accounts import disconnected
// and can be authorized afterward. Unmentioned resources are never deleted.
func (c *ConsoleAPI) handlePortableConfigImport(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.requireConnectionNamespaceAdministrator(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !c.connectorsSupported(w) {
		return
	}
	var config portableConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&config); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if config.Version != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported config version"})
		return
	}
	if len(config.Namespaces) > 0 && c.nsStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "namespaces not supported by this store"})
		return
	}
	if len(config.Accounts) > 250 || len(config.Connectors) > 250 || len(config.Namespaces) > 250 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config exceeds the 250 account/connector/namespace limit"})
		return
	}

	knownAccounts := map[string]bool{}
	for _, account := range c.store.Accounts() {
		knownAccounts[account.Name] = true
	}
	seenAccounts := map[string]bool{}
	for i, account := range config.Accounts {
		account.Name = strings.TrimSpace(account.Name)
		if account.Name == "" || slugify(account.Name) != account.Name {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("accounts[%d].name must be a normalized account prefix", i)})
			return
		}
		if seenAccounts[account.Name] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duplicate account " + strconv.Quote(account.Name)})
			return
		}
		seenAccounts[account.Name], knownAccounts[account.Name] = true, true
		if strings.TrimSpace(account.DisplayName) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "displayName is required for account " + strconv.Quote(account.Name)})
			return
		}
		if strings.TrimSpace(account.ConnectionNamespace) != "" &&
			strings.TrimSpace(account.Group) != "" &&
			strings.TrimSpace(account.ConnectionNamespace) != strings.TrimSpace(account.Group) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connectionNamespace and group must match for account " + strconv.Quote(account.Name)})
			return
		}
		if err := upstreamoauth.ValidateUpstreamURL(strings.TrimSpace(account.URL)); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account " + strconv.Quote(account.Name) + " must use a valid https URL"})
			return
		}
		if existing, ok := c.store.Account(account.Name); ok &&
			accountHasStoredCredentials(existing) &&
			!equalAccountURL(existing.URL, account.URL) {
			// Portable config intentionally contains no credentials. Never let it
			// retarget credentials already held by this Engine to another origin or
			// path; the operator must disconnect/re-authorize the account instead.
			// Keep the response generic because either URL may itself contain
			// sensitive query material in a legacy record.
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "cannot change the URL of connected account " + strconv.Quote(account.Name) + "; disconnect it first",
			})
			return
		}
		aliases := map[string]string{}
		for tool, override := range account.ToolOverrides {
			if override.Alias != "" && !toolAliasPattern.MatchString(override.Alias) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid alias for " + account.Name + "/" + tool})
				return
			}
			effective := override.Alias
			if effective == "" {
				effective = tool
			}
			if previous, exists := aliases[effective]; exists && previous != tool {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duplicate effective tool name " + strconv.Quote(effective) + " in account " + strconv.Quote(account.Name)})
				return
			}
			aliases[effective] = tool
		}
	}
	seenNamespaces := map[string]bool{}
	for i, namespace := range config.Namespaces {
		if namespace.Slug == "" || slugify(namespace.Slug) != namespace.Slug {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("namespaces[%d].slug must be normalized", i)})
			return
		}
		if seenNamespaces[namespace.Slug] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duplicate namespace " + strconv.Quote(namespace.Slug)})
			return
		}
		seenNamespaces[namespace.Slug] = true
		if strings.TrimSpace(namespace.Label) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required for namespace " + strconv.Quote(namespace.Slug)})
			return
		}
		for _, account := range normalizedNamespaceAccounts(namespace.Members) {
			if !knownAccounts[account] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace " + strconv.Quote(namespace.Slug) + " references unknown account " + strconv.Quote(account)})
				return
			}
		}
		if c.connStore != nil {
			if _, exists := c.connStore.VirtualConnector(r.Context(), namespace.Slug); exists {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "namespace " + strconv.Quote(namespace.Slug) + " conflicts with an existing connector"})
				return
			}
		}
	}

	seenConnectors := map[string]bool{}
	for i, connector := range config.Connectors {
		if connector.Slug == "" || slugify(connector.Slug) != connector.Slug {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("connectors[%d].slug must be normalized", i)})
			return
		}
		if seenConnectors[connector.Slug] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duplicate connector " + strconv.Quote(connector.Slug)})
			return
		}
		seenConnectors[connector.Slug] = true
		if seenNamespaces[connector.Slug] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "endpoint slug " + strconv.Quote(connector.Slug) + " is used by both a connector and namespace"})
			return
		}
		if c.nsStore != nil {
			if _, exists := c.nsStore.Namespace(r.Context(), connector.Slug); exists {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "connector " + strconv.Quote(connector.Slug) + " conflicts with an existing namespace"})
				return
			}
		}
		if strings.TrimSpace(connector.Label) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required for connector " + strconv.Quote(connector.Slug)})
			return
		}
		for account := range connector.Tools {
			if !knownAccounts[account] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connector " + strconv.Quote(connector.Slug) + " references unknown account " + strconv.Quote(account)})
				return
			}
		}
		if msg, ok := validateApproval(connector.Approval, connector.Tools); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if msg, ok := validateMaxResultBytes(connector.MaxResultBytes); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		if msg, ok := validateRedact(connector.Redact); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
	}

	var warnings []string
	for _, imported := range config.Accounts {
		update := PortableAccountConfig{
			Label: strings.TrimSpace(imported.DisplayName), URL: strings.TrimSpace(imported.URL),
			ReadOnly: imported.ReadOnly, DisabledTools: append([]string(nil), imported.DisabledTools...),
			ToolOverrides: imported.ToolOverrides,
		}
		account, exists := c.store.Account(imported.Name)
		if exists {
			// Existing accounts must retain the ownership boundary that is
			// current at commit time. A portable export has no stable namespace
			// ID, so replaying its legacy Group against a newer account snapshot
			// could otherwise undo a concurrent move.
			updater, ok := c.store.(PortableAccountConfigStore)
			if !ok {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "portable updates are not supported by this store"})
				return
			}
			var err error
			account, err = updater.UpdatePortableAccountConfig(r.Context(), imported.Name, update)
			if err != nil {
				switch {
				case errors.Is(err, ErrConnectAccountURLChanged):
					writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot change the URL of connected account " + strconv.Quote(imported.Name) + "; disconnect it first"})
				case errors.Is(err, ErrAccountNotFound):
					writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed while importing; retry the import"})
				default:
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not update account configuration"})
				}
				return
			}
		} else {
			group := strings.TrimSpace(imported.ConnectionNamespace)
			if group == "" {
				group = strings.TrimSpace(imported.Group)
			}
			account = Account{
				Name: imported.Name, AuthMode: "oauth", Group: group,
				Label: update.Label, URL: update.URL, ReadOnly: update.ReadOnly,
				DisabledTools: update.DisabledTools, ToolOverrides: update.ToolOverrides,
			}
			// Create rather than Upsert so a concurrent connection is never
			// replaced by the import's stale, credential-free snapshot.
			if err := c.store.Create(r.Context(), account); err != nil {
				if errors.Is(err, ErrAccountExists) {
					writeJSON(w, http.StatusConflict, map[string]string{"error": "connection changed while importing; retry the import"})
				} else {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not create account configuration"})
				}
				return
			}
			var found bool
			account, found = c.store.Account(imported.Name)
			if !found {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "account could not be read after import"})
				return
			}
		}
		if c.store.Token(account.Name) != "" || c.store.RefreshToken(account.Name) != "" {
			if _, err := c.gw.ReplaceAccount(r.Context(), account.Name); err != nil {
				warnings = append(warnings, account.Name+": "+err.Error())
			}
		} else {
			current, ok := c.store.Account(account.Name)
			if ok {
				c.gw.RemoveAccount(account.Name, current.IncarnationID)
			}
		}
	}
	for _, imported := range config.Namespaces {
		if c.nsStore == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "namespaces not supported by this store"})
			return
		}
		members := normalizedNamespaceAccounts(imported.Members)
		if current, ok := c.nsStore.Namespace(r.Context(), imported.Slug); ok {
			if _, err := c.gw.UpdateNamespace(r.Context(), Namespace{
				Slug: imported.Slug, Label: strings.TrimSpace(imported.Label), Accounts: members,
			}, NamespacePrecondition{
				Generation: current.Epoch,
				Revision:   current.Revision,
			}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
		} else {
			if _, err := c.gw.CreateNamespace(r.Context(), Namespace{
				Slug: imported.Slug, Label: strings.TrimSpace(imported.Label), Accounts: members,
			}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
		}
	}
	for _, imported := range config.Connectors {
		if err := c.gw.UpsertConnector(r.Context(), VirtualConnector{
			Slug: imported.Slug, Label: strings.TrimSpace(imported.Label), Tools: imported.Tools, Approval: imported.Approval,
			Record: imported.Record, MaxResultBytes: imported.MaxResultBytes, Redact: imported.Redact,
			DisableInjectionScan: imported.DisableInjectionScan,
		}); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accountsImported": len(config.Accounts), "connectorsImported": len(config.Connectors),
		"namespacesImported": len(config.Namespaces), "warnings": warnings,
	})
}

func accountHasStoredCredentials(account Account) bool {
	return account.BearerToken != "" || account.AccessToken != "" ||
		account.RefreshToken != "" || account.ClientSecret != ""
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return append([]string(nil), items...)
		}
	}
	return append(append([]string(nil), items...), value)
}

func without(items []string, value string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

func splitMarkers(markers string) []string {
	if markers == "" {
		return []string{}
	}
	return strings.Split(markers, ",")
}
