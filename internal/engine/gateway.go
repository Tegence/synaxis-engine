package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/upstreamoauth"
)

// Gateway aggregates every account's MCP tools into one MCP server (the
// MetaMCP replacement). One bad account is skipped, not fatal — and each
// upstream carries the refresh-and-redial guarantee from upstream.go.
type Gateway struct {
	store AccountStore
	mcp   *server.MCPServer
	audit AuditSink // optional; records every tool call

	mu         sync.Mutex
	byAcct     map[string][]string         // account name -> registered (prefixed) tool names
	cached     map[string][]cachedTool     // account name -> tools (post-rewrite) + handlers
	connectors map[string]*connectorServer // slug -> per-connector MCP server
	refreshMu  map[string]*sync.Mutex      // per-account refresh serialization
	alertState map[string]bool             // account -> currently-down (alert dedup)
	webhook    string                      // optional alert webhook URL
	consoleURL string                      // linked in approval webhook messages

	// revokeResource, when wired (SetTokenRevoker), tells the OAuth AS to drop
	// refresh grants for a deleted connector's resource path.
	revokeResource func(resourcePath string)

	// Flight recorder knobs (set once at startup, before serving).
	recordDefault bool          // record payloads for calls on the default /mcp endpoint
	retention     time.Duration // purge audit rows older than this in the watch tick (0 = never)

	// Approval manager (in-process; the store row is the audit record).
	approveMu       sync.Mutex
	approveCh       map[string]chan string // pending approval id -> decision channel
	approvalTimeout time.Duration          // wait budget per approval (0 = default)

	// listTools is a test seam; nil means "dial the upstream" (production).
	listTools func(ctx context.Context, a Account) ([]mcp.Tool, error)
}

// cachedTool is one registered tool (prefixed name, rewritten title) plus the
// exact handler closure registered on the main /mcp server — connector servers
// reuse it so audit/refresh behavior is identical on every endpoint.
type cachedTool struct {
	tool       mcp.Tool
	sourceName string // stable upstream bare name; tool.Name may be an operator alias
	handler    server.ToolHandlerFunc
}

// SetAlertWebhook configures where account-down/recovered alerts are POSTed.
func (g *Gateway) SetAlertWebhook(url string) { g.webhook = url }

func NewGateway(store AccountStore, mcpServer *server.MCPServer) *Gateway {
	return &Gateway{
		store:      store,
		mcp:        mcpServer,
		byAcct:     map[string][]string{},
		cached:     map[string][]cachedTool{},
		connectors: map[string]*connectorServer{},
	}
}

// SetAudit attaches an audit sink so tool calls are recorded.
func (g *Gateway) SetAudit(a AuditSink) { g.audit = a }

// SetRecordPayloads opts the DEFAULT /mcp endpoint into payload recording
// (connector endpoints carry their own per-connector Record flag). Wired from
// ENGINE_RECORD_PAYLOADS in main.
func (g *Gateway) SetRecordPayloads(on bool) { g.recordDefault = on }

// SetAuditRetention sets how long audit rows are kept; the watch tick deletes
// older rows on stores with the AuditPurger facet. 0 disables purging. Wired
// from AUDIT_RETENTION_DAYS in main.
func (g *Gateway) SetAuditRetention(d time.Duration) { g.retention = d }

// RecentCalls returns the most recent tool-call records (for the console).
// Summary-only: Args/Result are always empty here — use CallDetail.
func (g *Gateway) RecentCalls(ctx context.Context, limit int) ([]CallRecord, error) {
	if g.audit == nil {
		return nil, nil
	}
	return g.audit.RecentCalls(ctx, limit)
}

// CallDetail returns one full audit record including recorded payloads.
func (g *Gateway) CallDetail(ctx context.Context, id int64) (CallRecord, bool, error) {
	if g.audit == nil {
		return CallRecord{}, false, nil
	}
	return g.audit.CallDetail(ctx, id)
}

// AccountHealth is a live per-account status for the console.
type AccountHealth struct {
	UUID      string `json:"uuid"` // = account name (the console keys by this)
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	ToolCount int    `json:"toolCount"`
	LatencyMs int64  `json:"latencyMs"`
	CheckedAt string `json:"checkedAt"`
}

// upstreamFor builds a live Upstream for an account, wiring Token + Refresh
// against the store (refreshed tokens are persisted, and a rotated refresh
// token is re-read from the store on each refresh).
func (g *Gateway) upstreamFor(a Account) *Upstream {
	up := &Upstream{
		Name:  a.Name,
		URL:   a.URL,
		Token: func() string { return g.store.Token(a.Name) },
	}
	if a.AuthMode == "oauth" && a.RefreshToken != "" {
		name := a.Name
		// Both reactive (on-401) and proactive (refresh-ahead) refresh route
		// through refreshAccount, which serializes per account so two refreshes
		// never burn the same rotating token (the bug that revokes the family).
		up.Refresh = func(ctx context.Context) error { return g.refreshAccount(ctx, name) }
	}
	return up
}

func (g *Gateway) refreshLock(name string) *sync.Mutex {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refreshMu == nil {
		g.refreshMu = map[string]*sync.Mutex{}
	}
	mu, ok := g.refreshMu[name]
	if !ok {
		mu = &sync.Mutex{}
		g.refreshMu[name] = mu
	}
	return mu
}

// refreshAccount refreshes one OAuth account's tokens and persists them, under
// a per-account lock. Used by both the on-401 path and refresh-ahead.
func (g *Gateway) refreshAccount(ctx context.Context, name string) error {
	mu := g.refreshLock(name)
	mu.Lock()
	defer mu.Unlock()
	a, ok := g.store.Account(name)
	if !ok {
		return fmt.Errorf("account %q not found", name)
	}
	if a.AuthMode != "oauth" || a.RefreshToken == "" {
		return nil
	}
	meta := &upstreamoauth.Metadata{TokenEndpoint: a.TokenEndpoint, Resource: a.Resource}
	nt, err := upstreamoauth.Refresh(ctx, meta, a.RefreshToken, a.ClientID, a.ClientSecret)
	if err != nil {
		return err
	}
	return g.store.UpdateTokens(name, nt.AccessToken, nt.RefreshToken)
}

// aggregateAccount connects to one account, lists its tools, and registers each
// (prefixed) tool with a handler that routes tools/call back to that upstream.
func (g *Gateway) aggregateAccount(ctx context.Context, a Account) (int, error) {
	up := g.upstreamFor(a)
	var tools []mcp.Tool
	var err error
	if g.listTools != nil { // test seam
		tools, err = g.listTools(ctx, a)
	} else {
		tools, err = up.ListTools(ctx)
	}
	if err != nil {
		return 0, err
	}
	label := a.Label
	if label == "" {
		label = a.Name
	}
	disabled := toSet(a.DisabledTools)
	names := make([]string, 0, len(tools))
	cached := make([]cachedTool, 0, len(tools))
	for _, t := range tools {
		bare := strings.TrimPrefix(t.Name, a.Name+"__")
		if disabled[bare] {
			continue // curated off — never register it, so Claude never sees it
		}
		if a.ReadOnly && !readOnlyTool(t, bare) {
			continue // read-only account: mutating tools are never registered
		}
		override := a.ToolOverrides[bare]
		exposedName := bare
		if override.Alias != "" {
			exposedName = override.Alias
		}
		t.Name = a.Name + "__" + exposedName
		if override.Description != "" {
			t.Description = override.Description
		}
		// Stamp the account label into the DISPLAY title so multiple accounts of
		// the same provider (e.g. two Notion workspaces) are distinguishable in
		// the client UI — which shows Title, not the prefixed Name.
		disp := t.Title
		if disp == "" {
			disp = t.Annotations.Title
		}
		if disp == "" {
			disp = bare
		}
		t.Title = label + " · " + disp
		t.Annotations.Title = t.Title
		upRef, bareName, acct := up, bare, a.Name
		handler := server.ToolHandlerFunc(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			start := time.Now()
			res, err := upRef.CallTool(ctx, bareName, req.GetArguments())
			// Response guardrails — CONNECTOR endpoints only. The default
			// /mcp endpoint never injects an auditScope, so sc is nil there
			// and the result passes through raw (guards are a connector
			// feature by design). Order matters: redact → cap → injection
			// scan runs BEFORE the audit row below, so recorded payloads
			// never contain what redaction removed. Protocol errors (err !=
			// nil → res unusable) skip guards; isError tool results are
			// guarded like any other (their Error field isn't touched — only
			// text content).
			var guard string
			if sc := auditScopeFrom(ctx); sc != nil && sc.guards != nil && err == nil {
				res, guard = applyGuards(res, *sc.guards)
			}
			if g.audit != nil {
				rec := CallRecord{
					Account: acct, Tool: bareName, OK: err == nil,
					Ms:    time.Since(start).Milliseconds(),
					Guard: guard, // post-guard markers; "" on /mcp or when nothing fired
				}
				if err != nil {
					rec.Error = err.Error()
				}
				// This closure is shared byte-for-byte between /mcp and every
				// connector server; the endpoint identity (connector slug,
				// approval decision, record flag) is layered on by the scope
				// wrapper via ctx. No scope = the default /mcp endpoint.
				record := g.recordDefault
				if sc := auditScopeFrom(ctx); sc != nil {
					rec.Connector, rec.Decision, record = sc.connector, sc.decision, sc.record
				}
				if record {
					rec.Args = marshalPayload(req.GetArguments())
					if res != nil {
						rec.Result = marshalPayload(res)
					}
				}
				g.audit.LogCall(rec)
			}
			return res, err
		})
		g.mcp.AddTool(t, handler)
		names = append(names, t.Name)
		// Cache tool + the SAME closure so connector endpoints dispatch (and
		// audit) identically without re-dialing the upstream.
		cached = append(cached, cachedTool{tool: t, sourceName: bare, handler: handler})
	}
	g.mu.Lock()
	g.byAcct[a.Name] = names
	g.cached[a.Name] = cached
	g.mu.Unlock()
	return len(names), nil // count REGISTERED (enabled), not total
}

// readOnlyTool reports whether a tool is safe to expose on a read-only
// account. Explicit annotations win; without a usable annotation we fall back
// to a conservative NAME HEURISTIC (a write verb anywhere vetoes; otherwise a
// read verb as an exact word passes). It is a guess — UI copy must label it
// as such.
func readOnlyTool(t mcp.Tool, bare string) bool {
	if t.Annotations.ReadOnlyHint != nil {
		return *t.Annotations.ReadOnlyHint
	}
	if t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
		return false
	}
	return readOnlyName(bare)
}

var readVerbs = []string{"get", "list", "search", "read", "query", "fetch", "describe", "find", "show", "count"}

// writeVerbs veto the read heuristic: names like create_list, delete_saved_search
// or update_query contain a read word but MUTATE — the veto must win, or a
// read-only account leaks mutating tools.
var writeVerbs = []string{
	"create", "delete", "update", "add", "set", "remove", "insert", "write",
	"put", "post", "patch", "move", "archive", "send", "upload", "execute",
	"run", "apply", "save", "push", "merge", "reset", "edit", "cancel",
}

// nameTokens splits a tool name into lowercase words on '_', '-', '.' and
// camelCase boundaries ("getIssue" → ["get","issue"]). Exact-word matching —
// no prefix guessing, so "getaway_x" never reads as "get".
func nameTokens(bare string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	prevLower := false
	for _, r := range bare {
		if r == '_' || r == '-' || r == '.' {
			flush()
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			flush()
		}
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
		cur.WriteRune(r)
	}
	flush()
	return tokens
}

func readOnlyName(bare string) bool {
	tokens := nameTokens(bare)
	for _, t := range tokens {
		for _, w := range writeVerbs {
			if t == w {
				return false // veto wins: any write verb marks the tool mutating
			}
		}
	}
	for _, t := range tokens {
		for _, v := range readVerbs {
			if t == v {
				return true
			}
		}
	}
	return false
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ToolInfo describes one upstream tool for the curation UI.
type ToolInfo struct {
	Name        string `json:"name"` // stable upstream bare name
	Alias       string `json:"alias,omitempty"`
	Title       string `json:"title"` // upstream display title
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	ReadOnly    bool   `json:"readOnly"`
	Destructive bool   `json:"destructive"`
}

// ListAccountTools live-lists every tool an account exposes upstream, marked
// with its current enabled/disabled state and its read-only/destructive hint.
func (g *Gateway) ListAccountTools(ctx context.Context, name string) ([]ToolInfo, error) {
	a, ok := g.store.Account(name)
	if !ok {
		return nil, fmt.Errorf("account %q not found", name)
	}
	var tools []mcp.Tool
	var err error
	if g.listTools != nil {
		tools, err = g.listTools(ctx, a)
	} else {
		tools, err = g.upstreamFor(a).ListTools(ctx)
	}
	if err != nil {
		return nil, err
	}
	disabled := toSet(a.DisabledTools)
	out := make([]ToolInfo, 0, len(tools))
	for _, t := range tools {
		bare := strings.TrimPrefix(t.Name, a.Name+"__")
		title := t.Title
		if title == "" {
			title = t.Annotations.Title
		}
		if title == "" {
			title = bare
		}
		override := a.ToolOverrides[bare]
		description := t.Description
		if override.Description != "" {
			description = override.Description
		}
		ro := t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
		de := t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint
		out = append(out, ToolInfo{Name: bare, Alias: override.Alias, Title: title, Description: description, Enabled: !disabled[bare], ReadOnly: ro, Destructive: de})
	}
	return out, nil
}

// RemoveAccount unregisters an account's tools from the live MCP server.
func (g *Gateway) RemoveAccount(name string) {
	g.mu.Lock()
	names := g.byAcct[name]
	delete(g.byAcct, name)
	delete(g.cached, name)
	g.mu.Unlock()
	if len(names) > 0 {
		g.mcp.DeleteTools(names...)
	}
	g.RefreshConnectors(context.Background())
}

// ReplaceAccount re-aggregates one account (after a token/meta change) so its
// live tools — and their labels — reflect the current store.
func (g *Gateway) ReplaceAccount(ctx context.Context, name string) (int, error) {
	g.RemoveAccount(name)
	return g.AddAccount(ctx, name)
}

// Health live-checks every account (concurrently) by listing its tools.
func (g *Gateway) Health(ctx context.Context) []AccountHealth {
	accts := g.store.Accounts()
	out := make([]AccountHealth, len(accts))
	var wg sync.WaitGroup
	for i, a := range accts {
		wg.Add(1)
		go func(i int, a Account) {
			defer wg.Done()
			started := time.Now()
			h := AccountHealth{UUID: a.Name, CheckedAt: started.UTC().Format(time.RFC3339)}
			if a.AuthMode == "oauth" && a.AccessToken == "" && a.RefreshToken == "" {
				h.Status, h.Detail = "needs_auth", "not connected yet"
			} else if tools, err := g.upstreamFor(a).ListTools(ctx); err != nil {
				if isUnauthorized(err) {
					h.Status, h.Detail = "auth_expired", "re-connect needed"
				} else {
					h.Status, h.Detail = "error", err.Error()
				}
			} else {
				h.Status, h.ToolCount = "ok", len(tools)
			}
			h.LatencyMs = time.Since(started).Milliseconds()
			out[i] = h
		}(i, a)
	}
	wg.Wait()
	return out
}

// Aggregate registers tools for every account. One bad account is skipped.
func (g *Gateway) Aggregate(ctx context.Context) int {
	total := 0
	for _, a := range g.store.Accounts() {
		n, err := g.aggregateAccount(ctx, a)
		if err != nil {
			log.Printf("engine: account %q skipped (list tools failed): %v", a.Name, err)
			continue
		}
		total += n
		log.Printf("engine: aggregated %d tools from %q", n, a.Name)
	}
	g.RefreshConnectors(ctx)
	return total
}

// AddAccount registers a single account's tools at runtime (after a connect).
func (g *Gateway) AddAccount(ctx context.Context, name string) (int, error) {
	a, ok := g.store.Account(name)
	if !ok {
		return 0, fmt.Errorf("account %q not found", name)
	}
	n, err := g.aggregateAccount(ctx, a)
	if err == nil {
		g.RefreshConnectors(ctx)
	}
	return n, err
}

// StartWatch runs the background reliability loop: refresh-ahead for OAuth
// accounts (so tokens never reach expiry), then a health sweep that fires an
// alert on each down/recovered transition.
func (g *Gateway) StartWatch(ctx context.Context, interval time.Duration) {
	select { // first tick soon after boot, then on the interval
	case <-ctx.Done():
		return
	case <-time.After(60 * time.Second):
		g.tick(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.tick(ctx)
		}
	}
}

func (g *Gateway) tick(ctx context.Context) {
	refreshed := 0
	for _, a := range g.store.Accounts() {
		if a.AuthMode == "oauth" && a.RefreshToken != "" {
			if err := g.refreshAccount(ctx, a.Name); err != nil {
				log.Printf("engine: refresh-ahead %q: %v", a.Name, err)
			} else {
				refreshed++
			}
		}
	}
	if refreshed > 0 {
		log.Printf("engine: refresh-ahead refreshed %d oauth account(s)", refreshed)
	}
	for _, h := range g.Health(ctx) { // health sweep covers token accounts too
		g.evalAlert(h)
	}
	g.purgeAudit(ctx)
}

// purgeAudit applies audit retention: rows older than the window are deleted.
// No-op when retention is disabled, no audit sink is attached, or the sink
// has no purger facet (FileStore's ring self-bounds anyway).
func (g *Gateway) purgeAudit(ctx context.Context) {
	if g.retention <= 0 || g.audit == nil {
		return
	}
	p, ok := g.audit.(AuditPurger)
	if !ok {
		return
	}
	n, err := p.PurgeCalls(ctx, g.retention)
	if err != nil {
		log.Printf("engine: audit purge failed: %v", err)
		return
	}
	if n > 0 {
		log.Printf("engine: audit purge deleted %d call row(s) older than %s", n, g.retention)
	}
}

// evalAlert fires only on a state change, so a sustained outage alerts once.
func (g *Gateway) evalAlert(h AccountHealth) {
	g.mu.Lock()
	if g.alertState == nil {
		g.alertState = map[string]bool{}
	}
	was := g.alertState[h.UUID]
	now := h.Status != "ok"
	g.alertState[h.UUID] = now
	g.mu.Unlock()
	switch {
	case now && !was:
		g.fireAlert(fmt.Sprintf("⚠️ Synaxis: account %q is DOWN (%s) — %s", h.UUID, h.Status, h.Detail))
	case !now && was:
		g.fireAlert(fmt.Sprintf("✅ Synaxis: account %q recovered", h.UUID))
	}
}

func (g *Gateway) fireAlert(msg string) {
	log.Printf("ALERT: %s", msg)
	if g.webhook == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]string{"text": msg, "content": msg}) // Slack=text, Discord=content
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.webhook, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}
