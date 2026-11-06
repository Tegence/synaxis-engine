package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// The caller-grant tests run one loopback origin that serves a
// caller-delegated MCP server under a hosting path prefix, its token endpoint,
// and an ordinary token-auth MCP server. Nothing reaches a real service.

const (
	callerGrantTestClientID     = "client_test"
	callerGrantTestClientSecret = "secret_0123456789abcdef0123456789abcdef"
	callerGrantTestListingKey   = "listing-key"
	callerGrantTestSubject      = "subject-of-the-grant-7f3a"
)

type callerGrantExchangeSeen struct {
	authorization string
	contentType   string
	form          url.Values
	grantHeader   string
}

type callerGrantCallSeen struct {
	path          string
	method        string
	authorization string
	grantHeader   string
}

type callerGrantToolSeen struct {
	path string
	meta map[string]any
}

type callerGrantOrigin struct {
	*httptest.Server
	t *testing.T

	mu        sync.Mutex
	exchanges []callerGrantExchangeSeen
	calls     []callerGrantCallSeen
	tools     []callerGrantToolSeen
	issued    map[string]bool // access tokens the delegated upstream accepts
	revoked   map[string]bool // access tokens it now answers 401 to
	serial    int
	expiresIn int
	// exchange replaces the default token endpoint answer when set.
	exchange http.HandlerFunc
	// onExchange runs inside the default token endpoint before it answers.
	onExchange func()
	// revokeIssued makes every token the endpoint issues answer 401.
	revokeIssued bool
}

func newCallerGrantOrigin(t *testing.T) *callerGrantOrigin {
	t.Helper()
	origin := &callerGrantOrigin{t: t, issued: map[string]bool{}, revoked: map[string]bool{}, expiresIn: 120}
	mcpServer := func(path string) http.Handler {
		s := server.NewMCPServer("upstream", "1.0", server.WithToolCapabilities(true))
		s.AddTool(mcp.NewTool("search", mcp.WithDescription("search")), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			seen := callerGrantToolSeen{path: path}
			if req.Params.Meta != nil {
				seen.meta = map[string]any{}
				for k, v := range req.Params.Meta.AdditionalFields {
					seen.meta[k] = v
				}
				if req.Params.Meta.ProgressToken != nil {
					seen.meta["progressToken"] = req.Params.Meta.ProgressToken
				}
			}
			origin.mu.Lock()
			origin.tools = append(origin.tools, seen)
			origin.mu.Unlock()
			return mcp.NewToolResultText("result from " + path), nil
		})
		return server.NewStreamableHTTPServer(s, server.WithEndpointPath("/"))
	}
	delegated := mcpServer("/hosted/h1/mcp")
	plain := mcpServer("/plain/mcp")
	upstream := func(path string, inner http.Handler, accept func(method, token string) bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var envelope struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(body, &envelope)
			authorization := r.Header.Get("Authorization")
			origin.mu.Lock()
			origin.calls = append(origin.calls, callerGrantCallSeen{
				path: path, method: envelope.Method, authorization: authorization, grantHeader: r.Header.Get(callerGrantHeader),
			})
			ok := accept(envelope.Method, strings.TrimPrefix(authorization, "Bearer "))
			origin.mu.Unlock()
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
				return
			}
			inner.ServeHTTP(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hosted/h1/mcp", upstream("/hosted/h1/mcp", delegated, func(method, token string) bool {
		if origin.revoked[token] {
			return false
		}
		if method == string(mcp.MethodToolsCall) {
			return origin.issued[token] // the listing key never calls a tool
		}
		return token == callerGrantTestListingKey || origin.issued[token]
	}))
	mux.HandleFunc("/plain/mcp", upstream("/plain/mcp", plain, func(_, token string) bool {
		return token == "plain-token"
	}))
	mux.HandleFunc("/hosted/h1/mcp/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		origin.mu.Lock()
		origin.exchanges = append(origin.exchanges, callerGrantExchangeSeen{
			authorization: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"),
			form: r.PostForm, grantHeader: r.Header.Get(callerGrantHeader),
		})
		custom, hook := origin.exchange, origin.onExchange
		origin.mu.Unlock()
		if hook != nil {
			hook()
		}
		if custom != nil {
			custom(w, r)
			return
		}
		origin.mu.Lock()
		origin.serial++
		sum := sha256.Sum256([]byte(r.PostForm.Get("assertion")))
		token := fmt.Sprintf("atk_%s_%d", hex.EncodeToString(sum[:6]), origin.serial)
		origin.issued[token] = true
		if origin.revokeIssued {
			origin.revoked[token] = true
		}
		expiresIn := origin.expiresIn
		origin.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token, "token_type": "Bearer", "expires_in": expiresIn, "scope": "agent",
		})
	})
	origin.Server = httptest.NewServer(mux)
	t.Cleanup(origin.Close)
	return origin
}

// resource is the canonical resource identifier; the upstream itself lives
// under the /hosted/h1 prefix on the same origin.
func (o *callerGrantOrigin) resource() string { return o.URL + "/mcp" }

func (o *callerGrantOrigin) exchangeCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.exchanges)
}

func (o *callerGrantOrigin) lastExchange() callerGrantExchangeSeen {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.exchanges) == 0 {
		o.t.Fatal("no exchange reached the token endpoint")
	}
	return o.exchanges[len(o.exchanges)-1]
}

func (o *callerGrantOrigin) delegatedToolCalls() []callerGrantCallSeen {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []callerGrantCallSeen
	for _, call := range o.calls {
		if call.path == "/hosted/h1/mcp" && call.method == string(mcp.MethodToolsCall) {
			out = append(out, call)
		}
	}
	return out
}

func (o *callerGrantOrigin) toolsSeen() []callerGrantToolSeen {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]callerGrantToolSeen(nil), o.tools...)
}

func (o *callerGrantOrigin) setExchange(handler http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.exchange = handler
}

type callerGrantFixture struct {
	origin   *callerGrantOrigin
	store    *FileStore
	gateway  *Gateway
	workload MCPClient
	other    MCPClient // a second workload client with the same exact grant
}

// newCallerGrantFixture stores the caller-delegated account "delegated" and
// the ordinary account "plain", and two workload clients whose exact
// connection list names both.
func newCallerGrantFixture(t *testing.T) *callerGrantFixture {
	t.Helper()
	useLoopbackUpstreamTransport(t)
	ctx := context.Background()
	origin := newCallerGrantOrigin(t)
	store, gateway := newMCPClientGateway(t)
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Delegated", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "delegated", Label: "Acme Tools", URL: origin.URL + "/hosted/h1/mcp", AuthMode: "token",
		BearerToken: callerGrantTestListingKey, ConnectionNamespaceID: folder.ID, ConnectionScope: ConnectionScopeService,
		CallerDelegated: true, ClientID: callerGrantTestClientID, ClientSecret: callerGrantTestClientSecret,
		TokenEndpoint: origin.URL + "/hosted/h1/mcp/token", Resource: origin.resource(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "plain", Label: "Plain", URL: origin.URL + "/plain/mcp", AuthMode: "token", BearerToken: "plain-token",
		ConnectionNamespaceID: folder.ID,
	}); err != nil {
		t.Fatal(err)
	}
	gateway.Aggregate(ctx)
	fixture := &callerGrantFixture{origin: origin, store: store, gateway: gateway}
	for i, subject := range []string{"wl_agent_one", "wl_agent_two"} {
		client, err := store.CreateMCPClient(ctx, MCPClient{
			Name: subject, Subject: subject, Kind: MCPClientKindWorkload, ConnectionIDs: []string{"delegated", "plain"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			fixture.workload = client
		} else {
			fixture.other = client
		}
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// claims returns grant claims that route to the delegated account for
// client, expiring in a minute.
func (f *callerGrantFixture) claims(client MCPClient) map[string]any {
	now := callerGrantNow()
	return map[string]any{
		"iss": "https://control.example", "aud": f.origin.resource() + "/token", "resource": f.origin.resource(),
		"org": "org_1", "client_id": callerGrantTestClientID, "sub": callerGrantTestSubject,
		"act":     map[string]any{"sub": "agt_1", "run": "run_1", "job": "job_1", "client": client.ID},
		"trigger": "manual", "scope": "agent", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": "jti_0123456789abcdefghij",
	}
}

func (f *callerGrantFixture) grant(t *testing.T, client MCPClient) callerGrant {
	t.Helper()
	return callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, f.claims(client))}
}

// testCompactGrant builds a compact JWS with the given payload. The Engine
// never verifies signatures, so the signature segment is arbitrary bytes.
func testCompactGrant(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"oauth-id-jag+jwt","kid":"test"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 64))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + signature
}

func callerGrantHeaderValue(grant callerGrant) string {
	return `resource="` + grant.resource + `", grant="` + grant.compact + `"`
}

type callerGrantCallResult struct {
	text     string
	isError  bool
	rpcError string
}

func decodeCallerGrantCallResult(t *testing.T, raw []byte) callerGrantCallResult {
	t.Helper()
	var envelope struct {
		Result *struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	var out callerGrantCallResult
	if envelope.Error != nil {
		out.rpcError = envelope.Error.Message
	}
	if envelope.Result != nil {
		out.isError = envelope.Result.IsError
		for _, content := range envelope.Result.Content {
			out.text += content.Text
		}
	}
	return out
}

// callClientTool dispatches one tools/call on a client endpoint with the
// given lifted grants and _meta, as the transport would after lifting.
func callClientTool(t *testing.T, g *Gateway, slug, tool string, grants []callerGrant, meta map[string]any) callerGrantCallResult {
	t.Helper()
	g.mu.Lock()
	endpoint, ok := g.clientEndpoints[slug]
	g.mu.Unlock()
	if !ok {
		t.Fatalf("client endpoint %q has no server", slug)
	}
	params := map[string]any{"name": tool, "arguments": map[string]any{"query": "q-argument"}}
	if meta != nil {
		params["_meta"] = meta
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	ctx := context.Background()
	if grants != nil {
		ctx = withCallerGrants(ctx, grants)
	}
	out, err := json.Marshal(endpoint.mcp.HandleMessage(ctx, raw))
	if err != nil {
		t.Fatal(err)
	}
	return decodeCallerGrantCallResult(t, out)
}

// postClientToolCall sends initialize and then tools/call over Streamable
// HTTP to a client endpoint, with the given X-Synaxis-Caller-Grant lines on
// the tools/call only.
func postClientToolCall(t *testing.T, g *Gateway, slug, tool string, grantHeaders []string) callerGrantCallResult {
	t.Helper()
	handler, ok := g.MCPClientHandler(slug)
	if !ok {
		t.Fatalf("client endpoint %q is not live", slug)
	}
	return postToolCall(t, handler, "/mcp/clients/"+slug, tool, grantHeaders)
}

func postToolCall(t *testing.T, handler http.Handler, path, tool string, grantHeaders []string) callerGrantCallResult {
	t.Helper()
	post := func(body any, session string, headers []string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		for _, value := range headers {
			req.Header.Add(callerGrantHeader, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	init := post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": mcp.LATEST_PROTOCOL_VERSION, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "runner", "version": "1"},
	}}, "", nil)
	if init.Code != http.StatusOK {
		t.Fatalf("initialize = %d %s", init.Code, init.Body.String())
	}
	session := init.Header().Get("Mcp-Session-Id")
	w := post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": tool, "arguments": map[string]any{"query": "q-argument"},
		"_meta": map[string]any{callerGrantCallIDMetaKey: "toolu_01"},
	}}, session, grantHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("tools/call = %d %s", w.Code, w.Body.String())
	}
	body := w.Body.Bytes()
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(bytes.NewReader(body))
		for scanner.Scan() {
			if line := scanner.Text(); strings.HasPrefix(line, "data: ") {
				body = []byte(strings.TrimPrefix(line, "data: "))
			}
		}
	}
	return decodeCallerGrantCallResult(t, body)
}

func wantToolText(t *testing.T, got callerGrantCallResult, want string) {
	t.Helper()
	if got.rpcError != "" || got.isError || got.text != want {
		t.Fatalf("tool result = %+v; want success %q", got, want)
	}
}

func wantToolError(t *testing.T, got callerGrantCallResult, want string) {
	t.Helper()
	if got.rpcError != "" || !got.isError || got.text != want {
		t.Fatalf("tool result = %+v; want tool error %q", got, want)
	}
}

func setCallerGrantClock(t *testing.T, now time.Time) *time.Time {
	t.Helper()
	previous := callerGrantNow
	clock := now
	callerGrantNow = func() time.Time { return clock }
	t.Cleanup(func() { callerGrantNow = previous })
	return &clock
}

func TestCallerGrantHeaderReadOnlyForWorkloadClients(t *testing.T) {
	f := newCallerGrantFixture(t)
	ctx := context.Background()
	good := callerGrantHeaderValue(f.grant(t, f.workload))

	// A workload client's endpoint lifts the header and the call succeeds.
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{good}), "result from /hosted/h1/mcp")

	// Malformed lines are ignored one by one; the good line still works.
	malformed := []string{
		`resource="` + f.origin.resource() + `"`,                       // no grant
		`grant="` + f.grant(t, f.workload).compact + `"`,               // no resource
		`resource=` + f.origin.resource() + `, grant="a.b.c"`,          // unquoted
		`resource="` + f.origin.resource() + `", grant="not-a-jws"`,    // not compact JWS
		`resource="x", resource="y", grant="a.b.c"`,                    // duplicate
		`resource="` + f.origin.resource() + `", grant="a.b.c", x="y"`, // unknown parameter
		`resource="relative/path", grant="a.b.c"`,                      // not an absolute URL
	}
	for _, line := range malformed {
		if _, ok := parseCallerGrantHeader(line); ok {
			t.Fatalf("malformed header accepted: %s", line)
		}
		wantToolError(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{line}), callerGrantMissingRefusal)
	}
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", append(malformed[:3:3], good)), "result from /hosted/h1/mcp")

	// Each line is at most 4 KiB; a longer one is ignored.
	long := `resource="` + f.origin.resource() + `", grant="` + f.grant(t, f.workload).compact + strings.Repeat("A", maxCallerGrantHeaderBytes) + `"`
	wantToolError(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{long}), callerGrantMissingRefusal)
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{long, good}), "result from /hosted/h1/mcp")

	// At most four lines; a request with more carries none.
	four := []string{malformed[0], malformed[1], malformed[2], good}
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", four), "result from /hosted/h1/mcp")
	wantToolError(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", append(four, malformed[3])), callerGrantMissingRefusal)

	// The root /mcp (and every other non-client surface) never lifts it.
	probe := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(fmt.Sprintf("grants=%d", len(callerGrantsFrom(ctx)))), nil
	}
	root := server.NewMCPServer("root", "1", server.WithToolCapabilities(true))
	root.AddTool(mcp.NewTool("probe"), probe)
	wantToolText(t, postToolCall(t, NewStreamableMCPHandler(root, "/mcp"), "/mcp", "probe", []string{good}), "grants=0")
	wantToolText(t, postToolCall(t, newCallerGrantStreamableMCPHandler(root, "/mcp/clients/x"), "/mcp/clients/x", "probe", []string{good}), "grants=1")

	// An interactive client never reads it, even when its transport lifted it.
	interactive, err := f.store.CreateMCPClient(ctx, MCPClient{Name: "Desktop", Subject: "usr_owner", ConnectionIDs: []string{"plain"}})
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := f.store.Account("plain")
	seen := -1
	inner := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		seen = len(callerGrantsFrom(ctx))
		return mcp.NewToolResultText("ok"), nil
	}
	lifted := withCallerGrants(ctx, []callerGrant{f.grant(t, f.workload)})
	if _, err := f.gateway.clientAccountHandler(interactive.Slug, plain.Name, plain.IncarnationID, inner)(lifted, mcp.CallToolRequest{}); err != nil || seen != 0 {
		t.Fatalf("interactive client saw %d grants (err %v); want 0", seen, err)
	}
	if _, err := f.gateway.clientAccountHandler(f.workload.Slug, plain.Name, plain.IncarnationID, inner)(lifted, mcp.CallToolRequest{}); err != nil || seen != 1 {
		t.Fatalf("workload client saw %d grants (err %v); want 1", seen, err)
	}
}

func TestMemberCallerCarriesClientID(t *testing.T) {
	f := newCallerGrantFixture(t)
	plain, _ := f.store.Account("plain")
	var caller memberCaller
	inner := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		caller, _ = memberCallerFrom(ctx)
		return mcp.NewToolResultText("ok"), nil
	}
	if _, err := f.gateway.clientAccountHandler(f.workload.Slug, plain.Name, plain.IncarnationID, inner)(context.Background(), mcp.CallToolRequest{}); err != nil {
		t.Fatal(err)
	}
	want := memberCaller{subject: f.workload.Subject, workload: true, clientID: f.workload.ID}
	if caller != want {
		t.Fatalf("memberCaller = %+v; want %+v", caller, want)
	}
}

func TestCallerGrantRoutingClaims(t *testing.T) {
	f := newCallerGrantFixture(t)
	clock := setCallerGrantClock(t, time.Now())
	call := func(grants ...callerGrant) callerGrantCallResult {
		return callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", grants, nil)
	}
	with := func(edit func(map[string]any)) callerGrant {
		claims := f.claims(f.workload)
		edit(claims)
		return callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
	}

	// No grant, or only grants for other resources.
	wantToolError(t, call(), callerGrantMissingRefusal)
	other := f.grant(t, f.workload)
	other.resource = "https://elsewhere.example/mcp"
	wantToolError(t, call(other), callerGrantMissingRefusal)
	pathOnly := f.grant(t, f.workload)
	pathOnly.resource = f.origin.URL + "/hosted/h1/mcp" // the upstream URL is not the resource
	wantToolError(t, call(pathOnly), callerGrantMissingRefusal)

	// Each routing claim on its own refuses before any network call.
	mismatches := map[string]callerGrant{
		"client_id":        with(func(c map[string]any) { c["client_id"] = "client_other" }),
		"act.client":       with(func(c map[string]any) { c["act"] = map[string]any{"client": f.other.ID} }),
		"no act":           with(func(c map[string]any) { delete(c, "act") }),
		"exp now+5s":       with(func(c map[string]any) { c["exp"] = clock.Add(callerGrantMinRemaining).Unix() }),
		"exp past":         with(func(c map[string]any) { c["exp"] = clock.Add(-time.Minute).Unix() }),
		"resource claim":   with(func(c map[string]any) { c["resource"] = "https://elsewhere.example/mcp" }),
		"undecodable":      {resource: f.origin.resource(), compact: "aGVhZGVy.bm90LWpzb24.c2ln"},
		"exp not a number": with(func(c map[string]any) { c["exp"] = "soon" }),
		"exp quoted":       with(func(c map[string]any) { c["exp"] = fmt.Sprint(clock.Add(time.Hour).Unix()) }),
		"no exp":           with(func(c map[string]any) { delete(c, "exp") }),
		"no client_id":     with(func(c map[string]any) { delete(c, "client_id") }),
	}
	for name, grant := range mismatches {
		wantToolError(t, call(grant), callerGrantMismatchRefusal)
		if n := f.origin.exchangeCount(); n != 0 {
			t.Fatalf("%s: %d exchanges reached the token endpoint before routing refused", name, n)
		}
	}
	if calls := f.origin.delegatedToolCalls(); len(calls) != 0 {
		t.Fatalf("refused grants reached the upstream: %+v", calls)
	}

	// Resource selection lower-cases the scheme and host and ignores a
	// trailing slash; the first matching grant is used.
	upper := f.grant(t, f.workload)
	parsed, _ := url.Parse(upper.resource)
	upper.resource = "HTTP://" + strings.ToUpper(parsed.Host) + parsed.Path + "/"
	wantToolText(t, call(other, upper), "result from /hosted/h1/mcp")
	if got := f.origin.lastExchange().form.Get("resource"); got != f.origin.resource() {
		t.Fatalf("exchange resource = %q; want the account's %q", got, f.origin.resource())
	}

	// exp just past now+5s routes.
	wantToolText(t, call(with(func(c map[string]any) { c["exp"] = clock.Add(callerGrantMinRemaining + time.Second).Unix() })), "result from /hosted/h1/mcp")
}

func TestForgedGrantWithCachedJTIRefused(t *testing.T) {
	f := newCallerGrantFixture(t)
	clock := setCallerGrantClock(t, time.Now())
	real := f.grant(t, f.workload)
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{real}, nil), "result from /hosted/h1/mcp")
	if n := f.origin.exchangeCount(); n != 1 {
		t.Fatalf("exchanges = %d; want 1", n)
	}
	realToken := strings.TrimPrefix(f.origin.delegatedToolCalls()[0].authorization, "Bearer ")
	if key := callerGrantCacheKey(real.compact, f.workload.ID); key[:32] != string(func() []byte { s := sha256.Sum256([]byte(real.compact)); return s[:] }()) || key[32:] != f.workload.ID {
		t.Fatal("cache key is not SHA-256(compact grant) followed by the calling client ID")
	}
	if _, hit := f.gateway.callerGrants.lookup(callerGrantCacheKey(real.compact, f.workload.ID)); !hit {
		t.Fatal("the exchanged token was not cached under the grant hash and calling client")
	}

	// The same grant replayed by another workload client misses the cache
	// (another key) and fails routing (act.client) before any network call.
	wantToolError(t, callClientTool(t, f.gateway, f.other.Slug, "delegated__search", []callerGrant{real}, nil), callerGrantMismatchRefusal)

	// A forged grant reusing the real jti, naming the victim client, is
	// refused the same way when another client presents it.
	forgedClaims := f.claims(f.workload)
	forgedClaims["sub"] = "someone-else"
	forged := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, forgedClaims)}
	wantToolError(t, callClientTool(t, f.gateway, f.other.Slug, "delegated__search", []callerGrant{forged}, nil), callerGrantMismatchRefusal)
	if n := f.origin.exchangeCount(); n != 1 {
		t.Fatalf("a refused grant reached the token endpoint: %d exchanges", n)
	}

	// A forged grant that routes (it names the presenting client) misses the
	// cache, so it never receives the real grant's token: it must be
	// exchanged, and the authorization server refuses it.
	f.origin.setExchange(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"signature"}`))
	})
	routed := f.claims(f.other)
	routed["jti"] = f.claims(f.workload)["jti"]
	wantToolError(t, callClientTool(t, f.gateway, f.other.Slug, "delegated__search", []callerGrant{{resource: f.origin.resource(), compact: testCompactGrant(t, routed)}}, nil), callerGrantRefusedRefusal)
	if n := f.origin.exchangeCount(); n != 2 {
		t.Fatalf("exchanges = %d; want the forged grant exchanged (2)", n)
	}
	for _, call := range f.origin.delegatedToolCalls()[1:] {
		if strings.TrimPrefix(call.authorization, "Bearer ") == realToken {
			t.Fatal("another client reached the upstream with the real grant's cached token")
		}
	}

	// The checks run again on every cache hit: the real grant, still cached,
	// is refused once it is within 5 s of expiry, with no network call.
	f.origin.setExchange(nil)
	before := len(f.origin.delegatedToolCalls())
	*clock = clock.Add(time.Minute - callerGrantMinRemaining)
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{real}, nil), callerGrantMismatchRefusal)
	if n, calls := f.origin.exchangeCount(), len(f.origin.delegatedToolCalls()); n != 2 || calls != before {
		t.Fatalf("a refused cache hit reached the network: exchanges=%d calls=%d", n, calls)
	}
}

func TestCallIDMetaForwardedOnlyWhenValidAndOnlyToCallerDelegated(t *testing.T) {
	f := newCallerGrantFixture(t)
	grants := []callerGrant{f.grant(t, f.workload)}
	call := func(tool string, meta map[string]any) map[string]any {
		t.Helper()
		before := len(f.origin.toolsSeen())
		result := callClientTool(t, f.gateway, f.workload.Slug, tool, grants, meta)
		if result.isError || result.rpcError != "" {
			t.Fatalf("%s call failed: %+v", tool, result)
		}
		seen := f.origin.toolsSeen()
		if len(seen) != before+1 {
			t.Fatalf("%s did not reach its upstream", tool)
		}
		return seen[len(seen)-1].meta
	}
	valid := strings.Repeat("a", 61) + "_-Z"
	got := call("delegated__search", map[string]any{callerGrantCallIDMetaKey: valid, "other": "x", "progressToken": "p1"})
	if len(got) != 1 || got[callerGrantCallIDMetaKey] != valid {
		t.Fatalf("delegated upstream _meta = %v; want only the call ID", got)
	}
	for _, invalid := range []any{"", strings.Repeat("a", 65), "has space", "slash/id", "dot.id", 42, nil} {
		if got := call("delegated__search", map[string]any{callerGrantCallIDMetaKey: invalid}); len(got) != 0 {
			t.Fatalf("invalid call ID %#v forwarded as %v", invalid, got)
		}
	}
	if got := call("delegated__search", nil); len(got) != 0 {
		t.Fatalf("no call ID, yet _meta = %v", got)
	}
	// An ordinary account never receives it.
	if got := call("plain__search", map[string]any{callerGrantCallIDMetaKey: "toolu_01"}); len(got) != 0 {
		t.Fatalf("ordinary upstream _meta = %v; want none", got)
	}
}

func TestInteractiveClientCallerDelegatedToolRefused(t *testing.T) {
	f := newCallerGrantFixture(t)
	ctx := context.Background()
	f.gateway.mu.Lock()
	cached := append([]cachedTool(nil), f.gateway.cached["delegated"]...)
	f.gateway.mu.Unlock()
	if len(cached) != 1 {
		t.Fatalf("cached delegated tools = %d", len(cached))
	}
	grants := withCallerGrants(ctx, []callerGrant{f.grant(t, f.workload)})
	for name, callCtx := range map[string]context.Context{
		"interactive client":         withMemberCaller(grants, memberCaller{subject: "usr_owner", clientID: "mcl_desktop"}),
		"no caller (root)":           grants,
		"workload without client ID": withMemberCaller(grants, memberCaller{subject: f.workload.Subject, workload: true}),
	} {
		res, err := cached[0].handler(callCtx, mcp.CallToolRequest{})
		if err != nil || res == nil || !res.IsError || len(res.Content) != 1 {
			t.Fatalf("%s: result=%+v err=%v", name, res, err)
		}
		if text := res.Content[0].(mcp.TextContent).Text; text != callerGrantInteractiveRefusal {
			t.Fatalf("%s: %q; want %q", name, text, callerGrantInteractiveRefusal)
		}
	}
	if n := f.origin.exchangeCount(); n != 0 {
		t.Fatalf("an interactive call reached the token endpoint (%d)", n)
	}
	if calls := f.origin.delegatedToolCalls(); len(calls) != 0 {
		t.Fatalf("an interactive call reached the upstream: %+v", calls)
	}
}

func TestCallerDelegatedRevisionChurnYieldsConnectionChangedOnce(t *testing.T) {
	f := newCallerGrantFixture(t)
	ctx := context.Background()
	grants := []callerGrant{f.grant(t, f.workload)}
	before, _ := f.store.Account("delegated")
	// The listing credential is re-PUT while the call is between its
	// exchange and its upstream dial, exactly as PUT
	// /control/v1/connections/{name}/token does it: a revision-fenced store
	// write, then a synchronous re-aggregation.
	var once sync.Once
	f.origin.mu.Lock()
	f.origin.onExchange = func() {
		once.Do(func() {
			current, _ := f.store.Account("delegated")
			if _, err := f.store.SetBearerToken(ctx, current.Name, current.IncarnationID, "listing-key-2", current.Revision); err != nil {
				t.Errorf("re-PUT token: %v", err)
			}
			if _, err := f.gateway.ReplaceAccount(ctx, current.Name); err != nil {
				t.Errorf("re-aggregate: %v", err)
			}
		})
	}
	f.origin.mu.Unlock()
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", grants, nil), callerGrantConnectionChanged)
	if calls := f.origin.delegatedToolCalls(); len(calls) != 0 {
		t.Fatalf("a call on a changed connection reached the upstream: %+v", calls)
	}
	if after, _ := f.store.Account("delegated"); after.Revision != before.Revision+1 {
		t.Fatalf("revision %d -> %d; want one bump", before.Revision, after.Revision)
	}
	// The single retry after the re-aggregation succeeds, reusing the token
	// exchanged for the same grant.
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", grants, nil), "result from /hosted/h1/mcp")
	if n := f.origin.exchangeCount(); n != 1 {
		t.Fatalf("exchanges = %d; want the cached token reused (1)", n)
	}
}
