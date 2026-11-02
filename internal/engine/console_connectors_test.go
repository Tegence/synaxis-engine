package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// newConnectorConsole builds the full stack the connector endpoints sit on:
// FileStore (AccountStore + ConnectorStore) → Gateway (listTools seam, same
// as gateway_connectors_test.go) → ConsoleAPI mux, plus a bearer minted the
// same way handleLogin does (signToken).
func newConnectorConsole(t *testing.T, tools map[string][]string) (*http.ServeMux, string, *Gateway) {
	t.Helper()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	for name := range tools {
		if err := fs.Upsert(context.Background(), Account{Name: name, URL: "http://unused", AuthMode: "token", BearerToken: "t"}); err != nil {
			t.Fatalf("upsert account: %v", err)
		}
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		var out []mcp.Tool
		for _, bare := range tools[a.Name] {
			out = append(out, mcp.NewTool(a.Name+"__"+bare, mcp.WithDescription("test tool "+bare)))
		}
		return out, nil
	}
	g.Aggregate(context.Background())

	api := NewConsoleAPI(fs, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), g
}

func doJSON(t *testing.T, mux *http.ServeMux, token, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	if b := rec.Body.Bytes(); len(b) > 0 && b[0] == '{' {
		_ = json.Unmarshal(b, &out)
	}
	return rec, out
}

func TestConnectorAPICRUDHappyPath(t *testing.T) {
	mux, tok, g := newConnectorConsole(t, map[string][]string{
		"linear": {"get_issue", "save_issue"},
		"notion": {"search", "fetch"},
	})

	// CREATE: slug defaults to slugify(label).
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Work Stuff","tools":{"linear":["get_issue"],"notion":["search"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, body %s", rec.Code, rec.Body)
	}
	if got["slug"] != "work_stuff" || got["label"] != "Work Stuff" {
		t.Fatalf("created DTO = %v", got)
	}
	if got["url"] != "https://engine.example/mcp/work_stuff" {
		t.Fatalf("url = %v", got["url"])
	}
	if got["exposedTools"] != float64(2) || got["totalTools"] != float64(4) {
		t.Fatalf("stats = %v/%v, want 2/4", got["exposedTools"], got["totalTools"])
	}
	if eb, tb := got["exposedBytes"].(float64), got["totalBytes"].(float64); eb <= 0 || tb <= eb {
		t.Fatalf("bytes = %v/%v, want 0 < exposed < total", eb, tb)
	}
	// Live server exists (gateway path, not store-only write).
	if _, ok := g.ConnectorHandler("work_stuff"); !ok {
		t.Fatal("POST did not build the live /mcp/{slug} server")
	}

	// LIST
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/connectors", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}

	// UPDATE label only — tools untouched.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/work_stuff", `{"label":"Work"}`)
	if rec.Code != http.StatusOK || got["label"] != "Work" {
		t.Fatalf("PUT label = %d %v", rec.Code, got)
	}
	if got["exposedTools"] != float64(2) {
		t.Fatalf("tools changed on label-only update: %v", got)
	}

	// UPDATE tools — connector narrows live.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/work_stuff", `{"tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusOK || got["exposedTools"] != float64(1) {
		t.Fatalf("PUT tools = %d %v", rec.Code, got)
	}

	// DELETE
	rec, _ = doJSON(t, mux, tok, http.MethodDelete, "/api/connectors/work_stuff", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if _, ok := g.ConnectorHandler("work_stuff"); ok {
		t.Fatal("live server survived DELETE")
	}
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/connectors", "")
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("list after delete = %s", rec.Body)
	}
}

func TestConnectorAPIValidation(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{"linear": {"get_issue"}})

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"missing label", http.MethodPost, "/api/connectors", `{"tools":{}}`, http.StatusBadRequest},
		{"blank label", http.MethodPost, "/api/connectors", `{"label":"   "}`, http.StatusBadRequest},
		{"unslugifiable label", http.MethodPost, "/api/connectors", `{"label":"!!!"}`, http.StatusBadRequest},
		{"unknown account", http.MethodPost, "/api/connectors", `{"label":"X","tools":{"ghost":["t"]}}`, http.StatusBadRequest},
		{"bad json", http.MethodPost, "/api/connectors", `{`, http.StatusBadRequest},
		{"put unknown slug", http.MethodPut, "/api/connectors/nope", `{"label":"X"}`, http.StatusNotFound},
		{"delete unknown slug", http.MethodDelete, "/api/connectors/nope", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		rec, _ := doJSON(t, mux, tok, tc.method, tc.path, tc.body)
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (body %s)", tc.name, rec.Code, tc.want, rec.Body)
		}
	}

	// Duplicate slug → 409 (explicit slug wins over label-derived one).
	rec, _ := doJSON(t, mux, tok, http.MethodPost, "/api/connectors", `{"label":"A","slug":"dup","tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed POST = %d", rec.Code)
	}
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors", `{"label":"Other","slug":"dup"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dup POST = %d %v", rec.Code, got)
	}

	// PUT with empty label or unknown account rejected.
	rec, _ = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/dup", `{"label":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT empty label = %d", rec.Code)
	}
	rec, _ = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/dup", `{"tools":{"ghost":["t"]}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT unknown account = %d", rec.Code)
	}

	// No/invalid bearer → 401 (sec() wrapper applies).
	rec, _ = doJSON(t, mux, "", http.MethodGet, "/api/connectors", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d", rec.Code)
	}
}

// accountsOnly hides FileStore's ConnectorStore facet: only the embedded
// AccountStore interface methods are promoted, so the type assertion in
// NewConsoleAPI fails and connector endpoints must 501.
type accountsOnly struct{ AccountStore }

func TestConnectorAPI501WithoutConnectorStore(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	g := NewGateway(accountsOnly{fs}, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	api := NewConsoleAPI(accountsOnly{fs}, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	tok := api.signToken()

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/api/connectors"},
		{http.MethodPost, "/api/connectors"},
		{http.MethodPut, "/api/connectors/x"},
		{http.MethodDelete, "/api/connectors/x"},
	} {
		rec, got := doJSON(t, mux, tok, req.method, req.path, `{}`)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501", req.method, req.path, rec.Code)
		}
		if got["error"] != "connectors not supported by this store" {
			t.Errorf("%s %s error = %v", req.method, req.path, got["error"])
		}
	}
}

// TestConnectorAPIGuardrails: maxResultBytes + redact round-trip through
// create/update, defaults are explicit (0 / []), and PUT touches only what
// the request names.
func TestConnectorAPIGuardrails(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{"linear": {"get_issue"}})

	// Defaults: guard fields are always present in the DTO, never null.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Plain","tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST plain = %d, body %s", rec.Code, rec.Body)
	}
	if got["maxResultBytes"] != float64(0) {
		t.Fatalf("default maxResultBytes = %v, want 0", got["maxResultBytes"])
	}
	if rd, ok := got["redact"].([]any); !ok || len(rd) != 0 {
		t.Fatalf("default redact = %v (%T), want []", got["redact"], got["redact"])
	}

	// CREATE with guards → round-trip in the created DTO.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Guarded","tools":{"linear":["get_issue"]},"maxResultBytes":4096,"redact":["(?i)secret-\\d+","token"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST guarded = %d, body %s", rec.Code, rec.Body)
	}
	if got["maxResultBytes"] != float64(4096) {
		t.Fatalf("created maxResultBytes = %v, want 4096", got["maxResultBytes"])
	}
	rd, _ := got["redact"].([]any)
	if len(rd) != 2 || rd[0] != `(?i)secret-\d+` || rd[1] != "token" {
		t.Fatalf("created redact = %v", got["redact"])
	}

	// LIST round-trip: values persisted, not just echoed.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/connectors", "")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	for _, row := range list {
		if row["slug"] != "guarded" {
			continue
		}
		if row["maxResultBytes"] != float64(4096) {
			t.Fatalf("listed maxResultBytes = %v", row["maxResultBytes"])
		}
		if lrd, _ := row["redact"].([]any); len(lrd) != 2 {
			t.Fatalf("listed redact = %v", row["redact"])
		}
	}

	// PUT maxResultBytes only — redact untouched.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/guarded", `{"maxResultBytes":1024}`)
	if rec.Code != http.StatusOK || got["maxResultBytes"] != float64(1024) {
		t.Fatalf("PUT cap = %d %v", rec.Code, got)
	}
	if rd, _ := got["redact"].([]any); len(rd) != 2 {
		t.Fatalf("PUT cap clobbered redact: %v", got["redact"])
	}

	// PUT redact only — cap untouched; empty list clears.
	rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/guarded", `{"redact":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT redact = %d, body %s", rec.Code, rec.Body)
	}
	if rd, ok := got["redact"].([]any); !ok || len(rd) != 0 {
		t.Fatalf("cleared redact = %v (%T)", got["redact"], got["redact"])
	}
	if got["maxResultBytes"] != float64(1024) {
		t.Fatalf("PUT redact clobbered cap: %v", got["maxResultBytes"])
	}
}

// TestConnectorAPIGuardrailValidation: negative/absurd caps and uncompilable
// redact patterns 400 on both POST and PUT, and a rejected PUT leaves the
// stored connector unchanged.
func TestConnectorAPIGuardrailValidation(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{"linear": {"get_issue"}})

	rec, _ := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Base","slug":"base","tools":{"linear":["get_issue"]},"maxResultBytes":2048,"redact":["ok-pattern"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed POST = %d, body %s", rec.Code, rec.Body)
	}

	cases := []struct {
		name, method, path, body, wantErr string
	}{
		{"post negative cap", http.MethodPost, "/api/connectors", `{"label":"X1","tools":{},"maxResultBytes":-1}`, "maxResultBytes must be >= 0"},
		{"post absurd cap", http.MethodPost, "/api/connectors", `{"label":"X2","tools":{},"maxResultBytes":10485761}`, "maxResultBytes must be <="},
		{"post bad regex", http.MethodPost, "/api/connectors", `{"label":"X3","tools":{},"redact":["[unclosed"]}`, "invalid redact pattern"},
		{"put negative cap", http.MethodPut, "/api/connectors/base", `{"maxResultBytes":-5}`, "maxResultBytes must be >= 0"},
		{"put absurd cap", http.MethodPut, "/api/connectors/base", `{"maxResultBytes":99999999}`, "maxResultBytes must be <="},
		{"put bad regex", http.MethodPut, "/api/connectors/base", `{"redact":["good","a(b"]}`, "invalid redact pattern"},
	}
	for _, tc := range cases {
		rec, got := doJSON(t, mux, tok, tc.method, tc.path, tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400 (body %s)", tc.name, rec.Code, rec.Body)
			continue
		}
		msg, _ := got["error"].(string)
		if !strings.Contains(msg, tc.wantErr) {
			t.Errorf("%s: error %q, want it to contain %q", tc.name, msg, tc.wantErr)
		}
	}

	// The bad-regex 400 names the offending pattern.
	rec, got := doJSON(t, mux, tok, http.MethodPut, "/api/connectors/base", `{"redact":["[unclosed"]}`)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || !strings.Contains(msg, "[unclosed") {
		t.Fatalf("bad-regex error must name the pattern: %d %v", rec.Code, got)
	}

	// Rejected PUTs left the stored connector untouched.
	rec, _ = doJSON(t, mux, tok, http.MethodGet, "/api/connectors", "")
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %s (err %v)", rec.Body, err)
	}
	if list[0]["maxResultBytes"] != float64(2048) {
		t.Fatalf("rejected PUT mutated cap: %v", list[0]["maxResultBytes"])
	}
	if rd, _ := list[0]["redact"].([]any); len(rd) != 1 || rd[0] != "ok-pattern" {
		t.Fatalf("rejected PUT mutated redact: %v", list[0]["redact"])
	}
}

func TestReservedEndpointSlugRejected(t *testing.T) {
	mux, tok, _ := newConnectorConsole(t, map[string][]string{
		"linear": {"get_issue"},
	})

	// Connector: explicit slug, and a label that slugifies to the reserved word.
	rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"slug":"clients","label":"Clients","tools":{"linear":["get_issue"]}}`)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || msg != "that slug is reserved" {
		t.Fatalf("connector with reserved slug = %d %v, want 400 reserved", rec.Code, got)
	}
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"label":"Clients","tools":{"linear":["get_issue"]}}`)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || msg != "that slug is reserved" {
		t.Fatalf("connector with label-derived reserved slug = %d %v, want 400 reserved", rec.Code, got)
	}

	// Endpoint bundle: same reservation.
	rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/endpoints",
		`{"slug":"clients","label":"Clients","members":["linear"]}`)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || msg != "that slug is reserved" {
		t.Fatalf("endpoint bundle with reserved slug = %d %v, want 400 reserved", rec.Code, got)
	}

	// A neighboring slug is unaffected.
	rec, _ = doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
		`{"slug":"client_tools","label":"Client Tools","tools":{"linear":["get_issue"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("non-reserved slug = %d, body %s", rec.Code, rec.Body)
	}
}

// expectToolListingError asserts the console's tool-listing failure
// contract: exactly {"error","code","recovery"}, the given status, and no
// provider text.
func expectToolListingError(t *testing.T, rec *httptest.ResponseRecorder, got map[string]any, status int, code, recovery string, leaks ...string) {
	t.Helper()
	if rec.Code != status || got["code"] != code || got["recovery"] != recovery {
		t.Fatalf("listing failure = %d %s, want %d code=%s recovery=%s", rec.Code, rec.Body, status, code, recovery)
	}
	if message, _ := got["error"].(string); message == "" || len(got) != 3 {
		t.Fatalf("listing failure body = %s, want exactly error/code/recovery", rec.Body)
	}
	for _, leak := range leaks {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("listing failure leaked %q: %s", leak, rec.Body)
		}
	}
}

func TestToolsRouteAnswersListingFailuresWithARecoveryContract(t *testing.T) {
	const secret = "provider-secret-do-not-return"
	for _, tc := range []struct {
		name     string
		fail     func(context.Context) error
		status   int
		code     string
		recovery string
	}{
		{"expired credential", func(context.Context) error {
			return fmt.Errorf("%w: %s", transport.ErrAuthorizationRequired, secret)
		}, http.StatusConflict, healthStatusAuthExpired, healthRecoveryReauthorize},
		{"revoked refresh grant", func(context.Context) error {
			// The production leak: the provider's raw OAuth error body.
			return errors.New(`notion: refresh failed: refresh -> 400: {"error":"invalid_grant","error_description":"` + secret + `"}`)
		}, http.StatusConflict, healthStatusAuthExpired, healthRecoveryReauthorize},
		{"timeout", func(ctx context.Context) error {
			<-ctx.Done()
			return fmt.Errorf("list tools: %s: %w", secret, ctx.Err())
		}, http.StatusGatewayTimeout, healthStatusTimeout, healthRecoveryRetry},
		{"provider failure", func(context.Context) error {
			return errors.New("provider host failed: " + secret)
		}, http.StatusBadGateway, healthStatusUnreachable, healthRecoveryRetry},
		{"connection changed", func(context.Context) error {
			return fmt.Errorf("%s: %w", secret, ErrAccountIncarnation)
		}, http.StatusBadGateway, toolListingStatusError, healthRecoveryRetry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, token, g := newConnectorConsole(t, map[string][]string{"notion": {"search"}})
			g.accountToolsTimeout = 30 * time.Millisecond
			g.listTools = func(ctx context.Context, _ Account) ([]mcp.Tool, error) { return nil, tc.fail(ctx) }
			rec, got := doJSON(t, mux, token, http.MethodGet, "/api/servers/notion/tools", "")
			expectToolListingError(t, rec, got, tc.status, tc.code, tc.recovery, secret, "invalid_grant")
		})
	}
}

// TestToolsRoutesNeverDialAnUnauthorizedAccount: an OAuth account nobody has
// connected cannot list tools; every tool route says so without a dial.
func TestToolsRoutesNeverDialAnUnauthorizedAccount(t *testing.T) {
	mux, token, g := newConnectorConsole(t, nil)
	if err := g.store.Upsert(context.Background(), Account{Name: "figma", URL: "https://figma.example/mcp", AuthMode: "oauth"}); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	g.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/servers/figma/tools", ""},
		{http.MethodPut, "/api/servers/figma/tools", `{"disabled":["export"]}`},
		{http.MethodPut, "/api/servers/figma/tools/export", `{"enabled":false}`},
	} {
		rec, got := doJSON(t, mux, token, req.method, req.path, req.body)
		expectToolListingError(t, rec, got, http.StatusConflict, healthStatusNeedsAuth, healthRecoveryConnect)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("a never-authorized account was dialed %d times", got)
	}
}

// TestToolsRouteSkipsTheDialForARecordedAuthFailure: once a probe recorded
// that the exact current credentials are refused, listing tools answers from
// that without dialing; new credentials dial again.
func TestToolsRouteSkipsTheDialForARecordedAuthFailure(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{"notion": {"search"}})
	var dials atomic.Int32
	var revoked atomic.Bool
	revoked.Store(true)
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		dials.Add(1)
		if revoked.Load() {
			return nil, transport.ErrAuthorizationRequired
		}
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}

	rec, _ := doJSONWithHeaders(t, mux, token, http.MethodGet, "/api/health", "", map[string]string{healthRefreshHeader: "1"})
	if rec.Code != http.StatusOK || dials.Load() != 1 {
		t.Fatalf("probe-now = %d after %d dials", rec.Code, dials.Load())
	}
	rec, got := doJSON(t, mux, token, http.MethodGet, "/api/servers/notion/tools", "")
	expectToolListingError(t, rec, got, http.StatusConflict, healthStatusAuthExpired, healthRecoveryReauthorize)
	if got := dials.Load(); got != 1 {
		t.Fatalf("listing tools for refused credentials dialed %d more times", got-1)
	}

	revoked.Store(false)
	if rec, _ := doJSON(t, mux, token, http.MethodPut, "/api/servers/notion/token", `{"token":"replacement"}`); rec.Code != http.StatusOK {
		t.Fatalf("replace token = %d %s", rec.Code, rec.Body)
	}
	before := dials.Load()
	if rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/servers/notion/tools", ""); rec.Code != http.StatusOK || dials.Load() != before+1 {
		t.Fatalf("tools after new credentials = %d %s after %d dials", rec.Code, rec.Body, dials.Load()-before)
	}
	// The successful listing is recorded as the account's health.
	rec, _ = doJSON(t, mux, token, http.MethodGet, "/api/health", "")
	var rows []AccountHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0].Status != healthStatusOK || dials.Load() != before+1 {
		t.Fatalf("health after the listing = %s (err %v) after %d dials", rec.Body, err, dials.Load()-before)
	}
}

// TestBulkToolsPutReportsAListingFailure: a curation save whose live refresh
// fails answers with the listing contract (it used to answer 200 null).
func TestBulkToolsPutReportsAListingFailure(t *testing.T) {
	const secret = "provider-secret-do-not-return"
	mux, token, g := newConnectorConsole(t, map[string][]string{"notion": {"search", "fetch"}})
	working := g.listTools
	g.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		return nil, errors.New("provider host failed: " + secret)
	}

	rec, got := doJSON(t, mux, token, http.MethodPut, "/api/servers/notion/tools", `{"disabled":["fetch"]}`)
	expectToolListingError(t, rec, got, http.StatusBadGateway, healthStatusUnreachable, healthRecoveryRetry, secret)
	if message, _ := got["error"].(string); !strings.HasPrefix(message, toolPolicySavedNotLive) {
		t.Fatalf("error = %q, want it to say the policy was saved", message)
	}
	if account, _ := g.store.Account("notion"); len(account.DisabledTools) != 1 || account.DisabledTools[0] != "fetch" {
		t.Fatalf("curation was not saved: %v", account.DisabledTools)
	}

	// Once the provider answers, the response shape is the plain tool list.
	g.listTools = working
	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/servers/notion/tools", `{"disabled":["fetch"]}`)
	var tools []ToolInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tools) != nil || len(tools) != 2 {
		t.Fatalf("PUT tools = %d %s, want the two-tool list", rec.Code, rec.Body)
	}
}

// statsCountingStore counts the per-item store reads endpoint stats used to
// make: an account lookup per cached account, and a connector or bundle
// lookup, for every endpoint listed.
type statsCountingStore struct {
	*FileStore
	accountReads    atomic.Int32
	accountListings atomic.Int32
	connectorReads  atomic.Int32
	namespaceReads  atomic.Int32
}

func (s *statsCountingStore) Account(name string) (Account, bool) {
	s.accountReads.Add(1)
	return s.FileStore.Account(name)
}

func (s *statsCountingStore) Accounts() []Account {
	s.accountListings.Add(1)
	return s.FileStore.Accounts()
}

func (s *statsCountingStore) VirtualConnector(ctx context.Context, slug string) (VirtualConnector, bool) {
	s.connectorReads.Add(1)
	return s.FileStore.VirtualConnector(ctx, slug)
}

func (s *statsCountingStore) Namespace(ctx context.Context, slug string) (Namespace, bool) {
	s.namespaceReads.Add(1)
	return s.FileStore.Namespace(ctx, slug)
}

// legacyEndpointStats is the per-endpoint computation the list routes used to
// run — an account read per cached account and a marshal per tool — kept as
// the reference the batched stats must reproduce exactly.
func legacyEndpointStats(g *Gateway, store AccountStore, exposed func(account, sourceName string) bool) ConnectorStats {
	g.mu.Lock()
	cached := make(map[string][]cachedTool, len(g.cached))
	for account, tools := range g.cached {
		cached[account] = tools
	}
	g.mu.Unlock()
	var st ConnectorStats
	for account, tools := range cached {
		if stored, found := store.Account(account); !found || stored.IsPersonal() {
			continue
		}
		for _, ct := range tools {
			b, err := json.Marshal(ct.tool)
			if err != nil {
				continue
			}
			st.TotalTools++
			st.TotalBytes += len(b)
			if exposed(account, ct.sourceName) {
				st.ExposedTools++
				st.ExposedBytes += len(b)
			}
		}
	}
	return st
}

func TestEndpointListsComputeStatsFromOneSnapshot(t *testing.T) {
	ctx := context.Background()
	base, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string][]string{
		"linear":  {"get_issue", "save_issue", "list_issues"},
		"notion":  {"search", "fetch"},
		"github":  {"get_repo"},
		"private": {"read_mail"},
	}
	for name := range tools {
		account := Account{Name: name, URL: "https://" + name + ".example/mcp", AuthMode: "token", BearerToken: "t"}
		if name == "private" {
			account.ConnectionScope, account.OwnerSubject = ConnectionScopePersonal, "usr_alice"
		}
		if err := base.Upsert(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	store := &statsCountingStore{FileStore: base}
	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		var out []mcp.Tool
		for _, bare := range tools[a.Name] {
			out = append(out, mcp.NewTool(a.Name+"__"+bare, mcp.WithDescription("test tool "+bare)))
		}
		return out, nil
	}
	g.Aggregate(ctx)
	for _, vc := range []VirtualConnector{
		{Slug: "triage", Label: "Triage", Tools: map[string][]string{"linear": {"get_issue", "list_issues"}, "notion": {"search"}}},
		{Slug: "writer", Label: "Writer", Tools: map[string][]string{"linear": {"save_issue"}}},
		{Slug: "empty", Label: "Empty", Tools: map[string][]string{}},
	} {
		if err := g.UpsertConnector(ctx, vc); err != nil {
			t.Fatal(err)
		}
	}
	for _, ns := range []Namespace{
		{Slug: "work", Label: "Work", Accounts: []string{"linear", "github"}},
		{Slug: "docs", Label: "Docs", Accounts: []string{"notion"}},
	} {
		if _, err := g.CreateNamespace(ctx, ns); err != nil {
			t.Fatal(err)
		}
	}
	api := NewConsoleAPI(store, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	token := api.signToken()

	resetCounts := func() {
		store.accountReads.Store(0)
		store.accountListings.Store(0)
		store.connectorReads.Store(0)
		store.namespaceReads.Store(0)
	}
	expectOneSnapshot := func(route string) {
		t.Helper()
		if reads := store.accountReads.Load() + store.connectorReads.Load() + store.namespaceReads.Load(); reads != 0 || store.accountListings.Load() != 1 {
			t.Fatalf("GET %s made %d per-item reads and %d account listings, want none and one", route, reads, store.accountListings.Load())
		}
	}

	resetCounts()
	rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/connectors", "")
	expectOneSnapshot("/api/connectors")
	var connectors []connectorDTO
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &connectors) != nil || len(connectors) != 3 {
		t.Fatalf("GET /api/connectors = %d %s", rec.Code, rec.Body)
	}
	for i, dto := range connectors {
		vc, _ := base.VirtualConnector(ctx, dto.Slug)
		allow := map[string]map[string]bool{}
		for account, names := range vc.Tools {
			allow[account] = toSet(names)
		}
		want := legacyEndpointStats(g, base, func(account, sourceName string) bool { return allow[account][sourceName] })
		connectors[i].ExposedTools, connectors[i].TotalTools = want.ExposedTools, want.TotalTools
		connectors[i].ExposedBytes, connectors[i].TotalBytes = want.ExposedBytes, want.TotalBytes
	}
	var wantBody bytes.Buffer
	if err := json.NewEncoder(&wantBody).Encode(connectors); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Body.Bytes(), wantBody.Bytes()) {
		t.Fatalf("connector list differs from the per-item computation:\n got: %s\nwant: %s", rec.Body, wantBody.String())
	}

	resetCounts()
	rec, _ = doJSON(t, mux, token, http.MethodGet, "/api/endpoints", "")
	expectOneSnapshot("/api/endpoints")
	var bundles []namespaceDTO
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &bundles) != nil || len(bundles) != 2 {
		t.Fatalf("GET /api/endpoints = %d %s", rec.Code, rec.Body)
	}
	for i, dto := range bundles {
		members := toSet(dto.Members)
		want := legacyEndpointStats(g, base, func(account, _ string) bool { return members[account] })
		bundles[i].ExposedTools, bundles[i].TotalTools = want.ExposedTools, want.TotalTools
	}
	wantBody.Reset()
	if err := json.NewEncoder(&wantBody).Encode(bundles); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Body.Bytes(), wantBody.Bytes()) {
		t.Fatalf("endpoint list differs from the per-item computation:\n got: %s\nwant: %s", rec.Body, wantBody.String())
	}
}
