package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"narthex/backend/internal/oauthas"
	"narthex/backend/internal/upstreamoauth"
)

// existingSession is a well-formed session ID from an earlier initialize.
const existingSession = "mcp-session-6f1c2d3e-4b5a-4c6d-8e7f-001122334455"

// These tests pin the Engine behaviours that used to drop or confuse
// connected agents: per-request tool-list churn, database blips answered as
// "not found", startup projections lost to slow upstreams, and listening
// streams cut by the host's request timeout.

// recordingSession is an initialized MCP session that keeps every
// notification the server sends it.
type recordingSession struct {
	id            string
	notifications chan mcp.JSONRPCNotification
}

func newRecordingSession() *recordingSession {
	return &recordingSession{id: "recording", notifications: make(chan mcp.JSONRPCNotification, 1000)}
}

func (s *recordingSession) Initialize()       {}
func (s *recordingSession) Initialized() bool { return true }
func (s *recordingSession) SessionID() string { return s.id }
func (s *recordingSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return s.notifications
}

func (s *recordingSession) listChanged() int {
	count := 0
	for {
		select {
		case n := <-s.notifications:
			if n.Method == mcp.MethodNotificationToolsListChanged {
				count++
			}
		default:
			return count
		}
	}
}

// flakyStore fails its error-reporting reads on demand, as PgStore does when
// a pool acquire times out or Cloud SQL drops a connection.
type flakyStore struct {
	*FileStore
	failLookup   atomic.Bool
	failAccounts atomic.Bool
	expiredCtx   atomic.Bool // fail ctx-taking reads whose ctx is done, like pgx
}

var errFlakyRead = errors.New("connection reset by peer")

func (s *flakyStore) LookupActiveMCPClient(ctx context.Context, slug string) (MCPClient, bool, error) {
	if s.failLookup.Load() {
		return MCPClient{}, false, errFlakyRead
	}
	return s.FileStore.LookupActiveMCPClient(ctx, slug)
}

func (s *flakyStore) ListAccounts(ctx context.Context) ([]Account, error) {
	if s.failAccounts.Load() {
		return nil, errFlakyRead
	}
	if s.expiredCtx.Load() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FileStore.ListAccounts(ctx)
}

func (s *flakyStore) Connectors(ctx context.Context) ([]VirtualConnector, error) {
	if s.expiredCtx.Load() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FileStore.Connectors(ctx)
}

func (s *flakyStore) ActiveMCPClients(ctx context.Context) ([]MCPClient, error) {
	if s.expiredCtx.Load() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FileStore.ActiveMCPClients(ctx)
}

// newResilienceGateway builds a gateway with one shared account, team_notion,
// granted to one interactive client endpoint.
func newResilienceGateway(t *testing.T) (*flakyStore, *Gateway, MCPClient) {
	t.Helper()
	ctx := context.Background()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &flakyStore{FileStore: fs}
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(_ context.Context, account Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}
	shared, err := fs.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Shared", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Create(ctx, Account{Name: "team_notion", ConnectionNamespaceID: shared.ID, ConnectionScope: ConnectionScopeShared, URL: "https://team.example/mcp", AuthMode: "token", BearerToken: "team"}); err != nil {
		t.Fatal(err)
	}
	client, err := fs.CreateMCPClient(ctx, MCPClient{Name: "Codex", Subject: "usr_alice", CreatedBy: "usr_alice", ConnectionNamespaceIDs: []string{shared.ID}})
	if err != nil {
		t.Fatal(err)
	}
	gateway.Aggregate(ctx)
	if _, live := gateway.MCPClientEpoch(client.Slug); !live {
		t.Fatal("client endpoint was not projected")
	}
	return store, gateway, client
}

func ageClientProjection(gateway *Gateway, slug string) {
	gateway.mu.Lock()
	gateway.clientEndpoints[slug].refreshedAt = time.Now().Add(-2 * mcpClientProjectionTTL)
	gateway.mu.Unlock()
}

// toolsListOver sends tools/list on an existing session through the client
// endpoint handler, exactly as an agent's next call after idle would.
func toolsListOver(t *testing.T, gateway *Gateway, slug string) (int, string) {
	t.Helper()
	handler, ok := gateway.MCPClientHandler(slug)
	if !ok {
		t.Fatalf("client endpoint %q has no handler", slug)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp/clients/"+slug, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Session-Id", existingSession)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code, response.Body.String()
}

func TestClientEndpointRebuildIsSilentUnlessItsToolsChange(t *testing.T) {
	ctx := context.Background()
	store, gateway, client := newResilienceGateway(t)
	gateway.mu.Lock()
	endpoint := gateway.clientEndpoints[client.Slug].mcp
	gateway.mu.Unlock()
	session := newRecordingSession()
	if err := endpoint.RegisterSession(ctx, session); err != nil {
		t.Fatal(err)
	}

	// The 5s TTL rebuilds on nearly every agent turn. Unchanged, it used to
	// send one list_changed per tool (DeleteTools + AddTool each) every time.
	for i := 0; i < 3; i++ {
		ageClientProjection(gateway, client.Slug)
		if status, body := toolsListOver(t, gateway, client.Slug); status != http.StatusOK || !strings.Contains(body, "team_notion__search") {
			t.Fatalf("tools/list after rebuild = %d %s", status, body)
		}
	}
	if got := session.listChanged(); got != 0 {
		t.Fatalf("unchanged rebuilds sent %d tools/list_changed, want 0", got)
	}

	// A real change is one atomic replacement and one notification.
	shared := client.ConnectionNamespaceIDs[0]
	if err := store.Create(ctx, Account{Name: "team_linear", ConnectionNamespaceID: shared, ConnectionScope: ConnectionScopeShared, URL: "https://linear.example/mcp", AuthMode: "token", BearerToken: "linear"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.AddAccount(ctx, "team_linear"); err != nil {
		t.Fatal(err)
	}
	if got := session.listChanged(); got != 1 {
		t.Fatalf("adding one account sent %d tools/list_changed, want 1", got)
	}
	if endpoint.GetTool("team_linear__search") == nil || endpoint.GetTool("team_notion__search") == nil {
		t.Fatal("client endpoint lost or missed tools across the change")
	}
}

func TestClientEndpointKeepsServingThroughADatabaseBlip(t *testing.T) {
	store, gateway, client := newResilienceGateway(t)
	resource := "/mcp/clients/" + client.Slug

	// A failed lookup during the TTL rebuild used to answer 404, which
	// Streamable HTTP clients read as "session terminated".
	store.failLookup.Store(true)
	ageClientProjection(gateway, client.Slug)
	if status, body := toolsListOver(t, gateway, client.Slug); status != http.StatusOK || !strings.Contains(body, "team_notion__search") {
		t.Fatalf("tools/list during lookup failure = %d %s, want the last projection", status, body)
	}
	// And the OAuth binding check must say "could not read", never "no".
	if allowed, err := gateway.MCPClientAllowsOAuthClient("dcr-any", resource); allowed || !errors.Is(err, errFlakyRead) {
		t.Fatalf("binding check during lookup failure = %v, %v; want an error", allowed, err)
	}
	store.failLookup.Store(false)

	// A failed account listing used to project zero upstream tools.
	store.failAccounts.Store(true)
	if err := gateway.RefreshMCPClients(context.Background()); err == nil {
		t.Fatal("refresh with a failed account listing reported success")
	}
	ageClientProjection(gateway, client.Slug)
	if status, body := toolsListOver(t, gateway, client.Slug); status != http.StatusOK || !strings.Contains(body, "team_notion__search") {
		t.Fatalf("tools/list during account listing failure = %d %s, want the last projection", status, body)
	}
}

func TestStartupProjectsEndpointsEvenWhenSlowUpstreamsExhaustTheBudget(t *testing.T) {
	ctx := context.Background()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := &flakyStore{FileStore: fs}
	store.expiredCtx.Store(true)
	for _, name := range []string{"fast", "hung"} {
		if err := fs.Upsert(ctx, Account{Name: name, URL: "https://" + name + ".example/mcp", AuthMode: "token", BearerToken: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	client, err := fs.CreateMCPClient(ctx, MCPClient{Name: "Codex", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(ctx context.Context, account Account) ([]mcp.Tool, error) {
		if account.Name == "hung" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []mcp.Tool{mcp.NewTool(account.Name + "__search")}, nil
	}

	budget, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	gateway.Aggregate(budget)

	if gateway.mcp.GetTool("fast__search") == nil {
		t.Fatal("a hung upstream kept a healthy one from being aggregated")
	}
	// Projection used to reuse the exhausted context, fail, and leave every
	// client endpoint without an epoch: 401 on access, invalid_grant on
	// refresh, invalid_target on re-authorization.
	if _, live := gateway.MCPClientEpoch(client.Slug); !live {
		t.Fatal("client endpoint was not projected after the aggregation budget ran out")
	}
}

func TestReconcileRestoresAnAccountSkippedAtStartup(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{"notion": {"search"}})
	if err := g.store.Upsert(ctx, Account{Name: "unauthorized", URL: "https://figma.example/mcp", AuthMode: "oauth"}); err != nil {
		t.Fatal(err)
	}
	var down atomic.Bool
	down.Store(true)
	var unauthorizedCalls atomic.Int32
	list := g.listTools
	g.listTools = func(ctx context.Context, a Account) ([]mcp.Tool, error) {
		if a.Name == "unauthorized" {
			unauthorizedCalls.Add(1)
			return nil, errors.New("authorization required")
		}
		if down.Load() {
			return nil, errors.New("upstream 502")
		}
		return list(ctx, a)
	}
	g.Aggregate(ctx)
	if g.mcp.GetTool("notion__search") != nil {
		t.Fatal("test setup: account should have been skipped")
	}

	down.Store(false)
	// A failed health probe keeps the reconcile away from the account...
	g.reconcileProjection(ctx, map[string]bool{"notion": false})
	if g.mcp.GetTool("notion__search") != nil {
		t.Fatal("reconcile dialled an account whose health probe failed")
	}
	// ...and a successful one (or the post-boot pass) restores it.
	g.reconcileProjection(ctx, nil)
	if g.mcp.GetTool("notion__search") == nil {
		t.Fatal("reconcile did not restore the account skipped at startup")
	}
	if got := unauthorizedCalls.Load(); got != 1 {
		t.Fatalf("never-authorized account dialled %d times, want only the startup attempt", got)
	}
}

func TestListeningStreamEndsCleanlyBeforeTheHostTimeout(t *testing.T) {
	previous := mcpListenStreamMaxAge
	mcpListenStreamMaxAge = 50 * time.Millisecond
	t.Cleanup(func() { mcpListenStreamMaxAge = previous })

	endpoint := httptest.NewServer(NewStreamableMCPHandler(server.NewMCPServer("test", "0.0.0"), "/mcp"))
	defer endpoint.Close()
	request, err := http.NewRequest(http.MethodGet, endpoint.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Mcp-Session-Id", existingSession)
	started := time.Now()
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET stream status = %d", response.StatusCode)
	}
	// A clean end-of-stream, not a truncated response.
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("stream ended with an error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("stream stayed open %s, want it closed at its max age", elapsed)
	}
}

func TestRefreshAccountPersistsEvenIfTheCallerGivesUp(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": {}})
	account, _ := g.store.Account("notion")
	account.URL = "https://notion.example/mcp"
	account.AuthMode = "oauth"
	account.RefreshToken = "old-refresh"
	account.AccessToken = "old-access"
	account.TokenEndpoint = "https://notion.example/token"
	if err := g.store.Upsert(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	account, _ = g.store.Account("notion")
	caller, giveUp := context.WithCancel(context.Background())
	var providerCalls atomic.Int32
	g.refreshTokens = func(ctx context.Context, _ *upstreamoauth.Metadata, refreshToken, _, _ string) (*upstreamoauth.Tokens, error) {
		providerCalls.Add(1)
		// The provider has accepted (and, if it rotates, spent) refreshToken
		// when the caller disconnects from the tool call, or SIGTERM arrives.
		giveUp()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &upstreamoauth.Tokens{AccessToken: "new-access", RefreshToken: "new-refresh"}, nil
	}

	if err := g.refreshAccount(caller, account.Name, account.IncarnationID); err != nil {
		t.Fatalf("refresh whose caller gave up mid-flight: %v", err)
	}
	if stored, _ := g.store.Account("notion"); stored.RefreshToken != "new-refresh" || stored.AccessToken != "new-access" {
		t.Fatalf("stored tokens = %q/%q, want the refreshed pair", stored.AccessToken, stored.RefreshToken)
	}

	// But a caller already gone must not start a provider refresh at all.
	if err := g.refreshAccount(caller, account.Name, account.IncarnationID); err == nil {
		t.Fatal("refresh started for a caller that had already gone")
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("provider refresh calls = %d, want 1", got)
	}
}

func TestRevokedRefreshGrantAsksForReauthorization(t *testing.T) {
	err := errors.New(`lelapa_linear: refresh failed: refresh -> 400: {"error":"invalid_grant","error_description":"Grant not found"}`)
	if got := classifyHealthProbeError(err, context.Background()); got != healthStatusAuthExpired {
		t.Fatalf("revoked refresh grant classified %q, want %q (reauthorize, not retry)", got, healthStatusAuthExpired)
	}
}

func TestConsentNamesAnEndpointBoundToAnotherApp(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Codex", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	resource := "/mcp/clients/" + client.Slug
	if err := gateway.AuthorizeMCPConsent(ctx, "usr_alice", "operator", "dcr-first", resource); err != nil {
		t.Fatal(err)
	}
	// An agent that registered again gets a new DCR client ID. Consent must
	// say why it is refused so the member can choose to replace the sign-in.
	err = gateway.AuthorizeMCPConsent(ctx, "usr_alice", "operator", "dcr-second", resource)
	if !errors.Is(err, ErrMCPClientOAuthBinding) || !errors.Is(err, oauthas.ErrClientBoundToOtherApp) {
		t.Fatalf("consent for a second app = %v, want a bound-to-another-app refusal", err)
	}

	// Replacing is the endpoint member's explicit choice alone...
	if err := gateway.ReplaceMCPConsent(ctx, "usr_bob", "owner", "dcr-second", resource); err == nil {
		t.Fatal("another member replaced the sign-in")
	}
	oldEpoch, _ := gateway.MCPClientEpoch(client.Slug)
	var revokedEpochs []string
	gateway.SetTokenEpochRevoker(func(path, epoch string) {
		if path == resource {
			revokedEpochs = append(revokedEpochs, epoch)
		}
	})
	if err := gateway.ReplaceMCPConsent(ctx, "usr_alice", "operator", "dcr-second", resource); err != nil {
		t.Fatalf("replace sign-in: %v", err)
	}
	// ...and signs the previous app out: its binding check fails, its epoch
	// is gone, and its grants are revoked.
	if allowsOAuthClient(t, gateway, "dcr-first", resource) || !allowsOAuthClient(t, gateway, "dcr-second", resource) {
		t.Fatal("binding did not move to the replacing app")
	}
	if newEpoch, live := gateway.MCPClientEpoch(client.Slug); !live || newEpoch == oldEpoch {
		t.Fatalf("epoch after replace = %q (live %v), want a rotation from %q", newEpoch, live, oldEpoch)
	}
	if len(revokedEpochs) != 1 || revokedEpochs[0] != oldEpoch {
		t.Fatalf("revoked epochs = %v, want the previous epoch %q", revokedEpochs, oldEpoch)
	}
}

func TestProjectionReadyTracksTheLastEndpointRefresh(t *testing.T) {
	store, gateway, _ := newResilienceGateway(t)
	if !gateway.ProjectionReady() {
		t.Fatal("projection not ready after a successful startup")
	}
	store.failAccounts.Store(true)
	if err := gateway.RefreshConnectors(context.Background()); err == nil {
		t.Fatal("refresh with a failed read reported success")
	}
	if gateway.ProjectionReady() {
		t.Fatal("projection reported ready after a failed refresh")
	}
	store.failAccounts.Store(false)
	if err := gateway.RefreshConnectors(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gateway.ProjectionReady() {
		t.Fatal("projection not ready after a successful retry")
	}

	fresh := NewGateway(store, server.NewMCPServer("test", "0.0.0"))
	if fresh.ProjectionReady() {
		t.Fatal("a gateway that never projected reported ready")
	}
}
