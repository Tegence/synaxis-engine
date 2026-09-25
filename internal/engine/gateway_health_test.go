package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func healthRowsByAccount(rows []AccountHealth) map[string]AccountHealth {
	byAccount := make(map[string]AccountHealth, len(rows))
	for _, row := range rows {
		byAccount[row.UUID] = row
	}
	return byAccount
}

func TestHealthBoundsHungProviderWithoutBlockingHealthyAccounts(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"hung":    nil,
		"healthy": nil,
	})
	g.healthProbeTimeout = 30 * time.Millisecond

	// Intentionally ignore ctx. This models a third-party transport/library
	// that fails to observe cancellation; Health must still return and let the
	// watch loop continue. Release it during cleanup so the test does not leave
	// a goroutine behind.
	releaseHung := make(chan struct{})
	t.Cleanup(func() { close(releaseHung) })
	hungStarted := make(chan struct{})
	var startedOnce sync.Once
	var hungCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		switch a.Name {
		case "hung":
			hungCalls.Add(1)
			startedOnce.Do(func() { close(hungStarted) })
			<-releaseHung
			return nil, errors.New("provider-private-error-after-release")
		case "healthy":
			return []mcp.Tool{mcp.NewTool("healthy__search")}, nil
		default:
			return nil, errors.New("unexpected account")
		}
	}

	started := time.Now()
	rows := g.Health(context.Background())
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Health waited for a cancellation-ignorant provider: %s", elapsed)
	}
	byAccount := healthRowsByAccount(rows)
	if got := byAccount["healthy"]; got.Status != healthStatusOK || got.ToolCount != 1 {
		t.Fatalf("healthy account was not assessed while peer was hung: %+v", got)
	}
	if got := byAccount["hung"]; got.Status != healthStatusTimeout || got.Recovery != healthRecoveryRetry ||
		got.Detail != "The provider did not respond before the health check timed out." {
		t.Fatalf("hung account health = %+v", got)
	}
	select {
	case <-hungStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("hung provider probe did not start")
	}
	// Repeated dashboard polls receive bounded timeout rows instead of spawning
	// another non-cooperative provider operation.
	for range 4 {
		_ = g.Health(context.Background())
	}
	if got := hungCalls.Load(); got != 1 {
		t.Fatalf("hung provider received %d live probes, want one", got)
	}
}

func TestHealthRecoversAfterCredentialChangeWhileOldProbeIsStranded(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthProbeTimeout = 30 * time.Millisecond

	before, ok := g.store.Account("notion")
	if !ok {
		t.Fatal("seed account missing")
	}
	oldToken := before.BearerToken
	releaseOldProbe := make(chan struct{})
	oldStarted := make(chan struct{})
	oldFinished := make(chan struct{})
	var oldStartedOnce sync.Once
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		switch a.BearerToken {
		case oldToken:
			oldStartedOnce.Do(func() { close(oldStarted) })
			<-releaseOldProbe // deliberately ignores the health context
			close(oldFinished)
			return nil, errors.New("old provider call finally unwound")
		case "repaired-token":
			return []mcp.Tool{mcp.NewTool("notion__search")}, nil
		default:
			return nil, errors.New("unexpected credential generation")
		}
	}
	t.Cleanup(func() {
		close(releaseOldProbe)
		select {
		case <-oldFinished:
		case <-time.After(time.Second):
			t.Error("stranded probe did not unwind during cleanup")
		}
	})

	first := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if first.Status != healthStatusTimeout {
		t.Fatalf("first health = %+v, want timeout", first)
	}
	select {
	case <-oldStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("old provider probe did not start")
	}

	// A poll with the same durable credential remains coalesced with the old
	// probe. This is the no-goroutine-storm side of the recovery behavior.
	_ = g.Health(context.Background())
	if got := probeCalls.Load(); got != 1 {
		t.Fatalf("same credential started %d probes, want one", got)
	}

	if _, err := g.store.SetBearerToken(context.Background(), before.Name, before.IncarnationID, "repaired-token", before.Revision); err != nil {
		t.Fatalf("replace bearer token: %v", err)
	}
	recovered := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if recovered.Status != healthStatusOK || recovered.ToolCount != 1 {
		t.Fatalf("health after credential repair = %+v, want healthy one-tool account", recovered)
	}
	if got := probeCalls.Load(); got != 2 {
		t.Fatalf("credential repair started %d probes, want old plus one fresh", got)
	}

	// The unrecoverable old transport remains tracked, but a completed fresh
	// probe released its own generation. There is no unbounded per-poll work.
	g.healthProbeMu.Lock()
	remaining := len(g.healthProbes)
	g.healthProbeMu.Unlock()
	if remaining != 1 {
		t.Fatalf("in-flight probe generations = %d, want only the stranded old one", remaining)
	}
}

func TestHealthProbeGenerationsStayBoundedAcrossRepeatedRepairs(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	base := Account{
		Name:          "notion",
		IncarnationID: "incarnation-1",
		URL:           "https://notion.example/mcp",
		AuthMode:      "token",
		BearerToken:   "old-token",
	}

	releaseOld, started := g.beginHealthProbe(base)
	if !started {
		t.Fatal("start old generation")
	}
	repaired := base
	repaired.BearerToken = "repaired-token"
	releaseRepaired, started := g.beginHealthProbe(repaired)
	if !started {
		t.Fatal("credential repair should get one fresh probe generation")
	}

	thirdGeneration := repaired
	thirdGeneration.BearerToken = "third-token"
	if _, started := g.beginHealthProbe(thirdGeneration); started {
		t.Fatal("third stranded generation bypassed the per-account health-probe cap")
	}

	// Once the repaired probe finishes, capacity opens for the next real
	// configuration change even if the original transport is still stranded.
	releaseRepaired()
	releaseThird, started := g.beginHealthProbe(thirdGeneration)
	if !started {
		t.Fatal("completed repaired probe did not release recovery capacity")
	}
	releaseThird()
	releaseOld()
}

func TestHealthPublishesOnlySafeActionableFailures(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"expired":     nil,
		"unreachable": nil,
	})
	if err := g.store.Upsert(context.Background(), Account{
		Name: "unconnected", URL: "https://unused.example/mcp", AuthMode: "oauth",
	}); err != nil {
		t.Fatalf("seed unconnected account: %v", err)
	}
	const secret = "provider-secret-do-not-expose"
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		switch a.Name {
		case "expired":
			// What production now produces for a transport-level HTTP 401:
			// mcp-go's typed sentinel, wrapping a provider-controlled diagnostic
			// that must never be published.
			return nil, fmt.Errorf("%w: %s", transport.ErrAuthorizationRequired, secret)
		case "unreachable":
			return nil, errors.New("provider host failed: " + secret)
		default:
			return nil, errors.New("unexpected probe: " + a.Name)
		}
	}

	rows := healthRowsByAccount(g.Health(context.Background()))
	checks := []struct {
		account  string
		status   string
		recovery string
		detail   string
	}{
		{"unconnected", healthStatusNeedsAuth, healthRecoveryConnect, "This connection has not been authorized yet."},
		{"expired", healthStatusAuthExpired, healthRecoveryReauthorize, "This connection needs to be authorized again."},
		{"unreachable", healthStatusUnreachable, healthRecoveryRetry, "The provider could not be reached. Check its service and try again."},
	}
	for _, check := range checks {
		got := rows[check.account]
		if got.Status != check.status || got.Recovery != check.recovery || got.Detail != check.detail {
			t.Errorf("%s health = %+v, want status=%q recovery=%q detail=%q", check.account, got, check.status, check.recovery, check.detail)
		}
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("health response leaked provider diagnostic: %s", encoded)
	}
}

// TestHealthClassifiesToolLevelAuthFailureTextAsExpired guards the opposite
// side of the typed-401 fix in upstream.go: classifyHealthProbeError must NOT
// inherit isUnauthorized's strictness. A tool-level/proxy error that merely
// LOOKS auth-shaped (contains "401"/"invalid_token") but is not mcp-go's
// typed transport sentinel must still classify as auth_expired — the one
// actionable "reauthorize" message for TOKEN-mode (PAT) accounts, which
// upstreamFor never wires a Refresh for. The retry path's isUnauthorized, in
// contrast, must keep rejecting this exact same error (asserted below):
// re-executing a mutating tool call on it would be unsafe, which is exactly
// what TestToolLevelErrorMentioning401NeverRefreshesOrReexecutes proves for
// the CallTool path.
func TestHealthClassifiesToolLevelAuthFailureTextAsExpired(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"revoked-pat": nil})
	// A tool-level JSON-RPC error / proxy diagnostic delivered over HTTP 200 —
	// not mcp-go's typed transport.ErrAuthorizationRequired — exactly the
	// shape a revoked PAT surfaces as on many upstreams.
	toolLevelErr := errors.New("tool failed: upstream returned 401 unauthorized (invalid_token: invalid access token)")
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return nil, toolLevelErr
	}

	got := healthRowsByAccount(g.Health(context.Background()))["revoked-pat"]
	if got.Status != healthStatusAuthExpired || got.Recovery != healthRecoveryReauthorize ||
		got.Detail != "This connection needs to be authorized again." {
		t.Fatalf("revoked-pat health = %+v, want auth_expired/reauthorize", got)
	}

	// The retry/refresh path's predicate must remain typed-401-only.
	if isUnauthorized(toolLevelErr) {
		t.Fatal("isUnauthorized must stay typed-401-only; the retry path would unsafely re-execute a mutating call on tool-level error text")
	}
}

func TestWatchTickProgressesPastHungProvider(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"hung":    nil,
		"healthy": nil,
	})
	g.healthProbeTimeout = 30 * time.Millisecond
	releaseHung := make(chan struct{})
	t.Cleanup(func() { close(releaseHung) })
	var hungCalls atomic.Int32
	var healthyCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		if a.Name == "hung" {
			hungCalls.Add(1)
			<-releaseHung
			return nil, errors.New("provider-private-error-after-release")
		}
		healthyCalls.Add(1)
		return []mcp.Tool{mcp.NewTool("healthy__search")}, nil
	}

	for tick := 0; tick < 2; tick++ {
		done := make(chan struct{})
		go func() {
			g.tick(context.Background())
			close(done)
		}()
		select {
		case <-done:
			// A timeout row was produced, alerts were evaluated, and the watcher
			// is ready for its next interval despite the hung provider goroutine.
		case <-time.After(500 * time.Millisecond):
			t.Fatal("watch tick was blocked by a hung provider")
		}
	}
	if got := hungCalls.Load(); got != 1 {
		t.Fatalf("hung provider probes across two watch ticks = %d, want one", got)
	}
	if got := healthyCalls.Load(); got != 2 {
		t.Fatalf("healthy provider probes across two watch ticks = %d, want two", got)
	}
}

func TestHealthAlertNeverIncludesProviderDetail(t *testing.T) {
	received := make(chan string, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()

	g := newConnectorTestGateway(t, nil)
	g.SetAlertWebhook(webhook.URL)
	const secret = "provider-secret-do-not-alert"
	g.evalAlert(AccountHealth{
		UUID:     "notion",
		Status:   healthStatusUnreachable,
		Detail:   secret,
		Recovery: secret,
	})

	select {
	case body := <-received:
		if strings.Contains(body, secret) {
			t.Fatalf("alert leaked provider detail: %s", body)
		}
		if !strings.Contains(body, healthStatusUnreachable) || !strings.Contains(body, healthRecoveryRetry) {
			t.Fatalf("alert omitted safe status/recovery: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("health alert was not delivered")
	}
}

func TestConsoleHealthDefensivelyNormalizesProviderDetail(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{"linear": nil})
	const secret = "provider-secret-do-not-return"
	g.listTools = func(_ context.Context, _ Account) ([]mcp.Tool, error) {
		return nil, errors.New("upstream request failed: " + secret)
	}

	rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/health = %d, body %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("console health leaked provider detail: %s", rec.Body)
	}
	var rows []AccountHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("decode health = %s (err %v)", rec.Body, err)
	}
	got := rows[0]
	if got.Status != healthStatusUnreachable || got.Recovery != healthRecoveryRetry ||
		got.Detail != "The provider could not be reached. Check its service and try again." {
		t.Fatalf("console health row = %+v", got)
	}
}

// auditStatsStore adds the concrete-store audit diagnostic facet to a
// FileStore, standing in for PgStore without a database.
type auditStatsStore struct {
	*FileStore
	stats AuditPersistenceStats
}

func (s auditStatsStore) AuditPersistenceStats() AuditPersistenceStats { return s.stats }

func TestConsoleGatewayReportsAuditPersistenceStats(t *testing.T) {
	fs, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	store := auditStatsStore{
		FileStore: fs,
		stats: AuditPersistenceStats{
			Enqueued: 10, Persisted: 7, Dropped: 3, Failures: 1, Retries: 2,
			QueueDepth: 4, LastError: "driver-error-text-must-not-leak",
			LastDropReason: auditDropQueueFull,
		},
	}
	g := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	api := NewConsoleAPI(store, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	token := api.signToken()

	rec, got := doJSON(t, mux, token, http.MethodGet, "/api/gateway", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/gateway = %d, body %s", rec.Code, rec.Body)
	}
	raw, ok := got["auditPersistence"].(map[string]any)
	if !ok {
		t.Fatalf("auditPersistence missing from gateway status: %s", rec.Body)
	}
	if raw["dropped"] != float64(3) || raw["failures"] != float64(1) ||
		raw["enqueued"] != float64(10) || raw["persisted"] != float64(7) ||
		raw["queueDepth"] != float64(4) {
		t.Fatalf("audit persistence counters mismatch: %v", raw)
	}
	if raw["lastDropReason"] != auditDropQueueFull {
		t.Fatalf("lastDropReason = %v, want %q", raw["lastDropReason"], auditDropQueueFull)
	}
	if strings.Contains(rec.Body.String(), "driver-error-text-must-not-leak") {
		t.Fatalf("gateway status leaked LastError: %s", rec.Body)
	}

	// Unauthenticated callers get nothing.
	rec, _ = doJSON(t, mux, "", http.MethodGet, "/api/gateway", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /api/gateway = %d, want 401", rec.Code)
	}
}

func TestConsoleGatewayOmitsAuditPersistenceWithoutFacet(t *testing.T) {
	mux, token, _ := newConnectorConsole(t, nil)
	rec, got := doJSON(t, mux, token, http.MethodGet, "/api/gateway", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/gateway = %d, body %s", rec.Code, rec.Body)
	}
	if _, present := got["auditPersistence"]; present {
		t.Fatalf("file-backed store must omit auditPersistence: %s", rec.Body)
	}
}

func TestHealthServesCachedRowsWithinTTL(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = time.Minute
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}

	first := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if first.Status != healthStatusOK || first.ToolCount != 1 {
		t.Fatalf("first health = %+v, want healthy one-tool account", first)
	}
	second := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if got := probeCalls.Load(); got != 1 {
		t.Fatalf("two polls within the TTL started %d upstream probes, want one", got)
	}
	// A cached row keeps the actual probe time; it must not pretend to be fresh.
	if second.CheckedAt != first.CheckedAt {
		t.Fatalf("cached row CheckedAt = %q, want the real probe time %q", second.CheckedAt, first.CheckedAt)
	}
}

func TestHealthReprobesAfterCacheExpiry(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = 40 * time.Millisecond
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}

	g.Health(context.Background())
	time.Sleep(100 * time.Millisecond)
	row := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if got := probeCalls.Load(); got != 2 {
		t.Fatalf("poll after TTL expiry started %d upstream probes total, want two", got)
	}
	if row.Status != healthStatusOK {
		t.Fatalf("health after re-probe = %+v, want ok", row)
	}
}

func TestHealthSharesInFlightProbeAcrossConcurrentCallers(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	release := make(chan struct{})
	probeStarted := make(chan struct{})
	var startedOnce sync.Once
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		startedOnce.Do(func() { close(probeStarted) })
		<-release
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	first := make(chan []AccountHealth, 1)
	go func() { first <- g.Health(context.Background()) }()
	select {
	case <-probeStarted:
	case <-time.After(time.Second):
		t.Fatal("first caller's probe did not start")
	}
	// The probe is still blocked, so the second concurrent viewer cannot be
	// served from the completed-result cache: it must share the in-flight one.
	second := make(chan []AccountHealth, 1)
	go func() { second <- g.Health(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	for i, ch := range []chan []AccountHealth{first, second} {
		select {
		case rows := <-ch:
			got := healthRowsByAccount(rows)["notion"]
			if got.Status != healthStatusOK || got.ToolCount != 1 {
				t.Fatalf("caller %d health = %+v, want healthy one-tool account", i, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("caller %d did not complete", i)
		}
	}
	if got := probeCalls.Load(); got != 1 {
		t.Fatalf("concurrent viewers started %d upstream probes, want one shared probe", got)
	}
}

// TestHealthAbandonedSharerNeverPoisonsCache drives the exact interleaving
// behind a real, previously-confirmed bug: viewer A becomes the owner of a
// slow account's in-flight health probe; viewer B joins as a sharer of that
// same in-flight probe; B's own request context is then canceled (a closed
// tab, an aborted fetch) before A's real probe finishes. B's cancellation
// must resolve only B's own call — it must never be written into the shared
// health cache as though it were a genuine "unreachable" outcome, because any
// unrelated viewer C polling in that window would then be served that
// poisoned row instantly instead of the real, still-in-flight result.
func TestHealthAbandonedSharerNeverPoisonsCache(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = time.Minute // caching must be active for poisoning to be observable

	releaseProbe := make(chan struct{})
	probeStarted := make(chan struct{})
	var startedOnce sync.Once
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		startedOnce.Do(func() { close(probeStarted) })
		<-releaseProbe
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	t.Cleanup(func() {
		select {
		case <-releaseProbe:
		default:
			close(releaseProbe)
		}
	})

	notion, ok := g.store.Account("notion")
	if !ok {
		t.Fatal("seed account missing")
	}

	// Viewer A: becomes the flight owner and blocks inside the upstream call.
	ownerDone := make(chan []AccountHealth, 1)
	go func() { ownerDone <- g.Health(context.Background()) }()
	select {
	case <-probeStarted:
	case <-time.After(time.Second):
		t.Fatal("owner probe did not start")
	}

	// Viewer B: joins A's still in-flight probe as a sharer, then abandons the
	// wait when ITS OWN context is canceled — e.g. a closed browser tab —
	// well before A's real probe completes. The short sleep gives B's
	// goroutine time to register as a sharer and block in the shared-result
	// select before we pull its context out from under it; the same margin
	// TestHealthSharesInFlightProbeAcrossConcurrentCallers already relies on
	// for this handoff.
	sharerCtx, cancelSharer := context.WithCancel(context.Background())
	sharerDone := make(chan []AccountHealth, 1)
	go func() { sharerDone <- g.Health(sharerCtx) }()
	time.Sleep(50 * time.Millisecond)
	cancelSharer()

	select {
	case rows := <-sharerDone:
		got := healthRowsByAccount(rows)["notion"]
		if got.Status == "" {
			t.Fatalf("abandoned sharer returned an empty row: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("sharer call did not return after its own context was canceled")
	}

	// A's real probe is still running (releaseProbe is still open). The
	// sharer's abandoned wait must not have written anything into the shared
	// cache: this is the exact instant an unrelated viewer C polling right
	// now would be served a poisoned "unreachable" row from cache instead of
	// either sharing A's real in-flight probe or starting a fresh one.
	if row, ok := g.cachedHealthRow(notion, g.healthCacheTTL); ok {
		t.Fatalf("abandoned sharer poisoned the shared health cache: %+v", row)
	}

	// Viewer C polls in this exact window. It must never read back a
	// poisoned cache entry — only a fresh probe or the real shared one.
	thirdDone := make(chan []AccountHealth, 1)
	go func() { thirdDone <- g.Health(context.Background()) }()

	close(releaseProbe) // let the real upstream probe finish

	select {
	case rows := <-ownerDone:
		got := healthRowsByAccount(rows)["notion"]
		if got.Status != healthStatusOK || got.ToolCount != 1 {
			t.Fatalf("owner health = %+v, want healthy one-tool account", got)
		}
	case <-time.After(time.Second):
		t.Fatal("owner call did not complete")
	}
	select {
	case rows := <-thirdDone:
		got := healthRowsByAccount(rows)["notion"]
		if got.Status != healthStatusOK || got.ToolCount != 1 {
			t.Fatalf("viewer C health = %+v, want healthy one-tool account (must not see a poisoned cache entry)", got)
		}
	case <-time.After(time.Second):
		t.Fatal("viewer C call did not complete")
	}

	// The cache must now hold the real, genuine outcome for every future
	// reader — never the abandoned sharer's cancellation.
	row, ok := g.cachedHealthRow(notion, g.healthCacheTTL)
	if !ok || row.Status != healthStatusOK {
		t.Fatalf("final cached row = %+v (ok=%v), want a cached healthy outcome", row, ok)
	}
}
