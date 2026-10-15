package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	// Two probes, plus one aggregation in the first tick: the healthy account
	// was never projected, and its successful probe lets the reconcile restore
	// it. The hung account's failed probe keeps the reconcile away from it.
	if got := healthyCalls.Load(); got != 3 {
		t.Fatalf("healthy provider calls across two watch ticks = %d, want two probes and one restore", got)
	}
	if g.mcp.GetTool("healthy__search") == nil {
		t.Fatal("watch tick did not restore the healthy account's tools")
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
	row := AccountHealth{
		UUID:     "notion",
		Status:   healthStatusUnreachable,
		Detail:   secret,
		Recovery: secret,
	}
	g.evalAlerts(context.Background(), []AccountHealth{row})
	g.evalAlerts(context.Background(), []AccountHealth{row}) // transient: alerts on the second failed probe

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

func countAlerts(logs *syncLogBuffer, kind string) int {
	return strings.Count(logs.String(), kind)
}

func TestHealthAlertWaitsForSecondConsecutiveTransientFailure(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	logs := captureEngineLog(t)
	sweep := func(slow string) {
		g.evalAlerts(context.Background(), []AccountHealth{
			{UUID: "healthy", Status: healthStatusOK},
			{UUID: "slow", Status: slow},
		})
	}

	sweep(healthStatusTimeout)
	sweep(healthStatusOK) // a one-off blip recovers silently
	sweep(healthStatusTimeout)
	if n := countAlerts(logs, "needs attention"); n != 0 {
		t.Fatalf("single failed probes raised %d alert(s), want none:\n%s", n, logs)
	}
	sweep(healthStatusUnreachable)
	if n := countAlerts(logs, `account "slow" needs attention (unreachable)`); n != 1 {
		t.Fatalf("second consecutive failure raised %d alert(s), want one:\n%s", n, logs)
	}
	sweep(healthStatusTimeout)
	sweep(healthStatusOK)
	if countAlerts(logs, "needs attention") != 1 || countAlerts(logs, `account "slow" recovered`) != 1 {
		t.Fatalf("sustained outage should alert once then recover once:\n%s", logs)
	}
}

func TestHealthAlertIgnoresSweepWhereEveryProbeTimedOut(t *testing.T) {
	g := newConnectorTestGateway(t, nil)
	logs := captureEngineLog(t)
	for i := 0; i < 3; i++ { // a throttled cold-start Engine, woken repeatedly
		g.evalAlerts(context.Background(), []AccountHealth{
			{UUID: "linear", Status: healthStatusTimeout},
			{UUID: "notion", Status: healthStatusTimeout},
			{UUID: "figma", Status: healthStatusNeedsAuth}, // not probed: still alerts
		})
	}
	if n := countAlerts(logs, "needs attention"); n != 1 || countAlerts(logs, `account "figma" needs attention (needs_auth)`) != 1 {
		t.Fatalf("Engine-wide timeout sweeps raised %d alert(s), want only figma's:\n%s", n, logs)
	}
}

func TestHealthAlertIsNotRepeatedAfterEngineRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	logs := captureEngineLog(t)
	// Each sweep runs on a freshly booted Engine over the same store, as a
	// scale-to-zero Engine does when the Platform wakes it.
	sweepAfterRestart := func(rows ...AccountHealth) {
		fs, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("file store: %v", err)
		}
		NewGateway(fs, server.NewMCPServer("test", "0.0.0")).evalAlerts(context.Background(), rows)
	}
	figma := AccountHealth{UUID: "figma", Status: healthStatusNeedsAuth}

	sweepAfterRestart(figma)
	sweepAfterRestart(figma)
	if n := countAlerts(logs, "needs attention"); n != 1 {
		t.Fatalf("persistent needs_auth alerted %d time(s) across a restart, want once:\n%s", n, logs)
	}
	sweepAfterRestart(AccountHealth{UUID: "figma", Status: healthStatusOK})
	if n := countAlerts(logs, `account "figma" recovered`); n != 1 {
		t.Fatalf("recovery after restart alerted %d time(s), want once:\n%s", n, logs)
	}
	sweepAfterRestart(figma)
	sweepAfterRestart() // account deleted: its alert state goes with it
	sweepAfterRestart(figma)
	if n := countAlerts(logs, "needs attention"); n != 3 {
		t.Fatalf("re-broken and re-created account alerts = %d, want 3 total:\n%s", n, logs)
	}
}

func TestConsoleHealthDefensivelyNormalizesProviderDetail(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{"linear": nil})
	const secret = "provider-secret-do-not-return"
	g.listTools = func(_ context.Context, _ Account) ([]mcp.Tool, error) {
		return nil, errors.New("upstream request failed: " + secret)
	}
	// Setup's aggregation recorded its successful listing as the account's
	// health; forget it so this poll probes the now-failing provider.
	g.healthCacheMu.Lock()
	g.healthCache = map[string]cachedAccountHealth{}
	g.healthCacheMu.Unlock()

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
	notion, _ := g.store.Account("notion")

	g.Health(context.Background())
	first, _ := g.cachedHealth(notion)
	time.Sleep(100 * time.Millisecond)
	// Past the TTL the recorded row is still answered at once; the re-probe
	// runs in the background and lands in the cache.
	row := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if row.Status != healthStatusOK {
		t.Fatalf("health after TTL expiry = %+v, want the recorded ok row", row)
	}
	waitFor(t, "background re-probe after TTL expiry", func() bool {
		entry, ok := g.cachedHealth(notion)
		return ok && entry.probedAt.After(first.probedAt)
	})
	if got := probeCalls.Load(); got != 2 {
		t.Fatalf("poll after TTL expiry started %d upstream probes total, want two", got)
	}
}

// waitFor polls cond until it holds, failing the test after a second.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
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

// TestHealthServesStaleRowWhileOneBackgroundProbeRevalidates: past the TTL a
// poll answers at once from the recorded row, with its real CheckedAt, while
// a single background probe — shared by every poll meanwhile — refreshes it.
func TestHealthServesStaleRowWhileOneBackgroundProbeRevalidates(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = 20 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		if probeCalls.Add(1) == 1 {
			return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
		}
		<-release // the revalidating provider is slow
		return []mcp.Tool{mcp.NewTool(a.Name + "__search"), mcp.NewTool(a.Name + "__fetch")}, nil
	}
	notion, _ := g.store.Account("notion")

	first := healthRowsByAccount(g.Health(context.Background()))["notion"]
	time.Sleep(40 * time.Millisecond)
	for range 5 {
		started := time.Now()
		row := healthRowsByAccount(g.Health(context.Background()))["notion"]
		if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
			t.Fatalf("a stale row waited %s for the provider", elapsed)
		}
		if row.ToolCount != 1 || row.CheckedAt != first.CheckedAt {
			t.Fatalf("stale poll = %+v, want the recorded row %+v", row, first)
		}
	}
	waitFor(t, "the background revalidation", func() bool { return probeCalls.Load() == 2 })
	time.Sleep(20 * time.Millisecond)
	if got := probeCalls.Load(); got != 2 {
		t.Fatalf("five stale polls started %d probes, want one shared revalidation", got-1)
	}

	close(release)
	waitFor(t, "the revalidated row", func() bool {
		entry, ok := g.cachedHealth(notion)
		return ok && entry.row.ToolCount == 2
	})
	if row := healthRowsByAccount(g.Health(context.Background()))["notion"]; row.ToolCount != 2 {
		t.Fatalf("poll after revalidation = %+v, want the refreshed row", row)
	}
}

// TestHealthOwnerCancellationNeverPoisonsOtherViewers: the request that
// starts a shared probe (a browser reload, a proxy timeout) must not cancel
// it, nor have its own cancellation recorded as the account's health. This
// used to cache context.Canceled as "unreachable" for every other viewer.
func TestHealthOwnerCancellationNeverPoisonsOtherViewers(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = time.Minute
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	started := make(chan struct{})
	var startedOnce sync.Once
	var probeCalls atomic.Int32
	g.listTools = func(ctx context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
			return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
		case <-ctx.Done(): // a well-behaved transport honours cancellation
			return nil, ctx.Err()
		}
	}
	notion, _ := g.store.Account("notion")

	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	ownerDone := make(chan []AccountHealth, 1)
	go func() { ownerDone <- g.Health(ownerCtx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("owner probe did not start")
	}
	cancelOwner()
	select {
	case rows := <-ownerDone:
		if got := healthRowsByAccount(rows)["notion"]; got.Status == "" {
			t.Fatalf("cancelled owner got an empty row: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled owner did not return")
	}
	if row, ok := g.cachedHealthRow(notion, g.healthCacheTTL); ok {
		t.Fatalf("owner cancellation was recorded as the account's health: %+v", row)
	}

	// Another viewer shares the probe the owner started, which runs on.
	viewer := make(chan []AccountHealth, 1)
	go func() { viewer <- g.Health(context.Background()) }()
	time.Sleep(50 * time.Millisecond) // let it join, as the sharing tests above do
	close(release)
	select {
	case rows := <-viewer:
		if got := healthRowsByAccount(rows)["notion"]; got.Status != healthStatusOK || got.ToolCount != 1 {
			t.Fatalf("other viewer = %+v, want the probe's real healthy outcome", got)
		}
	case <-time.After(time.Second):
		t.Fatal("other viewer did not complete")
	}
	if row, ok := g.cachedHealthRow(notion, g.healthCacheTTL); !ok || row.Status != healthStatusOK {
		t.Fatalf("recorded row = %+v (ok=%v), want the healthy outcome", row, ok)
	}
	if got := probeCalls.Load(); got != 1 {
		t.Fatalf("provider probed %d times, want the one shared probe", got)
	}
}

// TestHealthWatchTickRecordsItsProbesForTheConsole: the watch loop keeps
// alerting on fresh probes, and the console then reads what it observed
// instead of dialing every provider again.
func TestHealthWatchTickRecordsItsProbesForTheConsole(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil, "linear": nil})
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		if a.Name == "linear" {
			return nil, transport.ErrAuthorizationRequired
		}
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}

	g.tick(context.Background())
	after := probeCalls.Load()
	rows := healthRowsByAccount(g.Health(context.Background()))
	if got := probeCalls.Load(); got != after {
		t.Fatalf("console poll after a tick dialed %d providers, want none", got-after)
	}
	if rows["notion"].Status != healthStatusOK || rows["linear"].Status != healthStatusAuthExpired {
		t.Fatalf("console rows after a tick = %+v", rows)
	}
}

// TestHealthBackgroundTimeoutNeverReplacesAHealthyRow: on Cloud Run a probe
// no request waits on runs CPU-throttled and times out spuriously, so its
// timeout keeps the healthy row. A foreground timeout, or any definitive
// failure, replaces it.
func TestHealthBackgroundTimeoutNeverReplacesAHealthyRow(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthProbeTimeout = 20 * time.Millisecond
	var mode atomic.Value // "ok" | "slow" | "down"
	mode.Store("ok")
	g.listTools = func(ctx context.Context, a Account) ([]mcp.Tool, error) {
		switch mode.Load() {
		case "slow":
			<-ctx.Done()
			return nil, ctx.Err()
		case "down":
			return nil, errors.New("upstream returned 502")
		}
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	notion, _ := g.store.Account("notion")
	recorded := func() AccountHealth {
		t.Helper()
		entry, ok := g.cachedHealth(notion)
		if !ok {
			t.Fatal("no recorded row")
		}
		return entry.row
	}

	if row := healthRowsByAccount(g.Health(context.Background()))["notion"]; row.Status != healthStatusOK {
		t.Fatalf("seed health = %+v", row)
	}
	mode.Store("slow")
	// The watch loop still sees the timeout for alerting...
	if row := g.liveHealth(context.Background(), []Account{notion})[0]; row.Status != healthStatusTimeout {
		t.Fatalf("background probe = %+v, want timeout", row)
	}
	// ...but the console keeps the healthy row.
	if row := recorded(); row.Status != healthStatusOK {
		t.Fatalf("background timeout replaced the healthy row: %+v", row)
	}
	// A request waiting on the probe makes its timeout real.
	if row := g.ProbeHealthFor(context.Background(), []Account{notion})[0]; row.Status != healthStatusTimeout {
		t.Fatalf("foreground probe = %+v, want timeout", row)
	}
	if row := recorded(); row.Status != healthStatusTimeout {
		t.Fatalf("foreground timeout was not recorded: %+v", row)
	}

	mode.Store("ok")
	g.ProbeHealthFor(context.Background(), []Account{notion})
	mode.Store("down")
	if row := g.liveHealth(context.Background(), []Account{notion})[0]; row.Status != healthStatusUnreachable {
		t.Fatalf("background probe = %+v, want unreachable", row)
	}
	if row := recorded(); row.Status != healthStatusUnreachable {
		t.Fatalf("a definitive background failure kept the healthy row: %+v", row)
	}
}

// TestHealthFailedRowNeedsExactCredentials: refresh-ahead rotates OAuth
// tokens on every tick, and a healthy row survives that. A failed row
// describes only the credentials it failed with, so a reconnect gets a live
// probe.
func TestHealthFailedRowNeedsExactCredentials(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, nil)
	if err := g.store.Upsert(ctx, Account{
		Name: "notion", URL: "https://notion.example/mcp", AuthMode: "oauth",
		AccessToken: "access-1", RefreshToken: "refresh-1", TokenEndpoint: "https://notion.example/token",
	}); err != nil {
		t.Fatal(err)
	}
	notion, _ := g.store.Account("notion")
	var failing atomic.Bool
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		if failing.Load() {
			return nil, transport.ErrAuthorizationRequired
		}
		return []mcp.Tool{mcp.NewTool(a.Name + "__search")}, nil
	}
	rotate := func(access, refresh string) {
		t.Helper()
		if err := g.store.UpdateTokens(ctx, notion.Name, notion.IncarnationID, access, refresh); err != nil {
			t.Fatal(err)
		}
	}

	g.Health(ctx)
	rotate("access-2", "refresh-2") // refresh-ahead
	if row := healthRowsByAccount(g.Health(ctx))["notion"]; row.Status != healthStatusOK || probeCalls.Load() != 1 {
		t.Fatalf("after a token rotation: row %+v, %d probes; want the healthy row without a probe", row, probeCalls.Load())
	}

	failing.Store(true)
	rotated, _ := g.store.Account("notion")
	g.ProbeHealthFor(ctx, []Account{rotated})
	if row := healthRowsByAccount(g.Health(ctx))["notion"]; row.Status != healthStatusAuthExpired || probeCalls.Load() != 2 {
		t.Fatalf("same credentials: row %+v, %d probes; want the recorded failure", row, probeCalls.Load())
	}

	failing.Store(false)
	rotate("access-3", "refresh-3") // a reconnect
	if row := healthRowsByAccount(g.Health(ctx))["notion"]; row.Status != healthStatusOK || probeCalls.Load() != 3 {
		t.Fatalf("after reconnecting: row %+v, %d probes; want a live healthy probe", row, probeCalls.Load())
	}
}

// TestHealthPastMaxStalenessWaitsForALiveProbe: a row older than the stale
// limit is not served; the poll waits for a live probe instead.
func TestHealthPastMaxStalenessWaitsForALiveProbe(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"notion": nil})
	g.healthCacheTTL = 10 * time.Millisecond
	g.healthMaxStaleness = 50 * time.Millisecond
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		tools := make([]mcp.Tool, probeCalls.Add(1))
		for i := range tools {
			tools[i] = mcp.NewTool(fmt.Sprintf("%s__tool%d", a.Name, i))
		}
		return tools, nil
	}

	g.Health(context.Background())
	time.Sleep(80 * time.Millisecond)
	row := healthRowsByAccount(g.Health(context.Background()))["notion"]
	if row.ToolCount != 2 || probeCalls.Load() != 2 {
		t.Fatalf("poll past the stale limit = %+v after %d probes, want the live second probe", row, probeCalls.Load())
	}
}

// TestConsoleHealthRefreshHeaderProbesLive: the console's "probe now" sends
// X-Synaxis-Health-Refresh: 1 and gets live probes — shared between
// concurrent requests — even while a fresh row is recorded; a plain poll
// keeps reading the recorded row.
func TestConsoleHealthRefreshHeaderProbesLive(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{"linear": {"get_issue"}})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var probeCalls atomic.Int32
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		probeCalls.Add(1)
		<-release
		return []mcp.Tool{mcp.NewTool(a.Name + "__get_issue"), mcp.NewTool(a.Name + "__save_issue")}, nil
	}
	toolCount := func(rec *httptest.ResponseRecorder) int {
		t.Helper()
		var rows []AccountHealth
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatalf("GET /api/health = %d %s", rec.Code, rec.Body)
		}
		return rows[0].ToolCount
	}

	// Setup's aggregation recorded one tool: a plain poll answers from it.
	if rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/health", ""); toolCount(rec) != 1 || probeCalls.Load() != 0 {
		t.Fatalf("plain poll probed %d times, want the recorded row", probeCalls.Load())
	}

	refresh := map[string]string{healthRefreshHeader: "1"}
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			rec, _ := doJSONWithHeaders(t, mux, token, http.MethodGet, "/api/health", "", refresh)
			results <- rec
		}()
	}
	waitFor(t, "the live probe", func() bool { return probeCalls.Load() == 1 })
	// The same handoff margin TestHealthSharesInFlightProbeAcrossConcurrentCallers
	// relies on: let the second request join the in-flight probe.
	time.Sleep(50 * time.Millisecond)
	close(release)
	for range 2 {
		if got := toolCount(<-results); got != 2 {
			t.Fatalf("probe-now row has %d tools, want the live probe's 2", got)
		}
	}
	if got := probeCalls.Load(); got != 1 {
		t.Fatalf("two concurrent probe-now requests dialed %d times, want one shared probe", got)
	}
	// The live result was recorded for every later plain poll.
	if rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/health", ""); toolCount(rec) != 2 || probeCalls.Load() != 1 {
		t.Fatalf("plain poll after probe-now dialed again or missed its result")
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/api/health", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, preflight)
	if !strings.Contains(recorder.Header().Get("Access-Control-Allow-Headers"), healthRefreshHeader) {
		t.Fatalf("CORS preflight does not allow %s: %q", healthRefreshHeader, recorder.Header().Get("Access-Control-Allow-Headers"))
	}
}
