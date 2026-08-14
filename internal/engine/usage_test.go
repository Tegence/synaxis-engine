package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type stubUsageStore struct {
	mu          sync.Mutex
	period      *UsagePeriod
	admitErr    error
	settleErr   error
	admissions  int
	settlements int
	recoveries  int
	sequence    int
	lastMeta    UsageCallMeta
	lastRuntime int64
	lastBytes   int64
}

func (s *stubUsageStore) ApplyUsageGrant(_ context.Context, grant UsageGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.period != nil {
		if grant.Revision < s.period.Grant.Revision {
			return errors.New("usage grant revision is stale")
		}
		if grant.Revision == s.period.Grant.Revision && grant.Digest != s.period.Grant.Digest {
			return errors.New("usage grant revision conflict")
		}
	}
	now := grant.IssuedAt
	s.period = &UsagePeriod{Grant: grant, UpdatedAt: now}
	return nil
}

func (s *stubUsageStore) CurrentUsage(
	_ context.Context,
	identity UsageIdentity,
	now time.Time,
) (UsagePeriod, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.period == nil || s.period.Grant.Identity != identity ||
		now.Before(s.period.Grant.PeriodStart) || !now.Before(s.period.Grant.PeriodEnd) ||
		!now.Before(s.period.Grant.ExpiresAt) {
		return UsagePeriod{}, false, nil
	}
	return *s.period, true, nil
}

func (s *stubUsageStore) AdmitUsage(
	_ context.Context,
	_ UsageIdentity,
	now time.Time,
	meta UsageCallMeta,
) (UsageReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.admitErr != nil {
		return UsageReservation{}, s.admitErr
	}
	if s.period == nil {
		return UsageReservation{}, usageError("usage_grant_required", "grant required")
	}
	s.sequence++
	s.admissions++
	s.lastMeta = meta
	s.period.CallsUsed++
	s.period.ActiveReservations++
	return UsageReservation{
		ID:          "reservation-" + string(rune('0'+s.sequence)),
		PeriodStart: s.period.Grant.PeriodStart, AdmittedAt: now,
		MaxCallSeconds: s.period.Grant.Limits.MaxCallSeconds,
	}, nil
}

func (s *stubUsageStore) SettleUsage(
	_ context.Context,
	_ UsageIdentity,
	_ string,
	_ time.Time,
	runtimeMilliseconds int64,
	transferBytes int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settleErr != nil {
		return s.settleErr
	}
	s.settlements++
	s.lastRuntime = runtimeMilliseconds
	s.lastBytes = transferBytes
	if s.period != nil {
		s.period.RuntimeMilliseconds += runtimeMilliseconds
		s.period.TransferBytesUsed += transferBytes
		s.period.ActiveReservations--
		s.period.UpdatedAt = time.Now()
	}
	return nil
}

func (s *stubUsageStore) RecoverUsageReservations(
	_ context.Context,
	_ UsageIdentity,
	_ time.Time,
) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoveries++
	return 0, nil
}

func starterClaims(now time.Time, status string) usageGrantClaims {
	claims := usageGrantClaims{
		Issuer: usageGrantIssuer, Audience: usageGrantAudience,
		WorkspaceID: "workspace-one", EngineGeneration: 7,
		PeriodStart: now.Add(-time.Minute).UTC().Format(time.RFC3339),
		PeriodEnd:   now.Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Revision:    1, PlanID: usageGrantPlan, Status: status,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(30 * 24 * time.Hour).Unix(),
	}
	if status == "trialing" {
		claims.PeriodEnd = now.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
		claims.ExpiresAt = now.Add(7 * 24 * time.Hour).Unix()
		claims.Limits.Calls = StarterTrialCalls
		claims.Limits.RuntimeSeconds = StarterTrialRuntimeSeconds
		claims.Limits.TransferBytes = StarterTrialTransferBytes
	} else {
		claims.Limits.Calls = StarterPaidCalls
		claims.Limits.RuntimeSeconds = StarterPaidRuntimeSeconds
		claims.Limits.TransferBytes = StarterPaidTransferBytes
	}
	claims.Limits.Concurrency = StarterMaxConcurrency
	claims.Limits.RatePerMinute = StarterRatePerMinute
	claims.Limits.Burst = StarterRateBurst
	claims.Limits.MaxCallSeconds = StarterMaxCallSeconds
	return claims
}

func signUsageClaims(t *testing.T, privateKey ed25519.PrivateKey, claims any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": usageGrantType})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	head := base64.RawURLEncoding.EncodeToString(header)
	body := base64.RawURLEncoding.EncodeToString(payload)
	input := head + "." + body
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}

func usageKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestVerifyUsageGrantAcceptsStarterPaidAndTrialPolicies(t *testing.T) {
	publicKey, privateKey := usageKeypair(t)
	now := time.Now().UTC().Truncate(time.Second)
	identity := UsageIdentity{WorkspaceID: "workspace-one", EngineGeneration: 7}
	for _, status := range []string{"active", "trialing"} {
		t.Run(status, func(t *testing.T) {
			grant, err := verifyUsageGrant(
				signUsageClaims(t, privateKey, starterClaims(now, status)),
				publicKey, identity, now,
			)
			if err != nil {
				t.Fatalf("valid %s grant: %v", status, err)
			}
			if grant.Status != status || grant.PlanID != usageGrantPlan ||
				grant.Identity != identity || len(grant.Digest) != 64 {
				t.Fatalf("verified grant = %+v", grant)
			}
			if status == "active" &&
				(grant.Limits.Calls != 10_000 || grant.Limits.RuntimeSeconds != 28_800) {
				t.Fatalf("paid policy = %+v", grant.Limits)
			}
			if status == "trialing" &&
				(grant.Limits.Calls != 2_000 || grant.Limits.RuntimeSeconds != 7_200) {
				t.Fatalf("trial policy = %+v", grant.Limits)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		planID string
		limits UsageLimits
	}{
		{
			name: "basic", planID: "basic-v1",
			limits: UsageLimits{
				Calls: 10_000, RuntimeSeconds: 18_000, TransferBytes: 2 << 30,
				Concurrency: 2, RatePerMinute: 60, Burst: 10, MaxCallSeconds: 300,
			},
		},
		{
			name: "pro", planID: "pro-v1",
			limits: UsageLimits{
				Calls: 40_000, RuntimeSeconds: 60_000, TransferBytes: 2 << 30,
				Concurrency: 5, RatePerMinute: 60, Burst: 10, MaxCallSeconds: 900,
			},
		},
	} {
		t.Run("accepts a platform-defined "+tc.name+" policy", func(t *testing.T) {
			claims := starterClaims(now, "active")
			claims.PlanID = tc.planID
			claims.Limits.Calls = tc.limits.Calls
			claims.Limits.RuntimeSeconds = tc.limits.RuntimeSeconds
			claims.Limits.TransferBytes = tc.limits.TransferBytes
			claims.Limits.Concurrency = tc.limits.Concurrency
			claims.Limits.RatePerMinute = tc.limits.RatePerMinute
			claims.Limits.Burst = tc.limits.Burst
			claims.Limits.MaxCallSeconds = tc.limits.MaxCallSeconds
			grant, err := verifyUsageGrant(
				signUsageClaims(t, privateKey, claims), publicKey, identity, now,
			)
			if err != nil {
				t.Fatalf("platform-defined %s policy: %v", tc.name, err)
			}
			if grant.PlanID != tc.planID || grant.Limits != tc.limits {
				t.Fatalf("verified grant = %+v", grant)
			}
		})
	}
	t.Run("signed operator extension", func(t *testing.T) {
		claims := starterClaims(now, "active")
		claims.Revision = 2
		claims.Limits.Calls += 5_000
		claims.Limits.RuntimeSeconds += 4 * 60 * 60
		claims.Limits.TransferBytes += 1 << 30
		claims.PeriodEnd = now.Add(60 * 24 * time.Hour).Format(time.RFC3339)
		grant, err := verifyUsageGrant(
			signUsageClaims(t, privateKey, claims), publicKey, identity, now,
		)
		if err != nil {
			t.Fatalf("operator extension: %v", err)
		}
		if grant.Limits.Calls != 15_000 ||
			grant.Limits.RuntimeSeconds != 43_200 ||
			grant.Limits.TransferBytes != 3<<30 {
			t.Fatalf("extended limits = %+v", grant.Limits)
		}
	})
}

func TestVerifyUsageGrantRejectsTamperingBindingExpiryAndOversizedPolicy(t *testing.T) {
	publicKey, privateKey := usageKeypair(t)
	_, wrongPrivateKey := usageKeypair(t)
	now := time.Now().UTC().Truncate(time.Second)
	identity := UsageIdentity{WorkspaceID: "workspace-one", EngineGeneration: 7}

	cases := []struct {
		name   string
		mutate func(*usageGrantClaims)
		key    ed25519.PrivateKey
	}{
		{"wrong signature", func(*usageGrantClaims) {}, wrongPrivateKey},
		{"issuer", func(c *usageGrantClaims) { c.Issuer = "attacker" }, privateKey},
		{"audience", func(c *usageGrantClaims) { c.Audience = "other" }, privateKey},
		{"workspace", func(c *usageGrantClaims) { c.WorkspaceID = "workspace-two" }, privateKey},
		{"generation", func(c *usageGrantClaims) { c.EngineGeneration++ }, privateKey},
		{"revision", func(c *usageGrantClaims) { c.Revision = 0 }, privateKey},
		{"plan", func(c *usageGrantClaims) { c.PlanID = "Pro" }, privateKey},
		{"status", func(c *usageGrantClaims) { c.Status = "past_due" }, privateKey},
		{"ended period", func(c *usageGrantClaims) {
			c.PeriodStart = now.Add(-2 * time.Hour).Format(time.RFC3339)
			c.PeriodEnd = now.Add(-time.Hour).Format(time.RFC3339)
		}, privateKey},
		{"future period", func(c *usageGrantClaims) {
			c.PeriodStart = now.Add(time.Hour).Format(time.RFC3339)
			c.PeriodEnd = now.Add(2 * time.Hour).Format(time.RFC3339)
		}, privateKey},
		{"expired assertion", func(c *usageGrantClaims) { c.ExpiresAt = now.Add(-time.Second).Unix() }, privateKey},
		{"future issued at", func(c *usageGrantClaims) { c.IssuedAt = now.Add(time.Hour).Unix() }, privateKey},
		{"expiry before issued at", func(c *usageGrantClaims) {
			c.IssuedAt = now.Add(time.Minute).Unix()
			c.ExpiresAt = now.Add(30 * time.Second).Unix()
		}, privateKey},
		{"negative calls", func(c *usageGrantClaims) { c.Limits.Calls = -1 }, privateKey},
		{"negative runtime", func(c *usageGrantClaims) { c.Limits.RuntimeSeconds = -1 }, privateKey},
		{"runtime overflow", func(c *usageGrantClaims) {
			c.Limits.RuntimeSeconds = maxRuntimeGrantSeconds + 1
		}, privateKey},
		{"negative transfer", func(c *usageGrantClaims) { c.Limits.TransferBytes = -1 }, privateKey},
		{"concurrency", func(c *usageGrantClaims) { c.Limits.Concurrency = maxUsageGrantConcurrency + 1 }, privateKey},
		{"rate", func(c *usageGrantClaims) { c.Limits.RatePerMinute = maxUsageGrantRatePerMinute + 1 }, privateKey},
		{"burst", func(c *usageGrantClaims) { c.Limits.Burst = maxUsageGrantBurst + 1 }, privateKey},
		{"deadline", func(c *usageGrantClaims) { c.Limits.MaxCallSeconds = maxUsageGrantMaxCallSeconds + 1 }, privateKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := starterClaims(now, "active")
			tc.mutate(&claims)
			if _, err := verifyUsageGrant(
				signUsageClaims(t, tc.key, claims), publicKey, identity, now,
			); err == nil {
				t.Fatal("invalid grant was accepted")
			}
		})
	}

	valid := signUsageClaims(t, privateKey, starterClaims(now, "active"))
	parts := strings.Split(valid, ".")
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	if _, err := verifyUsageGrant(strings.Join(parts, "."), publicKey, identity, now); err == nil {
		t.Fatal("tampered compact grant was accepted")
	}

	claimsMap := map[string]any{}
	raw, _ := json.Marshal(starterClaims(now, "active"))
	_ = json.Unmarshal(raw, &claimsMap)
	claimsMap["unexpected"] = true
	if _, err := verifyUsageGrant(
		signUsageClaims(t, privateKey, claimsMap), publicKey, identity, now,
	); err == nil {
		t.Fatal("unknown signed claim was accepted")
	}
}

func TestUsageGateApplyReportAndStructuredDenial(t *testing.T) {
	publicKey, privateKey := usageKeypair(t)
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubUsageStore{}
	gate, err := NewUsageGate(context.Background(), store, "workspace-one", 7, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	gate.now = func() time.Time { return now }
	report, err := gate.ApplyGrant(
		context.Background(),
		signUsageClaims(t, privateKey, starterClaims(now, "active")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != "enforced" || report.Status != "active" ||
		report.Limits.Calls != StarterPaidCalls || report.Remaining.Calls != StarterPaidCalls {
		t.Fatalf("report = %+v", report)
	}
	if store.recoveries < 2 { // constructor + report after apply
		t.Fatalf("recovery passes = %d, want constructor and report", store.recoveries)
	}

	denial := usageError("usage_calls_exhausted", "Monthly call allowance exhausted.")
	resetAt := now.Add(time.Hour)
	denial.Limit, denial.Used, denial.ResetAt = 10_000, 10_000, &resetAt
	result := UsageToolResult(denial)
	if !result.IsError {
		t.Fatal("quota denial must be an MCP tool error")
	}
	structured, ok := result.StructuredContent.(*UsageError)
	if !ok || structured.Code != "usage_calls_exhausted" || structured.Limit != 10_000 {
		t.Fatalf("structured denial = %#v", result.StructuredContent)
	}
}

func TestUsageReportRoundsRuntimeConservatively(t *testing.T) {
	now := time.Now().UTC()
	period := UsagePeriod{
		Grant: UsageGrant{
			Identity:    UsageIdentity{WorkspaceID: "w", EngineGeneration: 1},
			PeriodStart: now.Add(-time.Hour), PeriodEnd: now.Add(time.Hour),
			Revision: 2, PlanID: usageGrantPlan, Status: "active",
			Limits: UsageLimits{Calls: 10, RuntimeSeconds: 10, TransferBytes: 100},
		},
		CallsUsed: 3, RuntimeMilliseconds: 1_001, TransferBytesUsed: 25,
		ActiveReservations: 2, UpdatedAt: now,
	}
	report := usageReport(period)
	if report.Used.RuntimeSeconds != 2 || report.Remaining.RuntimeSeconds != 8 ||
		report.Remaining.Calls != 7 || report.Remaining.TransferBytes != 75 ||
		report.Reserved.Calls != 2 {
		t.Fatalf("report = %+v", report)
	}
}

func TestLimitMCPRequestBodyEnforcesCompleteOneMiBCap(t *testing.T) {
	called := 0
	handler := LimitMCPRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
		if len(body) != MaxMCPRequestBytes {
			t.Fatalf("accepted body bytes = %d", len(body))
		}
	}))

	exact := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", MaxMCPRequestBytes)))
	exactRec := httptest.NewRecorder()
	handler.ServeHTTP(exactRec, exact)
	if exactRec.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("exact cap = %d called=%d", exactRec.Code, called)
	}

	tooLarge := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", MaxMCPRequestBytes+1)))
	tooLargeRec := httptest.NewRecorder()
	handler.ServeHTTP(tooLargeRec, tooLarge)
	if tooLargeRec.Code != http.StatusRequestEntityTooLarge || called != 1 {
		t.Fatalf("over cap = %d called=%d body=%s", tooLargeRec.Code, called, tooLargeRec.Body)
	}
	var rpcError struct {
		Error struct {
			Data struct {
				Code       string `json:"code"`
				LimitBytes int    `json:"limitBytes"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(tooLargeRec.Body.Bytes(), &rpcError); err != nil {
		t.Fatal(err)
	}
	if rpcError.Error.Data.Code != "request_too_large" ||
		rpcError.Error.Data.LimitBytes != MaxMCPRequestBytes {
		t.Fatalf("oversize response = %+v", rpcError)
	}
}

func activeStubGate(t *testing.T, store *stubUsageStore, maxCallSeconds int64) *UsageGate {
	t.Helper()
	now := time.Now().UTC()
	identity := UsageIdentity{WorkspaceID: "workspace-one", EngineGeneration: 7}
	store.period = &UsagePeriod{Grant: UsageGrant{
		Identity: identity, PeriodStart: now.Add(-time.Hour), PeriodEnd: now.Add(time.Hour),
		ExpiresAt: now.Add(time.Hour), PlanID: usageGrantPlan, Status: "active", Revision: 1,
		Limits: UsageLimits{
			Calls: StarterPaidCalls, RuntimeSeconds: StarterPaidRuntimeSeconds,
			TransferBytes: StarterPaidTransferBytes, Concurrency: StarterMaxConcurrency,
			RatePerMinute: StarterRatePerMinute, Burst: StarterRateBurst,
			MaxCallSeconds: maxCallSeconds,
		},
	}}
	return &UsageGate{store: store, identity: identity, now: time.Now}
}

func TestDiscoveryDoesNotAdmitUsage(t *testing.T) {
	fileStore, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.Upsert(context.Background(), Account{
		Name: "remote", URL: "https://unused.example/mcp", AuthMode: "token",
	}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(
		fileStore,
		server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)),
	)
	usageStore := &stubUsageStore{}
	gateway.SetUsageGate(activeStubGate(t, usageStore, StarterMaxCallSeconds))
	gateway.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		return []mcp.Tool{mcp.NewTool("remote__run", mcp.WithDescription("run"))}, nil
	}
	if count := gateway.Aggregate(context.Background()); count != 1 {
		t.Fatalf("aggregate count = %d", count)
	}
	if usageStore.admissions != 0 || usageStore.settlements != 0 {
		t.Fatalf("tools/list consumed usage: admissions=%d settlements=%d",
			usageStore.admissions, usageStore.settlements)
	}
}

func TestGatewayCountsDispatchAndReplayButNotQuotaDenial(t *testing.T) {
	gateway, store, saves := newRecorderGateway(t)
	gateway.SetRecordPayloads(true)
	usageStore := &stubUsageStore{}
	gateway.SetUsageGate(activeStubGate(t, usageStore, StarterMaxCallSeconds))

	response := callMainTool(t, gateway, "linear__get_issue", map[string]any{"id": "42"})
	if !strings.Contains(response, "got-upstream") {
		t.Fatalf("call response = %s", response)
	}
	rows := callRows(t, store, "get_issue")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d", len(rows))
	}
	if _, err := gateway.Replay(context.Background(), rows[0].ID, false); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if usageStore.admissions != 2 || usageStore.settlements != 2 ||
		!usageStore.lastMeta.Replay || usageStore.lastBytes <= 0 {
		t.Fatalf("usage state = admissions %d settlements %d meta %+v bytes %d",
			usageStore.admissions, usageStore.settlements, usageStore.lastMeta, usageStore.lastBytes)
	}

	usageStore.admitErr = usageError("usage_calls_exhausted", "Monthly call allowance exhausted.")
	before := atomic.LoadInt32(saves)
	response = callMainTool(t, gateway, "linear__save_issue", map[string]any{"id": "43"})
	if !strings.Contains(response, `"isError":true`) ||
		!strings.Contains(response, "usage_calls_exhausted") {
		t.Fatalf("quota response = %s", response)
	}
	after := atomic.LoadInt32(saves)
	if after != before || usageStore.admissions != 2 || usageStore.settlements != 2 {
		t.Fatalf("denied call dispatched or counted: saves %d->%d admissions=%d settlements=%d",
			before, after, usageStore.admissions, usageStore.settlements)
	}
}

func newSingleToolUsageGateway(
	t *testing.T,
	handler server.ToolHandlerFunc,
	maxCallSeconds int64,
) (*Gateway, *stubUsageStore, *int32) {
	t.Helper()
	useLoopbackUpstreamTransport(t)
	var dispatches int32
	upstream := server.NewMCPServer("up", "0.0.0", server.WithToolCapabilities(true))
	upstream.AddTool(mcp.NewTool("run", mcp.WithDescription("run")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			atomic.AddInt32(&dispatches, 1)
			return handler(ctx, req)
		})
	testServer := server.NewTestStreamableHTTPServer(upstream)
	t.Cleanup(testServer.Close)
	fileStore, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.Upsert(context.Background(), Account{
		Name: "remote", URL: testServer.URL, AuthMode: "token", BearerToken: "token",
	}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(fileStore, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	if count := gateway.Aggregate(context.Background()); count != 1 {
		t.Fatalf("aggregate count = %d", count)
	}
	usageStore := &stubUsageStore{}
	gateway.SetUsageGate(activeStubGate(t, usageStore, maxCallSeconds))
	return gateway, usageStore, &dispatches
}

func TestGatewaySettlesUpstreamErrorsAndTimeouts(t *testing.T) {
	t.Run("upstream error", func(t *testing.T) {
		gateway, usageStore, dispatches := newSingleToolUsageGateway(
			t,
			func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, errors.New("upstream failed")
			},
			StarterMaxCallSeconds,
		)
		_ = callMainTool(t, gateway, "remote__run", nil)
		if atomic.LoadInt32(dispatches) != 1 ||
			usageStore.admissions != 1 || usageStore.settlements != 1 {
			t.Fatalf("error usage: dispatches=%d admissions=%d settlements=%d",
				atomic.LoadInt32(dispatches), usageStore.admissions, usageStore.settlements)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		gateway, usageStore, dispatches := newSingleToolUsageGateway(
			t,
			func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			1,
		)
		start := time.Now()
		_ = callMainTool(t, gateway, "remote__run", nil)
		elapsed := time.Since(start)
		if elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
			t.Fatalf("configured upstream deadline took %s", elapsed)
		}
		if atomic.LoadInt32(dispatches) != 1 ||
			usageStore.admissions != 1 || usageStore.settlements != 1 ||
			usageStore.lastRuntime < 900 {
			t.Fatalf("timeout usage: dispatches=%d admissions=%d settlements=%d runtime=%d",
				atomic.LoadInt32(dispatches), usageStore.admissions,
				usageStore.settlements, usageStore.lastRuntime)
		}
	})
}

func TestGatewayCapsCompleteResultOnRawMCP(t *testing.T) {
	huge := strings.Repeat("z", MaxMCPResultBytes+1024)
	gateway, usageStore, dispatches := newSingleToolUsageGateway(
		t,
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(huge), nil
		},
		StarterMaxCallSeconds,
	)
	response := callMainTool(t, gateway, "remote__run", nil)
	if strings.Contains(response, huge[:1024]) || !strings.Contains(response, "result_too_large") ||
		!strings.Contains(response, `"isError":true`) {
		t.Fatalf("oversize result was not replaced: response bytes=%d prefix=%s", len(response), response[:min(len(response), 500)])
	}
	if atomic.LoadInt32(dispatches) != 1 || usageStore.settlements != 1 ||
		usageStore.lastBytes <= MaxMCPResultBytes {
		t.Fatalf("oversize usage: dispatches=%d settlements=%d bytes=%d",
			atomic.LoadInt32(dispatches), usageStore.settlements, usageStore.lastBytes)
	}
}

func TestApprovalDenialDoesNotAdmitUsage(t *testing.T) {
	gateway, saves := newApprovalTestGateway(t)
	usageStore := &stubUsageStore{}
	gateway.SetUsageGate(activeStubGate(t, usageStore, StarterMaxCallSeconds))

	done := make(chan string, 1)
	go func() { done <- callConnectorTool(t, gateway, "work", "linear__save_issue") }()
	id := waitPendingID(t, gateway)
	if err := gateway.Decide(context.Background(), id, "denied"); err != nil {
		t.Fatal(err)
	}
	response := <-done
	if !strings.Contains(response, `"isError":true`) || atomic.LoadInt32(saves) != 0 {
		t.Fatalf("denied approval response=%s saves=%d", response, atomic.LoadInt32(saves))
	}
	if usageStore.admissions != 0 || usageStore.settlements != 0 {
		t.Fatalf("denied approval consumed usage: admissions=%d settlements=%d",
			usageStore.admissions, usageStore.settlements)
	}
}

func TestUsageControlEndpointsRequireAdminAndNeverEchoGrant(t *testing.T) {
	publicKey, privateKey := usageKeypair(t)
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubUsageStore{}
	gate, err := NewUsageGate(context.Background(), store, "workspace-one", 7, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	gate.now = func() time.Time { return now }
	const adminToken = "platform-machine-secret"
	mux := newAuthTestConsole(WithAdminToken(adminToken), WithUsageGate(gate))
	assertion := signUsageClaims(t, privateKey, starterClaims(now, "active"))
	body, _ := json.Marshal(map[string]string{"grant": assertion})

	if rec := requestStatus(mux, http.MethodPut, "/api/usage/grant", "", string(body)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed update = %d", rec.Code)
	}
	updated := requestStatus(mux, http.MethodPut, "/api/usage/grant", adminToken, string(body))
	if updated.Code != http.StatusOK {
		t.Fatalf("grant update = %d body=%s", updated.Code, updated.Body)
	}
	if strings.Contains(updated.Body.String(), assertion) {
		t.Fatal("usage response echoed bearer grant")
	}
	report := requestStatus(mux, http.MethodGet, "/api/usage", adminToken, "")
	if report.Code != http.StatusOK ||
		!strings.Contains(report.Body.String(), `"workspaceId":"workspace-one"`) ||
		!strings.Contains(report.Body.String(), `"calls":10000`) {
		t.Fatalf("usage report = %d body=%s", report.Code, report.Body)
	}
	if strings.Contains(report.Body.String(), "runtimeSeconds") ||
		!strings.Contains(report.Body.String(), `"runtime_seconds":28800`) {
		t.Fatalf("usage report did not use the Platform wire keys: %s", report.Body)
	}
	// Mirror Platform's strict report decoder. This catches accidental extra
	// fields or camelCase drift before a deployed Engine breaks reconciliation.
	var platformReport struct {
		Mode             string        `json:"mode"`
		WorkspaceID      string        `json:"workspaceId"`
		EngineGeneration int64         `json:"engineGeneration"`
		PlanID           string        `json:"planId"`
		Status           string        `json:"status"`
		PeriodStart      string        `json:"periodStart"`
		PeriodEnd        string        `json:"periodEnd"`
		Revision         int64         `json:"revision"`
		Limits           UsageLimits   `json:"limits"`
		Used             UsageAmounts  `json:"used"`
		Reserved         UsageReserved `json:"reserved"`
		Remaining        UsageAmounts  `json:"remaining"`
		UpdatedAt        string        `json:"updatedAt"`
	}
	decoder := json.NewDecoder(strings.NewReader(report.Body.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&platformReport); err != nil {
		t.Fatalf("Platform-compatible report decode: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing usage report JSON: %v", err)
	}
	if platformReport.WorkspaceID != "workspace-one" ||
		platformReport.EngineGeneration != 7 ||
		platformReport.PlanID != usageGrantPlan ||
		platformReport.Mode != "enforced" ||
		platformReport.Status != "active" ||
		platformReport.Revision != 1 {
		t.Fatalf("Platform-compatible report = %+v", platformReport)
	}
}
