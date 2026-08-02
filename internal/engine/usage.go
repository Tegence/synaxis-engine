package engine

// Hosted usage enforcement is deliberately an optional Engine boundary.
// Self-hosted Engines do not construct a UsageGate and remain unlimited. A
// hosted Engine constructs one with its Platform-issued workspace identity,
// immutable provisioning generation, and the same Ed25519 public key already
// used for hosted OAuth consent. The closed Platform signs allowances; the
// open-source Engine only verifies and enforces the generic grant.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	// Request/result caps apply to every MCP endpoint, including raw /mcp.
	MaxMCPRequestBytes = 1 << 20 // 1 MiB
	MaxMCPResultBytes  = 2 << 20 // 2 MiB

	// Base Starter allowances. Trusted, revisioned operator extensions may
	// raise these metered totals; the execution-safety ceilings below remain
	// hard Engine maxima.
	StarterPaidCalls           int64 = 10_000
	StarterPaidRuntimeSeconds  int64 = 8 * 60 * 60
	StarterPaidTransferBytes   int64 = 2 << 30
	StarterTrialCalls          int64 = 2_000
	StarterTrialRuntimeSeconds int64 = 2 * 60 * 60
	StarterTrialTransferBytes  int64 = 512 << 20

	StarterMaxConcurrency int64 = 4
	StarterRatePerMinute  int64 = 60
	StarterRateBurst      int64 = 10
	StarterMaxCallSeconds int64 = 120

	usageGrantIssuer   = "synaxis-platform"
	usageGrantAudience = "synaxis-engine"
	usageGrantPlan     = "starter-v1"
	usageGrantType     = "synaxis-engine-usage-grant+jwt"
	maxUsageGrantBytes = 16 << 10

	// Runtime is persisted in milliseconds. Bound the signed total before
	// multiplying so a trusted operator extension can never overflow int64.
	maxRuntimeGrantSeconds = int64(1<<63-1) / 1000
)

// UsageIdentity binds durable counters and signed grants to one immutable
// hosted Engine deployment.
type UsageIdentity struct {
	WorkspaceID      string
	EngineGeneration int64
}

// UsageLimits are the enforceable limits carried by a signed grant.
type UsageLimits struct {
	Calls          int64 `json:"calls"`
	RuntimeSeconds int64 `json:"runtime_seconds"`
	TransferBytes  int64 `json:"transfer_bytes"`
	Concurrency    int64 `json:"concurrency"`
	RatePerMinute  int64 `json:"rate_per_minute"`
	Burst          int64 `json:"burst"`
	MaxCallSeconds int64 `json:"max_call_seconds"`
}

// usageGrantClaims is the compact JWT/JWS payload signed by Platform. Claim
// names are snake_case to keep the wire contract independent of Go's API DTOs.
type usageGrantClaims struct {
	Issuer           string `json:"iss"`
	Audience         string `json:"aud"`
	WorkspaceID      string `json:"workspace_id"`
	EngineGeneration int64  `json:"engine_generation"`
	PeriodStart      string `json:"period_start"`
	PeriodEnd        string `json:"period_end"`
	Revision         int64  `json:"revision"`
	PlanID           string `json:"plan_id"`
	Status           string `json:"status"`
	Limits           struct {
		Calls          int64 `json:"calls"`
		RuntimeSeconds int64 `json:"runtime_seconds"`
		TransferBytes  int64 `json:"transfer_bytes"`
		Concurrency    int64 `json:"concurrency"`
		RatePerMinute  int64 `json:"rate_per_minute"`
		Burst          int64 `json:"burst"`
		MaxCallSeconds int64 `json:"max_call_seconds"`
	} `json:"limits"`
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// UsageGrant is the verified, persistence-ready form of a signed allowance.
// Digest identifies the assertion without storing the bearer token; stable
// policy fields, rather than the digest, bind a revision because Platform
// periodically re-signs that revision with a later short-lived expiry.
type UsageGrant struct {
	Identity    UsageIdentity
	PeriodStart time.Time
	PeriodEnd   time.Time
	Revision    int64
	PlanID      string
	Status      string
	Limits      UsageLimits
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Digest      string
}

// UsagePeriod is the store's authoritative aggregate. RuntimeMilliseconds is
// kept internally so admission does not lose sub-second calls; the public API
// reports whole seconds.
type UsagePeriod struct {
	Grant               UsageGrant
	CallsUsed           int64
	RuntimeMilliseconds int64
	TransferBytesUsed   int64
	ActiveReservations  int64
	UpdatedAt           time.Time
}

type UsageReservation struct {
	ID             string
	PeriodStart    time.Time
	AdmittedAt     time.Time
	MaxCallSeconds int64
}

type UsageCallMeta struct {
	Account   string
	Tool      string
	Connector string
	Replay    bool
}

// UsageStore is synchronous and authoritative. AuditSink is intentionally not
// involved: audit writes are best-effort, while quota admission and settlement
// must survive process failure.
type UsageStore interface {
	ApplyUsageGrant(context.Context, UsageGrant) error
	CurrentUsage(context.Context, UsageIdentity, time.Time) (UsagePeriod, bool, error)
	AdmitUsage(context.Context, UsageIdentity, time.Time, UsageCallMeta) (UsageReservation, error)
	SettleUsage(context.Context, UsageIdentity, string, time.Time, int64, int64) error
	RecoverUsageReservations(context.Context, UsageIdentity, time.Time) (int64, error)
}

// UsageError is returned for a policy denial or an unavailable authoritative
// meter. MCP callers receive it as an isError tool result with the same
// machine-readable fields in structuredContent.
type UsageError struct {
	Code              string     `json:"code"`
	Message           string     `json:"message"`
	ResetAt           *time.Time `json:"resetAt,omitempty"`
	RetryAfterSeconds int64      `json:"retryAfterSeconds,omitempty"`
	Limit             int64      `json:"limit,omitempty"`
	Used              int64      `json:"used,omitempty"`
}

func (e *UsageError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func usageError(code, message string) *UsageError {
	return &UsageError{Code: code, Message: message}
}

// UsageAmounts is the sanitized API shape for consumed and remaining quota.
type UsageAmounts struct {
	Calls          int64 `json:"calls"`
	RuntimeSeconds int64 `json:"runtime_seconds"`
	TransferBytes  int64 `json:"transfer_bytes"`
}

type UsageReserved struct {
	Calls int64 `json:"calls"`
}

// UsageReport contains no grant assertion, signing material, account names, or
// per-call payloads. It is safe for Platform to expose to the workspace UI.
type UsageReport struct {
	Mode             string        `json:"mode"`
	WorkspaceID      string        `json:"workspaceId,omitempty"`
	EngineGeneration int64         `json:"engineGeneration,omitempty"`
	PlanID           string        `json:"planId,omitempty"`
	Status           string        `json:"status"`
	PeriodStart      *time.Time    `json:"periodStart,omitempty"`
	PeriodEnd        *time.Time    `json:"periodEnd,omitempty"`
	Revision         int64         `json:"revision,omitempty"`
	Limits           UsageLimits   `json:"limits"`
	Used             UsageAmounts  `json:"used"`
	Reserved         UsageReserved `json:"reserved"`
	Remaining        UsageAmounts  `json:"remaining"`
	UpdatedAt        *time.Time    `json:"updatedAt,omitempty"`
}

// UsageGate verifies signed grants and delegates every state transition to its
// durable store. now is a test seam.
type UsageGate struct {
	store     UsageStore
	identity  UsageIdentity
	publicKey ed25519.PublicKey
	now       func() time.Time
}

func NewUsageGate(
	ctx context.Context,
	store UsageStore,
	workspaceID string,
	engineGeneration int64,
	publicKey ed25519.PublicKey,
) (*UsageGate, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if store == nil {
		return nil, errors.New("usage store is required")
	}
	if workspaceID == "" {
		return nil, errors.New("usage workspace ID is required")
	}
	if engineGeneration <= 0 {
		return nil, errors.New("usage engine generation must be positive")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("usage Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	key := append(ed25519.PublicKey(nil), publicKey...)
	g := &UsageGate{
		store: store,
		identity: UsageIdentity{
			WorkspaceID: workspaceID, EngineGeneration: engineGeneration,
		},
		publicKey: key,
		now:       time.Now,
	}
	if _, err := store.RecoverUsageReservations(ctx, g.identity, g.now()); err != nil {
		return nil, fmt.Errorf("recover usage reservations: %w", err)
	}
	return g, nil
}

func (g *UsageGate) Identity() UsageIdentity { return g.identity }

func (g *UsageGate) ApplyGrant(ctx context.Context, assertion string) (UsageReport, error) {
	now := g.now()
	grant, err := verifyUsageGrant(assertion, g.publicKey, g.identity, now)
	if err != nil {
		return UsageReport{}, err
	}
	if err := g.store.ApplyUsageGrant(ctx, grant); err != nil {
		return UsageReport{}, err
	}
	return g.Report(ctx)
}

func (g *UsageGate) Report(ctx context.Context) (UsageReport, error) {
	now := g.now()
	if _, err := g.store.RecoverUsageReservations(ctx, g.identity, now); err != nil {
		return UsageReport{}, err
	}
	period, ok, err := g.store.CurrentUsage(ctx, g.identity, now)
	if err != nil {
		return UsageReport{}, err
	}
	if !ok {
		return UsageReport{
			Mode: "enforced", WorkspaceID: g.identity.WorkspaceID,
			EngineGeneration: g.identity.EngineGeneration, Status: "grant_required",
		}, nil
	}
	return usageReport(period), nil
}

func usageReport(period UsagePeriod) UsageReport {
	usedRuntimeSeconds := ceilMilliseconds(period.RuntimeMilliseconds)
	remainingRuntimeMilliseconds := period.Grant.Limits.RuntimeSeconds*1000 - period.RuntimeMilliseconds
	if remainingRuntimeMilliseconds < 0 {
		remainingRuntimeMilliseconds = 0
	}
	remainingCalls := period.Grant.Limits.Calls - period.CallsUsed
	if remainingCalls < 0 {
		remainingCalls = 0
	}
	remainingTransfer := period.Grant.Limits.TransferBytes - period.TransferBytesUsed
	if remainingTransfer < 0 {
		remainingTransfer = 0
	}
	start, end, updated := period.Grant.PeriodStart, period.Grant.PeriodEnd, period.UpdatedAt
	return UsageReport{
		Mode: "enforced", WorkspaceID: period.Grant.Identity.WorkspaceID,
		EngineGeneration: period.Grant.Identity.EngineGeneration,
		PlanID:           period.Grant.PlanID, Status: period.Grant.Status,
		PeriodStart: &start, PeriodEnd: &end, Revision: period.Grant.Revision,
		Limits: period.Grant.Limits,
		Used: UsageAmounts{
			Calls: period.CallsUsed, RuntimeSeconds: usedRuntimeSeconds,
			TransferBytes: period.TransferBytesUsed,
		},
		Reserved: UsageReserved{Calls: period.ActiveReservations},
		Remaining: UsageAmounts{
			Calls:          remainingCalls,
			RuntimeSeconds: remainingRuntimeMilliseconds / 1000,
			TransferBytes:  remainingTransfer,
		},
		UpdatedAt: &updated,
	}
}

func ceilMilliseconds(ms int64) int64 {
	if ms <= 0 {
		return 0
	}
	seconds := ms / 1000
	if ms%1000 != 0 {
		seconds++
	}
	return seconds
}

func (g *UsageGate) Admit(ctx context.Context, meta UsageCallMeta) (UsageReservation, error) {
	reservation, err := g.store.AdmitUsage(ctx, g.identity, g.now(), meta)
	if err == nil {
		return reservation, nil
	}
	var denied *UsageError
	if errors.As(err, &denied) {
		return UsageReservation{}, denied
	}
	return UsageReservation{}, usageError(
		"usage_meter_unavailable",
		"Hosted usage could not be verified. Try again shortly.",
	)
}

func (g *UsageGate) Settle(
	ctx context.Context,
	reservation UsageReservation,
	runtime time.Duration,
	transferBytes int64,
) error {
	runtimeMilliseconds := runtime.Milliseconds()
	if runtime > 0 && runtimeMilliseconds == 0 {
		runtimeMilliseconds = 1
	}
	if runtimeMilliseconds < 0 {
		runtimeMilliseconds = 0
	}
	if max := reservation.MaxCallSeconds * 1000; max > 0 && runtimeMilliseconds > max {
		runtimeMilliseconds = max
	}
	if transferBytes < 0 {
		transferBytes = 0
	}
	if err := g.store.SettleUsage(
		ctx, g.identity, reservation.ID, g.now(), runtimeMilliseconds, transferBytes,
	); err != nil {
		return usageError(
			"usage_meter_unavailable",
			"The tool ran, but hosted usage could not be settled. Retry later to avoid a duplicate action.",
		)
	}
	return nil
}

func verifyUsageGrant(
	assertion string,
	publicKey ed25519.PublicKey,
	identity UsageIdentity,
	now time.Time,
) (UsageGrant, error) {
	if assertion == "" || len(assertion) > maxUsageGrantBytes {
		return UsageGrant{}, errors.New("usage grant is missing or too large")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return UsageGrant{}, errors.New("usage grant must be a compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return UsageGrant{}, errors.New("usage grant has an invalid header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ,omitempty"`
	}
	if err := decodeStrictJSON(headerBytes, &header); err != nil ||
		header.Algorithm != "EdDSA" || header.Type != usageGrantType {
		return UsageGrant{}, errors.New("usage grant requires an EdDSA JWT header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return UsageGrant{}, errors.New("usage grant signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return UsageGrant{}, errors.New("usage grant has an invalid payload")
	}
	var claims usageGrantClaims
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return UsageGrant{}, errors.New("usage grant claims are invalid")
	}
	start, err := time.Parse(time.RFC3339, claims.PeriodStart)
	if err != nil {
		return UsageGrant{}, errors.New("usage grant period_start must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, claims.PeriodEnd)
	if err != nil {
		return UsageGrant{}, errors.New("usage grant period_end must be RFC3339")
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	const clockSkew = 2 * time.Minute
	switch {
	case claims.Issuer != usageGrantIssuer:
		return UsageGrant{}, errors.New("usage grant issuer is invalid")
	case claims.Audience != usageGrantAudience:
		return UsageGrant{}, errors.New("usage grant audience is invalid")
	case claims.WorkspaceID != identity.WorkspaceID:
		return UsageGrant{}, errors.New("usage grant workspace does not match this Engine")
	case claims.EngineGeneration != identity.EngineGeneration:
		return UsageGrant{}, errors.New("usage grant generation does not match this Engine")
	case claims.Revision <= 0:
		return UsageGrant{}, errors.New("usage grant revision must be positive")
	case claims.PlanID != usageGrantPlan:
		return UsageGrant{}, errors.New("usage grant plan is unsupported")
	case claims.Status != "trialing" && claims.Status != "active":
		return UsageGrant{}, errors.New("usage grant status is not enforceable")
	case !end.After(start):
		return UsageGrant{}, errors.New("usage grant period is invalid")
	case now.Before(start.Add(-clockSkew)):
		return UsageGrant{}, errors.New("usage grant period has not started")
	case !now.Before(end):
		return UsageGrant{}, errors.New("usage grant period has ended")
	case claims.IssuedAt <= 0 || issuedAt.After(now.Add(clockSkew)):
		return UsageGrant{}, errors.New("usage grant issued-at time is invalid")
	case claims.ExpiresAt <= 0 || !expiresAt.After(now):
		return UsageGrant{}, errors.New("usage grant has expired")
	case !expiresAt.After(issuedAt):
		return UsageGrant{}, errors.New("usage grant expiry must follow issued-at time")
	}
	limits := UsageLimits{
		Calls: claims.Limits.Calls, RuntimeSeconds: claims.Limits.RuntimeSeconds,
		TransferBytes: claims.Limits.TransferBytes, Concurrency: claims.Limits.Concurrency,
		RatePerMinute: claims.Limits.RatePerMinute, Burst: claims.Limits.Burst,
		MaxCallSeconds: claims.Limits.MaxCallSeconds,
	}
	if err := validateUsageLimits(limits); err != nil {
		return UsageGrant{}, err
	}
	digest := sha256.Sum256([]byte(assertion))
	return UsageGrant{
		Identity: identity, PeriodStart: start.UTC(), PeriodEnd: end.UTC(),
		Revision: claims.Revision, PlanID: claims.PlanID, Status: claims.Status,
		Limits: limits, IssuedAt: issuedAt.UTC(), ExpiresAt: expiresAt.UTC(),
		Digest: hex.EncodeToString(digest[:]),
	}, nil
}

func validateUsageLimits(limits UsageLimits) error {
	switch {
	case limits.Calls < 0:
		return errors.New("usage grant calls cannot be negative")
	case limits.RuntimeSeconds < 0 || limits.RuntimeSeconds > maxRuntimeGrantSeconds:
		return fmt.Errorf("usage grant runtime_seconds must be between 0 and %d", maxRuntimeGrantSeconds)
	case limits.TransferBytes < 0:
		return errors.New("usage grant transfer_bytes cannot be negative")
	case limits.Concurrency <= 0 || limits.Concurrency > StarterMaxConcurrency:
		return fmt.Errorf("usage grant concurrency must be between 1 and %d", StarterMaxConcurrency)
	case limits.RatePerMinute <= 0 || limits.RatePerMinute > StarterRatePerMinute:
		return fmt.Errorf("usage grant rate_per_minute must be between 1 and %d", StarterRatePerMinute)
	case limits.Burst <= 0 || limits.Burst > StarterRateBurst:
		return fmt.Errorf("usage grant burst must be between 1 and %d", StarterRateBurst)
	case limits.Burst > limits.RatePerMinute:
		return errors.New("usage grant burst cannot exceed rate_per_minute")
	case limits.MaxCallSeconds <= 0 || limits.MaxCallSeconds > StarterMaxCallSeconds:
		return fmt.Errorf("usage grant max_call_seconds must be between 1 and %d", StarterMaxCallSeconds)
	}
	return nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

// UsageToolResult converts a quota denial into an MCP tool error (not a
// protocol error), allowing Claude/Codex to explain the limit and self-correct.
func UsageToolResult(err error) *mcp.CallToolResult {
	var usageErr *UsageError
	if !errors.As(err, &usageErr) {
		usageErr = usageError("usage_meter_unavailable", "Hosted usage could not be verified. Try again shortly.")
	}
	result := mcp.NewToolResultError(usageErr.Message)
	result.StructuredContent = usageErr
	return result
}

func resultLimitToolResult() *mcp.CallToolResult {
	result := mcp.NewToolResultError("The upstream tool result exceeded the 2 MiB Engine safety limit and was not returned.")
	result.StructuredContent = map[string]any{
		"code": "result_too_large", "limitBytes": MaxMCPResultBytes,
	}
	return result
}

// LimitMCPRequestBody bounds mcp-go's eager body buffering and returns a
// standard JSON-RPC error before parsing when the complete request exceeds
// 1 MiB. Mount it inside OAuth authentication so unauthorized bodies are not
// read by this middleware.
func LimitMCPRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > MaxMCPRequestBytes {
			writeMCPBodyError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				"The MCP request exceeds the 1 MiB Engine safety limit.")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxMCPRequestBytes+1))
		_ = r.Body.Close()
		if err != nil {
			writeMCPBodyError(w, http.StatusBadRequest, "request_read_failed",
				"The MCP request body could not be read.")
			return
		}
		if len(body) > MaxMCPRequestBytes {
			writeMCPBodyError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				"The MCP request exceeds the 1 MiB Engine safety limit.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

func writeMCPBodyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error": map[string]any{
			"code": -32600, "message": message,
			"data": map[string]any{"code": code, "limitBytes": MaxMCPRequestBytes},
		},
	})
}
