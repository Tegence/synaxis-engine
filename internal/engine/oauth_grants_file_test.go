package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"narthex/backend/internal/oauthas"
)

func TestFileStoreOAuthGrantsAndConsentReplaysSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	code := oauthas.DurableAuthorizationCode{
		TokenHash: "code-hash-that-is-long-enough-to-be-opaque-001",
		ClientID:  "client-1", RedirectURI: "https://client.example/callback",
		Challenge: "challenge", Scope: "mcp", Resource: "/mcp/team",
		ResourceEpoch: "team-v1", Generation: "workspace-v1", ExpiresAt: now.Add(time.Minute),
	}
	refresh := oauthas.DurableRefreshGrant{
		TokenHash: "refresh-hash-that-is-long-enough-to-be-opaque-01",
		ClientID:  "client-1", Resource: "/mcp/team", ResourceEpoch: "team-v1",
		Generation: "workspace-v1", ExpiresAt: now.Add(time.Hour),
	}
	replacementRefresh := oauthas.DurableRefreshGrant{
		TokenHash: "replacement-refresh-hash-long-enough-to-be-opaque-02",
		ClientID:  "client-1", Resource: "/mcp/team", ResourceEpoch: "team-v2",
		Generation: "workspace-v1", ExpiresAt: now.Add(time.Hour),
	}

	first, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.StoreAuthorizationCode(ctx, code); err != nil {
		t.Fatalf("StoreAuthorizationCode: %v", err)
	}
	if err := first.StoreRefreshGrant(ctx, refresh); err != nil {
		t.Fatalf("StoreRefreshGrant: %v", err)
	}
	if err := first.StoreRefreshGrant(ctx, replacementRefresh); err != nil {
		t.Fatalf("StoreRefreshGrant replacement: %v", err)
	}
	reserved, err := first.ReserveHostedConsentReplay(
		ctx,
		"reservation-opaque-identifier",
		"approval:opaque-jti-0001",
		"request:opaque-hash-0001",
		now.Add(time.Minute),
		now,
	)
	if err != nil || !reserved {
		t.Fatalf("ReserveHostedConsentReplay = %v, %v", reserved, err)
	}

	restarted, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore after restart: %v", err)
	}
	gotCode, found, err := restarted.ConsumeAuthorizationCode(ctx, code.TokenHash, now)
	if err != nil || !found || gotCode.ClientID != code.ClientID || gotCode.ResourceEpoch != code.ResourceEpoch {
		t.Fatalf("durable code after restart = %+v found=%v err=%v", gotCode, found, err)
	}
	if _, found, err := restarted.ConsumeAuthorizationCode(ctx, code.TokenHash, now); err != nil || found {
		t.Fatalf("authorization code replay after restart found=%v err=%v", found, err)
	}
	gotRefresh, found, err := restarted.LoadRefreshGrant(ctx, refresh.TokenHash, now)
	if err != nil || !found || gotRefresh.Generation != refresh.Generation {
		t.Fatalf("durable refresh after restart = %+v found=%v err=%v", gotRefresh, found, err)
	}
	if reserved, err := restarted.ReserveHostedConsentReplay(
		ctx,
		"another-reservation-opaque-id",
		"approval:opaque-jti-0001",
		"request:another-opaque-hash",
		now.Add(time.Minute),
		now,
	); err != nil || reserved {
		t.Fatalf("replayed hosted approval reservation = %v, %v", reserved, err)
	}
	if err := restarted.FinalizeHostedConsentReplay(ctx, "reservation-opaque-identifier"); err != nil {
		t.Fatalf("FinalizeHostedConsentReplay: %v", err)
	}
	if err := restarted.RevokeOAuthGrantsForResourceEpoch(ctx, "/mcp/team", "team-v1"); err != nil {
		t.Fatalf("RevokeOAuthGrantsForResourceEpoch: %v", err)
	}
	if _, found, err := restarted.LoadRefreshGrant(ctx, replacementRefresh.TokenHash, now); err != nil || !found {
		t.Fatalf("replacement-epoch refresh after cleanup found=%v err=%v", found, err)
	}

	third, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("second restart: %v", err)
	}
	if _, found, err := third.LoadRefreshGrant(ctx, refresh.TokenHash, now); err != nil || found {
		t.Fatalf("resource-revoked refresh after restart found=%v err=%v", found, err)
	}
	if _, found, err := third.LoadRefreshGrant(ctx, replacementRefresh.TokenHash, now); err != nil || !found {
		t.Fatalf("replacement refresh after restart found=%v err=%v", found, err)
	}
	if err := third.RevokeAllOAuthGrants(ctx); err != nil {
		t.Fatalf("RevokeAllOAuthGrants: %v", err)
	}
}
