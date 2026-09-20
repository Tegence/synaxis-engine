package upstreamoauth

import (
	"context"
	"os"
	"testing"
)

// Live integration test against Notion's MCP OAuth. Run explicitly:
//
//	SYNAXIS_LIVE_OAUTH_TESTS=1 go test ./internal/upstreamoauth -run TestLiveNotion -v
func TestLiveNotion(t *testing.T) {
	if os.Getenv("SYNAXIS_LIVE_OAUTH_TESTS") != "1" {
		t.Skip("set SYNAXIS_LIVE_OAUTH_TESTS=1 to register a real upstream OAuth client")
	}
	ctx := context.Background()
	m, err := Discover(ctx, "https://mcp.notion.com/mcp")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	t.Logf("resource=%s authorize=%s token=%s register=%s",
		m.Resource, m.AuthorizationEndpoint, m.TokenEndpoint, m.RegistrationEndpoint)

	for _, redirect := range []string{
		"http://localhost:8080/api/oauth/callback",
		"https://metamcp-x5xnmhemja-uc.a.run.app/api/oauth/callback",
	} {
		ci, err := RegisterDiscoveredClient(ctx, m, redirect)
		if err != nil {
			t.Logf("register redirect=%s -> REJECTED: %v", redirect, err)
			continue
		}
		t.Logf("register redirect=%s -> OK client_id=%s", redirect, ci.ClientID)
		pkce, state, _ := NewPKCE()
		t.Logf("  authorize URL: %s", AuthorizeURL(m, ci.ClientID, redirect, pkce.Challenge, state, m.Scope, nil))
	}
}
