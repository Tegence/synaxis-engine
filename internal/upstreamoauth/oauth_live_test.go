package upstreamoauth

import (
	"context"
	"testing"
)

// Live integration test against Notion's MCP OAuth. Run explicitly:
//
//	go test ./internal/upstreamoauth -run TestLiveNotion -v
func TestLiveNotion(t *testing.T) {
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
		ci, err := Register(ctx, m.RegistrationEndpoint, redirect)
		if err != nil {
			t.Logf("register redirect=%s -> REJECTED: %v", redirect, err)
			continue
		}
		t.Logf("register redirect=%s -> OK client_id=%s", redirect, ci.ClientID)
		pkce, state, _ := NewPKCE()
		t.Logf("  authorize URL: %s", AuthorizeURL(m, ci.ClientID, redirect, pkce.Challenge, state, ""))
	}
}
