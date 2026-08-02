package oauthas

import (
	"context"
	"strings"
	"testing"
)

// Access tokens are bound to the resource path they were authorized for —
// a token minted for a curated connector (/mcp/work) must not open the
// ungated aggregate endpoint (/mcp), or approval gating and connector
// allowlists are bypassable with the same bearer token.
func TestAccessTokenResourceBinding(t *testing.T) {
	s := New("https://gw.example.com", "pw", "secret-0123456789")

	cases := []struct {
		name     string
		resource string // RFC 8707 resource param at authorization time
		path     string // request path presented with the token
		want     bool
	}{
		{"connector token on its own path", "https://gw.example.com/mcp/work", "/mcp/work", true},
		{"connector token rejected on /mcp", "https://gw.example.com/mcp/work", "/mcp", false},
		{"connector token rejected on another connector", "https://gw.example.com/mcp/work", "/mcp/home", false},
		{"main token on /mcp", "https://gw.example.com/mcp", "/mcp", true},
		{"main token rejected on connector", "https://gw.example.com/mcp", "/mcp/work", false},
		{"no resource param binds to /mcp", "", "/mcp", true},
		{"no resource param rejected on connector", "", "/mcp/work", false},
		{"trailing slash normalized", "https://gw.example.com/mcp/work/", "/mcp/work", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok, _ := s.signAccess("client-1", c.resource)
			if got := s.validAccess(tok, c.path); got != c.want {
				t.Fatalf("validAccess(token bound to %q, path %q) = %v, want %v", c.resource, c.path, got, c.want)
			}
		})
	}
}

func TestAccessTokenTamperedResourceRejected(t *testing.T) {
	s := New("https://gw.example.com", "pw", "secret-0123456789")
	tok, _ := s.signAccess("client-1", "https://gw.example.com/mcp/work")
	// Re-bind the resource segment without re-signing: signature must fail.
	forged, _ := s.signAccess("client-1", "https://gw.example.com/mcp")
	parts1, parts2 := strings.Split(tok, "."), strings.Split(forged, ".")
	tampered := parts1[0] + "." + parts1[1] + "." + parts1[2] + "." + parts2[3]
	if s.validAccess(tampered, "/mcp") {
		t.Fatal("token with swapped resource segment must not validate")
	}
	// Legacy 3-part tokens (pre-binding) are rejected outright.
	legacy := parts1[0] + "." + parts1[1] + "." + parts1[2]
	if s.validAccess(legacy, "/mcp/work") {
		t.Fatal("legacy unbound token must not validate")
	}
}

// Deleting a connector must revoke its outstanding tokens: access tokens are
// invalidated by the epoch check (a deleted path no longer resolves, and a
// recreated slug carries a FRESH epoch), and RevokeResource drops the path's
// refresh grants so they can't mint new access tokens.
func TestConnectorEpochRevocation(t *testing.T) {
	epochs := map[string]string{"/mcp": "root", "/mcp/team": "epoch-1"}
	s := New("https://gw.example.com", "pw", "secret-0123456789")
	s.SetEpochLookup(func(path string) (string, bool) {
		e, ok := epochs[path]
		return e, ok
	})

	tok, ok := s.signAccess("client-1", "https://gw.example.com/mcp/team")
	if !ok {
		t.Fatal("mint for a live connector must succeed")
	}
	if !s.validAccess(tok, "/mcp/team") {
		t.Fatal("token must validate while the connector exists")
	}

	// Pre-authorization: a path with no connector can't be minted for at all.
	if _, ok := s.signAccess("client-1", "https://gw.example.com/mcp/notyet"); ok {
		t.Fatal("mint for a nonexistent connector must fail")
	}

	// Delete the connector: the outstanding token dies (fail closed).
	delete(epochs, "/mcp/team")
	if s.validAccess(tok, "/mcp/team") {
		t.Fatal("token must not validate after its connector is deleted")
	}
	if _, ok := s.signAccess("client-1", "https://gw.example.com/mcp/team"); ok {
		t.Fatal("refresh-minting for a deleted connector must fail")
	}

	// Recreate the slug with a fresh epoch: the OLD token stays dead, a newly
	// minted one works.
	epochs["/mcp/team"] = "epoch-2"
	if s.validAccess(tok, "/mcp/team") {
		t.Fatal("pre-deletion token must not validate against a recreated slug")
	}
	tok2, ok := s.signAccess("client-1", "https://gw.example.com/mcp/team")
	if !ok || !s.validAccess(tok2, "/mcp/team") {
		t.Fatal("token minted under the new epoch must validate")
	}

	// RevokeResource drops refresh grants for exactly that path.
	s.mu.Lock()
	s.refresh["rt-team"] = refreshGrant{clientID: "client-1", resource: "/mcp/team"}
	s.refresh["rt-root"] = refreshGrant{clientID: "client-1", resource: "/mcp"}
	s.mu.Unlock()
	s.RevokeResource("/mcp/team")
	s.mu.Lock()
	_, teamLeft := s.refresh["rt-team"]
	_, rootLeft := s.refresh["rt-root"]
	s.mu.Unlock()
	if teamLeft {
		t.Fatal("refresh grant for the deleted connector must be revoked")
	}
	if !rootLeft {
		t.Fatal("refresh grants for other resources must survive")
	}
}

func TestRevokeAllInvalidatesWorkspaceAccessAndRefreshGrants(t *testing.T) {
	s := New("https://gw.example.com", "pw", "secret-0123456789")
	s.SetEpochLookup(func(path string) (string, bool) {
		return "resource-epoch", path == "/mcp"
	})

	token, ok := s.signAccess("client-1", "https://gw.example.com/mcp")
	if !ok || !s.validAccess(token, "/mcp") {
		t.Fatal("pre-revocation token must be valid")
	}
	s.mu.Lock()
	s.refresh["rt-root"] = refreshGrant{clientID: "client-1", resource: "/mcp"}
	s.codes["code-root"] = authCode{clientID: "client-1", resource: "/mcp"}
	s.mu.Unlock()

	if err := s.RevokeAll(context.Background()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if s.validAccess(token, "/mcp") {
		t.Fatal("workspace-wide revocation must invalidate outstanding access tokens")
	}
	s.mu.Lock()
	refreshCount := len(s.refresh)
	codeCount := len(s.codes)
	s.mu.Unlock()
	if refreshCount != 0 || codeCount != 0 {
		t.Fatalf("workspace-wide revocation left refresh=%d codes=%d", refreshCount, codeCount)
	}
	newToken, ok := s.signAccess("client-1", "https://gw.example.com/mcp")
	if !ok || !s.validAccess(newToken, "/mcp") {
		t.Fatal("legitimate members must be able to reauthorize after revocation")
	}
}
