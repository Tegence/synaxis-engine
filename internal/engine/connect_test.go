package engine

import (
	"net/url"
	"strings"
	"testing"

	"narthex/backend/internal/upstreamoauth"
)

// TestStaticConnectSeam exercises the observable seam of the static-client
// connect path WITHOUT hitting the network. StartConnect's first step is
// Discover, which the upstreamoauth SSRF-guarded httpClient blocks against
// loopback, so we cannot stand up a real authorization server here. Instead we
// verify the two building blocks StartConnect composes on the sc!=nil branch:
//
//  1. StaticClient(id, secret) returns a ClientInfo carrying those exact creds
//     (which StartConnect stashes into pendingConnect -> Account), and
//  2. AuthorizeURL(meta, id, ..., scope) emits client_id=id and scope=<scope>
//     (StartConnect passes sc.ClientID and sc.Scope through unchanged).
//
// Together these prove that a *StaticCreds threads its client_id and scope into
// the authorize URL and the persisted account, distinct from the DCR path.
func TestStaticConnectSeam(t *testing.T) {
	meta := &upstreamoauth.Metadata{
		Resource:              "https://api.example.com/mcp",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}

	cases := []struct {
		name         string
		clientID     string
		clientSecret string
		scope        string
		wantScopeQP  string // expected scope query param value; "" means absent
	}{
		{
			name:         "id+secret+scope",
			clientID:     "pre-registered-id",
			clientSecret: "shhh-secret",
			scope:        "mcp:connect",
			wantScopeQP:  "mcp:connect",
		},
		{
			name:         "public client, empty secret, still scoped",
			clientID:     "public-id",
			clientSecret: "",
			scope:        "read write",
			wantScopeQP:  "read write",
		},
		{
			name:         "no scope -> omitted (matches DCR shape)",
			clientID:     "some-id",
			clientSecret: "s",
			scope:        "",
			wantScopeQP:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ci, err := upstreamoauth.StaticClient(tc.clientID, tc.clientSecret)
			if err != nil {
				t.Fatalf("StaticClient: %v", err)
			}
			if ci.ClientID != tc.clientID {
				t.Errorf("ClientID = %q; want %q", ci.ClientID, tc.clientID)
			}
			if ci.ClientSecret != tc.clientSecret {
				t.Errorf("ClientSecret = %q; want %q", ci.ClientSecret, tc.clientSecret)
			}

			u := upstreamoauth.AuthorizeURL(meta, ci.ClientID, "https://console.example/cb", "chal", "state123", tc.scope)

			if !strings.Contains(u, "client_id="+tc.clientID) {
				t.Errorf("authorize URL missing client_id=%s: %s", tc.clientID, u)
			}
			if tc.wantScopeQP == "" {
				if strings.Contains(u, "scope=") {
					t.Errorf("authorize URL should omit scope for empty scope: %s", u)
				}
			} else {
				parsed, err := url.Parse(u)
				if err != nil {
					t.Fatalf("parse authorize URL %q: %v", u, err)
				}
				if got := parsed.Query().Get("scope"); got != tc.wantScopeQP {
					t.Errorf("scope query = %q; want %q (url=%s)", got, tc.wantScopeQP, u)
				}
			}
		})
	}
}
