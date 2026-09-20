package engine

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

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
//  2. AuthorizeURL(meta, id, ..., scope, extras) emits client_id=id and scope=<scope>
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

			u := upstreamoauth.AuthorizeURL(meta, ci.ClientID, "https://console.example/cb", "chal", "state123", tc.scope, nil)

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

func TestEffectiveStaticCredsReusesPersistedGmailClientWithOfflineConsent(t *testing.T) {
	const secret = "stored-secret"
	persisted := Account{
		URL:          gmailMCPURL,
		ClientID:     "gmail-client-id",
		ClientSecret: secret,
		Scope:        "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose",
	}
	got := effectiveStaticCreds(nil, persisted, true, gmailMCPURL+"/")
	if got == nil {
		t.Fatal("expected persisted static OAuth client to be reused")
	}
	if got.ClientID != persisted.ClientID || got.ClientSecret != secret || got.Scope != persisted.Scope {
		t.Errorf("effective static creds = %+v, want persisted client, secret, and scope", got)
	}
	for key, want := range map[string]string{
		"access_type":            "offline",
		"prompt":                 "consent",
		"include_granted_scopes": "true",
	} {
		if value := got.AuthorizationExtras[key]; value != want {
			t.Errorf("AuthorizationExtras[%q] = %q, want %q", key, value, want)
		}
	}
}

func TestEffectiveStaticCredsLeavesLegacyDCRAccountsOnDCRPath(t *testing.T) {
	// Dynamic registration records a client ID but no operator-selected scope.
	// It must remain on the legacy DCR path when the user reauthorizes.
	persistedDCR := Account{ClientID: "dynamically-registered-id", Scope: ""}
	if got := effectiveStaticCreds(nil, persistedDCR, true, "https://mcp.notion.com/mcp"); got != nil {
		t.Errorf("effectiveStaticCreds() = %+v, want nil for legacy DCR account", got)
	}
}

func TestPendingConnectPersistsScopeOnlyForStaticClients(t *testing.T) {
	if got := (&pendingConnect{scope: "mcp:connect"}).persistedScope(); got != "" {
		t.Errorf("dynamic persisted scope = %q, want empty so reauthorization remains on DCR", got)
	}
	if got := (&pendingConnect{scope: "mcp:connect", staticClient: true}).persistedScope(); got != "mcp:connect" {
		t.Errorf("static persisted scope = %q, want mcp:connect", got)
	}
}

func TestEffectiveStaticCredsRejectsGmailClientWithoutSecret(t *testing.T) {
	persisted := Account{
		ClientID: "gmail-client-id",
		Scope:    "https://www.googleapis.com/auth/gmail.readonly",
	}
	creds := effectiveStaticCreds(nil, persisted, true, gmailMCPURL)
	if err := validateStaticCredsForUpstream(creds, gmailMCPURL); err == nil {
		t.Fatal("expected Gmail's confidential Web OAuth client to require a secret")
	}
}

func TestValidateStaticCredsForUpstreamRejectsSlackClientWithoutSecret(t *testing.T) {
	creds := &StaticCreds{ClientID: "slack-client-id", Scope: "channels:read chat:write"}
	if err := validateStaticCredsForUpstream(creds, slackMCPURL); err == nil {
		t.Fatal("expected Slack's confidential OAuth client to require a secret")
	}
	creds.ClientSecret = "slack-client-secret"
	if err := validateStaticCredsForUpstream(creds, slackMCPURL); err != nil {
		t.Errorf("validateStaticCredsForUpstream() with secret set = %v, want nil", err)
	}
}

func TestFinishConnectMergesOAuthIntoCurrentAccountAfterMetadataAndPolicyEdits(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{
		"tegence_notion": {"search", "old_tool"},
	})
	baseList := g.listTools
	g.listTools = func(callCtx context.Context, a Account) ([]mcp.Tool, error) {
		tools, err := baseList(callCtx, a)
		for i := range tools {
			if strings.HasSuffix(tools[i].Name, "__search") {
				tools[i].Annotations.ReadOnlyHint = mcp.ToBoolPtr(true)
			}
		}
		return tools, err
	}
	account := Account{
		Name: "tegence_notion", Label: "Notion old", Group: "Old namespace",
		URL: "https://mcp.example.com/", AuthMode: "oauth",
		ClientID: "new-client", AccessToken: "old-access", RefreshToken: "old-refresh", BearerToken: "stale-bearer",
		DisabledTools: []string{"old_tool"},
		ToolOverrides: map[string]ToolOverride{"search": {Description: "Curated search"}},
	}
	if err := g.store.Upsert(ctx, account); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := g.CreateNamespace(ctx, Namespace{
		Slug: "client", Label: "Client endpoint", Accounts: []string{account.Name},
	}); err != nil {
		t.Fatalf("create endpoint membership: %v", err)
	}
	currentAccount, ok := g.store.Account(account.Name)
	if !ok {
		t.Fatal("seeded account missing")
	}

	c := NewConnector(g.store, g)
	c.pend["state"] = &pendingConnect{
		name: account.Name, label: account.Label, group: account.Group,
		url: "https://MCP.Example.com:443", clientID: "new-client", clientSecret: "new-secret",
		verifier: "verifier", scope: "read write",
		meta: &upstreamoauth.Metadata{
			TokenEndpoint: "https://auth.example.com/token", Resource: "https://mcp.example.com",
		},
		redirectURI: "https://console.example.com/callback", created: time.Now(), accountExisted: true,
		accountPrecondition: oauthCompletionPreconditionForAccount(currentAccount),
	}
	c.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
		// The user relabels and tightens the account while consent is open.
		// Ownership-boundary moves intentionally require a fresh OAuth flow.
		if err := g.store.SetMeta(ctx, account.Name, "Notion · Curated", account.Group); err != nil {
			t.Fatalf("edit account during OAuth: %v", err)
		}
		if err := g.store.SetReadOnly(ctx, account.Name, true); err != nil {
			t.Fatalf("set read-only during OAuth: %v", err)
		}
		// Some providers omit refresh_token on reauthorization. The currently
		// valid refresh token must remain in that case.
		return &upstreamoauth.Tokens{AccessToken: "new-access"}, nil
	}

	name, count, err := c.FinishConnect(ctx, "state", "code")
	if err != nil {
		t.Fatalf("FinishConnect: %v", err)
	}
	if name != account.Name || count != 1 {
		t.Fatalf("FinishConnect result = %q/%d, want %q/1", name, count, account.Name)
	}
	got, ok := g.store.Account(account.Name)
	if !ok {
		t.Fatal("connected account disappeared")
	}
	if got.Label != "Notion · Curated" || got.Group != account.Group || !got.ReadOnly {
		t.Fatalf("OAuth completion lost current metadata/policy: %+v", got)
	}
	if len(got.DisabledTools) != 1 || got.DisabledTools[0] != "old_tool" ||
		got.ToolOverrides["search"].Description != "Curated search" {
		t.Fatalf("OAuth completion lost curation policy: %+v", got)
	}
	if got.AuthMode != "oauth" || got.ClientID != "new-client" || got.ClientSecret != "new-secret" ||
		got.AccessToken != "new-access" || got.RefreshToken != "old-refresh" || got.BearerToken != "" {
		t.Fatalf("OAuth completion did not replace credential metadata: %+v", got)
	}
	endpoint, ok := g.store.(NamespaceStore).Namespace(ctx, "client")
	if !ok || !sameStrings(endpoint.Accounts, []string{account.Name}) {
		t.Fatalf("OAuth completion changed endpoint membership: %+v ok=%v", endpoint, ok)
	}
	g.mu.Lock()
	cached := append([]cachedTool(nil), g.cached[account.Name]...)
	g.mu.Unlock()
	if len(cached) != 1 || cached[0].tool.Title != "Notion · Curated · search" {
		t.Fatalf("live tools did not use current label/policy: %+v", cached)
	}
}

func TestFinishConnectRejectsDeletedOrRetargetedAccount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wantErr error
		mutate  func(context.Context, *Gateway) error
	}{
		{
			name:    "deleted",
			wantErr: ErrConnectAccountDeleted,
			mutate: func(ctx context.Context, g *Gateway) error {
				current, _ := g.store.Account("notion")
				return g.store.Delete(ctx, current.Name, current.IncarnationID, current.Revision)
			},
		},
		{
			name:    "retargeted",
			wantErr: ErrConnectAccountURLChanged,
			mutate: func(ctx context.Context, g *Gateway) error {
				a, _ := g.store.Account("notion")
				a.URL = "https://attacker.example/mcp"
				return g.store.Upsert(ctx, a)
			},
		},
		{
			name:    "deleted and recreated with same name and URL",
			wantErr: ErrConnectAccountReplaced,
			mutate: func(ctx context.Context, g *Gateway) error {
				current, _ := g.store.Account("notion")
				if err := g.store.Delete(ctx, current.Name, current.IncarnationID, current.Revision); err != nil {
					return err
				}
				return g.store.Create(ctx, Account{
					Name: current.Name, Label: "Replacement", Group: "Different namespace",
					URL: current.URL, AuthMode: "token", BearerToken: "replacement-token",
				})
			},
		},
		{
			name:    "moved to a different ownership namespace",
			wantErr: ErrConnectAccountMoved,
			mutate: func(ctx context.Context, g *Gateway) error {
				store := g.store.(ConnectionNamespaceStore)
				ns, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Different owner boundary"})
				if err != nil {
					return err
				}
				current, _ := g.store.Account("notion")
				_, err = store.MoveAccountToConnectionNamespace(ctx, current.Name, current.IncarnationID, AccountConnectionAssignment{
					ConnectionNamespaceID: ns.ID,
					Scope:                 ConnectionScopeShared,
				}, current.Revision)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			g := newConnectorTestGateway(t, map[string][]string{"notion": {"search"}})
			a, _ := g.store.Account("notion")
			a.URL = "https://mcp.example.com/mcp"
			a.AccessToken, a.RefreshToken = "old-access", "old-refresh"
			if err := g.store.Upsert(ctx, a); err != nil {
				t.Fatalf("seed account: %v", err)
			}
			c := NewConnector(g.store, g)
			c.pend["state"] = &pendingConnect{
				name: "notion", url: a.URL, clientID: "new-client", verifier: "verifier",
				meta:        &upstreamoauth.Metadata{TokenEndpoint: "https://auth.example/token"},
				redirectURI: "https://console.example/callback", created: time.Now(), accountExisted: true,
				accountPrecondition: oauthCompletionPreconditionForAccount(a),
			}
			c.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
				if err := tc.mutate(ctx, g); err != nil {
					t.Fatalf("mutate pending account: %v", err)
				}
				return &upstreamoauth.Tokens{AccessToken: "new-access", RefreshToken: "new-refresh"}, nil
			}
			if _, _, err := c.FinishConnect(ctx, "state", "code"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("FinishConnect error = %v, want %v", err, tc.wantErr)
			}
			if current, exists := g.store.Account("notion"); exists && current.AccessToken == "new-access" {
				t.Fatal("rejected callback persisted the exchanged token")
			}
		})
	}
}

func TestFinishConnectRejectsReplacementAfterCredentialsPersistBeforeLiveAggregation(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{"notion": {"search"}})
	account, _ := g.store.Account("notion")
	account.URL = "https://notion.example/mcp"
	account.AuthMode = "oauth"
	account.ClientID = "old-client"
	account.AccessToken = "old-access"
	account.RefreshToken = "old-refresh"
	if err := g.store.Upsert(ctx, account); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	account, _ = g.store.Account(account.Name)

	c := NewConnector(g.store, g)
	c.pend["state"] = &pendingConnect{
		name: account.Name, url: account.URL, clientID: "new-client", verifier: "verifier",
		meta:        &upstreamoauth.Metadata{TokenEndpoint: "https://auth.example/token"},
		redirectURI: "https://console.example/callback", created: time.Now(), accountExisted: true,
		accountPrecondition: oauthCompletionPreconditionForAccount(account),
	}
	c.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
		return &upstreamoauth.Tokens{AccessToken: "new-access", RefreshToken: "new-refresh"}, nil
	}
	c.afterPersist = func() {
		live, ok := g.store.Account(account.Name)
		if !ok {
			t.Fatal("account vanished before replacement race")
		}
		if err := g.store.Delete(ctx, live.Name, live.IncarnationID, live.Revision); err != nil {
			t.Fatalf("delete completed account: %v", err)
		}
		if err := g.store.Create(ctx, Account{
			Name: live.Name, URL: live.URL, AuthMode: "token", BearerToken: "replacement-token",
		}); err != nil {
			t.Fatalf("create replacement account: %v", err)
		}
	}

	if _, _, err := c.FinishConnect(ctx, "state", "code"); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("FinishConnect error = %v, want ErrAccountIncarnation", err)
	}
	current, ok := g.store.Account(account.Name)
	if !ok || current.IncarnationID == account.IncarnationID || current.AuthMode != "token" ||
		current.BearerToken != "replacement-token" || current.AccessToken != "" || current.RefreshToken != "" {
		t.Fatalf("replacement account was reported as a successful OAuth completion: %+v, ok=%v", current, ok)
	}
}

func TestFinishConnectCreatesLegacyAbsentAccountWithoutOverwritingRace(t *testing.T) {
	ctx := context.Background()
	g := newConnectorTestGateway(t, map[string][]string{})
	c := NewConnector(g.store, g)
	seed := func(state string) {
		c.pend[state] = &pendingConnect{
			name: "legacy", label: "Legacy", group: "Imported", url: "https://mcp.example/mcp",
			clientID: "client", verifier: "verifier",
			meta:        &upstreamoauth.Metadata{TokenEndpoint: "https://auth.example/token"},
			redirectURI: "https://console.example/callback", created: time.Now(), accountExisted: false,
		}
	}
	c.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
		return &upstreamoauth.Tokens{AccessToken: "access"}, nil
	}
	seed("first")
	if _, _, err := c.FinishConnect(ctx, "first", "code"); err != nil {
		t.Fatalf("legacy FinishConnect: %v", err)
	}
	got, ok := g.store.Account("legacy")
	if !ok || got.Label != "Legacy" || got.Group != "Imported" || got.AccessToken != "access" {
		t.Fatalf("legacy account = %+v ok=%v", got, ok)
	}

	// A pending flow that began absent cannot overwrite an account created by a
	// different request while consent was open.
	seed("raced")
	if _, _, err := c.FinishConnect(ctx, "raced", "code"); err == nil {
		t.Fatal("absent-account flow overwrote a concurrently-created account")
	}
}

func TestFinishConnectRejectsExpiredStateBeforeTokenExchange(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{})
	c := NewConnector(g.store, g)
	c.pend["expired"] = &pendingConnect{
		name: "notion", url: "https://mcp.example/mcp", clientID: "client", verifier: "verifier",
		meta:        &upstreamoauth.Metadata{TokenEndpoint: "https://auth.example/token"},
		redirectURI: "https://console.example/callback",
		created:     time.Now().Add(-pendingConnectTTL - time.Second),
	}
	exchanged := false
	c.exchange = func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error) {
		exchanged = true
		return &upstreamoauth.Tokens{AccessToken: "must-not-persist"}, nil
	}

	if _, _, err := c.FinishConnect(context.Background(), "expired", "code"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("FinishConnect expired state error = %v", err)
	}
	if exchanged {
		t.Fatal("expired callback reached provider token exchange")
	}
	if _, exists := g.store.Account("notion"); exists {
		t.Fatal("expired callback created an account")
	}
}

func TestCompleteOAuthRefreshTokenFollowsClientBinding(t *testing.T) {
	for _, tc := range []struct {
		name              string
		completionClient  string
		completionRefresh string
		wantRefresh       string
	}{
		{name: "same client omission preserves current token", completionClient: "client-a", wantRefresh: "old-refresh"},
		{name: "changed client omission clears old token", completionClient: "client-b", wantRefresh: ""},
		{name: "provider replacement wins", completionClient: "client-b", completionRefresh: "new-refresh", wantRefresh: "new-refresh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			g := newConnectorTestGateway(t, map[string][]string{"notion": {}})
			a, _ := g.store.Account("notion")
			a.URL, a.AuthMode, a.ClientID, a.RefreshToken = "https://mcp.example/mcp", "oauth", "client-a", "old-refresh"
			if err := g.store.Upsert(ctx, a); err != nil {
				t.Fatalf("seed account: %v", err)
			}
			got, err := g.store.CompleteOAuth(ctx, oauthCompletionPreconditionForAccount(a), Account{
				Name: "notion", ClientID: tc.completionClient, AccessToken: "new-access", RefreshToken: tc.completionRefresh,
			})
			if err != nil {
				t.Fatalf("CompleteOAuth: %v", err)
			}
			if got.RefreshToken != tc.wantRefresh {
				t.Fatalf("refresh token = %q, want %q", got.RefreshToken, tc.wantRefresh)
			}
		})
	}
}
