package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

// Connector runs the upstream OAuth flow for adding an account (the engine's own
// "Connect", which the console will drive). In-memory pending flows; single
// instance. Reuses internal/upstreamoauth — the same client we already own.
type Connector struct {
	store AccountStore
	gw    *Gateway
	mu    sync.Mutex
	pend  map[string]*pendingConnect
	// exchange is a test seam; nil uses upstreamoauth.Exchange.
	exchange func(context.Context, *upstreamoauth.Metadata, string, string, string, string, string) (*upstreamoauth.Tokens, error)
	// afterPersist is a test seam for the narrow delete/recreate window between
	// a successful OAuth credential write and its live tool registration.
	afterPersist func()
}

const pendingConnectTTL = 10 * time.Minute

type pendingConnect struct {
	name, label, group, url          string
	clientID, clientSecret, verifier string
	scope                            string
	meta                             *upstreamoauth.Metadata
	redirectURI                      string
	created                          time.Time
	accountExisted                   bool
	accountPrecondition              OAuthCompletionPrecondition
}

// StaticCreds carries pre-registered OAuth app credentials for the
// static-client connect path (providers that don't allow RFC 7591 DCR).
// When passed to StartConnect, it skips Register and uses these creds
// directly. A nil *StaticCreds selects the DCR path (unchanged behavior).
type StaticCreds struct {
	ClientID, ClientSecret, Scope string
	AuthorizationExtras           map[string]string
}

const gmailMCPURL = "https://gmailmcp.googleapis.com/mcp/v1"

// effectiveStaticCreds preserves a pre-registered OAuth client across a
// reauthorization. Static-client accounts persist their client ID, optional
// secret, and requested scope after the first successful flow; reusing those
// credentials avoids incorrectly falling back to upstream DCR. DCR accounts
// have no persisted scope, so their legacy no-body behavior remains unchanged.
//
// Gmail requires offline consent parameters to reliably issue a refresh token.
// They are intentionally derived only for its first-party MCP URL rather than
// persisted in the account record, so no new credential schema is needed.
func effectiveStaticCreds(requested *StaticCreds, existing Account, accountExisted bool, upstreamURL string) *StaticCreds {
	if requested == nil && accountExisted && existing.ClientID != "" && existing.Scope != "" {
		requested = &StaticCreds{
			ClientID:     existing.ClientID,
			ClientSecret: existing.ClientSecret,
			Scope:        existing.Scope,
		}
	}
	if requested == nil {
		return nil
	}
	effective := *requested
	effective.AuthorizationExtras = copyAuthorizationExtras(requested.AuthorizationExtras)
	if isGmailMCPURL(upstreamURL) {
		effective.AuthorizationExtras = map[string]string{
			"access_type":            "offline",
			"prompt":                 "consent",
			"include_granted_scopes": "true",
		}
	}
	return &effective
}

func isGmailMCPURL(upstreamURL string) bool {
	return strings.TrimRight(strings.TrimSpace(upstreamURL), "/") == gmailMCPURL
}

// validateStaticCredsForUpstream enforces requirements that are specific to a
// first-party provider's officially supported OAuth client type. Google
// documents Gmail's MCP connection as a confidential Web OAuth client, so an
// empty secret must not start a flow that cannot exchange its code.
func validateStaticCredsForUpstream(sc *StaticCreds, upstreamURL string) error {
	if sc != nil && isGmailMCPURL(upstreamURL) && strings.TrimSpace(sc.ClientSecret) == "" {
		return errors.New("clientSecret is required for Gmail's pre-registered OAuth app")
	}
	return nil
}

func copyAuthorizationExtras(extras map[string]string) map[string]string {
	if len(extras) == 0 {
		return nil
	}
	copy := make(map[string]string, len(extras))
	for key, value := range extras {
		copy[key] = value
	}
	return copy
}

func NewConnector(store AccountStore, gw *Gateway) *Connector {
	return &Connector{store: store, gw: gw, pend: map[string]*pendingConnect{}}
}

// StartConnect: discovery + PKCE for an OAuth upstream; returns the authorize
// URL the browser should visit. sc==nil selects the DCR path (RFC 7591 Register
// + no scope). sc!=nil selects the static-client path (pre-registered app):
// the supplied client_id/client_secret are used directly (no Register call) and
// sc.Scope is requested. Runtime behavior (refresh, dispatch) is identical.
func (c *Connector) StartConnect(ctx context.Context, name, label, group, url, redirectURI string, sc *StaticCreds) (string, error) {
	existingAccount, accountExisted := c.store.Account(name)
	accountPrecondition := OAuthCompletionPrecondition{}
	if accountExisted {
		if existingAccount.IncarnationID == "" {
			return "", errors.New("existing account has no durable incarnation")
		}
		if !equalAccountURL(existingAccount.URL, url) {
			return "", ErrConnectAccountURLChanged
		}
		accountPrecondition = oauthCompletionPreconditionForAccount(existingAccount)
		accountPrecondition.URL = url
	}
	sc = effectiveStaticCreds(sc, existingAccount, accountExisted, url)
	if err := validateStaticCredsForUpstream(sc, url); err != nil {
		return "", err
	}
	meta, err := upstreamoauth.Discover(ctx, url)
	if err != nil {
		return "", fmt.Errorf("discover: %w", err)
	}
	var ci *upstreamoauth.ClientInfo
	scope := ""
	var authorizationExtras map[string]string
	if sc != nil {
		ci, err = upstreamoauth.StaticClient(sc.ClientID, sc.ClientSecret)
		if err != nil {
			return "", fmt.Errorf("static client: %w", err)
		}
		scope = sc.Scope
		authorizationExtras = sc.AuthorizationExtras
	} else {
		ci, err = upstreamoauth.Register(ctx, meta.RegistrationEndpoint, redirectURI)
		if err != nil {
			return "", fmt.Errorf("register (DCR): %w", err)
		}
	}
	pkce, state, err := upstreamoauth.NewPKCE()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	for k, v := range c.pend {
		if time.Since(v.created) > pendingConnectTTL {
			delete(c.pend, k)
		}
	}
	c.pend[state] = &pendingConnect{
		name: name, label: label, group: group, url: url,
		clientID: ci.ClientID, clientSecret: ci.ClientSecret, verifier: pkce.Verifier,
		scope: scope, meta: meta, redirectURI: redirectURI, created: time.Now(),
		accountExisted: accountExisted, accountPrecondition: accountPrecondition,
	}
	c.mu.Unlock()
	return upstreamoauth.AuthorizeURL(meta, ci.ClientID, redirectURI, pkce.Challenge, state, scope, authorizationExtras), nil
}

// FinishConnect: the OAuth callback — exchange the code, persist the account,
// and register its tools live (no restart needed).
func (c *Connector) FinishConnect(ctx context.Context, state, code string) (string, int, error) {
	c.mu.Lock()
	p := c.pend[state]
	delete(c.pend, state)
	c.mu.Unlock()
	if p == nil {
		return "", 0, fmt.Errorf("unknown or expired connect state")
	}
	if p.created.IsZero() || time.Since(p.created) > pendingConnectTTL {
		return "", 0, fmt.Errorf("unknown or expired connect state")
	}
	exchange := c.exchange
	if exchange == nil {
		exchange = upstreamoauth.Exchange
	}
	tokens, err := exchange(ctx, p.meta, code, p.redirectURI, p.clientID, p.clientSecret, p.verifier)
	if err != nil {
		return "", 0, fmt.Errorf("exchange: %w", err)
	}
	completion := Account{
		Name: p.name, URL: p.url, AuthMode: "oauth",
		ClientID: p.clientID, ClientSecret: p.clientSecret,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		TokenEndpoint: p.meta.TokenEndpoint, Resource: p.meta.Resource, Scope: p.scope,
	}
	var (
		persisted  Account
		persistErr error
	)
	if p.accountExisted {
		// Credential-only completion is atomic in the store: labels and tool
		// policy changed during consent are preserved, while deletion,
		// replacement, ownership moves, and URL retargeting reject the callback.
		persisted, persistErr = c.store.CompleteOAuth(ctx, p.accountPrecondition, completion)
	} else {
		// Legacy admin can start OAuth before an account row exists. Create (not
		// Upsert) ensures a concurrent account cannot be overwritten.
		completion.Label, completion.Group = p.label, p.group
		persistErr = c.store.Create(ctx, completion)
		if persistErr == nil {
			var found bool
			persisted, found = c.store.Account(p.name)
			if !found {
				persistErr = ErrConnectAccountDeleted
			}
		}
	}
	if persistErr != nil {
		return "", 0, fmt.Errorf("store: %w", persistErr)
	}
	if c.afterPersist != nil {
		c.afterPersist()
	}
	n, err := c.gw.AddAccountForIncarnation(ctx, persisted.Name, persisted.IncarnationID)
	if err != nil {
		return p.name, 0, fmt.Errorf("aggregate: %w", err)
	}
	return p.name, n, nil
}
