package engine

import (
	"context"
	"errors"
	"fmt"
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
	meta, err := upstreamoauth.Discover(ctx, url)
	if err != nil {
		return "", fmt.Errorf("discover: %w", err)
	}
	var ci *upstreamoauth.ClientInfo
	scope := ""
	if sc != nil {
		ci, err = upstreamoauth.StaticClient(sc.ClientID, sc.ClientSecret)
		if err != nil {
			return "", fmt.Errorf("static client: %w", err)
		}
		scope = sc.Scope
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
	return upstreamoauth.AuthorizeURL(meta, ci.ClientID, redirectURI, pkce.Challenge, state, scope), nil
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
