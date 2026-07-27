package engine

import (
	"context"
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
}

type pendingConnect struct {
	name, label, group, url          string
	clientID, clientSecret, verifier string
	scope                            string
	meta                             *upstreamoauth.Metadata
	redirectURI                      string
	created                          time.Time
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
		if time.Since(v.created) > 10*time.Minute {
			delete(c.pend, k)
		}
	}
	c.pend[state] = &pendingConnect{
		name: name, label: label, group: group, url: url,
		clientID: ci.ClientID, clientSecret: ci.ClientSecret, verifier: pkce.Verifier,
		scope: scope, meta: meta, redirectURI: redirectURI, created: time.Now(),
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
	tokens, err := upstreamoauth.Exchange(ctx, p.meta, code, p.redirectURI, p.clientID, p.clientSecret, p.verifier)
	if err != nil {
		return "", 0, fmt.Errorf("exchange: %w", err)
	}
	a := Account{
		Name: p.name, Label: p.label, Group: p.group, URL: p.url, AuthMode: "oauth",
		ClientID: p.clientID, ClientSecret: p.clientSecret,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		TokenEndpoint: p.meta.TokenEndpoint, Resource: p.meta.Resource,
		Scope: p.scope,
	}
	if err := c.store.Upsert(ctx, a); err != nil {
		return "", 0, fmt.Errorf("store: %w", err)
	}
	n, err := c.gw.AddAccount(ctx, p.name)
	if err != nil {
		return p.name, 0, fmt.Errorf("aggregate: %w", err)
	}
	return p.name, n, nil
}
