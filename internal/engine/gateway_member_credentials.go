package engine

import (
	"context"
	"errors"
	"time"
)

// Member credentials: an account in MemberCredentials mode calls its upstream
// with the calling member's own credential, so each member's actions upstream
// are theirs rather than the account owner's. Only a subject-bound MCP
// client knows who is calling; every other endpoint fails closed.

// ErrMemberCredentialMissing means the calling member has not connected
// their own account yet.
var ErrMemberCredentialMissing = errors.New("member credential missing")

// memberCaller is who a subject-bound MCP client call acts for.
type memberCaller struct {
	subject  string
	workload bool
}

type memberCallerKey struct{}

func withMemberCaller(ctx context.Context, caller memberCaller) context.Context {
	return context.WithValue(ctx, memberCallerKey{}, caller)
}

func memberCallerFrom(ctx context.Context) (memberCaller, bool) {
	caller, ok := ctx.Value(memberCallerKey{}).(memberCaller)
	return caller, ok && caller.subject != ""
}

func (g *Gateway) memberCredentialStore() (MemberCredentialStore, bool) {
	store, ok := g.store.(MemberCredentialStore)
	return store, ok
}

// memberUpstream builds the Upstream one member's call uses for account a.
// When there is none, it returns the tool error the agent sees instead.
func (g *Gateway) memberUpstream(ctx context.Context, a Account) (*Upstream, string) {
	label := a.Label
	if label == "" {
		label = a.Name
	}
	caller, ok := memberCallerFrom(ctx)
	switch {
	case !ok:
		return nil, "This " + label + " connection uses each member's own account. Call it from your own MCP client."
	case caller.workload:
		return nil, "This " + label + " connection uses each member's own account, which jobs cannot use yet."
	}
	store, ok := g.memberCredentialStore()
	if !ok {
		return nil, "This " + label + " connection uses each member's own account, which this Engine cannot store."
	}
	connect := "Connect your own " + label + " account in Synaxis (Connections, Accounts your agents use), then try again."
	stored, found, err := store.MemberCredential(ctx, a.Name, caller.subject)
	if err != nil {
		return nil, "Your " + label + " account could not be loaded. Try again."
	}
	if !found || stored.IncarnationID != a.IncarnationID {
		return nil, connect
	}
	credential := func() (string, error) {
		if !g.accountSnapshotLive(a.Name, a.IncarnationID, a.Revision, a.URL) {
			return "", ErrAccountIncarnation
		}
		current, found, err := store.MemberCredential(context.WithoutCancel(ctx), a.Name, caller.subject)
		if err != nil {
			return "", err
		}
		if !found || current.IncarnationID != a.IncarnationID {
			return "", ErrMemberCredentialMissing
		}
		if a.AuthMode == "token" {
			return current.BearerToken, nil
		}
		return current.AccessToken, nil
	}
	up := &Upstream{
		Name:       a.Name,
		URL:        a.URL,
		Credential: credential,
		Available: func() bool {
			_, err := credential()
			return err == nil
		},
		Token: func() string {
			token, _ := credential()
			return token
		},
	}
	if a.AuthMode == "oauth" && stored.RefreshToken != "" {
		up.Refresh = func(ctx context.Context) error {
			return g.refreshAccount(ctx, a.Name, a.IncarnationID, caller.subject)
		}
	}
	return up, ""
}

// PutMemberCredentialLocked stores a member's credential under the same lock
// as that member's token refresh, so a refresh already in flight cannot
// overwrite a fresh authorization with its older token family.
func (g *Gateway) PutMemberCredentialLocked(ctx context.Context, credential MemberCredential) error {
	store, ok := g.memberCredentialStore()
	if !ok {
		return errors.New("member credentials are not supported by this store")
	}
	mu := g.refreshLock(refreshLockKey(credential.Account, credential.Subject))
	mu.Lock()
	defer mu.Unlock()
	if credential.UpdatedAt.IsZero() {
		credential.UpdatedAt = time.Now().UTC()
	}
	return store.PutMemberCredential(ctx, credential)
}

// refreshLockKey is the account's own lock for its credential, and a
// separate one for each member's.
func refreshLockKey(account, subject string) string {
	if subject == "" {
		return account
	}
	return account + "\x00member\x00" + subject
}
