//go:build synaxis_e2e

package engine

import (
	"context"
	"strconv"
	"sync"
)

// This provider exists only in the disposable E2E binary. The credential form,
// BFF, actor checks, lifecycle and stores remain real; no website is contacted.
func init() {
	realProvider := managedBrowserSignInProviderFactory
	managedBrowserSignInProviderFactory = func(raw string) (managedBrowserSignInProvider, error) {
		if raw == `{"provider":"e2e"}` {
			return &e2eManagedSignInBrowser{logins: make(map[string]*e2eManagedLogin)}, nil
		}
		return realProvider(raw)
	}
}

type e2eManagedSignInBrowser struct {
	e2eSignInBrowser
	mu     sync.Mutex
	logins map[string]*e2eManagedLogin
}

type e2eManagedLogin struct {
	step        string
	interaction int
	message     string
}

func (*e2eManagedSignInBrowser) Kind() string            { return "kernel" }
func (*e2eManagedSignInBrowser) ConfigurationID() string { return "e2e-kernel-project" }

func (p *e2eManagedSignInBrowser) CreateLogin(ctx context.Context, profile, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	id := "e2e-login-" + profile
	if p.logins[id] == nil {
		p.logins[id] = &e2eManagedLogin{step: "working"}
	}
	return id, nil
}

func (p *e2eManagedSignInBrowser) BeginLogin(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	login := p.logins[id]
	if login == nil {
		return errBrowserResourceMissing
	}
	login.step, login.interaction, login.message = "credentials", login.interaction+1, ""
	return nil
}

func (p *e2eManagedSignInBrowser) LoginStatus(ctx context.Context, id string) (ManagedBrowserStatus, error) {
	if err := ctx.Err(); err != nil {
		return ManagedBrowserStatus{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	login := p.logins[id]
	if login == nil {
		return ManagedBrowserStatus{}, errBrowserResourceMissing
	}
	status := ManagedBrowserStatus{State: "working", Message: login.message, BrowserSessionID: "e2e-managed-session-" + id}
	switch login.step {
	case "credentials":
		status.State = "input"
		status.InteractionID = e2eManagedInteraction(id, login.interaction)
		status.Fields = []ManagedBrowserField{
			{ID: "username", Label: "Email address", Type: "email", Required: true},
			{ID: "password", Label: "Password", Type: "password", Required: true},
		}
	case "otp":
		status.State = "input"
		status.InteractionID = e2eManagedInteraction(id, login.interaction)
		status.Fields = []ManagedBrowserField{{ID: "otp", Label: "Verification code", Type: "otp", Required: true}}
	case "succeeded":
		status.State = "succeeded"
	}
	return status, nil
}

func (p *e2eManagedSignInBrowser) SubmitLogin(ctx context.Context, id, interactionID string, fields map[string]string, choice string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	login := p.logins[id]
	if login == nil {
		return errBrowserResourceMissing
	}
	if interactionID != e2eManagedInteraction(id, login.interaction) {
		return errBrowserRevision
	}
	if choice != "" {
		return errBrowserSignIn
	}
	switch login.step {
	case "credentials":
		if len(fields) == 2 && fields["username"] == "browser-user@example.test" && fields["password"] == "browser-test-password" {
			login.step, login.message = "otp", ""
		} else {
			login.message = "Sign-in details were not accepted. Try again."
		}
	case "otp":
		if len(fields) == 1 && fields["otp"] == "123456" {
			login.step, login.message = "succeeded", ""
		} else {
			login.message = "The verification code was not accepted. Try again."
		}
	default:
		return errBrowserRevision
	}
	// Only the stage and next challenge ID survive a request, never its values.
	login.interaction++
	return nil
}

func (p *e2eManagedSignInBrowser) DeleteLogin(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.logins, id)
	return nil
}

func e2eManagedInteraction(id string, revision int) string {
	return "e2e-interaction-" + id + "-" + strconv.Itoa(revision)
}
