//go:build synaxis_e2e

package engine

import "context"

// Only the disposable E2E binary contains this adapter. The Web, BFF, actor
// verification, Engine handlers and durable stores remain real. No public
// provider is contacted and no actual browser credentials are acquired.
func init() {
	realProvider := browserSignInProviderFactory
	browserSignInProviderFactory = func(raw string) (browserSignInProvider, error) {
		if raw == `{"provider":"e2e"}` {
			return e2eSignInBrowser{}, nil
		}
		return realProvider(raw)
	}
}

type e2eSignInBrowser struct{}

func (e2eSignInBrowser) Kind() string            { return "browserbase" }
func (e2eSignInBrowser) ConfigurationID() string { return "e2e-browser-project" }
func (e2eSignInBrowser) CreateProfile(_ context.Context, id string) (string, error) {
	return "e2e-profile-" + id, nil
}
func (e2eSignInBrowser) CreateSession(_ context.Context, id string) (string, string, error) {
	return "e2e-session-" + id, "e2e-no-browser", nil
}
func (e2eSignInBrowser) Navigate(context.Context, string, string) error { return nil }
func (e2eSignInBrowser) View(_ context.Context, id string) (string, error) {
	return "https://www.browserbase.com/synaxis-e2e/" + id, nil
}
func (e2eSignInBrowser) Stop(context.Context, string) (bool, error)  { return true, nil }
func (e2eSignInBrowser) ProfileReady(context.Context, string) error  { return nil }
func (e2eSignInBrowser) DeleteProfile(context.Context, string) error { return nil }

func (e2eSignInBrowser) CreateRuntimeSession(_ context.Context, p BrowserProfile) (string, string, error) {
	return "runtime-" + p.ProfileID, "e2e-runtime-private", nil
}
func (e2eSignInBrowser) BrowserAction(_ context.Context, _ string, site string, a BrowserAction) (*BrowserSnapshot, error) {
	if a.Operation == "snapshot" {
		return &BrowserSnapshot{ID: "e2e_snapshot", URL: site, Title: "Website fixture", Text: "Signed-in browser fixture", Elements: []BrowserElement{{ID: 1, Role: "button", Label: "Publish fixture"}}}, nil
	}
	return nil, nil
}
