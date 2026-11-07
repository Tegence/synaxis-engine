package engine

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type kernelBrowser struct {
	ID           string        `json:"session_id"`
	Name         string        `json:"name"`
	ConnectURL   string        `json:"cdp_ws_url"`
	ViewerURL    string        `json:"browser_live_view_url"`
	Profile      kernelProfile `json:"profile"`
	SaveChanges  *bool         `json:"profile_save_changes"`
	ChromePolicy struct {
		Blocklist []string `json:"URLBlocklist"`
		Allowlist []string `json:"URLAllowlist"`
	} `json:"chrome_policy"`
}

// The explicitly tagged E2E build supplies a synthetic browser data plane.
var kernelBrowserAction = browserCDPAction

func kernelBrowserURL(raw, scheme string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != scheme || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443" && u.Port() != "8443") {
		return false
	}
	host := u.Hostname()
	return host == "onkernel.com" || strings.HasSuffix(host, ".onkernel.com") || host == "kernel.sh" || strings.HasSuffix(host, ".kernel.sh")
}

func (p *kernelProvider) createBrowser(ctx context.Context, profile, name string, save bool, website string) (string, string, error) {
	if !kernelProfileName(profile) || !strings.HasPrefix(name, "synaxis-browser-") || !browserResourceID(name) {
		return "", "", errBrowserSignIn
	}
	allowedURL := ""
	body := map[string]any{
		"name": name, "profile": map[string]any{"name": profile, "save_changes": save},
		"timeout_seconds": 600, "headless": !save, "stealth": false,
		"proxy": map[string]string{"mode": "direct"}, "telemetry": map[string]bool{"enabled": false},
		"network": map[string]any{"private_hosts": []string{}},
	}
	if website != "" {
		if !validBrowserWebsite(website) {
			return "", "", errBrowserSignIn
		}
		u, _ := url.Parse(website)
		// Chromium's leading-dot filter matches only the exact host:
		// https://www.chromium.org/administrators/url-blocklist-filter-format/
		// This supplements the origin checks before every runtime read/action.
		allowedURL = "https://." + u.Hostname() + ":443"
		body["chrome_policy"] = map[string]any{"URLBlocklist": []string{"*"}, "URLAllowlist": []string{allowedURL}}
	}
	var out kernelBrowser
	err := p.request(ctx, http.MethodPost, "/browsers", body, &out)
	if err != nil || !browserResourceID(out.ID) || out.Name != name || out.Profile.Name != profile || out.SaveChanges == nil || *out.SaveChanges != save {
		// Return the preselected resource name even on a lost response. The
		// durable run ledger can close the uncertain allocation by this name.
		return name, "", errBrowserSignIn
	}
	if !kernelBrowserURL(out.ConnectURL, "wss") || p.exposesAPIKey(out.ConnectURL) {
		return name, "", errBrowserSignIn
	}
	if allowedURL != "" && (len(out.ChromePolicy.Blocklist) != 1 || out.ChromePolicy.Blocklist[0] != "*" || len(out.ChromePolicy.Allowlist) != 1 || out.ChromePolicy.Allowlist[0] != allowedURL) {
		return name, "", errBrowserSignIn
	}
	return name, out.ConnectURL, nil
}

func (p *kernelProvider) CreateSession(ctx context.Context, profile string) (string, string, error) {
	return p.CreateNamedSession(ctx, profile, p.SessionReference(newEpoch()))
}

func (p *kernelProvider) CreateRuntimeSession(ctx context.Context, profile BrowserProfile) (string, string, error) {
	return p.CreateNamedRuntimeSession(ctx, profile, p.SessionReference(newEpoch()))
}

func (p *kernelProvider) CreateNamedSession(ctx context.Context, profile, name string) (string, string, error) {
	return p.createBrowser(ctx, profile, name, true, "")
}

func (p *kernelProvider) CreateNamedRuntimeSession(ctx context.Context, profile BrowserProfile, name string) (string, string, error) {
	if !validBrowserProfile(profile) || profile.Provider != p.Kind() || profile.ConfigurationID != p.ConfigurationID() {
		return "", "", errBrowserSignIn
	}
	return p.createBrowser(ctx, profile.ProfileID, name, false, profile.WebsiteURL)
}

func (p *kernelProvider) Navigate(ctx context.Context, connect, website string) error {
	_, err := p.BrowserAction(ctx, connect, website, BrowserAction{Operation: "open"})
	return err
}

func (p *kernelProvider) BrowserAction(ctx context.Context, connect, website string, action BrowserAction) (*BrowserSnapshot, error) {
	if !kernelBrowserURL(connect, "wss") {
		return nil, errBrowserSignIn
	}
	return kernelBrowserAction(ctx, p.client, connect, website, action)
}

func (p *kernelProvider) View(ctx context.Context, session string) (string, error) {
	if !browserResourceID(session) {
		return "", errBrowserSignIn
	}
	var out kernelBrowser
	if p.request(ctx, http.MethodGet, "/browsers/"+session, nil, &out) != nil || (out.ID != session && out.Name != session) || !kernelBrowserURL(out.ViewerURL, "https") || p.exposesAPIKey(out.ViewerURL) {
		return "", errBrowserSignIn
	}
	return out.ViewerURL, nil
}

func (p *kernelProvider) Stop(ctx context.Context, session string) (bool, error) {
	if session == "" {
		return true, nil
	}
	if !browserResourceID(session) {
		return false, errBrowserSignIn
	}
	err := p.request(ctx, http.MethodDelete, "/browsers/"+session, nil, nil)
	if errors.Is(err, errBrowserResourceMissing) {
		return true, nil
	}
	return err == nil, err
}

func (p *kernelProvider) stopProfileBrowsers(ctx context.Context, profile string) error {
	var ids []string
	for offset := 0; offset < 1000; offset += 100 {
		var rows []kernelBrowser
		path := "/browsers?query=" + url.QueryEscape(profile) + "&status=active&limit=100&offset=" + strconv.Itoa(offset)
		if err := p.request(ctx, http.MethodGet, path, nil, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			if row.Profile.Name == profile {
				if !browserResourceID(row.ID) {
					return errBrowserSignIn
				}
				ids = append(ids, row.ID)
			}
		}
		if len(rows) < 100 {
			for _, id := range ids {
				if _, err := p.Stop(ctx, id); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return errBrowserSignIn
}
