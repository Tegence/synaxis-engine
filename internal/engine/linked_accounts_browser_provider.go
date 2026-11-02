package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"narthex/backend/internal/upstreamoauth"
)

// Provider-neutral orchestration never receives cookies, screenshots, form
// values or browser network logs. Adapters retain those at the browser service.
type browserSignInProvider interface {
	Kind() string
	ConfigurationID() string
	CreateProfile(context.Context, string) (string, error)
	CreateSession(context.Context, string) (string, string, error)
	Navigate(context.Context, string, string) error
	View(context.Context, string) (string, error)
	Stop(context.Context, string) (bool, error)
	ProfileReady(context.Context, string) error
	DeleteProfile(context.Context, string) error
}

var errBrowserResourceMissing = errors.New("browser resource missing")

type browserbaseConfig struct {
	Provider  string `json:"provider"`
	APIKey    string `json:"apiKey"`
	ProjectID string `json:"projectId"`
}
type browserbaseProvider struct {
	config browserbaseConfig
	client *http.Client
}

func newBrowserSignInProvider(raw string) (browserSignInProvider, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var config browserbaseConfig
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 64<<10 || d.Decode(&config) != nil || d.Decode(&struct{}{}) != io.EOF || config.Provider != "browserbase" || !validLinkedAccountToken(config.APIKey, false) || !browserResourceID(config.ProjectID) {
		return nil, errBrowserSignIn
	}
	client := upstreamoauth.NewHardenedHTTPClient(15 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browserbaseProvider{config: config, client: client}, nil
}
func (p *browserbaseProvider) Kind() string { return "browserbase" }
func (p *browserbaseProvider) ConfigurationID() string {
	return oauthLinkHash("browserbase:" + p.config.ProjectID)
}
func browserResourceID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func (p *browserbaseProvider) request(ctx context.Context, method, path string, body any, out any, missingOK bool) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errBrowserSignIn
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.browserbase.com/v1"+path, reader)
	if err != nil {
		return errBrowserSignIn
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-BB-API-Key", p.config.APIKey)
	response, err := p.client.Do(req)
	if err != nil {
		return errBrowserSignIn
	}
	defer response.Body.Close()
	if missingOK && response.StatusCode == 404 {
		return errBrowserResourceMissing
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errBrowserSignIn
	}
	if out == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil || len(raw) > 256<<10 || json.Unmarshal(raw, out) != nil {
		return errBrowserSignIn
	}
	return nil
}
func (p *browserbaseProvider) CreateProfile(ctx context.Context, id string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := p.request(ctx, "POST", "/contexts", map[string]any{"projectId": p.config.ProjectID, "name": "synaxis-" + id}, &out, false)
	if err != nil || !browserResourceID(out.ID) {
		return "", errBrowserSignIn
	}
	return out.ID, nil
}
func (p *browserbaseProvider) CreateSession(ctx context.Context, profile string) (string, string, error) {
	var out struct {
		ID         string `json:"id"`
		ProjectID  string `json:"projectId"`
		ContextID  string `json:"contextId"`
		ConnectURL string `json:"connectUrl"`
	}
	err := p.request(ctx, "POST", "/sessions", map[string]any{"projectId": p.config.ProjectID, "timeout": 600, "keepAlive": true, "proxies": false, "browserSettings": map[string]any{"context": map[string]any{"id": profile, "persist": true}, "recordSession": false, "logSession": false, "solveCaptchas": false, "advancedStealth": false, "verified": false, "viewport": map[string]int{"width": 1280, "height": 800}}}, &out, false)
	if err != nil || !browserResourceID(out.ID) || out.ProjectID != p.config.ProjectID || out.ContextID != profile {
		return "", "", errBrowserSignIn
	}
	return out.ID, out.ConnectURL, nil
}
func browserbaseURL(raw, scheme string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == scheme && u.User == nil && u.Port() == "" && (u.Hostname() == "browserbase.com" || strings.HasSuffix(u.Hostname(), ".browserbase.com"))
}
func (p *browserbaseProvider) Navigate(ctx context.Context, connectURL, website string) error {
	if !browserbaseURL(connectURL, "wss") || !validBrowserWebsite(website) {
		return errBrowserSignIn
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, connectURL, &websocket.DialOptions{HTTPClient: p.client})
	if err != nil {
		return errBrowserSignIn
	}
	defer conn.CloseNow()
	conn.SetReadLimit(256 << 10)
	requestID := 0
	call := func(method string, params any, session string, result any) error {
		requestID++
		request := map[string]any{"id": requestID, "method": method, "params": params}
		if session != "" {
			request["sessionId"] = session
		}
		if wsjson.Write(ctx, conn, request) != nil {
			return errBrowserSignIn
		}
		for range 100 {
			var message struct {
				ID     int             `json:"id"`
				Error  json.RawMessage `json:"error"`
				Result json.RawMessage `json:"result"`
			}
			if wsjson.Read(ctx, conn, &message) != nil {
				return errBrowserSignIn
			}
			if message.ID != requestID {
				continue
			}
			if len(message.Error) > 0 || json.Unmarshal(message.Result, result) != nil {
				return errBrowserSignIn
			}
			return nil
		}
		return errBrowserSignIn
	}
	// Navigate the initial page so the provider's first-page live viewer opens
	// the requested website instead of an unused about:blank tab.
	var targets struct {
		Infos []struct {
			ID   string `json:"targetId"`
			Type string `json:"type"`
		} `json:"targetInfos"`
	}
	if call("Target.getTargets", map[string]any{}, "", &targets) != nil {
		return errBrowserSignIn
	}
	target := ""
	for _, info := range targets.Infos {
		if info.Type == "page" {
			target = info.ID
			break
		}
	}
	if target == "" {
		var created struct {
			ID string `json:"targetId"`
		}
		if call("Target.createTarget", map[string]string{"url": "about:blank"}, "", &created) != nil || created.ID == "" {
			return errBrowserSignIn
		}
		target = created.ID
	}
	var attached struct {
		ID string `json:"sessionId"`
	}
	if call("Target.attachToTarget", map[string]any{"targetId": target, "flatten": true}, "", &attached) != nil || attached.ID == "" {
		return errBrowserSignIn
	}
	var navigation struct {
		Error string `json:"errorText"`
	}
	if call("Page.navigate", map[string]string{"url": website}, attached.ID, &navigation) != nil || navigation.Error != "" {
		return errBrowserSignIn
	}
	return call("Target.activateTarget", map[string]string{"targetId": target}, "", &struct{}{})
}
func (p *browserbaseProvider) View(ctx context.Context, session string) (string, error) {
	var out struct {
		URL string `json:"debuggerFullscreenUrl"`
	}
	if p.request(ctx, "GET", "/sessions/"+session+"/debug", nil, &out, false) != nil || !browserbaseURL(out.URL, "https") || strings.Contains(out.URL, p.config.APIKey) {
		return "", errBrowserSignIn
	}
	return out.URL, nil
}
func (p *browserbaseProvider) Stop(ctx context.Context, session string) (bool, error) {
	if session == "" {
		return true, nil
	}
	var out struct {
		Status    string `json:"status"`
		ProjectID string `json:"projectId"`
	}
	if err := p.request(ctx, "GET", "/sessions/"+session, nil, &out, true); err != nil {
		if errors.Is(err, errBrowserResourceMissing) {
			return true, nil
		}
		return false, err
	}
	if out.ProjectID != p.config.ProjectID {
		return false, errBrowserSignIn
	}
	switch out.Status {
	case "COMPLETED", "TIMED_OUT", "ERROR":
		return true, nil
	case "RUNNING", "PENDING":
	default:
		return false, errBrowserSignIn
	}
	err := p.request(ctx, "POST", "/sessions/"+session, map[string]string{"projectId": p.config.ProjectID, "status": "REQUEST_RELEASE"}, nil, false)
	return false, err
}
func (p *browserbaseProvider) ProfileReady(ctx context.Context, id string) error {
	var out struct {
		ID        string `json:"id"`
		ProjectID string `json:"projectId"`
	}
	if p.request(ctx, "GET", "/contexts/"+id, nil, &out, false) != nil || out.ID != id || out.ProjectID != p.config.ProjectID {
		return errBrowserSignIn
	}
	return nil
}
func (p *browserbaseProvider) DeleteProfile(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := p.request(ctx, "DELETE", "/contexts/"+id, nil, nil, true)
	if errors.Is(err, errBrowserResourceMissing) {
		return nil
	}
	return err
}
