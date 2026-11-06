package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"narthex/backend/internal/upstreamoauth"
)

// ProjectID identifies the dedicated project of the supplied scoped API key.
// Kernel's key supplies the API scope; this ID fences stored profile references
// across configuration changes without coupling them to API-key rotation.
type kernelConfig struct {
	Provider  string `json:"provider"`
	APIKey    string `json:"apiKey"`
	ProjectID string `json:"projectId"`
}

type kernelProvider struct {
	config kernelConfig
	client *http.Client
}

func validKernelConfig(config kernelConfig) bool {
	return config.Provider == "kernel" && validLinkedAccountToken(config.APIKey, false) && browserResourceID(config.ProjectID)
}

func newKernelProvider(config kernelConfig) *kernelProvider {
	client := upstreamoauth.NewHardenedHTTPClient(15 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &kernelProvider{config: config, client: client}
}

func newManagedBrowserSignInProvider(raw string) (managedBrowserSignInProvider, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	config, err := browserProviderConfiguration(raw)
	if err != nil {
		return nil, err
	}
	if config.Provider == "kernel" {
		return newKernelProvider(kernelConfig{Provider: config.Provider, APIKey: config.APIKey, ProjectID: config.ProjectID}), nil
	}
	if config.ManagedAuth != nil {
		return newKernelProvider(*config.ManagedAuth), nil
	}
	return nil, nil
}

func (p *kernelProvider) Kind() string { return "kernel" }
func (p *kernelProvider) ConfigurationID() string {
	return oauthLinkHash("kernel:" + p.config.ProjectID)
}

func (p *kernelProvider) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errBrowserSignIn
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.onkernel.com"+path, reader)
	if err != nil {
		return errBrowserSignIn
	}
	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return errBrowserSignIn
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
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

type kernelProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func kernelProfileName(name string) bool {
	return strings.HasPrefix(name, "synaxis-") && browserResourceID(name)
}

func (*kernelProvider) ProfileReference(flow string) string {
	name := "synaxis-" + flow
	if !browserResourceID(flow) || !kernelProfileName(name) {
		return ""
	}
	return name
}

func (*kernelProvider) SessionReference(id string) string {
	name := "synaxis-browser-" + id
	if !browserResourceID(id) || !browserResourceID(name) {
		return ""
	}
	return name
}

func (p *kernelProvider) CreateProfile(ctx context.Context, flow string) (string, error) {
	name := p.ProfileReference(flow)
	if !kernelProfileName(name) {
		return "", errBrowserSignIn
	}
	var out kernelProfile
	err := p.request(ctx, http.MethodPost, "/profiles", map[string]string{"name": name}, &out)
	if err != nil || !browserResourceID(out.ID) || out.Name != name {
		// The unique name is cleanup authority even if creation's response was
		// lost. GET/DELETE /profiles accepts a name as well as a provider ID.
		return name, errBrowserSignIn
	}
	return name, nil
}

func (p *kernelProvider) ProfileReady(ctx context.Context, profile string) error {
	if !kernelProfileName(profile) {
		return errBrowserSignIn
	}
	var out kernelProfile
	if p.request(ctx, http.MethodGet, "/profiles/"+profile, nil, &out) != nil || out.Name != profile || !browserResourceID(out.ID) {
		return errBrowserSignIn
	}
	return nil
}

type kernelAuth struct {
	ID               string     `json:"id"`
	Domain           string     `json:"domain"`
	ProfileName      string     `json:"profile_name"`
	Status           string     `json:"status"`
	FlowStatus       string     `json:"flow_status"`
	FlowStep         string     `json:"flow_step"`
	FlowExpiresAt    *time.Time `json:"flow_expires_at"`
	InteractionID    string     `json:"interaction_id"`
	BrowserSessionID string     `json:"browser_session_id"`
	Fields           []struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		Type      string `json:"type"`
		InputMode string `json:"input_mode"`
		Required  *bool  `json:"required"`
	} `json:"fields"`
	Choices []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"choices"`
}

func (p *kernelProvider) CreateLogin(ctx context.Context, profile, website string) (string, error) {
	if !kernelProfileName(profile) || !validBrowserWebsite(website) {
		return "", errBrowserSignIn
	}
	u, _ := url.Parse(website)
	domain := strings.ToLower(u.Hostname())
	var out kernelAuth
	body := map[string]any{
		"domain": domain, "profile_name": profile, "login_url": website,
		"allowed_domains": []string{domain}, "save_credentials": false,
		"health_checks": false, "auto_reauth": false, "record_session": false,
		"hitl":    true,
		"browser": map[string]any{"stealth": false, "proxy": map[string]string{"mode": "direct"}, "telemetry": map[string]bool{"enabled": false}},
	}
	if err := p.request(ctx, http.MethodPost, "/auth/connections", body, &out); err != nil {
		// Creation never starts a login. Recover its reference by the unique
		// profile/domain pair, so callers can checkpoint before BeginLogin.
		rows, listErr := p.authConnections(ctx, profile)
		if listErr != nil {
			return "", errBrowserSignIn
		}
		for _, row := range rows {
			if row.Domain == domain && row.ProfileName == profile && browserResourceID(row.ID) {
				return row.ID, nil
			}
		}
		return "", errBrowserSignIn
	}
	if !browserResourceID(out.ID) || out.Domain != domain || out.ProfileName != profile {
		return "", errBrowserSignIn
	}
	return out.ID, nil
}

func (p *kernelProvider) BeginLogin(ctx context.Context, connection string) error {
	if !browserResourceID(connection) {
		return errBrowserSignIn
	}
	var out struct {
		ID string `json:"id"`
	}
	if p.request(ctx, http.MethodPost, "/auth/connections/"+connection+"/login", map[string]any{"record_session": false, "skill_mode": "disabled"}, &out) != nil || out.ID != connection {
		return errBrowserSignIn
	}
	return nil
}

func managedText(value string, limit int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value))
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}

func managedIdentifier(value string) bool {
	return value != "" && len(value) <= 256 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (p *kernelProvider) LoginStatus(ctx context.Context, connection string) (ManagedBrowserStatus, error) {
	out := ManagedBrowserStatus{State: "working", Message: "Signing in…"}
	if !browserResourceID(connection) {
		return out, errBrowserSignIn
	}
	var auth kernelAuth
	if p.request(ctx, http.MethodGet, "/auth/connections/"+connection, nil, &auth) != nil || auth.ID != connection {
		return out, errBrowserSignIn
	}
	if auth.BrowserSessionID != "" {
		if !browserResourceID(auth.BrowserSessionID) {
			return out, errBrowserSignIn
		}
		out.BrowserSessionID = auth.BrowserSessionID
	}
	switch auth.FlowStatus {
	case "SUCCESS":
		if auth.Status != "AUTHENTICATED" {
			return out, errBrowserSignIn
		}
		out.State, out.Message = "succeeded", "Signed in. Saving your account…"
		return out, nil
	case "FAILED", "EXPIRED", "CANCELED":
		out.State, out.Message = "failed", "Sign-in did not finish. Cancel and try again."
		return out, nil
	case "IN_PROGRESS":
		if auth.FlowExpiresAt != nil && !time.Now().Before(*auth.FlowExpiresAt) {
			out.State, out.Message = "failed", "Sign-in expired. Cancel and try again."
			return out, nil
		}
	default:
		return out, errBrowserSignIn
	}
	switch auth.FlowStep {
	case "DISCOVERING", "SUBMITTING", "COMPLETED":
		return out, nil
	case "AWAITING_INPUT":
		out.State, out.Message = "input", "Enter the details requested by this website."
	case "AWAITING_EXTERNAL_ACTION":
		out.State, out.Message = "external", "Complete the website’s verification on your device."
	case "AWAITING_HUMAN_INTERVENTION":
		out.State, out.Message = "external", "Open the sign-in browser to complete this website’s challenge."
	default:
		return out, errBrowserSignIn
	}
	if len(auth.Fields) > 20 || len(auth.Choices) > 20 {
		return out, errBrowserSignIn
	}
	if len(auth.Fields)+len(auth.Choices) > 0 && !managedIdentifier(auth.InteractionID) {
		return out, errBrowserSignIn
	}
	out.InteractionID = auth.InteractionID
	ids := map[string]bool{}
	labels := map[string]string{"identifier": "Username or email", "password": "Password", "code": "Verification code", "totp_code": "Authenticator code", "totp_secret": "Authenticator setup key", "text": "Sign-in details"}
	for _, field := range auth.Fields {
		fallback, supported := labels[field.Type]
		if !supported || !managedIdentifier(field.ID) || ids[field.ID] {
			return out, errBrowserSignIn
		}
		ids[field.ID] = true
		label := managedText(field.Label, 160)
		if label == "" {
			label = fallback
		}
		typ := "text"
		switch field.Type {
		case "password", "totp_secret":
			typ = "password"
		case "code", "totp_code":
			typ = "otp"
		case "identifier":
			if field.InputMode == "email" {
				typ = "email"
			}
		}
		out.Fields = append(out.Fields, ManagedBrowserField{ID: field.ID, Label: label, Type: typ, Required: field.Required == nil || *field.Required})
	}
	for _, choice := range auth.Choices {
		label := managedText(choice.Label, 160)
		if !managedIdentifier(choice.ID) || label == "" || ids[choice.ID] {
			return out, errBrowserSignIn
		}
		ids[choice.ID] = true
		out.Choices = append(out.Choices, ManagedBrowserChoice{ID: choice.ID, Label: label})
	}
	if out.State == "input" && len(out.Fields)+len(out.Choices) == 0 {
		return out, errBrowserSignIn
	}
	return out, nil
}

func (p *kernelProvider) SubmitLogin(ctx context.Context, connection, interaction string, fields map[string]string, choice string) error {
	if !browserResourceID(connection) || !managedIdentifier(interaction) || (len(fields) == 0) == (choice == "") || len(fields) > 20 {
		return errBrowserSignIn
	}
	body := map[string]any{"interaction_id": interaction}
	if choice != "" {
		if !managedIdentifier(choice) {
			return errBrowserSignIn
		}
		body["selected_choice_id"] = choice
	} else {
		total := 0
		for id, value := range fields {
			if !managedIdentifier(id) || len(value) > 4096 {
				return errBrowserSignIn
			}
			total += len(value)
		}
		if total > 16<<10 {
			return errBrowserSignIn
		}
		body["field_values"] = fields
	}
	var out struct {
		Accepted bool `json:"accepted"`
	}
	if p.request(ctx, http.MethodPost, "/auth/connections/"+connection+"/submit", body, &out) != nil || !out.Accepted {
		return errBrowserSignIn
	}
	return nil
}

func (p *kernelProvider) DeleteLogin(ctx context.Context, connection string) error {
	if connection == "" {
		return nil
	}
	if !browserResourceID(connection) {
		return errBrowserSignIn
	}
	var auth kernelAuth
	err := p.request(ctx, http.MethodGet, "/auth/connections/"+connection, nil, &auth)
	if errors.Is(err, errBrowserResourceMissing) {
		return nil
	}
	if err != nil || auth.ID != connection || !kernelProfileName(auth.ProfileName) {
		return errBrowserSignIn
	}
	err = p.request(ctx, http.MethodDelete, "/auth/connections/"+connection, nil, nil)
	if err != nil && !errors.Is(err, errBrowserResourceMissing) {
		return err
	}
	if auth.BrowserSessionID != "" {
		if _, err = p.Stop(ctx, auth.BrowserSessionID); err != nil {
			return err
		}
	}
	return p.stopProfileBrowsers(ctx, auth.ProfileName)
}

func (p *kernelProvider) authConnections(ctx context.Context, profile string) ([]kernelAuth, error) {
	var matches []kernelAuth
	for offset := 0; offset < 1000; offset += 100 {
		var rows []kernelAuth
		path := "/auth/connections?profile_name=" + url.QueryEscape(profile) + "&limit=100&offset=" + strconv.Itoa(offset)
		if err := p.request(ctx, http.MethodGet, path, nil, &rows); err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.ProfileName == profile {
				matches = append(matches, row)
			}
		}
		if len(rows) < 100 {
			return matches, nil
		}
	}
	return nil, errBrowserSignIn
}

func (p *kernelProvider) DeleteProfile(ctx context.Context, profile string) error {
	if profile == "" {
		return nil
	}
	if !kernelProfileName(profile) {
		return errBrowserSignIn
	}
	// Profile identity survives a lost create response. Reconcile connection
	// references first, so an uncheckpointed login cannot recreate saved state.
	connections, err := p.authConnections(ctx, profile)
	if err != nil {
		return err
	}
	for _, connection := range connections {
		if err = p.DeleteLogin(ctx, connection.ID); err != nil {
			return err
		}
		if connection.BrowserSessionID != "" {
			if _, err = p.Stop(ctx, connection.BrowserSessionID); err != nil {
				return err
			}
		}
	}
	if err = p.stopProfileBrowsers(ctx, profile); err != nil {
		return err
	}
	err = p.request(ctx, http.MethodDelete, "/profiles/"+profile, nil, nil)
	if errors.Is(err, errBrowserResourceMissing) {
		return nil
	}
	return err
}
