package engine

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var errManagedInput = errors.New("invalid sign-in fields")

func (s *BrowserSignInService) signInProvider(method string) browserSignInProvider {
	if s == nil {
		return nil
	}
	if method == "credentials" {
		if s.managedProvider == nil {
			return nil
		}
		return s.managedProvider
	}
	if method == "" || method == "browser" {
		return s.provider
	}
	return nil
}

// Resolve each saved profile against its own provider and configuration. Adding
// managed login must not strand existing Browserbase accounts or grant access
// to profiles from a different provider project.
func (s *BrowserSignInService) providerFor(kind, configuration string) browserSignInProvider {
	if s == nil {
		return nil
	}
	if p := s.provider; p != nil && p.Kind() == kind && p.ConfigurationID() == configuration {
		return p
	}
	if p := s.managedProvider; p != nil && p.Kind() == kind && p.ConfigurationID() == configuration {
		return p
	}
	return nil
}

func (s *BrowserSignInService) runtimeProvider(profile BrowserProfile) browserRuntimeProvider {
	p, _ := s.providerFor(profile.Provider, profile.ConfigurationID).(browserRuntimeProvider)
	return p
}

func (s *BrowserSignInService) managedStatus(ctx context.Context, f BrowserSignIn) (ManagedBrowserStatus, error) {
	p, ok := s.providerFor(f.Provider, f.ConfigurationID).(managedBrowserSignInProvider)
	if !ok || f.Method != "credentials" || f.AuthConnectionID == "" {
		return ManagedBrowserStatus{}, errBrowserSignIn
	}
	return p.LoginStatus(ctx, f.AuthConnectionID)
}

func (s *BrowserSignInService) publicDTO(ctx context.Context, f BrowserSignIn) (browserSignInDTO, error) {
	out := s.dto(f)
	if f.Method != "credentials" || f.State != "ready" || !out.Available || time.Now().After(f.ExpiresAt) {
		return out, nil
	}
	status, err := s.managedStatus(ctx, f)
	if err != nil {
		return out, err
	}
	if time.Now().After(f.ExpiresAt) {
		out.CanSave = false
		return out, nil
	}
	// A claimed interaction is never silently retried after a lost response.
	// The provider must move to a new interaction before another submission.
	if status.InteractionID != "" && status.InteractionID == f.LastInteractionID && (status.State == "input" || status.State == "external") {
		status.State = "working"
		status.Fields = nil
		status.Choices = nil
		status.Message = "Checking the last sign-in attempt. Cancel to start again."
	}
	out.Login = &status
	out.CanSave = status.State == "succeeded"
	return out, nil
}

func validManagedSubmission(status ManagedBrowserStatus, interaction string, values map[string]string, choice string) bool {
	if (status.State != "input" && status.State != "external") || interaction == "" || status.InteractionID != interaction || len(values) > 20 {
		return false
	}
	if choice != "" {
		if len(values) != 0 {
			return false
		}
		for _, c := range status.Choices {
			if c.ID == choice {
				return true
			}
		}
		return false
	}
	if len(values) == 0 || len(status.Fields) == 0 || len(status.Fields) > 20 {
		return false
	}
	known := make(map[string]bool, len(status.Fields))
	for _, field := range status.Fields {
		if field.ID == "" || known[field.ID] {
			return false
		}
		known[field.ID] = true
		value, found := values[field.ID]
		if field.Required && (!found || value == "") {
			return false
		}
	}
	for id, value := range values {
		if !known[id] || len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
			return false
		}
	}
	return true
}

// Credential values live only in this request and the provider submission.
// The durable CAS records the attempted interaction, never its values.
func (s *BrowserSignInService) submitManaged(ctx context.Context, f BrowserSignIn, interaction string, values map[string]string, choice string, authorized func() bool) (BrowserSignIn, error) {
	if f.Method != "credentials" || f.State != "ready" || time.Now().After(f.ExpiresAt) || interaction == f.LastInteractionID {
		return f, errBrowserRevision
	}
	status, err := s.managedStatus(ctx, f)
	if err != nil {
		return f, err
	}
	if !validManagedSubmission(status, interaction, values, choice) {
		return f, errManagedInput
	}
	parent, found := s.store.Account(f.ConnectionID)
	if !found || !f.Parent.matches(parent) || time.Now().After(f.ExpiresAt) || !authorized() {
		return f, errBrowserRevision
	}
	f.LastInteractionID = interaction
	f, err = s.write(ctx, f)
	if err != nil {
		return f, err
	}
	p := s.providerFor(f.Provider, f.ConfigurationID).(managedBrowserSignInProvider)
	if err = p.SubmitLogin(ctx, f.AuthConnectionID, interaction, values, choice); err != nil {
		return f, errBrowserSignIn
	}
	return f, nil
}

func (s *BrowserSignInService) advanceManaged(ctx context.Context, f BrowserSignIn, provider browserSignInProvider) (BrowserSignIn, error) {
	p, ok := provider.(managedBrowserSignInProvider)
	if !ok {
		return f, errBrowserSignIn
	}
	if f.SessionID == "" && f.AuthConnectionID != "" {
		status, err := p.LoginStatus(ctx, f.AuthConnectionID)
		if err == nil && status.BrowserSessionID != "" {
			f.SessionID = status.BrowserSessionID
			f, err = s.write(ctx, f)
			if err != nil {
				return f, err
			}
		}
	}
	// Deleting the login connection stops its flow. Its saved profile is a
	// separate resource, retained on success and removed on cancellation.
	if f.AuthConnectionID != "" {
		if err := p.DeleteLogin(ctx, f.AuthConnectionID); err != nil {
			return f, err
		}
	}
	if f.SessionID != "" {
		stopped, err := p.Stop(ctx, f.SessionID)
		if err != nil {
			return f, err
		}
		if !stopped {
			if !f.SyncAfter.IsZero() {
				f.SyncAfter = time.Time{}
				return s.write(ctx, f)
			}
			return f, nil
		}
	}
	if f.SyncAfter.IsZero() {
		f.SyncAfter = time.Now().Add(5 * time.Second)
		return s.write(ctx, f)
	}
	if time.Now().Before(f.SyncAfter) {
		return f, nil
	}
	if f.State == "saving" {
		return f, p.ProfileReady(ctx, f.ProfileID)
	}
	if s.browserProfileBusy(ctx, BrowserProfile{Provider: f.Provider, ProfileID: f.ProfileID, ConfigurationID: f.ConfigurationID}) {
		return f, nil
	}
	if err := p.DeleteProfile(ctx, f.ProfileID); err != nil {
		return f, err
	}
	if f.AuthConnectionID == "" && time.Now().Before(f.ExpiresAt.Add(time.Minute)) {
		// A lost create response can arrive after an initial empty lookup or
		// 404 deletion. Keep reconciling the named profile and its connections.
		return f, nil
	}
	f.State = "closed"
	return s.write(ctx, f)
}
