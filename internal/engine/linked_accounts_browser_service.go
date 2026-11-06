package engine

import (
	"context"
	"errors"
	"time"
)

type BrowserSignInAvailability struct {
	Available        bool   `json:"available"`
	Provider         string `json:"provider,omitempty"`
	ManagedAvailable bool   `json:"managedAvailable"`
	ManagedProvider  string `json:"managedProvider,omitempty"`
}
type BrowserSignInService struct {
	provider        browserSignInProvider
	managedProvider managedBrowserSignInProvider
	flows           BrowserSignInStore
	accounts        LinkedAccountStore
	store           AccountStore
}

// The provider factory is replaced only in the explicitly tagged E2E build.
var browserSignInProviderFactory = newBrowserSignInProvider
var managedBrowserSignInProviderFactory = newManagedBrowserSignInProvider

func NewBrowserSignInService(raw string, store AccountStore) (*BrowserSignInService, error) {
	provider, err := browserSignInProviderFactory(raw)
	if err != nil {
		return nil, err
	}
	managed, err := managedBrowserSignInProviderFactory(raw)
	if err != nil {
		return nil, err
	}
	flows, ok := store.(BrowserSignInStore)
	accounts, links := store.(LinkedAccountStore)
	if !ok || !links {
		return nil, errBrowserSignIn
	}
	return &BrowserSignInService{provider: provider, managedProvider: managed, flows: flows, accounts: accounts, store: store}, nil
}
func WithBrowserSignIn(service *BrowserSignInService) ConsoleOption {
	return func(c *ConsoleAPI) { c.browserSignIn = service }
}
func (s *BrowserSignInService) availability() *BrowserSignInAvailability {
	out := &BrowserSignInAvailability{}
	if s != nil && s.provider != nil {
		out.Available = true
		out.Provider = s.provider.Kind()
	}
	if s != nil && s.managedProvider != nil {
		out.ManagedAvailable = true
		out.ManagedProvider = s.managedProvider.Kind()
	}
	return out
}
func (s *BrowserSignInService) configured(f BrowserSignIn) bool {
	return s.providerFor(f.Provider, f.ConfigurationID) != nil
}
func (s *BrowserSignInService) write(ctx context.Context, f BrowserSignIn) (BrowserSignIn, error) {
	return s.flows.WriteBrowserSignIn(ctx, f, f.Revision)
}
func (s *BrowserSignInService) lookup(ctx context.Context, id string) (BrowserSignIn, error) {
	flows, err := s.flows.BrowserSignIns(ctx)
	if err != nil {
		return BrowserSignIn{}, err
	}
	for _, f := range flows {
		if f.ID == id {
			return f, nil
		}
	}
	return BrowserSignIn{}, ErrLinkedAccountNotFound
}
func (s *BrowserSignInService) start(ctx context.Context, f BrowserSignIn) (BrowserSignIn, error) {
	provider := s.signInProvider(f.Method)
	if provider == nil {
		return f, errBrowserSignIn
	}
	f.ID = "bsign_" + newEpoch()
	f.State = "starting"
	f.ExpiresAt = time.Now().UTC().Add(browserSignInLifetime)
	f.Provider = provider.Kind()
	f.ConfigurationID = provider.ConfigurationID()
	// Named providers can be reconciled after a crash even if no allocation
	// response was received. Persist their cleanup references before I/O.
	named, hasNames := provider.(namedBrowserResources)
	if hasNames {
		f.ProfileID = named.ProfileReference(f.ID)
		if f.Method != "credentials" {
			f.SessionID = named.SessionReference(f.ID)
		}
	}
	var err error
	f, err = s.flows.WriteBrowserSignIn(ctx, f, 0)
	if err != nil {
		return f, err
	}
	// A disconnected client must not prevent checkpointing acquired resources.
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancel()
	fail := func() (BrowserSignIn, error) {
		f.State = "cleanup"
		_, _ = s.write(checkpoint, f)
		return f, errBrowserSignIn
	}
	profileID, err := provider.CreateProfile(ctx, f.ID)
	if !hasNames {
		f.ProfileID = profileID
	} else if profileID != f.ProfileID {
		return fail()
	}
	if err != nil {
		return fail()
	}
	f, err = s.write(checkpoint, f)
	if err != nil {
		_ = provider.DeleteProfile(checkpoint, f.ProfileID)
		return f, errBrowserSignIn
	}
	if f.Method == "credentials" {
		managed := provider.(managedBrowserSignInProvider)
		f.AuthConnectionID, err = managed.CreateLogin(ctx, f.ProfileID, f.WebsiteURL)
		if err != nil {
			return fail()
		}
		f, err = s.write(checkpoint, f)
		if err != nil {
			_ = managed.DeleteLogin(checkpoint, f.AuthConnectionID)
			return f, errBrowserSignIn
		}
		if err = managed.BeginLogin(ctx, f.AuthConnectionID); err != nil {
			return fail()
		}
		f.AllocationReady = true
		f.State = "ready"
		return s.write(checkpoint, f)
	}
	var connectURL string
	if hasNames {
		var sessionID string
		sessionID, connectURL, err = named.CreateNamedSession(ctx, f.ProfileID, f.SessionID)
		if sessionID != f.SessionID {
			return fail()
		}
	} else {
		f.SessionID, connectURL, err = provider.CreateSession(ctx, f.ProfileID)
	}
	if err != nil {
		return fail()
	}
	f, err = s.write(checkpoint, f)
	if err != nil {
		_, _ = provider.Stop(checkpoint, f.SessionID)
		return f, errBrowserSignIn
	}
	if provider.Navigate(ctx, connectURL, f.WebsiteURL) != nil {
		return fail()
	}
	f.AllocationReady = true
	f.State = "ready"
	return s.write(checkpoint, f)
}

// advance only closes sessions and synchronizes/erases profiles. Saving an
// account itself always requires another currently authenticated API request.
func (s *BrowserSignInService) advance(ctx context.Context, f BrowserSignIn) (BrowserSignIn, error) {
	provider := s.providerFor(f.Provider, f.ConfigurationID)
	if provider == nil {
		return f, errBrowserSignIn
	}
	now := time.Now()
	_, parentCurrent := s.browserSignInParent(f)
	if browserFlowPending(f) && (!parentCurrent || now.After(f.ExpiresAt)) {
		f.State = "cleanup"
		var err error
		f, err = s.write(ctx, f)
		if err != nil {
			return f, err
		}
	}
	if f.State == "saved" {
		records, err := s.accounts.LinkedAccounts(ctx, f.OwnerSubject)
		if err != nil {
			return f, err
		}
		if browserProfileRetained(f, records) {
			return f, nil
		}
		f.State = "cleanup"
		f, err = s.write(ctx, f)
		if err != nil {
			return f, err
		}
	}
	if f.State != "saving" && f.State != "cleanup" {
		return f, nil
	}
	if f.Method == "credentials" {
		return s.advanceManaged(ctx, f, provider)
	}
	// An unknown session creation outcome cannot be stopped by ID. Let its
	// provider-enforced lifetime elapse before deleting the known context.
	if f.SessionID == "" && now.Before(f.ExpiresAt.Add(time.Minute)) {
		return f, nil
	}
	stopped, err := provider.Stop(ctx, f.SessionID)
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
	if f.SyncAfter.IsZero() {
		f.SyncAfter = now.Add(5 * time.Second)
		return s.write(ctx, f)
	}
	if now.Before(f.SyncAfter) {
		return f, nil
	}
	if f.State == "saving" {
		return f, provider.ProfileReady(ctx, f.ProfileID)
	}
	if s.browserProfileBusy(ctx, BrowserProfile{ProfileID: f.ProfileID, ConfigurationID: f.ConfigurationID}) {
		return f, nil
	}
	if err = provider.DeleteProfile(ctx, f.ProfileID); err != nil {
		return f, err
	}
	if _, named := provider.(namedBrowserResources); named && !f.AllocationReady && now.Before(f.ExpiresAt.Add(time.Minute)) {
		// A provider can finish a timed-out create after an initial 404 delete.
		// Retain the named cleanup reference and retry through that window.
		return f, nil
	}
	f.State = "closed"
	return s.write(ctx, f)
}

// Run reaps abandoned sessions and detached profiles after restart and across
// multiple Engine processes. Revision CAS makes provider deletions idempotent.
func (s *BrowserSignInService) Run(ctx context.Context) {
	if s == nil || (s.provider == nil && s.managedProvider == nil) {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		s.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *BrowserSignInService) Reconcile(ctx context.Context) {
	s.reapBrowserRuns(ctx)
	flows, err := s.flows.BrowserSignIns(ctx)
	if err != nil {
		return
	}
	for _, f := range flows {
		if ctx.Err() != nil {
			return
		}
		_, _ = s.advance(ctx, f)
	}
}
func browserConflict(err error) bool {
	return errors.Is(err, errBrowserRevision) || errors.Is(err, ErrLinkedAccountRevision) || errors.Is(err, ErrAccountPolicyPrecondition) || errors.Is(err, ErrLinkedAccountNotFound)
}

func browserProfileRetained(f BrowserSignIn, records []LinkedAccountRecord) bool {
	for _, r := range records {
		if r.ID == f.AccountID && r.Browser != nil && r.Browser.FlowID == f.ID && r.Browser.ProfileID == f.ProfileID {
			return true
		}
	}
	return false
}
