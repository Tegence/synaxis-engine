package oauthas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryTokenGenerationStore struct {
	mu           sync.Mutex
	generation   string
	loadErr      error
	currentErr   error
	rotateErr    error
	currentReads int
}

type blockingCurrentGenerationStore struct {
	*memoryTokenGenerationStore
	readMu      sync.Mutex
	readCount   int
	firstRead   chan struct{}
	releaseRead chan struct{}
}

type blockingResponseWriter struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingResponseWriter() *blockingResponseWriter {
	return &blockingResponseWriter{
		header:  make(http.Header),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingResponseWriter) Header() http.Header { return w.header }

func (w *blockingResponseWriter) WriteHeader(status int) { w.status = status }

func (w *blockingResponseWriter) Write(payload []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.body.Write(payload)
}

func (s *memoryTokenGenerationStore) LoadOrCreateTokenGeneration(_ context.Context, candidate string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return "", s.loadErr
	}
	if s.generation == "" {
		s.generation = candidate
	}
	return s.generation, nil
}

func (s *memoryTokenGenerationStore) CurrentTokenGeneration(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentReads++
	if s.currentErr != nil {
		return "", s.currentErr
	}
	return s.generation, nil
}

func (s *blockingCurrentGenerationStore) CurrentTokenGeneration(_ context.Context) (string, error) {
	s.memoryTokenGenerationStore.mu.Lock()
	generation := s.memoryTokenGenerationStore.generation
	currentErr := s.memoryTokenGenerationStore.currentErr
	s.memoryTokenGenerationStore.currentReads++
	s.memoryTokenGenerationStore.mu.Unlock()

	s.readMu.Lock()
	s.readCount++
	readNumber := s.readCount
	s.readMu.Unlock()
	if readNumber == 1 {
		close(s.firstRead)
		<-s.releaseRead
	}
	if currentErr != nil {
		return "", currentErr
	}
	return generation, nil
}

func (s *memoryTokenGenerationStore) RotateTokenGeneration(_ context.Context, expected, replacement string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotateErr != nil {
		return "", s.rotateErr
	}
	if s.generation != expected {
		return s.generation, nil
	}
	s.generation = replacement
	return s.generation, nil
}

func configureGeneration(t *testing.T, server *Server, store TokenGenerationStore) {
	t.Helper()
	if err := server.ConfigureTokenGeneration(context.Background(), store); err != nil {
		t.Fatalf("ConfigureTokenGeneration: %v", err)
	}
}

func rootEpoch(path string) (string, bool) {
	return "root-resource-generation", path == "/mcp"
}

func newGenerationServer(t *testing.T, store TokenGenerationStore) *Server {
	t.Helper()
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	configureGeneration(t, server, store)
	return server
}

func serverGeneration(server *Server) string {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.tokenGeneration
}

func TestDurableTokenGenerationSurvivesRestartAndRevocationNeverResurrects(t *testing.T) {
	store := &memoryTokenGenerationStore{}

	first := New("https://engine.example", "pw", "shared-signing-secret")
	first.SetEpochLookup(rootEpoch)
	configureGeneration(t, first, store)
	beforeRevoke, ok := first.signAccess("client-1", "/mcp")
	if !ok || !first.validAccess(beforeRevoke, "/mcp") {
		t.Fatal("first Engine could not mint a valid access token")
	}

	// A cold start adopts the same durable generation, so access tokens do not
	// all die merely because Cloud Run scaled the Engine to zero.
	second := New("https://engine.example", "pw", "shared-signing-secret")
	second.SetEpochLookup(rootEpoch)
	configureGeneration(t, second, store)
	if !second.validAccess(beforeRevoke, "/mcp") {
		t.Fatal("access token did not survive an Engine restart")
	}

	if err := second.RevokeAll(context.Background()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if second.validAccess(beforeRevoke, "/mcp") {
		t.Fatal("revoked access token remained valid on the revoking Engine")
	}
	afterRevoke, ok := second.signAccess("client-1", "/mcp")
	if !ok || !second.validAccess(afterRevoke, "/mcp") {
		t.Fatal("Engine could not mint a valid token after revocation")
	}

	// A later restart must retain the rotated generation: the revoked token
	// stays dead while a token minted after revocation remains valid.
	third := New("https://engine.example", "pw", "shared-signing-secret")
	third.SetEpochLookup(rootEpoch)
	configureGeneration(t, third, store)
	if third.validAccess(beforeRevoke, "/mcp") {
		t.Fatal("revoked access token resurrected after an Engine restart")
	}
	if !third.validAccess(afterRevoke, "/mcp") {
		t.Fatal("post-revocation access token did not survive restart")
	}
}

func TestStaleServerRevokeAdvancesBeyondTheDurableGenerationItDiscovers(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	first := newGenerationServer(t, store)
	stale := newGenerationServer(t, store)
	initial := serverGeneration(stale)

	if err := first.RevokeAll(context.Background()); err != nil {
		t.Fatalf("first RevokeAll: %v", err)
	}
	afterFirst, err := store.CurrentTokenGeneration(context.Background())
	if err != nil {
		t.Fatalf("CurrentTokenGeneration after first revoke: %v", err)
	}
	if afterFirst == initial {
		t.Fatal("first revoke did not advance the durable generation")
	}
	if got := serverGeneration(stale); got != initial {
		t.Fatalf("stale server unexpectedly synchronized itself: got %q want %q", got, initial)
	}

	// stale still expects the initial generation. Its revoke must first learn
	// afterFirst, then win another CAS; merely adopting afterFirst is not a
	// completed revoke operation.
	if err := stale.RevokeAll(context.Background()); err != nil {
		t.Fatalf("stale RevokeAll: %v", err)
	}
	afterStaleRevoke, err := store.CurrentTokenGeneration(context.Background())
	if err != nil {
		t.Fatalf("CurrentTokenGeneration after stale revoke: %v", err)
	}
	if afterStaleRevoke == initial || afterStaleRevoke == afterFirst {
		t.Fatalf("stale revoke merely adopted an existing generation: initial=%q first=%q final=%q", initial, afterFirst, afterStaleRevoke)
	}
	if got := serverGeneration(stale); got != afterStaleRevoke {
		t.Fatalf("stale server generation = %q, durable = %q", got, afterStaleRevoke)
	}
}

func TestStaleServerSynchronizesBeforeAuthorizationSensitivePaths(t *testing.T) {
	t.Run("RequireAuth rejects an old access token", func(t *testing.T) {
		store := &memoryTokenGenerationStore{}
		first := newGenerationServer(t, store)
		stale := newGenerationServer(t, store)
		oldToken, ok := stale.signAccess("client-1", "/mcp")
		if !ok {
			t.Fatal("mint old access token")
		}
		stale.mu.Lock()
		generation := stale.tokenGeneration
		stale.codes["stale-code"] = authCode{generation: generation}
		stale.refresh["stale-refresh"] = refreshGrant{generation: generation}
		stale.mu.Unlock()

		if err := first.RevokeAll(context.Background()); err != nil {
			t.Fatalf("first RevokeAll: %v", err)
		}
		durable, _ := store.CurrentTokenGeneration(context.Background())
		called := false
		handler := stale.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}))
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+oldToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || called {
			t.Fatalf("stale RequireAuth = %d called=%v, want 401/false; body %s", rec.Code, called, rec.Body)
		}
		if got := serverGeneration(stale); got != durable {
			t.Fatalf("stale server adopted %q, want durable %q", got, durable)
		}
		stale.mu.RLock()
		codeCount, refreshCount := len(stale.codes), len(stale.refresh)
		stale.mu.RUnlock()
		if codeCount != 0 || refreshCount != 0 {
			t.Fatalf("generation synchronization left codes=%d refresh=%d", codeCount, refreshCount)
		}
	})

	t.Run("token endpoint cannot redeem stale grants", func(t *testing.T) {
		store := &memoryTokenGenerationStore{}
		first := newGenerationServer(t, store)
		stale := newGenerationServer(t, store)
		stale.mu.Lock()
		stale.refresh["stale-refresh"] = refreshGrant{
			clientID:   "client-1",
			resource:   "/mcp",
			generation: stale.tokenGeneration,
		}
		stale.mu.Unlock()
		if err := first.RevokeAll(context.Background()); err != nil {
			t.Fatalf("first RevokeAll: %v", err)
		}

		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"stale-refresh"}}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		stale.handleToken(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("stale refresh redemption = %d, want 400; body %s", rec.Code, rec.Body)
		}
	})

	t.Run("authorize rejects stale consent then issues only after retry", func(t *testing.T) {
		store := &memoryTokenGenerationStore{}
		first := newGenerationServer(t, store)
		stale := newGenerationServer(t, store)
		const clientID = "mcp_client"
		const redirect = "https://client.example/callback"
		stale.mu.Lock()
		stale.clients[clientID] = client{redirectURIs: map[string]bool{redirect: true}}
		stale.mu.Unlock()
		if err := first.RevokeAll(context.Background()); err != nil {
			t.Fatalf("first RevokeAll: %v", err)
		}
		durable, _ := store.CurrentTokenGeneration(context.Background())

		verifier := strings.Repeat("v", 64)
		form := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {redirect},
			"response_type":         {"code"},
			"code_challenge_method": {"S256"},
			"code_challenge":        {pkceChallenge(verifier)},
			"scope":                 {"mcp"},
			"resource":              {"https://engine.example/mcp"},
			"password":              {"pw"},
		}
		req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		stale.handleAuthorize(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize after external rotation = %d, body %s", rec.Code, rec.Body)
		}
		redirectURL, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse authorize redirect: %v", err)
		}
		if redirectURL.Query().Get("code") != "" || redirectURL.Query().Get("error") != "invalid_request" {
			t.Fatalf("stale authorize did not fail closed: %q", redirectURL)
		}

		retryReq := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		retryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		retryRec := httptest.NewRecorder()
		stale.handleAuthorize(retryRec, retryReq)
		if retryRec.Code != http.StatusFound {
			t.Fatalf("authorize retry = %d, body %s", retryRec.Code, retryRec.Body)
		}
		retryRedirect, err := url.Parse(retryRec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse authorize retry redirect: %v", err)
		}
		code := retryRedirect.Query().Get("code")
		stale.mu.RLock()
		issued, exists := stale.codes[code]
		stale.mu.RUnlock()
		if !exists || issued.generation != durable {
			t.Fatalf("authorize issued generation %q exists=%v, want durable %q", issued.generation, exists, durable)
		}
	})

	t.Run("hosted completion rejects a pending consent from the old generation", func(t *testing.T) {
		store := &memoryTokenGenerationStore{}
		first := newGenerationServer(t, store)
		harness := newHostedConsentHarness(t)
		configureGeneration(t, harness.server, store)
		requestToken := harness.authorize(t, "https://engine.example/mcp")
		assertion := approvalAssertion(t, harness.privateKey, harness.claims(requestToken, "approval_jti_external_rotation"))
		if err := first.RevokeAll(context.Background()); err != nil {
			t.Fatalf("first RevokeAll: %v", err)
		}
		rec := completeHostedConsent(harness.mux, requestToken, assertion, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("hosted completion after external rotation = %d, want 400; body %s", rec.Code, rec.Body)
		}
	})
}

func TestOlderGenerationReadCannotRollBackANewerLocalSynchronization(t *testing.T) {
	store := &blockingCurrentGenerationStore{
		memoryTokenGenerationStore: &memoryTokenGenerationStore{},
		firstRead:                  make(chan struct{}),
		releaseRead:                make(chan struct{}),
	}
	first := newGenerationServer(t, store)
	stale := newGenerationServer(t, store)
	initial := serverGeneration(stale)

	oldReadDone := make(chan error, 1)
	go func() { oldReadDone <- stale.syncTokenGeneration(context.Background()) }()
	awaitSignal(t, store.firstRead, "first current-generation read")
	if err := first.RevokeAll(context.Background()); err != nil {
		t.Fatalf("first RevokeAll: %v", err)
	}
	afterFirst, _ := store.memoryTokenGenerationStore.CurrentTokenGeneration(context.Background())
	if afterFirst == initial {
		t.Fatal("external revoke did not advance generation")
	}
	if err := stale.RevokeAll(context.Background()); err != nil {
		t.Fatalf("local RevokeAll while durable read was in flight: %v", err)
	}
	durable, _ := store.memoryTokenGenerationStore.CurrentTokenGeneration(context.Background())
	if durable == afterFirst {
		t.Fatal("local revoke did not advance beyond the externally rotated generation")
	}
	close(store.releaseRead)
	if err := awaitError(t, oldReadDone, "older generation read"); err != nil {
		t.Fatalf("older syncTokenGeneration: %v", err)
	}
	if got := serverGeneration(stale); got != durable {
		t.Fatalf("older in-flight read rolled generation back to %q; want %q", got, durable)
	}
}

func TestConcurrentGenerationSynchronizationsApplyTheNewestDurableValue(t *testing.T) {
	store := &blockingCurrentGenerationStore{
		memoryTokenGenerationStore: &memoryTokenGenerationStore{},
		firstRead:                  make(chan struct{}),
		releaseRead:                make(chan struct{}),
	}
	remote := newGenerationServer(t, store)
	stale := newGenerationServer(t, store)
	if err := remote.RevokeAll(context.Background()); err != nil {
		t.Fatalf("rotate to H: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- stale.syncTokenGeneration(context.Background()) }()
	awaitSignal(t, store.firstRead, "stale H read")
	if err := remote.RevokeAll(context.Background()); err != nil {
		t.Fatalf("rotate to J: %v", err)
	}
	store.memoryTokenGenerationStore.mu.Lock()
	newest := store.memoryTokenGenerationStore.generation
	store.memoryTokenGenerationStore.mu.Unlock()

	secondDone := make(chan error, 1)
	secondAttempted := make(chan struct{})
	go func() {
		secondDone <- stale.syncTokenGenerationWithHook(context.Background(), func() { close(secondAttempted) })
	}()
	awaitSignal(t, secondAttempted, "second generation sync attempt")
	// The second synchronization must not issue a newer durable read until the
	// first read+apply completes; this prevents completion-order inversion.
	store.memoryTokenGenerationStore.mu.Lock()
	readsWhileBlocked := store.memoryTokenGenerationStore.currentReads
	store.memoryTokenGenerationStore.mu.Unlock()
	if readsWhileBlocked != 1 {
		t.Fatalf("durable reads while first sync blocked = %d, want 1", readsWhileBlocked)
	}

	close(store.releaseRead)
	if err := awaitError(t, firstDone, "first generation sync"); err != nil {
		t.Fatalf("first syncTokenGeneration: %v", err)
	}
	if err := awaitError(t, secondDone, "second generation sync"); err != nil {
		t.Fatalf("second syncTokenGeneration: %v", err)
	}
	if got := serverGeneration(stale); got != newest {
		t.Fatalf("concurrent synchronizations left generation %q, want newest %q", got, newest)
	}
}

func TestGenerationReadFailuresFailClosedWithoutLeakingDetails(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	server := newGenerationServer(t, store)
	token, ok := server.signAccess("client-1", "/mcp")
	if !ok {
		t.Fatal("mint access token")
	}
	const clientID = "legacy_client"
	const redirect = "https://client.example/callback"
	verifier := strings.Repeat("v", 64)
	server.mu.Lock()
	server.clients[clientID] = client{redirectURIs: map[string]bool{redirect: true}}
	server.refresh["known-refresh"] = refreshGrant{
		clientID:   clientID,
		resource:   "/mcp",
		generation: server.tokenGeneration,
	}
	server.mu.Unlock()
	store.mu.Lock()
	store.currentErr = errors.New("top-secret generation-store detail")
	store.mu.Unlock()

	authorizeForm := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {pkceChallenge(verifier)},
		"resource":              {"https://engine.example/mcp"},
		"password":              {"pw"},
	}
	authorizeRequest := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(authorizeForm.Encode()))
	authorizeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"known-refresh"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cases := []struct {
		name    string
		handler http.Handler
		request *http.Request
	}{
		{
			name: "RequireAuth",
			handler: server.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("request reached protected handler after generation read failure")
			})),
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			}(),
		},
		{name: "authorize", handler: http.HandlerFunc(server.handleAuthorize), request: authorizeRequest},
		{name: "token", handler: http.HandlerFunc(server.handleToken), request: tokenRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, tc.request)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("generation read failure = %d, want 503; body %s", rec.Code, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "top-secret") {
				t.Fatalf("generation read failure leaked storage detail: %s", rec.Body)
			}
		})
	}

	t.Run("hosted completion", func(t *testing.T) {
		hostedStore := &memoryTokenGenerationStore{}
		harness := newHostedConsentHarness(t)
		configureGeneration(t, harness.server, hostedStore)
		requestToken := harness.authorize(t, "https://engine.example/mcp")
		assertion := approvalAssertion(t, harness.privateKey, harness.claims(requestToken, "approval_jti_store_failure"))
		hostedStore.mu.Lock()
		hostedStore.currentErr = errors.New("top-secret generation-store detail")
		hostedStore.mu.Unlock()
		rec := completeHostedConsent(harness.mux, requestToken, assertion, nil)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("generation read failure = %d, want 503; body %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "top-secret") {
			t.Fatalf("generation read failure leaked storage detail: %s", rec.Body)
		}
	})
}

func TestAnonymousAndForgedAuthorizationTrafficDoesNotReadDurableGeneration(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	server := newGenerationServer(t, store)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("forged request reached protected handler")
	})
	protected := server.RequireAuth(next)

	future := strconv.FormatInt(server.now().Add(time.Hour).Unix(), 10)
	shapedForgery := future + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("client-1")) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("/mcp"))
	for i := 0; i < 200; i++ {
		for _, authorization := range []string{"", "Bearer junk", "Bearer " + shapedForgery} {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("forged Authorization %q = %d, want 401", authorization, rec.Code)
			}
		}

		tokenForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unknown"}}
		tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokenRec := httptest.NewRecorder()
		server.handleToken(tokenRec, tokenReq)
		if tokenRec.Code != http.StatusBadRequest {
			t.Fatalf("unknown refresh = %d, want 400", tokenRec.Code)
		}

		authorizeRec := httptest.NewRecorder()
		server.handleAuthorize(authorizeRec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
		if authorizeRec.Code != http.StatusBadRequest {
			t.Fatalf("anonymous authorize = %d, want 400", authorizeRec.Code)
		}

		hostedRec := httptest.NewRecorder()
		server.handleHostedConsentComplete(hostedRec, httptest.NewRequest(http.MethodPost, "/authorize/complete", nil))
		if hostedRec.Code != http.StatusNotFound {
			t.Fatalf("anonymous hosted completion = %d, want 404", hostedRec.Code)
		}
	}
	store.mu.Lock()
	reads := store.currentReads
	store.mu.Unlock()
	if reads != 0 {
		t.Fatalf("anonymous/forged traffic caused %d durable generation reads, want 0", reads)
	}
}

func TestLocallyAuthenticAccessTokenReadsDurableGenerationAndDiesImmediatelyAfterRemoteRevoke(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	remote := newGenerationServer(t, store)
	stale := newGenerationServer(t, store)
	token, ok := stale.signAccess("client-1", "/mcp")
	if !ok {
		t.Fatal("mint access token")
	}
	if err := remote.RevokeAll(context.Background()); err != nil {
		t.Fatalf("remote RevokeAll: %v", err)
	}

	called := false
	handler := stale.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("revoked locally authentic token = %d called=%v, want 401/false", rec.Code, called)
	}
	store.mu.Lock()
	reads := store.currentReads
	store.mu.Unlock()
	if reads != 1 {
		t.Fatalf("locally authentic token caused %d durable reads, want 1", reads)
	}
}

func TestRevokeAllPersistenceFailureLeavesAuthorizationStateUnchanged(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	configureGeneration(t, server, store)

	token, ok := server.signAccess("client-1", "/mcp")
	if !ok {
		t.Fatal("mint access token")
	}
	server.mu.Lock()
	generation := server.tokenGeneration
	server.codes["code"] = authCode{generation: generation}
	server.refresh["refresh"] = refreshGrant{generation: generation}
	server.mu.Unlock()

	store.mu.Lock()
	store.rotateErr = errors.New("durable store unavailable")
	store.mu.Unlock()
	if err := server.RevokeAll(context.Background()); err == nil {
		t.Fatal("RevokeAll succeeded despite durable rotation failure")
	}
	if !server.validAccess(token, "/mcp") {
		t.Fatal("failed durable revocation changed the in-memory generation")
	}
	server.mu.RLock()
	_, codeExists := server.codes["code"]
	_, refreshExists := server.refresh["refresh"]
	server.mu.RUnlock()
	if !codeExists || !refreshExists {
		t.Fatal("failed durable revocation partially cleared authorization state")
	}
}

func TestCodeRedemptionCannotCrossRevocationBarrier(t *testing.T) {
	server := New("https://engine.example", "pw", "shared-signing-secret")
	enteredEpoch := make(chan struct{})
	releaseEpoch := make(chan struct{})
	var once sync.Once
	server.SetEpochLookup(func(path string) (string, bool) {
		once.Do(func() {
			close(enteredEpoch)
			<-releaseEpoch
		})
		return rootEpoch(path)
	})

	verifier := strings.Repeat("v", 64)
	challenge := pkceChallenge(verifier)
	server.mu.Lock()
	generation := server.tokenGeneration
	server.codes["code-before-revoke"] = authCode{
		clientID:    "client-1",
		redirectURI: "https://client.example/callback",
		challenge:   challenge,
		scope:       "mcp",
		resource:    "/mcp",
		generation:  generation,
		expires:     time.Now().Add(time.Minute),
	}
	server.mu.Unlock()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-before-revoke"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://client.example/callback"},
		"code_verifier": {verifier},
	}
	rec := httptest.NewRecorder()
	tokenDone := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.handleToken(rec, req)
		close(tokenDone)
	}()
	awaitSignal(t, enteredEpoch, "code redemption to reach token signing")

	revokeAttempted := make(chan struct{})
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- server.revokeAll(context.Background(), func() { close(revokeAttempted) })
	}()
	awaitSignal(t, revokeAttempted, "revocation attempt")
	close(releaseEpoch)
	awaitSignal(t, tokenDone, "code redemption completion")
	if err := awaitError(t, revokeDone, "revocation completion"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("code redemption = %d, body %s", rec.Code, rec.Body)
	}
	accessToken, refreshToken := decodeTokenResponse(t, rec)
	if server.validAccess(accessToken, "/mcp") {
		t.Fatal("code redemption left a valid access token after revocation completed")
	}
	server.mu.RLock()
	_, refreshExists := server.refresh[refreshToken]
	server.mu.RUnlock()
	if refreshExists {
		t.Fatal("code redemption inserted a refresh grant after revocation completed")
	}
}

func TestRefreshRedemptionCannotCrossRevocationBarrier(t *testing.T) {
	server := New("https://engine.example", "pw", "shared-signing-secret")
	enteredEpoch := make(chan struct{})
	releaseEpoch := make(chan struct{})
	var once sync.Once
	server.SetEpochLookup(func(path string) (string, bool) {
		once.Do(func() {
			close(enteredEpoch)
			<-releaseEpoch
		})
		return rootEpoch(path)
	})

	server.mu.Lock()
	server.refresh["refresh-before-revoke"] = refreshGrant{
		clientID:   "client-1",
		resource:   "/mcp",
		generation: server.tokenGeneration,
	}
	server.mu.Unlock()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"refresh-before-revoke"},
		"client_id":     {"client-1"},
	}
	rec := httptest.NewRecorder()
	tokenDone := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.handleToken(rec, req)
		close(tokenDone)
	}()
	awaitSignal(t, enteredEpoch, "refresh redemption to reach token signing")

	revokeAttempted := make(chan struct{})
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- server.revokeAll(context.Background(), func() { close(revokeAttempted) })
	}()
	awaitSignal(t, revokeAttempted, "revocation attempt")
	close(releaseEpoch)
	awaitSignal(t, tokenDone, "refresh redemption completion")
	if err := awaitError(t, revokeDone, "revocation completion"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("refresh redemption = %d, body %s", rec.Code, rec.Body)
	}
	accessToken, _ := decodeTokenResponse(t, rec)
	if server.validAccess(accessToken, "/mcp") {
		t.Fatal("refresh redemption left a valid access token after revocation completed")
	}
}

func TestStalledTokenDeliveryCannotBlockRevocation(t *testing.T) {
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	verifier := strings.Repeat("v", 64)
	server.mu.Lock()
	server.codes["code-for-slow-client"] = authCode{
		clientID:    "client-1",
		redirectURI: "https://client.example/callback",
		challenge:   pkceChallenge(verifier),
		scope:       "mcp",
		resource:    "/mcp",
		generation:  server.tokenGeneration,
		expires:     time.Now().Add(time.Minute),
	}
	server.mu.Unlock()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-for-slow-client"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://client.example/callback"},
		"code_verifier": {verifier},
	}
	writer := newBlockingResponseWriter()
	deliveryDone := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.handleToken(writer, req)
		close(deliveryDone)
	}()
	awaitSignal(t, writer.entered, "token response write to stall")

	revokeDone := make(chan error, 1)
	go func() { revokeDone <- server.RevokeAll(context.Background()) }()
	select {
	case err := <-revokeDone:
		if err != nil {
			close(writer.release)
			awaitSignal(t, deliveryDone, "stalled token delivery cleanup")
			t.Fatalf("RevokeAll: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(writer.release)
		awaitSignal(t, deliveryDone, "stalled token delivery cleanup")
		t.Fatal("slow HTTP response delivery blocked RevokeAll")
	}

	server.mu.RLock()
	refreshCount := len(server.refresh)
	server.mu.RUnlock()
	if refreshCount != 0 {
		t.Fatalf("revocation left %d refresh grants while delivery was stalled", refreshCount)
	}

	close(writer.release)
	awaitSignal(t, deliveryDone, "stalled token delivery")
	rec := httptest.NewRecorder()
	rec.Code = writer.status
	_, _ = rec.Body.Write(writer.body.Bytes())
	accessToken, _ := decodeTokenResponse(t, rec)
	if server.validAccess(accessToken, "/mcp") {
		t.Fatal("token delivered after revocation remained valid")
	}
}

func TestHostedConsentCompletionCannotCrossRevocationBarrier(t *testing.T) {
	harness := newHostedConsentHarness(t)
	requestToken := harness.authorize(t, "https://engine.example/mcp")
	assertion := approvalAssertion(t, harness.privateKey, harness.claims(requestToken, "approval_jti_barrier"))

	enteredEpoch := make(chan struct{})
	releaseEpoch := make(chan struct{})
	var once sync.Once
	harness.server.SetEpochLookup(func(path string) (string, bool) {
		once.Do(func() {
			close(enteredEpoch)
			<-releaseEpoch
		})
		epoch, ok := harness.epochs[path]
		return epoch, ok
	})

	var completion *httptest.ResponseRecorder
	completionDone := make(chan struct{})
	go func() {
		completion = completeHostedConsent(harness.mux, requestToken, assertion, nil)
		close(completionDone)
	}()
	awaitSignal(t, enteredEpoch, "hosted consent revalidation")

	revokeAttempted := make(chan struct{})
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- harness.server.revokeAll(context.Background(), func() { close(revokeAttempted) })
	}()
	awaitSignal(t, revokeAttempted, "revocation attempt")
	close(releaseEpoch)
	awaitSignal(t, completionDone, "hosted consent completion")
	if err := awaitError(t, revokeDone, "revocation completion"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	harness.server.mu.RLock()
	codeCount := len(harness.server.codes)
	harness.server.mu.RUnlock()
	if codeCount != 0 {
		t.Fatalf("revocation left hosted authorization codes: %d", codeCount)
	}
	if completion.Code == http.StatusFound {
		redirect, err := url.Parse(completion.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse hosted completion redirect: %v", err)
		}
		if code := redirect.Query().Get("code"); code != "" {
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"client_id":     {harness.clientID},
				"redirect_uri":  {harness.redirect},
				"code_verifier": {harness.verifier},
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			harness.server.handleToken(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("pre-revocation hosted code redeemed after revoke: %d, body %s", rec.Code, rec.Body)
			}
		}
	} else if completion.Code != http.StatusBadRequest {
		t.Fatalf("hosted completion = %d, want 302 before revoke or 400 after it; body %s", completion.Code, completion.Body)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeTokenResponse(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if payload.AccessToken == "" {
		t.Fatal("token response omitted access_token")
	}
	return payload.AccessToken, payload.RefreshToken
}

func awaitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func awaitError(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}
