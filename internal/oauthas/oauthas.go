// Package oauthas is a minimal, single-tenant OAuth 2.1 Authorization Server —
// exactly enough for claude.ai's MCP connector flow (the spec dance we reverse-
// engineered from MetaMCP): RFC 9728 protected-resource metadata, RFC 8414 AS
// metadata, RFC 7591 dynamic client registration, /authorize (PKCE, password
// consent or generic hosted consent delegation) and /token
// (authorization_code + refresh_token grants), plus a Bearer middleware that
// issues the 401 challenge pointing back at the PRM.
//
// Deliberately simple for the engine spike: in-memory state, stateless HMAC
// access tokens (bound to the RFC 8707 resource path they were authorized
// for, so a connector token cannot open the ungated /mcp surface),
// NON-rotating refresh tokens (rotating single-use tokens were
// the cause of the earlier reconnect bricking). Single instance, single user.
package oauthas

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	accessTTL             = 7 * 24 * time.Hour // long-lived: Claude rarely needs to refresh
	codeTTL               = 10 * time.Minute
	generationReadTimeout = 2 * time.Second

	maxRegistrationBody = 32 << 10
	maxClientIDLength   = 1024
)

type client struct {
	redirectURIs map[string]bool
}

type authCode struct {
	clientID    string
	redirectURI string
	challenge   string // PKCE S256 code_challenge
	scope       string
	resource    string // RFC 8707 resource the code was authorized for (endpoint path)
	generation  string // workspace-wide authorization generation at issuance
	expires     time.Time
}

// refreshGrant is what a refresh token re-issues: refreshed access tokens stay
// bound to the resource the original authorization was for.
type refreshGrant struct {
	clientID   string
	resource   string
	generation string
}

// TokenGenerationStore persists the workspace-wide OAuth generation. Engine
// storage implements this interface without importing oauthas, preserving the
// package boundary between the authorization server and the gateway.
type TokenGenerationStore interface {
	LoadOrCreateTokenGeneration(ctx context.Context, candidate string) (string, error)
	CurrentTokenGeneration(ctx context.Context) (string, error)
	RotateTokenGeneration(ctx context.Context, expected, replacement string) (string, error)
}

// Server is the single-tenant AS. issuer is this service's public base URL.
type Server struct {
	issuer   string
	password string // console password gating /authorize consent
	secret   []byte // HMAC key for access tokens

	// mu is the authorization-generation barrier. Generation reads, state
	// redemption, token signing, and grant insertion stay under this one lock,
	// so RevokeAll has a single linearization point.
	mu                 sync.RWMutex
	tokenGeneration    string
	generationStore    TokenGenerationStore
	generationSyncGate chan struct{}

	// epochOf resolves a resource path (e.g. /mcp/team) to the CURRENT token
	// epoch of the connector serving it, or ok=false if no such endpoint
	// exists. The epoch is baked into every access-token HMAC, so deleting a
	// connector (and recreating its slug, which mints a fresh epoch)
	// invalidates all previously issued tokens for that path — the revocation
	// seam between the stateless AS and the gateway's connector store. nil
	// means "no lookup wired" (tests): every path resolves to epoch "".
	epochOf func(path string) (string, bool)
	// clientResourceAuthorizer independently checks the current OAuth-client
	// binding for /mcp/clients/{handle}. The resource epoch revokes stale tokens
	// after a client grant changes; this callback also prevents an authorization
	// code or refresh token minted before that change from being upgraded into a
	// token for the new endpoint epoch.
	clientResourceAuthorizer func(clientID, resource string) bool

	clients map[string]client
	codes   map[string]authCode
	refresh map[string]refreshGrant // refresh_token -> grant (non-rotating)

	hosted *hostedConsent
	// hostedConsentAuthorizer is invoked only after Platform has signed an
	// approved hosted-consent decision. It receives the trusted member subject
	// and role as well as the dynamic OAuth client/resource, so the Engine can
	// distinguish a delegated personal client from a broad shared endpoint.
	// The callback lives at the Engine boundary so oauthas remains independent
	// of the Engine store package.
	hostedConsentAuthorizer func(context.Context, string, string, string, string) error
	// localConsentAuthorizer is the self-hosted counterpart used only for a
	// client-bound endpoint after the local console password has been verified.
	// Self-hosted Engines have one durable administrator identity, rather than a
	// Platform session, so the callback lets the Engine bind that identity to the
	// same registry invariant as a hosted approval.
	localConsentAuthorizer func(context.Context, string, string, string, string) error
	hostedRequestAEAD      cipher.AEAD
	usedApprovalJTIs       map[string]time.Time
	usedConsentRequests    map[string]time.Time
	hostedInFlightRequests map[string]struct{}
	now                    func() time.Time
}

func New(issuer, password, secret string) *Server {
	secretBytes := []byte(secret)
	return &Server{
		issuer:                 strings.TrimRight(issuer, "/"),
		password:               password,
		secret:                 secretBytes,
		tokenGeneration:        randToken(16),
		generationSyncGate:     make(chan struct{}, 1),
		clients:                map[string]client{},
		codes:                  map[string]authCode{},
		refresh:                map[string]refreshGrant{},
		hostedRequestAEAD:      newHostedRequestAEAD(secretBytes),
		usedApprovalJTIs:       map[string]time.Time{},
		usedConsentRequests:    map[string]time.Time{},
		hostedInFlightRequests: map[string]struct{}{},
		now:                    time.Now,
	}
}

// SetHostedSubjectAuthorizer retains a compact callback shape for callers that
// only need the signed subject. New Engine integrations should use
// SetHostedConsentAuthorizer so they can also enforce the signed Platform role.
func (s *Server) SetHostedSubjectAuthorizer(
	fn func(context.Context, string, string, string) error,
) {
	if fn == nil {
		s.hostedConsentAuthorizer = nil
		return
	}
	s.hostedConsentAuthorizer = func(ctx context.Context, subject, _ string, clientID, resource string) error {
		return fn(ctx, subject, clientID, resource)
	}
}

// SetHostedConsentAuthorizer installs the role-aware Engine authorization
// callback for hosted OAuth approval. It is called for every approved hosted
// resource, before an authorization code is minted. Configure it before
// serving requests.
func (s *Server) SetHostedConsentAuthorizer(
	fn func(context.Context, string, string, string, string) error,
) {
	s.hostedConsentAuthorizer = fn
}

// SetLocalConsentAuthorizer installs the self-hosted authorization callback
// for client-bound resources. It receives the durable local-admin subject and
// owner role only after password consent succeeds. It is deliberately not used
// for shared endpoints, whose existing local-password behavior remains intact.
func (s *Server) SetLocalConsentAuthorizer(
	fn func(context.Context, string, string, string, string) error,
) {
	s.localConsentAuthorizer = fn
}

// ConfigureTokenGeneration loads or creates the durable workspace OAuth
// generation. Production must call this before serving requests. New keeps an
// in-memory generation so isolated package tests and self-contained callers
// remain safe even before a durable store is configured.
func (s *Server) ConfigureTokenGeneration(ctx context.Context, store TokenGenerationStore) error {
	if ctx == nil {
		return errors.New("token generation context is required")
	}
	if store == nil {
		return errors.New("token generation store is required")
	}
	generation, err := store.LoadOrCreateTokenGeneration(ctx, randToken(16))
	if err != nil {
		return fmt.Errorf("load or create token generation: %w", err)
	}
	if generation == "" {
		return errors.New("load or create token generation: store returned an empty generation")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.generationStore = store
	s.tokenGeneration = generation
	// Configuration is expected before serving. Clearing transient issuance
	// state also makes a late configuration fail closed.
	clear(s.refresh)
	clear(s.codes)
	return nil
}

// syncTokenGeneration refreshes this process from durable state immediately
// before accepting locally authenticated authorization state. The local
// generation captured before the read prevents an older in-flight read from
// rolling memory backward after a concurrent local revocation advanced it.
func (s *Server) syncTokenGeneration(ctx context.Context) error {
	return s.syncTokenGenerationWithHook(ctx, nil)
}

// syncTokenGenerationWithHook exposes only a deterministic pre-barrier test
// seam; production always calls syncTokenGeneration.
func (s *Server) syncTokenGenerationWithHook(ctx context.Context, beforeBarrier func()) error {
	if ctx == nil {
		return errors.New("token generation context is required")
	}
	if beforeBarrier != nil {
		beforeBarrier()
	}
	// Serialize the durable read and local apply. Without this gate, two reads
	// that both snapshot local G could observe durable H then J, apply H first,
	// and incorrectly discard J merely because local no longer equals G.
	readCtx, cancel := context.WithTimeout(ctx, generationReadTimeout)
	defer cancel()
	select {
	case s.generationSyncGate <- struct{}{}:
		defer func() { <-s.generationSyncGate }()
	case <-readCtx.Done():
		return fmt.Errorf("wait for token generation synchronization: %w", readCtx.Err())
	}
	s.mu.RLock()
	store := s.generationStore
	observedLocal := s.tokenGeneration
	s.mu.RUnlock()
	if store == nil {
		return nil
	}

	durable, err := store.CurrentTokenGeneration(readCtx)
	if err != nil {
		return fmt.Errorf("read current token generation: %w", err)
	}
	if durable == "" {
		return errors.New("read current token generation: store returned an empty generation")
	}

	s.mu.Lock()
	if s.tokenGeneration != observedLocal {
		// Another local synchronization/revocation won while this durable read
		// was in flight. Never overwrite it with the older snapshot.
		s.mu.Unlock()
		return nil
	}
	if durable != observedLocal {
		s.tokenGeneration = durable
		clear(s.refresh)
		clear(s.codes)
	}
	s.mu.Unlock()
	return nil
}

// SetEpochLookup wires the resource-path → token-epoch resolver (see the
// epochOf field). Call before serving; not safe to swap concurrently.
func (s *Server) SetEpochLookup(fn func(path string) (string, bool)) { s.epochOf = fn }

// SetClientResourceAuthorizer installs the Engine-owned verifier for
// client-bound resource paths. It is intentionally called outside oauthas's
// generation lock, so implementations may perform a bounded durable lookup.
// It must return false for a missing, inactive, revoked, or differently-bound
// MCP client. Configure it before serving requests.
func (s *Server) SetClientResourceAuthorizer(fn func(clientID, resource string) bool) {
	s.clientResourceAuthorizer = fn
}

// epochFor resolves the current epoch for a (normalized) resource path.
// Without a lookup wired, every path is valid with a stable empty epoch.
func (s *Server) epochFor(path string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.epochForLocked(path)
}

// epochForLocked requires s.mu to be held for reading or writing.
func (s *Server) epochForLocked(path string) (string, bool) {
	resourceEpoch, ok := s.resourceEpoch(path)
	if !ok {
		return "", false
	}
	return s.tokenGeneration + "|" + resourceEpoch, true
}

func (s *Server) resourceEpoch(path string) (string, bool) {
	resourceEpoch := ""
	if s.epochOf == nil {
		resourceEpoch = ""
	} else {
		var ok bool
		resourceEpoch, ok = s.epochOf(path)
		if !ok {
			return "", false
		}
	}
	return resourceEpoch, true
}

// generationForResource validates a live resource and snapshots the current
// authorization generation under the same barrier.
func (s *Server) generationForResource(path string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.epochForLocked(path); !ok {
		return "", false
	}
	return s.tokenGeneration, true
}

// RevokeResource drops every refresh grant (and pending auth code) bound to
// the given resource path — called by the gateway when a connector is deleted
// so its refresh tokens can never mint new access tokens. Outstanding ACCESS
// tokens are stateless and are instead invalidated by the epoch check in
// validAccess (a deleted path no longer resolves; a recreated one has a fresh
// epoch).
func (s *Server) RevokeResource(path string) {
	path = strings.TrimRight(path, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	for rt, g := range s.refresh {
		if g.resource == path {
			delete(s.refresh, rt)
		}
	}
	for c, ac := range s.codes {
		if ac.resource == path {
			delete(s.codes, c)
		}
	}
}

// RevokeAll invalidates every outstanding access token, refresh grant,
// authorization code, and stateless hosted consent request for this Engine.
// Dynamic client registrations remain so legitimate workspace members can
// reconnect without re-registering after a membership change.
func (s *Server) RevokeAll(ctx context.Context) error {
	return s.revokeAll(ctx, nil)
}

// revokeAll's hook is a deterministic test seam that fires immediately before
// attempting the generation barrier. Production always passes nil.
func (s *Server) revokeAll(ctx context.Context, beforeBarrier func()) error {
	if ctx == nil {
		return errors.New("revocation context is required")
	}
	if beforeBarrier != nil {
		beforeBarrier()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	nextGeneration := randToken(16)
	if s.generationStore != nil {
		expected := s.tokenGeneration
		for {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("rotate token generation: %w", err)
			}
			nextGeneration = randToken(16)
			if nextGeneration == expected {
				continue
			}
			persisted, err := s.generationStore.RotateTokenGeneration(ctx, expected, nextGeneration)
			if err != nil {
				return fmt.Errorf("rotate token generation: %w", err)
			}
			if persisted == "" {
				return errors.New("rotate token generation: store returned an empty generation")
			}
			if persisted == nextGeneration {
				break
			}
			if persisted == expected {
				return errors.New("rotate token generation: store did not advance or report a newer generation")
			}
			// Another Engine already advanced the durable generation. Adopting
			// it would not fulfill this revoke request, so retry from that value
			// until this call wins its own fresh compare-and-swap.
			expected = persisted
		}
	}
	s.tokenGeneration = nextGeneration
	clear(s.refresh)
	clear(s.codes)
	return nil
}

// Routes registers the AS endpoints on a mux. The MCP endpoint is protected
// separately via RequireAuth.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handlePRM)
	// Path-suffixed variants (RFC 9728 path-appended discovery): clients probe
	// /.well-known/oauth-protected-resource/mcp and, for virtual connectors,
	// /.well-known/oauth-protected-resource/mcp/{slug}. The subtree pattern
	// answers all of them with the resource field reflecting the request path.
	mux.HandleFunc("/.well-known/oauth-protected-resource/", s.handlePRM)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleASMeta)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/authorize/complete", s.handleHostedConsentComplete)
	mux.HandleFunc("/token", s.handleToken)
}

func (s *Server) prmURL() string { return s.issuer + "/.well-known/oauth-protected-resource" }

// ---- RFC 9728: protected-resource metadata ----
func (s *Server) handlePRM(w http.ResponseWriter, r *http.Request) {
	// The resource reflects the requested path: bare well-known → /mcp; the
	// path-appended form (…/oauth-protected-resource/mcp/team) → /mcp/team.
	resource := s.issuer + "/mcp"
	if suffix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"), "/"); suffix != "" {
		resource = s.issuer + suffix
	}
	writeJSON(w, 200, map[string]any{
		"resource":              resource,
		"authorization_servers": []string{s.issuer},
	})
}

// ---- RFC 8414: authorization-server metadata ----
func (s *Server) handleASMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"registration_endpoint":                 s.issuer + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

// ---- RFC 7591: dynamic client registration ----
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegistrationBody)).Decode(&req); err != nil ||
		len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 16 {
		oauthErr(w, 400, "invalid_client_metadata", "redirect_uris required")
		return
	}
	canonicalURIs := map[string]bool{}
	for _, u := range req.RedirectURIs {
		canonical, ok := validClientRedirectURI(u)
		if !ok || canonicalURIs[canonical] {
			oauthErr(w, 400, "invalid_client_metadata", "redirect_uris must be unique absolute HTTPS URLs (loopback HTTP is allowed)")
			return
		}
		canonicalURIs[canonical] = true
	}
	id := s.statelessClientID(canonicalURIs)
	writeJSON(w, 201, map[string]any{
		"client_id":                  id,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

// validClientRedirectURI applies the redirect boundary used at registration,
// authorization, and hosted-consent completion. HTTPS is mandatory except for
// loopback native clients; browser-executable schemes, credentials, fragments,
// control characters, and oversized values are rejected.
func validClientRedirectURI(raw string) (string, bool) {
	if raw == "" || len(raw) > 2048 || strings.Contains(raw, "#") ||
		strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(u.Hostname())) {
		return "", false
	}
	decodedPath, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.IndexFunc(decodedPath, unicode.IsControl) >= 0 {
		return "", false
	}
	decodedQuery, err := url.QueryUnescape(u.RawQuery)
	if err != nil || strings.IndexFunc(decodedQuery, unicode.IsControl) >= 0 {
		return "", false
	}
	// Detect equivalent duplicates and derive the canonical value hashed into
	// stateless dynamic client IDs. Legacy in-memory clients retain exact URI
	// matching; stateless clients accept only canonical-equivalent URIs.
	canonical := scheme + "://" + strings.ToLower(u.Host) + u.EscapedPath()
	if u.ForceQuery || u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical, true
}

// statelessClientID encodes the registered redirect set into a signed,
// self-authenticating client_id. Dynamic registration therefore has no
// server-side growth surface and survives Engine restarts.
func (s *Server) statelessClientID(canonicalURIs map[string]bool) string {
	payload := make([]byte, 0, 18+sha256.Size*len(canonicalURIs))
	payload = append(payload, 1) // format version
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	payload = append(payload, nonce...)
	payload = append(payload, byte(len(canonicalURIs)))
	for canonical := range canonicalURIs {
		hash := sha256.Sum256([]byte(canonical))
		payload = append(payload, hash[:]...)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signature := s.sign("oauth-client-registration|v1|" + encoded)
	return "mcp_v1." + encoded + "." + signature
}

func (s *Server) statelessClientAllowsRedirect(clientID, redirectURI string) bool {
	if len(clientID) == 0 || len(clientID) > maxClientIDLength {
		return false
	}
	parts := strings.Split(clientID, ".")
	if len(parts) != 3 || parts[0] != "mcp_v1" {
		return false
	}
	expected := s.sign("oauth-client-registration|v1|" + parts[1])
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) < 18 || payload[0] != 1 {
		return false
	}
	count := int(payload[17])
	if count < 1 || count > 16 || len(payload) != 18+sha256.Size*count {
		return false
	}
	canonical, ok := validClientRedirectURI(redirectURI)
	if !ok {
		return false
	}
	candidate := sha256.Sum256([]byte(canonical))
	for offset := 18; offset < len(payload); offset += sha256.Size {
		if subtle.ConstantTimeCompare(payload[offset:offset+sha256.Size], candidate[:]) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) clientAllowsRedirect(clientID, redirectURI string) bool {
	if s.statelessClientAllowsRedirect(clientID, redirectURI) {
		return true
	}
	// In-memory entries remain as a compatibility/test seam for clients
	// registered by pre-stateless code during the lifetime of this process.
	s.mu.RLock()
	legacy, ok := s.clients[clientID]
	s.mu.RUnlock()
	return ok && legacy.redirectURIs[redirectURI]
}

// ---- /authorize: validate + password-gated consent + issue code ----
var consentTmpl = template.Must(template.New("c").Parse(`<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><title>Synaxis Engine — Authorize</title><style>body{font-family:system-ui;max-width:420px;margin:14vh auto;padding:0 20px;color:#222}h1{font-weight:600;font-size:20px}.b{background:#fff;border:1px solid #e8e5df;padding:24px;border-radius:6px}input{width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;margin:8px 0}button{width:100%;padding:11px;background:#1a56db;color:#fff;border:none;border-radius:4px;font-size:15px}.e{color:#b91c1c;font-size:13px}</style></head><body><div class=b><h1>Authorize Claude → Synaxis Engine</h1><p>Connecting <b>{{.Client}}</b> to <b>{{.Resource}}</b>. Enter your console password to approve.</p>{{if .Err}}<p class=e>{{.Err}}</p>{{end}}<form method=post><input type=password name=password placeholder=Password autofocus>{{range $k,$v := .Fields}}<input type=hidden name="{{$k}}" value="{{$v}}">{{end}}<button>Approve</button></form></div></body></html>`))

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Hosted consent has a separate signed completion endpoint. Never let a
	// password POST fall through while delegation is configured.
	if s.hosted != nil && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid form")
			return
		}
		q = r.Form
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")

	if _, validRedirect := validClientRedirectURI(redirectURI); !validRedirect ||
		!s.clientAllowsRedirect(clientID, redirectURI) {
		oauthErr(w, 400, "invalid_request", "unknown client_id or redirect_uri")
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !validPKCEChallenge(challenge) {
		s.redirectErr(w, r, redirectURI, state, "invalid_request", "response_type=code + S256 PKCE required")
		return
	}
	// RFC 8707 resource must map to a LIVE endpoint — no pre-authorizing a
	// connector path before that connector exists.
	resourceRaw, _, resourceValueValid := oneOAuthFormValue(q, "resource")
	resource, validResource := s.authorizedResource(resourceRaw)
	if !resourceValueValid || !validResource {
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "resource must be a live endpoint on this engine")
		return
	}
	if _, ok := s.resourceEpoch(resource); !ok {
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "unknown resource "+resource)
		return
	}
	if clientBoundResource(resource) && s.hosted == nil && s.localConsentAuthorizer == nil {
		// A self-hosted Engine can support client-bound delivery only when the
		// application has wired its durable local-admin identity into the same
		// registry authorization callback. Failing closed avoids accidentally
		// turning a personal connection into an aggregate shared credential.
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "client-bound resources require a configured local administrator")
		return
	}
	generation, ok := s.generationForResource(resource)
	if !ok {
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "unknown resource "+resource)
		return
	}
	request := authorizationRequest{
		clientID:     clientID,
		redirectURI:  redirectURI,
		state:        state,
		challenge:    challenge,
		scope:        q.Get("scope"),
		resourceRaw:  resourceRaw,
		resourcePath: resource,
		generation:   generation,
	}
	if !request.withinLimits() {
		s.redirectErr(w, r, redirectURI, state, "invalid_request", "authorization request is too large")
		return
	}

	if s.hosted != nil {
		s.beginHostedConsent(w, r, request)
		return
	}

	// Preserve the OAuth params across the consent POST.
	fields := map[string]string{
		"client_id": clientID, "redirect_uri": redirectURI, "state": state,
		"code_challenge": challenge, "code_challenge_method": "S256",
		"response_type": "code", "scope": q.Get("scope"), "resource": resourceRaw,
	}

	if r.Method != http.MethodPost {
		consentTmpl.Execute(w, map[string]any{"Client": clientID, "Resource": resource, "Fields": fields, "Err": ""})
		return
	}

	// POST: validate password.
	if subtle.ConstantTimeCompare([]byte(q.Get("password")), []byte(s.password)) != 1 {
		w.WriteHeader(401)
		consentTmpl.Execute(w, map[string]any{"Client": clientID, "Resource": resource, "Fields": fields, "Err": "Incorrect password."})
		return
	}

	if err := s.syncTokenGeneration(r.Context()); err != nil {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authorization state unavailable")
		return
	}
	if clientBoundResource(request.resourcePath) {
		if err := s.localConsentAuthorizer(
			r.Context(),
			"local-admin",
			"owner",
			request.clientID,
			request.resourcePath,
		); err != nil {
			s.redirectErr(w, r, request.redirectURI, request.state, "access_denied", "the local administrator is not permitted to authorize this client")
			return
		}
	}
	s.completeAuthorization(w, r, request)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, request authorizationRequest) {
	s.mu.Lock()
	code, ok := s.createAuthorizationCodeLocked(request)
	if !ok {
		s.mu.Unlock()
		s.redirectErr(w, r, request.redirectURI, request.state, "invalid_request", "authorization request was revoked")
		return
	}
	s.mu.Unlock()
	s.redirectAuthorizationCode(w, r, request, code)
}

// createAuthorizationCodeLocked requires s.mu for writing and refuses to
// create a code from authorization state captured before the latest revoke.
func (s *Server) createAuthorizationCodeLocked(request authorizationRequest) (string, bool) {
	if request.generation == "" || request.generation != s.tokenGeneration {
		return "", false
	}
	code := randToken(24)
	s.codes[code] = authCode{
		clientID:    request.clientID,
		redirectURI: request.redirectURI,
		challenge:   request.challenge,
		scope:       request.scope,
		resource:    request.resourcePath,
		generation:  s.tokenGeneration,
		expires:     s.now().Add(codeTTL),
	}
	return code, true
}

func (s *Server) redirectAuthorizationCode(w http.ResponseWriter, r *http.Request, request authorizationRequest, code string) {
	u, _ := url.Parse(request.redirectURI)
	q := u.Query()
	q.Set("code", code)
	if request.state != "" {
		q.Set("state", request.state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---- /token: authorization_code + refresh_token grants ----
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	// RFC 6749 §5.1 requires token responses not to be cached. This applies to
	// OAuth errors as well: they may describe a bearer-grant state that a proxy
	// must never store.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	grantType := r.Form.Get("grant_type")
	s.mu.RLock()
	locallyKnown := false
	switch grantType {
	case "authorization_code":
		_, locallyKnown = s.codes[r.Form.Get("code")]
	case "refresh_token":
		_, locallyKnown = s.refresh[r.Form.Get("refresh_token")]
	default:
		s.mu.RUnlock()
		oauthErr(w, 400, "unsupported_grant_type", "")
		return
	}
	s.mu.RUnlock()
	if !locallyKnown {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "grant is unknown")
		return
	}
	if err := s.syncTokenGeneration(r.Context()); err != nil {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authorization state unavailable")
		return
	}
	switch grantType {
	case "authorization_code":
		s.grantCode(w, r)
	case "refresh_token":
		s.grantRefresh(w, r)
	}
}

func (s *Server) grantCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code) // single-use
	if !ok || ac.generation == "" || ac.generation != s.tokenGeneration || s.now().After(ac.expires) {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "code invalid or expired")
		return
	}
	if !tokenClientMatches(r.Form, ac.clientID) || r.Form.Get("redirect_uri") != ac.redirectURI {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "client_id/redirect_uri mismatch")
		return
	}
	if !s.tokenResourceMatches(r.Form, ac.resource) {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource is missing, malformed, or does not match the authorization code")
		return
	}
	// PKCE S256: base64url(sha256(verifier)) == challenge
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}
	grantEpoch, resourceLive := s.epochForLocked(ac.resource)
	if !resourceLive {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource no longer exists")
		return
	}
	// The code is deliberately consumed before the durable client grant lookup:
	// a revoked/rebound client must retry an authorization rather than retaining
	// a redeemable bearer capability. The lookup is outside the OAuth generation
	// lock so a durable store stall cannot block global revocation.
	s.mu.Unlock()
	if !s.clientResourceAllowed(ac.clientID, ac.resource) {
		oauthErr(w, 400, "invalid_grant", "client is no longer authorized for this resource")
		return
	}
	s.mu.Lock()
	if ac.generation == "" || ac.generation != s.tokenGeneration {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "code invalid or expired")
		return
	}
	if currentEpoch, ok := s.epochForLocked(ac.resource); !ok || currentEpoch != grantEpoch {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "client authorization changed")
		return
	}
	response, ok := s.issueTokensLocked(ac.clientID, ac.scope, ac.resource, ac.generation, true)
	if !ok {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource no longer exists or authorization was revoked")
		return
	}
	s.mu.Unlock()
	// Delivery stays outside the barrier so a slow client cannot block
	// revocation. If RevokeAll wins before delivery, this response's generation
	// is already invalid and its refresh grant has already been removed.
	writeJSON(w, 200, response)
}

func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.Form.Get("refresh_token")
	s.mu.Lock()
	g, ok := s.refresh[rt]
	if !ok || g.generation == "" || g.generation != s.tokenGeneration {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "unknown refresh token")
		return
	}
	if !tokenClientMatches(r.Form, g.clientID) {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "client_id is missing, duplicated, or does not match the refresh grant")
		return
	}
	if !s.tokenResourceMatches(r.Form, g.resource) {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource is missing, malformed, or does not match the refresh grant")
		return
	}
	grantEpoch, resourceLive := s.epochForLocked(g.resource)
	if !resourceLive {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource no longer exists")
		return
	}
	// Do not let a refresh token from a formerly-bound client gain the current
	// endpoint epoch after an operator revokes or reassigns that client.
	s.mu.Unlock()
	if !s.clientResourceAllowed(g.clientID, g.resource) {
		oauthErr(w, 400, "invalid_grant", "client is no longer authorized for this resource")
		return
	}
	s.mu.Lock()
	g, ok = s.refresh[rt]
	if !ok || g.generation == "" || g.generation != s.tokenGeneration {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "unknown refresh token")
		return
	}
	if currentEpoch, ok := s.epochForLocked(g.resource); !ok || currentEpoch != grantEpoch {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "client authorization changed")
		return
	}
	// Non-rotating: reuse the same refresh token (robust against retries).
	// The refreshed access token keeps the original grant's resource binding.
	at, ok := s.signAccessLocked(g.clientID, g.resource)
	if !ok {
		s.mu.Unlock()
		oauthErr(w, 400, "invalid_grant", "resource no longer exists")
		return
	}
	s.mu.Unlock()
	writeJSON(w, 200, tokenResp(at, rt, "mcp"))
}

// issueTokensLocked requires s.mu for writing. The expected generation check,
// access-token signing, and refresh-grant insertion form one atomic operation
// with respect to RevokeAll.
func (s *Server) issueTokensLocked(clientID, scope, resource, expectedGeneration string, withRefresh bool) (map[string]any, bool) {
	if expectedGeneration == "" || expectedGeneration != s.tokenGeneration {
		return nil, false
	}
	at, ok := s.signAccessLocked(clientID, resource)
	if !ok {
		return nil, false
	}
	rt := ""
	if withRefresh {
		rt = randToken(32)
		s.refresh[rt] = refreshGrant{clientID: clientID, resource: resource, generation: s.tokenGeneration}
	}
	return tokenResp(at, rt, scope), true
}

func tokenResp(at, rt, scope string) map[string]any {
	m := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds())}
	if rt != "" {
		m["refresh_token"] = rt
	}
	if scope != "" {
		m["scope"] = scope
	}
	return m
}

// ---- access tokens: stateless HMAC "<exp>.<sig>.<client>.<resource>" ----
// The token is BOUND to the resource path it was authorized for (RFC 8707):
// a token minted for /mcp/work must not open /mcp (which has no approval
// gating or connector allowlist) — RequireAuth enforces the match.

// resourcePath normalizes an RFC 8707 resource indicator to the endpoint path
// the token is bound to. Absent or unparseable resources bind to /mcp — the
// default connector surface, never a broader one.
func resourcePath(res string) string {
	if res == "" {
		return "/mcp"
	}
	u, err := url.Parse(res)
	if err != nil {
		return "/mcp"
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		return "/mcp"
	}
	return p
}

// oneOAuthFormValue makes parameter cardinality explicit for values that bind
// an authorization decision. url.Values.Get silently chooses the first value;
// accepting a duplicate resource would let different OAuth components observe
// different audiences for the same request.
func oneOAuthFormValue(values url.Values, key string) (value string, present, valid bool) {
	items, present := values[key]
	if !present {
		return "", false, true
	}
	if len(items) != 1 {
		return "", true, false
	}
	return items[0], true, true
}

// tokenClientMatches requires exactly one public-client identity at token
// exchange. Dynamic registrations are not secrets, but keeping this binding
// explicit prevents a refresh token issued to one client from being presented
// under another client ID (and avoids duplicate-form ambiguity).
func tokenClientMatches(values url.Values, expected string) bool {
	clientID, present, valid := oneOAuthFormValue(values, "client_id")
	return valid && present && clientID == expected
}

// tokenResourceMatches applies RFC 8707's audience continuity at token time.
// Existing shared/root clients retain the historic omission-compatible path,
// but a client-bound endpoint requires an exact resource in every code and
// refresh request. Any supplied resource is canonicalized to this Engine
// origin and must equal the resource stored in the grant.
func (s *Server) tokenResourceMatches(values url.Values, expected string) bool {
	raw, present, valid := oneOAuthFormValue(values, "resource")
	if !valid {
		return false
	}
	if !present {
		return !clientBoundResource(expected)
	}
	path, ok := s.authorizedResource(raw)
	return ok && path == expected
}

// signAccess mints an access token for the resource path, baking the path's
// CURRENT epoch into the HMAC. ok=false when the path no longer maps to a
// live endpoint (e.g. the connector was deleted between grant and refresh).
func (s *Server) signAccess(clientID, resource string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signAccessLocked(clientID, resource)
}

// signAccessLocked requires s.mu for reading or writing.
func (s *Server) signAccessLocked(clientID, resource string) (string, bool) {
	resource = resourcePath(resource)
	epoch, ok := s.epochForLocked(resource)
	if !ok {
		return "", false
	}
	exp := strconv.FormatInt(s.now().Add(accessTTL).Unix(), 10)
	return exp + "." + s.sign(exp+"|"+clientID+"|"+resource+"|"+epoch) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(clientID)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(resource)), true
}

// clientBoundResource returns true only for the dedicated, single-segment
// client delivery namespace.  Shared /mcp and curated connector resources keep
// their existing workspace-level authorization semantics.
func clientBoundResource(resource string) bool {
	handle, ok := strings.CutPrefix(strings.TrimRight(resource, "/"), "/mcp/clients/")
	return ok && handle != "" && !strings.Contains(handle, "/")
}

// clientResourceAllowed is deliberately evaluated outside the OAuth server's
// generation mutex. Its implementation may do a bounded durable lookup, while
// the HMAC/epoch checks remain protected by validAccess's snapshot.
func (s *Server) clientResourceAllowed(clientID, resource string) bool {
	if !clientBoundResource(resource) {
		return true
	}
	fn := s.clientResourceAuthorizer
	return fn != nil && fn(clientID, resource)
}

func (s *Server) sign(msg string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validAccess verifies signature + expiry AND that the token's bound resource
// matches the path being requested (audience check). The signature covers the
// resource's epoch at MINT time; it is re-verified against the CURRENT epoch,
// so a token dies the moment its connector is deleted and stays dead even if
// the slug is later recreated (recreation mints a fresh epoch).
func (s *Server) validAccess(tok, path string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return false
	}
	cidBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	resBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	s.mu.RLock()
	epoch, ok := s.epochForLocked(string(resBytes))
	signatureValid := ok && subtle.ConstantTimeCompare(
		[]byte(parts[1]),
		[]byte(s.sign(parts[0]+"|"+string(cidBytes)+"|"+string(resBytes)+"|"+epoch)),
	) == 1
	s.mu.RUnlock()
	if !signatureValid {
		return false // bound endpoint no longer exists or token was forged
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || s.now().Unix() >= n {
		return false
	}
	resource := string(resBytes)
	return resource == strings.TrimRight(path, "/") &&
		s.clientResourceAllowed(string(cidBytes), resource)
}

// RequireAuth wraps the MCP handler: valid Bearer passes; otherwise a 401 whose
// WWW-Authenticate points Claude at the protected-resource metadata (RFC 9728).
func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, tok, hasCredentials := strings.Cut(r.Header.Get("Authorization"), " ")
		if !hasCredentials || !strings.EqualFold(scheme, "Bearer") ||
			strings.ContainsAny(tok, " \t\r\n") || !s.validAccess(tok, r.URL.Path) {
			s.rejectAccess(w, r)
			return
		}
		if err := s.syncTokenGeneration(r.Context()); err != nil {
			oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authorization state unavailable")
			return
		}
		if !s.validAccess(tok, r.URL.Path) {
			s.rejectAccess(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rejectAccess(w http.ResponseWriter, r *http.Request) {
	// Reflect the request path into the advertised PRM URL so the metadata's
	// resource matches the endpoint that returned the 401 (RFC 9728 §3.3).
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="narthex", resource_metadata=%q`, s.prmURL()+r.URL.Path))
	oauthErr(w, 401, "invalid_token", "missing or invalid access token")
}

// ---- helpers ----
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		oauthErr(w, 400, code, desc)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
