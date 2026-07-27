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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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
	accessTTL = 7 * 24 * time.Hour // long-lived: Claude rarely needs to refresh
	codeTTL   = 10 * time.Minute
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
	expires     time.Time
}

// refreshGrant is what a refresh token re-issues: refreshed access tokens stay
// bound to the resource the original authorization was for.
type refreshGrant struct {
	clientID string
	resource string
}

// Server is the single-tenant AS. issuer is this service's public base URL.
type Server struct {
	issuer   string
	password string // console password gating /authorize consent
	secret   []byte // HMAC key for access tokens

	// epochOf resolves a resource path (e.g. /mcp/team) to the CURRENT token
	// epoch of the connector serving it, or ok=false if no such endpoint
	// exists. The epoch is baked into every access-token HMAC, so deleting a
	// connector (and recreating its slug, which mints a fresh epoch)
	// invalidates all previously issued tokens for that path — the revocation
	// seam between the stateless AS and the gateway's connector store. nil
	// means "no lookup wired" (tests): every path resolves to epoch "".
	epochOf func(path string) (string, bool)

	mu      sync.Mutex
	clients map[string]client
	codes   map[string]authCode
	refresh map[string]refreshGrant // refresh_token -> grant (non-rotating)

	hosted           *hostedConsent
	pendingConsents  map[string]pendingConsent
	usedApprovalJTIs map[string]time.Time
	now              func() time.Time
}

func New(issuer, password, secret string) *Server {
	return &Server{
		issuer:           strings.TrimRight(issuer, "/"),
		password:         password,
		secret:           []byte(secret),
		clients:          map[string]client{},
		codes:            map[string]authCode{},
		refresh:          map[string]refreshGrant{},
		pendingConsents:  map[string]pendingConsent{},
		usedApprovalJTIs: map[string]time.Time{},
		now:              time.Now,
	}
}

// SetEpochLookup wires the resource-path → token-epoch resolver (see the
// epochOf field). Call before serving; not safe to swap concurrently.
func (s *Server) SetEpochLookup(fn func(path string) (string, bool)) { s.epochOf = fn }

// epochFor resolves the current epoch for a (normalized) resource path.
// Without a lookup wired, every path is valid with a stable empty epoch.
func (s *Server) epochFor(path string) (string, bool) {
	if s.epochOf == nil {
		return "", true
	}
	return s.epochOf(path)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil ||
		len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 16 {
		oauthErr(w, 400, "invalid_client_metadata", "redirect_uris required")
		return
	}
	id := "mcp_" + randToken(18)
	uris := map[string]bool{}
	canonicalURIs := map[string]bool{}
	for _, u := range req.RedirectURIs {
		canonical, ok := validClientRedirectURI(u)
		if !ok || canonicalURIs[canonical] {
			oauthErr(w, 400, "invalid_client_metadata", "redirect_uris must be unique absolute HTTPS URLs (loopback HTTP is allowed)")
			return
		}
		canonicalURIs[canonical] = true
		uris[u] = true
	}
	s.mu.Lock()
	s.clients[id] = client{redirectURIs: uris}
	s.mu.Unlock()
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
	// Detect equivalent duplicates without rewriting the exact redirect URI the
	// client registered (exact matching remains mandatory during OAuth).
	canonical := scheme + "://" + strings.ToLower(u.Host) + u.EscapedPath()
	if u.ForceQuery || u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical, true
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

	s.mu.Lock()
	cl, ok := s.clients[clientID]
	s.mu.Unlock()
	if _, validRedirect := validClientRedirectURI(redirectURI); !ok || !cl.redirectURIs[redirectURI] || !validRedirect {
		oauthErr(w, 400, "invalid_request", "unknown client_id or redirect_uri")
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !validPKCEChallenge(challenge) {
		s.redirectErr(w, r, redirectURI, state, "invalid_request", "response_type=code + S256 PKCE required")
		return
	}
	// RFC 8707 resource must map to a LIVE endpoint — no pre-authorizing a
	// connector path before that connector exists.
	resource, validResource := s.authorizedResource(q.Get("resource"))
	if !validResource {
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "resource must be a live endpoint on this engine")
		return
	}
	if _, ok := s.epochFor(resource); !ok {
		s.redirectErr(w, r, redirectURI, state, "invalid_target", "unknown resource "+resource)
		return
	}
	request := authorizationRequest{
		clientID:     clientID,
		redirectURI:  redirectURI,
		state:        state,
		challenge:    challenge,
		scope:        q.Get("scope"),
		resourceRaw:  q.Get("resource"),
		resourcePath: resource,
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
		"response_type": "code", "scope": q.Get("scope"), "resource": q.Get("resource"),
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

	s.completeAuthorization(w, r, request)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, request authorizationRequest) {
	code := randToken(24)
	s.mu.Lock()
	s.codes[code] = authCode{
		clientID:    request.clientID,
		redirectURI: request.redirectURI,
		challenge:   request.challenge,
		scope:       request.scope,
		resource:    request.resourcePath,
		expires:     s.now().Add(codeTTL),
	}
	s.mu.Unlock()

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
	r.ParseForm()
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.grantCode(w, r)
	case "refresh_token":
		s.grantRefresh(w, r)
	default:
		oauthErr(w, 400, "unsupported_grant_type", "")
	}
}

func (s *Server) grantCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code) // single-use
	s.mu.Unlock()
	if !ok || s.now().After(ac.expires) {
		oauthErr(w, 400, "invalid_grant", "code invalid or expired")
		return
	}
	if r.Form.Get("client_id") != ac.clientID || r.Form.Get("redirect_uri") != ac.redirectURI {
		oauthErr(w, 400, "invalid_grant", "client_id/redirect_uri mismatch")
		return
	}
	// PKCE S256: base64url(sha256(verifier)) == challenge
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		oauthErr(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}
	s.issueTokens(w, ac.clientID, ac.scope, ac.resource, true)
}

func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.Form.Get("refresh_token")
	s.mu.Lock()
	g, ok := s.refresh[rt]
	s.mu.Unlock()
	if !ok {
		oauthErr(w, 400, "invalid_grant", "unknown refresh token")
		return
	}
	// Non-rotating: reuse the same refresh token (robust against retries).
	// The refreshed access token keeps the original grant's resource binding.
	at, ok := s.signAccess(g.clientID, g.resource)
	if !ok {
		oauthErr(w, 400, "invalid_grant", "resource no longer exists")
		return
	}
	writeJSON(w, 200, tokenResp(at, rt, "mcp"))
}

func (s *Server) issueTokens(w http.ResponseWriter, clientID, scope, resource string, withRefresh bool) {
	at, ok := s.signAccess(clientID, resource)
	if !ok {
		oauthErr(w, 400, "invalid_grant", "resource no longer exists")
		return
	}
	rt := ""
	if withRefresh {
		rt = randToken(32)
		s.mu.Lock()
		s.refresh[rt] = refreshGrant{clientID: clientID, resource: resource}
		s.mu.Unlock()
	}
	writeJSON(w, 200, tokenResp(at, rt, scope))
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

// signAccess mints an access token for the resource path, baking the path's
// CURRENT epoch into the HMAC. ok=false when the path no longer maps to a
// live endpoint (e.g. the connector was deleted between grant and refresh).
func (s *Server) signAccess(clientID, resource string) (string, bool) {
	resource = resourcePath(resource)
	epoch, ok := s.epochFor(resource)
	if !ok {
		return "", false
	}
	exp := strconv.FormatInt(s.now().Add(accessTTL).Unix(), 10)
	return exp + "." + s.sign(exp+"|"+clientID+"|"+resource+"|"+epoch) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(clientID)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(resource)), true
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
	epoch, ok := s.epochFor(string(resBytes))
	if !ok {
		return false // bound endpoint no longer exists — fail closed
	}
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.sign(parts[0]+"|"+string(cidBytes)+"|"+string(resBytes)+"|"+epoch))) != 1 {
		return false
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || s.now().Unix() >= n {
		return false
	}
	return string(resBytes) == strings.TrimRight(path, "/")
}

// RequireAuth wraps the MCP handler: valid Bearer passes; otherwise a 401 whose
// WWW-Authenticate points Claude at the protected-resource metadata (RFC 9728).
func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || !s.validAccess(tok, r.URL.Path) {
			// Reflect the request path into the advertised PRM URL so the
			// metadata's resource matches the endpoint that returned the 401
			// (RFC 9728 §3.3) — required for virtual connectors at /mcp/{slug}.
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="narthex", resource_metadata=%q`, s.prmURL()+r.URL.Path))
			oauthErr(w, 401, "invalid_token", "missing or invalid access token")
			return
		}
		next.ServeHTTP(w, r)
	})
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
