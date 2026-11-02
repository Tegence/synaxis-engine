package engine

// Caller grants on workload calls (docs/CONTROL_V1.md, "Caller grants on
// workload calls"). A caller-delegated account acts only for the person who
// started a job. Each workload tools/call carries that person's short-lived
// grant in X-Synaxis-Caller-Grant; the Engine matches it to the account by
// resource and client binding, exchanges it (RFC 7523 jwt-bearer) at the
// account's token endpoint with the account's own client credentials, and
// dials the upstream once with the access token it gets back.
//
// The Engine never verifies the grant's signature (the upstream's
// authorization server does) and never reads its subject: it checks only the
// routing claims resource, client_id, act.client and exp. A grant or an
// exchanged access token is never persisted, logged, recorded or sent
// anywhere but the matching account's token endpoint.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"narthex/backend/internal/upstreamoauth"
)

const (
	// callerGrantHeader carries one grant per header line:
	//   X-Synaxis-Caller-Grant: resource="<url>", grant="<compact JWS>"
	callerGrantHeader = "X-Synaxis-Caller-Grant"
	// maxCallerGrantHeaders bounds the grants on one request. A request with
	// more carries none: the Engine does not guess which ones were meant.
	maxCallerGrantHeaders = 4
	// maxCallerGrantHeaderBytes bounds one header line; a longer line is
	// ignored.
	maxCallerGrantHeaderBytes = 4 << 10

	// callerGrantCallIDMetaKey is the one _meta key forwarded to a
	// caller-delegated upstream, so the upstream can key a write's
	// idempotency on the caller's own tool-use ID.
	callerGrantCallIDMetaKey = "io.synaxis/call-id"
	maxCallerGrantCallIDLen  = 64

	callerGrantJWTBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// maxCallerGrantExchangeResponseBytes bounds a token endpoint answer.
	maxCallerGrantExchangeResponseBytes = 16 << 10
	// callerGrantMinRemaining refuses a grant about to expire: the exchange
	// and the call must both fit before it does.
	callerGrantMinRemaining = 5 * time.Second
	// callerGrantTokenReuseMargin stops reusing a cached access token this
	// long before it expires.
	callerGrantTokenReuseMargin = 10 * time.Second
	// maxCallerGrantTokenLifetime is the longest expires_in (seconds) an
	// exchange may answer; anything outside 1..300 is refused.
	maxCallerGrantTokenLifetime = 300
	maxCallerGrantAccessToken   = 4096
	// maxCallerGrantCacheEntries bounds the per-Gateway token cache. Entries
	// live at most maxCallerGrantTokenLifetime seconds.
	maxCallerGrantCacheEntries = 4096
)

// callerGrantExchangeTimeout bounds one token exchange end to end. A var only
// so tests can shorten it; production never changes it.
var callerGrantExchangeTimeout = 5 * time.Second

// callerGrantNow is the clock for grant expiry and token reuse. A var only so
// tests can move it.
var callerGrantNow = time.Now

// The fixed tool errors an agent sees instead of an upstream result. None of
// them quotes the grant, the token endpoint's answer or any claim.
const (
	callerGrantInteractiveRefusal       = "This connection acts for the person who started a job. Use it from a job."
	callerGrantMissingRefusal           = "This connection acts for the person who started the job, and no permission for it came with this call."
	callerGrantMismatchRefusal          = "This job's permission doesn't match this agent."
	callerGrantInvalidClientRefusal     = "An admin must reconnect this connection."
	callerGrantAgentsDisabledRefusal    = "Agents are turned off for this organization."
	callerGrantProcessingBlockedRefusal = "This organization hasn't approved this model for its data."
	callerGrantRunEndedRefusal          = "This job has ended."
	callerGrantRefusedRefusal           = "The connection refused this job's permission."
	// callerGrantConnectionChanged is the gateway's existing answer for a
	// cached handler whose account changed; the runner retries once on it.
	callerGrantConnectionChanged = "this connection changed; refresh the MCP tool list"
)

// callerGrantConsentRequiredRefusal and callerGrantConfigChangedRefusal name
// the service the person allows agents in. The Engine is tenant-blind, so the
// name is the connection's own display label.
func callerGrantConsentRequiredRefusal(label string) string {
	return "Allow this agent to work in " + label + " first."
}

func callerGrantConfigChangedRefusal(label string) string {
	return "This agent changed. Its owner must allow it again in " + label + "."
}

// callerGrantRefusal is an error that must reach the agent as one fixed tool
// error. Its text is always one of the sentences above.
type callerGrantRefusal struct{ message string }

func (e *callerGrantRefusal) Error() string { return e.message }

// callerGrant is one lifted X-Synaxis-Caller-Grant value. It formats as a
// placeholder so a stray %v can never print it.
type callerGrant struct {
	resource string
	compact  string
}

func (callerGrant) String() string   { return "[caller grant]" }
func (callerGrant) GoString() string { return "[caller grant]" }

type callerGrantsKey struct{}

// liftCallerGrants is the Streamable HTTP context function of a workload
// client endpoint (server.WithHTTPContextFunc). It keeps only well-formed
// header lines within the limits; dispatch still reads them only for a
// workload caller (clientAccountHandler).
func liftCallerGrants(ctx context.Context, r *http.Request) context.Context {
	if r == nil {
		return ctx
	}
	values := r.Header.Values(callerGrantHeader)
	if len(values) == 0 || len(values) > maxCallerGrantHeaders {
		return ctx
	}
	grants := make([]callerGrant, 0, len(values))
	for _, value := range values {
		if grant, ok := parseCallerGrantHeader(value); ok {
			grants = append(grants, grant)
		}
	}
	if len(grants) == 0 {
		return ctx
	}
	return withCallerGrants(ctx, grants)
}

// withCallerGrants replaces the request's lifted grants; nil drops them.
func withCallerGrants(ctx context.Context, grants []callerGrant) context.Context {
	return context.WithValue(ctx, callerGrantsKey{}, grants)
}

func callerGrantsFrom(ctx context.Context) []callerGrant {
	grants, _ := ctx.Value(callerGrantsKey{}).([]callerGrant)
	return grants
}

// parseCallerGrantHeader reads exactly two quoted parameters, resource and
// grant, each once and in either order. A grant must have the compact JWS
// shape (three base64url segments); the Engine never verifies it.
func parseCallerGrantHeader(value string) (callerGrant, bool) {
	if len(value) > maxCallerGrantHeaderBytes {
		return callerGrant{}, false
	}
	params := map[string]string{}
	rest := strings.TrimSpace(value)
	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return callerGrant{}, false
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		if !callerGrantParamName(key) {
			return callerGrant{}, false
		}
		rest = strings.TrimLeft(rest[eq+1:], " \t")
		if !strings.HasPrefix(rest, `"`) {
			return callerGrant{}, false
		}
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return callerGrant{}, false
		}
		quoted := rest[1 : end+1]
		for i := 0; i < len(quoted); i++ {
			if quoted[i] < 0x21 || quoted[i] > 0x7e || quoted[i] == '\\' {
				return callerGrant{}, false
			}
		}
		if _, dup := params[key]; dup {
			return callerGrant{}, false
		}
		params[key] = quoted
		rest = strings.TrimLeft(rest[end+2:], " \t")
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return callerGrant{}, false
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		if rest == "" {
			return callerGrant{}, false
		}
	}
	resource, grant := params["resource"], params["grant"]
	if len(params) != 2 || resource == "" || !compactJWSShape(grant) {
		return callerGrant{}, false
	}
	if _, ok := normalizeCallerGrantResource(resource); !ok {
		return callerGrant{}, false
	}
	return callerGrant{resource: resource, compact: grant}, true
}

func callerGrantParamName(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < 'a' || c > 'z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// compactJWSShape reports three non-empty base64url segments.
func compactJWSShape(value string) bool {
	segments := strings.Split(value, ".")
	if len(segments) != 3 {
		return false
	}
	for _, segment := range segments {
		if segment == "" {
			return false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// normalizeCallerGrantResource compares resource identifiers with the scheme
// and host lower-cased and no trailing slash.
func normalizeCallerGrantResource(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host) + strings.TrimRight(parsed.EscapedPath(), "/"), true
}

// selectCallerGrant picks the first lifted grant whose resource is the
// account's resource.
func selectCallerGrant(grants []callerGrant, accountResource string) (callerGrant, bool) {
	want, ok := normalizeCallerGrantResource(accountResource)
	if !ok {
		return callerGrant{}, false
	}
	for _, grant := range grants {
		if got, ok := normalizeCallerGrantResource(grant.resource); ok && got == want {
			return grant, true
		}
	}
	return callerGrant{}, false
}

// callerGrantClaims are the only claims the Engine reads. The subject is
// deliberately not decoded.
type callerGrantClaims struct {
	resource  string
	clientID  string
	actClient string
	exp       time.Time
}

// decodeCallerGrantClaims decodes the payload segment without verifying the
// signature.
func decodeCallerGrantClaims(compact string) (callerGrantClaims, bool) {
	if !compactJWSShape(compact) {
		return callerGrantClaims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[1])
	if err != nil {
		return callerGrantClaims{}, false
	}
	var payload struct {
		Resource string          `json:"resource"`
		ClientID string          `json:"client_id"`
		Exp      json.RawMessage `json:"exp"`
		Act      struct {
			Client string `json:"client"`
		} `json:"act"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return callerGrantClaims{}, false
	}
	// exp is a NumericDate: a JSON number of seconds, possibly fractional.
	exp, ok := jsonNumberLiteral(payload.Exp)
	if !ok {
		return callerGrantClaims{}, false
	}
	seconds, err := exp.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > math.MaxInt32*4 {
		return callerGrantClaims{}, false
	}
	return callerGrantClaims{
		resource:  payload.Resource,
		clientID:  payload.ClientID,
		actClient: payload.Act.Client,
		exp:       time.Unix(int64(seconds), 0),
	}, true
}

// routes reports whether the grant may be exchanged for account a on behalf
// of the calling workload client: resource is the account's, client_id is the
// account's OAuth client, act.client is the calling client, and more than
// callerGrantMinRemaining is left before exp.
func (c callerGrantClaims) routes(a Account, callingClientID string, now time.Time) bool {
	want, ok := normalizeCallerGrantResource(a.Resource)
	got, gotOK := normalizeCallerGrantResource(c.resource)
	return ok && gotOK && got == want &&
		c.clientID != "" && c.clientID == a.ClientID &&
		c.actClient != "" && c.actClient == callingClientID &&
		c.exp.After(now.Add(callerGrantMinRemaining))
}

// callerGrantCache holds exchanged access tokens under
// SHA-256(compact grant) ‖ calling client ID. The zero value is ready.
type callerGrantCache struct {
	mu      sync.Mutex
	entries map[string]callerGrantCacheEntry
}

type callerGrantCacheEntry struct {
	// The account the token was exchanged for, so a recreated or
	// reconfigured account never reuses it.
	account       string
	incarnationID string
	oauthClientID string
	tokenEndpoint string
	resource      string

	claims    callerGrantClaims
	token     string
	reuseTill time.Time // expiry minus callerGrantTokenReuseMargin
}

func callerGrantCacheKey(compact, callingClientID string) string {
	sum := sha256.Sum256([]byte(compact))
	return string(sum[:]) + callingClientID
}

func (e callerGrantCacheEntry) boundTo(a Account) bool {
	return e.account == a.Name && e.incarnationID == a.IncarnationID && e.oauthClientID == a.ClientID &&
		e.tokenEndpoint == a.TokenEndpoint && e.resource == a.Resource
}

func (c *callerGrantCache) lookup(key string) (callerGrantCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	return entry, ok
}

func (c *callerGrantCache) put(key string, entry callerGrantCacheEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]callerGrantCacheEntry{}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCallerGrantCacheEntries {
		for k, e := range c.entries {
			if !now.Before(e.reuseTill) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < maxCallerGrantCacheEntries {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = entry
}

func (c *callerGrantCache) drop(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// dropToken drops key's entry only while it still holds token, so a token a
// concurrent call has just exchanged for the same grant is kept.
func (c *callerGrantCache) dropToken(key, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok && entry.token == token {
		delete(c.entries, key)
	}
}

func (c *callerGrantCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// callerDelegatedUpstream resolves the one-call Upstream for a tools/call on
// caller-delegated account a, or the fixed tool error the agent sees instead.
// Every refusal happens before any network call except an exchange refusal.
// forget drops the cached token the Upstream last used; the caller runs it
// when the call still ends in a 401 after the one re-exchange.
func (g *Gateway) callerDelegatedUpstream(ctx context.Context, a Account) (up *Upstream, forget func(), problem string) {
	caller, ok := memberCallerFrom(ctx)
	if !ok || !caller.workload || caller.clientID == "" {
		return nil, nil, callerGrantInteractiveRefusal
	}
	// Exchange with the account's current credentials, which must still be
	// the snapshot this handler was built for.
	current, live := g.store.Account(a.Name)
	if !live || !current.CallerDelegated || current.IncarnationID != a.IncarnationID ||
		current.Revision != a.Revision || !equalAccountSnapshotURL(current.URL, a.URL) {
		return nil, nil, callerGrantConnectionChanged
	}
	grant, ok := selectCallerGrant(callerGrantsFrom(ctx), current.Resource)
	if !ok {
		return nil, nil, callerGrantMissingRefusal
	}
	claims, ok := decodeCallerGrantClaims(grant.compact)
	if !ok || !claims.routes(current, caller.clientID, callerGrantNow()) {
		return nil, nil, callerGrantMismatchRefusal
	}

	key := callerGrantCacheKey(grant.compact, caller.clientID)
	token := ""
	if entry, hit := g.callerGrants.lookup(key); hit {
		// The routing checks run again against the cached grant's own
		// claims on every hit.
		now := callerGrantNow()
		switch {
		case !entry.claims.routes(current, caller.clientID, now):
			g.callerGrants.drop(key)
			return nil, nil, callerGrantMismatchRefusal
		case !entry.boundTo(current) || !now.Before(entry.reuseTill):
			g.callerGrants.drop(key)
		default:
			token = entry.token
		}
	}
	exchange := func(ctx context.Context) (string, error) {
		if !claims.routes(current, caller.clientID, callerGrantNow()) {
			return "", &callerGrantRefusal{message: callerGrantMismatchRefusal}
		}
		fresh, expiresAt, err := g.exchangeCallerGrant(ctx, current, grant.compact)
		if err != nil {
			return "", err
		}
		if reuseTill := expiresAt.Add(-callerGrantTokenReuseMargin); callerGrantNow().Before(reuseTill) {
			g.callerGrants.put(key, callerGrantCacheEntry{
				account: current.Name, incarnationID: current.IncarnationID, oauthClientID: current.ClientID,
				tokenEndpoint: current.TokenEndpoint, resource: current.Resource,
				claims: claims, token: fresh, reuseTill: reuseTill,
			}, callerGrantNow())
		}
		return fresh, nil
	}
	if token == "" {
		fresh, err := exchange(ctx)
		if err != nil {
			var refusal *callerGrantRefusal
			if errors.As(err, &refusal) {
				return nil, nil, refusal.message
			}
			return nil, nil, callerGrantRefusedRefusal
		}
		token = fresh
	}

	var mu sync.Mutex
	credential := func() (string, error) {
		if !g.accountSnapshotLive(a.Name, a.IncarnationID, a.Revision, a.URL) {
			return "", ErrAccountIncarnation
		}
		mu.Lock()
		defer mu.Unlock()
		return token, nil
	}
	delegated := &Upstream{
		Name:       a.Name,
		URL:        a.URL,
		Credential: credential,
		Available: func() bool {
			_, err := credential()
			return err == nil
		},
		Token: func() string {
			current, _ := credential()
			return current
		},
		// A 401 drops the cached token and exchanges the grant once more;
		// withConn re-dials once with the result.
		Refresh: func(ctx context.Context) error {
			g.callerGrants.drop(key)
			fresh, err := exchange(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			token = fresh
			mu.Unlock()
			return nil
		},
	}
	forget = func() {
		mu.Lock()
		refused := token
		mu.Unlock()
		g.callerGrants.dropToken(key, refused)
	}
	return delegated, forget, ""
}

// exchangeCallerGrant performs the RFC 7523 exchange at a's token endpoint
// with a's client credentials (HTTP Basic). Every failure is a
// *callerGrantRefusal carrying the fixed tool error for the answer.
func (g *Gateway) exchangeCallerGrant(ctx context.Context, a Account, compact string) (string, time.Time, error) {
	label := a.Label
	if label == "" {
		label = a.Name
	}
	refused := &callerGrantRefusal{message: callerGrantRefusedRefusal}
	ctx, cancel := context.WithTimeout(ctx, callerGrantExchangeTimeout)
	defer cancel()
	form := url.Values{}
	form.Set("grant_type", callerGrantJWTBearerGrantType)
	form.Set("assertion", compact)
	form.Set("resource", a.Resource)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("engine: caller grant exchange for %q could not start", a.Name)
		return "", time.Time{}, refused
	}
	request.SetBasicAuth(a.ClientID, a.ClientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout:   callerGrantExchangeTimeout,
		Transport: newUpstreamTransport(),
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if err := upstreamoauth.CheckUpstreamRedirect(next, via); err != nil {
				return err
			}
			return errCallerGrantRedirect
		},
	}
	started := callerGrantNow()
	response, err := client.Do(request)
	if err != nil {
		log.Printf("engine: caller grant exchange for %q failed: %s", a.Name, callerGrantTransportFailure(err))
		return "", time.Time{}, refused
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCallerGrantExchangeResponseBytes+1))
	if err != nil || len(body) > maxCallerGrantExchangeResponseBytes {
		log.Printf("engine: caller grant exchange for %q refused: unreadable or oversized answer (status %d)", a.Name, response.StatusCode)
		return "", time.Time{}, refused
	}
	if response.StatusCode != http.StatusOK {
		var problem struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &problem)
		code, reason := callerGrantOAuthToken(problem.Error), callerGrantOAuthToken(problem.Description)
		log.Printf("engine: caller grant exchange for %q refused: status %d, error %q, reason %q", a.Name, response.StatusCode, code, reason)
		return "", time.Time{}, &callerGrantRefusal{message: callerGrantExchangeRefusal(label, code, reason)}
	}
	var answer struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		log.Printf("engine: caller grant exchange for %q refused: answer is not a token response", a.Name)
		return "", time.Time{}, refused
	}
	lifetime, ok := callerGrantLifetime(answer.ExpiresIn)
	if !ok || !callerDelegatedPrintable(answer.AccessToken, 1, maxCallerGrantAccessToken) ||
		(answer.TokenType != "" && !strings.EqualFold(answer.TokenType, "bearer")) {
		log.Printf("engine: caller grant exchange for %q refused: token response outside limits", a.Name)
		return "", time.Time{}, refused
	}
	return answer.AccessToken, started.Add(time.Duration(lifetime) * time.Second), nil
}

var errCallerGrantRedirect = errors.New("caller grant exchange does not follow redirects")

// jsonNumberLiteral reads raw only when it is a JSON number literal:
// encoding/json would also read a quoted "60" into a json.Number.
func jsonNumberLiteral(raw json.RawMessage) (json.Number, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9')) {
		return "", false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return "", false
	}
	return number, true
}

// callerGrantLifetime accepts an integer expires_in from 1 to 300 seconds.
func callerGrantLifetime(raw json.RawMessage) (int64, bool) {
	number, ok := jsonNumberLiteral(raw)
	if !ok {
		return 0, false
	}
	seconds, err := number.Int64()
	if err != nil || seconds < 1 || seconds > maxCallerGrantTokenLifetime {
		return 0, false
	}
	return seconds, true
}

// callerGrantExchangeRefusal maps an OAuth error answer to its fixed tool
// error.
func callerGrantExchangeRefusal(label, code, reason string) string {
	switch code {
	case "invalid_client":
		return callerGrantInvalidClientRefusal
	case "access_denied":
		switch reason {
		case "consent_required":
			return callerGrantConsentRequiredRefusal(label)
		case "config_changed":
			return callerGrantConfigChangedRefusal(label)
		case "agents_disabled":
			return callerGrantAgentsDisabledRefusal
		case "processing_location_blocked":
			return callerGrantProcessingBlockedRefusal
		case "run_not_live":
			return callerGrantRunEndedRefusal
		}
	}
	return callerGrantRefusedRefusal
}

// callerGrantKnownOAuthTokens are the error codes and reasons the Engine
// recognises. Anything else is reduced to "other", so neither a log line nor
// a decision ever carries free text (or an identifier) from the token
// endpoint.
var callerGrantKnownOAuthTokens = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
	"unsupported_grant_type": true, "invalid_scope": true, "invalid_target": true, "access_denied": true,
	"consent_required": true, "config_changed": true, "agents_disabled": true, "member_inactive": true,
	"run_not_live": true, "agent_blocked": true, "processing_location_blocked": true,
}

func callerGrantOAuthToken(value string) string {
	switch {
	case value == "":
		return ""
	case callerGrantKnownOAuthTokens[value]:
		return value
	}
	return "other"
}

// callerGrantTransportFailure names a transport failure without its request.
func callerGrantTransportFailure(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, errCallerGrantRedirect):
		return "redirect refused"
	case errors.Is(err, upstreamoauth.ErrUnsafeOutboundAddress):
		return "unsafe address"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return "timed out"
	}
	return "network error"
}

// callerGrantCallMeta is the _meta a caller-delegated upstream receives: only
// io.synaxis/call-id, and only when the caller sent a valid one.
func callerGrantCallMeta(req mcp.CallToolRequest) *mcp.Meta {
	if req.Params.Meta == nil {
		return nil
	}
	id, ok := req.Params.Meta.AdditionalFields[callerGrantCallIDMetaKey].(string)
	if !ok || !validCallerGrantCallID(id) {
		return nil
	}
	return &mcp.Meta{AdditionalFields: map[string]any{callerGrantCallIDMetaKey: id}}
}

// validCallerGrantCallID matches [A-Za-z0-9_-]{1,64}.
func validCallerGrantCallID(id string) bool {
	if id == "" || len(id) > maxCallerGrantCallIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// callerDelegatedCallResult turns the failures a caller-delegated call can
// end with into the fixed tool errors: an exchange refused on the one
// re-exchange after a 401, an upstream that still answers 401 (whose token
// forget drops from the cache), and an account that changed during the call.
func callerDelegatedCallResult(res *mcp.CallToolResult, err error, forget func()) (*mcp.CallToolResult, error) {
	if err == nil {
		return res, nil
	}
	var refusal *callerGrantRefusal
	switch {
	case errors.As(err, &refusal):
		return mcp.NewToolResultError(refusal.message), nil
	case errors.Is(err, ErrAccountIncarnation):
		return mcp.NewToolResultError(callerGrantConnectionChanged), nil
	case isUnauthorized(err):
		if forget != nil {
			forget()
		}
		return mcp.NewToolResultError(callerGrantRefusedRefusal), nil
	}
	return res, err
}

// auditCallerDelegatedRefusal records a call refused before any upstream
// call: the account, tool, workload subject and outcome, never a payload,
// grant or claim.
func (g *Gateway) auditCallerDelegatedRefusal(ctx context.Context, a Account, tool, message string) {
	if g.audit == nil {
		return
	}
	rec := CallRecord{CallerSubject: auditCallerSubject(ctx),
		AccountIncarnationID: a.IncarnationID, AccountOwnerSubject: a.OwnerSubject,
		Account: a.Name, Tool: tool, OK: false, Error: message,
	}
	if sc := auditScopeFrom(ctx); sc != nil {
		rec.Connector = sc.connector
		rec.EndpointKind = sc.kind
		rec.EndpointGeneration = sc.generation
		rec.Decision = sc.decision
	}
	g.audit.LogCall(rec)
}
