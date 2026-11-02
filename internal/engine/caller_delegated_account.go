package engine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"narthex/backend/internal/upstreamoauth"
)

// IsCallerDelegated reports whether the account acts only for the caller named
// in a per-call grant (docs/CONTROL_V1.md, "Connections"). Such an account is
// delivered only through an exact connection grant and never projected through
// a folder grant, the root /mcp, a connector or an endpoint bundle.
func (a Account) IsCallerDelegated() bool {
	return a.CallerDelegated
}

// LibraryArtifactEraser is the optional store facet behind
// DELETE /control/v1/library/artifacts/{id}. DeleteLibraryArtifact removes the
// artifact with every version, media object, collaboration grant and chat-reply
// provenance record, and keeps a minimal tombstone (ID and deletion time) so a
// repeated delete stays idempotent. found is false only for an ID the store
// never knew; deleting an already-deleted artifact reports found=true.
type LibraryArtifactEraser interface {
	DeleteLibraryArtifact(ctx context.Context, id string) (found bool, err error)
}

// callerDelegatedAllowLoopbackHTTP is a package-private test seam. Production
// accepts only HTTPS for a caller-delegated connection's URL, token endpoint
// and resource; tests that run a local upstream may allow plain HTTP on a
// loopback host.
var callerDelegatedAllowLoopbackHTTP = false

const (
	callerDelegatedClientIDMaxBytes     = 128
	callerDelegatedClientSecretMinBytes = 32
	callerDelegatedClientSecretMaxBytes = 256
)

// callerDelegatedValidationError carries a message that is safe to return to
// the caller: it never quotes a submitted secret.
type callerDelegatedValidationError struct{ message string }

func (e callerDelegatedValidationError) Error() string { return e.message }

func invalidCallerDelegated(message string) error {
	return callerDelegatedValidationError{message: message}
}

// isCallerDelegatedValidationError reports whether err is a validation
// failure that maps to 400 validation_failed.
func isCallerDelegatedValidationError(err error) bool {
	var validation callerDelegatedValidationError
	return errors.As(err, &validation)
}

// callerDelegatedUpsertProblem refuses a whole-account write (Upsert: the
// deprecated /admin/token form, PgStore's encryption migration) that would
// change whether an account is caller-delegated. Upsert keeps the account's
// incarnation, so turning a caller-delegated connection into a plain one would
// hand the agents given that exact connection a shared credential, and the
// opposite would skip validateCallerDelegatedAccount. Only the control v1
// connections group creates or removes such an account.
func callerDelegatedUpsertProblem(previous *Account, next Account) error {
	if (previous != nil && previous.CallerDelegated) == next.CallerDelegated {
		return nil
	}
	return invalidCallerDelegated("a whole-account write cannot change whether a connection is caller-delegated")
}

// validateCallerDelegatedAccount checks every stored property a
// caller-delegated account depends on. The token endpoint and resource are
// credential-bearing destinations, so they must share the upstream's origin;
// the upstream URL may carry a path prefix that the canonical resource lacks
// (an upstream reachable under a hosting path prefix).
func validateCallerDelegatedAccount(a Account) error {
	if !a.CallerDelegated {
		return nil
	}
	if a.AuthMode != "token" {
		return invalidCallerDelegated("authMode must be token for a caller-delegated connection")
	}
	if a.IsPersonal() {
		return invalidCallerDelegated("a caller-delegated connection cannot be personal")
	}
	if a.MemberCredentials {
		return invalidCallerDelegated("a caller-delegated connection cannot use member credentials")
	}
	if !callerDelegatedPrintable(a.ClientID, 1, callerDelegatedClientIDMaxBytes) {
		return invalidCallerDelegated("callerDelegated.clientId must be 1 to 128 printable characters")
	}
	if !callerDelegatedPrintable(a.ClientSecret, callerDelegatedClientSecretMinBytes, callerDelegatedClientSecretMaxBytes) {
		return invalidCallerDelegated("callerDelegated.clientSecret must be 32 to 256 printable bytes")
	}
	upstream, err := callerDelegatedURL("url", a.URL)
	if err != nil {
		return err
	}
	tokenEndpoint, err := callerDelegatedURL("callerDelegated.tokenEndpoint", a.TokenEndpoint)
	if err != nil {
		return err
	}
	resource, err := callerDelegatedURL("callerDelegated.resource", a.Resource)
	if err != nil {
		return err
	}
	if !sameURLOrigin(upstream, tokenEndpoint) || !sameURLOrigin(upstream, resource) {
		return invalidCallerDelegated("url, callerDelegated.tokenEndpoint and callerDelegated.resource must share one origin")
	}
	upstreamPath := strings.TrimSuffix(upstream.EscapedPath(), "/")
	resourcePath := strings.TrimSuffix(resource.EscapedPath(), "/")
	if upstreamPath != resourcePath && !strings.HasSuffix(upstreamPath, resourcePath) {
		return invalidCallerDelegated("url must be callerDelegated.resource, optionally under a path prefix")
	}
	return nil
}

// callerDelegatedPrintable bounds a credential value to visible ASCII, so it
// can travel in an Authorization header without any encoding question.
func callerDelegatedPrintable(value string, minBytes, maxBytes int) bool {
	if len(value) < minBytes || len(value) > maxBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func callerDelegatedURL(field, raw string) (*url.URL, error) {
	invalid := invalidCallerDelegated(field + " must be an absolute https URL without credentials, query or fragment")
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2048 {
		return nil, invalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return nil, invalid
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return nil, invalid
		}
	}
	if parsed.Scheme == "http" && callerDelegatedAllowLoopbackHTTP && loopbackHost(parsed.Hostname()) {
		return parsed, nil
	}
	if parsed.Scheme != "https" || upstreamoauth.ValidateUpstreamURL(raw) != nil {
		return nil, invalid
	}
	return parsed, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameURLOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectiveURLPort(a) == effectiveURLPort(b)
}

func effectiveURLPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}

// callerDelegatedDTO is the secret-free projection of a caller-delegated
// account. The client secret is reported only as set; the bearer token is
// never reported at all.
type callerDelegatedDTO struct {
	TokenEndpoint   string `json:"tokenEndpoint"`
	ClientID        string `json:"clientId"`
	Resource        string `json:"resource"`
	ClientSecretSet bool   `json:"clientSecretSet"`
}

func newCallerDelegatedDTO(a Account) *callerDelegatedDTO {
	if !a.CallerDelegated {
		return nil
	}
	return &callerDelegatedDTO{
		TokenEndpoint:   a.TokenEndpoint,
		ClientID:        a.ClientID,
		Resource:        a.Resource,
		ClientSecretSet: a.ClientSecret != "",
	}
}

// accountConnectionUpdate is the revision-fenced connection edit behind
// PATCH /control/v1/connections/{name}: display name, upstream URL and the
// caller-delegated client configuration. Nil fields are unchanged. Ownership
// moves use MoveAccountToConnectionNamespace; the bearer token uses
// SetBearerToken.
type accountConnectionUpdate struct {
	Label         *string
	URL           *string
	TokenEndpoint *string
	ClientID      *string
	ClientSecret  *string
	Resource      *string
}

func (u accountConnectionUpdate) apply(a *Account) bool {
	changed := false
	set := func(target *string, value *string) {
		if value != nil && *target != *value {
			*target = *value
			changed = true
		}
	}
	set(&a.Label, u.Label)
	set(&a.URL, u.URL)
	set(&a.TokenEndpoint, u.TokenEndpoint)
	set(&a.ClientID, u.ClientID)
	set(&a.ClientSecret, u.ClientSecret)
	set(&a.Resource, u.Resource)
	return changed
}

// applyAccountConnectionUpdate is the whole edit rule, shared by the PATCH
// handler (before any write) and both stores (under their lock). It returns
// the edited account and whether anything changed.
//
// An edit never moves a credential the Engine already holds to another
// destination, where a destination is the upstream URL, the token endpoint
// or the resource, path included (one host may serve several tenants under
// path prefixes):
//   - a caller-delegated account changes destination only when the same edit
//     supplies the client secret, so the caller proves it holds the
//     credential that goes there; the listing token was issued for the old
//     destination and is dropped, to be PUT again;
//   - any other account keeps its URL while it holds credentials (its own
//     token, OAuth tokens, a client secret) or takes member credentials, as
//     portable config import does (ErrConnectAccountURLChanged).
func applyAccountConnectionUpdate(current Account, update accountConnectionUpdate) (Account, bool, error) {
	if !current.CallerDelegated && (update.TokenEndpoint != nil || update.ClientID != nil || update.ClientSecret != nil || update.Resource != nil) {
		return Account{}, false, invalidCallerDelegated("callerDelegated is set when a connection is created")
	}
	next := copyAccount(current)
	if !update.apply(&next) {
		return next, false, nil
	}
	if connectionDestinationChanged(current, next) {
		switch {
		case current.CallerDelegated && update.ClientSecret == nil:
			return Account{}, false, invalidCallerDelegated("url, callerDelegated.tokenEndpoint and callerDelegated.resource change only when callerDelegated.clientSecret is supplied in the same request")
		case !current.CallerDelegated && (accountHasStoredCredentials(current) || current.MemberCredentials):
			return Account{}, false, invalidCallerDelegated("url cannot change while the connection holds credentials; delete it and create it again")
		}
		next.BearerToken = ""
	}
	if err := validateCallerDelegatedAccount(next); err != nil {
		return Account{}, false, err
	}
	return next, true, nil
}

// connectionDestinationChanged compares the credential-bearing destinations
// of two versions of one account. Only differences an HTTPS request cannot
// tell apart (host case, the default port) count as equal.
func connectionDestinationChanged(current, next Account) bool {
	return !equalAccountSnapshotURL(current.URL, next.URL) ||
		!equalAccountSnapshotURL(current.TokenEndpoint, next.TokenEndpoint) ||
		!equalAccountSnapshotURL(current.Resource, next.Resource)
}

// accountConnectionUpdater is implemented by both built-in stores. A changed
// account advances Revision, so cached tool handlers fail closed until the
// account is re-aggregated.
type accountConnectionUpdater interface {
	UpdateAccountConnection(ctx context.Context, name, expectedIncarnationID string, expectedRevision int64, update accountConnectionUpdate) (Account, error)
}

var _ accountConnectionUpdater = (*FileStore)(nil)

func (s *FileStore) UpdateAccountConnection(_ context.Context, name, expectedIncarnationID string, expectedRevision int64, update accountConnectionUpdate) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.accounts {
		if account == nil || account.Name != name {
			continue
		}
		if expectedIncarnationID == "" || account.IncarnationID != expectedIncarnationID {
			return Account{}, ErrAccountIncarnation
		}
		if expectedRevision < 1 || account.Revision != expectedRevision {
			return Account{}, ErrConnectionNamespaceRevision
		}
		next, changed, err := applyAccountConnectionUpdate(*account, update)
		if err != nil {
			return Account{}, err
		}
		if !changed {
			return next, nil
		}
		before := copyAccount(*account)
		next.Revision++
		*account = next
		if err := s.saveLocked(); err != nil {
			*account = before
			return Account{}, err
		}
		return copyAccount(*account), nil
	}
	return Account{}, ErrAccountNotFound
}
