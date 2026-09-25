package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Workload clients (docs/CONTROL_V1.md, "Subject-bound MCP clients") are
// subject-bound MCP clients whose non-human subject runs on a hosting control
// plane's runner. Nobody consents for them in a browser. Instead the control
// plane's service principal asks the Engine for a short-lived bearer bound to
// the client's /mcp/clients/{slug} resource and current epoch, and hands it
// to the runner. The Engine stays tenant-blind: it never learns what the
// subject is, only that the verified service actor asked.

// workloadTokenTTL is deliberately far shorter than the interactive access
// lifetime: a runner asks again (once per run and on expiry) instead of
// holding a refresh grant.
const workloadTokenTTL = time.Hour

// workloadTokenAttempts bounds the retry when authorization state moves
// between binding the client and signing its token, for example an epoch
// rotation from a concurrent profile or folder change.
const workloadTokenAttempts = 2

// WorkloadTokenIssuer mints a resource-bound access token for a workload
// OAuth identity. cmd/engine wires oauthas.Server.IssueResourceAccess, which
// signs the same token format RequireAuth verifies and re-checks the Engine's
// binding through the client-resource authorizer before signing.
type WorkloadTokenIssuer func(ctx context.Context, oauthClientID, resource string, ttl time.Duration) (token string, expiresAt time.Time, err error)

// WithWorkloadTokenIssuer enables POST /control/v1/mcp-clients/{id}/workload-token
// and the workload-clients capability. Leaving it unset keeps both unavailable.
func WithWorkloadTokenIssuer(issue WorkloadTokenIssuer) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.workloadTokens = issue
	}
}

// workloadTokensAvailable reports whether every dependency of the route is
// wired: the issuer, the live gateway whose projection supplies the resource
// epoch, and a store with the client registry.
func (c *ConsoleAPI) workloadTokensAvailable() bool {
	if c.workloadTokens == nil || c.gw == nil {
		return false
	}
	_, ok := c.mcpClientStore()
	return ok
}

func mcpClientResourcePath(slug string) string {
	return "/mcp/clients/" + slug
}

// controlWorkloadTokenDTO carries the bearer. There is no refresh token: the
// caller mints again, which is also how it observes a revoke (409) or reset.
type controlWorkloadTokenDTO struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int64  `json:"expiresIn"`
	ExpiresAt   string `json:"expiresAt"`
	Resource    string `json:"resource"`
}

// handleControlMCPClientWorkloadToken serves
// POST /control/v1/mcp-clients/{id}/workload-token for the Platform service
// actor only. The assertion boundary already admits the service principal to
// this one exact operation; the role check here keeps every human role out,
// including owners and the self-hosted local admin.
func (c *ConsoleAPI) handleControlMCPClientWorkloadToken(w http.ResponseWriter, r *http.Request) {
	wire := controlWire
	store, ok := c.mcpClientStore()
	if !ok {
		wire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "MCP client registry is not supported by this store"))
		return
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || actor.Role != "service" || actor.UserID != platformServiceActorID {
		wire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "workload tokens are issued only to the Platform service"))
		return
	}
	if r.Method != http.MethodPost {
		wire.writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request struct{}
	if failure := wire.decodeJSON(w, r, &request); failure != nil {
		wire.writeFailure(w, failure)
		return
	}
	if !c.workloadTokensAvailable() {
		wire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "workload tokens are not available on this engine"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	for attempt := 1; ; attempt++ {
		client, failure := c.prepareWorkloadTokenClient(r.Context(), store, id)
		if failure != nil {
			wire.writeFailure(w, failure)
			return
		}
		resource := mcpClientResourcePath(client.Slug)
		token, expiresAt, err := c.workloadTokens(r.Context(), workloadOAuthClientID(client.ID), resource, workloadTokenTTL)
		if err == nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			writeJSON(w, http.StatusOK, controlWorkloadTokenDTO{
				AccessToken: token,
				TokenType:   "Bearer",
				ExpiresIn:   int64(workloadTokenTTL / time.Second),
				ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
				Resource:    resource,
			})
			return
		}
		// The issuer re-checks the durable binding and the live epoch. A
		// refusal after the checks above means state moved underneath this
		// request (an epoch rotation, a reset, a revoke, or a generation
		// change). The next attempt re-reads and reclassifies it; a persistent
		// refusal is transient from the caller's point of view.
		if attempt >= workloadTokenAttempts || r.Context().Err() != nil {
			wire.writeFailure(w, newConsoleFailure(http.StatusServiceUnavailable, controlCodeEngineUnavailable, "workload token is temporarily unavailable; retry"))
			return
		}
	}
}

// prepareWorkloadTokenClient resolves the client, classifies it without
// revealing interactive registrations, ensures the reserved OAuth binding,
// and makes this replica's endpoint projection current so the token is signed
// for the client's present epoch.
func (c *ConsoleAPI) prepareWorkloadTokenClient(ctx context.Context, store MCPClientStore, id string) (MCPClient, *consoleFailure) {
	client, found := store.MCPClient(ctx, id)
	if !found || mcpClientKind(client) != MCPClientKindWorkload {
		// An interactive client, revoked or not, is indistinguishable from an
		// unknown one on this route.
		return MCPClient{}, mcpClientFailure(ErrMCPClientNotFound)
	}
	if client.Status != MCPClientStatusActive {
		return MCPClient{}, mcpClientFailure(ErrMCPClientRevoked)
	}
	switch client.OAuthClientID {
	case workloadOAuthClientID(client.ID):
	case "":
		bound, err := store.BindMCPClientWorkloadIdentity(ctx, client.ID)
		if err != nil {
			return MCPClient{}, workloadTokenBindFailure(err)
		}
		client = bound
	default:
		return MCPClient{}, mcpClientFailure(ErrMCPClientWorkloadBinding)
	}
	// The bind moves Revision, and a concurrent change may have moved Epoch.
	// Rebuild only when this replica's projection is behind the durable
	// record; the issuer then reads the resource epoch from that projection.
	if !c.gw.mcpClientProjectionMatches(client) {
		if err := c.gw.RefreshMCPClients(ctx); err != nil {
			return MCPClient{}, newConsoleFailure(http.StatusServiceUnavailable, controlCodeEngineUnavailable, "MCP client endpoint could not be refreshed; retry")
		}
	}
	return client, nil
}

// workloadTokenBindFailure maps a bind error with the route's disclosure rule:
// a record that is (or became) unknown or interactive is 404, never a hint.
func workloadTokenBindFailure(err error) *consoleFailure {
	if errors.Is(err, ErrMCPClientKind) || errors.Is(err, ErrMCPClientNotFound) {
		return mcpClientFailure(ErrMCPClientNotFound)
	}
	return mcpClientFailure(err)
}
