package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

const (
	managedBrowserCapability     = "managed-kernel-browser-v1"
	managedBrowserTicketHeader   = "X-Synaxis-Managed-Browser-Ticket"
	managedBrowserReadyHeader    = "X-Synaxis-Managed-Browser-Ready"
	managedBrowserResponseHeader = "X-Synaxis-Managed-Browser-Provider-Response"
)

type managedBrowserRequestKey struct{}

type managedBrowserRequest struct {
	ticket       string
	ready        bool
	cleanupOwner string
}

func managedBrowserRequestFrom(ctx context.Context) managedBrowserRequest {
	request, _ := ctx.Value(managedBrowserRequestKey{}).(managedBrowserRequest)
	return request
}

func withManagedBrowserHeaders(r *http.Request) context.Context {
	ctx := r.Context()
	if _, trusted := PlatformActorFromContext(ctx); !trusted {
		return ctx
	}
	request := managedBrowserRequest{}
	if values := r.Header.Values(managedBrowserReadyHeader); len(values) == 1 && values[0] == "1" {
		request.ready = true
	}
	if values := r.Header.Values(managedBrowserTicketHeader); len(values) == 1 && validManagedBrowserTicket(values[0]) {
		request.ticket = values[0]
	}
	return context.WithValue(ctx, managedBrowserRequestKey{}, request)
}

func validManagedBrowserTicket(ticket string) bool {
	if ticket == "" || len(ticket) > 4096 {
		return false
	}
	for _, c := range ticket {
		if c < '!' || c > '~' || c == ',' {
			return false
		}
	}
	return true
}

func withManagedBrowserCleanup(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, managedBrowserRequestKey{}, managedBrowserRequest{cleanupOwner: owner})
}

type managedBrowserBroker struct {
	endpoint string
	token    string
	client   *http.Client
}

// The explicitly tagged E2E build can supply a loopback-only transport.
var managedBrowserClientFactory = newManagedBrowserHTTPClient

func newManagedBrowserHTTPClient() *http.Client {
	client := upstreamoauth.NewHardenedHTTPClient(20 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func managedBrowserEndpoint(eventsURL, workspace string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(eventsURL))
	if err != nil || !browserResourceID(workspace) || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.EscapedPath() != "/v1/internal/engine-events/"+workspace {
		return "", errBrowserSignIn
	}
	u.Path = "/v1/internal/managed-browser/" + workspace
	u.RawPath = ""
	return u.String(), nil
}

// ConfigureHostedBrowser reuses the existing Engine-to-Platform credential and
// endpoint. It runs only on an Engine with hosted actor verification enabled.
func (s *BrowserSignInService) ConfigureHostedBrowser(eventsURL, workspace, token string) error {
	if strings.TrimSpace(eventsURL) == "" {
		return nil
	}
	endpoint, err := managedBrowserEndpoint(eventsURL, workspace)
	if err != nil || token == "" {
		return errBrowserSignIn
	}
	broker := managedBrowserBroker{endpoint: endpoint, token: token, client: managedBrowserClientFactory()}
	provider := newKernelProvider(kernelConfig{})
	provider.configurationID = oauthLinkHash("synaxis-hosted-kernel:v1")
	provider.apiRequest = broker.request
	s.hostedProvider = provider
	return nil
}

func (b managedBrowserBroker) request(ctx context.Context, method, path string, body, out any) error {
	auth := managedBrowserRequestFrom(ctx)
	if auth.ticket == "" && !validActorIdentifier(auth.cleanupOwner) || auth.ticket != "" && auth.cleanupOwner != "" {
		return errBrowserSignIn
	}
	command, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Path      string `json:"path"`
		Body      any    `json:"body,omitempty"`
		Owner     string `json:"owner,omitempty"`
	}{Operation: method, Path: path, Body: body, Owner: auth.cleanupOwner})
	if err != nil || len(command) > 64<<10 {
		return errBrowserSignIn
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(command))
	if err != nil {
		return errBrowserSignIn
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	if auth.ticket != "" {
		req.Header.Set(managedBrowserTicketHeader, auth.ticket)
	}
	response, err := b.client.Do(req)
	if err != nil {
		return errBrowserSignIn
	}
	defer response.Body.Close()
	if marker := response.Header.Values(managedBrowserResponseHeader); len(marker) != 1 || marker[0] != "1" {
		return errBrowserSignIn
	}
	return kernelResponse(response, out)
}
