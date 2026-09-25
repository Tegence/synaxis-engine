package oauthas

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	workloadTestClientID = "workload:mcpcli_agent"
	workloadTestResource = "/mcp/clients/agent"
)

// newResourceAccessServer wires the two Engine seams IssueResourceAccess
// depends on: the per-path epoch lookup and the client-resource authorizer.
// The authorizer admits exactly one bound (client, resource) pair unless the
// test replaces it.
func newResourceAccessServer(t *testing.T, epochs map[string]string, store *memoryTokenGenerationStore) *Server {
	t.Helper()
	server := New("https://engine.example", "pw", "resource-access-secret")
	server.SetEpochLookup(func(path string) (string, bool) {
		epoch, ok := epochs[path]
		return epoch, ok
	})
	server.SetClientResourceAuthorizer(func(clientID, resource string) bool {
		return clientID == workloadTestClientID && resource == workloadTestResource
	})
	configureGeneration(t, server, store)
	return server
}

func requireAuthStatus(server *Server, token, path string) (int, bool) {
	called := false
	handler := server.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code, called
}

func TestIssueResourceAccessMintsARequireAuthTokenWithTheRequestedLifetime(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{workloadTestResource: "epoch-1", "/mcp/clients/other": "epoch-9"}
	server := newResourceAccessServer(t, epochs, &memoryTokenGenerationStore{})
	now := time.Date(2026, time.September, 25, 10, 0, 0, 500_000_000, time.UTC)
	server.now = func() time.Time { return now }

	token, expiresAt, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour)
	if err != nil {
		t.Fatalf("IssueResourceAccess: %v", err)
	}
	// Expiry is carried in whole seconds, so the reported instant is exactly
	// the one the token encodes, never later than now+ttl.
	wantExpiry := time.Unix(now.Add(time.Hour).Unix(), 0).UTC()
	if !expiresAt.Equal(wantExpiry) || expiresAt.After(now.Add(time.Hour)) {
		t.Fatalf("expiresAt=%s; want %s", expiresAt, wantExpiry)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != strconv.FormatInt(expiresAt.Unix(), 10) {
		t.Fatalf("token does not use the access-token format with the reported expiry: %q", token)
	}
	if clientID, _ := base64.RawURLEncoding.DecodeString(parts[2]); string(clientID) != workloadTestClientID {
		t.Fatalf("token client=%q", clientID)
	}
	if resource, _ := base64.RawURLEncoding.DecodeString(parts[3]); string(resource) != workloadTestResource {
		t.Fatalf("token resource=%q", resource)
	}

	if status, called := requireAuthStatus(server, token, workloadTestResource); status != http.StatusNoContent || !called {
		t.Fatalf("RequireAuth on the bound resource=%d called=%v; want 204/true", status, called)
	}
	// The audience is exact: another client's endpoint and the shared root
	// both reject it.
	for _, path := range []string{"/mcp/clients/other", "/mcp"} {
		if status, called := requireAuthStatus(server, token, path); status != http.StatusUnauthorized || called {
			t.Fatalf("RequireAuth on %s=%d called=%v; want 401/false", path, status, called)
		}
	}
	// Brokered issuance leaves no durable or in-memory grant behind.
	server.mu.RLock()
	codes, refresh := len(server.codes), len(server.refresh)
	server.mu.RUnlock()
	if codes != 0 || refresh != 0 {
		t.Fatalf("issuance created codes=%d refresh=%d; want none", codes, refresh)
	}

	// The token lives until, and not through, its encoded expiry.
	now = expiresAt.Add(-time.Second)
	if !server.validAccess(token, workloadTestResource) {
		t.Fatal("token expired before its lifetime ended")
	}
	now = expiresAt
	if server.validAccess(token, workloadTestResource) {
		t.Fatal("token outlived its one-hour lifetime")
	}

	// The lifetime bound is inclusive of the interactive maximum.
	if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, accessTTL); err != nil {
		t.Fatalf("maximum lifetime refused: %v", err)
	}
}

func TestIssueResourceAccessRefusesSharedResourcesAndMalformedRequests(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{"/mcp": "root", "/mcp/team": "team", workloadTestResource: "epoch-1"}
	server := newResourceAccessServer(t, epochs, &memoryTokenGenerationStore{})
	// Admit everything so each refusal below is attributable to its input.
	server.SetClientResourceAuthorizer(func(string, string) bool { return true })

	for _, ttl := range []time.Duration{0, -time.Second, accessTTL + time.Second} {
		if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, ttl); !errors.Is(err, ErrInvalidResourceAccess) {
			t.Fatalf("ttl %s err=%v; want ErrInvalidResourceAccess", ttl, err)
		}
	}
	for _, resource := range []string{
		"", "/mcp", "/mcp/team", "https://engine.example" + workloadTestResource, workloadTestResource + "/",
		"/mcp/clients/", "/mcp/clients/../clients/agent", "/mcp/clients/agent?x=1", "/mcp/clients/agent#x",
		"/mcp/clients/a%2Fb", "/mcp/clients/a|b", "/mcp/clients/a b", "/mcp/clients/agent/tools",
	} {
		if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, resource, time.Hour); !errors.Is(err, ErrInvalidResourceAccess) {
			t.Fatalf("resource %q err=%v; want ErrInvalidResourceAccess", resource, err)
		}
	}
	for _, clientID := range []string{"", "workload:a|b", "workload: spaced", "workload:\x00", strings.Repeat("x", maxClientIDLength+1)} {
		if _, _, err := server.IssueResourceAccess(ctx, clientID, workloadTestResource, time.Hour); !errors.Is(err, ErrInvalidResourceAccess) {
			t.Fatalf("client %q err=%v; want ErrInvalidResourceAccess", clientID, err)
		}
	}
}

func TestIssueResourceAccessRequiresALiveResourceAndTheEngineBinding(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{workloadTestResource: "epoch-1"}
	server := newResourceAccessServer(t, epochs, &memoryTokenGenerationStore{})

	if _, _, err := server.IssueResourceAccess(ctx, "workload:mcpcli_someone_else", workloadTestResource, time.Hour); !errors.Is(err, ErrResourceAccessDenied) {
		t.Fatalf("unbound client identity err=%v; want denied", err)
	}
	if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, "/mcp/clients/missing", time.Hour); !errors.Is(err, ErrResourceAccessDenied) {
		t.Fatalf("unknown resource err=%v; want denied", err)
	}
	// Without an Engine authorizer there is no binding to trust at all.
	server.SetClientResourceAuthorizer(nil)
	if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour); !errors.Is(err, ErrResourceAccessDenied) {
		t.Fatalf("no authorizer err=%v; want denied", err)
	}
}

func TestIssueResourceAccessTokensDieWithEpochRotationBindingLossAndRevokeAll(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{workloadTestResource: "epoch-1"}
	server := newResourceAccessServer(t, epochs, &memoryTokenGenerationStore{})
	mint := func() string {
		t.Helper()
		token, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour)
		if err != nil {
			t.Fatalf("IssueResourceAccess: %v", err)
		}
		if !server.validAccess(token, workloadTestResource) {
			t.Fatal("freshly minted token is not valid")
		}
		return token
	}

	token := mint()
	epochs[workloadTestResource] = "epoch-2"
	if server.validAccess(token, workloadTestResource) {
		t.Fatal("token survived an endpoint epoch rotation")
	}
	token = mint()

	if err := server.RevokeAll(ctx); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if server.validAccess(token, workloadTestResource) {
		t.Fatal("token survived a workspace-wide revocation")
	}
	token = mint()

	// validAccess re-asks the Engine on every use, so losing the binding
	// (a reset or revoke that has not rotated anything else yet) kills it.
	server.SetClientResourceAuthorizer(func(string, string) bool { return false })
	if server.validAccess(token, workloadTestResource) {
		t.Fatal("token survived the loss of its client binding")
	}
}

func TestIssueResourceAccessSynchronizesAStaleGenerationBeforeSigning(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{workloadTestResource: "epoch-1"}
	store := &memoryTokenGenerationStore{}
	fresh := newResourceAccessServer(t, epochs, store)
	stale := newResourceAccessServer(t, epochs, store)
	if err := fresh.RevokeAll(ctx); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	token, _, err := stale.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour)
	if err != nil {
		t.Fatalf("IssueResourceAccess on a stale replica: %v", err)
	}
	if !fresh.validAccess(token, workloadTestResource) {
		t.Fatal("a stale replica minted under the retired generation")
	}

	// A replica that cannot confirm the durable generation mints nothing.
	cold := newResourceAccessServer(t, epochs, store)
	store.mu.Lock()
	store.currentErr = errors.New("database unavailable")
	store.mu.Unlock()
	if _, _, err := cold.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour); err == nil ||
		errors.Is(err, ErrResourceAccessDenied) || errors.Is(err, ErrInvalidResourceAccess) {
		t.Fatalf("generation read failure err=%v; want an availability error", err)
	}
}

func TestIssueResourceAccessRefusesWhenAuthorizationStateMovesMidIssue(t *testing.T) {
	ctx := context.Background()
	epochs := map[string]string{workloadTestResource: "epoch-1"}
	server := newResourceAccessServer(t, epochs, &memoryTokenGenerationStore{})

	// The binding was approved for epoch-1, but the endpoint rotated before
	// signing: the token must not be issued for state nobody authorized.
	server.SetClientResourceAuthorizer(func(string, string) bool {
		epochs[workloadTestResource] = "epoch-2"
		return true
	})
	if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour); !errors.Is(err, ErrResourceAccessDenied) {
		t.Fatalf("epoch moved during authorization err=%v; want denied", err)
	}

	// Likewise for a workspace-wide revocation that lands mid-issue.
	server.SetClientResourceAuthorizer(func(string, string) bool {
		if err := server.RevokeAll(context.Background()); err != nil {
			t.Errorf("RevokeAll: %v", err)
		}
		return true
	})
	if _, _, err := server.IssueResourceAccess(ctx, workloadTestClientID, workloadTestResource, time.Hour); !errors.Is(err, ErrResourceAccessDenied) {
		t.Fatalf("generation moved during authorization err=%v; want denied", err)
	}
}
