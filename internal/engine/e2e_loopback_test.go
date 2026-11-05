//go:build engine_e2e_loopback

package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

// Run with: go test -tags engine_e2e_loopback ./internal/engine -run '^TestE2ELoopback'
// (the rest of the package assumes the default build, where loopback is
// refused).

func TestE2ELoopbackBuildAcceptsLoopbackHTTPCallerDelegatedURLs(t *testing.T) {
	account := Account{
		Name:            "delegated",
		AuthMode:        "token",
		ConnectionScope: ConnectionScopeService,
		CallerDelegated: true,
		ClientID:        "pcl_e2e_client",
		ClientSecret:    strings.Repeat("s", callerDelegatedClientSecretMinBytes),
		URL:             "http://localhost:3110/api/v1/mcp",
		TokenEndpoint:   "http://localhost:3110/api/v1/mcp/token",
		Resource:        "http://localhost:3110/api/v1/mcp",
	}
	if err := validateCallerDelegatedAccount(account); err != nil {
		t.Fatalf("loopback http caller-delegated account refused in the e2e build: %v", err)
	}
	remote := account
	remote.URL, remote.TokenEndpoint, remote.Resource = "http://tools.example.com/mcp", "http://tools.example.com/token", "http://tools.example.com/mcp"
	if err := validateCallerDelegatedAccount(remote); err == nil {
		t.Fatal("plain http to a non-loopback host accepted; only loopback may use http")
	}
}

func TestE2ELoopbackTransportReachesLoopbackOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	client := &http.Client{Transport: newUpstreamTransport(), Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("loopback upstream unreachable in the e2e build: %v", err)
	}
	response.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.255.255.1/", nil)
	if _, err := client.Do(request); !errors.Is(err, upstreamoauth.ErrUnsafeOutboundAddress) {
		t.Fatalf("private address dial error = %v; want ErrUnsafeOutboundAddress", err)
	}
}
