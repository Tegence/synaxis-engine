package engine

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// TestConnectionTokenWriteListsAgainSoon: an authorization server may accept
// a new listing credential only after the control plane's write has
// returned (it records the credential once the control plane answers). The
// token PUT's own listing then fails; the Engine lists the account again
// within seconds, instead of leaving it without tools until the next health
// sweep.
func TestConnectionTokenWriteListsAgainSoon(t *testing.T) {
	previous := aggregationRetryDelays
	aggregationRetryDelays = []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { aggregationRetryDelays = previous })

	store := newFileConnectionsStore(t)
	verifier, key, now := newActorVerifier(t)
	var accepted atomic.Bool
	var listed atomic.Int32
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		listed.Add(1)
		if !accepted.Load() {
			return nil, errors.New("401 Unauthorized: listing key not recorded yet")
		}
		return []mcp.Tool{mcp.NewTool("search_records", mcp.WithDescription("Search records"))}, nil
	}
	api := NewConsoleAPI(store, gateway, nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	h := &connectionsTestHarness{t: t, store: store, mux: mux, key: key, now: now, name: "delegated_retry", group: "Delegated retry"}

	created := h.mustCreate()
	put := h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`)
	if put.Code != http.StatusOK {
		t.Fatalf("token PUT status=%d body=%s", put.Code, put.Body)
	}
	account, _ := store.Account(h.name)
	if gateway.accountProjected(account) {
		t.Fatal("the account was projected although its listing was refused")
	}
	// The authorization server records the credential just after the write.
	accepted.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for !gateway.accountProjected(account) {
		if time.Now().After(deadline) {
			t.Fatalf("the account was not listed again after its credential was accepted (%d listings)", listed.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	gateway.mu.Lock()
	cached := gateway.cached[h.name]
	gateway.mu.Unlock()
	if len(cached) != 1 || !strings.HasSuffix(cached[0].tool.Name, "__search_records") {
		t.Fatalf("cached tools = %+v", cached)
	}
	// Once projected, nothing lists it again.
	settled := listed.Load()
	time.Sleep(100 * time.Millisecond)
	if listed.Load() != settled {
		t.Fatalf("listings went on after the account was projected: %d then %d", settled, listed.Load())
	}
}

// TestConnectionWriteRetrySaysWhenAnotherPassListedFirst: the start-up
// reconcile or the health sweep can list the account before the retry loop
// wakes. The loop then stops, and says so, so a watcher of the log learns
// that the account is listed.
func TestConnectionWriteRetrySaysWhenAnotherPassListedFirst(t *testing.T) {
	previous := aggregationRetryDelays
	aggregationRetryDelays = []time.Duration{300 * time.Millisecond}
	t.Cleanup(func() { aggregationRetryDelays = previous })
	var logs bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput); log.SetFlags(previousFlags) })

	store := newFileConnectionsStore(t)
	verifier, key, now := newActorVerifier(t)
	var accepted atomic.Bool
	gateway := NewGateway(store, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	gateway.listTools = func(context.Context, Account) ([]mcp.Tool, error) {
		if !accepted.Load() {
			return nil, errors.New("401 Unauthorized: listing key not recorded yet")
		}
		return []mcp.Tool{mcp.NewTool("search_records", mcp.WithDescription("Search records"))}, nil
	}
	api := NewConsoleAPI(store, gateway, nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	h := &connectionsTestHarness{t: t, store: store, mux: mux, key: key, now: now, name: "delegated_other_pass", group: "Delegated other pass"}

	created := h.mustCreate()
	put := h.service(http.MethodPut, h.path()+"/token", `{"token":"`+testDelegatedListingToken+`","revision":`+itoa64(created.Revision)+`}`)
	if put.Code != http.StatusOK {
		t.Fatalf("token PUT status=%d body=%s", put.Code, put.Body)
	}
	accepted.Store(true)
	account, _ := store.Account(h.name)
	if _, err := gateway.aggregateAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, running := gateway.aggregationRetries.Load(h.name); !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the retry loop did not stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), `account "delegated_other_pass" was listed by another pass after a connection write`) {
		t.Fatalf("log = %s", logs.String())
	}
}
