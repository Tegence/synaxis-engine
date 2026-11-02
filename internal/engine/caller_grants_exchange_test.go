package engine

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCallerGrantExchangeRequestShape(t *testing.T) {
	f := newCallerGrantFixture(t)
	grant := f.grant(t, f.workload)
	call := func() callerGrantCallResult {
		return callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil)
	}
	wantToolText(t, call(), "result from /hosted/h1/mcp")

	seen := f.origin.lastExchange()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(callerGrantTestClientID+":"+callerGrantTestClientSecret))
	if seen.authorization != wantAuth {
		t.Fatalf("Authorization = %q; want HTTP Basic with the account's client credentials", seen.authorization)
	}
	if seen.contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", seen.contentType)
	}
	if len(seen.form) != 3 || seen.form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
		seen.form.Get("assertion") != grant.compact || seen.form.Get("resource") != f.origin.resource() {
		t.Fatalf("form = %v", seen.form)
	}
	if seen.grantHeader != "" {
		t.Fatal("the grant header was forwarded to the token endpoint")
	}
	if got := f.origin.delegatedToolCalls(); len(got) != 1 || !strings.HasPrefix(got[0].authorization, "Bearer atk_") {
		t.Fatalf("upstream call = %+v; want the exchanged token as a bearer", got)
	}

	if callerGrantExchangeTimeout != 5*time.Second {
		t.Fatalf("exchange timeout = %v; want 5s", callerGrantExchangeTimeout)
	}

	// Each refused answer is a fixed tool error and dials nothing upstream.
	fresh := func() callerGrant {
		claims := f.claims(f.workload)
		claims["jti"] = "jti_" + time.Now().Format("150405.000000000")
		return callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
	}
	refuse := func(name string, handler http.HandlerFunc) {
		t.Helper()
		f.origin.setExchange(handler)
		before := len(f.origin.delegatedToolCalls())
		got := callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{fresh()}, nil)
		if got.rpcError != "" || !got.isError || got.text != callerGrantRefusedRefusal {
			t.Fatalf("%s: %+v; want %q", name, got, callerGrantRefusedRefusal)
		}
		if after := len(f.origin.delegatedToolCalls()); after != before {
			t.Fatalf("%s: the upstream was called after a refused exchange", name)
		}
	}
	answer := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}

	// Redirects are refused, never followed.
	var redirected atomic.Int32
	f.origin.Config.Handler.(*http.ServeMux).HandleFunc("/hosted/h1/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		answer(`{"access_token":"atk_redirected","token_type":"Bearer","expires_in":60}`)(w, nil)
	})
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		status := status
		refuse("redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/hosted/h1/elsewhere", status)
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("a redirect from the token endpoint was followed")
	}

	// An answer over 16 KiB is refused; one just under is read.
	padded := func(n int) string {
		body := `{"access_token":"atk_padded","token_type":"Bearer","expires_in":60,"pad":"`
		return body + strings.Repeat("x", n-len(body)-2) + `"}`
	}
	refuse("oversized answer", answer(padded(maxCallerGrantExchangeResponseBytes+1)))
	f.origin.mu.Lock()
	f.origin.issued["atk_padded"] = true
	f.origin.mu.Unlock()
	f.origin.setExchange(answer(padded(maxCallerGrantExchangeResponseBytes)))
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{fresh()}, nil), "result from /hosted/h1/mcp")

	// expires_in must be an integer from 1 to 300.
	for _, expires := range []string{`0`, `-1`, `301`, `1.5`, `"60"`, `null`} {
		refuse("expires_in "+expires, answer(`{"access_token":"atk_padded","token_type":"Bearer","expires_in":`+expires+`}`))
	}
	refuse("no expires_in", answer(`{"access_token":"atk_padded","token_type":"Bearer"}`))
	for _, expires := range []string{`1`, `300`} {
		f.origin.setExchange(answer(`{"access_token":"atk_padded","token_type":"Bearer","expires_in":` + expires + `}`))
		wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{fresh()}, nil), "result from /hosted/h1/mcp")
	}
	refuse("no token", answer(`{"token_type":"Bearer","expires_in":60}`))
	refuse("not bearer", answer(`{"access_token":"atk_padded","token_type":"mac","expires_in":60}`))
	refuse("not JSON", answer(`atk_padded`))
	refuse("token with a space", answer(`{"access_token":"atk padded","token_type":"Bearer","expires_in":60}`))

	// The exchange is bounded by its timeout.
	previous := callerGrantExchangeTimeout
	callerGrantExchangeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { callerGrantExchangeTimeout = previous })
	started := time.Now()
	refuse("slow endpoint", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		answer(`{"access_token":"atk_padded","token_type":"Bearer","expires_in":60}`)(w, r)
	})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a slow exchange took %v; the timeout did not apply", elapsed)
	}
}

func TestCallerGrantTokenCachedUntil10sBeforeExpiry(t *testing.T) {
	f := newCallerGrantFixture(t)
	clock := setCallerGrantClock(t, time.Now())
	claims := f.claims(f.workload)
	claims["exp"] = clock.Add(5 * time.Minute).Unix()
	grant := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
	f.origin.mu.Lock()
	f.origin.expiresIn = 60
	f.origin.mu.Unlock()
	start := *clock
	call := func() {
		t.Helper()
		wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), "result from /hosted/h1/mcp")
	}
	call()
	*clock = start.Add(49 * time.Second)
	call()
	if n := f.origin.exchangeCount(); n != 1 {
		t.Fatalf("exchanges at expiry-11s = %d; want the cached token (1)", n)
	}
	*clock = start.Add(50 * time.Second)
	call()
	if n := f.origin.exchangeCount(); n != 2 {
		t.Fatalf("exchanges at expiry-10s = %d; want a new exchange (2)", n)
	}
	calls := f.origin.delegatedToolCalls()
	if calls[0].authorization != calls[1].authorization || calls[1].authorization == calls[2].authorization {
		t.Fatalf("tokens used = %q, %q, %q", calls[0].authorization, calls[1].authorization, calls[2].authorization)
	}

	// A token that lives no longer than the margin is used once, never cached.
	f.origin.mu.Lock()
	f.origin.expiresIn = 10
	f.origin.mu.Unlock()
	other := f.claims(f.workload)
	other["exp"] = clock.Add(5 * time.Minute).Unix()
	other["jti"] = "jti_short"
	short := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, other)}
	for i := 0; i < 2; i++ {
		wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{short}, nil), "result from /hosted/h1/mcp")
	}
	if n := f.origin.exchangeCount(); n != 4 {
		t.Fatalf("exchanges = %d; want a short-lived token exchanged each time (4)", n)
	}
}

func TestCallerGrantReExchangesOnceOn401(t *testing.T) {
	f := newCallerGrantFixture(t)
	grant := f.grant(t, f.workload)
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), "result from /hosted/h1/mcp")
	first := f.origin.delegatedToolCalls()[0].authorization

	// The upstream stops accepting the cached token: one re-exchange, one
	// re-dial with the new token, success.
	f.origin.mu.Lock()
	f.origin.revoked[strings.TrimPrefix(first, "Bearer ")] = true
	f.origin.mu.Unlock()
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), "result from /hosted/h1/mcp")
	if n := f.origin.exchangeCount(); n != 2 {
		t.Fatalf("exchanges = %d; want one re-exchange (2)", n)
	}
	calls := f.origin.delegatedToolCalls()
	if last := calls[len(calls)-1].authorization; last == first {
		t.Fatal("the re-dial reused the refused token")
	}
	if entry, hit := f.gateway.callerGrants.lookup(callerGrantCacheKey(grant.compact, f.workload.ID)); !hit || "Bearer "+entry.token == first {
		t.Fatal("the refused token is still cached")
	}

	// Every token is refused: exactly one re-exchange, then a fixed error.
	f.origin.mu.Lock()
	f.origin.revokeIssued = true
	for token := range f.origin.issued {
		f.origin.revoked[token] = true
	}
	f.origin.mu.Unlock()
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), callerGrantRefusedRefusal)
	if n := f.origin.exchangeCount(); n != 3 {
		t.Fatalf("exchanges = %d; want exactly one re-exchange after the second 401 (3)", n)
	}
	// The re-exchanged token the upstream also refused is not kept: the next
	// call with this grant starts with a fresh exchange, not a 401 dial.
	if _, hit := f.gateway.callerGrants.lookup(callerGrantCacheKey(grant.compact, f.workload.ID)); hit {
		t.Fatal("a token the upstream refused after the re-exchange is still cached")
	}

	// A re-exchange the authorization server refuses ends with its fixed
	// error.
	f.origin.mu.Lock()
	f.origin.revokeIssued = false
	f.origin.mu.Unlock()
	f.origin.setExchange(nil)
	claims := f.claims(f.workload)
	claims["jti"] = "jti_ended"
	ended := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{ended}, nil), "result from /hosted/h1/mcp")
	f.origin.mu.Lock()
	for token := range f.origin.issued {
		f.origin.revoked[token] = true
	}
	f.origin.mu.Unlock()
	f.origin.setExchange(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"run_not_live"}`))
	})
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{ended}, nil), callerGrantRunEndedRefusal)
}

func TestCallerGrantExchangeErrorsAreFixedToolErrors(t *testing.T) {
	f := newCallerGrantFixture(t)
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusUnauthorized, `{"error":"invalid_client"}`, "An admin must reconnect this connection."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"consent_required"}`, "Allow this agent to work in Acme Tools first."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"config_changed"}`, "This agent changed. Its owner must allow it again in Acme Tools."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"agents_disabled"}`, "Agents are turned off for this organization."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"processing_location_blocked"}`, "This organization hasn't approved this model for its data."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"run_not_live"}`, "This job has ended."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"member_inactive"}`, "The connection refused this job's permission."},
		{http.StatusForbidden, `{"error":"access_denied","error_description":"agent_blocked"}`, "The connection refused this job's permission."},
		{http.StatusForbidden, `{"error":"access_denied"}`, "The connection refused this job's permission."},
		{http.StatusBadRequest, `{"error":"invalid_grant","error_description":"expired"}`, "The connection refused this job's permission."},
		{http.StatusBadRequest, `{"error":"consent_required"}`, "The connection refused this job's permission."},
		{http.StatusInternalServerError, `oops`, "The connection refused this job's permission."},
		{http.StatusServiceUnavailable, ``, "The connection refused this job's permission."},
	}
	for i, tc := range cases {
		tc := tc
		f.origin.setExchange(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})
		claims := f.claims(f.workload)
		claims["jti"] = "jti_case_" + string(rune('a'+i))
		grant := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
		wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), tc.want)
	}
	if calls := f.origin.delegatedToolCalls(); len(calls) != 0 {
		t.Fatalf("a refused exchange reached the upstream: %+v", calls)
	}
	if f.gateway.callerGrants.len() != 0 {
		t.Fatal("a refused exchange left a cache entry")
	}

	// The service is named by the connection's display label (the Engine is
	// tenant-blind); a connection without one is named by its tool prefix.
	current, _ := f.store.Account("delegated")
	current.Label = ""
	if err := f.store.Upsert(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if _, err := f.gateway.ReplaceAccount(context.Background(), "delegated"); err != nil {
		t.Fatal(err)
	}
	f.origin.setExchange(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"consent_required"}`))
	})
	claims := f.claims(f.workload)
	claims["jti"] = "jti_unlabelled"
	grant := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, nil), "Allow this agent to work in delegated first.")
}
