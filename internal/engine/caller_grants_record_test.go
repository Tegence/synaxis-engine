package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// auditRows returns every audit row with its payloads, as CallDetail would.
func auditRows(t *testing.T, sink *ring) []CallRecord {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]CallRecord(nil), sink.buf...)
}

func TestDelegatedAccountNeverRecordsPayloads(t *testing.T) {
	f := newCallerGrantFixture(t)
	sink := &ring{}
	f.gateway.SetAudit(sink)
	f.gateway.SetRecordPayloads(true) // ENGINE_RECORD_PAYLOADS=true
	ctx := context.Background()
	grant := f.grant(t, f.workload)

	// Through the workload client endpoint.
	wantToolText(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", []callerGrant{grant}, map[string]any{callerGrantCallIDMetaKey: "toolu_01"}), "result from /hosted/h1/mcp")
	// Under a scope that asks for payloads (a recording connector or a
	// high-risk policy), dispatching the cached handler directly.
	f.gateway.mu.Lock()
	cached := f.gateway.cached["delegated"][0]
	plainCached := f.gateway.cached["plain"][0]
	f.gateway.mu.Unlock()
	recording := withAuditScope(
		withMemberCaller(withCallerGrants(ctx, []callerGrant{grant}), memberCaller{subject: f.workload.Subject, workload: true, clientID: f.workload.ID}),
		&auditScope{connector: "recording", kind: endpointKindConnector, generation: "gen", record: true},
	)
	request := mcp.CallToolRequest{}
	request.Params.Name = "delegated__search"
	request.Params.Arguments = map[string]any{"query": "q-argument"}
	if res, err := cached.handler(recording, request); err != nil || res.IsError {
		t.Fatalf("recorded-scope call = %+v, %v", res, err)
	}
	// A refused call is audited without payloads too.
	wantToolError(t, callClientTool(t, f.gateway, f.workload.Slug, "delegated__search", nil, nil), callerGrantMissingRefusal)

	// The control: the same settings record an ordinary account's payloads.
	if res, err := plainCached.handler(recording, request); err != nil || res.IsError {
		t.Fatalf("plain call = %+v, %v", res, err)
	}

	rows := auditRows(t, sink)
	var delegated, plain int
	for _, row := range rows {
		switch row.Account {
		case "delegated":
			delegated++
			if row.Args != "" || row.Result != "" {
				t.Fatalf("caller-delegated payloads recorded: %+v", row)
			}
			if row.CallerSubject != f.workload.Subject || row.Tool != "search" {
				t.Fatalf("audit row = %+v; want the workload subject and the tool", row)
			}
		case "plain":
			plain++
			if !strings.Contains(row.Args, "q-argument") || row.Result == "" {
				t.Fatalf("control row did not record payloads: %+v", row)
			}
		}
	}
	if delegated != 3 || plain != 1 {
		t.Fatalf("audit rows: delegated=%d plain=%d; want 3 and 1", delegated, plain)
	}
	var refused CallRecord
	for _, row := range rows {
		if row.Account == "delegated" && !row.OK {
			refused = row
		}
	}
	if refused.Error != callerGrantMissingRefusal {
		t.Fatalf("refused call audit = %+v; want its outcome", refused)
	}

	// A replay has no caller grant to act on, so it is never available.
	for _, row := range rows {
		if row.Account == "delegated" {
			if _, err := f.gateway.Replay(ctx, row.ID, true); err == nil {
				t.Fatalf("replay of a caller-delegated call %d succeeded", row.ID)
			}
		}
	}
}

func TestCallerGrantRedactedInLogsAuditAndFlightRecorder(t *testing.T) {
	logs := captureEngineLog(t)
	f := newCallerGrantFixture(t)
	sink := &ring{}
	f.gateway.SetAudit(sink)
	f.gateway.SetRecordPayloads(true)
	grant := f.grant(t, f.workload)

	// Success over HTTP (the header lifted by the transport), a 401 with one
	// re-exchange, and every refused exchange.
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{callerGrantHeaderValue(grant)}), "result from /hosted/h1/mcp")
	f.origin.mu.Lock()
	for token := range f.origin.issued {
		f.origin.revoked[token] = true
	}
	f.origin.mu.Unlock()
	wantToolText(t, postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{callerGrantHeaderValue(grant)}), "result from /hosted/h1/mcp")
	for i, body := range []string{
		`{"error":"invalid_client","error_description":"` + callerGrantTestSubject + `"}`,
		`{"error":"access_denied","error_description":"run_not_live"}`,
		`{"error":"` + callerGrantTestSubject + `","error_description":"` + grant.compact + `"}`,
	} {
		body := body
		f.origin.setExchange(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(body))
		})
		claims := f.claims(f.workload)
		claims["jti"] = fmt.Sprintf("jti_refused_%d", i)
		refused := callerGrant{resource: f.origin.resource(), compact: testCompactGrant(t, claims)}
		result := postClientToolCall(t, f.gateway, f.workload.Slug, "delegated__search", []string{callerGrantHeaderValue(refused)})
		if !result.isError {
			t.Fatalf("refused exchange succeeded: %+v", result)
		}
	}

	f.origin.mu.Lock()
	var secrets []string
	for token := range f.origin.issued {
		secrets = append(secrets, token)
	}
	upstreamGrantHeaders := 0
	for _, call := range f.origin.calls {
		if call.grantHeader != "" {
			upstreamGrantHeaders++
		}
	}
	for _, exchange := range f.origin.exchanges {
		if exchange.grantHeader != "" {
			upstreamGrantHeaders++
		}
	}
	f.origin.mu.Unlock()
	if upstreamGrantHeaders != 0 {
		t.Fatalf("the grant header was forwarded %d times", upstreamGrantHeaders)
	}
	if len(secrets) < 2 {
		t.Fatalf("expected issued access tokens, got %v", secrets)
	}
	payload := strings.Split(grant.compact, ".")[1]
	secrets = append(secrets, grant.compact, payload, callerGrantTestSubject, callerGrantTestClientSecret)

	var recorded []string
	for _, row := range auditRows(t, sink) {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, string(raw), row.CallerSubject, row.AccountOwnerSubject, row.Error, row.Args, row.Result)
	}
	if len(recorded) == 0 {
		t.Fatal("no audit rows were written")
	}
	output := logs.String()
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Fatalf("a log line carries a secret (%.12s…):\n%s", secret, output)
		}
		for _, field := range recorded {
			if strings.Contains(field, secret) {
				t.Fatalf("an audit or recorder entry carries a secret (%.12s…): %s", secret, field)
			}
		}
	}
	if !strings.Contains(output, `caller grant exchange for "delegated" refused`) {
		t.Fatalf("refused exchanges were not logged at all:\n%s", output)
	}
}
