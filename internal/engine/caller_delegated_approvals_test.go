package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// newCallerDelegatedConsole is newConnectorConsole with one caller-delegated
// account ("delegated") beside an ordinary one ("plain"); both list a read
// tool and a write tool.
func newCallerDelegatedConsole(t *testing.T) (*http.ServeMux, string, *Gateway, *FileStore) {
	t.Helper()
	ctx := context.Background()
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Create(ctx, Account{
		Name: "delegated", URL: "https://delegated.example/api/v1/mcp", AuthMode: "token", BearerToken: "listing-key", CallerDelegated: true,
		ClientID: "client_test", ClientSecret: "secret_0123456789abcdef0123456789abcdef",
		TokenEndpoint: "https://delegated.example/api/v1/mcp/token", Resource: "https://delegated.example/api/v1/mcp",
	}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Create(ctx, Account{Name: "plain", URL: "https://plain.example/mcp", AuthMode: "token", BearerToken: "t"}); err != nil {
		t.Fatal(err)
	}
	g := NewGateway(fs, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	g.SetAudit(fs)
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{
			mcp.NewTool(a.Name+"__get_issue", mcp.WithReadOnlyHintAnnotation(true)),
			mcp.NewTool(a.Name + "__save_issue"),
		}, nil
	}
	g.Aggregate(ctx)
	api := NewConsoleAPI(fs, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux, api.signToken(), g, fs
}

func expectApprovalRefused(t *testing.T, label string, code int, got map[string]any, body string) {
	t.Helper()
	if code != http.StatusBadRequest || got["code"] != controlCodeApprovalNotSupportedForDelegated {
		t.Fatalf("%s = %d %s; want 400 %s", label, code, body, controlCodeApprovalNotSupportedForDelegated)
	}
}

func TestApprovalPolicyRefusedForCallerDelegatedAccount(t *testing.T) {
	ctx := context.Background()

	t.Run("tool governance", func(t *testing.T) {
		mux, tok, g, _ := newCallerDelegatedConsole(t)
		for _, preset := range []GovernancePreset{GovernancePresetSafeWrite, GovernancePresetHighRisk} {
			rec, got := doJSON(t, mux, tok, http.MethodPut, "/api/servers/delegated/tools/save_issue", `{"governancePreset":"`+string(preset)+`"}`)
			expectApprovalRefused(t, "governance "+string(preset), rec.Code, got, rec.Body.String())
		}
		if account, _ := g.store.Account("delegated"); len(account.ToolOverrides) != 0 {
			t.Fatalf("refused policy was stored: %+v", account.ToolOverrides)
		}
		// Policies that need no approval stay available, and other accounts
		// keep approval governance.
		if rec, _ := doJSON(t, mux, tok, http.MethodPut, "/api/servers/delegated/tools/get_issue", `{"governancePreset":"read_only"}`); rec.Code != http.StatusOK {
			t.Fatalf("read-only governance = %d %s", rec.Code, rec.Body)
		}
		if rec, _ := doJSON(t, mux, tok, http.MethodPut, "/api/servers/plain/tools/save_issue", `{"governancePreset":"safe_write"}`); rec.Code != http.StatusOK {
			t.Fatalf("ordinary safe-write governance = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("connector require_approval", func(t *testing.T) {
		mux, tok, _, fs := newCallerDelegatedConsole(t)
		rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connectors",
			`{"label":"Work","tools":{"delegated":["save_issue"]},"approval":{"delegated":["save_issue"]}}`)
		expectApprovalRefused(t, "connector create", rec.Code, got, rec.Body.String())
		if rec, _ := doJSON(t, mux, tok, http.MethodPost, "/api/connectors", `{"label":"Plain","tools":{"plain":["save_issue"]}}`); rec.Code != http.StatusCreated {
			t.Fatalf("ordinary connector = %d %s", rec.Code, rec.Body)
		}
		rec, got = doJSON(t, mux, tok, http.MethodPut, "/api/connectors/plain",
			`{"tools":{"plain":["save_issue"],"delegated":["save_issue"]},"approval":{"delegated":["save_issue"]}}`)
		expectApprovalRefused(t, "connector update", rec.Code, got, rec.Body.String())
		if connector, _ := fs.VirtualConnector(ctx, "plain"); len(connector.Approval) != 0 || len(connector.Tools["delegated"]) != 0 {
			t.Fatalf("refused connector policy was stored: %+v", connector)
		}

		// Triage cannot add one either, even for a call recorded through an
		// older connector row.
		if err := fs.UpsertConnector(ctx, VirtualConnector{Slug: "legacy", Label: "Legacy", Epoch: newEpoch(), Tools: map[string][]string{"delegated": {"save_issue"}}}); err != nil {
			t.Fatal(err)
		}
		fs.LogCall(CallRecord{Account: "delegated", Tool: "save_issue", Connector: "legacy", OK: true, Guard: "flagged:injection"})
		id := callRows(t, fs, "save_issue")[0].ID
		rec, got = doJSON(t, mux, tok, http.MethodPost, fmt.Sprintf("/api/logs/%d/triage", id), `{"action":"require_approval"}`)
		expectApprovalRefused(t, "triage require_approval", rec.Code, got, rec.Body.String())
		if connector, _ := fs.VirtualConnector(ctx, "legacy"); len(connector.Approval) != 0 {
			t.Fatalf("triage stored an approval policy: %+v", connector.Approval)
		}
	})

	t.Run("portable import", func(t *testing.T) {
		mux, tok, _, fs := newCallerDelegatedConsole(t)
		governed, _ := json.Marshal(portableConfig{Version: 1, Accounts: []portableAccount{{
			Name: "delegated", DisplayName: "Delegated", URL: "https://delegated.example/api/v1/mcp",
			ToolOverrides: map[string]ToolOverride{"save_issue": {GovernancePreset: GovernancePresetSafeWrite}},
		}}, Connectors: []portableConnector{}})
		rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/config/import", string(governed))
		expectApprovalRefused(t, "import governance", rec.Code, got, rec.Body.String())
		approval, _ := json.Marshal(portableConfig{Version: 1, Accounts: []portableAccount{}, Connectors: []portableConnector{{
			Slug: "work", Label: "Work", Tools: map[string][]string{"delegated": {"save_issue"}}, Approval: map[string][]string{"delegated": {"save_issue"}},
		}}})
		rec, got = doJSON(t, mux, tok, http.MethodPost, "/api/config/import", string(approval))
		expectApprovalRefused(t, "import connector approval", rec.Code, got, rec.Body.String())
		if account, _ := fs.Account("delegated"); len(account.ToolOverrides) != 0 {
			t.Fatalf("import stored a refused policy: %+v", account.ToolOverrides)
		}
		if _, found := fs.VirtualConnector(context.Background(), "work"); found {
			t.Fatal("import stored a refused connector")
		}
	})

	t.Run("shared tool grant on console and control", func(t *testing.T) {
		mux, tok, _, fs := newCallerDelegatedConsole(t)
		body := fmt.Sprintf(`{"name":"Share","connectionId":"delegated","recipientKind":"subject","recipientRef":"usr_member","recipientSubjects":["usr_member"],"tools":["get_issue"],"expiresAt":%q}`,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		rec, got := doJSON(t, mux, tok, http.MethodPost, "/api/connection-grants", body)
		expectApprovalRefused(t, "console connection grant", rec.Code, got, rec.Body.String())
		if grants, _ := fs.ConnectionGrants(ctx); len(grants) != 0 {
			t.Fatalf("refused grant stored: %+v", grants)
		}

		control, store, key, now, team := newHostedControlConsole(t)
		if err := store.Create(ctx, Account{
			Name: "delegated", URL: "https://delegated.example/api/v1/mcp", AuthMode: "token", BearerToken: "listing-key",
			ConnectionNamespaceID: team.ID, CallerDelegated: true,
			ClientID: "client_test", ClientSecret: "secret_0123456789abcdef0123456789abcdef",
			TokenEndpoint: "https://delegated.example/api/v1/mcp/token", Resource: "https://delegated.example/api/v1/mcp",
		}); err != nil {
			t.Fatal(err)
		}
		expectControlProblem(t, controlRequest(t, control, key, now, "usr_owner", "owner", http.MethodPost, "/control/v1/connection-grants", body),
			http.StatusBadRequest, controlCodeApprovalNotSupportedForDelegated)
	})

	t.Run("runtime never parks a call", func(t *testing.T) {
		_, _, g, fs := newCallerDelegatedConsole(t)
		// Without the refusal the call would park; keep a regression short.
		g.SetApprovalTimeout(50 * time.Millisecond)
		account, _ := fs.Account("delegated")
		called := false
		inner := func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			called = true
			return mcp.NewToolResultText("sent"), nil
		}
		request := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "delegated__save_issue", Arguments: map[string]any{"title": "private"}}}
		for label, handler := range map[string]server.ToolHandlerFunc{
			"approval wrapper":   g.approvalHandler("work", account, "save_issue", false, inner),
			"governance wrapper": g.governedAccountToolHandler(account, "save_issue", false, GovernancePresetHighRisk, inner),
		} {
			result, err := handler(ctx, request)
			if err != nil || result == nil || !result.IsError || called {
				t.Fatalf("%s: result=%+v err=%v called=%t; want a refusal without dispatch", label, result, err, called)
			}
		}
		if pending, err := g.PendingApprovals(ctx); err != nil || len(pending) != 0 {
			t.Fatalf("pending calls for a caller-delegated account: %+v err=%v", pending, err)
		}
	})
}
