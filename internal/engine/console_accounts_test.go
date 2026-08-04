package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestCreateAccountRejectsNormalizedNameCollisionWithoutMutation(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, map[string][]string{"acme": {}})

	rec, body := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":" ACME!! ","group":"replacement","url":"https://replacement.example/mcp","bearerToken":"replacement-secret"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST duplicate = %d, body %s; want 409", rec.Code, rec.Body)
	}
	if got, _ := body["error"].(string); !strings.Contains(got, `"acme"`) || !strings.Contains(got, "already exists") {
		t.Fatalf("duplicate error = %q; want normalized account name", got)
	}

	account, ok := gateway.store.Account("acme")
	if !ok {
		t.Fatal("original account disappeared")
	}
	if account.URL != "http://unused" || account.Group != "" || account.BearerToken != "t" {
		t.Fatalf("duplicate create mutated original account: %+v", account)
	}
	if got := gateway.store.Accounts(); len(got) != 1 {
		t.Fatalf("duplicate create changed account count to %d", len(got))
	}
}

func TestCreateAccountAllowsUniqueNormalizedName(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, nil)

	rec, _ := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Project Alpha!","group":"Product","url":"https://alpha.example/mcp"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST unique = %d, body %s; want 201", rec.Code, rec.Body)
	}

	var got serverDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode created account: %v", err)
	}
	if got.UUID != "project_alpha" || got.Name != "project_alpha" || got.Namespace != "project_alpha" {
		t.Fatalf("created account identity = %q/%q/%q; want normalized project_alpha", got.UUID, got.Name, got.Namespace)
	}
	if _, ok := gateway.store.Account("project_alpha"); !ok {
		t.Fatal("unique account was not persisted")
	}
}

func TestCreateAccountPersistsStaticOAuthConfigurationBeforeAuthorization(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, nil)
	const secret = "gmail-secret-must-never-appear-in-a-dto"
	const scope = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose"

	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/servers", `{
		"name":"Gmail · Operations",
		"toolPrefix":"operations_gmail",
		"url":"https://gmailmcp.googleapis.com/mcp/v1",
		"oauthClientId":"gmail-client-id",
		"oauthClientSecret":"`+secret+`",
		"oauthScope":"`+scope+`"
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST static OAuth account = %d, body %s; want 201", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("create response leaked OAuth client secret: %s", rec.Body.String())
	}
	for _, forbidden := range []string{"oauthClientId", "oauthClientSecret", "oauthScope", "clientSecret"} {
		if _, found := got[forbidden]; found {
			t.Fatalf("create DTO exposed %q: %v", forbidden, got)
		}
	}

	account, found := gateway.store.Account("operations_gmail")
	if !found {
		t.Fatal("created static OAuth account was not persisted")
	}
	if account.ClientID != "gmail-client-id" || account.ClientSecret != secret || account.Scope != scope {
		t.Fatalf("stored static OAuth configuration = %+v", account)
	}
	// This is the retry path after browser cancellation: no browser-supplied
	// credentials are necessary, and Gmail gets its durable-token parameters.
	retry := effectiveStaticCreds(nil, account, true, account.URL)
	if retry == nil || retry.ClientID != account.ClientID || retry.ClientSecret != secret || retry.Scope != scope {
		t.Fatalf("cancel/retry static OAuth configuration = %+v, want persisted Gmail client", retry)
	}
	if retry.AuthorizationExtras["access_type"] != "offline" || retry.AuthorizationExtras["prompt"] != "consent" {
		t.Fatalf("Gmail retry did not derive durable authorization extras: %+v", retry.AuthorizationExtras)
	}
}

func TestCreateAccountRejectsInvalidStaticOAuthConfigurationBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		want   string
		secret string
	}{
		{
			name: "missing scope",
			body: `{"name":"Static","url":"https://example.com/mcp","oauthClientId":"client-id"}`,
			want: "scope",
		},
		{
			name: "Gmail missing confidential client secret",
			body: `{"name":"Gmail","url":"https://gmailmcp.googleapis.com/mcp/v1","oauthClientId":"client-id","oauthScope":"https://www.googleapis.com/auth/gmail.readonly"}`,
			want: "clientSecret",
		},
		{
			name: "static OAuth plus bearer token",
			body: `{"name":"Mixed","url":"https://example.com/mcp","oauthClientId":"client-id","oauthScope":"read","bearerToken":"provider-token"}`,
			want: "bearer token",
		},
		{
			name:   "invalid URL does not echo OAuth secret",
			body:   `{"name":"Broken","url":"http://127.0.0.1/mcp","oauthClientId":"client-id","oauthClientSecret":"never-echo-this-secret","oauthScope":"read"}`,
			want:   "url",
			secret: "never-echo-this-secret",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, token, gateway := newConnectorConsole(t, nil)
			rec, got := doJSON(t, mux, token, http.MethodPost, "/api/servers", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST invalid static OAuth account = %d, body %s; want 400", rec.Code, rec.Body)
			}
			if message, _ := got["error"].(string); !strings.Contains(message, tc.want) {
				t.Fatalf("error = %q, want mention of %q", message, tc.want)
			}
			if tc.secret != "" && strings.Contains(rec.Body.String(), tc.secret) {
				t.Fatalf("invalid static OAuth response leaked client secret: %s", rec.Body.String())
			}
			if accounts := gateway.store.Accounts(); len(accounts) != 0 {
				t.Fatalf("invalid static OAuth request persisted account(s): %+v", accounts)
			}
		})
	}
}

func TestCreateAccountAllowsMultipleConnectionsToSameProvider(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, nil)

	for _, body := range []string{
		`{"name":"Notion · Work","namespace":"notion_work","url":"https://mcp.notion.com/mcp"}`,
		`{"name":"Notion · Personal","namespace":"notion_personal","url":"https://mcp.notion.com/mcp"}`,
	} {
		rec, _ := doJSON(t, mux, token, http.MethodPost, "/api/servers", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST same-provider account = %d, body %s; want 201", rec.Code, rec.Body)
		}
	}

	accounts := gateway.store.Accounts()
	if len(accounts) != 2 {
		t.Fatalf("account count = %d; want 2", len(accounts))
	}
	work, workOK := gateway.store.Account("notion_work")
	personal, personalOK := gateway.store.Account("notion_personal")
	if !workOK || !personalOK {
		t.Fatalf("namespaced accounts missing: work=%t personal=%t", workOK, personalOK)
	}
	if work.Label != "Notion · Work" || personal.Label != "Notion · Personal" {
		t.Fatalf("display labels = %q/%q; want distinct Notion labels", work.Label, personal.Label)
	}
	if work.URL != personal.URL {
		t.Fatalf("same provider URL was not preserved: %q/%q", work.URL, personal.URL)
	}
}

func TestSameProviderConnectionsKeepOwningNamespacesCredentialsAndMethodsIndependent(t *testing.T) {
	tools := map[string][]string{}
	mux, token, gateway := newConnectorConsole(t, tools)
	// The test seam is captured by reference. Populate it after constructing
	// the empty store so each API create aggregates the provider's same bare
	// method under that account's independent stable prefix.
	tools["tegence_notion"] = []string{"search", "fetch"}
	tools["personal_notion"] = []string{"search", "fetch"}

	for _, body := range []string{
		`{"name":"Notion · Tegence","toolPrefix":"tegence_notion","connectionNamespace":"Tegence","group":"Tegence","url":"https://mcp.notion.com/mcp","bearerToken":"tegence-token"}`,
		`{"name":"Notion · Personal","toolPrefix":"personal_notion","connectionNamespace":"Personal","group":"Personal","url":"https://mcp.notion.com/mcp","bearerToken":"personal-token"}`,
	} {
		rec, _ := doJSON(t, mux, token, http.MethodPost, "/api/servers", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST namespaced same-provider account = %d, body %s; want 201", rec.Code, rec.Body)
		}
	}

	tegence, tegenceOK := gateway.store.Account("tegence_notion")
	personal, personalOK := gateway.store.Account("personal_notion")
	if !tegenceOK || !personalOK {
		t.Fatalf("same-provider accounts missing: tegence=%t personal=%t", tegenceOK, personalOK)
	}
	if tegence.Group != "Tegence" || personal.Group != "Personal" {
		t.Fatalf("owning connection namespaces = %q/%q; want Tegence/Personal", tegence.Group, personal.Group)
	}
	if tegence.BearerToken != "tegence-token" || personal.BearerToken != "personal-token" ||
		tegence.BearerToken == personal.BearerToken {
		t.Fatal("same-provider account credentials were fused")
	}

	gateway.mu.Lock()
	tegenceTools := append([]cachedTool(nil), gateway.cached["tegence_notion"]...)
	personalTools := append([]cachedTool(nil), gateway.cached["personal_notion"]...)
	gateway.mu.Unlock()
	if len(tegenceTools) != 2 || len(personalTools) != 2 {
		t.Fatalf("cached method counts = %d/%d; want 2/2", len(tegenceTools), len(personalTools))
	}
	if tegenceTools[0].tool.Name != "tegence_notion__search" ||
		personalTools[0].tool.Name != "personal_notion__search" {
		t.Fatalf("same bare method tool names = %q/%q; want independent account prefixes",
			tegenceTools[0].tool.Name, personalTools[0].tool.Name)
	}

	rec, _ := doJSON(t, mux, token, http.MethodGet, "/api/servers", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET accounts = %d, body %s", rec.Code, rec.Body)
	}
	var accounts []serverDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &accounts); err != nil {
		t.Fatalf("decode account list: %v", err)
	}
	if len(accounts) != 2 ||
		accounts[0].ConnectionNamespace != accounts[0].Group ||
		accounts[1].ConnectionNamespace != accounts[1].Group {
		t.Fatalf("connectionNamespace/group aliases not mirrored: %+v", accounts)
	}
}

func TestConnectionNamespacePreferredAliasAndLegacyGroupStayCompatible(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, nil)

	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Notion","toolPrefix":"tegence_notion","connectionNamespace":"Tegence","url":"https://mcp.notion.com/mcp"}`)
	if rec.Code != http.StatusCreated || got["connectionNamespace"] != "Tegence" || got["group"] != "Tegence" {
		t.Fatalf("preferred namespace create = %d %v", rec.Code, got)
	}

	rec, got = doJSON(t, mux, token, http.MethodPatch, "/api/servers/tegence_notion",
		`{"connectionNamespace":"Research","group":"Research"}`)
	if rec.Code != http.StatusOK || got["connectionNamespace"] != "Research" || got["group"] != "Research" {
		t.Fatalf("matching namespace aliases PATCH = %d %v", rec.Code, got)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPatch, "/api/servers/tegence_notion",
		`{"connectionNamespace":"Tegence","group":"Personal"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflicting namespace aliases PATCH = %d, want 400", rec.Code)
	}
	if account, _ := gateway.store.Account("tegence_notion"); account.Group != "Research" {
		t.Fatalf("rejected namespace alias conflict mutated account: %+v", account)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Conflict","toolPrefix":"conflict","connectionNamespace":"Tegence","group":"Personal","url":"https://mcp.notion.com/mcp"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflicting namespace aliases POST = %d, want 400", rec.Code)
	}
	if _, exists := gateway.store.Account("conflict"); exists {
		t.Fatal("rejected namespace alias conflict persisted an account")
	}
}

func TestCreateAccountNamespaceIsIndependentFromDisplayName(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, nil)

	rec, _ := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Research workspace","namespace":"Notion / Client A","url":"https://mcp.notion.com/mcp"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST namespaced account = %d, body %s; want 201", rec.Code, rec.Body)
	}

	var got serverDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode created account: %v", err)
	}
	if got.Namespace != "notion_client_a" || got.Name != got.Namespace || got.UUID != got.Namespace {
		t.Fatalf("created identity = %+v; want stable notion_client_a aliases", got)
	}
	account, ok := gateway.store.Account("notion_client_a")
	if !ok || account.Label != "Research workspace" {
		t.Fatalf("stored account = %+v, %t; want independent display label", account, ok)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPatch, "/api/servers/notion_client_a",
		`{"displayName":"Renamed research workspace"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH display label = %d, body %s; want 200", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode renamed account: %v", err)
	}
	if got.Namespace != "notion_client_a" || got.DisplayName != "Renamed research workspace" {
		t.Fatalf("renamed account = %+v; namespace must remain stable", got)
	}
}

func TestDuplicateCreateDoesNotBlockExplicitUpdateOrReconnect(t *testing.T) {
	mux, token, gateway := newConnectorConsole(t, map[string][]string{"acme": {}})

	rec, _ := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Acme","url":"https://replacement.example/mcp","bearerToken":"replacement-secret"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST duplicate = %d, body %s; want 409", rec.Code, rec.Body)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPatch, "/api/servers/acme",
		`{"displayName":"Acme Updated","group":"Operations"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH existing = %d, body %s; want 200", rec.Code, rec.Body)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/servers/acme/token",
		`{"token":"reconnected-secret"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST token reconnect = %d, body %s; want 200", rec.Code, rec.Body)
	}

	account, ok := gateway.store.Account("acme")
	if !ok {
		t.Fatal("updated account disappeared")
	}
	if account.Label != "Acme Updated" || account.Group != "Operations" {
		t.Fatalf("explicit metadata update was not preserved: %+v", account)
	}
	if account.BearerToken != "reconnected-secret" {
		t.Fatal("explicit token reconnect did not replace the credential")
	}
	if !errors.Is(gateway.store.Create(t.Context(), Account{Name: "acme"}), ErrAccountExists) {
		t.Fatal("store Create no longer reports ErrAccountExists")
	}
}

func TestNamespaceOnlyMoveSkipsUpstreamAndFailedPolicyPatchCanBeRetried(t *testing.T) {
	ctx := context.Background()
	mux, token, gateway := newConnectorConsole(t, map[string][]string{
		"notion": {"search", "save_page"},
	})
	baseList := gateway.listTools
	gateway.listTools = func(callCtx context.Context, a Account) ([]mcp.Tool, error) {
		tools, err := baseList(callCtx, a)
		for i := range tools {
			if strings.HasSuffix(tools[i].Name, "__search") {
				tools[i].Annotations.ReadOnlyHint = mcp.ToBoolPtr(true)
			}
		}
		return tools, err
	}
	account, _ := gateway.store.Account("notion")
	account.Label, account.Group = "Notion", "Old namespace"
	account.BearerToken = "credential-must-survive"
	account.ToolOverrides = map[string]ToolOverride{"search": {Description: "Curated search"}}
	if err := gateway.store.Upsert(ctx, account); err != nil {
		t.Fatalf("seed account metadata: %v", err)
	}
	if _, err := gateway.ReplaceAccount(ctx, account.Name); err != nil {
		t.Fatalf("seed live cache: %v", err)
	}
	endpoint, err := gateway.CreateNamespace(ctx, Namespace{
		Slug: "client", Label: "Client", Accounts: []string{account.Name},
	})
	if err != nil {
		t.Fatalf("create endpoint bundle: %v", err)
	}
	originalList := gateway.listTools
	listCalls := 0
	failList := true
	gateway.listTools = func(callCtx context.Context, a Account) ([]mcp.Tool, error) {
		listCalls++
		if failList {
			return nil, errors.New("upstream is temporarily unavailable")
		}
		return originalList(callCtx, a)
	}

	// Moving the owning namespace is metadata-only. It must not dial upstream
	// or disturb the last-known-good cache and endpoint membership.
	rec, got := doJSON(t, mux, token, http.MethodPatch, "/api/servers/notion",
		`{"connectionNamespace":"Tegence"}`)
	if rec.Code != http.StatusOK || got["connectionNamespace"] != "Tegence" {
		t.Fatalf("namespace-only PATCH = %d %v", rec.Code, got)
	}
	if listCalls != 0 {
		t.Fatalf("namespace-only PATCH listed upstream %d times", listCalls)
	}
	moved, _ := gateway.store.Account("notion")
	if moved.Name != "notion" || moved.Group != "Tegence" || moved.BearerToken != "credential-must-survive" ||
		moved.ToolOverrides["search"].Description != "Curated search" {
		t.Fatalf("namespace move changed account identity/credentials/policy: %+v", moved)
	}
	storedEndpoint, ok := gateway.store.(NamespaceStore).Namespace(ctx, "client")
	if !ok || storedEndpoint.Epoch != endpoint.Epoch || !sameStrings(storedEndpoint.Accounts, []string{"notion"}) {
		t.Fatalf("namespace move changed endpoint membership: %+v ok=%v", storedEndpoint, ok)
	}
	if names := connectorNames(t, gateway, "client"); !eq(names, []string{"notion__save_page", "notion__search"}) {
		t.Fatalf("namespace move changed endpoint cache: %v", names)
	}

	// Label/read-only persistence succeeds but live replacement fails. The API
	// must surface that failure without deleting the previous cache.
	rec, _ = doJSON(t, mux, token, http.MethodPatch, "/api/servers/notion",
		`{"displayName":"Notion · Tegence","readOnly":true}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("failed label/read-only reaggregate = %d, body %s; want 502", rec.Code, rec.Body)
	}
	if listCalls != 1 {
		t.Fatalf("label/read-only PATCH list calls = %d, want 1", listCalls)
	}
	if names := connectorNames(t, gateway, "client"); !eq(names, []string{"notion__save_page", "notion__search"}) {
		t.Fatalf("failed replacement destroyed endpoint cache: %v", names)
	}

	// Retry with the same already-persisted values must still reaggregate.
	failList = false
	rec, got = doJSON(t, mux, token, http.MethodPatch, "/api/servers/notion",
		`{"displayName":"Notion · Tegence","readOnly":true}`)
	if rec.Code != http.StatusOK || got["displayName"] != "Notion · Tegence" || got["readOnly"] != true {
		t.Fatalf("retry PATCH = %d %v", rec.Code, got)
	}
	if listCalls != 2 {
		t.Fatalf("retry did not re-list upstream: calls=%d", listCalls)
	}
	if names := connectorNames(t, gateway, "client"); !eq(names, []string{"notion__search"}) {
		t.Fatalf("retry did not repair read-only endpoint cache: %v", names)
	}
}
