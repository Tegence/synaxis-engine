package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func preconditionOf(ns Namespace) NamespacePrecondition {
	return NamespacePrecondition{Generation: ns.Epoch, Revision: ns.Revision}
}

func TestFileStoreNamespacePersistenceAndAccountDetach(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{Name: "linear", URL: "https://linear.example/mcp", AuthMode: "token", BearerToken: "linear-token"},
		{Name: "notion_work", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "work-token"},
		{Name: "notion_personal", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "personal-token"},
	} {
		if err := store.Upsert(ctx, account); err != nil {
			t.Fatalf("upsert %s: %v", account.Name, err)
		}
	}
	if err := store.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team", Epoch: "team-epoch", Accounts: []string{"notion_work", "linear", "linear"},
	}); err != nil {
		t.Fatalf("create team: %v", err)
	}
	created, _ := store.Namespace(ctx, "team")
	team, err := store.AddNamespaceAccount(ctx, "team", "linear", preconditionOf(created))
	if err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if team.Revision != 1 {
		t.Fatalf("idempotent add changed revision to %d", team.Revision)
	}
	team, err = store.AddNamespaceAccount(ctx, "team", "notion_personal", preconditionOf(team))
	if err != nil {
		t.Fatalf("add personal: %v", err)
	}
	if team.Revision != 2 {
		t.Fatalf("membership add revision = %d, want 2", team.Revision)
	}
	if err := store.CreateNamespace(ctx, Namespace{
		Slug: "research", Label: "Research", Epoch: "research-epoch", Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("create research: %v", err)
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Namespace(ctx, "team")
	if !ok || got.Epoch != "team-epoch" || got.Revision != 2 ||
		!sameStrings(got.Accounts, []string{"linear", "notion_personal", "notion_work"}) {
		t.Fatalf("reopened team = %+v, ok=%v", got, ok)
	}
	got.Accounts[0] = "mutated"
	again, _ := reopened.Namespace(ctx, "team")
	if again.Accounts[0] == "mutated" {
		t.Fatal("Namespace returned a slice that aliases FileStore state")
	}

	linear, _ := reopened.Account("linear")
	if err := reopened.Delete(ctx, "linear", linear.IncarnationID, linear.Revision); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	got, _ = reopened.Namespace(ctx, "team")
	if got.Revision != 3 || !sameStrings(got.Accounts, []string{"notion_personal", "notion_work"}) {
		t.Fatalf("team after account delete = %+v", got)
	}
	research, _ := reopened.Namespace(ctx, "research")
	if research.Revision != 2 || len(research.Accounts) != 0 {
		t.Fatalf("research after account delete = %+v", research)
	}
	if reopened.Token("notion_work") != "work-token" {
		t.Fatal("detaching a different account changed member credentials")
	}

	if err := reopened.DeleteNamespace(ctx, "team", preconditionOf(got)); err != nil {
		t.Fatalf("delete namespace: %v", err)
	}
	if _, ok := reopened.Namespace(ctx, "team"); ok {
		t.Fatal("deleted namespace still exists")
	}
	if _, ok := reopened.Account("notion_work"); !ok || reopened.Token("notion_work") != "work-token" {
		t.Fatal("namespace deletion removed or changed its account")
	}
}

func TestNamespaceGatewayProjectsMixedProvidersAndSharedAccounts(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear":          {"get_issue", "save_issue"},
		"notion_work":     {"search", "fetch"},
		"notion_personal": {"search", "fetch"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)

	team, err := g.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team", Accounts: []string{"linear", "notion_work", "notion_personal"},
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	if team.Epoch == "" {
		t.Fatal("namespace endpoint did not receive an OAuth epoch")
	}
	wantTeam := []string{
		"linear__get_issue", "linear__save_issue",
		"notion_personal__fetch", "notion_personal__search",
		"notion_work__fetch", "notion_work__search",
	}
	if got := connectorNames(t, g, "team"); !sameStrings(got, wantTeam) {
		t.Fatalf("team tools = %v, want %v", got, wantTeam)
	}

	if _, err := g.CreateNamespace(ctx, Namespace{
		Slug: "research", Label: "Research", Accounts: []string{"linear", "notion_work"},
	}); err != nil {
		t.Fatalf("create research: %v", err)
	}
	if got := connectorNames(t, g, "research"); !sameStrings(got, []string{
		"linear__get_issue", "linear__save_issue", "notion_work__fetch", "notion_work__search",
	}) {
		t.Fatalf("research tools = %v", got)
	}

	if _, err := g.RemoveNamespaceAccount(ctx, "team", "linear", preconditionOf(team)); err != nil {
		t.Fatalf("detach linear: %v", err)
	}
	if got := connectorNames(t, g, "team"); !sameStrings(got, []string{
		"notion_personal__fetch", "notion_personal__search", "notion_work__fetch", "notion_work__search",
	}) {
		t.Fatalf("team after detach = %v", got)
	}
	g.mu.Lock()
	rootLinear := append([]string(nil), g.byAcct["linear"]...)
	g.mu.Unlock()
	if len(rootLinear) != 2 {
		t.Fatalf("namespace detach changed root /mcp tools: %v", rootLinear)
	}
	if g.store.Token("linear") != "t" {
		t.Fatal("namespace detach changed the account token")
	}

	team, _ = g.store.(NamespaceStore).Namespace(ctx, "team")
	if err := g.DeleteNamespace(ctx, "team", preconditionOf(team)); err != nil {
		t.Fatalf("delete team: %v", err)
	}
	if _, ok := g.ConnectorHandler("team"); ok {
		t.Fatal("deleted namespace endpoint is still served")
	}
	if _, ok := g.store.Account("notion_personal"); !ok || g.store.Token("notion_personal") != "t" {
		t.Fatal("namespace deletion removed an account or credential")
	}
	if got := connectorNames(t, g, "research"); len(got) != 4 {
		t.Fatalf("deleting team changed shared research namespace: %v", got)
	}
}

func TestNamespaceProjectsOnlyEnabledCachedToolsAndAllowsEmpty(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue", "save_issue", "delete_issue"},
	})
	g.listTools = func(_ context.Context, a Account) ([]mcp.Tool, error) {
		return []mcp.Tool{
			mcp.NewTool(a.Name+"__get_issue", mcp.WithReadOnlyHintAnnotation(true)),
			mcp.NewTool(a.Name+"__save_issue", mcp.WithReadOnlyHintAnnotation(false)),
			mcp.NewTool(a.Name+"__delete_issue", mcp.WithReadOnlyHintAnnotation(false)),
		}, nil
	}
	ctx := context.Background()
	if err := g.store.SetDisabledTools(ctx, "linear", []string{"save_issue"}); err != nil {
		t.Fatal(err)
	}
	if err := g.store.SetReadOnly(ctx, "linear", true); err != nil {
		t.Fatal(err)
	}
	if err := g.store.SetToolOverride(ctx, "linear", "get_issue", ToolOverride{Alias: "lookup_ticket"}); err != nil {
		t.Fatal(err)
	}
	g.Aggregate(ctx)

	if _, err := g.CreateNamespace(ctx, Namespace{Slug: "empty", Label: "Empty"}); err != nil {
		t.Fatalf("create empty namespace: %v", err)
	}
	if got := connectorNames(t, g, "empty"); len(got) != 0 {
		t.Fatalf("empty namespace tools = %v", got)
	}
	if _, err := g.CreateNamespace(ctx, Namespace{
		Slug: "readonly", Label: "Read only", Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("create policy namespace: %v", err)
	}
	if got := connectorNames(t, g, "readonly"); !sameStrings(got, []string{"linear__lookup_ticket"}) {
		t.Fatalf("namespace ignored account curation policy: %v", got)
	}
}

func TestNamespaceReplayFailsAfterAccountDetach(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{"linear": {"get_issue"}})
	ctx := context.Background()
	g.Aggregate(ctx)
	created, err := g.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team", Accounts: []string{"linear"},
	})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	store := g.store.(*FileStore)
	g.SetAudit(store)
	store.LogCall(CallRecord{
		Account: "linear", Tool: "get_issue", Connector: "team", Args: `{}`, OK: true,
		EndpointKind: endpointKindNamespace, EndpointGeneration: created.Epoch,
	})
	rows, err := store.RecentCalls(ctx, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows = %+v, err=%v", rows, err)
	}
	if _, err := g.RemoveNamespaceAccount(ctx, "team", "linear", preconditionOf(created)); err != nil {
		t.Fatalf("detach account: %v", err)
	}
	if _, err := g.Replay(ctx, rows[0].ID, true); err == nil ||
		!strings.Contains(err.Error(), `namespace "team" no longer includes account "linear"`) {
		t.Fatalf("replay after namespace detach = %v, want membership error", err)
	}
}

func TestNamespaceEndpointEpochLifecycle(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue"},
		"notion": {"search"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)
	var revoked []string
	g.SetTokenRevoker(func(resource string) { revoked = append(revoked, resource) })

	created, err := g.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team", Accounts: []string{"linear"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	epoch, ok := g.ConnectorEpoch("team")
	if !ok || epoch == "" || epoch != created.Epoch {
		t.Fatalf("live epoch = %q, ok=%v, namespace=%q", epoch, ok, created.Epoch)
	}
	handlerBefore, ok := g.ConnectorHandler("team")
	if !ok {
		t.Fatal("namespace handler missing after create")
	}
	updated, err := g.AddNamespaceAccount(ctx, "team", "notion", preconditionOf(created))
	if err != nil {
		t.Fatalf("expand membership: %v", err)
	}
	if updated.Epoch != epoch {
		t.Fatalf("membership update rotated stable endpoint epoch: %q -> %q", epoch, updated.Epoch)
	}
	handlerAfter, ok := g.ConnectorHandler("team")
	if !ok || handlerBefore != handlerAfter {
		t.Fatal("membership update replaced the stable live namespace handler")
	}

	if err := g.DeleteNamespace(ctx, "team", preconditionOf(updated)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := g.ConnectorEpoch("team"); ok {
		t.Fatal("deleted namespace still resolves an OAuth epoch")
	}
	if len(revoked) != 1 || revoked[0] != "/mcp/team" {
		t.Fatalf("namespace delete revocations = %v", revoked)
	}
	recreated, err := g.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team again", Accounts: []string{"linear"},
	})
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if recreated.Epoch == epoch {
		t.Fatal("recreated namespace reused the deleted endpoint epoch")
	}
}

func TestNamespaceGenerationPreconditionsRejectRecreateAndCrossKindReuse(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue"},
		"notion": {"search"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)

	old, err := g.CreateNamespace(ctx, Namespace{
		Slug: "shared", Label: "Original", Accounts: []string{"linear"},
	})
	if err != nil {
		t.Fatalf("create original: %v", err)
	}
	stale := preconditionOf(old)
	if err := g.DeleteNamespace(ctx, "shared", stale); err != nil {
		t.Fatalf("delete original: %v", err)
	}
	current, err := g.CreateNamespace(ctx, Namespace{
		Slug: "shared", Label: "Recreated", Accounts: []string{"notion"},
	})
	if err != nil {
		t.Fatalf("recreate namespace: %v", err)
	}
	if current.Revision != stale.Revision || current.Epoch == stale.Generation {
		t.Fatalf("test requires revision reset with new generation: old=%+v new=%+v", old, current)
	}

	if _, err := g.UpdateNamespace(ctx, Namespace{
		Slug: "shared", Label: "stale update", Accounts: []string{"linear"},
	}, stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale full update = %v, want ErrNamespaceRevision", err)
	}
	if _, err := g.AddNamespaceAccount(ctx, "shared", "linear", stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale membership add = %v, want ErrNamespaceRevision", err)
	}
	if _, err := g.RemoveNamespaceAccount(ctx, "shared", "notion", stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale membership removal = %v, want ErrNamespaceRevision", err)
	}
	if err := g.DeleteNamespace(ctx, "shared", stale); !errors.Is(err, ErrNamespaceRevision) {
		t.Fatalf("stale namespace delete = %v, want ErrNamespaceRevision", err)
	}
	stored, _ := g.store.(NamespaceStore).Namespace(ctx, "shared")
	if stored.Label != "Recreated" || !sameStrings(stored.Accounts, []string{"notion"}) ||
		stored.Epoch != current.Epoch || stored.Revision != current.Revision {
		t.Fatalf("stale mutations changed recreated namespace: %+v", stored)
	}

	if err := g.DeleteNamespace(ctx, "shared", preconditionOf(current)); err != nil {
		t.Fatalf("delete recreated namespace: %v", err)
	}
	if err := g.UpsertConnector(ctx, VirtualConnector{
		Slug: "shared", Label: "Connector reuse", Tools: map[string][]string{"linear": {"get_issue"}},
	}); err != nil {
		t.Fatalf("reuse slug as connector: %v", err)
	}
	connectorEpoch, _ := g.ConnectorEpoch("shared")
	connectorHandler, _ := g.ConnectorHandler("shared")
	if err := g.DeleteNamespace(ctx, "shared", stale); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("stale namespace delete after connector reuse = %v, want ErrNamespaceNotFound", err)
	}
	if epoch, ok := g.ConnectorEpoch("shared"); !ok || epoch != connectorEpoch {
		t.Fatalf("stale namespace delete tore down reused connector epoch: %q ok=%v", epoch, ok)
	}
	if handler, ok := g.ConnectorHandler("shared"); !ok || handler != connectorHandler {
		t.Fatal("stale namespace delete replaced reused connector handler")
	}

	var revoked []string
	g.SetTokenRevoker(func(path string) { revoked = append(revoked, path) })
	g.retireEndpoint("shared", endpointKindNamespace, stale.Generation)
	if _, ok := g.ConnectorHandler("shared"); !ok || len(revoked) != 0 {
		t.Fatalf("generation-mismatched retirement changed live endpoint or OAuth state: revoked=%v", revoked)
	}
}

func TestRefreshConvergesReplicaAfterCrossKindReuse(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"linear": {"get_issue"},
		"notion": {"search"},
	})
	ctx := context.Background()
	g.Aggregate(ctx)
	namespace, err := g.CreateNamespace(ctx, Namespace{
		Slug: "replica", Label: "Namespace", Accounts: []string{"notion"},
	})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	oldHandler, _ := g.ConnectorHandler("replica")

	// Simulate a different Engine replica committing namespace -> connector
	// reuse directly through the shared durable store.
	namespaces := g.store.(NamespaceStore)
	connectors := g.store.(ConnectorStore)
	if err := namespaces.DeleteNamespace(ctx, "replica", preconditionOf(namespace)); err != nil {
		t.Fatalf("external namespace delete: %v", err)
	}
	if err := connectors.UpsertConnector(ctx, VirtualConnector{
		Slug: "replica", Label: "Connector", Epoch: "connector-generation",
		Tools: map[string][]string{"linear": {"get_issue"}},
	}); err != nil {
		t.Fatalf("external connector create: %v", err)
	}
	g.RefreshConnectors(ctx)
	newHandler, ok := g.ConnectorHandler("replica")
	if !ok || newHandler == oldHandler {
		t.Fatal("refresh did not replace the stale namespace server")
	}
	if generation, _ := g.ConnectorEpoch("replica"); generation != "connector-generation" {
		t.Fatalf("refresh projected generation %q, want connector-generation", generation)
	}
	g.mu.Lock()
	kind := g.connectors["replica"].kind
	g.mu.Unlock()
	if kind != endpointKindConnector {
		t.Fatalf("refresh projected kind %q, want connector", kind)
	}
	if err := g.DeleteNamespace(ctx, "replica", preconditionOf(namespace)); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("stale local namespace delete = %v, want ErrNamespaceNotFound", err)
	}
	if handler, ok := g.ConnectorHandler("replica"); !ok || handler != newHandler {
		t.Fatal("stale delete tore down the cross-kind reused endpoint")
	}

	// And the inverse connector -> namespace transition converges in one
	// refresh while a stale connector delete fails closed.
	if err := connectors.DeleteConnector(ctx, "replica", "connector-generation"); err != nil {
		t.Fatalf("external connector delete: %v", err)
	}
	if err := namespaces.CreateNamespace(ctx, Namespace{
		Slug: "replica", Label: "Namespace again", Epoch: "namespace-generation",
		Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("external namespace create: %v", err)
	}
	g.RefreshConnectors(ctx)
	if generation, _ := g.ConnectorEpoch("replica"); generation != "namespace-generation" {
		t.Fatalf("inverse refresh projected generation %q, want namespace-generation", generation)
	}
	if err := g.DeleteConnector(ctx, "replica"); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("stale local connector delete = %v, want ErrConnectorNotFound", err)
	}
	g.mu.Lock()
	kind = g.connectors["replica"].kind
	g.mu.Unlock()
	if kind != endpointKindNamespace {
		t.Fatalf("stale connector delete changed live kind to %q", kind)
	}
}

func TestNamespaceAPIContractCollisionsAndIdempotency(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{
		"linear":          {"get_issue", "save_issue"},
		"notion_work":     {"search"},
		"notion_personal": {"search"},
	})

	rec, _ := doJSON(t, mux, "", http.MethodGet, "/api/namespaces", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized GET = %d, want 401", rec.Code)
	}

	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/namespaces",
		`{"slug":"shared","label":"Shared","members":["linear","notion_work"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST namespace = %d, body %s", rec.Code, rec.Body)
	}
	if got["slug"] != "shared" || got["url"] != "https://engine.example/mcp/shared" ||
		got["exposedTools"] != float64(3) || got["totalTools"] != float64(4) {
		t.Fatalf("created namespace DTO = %v", got)
	}
	if _, present := got["epoch"]; present {
		t.Fatalf("internal OAuth epoch leaked in public DTO: %v", got)
	}
	if _, present := got["key"]; present {
		t.Fatalf("legacy cosmetic namespace key leaked in public DTO: %v", got)
	}
	generation, ok := got["generation"].(string)
	if !ok || generation == "" {
		t.Fatalf("public namespace generation missing: %v", got)
	}
	revision := int64(got["revision"].(float64))

	for _, request := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPut, "/api/namespaces/shared", `{"label":"Missing precondition"}`},
		{http.MethodDelete, "/api/namespaces/shared", ""},
		{http.MethodPut, "/api/namespaces/shared/accounts/notion_personal", ""},
		{http.MethodDelete, "/api/namespaces/shared/accounts/notion_work", ""},
	} {
		rec, _ = doJSON(t, mux, token, request.method, request.path, request.body)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s without precondition = %d, want 409", request.method, request.path, rec.Code)
		}
	}

	rec, got = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared/accounts/notion_personal",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(revision, 10)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership PUT = %d, body %s", rec.Code, rec.Body)
	}
	addRevision := int64(got["revision"].(float64))
	if addRevision != revision+1 {
		t.Fatalf("membership revision = %d, want %d", addRevision, revision+1)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared/accounts/notion_personal",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(revision, 10)+`}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale membership PUT = %d, want 409", rec.Code)
	}
	rec, got = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared/accounts/notion_personal",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(addRevision, 10)+`}`)
	if rec.Code != http.StatusOK || int64(got["revision"].(float64)) != addRevision {
		t.Fatalf("idempotent membership PUT = %d %v", rec.Code, got)
	}

	rec, got = doJSON(t, mux, token, http.MethodDelete, "/api/namespaces/shared/accounts/notion_personal",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(addRevision, 10)+`}`)
	if rec.Code != http.StatusOK || int64(got["revision"].(float64)) != addRevision+1 {
		t.Fatalf("membership DELETE = %d %v", rec.Code, got)
	}
	removeRevision := int64(got["revision"].(float64))
	rec, got = doJSON(t, mux, token, http.MethodDelete, "/api/namespaces/shared/accounts/notion_personal",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(removeRevision, 10)+`}`)
	if rec.Code != http.StatusOK || int64(got["revision"].(float64)) != removeRevision {
		t.Fatalf("idempotent membership DELETE = %d %v", rec.Code, got)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared/accounts/missing",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(removeRevision, 10)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown account membership = %d, want 400", rec.Code)
	}
	rec, got = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared",
		`{"label":"Renamed","members":["notion_work"],"generation":`+strconv.Quote(generation)+
			`,"revision":`+strconv.FormatInt(removeRevision, 10)+`}`)
	if rec.Code != http.StatusOK || got["label"] != "Renamed" ||
		int64(got["revision"].(float64)) != removeRevision+1 {
		t.Fatalf("revision-checked namespace update = %d %v", rec.Code, got)
	}
	updateRevision := int64(got["revision"].(float64))
	if names := connectorNames(t, g, "shared"); !sameStrings(names, []string{"notion_work__search"}) {
		t.Fatalf("live tools after namespace update = %v", names)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared",
		`{"label":"Must Roll Back","members":["missing"],"generation":`+strconv.Quote(generation)+
			`,"revision":`+strconv.FormatInt(updateRevision, 10)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown-account full update = %d, want 400", rec.Code)
	}
	stored, _ := g.store.(NamespaceStore).Namespace(context.Background(), "shared")
	if stored.Label != "Renamed" || stored.Revision != updateRevision ||
		!sameStrings(stored.Accounts, []string{"notion_work"}) {
		t.Fatalf("failed full update mutated namespace: %+v", stored)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared",
		`{"label":"Renamed","members":["linear"],"generation":`+strconv.Quote(generation)+`,"revision":1}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale namespace update = %d, want 409", rec.Code)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPut, "/api/namespaces/shared",
		`{"label":"Wrong generation","members":["linear"],"generation":"recreated","revision":`+
			strconv.FormatInt(updateRevision, 10)+`}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("wrong-generation namespace update = %d, want 409", rec.Code)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/connectors",
		`{"slug":"shared","label":"Conflicting connector","tools":{}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("connector collision = %d, want 409", rec.Code)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/connectors",
		`{"slug":"legacy","label":"Legacy","tools":{}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create legacy connector = %d, body %s", rec.Code, rec.Body)
	}
	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/namespaces",
		`{"slug":"legacy","label":"Conflicting namespace","members":[]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("namespace collision = %d, want 409", rec.Code)
	}

	rec, _ = doJSON(t, mux, token, http.MethodDelete, "/api/namespaces/shared",
		`{"generation":"stale-generation","revision":`+strconv.FormatInt(updateRevision, 10)+`}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale-generation namespace DELETE = %d, want 409", rec.Code)
	}
	rec, _ = doJSON(t, mux, token, http.MethodDelete, "/api/namespaces/shared",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(updateRevision, 10)+`}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE namespace = %d, body %s", rec.Code, rec.Body)
	}
	if _, ok := g.ConnectorHandler("shared"); ok {
		t.Fatal("deleted API namespace is still served")
	}
	if _, ok := g.store.Account("linear"); !ok || g.store.Token("linear") != "t" {
		t.Fatal("API namespace deletion removed account credentials")
	}
	g.mu.Lock()
	rootLinear := append([]string(nil), g.byAcct["linear"]...)
	g.mu.Unlock()
	if len(rootLinear) != 2 {
		t.Fatalf("API namespace deletion changed root /mcp: %v", rootLinear)
	}
}

func TestEndpointAPIAliasesShareAuthorizationStateAndCAS(t *testing.T) {
	mux, token, _ := newConnectorConsole(t, map[string][]string{
		"tegence_notion":  {"search"},
		"personal_notion": {"search"},
	})

	for _, path := range []string{"/api/endpoints", "/api/namespaces"} {
		rec, _ := doJSON(t, mux, "", http.MethodGet, path, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized GET %s = %d, want 401", path, rec.Code)
		}
	}

	rec, created := doJSON(t, mux, token, http.MethodPost, "/api/endpoints",
		`{"slug":"notion-access","label":"Notion access","members":["tegence_notion"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST preferred endpoint = %d, body %s", rec.Code, rec.Body)
	}
	generation := created["generation"].(string)
	revision := int64(created["revision"].(float64))

	preferredGET, _ := doJSON(t, mux, token, http.MethodGet, "/api/endpoints/notion_access", "")
	legacyGET, _ := doJSON(t, mux, token, http.MethodGet, "/api/namespaces/notion_access", "")
	if preferredGET.Code != http.StatusOK || legacyGET.Code != http.StatusOK ||
		preferredGET.Body.String() != legacyGET.Body.String() {
		t.Fatalf("route GET parity = preferred %d %s, legacy %d %s",
			preferredGET.Code, preferredGET.Body, legacyGET.Code, legacyGET.Body)
	}

	rec, updated := doJSON(t, mux, token, http.MethodPut,
		"/api/endpoints/notion_access/accounts/personal_notion",
		`{"generation":`+strconv.Quote(generation)+`,"revision":`+strconv.FormatInt(revision, 10)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("preferred membership PUT = %d, body %s", rec.Code, rec.Body)
	}
	currentRevision := int64(updated["revision"].(float64))
	members, membersOK := updated["members"].([]any)
	if !membersOK || len(members) != 2 ||
		members[0] != "personal_notion" || members[1] != "tegence_notion" {
		t.Fatalf("preferred membership update = %v", updated)
	}

	// A stale CAS precondition must fail identically through both names and
	// leave the shared endpoint-bundle row untouched.
	staleBody := `{"label":"Stale","generation":` + strconv.Quote(generation) +
		`,"revision":` + strconv.FormatInt(revision, 10) + `}`
	preferredStale, _ := doJSON(t, mux, token, http.MethodPut, "/api/endpoints/notion_access", staleBody)
	legacyStale, _ := doJSON(t, mux, token, http.MethodPut, "/api/namespaces/notion_access", staleBody)
	if preferredStale.Code != http.StatusConflict || legacyStale.Code != http.StatusConflict ||
		preferredStale.Body.String() != legacyStale.Body.String() {
		t.Fatalf("route CAS parity = preferred %d %s, legacy %d %s",
			preferredStale.Code, preferredStale.Body, legacyStale.Code, legacyStale.Body)
	}

	deleteBody := `{"generation":` + strconv.Quote(generation) +
		`,"revision":` + strconv.FormatInt(currentRevision, 10) + `}`
	rec, _ = doJSON(t, mux, token, http.MethodDelete, "/api/endpoints/notion_access", deleteBody)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preferred endpoint DELETE = %d, body %s", rec.Code, rec.Body)
	}
	preferredMissing, _ := doJSON(t, mux, token, http.MethodGet, "/api/endpoints/notion_access", "")
	legacyMissing, _ := doJSON(t, mux, token, http.MethodGet, "/api/namespaces/notion_access", "")
	if preferredMissing.Code != http.StatusNotFound || legacyMissing.Code != http.StatusNotFound ||
		preferredMissing.Body.String() != legacyMissing.Body.String() {
		t.Fatalf("route post-delete parity = preferred %d %s, legacy %d %s",
			preferredMissing.Code, preferredMissing.Body, legacyMissing.Code, legacyMissing.Body)
	}
}

func TestNamespaceAPI501WithoutNamespaceStore(t *testing.T) {
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	accountStore := accountsOnly{store}
	gateway := NewGateway(accountStore, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	api := NewConsoleAPI(accountStore, gateway, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)
	token := api.signToken()
	for _, request := range []struct{ method, path string }{
		{http.MethodGet, "/api/endpoints"},
		{http.MethodPost, "/api/endpoints"},
		{http.MethodGet, "/api/endpoints/team"},
		{http.MethodPut, "/api/endpoints/team"},
		{http.MethodDelete, "/api/endpoints/team"},
		{http.MethodPut, "/api/endpoints/team/accounts/linear"},
		{http.MethodDelete, "/api/endpoints/team/accounts/linear"},
		{http.MethodGet, "/api/namespaces"},
		{http.MethodPost, "/api/namespaces"},
		{http.MethodGet, "/api/namespaces/team"},
		{http.MethodPut, "/api/namespaces/team"},
		{http.MethodDelete, "/api/namespaces/team"},
		{http.MethodPut, "/api/namespaces/team/accounts/linear"},
		{http.MethodDelete, "/api/namespaces/team/accounts/linear"},
	} {
		rec, got := doJSON(t, mux, token, request.method, request.path, `{}`)
		if rec.Code != http.StatusNotImplemented || got["error"] != "namespaces not supported by this store" {
			t.Errorf("%s %s = %d %v, want 501", request.method, request.path, rec.Code, got)
		}
	}
}

func TestPortableConfigImportsNamespacesWithoutSecrets(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{})
	payload := `{
	  "version":1,
	  "accounts":[
	    {"name":"linear","displayName":"Linear","url":"https://linear.example/mcp","readOnly":true},
	    {"name":"notion_work","displayName":"Notion Work","url":"https://notion.example/mcp","readOnly":false}
	  ],
	  "connectors":[],
	  "namespaces":[
	    {"slug":"research","label":"Research","members":["linear","notion_work"]}
	  ]
	}`
	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/config/import", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("namespace import = %d, body %s", rec.Code, rec.Body)
	}
	if got["namespacesImported"] != float64(1) {
		t.Fatalf("namespace import result = %v", got)
	}
	store := g.store.(NamespaceStore)
	ns, ok := store.Namespace(context.Background(), "research")
	if !ok || !sameStrings(ns.Accounts, []string{"linear", "notion_work"}) || ns.Epoch == "" {
		t.Fatalf("imported namespace = %+v, ok=%v", ns, ok)
	}
	if g.store.Token("linear") != "" || g.store.RefreshToken("linear") != "" {
		t.Fatal("portable namespace import created credentials")
	}

	rec, _ = doJSON(t, mux, token, http.MethodGet, "/api/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("namespace export = %d, body %s", rec.Code, rec.Body)
	}
	var exported portableConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if len(exported.Namespaces) != 1 ||
		!sameStrings(exported.Namespaces[0].Members, []string{"linear", "notion_work"}) {
		t.Fatalf("exported namespaces = %+v", exported.Namespaces)
	}
	if string(rec.Body.Bytes()) == "" || json.Valid(rec.Body.Bytes()) == false {
		t.Fatal("portable namespace export is not valid JSON")
	}
}

// TestPortableConfigImportRejectsReservedSlug guards the third creation path:
// /api/connectors and /api/endpoints already reject the reserved "clients"
// slug (see TestReservedEndpointSlugRejected), but config import reaches the
// same Gateway.CreateNamespace/UpsertConnector calls through a different
// handler and must reject it too, or an admin could bypass the other two
// endpoints by importing a config with "slug":"clients" and reintroduce the
// /mcp/clients routing collision.
func TestPortableConfigImportRejectsReservedSlug(t *testing.T) {
	mux, token, g := newConnectorConsole(t, map[string][]string{
		"linear": {"get_issue"},
	})
	ctx := context.Background()

	namespacePayload := `{
	  "version":1,
	  "accounts":[
	    {"name":"notion_work","displayName":"Notion Work","url":"https://notion.example/mcp","readOnly":false}
	  ],
	  "connectors":[],
	  "namespaces":[
	    {"slug":"clients","label":"Clients","members":["linear"]}
	  ]
	}`
	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/config/import", namespacePayload)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || msg != "that slug is reserved" {
		t.Fatalf("namespace import with reserved slug = %d %v, want 400 reserved", rec.Code, got)
	}
	nsStore := g.store.(NamespaceStore)
	if _, ok := nsStore.Namespace(ctx, "clients"); ok {
		t.Fatal("reserved-slug namespace import must not create the namespace")
	}
	// The reserved slug is caught in the pre-validation pass, before the apply
	// loop runs, so nothing else in the same payload should be applied either.
	if _, ok := g.store.Account("notion_work"); ok {
		t.Fatal("rejected reserved-slug import must not apply other resources in the same payload")
	}

	connectorPayload := `{
	  "version":1,
	  "accounts":[],
	  "connectors":[
	    {"slug":"clients","label":"Clients","tools":{"linear":["get_issue"]}}
	  ],
	  "namespaces":[]
	}`
	rec, got = doJSON(t, mux, token, http.MethodPost, "/api/config/import", connectorPayload)
	if msg, _ := got["error"].(string); rec.Code != http.StatusBadRequest || msg != "that slug is reserved" {
		t.Fatalf("connector import with reserved slug = %d %v, want 400 reserved", rec.Code, got)
	}
	connectorStore := g.store.(ConnectorStore)
	if _, ok := connectorStore.VirtualConnector(ctx, "clients"); ok {
		t.Fatal("reserved-slug connector import must not create the connector")
	}
}

func TestAccountCreatePrefersToolPrefixAndRejectsConflictingLegacyAlias(t *testing.T) {
	mux, token, _ := newConnectorConsole(t, map[string][]string{})
	rec, got := doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Notion Work","toolPrefix":"notion_work","url":"https://notion.example/mcp"}`)
	if rec.Code != http.StatusCreated || got["toolPrefix"] != "notion_work" ||
		got["namespace"] != "notion_work" || got["name"] != "notion_work" {
		t.Fatalf("preferred toolPrefix create = %d %v", rec.Code, got)
	}

	rec, got = doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Linear","toolPrefix":"Linear Team","namespace":"linear_team","url":"https://linear.example/mcp"}`)
	if rec.Code != http.StatusCreated || got["toolPrefix"] != "linear_team" {
		t.Fatalf("equivalent aliases create = %d %v", rec.Code, got)
	}

	rec, _ = doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Conflict","toolPrefix":"preferred","namespace":"different","url":"https://example.com/mcp"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflicting toolPrefix/namespace = %d, want 400", rec.Code)
	}

	rec, got = doJSON(t, mux, token, http.MethodPost, "/api/servers",
		`{"name":"Duplicate","toolPrefix":"notion_work","url":"https://notion.example/mcp"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate tool prefix = %d, want 409", rec.Code)
	}
	if got["error"] != `tool prefix "notion_work" already exists; choose a unique toolPrefix` {
		t.Fatalf("duplicate tool prefix error = %v", got)
	}
}
