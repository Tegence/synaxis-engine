package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type bootstrapAccountStore struct{ AccountStore }

type bootstrapLibraryStore struct {
	AccountStore
	LibraryStore
}

func mcpInitializeResult(t *testing.T, mcpServer *server.MCPServer) mcp.InitializeResult {
	t.Helper()
	request, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "bootstrap-test", "version": "1.0.0"},
		},
	})
	if err != nil {
		t.Fatalf("marshal initialize request: %v", err)
	}
	rawResponse := mcpServer.HandleMessage(context.Background(), request)
	response, ok := rawResponse.(mcp.JSONRPCResponse)
	if !ok {
		t.Fatalf("initialize response type = %T, want mcp.JSONRPCResponse", rawResponse)
	}
	result, ok := response.Result.(mcp.InitializeResult)
	if !ok {
		t.Fatalf("initialize result type = %T, want mcp.InitializeResult", response.Result)
	}
	return result
}

func TestMCPBootstrapInitializeIsSurfaceSpecific(t *testing.T) {
	ctx := context.Background()
	gateway := newConnectorTestGateway(t, map[string][]string{"linear": {"search"}})
	if got := gateway.Aggregate(ctx); got != 1 {
		t.Fatalf("aggregate = %d, want 1", got)
	}
	if err := gateway.UpsertConnector(ctx, VirtualConnector{
		Slug: "curated", Tools: map[string][]string{"linear": {"search"}},
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	if _, err := gateway.CreateNamespace(ctx, Namespace{
		Slug: "bundle", Accounts: []string{"linear"},
	}); err != nil {
		t.Fatalf("create endpoint bundle: %v", err)
	}
	store, ok := gateway.store.(*FileStore)
	if !ok {
		t.Fatalf("gateway store type = %T, want *FileStore", gateway.store)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Bootstrap client", Subject: "usr_bootstrap_private", CreatedBy: "usr_bootstrap_private",
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatalf("refresh MCP clients: %v", err)
	}

	root := NewRootMCPServer()
	RegisterLibraryArtifactTools(root, store, nil)

	gateway.mu.Lock()
	connector := gateway.connectors["curated"].mcp
	bundle := gateway.connectors["bundle"].mcp
	subjectClient := gateway.clientEndpoints[client.Slug].mcp
	gateway.mu.Unlock()

	tests := []struct {
		name        string
		server      *server.MCPServer
		surface     mcpBootstrapSurface
		features    mcpBootstrapFeatures
		serverName  string
		mustMention []string
		mustOmit    []string
	}{
		{
			name: "root", server: root, surface: mcpBootstrapSurfaceRoot, serverName: "synaxis-engine",
			mustMention: []string{"root aggregate", "library_skill_list", "library_skill_read", "library_skill_resolve"},
			mustOmit:    []string{"library_skill_activation", "library_memory_recall", "library_memory_read", "library_memory_propose"},
		},
		{
			name: "connector", server: connector, surface: mcpBootstrapSurfaceConnector, serverName: "narthex-curated",
			mustMention: []string{"governed virtual connector", "approval", "guardrails"},
			mustOmit:    []string{"library_skill_activation", "library_memory_recall", "library_memory_read", "library_memory_propose", "linear__search"},
		},
		{
			name: "bundle", server: bundle, surface: mcpBootstrapSurfaceBundle, serverName: "narthex-bundle",
			mustMention: []string{"endpoint bundle", "member connections"},
			mustOmit:    []string{"library_skill_activation", "library_memory_recall", "library_memory_read", "library_memory_propose", "linear__search"},
		},
		{
			name: "client", server: subjectClient, surface: mcpBootstrapSurfaceClient,
			features: mcpBootstrapFeatures{library: true, memory: true}, serverName: "narthex-client-" + client.Slug,
			mustMention: []string{"subject-bound MCP client", "first-party Library tools", "library_skill_activation", "with no arguments", "library_memory_recall", "library_memory_read", "library_memory_propose", "human review"},
			mustOmit:    []string{"usr_bootstrap_private", client.Slug},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mcpInitializeResult(t, test.server)
			if result.Instructions != mcpBootstrapInstructions(test.surface, test.features) {
				t.Fatalf("instructions mismatch:\n%s", result.Instructions)
			}
			if result.ServerInfo.Name != test.serverName {
				t.Fatalf("server name = %q, want %q", result.ServerInfo.Name, test.serverName)
			}
			if result.ServerInfo.Description != mcpBootstrapDescription(test.surface) {
				t.Fatalf("server description = %q, want %q", result.ServerInfo.Description, mcpBootstrapDescription(test.surface))
			}
			if result.Capabilities.Tools == nil || !result.Capabilities.Tools.ListChanged {
				t.Fatalf("tools capability = %+v, want listChanged", result.Capabilities.Tools)
			}
			for _, phrase := range []string{"host's current tools/list response", "exact authoritative inventory", "may still be denied", "action-time policy", "Neither grants credentials", "Verify current facts"} {
				if !strings.Contains(result.Instructions, phrase) {
					t.Errorf("instructions missing common contract phrase %q: %s", phrase, result.Instructions)
				}
			}
			for _, phrase := range test.mustMention {
				if !strings.Contains(result.Instructions, phrase) {
					t.Errorf("instructions missing %q: %s", phrase, result.Instructions)
				}
			}
			for _, phrase := range test.mustOmit {
				if strings.Contains(result.Instructions, phrase) {
					t.Errorf("instructions unexpectedly contain %q: %s", phrase, result.Instructions)
				}
			}
		})
	}

	for _, name := range []string{"library_skill_list", "library_skill_read", "library_skill_resolve"} {
		if root.GetTool(name) == nil {
			t.Errorf("root bootstrap names %q but tools/list omits it", name)
		}
	}
	for _, name := range []string{"library_skill_activation", "library_memory_recall", "library_memory_read", "library_memory_propose"} {
		if subjectClient.GetTool(name) == nil {
			t.Errorf("client bootstrap names %q but tools/list omits it", name)
		}
	}
}

func TestMCPClientBootstrapOmitsUnavailableLibraryFacets(t *testing.T) {
	plain := newSynaxisMCPServer("synaxis-client-plain", mcpBootstrapSurfaceClient, mcpBootstrapFeatures{})
	instructions := mcpInitializeResult(t, plain).Instructions
	for _, name := range []string{"library_skill_activation", "library_memory_recall", "library_memory_read", "library_memory_propose"} {
		if strings.Contains(instructions, name) {
			t.Fatalf("bootstrap advertises unavailable tool %q: %s", name, instructions)
		}
	}
	if strings.Contains(instructions, "first-party Library tools") {
		t.Fatalf("bootstrap claims unavailable Library tools: %s", instructions)
	}
	if !strings.Contains(instructions, "tools/list") || !strings.Contains(instructions, "subject-bound MCP client") {
		t.Fatalf("plain client lost its basic bootstrap contract: %s", instructions)
	}
}

func TestMCPBootstrapUnknownSurfaceFallsBackSafely(t *testing.T) {
	const unknown mcpBootstrapSurface = "future-surface"
	result := mcpInitializeResult(t, newSynaxisMCPServer("synaxis-future", unknown, mcpBootstrapFeatures{}))
	if result.Instructions != mcpBootstrapInstructions(unknown, mcpBootstrapFeatures{}) {
		t.Fatalf("unknown-surface instructions mismatch:\n%s", result.Instructions)
	}
	for _, phrase := range []string{"Synaxis MCP endpoint", "current tools/list response"} {
		if !strings.Contains(result.Instructions, phrase) {
			t.Errorf("unknown-surface bootstrap missing %q: %s", phrase, result.Instructions)
		}
	}
	if result.ServerInfo.Description != "Synaxis Engine governed MCP surface." {
		t.Errorf("unknown-surface description = %q", result.ServerInfo.Description)
	}
}

func TestMCPClientBootstrapMatchesAvailableStoreFacets(t *testing.T) {
	store, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(context.Background(), MCPClient{
		Name: "Facet client", Subject: "usr_facet", CreatedBy: "usr_facet",
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		store    AccountStore
		features mcpBootstrapFeatures
	}{
		{name: "account store only", store: bootstrapAccountStore{AccountStore: store}},
		{
			name: "Library without memory", store: bootstrapLibraryStore{AccountStore: store, LibraryStore: store},
			features: mcpBootstrapFeatures{library: true},
		},
		{name: "Library with memory", store: store, features: mcpBootstrapFeatures{library: true, memory: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gateway := NewGateway(test.store, NewRootMCPServer())
			if err := gateway.buildMCPClient(client); err != nil {
				t.Fatalf("build MCP client: %v", err)
			}
			gateway.mu.Lock()
			clientServer := gateway.clientEndpoints[client.Slug].mcp
			gateway.mu.Unlock()

			instructions := mcpInitializeResult(t, clientServer).Instructions
			if instructions != mcpBootstrapInstructions(mcpBootstrapSurfaceClient, test.features) {
				t.Fatalf("instructions do not match available facets:\n%s", instructions)
			}
			for _, name := range []string{"library_skill_activation"} {
				if advertised := clientServer.GetTool(name) != nil; advertised != test.features.library {
					t.Errorf("tool %q advertised = %v, want %v", name, advertised, test.features.library)
				}
				if mentioned := strings.Contains(instructions, name); mentioned != test.features.library {
					t.Errorf("bootstrap mentions %q = %v, want %v", name, mentioned, test.features.library)
				}
			}
			for _, name := range []string{"library_memory_recall", "library_memory_read", "library_memory_propose"} {
				if advertised := clientServer.GetTool(name) != nil; advertised != test.features.memory {
					t.Errorf("tool %q advertised = %v, want %v", name, advertised, test.features.memory)
				}
				if mentioned := strings.Contains(instructions, name); mentioned != test.features.memory {
					t.Errorf("bootstrap mentions %q = %v, want %v", name, mentioned, test.features.memory)
				}
			}
		})
	}
}

func TestMCPBootstrapSurvivesDynamicProjectionRebuild(t *testing.T) {
	tools := map[string][]string{"linear": {"old_tool"}}
	gateway := newConnectorTestGateway(t, tools)
	ctx := context.Background()
	gateway.Aggregate(ctx)
	if err := gateway.UpsertConnector(ctx, VirtualConnector{
		Slug: "stable", Tools: map[string][]string{"linear": {"old_tool", "new_tool"}},
	}); err != nil {
		t.Fatal(err)
	}
	gateway.mu.Lock()
	beforeServer := gateway.connectors["stable"].mcp
	gateway.mu.Unlock()
	before := mcpInitializeResult(t, beforeServer).Instructions

	tools["linear"] = []string{"new_tool"}
	if _, err := gateway.ReplaceAccount(ctx, "linear"); err != nil {
		t.Fatal(err)
	}
	gateway.mu.Lock()
	afterServer := gateway.connectors["stable"].mcp
	gateway.mu.Unlock()
	after := mcpInitializeResult(t, afterServer).Instructions
	if beforeServer != afterServer || before != after {
		t.Fatal("projection rebuild changed the stable server or its bootstrap contract")
	}
	for _, staleOrDynamic := range []string{"linear__old_tool", "linear__new_tool"} {
		if strings.Contains(after, staleOrDynamic) {
			t.Fatalf("bootstrap snapshots dynamic tool name %q: %s", staleOrDynamic, after)
		}
	}
}

func TestLibraryToolMetadataRepeatsBootstrapTrustBoundary(t *testing.T) {
	store, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(context.Background(), MCPClient{
		Name: "Metadata client", Subject: "usr_metadata", CreatedBy: "usr_metadata",
	})
	if err != nil {
		t.Fatal(err)
	}
	clientServer := newSynaxisMCPServer("synaxis-client-metadata", mcpBootstrapSurfaceClient, mcpBootstrapFeatures{library: true, memory: true})
	registerMCPClientLibraryTools(clientServer, store, nil, client, func(context.Context) bool { return true })
	rootServer := NewRootMCPServer()
	RegisterLibraryArtifactTools(rootServer, store, nil)

	descriptionChecks := map[string][]string{
		"library_skill_read":       {"context only", "grant no"},
		"library_skill_resolve":    {"context only", "grant no authority"},
		"library_skill_activation": {"no arguments", "task start", "grant credentials"},
		"library_memory_recall":    {"untrusted context", "authoritative source"},
		"library_memory_read":      {"untrusted context", "verified"},
	}
	for name, phrases := range descriptionChecks {
		tool := clientServer.GetTool(name)
		if tool == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		for _, phrase := range phrases {
			if !strings.Contains(tool.Tool.Description, phrase) {
				t.Errorf("%s description missing %q: %s", name, phrase, tool.Tool.Description)
			}
		}
	}
	rootResolve := rootServer.GetTool("library_skill_resolve")
	if rootResolve == nil {
		t.Fatal("root library_skill_resolve was not registered")
	}
	for _, phrase := range []string{"independently trusts", "never credentials or access", "grants no permissions", "authority"} {
		if !strings.Contains(rootResolve.Tool.Description, phrase) {
			t.Errorf("root library_skill_resolve description missing %q: %s", phrase, rootResolve.Tool.Description)
		}
	}
	rootInputSchema := rootResolve.Tool.RawInputSchema
	if len(rootInputSchema) == 0 {
		t.Fatal("root library_skill_resolve input schema is empty")
	}
	for _, phrase := range []string{
		"Optional explicit Library binding ID from independently trusted host context; overrides scope fields and grants no access",
		"Opaque folder context independently trusted by the host; not a credential or access selector",
		"Opaque repository context independently trusted by the host; not a credential or access selector",
		"Opaque generic namespace context independently trusted by the host; not a credential namespace or access selector",
		"Opaque workspace context independently trusted by the host; not a credential or access selector",
	} {
		if !strings.Contains(string(rootInputSchema), phrase) {
			t.Errorf("root library_skill_resolve input schema missing %q: %s", phrase, rootInputSchema)
		}
	}

	for name, phrases := range map[string][]string{
		"library_skill_activation": {
			"Version of the deterministic context-bundle contract",
			"Verified opaque MCP-client surface for this context bundle; not a credential",
			"Selected immutable procedural context; never an authority grant",
			"SHA-256 digest of the canonical bundle content",
			"Mandatory context-only and non-authority notice",
			"Checks the external host must perform before using this context or taking action",
			"Authored capability intent constraint; never an effective grant",
			"Binding capability ceiling constraint; never an effective grant",
		},
		"library_memory_recall": {
			"Provenance and review label; not authorization or factual certainty",
			"Governance lifecycle state; not factual certainty",
			"Visibility mode for this exact version; not a permission grant",
			"Mandatory context-only and non-authority notice",
		},
		"library_memory_read": {
			"Provenance and review label; not authorization or factual certainty",
			"Governance lifecycle state; not factual certainty",
			"Visibility mode for this exact version; not a permission grant",
			"Mandatory context-only and non-authority notice",
		},
	} {
		tool := clientServer.GetTool(name)
		schema, err := json.Marshal(tool.Tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal %s output schema: %v", name, err)
		}
		for _, phrase := range phrases {
			if !strings.Contains(string(schema), phrase) {
				t.Errorf("%s output schema missing %q: %s", name, phrase, schema)
			}
		}
	}
}
