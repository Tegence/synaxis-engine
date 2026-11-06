package engine

import (
	"context"
	"strings"
	"testing"
)

// TestPrivateOutputsClientBootstrapOmitsMemory: a client's initialize
// instructions describe the Library tools its projection keeps. A
// private_outputs client is offered no memory tool, so its instructions
// never send an agent to library_memory_*; the endpoint is built once, so
// the instructions follow a later projection change without a rebuild.
func TestPrivateOutputsClientBootstrapOmitsMemory(t *testing.T) {
	store, err := LoadFileStore(t.TempDir() + "/accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(context.Background(), MCPClient{
		Name: "Projection client", Subject: "usr_projection", CreatedBy: "usr_projection",
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(store, NewRootMCPServer())
	memoryTools := []string{"library_memory_recall", "library_memory_read", "library_memory_propose"}
	for _, step := range []struct {
		projection string
		memory     bool
	}{
		{projection: "", memory: true},
		{projection: LibraryProjectionPrivateOutputs, memory: false},
		{projection: LibraryProjectionFull, memory: true},
	} {
		client.LibraryProjection = step.projection
		if err := gateway.buildMCPClient(client, store.Accounts()); err != nil {
			t.Fatalf("build MCP client (%q): %v", step.projection, err)
		}
		gateway.mu.Lock()
		clientServer := gateway.clientEndpoints[client.Slug].mcp
		gateway.mu.Unlock()
		instructions := mcpInitializeResult(t, clientServer).Instructions
		want := mcpBootstrapInstructions(mcpBootstrapSurfaceClient, mcpBootstrapFeatures{library: true, memory: step.memory})
		if instructions != want {
			t.Fatalf("projection %q instructions:\n%s\nwant:\n%s", step.projection, instructions, want)
		}
		for _, name := range memoryTools {
			if advertised := clientServer.GetTool(name) != nil; advertised != step.memory {
				t.Errorf("projection %q: tool %q advertised = %v, want %v", step.projection, name, advertised, step.memory)
			}
			if mentioned := strings.Contains(instructions, name); mentioned != step.memory {
				t.Errorf("projection %q: instructions mention %q = %v, want %v", step.projection, name, mentioned, step.memory)
			}
		}
		if !strings.Contains(instructions, "library_skill_activation") || clientServer.GetTool("library_skill_activation") == nil {
			t.Errorf("projection %q: skill activation is kept and described", step.projection)
		}
	}
}
