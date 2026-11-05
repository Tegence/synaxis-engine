package engine

import (
	"context"
	"os"
	"testing"
)

func TestPgMCPClientLibraryProjectionPersists(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for Postgres contract")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	suffix := newPgFixtureSuffix()
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Projection " + suffix, Subject: "agt_projection_" + suffix, Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID) }()
	if client.LibraryProjection != "" {
		t.Fatalf("new client projection=%q; want the full default", client.LibraryProjection)
	}
	reduced := setLibraryProjectionForTest(t, store, client, LibraryProjectionPrivateOutputs)
	if reduced.LibraryProjection != LibraryProjectionPrivateOutputs || reduced.Epoch == client.Epoch || reduced.Revision != client.Revision+1 {
		t.Fatalf("projection change=%+v; want persisted with a new epoch", reduced)
	}
	same := setLibraryProjectionForTest(t, store, reduced, LibraryProjectionPrivateOutputs)
	if same.Revision != reduced.Revision || same.Epoch != reduced.Epoch {
		t.Fatalf("unchanged projection wrote a revision: %+v", same)
	}
	renamed, err := store.UpdateMCPClient(ctx, MCPClient{ID: client.ID, Name: "Renamed " + suffix}, MCPClientPrecondition{ID: client.ID, Revision: same.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.LibraryProjection != LibraryProjectionPrivateOutputs || renamed.Epoch != same.Epoch {
		t.Fatalf("rename changed the projection or epoch: %+v", renamed)
	}
	if _, err := store.UpdateMCPClient(ctx, MCPClient{ID: client.ID, Name: renamed.Name, LibraryProjection: "everything", libraryProjectionSet: true},
		MCPClientPrecondition{ID: client.ID, Revision: renamed.Revision}); err == nil {
		t.Fatal("unknown projection accepted")
	}

	// A second store re-runs the idempotent DDL and reads every query shape.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if loaded, ok := reopened.MCPClient(ctx, client.ID); !ok || loaded.LibraryProjection != LibraryProjectionPrivateOutputs || loaded.Epoch != renamed.Epoch {
		t.Fatalf("reloaded client=%+v ok=%t", loaded, ok)
	}
	if loaded, ok := reopened.MCPClientBySlug(ctx, client.Slug); !ok || loaded.LibraryProjection != LibraryProjectionPrivateOutputs {
		t.Fatalf("reloaded by slug=%+v ok=%t", loaded, ok)
	}
	clients, err := reopened.MCPClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, listed := range clients {
		if listed.ID == client.ID {
			found = listed.LibraryProjection == LibraryProjectionPrivateOutputs
		}
	}
	if !found {
		t.Fatal("listed client lost its projection")
	}
	restored := setLibraryProjectionForTest(t, reopened, renamed, LibraryProjectionFull)
	if restored.LibraryProjection != "" || restored.Epoch == renamed.Epoch {
		t.Fatalf("restoring full=%+v", restored)
	}

	// An unreadable stored value fails closed to the narrower projection.
	if _, err := store.pool.Exec(ctx, `UPDATE narthex_mcp_clients SET library_projection='bogus' WHERE id=$1`, client.ID); err != nil {
		t.Fatal(err)
	}
	if loaded, ok := reopened.MCPClient(ctx, client.ID); !ok || effectiveLibraryProjection(loaded.LibraryProjection) != LibraryProjectionPrivateOutputs {
		t.Fatalf("unreadable projection=%+v", loaded)
	}
}
