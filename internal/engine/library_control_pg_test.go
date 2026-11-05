package engine

import (
	"context"
	"os"
	"testing"
)

func TestPgLibraryControlArtifactExactGrantProjection(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL Library projection tests")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var fixture libraryControlArtifactFixture
	t.Cleanup(func() {
		for _, id := range fixture.artifactIDs() {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifact_grants WHERE artifact_id=$1`, id)
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, id)
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifacts WHERE id=$1`, id)
		}
		for _, id := range fixture.runIDs {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_runs WHERE id=$1`, id)
		}
		_ = cleanupPgBuiltInLibraryTestRows(ctx, store, fixture.clientIDs()...)
		for _, id := range fixture.clientIDs() {
			_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, id)
		}
	})
	buildLibraryControlArtifactFixture(t, ctx, store, &fixture, newPgFixtureSuffix())
	exerciseLibraryControlArtifactStore(t, ctx, store, &fixture)
}
