package engine

import (
	"context"
	"net/http"
	"os"
	"testing"
)

// The PgStore half of the Library artifact erasure suite. These tests are
// database-gated like the rest of the PgStore integration suite and named to
// match its Pg filter.

func newPgLibraryDeleteStore(t *testing.T) *PgStore {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library artifact erasure tests")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func TestPgControlLibraryArtifactDeleteRemovesVersionsMediaGrantsProvenance(t *testing.T) {
	store := newPgLibraryDeleteStore(t)
	testControlLibraryArtifactDeleteRemoves(t, store, pgLibraryDeleteResidue(store))
}

func TestPgControlLibraryArtifactDeleteServiceOnly(t *testing.T) {
	testControlLibraryArtifactDeleteServiceOnly(t, newPgLibraryDeleteStore(t))
}

func TestPgControlLibraryArtifactDeleteIdempotent(t *testing.T) {
	store := newPgLibraryDeleteStore(t)
	id := testControlLibraryArtifactDeleteIdempotent(t, store)
	var tombstones int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM narthex_library_artifact_tombstones WHERE artifact_id=$1`, id).Scan(&tombstones); err != nil || tombstones != 1 {
		t.Fatalf("tombstones=%d err=%v; want exactly one", tombstones, err)
	}
	// A second Engine replica (a fresh pool over the same database) agrees.
	other := newPgLibraryDeleteStore(t)
	h := newConnectionsTestHarness(t, other)
	if response := h.service(http.MethodDelete, "/control/v1/library/artifacts/"+id, ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete on another replica status=%d body=%s", response.Code, response.Body)
	}
}

// pgLibraryDeleteResidue counts rows the public read methods do not expose.
func pgLibraryDeleteResidue(store *PgStore) libraryDeleteResidue {
	return func(t *testing.T, artifactID string, versionIDs []string, runID string) []string {
		t.Helper()
		ctx := context.Background()
		var leftover []string
		for name, query := range map[string]string{
			"versions":                 `SELECT count(*) FROM narthex_library_artifact_versions WHERE artifact_id=$1 OR id=ANY($2)`,
			"media":                    `SELECT count(*) FROM narthex_library_artifact_media_blobs WHERE artifact_version_id=ANY($2) AND $1<>''`,
			"grants":                   `SELECT count(*) FROM narthex_library_artifact_grants WHERE artifact_id=$1 OR artifact_version_id=ANY($2)`,
			"receipts":                 `SELECT count(*) FROM narthex_library_mcp_client_artifact_version_requests WHERE artifact_id=$1 OR artifact_version_id=ANY($2)`,
			"collaboration":            `SELECT count(*) FROM narthex_library_collaborations WHERE artifact_id=$1 AND cardinality($2::text[])>=0`,
			"collaboration principals": `SELECT count(*) FROM narthex_library_collaboration_principals WHERE artifact_id=$1 AND cardinality($2::text[])>=0`,
			"chat saves":               `SELECT count(*) FROM narthex_library_chat_saves WHERE source_artifact_id=$1 OR artifact_id=$1 OR source_version_id=ANY($2) OR artifact_version_id=ANY($2)`,
		} {
			var count int
			if err := store.pool.QueryRow(ctx, query, artifactID, versionIDs).Scan(&count); err != nil {
				t.Fatalf("count %s: %v", name, err)
			}
			if count != 0 {
				leftover = append(leftover, name)
			}
		}
		if runID != "" {
			var count int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_runs WHERE id=$1`, runID).Scan(&count); err != nil {
				t.Fatalf("count run: %v", err)
			}
			if count != 0 {
				leftover = append(leftover, "run")
			}
		}
		return leftover
	}
}

// cleanupPgLibraryDeleteFixture removes whatever a test left behind, in
// foreign-key order, so a failed assertion never leaks rows into later tests.
func cleanupPgLibraryDeleteFixture(t *testing.T, store *PgStore, f libraryDeleteFixture) {
	t.Helper()
	ctx := context.Background()
	clients := []string{f.owner.ID, f.other.ID}
	ids := []string{f.target.ID, f.image.ID, f.reply.ID, f.savedCopyID, f.kept.ID}
	rows, err := store.pool.Query(ctx, `SELECT id FROM narthex_library_artifacts WHERE agent_surface_id=ANY($1)`, clients)
	if err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
	}
	runs := []string{f.targetRunID, f.imageRunID, f.replyRunID, f.keptRunID}
	rows, err = store.pool.Query(ctx, `SELECT run_id FROM narthex_library_artifacts WHERE id=ANY($1) AND run_id<>''`, ids)
	if err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				runs = append(runs, id)
			}
		}
		rows.Close()
	}
	exec := func(query string, args ...any) { _, _ = store.pool.Exec(ctx, query, args...) }
	exec(`DELETE FROM narthex_library_mcp_client_artifact_version_requests WHERE artifact_id=ANY($1) OR client_id=ANY($2)`, ids, clients)
	exec(`DELETE FROM narthex_library_chat_saves WHERE source_artifact_id=ANY($1) OR artifact_id=ANY($1)`, ids)
	exec(`DELETE FROM narthex_library_artifact_grants WHERE artifact_id=ANY($1) OR agent_surface_id=ANY($2)`, ids, clients)
	exec(`DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id IN (SELECT id FROM narthex_library_artifact_versions WHERE artifact_id=ANY($1))`, ids)
	exec(`DELETE FROM narthex_library_collaborations WHERE artifact_id=ANY($1)`, ids)
	exec(`DELETE FROM narthex_library_artifact_versions WHERE artifact_id=ANY($1)`, ids)
	exec(`DELETE FROM narthex_library_artifacts WHERE id=ANY($1)`, ids)
	exec(`DELETE FROM narthex_library_runs WHERE id=ANY($1)`, runs)
	exec(`DELETE FROM narthex_library_artifact_tombstones WHERE artifact_id=ANY($1)`, ids)
	exec(`DELETE FROM narthex_mcp_client_namespaces WHERE client_id=ANY($1)`, clients)
	exec(`DELETE FROM narthex_library_runtime_attestations WHERE client_id=ANY($1)`, clients)
	exec(`DELETE FROM narthex_mcp_clients WHERE id=ANY($1)`, clients)
}
