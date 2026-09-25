package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// newPgFixtureSuffix returns a random lowercase hex suffix for Postgres
// integration fixtures. Unlike newEpoch(), whose base64url output can contain
// "_" and uppercase letters, hex is always accepted by librarySlugPattern and
// the connection-namespace slug normalizer, so fixture slugs never fail
// validation intermittently.
func newPgFixtureSuffix() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// cleanupPgAuthoringFixtures removes everything an MCP-client skill-authoring
// test created, in foreign-key order, so rows encrypted under this test's
// cipher never survive into a later test that holds a different key. Skills
// authored through the clients are discovered from their authoring requests;
// skills the test created directly are appended to *skillIDs as they appear.
func cleanupPgAuthoringFixtures(t *testing.T, store *PgStore, clientIDs []string, skillIDs *[]string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		ids := append([]string(nil), *skillIDs...)
		rows, err := store.pool.Query(ctx, `SELECT DISTINCT skill_id FROM narthex_library_mcp_client_skill_authoring_requests WHERE client_id = ANY($1) AND skill_id <> ''`, clientIDs)
		if err == nil {
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil && id != "" {
					ids = append(ids, id)
				}
			}
			rows.Close()
		}
		exec := func(query string, args ...any) { _, _ = store.pool.Exec(ctx, query, args...) }
		exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_audit_events WHERE client_id = ANY($1)`, clientIDs)
		exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_requests WHERE client_id = ANY($1)`, clientIDs)
		exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_leases WHERE client_id = ANY($1)`, clientIDs)
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			exec(`DELETE FROM narthex_library_mcp_client_skill_authoring_requests WHERE skill_id=$1`, id)
			exec(`DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, id)
			exec(`DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, id)
			exec(`DELETE FROM narthex_library_skill_evaluations WHERE skill_id=$1`, id)
			exec(`DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, id)
			exec(`DELETE FROM narthex_library_skills WHERE id=$1`, id)
		}
		exec(`DELETE FROM narthex_mcp_client_namespaces WHERE client_id = ANY($1)`, clientIDs)
		exec(`DELETE FROM narthex_library_runtime_attestations WHERE client_id = ANY($1)`, clientIDs)
		exec(`DELETE FROM narthex_mcp_clients WHERE id = ANY($1)`, clientIDs)
	})
}
