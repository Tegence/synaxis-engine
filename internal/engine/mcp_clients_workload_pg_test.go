package engine

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestPgStoreMCPClientKindSchemaAndWorkloadBinding proves the idempotent DDL
// adds kind with an interactive default and both CHECKs, that PgStore keeps
// the FileStore contract for kinds and the reserved workload identity, and
// that the relational layer refuses a kind/binding combination the
// application never writes.
func TestPgStoreMCPClientKindSchemaAndWorkloadBinding(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client kind integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	suffix := newPgFixtureSuffix()
	subjects := []string{"agt_" + suffix, "usr_" + suffix, "agt_retired_" + suffix, "usr_legacy_" + suffix}
	defer func() {
		// Remove exactly this test's rows (and any built-in skill binding a
		// shared database attached to them), never anything else.
		cleanup := context.Background()
		_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_skill_bindings WHERE scope_id IN (SELECT id FROM narthex_mcp_clients WHERE subject = ANY($1))`, subjects)
		_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_mcp_client_namespaces WHERE client_id IN (SELECT id FROM narthex_mcp_clients WHERE subject = ANY($1))`, subjects)
		_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_mcp_clients WHERE subject = ANY($1)`, subjects)
	}()

	if columns := pgTableColumns(t, store, "narthex_mcp_clients"); columns["kind"] != "text" {
		t.Fatalf("kind column type=%q (all: %v)", columns["kind"], columns)
	}
	var columnDefault, nullable string
	if err := store.pool.QueryRow(ctx, `
SELECT COALESCE(column_default,''), is_nullable FROM information_schema.columns
WHERE table_schema=current_schema() AND table_name='narthex_mcp_clients' AND column_name='kind'`).Scan(&columnDefault, &nullable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(columnDefault, "'interactive'") || nullable != "NO" {
		t.Fatalf("kind default=%q nullable=%q; want NOT NULL DEFAULT 'interactive'", columnDefault, nullable)
	}
	for name, fragments := range map[string][]string{
		"narthex_mcp_clients_kind_check":             {"'interactive'", "'workload'"},
		"narthex_mcp_clients_workload_binding_check": {"'workload:'", "oauth_client_id", "kind"},
	} {
		var definition string
		if err := store.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint
WHERE conname=$1 AND conrelid='narthex_mcp_clients'::regclass`, name).Scan(&definition); err != nil {
			t.Fatalf("constraint %s: %v", name, err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(definition, fragment) {
				t.Fatalf("constraint %s=%q; want it to mention %s", name, definition, fragment)
			}
		}
	}

	bound := exerciseMCPClientWorkloadIdentity(t, ctx, store, suffix)
	var rawKind, rawOAuth string
	if err := store.pool.QueryRow(ctx, `SELECT kind,oauth_client_id FROM narthex_mcp_clients WHERE id=$1`, bound.ID).Scan(&rawKind, &rawOAuth); err != nil ||
		rawKind != "workload" || rawOAuth != "workload:"+bound.ID {
		t.Fatalf("stored kind=%q binding=%q err=%v", rawKind, rawOAuth, err)
	}

	// A row written without kind, as every pre-kind row was, reads as
	// interactive through every lookup.
	legacyID := "mcpcli_legacy_" + suffix
	if _, err := store.pool.Exec(ctx, `
INSERT INTO narthex_mcp_clients (id,slug,name,subject,epoch) VALUES ($1,$2,$3,$4,$5)`,
		legacyID, "legacy-"+suffix, "Legacy "+suffix, "usr_legacy_"+suffix, newEpoch()); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if legacy, ok := store.MCPClient(ctx, legacyID); !ok || legacy.Kind != MCPClientKindInteractive {
		t.Fatalf("legacy row=%+v ok=%v; want interactive", legacy, ok)
	}
	if legacy, ok := store.ActiveMCPClient(ctx, "legacy-"+suffix); !ok || legacy.Kind != MCPClientKindInteractive {
		t.Fatalf("legacy row by slug=%+v ok=%v; want interactive", legacy, ok)
	}

	// The CHECKs refuse what the application never writes, even when it is
	// bypassed.
	for name, statement := range map[string]struct {
		sql string
		id  string
	}{
		"unknown kind":                        {`UPDATE narthex_mcp_clients SET kind='robot' WHERE id=$1`, legacyID},
		"reserved identity on interactive":    {`UPDATE narthex_mcp_clients SET oauth_client_id='workload:'||id WHERE id=$1`, legacyID},
		"DCR identity on workload":            {`UPDATE narthex_mcp_clients SET oauth_client_id='mcp_v1.foreign' WHERE id=$1`, bound.ID},
		"another client's workload identity":  {`UPDATE narthex_mcp_clients SET oauth_client_id='workload:mcpcli_other' WHERE id=$1`, bound.ID},
		"kind flipped under a reserved bind":  {`UPDATE narthex_mcp_clients SET kind='interactive' WHERE id=$1`, bound.ID},
		"interactive flipped to workload+DCR": {`UPDATE narthex_mcp_clients SET kind='workload',oauth_client_id='mcp_v1.x' WHERE id=$1`, legacyID},
	} {
		if _, err := store.pool.Exec(ctx, statement.sql, statement.id); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23514") {
			t.Fatalf("%s err=%v; want CHECK violation", name, err)
		}
	}

	// A fresh store (which re-runs the idempotent DDL) reads the same
	// durable kind and binding, including through the list query.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	current, ok := reopened.MCPClient(ctx, bound.ID)
	if !ok || current.Kind != MCPClientKindWorkload || current.OAuthClientID != bound.OAuthClientID || current.Epoch != bound.Epoch || current.Revision != bound.Revision {
		t.Fatalf("reopened=%+v ok=%v; want %+v", current, ok, bound)
	}
	listed, err := reopened.MCPClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]MCPClientKind{}
	for _, client := range listed {
		seen[client.ID] = client.Kind
	}
	if seen[bound.ID] != MCPClientKindWorkload || seen[legacyID] != MCPClientKindInteractive {
		t.Fatalf("listed kinds bound=%q legacy=%q", seen[bound.ID], seen[legacyID])
	}
}
