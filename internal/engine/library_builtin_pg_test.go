package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type pgBuiltInLibraryBindingSnapshot struct {
	ID                string
	SkillID           string
	ScopeKind         string
	ScopeID           string
	Mode              string
	PinnedVersionID   string
	CapabilityCeiling string
	Priority          int
	CreatedBy         string
	CreatedAt         string
	UpdatedAt         string
}

type pgBuiltInLibrarySnapshot struct {
	CurrentVersionID      string
	CurrentVersionUpdated string
	SkillName             string
	SkillDescription      string
	SkillCreatedBy        string
	SkillCreatedAt        string
	SkillUpdatedAt        string
	VersionContent        string
	VersionDigest         string
	VersionCapabilities   string
	VersionCreatedBy      string
	VersionCreatedAt      string
	ExistingBinding       pgBuiltInLibraryBindingSnapshot
	NewBinding            pgBuiltInLibraryBindingSnapshot
	AllBindings           string
	BindingGeneration     int64
	SkillCount            int
	VersionCount          int
	ClientCount           int
	BindingCount          int
}

type pgBuiltInLibraryVersionSnapshot struct {
	Content               string
	Digest                string
	RequestedCapabilities string
	CreatedBy             string
	CreatedAt             string
}

func waitForPgBackendBlockedBy(ctx context.Context, conn *pgx.Conn, blockerPID, excludedPID int32) (int32, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		rows, err := conn.Query(ctx, `
SELECT pid,pg_blocking_pids(pid)
FROM pg_stat_activity
WHERE datname=current_database()
  AND pid<>pg_backend_pid()
  AND pid<>$1
  AND wait_event_type='Lock'`, excludedPID)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var pid int32
			var blockingPIDs []int32
			if err := rows.Scan(&pid, &blockingPIDs); err != nil {
				rows.Close()
				return 0, err
			}
			for _, candidate := range blockingPIDs {
				if candidate == blockerPID {
					rows.Close()
					return pid, nil
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, err
		}
		rows.Close()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func reconcilePgBuiltInLibraryDefinitionForTest(ctx context.Context, store *PgStore, definition builtInLibrarySkillDefinition) error {
	if err := definition.validate(); err != nil {
		return err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, libraryBuiltInReconcileLock); err != nil {
		return err
	}
	if err := store.reconcileBuiltInLibraryDefinitionTx(ctx, tx, definition); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func createPgBuiltInLibraryClientWithDefinitionForTest(ctx context.Context, store *PgStore, client MCPClient, definition builtInLibrarySkillDefinition) (MCPClient, error) {
	if err := prepareMCPClientForCreate(&client); err != nil {
		return MCPClient{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return MCPClient{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_mcp_clients
    (id,slug,name,subject,oauth_client_id,runtime_attestor_public_key,status,epoch,revision,created_by,created_at,updated_at,revoked_at,revoked_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		client.ID, client.Slug, client.Name, client.Subject, client.OAuthClientID, client.RuntimeAttestorPublicKey,
		client.Status, client.Epoch, client.Revision, client.CreatedBy,
		client.CreatedAt, client.UpdatedAt, client.RevokedAt, client.RevokedBy); err != nil {
		return MCPClient{}, err
	}
	if err := store.reconcileInstalledBuiltInLibraryForNewClientDefinitionTx(ctx, tx, client.ID, definition); err != nil {
		return MCPClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return copyMCPClient(client), nil
}

func cleanupPgBuiltInLibraryTestRows(ctx context.Context, store *PgStore, clientIDs ...string) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, libraryBuiltInReconcileLock); err != nil {
		return err
	}
	for _, clientID := range clientIDs {
		if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_requests WHERE client_id=$1`, clientID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_audit_events WHERE client_id=$1`, clientID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_leases WHERE client_id=$1`, clientID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_requests WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_audit_events WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_mcp_client_skill_authoring_leases WHERE target_skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_evaluations WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_builtin_current_versions WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skills WHERE id=$1`, usingSynaxisSkillID); err != nil {
		return err
	}
	for _, clientID := range clientIDs {
		if _, err := tx.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, clientID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func readPgBuiltInLibraryBindingSnapshot(t *testing.T, ctx context.Context, store *PgStore, clientID string) pgBuiltInLibraryBindingSnapshot {
	t.Helper()
	var snapshot pgBuiltInLibraryBindingSnapshot
	err := store.pool.QueryRow(ctx, `
SELECT id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling::text,priority,created_by,created_at::text,updated_at::text
FROM narthex_library_skill_bindings
WHERE id=$1`, usingSynaxisBindingID(clientID)).Scan(
		&snapshot.ID, &snapshot.SkillID, &snapshot.ScopeKind, &snapshot.ScopeID, &snapshot.Mode,
		&snapshot.PinnedVersionID, &snapshot.CapabilityCeiling, &snapshot.Priority, &snapshot.CreatedBy,
		&snapshot.CreatedAt, &snapshot.UpdatedAt,
	)
	if err != nil {
		t.Fatalf("read built-in binding for %s: %v", clientID, err)
	}
	return snapshot
}

func readPgBuiltInLibraryVersionSnapshot(t *testing.T, ctx context.Context, store *PgStore, versionID string) pgBuiltInLibraryVersionSnapshot {
	t.Helper()
	var snapshot pgBuiltInLibraryVersionSnapshot
	if err := store.pool.QueryRow(ctx, `
SELECT content,digest,requested_capabilities::text,created_by,created_at::text
FROM narthex_library_skill_versions
WHERE id=$1 AND skill_id=$2`, versionID, usingSynaxisSkillID).Scan(
		&snapshot.Content, &snapshot.Digest, &snapshot.RequestedCapabilities,
		&snapshot.CreatedBy, &snapshot.CreatedAt,
	); err != nil {
		t.Fatalf("read built-in version %s: %v", versionID, err)
	}
	return snapshot
}

func assertPgBuiltInLibraryVersionState(t *testing.T, ctx context.Context, store *PgStore, expectedVersionID string, expectedVersionCount int, clientIDs ...string) {
	t.Helper()
	var bindingCount, expectedPinCount, clientCount, versionCount, markerCount int
	var currentVersionID string
	if err := store.pool.QueryRow(ctx, `
SELECT count(*),count(*) FILTER (WHERE pinned_version_id=$2)
FROM narthex_library_skill_bindings
WHERE skill_id=$1`, usingSynaxisSkillID, expectedVersionID).Scan(&bindingCount, &expectedPinCount); err != nil {
		t.Fatalf("count managed pins for %s: %v", expectedVersionID, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients`).Scan(&clientCount); err != nil {
		t.Fatalf("count durable clients for %s: %v", expectedVersionID, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_versions WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&versionCount); err != nil {
		t.Fatalf("count retained built-in versions for %s: %v", expectedVersionID, err)
	}
	if err := store.pool.QueryRow(ctx, `
SELECT count(*),COALESCE(max(current_version_id),'')
FROM narthex_library_builtin_current_versions
WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&markerCount, &currentVersionID); err != nil {
		t.Fatalf("read authoritative built-in version for %s: %v", expectedVersionID, err)
	}
	if markerCount != 1 || currentVersionID != expectedVersionID {
		t.Fatalf("authoritative built-in version = count:%d version:%q, want one %q", markerCount, currentVersionID, expectedVersionID)
	}
	projectedVersionID, found, err := store.BuiltInLibraryCurrentVersion(ctx, usingSynaxisSkillID)
	if err != nil || !found || projectedVersionID != expectedVersionID {
		t.Fatalf("projected authoritative version = %q, found=%t, err=%v; want %q", projectedVersionID, found, err, expectedVersionID)
	}
	if bindingCount != clientCount || expectedPinCount != bindingCount {
		t.Fatalf("managed pins for %s = expected:%d bindings:%d clients:%d", expectedVersionID, expectedPinCount, bindingCount, clientCount)
	}
	if versionCount != expectedVersionCount {
		t.Fatalf("built-in version count for %s = %d, want %d", expectedVersionID, versionCount, expectedVersionCount)
	}
	for _, clientID := range clientIDs {
		selections, err := store.LibraryAgentSurfaceSkillSelections(ctx, clientID)
		if err != nil {
			t.Fatalf("resolve client %s at %s: %v", clientID, expectedVersionID, err)
		}
		if len(selections) != 1 || selections[0].Skill.ID != usingSynaxisSkillID ||
			selections[0].Version.ID != expectedVersionID || selections[0].Binding.PinnedVersionID != expectedVersionID {
			t.Fatalf("client %s selection at %s = %#v", clientID, expectedVersionID, selections)
		}
	}
}

func readPgBuiltInLibrarySnapshot(t *testing.T, ctx context.Context, store *PgStore, existingClientID, newClientID string) pgBuiltInLibrarySnapshot {
	t.Helper()
	var snapshot pgBuiltInLibrarySnapshot
	if err := store.pool.QueryRow(ctx, `
SELECT current_version_id,updated_at::text
FROM narthex_library_builtin_current_versions
WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&snapshot.CurrentVersionID, &snapshot.CurrentVersionUpdated); err != nil {
		t.Fatalf("read authoritative built-in version: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `
SELECT name,description,created_by,created_at::text,updated_at::text
FROM narthex_library_skills
WHERE id=$1`, usingSynaxisSkillID).Scan(
		&snapshot.SkillName, &snapshot.SkillDescription, &snapshot.SkillCreatedBy,
		&snapshot.SkillCreatedAt, &snapshot.SkillUpdatedAt,
	); err != nil {
		t.Fatalf("read built-in skill: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `
SELECT content,digest,requested_capabilities::text,created_by,created_at::text
FROM narthex_library_skill_versions
WHERE id=$1 AND skill_id=$2`, usingSynaxisSkillVersionID, usingSynaxisSkillID).Scan(
		&snapshot.VersionContent, &snapshot.VersionDigest, &snapshot.VersionCapabilities,
		&snapshot.VersionCreatedBy, &snapshot.VersionCreatedAt,
	); err != nil {
		t.Fatalf("read built-in version: %v", err)
	}
	snapshot.ExistingBinding = readPgBuiltInLibraryBindingSnapshot(t, ctx, store, existingClientID)
	snapshot.NewBinding = readPgBuiltInLibraryBindingSnapshot(t, ctx, store, newClientID)
	if err := store.pool.QueryRow(ctx, `
SELECT COALESCE(jsonb_agg(jsonb_build_array(id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at) ORDER BY id)::text,'[]')
FROM narthex_library_skill_bindings
WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&snapshot.AllBindings); err != nil {
		t.Fatalf("snapshot all built-in bindings: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT generation FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&snapshot.BindingGeneration); err != nil {
		t.Fatalf("read built-in binding generation: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skills WHERE id=$1`, usingSynaxisSkillID).Scan(&snapshot.SkillCount); err != nil {
		t.Fatalf("count built-in skills: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_versions WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&snapshot.VersionCount); err != nil {
		t.Fatalf("count built-in versions: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients`).Scan(&snapshot.ClientCount); err != nil {
		t.Fatalf("count durable MCP clients: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_bindings WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&snapshot.BindingCount); err != nil {
		t.Fatalf("count built-in bindings: %v", err)
	}
	return snapshot
}

func TestPgStoreBuiltInUsingSynaxisLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres built-in Library integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}

	suffix := newPgFixtureSuffix()
	existingClientID := "mcpcli_pg_builtin_existing_" + suffix
	newClientID := "mcpcli_pg_builtin_new_" + suffix
	v1ReplicaClientID := "mcpcli_pg_builtin_mixed_v1_" + suffix
	v2ReplicaClientID := "mcpcli_pg_builtin_mixed_v2_" + suffix
	conflictClientID := "mcpcli_pg_builtin_conflict_" + suffix
	clientIDs := []string{existingClientID, newClientID, v1ReplicaClientID, v2ReplicaClientID, conflictClientID}
	if err := cleanupPgBuiltInLibraryTestRows(ctx, store, clientIDs...); err != nil {
		store.Close()
		t.Fatalf("clean pre-existing built-in rows: %v", err)
	}
	defer func() {
		if err := cleanupPgBuiltInLibraryTestRows(context.Background(), store, clientIDs...); err != nil {
			t.Errorf("clean built-in rows: %v", err)
		}
		store.Close()
	}()
	store.SetCipher(testCipher(t, 91))

	// A clean integration database exercises startup with no durable clients:
	// the marker must still commit so the first later registration has one
	// authoritative pin to follow. Preserve shared databases by skipping only
	// this preconditioned subcase when unrelated client fixtures are present.
	t.Run("zero clients", func(t *testing.T) {
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Skipf("database contains %d unrelated durable clients", count)
		}
		if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
			t.Fatalf("zero-client reconcile: %v", err)
		}
		assertPgBuiltInLibraryVersionState(t, ctx, store, usingSynaxisSkillVersionID, 1)
		var bindingCount int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_bindings WHERE skill_id=$1`, usingSynaxisSkillID).Scan(&bindingCount); err != nil {
			t.Fatal(err)
		}
		if bindingCount != 0 {
			t.Fatalf("zero-client reconcile created %d managed bindings", bindingCount)
		}
		if err := cleanupPgBuiltInLibraryTestRows(ctx, store, clientIDs...); err != nil {
			t.Fatalf("reset zero-client fixture: %v", err)
		}
	})

	existingClient, err := store.CreateMCPClient(ctx, MCPClient{
		ID: existingClientID, Name: "PG built-in existing " + suffix,
		Subject: "usr_pg_builtin_existing", CreatedBy: "usr_pg_builtin_existing",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient(existing): %v", err)
	}
	var preReconcileBindings int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_bindings WHERE skill_id=$1 AND scope_kind=$2 AND scope_id=$3`,
		usingSynaxisSkillID, LibraryScopeAgentSurface, existingClient.ID).Scan(&preReconcileBindings); err != nil {
		t.Fatalf("count pre-reconcile bindings: %v", err)
	}
	if preReconcileBindings != 0 {
		t.Fatalf("existing client had %d built-in bindings before manifest installation, want 0", preReconcileBindings)
	}

	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("ReconcileBuiltInLibrary(existing): %v", err)
	}
	existingSelection, err := store.LibraryAgentSurfaceSkillSelections(ctx, existingClient.ID)
	if err != nil {
		t.Fatalf("LibraryAgentSurfaceSkillSelections(existing): %v", err)
	}
	if len(existingSelection) != 1 || existingSelection[0].Skill.ID != usingSynaxisSkillID ||
		existingSelection[0].Version.ID != usingSynaxisSkillVersionID ||
		existingSelection[0].Binding.ID != usingSynaxisBindingID(existingClient.ID) {
		t.Fatalf("existing client built-in selection = %#v", existingSelection)
	}

	newClient, err := store.CreateMCPClient(ctx, MCPClient{
		ID: newClientID, Name: "PG built-in new " + suffix,
		Subject: "usr_pg_builtin_new", CreatedBy: "usr_pg_builtin_new",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient(new): %v", err)
	}
	newSelection, err := store.LibraryAgentSurfaceSkillSelections(ctx, newClient.ID)
	if err != nil {
		t.Fatalf("LibraryAgentSurfaceSkillSelections(new): %v", err)
	}
	if len(newSelection) != 1 || newSelection[0].Skill.ID != usingSynaxisSkillID ||
		newSelection[0].Version.ID != usingSynaxisSkillVersionID ||
		newSelection[0].Binding.ID != usingSynaxisBindingID(newClient.ID) {
		t.Fatalf("new client built-in selection = %#v", newSelection)
	}

	before := readPgBuiltInLibrarySnapshot(t, ctx, store, existingClient.ID, newClient.ID)
	if before.SkillCount != 1 || before.VersionCount != 1 || before.BindingCount != before.ClientCount {
		t.Fatalf("built-in cardinality = skills:%d versions:%d bindings:%d clients:%d", before.SkillCount, before.VersionCount, before.BindingCount, before.ClientCount)
	}
	if before.CurrentVersionID != usingSynaxisSkillVersionID || strings.HasPrefix(before.CurrentVersionID, encPrefix) {
		t.Fatalf("authoritative version marker = %q, want non-sensitive canonical ID", before.CurrentVersionID)
	}
	if before.VersionDigest != usingSynaxisExpectedContentDigest || before.VersionCapabilities != "[]" {
		t.Fatalf("built-in version metadata = digest:%q capabilities:%q", before.VersionDigest, before.VersionCapabilities)
	}
	for label, value := range map[string]string{
		"skill name":               before.SkillName,
		"skill description":        before.SkillDescription,
		"skill creator":            before.SkillCreatedBy,
		"version content":          before.VersionContent,
		"version creator":          before.VersionCreatedBy,
		"existing binding creator": before.ExistingBinding.CreatedBy,
		"new binding creator":      before.NewBinding.CreatedBy,
	} {
		if !strings.HasPrefix(value, encPrefix) {
			t.Errorf("%s is not encrypted at rest", label)
		}
	}
	for label, fixture := range map[string]struct {
		binding  pgBuiltInLibraryBindingSnapshot
		clientID string
	}{
		"existing": {binding: before.ExistingBinding, clientID: existingClient.ID},
		"new":      {binding: before.NewBinding, clientID: newClient.ID},
	} {
		binding := fixture.binding
		if binding.ID != usingSynaxisBindingID(fixture.clientID) || binding.SkillID != usingSynaxisSkillID ||
			binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != fixture.clientID ||
			binding.Mode != LibraryBindingModePin || binding.PinnedVersionID != usingSynaxisSkillVersionID ||
			binding.CapabilityCeiling != "[]" || binding.Priority != usingSynaxisBindingPriority {
			t.Errorf("%s client built-in binding has wrong shape", label)
		}
	}

	const reconcileWorkers = 4
	start := make(chan struct{})
	errs := make(chan error, reconcileWorkers)
	var wg sync.WaitGroup
	for worker := 0; worker < reconcileWorkers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- store.ReconcileBuiltInLibrary(ctx)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ReconcileBuiltInLibrary: %v", err)
		}
	}
	afterConcurrent := readPgBuiltInLibrarySnapshot(t, ctx, store, existingClient.ID, newClient.ID)
	if afterConcurrent != before {
		t.Fatal("concurrent idempotent reconcile changed persisted state")
	}
	existingClient, err = store.BindMCPClientOAuthClient(ctx, existingClient.ID, "oauth-pg-builtin-"+suffix,
		MCPClientPrecondition{ID: existingClient.ID, Revision: existingClient.Revision},
		PlatformActor{UserID: existingClient.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("BindMCPClientOAuthClient(existing): %v", err)
	}

	mutations := []struct {
		name string
		call func() error
	}{
		{name: "reserved skill slug", call: func() error {
			_, _, err := store.CreateLibrarySkillWithInitialVersion(ctx,
				LibrarySkill{Slug: usingSynaxisSkillSlug, Name: "Reserved overwrite", CreatedBy: "usr_pg_builtin_owner"},
				LibrarySkillVersion{Content: "# Must not replace the built-in", CreatedBy: "usr_pg_builtin_owner"})
			return err
		}},
		{name: "reserved version append", call: func() error {
			_, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
				SkillID: usingSynaxisSkillID, Content: "# Must not append", CreatedBy: "usr_pg_builtin_owner",
			})
			return err
		}},
		{name: "reserved binding update", call: func() error {
			_, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
				SkillID: usingSynaxisSkillID, ScopeKind: LibraryScopeAgentSurface, ScopeID: existingClient.ID,
				Mode: LibraryBindingModeTrack, CreatedBy: "usr_pg_builtin_owner",
			})
			return err
		}},
		{name: "reserved binding delete", call: func() error {
			return store.DeleteLibrarySkillBinding(ctx, usingSynaxisSkillID, usingSynaxisBindingID(existingClient.ID))
		}},
		{name: "reserved version id", call: func() error {
			_, _, err := store.CreateLibrarySkillWithInitialVersion(ctx,
				LibrarySkill{Slug: "pg-built-in-version-squat-" + suffix, Name: "Version squat", CreatedBy: "usr_pg_builtin_owner"},
				LibrarySkillVersion{ID: usingSynaxisSkillVersionIDPrefix + "999", Content: "# Must not squat", CreatedBy: "usr_pg_builtin_owner"})
			return err
		}},
		{name: "reserved binding id", call: func() error {
			_, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
				ID: usingSynaxisBindingIDPrefix + "reserved", SkillID: "libsk_unmanaged",
				ScopeKind: LibraryScopeAgentSurface, ScopeID: existingClient.ID, Mode: LibraryBindingModeTrack,
				CreatedBy: "usr_pg_builtin_owner",
			})
			return err
		}},
		{name: "authoring adoption", call: func() error {
			_, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, existingClient.ID,
				MCPClientPrecondition{ID: existingClient.ID, Revision: existingClient.Revision},
				LibraryMCPClientSkillAuthoringAdoptionRequest{
					SkillID: usingSynaxisSkillID, ExpectedVersionID: usingSynaxisSkillVersionID,
					ExpectedVersionDigest: usingSynaxisExpectedContentDigest,
				}, "usr_pg_builtin_owner")
			return err
		}},
		{name: "leased reserved create", call: func() error {
			_, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, existingClient, LibraryMCPClientSkillAuthoringRequest{
				RequestID: "pg-built-in-reserved-create", Name: "Using Synaxis", Slug: usingSynaxisSkillSlug,
				Content: "# Must not create",
			})
			return err
		}},
		{name: "leased reserved update", call: func() error {
			_, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, existingClient, LibraryMCPClientSkillAuthoringUpdateRequest{
				RequestID: "pg-built-in-reserved-update", SkillID: usingSynaxisSkillID,
				ExpectedVersionID: usingSynaxisSkillVersionID, ExpectedVersionDigest: usingSynaxisExpectedContentDigest,
				Content: "# Must not update",
			})
			return err
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := mutation.call(); !errors.Is(err, ErrLibraryBuiltInManaged) {
				t.Fatalf("mutation error = %v, want ErrLibraryBuiltInManaged", err)
			}
		})
	}
	afterMutations := readPgBuiltInLibrarySnapshot(t, ctx, store, existingClient.ID, newClient.ID)
	if afterMutations != before {
		t.Fatal("rejected mutations changed persisted built-in state")
	}
	auditEvents, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, existingClient.ID)
	if err != nil {
		t.Fatalf("read rejected built-in authoring receipts: %v", err)
	}
	if len(auditEvents) != 3 ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationAdopt) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationCreate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(auditEvents, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationUpdate) != 1 {
		t.Fatalf("built-in authoring rejection receipts = %#v, want one rejected adopt/create/update receipt", auditEvents)
	}

	// Exercise the deployment sequence across binaries: upgrade to a manifest
	// containing v2, roll back to the v1-only manifest, then upgrade again. The
	// native reconciliation helper runs under the same lock ordering as startup.
	v1Definition := usingSynaxisDefinition()
	v1BeforeUpgrade := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, usingSynaxisSkillVersionID)
	assertPgBuiltInLibraryVersionState(t, ctx, store, usingSynaxisSkillVersionID, 1, existingClient.ID, newClient.ID)

	v2Content := usingSynaxisSkillContent + "\n## Engine v2 test note\nRefresh the verified activation after an Engine upgrade.\n"
	v2ID := usingSynaxisSkillVersionIDPrefix + "2"
	v2Definition := v1Definition
	v2Definition.Versions = append(append([]builtInLibrarySkillVersionDefinition(nil), v1Definition.Versions...), builtInLibrarySkillVersionDefinition{
		Revision: 2, VersionID: v2ID, Content: v2Content, ContentDigest: libraryDigest(v2Content),
	})
	v2Definition.CurrentVersionID = v2ID

	if err := reconcilePgBuiltInLibraryDefinitionForTest(ctx, store, v2Definition); err != nil {
		t.Fatalf("reconcile v1 to v2: %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, v2ID, 2, existingClient.ID, newClient.ID)
	// The public create path is compiled with v1 here. A newer replica's v2
	// marker is nevertheless authoritative for storage, so this transaction
	// must create and pin v2 rather than using the local manifest head.
	v1ReplicaClient, err := store.CreateMCPClient(ctx, MCPClient{
		ID: v1ReplicaClientID, Name: "PG built-in v1 replica under v2 " + suffix,
		Subject: "usr_pg_builtin_mixed_v1", CreatedBy: "usr_pg_builtin_mixed_v1",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient(v1 replica under v2): %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, v2ID, 2, existingClient.ID, newClient.ID, v1ReplicaClient.ID)
	v1AfterUpgrade := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, usingSynaxisSkillVersionID)
	v2AfterUpgrade := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, v2ID)
	if v1AfterUpgrade != v1BeforeUpgrade {
		t.Fatal("v2 rollout changed the immutable v1 row")
	}
	if !strings.HasPrefix(v2AfterUpgrade.Content, encPrefix) || !strings.HasPrefix(v2AfterUpgrade.CreatedBy, encPrefix) {
		t.Fatal("v2 content or creator is not encrypted at rest")
	}
	if v2AfterUpgrade.Digest != libraryDigest(v2Content) || v2AfterUpgrade.RequestedCapabilities != "[]" {
		t.Fatalf("v2 metadata = digest:%q capabilities:%q", v2AfterUpgrade.Digest, v2AfterUpgrade.RequestedCapabilities)
	}
	decryptedV2, found := store.LibrarySkillVersion(ctx, usingSynaxisSkillID, v2ID)
	if !found || decryptedV2.Version != 2 || decryptedV2.Content != v2Content ||
		decryptedV2.Digest != libraryDigest(v2Content) || decryptedV2.CreatedBy != libraryBuiltInManager ||
		len(decryptedV2.RequestedCapabilities) != 0 {
		t.Fatalf("decrypted v2 does not match the manifest: found=%t version=%d digest=%q creator=%q capabilities=%v",
			found, decryptedV2.Version, decryptedV2.Digest, decryptedV2.CreatedBy, decryptedV2.RequestedCapabilities)
	}

	if err := reconcilePgBuiltInLibraryDefinitionForTest(ctx, store, v1Definition); err != nil {
		t.Fatalf("reconcile v2 to v1 rollback: %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, usingSynaxisSkillVersionID, 2, existingClient.ID, newClient.ID, v1ReplicaClient.ID)
	v2ReplicaClient, err := createPgBuiltInLibraryClientWithDefinitionForTest(ctx, store, MCPClient{
		ID: v2ReplicaClientID, Name: "PG built-in v2 replica under v1 " + suffix,
		Subject: "usr_pg_builtin_mixed_v2", CreatedBy: "usr_pg_builtin_mixed_v2",
	}, v2Definition)
	if err != nil {
		t.Fatalf("create v2 replica client under v1 rollback: %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, usingSynaxisSkillVersionID, 2, existingClient.ID, newClient.ID, v1ReplicaClient.ID, v2ReplicaClient.ID)
	if got := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, usingSynaxisSkillVersionID); got != v1BeforeUpgrade {
		t.Fatal("rollback changed the immutable v1 row")
	}
	if got := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, v2ID); got != v2AfterUpgrade {
		t.Fatal("rollback deleted or changed the immutable v2 row")
	}

	if err := reconcilePgBuiltInLibraryDefinitionForTest(ctx, store, v2Definition); err != nil {
		t.Fatalf("reconcile v1 to v2 re-upgrade: %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, v2ID, 2, existingClient.ID, newClient.ID, v1ReplicaClient.ID, v2ReplicaClient.ID)
	if got := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, usingSynaxisSkillVersionID); got != v1BeforeUpgrade {
		t.Fatal("re-upgrade changed the immutable v1 row")
	}
	if got := readPgBuiltInLibraryVersionSnapshot(t, ctx, store, v2ID); got != v2AfterUpgrade {
		t.Fatal("re-upgrade changed the immutable v2 row")
	}
	afterReupgrade := readPgBuiltInLibrarySnapshot(t, ctx, store, existingClient.ID, newClient.ID)
	if err := reconcilePgBuiltInLibraryDefinitionForTest(ctx, store, v2Definition); err != nil {
		t.Fatalf("repeat v2 reconcile: %v", err)
	}
	if got := readPgBuiltInLibrarySnapshot(t, ctx, store, existingClient.ID, newClient.ID); got != afterReupgrade {
		t.Fatal("idempotent v2 reconcile changed the marker, immutable versions, bindings, or generation")
	}

	// Exercise the global reserved-binding scan with a row that ordinary store
	// APIs refuse to create. Reconciliation must fail closed before repinning
	// either legitimate client, even though this binding does not use the
	// reserved binding-ID prefix.
	rawBindingID := "libskb_pg_builtin_conflict_" + suffix
	rawCreator, err := store.enc("usr_pg_builtin_raw_conflict")
	if err != nil {
		t.Fatalf("encrypt raw conflict creator: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
INSERT INTO narthex_library_skill_bindings
    (id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,'','[]'::jsonb,0,$6,now(),now())`,
		rawBindingID, usingSynaxisSkillID, LibraryScopeWorkspace, "workspace_pg_builtin_conflict_"+suffix,
		LibraryBindingModeTrack, rawCreator); err != nil {
		t.Fatalf("insert raw conflicting built-in binding: %v", err)
	}
	if _, err := store.CreateMCPClient(ctx, MCPClient{
		ID: conflictClientID, Name: "PG built-in conflict rollback " + suffix,
		Subject: "usr_pg_builtin_conflict", CreatedBy: "usr_pg_builtin_conflict",
	}); !errors.Is(err, ErrLibraryBuiltInConflict) {
		t.Fatalf("new-client create with raw generic binding error = %v, want ErrLibraryBuiltInConflict", err)
	}
	var conflictClientCount, conflictBindingCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients WHERE id=$1`, conflictClientID).Scan(&conflictClientCount); err != nil {
		t.Fatalf("count rolled-back conflict client: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_bindings WHERE id=$1`, usingSynaxisBindingID(conflictClientID)).Scan(&conflictBindingCount); err != nil {
		t.Fatalf("count rolled-back conflict binding: %v", err)
	}
	if conflictClientCount != 0 || conflictBindingCount != 0 {
		t.Fatalf("malformed global binding committed client=%d binding=%d", conflictClientCount, conflictBindingCount)
	}
	existingBeforeConflict := readPgBuiltInLibraryBindingSnapshot(t, ctx, store, existingClient.ID)
	newBeforeConflict := readPgBuiltInLibraryBindingSnapshot(t, ctx, store, newClient.ID)
	if err := store.ReconcileBuiltInLibrary(ctx); !errors.Is(err, ErrLibraryBuiltInConflict) {
		t.Fatalf("reconcile with raw generic binding error = %v, want ErrLibraryBuiltInConflict", err)
	}
	if got := readPgBuiltInLibraryBindingSnapshot(t, ctx, store, existingClient.ID); got != existingBeforeConflict {
		t.Fatal("failed reconciliation changed the existing client's managed pin")
	}
	if got := readPgBuiltInLibraryBindingSnapshot(t, ctx, store, newClient.ID); got != newBeforeConflict {
		t.Fatal("failed reconciliation changed the new client's managed pin")
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM narthex_library_skill_bindings WHERE id=$1`, rawBindingID); err != nil {
		t.Fatalf("remove raw conflicting built-in binding: %v", err)
	}
	if err := reconcilePgBuiltInLibraryDefinitionForTest(ctx, store, v2Definition); err != nil {
		t.Fatalf("reconcile after removing raw binding conflict: %v", err)
	}
	assertPgBuiltInLibraryVersionState(t, ctx, store, v2ID, 2, existingClient.ID, newClient.ID, v1ReplicaClient.ID, v2ReplicaClient.ID)
}

func TestPgStoreMCPClientRegistrySerializesMembershipMutations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the PostgreSQL built-in lock-order integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}

	suffix := newPgFixtureSuffix()
	scopeClientID := "mcpcli_pg_builtin_lock_scope_" + suffix
	createClientID := "mcpcli_pg_builtin_lock_create_" + suffix
	invalidClientID := "mcpcli_pg_builtin_lock_invalid_" + suffix
	deleteClientID := "mcpcli_pg_builtin_lock_delete_" + suffix
	accountName := "pg_builtin_lock_account_" + suffix
	candidateAccountName := "pg_builtin_lock_candidate_" + suffix
	clientIDs := []string{scopeClientID, createClientID, invalidClientID, deleteClientID}
	if err := cleanupPgBuiltInLibraryTestRows(ctx, store, clientIDs...); err != nil {
		store.Close()
		t.Fatalf("clean pre-existing built-in rows: %v", err)
	}
	var lockNamespace, moveNamespace, deleteNamespace ConnectionNamespace
	defer func() {
		if err := cleanupPgBuiltInLibraryTestRows(context.Background(), store, clientIDs...); err != nil {
			t.Errorf("clean built-in lock-order rows: %v", err)
		}
		if _, err := store.pool.Exec(context.Background(), `DELETE FROM narthex_accounts WHERE name=ANY($1)`, []string{accountName, candidateAccountName}); err != nil {
			t.Errorf("clean lock-order accounts: %v", err)
		}
		for _, namespace := range []ConnectionNamespace{lockNamespace, moveNamespace, deleteNamespace} {
			if namespace.ID != "" {
				if _, err := store.pool.Exec(context.Background(), `DELETE FROM narthex_connection_namespaces WHERE id=$1`, namespace.ID); err != nil {
					t.Errorf("clean lock-order namespace %s: %v", namespace.ID, err)
				}
			}
		}
		store.Close()
	}()
	store.SetCipher(testCipher(t, 92))
	if err := store.ReconcileBuiltInLibrary(ctx); err != nil {
		t.Fatalf("install built-in manifest: %v", err)
	}
	lockNamespace, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG built-in lock order " + suffix, CreatedBy: "usr_pg_builtin_lock",
	})
	if err != nil {
		t.Fatalf("create lock-order namespace: %v", err)
	}
	moveNamespace, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG built-in lock move target " + suffix, CreatedBy: "usr_pg_builtin_lock",
	})
	if err != nil {
		t.Fatalf("create lock-order move target: %v", err)
	}
	deleteNamespace, err = store.CreateConnectionNamespace(ctx, ConnectionNamespace{
		Label: "PG built-in lock delete target " + suffix, CreatedBy: "usr_pg_builtin_lock",
	})
	if err != nil {
		t.Fatalf("create lock-order delete target: %v", err)
	}
	if err := store.Create(ctx, Account{
		Name: accountName, URL: "https://pg-builtin-lock.example/mcp", AuthMode: "token", BearerToken: "secret",
		ConnectionNamespaceID: lockNamespace.ID, ConnectionScope: ConnectionScopeShared,
	}); err != nil {
		t.Fatalf("create lock-order account: %v", err)
	}
	beforeAccount, ok := store.Account(accountName)
	if !ok {
		t.Fatal("lock-order account is missing")
	}
	scopeClient, err := store.CreateMCPClient(ctx, MCPClient{
		ID: scopeClientID, Name: "PG built-in lock scope " + suffix,
		Subject: "usr_pg_builtin_lock", CreatedBy: "usr_pg_builtin_lock",
		ConnectionNamespaceIDs: []string{lockNamespace.ID},
	})
	if err != nil {
		t.Fatalf("create lock-order scope client: %v", err)
	}
	deleteClient, err := store.CreateMCPClient(ctx, MCPClient{
		ID: deleteClientID, Name: "PG built-in lock deleted namespace " + suffix,
		Subject: "usr_pg_builtin_lock", CreatedBy: "usr_pg_builtin_lock",
		ConnectionNamespaceIDs: []string{deleteNamespace.ID},
	})
	if err != nil {
		t.Fatalf("create lock-order delete client: %v", err)
	}
	if _, err := store.RevokeMCPClient(ctx, deleteClient.ID, "usr_pg_builtin_lock", MCPClientPrecondition{
		ID: deleteClient.ID, Revision: deleteClient.Revision,
	}); err != nil {
		t.Fatalf("revoke lock-order delete client: %v", err)
	}

	blocker, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect lock-order blocker: %v", err)
	}
	defer blocker.Close(context.Background())
	lockKey := "mcp-client-namespace:" + lockNamespace.ID
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, lockKey); err != nil {
		t.Fatalf("lock namespace blocker: %v", err)
	}
	blockerLocked := true
	defer func() {
		if blockerLocked {
			_, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1,0))`, lockKey)
		}
	}()

	operationCtx, cancelOperations := context.WithTimeout(ctx, 15*time.Second)
	defer cancelOperations()
	type lockOrderResult struct {
		operation string
		client    MCPClient
		err       error
	}
	results := make(chan lockOrderResult, 2)
	go func() {
		client, err := store.CreateMCPClient(operationCtx, MCPClient{
			ID: createClientID, Name: "PG built-in lock create " + suffix,
			Subject: "usr_pg_builtin_lock", CreatedBy: "usr_pg_builtin_lock",
			ConnectionNamespaceIDs: []string{lockNamespace.ID},
		})
		results <- lockOrderResult{operation: "create", client: client, err: err}
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	blockerPID := int32(blocker.PgConn().PID())
	createPID, err := waitForPgBackendBlockedBy(waitCtx, blocker, blockerPID, blockerPID)
	cancelWait()
	if err != nil {
		t.Fatalf("wait for create at namespace lock: %v", err)
	}

	// While CreateMCPClient is paused after locking the registry and all client
	// rows, every other operation that can change account/client membership must
	// stop at the registry. If an ownership move instead locked a subset of
	// client rows first, a concurrent scope update could add a lower-ID client
	// and recreate the former three-way row-lock cycle.
	assertRegistryWait := func(name string, run func(context.Context) error) {
		t.Helper()
		waiterCtx, cancelWaiter := context.WithCancel(operationCtx)
		done := make(chan error, 1)
		go func() {
			done <- run(waiterCtx)
		}()

		waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
		waiterPID, waitErr := waitForPgBackendBlockedBy(waitCtx, blocker, createPID, createPID)
		cancelWait()
		if waitErr != nil {
			cancelWaiter()
			t.Fatalf("%s did not wait behind the client registry: %v", name, waitErr)
		}
		var query string
		if err := blocker.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, waiterPID).Scan(&query); err != nil {
			cancelWaiter()
			t.Fatalf("read %s waiting query: %v", name, err)
		}
		if !strings.Contains(query, "pg_advisory_xact_lock") {
			cancelWaiter()
			t.Fatalf("%s waits after taking an earlier row lock; query=%q", name, query)
		}
		cancelWaiter()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s unexpectedly committed while the registry was locked", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not stop after cancellation", name)
		}
	}

	assertRegistryWait("account create", func(waiterCtx context.Context) error {
		return store.Create(waiterCtx, Account{
			Name: candidateAccountName, URL: "https://pg-builtin-lock-candidate.example/mcp", AuthMode: "token", BearerToken: "secret",
			ConnectionNamespaceID: lockNamespace.ID, ConnectionScope: ConnectionScopeShared,
		})
	})
	assertRegistryWait("whole-account ownership upsert", func(waiterCtx context.Context) error {
		updated := beforeAccount
		updated.ConnectionNamespaceID = moveNamespace.ID
		updated.ConnectionScope = ConnectionScopeShared
		updated.OwnerSubject = ""
		updated.Group = moveNamespace.Label
		return store.Upsert(waiterCtx, updated)
	})
	assertRegistryWait("explicit account ownership move", func(waiterCtx context.Context) error {
		_, err := store.MoveAccountToConnectionNamespace(waiterCtx, beforeAccount.Name, beforeAccount.IncarnationID, AccountConnectionAssignment{
			ConnectionNamespaceID: moveNamespace.ID, Scope: ConnectionScopeShared,
		}, beforeAccount.Revision)
		return err
	})
	assertRegistryWait("startup client backfill", store.backfillMCPClients)
	assertRegistryWait("startup account ownership backfill", store.backfillConnectionNamespaces)
	assertRegistryWait("namespace deletion with revoked client grants", func(waiterCtx context.Context) error {
		return store.DeleteConnectionNamespace(waiterCtx, deleteNamespace.ID, ConnectionNamespacePrecondition{
			ID: deleteNamespace.ID, Revision: deleteNamespace.Revision,
		})
	})

	go func() {
		client, err := store.SetMCPClientNamespaces(operationCtx, scopeClient.ID, []string{lockNamespace.ID}, MCPClientPrecondition{
			ID: scopeClient.ID, Revision: scopeClient.Revision,
		})
		results <- lockOrderResult{operation: "scope update", client: client, err: err}
	}()

	// Scope mutation also stops at the registry, before it can lock the target
	// client row or namespace advisory and complete the former deadlock cycle.
	waitCtx, cancelWait = context.WithTimeout(ctx, 5*time.Second)
	scopePID, err := waitForPgBackendBlockedBy(waitCtx, blocker, createPID, createPID)
	if err != nil {
		cancelWait()
		t.Fatalf("scope update did not wait behind the client registry: %v", err)
	}
	cancelWait()
	var scopeQuery string
	if err := blocker.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, scopePID).Scan(&scopeQuery); err != nil {
		t.Fatalf("read scope update waiting query: %v", err)
	}
	if !strings.Contains(scopeQuery, "pg_advisory_xact_lock") {
		t.Fatalf("scope update waits after taking an earlier row lock; query=%q", scopeQuery)
	}

	var unlocked bool
	if err := blocker.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, lockKey).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("unlock namespace blocker: unlocked=%t err=%v", unlocked, err)
	}
	blockerLocked = false

	seen := make(map[string]MCPClient, 2)
	for len(seen) < 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("%s after ordered lock interleaving: %v", result.operation, result.err)
			}
			seen[result.operation] = result.client
		case <-operationCtx.Done():
			t.Fatalf("ordered lock interleaving did not complete: %v", operationCtx.Err())
		}
	}
	if got := seen["create"].ConnectionNamespaceIDs; len(got) != 1 || got[0] != lockNamespace.ID {
		t.Fatalf("created client namespace grants = %v, want %s", got, lockNamespace.ID)
	}
	if got := seen["scope update"].ConnectionNamespaceIDs; len(got) != 1 || got[0] != lockNamespace.ID {
		t.Fatalf("scope update namespace grants = %v, want %s", got, lockNamespace.ID)
	}

	// Namespace validation now follows managed binding reconciliation, but both
	// remain in one transaction: an invalid namespace must roll back the client
	// and the provisional system binding together.
	if _, err := store.CreateMCPClient(ctx, MCPClient{
		ID: invalidClientID, Name: "PG built-in invalid namespace " + suffix,
		Subject: "usr_pg_builtin_lock", CreatedBy: "usr_pg_builtin_lock",
		ConnectionNamespaceIDs: []string{"cns_missing_" + suffix},
	}); !errors.Is(err, ErrConnectionNamespaceNotFound) {
		t.Fatalf("invalid namespace create error = %v, want ErrConnectionNamespaceNotFound", err)
	}
	var invalidClientCount, invalidBindingCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients WHERE id=$1`, invalidClientID).Scan(&invalidClientCount); err != nil {
		t.Fatalf("count rolled-back invalid client: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM narthex_library_skill_bindings WHERE id=$1`, usingSynaxisBindingID(invalidClientID)).Scan(&invalidBindingCount); err != nil {
		t.Fatalf("count rolled-back invalid binding: %v", err)
	}
	if invalidClientCount != 0 || invalidBindingCount != 0 {
		t.Fatalf("invalid namespace committed client=%d managed binding=%d", invalidClientCount, invalidBindingCount)
	}
}
