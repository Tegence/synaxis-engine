package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgLibraryRunCorrelationsSchemaAndParity proves the idempotent DDL
// installs the run-correlation table with its relational guarantees (client
// FK RESTRICT, digest CHECKs, composite UNIQUEs) and that PgStore upholds the
// same invariants as FileStore.
func TestPgLibraryRunCorrelationsSchemaAndParity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres run-correlation integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	columns := pgTableColumns(t, store, "narthex_library_run_correlations")
	for _, column := range []string{"id", "client_id", "client_epoch", "run_id", "gateway_request_id", "execution_hash", "nonce_hash", "bundle_digest", "request_digest", "created_at"} {
		if _, ok := columns[column]; !ok {
			t.Fatalf("column %s is absent: %v", column, columns)
		}
	}
	constraints := pgTableConstraints(t, store, "narthex_library_run_correlations")
	for name, want := range map[string]pgConstraint{
		"narthex_library_run_correlations_pkey":                 {kind: "p"},
		"narthex_library_run_correlations_tuple_unique":         {kind: "u"},
		"narthex_library_run_correlations_nonce_unique":         {kind: "u"},
		"narthex_library_run_correlations_execution_hash_check": {kind: "c"},
		"narthex_library_run_correlations_nonce_hash_check":     {kind: "c"},
		"narthex_library_run_correlations_bundle_digest_check":  {kind: "c"},
		"narthex_library_run_correlations_request_digest_check": {kind: "c"},
	} {
		got, ok := constraints[name]
		if !ok || got.kind != want.kind {
			t.Fatalf("constraint %s=%+v; want %+v (all: %v)", name, got, want, constraints)
		}
	}
	var foreignKeys int
	for _, constraint := range constraints {
		if constraint.kind != "f" {
			continue
		}
		foreignKeys++
		if constraint.referenced != "narthex_mcp_clients" || constraint.onDelete != "r" {
			t.Fatalf("client foreign key=%+v; want RESTRICT on narthex_mcp_clients", constraint)
		}
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign keys=%d; want exactly the client reference", foreignKeys)
	}
	var indexExists bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname='narthex_library_run_correlations_created_idx')`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("created index exists=%t err=%v", indexExists, err)
	}

	// Skill slugs accept only lowercase alphanumerics and hyphens, so strip the
	// epoch's URL-safe base64 punctuation before using it as a suffix.
	suffix := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, strings.ToLower(newEpoch()))
	var (
		client MCPClient
		skill  LibrarySkill
	)
	defer func() {
		cleanup := context.Background()
		if client.ID != "" {
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_run_correlations WHERE client_id=$1`, client.ID)
		}
		if skill.ID != "" {
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_library_skills WHERE id=$1`, skill.ID)
		}
		if client.ID != "" {
			_, _ = store.pool.Exec(cleanup, `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
		}
	}()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err = store.CreateMCPClient(ctx, MCPClient{
		Name: "PG run correlation " + suffix, Subject: "usr_pg_correlation", CreatedBy: "usr_pg_correlation",
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public),
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	var initial LibrarySkillVersion
	skill, initial, err = store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-correlation-" + suffix, Name: "PG correlation skill", Description: "correlation fixture", CreatedBy: "usr_pg_correlation",
	}, LibrarySkillVersion{Content: "# PG correlation instructions", RequestedCapabilities: []string{"alerts.read"}, CreatedBy: "usr_pg_correlation"})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion: %v", err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: initial.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "usr_pg_correlation",
	}); err != nil {
		t.Fatalf("UpsertLibrarySkillBinding: %v", err)
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}

	base := time.Now().UTC().Truncate(time.Millisecond)
	records := exerciseLibraryRunCorrelationStore(t, ctx, store, client, skill, bundle, base)

	// Raw columns hold only scoped hashes, and the relational fences hold
	// without the application's pre-checks.
	var executionHash, nonceHash, requestDigest string
	if err := store.pool.QueryRow(ctx, `SELECT execution_hash,nonce_hash,request_digest FROM narthex_library_run_correlations WHERE id=$1`, records[len(records)-1].ID).Scan(&executionHash, &nonceHash, &requestDigest); err != nil ||
		executionHash != libraryRunCorrelationExecutionHash(client.ID, client.Epoch, "exec_secret_a") || nonceHash != libraryRunCorrelationNonceHash(client.ID, client.Epoch, runCorrelationNonce(50)) || !libraryDigestPattern.MatchString(requestDigest) {
		t.Fatalf("stored hashes execution=%q nonce=%q request=%q err=%v", executionHash, nonceHash, requestDigest, err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23503") {
		t.Fatalf("deleting a client with correlations err=%v; want FK RESTRICT violation", err)
	}
	insert := `INSERT INTO narthex_library_run_correlations (id,client_id,client_epoch,run_id,gateway_request_id,execution_hash,nonce_hash,bundle_digest,request_digest,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())`
	oldest := records[len(records)-1]
	for name, test := range map[string]struct {
		args []any
		code string
	}{
		"duplicate tuple": {[]any{"lrc_dup_" + suffix, client.ID, client.Epoch, oldest.RunID, oldest.GatewayRequestID, "", libraryDigest("fresh nonce"), oldest.BundleDigest, libraryDigest("fresh request")}, "23505"},
		"duplicate nonce": {[]any{"lrc_dupnonce_" + suffix, client.ID, client.Epoch, "run_fresh", "greq_fresh", "", oldest.NonceHash, oldest.BundleDigest, libraryDigest("fresh request 2")}, "23505"},
		"non-hex nonce":   {[]any{"lrc_badnonce_" + suffix, client.ID, client.Epoch, "run_fresh", "greq_fresh", "", "not-a-hash", oldest.BundleDigest, libraryDigest("fresh request 3")}, "23514"},
		"non-hex digest":  {[]any{"lrc_baddigest_" + suffix, client.ID, client.Epoch, "run_fresh", "greq_fresh", "", libraryDigest("fresh nonce 3"), "NOTHEX", libraryDigest("fresh request 4")}, "23514"},
		"non-hex exec":    {[]any{"lrc_badexec_" + suffix, client.ID, client.Epoch, "run_fresh", "greq_fresh", "plain-execution-id", libraryDigest("fresh nonce 4"), oldest.BundleDigest, libraryDigest("fresh request 5")}, "23514"},
		"unknown client":  {[]any{"lrc_orphan_" + suffix, "mcpcli_missing_" + suffix, client.Epoch, "run_fresh", "greq_fresh", "", libraryDigest("fresh nonce 5"), oldest.BundleDigest, libraryDigest("fresh request 6")}, "23503"},
	} {
		if _, err := store.pool.Exec(ctx, insert, test.args...); err == nil || !strings.Contains(err.Error(), "SQLSTATE "+test.code) {
			t.Fatalf("%s insert err=%v; want SQLSTATE %s", name, err, test.code)
		}
	}

	// A fresh store reads the same durable feed rather than a process-local
	// projection.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	page, err := reopened.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var mine []LibraryRunCorrelation
	for _, record := range page {
		if record.ClientID == client.ID {
			mine = append(mine, record)
		}
	}
	if len(mine) != len(records) {
		t.Fatalf("reopened feed=%d records; want %d", len(mine), len(records))
	}
	for i := range records {
		if mine[i].ID != records[i].ID || !mine[i].CreatedAt.Equal(records[i].CreatedAt) || mine[i].NonceHash != records[i].NonceHash {
			t.Fatalf("reopened record %d=%+v; want %+v", i, mine[i], records[i])
		}
	}
}

type pgConstraint struct {
	kind       string
	referenced string
	onDelete   string
}

func pgTableColumns(t *testing.T, store *PgStore, table string) map[string]string {
	t.Helper()
	rows, err := store.pool.Query(context.Background(), `
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema=current_schema() AND table_name=$1`, table)
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	defer rows.Close()
	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			t.Fatal(err)
		}
		columns[name] = dataType
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

func pgTableConstraints(t *testing.T, store *PgStore, table string) map[string]pgConstraint {
	t.Helper()
	rows, err := store.pool.Query(context.Background(), `
SELECT c.conname, c.contype::text, COALESCE(r.relname, ''), c.confdeltype::text
FROM pg_constraint c
LEFT JOIN pg_class r ON r.oid = c.confrelid
WHERE c.conrelid = $1::regclass`, table)
	if err != nil {
		t.Fatalf("constraints of %s: %v", table, err)
	}
	defer rows.Close()
	constraints := map[string]pgConstraint{}
	for rows.Next() {
		var name string
		var constraint pgConstraint
		if err := rows.Scan(&name, &constraint.kind, &constraint.referenced, &constraint.onDelete); err != nil {
			t.Fatal(err)
		}
		constraints[name] = constraint
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return constraints
}
