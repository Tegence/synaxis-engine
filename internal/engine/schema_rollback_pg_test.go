package engine

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These contracts cover THE RULE in store_pg.go (below libraryMigrate): every
// CHECK that schema bootstrap re-adds goes through engineReappliedChecks, so
// the previous Engine release can start over rows a newer release wrote, while
// fresh installs and forward starts end fully VALIDATED. Each test bootstraps
// a fresh, private schema of the TEST_DATABASE_URL database, so they start
// from a clean install and never leave the shared tables with a narrowed or
// NOT VALID constraint.

const (
	rollbackAuditTable    = "narthex_library_mcp_client_skill_authoring_audit_events"
	rollbackAuditCheck    = "narthex_library_mcp_client_skill_authoring_audit_events_operation_check"
	rollbackFormatTable   = "narthex_library_artifact_versions"
	rollbackFormatCheck   = "narthex_library_artifact_versions_format_check"
	rollbackMediaTable    = "narthex_library_artifact_media_blobs"
	rollbackMediaCheck    = "narthex_library_artifact_media_blobs_size_check"
	rollbackLeaseTable    = "narthex_library_mcp_client_skill_authoring_leases"
	rollbackLeaseCheck    = "narthex_library_mcp_client_skill_authoring_leases_kind_check"
	rollbackClientID      = "mcpcli_schema_rollback"
	rollbackClientEpoch   = "epoch-schema-rollback"
	rollbackArtifactID    = "libart_schema_rollback"
	rollbackNotValidEntry = "left NOT VALID"
)

func TestPgStoreSchemaReappliedChecksEndValidated(t *testing.T) {
	dsn := freshEnginePgSchemaDSN(t)
	ctx := context.Background()
	oids := map[string]uint32{}
	// A clean install, then the restart every replica performs.
	for start := 1; start <= 2; start++ {
		store, err := NewPgStore(ctx, dsn)
		if err != nil {
			t.Fatalf("start %d: NewPgStore: %v", start, err)
		}
		for _, check := range engineReappliedChecks {
			state := onlyEngineSchemaConstraint(t, ctx, store, check.constraint)
			if state.table != check.table || state.kind != "c" {
				t.Errorf("start %d: %s is %+v, want a CHECK on %s", start, check.constraint, state, check.table)
			}
			if !state.validated || strings.Contains(state.definition, "NOT VALID") {
				t.Errorf("start %d: %s is not VALIDATED: %s", start, check.constraint, state.definition)
			}
			// The constraint records this release's expression, so a restart
			// keeps it instead of re-adding it.
			if state.comment != check.appliedComment() {
				t.Errorf("start %d: %s records %q, want %q", start, check.constraint, state.comment, check.appliedComment())
			}
			if start == 1 {
				oids[check.constraint] = state.oid
			} else if oids[check.constraint] != state.oid {
				t.Errorf("start %d: %s was re-added although it records this release's expression", start, check.constraint)
			}
		}
		assertEngineNotValidConstraints(t, ctx, store)
		store.Close()
	}
}

// A start re-adds a listed constraint whenever the stored one is not this
// release's, however close it is: a previous release's list that lacked one of
// this release's values or used another limit, whether that release recorded
// its expression or was built before this rule and recorded nothing. A check
// that recognized "its" definition loosely would keep the old list on an
// upgraded database while fresh installs got the new one.
func TestPgStoreSchemaReappliesChangedExpressions(t *testing.T) {
	dsn := freshEnginePgSchemaDSN(t)
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	fresh := map[string]string{}
	variants := map[string][]string{}
	rounds := 0
	for _, check := range engineReappliedChecks {
		fresh[check.constraint] = onlyEngineSchemaConstraint(t, ctx, store, check.constraint).definition
		variants[check.constraint] = previousCheckExpressions(check.expression)
		if len(variants[check.constraint]) == 0 {
			t.Fatalf("%s: no previous expression derives from %s", check.constraint, check.expression)
		}
		rounds = max(rounds, len(variants[check.constraint]))
	}
	store.Close()

	for round := 0; round < rounds; round++ {
		// Even rounds stand in for a previous release that recorded its
		// expression, odd rounds for a binary that re-added a plain
		// constraint. Both are written directly, so that what this release's
		// helper decides cannot also decide what the previous release left.
		recorded := round%2 == 0
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range engineReappliedChecks {
			list := variants[check.constraint]
			previous := reappliedCheck{table: check.table, constraint: check.constraint, expression: list[round%len(list)]}
			statements := `
ALTER TABLE ` + previous.table + ` DROP CONSTRAINT IF EXISTS ` + previous.constraint + `;
ALTER TABLE ` + previous.table + ` ADD CONSTRAINT ` + previous.constraint + ` CHECK (` + previous.expression + `);`
			if recorded {
				statements += `
COMMENT ON CONSTRAINT ` + previous.constraint + ` ON ` + previous.table + ` IS ` + quoteSQLLiteral(previous.appliedComment()) + `;`
			}
			if _, err := conn.Exec(ctx, statements); err != nil {
				_ = conn.Close(ctx)
				t.Fatalf("round %d: apply %s: %v", round, previous.expression, err)
			}
		}
		_ = conn.Close(ctx)

		store, err := NewPgStore(ctx, dsn)
		if err != nil {
			t.Fatalf("round %d: this release over the previous expressions: %v", round, err)
		}
		for _, check := range engineReappliedChecks {
			state := onlyEngineSchemaConstraint(t, ctx, store, check.constraint)
			previous := variants[check.constraint][round%len(variants[check.constraint])]
			if state.definition != fresh[check.constraint] || !state.validated || state.comment != check.appliedComment() {
				t.Errorf("round %d (recorded=%t): %s kept the previous expression %s: definition %s, validated=%t, comment %q; want %s",
					round, recorded, check.constraint, previous, state.definition, state.validated, state.comment, fresh[check.constraint])
			}
		}
		assertEngineNotValidConstraints(t, ctx, store)
		store.Close()
	}
}

func TestPgStoreSchemaRollbackLeavesNarrowerCheckNotValid(t *testing.T) {
	dsn := freshEnginePgSchemaDSN(t)
	ctx := context.Background()
	logs := captureEngineLog(t)

	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	seedSchemaRollbackFixtures(t, ctx, store)

	// The next release widens every re-applied list and starts forward. Its
	// copy of engineReappliedChecks is this one with the wider lists.
	newer := widenedReappliedChecks(t)
	if err := reapplyCheckConstraints(ctx, store.pool, newer); err != nil {
		t.Fatalf("newer release forward start: %v", err)
	}
	assertEngineCheck(t, ctx, store, rollbackAuditCheck, true, "'publish'", "")
	assertEngineCheck(t, ctx, store, rollbackFormatCheck, true, "'pdf'", "")
	assertEngineCheck(t, ctx, store, rollbackMediaCheck, true, "1048576", "524288")
	assertEngineCheck(t, ctx, store, rollbackLeaseCheck, true, "'transfer'", "")
	assertEngineNotValidConstraints(t, ctx, store)

	// It stores rows that only its lists admit.
	mustSucceed(t, insertRollbackAuditEvent(ctx, store, "newer-publish", "publish"))
	mustSucceed(t, insertRollbackLease(ctx, store, "newer-transfer", "transfer"))
	mustSucceed(t, insertRollbackArtifactVersion(ctx, store, "newer-pdf", 2, "pdf"))
	mustSucceed(t, insertRollbackArtifactVersion(ctx, store, "newer-large", 3, "image"))
	mustSucceed(t, insertRollbackMediaBlob(ctx, store, "newer-large", 600000))
	// Like every hosted Engine, it encrypts private fields at rest.
	cipher := testCipher(t, 83)
	newerRows := encryptRollbackNewerRows(t, ctx, store, cipher)
	store.Close()

	// The limitation this rule removes: this release's re-add as it used to
	// be written, one simple-protocol batch with a plain validating ADD
	// CONSTRAINT, fails over the newer rows and rolls back whole.
	old := findReappliedCheck(t, engineReappliedChecks, rollbackAuditCheck)
	rigid, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rigid.Exec(ctx, `
ALTER TABLE `+rollbackAuditTable+` DROP CONSTRAINT IF EXISTS `+rollbackAuditCheck+`;
ALTER TABLE `+rollbackAuditTable+` ADD CONSTRAINT `+rollbackAuditCheck+` CHECK (`+old.expression+`);`)
	_ = rigid.Close(ctx)
	expectEngineCheckViolation(t, err, rollbackAuditCheck)

	// This release starts over the newer rows, and restarts. Each start
	// leaves exactly the constraints whose rows its lists reject NOT VALID
	// and logs each of them.
	wantNotValid := []string{rollbackAuditCheck, rollbackFormatCheck, rollbackMediaCheck, rollbackLeaseCheck}
	for start := 1; start <= 2; start++ {
		logs.Reset()
		store, err = NewPgStore(ctx, dsn)
		if err != nil {
			t.Fatalf("this release over newer rows, start %d: %v", start, err)
		}
		assertEngineCheck(t, ctx, store, rollbackAuditCheck, false, "'upload'", "'publish'")
		assertEngineCheck(t, ctx, store, rollbackMediaCheck, false, "524288", "1048576")
		assertEngineCheck(t, ctx, store, rollbackLeaseCheck, false, "'adoption'", "'transfer'")
		assertEngineCheck(t, ctx, store, rollbackFormatCheck, false, "'image'", "'pdf'")
		assertEngineNotValidConstraints(t, ctx, store, wantNotValid...)
		assertNotValidLogLines(t, logs.String(), wantNotValid)
		if start == 1 {
			// Rule 6: the startup encryption migration that follows NewPgStore
			// rewrites only rows it changes, so it completes over newer rows
			// that the narrower NOT VALID checks reject. Rewriting one of them
			// unchanged would fail.
			_, err = store.pool.Exec(ctx, `UPDATE `+rollbackMediaTable+` SET alt_text=alt_text WHERE artifact_version_id=$1`, "libartv_schema_rollback_newer-large")
			expectEngineCheckViolation(t, err, rollbackMediaCheck)
			store.SetCipher(cipher)
			if err := store.EncryptExisting(ctx); err != nil {
				t.Fatalf("this release's EncryptExisting over newer rows: %v", err)
			}
			if got := readRollbackMediaBlob(t, ctx, store, "newer-large"); got.altText != newerRows.media.altText || !bytes.Equal(got.data, newerRows.media.data) {
				t.Fatal("EncryptExisting rewrote an already encrypted newer media blob")
			}
			if got := readRollbackChangelog(t, ctx, store, "newer-pdf"); got != newerRows.pdfChangelog {
				t.Fatal("EncryptExisting rewrote an already encrypted newer artifact version")
			}
			store.Close()
		}
	}

	// New writes are still checked against this release's narrower lists.
	expectEngineCheckViolation(t, insertRollbackAuditEvent(ctx, store, "late-publish", "publish"), rollbackAuditCheck)
	mustSucceed(t, insertRollbackAuditEvent(ctx, store, "late-upload", "upload"))
	expectEngineCheckViolation(t, insertRollbackLease(ctx, store, "late-transfer", "transfer"), rollbackLeaseCheck)
	mustSucceed(t, insertRollbackLease(ctx, store, "late-adoption", "adoption"))
	mustSucceed(t, insertRollbackArtifactVersion(ctx, store, "late-large", 4, "image"))
	expectEngineCheckViolation(t, insertRollbackMediaBlob(ctx, store, "late-large", 600000), rollbackMediaCheck)
	mustSucceed(t, insertRollbackMediaBlob(ctx, store, "late-large", 1000))
	expectEngineCheckViolation(t, insertRollbackArtifactVersion(ctx, store, "late-pdf", 5, "pdf"), rollbackFormatCheck)
	mustSucceed(t, insertRollbackArtifactVersion(ctx, store, "late-text", 5, "text"))
	// The documented limitation: this release cannot update a newer row, even
	// in a column the constraint does not mention.
	_, err = store.pool.Exec(ctx, `UPDATE `+rollbackAuditTable+` SET actor_ref='rewritten' WHERE id=$1`, "aev_schema_rollback_newer-publish")
	expectEngineCheckViolation(t, err, rollbackAuditCheck)

	// Only check_violation is tolerated. Any other validation error fails the
	// re-add, which rolls back and leaves the constraint as it was.
	broken := reappliedCheck{table: rollbackAuditTable, constraint: rollbackAuditCheck, expression: `1 / (length(operation) - 5) = 0`}
	err = reapplyCheckConstraints(ctx, store.pool, []reappliedCheck{broken})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
		t.Fatalf("a division by zero during VALIDATE must fail the re-add, got %v", err)
	}
	assertEngineCheck(t, ctx, store, rollbackAuditCheck, false, "'upload'", "length")
	assertEngineNotValidConstraints(t, ctx, store, wantNotValid...)
	store.Close()

	// Rolling forward to the newer release validates every constraint again.
	store, err = openEngineSchemaPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := reapplyCheckConstraints(ctx, store.pool, newer); err != nil {
		t.Fatalf("roll forward: %v", err)
	}
	assertEngineCheck(t, ctx, store, rollbackAuditCheck, true, "'publish'", "")
	assertEngineCheck(t, ctx, store, rollbackFormatCheck, true, "'pdf'", "")
	assertEngineCheck(t, ctx, store, rollbackMediaCheck, true, "1048576", "")
	assertEngineCheck(t, ctx, store, rollbackLeaseCheck, true, "'transfer'", "")
	assertEngineNotValidConstraints(t, ctx, store)
	mustSucceed(t, insertRollbackAuditEvent(ctx, store, "forward-publish", "publish"))
	store.Close()

	// Roll back again, then clear the rows only the newer release admits. The
	// next start of this release validates, in place, every constraint that
	// an earlier start re-added with this release's expression and left NOT
	// VALID.
	store, err = NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("second rollback: %v", err)
	}
	assertEngineNotValidConstraints(t, ctx, store, wantNotValid...)
	lease := onlyEngineSchemaConstraint(t, ctx, store, rollbackLeaseCheck)
	for _, statement := range []string{
		`DELETE FROM ` + rollbackAuditTable + ` WHERE operation='publish'`,
		`DELETE FROM ` + rollbackLeaseTable + ` WHERE kind='transfer'`,
		`DELETE FROM ` + rollbackFormatTable + ` WHERE format='pdf'`,
		`DELETE FROM ` + rollbackMediaTable + ` WHERE size_bytes > 524288`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	store.Close()
	logs.Reset()
	store, err = NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("start after the newer rows are gone: %v", err)
	}
	defer store.Close()
	assertEngineCheck(t, ctx, store, rollbackAuditCheck, true, "'upload'", "'publish'")
	assertEngineCheck(t, ctx, store, rollbackMediaCheck, true, "524288", "")
	assertEngineCheck(t, ctx, store, rollbackLeaseCheck, true, "'adoption'", "'transfer'")
	assertEngineCheck(t, ctx, store, rollbackFormatCheck, true, "'image'", "'pdf'")
	assertEngineNotValidConstraints(t, ctx, store)
	assertNotValidLogLines(t, logs.String(), nil)
	if revalidated := onlyEngineSchemaConstraint(t, ctx, store, rollbackLeaseCheck); revalidated.oid != lease.oid {
		t.Errorf("the current lease kind check was re-added instead of validated in place")
	}
}

// freshEnginePgSchemaDSN creates an empty schema in the TEST_DATABASE_URL
// database and returns that DSN with search_path set to it, so Engine schema
// bootstrap runs there as a clean install. The schema is dropped on cleanup.
func freshEnginePgSchemaDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Engine schema rollback test")
	}
	ctx := context.Background()
	schema := "narthex_schema_test_" + newPgFixtureSuffix()
	identifier := pgx.Identifier{schema}.Sanitize()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, "CREATE SCHEMA "+identifier)
	_ = conn.Close(ctx)
	if err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("drop test schema %s: %v", schema, err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop test schema %s: %v", schema, err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return dsn + " search_path=" + schema
}

// openEngineSchemaPool opens a store on the test schema without running this
// release's bootstrap, standing in for a newer release's start: the test then
// applies that release's re-added checks by themselves.
func openEngineSchemaPool(ctx context.Context, dsn string) (*PgStore, error) {
	config, err := enginePostgresPoolConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return &PgStore{pool: pool}, nil
}

func widenedReappliedChecks(t *testing.T) []reappliedCheck {
	t.Helper()
	// Each entry replaces [0] with [1], admitting [2], which the fixture rows
	// use and this release must still reject.
	widen := map[string][3]string{
		rollbackAuditCheck:  {"'upload')", "'upload','publish')", "'publish'"},
		rollbackFormatCheck: {"'image')", "'image','pdf')", "'pdf'"},
		rollbackMediaCheck:  {"524288", "1048576", "1048576"},
		rollbackLeaseCheck:  {"'adoption')", "'adoption','transfer')", "'transfer'"},
	}
	var newer []reappliedCheck
	for _, check := range engineReappliedChecks {
		replacement, ok := widen[check.constraint]
		if !ok {
			newer = append(newer, check)
			continue
		}
		if strings.Contains(check.expression, replacement[2]) {
			t.Fatalf("%s already admits %s, so this contract can no longer use it as a newer release's value; pick one this release rejects: %s",
				check.constraint, replacement[2], check.expression)
		}
		widened := strings.Replace(check.expression, replacement[0], replacement[1], 1)
		if widened == check.expression {
			t.Fatalf("%s does not contain %s: %s", check.constraint, replacement[0], check.expression)
		}
		// The newer release re-adds its lists on its forward start.
		newer = append(newer, reappliedCheck{table: check.table, constraint: check.constraint, expression: widened})
		delete(widen, check.constraint)
	}
	if len(widen) != 0 {
		t.Fatalf("engineReappliedChecks no longer lists %v", widen)
	}
	return newer
}

func findReappliedCheck(t *testing.T, checks []reappliedCheck, constraint string) reappliedCheck {
	t.Helper()
	for _, check := range checks {
		if check.constraint == constraint {
			return check
		}
	}
	t.Fatalf("%s is not re-applied", constraint)
	return reappliedCheck{}
}

func seedSchemaRollbackFixtures(t *testing.T, ctx context.Context, store *PgStore) {
	t.Helper()
	mustSucceed(t, func() error {
		_, err := store.pool.Exec(ctx, `
INSERT INTO narthex_mcp_clients (id,slug,name,subject,epoch) VALUES ($1,'schema-rollback','Schema rollback','usr_schema_rollback',$2)`,
			rollbackClientID, rollbackClientEpoch)
		return err
	}())
	mustSucceed(t, func() error {
		_, err := store.pool.Exec(ctx, `
INSERT INTO narthex_library_artifacts (id,title,origin) VALUES ($1,'Schema rollback','human')`, rollbackArtifactID)
		return err
	}())
	mustSucceed(t, insertRollbackArtifactVersion(ctx, store, "seed", 1, "markdown"))
	// A row whose operation makes the broken expression divide by zero.
	mustSucceed(t, insertRollbackAuditEvent(ctx, store, "seed-grant", "grant"))
	mustSucceed(t, insertRollbackLease(ctx, store, "seed-generic", "generic"))
}

func insertRollbackAuditEvent(ctx context.Context, store *PgStore, key, operation string) error {
	_, err := store.pool.Exec(ctx, `
INSERT INTO `+rollbackAuditTable+` (id,client_id,client_epoch,action,operation,created_at)
VALUES ($1,$2,$3,'granted',$4,now())`,
		"aev_schema_rollback_"+key, rollbackClientID, rollbackClientEpoch, operation)
	return err
}

func insertRollbackLease(ctx context.Context, store *PgStore, key, kind string) error {
	_, err := store.pool.Exec(ctx, `
INSERT INTO `+rollbackLeaseTable+` (id,client_id,client_epoch,granted_at,expires_at,remaining_creates,created_at,updated_at,kind)
VALUES ($1,$2,$3,now(),now() + interval '1 hour',1,now(),now(),$4)`,
		"lease_schema_rollback_"+key, rollbackClientID, rollbackClientEpoch, kind)
	return err
}

func insertRollbackArtifactVersion(ctx context.Context, store *PgStore, key string, number int, format string) error {
	_, err := store.pool.Exec(ctx, `
INSERT INTO `+rollbackFormatTable+` (id,artifact_id,version_number,format,digest,size_bytes)
VALUES ($1,$2,$3,$4,$5,1)`,
		"libartv_schema_rollback_"+key, rollbackArtifactID, number, format, strings.Repeat("a", 64))
	return err
}

func insertRollbackMediaBlob(ctx context.Context, store *PgStore, versionKey string, size int64) error {
	_, err := store.pool.Exec(ctx, `
INSERT INTO `+rollbackMediaTable+` (artifact_version_id,mime_type,digest,size_bytes,delivery_mode,encrypted_data)
VALUES ($1,'image/png',$2,$3,'inline','\x00'::bytea)`,
		"libartv_schema_rollback_"+versionKey, strings.Repeat("b", 64), size)
	return err
}

type rollbackMediaBlob struct {
	altText string
	data    []byte
}

// rollbackNewerRows are the encrypted private fields of the newer release's
// rows, as stored.
type rollbackNewerRows struct {
	media        rollbackMediaBlob
	pdfChangelog string
}

// encryptRollbackNewerRows gives the newer release's rows the encrypted
// private fields it writes, while its wider lists still admit an UPDATE of
// them, and returns the newer media blob and PDF version changelog as stored.
func encryptRollbackNewerRows(t *testing.T, ctx context.Context, store *PgStore, cipher *Cipher) rollbackNewerRows {
	t.Helper()
	actor, err := cipher.Encrypt("usr_schema_rollback_newer")
	mustSucceed(t, err)
	altText, err := cipher.Encrypt("newer release image")
	mustSucceed(t, err)
	data, err := cipher.EncryptBytes([]byte("newer release image bytes"))
	mustSucceed(t, err)
	changelog, err := cipher.Encrypt("newer release PDF version")
	mustSucceed(t, err)
	for _, write := range []struct {
		statement string
		args      []any
	}{
		{`UPDATE ` + rollbackAuditTable + ` SET actor_ref=$2 WHERE id=$1`, []any{"aev_schema_rollback_newer-publish", actor}},
		{`UPDATE ` + rollbackLeaseTable + ` SET granted_by=$2 WHERE id=$1`, []any{"lease_schema_rollback_newer-transfer", actor}},
		{`UPDATE ` + rollbackMediaTable + ` SET alt_text=$2,encrypted_data=$3 WHERE artifact_version_id=$1`, []any{"libartv_schema_rollback_newer-large", altText, data}},
		{`UPDATE ` + rollbackFormatTable + ` SET changelog=$2 WHERE id=$1`, []any{"libartv_schema_rollback_newer-pdf", changelog}},
	} {
		tag, err := store.pool.Exec(ctx, write.statement, write.args...)
		mustSucceed(t, err)
		if tag.RowsAffected() != 1 {
			t.Fatalf("%s updated %d rows, want 1", write.statement, tag.RowsAffected())
		}
	}
	return rollbackNewerRows{
		media:        readRollbackMediaBlob(t, ctx, store, "newer-large"),
		pdfChangelog: readRollbackChangelog(t, ctx, store, "newer-pdf"),
	}
}

func readRollbackMediaBlob(t *testing.T, ctx context.Context, store *PgStore, versionKey string) rollbackMediaBlob {
	t.Helper()
	var blob rollbackMediaBlob
	mustSucceed(t, store.pool.QueryRow(ctx, `SELECT alt_text,encrypted_data FROM `+rollbackMediaTable+` WHERE artifact_version_id=$1`,
		"libartv_schema_rollback_"+versionKey).Scan(&blob.altText, &blob.data))
	return blob
}

func readRollbackChangelog(t *testing.T, ctx context.Context, store *PgStore, versionKey string) string {
	t.Helper()
	var changelog string
	mustSucceed(t, store.pool.QueryRow(ctx, `SELECT changelog FROM `+rollbackFormatTable+` WHERE id=$1`,
		"libartv_schema_rollback_"+versionKey).Scan(&changelog))
	return changelog
}

func mustSucceed(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type engineSchemaConstraint struct {
	oid        uint32
	table      string
	kind       string
	validated  bool
	definition string
	comment    string
}

func onlyEngineSchemaConstraint(t *testing.T, ctx context.Context, store *PgStore, constraint string) engineSchemaConstraint {
	t.Helper()
	rows, err := store.pool.Query(ctx, `
SELECT c.oid, c.conrelid::regclass::text, c.contype::text, c.convalidated, pg_get_constraintdef(c.oid),
       coalesce(obj_description(c.oid, 'pg_constraint'), '')
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
WHERE n.nspname = current_schema() AND c.conname = $1::text`, storedPgIdentifier(constraint))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var states []engineSchemaConstraint
	for rows.Next() {
		var state engineSchemaConstraint
		if err := rows.Scan(&state.oid, &state.table, &state.kind, &state.validated, &state.definition, &state.comment); err != nil {
			t.Fatal(err)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("constraint %s exists %d times, want exactly once: %+v", constraint, len(states), states)
	}
	return states[0]
}

// assertEngineCheck checks a CHECK's validation state and that its stored
// definition lists present (when set) and not absent (when set).
func assertEngineCheck(t *testing.T, ctx context.Context, store *PgStore, constraint string, validated bool, present, absent string) {
	t.Helper()
	state := onlyEngineSchemaConstraint(t, ctx, store, constraint)
	if state.kind != "c" || state.validated != validated {
		t.Fatalf("%s: kind=%s validated=%t, want CHECK validated=%t (%s)", constraint, state.kind, state.validated, validated, state.definition)
	}
	if strings.HasSuffix(state.definition, "NOT VALID") == validated {
		t.Fatalf("%s definition disagrees with convalidated=%t: %s", constraint, validated, state.definition)
	}
	if present != "" && !strings.Contains(state.definition, present) {
		t.Fatalf("%s definition should list %s: %s", constraint, present, state.definition)
	}
	if absent != "" && strings.Contains(state.definition, absent) {
		t.Fatalf("%s definition should not list %s: %s", constraint, absent, state.definition)
	}
}

// assertEngineNotValidConstraints compares every NOT VALID constraint in the
// test schema with want.
func assertEngineNotValidConstraints(t *testing.T, ctx context.Context, store *PgStore, want ...string) {
	t.Helper()
	rows, err := store.pool.Query(ctx, `
SELECT c.conname::text
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
WHERE n.nspname = current_schema() AND NOT c.convalidated
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var stored []string
	for _, name := range want {
		stored = append(stored, storedPgIdentifier(name))
	}
	sort.Strings(stored)
	if strings.Join(got, ",") != strings.Join(stored, ",") {
		t.Fatalf("NOT VALID constraints = %v, want %v", got, stored)
	}
}

// assertNotValidLogLines checks that the start logged exactly one NOT VALID
// line per constraint in want, naming the constraint and its table.
func assertNotValidLogLines(t *testing.T, output string, want []string) {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, rollbackNotValidEntry) {
			lines = append(lines, line)
		}
	}
	if len(lines) != len(want) {
		t.Fatalf("NOT VALID log lines = %q, want one for each of %v", lines, want)
	}
	for _, constraint := range want {
		check := findReappliedCheck(t, engineReappliedChecks, constraint)
		wantLine := "engine: schema constraint " + storedPgIdentifier(constraint) + " on " + check.table + " " + rollbackNotValidEntry
		found := false
		for _, line := range lines {
			found = found || strings.Contains(line, wantLine)
		}
		if !found {
			t.Fatalf("no log line %q in %q", wantLine, lines)
		}
	}
}

func expectEngineCheckViolation(t *testing.T, err error, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != storedPgIdentifier(constraint) {
		t.Fatalf("want check_violation on %s, got %v", constraint, err)
	}
}

// syncLogBuffer collects the standard logger's output. The store's background
// audit writer may log concurrently with the test reading it.
type syncLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *syncLogBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffer.Reset()
}

func captureEngineLog(t *testing.T) *syncLogBuffer {
	t.Helper()
	buffer := &syncLogBuffer{}
	previous := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buffer
}
