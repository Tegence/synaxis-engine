package engine

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgStoreControlIdempotencySchemaAndParity proves the idempotent DDL
// installs the keyed-result table with its primary key and CHECKs, and that
// PgStore upholds the FileStore invariants.
func TestPgStoreControlIdempotencySchemaAndParity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres control idempotency integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	columns := pgTableColumns(t, store, "narthex_control_idempotency")
	for column, dataType := range map[string]string{
		"idempotency_key": "text", "resource_path": "text", "actor_ref": "text", "body_digest": "text",
		"response_status": "integer", "response_body": "bytea", "created_at": "timestamp with time zone", "expires_at": "timestamp with time zone",
	} {
		if got := columns[column]; got != dataType {
			t.Fatalf("column %s type=%q; want %q (all: %v)", column, got, dataType, columns)
		}
	}
	constraints := pgTableConstraints(t, store, "narthex_control_idempotency")
	for name, kind := range map[string]string{
		"narthex_control_idempotency_pkey":              "p",
		"narthex_control_idempotency_body_digest_check": "c",
		"narthex_control_idempotency_status_check":      "c",
		"narthex_control_idempotency_expiry_check":      "c",
	} {
		if got, ok := constraints[name]; !ok || got.kind != kind {
			t.Fatalf("constraint %s=%+v; want kind %q (all: %v)", name, got, kind, constraints)
		}
	}
	var indexExists bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname='narthex_control_idempotency_expires_idx')`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("expiry index exists=%t err=%v", indexExists, err)
	}

	prefix := "pg-" + strings.ToLower(newEpoch())
	defer func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_control_idempotency WHERE idempotency_key LIKE $1`, prefix+"%")
	}()
	exerciseControlIdempotencyStore(t, ctx, store, prefix)

	// The CHECKs hold when the application layer is bypassed.
	now := time.Now().UTC()
	insert := `INSERT INTO narthex_control_idempotency (idempotency_key,resource_path,actor_ref,body_digest,response_status,response_body,created_at,expires_at)
VALUES ($1,$2,'a',$3,$4,'{}',$5,$6)`
	for name, test := range map[string]struct {
		digest string
		status int
		expiry time.Time
	}{
		"digest": {"NOTHEX", http.StatusOK, now.Add(time.Hour)},
		"status": {libraryDigest("x"), http.StatusConflict, now.Add(time.Hour)},
		"expiry": {libraryDigest("x"), http.StatusOK, now},
	} {
		if _, err := store.pool.Exec(ctx, insert, prefix+"-raw-"+name, "/control/v1/mcp-clients", test.digest, test.status, now, test.expiry); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23514") {
			t.Fatalf("%s raw insert err=%v; want CHECK violation", name, err)
		}
	}

	// A fresh store reads the same durable records.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	for name, key := range map[string]string{"create": prefix + "-create", "expired identity reuse": prefix + "-expired", "actor": prefix + "-actor"} {
		if _, found, err := reopened.ControlIdempotencyRecord(ctx, key, "/control/v1/mcp-clients", now); err != nil || !found {
			t.Fatalf("%s record missing from reopened store: found=%t err=%v", name, found, err)
		}
	}
}
