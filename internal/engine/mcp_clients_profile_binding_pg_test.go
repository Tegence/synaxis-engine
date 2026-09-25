package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgStoreMCPClientProfileBindingSchemaAndParity proves the idempotent
// ALTER TABLE migration installs the four binding columns and the all-or-
// nothing CHECK, and that PgStore upholds the FileStore invariants.
func TestPgStoreMCPClientProfileBindingSchemaAndParity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client profile-binding integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	columns := pgTableColumns(t, store, "narthex_mcp_clients")
	for column, dataType := range map[string]string{
		"agent_profile_id":            "text",
		"agent_profile_revision":      "bigint",
		"agent_profile_policy_digest": "text",
		"agent_profile_bound_at":      "timestamp with time zone",
	} {
		if got := columns[column]; got != dataType {
			t.Fatalf("column %s type=%q; want %q (all: %v)", column, got, dataType, columns)
		}
	}
	var definition string
	if err := store.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint
WHERE conname='narthex_mcp_clients_agent_profile_check' AND conrelid='narthex_mcp_clients'::regclass`).Scan(&definition); err != nil {
		t.Fatalf("agent profile constraint: %v", err)
	}
	if !strings.Contains(definition, "[a-f0-9]{64}") || !strings.Contains(definition, "agent_profile_bound_at IS NULL") {
		t.Fatalf("agent profile constraint definition=%q", definition)
	}

	suffix := strings.ToLower(newEpoch())
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "PG bound " + suffix, Subject: "usr_pg_bound", CreatedBy: "usr_pg_bound"})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	defer func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
	}()
	var (
		rawProfileID string
		rawRevision  int64
		rawDigest    string
		rawBoundAt   *time.Time
	)
	if err := store.pool.QueryRow(ctx, `SELECT agent_profile_id,agent_profile_revision,agent_profile_policy_digest,agent_profile_bound_at FROM narthex_mcp_clients WHERE id=$1`, client.ID).Scan(&rawProfileID, &rawRevision, &rawDigest, &rawBoundAt); err != nil ||
		rawProfileID != "" || rawRevision != 0 || rawDigest != "" || rawBoundAt != nil {
		t.Fatalf("new client binding columns=%q %d %q %v err=%v; want blank", rawProfileID, rawRevision, rawDigest, rawBoundAt, err)
	}

	final := exerciseMCPClientProfileBinding(t, ctx, store, client)

	if err := store.pool.QueryRow(ctx, `SELECT agent_profile_id,agent_profile_revision,agent_profile_policy_digest,agent_profile_bound_at FROM narthex_mcp_clients WHERE id=$1`, client.ID).Scan(&rawProfileID, &rawRevision, &rawDigest, &rawBoundAt); err != nil ||
		rawProfileID != final.AgentProfileBinding.ProfileID || rawRevision != final.AgentProfileBinding.ProfileRevision || rawDigest != final.AgentProfileBinding.PolicyDigest ||
		rawBoundAt == nil || !rawBoundAt.Equal(final.AgentProfileBinding.BoundAt) {
		t.Fatalf("stored binding columns=%q %d %q %v err=%v; want %+v", rawProfileID, rawRevision, rawDigest, rawBoundAt, err, final.AgentProfileBinding)
	}

	// The CHECK refuses half-bound rows and non-canonical digests even when
	// the application layer is bypassed.
	for name, statement := range map[string]string{
		"blank id with revision":  `UPDATE narthex_mcp_clients SET agent_profile_id='' WHERE id=$1`,
		"revision zero":           `UPDATE narthex_mcp_clients SET agent_profile_revision=0 WHERE id=$1`,
		"uppercase digest":        `UPDATE narthex_mcp_clients SET agent_profile_policy_digest=upper(agent_profile_policy_digest) WHERE id=$1`,
		"short digest":            `UPDATE narthex_mcp_clients SET agent_profile_policy_digest='abc' WHERE id=$1`,
		"bound_at cleared":        `UPDATE narthex_mcp_clients SET agent_profile_bound_at=NULL WHERE id=$1`,
		"unbound with bound_at":   `UPDATE narthex_mcp_clients SET agent_profile_id='',agent_profile_revision=0,agent_profile_policy_digest='' WHERE id=$1`,
		"unbound with profile id": `UPDATE narthex_mcp_clients SET agent_profile_revision=0,agent_profile_policy_digest='',agent_profile_bound_at=NULL WHERE id=$1`,
	} {
		if _, err := store.pool.Exec(ctx, statement, client.ID); err == nil || !strings.Contains(err.Error(), "SQLSTATE 23514") {
			t.Fatalf("%s err=%v; want CHECK violation", name, err)
		}
	}

	// A fresh store reads the same durable binding rather than a process-local
	// projection.
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	current, ok := reopened.MCPClient(ctx, client.ID)
	if !ok || current.Status != MCPClientStatusRevoked || current.Epoch != final.Epoch || current.Revision != final.Revision || !sameMCPClientProfileBinding(current.AgentProfileBinding, final.AgentProfileBinding) {
		t.Fatalf("reopened=%+v binding=%+v; want %+v binding=%+v", current, current.AgentProfileBinding, final, final.AgentProfileBinding)
	}
}
