package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPgLibraryMCPClientSkillAuthoringLeaseAtomicReplayAndEncryptedActors(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library skill authoring lease integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)

	suffix := strings.ToLower(newEpoch())
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "PG authoring lease " + suffix, Subject: "usr_pg_authoring_" + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-pg-authoring-"+suffix, MCPClientPrecondition{
		ID: client.ID, Revision: client.Revision,
	}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("bind MCP client OAuth identity: %v", err)
	}
	lease, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner")
	if err != nil {
		t.Fatalf("grant lease: %v", err)
	}
	var storedGrantActor string
	if err := store.pool.QueryRow(ctx, `SELECT granted_by FROM narthex_library_mcp_client_skill_authoring_leases WHERE id=$1`, lease.ID).Scan(&storedGrantActor); err != nil {
		t.Fatal(err)
	}
	if storedGrantActor == "usr_pg_owner" || !strings.HasPrefix(storedGrantActor, encPrefix) {
		t.Fatalf("lease grant actor was not encrypted at rest: %q", storedGrantActor)
	}
	var storedAuditActor string
	if err := store.pool.QueryRow(ctx, `SELECT actor_ref FROM narthex_library_mcp_client_skill_authoring_audit_events WHERE client_id=$1 AND action='granted' ORDER BY created_at,id LIMIT 1`, client.ID).Scan(&storedAuditActor); err != nil {
		t.Fatal(err)
	}
	if storedAuditActor == "usr_pg_owner" || !strings.HasPrefix(storedAuditActor, encPrefix) {
		t.Fatalf("audit actor was not encrypted at rest: %q", storedAuditActor)
	}

	request := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "pg-authoring-request", Name: "PG leased skill " + suffix, Content: "# PG leased instructions", RequestedCapabilities: []string{"repository.read"},
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("create leased skill: %v", err)
	}
	if created.Replayed || created.Skill.CreatedBy != client.Subject || created.Version.CreatedBy != client.Subject || created.Lease.RemainingCreates != 2 {
		t.Fatalf("created result=%+v", created)
	}
	bindings, err := store.LibrarySkillBindings(ctx, created.Skill.ID)
	if err != nil || len(bindings) != 0 {
		t.Fatalf("leased skill bindings=%#v err=%v", bindings, err)
	}
	replay, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil || !replay.Replayed || replay.Skill.ID != created.Skill.ID || replay.Lease.RemainingCreates != 2 {
		t.Fatalf("leased replay=%+v err=%v", replay, err)
	}
	changed := request
	changed.Content = "# changed"
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("changed replay error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringRequestConflict)
	}
	listed, listLease, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || listLease.RemainingCreates != 2 || len(listed) != 1 || listed[0].SkillID != created.Skill.ID ||
		listed[0].LatestVersionID != created.Version.ID || listed[0].LatestVersionDigest != created.Version.Digest {
		t.Fatalf("authored-skill list=%#v lease=%+v err=%v", listed, listLease, err)
	}
	update := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-authoring-update", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# PG updated instructions", RequestedCapabilities: []string{"repository.read", "repository.write"},
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update)
	if err != nil {
		t.Fatalf("update leased skill: %v", err)
	}
	if updated.Replayed || updated.Skill.ID != created.Skill.ID || updated.Version.Version != 2 || updated.Version.Content != update.Content ||
		updated.Lease.RemainingCreates != 1 {
		t.Fatalf("updated result=%+v", updated)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID || replay.Lease.RemainingCreates != 1 {
		t.Fatalf("updated replay=%+v err=%v", replay, err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "pg-authoring-bound-" + suffix,
		Mode: LibraryBindingModeTrack, CreatedBy: "usr_pg_owner",
	}); err != nil {
		t.Fatalf("bind updated skill: %v", err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-authoring-bound-update", SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# must not update bound skill",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("bound update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("bound skill leaked into authored list=%#v err=%v", listed, err)
	}
	if _, err := store.RevokeMCPClientSkillAuthoringLease(ctx, client.ID, "libmcpal_stale", MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseNotFound) {
		t.Fatalf("stale revoke error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringLeaseNotFound)
	}
	if _, err := store.RevokeMCPClientSkillAuthoringLease(ctx, client.ID, lease.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); err != nil {
		t.Fatalf("revoke lease: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "after-pg-revoke", Name: "Blocked PG skill", Content: "# blocked",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("create after revoke error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationGrant) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpdate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationRevoke) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationCreate) < 2 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationUpdate) < 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationRevoke) != 1 {
		t.Fatalf("Pg authoring audit events=%#v", events)
	}
}
