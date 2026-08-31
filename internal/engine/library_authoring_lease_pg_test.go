package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
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
	if created.Replayed || created.BindingID == "" || created.Skill.CreatedBy != client.Subject || created.Version.CreatedBy != client.Subject || created.Lease.RemainingCreates != 2 {
		t.Fatalf("created result=%+v", created)
	}
	bindings, err := store.LibrarySkillBindings(ctx, created.Skill.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != created.BindingID ||
		bindings[0].ScopeKind != LibraryScopeAgentSurface || bindings[0].ScopeID != client.ID ||
		bindings[0].Mode != LibraryBindingModeTrack || bindings[0].CreatedBy != client.Subject ||
		!reflect.DeepEqual(bindings[0].CapabilityCeiling, []string{"repository.read"}) {
		t.Fatalf("leased skill automatic binding=%#v result=%+v err=%v", bindings, created, err)
	}
	replay, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil || !replay.Replayed || replay.Skill.ID != created.Skill.ID || replay.BindingID != created.BindingID || replay.Lease.RemainingCreates != 2 {
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
	if updated.Replayed || updated.Skill.ID != created.Skill.ID || updated.BindingID != created.BindingID || updated.Version.Version != 2 || updated.Version.Content != update.Content ||
		updated.Lease.RemainingCreates != 1 {
		t.Fatalf("updated result=%+v", updated)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID || replay.BindingID != created.BindingID || replay.Lease.RemainingCreates != 1 {
		t.Fatalf("updated replay=%+v err=%v", replay, err)
	}
	extraBinding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "pg-authoring-bound-" + suffix,
		Mode: LibraryBindingModeTrack, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("add transient binding: %v", err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, extraBinding.ID); err != nil {
		t.Fatalf("remove transient binding: %v", err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-authoring-bound-update", SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# must not update restored binding set",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored binding-set update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("restored binding set leaked into authored list=%#v err=%v", listed, err)
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

func TestPgLibraryMCPClientSkillAuthoringAdoptionPreservesBindingsAndFencesMutation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library skill authoring adoption integration test")
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
		Name: "PG adoption client " + suffix, Subject: "usr_pg_adoption_" + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-pg-adoption-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	skill, head, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-adoption-target-" + suffix, Name: "PG adoption target " + suffix, CreatedBy: "usr_pg_owner",
	}, LibrarySkillVersion{Content: "# PG adoption head", RequestedCapabilities: []string{"repository.read"}, CreatedBy: "usr_pg_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "pg-workspace-" + suffix, Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"repository.read"}, Priority: 3, CreatedBy: "usr_pg_owner",
	}); err != nil {
		t.Fatal(err)
	}

	lease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: skill.ID, ExpectedVersionID: head.ID, ExpectedVersionDigest: head.Digest,
	}, "usr_pg_owner")
	if err != nil {
		t.Fatalf("grant Pg adoption: %v", err)
	}
	if lease.Kind != LibraryMCPClientSkillAuthoringLeaseKindAdoption || lease.TargetBindingID == "" || lease.TargetVersionID != head.ID || lease.TargetBindingGeneration <= 0 {
		t.Fatalf("Pg adoption lease=%+v", lease)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skill.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("Pg adoption bindings=%#v err=%v", bindings, err)
	}
	var adopted LibrarySkillBinding
	for _, binding := range bindings {
		if binding.ID == lease.TargetBindingID {
			adopted = binding
		}
	}
	if !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(adopted, skill.ID, client.ID) || !reflect.DeepEqual(adopted.CapabilityCeiling, []string{"repository.read"}) {
		t.Fatalf("Pg adoption binding=%+v", adopted)
	}
	listed, listedLease, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || listedLease.ID != lease.ID || len(listed) != 1 || listed[0].SkillID != skill.ID || listed[0].LatestVersionID != head.ID {
		t.Fatalf("Pg adoption list=%#v lease=%+v err=%v", listed, listedLease, err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-adoption-widen-" + suffix, SkillID: skill.ID, ExpectedVersionID: head.ID, ExpectedVersionDigest: head.Digest,
		Content: "# PG widened adoption update", RequestedCapabilities: []string{"repository.write"},
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("Pg widened adoption update error=%v, want unavailable", err)
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-adoption-update-" + suffix, SkillID: skill.ID, ExpectedVersionID: head.ID, ExpectedVersionDigest: head.Digest,
		Content: "# PG adoption update", RequestedCapabilities: []string{"repository.read"},
	})
	if err != nil || updated.Version.Version != 2 || updated.BindingID != adopted.ID || updated.Lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates-1 {
		t.Fatalf("Pg adoption update=%+v err=%v", updated, err)
	}
	transient, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "pg-adoption-transient-" + suffix, Mode: LibraryBindingModeTrack,
		CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, skill.ID, transient.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-adoption-restored-binding-set-" + suffix, SkillID: skill.ID, ExpectedVersionID: updated.Version.ID, ExpectedVersionDigest: updated.Version.Digest,
		Content: "# blocked after binding restoration",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("Pg restored adoption binding-set update error=%v, want unavailable", err)
	}
	if _, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("Pg restored adoption binding-set list error=%v, want unavailable", err)
	}
	if _, err := store.RevokeMCPClientSkillAuthoringLease(ctx, client.ID, lease.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); err != nil {
		t.Fatal(err)
	}
	pinnedSkill, pinnedHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-adoption-pinned-" + suffix, Name: "PG adoption pinned " + suffix, CreatedBy: "usr_pg_owner",
	}, LibrarySkillVersion{Content: "# pinned", CreatedBy: "usr_pg_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: pinnedSkill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: pinnedHead.ID, CreatedBy: "usr_pg_owner",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: pinnedSkill.ID, ExpectedVersionID: pinnedHead.ID, ExpectedVersionDigest: pinnedHead.Digest,
	}, "usr_pg_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound) {
		t.Fatalf("Pg pinned adoption error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound)
	}
}

func TestPgLibraryMCPClientSkillAuthoringLegacyNoBindingDoesNotRegainAuthorityAfterBindingRestore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres legacy no-binding authoring regression test")
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
		Name: "PG legacy author " + suffix, Subject: "usr_pg_legacy_" + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-pg-legacy-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_pg_owner"); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "pg-legacy-create-" + suffix, Name: "PG legacy no-binding " + suffix, Content: "# Version one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, created.BindingID); err != nil {
		t.Fatal(err)
	}
	// Reconstruct a true pre-auto-binding database fixture: the durable create
	// receipt and the generation row both predate their respective columns.
	if _, err := store.pool.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_requests
SET binding_id='',binding_digest='',binding_generation=0
WHERE client_id=$1 AND client_epoch=$2 AND skill_id=$3 AND version_id=$4`,
		client.ID, client.Epoch, created.Skill.ID, created.Version.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, created.Skill.ID); err != nil {
		t.Fatal(err)
	}
	listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || len(listed) != 1 || listed[0].SkillID != created.Skill.ID {
		t.Fatalf("legacy no-binding Pg list=%#v err=%v", listed, err)
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-legacy-update-" + suffix, SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Version two",
	})
	if err != nil || updated.BindingID != "" {
		t.Fatalf("legacy no-binding Pg update=%+v err=%v", updated, err)
	}
	transient, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "pg-legacy-transient-" + suffix,
		Mode: LibraryBindingModeTrack, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, transient.ID); err != nil {
		t.Fatal(err)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("restored legacy Pg binding set remained authoring-eligible: skills=%#v err=%v", listed, err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "pg-legacy-restored-binding-update-" + suffix, SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# Must remain owner-managed",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored legacy Pg binding-set update error=%v, want unavailable", err)
	}
}
