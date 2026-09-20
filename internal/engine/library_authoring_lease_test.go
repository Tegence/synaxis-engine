package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func newAuthoringLeaseMCPClient(t *testing.T, store *FileStore, subject string) MCPClient {
	t.Helper()
	ctx := context.Background()
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Authoring client " + subject, Subject: subject, CreatedBy: subject,
	})
	if err != nil {
		t.Fatalf("create MCP client: %v", err)
	}
	bound, err := store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-"+newEpoch(), MCPClientPrecondition{
		ID: client.ID, Revision: client.Revision,
	}, PlatformActor{UserID: subject, Role: "operator"})
	if err != nil {
		t.Fatalf("bind MCP client OAuth identity: %v", err)
	}
	return bound
}

func countLibraryMCPClientSkillAuthoringAudit(events []LibraryMCPClientSkillAuthoringAuditEvent, action, operation string) int {
	count := 0
	for _, event := range events {
		if event.Action == action && event.Operation == operation {
			count++
		}
	}
	return count
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreIsAtomicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_author")
	lease, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{
		ID: client.ID, Revision: client.Revision,
	}, "usr_owner")
	if err != nil {
		t.Fatalf("grant authoring lease: %v", err)
	}
	if lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates || lease.Status != LibraryMCPClientSkillAuthoringLeaseStatusActive || lease.MCPClientEpoch != client.Epoch {
		t.Fatalf("granted lease = %+v", lease)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || len(events) != 1 || events[0].Action != LibraryMCPClientSkillAuthoringAuditActionGranted || events[0].Operation != LibraryMCPClientSkillAuthoringAuditOperationGrant || events[0].LeaseID != lease.ID || events[0].ActorRef != "usr_owner" {
		t.Fatalf("grant audit events=%#v err=%v", events, err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseActive) {
		t.Fatalf("second live grant error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringLeaseActive)
	}

	request := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "request-1", Name: "Client-created skill", Description: "Created through a lease",
		Content: "# Client instructions\nNever claim a credential.", RequestedCapabilities: []string{"repository.read", "repository.read"},
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("create leased skill: %v", err)
	}
	if created.Replayed || created.Lease.RemainingCreates != 2 || created.Skill.CreatedBy != client.Subject || created.Version.CreatedBy != client.Subject || created.Version.Digest != libraryDigest(request.Content) {
		t.Fatalf("created leased skill = %+v", created)
	}
	if len(created.Version.RequestedCapabilities) != 1 || created.Version.RequestedCapabilities[0] != "repository.read" {
		t.Fatalf("created skill capabilities = %v", created.Version.RequestedCapabilities)
	}
	bindings, err := store.LibrarySkillBindings(ctx, created.Skill.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != created.BindingID ||
		bindings[0].ScopeKind != LibraryScopeAgentSurface || bindings[0].ScopeID != client.ID ||
		bindings[0].Mode != LibraryBindingModeTrack || bindings[0].CreatedBy != client.Subject ||
		!reflect.DeepEqual(bindings[0].CapabilityCeiling, []string{"repository.read"}) {
		t.Fatalf("leased skill automatic binding=%#v result=%+v err=%v", bindings, created, err)
	}

	replayed, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("exact authoring retry: %v", err)
	}
	if !replayed.Replayed || replayed.Skill.ID != created.Skill.ID || replayed.Version.ID != created.Version.ID || replayed.BindingID != created.BindingID || replayed.Lease.RemainingCreates != 2 {
		t.Fatalf("authoring replay = %+v; first=%+v", replayed, created)
	}
	changed := request
	changed.Content = "# Changed after request id reuse"
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("changed request id reuse error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringRequestConflict)
	}

	if _, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "global-duplicate", Name: "Existing private skill", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Existing", CreatedBy: "usr_owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "duplicate-slug", Name: "Duplicate", Slug: "global-duplicate", Content: "# Must not create",
	}); !errors.Is(err, ErrLibrarySkillExists) {
		t.Fatalf("duplicate slug error=%v, want %v", err, ErrLibrarySkillExists)
	}
	current, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || current.RemainingCreates != 2 {
		t.Fatalf("duplicate consumed authoring quota lease=%+v found=%t err=%v", current, found, err)
	}

	for _, requestID := range []string{"request-2", "request-3"} {
		if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
			RequestID: requestID, Name: "Another " + requestID, Content: "# " + requestID,
		}); err != nil {
			t.Fatalf("consume authoring slot %q: %v", requestID, err)
		}
	}
	current, found, err = store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || current.RemainingCreates != 0 || current.Status != LibraryMCPClientSkillAuthoringLeaseStatusExhausted {
		t.Fatalf("exhausted authoring lease=%+v found=%t err=%v", current, found, err)
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "request-4", Name: "Too late", Content: "# too late",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("exhausted create error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	events, err = store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate) != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("consumed audit events=%#v", events)
	}
	if countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationCreate) < 3 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationGrant) != 1 {
		t.Fatalf("rejected audit events=%#v", events)
	}
	var consumed LibraryMCPClientSkillAuthoringAuditEvent
	for _, event := range events {
		if event.Action == LibraryMCPClientSkillAuthoringAuditActionConsumed && event.SkillID == created.Skill.ID {
			consumed = event
			break
		}
	}
	if consumed.LeaseID != lease.ID || consumed.ActorRef != client.Subject || consumed.VersionID != created.Version.ID || consumed.RequestIDHash == "" || consumed.RequestIDHash == request.RequestID || consumed.PayloadDigest == "" {
		t.Fatalf("consumed audit record=%+v", consumed)
	}
	// FileStore's audit receipt survives the same durable write as the state
	// transition; a reload must not lose a successful or rejected receipt.
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	reloadedEvents, err := reloaded.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || len(reloadedEvents) != len(events) {
		t.Fatalf("reloaded audit events=%#v err=%v; original=%#v", reloadedEvents, err, events)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreUpdatesOnlyExactAutomaticClientBinding(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_update_author")
	// A second client with the same subject proves that subject ownership alone
	// is insufficient: update/list authorization must use the exact client
	// origin receipt created with the initial version.
	otherClient := newAuthoringLeaseMCPClient(t, store, "usr_update_author")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "update-create", Name: "Client update candidate", Description: "Bound only to its creating client",
		Content: "# Version one", RequestedCapabilities: []string{"repository.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, listLease, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || listLease.RemainingCreates != 2 || len(listed) != 1 || listed[0].SkillID != created.Skill.ID ||
		listed[0].LatestVersionID != created.Version.ID || listed[0].LatestVersionDigest != created.Version.Digest {
		t.Fatalf("initial authored-skill list=%#v lease=%+v err=%v", listed, listLease, err)
	}
	activationV1, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil || len(activationV1.Skills) != 1 || activationV1.Skills[0].SkillID != created.Skill.ID ||
		activationV1.Skills[0].VersionID != created.Version.ID || activationV1.Skills[0].Instructions != created.Version.Content ||
		activationV1.Skills[0].Binding.ID != created.BindingID || activationV1.Skills[0].Binding.Mode != LibraryBindingModeTrack ||
		!reflect.DeepEqual(activationV1.Skills[0].Constraints.CapabilityCeiling, []string{"repository.read"}) {
		t.Fatalf("source client activation at v1=%+v err=%v", activationV1, err)
	}
	otherActivation, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, otherClient.ID)
	if err != nil || len(otherActivation.Skills) != 0 {
		t.Fatalf("other same-subject client activation at v1=%+v err=%v", otherActivation, err)
	}

	request := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "update-v2", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Version two\nNo authority is granted.",
		RequestedCapabilities: []string{"repository.read", "repository.write", "repository.read"},
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("update leased skill: %v", err)
	}
	if updated.Replayed || updated.Skill.ID != created.Skill.ID || updated.BindingID != created.BindingID || updated.Version.Version != 2 || updated.Version.Content != request.Content ||
		updated.Version.CreatedBy != client.Subject || updated.Lease.RemainingCreates != 1 {
		t.Fatalf("updated leased skill=%+v", updated)
	}
	if got := updated.Version.RequestedCapabilities; len(got) != 2 || got[0] != "repository.read" || got[1] != "repository.write" {
		t.Fatalf("updated capabilities=%v", got)
	}
	activationV2, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil || len(activationV2.Skills) != 1 || activationV2.Skills[0].SkillID != created.Skill.ID ||
		activationV2.Skills[0].VersionID != updated.Version.ID || activationV2.Skills[0].Instructions != updated.Version.Content ||
		activationV2.Skills[0].Binding.ID != created.BindingID ||
		!reflect.DeepEqual(activationV2.Skills[0].Constraints.RequestedCapabilities, []string{"repository.read", "repository.write"}) ||
		!reflect.DeepEqual(activationV2.Skills[0].Constraints.CapabilityCeiling, []string{"repository.read"}) {
		t.Fatalf("source client activation at v2=%+v err=%v", activationV2, err)
	}
	otherActivation, err = BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, otherClient.ID)
	if err != nil || len(otherActivation.Skills) != 0 {
		t.Fatalf("other same-subject client activation at v2=%+v err=%v", otherActivation, err)
	}
	versions, err := store.LibrarySkillVersions(ctx, created.Skill.ID)
	if err != nil || len(versions) != 2 || versions[0].ID != created.Version.ID || versions[0].Content != "# Version one" || versions[1].ID != updated.Version.ID {
		t.Fatalf("immutable versions=%#v err=%v", versions, err)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID || replay.BindingID != created.BindingID || replay.Lease.RemainingCreates != 1 {
		t.Fatalf("update replay=%+v err=%v", replay, err)
	}
	changedRetry := request
	changedRetry.Content = "# Changed retry"
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, changedRetry); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("changed update retry error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringRequestConflict)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "stale-version", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Must not replace v2",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("stale version update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}

	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, otherClient.ID, MCPClientPrecondition{ID: otherClient.ID, Revision: otherClient.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, otherClient, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "other-client", SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# Other same-subject client",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("same-subject other-client update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	otherLease, found, err := store.MCPClientSkillAuthoringLease(ctx, otherClient.ID)
	if err != nil || !found || otherLease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("other-client denial consumed quota lease=%+v found=%t err=%v", otherLease, found, err)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, otherClient); err != nil || len(listed) != 0 {
		t.Fatalf("same-subject other-client list=%#v err=%v", listed, err)
	}

	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-owned", Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "bound-skill", SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# Additional bindings are owner-managed",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("bound skill update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("bound skill leaked into authored list=%#v err=%v", listed, err)
	}
	lease, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || lease.RemainingCreates != 1 {
		t.Fatalf("denied updates consumed authoring quota lease=%+v found=%t err=%v", lease, found, err)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpdate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationUpdate) < 3 {
		t.Fatalf("update authoring audit events=%#v err=%v", events, err)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreRejectsRecreatedAutomaticBinding(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_recreated_binding")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "recreated-binding-create", Name: "Exact binding provenance", Content: "# Version one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, created.BindingID); err != nil {
		t.Fatalf("delete automatic binding: %v", err)
	}
	replacement, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
		Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("recreate automatic-looking binding: %v", err)
	}
	if replacement.ID == created.BindingID {
		t.Fatalf("recreated binding retained automatic receipt ID %q", replacement.ID)
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("recreated binding remained authoring-eligible: skills=%#v err=%v", listed, err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "recreated-binding-update", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Must remain owner-managed",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("recreated binding update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
	lease, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || lease.RemainingCreates != 2 {
		t.Fatalf("recreated binding denial consumed quota lease=%+v found=%t err=%v", lease, found, err)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreRejectsRestoredBindingSet(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_restored_binding_set")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "restored-binding-create", Name: "Binding generation", Content: "# Version one",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Add and remove a different binding so the visible final set is exactly
	// the original automatic binding. Without a monotonic generation receipt,
	// this would revive the temporary client write window.
	extra, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-restored-binding-set",
		Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("add unrelated binding: %v", err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, extra.ID); err != nil {
		t.Fatalf("remove unrelated binding: %v", err)
	}
	bindings, err := store.LibrarySkillBindings(ctx, created.Skill.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != created.BindingID {
		t.Fatalf("restored binding set=%#v err=%v", bindings, err)
	}
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatalf("reload restored binding set: %v", err)
	}
	if listed, _, err := reloaded.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("restored binding set remained authoring-eligible: skills=%#v err=%v", listed, err)
	}
	if _, err := reloaded.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "restored-binding-update", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Must remain owner-managed",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored binding update error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreKeepsLegacyNoBindingSkillsCompatible(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_legacy_author")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "legacy-create", Name: "Legacy no-binding skill", Content: "# Version one",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Model the persisted pre-auto-binding shape: its create receipt has no
	// binding fingerprint and the skill itself has no bindings. This is
	// deliberately a compatibility path, not an implicit migration that would
	// create a new client assignment for an old skill.
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, created.BindingID); err != nil {
		t.Fatalf("remove automatic binding for legacy fixture: %v", err)
	}
	store.mu.Lock()
	foundCreateRecord := false
	for _, record := range store.libraryMCPClientSkillAuthoringRequests {
		if record != nil && record.MCPClientID == client.ID && record.SkillID == created.Skill.ID && record.VersionID == created.Version.ID {
			record.BindingID = ""
			record.BindingDigest = ""
			record.BindingGeneration = 0
			foundCreateRecord = true
		}
	}
	// The historical FileStore payload predates the generation map as well.
	// Removing the current marker makes this a genuine no-binding legacy
	// fixture rather than a newly changed binding set.
	delete(store.librarySkillBindingGenerations, created.Skill.ID)
	err = store.saveLocked()
	store.mu.Unlock()
	if !foundCreateRecord || err != nil {
		t.Fatalf("persist legacy authoring receipt found=%t err=%v", foundCreateRecord, err)
	}

	if activation, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID); err != nil || len(activation.Skills) != 0 {
		t.Fatalf("legacy no-binding skill unexpectedly activated: %+v err=%v", activation, err)
	}
	listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || len(listed) != 1 || listed[0].SkillID != created.Skill.ID {
		t.Fatalf("legacy authoring list=%#v err=%v", listed, err)
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "legacy-update", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Legacy version two",
	})
	if err != nil || updated.BindingID != "" || updated.Version.Version != 2 {
		t.Fatalf("legacy update=%+v err=%v", updated, err)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "legacy-update", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Legacy version two",
	}); err != nil || !replay.Replayed || replay.BindingID != "" || replay.Version.ID != updated.Version.ID {
		t.Fatalf("legacy update replay=%+v err=%v", replay, err)
	}
	transient, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: created.Skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "legacy-transient", Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, created.Skill.ID, transient.ID); err != nil {
		t.Fatal(err)
	}
	if generation := store.librarySkillBindingGenerationLocked(created.Skill.ID); generation == 0 {
		t.Fatal("legacy add/remove did not persist a binding generation")
	}
	if listed, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); err != nil || len(listed) != 0 {
		t.Fatalf("restored legacy no-binding set remained authoring-eligible: skills=%#v err=%v", listed, err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "legacy-restored-binding-update", SkillID: created.Skill.ID, ExpectedVersionID: updated.Version.ID,
		ExpectedVersionDigest: updated.Version.Digest, Content: "# Must remain owner-managed",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored legacy binding-set update error=%v, want unavailable", err)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreCreateRollsBackAutomaticBinding(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_authoring_rollback")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}

	// Force saveLocked to fail after it has staged the skill, V1, automatic
	// binding, receipt, lease decrement, and audit event. The operation must
	// leave both the in-memory and durable store at their pre-create state.
	originalPath := store.path
	store.path = originalPath + ".missing/library.json"
	_, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "rollback-create", Name: "Rollback binding", Content: "# Must not persist",
	})
	store.path = originalPath
	if err == nil {
		t.Fatal("create unexpectedly succeeded with an unwritable save path")
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil || len(skills) != 0 {
		t.Fatalf("failed create left skills=%#v err=%v", skills, err)
	}
	store.mu.Lock()
	bindingCount := len(store.librarySkillBindings)
	requestCount := len(store.libraryMCPClientSkillAuthoringRequests)
	store.mu.Unlock()
	if bindingCount != 0 || requestCount != 0 {
		t.Fatalf("failed create left bindings=%d requests=%d", bindingCount, requestCount)
	}
	lease, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("failed create changed quota lease=%+v found=%t err=%v", lease, found, err)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate) != 0 {
		t.Fatalf("failed create left consumed audit=%#v err=%v", events, err)
	}
	reloaded, err := LoadFileStore(originalPath)
	if err != nil {
		t.Fatalf("reload after failed create: %v", err)
	}
	if durableSkills, err := reloaded.LibrarySkills(ctx); err != nil || len(durableSkills) != 0 {
		t.Fatalf("failed create reached disk skills=%#v err=%v", durableSkills, err)
	}
}

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreSerializesLastSlotAndFencesEpoch(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_parallel")
	lease, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	// Set up the final slot without using a check-then-create path. The two
	// concurrent calls below both enter the production atomic store method.
	store.mu.Lock()
	storedLease := store.libraryMCPClientSkillAuthoringLeaseByIDLocked(lease.ID)
	if storedLease == nil {
		store.mu.Unlock()
		t.Fatal("granted lease was not stored")
	}
	storedLease.RemainingCreates = 1
	store.mu.Unlock()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, candidate := range []LibraryMCPClientSkillAuthoringRequest{
		{RequestID: "parallel-a", Name: "Parallel A", Content: "# A"},
		{RequestID: "parallel-b", Name: "Parallel B", Content: "# B"},
	} {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, candidate)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
			t.Fatalf("parallel create error=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("parallel final-slot successes=%d, want 1", successes)
	}

	if _, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "stale-epoch", Name: "Stale epoch", Content: "# stale",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("stale epoch create error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringUnavailable)
	}
}

func TestMCPClientSkillAuthoringLeaseConsoleRequiresOwnerAdminAndFencesRevoke(t *testing.T) {
	mux, store, _, key, now, team, _ := hostedNamespaceConsole(t)
	create := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients", `{"name":"Lease Claude","subject":"usr_owner","connectionNamespaceIds":["`+team.ID+`"]}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create MCP client = %d: %s", create.Code, create.Body)
	}
	var client mcpClientDTO
	if err := json.Unmarshal(create.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}

	// An owner cannot create a lease until the durable OAuth identity is bound.
	unbound := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease", `{"revision":`+jsonNumber(client.Revision)+`}`)
	if unbound.Code != http.StatusConflict {
		t.Fatalf("unbound lease grant = %d: %s", unbound.Code, unbound.Body)
	}
	stored, ok := store.MCPClient(context.Background(), client.ID)
	if !ok {
		t.Fatal("created MCP client was not stored")
	}
	bound, err := store.BindMCPClientOAuthClient(context.Background(), stored.ID, "oauth-console-lease", MCPClientPrecondition{ID: stored.ID, Revision: stored.Revision}, PlatformActor{UserID: "usr_owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		role string
		// The hosted assertion verifier rejects an internal service role before
		// this route's owner/admin check; both outcomes prove it cannot grant a
		// lease. Operator/viewer assertions reach the route and must be 403.
		want []int
	}{
		{role: "operator", want: []int{http.StatusForbidden}},
		{role: "viewer", want: []int{http.StatusForbidden}},
		{role: "service", want: []int{http.StatusUnauthorized, http.StatusForbidden}},
	} {
		test := test
		response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", test.role, http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease", `{"revision":`+jsonNumber(bound.Revision)+`}`)
		matched := false
		for _, want := range test.want {
			matched = matched || response.Code == want
		}
		if !matched {
			t.Errorf("%s lease grant = %d: %s; want one of %v", test.role, response.Code, response.Body, test.want)
		}
	}
	grant := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease", `{"revision":`+jsonNumber(bound.Revision)+`}`)
	if grant.Code != http.StatusCreated {
		t.Fatalf("owner lease grant = %d: %s", grant.Code, grant.Body)
	}
	var lease mcpClientSkillAuthoringLeaseDTO
	if err := json.Unmarshal(grant.Body.Bytes(), &lease); err != nil || lease.LeaseID == "" || lease.Status != LibraryMCPClientSkillAuthoringLeaseStatusActive || lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("decode granted lease=%+v err=%v", lease, err)
	}
	get := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease", "")
	if get.Code != http.StatusOK || get.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("lease read = %d cache=%q body=%s", get.Code, get.Header().Get("Cache-Control"), get.Body)
	}

	stale := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease/revoke", `{"revision":`+jsonNumber(bound.Revision)+`,"leaseId":"libmcpal_stale"}`)
	if stale.Code != http.StatusNotFound {
		t.Fatalf("stale revoke = %d: %s", stale.Code, stale.Body)
	}
	revoke := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-lease/revoke", `{"revision":`+jsonNumber(bound.Revision)+`,"leaseId":"`+lease.LeaseID+`"}`)
	if revoke.Code != http.StatusOK {
		t.Fatalf("lease revoke = %d: %s", revoke.Code, revoke.Body)
	}
	if err := json.Unmarshal(revoke.Body.Bytes(), &lease); err != nil || lease.Status != LibraryMCPClientSkillAuthoringLeaseStatusRevoked {
		t.Fatalf("decode revoked lease=%+v err=%v", lease, err)
	}
}

func TestMCPClientLibrarySkillCreateToolIsStaticButLeaseGated(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_tool_author")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	if _, found := mcpServer.ListTools()["library_skill_create"]; !found {
		t.Fatal("subject-bound MCP server did not statically advertise library_skill_create")
	}
	if response := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "before-lease", "name": "Before lease", "content": "# blocked",
	}); !strings.Contains(response, "skill authoring is not currently available") || !strings.Contains(response, `"isError":true`) {
		t.Fatalf("unleased skill create response=%s", response)
	}

	lease, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	response := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-create", "name": "Tool-created skill", "description": "narrow authoring test",
		"content": "# Tool-created instructions", "requestedCapabilities": []string{"repository.read"},
	})
	if strings.Contains(response, `"isError":true`) || !strings.Contains(response, `"skillId"`) || !strings.Contains(response, `"bindingId"`) || !strings.Contains(response, `"remainingCreates":2`) {
		t.Fatalf("leased skill create response=%s", response)
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil || len(skills) != 1 || skills[0].CreatedBy != client.Subject {
		t.Fatalf("tool-created skills=%#v err=%v", skills, err)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skills[0].ID)
	if err != nil || len(bindings) != 1 || bindings[0].ScopeKind != LibraryScopeAgentSurface || bindings[0].ScopeID != client.ID || bindings[0].Mode != LibraryBindingModeTrack {
		t.Fatalf("tool-created skill automatic binding=%#v err=%v", bindings, err)
	}
	if !strings.Contains(response, `"bindingId":"`+bindings[0].ID+`"`) {
		t.Fatalf("tool create did not return its exact binding ID: %s", response)
	}
	if replay := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-create", "name": "Tool-created skill", "description": "narrow authoring test",
		"content": "# Tool-created instructions", "requestedCapabilities": []string{"repository.read"},
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(replay, `"replayed":true`) || !strings.Contains(replay, `"bindingId":"`+bindings[0].ID+`"`) {
		t.Fatalf("tool skill create replay=%s", replay)
	}
	if _, err := store.RevokeMCPClientSkillAuthoringLease(ctx, client.ID, lease.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	if denied := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "after-revoke", "name": "After revoke", "content": "# blocked",
	}); !strings.Contains(denied, "skill authoring is not currently available") || strings.Contains(denied, `"skillId"`) {
		t.Fatalf("revoked tool skill create response=%s", denied)
	}
	// The old server projection remains intentionally harmless after an OAuth
	// reset. It still reaches the atomic store solely to durably record the
	// denied attempt; it cannot revive the stale endpoint identity.
	if _, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatal(err)
	}
	if denied := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "after-oauth-reset", "name": "After reset", "content": "# blocked",
	}); !strings.Contains(denied, "skill authoring is not currently available") || strings.Contains(denied, `"skillId"`) {
		t.Fatalf("stale endpoint skill create response=%s", denied)
	}
	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationGrant) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationRevoke) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionRejected, LibraryMCPClientSkillAuthoringAuditOperationCreate) < 3 {
		t.Fatalf("tool authoring audit events=%#v", events)
	}
}

func TestMCPClientLibrarySkillUpdateToolsAreStaticAndLeaseGated(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_tool_update")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	for _, tool := range []string{"library_skill_authoring_list", "library_skill_update"} {
		if _, found := mcpServer.ListTools()[tool]; !found {
			t.Fatalf("subject-bound MCP server did not statically advertise %s", tool)
		}
	}
	if response := callLibraryTool(t, mcpServer, "library_skill_authoring_list", nil); !strings.Contains(response, "skill authoring is not currently available") || !strings.Contains(response, `"isError":true`) {
		t.Fatalf("unleased authored-skill list response=%s", response)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	createResponse := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-update-create", "name": "Tool update candidate", "content": "# Original",
	})
	if strings.Contains(createResponse, `"isError":true`) {
		t.Fatalf("leased tool create response=%s", createResponse)
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil || len(skills) != 1 {
		t.Fatalf("tool-created skills=%#v err=%v", skills, err)
	}
	versions, err := store.LibrarySkillVersions(ctx, skills[0].ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("tool-created versions=%#v err=%v", versions, err)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skills[0].ID)
	if err != nil || len(bindings) != 1 || bindings[0].ScopeKind != LibraryScopeAgentSurface || bindings[0].ScopeID != client.ID || bindings[0].Mode != LibraryBindingModeTrack {
		t.Fatalf("tool-created update candidate binding=%#v err=%v", bindings, err)
	}
	if !strings.Contains(createResponse, `"bindingId":"`+bindings[0].ID+`"`) {
		t.Fatalf("tool update-create did not return its exact binding ID: %s", createResponse)
	}
	if response := callLibraryTool(t, mcpServer, "library_skill_authoring_list", nil); strings.Contains(response, `"isError":true`) ||
		!strings.Contains(response, `"skillId":"`+skills[0].ID+`"`) || !strings.Contains(response, `"latestVersionId":"`+versions[0].ID+`"`) ||
		strings.Contains(response, "# Original") {
		t.Fatalf("leased authored-skill list response=%s", response)
	}
	updateResponse := callLibraryTool(t, mcpServer, "library_skill_update", map[string]any{
		"requestId": "tool-update-v2", "skillId": skills[0].ID, "expectedVersionId": versions[0].ID,
		"expectedVersionDigest": versions[0].Digest, "content": "# Updated through MCP",
		"requestedCapabilities": []string{"repository.read"},
	})
	if strings.Contains(updateResponse, `"isError":true`) || !strings.Contains(updateResponse, `"skillId":"`+skills[0].ID+`"`) || !strings.Contains(updateResponse, `"bindingId":"`+bindings[0].ID+`"`) || !strings.Contains(updateResponse, `"remainingCreates":1`) {
		t.Fatalf("leased skill update response=%s", updateResponse)
	}
	versions, err = store.LibrarySkillVersions(ctx, skills[0].ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("updated tool versions=%#v err=%v", versions, err)
	}
	if replay := callLibraryTool(t, mcpServer, "library_skill_update", map[string]any{
		"requestId": "tool-update-v2", "skillId": skills[0].ID, "expectedVersionId": versions[0].ID,
		"expectedVersionDigest": versions[0].Digest, "content": "# Updated through MCP",
		"requestedCapabilities": []string{"repository.read"},
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(replay, `"replayed":true`) || !strings.Contains(replay, `"bindingId":"`+bindings[0].ID+`"`) {
		t.Fatalf("tool skill update replay=%s", replay)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skills[0].ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "tool-bound", Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	if denied := callLibraryTool(t, mcpServer, "library_skill_update", map[string]any{
		"requestId": "tool-update-bound", "skillId": skills[0].ID, "expectedVersionId": versions[1].ID,
		"expectedVersionDigest": versions[1].Digest, "content": "# Must not update bound skill",
	}); !strings.Contains(denied, "skill authoring is not currently available") || strings.Contains(denied, `"skillVersionId"`) {
		t.Fatalf("bound skill update response=%s", denied)
	}
}

func TestLibraryMCPClientSkillAuthoringAdoptionFileStoreFencesOneBoundSkill(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_adoption_client")
	otherClient := newAuthoringLeaseMCPClient(t, store, "usr_adoption_other")

	// An ordinary Console-owned skill may already have generic and other-client
	// delivery selections. Explicit adoption layers temporary write authority
	// over those bindings; it never repurposes or erases them.
	skill, first, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "console-owned-adoption", Name: "Console-owned adoption target", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# First immutable version", RequestedCapabilities: []string{"repository.read"}, CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-main", Mode: LibraryBindingModeTrack,
		CreatedBy: "usr_owner", CapabilityCeiling: []string{"repository.read"}, Priority: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: otherClient.ID, Mode: LibraryBindingModeTrack,
		CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}

	// The owner/admin head CAS must fail before it creates either a client
	// binding or a lease.
	if _, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: skill.ID, ExpectedVersionID: first.ID, ExpectedVersionDigest: strings.Repeat("0", 64),
	}, "usr_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict) {
		t.Fatalf("stale adoption head error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict)
	}
	if bindings, err := store.LibrarySkillBindings(ctx, skill.ID); err != nil || len(bindings) != 2 {
		t.Fatalf("stale adoption changed bindings=%#v err=%v", bindings, err)
	}

	lease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: skill.ID, ExpectedVersionID: first.ID, ExpectedVersionDigest: first.Digest,
	}, "usr_owner")
	if err != nil {
		t.Fatalf("grant adoption lease: %v", err)
	}
	if lease.Kind != LibraryMCPClientSkillAuthoringLeaseKindAdoption || lease.TargetSkillID != skill.ID || lease.TargetVersionID != first.ID || lease.TargetVersionDigest != first.Digest || lease.TargetBindingID == "" || lease.TargetBindingDigest == "" || lease.TargetBindingGeneration <= 0 || lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("adoption lease=%+v", lease)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skill.ID)
	if err != nil || len(bindings) != 3 {
		t.Fatalf("adoption bindings=%#v err=%v", bindings, err)
	}
	var adoptedBinding LibrarySkillBinding
	for _, binding := range bindings {
		if binding.ID == lease.TargetBindingID {
			adoptedBinding = binding
		}
	}
	if !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(adoptedBinding, skill.ID, client.ID) {
		t.Fatalf("adopted binding=%+v", adoptedBinding)
	}
	if !reflect.DeepEqual(adoptedBinding.CapabilityCeiling, first.RequestedCapabilities) {
		t.Fatalf("adopted binding ceiling=%v, want current head capabilities=%v", adoptedBinding.CapabilityCeiling, first.RequestedCapabilities)
	}
	selections, err := store.LibraryAgentSurfaceSkillSelections(ctx, client.ID)
	if err != nil || len(selections) != 1 || selections[0].Skill.ID != skill.ID || selections[0].Binding.ID != lease.TargetBindingID || selections[0].Version.ID != first.ID {
		t.Fatalf("adopted client activation selections=%#v err=%v", selections, err)
	}

	// Adoption is strictly update-only: the generic create path must remain
	// unavailable even while this target's revision lease is active.
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
		RequestID: "adoption-cannot-create", Name: "Must not create", Content: "# blocked",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("adoption create error=%v, want unavailable", err)
	}
	listed, listedLease, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || listedLease.ID != lease.ID || len(listed) != 1 || listed[0].SkillID != skill.ID || listed[0].LatestVersionID != first.ID || listed[0].LatestVersionDigest != first.Digest {
		t.Fatalf("adopted skill list=%#v lease=%+v err=%v", listed, listedLease, err)
	}

	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "adoption-widen-capabilities", SkillID: skill.ID, ExpectedVersionID: first.ID, ExpectedVersionDigest: first.Digest,
		Content: "# Widened capability attempt", RequestedCapabilities: []string{"repository.write"},
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("adoption widened capabilities error=%v, want unavailable", err)
	}
	if current, found, err := store.MCPClientSkillAuthoringLease(ctx, client.ID); err != nil || !found || current.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates {
		t.Fatalf("widened adoption consumed quota lease=%+v found=%t err=%v", current, found, err)
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "adoption-update-v2", SkillID: skill.ID, ExpectedVersionID: first.ID, ExpectedVersionDigest: first.Digest,
		Content: "# Second immutable version", RequestedCapabilities: []string{"repository.read"},
	})
	if err != nil {
		t.Fatalf("adoption update: %v", err)
	}
	if updated.Replayed || updated.Version.Version != 2 || updated.Version.CreatedBy != client.Subject || updated.BindingID != lease.TargetBindingID || updated.Lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates-1 {
		t.Fatalf("adoption update=%+v", updated)
	}
	versions, err := store.LibrarySkillVersions(ctx, skill.ID)
	if err != nil || len(versions) != 2 || versions[0].ID != first.ID || versions[0].Content != "# First immutable version" || versions[1].ID != updated.Version.ID {
		t.Fatalf("adoption immutable versions=%#v err=%v", versions, err)
	}

	// A non-target request is rejected before any caller-nominated skill can
	// influence this lease. The error intentionally remains neutral.
	other, otherHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "another-console-owned-skill", Name: "Another Console-owned skill", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Other", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "adoption-other-skill", SkillID: other.ID, ExpectedVersionID: otherHead.ID, ExpectedVersionDigest: otherHead.Digest, Content: "# blocked",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("other adoption target update error=%v, want unavailable", err)
	}

	// A binding set can be restored byte-for-byte after an add/delete. The
	// monotonic generation must still permanently invalidate the lease.
	extraBinding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "adoption-transient-workspace", Mode: LibraryBindingModeTrack,
		CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLibrarySkillBinding(ctx, skill.ID, extraBinding.ID); err != nil {
		t.Fatal(err)
	}
	if store.librarySkillBindingGenerationLocked(skill.ID) == lease.TargetBindingGeneration {
		t.Fatalf("add/delete restored authoring binding generation=%d", lease.TargetBindingGeneration)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "adoption-restored-binding-set", SkillID: skill.ID, ExpectedVersionID: updated.Version.ID, ExpectedVersionDigest: updated.Version.Digest,
		Content: "# blocked after binding restoration",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored adoption binding-set update error=%v, want unavailable", err)
	}
	if _, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("restored adoption binding-set list error=%v, want unavailable", err)
	}

	events, err := store.MCPClientSkillAuthoringLeaseAuditEvents(ctx, client.ID)
	if err != nil || countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationAdopt) != 1 ||
		countLibraryMCPClientSkillAuthoringAudit(events, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpdate) != 1 {
		t.Fatalf("adoption audit events=%#v err=%v", events, err)
	}

	// The lease receipt and delivery binding must survive a FileStore reload.
	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	reloadedLease, found, err := reloaded.MCPClientSkillAuthoringLease(ctx, client.ID)
	if err != nil || !found || reloadedLease.TargetBindingID != lease.TargetBindingID || reloadedLease.TargetBindingDigest != lease.TargetBindingDigest || reloadedLease.TargetBindingGeneration != lease.TargetBindingGeneration || reloadedLease.Kind != LibraryMCPClientSkillAuthoringLeaseKindAdoption {
		t.Fatalf("reloaded adoption lease=%+v found=%t err=%v", reloadedLease, found, err)
	}
	if reloadedBindings, err := reloaded.LibrarySkillBindings(ctx, skill.ID); err != nil || len(reloadedBindings) != 3 {
		t.Fatalf("reloaded adoption bindings=%#v err=%v", reloadedBindings, err)
	}
}

func TestLibraryMCPClientSkillAuthoringAdoptionFileStoreFailsClosedForLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_adoption_lifecycle")

	trackSkill, trackHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-reuse-track", Name: "Adoption reuses existing track", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Track", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	existingTrack, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: trackSkill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModeTrack,
		CapabilityCeiling: []string{"repository.read"}, Priority: 9, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: trackSkill.ID, ExpectedVersionID: trackHead.ID, ExpectedVersionDigest: trackHead.Digest,
	}, "usr_owner")
	if err != nil || lease.TargetBindingID != existingTrack.ID {
		t.Fatalf("reused track adoption lease=%+v err=%v", lease, err)
	}
	if bindings, err := store.LibrarySkillBindings(ctx, trackSkill.ID); err != nil || len(bindings) != 1 || bindings[0].ID != existingTrack.ID || bindings[0].Priority != 9 || len(bindings[0].CapabilityCeiling) != 1 {
		t.Fatalf("existing track binding was not reused=%#v err=%v", bindings, err)
	}
	if _, err := store.RevokeMCPClientSkillAuthoringLease(ctx, client.ID, lease.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	if bindings, err := store.LibrarySkillBindings(ctx, trackSkill.ID); err != nil || len(bindings) != 1 || bindings[0].ID != existingTrack.ID {
		t.Fatalf("revoking adoption removed delivery binding=%#v err=%v", bindings, err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "after-adoption-revoke", SkillID: trackSkill.ID, ExpectedVersionID: trackHead.ID, ExpectedVersionDigest: trackHead.Digest, Content: "# blocked",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("revoked adoption update error=%v, want unavailable", err)
	}

	pinnedSkill, pinnedHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-reject-pin", Name: "Adoption rejects pin", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Pin", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: pinnedSkill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: pinnedHead.ID, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: pinnedSkill.ID, ExpectedVersionID: pinnedHead.ID, ExpectedVersionDigest: pinnedHead.Digest,
	}, "usr_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound) {
		t.Fatalf("pinned selected-client adoption error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound)
	}

	// Damaged/legacy duplicate selected-client bindings are rejected instead of
	// allowing one arbitrary row to become temporary write authority.
	duplicateSkill, duplicateHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-reject-duplicate", Name: "Adoption rejects duplicate", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Duplicate", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	firstDuplicate, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: duplicateSkill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	secondDuplicate := copyLibrarySkillBinding(firstDuplicate)
	secondDuplicate.ID = newLibrarySkillBindingID()
	secondDuplicate.UpdatedAt = secondDuplicate.UpdatedAt.Add(time.Nanosecond)
	store.librarySkillBindings = append(store.librarySkillBindings, &secondDuplicate)
	store.mu.Unlock()
	if _, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: duplicateSkill.ID, ExpectedVersionID: duplicateHead.ID, ExpectedVersionDigest: duplicateHead.Digest,
	}, "usr_owner"); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound) {
		t.Fatalf("duplicate selected-client adoption error=%v, want %v", err, ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound)
	}
	store.mu.Lock()
	store.librarySkillBindings = store.librarySkillBindings[:len(store.librarySkillBindings)-1]
	store.mu.Unlock()

	// If the FileStore write fails, no staged binding, lease, audit, or
	// generation may leak into memory.
	rollbackClient := newAuthoringLeaseMCPClient(t, store, "usr_adoption_rollback")
	rollbackSkill, rollbackHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-rollback", Name: "Adoption save rollback", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Rollback", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	originalPath := store.path
	store.path = t.TempDir()
	_, err = store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, rollbackClient.ID, MCPClientPrecondition{ID: rollbackClient.ID, Revision: rollbackClient.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: rollbackSkill.ID, ExpectedVersionID: rollbackHead.ID, ExpectedVersionDigest: rollbackHead.Digest,
	}, "usr_owner")
	store.path = originalPath
	if err == nil {
		t.Fatal("adoption save unexpectedly succeeded against a directory")
	}
	if bindings, err := store.LibrarySkillBindings(ctx, rollbackSkill.ID); err != nil || len(bindings) != 0 {
		t.Fatalf("failed adoption leaked binding=%#v err=%v", bindings, err)
	}
	if _, found, err := store.MCPClientSkillAuthoringLease(ctx, rollbackClient.ID); err != nil || found {
		t.Fatalf("failed adoption leaked lease found=%t err=%v", found, err)
	}
	if generation := store.librarySkillBindingGenerationLocked(rollbackSkill.ID); generation != 0 {
		t.Fatalf("failed adoption leaked binding generation=%d", generation)
	}

	expiryClient := newAuthoringLeaseMCPClient(t, store, "usr_adoption_expiry")
	expirySkill, expiryHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-expiry", Name: "Adoption expiry", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Expiry", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	expiryLease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, expiryClient.ID, MCPClientPrecondition{ID: expiryClient.ID, Revision: expiryClient.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: expirySkill.ID, ExpectedVersionID: expiryHead.ID, ExpectedVersionDigest: expiryHead.Digest,
	}, "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	storedExpiryLease := store.libraryMCPClientSkillAuthoringLeaseByIDLocked(expiryLease.ID)
	if storedExpiryLease == nil {
		store.mu.Unlock()
		t.Fatal("stored expiry adoption lease missing")
	}
	storedExpiryLease.ExpiresAt = time.Now().UTC().Add(-time.Second)
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	if expired, found, err := store.MCPClientSkillAuthoringLease(ctx, expiryClient.ID); err != nil || !found || expired.Status != LibraryMCPClientSkillAuthoringLeaseStatusExpired {
		t.Fatalf("expired adoption lease=%+v found=%t err=%v", expired, found, err)
	}
	if bindings, err := store.LibrarySkillBindings(ctx, expirySkill.ID); err != nil || len(bindings) != 1 || bindings[0].ID != expiryLease.TargetBindingID {
		t.Fatalf("lease expiry removed binding=%#v err=%v", bindings, err)
	}

	resetClient := newAuthoringLeaseMCPClient(t, store, "usr_adoption_reset")
	resetSkill, resetHead, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "adoption-reset", Name: "Adoption reset", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Reset", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	resetLease, err := store.GrantMCPClientSkillAuthoringAdoptionLease(ctx, resetClient.ID, MCPClientPrecondition{ID: resetClient.ID, Revision: resetClient.Revision}, LibraryMCPClientSkillAuthoringAdoptionRequest{
		SkillID: resetSkill.ID, ExpectedVersionID: resetHead.ID, ExpectedVersionDigest: resetHead.Digest,
	}, "usr_owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetMCPClientOAuthClient(ctx, resetClient.ID, MCPClientPrecondition{ID: resetClient.ID, Revision: resetClient.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, resetClient, LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "adoption-reset-update", SkillID: resetSkill.ID, ExpectedVersionID: resetHead.ID, ExpectedVersionDigest: resetHead.Digest, Content: "# blocked",
	}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("reset adoption update error=%v, want unavailable", err)
	}
	if bindings, err := store.LibrarySkillBindings(ctx, resetSkill.ID); err != nil || len(bindings) != 1 || bindings[0].ID != resetLease.TargetBindingID {
		t.Fatalf("client OAuth reset removed binding=%#v err=%v", bindings, err)
	}
}

func TestMCPClientSkillAuthoringAdoptionConsoleRequiresOwnerAdminAndReturnsBinding(t *testing.T) {
	mux, store, _, key, now, team, _ := hostedNamespaceConsole(t)
	create := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients", `{"name":"Adoption Codex","subject":"usr_owner","connectionNamespaceIds":["`+team.ID+`"]}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create MCP client = %d: %s", create.Code, create.Body)
	}
	var client mcpClientDTO
	if err := json.Unmarshal(create.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	stored, ok := store.MCPClient(context.Background(), client.ID)
	if !ok {
		t.Fatal("created MCP client was not stored")
	}
	bound, err := store.BindMCPClientOAuthClient(context.Background(), stored.ID, "oauth-console-adoption", MCPClientPrecondition{ID: stored.ID, Revision: stored.Revision}, PlatformActor{UserID: "usr_owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	skill, head, err := store.CreateLibrarySkillWithInitialVersion(context.Background(), LibrarySkill{
		Slug: "console-adoption-target", Name: "Console adoption target", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{Content: "# Original", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"revision":` + jsonNumber(bound.Revision) + `,"skillId":"` + skill.ID + `","expectedVersionId":"` + head.ID + `","expectedVersionDigest":"` + head.Digest + `"}`
	for _, test := range []struct {
		role string
		want []int
	}{
		{role: "operator", want: []int{http.StatusForbidden}},
		{role: "viewer", want: []int{http.StatusForbidden}},
		// A service assertion with a human identity is rejected by the actor
		// verifier before Console authorization; either outcome is safely not a
		// delegation grant.
		{role: "service", want: []int{http.StatusUnauthorized, http.StatusForbidden}},
	} {
		response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", test.role, http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-adoption", body)
		allowed := false
		for _, status := range test.want {
			allowed = allowed || response.Code == status
		}
		if !allowed {
			t.Errorf("%s adoption = %d, want one of %v: %s", test.role, response.Code, test.want, response.Body)
		}
	}
	unknown := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-adoption", strings.TrimSuffix(body, "}")+`,"unexpected":true}`)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown adoption field = %d: %s", unknown.Code, unknown.Body)
	}
	method := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodGet, "/api/mcp-clients/"+client.ID+"/skill-authoring-adoption", "")
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("adoption method = %d allow=%q: %s", method.Code, method.Header().Get("Allow"), method.Body)
	}
	response := hostedNamespaceRequest(t, mux, key, now, "usr_owner", "owner", http.MethodPost, "/api/mcp-clients/"+client.ID+"/skill-authoring-adoption", body)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("owner adoption = %d cache=%q: %s", response.Code, response.Header().Get("Cache-Control"), response.Body)
	}
	var lease mcpClientSkillAuthoringLeaseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &lease); err != nil || lease.Kind != LibraryMCPClientSkillAuthoringLeaseKindAdoption || lease.SkillID != skill.ID || lease.BindingID == "" || lease.Status != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		t.Fatalf("adoption response lease=%+v err=%v", lease, err)
	}
	bindings, err := store.LibrarySkillBindings(context.Background(), skill.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != lease.BindingID || bindings[0].ScopeKind != LibraryScopeAgentSurface || bindings[0].ScopeID != client.ID || bindings[0].Mode != LibraryBindingModeTrack {
		t.Fatalf("console adoption binding=%#v err=%v", bindings, err)
	}
}
