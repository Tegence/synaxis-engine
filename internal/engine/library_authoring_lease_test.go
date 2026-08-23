package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
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
	if err != nil || len(bindings) != 0 {
		t.Fatalf("leased skill auto-bound bindings=%#v err=%v", bindings, err)
	}

	replayed, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("exact authoring retry: %v", err)
	}
	if !replayed.Replayed || replayed.Skill.ID != created.Skill.ID || replayed.Version.ID != created.Version.ID || replayed.Lease.RemainingCreates != 2 {
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

func TestLibraryMCPClientSkillAuthoringLeaseFileStoreUpdatesOnlyExactUnboundClientSkills(t *testing.T) {
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
		RequestID: "update-create", Name: "Client update candidate", Description: "Must remain unbound",
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

	request := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "update-v2", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID,
		ExpectedVersionDigest: created.Version.Digest, Content: "# Version two\nNo authority is granted.",
		RequestedCapabilities: []string{"repository.read", "repository.write", "repository.read"},
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request)
	if err != nil {
		t.Fatalf("update leased skill: %v", err)
	}
	if updated.Replayed || updated.Skill.ID != created.Skill.ID || updated.Version.Version != 2 || updated.Version.Content != request.Content ||
		updated.Version.CreatedBy != client.Subject || updated.Lease.RemainingCreates != 1 {
		t.Fatalf("updated leased skill=%+v", updated)
	}
	if got := updated.Version.RequestedCapabilities; len(got) != 2 || got[0] != "repository.read" || got[1] != "repository.write" {
		t.Fatalf("updated capabilities=%v", got)
	}
	versions, err := store.LibrarySkillVersions(ctx, created.Skill.ID)
	if err != nil || len(versions) != 2 || versions[0].ID != created.Version.ID || versions[0].Content != "# Version one" || versions[1].ID != updated.Version.ID {
		t.Fatalf("immutable versions=%#v err=%v", versions, err)
	}
	if replay, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, request); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID || replay.Lease.RemainingCreates != 1 {
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
		ExpectedVersionDigest: updated.Version.Digest, Content: "# Bound skills are owner-managed",
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
	if strings.Contains(response, `"isError":true`) || !strings.Contains(response, `"skillId"`) || !strings.Contains(response, `"remainingCreates":2`) {
		t.Fatalf("leased skill create response=%s", response)
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil || len(skills) != 1 || skills[0].CreatedBy != client.Subject {
		t.Fatalf("tool-created skills=%#v err=%v", skills, err)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skills[0].ID)
	if err != nil || len(bindings) != 0 {
		t.Fatalf("tool-created skill was auto-bound bindings=%#v err=%v", bindings, err)
	}
	if replay := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-create", "name": "Tool-created skill", "description": "narrow authoring test",
		"content": "# Tool-created instructions", "requestedCapabilities": []string{"repository.read"},
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(replay, `"replayed":true`) {
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
	if response := callLibraryTool(t, mcpServer, "library_skill_create", map[string]any{
		"requestId": "tool-update-create", "name": "Tool update candidate", "content": "# Original",
	}); strings.Contains(response, `"isError":true`) {
		t.Fatalf("leased tool create response=%s", response)
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil || len(skills) != 1 {
		t.Fatalf("tool-created skills=%#v err=%v", skills, err)
	}
	versions, err := store.LibrarySkillVersions(ctx, skills[0].ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("tool-created versions=%#v err=%v", versions, err)
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
	if strings.Contains(updateResponse, `"isError":true`) || !strings.Contains(updateResponse, `"skillId":"`+skills[0].ID+`"`) || !strings.Contains(updateResponse, `"remainingCreates":1`) {
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
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(replay, `"replayed":true`) {
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
