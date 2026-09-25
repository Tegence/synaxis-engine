package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"narthex/backend/pkg/libraryruntime"
)

func clientLibraryServer(t *testing.T, gateway *Gateway, slug string) *server.MCPServer {
	t.Helper()
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	endpoint, ok := gateway.clientEndpoints[slug]
	if !ok || endpoint.kind != endpointKindClient {
		t.Fatalf("client endpoint %q is not projected", slug)
	}
	return endpoint.mcp
}

func libraryToolJSONText(t *testing.T, response string) string {
	t.Helper()
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		t.Fatalf("decode Library tool response: %v\n%s", err, response)
	}
	if len(envelope.Result.Content) != 1 || envelope.Result.Content[0].Text == "" {
		t.Fatalf("Library tool response had no JSON text content: %s", response)
	}
	return envelope.Result.Content[0].Text
}

func createLibrarySkillForMCPClientTest(t *testing.T, store LibraryStore, slug, name, content string) (LibrarySkill, LibrarySkillVersion) {
	t.Helper()
	skill, version, err := store.CreateLibrarySkillWithInitialVersion(context.Background(), LibrarySkill{
		Slug: slug, Name: name, Description: name + " description", CreatedBy: "usr_owner",
	}, LibrarySkillVersion{
		Content: content, RequestedCapabilities: []string{"repository.read"}, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return skill, version
}

func TestMCPClientLibraryArtifactsAreSubjectAndSurfaceBound(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	alice, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	// The same human can have two client registrations. The surface check is
	// what stops one from reading artifacts created through the other.
	aliceSecond, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice Claude", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bob Codex", Subject: "usr_bob", CreatedBy: "usr_bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}

	wantTools := append([]string(nil), mcpClientLibraryToolNames...)
	sort.Strings(wantTools)
	if got := clientEndpointToolNames(t, gateway, alice.Slug); !sameStrings(got, wantTools) {
		t.Fatalf("client Library tools=%v want=%v", got, wantTools)
	}
	aliceMCP := clientLibraryServer(t, gateway, alice.Slug)
	created := callLibraryTool(t, aliceMCP, "library_artifact_create", map[string]any{
		"title": "Alice-only note", "summary": "private", "format": "markdown", "body": "# Alice secret",
	})
	if strings.Contains(created, `"isError":true`) || !strings.Contains(created, `"artifactId"`) {
		t.Fatalf("create scoped artifact=%s", created)
	}
	artifacts, err := store.LibraryArtifacts(ctx)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("artifacts=%#v err=%v", artifacts, err)
	}
	artifact := artifacts[0]
	run, found := store.LibraryRun(ctx, artifact.RunID)
	if !found || artifact.CreatedBy != alice.Subject || artifact.AgentSurfaceID != alice.ID || run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != alice.Subject || run.SurfaceRef != alice.ID {
		t.Fatalf("scoped artifact provenance artifact=%+v run=%+v found=%t", artifact, run, found)
	}

	if got := callLibraryTool(t, aliceMCP, "library_artifact_list", nil); !strings.Contains(got, "Alice-only note") {
		t.Fatalf("owner artifact list=%s", got)
	}
	if got := callLibraryTool(t, aliceMCP, "library_artifact_read", map[string]any{"artifactId": artifact.ID}); !strings.Contains(got, "# Alice secret") {
		t.Fatalf("owner artifact read=%s", got)
	}
	for _, other := range []MCPClient{aliceSecond, bob} {
		otherMCP := clientLibraryServer(t, gateway, other.Slug)
		if got := callLibraryTool(t, otherMCP, "library_artifact_list", nil); strings.Contains(got, "Alice-only note") {
			t.Fatalf("%s listed another client artifact: %s", other.Name, got)
		}
		if got := callLibraryTool(t, otherMCP, "library_artifact_read", map[string]any{"artifactId": artifact.ID}); !strings.Contains(got, "artifact not found") || strings.Contains(got, "# Alice secret") {
			t.Fatalf("%s read another client artifact: %s", other.Name, got)
		}
	}

	// A second refresh deletes the old built-ins before re-registering this
	// projection; the endpoint has exactly one copy of each name.
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if got := clientEndpointToolNames(t, gateway, alice.Slug); !sameStrings(got, wantTools) {
		t.Fatalf("client Library tools after refresh=%v want=%v", got, wantTools)
	}
	if _, err := store.RevokeMCPClient(ctx, alice.ID, alice.Subject, MCPClientPrecondition{ID: alice.ID, Revision: alice.Revision}); err != nil {
		t.Fatal(err)
	}
	if got := callLibraryTool(t, aliceMCP, "library_artifact_list", nil); !strings.Contains(got, "no longer available") {
		t.Fatalf("revoked client executed stale Library handler: %s", got)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	gateway.mu.Lock()
	_, stillProjected := gateway.clientEndpoints[alice.Slug]
	gateway.mu.Unlock()
	if stillProjected {
		t.Fatal("revoked client retained Library built-ins after refresh")
	}
}

func TestMCPClientLibraryArtifactListPaginatesAndRejectsMalformedCursor(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Cursor Codex", Subject: "usr_cursor", CreatedBy: "usr_cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	for _, title := range []string{"first page artifact", "second page artifact"} {
		created := callLibraryTool(t, mcpServer, "library_artifact_create", map[string]any{"title": title, "body": "# " + title})
		if strings.Contains(created, `"isError":true`) {
			t.Fatalf("create %q=%s", title, created)
		}
	}

	type artifactPage struct {
		Artifacts []struct {
			ID string `json:"id"`
		} `json:"artifacts"`
		NextCursor string `json:"nextCursor"`
	}
	var first artifactPage
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_artifact_list", map[string]any{"limit": 1}))), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Artifacts) != 1 || first.Artifacts[0].ID == "" || first.NextCursor == "" {
		t.Fatalf("first artifact page=%+v", first)
	}
	var second artifactPage
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_artifact_list", map[string]any{"limit": 1, "cursor": first.NextCursor}))), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Artifacts) != 1 || second.Artifacts[0].ID == "" || second.Artifacts[0].ID == first.Artifacts[0].ID || second.NextCursor != "" {
		t.Fatalf("second artifact page=%+v first=%+v", second, first)
	}
	if malformed := callLibraryTool(t, mcpServer, "library_artifact_list", map[string]any{"limit": 1, "cursor": "not-a-valid-cursor"}); !strings.Contains(malformed, "invalid artifact page") || !strings.Contains(malformed, `"isError":true`) {
		t.Fatalf("malformed artifact cursor response=%s", malformed)
	}
}

func TestMCPClientLibraryArtifactGrantPinsOneVersionAndRevokesImmediately(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	alice, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bob Codex", Subject: "usr_bob", CreatedBy: "usr_bob"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, first, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Owner research", Summary: "A version-pinned source", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Version one", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{
		ArtifactID: artifact.ID, Format: LibraryArtifactFormatMarkdown, Body: "# Version two", CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: first.ID, ArtifactVersionDigest: first.Digest,
		AgentSurfaceID: alice.ID, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}
	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: second.ID, ArtifactVersionDigest: second.Digest,
		AgentSurfaceID: alice.ID, CreatedBy: "usr_owner",
	}); !errors.Is(err, ErrLibraryArtifactGrantExists) {
		t.Fatalf("second live grant error=%v, want %v", err, ErrLibraryArtifactGrantExists)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	aliceMCP := clientLibraryServer(t, gateway, alice.Slug)
	bobMCP := clientLibraryServer(t, gateway, bob.Slug)
	listed := callLibraryTool(t, aliceMCP, "library_artifact_list", nil)
	if !strings.Contains(listed, artifact.ID) || !strings.Contains(listed, `"artifactVersionId":"`+first.ID+`"`) ||
		!strings.Contains(listed, `"digest":"`+first.Digest+`"`) || !strings.Contains(listed, `"access":"granted"`) || strings.Contains(listed, second.Digest) {
		t.Fatalf("granted artifact list was not exact-version only: %s", listed)
	}
	read := callLibraryTool(t, aliceMCP, "library_artifact_read", map[string]any{"artifactId": artifact.ID})
	if !strings.Contains(read, "# Version one") || strings.Contains(read, "# Version two") || !strings.Contains(read, `"artifactVersionId":"`+first.ID+`"`) {
		t.Fatalf("granted artifact read advanced to latest or omitted pin: %s", read)
	}
	if got := callLibraryTool(t, bobMCP, "library_artifact_read", map[string]any{"artifactId": artifact.ID}); !strings.Contains(got, "artifact not found") || strings.Contains(got, "Version one") {
		t.Fatalf("ungranted client read=%s", got)
	}

	// The exact granted source can be cited by a direct output. The client
	// does not get to supply its actor/version author; both are server-derived.
	created := callLibraryTool(t, aliceMCP, "library_artifact_create", map[string]any{
		"title": "Derived analysis", "body": "# Derived from v1",
		"sourceArtifactId": artifact.ID, "sourceArtifactVersionId": first.ID, "sourceArtifactDigest": first.Digest,
	})
	if strings.Contains(created, `"isError":true`) || !strings.Contains(created, "artifactId") {
		t.Fatalf("create from granted source=%s", created)
	}
	artifacts, err := store.LibraryArtifacts(ctx)
	if err != nil || len(artifacts) != 2 {
		t.Fatalf("artifact count=%#v err=%v", artifacts, err)
	}
	var derived LibraryArtifact
	for _, candidate := range artifacts {
		if candidate.Title == "Derived analysis" {
			derived = candidate
			break
		}
	}
	if derived.ID == "" {
		t.Fatalf("derived artifact not found in %#v", artifacts)
	}
	run, found := store.LibraryRun(ctx, derived.RunID)
	if !found || derived.SourceArtifactID != artifact.ID || derived.SourceArtifactVersionID != first.ID || derived.SourceArtifactDigest != first.Digest ||
		run.SourceArtifactID != artifact.ID || run.SourceArtifactVersionID != first.ID || run.SourceArtifactDigest != first.Digest {
		t.Fatalf("source provenance artifact=%+v run=%+v found=%t", derived, run, found)
	}
	derivedVersions, err := store.LibraryArtifactVersions(ctx, derived.ID)
	if err != nil || len(derivedVersions) != 1 || derivedVersions[0].CreatedBy != alice.Subject {
		t.Fatalf("server-derived artifact version author=%#v err=%v", derivedVersions, err)
	}

	if _, err := store.RevokeLibraryArtifactGrant(ctx, artifact.ID, grant.ID, "usr_owner", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeLibraryArtifactGrant: %v", err)
	}
	if got := callLibraryTool(t, aliceMCP, "library_artifact_list", nil); strings.Contains(got, artifact.ID) || !strings.Contains(got, derived.ID) {
		t.Fatalf("revoked grant list=%s", got)
	}
	if got := callLibraryTool(t, aliceMCP, "library_artifact_read", map[string]any{"artifactId": artifact.ID}); !strings.Contains(got, "artifact not found") || strings.Contains(got, "Version one") {
		t.Fatalf("revoked grant read=%s", got)
	}
	if got := callLibraryTool(t, aliceMCP, "library_artifact_create", map[string]any{
		"title": "Denied source", "body": "nope", "sourceArtifactId": artifact.ID, "sourceArtifactVersionId": first.ID, "sourceArtifactDigest": first.Digest,
	}); !strings.Contains(got, "source artifact not found") {
		t.Fatalf("revoked source was accepted=%s", got)
	}
	if _, err := store.RevokeMCPClient(ctx, bob.ID, "usr_bob", MCPClientPrecondition{ID: bob.ID, Revision: bob.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: second.ID, ArtifactVersionDigest: second.Digest,
		AgentSurfaceID: bob.ID, CreatedBy: "usr_owner",
	}); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("grant to revoked MCP client error=%v, want %v", err, ErrMCPClientRevoked)
	}
}

func TestMCPClientLibrarySkillsRequireExplicitAgentSurfaceBinding(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	alice, err := store.CreateMCPClient(ctx, MCPClient{Name: "Alice Codex", Subject: "usr_alice", CreatedBy: "usr_alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bob Codex", Subject: "usr_bob", CreatedBy: "usr_bob"})
	if err != nil {
		t.Fatal(err)
	}

	assigned, assignedVersion := createLibrarySkillForMCPClientTest(t, store, "assigned-client-skill", "Assigned client skill", "# Assigned only to Alice")
	unbound, _ := createLibrarySkillForMCPClientTest(t, store, "unbound-client-skill", "Unbound client skill", "# Must not leak")
	bobOnly, _ := createLibrarySkillForMCPClientTest(t, store, "bob-client-skill", "Bob client skill", "# Only Bob can read")
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: assigned.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: alice.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: assignedVersion.ID, CapabilityCeiling: []string{"repository.read"}, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	// A generic namespace binding remains valid Library data but does not
	// travel through an MCP-client projection.
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: assigned.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "generic-engineering", Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	unboundBinding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: unbound.ID, ScopeKind: LibraryScopeWorkspace, ScopeID: "workspace-example", Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: bobOnly.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: bob.ID, Mode: LibraryBindingModeTrack, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}

	aliceMCP := clientLibraryServer(t, gateway, alice.Slug)
	activationTool, found := aliceMCP.ListTools()["library_skill_activation"]
	if !found {
		t.Fatal("scoped MCP endpoint did not advertise the activation contract")
	}
	activationSchema, err := json.Marshal(activationTool.Tool)
	if err != nil {
		t.Fatalf("marshal activation tool schema: %v", err)
	}
	if !strings.Contains(string(activationSchema), `"additionalProperties":false`) ||
		!strings.Contains(string(activationSchema), `"contractVersion"`) ||
		!strings.Contains(string(activationSchema), `"contentDigest"`) {
		t.Fatalf("activation tool schema does not declare its no-argument portable contract: %s", activationSchema)
	}
	listed := callLibraryTool(t, aliceMCP, "library_skill_list", nil)
	if !strings.Contains(listed, "Assigned client skill") || strings.Contains(listed, "Unbound client skill") || strings.Contains(listed, "Bob client skill") {
		t.Fatalf("scoped skill list=%s", listed)
	}
	// structuredContent must be a JSON object; strict MCP clients reject a
	// bare array at the result schema boundary.
	if !strings.Contains(listed, `"structuredContent":{`) {
		t.Fatalf("scoped skill list structuredContent is not an object: %s", listed)
	}
	var listedPage struct {
		Skills []struct {
			ID        string `json:"id"`
			BindingID string `json:"bindingId"`
		} `json:"skills"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, listed)), &listedPage); err != nil {
		t.Fatalf("decode scoped skill list: %v\n%s", err, listed)
	}
	if len(listedPage.Skills) != 1 || listedPage.Skills[0].ID != assigned.ID || listedPage.Skills[0].BindingID == "" {
		t.Fatalf("scoped skill list envelope=%+v", listedPage)
	}
	readAssigned := callLibraryTool(t, aliceMCP, "library_skill_read", map[string]any{"skillId": assigned.ID})
	if !strings.Contains(readAssigned, "# Assigned only to Alice") || strings.Contains(readAssigned, "generic-engineering") || strings.Contains(readAssigned, "createdBy") {
		t.Fatalf("scoped skill read=%s", readAssigned)
	}
	if got := callLibraryTool(t, aliceMCP, "library_skill_read", map[string]any{"skillId": unbound.ID}); !strings.Contains(got, "skill not found") || strings.Contains(got, "Must not leak") {
		t.Fatalf("unbound skill leaked through read=%s", got)
	}

	// The handler intentionally has no client-controlled resolution context.
	// Supplying a valid binding from another scope must not select it.
	resolved := callLibraryTool(t, aliceMCP, "library_skill_resolve", map[string]any{
		"bindingId": unboundBinding.ID, "namespaceId": "generic-engineering", "workspaceId": "workspace-example",
	})
	if !strings.Contains(resolved, "# Assigned only to Alice") || !strings.Contains(resolved, `"scopeKind":"agent_surface"`) ||
		strings.Contains(resolved, "Must not leak") || strings.Contains(resolved, "Only Bob can read") || strings.Contains(resolved, unboundBinding.ID) {
		t.Fatalf("scoped skill resolution trusted caller context=%s", resolved)
	}

	// The activation contract has no client-controlled context input. Its
	// verified agent-surface identity comes solely from Alice's durable endpoint
	// projection, and it must remain a context-only host handoff.
	activation := callLibraryTool(t, aliceMCP, "library_skill_activation", map[string]any{
		"bindingId": unboundBinding.ID, "namespaceId": "generic-engineering", "workspaceId": "workspace-example",
	})
	if !strings.Contains(activation, LibrarySkillActivationContractVersion) || !strings.Contains(activation, "# Assigned only to Alice") ||
		!strings.Contains(activation, alice.ID) || !strings.Contains(activation, "bundleDigest") ||
		strings.Contains(activation, "Must not leak") || strings.Contains(activation, "Only Bob can read") ||
		strings.Contains(activation, unboundBinding.ID) || strings.Contains(activation, "usr_alice") ||
		strings.Contains(activation, "effectiveCapabilities") || strings.Contains(activation, "createdBy") {
		t.Fatalf("scoped activation contract was not surface-bound and authority-free: %s", activation)
	}
	if repeated := callLibraryTool(t, aliceMCP, "library_skill_activation", nil); repeated != activation {
		t.Fatalf("activation bundle changed without a Library state change:\nfirst=%s\nsecond=%s", activation, repeated)
	}

	// Validate the actual JSON content emitted by the MCP tool, rather than a
	// Go struct constructed in-process. This catches Engine wire-contract drift
	// against the public host-side adapter before release.
	activationJSON := libraryToolJSONText(t, activation)
	verified, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewBufferString(activationJSON), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("public runtime adapter rejected MCP-emitted activation JSON: %v\n%s", err, activationJSON)
	}
	if verified.AgentSurface().ID != alice.ID || len(verified.Skills()) != 1 || verified.BundleDigest() == "" {
		t.Fatalf("decoded MCP activation=%+v; want Alice surface, one selection, and a bundle digest", verified)
	}
}
