package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func createDirectArtifactForClientVersionTest(t *testing.T, store *FileStore, client MCPClient) (LibraryArtifact, LibraryArtifactVersion) {
	t.Helper()
	_, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(context.Background(), client, LibraryArtifact{
		Title: "Client-owned artifact", Summary: "private", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# Version one"})
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientArtifactWithInitialVersion: %v", err)
	}
	return artifact, version
}

func TestLibraryMCPClientArtifactVersionFileStoreIsOwnedCASAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_artifact_owner")
	sameSubject := newAuthoringLeaseMCPClient(t, store, "usr_artifact_owner")
	reader := newAuthoringLeaseMCPClient(t, store, "usr_artifact_reader")
	artifact, first := createDirectArtifactForClientVersionTest(t, store, owner)

	request := LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "artifact-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest,
		Body: "# Version two",
	}
	updated, err := store.CreateLibraryMCPClientArtifactVersion(ctx, owner, request)
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientArtifactVersion: %v", err)
	}
	if updated.Replayed || updated.Version.ArtifactID != artifact.ID || updated.Version.Version != 2 ||
		updated.Version.ID == first.ID || updated.Version.Digest != libraryDigest("# Version two") ||
		updated.Version.Format != LibraryArtifactFormatMarkdown || updated.Version.CreatedBy != owner.Subject ||
		updated.Version.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("updated immutable version=%+v", updated)
	}
	versions, err := store.LibraryArtifactVersions(ctx, artifact.ID)
	if err != nil || len(versions) != 2 || versions[0].Body != "# Version one" || versions[1].Body != "# Version two" {
		t.Fatalf("versions=%+v err=%v", versions, err)
	}

	replayed, err := store.CreateLibraryMCPClientArtifactVersion(ctx, owner, request)
	if err != nil || !replayed.Replayed || replayed.Version.ID != updated.Version.ID {
		t.Fatalf("exact replay=%+v err=%v", replayed, err)
	}
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, owner, LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "artifact-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Body: "# different",
	}); !errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict) {
		t.Fatalf("changed request-id error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionRequestConflict)
	}
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, owner, LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "stale-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Body: "# stale",
	}); !errors.Is(err, ErrLibraryMCPClientArtifactVersionConflict) {
		t.Fatalf("stale expected-head error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionConflict)
	}

	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: first.ID, ArtifactVersionDigest: first.Digest,
		AgentSurfaceID: reader.ID, CreatedBy: "usr_owner",
	}); err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}
	for _, client := range []MCPClient{sameSubject, reader} {
		if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, LibraryMCPClientArtifactVersionCreateRequest{
			RequestID: "denied-" + client.ID, ArtifactID: artifact.ID,
			ExpectedArtifactVersionID: updated.Version.ID, ExpectedDigest: updated.Version.Digest, Body: "# denied",
		}); !errors.Is(err, ErrLibraryArtifactNotFound) {
			t.Fatalf("%s revised another surface/grant error=%v, want %v", client.ID, err, ErrLibraryArtifactNotFound)
		}
	}

	// The receipt persists with the FileStore and remains enough to make a
	// response-lost retry safe after a process restart.
	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatalf("reopen FileStore: %v", err)
	}
	if replayAfterRestart, err := reopened.CreateLibraryMCPClientArtifactVersion(ctx, owner, request); err != nil || !replayAfterRestart.Replayed || replayAfterRestart.Version.ID != updated.Version.ID {
		t.Fatalf("replay after restart=%+v err=%v", replayAfterRestart, err)
	}
}

func TestMCPClientArtifactVersionToolAppendsOwnedVersionOnly(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_mcp_artifact_owner")
	other := newAuthoringLeaseMCPClient(t, store, "usr_mcp_artifact_other")
	artifact, first := createDirectArtifactForClientVersionTest(t, store, owner)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	ownerMCP := clientLibraryServer(t, gateway, owner.Slug)
	if _, found := ownerMCP.ListTools()["library_artifact_version_create"]; !found {
		t.Fatal("subject-bound MCP server did not advertise library_artifact_version_create")
	}
	updated := callLibraryTool(t, ownerMCP, "library_artifact_version_create", map[string]any{
		"requestId": "tool-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest, "body": "# Tool version two",
	})
	updatedText := libraryToolJSONText(t, updated)
	if strings.Contains(updated, `"isError":true`) || !strings.Contains(updatedText, `"version":2`) || !strings.Contains(updatedText, `"replayed":false`) {
		t.Fatalf("owned tool update=%s", updated)
	}
	if replay := callLibraryTool(t, ownerMCP, "library_artifact_version_create", map[string]any{
		"requestId": "tool-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest, "body": "# Tool version two",
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(libraryToolJSONText(t, replay), `"replayed":true`) {
		t.Fatalf("tool replay=%s", replay)
	}
	otherMCP := clientLibraryServer(t, gateway, other.Slug)
	if denied := callLibraryTool(t, otherMCP, "library_artifact_version_create", map[string]any{
		"requestId": "other-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest, "body": "# denied",
	}); !strings.Contains(denied, `"isError":true`) || !strings.Contains(denied, "artifact not found") {
		t.Fatalf("other client update=%s", denied)
	}
}

func TestLibraryMCPClientArtifactVersionRejectsStaleClientAndHostAttestedOutput(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_stale_artifact_client")
	artifact, first := createDirectArtifactForClientVersionTest(t, store, client)
	request := LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "after-oauth-reset", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Body: "# denied after reset",
	}
	if _, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatalf("ResetMCPClientOAuthClient: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, request); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("stale OAuth endpoint update error=%v, want %v", err, ErrMCPClientNotFound)
	}

	revoked := newAuthoringLeaseMCPClient(t, store, "usr_revoked_artifact_client")
	revokedArtifact, revokedFirst := createDirectArtifactForClientVersionTest(t, store, revoked)
	if _, err := store.RevokeMCPClient(ctx, revoked.ID, revoked.Subject, MCPClientPrecondition{ID: revoked.ID, Revision: revoked.Revision}); err != nil {
		t.Fatalf("RevokeMCPClient: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, revoked, LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "after-revoke", ArtifactID: revokedArtifact.ID,
		ExpectedArtifactVersionID: revokedFirst.ID, ExpectedDigest: revokedFirst.Digest, Body: "# denied after revoke",
	}); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("revoked client update error=%v, want %v", err, ErrMCPClientNotFound)
	}

	// Host-attested skill output is deliberately readable by its surface, but
	// it must never become mutable through the ordinary direct-artifact tool.
	runtime := newRuntimeAttestationFixture(t, store)
	raw := runtimeAttestationBody(t, runtime, "host-artifact-update", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano), "# host output")
	signature := ed25519.Sign(runtime.private, libraryRuntimeAttestationSigningMessage(libraryRuntimeAttestationPath(runtime.client.Slug), raw))
	_, hostArtifact, hostVersion, _, err := store.IngestLibraryRuntimeAttestation(ctx, LibraryRuntimeAttestation{
		ClientID: runtime.client.ID, Path: libraryRuntimeAttestationPath(runtime.client.Slug), RawBody: raw, Signature: signature,
	})
	if err != nil {
		t.Fatalf("IngestLibraryRuntimeAttestation: %v", err)
	}
	bound, err := store.BindMCPClientOAuthClient(ctx, runtime.client.ID, "oauth-host-artifact-update", MCPClientPrecondition{ID: runtime.client.ID, Revision: runtime.client.Revision}, PlatformActor{UserID: runtime.client.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("bind host client OAuth identity: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, bound, LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "host-output-update", ArtifactID: hostArtifact.ID,
		ExpectedArtifactVersionID: hostVersion.ID, ExpectedDigest: hostVersion.Digest, Body: "# must not replace host output",
	}); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("host-attested output update error=%v, want %v", err, ErrLibraryArtifactNotFound)
	}
}

func TestLibraryMCPClientArtifactVersionFileStoreCASAllowsOneConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_concurrent_artifact_client")
	artifact, first := createDirectArtifactForClientVersionTest(t, store, client)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, input := range []struct {
		requestID string
		body      string
	}{
		{requestID: "concurrent-one", body: "# writer one"},
		{requestID: "concurrent-two", body: "# writer two"},
	} {
		input := input
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, LibraryMCPClientArtifactVersionCreateRequest{
				RequestID: input.requestID, ArtifactID: artifact.ID,
				ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Body: input.body,
			})
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	succeeded, conflicted := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLibraryMCPClientArtifactVersionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent artifact update error=%v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent artifact update results succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	if versions, err := store.LibraryArtifactVersions(ctx, artifact.ID); err != nil || len(versions) != 2 {
		t.Fatalf("concurrent versions=%+v err=%v", versions, err)
	}
}
