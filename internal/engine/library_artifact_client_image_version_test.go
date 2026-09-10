package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

func libraryArtifactRevisionTestSVG(t *testing.T) (libraryArtifactImageCanonical, string) {
	t.Helper()
	raw := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="1"><path d="M0 0 L2 1" fill="#224466"/></svg>`)
	transport := base64.StdEncoding.EncodeToString(raw)
	image, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, transport)
	if err != nil {
		t.Fatalf("normalize revision SVG: %v", err)
	}
	return image, transport
}

func libraryArtifactRevisionTestJPEG(t *testing.T) (libraryArtifactImageCanonical, string) {
	t.Helper()
	canvas := image.NewNRGBA(image.Rect(0, 0, 2, 1))
	canvas.SetNRGBA(0, 0, color.NRGBA{R: 0x88, G: 0x33, B: 0x22, A: 0xff})
	canvas.SetNRGBA(1, 0, color.NRGBA{R: 0x22, G: 0x77, B: 0x44, A: 0xff})
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, canvas, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	transport := base64.StdEncoding.EncodeToString(encoded.Bytes())
	image, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMEJPEG, transport)
	if err != nil {
		t.Fatalf("normalize revision JPEG: %v", err)
	}
	return image, transport
}

func createDirectImageArtifactForClientVersionTest(t *testing.T, store *FileStore, client MCPClient) (LibraryArtifact, LibraryArtifactVersion, libraryArtifactImageCanonical) {
	t.Helper()
	image, _ := libraryArtifactTestPNG(t)
	_, artifact, version, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(context.Background(), client, LibraryArtifact{
		Title: "Client-owned image", Summary: "private", Origin: LibraryArtifactOriginAgentDirect,
	}, image, "Initial raster")
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactWithInitialVersion: %v", err)
	}
	return artifact, version, image
}

func TestLibraryMCPClientImageArtifactVersionFileStoreIsOwnedCASAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_image_revision_owner")
	sameSubject := newAuthoringLeaseMCPClient(t, store, "usr_image_revision_owner")
	reader := newAuthoringLeaseMCPClient(t, store, "usr_image_revision_reader")
	artifact, first, firstImage := createDirectImageArtifactForClientVersionTest(t, store, owner)
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: first.ID, ArtifactVersionDigest: first.Digest,
		AgentSurfaceID: reader.ID, CreatedBy: "usr_image_revision_owner",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}
	secondImage, _ := libraryArtifactRevisionTestJPEG(t)
	request := LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "image-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest,
		Image: secondImage, AltText: "Version two raster",
	}
	updated, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, request)
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactVersion: %v", err)
	}
	if updated.Replayed || updated.Version.ArtifactID != artifact.ID || updated.Version.Version != 2 ||
		updated.Version.ID == first.ID || updated.Version.Digest != secondImage.Digest || updated.Version.Format != LibraryArtifactFormatImage ||
		updated.Version.CreatedBy != owner.Subject || updated.Version.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("updated immutable image version=%+v", updated)
	}
	if len(store.libraryArtifactMediaBlobs) != 2 {
		t.Fatalf("media blobs=%d, want 2 immutable blobs", len(store.libraryArtifactMediaBlobs))
	}
	firstBytes, found, err := store.LibraryArtifactImageBytes(ctx, artifact.ID, first.ID)
	if err != nil || !found || !bytes.Equal(firstBytes, firstImage.Bytes) {
		t.Fatalf("first version bytes changed=%x found=%t err=%v", firstBytes, found, err)
	}
	secondMedia, found, err := store.LibraryArtifactMedia(ctx, artifact.ID, updated.Version.ID)
	if err != nil || !found || secondMedia.MIMEType != libraryArtifactImageMIMEJPEG || secondMedia.DeliveryMode != libraryArtifactImageDeliveryInline || secondMedia.AltText != "Version two raster" {
		t.Fatalf("updated media=%+v found=%t err=%v", secondMedia, found, err)
	}
	if secondBytes, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, updated.Version.ID); err != nil || !found || !bytes.Equal(secondBytes, secondImage.Bytes) {
		t.Fatalf("JPEG revision bytes=%x found=%t err=%v", secondBytes, found, err)
	}
	if access, allowed := libraryMCPClientArtifactAccess(ctx, store, artifact, reader); !allowed || access.Mode != "granted" || access.Version.ID != first.ID {
		t.Fatalf("v1 grant did not remain pinned after owner update: access=%+v allowed=%t", access, allowed)
	}
	activeGrant, found := store.ActiveLibraryArtifactGrant(ctx, artifact.ID, reader.ID)
	if !found || activeGrant.ID != grant.ID || activeGrant.ArtifactVersionID != first.ID || activeGrant.ArtifactVersionDigest != first.Digest {
		t.Fatalf("stored grant was retargeted: grant=%+v found=%t", activeGrant, found)
	}

	replayed, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, request)
	if err != nil || !replayed.Replayed || replayed.Version.ID != updated.Version.ID {
		t.Fatalf("exact image replay=%+v err=%v", replayed, err)
	}
	changed := request
	changed.AltText = "Changed request payload"
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, changed); !errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict) {
		t.Fatalf("changed image request-id error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionRequestConflict)
	}
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "stale-image-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Image: secondImage,
	}); !errors.Is(err, ErrLibraryMCPClientArtifactVersionConflict) {
		t.Fatalf("stale image expected-head error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionConflict)
	}

	thirdImage, _ := libraryArtifactRevisionTestSVG(t)
	svgRequest := LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "image-v3", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: updated.Version.ID, ExpectedDigest: updated.Version.Digest,
		Image: thirdImage, AltText: "Version three vector",
	}
	svgUpdated, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, svgRequest)
	if err != nil || svgUpdated.Replayed || svgUpdated.Version.Version != 3 || svgUpdated.Version.Digest != thirdImage.Digest {
		t.Fatalf("SVG image revision=%+v err=%v", svgUpdated, err)
	}
	if len(store.libraryArtifactMediaBlobs) != 3 {
		t.Fatalf("media blobs=%d, want 3 immutable blobs", len(store.libraryArtifactMediaBlobs))
	}
	thirdMedia, found, err := store.LibraryArtifactMedia(ctx, artifact.ID, svgUpdated.Version.ID)
	if err != nil || !found || thirdMedia.MIMEType != libraryArtifactImageMIMESVG || thirdMedia.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly || thirdMedia.AltText != "Version three vector" {
		t.Fatalf("SVG revision media=%+v found=%t err=%v", thirdMedia, found, err)
	}
	if _, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, svgUpdated.Version.ID); err != nil || found {
		t.Fatalf("SVG revision became inline raster found=%t err=%v", found, err)
	}
	for _, client := range []MCPClient{sameSubject, reader} {
		if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, LibraryMCPClientImageArtifactVersionCreateRequest{
			RequestID: "denied-image-" + client.ID, ArtifactID: artifact.ID,
			ExpectedArtifactVersionID: svgUpdated.Version.ID, ExpectedDigest: svgUpdated.Version.Digest, Image: thirdImage,
		}); !errors.Is(err, ErrLibraryArtifactNotFound) {
			t.Fatalf("%s revised another surface/grant image error=%v, want %v", client.ID, err, ErrLibraryArtifactNotFound)
		}
	}

	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatalf("reopen FileStore: %v", err)
	}
	if replayAfterRestart, err := reopened.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, svgRequest); err != nil || !replayAfterRestart.Replayed || replayAfterRestart.Version.ID != svgUpdated.Version.ID {
		t.Fatalf("image replay after restart=%+v err=%v", replayAfterRestart, err)
	}
}

func TestLibraryMCPClientImageArtifactVersionFileStoreCASAllowsOneConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_concurrent_image_revision")
	artifact, first, _ := createDirectImageArtifactForClientVersionTest(t, store, client)
	jpegImage, _ := libraryArtifactRevisionTestJPEG(t)
	svgImage, _ := libraryArtifactRevisionTestSVG(t)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, input := range []struct {
		requestID string
		image     libraryArtifactImageCanonical
	}{
		{requestID: "concurrent-image-jpeg", image: jpegImage},
		{requestID: "concurrent-image-svg", image: svgImage},
	} {
		input := input
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, LibraryMCPClientImageArtifactVersionCreateRequest{
				RequestID: input.requestID, ArtifactID: artifact.ID,
				ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Image: input.image,
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
			t.Fatalf("concurrent image append error=%v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent image append outcomes succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	versions, err := store.LibraryArtifactVersions(ctx, artifact.ID)
	if err != nil || len(versions) != 2 || len(store.libraryArtifactMediaBlobs) != 2 {
		t.Fatalf("concurrent image append versions=%+v blobs=%d err=%v", versions, len(store.libraryArtifactMediaBlobs), err)
	}
}

func TestMCPClientImageArtifactVersionToolIsSubjectBoundAndNeverEchoesBytes(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_mcp_image_revision_owner")
	other := newAuthoringLeaseMCPClient(t, store, "usr_mcp_image_revision_other")
	artifact, first, _ := createDirectImageArtifactForClientVersionTest(t, store, owner)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	ownerMCP := clientLibraryServer(t, gateway, owner.Slug)
	if _, found := ownerMCP.ListTools()["library_artifact_image_version_create"]; !found {
		t.Fatal("subject-bound MCP server did not advertise library_artifact_image_version_create")
	}
	rootMCP := server.NewMCPServer("library-image-revision-root", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(rootMCP, store, nil)
	if _, found := rootMCP.ListTools()["library_artifact_image_version_create"]; found {
		t.Fatal("root MCP unexpectedly advertised client-owned image revision")
	}
	_, transport := libraryArtifactRevisionTestSVG(t)
	updated := callLibraryTool(t, ownerMCP, "library_artifact_image_version_create", map[string]any{
		"requestId": "tool-image-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest,
		"mimeType": libraryArtifactImageMIMESVG, "dataBase64": transport, "altText": "Private tool vector",
	})
	updatedText := libraryToolJSONText(t, updated)
	if strings.Contains(updated, `"isError":true`) || strings.Contains(updated, transport) || !strings.Contains(updatedText, `"version":2`) || !strings.Contains(updatedText, `"mimeType":"image/svg+xml"`) || !strings.Contains(updatedText, `"replayed":false`) {
		t.Fatalf("owned image tool update=%s", updated)
	}
	if replay := callLibraryTool(t, ownerMCP, "library_artifact_image_version_create", map[string]any{
		"requestId": "tool-image-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest,
		"mimeType": libraryArtifactImageMIMESVG, "dataBase64": transport, "altText": "Private tool vector",
	}); strings.Contains(replay, `"isError":true`) || !strings.Contains(libraryToolJSONText(t, replay), `"replayed":true`) {
		t.Fatalf("tool image replay=%s", replay)
	}
	otherMCP := clientLibraryServer(t, gateway, other.Slug)
	if denied := callLibraryTool(t, otherMCP, "library_artifact_image_version_create", map[string]any{
		"requestId": "other-image-v2", "artifactId": artifact.ID,
		"expectedArtifactVersionId": first.ID, "expectedDigest": first.Digest,
		"mimeType": libraryArtifactImageMIMESVG, "dataBase64": transport,
	}); !strings.Contains(denied, `"isError":true`) || !strings.Contains(denied, "artifact not found") {
		t.Fatalf("other client image update=%s", denied)
	}
	versions, err := store.LibraryArtifactVersions(ctx, artifact.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("denied/malformed tool calls changed versions=%+v err=%v", versions, err)
	}
	if malformed := callLibraryTool(t, ownerMCP, "library_artifact_image_version_create", map[string]any{
		"requestId": "bad-image-v3", "artifactId": artifact.ID,
		"expectedArtifactVersionId": versions[1].ID, "expectedDigest": versions[1].Digest,
		"mimeType": libraryArtifactImageMIMEPNG, "dataBase64": "AAAA",
	}); !strings.Contains(malformed, `"isError":true`) || !strings.Contains(malformed, "invalid image artifact version input") {
		t.Fatalf("malformed image update=%s", malformed)
	}
	versions, err = store.LibraryArtifactVersions(ctx, artifact.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("malformed tool call changed versions=%+v err=%v", versions, err)
	}
}

func TestLibraryMCPClientImageArtifactVersionRejectsStaleAndRevokedClient(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_image_revision_stale")
	artifact, first, _ := createDirectImageArtifactForClientVersionTest(t, store, client)
	image, _ := libraryArtifactRevisionTestSVG(t)
	request := LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "stale-client-image", ArtifactID: artifact.ID, ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Image: image,
	}
	if _, err := store.ResetMCPClientOAuthClient(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatalf("ResetMCPClientOAuthClient: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, request); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("stale client image update error=%v, want %v", err, ErrMCPClientNotFound)
	}

	revoked := newAuthoringLeaseMCPClient(t, store, "usr_image_revision_revoked")
	revokedArtifact, revokedFirst, _ := createDirectImageArtifactForClientVersionTest(t, store, revoked)
	if _, err := store.RevokeMCPClient(ctx, revoked.ID, revoked.Subject, MCPClientPrecondition{ID: revoked.ID, Revision: revoked.Revision}); err != nil {
		t.Fatalf("RevokeMCPClient: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, revoked, LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "revoked-client-image", ArtifactID: revokedArtifact.ID,
		ExpectedArtifactVersionID: revokedFirst.ID, ExpectedDigest: revokedFirst.Digest, Image: image,
	}); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("revoked client image update error=%v, want %v", err, ErrMCPClientNotFound)
	}

	// Host-attested skill output is readable by the originating surface, but a
	// regular client image append must not convert it into mutable direct
	// provenance—even if its payload is a valid canonical image.
	runtime := newRuntimeAttestationFixture(t, store)
	raw := runtimeAttestationBody(t, runtime, "host-image-update", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano), "# host output")
	signature := ed25519.Sign(runtime.private, libraryRuntimeAttestationSigningMessage(libraryRuntimeAttestationPath(runtime.client.Slug), raw))
	_, hostArtifact, hostVersion, _, err := store.IngestLibraryRuntimeAttestation(ctx, LibraryRuntimeAttestation{
		ClientID: runtime.client.ID, Path: libraryRuntimeAttestationPath(runtime.client.Slug), RawBody: raw, Signature: signature,
	})
	if err != nil {
		t.Fatalf("IngestLibraryRuntimeAttestation: %v", err)
	}
	bound, err := store.BindMCPClientOAuthClient(ctx, runtime.client.ID, "oauth-host-image-update", MCPClientPrecondition{ID: runtime.client.ID, Revision: runtime.client.Revision}, PlatformActor{UserID: runtime.client.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("bind host client OAuth identity: %v", err)
	}
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, bound, LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "host-image-output-update", ArtifactID: hostArtifact.ID,
		ExpectedArtifactVersionID: hostVersion.ID, ExpectedDigest: hostVersion.Digest, Image: image,
	}); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("host-attested image update error=%v, want %v", err, ErrLibraryArtifactNotFound)
	}
}
