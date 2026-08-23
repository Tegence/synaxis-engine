package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

func libraryArtifactTestPNG(t *testing.T) (libraryArtifactImageCanonical, string) {
	t.Helper()
	canvas := image.NewNRGBA(image.Rect(0, 0, 2, 1))
	canvas.SetNRGBA(0, 0, color.NRGBA{R: 0x11, G: 0x22, B: 0x33, A: 0xff})
	canvas.SetNRGBA(1, 0, color.NRGBA{R: 0xaa, G: 0xbb, B: 0xcc, A: 0xff})
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, canvas); err != nil {
		t.Fatal(err)
	}
	transport := base64.StdEncoding.EncodeToString(encoded.Bytes())
	canonical, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMEPNG, transport)
	if err != nil {
		t.Fatalf("normalize test PNG: %v", err)
	}
	return canonical, transport
}

func libraryToolArtifactCreateResult(t *testing.T, response string) struct {
	ArtifactID string `json:"artifactId"`
	VersionID  string `json:"artifactVersionId"`
	Digest     string `json:"digest"`
} {
	t.Helper()
	var result struct {
		ArtifactID string `json:"artifactId"`
		VersionID  string `json:"artifactVersionId"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, response)), &result); err != nil {
		t.Fatalf("decode image artifact create result: %v\n%s", err, response)
	}
	return result
}

type libraryArtifactImageMCPMetadata struct {
	ArtifactID        string               `json:"artifactId"`
	ArtifactVersionID string               `json:"artifactVersionId"`
	Access            string               `json:"access"`
	Digest            string               `json:"digest"`
	DownloadOnly      bool                 `json:"downloadOnly"`
	Media             LibraryArtifactMedia `json:"media"`
}

// libraryArtifactImageMetadataResult extracts the JSON text that accompanies
// an MCP ImageContent result. It deliberately parses the nested content rather
// than looking for unescaped JSON in the outer JSON-RPC envelope.
func libraryArtifactImageMetadataResult(t *testing.T, response string) libraryArtifactImageMCPMetadata {
	t.Helper()
	var envelope struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		t.Fatalf("decode image artifact MCP response: %v\n%s", err, response)
	}
	for _, content := range envelope.Result.Content {
		if content.Type != "text" || content.Text == "" {
			continue
		}
		var metadata libraryArtifactImageMCPMetadata
		if err := json.Unmarshal([]byte(content.Text), &metadata); err != nil {
			t.Fatalf("decode image artifact MCP metadata: %v\n%s", err, response)
		}
		return metadata
	}
	t.Fatalf("image artifact response had no metadata text content: %s", response)
	return libraryArtifactImageMCPMetadata{}
}

type libraryArtifactImageDownloadPayload struct {
	ArtifactID        string               `json:"artifactId"`
	ArtifactVersionID string               `json:"artifactVersionId"`
	Access            string               `json:"access"`
	Digest            string               `json:"digest"`
	Media             LibraryArtifactMedia `json:"media"`
	DataBase64        string               `json:"dataBase64"`
}

func decodeLibraryArtifactImageDownloadPayload(t *testing.T, response string) libraryArtifactImageDownloadPayload {
	t.Helper()
	var payload libraryArtifactImageDownloadPayload
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, response)), &payload); err != nil {
		t.Fatalf("decode image artifact download payload: %v\n%s", err, response)
	}
	return payload
}

func TestLibraryArtifactMediaFileStorePreservesPrivateVersionAndGrantFences(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	owner, err := store.CreateMCPClient(ctx, MCPClient{Name: "Image owner", Subject: "usr_image_owner", CreatedBy: "usr_image_owner"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.CreateMCPClient(ctx, MCPClient{Name: "Image reader", Subject: "usr_image_reader", CreatedBy: "usr_image_reader"})
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := libraryArtifactTestPNG(t)
	run, artifact, version, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, owner, LibraryArtifact{
		Title: "Private systems diagram", Summary: "Private raster image", Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, "Two colored cells")
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactWithInitialVersion: %v", err)
	}
	if version.Format != LibraryArtifactFormatImage || version.Body != "" || version.Digest != canonical.Digest || version.SizeBytes != canonical.SizeBytes || run.OutputDigest != canonical.Digest ||
		artifact.CreatedBy != owner.Subject || artifact.AgentSurfaceID != owner.ID || run.ActorRef != owner.Subject || run.SurfaceRef != owner.ID {
		t.Fatalf("image provenance/version = run=%+v artifact=%+v version=%+v", run, artifact, version)
	}
	media, found, err := store.LibraryArtifactMedia(ctx, artifact.ID, version.ID)
	if err != nil || !found || media.MIMEType != libraryArtifactImageMIMEPNG || media.AltText != "Two colored cells" || media.DeliveryMode != libraryArtifactImageDeliveryInline {
		t.Fatalf("stored image media=%+v found=%t err=%v", media, found, err)
	}
	storedBytes, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, version.ID)
	if err != nil || !found || !bytes.Equal(storedBytes, canonical.Bytes) {
		t.Fatalf("stored raster bytes=%x found=%t err=%v", storedBytes, found, err)
	}
	page, err := store.LibraryMCPClientArtifactPage(ctx, owner, LibraryMCPClientArtifactCursor{}, 10)
	if err != nil || len(page.Artifacts) != 1 || page.Artifacts[0].Version.Format != LibraryArtifactFormatImage || page.Artifacts[0].Version.Digest != version.Digest {
		t.Fatalf("owned image page=%+v err=%v", page, err)
	}
	_, duplicateArtifact, duplicateVersion, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, owner, LibraryArtifact{
		Title: "Independently stored duplicate image", Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, "")
	if err != nil || duplicateArtifact.ID == artifact.ID || duplicateVersion.ID == version.ID || len(store.libraryArtifactMediaBlobs) != 2 {
		t.Fatalf("same digest was unexpectedly deduplicated: artifact=%+v version=%+v blobs=%d err=%v", duplicateArtifact, duplicateVersion, len(store.libraryArtifactMediaBlobs), err)
	}

	if _, _, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Unbacked image", Origin: LibraryArtifactOriginHuman, CreatedBy: "usr_owner",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatImage, CreatedBy: "usr_owner"}); err == nil {
		t.Fatal("generic artifact create accepted an image without a media blob transaction")
	}

	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
		AgentSurfaceID: reader.ID, CreatedBy: "usr_owner",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}
	if access, allowed := libraryMCPClientArtifactAccess(ctx, store, artifact, reader); !allowed || access.Mode != "granted" || access.Version.ID != version.ID {
		t.Fatalf("granted image access=%+v allowed=%t", access, allowed)
	}
	if _, err := store.RevokeLibraryArtifactGrant(ctx, artifact.ID, grant.ID, "usr_owner", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeLibraryArtifactGrant: %v", err)
	}
	if _, allowed := libraryMCPClientArtifactAccess(ctx, store, artifact, reader); allowed {
		t.Fatal("revoked image grant remained readable")
	}

	if _, err := store.ReviewLibraryArtifactVersion(ctx, artifact.ID, version.ID, LibraryRedactionApproved, "usr_reviewer", time.Now().UTC()); err != nil {
		t.Fatalf("ReviewLibraryArtifactVersion image: %v", err)
	}
	if _, err := store.LibraryPublicationCandidate(ctx, artifact.ID); !errors.Is(err, ErrLibraryPublicationNotReady) {
		t.Fatalf("image publication candidate error=%v, want publication not ready", err)
	}

	beforeArtifacts, err := store.LibraryArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeRuns, err := store.LibraryRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, owner, LibraryArtifact{
		Title: "Invalid source image", Origin: LibraryArtifactOriginAgentDirect,
		SourceArtifactID: "libart_missing", SourceArtifactVersionID: "libartv_missing", SourceArtifactDigest: canonical.Digest,
	}, canonical, ""); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("invalid image source error=%v, want artifact not found", err)
	}
	afterArtifacts, _ := store.LibraryArtifacts(ctx)
	afterRuns, _ := store.LibraryRuns(ctx)
	if len(afterArtifacts) != len(beforeArtifacts) || len(afterRuns) != len(beforeRuns) || len(store.libraryArtifactMediaBlobs) != 2 {
		t.Fatalf("invalid image write was not atomic: artifacts %d->%d runs %d->%d blobs=%d", len(beforeArtifacts), len(afterArtifacts), len(beforeRuns), len(afterRuns), len(store.libraryArtifactMediaBlobs))
	}
}

// A database or on-disk corruption must not be able to relabel static SVG as
// inline PNG while retaining its digest and parent version. Raster reads parse
// the bytes themselves before producing MCP ImageContent.
func TestLibraryArtifactRasterReadRejectsRelabeledSVGMedia(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	source := `<svg xmlns="http://www.w3.org/2000/svg" width="2" height="1"><path d="M0 0 L2 1" fill="#112233"/></svg>`
	canonical, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, base64.StdEncoding.EncodeToString([]byte(source)))
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, version, err := store.CreateLibraryRootMCPImageArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Tampered SVG metadata", Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, "")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	blob := store.libraryArtifactMediaBlobLocked(version.ID)
	if blob == nil {
		store.mu.Unlock()
		t.Fatal("created SVG blob is missing")
	}
	// This is structurally allowed by the metadata fields alone: dimensions,
	// digest, byte count, and parent version remain valid. The byte parser is
	// the required final fence before inline raster delivery.
	blob.MIMEType = libraryArtifactImageMIMEPNG
	blob.DeliveryMode = libraryArtifactImageDeliveryInline
	store.mu.Unlock()
	if raster, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, version.ID); found || err == nil || len(raster) != 0 {
		t.Fatalf("relabeled SVG reached FileStore raster read: bytes=%x found=%t err=%v", raster, found, err)
	}
	if downloaded, found, err := store.LibraryArtifactImageBytes(ctx, artifact.ID, version.ID); found || err == nil || len(downloaded) != 0 {
		t.Fatalf("relabeled SVG reached FileStore download read: bytes=%x found=%t err=%v", downloaded, found, err)
	}
}

func TestLibraryArtifactImageMCPRootAndClientResultsNeverInlineSVG(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	canonical, transport := libraryArtifactTestPNG(t)

	rootServer := server.NewMCPServer("library-media-root", "1.0.0", server.WithToolCapabilities(true))
	RegisterLibraryArtifactTools(rootServer, store, nil)
	rootCreatedResponse := callLibraryTool(t, rootServer, "library_artifact_image_create", map[string]any{
		"title": "Root raster", "mimeType": libraryArtifactImageMIMEPNG, "dataBase64": transport, "altText": "Root private raster",
	})
	if strings.Contains(rootCreatedResponse, `"isError":true`) || strings.Contains(rootCreatedResponse, transport) {
		t.Fatalf("root image create leaked/failed: %s", rootCreatedResponse)
	}
	rootCreated := libraryToolArtifactCreateResult(t, rootCreatedResponse)
	if rootCreated.Digest != canonical.Digest {
		t.Fatalf("root image digest=%q want canonical=%q", rootCreated.Digest, canonical.Digest)
	}
	rootRead := callLibraryTool(t, rootServer, "library_artifact_read", map[string]any{"artifactId": rootCreated.ArtifactID})
	if !strings.Contains(rootRead, `"type":"image"`) || !strings.Contains(rootRead, `"mimeType":"image/png"`) {
		t.Fatalf("root raster read did not return MCP image content: %s", rootRead)
	}
	rootList := callLibraryTool(t, rootServer, "library_artifact_list", nil)
	if strings.Contains(rootList, transport) {
		t.Fatalf("metadata list leaked image bytes: %s", rootList)
	}

	safeSVG := `<svg xmlns="http://www.w3.org/2000/svg" width="2" height="1"><path d="M0 0 L2 1" fill="#112233"/></svg>`
	svgTransport := base64.StdEncoding.EncodeToString([]byte(safeSVG))
	svgCreate := callLibraryTool(t, rootServer, "library_artifact_image_create", map[string]any{
		"title": "Root vector", "mimeType": libraryArtifactImageMIMESVG, "dataBase64": svgTransport,
	})
	if strings.Contains(svgCreate, `"isError":true`) || strings.Contains(svgCreate, svgTransport) {
		t.Fatalf("root SVG create leaked/failed: %s", svgCreate)
	}
	svgCreated := libraryToolArtifactCreateResult(t, svgCreate)
	svgRead := callLibraryTool(t, rootServer, "library_artifact_read", map[string]any{"artifactId": svgCreated.ArtifactID})
	if strings.Contains(svgRead, `"type":"image"`) || strings.Contains(svgRead, `<svg`) || !strings.Contains(svgRead, `"downloadOnly":true`) {
		t.Fatalf("SVG read was not metadata-only/download-only: %s", svgRead)
	}
	if svgMetadata := libraryArtifactImageMetadataResult(t, svgRead); !svgMetadata.DownloadOnly || svgMetadata.Media.MIMEType != libraryArtifactImageMIMESVG {
		t.Fatalf("SVG read metadata=%+v", svgMetadata)
	}
	svgDownload := callLibraryTool(t, rootServer, "library_artifact_image_download", map[string]any{
		"artifactId": svgCreated.ArtifactID, "artifactVersionId": svgCreated.VersionID,
	})
	if strings.Contains(svgDownload, `"type":"image"`) || strings.Contains(svgDownload, `<svg`) || strings.Contains(svgDownload, `"url"`) {
		t.Fatalf("SVG download was rendered or exposed a URL: %s", svgDownload)
	}
	svgPayload := decodeLibraryArtifactImageDownloadPayload(t, svgDownload)
	downloadedSVG, err := base64.StdEncoding.DecodeString(svgPayload.DataBase64)
	if err != nil {
		t.Fatalf("decode SVG download: %v", err)
	}
	storedSVG, found, err := store.LibraryArtifactImageBytes(ctx, svgCreated.ArtifactID, svgCreated.VersionID)
	if err != nil || !found || !bytes.Equal(downloadedSVG, storedSVG) || svgPayload.Digest != svgCreated.Digest || svgPayload.Media.MIMEType != libraryArtifactImageMIMESVG {
		t.Fatalf("SVG download payload=%+v found=%t err=%v", svgPayload, found, err)
	}
	wrongVersionDownload := callLibraryTool(t, rootServer, "library_artifact_image_download", map[string]any{
		"artifactId": svgCreated.ArtifactID, "artifactVersionId": rootCreated.VersionID,
	})
	if !strings.Contains(wrongVersionDownload, "artifact not found") || strings.Contains(wrongVersionDownload, svgPayload.DataBase64) {
		t.Fatalf("root image download accepted a mismatched parent version: %s", wrongVersionDownload)
	}

	before, err := store.LibraryArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	malformed := callLibraryTool(t, rootServer, "library_artifact_image_create", map[string]any{
		"title": "bad", "mimeType": libraryArtifactImageMIMEPNG, "dataBase64": "data:image/png;base64,AAAA",
	})
	after, _ := store.LibraryArtifacts(ctx)
	if !strings.Contains(malformed, "invalid image artifact input") || len(after) != len(before) {
		t.Fatalf("malformed image acceptance/atomicity response=%s artifacts=%d->%d", malformed, len(before), len(after))
	}

	owner, err := store.CreateMCPClient(ctx, MCPClient{Name: "Media client owner", Subject: "usr_media_owner", CreatedBy: "usr_media_owner"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.CreateMCPClient(ctx, MCPClient{Name: "Media client reader", Subject: "usr_media_reader", CreatedBy: "usr_media_reader"})
	if err != nil {
		t.Fatal(err)
	}
	ownerServer := server.NewMCPServer("library-media-client-owner", "1.0.0", server.WithToolCapabilities(true))
	registerMCPClientLibraryTools(ownerServer, store, nil, owner, func(context.Context) bool { return true })
	clientCreate := callLibraryTool(t, ownerServer, "library_artifact_image_create", map[string]any{
		"title": "Client raster", "mimeType": libraryArtifactImageMIMEPNG, "dataBase64": transport, "altText": "Client private raster",
	})
	if strings.Contains(clientCreate, `"isError":true`) || strings.Contains(clientCreate, transport) {
		t.Fatalf("client image create leaked/failed: %s", clientCreate)
	}
	clientCreated := libraryToolArtifactCreateResult(t, clientCreate)
	clientList := callLibraryTool(t, ownerServer, "library_artifact_list", nil)
	if !strings.Contains(clientList, `"format":"image"`) || strings.Contains(clientList, transport) {
		t.Fatalf("client metadata list did not remain metadata-only: %s", clientList)
	}

	readerServer := server.NewMCPServer("library-media-client-reader", "1.0.0", server.WithToolCapabilities(true))
	registerMCPClientLibraryTools(readerServer, store, nil, reader, func(context.Context) bool { return true })
	svgVersion, found := store.LibraryArtifactVersion(ctx, svgCreated.ArtifactID, svgCreated.VersionID)
	if !found {
		t.Fatal("root SVG version disappeared")
	}
	svgGrant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: svgCreated.ArtifactID, ArtifactVersionID: svgVersion.ID, ArtifactVersionDigest: svgVersion.Digest,
		AgentSurfaceID: reader.ID, CreatedBy: "usr_media_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	clientSVGDownload := callLibraryTool(t, readerServer, "library_artifact_image_download", map[string]any{"artifactId": svgCreated.ArtifactID, "artifactVersionId": svgVersion.ID})
	if strings.Contains(clientSVGDownload, `"type":"image"`) || strings.Contains(clientSVGDownload, `<svg`) {
		t.Fatalf("client SVG download was rendered inline: %s", clientSVGDownload)
	}
	clientSVGPayload := decodeLibraryArtifactImageDownloadPayload(t, clientSVGDownload)
	clientSVGBytes, err := base64.StdEncoding.DecodeString(clientSVGPayload.DataBase64)
	if err != nil || clientSVGPayload.Access != "granted" || clientSVGPayload.Media.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly || !bytes.Equal(clientSVGBytes, storedSVG) {
		t.Fatalf("client SVG download=%+v decoded=%x err=%v", clientSVGPayload, clientSVGBytes, err)
	}
	if _, err := store.RevokeLibraryArtifactGrant(ctx, svgCreated.ArtifactID, svgGrant.ID, "usr_media_owner", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if revoked := callLibraryTool(t, readerServer, "library_artifact_image_download", map[string]any{"artifactId": svgCreated.ArtifactID, "artifactVersionId": svgVersion.ID}); !strings.Contains(revoked, "artifact not found") || strings.Contains(revoked, clientSVGPayload.DataBase64) {
		t.Fatalf("revoked client SVG download=%s", revoked)
	}
	if denied := callLibraryTool(t, readerServer, "library_artifact_read", map[string]any{"artifactId": clientCreated.ArtifactID}); !strings.Contains(denied, "artifact not found") || strings.Contains(denied, transport) {
		t.Fatalf("ungranted client image read=%s", denied)
	}
	if denied := callLibraryTool(t, readerServer, "library_artifact_image_download", map[string]any{"artifactId": clientCreated.ArtifactID, "artifactVersionId": clientCreated.VersionID}); !strings.Contains(denied, "artifact not found") || strings.Contains(denied, transport) {
		t.Fatalf("ungranted client image download=%s", denied)
	}
	version, found := store.LibraryArtifactVersion(ctx, clientCreated.ArtifactID, clientCreated.VersionID)
	if !found {
		t.Fatal("created client image version disappeared")
	}
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: clientCreated.ArtifactID, ArtifactVersionID: version.ID, ArtifactVersionDigest: version.Digest,
		AgentSurfaceID: reader.ID, CreatedBy: "usr_media_owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	grantedRead := callLibraryTool(t, readerServer, "library_artifact_read", map[string]any{"artifactId": clientCreated.ArtifactID})
	grantedMetadata := libraryArtifactImageMetadataResult(t, grantedRead)
	if !strings.Contains(grantedRead, `"type":"image"`) || grantedMetadata.Access != "granted" {
		t.Fatalf("granted client image read=%s", grantedRead)
	}
	grantedDownload := callLibraryTool(t, readerServer, "library_artifact_image_download", map[string]any{"artifactId": clientCreated.ArtifactID, "artifactVersionId": clientCreated.VersionID})
	if strings.Contains(grantedDownload, `"type":"image"`) || strings.Contains(grantedDownload, `<svg`) {
		t.Fatalf("granted client image download was not a file payload: %s", grantedDownload)
	}
	grantedPayload := decodeLibraryArtifactImageDownloadPayload(t, grantedDownload)
	downloadedPNG, err := base64.StdEncoding.DecodeString(grantedPayload.DataBase64)
	if err != nil || grantedPayload.Access != "granted" || !bytes.Equal(downloadedPNG, canonical.Bytes) || grantedPayload.Digest != clientCreated.Digest {
		t.Fatalf("granted client image download=%+v decoded=%x err=%v", grantedPayload, downloadedPNG, err)
	}
	if _, err := store.RevokeLibraryArtifactGrant(ctx, clientCreated.ArtifactID, grant.ID, "usr_media_owner", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if revoked := callLibraryTool(t, readerServer, "library_artifact_read", map[string]any{"artifactId": clientCreated.ArtifactID}); !strings.Contains(revoked, "artifact not found") || strings.Contains(revoked, transport) {
		t.Fatalf("revoked client image read=%s", revoked)
	}
	if revoked := callLibraryTool(t, readerServer, "library_artifact_image_download", map[string]any{"artifactId": clientCreated.ArtifactID, "artifactVersionId": clientCreated.VersionID}); !strings.Contains(revoked, "artifact not found") || strings.Contains(revoked, grantedPayload.DataBase64) {
		t.Fatalf("revoked client image download=%s", revoked)
	}
}
