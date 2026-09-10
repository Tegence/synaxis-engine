package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPgLibraryMCPClientImageArtifactVersionIsAtomicIdempotentAndEncrypted(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client image-artifact-version integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	cipher, err := NewCipher(base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)

	suffix := newPgFixtureSuffix()
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "PG image artifact revision " + suffix, Subject: "usr_pg_image_artifact_" + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-pg-image-artifact-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("BindMCPClientOAuthClient: %v", err)
	}
	var artifact LibraryArtifact
	var run LibraryRun
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_mcp_client_artifact_version_requests WHERE client_id=$1`, client.ID)
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id IN (SELECT id FROM narthex_library_artifact_versions WHERE artifact_id=$1)`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
	})

	firstImage, _ := libraryArtifactTestPNG(t)
	run, artifact, first, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, client, LibraryArtifact{
		Title: "PG client image artifact", Origin: LibraryArtifactOriginAgentDirect,
	}, firstImage, "PG version one")
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactWithInitialVersion: %v", err)
	}
	secondImage, _ := libraryArtifactRevisionTestJPEG(t)
	request := LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID: "pg-image-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest,
		Image: secondImage, AltText: "PG version two",
	}
	updated, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, request)
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientImageArtifactVersion: %v", err)
	}
	if updated.Replayed || updated.Version.Version != 2 || updated.Version.Format != LibraryArtifactFormatImage || updated.Version.Digest != secondImage.Digest || updated.Version.CreatedBy != client.Subject || updated.Version.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("updated PG image version=%+v", updated)
	}
	if replay, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, request); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID {
		t.Fatalf("PG image replay=%+v err=%v", replay, err)
	}
	changed := request
	changed.AltText = "changed replay"
	if _, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict) {
		t.Fatalf("changed PG image replay error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionRequestConflict)
	}
	firstBytes, found, err := store.LibraryArtifactImageBytes(ctx, artifact.ID, first.ID)
	if err != nil || !found || !bytes.Equal(firstBytes, firstImage.Bytes) {
		t.Fatalf("PG first image changed=%x found=%t err=%v", firstBytes, found, err)
	}
	secondBytes, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, updated.Version.ID)
	if err != nil || !found || !bytes.Equal(secondBytes, secondImage.Bytes) {
		t.Fatalf("PG updated image bytes=%x found=%t err=%v", secondBytes, found, err)
	}

	var rawBody, rawCreatedBy, rawAltText string
	var rawData []byte
	if err := store.pool.QueryRow(ctx, `
SELECT version.body,version.created_by,blob.alt_text,blob.encrypted_data
FROM narthex_library_artifact_versions version
JOIN narthex_library_artifact_media_blobs blob ON blob.artifact_version_id=version.id
WHERE version.id=$1`, updated.Version.ID).Scan(&rawBody, &rawCreatedBy, &rawAltText, &rawData); err != nil {
		t.Fatal(err)
	}
	// An image revision has no text body by construction (validateLibraryArtifactMediaForVersion
	// rejects a non-empty one), and the cipher leaves an empty value empty, so the
	// body must be exactly empty at rest while every private field is encrypted.
	if rawBody != "" || !strings.HasPrefix(rawCreatedBy, encPrefix) || !strings.HasPrefix(rawAltText, encPrefix) || !bytes.HasPrefix(rawData, encBytesPrefix) || rawCreatedBy == updated.Version.CreatedBy {
		t.Fatalf("PG image revision private fields were not encrypted: body=%q creator=%q alt=%q data=%q", rawBody, rawCreatedBy, rawAltText, string(rawData))
	}
	var receiptVersionID string
	if err := store.pool.QueryRow(ctx, `SELECT artifact_version_id FROM narthex_library_mcp_client_artifact_version_requests WHERE client_id=$1 AND client_epoch=$2 AND artifact_id=$3 AND operation=$4`, client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationImageCreate).Scan(&receiptVersionID); err != nil || receiptVersionID != updated.Version.ID {
		t.Fatalf("PG image revision receipt=%q err=%v updated=%q", receiptVersionID, err, updated.Version.ID)
	}
}
