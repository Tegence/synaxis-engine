package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestPgLibraryArtifactMediaEncryptExistingAndRead proves the image-specific
// legacy plaintext upgrade is reached through the public PgStore
// EncryptExisting entry point, not merely through the helper that implements
// it. It is database-gated like the rest of the PgStore integration suite.
func TestPgLibraryArtifactMediaEncryptExistingAndRead(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library media integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)

	var run LibraryRun
	var artifact LibraryArtifact
	var version LibraryArtifactVersion
	t.Cleanup(func() {
		// The media row uses an ON DELETE RESTRICT parent reference, so delete
		// it first and leave unrelated shared integration-test data untouched.
		if version.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id=$1`, version.ID)
		}
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
	})

	canonical, _ := libraryArtifactTestPNG(t)
	const altText = "private PostgreSQL media alt text"
	run, artifact, version, err = store.CreateLibraryRootMCPImageArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "PG encrypted image " + strings.ToLower(newEpoch()), Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, altText)
	if err != nil {
		t.Fatalf("CreateLibraryRootMCPImageArtifactWithInitialVersion: %v", err)
	}

	var rawAltText string
	var rawData []byte
	if err := store.pool.QueryRow(ctx, `SELECT alt_text,encrypted_data FROM narthex_library_artifact_media_blobs WHERE artifact_version_id=$1`, version.ID).Scan(&rawAltText, &rawData); err != nil {
		t.Fatal(err)
	}
	if rawAltText != altText || !bytes.Equal(rawData, canonical.Bytes) {
		t.Fatalf("plaintext media fixture was not written as expected: alt=%q bytes=%x", rawAltText, rawData)
	}

	store.SetCipher(testCipher(t, 47))
	if err := store.EncryptExisting(ctx); err != nil {
		t.Fatalf("EncryptExisting media migration: %v", err)
	}
	var encryptedAltText string
	var encryptedData []byte
	if err := store.pool.QueryRow(ctx, `SELECT alt_text,encrypted_data FROM narthex_library_artifact_media_blobs WHERE artifact_version_id=$1`, version.ID).Scan(&encryptedAltText, &encryptedData); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encryptedAltText, encPrefix) || strings.Contains(encryptedAltText, altText) ||
		!bytes.HasPrefix(encryptedData, encBytesPrefix) || bytes.Equal(encryptedData, canonical.Bytes) {
		t.Fatalf("media data was not encrypted at rest: alt=%q bytes=%x", encryptedAltText, encryptedData)
	}

	media, found, err := store.LibraryArtifactMedia(ctx, artifact.ID, version.ID)
	if err != nil || !found || media.AltText != altText || media.Digest != canonical.Digest {
		t.Fatalf("encrypted media read=%+v found=%t err=%v", media, found, err)
	}
	raster, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, version.ID)
	if err != nil || !found || !bytes.Equal(raster, canonical.Bytes) {
		t.Fatalf("encrypted raster read=%x found=%t err=%v", raster, found, err)
	}
	download, found, err := store.LibraryArtifactImageBytes(ctx, artifact.ID, version.ID)
	if err != nil || !found || !bytes.Equal(download, canonical.Bytes) {
		t.Fatalf("encrypted image download=%x found=%t err=%v", download, found, err)
	}

	var sizeCheck string
	if err := store.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conname='narthex_library_artifact_media_blobs_size_check'
  AND conrelid='narthex_library_artifact_media_blobs'::regclass`).Scan(&sizeCheck); err != nil || !strings.Contains(sizeCheck, "524288") {
		t.Fatalf("media size constraint=%q err=%v, want 512 KiB limit", sizeCheck, err)
	}
}

// TestPgLibraryArtifactRasterReadRejectsRelabeledSVG verifies that an
// otherwise constraint-valid metadata rewrite cannot turn sanitized SVG bytes
// into MCP ImageContent. It is intentionally a raw-Pg mutation because the
// normal Engine write path never permits this mismatch.
func TestPgLibraryArtifactRasterReadRejectsRelabeledSVG(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library media integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	store.SetCipher(testCipher(t, 47))

	var run LibraryRun
	var artifact LibraryArtifact
	var version LibraryArtifactVersion
	t.Cleanup(func() {
		if version.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_media_blobs WHERE artifact_version_id=$1`, version.ID)
		}
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
	})

	source := `<svg xmlns="http://www.w3.org/2000/svg" width="2" height="1"><path d="M0 0 L2 1" fill="#112233"/></svg>`
	canonical, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, base64.StdEncoding.EncodeToString([]byte(source)))
	if err != nil {
		t.Fatal(err)
	}
	run, artifact, version, err = store.CreateLibraryRootMCPImageArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "PG relabeled SVG " + strings.ToLower(newEpoch()), Origin: LibraryArtifactOriginAgentDirect,
	}, canonical, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
UPDATE narthex_library_artifact_media_blobs
SET mime_type=$2,delivery_mode=$3
WHERE artifact_version_id=$1`, version.ID, libraryArtifactImageMIMEPNG, libraryArtifactImageDeliveryInline); err != nil {
		t.Fatalf("tamper media metadata: %v", err)
	}
	if raster, found, err := store.LibraryArtifactRasterBytes(ctx, artifact.ID, version.ID); found || err == nil || len(raster) != 0 {
		t.Fatalf("relabeled SVG reached PgStore raster read: bytes=%x found=%t err=%v", raster, found, err)
	}
	if downloaded, found, err := store.LibraryArtifactImageBytes(ctx, artifact.ID, version.ID); found || err == nil || len(downloaded) != 0 {
		t.Fatalf("relabeled SVG reached PgStore download read: bytes=%x found=%t err=%v", downloaded, found, err)
	}
}
