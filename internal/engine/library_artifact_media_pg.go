package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ LibraryArtifactMediaStore = (*PgStore)(nil)

const libraryArtifactMediaMetadataColumns = `artifact_version_id,mime_type,digest,size_bytes,width,height,alt_text,delivery_mode`

// libraryArtifactMediaBlobColumns is the same projection qualified for queries
// that join the blob table with narthex_library_artifact_versions, which also
// has a digest column; an unqualified digest is ambiguous there.
const libraryArtifactMediaBlobColumns = `blob.artifact_version_id,blob.mime_type,blob.digest,blob.size_bytes,blob.width,blob.height,blob.alt_text,blob.delivery_mode`

func (s *PgStore) scanLibraryArtifactMedia(row libraryRowScanner) (LibraryArtifactMedia, error) {
	var media LibraryArtifactMedia
	var altText string
	if err := row.Scan(
		&media.ArtifactVersionID, &media.MIMEType, &media.Digest, &media.SizeBytes,
		&media.Width, &media.Height, &altText, &media.DeliveryMode,
	); err != nil {
		return LibraryArtifactMedia{}, err
	}
	var err error
	if media.AltText, err = s.decryptLibraryText("artifact media", media.ArtifactVersionID, "alt text", altText); err != nil {
		return LibraryArtifactMedia{}, err
	}
	if err := validateLibraryArtifactMedia(media); err != nil {
		return LibraryArtifactMedia{}, fmt.Errorf("validate library artifact media %q: %w", media.ArtifactVersionID, err)
	}
	return media, nil
}

func (s *PgStore) insertLibraryArtifactMediaBlobTx(ctx context.Context, tx pgx.Tx, version LibraryArtifactVersion, image libraryArtifactImageCanonical, altText string) error {
	media, err := libraryArtifactMediaFromCanonical(version.ID, image, altText)
	if err != nil {
		return err
	}
	if err := validateLibraryArtifactMediaForVersion(version, media); err != nil {
		return err
	}
	storedAltText, err := s.enc(media.AltText)
	if err != nil {
		return fmt.Errorf("encrypt library artifact media alt text: %w", err)
	}
	encryptedData, err := s.encBytes(image.Bytes)
	if err != nil {
		return fmt.Errorf("encrypt library artifact media bytes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_artifact_media_blobs
    (artifact_version_id,mime_type,digest,size_bytes,width,height,alt_text,delivery_mode,encrypted_data,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		media.ArtifactVersionID, media.MIMEType, media.Digest, media.SizeBytes, media.Width, media.Height,
		storedAltText, media.DeliveryMode, encryptedData, version.CreatedAt,
	); err != nil {
		return err
	}
	return nil
}

func (s *PgStore) CreateLibraryRootMCPImageArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := normalizeLibraryArtifactImageAltText(altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)

	run, artifact, version, err := prepareLibraryRootMCPImageArtifact(artifact, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.SourceArtifactID != "" {
		allowed, err := s.libraryRootMCPMayUseArtifactVersionTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest)
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
		}
		if !allowed {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryArtifactMediaBlobTx(ctx, tx, version, image, altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

func (s *PgStore) CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx context.Context, client MCPClient, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := normalizeLibraryArtifactImageAltText(altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)

	var subject string
	var status MCPClientStatus
	err = tx.QueryRow(ctx, `SELECT subject,status FROM narthex_mcp_clients WHERE id=$1 FOR UPDATE`, client.ID).Scan(&subject, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if subject != client.Subject {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientRevoked
	}
	run, artifact, version, err := prepareLibraryMCPClientImageArtifact(MCPClient{ID: client.ID, Subject: subject}, artifact, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.SourceArtifactID != "" {
		allowed, err := s.libraryMCPClientMayUseArtifactVersionTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, client.ID, subject)
		if err != nil {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
		}
		if !allowed {
			return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryArtifactMediaBlobTx(ctx, tx, version, image, altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// CreateLibraryHumanImageArtifactWithInitialVersion is the Console image
// create: derived human run, artifact, first version, and blob commit in one
// transaction, with the optional source citation verified inside it.
func (s *PgStore) CreateLibraryHumanImageArtifactWithInitialVersion(ctx context.Context, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := normalizeLibraryArtifactImageAltText(altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, artifact, version, err := prepareLibraryHumanImageArtifact(artifact, image, "", nil)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.validateLibraryArtifactSourceTx(ctx, tx, artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryArtifactMediaBlobTx(ctx, tx, version, image, altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// CreateLibraryHumanImageArtifactVersion appends a Console image revision.
// The artifact row is the head-serialization fence, as for text versions.
func (s *PgStore) CreateLibraryHumanImageArtifactVersion(ctx context.Context, request LibraryHumanImageArtifactVersionCreateRequest) (LibraryArtifactVersion, error) {
	request, err := normalizeLibraryHumanImageArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	defer tx.Rollback(ctx)
	var artifactID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, request.ArtifactID).Scan(&artifactID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
		}
		return LibraryArtifactVersion{}, err
	}
	var latestVersion int
	var latestFormat string
	err = tx.QueryRow(ctx, `SELECT version_number,format FROM narthex_library_artifact_versions WHERE artifact_id=$1 ORDER BY version_number DESC LIMIT 1`, request.ArtifactID).Scan(&latestVersion, &latestFormat)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryArtifactVersion{}, ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if latestFormat != LibraryArtifactFormatImage {
		return LibraryArtifactVersion{}, ErrLibraryArtifactFormatMismatch
	}
	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: request.ArtifactID, Version: latestVersion + 1,
		Changelog: request.Changelog, Provenance: request.Provenance,
		CreatedBy: request.CreatedBy, CreatedAt: time.Now().UTC(),
	}, request.Image)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	body, err := s.enc("")
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt image artifact revision body: %w", err)
	}
	createdBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return LibraryArtifactVersion{}, fmt.Errorf("encrypt image artifact revision creator: %w", err)
	}
	provenance, err := s.encryptLibraryVersionProvenance(version.Changelog, version.Provenance)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if _, err := tx.Exec(ctx, libraryArtifactVersionInsert, version.ID, version.ArtifactID, version.Version, version.Format, body, version.Digest, version.SizeBytes, version.RedactionStatus, createdBy, "", version.CreatedAt,
		provenance.changelog, provenance.origin, provenance.generator, provenance.model, provenance.promptDigest, provenance.draftID); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := s.insertLibraryArtifactMediaBlobTx(ctx, tx, version, request.Image, request.AltText); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryArtifactVersion{}, err
	}
	return version, nil
}

func (s *PgStore) LibraryArtifactMedia(ctx context.Context, artifactID, versionID string) (LibraryArtifactMedia, bool, error) {
	media, err := s.scanLibraryArtifactMedia(s.pool.QueryRow(ctx, `
SELECT `+libraryArtifactMediaBlobColumns+`
FROM narthex_library_artifact_media_blobs blob
JOIN narthex_library_artifact_versions version ON version.id=blob.artifact_version_id
WHERE version.artifact_id=$1 AND version.id=$2 AND version.format=$3`, artifactID, versionID, LibraryArtifactFormatImage))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryArtifactMedia{}, false, nil
	}
	if err != nil {
		return LibraryArtifactMedia{}, false, err
	}
	version, err := s.scanLibraryArtifactVersion(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryArtifactMedia{}, false, nil
	}
	if err != nil {
		return LibraryArtifactMedia{}, false, err
	}
	if err := validateLibraryArtifactMediaForVersion(version, media); err != nil {
		return LibraryArtifactMedia{}, false, err
	}
	return media, true, nil
}

func (s *PgStore) LibraryArtifactRasterBytes(ctx context.Context, artifactID, versionID string) ([]byte, bool, error) {
	var media LibraryArtifactMedia
	var encryptedData []byte
	var encryptedAltText string
	err := s.pool.QueryRow(ctx, `
SELECT blob.artifact_version_id,blob.mime_type,blob.digest,blob.size_bytes,blob.width,blob.height,blob.alt_text,blob.delivery_mode,blob.encrypted_data
FROM narthex_library_artifact_media_blobs blob
JOIN narthex_library_artifact_versions version ON version.id=blob.artifact_version_id
WHERE version.artifact_id=$1 AND version.id=$2 AND version.format=$3`, artifactID, versionID, LibraryArtifactFormatImage).Scan(
		&media.ArtifactVersionID, &media.MIMEType, &media.Digest, &media.SizeBytes, &media.Width, &media.Height, &encryptedAltText, &media.DeliveryMode, &encryptedData,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var decryptErr error
	if media.AltText, decryptErr = s.decryptLibraryText("artifact media", media.ArtifactVersionID, "alt text", encryptedAltText); decryptErr != nil {
		return nil, false, decryptErr
	}
	if err := validateLibraryArtifactMedia(media); err != nil {
		return nil, false, err
	}
	version, err := s.scanLibraryArtifactVersion(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := validateLibraryArtifactMediaForVersion(version, media); err != nil {
		return nil, false, err
	}
	// Do not rely on delivery_mode alone. A malformed database row must never
	// turn SVG (or a future media type) into MCP ImageContent between the
	// metadata and byte reads.
	if media.MIMEType != libraryArtifactImageMIMEPNG && media.MIMEType != libraryArtifactImageMIMEJPEG {
		return nil, false, nil
	}
	if media.DeliveryMode != libraryArtifactImageDeliveryInline {
		return nil, false, nil
	}
	bytes, err := s.decBytes(encryptedData)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt library artifact media bytes: %w", err)
	}
	if err := validateLibraryArtifactMediaBytes(media, bytes); err != nil {
		return nil, false, ErrLibraryArtifactMediaInvalid
	}
	return append([]byte(nil), bytes...), true, nil
}

// LibraryArtifactImageBytes returns one immutable image's canonical bytes for
// the narrow, already-authorized parent-version download path. It includes SVG
// bytes, so callers must present them only as a bounded attachment payload;
// they must never turn this into raw markup, ImageContent, or a storage URL.
func (s *PgStore) LibraryArtifactImageBytes(ctx context.Context, artifactID, versionID string) ([]byte, bool, error) {
	var media LibraryArtifactMedia
	var encryptedData []byte
	var encryptedAltText string
	err := s.pool.QueryRow(ctx, `
SELECT blob.artifact_version_id,blob.mime_type,blob.digest,blob.size_bytes,blob.width,blob.height,blob.alt_text,blob.delivery_mode,blob.encrypted_data
FROM narthex_library_artifact_media_blobs blob
JOIN narthex_library_artifact_versions version ON version.id=blob.artifact_version_id
WHERE version.artifact_id=$1 AND version.id=$2 AND version.format=$3`, artifactID, versionID, LibraryArtifactFormatImage).Scan(
		&media.ArtifactVersionID, &media.MIMEType, &media.Digest, &media.SizeBytes, &media.Width, &media.Height, &encryptedAltText, &media.DeliveryMode, &encryptedData,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var decryptErr error
	if media.AltText, decryptErr = s.decryptLibraryText("artifact media", media.ArtifactVersionID, "alt text", encryptedAltText); decryptErr != nil {
		return nil, false, decryptErr
	}
	if err := validateLibraryArtifactMedia(media); err != nil {
		return nil, false, err
	}
	version, err := s.scanLibraryArtifactVersion(s.pool.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := validateLibraryArtifactMediaForVersion(version, media); err != nil {
		return nil, false, err
	}
	bytes, err := s.decBytes(encryptedData)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt library artifact media bytes: %w", err)
	}
	if err := validateLibraryArtifactMediaBytes(media, bytes); err != nil {
		return nil, false, ErrLibraryArtifactMediaInvalid
	}
	return append([]byte(nil), bytes...), true, nil
}

// encryptExistingLibraryArtifactMedia upgrades blobs written while PgStore was
// in its documented plaintext mode. It is called only by EncryptExisting,
// after a cipher is configured. Both Cipher helpers are idempotent, so a
// second startup migration authenticates and preserves already encrypted data.
func (s *PgStore) encryptExistingLibraryArtifactMedia(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT artifact_version_id,alt_text,encrypted_data FROM narthex_library_artifact_media_blobs ORDER BY artifact_version_id`)
	if err != nil {
		return fmt.Errorf("list library artifact media for encryption migration: %w", err)
	}
	type payload struct {
		versionID string
		altText   string
		data      []byte
	}
	var payloads []payload
	for rows.Next() {
		var item payload
		if err := rows.Scan(&item.versionID, &item.altText, &item.data); err != nil {
			rows.Close()
			return fmt.Errorf("read library artifact media for encryption migration: %w", err)
		}
		payloads = append(payloads, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate library artifact media for encryption migration: %w", err)
	}
	rows.Close()
	for _, item := range payloads {
		altText, err := s.dec(item.altText)
		if err != nil {
			return fmt.Errorf("decrypt library artifact media %q alt text: %w", item.versionID, err)
		}
		data, err := s.decBytes(item.data)
		if err != nil {
			return fmt.Errorf("decrypt library artifact media %q bytes: %w", item.versionID, err)
		}
		encryptedAltText, err := s.enc(altText)
		if err != nil {
			return fmt.Errorf("encrypt library artifact media %q alt text: %w", item.versionID, err)
		}
		encryptedData, err := s.encBytes(data)
		if err != nil {
			return fmt.Errorf("encrypt library artifact media %q bytes: %w", item.versionID, err)
		}
		if _, err := s.pool.Exec(ctx, `UPDATE narthex_library_artifact_media_blobs SET alt_text=$2,encrypted_data=$3 WHERE artifact_version_id=$1`, item.versionID, encryptedAltText, encryptedData); err != nil {
			return fmt.Errorf("write encrypted library artifact media %q: %w", item.versionID, err)
		}
	}
	return nil
}
