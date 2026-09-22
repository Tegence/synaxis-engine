package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ LibrarySkillBundleStore = (*PgStore)(nil)
var _ LibraryMCPClientSkillBlobStore = (*PgStore)(nil)

// librarySkillBlobColumns is the content-addressed bundle file table. Bytes
// are encrypted with the Engine cipher; digest and size stay queryable so a
// manifest can be verified without decrypting.
const librarySkillBlobStagingColumns = `id,client_id,client_epoch,lease_id,request_id_hash,payload_digest,digest,content_type,size_bytes,expires_at,created_at`

// encryptLibrarySkillManifest stores the manifest as one encrypted JSON
// document. Paths are authored text and follow the same at-rest rule as
// names and descriptions; the manifest digest column stays plain.
func (s *PgStore) encryptLibrarySkillManifest(files []LibrarySkillFile) (string, error) {
	if len(files) == 0 {
		return "", nil
	}
	encoded, err := json.Marshal(files)
	if err != nil {
		return "", fmt.Errorf("encode library skill manifest: %w", err)
	}
	encrypted, err := s.enc(string(encoded))
	if err != nil {
		return "", fmt.Errorf("encrypt library skill manifest: %w", err)
	}
	return encrypted, nil
}

func (s *PgStore) decryptLibrarySkillManifest(versionID, stored string) ([]LibrarySkillFile, error) {
	if stored == "" {
		return nil, nil
	}
	plain, err := s.decryptLibraryText("skill version", versionID, "manifest", stored)
	if err != nil {
		return nil, err
	}
	var files []LibrarySkillFile
	if err := json.Unmarshal([]byte(plain), &files); err != nil {
		return nil, fmt.Errorf("decode library skill version %q manifest: %w", versionID, err)
	}
	return files, nil
}

// insertLibrarySkillBlobsTx stores every blob a bundle supplies. A blob that
// already exists (same digest, same bytes) is left untouched, which is how
// identical files across versions and skills are stored once.
func (s *PgStore) insertLibrarySkillBlobsTx(ctx context.Context, tx pgx.Tx, blobs map[string][]byte, now time.Time) error {
	for digest, data := range blobs {
		encrypted, err := s.encBytes(data)
		if err != nil {
			return fmt.Errorf("encrypt library skill blob: %w", err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_blobs (digest,size_bytes,encrypted_data,created_at)
VALUES ($1,$2,$3,$4)
ON CONFLICT (digest) DO NOTHING`, digest, int64(len(data)), encrypted, now); err != nil {
			return err
		}
	}
	return nil
}

// requireLibrarySkillBlobsTx proves the bytes behind every manifest entry are
// present before a version referencing them is inserted.
func (s *PgStore) requireLibrarySkillBlobsTx(ctx context.Context, tx pgx.Tx, bundle LibrarySkillBundle) error {
	wanted := make([]string, 0, len(bundle.Files))
	for _, file := range bundle.Files {
		if file.Path == LibrarySkillInstructionsPath {
			continue
		}
		if _, supplied := bundle.Blobs[file.Digest]; supplied {
			continue
		}
		wanted = append(wanted, file.Digest)
	}
	if len(wanted) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT digest FROM narthex_library_skill_blobs WHERE digest = ANY($1::text[])`, wanted)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(wanted))
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return err
		}
		found[digest] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, digest := range wanted {
		if _, ok := found[digest]; !ok {
			return fmt.Errorf("%w: %s", ErrLibrarySkillBlobNotFound, digest[:12])
		}
	}
	return nil
}

func (s *PgStore) CreateLibrarySkillWithInitialBundle(ctx context.Context, skill LibrarySkill, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkill, LibrarySkillVersion, error) {
	return s.createLibrarySkillWithInitialVersion(ctx, skill, version, &bundle)
}

func (s *PgStore) CreateLibrarySkillBundleVersion(ctx context.Context, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkillVersion, error) {
	return s.createLibrarySkillVersion(ctx, version, &bundle)
}

// LibrarySkillFileBytes reads one file of one exact immutable version and
// re-verifies it against the manifest before returning it.
func (s *PgStore) LibrarySkillFileBytes(ctx context.Context, skillID, versionID, filePath string) ([]byte, LibrarySkillFile, bool, error) {
	version, err := s.scanLibrarySkillVersion(s.pool.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2`, skillID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, LibrarySkillFile{}, false, nil
	}
	if err != nil {
		return nil, LibrarySkillFile{}, false, err
	}
	file, found := librarySkillFileByPath(version, filePath)
	if !found {
		return nil, LibrarySkillFile{}, false, nil
	}
	var data []byte
	if file.Path == LibrarySkillInstructionsPath {
		data = []byte(version.Content)
	} else {
		var encrypted []byte
		err := s.pool.QueryRow(ctx, `SELECT encrypted_data FROM narthex_library_skill_blobs WHERE digest=$1`, file.Digest).Scan(&encrypted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, LibrarySkillFile{}, false, fmt.Errorf("%w: %q", ErrLibrarySkillBlobNotFound, filePath)
		}
		if err != nil {
			return nil, LibrarySkillFile{}, false, err
		}
		if data, err = s.decBytes(encrypted); err != nil {
			return nil, LibrarySkillFile{}, false, fmt.Errorf("decrypt library skill blob: %w", err)
		}
	}
	if int64(len(data)) != file.SizeBytes || librarySkillFileDigest(data) != file.Digest {
		return nil, LibrarySkillFile{}, false, fmt.Errorf("%w: stored bytes for %q do not match the manifest", ErrLibrarySkillBundleInvalid, filePath)
	}
	return data, file, true, nil
}

func (s *PgStore) scanLibrarySkillBlobStaging(row libraryRowScanner) (librarySkillBlobStagingRecord, error) {
	var staging librarySkillBlobStagingRecord
	if err := row.Scan(&staging.ID, &staging.MCPClientID, &staging.MCPClientEpoch, &staging.LeaseID, &staging.RequestIDHash, &staging.PayloadDigest,
		&staging.Digest, &staging.ContentType, &staging.SizeBytes, &staging.ExpiresAt, &staging.CreatedAt); err != nil {
		return librarySkillBlobStagingRecord{}, err
	}
	return staging, nil
}

// resolveLibrarySkillBlobRefsTx turns staged references into files inside
// the writing transaction. Only a live staging for this exact client and
// epoch qualifies, and the path's derived type must equal the staged type.
func (s *PgStore) resolveLibrarySkillBlobRefsTx(ctx context.Context, tx pgx.Tx, client MCPClient, refs []librarySkillBlobRef, now time.Time) ([]LibrarySkillFileContent, error) {
	files := make([]LibrarySkillFileContent, 0, len(refs))
	for _, ref := range refs {
		staging, err := s.scanLibrarySkillBlobStaging(tx.QueryRow(ctx, `
SELECT `+librarySkillBlobStagingColumns+`
FROM narthex_library_skill_blob_stagings
WHERE id=$1 AND client_id=$2 AND client_epoch=$3 AND expires_at > $4
FOR SHARE`, ref.BlobID, client.ID, client.Epoch, now))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q references an unknown or expired blob", ErrLibrarySkillBundleInvalid, ref.Path)
		}
		if err != nil {
			return nil, err
		}
		expectedType, err := librarySkillContentTypeForPath(ref.Path)
		if err != nil {
			return nil, err
		}
		if expectedType != staging.ContentType {
			return nil, fmt.Errorf("%w: %q was staged as %q", ErrLibrarySkillBundleInvalid, ref.Path, staging.ContentType)
		}
		var encrypted []byte
		if err := tx.QueryRow(ctx, `SELECT encrypted_data FROM narthex_library_skill_blobs WHERE digest=$1`, staging.Digest).Scan(&encrypted); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("%w: %q", ErrLibrarySkillBlobNotFound, ref.Path)
			}
			return nil, err
		}
		data, err := s.decBytes(encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt library skill blob: %w", err)
		}
		files = append(files, LibrarySkillFileContent{Path: ref.Path, ContentType: staging.ContentType, Data: data})
	}
	return files, nil
}

// StageLibraryMCPClientSkillBlob is the PostgreSQL counterpart of the
// FileStore staging write: one transaction rereads the active client and
// lease, replays an exact retry, stores the blob, consumes one authoring
// write, and records the staging receipt and audit event together.
func (s *PgStore) StageLibraryMCPClientSkillBlob(ctx context.Context, endpointClient MCPClient, request LibraryMCPClientSkillBlobUploadRequest) (LibraryMCPClientSkillBlobUploadResult, error) {
	request, file, payloadDigest, err := normalizeLibraryMCPClientSkillBlobUploadRequest(request)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringUploadRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, endpointClient.ID)
	if err != nil {
		if errors.Is(err, ErrMCPClientNotFound) {
			return LibraryMCPClientSkillBlobUploadResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	latestLeaseID := func() (string, error) {
		latest, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
		if err != nil || !found {
			return "", err
		}
		return latest.ID, nil
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject {
		leaseID, err := latestLeaseID()
		if err != nil {
			return LibraryMCPClientSkillBlobUploadResult{}, err
		}
		return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, firstNonEmpty(client.Subject, client.ID), LibraryMCPClientSkillAuthoringAuditOperationUpload,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	actorRef := client.Subject
	now := time.Now().UTC()
	existing, err := s.scanLibrarySkillBlobStaging(tx.QueryRow(ctx, `
SELECT `+librarySkillBlobStagingColumns+`
FROM narthex_library_skill_blob_stagings
WHERE client_id=$1 AND client_epoch=$2 AND request_id_hash=$3
FOR SHARE`, client.ID, client.Epoch, requestIDHash))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if err == nil {
		if existing.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
				ctx, tx, client, existing.LeaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpload,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		lease, found, err := s.libraryMCPClientSkillAuthoringLeaseByIDTx(ctx, tx, existing.LeaseID)
		if err != nil {
			return LibraryMCPClientSkillBlobUploadResult{}, err
		}
		if !found {
			return LibraryMCPClientSkillBlobUploadResult{}, errors.New("stored skill blob staging lease is unavailable")
		}
		lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
		if err := tx.Commit(ctx); err != nil {
			return LibraryMCPClientSkillBlobUploadResult{}, err
		}
		return LibraryMCPClientSkillBlobUploadResult{
			BlobID: existing.ID, Digest: existing.Digest, ContentType: existing.ContentType, SizeBytes: existing.SizeBytes,
			ExpiresAt: existing.ExpiresAt, Lease: lease, Replayed: true,
		}, nil
	}
	lease, found, err := s.libraryMCPClientSkillAuthoringUnrevokedLeaseForUpdateTx(ctx, tx, client.ID, client.Epoch)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if !found || libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive || lease.RemainingUploads <= 0 {
		leaseID, err := latestLeaseID()
		if err != nil {
			return LibraryMCPClientSkillBlobUploadResult{}, err
		}
		return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpload,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	digest := librarySkillFileDigest(file.Data)
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpload,
		actorRef, requestIDHash, payloadDigest, "", "", now,
	)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_blob_stagings WHERE expires_at < $1`, now.Add(-libraryMCPClientSkillAuthoringLeaseDuration)); err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if err := s.insertLibrarySkillBlobsTx(ctx, tx, map[string][]byte{digest: file.Data}, now); err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	updated, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET remaining_uploads=remaining_uploads-1,updated_at=$2
WHERE id=$1 AND client_id=$3 AND client_epoch=$4 AND revoked_at IS NULL AND remaining_creates > 0 AND remaining_uploads > 0 AND expires_at > $2`,
		lease.ID, now, client.ID, client.Epoch,
	)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if updated.RowsAffected() != 1 {
		return LibraryMCPClientSkillBlobUploadResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	staging := librarySkillBlobStagingRecord{
		ID: newLibrarySkillBlobStagingID(), MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID,
		RequestIDHash: requestIDHash, PayloadDigest: payloadDigest, Digest: digest, ContentType: file.ContentType,
		SizeBytes: int64(len(file.Data)), ExpiresAt: lease.ExpiresAt, CreatedAt: now,
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_blob_stagings (`+librarySkillBlobStagingColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		staging.ID, staging.MCPClientID, staging.MCPClientEpoch, staging.LeaseID, staging.RequestIDHash, staging.PayloadDigest,
		staging.Digest, staging.ContentType, staging.SizeBytes, staging.ExpiresAt, staging.CreatedAt,
	); err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, consumeEvent); err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	lease.RemainingUploads--
	lease.UpdatedAt = now
	lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	return LibraryMCPClientSkillBlobUploadResult{
		BlobID: staging.ID, Digest: staging.Digest, ContentType: staging.ContentType, SizeBytes: staging.SizeBytes,
		ExpiresAt: staging.ExpiresAt, Lease: lease,
	}, nil
}

// backfillLibrarySkillVersionManifests is the PostgreSQL migration for
// versions written before bundles: it records the derived one-file manifest
// and its digest on each row. It is idempotent, changes no version ID, content,
// or content digest, and runs after the cipher is configured so encrypted
// instructions can be measured.
func (s *PgStore) backfillLibrarySkillVersionManifests(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id,content,digest FROM narthex_library_skill_versions WHERE manifest_digest='' ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list library skill versions for manifest migration: %w", err)
	}
	type pending struct{ id, content, digest string }
	var versions []pending
	for rows.Next() {
		var version pending
		if err := rows.Scan(&version.id, &version.content, &version.digest); err != nil {
			rows.Close()
			return fmt.Errorf("read library skill version for manifest migration: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate library skill versions for manifest migration: %w", err)
	}
	rows.Close()
	for _, version := range versions {
		content, err := s.decryptLibraryText("skill version", version.id, "content", version.content)
		if err != nil {
			return err
		}
		materialized, err := librarySkillVersionWithManifest(LibrarySkillVersion{ID: version.id, Content: content, Digest: version.digest})
		if err != nil {
			return fmt.Errorf("derive manifest for library skill version %q: %w", version.id, err)
		}
		manifest, err := s.encryptLibrarySkillManifest(materialized.Files)
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `UPDATE narthex_library_skill_versions SET manifest=$2,manifest_digest=$3 WHERE id=$1 AND manifest_digest=''`,
			version.id, manifest, materialized.ManifestDigest); err != nil {
			return fmt.Errorf("write manifest for library skill version %q: %w", version.id, err)
		}
	}
	return nil
}

// UpdateLibrarySkillDescription is the PostgreSQL twin of the FileStore edit.
func (s *PgStore) UpdateLibrarySkillDescription(ctx context.Context, skillID, description string) (LibrarySkill, error) {
	if isBuiltInLibrarySkillID(skillID) {
		return LibrarySkill{}, ErrLibraryBuiltInManaged
	}
	if err := validateLibrarySkillDescriptionUpdate(description); err != nil {
		return LibrarySkill{}, err
	}
	encrypted, err := s.enc(description)
	if err != nil {
		return LibrarySkill{}, fmt.Errorf("encrypt library skill description: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkill{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE narthex_library_skills SET description=$2,updated_at=$3 WHERE id=$1`, skillID, encrypted, time.Now().UTC())
	if err != nil {
		return LibrarySkill{}, err
	}
	if tag.RowsAffected() != 1 {
		return LibrarySkill{}, ErrLibrarySkillNotFound
	}
	skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1`, skillID))
	if err != nil {
		return LibrarySkill{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibrarySkill{}, err
	}
	return skill, nil
}
