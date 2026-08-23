package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateLibraryMCPClientImageArtifactVersion is the PostgreSQL counterpart to
// the FileStore's narrow client-owned image append. The parent artifact row is
// the version-head serialization fence. The existing head is only key-shared:
// a grant can key-share that immutable version before locking its target
// client, so upgrading it to FOR UPDATE here would invert the grant lock order
// and risk a client/version deadlock.
func (s *PgStore) CreateLibraryMCPClientImageArtifactVersion(ctx context.Context, endpointClient MCPClient, request LibraryMCPClientImageArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientImageArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	requestIDHash := libraryMCPClientArtifactVersionRequestIDHash(
		endpointClient.ID, endpointClient.Epoch, request.ArtifactID,
		libraryMCPClientArtifactVersionOperationImageCreate, request.RequestID,
	)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	defer tx.Rollback(ctx)

	client, err := loadMCPClientForUpdate(ctx, tx, endpointClient.ID)
	if err != nil {
		if errors.Is(err, ErrMCPClientNotFound) {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrMCPClientNotFound
		}
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if client.Status != MCPClientStatusActive || client.Subject == "" || client.Subject != endpointClient.Subject ||
		client.Epoch == "" || client.Epoch != endpointClient.Epoch || client.OAuthClientID == "" {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrMCPClientNotFound
	}

	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, request.ArtifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject || artifact.RunID == "" {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	run, err := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, artifact.RunID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if run.Origin != LibraryRunOriginAgentDirect || run.Attestation != "" || run.ActorRef != client.Subject || run.SurfaceRef != client.ID {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}

	if record, found, err := s.libraryMCPClientArtifactVersionRequestTx(ctx, tx, client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationImageCreate, requestIDHash); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	} else if found {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionRequestConflict
		}
		version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, artifact.ID, record.ArtifactVersionID))
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("stored MCP client image artifact revision replay is incomplete")
		}
		if err != nil {
			return LibraryMCPClientArtifactVersionCreateResult{}, err
		}
		if version.Format != LibraryArtifactFormatImage {
			return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("stored MCP client image artifact revision replay has wrong format")
		}
		if err := tx.Commit(ctx); err != nil {
			return LibraryMCPClientArtifactVersionCreateResult{}, err
		}
		return LibraryMCPClientArtifactVersionCreateResult{Version: version, Replayed: true}, nil
	}

	latest, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `
SELECT `+libraryArtifactVersionColumns+`
FROM narthex_library_artifact_versions
WHERE artifact_id=$1
ORDER BY version_number DESC,id DESC
	LIMIT 1
	FOR KEY SHARE`, artifact.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if latest.Format != LibraryArtifactFormatImage {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if latest.ID != request.ExpectedArtifactVersionID || latest.Digest != request.ExpectedDigest {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionConflict
	}

	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID:         newLibraryArtifactVersionID(),
		ArtifactID: artifact.ID,
		Version:    latest.Version + 1,
		CreatedBy:  client.Subject,
		CreatedAt:  time.Now().UTC(),
	}, request.Image)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	body, err := s.enc("")
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client image artifact revision body: %w", err)
	}
	createdBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client image artifact revision creator: %w", err)
	}
	reviewedBy, err := s.enc("")
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client image artifact revision reviewer: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_artifact_versions
    (id,artifact_id,version_number,format,body,digest,size_bytes,redaction_status,created_by,reviewed_by,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		version.ID, version.ArtifactID, version.Version, version.Format, body, version.Digest, version.SizeBytes,
		version.RedactionStatus, createdBy, reviewedBy, version.CreatedAt,
	); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if err := s.insertLibraryArtifactMediaBlobTx(ctx, tx, version, request.Image, request.AltText); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_artifact_version_requests
    (client_id,client_epoch,artifact_id,operation,request_id_hash,payload_digest,artifact_version_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationImageCreate,
		requestIDHash, payloadDigest, version.ID, version.CreatedAt,
	); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	return LibraryMCPClientArtifactVersionCreateResult{Version: version}, nil
}
