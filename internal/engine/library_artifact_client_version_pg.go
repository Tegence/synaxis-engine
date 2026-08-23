package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ LibraryMCPClientArtifactVersionStore = (*PgStore)(nil)

func (s *PgStore) libraryMCPClientArtifactVersionRequestTx(ctx context.Context, tx pgx.Tx, clientID, epoch, artifactID, operation, requestIDHash string) (libraryMCPClientArtifactVersionRequestRecord, bool, error) {
	record := libraryMCPClientArtifactVersionRequestRecord{
		MCPClientID: clientID, MCPClientEpoch: epoch, ArtifactID: artifactID,
		Operation: operation, RequestIDHash: requestIDHash,
	}
	err := tx.QueryRow(ctx, `
SELECT payload_digest,artifact_version_id,created_at
FROM narthex_library_mcp_client_artifact_version_requests
WHERE client_id=$1 AND client_epoch=$2 AND artifact_id=$3 AND operation=$4 AND request_id_hash=$5
FOR UPDATE`, clientID, epoch, artifactID, operation, requestIDHash).Scan(
		&record.PayloadDigest, &record.ArtifactVersionID, &record.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return libraryMCPClientArtifactVersionRequestRecord{}, false, nil
	}
	if err != nil {
		return libraryMCPClientArtifactVersionRequestRecord{}, false, err
	}
	return record, true, nil
}

// CreateLibraryMCPClientArtifactVersion is the PostgreSQL counterpart to the
// FileStore narrow client-revision facet. The client and artifact parent rows
// are locked before the direct-run provenance and latest head are checked;
// generic Console appends use the same artifact-parent lock, so the expected
// version/digest pair is an actual compare-and-swap fence.
func (s *PgStore) CreateLibraryMCPClientArtifactVersion(ctx context.Context, endpointClient MCPClient, request LibraryMCPClientArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	requestIDHash := libraryMCPClientArtifactVersionRequestIDHash(
		endpointClient.ID, endpointClient.Epoch, request.ArtifactID,
		libraryMCPClientArtifactVersionOperationTextCreate, request.RequestID,
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
	if record, found, err := s.libraryMCPClientArtifactVersionRequestTx(ctx, tx, client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationTextCreate, requestIDHash); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	} else if found {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionRequestConflict
		}
		version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, artifact.ID, record.ArtifactVersionID))
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("stored MCP client artifact revision replay is incomplete")
		}
		if err != nil {
			return LibraryMCPClientArtifactVersionCreateResult{}, err
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
	// See the equivalent FileStore guard: media artifacts retain their existing
	// creation-only policy until a separate canonical media-version contract is
	// designed and implemented.
	if latest.Format != LibraryArtifactFormatText && latest.Format != LibraryArtifactFormatMarkdown {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if latest.ID != request.ExpectedArtifactVersionID || latest.Digest != request.ExpectedDigest {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionConflict
	}

	version, err := normalizedLibraryArtifactVersion(LibraryArtifactVersion{
		ID:         newLibraryArtifactVersionID(),
		ArtifactID: artifact.ID,
		Version:    latest.Version + 1,
		Format:     latest.Format,
		Body:       request.Body,
		CreatedBy:  client.Subject,
		CreatedAt:  time.Now().UTC(),
	})
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	body, err := s.enc(version.Body)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client artifact revision body: %w", err)
	}
	createdBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client artifact revision creator: %w", err)
	}
	reviewedBy, err := s.enc("")
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, fmt.Errorf("encrypt MCP client artifact revision reviewer: %w", err)
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
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_artifact_version_requests
    (client_id,client_epoch,artifact_id,operation,request_id_hash,payload_digest,artifact_version_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationTextCreate,
		requestIDHash, payloadDigest, version.ID, version.CreatedAt,
	); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	return LibraryMCPClientArtifactVersionCreateResult{Version: version}, nil
}
