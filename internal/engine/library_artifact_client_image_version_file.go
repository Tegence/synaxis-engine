package engine

import (
	"context"
	"errors"
	"time"
)

// CreateLibraryMCPClientImageArtifactVersion appends one immutable canonical
// image version to an artifact directly created by this exact active MCP
// client. The FileStore mutex covers client validation, direct-run provenance,
// request replay, head CAS, version/blob construction, and persistence as one
// state transition. A grant is deliberately never sufficient to revise an
// artifact.
func (s *FileStore) CreateLibraryMCPClientImageArtifactVersion(_ context.Context, endpointClient MCPClient, request LibraryMCPClientImageArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientImageArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	requestIDHash := libraryMCPClientArtifactVersionRequestIDHash(
		endpointClient.ID, endpointClient.Epoch, request.ArtifactID,
		libraryMCPClientArtifactVersionOperationImageCreate, request.RequestID,
	)

	s.mu.Lock()
	defer s.mu.Unlock()

	client, found := s.mcpClientByIDLocked(endpointClient.ID)
	if !found || client.Status != MCPClientStatusActive || client.Subject == "" ||
		client.Subject != endpointClient.Subject || client.Epoch == "" || client.Epoch != endpointClient.Epoch || client.OAuthClientID == "" {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrMCPClientNotFound
	}
	artifact := s.libraryArtifactLocked(request.ArtifactID)
	if artifact == nil || artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.AgentSurfaceID != client.ID ||
		artifact.CreatedBy != client.Subject || artifact.RunID == "" {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	run := s.libraryRunLocked(artifact.RunID)
	if run == nil || run.Origin != LibraryRunOriginAgentDirect || run.Attestation != "" || run.ActorRef != client.Subject || run.SurfaceRef != client.ID {
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
	}
	if record := s.libraryMCPClientArtifactVersionRequestLocked(client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationImageCreate, requestIDHash); record != nil {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionRequestConflict
		}
		version := s.libraryArtifactVersionLocked(artifact.ID, record.ArtifactVersionID)
		if version == nil {
			return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("stored MCP client image artifact revision replay is incomplete")
		}
		return LibraryMCPClientArtifactVersionCreateResult{Version: copyLibraryArtifactVersion(*version), Replayed: true}, nil
	}

	latest := s.latestLibraryArtifactVersionLocked(artifact.ID)
	if latest == nil || latest.Format != LibraryArtifactFormatImage || latest.ID != request.ExpectedArtifactVersionID || latest.Digest != request.ExpectedDigest {
		if latest != nil && latest.Format == LibraryArtifactFormatImage && (latest.ID != request.ExpectedArtifactVersionID || latest.Digest != request.ExpectedDigest) {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionConflict
		}
		return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryArtifactNotFound
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
	if s.libraryArtifactVersionLocked(version.ArtifactID, version.ID) != nil || s.libraryArtifactMediaBlobLocked(version.ID) != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("library image artifact version identity already exists")
	}
	media, err := libraryArtifactMediaFromCanonical(version.ID, request.Image, request.AltText)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	blob := libraryArtifactMediaBlob{
		ArtifactVersionID: media.ArtifactVersionID, MIMEType: media.MIMEType, Digest: media.Digest, SizeBytes: media.SizeBytes,
		Width: media.Width, Height: media.Height, AltText: media.AltText, DeliveryMode: media.DeliveryMode,
		Data: append([]byte(nil), request.Image.Bytes...), CreatedAt: version.CreatedAt,
	}
	if err := validateLibraryArtifactMediaBlob(blob); err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	requestRecord := libraryMCPClientArtifactVersionRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, ArtifactID: artifact.ID,
		Operation: libraryMCPClientArtifactVersionOperationImageCreate, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, ArtifactVersionID: version.ID, CreatedAt: version.CreatedAt,
	}
	versionCopy := copyLibraryArtifactVersion(version)
	blobCopy := copyLibraryArtifactMediaBlob(blob)
	requestCopy := copyLibraryMCPClientArtifactVersionRequestRecord(requestRecord)
	beforeRequests := copyLibraryMCPClientArtifactVersionRequestRecords(s.libraryMCPClientArtifactVersionRequests)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryArtifactMediaBlobs = append(s.libraryArtifactMediaBlobs, &blobCopy)
	s.libraryMCPClientArtifactVersionRequests = append(s.libraryMCPClientArtifactVersionRequests, &requestCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryArtifactMediaBlobs = s.libraryArtifactMediaBlobs[:len(s.libraryArtifactMediaBlobs)-1]
		s.libraryMCPClientArtifactVersionRequests = beforeRequests
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	return LibraryMCPClientArtifactVersionCreateResult{Version: copyLibraryArtifactVersion(versionCopy)}, nil
}
