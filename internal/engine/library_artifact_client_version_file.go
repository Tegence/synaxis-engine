package engine

import (
	"context"
	"errors"
	"time"
)

var _ LibraryMCPClientArtifactVersionStore = (*FileStore)(nil)

func (s *FileStore) latestLibraryArtifactVersionLocked(artifactID string) *LibraryArtifactVersion {
	var latest *LibraryArtifactVersion
	for _, version := range s.libraryArtifactVersions {
		if version == nil || version.ArtifactID != artifactID {
			continue
		}
		if latest == nil || version.Version > latest.Version || (version.Version == latest.Version && version.ID > latest.ID) {
			latest = version
		}
	}
	return latest
}

func (s *FileStore) libraryMCPClientArtifactVersionRequestLocked(clientID, epoch, artifactID, operation, requestIDHash string) *libraryMCPClientArtifactVersionRequestRecord {
	for _, record := range s.libraryMCPClientArtifactVersionRequests {
		if record != nil && record.MCPClientID == clientID && record.MCPClientEpoch == epoch &&
			record.ArtifactID == artifactID && record.Operation == operation && record.RequestIDHash == requestIDHash {
			return record
		}
	}
	return nil
}

// CreateLibraryMCPClientArtifactVersion appends one text/Markdown version to a
// directly owned client artifact. The FileStore mutex covers durable client
// validation, exact direct-run provenance, the head compare-and-swap, and the
// single save so a stale endpoint, grant, or concurrent Console append cannot
// turn into a mutable overwrite.
func (s *FileStore) CreateLibraryMCPClientArtifactVersion(_ context.Context, endpointClient MCPClient, request LibraryMCPClientArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	requestIDHash := libraryMCPClientArtifactVersionRequestIDHash(
		endpointClient.ID, endpointClient.Epoch, request.ArtifactID,
		libraryMCPClientArtifactVersionOperationTextCreate, request.RequestID,
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
	if record := s.libraryMCPClientArtifactVersionRequestLocked(client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationTextCreate, requestIDHash); record != nil {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientArtifactVersionCreateResult{}, ErrLibraryMCPClientArtifactVersionRequestConflict
		}
		version := s.libraryArtifactVersionLocked(artifact.ID, record.ArtifactVersionID)
		if version == nil {
			return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("stored MCP client artifact revision replay is incomplete")
		}
		return LibraryMCPClientArtifactVersionCreateResult{Version: copyLibraryArtifactVersion(*version), Replayed: true}, nil
	}

	latest := s.latestLibraryArtifactVersionLocked(artifact.ID)
	// This narrow feature intentionally does not add a version type-changing
	// path for private image/SVG artifacts. A later media revision design must
	// define canonical bytes, media validation, and delivery behavior first.
	if latest == nil || (latest.Format != LibraryArtifactFormatText && latest.Format != LibraryArtifactFormatMarkdown) {
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
	if s.libraryArtifactVersionLocked(version.ArtifactID, version.ID) != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("library artifact version identity already exists")
	}
	if s.libraryMCPClientArtifactVersionRequestLocked(client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationTextCreate, requestIDHash) != nil {
		return LibraryMCPClientArtifactVersionCreateResult{}, errors.New("library MCP client artifact revision request identity already exists")
	}
	requestRecord := libraryMCPClientArtifactVersionRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, ArtifactID: artifact.ID,
		Operation: libraryMCPClientArtifactVersionOperationTextCreate, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, ArtifactVersionID: version.ID, CreatedAt: version.CreatedAt,
	}
	versionCopy := copyLibraryArtifactVersion(version)
	requestCopy := copyLibraryMCPClientArtifactVersionRequestRecord(requestRecord)
	beforeRequests := copyLibraryMCPClientArtifactVersionRequestRecords(s.libraryMCPClientArtifactVersionRequests)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryMCPClientArtifactVersionRequests = append(s.libraryMCPClientArtifactVersionRequests, &requestCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryMCPClientArtifactVersionRequests = beforeRequests
		return LibraryMCPClientArtifactVersionCreateResult{}, err
	}
	return LibraryMCPClientArtifactVersionCreateResult{Version: copyLibraryArtifactVersion(versionCopy)}, nil
}
