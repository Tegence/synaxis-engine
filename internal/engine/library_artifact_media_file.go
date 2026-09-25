package engine

import (
	"context"
	"errors"
	"time"
)

var _ LibraryArtifactMediaStore = (*FileStore)(nil)

// libraryArtifactMediaBlob is one immutable private blob for one immutable
// image artifact version. There is deliberately no digest uniqueness index or
// shared blob pool: copying the same image into two versions must not make a
// later authorization decision depend on another artifact's lifetime.
//
// FileStore keeps the repository's documented local/plaintext posture. JSON
// marshals Data as base64 internally; it is never included in an artifact
// metadata projection or MCP create response.
type libraryArtifactMediaBlob struct {
	ArtifactVersionID string    `json:"artifactVersionId"`
	MIMEType          string    `json:"mimeType"`
	Digest            string    `json:"digest"`
	SizeBytes         int64     `json:"sizeBytes"`
	Width             int       `json:"width,omitempty"`
	Height            int       `json:"height,omitempty"`
	AltText           string    `json:"altText,omitempty"`
	DeliveryMode      string    `json:"deliveryMode"`
	Data              []byte    `json:"data"`
	CreatedAt         time.Time `json:"createdAt"`
}

func copyLibraryArtifactMediaBlob(blob libraryArtifactMediaBlob) libraryArtifactMediaBlob {
	blob.Data = append([]byte(nil), blob.Data...)
	return blob
}

func libraryArtifactMediaFromBlob(blob libraryArtifactMediaBlob) LibraryArtifactMedia {
	return LibraryArtifactMedia{
		ArtifactVersionID: blob.ArtifactVersionID,
		MIMEType:          blob.MIMEType,
		Digest:            blob.Digest,
		SizeBytes:         blob.SizeBytes,
		Width:             blob.Width,
		Height:            blob.Height,
		AltText:           blob.AltText,
		DeliveryMode:      blob.DeliveryMode,
	}
}

func validateLibraryArtifactMediaBlob(blob libraryArtifactMediaBlob) error {
	media := libraryArtifactMediaFromBlob(blob)
	return validateLibraryArtifactMediaBytes(media, blob.Data)
}

func (s *FileStore) libraryArtifactMediaBlobLocked(versionID string) *libraryArtifactMediaBlob {
	for _, blob := range s.libraryArtifactMediaBlobs {
		if blob != nil && blob.ArtifactVersionID == versionID {
			return blob
		}
	}
	return nil
}

func (s *FileStore) CreateLibraryRootMCPImageArtifactWithInitialVersion(_ context.Context, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := normalizeLibraryArtifactImageAltText(altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, artifact, version, err := prepareLibraryRootMCPImageArtifact(artifact, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil || s.libraryArtifactMediaBlobLocked(version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if artifact.SourceArtifactID != "" && !s.libraryRootMCPMayUseArtifactVersionLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	media, err := libraryArtifactMediaFromCanonical(version.ID, image, altText)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	blob := libraryArtifactMediaBlob{
		ArtifactVersionID: media.ArtifactVersionID, MIMEType: media.MIMEType, Digest: media.Digest, SizeBytes: media.SizeBytes,
		Width: media.Width, Height: media.Height, AltText: media.AltText, DeliveryMode: media.DeliveryMode,
		Data: append([]byte(nil), image.Bytes...), CreatedAt: version.CreatedAt,
	}
	if err := validateLibraryArtifactMediaBlob(blob); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	blobCopy := copyLibraryArtifactMediaBlob(blob)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryArtifactMediaBlobs = append(s.libraryArtifactMediaBlobs, &blobCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryArtifactMediaBlobs = s.libraryArtifactMediaBlobs[:len(s.libraryArtifactMediaBlobs)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

func (s *FileStore) CreateLibraryMCPClientImageArtifactWithInitialVersion(_ context.Context, client MCPClient, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if _, err := normalizeLibraryArtifactImageAltText(altText); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	storedClient, found := s.mcpClientByIDLocked(client.ID)
	if !found || storedClient.Subject != client.Subject {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientNotFound
	}
	if storedClient.Status != MCPClientStatusActive {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrMCPClientRevoked
	}
	run, artifact, version, err := prepareLibraryMCPClientImageArtifact(*storedClient, artifact, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil || s.libraryArtifactMediaBlobLocked(version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if artifact.SourceArtifactID != "" && !s.libraryMCPClientMayUseArtifactVersionLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, *storedClient) {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	if err := s.validateLibraryArtifactSourceLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	media, err := libraryArtifactMediaFromCanonical(version.ID, image, altText)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	blob := libraryArtifactMediaBlob{
		ArtifactVersionID: media.ArtifactVersionID, MIMEType: media.MIMEType, Digest: media.Digest, SizeBytes: media.SizeBytes,
		Width: media.Width, Height: media.Height, AltText: media.AltText, DeliveryMode: media.DeliveryMode,
		Data: append([]byte(nil), image.Bytes...), CreatedAt: version.CreatedAt,
	}
	if err := validateLibraryArtifactMediaBlob(blob); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	blobCopy := copyLibraryArtifactMediaBlob(blob)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryArtifactMediaBlobs = append(s.libraryArtifactMediaBlobs, &blobCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryArtifactMediaBlobs = s.libraryArtifactMediaBlobs[:len(s.libraryArtifactMediaBlobs)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// CreateLibraryHumanImageArtifactWithInitialVersion is the Console image
// create. Run, artifact, version, and blob are appended and saved under one
// mutex hold, so an image artifact never exists without its bytes.
func (s *FileStore) CreateLibraryHumanImageArtifactWithInitialVersion(_ context.Context, artifact LibraryArtifact, image libraryArtifactImageCanonical, altText string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	if s.libraryRunLocked(run.ID) != nil || s.libraryArtifactLocked(artifact.ID) != nil || s.libraryArtifactVersionLocked(artifact.ID, version.ID) != nil || s.libraryArtifactMediaBlobLocked(version.ID) != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("library artifact identity already exists")
	}
	if err := s.validateLibraryArtifactSourceLocked(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	media, err := libraryArtifactMediaFromCanonical(version.ID, image, altText)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	blob := libraryArtifactMediaBlob{
		ArtifactVersionID: media.ArtifactVersionID, MIMEType: media.MIMEType, Digest: media.Digest, SizeBytes: media.SizeBytes,
		Width: media.Width, Height: media.Height, AltText: media.AltText, DeliveryMode: media.DeliveryMode,
		Data: append([]byte(nil), image.Bytes...), CreatedAt: version.CreatedAt,
	}
	if err := validateLibraryArtifactMediaBlob(blob); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	runCopy := copyLibraryRun(run)
	artifactCopy := copyLibraryArtifact(artifact)
	versionCopy := copyLibraryArtifactVersion(version)
	blobCopy := copyLibraryArtifactMediaBlob(blob)
	s.libraryRuns = append(s.libraryRuns, &runCopy)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifactCopy)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryArtifactMediaBlobs = append(s.libraryArtifactMediaBlobs, &blobCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryArtifactMediaBlobs = s.libraryArtifactMediaBlobs[:len(s.libraryArtifactMediaBlobs)-1]
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return copyLibraryRun(runCopy), copyLibraryArtifact(artifactCopy), copyLibraryArtifactVersion(versionCopy), nil
}

// CreateLibraryHumanImageArtifactVersion appends a canonical image version
// to an existing image artifact for the administrator Console. The head is
// re-read under the mutex; a text artifact never gains an image version.
func (s *FileStore) CreateLibraryHumanImageArtifactVersion(_ context.Context, request LibraryHumanImageArtifactVersionCreateRequest) (LibraryArtifactVersion, error) {
	request, err := normalizeLibraryHumanImageArtifactVersionCreateRequest(request)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.libraryArtifactLocked(request.ArtifactID) == nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactNotFound
	}
	latest := s.latestLibraryArtifactVersionLocked(request.ArtifactID)
	if latest == nil {
		return LibraryArtifactVersion{}, ErrLibraryArtifactVersionNotFound
	}
	if latest.Format != LibraryArtifactFormatImage {
		return LibraryArtifactVersion{}, ErrLibraryArtifactFormatMismatch
	}
	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: request.ArtifactID, Version: latest.Version + 1,
		Changelog: request.Changelog, Provenance: request.Provenance,
		CreatedBy: request.CreatedBy, CreatedAt: time.Now().UTC(),
	}, request.Image)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	if s.libraryArtifactVersionLocked(version.ArtifactID, version.ID) != nil || s.libraryArtifactMediaBlobLocked(version.ID) != nil {
		return LibraryArtifactVersion{}, errors.New("library image artifact version identity already exists")
	}
	media, err := libraryArtifactMediaFromCanonical(version.ID, request.Image, request.AltText)
	if err != nil {
		return LibraryArtifactVersion{}, err
	}
	blob := libraryArtifactMediaBlob{
		ArtifactVersionID: media.ArtifactVersionID, MIMEType: media.MIMEType, Digest: media.Digest, SizeBytes: media.SizeBytes,
		Width: media.Width, Height: media.Height, AltText: media.AltText, DeliveryMode: media.DeliveryMode,
		Data: append([]byte(nil), request.Image.Bytes...), CreatedAt: version.CreatedAt,
	}
	if err := validateLibraryArtifactMediaBlob(blob); err != nil {
		return LibraryArtifactVersion{}, err
	}
	versionCopy := copyLibraryArtifactVersion(version)
	blobCopy := copyLibraryArtifactMediaBlob(blob)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &versionCopy)
	s.libraryArtifactMediaBlobs = append(s.libraryArtifactMediaBlobs, &blobCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryArtifactMediaBlobs = s.libraryArtifactMediaBlobs[:len(s.libraryArtifactMediaBlobs)-1]
		return LibraryArtifactVersion{}, err
	}
	return copyLibraryArtifactVersion(versionCopy), nil
}

func (s *FileStore) LibraryArtifactMedia(_ context.Context, artifactID, versionID string) (LibraryArtifactMedia, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if version == nil || version.Format != LibraryArtifactFormatImage {
		return LibraryArtifactMedia{}, false, nil
	}
	blob := s.libraryArtifactMediaBlobLocked(version.ID)
	if blob == nil {
		return LibraryArtifactMedia{}, false, ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactMediaBlob(*blob); err != nil {
		return LibraryArtifactMedia{}, false, err
	}
	media := libraryArtifactMediaFromBlob(*blob)
	if err := validateLibraryArtifactMediaForVersion(*version, media); err != nil {
		return LibraryArtifactMedia{}, false, err
	}
	return media, true, nil
}

func (s *FileStore) LibraryArtifactRasterBytes(_ context.Context, artifactID, versionID string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if version == nil || version.Format != LibraryArtifactFormatImage {
		return nil, false, nil
	}
	blob := s.libraryArtifactMediaBlobLocked(version.ID)
	if blob == nil {
		return nil, false, ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactMediaBlob(*blob); err != nil {
		return nil, false, err
	}
	media := libraryArtifactMediaFromBlob(*blob)
	if err := validateLibraryArtifactMediaForVersion(*version, media); err != nil {
		return nil, false, err
	}
	if media.DeliveryMode != libraryArtifactImageDeliveryInline {
		return nil, false, nil
	}
	return append([]byte(nil), blob.Data...), true, nil
}

// LibraryArtifactImageBytes returns one immutable image's canonical bytes only
// after a caller has authorized the exact parent artifact version. In
// particular, this must not be exposed by blob ID, and SVG callers must use an
// attachment-style download response rather than inline rendering.
func (s *FileStore) LibraryArtifactImageBytes(_ context.Context, artifactID, versionID string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.libraryArtifactVersionLocked(artifactID, versionID)
	if version == nil || version.Format != LibraryArtifactFormatImage {
		return nil, false, nil
	}
	blob := s.libraryArtifactMediaBlobLocked(version.ID)
	if blob == nil {
		return nil, false, ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactMediaBlob(*blob); err != nil {
		return nil, false, err
	}
	media := libraryArtifactMediaFromBlob(*blob)
	if err := validateLibraryArtifactMediaForVersion(*version, media); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), blob.Data...), true, nil
}
