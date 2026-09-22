package engine

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var _ LibrarySkillBundleStore = (*FileStore)(nil)
var _ LibraryMCPClientSkillBlobStore = (*FileStore)(nil)

// librarySkillBlobRecord is one content-addressed bundle file. FileStore keeps
// the repository's documented local plaintext posture; JSON marshals Data as
// base64. A blob is never independently addressable: every read goes through
// an exact skill/version/path lookup.
type librarySkillBlobRecord struct {
	Digest    string    `json:"digest"`
	SizeBytes int64     `json:"sizeBytes"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"createdAt"`
}

// librarySkillBlobStagingRecord authorizes exactly one leased MCP client and
// epoch to reference an uploaded blob until the lease that accepted it
// expires. It carries the same hash-only idempotency fields as other leased
// writes; the raw request ID is never persisted.
type librarySkillBlobStagingRecord struct {
	ID             string    `json:"id"`
	MCPClientID    string    `json:"mcpClientId"`
	MCPClientEpoch string    `json:"mcpClientEpoch"`
	LeaseID        string    `json:"leaseId"`
	RequestIDHash  string    `json:"requestIdHash"`
	PayloadDigest  string    `json:"payloadDigest"`
	Digest         string    `json:"digest"`
	ContentType    string    `json:"contentType"`
	SizeBytes      int64     `json:"sizeBytes"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
}

func copyLibrarySkillBlobRecords(in []*librarySkillBlobRecord) []*librarySkillBlobRecord {
	out := make([]*librarySkillBlobRecord, len(in))
	copy(out, in)
	return out
}

func copyLibrarySkillBlobStagingRecords(in []*librarySkillBlobStagingRecord) []*librarySkillBlobStagingRecord {
	out := make([]*librarySkillBlobStagingRecord, len(in))
	copy(out, in)
	return out
}

// materializeLibrarySkillManifestsLocked is the FileStore migration: every
// version loaded without a manifest becomes the equivalent one-file manifest
// in memory and is persisted with it on the next save. Content and Digest are
// never touched, so legacy version IDs and digests remain valid.
func (s *FileStore) materializeLibrarySkillManifestsLocked() error {
	for _, version := range s.librarySkillVersions {
		if version == nil {
			continue
		}
		if len(version.Files) > 0 && version.ManifestDigest != "" {
			continue
		}
		materialized, err := librarySkillVersionWithManifest(*version)
		if err != nil {
			return fmt.Errorf("skill version %q: %w", version.ID, err)
		}
		version.Files = materialized.Files
		version.ManifestDigest = materialized.ManifestDigest
	}
	return nil
}

func (s *FileStore) librarySkillBlobLocked(digest string) *librarySkillBlobRecord {
	for _, blob := range s.librarySkillBlobs {
		if blob != nil && blob.Digest == digest {
			return blob
		}
	}
	return nil
}

// storeLibrarySkillBlobsLocked appends the blobs a bundle needs that are not
// already stored and returns the digests it added, so a failed save can
// remove exactly those and leave shared blobs untouched.
func (s *FileStore) storeLibrarySkillBlobsLocked(blobs map[string][]byte, now time.Time) []string {
	added := make([]string, 0, len(blobs))
	for digest, data := range blobs {
		if s.librarySkillBlobLocked(digest) != nil {
			continue
		}
		s.librarySkillBlobs = append(s.librarySkillBlobs, &librarySkillBlobRecord{
			Digest: digest, SizeBytes: int64(len(data)), Data: append([]byte(nil), data...), CreatedAt: now,
		})
		added = append(added, digest)
	}
	return added
}

func (s *FileStore) removeLibrarySkillBlobsLocked(digests []string) {
	if len(digests) == 0 {
		return
	}
	remove := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		remove[digest] = struct{}{}
	}
	kept := s.librarySkillBlobs[:0]
	for _, blob := range s.librarySkillBlobs {
		if blob == nil {
			continue
		}
		if _, drop := remove[blob.Digest]; drop {
			continue
		}
		kept = append(kept, blob)
	}
	s.librarySkillBlobs = kept
}

// requireLibrarySkillBlobsLocked proves every manifest entry other than
// SKILL.md has its bytes in the content-addressed store before a version that
// references it is written.
func (s *FileStore) requireLibrarySkillBlobsLocked(bundle LibrarySkillBundle) error {
	for _, file := range bundle.Files {
		if file.Path == LibrarySkillInstructionsPath {
			continue
		}
		if _, supplied := bundle.Blobs[file.Digest]; supplied {
			continue
		}
		if s.librarySkillBlobLocked(file.Digest) == nil {
			return fmt.Errorf("%w: %q", ErrLibrarySkillBlobNotFound, file.Path)
		}
	}
	return nil
}

// bundleForVersion aligns a caller-supplied version with its normalized
// bundle: the bundle's SKILL.md content wins when the version left Content
// empty, and the manifest is copied onto the version so normalizedLibraryVersion
// validates and digests it.
func librarySkillVersionFromBundle(version LibrarySkillVersion, content string, bundle LibrarySkillBundle) (LibrarySkillVersion, error) {
	if version.Content == "" {
		version.Content = content
	}
	if version.Content != content {
		return LibrarySkillVersion{}, fmt.Errorf("%w: version content does not match the bundle", ErrLibrarySkillBundleInvalid)
	}
	version.Files = copyLibrarySkillFiles(bundle.Files)
	version.ManifestDigest = bundle.ManifestDigest
	return version, nil
}

func (s *FileStore) CreateLibrarySkillWithInitialBundle(_ context.Context, skill LibrarySkill, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkill, LibrarySkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLibrarySkillWithInitialVersionLocked(skill, version, &bundle)
}

func (s *FileStore) CreateLibrarySkillBundleVersion(_ context.Context, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLibrarySkillVersionLocked(version, &bundle)
}

// LibrarySkillFileBytes returns one file of one exact immutable version. The
// bytes are re-verified against the manifest digest and size before they are
// returned, so a corrupt blob can never be served as a valid file.
func (s *FileStore) LibrarySkillFileBytes(_ context.Context, skillID, versionID, filePath string) ([]byte, LibrarySkillFile, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.librarySkillVersionLocked(skillID, versionID)
	if version == nil {
		return nil, LibrarySkillFile{}, false, nil
	}
	return s.librarySkillFileBytesLocked(*version, filePath)
}

func (s *FileStore) librarySkillFileBytesLocked(version LibrarySkillVersion, filePath string) ([]byte, LibrarySkillFile, bool, error) {
	file, found := librarySkillFileByPath(version, filePath)
	if !found {
		return nil, LibrarySkillFile{}, false, nil
	}
	var data []byte
	if file.Path == LibrarySkillInstructionsPath {
		data = []byte(version.Content)
	} else {
		blob := s.librarySkillBlobLocked(file.Digest)
		if blob == nil {
			return nil, LibrarySkillFile{}, false, fmt.Errorf("%w: %q", ErrLibrarySkillBlobNotFound, filePath)
		}
		data = append([]byte(nil), blob.Data...)
	}
	if int64(len(data)) != file.SizeBytes || librarySkillFileDigest(data) != file.Digest {
		return nil, LibrarySkillFile{}, false, fmt.Errorf("%w: stored bytes for %q do not match the manifest", ErrLibrarySkillBundleInvalid, filePath)
	}
	return data, file, true, nil
}

// librarySkillBlobStagingLocked finds a live staging record for one exact
// client and epoch. Expired records are ignored rather than deleted here so
// the read stays side-effect free; a later write sweeps them.
func (s *FileStore) librarySkillBlobStagingLocked(clientID, epoch, blobID string, now time.Time) *librarySkillBlobStagingRecord {
	for _, staging := range s.librarySkillBlobStagings {
		if staging != nil && staging.ID == blobID && staging.MCPClientID == clientID && staging.MCPClientEpoch == epoch && now.Before(staging.ExpiresAt) {
			return staging
		}
	}
	return nil
}

func (s *FileStore) librarySkillBlobStagingByRequestLocked(clientID, epoch, requestIDHash string) *librarySkillBlobStagingRecord {
	for _, staging := range s.librarySkillBlobStagings {
		if staging != nil && staging.MCPClientID == clientID && staging.MCPClientEpoch == epoch && staging.RequestIDHash == requestIDHash {
			return staging
		}
	}
	return nil
}

// sweepLibrarySkillBlobStagingsLocked drops expired authorizations. Blob
// bytes stay in the content-addressed store; only the right to reference them
// without re-uploading lapses.
func (s *FileStore) sweepLibrarySkillBlobStagingsLocked(now time.Time) {
	kept := s.librarySkillBlobStagings[:0]
	for _, staging := range s.librarySkillBlobStagings {
		if staging != nil && now.Before(staging.ExpiresAt.Add(libraryMCPClientSkillAuthoringLeaseDuration)) {
			kept = append(kept, staging)
		}
	}
	s.librarySkillBlobStagings = kept
}

// resolveLibrarySkillBlobRefsLocked turns staged references into files for
// bundle normalization. A reference the client did not stage under this epoch,
// an expired staging, or a path whose type differs from the staged type is
// rejected before any version write.
func (s *FileStore) resolveLibrarySkillBlobRefsLocked(client MCPClient, refs []librarySkillBlobRef, now time.Time) ([]LibrarySkillFileContent, error) {
	files := make([]LibrarySkillFileContent, 0, len(refs))
	for _, ref := range refs {
		staging := s.librarySkillBlobStagingLocked(client.ID, client.Epoch, ref.BlobID, now)
		if staging == nil {
			return nil, fmt.Errorf("%w: %q references an unknown or expired blob", ErrLibrarySkillBundleInvalid, ref.Path)
		}
		expectedType, err := librarySkillContentTypeForPath(ref.Path)
		if err != nil {
			return nil, err
		}
		if expectedType != staging.ContentType {
			return nil, fmt.Errorf("%w: %q was staged as %q", ErrLibrarySkillBundleInvalid, ref.Path, staging.ContentType)
		}
		blob := s.librarySkillBlobLocked(staging.Digest)
		if blob == nil {
			return nil, fmt.Errorf("%w: %q", ErrLibrarySkillBlobNotFound, ref.Path)
		}
		files = append(files, LibrarySkillFileContent{Path: ref.Path, ContentType: staging.ContentType, Data: append([]byte(nil), blob.Data...)})
	}
	return files, nil
}

// StageLibraryMCPClientSkillBlob stores one file's bytes under the caller's
// active authoring lease. It consumes one bounded authoring write, replays an
// exact retry without consuming another, and rejects a changed payload for a
// reused request ID. The returned blobId is usable only by this client and
// epoch and only until the lease expires.
func (s *FileStore) StageLibraryMCPClientSkillBlob(_ context.Context, endpointClient MCPClient, request LibraryMCPClientSkillBlobUploadRequest) (LibraryMCPClientSkillBlobUploadResult, error) {
	request, file, payloadDigest, err := normalizeLibraryMCPClientSkillBlobUploadRequest(request)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringUploadRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)

	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(endpointClient.ID)
	if !found {
		return LibraryMCPClientSkillBlobUploadResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	latest := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	latestID := ""
	if latest != nil {
		latestID = latest.ID
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject || client.Subject == "" {
		return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestID, firstNonEmpty(client.Subject, client.ID), LibraryMCPClientSkillAuthoringAuditOperationUpload,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	now := time.Now().UTC()
	if record := s.librarySkillBlobStagingByRequestLocked(client.ID, client.Epoch, requestIDHash); record != nil {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
				*client, record.LeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpload,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		lease := s.libraryMCPClientSkillAuthoringLeaseByIDLocked(record.LeaseID)
		if lease == nil {
			return LibraryMCPClientSkillBlobUploadResult{}, errors.New("stored skill blob staging lease is unavailable")
		}
		leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
		leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
		return LibraryMCPClientSkillBlobUploadResult{
			BlobID: record.ID, Digest: record.Digest, ContentType: record.ContentType, SizeBytes: record.SizeBytes,
			ExpiresAt: record.ExpiresAt, Lease: leaseCopy, Replayed: true,
		}, nil
	}
	lease := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	if lease == nil || lease.MCPClientEpoch != client.Epoch ||
		libraryMCPClientSkillAuthoringLeaseStatus(*lease, *client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive ||
		lease.RemainingUploads <= 0 {
		return LibraryMCPClientSkillBlobUploadResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpload,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	digest := librarySkillFileDigest(file.Data)
	staging := &librarySkillBlobStagingRecord{
		ID: newLibrarySkillBlobStagingID(), MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID,
		RequestIDHash: requestIDHash, PayloadDigest: payloadDigest, Digest: digest, ContentType: file.ContentType,
		SizeBytes: int64(len(file.Data)), ExpiresAt: lease.ExpiresAt, CreatedAt: now,
	}
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpload,
		client.Subject, requestIDHash, payloadDigest, "", "", now,
	)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	beforeLease := copyLibraryMCPClientSkillAuthoringLease(*lease)
	beforeStagings := copyLibrarySkillBlobStagingRecords(s.librarySkillBlobStagings)
	beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	s.sweepLibrarySkillBlobStagingsLocked(now)
	addedBlobs := s.storeLibrarySkillBlobsLocked(map[string][]byte{digest: file.Data}, now)
	lease.RemainingUploads--
	lease.UpdatedAt = now
	s.librarySkillBlobStagings = append(s.librarySkillBlobStagings, staging)
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(consumeEvent)
	if err := s.saveLocked(); err != nil {
		*lease = beforeLease
		s.librarySkillBlobStagings = beforeStagings
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		s.removeLibrarySkillBlobsLocked(addedBlobs)
		return LibraryMCPClientSkillBlobUploadResult{}, err
	}
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return LibraryMCPClientSkillBlobUploadResult{
		BlobID: staging.ID, Digest: digest, ContentType: staging.ContentType, SizeBytes: staging.SizeBytes,
		ExpiresAt: staging.ExpiresAt, Lease: leaseCopy,
	}, nil
}

// UpdateLibrarySkillDescription edits the record's description in one save.
// It is an owner/admin metadata change: versions, bindings, slug, and name
// are untouched, and the Engine-managed guide cannot be edited.
func (s *FileStore) UpdateLibrarySkillDescription(_ context.Context, skillID, description string) (LibrarySkill, error) {
	if isBuiltInLibrarySkillID(skillID) {
		return LibrarySkill{}, ErrLibraryBuiltInManaged
	}
	if err := validateLibrarySkillDescriptionUpdate(description); err != nil {
		return LibrarySkill{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	skill := s.librarySkillLocked(skillID)
	if skill == nil {
		return LibrarySkill{}, ErrLibrarySkillNotFound
	}
	previousDescription, previousUpdatedAt := skill.Description, skill.UpdatedAt
	skill.Description = description
	skill.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		skill.Description, skill.UpdatedAt = previousDescription, previousUpdatedAt
		return LibrarySkill{}, err
	}
	return copyLibrarySkill(*skill), nil
}
