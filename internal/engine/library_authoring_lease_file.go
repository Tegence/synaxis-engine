package engine

import (
	"context"
	"errors"
	"sort"
	"time"
)

var _ LibraryMCPClientSkillAuthoringStore = (*FileStore)(nil)
var _ LibraryMCPClientSkillAuthoringAuditStore = (*FileStore)(nil)

func (s *FileStore) libraryMCPClientSkillAuthoringLeaseLocked(clientID string) *LibraryMCPClientSkillAuthoringLease {
	var selected *LibraryMCPClientSkillAuthoringLease
	for _, lease := range s.libraryMCPClientSkillAuthoringLeases {
		if lease == nil || lease.MCPClientID != clientID {
			continue
		}
		if selected == nil || lease.GrantedAt.After(selected.GrantedAt) || (lease.GrantedAt.Equal(selected.GrantedAt) && lease.ID > selected.ID) {
			selected = lease
		}
	}
	return selected
}

func (s *FileStore) libraryMCPClientSkillAuthoringLeaseByIDLocked(id string) *LibraryMCPClientSkillAuthoringLease {
	for _, lease := range s.libraryMCPClientSkillAuthoringLeases {
		if lease != nil && lease.ID == id {
			return lease
		}
	}
	return nil
}

func (s *FileStore) activeLibraryMCPClientSkillAuthoringLeasesLocked(clientID string) []*LibraryMCPClientSkillAuthoringLease {
	out := make([]*LibraryMCPClientSkillAuthoringLease, 0, 1)
	for _, lease := range s.libraryMCPClientSkillAuthoringLeases {
		if lease != nil && lease.MCPClientID == clientID && lease.RevokedAt == nil {
			out = append(out, lease)
		}
	}
	return out
}

func (s *FileStore) libraryMCPClientSkillAuthoringRequestLocked(clientID, epoch, requestIDHash string) *libraryMCPClientSkillAuthoringRequestRecord {
	for _, record := range s.libraryMCPClientSkillAuthoringRequests {
		if record != nil && record.MCPClientID == clientID && record.MCPClientEpoch == epoch && record.RequestIDHash == requestIDHash {
			return record
		}
	}
	return nil
}

// libraryMCPClientCreatedSkillLocked requires both sides of the durable create
// receipt: the scoped idempotency record points this client at version one and
// the append-only audit receipt records a consumed create. A skill's CreatedBy
// subject is intentionally not enough: multiple subject-bound clients can
// share it.
func (s *FileStore) libraryMCPClientCreatedSkillLocked(clientID, skillID string) bool {
	hasInitialRequest := false
	for _, record := range s.libraryMCPClientSkillAuthoringRequests {
		if record == nil || record.MCPClientID != clientID || record.SkillID != skillID {
			continue
		}
		version := s.librarySkillVersionLocked(skillID, record.VersionID)
		if version != nil && version.Version == 1 {
			hasInitialRequest = true
			break
		}
	}
	if !hasInitialRequest {
		return false
	}
	for _, event := range s.libraryMCPClientSkillAuthoringAuditEvents {
		if event != nil && event.MCPClientID == clientID && event.SkillID == skillID &&
			event.Action == LibraryMCPClientSkillAuthoringAuditActionConsumed &&
			event.Operation == LibraryMCPClientSkillAuthoringAuditOperationCreate {
			return true
		}
	}
	return false
}

func (s *FileStore) librarySkillHasBindingsLocked(skillID string) bool {
	for _, binding := range s.librarySkillBindings {
		if binding != nil && binding.SkillID == skillID {
			return true
		}
	}
	return false
}

func (s *FileStore) latestLibrarySkillVersionLocked(skillID string) *LibrarySkillVersion {
	var latest *LibrarySkillVersion
	for _, version := range s.librarySkillVersions {
		if version == nil || version.SkillID != skillID {
			continue
		}
		if latest == nil || version.Version > latest.Version || (version.Version == latest.Version && version.ID > latest.ID) {
			latest = version
		}
	}
	return latest
}

func (s *FileStore) MCPClientSkillAuthoringLeaseAuditEvents(_ context.Context, clientID string) ([]LibraryMCPClientSkillAuthoringAuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryMCPClientSkillAuthoringAuditEvent, 0)
	for _, event := range s.libraryMCPClientSkillAuthoringAuditEvents {
		if event != nil && event.MCPClientID == clientID {
			out = append(out, copyLibraryMCPClientSkillAuthoringAuditEvent(*event))
		}
	}
	return out, nil
}

func (s *FileStore) appendLibraryMCPClientSkillAuthoringAuditLocked(event LibraryMCPClientSkillAuthoringAuditEvent) {
	copy := copyLibraryMCPClientSkillAuthoringAuditEvent(event)
	s.libraryMCPClientSkillAuthoringAuditEvents = append(s.libraryMCPClientSkillAuthoringAuditEvents, &copy)
}

// rejectLibraryMCPClientSkillAuthoringLocked commits a safe, server-derived
// rejection receipt before returning its normal caller-facing error. It never
// writes raw MCP request fields and is only called after a durable client has
// been loaded under this FileStore lock.
func (s *FileStore) rejectLibraryMCPClientSkillAuthoringLocked(client MCPClient, leaseID, actorRef, operation, requestIDHash, payloadDigest string, cause error) error {
	event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, leaseID, LibraryMCPClientSkillAuthoringAuditActionRejected, operation, actorRef,
		requestIDHash, payloadDigest, "", "", time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	before := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(event)
	if err := s.saveLocked(); err != nil {
		s.libraryMCPClientSkillAuthoringAuditEvents = before
		return err
	}
	return cause
}

func (s *FileStore) MCPClientSkillAuthoringLease(_ context.Context, clientID string) (LibraryMCPClientSkillAuthoringLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lease := s.libraryMCPClientSkillAuthoringLeaseLocked(clientID)
	if lease == nil {
		return LibraryMCPClientSkillAuthoringLease{}, false, nil
	}
	client, found := s.mcpClientByIDLocked(clientID)
	copy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	if found {
		copy.Status = libraryMCPClientSkillAuthoringLeaseStatus(copy, *client, true, time.Now().UTC())
	} else {
		copy.Status = libraryMCPClientSkillAuthoringLeaseStatus(copy, MCPClient{}, false, time.Now().UTC())
	}
	return copy, true, nil
}

func (s *FileStore) GrantMCPClientSkillAuthoringLease(_ context.Context, clientID string, precondition MCPClientPrecondition, grantedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	if err := validateLibraryOpaqueRef("granted by", grantedBy, false); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(clientID)
	if !found {
		return LibraryMCPClientSkillAuthoringLease{}, ErrMCPClientNotFound
	}
	current := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	currentLeaseID := ""
	if current != nil {
		currentLeaseID = current.ID
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrMCPClientRevision)
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrLibraryMCPClientSkillAuthoringClientUnavailable)
	}

	if current != nil &&
		current.MCPClientEpoch == client.Epoch &&
		libraryMCPClientSkillAuthoringLeaseStatus(*current, *client, true, time.Now().UTC()) == LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, current.ID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrLibraryMCPClientSkillAuthoringLeaseActive)
	}
	beforeLeases := copyLibraryMCPClientSkillAuthoringLeases(s.libraryMCPClientSkillAuthoringLeases)
	beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	now := time.Now().UTC()
	// An expired, exhausted, or invalid historical window must not block a new
	// one forever. Preserve it as revoked rather than overwriting it, so its
	// request receipts remain auditable and retries stay deterministic. A live
	// lease was rejected above and can only be ended through the explicit
	// lease-ID-fenced revoke route.
	for _, lease := range s.activeLibraryMCPClientSkillAuthoringLeasesLocked(client.ID) {
		auditClient := *client
		auditClient.Epoch = lease.MCPClientEpoch
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			auditClient, lease.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationGrant,
			grantedBy, "", "", "", "", now,
		)
		if err != nil {
			s.libraryMCPClientSkillAuthoringLeases = beforeLeases
			s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		s.appendLibraryMCPClientSkillAuthoringAuditLocked(event)
		revokedAt := now
		lease.RevokedAt = &revokedAt
		lease.RevokedBy = grantedBy
		lease.UpdatedAt = now
	}
	lease := LibraryMCPClientSkillAuthoringLease{
		ID:               newLibraryMCPClientSkillAuthoringLeaseID(),
		MCPClientID:      client.ID,
		MCPClientEpoch:   client.Epoch,
		GrantedBy:        grantedBy,
		GrantedAt:        now,
		ExpiresAt:        now.Add(libraryMCPClientSkillAuthoringLeaseDuration),
		RemainingCreates: libraryMCPClientSkillAuthoringLeaseMaxCreates,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.libraryMCPClientSkillAuthoringLeases = append(s.libraryMCPClientSkillAuthoringLeases, &lease)
	grantEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationGrant,
		grantedBy, "", "", "", "", now,
	)
	if err != nil {
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(grantEvent)
	if err := s.saveLocked(); err != nil {
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	result := copyLibraryMCPClientSkillAuthoringLease(lease)
	result.Status = LibraryMCPClientSkillAuthoringLeaseStatusActive
	return result, nil
}

func (s *FileStore) RevokeMCPClientSkillAuthoringLease(_ context.Context, clientID, leaseID string, precondition MCPClientPrecondition, revokedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	if err := validateLibraryOpaqueRef("revoked by", revokedBy, false); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(clientID)
	if !found {
		return LibraryMCPClientSkillAuthoringLease{}, ErrMCPClientNotFound
	}
	latest := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	latestID := ""
	if latest != nil {
		latestID = latest.ID
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, latestID, revokedBy, LibraryMCPClientSkillAuthoringAuditOperationRevoke, "", "", ErrMCPClientRevision)
	}
	lease := latest
	if lease == nil || lease.ID != leaseID {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, latestID, revokedBy, LibraryMCPClientSkillAuthoringAuditOperationRevoke, "", "", ErrLibraryMCPClientSkillAuthoringLeaseNotFound)
	}
	if lease.RevokedAt == nil {
		before := copyLibraryMCPClientSkillAuthoringLease(*lease)
		beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
		now := time.Now().UTC()
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationRevoke,
			revokedBy, "", "", "", "", now,
		)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		lease.RevokedAt = &now
		lease.RevokedBy = revokedBy
		lease.UpdatedAt = now
		s.appendLibraryMCPClientSkillAuthoringAuditLocked(event)
		if err := s.saveLocked(); err != nil {
			*lease = before
			s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
	}
	result := copyLibraryMCPClientSkillAuthoringLease(*lease)
	result.Status = LibraryMCPClientSkillAuthoringLeaseStatusRevoked
	return result, nil
}

func (s *FileStore) CreateLibraryMCPClientSkillWithAuthoringLease(_ context.Context, endpointClient MCPClient, request LibraryMCPClientSkillAuthoringRequest) (LibraryMCPClientSkillAuthoringResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientSkillAuthoringRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)

	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(endpointClient.ID)
	if !found {
		return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	latest := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	latestID := ""
	if latest != nil {
		latestID = latest.ID
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if client.Subject == "" {
		return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	if record := s.libraryMCPClientSkillAuthoringRequestLocked(client.ID, client.Epoch, requestIDHash); record != nil {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
				*client, record.LeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		skill := s.librarySkillLocked(record.SkillID)
		version := s.librarySkillVersionLocked(record.SkillID, record.VersionID)
		if skill == nil || version == nil {
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring replay is incomplete")
		}
		lease := s.libraryMCPClientSkillAuthoringLeaseByIDLocked(record.LeaseID)
		if lease == nil {
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring lease is unavailable")
		}
		leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
		leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, time.Now().UTC())
		return LibraryMCPClientSkillAuthoringResult{
			Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(*version), Lease: leaseCopy, Replayed: true,
		}, nil
	}

	lease := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	if lease == nil || lease.MCPClientEpoch != client.Epoch ||
		libraryMCPClientSkillAuthoringLeaseStatus(*lease, *client, true, time.Now().UTC()) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	for _, existing := range s.librarySkills {
		if existing != nil && existing.Slug == request.Slug {
			// The handler deliberately maps this to a neutral unavailable result
			// for the subject-bound MCP client. Do not reveal a global slug match.
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
				*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
				requestIDHash, payloadDigest, ErrLibrarySkillExists,
			)
		}
	}

	now := time.Now().UTC()
	skill := LibrarySkill{
		ID: newLibrarySkillID(), Slug: request.Slug, Name: request.Name, Description: request.Description,
		CreatedBy: client.Subject, CreatedAt: now, UpdatedAt: now,
	}
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: 1, Content: request.Content,
		RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate,
		client.Subject, requestIDHash, payloadDigest, skill.ID, version.ID, now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}

	beforeLeases := copyLibraryMCPClientSkillAuthoringLeases(s.libraryMCPClientSkillAuthoringLeases)
	beforeRequests := copyLibraryMCPClientSkillAuthoringRequestRecords(s.libraryMCPClientSkillAuthoringRequests)
	beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	skillCopy, versionCopy := copyLibrarySkill(skill), copyLibrarySkillVersion(version)
	lease.RemainingCreates--
	lease.UpdatedAt = now
	s.librarySkills = append(s.librarySkills, &skillCopy)
	s.librarySkillVersions = append(s.librarySkillVersions, &versionCopy)
	s.libraryMCPClientSkillAuthoringRequests = append(s.libraryMCPClientSkillAuthoringRequests, &libraryMCPClientSkillAuthoringRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, SkillID: skill.ID, VersionID: version.ID, CreatedAt: now,
	})
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(consumeEvent)
	if err := s.saveLocked(); err != nil {
		s.librarySkills = s.librarySkills[:len(s.librarySkills)-1]
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.libraryMCPClientSkillAuthoringRequests = beforeRequests
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return LibraryMCPClientSkillAuthoringResult{
		Skill: copyLibrarySkill(skillCopy), Version: copyLibrarySkillVersion(versionCopy), Lease: leaseCopy,
	}, nil
}

// UpdateLibraryMCPClientSkillWithAuthoringLease appends one immutable version
// for a skill created by this exact durable MCP client. The single FileStore
// lock makes lease validation, unbound/ownership checks, optimistic-version
// fencing, version insertion, quota consumption, replay receipt, and audit
// persistence one recoverable state transition.
func (s *FileStore) UpdateLibraryMCPClientSkillWithAuthoringLease(_ context.Context, endpointClient MCPClient, request LibraryMCPClientSkillAuthoringUpdateRequest) (LibraryMCPClientSkillAuthoringResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientSkillAuthoringUpdateRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringUpdateRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)

	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(endpointClient.ID)
	if !found {
		return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	latestLease := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	latestLeaseID := ""
	if latestLease != nil {
		latestLeaseID = latestLease.ID
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject || client.Subject == "" {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestLeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if record := s.libraryMCPClientSkillAuthoringRequestLocked(client.ID, client.Epoch, requestIDHash); record != nil {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
				*client, record.LeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		skill := s.librarySkillLocked(record.SkillID)
		version := s.librarySkillVersionLocked(record.SkillID, record.VersionID)
		if skill == nil || version == nil {
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring replay is incomplete")
		}
		lease := s.libraryMCPClientSkillAuthoringLeaseByIDLocked(record.LeaseID)
		if lease == nil {
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring lease is unavailable")
		}
		leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
		leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, time.Now().UTC())
		return LibraryMCPClientSkillAuthoringResult{
			Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(*version), Lease: leaseCopy, Replayed: true,
		}, nil
	}

	now := time.Now().UTC()
	lease := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	if lease == nil || lease.MCPClientEpoch != client.Epoch ||
		libraryMCPClientSkillAuthoringLeaseStatus(*lease, *client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestLeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	skill := s.librarySkillLocked(request.SkillID)
	if skill == nil || skill.CreatedBy != client.Subject || !s.libraryMCPClientCreatedSkillLocked(client.ID, request.SkillID) || s.librarySkillHasBindingsLocked(request.SkillID) {
		// A deliberately neutral failure covers unknown, other-client, bound, and
		// ordinary owner-authored skills so this endpoint cannot become a Library
		// membership or binding oracle.
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	latestVersion := s.latestLibrarySkillVersionLocked(skill.ID)
	if latestVersion == nil || latestVersion.ID != request.ExpectedVersionID || latestVersion.Digest != request.ExpectedVersionDigest {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: latestVersion.Version + 1,
		Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
		client.Subject, requestIDHash, payloadDigest, skill.ID, version.ID, now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}

	beforeLease := copyLibraryMCPClientSkillAuthoringLease(*lease)
	beforeSkill := copyLibrarySkill(*skill)
	beforeRequests := copyLibraryMCPClientSkillAuthoringRequestRecords(s.libraryMCPClientSkillAuthoringRequests)
	beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	versionCopy := copyLibrarySkillVersion(version)
	lease.RemainingCreates--
	lease.UpdatedAt = now
	skill.UpdatedAt = now
	s.librarySkillVersions = append(s.librarySkillVersions, &versionCopy)
	s.libraryMCPClientSkillAuthoringRequests = append(s.libraryMCPClientSkillAuthoringRequests, &libraryMCPClientSkillAuthoringRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, SkillID: skill.ID, VersionID: version.ID, CreatedAt: now,
	})
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(consumeEvent)
	if err := s.saveLocked(); err != nil {
		*lease = beforeLease
		*skill = beforeSkill
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		s.libraryMCPClientSkillAuthoringRequests = beforeRequests
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return LibraryMCPClientSkillAuthoringResult{
		Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(versionCopy), Lease: leaseCopy,
	}, nil
}

// ListLibraryMCPClientAuthoredSkillsWithAuthoringLease is metadata-only
// discovery for the same lease boundary as updates. It exists so a later
// Claude/Codex turn can get the exact latest version pair needed for a safe
// compare-and-swap update without exposing assigned, bound, or other-client
// skills.
func (s *FileStore) ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(_ context.Context, endpointClient MCPClient) ([]LibraryMCPClientSkillAuthoringSkill, LibraryMCPClientSkillAuthoringLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, found := s.mcpClientByIDLocked(endpointClient.ID)
	if !found || client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject || client.Subject == "" {
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	now := time.Now().UTC()
	lease := s.libraryMCPClientSkillAuthoringLeaseLocked(client.ID)
	if lease == nil || lease.MCPClientEpoch != client.Epoch ||
		libraryMCPClientSkillAuthoringLeaseStatus(*lease, *client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	items := make([]LibraryMCPClientSkillAuthoringSkill, 0)
	for _, skill := range s.librarySkills {
		if skill == nil || skill.CreatedBy != client.Subject || s.librarySkillHasBindingsLocked(skill.ID) || !s.libraryMCPClientCreatedSkillLocked(client.ID, skill.ID) {
			continue
		}
		latest := s.latestLibrarySkillVersionLocked(skill.ID)
		if latest == nil {
			continue
		}
		items = append(items, LibraryMCPClientSkillAuthoringSkill{
			SkillID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
			LatestVersionID: latest.ID, LatestVersion: latest.Version, LatestVersionDigest: latest.Digest,
			UpdatedAt: skill.UpdatedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].SkillID > items[j].SkillID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return items, leaseCopy, nil
}
