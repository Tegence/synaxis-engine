package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

var _ LibraryMCPClientSkillAuthoringStore = (*FileStore)(nil)
var _ LibraryMCPClientSkillAuthoringAuditStore = (*FileStore)(nil)

func copyLibrarySkillBindings(in []*LibrarySkillBinding) []*LibrarySkillBinding {
	out := make([]*LibrarySkillBinding, len(in))
	for i, binding := range in {
		if binding == nil {
			continue
		}
		copy := copyLibrarySkillBinding(*binding)
		out[i] = &copy
	}
	return out
}

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

// libraryMCPClientCreatedSkillBindingLocked requires both sides of the durable
// create receipt: the scoped idempotency record points this client at version
// one and the append-only audit receipt records that exact consumed create. A
// skill's CreatedBy subject is intentionally not enough: multiple
// subject-bound clients can share it. BindingID is empty for legacy V1
// no-binding skills and otherwise identifies the exact auto-created binding.
// New records also require a structural digest and monotonic binding-set
// generation; absent values fail closed rather than silently reviving a
// pre-hardening temporary authoring window.
func (s *FileStore) libraryMCPClientCreatedSkillBindingLocked(clientID, skillID string) (string, string, int64, bool) {
	var initial *libraryMCPClientSkillAuthoringRequestRecord
	for _, record := range s.libraryMCPClientSkillAuthoringRequests {
		if record == nil || record.MCPClientID != clientID || record.SkillID != skillID {
			continue
		}
		version := s.librarySkillVersionLocked(skillID, record.VersionID)
		if version != nil && version.Version == 1 {
			initial = record
			break
		}
	}
	if initial == nil {
		return "", "", 0, false
	}
	for _, event := range s.libraryMCPClientSkillAuthoringAuditEvents {
		if event != nil && event.MCPClientID == clientID && event.MCPClientEpoch == initial.MCPClientEpoch &&
			event.SkillID == skillID && event.VersionID == initial.VersionID &&
			event.Action == LibraryMCPClientSkillAuthoringAuditActionConsumed &&
			event.Operation == LibraryMCPClientSkillAuthoringAuditOperationCreate {
			return initial.BindingID, initial.BindingDigest, initial.BindingGeneration, true
		}
	}
	return "", "", 0, false
}

// libraryMCPClientAuthoredSkillBindingEligibleLocked preserves legacy
// no-binding leased skills while allowing only the exact automatic
// client-surface binding made with a newer create. Any owner/admin binding
// change that adds, removes, replaces, or pins a binding ends the temporary
// client's version-authoring eligibility.
func (s *FileStore) libraryMCPClientAuthoredSkillBindingEligibleLocked(clientID, skillID string) (string, bool) {
	bindingID, bindingDigest, bindingGeneration, originated := s.libraryMCPClientCreatedSkillBindingLocked(clientID, skillID)
	if !originated {
		return "", false
	}
	bindings := make([]LibrarySkillBinding, 0, 1)
	for _, binding := range s.librarySkillBindings {
		if binding != nil && binding.SkillID == skillID {
			bindings = append(bindings, copyLibrarySkillBinding(*binding))
		}
	}
	return bindingID, libraryMCPClientSkillAuthoringBindingEligible(
		clientID, bindingID, bindingDigest, bindingGeneration,
		s.librarySkillBindingGenerationLocked(skillID), bindings,
	)
}

// libraryMCPClientSkillAdoptionBindingLocked returns the one selected-client
// agent-surface binding for a skill. FileStore normally preserves the same
// uniqueness invariant as PgStore, but detecting a duplicate here makes a
// manually-corrupted legacy file fail closed rather than selecting one
// arbitrary binding for temporary write authority.
func (s *FileStore) libraryMCPClientSkillAdoptionBindingLocked(skillID, clientID string) (*LibrarySkillBinding, bool) {
	var selected *LibrarySkillBinding
	for _, binding := range s.librarySkillBindings {
		if binding == nil || binding.SkillID != skillID || binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != clientID {
			continue
		}
		if selected != nil {
			return nil, true
		}
		selected = binding
	}
	return selected, false
}

func (s *FileStore) libraryMCPClientSkillAuthoringAdoptionBindingMatchesLocked(lease LibraryMCPClientSkillAuthoringLease) bool {
	if libraryMCPClientSkillAuthoringLeaseKind(lease) != LibraryMCPClientSkillAuthoringLeaseKindAdoption ||
		!libraryMCPClientSkillAuthoringAdoptionLeaseWellFormed(lease) {
		return false
	}
	binding, ambiguous := s.libraryMCPClientSkillAdoptionBindingLocked(lease.TargetSkillID, lease.MCPClientID)
	if ambiguous || binding == nil || !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(*binding, lease.TargetSkillID, lease.MCPClientID) || binding.ID != lease.TargetBindingID {
		return false
	}
	digest, err := libraryMCPClientSkillAuthoringBindingDigest(*binding)
	return err == nil && digest == lease.TargetBindingDigest &&
		s.librarySkillBindingGenerationLocked(lease.TargetSkillID) == lease.TargetBindingGeneration
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
		Kind:             LibraryMCPClientSkillAuthoringLeaseKindGeneric,
		GrantedBy:        grantedBy,
		GrantedAt:        now,
		ExpiresAt:        now.Add(libraryMCPClientSkillAuthoringLeaseDuration),
		RemainingCreates: libraryMCPClientSkillAuthoringLeaseMaxCreates,
		RemainingUploads: libraryMCPClientSkillAuthoringLeaseMaxUploads,
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

// GrantMCPClientSkillAuthoringAdoptionLease is the owner/admin control-plane
// operation for one existing skill. It atomically fences the selected head,
// creates or adopts exactly one client-surface track binding, and issues a
// short write lease that cannot create other skills. Generic or other-client
// bindings are deliberately preserved: delivery selection is separate from
// the temporary write authority represented by this lease.
func (s *FileStore) GrantMCPClientSkillAuthoringAdoptionLease(_ context.Context, clientID string, precondition MCPClientPrecondition, request LibraryMCPClientSkillAuthoringAdoptionRequest, grantedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	request, err := normalizeLibraryMCPClientSkillAuthoringAdoptionRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
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
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrMCPClientRevision)
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringClientUnavailable)
	}
	if isBuiltInLibrarySkillID(request.SkillID) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryBuiltInManaged)
	}
	if current != nil && current.MCPClientEpoch == client.Epoch &&
		libraryMCPClientSkillAuthoringLeaseStatus(*current, *client, true, time.Now().UTC()) == LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, current.ID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringLeaseActive)
	}

	skill := s.librarySkillLocked(request.SkillID)
	if skill == nil {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibrarySkillNotFound)
	}
	head := s.latestLibrarySkillVersionLocked(skill.ID)
	if head == nil || head.ID != request.ExpectedVersionID || head.Digest != request.ExpectedVersionDigest {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict)
	}
	existingBinding, ambiguousBinding := s.libraryMCPClientSkillAdoptionBindingLocked(skill.ID, client.ID)
	if ambiguousBinding || (existingBinding != nil && !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(*existingBinding, skill.ID, client.ID)) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringLocked(*client, currentLeaseID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound)
	}

	now := time.Now().UTC()
	var binding LibrarySkillBinding
	if existingBinding != nil {
		binding = copyLibrarySkillBinding(*existingBinding)
	} else {
		binding, err = normalizedLibraryBinding(LibrarySkillBinding{
			ID: newLibrarySkillBindingID(), SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface,
			ScopeID: client.ID, Mode: LibraryBindingModeTrack, CapabilityCeiling: append([]string(nil), head.RequestedCapabilities...),
			CreatedBy: grantedBy, CreatedAt: now,
		})
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
	}
	bindingDigest, err := libraryMCPClientSkillAuthoringBindingDigest(binding)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}

	beforeLeases := copyLibraryMCPClientSkillAuthoringLeases(s.libraryMCPClientSkillAuthoringLeases)
	beforeBindings := copyLibrarySkillBindings(s.librarySkillBindings)
	beforeBindingGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
	beforeAudits := copyLibraryMCPClientSkillAuthoringAuditEvents(s.libraryMCPClientSkillAuthoringAuditEvents)
	var bindingGeneration int64
	if existingBinding == nil {
		bindingGeneration, err = s.bumpLibrarySkillBindingGenerationLocked(skill.ID)
	} else {
		bindingGeneration = s.ensureLibrarySkillBindingGenerationLocked(skill.ID)
	}
	if err != nil {
		s.librarySkillBindingGenerations = beforeBindingGenerations
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	// Preserve historical leases and their receipts. A live lease was rejected
	// above; older expired/exhausted/invalid windows are retired before the new
	// exact-target adoption is issued.
	for _, prior := range s.activeLibraryMCPClientSkillAuthoringLeasesLocked(client.ID) {
		auditClient := *client
		auditClient.Epoch = prior.MCPClientEpoch
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			auditClient, prior.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationAdopt,
			grantedBy, "", "", "", "", now,
		)
		if err != nil {
			s.libraryMCPClientSkillAuthoringLeases = beforeLeases
			s.librarySkillBindings = beforeBindings
			s.librarySkillBindingGenerations = beforeBindingGenerations
			s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		s.appendLibraryMCPClientSkillAuthoringAuditLocked(event)
		revokedAt := now
		prior.RevokedAt = &revokedAt
		prior.RevokedBy = grantedBy
		prior.UpdatedAt = now
	}
	lease := LibraryMCPClientSkillAuthoringLease{
		ID: newLibraryMCPClientSkillAuthoringLeaseID(), MCPClientID: client.ID, MCPClientEpoch: client.Epoch,
		Kind: LibraryMCPClientSkillAuthoringLeaseKindAdoption, GrantedBy: grantedBy, GrantedAt: now,
		ExpiresAt: now.Add(libraryMCPClientSkillAuthoringLeaseDuration), RemainingCreates: libraryMCPClientSkillAuthoringLeaseMaxCreates,
		RemainingUploads: libraryMCPClientSkillAuthoringLeaseMaxUploads,
		TargetSkillID:    skill.ID, TargetVersionID: head.ID, TargetVersionDigest: head.Digest,
		TargetBindingID: binding.ID, TargetBindingDigest: bindingDigest, TargetBindingGeneration: bindingGeneration,
		CreatedAt: now, UpdatedAt: now,
	}
	if existingBinding == nil {
		bindingCopy := copyLibrarySkillBinding(binding)
		s.librarySkillBindings = append(s.librarySkillBindings, &bindingCopy)
	}
	s.libraryMCPClientSkillAuthoringLeases = append(s.libraryMCPClientSkillAuthoringLeases, &lease)
	event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		*client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationAdopt,
		grantedBy, "", "", skill.ID, head.ID, now,
	)
	if err != nil {
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.librarySkillBindings = beforeBindings
		s.librarySkillBindingGenerations = beforeBindingGenerations
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(event)
	if err := s.saveLocked(); err != nil {
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.librarySkillBindings = beforeBindings
		s.librarySkillBindingGenerations = beforeBindingGenerations
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
	if request.Slug == usingSynaxisSkillSlug {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryBuiltInManaged,
		)
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
			Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(*version), BindingID: record.BindingID, Lease: leaseCopy, Replayed: true,
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
	if libraryMCPClientSkillAuthoringLeaseKind(*lease) != LibraryMCPClientSkillAuthoringLeaseKindGeneric {
		// An adoption lease intentionally carries no generic-create authority.
		// Keep the MCP-facing response neutral so it cannot expose which
		// owner/admin delegation mode is currently active.
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
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
	bundle, err := s.libraryMCPClientSkillBundleLocked(*client, skill, request.Content, request.bundle, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, err,
		)
	}
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: 1, Content: request.Content,
		RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
		Files: bundle.Files, ManifestDigest: bundle.ManifestDigest,
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	binding, err := newLibraryMCPClientSkillAuthoringBinding(*client, skill, request.RequestedCapabilities, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingDigest, err := libraryMCPClientSkillAuthoringBindingDigest(binding)
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
	beforeBindingGenerations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
	bindingGeneration, err := s.bumpLibrarySkillBindingGenerationLocked(skill.ID)
	if err != nil {
		s.librarySkillBindingGenerations = beforeBindingGenerations
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	skillCopy, versionCopy, bindingCopy := copyLibrarySkill(skill), copyLibrarySkillVersion(version), copyLibrarySkillBinding(binding)
	addedBlobs := s.storeLibrarySkillBlobsLocked(bundle.Blobs, now)
	lease.RemainingCreates--
	lease.UpdatedAt = now
	s.librarySkills = append(s.librarySkills, &skillCopy)
	s.librarySkillVersions = append(s.librarySkillVersions, &versionCopy)
	s.librarySkillBindings = append(s.librarySkillBindings, &bindingCopy)
	s.libraryMCPClientSkillAuthoringRequests = append(s.libraryMCPClientSkillAuthoringRequests, &libraryMCPClientSkillAuthoringRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, SkillID: skill.ID, VersionID: version.ID, BindingID: binding.ID,
		BindingDigest: bindingDigest, BindingGeneration: bindingGeneration, CreatedAt: now,
	})
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(consumeEvent)
	if err := s.saveLocked(); err != nil {
		s.librarySkills = s.librarySkills[:len(s.librarySkills)-1]
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		s.librarySkillBindings = s.librarySkillBindings[:len(s.librarySkillBindings)-1]
		s.libraryMCPClientSkillAuthoringLeases = beforeLeases
		s.libraryMCPClientSkillAuthoringRequests = beforeRequests
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		s.librarySkillBindingGenerations = beforeBindingGenerations
		s.removeLibrarySkillBlobsLocked(addedBlobs)
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return LibraryMCPClientSkillAuthoringResult{
		Skill: copyLibrarySkill(skillCopy), Version: copyLibrarySkillVersion(versionCopy), BindingID: bindingCopy.ID, Lease: leaseCopy,
	}, nil
}

// UpdateLibraryMCPClientSkillWithAuthoringLease appends one immutable version
// for a skill created by this exact durable MCP client. The single FileStore
// lock makes lease validation, automatic-binding/ownership checks, optimistic-version
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
	if isBuiltInLibrarySkillID(request.SkillID) {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, latestLeaseID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryBuiltInManaged,
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
			Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(*version), BindingID: record.BindingID, Lease: leaseCopy, Replayed: true,
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
	if libraryMCPClientSkillAuthoringLeaseKind(*lease) == LibraryMCPClientSkillAuthoringLeaseKindAdoption && request.SkillID != lease.TargetSkillID {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	skill := s.librarySkillLocked(request.SkillID)
	if skill == nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	bindingID := ""
	switch libraryMCPClientSkillAuthoringLeaseKind(*lease) {
	case LibraryMCPClientSkillAuthoringLeaseKindGeneric:
		var bindingEligible bool
		bindingID, bindingEligible = s.libraryMCPClientAuthoredSkillBindingEligibleLocked(client.ID, request.SkillID)
		if skill.CreatedBy == client.Subject && bindingEligible {
			break
		}
		// A deliberately neutral failure covers unknown, other-client, bound, and
		// ordinary owner-authored skills so this endpoint cannot become a Library
		// membership or binding oracle.
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	case LibraryMCPClientSkillAuthoringLeaseKindAdoption:
		if s.libraryMCPClientSkillAuthoringAdoptionBindingMatchesLocked(*lease) {
			bindingID = lease.TargetBindingID
			break
		}
		// A retained agent-surface binding is a delivery selector, not broad
		// authority. Only the exact immutable binding chosen during adoption
		// may keep this one target's temporary write lease usable.
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	default:
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
	if libraryMCPClientSkillAuthoringLeaseKind(*lease) == LibraryMCPClientSkillAuthoringLeaseKindAdoption &&
		!libraryMCPClientSkillAuthoringAdoptionCapabilitiesAllowed(latestVersion.RequestedCapabilities, request.RequestedCapabilities) {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if err := requireLibrarySkillFilesDeclared(latestVersion, request.bundle.declared); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, err,
		)
	}
	bundle, err := s.libraryMCPClientSkillBundleLocked(*client, *skill, request.Content, request.bundle, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringLocked(
			*client, lease.ID, client.Subject, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, err,
		)
	}
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: latestVersion.Version + 1,
		Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
		Files: bundle.Files, ManifestDigest: bundle.ManifestDigest,
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
	addedBlobs := s.storeLibrarySkillBlobsLocked(bundle.Blobs, now)
	lease.RemainingCreates--
	lease.UpdatedAt = now
	skill.UpdatedAt = now
	s.librarySkillVersions = append(s.librarySkillVersions, &versionCopy)
	s.libraryMCPClientSkillAuthoringRequests = append(s.libraryMCPClientSkillAuthoringRequests, &libraryMCPClientSkillAuthoringRequestRecord{
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, LeaseID: lease.ID, RequestIDHash: requestIDHash,
		PayloadDigest: payloadDigest, SkillID: skill.ID, VersionID: version.ID, BindingID: bindingID, CreatedAt: now,
	})
	s.appendLibraryMCPClientSkillAuthoringAuditLocked(consumeEvent)
	if err := s.saveLocked(); err != nil {
		*lease = beforeLease
		*skill = beforeSkill
		s.librarySkillVersions = s.librarySkillVersions[:len(s.librarySkillVersions)-1]
		s.libraryMCPClientSkillAuthoringRequests = beforeRequests
		s.libraryMCPClientSkillAuthoringAuditEvents = beforeAudits
		s.removeLibrarySkillBlobsLocked(addedBlobs)
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	leaseCopy := copyLibraryMCPClientSkillAuthoringLease(*lease)
	leaseCopy.Status = libraryMCPClientSkillAuthoringLeaseStatus(leaseCopy, *client, true, now)
	return LibraryMCPClientSkillAuthoringResult{
		Skill: copyLibrarySkill(*skill), Version: copyLibrarySkillVersion(versionCopy), BindingID: bindingID, Lease: leaseCopy,
	}, nil
}

// ListLibraryMCPClientAuthoredSkillsWithAuthoringLease is metadata-only
// discovery for the same lease boundary as updates. It exists so a later
// Claude/Codex turn can get the exact latest version pair needed for a safe
// compare-and-swap update without exposing other clients' or owner/admin-
// managed skills.
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
	switch libraryMCPClientSkillAuthoringLeaseKind(*lease) {
	case LibraryMCPClientSkillAuthoringLeaseKindGeneric:
		for _, skill := range s.librarySkills {
			if skill == nil || skill.CreatedBy != client.Subject {
				continue
			}
			if _, eligible := s.libraryMCPClientAuthoredSkillBindingEligibleLocked(client.ID, skill.ID); !eligible {
				continue
			}
			latest := s.latestLibrarySkillVersionLocked(skill.ID)
			if latest == nil {
				continue
			}
			items = append(items, LibraryMCPClientSkillAuthoringSkill{
				SkillID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
				LatestVersionID: latest.ID, LatestVersion: latest.Version, LatestVersionDigest: latest.Digest,
				LatestManifestDigest: latest.ManifestDigest, UpdatedAt: skill.UpdatedAt,
			})
		}
	case LibraryMCPClientSkillAuthoringLeaseKindAdoption:
		if !s.libraryMCPClientSkillAuthoringAdoptionBindingMatchesLocked(*lease) {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		skill := s.librarySkillLocked(lease.TargetSkillID)
		latest := (*LibrarySkillVersion)(nil)
		if skill != nil {
			latest = s.latestLibrarySkillVersionLocked(skill.ID)
		}
		if skill == nil || latest == nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		items = append(items, LibraryMCPClientSkillAuthoringSkill{
			SkillID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
			LatestVersionID: latest.ID, LatestVersion: latest.Version, LatestVersionDigest: latest.Digest,
			LatestManifestDigest: latest.ManifestDigest, UpdatedAt: skill.UpdatedAt,
		})
	default:
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
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

// libraryMCPClientSkillBundleLocked resolves staged references, normalizes
// the bundle, and enforces the SKILL.md front-matter agreement rule for a
// leased write. It returns a bundle whose SKILL.md equals the request content
// so the caller can build the version without re-deriving anything.
func (s *FileStore) libraryMCPClientSkillBundleLocked(client MCPClient, skill LibrarySkill, content string, input librarySkillAuthoringBundleInput, now time.Time) (LibrarySkillBundle, error) {
	files := append([]LibrarySkillFileContent(nil), input.inline...)
	if len(input.refs) > 0 {
		resolved, err := s.resolveLibrarySkillBlobRefsLocked(client, input.refs, now)
		if err != nil {
			return LibrarySkillBundle{}, err
		}
		files = append(files, resolved...)
	}
	resolvedContent, bundle, err := normalizeLibrarySkillBundle(content, files)
	if err != nil {
		return LibrarySkillBundle{}, err
	}
	if resolvedContent != content {
		return LibrarySkillBundle{}, fmt.Errorf("%w: content and the SKILL.md file entry disagree", ErrLibrarySkillBundleInvalid)
	}
	if err := validateLibrarySkillFrontMatter(skill, content, input.authored); err != nil {
		return LibrarySkillBundle{}, err
	}
	return bundle, nil
}
