package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ LibraryMCPClientSkillAuthoringStore = (*PgStore)(nil)
var _ LibraryMCPClientSkillAuthoringAuditStore = (*PgStore)(nil)

const libraryMCPClientSkillAuthoringLeaseColumns = `id,client_id,client_epoch,granted_by,granted_at,expires_at,remaining_creates,revoked_at,revoked_by,created_at,updated_at,kind,target_skill_id,target_version_id,target_version_digest,target_binding_id,target_binding_digest,target_binding_generation,remaining_uploads`
const libraryMCPClientSkillAuthoringAuditColumns = `id,lease_id,client_id,client_epoch,action,operation,actor_ref,request_id_hash,payload_digest,skill_id,version_id,created_at`

func (s *PgStore) scanLibraryMCPClientSkillAuthoringLease(row libraryRowScanner) (LibraryMCPClientSkillAuthoringLease, error) {
	var lease LibraryMCPClientSkillAuthoringLease
	var grantedBy, revokedBy string
	if err := row.Scan(
		&lease.ID, &lease.MCPClientID, &lease.MCPClientEpoch, &grantedBy, &lease.GrantedAt,
		&lease.ExpiresAt, &lease.RemainingCreates, &lease.RevokedAt, &revokedBy, &lease.CreatedAt, &lease.UpdatedAt,
		&lease.Kind, &lease.TargetSkillID, &lease.TargetVersionID, &lease.TargetVersionDigest, &lease.TargetBindingID, &lease.TargetBindingDigest, &lease.TargetBindingGeneration,
		&lease.RemainingUploads,
	); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	var err error
	if lease.GrantedBy, err = s.decryptLibraryText("MCP client skill authoring lease", lease.ID, "granted by", grantedBy); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if lease.RevokedBy, err = s.decryptLibraryText("MCP client skill authoring lease", lease.ID, "revoked by", revokedBy); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	return lease, nil
}

func (s *PgStore) scanLibraryMCPClientSkillAuthoringRequest(row libraryRowScanner) (libraryMCPClientSkillAuthoringRequestRecord, error) {
	var record libraryMCPClientSkillAuthoringRequestRecord
	if err := row.Scan(
		&record.MCPClientID, &record.MCPClientEpoch, &record.RequestIDHash, &record.PayloadDigest,
		&record.LeaseID, &record.SkillID, &record.VersionID, &record.BindingID,
		&record.BindingDigest, &record.BindingGeneration, &record.CreatedAt,
	); err != nil {
		return libraryMCPClientSkillAuthoringRequestRecord{}, err
	}
	return record, nil
}

func (s *PgStore) scanLibraryMCPClientSkillAuthoringAuditEvent(row libraryRowScanner) (LibraryMCPClientSkillAuthoringAuditEvent, error) {
	var event LibraryMCPClientSkillAuthoringAuditEvent
	var actorRef string
	if err := row.Scan(
		&event.ID, &event.LeaseID, &event.MCPClientID, &event.MCPClientEpoch, &event.Action, &event.Operation,
		&actorRef, &event.RequestIDHash, &event.PayloadDigest, &event.SkillID, &event.VersionID, &event.CreatedAt,
	); err != nil {
		return LibraryMCPClientSkillAuthoringAuditEvent{}, err
	}
	actor, err := s.decryptLibraryText("MCP client skill authoring audit", event.ID, "actor", actorRef)
	if err != nil {
		return LibraryMCPClientSkillAuthoringAuditEvent{}, err
	}
	event.ActorRef = actor
	return event, nil
}

func (s *PgStore) MCPClientSkillAuthoringLeaseAuditEvents(ctx context.Context, clientID string) ([]LibraryMCPClientSkillAuthoringAuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
SELECT `+libraryMCPClientSkillAuthoringAuditColumns+`
FROM narthex_library_mcp_client_skill_authoring_audit_events
WHERE client_id=$1
ORDER BY created_at ASC,id ASC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]LibraryMCPClientSkillAuthoringAuditEvent, 0)
	for rows.Next() {
		event, err := s.scanLibraryMCPClientSkillAuthoringAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *PgStore) insertLibraryMCPClientSkillAuthoringAuditTx(ctx context.Context, tx pgx.Tx, event LibraryMCPClientSkillAuthoringAuditEvent) error {
	actorRef, err := s.enc(event.ActorRef)
	if err != nil {
		return fmt.Errorf("encrypt MCP client skill authoring audit actor: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_audit_events
    (id,lease_id,client_id,client_epoch,action,operation,actor_ref,request_id_hash,payload_digest,skill_id,version_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		event.ID, event.LeaseID, event.MCPClientID, event.MCPClientEpoch, event.Action, event.Operation, actorRef,
		event.RequestIDHash, event.PayloadDigest, event.SkillID, event.VersionID, event.CreatedAt,
	); err != nil {
		return err
	}
	return nil
}

// rejectLibraryMCPClientSkillAuthoringTx preserves a durable, opaque receipt
// for a safe denied attempt before returning the same neutral/public error to
// the caller. The caller already holds the client row lock, so this receipt
// cannot be attributed to a spoofed endpoint client.
func (s *PgStore) rejectLibraryMCPClientSkillAuthoringTx(ctx context.Context, tx pgx.Tx, client MCPClient, leaseID, actorRef, operation, requestIDHash, payloadDigest string, cause error) error {
	event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, leaseID, LibraryMCPClientSkillAuthoringAuditActionRejected, operation, actorRef,
		requestIDHash, payloadDigest, "", "", time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return cause
}

func (s *PgStore) MCPClientSkillAuthoringLease(ctx context.Context, clientID string) (LibraryMCPClientSkillAuthoringLease, bool, error) {
	lease, err := s.scanLibraryMCPClientSkillAuthoringLease(s.pool.QueryRow(ctx, `
SELECT `+libraryMCPClientSkillAuthoringLeaseColumns+`
FROM narthex_library_mcp_client_skill_authoring_leases
WHERE client_id=$1
ORDER BY granted_at DESC,id DESC
LIMIT 1`, clientID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, false, nil
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, false, err
	}
	client, found := s.MCPClient(ctx, clientID)
	lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, found, time.Now().UTC())
	return lease, true, nil
}

func (s *PgStore) GrantMCPClientSkillAuthoringLease(ctx context.Context, clientID string, precondition MCPClientPrecondition, grantedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	if err := validateLibraryOpaqueRef("granted by", grantedBy, false); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, clientID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	latest, latestFound, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	latestID := ""
	if latestFound {
		latestID = latest.ID
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrMCPClientRevision)
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrLibraryMCPClientSkillAuthoringClientUnavailable)
	}
	now := time.Now().UTC()
	unrevoked, err := s.libraryMCPClientSkillAuthoringUnrevokedLeasesForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	for _, prior := range unrevoked {
		if prior.MCPClientEpoch == client.Epoch && libraryMCPClientSkillAuthoringLeaseStatus(prior, client, true, now) == LibraryMCPClientSkillAuthoringLeaseStatusActive {
			return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, prior.ID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationGrant, "", "", ErrLibraryMCPClientSkillAuthoringLeaseActive)
		}
	}
	grantedByEncrypted, err := s.enc(grantedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, fmt.Errorf("encrypt MCP client skill authoring grant actor: %w", err)
	}
	// Retire expired, exhausted, or stale-epoch history before opening the new
	// window. A still-live window was rejected above and can only be removed by
	// the explicit lease-ID-fenced revoke route.
	if _, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET revoked_at=$2,revoked_by=$3,updated_at=$2
	WHERE client_id=$1 AND revoked_at IS NULL`, client.ID, now, grantedByEncrypted); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	for _, prior := range unrevoked {
		auditClient := client
		auditClient.Epoch = prior.MCPClientEpoch
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			auditClient, prior.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationGrant,
			grantedBy, "", "", "", "", now,
		)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, event); err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
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
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_leases
	    (id,client_id,client_epoch,granted_by,granted_at,expires_at,remaining_creates,revoked_at,revoked_by,created_at,updated_at,kind,target_skill_id,target_version_id,target_version_digest,target_binding_id,target_binding_digest,target_binding_generation,remaining_uploads)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,'',$5,$5,$8,'','','','','',0,$9)`,
		lease.ID, lease.MCPClientID, lease.MCPClientEpoch, grantedByEncrypted, lease.GrantedAt, lease.ExpiresAt, lease.RemainingCreates, lease.Kind, lease.RemainingUploads,
	); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	grantEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationGrant,
		grantedBy, "", "", "", "", now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, grantEvent); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	lease.Status = LibraryMCPClientSkillAuthoringLeaseStatusActive
	return lease, nil
}

// GrantMCPClientSkillAuthoringAdoptionLease is the narrow owner/admin path
// for temporarily revising one existing skill through one registered client.
// It creates or adopts only that client's exact agent-surface track binding;
// generic and other-client bindings remain untouched and never become write
// authority on their own.
func (s *PgStore) GrantMCPClientSkillAuthoringAdoptionLease(ctx context.Context, clientID string, precondition MCPClientPrecondition, request LibraryMCPClientSkillAuthoringAdoptionRequest, grantedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	request, err := normalizeLibraryMCPClientSkillAuthoringAdoptionRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if err := validateLibraryOpaqueRef("granted by", grantedBy, false); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, clientID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	latest, latestFound, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	latestID := ""
	if latestFound {
		latestID = latest.ID
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrMCPClientRevision)
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringClientUnavailable)
	}
	if isBuiltInLibrarySkillID(request.SkillID) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryBuiltInManaged)
	}
	now := time.Now().UTC()
	unrevoked, err := s.libraryMCPClientSkillAuthoringUnrevokedLeasesForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	for _, prior := range unrevoked {
		if prior.MCPClientEpoch == client.Epoch && libraryMCPClientSkillAuthoringLeaseStatus(prior, client, true, now) == LibraryMCPClientSkillAuthoringLeaseStatusActive {
			return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, prior.ID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringLeaseActive)
		}
	}

	skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, request.SkillID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibrarySkillNotFound)
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	head, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `
SELECT `+librarySkillVersionColumns+`
FROM narthex_library_skill_versions
WHERE skill_id=$1
ORDER BY version_number DESC,id DESC
LIMIT 1
FOR UPDATE`, skill.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict)
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if head.ID != request.ExpectedVersionID || head.Digest != request.ExpectedVersionDigest {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict)
	}
	existingBinding, bindingFound, ambiguousBinding, err := s.libraryMCPClientSkillAdoptionBindingForUpdateTx(ctx, tx, skill.ID, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if ambiguousBinding || (bindingFound && !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(existingBinding, skill.ID, client.ID)) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, grantedBy, LibraryMCPClientSkillAuthoringAuditOperationAdopt, "", "", ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound)
	}
	binding := existingBinding
	if !bindingFound {
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

	grantedByEncrypted, err := s.enc(grantedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, fmt.Errorf("encrypt MCP client skill adoption grant actor: %w", err)
	}
	// End only expired/exhausted/invalid history. A live lease was rejected
	// above; its binding intentionally persists even after any later lease
	// expiry because selection and temporary write authority are separate.
	if _, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET revoked_at=$2,revoked_by=$3,updated_at=$2
WHERE client_id=$1 AND revoked_at IS NULL`, client.ID, now, grantedByEncrypted); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	for _, prior := range unrevoked {
		auditClient := client
		auditClient.Epoch = prior.MCPClientEpoch
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			auditClient, prior.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationAdopt,
			grantedBy, "", "", "", "", now,
		)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, event); err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
	}
	if !bindingFound {
		capabilities, err := libraryJSONCapabilities(binding.CapabilityCeiling)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		createdBy, err := s.enc(binding.CreatedBy)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, fmt.Errorf("encrypt MCP client skill adoption binding creator: %w", err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_bindings (id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			binding.ID, binding.SkillID, binding.ScopeKind, binding.ScopeID, binding.Mode, binding.PinnedVersionID,
			capabilities, binding.Priority, createdBy, binding.CreatedAt, binding.UpdatedAt,
		); err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
	}
	var bindingGeneration int64
	if bindingFound {
		bindingGeneration, err = s.ensureLibrarySkillBindingGenerationForUpdateTx(ctx, tx, skill.ID)
	} else {
		bindingGeneration, err = s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, skill.ID)
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
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
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_leases
	    (id,client_id,client_epoch,granted_by,granted_at,expires_at,remaining_creates,revoked_at,revoked_by,created_at,updated_at,kind,target_skill_id,target_version_id,target_version_digest,target_binding_id,target_binding_digest,target_binding_generation,remaining_uploads)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,'',$5,$5,$8,$9,$10,$11,$12,$13,$14,$15)`,
		lease.ID, lease.MCPClientID, lease.MCPClientEpoch, grantedByEncrypted, lease.GrantedAt, lease.ExpiresAt, lease.RemainingCreates,
		lease.Kind, lease.TargetSkillID, lease.TargetVersionID, lease.TargetVersionDigest, lease.TargetBindingID, lease.TargetBindingDigest, lease.TargetBindingGeneration,
		lease.RemainingUploads,
	); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionGranted, LibraryMCPClientSkillAuthoringAuditOperationAdopt,
		grantedBy, "", "", skill.ID, head.ID, now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, event); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	lease.Status = LibraryMCPClientSkillAuthoringLeaseStatusActive
	return lease, nil
}

func (s *PgStore) RevokeMCPClientSkillAuthoringLease(ctx context.Context, clientID, leaseID string, precondition MCPClientPrecondition, revokedBy string) (LibraryMCPClientSkillAuthoringLease, error) {
	if err := validateLibraryOpaqueRef("revoked by", revokedBy, false); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, clientID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	lease, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	latestID := ""
	if found {
		latestID = lease.ID
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, revokedBy, LibraryMCPClientSkillAuthoringAuditOperationRevoke, "", "", ErrMCPClientRevision)
	}
	if !found || lease.ID != leaseID {
		return LibraryMCPClientSkillAuthoringLease{}, s.rejectLibraryMCPClientSkillAuthoringTx(ctx, tx, client, latestID, revokedBy, LibraryMCPClientSkillAuthoringAuditOperationRevoke, "", "", ErrLibraryMCPClientSkillAuthoringLeaseNotFound)
	}
	if lease.RevokedAt == nil {
		now := time.Now().UTC()
		revokedByEncrypted, err := s.enc(revokedBy)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, fmt.Errorf("encrypt MCP client skill authoring revoke actor: %w", err)
		}
		if _, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET revoked_at=$2,revoked_by=$3,updated_at=$2
WHERE id=$1 AND revoked_at IS NULL`, lease.ID, now, revokedByEncrypted); err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		lease.RevokedAt = &now
		lease.RevokedBy = revokedBy
		lease.UpdatedAt = now
		event, err := newLibraryMCPClientSkillAuthoringAuditEvent(
			client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionRevoked, LibraryMCPClientSkillAuthoringAuditOperationRevoke,
			revokedBy, "", "", "", "", now,
		)
		if err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
		if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, event); err != nil {
			return LibraryMCPClientSkillAuthoringLease{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, err
	}
	lease.Status = LibraryMCPClientSkillAuthoringLeaseStatusRevoked
	return lease, nil
}

func (s *PgStore) CreateLibraryMCPClientSkillWithAuthoringLease(ctx context.Context, endpointClient MCPClient, request LibraryMCPClientSkillAuthoringRequest) (LibraryMCPClientSkillAuthoringResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientSkillAuthoringRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, endpointClient.ID)
	if err != nil {
		if errors.Is(err, ErrMCPClientNotFound) {
			return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject {
		latest, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		leaseID := ""
		if found {
			leaseID = latest.ID
		}
		actorRef := client.Subject
		if actorRef == "" {
			actorRef = client.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	actorRef := client.Subject
	if request.Slug == usingSynaxisSkillSlug {
		latest, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		leaseID := ""
		if found {
			leaseID = latest.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryBuiltInManaged,
		)
	}

	if record, found, err := s.libraryMCPClientSkillAuthoringRequestTx(ctx, tx, client.ID, client.Epoch, requestIDHash); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	} else if found {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
				ctx, tx, client, record.LeaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR SHARE`, record.SkillID))
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("read stored skill authoring skill: %w", err)
		}
		version, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2 FOR SHARE`, record.SkillID, record.VersionID))
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("read stored skill authoring version: %w", err)
		}
		lease, found, err := s.libraryMCPClientSkillAuthoringLeaseByIDTx(ctx, tx, record.LeaseID)
		if err != nil || !found {
			if err != nil {
				return LibraryMCPClientSkillAuthoringResult{}, err
			}
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring lease is unavailable")
		}
		lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, time.Now().UTC())
		if err := tx.Commit(ctx); err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, BindingID: record.BindingID, Lease: lease, Replayed: true}, nil
	}

	now := time.Now().UTC()
	latest, latestFound, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	lease, found, err := s.libraryMCPClientSkillAuthoringUnrevokedLeaseForUpdateTx(ctx, tx, client.ID, client.Epoch)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if !found || libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		leaseID := ""
		if latestFound {
			leaseID = latest.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if libraryMCPClientSkillAuthoringLeaseKind(lease) != LibraryMCPClientSkillAuthoringLeaseKindGeneric {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}

	skill := LibrarySkill{
		ID: newLibrarySkillID(), Slug: request.Slug, Name: request.Name, Description: request.Description,
		CreatedBy: client.Subject, CreatedAt: now, UpdatedAt: now,
	}
	bundle, err := s.libraryMCPClientSkillBundleTx(ctx, tx, client, skill, request.Content, request.bundle, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
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
	manifest, err := s.encryptLibrarySkillManifest(version.Files)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	binding, err := newLibraryMCPClientSkillAuthoringBinding(client, skill, request.RequestedCapabilities, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingDigest, err := libraryMCPClientSkillAuthoringBindingDigest(binding)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	name, err := s.enc(skill.Name)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill name: %w", err)
	}
	description, err := s.enc(skill.Description)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill description: %w", err)
	}
	createdBy, err := s.enc(skill.CreatedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill creator: %w", err)
	}
	content, err := s.enc(version.Content)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill content: %w", err)
	}
	versionCreatedBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill version creator: %w", err)
	}
	capabilities, err := libraryJSONCapabilities(version.RequestedCapabilities)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingCapabilities, err := libraryJSONCapabilities(binding.CapabilityCeiling)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingCreatedBy, err := s.enc(binding.CreatedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill binding creator: %w", err)
	}
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate,
		actorRef, requestIDHash, payloadDigest, skill.ID, version.ID, now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	var insertedSkillID string
	if err := tx.QueryRow(ctx, `
INSERT INTO narthex_library_skills (id,slug,name,description,created_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$6)
ON CONFLICT (slug) DO NOTHING
RETURNING id`, skill.ID, skill.Slug, name, description, createdBy, now).Scan(&insertedSkillID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
				ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationCreate,
				requestIDHash, payloadDigest, ErrLibrarySkillExists,
			)
		}
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.insertLibrarySkillBlobsTx(ctx, tx, bundle.Blobs, now); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.requireLibrarySkillBlobsTx(ctx, tx, bundle); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_versions (id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at,manifest,manifest_digest)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		version.ID, version.SkillID, version.Version, content, version.Digest, capabilities, versionCreatedBy, version.CreatedAt, manifest, version.ManifestDigest,
	); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_bindings (id,skill_id,scope_kind,scope_id,mode,pinned_version_id,capability_ceiling,priority,created_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		binding.ID, binding.SkillID, binding.ScopeKind, binding.ScopeID, binding.Mode, binding.PinnedVersionID,
		bindingCapabilities, binding.Priority, bindingCreatedBy, binding.CreatedAt, binding.UpdatedAt,
	); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingGeneration, err := s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, skill.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	updated, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET remaining_creates=remaining_creates-1,updated_at=$2
WHERE id=$1 AND client_id=$3 AND client_epoch=$4 AND revoked_at IS NULL AND remaining_creates > 0 AND expires_at > $2`,
		lease.ID, now, client.ID, client.Epoch,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if updated.RowsAffected() != 1 {
		return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_requests
    (client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,binding_id,binding_digest,binding_generation,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		client.ID, client.Epoch, requestIDHash, payloadDigest, lease.ID, skill.ID, version.ID, binding.ID, bindingDigest, bindingGeneration, now,
	); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, consumeEvent); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	lease.RemainingCreates--
	lease.UpdatedAt = now
	lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, BindingID: binding.ID, Lease: lease}, nil
}

// UpdateLibraryMCPClientSkillWithAuthoringLease appends a new immutable
// version only when the current lease belongs to the calling client/epoch and
// the target was originally created by that exact durable client and retains
// its exact automatic binding (or is a legacy no-binding skill). The client
// row and skill row locks serialize lease mutation, binding, and version
// append operations so the expected-version pair is a real compare-and-swap
// fence rather than a best-effort preflight.
func (s *PgStore) UpdateLibraryMCPClientSkillWithAuthoringLease(ctx context.Context, endpointClient MCPClient, request LibraryMCPClientSkillAuthoringUpdateRequest) (LibraryMCPClientSkillAuthoringResult, error) {
	request, payloadDigest, err := normalizeLibraryMCPClientSkillAuthoringUpdateRequest(request)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	requestIDHash := libraryMCPClientSkillAuthoringUpdateRequestIDHash(endpointClient.ID, endpointClient.Epoch, request.RequestID)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, endpointClient.ID)
	if err != nil {
		if errors.Is(err, ErrMCPClientNotFound) {
			return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject {
		latest, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		leaseID := ""
		if found {
			leaseID = latest.ID
		}
		actorRef := client.Subject
		if actorRef == "" {
			actorRef = client.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	actorRef := client.Subject
	if isBuiltInLibrarySkillID(request.SkillID) {
		latest, found, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		leaseID := ""
		if found {
			leaseID = latest.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryBuiltInManaged,
		)
	}

	if record, found, err := s.libraryMCPClientSkillAuthoringRequestTx(ctx, tx, client.ID, client.Epoch, requestIDHash); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	} else if found {
		if record.PayloadDigest != payloadDigest {
			return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
				ctx, tx, client, record.LeaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
				requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringRequestConflict,
			)
		}
		skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR SHARE`, record.SkillID))
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("read stored skill authoring skill: %w", err)
		}
		version, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=$1 AND id=$2 FOR SHARE`, record.SkillID, record.VersionID))
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("read stored skill authoring version: %w", err)
		}
		lease, found, err := s.libraryMCPClientSkillAuthoringLeaseByIDTx(ctx, tx, record.LeaseID)
		if err != nil || !found {
			if err != nil {
				return LibraryMCPClientSkillAuthoringResult{}, err
			}
			return LibraryMCPClientSkillAuthoringResult{}, errors.New("stored skill authoring lease is unavailable")
		}
		lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, time.Now().UTC())
		if err := tx.Commit(ctx); err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, BindingID: record.BindingID, Lease: lease, Replayed: true}, nil
	}

	now := time.Now().UTC()
	latestLease, latestLeaseFound, err := s.libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx, tx, client.ID)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	lease, found, err := s.libraryMCPClientSkillAuthoringUnrevokedLeaseForUpdateTx(ctx, tx, client.ID, client.Epoch)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if !found || libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		leaseID := ""
		if latestLeaseFound {
			leaseID = latestLease.ID
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, leaseID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	// An adoption lease has exactly one target. Reject a cross-skill request
	// before reading or locking a caller-nominated skill row, so this narrow
	// MCP path cannot become either a cross-skill lock primitive or an oracle.
	if libraryMCPClientSkillAuthoringLeaseKind(lease) == LibraryMCPClientSkillAuthoringLeaseKindAdoption && request.SkillID != lease.TargetSkillID {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}

	skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, request.SkillID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	bindingID := ""
	switch libraryMCPClientSkillAuthoringLeaseKind(lease) {
	case LibraryMCPClientSkillAuthoringLeaseKindGeneric:
		bindingEligible := false
		bindingID, bindingEligible, err = s.libraryMCPClientAuthoredSkillBindingEligibleForUpdateTx(ctx, tx, client.ID, skill.ID)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		if skill.CreatedBy == client.Subject && bindingEligible {
			break
		}
		// Match unknown skills, other same-subject clients, owner-managed skills,
		// and a changed/deleted/replaced automatic binding. The client cannot use
		// this write path as a Library membership or binding oracle.
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	case LibraryMCPClientSkillAuthoringLeaseKindAdoption:
		bindingMatches, err := s.libraryMCPClientSkillAuthoringAdoptionBindingMatchesForUpdateTx(ctx, tx, lease)
		if err != nil {
			return LibraryMCPClientSkillAuthoringResult{}, err
		}
		if bindingMatches {
			bindingID = lease.TargetBindingID
			break
		}
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	default:
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	currentVersion, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `
SELECT `+librarySkillVersionColumns+`
FROM narthex_library_skill_versions
WHERE skill_id=$1
ORDER BY version_number DESC,id DESC
LIMIT 1
FOR UPDATE`, skill.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if currentVersion.ID != request.ExpectedVersionID || currentVersion.Digest != request.ExpectedVersionDigest {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if libraryMCPClientSkillAuthoringLeaseKind(lease) == LibraryMCPClientSkillAuthoringLeaseKindAdoption &&
		!libraryMCPClientSkillAuthoringAdoptionCapabilitiesAllowed(currentVersion.RequestedCapabilities, request.RequestedCapabilities) {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, ErrLibraryMCPClientSkillAuthoringUnavailable,
		)
	}
	if err := requireLibrarySkillFilesDeclared(&currentVersion, request.bundle.declared); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, err,
		)
	}
	bundle, err := s.libraryMCPClientSkillBundleTx(ctx, tx, client, skill, request.Content, request.bundle, now)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, s.rejectLibraryMCPClientSkillAuthoringTx(
			ctx, tx, client, lease.ID, actorRef, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
			requestIDHash, payloadDigest, err,
		)
	}
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: currentVersion.Version + 1,
		Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
		Files: bundle.Files, ManifestDigest: bundle.ManifestDigest,
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	manifest, err := s.encryptLibrarySkillManifest(version.Files)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	content, err := s.enc(version.Content)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill update content: %w", err)
	}
	versionCreatedBy, err := s.enc(version.CreatedBy)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, fmt.Errorf("encrypt MCP client authored skill update creator: %w", err)
	}
	capabilities, err := libraryJSONCapabilities(version.RequestedCapabilities)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	consumeEvent, err := newLibraryMCPClientSkillAuthoringAuditEvent(
		client, lease.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationUpdate,
		actorRef, requestIDHash, payloadDigest, skill.ID, version.ID, now,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.insertLibrarySkillBlobsTx(ctx, tx, bundle.Blobs, now); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.requireLibrarySkillBlobsTx(ctx, tx, bundle); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_versions (id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at,manifest,manifest_digest)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		version.ID, version.SkillID, version.Version, content, version.Digest, capabilities, versionCreatedBy, version.CreatedAt, manifest, version.ManifestDigest,
	); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_skills SET updated_at=$2 WHERE id=$1`, skill.ID, now); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	updated, err := tx.Exec(ctx, `
UPDATE narthex_library_mcp_client_skill_authoring_leases
SET remaining_creates=remaining_creates-1,updated_at=$2
WHERE id=$1 AND client_id=$3 AND client_epoch=$4 AND revoked_at IS NULL AND remaining_creates > 0 AND expires_at > $2`,
		lease.ID, now, client.ID, client.Epoch,
	)
	if err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if updated.RowsAffected() != 1 {
		return LibraryMCPClientSkillAuthoringResult{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_requests
    (client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,binding_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		client.ID, client.Epoch, requestIDHash, payloadDigest, lease.ID, skill.ID, version.ID, bindingID, now,
	); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := s.insertLibraryMCPClientSkillAuthoringAuditTx(ctx, tx, consumeEvent); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	lease.RemainingCreates--
	lease.UpdatedAt = now
	lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
	skill.UpdatedAt = now
	if err := tx.Commit(ctx); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, BindingID: bindingID, Lease: lease}, nil
}

// ListLibraryMCPClientAuthoredSkillsWithAuthoringLease is the metadata-only
// discovery half of the update protocol. It uses the successful create audit
// record as the exact client-surface provenance key and intentionally omits
// version Content, bindings, grants, and every skill that has moved into an
// owner/admin-managed state.
func (s *PgStore) ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx context.Context, endpointClient MCPClient) ([]LibraryMCPClientSkillAuthoringSkill, LibraryMCPClientSkillAuthoringLease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, endpointClient.ID)
	if err != nil {
		if errors.Is(err, ErrMCPClientNotFound) {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	if client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" ||
		client.Epoch != endpointClient.Epoch || client.Subject != endpointClient.Subject || client.Subject == "" {
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	now := time.Now().UTC()
	lease, found, err := s.libraryMCPClientSkillAuthoringUnrevokedLeaseForUpdateTx(ctx, tx, client.ID, client.Epoch)
	if err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	if !found || libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now) != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	if libraryMCPClientSkillAuthoringLeaseKind(lease) == LibraryMCPClientSkillAuthoringLeaseKindAdoption {
		// Take the parent skill lock before the selected binding lock. Binding
		// mutations take the same parent lock first, which keeps list/update
		// fencing atomic without inverting the lock order.
		var targetSkillID string
		if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skills WHERE id=$1 FOR SHARE`, lease.TargetSkillID).Scan(&targetSkillID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
			}
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		bindingMatches, err := s.libraryMCPClientSkillAuthoringAdoptionBindingMatchesForUpdateTx(ctx, tx, lease)
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		if !bindingMatches {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR SHARE`, lease.TargetSkillID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		head, err := s.scanLibrarySkillVersion(tx.QueryRow(ctx, `
SELECT `+librarySkillVersionColumns+`
FROM narthex_library_skill_versions
WHERE skill_id=$1
ORDER BY version_number DESC,id DESC
LIMIT 1
FOR SHARE`, skill.ID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
		}
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		item := LibraryMCPClientSkillAuthoringSkill{
			SkillID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
			LatestVersionID: head.ID, LatestVersion: head.Version, LatestVersionDigest: head.Digest, LatestManifestDigest: head.ManifestDigest,
			UpdatedAt: skill.UpdatedAt,
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
		return []LibraryMCPClientSkillAuthoringSkill{item}, lease, nil
	}
	if libraryMCPClientSkillAuthoringLeaseKind(lease) != LibraryMCPClientSkillAuthoringLeaseKindGeneric {
		return nil, LibraryMCPClientSkillAuthoringLease{}, ErrLibraryMCPClientSkillAuthoringUnavailable
	}
	rows, err := tx.Query(ctx, `
WITH authored AS (
    SELECT DISTINCT ON (r.skill_id) r.skill_id,r.binding_id,r.binding_digest,r.binding_generation
    FROM narthex_library_mcp_client_skill_authoring_audit_events a
    JOIN narthex_library_mcp_client_skill_authoring_requests r
      ON r.client_id=a.client_id AND r.client_epoch=a.client_epoch
     AND r.skill_id=a.skill_id AND r.version_id=a.version_id
    JOIN narthex_library_skill_versions initial
      ON initial.id=r.version_id AND initial.skill_id=r.skill_id AND initial.version_number=1
    WHERE a.client_id=$1 AND a.action=$2 AND a.operation=$3
    ORDER BY r.skill_id,r.created_at ASC,r.request_id_hash ASC
)
SELECT s.id,s.slug,s.name,s.description,s.created_by,s.created_at,s.updated_at,
       latest.id,latest.version_number,latest.digest,latest.manifest_digest,latest.content,
       authored.binding_id,authored.binding_digest,authored.binding_generation
FROM narthex_library_skills s
JOIN authored ON authored.skill_id=s.id
JOIN LATERAL (
    SELECT id,version_number,digest,manifest_digest,content
    FROM narthex_library_skill_versions
    WHERE skill_id=s.id
    ORDER BY version_number DESC,id DESC
    LIMIT 1
) latest ON TRUE
ORDER BY s.updated_at DESC,s.id DESC`, client.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate)
	if err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer rows.Close()
	type authoredCandidate struct {
		item              LibraryMCPClientSkillAuthoringSkill
		bindingID         string
		bindingDigest     string
		bindingGeneration int64
	}
	candidates := make([]authoredCandidate, 0)
	for rows.Next() {
		var candidate authoredCandidate
		var name, description, createdBy, latestContent string
		var createdAt time.Time
		if err := rows.Scan(
			&candidate.item.SkillID, &candidate.item.Slug, &name, &description, &createdBy, &createdAt, &candidate.item.UpdatedAt,
			&candidate.item.LatestVersionID, &candidate.item.LatestVersion, &candidate.item.LatestVersionDigest, &candidate.item.LatestManifestDigest, &latestContent,
			&candidate.bindingID, &candidate.bindingDigest, &candidate.bindingGeneration,
		); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		var err error
		if candidate.item.LatestManifestDigest == "" {
			// A legacy head has no stored manifest; report the derived one-file
			// manifest digest so an update can fence on it like any other.
			plain, err := s.decryptLibraryText("skill version", candidate.item.LatestVersionID, "content", latestContent)
			if err != nil {
				return nil, LibraryMCPClientSkillAuthoringLease{}, err
			}
			derived, err := librarySkillVersionWithManifest(LibrarySkillVersion{ID: candidate.item.LatestVersionID, Content: plain, Digest: candidate.item.LatestVersionDigest})
			if err != nil {
				return nil, LibraryMCPClientSkillAuthoringLease{}, err
			}
			candidate.item.LatestManifestDigest = derived.ManifestDigest
		}
		if candidate.item.Name, err = s.decryptLibraryText("skill", candidate.item.SkillID, "name", name); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		if candidate.item.Description, err = s.decryptLibraryText("skill", candidate.item.SkillID, "description", description); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		createdBy, err = s.decryptLibraryText("skill", candidate.item.SkillID, "created by", createdBy)
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		// The structural audit filter enforces the exact client surface. Retain
		// the subject check as a second defense against corrupted provenance.
		if createdBy == client.Subject {
			candidates = append(candidates, candidate)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	rows.Close()
	items := make([]LibraryMCPClientSkillAuthoringSkill, 0, len(candidates))
	for _, candidate := range candidates {
		eligible, err := s.libraryMCPClientAuthoredSkillBindingEligibleForReadTx(
			ctx, tx, client.ID, candidate.item.SkillID, candidate.bindingID, candidate.bindingDigest, candidate.bindingGeneration,
		)
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		if eligible {
			items = append(items, candidate.item)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	lease.Status = libraryMCPClientSkillAuthoringLeaseStatus(lease, client, true, now)
	return items, lease, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringLatestLeaseForUpdateTx(ctx context.Context, tx pgx.Tx, clientID string) (LibraryMCPClientSkillAuthoringLease, bool, error) {
	lease, err := s.scanLibraryMCPClientSkillAuthoringLease(tx.QueryRow(ctx, `
SELECT `+libraryMCPClientSkillAuthoringLeaseColumns+`
FROM narthex_library_mcp_client_skill_authoring_leases
WHERE client_id=$1
ORDER BY granted_at DESC,id DESC
LIMIT 1
FOR UPDATE`, clientID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, false, nil
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, false, err
	}
	return lease, true, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringUnrevokedLeasesForUpdateTx(ctx context.Context, tx pgx.Tx, clientID string) ([]LibraryMCPClientSkillAuthoringLease, error) {
	rows, err := tx.Query(ctx, `
SELECT `+libraryMCPClientSkillAuthoringLeaseColumns+`
FROM narthex_library_mcp_client_skill_authoring_leases
WHERE client_id=$1 AND revoked_at IS NULL
ORDER BY granted_at ASC,id ASC
FOR UPDATE`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	leases := make([]LibraryMCPClientSkillAuthoringLease, 0, 1)
	for rows.Next() {
		lease, err := s.scanLibraryMCPClientSkillAuthoringLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return leases, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringUnrevokedLeaseForUpdateTx(ctx context.Context, tx pgx.Tx, clientID, epoch string) (LibraryMCPClientSkillAuthoringLease, bool, error) {
	lease, err := s.scanLibraryMCPClientSkillAuthoringLease(tx.QueryRow(ctx, `
SELECT `+libraryMCPClientSkillAuthoringLeaseColumns+`
FROM narthex_library_mcp_client_skill_authoring_leases
WHERE client_id=$1 AND client_epoch=$2 AND revoked_at IS NULL
ORDER BY granted_at DESC,id DESC
LIMIT 1
FOR UPDATE`, clientID, epoch))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, false, nil
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, false, err
	}
	return lease, true, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringLeaseByIDTx(ctx context.Context, tx pgx.Tx, id string) (LibraryMCPClientSkillAuthoringLease, bool, error) {
	lease, err := s.scanLibraryMCPClientSkillAuthoringLease(tx.QueryRow(ctx, `
SELECT `+libraryMCPClientSkillAuthoringLeaseColumns+`
FROM narthex_library_mcp_client_skill_authoring_leases
WHERE id=$1
FOR SHARE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMCPClientSkillAuthoringLease{}, false, nil
	}
	if err != nil {
		return LibraryMCPClientSkillAuthoringLease{}, false, err
	}
	return lease, true, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringRequestTx(ctx context.Context, tx pgx.Tx, clientID, epoch, requestIDHash string) (libraryMCPClientSkillAuthoringRequestRecord, bool, error) {
	record, err := s.scanLibraryMCPClientSkillAuthoringRequest(tx.QueryRow(ctx, `
SELECT client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,binding_id,binding_digest,binding_generation,created_at
FROM narthex_library_mcp_client_skill_authoring_requests
WHERE client_id=$1 AND client_epoch=$2 AND request_id_hash=$3
FOR SHARE`, clientID, epoch, requestIDHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return libraryMCPClientSkillAuthoringRequestRecord{}, false, nil
	}
	if err != nil {
		return libraryMCPClientSkillAuthoringRequestRecord{}, false, err
	}
	return record, true, nil
}

// libraryMCPClientCreatedSkillBindingReceiptTx verifies the durable
// initial-create receipt for this exact client before returning its automatic
// binding fingerprint. Empty binding IDs are pre-auto-binding legacy records,
// not an error; a nonempty ID without its digest and generation is deliberately
// ineligible rather than reconstructed after the fact.
func (s *PgStore) libraryMCPClientCreatedSkillBindingReceiptTx(ctx context.Context, tx pgx.Tx, clientID, skillID string) (bindingID, bindingDigest string, bindingGeneration int64, found bool, err error) {
	err = tx.QueryRow(ctx, `
SELECT r.binding_id,r.binding_digest,r.binding_generation
FROM narthex_library_mcp_client_skill_authoring_audit_events a
JOIN narthex_library_mcp_client_skill_authoring_requests r
  ON r.client_id=a.client_id AND r.client_epoch=a.client_epoch
 AND r.skill_id=a.skill_id AND r.version_id=a.version_id
JOIN narthex_library_skill_versions initial
  ON initial.id=r.version_id AND initial.skill_id=r.skill_id AND initial.version_number=1
WHERE a.client_id=$1 AND a.skill_id=$2
  AND a.action=$3 AND a.operation=$4
ORDER BY r.created_at ASC,r.request_id_hash ASC

LIMIT 1`, clientID, skillID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate).Scan(&bindingID, &bindingDigest, &bindingGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", 0, false, nil
	}
	if err != nil {
		return "", "", 0, false, err
	}
	return bindingID, bindingDigest, bindingGeneration, true, nil
}

// librarySkillBindingGenerationForShareTx reads the monotonically increasing
// binding-set marker while the caller holds a lock on the parent skill. A
// missing marker is the expected legacy state and makes a new automatic
// binding receipt ineligible, rather than silently recreating authority.
func (s *PgStore) librarySkillBindingGenerationForShareTx(ctx context.Context, tx pgx.Tx, skillID string) (int64, error) {
	var generation int64
	err := tx.QueryRow(ctx, `
SELECT generation
FROM narthex_library_skill_binding_generations
WHERE skill_id=$1
FOR SHARE`, skillID).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if generation <= 0 {
		return 0, fmt.Errorf("invalid library skill binding generation for %q", skillID)
	}
	return generation, nil
}

// libraryMCPClientAuthoredSkillBindingEligibleForUpdateTx locks the skill's
// binding set after the caller has locked the skill row. That order matches
// regular binding writes; locking rows also stops a direct delete from racing
// a leased version append. Only a legacy no-binding skill or the exact
// recorded automatic track binding remains client-authorable.
func (s *PgStore) libraryMCPClientAuthoredSkillBindingEligibleForUpdateTx(ctx context.Context, tx pgx.Tx, clientID, skillID string) (string, bool, error) {
	bindingID, bindingDigest, bindingGeneration, originated, err := s.libraryMCPClientCreatedSkillBindingReceiptTx(ctx, tx, clientID, skillID)
	if err != nil || !originated {
		return "", false, err
	}
	rows, err := tx.Query(ctx, `
SELECT `+libraryBindingColumns+`
FROM narthex_library_skill_bindings
WHERE skill_id=$1
ORDER BY id
FOR UPDATE`, skillID)
	if err != nil {
		return "", false, err
	}
	bindings := make([]LibrarySkillBinding, 0, 1)
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			return "", false, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	rows.Close()
	currentGeneration, err := s.librarySkillBindingGenerationForShareTx(ctx, tx, skillID)
	if err != nil {
		return "", false, err
	}
	return bindingID, libraryMCPClientSkillAuthoringBindingEligible(clientID, bindingID, bindingDigest, bindingGeneration, currentGeneration, bindings), nil
}

// libraryMCPClientAuthoredSkillBindingEligibleForReadTx takes compatible
// shared locks while listing authorable skill metadata. It rechecks the same
// durable receipt and binding-set generation as the write path, so a changed
// binding can never reappear in a client's discovery result merely because an
// earlier SQL projection still looked eligible.
func (s *PgStore) libraryMCPClientAuthoredSkillBindingEligibleForReadTx(ctx context.Context, tx pgx.Tx, clientID, skillID, bindingID, bindingDigest string, bindingGeneration int64) (bool, error) {
	var existingSkillID string
	if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skills WHERE id=$1 FOR SHARE`, skillID).Scan(&existingSkillID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	rows, err := tx.Query(ctx, `
SELECT `+libraryBindingColumns+`
FROM narthex_library_skill_bindings
WHERE skill_id=$1
ORDER BY id
FOR SHARE`, skillID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	bindings := make([]LibrarySkillBinding, 0, 1)
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			return false, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	rows.Close()
	// Read the marker even for a legacy no-binding receipt. A later
	// add/remove mutation restores an empty row set but leaves a nonzero
	// generation, which must permanently end the old temporary write window.
	currentGeneration, err := s.librarySkillBindingGenerationForShareTx(ctx, tx, skillID)
	if err != nil {
		return false, err
	}
	return libraryMCPClientSkillAuthoringBindingEligible(clientID, bindingID, bindingDigest, bindingGeneration, currentGeneration, bindings), nil
}

// libraryMCPClientSkillAdoptionBindingForUpdateTx locks the selected client's
// exact agent-surface row while its parent skill is already locked by the
// caller. PgStore normally enforces uniqueness on this triple; the explicit
// ambiguity result still makes a damaged/legacy table fail closed.
func (s *PgStore) libraryMCPClientSkillAdoptionBindingForUpdateTx(ctx context.Context, tx pgx.Tx, skillID, clientID string) (LibrarySkillBinding, bool, bool, error) {
	rows, err := tx.Query(ctx, `
SELECT `+libraryBindingColumns+`
FROM narthex_library_skill_bindings
WHERE skill_id=$1 AND scope_kind=$2 AND scope_id=$3
ORDER BY id
FOR UPDATE`, skillID, LibraryScopeAgentSurface, clientID)
	if err != nil {
		return LibrarySkillBinding{}, false, false, err
	}
	defer rows.Close()
	var selected LibrarySkillBinding
	found := false
	for rows.Next() {
		binding, err := s.scanLibrarySkillBinding(rows)
		if err != nil {
			return LibrarySkillBinding{}, false, false, err
		}
		if found {
			return LibrarySkillBinding{}, false, true, nil
		}
		selected = binding
		found = true
	}
	if err := rows.Err(); err != nil {
		return LibrarySkillBinding{}, false, false, err
	}
	return selected, found, false, nil
}

func (s *PgStore) libraryMCPClientSkillAuthoringAdoptionBindingMatchesForUpdateTx(ctx context.Context, tx pgx.Tx, lease LibraryMCPClientSkillAuthoringLease) (bool, error) {
	if libraryMCPClientSkillAuthoringLeaseKind(lease) != LibraryMCPClientSkillAuthoringLeaseKindAdoption ||
		!libraryMCPClientSkillAuthoringAdoptionLeaseWellFormed(lease) {
		return false, nil
	}
	binding, found, ambiguous, err := s.libraryMCPClientSkillAdoptionBindingForUpdateTx(ctx, tx, lease.TargetSkillID, lease.MCPClientID)
	if err != nil || !found || ambiguous || !libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(binding, lease.TargetSkillID, lease.MCPClientID) || binding.ID != lease.TargetBindingID {
		return false, err
	}
	digest, err := libraryMCPClientSkillAuthoringBindingDigest(binding)
	if err != nil {
		return false, err
	}
	generation, err := s.librarySkillBindingGenerationForShareTx(ctx, tx, lease.TargetSkillID)
	if err != nil {
		return false, err
	}
	return digest == lease.TargetBindingDigest && generation == lease.TargetBindingGeneration, nil
}

// libraryMCPClientSkillBundleTx is the PostgreSQL twin of the FileStore
// helper: resolve staged references inside the writing transaction, normalize
// the bundle, and enforce the front-matter agreement rule.
func (s *PgStore) libraryMCPClientSkillBundleTx(ctx context.Context, tx pgx.Tx, client MCPClient, skill LibrarySkill, content string, input librarySkillAuthoringBundleInput, now time.Time) (LibrarySkillBundle, error) {
	files := append([]LibrarySkillFileContent(nil), input.inline...)
	if len(input.refs) > 0 {
		resolved, err := s.resolveLibrarySkillBlobRefsTx(ctx, tx, client, input.refs, now)
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
