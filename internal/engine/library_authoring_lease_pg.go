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

const libraryMCPClientSkillAuthoringLeaseColumns = `id,client_id,client_epoch,granted_by,granted_at,expires_at,remaining_creates,revoked_at,revoked_by,created_at,updated_at`
const libraryMCPClientSkillAuthoringAuditColumns = `id,lease_id,client_id,client_epoch,action,operation,actor_ref,request_id_hash,payload_digest,skill_id,version_id,created_at`

func (s *PgStore) scanLibraryMCPClientSkillAuthoringLease(row libraryRowScanner) (LibraryMCPClientSkillAuthoringLease, error) {
	var lease LibraryMCPClientSkillAuthoringLease
	var grantedBy, revokedBy string
	if err := row.Scan(
		&lease.ID, &lease.MCPClientID, &lease.MCPClientEpoch, &grantedBy, &lease.GrantedAt,
		&lease.ExpiresAt, &lease.RemainingCreates, &lease.RevokedAt, &revokedBy, &lease.CreatedAt, &lease.UpdatedAt,
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
		&record.LeaseID, &record.SkillID, &record.VersionID, &record.CreatedAt,
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
		GrantedBy:        grantedBy,
		GrantedAt:        now,
		ExpiresAt:        now.Add(libraryMCPClientSkillAuthoringLeaseDuration),
		RemainingCreates: libraryMCPClientSkillAuthoringLeaseMaxCreates,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_mcp_client_skill_authoring_leases
    (id,client_id,client_epoch,granted_by,granted_at,expires_at,remaining_creates,revoked_at,revoked_by,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,'',$5,$5)`,
		lease.ID, lease.MCPClientID, lease.MCPClientEpoch, grantedByEncrypted, lease.GrantedAt, lease.ExpiresAt, lease.RemainingCreates,
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
		return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, Lease: lease, Replayed: true}, nil
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
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_versions (id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		version.ID, version.SkillID, version.Version, content, version.Digest, capabilities, versionCreatedBy, version.CreatedAt,
	); err != nil {
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
    (client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		client.ID, client.Epoch, requestIDHash, payloadDigest, lease.ID, skill.ID, version.ID, now,
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
	return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, Lease: lease}, nil
}

// UpdateLibraryMCPClientSkillWithAuthoringLease appends a new immutable
// version only when the current lease belongs to the calling client/epoch and
// the target is an unbound skill originally created by that exact durable
// client. The client row and skill row locks serialize lease mutation,
// binding, and version append operations so the expected-version pair is a
// real compare-and-swap fence rather than a best-effort preflight.
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
		return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, Lease: lease, Replayed: true}, nil
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
	var originatedByClient, hasBinding bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM narthex_library_mcp_client_skill_authoring_audit_events a
    JOIN narthex_library_mcp_client_skill_authoring_requests r
      ON r.client_id=a.client_id AND r.client_epoch=a.client_epoch
     AND r.skill_id=a.skill_id AND r.version_id=a.version_id
    JOIN narthex_library_skill_versions initial
      ON initial.id=r.version_id AND initial.skill_id=r.skill_id AND initial.version_number=1
    WHERE a.client_id=$1 AND a.skill_id=$2 AND a.action=$3 AND a.operation=$4
)`, client.ID, skill.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate).Scan(&originatedByClient); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM narthex_library_skill_bindings WHERE skill_id=$1)`, skill.ID).Scan(&hasBinding); err != nil {
		return LibraryMCPClientSkillAuthoringResult{}, err
	}
	if skill.CreatedBy != client.Subject || !originatedByClient || hasBinding {
		// Match unknown skills, other same-subject clients, owner-managed skills,
		// and bound skills. The client cannot use this write path as a Library
		// membership, origin, or binding oracle.
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
	version, err := normalizedLibraryVersion(LibrarySkillVersion{
		ID: newLibrarySkillVersionID(), SkillID: skill.ID, Version: currentVersion.Version + 1,
		Content: request.Content, RequestedCapabilities: request.RequestedCapabilities, CreatedBy: client.Subject, CreatedAt: now,
	})
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
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_library_skill_versions (id,skill_id,version_number,content,digest,requested_capabilities,created_by,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		version.ID, version.SkillID, version.Version, content, version.Digest, capabilities, versionCreatedBy, version.CreatedAt,
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
    (client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		client.ID, client.Epoch, requestIDHash, payloadDigest, lease.ID, skill.ID, version.ID, now,
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
	return LibraryMCPClientSkillAuthoringResult{Skill: skill, Version: version, Lease: lease}, nil
}

// ListLibraryMCPClientAuthoredSkillsWithAuthoringLease is the metadata-only
// discovery half of the update protocol. It uses the successful create audit
// record as the exact client-surface provenance key and intentionally omits
// version Content, bindings, grants, and every skill that has moved into an
// owner/admin-managed (bound) state.
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
	rows, err := tx.Query(ctx, `
SELECT s.id,s.slug,s.name,s.description,s.created_by,s.created_at,s.updated_at,
       latest.id,latest.version_number,latest.digest
FROM narthex_library_skills s
JOIN LATERAL (
    SELECT id,version_number,digest
    FROM narthex_library_skill_versions
    WHERE skill_id=s.id
    ORDER BY version_number DESC,id DESC
    LIMIT 1
) latest ON TRUE
WHERE EXISTS (
    SELECT 1
    FROM narthex_library_mcp_client_skill_authoring_audit_events a
    JOIN narthex_library_mcp_client_skill_authoring_requests r
      ON r.client_id=a.client_id AND r.client_epoch=a.client_epoch
     AND r.skill_id=a.skill_id AND r.version_id=a.version_id
    JOIN narthex_library_skill_versions initial
      ON initial.id=r.version_id AND initial.skill_id=r.skill_id AND initial.version_number=1
    WHERE a.client_id=$1 AND a.skill_id=s.id AND a.action=$2 AND a.operation=$3
)
  AND NOT EXISTS (
    SELECT 1 FROM narthex_library_skill_bindings b WHERE b.skill_id=s.id
)
ORDER BY s.updated_at DESC,s.id DESC`, client.ID, LibraryMCPClientSkillAuthoringAuditActionConsumed, LibraryMCPClientSkillAuthoringAuditOperationCreate)
	if err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	defer rows.Close()
	items := make([]LibraryMCPClientSkillAuthoringSkill, 0)
	for rows.Next() {
		var item LibraryMCPClientSkillAuthoringSkill
		var name, description, createdBy string
		var createdAt time.Time
		if err := rows.Scan(
			&item.SkillID, &item.Slug, &name, &description, &createdBy, &createdAt, &item.UpdatedAt,
			&item.LatestVersionID, &item.LatestVersion, &item.LatestVersionDigest,
		); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		var err error
		if item.Name, err = s.decryptLibraryText("skill", item.SkillID, "name", name); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		if item.Description, err = s.decryptLibraryText("skill", item.SkillID, "description", description); err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		createdBy, err = s.decryptLibraryText("skill", item.SkillID, "created by", createdBy)
		if err != nil {
			return nil, LibraryMCPClientSkillAuthoringLease{}, err
		}
		// The structural audit filter enforces the exact client surface. Retain
		// the subject check as a second defense against corrupted provenance.
		if createdBy == client.Subject {
			items = append(items, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, LibraryMCPClientSkillAuthoringLease{}, err
	}
	rows.Close()
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
SELECT client_id,client_epoch,request_id_hash,payload_digest,lease_id,skill_id,version_id,created_at
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
