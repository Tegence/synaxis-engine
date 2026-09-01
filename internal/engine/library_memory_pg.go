package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const libraryMemoryColumns = `id,kind,state,trust,agent_surface_id,current_version_id,current_version_digest,created_by,created_at,updated_at,expires_at,review_after,reviewed_by,reviewed_at,superseded_by_memory_id`
const libraryMemoryVersionColumns = `id,memory_id,version_number,content,digest,source_run_id,source_artifact_id,source_artifact_version_id,source_digest,created_by,created_at`
const libraryMemoryGrantColumns = `id,memory_id,memory_version_id,memory_version_digest,agent_surface_id,created_by,created_at,revoked_by,revoked_at`

type libraryMemoryScanValues struct {
	memory                 LibraryMemory
	createdBy, reviewedBy  string
	expiresAt, reviewAfter *time.Time
	reviewedAt             *time.Time
}

func (v *libraryMemoryScanValues) destinations() []any {
	return []any{
		&v.memory.ID, &v.memory.Kind, &v.memory.State, &v.memory.Trust, &v.memory.AgentSurfaceID,
		&v.memory.CurrentVersionID, &v.memory.CurrentVersionDigest, &v.createdBy,
		&v.memory.CreatedAt, &v.memory.UpdatedAt, &v.expiresAt, &v.reviewAfter,
		&v.reviewedBy, &v.reviewedAt, &v.memory.SupersededByMemoryID,
	}
}

func (s *PgStore) decodeLibraryMemory(v libraryMemoryScanValues) (LibraryMemory, error) {
	var err error
	if v.memory.CreatedBy, err = s.decryptLibraryText("memory", v.memory.ID, "created by", v.createdBy); err != nil {
		return LibraryMemory{}, err
	}
	if v.memory.ReviewedBy, err = s.decryptLibraryText("memory", v.memory.ID, "reviewed by", v.reviewedBy); err != nil {
		return LibraryMemory{}, err
	}
	if v.expiresAt != nil {
		v.memory.ExpiresAt = v.expiresAt.UTC()
	}
	if v.reviewAfter != nil {
		v.memory.ReviewAfter = v.reviewAfter.UTC()
	}
	if v.reviewedAt != nil {
		v.memory.ReviewedAt = v.reviewedAt.UTC()
	}
	return v.memory, nil
}

type libraryMemoryVersionScanValues struct {
	version                                                                                  LibraryMemoryVersion
	content, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, createdBy string
}

func (v *libraryMemoryVersionScanValues) destinations() []any {
	return []any{
		&v.version.ID, &v.version.MemoryID, &v.version.Version, &v.content, &v.version.Digest,
		&v.sourceRunID, &v.sourceArtifactID, &v.sourceArtifactVersionID, &v.sourceDigest,
		&v.createdBy, &v.version.CreatedAt,
	}
}

func (s *PgStore) decodeLibraryMemoryVersion(v libraryMemoryVersionScanValues) (LibraryMemoryVersion, error) {
	var err error
	if v.version.Content, err = s.decryptLibraryText("memory version", v.version.ID, "content", v.content); err != nil {
		return LibraryMemoryVersion{}, err
	}
	if v.version.SourceRunID, err = s.decryptLibraryText("memory version", v.version.ID, "source run", v.sourceRunID); err != nil {
		return LibraryMemoryVersion{}, err
	}
	if v.version.SourceArtifactID, err = s.decryptLibraryText("memory version", v.version.ID, "source artifact", v.sourceArtifactID); err != nil {
		return LibraryMemoryVersion{}, err
	}
	if v.version.SourceArtifactVersionID, err = s.decryptLibraryText("memory version", v.version.ID, "source artifact version", v.sourceArtifactVersionID); err != nil {
		return LibraryMemoryVersion{}, err
	}
	if v.version.SourceDigest, err = s.decryptLibraryText("memory version", v.version.ID, "source digest", v.sourceDigest); err != nil {
		return LibraryMemoryVersion{}, err
	}
	if v.version.CreatedBy, err = s.decryptLibraryText("memory version", v.version.ID, "created by", v.createdBy); err != nil {
		return LibraryMemoryVersion{}, err
	}
	return v.version, nil
}

func (s *PgStore) scanLibraryMemory(row libraryRowScanner) (LibraryMemory, error) {
	var raw libraryMemoryScanValues
	if err := row.Scan(raw.destinations()...); err != nil {
		return LibraryMemory{}, err
	}
	return s.decodeLibraryMemory(raw)
}

func (s *PgStore) scanLibraryMemoryVersion(row libraryRowScanner) (LibraryMemoryVersion, error) {
	var raw libraryMemoryVersionScanValues
	if err := row.Scan(raw.destinations()...); err != nil {
		return LibraryMemoryVersion{}, err
	}
	return s.decodeLibraryMemoryVersion(raw)
}

func (s *PgStore) scanLibraryMemoryGrant(row libraryRowScanner) (LibraryMemoryGrant, error) {
	var grant LibraryMemoryGrant
	var createdBy, revokedBy string
	var revokedAt *time.Time
	if err := row.Scan(&grant.ID, &grant.MemoryID, &grant.MemoryVersionID, &grant.MemoryVersionDigest, &grant.AgentSurfaceID, &createdBy, &grant.CreatedAt, &revokedBy, &revokedAt); err != nil {
		return LibraryMemoryGrant{}, err
	}
	var err error
	if grant.CreatedBy, err = s.decryptLibraryText("memory grant", grant.ID, "created by", createdBy); err != nil {
		return LibraryMemoryGrant{}, err
	}
	if grant.RevokedBy, err = s.decryptLibraryText("memory grant", grant.ID, "revoked by", revokedBy); err != nil {
		return LibraryMemoryGrant{}, err
	}
	if revokedAt != nil {
		grant.RevokedAt = revokedAt.UTC()
	}
	return grant, nil
}

func (s *PgStore) LibraryConsoleMemoryPage(ctx context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleMemoryPage, error) {
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	var afterTimestamp *time.Time
	if !cursor.Timestamp.IsZero() {
		ts := cursor.Timestamp.UTC()
		afterTimestamp = &ts
	}
	rows, err := s.pool.Query(ctx, `SELECT `+prefixedLibraryMemoryColumns("m")+`,v.content
FROM narthex_library_memories m
JOIN narthex_library_memory_versions v ON v.memory_id=m.id AND v.id=m.current_version_id AND v.digest=m.current_version_digest
WHERE ($1::timestamptz IS NULL OR m.updated_at<$1 OR (m.updated_at=$1 AND m.id<$2))
ORDER BY m.updated_at DESC,m.id DESC
LIMIT $3`, afterTimestamp, cursor.ID, limit+1)
	if err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	defer rows.Close()
	type rawPageItem struct {
		memory           libraryMemoryScanValues
		encryptedContent string
	}
	rawItems := make([]rawPageItem, 0, limit+1)
	for rows.Next() {
		var item rawPageItem
		destinations := append(item.memory.destinations(), &item.encryptedContent)
		if err := rows.Scan(destinations...); err != nil {
			return LibraryConsoleMemoryPage{}, err
		}
		rawItems = append(rawItems, item)
	}
	if err := rows.Err(); err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	page := LibraryConsoleMemoryPage{Memories: make([]LibraryMemory, 0, min(len(rawItems), limit))}
	if len(rawItems) > limit {
		last := rawItems[limit-1].memory.memory
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.UpdatedAt, ID: last.ID}
		rawItems = rawItems[:limit]
	}
	for _, raw := range rawItems {
		memory, err := s.decodeLibraryMemory(raw.memory)
		if err != nil {
			return LibraryConsoleMemoryPage{}, err
		}
		content, err := s.decryptLibraryText("memory version", memory.CurrentVersionID, "content", raw.encryptedContent)
		if err != nil {
			return LibraryConsoleMemoryPage{}, err
		}
		memory.Preview = libraryMemoryPreview(content)
		page.Memories = append(page.Memories, memory)
	}
	return page, nil
}

func (s *PgStore) LibraryMemory(ctx context.Context, id string) (LibraryMemory, bool) {
	memory, err := s.scanLibraryMemory(s.pool.QueryRow(ctx, `SELECT `+libraryMemoryColumns+` FROM narthex_library_memories WHERE id=$1`, id))
	if err != nil {
		return LibraryMemory{}, false
	}
	return memory, true
}

func (s *PgStore) LibraryMemoryVersions(ctx context.Context, memoryID string) ([]LibraryMemoryVersion, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_memories WHERE id=$1)`, memoryID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrLibraryMemoryNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+libraryMemoryVersionColumns+` FROM narthex_library_memory_versions WHERE memory_id=$1 ORDER BY version_number`, memoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LibraryMemoryVersion, 0)
	for rows.Next() {
		version, err := s.scanLibraryMemoryVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, version)
	}
	return out, rows.Err()
}

func (s *PgStore) LibraryMemoryVersion(ctx context.Context, memoryID, id string) (LibraryMemoryVersion, bool) {
	version, err := s.scanLibraryMemoryVersion(s.pool.QueryRow(ctx, `SELECT `+libraryMemoryVersionColumns+` FROM narthex_library_memory_versions WHERE memory_id=$1 AND id=$2`, memoryID, id))
	if err != nil {
		return LibraryMemoryVersion{}, false
	}
	return version, true
}

func (s *PgStore) validateLibraryMemoryEvidenceTx(ctx context.Context, tx pgx.Tx, version LibraryMemoryVersion) error {
	if version.SourceRunID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_runs WHERE id=$1)`, version.SourceRunID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrLibraryRunNotFound
		}
	}
	if version.SourceArtifactID == "" {
		return nil
	}
	var digest string
	err := tx.QueryRow(ctx, `SELECT digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, version.SourceArtifactID, version.SourceArtifactVersionID).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		var artifactExists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1)`, version.SourceArtifactID).Scan(&artifactExists); lookupErr != nil {
			return lookupErr
		}
		if !artifactExists {
			return ErrLibraryArtifactNotFound
		}
		return ErrLibraryArtifactVersionNotFound
	}
	if err != nil {
		return err
	}
	if digest != version.SourceDigest {
		return ErrLibraryArtifactVersionNotFound
	}
	return nil
}

func (s *PgStore) encryptLibraryMemoryVersion(version LibraryMemoryVersion) (content, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, createdBy string, err error) {
	if content, err = s.enc(version.Content); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory content: %w", err)
	}
	if sourceRunID, err = s.enc(version.SourceRunID); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory source run: %w", err)
	}
	if sourceArtifactID, err = s.enc(version.SourceArtifactID); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory source artifact: %w", err)
	}
	if sourceArtifactVersionID, err = s.enc(version.SourceArtifactVersionID); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory source artifact version: %w", err)
	}
	if sourceDigest, err = s.enc(version.SourceDigest); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory source digest: %w", err)
	}
	if createdBy, err = s.enc(version.CreatedBy); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("encrypt library memory version creator: %w", err)
	}
	return content, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, createdBy, nil
}

func (s *PgStore) insertLibraryMemoryTx(ctx context.Context, tx pgx.Tx, memory LibraryMemory, version LibraryMemoryVersion) error {
	createdBy, err := s.enc(memory.CreatedBy)
	if err != nil {
		return fmt.Errorf("encrypt library memory creator: %w", err)
	}
	reviewedBy, err := s.enc(memory.ReviewedBy)
	if err != nil {
		return fmt.Errorf("encrypt library memory reviewer: %w", err)
	}
	content, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, versionCreatedBy, err := s.encryptLibraryMemoryVersion(version)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_memories
(id,kind,state,trust,agent_surface_id,current_version_id,current_version_digest,created_by,created_at,updated_at,expires_at,review_after,reviewed_by,reviewed_at,superseded_by_memory_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, memory.ID, memory.Kind, memory.State, memory.Trust, memory.AgentSurfaceID, memory.CurrentVersionID, memory.CurrentVersionDigest, createdBy, memory.CreatedAt, memory.UpdatedAt, nullableLibraryTime(memory.ExpiresAt), nullableLibraryTime(memory.ReviewAfter), reviewedBy, nullableLibraryTime(memory.ReviewedAt), memory.SupersededByMemoryID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO narthex_library_memory_versions
(id,memory_id,version_number,content,digest,source_run_id,source_artifact_id,source_artifact_version_id,source_digest,created_by,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, version.ID, version.MemoryID, version.Version, content, version.Digest, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, versionCreatedBy, version.CreatedAt)
	return err
}

func nullableLibraryTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func (s *PgStore) activeMemoryTargetTx(ctx context.Context, tx pgx.Tx, agentSurfaceID string) error {
	var status MCPClientStatus
	// Memory creation/grant is a durable write authorized by the client's live
	// state. FOR UPDATE linearizes it with status/epoch mutation; KEY SHARE
	// would allow a concurrent revocation to change those non-key columns.
	err := tx.QueryRow(ctx, `SELECT status FROM narthex_mcp_clients WHERE id=$1 FOR UPDATE`, agentSurfaceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrMCPClientNotFound
	}
	if err != nil {
		return err
	}
	if status != MCPClientStatusActive {
		return ErrMCPClientRevoked
	}
	return nil
}

func (s *PgStore) memoryClientTx(ctx context.Context, tx pgx.Tx, client MCPClient, forWrite bool) (MCPClient, error) {
	var stored MCPClient
	query := `SELECT id,subject,status,epoch FROM narthex_mcp_clients WHERE id=$1`
	if forWrite {
		// Subject-bound memory proposals must linearize with revocation and
		// epoch rotation before any authored content is committed.
		query += ` FOR UPDATE`
	}
	err := tx.QueryRow(ctx, query, client.ID).Scan(&stored.ID, &stored.Subject, &stored.Status, &stored.Epoch)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (stored.Subject != client.Subject || stored.Epoch != client.Epoch)) {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if err != nil {
		return MCPClient{}, err
	}
	if stored.Status != MCPClientStatusActive {
		return MCPClient{}, ErrMCPClientRevoked
	}
	return stored, nil
}

func (s *PgStore) liveMemoryClientTx(ctx context.Context, tx pgx.Tx, client MCPClient) (MCPClient, error) {
	return s.memoryClientTx(ctx, tx, client, false)
}

func (s *PgStore) liveMemoryClientForWriteTx(ctx context.Context, tx pgx.Tx, client MCPClient) (MCPClient, error) {
	return s.memoryClientTx(ctx, tx, client, true)
}

func (s *PgStore) createLibraryMemory(ctx context.Context, memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	memory, version, err := prepareLibraryMemoryInitial(memory, version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.activeMemoryTargetTx(ctx, tx, memory.AgentSurfaceID); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := s.validateLibraryMemoryEvidenceTx(ctx, tx, version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := s.insertLibraryMemoryTx(ctx, tx, memory, version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return memory, version, nil
}

func (s *PgStore) CreateLibraryMemoryWithInitialVersion(ctx context.Context, memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	return s.createLibraryMemory(ctx, memory, version)
}

func (s *PgStore) CreateLibraryMCPClientMemoryProposal(ctx context.Context, client MCPClient, memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	if memory.ID != "" || memory.AgentSurfaceID != "" || memory.State != "" || memory.Trust != "" || memory.CreatedBy != "" || memory.CurrentVersionID != "" || version.ID != "" || version.MemoryID != "" || version.Version != 0 || version.CreatedBy != "" {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("MCP memory proposal must derive identity, surface, actor, state, and trust")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	defer tx.Rollback(ctx)
	stored, err := s.liveMemoryClientForWriteTx(ctx, tx, client)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	memory.AgentSurfaceID, memory.State, memory.Trust, memory.CreatedBy = stored.ID, LibraryMemoryStateProposed, LibraryMemoryTrustAgentObserved, stored.Subject
	version.CreatedBy = stored.Subject
	memory, version, err = prepareLibraryMemoryInitial(memory, version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if version.SourceRunID != "" {
		run, runErr := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, version.SourceRunID))
		if runErr != nil || run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != stored.Subject || run.SurfaceRef != stored.ID {
			return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryEvidenceUnavailable
		}
	}
	if version.SourceArtifactID != "" {
		allowed, accessErr := s.libraryMCPClientMayUseArtifactVersionTx(ctx, tx, version.SourceArtifactID, version.SourceArtifactVersionID, version.SourceDigest, stored.ID, stored.Subject)
		if accessErr != nil {
			return LibraryMemory{}, LibraryMemoryVersion{}, accessErr
		}
		if !allowed {
			return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryEvidenceUnavailable
		}
	}
	if err := s.validateLibraryMemoryEvidenceTx(ctx, tx, version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := s.insertLibraryMemoryTx(ctx, tx, memory, version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return memory, version, nil
}

func (s *PgStore) CreateLibraryMemoryVersion(ctx context.Context, memoryID string, version LibraryMemoryVersion, createdBy string) (LibraryMemory, LibraryMemoryVersion, error) {
	if err := validateLibraryOpaqueRef("memory version creator", createdBy, false); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if version.ID != "" || (version.MemoryID != "" && version.MemoryID != memoryID) || version.Version != 0 || version.CreatedBy != "" {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("memory correction must derive immutable identity")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	defer tx.Rollback(ctx)
	memory, err := s.scanLibraryMemory(tx.QueryRow(ctx, `SELECT `+libraryMemoryColumns+` FROM narthex_library_memories WHERE id=$1 FOR UPDATE`, memoryID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryNotFound
	}
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	version.ID, version.MemoryID, version.CreatedBy = newLibraryMemoryVersionID(), memoryID, createdBy
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version_number),0)+1 FROM narthex_library_memory_versions WHERE memory_id=$1`, memoryID).Scan(&version.Version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	version, err = normalizeLibraryMemoryVersion(version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := s.validateLibraryMemoryEvidenceTx(ctx, tx, version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	content, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, encryptedCreatedBy, err := s.encryptLibraryMemoryVersion(version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_memory_versions
(id,memory_id,version_number,content,digest,source_run_id,source_artifact_id,source_artifact_version_id,source_digest,created_by,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, version.ID, version.MemoryID, version.Version, content, version.Digest, sourceRunID, sourceArtifactID, sourceArtifactVersionID, sourceDigest, encryptedCreatedBy, version.CreatedAt); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_memories SET current_version_id=$2,current_version_digest=$3,state=$4,trust=$5,reviewed_by='',reviewed_at=NULL,superseded_by_memory_id='',updated_at=$6 WHERE id=$1`, memoryID, version.ID, version.Digest, LibraryMemoryStateProposed, LibraryMemoryTrustHumanConfirmed, version.CreatedAt); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	encryptedGrantRevoker, err := s.enc(createdBy)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, fmt.Errorf("encrypt automatic memory grant revoker: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_memory_grants SET revoked_by=$2,revoked_at=$3 WHERE memory_id=$1 AND revoked_at IS NULL`, memoryID, encryptedGrantRevoker, version.CreatedAt); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	memory.CurrentVersionID, memory.CurrentVersionDigest = version.ID, version.Digest
	memory.State, memory.Trust = LibraryMemoryStateProposed, LibraryMemoryTrustHumanConfirmed
	memory.ReviewedBy, memory.ReviewedAt, memory.SupersededByMemoryID = "", time.Time{}, ""
	memory.UpdatedAt = version.CreatedAt
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return memory, version, nil
}

func (s *PgStore) ReviewLibraryMemory(ctx context.Context, memoryID string, review LibraryMemoryReview) (LibraryMemory, error) {
	if err := validateLibraryOpaqueRef("memory reviewer", review.ReviewedBy, false); err != nil {
		return LibraryMemory{}, err
	}
	state, trust := strings.ToLower(strings.TrimSpace(review.State)), strings.ToLower(strings.TrimSpace(review.Trust))
	if !validLibraryMemoryAdministrativeReview(state, trust) {
		return LibraryMemory{}, errors.New("invalid memory review state or trust")
	}
	if state == LibraryMemoryStateSuperseded && (review.SupersededByMemoryID == "" || review.SupersededByMemoryID == memoryID) {
		return LibraryMemory{}, ErrLibraryMemorySupersessionIneligible
	}
	if review.ReviewedAt.IsZero() {
		review.ReviewedAt = time.Now().UTC()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemory{}, err
	}
	defer tx.Rollback(ctx)
	lockIDs := []string{memoryID}
	if state == LibraryMemoryStateSuperseded {
		lockIDs = append(lockIDs, review.SupersededByMemoryID)
	}
	sort.Strings(lockIDs)
	locked := make(map[string]LibraryMemory, len(lockIDs))
	for _, id := range lockIDs {
		item, lockErr := s.scanLibraryMemory(tx.QueryRow(ctx, `SELECT `+libraryMemoryColumns+` FROM narthex_library_memories WHERE id=$1 FOR UPDATE`, id))
		if errors.Is(lockErr, pgx.ErrNoRows) {
			if id == memoryID {
				return LibraryMemory{}, ErrLibraryMemoryNotFound
			}
			return LibraryMemory{}, ErrLibraryMemorySupersessionIneligible
		}
		if lockErr != nil {
			return LibraryMemory{}, lockErr
		}
		locked[id] = item
	}
	memory := locked[memoryID]
	if memory.CurrentVersionID != review.MemoryVersionID {
		return LibraryMemory{}, ErrLibraryMemoryVersionConflict
	}
	var currentDigest string
	if err := tx.QueryRow(ctx, `SELECT digest FROM narthex_library_memory_versions WHERE memory_id=$1 AND id=$2 FOR KEY SHARE`, memoryID, review.MemoryVersionID).Scan(&currentDigest); err != nil || currentDigest != memory.CurrentVersionDigest {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return LibraryMemory{}, err
		}
		return LibraryMemory{}, ErrLibraryMemoryVersionConflict
	}
	if state == LibraryMemoryStateSuperseded {
		replacement := locked[review.SupersededByMemoryID]
		if !libraryMemoryIsRecallable(replacement, time.Now().UTC()) {
			return LibraryMemory{}, ErrLibraryMemorySupersessionIneligible
		}
	}
	memory.State, memory.Trust = state, trust
	if review.ExpiresAt != nil {
		memory.ExpiresAt = review.ExpiresAt.UTC()
	}
	if review.ReviewAfter != nil {
		memory.ReviewAfter = review.ReviewAfter.UTC()
	}
	memory.SupersededByMemoryID, memory.ReviewedBy = review.SupersededByMemoryID, review.ReviewedBy
	memory.ReviewedAt, memory.UpdatedAt = review.ReviewedAt.UTC(), review.ReviewedAt.UTC()
	if err := validateLibraryMemory(memory); err != nil {
		return LibraryMemory{}, err
	}
	encryptedReviewedBy, err := s.enc(review.ReviewedBy)
	if err != nil {
		return LibraryMemory{}, fmt.Errorf("encrypt library memory reviewer: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_memories SET state=$2,trust=$3,expires_at=$4,review_after=$5,reviewed_by=$6,reviewed_at=$7,superseded_by_memory_id=$8,updated_at=$7 WHERE id=$1`, memoryID, memory.State, memory.Trust, nullableLibraryTime(memory.ExpiresAt), nullableLibraryTime(memory.ReviewAfter), encryptedReviewedBy, memory.ReviewedAt, memory.SupersededByMemoryID); err != nil {
		return LibraryMemory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemory{}, err
	}
	return memory, nil
}

func (s *PgStore) LibraryMemoryGrants(ctx context.Context, memoryID string) ([]LibraryMemoryGrant, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_memories WHERE id=$1)`, memoryID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrLibraryMemoryNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+libraryMemoryGrantColumns+` FROM narthex_library_memory_grants WHERE memory_id=$1 ORDER BY created_at`, memoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LibraryMemoryGrant, 0)
	for rows.Next() {
		grant, err := s.scanLibraryMemoryGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

func (s *PgStore) CreateLibraryMemoryGrant(ctx context.Context, grant LibraryMemoryGrant) (LibraryMemoryGrant, error) {
	if grant.ID == "" {
		grant.ID = newLibraryMemoryGrantID()
	}
	grant, err := normalizeLibraryMemoryGrant(grant)
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	if !grant.RevokedAt.IsZero() {
		return LibraryMemoryGrant{}, errors.New("new memory grant must be live")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	defer tx.Rollback(ctx)
	memory, err := s.scanLibraryMemory(tx.QueryRow(ctx, `SELECT `+libraryMemoryColumns+` FROM narthex_library_memories WHERE id=$1 FOR KEY SHARE`, grant.MemoryID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMemoryGrant{}, ErrLibraryMemoryNotFound
	}
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	if !libraryMemoryIsRecallable(memory, time.Now().UTC()) || memory.CurrentVersionID != grant.MemoryVersionID || memory.CurrentVersionDigest != grant.MemoryVersionDigest {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantIneligible
	}
	var versionDigest string
	err = tx.QueryRow(ctx, `SELECT digest FROM narthex_library_memory_versions WHERE memory_id=$1 AND id=$2 FOR KEY SHARE`, grant.MemoryID, grant.MemoryVersionID).Scan(&versionDigest)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && versionDigest != grant.MemoryVersionDigest) {
		return LibraryMemoryGrant{}, ErrLibraryMemoryVersionNotFound
	}
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	if memory.AgentSurfaceID == grant.AgentSurfaceID {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantOwner
	}
	if err := s.activeMemoryTargetTx(ctx, tx, grant.AgentSurfaceID); err != nil {
		return LibraryMemoryGrant{}, err
	}
	createdBy, err := s.enc(grant.CreatedBy)
	if err != nil {
		return LibraryMemoryGrant{}, fmt.Errorf("encrypt library memory grant creator: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_memory_grants (id,memory_id,memory_version_id,memory_version_digest,agent_surface_id,created_by,created_at,revoked_by) VALUES ($1,$2,$3,$4,$5,$6,$7,'')`, grant.ID, grant.MemoryID, grant.MemoryVersionID, grant.MemoryVersionDigest, grant.AgentSurfaceID, createdBy, grant.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return LibraryMemoryGrant{}, ErrLibraryMemoryGrantExists
		}
		return LibraryMemoryGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemoryGrant{}, err
	}
	return grant, nil
}

func (s *PgStore) RevokeLibraryMemoryGrant(ctx context.Context, memoryID, grantID, revokedBy string, revokedAt time.Time) (LibraryMemoryGrant, error) {
	if err := validateLibraryOpaqueRef("memory grant revoker", revokedBy, false); err != nil {
		return LibraryMemoryGrant{}, err
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	defer tx.Rollback(ctx)
	grant, err := s.scanLibraryMemoryGrant(tx.QueryRow(ctx, `SELECT `+libraryMemoryGrantColumns+` FROM narthex_library_memory_grants WHERE memory_id=$1 AND id=$2 FOR UPDATE`, memoryID, grantID))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if lookupErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_memories WHERE id=$1)`, memoryID).Scan(&exists); lookupErr != nil {
			return LibraryMemoryGrant{}, lookupErr
		}
		if !exists {
			return LibraryMemoryGrant{}, ErrLibraryMemoryNotFound
		}
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantNotFound
	}
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	if !grant.RevokedAt.IsZero() {
		return grant, nil
	}
	encryptedRevokedBy, err := s.enc(revokedBy)
	if err != nil {
		return LibraryMemoryGrant{}, fmt.Errorf("encrypt library memory grant revoker: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_memory_grants SET revoked_by=$3,revoked_at=$4 WHERE memory_id=$1 AND id=$2`, memoryID, grantID, encryptedRevokedBy, revokedAt.UTC()); err != nil {
		return LibraryMemoryGrant{}, err
	}
	grant.RevokedBy, grant.RevokedAt = revokedBy, revokedAt.UTC()
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemoryGrant{}, err
	}
	return grant, nil
}

func (s *PgStore) scanLibraryMemorySelection(row libraryRowScanner, access string) (LibraryMemorySelection, error) {
	var memoryRaw libraryMemoryScanValues
	var versionRaw libraryMemoryVersionScanValues
	var grantID string
	destinations := append(memoryRaw.destinations(), versionRaw.destinations()...)
	destinations = append(destinations, &grantID)
	if err := row.Scan(destinations...); err != nil {
		return LibraryMemorySelection{}, err
	}
	memory, err := s.decodeLibraryMemory(memoryRaw)
	if err != nil {
		return LibraryMemorySelection{}, err
	}
	version, err := s.decodeLibraryMemoryVersion(versionRaw)
	if err != nil {
		return LibraryMemorySelection{}, err
	}
	return LibraryMemorySelection{Memory: memory, Version: version, Access: access, GrantID: grantID}, nil
}

func (s *PgStore) LibraryMemoryRecallSelections(ctx context.Context, client MCPClient, now time.Time) ([]LibraryMemorySelection, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	stored, err := s.liveMemoryClientTx(ctx, tx, client)
	if err != nil {
		return nil, err
	}
	out := make([]LibraryMemorySelection, 0)
	seen := make(map[string]struct{})
	query := func(sql, access string, args ...any) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			selection, err := s.scanLibraryMemorySelection(rows, access)
			if err != nil {
				return err
			}
			key := selection.Memory.ID + "\x00" + selection.Version.ID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, selection)
		}
		return rows.Err()
	}
	if err := query(`SELECT `+prefixedLibraryMemoryColumns("m")+`,`+prefixedLibraryMemoryVersionColumns("v")+`,''
FROM narthex_library_memories m
JOIN narthex_library_memory_versions v ON v.memory_id=m.id AND v.id=m.current_version_id AND v.digest=m.current_version_digest
WHERE m.agent_surface_id=$1 AND m.state='active' AND (m.expires_at IS NULL OR m.expires_at>$2)`, LibraryMemoryAccessOwnSurface, stored.ID, now); err != nil {
		return nil, err
	}
	if err := query(`SELECT `+prefixedLibraryMemoryColumns("m")+`,`+prefixedLibraryMemoryVersionColumns("v")+`,g.id
FROM narthex_library_memory_grants g
JOIN narthex_library_memories m ON m.id=g.memory_id
JOIN narthex_library_memory_versions v ON v.memory_id=g.memory_id AND v.id=g.memory_version_id AND v.digest=g.memory_version_digest
WHERE g.agent_surface_id=$1 AND g.revoked_at IS NULL AND m.state='active' AND (m.expires_at IS NULL OR m.expires_at>$2)`, LibraryMemoryAccessGranted, stored.ID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	sortLibraryMemorySelections(out)
	return out, nil
}

func prefixedLibraryMemoryColumns(prefix string) string {
	parts := strings.Split(libraryMemoryColumns, ",")
	for i := range parts {
		parts[i] = prefix + "." + parts[i]
	}
	return strings.Join(parts, ",")
}

func prefixedLibraryMemoryVersionColumns(prefix string) string {
	parts := strings.Split(libraryMemoryVersionColumns, ",")
	for i := range parts {
		parts[i] = prefix + "." + parts[i]
	}
	return strings.Join(parts, ",")
}

func (s *PgStore) LibraryMemoryReadSelection(ctx context.Context, client MCPClient, memoryID, versionID string, now time.Time) (LibraryMemorySelection, bool, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return LibraryMemorySelection{}, false, err
	}
	defer tx.Rollback(ctx)
	stored, err := s.liveMemoryClientTx(ctx, tx, client)
	if err != nil {
		return LibraryMemorySelection{}, false, err
	}
	row := tx.QueryRow(ctx, `SELECT `+prefixedLibraryMemoryColumns("m")+`,`+prefixedLibraryMemoryVersionColumns("v")+`,
CASE WHEN m.agent_surface_id=$3 AND m.current_version_id=v.id AND m.current_version_digest=v.digest THEN '' ELSE COALESCE(g.id,'') END
FROM narthex_library_memories m
JOIN narthex_library_memory_versions v ON v.memory_id=m.id AND v.id=$2
LEFT JOIN narthex_library_memory_grants g ON g.memory_id=m.id AND g.memory_version_id=v.id AND g.memory_version_digest=v.digest AND g.agent_surface_id=$3 AND g.revoked_at IS NULL
WHERE m.id=$1 AND m.state='active' AND (m.expires_at IS NULL OR m.expires_at>$4)
  AND ((m.agent_surface_id=$3 AND m.current_version_id=v.id AND m.current_version_digest=v.digest) OR g.id IS NOT NULL)`, memoryID, versionID, stored.ID, now)
	selection, err := s.scanLibraryMemorySelection(row, LibraryMemoryAccessGranted)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMemorySelection{}, false, nil
	}
	if err != nil {
		return LibraryMemorySelection{}, false, err
	}
	if selection.GrantID == "" {
		selection.Access = LibraryMemoryAccessOwnSurface
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryMemorySelection{}, false, err
	}
	return selection, true, nil
}

func (s *PgStore) ForgetLibraryMemory(ctx context.Context, memoryID string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var foundID string
	err = tx.QueryRow(ctx, `SELECT id FROM narthex_library_memories WHERE id=$1 FOR UPDATE`, memoryID).Scan(&foundID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLibraryMemoryNotFound
	}
	if err != nil {
		return err
	}
	// Clear incoming logical references before the target and all of its
	// authored versions/grants are cascaded away. Referrers become explicitly
	// non-recallable instead of being resurrected or left with a dangling ID.
	if _, err := tx.Exec(ctx, `UPDATE narthex_library_memories SET state='expired',superseded_by_memory_id='',updated_at=now() WHERE superseded_by_memory_id=$1`, memoryID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_memories WHERE id=$1`, memoryID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
