package engine

import (
	"context"
	"time"
)

// libraryControlArtifactProjectionColumns selects only the control metadata:
// the artifact identity and its surface key, the head version's metadata, the
// access class, and the pinned grant version's metadata. Version bodies,
// provenance, and actor references are never read for a list.
const libraryControlArtifactProjectionColumns = `a.id,a.title,a.summary,a.origin,a.agent_surface_id,a.created_at,` +
	`latest.id,latest.version_number,latest.format,latest.digest,latest.size_bytes,latest.redaction_status,latest.created_at,` +
	`selected.access,` +
	`COALESCE(granted.id,''),COALESCE(granted.version_number,0),COALESCE(granted.format,''),COALESCE(granted.digest,''),COALESCE(granted.size_bytes,0),COALESCE(granted.redaction_status,''),granted.created_at`

// LibraryControlArtifactPage is the PostgreSQL twin of the FileStore
// projection: ownership comes from the queryable agent_surface_id column and
// delegation from live grants whose pinned version still carries the recorded
// digest. Direct ownership wins over a grant; the highest pinned version wins
// among grants. The page is keyset-ordered by the head version's creation time.
func (s *PgStore) LibraryControlArtifactPage(ctx context.Context, scope LibraryControlArtifactScope, cursor LibraryControlArtifactCursor, limit int) (LibraryControlArtifactPage, error) {
	scope, err := normalizeLibraryControlArtifactScope(scope)
	if err != nil {
		return LibraryControlArtifactPage{}, err
	}
	if err := validateLibraryControlArtifactCursor(cursor); err != nil {
		return LibraryControlArtifactPage{}, err
	}
	limit, err = normalizeLibraryControlArtifactPageLimit(limit)
	if err != nil {
		return LibraryControlArtifactPage{}, err
	}
	var afterUpdatedAt *time.Time
	if !cursor.UpdatedAt.IsZero() {
		ts := cursor.UpdatedAt.UTC()
		afterUpdatedAt = &ts
	}
	surfaceIDs := scope.AgentSurfaceIDs
	if surfaceIDs == nil {
		surfaceIDs = []string{}
	}

	rows, err := s.pool.Query(ctx, `
WITH candidates AS (
    SELECT a.id AS artifact_id,
           CASE WHEN $1::boolean THEN ''::TEXT ELSE 'owned'::TEXT END AS access,
           ''::TEXT AS granted_version_id,
           0 AS granted_version_number
    FROM narthex_library_artifacts a
    WHERE $1::boolean OR (a.agent_surface_id <> '' AND a.agent_surface_id = ANY($2::text[]))
    UNION ALL
    SELECT g.artifact_id, 'granted'::TEXT, v.id, v.version_number
    FROM narthex_library_artifact_grants g
    JOIN narthex_library_artifact_versions v ON v.artifact_id=g.artifact_id AND v.id=g.artifact_version_id AND v.digest=g.artifact_version_digest
    WHERE NOT $1::boolean AND g.revoked_at IS NULL AND g.agent_surface_id = ANY($2::text[])
), selected AS (
    SELECT DISTINCT ON (artifact_id) artifact_id, access, granted_version_id
    FROM candidates
    ORDER BY artifact_id, CASE access WHEN 'granted' THEN 1 ELSE 0 END, granted_version_number DESC
)
SELECT `+libraryControlArtifactProjectionColumns+`
FROM selected
JOIN narthex_library_artifacts a ON a.id=selected.artifact_id
JOIN LATERAL (
    SELECT id,version_number,format,digest,size_bytes,redaction_status,created_at
    FROM narthex_library_artifact_versions
    WHERE artifact_id=a.id
    ORDER BY version_number DESC
    LIMIT 1
) latest ON TRUE
LEFT JOIN narthex_library_artifact_versions granted ON granted.artifact_id=a.id AND granted.id=selected.granted_version_id
WHERE ($3::timestamptz IS NULL OR latest.created_at < $3 OR (latest.created_at = $3 AND a.id < $4))
ORDER BY latest.created_at DESC, a.id DESC
LIMIT $5`, scope.Everything, surfaceIDs, afterUpdatedAt, cursor.ID, limit+1)
	if err != nil {
		return LibraryControlArtifactPage{}, err
	}
	defer rows.Close()
	items := make([]LibraryControlArtifact, 0, limit+1)
	for rows.Next() {
		item, err := s.scanLibraryControlArtifact(rows)
		if err != nil {
			return LibraryControlArtifactPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return LibraryControlArtifactPage{}, err
	}
	return finishLibraryControlArtifactPage(items, limit), nil
}

func (s *PgStore) scanLibraryControlArtifact(row libraryRowScanner) (LibraryControlArtifact, error) {
	var item LibraryControlArtifact
	var title, summary string
	var granted LibraryArtifactVersion
	var grantedCreatedAt *time.Time
	if err := row.Scan(
		&item.Artifact.ID, &title, &summary, &item.Artifact.Origin, &item.Artifact.AgentSurfaceID, &item.Artifact.CreatedAt,
		&item.LatestVersion.ID, &item.LatestVersion.Version, &item.LatestVersion.Format, &item.LatestVersion.Digest, &item.LatestVersion.SizeBytes, &item.LatestVersion.RedactionStatus, &item.LatestVersion.CreatedAt,
		&item.Access,
		&granted.ID, &granted.Version, &granted.Format, &granted.Digest, &granted.SizeBytes, &granted.RedactionStatus, &grantedCreatedAt,
	); err != nil {
		return LibraryControlArtifact{}, err
	}
	var err error
	if item.Artifact.Title, err = s.decryptLibraryText("artifact", item.Artifact.ID, "title", title); err != nil {
		return LibraryControlArtifact{}, err
	}
	if item.Artifact.Summary, err = s.decryptLibraryText("artifact", item.Artifact.ID, "summary", summary); err != nil {
		return LibraryControlArtifact{}, err
	}
	item.LatestVersion.ArtifactID = item.Artifact.ID
	item.UpdatedAt = item.LatestVersion.CreatedAt
	if item.Access == LibraryControlArtifactAccessGranted && granted.ID != "" {
		granted.ArtifactID = item.Artifact.ID
		if grantedCreatedAt != nil {
			granted.CreatedAt = *grantedCreatedAt
		}
		item.GrantedVersion = &granted
	}
	return item, nil
}
