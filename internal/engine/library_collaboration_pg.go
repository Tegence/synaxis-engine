package engine

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var _ LibraryCollaborationStore = (*PgStore)(nil)

func (s *PgStore) Collaborate(ctx context.Context, actor LibraryCollaborationActor, req LibraryCollaborationRequest) (LibraryCollaborationResult, error) {
	var zero LibraryCollaborationResult
	if actor.Kind != "admin" && (req.Operation == "grant" || req.Operation == "grants" || req.Operation == "revoke") {
		return zero, ErrCollaborationForbidden
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback(ctx)
	if actor.Kind == "client" {
		client, err := loadMCPClientForUpdate(ctx, tx, actor.Ref)
		if err != nil || !collaborationClientValid(client, actor) {
			return zero, ErrCollaborationUnavailable
		}
	}
	var epoch string
	if req.Operation == "grant" && req.Kind == "client" {
		client, err := loadMCPClientForUpdate(ctx, tx, req.Recipient)
		if err != nil || client.Status != MCPClientStatusActive || client.Subject == "" || client.Epoch == "" {
			return zero, ErrCollaborationInvalid
		}
		epoch = client.Epoch
	}
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, req.ArtifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, ErrCollaborationUnavailable
	}
	if err != nil {
		return zero, err
	}
	var state libraryCollaborationState
	var sealed string
	err = tx.QueryRow(ctx, `SELECT state FROM narthex_library_collaborations WHERE artifact_id=$1`, artifact.ID).Scan(&sealed)
	if err == nil {
		plain, e := s.dec(sealed)
		if e != nil {
			return zero, e
		}
		if e = json.Unmarshal([]byte(plain), &state); e != nil {
			return zero, e
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, err
	}
	if _, _, _, allowed := collaborationAccess(state, actor, time.Now().UTC()); !allowed {
		return zero, ErrCollaborationUnavailable
	}

	rows, err := tx.Query(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND (id=ANY($2::text[]) OR id=(SELECT id FROM narthex_library_artifact_versions WHERE artifact_id=$1 ORDER BY version_number DESC,id DESC LIMIT 1))`, artifact.ID, collaborationVersionIDs(state, actor, req))
	if err != nil {
		return zero, err
	}
	var versions []LibraryArtifactVersion
	for rows.Next() {
		v, e := s.scanLibraryArtifactVersion(rows)
		if e != nil {
			rows.Close()
			return zero, e
		}
		versions = append(versions, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return zero, rows.Err()
	}
	result, version, changed, err := applyCollaboration(&state, artifact, versions, actor, req, time.Now().UTC())
	if err != nil {
		return zero, err
	}
	if changed {
		if epoch != "" {
			state.Grants[len(state.Grants)-1].ClientEpoch = epoch
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return zero, err
		}
		if len(raw) > 1<<20 && req.Operation != "revoke" {
			return zero, ErrCollaborationCapacity
		}
		sealed, err = s.enc(string(raw))
		if err != nil {
			return zero, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO narthex_library_collaborations(artifact_id,state) VALUES($1,$2) ON CONFLICT(artifact_id) DO UPDATE SET state=EXCLUDED.state`, artifact.ID, sealed); err != nil {
			return zero, err
		}
		if result.Grant != nil && result.Grant.Recipient != "" {
			if _, err = tx.Exec(ctx, `INSERT INTO narthex_library_collaboration_principals(artifact_id,principal_hash) VALUES($1,$2) ON CONFLICT DO NOTHING`, artifact.ID, collaborationPrincipal(LibraryCollaborationActor{Kind: result.Grant.Kind, Ref: result.Grant.Recipient})); err != nil {
				return zero, err
			}
		}
		if version != nil {
			body, e := s.enc(version.Body)
			if e != nil {
				return zero, e
			}
			author, e := s.enc(version.CreatedBy)
			if e != nil {
				return zero, e
			}
			reviewer, e := s.enc("")
			if e != nil {
				return zero, e
			}
			changelog, e := s.enc(version.Changelog)
			if e != nil {
				return zero, e
			}

			if _, err = tx.Exec(ctx, `INSERT INTO narthex_library_artifact_versions(id,artifact_id,version_number,format,body,digest,size_bytes,redaction_status,created_by,reviewed_by,created_at,changelog) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, version.ID, artifact.ID, version.Version, version.Format, body, version.Digest, version.SizeBytes, version.RedactionStatus, author, reviewer, version.CreatedAt, changelog); err != nil {
				return zero, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, err
	}
	return result, nil
}

func (s *PgStore) CollaborationArtifacts(ctx context.Context, actor LibraryCollaborationActor) ([]LibraryCollaborationSummary, error) {
	if actor.Kind != "subject" && actor.Kind != "client" {
		return nil, ErrCollaborationForbidden
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if actor.Kind == "client" {
		client, e := loadMCPClientForUpdate(ctx, tx, actor.Ref)
		if e != nil || !collaborationClientValid(client, actor) {
			return nil, ErrCollaborationUnavailable
		}
	}
	rows, err := tx.Query(ctx, `SELECT a.id,a.title,c.state FROM narthex_library_collaboration_principals p JOIN narthex_library_artifacts a ON a.id=p.artifact_id JOIN narthex_library_collaborations c ON c.artifact_id=a.id WHERE p.principal_hash=$1 ORDER BY a.id`, collaborationPrincipal(actor))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LibraryCollaborationSummary, 0)
	for rows.Next() {
		var id, title, sealed string
		if err = rows.Scan(&id, &title, &sealed); err != nil {
			return nil, err
		}
		plain, e := s.dec(sealed)
		if e != nil {
			return nil, e
		}
		var state libraryCollaborationState
		if e = json.Unmarshal([]byte(plain), &state); e != nil {
			return nil, e
		}
		role, _, expiry, ok := collaborationAccess(state, actor, time.Now().UTC())
		if !ok {
			continue
		}
		title, e = s.dec(title)
		if e != nil {
			return nil, e
		}
		out = append(out, LibraryCollaborationSummary{ArtifactID: id, Title: title, Role: role, ExpiresAt: expiry})
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	rows.Close()
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
