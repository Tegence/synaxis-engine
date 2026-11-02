package engine

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
)

var _ LibraryChatArtifactStore = (*PgStore)(nil)

// All mutations lock the client before its artifact, matching version writes.
func (s *PgStore) libraryChatSourceTx(ctx context.Context, tx pgx.Tx, ref LibraryChatReplyReference, active, body bool) (LibraryArtifact, LibraryArtifactVersion, MCPClient, error) {
	client, err := loadMCPClientForUpdate(ctx, tx, ref.AgentSurfaceID)
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, libraryChatSourceError(err)
	}
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR UPDATE`, ref.ArtifactID))
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, libraryChatSourceError(err)
	}
	var version LibraryArtifactVersion
	if body {
		version, err = s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, ref.ArtifactID, ref.ArtifactVersionID))
	} else {
		err = tx.QueryRow(ctx, `SELECT id,artifact_id,format,digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, ref.ArtifactID, ref.ArtifactVersionID).Scan(&version.ID, &version.ArtifactID, &version.Format, &version.Digest)
	}
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, libraryChatSourceError(err)
	}
	if (active && client.Status != MCPClientStatusActive) || !libraryChatSourceMatches(artifact, version, client, ref) {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, ErrLibraryArtifactNotFound
	}
	run, err := s.scanLibraryRun(tx.QueryRow(ctx, `SELECT `+libraryRunColumns+` FROM narthex_library_runs WHERE id=$1 FOR KEY SHARE`, artifact.RunID))
	if err != nil {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, libraryChatSourceError(err)
	}
	if run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != client.Subject || run.SurfaceRef != client.ID {
		return LibraryArtifact{}, LibraryArtifactVersion{}, MCPClient{}, ErrLibraryArtifactNotFound
	}
	return artifact, version, client, nil
}
func libraryChatSourceError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrMCPClientNotFound) {
		return ErrLibraryArtifactNotFound
	}
	return err
}

func (s *PgStore) ClassifyLibraryChatReplies(ctx context.Context, refs []LibraryChatReplyReference) (int, error) {
	if err := validateLibraryChatClassification(refs); err != nil {
		return 0, err
	}
	refs = append([]LibraryChatReplyReference(nil), refs...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].AgentSurfaceID != refs[j].AgentSurfaceID {
			return refs[i].AgentSurfaceID < refs[j].AgentSurfaceID
		}
		return refs[i].ArtifactID < refs[j].ArtifactID
	})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	changed := 0
	for _, ref := range refs {
		// Missing historical content is already absent from the catalog. Never
		// mistake an existing but differently owned record for a missing one.
		var artifactExists, versionExists, matching bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_library_artifacts WHERE id=$1),EXISTS(SELECT 1 FROM narthex_library_artifact_versions WHERE id=$2),EXISTS(SELECT 1 FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2)`, ref.ArtifactID, ref.ArtifactVersionID).Scan(&artifactExists, &versionExists, &matching); err != nil {
			return 0, err
		}
		if !artifactExists || !versionExists {
			continue
		}
		if !matching {
			return 0, ErrLibraryArtifactNotFound
		}
		artifact, _, _, err := s.libraryChatSourceTx(ctx, tx, ref, false, false)
		if err != nil {
			return 0, err
		}
		if artifact.ContentKind != "" {
			continue
		}
		result, err := tx.Exec(ctx, `UPDATE narthex_library_artifacts SET content_kind='chat_reply' WHERE id=$1 AND content_kind=''`, artifact.ID)
		if err != nil {
			return 0, err
		}
		changed += int(result.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return changed, nil
}
func (s *PgStore) SaveLibraryChatReply(ctx context.Context, request LibraryChatSaveRequest) (LibraryChatSaveResult, error) {
	if err := validateLibraryChatSave(request); err != nil {
		return LibraryChatSaveResult{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryChatSaveResult{}, err
	}
	defer tx.Rollback(ctx)
	source, sourceVersion, client, err := s.libraryChatSourceTx(ctx, tx, request.LibraryChatReplyReference, true, true)
	if err != nil {
		return LibraryChatSaveResult{}, err
	}
	if source.ContentKind != LibraryContentChatReply {
		return LibraryChatSaveResult{}, ErrLibraryArtifactNotFound
	}
	var artifactID, versionID string
	err = tx.QueryRow(ctx, `SELECT artifact_id,artifact_version_id FROM narthex_library_chat_saves WHERE source_artifact_id=$1 AND source_version_id=$2`, source.ID, sourceVersion.ID).Scan(&artifactID, &versionID)
	if err == nil {
		artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1`, artifactID))
		if err != nil {
			return LibraryChatSaveResult{}, err
		}
		version, err := s.scanLibraryArtifactVersion(tx.QueryRow(ctx, `SELECT `+libraryArtifactVersionColumns+` FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2`, artifactID, versionID))
		if err != nil {
			return LibraryChatSaveResult{}, err
		}
		if artifact.ContentKind == LibraryContentChatReply || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject {
			return LibraryChatSaveResult{}, ErrLibraryArtifactNotFound
		}
		if err := tx.Commit(ctx); err != nil {
			return LibraryChatSaveResult{}, err
		}
		return LibraryChatSaveResult{Artifact: libraryChatCard(artifact, version), Replayed: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return LibraryChatSaveResult{}, err
	}
	run, artifact, version, err := prepareLibraryChatCopy(client, source, sourceVersion, request.Title)
	if err != nil {
		return LibraryChatSaveResult{}, err
	}
	if err := s.insertLibraryRunArtifactWithInitialVersionTx(ctx, tx, run, artifact, version); err != nil {
		return LibraryChatSaveResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO narthex_library_chat_saves(source_artifact_id,source_version_id,artifact_id,artifact_version_id) VALUES($1,$2,$3,$4)`, source.ID, sourceVersion.ID, artifact.ID, version.ID); err != nil {
		return LibraryChatSaveResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LibraryChatSaveResult{}, err
	}
	return LibraryChatSaveResult{Artifact: libraryChatCard(artifact, version)}, nil
}
func (s *PgStore) libraryChatLinkTx(ctx context.Context, tx pgx.Tx, ref LibraryChatArtifactRef, client MCPClient) (LibraryChatArtifactCard, bool, error) {
	artifact, err := s.scanLibraryArtifact(tx.QueryRow(ctx, `SELECT `+libraryArtifactColumns+` FROM narthex_library_artifacts WHERE id=$1 FOR KEY SHARE`, ref.ArtifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryChatArtifactCard{}, false, nil
	}
	if err != nil {
		return LibraryChatArtifactCard{}, false, err
	}
	var version LibraryArtifactVersion
	err = tx.QueryRow(ctx, `SELECT id,artifact_id,format,digest FROM narthex_library_artifact_versions WHERE artifact_id=$1 AND id=$2 FOR KEY SHARE`, ref.ArtifactID, ref.ArtifactVersionID).Scan(&version.ID, &version.ArtifactID, &version.Format, &version.Digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryChatArtifactCard{}, false, nil
	}
	if err != nil {
		return LibraryChatArtifactCard{}, false, err
	}
	if artifact.ContentKind == LibraryContentChatReply || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject || version.Digest != ref.Digest {
		return LibraryChatArtifactCard{}, false, nil
	}
	return libraryChatCard(artifact, version), true, nil
}
func (s *PgStore) validateLibraryChatLinksTx(ctx context.Context, tx pgx.Tx, artifact LibraryArtifact, client MCPClient) error {
	for _, ref := range artifact.LinkedArtifacts {
		_, ok, err := s.libraryChatLinkTx(ctx, tx, ref, client)
		if err != nil {
			return err
		}
		if !ok {
			return ErrLibraryArtifactNotFound
		}
	}
	return nil
}
func (s *PgStore) LibraryChatArtifactCards(ctx context.Context, artifactID, versionID string, surfaces []string) ([]LibraryChatArtifactCard, *LibraryChatArtifactCard, error) {
	cards := []LibraryChatArtifactCard{}
	source, found := s.LibraryArtifact(ctx, artifactID)
	if !found || source.ContentKind != LibraryContentChatReply || !containsSurface(surfaces, source.AgentSurfaceID) {
		return cards, nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return cards, nil, err
	}
	defer tx.Rollback(ctx)
	source, _, client, err := s.libraryChatSourceTx(ctx, tx, LibraryChatReplyReference{ArtifactID: artifactID, ArtifactVersionID: versionID, AgentSurfaceID: source.AgentSurfaceID, Subject: source.CreatedBy}, true, false)
	if err != nil {
		return cards, nil, err
	}
	for _, ref := range source.LinkedArtifacts {
		card, ok, err := s.libraryChatLinkTx(ctx, tx, ref, client)
		if err != nil {
			return cards, nil, err
		}
		if ok {
			cards = append(cards, card)
		}
	}
	var saved *LibraryChatArtifactCard
	var savedArtifactID, savedVersionID, digest string
	err = tx.QueryRow(ctx, `SELECT save.artifact_id,save.artifact_version_id,v.digest FROM narthex_library_chat_saves save JOIN narthex_library_artifact_versions v ON v.artifact_id=save.artifact_id AND v.id=save.artifact_version_id WHERE save.source_artifact_id=$1 AND save.source_version_id=$2`, artifactID, versionID).Scan(&savedArtifactID, &savedVersionID, &digest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return cards, nil, err
	}
	if err == nil {
		card, ok, err := s.libraryChatLinkTx(ctx, tx, LibraryChatArtifactRef{ArtifactID: savedArtifactID, ArtifactVersionID: savedVersionID, Digest: digest}, client)
		if err != nil {
			return cards, nil, err
		}
		if ok {
			saved = &card
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return cards, nil, err
	}
	return cards, saved, nil
}
