package engine

import "context"

var _ LibraryChatArtifactStore = (*FileStore)(nil)

func (s *FileStore) libraryChatSourceLocked(ref LibraryChatReplyReference, active bool) (*LibraryArtifact, *LibraryArtifactVersion, *MCPClient, error) {
	client, found := s.mcpClientByIDLocked(ref.AgentSurfaceID)
	artifact := s.libraryArtifactLocked(ref.ArtifactID)
	version := s.libraryArtifactVersionLocked(ref.ArtifactID, ref.ArtifactVersionID)
	if !found || artifact == nil || version == nil || (active && client.Status != MCPClientStatusActive) || !libraryChatSourceMatches(*artifact, *version, *client, ref) {
		return nil, nil, nil, ErrLibraryArtifactNotFound
	}
	run := s.libraryRunLocked(artifact.RunID)
	if run == nil || run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != client.Subject || run.SurfaceRef != client.ID {
		return nil, nil, nil, ErrLibraryArtifactNotFound
	}
	return artifact, version, client, nil
}
func (s *FileStore) ClassifyLibraryChatReplies(_ context.Context, refs []LibraryChatReplyReference) (int, error) {
	if err := validateLibraryChatClassification(refs); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := []*LibraryArtifact{}
	seen := map[string]bool{}
	for _, ref := range refs {
		if s.libraryArtifactLocked(ref.ArtifactID) == nil {
			continue
		}
		if s.libraryArtifactVersionLocked(ref.ArtifactID, ref.ArtifactVersionID) == nil {
			for _, version := range s.libraryArtifactVersions {
				if version != nil && version.ID == ref.ArtifactVersionID {
					return 0, ErrLibraryArtifactNotFound
				}
			}
			continue
		}
		artifact, _, _, err := s.libraryChatSourceLocked(ref, false)
		if err != nil {
			return 0, err
		}
		if artifact.ContentKind == "" && !seen[artifact.ID] {
			changed = append(changed, artifact)
			seen[artifact.ID] = true
		}
	}
	for _, artifact := range changed {
		artifact.ContentKind = LibraryContentChatReply
	}
	if len(changed) > 0 {
		if err := s.saveLocked(); err != nil {
			for _, artifact := range changed {
				artifact.ContentKind = ""
			}
			return 0, err
		}
	}
	return len(changed), nil
}
func (s *FileStore) SaveLibraryChatReply(_ context.Context, request LibraryChatSaveRequest) (LibraryChatSaveResult, error) {
	if err := validateLibraryChatSave(request); err != nil {
		return LibraryChatSaveResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	source, sourceVersion, client, err := s.libraryChatSourceLocked(request.LibraryChatReplyReference, true)
	if err != nil {
		return LibraryChatSaveResult{}, err
	}
	if source.ContentKind != LibraryContentChatReply {
		return LibraryChatSaveResult{}, ErrLibraryArtifactNotFound
	}
	for _, record := range s.libraryChatSaves {
		if record == nil || record.SourceArtifactID != source.ID || record.SourceVersionID != sourceVersion.ID {
			continue
		}
		artifact := s.libraryArtifactLocked(record.ArtifactID)
		version := s.libraryArtifactVersionLocked(record.ArtifactID, record.ArtifactVersionID)
		if artifact == nil || version == nil || artifact.ContentKind == LibraryContentChatReply || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject {
			return LibraryChatSaveResult{}, ErrLibraryArtifactNotFound
		}
		return LibraryChatSaveResult{Artifact: libraryChatCard(*artifact, *version), Replayed: true}, nil
	}
	run, artifact, version, err := prepareLibraryChatCopy(*client, *source, *sourceVersion, request.Title)
	if err != nil {
		return LibraryChatSaveResult{}, err
	}
	record := libraryChatSaveRecord{SourceArtifactID: source.ID, SourceVersionID: sourceVersion.ID, ArtifactID: artifact.ID, ArtifactVersionID: version.ID}
	s.libraryRuns = append(s.libraryRuns, &run)
	s.libraryArtifacts = append(s.libraryArtifacts, &artifact)
	s.libraryArtifactVersions = append(s.libraryArtifactVersions, &version)
	s.libraryChatSaves = append(s.libraryChatSaves, &record)
	if err := s.saveLocked(); err != nil {
		s.libraryRuns = s.libraryRuns[:len(s.libraryRuns)-1]
		s.libraryArtifacts = s.libraryArtifacts[:len(s.libraryArtifacts)-1]
		s.libraryArtifactVersions = s.libraryArtifactVersions[:len(s.libraryArtifactVersions)-1]
		s.libraryChatSaves = s.libraryChatSaves[:len(s.libraryChatSaves)-1]
		return LibraryChatSaveResult{}, err
	}
	return LibraryChatSaveResult{Artifact: libraryChatCard(artifact, version)}, nil
}
func (s *FileStore) libraryChatLinkLocked(ref LibraryChatArtifactRef, client MCPClient) (LibraryChatArtifactCard, bool) {
	artifact := s.libraryArtifactLocked(ref.ArtifactID)
	version := s.libraryArtifactVersionLocked(ref.ArtifactID, ref.ArtifactVersionID)
	if artifact == nil || version == nil || artifact.ContentKind == LibraryContentChatReply || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject || version.Digest != ref.Digest {
		return LibraryChatArtifactCard{}, false
	}
	return libraryChatCard(*artifact, *version), true
}
func (s *FileStore) validateLibraryChatLinksLocked(artifact LibraryArtifact, client MCPClient) error {
	for _, ref := range artifact.LinkedArtifacts {
		if _, ok := s.libraryChatLinkLocked(ref, client); !ok {
			return ErrLibraryArtifactNotFound
		}
	}
	return nil
}
func (s *FileStore) LibraryChatArtifactCards(_ context.Context, artifactID, versionID string, surfaces []string) ([]LibraryChatArtifactCard, *LibraryChatArtifactCard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cards := []LibraryChatArtifactCard{}
	source := s.libraryArtifactLocked(artifactID)
	if source == nil || source.ContentKind != LibraryContentChatReply || !containsSurface(surfaces, source.AgentSurfaceID) {
		return cards, nil, nil
	}
	_, _, client, err := s.libraryChatSourceLocked(LibraryChatReplyReference{ArtifactID: artifactID, ArtifactVersionID: versionID, AgentSurfaceID: source.AgentSurfaceID, Subject: source.CreatedBy}, true)
	if err != nil {
		return cards, nil, nil
	}
	for _, ref := range source.LinkedArtifacts {
		if card, ok := s.libraryChatLinkLocked(ref, *client); ok {
			cards = append(cards, card)
		}
	}
	for _, record := range s.libraryChatSaves {
		if record == nil || record.SourceArtifactID != artifactID || record.SourceVersionID != versionID {
			continue
		}
		artifact := s.libraryArtifactLocked(record.ArtifactID)
		version := s.libraryArtifactVersionLocked(record.ArtifactID, record.ArtifactVersionID)
		if artifact == nil || version == nil || artifact.ContentKind == LibraryContentChatReply || artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject {
			continue
		}
		card := libraryChatCard(*artifact, *version)
		return cards, &card, nil
	}
	return cards, nil, nil
}
