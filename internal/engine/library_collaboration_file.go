package engine

import (
	"context"
	"encoding/json"
	"time"
)

var _ LibraryCollaborationStore = (*FileStore)(nil)

func (s *FileStore) Collaborate(_ context.Context, actor LibraryCollaborationActor, req LibraryCollaborationRequest) (LibraryCollaborationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero LibraryCollaborationResult
	if actor.Kind != "admin" && (req.Operation == "grant" || req.Operation == "grants" || req.Operation == "revoke") {
		return zero, ErrCollaborationForbidden
	}
	if actor.Kind == "client" {
		client, ok := s.mcpClientByIDLocked(actor.Ref)
		if !ok || !collaborationClientValid(*client, actor) {
			return zero, ErrCollaborationUnavailable
		}
	}
	var epoch string
	if req.Operation == "grant" && req.Kind == "client" {
		client, ok := s.mcpClientByIDLocked(req.Recipient)
		if !ok || client.Status != MCPClientStatusActive || client.Subject == "" || client.Epoch == "" {
			return zero, ErrCollaborationInvalid
		}
		epoch = client.Epoch
	}
	artifact := s.libraryArtifactLocked(req.ArtifactID)
	if artifact == nil {
		return zero, ErrCollaborationUnavailable
	}
	state := cloneCollaborationState(s.libraryCollaborations[artifact.ID])
	if _, _, _, allowed := collaborationAccess(state, actor, time.Now().UTC()); !allowed {
		return zero, ErrCollaborationUnavailable
	}
	var versions []LibraryArtifactVersion
	head := s.latestLibraryArtifactVersionLocked(artifact.ID)
	if head != nil {
		versions = append(versions, copyLibraryArtifactVersion(*head))
	}
	for _, id := range collaborationVersionIDs(state, actor, req) {
		if head != nil && id == head.ID {
			continue
		}
		if v := s.libraryArtifactVersionLocked(artifact.ID, id); v != nil {
			versions = append(versions, copyLibraryArtifactVersion(*v))
		}
	}

	result, version, changed, err := applyCollaboration(&state, *artifact, versions, actor, req, time.Now().UTC())
	if err != nil || !changed {
		return result, err
	}
	if epoch != "" {
		state.Grants[len(state.Grants)-1].ClientEpoch = epoch
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return zero, err
	}
	if len(encoded) > 1<<20 && req.Operation != "revoke" {
		return zero, ErrCollaborationCapacity
	}
	if s.libraryCollaborations == nil {
		s.libraryCollaborations = make(map[string]*libraryCollaborationState)
	}
	before := s.libraryCollaborations[artifact.ID]
	beforeVersions := len(s.libraryArtifactVersions)
	storedState := cloneCollaborationState(&state)
	s.libraryCollaborations[artifact.ID] = &storedState
	if version != nil {
		storedVersion := copyLibraryArtifactVersion(*version)
		s.libraryArtifactVersions = append(s.libraryArtifactVersions, &storedVersion)
	}
	if err := s.saveLocked(); err != nil {
		s.libraryCollaborations[artifact.ID] = before
		s.libraryArtifactVersions = s.libraryArtifactVersions[:beforeVersions]
		return zero, err
	}
	return result, nil
}

func (s *FileStore) CollaborationArtifacts(_ context.Context, actor LibraryCollaborationActor) ([]LibraryCollaborationSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if actor.Kind != "subject" && actor.Kind != "client" {
		return nil, ErrCollaborationForbidden
	}
	if actor.Kind == "client" {
		client, ok := s.mcpClientByIDLocked(actor.Ref)
		if !ok || !collaborationClientValid(*client, actor) {
			return nil, ErrCollaborationUnavailable
		}
	}
	out := make([]LibraryCollaborationSummary, 0)
	for _, artifact := range s.libraryArtifacts {
		state := s.libraryCollaborations[artifact.ID]
		if state == nil {
			continue
		}
		role, _, expiry, ok := collaborationAccess(*state, actor, time.Now().UTC())
		if ok {
			if expiry != nil {
				copy := *expiry
				expiry = &copy
			}
			out = append(out, LibraryCollaborationSummary{ArtifactID: artifact.ID, Title: artifact.Title, Role: role, ExpiresAt: expiry})
		}
	}
	return out, nil
}
