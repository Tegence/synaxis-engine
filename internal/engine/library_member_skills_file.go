package engine

import (
	"context"
	"time"
)

var _ LibraryMemberSkillStore = (*FileStore)(nil)

func (s *FileStore) MemberLibrarySkills(_ context.Context, r LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error) {
	if err := validateMemberSkillRequest(r); err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Operation == "shares" || r.Operation == "share" || r.Operation == "revoke-share" {
		return s.memberSkillSharingLocked(r)
	}
	if r.Operation != "list" && r.Operation != "get" && r.Operation != "create" {
		skill := s.librarySkillLocked(r.SkillID)
		if skill == nil || (!memberOwnsSkill(*skill, r.Subject) && ((r.Operation != "bind" && r.Operation != "unbind") || memberSkillGrant(s.skillGrantsLocked(), r) == nil)) {
			return LibraryMemberSkillResponse{}, ErrLibrarySkillNotFound
		}
	}
	switch r.Operation {
	case "create":
		skill, version := memberSkillNew(r)
		created, _, err := s.createLibrarySkillWithInitialVersionLocked(skill, version, nil)
		if err != nil {
			return LibraryMemberSkillResponse{}, err
		}
		r.SkillID = created.ID
	case "version":
		head := s.latestLibrarySkillVersionLocked(r.SkillID)
		if head == nil || head.ID != r.BaseVersionID {
			return LibraryMemberSkillResponse{}, ErrLibraryMemberSkillConflict
		}
		if _, err := s.createLibrarySkillVersionLocked(memberSkillVersion(r), memberSkillBundle(r)); err != nil {
			return LibraryMemberSkillResponse{}, err
		}
	case "bind", "unbind":
		client, found := s.mcpClientByIDLocked(r.AgentSurfaceID)
		if !found || !memberSkillClientAllowed(*client, r) {
			return LibraryMemberSkillResponse{}, ErrLibraryMemberSkillAccess
		}
		var existing *LibrarySkillBinding
		for _, b := range s.librarySkillBindings {
			if b != nil && b.SkillID == r.SkillID && b.ScopeKind == LibraryScopeAgentSurface && b.ScopeID == r.AgentSurfaceID {
				existing = b
				break
			}
		}
		if existing != nil && existing.CreatedBy != r.Subject {
			return LibraryMemberSkillResponse{}, ErrLibraryMemberSkillAccess
		}
		if r.Operation == "bind" {
			binding := memberSkillBinding(r)
			if skill := s.librarySkillLocked(r.SkillID); skill != nil && !memberOwnsSkill(*skill, r.Subject) {
				g := memberSkillGrant(s.skillGrantsLocked(), r)
				if g == nil || !skillGrantAllows(*g, r.SkillID, r.VersionID, client.Subject, time.Now().UTC()) {
					return LibraryMemberSkillResponse{}, ErrLibraryMemberSkillAccess
				}
				binding.SharedGrantID = g.ID
			}
			if _, err := s.upsertLibrarySkillBindingLocked(binding); err != nil {
				return LibraryMemberSkillResponse{}, err
			}
		} else {
			if existing == nil || existing.ID != r.BindingID {
				return LibraryMemberSkillResponse{}, ErrLibraryBindingNotFound
			}
			if err := s.deleteLibrarySkillBindingLocked(r.SkillID, r.BindingID); err != nil {
				return LibraryMemberSkillResponse{}, err
			}
		}
	}
	skills := []LibrarySkill{}
	versions := []LibrarySkillVersion{}
	bindings := []LibrarySkillBinding{}
	clients := []MCPClient{}
	for _, v := range s.librarySkills {
		if v != nil {
			skills = append(skills, *v)
		}
	}
	for _, v := range s.librarySkillVersions {
		if v != nil {
			versions = append(versions, *v)
		}
	}
	for _, v := range s.librarySkillBindings {
		if v != nil {
			bindings = append(bindings, *v)
		}
	}
	for _, v := range s.mcpClients {
		if v != nil {
			clients = append(clients, *v)
		}
	}
	return memberSkillProjection(r, skills, versions, bindings, clients, s.skillGrantsLocked())
}
