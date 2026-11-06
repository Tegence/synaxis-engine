package engine

import (
	"context"
	"slices"
	"time"
)

var _ LibrarySkillGrantStore = (*FileStore)(nil)

func (s *FileStore) skillGrantsLocked() []LibrarySkillGrant {
	out := []LibrarySkillGrant{}
	for _, g := range s.librarySkillGrants {
		if g != nil {
			out = append(out, copyLibrarySkillGrant(*g))
		}
	}
	return out
}
func (s *FileStore) skillClientsLocked() []MCPClient {
	out := []MCPClient{}
	for _, c := range s.mcpClients {
		if c != nil {
			out = append(out, *c)
		}
	}
	return out
}
func (s *FileStore) skillBindingGrantAllowedLocked(b LibrarySkillBinding) bool {
	return skillBindingGrantAllowed(b, s.skillGrantsLocked(), s.skillClientsLocked(), time.Now().UTC())
}

// All grant and assignment mutations share the store lock. Removing a subject
// deletes their old assignments, so joining again never revives old access.
func (s *FileStore) mutateSkillGrantsLocked(mutate func(*LibrarySkillGrant) (bool, error)) error {
	before := s.skillGrantsLocked()
	bindings := copyLibrarySkillBindings(s.librarySkillBindings)
	generations := copyLibrarySkillBindingGenerations(s.librarySkillBindingGenerations)
	changed := map[string]bool{}
	rollback := func() {
		s.librarySkillGrants = nil
		for _, v := range before {
			c := v
			s.librarySkillGrants = append(s.librarySkillGrants, &c)
		}
		s.librarySkillBindings = bindings
		s.librarySkillBindingGenerations = generations
	}
	for _, g := range s.librarySkillGrants {
		if g == nil {
			continue
		}
		updated, err := mutate(g)
		if err != nil {
			rollback()
			return err
		}
		if updated {
			g.Revision++
			changed[g.ID] = true
		}
	}
	kept := s.librarySkillBindings[:0]
	for _, b := range s.librarySkillBindings {
		if b != nil && changed[b.SharedGrantID] && !s.skillBindingGrantAllowedLocked(*b) {
			if _, err := s.bumpLibrarySkillBindingGenerationLocked(b.SkillID); err != nil {
				rollback()
				return err
			}
			continue
		}
		kept = append(kept, b)
	}
	s.librarySkillBindings = kept
	if err := s.saveLocked(); err != nil {
		rollback()
		return err
	}
	return nil
}
func (s *FileStore) LibrarySkillGrants(_ context.Context, r LibrarySkillGrantRequest) (LibrarySkillGrantResponse, error) {
	if err := validateSkillGrantRequest(r); err != nil {
		return LibrarySkillGrantResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Operation != "list" {
		found := false
		err := s.mutateSkillGrantsLocked(func(g *LibrarySkillGrant) (bool, error) {
			if r.Operation == "set-recipients" {
				if g.ID != r.GrantID {
					return false, nil
				}
				found = true
				if g.Revision != r.Revision {
					return false, ErrLibraryMemberSkillConflict
				}
				if g.RevokedAt != nil {
					return false, ErrLibrarySkillGrantNotFound
				}
				subjects, _ := normalizeGrantSubjects(r.RecipientSubjects)
				g.RecipientSubjects = skillGrantRecipients(*g, subjects)
				return true, nil
			}
			if g.RevokedAt != nil {
				return false, nil
			}
			if g.OwnerSubject == r.Subject {
				now := time.Now().UTC()
				g.RevokedAt = &now
				return true, nil
			}
			if !slices.Contains(g.ExcludedSubjects, r.Subject) {
				g.ExcludedSubjects = append(g.ExcludedSubjects, r.Subject)
				g.RecipientSubjects = slices.DeleteFunc(g.RecipientSubjects, func(v string) bool { return v == r.Subject })
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return LibrarySkillGrantResponse{}, err
		}
		if r.Operation == "set-recipients" && !found {
			return LibrarySkillGrantResponse{}, ErrLibrarySkillGrantNotFound
		}
	}
	out := LibrarySkillGrantResponse{Shares: s.skillGrantsLocked()}
	if r.GrantID != "" {
		for _, g := range out.Shares {
			if g.ID == r.GrantID {
				v := g
				out.Share = &v
				break
			}
		}
	}
	return out, nil
}
func (s *FileStore) memberSkillSharingLocked(r LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error) {
	skill := s.librarySkillLocked(r.SkillID)
	if skill == nil || !memberOwnsSkill(*skill, r.Subject) {
		return LibraryMemberSkillResponse{}, ErrLibrarySkillNotFound
	}
	out := LibraryMemberSkillResponse{Shares: []LibrarySkillGrant{}}
	switch r.Operation {
	case "share":
		if s.librarySkillVersionLocked(r.SkillID, r.VersionID) == nil {
			return out, ErrLibrarySkillVersionNotFound
		}
		g, err := newMemberSkillGrant(r)
		if err != nil {
			return out, err
		}
		s.librarySkillGrants = append(s.librarySkillGrants, &g)
		if err := s.saveLocked(); err != nil {
			s.librarySkillGrants = s.librarySkillGrants[:len(s.librarySkillGrants)-1]
			return out, err
		}
		c := copyLibrarySkillGrant(g)
		out.Share = &c
	case "revoke-share":
		found := false
		err := s.mutateSkillGrantsLocked(func(g *LibrarySkillGrant) (bool, error) {
			if g.ID != r.GrantID || g.SkillID != r.SkillID || g.OwnerSubject != r.Subject {
				return false, nil
			}
			found = true
			if g.Revision != r.Revision {
				return false, ErrLibraryMemberSkillConflict
			}
			if g.RevokedAt == nil {
				now := time.Now().UTC()
				g.RevokedAt = &now
			}
			return true, nil
		})
		if err != nil {
			return out, err
		}
		if !found {
			return out, ErrLibrarySkillGrantNotFound
		}
	}
	for _, g := range s.skillGrantsLocked() {
		if g.SkillID == r.SkillID && g.OwnerSubject == r.Subject {
			out.Shares = append(out.Shares, g)
			if g.ID == r.GrantID {
				c := g
				out.Share = &c
			}
		}
	}
	return out, nil
}
