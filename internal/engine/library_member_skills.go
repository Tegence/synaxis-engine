package engine

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrLibraryMemberSkillAccess = errors.New("private skill access is not permitted")
var ErrLibraryMemberSkillConflict = errors.New("skill has changed; reload before editing")

// LibraryMemberSkillStore is a narrow hosting seam. SubjectIDs are derived by
// the trusted host from current membership and owned agents, never by clients.
type LibraryMemberSkillStore interface {
	MemberLibrarySkills(context.Context, LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error)
}
type LibraryMemberSkillRequest struct {
	GrantID           string     `json:"grantId,omitempty"`
	RecipientKind     string     `json:"recipientKind,omitempty"`
	RecipientRef      string     `json:"recipientRef,omitempty"`
	RecipientSubjects []string   `json:"recipientSubjects,omitempty"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	Revision          int64      `json:"revision,omitempty"`
	Operation         string     `json:"operation"`
	Subject           string     `json:"-"`
	SubjectIDs        []string   `json:"subjectIds"`
	SkillID           string     `json:"skillId,omitempty"`
	BaseVersionID     string     `json:"baseVersionId,omitempty"`
	VersionID         string     `json:"versionId,omitempty"`
	BindingID         string     `json:"bindingId,omitempty"`
	AgentSurfaceID    string     `json:"agentSurfaceId,omitempty"`
	Name              string     `json:"name,omitempty"`
	Description       *string    `json:"description,omitempty"`
	Instructions      string     `json:"instructions,omitempty"`
	Changelog         string     `json:"changelog,omitempty"`
}
type LibraryMemberSkillVersion struct {
	ID           string    `json:"id"`
	Version      int       `json:"version"`
	Digest       string    `json:"digest"`
	CreatedAt    time.Time `json:"createdAt"`
	Instructions string    `json:"instructions,omitempty"`
	Changelog    string    `json:"changelog,omitempty"`
}
type LibraryMemberSkillBinding struct {
	ID             string `json:"id"`
	AgentSurfaceID string `json:"agentSurfaceId"`
	VersionID      string `json:"versionId"`
	Version        int    `json:"version"`
	Managed        bool   `json:"managed"`
}
type LibraryMemberSkill struct {
	ID            string                      `json:"id"`
	Name          string                      `json:"name"`
	Description   string                      `json:"description"`
	Access        string                      `json:"access"`
	CanShare      bool                        `json:"canShare"`
	CanEdit       bool                        `json:"canEdit"`
	CanAssign     bool                        `json:"canAssign"`
	LatestVersion LibraryMemberSkillVersion   `json:"latestVersion"`
	Bindings      []LibraryMemberSkillBinding `json:"bindings"`
}
type LibraryMemberSkillResponse struct {
	Shares    []LibrarySkillGrant         `json:"shares,omitempty"`
	Share     *LibrarySkillGrant          `json:"share,omitempty"`
	Skills    []LibraryMemberSkill        `json:"skills"`
	CanCreate bool                        `json:"canCreate"`
	Skill     *LibraryMemberSkill         `json:"skill,omitempty"`
	Versions  []LibraryMemberSkillVersion `json:"versions,omitempty"`
}

func validateMemberSkillRequest(r LibraryMemberSkillRequest) error {
	if validateMCPClientSubject(r.Subject) != nil || r.Subject == platformServiceActorID || len(r.SubjectIDs) == 0 || len(r.SubjectIDs) > 100 {
		return ErrLibraryMemberSkillAccess
	}
	seen := map[string]bool{}
	for _, id := range r.SubjectIDs {
		if validateMCPClientSubject(id) != nil || seen[id] || id == platformServiceActorID {
			return ErrLibraryMemberSkillAccess
		}
		seen[id] = true
	}
	if !seen[r.Subject] {
		return ErrLibraryMemberSkillAccess
	}
	switch r.Operation {
	case "list":
	case "create":
		if strings.TrimSpace(r.Name) == "" {
			return errors.New("skill name is required")
		}
	case "get", "version", "bind", "unbind", "shares", "share", "revoke-share":
		if r.SkillID == "" {
			return errors.New("skill ID is required")
		}
	default:
		return errors.New("invalid skill operation")
	}
	if r.Operation == "revoke-share" && (r.GrantID == "" || r.Revision < 1) {
		return ErrLibraryMemberSkillAccess
	}
	if r.Operation == "version" && r.BaseVersionID == "" {
		return errors.New("base version ID is required")
	}
	if (r.Operation == "bind" || r.Operation == "unbind") && r.AgentSurfaceID == "" {
		return errors.New("agent surface is required")
	}
	if r.Operation == "bind" && r.VersionID == "" {
		return errors.New("version ID is required")
	}
	if r.Operation == "unbind" && r.BindingID == "" {
		return errors.New("binding ID is required")
	}
	if r.Description != nil {
		return validateLibrarySkillDescriptionUpdate(*r.Description)
	}
	return nil
}
func memberOwnsSkill(s LibrarySkill, subject string) bool { return s.Private && s.CreatedBy == subject }
func memberSkillClientAllowed(c MCPClient, r LibraryMemberSkillRequest) bool {
	return c.Status == MCPClientStatusActive && containsSurface(r.SubjectIDs, c.Subject)
}
func memberSkillNew(r LibraryMemberSkillRequest) (LibrarySkill, LibrarySkillVersion) {
	id := newLibrarySkillID()
	d := ""
	if r.Description != nil {
		d = *r.Description
	}
	return LibrarySkill{ID: id, Slug: "private-" + strings.ReplaceAll(strings.ToLower(id), "_", "-"), Name: strings.TrimSpace(r.Name), Description: d, Private: true, CreatedBy: r.Subject}, LibrarySkillVersion{Content: r.Instructions, CreatedBy: r.Subject}
}
func memberSkillVersion(r LibraryMemberSkillRequest) LibrarySkillVersion {
	return LibrarySkillVersion{SkillID: r.SkillID, Content: r.Instructions, Changelog: r.Changelog, CreatedBy: r.Subject}
}
func memberSkillBundle(r LibraryMemberSkillRequest) *LibrarySkillBundle {
	if r.Description == nil {
		return nil
	}
	return &LibrarySkillBundle{SkillDescription: r.Description}
}
func memberSkillBinding(r LibraryMemberSkillRequest) LibrarySkillBinding {
	return LibrarySkillBinding{SkillID: r.SkillID, ScopeKind: LibraryScopeAgentSurface, ScopeID: r.AgentSurfaceID, Mode: LibraryBindingModePin, PinnedVersionID: r.VersionID, CreatedBy: r.Subject}
}
func memberSkillVersionDTO(v LibrarySkillVersion, body bool) LibraryMemberSkillVersion {
	o := LibraryMemberSkillVersion{ID: v.ID, Version: v.Version, Digest: v.Digest, CreatedAt: v.CreatedAt}
	if body {
		o.Instructions = v.Content
		o.Changelog = v.Changelog
	}
	return o
}

// The projection consumes one storage snapshot. Assigned skills expose only
// actually bound versions, never an unassigned head or unrelated bindings.
func memberSkillProjection(r LibraryMemberSkillRequest, skills []LibrarySkill, versions []LibrarySkillVersion, bindings []LibrarySkillBinding, clients []MCPClient, grants []LibrarySkillGrant) (LibraryMemberSkillResponse, error) {
	out := LibraryMemberSkillResponse{Skills: []LibraryMemberSkill{}, CanCreate: true}
	allowed := map[string]bool{}
	for _, c := range clients {
		if memberSkillClientAllowed(c, r) {
			allowed[c.ID] = true
		}
	}
	bySkill := map[string][]LibrarySkillVersion{}
	byID := map[string]LibrarySkillVersion{}
	for _, v := range versions {
		bySkill[v.SkillID] = append(bySkill[v.SkillID], v)
		byID[v.ID] = v
	}
	for _, s := range skills {
		if r.SkillID != "" && s.ID != r.SkillID {
			continue
		}
		own := memberOwnsSkill(s, r.Subject)

		visible := map[string]LibrarySkillVersion{}
		item := LibraryMemberSkill{ID: s.ID, Name: s.Name, Description: s.Description, Access: "assigned", CanEdit: own, CanAssign: own, CanShare: own, Bindings: []LibraryMemberSkillBinding{}}
		all := bySkill[s.ID]
		sort.Slice(all, func(i, j int) bool { return all[i].Version < all[j].Version })
		if own {
			item.Access = "owned"
			for _, v := range all {
				visible[v.ID] = v
			}
		}
		if s.Private && !own {
			for _, g := range grants {
				if skillGrantAllows(g, s.ID, "", r.Subject, time.Now().UTC()) {
					if v, ok := byID[g.VersionID]; ok && v.SkillID == s.ID {
						visible[v.ID] = v
						item.Access = "shared"
						item.Description = ""
						item.CanAssign = true
					}
				}
			}
			if len(visible) == 0 {
				continue
			}
		}
		for _, b := range bindings {
			if !skillBindingGrantAllowed(b, grants, clients, time.Now().UTC()) || b.SkillID != s.ID || b.ScopeKind != LibraryScopeAgentSurface || !allowed[b.ScopeID] {
				continue
			}
			var v LibrarySkillVersion
			if b.Mode == LibraryBindingModePin {
				v = byID[b.PinnedVersionID]
			} else if b.Mode == LibraryBindingModeTrack && len(all) > 0 {
				v = all[len(all)-1]
			}
			if v.ID == "" || v.SkillID != s.ID {
				continue
			}
			if s.Private && !own {
				if _, ok := visible[v.ID]; !ok {
					continue
				}
			}
			visible[v.ID] = v
			item.Bindings = append(item.Bindings, LibraryMemberSkillBinding{ID: b.ID, AgentSurfaceID: b.ScopeID, VersionID: v.ID, Version: v.Version, Managed: (!own && item.Access != "shared") || b.CreatedBy != r.Subject})
		}
		if !own && item.Access != "shared" && len(item.Bindings) == 0 {
			continue
		}
		selected := []LibrarySkillVersion{}
		for _, v := range visible {
			selected = append(selected, v)
		}
		sort.Slice(selected, func(i, j int) bool { return selected[i].Version < selected[j].Version })
		if len(selected) == 0 {
			return out, ErrLibrarySkillVersionNotFound
		}
		item.LatestVersion = memberSkillVersionDTO(selected[len(selected)-1], false)
		sort.Slice(item.Bindings, func(i, j int) bool { return item.Bindings[i].ID < item.Bindings[j].ID })
		if r.SkillID != "" {
			out.Skill = &item
			out.Versions = []LibraryMemberSkillVersion{}
			for _, v := range selected {
				out.Versions = append(out.Versions, memberSkillVersionDTO(v, true))
			}
			out.Skills = nil
			return out, nil
		}
		out.Skills = append(out.Skills, item)
	}
	if r.SkillID != "" {
		return out, ErrLibrarySkillNotFound
	}
	sort.Slice(out.Skills, func(i, j int) bool {
		if out.Skills[i].Name == out.Skills[j].Name {
			return out.Skills[i].ID < out.Skills[j].ID
		}
		return out.Skills[i].Name < out.Skills[j].Name
	})
	return out, nil
}
