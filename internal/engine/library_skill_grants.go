package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// LibrarySkillGrant shares one immutable instruction version. It never grants
// tools or credentials. The host resolves opaque recipients to current subjects.
type LibrarySkillGrant struct {
	ID                string     `json:"id"`
	SkillID           string     `json:"skillId"`
	VersionID         string     `json:"versionId"`
	OwnerSubject      string     `json:"ownerSubject"`
	RecipientKind     string     `json:"recipientKind"`
	RecipientRef      string     `json:"recipientRef"`
	RecipientSubjects []string   `json:"recipientSubjects"`
	ExcludedSubjects  []string   `json:"excludedSubjects,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	RevokedAt         *time.Time `json:"revokedAt,omitempty"`
	Revision          int64      `json:"revision"`
}
type LibrarySkillGrantRequest struct {
	Operation         string   `json:"operation"`
	GrantID           string   `json:"grantId,omitempty"`
	Revision          int64    `json:"revision,omitempty"`
	RecipientSubjects []string `json:"recipientSubjects,omitempty"`
	Subject           string   `json:"subject,omitempty"`
}
type LibrarySkillGrantResponse struct {
	Shares []LibrarySkillGrant `json:"grants"`
	Share  *LibrarySkillGrant  `json:"grant,omitempty"`
}
type LibrarySkillGrantStore interface {
	LibrarySkillGrants(context.Context, LibrarySkillGrantRequest) (LibrarySkillGrantResponse, error)
}

var ErrLibrarySkillGrantNotFound = errors.New("skill share not found")

func copyLibrarySkillGrant(g LibrarySkillGrant) LibrarySkillGrant {
	g.RecipientSubjects = append([]string{}, g.RecipientSubjects...)
	g.ExcludedSubjects = append([]string{}, g.ExcludedSubjects...)
	if g.ExpiresAt != nil {
		v := *g.ExpiresAt
		g.ExpiresAt = &v
	}
	if g.RevokedAt != nil {
		v := *g.RevokedAt
		g.RevokedAt = &v
	}
	return g
}
func skillGrantActive(g LibrarySkillGrant, now time.Time) bool {
	return g.RevokedAt == nil && (g.ExpiresAt == nil || g.ExpiresAt.After(now))
}
func skillGrantAllows(g LibrarySkillGrant, skillID, versionID, subject string, now time.Time) bool {
	return g.SkillID == skillID && (versionID == "" || g.VersionID == versionID) && skillGrantActive(g, now) && slices.Contains(g.RecipientSubjects, subject) && !slices.Contains(g.ExcludedSubjects, subject)
}
func memberSkillGrant(grants []LibrarySkillGrant, r LibraryMemberSkillRequest) *LibrarySkillGrant {
	for _, g := range grants {
		if skillGrantAllows(g, r.SkillID, r.VersionID, r.Subject, time.Now().UTC()) {
			c := copyLibrarySkillGrant(g)
			return &c
		}
	}
	return nil
}
func newMemberSkillGrant(r LibraryMemberSkillRequest) (LibrarySkillGrant, error) {
	subjects, err := normalizeGrantSubjects(r.RecipientSubjects)
	if err != nil || (len(subjects) == 0 && r.RecipientKind != "team") || r.VersionID == "" || (r.RecipientKind != "subject" && r.RecipientKind != "team") || strings.TrimSpace(r.RecipientRef) == "" || !validActorIdentifier(r.RecipientRef) {
		return LibrarySkillGrant{}, ErrLibraryMemberSkillAccess
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now().UTC()) {
		return LibrarySkillGrant{}, errors.New("share expiry must be in the future")
	}
	g := LibrarySkillGrant{ID: "libsg_" + newEpoch(), SkillID: r.SkillID, VersionID: r.VersionID, OwnerSubject: r.Subject, RecipientKind: r.RecipientKind, RecipientRef: r.RecipientRef, RecipientSubjects: subjects, CreatedAt: time.Now().UTC(), ExpiresAt: r.ExpiresAt, Revision: 1}
	return copyLibrarySkillGrant(g), nil
}
func validateSkillGrantRequest(r LibrarySkillGrantRequest) error {
	switch r.Operation {
	case "list":
		return nil
	case "set-recipients":
		if r.GrantID == "" || r.Revision < 1 {
			return ErrLibraryMemberSkillAccess
		}
		_, err := normalizeGrantSubjects(r.RecipientSubjects)
		return err
	case "end-subject":
		if validateMCPClientSubject(r.Subject) != nil || r.Subject == platformServiceActorID {
			return ErrLibraryMemberSkillAccess
		}
		return nil
	default:
		return errors.New("invalid skill share operation")
	}
}
func skillBindingGrantAllowed(b LibrarySkillBinding, grants []LibrarySkillGrant, clients []MCPClient, now time.Time) bool {
	if b.SharedGrantID == "" {
		return true
	}
	if b.ScopeKind != LibraryScopeAgentSurface || b.Mode != LibraryBindingModePin {
		return false
	}
	var subject string
	for _, c := range clients {
		if c.ID == b.ScopeID && c.Status == MCPClientStatusActive {
			subject = c.Subject
			break
		}
	}
	if subject == "" {
		return false
	}
	for _, g := range grants {
		if g.ID == b.SharedGrantID {
			return skillGrantAllows(g, b.SkillID, b.PinnedVersionID, subject, now)
		}
	}
	return false
}

func skillGrantRecipients(g LibrarySkillGrant, subjects []string) []string {
	return slices.DeleteFunc(subjects, func(v string) bool { return slices.Contains(g.ExcludedSubjects, v) })
}
