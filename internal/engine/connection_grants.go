package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ConnectionGrant delegates selected tools, never a credential or management
// authority. Recipient subjects are opaque references resolved by Platform.
// Team grants carry an auditable team reference and a current subject snapshot.
type ConnectionGrant struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	ConnectionID      string     `json:"connectionId"`
	IncarnationID     string     `json:"incarnationId"`
	SourceRevision    int64      `json:"sourceRevision"`
	OwnerSubject      string     `json:"ownerSubject"`
	CreatedBy         string     `json:"createdBy"`
	RecipientKind     string     `json:"recipientKind"`
	RecipientRef      string     `json:"recipientRef"`
	RecipientSubjects []string   `json:"recipientSubjects"`
	Tools             []string   `json:"tools"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	CreatedAt         time.Time  `json:"createdAt"`
	RevokedAt         *time.Time `json:"revokedAt,omitempty"`
	Revision          int64      `json:"revision"`
	// Only the service-owned personal workload route can create this grant.
	// Its expiry follows the agent, including no expiry; delegated shares expire.
	PersonalWorkload bool `json:"personalWorkload,omitempty"`
	// Writes always require approval by someone who manages the source account.
	RequireWriteApproval bool `json:"requireWriteApproval"`
}

var (
	ErrConnectionGrantNotFound = errors.New("connection grant not found")
	ErrConnectionGrantRevision = errors.New("connection grant changed")
	ErrConnectionGrantInvalid  = errors.New("invalid connection grant")
)

type ConnectionGrantStore interface {
	ConnectionGrants(context.Context) ([]ConnectionGrant, error)
	CreateConnectionGrant(context.Context, ConnectionGrant, AccountPolicyPrecondition) (ConnectionGrant, error)
	RevokeConnectionGrant(context.Context, string, int64) (ConnectionGrant, error)
	SetConnectionGrantRecipients(context.Context, string, int64, []string) (ConnectionGrant, error)
	SubjectAllowed(context.Context, string) (bool, error)
	SetSubjectAllowed(context.Context, string, bool) error
}

func validatePersonalNamespaceAccount(ns ConnectionNamespace, a Account) error {
	if ns.OwnerSubject != "" && (!a.IsPersonal() || a.OwnerSubject != ns.OwnerSubject) {
		return fmt.Errorf("%w: personal folders accept only their owner's personal connections", ErrInvalidConnectionScope)
	}
	return nil
}

func normalizeGrantSubjects(subjects []string) ([]string, error) {
	if len(subjects) > 200 {
		return nil, ErrConnectionGrantInvalid
	}
	out := append([]string{}, subjects...)
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
		if !validActorIdentifier(out[i]) || out[i] == "" {
			return nil, ErrConnectionGrantInvalid
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func normalizeConnectionGrant(g ConnectionGrant) (ConnectionGrant, error) {
	var err error
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 160 || g.ConnectionID == "" || g.IncarnationID == "" || !validActorIdentifier(g.CreatedBy) {
		return g, ErrConnectionGrantInvalid
	}
	if g.RecipientKind != "subject" && g.RecipientKind != "team" {
		return g, ErrConnectionGrantInvalid
	}
	if !validActorIdentifier(g.RecipientRef) || g.RecipientRef == "" {
		return g, ErrConnectionGrantInvalid
	}
	g.RecipientSubjects, err = normalizeGrantSubjects(g.RecipientSubjects)
	if err != nil || len(g.RecipientSubjects) == 0 {
		return g, ErrConnectionGrantInvalid
	}
	if len(g.Tools) == 0 || len(g.Tools) > 256 {
		return g, ErrConnectionGrantInvalid
	}
	g.Tools = append([]string{}, g.Tools...)
	for _, tool := range g.Tools {
		if strings.TrimSpace(tool) != tool || tool == "" || len(tool) > 256 || strings.ContainsAny(tool, "*\x00\r\n") {
			return g, ErrConnectionGrantInvalid
		}
	}
	slices.Sort(g.Tools)
	g.Tools = slices.Compact(g.Tools)
	now := time.Now().UTC()
	if g.PersonalWorkload && (!strings.HasPrefix(g.ID, "cgr_self_") || g.OwnerSubject == "" || g.CreatedBy != g.OwnerSubject || g.RecipientKind != "subject" || len(g.RecipientSubjects) != 1 || g.RecipientSubjects[0] != g.RecipientRef) {
		return g, ErrConnectionGrantInvalid
	}
	if (!g.ExpiresAt.IsZero() && !g.ExpiresAt.After(now)) || (!g.PersonalWorkload && (g.ExpiresAt.IsZero() || g.ExpiresAt.After(now.Add(366*24*time.Hour)))) {
		return g, ErrConnectionGrantInvalid
	}
	if g.ID == "" {
		g.ID = "cgr_" + newEpoch()
	}
	g.CreatedAt = now
	g.Revision = 1
	g.RevokedAt = nil
	g.RequireWriteApproval = true
	return g, nil
}

func copyConnectionGrant(g ConnectionGrant) ConnectionGrant {
	g.Tools = append([]string{}, g.Tools...)
	g.RecipientSubjects = append([]string{}, g.RecipientSubjects...)
	if g.RevokedAt != nil {
		v := *g.RevokedAt
		g.RevokedAt = &v
	}
	return g
}

func connectionGrantAllows(g ConnectionGrant, a Account, subject, tool string, now time.Time) bool {
	return g.RevokedAt == nil && (g.ExpiresAt.After(now) || (g.PersonalWorkload && g.ExpiresAt.IsZero())) && g.ConnectionID == a.Name && g.IncarnationID == a.IncarnationID && g.SourceRevision > 0 && g.SourceRevision == a.Revision &&
		g.OwnerSubject == a.OwnerSubject && slices.Contains(g.RecipientSubjects, subject) && slices.Contains(g.Tools, tool) && !a.MemberCredentials &&
		!accountDeliveredOnlyByExactGrant(a) // caller-delegated: exact client grants only
}

func (s *FileStore) ConnectionGrants(_ context.Context) ([]ConnectionGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConnectionGrant, 0, len(s.connectionGrants))
	for _, g := range s.connectionGrants {
		if g != nil {
			out = append(out, copyConnectionGrant(*g))
		}
	}
	return out, nil
}
func (s *FileStore) CreateConnectionGrant(_ context.Context, g ConnectionGrant, p AccountPolicyPrecondition) (ConnectionGrant, error) {
	g, err := normalizeConnectionGrant(g)
	if err != nil {
		return g, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var account *Account
	for _, a := range s.accounts {
		if a != nil && a.Name == g.ConnectionID {
			account = a
			break
		}
	}
	if account == nil || !p.matches(*account) || g.IncarnationID != account.IncarnationID || g.OwnerSubject != account.OwnerSubject || account.MemberCredentials || (g.PersonalWorkload && !account.IsPersonal()) {
		return ConnectionGrant{}, ErrAccountPolicyPrecondition
	}
	for _, existing := range s.connectionGrants {
		if existing != nil && existing.ID == g.ID {
			return ConnectionGrant{}, ErrConnectionGrantInvalid
		}
	}
	g.SourceRevision = account.Revision
	cp := copyConnectionGrant(g)
	s.connectionGrants = append(s.connectionGrants, &cp)
	if err := s.saveLocked(); err != nil {
		s.connectionGrants = s.connectionGrants[:len(s.connectionGrants)-1]
		return ConnectionGrant{}, err
	}
	return copyConnectionGrant(cp), nil
}
func (s *FileStore) mutateConnectionGrant(id string, revision int64, mutate func(*ConnectionGrant) error) (ConnectionGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.connectionGrants {
		if g == nil || g.ID != id {
			continue
		}
		if revision < 1 || g.Revision != revision {
			return ConnectionGrant{}, ErrConnectionGrantRevision
		}
		before := copyConnectionGrant(*g)
		if err := mutate(g); err != nil {
			return ConnectionGrant{}, err
		}
		g.Revision++
		if err := s.saveLocked(); err != nil {
			*g = before
			return ConnectionGrant{}, err
		}
		return copyConnectionGrant(*g), nil
	}
	return ConnectionGrant{}, ErrConnectionGrantNotFound
}
func (s *FileStore) RevokeConnectionGrant(_ context.Context, id string, revision int64) (ConnectionGrant, error) {
	return s.mutateConnectionGrant(id, revision, func(g *ConnectionGrant) error {
		if g.RevokedAt == nil {
			now := time.Now().UTC()
			g.RevokedAt = &now
		}
		return nil
	})
}
func (s *FileStore) SetConnectionGrantRecipients(_ context.Context, id string, revision int64, subjects []string) (ConnectionGrant, error) {
	subjects, err := normalizeGrantSubjects(subjects)
	if err != nil {
		return ConnectionGrant{}, err
	}
	return s.mutateConnectionGrant(id, revision, func(g *ConnectionGrant) error {
		if g.RevokedAt != nil {
			return ErrConnectionGrantNotFound
		}
		g.RecipientSubjects = subjects
		return nil
	})
}
func (s *FileStore) SubjectAllowed(_ context.Context, subject string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed, present := s.subjectAccess[subject]
	return !present || allowed, nil
}
func (s *FileStore) SetSubjectAllowed(_ context.Context, subject string, allowed bool) error {
	if subject == "" || !validActorIdentifier(subject) {
		return ErrConnectionGrantInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subjectAccess == nil {
		s.subjectAccess = map[string]bool{}
	}
	before, present := s.subjectAccess[subject]
	oldClients := copyMCPClients(s.mcpClients)
	if !allowed && (!present || before) {
		for _, client := range s.mcpClients {
			if client != nil && client.Subject == subject && client.Status == MCPClientStatusActive {
				client.Epoch = newEpoch()
				client.Revision++
				client.UpdatedAt = time.Now().UTC()
			}
		}
	}
	s.subjectAccess[subject] = allowed
	if err := s.saveLocked(); err != nil {
		s.mcpClients = oldClients
		if present {
			s.subjectAccess[subject] = before
		} else {
			delete(s.subjectAccess, subject)
		}
		return err
	}
	return nil
}
