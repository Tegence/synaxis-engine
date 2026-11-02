package engine

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"slices"
	"time"
)

var _ LibrarySkillGrantStore = (*PgStore)(nil)

func (s *PgStore) skillGrantsTx(ctx context.Context, tx pgx.Tx) ([]LibrarySkillGrant, error) {
	rows, err := tx.Query(ctx, `SELECT id,payload FROM narthex_library_skill_grants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LibrarySkillGrant{}
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		raw, err := s.dec(payload)
		if err != nil {
			return nil, err
		}
		var g LibrarySkillGrant
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			return nil, err
		}
		if g.ID != id {
			return nil, errors.New("invalid skill share identity")
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *PgStore) saveSkillGrantTx(ctx context.Context, tx pgx.Tx, g LibrarySkillGrant) error {
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	payload, err := s.enc(string(raw))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO narthex_library_skill_grants(id,skill_id,payload) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload`, g.ID, g.SkillID, payload)
	return err
}
func (s *PgStore) skillGrantClientsTx(ctx context.Context, tx pgx.Tx) ([]MCPClient, error) {
	rows, err := tx.Query(ctx, `SELECT `+mcpClientColumns+` FROM narthex_mcp_clients c`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MCPClient{}
	for rows.Next() {
		c, err := scanMCPClientColumns(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *PgStore) skillBindingGrantAllowedTx(ctx context.Context, tx pgx.Tx, b LibrarySkillBinding) (bool, error) {
	if b.SharedGrantID == "" {
		return true, nil
	}
	grants, err := s.skillGrantsTx(ctx, tx)
	if err != nil {
		return false, err
	}
	clients, err := s.skillGrantClientsTx(ctx, tx)
	if err != nil {
		return false, err
	}
	return skillBindingGrantAllowed(b, grants, clients, time.Now().UTC()), nil
}

// Call with every affected skill locked, before changing any bindings.
func (s *PgStore) pruneSkillGrantBindingsTx(ctx context.Context, tx pgx.Tx, g LibrarySkillGrant) error {
	rows, err := tx.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE shared_grant_id=$1`, g.ID)
	if err != nil {
		return err
	}
	bindings := []LibrarySkillBinding{}
	for rows.Next() {
		b, e := s.scanLibrarySkillBinding(rows)
		if e != nil {
			rows.Close()
			return e
		}
		bindings = append(bindings, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	clients, err := s.skillGrantClientsTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		if !skillBindingGrantAllowed(b, []LibrarySkillGrant{g}, clients, time.Now().UTC()) {
			if _, err := tx.Exec(ctx, `DELETE FROM narthex_library_skill_bindings WHERE id=$1`, b.ID); err != nil {
				return err
			}
			if _, err := s.bumpLibrarySkillBindingGenerationForUpdateTx(ctx, tx, b.SkillID); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *PgStore) LibrarySkillGrants(ctx context.Context, r LibrarySkillGrantRequest) (LibrarySkillGrantResponse, error) {
	if err := validateSkillGrantRequest(r); err != nil {
		return LibrarySkillGrantResponse{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibrarySkillGrantResponse{}, err
	}
	defer tx.Rollback(ctx)
	// Consistent skill -> grant -> binding lock order with member mutations.
	if r.Operation != "list" {
		rows, err := tx.Query(ctx, `SELECT id FROM narthex_library_skills ORDER BY id FOR UPDATE`)
		if err != nil {
			return LibrarySkillGrantResponse{}, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return LibrarySkillGrantResponse{}, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return LibrarySkillGrantResponse{}, err
		}
	}
	grants, err := s.skillGrantsTx(ctx, tx)
	if err != nil {
		return LibrarySkillGrantResponse{}, err
	}
	found := false
	out := LibrarySkillGrantResponse{Shares: []LibrarySkillGrant{}}
	for _, g := range grants {
		changed := false
		if r.Operation == "set-recipients" && g.ID == r.GrantID {
			found = true
			if g.Revision != r.Revision {
				return out, ErrLibraryMemberSkillConflict
			}
			if g.RevokedAt != nil {
				return out, ErrLibrarySkillGrantNotFound
			}
			g.RecipientSubjects, _ = normalizeGrantSubjects(r.RecipientSubjects)
			g.RecipientSubjects = skillGrantRecipients(g, g.RecipientSubjects)
			changed = true
		}
		if r.Operation == "end-subject" && g.RevokedAt == nil {
			if g.OwnerSubject == r.Subject {
				now := time.Now().UTC()
				g.RevokedAt = &now
				changed = true
			} else if !slices.Contains(g.ExcludedSubjects, r.Subject) {
				g.ExcludedSubjects = append(g.ExcludedSubjects, r.Subject)
				g.RecipientSubjects = slices.DeleteFunc(g.RecipientSubjects, func(v string) bool { return v == r.Subject })
				changed = true
			}
		}
		if changed {
			g.Revision++
			if err := s.saveSkillGrantTx(ctx, tx, g); err != nil {
				return out, err
			}
			if err := s.pruneSkillGrantBindingsTx(ctx, tx, g); err != nil {
				return out, err
			}
		}
		out.Shares = append(out.Shares, g)
		if g.ID == r.GrantID {
			c := copyLibrarySkillGrant(g)
			out.Share = &c
		}
	}
	if r.Operation == "set-recipients" && !found {
		return out, ErrLibrarySkillGrantNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
func (s *PgStore) memberSkillSharing(ctx context.Context, r LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	defer tx.Rollback(ctx)
	skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1 FOR UPDATE`, r.SkillID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LibraryMemberSkillResponse{}, ErrLibrarySkillNotFound
	}
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	if !memberOwnsSkill(skill, r.Subject) {
		return LibraryMemberSkillResponse{}, ErrLibrarySkillNotFound
	}
	out := LibraryMemberSkillResponse{Shares: []LibrarySkillGrant{}}
	if r.Operation == "share" {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM narthex_library_skill_versions WHERE id=$1 AND skill_id=$2`, r.VersionID, r.SkillID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return out, ErrLibrarySkillVersionNotFound
			}
			return out, err
		}
		g, err := newMemberSkillGrant(r)
		if err != nil {
			return out, err
		}
		if err := s.saveSkillGrantTx(ctx, tx, g); err != nil {
			return out, err
		}
		out.Share = &g
	}
	grants, err := s.skillGrantsTx(ctx, tx)
	if err != nil {
		return out, err
	}
	found := false
	for _, g := range grants {
		if g.SkillID != r.SkillID || g.OwnerSubject != r.Subject {
			continue
		}
		if r.Operation == "revoke-share" && g.ID == r.GrantID {
			found = true
			if g.Revision != r.Revision {
				return out, ErrLibraryMemberSkillConflict
			}
			if g.RevokedAt == nil {
				now := time.Now().UTC()
				g.RevokedAt = &now
			}
			g.Revision++
			if err := s.saveSkillGrantTx(ctx, tx, g); err != nil {
				return out, err
			}
			if err := s.pruneSkillGrantBindingsTx(ctx, tx, g); err != nil {
				return out, err
			}
			c := g
			out.Share = &c
		}
		out.Shares = append(out.Shares, g)
	}
	if r.Operation == "revoke-share" && !found {
		return out, ErrLibrarySkillGrantNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}
