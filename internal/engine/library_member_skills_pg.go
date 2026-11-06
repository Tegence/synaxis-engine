package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var _ LibraryMemberSkillStore = (*PgStore)(nil)

func (s *PgStore) MemberLibrarySkills(ctx context.Context, r LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error) {
	if err := validateMemberSkillRequest(r); err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	if r.Operation == "shares" || r.Operation == "share" || r.Operation == "revoke-share" {
		return s.memberSkillSharing(ctx, r)
	}
	switch r.Operation {
	case "create":
		skill, version := memberSkillNew(r)
		created, _, err := s.createLibrarySkillWithInitialVersion(ctx, skill, version, nil)
		if err != nil {
			return LibraryMemberSkillResponse{}, err
		}
		r.SkillID = created.ID
	case "version":
		if _, err := s.createLibrarySkillVersion(ctx, memberSkillVersion(r), memberSkillBundle(r), r); err != nil {
			return LibraryMemberSkillResponse{}, err
		}
	case "bind":
		if _, err := s.upsertLibrarySkillBinding(ctx, memberSkillBinding(r), &r); err != nil {
			return LibraryMemberSkillResponse{}, err
		}
	case "unbind":
		if err := s.deleteLibrarySkillBinding(ctx, r.SkillID, r.BindingID, &r); err != nil {
			return LibraryMemberSkillResponse{}, err
		}
	}
	return s.memberSkillSnapshot(ctx, r)
}
func (s *PgStore) guardMemberSkillClientTx(ctx context.Context, tx pgx.Tx, r LibraryMemberSkillRequest) error {
	client, err := loadMCPClientForUpdate(ctx, tx, r.AgentSurfaceID)
	if err != nil {
		return err
	}
	if !memberSkillClientAllowed(client, r) {
		return ErrLibraryMemberSkillAccess
	}
	return nil
}

// Called with the skill row held FOR UPDATE; all binding mutations serialize on it.
func (s *PgStore) guardMemberSkillTx(ctx context.Context, tx pgx.Tx, r LibraryMemberSkillRequest, surface string) error {
	skill, err := s.scanLibrarySkill(tx.QueryRow(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE id=$1`, r.SkillID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLibrarySkillNotFound
	}
	if err != nil {
		return err
	}
	if !memberOwnsSkill(skill, r.Subject) {
		if r.Operation != "bind" && r.Operation != "unbind" {
			return ErrLibrarySkillNotFound
		}
		grants, err := s.skillGrantsTx(ctx, tx)
		if err != nil {
			return err
		}
		if memberSkillGrant(grants, r) == nil {
			return ErrLibrarySkillNotFound
		}
	}
	if surface == "" {
		return nil
	}
	b, err := s.scanLibrarySkillBinding(tx.QueryRow(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE skill_id=$1 AND scope_kind=$2 AND scope_id=$3`, r.SkillID, LibraryScopeAgentSurface, surface))
	if errors.Is(err, pgx.ErrNoRows) {
		if r.Operation == "unbind" {
			return ErrLibraryBindingNotFound
		}
		return nil
	}
	if err != nil {
		return err
	}
	if b.CreatedBy != r.Subject {
		return ErrLibraryMemberSkillAccess
	}
	if r.Operation == "unbind" && b.ID != r.BindingID {
		return ErrLibraryBindingNotFound
	}
	return nil
}
func (s *PgStore) memberSkillSnapshot(ctx context.Context, r LibraryMemberSkillRequest) (LibraryMemberSkillResponse, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	defer tx.Rollback(ctx)
	grants, err := s.skillGrantsTx(ctx, tx)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	skills := []LibrarySkill{}
	versions := []LibrarySkillVersion{}
	bindings := []LibrarySkillBinding{}
	clients := []MCPClient{}
	rows, err := tx.Query(ctx, `SELECT `+librarySkillColumns+` FROM narthex_library_skills WHERE ($1='' OR id=$1)`, r.SkillID)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	for rows.Next() {
		v, e := s.scanLibrarySkill(rows)
		if e != nil {
			rows.Close()
			return LibraryMemberSkillResponse{}, e
		}
		skills = append(skills, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	rows, err = tx.Query(ctx, `SELECT `+mcpClientColumns+` FROM narthex_mcp_clients c WHERE c.status=$1 AND c.subject=ANY($2)`, MCPClientStatusActive, r.SubjectIDs)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	surfaces := []string{}
	for rows.Next() {
		v, e := scanMCPClientColumns(rows)
		if e != nil {
			rows.Close()
			return LibraryMemberSkillResponse{}, e
		}
		clients = append(clients, v)
		surfaces = append(surfaces, v.ID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	rows, err = tx.Query(ctx, `SELECT `+libraryBindingColumns+` FROM narthex_library_skill_bindings WHERE scope_kind=$1 AND scope_id=ANY($2) AND ($3='' OR skill_id=$3)`, LibraryScopeAgentSurface, surfaces, r.SkillID)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	wanted := map[string]bool{}
	for _, v := range skills {
		if memberOwnsSkill(v, r.Subject) || memberSkillGrant(grants, LibraryMemberSkillRequest{Subject: r.Subject, SkillID: v.ID}) != nil {
			wanted[v.ID] = true
		}
	}
	for rows.Next() {
		v, e := s.scanLibrarySkillBinding(rows)
		if e != nil {
			rows.Close()
			return LibraryMemberSkillResponse{}, e
		}
		bindings = append(bindings, v)
		wanted[v.SkillID] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	ids := []string{}
	for _, v := range skills {
		if wanted[v.ID] {
			ids = append(ids, v.ID)
		}
	}
	rows, err = tx.Query(ctx, `SELECT `+librarySkillVersionColumns+` FROM narthex_library_skill_versions WHERE skill_id=ANY($1)`, ids)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	for rows.Next() {
		v, e := s.scanLibrarySkillVersion(rows)
		if e != nil {
			rows.Close()
			return LibraryMemberSkillResponse{}, e
		}
		versions = append(versions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	result, err := memberSkillProjection(r, skills, versions, bindings, clients, grants)
	if err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return LibraryMemberSkillResponse{}, err
	}
	return result, nil
}
