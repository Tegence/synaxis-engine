package engine

import (
	"context"
	"time"
)

// ---- FileStore: SkillStore -------------------------------------------------
//
// Same shape as the Connectors/Namespaces facets above: plain slices behind
// s.mu, persisted through the single JSON file via saveLocked(). Local dev /
// self-hosted single-instance use only, matching FileStore's existing
// plaintext-JSON posture (see store.go's package doc on FileStore vs PgStore).

var _ SkillStore = (*FileStore)(nil)

func copySkillSource(s SkillSource) SkillSource { return s } // no nested slices/maps to deep-copy

func (s *FileStore) SkillSources(_ context.Context) ([]SkillSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SkillSource, len(s.skillSources))
	for i, src := range s.skillSources {
		out[i] = copySkillSource(*src)
	}
	return out, nil
}

func (s *FileStore) SkillSource(_ context.Context, id string) (SkillSource, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, src := range s.skillSources {
		if src.ID == id {
			return copySkillSource(*src), true
		}
	}
	return SkillSource{}, false
}

func (s *FileStore) CreateSkillSource(_ context.Context, src SkillSource) (SkillSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src.ID == "" {
		src.ID = newSkillSourceID()
	}
	now := time.Now().UTC()
	src.CreatedAt, src.UpdatedAt = now, now
	cp := copySkillSource(src)
	s.skillSources = append(s.skillSources, &cp)
	if err := s.saveLocked(); err != nil {
		s.skillSources = s.skillSources[:len(s.skillSources)-1]
		return SkillSource{}, err
	}
	return cp, nil
}

func (s *FileStore) DeleteSkillSource(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, src := range s.skillSources {
		if src.ID != id {
			continue
		}
		removed := src
		s.skillSources = append(s.skillSources[:i], s.skillSources[i+1:]...)
		// Cascade: drop every skill (and its versions/carriers/drift/checks)
		// owned by this source, mirroring the CASCADE FKs used in the Pg
		// schema (skills_pg.go).
		var keepSkillIDs, dropSkillIDs []string
		var keptSkills []*Skill
		for _, sk := range s.skills {
			if sk.SourceID == id {
				dropSkillIDs = append(dropSkillIDs, sk.ID)
				continue
			}
			keepSkillIDs = append(keepSkillIDs, sk.ID)
			keptSkills = append(keptSkills, sk)
		}
		s.skills = keptSkills
		s.pruneSkillChildrenLocked(dropSkillIDs)
		if err := s.saveLocked(); err != nil {
			s.skillSources = append(s.skillSources, nil)
			copy(s.skillSources[i+1:], s.skillSources[i:])
			s.skillSources[i] = removed
			return err
		}
		_ = keepSkillIDs
		return nil
	}
	return ErrSkillSourceNotFound
}

// pruneSkillChildrenLocked removes every version/carrier/drift-finding/check
// row belonging to any skill ID in dropIDs. Must be called under s.mu.
func (s *FileStore) pruneSkillChildrenLocked(dropIDs []string) {
	if len(dropIDs) == 0 {
		return
	}
	drop := toSet(dropIDs)
	var versions []*SkillVersion
	for _, v := range s.skillVersions {
		if !drop[v.SkillID] {
			versions = append(versions, v)
		}
	}
	s.skillVersions = versions
	var carriers []*SkillCarrier
	for _, c := range s.skillCarriers {
		if !drop[c.SkillID] {
			carriers = append(carriers, c)
		}
	}
	s.skillCarriers = carriers
	var drift []*SkillDriftFinding
	for _, d := range s.skillDrift {
		if !drop[d.SkillID] {
			drift = append(drift, d)
		}
	}
	s.skillDrift = drift
	for id := range drop {
		delete(s.skillChecks, id)
	}
}

func (s *FileStore) UpdateSkillSourceSync(_ context.Context, id string, syncedAt time.Time, commit, syncErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, src := range s.skillSources {
		if src.ID == id {
			src.LastSyncedAt, src.LastSyncCommit, src.LastSyncError, src.UpdatedAt = syncedAt, commit, syncErr, syncedAt
			return s.saveLocked()
		}
	}
	return ErrSkillSourceNotFound
}

func copySkill(sk Skill) Skill { return sk }

func (s *FileStore) Skills(_ context.Context) ([]Skill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Skill, len(s.skills))
	for i, sk := range s.skills {
		out[i] = copySkill(*sk)
	}
	return out, nil
}

func (s *FileStore) Skill(_ context.Context, id string) (Skill, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sk := range s.skills {
		if sk.ID == id {
			return copySkill(*sk), true
		}
	}
	return Skill{}, false
}

func (s *FileStore) SkillsBySource(_ context.Context, sourceID string) ([]Skill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Skill
	for _, sk := range s.skills {
		if sk.SourceID == sourceID {
			out = append(out, copySkill(*sk))
		}
	}
	return out, nil
}

func (s *FileStore) UpsertSkill(_ context.Context, sk Skill) (Skill, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.skills {
		if existing.SourceID == sk.SourceID && existing.Path == sk.Path {
			return copySkill(*existing), nil
		}
	}
	if sk.ID == "" {
		sk.ID = newSkillID()
	}
	now := time.Now().UTC()
	sk.CreatedAt, sk.UpdatedAt = now, now
	cp := copySkill(sk)
	s.skills = append(s.skills, &cp)
	if err := s.saveLocked(); err != nil {
		s.skills = s.skills[:len(s.skills)-1]
		return Skill{}, err
	}
	return cp, nil
}

func (s *FileStore) PruneSkills(_ context.Context, sourceID string, keepIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := toSet(keepIDs)
	var kept []*Skill
	var dropIDs []string
	for _, sk := range s.skills {
		if sk.SourceID == sourceID && !keep[sk.ID] {
			dropIDs = append(dropIDs, sk.ID)
			continue
		}
		kept = append(kept, sk)
	}
	if len(dropIDs) == 0 {
		return nil
	}
	s.skills = kept
	s.pruneSkillChildrenLocked(dropIDs)
	return s.saveLocked()
}

func copySkillVersion(v SkillVersion) SkillVersion {
	cp := v
	cp.Tools = append([]string(nil), v.Tools...)
	if v.ToolSchemas != nil {
		cp.ToolSchemas = make(map[string]skillToolSchema, len(v.ToolSchemas))
		for k, schema := range v.ToolSchemas {
			s := schema
			s.Properties = append([]string(nil), schema.Properties...)
			s.Required = append([]string(nil), schema.Required...)
			cp.ToolSchemas[k] = s
		}
	}
	return cp
}

func (s *FileStore) SkillVersions(_ context.Context, skillID string) ([]SkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SkillVersion
	for _, v := range s.skillVersions {
		if v.SkillID == skillID {
			out = append(out, copySkillVersion(*v))
		}
	}
	return out, nil
}

func (s *FileStore) LatestSkillVersion(_ context.Context, skillID string) (SkillVersion, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *SkillVersion
	for _, v := range s.skillVersions {
		if v.SkillID != skillID {
			continue
		}
		if best == nil || v.Version > best.Version {
			best = v
		}
	}
	if best == nil {
		return SkillVersion{}, false
	}
	return copySkillVersion(*best), true
}

func (s *FileStore) CreateSkillVersion(_ context.Context, v SkillVersion) (SkillVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.ID == "" {
		v.ID = newSkillVersionID()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	cp := copySkillVersion(v)
	s.skillVersions = append(s.skillVersions, &cp)
	if err := s.saveLocked(); err != nil {
		s.skillVersions = s.skillVersions[:len(s.skillVersions)-1]
		return SkillVersion{}, err
	}
	return cp, nil
}

func copySkillCarrier(c SkillCarrier) SkillCarrier {
	cp := c
	cp.Surfaces = append([]string(nil), c.Surfaces...)
	return cp
}

func (s *FileStore) SkillCarriers(_ context.Context, skillID string) ([]SkillCarrier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SkillCarrier
	for _, c := range s.skillCarriers {
		if c.SkillID == skillID {
			out = append(out, copySkillCarrier(*c))
		}
	}
	return out, nil
}

func (s *FileStore) UpsertSkillCarrier(_ context.Context, c SkillCarrier) (SkillCarrier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, existing := range s.skillCarriers {
		if existing.SkillID == c.SkillID && existing.ConnectorSlug == c.ConnectorSlug {
			id, createdAt := existing.ID, existing.CreatedAt
			*existing = c
			existing.ID, existing.CreatedAt, existing.UpdatedAt = id, createdAt, now
			if err := s.saveLocked(); err != nil {
				return SkillCarrier{}, err
			}
			return copySkillCarrier(*existing), nil
		}
	}
	if c.ID == "" {
		c.ID = newSkillCarrierID()
	}
	c.CreatedAt, c.UpdatedAt = now, now
	cp := copySkillCarrier(c)
	s.skillCarriers = append(s.skillCarriers, &cp)
	if err := s.saveLocked(); err != nil {
		s.skillCarriers = s.skillCarriers[:len(s.skillCarriers)-1]
		return SkillCarrier{}, err
	}
	return cp, nil
}

func (s *FileStore) DeleteSkillCarrier(_ context.Context, skillID, connectorSlug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.skillCarriers {
		if c.SkillID == skillID && c.ConnectorSlug == connectorSlug {
			removed := c
			s.skillCarriers = append(s.skillCarriers[:i], s.skillCarriers[i+1:]...)
			if err := s.saveLocked(); err != nil {
				s.skillCarriers = append(s.skillCarriers, nil)
				copy(s.skillCarriers[i+1:], s.skillCarriers[i:])
				s.skillCarriers[i] = removed
				return err
			}
			return nil
		}
	}
	return ErrSkillNotFound
}

func (s *FileStore) SkillDriftFindings(_ context.Context, skillID string) ([]SkillDriftFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SkillDriftFinding
	for _, d := range s.skillDrift {
		if d.SkillID == skillID {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (s *FileStore) ReplaceSkillDriftFindings(_ context.Context, skillID string, findings []SkillDriftFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []*SkillDriftFinding
	for _, d := range s.skillDrift {
		if d.SkillID != skillID {
			kept = append(kept, d)
		}
	}
	for _, f := range findings {
		cp := f
		kept = append(kept, &cp)
	}
	s.skillDrift = kept
	return s.saveLocked()
}

func (s *FileStore) SkillCheckRun(_ context.Context, skillID string) (SkillCheckRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.skillChecks[skillID]
	if !ok {
		return SkillCheckRun{}, false
	}
	return *run, true
}

func (s *FileStore) SaveSkillCheckRun(_ context.Context, run SkillCheckRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.skillChecks == nil {
		s.skillChecks = map[string]*SkillCheckRun{}
	}
	cp := run
	s.skillChecks[run.SkillID] = &cp
	return s.saveLocked()
}
