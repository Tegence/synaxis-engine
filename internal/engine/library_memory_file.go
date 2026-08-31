package engine

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

func (s *FileStore) libraryMemoryLocked(id string) *LibraryMemory {
	for _, memory := range s.libraryMemories {
		if memory != nil && memory.ID == id {
			return memory
		}
	}
	return nil
}

func (s *FileStore) libraryMemoryVersionLocked(memoryID, id string) *LibraryMemoryVersion {
	for _, version := range s.libraryMemoryVersions {
		if version != nil && version.MemoryID == memoryID && version.ID == id {
			return version
		}
	}
	return nil
}

func (s *FileStore) libraryMemoryGrantLocked(memoryID, id string) *LibraryMemoryGrant {
	for _, grant := range s.libraryMemoryGrants {
		if grant != nil && grant.MemoryID == memoryID && grant.ID == id {
			return grant
		}
	}
	return nil
}

func (s *FileStore) activeLibraryMemoryGrantLocked(memoryID, agentSurfaceID string) *LibraryMemoryGrant {
	for _, grant := range s.libraryMemoryGrants {
		if grant != nil && grant.MemoryID == memoryID && grant.AgentSurfaceID == agentSurfaceID && grant.RevokedAt.IsZero() {
			return grant
		}
	}
	return nil
}

func (s *FileStore) validateLibraryMemoryEvidenceLocked(version LibraryMemoryVersion) error {
	if version.SourceRunID != "" && s.libraryRunLocked(version.SourceRunID) == nil {
		return ErrLibraryRunNotFound
	}
	if version.SourceArtifactID == "" {
		return nil
	}
	if s.libraryArtifactLocked(version.SourceArtifactID) == nil {
		return ErrLibraryArtifactNotFound
	}
	source := s.libraryArtifactVersionLocked(version.SourceArtifactID, version.SourceArtifactVersionID)
	if source == nil || source.Digest != version.SourceDigest {
		return ErrLibraryArtifactVersionNotFound
	}
	return nil
}

func (s *FileStore) LibraryConsoleMemoryPage(_ context.Context, cursor LibraryConsolePageCursor, limit int) (LibraryConsoleMemoryPage, error) {
	if err := validateLibraryConsolePageCursor(cursor); err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	limit, err := normalizeLibraryConsolePageLimit(limit)
	if err != nil {
		return LibraryConsoleMemoryPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	comesBefore := func(left, right LibraryMemory) bool {
		if !left.UpdatedAt.Equal(right.UpdatedAt) {
			return left.UpdatedAt.After(right.UpdatedAt)
		}
		return left.ID > right.ID
	}
	out := make([]LibraryMemory, 0, min(len(s.libraryMemories), limit+1))
	for _, memory := range s.libraryMemories {
		if memory == nil {
			continue
		}
		if !cursor.Timestamp.IsZero() && (memory.UpdatedAt.After(cursor.Timestamp) || (memory.UpdatedAt.Equal(cursor.Timestamp) && memory.ID >= cursor.ID)) {
			continue
		}
		item := copyLibraryMemory(*memory)
		item.Preview = ""
		if len(out) < limit+1 {
			out = append(out, item)
			continue
		}
		worst := 0
		for index := 1; index < len(out); index++ {
			if comesBefore(out[worst], out[index]) {
				worst = index
			}
		}
		if comesBefore(item, out[worst]) {
			out[worst] = item
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return comesBefore(out[i], out[j])
	})
	page := LibraryConsoleMemoryPage{Memories: out}
	if len(page.Memories) > limit {
		last := page.Memories[limit-1]
		page.NextCursor = LibraryConsolePageCursor{Timestamp: last.UpdatedAt, ID: last.ID}
		page.Memories = page.Memories[:limit]
	}
	// Match PgStore's privacy/resource boundary: inspect authored content only
	// for the bounded rows that will actually leave this page.
	for index := range page.Memories {
		item := &page.Memories[index]
		if version := s.libraryMemoryVersionLocked(item.ID, item.CurrentVersionID); version != nil && version.Digest == item.CurrentVersionDigest {
			item.Preview = libraryMemoryPreview(version.Content)
		}
	}
	return page, nil
}

func (s *FileStore) LibraryMemory(_ context.Context, id string) (LibraryMemory, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	memory := s.libraryMemoryLocked(id)
	if memory == nil {
		return LibraryMemory{}, false
	}
	return copyLibraryMemory(*memory), true
}

func (s *FileStore) LibraryMemoryVersions(_ context.Context, memoryID string) ([]LibraryMemoryVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.libraryMemoryLocked(memoryID) == nil {
		return nil, ErrLibraryMemoryNotFound
	}
	out := make([]LibraryMemoryVersion, 0)
	for _, version := range s.libraryMemoryVersions {
		if version != nil && version.MemoryID == memoryID {
			out = append(out, copyLibraryMemoryVersion(*version))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func (s *FileStore) LibraryMemoryVersion(_ context.Context, memoryID, id string) (LibraryMemoryVersion, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version := s.libraryMemoryVersionLocked(memoryID, id)
	if version == nil {
		return LibraryMemoryVersion{}, false
	}
	return copyLibraryMemoryVersion(*version), true
}

func (s *FileStore) createLibraryMemoryWithInitialVersionLocked(memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	memory, version, err := prepareLibraryMemoryInitial(memory, version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if s.libraryMemoryLocked(memory.ID) != nil || s.libraryMemoryVersionLocked(memory.ID, version.ID) != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("library memory identity already exists")
	}
	client, found := s.mcpClientByIDLocked(memory.AgentSurfaceID)
	if !found {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrMCPClientNotFound
	}
	if client.Status != MCPClientStatusActive {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrMCPClientRevoked
	}
	if err := s.validateLibraryMemoryEvidenceLocked(version); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	memory.Preview = ""
	memoryCopy, versionCopy := copyLibraryMemory(memory), copyLibraryMemoryVersion(version)
	s.libraryMemories = append(s.libraryMemories, &memoryCopy)
	s.libraryMemoryVersions = append(s.libraryMemoryVersions, &versionCopy)
	if err := s.saveLocked(); err != nil {
		s.libraryMemories = s.libraryMemories[:len(s.libraryMemories)-1]
		s.libraryMemoryVersions = s.libraryMemoryVersions[:len(s.libraryMemoryVersions)-1]
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return copyLibraryMemory(memoryCopy), copyLibraryMemoryVersion(versionCopy), nil
}

func (s *FileStore) CreateLibraryMemoryWithInitialVersion(_ context.Context, memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLibraryMemoryWithInitialVersionLocked(memory, version)
}

func (s *FileStore) CreateLibraryMCPClientMemoryProposal(_ context.Context, client MCPClient, memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, found := s.mcpClientByIDLocked(client.ID)
	if !found || stored.Subject != client.Subject || stored.Epoch != client.Epoch {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrMCPClientNotFound
	}
	if stored.Status != MCPClientStatusActive {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrMCPClientRevoked
	}
	if memory.ID != "" || memory.AgentSurfaceID != "" || memory.State != "" || memory.Trust != "" || memory.CreatedBy != "" || memory.CurrentVersionID != "" || version.ID != "" || version.MemoryID != "" || version.Version != 0 || version.CreatedBy != "" {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("MCP memory proposal must derive identity, surface, actor, state, and trust")
	}
	memory.AgentSurfaceID = stored.ID
	memory.State = LibraryMemoryStateProposed
	memory.Trust = LibraryMemoryTrustAgentObserved
	memory.CreatedBy = stored.Subject
	version.CreatedBy = stored.Subject
	if version.SourceRunID != "" {
		run := s.libraryRunLocked(version.SourceRunID)
		if run == nil || run.Origin != LibraryRunOriginAgentDirect || run.ActorRef != stored.Subject || run.SurfaceRef != stored.ID {
			return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryEvidenceUnavailable
		}
	}
	if version.SourceArtifactID != "" && !s.libraryMCPClientMayUseArtifactVersionLocked(version.SourceArtifactID, version.SourceArtifactVersionID, version.SourceDigest, *stored) {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryEvidenceUnavailable
	}
	return s.createLibraryMemoryWithInitialVersionLocked(memory, version)
}

func (s *FileStore) CreateLibraryMemoryVersion(_ context.Context, memoryID string, version LibraryMemoryVersion, createdBy string) (LibraryMemory, LibraryMemoryVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	memory := s.libraryMemoryLocked(memoryID)
	if memory == nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, ErrLibraryMemoryNotFound
	}
	if err := validateLibraryOpaqueRef("memory version creator", createdBy, false); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if version.ID != "" || (version.MemoryID != "" && version.MemoryID != memoryID) || version.Version != 0 || version.CreatedBy != "" {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("memory correction must derive immutable identity")
	}
	version.ID = newLibraryMemoryVersionID()
	version.MemoryID = memoryID
	version.CreatedBy = createdBy
	maxVersion := 0
	for _, candidate := range s.libraryMemoryVersions {
		if candidate != nil && candidate.MemoryID == memoryID && candidate.Version > maxVersion {
			maxVersion = candidate.Version
		}
	}
	version.Version = maxVersion + 1
	normalized, err := normalizeLibraryMemoryVersion(version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	if err := s.validateLibraryMemoryEvidenceLocked(normalized); err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	before := copyLibraryMemory(*memory)
	memory.CurrentVersionID = normalized.ID
	memory.CurrentVersionDigest = normalized.Digest
	memory.State = LibraryMemoryStateProposed
	memory.Trust = LibraryMemoryTrustHumanConfirmed
	memory.ReviewedBy = ""
	memory.ReviewedAt = time.Time{}
	memory.SupersededByMemoryID = ""
	memory.UpdatedAt = normalized.CreatedAt
	versionCopy := copyLibraryMemoryVersion(normalized)
	s.libraryMemoryVersions = append(s.libraryMemoryVersions, &versionCopy)
	type revokedGrant struct {
		grant  *LibraryMemoryGrant
		before LibraryMemoryGrant
	}
	revoked := make([]revokedGrant, 0)
	for _, grant := range s.libraryMemoryGrants {
		if grant == nil || grant.MemoryID != memoryID || !grant.RevokedAt.IsZero() {
			continue
		}
		revoked = append(revoked, revokedGrant{grant: grant, before: copyLibraryMemoryGrant(*grant)})
		grant.RevokedBy = createdBy
		grant.RevokedAt = normalized.CreatedAt
	}
	if err := s.saveLocked(); err != nil {
		*memory = before
		s.libraryMemoryVersions = s.libraryMemoryVersions[:len(s.libraryMemoryVersions)-1]
		for _, rollback := range revoked {
			*rollback.grant = rollback.before
		}
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return copyLibraryMemory(*memory), copyLibraryMemoryVersion(versionCopy), nil
}

func (s *FileStore) ReviewLibraryMemory(_ context.Context, memoryID string, review LibraryMemoryReview) (LibraryMemory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	memory := s.libraryMemoryLocked(memoryID)
	if memory == nil {
		return LibraryMemory{}, ErrLibraryMemoryNotFound
	}
	version := s.libraryMemoryVersionLocked(memoryID, review.MemoryVersionID)
	if memory.CurrentVersionID != review.MemoryVersionID || version == nil || memory.CurrentVersionDigest != version.Digest {
		return LibraryMemory{}, ErrLibraryMemoryVersionConflict
	}
	if err := validateLibraryOpaqueRef("memory reviewer", review.ReviewedBy, false); err != nil {
		return LibraryMemory{}, err
	}
	state, trust := strings.ToLower(strings.TrimSpace(review.State)), strings.ToLower(strings.TrimSpace(review.Trust))
	if !validLibraryMemoryAdministrativeReview(state, trust) {
		return LibraryMemory{}, errors.New("invalid memory review state or trust")
	}
	if review.ReviewedAt.IsZero() {
		review.ReviewedAt = time.Now().UTC()
	}
	if state == LibraryMemoryStateSuperseded {
		replacement := s.libraryMemoryLocked(review.SupersededByMemoryID)
		if replacement == nil || replacement.ID == memoryID || !libraryMemoryIsRecallable(*replacement, time.Now().UTC()) {
			return LibraryMemory{}, ErrLibraryMemorySupersessionIneligible
		}
	}
	before := copyLibraryMemory(*memory)
	memory.State = state
	memory.Trust = trust
	if review.ExpiresAt != nil {
		memory.ExpiresAt = review.ExpiresAt.UTC()
	}
	if review.ReviewAfter != nil {
		memory.ReviewAfter = review.ReviewAfter.UTC()
	}
	memory.SupersededByMemoryID = review.SupersededByMemoryID
	memory.ReviewedBy = review.ReviewedBy
	memory.ReviewedAt = review.ReviewedAt.UTC()
	memory.UpdatedAt = review.ReviewedAt.UTC()
	if err := validateLibraryMemory(*memory); err != nil {
		*memory = before
		return LibraryMemory{}, err
	}
	if err := s.saveLocked(); err != nil {
		*memory = before
		return LibraryMemory{}, err
	}
	return copyLibraryMemory(*memory), nil
}

func (s *FileStore) LibraryMemoryGrants(_ context.Context, memoryID string) ([]LibraryMemoryGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.libraryMemoryLocked(memoryID) == nil {
		return nil, ErrLibraryMemoryNotFound
	}
	out := make([]LibraryMemoryGrant, 0)
	for _, grant := range s.libraryMemoryGrants {
		if grant != nil && grant.MemoryID == memoryID {
			out = append(out, copyLibraryMemoryGrant(*grant))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) CreateLibraryMemoryGrant(_ context.Context, grant LibraryMemoryGrant) (LibraryMemoryGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if grant.ID == "" {
		grant.ID = newLibraryMemoryGrantID()
	}
	grant, err := normalizeLibraryMemoryGrant(grant)
	if err != nil {
		return LibraryMemoryGrant{}, err
	}
	if !grant.RevokedAt.IsZero() {
		return LibraryMemoryGrant{}, errors.New("new memory grant must be live")
	}
	memory := s.libraryMemoryLocked(grant.MemoryID)
	if memory == nil {
		return LibraryMemoryGrant{}, ErrLibraryMemoryNotFound
	}
	if !libraryMemoryIsRecallable(*memory, time.Now().UTC()) || memory.CurrentVersionID != grant.MemoryVersionID || memory.CurrentVersionDigest != grant.MemoryVersionDigest {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantIneligible
	}
	if memory.AgentSurfaceID == grant.AgentSurfaceID {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantOwner
	}
	client, found := s.mcpClientByIDLocked(grant.AgentSurfaceID)
	if !found {
		return LibraryMemoryGrant{}, ErrMCPClientNotFound
	}
	if client.Status != MCPClientStatusActive {
		return LibraryMemoryGrant{}, ErrMCPClientRevoked
	}
	version := s.libraryMemoryVersionLocked(grant.MemoryID, grant.MemoryVersionID)
	if version == nil || version.Digest != grant.MemoryVersionDigest {
		return LibraryMemoryGrant{}, ErrLibraryMemoryVersionNotFound
	}
	if s.activeLibraryMemoryGrantLocked(grant.MemoryID, grant.AgentSurfaceID) != nil {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantExists
	}
	copy := copyLibraryMemoryGrant(grant)
	s.libraryMemoryGrants = append(s.libraryMemoryGrants, &copy)
	if err := s.saveLocked(); err != nil {
		s.libraryMemoryGrants = s.libraryMemoryGrants[:len(s.libraryMemoryGrants)-1]
		return LibraryMemoryGrant{}, err
	}
	return copyLibraryMemoryGrant(copy), nil
}

func (s *FileStore) RevokeLibraryMemoryGrant(_ context.Context, memoryID, grantID, revokedBy string, revokedAt time.Time) (LibraryMemoryGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateLibraryOpaqueRef("memory grant revoker", revokedBy, false); err != nil {
		return LibraryMemoryGrant{}, err
	}
	if s.libraryMemoryLocked(memoryID) == nil {
		return LibraryMemoryGrant{}, ErrLibraryMemoryNotFound
	}
	grant := s.libraryMemoryGrantLocked(memoryID, grantID)
	if grant == nil {
		return LibraryMemoryGrant{}, ErrLibraryMemoryGrantNotFound
	}
	if !grant.RevokedAt.IsZero() {
		return copyLibraryMemoryGrant(*grant), nil
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	before := copyLibraryMemoryGrant(*grant)
	grant.RevokedBy, grant.RevokedAt = revokedBy, revokedAt.UTC()
	if err := s.saveLocked(); err != nil {
		*grant = before
		return LibraryMemoryGrant{}, err
	}
	return copyLibraryMemoryGrant(*grant), nil
}

func (s *FileStore) liveLibraryMemoryClientLocked(client MCPClient) (*MCPClient, error) {
	stored, found := s.mcpClientByIDLocked(client.ID)
	if !found || stored.Subject != client.Subject || stored.Epoch != client.Epoch {
		return nil, ErrMCPClientNotFound
	}
	if stored.Status != MCPClientStatusActive {
		return nil, ErrMCPClientRevoked
	}
	return stored, nil
}

func (s *FileStore) LibraryMemoryRecallSelections(_ context.Context, client MCPClient, now time.Time) ([]LibraryMemorySelection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.liveLibraryMemoryClientLocked(client)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := make([]LibraryMemorySelection, 0)
	seen := make(map[string]struct{})
	for _, memory := range s.libraryMemories {
		if memory == nil || !libraryMemoryIsRecallable(*memory, now) {
			continue
		}
		if memory.AgentSurfaceID == stored.ID {
			version := s.libraryMemoryVersionLocked(memory.ID, memory.CurrentVersionID)
			if version != nil && version.Digest == memory.CurrentVersionDigest {
				out = append(out, LibraryMemorySelection{Memory: copyLibraryMemory(*memory), Version: copyLibraryMemoryVersion(*version), Access: LibraryMemoryAccessOwnSurface})
				seen[memory.ID+"\x00"+version.ID] = struct{}{}
			}
		}
	}
	for _, grant := range s.libraryMemoryGrants {
		if grant == nil || grant.AgentSurfaceID != stored.ID || !grant.RevokedAt.IsZero() {
			continue
		}
		memory := s.libraryMemoryLocked(grant.MemoryID)
		version := s.libraryMemoryVersionLocked(grant.MemoryID, grant.MemoryVersionID)
		if memory == nil || version == nil || !libraryMemoryIsRecallable(*memory, now) || version.Digest != grant.MemoryVersionDigest {
			continue
		}
		key := memory.ID + "\x00" + version.ID
		if _, exists := seen[key]; exists {
			continue
		}
		out = append(out, LibraryMemorySelection{Memory: copyLibraryMemory(*memory), Version: copyLibraryMemoryVersion(*version), Access: LibraryMemoryAccessGranted, GrantID: grant.ID})
		seen[key] = struct{}{}
	}
	sortLibraryMemorySelections(out)
	return out, nil
}

func (s *FileStore) LibraryMemoryReadSelection(_ context.Context, client MCPClient, memoryID, versionID string, now time.Time) (LibraryMemorySelection, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.liveLibraryMemoryClientLocked(client)
	if err != nil {
		return LibraryMemorySelection{}, false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	memory := s.libraryMemoryLocked(memoryID)
	version := s.libraryMemoryVersionLocked(memoryID, versionID)
	if memory == nil || version == nil || !libraryMemoryIsRecallable(*memory, now) {
		return LibraryMemorySelection{}, false, nil
	}
	if memory.AgentSurfaceID == stored.ID && memory.CurrentVersionID == version.ID && memory.CurrentVersionDigest == version.Digest {
		return LibraryMemorySelection{Memory: copyLibraryMemory(*memory), Version: copyLibraryMemoryVersion(*version), Access: LibraryMemoryAccessOwnSurface}, true, nil
	}
	grant := s.activeLibraryMemoryGrantLocked(memoryID, stored.ID)
	if grant == nil || grant.MemoryVersionID != version.ID || grant.MemoryVersionDigest != version.Digest {
		return LibraryMemorySelection{}, false, nil
	}
	return LibraryMemorySelection{Memory: copyLibraryMemory(*memory), Version: copyLibraryMemoryVersion(*version), Access: LibraryMemoryAccessGranted, GrantID: grant.ID}, true, nil
}

func (s *FileStore) ForgetLibraryMemory(_ context.Context, memoryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.libraryMemoryLocked(memoryID) == nil {
		return ErrLibraryMemoryNotFound
	}
	oldMemories, oldVersions, oldGrants := s.libraryMemories, s.libraryMemoryVersions, s.libraryMemoryGrants
	memories := make([]*LibraryMemory, 0, len(oldMemories)-1)
	now := time.Now().UTC()
	for _, memory := range oldMemories {
		if memory == nil || memory.ID == memoryID {
			continue
		}
		// A forgotten replacement must not remain named by another logical
		// card. Keep the referring card and its own authored history, but make
		// it explicitly non-recallable and clear the dangling identifier.
		copy := copyLibraryMemory(*memory)
		if copy.SupersededByMemoryID == memoryID {
			copy.State = LibraryMemoryStateExpired
			copy.SupersededByMemoryID = ""
			copy.UpdatedAt = now
		}
		memories = append(memories, &copy)
	}
	versions := make([]*LibraryMemoryVersion, 0, len(oldVersions))
	for _, version := range oldVersions {
		if version != nil && version.MemoryID != memoryID {
			versions = append(versions, version)
		}
	}
	grants := make([]*LibraryMemoryGrant, 0, len(oldGrants))
	for _, grant := range oldGrants {
		if grant != nil && grant.MemoryID != memoryID {
			grants = append(grants, grant)
		}
	}
	s.libraryMemories, s.libraryMemoryVersions, s.libraryMemoryGrants = memories, versions, grants
	if err := s.saveLocked(); err != nil {
		s.libraryMemories, s.libraryMemoryVersions, s.libraryMemoryGrants = oldMemories, oldVersions, oldGrants
		return err
	}
	return nil
}
