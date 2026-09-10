package engine

import "context"

// LibraryControlArtifactPage projects the scope's surfaces directly from the
// artifact ownership key and live grants, the same two predicates the
// subject-bound client page uses, and never from a per-artifact run lookup.
func (s *FileStore) LibraryControlArtifactPage(_ context.Context, scope LibraryControlArtifactScope, cursor LibraryControlArtifactCursor, limit int) (LibraryControlArtifactPage, error) {
	scope, err := normalizeLibraryControlArtifactScope(scope)
	if err != nil {
		return LibraryControlArtifactPage{}, err
	}
	if err := validateLibraryControlArtifactCursor(cursor); err != nil {
		return LibraryControlArtifactPage{}, err
	}
	limit, err = normalizeLibraryControlArtifactPageLimit(limit)
	if err != nil {
		return LibraryControlArtifactPage{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	heads := make(map[string]*LibraryArtifactVersion, len(s.libraryArtifacts))
	for _, version := range s.libraryArtifactVersions {
		if version == nil {
			continue
		}
		if current := heads[version.ArtifactID]; current == nil || version.Version > current.Version {
			heads[version.ArtifactID] = version
		}
	}

	type candidate struct {
		artifact *LibraryArtifact
		access   string
		granted  *LibraryArtifactVersion
	}
	selected := make(map[string]candidate)
	if scope.Everything {
		for _, artifact := range s.libraryArtifacts {
			if artifact != nil {
				selected[artifact.ID] = candidate{artifact: artifact}
			}
		}
	} else {
		surfaces := make(map[string]struct{}, len(scope.AgentSurfaceIDs))
		for _, id := range scope.AgentSurfaceIDs {
			surfaces[id] = struct{}{}
		}
		for _, grant := range s.libraryArtifactGrants {
			if grant == nil || !grant.RevokedAt.IsZero() {
				continue
			}
			if _, ok := surfaces[grant.AgentSurfaceID]; !ok {
				continue
			}
			artifact := s.libraryArtifactLocked(grant.ArtifactID)
			version := s.libraryArtifactVersionLocked(grant.ArtifactID, grant.ArtifactVersionID)
			if artifact == nil || version == nil || version.Digest != grant.ArtifactVersionDigest {
				continue
			}
			if current, ok := selected[artifact.ID]; ok && current.granted != nil && current.granted.Version >= version.Version {
				continue
			}
			selected[artifact.ID] = candidate{artifact: artifact, access: LibraryControlArtifactAccessGranted, granted: version}
		}
		for _, artifact := range s.libraryArtifacts {
			if artifact == nil || artifact.AgentSurfaceID == "" {
				continue
			}
			if _, ok := surfaces[artifact.AgentSurfaceID]; !ok {
				continue
			}
			// Direct ownership wins over any grant one of the subject's other
			// surfaces may hold.
			selected[artifact.ID] = candidate{artifact: artifact, access: LibraryControlArtifactAccessOwned}
		}
	}

	items := make([]LibraryControlArtifact, 0, len(selected))
	for _, entry := range selected {
		head := heads[entry.artifact.ID]
		if head == nil {
			continue
		}
		item := LibraryControlArtifact{
			Artifact:      libraryControlArtifactMetadata(*entry.artifact),
			Access:        entry.access,
			LatestVersion: libraryArtifactVersionMetadata(*head),
			UpdatedAt:     head.CreatedAt,
		}
		if entry.granted != nil {
			granted := libraryArtifactVersionMetadata(*entry.granted)
			item.GrantedVersion = &granted
		}
		if libraryControlArtifactAfter(cursor, item) {
			items = append(items, item)
		}
	}
	sortLibraryControlArtifacts(items)
	return finishLibraryControlArtifactPage(items, limit), nil
}
