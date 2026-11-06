package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"time"
)

var _ LibraryArtifactEraser = (*FileStore)(nil)

// fileLibraryArtifactTombstoneSuffix names the FileStore's erasure sidecar.
// Tombstones hold only an artifact ID and its deletion time; they live beside
// the main state file so the main on-disk shape is unchanged.
const fileLibraryArtifactTombstoneSuffix = ".library-artifact-tombstones.json"

type fileLibraryArtifactTombstones struct {
	Tombstones map[string]time.Time `json:"tombstones"`
}

// DeleteLibraryArtifact erases one artifact with every version, private media
// blob, exact-version grant, collaboration state (grants, threads and
// receipts), revision receipt, chat-save record in either direction, and the
// producing run when no other artifact or runtime attestation still names it.
// The tombstone is written first: a crash between the two writes leaves a
// tombstone for a live artifact, which the next delete simply completes.
func (s *FileStore) DeleteLibraryArtifact(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	artifact := s.libraryArtifactLocked(id)
	if artifact == nil {
		tombstones, err := s.readLibraryArtifactTombstonesLocked()
		if err != nil {
			return false, err
		}
		_, deleted := tombstones.Tombstones[id]
		return deleted, nil
	}
	if err := s.recordLibraryArtifactTombstoneLocked(id, time.Now().UTC()); err != nil {
		return true, err
	}

	runID := artifact.RunID
	versions := map[string]bool{}
	for _, version := range s.libraryArtifactVersions {
		if version != nil && version.ArtifactID == id {
			versions[version.ID] = true
		}
	}
	oldArtifacts, oldVersions, oldMedia := s.libraryArtifacts, s.libraryArtifactVersions, s.libraryArtifactMediaBlobs
	oldGrants, oldSaves, oldReceipts, oldRuns := s.libraryArtifactGrants, s.libraryChatSaves, s.libraryMCPClientArtifactVersionRequests, s.libraryRuns
	oldCollaboration, hadCollaboration := s.libraryCollaborations[id]

	s.libraryArtifacts = slices.DeleteFunc(slices.Clone(s.libraryArtifacts), func(a *LibraryArtifact) bool { return a != nil && a.ID == id })
	s.libraryArtifactVersions = slices.DeleteFunc(slices.Clone(s.libraryArtifactVersions), func(v *LibraryArtifactVersion) bool {
		return v != nil && (v.ArtifactID == id || versions[v.ID])
	})
	s.libraryArtifactMediaBlobs = slices.DeleteFunc(slices.Clone(s.libraryArtifactMediaBlobs), func(b *libraryArtifactMediaBlob) bool {
		return b != nil && versions[b.ArtifactVersionID]
	})
	s.libraryArtifactGrants = slices.DeleteFunc(slices.Clone(s.libraryArtifactGrants), func(g *LibraryArtifactGrant) bool { return g != nil && g.ArtifactID == id })
	s.libraryChatSaves = slices.DeleteFunc(slices.Clone(s.libraryChatSaves), func(r *libraryChatSaveRecord) bool {
		return r != nil && (r.SourceArtifactID == id || r.ArtifactID == id)
	})
	s.libraryMCPClientArtifactVersionRequests = slices.DeleteFunc(slices.Clone(s.libraryMCPClientArtifactVersionRequests), func(r *libraryMCPClientArtifactVersionRequestRecord) bool {
		return r != nil && r.ArtifactID == id
	})
	delete(s.libraryCollaborations, id)
	if runID != "" && !s.libraryRunStillReferencedLocked(runID) {
		s.libraryRuns = slices.DeleteFunc(slices.Clone(s.libraryRuns), func(r *LibraryRun) bool { return r != nil && r.ID == runID })
	}

	if err := s.saveLocked(); err != nil {
		s.libraryArtifacts, s.libraryArtifactVersions, s.libraryArtifactMediaBlobs = oldArtifacts, oldVersions, oldMedia
		s.libraryArtifactGrants, s.libraryChatSaves, s.libraryMCPClientArtifactVersionRequests, s.libraryRuns = oldGrants, oldSaves, oldReceipts, oldRuns
		if hadCollaboration {
			s.libraryCollaborations[id] = oldCollaboration
		}
		return true, err
	}
	return true, nil
}

// libraryRunStillReferencedLocked keeps a run another artifact or a runtime
// attestation still names; it runs after the erased artifact was removed.
func (s *FileStore) libraryRunStillReferencedLocked(runID string) bool {
	for _, artifact := range s.libraryArtifacts {
		if artifact != nil && artifact.RunID == runID {
			return true
		}
	}
	for _, record := range s.libraryRuntimeAttestations {
		if record != nil && record.RunID == runID {
			return true
		}
	}
	return false
}

func (s *FileStore) libraryArtifactTombstonePath() string {
	return s.path + fileLibraryArtifactTombstoneSuffix
}

func (s *FileStore) readLibraryArtifactTombstonesLocked() (fileLibraryArtifactTombstones, error) {
	tombstones := fileLibraryArtifactTombstones{Tombstones: map[string]time.Time{}}
	raw, err := os.ReadFile(s.libraryArtifactTombstonePath())
	if errors.Is(err, os.ErrNotExist) {
		return tombstones, nil
	}
	if err != nil {
		return tombstones, err
	}
	if err := json.Unmarshal(raw, &tombstones); err != nil {
		return tombstones, err
	}
	if tombstones.Tombstones == nil {
		tombstones.Tombstones = map[string]time.Time{}
	}
	return tombstones, nil
}

func (s *FileStore) recordLibraryArtifactTombstoneLocked(id string, at time.Time) error {
	tombstones, err := s.readLibraryArtifactTombstonesLocked()
	if err != nil {
		return err
	}
	if _, exists := tombstones.Tombstones[id]; exists {
		return nil
	}
	tombstones.Tombstones[id] = at
	encoded, err := json.MarshalIndent(tombstones, "", "  ")
	if err != nil {
		return err
	}
	path := s.libraryArtifactTombstonePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
