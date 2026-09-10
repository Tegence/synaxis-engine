package engine

import (
	"context"
	"sort"
	"time"
)

var _ LibraryRunCorrelationStore = (*FileStore)(nil)

// RecordLibraryRunCorrelation replays every validation while holding the same
// mutex used to commit the record, so the client epoch and selected bundle it
// checks are exactly the state the record is written against.
func (s *FileStore) RecordLibraryRunCorrelation(_ context.Context, client MCPClient, raw []byte, now time.Time) (LibraryRunCorrelation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.mcpClientByIDLocked(client.ID)
	if !found {
		return LibraryRunCorrelation{}, false, ErrMCPClientNotFound
	}
	currentBuiltInVersionID, builtInManifestInstalled := s.builtInLibraryCurrentVersionLocked(usingSynaxisSkillID)
	selections, err := s.libraryAgentSurfaceSkillSelectionsLocked(current.ID)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	parsed, err := verifyLibraryRunCorrelationForClient(*current, raw, now, selections, currentBuiltInVersionID, builtInManifestInstalled)
	if err != nil {
		return LibraryRunCorrelation{}, false, err
	}
	nonceHash := libraryRunCorrelationNonceHash(current.ID, current.Epoch, parsed.Request.Nonce)
	for _, record := range s.libraryRunCorrelations {
		if record == nil || record.ClientID != current.ID || record.ClientEpoch != current.Epoch {
			continue
		}
		if sameLibraryRunCorrelationTuple(*record, *current, parsed) {
			if record.RequestDigest != parsed.RequestDigest {
				return LibraryRunCorrelation{}, false, ErrLibraryRunCorrelationConflict
			}
			return *record, true, nil
		}
		if record.NonceHash == nonceHash {
			return LibraryRunCorrelation{}, false, ErrLibraryRunCorrelationReplay
		}
	}
	record := newLibraryRunCorrelationRecord(*current, parsed, now)
	s.libraryRunCorrelations = append(s.libraryRunCorrelations, &record)
	if err := s.saveLocked(); err != nil {
		s.libraryRunCorrelations = s.libraryRunCorrelations[:len(s.libraryRunCorrelations)-1]
		return LibraryRunCorrelation{}, false, err
	}
	return record, false, nil
}

func (s *FileStore) LibraryRunCorrelations(_ context.Context, cursor LibraryRunCorrelationCursor, limit int) ([]LibraryRunCorrelation, error) {
	if limit <= 0 {
		return []LibraryRunCorrelation{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LibraryRunCorrelation, 0, len(s.libraryRunCorrelations))
	for _, record := range s.libraryRunCorrelations {
		if record != nil && libraryRunCorrelationsAfter(cursor, *record) {
			out = append(out, *record)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
