package engine

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ControlIdempotencyRecord pins the first successful result of a keyed
// /control/v1 mutation for a bounded horizon. The key and resource path are
// the lookup identity; the actor reference and body digest decide whether a
// later request with the same key is a replay (identical) or a conflict.
// Only completed (2xx) results are stored, and the stored body is the same
// DTO the caller already received, so the record contains no secret.
type ControlIdempotencyRecord struct {
	Key          string    `json:"key"`
	ResourcePath string    `json:"resource_path"`
	ActorRef     string    `json:"actor_ref"`
	BodyDigest   string    `json:"body_digest"`
	Status       int       `json:"status"`
	Body         []byte    `json:"body"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ControlIdempotencyStore is the narrow durable facet behind the
// Idempotency-Key header. It is separate from every domain facet so ordinary
// handlers cannot read another request's stored response.
type ControlIdempotencyStore interface {
	// ControlIdempotencyRecord returns the unexpired record for (key, path).
	ControlIdempotencyRecord(ctx context.Context, key, resourcePath string, now time.Time) (ControlIdempotencyRecord, bool, error)
	// StoreControlIdempotencyRecord persists a record unless one already
	// exists for the same identity, in which case the existing record wins and
	// stored is false. Expired records are pruned opportunistically.
	StoreControlIdempotencyRecord(ctx context.Context, record ControlIdempotencyRecord) (ControlIdempotencyRecord, bool, error)
}

var _ ControlIdempotencyStore = (*FileStore)(nil)

// ErrInvalidControlIdempotencyRecord reports a record that does not describe
// a completed keyed control mutation (bad key, non-v1 path, non-2xx status,
// malformed digest, or an expiry that is not after creation).
var ErrInvalidControlIdempotencyRecord = errors.New("invalid control idempotency record")

func copyControlIdempotencyRecord(record ControlIdempotencyRecord) ControlIdempotencyRecord {
	record.Body = append([]byte(nil), record.Body...)
	return record
}

func validControlIdempotencyRecord(record ControlIdempotencyRecord) bool {
	return validControlIdempotencyKey(record.Key) && strings.HasPrefix(record.ResourcePath, controlV1PathPrefix) &&
		libraryDigestPattern.MatchString(record.BodyDigest) && record.Status >= 200 && record.Status <= 299 &&
		!record.CreatedAt.IsZero() && record.ExpiresAt.After(record.CreatedAt)
}

func (s *FileStore) pruneControlIdempotencyRecordsLocked(now time.Time) {
	kept := s.controlIdempotencyRecords[:0]
	for _, record := range s.controlIdempotencyRecords {
		if record != nil && record.ExpiresAt.After(now) {
			kept = append(kept, record)
		}
	}
	for i := len(kept); i < len(s.controlIdempotencyRecords); i++ {
		s.controlIdempotencyRecords[i] = nil
	}
	s.controlIdempotencyRecords = kept
}

func (s *FileStore) ControlIdempotencyRecord(_ context.Context, key, resourcePath string, now time.Time) (ControlIdempotencyRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.controlIdempotencyRecords {
		if record == nil || record.Key != key || record.ResourcePath != resourcePath || !record.ExpiresAt.After(now) {
			continue
		}
		return copyControlIdempotencyRecord(*record), true, nil
	}
	return ControlIdempotencyRecord{}, false, nil
}

func (s *FileStore) StoreControlIdempotencyRecord(_ context.Context, record ControlIdempotencyRecord) (ControlIdempotencyRecord, bool, error) {
	if !validControlIdempotencyRecord(record) {
		return ControlIdempotencyRecord{}, false, ErrInvalidControlIdempotencyRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.controlIdempotencyRecords
	s.pruneControlIdempotencyRecordsLocked(record.CreatedAt)
	for _, existing := range s.controlIdempotencyRecords {
		if existing != nil && existing.Key == record.Key && existing.ResourcePath == record.ResourcePath {
			return copyControlIdempotencyRecord(*existing), false, nil
		}
	}
	stored := copyControlIdempotencyRecord(record)
	s.controlIdempotencyRecords = append(s.controlIdempotencyRecords, &stored)
	if err := s.saveLocked(); err != nil {
		s.controlIdempotencyRecords = before
		return ControlIdempotencyRecord{}, false, err
	}
	return copyControlIdempotencyRecord(stored), true, nil
}
