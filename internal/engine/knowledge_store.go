package engine

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (s *FileStore) PutKnowledge(ctx context.Context, d KnowledgeDocument) error {
	if !d.valid() {
		return ErrKnowledgeConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := d.Source + "\x00" + d.ID
	old, exists := s.knowledgeDocuments[key]
	if exists && d.Version < old.Version {
		return nil
	}
	if exists && d.Version == old.Version {
		if knowledgeDigest(d) != knowledgeDigest(old) {
			return ErrKnowledgeConflict
		}
		return nil
	}
	if !exists && len(s.knowledgeDocuments) >= knowledgeMaxDocuments {
		return ErrKnowledgeCapacity
	}
	if s.knowledgeDocuments == nil {
		s.knowledgeDocuments = map[string]KnowledgeDocument{}
	}
	s.knowledgeDocuments[key] = d
	if err := s.saveLocked(); err != nil {
		if exists {
			s.knowledgeDocuments[key] = old
		} else {
			delete(s.knowledgeDocuments, key)
		}
		return err
	}
	return nil
}
func (s *FileStore) VisitKnowledge(ctx context.Context, source string, visit func(KnowledgeDocument) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.knowledgeDocuments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.Source == source {
			if err := visit(d); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *PgStore) PutKnowledge(ctx context.Context, d KnowledgeDocument) error {
	if !d.valid() {
		return ErrKnowledgeConflict
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize admission and version changes, including concurrent first inserts.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(738451922)`); err != nil {
		return err
	}
	var version int64
	var digest string
	err = tx.QueryRow(ctx, `SELECT version,digest FROM synaxis_knowledge_documents WHERE source=$1 AND id=$2`, d.Source, d.ID).Scan(&version, &digest)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	hash := knowledgeDigest(d)
	if exists && d.Version < version {
		return nil
	}
	if exists && d.Version == version {
		if hash != digest {
			return ErrKnowledgeConflict
		}
		return nil
	}
	if !exists {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM synaxis_knowledge_documents`).Scan(&count); err != nil {
			return err
		}
		if count >= knowledgeMaxDocuments {
			return ErrKnowledgeCapacity
		}
	}
	raw, _ := json.Marshal(d)
	encrypted, err := s.enc(string(raw))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO synaxis_knowledge_documents(source,id,version,digest,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,id) DO UPDATE SET version=EXCLUDED.version,digest=EXCLUDED.digest,payload=EXCLUDED.payload`, d.Source, d.ID, d.Version, hash, encrypted)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *PgStore) VisitKnowledge(ctx context.Context, source string, visit func(KnowledgeDocument) error) error {
	rows, err := s.pool.Query(ctx, `SELECT payload FROM synaxis_knowledge_documents WHERE source=$1 ORDER BY id`, source)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		raw, err = s.dec(raw)
		if err != nil {
			return err
		}
		var d KnowledgeDocument
		if err = json.Unmarshal([]byte(raw), &d); err != nil {
			return err
		}
		if err = visit(d); err != nil {
			return err
		}
	}
	return rows.Err()
}
