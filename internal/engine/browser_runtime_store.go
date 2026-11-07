package engine

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

func prepareBrowserRun(r BrowserRun, revision int64) (BrowserRun, error) {
	if r.ID != browserRunID(r.ExecutionID, r.AccountID) || !validActorIdentifier(r.Owner) || !validActorIdentifier(r.ExecutionID) || r.ClientID == "" || r.GrantID == "" || !validBrowserProfile(r.Profile) || len(r.Actions) > 128 || r.ExpiresAt.IsZero() {
		return r, errBrowserSignIn
	}
	switch r.State {
	case "starting", "ready", "closing", "closed":
	default:
		return r, errBrowserSignIn
	}
	r.Revision = revision + 1
	return cloneBrowserRun(r), nil
}
func (s *FileStore) BrowserRuns(ctx context.Context) ([]BrowserRun, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BrowserRun, 0, len(s.browserRuns))
	for _, r := range s.browserRuns {
		out = append(out, cloneBrowserRun(r))
	}
	return out, nil
}
func (s *FileStore) WriteBrowserRun(ctx context.Context, r BrowserRun, revision int64) (BrowserRun, error) {
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := prepareBrowserRun(r, revision)
	if err != nil {
		return r, err
	}
	index := -1
	for i, existing := range s.browserRuns {
		if existing.ID == r.ID {
			index = i
		}
		if revision == 0 && existing.State != "closed" && existing.Profile.ProfileID == r.Profile.ProfileID && existing.Profile.ConfigurationID == r.Profile.ConfigurationID {
			return r, errBrowserRevision
		}
	}
	if index < 0 && revision != 0 || index >= 0 && s.browserRuns[index].Revision != revision {
		return r, errBrowserRevision
	}
	before := s.browserRuns
	s.browserRuns = slices.Clone(before)
	if index < 0 {
		s.browserRuns = append(s.browserRuns, r)
	} else {
		s.browserRuns[index] = r
	}
	// Closed tombstones prevent reopening the same execution after completion.
	s.browserRuns = slices.DeleteFunc(s.browserRuns, func(v BrowserRun) bool { return v.State == "closed" && time.Now().After(v.ExpiresAt.Add(24*time.Hour)) })
	if err = s.saveLocked(); err != nil {
		s.browserRuns = before
		return r, err
	}
	return cloneBrowserRun(r), nil
}
func (s *PgStore) BrowserRuns(ctx context.Context) ([]BrowserRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,revision,payload FROM narthex_browser_runs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BrowserRun{}
	for rows.Next() {
		var id, raw string
		var revision int64
		if err = rows.Scan(&id, &revision, &raw); err != nil {
			return nil, err
		}
		r, err := s.decodeBrowserRun(id, revision, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *PgStore) decodeBrowserRun(id string, revision int64, raw string) (BrowserRun, error) {
	plain, err := s.dec(raw)
	if err != nil {
		return BrowserRun{}, err
	}
	var r BrowserRun
	if json.Unmarshal([]byte(plain), &r) != nil || r.ID != id || r.Revision != revision {
		return r, errBrowserSignIn
	}
	return r, nil
}
func (s *PgStore) WriteBrowserRun(ctx context.Context, r BrowserRun, revision int64) (BrowserRun, error) {
	r, err := prepareBrowserRun(r, revision)
	if err != nil {
		return r, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	// All creates serialize against the profile: no concurrent sessions may load
	// the same saved context. Updates use CAS and never acquire a second lock.
	if revision == 0 {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "browser-runtime:"+r.Profile.ConfigurationID+":"+r.Profile.ProfileID); err != nil {
			return r, err
		}
		rows, err := tx.Query(ctx, `SELECT id,revision,payload FROM narthex_browser_runs`)
		if err != nil {
			return r, err
		}
		busy := false
		for rows.Next() {
			var id, raw string
			var rev int64
			if err = rows.Scan(&id, &rev, &raw); err != nil {
				rows.Close()
				return r, err
			}
			v, e := s.decodeBrowserRun(id, rev, raw)
			if e != nil {
				rows.Close()
				return r, e
			}
			if v.State != "closed" && v.Profile.ProfileID == r.Profile.ProfileID && v.Profile.ConfigurationID == r.Profile.ConfigurationID {
				busy = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return r, err
		}
		if busy {
			return r, errBrowserRevision
		}
	}
	raw, _ := json.Marshal(r)
	payload, err := s.enc(string(raw))
	if err != nil {
		return r, err
	}
	if revision > 0 && r.State == "closed" && time.Now().After(r.ExpiresAt.Add(24*time.Hour)) {
		result, e := tx.Exec(ctx, `DELETE FROM narthex_browser_runs WHERE id=$1 AND revision=$2`, r.ID, revision)
		if e != nil {
			return r, e
		}
		if result.RowsAffected() != 1 {
			return r, errBrowserRevision
		}
		return r, tx.Commit(ctx)
	}
	var n int64
	if revision == 0 {
		result, e := tx.Exec(ctx, `INSERT INTO narthex_browser_runs(id,revision,payload) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, r.ID, r.Revision, payload)
		err = e
		n = result.RowsAffected()
	} else {
		result, e := tx.Exec(ctx, `UPDATE narthex_browser_runs SET revision=$2,payload=$3 WHERE id=$1 AND revision=$4`, r.ID, r.Revision, payload, revision)
		err = e
		n = result.RowsAffected()
	}
	if err != nil {
		return r, err
	}
	if n != 1 {
		return r, errBrowserRevision
	}
	return r, tx.Commit(ctx)
}
