package engine

import (
	"context"
	"encoding/json"
	"slices"
)

func (s *FileStore) BrowserSignIns(ctx context.Context) ([]BrowserSignIn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.browserSignIns), nil
}
func (s *FileStore) WriteBrowserSignIn(ctx context.Context, input BrowserSignIn, revision int64) (BrowserSignIn, error) {
	if ctx.Err() != nil {
		return input, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := prepareBrowserFlow(input, revision)
	if err != nil {
		return f, err
	}
	index, count := -1, 0
	for i, existing := range s.browserSignIns {
		if existing.ID == f.ID {
			index = i
		}
		if existing.OwnerSubject == f.OwnerSubject && browserFlowPending(existing) {
			count++
		}
	}
	if index < 0 {
		if revision != 0 {
			return f, errBrowserRevision
		}
		if count >= 2 {
			return f, ErrLinkedAccountLimit
		}
	} else if revision == 0 || s.browserSignIns[index].Revision != revision || s.browserSignIns[index].OwnerSubject != f.OwnerSubject {
		return f, errBrowserRevision
	}
	before := s.browserSignIns
	s.browserSignIns = slices.Clone(before)
	if index < 0 {
		s.browserSignIns = append(s.browserSignIns, f)
	} else if f.State == "closed" {
		s.browserSignIns = slices.Delete(s.browserSignIns, index, index+1)
	} else {
		s.browserSignIns[index] = f
	}
	if err = s.saveLocked(); err != nil {
		s.browserSignIns = before
		return f, err
	}
	return f, nil
}
func (s *FileStore) CommitBrowserSignIn(ctx context.Context, id string, revision int64) (LinkedAccountRecord, error) {
	if ctx.Err() != nil {
		return LinkedAccountRecord{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.browserSignIns {
		if f.ID != id {
			continue
		}
		if f.Revision != revision {
			return LinkedAccountRecord{}, errBrowserRevision
		}
		parent, err := s.linkedAccountParentLocked(f.ConnectionID, f.Parent)
		if err != nil {
			return LinkedAccountRecord{}, err
		}
		records := []LinkedAccountRecord{}
		for _, r := range s.linkedAccounts {
			if r != nil {
				records = append(records, *r)
			}
		}
		record, err := browserFlowAccount(f, parent, records)
		if err != nil {
			return record, err
		}
		beforeAccounts, beforeFlows := s.linkedAccounts, s.browserSignIns
		s.linkedAccounts = slices.Clone(beforeAccounts)
		found := false
		for j, r := range s.linkedAccounts {
			if r != nil && r.ID == record.ID {
				s.linkedAccounts[j] = &record
				found = true
			}
		}
		if !found {
			s.linkedAccounts = append(s.linkedAccounts, &record)
		}
		f.State = "saved"
		f.AccountID = record.ID
		f.AccountRevision = record.Revision
		f, _ = prepareBrowserFlow(f, revision)
		s.browserSignIns = slices.Clone(beforeFlows)
		s.browserSignIns[i] = f
		if err = s.saveLocked(); err != nil {
			s.linkedAccounts = beforeAccounts
			s.browserSignIns = beforeFlows
			return LinkedAccountRecord{}, err
		}
		result := record
		result.BrowserGrants = slices.Clone(record.BrowserGrants)
		result.Browser = cloneBrowserProfile(record.Browser)
		return result, nil
	}
	return LinkedAccountRecord{}, errBrowserRevision
}
func (s *PgStore) BrowserSignIns(ctx context.Context) ([]BrowserSignIn, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,owner_subject,revision,payload FROM narthex_browser_sign_ins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BrowserSignIn{}
	for rows.Next() {
		var id, owner, raw string
		var revision int64
		if err = rows.Scan(&id, &owner, &revision, &raw); err != nil {
			return nil, err
		}
		f, err := s.decodeBrowserFlow(raw, id, owner, revision)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *PgStore) decodeBrowserFlow(raw, id, owner string, revision int64) (BrowserSignIn, error) {
	plain, err := s.dec(raw)
	if err != nil {
		return BrowserSignIn{}, err
	}
	var f BrowserSignIn
	if json.Unmarshal([]byte(plain), &f) != nil || f.ID != id || f.OwnerSubject != owner || f.Revision != revision {
		return f, errBrowserSignIn
	}
	return f, nil
}
func (s *PgStore) encodeBrowserFlow(f BrowserSignIn) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return s.enc(string(raw))
}
func (s *PgStore) WriteBrowserSignIn(ctx context.Context, input BrowserSignIn, revision int64) (BrowserSignIn, error) {
	f, err := prepareBrowserFlow(input, revision)
	if err != nil {
		return f, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return f, err
	}
	defer tx.Rollback(ctx)
	if revision == 0 {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "browser-sign-in:"+f.OwnerSubject); err != nil {
			return f, err
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM narthex_browser_sign_ins WHERE owner_subject=$1 AND state IN ('starting','ready','saving')`, f.OwnerSubject).Scan(&count); err != nil {
			return f, err
		}
		if count >= 2 {
			return f, ErrLinkedAccountLimit
		}
	}
	payload, err := s.encodeBrowserFlow(f)
	if err != nil {
		return f, err
	}
	if revision == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO narthex_browser_sign_ins(id,owner_subject,revision,state,payload) VALUES($1,$2,$3,$4,$5)`, f.ID, f.OwnerSubject, f.Revision, f.State, payload)
	} else {
		if f.State == "closed" {
			result, e := tx.Exec(ctx, `DELETE FROM narthex_browser_sign_ins WHERE id=$1 AND owner_subject=$2 AND revision=$3`, f.ID, f.OwnerSubject, revision)
			if e != nil {
				return f, e
			}
			if result.RowsAffected() != 1 {
				return f, errBrowserRevision
			}
			return f, tx.Commit(ctx)
		}
		result, e := tx.Exec(ctx, `UPDATE narthex_browser_sign_ins SET revision=$3,state=$4,payload=$5 WHERE id=$1 AND owner_subject=$2 AND revision=$6`, f.ID, f.OwnerSubject, f.Revision, f.State, payload, revision)
		err = e
		if err == nil && result.RowsAffected() != 1 {
			err = errBrowserRevision
		}
	}
	if err != nil {
		return f, err
	}
	return f, tx.Commit(ctx)
}
func (s *PgStore) CommitBrowserSignIn(ctx context.Context, id string, revision int64) (LinkedAccountRecord, error) {
	// Lock parent before the flow, matching account mutations. The initial read
	// supplies the parent ID only; the locked row is re-read and revision fenced.
	var raw, owner string
	var storedRevision int64
	if err := s.pool.QueryRow(ctx, `SELECT owner_subject,revision,payload FROM narthex_browser_sign_ins WHERE id=$1`, id).Scan(&owner, &storedRevision, &raw); err != nil {
		return LinkedAccountRecord{}, err
	}
	f, err := s.decodeBrowserFlow(raw, id, owner, storedRevision)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	parent, err := linkedAccountParentTx(ctx, tx, f.ConnectionID, f.Parent)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT owner_subject,revision,payload FROM narthex_browser_sign_ins WHERE id=$1 FOR UPDATE`, id).Scan(&owner, &storedRevision, &raw); err != nil {
		return LinkedAccountRecord{}, err
	}
	f, err = s.decodeBrowserFlow(raw, id, owner, storedRevision)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if f.Revision != revision || !f.Parent.matches(parent) {
		return LinkedAccountRecord{}, errBrowserRevision
	}
	rows, err := tx.Query(ctx, `SELECT id,payload FROM narthex_linked_accounts WHERE owner_subject=$1 AND connection_name=$2 AND incarnation_id=$3 FOR UPDATE`, f.OwnerSubject, parent.Name, parent.IncarnationID)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	records := []LinkedAccountRecord{}
	for rows.Next() {
		var accountID, payload string
		if err = rows.Scan(&accountID, &payload); err != nil {
			rows.Close()
			return LinkedAccountRecord{}, err
		}
		r, e := s.decodeLinkedAccount(payload, accountID, parent.Name, parent.IncarnationID, f.OwnerSubject)
		if e != nil {
			rows.Close()
			return LinkedAccountRecord{}, e
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := browserFlowAccount(f, parent, records)
	if err != nil {
		return record, err
	}
	payload, err := s.encodeLinkedAccount(record)
	if err != nil {
		return record, err
	}
	if f.AccountID == "" {
		_, err = tx.Exec(ctx, `INSERT INTO narthex_linked_accounts(id,connection_name,incarnation_id,owner_subject,payload) VALUES($1,$2,$3,$4,$5)`, record.ID, parent.Name, parent.IncarnationID, f.OwnerSubject, payload)
	} else {
		_, err = tx.Exec(ctx, `UPDATE narthex_linked_accounts SET payload=$2 WHERE id=$1`, record.ID, payload)
	}
	if err != nil {
		return record, err
	}
	f.State = "saved"
	f.AccountID = record.ID
	f.AccountRevision = record.Revision
	f, _ = prepareBrowserFlow(f, revision)
	payload, err = s.encodeBrowserFlow(f)
	if err != nil {
		return record, err
	}
	if _, err = tx.Exec(ctx, `UPDATE narthex_browser_sign_ins SET revision=$2,state=$3,payload=$4 WHERE id=$1`, f.ID, f.Revision, f.State, payload); err != nil {
		return record, err
	}
	return record, tx.Commit(ctx)
}

var _ BrowserSignInStore = (*FileStore)(nil)
var _ BrowserSignInStore = (*PgStore)(nil)
