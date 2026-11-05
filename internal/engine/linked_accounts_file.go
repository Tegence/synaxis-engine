package engine

import (
	"context"
	"slices"
	"sort"
)

var _ LinkedAccountStore = (*FileStore)(nil)

func (s *FileStore) LinkedAccounts(ctx context.Context, subject string) ([]LinkedAccountRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []LinkedAccountRecord{}
	for _, record := range s.linkedAccounts {
		if record != nil && record.OwnerSubject == subject {
			copy := *record
			copy.BrowserGrants = slices.Clone(record.BrowserGrants)
			copy.Browser = cloneBrowserProfile(record.Browser)
			copy.OAuth = cloneOAuthCredential(record.OAuth)
			out = append(out, copy)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *FileStore) linkedAccountParentLocked(name string, p AccountPolicyPrecondition) (Account, error) {
	for _, parent := range s.accounts {
		if parent != nil && parent.Name == name && p.matches(*parent) {
			return *parent, nil
		}
	}
	return Account{}, ErrAccountPolicyPrecondition
}

func (s *FileStore) CreateLinkedAccount(ctx context.Context, input LinkedAccountRecord, p AccountPolicyPrecondition) (LinkedAccountRecord, error) {
	if err := ctx.Err(); err != nil {
		return LinkedAccountRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, err := s.linkedAccountParentLocked(input.ConnectionID, p)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := newLinkedAccount(input, parent)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	count := 0
	for _, existing := range s.linkedAccounts {
		if existing != nil && existing.ConnectionID == parent.Name && existing.OwnerSubject == record.OwnerSubject && existing.Boundary.IncarnationID == parent.IncarnationID {
			count++
		}
	}
	if count >= maxLinkedAccountsPerConnection {
		return LinkedAccountRecord{}, ErrLinkedAccountLimit
	}
	before := s.linkedAccounts
	s.linkedAccounts = append(slices.Clone(before), &record)
	if err := s.saveLocked(); err != nil {
		s.linkedAccounts = before
		return LinkedAccountRecord{}, err
	}
	result := record
	result.Browser = cloneBrowserProfile(record.Browser)
	result.OAuth = cloneOAuthCredential(record.OAuth)
	return result, nil
}

func (s *FileStore) MutateLinkedAccount(ctx context.Context, connectionID, id, subject string, revision int64, p AccountPolicyPrecondition, mutation LinkedAccountMutation) (LinkedAccountRecord, error) {
	if err := ctx.Err(); err != nil {
		return LinkedAccountRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, err := s.linkedAccountParentLocked(connectionID, p)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	for i, record := range s.linkedAccounts {
		if record == nil || record.ID != id || record.ConnectionID != connectionID || record.OwnerSubject != subject || record.Boundary.IncarnationID != parent.IncarnationID {
			continue
		}
		if revision < 1 || record.Revision != revision {
			return LinkedAccountRecord{}, ErrLinkedAccountRevision
		}
		updated, err := mutateLinkedAccount(*record, parent, mutation)
		if err != nil {
			return LinkedAccountRecord{}, err
		}
		before := s.linkedAccounts
		s.linkedAccounts = slices.Clone(before)
		if mutation.Remove {
			s.linkedAccounts = slices.Delete(s.linkedAccounts, i, i+1)
		} else {
			s.linkedAccounts[i] = &updated
		}
		if err := s.saveLocked(); err != nil {
			s.linkedAccounts = before
			return LinkedAccountRecord{}, err
		}
		result := updated
		result.BrowserGrants = slices.Clone(updated.BrowserGrants)
		result.Browser = cloneBrowserProfile(updated.Browser)
		result.OAuth = cloneOAuthCredential(updated.OAuth)
		return result, nil
	}
	return LinkedAccountRecord{}, ErrLinkedAccountNotFound
}
