package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func lockWebsiteAccounts(ctx context.Context, tx pgx.Tx, owner string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "website-accounts:"+owner)
	return err
}

func (s *PgStore) createWebsiteAccount(ctx context.Context, input LinkedAccountRecord, p AccountPolicyPrecondition) (LinkedAccountRecord, error) {
	if p != (AccountPolicyPrecondition{}) || !input.isWebsiteAccount() {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	record, err := newLinkedAccount(input, Account{})
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockWebsiteAccounts(ctx, tx, record.OwnerSubject); err != nil {
		return LinkedAccountRecord{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM narthex_website_accounts WHERE owner_subject=$1`, record.OwnerSubject).Scan(&count); err != nil {
		return LinkedAccountRecord{}, err
	}
	if count >= maxLinkedAccountsPerConnection {
		return LinkedAccountRecord{}, ErrLinkedAccountLimit
	}
	payload, err := s.encodeLinkedAccount(record)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO narthex_website_accounts(id,owner_subject,payload) VALUES($1,$2,$3)`, record.ID, record.OwnerSubject, payload); err != nil {
		return LinkedAccountRecord{}, err
	}
	return record, tx.Commit(ctx)
}

func (s *PgStore) mutateWebsiteAccount(ctx context.Context, id, subject string, revision int64, p AccountPolicyPrecondition, mutation LinkedAccountMutation) (LinkedAccountRecord, error) {
	if p != (AccountPolicyPrecondition{}) || !validActorIdentifier(subject) {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockWebsiteAccounts(ctx, tx, subject); err != nil {
		return LinkedAccountRecord{}, err
	}
	var raw string
	err = tx.QueryRow(ctx, `SELECT payload FROM narthex_website_accounts WHERE id=$1 AND owner_subject=$2 FOR UPDATE`, id, subject).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return LinkedAccountRecord{}, ErrLinkedAccountNotFound
	}
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := s.decodeLinkedAccount(raw, id, "", "", subject)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if !record.isWebsiteAccount() {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	if revision < 1 || revision != record.Revision {
		return LinkedAccountRecord{}, ErrLinkedAccountRevision
	}
	updated, err := mutateLinkedAccount(record, Account{}, mutation)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if mutation.Remove {
		_, err = tx.Exec(ctx, `DELETE FROM narthex_website_accounts WHERE id=$1 AND owner_subject=$2`, id, subject)
	} else {
		var payload string
		payload, err = s.encodeLinkedAccount(updated)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE narthex_website_accounts SET payload=$2 WHERE id=$1 AND owner_subject=$3`, id, payload, subject)
		}
	}
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	return updated, tx.Commit(ctx)
}

func (s *PgStore) commitWebsiteSignIn(ctx context.Context, initial BrowserSignIn, revision int64) (LinkedAccountRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockWebsiteAccounts(ctx, tx, initial.OwnerSubject); err != nil {
		return LinkedAccountRecord{}, err
	}
	var raw, owner string
	var storedRevision int64
	if err = tx.QueryRow(ctx, `SELECT owner_subject,revision,payload FROM narthex_website_sign_ins WHERE id=$1 FOR UPDATE`, initial.ID).Scan(&owner, &storedRevision, &raw); err != nil {
		return LinkedAccountRecord{}, err
	}
	f, err := s.decodeBrowserFlow(raw, initial.ID, owner, storedRevision)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if f.Revision != revision || !f.isWebsiteSignIn() || f.OwnerSubject != initial.OwnerSubject {
		return LinkedAccountRecord{}, errBrowserRevision
	}
	rows, err := tx.Query(ctx, `SELECT id,payload FROM narthex_website_accounts WHERE owner_subject=$1 FOR UPDATE`, f.OwnerSubject)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	records := []LinkedAccountRecord{}
	for rows.Next() {
		var id, payload string
		if err = rows.Scan(&id, &payload); err != nil {
			rows.Close()
			return LinkedAccountRecord{}, err
		}
		r, e := s.decodeLinkedAccount(payload, id, "", "", f.OwnerSubject)
		if e != nil {
			rows.Close()
			return LinkedAccountRecord{}, e
		}
		if !r.isWebsiteAccount() {
			rows.Close()
			return LinkedAccountRecord{}, ErrLinkedAccountInvalid
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := browserFlowAccount(f, Account{}, records)
	if err != nil {
		return record, err
	}
	payload, err := s.encodeLinkedAccount(record)
	if err != nil {
		return record, err
	}
	if f.AccountID == "" {
		_, err = tx.Exec(ctx, `INSERT INTO narthex_website_accounts(id,owner_subject,payload) VALUES($1,$2,$3)`, record.ID, record.OwnerSubject, payload)
	} else {
		_, err = tx.Exec(ctx, `UPDATE narthex_website_accounts SET payload=$2 WHERE id=$1 AND owner_subject=$3`, record.ID, payload, record.OwnerSubject)
	}
	if err != nil {
		return record, err
	}
	f.State, f.AccountID, f.AccountRevision = "saved", record.ID, record.Revision
	f, err = prepareBrowserFlow(f, revision)
	if err != nil {
		return record, err
	}
	payload, err = s.encodeBrowserFlow(f)
	if err != nil {
		return record, err
	}
	if _, err = tx.Exec(ctx, `UPDATE narthex_website_sign_ins SET revision=$2,state=$3,payload=$4 WHERE id=$1`, f.ID, f.Revision, f.State, payload); err != nil {
		return record, err
	}
	return record, tx.Commit(ctx)
}
