package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func lockIntegrationAccounts(ctx context.Context, tx pgx.Tx, owner string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "integration-accounts:"+owner)
	return err
}

func (s *PgStore) createIntegrationAccount(ctx context.Context, input LinkedAccountRecord, p AccountPolicyPrecondition) (LinkedAccountRecord, error) {
	if p != (AccountPolicyPrecondition{}) || !input.isIntegrationAccount() {
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
	if err = lockIntegrationAccounts(ctx, tx, record.OwnerSubject); err != nil {
		return LinkedAccountRecord{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM narthex_integration_accounts WHERE owner_subject=$1`, record.OwnerSubject).Scan(&count); err != nil {
		return LinkedAccountRecord{}, err
	}
	if count >= maxLinkedAccountsPerConnection {
		return LinkedAccountRecord{}, ErrLinkedAccountLimit
	}
	payload, err := s.encodeLinkedAccount(record)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO narthex_integration_accounts(id,integration_id,owner_subject,payload) VALUES($1,$2,$3,$4)`, record.ID, record.IntegrationID, record.OwnerSubject, payload); err != nil {
		return LinkedAccountRecord{}, err
	}
	return record, tx.Commit(ctx)
}

func (s *PgStore) mutateIntegrationAccount(ctx context.Context, id, subject string, revision int64, p AccountPolicyPrecondition, mutation LinkedAccountMutation) (LinkedAccountRecord, error) {
	if p != (AccountPolicyPrecondition{}) || !validActorIdentifier(subject) {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockIntegrationAccounts(ctx, tx, subject); err != nil {
		return LinkedAccountRecord{}, err
	}
	var raw, integrationID string
	err = tx.QueryRow(ctx, `SELECT integration_id,payload FROM narthex_integration_accounts WHERE id=$1 AND owner_subject=$2 FOR UPDATE`, id, subject).Scan(&integrationID, &raw)
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
	if !record.isIntegrationAccount() || record.IntegrationID != integrationID {
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
		_, err = tx.Exec(ctx, `DELETE FROM narthex_integration_accounts WHERE id=$1 AND owner_subject=$2`, id, subject)
	} else {
		var payload string
		payload, err = s.encodeLinkedAccount(updated)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE narthex_integration_accounts SET payload=$2 WHERE id=$1 AND owner_subject=$3`, id, payload, subject)
		}
	}
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	return updated, tx.Commit(ctx)
}
