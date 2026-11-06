package engine

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

var _ LinkedAccountStore = (*PgStore)(nil)

func (s *PgStore) encryptExistingLinkedAccounts(ctx context.Context) error {
	for _, table := range []struct{ read, write string }{
		{`SELECT id,payload FROM narthex_website_sign_ins ORDER BY id`, `UPDATE narthex_website_sign_ins SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT id,payload FROM narthex_website_accounts ORDER BY id`, `UPDATE narthex_website_accounts SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT id,payload FROM narthex_integration_accounts ORDER BY id`, `UPDATE narthex_integration_accounts SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT id,payload FROM narthex_browser_runs ORDER BY id`, `UPDATE narthex_browser_runs SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT id,payload FROM narthex_browser_sign_ins ORDER BY id`, `UPDATE narthex_browser_sign_ins SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT id,payload FROM narthex_linked_accounts ORDER BY id`, `UPDATE narthex_linked_accounts SET payload=$2 WHERE id=$1 AND payload=$3`},
		{`SELECT state_hash,payload FROM narthex_linked_oauth_flows ORDER BY state_hash`, `UPDATE narthex_linked_oauth_flows SET payload=$2 WHERE state_hash=$1 AND payload=$3`},
	} {
		if err := s.encryptLinkedAccountPayloads(ctx, table.read, table.write); err != nil {
			return err
		}
	}
	return nil
}
func (s *PgStore) encryptLinkedAccountPayloads(ctx context.Context, read, write string) error {
	rows, err := s.pool.Query(ctx, read)
	if err != nil {
		return err
	}
	type storedPayload struct{ id, raw string }
	var payloads []storedPayload
	for rows.Next() {
		var payload storedPayload
		if err := rows.Scan(&payload.id, &payload.raw); err != nil {
			rows.Close()
			return err
		}
		payloads = append(payloads, payload)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, payload := range payloads {
		encrypted, err := s.enc(payload.raw)
		if err != nil {
			return err
		}
		if encrypted != payload.raw {
			// Do not overwrite a concurrent rotation, rename or disconnection.
			if _, err := s.pool.Exec(ctx, write, payload.id, encrypted, payload.raw); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *PgStore) encodeLinkedAccount(record LinkedAccountRecord) (string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return s.enc(string(raw))
}

func (s *PgStore) decodeLinkedAccount(raw, id, connectionID, incarnation, subject string) (LinkedAccountRecord, error) {
	plain, err := s.dec(raw)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	var record LinkedAccountRecord
	if err := json.Unmarshal([]byte(plain), &record); err != nil {
		return LinkedAccountRecord{}, err
	}
	if record.ID != id || record.ConnectionID != connectionID || record.Boundary.IncarnationID != incarnation || record.OwnerSubject != subject {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	return record, nil
}

func (s *PgStore) LinkedAccounts(ctx context.Context, subject string) ([]LinkedAccountRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,connection_name,incarnation_id,payload,'linked'::text AS kind,''::text AS integration_id FROM narthex_linked_accounts WHERE owner_subject=$1
UNION ALL SELECT id,''::text,''::text,payload,'website'::text,''::text FROM narthex_website_accounts WHERE owner_subject=$1
UNION ALL SELECT id,''::text,''::text,payload,'integration'::text,integration_id FROM narthex_integration_accounts WHERE owner_subject=$1 ORDER BY id`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LinkedAccountRecord{}
	for rows.Next() {
		var id, connectionID, incarnation, raw, kind, integrationID string
		if err := rows.Scan(&id, &connectionID, &incarnation, &raw, &kind, &integrationID); err != nil {
			return nil, err
		}
		record, err := s.decodeLinkedAccount(raw, id, connectionID, incarnation, subject)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "website":
			if !record.isWebsiteAccount() {
				return nil, ErrLinkedAccountInvalid
			}
		case "integration":
			if !record.isIntegrationAccount() || record.IntegrationID != integrationID {
				return nil, ErrLinkedAccountInvalid
			}
		default:
			if record.IntegrationID != "" {
				return nil, ErrLinkedAccountInvalid
			}
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func linkedAccountParentTx(ctx context.Context, tx pgx.Tx, name string, p AccountPolicyPrecondition) (Account, error) {
	var parent Account
	err := tx.QueryRow(ctx, `SELECT name,incarnation_id,revision,connection_namespace_id,connection_scope,owner_subject,url,caller_delegated
FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name).Scan(&parent.Name, &parent.IncarnationID, &parent.Revision, &parent.ConnectionNamespaceID, &parent.ConnectionScope, &parent.OwnerSubject, &parent.URL, &parent.CallerDelegated)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountPolicyPrecondition
	}
	if err != nil {
		return Account{}, err
	}
	if !p.matches(parent) {
		return Account{}, ErrAccountPolicyPrecondition
	}
	return parent, nil
}

func (s *PgStore) CreateLinkedAccount(ctx context.Context, input LinkedAccountRecord, p AccountPolicyPrecondition) (LinkedAccountRecord, error) {
	if input.ConnectionID == "" && input.IntegrationID != "" {
		return s.createIntegrationAccount(ctx, input, p)
	}
	if input.ConnectionID == "" {
		return s.createWebsiteAccount(ctx, input, p)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	parent, err := linkedAccountParentTx(ctx, tx, input.ConnectionID, p)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := newLinkedAccount(input, parent)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM narthex_linked_accounts WHERE connection_name=$1 AND incarnation_id=$2 AND owner_subject=$3`, parent.Name, parent.IncarnationID, record.OwnerSubject).Scan(&count); err != nil {
		return LinkedAccountRecord{}, err
	}
	if count >= maxLinkedAccountsPerConnection {
		return LinkedAccountRecord{}, ErrLinkedAccountLimit
	}
	payload, err := s.encodeLinkedAccount(record)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO narthex_linked_accounts (id,connection_name,incarnation_id,owner_subject,payload) VALUES ($1,$2,$3,$4,$5)`, record.ID, record.ConnectionID, record.Boundary.IncarnationID, record.OwnerSubject, payload)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LinkedAccountRecord{}, err
	}
	return record, nil
}

func (s *PgStore) MutateLinkedAccount(ctx context.Context, connectionID, id, subject string, revision int64, p AccountPolicyPrecondition, mutation LinkedAccountMutation) (LinkedAccountRecord, error) {
	if connectionID == "" && mutation.Integration {
		return s.mutateIntegrationAccount(ctx, id, subject, revision, p, mutation)
	}
	if connectionID == "" {
		return s.mutateWebsiteAccount(ctx, id, subject, revision, p, mutation)
	}
	if mutation.Integration {
		return LinkedAccountRecord{}, ErrLinkedAccountInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	defer tx.Rollback(ctx)
	parent, err := linkedAccountParentTx(ctx, tx, connectionID, p)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	var raw string
	err = tx.QueryRow(ctx, `SELECT payload FROM narthex_linked_accounts WHERE id=$1 AND connection_name=$2 AND owner_subject=$3 AND incarnation_id=$4 FOR UPDATE`, id, connectionID, subject, parent.IncarnationID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return LinkedAccountRecord{}, ErrLinkedAccountNotFound
	}
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	record, err := s.decodeLinkedAccount(raw, id, connectionID, parent.IncarnationID, subject)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if revision < 1 || record.Revision != revision {
		return LinkedAccountRecord{}, ErrLinkedAccountRevision
	}
	updated, err := mutateLinkedAccount(record, parent, mutation)
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if mutation.Remove {
		_, err = tx.Exec(ctx, `DELETE FROM narthex_linked_accounts WHERE id=$1`, id)
	} else {
		var payload string
		payload, err = s.encodeLinkedAccount(updated)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE narthex_linked_accounts SET payload=$2 WHERE id=$1`, id, payload)
		}
	}
	if err != nil {
		return LinkedAccountRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LinkedAccountRecord{}, err
	}
	return updated, nil
}
