package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// MCP clients are separate from OAuth authorization-server registrations. A
// row is the durable subject/scope policy for one named AI client; the public
// OAuth client ID is optional until a future DCR/consent path atomically binds
// it. Namespace grants deliberately reference the credential-folder table,
// never the legacy endpoint-bundle tables.
const mcpClientsSchema = `
CREATE TABLE IF NOT EXISTS narthex_mcp_clients (
    id              TEXT PRIMARY KEY,
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    oauth_client_id TEXT NOT NULL DEFAULT '',
	runtime_attestor_public_key TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    epoch           TEXT NOT NULL,
    revision        BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT NOT NULL DEFAULT '',
    CONSTRAINT narthex_mcp_clients_status_check CHECK (status IN ('active','revoked'))
);
CREATE TABLE IF NOT EXISTS narthex_mcp_client_namespaces (
    client_id               TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE CASCADE,
    connection_namespace_id TEXT NOT NULL REFERENCES narthex_connection_namespaces(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, connection_namespace_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS narthex_mcp_clients_oauth_client_id_unique
    ON narthex_mcp_clients (oauth_client_id)
    WHERE oauth_client_id <> '';
CREATE INDEX IF NOT EXISTS narthex_mcp_clients_subject_status_idx
    ON narthex_mcp_clients (subject, status, slug);
CREATE INDEX IF NOT EXISTS narthex_mcp_client_namespaces_namespace_idx
    ON narthex_mcp_client_namespaces (connection_namespace_id, client_id);
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS oauth_client_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS runtime_attestor_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS epoch TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE narthex_mcp_clients ADD COLUMN IF NOT EXISTS revoked_by TEXT NOT NULL DEFAULT '';
-- A revoked client retains its history but must not permanently prevent
-- deleting an otherwise-empty credential folder. Active grants are rejected
-- by the application before delete; cascade only prunes inert grant rows.
ALTER TABLE narthex_mcp_client_namespaces
    DROP CONSTRAINT IF EXISTS narthex_mcp_client_namespaces_connection_namespace_id_fkey;
ALTER TABLE narthex_mcp_client_namespaces
    ADD CONSTRAINT narthex_mcp_client_namespaces_connection_namespace_id_fkey
    FOREIGN KEY (connection_namespace_id)
    REFERENCES narthex_connection_namespaces(id) ON DELETE CASCADE;
UPDATE narthex_mcp_clients SET status='active' WHERE status='';
UPDATE narthex_mcp_clients SET revision=1 WHERE revision < 1;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'narthex_mcp_clients_status_check'
          AND conrelid = 'narthex_mcp_clients'::regclass
    ) THEN
        ALTER TABLE narthex_mcp_clients
            ADD CONSTRAINT narthex_mcp_clients_status_check
            CHECK (status IN ('active','revoked'));
    END IF;
END $$;`

var _ MCPClientStore = (*PgStore)(nil)

const mcpClientSelect = `
SELECT c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
       c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by,
       COALESCE(
           array_agg(g.connection_namespace_id ORDER BY g.connection_namespace_id)
               FILTER (WHERE g.connection_namespace_id IS NOT NULL),
           ARRAY[]::TEXT[]
       )
FROM narthex_mcp_clients c
LEFT JOIN narthex_mcp_client_namespaces g ON g.client_id=c.id`

type mcpClientQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanMCPClient(row pgx.Row) (MCPClient, error) {
	var (
		client       MCPClient
		namespaceIDs []string
	)
	if err := row.Scan(
		&client.ID, &client.Slug, &client.Name, &client.Subject, &client.OAuthClientID, &client.RuntimeAttestorPublicKey,
		&client.Status, &client.Epoch, &client.Revision, &client.CreatedBy,
		&client.CreatedAt, &client.UpdatedAt, &client.RevokedAt, &client.RevokedBy,
		&namespaceIDs,
	); err != nil {
		return MCPClient{}, err
	}
	client.ConnectionNamespaceIDs = namespaceIDs
	if client.ConnectionNamespaceIDs == nil {
		client.ConnectionNamespaceIDs = []string{}
	}
	return client, nil
}

func loadMCPClient(ctx context.Context, q mcpClientQueryer, id string) (MCPClient, error) {
	return scanMCPClient(q.QueryRow(ctx, mcpClientSelect+`
WHERE c.id=$1
GROUP BY c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
         c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by`, id))
}

func loadMCPClientForUpdate(ctx context.Context, tx pgx.Tx, id string) (MCPClient, error) {
	// Lock the parent row first. The second select gets a stable grant set in
	// this transaction while all client mutations serialize on the row lock.
	var client MCPClient
	err := tx.QueryRow(ctx, `
SELECT id,slug,name,subject,oauth_client_id,runtime_attestor_public_key,status,epoch,revision,
       created_by,created_at,updated_at,revoked_at,revoked_by
FROM narthex_mcp_clients
WHERE id=$1
FOR UPDATE`, id).Scan(
		&client.ID, &client.Slug, &client.Name, &client.Subject, &client.OAuthClientID, &client.RuntimeAttestorPublicKey,
		&client.Status, &client.Epoch, &client.Revision, &client.CreatedBy,
		&client.CreatedAt, &client.UpdatedAt, &client.RevokedAt, &client.RevokedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if err != nil {
		return MCPClient{}, err
	}
	rows, err := tx.Query(ctx, `
SELECT connection_namespace_id
FROM narthex_mcp_client_namespaces
WHERE client_id=$1
ORDER BY connection_namespace_id`, id)
	if err != nil {
		return MCPClient{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var namespaceID string
		if err := rows.Scan(&namespaceID); err != nil {
			return MCPClient{}, err
		}
		client.ConnectionNamespaceIDs = append(client.ConnectionNamespaceIDs, namespaceID)
	}
	if err := rows.Err(); err != nil {
		return MCPClient{}, err
	}
	if client.ConnectionNamespaceIDs == nil {
		client.ConnectionNamespaceIDs = []string{}
	}
	return client, nil
}

const mcpClientRegistryLock = "mcp-client-registry"

// lockMCPClientRegistryTx is the first lock for any transaction that can
// change the durable client registry or the account/namespace membership it
// projects. The canonical order is registry, account parents where needed,
// client rows in ID order, then namespace advisory locks.
func lockMCPClientRegistryTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, mcpClientRegistryLock)
	return err
}

func (s *PgStore) backfillMCPClients(ctx context.Context) error {
	// This registry has no predecessor table to infer from. The small repair
	// pass makes a pre-release/hand-authored table fail closed instead: empty
	// epoch values are regenerated, invalid revision values are normalized, and
	// any unresolvable namespace grant is revoked rather than served.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM narthex_mcp_clients ORDER BY id FOR UPDATE`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range ids {
		client, err := loadMCPClientForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if client.Epoch == "" || client.Revision < 1 {
			epoch := client.Epoch
			if epoch == "" {
				epoch = newEpoch()
			}
			revision := client.Revision
			if revision < 1 {
				revision = 1
			}
			if _, err := tx.Exec(ctx, `UPDATE narthex_mcp_clients SET epoch=$2,revision=$3 WHERE id=$1`, client.ID, epoch, revision); err != nil {
				return err
			}
		}
		if client.Status != MCPClientStatusActive {
			continue
		}
		if err := validateMCPClientNamespacesTx(ctx, tx, client); err != nil {
			// Never reactivate a pre-release/manual registration whose grants
			// include another subject's personal credential. The normal schema
			// FK prevents a missing namespace; this check covers the ownership
			// invariant that relational constraints cannot express.
			if !errors.Is(err, ErrConnectionNamespaceNotFound) && !errors.Is(err, ErrMCPClientNamespaceSubject) {
				return err
			}
			now := time.Now().UTC()
			if _, err := tx.Exec(ctx, `
UPDATE narthex_mcp_clients
SET status='revoked',epoch=$2,revision=GREATEST(revision,1)+1,
    updated_at=$3,revoked_at=$3,revoked_by='migration'
WHERE id=$1`, client.ID, newEpoch(), now); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func validateMCPClientNamespacesTx(ctx context.Context, tx pgx.Tx, client MCPClient) error {
	for _, namespaceID := range client.ConnectionNamespaceIDs {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_connection_namespaces WHERE id=$1)`, namespaceID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: %s", ErrConnectionNamespaceNotFound, namespaceID)
		}
		var crossSubjectPersonal bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1 FROM narthex_accounts
    WHERE connection_namespace_id=$1
      AND connection_scope='personal'
      AND owner_subject <> $2
)`, namespaceID, client.Subject).Scan(&crossSubjectPersonal); err != nil {
			return err
		}
		if crossSubjectPersonal {
			return ErrMCPClientNamespaceSubject
		}
	}
	return nil
}

// lockMCPClientNamespacesTx serializes the two directions of the personal
// ownership invariant: assigning a client scope to a folder and moving or
// creating a personal account in that folder. Row locks alone cannot protect
// an empty namespace, so take deterministic transaction-scoped advisory locks
// for the durable namespace IDs before either side validates its view.
func lockMCPClientNamespacesTx(ctx context.Context, tx pgx.Tx, namespaceIDs []string) error {
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(namespaceIDs)
	if err != nil {
		return err
	}
	for _, namespaceID := range namespaceIDs {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "mcp-client-namespace:"+namespaceID); err != nil {
			return err
		}
	}
	return nil
}

// lockActiveMCPClientsForAccountMoveTx locks active registrations that could
// gain or lose an account when it moves between the supplied namespaces. The
// caller must already hold the client-registry lock. The parent-row locks then
// serialize an epoch rotation with client OAuth and revoke mutations before
// the caller takes namespace advisory locks.
func lockActiveMCPClientsForAccountMoveTx(ctx context.Context, tx pgx.Tx, namespaceIDs []string) ([]MCPClient, error) {
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(namespaceIDs)
	if err != nil {
		return nil, err
	}
	if len(namespaceIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
SELECT c.id
FROM narthex_mcp_clients c
WHERE c.status='active'
  AND EXISTS (
      SELECT 1
      FROM narthex_mcp_client_namespaces g
      WHERE g.client_id=c.id
        AND g.connection_namespace_id=ANY($1)
  )
ORDER BY c.id
FOR UPDATE`, namespaceIDs)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	clients := make([]MCPClient, 0, len(ids))
	for _, id := range ids {
		client, err := loadMCPClientForUpdate(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		// The initial SELECT filters active records and holds their parent
		// rows, but retain the check so manually-corrupt data always fails
		// closed instead of rotating a revoked historical registration.
		if client.Status == MCPClientStatusActive {
			clients = append(clients, client)
		}
	}
	return clients, nil
}

// prepareMCPClientEpochRotationForAccountOwnershipChangeTx takes the same
// deterministic locks used by an explicit account move before a legacy
// whole-account write can publish a different ownership boundary. The caller
// must already hold the client-registry lock, which freezes store-managed
// registration and scope membership while the client rows and then namespace
// advisories are acquired. The second selection is a defensive final snapshot
// of the locked rotation set. Callers persist the account and rotate the
// returned clients in the same transaction.
func prepareMCPClientEpochRotationForAccountOwnershipChangeTx(ctx context.Context, tx pgx.Tx, before, after Account) ([]MCPClient, error) {
	if !accountOwnershipChanged(before, after) {
		return nil, nil
	}
	namespaceIDs := []string{before.ConnectionNamespaceID, after.ConnectionNamespaceID}
	if _, err := lockActiveMCPClientsForAccountMoveTx(ctx, tx, namespaceIDs); err != nil {
		return nil, err
	}
	if err := lockMCPClientNamespacesTx(ctx, tx, namespaceIDs); err != nil {
		return nil, err
	}
	return lockActiveMCPClientsForAccountMoveTx(ctx, tx, namespaceIDs)
}

// rotateMCPClientEpochsForAccountMoveTx invalidates exactly the active
// registrations whose durable account-delivery boundary changes. It preserves
// the registration slug and OAuth client binding: the endpoint URL remains
// stable, while tokens and refresh grants for the previous epoch must be
// renewed before the new tool set is usable.
func rotateMCPClientEpochsForAccountMoveTx(ctx context.Context, tx pgx.Tx, clients []MCPClient, before, after Account) error {
	for _, client := range clients {
		if !mcpClientDeliveryChangesForAccountMove(client, before, after) {
			continue
		}
		tag, err := tx.Exec(ctx, `
UPDATE narthex_mcp_clients
SET epoch=$2,revision=revision+1,updated_at=now()
WHERE id=$1 AND status='active'`, client.ID, newEpoch())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrMCPClientNotFound
		}
	}
	return nil
}

func validatePersonalAccountMCPClientGrantsTx(ctx context.Context, tx pgx.Tx, account Account) error {
	if !account.IsPersonal() {
		return nil
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1
    FROM narthex_mcp_clients c
    JOIN narthex_mcp_client_namespaces g ON g.client_id=c.id
    WHERE c.status='active'
      AND g.connection_namespace_id=$1
      AND c.subject <> $2
)`, account.ConnectionNamespaceID, account.OwnerSubject).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrMCPClientNamespaceSubject
	}
	return nil
}

// ---- PgStore: MCPClientStore ----

func (s *PgStore) MCPClients(ctx context.Context) ([]MCPClient, error) {
	rows, err := s.pool.Query(ctx, mcpClientSelect+`
GROUP BY c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
         c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by
ORDER BY c.slug,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MCPClient, 0)
	for rows.Next() {
		client, err := scanMCPClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, rows.Err()
}

func (s *PgStore) ActiveMCPClients(ctx context.Context) ([]MCPClient, error) {
	rows, err := s.pool.Query(ctx, mcpClientSelect+`
WHERE c.status='active'
GROUP BY c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
         c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by
ORDER BY c.slug,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MCPClient, 0)
	for rows.Next() {
		client, err := scanMCPClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, rows.Err()
}

func (s *PgStore) MCPClient(ctx context.Context, id string) (MCPClient, bool) {
	client, err := loadMCPClient(ctx, s.pool, strings.TrimSpace(id))
	if err != nil {
		return MCPClient{}, false
	}
	return client, true
}

func (s *PgStore) MCPClientBySlug(ctx context.Context, slug string) (MCPClient, bool) {
	client, err := scanMCPClient(s.pool.QueryRow(ctx, mcpClientSelect+`
WHERE c.slug=$1
GROUP BY c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
         c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by`, normalizeMCPClientSlug(slug)))
	if err != nil {
		return MCPClient{}, false
	}
	return client, true
}

func (s *PgStore) ActiveMCPClient(ctx context.Context, endpointIdentifier string) (MCPClient, bool) {
	if client, ok := s.MCPClient(ctx, endpointIdentifier); ok && client.Status == MCPClientStatusActive {
		return client, true
	}
	client, ok := s.MCPClientBySlug(ctx, endpointIdentifier)
	if !ok || client.Status != MCPClientStatusActive {
		return MCPClient{}, false
	}
	return client, true
}

func (s *PgStore) ActiveMCPClientByOAuthClientID(ctx context.Context, oauthClientID string) (MCPClient, bool) {
	oauthClientID = strings.TrimSpace(oauthClientID)
	if oauthClientID == "" {
		return MCPClient{}, false
	}
	client, err := scanMCPClient(s.pool.QueryRow(ctx, mcpClientSelect+`
WHERE c.oauth_client_id=$1 AND c.status='active'
GROUP BY c.id,c.slug,c.name,c.subject,c.oauth_client_id,c.runtime_attestor_public_key,c.status,c.epoch,c.revision,
         c.created_by,c.created_at,c.updated_at,c.revoked_at,c.revoked_by`, oauthClientID))
	if err != nil {
		return MCPClient{}, false
	}
	return client, true
}

func (s *PgStore) CreateMCPClient(ctx context.Context, client MCPClient) (MCPClient, error) {
	if err := prepareMCPClientForCreate(&client); err != nil {
		return MCPClient{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	// This inexpensive workspace-local lock serializes the active-record cap,
	// slug suffix selection, and public OAuth-ID uniqueness across replicas.
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return MCPClient{}, err
	}
	var idExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE id=$1)`, client.ID).Scan(&idExists); err != nil {
		return MCPClient{}, err
	}
	if idExists {
		return MCPClient{}, ErrMCPClientExists
	}
	baseSlug := client.Slug
	for n := 1; ; n++ {
		candidate := baseSlug
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d", baseSlug, n)
		}
		if len(candidate) > maxMCPClientSlugBytes {
			return MCPClient{}, ErrMCPClientExists
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE slug=$1)`, candidate).Scan(&exists); err != nil {
			return MCPClient{}, err
		}
		if !exists {
			client.Slug = candidate
			break
		}
	}
	if client.OAuthClientID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE oauth_client_id=$1)`, client.OAuthClientID).Scan(&exists); err != nil {
			return MCPClient{}, err
		}
		if exists {
			return MCPClient{}, ErrMCPClientOAuthBinding
		}
	}
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM narthex_mcp_clients WHERE status='active'`).Scan(&active); err != nil {
		return MCPClient{}, err
	}
	if active >= maxActiveMCPClients {
		return MCPClient{}, ErrMCPClientLimit
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO narthex_mcp_clients
    (id,slug,name,subject,oauth_client_id,runtime_attestor_public_key,status,epoch,revision,created_by,created_at,updated_at,revoked_at,revoked_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		client.ID, client.Slug, client.Name, client.Subject, client.OAuthClientID, client.RuntimeAttestorPublicKey,
		client.Status, client.Epoch, client.Revision, client.CreatedBy,
		client.CreatedAt, client.UpdatedAt, client.RevokedAt, client.RevokedBy); err != nil {
		return MCPClient{}, err
	}
	// Once the managed manifest is installed, client creation keeps the global
	// registry lock while the built-in helper locks every durable client and
	// only then takes namespace advisories. Scope edits and account ownership
	// changes take the same registry -> client rows -> namespace order. The
	// enclosing transaction still makes the client, managed binding, namespace
	// validation, and grants one atomic commit.
	if err := s.reconcileInstalledBuiltInLibraryForNewClientTx(ctx, tx, client.ID); err != nil {
		return MCPClient{}, err
	}
	if err := lockMCPClientNamespacesTx(ctx, tx, client.ConnectionNamespaceIDs); err != nil {
		return MCPClient{}, err
	}
	if err := validateMCPClientNamespacesTx(ctx, tx, client); err != nil {
		return MCPClient{}, err
	}
	for _, namespaceID := range client.ConnectionNamespaceIDs {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_mcp_client_namespaces (client_id,connection_namespace_id)
VALUES ($1,$2)`, client.ID, namespaceID); err != nil {
			return MCPClient{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return copyMCPClient(client), nil
}

func (s *PgStore) UpdateMCPClient(ctx context.Context, update MCPClient, precondition MCPClientPrecondition) (MCPClient, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, strings.TrimSpace(update.ID))
	if err != nil {
		return MCPClient{}, err
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	name := strings.TrimSpace(update.Name)
	if err := validateMCPClientName(name); err != nil {
		return MCPClient{}, err
	}
	if update.Subject != "" && strings.TrimSpace(update.Subject) != client.Subject {
		return MCPClient{}, fmt.Errorf("%w: subject is immutable", ErrInvalidMCPClient)
	}
	if update.Slug != "" && normalizeMCPClientSlug(update.Slug) != client.Slug {
		return MCPClient{}, fmt.Errorf("%w: endpoint slug is immutable", ErrInvalidMCPClient)
	}
	key := client.RuntimeAttestorPublicKey
	if update.runtimeAttestorKeySet {
		var keyErr error
		key, keyErr = normalizeMCPClientRuntimeAttestorPublicKey(update.RuntimeAttestorPublicKey)
		if keyErr != nil {
			return MCPClient{}, keyErr
		}
	}
	if name == client.Name && key == client.RuntimeAttestorPublicKey {
		if err := tx.Commit(ctx); err != nil {
			return MCPClient{}, err
		}
		return client, nil
	}
	if err := tx.QueryRow(ctx, `
UPDATE narthex_mcp_clients
SET name=$2,runtime_attestor_public_key=$3,
    epoch=CASE WHEN runtime_attestor_public_key IS DISTINCT FROM $3 THEN $4 ELSE epoch END,
    revision=revision+1,updated_at=now()
WHERE id=$1
RETURNING epoch,revision,updated_at`, client.ID, name, key, newEpoch()).Scan(&client.Epoch, &client.Revision, &client.UpdatedAt); err != nil {
		return MCPClient{}, err
	}
	client.Name = name
	client.RuntimeAttestorPublicKey = key
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return client, nil
}

func (s *PgStore) SetMCPClientNamespaces(ctx context.Context, id string, namespaceIDs []string, precondition MCPClientPrecondition) (MCPClient, error) {
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(namespaceIDs)
	if err != nil {
		return MCPClient{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return MCPClient{}, err
	}
	client, err := loadMCPClientForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return MCPClient{}, err
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	proposed := copyMCPClient(client)
	proposed.ConnectionNamespaceIDs = namespaceIDs
	// Lock the union so a concurrent personal-account move cannot observe a
	// partially changed grant set while this request removes one folder and
	// adds another.
	lockIDs := append(append([]string(nil), client.ConnectionNamespaceIDs...), namespaceIDs...)
	if err := lockMCPClientNamespacesTx(ctx, tx, lockIDs); err != nil {
		return MCPClient{}, err
	}
	if err := validateMCPClientNamespacesTx(ctx, tx, proposed); err != nil {
		return MCPClient{}, err
	}
	if sameStrings(client.ConnectionNamespaceIDs, namespaceIDs) {
		if err := tx.Commit(ctx); err != nil {
			return MCPClient{}, err
		}
		return client, nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_mcp_client_namespaces WHERE client_id=$1`, client.ID); err != nil {
		return MCPClient{}, err
	}
	for _, namespaceID := range namespaceIDs {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_mcp_client_namespaces (client_id,connection_namespace_id)
VALUES ($1,$2)`, client.ID, namespaceID); err != nil {
			return MCPClient{}, err
		}
	}
	if err := tx.QueryRow(ctx, `
UPDATE narthex_mcp_clients
SET epoch=$2,revision=revision+1,updated_at=now()
WHERE id=$1
RETURNING epoch,revision,updated_at`, client.ID, newEpoch()).Scan(&client.Epoch, &client.Revision, &client.UpdatedAt); err != nil {
		return MCPClient{}, err
	}
	client.ConnectionNamespaceIDs = namespaceIDs
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return client, nil
}

func (s *PgStore) BindMCPClientOAuthClient(ctx context.Context, id, oauthClientID string, precondition MCPClientPrecondition, actor PlatformActor) (MCPClient, error) {
	oauthClientID = strings.TrimSpace(oauthClientID)
	if !validMCPClientOAuthClientID(oauthClientID) {
		return MCPClient{}, fmt.Errorf("%w: OAuth client ID is invalid", ErrInvalidMCPClient)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "mcp-client-oauth:"+oauthClientID); err != nil {
		return MCPClient{}, err
	}
	client, err := loadMCPClientForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return MCPClient{}, err
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	if !MCPClientAllowsActor(client, actor) {
		return MCPClient{}, fmt.Errorf("%w: actor cannot bind this client", ErrInvalidMCPClient)
	}
	if client.OAuthClientID == oauthClientID {
		if err := tx.Commit(ctx); err != nil {
			return MCPClient{}, err
		}
		return client, nil
	}
	if client.OAuthClientID != "" {
		return MCPClient{}, ErrMCPClientOAuthBinding
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE oauth_client_id=$1)`, oauthClientID).Scan(&exists); err != nil {
		return MCPClient{}, err
	}
	if exists {
		return MCPClient{}, ErrMCPClientOAuthBinding
	}
	if err := tx.QueryRow(ctx, `
UPDATE narthex_mcp_clients
SET oauth_client_id=$2,epoch=$3,revision=revision+1,updated_at=now()
WHERE id=$1
RETURNING epoch,revision,updated_at`, client.ID, oauthClientID, newEpoch()).Scan(&client.Epoch, &client.Revision, &client.UpdatedAt); err != nil {
		return MCPClient{}, err
	}
	client.OAuthClientID = oauthClientID
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return client, nil
}

func (s *PgStore) ResetMCPClientOAuthClient(ctx context.Context, id string, precondition MCPClientPrecondition) (MCPClient, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return MCPClient{}, err
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	// Always rotate, including when the old binding is already blank. That
	// makes a user-initiated reconnect an explicit invalidation boundary for
	// any token an older deployment may have minted.
	if err := tx.QueryRow(ctx, `
UPDATE narthex_mcp_clients
SET oauth_client_id='',epoch=$2,revision=revision+1,updated_at=now()
WHERE id=$1
RETURNING epoch,revision,updated_at`, client.ID, newEpoch()).Scan(&client.Epoch, &client.Revision, &client.UpdatedAt); err != nil {
		return MCPClient{}, err
	}
	client.OAuthClientID = ""
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return client, nil
}

func (s *PgStore) RevokeMCPClient(ctx context.Context, id, revokedBy string, precondition MCPClientPrecondition) (MCPClient, error) {
	revokedBy = strings.TrimSpace(revokedBy)
	if revokedBy != "" && !validActorIdentifier(revokedBy) {
		return MCPClient{}, fmt.Errorf("%w: revoker is invalid", ErrInvalidMCPClient)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MCPClient{}, err
	}
	defer tx.Rollback(ctx)
	client, err := loadMCPClientForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return MCPClient{}, err
	}
	if !mcpClientPreconditionMatches(client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		if err := tx.Commit(ctx); err != nil {
			return MCPClient{}, err
		}
		return client, nil
	}
	now := time.Now().UTC()
	if err := tx.QueryRow(ctx, `
UPDATE narthex_mcp_clients
SET status='revoked',epoch=$2,revision=revision+1,updated_at=$3,revoked_at=$3,revoked_by=$4
WHERE id=$1
RETURNING epoch,revision,updated_at,revoked_at,revoked_by`, client.ID, newEpoch(), now, revokedBy).Scan(
		&client.Epoch, &client.Revision, &client.UpdatedAt, &client.RevokedAt, &client.RevokedBy,
	); err != nil {
		return MCPClient{}, err
	}
	client.Status = MCPClientStatusRevoked
	if err := tx.Commit(ctx); err != nil {
		return MCPClient{}, err
	}
	return client, nil
}
