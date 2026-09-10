package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore is the Postgres-backed AccountStore — the deployable one (tokens
// survive Cloud Run restarts). Plain columns, no oauth_sessions black box.
type PgStore struct {
	pool   *pgxpool.Pool
	cipher *Cipher // nil = no at-rest encryption (passthrough)

	// audit accepts durable activity without letting Postgres latency block an
	// already-governed tool call. It is initialized only after schema bootstrap
	// succeeds, so a partially constructed store never owns a worker.
	audit *auditWriter

	poolCloseOnce           sync.Once
	poolCloseAfterAuditOnce sync.Once
}

var _ NamespaceStore = (*PgStore)(nil)
var _ ConnectionNamespaceStore = (*PgStore)(nil)
var _ StaticOAuthConfigStore = (*PgStore)(nil)
var _ LibraryMemoryStore = (*PgStore)(nil)

const (
	enginePostgresMaxConns        int32 = 2
	enginePostgresMaxConnLifetime       = 30 * time.Minute
	enginePostgresMaxConnIdleTime       = 5 * time.Minute
)

// SetCipher enables AES-GCM encryption of PgStore's sensitive content at rest.
func (s *PgStore) SetCipher(c *Cipher) { s.cipher = c }

func (s *PgStore) enc(v string) (string, error)      { return s.cipher.Encrypt(v) }
func (s *PgStore) dec(v string) (string, error)      { return s.cipher.Decrypt(v) }
func (s *PgStore) encBytes(v []byte) ([]byte, error) { return s.cipher.EncryptBytes(v) }
func (s *PgStore) decBytes(v []byte) ([]byte, error) { return s.cipher.DecryptBytes(v) }

func (s *PgStore) encryptAccountSecrets(a Account) (clientSecret, accessToken, refreshToken, bearerToken string, err error) {
	if clientSecret, err = s.enc(a.ClientSecret); err != nil {
		return "", "", "", "", fmt.Errorf("encrypt client secret: %w", err)
	}
	if accessToken, err = s.enc(a.AccessToken); err != nil {
		return "", "", "", "", fmt.Errorf("encrypt access token: %w", err)
	}
	if refreshToken, err = s.enc(a.RefreshToken); err != nil {
		return "", "", "", "", fmt.Errorf("encrypt refresh token: %w", err)
	}
	if bearerToken, err = s.enc(a.BearerToken); err != nil {
		return "", "", "", "", fmt.Errorf("encrypt bearer token: %w", err)
	}
	return clientSecret, accessToken, refreshToken, bearerToken, nil
}

// EncryptExisting re-writes every account so any legacy plaintext token columns,
// recorded payloads, and audit error/decision metadata become encrypted.
// Idempotent: already-encrypted values are authenticated and left as-is. A
// malformed ciphertext or a wrong key stops the migration; silently skipping
// it would make a hosted Engine appear healthy while credentials were
// unavailable.
func (s *PgStore) EncryptExisting(ctx context.Context) error {
	if s.cipher == nil {
		return ErrCipherUnavailable
	}
	rows, err := s.pool.Query(ctx, `SELECT `+accountCols+` FROM narthex_accounts ORDER BY name`)
	if err != nil {
		return fmt.Errorf("list accounts for encryption migration: %w", err)
	}
	var accounts []Account
	for rows.Next() {
		a, err := s.scanAccount(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("read account for encryption migration: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate accounts for encryption migration: %w", err)
	}
	rows.Close()
	for _, a := range accounts {
		if err := s.Upsert(ctx, a); err != nil { // Upsert re-encrypts
			return fmt.Errorf("encrypt account %q: %w", a.Name, err)
		}
	}
	if err := s.encryptExistingPendingCalls(ctx); err != nil {
		return err
	}
	if err := s.encryptExistingCallPayloads(ctx); err != nil {
		return err
	}
	if err := s.encryptExistingLibraryPrivateFields(ctx); err != nil {
		return err
	}
	return s.backfillEncryptedLibraryArtifactSurfaceIDs(ctx)
}

// backfillPlainLibraryArtifactSurfaceIDs covers self-hosted PgStores that do
// not enable at-rest encryption. It intentionally uses only an exact existing
// client ID/subject match; encrypted legacy provenance is handled later by the
// cipher-aware startup migration below.
func (s *PgStore) backfillPlainLibraryArtifactSurfaceIDs(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
UPDATE narthex_library_artifacts AS artifact
SET agent_surface_id=run.surface_ref
FROM narthex_library_runs AS run
JOIN narthex_mcp_clients AS client ON client.id=run.surface_ref AND client.subject=run.actor_ref
WHERE artifact.agent_surface_id=''
  AND artifact.origin='agent_direct'
  AND artifact.run_id=run.id
  AND run.origin='agent_direct'
  AND artifact.created_by=run.actor_ref`)
	return err
}

// backfillEncryptedLibraryArtifactSurfaceIDs is the same conservative
// migration after a cipher is configured. Actor/surface refs are private
// AES-GCM values, so a queryable opaque client ID can only be populated after
// authenticating/decrypting both sides in-process.
func (s *PgStore) backfillEncryptedLibraryArtifactSurfaceIDs(ctx context.Context) error {
	type candidate struct {
		artifactID string
		createdBy  string
		actorRef   string
		surfaceRef string
	}
	rows, err := s.pool.Query(ctx, `
SELECT artifact.id,artifact.created_by,run.actor_ref,run.surface_ref
FROM narthex_library_artifacts AS artifact
JOIN narthex_library_runs AS run ON run.id=artifact.run_id
WHERE artifact.agent_surface_id=''
  AND artifact.origin='agent_direct'
  AND run.origin='agent_direct'
ORDER BY artifact.id`)
	if err != nil {
		return fmt.Errorf("list Library artifact surface projections: %w", err)
	}
	var candidates []candidate
	for rows.Next() {
		var raw candidate
		if err := rows.Scan(&raw.artifactID, &raw.createdBy, &raw.actorRef, &raw.surfaceRef); err != nil {
			rows.Close()
			return fmt.Errorf("read Library artifact surface projection: %w", err)
		}
		candidates = append(candidates, raw)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Library artifact surface projections: %w", err)
	}
	rows.Close()
	for _, raw := range candidates {
		createdBy, err := s.dec(raw.createdBy)
		if err != nil {
			return fmt.Errorf("decrypt Library artifact %q creator for surface projection: %w", raw.artifactID, err)
		}
		actorRef, err := s.dec(raw.actorRef)
		if err != nil {
			return fmt.Errorf("decrypt Library artifact %q run actor for surface projection: %w", raw.artifactID, err)
		}
		surfaceRef, err := s.dec(raw.surfaceRef)
		if err != nil {
			return fmt.Errorf("decrypt Library artifact %q run surface for surface projection: %w", raw.artifactID, err)
		}
		if createdBy != actorRef || surfaceRef == "" {
			continue
		}
		var matches bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE id=$1 AND subject=$2)`, surfaceRef, actorRef).Scan(&matches); err != nil {
			return fmt.Errorf("verify Library artifact %q client surface: %w", raw.artifactID, err)
		}
		if !matches {
			continue
		}
		if _, err := s.pool.Exec(ctx, `UPDATE narthex_library_artifacts SET agent_surface_id=$2 WHERE id=$1 AND agent_surface_id=''`, raw.artifactID, surfaceRef); err != nil {
			return fmt.Errorf("write Library artifact %q surface projection: %w", raw.artifactID, err)
		}
	}
	return nil
}

// encryptExistingLibraryPrivateFields upgrades portable Library authored text,
// generated/manual drafts, evaluation annotations, artifact metadata/body,
// and user/agent provenance identifiers that were written before an Engine
// enabled ENGINE_ENCRYPTION_KEY. The rows remain readable during the migration
// because Cipher.Decrypt accepts legacy plaintext, but a successful hosted
// startup must not leave a second private text or provenance store in
// plaintext.
func (s *PgStore) encryptExistingLibraryPrivateFields(ctx context.Context) error {
	type libraryPayload struct{ id, content string }

	upgrade := func(table, column, label string) error {
		rows, err := s.pool.Query(ctx, `SELECT id,`+column+` FROM `+table+` ORDER BY id`)
		if err != nil {
			return fmt.Errorf("list library %s for encryption migration: %w", label, err)
		}
		var payloads []libraryPayload
		for rows.Next() {
			var payload libraryPayload
			if err := rows.Scan(&payload.id, &payload.content); err != nil {
				rows.Close()
				return fmt.Errorf("read library %s for encryption migration: %w", label, err)
			}
			payloads = append(payloads, payload)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate library %s for encryption migration: %w", label, err)
		}
		rows.Close()
		for _, payload := range payloads {
			encrypted, err := s.enc(payload.content)
			if err != nil {
				return fmt.Errorf("encrypt library %s %q: %w", label, payload.id, err)
			}
			if encrypted == payload.content {
				continue
			}
			if _, err := s.pool.Exec(ctx, `UPDATE `+table+` SET `+column+`=$2 WHERE id=$1`, payload.id, encrypted); err != nil {
				return fmt.Errorf("write encrypted library %s %q: %w", label, payload.id, err)
			}
		}
		return nil
	}

	if err := upgrade("narthex_library_skills", "name", "skill name"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skills", "description", "skill description"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skills", "created_by", "skill created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_versions", "content", "skill version"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_versions", "created_by", "skill version created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "name", "skill draft name"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "description", "skill draft description"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "content", "draft"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "generator", "draft generator"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "model", "draft model"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_drafts", "created_by", "skill draft created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_bindings", "created_by", "skill binding created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_evaluations", "evaluator", "skill evaluation evaluator"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_evaluations", "summary", "skill evaluation summary"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_skill_evaluations", "created_by", "skill evaluation created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_runs", "actor_ref", "run actor reference"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_runs", "surface_ref", "run surface reference"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_runs", "source_artifact_id", "run source artifact"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_runs", "source_artifact_version_id", "run source artifact version"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_runs", "source_artifact_digest", "run source artifact digest"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "title", "artifact title"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "summary", "artifact summary"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "created_by", "artifact created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "source_artifact_id", "artifact source artifact"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "source_artifact_version_id", "artifact source artifact version"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifacts", "source_artifact_digest", "artifact source artifact digest"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifact_versions", "body", "artifact version"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifact_versions", "created_by", "artifact version created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifact_versions", "reviewed_by", "artifact version reviewed by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifact_grants", "created_by", "artifact grant created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_artifact_grants", "revoked_by", "artifact grant revoked by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memories", "created_by", "memory created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memories", "reviewed_by", "memory reviewed by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "content", "memory version content"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "source_run_id", "memory source run"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "source_artifact_id", "memory source artifact"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "source_artifact_version_id", "memory source artifact version"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "source_digest", "memory source digest"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_versions", "created_by", "memory version created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_grants", "created_by", "memory grant created by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_memory_grants", "revoked_by", "memory grant revoked by"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_mcp_client_skill_authoring_leases", "granted_by", "MCP client skill authoring grant actor"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_mcp_client_skill_authoring_leases", "revoked_by", "MCP client skill authoring revoke actor"); err != nil {
		return err
	}
	if err := upgrade("narthex_library_mcp_client_skill_authoring_audit_events", "actor_ref", "MCP client skill authoring audit actor"); err != nil {
		return err
	}
	return s.encryptExistingLibraryArtifactMedia(ctx)
}

// encryptExistingPendingCalls covers args plus the decided_by/decision_note
// approval-decision metadata added alongside audit-at-rest encryption. Those
// two columns are write-once (set only at decision time, never UPDATEd
// again), so a row decided before this migration existed would otherwise stay
// plaintext forever without this pass.
func (s *PgStore) encryptExistingPendingCalls(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id,args,decided_by,decision_note FROM pending_calls ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list pending calls for encryption migration: %w", err)
	}
	type pendingPayload struct{ id, args, decidedBy, decisionNote string }
	var payloads []pendingPayload
	for rows.Next() {
		var payload pendingPayload
		if err := rows.Scan(&payload.id, &payload.args, &payload.decidedBy, &payload.decisionNote); err != nil {
			rows.Close()
			return fmt.Errorf("read pending call for encryption migration: %w", err)
		}
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate pending calls for encryption migration: %w", err)
	}
	rows.Close()
	for _, payload := range payloads {
		args, err := s.enc(payload.args)
		if err != nil {
			return fmt.Errorf("encrypt pending call %q arguments: %w", payload.id, err)
		}
		decidedBy, err := s.enc(payload.decidedBy)
		if err != nil {
			return fmt.Errorf("encrypt pending call %q decider: %w", payload.id, err)
		}
		decisionNote, err := s.enc(payload.decisionNote)
		if err != nil {
			return fmt.Errorf("encrypt pending call %q decision note: %w", payload.id, err)
		}
		if args == payload.args && decidedBy == payload.decidedBy && decisionNote == payload.decisionNote {
			continue
		}
		if _, err := s.pool.Exec(ctx, `UPDATE pending_calls SET args=$2,decided_by=$3,decision_note=$4 WHERE id=$1`,
			payload.id, args, decidedBy, decisionNote); err != nil {
			return fmt.Errorf("write encrypted pending call %q: %w", payload.id, err)
		}
	}
	return nil
}

// encryptExistingCallPayloads covers args/result plus the error column that
// encryptAuditFields now encrypts on write. error is write-once (set only at
// insert, never UPDATEd again), so a row logged before this migration existed
// would otherwise stay plaintext forever without this pass.
func (s *PgStore) encryptExistingCallPayloads(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id,args,result,error FROM tool_calls ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list call payloads for encryption migration: %w", err)
	}
	type callPayload struct {
		id                   int64
		args, result, errTxt string
	}
	var payloads []callPayload
	for rows.Next() {
		var payload callPayload
		if err := rows.Scan(&payload.id, &payload.args, &payload.result, &payload.errTxt); err != nil {
			rows.Close()
			return fmt.Errorf("read call payload for encryption migration: %w", err)
		}
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate call payloads for encryption migration: %w", err)
	}
	rows.Close()
	for _, payload := range payloads {
		args, err := s.enc(payload.args)
		if err != nil {
			return fmt.Errorf("encrypt call %d arguments: %w", payload.id, err)
		}
		result, err := s.enc(payload.result)
		if err != nil {
			return fmt.Errorf("encrypt call %d result: %w", payload.id, err)
		}
		errTxt, err := s.enc(payload.errTxt)
		if err != nil {
			return fmt.Errorf("encrypt call %d error: %w", payload.id, err)
		}
		if args == payload.args && result == payload.result && errTxt == payload.errTxt {
			continue
		}
		if _, err := s.pool.Exec(ctx, `UPDATE tool_calls SET args=$2,result=$3,error=$4 WHERE id=$1`,
			payload.id, args, result, errTxt); err != nil {
			return fmt.Errorf("write encrypted call %d payload: %w", payload.id, err)
		}
	}
	return nil
}

// The legacy workspace column stores Account.Group: a display-only alias for
// the owning connection namespace. Its name is preserved so rolling upgrades
// and portable config remain compatible; connection_namespace_id below is the
// authoritative ownership boundary.
const accountsSchema = `
CREATE TABLE IF NOT EXISTS narthex_accounts (
    name           TEXT PRIMARY KEY,
    label          TEXT NOT NULL DEFAULT '',
    workspace      TEXT NOT NULL DEFAULT '',
    url            TEXT NOT NULL,
    auth_mode      TEXT NOT NULL,
    client_id      TEXT NOT NULL DEFAULT '',
    client_secret  TEXT NOT NULL DEFAULT '',
    access_token   TEXT NOT NULL DEFAULT '',
    refresh_token  TEXT NOT NULL DEFAULT '',
    token_endpoint TEXT NOT NULL DEFAULT '',
    resource       TEXT NOT NULL DEFAULT '',
    scope          TEXT NOT NULL DEFAULT '',
    bearer_token   TEXT NOT NULL DEFAULT '',
    disabled_tools TEXT[],
    tool_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    read_only      BOOLEAN NOT NULL DEFAULT false,
    connection_namespace_id TEXT NOT NULL DEFAULT '',
    connection_scope TEXT NOT NULL DEFAULT 'shared',
    owner_subject TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
	incarnation_id TEXT NOT NULL DEFAULT ('accti_' || md5(random()::text || clock_timestamp()::text)),
    CONSTRAINT narthex_accounts_connection_scope_check
        CHECK (connection_scope IN ('shared','personal','service'))
);`

const engineStateSchema = `
CREATE TABLE IF NOT EXISTS narthex_engine_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);`

// idempotent migrations for tables created before these columns existed.
const accountsMigrate = `
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS disabled_tools TEXT[];
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS tool_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS read_only BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS connection_namespace_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS connection_scope TEXT NOT NULL DEFAULT 'shared';
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS owner_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS incarnation_id TEXT NOT NULL DEFAULT ('accti_' || md5(random()::text || clock_timestamp()::text));
ALTER TABLE narthex_accounts ALTER COLUMN revision SET DEFAULT 1;
ALTER TABLE narthex_accounts ALTER COLUMN incarnation_id SET DEFAULT ('accti_' || md5(random()::text || clock_timestamp()::text));
UPDATE narthex_accounts SET connection_scope='shared' WHERE connection_scope='';
UPDATE narthex_accounts SET connection_scope='shared' WHERE connection_scope NOT IN ('shared','personal','service');
UPDATE narthex_accounts SET revision=1 WHERE revision < 1;
UPDATE narthex_accounts SET incarnation_id=('accti_' || md5(random()::text || clock_timestamp()::text || name)) WHERE incarnation_id='';
CREATE UNIQUE INDEX IF NOT EXISTS narthex_accounts_incarnation_id_idx ON narthex_accounts (incarnation_id);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'narthex_accounts_connection_scope_check'
          AND conrelid = 'narthex_accounts'::regclass
    ) THEN
        ALTER TABLE narthex_accounts
            ADD CONSTRAINT narthex_accounts_connection_scope_check
            CHECK (connection_scope IN ('shared','personal','service'));
    END IF;
END $$;`

// Connection namespaces deliberately use a separate table family from the
// legacy narthex_namespaces + narthex_namespace_accounts endpoint-bundle
// tables. The former own credentials; the latter expose shared MCP endpoints.
const connectionNamespacesSchema = `
CREATE TABLE IF NOT EXISTS narthex_connection_namespaces (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    label      TEXT NOT NULL,
    revision   BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS narthex_connection_namespace_managers (
    connection_namespace_id TEXT NOT NULL REFERENCES narthex_connection_namespaces(id) ON DELETE CASCADE,
    subject                 TEXT NOT NULL,
    PRIMARY KEY (connection_namespace_id, subject)
);
CREATE INDEX IF NOT EXISTS narthex_accounts_connection_namespace_idx
    ON narthex_accounts (connection_namespace_id);
CREATE INDEX IF NOT EXISTS narthex_connection_namespaces_slug_idx
    ON narthex_connection_namespaces (slug);
ALTER TABLE narthex_connection_namespaces ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE narthex_connection_namespaces ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();`

// librarySchema is intentionally independent of the legacy narthex_skills
// tables. It is idempotent DDL so an Engine can be restarted onto an existing
// database without a migration framework.
const librarySchema = `
CREATE TABLE IF NOT EXISTS narthex_library_skills (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS narthex_library_skills_created_id_idx ON narthex_library_skills (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS narthex_library_skills_updated_id_idx ON narthex_library_skills (updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS narthex_library_skill_versions (
    id                     TEXT PRIMARY KEY,
    skill_id               TEXT NOT NULL REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    version_number         INT NOT NULL,
    content                TEXT NOT NULL DEFAULT '',
    digest                 TEXT NOT NULL,
    requested_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by             TEXT NOT NULL DEFAULT '',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (skill_id, version_number)
);
CREATE INDEX IF NOT EXISTS narthex_library_skill_versions_skill_idx ON narthex_library_skill_versions (skill_id, version_number DESC);

-- Full Engine reconciliation is the sole writer of this marker. Runtime
-- activation and new-client registration read it as the authoritative managed
-- pin, so mixed binary revisions cannot silently choose their local head.
CREATE TABLE IF NOT EXISTS narthex_library_builtin_current_versions (
    skill_id          TEXT PRIMARY KEY REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    current_version_id TEXT NOT NULL REFERENCES narthex_library_skill_versions(id) ON DELETE RESTRICT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS narthex_library_skill_drafts (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    content                TEXT NOT NULL DEFAULT '',
    requested_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    origin                 TEXT NOT NULL,
    generator              TEXT NOT NULL DEFAULT '',
    model                  TEXT NOT NULL DEFAULT '',
    prompt_digest          TEXT NOT NULL DEFAULT '',
    created_by             TEXT NOT NULL DEFAULT '',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_skill_drafts_origin_check CHECK (origin IN ('generated','manual'))
);

-- This table is intentionally hash-only. A Platform request id is an opaque
-- correlation value, and persisting the raw value would add a needless second
-- private identifier store. The payload digest catches a request-id replay
-- with different generated content before it could mint another draft.
CREATE TABLE IF NOT EXISTS narthex_library_skill_draft_imports (
    request_id_hash TEXT PRIMARY KEY,
    payload_digest  TEXT NOT NULL,
    draft_id        TEXT NOT NULL REFERENCES narthex_library_skill_drafts(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_skill_draft_imports_request_hash_check CHECK (request_id_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_skill_draft_imports_payload_digest_check CHECK (payload_digest ~ '^[a-f0-9]{64}$')
);

CREATE TABLE IF NOT EXISTS narthex_library_skill_bindings (
    id                   TEXT PRIMARY KEY,
    skill_id             TEXT NOT NULL REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    scope_kind           TEXT NOT NULL,
    scope_id             TEXT NOT NULL,
    mode                 TEXT NOT NULL,
    pinned_version_id    TEXT NOT NULL DEFAULT '',
    capability_ceiling   JSONB NOT NULL DEFAULT '[]'::jsonb,
    priority             INT NOT NULL DEFAULT 0,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (skill_id, scope_kind, scope_id),
    CONSTRAINT narthex_library_skill_bindings_mode_check CHECK (mode IN ('pin','track')),
    CONSTRAINT narthex_library_skill_bindings_scope_check CHECK (scope_kind IN ('workspace','namespace','folder','repository','project','agent_surface'))
);
CREATE INDEX IF NOT EXISTS narthex_library_skill_bindings_skill_idx ON narthex_library_skill_bindings (skill_id, priority DESC);

-- A monotonic mutation marker makes temporary MCP-client authoring authority
-- non-revivable. A binding set can otherwise be changed and later restored
-- byte-for-byte while an authoring lease remains open.
CREATE TABLE IF NOT EXISTS narthex_library_skill_binding_generations (
    skill_id   TEXT PRIMARY KEY REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    generation BIGINT NOT NULL CHECK (generation > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS narthex_library_skill_evaluations (
    id               TEXT PRIMARY KEY,
    skill_id         TEXT NOT NULL REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    skill_version_id TEXT NOT NULL REFERENCES narthex_library_skill_versions(id) ON DELETE RESTRICT,
    evaluator        TEXT NOT NULL,
    score            INT NOT NULL,
    passed           BOOLEAN NOT NULL,
    summary          TEXT NOT NULL DEFAULT '',
    evidence_digest  TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_skill_evaluations_score_check CHECK (score >= 0 AND score <= 100)
);
CREATE INDEX IF NOT EXISTS narthex_library_skill_evaluations_skill_idx ON narthex_library_skill_evaluations (skill_id, created_at);

CREATE TABLE IF NOT EXISTS narthex_library_runs (
    id                     TEXT PRIMARY KEY,
    origin                 TEXT NOT NULL,
    attestation            TEXT NOT NULL DEFAULT '',
    skill_id               TEXT NOT NULL DEFAULT '',
    skill_version_id       TEXT NOT NULL DEFAULT '',
    binding_id             TEXT NOT NULL DEFAULT '',
    actor_ref              TEXT NOT NULL DEFAULT '',
    surface_ref            TEXT NOT NULL DEFAULT '',
    effective_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    status                 TEXT NOT NULL,
    input_digest           TEXT NOT NULL DEFAULT '',
    output_digest          TEXT NOT NULL DEFAULT '',
		source_artifact_id       TEXT NOT NULL DEFAULT '',
		source_artifact_version_id TEXT NOT NULL DEFAULT '',
		source_artifact_digest   TEXT NOT NULL DEFAULT '',
    started_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_runs_origin_check CHECK (origin IN ('skill_run','agent_direct','automation','human')),
    CONSTRAINT narthex_library_runs_attestation_check CHECK (attestation='' OR (attestation='host_attested' AND origin='skill_run'))
);
CREATE INDEX IF NOT EXISTS narthex_library_runs_started_idx ON narthex_library_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS narthex_library_runs_started_id_idx ON narthex_library_runs (started_at DESC, id DESC);

-- Host-attestation replay protection stores only scoped verifier hashes. The
-- raw execution ID, nonce, signature, and request body never enter PgStore.
CREATE TABLE IF NOT EXISTS narthex_library_runtime_attestations (
    run_id          TEXT PRIMARY KEY REFERENCES narthex_library_runs(id) ON DELETE RESTRICT,
    client_id       TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch    TEXT NOT NULL,
    execution_hash  TEXT NOT NULL,
    nonce_hash      TEXT NOT NULL,
    request_digest  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_runtime_attestations_execution_hash_check CHECK (execution_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_runtime_attestations_nonce_hash_check CHECK (nonce_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_runtime_attestations_request_digest_check CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    UNIQUE (client_id, client_epoch, execution_hash),
    UNIQUE (client_id, client_epoch, nonce_hash)
);

CREATE TABLE IF NOT EXISTS narthex_library_artifacts (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    summary          TEXT NOT NULL DEFAULT '',
    origin           TEXT NOT NULL,
    run_id           TEXT NOT NULL DEFAULT '',
    skill_id         TEXT NOT NULL DEFAULT '',
    skill_version_id TEXT NOT NULL DEFAULT '',
    binding_id       TEXT NOT NULL DEFAULT '',
		agent_surface_id TEXT NOT NULL DEFAULT '',
		source_artifact_id TEXT NOT NULL DEFAULT '',
		source_artifact_version_id TEXT NOT NULL DEFAULT '',
		source_artifact_digest TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_artifacts_origin_check CHECK (origin IN ('skill_run','agent_direct','automation','human'))
);
CREATE INDEX IF NOT EXISTS narthex_library_artifacts_created_idx ON narthex_library_artifacts (created_at DESC);
CREATE INDEX IF NOT EXISTS narthex_library_artifacts_created_id_idx ON narthex_library_artifacts (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS narthex_library_artifacts_surface_created_idx ON narthex_library_artifacts (agent_surface_id, created_at DESC, id DESC) WHERE agent_surface_id <> '';

CREATE TABLE IF NOT EXISTS narthex_library_artifact_versions (
    id               TEXT PRIMARY KEY,
    artifact_id      TEXT NOT NULL REFERENCES narthex_library_artifacts(id) ON DELETE RESTRICT,
    version_number   INT NOT NULL,
    format           TEXT NOT NULL,
    body             TEXT NOT NULL DEFAULT '',
    digest           TEXT NOT NULL,
    size_bytes       BIGINT NOT NULL,
    redaction_status TEXT NOT NULL DEFAULT 'pending',
		created_by       TEXT NOT NULL DEFAULT '',
    reviewed_by      TEXT NOT NULL DEFAULT '',
    reviewed_at      TIMESTAMPTZ,
	publication_claimed_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (artifact_id, version_number),
    CONSTRAINT narthex_library_artifact_versions_format_check CHECK (format IN ('markdown','text','image')),
    CONSTRAINT narthex_library_artifact_versions_redaction_check CHECK (redaction_status IN ('pending','approved','rejected'))
);
CREATE INDEX IF NOT EXISTS narthex_library_artifact_versions_artifact_idx ON narthex_library_artifact_versions (artifact_id, version_number DESC);

-- One immutable private image blob belongs to one image-format artifact
-- version. There is intentionally no digest uniqueness constraint: two
-- independent artifact versions may contain identical bytes without sharing
-- authorization, retention, or deletion semantics.
CREATE TABLE IF NOT EXISTS narthex_library_artifact_media_blobs (
    artifact_version_id TEXT PRIMARY KEY REFERENCES narthex_library_artifact_versions(id) ON DELETE RESTRICT,
    mime_type           TEXT NOT NULL,
    digest              TEXT NOT NULL,
    size_bytes          BIGINT NOT NULL,
    width               INT NOT NULL DEFAULT 0,
    height              INT NOT NULL DEFAULT 0,
    alt_text            TEXT NOT NULL DEFAULT '',
    delivery_mode       TEXT NOT NULL,
    encrypted_data      BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT narthex_library_artifact_media_blobs_mime_check
        CHECK (mime_type IN ('image/png','image/jpeg','image/svg+xml')),
    CONSTRAINT narthex_library_artifact_media_blobs_digest_check
        CHECK (digest ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_artifact_media_blobs_size_check
        CHECK (size_bytes > 0 AND size_bytes <= 524288),
    CONSTRAINT narthex_library_artifact_media_blobs_dimensions_check
        CHECK ((width = 0 AND height = 0) OR (width > 0 AND height > 0)),
    CONSTRAINT narthex_library_artifact_media_blobs_delivery_check
        CHECK ((mime_type='image/svg+xml' AND delivery_mode='download_only') OR
               (mime_type <> 'image/svg+xml' AND delivery_mode='inline'))
);

CREATE TABLE IF NOT EXISTS narthex_library_artifact_grants (
    id                      TEXT PRIMARY KEY,
    artifact_id             TEXT NOT NULL REFERENCES narthex_library_artifacts(id) ON DELETE RESTRICT,
    artifact_version_id     TEXT NOT NULL REFERENCES narthex_library_artifact_versions(id) ON DELETE RESTRICT,
    artifact_version_digest TEXT NOT NULL,
    agent_surface_id        TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    created_by              TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by              TEXT NOT NULL DEFAULT '',
    revoked_at              TIMESTAMPTZ,
    CONSTRAINT narthex_library_artifact_grants_digest_check CHECK (artifact_version_digest ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS narthex_library_artifact_grants_artifact_idx ON narthex_library_artifact_grants (artifact_id, created_at);
CREATE INDEX IF NOT EXISTS narthex_library_artifact_grants_surface_idx ON narthex_library_artifact_grants (agent_surface_id, artifact_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS narthex_library_artifact_grants_live_target_idx ON narthex_library_artifact_grants (artifact_id, agent_surface_id) WHERE revoked_at IS NULL;

-- Durable agent memory is a separate Library facet. The logical row owns
-- lifecycle/freshness; authored statements live only in immutable versions.
-- current_version_id is intentionally not an FK so the logical row and v1 can
-- be inserted in one transaction without a deferrable circular dependency.
CREATE TABLE IF NOT EXISTS narthex_library_memories (
    id                       TEXT PRIMARY KEY,
    kind                     TEXT NOT NULL,
    state                    TEXT NOT NULL,
    trust                    TEXT NOT NULL,
    agent_surface_id         TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    current_version_id       TEXT NOT NULL,
    current_version_digest   TEXT NOT NULL,
    created_by               TEXT NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ,
    review_after             TIMESTAMPTZ,
    reviewed_by              TEXT NOT NULL DEFAULT '',
    reviewed_at              TIMESTAMPTZ,
    superseded_by_memory_id  TEXT NOT NULL DEFAULT '',
    CONSTRAINT narthex_library_memories_kind_check CHECK (kind IN ('decision','constraint','preference','lesson','fact','handoff')),
    CONSTRAINT narthex_library_memories_state_check CHECK (state IN ('proposed','active','disputed','superseded','expired')),
    CONSTRAINT narthex_library_memories_trust_check CHECK (trust IN ('agent_observed','human_confirmed','workspace_approved','host_attested')),
    CONSTRAINT narthex_library_memories_digest_check CHECK (current_version_digest ~ '^[a-f0-9]{64}$')
);
-- Match FileStore's byte-ordered ID tie-breaker, including on existing databases.
-- A new name upgrades the old locale-dependent index idempotently.
CREATE INDEX IF NOT EXISTS narthex_library_memories_updated_c_idx ON narthex_library_memories (updated_at DESC, id COLLATE "C" DESC);
DROP INDEX IF EXISTS narthex_library_memories_updated_idx;
CREATE INDEX IF NOT EXISTS narthex_library_memories_surface_active_idx ON narthex_library_memories (agent_surface_id, updated_at DESC, id DESC) WHERE state='active';
CREATE INDEX IF NOT EXISTS narthex_library_memories_superseded_by_idx ON narthex_library_memories (superseded_by_memory_id) WHERE superseded_by_memory_id<>'';

CREATE TABLE IF NOT EXISTS narthex_library_memory_versions (
    id                         TEXT PRIMARY KEY,
    memory_id                  TEXT NOT NULL REFERENCES narthex_library_memories(id) ON DELETE CASCADE,
    version_number             INT NOT NULL CHECK (version_number > 0),
    content                    TEXT NOT NULL,
    digest                     TEXT NOT NULL,
    source_run_id              TEXT NOT NULL DEFAULT '',
    source_artifact_id         TEXT NOT NULL DEFAULT '',
    source_artifact_version_id TEXT NOT NULL DEFAULT '',
    source_digest              TEXT NOT NULL DEFAULT '',
    created_by                 TEXT NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (memory_id, version_number),
    CONSTRAINT narthex_library_memory_versions_digest_check CHECK (digest ~ '^[a-f0-9]{64}$')
);
-- source_digest is private provenance and is encrypted when a cipher is
-- configured. Drop the short-lived development constraint if this idempotent
-- schema is applied over an earlier local build.
ALTER TABLE narthex_library_memory_versions DROP CONSTRAINT IF EXISTS narthex_library_memory_versions_source_digest_check;
CREATE INDEX IF NOT EXISTS narthex_library_memory_versions_memory_idx ON narthex_library_memory_versions (memory_id, version_number);

CREATE TABLE IF NOT EXISTS narthex_library_memory_grants (
    id                    TEXT PRIMARY KEY,
    memory_id             TEXT NOT NULL REFERENCES narthex_library_memories(id) ON DELETE CASCADE,
    memory_version_id     TEXT NOT NULL REFERENCES narthex_library_memory_versions(id) ON DELETE CASCADE,
    memory_version_digest TEXT NOT NULL,
    agent_surface_id      TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    created_by            TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by            TEXT NOT NULL DEFAULT '',
    revoked_at            TIMESTAMPTZ,
    CONSTRAINT narthex_library_memory_grants_digest_check CHECK (memory_version_digest ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS narthex_library_memory_grants_memory_idx ON narthex_library_memory_grants (memory_id, created_at);
CREATE INDEX IF NOT EXISTS narthex_library_memory_grants_surface_idx ON narthex_library_memory_grants (agent_surface_id, memory_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS narthex_library_memory_grants_live_target_idx ON narthex_library_memory_grants (memory_id, agent_surface_id) WHERE revoked_at IS NULL;

-- Subject-bound artifact revision replay receipts. The operation is generic
-- so text and media appends can share a
-- durable idempotency boundary without persisting a raw request ID or body.
CREATE TABLE IF NOT EXISTS narthex_library_mcp_client_artifact_version_requests (
    client_id           TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch        TEXT NOT NULL,
    artifact_id         TEXT NOT NULL REFERENCES narthex_library_artifacts(id) ON DELETE RESTRICT,
    operation           TEXT NOT NULL,
    request_id_hash     TEXT NOT NULL,
    payload_digest      TEXT NOT NULL,
    artifact_version_id TEXT NOT NULL REFERENCES narthex_library_artifact_versions(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, client_epoch, artifact_id, operation, request_id_hash),
    CONSTRAINT narthex_library_mcp_client_artifact_version_requests_operation_check CHECK (operation <> ''),
    CONSTRAINT narthex_library_mcp_client_artifact_version_requests_request_hash_check CHECK (request_id_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_mcp_client_artifact_version_requests_payload_digest_check CHECK (payload_digest ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS narthex_library_mcp_client_artifact_version_requests_artifact_idx
    ON narthex_library_mcp_client_artifact_version_requests (artifact_id, created_at DESC);

-- A lease is a short, server-clock-bounded exception for one durable
-- subject-bound MCP client. It holds no bearer secret: client_id + epoch are
-- structural fences, while administrative actor references are encrypted by
-- the PgStore write path.
CREATE TABLE IF NOT EXISTS narthex_library_mcp_client_skill_authoring_leases (
    id                TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch      TEXT NOT NULL,
    granted_by        TEXT NOT NULL DEFAULT '',
    granted_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    remaining_creates INT NOT NULL,
    revoked_at        TIMESTAMPTZ,
    revoked_by        TEXT NOT NULL DEFAULT '',
	created_at        TIMESTAMPTZ NOT NULL,
	updated_at        TIMESTAMPTZ NOT NULL,
	kind              TEXT NOT NULL DEFAULT 'generic',
	target_skill_id   TEXT NOT NULL DEFAULT '',
	target_version_id TEXT NOT NULL DEFAULT '',
	target_version_digest TEXT NOT NULL DEFAULT '',
	target_binding_id TEXT NOT NULL DEFAULT '',
	target_binding_digest TEXT NOT NULL DEFAULT '',
	target_binding_generation BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT narthex_library_mcp_client_skill_authoring_leases_remaining_check CHECK (remaining_creates >= 0),
	CONSTRAINT narthex_library_mcp_client_skill_authoring_leases_expiry_check CHECK (expires_at > granted_at),
	CONSTRAINT narthex_library_mcp_client_skill_authoring_leases_kind_check CHECK (kind IN ('generic','adoption'))
);
CREATE INDEX IF NOT EXISTS narthex_library_mcp_client_skill_authoring_leases_client_idx
    ON narthex_library_mcp_client_skill_authoring_leases (client_id, granted_at DESC, id DESC);

-- Replay records retain scoped request/payload hashes only. The raw MCP
-- requestId and instruction body never become a second metadata store.
CREATE TABLE IF NOT EXISTS narthex_library_mcp_client_skill_authoring_requests (
    client_id       TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch    TEXT NOT NULL,
    request_id_hash TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    lease_id        TEXT NOT NULL REFERENCES narthex_library_mcp_client_skill_authoring_leases(id) ON DELETE RESTRICT,
    skill_id        TEXT NOT NULL REFERENCES narthex_library_skills(id) ON DELETE RESTRICT,
    version_id      TEXT NOT NULL REFERENCES narthex_library_skill_versions(id) ON DELETE RESTRICT,
    -- Empty only for pre-auto-binding legacy records. New leased creates
    -- persist the exact generated binding ID so later client authoring cannot
    -- mistake an owner/admin replacement binding for its automatic one.
    binding_id      TEXT NOT NULL DEFAULT '',
    -- New automatic bindings also retain their structural digest and the
    -- monotonic per-skill generation observed immediately after creation.
    -- Legacy unbound records deliberately retain the zero values.
    binding_digest      TEXT NOT NULL DEFAULT '',
    binding_generation BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, client_epoch, request_id_hash),
    CONSTRAINT narthex_library_mcp_client_skill_authoring_requests_request_hash_check CHECK (request_id_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_mcp_client_skill_authoring_requests_payload_digest_check CHECK (payload_digest ~ '^[a-f0-9]{64}$')
);

-- Append-only receipts intentionally outlive a lease and are kept separate
-- from the lossy asynchronous general call audit. They contain only opaque
-- references and one-way request/payload hashes; actor_ref is encrypted by
-- PgStore before every write.
CREATE TABLE IF NOT EXISTS narthex_library_mcp_client_skill_authoring_audit_events (
    id              TEXT PRIMARY KEY,
    lease_id        TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL REFERENCES narthex_mcp_clients(id) ON DELETE RESTRICT,
    client_epoch    TEXT NOT NULL,
    action          TEXT NOT NULL,
    operation       TEXT NOT NULL,
    actor_ref       TEXT NOT NULL DEFAULT '',
    request_id_hash TEXT NOT NULL DEFAULT '',
    payload_digest  TEXT NOT NULL DEFAULT '',
    skill_id        TEXT NOT NULL DEFAULT '',
    version_id      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT narthex_library_mcp_client_skill_authoring_audit_events_action_check
        CHECK (action IN ('granted','revoked','consumed','rejected')),
    CONSTRAINT narthex_library_mcp_client_skill_authoring_audit_events_operation_check
        CHECK (operation IN ('grant','revoke','create','update','adopt')),
    CONSTRAINT narthex_library_mcp_client_skill_authoring_audit_events_request_hash_check
        CHECK (request_id_hash = '' OR request_id_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT narthex_library_mcp_client_skill_authoring_audit_events_payload_digest_check
        CHECK (payload_digest = '' OR payload_digest ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS narthex_library_mcp_client_skill_authoring_audit_events_client_idx
    ON narthex_library_mcp_client_skill_authoring_audit_events (client_id, created_at DESC, id DESC);
`

// libraryMigrate is intentionally additive: Engine schema bootstrap runs on
// every replica start, so it must tolerate old workspace databases and rolling
// image updates. The claim marker is non-sensitive durability metadata; private
// artifact body and reviewer identity remain encrypted in their existing
// columns.
const libraryMigrate = `
ALTER TABLE narthex_library_artifact_versions
    ADD COLUMN IF NOT EXISTS publication_claimed_at TIMESTAMPTZ;
ALTER TABLE narthex_library_artifact_versions
    ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_requests
    ADD COLUMN IF NOT EXISTS binding_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_requests
    ADD COLUMN IF NOT EXISTS binding_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_requests
    ADD COLUMN IF NOT EXISTS binding_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'generic';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_skill_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_version_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_version_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_binding_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_binding_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
	ADD COLUMN IF NOT EXISTS target_binding_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE narthex_library_runs
    ADD COLUMN IF NOT EXISTS source_artifact_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_runs
    ADD COLUMN IF NOT EXISTS attestation TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_runs
    ADD COLUMN IF NOT EXISTS source_artifact_version_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_runs
    ADD COLUMN IF NOT EXISTS source_artifact_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_artifacts
    ADD COLUMN IF NOT EXISTS source_artifact_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_artifacts
    ADD COLUMN IF NOT EXISTS source_artifact_version_id TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_artifacts
    ADD COLUMN IF NOT EXISTS source_artifact_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE narthex_library_artifacts
    ADD COLUMN IF NOT EXISTS agent_surface_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS narthex_library_artifacts_surface_created_idx ON narthex_library_artifacts (agent_surface_id, created_at DESC, id DESC) WHERE agent_surface_id <> '';
DO $$
BEGIN
	-- Older installations accepted only text/Markdown versions. Replace that
	-- one named check exactly once when image support is absent; this remains
	-- additive for all other artifact columns and preserves existing rows.
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname='narthex_library_artifact_versions_format_check'
		  AND conrelid='narthex_library_artifact_versions'::regclass
		  AND pg_get_constraintdef(oid) LIKE '%image%'
	) THEN
		ALTER TABLE narthex_library_artifact_versions
			DROP CONSTRAINT IF EXISTS narthex_library_artifact_versions_format_check;
		ALTER TABLE narthex_library_artifact_versions
			ADD CONSTRAINT narthex_library_artifact_versions_format_check
			CHECK (format IN ('markdown','text','image'));
	END IF;
	-- Keep the SQL admission limit equal to the bounded MCP/base64 transport
	-- limit. Replacing the named check is idempotent and prevents a direct SQL
	-- write or an older bootstrap from inserting a blob that the Engine cannot
	-- safely deliver.
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname='narthex_library_artifact_media_blobs_size_check'
		  AND conrelid='narthex_library_artifact_media_blobs'::regclass
		  AND pg_get_constraintdef(oid) LIKE '%524288%'
	) THEN
		ALTER TABLE narthex_library_artifact_media_blobs
			DROP CONSTRAINT IF EXISTS narthex_library_artifact_media_blobs_size_check;
		ALTER TABLE narthex_library_artifact_media_blobs
			ADD CONSTRAINT narthex_library_artifact_media_blobs_size_check
			CHECK (size_bytes > 0 AND size_bytes <= 524288);
	END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='narthex_library_runs_attestation_check'
          AND conrelid='narthex_library_runs'::regclass
    ) THEN
        ALTER TABLE narthex_library_runs
            ADD CONSTRAINT narthex_library_runs_attestation_check
            CHECK (attestation='' OR (attestation='host_attested' AND origin='skill_run'));
    END IF;
	-- Existing lease tables predate explicit kind metadata. Rebuild the named
	-- constraint when needed so a rolling upgrade cannot admit an unrecognized
	-- mode that the Engine would otherwise only reject in application code.
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname='narthex_library_mcp_client_skill_authoring_leases_kind_check'
		  AND conrelid='narthex_library_mcp_client_skill_authoring_leases'::regclass
		  AND pg_get_constraintdef(oid) LIKE '%generic%'
		  AND pg_get_constraintdef(oid) LIKE '%adoption%'
		  -- The generated CHECK has exactly the two quoted enum values. This
		  -- additionally repairs an early/partial migration that happened to
		  -- mention both names but admitted a third kind.
		  AND length(pg_get_constraintdef(oid)) - length(replace(pg_get_constraintdef(oid), '''', '')) = 4
	) THEN
		ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
			DROP CONSTRAINT IF EXISTS narthex_library_mcp_client_skill_authoring_leases_kind_check;
		ALTER TABLE narthex_library_mcp_client_skill_authoring_leases
			ADD CONSTRAINT narthex_library_mcp_client_skill_authoring_leases_kind_check
			CHECK (kind IN ('generic','adoption'));
	END IF;
	-- A version update and owner/admin adoption remain distinct append-only
	-- operations for review and incident analysis. Rebuild the named check for
	-- older Engine databases that predate either operation.
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
	WHERE conname='narthex_library_mcp_client_skill_authoring_audit_events_operation_check'
		  AND conrelid='narthex_library_mcp_client_skill_authoring_audit_events'::regclass
		  AND pg_get_constraintdef(oid) LIKE '%update%'
		  AND pg_get_constraintdef(oid) LIKE '%adopt%'
	) THEN
		ALTER TABLE narthex_library_mcp_client_skill_authoring_audit_events
			DROP CONSTRAINT IF EXISTS narthex_library_mcp_client_skill_authoring_audit_events_operation_check;
		ALTER TABLE narthex_library_mcp_client_skill_authoring_audit_events
			ADD CONSTRAINT narthex_library_mcp_client_skill_authoring_audit_events_operation_check
			CHECK (operation IN ('grant','revoke','create','update','adopt'));
	END IF;
END $$;
`

const accountCols = `name,label,workspace,url,auth_mode,connection_namespace_id,connection_scope,owner_subject,revision,incarnation_id,client_id,client_secret,access_token,refresh_token,token_endpoint,resource,scope,bearer_token,disabled_tools,tool_overrides,read_only`

const engineSchemaBootstrapLock = "narthex-engine-schema-bootstrap:v1"

func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	config, err := enginePostgresPoolConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	// Keep one pooled connection for all bootstrap work and reserve the other
	// for a session-level lock. Holding the lock on an acquired connection
	// serializes DDL plus data backfills across replica startups without
	// exceeding the store's normal two-connection pool cap.
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("acquire schema bootstrap lock connection: %w", err)
	}
	releaseBootstrapLock := func() {
		if lockConn == nil {
			return
		}
		unlockCtx, cancel := context.WithTimeout(context.Background(), engineAuditCloseTimeout)
		defer cancel()
		if _, err := lockConn.Exec(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, engineSchemaBootstrapLock); err != nil {
			// Releasing the acquired connection also releases a session lock.
			// Log the explicit unlock failure so a stuck connection is visible.
			log.Printf("engine: unlock schema bootstrap advisory lock: %v", err)
		}
		lockConn.Release()
		lockConn = nil
	}
	defer releaseBootstrapLock()
	closePool := func() {
		releaseBootstrapLock()
		pool.Close()
	}
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, engineSchemaBootstrapLock); err != nil {
		closePool()
		return nil, fmt.Errorf("lock Engine schema bootstrap: %w", err)
	}
	if _, err := pool.Exec(ctx, accountsSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure accounts schema: %w", err)
	}
	if _, err := pool.Exec(ctx, accountsMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate accounts schema: %w", err)
	}
	if _, err := pool.Exec(ctx, connectionNamespacesSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure connection namespaces schema: %w", err)
	}
	if _, err := pool.Exec(ctx, mcpClientsSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure MCP client registry schema: %w", err)
	}
	store := &PgStore{pool: pool}
	if err := store.backfillConnectionNamespaces(ctx); err != nil {
		closePool()
		return nil, fmt.Errorf("backfill connection namespaces: %w", err)
	}
	if err := store.backfillMCPClients(ctx); err != nil {
		closePool()
		return nil, fmt.Errorf("backfill MCP clients: %w", err)
	}
	if _, err := pool.Exec(ctx, engineStateSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure engine state schema: %w", err)
	}
	if err := store.ensureOAuthGrantSchema(ctx); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure durable OAuth grant schema: %w", err)
	}
	if _, err := pool.Exec(ctx, callsSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure tool_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, callsMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate tool_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, connectorsSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure connectors schema: %w", err)
	}
	if _, err := pool.Exec(ctx, connectorsMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate connectors schema: %w", err)
	}
	if _, err := pool.Exec(ctx, namespacesSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure namespaces schema: %w", err)
	}
	if _, err := pool.Exec(ctx, pendingSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure pending_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, pendingMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate pending_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, usageSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure usage schema: %w", err)
	}
	if _, err := pool.Exec(ctx, usageMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate usage schema: %w", err)
	}
	if _, err := pool.Exec(ctx, skillSourcesSchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure skills schema: %w", err)
	}
	if _, err := pool.Exec(ctx, librarySchema); err != nil {
		closePool()
		return nil, fmt.Errorf("ensure library schema: %w", err)
	}
	if _, err := pool.Exec(ctx, libraryMigrate); err != nil {
		closePool()
		return nil, fmt.Errorf("migrate library schema: %w", err)
	}
	if err := store.backfillPlainLibraryArtifactSurfaceIDs(ctx); err != nil {
		closePool()
		return nil, fmt.Errorf("backfill library artifact surface projections: %w", err)
	}
	store.audit = newAuditWriter(store.persistAuditCall, defaultAuditWriterConfig())
	return store, nil
}

func enginePostgresPoolConfig(dsn string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse Engine database URL: %w", err)
	}
	// Hosted Engines share one Cloud SQL instance across isolated workspace
	// databases. Keep each scale-to-zero Engine's connection footprint bounded
	// so a small number of active workspaces cannot starve Platform control
	// operations. Callers cannot raise this safety cap through pool_* DSN
	// parameters.
	config.MaxConns = enginePostgresMaxConns
	config.MinConns = 0
	config.MaxConnLifetime = enginePostgresMaxConnLifetime
	config.MaxConnIdleTime = enginePostgresMaxConnIdleTime
	return config, nil
}

type persistedAccountConnection struct {
	Name                  string
	Group                 string
	ConnectionNamespaceID string
	ConnectionScope       ConnectionScope
	OwnerSubject          string
	Revision              int64
}

// backfillConnectionNamespaces upgrades legacy Group/workspace-only account
// rows on startup. A group label is never treated as proof of personal access:
// all rows that lack a durable namespace are explicitly made shared. This is
// an intentionally conservative rolling migration, not an authorization
// inference.
func (s *PgStore) backfillConnectionNamespaces(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
SELECT name,workspace,connection_namespace_id,connection_scope,owner_subject,revision
FROM narthex_accounts
ORDER BY name
FOR UPDATE`)
	if err != nil {
		return err
	}
	var accounts []persistedAccountConnection
	for rows.Next() {
		var a persistedAccountConnection
		if err := rows.Scan(&a.Name, &a.Group, &a.ConnectionNamespaceID, &a.ConnectionScope, &a.OwnerSubject, &a.Revision); err != nil {
			rows.Close()
			return err
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, persisted := range accounts {
		a := Account{
			Name:                  persisted.Name,
			Group:                 persisted.Group,
			ConnectionNamespaceID: strings.TrimSpace(persisted.ConnectionNamespaceID),
			ConnectionScope:       persisted.ConnectionScope,
			OwnerSubject:          persisted.OwnerSubject,
			Revision:              persisted.Revision,
		}
		if a.ConnectionNamespaceID == "" {
			a.ConnectionScope = ConnectionScopeShared
			a.OwnerSubject = ""
		}
		if err := s.ensureAccountConnectionNamespaceTx(ctx, tx, &a); err != nil {
			return fmt.Errorf("account %q: %w", a.Name, err)
		}
		if a.ConnectionNamespaceID != persisted.ConnectionNamespaceID || a.ConnectionScope != persisted.ConnectionScope ||
			a.OwnerSubject != persisted.OwnerSubject || a.Revision != persisted.Revision || a.Group != persisted.Group {
			if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET workspace=$2, connection_namespace_id=$3, connection_scope=$4, owner_subject=$5, revision=$6
WHERE name=$1`, a.Name, a.Group, a.ConnectionNamespaceID, a.ConnectionScope, a.OwnerSubject, a.Revision); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func pgConnectionNamespaceSlug(ctx context.Context, tx pgx.Tx, label string) (string, error) {
	base := normalizeConnectionNamespaceSlug(label)
	if base == "" {
		base = "general"
	}
	for n := 1; ; n++ {
		slug := base
		if n > 1 {
			slug = fmt.Sprintf("%s-%d", base, n)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_connection_namespaces WHERE slug=$1)`, slug).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return slug, nil
		}
	}
}

func insertConnectionNamespaceTx(ctx context.Context, tx pgx.Tx, ns ConnectionNamespace) (ConnectionNamespace, error) {
	if err := prepareConnectionNamespaceForCreate(&ns); err != nil {
		return ConnectionNamespace{}, err
	}
	for {
		// Serialize same-slug creates across Engine replicas. The random ID is
		// still checked by the primary key, but a collision is astronomically
		// unlikely and a retry is cheap.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "connection-namespace:"+ns.Slug); err != nil {
			return ConnectionNamespace{}, err
		}
		var inserted string
		err := tx.QueryRow(ctx, `
			INSERT INTO narthex_connection_namespaces (id,slug,label,revision,created_by,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT DO NOTHING
			RETURNING id`, ns.ID, ns.Slug, ns.Label, ns.Revision, ns.CreatedBy, ns.CreatedAt, ns.UpdatedAt).Scan(&inserted)
		if err == nil {
			for _, grant := range ns.ManagerGrants {
				if _, err := tx.Exec(ctx, `
INSERT INTO narthex_connection_namespace_managers (connection_namespace_id,subject)
VALUES ($1,$2)`, ns.ID, grant.Subject); err != nil {
					return ConnectionNamespace{}, err
				}
			}
			return ns, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return ConnectionNamespace{}, err
		}
		// A slug collision is common enough under a label migration. Try a
		// suffix; an ID collision takes the same safe path.
		slug, slugErr := pgConnectionNamespaceSlug(ctx, tx, ns.Slug)
		if slugErr != nil {
			return ConnectionNamespace{}, slugErr
		}
		ns.Slug = slug
		ns.ID = newConnectionNamespaceID()
	}
}

func loadConnectionNamespaceByIDTx(ctx context.Context, tx pgx.Tx, id string) (ConnectionNamespace, error) {
	var ns ConnectionNamespace
	err := tx.QueryRow(ctx, `
	SELECT id,slug,label,revision,created_by,created_at,updated_at
FROM narthex_connection_namespaces
WHERE id=$1`, id).Scan(&ns.ID, &ns.Slug, &ns.Label, &ns.Revision, &ns.CreatedBy, &ns.CreatedAt, &ns.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	return ns, err
}

func (s *PgStore) ensureAccountConnectionNamespaceTx(ctx context.Context, tx pgx.Tx, a *Account) error {
	if err := normalizeAccountConnection(a); err != nil {
		return err
	}
	if a.ConnectionNamespaceID != "" {
		ns, err := loadConnectionNamespaceByIDTx(ctx, tx, a.ConnectionNamespaceID)
		if err != nil {
			return err
		}
		if strings.TrimSpace(a.Group) == "" {
			a.Group = ns.Label
		}
		return nil
	}

	label := defaultConnectionNamespaceLabel(*a)
	if a.ConnectionScope != ConnectionScopePersonal {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "connection-namespace-label:"+strings.ToLower(label)); err != nil {
			return err
		}
		var existing string
		err := tx.QueryRow(ctx, `
SELECT id FROM narthex_connection_namespaces
WHERE lower(label)=lower($1)
ORDER BY id
LIMIT 1`, label).Scan(&existing)
		if err == nil {
			a.ConnectionNamespaceID = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}

	ns := ConnectionNamespace{
		ID:        newConnectionNamespaceID(),
		Slug:      normalizeConnectionNamespaceSlug(label),
		Label:     label,
		Revision:  1,
		CreatedBy: a.OwnerSubject,
	}
	if a.ConnectionScope == ConnectionScopePersonal {
		ns.Slug = "personal"
	}
	created, err := insertConnectionNamespaceTx(ctx, tx, ns)
	if err != nil {
		return err
	}
	a.ConnectionNamespaceID = created.ID
	return nil
}

// LoadOrCreateTokenGeneration returns the Engine's durable workspace OAuth
// generation. INSERT ... ON CONFLICT makes first startup safe under concurrent
// constructors; the subsequent SELECT observes the winning value.
func (s *PgStore) LoadOrCreateTokenGeneration(ctx context.Context, candidate string) (string, error) {
	if candidate == "" {
		return "", errors.New("token generation candidate is required")
	}
	const key = "oauth_token_generation"
	if _, err := s.pool.Exec(ctx, `
INSERT INTO narthex_engine_state (key,value)
VALUES ($1,$2)
ON CONFLICT (key) DO NOTHING`, key, candidate); err != nil {
		return "", fmt.Errorf("initialize token generation: %w", err)
	}
	var generation string
	if err := s.pool.QueryRow(ctx, `SELECT value FROM narthex_engine_state WHERE key=$1`, key).Scan(&generation); err != nil {
		return "", fmt.Errorf("load token generation: %w", err)
	}
	if generation == "" {
		return "", errors.New("load token generation: stored generation is empty")
	}
	return generation, nil
}

func (s *PgStore) CurrentTokenGeneration(ctx context.Context) (string, error) {
	const key = "oauth_token_generation"
	var generation string
	if err := s.pool.QueryRow(ctx, `SELECT value FROM narthex_engine_state WHERE key=$1`, key).Scan(&generation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("token generation is not initialized")
		}
		return "", fmt.Errorf("load current token generation: %w", err)
	}
	if generation == "" {
		return "", errors.New("load current token generation: stored generation is empty")
	}
	return generation, nil
}

// RotateTokenGeneration uses compare-and-swap so a stale Engine instance can
// never overwrite a newer revocation generation. On a stale expectation it
// returns the already-current value for the caller to adopt.
func (s *PgStore) RotateTokenGeneration(ctx context.Context, expected, replacement string) (string, error) {
	if expected == "" || replacement == "" {
		return "", errors.New("expected and replacement token generations are required")
	}
	const key = "oauth_token_generation"
	var generation string
	err := s.pool.QueryRow(ctx, `
UPDATE narthex_engine_state
SET value=$3
WHERE key=$1 AND value=$2
RETURNING value`, key, expected, replacement).Scan(&generation)
	if err == nil {
		return generation, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("rotate token generation: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT value FROM narthex_engine_state WHERE key=$1`, key).Scan(&generation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("token generation is not initialized")
		}
		return "", fmt.Errorf("load current token generation: %w", err)
	}
	if generation == "" {
		return "", errors.New("load current token generation: stored generation is empty")
	}
	return generation, nil
}

const connectorsSchema = `
CREATE TABLE IF NOT EXISTS narthex_connectors (
    slug             TEXT PRIMARY KEY,
    label            TEXT NOT NULL DEFAULT '',
    tools            JSONB NOT NULL DEFAULT '{}'::jsonb,
    approval         JSONB NOT NULL DEFAULT '{}'::jsonb,
    record           BOOLEAN NOT NULL DEFAULT false,
    max_result_bytes BIGINT NOT NULL DEFAULT 0,
    redact           JSONB NOT NULL DEFAULT '[]'::jsonb,
    disable_injection_scan BOOLEAN NOT NULL DEFAULT false,
    epoch            TEXT NOT NULL DEFAULT ''
);`

// idempotent migrations for tables created before approval/record/guardrail
// columns existed.
const connectorsMigrate = `
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS approval JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS record BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS max_result_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS redact JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS disable_injection_scan BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE narthex_connectors ADD COLUMN IF NOT EXISTS epoch TEXT NOT NULL DEFAULT '';`

const namespacesSchema = `
CREATE TABLE IF NOT EXISTS narthex_namespaces (
    slug     TEXT PRIMARY KEY,
    label    TEXT NOT NULL DEFAULT '',
    epoch    TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1)
);
CREATE TABLE IF NOT EXISTS narthex_namespace_accounts (
    namespace_slug TEXT NOT NULL REFERENCES narthex_namespaces(slug) ON DELETE CASCADE,
    account_name   TEXT NOT NULL REFERENCES narthex_accounts(name) ON DELETE CASCADE,
    PRIMARY KEY (namespace_slug, account_name)
);
CREATE INDEX IF NOT EXISTS narthex_namespace_accounts_account_idx
    ON narthex_namespace_accounts (account_name);`

const pendingSchema = `
CREATE TABLE IF NOT EXISTS pending_calls (
    id                      TEXT PRIMARY KEY,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    connector               TEXT NOT NULL DEFAULT '',
    account                 TEXT NOT NULL DEFAULT '',
    account_incarnation_id  TEXT NOT NULL DEFAULT '',
    account_revision        BIGINT NOT NULL DEFAULT 0,
    connection_namespace_id TEXT NOT NULL DEFAULT '',
    tool                    TEXT NOT NULL DEFAULT '',
    args                    TEXT NOT NULL DEFAULT '{}',
    status                  TEXT NOT NULL DEFAULT 'pending',
    expires_at              TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '3 minutes'),
    decided_at              TIMESTAMPTZ,
    decided_by              TEXT NOT NULL DEFAULT '',
    decision_note           TEXT NOT NULL DEFAULT '',
    kind                    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS pending_calls_ts_idx ON pending_calls (ts DESC);`

// idempotent migration for tables created when args was JSONB: the column
// becomes TEXT so it can hold the enc:-prefixed ciphertext (legacy plaintext
// JSON rows keep working — s.dec passes un-prefixed values through).
const pendingMigrate = `
ALTER TABLE pending_calls ALTER COLUMN args DROP DEFAULT;
ALTER TABLE pending_calls ALTER COLUMN args TYPE TEXT USING args::text;
ALTER TABLE pending_calls ALTER COLUMN args SET DEFAULT '{}';
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS decision_note TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS account_incarnation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS account_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS connection_namespace_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_calls ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT '';
UPDATE pending_calls
SET expires_at = ts + interval '3 minutes'
WHERE expires_at IS NULL;
ALTER TABLE pending_calls ALTER COLUMN expires_at SET DEFAULT (now() + interval '3 minutes');
ALTER TABLE pending_calls ALTER COLUMN expires_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS pending_calls_pending_expiry_idx
    ON pending_calls (expires_at) WHERE status = 'pending';`

const callsSchema = `
CREATE TABLE IF NOT EXISTS tool_calls (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    account   TEXT NOT NULL,
    tool      TEXT NOT NULL,
    ok        BOOLEAN NOT NULL,
    ms        BIGINT NOT NULL,
    error     TEXT NOT NULL DEFAULT '',
    connector TEXT NOT NULL DEFAULT '',
    endpoint_kind TEXT NOT NULL DEFAULT '',
    endpoint_generation TEXT NOT NULL DEFAULT '',
    decision  TEXT NOT NULL DEFAULT '',
    args      TEXT NOT NULL DEFAULT '',
    result    TEXT NOT NULL DEFAULT '',
    guard     TEXT NOT NULL DEFAULT '',
    triage    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tool_calls_ts_idx ON tool_calls (ts DESC);`

// idempotent migrations for tables created before the flight-recorder /
// guardrail columns.
const callsMigrate = `
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS connector TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS endpoint_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS endpoint_generation TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS decision TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS args TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS guard TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS triage TEXT NOT NULL DEFAULT '';`

// LogCall is non-blocking: a tool call must never fail or wait on audit
// persistence. The bounded writer makes any overload explicit through its
// stats/logs rather than creating one goroutine per governed call. Args/Result
// are clamped and encrypted by the worker at rest (nil cipher = plaintext,
// same as token columns).
func (s *PgStore) LogCall(rec CallRecord) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.enqueue(rec)
}

// encryptAuditFields clamps and encrypts the at-rest-sensitive audit columns.
// The error text joins args/result behind the cipher: upstream errors can
// embed URLs with query tokens or echoed input, and incident review reads
// exactly these rows. Legacy plaintext rows predate encryption and keep
// reading through s.dec's passthrough.
func (s *PgStore) encryptAuditFields(rec CallRecord) (args, result, auditErr string, err error) {
	if args, err = s.enc(clampPayload(rec.Args, maxPayloadBytes)); err != nil {
		return "", "", "", fmt.Errorf("encrypt audit arguments: %w", err)
	}
	if result, err = s.enc(clampPayload(rec.Result, maxPayloadBytes)); err != nil {
		return "", "", "", fmt.Errorf("encrypt audit result: %w", err)
	}
	if auditErr, err = s.enc(clampErr(rec.Error)); err != nil {
		return "", "", "", fmt.Errorf("encrypt audit error: %w", err)
	}
	return args, result, auditErr, nil
}

func (s *PgStore) persistAuditCall(ctx context.Context, rec CallRecord) error {
	args, result, auditErr, err := s.encryptAuditFields(rec)
	if err != nil {
		return err
	}
	if s == nil || s.pool == nil {
		return errors.New("Postgres audit pool is unavailable")
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO tool_calls (
    ts,account,tool,ok,ms,error,connector,endpoint_kind,endpoint_generation,decision,args,result,guard
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		rec.TS, rec.Account, rec.Tool, rec.OK, rec.Ms, auditErr,
		rec.Connector, rec.EndpointKind, rec.EndpointGeneration, rec.Decision,
		args, result,
		rec.Guard); err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

// AuditPersistenceStats returns bounded-writer health without exposing audit
// payloads. It is deliberately a concrete-store diagnostic rather than part
// of AuditSink so existing file-backed development stores remain unchanged.
func (s *PgStore) AuditPersistenceStats() AuditPersistenceStats {
	if s == nil {
		return AuditPersistenceStats{}
	}
	return s.audit.stats()
}

// undecryptableAuditErrorPlaceholder replaces an audit error field that fails
// to decrypt (wrong/rotated key, corrupt ciphertext). Only the error column is
// ever ciphertext here — successful calls store error="" and never touch the
// cipher — so a decrypt failure disproportionately affects FAILED-call rows,
// exactly what an incident investigator needs most. The row's other fields
// never needed decryption and stay trustworthy, so RecentCalls keeps the row
// (like PgStore.Accounts omits only the one unreadable field/record, not the
// whole list) instead of hiding it.
const undecryptableAuditErrorPlaceholder = "[undecryptable]"

// RecentCalls is summary-only: Args/Result are never selected, so the 100-row
// list response stays payload-free (and no decryption work happens per row).
// Guard IS selected — it's tiny and the Activity UI chips on it. The id
// tie-break matches RecentCallsBefore's ORDER BY exactly: without it, rows
// sharing one exact ts could sort differently between this query (which
// always produces the first /api/logs page) and RecentCallsBefore (which
// produces every page after it), duplicating some rows across the two pages
// and permanently losing others at the boundary.
func (s *PgStore) RecentCalls(ctx context.Context, limit int) ([]CallRecord, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id,ts,account,tool,ok,ms,error,connector,endpoint_kind,endpoint_generation,decision,guard,triage
FROM tool_calls ORDER BY ts DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CallRecord
	for rows.Next() {
		var c CallRecord
		if err := rows.Scan(
			&c.ID, &c.TS, &c.Account, &c.Tool, &c.OK, &c.Ms, &c.Error,
			&c.Connector, &c.EndpointKind, &c.EndpointGeneration,
			&c.Decision, &c.Guard, &c.Triage,
		); err != nil {
			continue
		}
		// Legacy rows hold plaintext errors; s.dec passes them through. A
		// decrypt failure must not drop the whole row (see
		// undecryptableAuditErrorPlaceholder) — omit just the unreadable field,
		// log the row ID only (never decrypted/attempted-decrypt content), and
		// keep the rest of the row intact.
		auditErr, err := s.dec(c.Error)
		if err != nil {
			log.Printf("engine: omit unreadable audit error for call %d: %v", c.ID, err)
			auditErr = undecryptableAuditErrorPlaceholder
		}
		c.Error = auditErr
		out = append(out, c)
	}
	return out, nil
}

// RecentCallsBefore pages backward from a keyset cursor for the Activity
// "Load older" control — RecentCalls alone hard-caps at the newest `limit`
// rows. Same summary-only contract as RecentCalls: Args/Result are never
// selected, Guard IS selected (it's tiny, and the Activity UI chips on it).
func (s *PgStore) RecentCallsBefore(ctx context.Context, beforeTS time.Time, beforeID int64, limit int) ([]CallRecord, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id,ts,account,tool,ok,ms,error,connector,endpoint_kind,endpoint_generation,decision,guard,triage
FROM tool_calls WHERE (ts, id) < ($2, $3) ORDER BY ts DESC, id DESC LIMIT $1`, limit, beforeTS, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CallRecord
	for rows.Next() {
		var c CallRecord
		if err := rows.Scan(
			&c.ID, &c.TS, &c.Account, &c.Tool, &c.OK, &c.Ms, &c.Error,
			&c.Connector, &c.EndpointKind, &c.EndpointGeneration,
			&c.Decision, &c.Guard, &c.Triage,
		); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// CallDetail returns one full record including decrypted payloads.
func (s *PgStore) CallDetail(ctx context.Context, id int64) (CallRecord, bool, error) {
	var c CallRecord
	err := s.pool.QueryRow(ctx, `
SELECT id,ts,account,tool,ok,ms,error,connector,endpoint_kind,endpoint_generation,decision,args,result,guard,triage
FROM tool_calls WHERE id=$1`, id).Scan(
		&c.ID, &c.TS, &c.Account, &c.Tool, &c.OK, &c.Ms, &c.Error,
		&c.Connector, &c.EndpointKind, &c.EndpointGeneration,
		&c.Decision, &c.Args, &c.Result, &c.Guard, &c.Triage,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CallRecord{}, false, nil
	}
	if err != nil {
		return CallRecord{}, false, err
	}
	args, err := s.dec(c.Args)
	if err != nil {
		return CallRecord{}, false, fmt.Errorf("decrypt call %d arguments: %w", id, err)
	}
	result, err := s.dec(c.Result)
	if err != nil {
		return CallRecord{}, false, fmt.Errorf("decrypt call %d result: %w", id, err)
	}
	auditErr, err := s.dec(c.Error)
	if err != nil {
		return CallRecord{}, false, fmt.Errorf("decrypt call %d error: %w", id, err)
	}
	c.Args, c.Result, c.Error = args, result, auditErr
	return c, true, nil
}

func (s *PgStore) SetCallTriage(ctx context.Context, id int64, triage string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE tool_calls SET triage=$2 WHERE id=$1`, id, triage)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("call %d not found", id)
	}
	return nil
}

// PurgeCalls deletes audit rows older than the cutoff (retention). Cheap via
// tool_calls_ts_idx / pending_calls_ts_idx. Decided approval rows age out
// under the same window — they carry recorded args too; still-pending rows
// are kept (they expire via ExpireOrphanedPending, then age out).
func (s *PgStore) PurgeCalls(ctx context.Context, olderThan time.Duration) (int64, error) {
	secs := int64(olderThan.Seconds())
	tag, err := s.pool.Exec(ctx, `DELETE FROM tool_calls WHERE ts < now() - ($1::bigint * interval '1 second')`, secs)
	if err != nil {
		return 0, err
	}
	n := tag.RowsAffected()
	tag, err = s.pool.Exec(ctx, `DELETE FROM pending_calls WHERE status <> 'pending' AND ts < now() - ($1::bigint * interval '1 second')`, secs)
	if err != nil {
		return n, err
	}
	return n + tag.RowsAffected(), nil
}

// Shutdown drains the bounded audit queue before closing the database pool.
// It matches the optional Engine dependency hook, so graceful process
// shutdown does not drop rows simply because the HTTP listener stopped first.
func (s *PgStore) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.audit != nil {
		if err := s.audit.Shutdown(ctx); err != nil {
			// The writer has been cancelled but may still be unwinding an
			// in-flight driver call. Closing the pool here would race it, so
			// schedule exactly one final close once that worker exits.
			s.closePoolAfterAuditExit()
			return err
		}
	}
	s.closePool()
	return nil
}

func (s *PgStore) closePool() {
	s.poolCloseOnce.Do(func() {
		if s.pool != nil {
			s.pool.Close()
		}
	})
}

func (s *PgStore) closePoolAfterAuditExit() {
	if s == nil || s.audit == nil {
		return
	}
	s.poolCloseAfterAuditOnce.Do(func() {
		go func() {
			<-s.audit.done
			s.closePool()
		}()
	})
}

// Close preserves the legacy no-error cleanup API used by callers and tests.
// Production lifecycle uses Shutdown with its larger drain budget; direct
// callers get a bounded best-effort drain rather than an unbounded wait.
func (s *PgStore) Close() {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), engineAuditCloseTimeout)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Printf("engine: audit shutdown during store close: %v", err)
	}
}

type accountScanner interface {
	Scan(...any) error
}

func (s *PgStore) scanAccount(row accountScanner) (Account, error) {
	var a Account
	var overrides []byte
	err := row.Scan(
		&a.Name, &a.Label, &a.Group, &a.URL, &a.AuthMode,
		&a.ConnectionNamespaceID, &a.ConnectionScope, &a.OwnerSubject, &a.Revision,
		&a.IncarnationID,
		&a.ClientID, &a.ClientSecret, &a.AccessToken, &a.RefreshToken,
		&a.TokenEndpoint, &a.Resource, &a.Scope, &a.BearerToken,
		&a.DisabledTools, &overrides, &a.ReadOnly,
	)
	if err != nil {
		return Account{}, err
	}
	if err := json.Unmarshal(overrides, &a.ToolOverrides); err != nil {
		return Account{}, err
	}
	if a.ClientSecret, err = s.dec(a.ClientSecret); err != nil {
		return Account{}, fmt.Errorf("decrypt account %q client secret: %w", a.Name, err)
	}
	if a.AccessToken, err = s.dec(a.AccessToken); err != nil {
		return Account{}, fmt.Errorf("decrypt account %q access token: %w", a.Name, err)
	}
	if a.RefreshToken, err = s.dec(a.RefreshToken); err != nil {
		return Account{}, fmt.Errorf("decrypt account %q refresh token: %w", a.Name, err)
	}
	if a.BearerToken, err = s.dec(a.BearerToken); err != nil {
		return Account{}, fmt.Errorf("decrypt account %q bearer token: %w", a.Name, err)
	}
	return a, nil
}

func (s *PgStore) Accounts() []Account {
	rows, err := s.pool.Query(context.Background(), `SELECT `+accountCols+` FROM narthex_accounts ORDER BY name`)
	if err != nil {
		log.Printf("engine: list accounts failed: %v", err)
		return nil
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := s.scanAccount(rows)
		if err != nil {
			// AccountStore predates error-returning list methods. Keep this
			// constrained compatibility API fail-closed, while making the
			// operational cause explicit without logging secret values.
			log.Printf("engine: omit unreadable account: %v", err)
			continue
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		log.Printf("engine: iterate accounts failed: %v", err)
	}
	return out
}

func (s *PgStore) Token(name string) string {
	var auth, access, bearer string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT auth_mode,access_token,bearer_token FROM narthex_accounts WHERE name=$1`, name).
		Scan(&auth, &access, &bearer); err != nil {
		log.Printf("engine: read token for account %q failed: %v", name, err)
		return ""
	}
	var value string
	var err error
	if auth == "token" {
		value, err = s.dec(bearer)
	} else {
		value, err = s.dec(access)
	}
	if err != nil {
		log.Printf("engine: credential for account %q is unavailable: %v", name, err)
		return ""
	}
	return value
}

func (s *PgStore) RefreshToken(name string) string {
	var rt string
	if err := s.pool.QueryRow(context.Background(), `SELECT refresh_token FROM narthex_accounts WHERE name=$1`, name).Scan(&rt); err != nil {
		log.Printf("engine: read refresh token for account %q failed: %v", name, err)
		return ""
	}
	value, err := s.dec(rt)
	if err != nil {
		log.Printf("engine: refresh credential for account %q is unavailable: %v", name, err)
		return ""
	}
	return value
}

func (s *PgStore) UpdateTokens(ctx context.Context, name, expectedIncarnationID, access, refresh string) error {
	if expectedIncarnationID == "" {
		return ErrAccountIncarnation
	}
	encryptedAccess, err := s.enc(access)
	if err != nil {
		return fmt.Errorf("encrypt access token: %w", err)
	}
	var encryptedRefresh string
	if refresh != "" {
		encryptedRefresh, err = s.enc(refresh)
		if err != nil {
			return fmt.Errorf("encrypt refresh token: %w", err)
		}
	}
	var tag pgconn.CommandTag
	if refresh != "" {
		tag, err = s.pool.Exec(ctx, `UPDATE narthex_accounts SET access_token=$3, refresh_token=$4 WHERE name=$1 AND incarnation_id=$2`, name, expectedIncarnationID, encryptedAccess, encryptedRefresh)
	} else {
		tag, err = s.pool.Exec(ctx, `UPDATE narthex_accounts SET access_token=$3 WHERE name=$1 AND incarnation_id=$2`, name, expectedIncarnationID, encryptedAccess)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAccountIncarnation
	}
	return nil
}

// SetBearerToken updates one credential under the account's current ownership
// revision. The lock/CAS is intentional: a manager who was just removed from
// a namespace must not be able to race a token write that restores stale
// account metadata through a whole-row Upsert.
func (s *PgStore) SetBearerToken(ctx context.Context, name, expectedIncarnationID, token string, expectedRevision int64) (Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)
	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if expectedIncarnationID == "" || current.IncarnationID != expectedIncarnationID {
		return Account{}, ErrAccountIncarnation
	}
	if expectedRevision < 1 || current.Revision != expectedRevision {
		return Account{}, ErrConnectionNamespaceRevision
	}
	encryptedToken, err := s.enc(token)
	if err != nil {
		return Account{}, fmt.Errorf("encrypt bearer token: %w", err)
	}
	updated, err := s.scanAccount(tx.QueryRow(ctx, `
UPDATE narthex_accounts
SET auth_mode='token', bearer_token=$2, revision=revision+1
WHERE name=$1
RETURNING `+accountCols, name, encryptedToken))
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	return updated, nil
}

// Create inserts a new account without replacing an existing account with the
// same name. The database constraint makes this check atomic across requests.
func (s *PgStore) Create(ctx context.Context, a Account) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	// Store-owned identity: callers cannot recreate a deleted account with its
	// former incarnation identifier.
	a.IncarnationID = newAccountIncarnationID()
	if err := s.ensureAccountConnectionNamespaceTx(ctx, tx, &a); err != nil {
		return err
	}
	if a.IsPersonal() {
		if err := lockMCPClientNamespacesTx(ctx, tx, []string{a.ConnectionNamespaceID}); err != nil {
			return err
		}
	}
	if err := validatePersonalAccountMCPClientGrantsTx(ctx, tx, a); err != nil {
		return err
	}
	ob, err := json.Marshal(a.ToolOverrides)
	if err != nil {
		return err
	}
	if a.ToolOverrides == nil {
		ob = []byte(`{}`)
	}
	clientSecret, accessToken, refreshToken, bearerToken, err := s.encryptAccountSecrets(a)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO narthex_accounts (`+accountCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT (name) DO NOTHING`,
		a.Name, a.Label, a.Group, a.URL, a.AuthMode,
		a.ConnectionNamespaceID, a.ConnectionScope, a.OwnerSubject, a.Revision,
		a.IncarnationID, a.ClientID, clientSecret, accessToken, refreshToken,
		a.TokenEndpoint, a.Resource, a.Scope, bearerToken, a.DisabledTools, ob, a.ReadOnly)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAccountExists
	}
	return tx.Commit(ctx)
}

// Upsert adds or updates an account — used by the console "Connect" flow and by
// migration. Tokens included so a freshly-connected account works immediately.
// Caller-supplied revisions are ignored on update: the store owns revision
// monotonicity, deriving the new revision from the locked prior row (bump on
// ownership change, preserve otherwise).
func (s *PgStore) Upsert(ctx context.Context, a Account) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	var previous *Account
	stored, readErr := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, a.Name))
	if readErr == nil {
		previous = &stored
		// The account identity is immutable across whole-row updates.
		a.IncarnationID = stored.IncarnationID
		if a.IncarnationID == "" {
			a.IncarnationID = newAccountIncarnationID()
		}
		// Preserve an already-personal boundary when a legacy upsert omits all
		// new ownership fields. A caller that wants to change the boundary must
		// use MoveAccountToConnectionNamespace with an account revision.
		if strings.TrimSpace(a.ConnectionNamespaceID) == "" && strings.TrimSpace(string(a.ConnectionScope)) == "" && strings.TrimSpace(a.OwnerSubject) == "" && stored.IsPersonal() {
			a.ConnectionNamespaceID = stored.ConnectionNamespaceID
			a.ConnectionScope = stored.ConnectionScope
			a.OwnerSubject = stored.OwnerSubject
			a.Group = stored.Group
		}
	} else if !errors.Is(readErr, pgx.ErrNoRows) {
		return readErr
	}
	if previous == nil {
		a.IncarnationID = newAccountIncarnationID()
	}
	if err := s.ensureAccountConnectionNamespaceTx(ctx, tx, &a); err != nil {
		return err
	}
	var affectedClients []MCPClient
	if previous != nil && accountOwnershipChanged(*previous, a) {
		// Whole-account compatibility writes (including self-hosted
		// /admin/token) may still carry only a legacy Group label. Once that
		// label resolves to a different durable folder, use the exact locking
		// and epoch-rotation boundary as an explicit account move.
		affectedClients, err = prepareMCPClientEpochRotationForAccountOwnershipChangeTx(ctx, tx, *previous, a)
		if err != nil {
			return err
		}
	} else if a.IsPersonal() {
		if err := lockMCPClientNamespacesTx(ctx, tx, []string{a.ConnectionNamespaceID}); err != nil {
			return err
		}
	}
	if err := validatePersonalAccountMCPClientGrantsTx(ctx, tx, a); err != nil {
		return err
	}
	if previous != nil {
		// The store owns revision monotonicity: derive the new revision from the
		// locked prior row, ignoring any caller-supplied value.
		if a.ConnectionNamespaceID != previous.ConnectionNamespaceID || a.ConnectionScope != previous.ConnectionScope || a.OwnerSubject != previous.OwnerSubject {
			a.Revision = previous.Revision + 1
		} else {
			a.Revision = previous.Revision
		}
	}
	ob, err := json.Marshal(a.ToolOverrides)
	if err != nil {
		return err
	}
	if a.ToolOverrides == nil {
		ob = []byte(`{}`)
	}
	clientSecret, accessToken, refreshToken, bearerToken, err := s.encryptAccountSecrets(a)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO narthex_accounts (`+accountCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT (name) DO UPDATE SET
  label=$2, workspace=$3, url=$4, auth_mode=$5,
  connection_namespace_id=$6, connection_scope=$7, owner_subject=$8, revision=$9,
	incarnation_id=CASE
	  WHEN narthex_accounts.incarnation_id='' THEN EXCLUDED.incarnation_id
	  ELSE narthex_accounts.incarnation_id
	END,
  client_id=$11, client_secret=$12, access_token=$13, refresh_token=$14,
  token_endpoint=$15, resource=$16, scope=$17, bearer_token=$18,
  disabled_tools=$19, tool_overrides=$20, read_only=$21`,
		a.Name, a.Label, a.Group, a.URL, a.AuthMode,
		a.ConnectionNamespaceID, a.ConnectionScope, a.OwnerSubject, a.Revision,
		a.IncarnationID, a.ClientID, clientSecret, accessToken, refreshToken,
		a.TokenEndpoint, a.Resource, a.Scope, bearerToken, a.DisabledTools, ob, a.ReadOnly)
	if err != nil {
		return err
	}
	if a.IsPersonal() {
		if err := removePersonalAccountExposureTx(ctx, tx, a.Name); err != nil {
			return err
		}
	}
	if previous != nil && accountOwnershipChanged(*previous, a) {
		if err := rotateMCPClientEpochsForAccountMoveTx(ctx, tx, affectedClients, *previous, a); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// CompleteOAuth locks the account row, verifies its immutable incarnation and
// ownership boundary, and updates credential columns only. Metadata and policy
// edits that happen while provider consent is open are therefore never
// replaced by an older whole-Account snapshot.
func (s *PgStore) CompleteOAuth(ctx context.Context, precondition OAuthCompletionPrecondition, completion Account) (Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)

	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, completion.Name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrConnectAccountDeleted
	}
	if err != nil {
		return Account{}, err
	}
	if precondition.IncarnationID == "" || current.IncarnationID != precondition.IncarnationID {
		return Account{}, ErrConnectAccountReplaced
	}
	if !equalAccountURL(current.URL, precondition.URL) {
		return Account{}, ErrConnectAccountURLChanged
	}
	if current.ConnectionNamespaceID != precondition.ConnectionNamespaceID ||
		current.ConnectionScope != precondition.ConnectionScope ||
		current.OwnerSubject != precondition.OwnerSubject {
		return Account{}, ErrConnectAccountMoved
	}

	refresh := completion.RefreshToken
	if refresh == "" && current.ClientID == completion.ClientID {
		refresh = current.RefreshToken
	}
	encryptedClientSecret, err := s.enc(completion.ClientSecret)
	if err != nil {
		return Account{}, fmt.Errorf("encrypt OAuth client secret: %w", err)
	}
	encryptedAccessToken, err := s.enc(completion.AccessToken)
	if err != nil {
		return Account{}, fmt.Errorf("encrypt OAuth access token: %w", err)
	}
	encryptedRefreshToken, err := s.enc(refresh)
	if err != nil {
		return Account{}, fmt.Errorf("encrypt OAuth refresh token: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET auth_mode='oauth', client_id=$2, client_secret=$3, access_token=$4,
    refresh_token=$5, token_endpoint=$6, resource=$7, scope=$8, bearer_token=''
WHERE name=$1`, completion.Name, completion.ClientID, encryptedClientSecret,
		encryptedAccessToken, encryptedRefreshToken, completion.TokenEndpoint,
		completion.Resource, completion.Scope); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	current.AuthMode = "oauth"
	current.ClientID, current.ClientSecret = completion.ClientID, completion.ClientSecret
	current.AccessToken, current.RefreshToken = completion.AccessToken, refresh
	current.TokenEndpoint, current.Resource, current.Scope = completion.TokenEndpoint, completion.Resource, completion.Scope
	current.BearerToken = ""
	return current, nil
}

// SaveStaticOAuthConfig records a pre-registered OAuth application before the
// browser is redirected to the provider. The existing provider tokens remain
// untouched, so a cancelled authorization does not disrupt a previously
// working account; only the durable client configuration is updated.
func (s *PgStore) SaveStaticOAuthConfig(ctx context.Context, name string, precondition OAuthCompletionPrecondition, config StaticOAuthConfig) (Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)

	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrConnectAccountDeleted
	}
	if err != nil {
		return Account{}, err
	}
	if precondition.IncarnationID == "" || current.IncarnationID != precondition.IncarnationID {
		return Account{}, ErrConnectAccountReplaced
	}
	if !equalAccountURL(current.URL, precondition.URL) {
		return Account{}, ErrConnectAccountURLChanged
	}
	if current.ConnectionNamespaceID != precondition.ConnectionNamespaceID ||
		current.ConnectionScope != precondition.ConnectionScope ||
		current.OwnerSubject != precondition.OwnerSubject {
		return Account{}, ErrConnectAccountMoved
	}
	encryptedClientSecret, err := s.enc(config.ClientSecret)
	if err != nil {
		return Account{}, fmt.Errorf("encrypt OAuth client secret: %w", err)
	}

	if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET client_id=$2, client_secret=$3, scope=$4
WHERE name=$1`, name, config.ClientID, encryptedClientSecret, config.Scope); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	current.ClientID = config.ClientID
	current.ClientSecret = config.ClientSecret
	current.Scope = config.Scope
	return current, nil
}

func (s *PgStore) Account(name string) (Account, bool) {
	a, err := s.scanAccount(s.pool.QueryRow(context.Background(), `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1`, name))
	if err != nil {
		log.Printf("engine: account %q is unavailable: %v", name, err)
		return Account{}, false
	}
	return a, true
}

// UpdateAccountPolicy applies only curation/presentation fields after locking
// and comparing the exact account snapshot authorized by the console. In
// particular, no ownership column appears in the SET clause: a stale manager
// cannot restore a namespace assignment which changed after authorization.
func (s *PgStore) UpdateAccountPolicy(ctx context.Context, name string, precondition AccountPolicyPrecondition, mutation AccountPolicyMutation) (Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)

	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountPolicyPrecondition
	}
	if err != nil {
		return Account{}, err
	}
	if !precondition.matches(current) {
		return Account{}, ErrAccountPolicyPrecondition
	}

	changed := false
	if mutation.Label != nil {
		label := strings.TrimSpace(*mutation.Label)
		if current.Label != label {
			current.Label = label
			changed = true
		}
	}
	if mutation.DisabledTools != nil {
		disabled := append([]string(nil), (*mutation.DisabledTools)...)
		if !sameStrings(current.DisabledTools, disabled) {
			current.DisabledTools = disabled
			changed = true
		}
	}
	if mutation.ToolOverrides != nil {
		overrides := copyAccount(Account{ToolOverrides: *mutation.ToolOverrides}).ToolOverrides
		if !sameToolOverrides(current.ToolOverrides, overrides) {
			current.ToolOverrides = overrides
			changed = true
		}
	}
	if mutation.ReadOnly != nil && current.ReadOnly != *mutation.ReadOnly {
		current.ReadOnly = *mutation.ReadOnly
		changed = true
	}
	if !changed {
		if err := tx.Commit(ctx); err != nil {
			return Account{}, err
		}
		return current, nil
	}

	overrides, err := json.Marshal(current.ToolOverrides)
	if err != nil {
		return Account{}, err
	}
	if current.ToolOverrides == nil {
		overrides = []byte(`{}`)
	}
	beforeRevision := current.Revision
	current.Revision++
	updated, err := s.scanAccount(tx.QueryRow(ctx, `
UPDATE narthex_accounts
SET label=$2,disabled_tools=$3,tool_overrides=$4,read_only=$5,revision=$6
WHERE name=$1
  AND incarnation_id=$7
  AND revision=$8
  AND connection_namespace_id=$9
  AND connection_scope=$10
  AND owner_subject=$11
RETURNING `+accountCols,
		current.Name, current.Label, current.DisabledTools, overrides, current.ReadOnly, current.Revision,
		precondition.IncarnationID, beforeRevision, precondition.ConnectionNamespaceID,
		precondition.ConnectionScope, precondition.OwnerSubject))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountPolicyPrecondition
	}
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	return updated, nil
}

func (s *PgStore) SetDisabledTools(ctx context.Context, name string, disabled []string) error {
	_, err := s.pool.Exec(ctx, `UPDATE narthex_accounts SET disabled_tools=$2 WHERE name=$1`, name, disabled)
	return err
}

func (s *PgStore) SetToolOverride(ctx context.Context, name, tool string, override ToolOverride) error {
	a, ok := s.Account(name)
	if !ok {
		return fmt.Errorf("account %q not found", name)
	}
	if a.ToolOverrides == nil {
		a.ToolOverrides = map[string]ToolOverride{}
	}
	if override.Alias == "" && override.Description == "" {
		delete(a.ToolOverrides, tool)
	} else {
		a.ToolOverrides[tool] = override
	}
	b, err := json.Marshal(a.ToolOverrides)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE narthex_accounts SET tool_overrides=$2 WHERE name=$1`, name, b)
	return err
}

func (s *PgStore) SetReadOnly(ctx context.Context, name string, ro bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE narthex_accounts SET read_only=$2 WHERE name=$1`, name, ro)
	return err
}

func (s *PgStore) Delete(ctx context.Context, name, expectedIncarnationID string, expectedRevision int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentIncarnationID string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT incarnation_id,revision FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name).Scan(&currentIncarnationID, &currentRevision); errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountIncarnation
	} else if err != nil {
		return err
	}
	if expectedIncarnationID == "" || currentIncarnationID != expectedIncarnationID {
		return ErrAccountIncarnation
	}
	if expectedRevision < 1 || currentRevision != expectedRevision {
		return ErrConnectionNamespaceRevision
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_namespaces
SET revision=revision+1
WHERE slug IN (
    SELECT namespace_slug FROM narthex_namespace_accounts WHERE account_name=$1
)`, name); err != nil {
		return err
	}
	// A connector's JSONB maps are keyed by the immutable account/tool prefix.
	// Prune both maps in the same transaction as account deletion so recreating
	// the same prefix cannot silently inherit the old connector exposure or
	// leave portable config referencing a nonexistent account.
	if _, err := tx.Exec(ctx, `
UPDATE narthex_connectors
SET tools=tools - $1, approval=approval - $1
WHERE tools ? $1 OR approval ? $1`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PgStore) SetMeta(ctx context.Context, name, label, group string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // preserve historical no-op behavior for a deleted account
	}
	if err != nil {
		return err
	}
	label, group = strings.TrimSpace(label), strings.TrimSpace(group)
	before := current
	// SetMeta is intentionally label-only. Reassigning an account by legacy
	// Group here could let a stale metadata write undo a newer CAS ownership
	// move. Intentional legacy group-only changes go through Upsert, which
	// serializes and rotates affected scoped MCP-client epochs.
	if group != strings.TrimSpace(before.Group) {
		return fmt.Errorf("%w: use MoveAccountToConnectionNamespace for ownership changes", ErrConnectionNamespaceRevision)
	}
	current.Label = label
	if current.Label == before.Label {
		return tx.Commit(ctx)
	}
	current.Revision = before.Revision + 1
	if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET label=$2, revision=$3
WHERE name=$1`, current.Name, current.Label, current.Revision); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UpdatePortableAccountConfig atomically changes only the secret-free fields
// carried by portable config. Ownership, credentials, and OAuth metadata are
// intentionally absent from the UPDATE: an import based on an old export can
// never overwrite a concurrent connection-namespace move.
func (s *PgStore) UpdatePortableAccountConfig(ctx context.Context, name string, update PortableAccountConfig) (Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)
	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, err
	}
	update.Label = strings.TrimSpace(update.Label)
	update.URL = strings.TrimSpace(update.URL)
	if (current.BearerToken != "" || current.AccessToken != "" || current.RefreshToken != "" || current.ClientSecret != "") &&
		!equalAccountURL(current.URL, update.URL) {
		return Account{}, ErrConnectAccountURLChanged
	}
	overrides, err := json.Marshal(update.ToolOverrides)
	if err != nil {
		return Account{}, err
	}
	if update.ToolOverrides == nil {
		overrides = []byte(`{}`)
	}
	updated, err := s.scanAccount(tx.QueryRow(ctx, `
UPDATE narthex_accounts
SET label=$2,url=$3,disabled_tools=$4,tool_overrides=$5,read_only=$6
WHERE name=$1
RETURNING `+accountCols,
		current.Name, update.Label, update.URL, update.DisabledTools, overrides, update.ReadOnly))
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	return updated, nil
}

func rejectPersonalAccountsTx(ctx context.Context, tx pgx.Tx, accounts []string) error {
	if len(accounts) == 0 {
		return nil
	}
	var account string
	err := tx.QueryRow(ctx, `
SELECT name
FROM narthex_accounts
WHERE name = ANY($1) AND connection_scope='personal'
ORDER BY name
LIMIT 1`, accounts).Scan(&account)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrPersonalAccountExposure, account)
}

// ---- PgStore: ConnectorStore ----
// No secrets in connectors — the cipher is not involved.

func (s *PgStore) Connectors(ctx context.Context) ([]VirtualConnector, error) {
	rows, err := s.pool.Query(ctx, `SELECT slug,label,tools,approval,record,max_result_bytes,redact,disable_injection_scan,epoch FROM narthex_connectors ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VirtualConnector
	for rows.Next() {
		var c VirtualConnector
		var tools, approval, redact []byte
		if err := rows.Scan(&c.Slug, &c.Label, &tools, &approval, &c.Record, &c.MaxResultBytes, &redact, &c.DisableInjectionScan, &c.Epoch); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(tools, &c.Tools); err != nil {
			return nil, fmt.Errorf("connector %q tools: %w", c.Slug, err)
		}
		if err := json.Unmarshal(approval, &c.Approval); err != nil {
			return nil, fmt.Errorf("connector %q approval: %w", c.Slug, err)
		}
		if err := json.Unmarshal(redact, &c.Redact); err != nil {
			return nil, fmt.Errorf("connector %q redact: %w", c.Slug, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PgStore) VirtualConnector(ctx context.Context, slug string) (VirtualConnector, bool) {
	var c VirtualConnector
	var tools, approval, redact []byte
	err := s.pool.QueryRow(ctx, `SELECT slug,label,tools,approval,record,max_result_bytes,redact,disable_injection_scan,epoch FROM narthex_connectors WHERE slug=$1`, slug).
		Scan(&c.Slug, &c.Label, &tools, &approval, &c.Record, &c.MaxResultBytes, &redact, &c.DisableInjectionScan, &c.Epoch)
	if err != nil {
		return VirtualConnector{}, false
	}
	if err := json.Unmarshal(tools, &c.Tools); err != nil {
		return VirtualConnector{}, false
	}
	if err := json.Unmarshal(approval, &c.Approval); err != nil {
		return VirtualConnector{}, false
	}
	if err := json.Unmarshal(redact, &c.Redact); err != nil {
		return VirtualConnector{}, false
	}
	return c, true
}

func (s *PgStore) UpsertConnector(ctx context.Context, c VirtualConnector) error {
	// JSONB columns are NOT NULL '{}' / '[]' — never write SQL null.
	b, err := json.Marshal(orEmpty(c.Tools))
	if err != nil {
		return err
	}
	ab, err := json.Marshal(orEmpty(c.Approval))
	if err != nil {
		return err
	}
	rb, err := json.Marshal(orEmptySlice(c.Redact))
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := rejectPersonalAccountsTx(ctx, tx, accountNamesInToolMap(c.Tools)); err != nil {
		return err
	}
	if err := rejectPersonalAccountsTx(ctx, tx, accountNamesInToolMap(c.Approval)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, c.Slug); err != nil {
		return err
	}
	var namespaceExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_namespaces WHERE slug=$1)`, c.Slug).Scan(&namespaceExists); err != nil {
		return err
	}
	if namespaceExists {
		return fmt.Errorf("%w: %s", ErrEndpointCollision, c.Slug)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO narthex_connectors (slug,label,tools,approval,record,max_result_bytes,redact,disable_injection_scan,epoch) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (slug) DO UPDATE SET label=$2, tools=$3, approval=$4, record=$5, max_result_bytes=$6, redact=$7, disable_injection_scan=$8, epoch=$9`,
		c.Slug, c.Label, b, ab, c.Record, c.MaxResultBytes, rb, c.DisableInjectionScan, c.Epoch)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func orEmpty(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}

// orEmptySlice keeps a nil slice from marshaling to JSON null (the redact
// column is NOT NULL '[]'::jsonb).
func orEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *PgStore) DeleteConnector(ctx context.Context, slug, expectedGeneration string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Share the slug advisory lock with connector upserts and namespace
	// creation/deletion. This makes kind reuse linearizable across Engine
	// replicas instead of letting a stale delete remove a newer incarnation.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, slug); err != nil {
		return err
	}
	var generation string
	if err := tx.QueryRow(ctx, `SELECT epoch FROM narthex_connectors WHERE slug=$1 FOR UPDATE`, slug).Scan(&generation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConnectorNotFound
		}
		return err
	}
	if generation != expectedGeneration {
		return ErrEndpointGeneration
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug=$1`, slug); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- PgStore: NamespaceStore ----

const namespaceSelect = `
SELECT n.slug,n.label,n.epoch,n.revision,
       COALESCE(
           array_agg(m.account_name ORDER BY m.account_name)
               FILTER (WHERE m.account_name IS NOT NULL),
           ARRAY[]::TEXT[]
       )
FROM narthex_namespaces n
LEFT JOIN narthex_namespace_accounts m ON m.namespace_slug=n.slug`

type namespaceQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanNamespace(row pgx.Row) (Namespace, error) {
	var ns Namespace
	err := row.Scan(&ns.Slug, &ns.Label, &ns.Epoch, &ns.Revision, &ns.Accounts)
	if ns.Accounts == nil {
		ns.Accounts = []string{}
	}
	return ns, err
}

func loadNamespace(ctx context.Context, q namespaceQueryer, slug string) (Namespace, error) {
	return scanNamespace(q.QueryRow(ctx, namespaceSelect+`
WHERE n.slug=$1
GROUP BY n.slug,n.label,n.epoch,n.revision`, slug))
}

func (s *PgStore) Namespaces(ctx context.Context) ([]Namespace, error) {
	rows, err := s.pool.Query(ctx, namespaceSelect+`
GROUP BY n.slug,n.label,n.epoch,n.revision
ORDER BY n.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Namespace
	for rows.Next() {
		var ns Namespace
		if err := rows.Scan(&ns.Slug, &ns.Label, &ns.Epoch, &ns.Revision, &ns.Accounts); err != nil {
			return nil, err
		}
		if ns.Accounts == nil {
			ns.Accounts = []string{}
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

func (s *PgStore) Namespace(ctx context.Context, slug string) (Namespace, bool) {
	ns, err := loadNamespace(ctx, s.pool, slug)
	if err != nil {
		return Namespace{}, false
	}
	return ns, true
}

func (s *PgStore) CreateNamespace(ctx context.Context, ns Namespace) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, ns.Slug); err != nil {
		return err
	}
	var connectorExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_connectors WHERE slug=$1)`, ns.Slug).Scan(&connectorExists); err != nil {
		return err
	}
	if connectorExists {
		return fmt.Errorf("%w: %s", ErrEndpointCollision, ns.Slug)
	}
	if ns.Revision < 1 {
		ns.Revision = 1
	}
	if ns.Epoch == "" {
		ns.Epoch = newEpoch()
	}
	members := normalizedNamespaceAccounts(ns.Accounts)
	if err := rejectPersonalAccountsTx(ctx, tx, members); err != nil {
		return err
	}
	var inserted string
	if err := tx.QueryRow(ctx, `
INSERT INTO narthex_namespaces (slug,label,epoch,revision)
VALUES ($1,$2,$3,$4)
ON CONFLICT (slug) DO NOTHING
RETURNING slug`, ns.Slug, ns.Label, ns.Epoch, ns.Revision).Scan(&inserted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNamespaceExists
		}
		return err
	}
	for _, account := range members {
		tag, err := tx.Exec(ctx, `
INSERT INTO narthex_namespace_accounts (namespace_slug,account_name)
SELECT $1,name FROM narthex_accounts WHERE name=$2
ON CONFLICT DO NOTHING`, ns.Slug, account)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrAccountNotFound, account)
		}
	}
	return tx.Commit(ctx)
}

func (s *PgStore) UpdateNamespace(ctx context.Context, update Namespace, precondition NamespacePrecondition) (Namespace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Namespace{}, err
	}
	defer tx.Rollback(ctx)
	var currentGeneration string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT epoch,revision FROM narthex_namespaces WHERE slug=$1 FOR UPDATE`, update.Slug).
		Scan(&currentGeneration, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Namespace{}, ErrNamespaceNotFound
		}
		return Namespace{}, err
	}
	if precondition.Generation == "" || precondition.Revision < 1 ||
		currentGeneration != precondition.Generation || currentRevision != precondition.Revision {
		return Namespace{}, ErrNamespaceRevision
	}
	current, err := loadNamespace(ctx, tx, update.Slug)
	if err != nil {
		return Namespace{}, err
	}
	accounts := normalizedNamespaceAccounts(update.Accounts)
	if err := rejectPersonalAccountsTx(ctx, tx, accounts); err != nil {
		return Namespace{}, err
	}
	for _, account := range accounts {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_accounts WHERE name=$1)`, account).Scan(&exists); err != nil {
			return Namespace{}, err
		}
		if !exists {
			return Namespace{}, fmt.Errorf("%w: %s", ErrAccountNotFound, account)
		}
	}
	if current.Label == update.Label && sameStrings(current.Accounts, accounts) {
		if err := tx.Commit(ctx); err != nil {
			return Namespace{}, err
		}
		return current, nil
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_namespaces SET label=$2,revision=revision+1 WHERE slug=$1`,
		update.Slug, update.Label); err != nil {
		return Namespace{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_namespace_accounts WHERE namespace_slug=$1`, update.Slug); err != nil {
		return Namespace{}, err
	}
	for _, account := range accounts {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_namespace_accounts (namespace_slug,account_name) VALUES ($1,$2)`,
			update.Slug, account); err != nil {
			return Namespace{}, err
		}
	}
	ns, err := loadNamespace(ctx, tx, update.Slug)
	if err != nil {
		return Namespace{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

func (s *PgStore) AddNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Namespace{}, err
	}
	defer tx.Rollback(ctx)
	var currentGeneration string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT epoch,revision FROM narthex_namespaces WHERE slug=$1 FOR UPDATE`, slug).
		Scan(&currentGeneration, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Namespace{}, ErrNamespaceNotFound
		}
		return Namespace{}, err
	}
	if precondition.Generation == "" || precondition.Revision < 1 ||
		currentGeneration != precondition.Generation || currentRevision != precondition.Revision {
		return Namespace{}, ErrNamespaceRevision
	}
	var accountExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_accounts WHERE name=$1)`, account).Scan(&accountExists); err != nil {
		return Namespace{}, err
	}
	if !accountExists {
		return Namespace{}, fmt.Errorf("%w: %s", ErrAccountNotFound, account)
	}
	if err := rejectPersonalAccountsTx(ctx, tx, []string{account}); err != nil {
		return Namespace{}, err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO narthex_namespace_accounts (namespace_slug,account_name)
VALUES ($1,$2)
ON CONFLICT DO NOTHING`, slug, account)
	if err != nil {
		return Namespace{}, err
	}
	if tag.RowsAffected() > 0 {
		if _, err := tx.Exec(ctx, `UPDATE narthex_namespaces SET revision=revision+1 WHERE slug=$1`, slug); err != nil {
			return Namespace{}, err
		}
	}
	ns, err := loadNamespace(ctx, tx, slug)
	if err != nil {
		return Namespace{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

func (s *PgStore) RemoveNamespaceAccount(ctx context.Context, slug, account string, precondition NamespacePrecondition) (Namespace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Namespace{}, err
	}
	defer tx.Rollback(ctx)
	var currentGeneration string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT epoch,revision FROM narthex_namespaces WHERE slug=$1 FOR UPDATE`, slug).
		Scan(&currentGeneration, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Namespace{}, ErrNamespaceNotFound
		}
		return Namespace{}, err
	}
	if precondition.Generation == "" || precondition.Revision < 1 ||
		currentGeneration != precondition.Generation || currentRevision != precondition.Revision {
		return Namespace{}, ErrNamespaceRevision
	}
	tag, err := tx.Exec(ctx, `
DELETE FROM narthex_namespace_accounts
WHERE namespace_slug=$1 AND account_name=$2`, slug, account)
	if err != nil {
		return Namespace{}, err
	}
	if tag.RowsAffected() > 0 {
		if _, err := tx.Exec(ctx, `UPDATE narthex_namespaces SET revision=revision+1 WHERE slug=$1`, slug); err != nil {
			return Namespace{}, err
		}
	}
	ns, err := loadNamespace(ctx, tx, slug)
	if err != nil {
		return Namespace{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Namespace{}, err
	}
	return ns, nil
}

func (s *PgStore) DeleteNamespace(ctx context.Context, slug string, precondition NamespacePrecondition) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize namespace deletion with connector upsert and namespace create
	// for this slug. The generation+revision comparison then rejects a stale
	// replica after delete/recreate, even when the recreated row reset to v1.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, slug); err != nil {
		return err
	}
	var currentGeneration string
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT epoch,revision FROM narthex_namespaces WHERE slug=$1 FOR UPDATE`, slug).
		Scan(&currentGeneration, &currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNamespaceNotFound
		}
		return err
	}
	if precondition.Generation == "" || precondition.Revision < 1 ||
		currentGeneration != precondition.Generation || currentRevision != precondition.Revision {
		return ErrNamespaceRevision
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_namespaces WHERE slug=$1`, slug); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- PgStore: ConnectionNamespaceStore ----

const connectionNamespaceSelect = `
SELECT n.id,n.slug,n.label,n.revision,n.created_by,n.created_at,n.updated_at,
       COALESCE(
           array_agg(m.subject ORDER BY m.subject) FILTER (WHERE m.subject IS NOT NULL),
           ARRAY[]::TEXT[]
       )
FROM narthex_connection_namespaces n
LEFT JOIN narthex_connection_namespace_managers m
  ON m.connection_namespace_id=n.id`

type connectionNamespaceQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanConnectionNamespace(row pgx.Row) (ConnectionNamespace, error) {
	var (
		ns       ConnectionNamespace
		subjects []string
	)
	if err := row.Scan(&ns.ID, &ns.Slug, &ns.Label, &ns.Revision, &ns.CreatedBy, &ns.CreatedAt, &ns.UpdatedAt, &subjects); err != nil {
		return ConnectionNamespace{}, err
	}
	for _, subject := range subjects {
		ns.ManagerGrants = append(ns.ManagerGrants, ConnectionNamespaceManagerGrant{Subject: subject})
	}
	if ns.ManagerGrants == nil {
		ns.ManagerGrants = []ConnectionNamespaceManagerGrant{}
	}
	return ns, nil
}

func loadConnectionNamespace(ctx context.Context, q connectionNamespaceQueryer, id string) (ConnectionNamespace, error) {
	return scanConnectionNamespace(q.QueryRow(ctx, connectionNamespaceSelect+`
WHERE n.id=$1
GROUP BY n.id,n.slug,n.label,n.revision,n.created_by,n.created_at,n.updated_at`, id))
}

func (s *PgStore) ConnectionNamespaces(ctx context.Context) ([]ConnectionNamespace, error) {
	rows, err := s.pool.Query(ctx, connectionNamespaceSelect+`
GROUP BY n.id,n.slug,n.label,n.revision,n.created_by,n.created_at,n.updated_at
ORDER BY n.slug,n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectionNamespace
	for rows.Next() {
		ns, err := scanConnectionNamespace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

func (s *PgStore) ConnectionNamespace(ctx context.Context, id string) (ConnectionNamespace, bool) {
	ns, err := loadConnectionNamespace(ctx, s.pool, strings.TrimSpace(id))
	if err != nil {
		return ConnectionNamespace{}, false
	}
	return ns, true
}

func (s *PgStore) ConnectionNamespaceBySlug(ctx context.Context, slug string) (ConnectionNamespace, bool) {
	slug = normalizeConnectionNamespaceSlug(slug)
	ns, err := scanConnectionNamespace(s.pool.QueryRow(ctx, connectionNamespaceSelect+`
WHERE n.slug=$1
GROUP BY n.id,n.slug,n.label,n.revision,n.created_by,n.created_at,n.updated_at`, slug))
	if err != nil {
		return ConnectionNamespace{}, false
	}
	return ns, true
}

func (s *PgStore) CreateConnectionNamespace(ctx context.Context, ns ConnectionNamespace) (ConnectionNamespace, error) {
	if err := prepareConnectionNamespaceForCreate(&ns); err != nil {
		return ConnectionNamespace{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "connection-namespace:"+ns.Slug); err != nil {
		return ConnectionNamespace{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1 FROM narthex_connection_namespaces WHERE id=$1 OR slug=$2
)`, ns.ID, ns.Slug).Scan(&exists); err != nil {
		return ConnectionNamespace{}, err
	}
	if exists {
		return ConnectionNamespace{}, ErrConnectionNamespaceExists
	}
	if _, err := tx.Exec(ctx, `
	INSERT INTO narthex_connection_namespaces (id,slug,label,revision,created_by,created_at,updated_at)
	VALUES ($1,$2,$3,$4,$5,$6,$7)`, ns.ID, ns.Slug, ns.Label, ns.Revision, ns.CreatedBy, ns.CreatedAt, ns.UpdatedAt); err != nil {
		return ConnectionNamespace{}, err
	}
	for _, grant := range ns.ManagerGrants {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_connection_namespace_managers (connection_namespace_id,subject)
VALUES ($1,$2)`, ns.ID, grant.Subject); err != nil {
			return ConnectionNamespace{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionNamespace{}, err
	}
	return copyConnectionNamespace(ns), nil
}

func loadConnectionNamespaceForUpdate(ctx context.Context, tx pgx.Tx, id string) (ConnectionNamespace, error) {
	var ns ConnectionNamespace
	err := tx.QueryRow(ctx, `
	SELECT id,slug,label,revision,created_by,created_at,updated_at
FROM narthex_connection_namespaces
WHERE id=$1
FOR UPDATE`, id).Scan(&ns.ID, &ns.Slug, &ns.Label, &ns.Revision, &ns.CreatedBy, &ns.CreatedAt, &ns.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionNamespace{}, ErrConnectionNamespaceNotFound
	}
	if err != nil {
		return ConnectionNamespace{}, err
	}
	rows, err := tx.Query(ctx, `
SELECT subject
FROM narthex_connection_namespace_managers
WHERE connection_namespace_id=$1
ORDER BY subject`, id)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return ConnectionNamespace{}, err
		}
		ns.ManagerGrants = append(ns.ManagerGrants, ConnectionNamespaceManagerGrant{Subject: subject})
	}
	if err := rows.Err(); err != nil {
		return ConnectionNamespace{}, err
	}
	if ns.ManagerGrants == nil {
		ns.ManagerGrants = []ConnectionNamespaceManagerGrant{}
	}
	return ns, nil
}

func (s *PgStore) updateConnectionNamespaceTx(ctx context.Context, tx pgx.Tx, update ConnectionNamespace, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error) {
	current, err := loadConnectionNamespaceForUpdate(ctx, tx, strings.TrimSpace(update.ID))
	if err != nil {
		return ConnectionNamespace{}, err
	}
	if !connectionNamespacePreconditionMatches(current, precondition) {
		return ConnectionNamespace{}, ErrConnectionNamespaceRevision
	}
	if update.Slug != "" && normalizeConnectionNamespaceSlug(update.Slug) != current.Slug {
		return ConnectionNamespace{}, errors.New("connection namespace slug is immutable")
	}
	if update.CreatedBy != "" && strings.TrimSpace(update.CreatedBy) != current.CreatedBy {
		return ConnectionNamespace{}, errors.New("connection namespace creator is immutable")
	}
	label := strings.TrimSpace(update.Label)
	if label == "" {
		return ConnectionNamespace{}, errors.New("connection namespace label is required")
	}
	grants := normalizedManagerGrants(update.ManagerGrants)
	if current.Label == label && sameManagerGrants(current.ManagerGrants, grants) {
		return current, nil
	}
	if err := tx.QueryRow(ctx, `
	UPDATE narthex_connection_namespaces
	SET label=$2,revision=revision+1,updated_at=now()
	WHERE id=$1
RETURNING revision,updated_at`, current.ID, label).Scan(&current.Revision, &current.UpdatedAt); err != nil {
		return ConnectionNamespace{}, err
	}
	if current.Label != label {
		if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET workspace=$2
WHERE connection_namespace_id=$1`, current.ID, label); err != nil {
			return ConnectionNamespace{}, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_connection_namespace_managers WHERE connection_namespace_id=$1`, current.ID); err != nil {
		return ConnectionNamespace{}, err
	}
	for _, grant := range grants {
		if _, err := tx.Exec(ctx, `
INSERT INTO narthex_connection_namespace_managers (connection_namespace_id,subject)
VALUES ($1,$2)`, current.ID, grant.Subject); err != nil {
			return ConnectionNamespace{}, err
		}
	}
	current.Label, current.ManagerGrants = label, grants
	return current, nil
}

func (s *PgStore) UpdateConnectionNamespace(ctx context.Context, ns ConnectionNamespace, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	defer tx.Rollback(ctx)
	updated, err := s.updateConnectionNamespaceTx(ctx, tx, ns, precondition)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionNamespace{}, err
	}
	return updated, nil
}

func (s *PgStore) SetConnectionNamespaceManagers(ctx context.Context, id string, managers []ConnectionNamespaceManagerGrant, precondition ConnectionNamespacePrecondition) (ConnectionNamespace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadConnectionNamespaceForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return ConnectionNamespace{}, err
	}
	if !connectionNamespacePreconditionMatches(current, precondition) {
		return ConnectionNamespace{}, ErrConnectionNamespaceRevision
	}
	current.ManagerGrants = managers
	updated, err := s.updateConnectionNamespaceTx(ctx, tx, current, precondition)
	if err != nil {
		return ConnectionNamespace{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionNamespace{}, err
	}
	return updated, nil
}

func (s *PgStore) DeleteConnectionNamespace(ctx context.Context, id string, precondition ConnectionNamespacePrecondition) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return err
	}
	current, err := loadConnectionNamespaceForUpdate(ctx, tx, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if !connectionNamespacePreconditionMatches(current, precondition) {
		return ErrConnectionNamespaceRevision
	}
	var inUse bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM narthex_accounts WHERE connection_namespace_id=$1)`, current.ID).Scan(&inUse); err != nil {
		return err
	}
	if inUse {
		return ErrConnectionNamespaceInUse
	}
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1
    FROM narthex_mcp_clients c
    JOIN narthex_mcp_client_namespaces g ON g.client_id=c.id
    WHERE c.status='active' AND g.connection_namespace_id=$1
)`, current.ID).Scan(&inUse); err != nil {
		return err
	}
	if inUse {
		return ErrConnectionNamespaceInUse
	}
	// Revoked client registrations have no delivery authority. Remove their
	// inert historical grant before deleting the namespace so an older
	// restrictive FK cannot turn a successful revoke into an undeletable
	// empty folder. Bump the record revision to keep its audit shape honest.
	if _, err := tx.Exec(ctx, `
UPDATE narthex_mcp_clients c
SET revision=revision+1,updated_at=now()
WHERE c.status='revoked'
  AND EXISTS (
      SELECT 1 FROM narthex_mcp_client_namespaces g
      WHERE g.client_id=c.id AND g.connection_namespace_id=$1
  )`, current.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
DELETE FROM narthex_mcp_client_namespaces g
USING narthex_mcp_clients c
WHERE g.client_id=c.id
  AND c.status='revoked'
  AND g.connection_namespace_id=$1`, current.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_connection_namespaces WHERE id=$1`, current.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func removePersonalAccountExposureTx(ctx context.Context, tx pgx.Tx, account string) error {
	// Revisions make stale endpoint management clients fail closed after a
	// privacy move. Connector allowlists are keyed by the stable account name,
	// so prune both policy maps atomically as well.
	if _, err := tx.Exec(ctx, `
UPDATE narthex_namespaces
SET revision=revision+1
WHERE slug IN (
    SELECT namespace_slug FROM narthex_namespace_accounts WHERE account_name=$1
)`, account); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM narthex_namespace_accounts WHERE account_name=$1`, account); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE narthex_connectors
SET tools=tools - $1, approval=approval - $1
WHERE tools ? $1 OR approval ? $1`, account); err != nil {
		return err
	}
	return nil
}

// cancelPendingForAccountMoveTx invalidates still-parked connector requests in
// the same transaction as their account's ownership move. A concurrent human
// decision therefore either commits before the move (and the Gateway's
// revision-bound dispatch check blocks it after the move) or observes this
// cancellation and cannot release the waiter at all.
func cancelPendingForAccountMoveTx(ctx context.Context, tx pgx.Tx, account string) error {
	_, err := tx.Exec(ctx, `
UPDATE pending_calls
SET status='cancelled', decided_at=now(), decided_by='engine',
    decision_note='connection ownership changed while approval was pending'
WHERE account=$1 AND status='pending' AND expires_at > now()`, account)
	return err
}

// MoveAccountToConnectionNamespace changes a credential ownership boundary by
// CAS and leaves Account.Name untouched. If the target scope is personal, all
// current shared endpoint memberships and virtual connector maps are removed
// in the same transaction before the personal scope is committed.
func (s *PgStore) MoveAccountToConnectionNamespace(ctx context.Context, name, expectedIncarnationID string, assignment AccountConnectionAssignment, expectedRevision int64) (Account, error) {
	assignment, err := normalizeAccountConnectionAssignment(assignment)
	if err != nil {
		return Account{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMCPClientRegistryTx(ctx, tx); err != nil {
		return Account{}, err
	}
	target, err := loadConnectionNamespaceForUpdate(ctx, tx, assignment.ConnectionNamespaceID)
	if err != nil {
		return Account{}, err
	}
	current, err := s.scanAccount(tx.QueryRow(ctx, `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1 FOR UPDATE`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if expectedIncarnationID == "" || current.IncarnationID != expectedIncarnationID {
		return Account{}, ErrAccountIncarnation
	}
	if expectedRevision < 1 || current.Revision != expectedRevision {
		return Account{}, ErrConnectionNamespaceRevision
	}
	if current.ConnectionNamespaceID == assignment.ConnectionNamespaceID && current.ConnectionScope == assignment.Scope && current.OwnerSubject == assignment.OwnerSubject {
		if err := tx.Commit(ctx); err != nil {
			return Account{}, err
		}
		return current, nil
	}
	proposed := copyAccount(current)
	proposed.ConnectionNamespaceID = assignment.ConnectionNamespaceID
	proposed.ConnectionScope = assignment.Scope
	proposed.OwnerSubject = assignment.OwnerSubject
	proposed.Group = target.Label
	moveNamespaceIDs := []string{current.ConnectionNamespaceID, proposed.ConnectionNamespaceID}
	// The registry lock freezes store-managed client scope membership. Lock the
	// current candidates in ID order before taking the namespace advisories, then
	// take a defensive final snapshot of the affected registrations.
	if _, err := lockActiveMCPClientsForAccountMoveTx(ctx, tx, moveNamespaceIDs); err != nil {
		return Account{}, err
	}
	if err := lockMCPClientNamespacesTx(ctx, tx, moveNamespaceIDs); err != nil {
		return Account{}, err
	}
	affectedClients, err := lockActiveMCPClientsForAccountMoveTx(ctx, tx, moveNamespaceIDs)
	if err != nil {
		return Account{}, err
	}
	if err := validatePersonalAccountMCPClientGrantsTx(ctx, tx, proposed); err != nil {
		return Account{}, err
	}
	if err := cancelPendingForAccountMoveTx(ctx, tx, current.Name); err != nil {
		return Account{}, err
	}
	if assignment.Scope == ConnectionScopePersonal {
		if err := removePersonalAccountExposureTx(ctx, tx, current.Name); err != nil {
			return Account{}, err
		}
	}
	// Persist the client generation boundary in the same transaction as the
	// account assignment. Existing scoped OAuth grants then fail closed until a
	// client refreshes, while unchanged scoped clients retain their sessions.
	if err := rotateMCPClientEpochsForAccountMoveTx(ctx, tx, affectedClients, current, proposed); err != nil {
		return Account{}, err
	}
	current.ConnectionNamespaceID = assignment.ConnectionNamespaceID
	current.ConnectionScope = assignment.Scope
	current.OwnerSubject = assignment.OwnerSubject
	current.Group = target.Label
	current.Revision++
	if _, err := tx.Exec(ctx, `
UPDATE narthex_accounts
SET workspace=$2,connection_namespace_id=$3,connection_scope=$4,owner_subject=$5,revision=$6
WHERE name=$1`, current.Name, current.Group, current.ConnectionNamespaceID, current.ConnectionScope, current.OwnerSubject, current.Revision); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, err
	}
	return current, nil
}

// ---- PgStore: durable approval lifecycle ----
//
// Approval decisions are conditional transitions. In particular, a decision
// may only move a still-pending row whose persisted deadline has not elapsed.
// This prevents a late Approve from reviving a timed-out call and gives every
// Engine instance one authoritative result to observe.

const pendingCallColumns = `id,ts,connector,account,account_incarnation_id,account_revision,connection_namespace_id,tool,args,status,expires_at,decided_at,decided_by,decision_note,kind`

type pendingCallScanner interface {
	Scan(...any) error
}

func (s *PgStore) scanPendingCall(row pendingCallScanner) (PendingCall, error) {
	var (
		p       PendingCall
		args    string
		expires time.Time
	)
	if err := row.Scan(
		&p.ID, &p.TS, &p.Connector, &p.Account, &p.AccountIncarnationID, &p.AccountRevision, &p.ConnectionNamespaceID, &p.Tool, &args, &p.Status,
		&expires, &p.DecidedAt, &p.DecidedBy, &p.DecisionNote, &p.Kind,
	); err != nil {
		return PendingCall{}, err
	}
	p.ExpiresAt = &expires
	plainArgs, err := s.dec(args)
	if err != nil {
		return PendingCall{}, fmt.Errorf("decrypt pending call %q arguments: %w", p.ID, err)
	}
	if err := json.Unmarshal([]byte(plainArgs), &p.Args); err != nil {
		return PendingCall{}, fmt.Errorf("pending call %q args: %w", p.ID, err)
	}
	// decided_by/decision_note are encrypted at rest like the audit error
	// column; legacy plaintext rows read through s.dec's passthrough.
	decidedBy, err := s.dec(p.DecidedBy)
	if err != nil {
		return PendingCall{}, fmt.Errorf("decrypt pending call %q decider: %w", p.ID, err)
	}
	decisionNote, err := s.dec(p.DecisionNote)
	if err != nil {
		return PendingCall{}, fmt.Errorf("decrypt pending call %q decision note: %w", p.ID, err)
	}
	p.DecidedBy, p.DecisionNote = decidedBy, decisionNote
	return p, nil
}

func (s *PgStore) LogPending(ctx context.Context, p PendingCall) error {
	if err := normalizePendingCall(&p); err != nil {
		return err
	}
	args := p.Args
	if args == nil {
		args = map[string]any{} // column is NOT NULL '{}'
	}
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	encryptedArgs, err := s.enc(string(b))
	if err != nil {
		return fmt.Errorf("encrypt pending call arguments: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO pending_calls
    (id,ts,connector,account,account_incarnation_id,account_revision,connection_namespace_id,tool,args,status,expires_at,kind)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.TS, p.Connector, p.Account, p.AccountIncarnationID, p.AccountRevision, p.ConnectionNamespaceID,
		p.Tool, encryptedArgs, p.Status, p.ExpiresAt, p.Kind)
	return err
}

// ApprovalCall reads one approval row for cross-instance waiters and console
// error handling. It intentionally includes terminal history.
func (s *PgStore) ApprovalCall(ctx context.Context, id string) (PendingCall, bool, error) {
	p, err := s.scanPendingCall(s.pool.QueryRow(ctx,
		`SELECT `+pendingCallColumns+` FROM pending_calls WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingCall{}, false, nil
	}
	if err != nil {
		return PendingCall{}, false, err
	}
	return p, true, nil
}

func (s *PgStore) pendingTransitionResult(ctx context.Context, id, wanted string) (PendingCall, error) {
	p, found, err := s.ApprovalCall(ctx, id)
	if err != nil {
		return PendingCall{}, err
	}
	if !found {
		return PendingCall{}, ErrApprovalNotFound
	}
	if p.Status == wanted { // idempotent retry of the same terminal action
		return p, nil
	}
	if p.Status == ApprovalPending && approvalIsDue(p, time.Now()) {
		return p, ErrApprovalExpired
	}
	return p, ErrApprovalNotPending
}

// SetDecision is the compatibility wrapper for direct store callers. It uses
// DecidePending, so it never overwrites a previous terminal decision.
func (s *PgStore) SetDecision(ctx context.Context, id, status string) error {
	_, err := s.DecidePending(ctx, id, ApprovalDecision{Status: status})
	return err
}

// DecidePending atomically transitions pending -> approved|denied. The
// deadline predicate is inside the UPDATE (rather than only in Go) so two
// console requests and a timeout race cannot both win.
func (s *PgStore) DecidePending(ctx context.Context, id string, decision ApprovalDecision) (PendingCall, error) {
	decision, err := normalizeHumanDecision(decision)
	if err != nil {
		return PendingCall{}, err
	}
	actor, note, err := s.encryptDecisionMetadata(decision.Actor, decision.Note)
	if err != nil {
		return PendingCall{}, err
	}
	p, err := s.scanPendingCall(s.pool.QueryRow(ctx, `
UPDATE pending_calls
SET status=$2, decided_at=now(), decided_by=$3, decision_note=$4
WHERE id=$1 AND status='pending' AND expires_at > now()
RETURNING `+pendingCallColumns, id, decision.Status, actor, note))
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PendingCall{}, err
	}
	return s.pendingTransitionResult(ctx, id, decision.Status)
}

// encryptDecisionMetadata applies the at-rest cipher to caller-supplied
// approval decision metadata before it is written to decided_by/decision_note.
// Engine-written constants (for example 'engine' / 'approval deadline
// elapsed') carry no caller input and stay plaintext literals in SQL; s.dec's
// passthrough reads both forms.
func (s *PgStore) encryptDecisionMetadata(actor, note string) (string, string, error) {
	encActor, err := s.enc(actor)
	if err != nil {
		return "", "", fmt.Errorf("encrypt approval actor: %w", err)
	}
	encNote, err := s.enc(note)
	if err != nil {
		return "", "", fmt.Errorf("encrypt approval note: %w", err)
	}
	return encActor, encNote, nil
}

// ExpirePending atomically transitions only a due pending call. Calling it
// again after a successful expiry is idempotent.
func (s *PgStore) ExpirePending(ctx context.Context, id string, now time.Time) (PendingCall, error) {
	p, err := s.scanPendingCall(s.pool.QueryRow(ctx, `
UPDATE pending_calls
SET status='expired', decided_at=now(), decided_by='engine', decision_note='approval deadline elapsed'
WHERE id=$1 AND status='pending' AND expires_at <= $2
RETURNING `+pendingCallColumns, id, now))
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PendingCall{}, err
	}
	return s.pendingTransitionResult(ctx, id, ApprovalExpired)
}

// CancelPending records that the original MCP request ended before a human
// decision. It cannot cancel a genuinely timed-out call; that row becomes
// expired instead.
func (s *PgStore) CancelPending(ctx context.Context, id, actor, note string) (PendingCall, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "engine"
	}
	note = strings.TrimSpace(note)
	if len(actor) > maxApprovalActorBytes || len(note) > maxApprovalNoteBytes {
		return PendingCall{}, errors.New("approval cancellation metadata is too long")
	}
	encActor, encNote, err := s.encryptDecisionMetadata(actor, note)
	if err != nil {
		return PendingCall{}, err
	}
	p, err := s.scanPendingCall(s.pool.QueryRow(ctx, `
UPDATE pending_calls
SET status='cancelled', decided_at=now(), decided_by=$2, decision_note=$3
WHERE id=$1 AND status='pending' AND expires_at > now()
RETURNING `+pendingCallColumns, id, encActor, encNote))
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PendingCall{}, err
	}
	return s.pendingTransitionResult(ctx, id, ApprovalCancelled)
}

// ExpireTimedOutPending is the safe maintenance sweep: only rows whose stored
// deadline has passed are marked expired. It deliberately does not blanket-
// expire all pending rows at process startup.
func (s *PgStore) ExpireTimedOutPending(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE pending_calls
SET status='expired', decided_at=now(), decided_by='engine', decision_note='approval deadline elapsed'
WHERE status='pending' AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ApprovalRecovery summarizes startup recovery. Non-expired rows are
// cancelled, not approved or replayed: their original MCP transport request
// ended with the previous Engine process and generic tool calls are not safe to
// re-run from stored arguments.
type ApprovalRecovery struct {
	Expired   int64
	Cancelled int64
}

func (s *PgStore) RecoverPendingApprovals(ctx context.Context, now time.Time) (ApprovalRecovery, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ApprovalRecovery{}, err
	}
	defer tx.Rollback(ctx)

	result := ApprovalRecovery{}
	tag, err := tx.Exec(ctx, `
UPDATE pending_calls
SET status='expired', decided_at=now(), decided_by='engine', decision_note='approval deadline elapsed'
WHERE status='pending' AND expires_at <= $1`, now)
	if err != nil {
		return ApprovalRecovery{}, err
	}
	result.Expired = tag.RowsAffected()

	// Only rows still pending after the deadline sweep are cancelled. This is
	// an explicit interrupted-request outcome, not a fabricated timeout.
	tag, err = tx.Exec(ctx, `
UPDATE pending_calls
SET status='cancelled', decided_at=now(), decided_by='engine',
    decision_note='Engine restarted; original MCP request was not replayed'
WHERE status='pending'`)
	if err != nil {
		return ApprovalRecovery{}, err
	}
	result.Cancelled = tag.RowsAffected()
	if err := tx.Commit(ctx); err != nil {
		return ApprovalRecovery{}, err
	}
	return result, nil
}

// ExpireOrphanedPending remains for source compatibility with older Engine
// callers. Its corrected behavior is deadline-only; use
// RecoverPendingApprovals at startup when interrupted waits should be marked
// cancelled as well.
func (s *PgStore) ExpireOrphanedPending(ctx context.Context) (int64, error) {
	return s.ExpireTimedOutPending(ctx, time.Now())
}

func (s *PgStore) PendingCalls(ctx context.Context) ([]PendingCall, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pendingCallColumns+` FROM pending_calls ORDER BY ts DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingCall
	for rows.Next() {
		p, err := s.scanPendingCall(rows)
		if err != nil {
			// A single unreadable row (e.g. a decrypt failure from a
			// wrong/rotated key) must not fail the whole list: console.go turns
			// a PendingCalls error into a 502 for every caller, hiding all
			// pending and historical approvals instead of just the one bad
			// record. Match PgStore.Accounts: log (row content, never
			// decrypted/attempted-decrypt values) and skip just this row.
			// scanPendingCall's single-row callers (ApprovalCall,
			// DecidePending, ExpirePending, CancelPending) keep propagating the
			// error for their one row — only this list path omits-and-logs.
			log.Printf("engine: omit unreadable pending call: %v", err)
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
