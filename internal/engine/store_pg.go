package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore is the Postgres-backed AccountStore — the deployable one (tokens
// survive Cloud Run restarts). Plain columns, no oauth_sessions black box.
type PgStore struct {
	pool   *pgxpool.Pool
	cipher *Cipher // nil = no at-rest encryption (passthrough)
}

// SetCipher enables AES-GCM encryption of token columns at rest.
func (s *PgStore) SetCipher(c *Cipher) { s.cipher = c }

func (s *PgStore) enc(v string) string { return s.cipher.Encrypt(v) }
func (s *PgStore) dec(v string) string { return s.cipher.Decrypt(v) }

// EncryptExisting re-writes every account so any legacy plaintext token columns
// become encrypted. Idempotent: already-encrypted values are left as-is.
func (s *PgStore) EncryptExisting(ctx context.Context) error {
	if s.cipher == nil {
		return nil
	}
	for _, a := range s.Accounts() { // Accounts() returns decrypted values
		if err := s.Upsert(ctx, a); err != nil { // Upsert re-encrypts
			return err
		}
	}
	return nil
}

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
    read_only      BOOLEAN NOT NULL DEFAULT false
);`

// idempotent migrations for tables created before these columns existed.
const accountsMigrate = `
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS disabled_tools TEXT[];
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS tool_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS read_only BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE narthex_accounts ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';`

const accountCols = `name,label,workspace,url,auth_mode,client_id,client_secret,access_token,refresh_token,token_endpoint,resource,scope,bearer_token,disabled_tools,tool_overrides,read_only`

func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, accountsSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure accounts schema: %w", err)
	}
	if _, err := pool.Exec(ctx, accountsMigrate); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate accounts schema: %w", err)
	}
	if _, err := pool.Exec(ctx, callsSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure tool_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, callsMigrate); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate tool_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, connectorsSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure connectors schema: %w", err)
	}
	if _, err := pool.Exec(ctx, connectorsMigrate); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate connectors schema: %w", err)
	}
	if _, err := pool.Exec(ctx, pendingSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure pending_calls schema: %w", err)
	}
	if _, err := pool.Exec(ctx, pendingMigrate); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate pending_calls schema: %w", err)
	}
	return &PgStore{pool: pool}, nil
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

const pendingSchema = `
CREATE TABLE IF NOT EXISTS pending_calls (
    id         TEXT PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    connector  TEXT NOT NULL DEFAULT '',
    account    TEXT NOT NULL DEFAULT '',
    tool       TEXT NOT NULL DEFAULT '',
    args       TEXT NOT NULL DEFAULT '{}',
    status     TEXT NOT NULL DEFAULT 'pending',
    decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS pending_calls_ts_idx ON pending_calls (ts DESC);`

// idempotent migration for tables created when args was JSONB: the column
// becomes TEXT so it can hold the enc:-prefixed ciphertext (legacy plaintext
// JSON rows keep working — s.dec passes un-prefixed values through).
const pendingMigrate = `
ALTER TABLE pending_calls ALTER COLUMN args DROP DEFAULT;
ALTER TABLE pending_calls ALTER COLUMN args TYPE TEXT USING args::text;
ALTER TABLE pending_calls ALTER COLUMN args SET DEFAULT '{}';`

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
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS decision TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS args TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS guard TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_calls ADD COLUMN IF NOT EXISTS triage TEXT NOT NULL DEFAULT '';`

// LogCall is fire-and-forget: a tool call must never fail or block on auditing.
// Args/Result are clamped and encrypted at rest (nil cipher = plaintext, same
// as token columns).
func (s *PgStore) LogCall(rec CallRecord) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rec.TS.IsZero() {
			rec.TS = time.Now()
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO tool_calls (ts,account,tool,ok,ms,error,connector,decision,args,result,guard)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			rec.TS, rec.Account, rec.Tool, rec.OK, rec.Ms, clampErr(rec.Error), rec.Connector, rec.Decision,
			s.enc(clampPayload(rec.Args, maxPayloadBytes)), s.enc(clampPayload(rec.Result, maxPayloadBytes)), rec.Guard); err != nil {
			log.Printf("engine: audit insert failed (call %s/%s dropped): %v", rec.Account, rec.Tool, err)
		}
	}()
}

// RecentCalls is summary-only: Args/Result are never selected, so the 100-row
// list response stays payload-free (and no decryption work happens per row).
// Guard IS selected — it's tiny and the Activity UI chips on it.
func (s *PgStore) RecentCalls(ctx context.Context, limit int) ([]CallRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,ts,account,tool,ok,ms,error,connector,decision,guard,triage FROM tool_calls ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CallRecord
	for rows.Next() {
		var c CallRecord
		if err := rows.Scan(&c.ID, &c.TS, &c.Account, &c.Tool, &c.OK, &c.Ms, &c.Error, &c.Connector, &c.Decision, &c.Guard, &c.Triage); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// CallDetail returns one full record including decrypted payloads.
func (s *PgStore) CallDetail(ctx context.Context, id int64) (CallRecord, bool, error) {
	var c CallRecord
	err := s.pool.QueryRow(ctx, `SELECT id,ts,account,tool,ok,ms,error,connector,decision,args,result,guard,triage FROM tool_calls WHERE id=$1`, id).
		Scan(&c.ID, &c.TS, &c.Account, &c.Tool, &c.OK, &c.Ms, &c.Error, &c.Connector, &c.Decision, &c.Args, &c.Result, &c.Guard, &c.Triage)
	if errors.Is(err, pgx.ErrNoRows) {
		return CallRecord{}, false, nil
	}
	if err != nil {
		return CallRecord{}, false, err
	}
	c.Args, c.Result = s.dec(c.Args), s.dec(c.Result)
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

func (s *PgStore) Close() { s.pool.Close() }

func (s *PgStore) Accounts() []Account {
	rows, err := s.pool.Query(context.Background(), `SELECT `+accountCols+` FROM narthex_accounts ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var overrides []byte
		if err := rows.Scan(&a.Name, &a.Label, &a.Group, &a.URL, &a.AuthMode, &a.ClientID, &a.ClientSecret,
			&a.AccessToken, &a.RefreshToken, &a.TokenEndpoint, &a.Resource, &a.Scope, &a.BearerToken, &a.DisabledTools, &overrides, &a.ReadOnly); err == nil {
			if err := json.Unmarshal(overrides, &a.ToolOverrides); err != nil {
				continue
			}
			a.ClientSecret, a.AccessToken, a.RefreshToken, a.BearerToken =
				s.dec(a.ClientSecret), s.dec(a.AccessToken), s.dec(a.RefreshToken), s.dec(a.BearerToken)
			out = append(out, a)
		}
	}
	return out
}

func (s *PgStore) Token(name string) string {
	var auth, access, bearer string
	if err := s.pool.QueryRow(context.Background(),
		`SELECT auth_mode,access_token,bearer_token FROM narthex_accounts WHERE name=$1`, name).
		Scan(&auth, &access, &bearer); err != nil {
		return ""
	}
	if auth == "token" {
		return s.dec(bearer)
	}
	return s.dec(access)
}

func (s *PgStore) RefreshToken(name string) string {
	var rt string
	_ = s.pool.QueryRow(context.Background(), `SELECT refresh_token FROM narthex_accounts WHERE name=$1`, name).Scan(&rt)
	return s.dec(rt)
}

func (s *PgStore) UpdateTokens(name, access, refresh string) error {
	ctx := context.Background()
	if refresh != "" {
		_, err := s.pool.Exec(ctx, `UPDATE narthex_accounts SET access_token=$2, refresh_token=$3 WHERE name=$1`, name, s.enc(access), s.enc(refresh))
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE narthex_accounts SET access_token=$2 WHERE name=$1`, name, s.enc(access))
	return err
}

// Upsert adds or updates an account — used by the console "Connect" flow and by
// migration. Tokens included so a freshly-connected account works immediately.
func (s *PgStore) Upsert(ctx context.Context, a Account) error {
	ob, err := json.Marshal(a.ToolOverrides)
	if err != nil {
		return err
	}
	if a.ToolOverrides == nil {
		ob = []byte(`{}`)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO narthex_accounts (`+accountCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (name) DO UPDATE SET
  label=$2, workspace=$3, url=$4, auth_mode=$5, client_id=$6, client_secret=$7,
  access_token=$8, refresh_token=$9, token_endpoint=$10, resource=$11, scope=$12, bearer_token=$13, disabled_tools=$14, tool_overrides=$15, read_only=$16`,
		a.Name, a.Label, a.Group, a.URL, a.AuthMode, a.ClientID, s.enc(a.ClientSecret),
		s.enc(a.AccessToken), s.enc(a.RefreshToken), a.TokenEndpoint, a.Resource, a.Scope, s.enc(a.BearerToken), a.DisabledTools, ob, a.ReadOnly)
	return err
}

func (s *PgStore) Account(name string) (Account, bool) {
	var a Account
	var overrides []byte
	err := s.pool.QueryRow(context.Background(), `SELECT `+accountCols+` FROM narthex_accounts WHERE name=$1`, name).
		Scan(&a.Name, &a.Label, &a.Group, &a.URL, &a.AuthMode, &a.ClientID, &a.ClientSecret,
			&a.AccessToken, &a.RefreshToken, &a.TokenEndpoint, &a.Resource, &a.Scope, &a.BearerToken, &a.DisabledTools, &overrides, &a.ReadOnly)
	if err != nil {
		return Account{}, false
	}
	if err := json.Unmarshal(overrides, &a.ToolOverrides); err != nil {
		return Account{}, false
	}
	a.ClientSecret, a.AccessToken, a.RefreshToken, a.BearerToken =
		s.dec(a.ClientSecret), s.dec(a.AccessToken), s.dec(a.RefreshToken), s.dec(a.BearerToken)
	return a, true
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

func (s *PgStore) Delete(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM narthex_accounts WHERE name=$1`, name)
	return err
}

func (s *PgStore) SetMeta(ctx context.Context, name, label, group string) error {
	_, err := s.pool.Exec(ctx, `UPDATE narthex_accounts SET label=$2, workspace=$3 WHERE name=$1`, name, label, group)
	return err
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
	_, err = s.pool.Exec(ctx, `
INSERT INTO narthex_connectors (slug,label,tools,approval,record,max_result_bytes,redact,disable_injection_scan,epoch) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (slug) DO UPDATE SET label=$2, tools=$3, approval=$4, record=$5, max_result_bytes=$6, redact=$7, disable_injection_scan=$8, epoch=$9`,
		c.Slug, c.Label, b, ab, c.Record, c.MaxResultBytes, rb, c.DisableInjectionScan, c.Epoch)
	return err
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

func (s *PgStore) DeleteConnector(ctx context.Context, slug string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM narthex_connectors WHERE slug=$1`, slug)
	return err
}

// ---- PgStore: ApprovalLog ----
// The row is the audit record; the live wait for a decision is in-process.

func (s *PgStore) LogPending(ctx context.Context, p PendingCall) error {
	if p.TS.IsZero() {
		p.TS = time.Now()
	}
	args := p.Args
	if args == nil {
		args = map[string]any{} // column is NOT NULL '{}'
	}
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO pending_calls (id,ts,connector,account,tool,args,status) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		p.ID, p.TS, p.Connector, p.Account, p.Tool, s.enc(string(b)), p.Status)
	return err
}

// ExpireOrphanedPending marks every still-pending call expired. Run at
// startup: a row pending when the process starts can never be decided — its
// in-process waiter died with the previous instance — so without this sweep
// it renders in the console forever with no-op Approve/Deny buttons.
func (s *PgStore) ExpireOrphanedPending(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE pending_calls SET status='expired', decided_at=now() WHERE status='pending'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *PgStore) SetDecision(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE pending_calls SET status=$2, decided_at=now() WHERE id=$1`, id, status)
	return err
}

func (s *PgStore) PendingCalls(ctx context.Context) ([]PendingCall, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,ts,connector,account,tool,args,status,decided_at FROM pending_calls ORDER BY ts DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingCall
	for rows.Next() {
		var p PendingCall
		var args string
		if err := rows.Scan(&p.ID, &p.TS, &p.Connector, &p.Account, &p.Tool, &args, &p.Status, &p.DecidedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(s.dec(args)), &p.Args); err != nil {
			return nil, fmt.Errorf("pending call %q args: %w", p.ID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
