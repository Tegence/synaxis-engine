# Contributing to Synaxis Engine

Synaxis Engine is the Apache-2.0, tenant-blind MCP runtime. Hosted product
identity, billing, provisioning, and tenant routing are intentionally outside
this repository.

## Development

Run commands from `backend/` in the private monorepo, or from the standalone
Engine repository root. Start by downloading modules and running the full
local check set:

```bash
go mod download
go build ./...
go vet ./...
go test -race ./internal/engine/
go test ./...
```

With no `DATABASE_URL`, the engine uses the local JSON file store. Persistence
changes must work with both the file and Postgres stores, or degrade through
the documented optional store facets.

## Schema changes

The Postgres store has no migration framework. `NewPgStore` applies the
idempotent DDL in `internal/engine/*_pg.go` on every start, under an advisory
lock. The policy is **Engine N-1 starts on schema N**: the previous release
must start, and keep serving, on a database that the current release has
already migrated and written to, so an update can be rolled back by
redeploying the previous binary. That previous release also runs its own copy
of the DDL on every start.

- Prefer additive DDL: `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT
  EXISTS`, and `CREATE INDEX IF NOT EXISTS`, with a new column's CHECK inline.
- Re-add a CHECK constraint only through `engineReappliedChecks` (THE RULE in
  `internal/engine/store_pg.go`). The helper records the expression it applied
  in the constraint's comment and re-adds the constraint whenever that differs
  from the current release's expression, so changing a listed constraint means
  editing its expression and the matching inline CHECK, nothing else. It
  re-adds the constraint `NOT VALID` and then validates it, tolerating only a
  check violation. Never write a plain
  validating `ADD CONSTRAINT ... CHECK` re-add; `schema_rules_test.go` fails on
  one. A one-time add inside a `DO` block, guarded by the constraint's name
  alone, is also safe, as long as nothing drops or renames that constraint:
  its guard would then add it again, validating, on every start. The same
  test fails on such a drop or rename, and on any other `DROP` or `RENAME
  CONSTRAINT` outside the helper until it is reviewed.
- Widening an allowed-value list is safe only for a constraint in
  `engineReappliedChecks`, and only when nothing the previous release runs at
  startup rewrites or rejects the new value and its code reads that value
  safely. `connection_scope` on `narthex_accounts` is not safe to widen yet:
  every start rewrites an unknown scope to `shared`, so a rollback would
  silently widen access to those accounts. Adding a scope takes two releases:
  first one that keeps an unknown scope as stored, neither rewrites nor
  rejects it, and keeps such accounts off shared surfaces; then the one that
  adds the scope. Narrowing a list, relaxing a `NOT NULL`, changing a column
  type, or dropping or renaming a constraint needs a data migration first,
  because the previous release still runs its own statements.
- Startup writes (schema backfills and the `EncryptExisting` migration) must
  match only legacy rows and skip rows they would leave unchanged: Postgres
  checks even a `NOT VALID` CHECK on every row an `UPDATE` writes.
- When an older release starts over rows its narrower list rejects, it leaves
  only that constraint `NOT VALID`, logs `engine: schema constraint <name> on
  <table> left NOT VALID`, and still checks new writes. The next start of a
  release whose list admits those rows validates it again. To list them, run
  `SELECT conrelid::regclass, conname FROM pg_constraint WHERE NOT
  convalidated;`.

The Postgres contracts, including the rollback contract in
`schema_rollback_pg_test.go`, run against a disposable database:

```bash
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:5432/engine_test?sslmode=disable \
  go test -count=1 ./internal/engine/ -run 'Pg|Postgres'
```

For an interactive local sandbox:

```bash
umask 077
ENGINE_ISSUER=http://localhost:8080 \
ENGINE_DEVELOPMENT_MODE=true \
go run ./cmd/engine
```

Development mode prints a temporary password, rotates its signing secret on
restart, and is never suitable for an exposed deployment. The server listens
on all interfaces, so keep port 8080 behind a local firewall. Do not commit
`.env`, `accounts.json`, local binaries, or coverage output; the exported
`.gitignore`, `.dockerignore`, and `.gcloudignore` enforce the same boundary in
source control and build uploads.

## Invariants

- Engine code must not import Synaxis Platform or Web packages.
- Do not add users, organizations, subscriptions, plans, workspace tenants, or
  provisioning jobs to the engine.
- Upstream token refresh goes through `Gateway.refreshAccount` so a rotating
  refresh token cannot be double-spent.
- MCP-facing refresh grants deliberately do not rotate because supported MCP
  client reconnect behavior depends on it.
- Persisted secrets go through the configured cipher.
- Response guardrails cover every model-visible carrier before payload audit.
- Response guardrails belong only to curated virtual connectors. `/mcp`,
  whole-connection endpoint bundles, and `/mcp/clients/{slug}` remain raw
  response surfaces.
- A tool call writes one terminal audit row.
- `/mcp` is a raw aggregate; connector audience binding prevents connector
  tokens from escaping connector policy.
- Connection namespace IDs, account scope/owner, manager grants, incarnation
  IDs, and revisions are authorization facts. Human-readable labels are not.
- Personal connections never appear on shared MCP surfaces and may reach a
  scoped `/mcp/clients/{slug}` endpoint only for the exact owner subject.
- MCP client grant, account-move, reset, and revocation changes rotate the
  affected endpoint epoch so prior resource tokens fail closed.
- `library_skill_activation` is a context-only handoff on a verified,
  subject-bound MCP-client endpoint. Do not expose it on root `/mcp`, accept
  caller-controlled scope/binding context, or add credentials, connection
  access, runtime grants, or effective capabilities to its contract.
- Hosted `/api/activation` is service-actor-only and returns only an aggregate
  connection count. Never expand it with account or provider metadata.
- Process-local OAuth and pending-connect state, plus each live approval
  waiter/request, mean one maximum production instance until they are durable
  or coordinated. Approval records and decisions are durable with PostgreSQL.
- An MCP client's agent profile binding is an opaque, revisioned reference
  installed by a hosting control plane. The Engine validates only its shape,
  never resolves or applies the policy it names, and treats it as an
  authorization fact: any change to the bound reference rotates the client's
  endpoint epoch so prior resource tokens fail closed.
- Run correlations record what the Engine observed: a signed host claim that
  this client, at this epoch, associated a run with a gateway request while
  its activation bundle digest was as stated. They are not proof that
  instructions were injected or that anything executed, and they persist only
  scoped hashes of the host-chosen execution ID and nonce.
- The runtime activation fetch (`GET /runtime/clients/{slug}/activation`) is
  a host-signed, timestamp-bound, no-CORS ingress like the skill-run
  attestation route. It is never mounted under `/api` or the root `/mcp`, and
  browser-shaped requests receive the same 404 as an unknown client.

New behavior needs focused tests in the existing standard-library style.

## Public export checks

From the private monorepo root, run:

```bash
scripts/check-engine-boundary.sh
export_dir="$(mktemp -d)"
scripts/export-engine.sh "$export_dir"
(cd "$export_dir" && go build ./... && go test ./...)
```

The export is a committed-source allowlist, not a copy of the working tree.
When adding a public file, update `engine-export.manifest` and the boundary
requirements together. `.github` is a special case: only the reviewed public
Engine CI workflow may be exported. Never add private product workflows,
frontend code, Platform code, local data, or generated artifacts to the
manifest.

## Public/private boundary

The public engine may expose a generic, versioned control API. A hosted
platform can authenticate to that API, but platform roles, sessions, billing,
and tenant identity are not engine concepts.

Do not copy files from private Synaxis product repositories into an engine
change unless they have been explicitly relicensed for the Apache-2.0 engine.
