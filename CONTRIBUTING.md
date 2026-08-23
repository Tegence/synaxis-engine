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
