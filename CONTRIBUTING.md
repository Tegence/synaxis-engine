# Contributing to Synaxis Engine

Synaxis Engine is the Apache-2.0, tenant-blind MCP runtime. Hosted product
identity, billing, provisioning, and tenant routing are intentionally outside
this repository.

## Development

```bash
go build ./...
go vet ./...
go test -race ./internal/engine/
go test ./...
```

With no `DATABASE_URL`, the engine uses the local JSON file store. Persistence
changes must work with both the file and Postgres stores, or degrade through
the documented optional store facets.

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
- A tool call writes one terminal audit row.
- `/mcp` is a raw aggregate; connector audience binding prevents connector
  tokens from escaping connector policy.
- In-memory OAuth and approval state means one maximum production instance
  until that state is durable or coordinated.

New behavior needs focused tests in the existing standard-library style.

## Public/private boundary

The public engine may expose a generic, versioned control API. A hosted
platform can authenticate to that API, but platform roles, sessions, billing,
and tenant identity are not engine concepts.

Do not copy files from private Synaxis product repositories into an engine
change unless they have been explicitly relicensed for the Apache-2.0 engine.
