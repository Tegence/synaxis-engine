# Synaxis Engine

Synaxis Engine is the open-source MCP runtime behind Synaxis. It combines
multiple upstream MCP accounts into one endpoint while keeping account
credentials, policy enforcement, and detailed audit data inside the engine's
trust boundary.

The engine is deliberately tenant-blind. A self-hosted installation represents
one operator or one isolated workspace. Hosted multi-tenancy, product identity,
billing, provisioning, and tenant routing belong to Synaxis Platform and are
not engine dependencies.

## Included capabilities

- MCP Streamable HTTP at `/mcp` and curated `/mcp/{connector}` endpoints
- MCP-facing OAuth authorization server with DCR, PKCE, audience binding, and
  refresh grants
- OAuth client support for upstream MCP providers, including discovery,
  dynamic or static client registration, PKCE, refresh, and SSRF protections
- multiple accounts from the same provider with stable tool namespaces
- live tool curation, aliases, descriptions, and conservative read-only policy
- virtual connectors with per-tool approvals and token-epoch revocation
- response redaction, result size caps, and prompt-injection flagging
- summary audit records, optional encrypted payload recording, and replay
- encrypted Postgres credential storage or a local JSON store for development
- proactive health checks, credential refresh, and operational alerts
- secret-free configuration import and export

These capabilities are part of the Apache-2.0 engine. A hosted plan may govern
use of the managed Synaxis service, but it does not remove functionality from
self-hosted engine builds.

## Run locally

Requirements:

- Go 1.25.5 or newer
- optional Postgres for durable production storage

```bash
cp .env.example .env
go run ./cmd/engine
```

The development defaults listen on `http://localhost:8080`. Add
`http://localhost:8080/mcp` to an MCP client after completing the engine's
consent flow.

Build the container:

```bash
docker build -t synaxis-engine .
docker run --rm -p 8080:8080 \
  -e ENGINE_ISSUER=http://localhost:8080 \
  -e ENGINE_PASSWORD=change-me \
  -e ENGINE_SECRET=change-me-with-at-least-32-random-characters \
  synaxis-engine
```

Use `DATABASE_URL` and `ENGINE_ENCRYPTION_KEY` for a durable deployment. Do not
expose development credentials.

## Health and control access

`GET /healthz` and `GET /readyz` are public process probes. They intentionally
do not reveal connected accounts or upstream health.

Protected management routes accept either:

- a self-hosted session obtained from `POST /api/login`; or
- a machine credential configured as `SYNAXIS_ADMIN_TOKEN`.

`ENGINE_ADMIN_TOKEN` is a migration alias. When both are present,
`SYNAXIS_ADMIN_TOKEN` wins. The machine token grants broad engine management
access and must be random, held in a secret manager, rotated, and never sent to
a browser.

The hosted Synaxis frontend authenticates to Synaxis Platform, not directly to
an engine. Platform resolves the workspace and attaches the relevant
per-engine machine credential server-side.

## Hosted OAuth consent contract

Self-hosted Engine uses its password consent form by default. A hosted Engine
can delegate only the human consent decision to a control plane without
learning about users, workspaces, subscriptions, or tenants:

1. Configure both `ENGINE_CONSENT_URL` and
   `ENGINE_CONSENT_PUBLIC_KEY`. The key is the base64 encoding of the
   Platform signer's raw 32-byte Ed25519 public key.
2. After validating `/authorize` client, redirect, S256 PKCE, and resource
   parameters, Engine redirects the browser to `ENGINE_CONSENT_URL` with:
   `request` (an opaque five-minute HMAC token), `engine_issuer` (the exact
   `ENGINE_ISSUER`), and `completion_url`
   (`ENGINE_ISSUER/authorize/complete`). Existing query parameters on the
   configured consent URL are preserved.
3. Platform must resolve the signed-in user's workspace independently and
   match its registered Engine issuer. It must not trust `engine_issuer` or
   `completion_url` merely because they arrived in the browser.
4. Platform signs a compact Ed25519 JWS. Its protected header is exactly:

   ```json
   {"alg":"EdDSA","typ":"synaxis-engine-consent+jwt"}
   ```

   Its payload contains:

   ```json
   {
     "aud": "https://exact-engine.example",
     "engine_issuer": "https://exact-engine.example",
     "request_sha256": "<base64url-no-padding SHA-256 of the exact request token>",
     "jti": "<unique 16-128 character base64url identifier>",
     "exp": 1785153780,
     "approved": true
   }
   ```

   `aud` and `engine_issuer` must both exactly equal `ENGINE_ISSUER`. `exp`
   must be in the future and no more than five minutes ahead. Set
   `approved` explicitly to `true` or `false`; a signed `false` is a normal
   OAuth denial.
5. Platform returns an `application/x-www-form-urlencoded` browser POST to the
   supplied completion URL with exactly `request=<opaque-token>` and
   `assertion=<compact-jws>`. Platform must never attach the Engine machine
   credential or an end-user bearer token.
6. Engine verifies the request HMAC and Ed25519 signature, revalidates the
   registered redirect, live resource, and PKCE challenge, and atomically
   consumes both the request and JWS `jti`. Approval redirects to the original
   OAuth client with `code` and its original `state`; denial redirects with
   `error=access_denied` and the original `state`.

The opaque request contains no Engine secret and reveals none of the OAuth
request fields to Platform. Requests and assertion IDs are single-use. Engine
rejects completion parameters that try to supply or replace a redirect URI,
resource, PKCE challenge, or state.

Hosted deployments should also set
`ENGINE_LOCAL_ADMIN_AUTH_ENABLED=false` and
`SYNAXIS_ENABLE_LEGACY_ADMIN=false`. This removes the password login/session
path and compatibility forms while preserving server-to-server access through
`SYNAXIS_ADMIN_TOKEN`.

## Configuration

The complete example is in [`.env.example`](.env.example). Important values:

| Variable | Purpose |
| --- | --- |
| `PORT` / `ENGINE_PORT` | HTTP listen port |
| `ENGINE_ISSUER` | Canonical public origin used in OAuth metadata and MCP URLs |
| `ENGINE_PASSWORD` | Local/self-hosted console and consent password |
| `ENGINE_SECRET` | HMAC key for OAuth and local console tokens |
| `ENGINE_CONSENT_URL` | Optional generic Platform consent page; must be paired with `ENGINE_CONSENT_PUBLIC_KEY` |
| `ENGINE_CONSENT_PUBLIC_KEY` | Base64 raw Ed25519 public key used to verify hosted approval assertions |
| `ENGINE_LOCAL_ADMIN_AUTH_ENABLED` | Enables password `/api/login` and local session tokens; defaults to `true`, hosted engines set `false` |
| `SYNAXIS_ADMIN_TOKEN` | Optional trusted control-plane credential |
| `SYNAXIS_ENABLE_LEGACY_ADMIN` | Enables password-bearing `/admin/*` compatibility forms; hosted engines set `false` |
| `DATABASE_URL` | Optional Postgres connection string |
| `ENGINE_ENCRYPTION_KEY` | Base64 32-byte AES-GCM key for stored secrets |
| `CONSOLE_URL` | Browser destination after upstream OAuth |
| `CONSOLE_ORIGIN` | Allowed browser origins for the legacy direct console |

Migration-sensitive `ENGINE_*` names remain supported even as user-visible
product surfaces use Synaxis.

## Test

```bash
go build ./...
go vet ./...
go test -race ./internal/engine/
go test ./...
```

## Architecture boundary

Engine code must not import private Synaxis Platform or Web packages. It may
define and serve generic, tenant-blind control operations. Platform concepts
such as users, organizations, memberships, subscriptions, entitlements,
workspace slugs, custom domains, and provisioning jobs do not belong in this
module.

One hosted workspace runs one isolated engine process and datastore. Until the
engine's in-memory OAuth and approval state is made durable or coordinated,
production deployments must use one maximum application instance.

## License

Synaxis Engine is licensed under the [Apache License 2.0](LICENSE). The license
does not grant permission to use Synaxis trademarks except as needed to
describe the software's origin.
