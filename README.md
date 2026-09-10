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

- MCP Streamable HTTP at `/mcp`, reusable `/mcp/{endpoint}` whole-connection
  bundles, curated `/mcp/{connector}` endpoints, and subject-bound
  `/mcp/clients/{client}` endpoints
- MCP-facing OAuth authorization server with DCR, PKCE, audience binding, and
  refresh grants
- OAuth client support for upstream MCP providers, including discovery,
  dynamic or static client registration, PKCE, refresh, and SSRF protections
- multiple independently credentialed connections from the same provider,
  organized in owning namespaces with stable tool prefixes
- provider-agnostic, many-to-many endpoint membership without credential
  duplication
- live tool curation, aliases, descriptions, and conservative read-only policy
- virtual connectors with per-tool approvals and token-epoch revocation
- connector-only response redaction, result size caps, and prompt-injection
  flagging
- summary audit records, optional encrypted payload recording, and replay
- portable Library skills and governed memory cards with immutable versions,
  generic bindings, exact-version grants, private artifacts, and run provenance
- read-only Library skill resolution with explicit-binding or
  folder/repository/namespace/workspace precedence
- direct-agent private artifact storage without requiring a skill parent
- encrypted Postgres credential storage or a local JSON store for development
- proactive health checks, credential refresh, and operational alerts
- secret-free configuration import and export

These capabilities are part of the Apache-2.0 engine. A hosted plan may govern
use of the managed Synaxis service, but it does not remove functionality from
self-hosted engine builds.

## MCP agent bootstrap

Every Engine-owned MCP surface returns a short, versioned
`synaxis.mcp.bootstrap.v1` instruction block during initialization. It tells a
host to treat that endpoint's current `tools/list` response and schemas as the
exact advertised inventory, distinguishes advertised tools from action-time
authorization, and identifies the surface as the root aggregate, a governed
connector, an endpoint bundle, or a subject-bound client. The text is static:
it never contains provider data, credentials, subjects, skill bodies, or
memory content, so live projection changes cannot make a snapshotted tool list
stale.

Root Library tools support explicit skill inspection and resolution, not
activation. Generic connectors and endpoint bundles expose no Library
orientation or memory workflow. When those facets are available on a
subject-bound client, its bootstrap points the agent to no-argument
`library_skill_activation` for assigned procedural context, including the
managed **Using Synaxis** guide, and to focused `library_memory_recall` for
governed durable context. Automatic assignment does not inject instructions
into an external host: the host still requests and verifies the activation
bundle and chooses its model-context placement. Skills and memories do not
grant tools, credentials, OAuth scopes, permissions, or authority; the Engine
enforces the authenticated endpoint and current policy again for every
requested action.

## Secure development quickstart

Requirements:

- Go 1.25.5 or newer
- optional Postgres for durable production storage

Run these commands from `backend/` in the private monorepo, or from the
standalone Engine repository root after export:

```bash
go mod download
umask 077
ENGINE_ISSUER=http://localhost:8080 \
ENGINE_DEVELOPMENT_MODE=true \
go run ./cmd/engine
```

The Engine prints a fresh temporary console/consent password and keeps its
ephemeral signing secret in memory. Confirm startup with
`curl http://localhost:8080/healthz`, then add `http://localhost:8080/mcp` to
an MCP client and complete consent with the printed password. The development
server listens on all interfaces, so keep it behind a local firewall and never
forward port 8080 from an untrusted network. The generated password and signing
secret change on restart.

Development mode is an explicit local sandbox, not a shortcut for a persistent
deployment. For self-hosting, supply unique `ENGINE_PASSWORD` and
`ENGINE_SECRET` values, enable `ENGINE_LOCAL_ADMIN_AUTH_ENABLED=true` only when
you need password login, and use Postgres plus `ENGINE_ENCRYPTION_KEY` before
storing real provider credentials. Local `.env` files and the default
`accounts.json` store are ignored by Git, Docker, and Cloud Build.

Build the container:

```bash
docker build -t synaxis-engine .
docker run --rm -p 8080:8080 \
  -e ENGINE_ISSUER=http://localhost:8080 \
  -e ENGINE_PASSWORD='<unique-random-password>' \
  -e ENGINE_SECRET='<at-least-32-random-characters>' \
  -e ENGINE_LOCAL_ADMIN_AUTH_ENABLED=true \
  synaxis-engine
```

Use `DATABASE_URL` and `ENGINE_ENCRYPTION_KEY` for a durable deployment. A
Platform-managed Engine (`SYNAXIS_WORKSPACE_ID`) refuses to start without an
encryption key; self-hosted development may omit it only for disposable local
data. Do not expose development credentials.

## Health and control access

`GET /healthz` and `GET /readyz` are public process probes. They intentionally
do not reveal connected accounts or upstream health.

Protected management routes accept either:

- a self-hosted session obtained from `POST /api/login`; or
- a machine credential configured as `SYNAXIS_ADMIN_TOKEN`.

Password login is **off by default** for a configured self-hosted Engine, so
an unattended process does not publish `/api/login` or legacy `/admin/*`
forms behind a repository-known credential. To use the local console on a
self-hosted deployment, set unique `ENGINE_PASSWORD` and `ENGINE_SECRET`
values and explicitly set `ENGINE_LOCAL_ADMIN_AUTH_ENABLED=true`. Legacy
`/admin/connect` and `/admin/token` compatibility forms additionally require
`SYNAXIS_ENABLE_LEGACY_ADMIN=true`.

`ENGINE_ADMIN_TOKEN` is a migration alias. When both are present,
`SYNAXIS_ADMIN_TOKEN` wins. The machine token grants broad engine management
access and must be random, held in a secret manager, rotated, and never sent to
a browser.

The hosted Synaxis frontend authenticates to Synaxis Platform, not directly to
an engine. Platform resolves the workspace and attaches the relevant
per-engine machine credential server-side.

## Management API

`GET /healthz`, `GET /readyz`, `GET /api/auth`, and the state-validated
`GET /api/oauth/callback` are public. `POST /api/login` exists only when local
admin authentication is explicitly enabled. Every other `/api/*` route below
requires either a local session bearer token or `SYNAXIS_ADMIN_TOKEN`. Hosted
requests also carry a signed Platform actor assertion; the Engine applies the
actor's role, subject, and connection-namespace grants after machine
authentication.

| Methods | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/gateway`, `/api/health` | MCP endpoint metadata and per-connection health |
| `GET` | `/api/logs`, `/api/logs/{id}` | Summary audit rows and one recorded call |
| `POST` | `/api/logs/{id}/replay`, `/api/logs/{id}/triage` | Replay a recorded call or persist a triage decision |
| `GET, POST` | `/api/servers` | List or create credential-bearing connections |
| `PATCH, DELETE` | `/api/servers/{id}` | Update policy/ownership metadata or delete a connection |
| `POST` | `/api/servers/{id}/connect` | Start upstream OAuth |
| `PUT` | `/api/servers/{id}/token` | Store a bearer token for a token-auth connection |
| `GET, PUT` | `/api/servers/{id}/tools` | Read or replace the connection's enabled-tool set |
| `PUT` | `/api/servers/{id}/tools/{tool}` | Update one tool's alias, description, or enabled policy |
| `GET, POST` | `/api/connection-namespaces` | List visible credential folders or create a shared folder |
| `GET, PATCH, DELETE` | `/api/connection-namespaces/{id}` | Read, rename, or delete a credential folder |
| `GET, PUT` | `/api/connection-namespaces/{id}/managers` | Read or replace delegated manager subjects |
| `PUT, DELETE` | `/api/connection-namespaces/{id}/managers/{subject}` | Grant or revoke one manager subject |
| `GET, POST` | `/api/mcp-clients` | List or register subject-bound MCP clients |
| `GET, PATCH` | `/api/mcp-clients/{id}` | Read or rename an MCP client registration |
| `PUT` | `/api/mcp-clients/{id}/namespaces` | Replace an MCP client's connection-namespace grants |
| `POST` | `/api/mcp-clients/{id}/oauth-client/reset` | Clear a stale DCR binding and rotate the endpoint epoch |
| `POST` | `/api/mcp-clients/{id}/revoke` | Revoke a scoped MCP client and its resource tokens |
| `GET, POST` | `/api/connectors` | List or create curated virtual connectors |
| `PUT, DELETE` | `/api/connectors/{slug}` | Update or delete a virtual connector |
| `GET, POST` | `/api/endpoints` | List or create whole-connection endpoint bundles |
| `GET, PUT, DELETE` | `/api/endpoints/{slug}` | Read, update, or delete an endpoint bundle |
| `PUT, DELETE` | `/api/endpoints/{slug}/accounts/{account}` | Add or remove an endpoint-bundle member |
| `POST` | `/api/guardrails/test` | Test content against the connector guard pipeline |
| `GET` | `/api/config` | Export secret-free configuration |
| `POST` | `/api/config/import` | Validate and merge a secret-free configuration export |
| `GET` | `/api/approvals` | List parked-call records |
| `POST` | `/api/approvals/{id}/approve`, `/api/approvals/{id}/deny` | Decide a parked call |
| `POST` | `/api/oauth/revoke-all` | Revoke all MCP-facing OAuth grants |
| `GET` | `/api/activation` | Return the privacy-limited connection count described below |
| `GET` | `/api/usage` | Read sanitized usage |
| `PUT` | `/api/usage/grant` | Install a signed hosted allowance |
| `POST` | `/api/library/resolve` | Read applicable portable instructions from opaque context; never executes a skill or grants authority |
| `GET, POST` | `/api/library/skills` | List/create portable skills and their initial immutable version |
| `GET` | `/api/library/skills/{id}` | Read a skill, immutable versions, generic bindings, and evaluations |
| `GET, POST` | `/api/library/skills/{id}/versions`, `/bindings`, `/evaluations` | Manage versions, bindings, and append-only evaluation evidence |
| `DELETE` | `/api/library/skills/{id}/bindings/{binding}` | Remove one generic binding |
| `POST` | `/api/library/skill-drafts` | Self-hosted direct generator; returns `503` when unconfigured and is rejected for hosted Engines |
| `POST` | `/api/library/skill-drafts/platform-import` | Platform-only import of one validated editable generated draft; hosted owner/admin actor assertion and machine credential required |
| `GET, POST` | `/api/library/memories` | List memory metadata or create a human-confirmed proposal for one exact active agent surface |
| `GET, DELETE` | `/api/library/memories/{id}` | Read a card and immutable versions, or hard-forget the card, versions, and grants |
| `GET, POST` | `/api/library/memories/{id}/versions` | List immutable versions or append a proposed correction |
| `POST` | `/api/library/memories/{id}/review` | Review the exact current memory version and set lifecycle, trust, and freshness |
| `GET, POST` | `/api/library/memories/{id}/grants` | List grants or delegate the active, unexpired current version/digest to one active MCP client |
| `POST` | `/api/library/memories/{id}/grants/{grant}/revoke` | Revoke one exact-version memory handoff |
| `GET, POST` | `/api/library/artifacts` | List/create private immutable artifacts |
| `GET` | `/api/library/artifacts/{id}` | Read an artifact and all of its versions |
| `GET, POST` | `/api/library/artifacts/{id}/versions` | List/create artifact versions; each new version starts pending review |
| `POST` | `/api/library/artifacts/{id}/review` | Approve or reject an artifact version for Platform public sharing |
| `GET, POST` | `/api/library/artifacts/{id}/grants` | List or create a private, version-pinned handoff to one live MCP-client registration; never grants credentials or authority |
| `POST` | `/api/library/artifacts/{id}/grants/{grant}/revoke` | Revoke one private agent handoff without altering its historical record |
| `GET` | `/api/library/artifacts/{id}/publication-candidate` | Platform-service-only reviewed snapshot candidate; not browser-proxied |
| `POST` | `/api/library/artifacts/{id}/publication-claim` | Platform-service-only exact-version compare-and-claim before public publication |
| `GET, POST` | `/api/library/runs` | List provenance or add a manual `human`/`automation` record; trusted `skill_run`/`agent_direct` provenance is not browser-creatable |
| `GET` | `/api/library/runs/{id}` | Read one run |

The legacy `/api/namespaces*` route family remains an exact compatibility alias
for `/api/endpoints*`; it does not address credential-owning connection
namespaces.

### Activation snapshot

`GET /api/activation` returns only `{"connectionCount": <number>}`. It does
not return connection names, provider URLs, credential state, namespace
membership, or tool metadata. In hosted mode, the route accepts only the
signed Platform **service** actor, never a browser member actor, even when that
member is an owner or admin. A self-hosted Engine without a Platform actor
verifier may read it through normal management authentication. The narrow
contract lets a control plane measure first-connection activation without
copying credential metadata out of the Engine trust boundary.

## Hosted OAuth consent contract

Self-hosted Engine uses its password consent form by default. A hosted Engine
can delegate only the human consent decision to a control plane without
receiving Platform profiles, membership records, subscriptions, tenant slugs,
or billing data. It receives only the opaque subject, role, and resource facts
needed to authorize the request:

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
     "resource_path": "/mcp/clients/my-codex",
     "sub": "opaque-member-id",
     "role": "operator",
     "request_sha256": "<base64url-no-padding SHA-256 of the exact request token>",
     "jti": "<unique 16-128 character base64url identifier>",
     "exp": 1785153780,
     "approved": true
   }
   ```

   `aud` and `engine_issuer` must both exactly equal `ENGINE_ISSUER`, and
   `resource_path` must exactly match the resource sealed into the Engine's
   request token. Current hosted approvals also include the authenticated
   member's opaque `sub` and role; Engine rechecks both against the resource
   class before issuing a code. `exp` must be in the future and no more than
   five minutes ahead. Set `approved` explicitly to `true` or `false`; a
   signed `false` is a normal OAuth denial.
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

Hosted deployments force `ENGINE_LOCAL_ADMIN_AUTH_ENABLED=false` and
`SYNAXIS_ENABLE_LEGACY_ADMIN=false`, even if an inherited environment attempts
to enable them. This removes the password login/session path and compatibility
forms while preserving server-to-server access through `SYNAXIS_ADMIN_TOKEN`.

### Hosted management actor contract

Hosted management requests require both the machine bearer credential and an
Ed25519 JWS in `X-Synaxis-Actor-Assertion`. The JWS type is
`synaxis-engine-actor+jwt`; its claims bind the opaque `workspace_id`,
`user_id`, and `role` to the Engine audience, exact HTTP `method`, normalized
`path`, and base64url SHA-256 `body_sha256`, with `iss`, `iat`, `exp`, and
`jti`. Assertions live for at most two minutes, accept at most ten seconds of
clock skew, and cannot carry a query string or be reused for another method,
path, or body.

Member assertions use `owner`, `admin`, `operator`, or `viewer`; Engine
handlers then enforce their own namespace and connection rules. The reserved
`service` actor is accepted only as `platform-service` on
`POST /api/oauth/revoke-all`, `PUT /api/usage/grant`, `GET /api/usage`, and
`GET /api/activation`. It cannot mutate connections or approvals.

## Hosted usage contract

Self-hosted Engines are quota-unlimited. A hosted provisioner enables the
generic usage boundary by setting `SYNAXIS_WORKSPACE_ID` and the positive
`SYNAXIS_PROVISION_GENERATION`; this requires Postgres and the existing
`ENGINE_CONSENT_PUBLIC_KEY`.

Before exposing MCP traffic, Platform sends an authenticated
`PUT /api/usage/grant` with `{"grant":"<compact-jws>"}`. The Ed25519 JWT uses
`{"alg":"EdDSA","typ":"synaxis-engine-usage-grant+jwt"}` and these claims:

```json
{
  "iss": "synaxis-platform",
  "aud": "synaxis-engine",
  "workspace_id": "opaque-workspace-id",
  "engine_generation": 7,
  "period_start": "2026-07-30T00:00:00Z",
  "period_end": "2026-08-30T00:00:00Z",
  "revision": 3,
  "plan_id": "platform-plan-v1",
  "status": "active",
  "limits": {
    "calls": 10000,
    "runtime_seconds": 28800,
    "transfer_bytes": 2147483648,
    "concurrency": 4,
    "rate_per_minute": 60,
    "burst": 10,
    "max_call_seconds": 120
  },
  "iat": 1785369600,
  "exp": 1788048000
}
```

`plan_id` is an opaque, Platform-defined identifier. The Engine validates its
format and signature but intentionally does not maintain a commercial plan
catalogue: every enforceable allowance is carried explicitly in the signed
`limits` claim. Signed grants may include audited operator extensions to the
metered totals. The Engine still applies its independent request, result, and
signed-limit safety validation.

Admission and settlement use durable usage-period and reservation rows, not
the asynchronous audit log. An interrupted reservation retains its concurrency
slot until its signed call deadline, then recovery charges that bounded runtime
and releases it. `GET /api/usage` returns only sanitized aggregate usage with
`mode: "enforced"` and the same snake_case inner limit/counter keys carried by
the grant. Both routes require the normal management bearer credential.

All MCP endpoints independently enforce a 1 MiB complete request cap, a 2 MiB
complete tool-result cap, and a maximum 120-second upstream deadline. Discovery,
authentication, health checks, and denied approvals do not consume a call.
Upstream errors, timeouts, approved calls, and explicit replays do.

The Engine's supported upstream transport is MCP Streamable HTTP. Both its
`application/json` and per-request `text/event-stream` response bodies are
bounded before MCP decoding at the 2 MiB result limit plus 64 KiB of protocol
framing. The decoded result is still checked against the exact 2 MiB public
cap. Legacy persistent-SSE and stdio upstream clients are not instantiated.

## Namespaces, connections, and endpoint bundles

A **namespace** is an owning folder inside one Engine workspace. A
**connection** is one upstream provider account, one credential set, one
refresh lifecycle, and one immutable tool prefix, and it belongs to exactly one
namespace. A provider definition supplies reusable URL, authentication, and
method metadata; it does not own a user's credential. The same provider can
therefore be connected repeatedly:

```text
Tegence
└── Notion (credential A)   → tegence_notion__notion-search

Personal
└── Notion (credential B)   → personal_notion__notion-search
```

Both connections expose the same core Notion methods, but their tool prefixes
and handler closures route every call through different stored credentials.
The console suggests `<namespace>_<provider>` and appends a suffix for a
collision; the management API also accepts an explicit globally unique
`toolPrefix`. Existing prefixes are never silently rewritten when a connection
label is renamed or its owning namespace changes.

An **endpoint bundle** is a separate, provider-agnostic delivery resource. It
references eligible shared or service connections from any namespaces and is
served as an audience-bound MCP resource at
`<ENGINE_ISSUER>/mcp/<slug>`. One connection can be a member of multiple
endpoint bundles without copying credentials:

```text
Client delivery  → Tegence / Notion, Tegence / GitHub
Research tools   → Tegence / Notion
```

Inside every endpoint, tools retain their `<tool-prefix>__<tool>` identities.
Adding or removing a connection therefore does not rename tools or require
another upstream OAuth flow. Deleting an endpoint revokes only that MCP
resource and leaves member connections, credentials, namespace folders, and
the root `/mcp` aggregate intact.

Membership edits intentionally keep the endpoint generation stable, so
already-authorized clients see its current contents immediately. Mutations
carry both the opaque generation and current revision; stale tabs cannot
modify a deleted-and-recreated endpoint that reuses a slug. Audit rows retain
endpoint kind and generation, so replay fails closed after deletion or
replacement. Endpoint-bundle and curated-connector slugs share the
`/mcp/<slug>` URL space and must be unique.

The preferred CRUD surface is `/api/endpoints*`. The former
`/api/namespaces*` routes remain behaviorally identical compatibility aliases
for endpoint bundles. On connection payloads, `connectionNamespace` is the
owning folder and `toolPrefix` is the routing identity. Legacy clients may keep
sending `group` for the folder and `namespace` for the tool prefix. Stored
accounts, credentials, prefixes, endpoint URLs, and OAuth grants require no
destructive migration.

### Connection scopes and access control

Connection namespaces own credentials; they are not MCP delivery endpoints.
Each account carries one durable namespace ID and one explicit scope:

- `shared` is eligible for the root aggregate, endpoint bundles, curated
  connectors, and scoped MCP clients that have the owning namespace grant.
- `personal` requires an `owner_subject`. It is excluded from `/mcp`, endpoint
  bundles, and virtual connectors, and can appear only on a subject-bound MCP
  client whose subject exactly matches the account owner.
- `service` is a non-personal automation classification. It currently follows
  the same namespace-management and shared-delivery rules as `shared`; it does
  not create an additional authorization boundary by itself.

In hosted mode, owners and admins can read and manage every namespace. An
operator can read and manage only their own personal connections and shared
namespaces carrying an explicit manager grant. The Platform service actor is
restricted to its small control-route allowlist and cannot use namespace
management routes. Only workspace administrators may create or delete shared
namespaces or change their manager grants. `created_by` is audit attribution,
not permanent authority, and an administrator may revoke the creator's manager
grant. Unauthorized namespace and account lookups return `404` to avoid
becoming an enumeration channel.

Namespace and account mutations use opaque IDs, immutable account incarnation
IDs, and compare-and-swap revisions. A stale tab or delayed OAuth callback
therefore cannot write policy or credentials across a move, delete/recreate,
or concurrent manager revocation.

## Subject-bound MCP client endpoints

`/mcp/clients/{slug}` is a separate path namespace from shared
`/mcp/{slug}` endpoints. An MCP client registration contains a stable endpoint
slug, one Platform subject, and a set of connection-namespace IDs. It contains
no bearer credential. The first approved OAuth consent binds the registration
to one DCR client ID; replacing that binding requires an explicit reset.

Owners and admins may authorize shared root and connector resources. Operators
may authorize only a subject-bound MCP client registered to their exact
subject. A scoped endpoint projects shared/service connections from its granted
namespaces plus personal connections owned by the same subject. The Engine
rechecks that boundary from durable state before listing tools and immediately
before every tool call.

Changing namespace grants, moving an account across an endpoint boundary,
resetting the OAuth binding, or revoking the client rotates its endpoint epoch.
Tokens, authorization codes, and refresh grants minted for the prior epoch then
fail closed. Slugs and tool prefixes remain stable.

Only this subject-bound resource exposes `library_memory_propose`,
`library_memory_recall`, and `library_memory_read`. Memory tools are absent
from root `/mcp`, shared endpoints, and generic connector resources. The
Engine derives the exact durable client ID, subject, and epoch from the
authenticated resource; no memory tool accepts a caller-selected agent surface.

## Connector-only response guardrails

Response redaction, result-size caps, and prompt-injection scanning run only on
curated virtual connectors. The pipeline is
`redact -> size cap -> injection scan -> audit`, and recorded payloads contain
the post-guard result. Replays through a surviving connector apply that
connector's current rules.

The root `/mcp` aggregate is an intentional raw passthrough. Whole-connection
endpoint bundles and `/mcp/clients/{slug}` subject-bound endpoints are also raw
with respect to connector response guardrails. Account-level tool disabling,
read-only filtering, OAuth resource binding, namespace ACLs, request/result
hard caps, and audit logging still apply on their respective surfaces. Do not
describe an endpoint bundle or scoped MCP client as redacted unless a future
explicit policy layer adds that behavior.

## Portable Library

The Engine-native Library stores reusable skills, governed memory, artifacts,
and provenance without importing Platform concepts. A skill has stable
metadata plus immutable Markdown instruction versions and requested
capabilities. Requested capabilities are intent, not authority: an effective
runtime set can only be the intersection of the skill request, an optional
binding ceiling, and the already-granted runtime capabilities.

Bindings use opaque, generic scope kinds — `workspace`, `namespace`, `folder`,
`repository`, `project`, and `agent_surface` — and can track latest or pin a
version. The generic `namespace` kind is deliberately unrelated to a
credential-owning `connection_namespace`. A binding cannot connect an upstream,
grant a credential, or override MCP/connector policy.

Authored binding priorities use the portable signed 32-bit range through
`2147483646`; the top value, `2147483647`, is reserved for the Engine-managed
operating guide.

The Engine reserves and persists one first-party skill:
`libsk_synaxis_using_synaxis` (slug `synaxis-using-synaxis`,
`managedBy` = `synaxis-engine`). The exact shipped **Using Synaxis** v1 is
`libskv_synaxis_using_synaxis_v1`; it is capability-free and automatically
pinned at the highest priority to every durable subject-bound MCP client.
Startup atomically selects a durable current-version marker and reconciles
registrations created by older binaries; creating a new client follows that
marker in the same store operation. Upgrades move the marker and every managed
binding to the new binary's exact immutable version, while a rollback moves
them to the version known by the older binary. A process that does not
recognize the marked version fails activation closed. Owners may inspect
the skill, version, and binding for audit but cannot edit, append, adopt for
authoring, rebind, or delete them. These records remain context constraints,
never credentials or action authority.

Memory cards retain deliberate `decision`, `constraint`, `preference`,
`lesson`, `fact`, or `handoff` context. A logical card is `proposed`, `active`,
`disputed`, `superseded`, or `expired` and carries an `agent_observed`,
`human_confirmed`, `workspace_approved`, or `host_attested` trust label plus
optional expiry and review dates. Content exists only in immutable, SHA-256
digested versions with optional run and exact artifact-version provenance; each
statement is capped at 8 KiB. A correction appends a version and resets the
head to a human-confirmed proposal; an owner/admin must review that exact head
before it becomes recallable. A superseded card must name another active,
unexpired card as its replacement. Memory has no public candidate or anonymous
read route.

`library_memory_propose` derives ownership from the live client and can create
only an agent-observed proposal. `library_memory_recall` accepts optional
query/kind filters, a default-5/max-20 limit, and a 1–32 KiB byte budget that
defaults to 32 KiB; queries are capped at 4 KiB. It deterministically returns
only active, unexpired exact versions owned by that surface or pinned to it
through a live grant. `library_memory_read` requires both `memoryId` and
`memoryVersionId`—it never follows “latest.” The returned
`synaxis.library.memory.v1` bundle includes exact digest, provenance,
freshness, `own_surface` or `granted_exact_version` access, `reviewDue`, an
independent-record conflict policy, and a deterministic bundle digest. It does
not blend or truncate content and labels memory as context, never instructions,
authorization, or proof of execution.

An owner/admin may share only the active, unexpired current memory version and
digest with one active durable client registration. A correction atomically
revokes every live handoff; it neither advances a grant nor lets an old version
inherit the corrected head's review state. Revocation is enforced on the next
read or recall. Forget hard-deletes the card's authored versions and grants.
The Engine does not passively ingest chat,
audit, prompts, hidden reasoning, or runs, and does not inject memory into an
external host. Working memory remains host-side; cross-workspace personal
memory is not part of this Engine contract.

Artifacts have immutable text or Markdown versions (maximum 1 MiB), plus
private PNG/JPEG or safely sanitized SVG image versions (maximum 512 KiB).
Every new version is `pending` review. Runs retain only opaque actor/surface references,
source type, effective capabilities, status, and SHA-256 input/output digests.
An artifact created directly by an agent is marked `agent_direct`; it never
pretends to have a skill parent. The Engine offers `library_skill_list`,
`library_skill_read`, `library_skill_resolve`, `library_artifact_create`,
`library_artifact_read`, and `library_artifact_list` as ordinary MCP tools.
An authenticated subject-bound MCP client additionally has narrow append-only
revision tools for its own direct artifacts: `library_artifact_version_create`
for text/Markdown and `library_artifact_image_version_create` for image
versions. Each requires a unique request ID plus exact current version ID and
digest, rechecks the current client/epoch/direct-run ownership atomically, and
appends a new immutable pending version; it never overwrites content, follows a
grant, mutates a handoff, or changes authority. Exact retry replays the prior
result, while changed request-ID reuse or a stale head conflicts.
`library_skill_resolve` (and the protected `POST /api/library/resolve`)
selects an explicit binding or, per skill, the most-specific matching binding
in the order `folder > repository > namespace > workspace`. It returns
instructions and constraints only: runtime policy must independently grant and
intersect capability access immediately before a tool call. `project` and
`agent_surface` bindings are persisted but not automatically resolved until
their hierarchy is designed. Direct artifact tools create private content only
and cannot approve or publish it.

An owner/admin can grant one exact immutable artifact version to one durable
subject-bound MCP-client registration. A grant stores the artifact version ID
and digest plus the opaque client ID; it is never a user, connection, OAuth,
or credential grant. Client artifact list/read returns the pinned body and
digest rather than following later versions, and revocation is evaluated on
each call. A direct client artifact may cite one exact source
artifact/version/digest tuple only when the client owns it on that same surface
or has the matching live grant; V1 intentionally records one singular parent,
not general multi-input lineage. The trusted console/MCP endpoint derives each
artifact-version author rather than accepting one from a tool request.

A subject-bound `/mcp/clients/{slug}` endpoint is the narrow exception for an
explicit `agent_surface` binding: it derives the durable MCP-client ID from the
authenticated endpoint, never caller-supplied scope arguments. That scoped
endpoint also offers the read-only, no-argument `library_skill_activation`
tool for an external agent-host integration. It returns a deterministic
`synaxis.library.activation.v1` bundle with only an opaque agent-surface ID,
selected immutable skill/version/content digest/instructions, selected binding
metadata, and requested-capability/binding-ceiling constraints. It excludes
the client subject, OAuth identity, credential folders, connections, runtime
grants, and effective capabilities. The Engine verifies each instruction body
against its digest and includes a deterministic bundle digest. It does not inject
content into Codex, Claude, Cursor, or any other host, execute a skill, or
authorize a tool call; the host must independently verify the contract, choose
model-context placement, and enforce every action-time policy. Root `/mcp`
deliberately does not expose this activation tool.

The default activation envelope permits 33 total selections: the one managed
Using Synaxis skill plus up to 32 other assigned skills. Each instruction body
is still limited to 32 KiB. The complete canonical host context allows 132 KiB:
the prior 128 KiB workspace-instruction budget plus a 4 KiB reserve for the
exact managed guide. An over-limit bundle fails closed rather than returning a
partial selection. Hosts using an older reference-adapter default must update
it or explicitly allow at least 33 skills and 132 KiB before consuming the new
automatic assignment.

The open `narthex/backend/pkg/libraryruntime` package is a small Go reference
adapter for that handoff. It strictly verifies the v1 content and bundle
digests, builds a bounded deterministic JSON context document, and provides a
host-owned `GrantProvider`/`ToolInterceptor` contract that intersects fresh
host-authenticated grants with the skill request and binding ceiling for every
tool call. It neither receives credentials or connection data nor chooses a
model role or injects a model turn. Its `SkillRunEvidenceInput` is only a
digest-only immutable selection record for a separately authenticated runtime
provenance path; constructing one is not an Engine write or proof of execution.

Hosted sharing is deliberately split: after an administrator approves the
latest artifact version, Platform's exact service actor may call
`GET /api/library/artifacts/{id}/publication-candidate`. The candidate is a
narrow reviewed payload, not a raw artifact API, and is excluded from the
browser BFF. Platform copies an immutable allowlisted snapshot and owns the
one-time public URL, expiry, and revocation. The Engine remains usable
self-hosted without a Platform public-link implementation.

With Postgres and `ENGINE_ENCRYPTION_KEY`, all private authored Library free
text is AES-GCM encrypted at rest: skill/draft names and descriptions,
instructions, evaluation annotations, memory-version content, artifact
titles/summaries, and artifact bodies, plus private authorship/source
references (including the memory provenance source digest). Structural IDs,
content/version digests, timestamps, and policy fields remain queryable
metadata. FileStore implements the same memory lifecycle, recall, grant, and
forget semantics while retaining its documented plaintext local-development
posture.

### Optional direct server-side draft creator

`POST /api/library/skill-drafts` can use an OpenAI-compatible Chat Completions
endpoint to produce a reviewable skill draft for a self-hosted deployment. The
Engine process alone holds the provider key; raw task briefs are not retained
as provenance (only their SHA-256 digest). The generator cannot publish, bind,
obtain connector credentials, or run an agent. With no draft configuration,
the route returns `503` rather than fabricating a draft. Synaxis does not ship
or infer a provider secret: a self-hosted operator must configure the provider
URL and key explicitly through the Engine runtime secret/configuration system.
Managed deployments should not distribute one provider key across workspace
Engines. A hosted Engine fails startup if any direct-provider variables are
set; when it is running, the ordinary direct route rejects hosted requests. A
Platform-held broker may use the fixed
`/api/library/skill-drafts/platform-import` route to persist only a validated
editable candidate. That import requires the normal machine credential plus a
request-bound original owner/admin assertion, stores only a hash of its opaque
idempotency request ID, and cannot create a skill, binding, run, artifact, or
public link. The Engine ships no managed provider configuration; an
unconfigured Platform broker keeps hosted generation off.

## Configuration

The complete example is in [`.env.example`](.env.example). Important values:

| Variable | Purpose |
| --- | --- |
| `PORT` / `ENGINE_PORT` | HTTP listen port |
| `ENGINE_ISSUER` | Canonical public origin used in OAuth metadata and MCP URLs |
| `ENGINE_DEVELOPMENT_MODE` | Explicit local-only opt-in; generates ephemeral credentials and enables local login, never use for a hosted workspace |
| `ENGINE_PASSWORD` | Required unique local/self-hosted console and consent password unless explicit development mode generates one |
| `ENGINE_SECRET` | Required unique HMAC key for OAuth and local console tokens unless explicit development mode generates one |
| `ENGINE_CONSENT_URL` | Optional generic Platform consent page; must be paired with `ENGINE_CONSENT_PUBLIC_KEY` |
| `ENGINE_CONSENT_PUBLIC_KEY` | Base64 raw Ed25519 public key used to verify hosted approval assertions |
| `SYNAXIS_WORKSPACE_ID` | Optional opaque hosted workspace binding; enables durable usage enforcement |
| `SYNAXIS_PROVISION_GENERATION` | Positive hosted deployment generation bound into every signed usage grant |
| `ENGINE_LOCAL_ADMIN_AUTH_ENABLED` | Enables password `/api/login` and local session tokens; defaults to `false` outside explicit development mode; hosted engines force `false` |
| `SYNAXIS_ADMIN_TOKEN` | Optional trusted control-plane credential |
| `SYNAXIS_ENABLE_LEGACY_ADMIN` | Enables password-bearing `/admin/*` compatibility forms; defaults to `false`, hosted engines force `false` |
| `DATABASE_URL` | Optional Postgres connection string |
| `ENGINE_ENCRYPTION_KEY` | Base64 32-byte AES-GCM key for stored secrets; required when `SYNAXIS_WORKSPACE_ID` is set |
| `CONSOLE_URL` | Browser destination after upstream OAuth |
| `CONSOLE_ORIGIN` | Allowed browser origins for the legacy direct console |
| `ENGINE_SKILL_DRAFT_OPENAI_URL` | Optional HTTPS OpenAI-compatible API base or full Chat Completions endpoint for direct self-hosted skill drafts |
| `ENGINE_SKILL_DRAFT_OPENAI_API_KEY` | Server-only provider key for the direct self-hosted creator; use a secret manager and never expose it to an MCP client, browser, or hosted workspace Engine |
| `ENGINE_SKILL_DRAFT_OPENAI_MODEL` | Optional direct-creator model name; defaults to `gpt-4.1-mini` after URL/key are configured |

Migration-sensitive `ENGINE_*` names remain supported even as user-visible
product surfaces use Synaxis.

## Test

```bash
go build ./...
go vet ./...
go test -race ./internal/engine/
go test ./...
```

The exported repository runs the same commands in `.github/workflows/ci.yml`.
In the private monorepo, also verify the public boundary and a clean standalone
export from the repository root:

```bash
scripts/check-engine-boundary.sh
export_dir="$(mktemp -d)"
scripts/export-engine.sh "$export_dir"
(cd "$export_dir" && go test ./...)
```

## Architecture boundary

Engine code must not import private Synaxis Platform or Web packages. It may
define and serve generic control operations and enforce signed actor and usage
claims bound to opaque workspace/deployment identifiers. Platform concepts
such as user profiles, organizations, membership records, subscriptions,
entitlements, workspace slugs, custom domains, and provisioning jobs do not
belong in this module.

One hosted workspace runs one isolated engine process and datastore. Until the
Engine's OAuth and pending-connect state, plus each live approval waiter and
request, is made durable or coordinated, production deployments must use one
maximum application instance. Approval records and decisions themselves are
durable with PostgreSQL.

## License

Synaxis Engine is licensed under the [Apache License 2.0](LICENSE). The license
does not grant permission to use Synaxis trademarks except as needed to
describe the software's origin.
