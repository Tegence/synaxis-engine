# Deprecations

Every compatibility path the Engine keeps is listed here with its replacement
and the earliest date it may be removed. The code marks each one with
`NoteDeprecated("<kind:name>")`, or `deprecatedHandler` for a route, which logs
the first use per process; production logs therefore answer "does anything
still use this?" before the date arrives. `TestDeprecatedSurfacesAreInTheLedger`
fails when code notes a surface this table does not list.

Rules:

- A new alias, fallback or compatibility route lands with a row here and a
  `NoteDeprecated` call, never silently.
- "Not before" is a floor, not a promise. Removal needs that date to have
  passed and 30 days of production logs without the surface's first-use line.
- Surfaces a self-hosted operator can reach (routes, environment variables)
  are also announced in the release notes of the version that adds the row.
- The dates below are proposals until the maintainer confirms them.

| Surface | Replacement | Not before | Evidence |
| --- | --- | --- | --- |
| `route:/api/namespaces` — `/api/namespaces`, `/api/namespaces/{slug}` and `/api/namespaces/{slug}/accounts/{account}` | `/api/endpoints` with the same sub-paths | 2027-01-31 | first-use log line |
| `field:account.namespace` — `namespace` on `POST /api/servers` | `toolPrefix` | 2027-01-31 | first-use log line |
| `field:account.group` — `group` on `POST` and `PATCH /api/servers`, and in `POST /api/config/import` documents that carry no `connectionNamespace` | `connectionNamespace` or `connectionNamespaceId` | 2027-01-31 | first-use log line |
| `env:ENGINE_ADMIN_TOKEN` — read when `SYNAXIS_ADMIN_TOKEN` is unset | `SYNAXIS_ADMIN_TOKEN` | 2027-01-31 | first-use log line at startup |
| `env:ENGINE_ENABLE_LEGACY_ADMIN` — read when `SYNAXIS_ENABLE_LEGACY_ADMIN` is unset | `SYNAXIS_ENABLE_LEGACY_ADMIN` | 2027-01-31 | first-use log line at startup |
| `route:/admin/connect` and `route:/admin/token` — password-bearing bootstrap forms, served only with `SYNAXIS_ENABLE_LEGACY_ADMIN=true` | the console, or `POST /api/servers` followed by `POST /api/servers/{id}/connect` or `PUT /api/servers/{id}/token` | 2027-01-31 | first-use log line |
| `route:/api/skills` — the Git-backed skills API under `/api/skills` and `/api/skill-sources` | the Library: `/api/library/skills` and skill bundles | 2027-01-31 | first-use log line; Synaxis Web does not call it |
