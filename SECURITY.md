# Synaxis Engine security policy

## Reporting

Do not open a public issue for a suspected vulnerability. Use the repository's
private vulnerability-reporting form from its **Security** tab. Include a
minimal reproduction, affected version, expected impact, and whether secrets
or cross-boundary access were observed.

## Deployment boundary

Synaxis Engine holds upstream OAuth tokens and brokers agent tool calls.

- Set unique production values for `ENGINE_SECRET`, `ENGINE_PASSWORD`,
  `ENGINE_ENCRYPTION_KEY`, and any `SYNAXIS_ADMIN_TOKEN`. Engine startup
  rejects missing password/signing credentials outside explicit development
  mode; it never supplies a source-known fallback.
- Keep machine control credentials in a secret manager and never expose them
  to a browser.
- Hosted consent uses only an Ed25519 public key inside Engine. Keep the
  corresponding private key in Platform, validate the signed-in workspace
  independently of browser query parameters, and never attach the Engine
  machine credential to the consent browser flow.
- Password `/api/login` is disabled by default and legacy `/admin/*` forms
  require `SYNAXIS_ENABLE_LEGACY_ADMIN=true`. Hosted deployments force both
  paths off; machine bearer authentication remains available for Platform.
- Use HTTPS and an exact canonical `ENGINE_ISSUER`.
- Use Postgres plus `ENGINE_ENCRYPTION_KEY` for durable encrypted storage.
- The local JSON store is a development convenience and stores values in the
  local file.
- Run one maximum application instance until OAuth client/code/grant state,
  pending connection flows, and approval waiters are durable or coordinated.
- Public `/healthz` and `/readyz` expose process status only. Detailed account
  and upstream health remains authenticated.
- Connector guardrails do not apply to the raw aggregate `/mcp`; audience
  binding is what prevents a connector token from calling that raw endpoint.

Supported version: the latest published release.

## GO-2026-6911 local mitigation

Reviewed November 6, 2026; review required **before November 13, 2026 UTC**.
The [official Go advisory](https://vuln.go.dev/ID/GO-2026-6911.json) currently
reports unvalidated MCP redirects in `github.com/mark3labs/mcp-go`, with no
fixed version. Engine uses v1.4.0 and still produces this scanner finding.
This is a verified local mitigation, not an upstream fix or a clean scan.

Engine supplies the SDK's HTTP client with `checkUpstreamMCPRedirect`, which
rejects a change of scheme, hostname, or effective port before another request
is sent. It also retains the existing HTTPS, public-address, userinfo, and
redirect-limit checks. Same-origin redirects remain supported; OAuth discovery
uses its separate redirect policy. The actual
[v1.4.0 transport source](https://github.com/mark3labs/mcp-go/blob/v1.4.0/client/transport/streamable_http.go)
attaches configured headers before sending requests. All request paths, including
session close, use the supplied HTTP client; bearer headers and session IDs stay
within its redirect boundary. The advisory's issue links currently
point to a different JSON-RPC issue; the review relies on the published advisory,
the pinned SDK source, and adversarial tests of the real client.

`scripts/check_go_vulnerabilities.py` runs the complete current Go vulnerability
database scan. It prints every finding and preserves the normal symbol-scan
distinction between reachable findings and informational module/package findings.
As documented by [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
JSON mode itself returns success even when vulnerabilities are found, so the
wrapper enforces failure explicitly. Only GO-2026-6911 in original mcp-go v1.4.0
may pass with local mitigation, and only for the reviewed transport symbols
whose traces enter Engine's `(*Upstream).dial` (`withConn` for deferred `Close`).
Different findings, dependencies, call sites, affected metadata, available fixes,
tool failures, malformed output, and expiration fail the gate.

Before allowing that result, the gate runs all three `TestUpstreamMCPRedirect*`
regressions without cached results and verifies that each actually ran and passed,
with no skipped cases. These cover redirects to unrelated hosts, subdomains and
changed ports across HTTP redirect status codes using both credential callbacks;
same-origin success; and the existing redirect safety checks. The gate and its
negative tests ship in the public Engine export and run in local verification
and CI. There is no general exception list or deadline override.

At review, check for an upstream patched release, upgrade and remove this special
handling when available, or reassess the local mitigation explicitly before
changing the deadline. Do not pin an older vulnerability database to pass CI.
