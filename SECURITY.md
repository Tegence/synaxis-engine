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
