# Synaxis Library runtime adapter

`libraryruntime` is a provider-neutral reference adapter for the Engine's
context-only Library activation handoff. It deliberately does not authenticate
an actor, inject text into a model turn, obtain a credential, resolve a
connection, execute a tool, or turn a requested capability into authority.
Those remain responsibilities of the host integration.

## Activation bundle v1

[`activation-bundle.v1.schema.json`](activation-bundle.v1.schema.json) is the
language-neutral JSON Schema for `synaxis.library.activation.v1`. It declares
the complete strict wire shape, the fixed authority notice and host
responsibilities, the `mcp_client` surface type, and field-level constraints.
It is useful for non-Go host implementations and generated clients.

The schema is necessary but not sufficient for safe activation. JSON Schema
cannot prove that `contentDigest` covers the exact instruction bytes, that
`bundleDigest` covers the canonical contract material, or that capability
arrays are canonically ordered. A host must parse the raw response with
`DecodeAndVerifyActivationBundle` before using it and must enforce its own
resource limits through `Limits`.

The canonical fixtures are intentionally small and stable:

- [`testdata/activation-bundle.v1.valid.json`](testdata/activation-bundle.v1.valid.json)
  passes both the JSON Schema and the Go reference adapter.
- [`testdata/activation-bundle.v1.invalid-unknown-field.json`](testdata/activation-bundle.v1.invalid-unknown-field.json)
  demonstrates strict rejection of an authority-bearing extra field.
- [`testdata/activation-bundle.v1.invalid-tampered-instructions.json`](testdata/activation-bundle.v1.invalid-tampered-instructions.json)
  has a valid structural shape but a stale digest, so only cryptographic
  runtime verification can reject it.

The Engine integration test decodes the actual `library_skill_activation` MCP
tool result through this public adapter. Any Engine wire-contract change must
therefore update the versioned schema, fixtures, adapter, and tests together.

## Host-attested result claims

This package intentionally implements only the context-only activation handoff.
It does not create or verify a runtime result claim. An Engine with a configured
per-client runtime-attestor key may additionally offer a client-only
`library_skill_runtime_receipt` MCP tool and a separate signed direct ingress.
That receipt is an **unsigned current-selection helper**, not an Engine-signed
token, bearer credential, or proof that a third-party host executed a tool.
Only the host signs the exact result request; even a verified signature records
host-reported provenance rather than Engine evidence of injection or execution.

See the [host-attested external runtime provenance contract](../../../docs/LIBRARY.md#host-attested-external-runtime-provenance)
for the exact byte-signing, expiry, replay, and revalidation rules. Provider
adapters should keep this boundary separate from activation v1 rather than
extend the activation schema with output or authority fields.
