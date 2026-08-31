# KernAid Fleet wire schemas

This package is the closed, dependency-free TypeScript contract for Fleet v1.
It accepts only the documented fields and emits the exact bytes signed by the
KernAid Rust device client.

## Canonical JSON

`canonicalJson` recursively sorts object keys lexicographically, preserves
array order, and emits compact UTF-8 JSON. Values are limited to strings,
booleans, null, safe integers, arrays and plain objects. Floats, unsafe
integers, unsupported JavaScript values, cycles and invalid Unicode fail
closed.

Signatures are Ed25519 over these bytes, with no length prefix:

```text
kernaid:fleet:enrollment:v1\0 || canonical JSON(request without signature)
kernaid:fleet:inventory:v1\0  || canonical JSON(envelope without signature)
```

The test suite includes fixed enrollment and inventory vectors produced by the
Rust `fleet-client` crate. It verifies byte-for-byte canonical JSON and both
signatures in Node.js.

## Closed payloads

- `dev.kernaid.fleet.enrollment-request.v1` binds a one-time token, tenant,
  key-derived device ID, canonical Ed25519 SPKI key, platform, agent version,
  timestamp and nonce.
- `dev.kernaid.fleet.inventory-envelope.v1` carries one bounded aggregate asset
  snapshot. It has no field for command execution, logs, serial numbers,
  arbitrary findings or raw diagnostic content.

Device IDs have the canonical form
`KA-<first 24 lowercase hex characters of SHA-256(raw Ed25519 public key)>`.
