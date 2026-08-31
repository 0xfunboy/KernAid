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
kernaid:fleet:policy-pull:v1\0 || canonical JSON(request without signature)
```

The test suite includes fixed enrollment and inventory vectors produced by the
Rust `fleet-client` crate. It verifies byte-for-byte canonical JSON and both
signatures in Node.js.

Audit envelopes preserve the Rust `DeviceIdentity::sign_report` framing. The
Ed25519 signature covers the following nested byte sequence, where lengths are
unsigned big-endian integers:

```text
KERNAID-SIGNED-REPORT-V1\0 || u128be(payload length) || payload
payload = kernaid:fleet:audit:v1\0 || u64be(canonical length) || canonical JSON(unsigned envelope)
```

The fixed audit vector in `test/protocol.test.ts` was produced by the Rust
`fleet-audit` crate and verifies the complete nested framing cross-language.

Fleet policy bundles preserve the existing `kernaid-fleet-policy` framing:

```text
kernaid:fleet:policy:v1\0 || u64be(canonical unsigned length)
                              || canonical JSON(unsigned bundle)
```

Fixed Rust vectors verify both the policy-pull direct framing and the policy
bundle length framing byte-for-byte in Node.js.

## Closed payloads

- `dev.kernaid.fleet.enrollment-request.v1` binds a one-time token, tenant,
  key-derived device ID, canonical Ed25519 SPKI key, platform, agent version,
  timestamp and nonce.
- `dev.kernaid.fleet.inventory-envelope.v1` carries one bounded aggregate asset
  snapshot. It has no field for command execution, logs, serial numbers,
  arbitrary findings or raw diagnostic content.
- `dev.kernaid.fleet.audit-envelope.v1` carries a bounded event in a
  per-device, per-session digest chain. It accepts only identifiers, status,
  risk and target/report/evidence digests; raw logs, PII and arbitrary fields
  are not representable.
- `dev.kernaid.fleet.policy-pull-request.v1` is a minimal freshness proof from
  an enrolled device. Commands, diagnostics and repair authority cannot be
  represented.
- `dev.kernaid.fleet.policy-bundle.v1` mirrors the strict Rust policy format,
  including sorted assignments/rules and mandatory rollback availability.

Device IDs have the canonical form
`KA-<first 24 lowercase hex characters of SHA-256(raw Ed25519 public key)>`.
