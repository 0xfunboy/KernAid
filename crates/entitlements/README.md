# KernAid signed entitlements

This crate is the offline licensing boundary shared by Desk, Rescue and Fleet.
It verifies canonical Ed25519-signed entitlement and revocation documents
against a trust anchor obtained through the release/enrollment channel.

The client retains the returned checkpoint in its protected state and supplies
it to the next verification. Lower sequences and different documents at the
same sequence fail closed; a byte-identical replay is idempotent.

Signing messages are:

```text
KERNAID-ENTITLEMENT-V1\0 || uint64_be(canonical_claims_bytes) || canonical_claims_bytes
KERNAID-ENTITLEMENT-REVOCATIONS-V1\0 || uint64_be(canonical_claims_bytes) || canonical_claims_bytes
```

Documents contain only ASCII identifiers, enums and non-negative integers no
larger than JavaScript's safe integer. JSON objects are serialized with keys in
lexicographic order and no insignificant whitespace. The verifier rejects
unknown fields, duplicate/non-canonical input, unsafe numbers, invalid time
ordering, signature tampering and sequence rollback.

`capabilities()` implements safe degradation. Diagnostics, report export and
rollback of an already-started transaction remain available even when a paid
entitlement is expired, revoked or assigned to another device. New paid repair,
Fleet synchronization, audit upload and updates are gated according to the
verified feature set and lease state.

The crate does not store signing seeds, fetch licenses or grant broker access.
Private vendor signing material belongs only in the offline release signing
system; devices and the control plane receive only the pinned public trust
anchor. The control plane has no entitlement signing endpoint.

## Offline issuance

`kernaid-entitlement-issuer` is the offline release-side tool. It refuses
symlinked inputs, existing outputs, broadly readable seed files and
non-canonical claims. The control plane never needs the signing seed.

```bash
cargo run -p kernaid-entitlements --bin kernaid-entitlement-issuer -- \
  generate-key /private/entitlement.seed /private/entitlement.public

cargo run -p kernaid-entitlements --bin kernaid-entitlement-issuer -- \
  sign-entitlement /private/entitlement.seed claims.canonical.json \
  entitlement.signed.json

cargo run -p kernaid-entitlements --bin kernaid-entitlement-issuer -- \
  sign-revocations /private/entitlement.seed revocations.canonical.json \
  revocations.signed.json
```

The public-key file contains the unpadded base64url Ed25519 trust anchor. Seed
and signed outputs are created with owner-only permissions and are never
overwritten. Claims must already be exact compact canonical JSON; this prevents
an operator from signing a visually ambiguous or duplicate-key source.
