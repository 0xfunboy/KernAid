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
Private vendor signing material belongs in the control plane or an offline
release signer; the product receives only the pinned public trust anchor.
