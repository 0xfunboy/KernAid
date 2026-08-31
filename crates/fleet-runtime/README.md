# KernAid Fleet runtime

`kernaid-fleet-runtime` is the device-side durable queue between signed Fleet
messages and an authenticated transport. It deliberately does not contain an
HTTP client or credentials: Resident and Rescue can use the same state machine
with their platform transport while the Ed25519 seed remains in the existing
native keychain or encrypted Rescue vault.

The runtime binds one database permanently to one tenant and device, allocates
inventory sequence numbers transactionally, signs one canonical envelope per
asset, and commits every envelope to SQLite before returning. A transport asks
for a bounded ready batch, acknowledges the exact row and payload digest after
a successful server response, or records a bounded retry delay after a
transient failure. Restarting or losing connectivity therefore cannot silently
drop inventory.

## Signed audit outbox

`enqueue_audit()` accepts only the privacy-bounded fields of an audit event.
Inside one immediate SQLite transaction it allocates the next sequence for the
session, reads the retained previous-event digest, signs with the caller-owned
`DeviceIdentity`, verifies the resulting envelope, advances the canonical
`AuditChainCheckpoint`, and stores the exact delivery bytes. The identity seed
and transport credentials never enter runtime state.

`pending_audit()` returns a bounded batch only after rechecking each canonical
payload, Ed25519 signature, database metadata and session checkpoint.
`acknowledge_audit()` requires the exact row ID and payload digest. Exact
enqueue replay and repeated acknowledgement are idempotent; changed event-ID
replay, chain gaps, forks, wrong identities and corrupt rows fail closed.
Acknowledged events remain as a bounded signed journal so replay decisions and
the next chain link survive restart.

## Entitlement runtime

`open_with_entitlement_anchor()` accepts the externally pinned Ed25519 vendor
public key. The anchor remains in process memory and is never written to the
database. `apply_entitlement()` and `apply_revocations()` verify canonical
signed documents, tenant/device assignment and their retained monotonic
checkpoints before updating document and checkpoint in one SQLite transaction.
Exact replay is idempotent; lower sequences and a different document at the
same sequence fail closed. `load_entitlement()` and `load_revocations()`
re-verify the persisted bytes, signature, checkpoint and binding on every
load.

`capabilities(now)` is the only licensing decision surface. A missing anchor,
missing entitlement, invalid clock, expired/revoked license, corrupt document,
bad signature or checkpoint mismatch leaves diagnostics, report export and
rollback available while every paid capability is false. In particular, an
entitlement failure can never prevent an already-started rollback.

## Signed policy cache

`open_with_policy_anchor()` accepts the externally pinned tenant Ed25519
public key and re-verifies every retained policy before returning. The anchor
stays in process memory. `open_with_trust_anchors()` configures both policy and
entitlement verification without mixing their trust domains.

`apply_policy()` accepts only canonical `SignedPolicyBundle` bytes for the
runtime tenant and enrolled device. Each `policyId` has an independent
monotonic checkpoint; document and checkpoint advance in one immediate SQLite
transaction. Exact replay is idempotent, while rollback, same-revision
conflicts, cross-tenant documents and policies not assigned to this device are
rejected. There is intentionally no replace-all or delete-on-pull API: a policy
missing from a partial Fleet response stays cached until its signed expiry or
offline window makes it inapplicable, or until a future signed revocation
contract is implemented.

`load_policies()` rechecks canonical encoding, signature, binding, digest and
checkpoint for the complete cache and fails the whole load if any row is
invalid. `applicable_policies(now, transport)` returns the verified policies
currently applicable to new repair. Core/Broker must intersect every returned
policy with every local restriction; no cached policy independently grants
execution authority. Diagnostics and an already-started rollback continue to
use the safety behavior defined by `kernaid-fleet-policy`.

Database schema v4 adds the signed per-policy document/checkpoint cache without
changing or discarding the v3 audit journal, v2 entitlement state, v1 identity
or inventory outbox. Opening a protected v1, v2 or v3 database migrates it
transactionally before use.

The database contains only signed, privacy-minimized Fleet envelopes and audit
events, signed commercial documents, their public digests/checkpoints and
queue metadata. Callers must still place it in KernAid's protected application
state (the Rescue vault or a Resident data directory with OS access controls).
Enrollment tokens, bearer credentials, provider secrets, raw evidence,
signing seeds and device seeds must never be passed to this crate.
