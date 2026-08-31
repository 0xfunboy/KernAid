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

Database schema v2 adds the signed documents and checkpoints without changing
or discarding the v1 identity and inventory outbox. Opening a protected v1
database migrates it transactionally before use.

The database contains only signed, privacy-minimized Fleet envelopes, signed
commercial documents, their public digests/checkpoints and queue metadata.
Callers must still place it in KernAid's protected application state (the
Rescue vault or a Resident data directory with OS access controls). Enrollment
tokens, bearer credentials, provider secrets, raw evidence, signing seeds and
device seeds must never be passed to this crate.
