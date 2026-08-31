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

The database contains only signed, privacy-minimized Fleet envelopes and public
queue metadata. Callers must still place it in KernAid's protected application
state (the Rescue vault or a Resident data directory with OS access controls).
Enrollment tokens, bearer credentials, provider secrets, raw evidence and
device seeds must never be passed to this crate.
