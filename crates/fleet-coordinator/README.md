# KernAid Fleet device coordinator

`kernaid-fleet-coordinator` is the transport-neutral service boundary between
Resident/Rescue and Fleet. It combines the signed wire contracts from
`kernaid-fleet-client` with the durable outboxes and verified caches in
`kernaid-fleet-runtime`; it does not contain an HTTP client, bearer token,
remote-command channel, or signing seed.

The caller owns HTTPS. It asks the coordinator for an exact request body and
the fixed route returned by `PreparedRequest::route()`, transports those bytes
unchanged, and returns the exact response body plus a separately delivered
canonical `dev.kernaid.fleet.service-receipt.v1` receipt. The receipt is signed
by an externally pinned Fleet service public key and binds the operation,
tenant, device, request SHA-256, response SHA-256 and a monotonic per-device
receipt sequence. Inventory and audit rows are acknowledged only after that
receipt verifies. The service private key never enters this crate.

The receipt is exact compact canonical JSON. Its fields are `schema`,
`tenantId`, `deviceId`, `operation`, positive safe-integer `sequence`,
lowercase `requestSha256`, lowercase `responseSha256`, RFC3339 `acceptedAt`,
`outcome: "accepted"`, and base64url-no-pad `signature`. The signature is
Ed25519 over
`kernaid:fleet:service-receipt:v1\0 || canonical_json(receipt_without_signature)`.
Operations are `inventory`, `audit`, `policy_pull`, and `entitlement_pull`.

Policy and entitlement pulls are signed with the existing `DeviceIdentity`.
Only one request per pull kind may be pending. Its canonical bytes survive a
restart, so a timeout never silently changes nonce or request identity. Before
any cache mutation, the coordinator verifies the service receipt and every
independently signed policy, entitlement, and revocation document. It journals
the complete bounded response before applying it. A process exit during apply
is recovered by exact replay on open; a changed, truncated, cross-tenant or
rollback response fails closed. Missing policy items never delete cached
policy.

`local_snapshot()` is the only presentation-facing view. It exposes bounded
queue counts, pull/recovery state, paid/safety capability booleans and policy
counts—never raw diagnostics, audit bodies, tokens, nonces, paths, signatures,
keys, or document content. An incomplete staged pull degrades paid capability
flags while diagnostics, report export and rollback remain available.

The coordinator state database and Fleet runtime database must live in the
same protected application-state boundary (Resident private data directory or
encrypted Rescue vault). Public trust anchors are supplied on every open and
are not persisted. Callers should abandon an expired pending pull explicitly
with its exact request digest before creating a fresh nonce.
