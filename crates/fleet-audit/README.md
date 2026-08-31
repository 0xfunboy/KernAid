# KernAid Fleet Audit Envelope v1

This crate creates a privacy-minimized, tamper-evident audit chain with the
existing `kernaid-device-identity::DeviceIdentity`. It never owns or serializes
the Ed25519 seed and contains no network or server implementation.

## Event contract

The wire schema is `dev.kernaid.fleet.audit-envelope.v1`. An event contains
only opaque tenant/device/session/event IDs, a monotonic sequence, the previous
signed event's SHA-256, an RFC 3339 timestamp, closed kind/outcome/risk enums,
an optional typed action ID, and optional target/report/evidence SHA-256
digests. There is no message, raw log, hostname, path, username, email,
credential, report body, or evidence body field.

Repair and rollback lifecycle events require an action ID and a known R0-R3
risk. R4 can only be recorded as a denied authorization decision; it cannot be
represented as an execution event. Diagnostic and rollback events have
dedicated enum variants.

## Signature and canonical bytes

Unsigned JSON is compact, recursively key-sorted canonical JSON. The audit
payload is:

```text
"kernaid:fleet:audit:v1\0" || uint64_be(canonical_json_length)
                                 || canonical_unsigned_json
```

`DeviceIdentity::sign_report` signs that payload using its existing
`KERNAID-SIGNED-REPORT-V1\0` framing. Verification reconstructs the same
`SignedReport` and requires caller-owned tenant ID, device ID, and enrolled
public key trust anchors. The public key and private seed are absent from the
event wire format.

Offline import accepts only exact canonical bytes and verifies the signature;
re-export is byte-identical. Unknown fields, floats, unsafe integers,
non-canonical base64url, invalid IDs/timestamps/digests, and oversized events
fail closed.

## Chain admission

Hash the complete canonical signed event with `event_sha256()`. Sequence 1 has
`previousEventSha256: null`; every later event must name the immediately prior
signed event digest. `AuditChainCheckpoint::admit` accepts the exact next event,
treats an identical latest event as an idempotent replay, and rejects gaps,
forks, cross-session events, and altered replays. Persist the checkpoint
atomically after admission.
