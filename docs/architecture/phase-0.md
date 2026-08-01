# Phase 0 architecture

```text
Desk UI -> SessionDriver -> Agent Gateway -> Provider
                          -> Core -> Policy -> typed Broker
                          -> Evidence / journal
```

Provider output is an untrusted proposal. It cannot call the broker. Core links claims to evidence, validates action metadata, and admits only R0 in this phase. The fake broker recognizes only `system.observe.noop`, checks the target fingerprint, and rejects repeated or decreasing sequence numbers.

The Linux collector accepts exactly one directory fixture. It reads metadata only, never follows a block-device selector, never elevates privileges, and emits normalized JSON tagged `observed-untrusted`.

## Implemented acceptance checks

- Unknown broker actions are rejected.
- R1–R4 plans are rejected by Phase 0 policy.
- Provider diagnoses require evidence IDs.
- Seeded API-shaped secrets are redacted.
- Fixture file hashes are identical before and after Observe collection.

## Open release gates

The repository scaffold does not establish bootability, encrypted persistence, signed reports, Secure Boot compatibility, WebKit/GPU compatibility, or physical hardware support. Those require the next milestones and suitable build/test hosts.
