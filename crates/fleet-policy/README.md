# KernAid Signed Fleet Policy Bundle v1

This crate verifies centrally signed Fleet restrictions without granting Fleet
any Core or broker authority. A policy can narrow a device's local action set,
risk ceiling, or approval threshold; it cannot make an unknown, locally denied,
or higher-risk action executable.

## Wire contract

The schema is `dev.kernaid.fleet.policy-bundle.v1`. JSON is compact and
recursive object keys are lexicographically sorted. The Ed25519 message is:

```text
"kernaid:fleet:policy:v1\0" || uint64_be(canonical_unsigned_json_length)
                                  || canonical_unsigned_json
```

`signature` is canonical unpadded base64url and is omitted from the signed JSON.
The bundle contains no public key. Verification always receives the tenant's
external `ed25519_dalek::VerifyingKey` trust anchor and expected tenant ID.

Assignments encode as exactly one of:

```json
{"all":true}
{"deviceIds":["KA-...","KA-..."]}
```

The device list, action lists, and provider-mode wire values must already be
lexicographically sorted and unique. Imports reject non-canonical bytes, floats, unsafe integers, duplicate
or unknown fields, invalid time windows, overlapping allow/deny actions, and an
`emergencyRollbackAlwaysAllowed` value other than `true`.

## Verification and anti-rollback

```rust,ignore
let verified = SignedPolicyBundle::import_and_verify(
    cached_bytes,
    &tenant_policy_public_key,
    expected_tenant_id,
)?;

match checkpoint.admit(&verified)? {
    CheckpointAdmission::Advanced | CheckpointAdmission::IdempotentReplay => {}
}
```

A checkpoint accepts a greater revision, treats the same revision and digest as
an idempotent replay, and rejects lower revisions or same-revision substitutions.
Persist `PolicyCheckpoint::export_canonical()` atomically with the cached bundle.

## Restrictive evaluation

`VerifiedPolicyBundle::evaluate` requires the device's local safety floor for
every action: local risk ceiling, local approval threshold, and explicit
known/allowed flags. Unknown risk or action and every locally denied action fail
closed before Fleet rules are considered.

Known local diagnostics remain available if a cached policy is past its offline
window. New repairs fail closed offline after `offlineAllowedUntilUnix` and at
policy expiry. A rollback that Core/broker already began remains available and
returns `audit_required: true`; Fleet never creates rollback authority.
