# KernAid signed A/B update client v1

`kernaid-update-client` is the device-side verification and planning boundary
for KernAid updates. It is deliberately a pure Rust library: it performs no
HTTP requests, filesystem writes, bootloader changes, or block-device access.

## Security contract

- Manifests use schema `dev.kernaid.update.manifest.v1` and Ed25519 over
  `kernaid:update:manifest:v1\0 || canonical_json(unsigned_manifest)`.
- The trust anchor is supplied out of band. A manifest cannot select its own
  key.
- Canonical JSON sorts object keys recursively, preserves array order, accepts
  only strings, booleans, null, and safe integers, and rejects unknown fields.
- Artifact URLs must be HTTPS without credentials or fragments. Size and
  lowercase SHA-256 are signed and bounded.
- A durable checkpoint accepts a higher sequence or a byte-identical replay.
  Lower sequences and different manifests at the same sequence fail closed.
- A signed emergency rollback release may bypass ring/rollout holds, but never
  signature, monotonic sequence, platform, architecture, or validity time.
- Local rollback and diagnostics are invariant capabilities. No wire field or
  update state can disable either one.

## Integration order

1. Fetch bytes outside this crate with normal transport hardening and limits.
2. Call `SignedUpdateManifest::import_and_verify` with the provisioned key.
3. Evaluate platform, architecture, time, ring, and deterministic rollout.
4. Call `admit_update` and atomically persist its `next_checkpoint`.
5. Download to ordinary temporary storage outside this crate. Hash the entire
   artifact and provide `CompletedArtifactEvidence`.
6. Call `UpdateState::plan_stage`. It selects only the inactive slot and refuses
   a size or digest mismatch.
7. The platform layer may execute the returned plan under its own reviewed,
   privileged boundary. Re-hash the staged target before `confirm_staged`.
8. Persist every pure transition before changing boot selection. Arm pending
   boot, consume bounded attempts, then call `mark_good`; explicit failure or
   attempt exhaustion selects the known-good rollback slot.

The application must persist canonical checkpoint and state documents using an
atomic replace/durable database transaction. An update executor must never be
given general shell authority. Diagnostics continue from either slot, and
`plan_local_rollback` remains available without network, entitlement, Fleet
policy, or a new manifest.

## Offline release issuance

`kernaid-update-issuer` keeps the Ed25519 release seed outside Fleet and emits
only canonical signed manifests. It refuses symlinked inputs, non-canonical
content, existing outputs and signing seeds readable by group or other users.

```sh
cargo run -p kernaid-update-client --bin kernaid-update-issuer -- \
  generate-key /private/update.seed /private/update.public

cargo run -p kernaid-update-client --bin kernaid-update-issuer -- \
  sign-manifest /private/update.seed manifest-content.canonical.json \
  manifest.signed.json
```

The content document has the same fields as a signed manifest except
`signature`; it must include schema `dev.kernaid.update.manifest.v1`. The
public-key file is the unpadded base64url trust anchor provisioned to devices.
The issuer creates private seeds as mode `0600`, never overwrites any output
and does not contact the control plane or an artifact server.

## Focused verification

```sh
cargo fmt --check
cargo clippy -p kernaid-update-client --all-targets -- -D warnings
cargo test -p kernaid-update-client
```
