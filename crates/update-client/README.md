# KernAid signed A/B update client v1

`kernaid-update-client` is the device-side verification and planning boundary
for KernAid updates. It performs no HTTP requests and never changes a
bootloader. Its staging layer can write only to a destination already opened
and identified as inactive by trusted platform code; manifests cannot supply a
destination path or slot.

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
- `ArtifactStager` accepts only an `AdmittedUpdate`, requires the current
  entitlement `Updates` capability, and re-evaluates the effective update ring
  so Fleet `Hold` fails closed for ordinary releases.
- Before changing destination bytes, the stager durably records a canonical
  intent. It streams exactly the signed size, requires EOF, hashes SHA-256,
  syncs the inactive destination, and atomically publishes a receipt. A crash
  can therefore leave only an interrupted checkpoint, never boot authority.

## Integration order

1. Fetch bytes outside this crate with normal transport hardening and limits.
2. Call `SignedUpdateManifest::import_and_verify` with the provisioned key.
3. Evaluate platform, architecture, time, ring, and deterministic rollout.
4. Call `admit_update` and atomically persist its `next_checkpoint`.
5. Open the inactive destination in trusted platform code. Construct
   `PreopenedInactiveTarget`; selecting the active slot is rejected and no
   manifest field participates in destination selection.
6. Call `ArtifactStager::stage` with the admitted update, effective
   `UpdateContext`, current entitlement `Updates` boolean, and a streaming
   reader supplied by transport code. No generic network client is included.
7. Persist/use the returned `StagingReceipt` with `plan_staged_update`. It binds
   release, manifest, artifact, active slot and inactive target, and repeats
   entitlement/ring validation before producing the existing `StagePlan`.
8. Persist every pure transition before changing boot selection. Arm pending
   boot, consume bounded attempts, then call `mark_good`; explicit failure or
   attempt exhaustion selects the known-good rollback slot.

`ArtifactStager::recovery_status` returns `Interrupted` after a crash or failed
stream. Regular-file test/image targets are truncated and synced on failure;
non-truncatable inactive block targets remain unusable because no receipt is
published. Only an exact retry may replace that residue. A completed receipt
is retained until the boot planner has durably consumed it and calls
`clear_completed`. Product integration must hold its per-device update lock
while using the stager and keep its state directory private.

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
