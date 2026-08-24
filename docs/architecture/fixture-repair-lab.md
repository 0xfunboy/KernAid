# Fixture repair lab boundary

`fixture-repair-lab` is an opt-in Rust feature for demonstrating one complete,
reversible Linux repair against a checked disposable fixture. It is absent from
normal builds and Rescue. The Linux-only Desk lab connects the existing broker
to a closed Tauri command set and a dedicated TypeScript driver; it cannot use
Desk target selection, providers, a caller-supplied path, or production disks.
The standard Phase 0 session and production invoke handler remain
diagnosis-only.

The feature build creates its target, backup directory, authenticated journal
and ephemeral signing identity inside an application-owned temporary directory.
Its status exposes only typed IDs, declarations and `sha256:` values. The webview
can request the five fixed transitions `status`, `stage`, `execute`,
`stage rollback` and `execute rollback`. Two read-only reconciliation calls can
reissue an already committed in-memory receipt if IPC fails after completion;
they never retry a mutation. Native IPC accepts no action selector, path,
command, environment, replacement bytes or arbitrary JSON operation.

## Closed transaction

The broker accepts only typed session/plan/action IDs, the pinned finding
`KA-LNX-P0-003` version 2, a diagnosis SHA-256, and canonical evidence
ID/SHA-256 bindings. The trusted local `FixtureRepairConfig` owns the fixture
and backup directories; it is neither serializable nor path-revealing. No
untrusted repair/rollback request or signed report field accepts or reveals a
filesystem path, command, shell fragment, replacement content, or raw JSON
action input. Trusted local setup supplies the two fixture-only directories.

The repair plan hash binds the diagnosis, finding, evidence, R2 risk, resource,
target precondition, before/after hashes, diff hash, logical backup locator,
validation, and rollback declarations. A monotonic approval is consumed only
when the encrypted journal has durably recorded intent. The pack then creates
and byte-verifies a separate backup, atomically installs the pinned repair, and
validates the result. Any failure after intent writes a recovery record when
possible and permanently blocks later mutation on that journal.

Rollback is a second staged R2 plan and a second monotonic approval. The broker
reconstructs the pack receipt and physical backup path only from the
authenticated repair completion plus local configuration. A read-only
preflight verifies the installed file and backup before rollback intent. The
completion is a strict, device-signed cycle report bound to the exact journal
head. It contains only IDs, declarations, hashes, supported metadata, and a
deterministic logical backup locator.

## Threat model and limits

The boundary rejects stale/replaced targets, symlinks, unsupported metadata,
backup collisions or tampering, approval replay/non-monotonicity, malformed or
extra report/event fields, foreign device journals, and interrupted repair or
rollback intents. Observed bytes remain untrusted and never become commands.

This lab does not authorize production mutation. It does not accept arbitrary
fstab entries, targets, commands, devices, or recovery overrides through its
untrusted request/report boundary, and those surfaces carry no filesystem
paths. The fixture marker, target entry, action/resource IDs, diagnosis rule,
validation, and rollback are compile-time pinned. A physical or QEMU support
claim remains outside this fixture-only tranche.

Evidence bindings are serialized in strictly increasing ID order. The Rust
verifier requires IDs to be semantically unique even if two entries have
different hashes; the schema's `uniqueItems` also rejects byte-equivalent
duplicate bindings.

## Verification

Launch the interactive Linux lab with:

```sh
just run-desk-fixture
```

The visible cycle requires one typed approval for the R2 repair and a different,
later typed approval for rollback. Desk re-runs the deterministic diagnosis
after each operation: `KA-LNX-P0-003` disappears after repair, then reappears
only after the original bytes have been restored.

With the repository's pinned Rust toolchain and a system C linker available:

```sh
cargo test --locked -p kernaid-linux-pack --features fixture-repair-lab

cargo test --locked -p kernaid-broker --features fixture-repair-lab \
  coherent_fixture_runs_diagnosis_repair_verify_rollback_and_signed_report
```

Shipping-negative checks use the same commands without `--features` and verify
with `cargo tree -e normal` that the default broker does not depend on the Linux
pack or storage transaction implementation.
