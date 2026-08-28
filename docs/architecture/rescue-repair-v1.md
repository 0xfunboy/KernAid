# Rescue Linux repair v1

Status: **disabled production candidate**. This document defines the safety
boundary being implemented; it is not a claim that a shipping image can yet
repair a customer filesystem.

## First supported action

`linux.fstab.disable-missing-uuid.v1` is an R2 Rescue-only action for one
deterministically diagnosed `KA-LNX-P0-003` finding. It may comment exactly one
mandatory `UUID=` entry whose UUID is absent from the freshly observed block
inventory, whose filesystem is `ext4`, and whose mount point is below `/mnt/`,
`/media/` or `/srv/`.

The action rejects malformed or ambiguous `fstab` data, missing critical
mounts, swap, bind and network entries, optional `nofail`/`noauto` entries and
other filesystem types or every mount point outside that data-only allowlist.
Provider output cannot
select the entry, path, command or replacement bytes.

## Trust boundaries

```text
read-only target scan
        |
deterministic finding + evidence hashes
        |
Core creates one typed R2 plan
        |
local user sees exact diff, target and vault backup destination
        |
separate approval
        |
root broker resolves the same opaque target and vault capabilities
        |
backup -> target recheck -> atomic edit -> validation -> receipt
```

The UI carries typed IDs, hashes, plan identity and approval identity. It never
carries a block-device path, mount path, shell command or replacement file.
The model remains outside the broker boundary.

The privileged broker must resolve the selected Rescue target internally from
the existing target ID and scan fingerprint, repeat discovery immediately
before any write and retain descriptors across every identity checkpoint. The
first version accepts only a simple, clean, directly mounted ext4 target. More
complex storage remains read-only.

The feature-gated Rust candidate now includes a pure immutable transaction-plan
binding for the preview hashes, selected-target scan identity, target physical
parent, authenticated boot-Vault identity, Vault physical parent, opaque backup
locator, durable reservation ID/binding, reserved capacity and the two
canonical diagnostic evidence hashes. A free-space observation alone is not a
backup capability. The plan also binds
its risk, safety declarations, timeout, cancellation, idempotency and redaction
policy. It rejects equal physical parents, insufficient Vault capacity and
path-like capability IDs. Core and policy expose a separate, feature-gated,
single-use approval transition bound to session, plan hash, target fingerprint
and `fstab` snapshot. The broker crate has a feature-gated, path-free preflight
boundary that consumes that non-cloneable admission, acquires an opaque
read-only target lock, retains the exact Vault reservation guard, asks a
trusted resolver for observations and rebuilds the preview and transaction
plan. Its `ready-read-only` receipt is audit evidence only: it is never
execution authority and cannot replace the non-cloneable prepared object that
holds the admission and both guards.

The off-default `experimental-repair-store` implementation now provides a
separate encrypted Repair Vault namespace and a closed
Reserve/Persist/Status/Get/Cancel/Retire daemon protocol for the exact backup
capability. It reserves physical blocks, accepts bytes only through anonymous
pipes, verifies exact size, EOF, SHA-256, allocation and named readback,
journals crash boundaries, and keeps durable identity stable across reboot
while treating the kernel physical-parent claim as live authority for
reserve-to-persist. The default daemon ABI remains unchanged. The separate
off-default target handoff resolves the selection twice and transfers one
read-only block FD over a fixed root-owned `SOCK_SEQPACKET` endpoint to a
strict Rust client. A dedicated system account and hardened static unit files
are packaged for qualification, but Vault does not allowlist that UID and no
socket, broker process or combined FD-and-lock resolver is enabled. Both routes
therefore remain unreachable in the shipping image. A mutation handler still
does not exist.

## Backup boundary

The pre-change `fstab` bytes and supported metadata must be written to the
unlocked KernAid vault before the target becomes writable. The receipt exposes
only a logical locator such as `vault://repair/<receipt-id>` and hashes; it does
not expose a host path.

The broker must prove through kernel block ancestry that the vault's physical
parent differs from the target's physical parent. An unavailable or locked
vault, insufficient space, ambiguous ancestry, identity drift or failed
read-back blocks the repair.

The implemented candidate persists only path-free IDs and hashes. Its stable
Vault identity is derived from the authenticated LUKS UUID and provisioned
device-identity public key; boot-local mount IDs, device-mapper numbers and
disk sequence remain live attestations rather than durable identity. Recovery
authenticates the stable identity before it may reconcile an interrupted
journal intent. Durable backups can therefore be verified after a reboot,
while a stale reserved write capability cannot be resumed across a changed
physical-parent epoch.

Reserved capacity can be cancelled with the stable reservation ID plus its
exact draft binding without re-minting live-parent write authority. Durable
capacity can be retired only by presenting the complete returned durable
status, including plan, approval and resource binding. Both release paths use
intent/complete journal pairs and recover idempotently after interruption.
Bounded authenticated release tombstones replay the same acknowledgement after
a lost response and reject mismatched or cross-operation retries. The journal
is bounded to 4096 events (at most 16 MiB of event payload); crash-safe
compaction remains a promotion gate rather than being misrepresented as
unbounded retention.

## Required transaction

1. Re-run target discovery and the deterministic diagnosis read-only.
2. Recompute the exact before, UUID-set, proposed-after and diff hashes.
3. Stage one bounded plan and show the escaped local diff.
4. Obtain a fresh R2 approval bound to the complete plan hash.
5. Acquire a root-owned lock for the target/resource pair.
6. Recheck target and vault device identities and fingerprints.
7. Persist and read back the original bytes, metadata and transaction intent
   in the vault.
8. Mount only the selected target privately and read-write for the bounded
   operation.
9. Install the locally derived replacement atomically, then fsync the file and
   containing directory.
10. Parse and byte-verify the installed `fstab`, repeat diagnosis and confirm
    that only the approved entry changed.
11. Unmount normally, rescan the target, close the durable intent and emit a
    signed receipt.

Every failure after the write begins attempts an automatic restore from the
verified backup. An interrupted or ambiguous intent blocks later mutations
until an explicit reconciliation succeeds. Manual rollback requires a second
plan and approval and refuses to overwrite any post-repair external edit.

## Feature and qualification gates

The contract, pure preview, immutable plan and approval boundary compile only
with the off-by-default `rescue-fstab-production-candidate` feature. No normal
Desk build, public
Rescue image or default broker may enable it until all of these are true:

- broker, Core, policy, vault backup and signed-report integration are complete;
- bounded retention and crash-safe journal compaction are complete;
- disposable two-disk QEMU tests cover stale targets, tampered backups,
  cancellation, process termination, automatic restore and reconciliation;
- the exact image passes BIOS and UEFI repair/rollback qualification; and
- physical USB testing proves separate-device backup and power-loss recovery
  on the supported hardware matrix.

In particular, Phase 0 remains diagnosis-only under `AGENTS.md`. A production
handler cannot be added merely by enabling this candidate feature. Promotion
requires a formal phase/policy change plus production target-locator and Vault
backup capabilities, then reuse or generalization of the already exercised
fixture transaction/broker state machine.
