# Rescue Linux repair v1

Status: **implemented, off-default production candidate; not promoted**. The
default/stable image remains diagnosis-only. This document describes the gated
candidate implementation, not a claim that a shipping image can repair a
customer filesystem.

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
broker re-resolves target and observes exact fstab read-only
        |
Vault reserves capacity on a distinct physical parent
        |
broker creates the immutable plan and audit-only prepared receipt
        |
Core stages that exact plan; local user sees target, diff and backup destination
        |
separate approval bound to the complete plan
        |
persist/read back backup -> target recheck -> atomic edit -> validation
        |
durable terminal receipt or automatic restore
```

The prepare UI carries only a request correlation and the selected boot-local
target claims. The daemon derives session/plan IDs, and the broker derives the
action, resource, exact snapshot, evidence hashes, diff and replacement bytes.
Approval later echoes the complete prepared binding. No UI message carries a
block-device path, mount path, shell command or replacement file; the model
remains outside the broker boundary.

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
path-like capability IDs. The broker accepts only request/session/plan IDs and
the selected target claims, acquires an opaque read-only target guard, performs
the detached ext4 observation, and internally derives the preflight intent
before reserving Vault capacity and creating the final plan. Core stages a
canonical `ValidatedPlan` directly from that exact broker evidence—without a
synthetic Linux snapshot—then performs a separate, feature-gated, single-use
approval transition bound to the session, complete plan hash, target
fingerprint and exact `fstab` snapshot.
Its `ready-read-only` receipt is audit evidence only: it is never execution
authority and cannot replace the non-cloneable prepared object retaining both
guards. Every rejection after reservation explicitly cancels it; the approved
authority also supports an explicit pre-execution abort.

The off-default `experimental-repair-store` implementation now provides a
separate encrypted Repair Vault namespace and a closed
Reserve/Persist/Status/Get/Cancel/Retire daemon protocol for the exact backup
capability. It reserves physical blocks, accepts bytes only through anonymous
pipes, verifies exact size, EOF, SHA-256, allocation and named readback,
journals crash boundaries, and keeps durable identity stable across reboot
while treating the kernel physical-parent claim as live authority for
reserve-to-persist. The default daemon ABI remains unchanged. The separate
off-default v1alpha2 target handoff performs three matching fresh resolutions and transfers
a read-only leaf FD, an `O_PATH` physical-parent identity FD, a sealed bounded
UUID-inventory memfd and an unattached `ro,noload` ext4 mount over a fixed
root-owned `SOCK_SEQPACKET` endpoint. A strict Rust client validates the complete
bundle. The observer and physical-parent guard consume those capabilities and
do not open `/dev` or `/sys`. A dedicated system account and hardened static
unit files are packaged for qualification. The feature-gated Vault daemon
resolves and allowlists only that exact private account. The candidate image
now adds a persistent
unprivileged repair daemon, strict local `SOCK_SEQPACKET` control plane, bounded
single-authority state machine and dedicated UI group. Its executor persists
and reads back the Vault backup before acquiring write authority, mounts only
the retained ext4 target privately, uses an atomic exchange, verifies exact
bytes/metadata and restores automatically on failure. These components are
absent from the default/stable image.

On startup the candidate daemon treats recovery as a readiness barrier. It
queries the single unresolved transaction, authenticates the live Vault
identity/physical parent, reacquires the target only by its stable recovery
fingerprint and classifies the resource as exact `Before`, exact `After` or a
third state. `Before` closes unchanged, `After` restores the authenticated
backup, and a third or ambiguous state becomes manual without any overwrite.

Vault and broker candidate builds now share one pure, feature-gated V1 formula
for the physical-parent digest, including raw and `sha256:` renderings. Kernel
observation remains Linux-specific and is not supplied by the wire: the broker
derives it from bounded sysfs observations plus retained read-only leaf and
parent descriptors, and revalidates all three before use.

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

The Vault now atomically consumes one transaction-bound repair write lease per
boot epoch. The lease is boot-scoped and single-use; it does not make a durable
reservation or backup into reusable write authority after reboot.

Reserved capacity can be cancelled with the stable reservation ID plus its
exact draft binding without re-minting live-parent write authority. Durable
capacity can be retired only by presenting the complete returned durable
status, including plan, approval and resource binding. Both release paths use
intent/complete journal pairs and recover idempotently after interruption.
Bounded authenticated release tombstones replay the same acknowledgement after
a lost response and reject mismatched or cross-operation retries. Exact reserve
retries reconcile a lost response to the same live reservation. The journal is
bounded to 4096 events (at most 16 MiB of event payload), compacts automatically
at 3072 events, preserves every active backup and retains at most 64 release
tombstones for a deterministic 512-event window. Its PREPARED/COMMITTED swap is
authenticated, directory-synchronized and recovered across interrupted
generation installs.

## Required transaction

1. Re-run target discovery and the deterministic diagnosis read-only while
   retaining the target descriptor and physical-parent guard.
2. Recompute the exact before, UUID-set, proposed-after and diff hashes.
3. Reserve bounded capacity on an authenticated Vault whose physical parent is
   distinct from the target.
4. Create one immutable plan/receipt containing the exact backup locator and
   show the escaped local diff.
5. Stage that exact plan in Core and obtain a fresh R2 approval bound to its
   complete plan and approval hashes.
6. Recheck the held target and Vault identities and fingerprints.
7. Persist and read back the original bytes, metadata and transaction intent
   in the vault.
8. Mount only the selected target privately and read-write for the bounded
   operation.
9. Install the locally derived replacement atomically, then fsync the file and
   containing directory.
10. Parse and byte-verify the installed `fstab`, repeat diagnosis and confirm
    that only the approved entry changed.
11. Drop the private mount, rescan the target, durably resolve the transaction
    and emit the bounded terminal receipt.

Every failure after the write begins attempts an automatic restore from the
verified backup. An interrupted or ambiguous intent blocks later mutations
until startup reconciliation succeeds or records a manual state. Recovery
never overwrites a post-repair third state.

## Feature and qualification gates

The contract, pure preview, immutable plan and approval boundary compile only
with the off-by-default `rescue-fstab-production-candidate` feature. No normal
Desk build, public
Rescue image or default broker may enable it until all of these are true:

- disposable two-disk QEMU tests cover stale targets, tampered backups,
  cancellation, process termination, automatic restore and reconciliation;
- the exact image passes BIOS and UEFI repair/rollback qualification; and
- physical USB testing proves separate-device backup and power-loss recovery
  on the supported hardware matrix;
- the read-write mount/executor no longer acquires its target directly and is
  migrated to a narrowly typed root-helper capability; only then can the
  repair daemon's still-broad block-device sandbox be closed; and
- Secure Boot is qualified for the exact promoted image.

In particular, Phase 0 remains diagnosis-only under `AGENTS.md`. A production
handler cannot become shipping merely by enabling this candidate feature.
Promotion requires the remaining isolation and physical qualification gates,
an explicit policy/release decision and an exact candidate-image promotion.
