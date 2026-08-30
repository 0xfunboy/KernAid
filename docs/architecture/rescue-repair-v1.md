# Rescue Linux repair v1

Status: **implemented, off-default private candidate; unavailable through the
product site/Release Channel, unqualified and not promoted**. The last
documented terminal exact-image run passed BIOS/UEFI boot and apply in QEMU,
but failed the UEFI post-commit rollback gate. A later requalification run is
tracked separately and creates no qualification claim until its complete
terminal evidence is reviewed. The default/stable image remains diagnosis-only.
This document describes the gated candidate implementation, not a claim that a
shipping image can repair a customer filesystem.

The last documented terminal candidate was built from
[`64db3bcf4050df01e96e1b55e08750b6957df801`](https://github.com/0xfunboy/KernAid/commit/64db3bcf4050df01e96e1b55e08750b6957df801)
by [repair run 33306646523, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306646523).
That run is terminal failure: the formal candidate ISO publish step was
skipped, while a one-day Actions forensics artifact retained ISO and checksum
only for CI investigation. Nothing was promoted to the product site or Release
Channel. Requalification [run 33334118587](https://github.com/0xfunboy/KernAid/actions/runs/33334118587)
is separate; this document intentionally makes no claim about its outcome
until its terminal evidence is reviewed. The current immutable
`0.1.0-internal.6` stable Rescue release comes from commit
[`5db47001fad2a3814d90837bcdcea545b2da0fa9`](https://github.com/0xfunboy/KernAid/commit/5db47001fad2a3814d90837bcdcea545b2da0fa9),
was built with repair disabled and remains diagnosis-only.

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

## Exact-image evidence

Run `33306646523` built and checksum-verified one private image, then passed
ordinary QEMU boot smoke under BIOS and UEFI. The same run passed
`linux.fstab.disable-missing-uuid.v1` apply under both BIOS and UEFI on
disposable direct-leaf ext4 fixtures with a distinct LUKS2/ext4 Vault. It
verified the exact expected-after bytes, terminal `committed`, unchanged
unrelated sentinel and immutable ISO prefix.

The next gate, UEFI post-commit rollback, failed at the fixed sanitized marker
`repair-rollback-service-ready`. The subsequent restart-reconciliation gate was
skipped. Because the workflow failed, its formal ISO publish step was skipped;
only a temporary Actions forensics artifact retained ISO and checksum. There is
no promoted product download or release digest to trust. The successful
boot/apply steps do not qualify rollback, restart reconciliation, injected
faults, automatic restore, process interruption, destructive power loss,
physical media/hardware/firmware, Secure Boot, customer data or production use.

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
persist/read back backup -> target recheck
        |
separate root helper consumes Vault lease and returns one detached RW mount
        |
atomic edit -> validation
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
off-default v1alpha2 read-only target handoff performs three matching fresh
resolutions and transfers exactly four descriptors over a fixed root-owned
`SOCK_SEQPACKET` endpoint: a read-only leaf FD, an `O_PATH` physical-parent
identity FD, a sealed bounded UUID-inventory memfd and an unattached
`ro,noload` ext4 mount. A strict Rust client validates the complete four-FD
bundle. The observer and physical-parent guard consume those capabilities and
do not open `/dev` or `/sys`.

Write authority crosses a different root-owned, socket-activated
`SOCK_SEQPACKET` endpoint. The unprivileged daemon can request it only for one
already durable Pending transaction, using its opaque reservation ID and exact
transaction binding. The write helper first consumes that transaction's
boot-scoped, single-use Vault lease, obtains its approval-bound stable recovery
fingerprint, resolves the target three times from fresh current-boot state,
creates one detached read-write ext4 mount, closes its raw leaf and parent FDs
and transfers only the mount FD. Once the request has been sent, every failure
is treated as ambiguous lease consumption and requires reconciliation; it is
never retried or converted into cancellation authority.

A dedicated system account and hardened static unit files are packaged for
qualification. The feature-gated Vault daemon resolves and allowlists only
that exact private account. `repaird` runs with `PrivateDevices=yes` and a
closed device policy, with no `DeviceAllow` and no `CAP_SYS_ADMIN`; the executor
no longer creates a mount or receives a raw block device. The candidate image
also adds a persistent unprivileged repair daemon, strict local
`SOCK_SEQPACKET` control plane, bounded single-authority state machine and
dedicated UI group. Its executor persists and reads back the Vault backup
before acquiring the single write-mount capability, uses an atomic exchange,
verifies exact bytes and metadata, and restores automatically on failure.
These components are absent from the default/stable image.

On startup the candidate daemon treats recovery as a readiness barrier. It
queries the single unresolved transaction and authenticates the live Vault
identity and physical parent. Post-reboot target reacquisition uses only the
approval-bound stable recovery fingerprint: the read-only helper resolves it
three times from fresh current-boot discovery and transfers a newly validated
four-FD bundle. The daemon classifies the resource as exact `Before`, exact
`After` or a third state. `Before` closes unchanged; for `After`, the separate
write helper consumes the current boot's lease and independently repeats the
stable-fingerprint triple resolution before returning the one RW mount used to
restore the authenticated backup. A third or ambiguous state becomes manual
without any overwrite.

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
boot epoch. Only the separate write root helper consumes it, before resolving
devices or creating the detached RW mount. The lease is boot-scoped and
single-use; it does not make a durable reservation or backup into reusable
write authority after reboot.

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
8. Drop the read-only target bundle, then use the separate root-helper socket
   to consume the single-use Vault lease, resolve the stable recovery
   fingerprint three times from fresh current-boot state and receive only one
   detached read-write mount FD.
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
- an exact image passes BIOS/UEFI repair plus rollback, restart reconciliation
  and failure-path qualification in one complete run; and
- physical USB testing proves separate-device backup and power-loss recovery
  on the supported hardware matrix;
- Secure Boot is qualified for the exact promoted image.

The exact-image failure-path gate is one UEFI suite over disposable Rescue and
target images derived from one freshly provisioned base. It must independently
prove all of the following before emitting its single ISO-bound attestation:

- a stale target claim fails before a transaction or target write exists;
- cancelling the exact prepared plan releases its reservation and performs no
  target write;
- changing the authenticated backup offline makes rollback preparation fail
  closed while the committed target remains byte- and metadata-exact `After`;
- terminating only `kernaid-rescue-repaird` after durable `Pending`, with QEMU
  and the helpers still running, starts a different daemon PID and reconciles
  to `closed-before-unchanged` without a target write; and
- an injected failure after durable, exact `After` traverses the production
  automatic-restore path and ends specifically at `closed-before-restored`,
  with exact `Before` bytes and metadata.

The two injected boundaries accept only fixed tokens from the candidate-only
`kernaid-repair-fault` systemd credential. PID 1 loads it only
from the fixed root-only QEMU fw_cfg sysfs node, otherwise supplying the fixed
non-fault default; the daemon rejects unknown credentials and has no
environment, HTTP or command-controlled fault mode.
The stable image contains neither the candidate daemon nor this credential
surface. The existing whole-VM power-cut test remains a separate reconciliation
gate and cannot substitute for process-only termination or deterministic
automatic restore.

In particular, Phase 0 remains diagnosis-only under `AGENTS.md`. A production
handler cannot become shipping merely by enabling this candidate feature.
Promotion requires the remaining QEMU rollback/restart/failure-path,
destructive power-loss, physical and Secure Boot qualification gates, an
explicit policy/release decision and an exact candidate-image promotion.
