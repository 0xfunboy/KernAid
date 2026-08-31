# Rescue crypttab repair v1

Status: **implemented as an off-default private candidate; unqualified and not
promoted**. This is an engineering contract for disposable qualification, not
a claim that a public KernAid image can modify customer systems.

## Closed action

`linux.crypttab.disable-missing-uuid.v1` is the only crypttab mutation. It is
an R2 Rescue action for `KA-LNX-P0-012` and comments exactly one auxiliary
UUID-backed mapping whose UUID is absent from the fresh descriptor-bound block
inventory. No client supplies a path, mapper name, action, command, backup, or
replacement bytes.

The candidate accepts only a directly selected ext4 root and a regular,
root-owned `/etc/crypttab` with mode `0600` or `0644`, no xattrs or POSIX ACL,
and one hard link. It rejects malformed or ambiguous input, root/cryptroot,
swap, resume, initramfs, network and keyscript mappings, external key files,
unsupported options, multiple eligible entries, and any mandatory active
`fstab` consumer of the mapper name. That consumer check is mandatory and
fails closed; the repair is never admitted merely because the crypttab UUID is
missing.

## Transaction boundary

The action reuses the fstab repair transaction engine through a closed
`RepairResourceV1` enum. The resource selects a compiled leaf name, action,
Vault capability, lock domain, metadata policy, write lease, and rollback
lease. A request cannot cross-bind fstab and crypttab contracts.

The end-to-end sequence is:

1. reacquire and revalidate the selected descriptor-only target capability;
2. observe exact crypttab bytes and metadata, fstab bytes, and UUID inventory;
3. derive the one-entry preview, hashes, evidence, and immutable Core plan;
4. reserve authenticated Vault capacity on a distinct physical parent;
5. expose only a path-free prepared descriptor and require the exact
   `DISABILITA VOCE CRYPTTAB` single-use approval;
6. persist and read back the byte-exact backup plus metadata and durable
   `Pending` transaction before requesting write authority;
7. consume the exact crypttab write lease through the fixed root helper;
8. atomically exchange `/etc/crypttab`, preserve supported metadata, fsync,
   reread, byte-verify, and record the terminal state;
9. automatically restore the authenticated backup on a failed apply, or
   reconcile an interrupted `Pending` transaction on daemon restart without
   overwriting a third state.

Crypttab backup and transaction records use their own action/resource and
capability bindings. They share the authenticated Vault implementation and
atomic/reconciliation code with fstab rather than creating a second mutation
engine. Raw shell execution is not part of this path.

## Product and build gate

The slice compiles only with
`rescue-crypttab-production-candidate`, which composes the existing fstab
transaction engine. Default Desk, broker, Rescue, and stable release builds do
not enable it. The private repair-candidate workflow enables both feature
flags so the same isolated image can qualify both closed actions.

The local repair service accepts only these additional operations:

- `repair.crypttab.prepare`
- `repair.crypttab.approve`
- `repair.crypttab.cancel`

The Desk repair panel can prepare either candidate and renders the exact
action/resource/confirmation returned by the local service. It never receives
target paths, configuration bytes, Vault authority, or a generic execution
primitive.

## Deliberate remaining gate

Automatic restore during a failed apply and startup reconciliation are
implemented. A separate user-initiated **post-commit crypttab rollback** is
not exposed through Core, the local service, or Desk in this version. The
protocol/Vault/root leaf already keep crypttab rollback authority distinct, but
shipping that user flow requires its own Core admission, source-receipt API,
UI confirmation, and exact-image rollback qualification. Desk therefore does
not offer the existing fstab rollback action for a crypttab receipt.

Before promotion, one exact image still must pass crypttab apply, automatic
restore, daemon interruption/restart reconciliation, cross-contract rejection,
BIOS/UEFI, and physical USB/power-loss qualification with the Vault on a
different physical device. Until that evidence exists, the action remains a
private off-default candidate.
