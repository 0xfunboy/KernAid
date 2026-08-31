# Rescue crypttab repair v1

Status: **off-default read-only preflight and Core approval implemented; no
execution, packaging, UI or support claim**.

The candidate action is `linux.crypttab.disable-missing-uuid.v1` (R2). It
addresses one stale auxiliary encrypted-volume entry that can hold boot while
its UUID is absent. The action remains a one-file transaction: if the mapper
has any active mandatory fstab consumer, preflight fails closed rather than
leaving the machine with a partially repaired boot configuration.

## Closed scope

- directly selected, simple ext4 installed root only;
- exactly one active `UUID=` crypttab entry proven absent by the sealed block
  inventory;
- key source absent, `none` or `-` only;
- no `nofail` or `noauto` entry (already non-blocking);
- no root, initramfs, resume, swap, keyscript, network, token/header or
  externally keyed mapping;
- no mandatory `/dev/mapper/<name>` or `dm-name-<name>` fstab consumer;
- no path, action, mapper name, UUID, replacement bytes, key field or command
  supplied by the UI/provider protocol.

The pure pack derives exact before, after, diff, UUID-set and fstab-consumer
hashes. The broker reads `etc/crypttab` and `etc/fstab` with descriptor-rooted
`openat2`, no symlinks, bounded regular files, root-owned supported metadata
and no xattrs. It uses the existing root-issued bundle containing the selected
read-only leaf, physical-parent identity, sealed UUID inventory and detached
read-only ext4 mount, and revalidates the bundle before and after observation.
Policy admits only the exact one-step R2 plan. Core binds a one-use local
approval to the complete plan hash, target fingerprint and before hash.

## Remaining execution gate

No code in this feature can write. Before enabling packaging, the existing
fstab transaction engine must be generalized without accepting a caller path
or arbitrary action. The crypttab action then needs all of the same retained
proofs: durable byte-exact backup on an authenticated distinct Vault physical
parent, Pending journal state, consumed boot-local write lease, detached RW
mount, atomic exchange of only `etc/crypttab`, exact parse/byte/metadata
validation, automatic restore, fresh separately approved rollback and
Before/After/Third-state reboot reconciliation. QEMU failure injection,
power-loss and physical two-device qualification remain mandatory.
