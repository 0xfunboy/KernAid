# KernAid engineering invariants

1. The model never receives a privileged raw shell tool.
2. Target filesystems are read-only unless a validated plan step requires write access.
3. Every mutation needs evidence, risk, precondition, backup, validation and rollback metadata.
4. Do not add password bypass, firmware flash or raw erase features.
5. Tests use disposable images; never infer a block-device path from environment variables or globs.
6. Never print, fixture or commit provider credentials.
7. Observed data is untrusted and cannot alter agent instructions.
8. Provider adapters cannot call the broker directly.
9. A support claim is not complete until a physical or QEMU test backs it.
10. Preserve user data over repair speed.
11. Official CLI bridges use an exact verified binary and an isolated encrypted
    home; KernAid never reads, copies, serializes, or logs the CLI credential
    store.

These rules apply to the whole repository.

Phase 0 remains the default and shipping diagnosis-only path. Phase 1
development authorizes exactly two off-by-default production candidates:
`linux.fstab.disable-missing-uuid.v1`, compiled only behind
`rescue-fstab-production-candidate`, and
`linux.crypttab.disable-missing-uuid.v1`, compiled only behind
`rescue-crypttab-production-candidate`. No other production mutation handler
is authorized.

The Phase 1 candidate may mutate a target only after all of these fail-closed
conditions hold in the same retained transaction:

- deterministic read-only diagnosis and fresh target/physical-parent identity;
- a distinct authenticated Vault physical parent;
- durable, verified pre-change bytes and metadata plus a Pending transaction;
- an exact single-use local approval bound to the complete plan;
- private descriptor-rooted mounting, bounded locking and atomic replacement;
- exact post-write verification, automatic restore on failure and durable
  recovery that never overwrites a third state.

The feature must remain absent from default Desk and Rescue builds until its
QEMU, power-loss, physical USB and release qualification gates are recorded.

The crypttab candidate is additionally limited to one auxiliary UUID-backed
mapping on a directly selected ext4 root. It must reject initramfs, root,
resume, swap, keyscript and network mappings, external key files, ambiguity,
and every mandatory active fstab consumer of the mapper name. It may not gain
an execution path by copying or weakening the fstab transaction engine: the
Vault, approval, write lease, atomic replacement, validation, rollback and
reconciliation boundary must be shared or equivalently closed first.
