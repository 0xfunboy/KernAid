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

These rules apply to the whole repository. Phase 0 is diagnosis-only: no production mutation handlers.
