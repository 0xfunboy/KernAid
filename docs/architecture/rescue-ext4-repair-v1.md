# Rescue ext4 repair v1

`linux.ext4.fsck-preen-with-undo.v1` is a private, off-default R3 action for one
explicitly selected, unmounted ext4 target. It is compiled only with
`rescue-ext4-fsck-production-candidate`, which composes the existing Rescue
repair transaction engine. Stable Rescue and Resident remain diagnosis-only.

The browser sends no path, device name, option, command, or content. The broker
reacquires the selected descriptor-bound target, repeats fixed
`e2fsck -f -n`, and admits the action only for `repair-required`. It stores a
minimal path-free preflight evidence object in the authenticated, physically
distinct Repair Vault and makes the transaction durably Pending before the
single-use write lease can be consumed. Approval sequence 1 is bound to the
target, plan, action and exact phrase `REPAIR EXT4 OFFLINE`.

The root-owned write helper consumes that lease, resolves the recovery target
three times, rejects any mounted target or identity drift, and retains all raw
block authority. The unprivileged broker never receives a block descriptor.
The helper runs only these fixed, environment-cleared commands with discarded
output and hard deadlines:

- preflight and postcondition: `e2fsck -f -n`;
- apply: `e2fsck -f -p -z <same-boot-undo> <bound-device>`;
- controlled failure restore: `e2undo -f <same-boot-undo> <bound-device>`.

Only a normalized result crosses back to the broker. A clean read-only
postcheck commits the transaction. If apply is not qualified, KernAid attempts
e2undo and reports `closed-before-restored` only when the prior
`repair-required` diagnostic class is observed again. It does not claim a
byte-perfect filesystem image comparison.

The undo stream is root-only under `/run/lock/kernaid-repair` and exists only
for the current Rescue boot. Upstream e2fsprogs explicitly does not make this
mechanism safe across a power or system crash. Therefore an unsuccessful undo,
lost reply, repaird restart, helper termination, reboot, or other ambiguous
Pending state becomes `manual-reconciliation-required`: KernAid never retries
the mutation automatically and exposes no post-commit rollback button. The
Vault object is evidence, not a full-filesystem backup. Users must preserve
recoverable data separately before this candidate can be considered for use.

This vertical slice is implemented but not promoted or physically qualified.
Promotion requires exact-image VM fault tests plus disposable-device coverage
for clean commit, controlled same-boot restore, timeout, helper termination,
power-loss ambiguity, large filesystems, and representative storage bridges.
