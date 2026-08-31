# Linux filesystem health v1

KernAid exposes one read-only filesystem health engine through
`kernaid-linux-filesystem-health`. It has two closed entry points: no arguments
checks the running Linux root for Resident; the trusted Rescue helper supplies
`--selected <disk-N[/volume-N]> <ext4|ntfs> <major:minor>` after resolving and
revalidating the selected target. The browser, provider, and report cannot
supply a host path or command.

The engine resolves exactly one top-level `/dev` block node matching the bound
kernel device number, opens it read-only with no-follow semantics, and
revalidates the descriptor. Selected Rescue targets must be unmounted. It then
invokes only one fixed command against the inherited descriptor:

- `/usr/sbin/e2fsck -f -n` for ext4; or
- `/usr/bin/ntfsfix -n` for NTFS.

No mount, journal replay, repair flag, shell, or caller-controlled option is
available. Each process has a 30-second timeout and bounded stdout/stderr
drains; raw output is discarded. The canonical result contains only the
normalized target reference, filesystem family, check mode, mounted flag, one
of `healthy`, `degraded`, `repair-required`, or `unsupported`, and an optional
fixed finding. It cannot contain paths, file names, user content, or raw tool
text. The stable product has no filesystem write executor. A separate private,
off-default ext4 candidate is documented in
[Rescue ext4 repair v1](rescue-ext4-repair-v1.md).

The privileged Rescue helper reacquires and compares the selected target both
before and after execution. Its HTTP route returns only the validated canonical
document. Desk includes that observation in local diagnosis and reports, but
does not send it to an OpenAI provider; any provider proposal is augmented
locally with the deterministic finding. A repair-required result recommends a
backup and an explicit OS-native repair workflow in every stable build.

The Rescue build stages the same verified binary used by Resident and includes
`e2fsprogs` and `ntfs-3g`. The ready gate requires a valid normalized live-root
observation. Physical media/filesystem compatibility remains a separate
qualification gate.
