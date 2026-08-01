# Linux pack

`kernaid-linux-inventory` is restricted to directory fixtures and emits names,
sizes, and readonly permission state. It does not read file contents or mutate
the target. Host hardware collectors will be added as separate typed
collectors after sandboxing and redaction tests exist.

The library contains a deliberately isolated R2 repair transaction for one
known missing-device `fstab` entry. It is **fixture-only**: the exact
`.kernaid-disposable-fixture` marker is mandatory, and the code is not wired to
Tauri, Rescue, the broker, or real disks.

The transaction:

- parses the documented Linux `fstab` grammar (four required fields, two
  optional numeric fields, comments, blank lines, and octal field escapes);
- rejects malformed or ambiguous input before creating a backup;
- opens the fixture, `etc`, `fstab`, backup, lock, and temporary files relative
  to held directory descriptors with no-follow semantics;
- holds a nonblocking advisory lock on a persistent, no-follow, mode-`0600`
  regular file in the target `etc` directory, so the same `fstab` is serialized
  even when callers choose different backup directories; the lock file is
  never unlinked and the descriptor/name identity is rechecked;
- rechecks target bytes plus device/inode identity immediately before the
  atomic exchange;
- writes and fsyncs a byte-verified backup outside the target;
- preserves and verifies mode, uid, and gid on the replacement before the
  target is changed. If ownership cannot be set safely, the operation fails
  closed before target mutation;
- installs with an atomic `RENAME_EXCHANGE`, validates syntax, bytes, metadata,
  and target identity, then fsyncs file and directory boundaries;
- automatically exchanges the original file back after every post-install
  failure and returns a structured rollback receipt; and
- supports an explicit, structured, byte-verified rollback using the repair
  receipt.

Tests cover injected post-install validation failure with automatic rollback,
symlink rejection, stale targets, concurrent locks, backup tampering,
mode/uid/gid preservation, malformed grammar, and backups placed inside the
target. Temporary files are created exclusively and removed only when their
device/inode identity still matches the file created by this transaction.
