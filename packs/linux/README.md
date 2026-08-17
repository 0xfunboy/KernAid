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
- binds execution to an opaque preview precondition covering the exact target
  file, its bytes, mode, uid, and gid; a content-only fingerprint is exposed
  separately for receipts and comparison;
- fails closed before mutation when any extended attribute is present or
  cannot be inspected. This includes unsupported POSIX ACL, SELinux label,
  file-capability, and user-xattr metadata;
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
  receipt; rollback first requires the current bytes to match the receipt's
  post-repair fingerprint and an opaque precondition to match the exact
  installed file plus its mode/uid/gid, so an external edit or same-content
  replacement is never overwritten.

Tests cover injected post-install validation failure with automatic rollback,
symlink rejection, stale targets, concurrent locks, backup tampering,
mode/uid/gid preservation, metadata-bound previews, unsupported xattrs,
post-repair byte and mode changes, same-content target replacement, malformed
grammar, and backups placed inside the target. Temporary files are created
exclusively and removed only when their device/inode identity still matches
the file created by this transaction.

## P0 read-only diagnostics

`diagnostics` is independent from the fixture repair transaction. It accepts
only caller-supplied byte slices and cannot execute commands, open host files,
or mutate state. The `linux-p0.2` corpus requires nine separately identified
evidence documents:

- `lsblk --json` data with `name`, `type`, `uuid`, `ro`, `mountpoint(s)`, and
  optional nested `children`;
- `findmnt --json --list --options ro --output TARGET,FSTYPE` data used to
  distinguish the VFS mount state from a block device's hardware RO flag;
- plain `systemctl --failed --no-legend --plain` rows;
- `systemctl show`-style `key=value` unit/manager state, with blank lines
  between records;
- a normalized `fstab` projection containing only UUID and `nofail` state,
  compared with UUIDs from the bound `lsblk` evidence;
- C-locale, byte-valued `df` rows (`Filesystem ... Used Available Use% Mounted
  on`);
- `ip -json link` data;
- `ip -json route` data; and
- `dpkg --audit` output, where empty output is healthy and non-empty output is
  treated only as an interrupted/incomplete-state signal.

These strings document the upstream collector contract; this crate does not
run them. Inputs are byte-, line-, string-, and record-bounded. Evidence IDs
are validated and must be unique. A malformed or partial source fails the
whole evaluation instead of producing a misleading healthy report.

Findings contain a schema version, stable rule ID/version, severity, exact
evidence bindings, a fixed summary, and a fixed next-collector identifier.
Untrusted descriptions, comments, package text, interface aliases, and unknown
JSON fields are never copied into a finding. Record order is canonicalized so
equivalent evidence produces byte-equivalent report data.

`fixtures/diagnostics` contains a fully synthetic, secret-free healthy set and
incident/adversarial fixtures for duplicate UUIDs, read-only root storage,
failed/degraded systemd, missing `fstab` UUIDs, exhausted filesystems, down
links, absent/misdirected routes, interrupted `dpkg`, malformed JSON, control
characters, and prompt-injection strings.
