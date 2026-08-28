# Linux pack

`kernaid-linux-inventory` is restricted to directory fixtures and emits names,
sizes, and readonly permission state. It does not read file contents or mutate
the target. Host hardware collectors will be added as separate typed
collectors after sandboxing and redaction tests exist.

The library contains a deliberately isolated R2 repair transaction for one
known missing-device `fstab` entry. It is **fixture-only**: the exact
`.kernaid-disposable-fixture` marker is mandatory, and the code is not wired to
Tauri, Rescue, the production broker build, or real disks. An opt-in broker
feature exposes only the typed fixture-lab transaction; default broker builds
do not depend on this pack or its storage mutation implementation.

The separate `action-pack.production-candidate-v1.yaml` describes the first
Rescue-only production candidate, `linux.fstab.disable-missing-uuid.v1`. It is
explicitly `productionCandidateOnly`, disabled by default, and its Rust code is
compiled only with the off-by-default `rescue-fstab-production-candidate`
feature. This is currently a contract plus a pure preview function: there is
no filesystem I/O, broker/UI route, backup implementation, approval path, or
production mutation handler, so it does **not** make the repair available to
users yet.

The candidate can propose commenting only one active, mandatory UUID entry
that is absent from a caller-supplied observed UUID set and mounts below
`/mnt/`, `/media/`, or `/srv/`. It fails closed for malformed input, multiple
targets, critical mount trees (`/`, boot, system directories, home, or swap),
other mount locations, bind mounts, and network filesystems. Its strict JSON
input binds the version-2 `KA-LNX-P0-003` finding and exact before, observed
UUID-set, and proposed-after SHA-256 fingerprints; it accepts no path,
replacement bytes, or command.

The pure preview emits all three contract bindings plus `diffSha256`.
`beforeSha256` and `afterSha256` hash the exact input and proposed byte streams.
For `observedUuidSetSha256`, UUIDs are validated, normalized to lowercase and
sorted lexically; the SHA-256 input is the ASCII domain
`kernaid:linux.fstab.disable-missing-uuid.v1:observed-uuid-set:v1` followed by
a NUL byte, a big-endian `u64` item count, and each UUID as a big-endian `u64`
byte length plus its bytes. `diffSha256` similarly uses the ASCII domain
`kernaid:linux.fstab.disable-missing-uuid.v1:diff:v1` plus NUL, the big-endian
`u64` start/end offsets, and length-framed original/replacement line bytes;
the line terminator is outside both frames. All four values use lowercase
`sha256:<hex>` form.

`action-pack.fixture-v1.yaml` and its JSON input schema pin the single
`linux.fstab.repair-entry.fixture-v1` contract at compile time. That manifest
is explicitly fixture-lab-only and non-production: it is not a claim that the
handler is available through a public broker or UI. Its input can identify
only `fixture:linux-fstab-v1` and distinct exact lowercase
`expectedBeforeSha256`/`expectedAfterSha256` fingerprints of the previewed
before/after bytes; paths, raw content, replacement text, commands, and other
fields are rejected.

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
- C-locale, byte-valued `df` rows
  (`Filesystem ... Used Available Use% Mounted on`);
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
