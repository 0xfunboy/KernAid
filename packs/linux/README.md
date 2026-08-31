# Linux pack

`kernaid-linux-inventory` is restricted to directory fixtures and emits names,
sizes, and readonly permission state. It does not read file contents or mutate
the target. The separate no-argument production binaries
`kernaid-linux-hardware-inventory`, `kernaid-linux-storage-health`, and
`kernaid-linux-filesystem-health` inspect
only the running machine. Storage health invokes fixed, bounded `lsblk`,
`smartctl` and `nvme` commands and returns only normalized `disk-N` references,
health states and the documented SMART/NVMe indicators. Serial numbers, WWNs,
kernel device names and raw tool JSON are never part of its output. Missing
tools and unavailable permissions remain explicit unsupported states; they are
never interpreted as healthy.

Filesystem health accepts no arbitrary command or path. Resident checks only
the current Linux root; Rescue's root-owned helper may pass one freshly
resolved normalized target reference plus its kernel major/minor binding. The
engine opens that exact block node without following symlinks and invokes only
`e2fsck -f -n` for ext4 or `ntfsfix -n` for NTFS. It never mounts a target,
never replays a journal, discards bounded raw tool output, and emits only the
closed `healthy`, `degraded`, `repair-required`, or `unsupported` result.

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
feature. That private feature now has a real end-to-end handler: broker-owned
read-only target resolution and observation, an immutable transaction plan,
separate Core/policy approval, encrypted Vault backup, a closed daemon/UI
route, atomic mutation and validation, explicit rollback, and startup
reconciliation. The broker retains the non-cloneable approval authority,
opaque target capabilities and exact Vault reservation guard; receipts remain
audit evidence and never become execution authority.

None of that handler is compiled into the default/stable Rescue image, which
remains diagnosis-only. The repair candidate is still private,
feature-gated/off-default, unpromoted and unavailable through the product site
or Release Channel. It is therefore not a shipping or user-supported repair
path. The manifest's `productionCandidateOnly` label names the qualification
track; it does not itself authorize production use.

`action-pack.crypttab-production-candidate-v1.yaml` defines a second and
separately compiled preflight candidate,
`linux.crypttab.disable-missing-uuid.v1`. Its pure pack can comment exactly one
UUID-backed auxiliary mapping proven absent by the sealed UUID inventory. It
rejects root/initramfs/resume/swap/keyscript/network mappings, external key
files, malformed or ambiguous documents, and every active mandatory fstab
consumer of the mapper name. Optional `nofail`/`noauto` consumers are allowed.
The broker reads both files only through the retained detached read-only ext4
mount, revalidates target identity around observation, binds three canonical
evidence hashes and stages a single-use typed Core approval. Raw UUID, mapper,
key and configuration data remain out of protocol, logs and `Debug`.

This crypttab tranche deliberately has no execution method, repaird route or
UI. It must reuse the fstab candidate's distinct-Vault reservation, single-use
write lease, atomic regular-file replacement, automatic restore, explicit
rollback and reboot reconciliation before it can be packaged. The manifest is
a required contract, not evidence that those gates already exist.

The candidate can propose commenting only one active, mandatory UUID entry
that is absent from a caller-supplied observed UUID set and mounts below
`/mnt/`, `/media/`, or `/srv/` on `ext4`. It fails closed for malformed input,
multiple targets, critical mount trees (`/`, boot, system directories, home,
or swap), other mount locations or filesystem types, bind mounts, and network
filesystems. Its strict JSON input binds the version-2 `KA-LNX-P0-003` finding
and exact before, observed UUID-set, and proposed-after SHA-256 fingerprints;
it accepts no path, replacement bytes, or command.

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

The immutable candidate plan additionally binds the session and plan IDs,
canonical evidence hashes, selected-target scan identity, target and Vault
physical-parent identities, authenticated Vault identity and opaque backup
locator, a durable reservation ID and binding, actually reserved capacity,
exact risk/preflight/backup/validation/rollback declarations, timeout,
cancellation, idempotency and redaction policy. A mutable free-space snapshot
is deliberately not treated as a capability. The
target and Vault must have distinct physical parents. These values are still
admission material supplied to pure code. In the private candidate, the
feature-gated trusted broker derives and rechecks them from retained
kernel-backed capabilities before any write is possible; neither the UI nor a
provider may supply a host path, device path, command, or replacement bytes.

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
