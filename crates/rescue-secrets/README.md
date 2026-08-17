# KernAid Rescue secure state

This crate implements fail-closed persistence for the KernAid Rescue journal,
device identity, provider credential, typed Agent audit, and signed reports.
Its production constructor requires an opaque mount
attestation. The only component that can mint that attestation—the privileged
LUKS2 mount manager—is deliberately disabled by default and is available only
with `experimental-vault-manager`; its disposable integration probe
additionally requires `privileged-probe`.

It is not yet a packaged production service or a bootable repair product. A
Rust-only lifecycle daemon and terminal companion now exist behind
`experimental-vault-manager`, but the systemd isolation, ISO integration and
privileged QEMU lifecycle proof are deliberately a later tranche.

## Experimental manager API

`RescueVaultMountManager::acquire` requires effective uid 0 and holds one
non-blocking root-owned lifecycle lock. The integration-shaped
`VaultUnlockRequest::from_located` consumes only the sealed, read-only
`LocatedVaultPartition` returned for the exact boot medium; it does not accept
a client-selected device or path. The path-taking `VaultUnlockRequest::new` is
compiled only for the `privileged-probe` disposable integration binary and
accepts only:

- a direct, absolute, symlink-free `/dev/<node>` block-device path (never a
  `/dev/disk/by-*` alias or an existing device-mapper node); and
- `kernaid-vault-<16 lowercase hexadecimal characters>` as mapper name.

The current manager supports root-owned vault layouts only. There is no
non-root owner parameter and no claim that a split-privilege service account is
already supported. The mount point is derived beneath `/run/kernaid/vault/`;
it is not caller-controlled.

`unlock_from_fd(request, passphrase_fd)` sets `FD_CLOEXEC` on the supplied
descriptor before spawning validation tools. Only immediately before
`cryptsetup open` it makes one `F_DUPFD_CLOEXEC` duplicate and transfers that
duplicate to stdin. The passphrase is never placed in argv, an environment
variable, a Rust string, a log, or an error. Cryptsetup receives one
non-interactive attempt. Cryptsetup and blkid children have a 30-second
user-space deadline; the descriptor-bound blockdev identity queries instead
share one aggregate two-second deadline per identity check. A missing
passphrase EOF is therefore covered by the user-space child deadline while the
child remains interruptible. Every fixed child starts in a new process group. The manager drains
captured output non-blockingly, rejects unexpected descendants even after the
direct child exits, and uses bounded TERM/KILL cleanup on errors or timeouts.

These deadlines are checkpoints, not a hard wall-clock guarantee against a
faulting block device. A synchronous kernel `pread` can remain in
uninterruptible I/O past the requested classification deadline. A fixed child
in kernel D-state can survive TERM/KILL, but cleanup uses only bounded
`try_wait` polling and returns `cleanup-failed` after the kill grace instead of
entering an unbounded reap. The integrating service must isolate this backend
work in a separate process and treat either condition as a terminal
reboot-required host fault rather than retry inside that process.

The selected vault device is different: its pre-unlock classifier reads only
the manager's retained read-only descriptor and runs no external command.
`cryptsetup open` is the first operation allowed to reopen that descriptor as
a mutating capability, and it receives only
`/proc/<daemon-pid>/fd/<retained-fd>`. Later cache-free `blkid` checks receive
only retained mapper procfds. The direct `/dev/<node>` names remain repeated
identity checkpoints and are never child-tool device arguments, so a udev
rename or replacement cannot retarget an operation.

An accepted vault must already contain this root-owned layout:

```text
/.kernaid-rescue-vault             regular file, 0600, exact V1 marker
/.kernaid-rescue-secrets.lock      regular file, 0600
/.kernaid-secure-state-v1/         directory, 0700
```

Unlock and `RescueVaultSecrets::open` validate that layout; they do not create,
chmod, chown, or repair its externally provisioned objects. One exact secure
`.tmp-<32 lowercase hex>` core-secret file left after file and directory fsync
may be reconciled under the vault lock: a valid typed value is promoted with
`RENAME_NOREPLACE` when its final is absent, or removed only when the final
state makes that action unambiguous. Multiple, malformed, linked, cross-mount,
wrong-owner/mode, invalid, or conflicting temporary objects remain untouched
and fail closed. Journal and application writes happen only through later,
explicit typed calls. Raw journal and identity-creation surfaces are compiled
public only for the disposable `privileged-probe` feature.

## Kernel identity checks

Before activation, the manager holds a CLOEXEC descriptor for the selected
block device and repeatedly compares its inode, filesystem device and `rdev`
with the direct pathname. It also re-reads disk sequence, capacity and logical
sector size through the retained descriptor under one aggregate blockdev
deadline, requires no holders, rejects an existing mapper, and validates the
embedded device-layout and vault-profile manifests. Exactly one of three closed
results is possible:

- every byte of the exact 8 GiB p3 is zero: `UNPROVISIONED`;
- both independently checksummed 16 KiB LUKS2 metadata copies have the exact
  label, RFC 4122 v4 UUID, matching sequence and logical JSON, and every
  cipher/KDF/keyslot/offset/sector/profile field is pinned: `LOCKED`; or
- any other non-zero layout or metadata state: `PROFILE_MISMATCH`.

The raw classifier never invokes cryptsetup: `luksDump`/`luksUUID` can repair a
redundant header when run as root even when the original descriptor was opened
read-only. Avoiding those commands is therefore part of the zero-write trust
boundary, not merely an implementation preference.

After `cryptsetup open`, it retains a separate read-only mapper descriptor and
verifies its device numbers, exact name, LUKS2 DM UUID, exact payload capacity,
one direct backing slave, cryptsetup status, and that this mapper is the
backing device's only holder. Before mount, the inner filesystem must match the
complete ext4 profile, including superblock and group-descriptor checksums,
feature/geometry policy, RFC 4122 v4 UUID, inode 8's initialized 128 MiB
journal extent and the JBD2 superblock. It is mounted with
`rw,nosuid,nodev,noexec,nosymfollow,relatime,errors=remount-ro` and then checked
again through the retained mapper descriptor, `/proc/self/mountinfo` and
sysfs. Mutable ext4 fields are accepted after mount only where the profile
explicitly permits them; immutable profile evidence must remain identical.

Linux omits an `errors=` mountinfo token when the requested policy equals the
ext4 superblock default. The manager therefore accepts either an explicit
`errors=remount-ro` token or an omitted token plus an exact, descriptor-bound
ext4 `s_errors=2` observation from the validated mapper. Explicit
`errors=continue`, `errors=panic`, duplicate policies, a bad ext4 magic value,
or any other policy fail closed.

These are strong checkpoint validations in the manager's current mount
namespace, not an atomic proof against a concurrent privileged namespace/path
actor. Cleanup rechecks the same claims and refuses force/lazy unmount or an
unverified mapping close on ambiguity. A `cryptsetup open` error after a child
actually ran is followed by mapping inspection; if the exact mapping was
nevertheless created, its identity is acquired and verified cleanup is
attempted. A spawn failure, or a child/process group that cannot be proven
reaped, stops before any mapper inspection or close because ownership was not
established.

## Read-only boot-medium locator

`locate_boot_vault()` is a separate, production-visible Observe primitive. It
accepts no argument and never searches `/dev` or all disks. It starts at the
single exact ISO9660 mount `/run/live/medium`, resolves that mount's kernel
major:minor through sysfs, identifies its containing disk, and considers only
that parent's direct partition number 3. Optical boot returns the distinct
`OpticalBootAbsent` state and never falls back to another attached device.

For USB boot, the locator requires an unambiguous USB sysfs ancestry, parent
and p3 `/sys/dev/block` identities, direct parentage, uevent major/minor/type,
partition number, disk sequence, 512-byte logical sectors, at least the
qualified 32 GB media capacity, and the exact layout-v1 p3 start/length. It
then opens the parent and p3 direct nodes read-only with NOFOLLOW, NONBLOCK and
CLOEXEC. Fixed, bounded `/usr/sbin/blockdev` children perform the actual
BLKGETDISKSEQ and geometry ioctls only through
`/proc/<locator-pid>/fd/<retained-fd>`; no mutable device pathname is handed to
the tool and all queries share one aggregate deadline. The
retained parent descriptor must contain the complete finalized layout-v1 MBR:
qualified ISO slots 1/2 before the vault, exact slot 3, and an all-zero reserved
slot 4. The complete mountinfo/sysfs/FD/ioctl/MBR identity is checked twice
before a path-free `LocatedVaultPartition` is returned.

That sealed capability can be moved directly into
`VaultUnlockRequest::from_located`. Its validated kernel node name remains
crate-private, and the experimental manager keeps the locator descriptor open
while binding every pathname checkpoint to its major/minor, disk sequence and
capacity. Cryptsetup and blkid receive only the retained daemon procfd; no IPC
field exposes or selects the checkpoint name.

This constructor is not yet a production unlock claim. The manager now applies
the non-bypassable descriptor-bound classifier and repeats immutable profile
checks before and after unlock and mount, but the feature gate remains until a
dedicated daemon owns the private mount namespace, restart recovery and IPC
lifecycle.

The locator never invokes cryptsetup, activates device mapper, mounts a
filesystem, reads a LUKS header, repairs metadata, or writes any byte. It does
not prove that p3 is provisioned; that remains a later typed service step.

## Closed application store

`RescueVaultSecrets::open_application_store` is the production persistence
surface. It is load-only for `DeviceIdentity`: an identity must already exist,
and journal sequence one must be the sole canonical `vault.identity.bound`
event containing the matching device ID and public-key SHA-256. Authenticated
replay is side-effect-free; only after the complete chain is accepted may one
tail intent be recovered. Unknown, non-canonical, duplicate, out-of-order, or
raw caller-supplied journal events fail closed.

The store exposes only these bounded operations:

- presence-only OpenAI status, configure/replace, callback-scoped borrow, and
  logout. Values are 1–512 visible ASCII bytes, callback allocations are
  zeroized, and journal events contain only old/new SHA-256 values. The fixed
  file is `provider-openai-api-key-v1`; replacement uses atomic
  `RENAME_EXCHANGE`, retaining the old value as the transaction-bound stage
  until the applied completion is durable;
- typed Agent lifecycle audit accepted only as an authenticated
  `kernaid_protocol::rescue_vault::ValidatedRequest`. Request IDs are kept in
  an exact bounded `[u8; 16]` replay set, sequence is monotonic within a
  lifecycle, and a fresh successful session-start explicitly begins a new
  lifecycle while failed/rejected starts do not replace the active one; and
- validation, expected-hash binding, identity signing, persistence, bounded
  listing, and callback-scoped retrieval of strict `SessionReport` JSON. Raw
  input is at most 1 MiB, reports are capped at 256, filenames are
  `report-v1-RP-<uuid>.json`, and every envelope binds the report hash plus the
  exact journal intent sequence/hash. Open performs full bounded verification;
  list checks authenticated metadata and filesystem bijection; get re-verifies
  the one requested envelope and schema.

New application files are accessed relative to the retained state-directory
descriptor with `openat2` beneath/no-symlink/no-magiclink/no-cross-mount
resolution, owner/mode/nlink/mount checks, CSPRNG transaction stages, file and
directory fsync, no-replace report installation, and final named readback.
Application stages are `.kernaid-app-stage-v1-<32 lowercase hex>` and only the
single journal-authenticated tail transaction can be reconciled.

The SQLite journal implementation still opens its database through a pathname
inside `SecureJournal`; the application store checks the retained directory
and DB/WAL/SHM owner, mode, link, device, and mount identity before and after
each journal operation. A concurrent root actor able to replace pathname state
inside that narrow interval remains an explicit residual threat until a
descriptor-bound SQLite VFS or private privileged daemon boundary replaces it.

## Provisioning and disposable probe

The Rust production surface contains no format, erase, raw-write, LUKS repair,
keyslot mutation, marker creation, permission repair, forced-unmount, or
arbitrary-command API. Provisioning is a separate administrative operation.

`tests/privileged-luks.sh` is the only provisioning path in this crate. It is
restricted to a newly allocated disposable loop image, creates the LUKS2/ext4
filesystem with the same pinned profile-v1 arguments as the USB smoke test and
the required marker/layout outside the Rust manager, and then runs:

```text
kernaid-rescue-vault-probe --device /dev/loopN \
  --mapper kernaid-vault-<suffix> --mode initialize
kernaid-rescue-vault-probe --device /dev/loopN \
  --mapper kernaid-vault-<suffix> --mode verify
```

The first mode proves the journal is empty, creates a device identity, and then
opens the closed application store so sequence one becomes the canonical
identity-binding event. The second unlocks the same volume and opens that store
again, thereby authenticating the journal key/anchor and exact identity
binding before reporting the same public key. No provider or report fixture is
written. The script also requires a wrong passphrase to fail without leaving a
mount or mapping.

The successful probe output is one machine-readable, non-secret line:

```text
KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 mode=<initialize|verify> journal_binding=device-identity-bound-v1 identity_public_key=<64 lowercase hex> clean_shutdown=true
```

It is emitted only after `MountedRescueVault::shutdown` succeeds. The identity
value is the public Ed25519 key in canonical lowercase hexadecimal, never its
seed. Failures emit exactly one closed diagnostic such as
`KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1 stage=unlock code=mount-verification-failed`.
Stage/code values are fixed enum literals; paths, mapper identities, command
output, OS messages, passphrases, and stored bytes are never copied. Once a
mount exists, the probe always executes the verified shutdown path even when
the journal or identity operation fails; a cleanup failure takes precedence
over the operation failure.

The Rescue workflow also exercises this probe against p3 of a disposable
32,000,000,000-byte raw USB image. Provisioning and initialize happen on the
host before two consecutive BIOS or UEFI QEMU USB boots; verify happens on the
host after both boots. CI binds the authenticated journal identity claim and identity,
LUKS/filesystem UUIDs, wrong-key rejection and two clean managed lifecycles to
the same log that proves raw prefix/p3/target invariance during the boot
window. This is intentionally not an in-guest unlock or vault-service claim.
The probe, provisioning commands and tmpfs key files are never packaged in the
Rescue ISO.

## Experimental Rescue lifecycle daemon

With `experimental-vault-manager`, `kernaid-rescue-vaultd` implements only the
closed `vault.status`, `vault.unlock`, and `vault.lock` lifecycle. Every
provider configure/status/logout/borrow/home-lease, Agent audit, and report
persist/list/get request is answered `NOT_AUTHORIZED`, with no output
descriptor and no worker dispatch. The public socket is the fixed top-level
`/run/kernaid-rescue-vault.sock`; the daemon accepts only protocol-authenticated
UID 1000 `kernaid` companion requests and never accepts a client path, mapper
name, command, JSON secret, or configuration argument. `stateVersion` starts
from a CSPRNG value in the exact JSON-safe range and is checked before every
transition; status accepts only bootstrap zero or the exact current version.

The supervisor remains responsive while a separate, long-lived internal
worker owns the locator, mount manager, mounted vault and transient application
store used to copy the public device ID. The worker is moved, before any probe,
from the exact delegated cgroup-v2 `supervisor` subgroup to its fixed sibling
`worker`. The supervisor requires `pids` in the delegated root's controller
set, enables it through the retained `cgroup.subtree_control` descriptor, and
requires exact readback plus recursive sibling/leaf topology before creating
or using `worker`. A bootstrap barrier makes the child prove its own `/worker`
membership; the parent brackets commands with pidfd, `cgroup.procs`,
`pids.current`, `nr_descendants`, and supervisor-topology checks. Internal
messages have a fixed binary layout, closed result codes, bounded records,
exact correlation and descriptor arity, and contain neither paths nor secret
bytes. The LUKS mapper name is freshly randomized for each unlock attempt.

`/run/kernaid-rescue-vault/lifecycle-active-v1` is a daemon-created crash
marker beneath the systemd-owned runtime directory, not a generic state file.
The supervisor creates, file-fsyncs and directory-fsyncs it immediately before
the first mutating worker dispatch. It remains present while unlocked and
through every ambiguous cleanup. It is removed and the directory fsynced only
after the worker proves the exact boot partition is LUKS-locked and quiescent
(no holders or mount), worker/cgroup identity remains exact, and cleanup is
complete. Any named marker found at restart—including a partial or malformed
one—means status-only
`FaultedRebootRequired`; no worker is started. Marker, cgroup, pidfd, reap, or
cleanup ambiguity is terminal and never causes an automatic retry. The
singleton flock is inside the root-owned mode-0700 runtime directory rather
than a pre-creatable `/run/lock` name.

The supervisor performs startup locate/classify with the same quiescent
`Locked` meaning used for marker removal. A client disappearing before the
lifecycle begin or immediately before marker arm is observed on that exact
accepted seqpacket socket and prevents dispatch. Disappearance observed after
the durable arm but before dispatch becomes a terminal fault; after dispatch,
the authoritative outcome may still complete and is reconciled. A correlated
response that has already arrived remains authoritative; a terminal signal
that wins a later receive poll closes that connection and uses the same
unknown-outcome reconciliation as a genuine post-send transport failure.
Fresh status connections poll transitional `Unlocking`/`Locking` evidence
silently until a terminal state or the original aggregate deadline, and only
the exact target with sufficient version advancement is success.
Linux cannot distinguish an orderly `SOCK_SEQPACKET` shutdown from an empty
record immediately followed by shutdown. That explicit zero-byte peer-state
ambiguity—including a classification deadline reached after consuming the
zero byte—is eligible for reconciliation only in the post-mutation context; a
confirmed live empty record and every other malformed frame remain protocol
failures.

`kernaid-rescue-vaultctl` is the only shipping-shaped passphrase path. It has
no path/configuration option, verifies the fixed UID/name binding, opens only
`/dev/tty`, proves foreground job-control ownership, disables and reads back
echo before printing `READY`, and intercepts INT, TERM, HUP, QUIT, TSTP, TTIN
and TTOU. Input uses a preallocated zeroizing buffer, exact length/EOF/NUL and
single-line validation, an anonymous pipe, and cleanup-dominant input flush
plus verified echo restore. The secret is never placed in argv, environment,
stdout, JSON or a log. The daemon revalidates the pipe as read-only CLOEXEC
PIPEFS and copies it into a separate internal pipe only after stale/policy and
pre-secret swap gates succeed.

Daemon, worker and companion set `PR_SET_DUMPABLE=0` and prove the initial user
namespace before sensitive work. The daemon additionally requires an empty
`/proc/sys/kernel/core_pattern`, exact-zero `core_uses_pid`, and header-only
`/proc/swaps`; swap is rechecked immediately before external secret read and
again before worker consumption. Each daemon mutation handler, including its
worker transaction, fault cleanup and correlated response send, shares one
aggregate 600-second absolute budget; the final send is additionally capped at
three seconds within the remaining aggregate budget. The companion
mutation/reconciliation budget is 610 seconds, and the single stop budget is
at most 110 seconds from the first caught signal; fault cleanup never starts a
fresh grace interval beyond either absolute deadline.
These are user-space checkpoint bounds. The packaged delegated cgroup provides
recursive `cgroup.kill`, pidfd signalling and bounded population checks, but a
kernel D-state block read or exec stall still cannot be reaped until the kernel
returns. In that case the durable lifecycle marker remains and reboot is the
only honest recovery.

The Rescue live-build packaging installs the feature-gated daemon and
companion, a root:`kernaid-vault` sequential-packet socket, a `Type=notify`
service with a private mount namespace and delegated worker cgroup, the
root-owned runtime/tmpfiles boundary, and fail-closed core/swap and UID-1000
policy. The target systemd 257 unit intentionally omits `RestrictSUIDSGID`
because that version implements it by denying all `openat2` calls; the daemon's
descriptor-bound path validation requires `openat2`, while `NoNewPrivileges`,
the `CAP_SYS_ADMIN`-only bounding set, strict filesystem protection and the
remaining sandbox gates stay enabled. The one systemd `RuntimeDirectory`
bind-mount crossing is opened relative to a validated `/run` descriptor and
accepted only when descriptor, named entry and `/run` share the exact expected
root-owned tmpfs identity; all child operations restore no-cross-mount
resolution. The daemon sends `READY=1` only after runtime disposition, worker
Probe,
an immediate worker-health recheck, and coherent Supervisor construction on a
marker-free startup. Any fresh cgroup, spawn, Probe, or health failure exits
without READY. A marker found before startup may become ready only as a
contained status-only `PersistentFault` service and never starts a worker.
Static tests and target-systemd unit verification do not qualify the real
deployment by themselves. A separate privileged QEMU lifecycle test must still
prove socket ownership/mode, cgroup topology and capabilities, core/swap
policy, UID-1000 privacy, signal/stop behavior, real dm-crypt holder rejection,
mount-namespace isolation and reboot-required recovery before this integration
is described as shipping-qualified. The web/Python UI never receives the LUKS
passphrase, journal key, identity seed, raw mount path, or an arbitrary command
primitive.

## Remaining production gates

- replace the current private-namespace pathname mount attachment with a
  descriptor-based attachment (`open_tree`/`move_mount` or an equivalent
  design);
- define and test restart recovery for an interrupted process and mappings or
  mounts visible in other namespaces;
- exercise crash windows, additional-holder races, and real hardware in the
  privileged test matrix;
- run the packaged service and companion through the separate BIOS/UEFI,
  two-boot privileged QEMU lifecycle matrix; and
- add TPM/Fleet anchoring for rollback detection across full vault-image
  replay.

Unit tests cover strict parsing, CLOEXEC inheritance, activation ordering,
ambiguous-open cleanup, no-provision open behavior, atomic secure-state writes,
and fail-safe cleanup. The kernel-bound loop test remains CI-only and requires
root plus cryptsetup/e2fsprogs.
