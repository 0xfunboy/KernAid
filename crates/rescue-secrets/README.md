# KernAid Rescue secure state

This crate implements fail-closed persistence for the KernAid Rescue journal
and device identity. Its production constructor requires an opaque mount
attestation. The only component that can mint that attestation—the privileged
LUKS2 mount manager—is deliberately disabled by default and is available only
with `experimental-vault-manager`; its disposable integration probe
additionally requires `privileged-probe`.

It is not yet a production daemon or a bootable repair product. The feature
gate remains in place because mount-namespace/path races and restart recovery
still need a dedicated privileged service design.

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
non-interactive attempt and every child operation has a 30-second deadline, so
a missing passphrase EOF cannot block the manager indefinitely. Every fixed
cryptsetup/blkid child starts in a new process group. The manager drains
captured output non-blockingly, rejects unexpected descendants even after the
direct child exits, and uses bounded TERM/KILL cleanup on errors or timeouts.

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
chmod, chown, repair, or delete anything inside the mounted filesystem. A
leftover `.tmp-*` object fails closed and is not removed. Journal/database and
identity writes happen only through later, explicit application calls such as
`open_journal`, `append`, and `create_device_identity`.

## Kernel identity checks

Before activation, the manager holds a CLOEXEC descriptor for the selected
block device and repeatedly compares its inode, filesystem device and `rdev`
with the direct pathname. It also retains the kernel sysfs disk sequence and
capacity, requires no holders, rejects an existing mapper, and validates the
embedded device-layout and vault-profile manifests. Exactly one of three
closed results is possible:

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
unverified mapping close on ambiguity. A `cryptsetup open` error is followed
by mapping inspection; if the exact mapping was nevertheless created, its
identity is acquired and verified cleanup is attempted.

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
CLOEXEC. A fixed, bounded `/usr/sbin/blockdev` child receives a CLOEXEC
duplicate as fd 0 and performs the actual BLKGETDISKSEQ and geometry ioctls on
`/proc/self/fd/0`; no mutable device pathname is handed to the tool. The
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

The first mode initializes an encrypted journal, appends a fixed sentinel, and
creates a device identity. The second unlocks the same volume and verifies the
journal key/anchor, sentinel, and identity survived the reopen. The script also
requires a wrong passphrase to fail without leaving a mount or mapping.

The successful probe output is one machine-readable, non-secret line:

```text
KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 mode=<initialize|verify> sentinel=kernaid-disposable-vault-persistence-v1 identity_public_key=<64 lowercase hex> clean_shutdown=true
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
host after both boots. CI binds the stable logical sentinel and identity,
LUKS/filesystem UUIDs, wrong-key rejection and two clean managed lifecycles to
the same log that proves raw prefix/p3/target invariance during the boot
window. This is intentionally not an in-guest unlock or vault-service claim.
The probe, provisioning commands and tmpfs key files are never packaged in the
Rescue ISO.

## Service and UI integration

The intended integration is a small root-owned local daemon that holds
`MountedRescueVault` for the complete session and exposes only bounded typed
operations over a permission-checked Unix socket. The closed AF_UNIX
`SOCK_SEQPACKET` message and descriptor contract now lives in
`kernaid-protocol`; this crate supplies only its read-only boot-media locator.
The web/Python UI must never receive the LUKS passphrase, journal key, identity
seed, raw mount path, or an arbitrary command primitive. The daemon, socket
listener, systemd/ISO packaging, unlock/store handlers, and Rescue UI flow are
not implemented yet.

## Remaining production gates

- run the daemon in a private mount namespace and adopt descriptor-based mount
  attachment (`open_tree`/`move_mount` or an equivalent design);
- replace the experimental manager's remaining sysfs disk-sequence checkpoint
  with its descriptor-bound `BLKGETDISKSEQ` observation;
- define and test restart recovery for an interrupted process and mappings or
  mounts visible in other namespaces;
- exercise crash windows, additional-holder races, and real hardware in the
  privileged test matrix;
- package the service and tools into the Rescue ISO; and
- add TPM/Fleet anchoring for rollback detection across full vault-image
  replay.

Unit tests cover strict parsing, CLOEXEC inheritance, activation ordering,
ambiguous-open cleanup, no-provision open behavior, atomic secure-state writes,
and fail-safe cleanup. The kernel-bound loop test remains CI-only and requires
root plus cryptsetup/e2fsprogs.
