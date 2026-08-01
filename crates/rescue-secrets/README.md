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
non-blocking root-owned lifecycle lock. `VaultUnlockRequest::new` accepts only:

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
a missing passphrase EOF cannot block the manager indefinitely.

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
capacity, requires no holders, rejects an existing mapper, and requires:

- a LUKS2 header recognized by cryptsetup;
- agreement between cryptsetup and cache-free blkid UUID observations; and
- the exact `KERNAID_VAULT` LUKS label.

After `cryptsetup open`, it verifies the mapper's device numbers, exact name,
LUKS2 DM UUID, one direct backing slave, cryptsetup status, and that this mapper
is the backing device's only holder. The inner filesystem must be ext4 with the
`KERNAID_VAULT` label. It is mounted with
`rw,nosuid,nodev,noexec,nosymfollow,relatime,errors=remount-ro` and then checked
against `/proc/self/mountinfo` and sysfs again.

These are strong checkpoint validations in the manager's current mount
namespace, not an atomic proof against a concurrent privileged namespace/path
actor. Cleanup rechecks the same claims and refuses force/lazy unmount or an
unverified mapping close on ambiguity. A `cryptsetup open` error is followed
by mapping inspection; if the exact mapping was nevertheless created, its
identity is acquired and verified cleanup is attempted.

## Provisioning and disposable probe

The Rust production surface contains no format, erase, raw-write, LUKS repair,
keyslot mutation, marker creation, permission repair, forced-unmount, or
arbitrary-command API. Provisioning is a separate administrative operation.

`tests/privileged-luks.sh` is the only provisioning path in this crate. It is
restricted to a newly allocated disposable loop image, creates the LUKS2/ext4
filesystem and required marker/layout outside the Rust manager, and then runs:

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

## Service and UI integration

The intended integration is a small root-owned local daemon that holds
`MountedRescueVault` for the complete session and exposes only bounded typed
operations over a permission-checked Unix socket. The web/Python UI must never
receive the LUKS passphrase, journal key, identity seed, raw mount path, or an
arbitrary command primitive. That daemon, its socket protocol, systemd/ISO
packaging, and the Rescue UI flow are not implemented by this crate yet.

## Remaining production gates

- run the daemon in a private mount namespace and adopt descriptor-based mount
  attachment (`open_tree`/`move_mount` or an equivalent design);
- replace the sysfs disk-sequence checkpoint with a safe `BLKGETDISKSEQ` ioctl
  wrapper and eliminate pathname handoff to external tools where possible;
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
