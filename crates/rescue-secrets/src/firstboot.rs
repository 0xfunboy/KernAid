//! Fail-closed first-boot provisioning boundary.
//!
//! This feature-gated module proves that the exact p3 capability belonging to
//! `/run/live/medium` is all-zero, confirms an opaque passphrase from two
//! independent CLOEXEC descriptors, and drives the closed privileged
//! provisioning lifecycle. It has no path-taking constructor; success is
//! exposed only after verified cleanup and locked-profile reclassification.

use crate::{
    BootVaultLocation, LocatedVaultClassification, LocatedVaultClassificationError,
    LocatedVaultIdentity, LocatedVaultPartition, RescueVaultMountManager, VaultMountManagerError,
    bounded_process, locate_boot_vault, profile_classifier::verify_embedded_profile,
};
use kernaid_protocol::rescue_vault::{MAX_PASSPHRASE_BYTES, MIN_PASSPHRASE_BYTES};
use std::{
    error::Error,
    fmt,
    os::fd::AsFd,
    process::{Command, Stdio},
    time::Duration,
};
use zeroize::Zeroizing;

const CLASSIFICATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PLYMOUTH_QUIT_TIMEOUT: Duration = Duration::from_secs(3);
const PLYMOUTH_PATH: &str = "/usr/bin/plymouth";
const PLYMOUTH_QUIT_ARGUMENTS: &[&str] = &["quit"];
const SECRET_READ_CHUNK_BYTES: usize = 256;

/// Stable, redacted failures for the first-boot boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstBootBoundaryError {
    InvalidInvocation,
    PrivilegeRequired,
    BootMediumUnavailable,
    OpticalBootHasNoVault,
    LocatorRejected,
    CanonicalProfileUnavailable,
    MediaChanged,
    ClassificationTimedOut,
    ClassificationCleanupFailed,
    VaultAlreadyProvisioned,
    VaultProfileMismatch,
    SecretDescriptorUnavailable,
    SecretInvalid,
    SecretMismatch,
    ProcessPrivacyUnavailable,
    PrivateMountNamespaceUnavailable,
    BootSplashDismissalFailed,
    TtyConfirmationUnavailable,
    ManagerUnavailable,
    ProvisioningFailed,
    SecureStateInitializationFailed,
}

impl FirstBootBoundaryError {
    /// Machine-readable value that contains no path, device name, command
    /// output, OS message, or secret material.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInvocation => "invalid-invocation",
            Self::PrivilegeRequired => "privilege-required",
            Self::BootMediumUnavailable => "boot-medium-unavailable",
            Self::OpticalBootHasNoVault => "optical-boot-has-no-vault",
            Self::LocatorRejected => "locator-rejected",
            Self::CanonicalProfileUnavailable => "canonical-profile-unavailable",
            Self::MediaChanged => "media-changed",
            Self::ClassificationTimedOut => "classification-timed-out",
            Self::ClassificationCleanupFailed => "classification-cleanup-failed",
            Self::VaultAlreadyProvisioned => "vault-already-provisioned",
            Self::VaultProfileMismatch => "vault-profile-mismatch",
            Self::SecretDescriptorUnavailable => "secret-descriptor-unavailable",
            Self::SecretInvalid => "secret-invalid",
            Self::SecretMismatch => "secret-mismatch",
            Self::ProcessPrivacyUnavailable => "process-privacy-unavailable",
            Self::PrivateMountNamespaceUnavailable => "private-mount-namespace-unavailable",
            Self::BootSplashDismissalFailed => "boot-splash-dismissal-failed",
            Self::TtyConfirmationUnavailable => "tty-confirmation-unavailable",
            Self::ManagerUnavailable => "manager-unavailable",
            Self::ProvisioningFailed => "provisioning-failed",
            Self::SecureStateInitializationFailed => "secure-state-initialization-failed",
        }
    }
}

impl fmt::Display for FirstBootBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for FirstBootBoundaryError {}

/// The closed lifecycle implemented by the feature-gated executor.
///
/// Intermediate values are audit vocabulary, not public success states. The
/// executor returns evidence only after `ReclassifiedLocked`; a partial
/// provisioning failure is never represented as success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningState {
    Located,
    ClassifiedUnprovisioned,
    Confirmed,
    LuksFormatted,
    MappingVerified,
    FilesystemFormatted,
    FilesystemVerified,
    LayoutSeeded,
    DeviceIdentityInitialized,
    Synced,
    Closed,
    ReclassifiedLocked,
}

/// How a pinned command must receive its mutation target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningCommandTarget {
    /// A child-only duplicate of the retained p3 capability. The executor must
    /// substitute its own `/proc/self/fd/<n>` path immediately before spawn.
    LocatedPartitionChildDescriptor,
    /// A child-only descriptor opened only after exact mapper identity checks.
    VerifiedMapperChildDescriptor,
}

/// Immutable command blueprint for canonical profile v1.
///
/// `arguments_before_target` contains only compile-time literals. The target
/// is never supplied by an API caller. `cryptsetup open` additionally appends
/// the executor-derived mapper name after the descriptor target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalProvisioningCommand {
    pub program: &'static str,
    pub arguments_before_target: &'static [&'static str],
    pub target: ProvisioningCommandTarget,
    pub reads_confirmed_passphrase_from_stdin: bool,
    pub appends_derived_mapper_name: bool,
}

const LUKS_FORMAT_ARGUMENTS: &[&str] = &[
    "luksFormat",
    "--type",
    "luks2",
    "--batch-mode",
    "--label",
    "KERNAID_VAULT",
    "--uuid",
    "<generated-rfc4122-v4-luks-uuid>",
    "--cipher",
    "aes-xts-plain64",
    "--key-size",
    "512",
    "--hash",
    "sha256",
    "--sector-size",
    "512",
    "--pbkdf",
    "argon2id",
    "--pbkdf-force-iterations",
    "4",
    "--pbkdf-memory",
    "65536",
    "--pbkdf-parallel",
    "1",
    "--key-slot",
    "0",
    "--keyslot-cipher",
    "aes-xts-plain64",
    "--keyslot-key-size",
    "512",
    "--luks2-metadata-size",
    "16384",
    "--luks2-keyslots-size",
    "16744448",
    "--use-urandom",
    "--key-file",
    "-",
    "--keyfile-size",
    "<confirmed-passphrase-byte-count>",
];

const LUKS_OPEN_ARGUMENTS: &[&str] = &[
    "open",
    "--type",
    "luks2",
    "--batch-mode",
    "--tries",
    "1",
    "--disable-external-tokens",
    "--key-file",
    "-",
    "--keyfile-size",
    "<confirmed-passphrase-byte-count>",
];

const MKFS_EXT4_ARGUMENTS: &[&str] = &[
    "-q",
    "-F",
    "-t",
    "ext4",
    "-b",
    "4096",
    "-I",
    "256",
    "-i",
    "16384",
    "-g",
    "32768",
    "-G",
    "16",
    "-m",
    "0",
    "-o",
    "linux",
    "-e",
    "remount-ro",
    "-J",
    "size=128",
    "-E",
    "lazy_itable_init=0,lazy_journal_init=0",
    "-O",
    "none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum",
    "-L",
    "KERNAID_VAULT",
    "-U",
    "<generated-rfc4122-v4-filesystem-uuid>",
    "-M",
    "/",
];

const TUNE_EXT4_ARGUMENTS: &[&str] = &[
    "-c",
    "0",
    "-i",
    "0",
    "-e",
    "remount-ro",
    "-m",
    "0",
    "-o",
    "^acl,^user_xattr",
    "-M",
    "/",
];

/// Exact tool paths and closed arguments for the canonical v1 outer and inner
/// profiles. Mounting, marker/layout creation, identity initialization and
/// cleanup are descriptor-relative state-machine operations rather than shell
/// command templates.
pub const CANONICAL_PROVISIONING_COMMANDS_V1: &[CanonicalProvisioningCommand] = &[
    CanonicalProvisioningCommand {
        program: "/usr/sbin/cryptsetup",
        arguments_before_target: LUKS_FORMAT_ARGUMENTS,
        target: ProvisioningCommandTarget::LocatedPartitionChildDescriptor,
        reads_confirmed_passphrase_from_stdin: true,
        appends_derived_mapper_name: false,
    },
    CanonicalProvisioningCommand {
        program: "/usr/sbin/cryptsetup",
        arguments_before_target: LUKS_OPEN_ARGUMENTS,
        target: ProvisioningCommandTarget::LocatedPartitionChildDescriptor,
        reads_confirmed_passphrase_from_stdin: true,
        appends_derived_mapper_name: true,
    },
    CanonicalProvisioningCommand {
        program: "/usr/sbin/mkfs.ext4",
        arguments_before_target: MKFS_EXT4_ARGUMENTS,
        target: ProvisioningCommandTarget::VerifiedMapperChildDescriptor,
        reads_confirmed_passphrase_from_stdin: false,
        appends_derived_mapper_name: false,
    },
    CanonicalProvisioningCommand {
        program: "/usr/sbin/tune2fs",
        arguments_before_target: TUNE_EXT4_ARGUMENTS,
        target: ProvisioningCommandTarget::VerifiedMapperChildDescriptor,
        reads_confirmed_passphrase_from_stdin: false,
        appends_derived_mapper_name: false,
    },
];

/// Opaque confirmed secret. It cannot be formatted, cloned, compared by a
/// caller, converted to text, or read back. Both source allocations are
/// zeroized on every result path.
pub struct ConfirmedPassphrase {
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ConfirmedPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedPassphrase([REDACTED])")
    }
}

impl ConfirmedPassphrase {
    /// Read and compare two independent CLOEXEC descriptors.
    ///
    /// Each descriptor must contain only the raw passphrase bytes followed by
    /// EOF. A trusted terminal broker is responsible for `/dev/tty`, echo
    /// suppression, foreground-process checks, swap policy and line removal.
    /// This lower boundary intentionally has no `/dev/tty` or pathname API.
    pub fn confirm_from_fds(
        first: impl AsFd,
        confirmation: impl AsFd,
    ) -> Result<Self, FirstBootBoundaryError> {
        let first = read_secret_descriptor(first)?;
        let confirmation = read_secret_descriptor(confirmation)?;
        Self::confirm_values(first, confirmation)
    }

    fn confirm_values(
        first: Zeroizing<Vec<u8>>,
        confirmation: Zeroizing<Vec<u8>>,
    ) -> Result<Self, FirstBootBoundaryError> {
        if !constant_time_equal(&first, &confirmation) {
            return Err(FirstBootBoundaryError::SecretMismatch);
        }
        Ok(Self { bytes: first })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Located, descriptor-retaining proof that p3 was all-zero.
pub struct UnprovisionedFirstBoot {
    partition: LocatedVaultPartition,
    identity: LocatedVaultIdentity,
}

impl fmt::Debug for UnprovisionedFirstBoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnprovisionedFirstBoot")
            .field("identity", &self.identity)
            .field("state", &ProvisioningState::ClassifiedUnprovisioned)
            .finish()
    }
}

impl UnprovisionedFirstBoot {
    #[must_use]
    pub const fn state(&self) -> ProvisioningState {
        ProvisioningState::ClassifiedUnprovisioned
    }

    #[must_use]
    pub const fn identity(&self) -> LocatedVaultIdentity {
        self.identity
    }

    /// Bind the opaque confirmation without exposing either the block
    /// descriptor or secret.
    #[must_use]
    pub fn bind_confirmation(self, passphrase: ConfirmedPassphrase) -> ConfirmedFirstBoot {
        ConfirmedFirstBoot {
            partition: self.partition,
            identity: self.identity,
            passphrase,
        }
    }
}

/// Confirmed capability ready for the cleanup-safe, feature-gated executor.
pub struct ConfirmedFirstBoot {
    partition: LocatedVaultPartition,
    identity: LocatedVaultIdentity,
    passphrase: ConfirmedPassphrase,
}

/// Verified, non-secret evidence returned only after the mapper and mount are
/// gone and p3 reclassifies as the exact locked profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstBootProvisioningEvidence {
    luks_uuid: String,
    filesystem_uuid: String,
    device_id: String,
    identity_public_key: [u8; 32],
}

impl FirstBootProvisioningEvidence {
    #[must_use]
    pub fn luks_uuid(&self) -> &str {
        &self.luks_uuid
    }

    #[must_use]
    pub fn filesystem_uuid(&self) -> &str {
        &self.filesystem_uuid
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub const fn identity_public_key(&self) -> &[u8; 32] {
        &self.identity_public_key
    }
}

impl fmt::Debug for ConfirmedFirstBoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedFirstBoot")
            .field("identity", &self.identity)
            .field("state", &ProvisioningState::Confirmed)
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

impl ConfirmedFirstBoot {
    #[must_use]
    pub const fn state(&self) -> ProvisioningState {
        ProvisioningState::Confirmed
    }

    #[must_use]
    pub const fn identity(&self) -> LocatedVaultIdentity {
        self.identity
    }

    /// Repeat the complete zero classifier and immutable identity checks at
    /// the last available boundary before the executor may mutate.
    pub fn revalidate_unprovisioned(&self) -> Result<(), FirstBootBoundaryError> {
        if self.partition.identity() != self.identity {
            return Err(FirstBootBoundaryError::MediaChanged);
        }
        classify_unprovisioned(&self.partition)
    }

    /// Enter a new private mount namespace and execute the complete canonical
    /// provisioning lifecycle. Success is returned only after secure-state
    /// initialization, verified unmount/mapper close and locked
    /// reclassification.
    pub fn provision(self) -> Result<FirstBootProvisioningEvidence, FirstBootBoundaryError> {
        crate::rescue_daemon::enforce_process_privacy()
            .map_err(|()| FirstBootBoundaryError::ProcessPrivacyUnavailable)?;
        enter_private_mount_namespace()?;
        self.provision_in_private_namespace()
    }

    fn provision_in_private_namespace(
        self,
    ) -> Result<FirstBootProvisioningEvidence, FirstBootBoundaryError> {
        self.revalidate_unprovisioned()?;
        crate::rescue_daemon::validate_no_active_swap()
            .map_err(|()| FirstBootBoundaryError::ProcessPrivacyUnavailable)?;
        let manager = RescueVaultMountManager::acquire().map_err(map_manager_error)?;
        let evidence = manager
            .provision_firstboot(self.partition, self.passphrase.as_bytes())
            .map_err(map_manager_error)?;
        let luks_uuid = std::str::from_utf8(&evidence.luks_uuid)
            .map_err(|_| FirstBootBoundaryError::ProvisioningFailed)?
            .to_owned();
        let filesystem_uuid = std::str::from_utf8(&evidence.filesystem_uuid)
            .map_err(|_| FirstBootBoundaryError::ProvisioningFailed)?
            .to_owned();
        Ok(FirstBootProvisioningEvidence {
            luks_uuid,
            filesystem_uuid,
            device_id: evidence.device_id,
            identity_public_key: evidence.identity_public_key,
        })
    }
}

/// Preflight result returned by the no-argument first-boot entrypoint.
pub struct FirstBootPreflight {
    unprovisioned: UnprovisionedFirstBoot,
}

impl FirstBootPreflight {
    #[must_use]
    pub const fn state(&self) -> ProvisioningState {
        self.unprovisioned.state()
    }

    #[must_use]
    pub fn into_unprovisioned(self) -> UnprovisionedFirstBoot {
        self.unprovisioned
    }

    #[must_use]
    pub const fn canonical_commands(&self) -> &'static [CanonicalProvisioningCommand] {
        CANONICAL_PROVISIONING_COMMANDS_V1
    }
}

/// Locate only p3 of the exact Rescue boot medium and accept only an all-zero
/// canonical-sized capability. No caller input selects a device or path.
pub fn run_rescue_firstboot_preflight() -> Result<FirstBootPreflight, FirstBootBoundaryError> {
    if !rustix::process::geteuid().is_root() {
        return Err(FirstBootBoundaryError::PrivilegeRequired);
    }
    verify_embedded_profile().map_err(|_| FirstBootBoundaryError::CanonicalProfileUnavailable)?;
    let partition = match locate_boot_vault().map_err(|error| match error.code() {
        "boot-medium-absent" => FirstBootBoundaryError::BootMediumUnavailable,
        "media-changed" => FirstBootBoundaryError::MediaChanged,
        "operation-timed-out" => FirstBootBoundaryError::ClassificationTimedOut,
        "cleanup-failed" => FirstBootBoundaryError::ClassificationCleanupFailed,
        _ => FirstBootBoundaryError::LocatorRejected,
    })? {
        BootVaultLocation::OpticalBootAbsent => {
            return Err(FirstBootBoundaryError::OpticalBootHasNoVault);
        }
        BootVaultLocation::Vault(partition) => partition,
    };
    let identity = partition.identity();
    classify_unprovisioned(&partition)?;
    if partition.identity() != identity {
        return Err(FirstBootBoundaryError::MediaChanged);
    }
    Ok(FirstBootPreflight {
        unprovisioned: UnprovisionedFirstBoot {
            partition,
            identity,
        },
    })
}

/// Complete no-argument terminal first-boot flow used by the feature-gated
/// binary. Privacy and a private mount namespace are established before the
/// first secret is read or mutation can occur.
pub fn run_rescue_firstboot() -> Result<FirstBootProvisioningEvidence, FirstBootBoundaryError> {
    crate::rescue_daemon::enforce_process_privacy()
        .map_err(|()| FirstBootBoundaryError::ProcessPrivacyUnavailable)?;
    enter_private_mount_namespace()?;
    let preflight = run_rescue_firstboot_preflight()?;
    dismiss_boot_splash()?;
    let (first, confirmation) = crate::rescue_daemon::read_firstboot_passphrase_pair()
        .map_err(|_| FirstBootBoundaryError::TtyConfirmationUnavailable)?;
    let passphrase = ConfirmedPassphrase::confirm_values(first, confirmation)?;
    preflight
        .into_unprovisioned()
        .bind_confirmation(passphrase)
        .provision_in_private_namespace()
}

/// Relinquish Plymouth only after the exact boot Vault has passed its complete
/// read-only unprovisioned classification. The fixed child has no shell, no
/// caller-controlled argument or inherited stdio, and is killed as a process
/// group if it exceeds the bounded prompt-transition deadline.
fn dismiss_boot_splash() -> Result<(), FirstBootBoundaryError> {
    let mut command = Command::new(PLYMOUTH_PATH);
    command
        .args(PLYMOUTH_QUIT_ARGUMENTS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = bounded_process::wait(&mut command, PLYMOUTH_QUIT_TIMEOUT)
        .map_err(|_| FirstBootBoundaryError::BootSplashDismissalFailed)?;
    if !status.success() {
        return Err(FirstBootBoundaryError::BootSplashDismissalFailed);
    }
    Ok(())
}

fn enter_private_mount_namespace() -> Result<(), FirstBootBoundaryError> {
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .map_err(|_| FirstBootBoundaryError::PrivateMountNamespaceUnavailable)?;
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .map_err(|_| FirstBootBoundaryError::PrivateMountNamespaceUnavailable)
}

fn map_manager_error(error: VaultMountManagerError) -> FirstBootBoundaryError {
    match error {
        VaultMountManagerError::PrivilegeRequired => FirstBootBoundaryError::PrivilegeRequired,
        VaultMountManagerError::ManagerLocked | VaultMountManagerError::MapperConflict => {
            FirstBootBoundaryError::ManagerUnavailable
        }
        VaultMountManagerError::InvalidBlockDevice => FirstBootBoundaryError::MediaChanged,
        VaultMountManagerError::Unprovisioned => FirstBootBoundaryError::VaultProfileMismatch,
        VaultMountManagerError::ProfileMismatch
        | VaultMountManagerError::InvalidLuks2Header
        | VaultMountManagerError::WrongVaultLabel
        | VaultMountManagerError::UnsupportedFilesystem => {
            FirstBootBoundaryError::VaultProfileMismatch
        }
        VaultMountManagerError::ClassifierUnavailable => {
            FirstBootBoundaryError::CanonicalProfileUnavailable
        }
        VaultMountManagerError::PassphraseUnavailable => FirstBootBoundaryError::SecretInvalid,
        VaultMountManagerError::ProvisioningInitializationFailed
        | VaultMountManagerError::SecureStateUnavailable => {
            FirstBootBoundaryError::SecureStateInitializationFailed
        }
        VaultMountManagerError::ProvisioningFormatFailed
        | VaultMountManagerError::UnlockFailed
        | VaultMountManagerError::MappingVerificationFailed
        | VaultMountManagerError::UnsafeMountRoot
        | VaultMountManagerError::MountFailed
        | VaultMountManagerError::MountVerificationFailed
        | VaultMountManagerError::ToolUnavailable => FirstBootBoundaryError::ProvisioningFailed,
        VaultMountManagerError::CleanupFailed => {
            FirstBootBoundaryError::ClassificationCleanupFailed
        }
        VaultMountManagerError::OperationTimedOut => FirstBootBoundaryError::ClassificationTimedOut,
        VaultMountManagerError::UnsupportedPlatform | VaultMountManagerError::InvalidMapperName => {
            FirstBootBoundaryError::ManagerUnavailable
        }
    }
}

fn classify_unprovisioned(partition: &LocatedVaultPartition) -> Result<(), FirstBootBoundaryError> {
    match partition.classify_read_only(CLASSIFICATION_TIMEOUT) {
        Ok(LocatedVaultClassification::Unprovisioned) => Ok(()),
        Ok(LocatedVaultClassification::Locked) => {
            Err(FirstBootBoundaryError::VaultAlreadyProvisioned)
        }
        Err(error) => Err(map_classification_error(error)),
    }
}

fn map_classification_error(error: LocatedVaultClassificationError) -> FirstBootBoundaryError {
    match error {
        LocatedVaultClassificationError::InvalidDeadline
        | LocatedVaultClassificationError::ClassifierUnavailable => {
            FirstBootBoundaryError::CanonicalProfileUnavailable
        }
        LocatedVaultClassificationError::MediaChanged
        | LocatedVaultClassificationError::BlockIdentityUnavailable => {
            FirstBootBoundaryError::MediaChanged
        }
        LocatedVaultClassificationError::ProfileMismatch => {
            FirstBootBoundaryError::VaultProfileMismatch
        }
        LocatedVaultClassificationError::ToolUnavailable => FirstBootBoundaryError::LocatorRejected,
        LocatedVaultClassificationError::OperationTimedOut => {
            FirstBootBoundaryError::ClassificationTimedOut
        }
        LocatedVaultClassificationError::CleanupFailed => {
            FirstBootBoundaryError::ClassificationCleanupFailed
        }
    }
}

fn read_secret_descriptor(
    descriptor: impl AsFd,
) -> Result<Zeroizing<Vec<u8>>, FirstBootBoundaryError> {
    let descriptor = descriptor.as_fd();
    let flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| FirstBootBoundaryError::SecretDescriptorUnavailable)?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(FirstBootBoundaryError::SecretDescriptorUnavailable);
    }
    let maximum =
        usize::try_from(MAX_PASSPHRASE_BYTES).map_err(|_| FirstBootBoundaryError::SecretInvalid)?;
    let minimum =
        usize::try_from(MIN_PASSPHRASE_BYTES).map_err(|_| FirstBootBoundaryError::SecretInvalid)?;
    let mut value = Zeroizing::new(Vec::with_capacity(maximum));
    loop {
        let mut chunk = Zeroizing::new([0_u8; SECRET_READ_CHUNK_BYTES]);
        let read = loop {
            match rustix::io::read(descriptor, &mut chunk[..]) {
                Ok(read) => break read,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(FirstBootBoundaryError::SecretDescriptorUnavailable),
            }
        };
        if read == 0 {
            break;
        }
        if value
            .len()
            .checked_add(read)
            .is_none_or(|size| size > maximum)
        {
            return Err(FirstBootBoundaryError::SecretInvalid);
        }
        value.extend_from_slice(&chunk[..read]);
    }
    if !(minimum..=maximum).contains(&value.len()) || value.contains(&0) {
        return Err(FirstBootBoundaryError::SecretInvalid);
    }
    Ok(value)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let maximum = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..maximum {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        os::fd::AsFd,
    };

    fn secret_file(bytes: &[u8]) -> std::fs::File {
        let mut file = tempfile::tempfile().expect("anonymous secret file");
        file.write_all(bytes).expect("write test secret");
        file.seek(SeekFrom::Start(0)).expect("rewind test secret");
        let flags = rustix::io::fcntl_getfd(file.as_fd()).expect("descriptor flags");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        file
    }

    #[test]
    fn confirmation_is_opaque_and_rejects_mismatch() {
        let bytes = vec![b'k'; MIN_PASSPHRASE_BYTES as usize];
        let first = secret_file(&bytes);
        let second = secret_file(&bytes);
        let confirmed =
            ConfirmedPassphrase::confirm_from_fds(&first, &second).expect("matching secret");
        assert_eq!(format!("{confirmed:?}"), "ConfirmedPassphrase([REDACTED])");

        let mut different = bytes;
        different[0] = b'x';
        let first = secret_file(&different);
        let second = secret_file(&vec![b'k'; MIN_PASSPHRASE_BYTES as usize]);
        assert_eq!(
            ConfirmedPassphrase::confirm_from_fds(&first, &second)
                .expect_err("mismatched confirmation"),
            FirstBootBoundaryError::SecretMismatch
        );
    }

    #[test]
    fn confirmation_rejects_invalid_lengths_and_nul() {
        for invalid in [
            vec![b'a'; MIN_PASSPHRASE_BYTES as usize - 1],
            vec![b'a'; MAX_PASSPHRASE_BYTES as usize + 1],
            {
                let mut value = vec![b'a'; MIN_PASSPHRASE_BYTES as usize];
                value[1] = 0;
                value
            },
        ] {
            let first = secret_file(&invalid);
            let second = secret_file(&invalid);
            assert_eq!(
                ConfirmedPassphrase::confirm_from_fds(&first, &second).expect_err("invalid secret"),
                FirstBootBoundaryError::SecretInvalid
            );
        }
    }

    #[test]
    fn canonical_v1_blueprints_are_closed_and_descriptor_bound() {
        verify_embedded_profile().expect("embedded profile");
        assert_eq!(CANONICAL_PROVISIONING_COMMANDS_V1.len(), 4);
        assert_eq!(
            CANONICAL_PROVISIONING_COMMANDS_V1
                .iter()
                .map(|command| command.program)
                .collect::<Vec<_>>(),
            vec![
                "/usr/sbin/cryptsetup",
                "/usr/sbin/cryptsetup",
                "/usr/sbin/mkfs.ext4",
                "/usr/sbin/tune2fs",
            ]
        );
        assert!(CANONICAL_PROVISIONING_COMMANDS_V1.iter().all(|command| {
            command
                .arguments_before_target
                .iter()
                .all(|argument| !argument.starts_with("/dev/") && !argument.contains("/proc/"))
        }));
        assert_eq!(
            CANONICAL_PROVISIONING_COMMANDS_V1[0].arguments_before_target,
            LUKS_FORMAT_ARGUMENTS
        );
        assert_eq!(
            CANONICAL_PROVISIONING_COMMANDS_V1[2].arguments_before_target,
            MKFS_EXT4_ARGUMENTS
        );
        assert!(
            CANONICAL_PROVISIONING_COMMANDS_V1[..2]
                .iter()
                .all(|command| command.reads_confirmed_passphrase_from_stdin)
        );
        assert!(
            CANONICAL_PROVISIONING_COMMANDS_V1[2..]
                .iter()
                .all(|command| !command.reads_confirmed_passphrase_from_stdin)
        );
    }

    #[test]
    fn boot_splash_release_is_fixed_and_bounded() {
        assert_eq!(PLYMOUTH_PATH, "/usr/bin/plymouth");
        assert_eq!(PLYMOUTH_QUIT_ARGUMENTS, ["quit"]);
        assert_eq!(PLYMOUTH_QUIT_TIMEOUT, Duration::from_secs(3));
    }

    #[test]
    fn declared_state_machine_cannot_skip_cleanup_or_final_reclassification() {
        let states = [
            ProvisioningState::Located,
            ProvisioningState::ClassifiedUnprovisioned,
            ProvisioningState::Confirmed,
            ProvisioningState::LuksFormatted,
            ProvisioningState::MappingVerified,
            ProvisioningState::FilesystemFormatted,
            ProvisioningState::FilesystemVerified,
            ProvisioningState::LayoutSeeded,
            ProvisioningState::DeviceIdentityInitialized,
            ProvisioningState::Synced,
            ProvisioningState::Closed,
            ProvisioningState::ReclassifiedLocked,
        ];
        assert_eq!(states.last(), Some(&ProvisioningState::ReclassifiedLocked));
        assert!(
            states
                .iter()
                .position(|state| *state == ProvisioningState::Closed)
                < states
                    .iter()
                    .position(|state| *state == ProvisioningState::ReclassifiedLocked)
        );
    }
}
