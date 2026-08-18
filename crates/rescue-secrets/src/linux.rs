use super::{
    MountAttestationClaims, RescueSecretError, VAULT_MARKER_NAME, VAULT_MARKER_V1,
    VaultMountAttestation, VaultOwner,
};
use crate::application_store::{RescueApplicationStoreError, RescueVaultApplicationStore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kernaid_device_identity::DeviceIdentity;
use kernaid_storage::{
    JOURNAL_KEY_BYTES, JournalAnchor, JournalError, JournalKey, JournalSecretStore,
    SecretStoreError, SecureJournal,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, RawDir, RenameFlags,
        ResolveFlags, Stat, StatxFlags,
    },
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt, fs::FileExt},
    path::{Component, Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

const STATE_DIRECTORY: &str = ".kernaid-secure-state-v1";
const LOCK_NAME: &str = ".kernaid-rescue-secrets.lock";
pub(crate) const JOURNAL_KEY_NAME: &str = "journal-key";
pub(crate) const JOURNAL_ANCHOR_NAME: &str = "journal-anchor";
pub(crate) const DEVICE_IDENTITY_NAME: &str = "device-identity";
pub(crate) const JOURNAL_DATABASE_NAME: &str = "audit.sqlite3";
pub(crate) const JOURNAL_WAL_NAME: &str = "audit.sqlite3-wal";
pub(crate) const JOURNAL_SHM_NAME: &str = "audit.sqlite3-shm";
const ENVELOPE_PREFIX: &[u8] = b"kernaid-rescue-secret-v1:";
const IDENTITY_SEED_BYTES: usize = 32;
const MAX_ENVELOPE_BYTES: usize = 256;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
#[cfg(feature = "experimental-vault-manager")]
const MAX_MOUNTINFO_LINES: usize = 4096;
const MAX_DM_UUID_BYTES: u64 = 512;
const MAX_DM_UUID_LENGTH: usize = 128;
const DM_LUKS2_PREFIX: &[u8] = b"CRYPT-LUKS2-";
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_PREFIX_BYTES: usize = 64;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_ERRORS_OFFSET: usize = 60;
const EXT4_ERRORS_REMOUNT_READ_ONLY: u16 = 2;
const ORPHAN_SCAN_BUFFER_BYTES: usize = 8192;
const MAX_STATE_DIRECTORY_ENTRIES: usize = 288;
const MAX_STATE_DIRECTORY_NAME_BYTES: usize = 128;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Owns the vault-wide lock and creates scoped journal and identity handles.
/// Derived handles borrow this value and therefore cannot outlive the verified
/// mapping/mount boundary that owns it.
pub struct RescueVaultSecrets {
    pub(crate) inner: VaultInner,
}

impl RescueVaultSecrets {
    /// Open a real Rescue vault. The root must already be an unlocked LUKS2
    /// filesystem mount and `attestation` must have been minted by KernAid's
    /// privileged mount manager for the current mapping/mount checkpoints. Any
    /// ambiguity is an error.
    pub fn open(
        root: impl AsRef<Path>,
        attestation: &VaultMountAttestation,
    ) -> Result<Self, RescueSecretError> {
        Self::open_with_policy(
            root.as_ref(),
            VaultOwner { uid: 0, gid: 0 },
            MountPolicy::attested(attestation.claims),
        )
    }

    /// Build a journal secret-store sharing this vault's exclusive lock.
    #[must_use]
    #[cfg(feature = "privileged-probe")]
    pub fn journal_store(&self) -> RescueJournalSecretStore<'_> {
        RescueJournalSecretStore { inner: &self.inner }
    }

    #[cfg(all(test, not(feature = "privileged-probe")))]
    pub(crate) fn journal_store(&self) -> RescueJournalSecretStore<'_> {
        RescueJournalSecretStore { inner: &self.inner }
    }

    /// Build a device-identity store sharing this vault's exclusive lock.
    #[must_use]
    #[cfg(feature = "privileged-probe")]
    pub fn device_identity_store(&self) -> RescueDeviceIdentityStore<'_> {
        RescueDeviceIdentityStore { inner: &self.inner }
    }

    #[cfg(all(test, not(feature = "privileged-probe")))]
    pub(crate) fn device_identity_store(&self) -> RescueDeviceIdentityStore<'_> {
        RescueDeviceIdentityStore { inner: &self.inner }
    }

    /// Explicitly open or initialize the encrypted audit journal. Unlike
    /// [`Self::open`], this is a state-mutating application operation and must
    /// only be called after the pre-provisioned vault boundary is accepted.
    #[cfg(feature = "privileged-probe")]
    pub fn open_journal(
        &self,
    ) -> Result<SecureJournal<RescueJournalSecretStore<'_>>, JournalError> {
        self.inner.open_application_journal()
    }

    #[cfg(all(test, not(feature = "privileged-probe")))]
    pub(crate) fn open_journal(
        &self,
    ) -> Result<SecureJournal<RescueJournalSecretStore<'_>>, JournalError> {
        self.inner.open_application_journal()
    }

    /// Open the closed, descriptor-oriented Rescue application store.
    ///
    /// The device identity must already exist. This call never creates or
    /// replaces it and does not expose a raw journal append or signing API.
    pub fn open_application_store(
        &self,
    ) -> Result<RescueVaultApplicationStore<'_>, RescueApplicationStoreError> {
        RescueVaultApplicationStore::open(&self.inner)
    }

    /// Open the pre-provisioned Codex home as a descriptor-only capability.
    ///
    /// This deliberately never creates, repairs, renames, or changes ownership
    /// of the directory. Provisioning is a separate trusted writer. `None`
    /// means that writer has not configured a Codex home yet; every ambiguous
    /// or unsafe object is an error.
    #[cfg(feature = "experimental-codex-home-lease")]
    pub(crate) fn open_codex_home_lease(&self) -> Result<Option<OwnedFd>, RescueSecretError> {
        self.open_codex_home_lease_for(crate::CODEX_AGENT_UID, crate::CODEX_AGENT_GID)
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    fn open_codex_home_lease_for(
        &self,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Option<OwnedFd>, RescueSecretError> {
        let _guard = self.inner.operation_guard()?;
        self.inner.ensure_integrity()?;
        let descriptor = match open_child(
            &self.inner.root_fd,
            Path::new(crate::CODEX_HOME_NAME),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(RescueSecretError::UnsafePath),
        };
        validate_codex_home_descriptor(
            &descriptor,
            &self.inner.root_fd,
            self.inner.root_mount_id,
            expected_uid,
            expected_gid,
        )?;
        let named = rfs::statat(
            &self.inner.root_fd,
            crate::CODEX_HOME_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RescueSecretError::StaleVault)?;
        validate_codex_home_stat(&named, expected_uid, expected_gid)?;
        let opened = rfs::fstat(&descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
        if opened.st_dev != named.st_dev || opened.st_ino != named.st_ino {
            return Err(RescueSecretError::StaleVault);
        }
        self.inner.ensure_integrity()?;
        Ok(Some(descriptor))
    }

    #[cfg(all(test, feature = "experimental-codex-home-lease"))]
    fn open_codex_home_lease_for_test(&self) -> Result<Option<OwnedFd>, RescueSecretError> {
        self.open_codex_home_lease_for(self.inner.owner.uid, self.inner.owner.gid)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        root: impl AsRef<Path>,
        owner: VaultOwner,
    ) -> Result<Self, RescueSecretError> {
        Self::open_with_policy(root.as_ref(), owner, MountPolicy::test_fixture())
    }

    fn open_with_policy(
        root: &Path,
        owner: VaultOwner,
        mount_policy: MountPolicy,
    ) -> Result<Self, RescueSecretError> {
        let root_path = normalize_absolute_root(root)?;
        let root_fd = open_root(&root_path)?;
        let root_state = directory_state(&root_fd, owner, DIRECTORY_MODE)?;
        let named_root = stat_root_path(&root_path)?;
        validate_directory_stat(&named_root, owner, DIRECTORY_MODE)?;
        if !root_state.same_object(&FileState::from_stat(&named_root)) {
            return Err(RescueSecretError::StaleVault);
        }

        let root_mount_id = descriptor_mount_id(&root_fd)?;
        if let Some(attestation) = mount_policy.attestation {
            let observed = verify_luks2_mount(&root_path, &root_state, root_mount_id)?;
            observed.verify_attestation(attestation)?;
        }
        verify_marker(&root_fd, owner)?;

        let (lock_fd, lock_state) = acquire_vault_lock(&root_fd, owner)?;

        // Recheck all externally named objects after acquiring the lock. The
        // lock serializes cooperative manager instances; retained descriptors
        // and per-operation checks remain necessary for all other changes.
        let reopened = open_root(&root_path)?;
        let reopened_state = directory_state(&reopened, owner, DIRECTORY_MODE)?;
        if !root_state.same_object(&reopened_state)
            || descriptor_mount_id(&reopened)? != root_mount_id
        {
            return Err(RescueSecretError::StaleVault);
        }
        verify_marker(&root_fd, owner)?;

        let (state_fd, state_state) = open_existing_state_directory(&root_fd, owner)?;
        if state_state.device != root_state.device
            || descriptor_mount_id(&state_fd)? != root_mount_id
            || descriptor_mount_id(&lock_fd)? != root_mount_id
        {
            return Err(RescueSecretError::UnsafePath);
        }
        recover_or_reject_orphan_temporary_file(
            &state_fd,
            owner,
            state_state.device,
            root_mount_id,
        )?;

        let inner = VaultInner {
            root_path,
            root_fd,
            root_state,
            root_mount_id,
            state_fd,
            state_state,
            lock_fd,
            lock_state,
            owner,
            mount_policy,
            operation_lock: Mutex::new(()),
            application_lock: Mutex::new(()),
        };
        inner.ensure_integrity()?;
        Ok(Self { inner })
    }
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_home_descriptor(
    descriptor: &OwnedFd,
    root: &OwnedFd,
    expected_mount_id: u64,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RescueSecretError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_codex_home_stat(&stat, expected_uid, expected_gid)?;
    let root_stat = rfs::fstat(root).map_err(|_| RescueSecretError::StorageUnavailable)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    if stat.st_dev != root_stat.st_dev
        || descriptor_mount_id(descriptor)? != expected_mount_id
        || !crate::codex_home_status_flags_are_exact(status)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueSecretError::UnsafePath);
    }
    Ok(())
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_home_stat(
    stat: &Stat,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RescueSecretError> {
    if !FileType::from_raw_mode(stat.st_mode).is_dir() || stat.st_nlink < 2 {
        return Err(RescueSecretError::UnsafePath);
    }
    if stat.st_uid != expected_uid || stat.st_gid != expected_gid {
        return Err(RescueSecretError::WrongOwner);
    }
    if mode_bits(stat) != DIRECTORY_MODE {
        return Err(RescueSecretError::UnsafePermissions);
    }
    Ok(())
}

/// LUKS-vault implementation of the encrypted journal's secret-store trait.
pub struct RescueJournalSecretStore<'vault> {
    pub(crate) inner: &'vault VaultInner,
}

impl JournalSecretStore for RescueJournalSecretStore<'_> {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        let decoded = self
            .inner
            .load_secret(SecretKind::JournalKey)
            .map_err(to_journal_error)?;
        let Some(decoded) = decoded else {
            return Ok(None);
        };
        let mut key = Zeroizing::new([0_u8; JOURNAL_KEY_BYTES]);
        key.copy_from_slice(&decoded);
        Ok(Some(JournalKey::from_zeroizing(key)))
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        self.inner
            .store_secret(
                SecretKind::JournalKey,
                key.expose_secret(),
                ReplaceMode::Replace,
            )
            .map_err(to_journal_error)
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        let decoded = self
            .inner
            .load_secret(SecretKind::JournalAnchor)
            .map_err(to_journal_error)?;
        decoded
            .map(|bytes| {
                JournalAnchor::from_bytes(&bytes)
                    .map_err(|_| to_journal_error(RescueSecretError::InvalidStoredValue))
            })
            .transpose()
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        let bytes = anchor.to_bytes();
        self.inner
            .store_secret(SecretKind::JournalAnchor, &bytes, ReplaceMode::Replace)
            .map_err(to_journal_error)
    }
}

impl RescueJournalSecretStore<'_> {
    #[cfg(test)]
    fn fail_key_replace_before_rename(&self, key: &JournalKey) -> Result<(), RescueSecretError> {
        self.inner.store_secret_with_stage(
            SecretKind::JournalKey,
            key.expose_secret(),
            ReplaceMode::Replace,
            WriteStage::FailBeforeRename,
        )
    }
}

/// Explicit Rescue device-identity persistence. Loading never creates, and
/// creation never overwrites an existing or malformed identity.
pub struct RescueDeviceIdentityStore<'vault> {
    pub(crate) inner: &'vault VaultInner,
}

impl RescueDeviceIdentityStore<'_> {
    pub fn load_device_identity(&mut self) -> Result<Option<DeviceIdentity>, RescueSecretError> {
        let decoded = self.inner.load_secret(SecretKind::DeviceIdentity)?;
        decoded
            .map(|seed| {
                DeviceIdentity::from_seed(&seed).map_err(|_| RescueSecretError::InvalidStoredValue)
            })
            .transpose()
    }

    /// Persist a caller-created identity only if no identity file exists.
    #[cfg(any(test, feature = "privileged-probe"))]
    pub fn store_new_device_identity(
        &mut self,
        identity: &DeviceIdentity,
    ) -> Result<(), RescueSecretError> {
        let seed = identity.export_seed_for_encrypted_storage();
        self.inner.store_secret(
            SecretKind::DeviceIdentity,
            seed.as_slice(),
            ReplaceMode::CreateOnly,
        )?;
        let persisted = self
            .load_device_identity()?
            .ok_or(RescueSecretError::WriteVerificationFailed)?;
        if persisted.public_key() != identity.public_key() {
            return Err(RescueSecretError::ConcurrentWrite);
        }
        Ok(())
    }

    /// Generate and persist an identity as an explicit first-run action.
    /// There is intentionally no load-or-create API.
    #[cfg(any(test, feature = "privileged-probe"))]
    pub fn create_device_identity(&mut self) -> Result<DeviceIdentity, RescueSecretError> {
        if self.load_device_identity()?.is_some() {
            return Err(RescueSecretError::IdentityAlreadyExists);
        }
        let identity = DeviceIdentity::generate();
        self.store_new_device_identity(&identity)?;
        Ok(identity)
    }
}

pub(crate) struct VaultInner {
    root_path: PathBuf,
    root_fd: OwnedFd,
    root_state: FileState,
    root_mount_id: u64,
    state_fd: OwnedFd,
    state_state: FileState,
    lock_fd: OwnedFd,
    lock_state: FileState,
    owner: VaultOwner,
    mount_policy: MountPolicy,
    operation_lock: Mutex<()>,
    application_lock: Mutex<()>,
}

impl VaultInner {
    pub(crate) fn preflight_journal_layout(&self) -> Result<(), RescueSecretError> {
        let _guard = self.operation_guard()?;
        self.ensure_integrity()?;
        let database = verify_optional_journal_file(self, JOURNAL_DATABASE_NAME)?;
        let wal = verify_optional_journal_file(self, JOURNAL_WAL_NAME)?;
        let shm = verify_optional_journal_file(self, JOURNAL_SHM_NAME)?;
        if !database && (wal || shm) {
            return Err(RescueSecretError::UnsafePath);
        }
        Ok(())
    }

    pub(crate) fn operation_guard(&self) -> Result<MutexGuard<'_, ()>, RescueSecretError> {
        self.operation_lock
            .lock()
            .map_err(|_| RescueSecretError::StorageUnavailable)
    }

    pub(crate) fn application_guard(&self) -> Result<MutexGuard<'_, ()>, RescueSecretError> {
        self.application_lock
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => RescueSecretError::VaultLocked,
                std::sync::TryLockError::Poisoned(_) => RescueSecretError::StorageUnavailable,
            })
    }

    pub(crate) fn ensure_integrity(&self) -> Result<(), RescueSecretError> {
        let root_descriptor = directory_state(&self.root_fd, self.owner, DIRECTORY_MODE)?;
        if !root_descriptor.same_object(&self.root_state)
            || descriptor_mount_id(&self.root_fd)? != self.root_mount_id
        {
            return Err(RescueSecretError::StaleVault);
        }
        let reopened = open_root(&self.root_path).map_err(|_| RescueSecretError::StaleVault)?;
        let reopened_state = directory_state(&reopened, self.owner, DIRECTORY_MODE).map_err(
            |error| match error {
                RescueSecretError::WrongOwner | RescueSecretError::UnsafePermissions => error,
                _ => RescueSecretError::StaleVault,
            },
        )?;
        if !reopened_state.same_object(&self.root_state)
            || descriptor_mount_id(&reopened)? != self.root_mount_id
        {
            return Err(RescueSecretError::StaleVault);
        }
        if let Some(attestation) = self.mount_policy.attestation {
            let observed =
                verify_luks2_mount(&self.root_path, &self.root_state, self.root_mount_id)?;
            observed.verify_attestation(attestation)?;
        }

        verify_marker(&self.root_fd, self.owner)?;

        let state_descriptor = directory_state(&self.state_fd, self.owner, DIRECTORY_MODE)?;
        let state_named = stat_named(&self.root_fd, STATE_DIRECTORY)?;
        validate_directory_stat(&state_named, self.owner, DIRECTORY_MODE)?;
        let state_named = FileState::from_stat(&state_named);
        if !state_descriptor.same_object(&self.state_state)
            || !state_named.same_object(&self.state_state)
            || state_descriptor.device != self.root_state.device
            || descriptor_mount_id(&self.state_fd)? != self.root_mount_id
        {
            return Err(RescueSecretError::StaleVault);
        }

        let lock_descriptor = regular_file_state(&self.lock_fd, self.owner, FILE_MODE)?;
        let lock_named = stat_named(&self.root_fd, LOCK_NAME)?;
        validate_regular_stat(&lock_named, self.owner, FILE_MODE)?;
        let lock_named = FileState::from_stat(&lock_named);
        if !lock_descriptor.same_object(&self.lock_state)
            || !lock_named.same_object(&self.lock_state)
            || descriptor_mount_id(&self.lock_fd)? != self.root_mount_id
        {
            return Err(RescueSecretError::StaleVault);
        }
        Ok(())
    }

    pub(crate) fn open_application_journal(
        &self,
    ) -> Result<SecureJournal<RescueJournalSecretStore<'_>>, JournalError> {
        self.preflight_journal_layout()
            .map_err(|_| JournalError::InvalidPath)?;
        let path = self
            .root_path
            .join(STATE_DIRECTORY)
            .join(JOURNAL_DATABASE_NAME);
        SecureJournal::open(&path, RescueJournalSecretStore { inner: self })
    }

    pub(crate) fn state_directory_fd(&self) -> &OwnedFd {
        &self.state_fd
    }

    pub(crate) const fn state_device(&self) -> u64 {
        self.state_state.device
    }

    pub(crate) const fn root_mount_id(&self) -> u64 {
        self.root_mount_id
    }

    pub(crate) const fn owner(&self) -> VaultOwner {
        self.owner
    }

    fn load_secret(
        &self,
        kind: SecretKind,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RescueSecretError> {
        let _guard = self.operation_guard()?;
        self.ensure_integrity()?;
        let Some(encoded) = read_optional_named(&self.state_fd, kind.filename(), self.owner)?
        else {
            return Ok(None);
        };
        decode_secret(kind, &encoded).map(Some)
    }

    fn store_secret(
        &self,
        kind: SecretKind,
        bytes: &[u8],
        replace_mode: ReplaceMode,
    ) -> Result<(), RescueSecretError> {
        self.store_secret_with_stage(kind, bytes, replace_mode, WriteStage::Complete)
    }

    fn store_secret_with_stage(
        &self,
        kind: SecretKind,
        bytes: &[u8],
        replace_mode: ReplaceMode,
        stage: WriteStage,
    ) -> Result<(), RescueSecretError> {
        if bytes.len() != kind.bytes() {
            return Err(RescueSecretError::InvalidStoredValue);
        }
        let encoded = encode_secret(kind, bytes)?;
        let _guard = self.operation_guard()?;
        self.ensure_integrity()?;
        atomic_store(
            &self.state_fd,
            kind,
            &encoded,
            self.owner,
            replace_mode,
            stage,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MountPolicy {
    attestation: Option<MountAttestationClaims>,
}

impl MountPolicy {
    const fn attested(attestation: MountAttestationClaims) -> Self {
        Self {
            attestation: Some(attestation),
        }
    }

    #[cfg(test)]
    const fn test_fixture() -> Self {
        Self { attestation: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplaceMode {
    Replace,
    CreateOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteStage {
    Complete,
    #[cfg(test)]
    FailBeforeRename,
    #[cfg(test)]
    CrashAfterDirectorySync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretKind {
    JournalKey,
    JournalAnchor,
    DeviceIdentity,
}

impl SecretKind {
    const fn label(self) -> &'static str {
        match self {
            Self::JournalKey => "journal-key-v1",
            Self::JournalAnchor => "journal-anchor-v2",
            Self::DeviceIdentity => "device-identity-seed-v1",
        }
    }

    const fn filename(self) -> &'static str {
        match self {
            Self::JournalKey => JOURNAL_KEY_NAME,
            Self::JournalAnchor => JOURNAL_ANCHOR_NAME,
            Self::DeviceIdentity => DEVICE_IDENTITY_NAME,
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::JournalKey => JOURNAL_KEY_BYTES,
            Self::JournalAnchor => JournalAnchor::ENCODED_BYTES,
            Self::DeviceIdentity => IDENTITY_SEED_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileState {
    device: u64,
    inode: u64,
    size: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanos: u64,
    changed_seconds: i64,
    changed_nanos: u64,
}

impl FileState {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: stat.st_nlink,
            modified_seconds: stat.st_mtime,
            modified_nanos: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanos: stat.st_ctime_nsec,
        }
    }

    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

fn normalize_absolute_root(root: &Path) -> Result<PathBuf, RescueSecretError> {
    if !root.is_absolute() || root == Path::new("/") {
        return Err(RescueSecretError::InvalidRoot);
    }
    let mut normalized = PathBuf::new();
    let mut normal_components = 0_usize;
    for component in root.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(value) => {
                normalized.push(value);
                normal_components += 1;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(RescueSecretError::InvalidRoot);
            }
        }
    }
    if normal_components == 0 || normalized.as_os_str().as_bytes().contains(&0) {
        return Err(RescueSecretError::InvalidRoot);
    }
    Ok(normalized)
}

fn open_root(path: &Path) -> Result<OwnedFd, RescueSecretError> {
    rfs::openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueSecretError::UnsafePath)
}

fn open_child(
    directory: &OwnedFd,
    path: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, rustix::io::Errno> {
    rfs::openat2(
        directory,
        path,
        flags,
        mode,
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
}

fn descriptor_mount_id(descriptor: impl AsFd) -> Result<u64, RescueSecretError> {
    let stat = rfs::statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| RescueSecretError::StorageUnavailable)?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID)
        || stat.stx_mnt_id == 0
    {
        return Err(RescueSecretError::StorageUnavailable);
    }
    Ok(stat.stx_mnt_id)
}

fn stat_root_path(path: &Path) -> Result<Stat, RescueSecretError> {
    rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| RescueSecretError::InvalidRoot)
}

fn stat_named(directory: &OwnedFd, name: &str) -> Result<Stat, RescueSecretError> {
    rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::UnsafePath)
}

fn mode_bits(stat: &Stat) -> u32 {
    stat.st_mode & 0o7777
}

fn validate_owner(stat: &Stat, owner: VaultOwner) -> Result<(), RescueSecretError> {
    if stat.st_uid != owner.uid || stat.st_gid != owner.gid {
        return Err(RescueSecretError::WrongOwner);
    }
    Ok(())
}

fn validate_directory_stat(
    stat: &Stat,
    owner: VaultOwner,
    expected_mode: u32,
) -> Result<(), RescueSecretError> {
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(RescueSecretError::UnsafePath);
    }
    validate_owner(stat, owner)?;
    if mode_bits(stat) != expected_mode {
        return Err(RescueSecretError::UnsafePermissions);
    }
    Ok(())
}

fn validate_regular_stat(
    stat: &Stat,
    owner: VaultOwner,
    expected_mode: u32,
) -> Result<(), RescueSecretError> {
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_nlink != 1 || stat.st_size < 0 {
        return Err(RescueSecretError::UnsafePath);
    }
    validate_owner(stat, owner)?;
    if mode_bits(stat) != expected_mode {
        return Err(RescueSecretError::UnsafePermissions);
    }
    Ok(())
}

fn directory_state(
    descriptor: &OwnedFd,
    owner: VaultOwner,
    expected_mode: u32,
) -> Result<FileState, RescueSecretError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_directory_stat(&stat, owner, expected_mode)?;
    Ok(FileState::from_stat(&stat))
}

fn regular_file_state(
    descriptor: &OwnedFd,
    owner: VaultOwner,
    expected_mode: u32,
) -> Result<FileState, RescueSecretError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_regular_stat(&stat, owner, expected_mode)?;
    Ok(FileState::from_stat(&stat))
}

fn verify_marker(root: &OwnedFd, owner: VaultOwner) -> Result<(), RescueSecretError> {
    let marker = read_optional_named(root, VAULT_MARKER_NAME, owner)
        .map_err(|_| RescueSecretError::InvalidMarker)?
        .ok_or(RescueSecretError::InvalidMarker)?;
    if marker.as_slice() != VAULT_MARKER_V1 {
        return Err(RescueSecretError::InvalidMarker);
    }
    Ok(())
}

fn acquire_vault_lock(
    root: &OwnedFd,
    owner: VaultOwner,
) -> Result<(OwnedFd, FileState), RescueSecretError> {
    let lock_fd = open_child(
        root,
        Path::new(LOCK_NAME),
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueSecretError::UnsafePath)?;
    let state = regular_file_state(&lock_fd, owner, FILE_MODE)?;
    rfs::flock(&lock_fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
            RescueSecretError::VaultLocked
        } else {
            RescueSecretError::StorageUnavailable
        }
    })?;
    let named = stat_named(root, LOCK_NAME)?;
    validate_regular_stat(&named, owner, FILE_MODE)?;
    if !state.same_object(&FileState::from_stat(&named)) {
        return Err(RescueSecretError::StaleVault);
    }
    Ok((lock_fd, state))
}

fn open_existing_state_directory(
    root: &OwnedFd,
    owner: VaultOwner,
) -> Result<(OwnedFd, FileState), RescueSecretError> {
    let descriptor = open_child(
        root,
        Path::new(STATE_DIRECTORY),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueSecretError::UnsafePath)?;
    let state = directory_state(&descriptor, owner, DIRECTORY_MODE)?;
    let named = stat_named(root, STATE_DIRECTORY)?;
    validate_directory_stat(&named, owner, DIRECTORY_MODE)?;
    if !state.same_object(&FileState::from_stat(&named)) {
        return Err(RescueSecretError::StaleVault);
    }
    Ok((descriptor, state))
}

fn verify_optional_journal_file(vault: &VaultInner, name: &str) -> Result<bool, RescueSecretError> {
    let descriptor = match open_child(
        &vault.state_fd,
        Path::new(name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
        Err(_) => return Err(RescueSecretError::UnsafePath),
    };
    let descriptor_state = regular_file_state(&descriptor, vault.owner, FILE_MODE)?;
    if descriptor_state.device != vault.state_state.device
        || descriptor_mount_id(&descriptor)? != vault.root_mount_id
    {
        return Err(RescueSecretError::UnsafePath);
    }
    let named = rfs::statat(&vault.state_fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::StaleVault)?;
    validate_regular_stat(&named, vault.owner, FILE_MODE)?;
    if descriptor_state != FileState::from_stat(&named) {
        return Err(RescueSecretError::StaleVault);
    }
    Ok(true)
}

fn recover_or_reject_orphan_temporary_file(
    directory: &OwnedFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(), RescueSecretError> {
    let scan_fd = open_child(
        directory,
        Path::new("."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueSecretError::UnsafePath)?;
    if descriptor_mount_id(&scan_fd)? != expected_mount_id {
        return Err(RescueSecretError::UnsafePath);
    }

    let mut orphan_name = None;
    let mut entry_count = 0_usize;
    let mut buffer = [MaybeUninit::<u8>::uninit(); ORPHAN_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(&scan_fd, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| RescueSecretError::StorageUnavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        entry_count = entry_count
            .checked_add(1)
            .ok_or(RescueSecretError::UnsafePath)?;
        if entry_count > MAX_STATE_DIRECTORY_ENTRIES || name.len() > MAX_STATE_DIRECTORY_NAME_BYTES
        {
            return Err(RescueSecretError::UnsafePath);
        }
        if !name.starts_with(b".tmp-") {
            continue;
        }
        if name.len() != 37
            || !name[5..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || orphan_name.is_some()
        {
            return Err(RescueSecretError::UnsafePath);
        }
        orphan_name = Some(
            std::str::from_utf8(name)
                .map_err(|_| RescueSecretError::UnsafePath)?
                .to_owned(),
        );
    }
    let Some(orphan_name) = orphan_name else {
        return Ok(());
    };

    let orphan = open_recovery_file(
        directory,
        &orphan_name,
        owner,
        expected_device,
        expected_mount_id,
    )?
    .ok_or(RescueSecretError::UnsafePath)?;

    let mut decoded_kind = None;
    for kind in [
        SecretKind::JournalKey,
        SecretKind::JournalAnchor,
        SecretKind::DeviceIdentity,
    ] {
        if decode_secret(kind, &orphan.envelope).is_ok() && decoded_kind.replace(kind).is_some() {
            return Err(RescueSecretError::UnsafePath);
        }
    }
    let kind = decoded_kind.ok_or(RescueSecretError::UnsafePath)?;
    let orphan_value = decode_secret(kind, &orphan.envelope)?;
    validate_recovery_secret_value(kind, &orphan_value)?;
    let final_file = open_recovery_file(
        directory,
        kind.filename(),
        owner,
        expected_device,
        expected_mount_id,
    )?;
    match final_file {
        None => {
            recheck_open_recovery_file(directory, &orphan_name, owner, &orphan)?;
            if optional_named_state(directory, kind.filename(), owner)?.is_some() {
                return Err(RescueSecretError::ConcurrentWrite);
            }
            rfs::renameat_with(
                directory,
                &orphan_name,
                directory,
                kind.filename(),
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| RescueSecretError::ConcurrentWrite)?;
            recheck_open_recovery_file_same_object(directory, kind.filename(), owner, &orphan)?;
            sync_directory(directory)?;
            let persisted = open_recovery_file(
                directory,
                kind.filename(),
                owner,
                expected_device,
                expected_mount_id,
            )?
            .ok_or(RescueSecretError::WriteVerificationFailed)?;
            if !persisted.state.same_object(&orphan.state)
                || persisted.envelope.as_slice() != orphan.envelope.as_slice()
                || decode_secret(kind, &persisted.envelope)?.as_slice() != orphan_value.as_slice()
            {
                return Err(RescueSecretError::WriteVerificationFailed);
            }
        }
        Some(final_file) => {
            let final_value = decode_secret(kind, &final_file.envelope)
                .map_err(|_| RescueSecretError::UnsafePath)?;
            validate_recovery_secret_value(kind, &final_value)?;
            if kind != SecretKind::JournalAnchor
                && final_value.as_slice() != orphan_value.as_slice()
            {
                return Err(RescueSecretError::UnsafePath);
            }
            recheck_open_recovery_file(directory, kind.filename(), owner, &final_file)?;
            recheck_open_recovery_file(directory, &orphan_name, owner, &orphan)?;
            rfs::unlinkat(directory, &orphan_name, AtFlags::empty())
                .map_err(|_| RescueSecretError::StorageUnavailable)?;
            let unlinked = rfs::fstat(&orphan.descriptor)
                .map_err(|_| RescueSecretError::StorageUnavailable)?;
            if !orphan.state.same_object(&FileState::from_stat(&unlinked)) || unlinked.st_nlink != 0
            {
                return Err(RescueSecretError::ConcurrentWrite);
            }
            if optional_named_state(directory, &orphan_name, owner)?.is_some() {
                return Err(RescueSecretError::ConcurrentWrite);
            }
            recheck_open_recovery_file(directory, kind.filename(), owner, &final_file)?;
            sync_directory(directory)?;
        }
    }
    Ok(())
}

struct OpenRecoveryFile {
    descriptor: File,
    state: FileState,
    envelope: Zeroizing<Vec<u8>>,
}

fn open_recovery_file(
    directory: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<Option<OpenRecoveryFile>, RescueSecretError> {
    let descriptor = match open_child(
        directory,
        Path::new(name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(RescueSecretError::UnsafePath),
    };
    let before = regular_file_state(&descriptor, owner, FILE_MODE)?;
    if before.device != expected_device || descriptor_mount_id(&descriptor)? != expected_mount_id {
        return Err(RescueSecretError::UnsafePath);
    }
    let size = usize::try_from(before.size).map_err(|_| RescueSecretError::InvalidStoredValue)?;
    if size > MAX_ENVELOPE_BYTES {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let mut descriptor = File::from(descriptor);
    let mut envelope = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut descriptor)
        .take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(envelope.as_mut())
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    if envelope.len() != size || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(RescueSecretError::StaleVault);
    }
    let opened = OpenRecoveryFile {
        descriptor,
        state: before,
        envelope,
    };
    recheck_open_recovery_file(directory, name, owner, &opened)?;
    Ok(Some(opened))
}

fn recheck_open_recovery_file(
    directory: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    opened: &OpenRecoveryFile,
) -> Result<(), RescueSecretError> {
    let descriptor_stat =
        rfs::fstat(&opened.descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_regular_stat(&descriptor_stat, owner, FILE_MODE)?;
    let named_stat = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::StaleVault)?;
    validate_regular_stat(&named_stat, owner, FILE_MODE)?;
    if FileState::from_stat(&descriptor_stat) != opened.state
        || FileState::from_stat(&named_stat) != opened.state
    {
        return Err(RescueSecretError::StaleVault);
    }
    Ok(())
}

fn recheck_open_recovery_file_same_object(
    directory: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    opened: &OpenRecoveryFile,
) -> Result<(), RescueSecretError> {
    let descriptor_stat =
        rfs::fstat(&opened.descriptor).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_regular_stat(&descriptor_stat, owner, FILE_MODE)?;
    let named_stat = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::StaleVault)?;
    validate_regular_stat(&named_stat, owner, FILE_MODE)?;
    let descriptor_state = FileState::from_stat(&descriptor_stat);
    let named_state = FileState::from_stat(&named_stat);
    if !opened.state.same_object(&descriptor_state) || descriptor_state != named_state {
        return Err(RescueSecretError::StaleVault);
    }
    Ok(())
}

fn validate_recovery_secret_value(kind: SecretKind, value: &[u8]) -> Result<(), RescueSecretError> {
    match kind {
        SecretKind::JournalKey => Ok(()),
        SecretKind::JournalAnchor => JournalAnchor::from_bytes(value)
            .map(|_| ())
            .map_err(|_| RescueSecretError::UnsafePath),
        SecretKind::DeviceIdentity => DeviceIdentity::from_seed(value)
            .map(|_| ())
            .map_err(|_| RescueSecretError::UnsafePath),
    }
}

fn read_optional_named(
    directory: &OwnedFd,
    name: &str,
    owner: VaultOwner,
) -> Result<Option<Zeroizing<Vec<u8>>>, RescueSecretError> {
    let descriptor = match open_child(
        directory,
        Path::new(name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(RescueSecretError::UnsafePath),
    };
    let before = regular_file_state(&descriptor, owner, FILE_MODE)?;
    let size = usize::try_from(before.size).map_err(|_| RescueSecretError::InvalidStoredValue)?;
    if size > MAX_ENVELOPE_BYTES {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut file)
        .take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(bytes.as_mut())
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    if bytes.len() != size || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(RescueSecretError::StaleVault);
    }
    let after_stat = rfs::fstat(&file).map_err(|_| RescueSecretError::StorageUnavailable)?;
    validate_regular_stat(&after_stat, owner, FILE_MODE)?;
    let after = FileState::from_stat(&after_stat);
    let named_stat = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::StaleVault)?;
    validate_regular_stat(&named_stat, owner, FILE_MODE)?;
    let named = FileState::from_stat(&named_stat);
    if before != after || after != named {
        return Err(RescueSecretError::StaleVault);
    }
    Ok(Some(bytes))
}

fn encode_secret(kind: SecretKind, value: &[u8]) -> Result<Zeroizing<Vec<u8>>, RescueSecretError> {
    if value.len() != kind.bytes() {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let encoded_value = encode_base64url(value)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        ENVELOPE_PREFIX.len() + kind.label().len() + encoded_value.len() + 2,
    ));
    envelope.extend_from_slice(ENVELOPE_PREFIX);
    envelope.extend_from_slice(kind.label().as_bytes());
    envelope.push(b':');
    envelope.extend_from_slice(&encoded_value);
    envelope.push(b'\n');
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    Ok(envelope)
}

fn decode_secret(
    kind: SecretKind,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RescueSecretError> {
    if envelope.len() > MAX_ENVELOPE_BYTES || !envelope.ends_with(b"\n") {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let mut expected_prefix = Vec::with_capacity(ENVELOPE_PREFIX.len() + kind.label().len() + 1);
    expected_prefix.extend_from_slice(ENVELOPE_PREFIX);
    expected_prefix.extend_from_slice(kind.label().as_bytes());
    expected_prefix.push(b':');
    if !envelope.starts_with(&expected_prefix) {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let encoded = &envelope[expected_prefix.len()..envelope.len() - 1];
    if encoded.is_empty() || encoded.contains(&b'=') {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    let mut decoded = Zeroizing::new(vec![0_u8; base64::decoded_len_estimate(encoded.len())]);
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode_slice(encoded, decoded.as_mut_slice())
        .map_err(|_| RescueSecretError::InvalidStoredValue)?;
    decoded.truncate(decoded_bytes);
    let canonical = encode_base64url(&decoded)?;
    if decoded.len() != kind.bytes() || canonical.as_slice() != encoded {
        return Err(RescueSecretError::InvalidStoredValue);
    }
    Ok(decoded)
}

fn encode_base64url(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, RescueSecretError> {
    let encoded_bytes =
        base64::encoded_len(value.len(), false).ok_or(RescueSecretError::InvalidStoredValue)?;
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_bytes]);
    let written = URL_SAFE_NO_PAD
        .encode_slice(value, encoded.as_mut_slice())
        .map_err(|_| RescueSecretError::InvalidStoredValue)?;
    encoded.truncate(written);
    Ok(encoded)
}

fn atomic_store(
    directory: &OwnedFd,
    kind: SecretKind,
    envelope: &[u8],
    owner: VaultOwner,
    replace_mode: ReplaceMode,
    stage: WriteStage,
) -> Result<(), RescueSecretError> {
    let existing = match read_optional_named(directory, kind.filename(), owner)? {
        Some(value) => {
            decode_secret(kind, &value)?;
            let stat = stat_named(directory, kind.filename())?;
            validate_regular_stat(&stat, owner, FILE_MODE)?;
            Some(FileState::from_stat(&stat))
        }
        None => None,
    };
    if existing.is_some() && replace_mode == ReplaceMode::CreateOnly {
        return Err(RescueSecretError::IdentityAlreadyExists);
    }

    let (mut file, state, mut guard) = create_temporary_file(directory, owner)?;
    file.write_all(envelope)
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    file.flush()
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    rfs::fchmod(&file, Mode::RUSR | Mode::WUSR)
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| RescueSecretError::StorageUnavailable)?;
    let written = read_optional_named(directory, guard.name(), owner)?
        .ok_or(RescueSecretError::WriteVerificationFailed)?;
    if written.as_slice() != envelope {
        return Err(RescueSecretError::WriteVerificationFailed);
    }
    sync_directory(directory)?;

    #[cfg(test)]
    if stage == WriteStage::FailBeforeRename {
        return Err(RescueSecretError::StorageUnavailable);
    }
    #[cfg(test)]
    if stage == WriteStage::CrashAfterDirectorySync {
        // Model abrupt process/power loss: unlike an ordinary error return,
        // the temporary-file destructor would never have run.
        guard.disarm();
        return Err(RescueSecretError::StorageUnavailable);
    }
    #[cfg(not(test))]
    let _ = stage;

    let current = optional_named_state(directory, kind.filename(), owner)?;
    if current != existing {
        return Err(RescueSecretError::ConcurrentWrite);
    }

    let rename_result = if replace_mode == ReplaceMode::CreateOnly || existing.is_none() {
        rfs::renameat_with(
            directory,
            guard.name(),
            directory,
            kind.filename(),
            RenameFlags::NOREPLACE,
        )
    } else {
        rfs::renameat(directory, guard.name(), directory, kind.filename())
    };
    rename_result.map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            if replace_mode == ReplaceMode::CreateOnly {
                RescueSecretError::IdentityAlreadyExists
            } else {
                RescueSecretError::ConcurrentWrite
            }
        } else {
            RescueSecretError::StorageUnavailable
        }
    })?;
    guard.disarm();
    sync_directory(directory)?;

    let final_stat = stat_named(directory, kind.filename())?;
    validate_regular_stat(&final_stat, owner, FILE_MODE)?;
    let final_state = FileState::from_stat(&final_stat);
    if !final_state.same_object(&state) {
        return Err(RescueSecretError::ConcurrentWrite);
    }
    let persisted = read_optional_named(directory, kind.filename(), owner)?
        .ok_or(RescueSecretError::WriteVerificationFailed)?;
    if persisted.as_slice() != envelope {
        return Err(RescueSecretError::WriteVerificationFailed);
    }
    Ok(())
}

fn optional_named_state(
    directory: &OwnedFd,
    name: &str,
    owner: VaultOwner,
) -> Result<Option<FileState>, RescueSecretError> {
    match rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            validate_regular_stat(&stat, owner, FILE_MODE)?;
            Ok(Some(FileState::from_stat(&stat)))
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(_) => Err(RescueSecretError::UnsafePath),
    }
}

fn create_temporary_file(
    directory: &OwnedFd,
    owner: VaultOwner,
) -> Result<(File, FileState, TemporaryFileGuard), RescueSecretError> {
    for _ in 0..16 {
        let name = format!(".tmp-{:016x}{:016x}", OsRng.next_u64(), OsRng.next_u64());
        let descriptor = match open_child(
            directory,
            Path::new(name.as_str()),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(_) => return Err(RescueSecretError::StorageUnavailable),
        };
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RescueSecretError::StorageUnavailable)?;
        let state = regular_file_state(&descriptor, owner, FILE_MODE)?;
        let named = stat_named(directory, &name)?;
        validate_regular_stat(&named, owner, FILE_MODE)?;
        if !state.same_object(&FileState::from_stat(&named)) {
            return Err(RescueSecretError::ConcurrentWrite);
        }
        let guard = TemporaryFileGuard {
            directory: rustix::io::fcntl_dupfd_cloexec(directory, 3)
                .map_err(|_| RescueSecretError::StorageUnavailable)?,
            name,
            state,
            armed: true,
        };
        return Ok((File::from(descriptor), state, guard));
    }
    Err(RescueSecretError::StorageUnavailable)
}

struct TemporaryFileGuard {
    directory: OwnedFd,
    name: String,
    state: FileState,
    armed: bool,
}

impl TemporaryFileGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(stat) = rfs::statat(
            &self.directory,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) && self.state.same_object(&FileState::from_stat(&stat))
        {
            let _ = rfs::unlinkat(&self.directory, self.name.as_str(), AtFlags::empty());
            let _ = rfs::fsync(&self.directory);
        }
    }
}

fn sync_directory(directory: &OwnedFd) -> Result<(), RescueSecretError> {
    rfs::fsync(directory).map_err(|_| RescueSecretError::StorageUnavailable)
}

fn to_journal_error(error: RescueSecretError) -> SecretStoreError {
    SecretStoreError::new(error.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObservedVaultMount {
    root_device: u64,
    mount_id: u64,
    mapping_major: u32,
    mapping_minor: u32,
    backing_major: u32,
    backing_minor: u32,
    mapper_name: [u8; 30],
    luks_uuid: [u8; 36],
}

impl ObservedVaultMount {
    fn verify_attestation(
        self,
        attestation: MountAttestationClaims,
    ) -> Result<(), RescueSecretError> {
        if self.root_device != attestation.root_device
            || self.mount_id != attestation.mount_id
            || self.mapping_major != attestation.mapping_major
            || self.mapping_minor != attestation.mapping_minor
            || self.backing_major != attestation.backing_major
            || self.backing_minor != attestation.backing_minor
            || self.mapper_name != attestation.mapper_name
            || self.luks_uuid != attestation.luks_uuid
        {
            return Err(RescueSecretError::InvalidMountAttestation);
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_attestation(self) -> VaultMountAttestation {
        VaultMountAttestation {
            claims: MountAttestationClaims {
                root_device: self.root_device,
                mount_id: self.mount_id,
                mapping_major: self.mapping_major,
                mapping_minor: self.mapping_minor,
                backing_major: self.backing_major,
                backing_minor: self.backing_minor,
                mapper_name: self.mapper_name,
                luks_uuid: self.luks_uuid,
            },
        }
    }
}

fn verify_luks2_mount(
    root_path: &Path,
    root_state: &FileState,
    root_mount_id: u64,
) -> Result<ObservedVaultMount, RescueSecretError> {
    let mut mountinfo = Vec::new();
    File::open("/proc/self/mountinfo")
        .map_err(|_| RescueSecretError::VaultNotMounted)?
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut mountinfo)
        .map_err(|_| RescueSecretError::VaultNotMounted)?;
    if mountinfo.len() as u64 > MAX_MOUNTINFO_BYTES {
        return Err(RescueSecretError::VaultNotMounted);
    }

    let expected_mountpoint = root_path.as_os_str().as_bytes();
    let mut match_found: Option<MountEntry> = None;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(entry) = parse_mountinfo_line(line)? else {
            continue;
        };
        if entry.mountpoint == expected_mountpoint {
            if match_found.is_some() {
                return Err(RescueSecretError::VaultNotMounted);
            }
            match_found = Some(entry);
        }
    }
    let entry = match_found.ok_or(RescueSecretError::VaultNotMounted)?;
    verify_mount_entry_identity(&entry, root_state.device, root_mount_id)?;
    if entry.filesystem.as_slice() != b"ext4" {
        return Err(RescueSecretError::UnsupportedFilesystem);
    }

    let dm_uuid_path = PathBuf::from(format!(
        "/sys/dev/block/{}:{}/dm/uuid",
        entry.major, entry.minor
    ));
    let mut dm_uuid = Vec::new();
    File::open(dm_uuid_path)
        .map_err(|_| RescueSecretError::NotLuks2)?
        .take(MAX_DM_UUID_BYTES + 1)
        .read_to_end(&mut dm_uuid)
        .map_err(|_| RescueSecretError::NotLuks2)?;
    if dm_uuid.len() as u64 > MAX_DM_UUID_BYTES {
        return Err(RescueSecretError::NotLuks2);
    }
    while matches!(dm_uuid.last(), Some(b'\n' | b'\r')) {
        dm_uuid.pop();
    }
    let luks_uuid = parse_luks2_dm_uuid(&dm_uuid).ok_or(RescueSecretError::NotLuks2)?;

    let dm_name_path = PathBuf::from(format!(
        "/sys/dev/block/{}:{}/dm/name",
        entry.major, entry.minor
    ));
    let mut dm_name = Vec::new();
    File::open(dm_name_path)
        .map_err(|_| RescueSecretError::NotLuks2)?
        .take(128)
        .read_to_end(&mut dm_name)
        .map_err(|_| RescueSecretError::NotLuks2)?;
    while matches!(dm_name.last(), Some(b'\n' | b'\r')) {
        dm_name.pop();
    }
    let mapper_name: [u8; 30] = dm_name
        .try_into()
        .map_err(|_| RescueSecretError::NotLuks2)?;
    if !is_managed_mapper_name(&mapper_name) {
        return Err(RescueSecretError::NotLuks2);
    }
    match entry.errors_policy {
        MountErrorsPolicy::RemountReadOnly => {}
        MountErrorsPolicy::Unspecified => {
            verify_ext4_default_errors_policy(entry.major, entry.minor, &mapper_name)?;
        }
        MountErrorsPolicy::Other => return Err(RescueSecretError::VaultNotMounted),
    }
    let (backing_major, backing_minor) = observed_single_backing_device(entry.major, entry.minor)?;
    verify_unique_mapping_holder(backing_major, backing_minor, entry.major, entry.minor)?;
    Ok(ObservedVaultMount {
        root_device: root_state.device,
        mount_id: root_mount_id,
        mapping_major: entry.major,
        mapping_minor: entry.minor,
        backing_major,
        backing_minor,
        mapper_name,
        luks_uuid,
    })
}

fn verify_mount_entry_identity(
    entry: &MountEntry,
    root_device: u64,
    root_mount_id: u64,
) -> Result<(), RescueSecretError> {
    if entry.mount_root != b"/"
        || !entry.read_write
        || !entry.no_suid
        || !entry.no_dev
        || !entry.no_exec
        || !entry.no_sym_follow
        || entry.mount_id != root_mount_id
        || entry.major != rfs::major(root_device)
        || entry.minor != rfs::minor(root_device)
    {
        return Err(RescueSecretError::VaultNotMounted);
    }
    Ok(())
}

#[cfg(feature = "experimental-vault-manager")]
pub(crate) fn mint_managed_mount_attestation(
    root_path: &Path,
    mapper_name: [u8; 30],
    luks_uuid: [u8; 36],
    mapping_major: u32,
    mapping_minor: u32,
    backing_major: u32,
    backing_minor: u32,
) -> Result<VaultMountAttestation, RescueSecretError> {
    let root_path = normalize_absolute_root(root_path)?;
    let root_fd = open_root(&root_path)?;
    let stat = rfs::fstat(&root_fd).map_err(|_| RescueSecretError::VaultNotMounted)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(RescueSecretError::VaultNotMounted);
    }
    let root_state = FileState::from_stat(&stat);
    let mount_id = descriptor_mount_id(&root_fd)?;
    let observed = verify_luks2_mount(&root_path, &root_state, mount_id)?;
    if observed.mapper_name != mapper_name
        || observed.luks_uuid != luks_uuid
        || observed.mapping_major != mapping_major
        || observed.mapping_minor != mapping_minor
        || observed.backing_major != backing_major
        || observed.backing_minor != backing_minor
    {
        return Err(RescueSecretError::InvalidMountAttestation);
    }
    Ok(VaultMountAttestation {
        claims: MountAttestationClaims {
            root_device: observed.root_device,
            mount_id: observed.mount_id,
            mapping_major: observed.mapping_major,
            mapping_minor: observed.mapping_minor,
            backing_major: observed.backing_major,
            backing_minor: observed.backing_minor,
            mapper_name: observed.mapper_name,
            luks_uuid: observed.luks_uuid,
        },
    })
}

/// Proves that neither the managed mountpoint nor the exact mapper device is
/// present in this mount namespace after `umount(2)` returned success. The
/// caller performs mapper-identity checkpoints around each invocation.
#[cfg(feature = "experimental-vault-manager")]
pub(crate) fn verify_managed_mount_absent(
    root_path: &Path,
    mapping_major: u32,
    mapping_minor: u32,
) -> Result<(), RescueSecretError> {
    let root_path = normalize_absolute_root(root_path)?;
    let root_fd = open_root(&root_path)?;
    let descriptor_before =
        rfs::fstat(&root_fd).map_err(|_| RescueSecretError::InvalidMountAttestation)?;
    let named_before = rfs::statat(CWD, &root_path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::InvalidMountAttestation)?;
    if !FileType::from_raw_mode(descriptor_before.st_mode).is_dir()
        || descriptor_before.st_dev != named_before.st_dev
        || descriptor_before.st_ino != named_before.st_ino
        || descriptor_before.st_dev == rfs::makedev(mapping_major, mapping_minor)
    {
        return Err(RescueSecretError::InvalidMountAttestation);
    }

    let mut mountinfo = Vec::new();
    File::open("/proc/self/mountinfo")
        .map_err(|_| RescueSecretError::InvalidMountAttestation)?
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut mountinfo)
        .map_err(|_| RescueSecretError::InvalidMountAttestation)?;
    if mountinfo.len() as u64 > MAX_MOUNTINFO_BYTES {
        return Err(RescueSecretError::InvalidMountAttestation);
    }
    verify_mountinfo_absence(
        &mountinfo,
        root_path.as_os_str().as_bytes(),
        mapping_major,
        mapping_minor,
    )?;

    let descriptor_after =
        rfs::fstat(&root_fd).map_err(|_| RescueSecretError::InvalidMountAttestation)?;
    let named_after = rfs::statat(CWD, &root_path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueSecretError::InvalidMountAttestation)?;
    if descriptor_after.st_dev != descriptor_before.st_dev
        || descriptor_after.st_ino != descriptor_before.st_ino
        || named_after.st_dev != descriptor_before.st_dev
        || named_after.st_ino != descriptor_before.st_ino
    {
        return Err(RescueSecretError::InvalidMountAttestation);
    }
    Ok(())
}

#[cfg(feature = "experimental-vault-manager")]
fn verify_mountinfo_absence(
    mountinfo: &[u8],
    root_path: &[u8],
    mapping_major: u32,
    mapping_minor: u32,
) -> Result<(), RescueSecretError> {
    let mut line_count = 0_usize;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        line_count = line_count
            .checked_add(1)
            .filter(|count| *count <= MAX_MOUNTINFO_LINES)
            .ok_or(RescueSecretError::InvalidMountAttestation)?;
        let entry =
            parse_mountinfo_line(line)?.ok_or(RescueSecretError::InvalidMountAttestation)?;
        if entry.mountpoint == root_path
            || (entry.major == mapping_major && entry.minor == mapping_minor)
        {
            return Err(RescueSecretError::InvalidMountAttestation);
        }
    }
    Ok(())
}

fn is_managed_mapper_name(name: &[u8; 30]) -> bool {
    name.starts_with(b"kernaid-vault-")
        && name[b"kernaid-vault-".len()..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn verify_ext4_default_errors_policy(
    mapping_major: u32,
    mapping_minor: u32,
    mapper_name: &[u8; 30],
) -> Result<(), RescueSecretError> {
    let mapper_path = PathBuf::from("/dev/mapper").join(OsStr::from_bytes(mapper_name));
    let descriptor = rfs::openat2(
        CWD,
        &mapper_path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueSecretError::VaultNotMounted)?;
    let expected_rdev = rfs::makedev(mapping_major, mapping_minor);
    let before = rfs::fstat(&descriptor).map_err(|_| RescueSecretError::VaultNotMounted)?;
    if !FileType::from_raw_mode(before.st_mode).is_block_device() || before.st_rdev != expected_rdev
    {
        return Err(RescueSecretError::VaultNotMounted);
    }

    let file = File::from(descriptor);
    let mut superblock = [0_u8; EXT4_SUPERBLOCK_PREFIX_BYTES];
    file.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET)
        .map_err(|_| RescueSecretError::VaultNotMounted)?;
    let after = rfs::fstat(&file).map_err(|_| RescueSecretError::VaultNotMounted)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_rdev != after.st_rdev
        || !ext4_default_errors_remount_read_only(&superblock)
    {
        return Err(RescueSecretError::VaultNotMounted);
    }
    Ok(())
}

fn ext4_default_errors_remount_read_only(superblock: &[u8]) -> bool {
    superblock.get(EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2) == Some([0x53, 0xef].as_slice())
        && superblock
            .get(EXT4_ERRORS_OFFSET..EXT4_ERRORS_OFFSET + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_le_bytes)
            == Some(EXT4_ERRORS_REMOUNT_READ_ONLY)
}

fn observed_single_backing_device(
    mapping_major: u32,
    mapping_minor: u32,
) -> Result<(u32, u32), RescueSecretError> {
    let directory = PathBuf::from(format!(
        "/sys/dev/block/{mapping_major}:{mapping_minor}/slaves"
    ));
    let mut entries = fs::read_dir(directory).map_err(|_| RescueSecretError::NotLuks2)?;
    let entry = entries
        .next()
        .ok_or(RescueSecretError::NotLuks2)?
        .map_err(|_| RescueSecretError::NotLuks2)?;
    if entries.next().is_some() {
        return Err(RescueSecretError::NotLuks2);
    }
    let mut device = Vec::new();
    File::open(entry.path().join("dev"))
        .map_err(|_| RescueSecretError::NotLuks2)?
        .take(64)
        .read_to_end(&mut device)
        .map_err(|_| RescueSecretError::NotLuks2)?;
    while matches!(device.last(), Some(b'\n' | b'\r')) {
        device.pop();
    }
    parse_major_minor(&device).ok_or(RescueSecretError::NotLuks2)
}

fn verify_unique_mapping_holder(
    backing_major: u32,
    backing_minor: u32,
    mapping_major: u32,
    mapping_minor: u32,
) -> Result<(), RescueSecretError> {
    let directory = PathBuf::from(format!(
        "/sys/dev/block/{backing_major}:{backing_minor}/holders"
    ));
    let mut entries = fs::read_dir(directory).map_err(|_| RescueSecretError::NotLuks2)?;
    let entry = entries
        .next()
        .ok_or(RescueSecretError::NotLuks2)?
        .map_err(|_| RescueSecretError::NotLuks2)?;
    if entries.next().is_some() {
        return Err(RescueSecretError::NotLuks2);
    }
    let mut device = Vec::new();
    File::open(entry.path().join("dev"))
        .map_err(|_| RescueSecretError::NotLuks2)?
        .take(64)
        .read_to_end(&mut device)
        .map_err(|_| RescueSecretError::NotLuks2)?;
    while matches!(device.last(), Some(b'\n' | b'\r')) {
        device.pop();
    }
    if parse_major_minor(&device) != Some((mapping_major, mapping_minor)) {
        return Err(RescueSecretError::NotLuks2);
    }
    Ok(())
}

struct MountEntry {
    mount_id: u64,
    major: u32,
    minor: u32,
    mount_root: Vec<u8>,
    mountpoint: Vec<u8>,
    read_write: bool,
    no_suid: bool,
    no_dev: bool,
    no_exec: bool,
    no_sym_follow: bool,
    errors_policy: MountErrorsPolicy,
    filesystem: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountErrorsPolicy {
    Unspecified,
    RemountReadOnly,
    Other,
}

fn parse_mountinfo_line(line: &[u8]) -> Result<Option<MountEntry>, RescueSecretError> {
    let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
    let Some(separator) = fields.iter().position(|field| *field == b"-") else {
        return Err(RescueSecretError::VaultNotMounted);
    };
    let Some(mount_id) = parse_u64_decimal(fields[0]) else {
        return Err(RescueSecretError::VaultNotMounted);
    };
    if separator < 6 || fields.len() < separator + 4 {
        return Err(RescueSecretError::VaultNotMounted);
    }
    let Some((major, minor)) = parse_major_minor(fields[2]) else {
        return Err(RescueSecretError::VaultNotMounted);
    };
    let mount_root = decode_mountinfo_field(fields[3])?;
    let mountpoint = decode_mountinfo_field(fields[4])?;
    // The source string is presentation-only and may legitimately be the
    // retained `/proc/<pid>/fd/<fd>` path supplied to mount(2). Decode it to
    // keep the mountinfo grammar strict, but never use it as identity. The
    // mount ID, root st_dev, device-mapper major:minor, dm UUID/name, sole
    // backing device, and holder relationship are the authoritative binding.
    let _source = decode_mountinfo_field(fields[separator + 2])?;
    let mount_options: Vec<_> = fields[5].split(|byte| *byte == b',').collect();
    let read_write = mount_options.contains(&b"rw".as_slice());
    let no_suid = mount_options.contains(&b"nosuid".as_slice());
    let no_dev = mount_options.contains(&b"nodev".as_slice());
    let no_exec = mount_options.contains(&b"noexec".as_slice());
    let no_sym_follow = mount_options.contains(&b"nosymfollow".as_slice());
    let super_options: Vec<_> = fields[separator + 3].split(|byte| *byte == b',').collect();
    let mut errors_policy = MountErrorsPolicy::Unspecified;
    for option in super_options
        .iter()
        .filter(|option| option.starts_with(b"errors="))
    {
        if errors_policy != MountErrorsPolicy::Unspecified {
            return Err(RescueSecretError::VaultNotMounted);
        }
        errors_policy = if *option == b"errors=remount-ro" {
            MountErrorsPolicy::RemountReadOnly
        } else {
            MountErrorsPolicy::Other
        };
    }
    Ok(Some(MountEntry {
        mount_id,
        major,
        minor,
        mount_root,
        mountpoint,
        read_write,
        no_suid,
        no_dev,
        no_exec,
        no_sym_follow,
        errors_policy,
        filesystem: fields[separator + 1].to_vec(),
    }))
}

fn parse_major_minor(value: &[u8]) -> Option<(u32, u32)> {
    let separator = value.iter().position(|byte| *byte == b':')?;
    let major = parse_decimal(&value[..separator])?;
    let minor = parse_decimal(&value[separator + 1..])?;
    Some((major, minor))
}

fn parse_decimal(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut result = 0_u32;
    for digit in value {
        result = result
            .checked_mul(10)?
            .checked_add(u32::from(digit - b'0'))?;
    }
    Some(result)
}

fn parse_u64_decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut result = 0_u64;
    for digit in value {
        result = result
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    Some(result)
}

fn parse_luks2_dm_uuid(value: &[u8]) -> Option<[u8; 36]> {
    if value.len() > MAX_DM_UUID_LENGTH || !value.starts_with(DM_LUKS2_PREFIX) {
        return None;
    }
    let remainder = &value[DM_LUKS2_PREFIX.len()..];
    let (compact_uuid, mapper_suffix) = remainder.split_at_checked(32)?;
    let mapper_suffix = mapper_suffix.strip_prefix(b"-")?;
    if !compact_uuid
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || mapper_suffix.is_empty()
        || !mapper_suffix
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.'))
    {
        return None;
    }

    let mut canonical = [0_u8; 36];
    let mut source = 0_usize;
    for (destination, byte) in canonical.iter_mut().enumerate() {
        if matches!(destination, 8 | 13 | 18 | 23) {
            *byte = b'-';
        } else {
            *byte = compact_uuid[source];
            source += 1;
        }
    }
    Some(canonical)
}

fn decode_mountinfo_field(value: &[u8]) -> Result<Vec<u8>, RescueSecretError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        if index + 3 >= value.len() {
            return Err(RescueSecretError::VaultNotMounted);
        }
        let escaped = &value[index + 1..index + 4];
        let byte = match escaped {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(RescueSecretError::VaultNotMounted),
        };
        decoded.push(byte);
        index += 4;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_storage::JournalSecretStore;
    use std::{
        fs::{self, OpenOptions},
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        },
    };
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        owner: VaultOwner,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("vault");
            fs::create_dir(&root).expect("create vault root");
            fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .expect("secure vault permissions");
            let marker = root.join(VAULT_MARKER_NAME);
            let mut marker_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(marker)
                .expect("create marker");
            marker_file
                .write_all(VAULT_MARKER_V1)
                .expect("write marker");
            marker_file.sync_all().expect("sync marker");
            let state = root.join(STATE_DIRECTORY);
            fs::create_dir(&state).expect("create pre-provisioned state directory");
            fs::set_permissions(&state, fs::Permissions::from_mode(DIRECTORY_MODE))
                .expect("secure state permissions");
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(root.join(LOCK_NAME))
                .expect("create pre-provisioned lock");
            lock.sync_all().expect("sync pre-provisioned lock");
            Self {
                _temporary: temporary,
                root,
                owner: VaultOwner::effective(),
            }
        }

        fn open(&self) -> RescueVaultSecrets {
            RescueVaultSecrets::open_for_test(&self.root, self.owner).expect("open test vault")
        }

        fn state_path(&self, name: &str) -> PathBuf {
            self.root.join(STATE_DIRECTORY).join(name)
        }
    }

    fn key(byte: u8) -> JournalKey {
        JournalKey::from_zeroizing(Zeroizing::new([byte; JOURNAL_KEY_BYTES]))
    }

    fn anchor(sequence: u64) -> JournalAnchor {
        JournalAnchor {
            journal_id: [7; 16],
            sequence,
            entry_hash: [9; 32],
        }
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    fn create_test_codex_home(fixture: &Fixture) -> PathBuf {
        let home = fixture.root.join(crate::CODEX_HOME_NAME);
        fs::create_dir(&home).expect("create Codex home");
        fs::set_permissions(&home, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("set Codex home mode");
        home
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_lease_is_absent_or_exact_descriptor_without_creation() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        assert!(
            vault
                .open_codex_home_lease_for_test()
                .expect("absent home")
                .is_none()
        );
        assert!(!fixture.root.join(crate::CODEX_HOME_NAME).exists());
        drop(vault);

        let home = create_test_codex_home(&fixture);
        fs::create_dir(home.join("sessions")).expect("persistent child directory");
        let vault = fixture.open();
        let descriptor = vault
            .open_codex_home_lease_for_test()
            .expect("open home")
            .expect("configured home");
        let stat = rfs::fstat(&descriptor).expect("home stat");
        let named = fs::symlink_metadata(&home).expect("named home");
        assert!(FileType::from_raw_mode(stat.st_mode).is_dir());
        assert!(
            stat.st_nlink >= 3,
            "persistent subdirectories remain allowed"
        );
        assert_eq!(stat.st_uid, fixture.owner.uid);
        assert_eq!(stat.st_gid, fixture.owner.gid);
        assert_eq!(stat.st_mode & 0o7777, DIRECTORY_MODE);
        assert_eq!(stat.st_ino, named.ino());
        assert_eq!(
            rfs::fcntl_getfl(&descriptor).expect("status flags"),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW
        );
        assert_eq!(
            rustix::io::fcntl_getfd(&descriptor).expect("descriptor flags"),
            rustix::io::FdFlags::CLOEXEC
        );
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_rejects_symlink_file_and_unsafe_mode() {
        let fixture = Fixture::new();
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, fixture.root.join(crate::CODEX_HOME_NAME)).expect("home symlink");
        let vault = fixture.open();
        assert!(vault.open_codex_home_lease_for_test().is_err());
        drop(vault);
        fs::remove_file(fixture.root.join(crate::CODEX_HOME_NAME)).expect("remove symlink");

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(DIRECTORY_MODE)
            .open(fixture.root.join(crate::CODEX_HOME_NAME))
            .expect("home regular file");
        let vault = fixture.open();
        assert!(vault.open_codex_home_lease_for_test().is_err());
        drop(vault);
        fs::remove_file(fixture.root.join(crate::CODEX_HOME_NAME)).expect("remove file");

        let home = create_test_codex_home(&fixture);
        fs::set_permissions(&home, fs::Permissions::from_mode(0o750)).expect("unsafe mode");
        let vault = fixture.open();
        assert_eq!(
            vault.open_codex_home_lease_for_test().err(),
            Some(RescueSecretError::UnsafePermissions)
        );
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_metadata_rejects_owner_link_and_mount_identity_changes() {
        let fixture = Fixture::new();
        let home = create_test_codex_home(&fixture);
        let vault = fixture.open();
        let descriptor = open_child(
            &vault.inner.root_fd,
            Path::new(crate::CODEX_HOME_NAME),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("home descriptor");
        let mut stat = rfs::fstat(&descriptor).expect("home stat");
        stat.st_uid = stat.st_uid.saturating_add(1);
        assert_eq!(
            validate_codex_home_stat(&stat, fixture.owner.uid, fixture.owner.gid),
            Err(RescueSecretError::WrongOwner)
        );
        stat.st_uid = fixture.owner.uid;
        stat.st_gid = stat.st_gid.saturating_add(1);
        assert_eq!(
            validate_codex_home_stat(&stat, fixture.owner.uid, fixture.owner.gid),
            Err(RescueSecretError::WrongOwner)
        );
        stat.st_gid = fixture.owner.gid;
        stat.st_nlink = 1;
        assert_eq!(
            validate_codex_home_stat(&stat, fixture.owner.uid, fixture.owner.gid),
            Err(RescueSecretError::UnsafePath)
        );
        assert!(
            validate_codex_home_descriptor(
                &descriptor,
                &vault.inner.root_fd,
                vault.inner.root_mount_id.saturating_add(1),
                fixture.owner.uid,
                fixture.owner.gid,
            )
            .is_err()
        );

        for flags in [
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        ] {
            let inexact = open_child(
                &vault.inner.root_fd,
                Path::new(crate::CODEX_HOME_NAME),
                flags,
                Mode::empty(),
            )
            .expect("inexact O_PATH descriptor");
            assert_eq!(
                validate_codex_home_descriptor(
                    &inexact,
                    &vault.inner.root_fd,
                    vault.inner.root_mount_id,
                    fixture.owner.uid,
                    fixture.owner.gid,
                ),
                Err(RescueSecretError::UnsafePath)
            );
        }

        let foreign = tempfile::Builder::new()
            .prefix("kernaid-codex-home-")
            .tempdir_in("/dev/shm")
            .expect("foreign tmpfs directory");
        fs::set_permissions(foreign.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("foreign mode");
        let foreign_descriptor = rfs::openat2(
            CWD,
            foreign.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .expect("foreign descriptor");
        assert_ne!(
            descriptor_mount_id(&foreign_descriptor).expect("foreign mount id"),
            vault.inner.root_mount_id
        );
        assert!(
            validate_codex_home_descriptor(
                &foreign_descriptor,
                &vault.inner.root_fd,
                vault.inner.root_mount_id,
                fixture.owner.uid,
                fixture.owner.gid,
            )
            .is_err()
        );
        assert!(home.is_dir());
    }

    fn write_test_secret_file(path: &Path, kind: SecretKind, value: &[u8]) {
        let encoded = encode_secret(kind, value).expect("encode test secret");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)
            .expect("create test secret file");
        file.write_all(&encoded).expect("write test secret file");
        file.sync_all().expect("sync test secret file");
    }

    #[test]
    fn subprocess_crash_writer_helper() {
        let Some(root) = std::env::var_os("KERNAID_TEST_CRASH_VAULT_ROOT") else {
            return;
        };
        let ready =
            PathBuf::from(std::env::var_os("KERNAID_TEST_CRASH_READY").expect("crash ready path"));
        let kind = match std::env::var("KERNAID_TEST_CRASH_SECRET")
            .expect("crash secret kind")
            .as_str()
        {
            "journal-key" => SecretKind::JournalKey,
            "journal-anchor" => SecretKind::JournalAnchor,
            "device-identity" => SecretKind::DeviceIdentity,
            _ => return,
        };
        let value = Zeroizing::new(match kind {
            SecretKind::JournalKey => vec![71; JOURNAL_KEY_BYTES],
            SecretKind::JournalAnchor => anchor(71).to_bytes().to_vec(),
            SecretKind::DeviceIdentity => vec![72; IDENTITY_SEED_BYTES],
        });
        let envelope = encode_secret(kind, &value).expect("encode crash secret");
        let vault = RescueVaultSecrets::open_for_test(PathBuf::from(root), VaultOwner::effective())
            .expect("open crash child vault");
        let (mut file, _state, mut guard) =
            create_temporary_file(&vault.inner.state_fd, vault.inner.owner)
                .expect("create crash temp");
        file.write_all(&envelope).expect("write crash temp");
        file.flush().expect("flush crash temp");
        rfs::fchmod(&file, Mode::RUSR | Mode::WUSR).expect("set crash temp mode");
        file.sync_all().expect("sync crash temp");
        assert_eq!(
            read_optional_named(&vault.inner.state_fd, guard.name(), vault.inner.owner)
                .expect("read crash temp")
                .expect("crash temp exists")
                .as_slice(),
            envelope.as_slice()
        );
        sync_directory(&vault.inner.state_fd).expect("sync crash temp directory");
        guard.disarm();

        let ready_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(ready)
            .expect("create crash-ready marker");
        ready_file.sync_all().expect("sync crash-ready marker");
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(60));
        }
    }

    #[test]
    fn journal_and_identity_roundtrip_across_reopen() {
        let fixture = Fixture::new();
        let expected_public_key;
        {
            let vault = fixture.open();
            let mut journal = vault.journal_store();
            journal.store_key(&key(42)).expect("store key");
            journal.store_anchor(&anchor(11)).expect("store anchor");
            let mut identities = vault.device_identity_store();
            let identity = identities
                .create_device_identity()
                .expect("create identity");
            expected_public_key = identity.public_key();
        }

        let vault = fixture.open();
        let mut journal = vault.journal_store();
        assert_eq!(
            journal
                .load_key()
                .expect("load key")
                .expect("key")
                .expose_secret(),
            &[42; JOURNAL_KEY_BYTES]
        );
        assert_eq!(
            journal.load_anchor().expect("load anchor"),
            Some(anchor(11))
        );
        let mut identities = vault.device_identity_store();
        assert_eq!(
            identities
                .load_device_identity()
                .expect("load identity")
                .expect("identity")
                .public_key(),
            expected_public_key
        );
    }

    #[test]
    fn journal_preflight_rejects_hardlinked_database_and_sidecars_without_modification() {
        for (index, name) in [JOURNAL_DATABASE_NAME, JOURNAL_WAL_NAME, JOURNAL_SHM_NAME]
            .into_iter()
            .enumerate()
        {
            let fixture = Fixture::new();
            let vault = fixture.open();
            let referent = fixture
                ._temporary
                .path()
                .join(format!("journal-referent-{index}"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .open(&referent)
                .expect("create hardlink referent");
            file.write_all(b"must-not-be-opened-or-modified")
                .expect("write hardlink referent");
            file.sync_all().expect("sync hardlink referent");
            fs::set_permissions(&referent, fs::Permissions::from_mode(0o640))
                .expect("set referent mode");
            fs::hard_link(&referent, fixture.state_path(name)).expect("link journal candidate");

            let before_bytes = fs::read(&referent).expect("read referent before preflight");
            let before = fs::metadata(&referent).expect("stat referent before preflight");
            let before_modified = before.modified().expect("referent modified timestamp");
            assert!(matches!(
                vault.open_journal(),
                Err(JournalError::InvalidPath)
            ));

            let after = fs::metadata(&referent).expect("stat referent after preflight");
            assert_eq!(
                fs::read(&referent).expect("read referent after preflight"),
                before_bytes
            );
            assert_eq!(after.mode(), before.mode());
            assert_eq!(after.nlink(), before.nlink());
            assert_eq!(after.len(), before.len());
            assert_eq!(
                after.modified().expect("referent modified timestamp"),
                before_modified
            );
        }
    }

    #[test]
    fn malformed_and_truncated_values_are_not_missing_or_overwritten() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            let mut journal = vault.journal_store();
            journal.store_key(&key(1)).expect("store key");
        }
        fs::write(fixture.state_path(JOURNAL_KEY_NAME), b"truncated")
            .expect("truncate stored value");
        fs::set_permissions(
            fixture.state_path(JOURNAL_KEY_NAME),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .expect("restore mode");
        let vault = fixture.open();
        let mut journal = vault.journal_store();
        assert!(journal.load_key().is_err());
        assert!(journal.store_key(&key(2)).is_err());
    }

    #[test]
    fn symlink_and_hardlink_secret_paths_are_rejected() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            let mut journal = vault.journal_store();
            journal.store_key(&key(3)).expect("store key");
        }
        let key_path = fixture.state_path(JOURNAL_KEY_NAME);
        let moved = fixture.state_path("moved-key");
        fs::rename(&key_path, &moved).expect("move key");
        symlink(&moved, &key_path).expect("replace with symlink");
        let vault = fixture.open();
        assert!(vault.journal_store().load_key().is_err());
        fs::remove_file(&key_path).expect("remove symlink");
        fs::rename(&moved, &key_path).expect("restore key");
        fs::hard_link(&key_path, fixture.state_path("key-link")).expect("hard link key");
        assert!(vault.journal_store().load_key().is_err());
    }

    #[test]
    fn unsafe_mode_and_owner_are_rejected() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            let mut journal = vault.journal_store();
            journal.store_key(&key(4)).expect("store key");
        }
        fs::set_permissions(
            fixture.state_path(JOURNAL_KEY_NAME),
            fs::Permissions::from_mode(0o640),
        )
        .expect("weaken mode");
        let vault = fixture.open();
        assert!(vault.journal_store().load_key().is_err());
        assert_eq!(
            RescueVaultSecrets::open_for_test(
                &fixture.root,
                VaultOwner {
                    uid: fixture.owner.uid.saturating_add(1),
                    gid: fixture.owner.gid,
                },
            )
            .err(),
            Some(RescueSecretError::WrongOwner)
        );
    }

    #[test]
    fn stale_state_directory_is_detected() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        let original = fixture.root.join(STATE_DIRECTORY);
        let moved = fixture.root.join("stale-state");
        fs::rename(&original, &moved).expect("move state directory");
        fs::create_dir(&original).expect("replacement state directory");
        fs::set_permissions(&original, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure replacement mode");
        assert!(vault.journal_store().load_key().is_err());
    }

    #[test]
    fn exclusive_lock_blocks_a_second_process_handle_and_allows_stale_file() {
        let fixture = Fixture::new();
        let first = fixture.open();
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::VaultLocked)
        );
        drop(first);
        RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner)
            .expect("persistent unlocked lock file is safe");
    }

    #[test]
    fn failed_atomic_replace_preserves_old_value_and_removes_temp() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        let mut journal = vault.journal_store();
        journal.store_key(&key(5)).expect("store old key");
        assert_eq!(
            journal.fail_key_replace_before_rename(&key(6)),
            Err(RescueSecretError::StorageUnavailable)
        );
        assert_eq!(
            journal
                .load_key()
                .expect("load old key")
                .expect("old key")
                .expose_secret(),
            &[5; JOURNAL_KEY_BYTES]
        );
        let names: Vec<_> = fs::read_dir(fixture.root.join(STATE_DIRECTORY))
            .expect("read state directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| name.as_bytes().starts_with(b".tmp-"))
        );
    }

    #[test]
    fn crash_orphans_for_each_core_secret_recover_deterministically() {
        {
            let fixture = Fixture::new();
            {
                let vault = fixture.open();
                assert_eq!(
                    vault.inner.store_secret_with_stage(
                        SecretKind::JournalKey,
                        key(31).expose_secret(),
                        ReplaceMode::Replace,
                        WriteStage::CrashAfterDirectorySync,
                    ),
                    Err(RescueSecretError::StorageUnavailable)
                );
            }
            let vault = fixture.open();
            assert_eq!(
                vault
                    .journal_store()
                    .load_key()
                    .expect("load recovered key")
                    .expect("recovered key")
                    .expose_secret(),
                &[31; JOURNAL_KEY_BYTES]
            );
        }

        {
            let fixture = Fixture::new();
            let expected = anchor(17);
            {
                let vault = fixture.open();
                assert_eq!(
                    vault.inner.store_secret_with_stage(
                        SecretKind::JournalAnchor,
                        &expected.to_bytes(),
                        ReplaceMode::Replace,
                        WriteStage::CrashAfterDirectorySync,
                    ),
                    Err(RescueSecretError::StorageUnavailable)
                );
            }
            let vault = fixture.open();
            assert_eq!(
                vault
                    .journal_store()
                    .load_anchor()
                    .expect("load recovered anchor"),
                Some(expected)
            );
        }

        {
            let fixture = Fixture::new();
            let identity = DeviceIdentity::generate();
            let seed = identity.export_seed_for_encrypted_storage();
            let expected_public_key = identity.public_key();
            {
                let vault = fixture.open();
                assert_eq!(
                    vault.inner.store_secret_with_stage(
                        SecretKind::DeviceIdentity,
                        seed.as_slice(),
                        ReplaceMode::CreateOnly,
                        WriteStage::CrashAfterDirectorySync,
                    ),
                    Err(RescueSecretError::StorageUnavailable)
                );
            }
            let vault = fixture.open();
            assert_eq!(
                vault
                    .device_identity_store()
                    .load_device_identity()
                    .expect("load recovered identity")
                    .expect("recovered identity")
                    .public_key(),
                expected_public_key
            );
        }
    }

    #[test]
    #[ignore = "SIGKILL fork must run without parallel vault descriptors"]
    fn sigkill_after_temp_directory_fsync_recovers_each_core_secret() {
        for kind in ["journal-key", "journal-anchor", "device-identity"] {
            let fixture = Fixture::new();
            let ready = fixture._temporary.path().join(format!("ready-{kind}"));
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("resolve current test executable"),
            )
            .args([
                "--exact",
                "linux::tests::subprocess_crash_writer_helper",
                "--nocapture",
            ])
            .env("KERNAID_TEST_CRASH_VAULT_ROOT", &fixture.root)
            .env("KERNAID_TEST_CRASH_READY", &ready)
            .env("KERNAID_TEST_CRASH_SECRET", kind)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn crash writer");
            let mut ready_seen = false;
            for _ in 0..500 {
                if ready.exists() {
                    ready_seen = true;
                    break;
                }
                if child.try_wait().expect("poll crash writer").is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                ready_seen,
                "crash writer reached durable boundary for {kind}"
            );
            child.kill().expect("SIGKILL crash writer");
            let status = child.wait().expect("wait for killed crash writer");
            assert!(!status.success());

            let vault = fixture.open();
            match kind {
                "journal-key" => assert_eq!(
                    vault
                        .journal_store()
                        .load_key()
                        .expect("load SIGKILL-recovered key")
                        .expect("SIGKILL-recovered key")
                        .expose_secret(),
                    &[71; JOURNAL_KEY_BYTES]
                ),
                "journal-anchor" => assert_eq!(
                    vault
                        .journal_store()
                        .load_anchor()
                        .expect("load SIGKILL-recovered anchor"),
                    Some(anchor(71))
                ),
                "device-identity" => assert_eq!(
                    vault
                        .device_identity_store()
                        .load_device_identity()
                        .expect("load SIGKILL-recovered identity")
                        .expect("SIGKILL-recovered identity")
                        .public_key(),
                    DeviceIdentity::from_seed(&[72; IDENTITY_SEED_BYTES])
                        .expect("expected SIGKILL identity")
                        .public_key()
                ),
                _ => unreachable!(),
            }
            assert!(
                fs::read_dir(fixture.root.join(STATE_DIRECTORY))
                    .expect("scan recovered state")
                    .all(|entry| !entry
                        .expect("state entry")
                        .file_name()
                        .as_bytes()
                        .starts_with(b".tmp-"))
            );
        }
    }

    #[test]
    fn crash_orphan_reconciliation_never_guesses_between_valid_values() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            vault
                .journal_store()
                .store_key(&key(41))
                .expect("store final key");
            assert_eq!(
                vault.inner.store_secret_with_stage(
                    SecretKind::JournalKey,
                    key(42).expose_secret(),
                    ReplaceMode::Replace,
                    WriteStage::CrashAfterDirectorySync,
                ),
                Err(RescueSecretError::StorageUnavailable)
            );
        }
        let orphan = fs::read_dir(fixture.root.join(STATE_DIRECTORY))
            .expect("read state directory")
            .map(|entry| entry.expect("directory entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.as_bytes().starts_with(b".tmp-"))
            })
            .expect("preserved crash orphan");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(orphan.exists());
    }

    #[test]
    fn newer_anchor_orphan_defers_to_valid_final_for_journal_replay() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            vault
                .journal_store()
                .store_anchor(&anchor(21))
                .expect("store final anchor");
            assert_eq!(
                vault.inner.store_secret_with_stage(
                    SecretKind::JournalAnchor,
                    &anchor(22).to_bytes(),
                    ReplaceMode::Replace,
                    WriteStage::CrashAfterDirectorySync,
                ),
                Err(RescueSecretError::StorageUnavailable)
            );
        }
        let vault = fixture.open();
        assert_eq!(
            vault
                .journal_store()
                .load_anchor()
                .expect("load retained final anchor"),
            Some(anchor(21))
        );
        assert!(
            fs::read_dir(fixture.root.join(STATE_DIRECTORY))
                .expect("read state directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .as_bytes()
                    .starts_with(b".tmp-"))
        );
    }

    #[test]
    fn anchor_orphan_cleanup_composes_with_authenticated_database_ahead_recovery() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open();
            vault
                .device_identity_store()
                .create_device_identity()
                .expect("provision application identity");
            vault
                .open_application_store()
                .expect("bootstrap identity binding");
        }
        let anchor_one = fs::read(fixture.state_path(JOURNAL_ANCHOR_NAME))
            .expect("read sequence-one anchor envelope");
        {
            let vault = fixture.open();
            vault
                .open_journal()
                .expect("open application journal")
                .append(
                    br#"{"type":"provider.openai.logout.intent","transactionId":"00000000000000000000000000000001","oldSha256":null}"#,
                )
                .expect("append canonical sequence-two intent");
        }
        let anchor_two = fs::read(fixture.state_path(JOURNAL_ANCHOR_NAME))
            .expect("read sequence-two anchor envelope");
        assert_ne!(anchor_one, anchor_two);
        fs::write(fixture.state_path(JOURNAL_ANCHOR_NAME), &anchor_one)
            .expect("restore prefix anchor");
        fs::set_permissions(
            fixture.state_path(JOURNAL_ANCHOR_NAME),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .expect("restore anchor mode");
        let orphan_name = ".tmp-abcdefabcdefabcdefabcdefabcdefab";
        let mut orphan = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(fixture.state_path(orphan_name))
            .expect("create sequence-two anchor orphan");
        orphan
            .write_all(&anchor_two)
            .expect("write sequence-two anchor orphan");
        orphan.sync_all().expect("sync anchor orphan");
        drop(orphan);

        {
            let vault = fixture.open();
            assert!(!fixture.state_path(orphan_name).exists());
            vault
                .open_journal()
                .expect("authenticate database-ahead prefix and advance anchor");
        }
        assert_eq!(
            fs::read(fixture.state_path(JOURNAL_ANCHOR_NAME))
                .expect("read recovered sequence-two anchor"),
            anchor_two
        );
        let vault = fixture.open();
        vault
            .open_application_store()
            .expect("recover authenticated tail intent after anchor advancement");
    }

    #[test]
    fn multiple_valid_crash_orphans_are_preserved_and_rejected() {
        let fixture = Fixture::new();
        for (name, value) in [
            (".tmp-00112233445566778899aabbccddeeff", key(51)),
            (".tmp-ffeeddccbbaa99887766554433221100", key(52)),
        ] {
            let encoded = encode_secret(SecretKind::JournalKey, value.expose_secret())
                .expect("encode orphan key");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(fixture.state_path(name))
                .expect("create valid orphan");
            file.write_all(&encoded).expect("write valid orphan");
            file.sync_all().expect("sync valid orphan");
        }
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(
            fixture
                .state_path(".tmp-00112233445566778899aabbccddeeff")
                .exists()
        );
        assert!(
            fixture
                .state_path(".tmp-ffeeddccbbaa99887766554433221100")
                .exists()
        );
    }

    #[test]
    fn retained_recovery_descriptors_detect_orphan_and_final_name_swaps() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        let orphan_name = ".tmp-1234567890abcdef1234567890abcdef";
        let orphan_path = fixture.state_path(orphan_name);
        let orphan_held = fixture.state_path("held-orphan-a");
        let orphan_replacement = fixture.state_path("orphan-replacement-b");
        write_test_secret_file(
            &orphan_path,
            SecretKind::JournalKey,
            key(61).expose_secret(),
        );
        write_test_secret_file(
            &orphan_replacement,
            SecretKind::JournalKey,
            key(62).expose_secret(),
        );
        let opened_orphan = open_recovery_file(
            &vault.inner.state_fd,
            orphan_name,
            fixture.owner,
            vault.inner.state_state.device,
            vault.inner.root_mount_id,
        )
        .expect("open retained orphan")
        .expect("retained orphan exists");
        fs::rename(&orphan_path, &orphan_held).expect("move orphan A aside");
        fs::rename(&orphan_replacement, &orphan_path).expect("install orphan B");
        assert_eq!(
            recheck_open_recovery_file(
                &vault.inner.state_fd,
                orphan_name,
                fixture.owner,
                &opened_orphan,
            ),
            Err(RescueSecretError::StaleVault)
        );
        fs::rename(&orphan_path, &orphan_replacement).expect("move orphan B aside");
        fs::rename(&orphan_held, &orphan_path).expect("restore orphan A");
        assert_eq!(
            recheck_open_recovery_file(
                &vault.inner.state_fd,
                orphan_name,
                fixture.owner,
                &opened_orphan,
            ),
            Err(RescueSecretError::StaleVault),
            "an A-to-B-to-A name replay must remain detectable through ctime",
        );
        assert_eq!(
            decode_secret(SecretKind::JournalKey, &opened_orphan.envelope)
                .expect("decode retained orphan")
                .as_slice(),
            key(61).expose_secret()
        );

        vault
            .journal_store()
            .store_key(&key(63))
            .expect("store final key");
        let final_path = fixture.state_path(JOURNAL_KEY_NAME);
        let final_held = fixture.state_path("held-final-a");
        let final_replacement = fixture.state_path("final-replacement-b");
        write_test_secret_file(
            &final_replacement,
            SecretKind::JournalKey,
            key(64).expose_secret(),
        );
        let opened_final = open_recovery_file(
            &vault.inner.state_fd,
            JOURNAL_KEY_NAME,
            fixture.owner,
            vault.inner.state_state.device,
            vault.inner.root_mount_id,
        )
        .expect("open retained final")
        .expect("retained final exists");
        fs::rename(&final_path, &final_held).expect("move final A aside");
        fs::rename(&final_replacement, &final_path).expect("install final B");
        assert_eq!(
            recheck_open_recovery_file(
                &vault.inner.state_fd,
                JOURNAL_KEY_NAME,
                fixture.owner,
                &opened_final,
            ),
            Err(RescueSecretError::StaleVault)
        );
        fs::rename(&final_path, &final_replacement).expect("move final B aside");
        fs::rename(&final_held, &final_path).expect("restore final A");
        assert_eq!(
            recheck_open_recovery_file(
                &vault.inner.state_fd,
                JOURNAL_KEY_NAME,
                fixture.owner,
                &opened_final,
            ),
            Err(RescueSecretError::StaleVault),
            "an A-to-B-to-A final replay must remain detectable through ctime",
        );
    }

    #[test]
    fn orphan_scan_has_explicit_entry_and_name_budgets() {
        {
            let fixture = Fixture::new();
            for index in 0..=MAX_STATE_DIRECTORY_ENTRIES {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(FILE_MODE)
                    .open(fixture.state_path(&format!("bounded-entry-{index:03}")))
                    .expect("create bounded directory entry");
                file.sync_all().expect("sync bounded directory entry");
            }
            assert_eq!(
                RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
                Some(RescueSecretError::UnsafePath)
            );
        }

        {
            let fixture = Fixture::new();
            let oversized_name = "x".repeat(MAX_STATE_DIRECTORY_NAME_BYTES + 1);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(fixture.state_path(&oversized_name))
                .expect("create oversized name");
            file.sync_all().expect("sync oversized name");
            assert_eq!(
                RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
                Some(RescueSecretError::UnsafePath)
            );
        }
    }

    #[test]
    fn identity_creation_never_overwrites() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        let mut identities = vault.device_identity_store();
        let first = identities.create_device_identity().expect("first identity");
        assert_eq!(
            identities.create_device_identity().err(),
            Some(RescueSecretError::IdentityAlreadyExists)
        );
        assert_eq!(
            identities
                .load_device_identity()
                .expect("reload")
                .expect("identity")
                .public_key(),
            first.public_key()
        );
    }

    #[test]
    fn marker_version_and_marker_symlink_fail_closed() {
        let fixture = Fixture::new();
        let marker = fixture.root.join(VAULT_MARKER_NAME);
        fs::write(&marker, b"KERNAID-RESCUE-VAULT-V0\n").expect("tamper marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(FILE_MODE)).expect("marker mode");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::InvalidMarker)
        );
        fs::remove_file(&marker).expect("remove marker");
        let target = fixture.root.join("marker-target");
        fs::write(&target, VAULT_MARKER_V1).expect("marker target");
        fs::set_permissions(&target, fs::Permissions::from_mode(FILE_MODE)).expect("target mode");
        symlink(&target, marker).expect("marker symlink");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::InvalidMarker)
        );
    }

    #[test]
    fn strict_envelope_rejects_padding_and_wrong_purpose() {
        let fixture = Fixture::new();
        let vault = fixture.open();
        let mut journal = vault.journal_store();
        journal.store_key(&key(8)).expect("store key");
        let path = fixture.state_path(JOURNAL_KEY_NAME);
        let original = fs::read(&path).expect("read envelope");
        let mut padded = original.clone();
        padded.insert(padded.len() - 1, b'=');
        fs::write(&path, padded).expect("write padded envelope");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("mode");
        assert!(journal.load_key().is_err());
        let wrong = original
            .windows(b"journal-key-v1".len())
            .position(|window| window == b"journal-key-v1")
            .expect("purpose");
        let mut wrong_purpose = original;
        wrong_purpose[wrong..wrong + b"journal-key-v1".len()].copy_from_slice(b"identity-seed1");
        fs::write(&path, wrong_purpose).expect("write wrong purpose");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("mode");
        assert!(journal.load_key().is_err());
    }

    #[test]
    fn mountinfo_decoder_is_strict() {
        assert_eq!(
            decode_mountinfo_field(b"/media/KernAid\\040Vault").expect("decode"),
            b"/media/KernAid Vault"
        );
        assert!(decode_mountinfo_field(b"/bad\\000path").is_err());
        assert_eq!(parse_major_minor(b"253:17"), Some((253, 17)));
        assert_eq!(parse_major_minor(b"253:x"), None);
        let entry = parse_mountinfo_line(
            b"41 29 253:17 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw,errors=remount-ro",
        )
        .expect("valid mountinfo")
        .expect("entry");
        assert_eq!(entry.mount_id, 41);
        assert!(entry.read_write);
        assert!(entry.no_suid);
        assert!(entry.no_dev);
        assert!(entry.no_exec);
        assert!(entry.no_sym_follow);
        assert_eq!(entry.errors_policy, MountErrorsPolicy::RemountReadOnly);
        let default_policy = parse_mountinfo_line(
            b"41 29 253:17 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw",
        )
        .expect("valid default-policy mountinfo")
        .expect("default-policy entry");
        assert_eq!(default_policy.errors_policy, MountErrorsPolicy::Unspecified);
        let unsafe_policy = parse_mountinfo_line(
            b"41 29 253:17 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw,errors=continue",
        )
        .expect("syntactically valid unsafe-policy mountinfo")
        .expect("unsafe-policy entry");
        assert_eq!(unsafe_policy.errors_policy, MountErrorsPolicy::Other);
        assert!(parse_mountinfo_line(
            b"41 29 253:17 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/dm-0 rw,errors=continue,errors=remount-ro",
        )
        .is_err());
        assert!(parse_mountinfo_line(b"x 29 253:17 / /vault rw - ext4 /dev/dm-0 rw").is_err());
    }

    #[cfg(feature = "experimental-vault-manager")]
    #[test]
    fn unmount_postcondition_rejects_residual_mountpoint_or_mapper_device() {
        let unrelated = b"40 29 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            verify_mountinfo_absence(unrelated, b"/vault", 253, 17),
            Ok(())
        );

        let residual_mountpoint = b"41 29 8:1 / /vault rw - ext4 /dev/sda1 rw\n";
        assert!(verify_mountinfo_absence(residual_mountpoint, b"/vault", 253, 17).is_err());

        let residual_mapper_elsewhere = b"42 29 253:17 / /elsewhere rw - ext4 /dev/dm-0 rw\n";
        assert!(verify_mountinfo_absence(residual_mapper_elsewhere, b"/vault", 253, 17).is_err());
        assert!(verify_mountinfo_absence(b"malformed\n", b"/vault", 253, 17).is_err());
    }

    #[test]
    fn procfd_mount_source_is_non_authoritative_but_kernel_identity_is_exact() {
        let descriptor = tempfile::tempfile().expect("create retained descriptor fixture");
        let procfd_source = format!("/proc/{}/fd/{}", std::process::id(), descriptor.as_raw_fd());
        assert!(Path::new(&procfd_source).exists());
        let line = format!(
            "41 29 253:17 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 {procfd_source} rw,errors=remount-ro"
        );
        let entry = parse_mountinfo_line(line.as_bytes())
            .expect("valid procfd-source mountinfo")
            .expect("procfd-source entry");
        let root_device = rfs::makedev(253, 17);
        assert_eq!(verify_mount_entry_identity(&entry, root_device, 41), Ok(()));

        let bind_or_subroot = parse_mountinfo_line(
            b"41 29 253:17 /subtree /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /proc/1/fd/7 rw,errors=remount-ro",
        )
        .expect("syntactically valid subroot mountinfo")
        .expect("subroot entry");
        assert_eq!(
            verify_mount_entry_identity(&bind_or_subroot, root_device, 41),
            Err(RescueSecretError::VaultNotMounted)
        );

        let wrong_device = parse_mountinfo_line(
            b"41 29 253:18 / /vault rw,nosuid,nodev,noexec,nosymfollow - ext4 /proc/1/fd/7 rw,errors=remount-ro",
        )
        .expect("syntactically valid wrong-device mountinfo")
        .expect("wrong-device entry");
        assert_eq!(
            verify_mount_entry_identity(&wrong_device, root_device, 41),
            Err(RescueSecretError::VaultNotMounted)
        );
        assert_eq!(
            verify_mount_entry_identity(&entry, root_device, 42),
            Err(RescueSecretError::VaultNotMounted)
        );
    }

    #[test]
    fn ext4_default_error_policy_parser_is_exact() {
        let mut superblock = [0_u8; EXT4_SUPERBLOCK_PREFIX_BYTES];
        superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2].copy_from_slice(&[0x53, 0xef]);
        superblock[EXT4_ERRORS_OFFSET..EXT4_ERRORS_OFFSET + 2]
            .copy_from_slice(&EXT4_ERRORS_REMOUNT_READ_ONLY.to_le_bytes());
        assert!(ext4_default_errors_remount_read_only(&superblock));

        superblock[EXT4_ERRORS_OFFSET..EXT4_ERRORS_OFFSET + 2]
            .copy_from_slice(&1_u16.to_le_bytes());
        assert!(!ext4_default_errors_remount_read_only(&superblock));
        superblock[EXT4_ERRORS_OFFSET..EXT4_ERRORS_OFFSET + 2]
            .copy_from_slice(&3_u16.to_le_bytes());
        assert!(!ext4_default_errors_remount_read_only(&superblock));
        superblock[EXT4_MAGIC_OFFSET] = 0;
        assert!(!ext4_default_errors_remount_read_only(&superblock));
        assert!(!ext4_default_errors_remount_read_only(&superblock[..32]));
    }

    #[test]
    fn dm_uuid_parser_requires_exact_luks2_uuid_and_safe_mapper_suffix() {
        assert_eq!(
            parse_luks2_dm_uuid(b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-kernaid-vault_01"),
            Some(*b"a9950603-ffce-492a-b082-43fba5c492a1")
        );
        for invalid in [
            b"CRYPT-LUKS1-a9950603ffce492ab08243fba5c492a1-vault".as_slice(),
            b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a-vault",
            b"CRYPT-LUKS2-A9950603ffce492ab08243fba5c492a1-vault",
            b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492ag-vault",
            b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-",
            b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-vault/name",
            b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-vault name",
        ] {
            assert_eq!(parse_luks2_dm_uuid(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn mount_attestation_is_bound_to_every_observed_kernel_identifier() {
        let observed = ObservedVaultMount {
            root_device: 11,
            mount_id: 22,
            mapping_major: 253,
            mapping_minor: 7,
            backing_major: 7,
            backing_minor: 8,
            mapper_name: *b"kernaid-vault-0123456789abcdef",
            luks_uuid: *b"a9950603-ffce-492a-b082-43fba5c492a1",
        };
        let claims = observed.test_attestation().claims;
        assert_eq!(observed.verify_attestation(claims), Ok(()));

        let mut mismatches = Vec::new();
        let mut changed = claims;
        changed.mount_id += 1;
        mismatches.push(changed);
        let mut changed = claims;
        changed.mapping_minor += 1;
        mismatches.push(changed);
        let mut changed = claims;
        changed.backing_minor += 1;
        mismatches.push(changed);
        let mut changed = claims;
        changed.mapper_name[29] = b'0';
        mismatches.push(changed);
        let mut changed = claims;
        changed.luks_uuid[35] = b'0';
        mismatches.push(changed);
        for changed in mismatches {
            assert_eq!(
                observed.verify_attestation(changed),
                Err(RescueSecretError::InvalidMountAttestation)
            );
        }
    }

    #[test]
    fn production_constructor_never_accepts_an_ordinary_directory() {
        let fixture = Fixture::new();
        let root_fd = open_root(&fixture.root).expect("open fixture root");
        let root_state =
            directory_state(&root_fd, fixture.owner, DIRECTORY_MODE).expect("fixture root state");
        let attestation = VaultMountAttestation {
            claims: MountAttestationClaims {
                root_device: root_state.device,
                mount_id: descriptor_mount_id(&root_fd).expect("fixture mount id"),
                mapping_major: rfs::major(root_state.device),
                mapping_minor: rfs::minor(root_state.device),
                backing_major: 7,
                backing_minor: 8,
                mapper_name: *b"kernaid-vault-0123456789abcdef",
                luks_uuid: *b"a9950603-ffce-492a-b082-43fba5c492a1",
            },
        };
        let expected = if rustix::process::geteuid().is_root() {
            RescueSecretError::VaultNotMounted
        } else {
            RescueSecretError::WrongOwner
        };
        assert_eq!(
            RescueVaultSecrets::open(&fixture.root, &attestation).err(),
            Some(expected)
        );
    }

    #[test]
    fn reopen_rejects_orphans_without_deleting_them() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let orphan = fixture.state_path(".tmp-0123456789abcdef0123456789abcdef");
        let orphan_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&orphan)
            .expect("create orphan");
        orphan_file.sync_all().expect("sync orphan");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(orphan.exists());
        fs::remove_file(&orphan).expect("explicit test cleanup");

        let malformed = fixture.state_path(".tmp-not-a-valid-random-name");
        let malformed_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&malformed)
            .expect("create malformed temp");
        malformed_file.sync_all().expect("sync malformed temp");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
    }

    #[test]
    fn orphan_temporary_symlink_fails_closed_without_following_it() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let outside = fixture._temporary.path().join("outside");
        fs::write(&outside, b"must survive").expect("outside file");
        let orphan = fixture.state_path(".tmp-fedcba9876543210fedcba9876543210");
        symlink(&outside, &orphan).expect("orphan symlink");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert_eq!(
            fs::read(&outside).expect("outside survives"),
            b"must survive"
        );
    }

    #[test]
    fn orphan_temporary_hardlink_is_never_deleted() {
        let fixture = Fixture::new();
        drop(fixture.open());
        let outside = fixture.state_path("outside-state-file");
        let outside_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&outside)
            .expect("outside state file");
        outside_file.sync_all().expect("sync outside state file");
        let orphan = fixture.state_path(".tmp-00112233445566778899aabbccddeeff");
        fs::hard_link(&outside, &orphan).expect("orphan hard link");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(outside.exists());
        assert!(orphan.exists());
    }

    #[test]
    fn symlinked_root_and_unsafe_existing_lock_fail_closed() {
        let fixture = Fixture::new();
        let root_link = fixture._temporary.path().join("vault-link");
        symlink(&fixture.root, &root_link).expect("root symlink");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&root_link, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );

        let lock_path = fixture.root.join(LOCK_NAME);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640))
            .expect("weaken lock permissions");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePermissions)
        );
    }

    #[test]
    fn open_never_provisions_missing_layout() {
        let fixture = Fixture::new();
        let state = fixture.root.join(STATE_DIRECTORY);
        fs::remove_dir(&state).expect("remove pre-provisioned state");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(!state.exists());

        fs::create_dir(&state).expect("restore state");
        fs::set_permissions(&state, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("restore state mode");
        let lock = fixture.root.join(LOCK_NAME);
        fs::remove_file(&lock).expect("remove pre-provisioned lock");
        assert_eq!(
            RescueVaultSecrets::open_for_test(&fixture.root, fixture.owner).err(),
            Some(RescueSecretError::UnsafePath)
        );
        assert!(!lock.exists());
    }
}
