use super::{
    MountAttestationClaims, RescueSecretError, VAULT_MARKER_NAME, VAULT_MARKER_V1,
    VaultMountAttestation, VaultOwner,
};
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
const JOURNAL_KEY_NAME: &str = "journal-key";
const JOURNAL_ANCHOR_NAME: &str = "journal-anchor";
const DEVICE_IDENTITY_NAME: &str = "device-identity";
const JOURNAL_DATABASE_NAME: &str = "audit.sqlite3";
const JOURNAL_WAL_NAME: &str = "audit.sqlite3-wal";
const JOURNAL_SHM_NAME: &str = "audit.sqlite3-shm";
const ENVELOPE_PREFIX: &[u8] = b"kernaid-rescue-secret-v1:";
const IDENTITY_SEED_BYTES: usize = 32;
const MAX_ENVELOPE_BYTES: usize = 256;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const MAX_DM_UUID_BYTES: u64 = 512;
const MAX_DM_UUID_LENGTH: usize = 128;
const DM_LUKS2_PREFIX: &[u8] = b"CRYPT-LUKS2-";
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_PREFIX_BYTES: usize = 64;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_ERRORS_OFFSET: usize = 60;
const EXT4_ERRORS_REMOUNT_READ_ONLY: u16 = 2;
const ORPHAN_SCAN_BUFFER_BYTES: usize = 8192;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Owns the vault-wide lock and creates scoped journal and identity handles.
/// Derived handles borrow this value and therefore cannot outlive the verified
/// mapping/mount boundary that owns it.
pub struct RescueVaultSecrets {
    inner: VaultInner,
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
    pub fn journal_store(&self) -> RescueJournalSecretStore<'_> {
        RescueJournalSecretStore { inner: &self.inner }
    }

    /// Build a device-identity store sharing this vault's exclusive lock.
    #[must_use]
    pub fn device_identity_store(&self) -> RescueDeviceIdentityStore<'_> {
        RescueDeviceIdentityStore { inner: &self.inner }
    }

    /// Explicitly open or initialize the encrypted audit journal. Unlike
    /// [`Self::open`], this is a state-mutating application operation and must
    /// only be called after the pre-provisioned vault boundary is accepted.
    pub fn open_journal(
        &self,
    ) -> Result<SecureJournal<RescueJournalSecretStore<'_>>, JournalError> {
        self.inner
            .preflight_journal_layout()
            .map_err(|_| JournalError::InvalidPath)?;
        let path = self
            .inner
            .root_path
            .join(STATE_DIRECTORY)
            .join(JOURNAL_DATABASE_NAME);
        SecureJournal::open(&path, self.journal_store())
    }

    #[cfg(test)]
    fn open_for_test(root: impl AsRef<Path>, owner: VaultOwner) -> Result<Self, RescueSecretError> {
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
        reject_orphan_temporary_files(&state_fd, root_mount_id)?;

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
        };
        inner.ensure_integrity()?;
        Ok(Self { inner })
    }
}

/// LUKS-vault implementation of the encrypted journal's secret-store trait.
pub struct RescueJournalSecretStore<'vault> {
    inner: &'vault VaultInner,
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
    inner: &'vault VaultInner,
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
    pub fn create_device_identity(&mut self) -> Result<DeviceIdentity, RescueSecretError> {
        if self.load_device_identity()?.is_some() {
            return Err(RescueSecretError::IdentityAlreadyExists);
        }
        let identity = DeviceIdentity::generate();
        self.store_new_device_identity(&identity)?;
        Ok(identity)
    }
}

struct VaultInner {
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
}

impl VaultInner {
    fn preflight_journal_layout(&self) -> Result<(), RescueSecretError> {
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

    fn operation_guard(&self) -> Result<MutexGuard<'_, ()>, RescueSecretError> {
        self.operation_lock
            .lock()
            .map_err(|_| RescueSecretError::StorageUnavailable)
    }

    fn ensure_integrity(&self) -> Result<(), RescueSecretError> {
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

fn reject_orphan_temporary_files(
    directory: &OwnedFd,
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

    let mut buffer = [MaybeUninit::<u8>::uninit(); ORPHAN_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(&scan_fd, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| RescueSecretError::StorageUnavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || !name.starts_with(b".tmp-") {
            continue;
        }
        // Unlock/open is layout-validation only. Recovery or deletion of a
        // prior crash artifact requires a separate explicit maintenance flow.
        return Err(RescueSecretError::UnsafePath);
    }
    Ok(())
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
    if entry.mount_root != b"/"
        || !entry.read_write
        || !entry.no_suid
        || !entry.no_dev
        || !entry.no_exec
        || !entry.no_sym_follow
        || entry.mount_id != root_mount_id
        || entry.major != rfs::major(root_state.device)
        || entry.minor != rfs::minor(root_state.device)
    {
        return Err(RescueSecretError::VaultNotMounted);
    }
    if entry.filesystem.as_slice() != b"ext4" {
        return Err(RescueSecretError::UnsupportedFilesystem);
    }
    if !entry.source.starts_with(b"/dev/") {
        return Err(RescueSecretError::VaultNotMounted);
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
    source: Vec<u8>,
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
    let source = decode_mountinfo_field(fields[separator + 2])?;
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
        source,
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
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
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
