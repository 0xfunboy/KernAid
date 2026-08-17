#![forbid(unsafe_code)]

use fs2::FileExt as _;
use kernaid_native_secrets::{
    NativeOpenAiApiKeyStore, NativeProviderSecretStatus, NativeSecretError,
};
use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use rustix::{
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags},
    process,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(not(unix))]
use std::fs::OpenOptions;

pub const RESIDENT_SECRET_NAMESPACE: &str = "resident-v1";
pub const OPENAI_PROVIDER_PROFILE: &str = "resident-default";
const APP_IDENTIFIER: &str = "dev.kernaid.desk";
#[cfg(any(test, not(unix)))]
const PROVIDER_LOCK_FILE_NAME: &str = ".resident-openai-v1.lock";

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentOpenAiCredentialError {
    InvalidApplicationDirectory,
    InstanceAlreadyRunning,
    CredentialUnavailable,
    CredentialInvalid,
    CredentialWriteFailed,
}

impl fmt::Display for ResidentOpenAiCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidApplicationDirectory => {
                "KernAid cannot establish its private application directory"
            }
            Self::InstanceAlreadyRunning => {
                "close KernAid Desk before using the provider credential companion"
            }
            Self::CredentialUnavailable => "the operating-system credential store is unavailable",
            Self::CredentialInvalid => "the provider credential is invalid",
            Self::CredentialWriteFailed => "the provider credential operation was not verified",
        })
    }
}

impl Error for ResidentOpenAiCredentialError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentOpenAiCredentialStatus {
    Absent,
    Configured,
}

/// Resident-only OpenAI credential access guarded by an inter-process lock.
///
/// The lock is held for the lifetime of this value. The secret can only be
/// borrowed through a scoped callback; it has no serializable or raw getter.
pub struct ResidentOpenAiCredentials {
    store: Mutex<NativeOpenAiApiKeyStore>,
    _instance_lock: File,
}

impl ResidentOpenAiCredentials {
    pub fn open(app_data_directory: &Path) -> Result<Self, ResidentOpenAiCredentialError> {
        if app_data_directory != default_app_data_directory()? {
            return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
        }
        ensure_private_directory(app_data_directory)?;
        let instance_lock = open_instance_lock(&provider_lock_path(app_data_directory))?;
        let store =
            NativeOpenAiApiKeyStore::open_named(RESIDENT_SECRET_NAMESPACE, OPENAI_PROVIDER_PROFILE)
                .map_err(map_open_error)?;
        Ok(Self {
            store: Mutex::new(store),
            _instance_lock: instance_lock,
        })
    }

    pub fn status(&self) -> Result<ResidentOpenAiCredentialStatus, ResidentOpenAiCredentialError> {
        match lock_store(&self.store)?
            .status()
            .map_err(map_native_error)?
        {
            NativeProviderSecretStatus::Absent => Ok(ResidentOpenAiCredentialStatus::Absent),
            NativeProviderSecretStatus::Configured => {
                Ok(ResidentOpenAiCredentialStatus::Configured)
            }
        }
    }

    pub fn configure(
        &self,
        api_key: Zeroizing<Vec<u8>>,
    ) -> Result<(), ResidentOpenAiCredentialError> {
        lock_store(&self.store)?
            .configure(api_key)
            .map_err(map_native_error)
    }

    pub fn with_api_key<T>(
        &self,
        use_secret: impl FnOnce(&[u8]) -> T,
    ) -> Result<Option<T>, ResidentOpenAiCredentialError> {
        lock_store(&self.store)?
            .with_openai_api_key(use_secret)
            .map_err(map_native_error)
    }

    pub fn logout(&self) -> Result<(), ResidentOpenAiCredentialError> {
        lock_store(&self.store)?.logout().map_err(map_native_error)
    }
}

pub fn default_app_data_directory() -> Result<PathBuf, ResidentOpenAiCredentialError> {
    let root =
        dirs::data_dir().ok_or(ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    if !root.is_absolute() {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    Ok(root.join(APP_IDENTIFIER))
}

#[cfg(unix)]
fn provider_lock_path(_app_data_directory: &Path) -> PathBuf {
    Path::new("/tmp").join(format!(
        ".kernaid-resident-openai-v1-{}-{}.lock",
        OPENAI_PROVIDER_PROFILE,
        process::getuid().as_raw()
    ))
}

#[cfg(not(unix))]
fn provider_lock_path(app_data_directory: &Path) -> PathBuf {
    app_data_directory.join(PROVIDER_LOCK_FILE_NAME)
}

fn lock_store(
    store: &Mutex<NativeOpenAiApiKeyStore>,
) -> Result<MutexGuard<'_, NativeOpenAiApiKeyStore>, ResidentOpenAiCredentialError> {
    store
        .lock()
        .map_err(|_| ResidentOpenAiCredentialError::CredentialUnavailable)
}

fn map_open_error(error: NativeSecretError) -> ResidentOpenAiCredentialError {
    match error {
        NativeSecretError::InvalidNamespace | NativeSecretError::InvalidProviderProfile => {
            ResidentOpenAiCredentialError::CredentialInvalid
        }
        _ => ResidentOpenAiCredentialError::CredentialUnavailable,
    }
}

fn map_native_error(error: NativeSecretError) -> ResidentOpenAiCredentialError {
    match error {
        NativeSecretError::InvalidProviderCredential
        | NativeSecretError::InvalidProviderProfile
        | NativeSecretError::InvalidNamespace => ResidentOpenAiCredentialError::CredentialInvalid,
        NativeSecretError::WriteVerificationFailed => {
            ResidentOpenAiCredentialError::CredentialWriteFailed
        }
        NativeSecretError::UnsupportedPlatform
        | NativeSecretError::BackendUnavailable
        | NativeSecretError::StorageAccessDenied
        | NativeSecretError::AmbiguousEntry
        | NativeSecretError::InvalidStoredValue
        | NativeSecretError::InvalidRequest
        | NativeSecretError::IdentityAlreadyExists
        | NativeSecretError::ConcurrentIdentityWrite => {
            ResidentOpenAiCredentialError::CredentialUnavailable
        }
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), ResidentOpenAiCredentialError> {
    if !path.is_absolute() {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
        }
        Err(_) => return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != process::getuid().as_raw() {
            return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
        let hardened = fs::symlink_metadata(path)
            .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
        if hardened.mode() & 0o7777 != 0o700 {
            return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_instance_lock(path: &Path) -> Result<File, ResidentOpenAiCredentialError> {
    let fd = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    let descriptor =
        rfs::fstat(&fd).map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    let named = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    if !FileType::from_raw_mode(descriptor.st_mode).is_file()
        || !FileType::from_raw_mode(named.st_mode).is_file()
        || descriptor.st_dev != named.st_dev
        || descriptor.st_ino != named.st_ino
        || descriptor.st_nlink != 1
        || descriptor.st_uid != process::getuid().as_raw()
    {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    rfs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    let hardened =
        rfs::fstat(&fd).map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    if Mode::from_raw_mode(hardened.st_mode).as_raw_mode() & 0o7777 != 0o600 {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    lock_file(File::from(fd))
}

#[cfg(windows)]
fn open_instance_lock(path: &Path) -> Result<File, ResidentOpenAiCredentialError> {
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    let metadata = file
        .metadata()
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory);
    }
    lock_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_instance_lock(path: &Path) -> Result<File, ResidentOpenAiCredentialError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|_| ResidentOpenAiCredentialError::InvalidApplicationDirectory)?;
    lock_file(file)
}

fn lock_file(file: File) -> Result<File, ResidentOpenAiCredentialError> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Err(ResidentOpenAiCredentialError::InstanceAlreadyRunning)
        }
        Err(_) => Err(ResidentOpenAiCredentialError::InvalidApplicationDirectory),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_lock_is_exclusive_and_recovers_after_drop() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(PROVIDER_LOCK_FILE_NAME);
        let first = open_instance_lock(&path).expect("first lock");
        assert_eq!(
            open_instance_lock(&path).expect_err("second lock must fail"),
            ResidentOpenAiCredentialError::InstanceAlreadyRunning
        );
        drop(first);
        assert!(open_instance_lock(&path).is_ok());
    }

    #[test]
    fn app_data_path_matches_the_tauri_dirs_contract_and_rejects_overrides() {
        let canonical = default_app_data_directory().expect("canonical application data path");
        assert_eq!(
            canonical,
            dirs::data_dir()
                .expect("platform data directory")
                .join(APP_IDENTIFIER)
        );
        let alternate = canonical.with_file_name("dev.kernaid.desk-alternate");
        assert_eq!(
            ResidentOpenAiCredentials::open(&alternate)
                .err()
                .expect("alternate lock root must fail"),
            ResidentOpenAiCredentialError::InvalidApplicationDirectory
        );
    }

    #[cfg(unix)]
    #[test]
    fn provider_lock_identity_is_independent_of_app_data_paths() {
        assert_eq!(
            provider_lock_path(Path::new("/one/app-data-root")),
            provider_lock_path(Path::new("/another/app-data-root"))
        );
        assert_eq!(
            provider_lock_path(Path::new("/ignored"))
                .parent()
                .expect("global lock parent"),
            Path::new("/tmp")
        );
    }

    #[cfg(unix)]
    #[test]
    fn provider_lock_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        File::create(&target).expect("target file");
        let link = directory.path().join(PROVIDER_LOCK_FILE_NAME);
        symlink(&target, &link).expect("lock symlink");
        assert_eq!(
            open_instance_lock(&link).expect_err("symlink must fail"),
            ResidentOpenAiCredentialError::InvalidApplicationDirectory
        );
    }

    #[cfg(unix)]
    #[test]
    fn provider_lock_rejects_hardlinks_without_changing_target_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        File::create(&target).expect("target file");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
            .expect("target permissions");
        let link = directory.path().join(PROVIDER_LOCK_FILE_NAME);
        fs::hard_link(&target, &link).expect("lock hardlink");
        assert_eq!(
            open_instance_lock(&link).expect_err("hardlink must fail"),
            ResidentOpenAiCredentialError::InvalidApplicationDirectory
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
    }
}
