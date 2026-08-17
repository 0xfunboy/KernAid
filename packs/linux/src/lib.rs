#![forbid(unsafe_code)]
//! Linux repair-pack primitives. Mutations in this crate are restricted to
//! explicitly marked disposable fixtures until the production broker exists.

pub mod action_contract;
pub mod diagnostics;

use rustix::{
    fd::OwnedFd,
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Gid, Mode, OFlags, RenameFlags, Stat,
        Uid,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const FIXTURE_MARKER: &[u8] = b"KERNAID_DISPOSABLE_FIXTURE_V1\n";
const FSTAB_NAME: &str = "fstab";
const LOCK_NAME: &str = ".kernaid-fstab.lock";
const MAX_FSTAB_BYTES: usize = 1024 * 1024;
const MAX_FSTAB_LINE_BYTES: usize = 16 * 1024;
const REPAIR_COMMENT: &[u8] = b"# KernAid disabled missing device: ";
const BROKEN_FIELDS: [&[u8]; 6] = [
    b"UUID=missing-data",
    b"/mnt/data",
    b"ext4",
    b"defaults",
    b"0",
    b"2",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackReceipt {
    pub replaced_fingerprint: String,
    pub restored_fingerprint: String,
    pub backup_path: PathBuf,
    pub backup_fingerprint: String,
    pub automatic: bool,
    pub validation_passed: bool,
    pub metadata_preserved: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RepairError {
    NotDisposableFixture,
    UnsafePath,
    MissingEvidence,
    StaleTarget,
    ApprovalRequired,
    BackupInsideTarget,
    BackupExists,
    ResourceLocked,
    RepairNotApplicable,
    AmbiguousTarget,
    ValidationFailed,
    UnsupportedMetadata,
    MetadataPreservationFailed,
    PostInstallRolledBack {
        cause: Box<RepairError>,
        rollback: RollbackReceipt,
    },
    AutomaticRollbackFailed {
        cause: Box<RepairError>,
        rollback: Box<RepairError>,
    },
    Io(String),
}

impl From<std::io::Error> for RepairError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabPreview {
    /// Opaque execution precondition binding content, ownership, mode, and
    /// the exact file observed during preview.
    pub target_fingerprint: String,
    /// Content-only fingerprint suitable for receipts and user-visible
    /// comparisons. It is not sufficient to authorize execution.
    pub target_content_fingerprint: String,
    pub before: String,
    pub after: String,
    pub backup_required: bool,
    pub validation: &'static str,
    pub rollback: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairReceipt {
    pub before_fingerprint: String,
    pub after_fingerprint: String,
    /// Opaque rollback precondition for the exact installed file and its
    /// supported metadata.
    pub after_target_precondition: String,
    pub backup_path: PathBuf,
    pub backup_fingerprint: String,
    pub before_metadata: PreservedMetadata,
    pub validation_passed: bool,
    pub metadata_preserved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileState {
    identity: FileIdentity,
    metadata: PreservedMetadata,
}

struct Snapshot {
    bytes: Vec<u8>,
    state: FileState,
}

struct Fixture {
    canonical_path: PathBuf,
    _root: OwnedFd,
    etc: OwnedFd,
}

struct BackupHandle {
    path: PathBuf,
    fingerprint: String,
}

fn fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn snapshot_precondition(snapshot: &Snapshot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"KERNAID_FSTAB_SNAPSHOT_PRECONDITION_V1\0");
    digest.update(
        u64::try_from(snapshot.bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(&snapshot.bytes);
    digest.update(snapshot.state.identity.device.to_be_bytes());
    digest.update(snapshot.state.identity.inode.to_be_bytes());
    digest.update(snapshot.state.metadata.mode.to_be_bytes());
    digest.update(snapshot.state.metadata.uid.to_be_bytes());
    digest.update(snapshot.state.metadata.gid.to_be_bytes());
    format!("sha256:{:x}", digest.finalize())
}

fn rustix_error(error: rustix::io::Errno) -> RepairError {
    RepairError::Io(error.to_string())
}

fn state_from_stat(stat: &Stat) -> Result<FileState, RepairError> {
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_size < 0 {
        return Err(RepairError::UnsafePath);
    }
    Ok(FileState {
        identity: FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        },
        metadata: PreservedMetadata {
            mode: Mode::from_raw_mode(stat.st_mode).as_raw_mode(),
            uid: stat.st_uid,
            gid: stat.st_gid,
        },
    })
}

fn same_identity(left: &FileState, right: &FileState) -> bool {
    left.identity == right.identity
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn reject_unsupported_metadata(file: &File) -> Result<(), RepairError> {
    let mut empty = [0_u8; 0];
    match rfs::flistxattr(file, &mut empty) {
        Ok(0) => Ok(()),
        Ok(_) | Err(_) => Err(RepairError::UnsupportedMetadata),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn reject_unsupported_metadata(_file: &File) -> Result<(), RepairError> {
    Err(RepairError::UnsupportedMetadata)
}

fn open_directory(path: &Path) -> Result<(PathBuf, OwnedFd), RepairError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_dir() || path_metadata.file_type().is_symlink() {
        return Err(RepairError::UnsafePath);
    }
    let canonical = fs::canonicalize(path)?;
    let fd = rfs::openat(
        CWD,
        &canonical,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_error)?;
    let descriptor_stat = rfs::fstat(&fd).map_err(rustix_error)?;
    let name_stat =
        rfs::statat(CWD, &canonical, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_error)?;
    if !FileType::from_raw_mode(descriptor_stat.st_mode).is_dir()
        || !FileType::from_raw_mode(name_stat.st_mode).is_dir()
        || descriptor_stat.st_dev != name_stat.st_dev
        || descriptor_stat.st_ino != name_stat.st_ino
    {
        return Err(RepairError::UnsafePath);
    }
    Ok((canonical, fd))
}

fn open_subdirectory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, RepairError> {
    rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RepairError::UnsafePath)
}

fn open_named_regular(parent: &OwnedFd, name: &Path) -> Result<(File, FileState), RepairError> {
    let fd = rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RepairError::UnsafePath)?;
    let state = state_from_stat(&rfs::fstat(&fd).map_err(rustix_error)?)?;
    let named = state_from_stat(
        &rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_error)?,
    )?;
    if !same_identity(&state, &named) {
        return Err(RepairError::StaleTarget);
    }
    let file = File::from(fd);
    reject_unsupported_metadata(&file)?;
    Ok((file, state))
}

fn read_bounded(file: &File) -> Result<Vec<u8>, RepairError> {
    let stat = rfs::fstat(file).map_err(rustix_error)?;
    let size = usize::try_from(stat.st_size).map_err(|_| RepairError::ValidationFailed)?;
    if size > MAX_FSTAB_BYTES {
        return Err(RepairError::ValidationFailed);
    }
    let mut duplicate = File::from(rustix::io::dup(file).map_err(rustix_error)?);
    duplicate.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(size);
    duplicate
        .take((MAX_FSTAB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FSTAB_BYTES {
        return Err(RepairError::ValidationFailed);
    }
    Ok(bytes)
}

fn snapshot_named(parent: &OwnedFd, name: &Path) -> Result<Snapshot, RepairError> {
    let (file, state) = open_named_regular(parent, name)?;
    let bytes = read_bounded(&file)?;
    reject_unsupported_metadata(&file)?;
    let final_state = state_from_stat(&rfs::fstat(&file).map_err(rustix_error)?)?;
    let named_state = state_from_stat(
        &rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_error)?,
    )?;
    if final_state != state || named_state != state {
        return Err(RepairError::StaleTarget);
    }
    Ok(Snapshot { bytes, state })
}

fn canonical_fixture(root: &Path) -> Result<Fixture, RepairError> {
    let (canonical_path, root_fd) = open_directory(root)?;
    let marker = snapshot_named(&root_fd, Path::new(".kernaid-disposable-fixture"))?;
    if marker.bytes != FIXTURE_MARKER {
        return Err(RepairError::NotDisposableFixture);
    }
    let etc = open_subdirectory(&root_fd, "etc")?;
    Ok(Fixture {
        canonical_path,
        _root: root_fd,
        etc,
    })
}

#[derive(Debug)]
struct ParsedLine {
    start: usize,
    content_end: usize,
    fields: Option<Vec<Vec<u8>>>,
}

fn decode_field(field: &[u8]) -> Result<Vec<u8>, RepairError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut cursor = 0;
    while cursor < field.len() {
        let byte = field[cursor];
        if byte == b'\\' {
            if cursor + 3 >= field.len()
                || !field[cursor + 1..=cursor + 3]
                    .iter()
                    .all(|digit| matches!(digit, b'0'..=b'7'))
            {
                return Err(RepairError::ValidationFailed);
            }
            let value = u16::from(field[cursor + 1] - b'0') * 64
                + u16::from(field[cursor + 2] - b'0') * 8
                + u16::from(field[cursor + 3] - b'0');
            decoded.push(u8::try_from(value).map_err(|_| RepairError::ValidationFailed)?);
            cursor += 4;
        } else {
            if byte < b' ' || byte == 0x7f {
                return Err(RepairError::ValidationFailed);
            }
            decoded.push(byte);
            cursor += 1;
        }
    }
    Ok(decoded)
}

fn parse_fstab(bytes: &[u8]) -> Result<Vec<ParsedLine>, RepairError> {
    if bytes.len() > MAX_FSTAB_BYTES || bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Err(RepairError::ValidationFailed);
    }
    let mut parsed = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset + 1);
        let content_end = if newline > start && bytes[newline - 1] == b'\n' {
            newline - 1
        } else {
            newline
        };
        let content = &bytes[start..content_end];
        if content.len() > MAX_FSTAB_LINE_BYTES || content.contains(&b'\r') {
            return Err(RepairError::ValidationFailed);
        }
        let first = content
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'));
        let fields = if first.is_none() || first.is_some_and(|index| content[index] == b'#') {
            None
        } else {
            let mut fields = Vec::new();
            let mut cursor = 0;
            while cursor < content.len() {
                while cursor < content.len() && matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                if cursor == content.len() {
                    break;
                }
                let field_start = cursor;
                while cursor < content.len() && !matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                fields.push(decode_field(&content[field_start..cursor])?);
                if fields.len() > 6 {
                    return Err(RepairError::ValidationFailed);
                }
            }
            if !(4..=6).contains(&fields.len()) {
                return Err(RepairError::ValidationFailed);
            }
            for numeric in fields.iter().skip(4) {
                let value = std::str::from_utf8(numeric)
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok());
                if value.is_none() {
                    return Err(RepairError::ValidationFailed);
                }
            }
            Some(fields)
        };
        parsed.push(ParsedLine {
            start,
            content_end,
            fields,
        });
        start = newline;
    }
    Ok(parsed)
}

fn is_broken_entry(fields: &[Vec<u8>]) -> bool {
    fields.len() == BROKEN_FIELDS.len()
        && fields
            .iter()
            .zip(BROKEN_FIELDS)
            .all(|(actual, expected)| actual.as_slice() == expected)
}

fn repaired(bytes: &[u8]) -> Result<Vec<u8>, RepairError> {
    let parsed = parse_fstab(bytes)?;
    let targets: Vec<&ParsedLine> = parsed
        .iter()
        .filter(|line| line.fields.as_deref().is_some_and(is_broken_entry))
        .collect();
    let target = match targets.as_slice() {
        [] => return Err(RepairError::RepairNotApplicable),
        [target] => *target,
        _ => return Err(RepairError::AmbiguousTarget),
    };
    let mut result = Vec::with_capacity(bytes.len() + REPAIR_COMMENT.len());
    result.extend_from_slice(&bytes[..target.start]);
    result.extend_from_slice(REPAIR_COMMENT);
    result.extend_from_slice(&bytes[target.start..target.content_end]);
    result.extend_from_slice(&bytes[target.content_end..]);
    let validated = parse_fstab(&result)?;
    if validated
        .iter()
        .any(|line| line.fields.as_deref().is_some_and(is_broken_entry))
    {
        return Err(RepairError::ValidationFailed);
    }
    Ok(result)
}

fn prepare_metadata(file: &File, metadata: &PreservedMetadata) -> Result<(), RepairError> {
    rfs::fchown(
        file,
        Some(Uid::from_raw(metadata.uid)),
        Some(Gid::from_raw(metadata.gid)),
    )
    .map_err(|_| RepairError::MetadataPreservationFailed)?;
    rfs::fchmod(file, Mode::from_raw_mode(metadata.mode))
        .map_err(|_| RepairError::MetadataPreservationFailed)?;
    let actual = state_from_stat(&rfs::fstat(file).map_err(rustix_error)?)?;
    if actual.metadata != *metadata {
        return Err(RepairError::MetadataPreservationFailed);
    }
    Ok(())
}

fn sync_directory(directory: &OwnedFd) -> Result<(), RepairError> {
    rfs::fsync(directory).map_err(rustix_error)
}

struct NamedFileGuard {
    directory: OwnedFd,
    name: String,
    identity: Option<FileIdentity>,
    armed: bool,
}

impl NamedFileGuard {
    fn new(directory: &OwnedFd, name: &str) -> Result<Self, RepairError> {
        Ok(Self {
            directory: rustix::io::dup(directory).map_err(rustix_error)?,
            name: name.to_owned(),
            identity: None,
            armed: true,
        })
    }

    fn set_identity(&mut self, state: &FileState) {
        self.identity = Some(state.identity);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for NamedFileGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let (Some(expected), Ok(stat)) = (
            self.identity,
            rfs::statat(
                &self.directory,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ),
        ) && stat.st_dev == expected.device
            && stat.st_ino == expected.inode
        {
            let _ = rfs::unlinkat(&self.directory, self.name.as_str(), AtFlags::empty());
            let _ = rfs::fsync(&self.directory);
        }
    }
}

fn create_prepared_file(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
    metadata: &PreservedMetadata,
) -> Result<(FileState, NamedFileGuard), RepairError> {
    let mut guard = NamedFileGuard::new(directory, name)?;
    let fd = rfs::openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(rustix_error)?;
    let mut file = File::from(fd);
    let initial = state_from_stat(&rfs::fstat(&file).map_err(rustix_error)?)?;
    guard.set_identity(&initial);
    file.write_all(bytes)?;
    prepare_metadata(&file, metadata)?;
    file.sync_all()?;
    let state = state_from_stat(&rfs::fstat(&file).map_err(rustix_error)?)?;
    guard.set_identity(&state);
    let written = read_bounded(&file)?;
    if written != bytes {
        return Err(RepairError::ValidationFailed);
    }
    let named = snapshot_named(directory, Path::new(name))?;
    if !same_identity(&state, &named.state) || named.bytes != bytes {
        return Err(RepairError::StaleTarget);
    }
    sync_directory(directory)?;
    Ok((state, guard))
}

fn remove_name_if_identity(
    directory: &OwnedFd,
    name: &str,
    expected: &FileState,
) -> Result<(), RepairError> {
    let current = state_from_stat(
        &rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(rustix_error)?,
    )?;
    if !same_identity(&current, expected) {
        return Err(RepairError::StaleTarget);
    }
    rfs::unlinkat(directory, name, AtFlags::empty()).map_err(rustix_error)
}

struct FixtureLock {
    _file: OwnedFd,
}

impl FixtureLock {
    fn acquire(directory: &OwnedFd) -> Result<Self, RepairError> {
        let create_flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let file = match rfs::openat(directory, LOCK_NAME, create_flags, Mode::RUSR | Mode::WUSR) {
            Ok(file) => file,
            Err(error) if error == rustix::io::Errno::EXIST => rfs::openat(
                directory,
                LOCK_NAME,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RepairError::UnsafePath)?,
            Err(error) => return Err(rustix_error(error)),
        };
        let directory_stat = rfs::fstat(directory).map_err(rustix_error)?;
        let descriptor_stat = rfs::fstat(&file).map_err(rustix_error)?;
        let name_stat = rfs::statat(directory, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RepairError::UnsafePath)?;
        if !FileType::from_raw_mode(descriptor_stat.st_mode).is_file()
            || !FileType::from_raw_mode(name_stat.st_mode).is_file()
            || descriptor_stat.st_dev != name_stat.st_dev
            || descriptor_stat.st_ino != name_stat.st_ino
            || descriptor_stat.st_nlink != 1
            || descriptor_stat.st_uid != directory_stat.st_uid
            || descriptor_stat.st_gid != directory_stat.st_gid
        {
            return Err(RepairError::UnsafePath);
        }
        rfs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK {
                RepairError::ResourceLocked
            } else {
                rustix_error(error)
            }
        })?;
        rfs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| RepairError::UnsafePath)?;
        rfs::fsync(&file).map_err(rustix_error)?;
        sync_directory(directory)?;
        let locked_descriptor = rfs::fstat(&file).map_err(rustix_error)?;
        let locked_name = rfs::statat(directory, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RepairError::UnsafePath)?;
        if !FileType::from_raw_mode(locked_descriptor.st_mode).is_file()
            || !FileType::from_raw_mode(locked_name.st_mode).is_file()
            || locked_descriptor.st_dev != locked_name.st_dev
            || locked_descriptor.st_ino != locked_name.st_ino
            || locked_descriptor.st_nlink != 1
            || locked_descriptor.st_uid != directory_stat.st_uid
            || locked_descriptor.st_gid != directory_stat.st_gid
            || Mode::from_raw_mode(locked_descriptor.st_mode) != (Mode::RUSR | Mode::WUSR)
        {
            return Err(RepairError::UnsafePath);
        }
        Ok(Self { _file: file })
    }
}

fn create_backup(
    directory: &OwnedFd,
    canonical_directory: &Path,
    name: &str,
    before: &Snapshot,
) -> Result<BackupHandle, RepairError> {
    let mut guard = NamedFileGuard::new(directory, name)?;
    let fd = rfs::openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            RepairError::BackupExists
        } else {
            rustix_error(error)
        }
    })?;
    let mut file = File::from(fd);
    let initial = state_from_stat(&rfs::fstat(&file).map_err(rustix_error)?)?;
    guard.set_identity(&initial);
    file.write_all(&before.bytes)?;
    prepare_metadata(&file, &before.state.metadata)?;
    file.sync_all()?;
    let state = state_from_stat(&rfs::fstat(&file).map_err(rustix_error)?)?;
    guard.set_identity(&state);
    sync_directory(directory)?;
    let verified = read_bounded(&file)?;
    let backup_fingerprint = fingerprint(&verified);
    if verified != before.bytes || backup_fingerprint != fingerprint(&before.bytes) {
        return Err(RepairError::ValidationFailed);
    }
    let named = snapshot_named(directory, Path::new(name))?;
    if !same_identity(&state, &named.state)
        || named.bytes != before.bytes
        || named.state.metadata != before.state.metadata
    {
        return Err(RepairError::ValidationFailed);
    }
    guard.disarm();
    Ok(BackupHandle {
        path: canonical_directory.join(name),
        fingerprint: backup_fingerprint,
    })
}

fn rollback_exchange(
    fixture: &Fixture,
    temporary_name: &str,
    new_state: &FileState,
    guard: &mut NamedFileGuard,
    backup: &BackupHandle,
) -> Result<RollbackReceipt, RepairError> {
    let installed = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if !same_identity(&installed.state, new_state) {
        return Err(RepairError::StaleTarget);
    }
    let displaced = snapshot_named(&fixture.etc, Path::new(temporary_name))?;
    rfs::renameat_with(
        &fixture.etc,
        temporary_name,
        &fixture.etc,
        FSTAB_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(rustix_error)?;
    sync_directory(&fixture.etc)?;
    let restored = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if !same_identity(&restored.state, &displaced.state)
        || restored.bytes != displaced.bytes
        || restored.state.metadata != displaced.state.metadata
    {
        return Err(RepairError::ValidationFailed);
    }
    remove_name_if_identity(&fixture.etc, temporary_name, new_state)?;
    guard.disarm();
    sync_directory(&fixture.etc)?;
    Ok(RollbackReceipt {
        replaced_fingerprint: fingerprint(&installed.bytes),
        restored_fingerprint: fingerprint(&restored.bytes),
        backup_path: backup.path.clone(),
        backup_fingerprint: backup.fingerprint.clone(),
        automatic: true,
        validation_passed: true,
        metadata_preserved: true,
    })
}

fn restore_from_copy(
    fixture: &Fixture,
    restore: &Snapshot,
    expected_current: &Snapshot,
    backup: &BackupHandle,
) -> Result<RollbackReceipt, RepairError> {
    let digest = fingerprint(&restore.bytes);
    let digest = digest
        .strip_prefix("sha256:")
        .ok_or(RepairError::ValidationFailed)?;
    let temporary_name = format!(".fstab.kernaid-emergency-{}", &digest[..16]);
    let (restored_state, mut guard) = create_prepared_file(
        &fixture.etc,
        &temporary_name,
        &restore.bytes,
        &restore.state.metadata,
    )?;
    let current = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if !same_identity(&current.state, &expected_current.state)
        || current.bytes != expected_current.bytes
    {
        return Err(RepairError::StaleTarget);
    }
    rfs::renameat_with(
        &fixture.etc,
        temporary_name.as_str(),
        &fixture.etc,
        FSTAB_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(rustix_error)?;
    sync_directory(&fixture.etc)?;
    let restored = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    let displaced = snapshot_named(&fixture.etc, Path::new(&temporary_name))?;
    if !same_identity(&restored.state, &restored_state)
        || restored.bytes != restore.bytes
        || restored.state.metadata != restore.state.metadata
        || !same_identity(&displaced.state, &expected_current.state)
        || displaced.bytes != expected_current.bytes
    {
        return Err(RepairError::ValidationFailed);
    }
    parse_fstab(&restored.bytes)?;
    remove_name_if_identity(&fixture.etc, &temporary_name, &expected_current.state)?;
    guard.disarm();
    sync_directory(&fixture.etc)?;
    Ok(RollbackReceipt {
        replaced_fingerprint: fingerprint(&expected_current.bytes),
        restored_fingerprint: fingerprint(&restored.bytes),
        backup_path: backup.path.clone(),
        backup_fingerprint: backup.fingerprint.clone(),
        automatic: true,
        validation_passed: true,
        metadata_preserved: true,
    })
}

fn copy_rollback_error(
    cause: RepairError,
    fixture: &Fixture,
    restore: &Snapshot,
    expected_current: &Snapshot,
    backup: &BackupHandle,
) -> RepairError {
    match restore_from_copy(fixture, restore, expected_current, backup) {
        Ok(rollback) => RepairError::PostInstallRolledBack {
            cause: Box::new(cause),
            rollback,
        },
        Err(rollback) => RepairError::AutomaticRollbackFailed {
            cause: Box::new(cause),
            rollback: Box::new(rollback),
        },
    }
}

fn post_install_error(
    cause: RepairError,
    fixture: &Fixture,
    temporary_name: &str,
    new_state: &FileState,
    guard: &mut NamedFileGuard,
    backup: &BackupHandle,
) -> RepairError {
    match rollback_exchange(fixture, temporary_name, new_state, guard, backup) {
        Ok(rollback) => RepairError::PostInstallRolledBack {
            cause: Box::new(cause),
            rollback,
        },
        Err(rollback) => RepairError::AutomaticRollbackFailed {
            cause: Box::new(cause),
            rollback: Box::new(rollback),
        },
    }
}

fn validate_installed(bytes: &[u8], expected: &[u8]) -> Result<(), RepairError> {
    if bytes != expected {
        return Err(RepairError::ValidationFailed);
    }
    let parsed = parse_fstab(bytes)?;
    if parsed
        .iter()
        .any(|line| line.fields.as_deref().is_some_and(is_broken_entry))
    {
        return Err(RepairError::ValidationFailed);
    }
    Ok(())
}

pub fn preview_missing_fstab_device(
    root: &Path,
    evidence_ids: &[String],
) -> Result<FstabPreview, RepairError> {
    if evidence_ids.is_empty() {
        return Err(RepairError::MissingEvidence);
    }
    let fixture = canonical_fixture(root)?;
    let before = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    let after = repaired(&before.bytes)?;
    let target_content_fingerprint = fingerprint(&before.bytes);
    Ok(FstabPreview {
        target_fingerprint: snapshot_precondition(&before),
        target_content_fingerprint,
        before: String::from_utf8(before.bytes).map_err(|_| RepairError::ValidationFailed)?,
        after: String::from_utf8(after).map_err(|_| RepairError::ValidationFailed)?,
        backup_required: true,
        validation: "fstab is syntactically parsed and the unique missing UUID entry is disabled",
        rollback: "atomically restore the byte-verified backup and original mode/uid/gid",
    })
}

pub fn execute_missing_fstab_device_repair(
    root: &Path,
    backup_dir: &Path,
    expected_precondition: &str,
    evidence_ids: &[String],
    approval_id: &str,
) -> Result<RepairReceipt, RepairError> {
    execute_with_post_install_validator(
        root,
        backup_dir,
        expected_precondition,
        evidence_ids,
        approval_id,
        |_, _| Ok(()),
    )
}

fn execute_with_post_install_validator<F>(
    root: &Path,
    backup_dir: &Path,
    expected_precondition: &str,
    evidence_ids: &[String],
    approval_id: &str,
    post_install_validator: F,
) -> Result<RepairReceipt, RepairError>
where
    F: FnOnce(&[u8], &[u8]) -> Result<(), RepairError>,
{
    if approval_id.trim().is_empty() {
        return Err(RepairError::ApprovalRequired);
    }
    if evidence_ids.is_empty() {
        return Err(RepairError::MissingEvidence);
    }
    let fixture = canonical_fixture(root)?;
    let (canonical_backup, backup_fd) = open_directory(backup_dir)?;
    if canonical_backup.starts_with(&fixture.canonical_path) {
        return Err(RepairError::BackupInsideTarget);
    }
    let observed = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if snapshot_precondition(&observed) != expected_precondition {
        return Err(RepairError::StaleTarget);
    }
    let _lock = FixtureLock::acquire(&fixture.etc)?;
    let before = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if before.state != observed.state
        || before.bytes != observed.bytes
        || snapshot_precondition(&before) != expected_precondition
    {
        return Err(RepairError::StaleTarget);
    }
    let after = repaired(&before.bytes)?;
    let before_fingerprint = fingerprint(&before.bytes);
    let digest = before_fingerprint
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(RepairError::StaleTarget)?;
    let backup_name = format!("fstab-{}.bak", &digest[..16]);
    let backup = create_backup(&backup_fd, &canonical_backup, &backup_name, &before)?;

    let current = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if !same_identity(&current.state, &before.state)
        || current.bytes != before.bytes
        || current.state.metadata != before.state.metadata
    {
        return Err(RepairError::StaleTarget);
    }

    let temporary_name = format!(".fstab.kernaid-new-{}", &digest[..16]);
    let (new_state, mut temporary_guard) = create_prepared_file(
        &fixture.etc,
        &temporary_name,
        &after,
        &before.state.metadata,
    )?;
    let final_recheck = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if final_recheck.state != before.state || final_recheck.bytes != before.bytes {
        return Err(RepairError::StaleTarget);
    }

    rfs::renameat_with(
        &fixture.etc,
        temporary_name.as_str(),
        &fixture.etc,
        FSTAB_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(rustix_error)?;

    let post_install = (|| {
        sync_directory(&fixture.etc)?;
        let installed = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
        let displaced = snapshot_named(&fixture.etc, Path::new(&temporary_name))?;
        if !same_identity(&installed.state, &new_state)
            || !same_identity(&displaced.state, &before.state)
            || displaced.bytes != before.bytes
            || installed.state.metadata != before.state.metadata
        {
            return Err(RepairError::StaleTarget);
        }
        validate_installed(&installed.bytes, &after)?;
        post_install_validator(&before.bytes, &installed.bytes)?;
        Ok(installed)
    })();

    let installed = match post_install {
        Ok(installed) => installed,
        Err(cause) => {
            return Err(post_install_error(
                cause,
                &fixture,
                &temporary_name,
                &new_state,
                &mut temporary_guard,
                &backup,
            ));
        }
    };

    if let Err(cause) = remove_name_if_identity(&fixture.etc, &temporary_name, &before.state) {
        return Err(post_install_error(
            cause,
            &fixture,
            &temporary_name,
            &new_state,
            &mut temporary_guard,
            &backup,
        ));
    }
    temporary_guard.disarm();
    if let Err(cause) = sync_directory(&fixture.etc) {
        return Err(copy_rollback_error(
            cause, &fixture, &before, &installed, &backup,
        ));
    }

    Ok(RepairReceipt {
        before_fingerprint,
        after_fingerprint: fingerprint(&installed.bytes),
        after_target_precondition: snapshot_precondition(&installed),
        backup_path: backup.path,
        backup_fingerprint: backup.fingerprint,
        before_metadata: before.state.metadata,
        validation_passed: true,
        metadata_preserved: true,
    })
}

fn open_verified_backup(
    fixture: &Fixture,
    receipt: &RepairReceipt,
) -> Result<(PathBuf, OwnedFd, Snapshot), RepairError> {
    let backup_metadata = fs::symlink_metadata(&receipt.backup_path)?;
    if !backup_metadata.is_file() || backup_metadata.file_type().is_symlink() {
        return Err(RepairError::UnsafePath);
    }
    let backup_parent = receipt
        .backup_path
        .parent()
        .ok_or(RepairError::UnsafePath)?;
    let (canonical_parent, parent_fd) = open_directory(backup_parent)?;
    if canonical_parent.starts_with(&fixture.canonical_path) {
        return Err(RepairError::BackupInsideTarget);
    }
    let name = receipt
        .backup_path
        .file_name()
        .ok_or(RepairError::UnsafePath)?;
    let backup = snapshot_named(&parent_fd, Path::new(name))?;
    if fingerprint(&backup.bytes) != receipt.backup_fingerprint
        || backup.state.metadata != receipt.before_metadata
    {
        return Err(RepairError::ValidationFailed);
    }
    parse_fstab(&backup.bytes)?;
    Ok((canonical_parent, parent_fd, backup))
}

pub fn rollback_missing_fstab_device_repair(
    root: &Path,
    repair: &RepairReceipt,
    approval_id: &str,
) -> Result<RollbackReceipt, RepairError> {
    if approval_id.trim().is_empty() {
        return Err(RepairError::ApprovalRequired);
    }
    let fixture = canonical_fixture(root)?;
    let observed = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if fingerprint(&observed.bytes) != repair.after_fingerprint
        || snapshot_precondition(&observed) != repair.after_target_precondition
        || observed.state.metadata != repair.before_metadata
    {
        return Err(RepairError::StaleTarget);
    }
    let _lock = FixtureLock::acquire(&fixture.etc)?;
    let current = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if current.state != observed.state
        || current.bytes != observed.bytes
        || fingerprint(&current.bytes) != repair.after_fingerprint
        || snapshot_precondition(&current) != repair.after_target_precondition
        || current.state.metadata != repair.before_metadata
    {
        return Err(RepairError::StaleTarget);
    }
    let (_backup_parent, _backup_fd, backup) = open_verified_backup(&fixture, repair)?;
    let digest = repair
        .before_fingerprint
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(RepairError::ValidationFailed)?;
    let temporary_name = format!(".fstab.kernaid-rollback-{}", &digest[..16]);
    let (restored_state, mut guard) = create_prepared_file(
        &fixture.etc,
        &temporary_name,
        &backup.bytes,
        &repair.before_metadata,
    )?;
    let final_recheck = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
    if final_recheck.state != current.state || final_recheck.bytes != current.bytes {
        return Err(RepairError::StaleTarget);
    }
    rfs::renameat_with(
        &fixture.etc,
        temporary_name.as_str(),
        &fixture.etc,
        FSTAB_NAME,
        RenameFlags::EXCHANGE,
    )
    .map_err(rustix_error)?;

    let validation = (|| {
        sync_directory(&fixture.etc)?;
        let restored = snapshot_named(&fixture.etc, Path::new(FSTAB_NAME))?;
        let displaced = snapshot_named(&fixture.etc, Path::new(&temporary_name))?;
        if !same_identity(&restored.state, &restored_state)
            || !same_identity(&displaced.state, &current.state)
            || restored.bytes != backup.bytes
            || restored.state.metadata != repair.before_metadata
        {
            return Err(RepairError::ValidationFailed);
        }
        parse_fstab(&restored.bytes)?;
        Ok(restored)
    })();

    let restored = match validation {
        Ok(restored) => restored,
        Err(cause) => {
            let backup_handle = BackupHandle {
                path: repair.backup_path.clone(),
                fingerprint: repair.backup_fingerprint.clone(),
            };
            return Err(post_install_error(
                cause,
                &fixture,
                &temporary_name,
                &restored_state,
                &mut guard,
                &backup_handle,
            ));
        }
    };
    if let Err(cause) = remove_name_if_identity(&fixture.etc, &temporary_name, &current.state) {
        let backup_handle = BackupHandle {
            path: repair.backup_path.clone(),
            fingerprint: repair.backup_fingerprint.clone(),
        };
        return Err(post_install_error(
            cause,
            &fixture,
            &temporary_name,
            &restored_state,
            &mut guard,
            &backup_handle,
        ));
    }
    guard.disarm();
    if let Err(cause) = sync_directory(&fixture.etc) {
        let backup_handle = BackupHandle {
            path: repair.backup_path.clone(),
            fingerprint: repair.backup_fingerprint.clone(),
        };
        return Err(copy_rollback_error(
            cause,
            &fixture,
            &current,
            &restored,
            &backup_handle,
        ));
    }
    Ok(RollbackReceipt {
        replaced_fingerprint: fingerprint(&current.bytes),
        restored_fingerprint: fingerprint(&restored.bytes),
        backup_path: repair.backup_path.clone(),
        backup_fingerprint: repair.backup_fingerprint.clone(),
        automatic: false,
        validation_passed: true,
        metadata_preserved: restored.state.metadata == repair.before_metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn broken_fstab() -> Vec<u8> {
        b"# test\nUUID=missing-data /mnt/data ext4 defaults 0 2\n".to_vec()
    }

    fn directory_names(path: &Path) -> Vec<String> {
        let mut names = fs::read_dir(path)
            .expect("read directory")
            .map(|entry| {
                entry
                    .expect("read directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    struct TestTree {
        root: PathBuf,
    }

    impl TestTree {
        fn new(name: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "kernaid-{name}-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("target/etc")).expect("create target fixture");
            fs::create_dir_all(root.join("backup")).expect("create backup fixture");
            fs::write(
                root.join("target/.kernaid-disposable-fixture"),
                FIXTURE_MARKER,
            )
            .expect("write fixture marker");
            fs::write(root.join("target/etc/fstab"), broken_fstab()).expect("write fstab fixture");
            Self { root }
        }

        fn target(&self) -> PathBuf {
            self.root.join("target")
        }

        fn backup(&self) -> PathBuf {
            self.root.join("backup")
        }

        fn fstab(&self) -> PathBuf {
            self.target().join("etc/fstab")
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn parser_handles_escaped_fields_and_preserves_unrelated_bytes() {
        let before = b"# header\nLABEL=hello\\040world /srv ext4 defaults 0 2\n\tUUID=missing-data\t/mnt/data ext4 defaults 0 2\n";
        let after = repaired(before).expect("repair parsed fstab");
        assert!(after.starts_with(b"# header\nLABEL=hello\\040world /srv ext4 defaults 0 2\n"));
        assert!(after.ends_with(
            b"# KernAid disabled missing device: \tUUID=missing-data\t/mnt/data ext4 defaults 0 2\n"
        ));
        parse_fstab(&after).expect("parse repaired fstab");
    }

    #[test]
    fn malformed_fstab_is_rejected_before_preview() {
        let tree = TestTree::new("fstab-malformed");
        fs::write(
            tree.fstab(),
            b"UUID=ok / ext4 defaults 0 not-a-number\nUUID=missing-data /mnt/data ext4 defaults 0 2\n",
        )
        .expect("write malformed fstab");
        assert_eq!(
            preview_missing_fstab_device(&tree.target(), &["E-1".to_owned()]),
            Err(RepairError::ValidationFailed)
        );
        assert_eq!(
            repaired(
                b"LABEL=bad\\777 /srv ext4 defaults 0 2\nUUID=missing-data /mnt/data ext4 defaults 0 2\n"
            ),
            Err(RepairError::ValidationFailed)
        );
    }

    #[test]
    fn repair_is_backed_up_validated_and_rollbackable() {
        let tree = TestTree::new("fstab-transaction");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute fixture repair");
        assert!(receipt.validation_passed);
        assert!(receipt.metadata_preserved);
        assert_ne!(receipt.before_fingerprint, receipt.after_fingerprint);
        let rollback = rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback")
            .expect("rollback fixture repair");
        assert_eq!(
            rollback.restored_fingerprint,
            preview.target_content_fingerprint
        );
        assert!(!rollback.automatic);
        assert_eq!(
            fs::read(tree.fstab()).expect("read restored fstab"),
            broken_fstab()
        );
    }

    #[test]
    fn injected_post_install_failure_rolls_back_automatically() {
        let tree = TestTree::new("fstab-auto-rollback");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let result = execute_with_post_install_validator(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
            |_, _| Err(RepairError::ValidationFailed),
        );
        assert!(matches!(
            result,
            Err(RepairError::PostInstallRolledBack { .. })
        ));
        let Err(RepairError::PostInstallRolledBack { cause, rollback }) = result else {
            return;
        };
        assert_eq!(*cause, RepairError::ValidationFailed);
        assert!(rollback.automatic);
        assert!(rollback.validation_passed);
        assert_eq!(
            rollback.restored_fingerprint,
            preview.target_content_fingerprint
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read restored fstab"),
            broken_fstab()
        );
        assert!(
            fs::read_dir(tree.target().join("etc"))
                .expect("read etc")
                .all(|entry| !entry
                    .expect("read entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".fstab.kernaid-"))
        );
    }

    #[test]
    fn stale_fingerprint_is_rejected_before_backup_or_write() {
        let tree = TestTree::new("fstab-stale");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let externally_changed =
            b"# changed after preview\nUUID=missing-data /mnt/data ext4 defaults 0 2\n";
        fs::write(tree.fstab(), externally_changed).expect("make preview stale");
        let result = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        );
        assert_eq!(result, Err(RepairError::StaleTarget));
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fstab"),
            externally_changed
        );
        assert_eq!(
            fs::read_dir(tree.backup())
                .expect("read backup directory")
                .count(),
            0
        );
        assert!(!tree.target().join("etc").join(LOCK_NAME).exists());
    }

    #[test]
    fn metadata_change_since_preview_is_rejected_without_mutation() {
        let tree = TestTree::new("fstab-stale-metadata");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let before = fs::read(tree.fstab()).expect("read fstab before metadata edit");
        fs::set_permissions(tree.fstab(), fs::Permissions::from_mode(0o600))
            .expect("change target mode after preview");

        assert_eq!(
            execute_missing_fstab_device_repair(
                &tree.target(),
                &tree.backup(),
                &preview.target_fingerprint,
                &evidence,
                "A-local",
            ),
            Err(RepairError::StaleTarget)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fstab"),
            before
        );
        assert_eq!(
            fs::metadata(tree.fstab())
                .expect("read externally changed mode")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(directory_names(&tree.backup()).is_empty());
        assert_eq!(
            directory_names(&tree.target().join("etc")),
            vec![FSTAB_NAME]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn extended_metadata_is_rejected_without_mutation() {
        let tree = TestTree::new("fstab-unsupported-metadata");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let before = fs::read(tree.fstab()).expect("read fstab before xattr edit");
        rfs::setxattr(
            tree.fstab(),
            "user.kernaid-test",
            b"preserve-me",
            rfs::XattrFlags::CREATE,
        )
        .expect("set unsupported target xattr");

        assert_eq!(
            execute_missing_fstab_device_repair(
                &tree.target(),
                &tree.backup(),
                &preview.target_fingerprint,
                &evidence,
                "A-local",
            ),
            Err(RepairError::UnsupportedMetadata)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fstab"),
            before
        );
        let mut value = [0_u8; 32];
        let length = rfs::getxattr(tree.fstab(), "user.kernaid-test", &mut value)
            .expect("read retained target xattr");
        assert_eq!(&value[..length], b"preserve-me");
        assert!(directory_names(&tree.backup()).is_empty());
        assert_eq!(
            directory_names(&tree.target().join("etc")),
            vec![FSTAB_NAME]
        );
    }

    #[test]
    fn symlink_target_is_rejected_without_touching_referent() {
        let tree = TestTree::new("fstab-symlink");
        let outside = tree.root.join("outside-fstab");
        fs::write(&outside, broken_fstab()).expect("write outside fstab");
        fs::remove_file(tree.fstab()).expect("remove target fstab");
        symlink(&outside, tree.fstab()).expect("create fstab symlink");
        assert_eq!(
            preview_missing_fstab_device(&tree.target(), &["E-1".to_owned()]),
            Err(RepairError::UnsafePath)
        );
        assert_eq!(fs::read(outside).expect("read referent"), broken_fstab());
    }

    #[test]
    fn target_lock_blocks_other_backup_directory_and_allows_retry() {
        let tree = TestTree::new("fstab-lock");
        let other_backup = tree.root.join("backup-other");
        fs::create_dir(&other_backup).expect("create second backup directory");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let fixture = canonical_fixture(&tree.target()).expect("open fixture");
        let held = FixtureLock::acquire(&fixture.etc).expect("hold target lock");
        assert_eq!(
            execute_missing_fstab_device_repair(
                &tree.target(),
                &other_backup,
                &preview.target_fingerprint,
                &evidence,
                "A-local",
            ),
            Err(RepairError::ResourceLocked)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fstab"),
            broken_fstab()
        );
        assert_eq!(
            fs::read_dir(&other_backup)
                .expect("read second backup directory")
                .count(),
            0
        );
        drop(held);
        drop(fixture);

        let lock_path = tree.target().join("etc").join(LOCK_NAME);
        let lock_metadata = fs::symlink_metadata(&lock_path).expect("read persistent lock");
        assert!(lock_metadata.is_file());
        assert!(!lock_metadata.file_type().is_symlink());
        assert_eq!(lock_metadata.permissions().mode() & 0o7777, 0o600);
        execute_missing_fstab_device_repair(
            &tree.target(),
            &other_backup,
            &preview.target_fingerprint,
            &evidence,
            "A-retry",
        )
        .expect("retry after lock release");
        assert!(lock_path.is_file());
    }

    #[test]
    fn symlink_lock_file_is_rejected_without_mutation() {
        let tree = TestTree::new("fstab-lock-symlink");
        let outside = tree.root.join("outside-lock");
        fs::write(&outside, b"do not touch").expect("write outside lock");
        symlink(&outside, tree.target().join("etc").join(LOCK_NAME)).expect("create lock symlink");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        assert_eq!(
            execute_missing_fstab_device_repair(
                &tree.target(),
                &tree.backup(),
                &preview.target_fingerprint,
                &evidence,
                "A-local",
            ),
            Err(RepairError::UnsafePath)
        );
        assert_eq!(
            fs::read(&outside).expect("read lock referent"),
            b"do not touch"
        );
        assert_eq!(fs::read(tree.fstab()).expect("read fstab"), broken_fstab());
        assert_eq!(
            fs::read_dir(tree.backup())
                .expect("read backup directory")
                .count(),
            0
        );
    }

    #[test]
    fn tampered_backup_is_rejected_without_rollback_mutation() {
        let tree = TestTree::new("fstab-backup-tamper");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let installed = fs::read(tree.fstab()).expect("read installed fstab");
        fs::write(&receipt.backup_path, b"tampered\n").expect("tamper backup");
        assert_eq!(
            rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback"),
            Err(RepairError::ValidationFailed)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read installed fstab"),
            installed
        );
    }

    #[test]
    fn post_repair_byte_edit_is_rejected_before_explicit_rollback_mutation() {
        let tree = TestTree::new("fstab-rollback-stale-bytes");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let backup_before = fs::read(&receipt.backup_path).expect("read backup before rollback");
        let names_before = directory_names(&tree.target().join("etc"));
        let externally_changed = b"# changed after repair\nUUID=other / ext4 defaults 0 1\n";
        fs::write(tree.fstab(), externally_changed).expect("edit repaired target externally");

        assert_eq!(
            rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback"),
            Err(RepairError::StaleTarget)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read retained external edit"),
            externally_changed
        );
        assert_eq!(
            fs::read(&receipt.backup_path).expect("read unchanged backup"),
            backup_before
        );
        assert_eq!(directory_names(&tree.target().join("etc")), names_before);
    }

    #[test]
    fn post_repair_same_content_replacement_is_rejected_without_mutation() {
        let tree = TestTree::new("fstab-rollback-replaced-target");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let installed = fs::read(tree.fstab()).expect("read installed target");
        let installed_metadata = fs::metadata(tree.fstab()).expect("read installed metadata");
        let installed_inode = installed_metadata.ino();
        let replacement = tree.target().join("etc/fstab.external-replacement");
        fs::write(&replacement, &installed).expect("write same-content replacement");
        fs::set_permissions(
            &replacement,
            fs::Permissions::from_mode(installed_metadata.mode() & 0o7777),
        )
        .expect("copy installed mode to replacement");
        fs::rename(&replacement, tree.fstab()).expect("replace installed target externally");
        let replacement_inode = fs::metadata(tree.fstab())
            .expect("read replacement metadata")
            .ino();
        assert_ne!(replacement_inode, installed_inode);
        let names_before = directory_names(&tree.target().join("etc"));

        assert_eq!(
            rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback"),
            Err(RepairError::StaleTarget)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read retained replacement"),
            installed
        );
        assert_eq!(
            fs::metadata(tree.fstab())
                .expect("read retained replacement identity")
                .ino(),
            replacement_inode
        );
        assert_eq!(directory_names(&tree.target().join("etc")), names_before);
    }

    #[test]
    fn post_repair_metadata_edit_is_rejected_before_explicit_rollback_mutation() {
        let tree = TestTree::new("fstab-rollback-stale-metadata");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let installed = fs::read(tree.fstab()).expect("read installed target");
        let names_before = directory_names(&tree.target().join("etc"));
        fs::set_permissions(tree.fstab(), fs::Permissions::from_mode(0o600))
            .expect("change installed target mode externally");

        assert_eq!(
            rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback"),
            Err(RepairError::StaleTarget)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read installed target"),
            installed
        );
        assert_eq!(
            fs::metadata(tree.fstab())
                .expect("read retained external mode")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(directory_names(&tree.target().join("etc")), names_before);
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[test]
    fn post_repair_xattr_is_rejected_before_explicit_rollback_mutation() {
        let tree = TestTree::new("fstab-rollback-unsupported-metadata");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let installed = fs::read(tree.fstab()).expect("read installed target");
        let names_before = directory_names(&tree.target().join("etc"));
        rfs::setxattr(
            tree.fstab(),
            "user.kernaid-test",
            b"preserve-me",
            rfs::XattrFlags::CREATE,
        )
        .expect("set installed target xattr externally");

        assert_eq!(
            rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback"),
            Err(RepairError::UnsupportedMetadata)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read installed target"),
            installed
        );
        let mut value = [0_u8; 32];
        let length = rfs::getxattr(tree.fstab(), "user.kernaid-test", &mut value)
            .expect("read retained installed xattr");
        assert_eq!(&value[..length], b"preserve-me");
        assert_eq!(directory_names(&tree.target().join("etc")), names_before);
    }

    #[test]
    fn mode_uid_and_gid_survive_repair_and_rollback() {
        let tree = TestTree::new("fstab-metadata");
        fs::set_permissions(tree.fstab(), fs::Permissions::from_mode(0o640))
            .expect("set fixture mode");
        let original = fs::metadata(tree.fstab()).expect("read original metadata");
        let expected = (original.mode() & 0o7777, original.uid(), original.gid());
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute repair");
        let installed = fs::metadata(tree.fstab()).expect("read installed metadata");
        assert_eq!(
            (installed.mode() & 0o7777, installed.uid(), installed.gid()),
            expected
        );
        rollback_missing_fstab_device_repair(&tree.target(), &receipt, "A-rollback")
            .expect("rollback repair");
        let restored = fs::metadata(tree.fstab()).expect("read restored metadata");
        assert_eq!(
            (restored.mode() & 0o7777, restored.uid(), restored.gid()),
            expected
        );
    }

    #[test]
    fn backup_inside_target_is_rejected() {
        let tree = TestTree::new("fstab-backup-inside");
        let inside = tree.target().join("backups");
        fs::create_dir(&inside).expect("create inside backup directory");
        let evidence = vec!["E-1".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        assert_eq!(
            execute_missing_fstab_device_repair(
                &tree.target(),
                &inside,
                &preview.target_fingerprint,
                &evidence,
                "A-local",
            ),
            Err(RepairError::BackupInsideTarget)
        );
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fstab"),
            broken_fstab()
        );
    }

    #[test]
    fn unmarked_target_is_never_mutated() {
        let tree = TestTree::new("fstab-unmarked");
        fs::remove_file(tree.target().join(".kernaid-disposable-fixture")).expect("remove marker");
        let result = preview_missing_fstab_device(&tree.target(), &["E-1".to_owned()]);
        assert!(matches!(result, Err(RepairError::UnsafePath)));
    }
}
