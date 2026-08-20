//! Fixed-path, descriptor-relative Linux installed-root snapshot collector.
//!
//! Production collection always opens `/` internally. Arbitrary roots exist
//! only inside unit tests; the feature-gated repository fixture entrypoint is
//! closed over the named golden corpus.

use kernaid_evidence::linux_snapshot::{
    COLLECTION_SCOPE, LinuxBoot, LinuxConfiguration, LinuxFilesystemTopology, LinuxFstabSummary,
    LinuxNormalizedSnapshot, LinuxNormalizedSnapshotEnvelope, LinuxPackageDatabases, LinuxRelease,
    LinuxSnapshotCapture, SNAPSHOT_SCOPE,
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, CWD, Dir, FileType, Mode, OFlags},
};
use std::{error::Error, fmt, fs::File, io::Read, path::Path};

const MAX_TEXT_FILE_BYTES: usize = 64 * 1024;
const MAX_OS_RELEASE_BYTES: usize = 16 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_RELEASE_VALUE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionError {
    UnsafeRoot,
    UnsafeContent,
    InputTooLarge,
    InvalidUtf8,
    InvalidMetadata,
    Io,
    InvalidSnapshot,
}

impl fmt::Display for CollectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeRoot => "Linux snapshot root is unsafe",
            Self::UnsafeContent => "Linux snapshot encountered unsafe content",
            Self::InputTooLarge => "Linux snapshot input exceeds its limit",
            Self::InvalidUtf8 => "Linux snapshot input is not valid UTF-8",
            Self::InvalidMetadata => "Linux snapshot metadata is invalid",
            Self::Io => "Linux snapshot could not be collected",
            Self::InvalidSnapshot => "Linux snapshot normalization failed",
        })
    }
}

impl Error for CollectionError {}

pub fn collect_current_root_snapshot() -> Result<LinuxNormalizedSnapshotEnvelope, CollectionError> {
    let root = open_root(Path::new("/"))?;
    let snapshot = collect_from_fd(root.as_fd())?;
    LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::resident(), snapshot)
        .map_err(|_| CollectionError::InvalidSnapshot)
}

#[cfg(test)]
fn collect_fixture_root_snapshot(
    root: &Path,
) -> Result<LinuxNormalizedSnapshotEnvelope, CollectionError> {
    if !root.is_absolute() {
        return Err(CollectionError::UnsafeRoot);
    }
    let root = open_root(root)?;
    let snapshot = collect_from_fd(root.as_fd())?;
    LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::resident(), snapshot)
        .map_err(|_| CollectionError::InvalidSnapshot)
}

#[cfg(feature = "fixture-snapshot-cli")]
pub fn collect_repository_fixture_snapshot(
    fixture: &str,
) -> Result<LinuxNormalizedSnapshotEnvelope, CollectionError> {
    let fixture_path = match fixture {
        "healthy" => "../../tests/fixtures/linux-normalized-snapshot/healthy/root",
        "multi-fs" => "../../tests/fixtures/linux-normalized-snapshot/multi-fs/root",
        _ => return Err(CollectionError::UnsafeRoot),
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture_path);
    let root = open_root(&root)?;
    let snapshot = collect_from_fd(root.as_fd())?;
    LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::resident(), snapshot)
        .map_err(|_| CollectionError::InvalidSnapshot)
}

fn open_root(path: &Path) -> Result<OwnedFd, CollectionError> {
    rfs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| CollectionError::UnsafeRoot)
}

fn open_directory_chain(
    root: BorrowedFd<'_>,
    components: &[&str],
) -> Result<Option<OwnedFd>, CollectionError> {
    let root_device = rfs::fstat(root)
        .map_err(|_| CollectionError::UnsafeRoot)?
        .st_dev;
    let mut current = rfs::openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| CollectionError::UnsafeRoot)?;
    for component in components {
        match rfs::openat(
            &current,
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(next) => {
                if rfs::fstat(&next).map_err(|_| CollectionError::Io)?.st_dev != root_device {
                    return Err(CollectionError::UnsafeContent);
                }
                current = next;
            }
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(CollectionError::UnsafeContent),
        }
    }
    Ok(Some(current))
}

fn read_regular(
    root: BorrowedFd<'_>,
    directory_components: &[&str],
    name: &str,
    maximum: usize,
    symlink_is_absent: bool,
) -> Result<Option<Vec<u8>>, CollectionError> {
    let Some(directory) = open_directory_chain(root, directory_components)? else {
        return Ok(None);
    };
    let descriptor = match rfs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) if symlink_is_absent => return Ok(None),
        Err(_) => return Err(CollectionError::UnsafeContent),
    };
    let before = rfs::fstat(&descriptor).map_err(|_| CollectionError::Io)?;
    let root_device = rfs::fstat(root)
        .map_err(|_| CollectionError::UnsafeRoot)?
        .st_dev;
    if before.st_dev != root_device
        || !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_size < 0
    {
        return Err(CollectionError::UnsafeContent);
    }
    let length = usize::try_from(before.st_size).map_err(|_| CollectionError::InputTooLarge)?;
    if length > maximum {
        return Err(CollectionError::InputTooLarge);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(length);
    file.by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CollectionError::Io)?;
    if bytes.len() > maximum {
        return Err(CollectionError::InputTooLarge);
    }
    let after = rfs::fstat(&file).map_err(|_| CollectionError::Io)?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) || bytes.len() != length
    {
        return Err(CollectionError::UnsafeContent);
    }
    Ok(Some(bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeKind {
    Absent,
    Regular,
    Directory,
}

fn safe_kind(
    root: BorrowedFd<'_>,
    directory_components: &[&str],
    name: &str,
) -> Result<SafeKind, CollectionError> {
    let Some(directory) = open_directory_chain(root, directory_components)? else {
        return Ok(SafeKind::Absent);
    };
    let stat = match rfs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(SafeKind::Absent),
        Err(_) => return Err(CollectionError::UnsafeContent),
    };
    let kind = FileType::from_raw_mode(stat.st_mode);
    if stat.st_dev
        != rfs::fstat(root)
            .map_err(|_| CollectionError::UnsafeRoot)?
            .st_dev
    {
        return Err(CollectionError::UnsafeContent);
    }
    if kind.is_file() {
        Ok(SafeKind::Regular)
    } else if kind.is_dir() {
        Ok(SafeKind::Directory)
    } else {
        Err(CollectionError::UnsafeContent)
    }
}

fn collect_from_fd(root: BorrowedFd<'_>) -> Result<LinuxNormalizedSnapshot, CollectionError> {
    let fstab_payload = read_regular(root, &["etc"], "fstab", MAX_TEXT_FILE_BYTES, false)?;
    let (fstab, topology) = summarize_fstab(fstab_payload.as_deref())?;
    let release_payload = if topology.separate_etc_mount_present {
        None
    } else {
        read_regular(root, &["etc"], "os-release", MAX_OS_RELEASE_BYTES, true)?
    };
    let (release_payload, release_source) = match release_payload {
        Some(payload) => (Some(payload), "etc-os-release"),
        None if !topology.separate_etc_mount_present && !topology.separate_usr_mount_present => {
            match read_regular(
                root,
                &["usr", "lib"],
                "os-release",
                MAX_OS_RELEASE_BYTES,
                false,
            )? {
                Some(payload) => (Some(payload), "usr-lib-os-release"),
                None => (None, "absent"),
            }
        }
        None => (None, "absent"),
    };
    let release = parse_os_release(release_payload.as_deref(), release_source)?;
    let boot = if topology.separate_boot_mount_present {
        absent_boot()
    } else {
        boot_summary(root)?
    };
    let machine_id_present = !topology.separate_etc_mount_present
        && safe_kind(root, &["etc"], "machine-id")? == SafeKind::Regular;
    let package_databases = if topology.separate_var_mount_present {
        LinuxPackageDatabases {
            dpkg_status_present: false,
            rpm_database_present: false,
            pacman_database_present: false,
        }
    } else {
        LinuxPackageDatabases {
            dpkg_status_present: safe_kind(root, &["var", "lib", "dpkg"], "status")?
                == SafeKind::Regular,
            rpm_database_present: safe_kind(root, &["var", "lib"], "rpm")? == SafeKind::Directory,
            pacman_database_present: safe_kind(root, &["var", "lib", "pacman"], "local")?
                == SafeKind::Directory,
        }
    };
    let etc_present =
        !topology.separate_etc_mount_present && open_directory_chain(root, &["etc"])?.is_some();
    let usr_present =
        !topology.separate_usr_mount_present && open_directory_chain(root, &["usr"])?.is_some();
    let installation_confirmed = release.id.is_some() && etc_present && usr_present;
    let snapshot = LinuxNormalizedSnapshot {
        family: "linux".to_owned(),
        scope: SNAPSHOT_SCOPE.to_owned(),
        installation_confirmed,
        topology,
        release,
        boot,
        configuration: LinuxConfiguration {
            fstab,
            machine_id_present,
        },
        package_databases,
    };
    snapshot
        .validate()
        .map_err(|_| CollectionError::InvalidSnapshot)?;
    Ok(snapshot)
}

fn parse_os_release(payload: Option<&[u8]>, source: &str) -> Result<LinuxRelease, CollectionError> {
    let mut id = None;
    let mut name = None;
    let mut pretty_name = None;
    let mut version_id = None;
    let Some(payload) = payload else {
        return Ok(LinuxRelease {
            id,
            name,
            pretty_name,
            version_id,
            source: source.to_owned(),
        });
    };
    if payload
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && payload.get(index + 1) != Some(&b'\n'))
    {
        return Err(CollectionError::InvalidMetadata);
    }
    let text = std::str::from_utf8(payload).map_err(|_| CollectionError::InvalidUtf8)?;
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or(CollectionError::InvalidMetadata)?;
        if !valid_release_key(key) || !seen.insert(key) {
            return Err(CollectionError::InvalidMetadata);
        }
        let value = unquote_release_value(raw_value)?;
        match key {
            "ID" => id = Some(value),
            "NAME" => name = Some(value),
            "PRETTY_NAME" => pretty_name = Some(value),
            "VERSION_ID" => version_id = Some(value),
            _ => {}
        }
    }
    Ok(LinuxRelease {
        id,
        name,
        pretty_name,
        version_id,
        source: source.to_owned(),
    })
}

fn valid_release_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn unquote_release_value(raw: &str) -> Result<String, CollectionError> {
    let value = if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        let quote = raw.as_bytes()[0];
        let body = &raw.as_bytes()[1..raw.len() - 1];
        let mut decoded = Vec::with_capacity(body.len());
        let mut cursor = 0;
        while cursor < body.len() {
            let mut byte = body[cursor];
            if byte == b'\\' {
                cursor += 1;
                if cursor >= body.len()
                    || !matches!(body[cursor], b'\\' | b'$' | b'`') && body[cursor] != quote
                {
                    return Err(CollectionError::InvalidMetadata);
                }
                byte = body[cursor];
            }
            decoded.push(byte);
            cursor += 1;
        }
        String::from_utf8(decoded).map_err(|_| CollectionError::InvalidUtf8)?
    } else {
        if raw.chars().any(char::is_whitespace) {
            return Err(CollectionError::InvalidMetadata);
        }
        raw.to_owned()
    };
    if value.is_empty()
        || value.len() > MAX_RELEASE_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CollectionError::InvalidMetadata);
    }
    Ok(value)
}

fn summarize_fstab(
    payload: Option<&[u8]>,
) -> Result<(LinuxFstabSummary, LinuxFilesystemTopology), CollectionError> {
    let mut summary = LinuxFstabSummary {
        present: payload.is_some(),
        entry_count: 0,
        root_entry_present: false,
        efi_entry_present: false,
        swap_entry_count: 0,
        network_entry_count: 0,
        malformed_line_count: 0,
    };
    let mut topology = LinuxFilesystemTopology {
        collection_scope: COLLECTION_SCOPE.to_owned(),
        separate_etc_mount_present: false,
        separate_boot_mount_present: false,
        separate_usr_mount_present: false,
        separate_var_mount_present: false,
        relevant_separate_mount_present: false,
        supported: true,
    };
    let Some(payload) = payload else {
        return Ok((summary, topology));
    };
    let text = std::str::from_utf8(payload).map_err(|_| CollectionError::InvalidUtf8)?;
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t' | '\r'))
    {
        return Err(CollectionError::InvalidMetadata);
    }
    for line in text.lines() {
        let trimmed = line.trim_start_matches(|character: char| character.is_ascii_whitespace());
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed = parse_fstab_line(trimmed);
        let Ok(fields) = parsed else {
            summary.malformed_line_count = summary.malformed_line_count.saturating_add(1);
            continue;
        };
        if !canonical_fstab_target(&fields[1]) {
            return Err(CollectionError::InvalidMetadata);
        }
        summary.entry_count = summary.entry_count.saturating_add(1);
        if fields[1] == "/" {
            summary.root_entry_present = true;
        }
        if matches!(fields[1].as_str(), "/boot/efi" | "/efi") {
            summary.efi_entry_present = true;
        }
        topology.separate_etc_mount_present =
            topology.separate_etc_mount_present || mount_target_is_within(&fields[1], "/etc");
        topology.separate_boot_mount_present = topology.separate_boot_mount_present
            || mount_target_is_within(&fields[1], "/boot")
            || mount_target_is_within(&fields[1], "/efi");
        topology.separate_usr_mount_present =
            topology.separate_usr_mount_present || mount_target_is_within(&fields[1], "/usr");
        topology.separate_var_mount_present =
            topology.separate_var_mount_present || mount_target_is_within(&fields[1], "/var");
        if fields[2] == "swap"
            || (fields[1] == "none" && fields[3].split(',').any(|option| option == "sw"))
        {
            summary.swap_entry_count = summary.swap_entry_count.saturating_add(1);
        }
        if matches!(fields[2].as_str(), "cifs" | "nfs" | "nfs4" | "sshfs") {
            summary.network_entry_count = summary.network_entry_count.saturating_add(1);
        }
    }
    topology.relevant_separate_mount_present = topology.separate_etc_mount_present
        || topology.separate_boot_mount_present
        || topology.separate_usr_mount_present
        || topology.separate_var_mount_present;
    topology.supported = !topology.relevant_separate_mount_present;
    Ok((summary, topology))
}

fn mount_target_is_within(target: &str, root: &str) -> bool {
    target == root
        || target
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn canonical_fstab_target(target: &str) -> bool {
    target == "none"
        || target == "/"
        || target.strip_prefix('/').is_some_and(|suffix| {
            suffix
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        })
}

fn parse_fstab_line(line: &str) -> Result<Vec<String>, CollectionError> {
    let mut fields = Vec::new();
    for raw in line.split_ascii_whitespace() {
        if raw.starts_with('#') {
            break;
        }
        fields.push(decode_fstab_field(raw.as_bytes())?);
        if fields.len() > 6 {
            return Err(CollectionError::InvalidMetadata);
        }
    }
    if !(4..=6).contains(&fields.len())
        || fields
            .iter()
            .skip(4)
            .any(|value| value.parse::<u32>().is_err())
    {
        return Err(CollectionError::InvalidMetadata);
    }
    Ok(fields)
}

fn decode_fstab_field(field: &[u8]) -> Result<String, CollectionError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut cursor = 0;
    while cursor < field.len() {
        if field[cursor] == b'\\' {
            if cursor + 3 >= field.len()
                || !field[cursor + 1..=cursor + 3]
                    .iter()
                    .all(|digit| matches!(digit, b'0'..=b'7'))
            {
                return Err(CollectionError::InvalidMetadata);
            }
            let value = u16::from(field[cursor + 1] - b'0') * 64
                + u16::from(field[cursor + 2] - b'0') * 8
                + u16::from(field[cursor + 3] - b'0');
            decoded.push(u8::try_from(value).map_err(|_| CollectionError::InvalidMetadata)?);
            cursor += 4;
        } else {
            decoded.push(field[cursor]);
            cursor += 1;
        }
    }
    let value = String::from_utf8(decoded).map_err(|_| CollectionError::InvalidUtf8)?;
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(CollectionError::InvalidMetadata);
    }
    Ok(value)
}

fn boot_summary(root: BorrowedFd<'_>) -> Result<LinuxBoot, CollectionError> {
    let root_device = rfs::fstat(root)
        .map_err(|_| CollectionError::UnsafeRoot)?
        .st_dev;
    let Some(boot) = open_directory_chain(root, &["boot"])? else {
        return Ok(absent_boot());
    };
    let mut directory = Dir::read_from(&boot).map_err(|_| CollectionError::Io)?;
    let mut observed = 0_usize;
    let mut result = LinuxBoot {
        directory_present: true,
        kernel_artifact_count: 0,
        initramfs_artifact_count: 0,
        bootloader_directory_count: 0,
        symlink_artifact_count: 0,
    };
    while let Some(entry) = directory.read() {
        let entry = entry.map_err(|_| CollectionError::Io)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        observed = observed.saturating_add(1);
        if observed > MAX_DIRECTORY_ENTRIES {
            return Err(CollectionError::InputTooLarge);
        }
        let stat = rfs::statat(&boot, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CollectionError::UnsafeContent)?;
        require_same_device(root_device, stat.st_dev)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind.is_symlink() {
            result.symlink_artifact_count = result.symlink_artifact_count.saturating_add(1);
            continue;
        }
        let name = name.to_bytes();
        if kind.is_file() {
            if name.starts_with(b"vmlinuz-") || name.starts_with(b"vmlinux-") {
                result.kernel_artifact_count = result.kernel_artifact_count.saturating_add(1);
            }
            if name.starts_with(b"initrd.img-") || name.starts_with(b"initramfs-") {
                result.initramfs_artifact_count = result.initramfs_artifact_count.saturating_add(1);
            }
        } else if kind.is_dir() && (name == b"efi" || name == b"grub" || name == b"loader") {
            result.bootloader_directory_count = result.bootloader_directory_count.saturating_add(1);
        }
    }
    Ok(result)
}

fn absent_boot() -> LinuxBoot {
    LinuxBoot {
        directory_present: false,
        kernel_artifact_count: 0,
        initramfs_artifact_count: 0,
        bootloader_directory_count: 0,
        symlink_artifact_count: 0,
    }
}

fn require_same_device(root_device: u64, observed_device: u64) -> Result<(), CollectionError> {
    if root_device == observed_device {
        Ok(())
    } else {
        Err(CollectionError::UnsafeContent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn fixture() -> TempDir {
        let directory = tempfile::tempdir().expect("fixture root");
        let root = directory.path();
        for path in ["etc", "usr/lib", "boot/grub", "var/lib/dpkg"] {
            fs::create_dir_all(root.join(path)).expect("fixture directory");
        }
        fs::write(
            root.join("etc/os-release"),
            b"ID=kernaid-fixture\nNAME=KernAid\nPRETTY_NAME=\"KernAid Fixture\"\nVERSION_ID=1\n",
        )
        .expect("os-release");
        fs::write(
            root.join("etc/fstab"),
            b"LABEL=root / ext4 defaults 0 1\nUUID=EFI /boot/efi vfat defaults 0 2\nserver:/export /mnt/team\\040share nfs ro 0 0\n",
        )
        .expect("fstab");
        fs::write(root.join("etc/machine-id"), b"secret-machine-id\n").expect("machine id");
        fs::write(root.join("boot/vmlinuz-test"), b"kernel").expect("kernel");
        fs::write(root.join("boot/initrd.img-test"), b"initramfs").expect("initramfs");
        fs::write(root.join("var/lib/dpkg/status"), b"Package: secret\n").expect("dpkg");
        directory
    }

    #[test]
    fn fixture_snapshot_is_bounded_normalized_and_secret_free() {
        let directory = fixture();
        let envelope = collect_fixture_root_snapshot(directory.path()).expect("snapshot");
        assert!(envelope.capture.is_resident());
        assert!(envelope.snapshot.installation_confirmed);
        assert_eq!(envelope.snapshot.configuration.fstab.entry_count, 3);
        assert!(envelope.snapshot.configuration.fstab.root_entry_present);
        assert!(envelope.snapshot.configuration.fstab.efi_entry_present);
        assert_eq!(envelope.snapshot.configuration.fstab.network_entry_count, 1);
        let encoded =
            String::from_utf8(envelope.canonical_json().expect("canonical")).expect("UTF-8");
        for secret in [
            "secret-machine-id",
            "server:/export",
            "Package: secret",
            "UUID=EFI",
        ] {
            assert!(!encoded.contains(secret));
        }
    }

    #[test]
    fn unsafe_allowed_path_types_fail_closed() {
        let directory = fixture();
        fs::remove_file(directory.path().join("etc/fstab")).expect("remove fstab");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", directory.path().join("etc/fstab"))
            .expect("symlink");
        assert_eq!(
            collect_fixture_root_snapshot(directory.path()),
            Err(CollectionError::UnsafeContent)
        );
    }

    #[test]
    fn malformed_fstab_is_counted_without_copying_the_line() {
        let directory = fixture();
        fs::write(
            directory.path().join("etc/fstab"),
            b"LABEL=root / ext4 defaults 0 1\nPROMPT INJECTION\n",
        )
        .expect("fstab");
        let envelope = collect_fixture_root_snapshot(directory.path()).expect("snapshot");
        assert_eq!(envelope.snapshot.configuration.fstab.entry_count, 1);
        assert_eq!(
            envelope.snapshot.configuration.fstab.malformed_line_count,
            1
        );
        assert!(
            !String::from_utf8(envelope.canonical_json().expect("canonical"))
                .expect("UTF-8")
                .contains("PROMPT")
        );
    }

    #[test]
    fn shared_os_release_line_ending_vectors_match_the_contract() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/linux-normalized-snapshot/os-release-line-endings.v1.json"
        ))
        .expect("line-ending vectors");
        for case in vectors["cases"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("case name");
            let payload = case["payload"].as_str().expect("case payload");
            let accepted = case["accepted"].as_bool().expect("accepted");
            let result = parse_os_release(Some(payload.as_bytes()), "etc-os-release");
            assert_eq!(result.is_ok(), accepted, "case {name}");
            if let Ok(release) = result {
                assert_eq!(release.id.as_deref(), case["id"].as_str(), "case {name}");
            }
        }
    }

    #[test]
    fn shared_fstab_target_vectors_match_the_contract() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/linux-normalized-snapshot/fstab-targets.v1.json"
        ))
        .expect("fstab target vectors");
        for case in vectors["cases"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("case name");
            let target = case["target"].as_str().expect("target");
            let accepted = case["accepted"].as_bool().expect("accepted");
            assert_eq!(canonical_fstab_target(target), accepted, "case {name}");
            if !accepted && !target.is_empty() {
                let payload = format!("LABEL=x {target} ext4 defaults 0 2\n");
                assert_eq!(
                    summarize_fstab(Some(payload.as_bytes())),
                    Err(CollectionError::InvalidMetadata),
                    "case {name}"
                );
            }
        }
    }

    #[test]
    fn boot_entries_from_another_device_fail_closed() {
        assert_eq!(
            require_same_device(1, 2),
            Err(CollectionError::UnsafeContent)
        );
    }
}
