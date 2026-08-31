//! Read-only, device-bound ext4/NTFS filesystem health checks.
//!
//! Callers can select only a normalized target reference. The production
//! runner opens one block device by kernel major/minor identity and gives a
//! fixed descriptor to either `e2fsck -f -n` or `ntfsfix -n`. Tool output is
//! drained under fixed limits and discarded; paths, filenames and user bytes
//! can never enter the normalized document.

use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        process::CommandExt,
    },
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

pub const COLLECTOR: &str = "linux.filesystem.health.v1";
pub const KIND: &str = "linux-filesystem-health";
pub const SCHEMA_VERSION: &str = "1.0";
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024;
const MAX_TOOL_STREAM_BYTES: usize = 64 * 1024;
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const E2FSCK: &str = "/usr/sbin/e2fsck";
const NTFSFIX: &str = "/usr/bin/ntfsfix";
static FIXED_TOOL_SPAWN: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemKind {
    Ext4,
    Ntfs,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemHealthState {
    Healthy,
    Degraded,
    RepairRequired,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCheckMode {
    E2fsckReadOnly,
    NtfsfixNoAction,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Low,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemHealthFinding {
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: FindingSeverity,
    pub summary: String,
    pub next_action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemHealthSnapshot {
    pub schema_version: String,
    pub kind: String,
    pub target_ref: String,
    pub filesystem: FilesystemKind,
    pub state: FilesystemHealthState,
    pub check_mode: FilesystemCheckMode,
    pub mounted_at_check: bool,
    pub finding: Option<FilesystemHealthFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFilesystemHealth;

impl fmt::Display for InvalidFilesystemHealth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid normalized Linux filesystem health")
    }
}

impl Error for InvalidFilesystemHealth {}

impl FilesystemHealthSnapshot {
    pub fn validate(&self) -> bool {
        if self.schema_version != SCHEMA_VERSION
            || self.kind != KIND
            || !valid_target_ref(&self.target_ref)
            || (self.target_ref == "local-root" && !self.mounted_at_check)
            || (self.target_ref != "local-root"
                && self.mounted_at_check
                && self.state != FilesystemHealthState::Unsupported)
            || self.check_mode != check_mode(self.filesystem)
                && self.check_mode != FilesystemCheckMode::Unavailable
            || (self.filesystem == FilesystemKind::Other
                && self.check_mode != FilesystemCheckMode::Unavailable)
            || (self.state == FilesystemHealthState::Unsupported)
                != (self.check_mode == FilesystemCheckMode::Unavailable)
        {
            return false;
        }
        self.finding == finding_for_state(self.state)
    }
}

pub fn parse_bounded_json(
    input: &[u8],
) -> Result<FilesystemHealthSnapshot, InvalidFilesystemHealth> {
    if input.is_empty() || input.len() > MAX_SNAPSHOT_BYTES {
        return Err(InvalidFilesystemHealth);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let snapshot = FilesystemHealthSnapshot::deserialize(&mut deserializer)
        .map_err(|_| InvalidFilesystemHealth)?;
    deserializer.end().map_err(|_| InvalidFilesystemHealth)?;
    if !snapshot.validate()
        || serde_json::to_vec(&snapshot).map_err(|_| InvalidFilesystemHealth)? != input
    {
        return Err(InvalidFilesystemHealth);
    }
    Ok(snapshot)
}

pub fn to_bounded_json(snapshot: &FilesystemHealthSnapshot) -> Result<String, serde_json::Error> {
    if !snapshot.validate() {
        return Err(serde_json::Error::io(io::Error::other(
            "filesystem health violated the normalized contract",
        )));
    }
    let encoded = serde_json::to_string(snapshot)?;
    if encoded.len() > MAX_SNAPSHOT_BYTES {
        return Err(serde_json::Error::io(io::Error::other(
            "filesystem health exceeded the output limit",
        )));
    }
    Ok(encoded)
}

pub fn collect_current_root() -> FilesystemHealthSnapshot {
    let Some((filesystem, major, minor)) = current_root_identity() else {
        return unsupported("local-root", FilesystemKind::Other, true);
    };
    collect_bound("local-root", filesystem, major, minor, true, &SystemRunner)
}

pub fn collect_selected(
    target_ref: &str,
    filesystem: &str,
    major_minor: &str,
) -> Result<FilesystemHealthSnapshot, InvalidFilesystemHealth> {
    if target_ref == "local-root" || !valid_target_ref(target_ref) {
        return Err(InvalidFilesystemHealth);
    }
    let filesystem = parse_filesystem(filesystem).ok_or(InvalidFilesystemHealth)?;
    let (major, minor) = parse_major_minor(major_minor).ok_or(InvalidFilesystemHealth)?;
    Ok(collect_bound(
        target_ref,
        filesystem,
        major,
        minor,
        false,
        &SystemRunner,
    ))
}

fn valid_target_ref(value: &str) -> bool {
    if value == "local-root" {
        return true;
    }
    let Some((disk, volume)) = value.strip_prefix("disk-").and_then(|tail| {
        tail.split_once('/')
            .map_or(Some((tail, None)), |(disk, tail)| {
                tail.strip_prefix("volume-")
                    .map(|volume| (disk, Some(volume)))
            })
    }) else {
        return false;
    };
    valid_index(disk, 32) && volume.is_none_or(|value| valid_index(value, 128))
}

fn valid_index(value: &str, maximum: u16) -> bool {
    !value.is_empty()
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|number| number <= maximum)
}

fn parse_filesystem(value: &str) -> Option<FilesystemKind> {
    match value {
        "ext4" => Some(FilesystemKind::Ext4),
        "ntfs" => Some(FilesystemKind::Ntfs),
        _ => None,
    }
}

fn parse_major_minor(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once(':')?;
    if major.is_empty()
        || minor.is_empty()
        || major.len() > 10
        || minor.len() > 10
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || (major.len() > 1 && major.starts_with('0'))
        || (minor.len() > 1 && minor.starts_with('0'))
    {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn current_root_identity() -> Option<(FilesystemKind, u32, u32)> {
    let metadata = fs::metadata("/").ok()?;
    let device = metadata.dev();
    let major = libc::major(device) as u32;
    let minor = libc::minor(device) as u32;
    let mountinfo = read_mountinfo()?;
    let filesystem = mountinfo.lines().find_map(|line| {
        let (before, after) = line.split_once(" - ")?;
        let fields: Vec<_> = before.split_ascii_whitespace().collect();
        if fields.len() < 5 || fields[2] != format!("{major}:{minor}") || fields[4] != "/" {
            return None;
        }
        parse_filesystem(after.split_ascii_whitespace().next()?)
    })?;
    Some((filesystem, major, minor))
}

fn read_mountinfo() -> Option<String> {
    let file = File::open("/proc/self/mountinfo").ok()?;
    let mut bytes = Vec::with_capacity(4096);
    file.take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_MOUNTINFO_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn mounted(major: u32, minor: u32) -> Option<bool> {
    let needle = format!("{major}:{minor}");
    Some(read_mountinfo()?.lines().any(|line| {
        line.split_once(" - ")
            .map(|(before, _)| before.split_ascii_whitespace().nth(2) == Some(needle.as_str()))
            .unwrap_or(false)
    }))
}

fn collect_bound(
    target_ref: &str,
    filesystem: FilesystemKind,
    major: u32,
    minor: u32,
    allow_mounted: bool,
    runner: &impl CheckRunner,
) -> FilesystemHealthSnapshot {
    let is_mounted = match mounted(major, minor) {
        Some(value) => value,
        None => return unsupported(target_ref, filesystem, allow_mounted),
    };
    if is_mounted != allow_mounted {
        return unsupported(target_ref, filesystem, is_mounted);
    }
    let Some(device) = open_bound_device(major, minor) else {
        return unsupported(target_ref, filesystem, is_mounted);
    };
    let result = runner.run(filesystem, &device);
    let identity_unchanged =
        bound_device_matches(&device, major, minor) && mounted(major, minor) == Some(is_mounted);
    if !identity_unchanged {
        return unsupported(target_ref, filesystem, is_mounted);
    }
    snapshot(
        target_ref,
        filesystem,
        classify(filesystem, result, is_mounted),
        is_mounted,
    )
}

fn open_bound_device(major: u32, minor: u32) -> Option<File> {
    let mut matches = Vec::new();
    let entries = fs::read_dir("/dev").ok()?;
    for entry in entries.take(4097) {
        let entry = entry.ok()?;
        let file_type = entry.file_type().ok()?;
        if !file_type.is_block_device() {
            continue;
        }
        let metadata = entry.metadata().ok()?;
        if libc::major(metadata.rdev()) as u32 == major
            && libc::minor(metadata.rdev()) as u32 == minor
        {
            matches.push(entry.path());
        }
    }
    if matches.len() != 1 {
        return None;
    }
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&matches[0])
        .ok()?;
    bound_device_matches(&device, major, minor).then_some(device)
}

fn bound_device_matches(device: &File, major: u32, minor: u32) -> bool {
    device.metadata().is_ok_and(|metadata| {
        metadata.file_type().is_block_device()
            && libc::major(metadata.rdev()) as u32 == major
            && libc::minor(metadata.rdev()) as u32 == minor
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunDisposition {
    Completed,
    Unavailable,
    TimedOut,
    Truncated,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CheckResult {
    disposition: RunDisposition,
    exit_code: Option<i32>,
}

trait CheckRunner: Sync {
    fn run(&self, filesystem: FilesystemKind, device: &File) -> CheckResult;
}

struct SystemRunner;

impl CheckRunner for SystemRunner {
    fn run(&self, filesystem: FilesystemKind, device: &File) -> CheckResult {
        let descriptor = format!("/proc/self/fd/{}", device.as_raw_fd());
        let (binary, arguments): (&str, Vec<String>) = match filesystem {
            FilesystemKind::Ext4 => (E2FSCK, vec!["-f".to_owned(), "-n".to_owned(), descriptor]),
            FilesystemKind::Ntfs => (NTFSFIX, vec!["-n".to_owned(), descriptor]),
            FilesystemKind::Other => return unavailable_result(),
        };
        run_bounded(binary, &arguments, device)
    }
}

fn run_bounded(binary: &str, arguments: &[String], device: &File) -> CheckResult {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // Inherit the already-bound descriptor only across this one fixed spawn.
    // The output path names the descriptor, never a caller-provided device.
    let Ok(_spawn_guard) = FIXED_TOOL_SPAWN.lock() else {
        return unavailable_result();
    };
    let Ok(original_flags) = rustix::io::fcntl_getfd(device) else {
        return unavailable_result();
    };
    if rustix::io::fcntl_setfd(device, original_flags & !rustix::io::FdFlags::CLOEXEC).is_err() {
        return unavailable_result();
    }
    let spawned = command.spawn();
    let restored = rustix::io::fcntl_setfd(device, original_flags).is_ok();
    let mut child = match spawned {
        Ok(mut child) if !restored => {
            terminate(&mut child);
            return unavailable_result();
        }
        Ok(child) => child,
        Err(_) => return unavailable_result(),
    };
    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        return unavailable_result();
    };
    let Some(stderr) = child.stderr.take() else {
        terminate(&mut child);
        return unavailable_result();
    };
    let stdout_reader = thread::spawn(move || drain_bounded(stdout));
    let stderr_reader = thread::spawn(move || drain_bounded(stderr));
    let deadline = Instant::now() + TOOL_TIMEOUT;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                terminate(&mut child);
                break (child.wait().ok(), true);
            }
            Err(_) => {
                terminate(&mut child);
                break (None, false);
            }
        }
    };
    terminate_group(&child);
    let stdout_truncated = stdout_reader.join().unwrap_or(true);
    let stderr_truncated = stderr_reader.join().unwrap_or(true);
    CheckResult {
        disposition: if timed_out {
            RunDisposition::TimedOut
        } else if stdout_truncated || stderr_truncated {
            RunDisposition::Truncated
        } else if status.is_none() {
            RunDisposition::Unavailable
        } else {
            RunDisposition::Completed
        },
        exit_code: status.and_then(|status| status.code()),
    }
}

fn terminate(child: &mut Child) {
    terminate_group(child);
    let _ = child.kill();
    let _ = child.wait();
}

fn terminate_group(child: &Child) {
    let Ok(raw_pid) = i32::try_from(child.id()) else {
        return;
    };
    let Some(pid) = rustix::process::Pid::from_raw(raw_pid) else {
        return;
    };
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
}

fn drain_bounded(mut stream: impl Read) -> bool {
    let mut observed = 0_usize;
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                observed = observed.saturating_add(count);
                if observed > MAX_TOOL_STREAM_BYTES {
                    truncated = true;
                }
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    truncated
}

fn unavailable_result() -> CheckResult {
    CheckResult {
        disposition: RunDisposition::Unavailable,
        exit_code: None,
    }
}

fn classify(
    filesystem: FilesystemKind,
    result: CheckResult,
    mounted_at_check: bool,
) -> FilesystemHealthState {
    if result.disposition != RunDisposition::Completed {
        return FilesystemHealthState::Unsupported;
    }
    match (filesystem, result.exit_code) {
        (FilesystemKind::Ext4, Some(0)) | (FilesystemKind::Ntfs, Some(0)) => {
            if mounted_at_check {
                FilesystemHealthState::Degraded
            } else {
                FilesystemHealthState::Healthy
            }
        }
        (FilesystemKind::Ext4, Some(code)) if code & 0b111 != 0 => {
            FilesystemHealthState::RepairRequired
        }
        (FilesystemKind::Ntfs, Some(1)) => FilesystemHealthState::RepairRequired,
        _ => FilesystemHealthState::Unsupported,
    }
}

fn check_mode(filesystem: FilesystemKind) -> FilesystemCheckMode {
    match filesystem {
        FilesystemKind::Ext4 => FilesystemCheckMode::E2fsckReadOnly,
        FilesystemKind::Ntfs => FilesystemCheckMode::NtfsfixNoAction,
        FilesystemKind::Other => FilesystemCheckMode::Unavailable,
    }
}

fn snapshot(
    target_ref: &str,
    filesystem: FilesystemKind,
    state: FilesystemHealthState,
    mounted_at_check: bool,
) -> FilesystemHealthSnapshot {
    FilesystemHealthSnapshot {
        schema_version: SCHEMA_VERSION.to_owned(),
        kind: KIND.to_owned(),
        target_ref: target_ref.to_owned(),
        filesystem,
        state,
        check_mode: if state == FilesystemHealthState::Unsupported {
            FilesystemCheckMode::Unavailable
        } else {
            check_mode(filesystem)
        },
        mounted_at_check,
        finding: finding_for_state(state),
    }
}

fn unsupported(
    target_ref: &str,
    filesystem: FilesystemKind,
    mounted_at_check: bool,
) -> FilesystemHealthSnapshot {
    snapshot(
        target_ref,
        filesystem,
        FilesystemHealthState::Unsupported,
        mounted_at_check,
    )
}

fn finding_for_state(state: FilesystemHealthState) -> Option<FilesystemHealthFinding> {
    let (rule_id, severity, summary, next_action) = match state {
        FilesystemHealthState::Healthy => return None,
        FilesystemHealthState::RepairRequired => (
            "KA-LNX-FS-001",
            FindingSeverity::Critical,
            "The fixed read-only filesystem check reports errors that require repair.",
            "Back up recoverable data, then use the operating system's native repair workflow with explicit write authorization; KernAid did not modify this filesystem.",
        ),
        FilesystemHealthState::Degraded => (
            "KA-LNX-FS-002",
            FindingSeverity::High,
            "The filesystem was checked while mounted, so a clean result cannot be qualified.",
            "Boot KernAid Rescue and repeat the fixed read-only check on the unmounted selected target.",
        ),
        FilesystemHealthState::Unsupported => (
            "KA-LNX-FS-003",
            FindingSeverity::Low,
            "The fixed read-only filesystem check is unsupported or unavailable.",
            "Use a qualified read-only diagnostic for this filesystem; do not infer that it is healthy.",
        ),
    };
    Some(FilesystemHealthFinding {
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        severity,
        summary: summary.to_owned(),
        next_action: next_action.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_TOOL_OUTPUT: &str =
        "Inode /home/customer/private.txt contains SECRET-CUSTOMER-CONTENT";

    fn result(exit_code: i32) -> CheckResult {
        let _discarded = SECRET_TOOL_OUTPUT.as_bytes();
        CheckResult {
            disposition: RunDisposition::Completed,
            exit_code: Some(exit_code),
        }
    }

    #[test]
    fn ext4_and_ntfs_exit_codes_are_deterministic() {
        assert_eq!(
            classify(FilesystemKind::Ext4, result(0), false),
            FilesystemHealthState::Healthy
        );
        assert_eq!(
            classify(FilesystemKind::Ext4, result(4), false),
            FilesystemHealthState::RepairRequired
        );
        assert_eq!(
            classify(FilesystemKind::Ntfs, result(0), false),
            FilesystemHealthState::Healthy
        );
        assert_eq!(
            classify(FilesystemKind::Ntfs, result(1), false),
            FilesystemHealthState::RepairRequired
        );
        assert_eq!(
            classify(FilesystemKind::Ext4, result(0), true),
            FilesystemHealthState::Degraded
        );
    }

    #[test]
    fn unavailable_and_malformed_results_never_imply_health() {
        for disposition in [
            RunDisposition::Unavailable,
            RunDisposition::TimedOut,
            RunDisposition::Truncated,
        ] {
            assert_eq!(
                classify(
                    FilesystemKind::Ext4,
                    CheckResult {
                        disposition,
                        exit_code: None,
                    },
                    false,
                ),
                FilesystemHealthState::Unsupported
            );
        }
        assert!(collect_selected("/dev/sda1", "ext4", "8:1").is_err());
        assert!(collect_selected("disk-1/volume-1", "xfs", "8:1").is_err());
        assert!(collect_selected("disk-1/volume-1", "ext4", "08:1").is_err());
    }

    #[test]
    fn normalized_documents_are_canonical_and_content_free() {
        for state in [
            FilesystemHealthState::Healthy,
            FilesystemHealthState::Degraded,
            FilesystemHealthState::RepairRequired,
            FilesystemHealthState::Unsupported,
        ] {
            let snapshot = snapshot(
                if state == FilesystemHealthState::Degraded {
                    "local-root"
                } else {
                    "disk-1/volume-2"
                },
                FilesystemKind::Ext4,
                state,
                state == FilesystemHealthState::Degraded,
            );
            let encoded = to_bounded_json(&snapshot).expect("serialize filesystem health");
            assert!(!encoded.contains("SECRET"));
            assert!(!encoded.contains("private.txt"));
            assert!(!encoded.contains("/dev/"));
            assert_eq!(parse_bounded_json(encoded.as_bytes()), Ok(snapshot));
        }
    }

    #[test]
    fn only_normalized_target_references_are_admitted() {
        for value in ["local-root", "disk-1", "disk-32/volume-128"] {
            assert!(valid_target_ref(value));
        }
        for value in [
            "disk-0",
            "disk-33",
            "disk-1/volume-0",
            "disk-1/volume-129",
            "disk-1/../../dev/sda",
        ] {
            assert!(!valid_target_ref(value));
        }
    }
}
