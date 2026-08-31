//! Fixed-command, bounded and privacy-minimized Linux boot-path diagnostics.
//!
//! The collector emits counts and fixed findings only. Unit names, paths,
//! kernel versions, command output and configuration contents never cross the
//! normalization boundary.

use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const COLLECTOR: &str = "linux.boot-critical-path.v1";
pub const KIND: &str = "linux-boot-critical-path";
pub const SCHEMA_VERSION: &str = "1.0";
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024;
const MAX_TOOL_STREAM_BYTES: usize = 64 * 1024;
const MAX_FSTAB_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootState {
    Healthy,
    Degraded,
    BootRisk,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceStatus {
    Complete,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FstabStatus {
    Valid,
    Absent,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresenceStatus {
    Present,
    Absent,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootloaderStatus {
    Configured,
    Partial,
    Absent,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootloaderKind {
    Grub,
    SystemdBoot,
    Multiple,
    Other,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeBootState {
    pub failed_units_status: SourceStatus,
    pub failed_unit_count: u16,
    pub critical_failed_unit_count: u16,
    pub critical_chain_status: SourceStatus,
    pub critical_chain_unit_count: u16,
    pub slowest_activation_millis: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootConfigurationState {
    pub fstab_status: FstabStatus,
    pub fstab_entry_count: u16,
    pub critical_mount_entry_count: u16,
    pub initramfs_status: PresenceStatus,
    pub initramfs_image_count: u16,
    pub kernel_image_count: u16,
    pub bootloader_status: BootloaderStatus,
    pub bootloader: BootloaderKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootFinding {
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: FindingSeverity,
    pub summary: String,
    pub next_action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootCriticalPathSnapshot {
    pub schema_version: String,
    pub kind: String,
    pub scope: String,
    pub state: BootState,
    pub runtime: RuntimeBootState,
    pub configuration: BootConfigurationState,
    pub findings: Vec<BootFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidBootCriticalPath;

impl fmt::Display for InvalidBootCriticalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid normalized Linux boot critical path")
    }
}

impl Error for InvalidBootCriticalPath {}

impl BootCriticalPathSnapshot {
    pub fn validate(&self) -> bool {
        if self.schema_version != SCHEMA_VERSION
            || self.kind != KIND
            || self.scope != "local-root"
            || self.runtime.failed_unit_count > 256
            || self.runtime.critical_failed_unit_count > self.runtime.failed_unit_count
            || self.runtime.critical_chain_unit_count > 256
            || self.configuration.fstab_entry_count > 1024
            || self.configuration.critical_mount_entry_count > self.configuration.fstab_entry_count
            || self.configuration.initramfs_image_count > MAX_DIRECTORY_ENTRIES as u16
            || self.configuration.kernel_image_count > MAX_DIRECTORY_ENTRIES as u16
            || self
                .runtime
                .slowest_activation_millis
                .is_some_and(|value| value > 86_400_000)
            || (self.runtime.failed_units_status == SourceStatus::Unavailable
                && (self.runtime.failed_unit_count != 0
                    || self.runtime.critical_failed_unit_count != 0))
            || (self.runtime.critical_chain_status == SourceStatus::Unavailable
                && (self.runtime.critical_chain_unit_count != 0
                    || self.runtime.slowest_activation_millis.is_some()))
            || (self.configuration.fstab_status != FstabStatus::Valid
                && (self.configuration.fstab_entry_count != 0
                    || self.configuration.critical_mount_entry_count != 0))
            || (self.configuration.initramfs_status == PresenceStatus::Unavailable
                && (self.configuration.initramfs_image_count != 0
                    || self.configuration.kernel_image_count != 0))
            || (self.configuration.initramfs_status == PresenceStatus::Present
                && self.configuration.initramfs_image_count == 0)
            || (self.configuration.initramfs_status == PresenceStatus::Absent
                && self.configuration.initramfs_image_count != 0)
            || (self.configuration.bootloader_status == BootloaderStatus::Configured)
                == (self.configuration.bootloader == BootloaderKind::None)
        {
            return false;
        }
        let expected = classify(&self.runtime, &self.configuration);
        self.state == expected.0 && self.findings == expected.1
    }
}

pub fn parse_bounded_json(
    input: &[u8],
) -> Result<BootCriticalPathSnapshot, InvalidBootCriticalPath> {
    if input.is_empty() || input.len() > MAX_SNAPSHOT_BYTES {
        return Err(InvalidBootCriticalPath);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let snapshot = BootCriticalPathSnapshot::deserialize(&mut deserializer)
        .map_err(|_| InvalidBootCriticalPath)?;
    deserializer.end().map_err(|_| InvalidBootCriticalPath)?;
    if !snapshot.validate()
        || serde_json::to_vec(&snapshot).map_err(|_| InvalidBootCriticalPath)? != input
    {
        return Err(InvalidBootCriticalPath);
    }
    Ok(snapshot)
}

pub fn to_bounded_json(snapshot: &BootCriticalPathSnapshot) -> Result<String, serde_json::Error> {
    if !snapshot.validate() {
        return Err(serde_json::Error::io(io::Error::other(
            "boot critical path violated the normalized contract",
        )));
    }
    let output = serde_json::to_string(snapshot)?;
    if output.len() > MAX_SNAPSHOT_BYTES {
        return Err(serde_json::Error::io(io::Error::other(
            "boot critical path exceeded the output limit",
        )));
    }
    Ok(output)
}

pub fn collect_current_machine() -> BootCriticalPathSnapshot {
    // Debian Live keeps the bootloader/kernel artifacts on the read-only boot
    // medium rather than in the overlay root. Inspect that fixed location when
    // present so Rescue does not misclassify its own valid boot chain.
    let live_medium = Path::new("/run/live/medium");
    let configuration_root = fs::symlink_metadata(live_medium)
        .ok()
        .filter(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .map(|_| live_medium)
        .unwrap_or_else(|| Path::new("/"));
    collect(configuration_root, &SystemRunner)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Invocation {
    FailedUnits,
    CriticalChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunDisposition {
    Completed,
    Unavailable,
    TimedOut,
    Truncated,
}

#[derive(Clone)]
struct RunOutput {
    disposition: RunDisposition,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
}

trait ToolRunner {
    fn run(&self, invocation: Invocation) -> RunOutput;
}

struct SystemRunner;

impl ToolRunner for SystemRunner {
    fn run(&self, invocation: Invocation) -> RunOutput {
        let (binary, arguments): (&str, &[&str]) = match invocation {
            Invocation::FailedUnits => (
                "/usr/bin/systemctl",
                &["--failed", "--no-pager", "--plain", "--no-legend"],
            ),
            Invocation::CriticalChain => (
                "/usr/bin/systemd-analyze",
                &["critical-chain", "--no-pager"],
            ),
        };
        run_bounded(binary, arguments)
    }
}

fn run_bounded(binary: &str, arguments: &[&str]) -> RunOutput {
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
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return unavailable_output(),
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return unavailable_output();
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return unavailable_output();
    };
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + TOOL_TIMEOUT;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                break (child.wait().ok(), true);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break (None, false);
            }
        }
    };
    let (stdout, stdout_truncated) = stdout_reader.join().unwrap_or_else(|_| (Vec::new(), true));
    let (_, stderr_truncated) = stderr_reader.join().unwrap_or_else(|_| (Vec::new(), true));
    RunOutput {
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
        stdout,
    }
}

fn read_bounded(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut retained = Vec::with_capacity(4096);
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => return (retained, true),
        };
        let remaining = MAX_TOOL_STREAM_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
    }
    (retained, truncated)
}

fn unavailable_output() -> RunOutput {
    RunOutput {
        disposition: RunDisposition::Unavailable,
        exit_code: None,
        stdout: Vec::new(),
    }
}

fn collect(root: &Path, runner: &impl ToolRunner) -> BootCriticalPathSnapshot {
    let runtime = collect_runtime(runner);
    let configuration = collect_configuration(root);
    let (state, findings) = classify(&runtime, &configuration);
    BootCriticalPathSnapshot {
        schema_version: SCHEMA_VERSION.to_owned(),
        kind: KIND.to_owned(),
        scope: "local-root".to_owned(),
        state,
        runtime,
        configuration,
        findings,
    }
}

fn collect_runtime(runner: &impl ToolRunner) -> RuntimeBootState {
    let failed = runner.run(Invocation::FailedUnits);
    let chain = runner.run(Invocation::CriticalChain);
    let failed_counts = parse_failed_units(&failed);
    let chain_counts = parse_critical_chain(&chain);
    RuntimeBootState {
        failed_units_status: failed_counts
            .map(|_| SourceStatus::Complete)
            .unwrap_or(SourceStatus::Unavailable),
        failed_unit_count: failed_counts.map(|value| value.0).unwrap_or(0),
        critical_failed_unit_count: failed_counts.map(|value| value.1).unwrap_or(0),
        critical_chain_status: chain_counts
            .map(|_| SourceStatus::Complete)
            .unwrap_or(SourceStatus::Unavailable),
        critical_chain_unit_count: chain_counts.map(|value| value.0).unwrap_or(0),
        slowest_activation_millis: chain_counts.and_then(|value| value.1),
    }
}

fn parse_failed_units(output: &RunOutput) -> Option<(u16, u16)> {
    if output.disposition != RunDisposition::Completed || output.exit_code != Some(0) {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    let mut count = 0_u16;
    let mut critical = 0_u16;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let first = fields.next()?;
        let unit = if first == "●" {
            fields.next()?
        } else {
            first
        };
        count = count.checked_add(1)?;
        if count > 256 {
            return None;
        }
        if is_critical_unit(unit) {
            critical += 1;
        }
    }
    Some((count, critical))
}

fn is_critical_unit(unit: &str) -> bool {
    matches!(
        unit,
        "local-fs.target"
            | "initrd-root-fs.target"
            | "systemd-remount-fs.service"
            | "systemd-fsck-root.service"
            | "boot.mount"
            | "boot-efi.mount"
            | "efi.mount"
    )
}

fn parse_critical_chain(output: &RunOutput) -> Option<(u16, Option<u64>)> {
    if output.disposition != RunDisposition::Completed || output.exit_code != Some(0) {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    let mut count = 0_u16;
    let mut slowest = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if [".target", ".service", ".mount", ".socket", ".device"]
            .iter()
            .any(|suffix| trimmed.contains(suffix))
        {
            count = count.checked_add(1)?;
            if count > 256 {
                return None;
            }
        }
        for token in trimmed.split_whitespace() {
            if let Some(milliseconds) = parse_duration_millis(token) {
                slowest = Some(slowest.map_or(milliseconds, |old: u64| old.max(milliseconds)));
            }
        }
    }
    Some((count, slowest))
}

fn parse_duration_millis(token: &str) -> Option<u64> {
    let token = token.trim_matches(|ch: char| matches!(ch, ')' | '(' | ','));
    let value = token.strip_prefix('+')?;
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds.parse::<u64>().ok();
    }
    let seconds = value.strip_suffix('s')?.parse::<f64>().ok()?;
    if !seconds.is_finite() || !(0.0..=86_400.0).contains(&seconds) {
        return None;
    }
    Some((seconds * 1000.0).round() as u64)
}

fn collect_configuration(root: &Path) -> BootConfigurationState {
    let (fstab_status, fstab_entry_count, critical_mount_entry_count) =
        inspect_fstab(&root.join("etc/fstab"));
    let (initramfs_status, initramfs_image_count, kernel_image_count) = inspect_boot_images(root);
    let (bootloader_status, bootloader) = inspect_bootloader(root);
    BootConfigurationState {
        fstab_status,
        fstab_entry_count,
        critical_mount_entry_count,
        initramfs_status,
        initramfs_image_count,
        kernel_image_count,
        bootloader_status,
        bootloader,
    }
}

fn inspect_fstab(path: &Path) -> (FstabStatus, u16, u16) {
    let bytes = match read_fixed_file(path, MAX_FSTAB_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return (FstabStatus::Absent, 0, 0),
        Err(()) => return (FstabStatus::Unavailable, 0, 0),
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return (FstabStatus::Invalid, 0, 0);
    };
    let mut entries = 0_u16;
    let mut critical = 0_u16;
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or_default().trim();
        if content.is_empty() {
            continue;
        }
        let fields: Vec<_> = content.split_whitespace().collect();
        if fields.len() != 6 || entries == 1024 {
            return (FstabStatus::Invalid, 0, 0);
        }
        entries += 1;
        if matches!(fields[1], "/" | "/usr" | "/boot" | "/boot/efi" | "/efi") {
            critical += 1;
        }
    }
    (FstabStatus::Valid, entries, critical)
}

fn read_fixed_file(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>, ()> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if bytes.len() > maximum
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(());
    }
    Ok(Some(bytes))
}

fn inspect_boot_images(root: &Path) -> (PresenceStatus, u16, u16) {
    let mut saw_directory = false;
    let mut initramfs = 0_u16;
    let mut kernels = 0_u16;
    for relative in ["boot", "live"] {
        let directory = root.join(relative);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return (PresenceStatus::Unavailable, 0, 0),
        };
        saw_directory = true;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_DIRECTORY_ENTRIES {
                return (PresenceStatus::Unavailable, 0, 0);
            }
            let Ok(entry) = entry else {
                return (PresenceStatus::Unavailable, 0, 0);
            };
            let Ok(kind) = entry.file_type() else {
                return (PresenceStatus::Unavailable, 0, 0);
            };
            if !kind.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "initrd.img"
                || name.starts_with("initrd.img-")
                || name.starts_with("initramfs-")
            {
                initramfs = initramfs.saturating_add(1);
                if initramfs > MAX_DIRECTORY_ENTRIES as u16 {
                    return (PresenceStatus::Unavailable, 0, 0);
                }
            } else if name == "vmlinuz" || name.starts_with("vmlinuz-") {
                kernels = kernels.saturating_add(1);
                if kernels > MAX_DIRECTORY_ENTRIES as u16 {
                    return (PresenceStatus::Unavailable, 0, 0);
                }
            }
        }
    }
    if !saw_directory {
        return (PresenceStatus::Absent, 0, 0);
    }
    (
        if initramfs > 0 {
            PresenceStatus::Present
        } else {
            PresenceStatus::Absent
        },
        initramfs,
        kernels,
    )
}

fn inspect_bootloader(root: &Path) -> (BootloaderStatus, BootloaderKind) {
    let grub = fixed_nonempty(root, &["boot/grub/grub.cfg", "boot/grub2/grub.cfg"]);
    let systemd_boot = fixed_nonempty(root, &["boot/loader/loader.conf"]);
    let other = fixed_nonempty(root, &["boot/extlinux/extlinux.conf"]);
    if grub.is_err() || systemd_boot.is_err() || other.is_err() {
        return (BootloaderStatus::Unavailable, BootloaderKind::None);
    }
    let grub = grub.unwrap_or(false);
    let systemd_boot = systemd_boot.unwrap_or(false);
    let other = other.unwrap_or(false);
    let configured_count = usize::from(grub) + usize::from(systemd_boot) + usize::from(other);
    if configured_count > 1 {
        return (BootloaderStatus::Configured, BootloaderKind::Multiple);
    }
    if grub {
        return (BootloaderStatus::Configured, BootloaderKind::Grub);
    }
    if systemd_boot {
        return (BootloaderStatus::Configured, BootloaderKind::SystemdBoot);
    }
    if other {
        return (BootloaderStatus::Configured, BootloaderKind::Other);
    }
    let partial = [
        "boot/grub",
        "boot/grub2",
        "boot/loader",
        "boot/efi/EFI",
        "efi/EFI",
    ]
    .iter()
    .any(|relative| fs::symlink_metadata(root.join(relative)).is_ok_and(|meta| meta.is_dir()));
    if partial {
        (BootloaderStatus::Partial, BootloaderKind::None)
    } else {
        (BootloaderStatus::Absent, BootloaderKind::None)
    }
}

fn fixed_nonempty(root: &Path, paths: &[&str]) -> Result<bool, ()> {
    for relative in paths {
        match read_fixed_file(&root.join(relative), 1024 * 1024)? {
            Some(bytes) if !bytes.is_empty() => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

fn classify(
    runtime: &RuntimeBootState,
    configuration: &BootConfigurationState,
) -> (BootState, Vec<BootFinding>) {
    let mut findings = Vec::new();
    if runtime.critical_failed_unit_count > 0 {
        findings.push(finding(
            "KA-LNX-BOOT-001",
            FindingSeverity::Critical,
            "A critical boot-path unit is in the failed state.",
            "Keep the system read-only where possible, preserve evidence, and inspect the failed boot dependency before restarting.",
        ));
    }
    if configuration.fstab_status == FstabStatus::Invalid {
        findings.push(finding(
            "KA-LNX-BOOT-002",
            FindingSeverity::High,
            "The fixed fstab parser found an invalid boot-critical configuration.",
            "Review the boot-critical mount entries from Rescue and create a backup before any typed repair action.",
        ));
    }
    if configuration.kernel_image_count > 0 && configuration.initramfs_image_count == 0 {
        findings.push(finding(
            "KA-LNX-BOOT-003",
            FindingSeverity::High,
            "A kernel image is present but no matching initramfs artifact was observed.",
            "Regenerate initramfs only through an OS-native, explicitly authorized repair workflow after preserving evidence.",
        ));
    }
    if matches!(
        configuration.bootloader_status,
        BootloaderStatus::Partial | BootloaderStatus::Absent
    ) {
        findings.push(finding(
            "KA-LNX-BOOT-004",
            FindingSeverity::High,
            "Bootloader configuration is absent or incomplete in the observed root.",
            "Verify the firmware mode and boot partition from Rescue before using an OS-native bootloader recovery workflow.",
        ));
    }
    if runtime
        .slowest_activation_millis
        .is_some_and(|value| value >= 30_000)
    {
        findings.push(finding(
            "KA-LNX-BOOT-005",
            FindingSeverity::Medium,
            "The critical boot chain contains an activation of at least 30 seconds.",
            "Inspect boot dependencies and device availability; no service or timeout was changed.",
        ));
    }
    if runtime.failed_unit_count > runtime.critical_failed_unit_count {
        findings.push(finding(
            "KA-LNX-BOOT-006",
            FindingSeverity::Medium,
            "One or more non-critical systemd units are failed.",
            "Inspect the affected unit class and its dependencies before considering a restart or repair.",
        ));
    }
    let incomplete = runtime.failed_units_status == SourceStatus::Unavailable
        || runtime.critical_chain_status == SourceStatus::Unavailable
        || configuration.fstab_status == FstabStatus::Unavailable
        || configuration.initramfs_status == PresenceStatus::Unavailable
        || configuration.bootloader_status == BootloaderStatus::Unavailable;
    if incomplete {
        findings.push(finding(
            "KA-LNX-BOOT-007",
            FindingSeverity::Low,
            "One or more fixed boot-path sources were unavailable.",
            "Repeat the read-only collector with appropriate local privileges; no healthy conclusion was inferred for unavailable sources.",
        ));
    }
    let risk = findings.iter().any(|item| {
        matches!(
            item.severity,
            FindingSeverity::Critical | FindingSeverity::High
        )
    });
    let all_unavailable = runtime.failed_units_status == SourceStatus::Unavailable
        && runtime.critical_chain_status == SourceStatus::Unavailable
        && configuration.fstab_status == FstabStatus::Unavailable
        && configuration.initramfs_status == PresenceStatus::Unavailable
        && configuration.bootloader_status == BootloaderStatus::Unavailable;
    let state = if all_unavailable {
        BootState::Unsupported
    } else if risk {
        BootState::BootRisk
    } else if !findings.is_empty() {
        BootState::Degraded
    } else {
        BootState::Healthy
    };
    (state, findings)
}

fn finding(
    rule_id: &str,
    severity: FindingSeverity,
    summary: &str,
    next_action: &str,
) -> BootFinding {
    BootFinding {
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        severity,
        summary: summary.to_owned(),
        next_action: next_action.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    struct FixtureRunner(BTreeMap<u8, RunOutput>);

    impl ToolRunner for FixtureRunner {
        fn run(&self, invocation: Invocation) -> RunOutput {
            self.0
                .get(&(invocation as u8))
                .cloned()
                .unwrap_or_else(unavailable_output)
        }
    }

    fn completed(output: &str) -> RunOutput {
        RunOutput {
            disposition: RunDisposition::Completed,
            exit_code: Some(0),
            stdout: output.as_bytes().to_vec(),
        }
    }

    fn runner(failed: &str, chain: &str) -> FixtureRunner {
        FixtureRunner(BTreeMap::from([
            (Invocation::FailedUnits as u8, completed(failed)),
            (Invocation::CriticalChain as u8, completed(chain)),
        ]))
    }

    fn healthy_root() -> TempDir {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::create_dir_all(root.path().join("boot/grub")).unwrap();
        fs::write(
            root.path().join("etc/fstab"),
            "UUID=x / ext4 defaults 0 1\n",
        )
        .unwrap();
        fs::write(root.path().join("boot/vmlinuz-test"), b"kernel").unwrap();
        fs::write(root.path().join("boot/initrd.img-test"), b"initrd").unwrap();
        fs::write(root.path().join("boot/grub/grub.cfg"), b"config").unwrap();
        root
    }

    #[test]
    fn healthy_snapshot_is_canonical_and_privacy_minimized() {
        let root = healthy_root();
        let snapshot = collect(
            root.path(),
            &runner("", "graphical.target @1.0s\n└─basic.target @1.0s +250ms\n"),
        );
        assert_eq!(snapshot.state, BootState::Healthy);
        let json = to_bounded_json(&snapshot).unwrap();
        assert_eq!(parse_bounded_json(json.as_bytes()).unwrap(), snapshot);
        assert!(!json.contains("UUID=x"));
        assert!(!json.contains("vmlinuz-test"));
        assert!(!json.contains("basic.target"));
    }

    #[test]
    fn failed_critical_unit_and_missing_initramfs_are_boot_risk() {
        let root = healthy_root();
        fs::remove_file(root.path().join("boot/initrd.img-test")).unwrap();
        let snapshot = collect(
            root.path(),
            &runner(
                "● local-fs.target loaded failed failed user-private-value\n",
                "local-fs.target @1s +31.2s\n",
            ),
        );
        assert_eq!(snapshot.state, BootState::BootRisk);
        assert_eq!(snapshot.runtime.critical_failed_unit_count, 1);
        assert_eq!(
            snapshot
                .findings
                .iter()
                .map(|item| item.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["KA-LNX-BOOT-001", "KA-LNX-BOOT-003", "KA-LNX-BOOT-005"]
        );
        let json = to_bounded_json(&snapshot).unwrap();
        assert!(!json.contains("user-private-value"));
        assert!(!json.contains("local-fs.target"));
    }

    #[test]
    fn malformed_fstab_and_unavailable_tools_fail_closed() {
        let root = healthy_root();
        fs::write(root.path().join("etc/fstab"), b"secret invalid row\n").unwrap();
        let snapshot = collect(root.path(), &FixtureRunner(BTreeMap::new()));
        assert_eq!(snapshot.state, BootState::BootRisk);
        assert_eq!(snapshot.configuration.fstab_status, FstabStatus::Invalid);
        assert_eq!(
            snapshot.runtime.failed_units_status,
            SourceStatus::Unavailable
        );
        let json = to_bounded_json(&snapshot).unwrap();
        assert!(!json.contains("secret"));
    }

    #[test]
    fn parser_rejects_noncanonical_and_unknown_fields() {
        let root = healthy_root();
        let snapshot = collect(root.path(), &runner("", "basic.target @1s +1ms\n"));
        let canonical = to_bounded_json(&snapshot).unwrap();
        assert!(parse_bounded_json(format!("{canonical}\n").as_bytes()).is_err());
        let injected = canonical.replacen("{", "{\"rawOutput\":\"secret\",", 1);
        assert!(parse_bounded_json(injected.as_bytes()).is_err());
    }
}
