//! Fixed-command, bounded and privacy-minimized Linux drive health collector.
//!
//! The production entry point discovers disks with one fixed `lsblk` shape and
//! invokes only fixed `smartctl`/`nvme` commands for strictly validated kernel
//! disk names. Raw command output, device names, serials and WWNs never enter
//! the normalized snapshot, findings, logs or `Debug` output.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const COLLECTOR: &str = "linux.storage.health.v1";
pub const KIND: &str = "linux-storage-health";
pub const SCHEMA_VERSION: &str = "1.0";
pub const SCOPE: &str = "local-physical-disks";
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_DISKS: usize = 32;
const TOOL_TIMEOUT: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const LSBLK: &str = "/usr/bin/lsblk";
const SMARTCTL: &str = "/usr/sbin/smartctl";
const NVME: &str = "/usr/sbin/nvme";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageEnumerationStatus {
    Complete,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageHealthState {
    Healthy,
    Degraded,
    Failing,
    Unsupported,
    PermissionUnavailable,
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
pub struct StorageDiskHealth {
    pub disk_ref: String,
    pub state: StorageHealthState,
    pub overall_passed: Option<bool>,
    pub critical_warning: Option<u8>,
    pub media_errors: Option<u64>,
    pub temperature_celsius: Option<i16>,
    pub available_spare_percent: Option<u8>,
    pub percentage_used: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageHealthFinding {
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: FindingSeverity,
    pub disk_ref: String,
    pub summary: String,
    pub next_action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageHealthSnapshot {
    pub schema_version: String,
    pub kind: String,
    pub scope: String,
    pub enumeration_status: StorageEnumerationStatus,
    pub disks: Vec<StorageDiskHealth>,
    pub findings: Vec<StorageHealthFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidStorageHealth;

impl fmt::Display for InvalidStorageHealth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid normalized Linux storage health")
    }
}

impl Error for InvalidStorageHealth {}

impl StorageHealthSnapshot {
    pub fn validate(&self) -> bool {
        if self.schema_version != SCHEMA_VERSION
            || self.kind != KIND
            || self.scope != SCOPE
            || self.disks.len() > MAX_DISKS
            || (self.enumeration_status == StorageEnumerationStatus::Unsupported
                && !self.disks.is_empty())
        {
            return false;
        }
        let mut previous_number = 0_usize;
        for disk in &self.disks {
            let Some(number) = disk_ref_number(&disk.disk_ref) else {
                return false;
            };
            if number <= previous_number
                || disk
                    .temperature_celsius
                    .is_some_and(|temperature| !(-100..=300).contains(&temperature))
                || matches!(
                    disk.state,
                    StorageHealthState::Unsupported | StorageHealthState::PermissionUnavailable
                ) && has_indicators(disk)
                || matches!(
                    disk.state,
                    StorageHealthState::Healthy
                        | StorageHealthState::Degraded
                        | StorageHealthState::Failing
                ) && !has_indicators(disk)
            {
                return false;
            }
            previous_number = number;
        }
        let expected_findings: Vec<_> = self
            .disks
            .iter()
            .filter(|disk| disk.state != StorageHealthState::Healthy)
            .map(finding_for_disk)
            .collect();
        self.findings == expected_findings
    }

    pub fn for_disk(&self, disk_ref: &str) -> Option<Self> {
        if !self.validate() || !valid_disk_ref(disk_ref) {
            return None;
        }
        let disk = self
            .disks
            .iter()
            .find(|disk| disk.disk_ref == disk_ref)?
            .clone();
        let findings = if disk.state == StorageHealthState::Healthy {
            Vec::new()
        } else {
            vec![finding_for_disk(&disk)]
        };
        Some(Self {
            schema_version: self.schema_version.clone(),
            kind: self.kind.clone(),
            scope: self.scope.clone(),
            enumeration_status: self.enumeration_status,
            disks: vec![disk],
            findings,
        })
    }
}

pub fn parse_bounded_json(input: &[u8]) -> Result<StorageHealthSnapshot, InvalidStorageHealth> {
    if input.is_empty() || input.len() > MAX_SNAPSHOT_BYTES {
        return Err(InvalidStorageHealth);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let snapshot =
        StorageHealthSnapshot::deserialize(&mut deserializer).map_err(|_| InvalidStorageHealth)?;
    deserializer.end().map_err(|_| InvalidStorageHealth)?;
    if !snapshot.validate()
        || serde_json::to_vec(&snapshot).map_err(|_| InvalidStorageHealth)? != input
    {
        return Err(InvalidStorageHealth);
    }
    Ok(snapshot)
}

pub fn to_bounded_json(snapshot: &StorageHealthSnapshot) -> Result<String, serde_json::Error> {
    if !snapshot.validate() {
        return Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage health violated the normalized contract",
        )));
    }
    let output = serde_json::to_string(snapshot)?;
    if output.len() > MAX_SNAPSHOT_BYTES {
        return Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage health exceeded the output limit",
        )));
    }
    Ok(output)
}

pub fn collect_current_machine() -> StorageHealthSnapshot {
    collect_with_runner(&SystemRunner)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Invocation {
    ListDisks,
    Smartctl(String),
    Nvme(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RunDisposition {
    Completed,
    Unavailable,
    TimedOut,
    Truncated,
}

#[derive(Clone, PartialEq, Eq)]
struct RunOutput {
    disposition: RunDisposition,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait ToolRunner: Sync {
    fn run(&self, invocation: &Invocation) -> RunOutput;
}

struct SystemRunner;

impl ToolRunner for SystemRunner {
    fn run(&self, invocation: &Invocation) -> RunOutput {
        let (binary, arguments): (&str, Vec<String>) = match invocation {
            Invocation::ListDisks => (
                LSBLK,
                vec!["--json", "--nodeps", "--output", "NAME,TYPE"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
            Invocation::Smartctl(name) if valid_device_name(name) => (
                SMARTCTL,
                vec![
                    "--json=c".to_owned(),
                    "--all".to_owned(),
                    format!("/dev/{name}"),
                ],
            ),
            Invocation::Nvme(name) if valid_device_name(name) => (
                NVME,
                vec![
                    "smart-log".to_owned(),
                    "--output-format=json".to_owned(),
                    format!("/dev/{name}"),
                ],
            ),
            _ => return unavailable_output(),
        };
        run_bounded(binary, &arguments)
    }
}

fn run_bounded(binary: &str, arguments: &[String]) -> RunOutput {
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
        .stderr(Stdio::piped());
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
    let (stderr, stderr_truncated) = stderr_reader.join().unwrap_or_else(|_| (Vec::new(), true));
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
        stderr,
    }
}

fn read_bounded(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut retained = Vec::with_capacity(MAX_TOOL_OUTPUT_BYTES.min(4096));
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => {
                truncated = true;
                break;
            }
        };
        let remaining = MAX_TOOL_OUTPUT_BYTES.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
        }
    }
    (retained, truncated)
}

fn unavailable_output() -> RunOutput {
    RunOutput {
        disposition: RunDisposition::Unavailable,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LsblkDocument {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LsblkDevice {
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

fn collect_with_runner(runner: &impl ToolRunner) -> StorageHealthSnapshot {
    let listed = runner.run(&Invocation::ListDisks);
    let Some(names) = parse_disk_names(&listed) else {
        return StorageHealthSnapshot {
            schema_version: SCHEMA_VERSION.to_owned(),
            kind: KIND.to_owned(),
            scope: SCOPE.to_owned(),
            enumeration_status: StorageEnumerationStatus::Unsupported,
            disks: Vec::new(),
            findings: Vec::new(),
        };
    };
    let disks = thread::scope(|scope| {
        let handles: Vec<_> = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                scope.spawn(move || collect_disk(runner, name, format!("disk-{}", index + 1)))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_else(|_| unsupported_disk("disk-0")))
            .collect::<Vec<_>>()
    });
    if disks.iter().any(|disk| disk.disk_ref == "disk-0") {
        return StorageHealthSnapshot {
            schema_version: SCHEMA_VERSION.to_owned(),
            kind: KIND.to_owned(),
            scope: SCOPE.to_owned(),
            enumeration_status: StorageEnumerationStatus::Unsupported,
            disks: Vec::new(),
            findings: Vec::new(),
        };
    }
    let findings = disks
        .iter()
        .filter(|disk| disk.state != StorageHealthState::Healthy)
        .map(finding_for_disk)
        .collect();
    StorageHealthSnapshot {
        schema_version: SCHEMA_VERSION.to_owned(),
        kind: KIND.to_owned(),
        scope: SCOPE.to_owned(),
        enumeration_status: StorageEnumerationStatus::Complete,
        disks,
        findings,
    }
}

fn parse_disk_names(output: &RunOutput) -> Option<Vec<String>> {
    if output.disposition != RunDisposition::Completed || output.exit_code != Some(0) {
        return None;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&output.stdout);
    let document = LsblkDocument::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    let names: BTreeSet<_> = document
        .blockdevices
        .into_iter()
        .filter(|device| device.kind == "disk")
        .map(|device| device.name)
        .collect();
    if names.len() > MAX_DISKS || names.iter().any(|name| !valid_device_name(name)) {
        return None;
    }
    Some(names.into_iter().collect())
}

fn valid_device_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_lowercase() || byte.is_ascii_digit() && index > 0)
}

fn valid_disk_ref(value: &str) -> bool {
    disk_ref_number(value).is_some()
}

fn disk_ref_number(value: &str) -> Option<usize> {
    let number = value.strip_prefix("disk-")?;
    if number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    number
        .parse::<usize>()
        .ok()
        .filter(|number| *number <= MAX_DISKS)
}

#[derive(Default)]
struct Indicators {
    overall_passed: Option<bool>,
    critical_warning: Option<u8>,
    media_errors: Option<u64>,
    temperature_celsius: Option<i16>,
    available_spare_percent: Option<u8>,
    percentage_used: Option<u8>,
}

impl Indicators {
    fn merge_missing(&mut self, other: Self) {
        self.overall_passed = self.overall_passed.or(other.overall_passed);
        self.critical_warning = self.critical_warning.or(other.critical_warning);
        self.media_errors = self.media_errors.or(other.media_errors);
        self.temperature_celsius = self.temperature_celsius.or(other.temperature_celsius);
        self.available_spare_percent = self
            .available_spare_percent
            .or(other.available_spare_percent);
        self.percentage_used = self.percentage_used.or(other.percentage_used);
    }

    fn present(&self) -> bool {
        self.overall_passed.is_some()
            || self.critical_warning.is_some()
            || self.media_errors.is_some()
            || self.temperature_celsius.is_some()
            || self.available_spare_percent.is_some()
            || self.percentage_used.is_some()
    }
}

fn collect_disk(runner: &impl ToolRunner, name: String, disk_ref: String) -> StorageDiskHealth {
    let smart = runner.run(&Invocation::Smartctl(name.clone()));
    let nvme = name
        .starts_with("nvme")
        .then(|| runner.run(&Invocation::Nvme(name)));
    let permission_unavailable =
        permission_denied(&smart) || nvme.as_ref().is_some_and(permission_denied);
    let mut indicators = parse_smartctl(&smart).unwrap_or_default();
    if let Some(nvme) = &nvme {
        if let Some(nvme_indicators) = parse_nvme(nvme) {
            indicators.merge_missing(nvme_indicators);
        }
    }
    if !indicators.present() {
        return StorageDiskHealth {
            disk_ref,
            state: if permission_unavailable {
                StorageHealthState::PermissionUnavailable
            } else {
                StorageHealthState::Unsupported
            },
            overall_passed: None,
            critical_warning: None,
            media_errors: None,
            temperature_celsius: None,
            available_spare_percent: None,
            percentage_used: None,
        };
    }
    let state = classify(&indicators);
    StorageDiskHealth {
        disk_ref,
        state,
        overall_passed: indicators.overall_passed,
        critical_warning: indicators.critical_warning,
        media_errors: indicators.media_errors,
        temperature_celsius: indicators.temperature_celsius,
        available_spare_percent: indicators.available_spare_percent,
        percentage_used: indicators.percentage_used,
    }
}

fn unsupported_disk(disk_ref: &str) -> StorageDiskHealth {
    StorageDiskHealth {
        disk_ref: disk_ref.to_owned(),
        state: StorageHealthState::Unsupported,
        overall_passed: None,
        critical_warning: None,
        media_errors: None,
        temperature_celsius: None,
        available_spare_percent: None,
        percentage_used: None,
    }
}

fn parse_smartctl(output: &RunOutput) -> Option<Indicators> {
    if output.disposition != RunDisposition::Completed {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let mut indicators = Indicators {
        overall_passed: value
            .pointer("/smart_status/passed")
            .and_then(Value::as_bool),
        critical_warning: u8_at(
            &value,
            "/nvme_smart_health_information_log/critical_warning",
        ),
        media_errors: value
            .pointer("/nvme_smart_health_information_log/media_errors")
            .and_then(Value::as_u64),
        temperature_celsius: i16_at(&value, "/temperature/current"),
        available_spare_percent: u8_at(
            &value,
            "/nvme_smart_health_information_log/available_spare",
        ),
        percentage_used: u8_at(&value, "/nvme_smart_health_information_log/percentage_used"),
    };
    if indicators.temperature_celsius.is_none() {
        indicators.temperature_celsius =
            i16_at(&value, "/nvme_smart_health_information_log/temperature");
    }
    Some(indicators)
}

fn parse_nvme(output: &RunOutput) -> Option<Indicators> {
    if output.disposition != RunDisposition::Completed {
        return None;
    }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    Some(Indicators {
        overall_passed: None,
        critical_warning: u8_at(&value, "/critical_warning"),
        media_errors: value.pointer("/media_errors").and_then(Value::as_u64),
        temperature_celsius: value
            .pointer("/temperature")
            .and_then(Value::as_i64)
            .and_then(normalize_nvme_temperature),
        available_spare_percent: u8_at(&value, "/avail_spare"),
        percentage_used: u8_at(&value, "/percent_used"),
    })
}

fn u8_at(value: &Value, pointer: &str) -> Option<u8> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
}

fn i16_at(value: &Value, pointer: &str) -> Option<i16> {
    value
        .pointer(pointer)
        .and_then(Value::as_i64)
        .and_then(|value| i16::try_from(value).ok())
        .filter(|value| (-100..=300).contains(value))
}

fn normalize_nvme_temperature(value: i64) -> Option<i16> {
    let celsius = if (200..=573).contains(&value) {
        value - 273
    } else {
        value
    };
    i16::try_from(celsius)
        .ok()
        .filter(|value| (-100..=300).contains(value))
}

fn permission_denied(output: &RunOutput) -> bool {
    output.disposition == RunDisposition::Completed
        && [&output.stdout, &output.stderr].into_iter().any(|bytes| {
            let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
            text.contains("permission denied") || text.contains("operation not permitted")
        })
}

fn classify(indicators: &Indicators) -> StorageHealthState {
    if indicators.overall_passed == Some(false)
        || indicators.media_errors.is_some_and(|errors| errors > 0)
        || indicators
            .critical_warning
            .is_some_and(|warning| warning & 0b0001_1101 != 0)
        || indicators.percentage_used.is_some_and(|used| used >= 100)
        || indicators
            .available_spare_percent
            .is_some_and(|spare| spare == 0)
    {
        StorageHealthState::Failing
    } else if indicators
        .critical_warning
        .is_some_and(|warning| warning != 0)
        || indicators
            .temperature_celsius
            .is_some_and(|temperature| temperature >= 70)
        || indicators
            .available_spare_percent
            .is_some_and(|spare| spare <= 10)
        || indicators.percentage_used.is_some_and(|used| used >= 90)
    {
        StorageHealthState::Degraded
    } else {
        StorageHealthState::Healthy
    }
}

fn has_indicators(disk: &StorageDiskHealth) -> bool {
    disk.overall_passed.is_some()
        || disk.critical_warning.is_some()
        || disk.media_errors.is_some()
        || disk.temperature_celsius.is_some()
        || disk.available_spare_percent.is_some()
        || disk.percentage_used.is_some()
}

fn finding_for_disk(disk: &StorageDiskHealth) -> StorageHealthFinding {
    let (rule_id, severity, summary, next_action) = match disk.state {
        StorageHealthState::Failing => (
            "KA-LNX-STORAGE-001",
            FindingSeverity::Critical,
            "The drive reports a deterministic failure indicator.",
            "Back up recoverable data immediately and replace the drive; KernAid will not claim a hardware repair.",
        ),
        StorageHealthState::Degraded => (
            "KA-LNX-STORAGE-002",
            FindingSeverity::High,
            "The drive reports a deterministic degradation indicator.",
            "Back up important data now and schedule drive replacement after vendor diagnostics.",
        ),
        StorageHealthState::PermissionUnavailable => (
            "KA-LNX-STORAGE-003",
            FindingSeverity::Medium,
            "Drive health telemetry could not be read with the current privileges.",
            "Repeat this read-only check through an authorized local or Rescue collector; do not infer that the drive is healthy.",
        ),
        StorageHealthState::Unsupported => (
            "KA-LNX-STORAGE-004",
            FindingSeverity::Low,
            "Drive health telemetry is unsupported or unavailable.",
            "Use the drive vendor's read-only diagnostic and keep a current backup; no health conclusion was made.",
        ),
        StorageHealthState::Healthy => unreachable!("healthy disks do not emit findings"),
    };
    StorageHealthFinding {
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        severity,
        disk_ref: disk.disk_ref.clone(),
        summary: summary.to_owned(),
        next_action: next_action.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const HEALTHY_SMART: &[u8] = include_bytes!("../fixtures/storage-health/healthy-smart.json");
    const FAILING_SMART: &[u8] = include_bytes!("../fixtures/storage-health/failing-smart.json");
    const HEALTHY_NVME: &[u8] = include_bytes!("../fixtures/storage-health/healthy-nvme.json");
    const FAILING_NVME: &[u8] = include_bytes!("../fixtures/storage-health/failing-nvme.json");
    const MALFORMED: &[u8] = include_bytes!("../fixtures/storage-health/malformed.json");

    struct FixtureRunner(BTreeMap<Invocation, RunOutput>);

    impl ToolRunner for FixtureRunner {
        fn run(&self, invocation: &Invocation) -> RunOutput {
            self.0
                .get(invocation)
                .cloned()
                .unwrap_or_else(unavailable_output)
        }
    }

    fn completed(stdout: &[u8], exit_code: i32) -> RunOutput {
        RunOutput {
            disposition: RunDisposition::Completed,
            exit_code: Some(exit_code),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    type FixtureDisk<'a> = (&'a str, &'a [u8], Option<&'a [u8]>);

    fn runner(disks: &[FixtureDisk<'_>]) -> FixtureRunner {
        let list = format!(
            "{{\"blockdevices\":[{}]}}",
            disks
                .iter()
                .map(|(name, _, _)| format!("{{\"name\":\"{name}\",\"type\":\"disk\"}}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut outputs = BTreeMap::from([(Invocation::ListDisks, completed(list.as_bytes(), 0))]);
        for (name, smart, nvme) in disks {
            outputs.insert(
                Invocation::Smartctl((*name).to_owned()),
                completed(smart, 0),
            );
            if let Some(nvme) = nvme {
                outputs.insert(Invocation::Nvme((*name).to_owned()), completed(nvme, 0));
            }
        }
        FixtureRunner(outputs)
    }

    #[test]
    fn healthy_sata_and_nvme_are_minimized_and_never_leak_identity() {
        let snapshot = collect_with_runner(&runner(&[
            ("sda", HEALTHY_SMART, None),
            ("nvme0n1", HEALTHY_SMART, Some(HEALTHY_NVME)),
        ]));
        assert!(snapshot.validate());
        assert_eq!(snapshot.disks[0].disk_ref, "disk-1");
        assert_eq!(snapshot.disks[0].state, StorageHealthState::Healthy);
        assert_eq!(snapshot.disks[1].disk_ref, "disk-2");
        assert_eq!(snapshot.disks[1].temperature_celsius, Some(34));
        assert!(snapshot.findings.is_empty());
        let json = to_bounded_json(&snapshot).expect("serialize health");
        for secret in ["SECRET", "SERIAL", "WWN", "/dev/", "nvme0n1", "sda"] {
            assert!(!json.to_ascii_uppercase().contains(secret));
        }
        assert_eq!(parse_bounded_json(json.as_bytes()), Ok(snapshot));
    }

    #[test]
    fn failing_signals_emit_fixed_backup_and_replacement_actions() {
        let snapshot = collect_with_runner(&runner(&[
            ("sda", FAILING_SMART, None),
            ("nvme0n1", HEALTHY_SMART, Some(FAILING_NVME)),
        ]));
        assert!(
            snapshot
                .disks
                .iter()
                .all(|disk| disk.state == StorageHealthState::Failing)
        );
        assert!(
            snapshot
                .findings
                .iter()
                .all(|finding| finding.next_action.contains("Back up")
                    && finding.next_action.contains("replace"))
        );
        assert!(
            !to_bounded_json(&snapshot)
                .expect("serialize failing health")
                .contains("SECRET")
        );
    }

    #[test]
    fn malformed_absent_and_permission_denied_tools_fail_closed() {
        let mut malformed = runner(&[("sda", MALFORMED, None)]);
        malformed.0.insert(
            Invocation::Smartctl("sda".to_owned()),
            RunOutput {
                disposition: RunDisposition::Completed,
                exit_code: Some(2),
                stdout: MALFORMED.to_vec(),
                stderr: Vec::new(),
            },
        );
        assert_eq!(
            collect_with_runner(&malformed).disks[0].state,
            StorageHealthState::Unsupported
        );

        let mut permission = runner(&[("sda", b"{}", None)]);
        permission.0.insert(
            Invocation::Smartctl("sda".to_owned()),
            RunOutput {
                disposition: RunDisposition::Completed,
                exit_code: Some(2),
                stdout: b"{}".to_vec(),
                stderr: b"Permission denied; SECRET-SERIAL".to_vec(),
            },
        );
        let snapshot = collect_with_runner(&permission);
        assert_eq!(
            snapshot.disks[0].state,
            StorageHealthState::PermissionUnavailable
        );
        assert!(
            !to_bounded_json(&snapshot)
                .expect("serialize permission state")
                .contains("SECRET")
        );

        let unavailable = collect_with_runner(&FixtureRunner(BTreeMap::new()));
        assert_eq!(
            unavailable.enumeration_status,
            StorageEnumerationStatus::Unsupported
        );
        assert!(unavailable.disks.is_empty());
    }

    #[test]
    fn unsafe_disk_names_and_oversized_outputs_never_become_commands_or_reports() {
        let malicious = completed(
            br#"{"blockdevices":[{"name":"sda;reboot","type":"disk"}]}"#,
            0,
        );
        let snapshot = collect_with_runner(&FixtureRunner(BTreeMap::from([(
            Invocation::ListDisks,
            malicious,
        )])));
        assert_eq!(
            snapshot.enumeration_status,
            StorageEnumerationStatus::Unsupported
        );

        let oversized = RunOutput {
            disposition: RunDisposition::Truncated,
            exit_code: Some(0),
            stdout: vec![b'x'; MAX_TOOL_OUTPUT_BYTES],
            stderr: Vec::new(),
        };
        let snapshot = collect_with_runner(&FixtureRunner(BTreeMap::from([(
            Invocation::ListDisks,
            oversized,
        )])));
        assert_eq!(
            snapshot.enumeration_status,
            StorageEnumerationStatus::Unsupported
        );
    }
}
