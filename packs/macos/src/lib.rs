#![forbid(unsafe_code)]
//! Deterministic, read-only macOS Resident P0 diagnostics.
//!
//! This crate only parses already-collected, normalized evidence bytes. It
//! cannot spawn a process, open a host path, or mutate the machine. All
//! observed data is untrusted. Findings contain only fixed text and fixed
//! collector identifiers; observed strings are never copied into a finding.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, error::Error, fmt};

pub const CORPUS_VERSION: &str = "macos-resident-p0.1";
pub const REPORT_SCHEMA_VERSION: &str = "1.0";
pub const PROJECTION_SCHEMA_VERSION: &str = "1.0";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_EVIDENCE_ID_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub struct EvidenceInput<'a> {
    pub id: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct MacosP0Inputs<'a> {
    pub storage: EvidenceInput<'a>,
    pub apfs: EvidenceInput<'a>,
    pub launchd: EvidenceInput<'a>,
    pub network: EvidenceInput<'a>,
    pub updates: EvidenceInput<'a>,
    pub events: EvidenceInput<'a>,
    pub startup: EvidenceInput<'a>,
    pub snapshots: EvidenceInput<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    Storage,
    Apfs,
    Launchd,
    Network,
    Updates,
    Events,
    Startup,
    Snapshots,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticErrorKind {
    InvalidEvidenceId,
    DuplicateEvidenceId,
    EmptyInput,
    InputTooLarge,
    MalformedInput,
    UnsupportedSchema,
    PartialEvidence,
    TooManyRecords,
    ValueOutOfRange,
    InconsistentEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticError {
    pub source: EvidenceSource,
    pub kind: DiagnosticErrorKind,
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DiagnosticErrorKind::InvalidEvidenceId => {
                "macOS diagnostic evidence identifier is invalid"
            }
            DiagnosticErrorKind::DuplicateEvidenceId => {
                "macOS diagnostic evidence identifiers must be unique"
            }
            DiagnosticErrorKind::EmptyInput => "macOS diagnostic evidence is empty",
            DiagnosticErrorKind::InputTooLarge => {
                "macOS diagnostic evidence exceeds its byte limit"
            }
            DiagnosticErrorKind::MalformedInput => "macOS diagnostic evidence is malformed",
            DiagnosticErrorKind::UnsupportedSchema => {
                "macOS diagnostic projection schema is unsupported"
            }
            DiagnosticErrorKind::PartialEvidence => {
                "macOS diagnostic evidence is explicitly partial"
            }
            DiagnosticErrorKind::TooManyRecords => "macOS diagnostic evidence has too many records",
            DiagnosticErrorKind::ValueOutOfRange => {
                "macOS diagnostic evidence contains an out-of-range value"
            }
            DiagnosticErrorKind::InconsistentEvidence => {
                "macOS diagnostic evidence is internally inconsistent"
            }
        })
    }
}

impl Error for DiagnosticError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub schema_version: String,
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: Severity,
    pub evidence_ids: Vec<String>,
    pub summary: String,
    pub next_collector: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReport {
    pub schema_version: String,
    pub corpus_version: String,
    pub mode: String,
    pub complete: bool,
    pub evidence_ids: Vec<String>,
    pub findings: Vec<Finding>,
    pub scope_statement: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDiagnosisProposal {
    pub schema_version: String,
    pub diagnosis: String,
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
    pub requested_evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub devices: Vec<StorageDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageDevice {
    pub internal: bool,
    pub solid_state: bool,
    pub smart_status: SmartStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmartStatus {
    Verified,
    Failing,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApfsProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub container_count: u32,
    pub root_data_volume: RootDataVolume,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootDataVolume {
    pub capacity_bytes: u64,
    pub free_bytes: u64,
    pub purgeable_bytes: u64,
    pub file_vault: FileVaultState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileVaultState {
    On,
    Off,
    Deferred,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchdProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub services: Vec<LaunchdService>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchdService {
    pub scope: LaunchdScope,
    pub state: LaunchdState,
    pub last_exit_status: i32,
    pub consecutive_failures: u32,
    pub apple_signed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LaunchdScope {
    System,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchdState {
    Running,
    Waiting,
    Exited,
    Throttled,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub active_interfaces: u16,
    pub default_route_present: bool,
    pub dns_servers: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatesProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub pending: Vec<PendingUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingUpdate {
    pub security: bool,
    pub restart_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventsProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub window_hours: u16,
    pub kernel_panics: u32,
    pub watchdog_reboots: u32,
    pub repeated_app_crashes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub safe_mode: bool,
    pub third_party_login_items_enabled: u16,
    pub background_items_blocked: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotsProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub local_snapshots: u32,
    pub oldest_age_hours: Option<u32>,
}

fn error(source: EvidenceSource, kind: DiagnosticErrorKind) -> DiagnosticError {
    DiagnosticError { source, kind }
}

fn parse_projection<T: DeserializeOwned>(
    input: EvidenceInput<'_>,
    source: EvidenceSource,
) -> Result<T, DiagnosticError> {
    if !valid_evidence_id(input.id) {
        return Err(error(source, DiagnosticErrorKind::InvalidEvidenceId));
    }
    if input.body.is_empty() {
        return Err(error(source, DiagnosticErrorKind::EmptyInput));
    }
    if input.body.len() > MAX_INPUT_BYTES {
        return Err(error(source, DiagnosticErrorKind::InputTooLarge));
    }
    serde_json::from_slice(input.body)
        .map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))
}

fn valid_evidence_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.starts_with(b"E-")
        && bytes.len() > 2
        && bytes.len() <= MAX_EVIDENCE_ID_BYTES
        && bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn require_complete(
    source: EvidenceSource,
    schema_version: &str,
    complete: bool,
) -> Result<(), DiagnosticError> {
    if schema_version != PROJECTION_SCHEMA_VERSION {
        return Err(error(source, DiagnosticErrorKind::UnsupportedSchema));
    }
    if !complete {
        return Err(error(source, DiagnosticErrorKind::PartialEvidence));
    }
    Ok(())
}

pub fn parse_storage(input: EvidenceInput<'_>) -> Result<StorageProjection, DiagnosticError> {
    let projection: StorageProjection = parse_projection(input, EvidenceSource::Storage)?;
    require_complete(
        EvidenceSource::Storage,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.devices.is_empty() {
        return Err(error(
            EvidenceSource::Storage,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    if projection.devices.len() > MAX_RECORDS {
        return Err(error(
            EvidenceSource::Storage,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    Ok(projection)
}

pub fn parse_apfs(input: EvidenceInput<'_>) -> Result<ApfsProjection, DiagnosticError> {
    let projection: ApfsProjection = parse_projection(input, EvidenceSource::Apfs)?;
    require_complete(
        EvidenceSource::Apfs,
        &projection.schema_version,
        projection.query_complete,
    )?;
    let root = &projection.root_data_volume;
    if projection.container_count == 0
        || root.capacity_bytes == 0
        || root.free_bytes > root.capacity_bytes
        || root.purgeable_bytes > root.capacity_bytes
    {
        return Err(error(
            EvidenceSource::Apfs,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    if projection.container_count as usize > MAX_RECORDS {
        return Err(error(
            EvidenceSource::Apfs,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    Ok(projection)
}

pub fn parse_launchd(input: EvidenceInput<'_>) -> Result<LaunchdProjection, DiagnosticError> {
    let projection: LaunchdProjection = parse_projection(input, EvidenceSource::Launchd)?;
    require_complete(
        EvidenceSource::Launchd,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.services.is_empty() {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    if projection.services.len() > MAX_RECORDS {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    if projection
        .services
        .iter()
        .any(|service| service.consecutive_failures > 1_000_000)
    {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::ValueOutOfRange,
        ));
    }
    Ok(projection)
}

pub fn parse_network(input: EvidenceInput<'_>) -> Result<NetworkProjection, DiagnosticError> {
    let projection: NetworkProjection = parse_projection(input, EvidenceSource::Network)?;
    require_complete(
        EvidenceSource::Network,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.active_interfaces > 128 || projection.dns_servers > 64 {
        return Err(error(
            EvidenceSource::Network,
            DiagnosticErrorKind::ValueOutOfRange,
        ));
    }
    if projection.active_interfaces == 0 && projection.default_route_present {
        return Err(error(
            EvidenceSource::Network,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    Ok(projection)
}

pub fn parse_updates(input: EvidenceInput<'_>) -> Result<UpdatesProjection, DiagnosticError> {
    let projection: UpdatesProjection = parse_projection(input, EvidenceSource::Updates)?;
    require_complete(
        EvidenceSource::Updates,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.pending.len() > 512 {
        return Err(error(
            EvidenceSource::Updates,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    Ok(projection)
}

pub fn parse_events(input: EvidenceInput<'_>) -> Result<EventsProjection, DiagnosticError> {
    let projection: EventsProjection = parse_projection(input, EvidenceSource::Events)?;
    require_complete(
        EvidenceSource::Events,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.window_hours == 0
        || projection.window_hours > 168
        || projection.kernel_panics > 100_000
        || projection.watchdog_reboots > 100_000
        || projection.repeated_app_crashes > 1_000_000
    {
        return Err(error(
            EvidenceSource::Events,
            DiagnosticErrorKind::ValueOutOfRange,
        ));
    }
    Ok(projection)
}

pub fn parse_startup(input: EvidenceInput<'_>) -> Result<StartupProjection, DiagnosticError> {
    let projection: StartupProjection = parse_projection(input, EvidenceSource::Startup)?;
    require_complete(
        EvidenceSource::Startup,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.third_party_login_items_enabled as usize > MAX_RECORDS
        || projection.background_items_blocked as usize > MAX_RECORDS
    {
        return Err(error(
            EvidenceSource::Startup,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    Ok(projection)
}

pub fn parse_snapshots(input: EvidenceInput<'_>) -> Result<SnapshotsProjection, DiagnosticError> {
    let projection: SnapshotsProjection = parse_projection(input, EvidenceSource::Snapshots)?;
    require_complete(
        EvidenceSource::Snapshots,
        &projection.schema_version,
        projection.query_complete,
    )?;
    if projection.local_snapshots > 100_000
        || projection
            .oldest_age_hours
            .is_some_and(|hours| hours > 24 * 3650)
    {
        return Err(error(
            EvidenceSource::Snapshots,
            DiagnosticErrorKind::ValueOutOfRange,
        ));
    }
    if (projection.local_snapshots == 0) != projection.oldest_age_hours.is_none() {
        return Err(error(
            EvidenceSource::Snapshots,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    Ok(projection)
}

fn finding(
    rule_id: &str,
    severity: Severity,
    evidence_ids: &[&str],
    summary: &str,
    next_collector: &str,
) -> Finding {
    Finding {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        severity,
        evidence_ids: evidence_ids
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        summary: summary.to_owned(),
        next_collector: next_collector.to_owned(),
    }
}

fn low_space(root: &RootDataVolume) -> bool {
    root.free_bytes < 2 * 1024 * 1024 * 1024
        || u128::from(root.free_bytes) * 100 <= u128::from(root.capacity_bytes) * 5
}

fn ensure_unique_evidence_ids(inputs: MacosP0Inputs<'_>) -> Result<(), DiagnosticError> {
    let evidence = [
        (EvidenceSource::Storage, inputs.storage.id),
        (EvidenceSource::Apfs, inputs.apfs.id),
        (EvidenceSource::Launchd, inputs.launchd.id),
        (EvidenceSource::Network, inputs.network.id),
        (EvidenceSource::Updates, inputs.updates.id),
        (EvidenceSource::Events, inputs.events.id),
        (EvidenceSource::Startup, inputs.startup.id),
        (EvidenceSource::Snapshots, inputs.snapshots.id),
    ];
    let mut seen = BTreeSet::new();
    for (source, id) in evidence {
        if !seen.insert(id) {
            return Err(error(source, DiagnosticErrorKind::DuplicateEvidenceId));
        }
    }
    Ok(())
}

pub fn diagnose_macos_p0(inputs: MacosP0Inputs<'_>) -> Result<DiagnosticReport, DiagnosticError> {
    // Parse every required source before evaluating a single rule. This is the
    // fail-closed completeness boundary: no partial report can be produced.
    let storage = parse_storage(inputs.storage)?;
    let apfs = parse_apfs(inputs.apfs)?;
    let launchd = parse_launchd(inputs.launchd)?;
    let network = parse_network(inputs.network)?;
    let updates = parse_updates(inputs.updates)?;
    let events = parse_events(inputs.events)?;
    let startup = parse_startup(inputs.startup)?;
    let snapshots = parse_snapshots(inputs.snapshots)?;
    ensure_unique_evidence_ids(inputs)?;

    let mut findings = Vec::new();

    if storage
        .devices
        .iter()
        .any(|device| device.internal && device.smart_status == SmartStatus::Failing)
    {
        findings.push(finding(
            "macos.storage.smart-failing",
            Severity::Critical,
            &[inputs.storage.id],
            "An internal storage device reports a failing hardware-health state.",
            "macos.apple-diagnostics.handoff",
        ));
    }
    if !storage.devices.iter().any(|device| device.internal) {
        findings.push(finding(
            "macos.storage.internal-device-unreported",
            Severity::Medium,
            &[inputs.storage.id],
            "The complete storage projection did not report an internal device.",
            "macos.storage.native-detail",
        ));
    }

    let root_low_space = low_space(&apfs.root_data_volume);
    if root_low_space {
        findings.push(finding(
            "macos.apfs.root-low-space",
            Severity::High,
            &[inputs.apfs.id],
            "The root APFS data volume has critically low free space.",
            "macos.storage.space-breakdown",
        ));
    }
    if root_low_space && snapshots.local_snapshots >= 10 {
        findings.push(finding(
            "macos.apfs.snapshot-pressure-correlation",
            Severity::Medium,
            &[inputs.apfs.id, inputs.snapshots.id],
            "Low root-volume space coincides with a substantial local snapshot inventory.",
            "macos.snapshots.native-detail",
        ));
    }

    if launchd
        .services
        .iter()
        .any(|service| service.state == LaunchdState::Failed || service.consecutive_failures >= 3)
    {
        findings.push(finding(
            "macos.launchd.repeated-failure",
            Severity::High,
            &[inputs.launchd.id],
            "At least one launchd service is failed or repeatedly exiting.",
            "macos.launchd.failure-detail",
        ));
    } else if launchd
        .services
        .iter()
        .any(|service| service.state == LaunchdState::Throttled && service.last_exit_status != 0)
    {
        findings.push(finding(
            "macos.launchd.throttled-after-error",
            Severity::Medium,
            &[inputs.launchd.id],
            "At least one launchd service is throttled after a nonzero exit.",
            "macos.launchd.failure-detail",
        ));
    }

    if network.active_interfaces == 0 {
        findings.push(finding(
            "macos.network.no-active-interface",
            Severity::Medium,
            &[inputs.network.id],
            "No active non-loopback network interface was observed.",
            "macos.network.interface-detail",
        ));
    } else if !network.default_route_present {
        findings.push(finding(
            "macos.network.default-route-missing",
            Severity::High,
            &[inputs.network.id],
            "Active networking was observed without a default route.",
            "macos.network.route-detail",
        ));
    } else if network.dns_servers == 0 {
        findings.push(finding(
            "macos.network.dns-unconfigured",
            Severity::Medium,
            &[inputs.network.id],
            "A default route exists but no DNS resolver is configured.",
            "macos.network.dns-detail",
        ));
    }

    if updates.pending.iter().any(|update| update.security) {
        findings.push(finding(
            "macos.software-update.security-pending",
            Severity::Medium,
            &[inputs.updates.id],
            "At least one pending software update is security-relevant.",
            "macos.software-update.native-detail",
        ));
    }
    if updates.pending.iter().any(|update| update.restart_required) {
        findings.push(finding(
            "macos.software-update.restart-pending",
            Severity::Low,
            &[inputs.updates.id],
            "At least one pending software update requires a restart.",
            "macos.software-update.native-detail",
        ));
    }

    if events.kernel_panics > 0 {
        findings.push(finding(
            "macos.events.kernel-panic-observed",
            Severity::Critical,
            &[inputs.events.id],
            "The bounded unified-event window contains a kernel panic signal.",
            "macos.apple-diagnostics.handoff",
        ));
    }
    if events.watchdog_reboots > 0 {
        findings.push(finding(
            "macos.events.watchdog-reboot-observed",
            Severity::High,
            &[inputs.events.id],
            "The bounded unified-event window contains a watchdog reboot signal.",
            "macos.events.shutdown-detail",
        ));
    }
    if events.repeated_app_crashes >= 3 {
        findings.push(finding(
            "macos.events.repeated-app-crash",
            Severity::Medium,
            &[inputs.events.id],
            "The bounded event window contains a repeated application-crash signal.",
            "macos.events.crash-detail",
        ));
    }

    if startup.safe_mode {
        findings.push(finding(
            "macos.startup.safe-mode-active",
            Severity::Low,
            &[inputs.startup.id],
            "The current macOS session is running in safe mode.",
            "macos.startup.normal-boot-compare",
        ));
    }
    if startup.background_items_blocked > 0 {
        findings.push(finding(
            "macos.startup.background-items-blocked",
            Severity::Low,
            &[inputs.startup.id],
            "At least one configured background item is blocked.",
            "macos.startup.login-item-detail",
        ));
    }
    if startup.third_party_login_items_enabled >= 25 {
        findings.push(finding(
            "macos.startup.login-item-volume-high",
            Severity::Low,
            &[inputs.startup.id],
            "The enabled third-party login-item count exceeds the P0 review threshold.",
            "macos.startup.login-item-detail",
        ));
    }

    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    Ok(DiagnosticReport {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        corpus_version: CORPUS_VERSION.to_owned(),
        mode: "macos-resident-read-only".to_owned(),
        complete: true,
        evidence_ids: [
            inputs.storage.id,
            inputs.apfs.id,
            inputs.launchd.id,
            inputs.network.id,
            inputs.updates.id,
            inputs.events.id,
            inputs.startup.id,
            inputs.snapshots.id,
        ]
        .iter()
        .map(|value| (*value).to_owned())
        .collect(),
        findings,
        scope_statement: "Complete means all eight bounded P0 projections were parsed; it is not a health certification.".to_owned(),
    })
}

pub fn proposal_from_report(report: &DiagnosticReport) -> MacosDiagnosisProposal {
    let requested_evidence = report
        .findings
        .iter()
        .map(|finding| finding.next_collector.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (diagnosis, confidence) = if report.findings.is_empty() {
        (
            "No deterministic macOS P0 incident rule matched the complete evidence set; this is not a health certification.".to_owned(),
            0.55,
        )
    } else {
        (
            format!(
                "{} deterministic macOS P0 signal(s) require review.",
                report.findings.len()
            ),
            0.9,
        )
    };
    MacosDiagnosisProposal {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        diagnosis,
        confidence,
        evidence_ids: report.evidence_ids.clone(),
        requested_evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORAGE_EVIDENCE_ID: &str = "E-SESSION-42-STORAGE";
    const APFS_EVIDENCE_ID: &str = "E-SESSION-42-APFS";
    const LAUNCHD_EVIDENCE_ID: &str = "E-SESSION-42-LAUNCHD";
    const NETWORK_EVIDENCE_ID: &str = "E-SESSION-42-NETWORK";
    const UPDATES_EVIDENCE_ID: &str = "E-SESSION-42-UPDATES";
    const EVENTS_EVIDENCE_ID: &str = "E-SESSION-42-EVENTS";
    const STARTUP_EVIDENCE_ID: &str = "E-SESSION-42-STARTUP";
    const SNAPSHOTS_EVIDENCE_ID: &str = "E-SESSION-42-SNAPSHOTS";
    const REQUIRED_EVIDENCE_IDS: [&str; 8] = [
        STORAGE_EVIDENCE_ID,
        APFS_EVIDENCE_ID,
        LAUNCHD_EVIDENCE_ID,
        NETWORK_EVIDENCE_ID,
        UPDATES_EVIDENCE_ID,
        EVENTS_EVIDENCE_ID,
        STARTUP_EVIDENCE_ID,
        SNAPSHOTS_EVIDENCE_ID,
    ];

    fn healthy_inputs() -> MacosP0Inputs<'static> {
        MacosP0Inputs {
            storage: EvidenceInput {
                id: STORAGE_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/storage.json"),
            },
            apfs: EvidenceInput {
                id: APFS_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/apfs.json"),
            },
            launchd: EvidenceInput {
                id: LAUNCHD_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/launchd.json"),
            },
            network: EvidenceInput {
                id: NETWORK_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/network.json"),
            },
            updates: EvidenceInput {
                id: UPDATES_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/updates.json"),
            },
            events: EvidenceInput {
                id: EVENTS_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/events.json"),
            },
            startup: EvidenceInput {
                id: STARTUP_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/startup.json"),
            },
            snapshots: EvidenceInput {
                id: SNAPSHOTS_EVIDENCE_ID,
                body: include_bytes!("../fixtures/diagnostics/healthy/snapshots.json"),
            },
        }
    }

    #[test]
    fn complete_no_match_report_is_not_a_health_claim() {
        let report = diagnose_macos_p0(healthy_inputs()).expect("complete fixture parses");
        assert!(report.complete);
        assert!(report.findings.is_empty());
        assert_eq!(report.evidence_ids, REQUIRED_EVIDENCE_IDS);
        let proposal = proposal_from_report(&report);
        assert!(proposal.diagnosis.contains("not a health certification"));
        assert!(proposal.requested_evidence.is_empty());
    }

    #[test]
    fn valid_dynamic_id_is_accepted_and_invalid_id_is_rejected() {
        parse_storage(EvidenceInput {
            id: "E-ANOTHER-SESSION-9001",
            body: include_bytes!("../fixtures/diagnostics/healthy/storage.json"),
        })
        .expect("valid caller evidence ID");
        let result = parse_storage(EvidenceInput {
            id: "MACOS-STORAGE",
            body: include_bytes!("../fixtures/diagnostics/healthy/storage.json"),
        });
        assert_eq!(
            result.expect_err("invalid ID must fail").kind,
            DiagnosticErrorKind::InvalidEvidenceId
        );
    }

    #[test]
    fn duplicate_dynamic_ids_fail_the_complete_report() {
        let mut inputs = healthy_inputs();
        inputs.snapshots.id = inputs.storage.id;
        let diagnostic_error =
            diagnose_macos_p0(inputs).expect_err("duplicate evidence IDs must fail");
        assert_eq!(
            diagnostic_error.kind,
            DiagnosticErrorKind::DuplicateEvidenceId
        );
        assert_eq!(diagnostic_error.source, EvidenceSource::Snapshots);
    }

    #[test]
    fn partial_projection_fails_before_any_report() {
        let mut inputs = healthy_inputs();
        inputs.network = EvidenceInput {
            id: NETWORK_EVIDENCE_ID,
            body: br#"{"schemaVersion":"1.0","queryComplete":false,"activeInterfaces":1,"defaultRoutePresent":true,"dnsServers":2}"#,
        };
        assert_eq!(
            diagnose_macos_p0(inputs)
                .expect_err("partial evidence must fail")
                .kind,
            DiagnosticErrorKind::PartialEvidence
        );
    }

    #[test]
    fn malformed_and_unknown_fields_fail_closed() {
        let unknown = br#"{"schemaVersion":"1.0","queryComplete":true,"activeInterfaces":1,"defaultRoutePresent":true,"dnsServers":2,"claim":"healthy"}"#;
        assert_eq!(
            parse_network(EvidenceInput {
                id: NETWORK_EVIDENCE_ID,
                body: unknown,
            })
            .expect_err("unknown field must fail")
            .kind,
            DiagnosticErrorKind::MalformedInput
        );
        let invalid = br#"{"schemaVersion":"1.0""#;
        assert_eq!(
            parse_network(EvidenceInput {
                id: NETWORK_EVIDENCE_ID,
                body: invalid,
            })
            .expect_err("malformed JSON must fail")
            .kind,
            DiagnosticErrorKind::MalformedInput
        );
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
        assert_eq!(
            parse_storage(EvidenceInput {
                id: STORAGE_EVIDENCE_ID,
                body: &oversized,
            })
            .expect_err("oversized evidence must fail")
            .kind,
            DiagnosticErrorKind::InputTooLarge
        );
    }

    #[test]
    fn cross_source_incidents_produce_only_fixed_findings() {
        let mut inputs = healthy_inputs();
        inputs.storage = EvidenceInput {
            id: STORAGE_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/storage-failing.json"),
        };
        inputs.apfs = EvidenceInput {
            id: APFS_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/apfs-low-space.json"),
        };
        inputs.snapshots = EvidenceInput {
            id: SNAPSHOTS_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/snapshots-many.json"),
        };
        inputs.events = EvidenceInput {
            id: EVENTS_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/events-panic.json"),
        };
        let report = diagnose_macos_p0(inputs).expect("incident fixture parses");
        let rules = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rules,
            vec![
                "macos.apfs.root-low-space",
                "macos.apfs.snapshot-pressure-correlation",
                "macos.events.kernel-panic-observed",
                "macos.storage.smart-failing",
            ]
        );
        let smart = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "macos.storage.smart-failing")
            .expect("SMART finding");
        assert_eq!(smart.evidence_ids, vec![STORAGE_EVIDENCE_ID]);
        let snapshot = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "macos.apfs.snapshot-pressure-correlation")
            .expect("snapshot correlation finding");
        assert_eq!(
            snapshot.evidence_ids,
            vec![APFS_EVIDENCE_ID, SNAPSHOTS_EVIDENCE_ID]
        );
        let serialized = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.contains("prompt"));
        assert!(!serialized.contains("device_name"));
    }

    #[test]
    fn service_network_update_event_and_startup_corpus_is_deterministic() {
        let mut inputs = healthy_inputs();
        inputs.launchd = EvidenceInput {
            id: LAUNCHD_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/launchd-failures.json"),
        };
        inputs.network = EvidenceInput {
            id: NETWORK_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/network-route-missing.json"),
        };
        inputs.updates = EvidenceInput {
            id: UPDATES_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/updates-pending.json"),
        };
        inputs.events = EvidenceInput {
            id: EVENTS_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/events-instability.json"),
        };
        inputs.startup = EvidenceInput {
            id: STARTUP_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/startup-safe-mode.json"),
        };
        let report = diagnose_macos_p0(inputs).expect("incident corpus parses");
        let rules = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rules,
            vec![
                "macos.events.repeated-app-crash",
                "macos.events.watchdog-reboot-observed",
                "macos.launchd.repeated-failure",
                "macos.network.default-route-missing",
                "macos.software-update.restart-pending",
                "macos.software-update.security-pending",
                "macos.startup.background-items-blocked",
                "macos.startup.login-item-volume-high",
                "macos.startup.safe-mode-active",
            ]
        );
        let proposal = proposal_from_report(&report);
        let mut sorted = proposal.requested_evidence.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(proposal.requested_evidence, sorted);
    }

    #[test]
    fn adversarial_projection_text_cannot_enter_a_report() {
        let error = parse_storage(EvidenceInput {
            id: STORAGE_EVIDENCE_ID,
            body: include_bytes!(
                "../fixtures/diagnostics/adversarial/storage-prompt-injection.json"
            ),
        })
        .expect_err("unknown untrusted string must be rejected");
        assert_eq!(error.kind, DiagnosticErrorKind::MalformedInput);

        let error = parse_apfs(EvidenceInput {
            id: APFS_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/adversarial/apfs-inconsistent.json"),
        })
        .expect_err("inconsistent capacity must be rejected");
        assert_eq!(error.kind, DiagnosticErrorKind::InconsistentEvidence);
    }

    #[test]
    fn snapshot_count_and_age_must_be_coherent() {
        let missing_age = br#"{"schemaVersion":"1.0","queryComplete":true,"localSnapshots":1,"oldestAgeHours":null}"#;
        assert_eq!(
            parse_snapshots(EvidenceInput {
                id: SNAPSHOTS_EVIDENCE_ID,
                body: missing_age,
            })
            .expect_err("nonzero count needs an age")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );
        let spurious_age = br#"{"schemaVersion":"1.0","queryComplete":true,"localSnapshots":0,"oldestAgeHours":1}"#;
        assert_eq!(
            parse_snapshots(EvidenceInput {
                id: SNAPSHOTS_EVIDENCE_ID,
                body: spurious_age,
            })
            .expect_err("zero count cannot have an age")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );
    }

    #[test]
    fn equivalent_record_order_has_identical_report_bytes() {
        let one = br#"{"schemaVersion":"1.0","queryComplete":true,"services":[{"scope":"user","state":"waiting","lastExitStatus":0,"consecutiveFailures":0,"appleSigned":false},{"scope":"system","state":"running","lastExitStatus":0,"consecutiveFailures":0,"appleSigned":true}]}"#;
        let two = br#"{"schemaVersion":"1.0","queryComplete":true,"services":[{"scope":"system","state":"running","lastExitStatus":0,"consecutiveFailures":0,"appleSigned":true},{"scope":"user","state":"waiting","lastExitStatus":0,"consecutiveFailures":0,"appleSigned":false}]}"#;
        let mut left_inputs = healthy_inputs();
        left_inputs.launchd = EvidenceInput {
            id: LAUNCHD_EVIDENCE_ID,
            body: one,
        };
        let mut right_inputs = healthy_inputs();
        right_inputs.launchd = EvidenceInput {
            id: LAUNCHD_EVIDENCE_ID,
            body: two,
        };
        let left = diagnose_macos_p0(left_inputs).expect("left report");
        let right = diagnose_macos_p0(right_inputs).expect("right report");
        assert_eq!(
            serde_json::to_vec(&left).expect("serialize left"),
            serde_json::to_vec(&right).expect("serialize right")
        );
    }
}
