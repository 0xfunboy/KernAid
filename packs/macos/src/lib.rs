#![forbid(unsafe_code)]
//! Deterministic, read-only macOS Resident P0 diagnostics.
//!
//! This crate only parses already-collected, normalized evidence bytes. It
//! cannot spawn a process, open a host path, or mutate the machine. All
//! observed data is untrusted. Findings contain only fixed text and fixed
//! collector identifiers; observed strings are never copied into a finding.

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, error::Error, fmt};

pub const CORPUS_VERSION: &str = "macos-resident-p0.2";
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CollectionState {
    Complete,
    NotRunUnqualified,
    UnavailableStaleCache,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchdProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub user_query_state: CollectionState,
    pub system_query_state: CollectionState,
    pub services: Vec<LaunchdService>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchdService {
    pub scope: LaunchdScope,
    pub state: LaunchdState,
    #[serde(deserialize_with = "required_option")]
    pub last_exit_status: Option<i32>,
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
    pub execution_state: CollectionState,
    pub query_state: CollectionState,
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
    pub execution_state: CollectionState,
    pub query_state: CollectionState,
    #[serde(deserialize_with = "required_option")]
    pub window_hours: Option<u16>,
    #[serde(deserialize_with = "required_option")]
    pub kernel_panics: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    pub watchdog_reboots: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    pub repeated_app_crashes: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub safe_mode_query_state: CollectionState,
    pub login_items_query_state: CollectionState,
    pub background_items_query_state: CollectionState,
    pub safe_mode: bool,
    #[serde(deserialize_with = "required_option")]
    pub third_party_login_items_enabled: Option<u16>,
    #[serde(deserialize_with = "required_option")]
    pub background_items_blocked: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotsProjection {
    pub schema_version: String,
    pub query_complete: bool,
    pub local_snapshots: u32,
    #[serde(deserialize_with = "required_option")]
    pub oldest_age_hours: Option<u32>,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
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
    if projection.services.len() > MAX_RECORDS {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    if projection.user_query_state != CollectionState::Complete
        || projection.system_query_state != CollectionState::NotRunUnqualified
    {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::InconsistentEvidence,
        ));
    }
    let inconsistent = projection.services.iter().any(|service| {
        service.scope != LaunchdScope::User
            || matches!(service.state, LaunchdState::Running) && service.last_exit_status.is_some()
            || matches!(service.state, LaunchdState::Waiting)
                && service.last_exit_status.is_some_and(|status| status != 0)
            || matches!(service.state, LaunchdState::Failed)
                && service.last_exit_status.is_none_or(|status| status == 0)
    });
    if inconsistent {
        return Err(error(
            EvidenceSource::Launchd,
            DiagnosticErrorKind::InconsistentEvidence,
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
    let explicitly_unqualified = projection.execution_state == CollectionState::NotRunUnqualified
        && projection.query_state == CollectionState::UnavailableStaleCache
        && projection.pending.is_empty();
    if !explicitly_unqualified {
        return Err(error(
            EvidenceSource::Updates,
            DiagnosticErrorKind::InconsistentEvidence,
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
    let explicitly_unqualified = projection.execution_state == CollectionState::NotRunUnqualified
        && projection.query_state == CollectionState::NotRunUnqualified;
    let counts = (
        projection.window_hours,
        projection.kernel_panics,
        projection.watchdog_reboots,
        projection.repeated_app_crashes,
    );
    let values_valid = matches!(counts, (None, None, None, None)) && explicitly_unqualified;
    if !values_valid {
        return Err(error(
            EvidenceSource::Events,
            DiagnosticErrorKind::InconsistentEvidence,
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
    let explicitly_unqualified = projection.safe_mode_query_state == CollectionState::Complete
        && projection.login_items_query_state == CollectionState::NotRunUnqualified
        && projection.background_items_query_state == CollectionState::NotRunUnqualified
        && projection.third_party_login_items_enabled.is_none()
        && projection.background_items_blocked.is_none();
    if !explicitly_unqualified {
        return Err(error(
            EvidenceSource::Startup,
            DiagnosticErrorKind::InconsistentEvidence,
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
    parse_updates(inputs.updates)?;
    parse_events(inputs.events)?;
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

    findings.push(finding(
        "macos.launchd.system-scope-not-qualified",
        Severity::Medium,
        &[inputs.launchd.id],
        "System-domain launchd services were not queried because that collector is not qualified for P0.",
        "macos.launchd.system-read-only-qualified",
    ));
    if launchd
        .services
        .iter()
        .any(|service| service.last_exit_status.is_some_and(|status| status != 0))
    {
        findings.push(finding(
            "macos.launchd.last-exit-nonzero",
            Severity::Medium,
            &[inputs.launchd.id],
            "At least one service in a queried launchd scope has a nonzero last exit status.",
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

    findings.push(finding(
        "macos.software-update.query-not-qualified",
        Severity::Medium,
        &[inputs.updates.id],
        "Software-update availability was not queried because the cached preference data is not a qualified freshness source.",
        "macos.software-update.read-only-qualified",
    ));

    findings.push(finding(
        "macos.events.query-not-qualified",
        Severity::Medium,
        &[inputs.events.id],
        "System incidents were not queried because process-name-only Unified Log counts are not qualified evidence.",
        "macos.events.read-only-qualified",
    ));

    findings.push(finding(
        "macos.startup.items-scope-not-qualified",
        Severity::Medium,
        &[inputs.startup.id],
        "Login-item and background-item state was not queried because the available text source is not qualified evidence.",
        "macos.startup.items-read-only-qualified",
    ));

    if startup.safe_mode {
        findings.push(finding(
            "macos.startup.safe-mode-active",
            Severity::Low,
            &[inputs.startup.id],
            "The current macOS session is running in safe mode.",
            "macos.startup.normal-boot-compare",
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
        scope_statement: "Complete means all eight bounded P0 projection documents and their declared query states were parsed. System launchd, software-update, system-event, login-item, and background-item scopes remain explicitly unqualified; this is not a health certification.".to_owned(),
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
    let has_unqualified_scope = report
        .findings
        .iter()
        .any(|finding| finding.rule_id.ends_with("not-qualified"));
    let (diagnosis, confidence) = if report.findings.is_empty() {
        (
            "No deterministic macOS P0 incident rule matched the complete evidence set; this is not a health certification.".to_owned(),
            0.55,
        )
    } else if has_unqualified_scope {
        (
            format!(
                "{} deterministic macOS P0 signal(s), including explicitly unqualified diagnostic scopes, require review; this is not a health certification.",
                report.findings.len()
            ),
            0.65,
        )
    } else {
        (
            format!(
                "{} deterministic macOS P0 signal(s) require review; this is not a health certification.",
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
    fn complete_projection_set_surfaces_every_unqualified_scope() {
        let report = diagnose_macos_p0(healthy_inputs()).expect("complete fixture parses");
        assert!(report.complete);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "macos.events.query-not-qualified",
                "macos.launchd.system-scope-not-qualified",
                "macos.software-update.query-not-qualified",
                "macos.startup.items-scope-not-qualified",
            ]
        );
        assert_eq!(report.evidence_ids, REQUIRED_EVIDENCE_IDS);
        assert!(report.scope_statement.contains("login-item"));
        assert!(report.scope_statement.contains("background-item"));
        let proposal = proposal_from_report(&report);
        assert!(proposal.diagnosis.contains("not a health certification"));
        assert_eq!(proposal.confidence, 0.65);
        assert_eq!(proposal.requested_evidence.len(), 4);
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
    fn nullable_projection_fields_are_still_required() {
        let launchd = br#"{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{"scope":"user","state":"running"}]}"#;
        assert_eq!(
            parse_launchd(EvidenceInput {
                id: LAUNCHD_EVIDENCE_ID,
                body: launchd,
            })
            .expect_err("launchd null state must be explicit")
            .kind,
            DiagnosticErrorKind::MalformedInput
        );

        let events = br#"{"schemaVersion":"1.0","queryComplete":true,"executionState":"not-run-unqualified","queryState":"not-run-unqualified","windowHours":null,"kernelPanics":null,"watchdogReboots":null}"#;
        assert_eq!(
            parse_events(EvidenceInput {
                id: EVENTS_EVIDENCE_ID,
                body: events,
            })
            .expect_err("every unqualified event metric must be explicit")
            .kind,
            DiagnosticErrorKind::MalformedInput
        );

        let startup = br#"{"schemaVersion":"1.0","queryComplete":true,"safeModeQueryState":"complete","loginItemsQueryState":"not-run-unqualified","backgroundItemsQueryState":"not-run-unqualified","safeMode":false,"thirdPartyLoginItemsEnabled":null}"#;
        assert_eq!(
            parse_startup(EvidenceInput {
                id: STARTUP_EVIDENCE_ID,
                body: startup,
            })
            .expect_err("every unqualified startup metric must be explicit")
            .kind,
            DiagnosticErrorKind::MalformedInput
        );

        let snapshots = br#"{"schemaVersion":"1.0","queryComplete":true,"localSnapshots":0}"#;
        assert_eq!(
            parse_snapshots(EvidenceInput {
                id: SNAPSHOTS_EVIDENCE_ID,
                body: snapshots,
            })
            .expect_err("snapshot age null must be explicit")
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
                "macos.events.query-not-qualified",
                "macos.launchd.system-scope-not-qualified",
                "macos.software-update.query-not-qualified",
                "macos.startup.items-scope-not-qualified",
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
    fn qualified_collectors_and_unqualified_scopes_are_deterministic() {
        let mut inputs = healthy_inputs();
        inputs.launchd = EvidenceInput {
            id: LAUNCHD_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/launchd-failures.json"),
        };
        inputs.network = EvidenceInput {
            id: NETWORK_EVIDENCE_ID,
            body: include_bytes!("../fixtures/diagnostics/incidents/network-route-missing.json"),
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
                "macos.events.query-not-qualified",
                "macos.launchd.last-exit-nonzero",
                "macos.launchd.system-scope-not-qualified",
                "macos.network.default-route-missing",
                "macos.software-update.query-not-qualified",
                "macos.startup.items-scope-not-qualified",
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
        let one = br#"{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{"scope":"user","state":"waiting","lastExitStatus":0},{"scope":"user","state":"running","lastExitStatus":null}]}"#;
        let two = br#"{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{"scope":"user","state":"running","lastExitStatus":null},{"scope":"user","state":"waiting","lastExitStatus":0}]}"#;
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

    #[test]
    fn unqualified_sources_cannot_smuggle_interpreted_values() {
        let updates = br#"{"schemaVersion":"1.0","queryComplete":true,"executionState":"not-run-unqualified","queryState":"unavailable-stale-cache","pending":[{"security":true,"restartRequired":true}]}"#;
        assert_eq!(
            parse_updates(EvidenceInput {
                id: UPDATES_EVIDENCE_ID,
                body: updates,
            })
            .expect_err("unqualified update query cannot carry pending claims")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );

        let events = br#"{"schemaVersion":"1.0","queryComplete":true,"executionState":"not-run-unqualified","queryState":"not-run-unqualified","windowHours":24,"kernelPanics":1,"watchdogReboots":0,"repeatedAppCrashes":0}"#;
        assert_eq!(
            parse_events(EvidenceInput {
                id: EVENTS_EVIDENCE_ID,
                body: events,
            })
            .expect_err("unqualified event query cannot carry incident counts")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );

        let launchd = br#"{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{"scope":"system","state":"running","lastExitStatus":null}]}"#;
        assert_eq!(
            parse_launchd(EvidenceInput {
                id: LAUNCHD_EVIDENCE_ID,
                body: launchd,
            })
            .expect_err("unqualified launchd scope cannot carry services")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );

        let qualified_updates = br#"{"schemaVersion":"1.0","queryComplete":true,"executionState":"complete","queryState":"complete","pending":[]}"#;
        assert_eq!(
            parse_updates(EvidenceInput {
                id: UPDATES_EVIDENCE_ID,
                body: qualified_updates,
            })
            .expect_err("P0 has no qualified update source")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );

        let qualified_events = br#"{"schemaVersion":"1.0","queryComplete":true,"executionState":"complete","queryState":"complete","windowHours":24,"kernelPanics":0,"watchdogReboots":0,"repeatedAppCrashes":0}"#;
        assert_eq!(
            parse_events(EvidenceInput {
                id: EVENTS_EVIDENCE_ID,
                body: qualified_events,
            })
            .expect_err("P0 has no qualified incident source")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );

        let startup_counts = br#"{"schemaVersion":"1.0","queryComplete":true,"safeModeQueryState":"complete","loginItemsQueryState":"not-run-unqualified","backgroundItemsQueryState":"not-run-unqualified","safeMode":false,"thirdPartyLoginItemsEnabled":3,"backgroundItemsBlocked":0}"#;
        assert_eq!(
            parse_startup(EvidenceInput {
                id: STARTUP_EVIDENCE_ID,
                body: startup_counts,
            })
            .expect_err("unqualified startup item scopes cannot carry counts")
            .kind,
            DiagnosticErrorKind::InconsistentEvidence
        );
    }

    #[test]
    fn launchd_state_and_optional_exit_status_must_be_coherent() {
        for (state, status) in [
            ("running", "0"),
            ("waiting", "78"),
            ("failed", "null"),
            ("failed", "0"),
        ] {
            let projection = format!(
                r#"{{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{{"scope":"user","state":"{state}","lastExitStatus":{status}}}]}}"#
            );
            assert_eq!(
                parse_launchd(EvidenceInput {
                    id: LAUNCHD_EVIDENCE_ID,
                    body: projection.as_bytes(),
                })
                .expect_err("launchd state cannot invent or contradict exit status")
                .kind,
                DiagnosticErrorKind::InconsistentEvidence
            );
        }

        for (state, status) in [
            ("running", "null"),
            ("waiting", "null"),
            ("waiting", "0"),
            ("failed", "-15"),
        ] {
            let projection = format!(
                r#"{{"schemaVersion":"1.0","queryComplete":true,"userQueryState":"complete","systemQueryState":"not-run-unqualified","services":[{{"scope":"user","state":"{state}","lastExitStatus":{status}}}]}}"#
            );
            parse_launchd(EvidenceInput {
                id: LAUNCHD_EVIDENCE_ID,
                body: projection.as_bytes(),
            })
            .expect("documented launchctl state must be accepted");
        }
    }
}
