//! Deterministic, read-only Windows Resident/WinPE P0 diagnostic corpus.
//!
//! Every parser consumes caller-supplied bytes from one fixed collector
//! contract. The module never spawns a process, opens a host path, or changes
//! state. Observed strings are untrusted and are never copied into summaries,
//! rule identifiers, or next-collector identifiers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::{error::Error, fmt};

pub const CORPUS_VERSION: &str = "windows-p0.1";
pub const FINDING_SCHEMA_VERSION: &str = "1.0";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_EVIDENCE_ID_BYTES: usize = 128;
pub const LOOKBACK_HOURS: u16 = 168;

#[derive(Clone, Copy)]
pub struct EvidenceInput<'a> {
    pub id: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct WindowsP0Inputs<'a> {
    pub event_log_json: EvidenceInput<'a>,
    pub reliability_json: EvidenceInput<'a>,
    pub component_store_json: EvidenceInput<'a>,
    pub sfc_json: EvidenceInput<'a>,
    pub update_json: EvidenceInput<'a>,
    pub services_json: EvidenceInput<'a>,
    pub network_json: EvidenceInput<'a>,
    pub drivers_json: EvidenceInput<'a>,
    pub bitlocker_json: EvidenceInput<'a>,
    pub boot_json: EvidenceInput<'a>,
    pub volumes_json: EvidenceInput<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    EventLog,
    Reliability,
    ComponentStore,
    SfcVerify,
    Update,
    Services,
    Network,
    Drivers,
    Bitlocker,
    Boot,
    Volumes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticErrorKind {
    InvalidEvidenceId,
    DuplicateEvidenceId,
    InputTooLarge,
    MalformedInput,
    UnsafeControlCharacter,
    StringTooLong,
    TooManyRecords,
    ValueOutOfRange,
    InconsistentSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticError {
    pub source: EvidenceSource,
    pub kind: DiagnosticErrorKind,
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DiagnosticErrorKind::InvalidEvidenceId => "invalid diagnostic evidence identifier",
            DiagnosticErrorKind::DuplicateEvidenceId => {
                "diagnostic evidence identifiers must be unique"
            }
            DiagnosticErrorKind::InputTooLarge => "diagnostic input exceeds its byte limit",
            DiagnosticErrorKind::MalformedInput => "diagnostic input is malformed",
            DiagnosticErrorKind::UnsafeControlCharacter => {
                "diagnostic input contains a forbidden control character"
            }
            DiagnosticErrorKind::StringTooLong => "diagnostic string exceeds its byte limit",
            DiagnosticErrorKind::TooManyRecords => "diagnostic input has too many records",
            DiagnosticErrorKind::ValueOutOfRange => "diagnostic value is out of range",
            DiagnosticErrorKind::InconsistentSnapshot => {
                "diagnostic snapshot contains inconsistent observations"
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
    pub corpus_version: String,
    pub evaluation: String,
    pub evidence_ids: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsDiagnosisProposal {
    pub schema_version: String,
    pub diagnosis: String,
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
    pub requested_evidence: Vec<String>,
}

fn error(source: EvidenceSource, kind: DiagnosticErrorKind) -> DiagnosticError {
    DiagnosticError { source, kind }
}

fn validate_input<'a>(
    input: EvidenceInput<'a>,
    source: EvidenceSource,
) -> Result<&'a [u8], DiagnosticError> {
    if !valid_evidence_id(input.id) {
        return Err(error(source, DiagnosticErrorKind::InvalidEvidenceId));
    }
    if input.body.is_empty() {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    if input.body.len() > MAX_INPUT_BYTES {
        return Err(error(source, DiagnosticErrorKind::InputTooLarge));
    }
    Ok(input.body)
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

fn parse_json<'a, T: Deserialize<'a>>(
    input: EvidenceInput<'a>,
    source: EvidenceSource,
) -> Result<T, DiagnosticError> {
    let body = validate_input(input, source)?;
    serde_json::from_slice(body).map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))
}

fn validate_string(
    source: EvidenceSource,
    value: &str,
    maximum: usize,
) -> Result<(), DiagnosticError> {
    if value.len() > maximum {
        return Err(error(source, DiagnosticErrorKind::StringTooLong));
    }
    if value.chars().any(char::is_control) {
        return Err(error(source, DiagnosticErrorKind::UnsafeControlCharacter));
    }
    Ok(())
}

fn validate_nonempty_string(
    source: EvidenceSource,
    value: &str,
    maximum: usize,
) -> Result<(), DiagnosticError> {
    validate_string(source, value, maximum)?;
    if value.trim().is_empty() {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    Ok(())
}

fn validate_token<F>(
    source: EvidenceSource,
    value: &str,
    maximum: usize,
    allowed: F,
) -> Result<(), DiagnosticError>
where
    F: Fn(u8) -> bool,
{
    validate_nonempty_string(source, value, maximum)?;
    if !value.bytes().all(allowed) {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    Ok(())
}

fn validate_rfc3339_utc(source: EvidenceSource, value: &str) -> Result<(), DiagnosticError> {
    validate_string(source, value, 20)?;
    let bytes = value.as_bytes();
    let separators = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if bytes.len() != 20
        || separators
            .iter()
            .any(|(index, byte)| bytes[*index] != *byte)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !separators.iter().any(|(separator, _)| *separator == index) && !byte.is_ascii_digit()
        })
    {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    let number = |start: usize, end: usize| -> Option<u16> {
        std::str::from_utf8(&bytes[start..end]).ok()?.parse().ok()
    };
    let (Some(year), Some(month), Some(day)) = (number(0, 4), number(5, 7), number(8, 10)) else {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if !(1601..=9999).contains(&year)
        || day == 0
        || day > maximum_day
        || !matches!(number(11, 13), Some(0..=23))
        || !matches!(number(14, 16), Some(0..=59))
        || !matches!(number(17, 19), Some(0..=60))
    {
        return Err(error(source, DiagnosticErrorKind::ValueOutOfRange));
    }
    Ok(())
}

fn validate_hresult(source: EvidenceSource, value: &str) -> Result<(), DiagnosticError> {
    if value.len() != 10
        || !value.starts_with("0x")
        || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    Ok(())
}

fn validate_guid(source: EvidenceSource, value: &str) -> Result<(), DiagnosticError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || [8, 13, 18, 23].iter().any(|index| bytes[*index] != b'-')
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| ![8, 13, 18, 23].contains(&index) && !byte.is_ascii_hexdigit())
    {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    Ok(())
}

fn bounded_records<T>(source: EvidenceSource, records: &[T]) -> Result<(), DiagnosticError> {
    if records.len() > MAX_RECORDS {
        return Err(error(source, DiagnosticErrorKind::TooManyRecords));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub enum EventLevel {
    Critical,
    Error,
    Warning,
    Information,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventRecord {
    pub log_name: String,
    pub record_id: u64,
    pub provider_name: String,
    pub event_id: u32,
    pub level: EventLevel,
    pub timestamp_utc: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventLogSnapshot {
    pub lookback_hours: u16,
    pub query_complete: bool,
    pub records: Vec<EventRecord>,
}

pub fn parse_event_log(input: EvidenceInput<'_>) -> Result<EventLogSnapshot, DiagnosticError> {
    let source = EvidenceSource::EventLog;
    let snapshot: EventLogSnapshot = parse_json(input, source)?;
    if !snapshot.query_complete {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.lookback_hours != LOOKBACK_HOURS {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.records)?;
    let mut records = BTreeSet::new();
    for record in &snapshot.records {
        if !record.log_name.eq_ignore_ascii_case("System")
            && !record.log_name.eq_ignore_ascii_case("Application")
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        validate_token(source, &record.log_name, 128, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })?;
        validate_nonempty_string(source, &record.provider_name, 256)?;
        if record.event_id > 65535 {
            return Err(error(source, DiagnosticErrorKind::ValueOutOfRange));
        }
        validate_rfc3339_utc(source, &record.timestamp_utc)?;
        if !records.insert((record.log_name.to_ascii_lowercase(), record.record_id)) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub enum ReliabilityRecordType {
    ApplicationFailure,
    WindowsFailure,
    HardwareFailure,
    Informational,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReliabilityRecord {
    pub log_file: String,
    pub record_number: u32,
    pub source_name: String,
    pub product_name: Option<String>,
    pub record_type: ReliabilityRecordType,
    pub timestamp_utc: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReliabilitySnapshot {
    pub lookback_hours: u16,
    pub query_state: QueryState,
    pub records: Vec<ReliabilityRecord>,
}

pub fn parse_reliability(input: EvidenceInput<'_>) -> Result<ReliabilitySnapshot, DiagnosticError> {
    let source = EvidenceSource::Reliability;
    let snapshot: ReliabilitySnapshot = parse_json(input, source)?;
    if snapshot.lookback_hours != LOOKBACK_HOURS {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.records)?;
    if snapshot.query_state == QueryState::Unavailable && !snapshot.records.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    let mut records = BTreeSet::new();
    for record in &snapshot.records {
        validate_nonempty_string(source, &record.log_file, 256)?;
        validate_nonempty_string(source, &record.source_name, 256)?;
        if let Some(product_name) = &record.product_name {
            validate_nonempty_string(source, product_name, 256)?;
        }
        validate_rfc3339_utc(source, &record.timestamp_utc)?;
        if !records.insert((
            record.log_file.to_ascii_lowercase(),
            record.record_number,
            record.timestamp_utc.as_str(),
        )) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentStoreState {
    Healthy,
    Repairable,
    NonRepairable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentStoreSnapshot {
    pub check_mode: String,
    pub state: ComponentStoreState,
    pub exit_code: i32,
    pub reboot_required: bool,
}

pub fn parse_component_store(
    input: EvidenceInput<'_>,
) -> Result<ComponentStoreSnapshot, DiagnosticError> {
    let source = EvidenceSource::ComponentStore;
    let snapshot: ComponentStoreSnapshot = parse_json(input, source)?;
    if snapshot.check_mode != "check-health-read-only" {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.state == ComponentStoreState::Healthy && snapshot.exit_code != 0 {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SfcState {
    Clean,
    Violations,
    CouldNotVerify,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SfcSnapshot {
    pub mode: String,
    pub state: SfcState,
    pub exit_code: i32,
}

pub fn parse_sfc(input: EvidenceInput<'_>) -> Result<SfcSnapshot, DiagnosticError> {
    let source = EvidenceSource::SfcVerify;
    let snapshot: SfcSnapshot = parse_json(input, source)?;
    if snapshot.mode != "verify-only" {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.state == SfcState::Clean && snapshot.exit_code != 0 {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateScanState {
    Complete,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailedUpdate {
    pub update_id: String,
    pub hresult: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSnapshot {
    pub history_lookback_hours: u16,
    pub scan_state: UpdateScanState,
    pub pending_reboot: bool,
    pub cbs_reboot_pending: bool,
    pub windows_update_reboot_pending: bool,
    pub pending_file_rename_operations: bool,
    pub last_successful_scan_utc: Option<String>,
    pub failed_updates: Vec<FailedUpdate>,
}

pub fn parse_update(input: EvidenceInput<'_>) -> Result<UpdateSnapshot, DiagnosticError> {
    let source = EvidenceSource::Update;
    let snapshot: UpdateSnapshot = parse_json(input, source)?;
    bounded_records(source, &snapshot.failed_updates)?;
    if snapshot.history_lookback_hours != LOOKBACK_HOURS {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.scan_state == UpdateScanState::Complete
        && snapshot.last_successful_scan_utc.is_none()
    {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if let Some(timestamp) = &snapshot.last_successful_scan_utc {
        validate_rfc3339_utc(source, timestamp)?;
    }
    let mut ids = BTreeSet::new();
    for update in &snapshot.failed_updates {
        validate_guid(source, &update.update_id)?;
        validate_hresult(source, &update.hresult)?;
        if !ids.insert(update.update_id.to_ascii_lowercase()) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceStartMode {
    Boot,
    System,
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    Running,
    Stopped,
    StartPending,
    StopPending,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRecord {
    pub name: String,
    pub start_mode: ServiceStartMode,
    pub state: ServiceState,
    pub win32_exit_code: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicesSnapshot {
    pub snapshot_complete: bool,
    pub services: Vec<ServiceRecord>,
}

pub fn parse_services(input: EvidenceInput<'_>) -> Result<ServicesSnapshot, DiagnosticError> {
    let source = EvidenceSource::Services;
    let snapshot: ServicesSnapshot = parse_json(input, source)?;
    if !snapshot.snapshot_complete || snapshot.services.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.services)?;
    let mut names = BTreeSet::new();
    for service in &snapshot.services {
        validate_token(source, &service.name, 256, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'$')
        })?;
        if !names.insert(service.name.to_ascii_lowercase()) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum AdapterStatus {
    Up,
    Down,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkAdapter {
    pub interface_index: u32,
    pub status: AdapterStatus,
    pub hardware_interface: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteRecord {
    pub destination_prefix: String,
    pub interface_index: u32,
    pub next_hop: String,
    pub route_metric: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsRecord {
    pub interface_index: u32,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkSnapshot {
    pub snapshot_complete: bool,
    pub adapters: Vec<NetworkAdapter>,
    pub routes: Vec<RouteRecord>,
    pub dns_servers: Vec<DnsRecord>,
}

fn validate_prefix(source: EvidenceSource, value: &str) -> Result<(IpAddr, u8), DiagnosticError> {
    let Some((address, prefix)) = value.split_once('/') else {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(error(source, DiagnosticErrorKind::ValueOutOfRange));
    }
    let canonical_network = match address {
        IpAddr::V4(address) => {
            let raw = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            raw & mask == raw
        }
        IpAddr::V6(address) => {
            let raw = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            raw & mask == raw
        }
    };
    if !canonical_network {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    Ok((address, prefix))
}

fn is_default_prefix(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    prefix.parse::<u8>() == Ok(0)
        && address
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_unspecified())
}

pub fn parse_network(input: EvidenceInput<'_>) -> Result<NetworkSnapshot, DiagnosticError> {
    let source = EvidenceSource::Network;
    let snapshot: NetworkSnapshot = parse_json(input, source)?;
    if !snapshot.snapshot_complete {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.adapters)?;
    bounded_records(source, &snapshot.routes)?;
    bounded_records(source, &snapshot.dns_servers)?;
    let mut indices = BTreeSet::new();
    for adapter in &snapshot.adapters {
        if adapter.interface_index == 0 || !indices.insert(adapter.interface_index) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    let mut routes = BTreeSet::new();
    for route in &snapshot.routes {
        let (destination, prefix) = validate_prefix(source, &route.destination_prefix)?;
        let next_hop = route
            .next_hop
            .parse::<IpAddr>()
            .map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))?;
        if destination.is_ipv4() != next_hop.is_ipv4()
            || next_hop.is_multicast()
            || !indices.contains(&route.interface_index)
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        if !routes.insert((
            destination,
            prefix,
            route.interface_index,
            next_hop,
            route.route_metric,
        )) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    let mut dns_indices = BTreeSet::new();
    for record in &snapshot.dns_servers {
        if !indices.contains(&record.interface_index)
            || !dns_indices.insert(record.interface_index)
            || record.addresses.len() > 64
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        let mut addresses = BTreeSet::new();
        for address in &record.addresses {
            let parsed = address
                .parse::<IpAddr>()
                .map_err(|_| error(source, DiagnosticErrorKind::MalformedInput))?;
            if parsed.is_unspecified() || parsed.is_multicast() || !addresses.insert(parsed) {
                return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
            }
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum DriverStatus {
    Ok,
    Error,
    Degraded,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriverRecord {
    pub device_id: String,
    pub status: DriverStatus,
    pub problem_code: u16,
    pub signed: bool,
    pub driver_version: String,
    pub driver_date_utc: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Driver,
    Update,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentChange {
    pub kind: ChangeKind,
    pub identifier: String,
    pub installed_at_utc: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriversSnapshot {
    pub change_lookback_hours: u16,
    pub snapshot_complete: bool,
    pub drivers: Vec<DriverRecord>,
    pub recent_changes: Vec<RecentChange>,
}

pub fn parse_drivers(input: EvidenceInput<'_>) -> Result<DriversSnapshot, DiagnosticError> {
    let source = EvidenceSource::Drivers;
    let snapshot: DriversSnapshot = parse_json(input, source)?;
    if !snapshot.snapshot_complete || snapshot.drivers.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.change_lookback_hours != LOOKBACK_HOURS {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.drivers)?;
    bounded_records(source, &snapshot.recent_changes)?;
    let mut ids = BTreeSet::new();
    for driver in &snapshot.drivers {
        validate_nonempty_string(source, &driver.device_id, 512)?;
        validate_token(source, &driver.driver_version, 128, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })?;
        validate_rfc3339_utc(source, &driver.driver_date_utc)?;
        if driver.problem_code > 255 || !ids.insert(driver.device_id.to_ascii_lowercase()) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    let mut changes = BTreeSet::new();
    for change in &snapshot.recent_changes {
        validate_nonempty_string(source, &change.identifier, 512)?;
        validate_rfc3339_utc(source, &change.installed_at_utc)?;
        if !changes.insert((
            change.kind,
            change.identifier.to_ascii_lowercase(),
            change.installed_at_utc.as_str(),
        )) {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QueryState {
    Complete,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum VolumeType {
    OperatingSystem,
    FixedData,
    RemovableData,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ProtectionStatus {
    On,
    Off,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum LockStatus {
    Unlocked,
    Locked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConversionStatus {
    FullyEncrypted,
    EncryptionInProgress,
    EncryptionPaused,
    DecryptionInProgress,
    DecryptionPaused,
    FullyDecrypted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitlockerVolume {
    pub mount_point: String,
    pub volume_type: VolumeType,
    pub protection_status: ProtectionStatus,
    pub lock_status: LockStatus,
    pub conversion_status: ConversionStatus,
    pub encryption_percentage: u8,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitlockerSnapshot {
    pub query_state: QueryState,
    pub volumes: Vec<BitlockerVolume>,
}

fn validate_mount_point(source: EvidenceSource, value: &str) -> Result<(), DiagnosticError> {
    let bytes = value.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return Err(error(source, DiagnosticErrorKind::MalformedInput));
    }
    Ok(())
}

pub fn parse_bitlocker(input: EvidenceInput<'_>) -> Result<BitlockerSnapshot, DiagnosticError> {
    let source = EvidenceSource::Bitlocker;
    let snapshot: BitlockerSnapshot = parse_json(input, source)?;
    bounded_records(source, &snapshot.volumes)?;
    if snapshot.query_state == QueryState::Complete && snapshot.volumes.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.query_state == QueryState::Unavailable && !snapshot.volumes.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    let mut mount_points = BTreeSet::new();
    let mut operating_system_volumes = 0_usize;
    for volume in &snapshot.volumes {
        validate_mount_point(source, &volume.mount_point)?;
        if volume.encryption_percentage > 100
            || !mount_points.insert(volume.mount_point.to_ascii_uppercase())
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        let coherent_conversion = match volume.conversion_status {
            ConversionStatus::FullyEncrypted => volume.encryption_percentage == 100,
            ConversionStatus::FullyDecrypted => volume.encryption_percentage == 0,
            ConversionStatus::EncryptionInProgress
            | ConversionStatus::EncryptionPaused
            | ConversionStatus::DecryptionInProgress
            | ConversionStatus::DecryptionPaused => true,
            ConversionStatus::Unknown => true,
        };
        if !coherent_conversion
            || (volume.protection_status == ProtectionStatus::On
                && volume.conversion_status == ConversionStatus::FullyDecrypted)
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        if volume.volume_type == VolumeType::OperatingSystem {
            operating_system_volumes += 1;
        }
    }
    if snapshot.query_state == QueryState::Complete && operating_system_volumes != 1 {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum FirmwareType {
    Uefi,
    Bios,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootSnapshot {
    pub query_state: QueryState,
    pub firmware_type: Option<FirmwareType>,
    pub windows_boot_manager_present: Option<bool>,
    pub os_loader_count: Option<u16>,
    pub default_loader_present: Option<bool>,
}

pub fn parse_boot(input: EvidenceInput<'_>) -> Result<BootSnapshot, DiagnosticError> {
    let source = EvidenceSource::Boot;
    let snapshot: BootSnapshot = parse_json(input, source)?;
    let complete = snapshot.firmware_type.is_some()
        && snapshot.windows_boot_manager_present.is_some()
        && snapshot.os_loader_count.is_some()
        && snapshot.default_loader_present.is_some();
    if (snapshot.query_state == QueryState::Complete) != complete {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    if snapshot.os_loader_count.is_some_and(|count| count > 256) {
        return Err(error(source, DiagnosticErrorKind::ValueOutOfRange));
    }
    Ok(snapshot)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VolumeRecord {
    pub drive_letter: String,
    pub file_system: String,
    pub capacity_bytes: u64,
    pub free_bytes: u64,
    pub system_volume: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VolumesSnapshot {
    pub snapshot_complete: bool,
    pub volumes: Vec<VolumeRecord>,
}

pub fn parse_volumes(input: EvidenceInput<'_>) -> Result<VolumesSnapshot, DiagnosticError> {
    let source = EvidenceSource::Volumes;
    let snapshot: VolumesSnapshot = parse_json(input, source)?;
    if !snapshot.snapshot_complete || snapshot.volumes.is_empty() {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    bounded_records(source, &snapshot.volumes)?;
    let mut drive_letters = BTreeSet::new();
    let mut system_volumes = 0_usize;
    for volume in &snapshot.volumes {
        validate_mount_point(source, &volume.drive_letter)?;
        validate_token(source, &volume.file_system, 32, |byte| {
            byte.is_ascii_alphanumeric() || byte == b'-'
        })?;
        if volume.capacity_bytes == 0
            || volume.free_bytes > volume.capacity_bytes
            || !drive_letters.insert(volume.drive_letter.to_ascii_uppercase())
        {
            return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
        }
        if volume.system_volume {
            system_volumes += 1;
        }
    }
    if system_volumes != 1 {
        return Err(error(source, DiagnosticErrorKind::InconsistentSnapshot));
    }
    Ok(snapshot)
}

fn finding(
    rule_id: &str,
    severity: Severity,
    evidence_ids: &[&str],
    summary: &str,
    next_collector: &str,
) -> Finding {
    Finding {
        schema_version: FINDING_SCHEMA_VERSION.to_owned(),
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

pub fn diagnose_windows_p0(
    inputs: WindowsP0Inputs<'_>,
) -> Result<DiagnosticReport, DiagnosticError> {
    let supplied_ids = [
        (EvidenceSource::EventLog, inputs.event_log_json.id),
        (EvidenceSource::Reliability, inputs.reliability_json.id),
        (
            EvidenceSource::ComponentStore,
            inputs.component_store_json.id,
        ),
        (EvidenceSource::SfcVerify, inputs.sfc_json.id),
        (EvidenceSource::Update, inputs.update_json.id),
        (EvidenceSource::Services, inputs.services_json.id),
        (EvidenceSource::Network, inputs.network_json.id),
        (EvidenceSource::Drivers, inputs.drivers_json.id),
        (EvidenceSource::Bitlocker, inputs.bitlocker_json.id),
        (EvidenceSource::Boot, inputs.boot_json.id),
        (EvidenceSource::Volumes, inputs.volumes_json.id),
    ];
    let mut unique_ids = BTreeSet::new();
    for (source, id) in supplied_ids.iter().copied() {
        if !unique_ids.insert(id) {
            return Err(error(source, DiagnosticErrorKind::DuplicateEvidenceId));
        }
    }

    let events = parse_event_log(inputs.event_log_json)?;
    let reliability = parse_reliability(inputs.reliability_json)?;
    let component = parse_component_store(inputs.component_store_json)?;
    let sfc = parse_sfc(inputs.sfc_json)?;
    let update = parse_update(inputs.update_json)?;
    let services = parse_services(inputs.services_json)?;
    let network = parse_network(inputs.network_json)?;
    let drivers = parse_drivers(inputs.drivers_json)?;
    let bitlocker = parse_bitlocker(inputs.bitlocker_json)?;
    let boot = parse_boot(inputs.boot_json)?;
    let volumes = parse_volumes(inputs.volumes_json)?;

    if bitlocker.query_state == QueryState::Complete {
        let Some(bitlocker_os_volume) = bitlocker
            .volumes
            .iter()
            .find(|volume| volume.volume_type == VolumeType::OperatingSystem)
        else {
            return Err(error(
                EvidenceSource::Bitlocker,
                DiagnosticErrorKind::InconsistentSnapshot,
            ));
        };
        let Some(system_volume) = volumes.volumes.iter().find(|volume| volume.system_volume) else {
            return Err(error(
                EvidenceSource::Volumes,
                DiagnosticErrorKind::InconsistentSnapshot,
            ));
        };
        if !bitlocker_os_volume
            .mount_point
            .eq_ignore_ascii_case(&system_volume.drive_letter)
        {
            return Err(error(
                EvidenceSource::Bitlocker,
                DiagnosticErrorKind::InconsistentSnapshot,
            ));
        }
    }

    let mut findings = Vec::new();
    let critical_events = events
        .records
        .iter()
        .filter(|record| record.level == EventLevel::Critical)
        .count();
    let error_events = events
        .records
        .iter()
        .filter(|record| record.level == EventLevel::Error)
        .count();
    if critical_events > 0 {
        findings.push(finding(
            "windows.event-log.critical",
            Severity::High,
            &[inputs.event_log_json.id],
            "The bounded system event window contains one or more critical events.",
            "windows.event-log.correlated-details",
        ));
    } else if error_events >= 3 {
        findings.push(finding(
            "windows.event-log.repeated-errors",
            Severity::Medium,
            &[inputs.event_log_json.id],
            "The bounded system event window contains repeated error-level events.",
            "windows.event-log.correlated-details",
        ));
    }

    if reliability.query_state == QueryState::Unavailable {
        findings.push(finding(
            "windows.reliability.unavailable",
            Severity::Low,
            &[inputs.reliability_json.id],
            "Windows Reliability history was unavailable to the fixed collector.",
            "windows.reliability.records",
        ));
    } else if reliability
        .records
        .iter()
        .any(|record| record.record_type == ReliabilityRecordType::HardwareFailure)
    {
        findings.push(finding(
            "windows.reliability.hardware-failure",
            Severity::High,
            &[inputs.reliability_json.id],
            "Reliability history reports at least one hardware-failure record.",
            "windows.hardware.extended-inventory",
        ));
    } else if reliability.records.iter().any(|record| {
        matches!(
            record.record_type,
            ReliabilityRecordType::ApplicationFailure | ReliabilityRecordType::WindowsFailure
        )
    }) {
        findings.push(finding(
            "windows.reliability.failures",
            Severity::Medium,
            &[inputs.reliability_json.id],
            "Reliability history reports an application or Windows failure.",
            "windows.reliability.correlated-details",
        ));
    }

    match component.state {
        ComponentStoreState::Healthy => {}
        ComponentStoreState::Repairable => findings.push(finding(
            "windows.component-store.repairable",
            Severity::Medium,
            &[inputs.component_store_json.id],
            "The component-store check reports repairable corruption.",
            "windows.component-store.scan-health",
        )),
        ComponentStoreState::NonRepairable => findings.push(finding(
            "windows.component-store.non-repairable",
            Severity::High,
            &[inputs.component_store_json.id],
            "The component-store check reports non-repairable corruption.",
            "windows.component-store.recovery-options",
        )),
        ComponentStoreState::Unknown => findings.push(finding(
            "windows.component-store.unknown",
            Severity::Medium,
            &[inputs.component_store_json.id],
            "The component-store state could not be determined.",
            "windows.component-store.scan-health",
        )),
    }
    if component.reboot_required {
        findings.push(finding(
            "windows.component-store.reboot-required",
            Severity::Medium,
            &[inputs.component_store_json.id],
            "The component-store observation reports a pending restart.",
            "windows.update.pending-actions-details",
        ));
    }

    match sfc.state {
        SfcState::Clean => {}
        SfcState::Violations => findings.push(finding(
            "windows.sfc.integrity-violations",
            Severity::High,
            &[inputs.sfc_json.id],
            "Read-only system-file verification reports integrity violations.",
            "windows.sfc.verification-details",
        )),
        SfcState::CouldNotVerify => findings.push(finding(
            "windows.sfc.inconclusive",
            Severity::Medium,
            &[inputs.sfc_json.id],
            "Read-only system-file verification could not complete.",
            "windows.sfc.verification-details",
        )),
    }

    if update.pending_reboot
        || update.cbs_reboot_pending
        || update.windows_update_reboot_pending
        || update.pending_file_rename_operations
    {
        findings.push(finding(
            "windows.update.reboot-pending",
            Severity::Medium,
            &[inputs.update_json.id],
            "One or more normalized Windows restart-pending signals are present.",
            "windows.update.pending-actions-details",
        ));
    }
    if !update.failed_updates.is_empty() {
        findings.push(finding(
            "windows.update.failed",
            Severity::Medium,
            &[inputs.update_json.id],
            "The bounded update history contains one or more failed updates.",
            "windows.update.failure-details",
        ));
    }
    if update.scan_state == UpdateScanState::Unavailable {
        findings.push(finding(
            "windows.update.scan-unavailable",
            Severity::Low,
            &[inputs.update_json.id],
            "Windows Update scan state was unavailable to the fixed collector.",
            "windows.update.scan-state",
        ));
    }

    if services.services.iter().any(|service| {
        matches!(
            service.start_mode,
            ServiceStartMode::Automatic | ServiceStartMode::AutomaticDelayed
        ) && matches!(service.state, ServiceState::Stopped | ServiceState::Unknown)
    }) {
        findings.push(finding(
            "windows.services.automatic-not-running",
            Severity::Medium,
            &[inputs.services_json.id],
            "At least one automatically started service is not in the running state.",
            "windows.services.failure-details",
        ));
    }
    if services
        .services
        .iter()
        .any(|service| service.win32_exit_code != 0)
    {
        findings.push(finding(
            "windows.services.nonzero-exit",
            Severity::Medium,
            &[inputs.services_json.id],
            "At least one service reports a non-zero Win32 exit code.",
            "windows.services.failure-details",
        ));
    }
    let up_hardware = network
        .adapters
        .iter()
        .filter(|adapter| adapter.hardware_interface && adapter.status == AdapterStatus::Up)
        .map(|adapter| adapter.interface_index)
        .collect::<BTreeSet<_>>();
    if up_hardware.is_empty() {
        findings.push(finding(
            "windows.network.no-up-hardware-adapter",
            Severity::Medium,
            &[inputs.network_json.id],
            "No physical network adapter is observed in the Up state.",
            "windows.network.adapter-details",
        ));
    } else {
        let default_route = network.routes.iter().any(|route| {
            is_default_prefix(&route.destination_prefix)
                && up_hardware.contains(&route.interface_index)
        });
        if !default_route {
            findings.push(finding(
                "windows.network.default-route-missing",
                Severity::Medium,
                &[inputs.network_json.id],
                "No default route is bound to an Up physical adapter.",
                "windows.network.route-details",
            ));
        }
        let dns_present = network.dns_servers.iter().any(|record| {
            up_hardware.contains(&record.interface_index) && !record.addresses.is_empty()
        });
        if !dns_present {
            findings.push(finding(
                "windows.network.dns-missing",
                Severity::Medium,
                &[inputs.network_json.id],
                "No DNS server is bound to an Up physical adapter.",
                "windows.network.dns-details",
            ));
        }
    }

    if drivers
        .drivers
        .iter()
        .any(|driver| driver.problem_code != 0 || driver.status != DriverStatus::Ok)
    {
        findings.push(finding(
            "windows.drivers.problem",
            Severity::High,
            &[inputs.drivers_json.id],
            "At least one present device driver reports a problem state.",
            "windows.drivers.problem-details",
        ));
        if !drivers.recent_changes.is_empty() {
            findings.push(finding(
                "windows.drivers.problem-with-recent-change",
                Severity::High,
                &[inputs.drivers_json.id],
                "A driver problem and at least one recent driver or update change coexist; causality is not established.",
                "windows.drivers.change-correlation",
            ));
        }
    }
    if drivers.drivers.iter().any(|driver| !driver.signed) {
        findings.push(finding(
            "windows.drivers.unsigned",
            Severity::Medium,
            &[inputs.drivers_json.id],
            "At least one present device driver is reported as unsigned.",
            "windows.drivers.signature-details",
        ));
    }

    if bitlocker.query_state == QueryState::Unavailable {
        findings.push(finding(
            "windows.bitlocker.unavailable",
            Severity::Low,
            &[inputs.bitlocker_json.id],
            "BitLocker protection state was unavailable; no recovery material was requested.",
            "windows.bitlocker.protection-state",
        ));
    } else if let Some(os_volume) = bitlocker
        .volumes
        .iter()
        .find(|volume| volume.volume_type == VolumeType::OperatingSystem)
    {
        match os_volume.conversion_status {
            ConversionStatus::FullyEncrypted => {}
            ConversionStatus::EncryptionInProgress => findings.push(finding(
                "windows.bitlocker.os-encryption-in-progress",
                Severity::Low,
                &[inputs.bitlocker_json.id],
                "BitLocker encryption of the operating-system volume is still in progress.",
                "windows.bitlocker.conversion-state",
            )),
            ConversionStatus::EncryptionPaused => findings.push(finding(
                "windows.bitlocker.os-encryption-paused",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "BitLocker encryption of the operating-system volume is paused.",
                "windows.bitlocker.conversion-state",
            )),
            ConversionStatus::DecryptionInProgress => findings.push(finding(
                "windows.bitlocker.os-decryption-in-progress",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "BitLocker decryption of the operating-system volume is in progress.",
                "windows.bitlocker.conversion-state",
            )),
            ConversionStatus::DecryptionPaused => findings.push(finding(
                "windows.bitlocker.os-decryption-paused",
                Severity::High,
                &[inputs.bitlocker_json.id],
                "BitLocker decryption of the operating-system volume is paused.",
                "windows.bitlocker.conversion-state",
            )),
            ConversionStatus::FullyDecrypted => findings.push(finding(
                "windows.bitlocker.os-fully-decrypted",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "The operating-system volume is reported as fully decrypted.",
                "windows.bitlocker.conversion-state",
            )),
            ConversionStatus::Unknown => findings.push(finding(
                "windows.bitlocker.os-conversion-unknown",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "BitLocker conversion state for the operating-system volume is inconclusive.",
                "windows.bitlocker.conversion-state",
            )),
        }
        if os_volume.protection_status != ProtectionStatus::On
            || matches!(
                os_volume.conversion_status,
                ConversionStatus::FullyDecrypted
                    | ConversionStatus::DecryptionInProgress
                    | ConversionStatus::DecryptionPaused
            )
        {
            findings.push(finding(
                "windows.bitlocker.os-protection-off",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "The operating-system volume is not observed with active BitLocker protection.",
                "windows.bitlocker.protection-state",
            ));
        }
        if os_volume.lock_status != LockStatus::Unlocked {
            findings.push(finding(
                "windows.bitlocker.os-lock-state",
                Severity::Medium,
                &[inputs.bitlocker_json.id],
                "The operating-system volume lock state is not reported as unlocked.",
                "windows.bitlocker.lock-state",
            ));
        }
    }
    if bitlocker.volumes.iter().any(|volume| {
        volume.volume_type != VolumeType::OperatingSystem
            && volume.conversion_status == ConversionStatus::Unknown
    }) {
        findings.push(finding(
            "windows.bitlocker.data-conversion-unknown",
            Severity::Medium,
            &[inputs.bitlocker_json.id],
            "BitLocker conversion state for at least one data volume is inconclusive.",
            "windows.bitlocker.conversion-state",
        ));
    }
    if bitlocker.volumes.iter().any(|volume| {
        volume.volume_type != VolumeType::OperatingSystem
            && volume.conversion_status == ConversionStatus::EncryptionPaused
    }) {
        findings.push(finding(
            "windows.bitlocker.data-encryption-paused",
            Severity::Medium,
            &[inputs.bitlocker_json.id],
            "BitLocker encryption is paused on at least one data volume.",
            "windows.bitlocker.conversion-state",
        ));
    }
    if bitlocker.volumes.iter().any(|volume| {
        volume.volume_type != VolumeType::OperatingSystem
            && volume.conversion_status == ConversionStatus::DecryptionPaused
    }) {
        findings.push(finding(
            "windows.bitlocker.data-decryption-paused",
            Severity::High,
            &[inputs.bitlocker_json.id],
            "BitLocker decryption is paused on at least one data volume.",
            "windows.bitlocker.conversion-state",
        ));
    }

    if boot.query_state == QueryState::Unavailable {
        findings.push(finding(
            "windows.boot.query-unavailable",
            Severity::Medium,
            &[inputs.boot_json.id],
            "The normalized boot configuration could not be inspected.",
            "windows.boot.configuration-details",
        ));
    } else if boot.windows_boot_manager_present != Some(true)
        || boot.default_loader_present != Some(true)
        || boot.os_loader_count == Some(0)
    {
        findings.push(finding(
            "windows.boot.configuration-incomplete",
            Severity::High,
            &[inputs.boot_json.id],
            "The normalized Windows boot configuration is incomplete.",
            "windows.boot.configuration-details",
        ));
    }

    const TWO_GIB: u64 = 2 * 1024 * 1024 * 1024;
    if volumes.volumes.iter().any(|volume| {
        volume.system_volume
            && (volume.free_bytes < TWO_GIB
                || u128::from(volume.free_bytes) * 100 / u128::from(volume.capacity_bytes) < 10)
    }) {
        findings.push(finding(
            "windows.volumes.system-low-space",
            Severity::High,
            &[inputs.volumes_json.id],
            "The system volume has less than ten percent or two GiB of free space.",
            "windows.volumes.usage-details",
        ));
    }

    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    Ok(DiagnosticReport {
        corpus_version: CORPUS_VERSION.to_owned(),
        evaluation: "complete".to_owned(),
        evidence_ids: supplied_ids
            .iter()
            .map(|(_, value)| (*value).to_owned())
            .collect(),
        findings,
    })
}

pub fn proposal_from_report(report: &DiagnosticReport) -> WindowsDiagnosisProposal {
    let evidence_ids = if report.findings.is_empty() {
        report.evidence_ids.clone()
    } else {
        report
            .findings
            .iter()
            .flat_map(|finding| finding.evidence_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let requested_evidence = report
        .findings
        .iter()
        .map(|finding| finding.next_collector.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let diagnosis = if report.findings.is_empty() {
        "The complete Windows P0 evidence set matched no deterministic incident rule.".to_owned()
    } else {
        let details = report
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.rule_id, finding.summary))
            .collect::<Vec<_>>()
            .join(" ");
        format!("Deterministic Windows P0 findings: {details}")
    };
    let confidence = match report.findings.iter().map(|finding| finding.severity).max() {
        Some(Severity::Critical) => 0.95,
        Some(Severity::High) => 0.88,
        Some(Severity::Medium) => 0.75,
        Some(Severity::Low) => 0.65,
        None => 0.60,
    };
    WindowsDiagnosisProposal {
        schema_version: FINDING_SCHEMA_VERSION.to_owned(),
        diagnosis,
        confidence,
        evidence_ids,
        requested_evidence,
    }
}
