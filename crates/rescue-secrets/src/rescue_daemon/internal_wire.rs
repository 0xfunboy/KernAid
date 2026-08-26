//! Closed parent/worker transport for the privileged vault lifecycle.
//!
//! The wire is fixed-size binary data. It contains no pathname, secret,
//! command string, diagnostic text, or JSON. The sole permitted descriptor is
//! one anonymous pipe on commands with an exact input or output body. Frames
//! carry only closed enums, numeric bounds, UUID bytes and SHA-256 bytes; JSON,
//! paths, report bodies and credentials travel only through those pipes. With
//! the separate experimental Codex-home feature, one successful response may
//! instead carry the already validated `O_PATH` home-directory descriptor.

use kernaid_protocol::rescue_vault::{
    AuditEventType, AuditOutcome, ErrorToken, MAX_AUDIT_SEQUENCE, MAX_OPENAI_KEY_BYTES,
    MAX_PASSPHRASE_BYTES, MAX_REPORTS_PER_RESPONSE, MAX_SESSION_REPORT_JSON_BYTES,
    MAX_SIGNED_REPORT_ENVELOPE_BYTES, MIN_PASSPHRASE_BYTES, ReportId, ReportSummary, RequestId,
    Sha256,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
    },
};
use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

#[cfg(feature = "experimental-codex-home-lease")]
use std::os::fd::AsFd;

const COMMAND_MAGIC: &[u8; 8] = b"KRVWC003";
const RESPONSE_MAGIC: &[u8; 8] = b"KRVWR003";
const COMMAND_BYTES: usize = 128;
const RESPONSE_BYTES: usize = 128;
const MAX_RECORD_BYTES: usize = RESPONSE_BYTES;
const COMMAND_VALUE_OFFSET: usize = 20;
const COMMAND_PEER_UID_OFFSET: usize = 28;
const COMMAND_PEER_PID_OFFSET: usize = 32;
const COMMAND_IDENTIFIER_OFFSET: usize = 36;
const COMMAND_SHA256_OFFSET: usize = 52;
const RESPONSE_VALUE_OFFSET: usize = 20;
const RESPONSE_COUNT_OFFSET: usize = 28;
const RESPONSE_IDENTIFIER_OFFSET: usize = 32;
const RESPONSE_SHA256_OFFSET: usize = 48;
const DEVICE_ID_OFFSET: usize = 80;
const MAX_DEVICE_ID_BYTES: usize = 32;
pub(super) const APPLICATION_REPORT_RECORD_BYTES: usize = 64;
pub(super) const MAX_APPLICATION_REPORT_LIST_BYTES: usize =
    MAX_REPORTS_PER_RESPONSE * APPLICATION_REPORT_RECORD_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum WorkerApplicationCommand {
    AuditAppend {
        request_id: RequestId,
        peer_uid: u32,
        peer_pid: u32,
        sequence: u64,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    },
    ReportPersist {
        report_id: ReportId,
        payload_sha256: [u8; 32],
        input_size: u64,
    },
    ReportList,
    ReportGet {
        report_id: ReportId,
    },
}

impl WorkerApplicationCommand {
    pub(super) const fn kind(&self) -> WorkerCommandKind {
        match self {
            Self::AuditAppend { .. } => WorkerCommandKind::AuditAppend,
            Self::ReportPersist { .. } => WorkerCommandKind::ReportPersist,
            Self::ReportList => WorkerCommandKind::ReportList,
            Self::ReportGet { .. } => WorkerCommandKind::ReportGet,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerCommandKind {
    Bootstrap,
    Probe,
    Unlock,
    Lock,
    ProviderStatus,
    ProviderOpenAiConfigure,
    ProviderOpenAiLogout,
    ProviderOpenAiBorrow,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeLease,
    AuditAppend,
    ReportPersist,
    ReportList,
    ReportGet,
    AttestQuiescent,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerCommand {
    pub(super) request_id: u64,
    pub(super) kind: WorkerCommandKind,
    pub(super) secret_size: u16,
    pub(super) application: Option<WorkerApplicationCommand>,
}

impl WorkerCommand {
    pub(super) fn bootstrap(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Bootstrap,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn probe(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Probe,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn unlock(request_id: u64, passphrase_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Unlock,
            secret_size: passphrase_size,
            application: None,
        }
    }

    pub(super) fn lock(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Lock,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn provider_status(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderStatus,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn provider_openai_configure(request_id: u64, api_key_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiConfigure,
            secret_size: api_key_size,
            application: None,
        }
    }

    pub(super) fn provider_openai_logout(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiLogout,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn provider_openai_borrow(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiBorrow,
            secret_size: 0,
            application: None,
        }
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    pub(super) fn provider_codex_home_lease(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderCodexHomeLease,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn application(request_id: u64, application: WorkerApplicationCommand) -> Self {
        Self {
            request_id,
            kind: application.kind(),
            secret_size: 0,
            application: Some(application),
        }
    }

    pub(super) fn shutdown(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Shutdown,
            secret_size: 0,
            application: None,
        }
    }

    pub(super) fn attest_quiescent(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::AttestQuiescent,
            secret_size: 0,
            application: None,
        }
    }

    fn encode(&self) -> Result<[u8; COMMAND_BYTES], InternalWireError> {
        let application_kind = self
            .application
            .as_ref()
            .map(WorkerApplicationCommand::kind);
        if self.request_id == 0
            || application_kind.is_some_and(|kind| kind != self.kind)
            || (application_kind.is_some() && self.secret_size != 0)
            || (application_kind.is_none()
                && ((self.kind == WorkerCommandKind::Unlock
                    && !valid_passphrase_size(self.secret_size))
                    || (self.kind == WorkerCommandKind::ProviderOpenAiConfigure
                        && !valid_openai_key_size(self.secret_size))
                    || (!matches!(
                        self.kind,
                        WorkerCommandKind::Unlock | WorkerCommandKind::ProviderOpenAiConfigure
                    ) && self.secret_size != 0)
                    || matches!(
                        self.kind,
                        WorkerCommandKind::AuditAppend
                            | WorkerCommandKind::ReportPersist
                            | WorkerCommandKind::ReportList
                            | WorkerCommandKind::ReportGet
                    )))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; COMMAND_BYTES];
        bytes[..8].copy_from_slice(COMMAND_MAGIC);
        bytes[8] = match self.kind {
            WorkerCommandKind::Bootstrap => 1,
            WorkerCommandKind::Probe => 2,
            WorkerCommandKind::Unlock => 3,
            WorkerCommandKind::Lock => 4,
            WorkerCommandKind::Shutdown => 5,
            WorkerCommandKind::AttestQuiescent => 6,
            WorkerCommandKind::ProviderStatus => 7,
            WorkerCommandKind::ProviderOpenAiConfigure => 8,
            WorkerCommandKind::ProviderOpenAiLogout => 9,
            WorkerCommandKind::ProviderOpenAiBorrow => 10,
            #[cfg(feature = "experimental-codex-home-lease")]
            WorkerCommandKind::ProviderCodexHomeLease => 11,
            WorkerCommandKind::AuditAppend => 12,
            WorkerCommandKind::ReportPersist => 13,
            WorkerCommandKind::ReportList => 14,
            WorkerCommandKind::ReportGet => 15,
        };
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        if let Some(application) = &self.application {
            match application {
                WorkerApplicationCommand::AuditAppend {
                    request_id,
                    peer_uid,
                    peer_pid,
                    sequence,
                    event,
                    outcome,
                    error,
                } => {
                    if *peer_uid == 0
                        || *peer_pid == 0
                        || !(1..=MAX_AUDIT_SEQUENCE).contains(sequence)
                        || ((*outcome == AuditOutcome::Succeeded && error.is_some())
                            || (*outcome != AuditOutcome::Succeeded && error.is_none()))
                    {
                        return Err(InternalWireError::InvalidFrame);
                    }
                    bytes[9] = encode_audit_event(*event);
                    bytes[10] = encode_audit_outcome(*outcome);
                    bytes[11] = error.map(encode_error_token).unwrap_or(0);
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .copy_from_slice(&sequence.to_be_bytes());
                    bytes[COMMAND_PEER_UID_OFFSET..COMMAND_PEER_UID_OFFSET + 4]
                        .copy_from_slice(&peer_uid.to_be_bytes());
                    bytes[COMMAND_PEER_PID_OFFSET..COMMAND_PEER_PID_OFFSET + 4]
                        .copy_from_slice(&peer_pid.to_be_bytes());
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(request_id.as_str(), b"R-")?);
                }
                WorkerApplicationCommand::ReportPersist {
                    report_id,
                    payload_sha256,
                    input_size,
                } => {
                    if !(2..=MAX_SESSION_REPORT_JSON_BYTES).contains(input_size) {
                        return Err(InternalWireError::InvalidFrame);
                    }
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .copy_from_slice(&input_size.to_be_bytes());
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(report_id.as_str(), b"RP-")?);
                    bytes[COMMAND_SHA256_OFFSET..COMMAND_SHA256_OFFSET + 32]
                        .copy_from_slice(payload_sha256);
                }
                WorkerApplicationCommand::ReportList => {}
                WorkerApplicationCommand::ReportGet { report_id } => {
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(report_id.as_str(), b"RP-")?);
                }
            }
        } else {
            bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 2]
                .copy_from_slice(&self.secret_size.to_be_bytes());
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != COMMAND_BYTES || &bytes[..8] != COMMAND_MAGIC {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let secret_size = u16::from_be_bytes(
            bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 2]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let kind = match bytes[8] {
            1 => WorkerCommandKind::Bootstrap,
            2 => WorkerCommandKind::Probe,
            3 => WorkerCommandKind::Unlock,
            4 => WorkerCommandKind::Lock,
            5 => WorkerCommandKind::Shutdown,
            6 => WorkerCommandKind::AttestQuiescent,
            7 => WorkerCommandKind::ProviderStatus,
            8 => WorkerCommandKind::ProviderOpenAiConfigure,
            9 => WorkerCommandKind::ProviderOpenAiLogout,
            10 => WorkerCommandKind::ProviderOpenAiBorrow,
            #[cfg(feature = "experimental-codex-home-lease")]
            11 => WorkerCommandKind::ProviderCodexHomeLease,
            12 => WorkerCommandKind::AuditAppend,
            13 => WorkerCommandKind::ReportPersist,
            14 => WorkerCommandKind::ReportList,
            15 => WorkerCommandKind::ReportGet,
            _ => return Err(InternalWireError::InvalidFrame),
        };
        let application = match kind {
            WorkerCommandKind::AuditAppend => Some(WorkerApplicationCommand::AuditAppend {
                request_id: RequestId::parse(&decode_identifier(
                    b"R-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                peer_uid: u32::from_be_bytes(
                    bytes[COMMAND_PEER_UID_OFFSET..COMMAND_PEER_UID_OFFSET + 4]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                peer_pid: u32::from_be_bytes(
                    bytes[COMMAND_PEER_PID_OFFSET..COMMAND_PEER_PID_OFFSET + 4]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                sequence: u64::from_be_bytes(
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                event: decode_audit_event(bytes[9])?,
                outcome: decode_audit_outcome(bytes[10])?,
                error: (bytes[11] != 0)
                    .then(|| decode_error_token(bytes[11]))
                    .transpose()?,
            }),
            WorkerCommandKind::ReportPersist => Some(WorkerApplicationCommand::ReportPersist {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                payload_sha256: bytes[COMMAND_SHA256_OFFSET..COMMAND_SHA256_OFFSET + 32]
                    .try_into()
                    .map_err(|_| InternalWireError::InvalidFrame)?,
                input_size: u64::from_be_bytes(
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
            }),
            WorkerCommandKind::ReportList => Some(WorkerApplicationCommand::ReportList),
            WorkerCommandKind::ReportGet => Some(WorkerApplicationCommand::ReportGet {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
            }),
            _ => None,
        };
        let command = Self {
            request_id,
            kind,
            secret_size: if application.is_some() {
                0
            } else {
                secret_size
            },
            application,
        };
        if command.encode()?.as_slice() != bytes {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(command)
    }
}

fn encode_identifier(value: &str, prefix: &[u8]) -> Result<[u8; 16], InternalWireError> {
    let bytes = value.as_bytes();
    if bytes.len() != prefix.len() + 36 || &bytes[..prefix.len()] != prefix {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = [0_u8; 16];
    let mut nibble = 0_usize;
    for (index, byte) in bytes[prefix.len()..].iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(InternalWireError::InvalidFrame);
            }
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(InternalWireError::InvalidFrame),
        };
        if nibble & 1 == 0 {
            output[nibble / 2] = value << 4;
        } else {
            output[nibble / 2] |= value;
        }
        nibble += 1;
    }
    if nibble != 32 {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(output)
}

fn decode_identifier(prefix: &[u8], value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert_eq!(value.len(), 16);
    let mut bytes = vec![0_u8; prefix.len() + 36];
    bytes[..prefix.len()].copy_from_slice(prefix);
    let mut output = prefix.len();
    for (index, byte) in value.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            bytes[output] = b'-';
            output += 1;
        }
        bytes[output] = HEX[usize::from(byte >> 4)];
        bytes[output + 1] = HEX[usize::from(byte & 0x0f)];
        output += 2;
    }
    String::from_utf8(bytes).expect("closed ASCII identifier")
}

fn encode_sha256(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 64];
    for (index, byte) in value.iter().copied().enumerate() {
        bytes[index * 2] = HEX[usize::from(byte >> 4)];
        bytes[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    String::from_utf8(bytes.to_vec()).expect("closed lowercase SHA-256")
}

pub(super) fn decode_sha256(value: &Sha256) -> Result<[u8; 32], InternalWireError> {
    let bytes = value.as_str().as_bytes();
    if bytes.len() != 64 {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(InternalWireError::InvalidFrame),
        };
        output[index] = (decode(pair[0])? << 4) | decode(pair[1])?;
    }
    Ok(output)
}

pub(super) fn encode_report_records(
    reports: &[WorkerReportSummary],
) -> Result<Vec<u8>, InternalWireError> {
    if reports.len() > MAX_REPORTS_PER_RESPONSE {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = vec![0_u8; reports.len() * APPLICATION_REPORT_RECORD_BYTES];
    let mut previous: Option<String> = None;
    for (index, report) in reports.iter().enumerate() {
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&report.envelope_size)
            || previous
                .as_deref()
                .is_some_and(|value| value >= report.report_id.as_str())
        {
            return Err(InternalWireError::InvalidFrame);
        }
        previous = Some(report.report_id.as_str().to_owned());
        let offset = index * APPLICATION_REPORT_RECORD_BYTES;
        output[offset..offset + 16]
            .copy_from_slice(&encode_identifier(report.report_id.as_str(), b"RP-")?);
        output[offset + 16..offset + 24].copy_from_slice(&report.envelope_size.to_be_bytes());
        output[offset + 24..offset + 56].copy_from_slice(&report.envelope_sha256);
    }
    Ok(output)
}

pub(super) fn decode_report_records(
    bytes: &[u8],
    expected_count: u16,
) -> Result<Vec<ReportSummary>, InternalWireError> {
    if usize::from(expected_count) > MAX_REPORTS_PER_RESPONSE
        || bytes.len() != usize::from(expected_count) * APPLICATION_REPORT_RECORD_BYTES
    {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = Vec::with_capacity(usize::from(expected_count));
    let mut previous: Option<String> = None;
    for record in bytes.chunks_exact(APPLICATION_REPORT_RECORD_BYTES) {
        if record[56..].iter().any(|byte| *byte != 0) {
            return Err(InternalWireError::InvalidFrame);
        }
        let report_id = ReportId::parse(&decode_identifier(b"RP-", &record[..16]))
            .map_err(|_| InternalWireError::InvalidFrame)?;
        if previous
            .as_deref()
            .is_some_and(|value| value >= report_id.as_str())
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let envelope_size = u64::from_be_bytes(
            record[16..24]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let envelope_sha256: [u8; 32] = record[24..56]
            .try_into()
            .map_err(|_| InternalWireError::InvalidFrame)?;
        let summary = WorkerReportSummary {
            report_id,
            envelope_size,
            envelope_sha256,
        };
        previous = Some(summary.report_id.as_str().to_owned());
        output.push(summary.to_protocol()?);
    }
    Ok(output)
}

fn encode_audit_event(value: AuditEventType) -> u8 {
    match value {
        AuditEventType::AgentSessionStart => 1,
        AuditEventType::AgentDiagnosisComplete => 2,
        AuditEventType::AgentSessionEnd => 3,
    }
}

fn decode_audit_event(value: u8) -> Result<AuditEventType, InternalWireError> {
    match value {
        1 => Ok(AuditEventType::AgentSessionStart),
        2 => Ok(AuditEventType::AgentDiagnosisComplete),
        3 => Ok(AuditEventType::AgentSessionEnd),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn encode_audit_outcome(value: AuditOutcome) -> u8 {
    match value {
        AuditOutcome::Succeeded => 1,
        AuditOutcome::Rejected => 2,
        AuditOutcome::Failed => 3,
    }
}

fn decode_audit_outcome(value: u8) -> Result<AuditOutcome, InternalWireError> {
    match value {
        1 => Ok(AuditOutcome::Succeeded),
        2 => Ok(AuditOutcome::Rejected),
        3 => Ok(AuditOutcome::Failed),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn encode_error_token(value: ErrorToken) -> u8 {
    match value {
        ErrorToken::Absent => 1,
        ErrorToken::Unprovisioned => 2,
        ErrorToken::Locked => 3,
        ErrorToken::BadPassphrase => 4,
        ErrorToken::MediaChanged => 5,
        ErrorToken::ProfileMismatch => 6,
        ErrorToken::StaleState => 7,
        ErrorToken::FdRequired => 8,
        ErrorToken::FdForbidden => 9,
        ErrorToken::NotAuthorized => 10,
        ErrorToken::RateLimited => 11,
        ErrorToken::Busy => 12,
        ErrorToken::ProviderUnconfigured => 13,
        ErrorToken::ReportTooLarge => 14,
        ErrorToken::IoFailed => 15,
        ErrorToken::RebootRequired => 16,
    }
}

fn decode_error_token(value: u8) -> Result<ErrorToken, InternalWireError> {
    match value {
        1 => Ok(ErrorToken::Absent),
        2 => Ok(ErrorToken::Unprovisioned),
        3 => Ok(ErrorToken::Locked),
        4 => Ok(ErrorToken::BadPassphrase),
        5 => Ok(ErrorToken::MediaChanged),
        6 => Ok(ErrorToken::ProfileMismatch),
        7 => Ok(ErrorToken::StaleState),
        8 => Ok(ErrorToken::FdRequired),
        9 => Ok(ErrorToken::FdForbidden),
        10 => Ok(ErrorToken::NotAuthorized),
        11 => Ok(ErrorToken::RateLimited),
        12 => Ok(ErrorToken::Busy),
        13 => Ok(ErrorToken::ProviderUnconfigured),
        14 => Ok(ErrorToken::ReportTooLarge),
        15 => Ok(ErrorToken::IoFailed),
        16 => Ok(ErrorToken::RebootRequired),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn valid_passphrase_size(size: u16) -> bool {
    let size = u64::from(size);
    (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&size)
}

fn valid_openai_key_size(size: u16) -> bool {
    (1..=MAX_OPENAI_KEY_BYTES).contains(&u64::from(size))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerResultCode {
    BootstrapReady,
    ProbeAbsent,
    ProbeUnprovisioned,
    ProbeLocked,
    ProbeProfileMismatch,
    ProbeClassifierUnavailable,
    ProbeIoFailed,
    UnlockSucceeded,
    LockSucceeded,
    ShutdownSucceeded,
    Absent,
    Unprovisioned,
    ProfileMismatch,
    BadPassphrase,
    MediaChanged,
    IoFailed,
    CleanupFailed,
    TimedOut,
    Busy,
    InvalidRequest,
    AttestAbsent,
    AttestUnprovisioned,
    AttestLocked,
    AttestProfileMismatch,
    ProviderStatusUnconfigured,
    ProviderStatusConfigured,
    ProviderConfigureSucceeded,
    ProviderLogoutSucceeded,
    ProviderMutationAborted,
    ProviderStateAmbiguous,
    ProviderBorrowReady,
    ProviderBorrowUnconfigured,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeReady,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeUnconfigured,
    UnlockIoProbe,
    UnlockIoProbeClassifier,
    UnlockIoMapperName,
    UnlockIoUnsupportedPlatform,
    UnlockIoPrivilegeRequired,
    UnlockIoInvalidMapperName,
    UnlockIoClassifierUnavailable,
    UnlockIoPassphraseUnavailable,
    UnlockIoUnsupportedFilesystem,
    UnlockIoUnsafeMountRoot,
    UnlockIoMountFailed,
    UnlockIoMountVerificationFailed,
    UnlockIoSecureStateUnavailable,
    UnlockIoToolUnavailable,
    UnlockIoApplicationStore,
    UnlockIoDeviceId,
    ApplicationAuditAppended,
    ApplicationReportPersisted,
    ApplicationReportListReady,
    ApplicationReportReady,
    ApplicationReportNotFound,
    ApplicationInvalidRequest,
    ApplicationStaleSequence,
    ApplicationReportTooLarge,
    ApplicationMutationAborted,
    ApplicationStateAmbiguous,
}

impl WorkerResultCode {
    fn encode(self) -> u8 {
        match self {
            Self::BootstrapReady => 1,
            Self::ProbeAbsent => 2,
            Self::ProbeUnprovisioned => 3,
            Self::ProbeLocked => 4,
            Self::ProbeProfileMismatch => 5,
            Self::ProbeClassifierUnavailable => 6,
            Self::ProbeIoFailed => 7,
            Self::UnlockSucceeded => 8,
            Self::LockSucceeded => 9,
            Self::ShutdownSucceeded => 10,
            Self::Absent => 11,
            Self::Unprovisioned => 12,
            Self::ProfileMismatch => 13,
            Self::BadPassphrase => 14,
            Self::MediaChanged => 15,
            Self::IoFailed => 16,
            Self::CleanupFailed => 17,
            Self::TimedOut => 18,
            Self::Busy => 19,
            Self::InvalidRequest => 20,
            Self::AttestAbsent => 21,
            Self::AttestUnprovisioned => 22,
            Self::AttestLocked => 23,
            Self::AttestProfileMismatch => 24,
            Self::ProviderStatusUnconfigured => 25,
            Self::ProviderStatusConfigured => 26,
            Self::ProviderConfigureSucceeded => 27,
            Self::ProviderLogoutSucceeded => 28,
            Self::ProviderMutationAborted => 29,
            Self::ProviderStateAmbiguous => 30,
            Self::ProviderBorrowReady => 31,
            Self::ProviderBorrowUnconfigured => 32,
            #[cfg(feature = "experimental-codex-home-lease")]
            Self::ProviderCodexHomeReady => 33,
            #[cfg(feature = "experimental-codex-home-lease")]
            Self::ProviderCodexHomeUnconfigured => 34,
            Self::UnlockIoProbe => 35,
            Self::UnlockIoProbeClassifier => 36,
            Self::UnlockIoMapperName => 37,
            Self::UnlockIoUnsupportedPlatform => 38,
            Self::UnlockIoPrivilegeRequired => 39,
            Self::UnlockIoInvalidMapperName => 40,
            Self::UnlockIoClassifierUnavailable => 41,
            Self::UnlockIoPassphraseUnavailable => 42,
            Self::UnlockIoUnsupportedFilesystem => 43,
            Self::UnlockIoUnsafeMountRoot => 44,
            Self::UnlockIoMountFailed => 45,
            Self::UnlockIoMountVerificationFailed => 46,
            Self::UnlockIoSecureStateUnavailable => 47,
            Self::UnlockIoToolUnavailable => 48,
            Self::UnlockIoApplicationStore => 49,
            Self::UnlockIoDeviceId => 50,
            Self::ApplicationAuditAppended => 51,
            Self::ApplicationReportPersisted => 52,
            Self::ApplicationReportListReady => 53,
            Self::ApplicationReportReady => 54,
            Self::ApplicationReportNotFound => 55,
            Self::ApplicationInvalidRequest => 56,
            Self::ApplicationStaleSequence => 57,
            Self::ApplicationReportTooLarge => 58,
            Self::ApplicationMutationAborted => 59,
            Self::ApplicationStateAmbiguous => 60,
        }
    }

    fn decode(value: u8) -> Result<Self, InternalWireError> {
        match value {
            1 => Ok(Self::BootstrapReady),
            2 => Ok(Self::ProbeAbsent),
            3 => Ok(Self::ProbeUnprovisioned),
            4 => Ok(Self::ProbeLocked),
            5 => Ok(Self::ProbeProfileMismatch),
            6 => Ok(Self::ProbeClassifierUnavailable),
            7 => Ok(Self::ProbeIoFailed),
            8 => Ok(Self::UnlockSucceeded),
            9 => Ok(Self::LockSucceeded),
            10 => Ok(Self::ShutdownSucceeded),
            11 => Ok(Self::Absent),
            12 => Ok(Self::Unprovisioned),
            13 => Ok(Self::ProfileMismatch),
            14 => Ok(Self::BadPassphrase),
            15 => Ok(Self::MediaChanged),
            16 => Ok(Self::IoFailed),
            17 => Ok(Self::CleanupFailed),
            18 => Ok(Self::TimedOut),
            19 => Ok(Self::Busy),
            20 => Ok(Self::InvalidRequest),
            21 => Ok(Self::AttestAbsent),
            22 => Ok(Self::AttestUnprovisioned),
            23 => Ok(Self::AttestLocked),
            24 => Ok(Self::AttestProfileMismatch),
            25 => Ok(Self::ProviderStatusUnconfigured),
            26 => Ok(Self::ProviderStatusConfigured),
            27 => Ok(Self::ProviderConfigureSucceeded),
            28 => Ok(Self::ProviderLogoutSucceeded),
            29 => Ok(Self::ProviderMutationAborted),
            30 => Ok(Self::ProviderStateAmbiguous),
            31 => Ok(Self::ProviderBorrowReady),
            32 => Ok(Self::ProviderBorrowUnconfigured),
            #[cfg(feature = "experimental-codex-home-lease")]
            33 => Ok(Self::ProviderCodexHomeReady),
            #[cfg(feature = "experimental-codex-home-lease")]
            34 => Ok(Self::ProviderCodexHomeUnconfigured),
            35 => Ok(Self::UnlockIoProbe),
            36 => Ok(Self::UnlockIoProbeClassifier),
            37 => Ok(Self::UnlockIoMapperName),
            38 => Ok(Self::UnlockIoUnsupportedPlatform),
            39 => Ok(Self::UnlockIoPrivilegeRequired),
            40 => Ok(Self::UnlockIoInvalidMapperName),
            41 => Ok(Self::UnlockIoClassifierUnavailable),
            42 => Ok(Self::UnlockIoPassphraseUnavailable),
            43 => Ok(Self::UnlockIoUnsupportedFilesystem),
            44 => Ok(Self::UnlockIoUnsafeMountRoot),
            45 => Ok(Self::UnlockIoMountFailed),
            46 => Ok(Self::UnlockIoMountVerificationFailed),
            47 => Ok(Self::UnlockIoSecureStateUnavailable),
            48 => Ok(Self::UnlockIoToolUnavailable),
            49 => Ok(Self::UnlockIoApplicationStore),
            50 => Ok(Self::UnlockIoDeviceId),
            51 => Ok(Self::ApplicationAuditAppended),
            52 => Ok(Self::ApplicationReportPersisted),
            53 => Ok(Self::ApplicationReportListReady),
            54 => Ok(Self::ApplicationReportReady),
            55 => Ok(Self::ApplicationReportNotFound),
            56 => Ok(Self::ApplicationInvalidRequest),
            57 => Ok(Self::ApplicationStaleSequence),
            58 => Ok(Self::ApplicationReportTooLarge),
            59 => Ok(Self::ApplicationMutationAborted),
            60 => Ok(Self::ApplicationStateAmbiguous),
            _ => Err(InternalWireError::InvalidFrame),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerReportSummary {
    pub(super) report_id: ReportId,
    pub(super) envelope_size: u64,
    pub(super) envelope_sha256: [u8; 32],
}

impl WorkerReportSummary {
    pub(super) fn from_store(
        value: &crate::RescueReportSummary,
    ) -> Result<Self, InternalWireError> {
        let report_id =
            ReportId::parse(value.report_id()).map_err(|_| InternalWireError::InvalidFrame)?;
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&value.envelope_size()) {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(Self {
            report_id,
            envelope_size: value.envelope_size(),
            envelope_sha256: *value.envelope_sha256(),
        })
    }

    pub(super) fn to_protocol(&self) -> Result<ReportSummary, InternalWireError> {
        ReportSummary::new(
            self.report_id.clone(),
            self.envelope_size,
            Sha256::parse(&encode_sha256(&self.envelope_sha256))
                .map_err(|_| InternalWireError::InvalidFrame)?,
        )
        .map_err(|_| InternalWireError::InvalidFrame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerResponse {
    pub(super) request_id: u64,
    pub(super) code: WorkerResultCode,
    pub(super) device_id: Option<String>,
    pub(super) output_size: Option<u16>,
    pub(super) audit_sequence: Option<u64>,
    pub(super) report: Option<WorkerReportSummary>,
    pub(super) application_output_size: Option<u64>,
    pub(super) application_record_count: Option<u16>,
}

impl WorkerResponse {
    pub(super) fn new(request_id: u64, code: WorkerResultCode) -> Self {
        Self {
            request_id,
            code,
            device_id: None,
            output_size: None,
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
        }
    }

    pub(super) fn unlocked(request_id: u64, device_id: String) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::UnlockSucceeded,
            device_id: Some(device_id),
            output_size: None,
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
        }
    }

    pub(super) fn provider_borrow_ready(request_id: u64, output_size: u16) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::ProviderBorrowReady,
            device_id: None,
            output_size: Some(output_size),
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
        }
    }

    pub(super) fn audit_appended(request_id: u64, sequence: u64) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationAuditAppended);
        response.audit_sequence = Some(sequence);
        response
    }

    pub(super) fn report_persisted(request_id: u64, report: WorkerReportSummary) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportPersisted);
        response.report = Some(report);
        response
    }

    pub(super) fn report_list_ready(request_id: u64, output_size: u64, count: u16) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportListReady);
        response.application_output_size = Some(output_size);
        response.application_record_count = Some(count);
        response
    }

    pub(super) fn report_ready(request_id: u64, report: WorkerReportSummary) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportReady);
        response.application_output_size = Some(report.envelope_size);
        response.report = Some(report);
        response
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    pub(super) fn provider_codex_home_ready(request_id: u64) -> Self {
        Self::new(request_id, WorkerResultCode::ProviderCodexHomeReady)
    }

    fn encode(&self) -> Result<[u8; RESPONSE_BYTES], InternalWireError> {
        let device_metadata = self.code == WorkerResultCode::UnlockSucceeded;
        let provider_metadata = self.code == WorkerResultCode::ProviderBorrowReady;
        let audit_metadata = self.code == WorkerResultCode::ApplicationAuditAppended;
        let persisted_metadata = self.code == WorkerResultCode::ApplicationReportPersisted;
        let list_metadata = self.code == WorkerResultCode::ApplicationReportListReady;
        let report_metadata = self.code == WorkerResultCode::ApplicationReportReady;
        if self.request_id == 0
            || device_metadata != self.device_id.is_some()
            || provider_metadata != self.output_size.is_some()
            || audit_metadata != self.audit_sequence.is_some()
            || (persisted_metadata || report_metadata) != self.report.is_some()
            || (list_metadata || report_metadata) != self.application_output_size.is_some()
            || list_metadata != self.application_record_count.is_some()
            || self
                .output_size
                .is_some_and(|size| !valid_openai_key_size(size))
            || self
                .audit_sequence
                .is_some_and(|sequence| !(1..=MAX_AUDIT_SEQUENCE).contains(&sequence))
            || self
                .application_record_count
                .is_some_and(|count| usize::from(count) > MAX_REPORTS_PER_RESPONSE)
            || self.application_output_size.is_some_and(|size| {
                if list_metadata {
                    size > MAX_APPLICATION_REPORT_LIST_BYTES as u64
                } else {
                    !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&size)
                }
            })
            || self.report.as_ref().is_some_and(|report| {
                !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&report.envelope_size)
                    || (report_metadata
                        && self.application_output_size != Some(report.envelope_size))
            })
            || (list_metadata
                && self.application_output_size
                    != self
                        .application_record_count
                        .map(|count| u64::from(count) * APPLICATION_REPORT_RECORD_BYTES as u64))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let device = self.device_id.as_deref().unwrap_or_default().as_bytes();
        if (!device.is_empty() && !valid_device_id(device)) || device.len() > MAX_DEVICE_ID_BYTES {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8] = self.code.encode();
        bytes[9] = u8::try_from(device.len()).map_err(|_| InternalWireError::InvalidFrame)?;
        bytes[10..12].copy_from_slice(&self.output_size.unwrap_or_default().to_be_bytes());
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        let value = self
            .audit_sequence
            .or(self.application_output_size)
            .or_else(|| self.report.as_ref().map(|report| report.envelope_size))
            .unwrap_or_default();
        bytes[RESPONSE_VALUE_OFFSET..RESPONSE_VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_be_bytes());
        bytes[RESPONSE_COUNT_OFFSET..RESPONSE_COUNT_OFFSET + 2].copy_from_slice(
            &self
                .application_record_count
                .unwrap_or_default()
                .to_be_bytes(),
        );
        if let Some(report) = &self.report {
            bytes[RESPONSE_IDENTIFIER_OFFSET..RESPONSE_IDENTIFIER_OFFSET + 16]
                .copy_from_slice(&encode_identifier(report.report_id.as_str(), b"RP-")?);
            bytes[RESPONSE_SHA256_OFFSET..RESPONSE_SHA256_OFFSET + 32]
                .copy_from_slice(&report.envelope_sha256);
        }
        bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device.len()].copy_from_slice(device);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != RESPONSE_BYTES || &bytes[..8] != RESPONSE_MAGIC {
            return Err(InternalWireError::InvalidFrame);
        }
        let code = WorkerResultCode::decode(bytes[8])?;
        let device_len = usize::from(bytes[9]);
        let output_size = u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        if device_len > MAX_DEVICE_ID_BYTES
            || bytes[DEVICE_ID_OFFSET + device_len..DEVICE_ID_OFFSET + MAX_DEVICE_ID_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let device_id = if device_len == 0 {
            None
        } else {
            let device = &bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device_len];
            if !valid_device_id(device) {
                return Err(InternalWireError::InvalidFrame);
            }
            Some(
                std::str::from_utf8(device)
                    .map_err(|_| InternalWireError::InvalidFrame)?
                    .to_owned(),
            )
        };
        let value = u64::from_be_bytes(
            bytes[RESPONSE_VALUE_OFFSET..RESPONSE_VALUE_OFFSET + 8]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let count = u16::from_be_bytes(
            bytes[RESPONSE_COUNT_OFFSET..RESPONSE_COUNT_OFFSET + 2]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let report = if matches!(
            code,
            WorkerResultCode::ApplicationReportPersisted | WorkerResultCode::ApplicationReportReady
        ) {
            Some(WorkerReportSummary {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[RESPONSE_IDENTIFIER_OFFSET..RESPONSE_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                envelope_size: value,
                envelope_sha256: bytes[RESPONSE_SHA256_OFFSET..RESPONSE_SHA256_OFFSET + 32]
                    .try_into()
                    .map_err(|_| InternalWireError::InvalidFrame)?,
            })
        } else {
            None
        };
        let response = Self {
            request_id,
            code,
            device_id,
            output_size: (output_size != 0).then_some(output_size),
            audit_sequence: (code == WorkerResultCode::ApplicationAuditAppended).then_some(value),
            report,
            application_output_size: matches!(
                code,
                WorkerResultCode::ApplicationReportListReady
                    | WorkerResultCode::ApplicationReportReady
            )
            .then_some(value),
            application_record_count: (code == WorkerResultCode::ApplicationReportListReady)
                .then_some(count),
        };
        if response.encode()?.as_slice() != bytes {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(response)
    }
}

fn valid_device_id(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .ok()
        .is_some_and(|value| kernaid_device_identity::validate_device_id(value).is_ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InternalWireError {
    InvalidTransport,
    InvalidFrame,
    InvalidDescriptors,
    TimedOut,
    IoFailed,
}

impl fmt::Display for InternalWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransport => "invalid Rescue worker transport",
            Self::InvalidFrame => "invalid Rescue worker frame",
            Self::InvalidDescriptors => "invalid Rescue worker descriptors",
            Self::TimedOut => "Rescue worker transport timed out",
            Self::IoFailed => "Rescue worker transport failed",
        })
    }
}

impl std::error::Error for InternalWireError {}

pub(super) fn send_command(
    socket: BorrowedFd<'_>,
    command: WorkerCommand,
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    let bytes = command.encode()?;
    match (command.kind, descriptor) {
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow
            | WorkerCommandKind::ReportPersist
            | WorkerCommandKind::ReportList
            | WorkerCommandKind::ReportGet,
            Some(descriptor),
        ) => send_record(socket, &bytes, &[descriptor], deadline),
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow
            | WorkerCommandKind::ReportPersist
            | WorkerCommandKind::ReportList
            | WorkerCommandKind::ReportGet,
            None,
        )
        | (_, Some(_)) => Err(InternalWireError::InvalidDescriptors),
        (_, None) => send_record(socket, &bytes, &[], deadline),
    }
}

pub(super) fn receive_command(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(WorkerCommand, Option<OwnedFd>), InternalWireError> {
    let (bytes, mut descriptors) = receive_record(socket, deadline)?;
    let command = WorkerCommand::decode(&bytes)?;
    match (command.kind, descriptors.len()) {
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow
            | WorkerCommandKind::ReportPersist
            | WorkerCommandKind::ReportList
            | WorkerCommandKind::ReportGet,
            1,
        ) => Ok((command, descriptors.pop())),
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow
            | WorkerCommandKind::ReportPersist
            | WorkerCommandKind::ReportList
            | WorkerCommandKind::ReportGet,
            _,
        )
        | (_, 1..) => Err(InternalWireError::InvalidDescriptors),
        (_, 0) => Ok((command, None)),
    }
}

pub(super) fn send_response(
    socket: BorrowedFd<'_>,
    response: &WorkerResponse,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    send_record(socket, &response.encode()?, &[], deadline)
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn send_codex_home_response(
    socket: BorrowedFd<'_>,
    response: &WorkerResponse,
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    match (response.code, descriptor) {
        (WorkerResultCode::ProviderCodexHomeReady, Some(descriptor)) => {
            validate_codex_home_descriptor(descriptor)?;
            send_record(socket, &response.encode()?, &[descriptor], deadline)
        }
        (WorkerResultCode::ProviderCodexHomeUnconfigured, None) => {
            send_record(socket, &response.encode()?, &[], deadline)
        }
        _ => Err(InternalWireError::InvalidDescriptors),
    }
}

pub(super) fn receive_response(
    socket: BorrowedFd<'_>,
    expected_request_id: u64,
    deadline: Instant,
) -> Result<WorkerResponse, InternalWireError> {
    let (bytes, descriptors) = receive_record(socket, deadline)?;
    if !descriptors.is_empty() {
        return Err(InternalWireError::InvalidDescriptors);
    }
    let response = WorkerResponse::decode(&bytes)?;
    if response.request_id != expected_request_id {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(response)
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn receive_codex_home_response(
    socket: BorrowedFd<'_>,
    expected_request_id: u64,
    deadline: Instant,
) -> Result<(WorkerResponse, Option<OwnedFd>), InternalWireError> {
    let (bytes, mut descriptors) = receive_record(socket, deadline)?;
    let response = WorkerResponse::decode(&bytes)?;
    if response.request_id != expected_request_id {
        return Err(InternalWireError::InvalidFrame);
    }
    match (response.code, descriptors.len()) {
        (WorkerResultCode::ProviderCodexHomeReady, 1) => {
            let descriptor = descriptors
                .pop()
                .ok_or(InternalWireError::InvalidDescriptors)?;
            validate_codex_home_descriptor(descriptor.as_fd())?;
            Ok((response, Some(descriptor)))
        }
        (
            WorkerResultCode::ProviderCodexHomeUnconfigured
            | WorkerResultCode::ProviderStateAmbiguous
            | WorkerResultCode::CleanupFailed
            | WorkerResultCode::Busy
            | WorkerResultCode::InvalidRequest,
            0,
        ) => Ok((response, None)),
        _ => Err(InternalWireError::InvalidDescriptors),
    }
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_home_descriptor(descriptor: BorrowedFd<'_>) -> Result<(), InternalWireError> {
    use rustix::fs::{self as rfs, FileType};

    let stat = rfs::fstat(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    let flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_nlink < 2
        || stat.st_uid != crate::CODEX_AGENT_UID
        || stat.st_gid != crate::CODEX_AGENT_GID
        || stat.st_mode & 0o7777 != 0o700
        || !crate::codex_home_status_flags_are_exact(status)
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(InternalWireError::InvalidDescriptors);
    }
    Ok(())
}

pub(super) fn validate_control_socket(socket: BorrowedFd<'_>) -> Result<(), InternalWireError> {
    let flags = rustix::io::fcntl_getfd(socket).map_err(|_| InternalWireError::InvalidTransport)?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC)
        || rustix::net::sockopt::socket_domain(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
        || rustix::net::getpeername(socket).is_err()
        || rustix::net::sockopt::socket_passcred(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
    {
        return Err(InternalWireError::InvalidTransport);
    }
    Ok(())
}

pub(super) fn send_record(
    socket: BorrowedFd<'_>,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES || descriptors.len() > 3 {
        return Err(InternalWireError::InvalidFrame);
    }
    let io = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(InternalWireError::IoFailed);
    }
    loop {
        ensure_deadline(deadline)?;
        match sendmsg(
            socket,
            &io,
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(sent) if sent == bytes.len() => return Ok(()),
            Ok(_) => return Err(InternalWireError::IoFailed),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    }
}

pub(super) fn receive_record(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    let mut bytes = [0_u8; MAX_RECORD_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = loop {
        ensure_deadline(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    };
    if message
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || message.bytes == 0
        || message.bytes > MAX_RECORD_BYTES
    {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(_) => unexpected = true,
            _ => unexpected = true,
        }
    }
    if unexpected
        || descriptors.len() > 3
        || descriptors.iter().any(|descriptor| {
            rustix::io::fcntl_getfd(descriptor)
                .map(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
                .unwrap_or(true)
        })
    {
        return Err(InternalWireError::InvalidDescriptors);
    }
    Ok((bytes[..message.bytes].to_vec(), descriptors))
}

fn ensure_deadline(deadline: Instant) -> Result<(), InternalWireError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(InternalWireError::TimedOut)
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(InternalWireError::TimedOut)?;
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(InternalWireError::TimedOut),
            Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                return Err(InternalWireError::InvalidTransport);
            }
            Ok(_)
                if descriptors[0]
                    .revents()
                    .intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) =>
            {
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    }
}

fn duration_to_timespec(duration: Duration) -> Timespec {
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    Timespec {
        tv_sec: seconds,
        tv_nsec: if seconds == i64::MAX {
            999_999_999
        } else {
            i64::from(duration.subsec_nanos())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::{
        net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
            SocketType, send, sendmsg, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        ffi::OsString,
        io::IoSlice,
        mem::MaybeUninit,
        os::fd::{AsFd, AsRawFd},
    };

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    #[test]
    fn closed_command_and_response_round_trip() {
        let (parent, worker) = pair();
        let (read, _write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        let deadline = Instant::now() + Duration::from_secs(2);
        send_command(
            parent.as_fd(),
            WorkerCommand::unlock(7, 12),
            Some(read.as_fd()),
            deadline,
        )
        .expect("send unlock");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::unlock(7, 12));
        assert!(descriptor.is_some());

        let (key_read, _key_write) = pipe_with(PipeFlags::CLOEXEC).expect("key pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_configure(8, 32),
            Some(key_read.as_fd()),
            deadline,
        )
        .expect("send provider configure");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_configure(8, 32));
        assert!(descriptor.is_some());

        let (_borrow_read, borrow_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("borrow pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_borrow(9),
            Some(borrow_write.as_fd()),
            deadline,
        )
        .expect("send provider borrow");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_borrow(9));
        assert!(descriptor.is_some());

        #[cfg(feature = "experimental-codex-home-lease")]
        {
            send_command(
                parent.as_fd(),
                WorkerCommand::provider_codex_home_lease(10),
                None,
                deadline,
            )
            .expect("send Codex home lease");
            let (command, descriptor) =
                receive_command(worker.as_fd(), deadline).expect("receive Codex home lease");
            assert_eq!(command, WorkerCommand::provider_codex_home_lease(10));
            assert!(descriptor.is_none());
        }

        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        send_response(worker.as_fd(), &response, deadline).expect("send response");
        assert_eq!(
            receive_response(parent.as_fd(), 7, deadline).expect("receive response"),
            response
        );

        let response = WorkerResponse::provider_borrow_ready(9, 32);
        send_response(worker.as_fd(), &response, deadline).expect("send borrow response");
        assert_eq!(
            receive_response(parent.as_fd(), 9, deadline).expect("receive borrow response"),
            response
        );

        #[cfg(feature = "experimental-codex-home-lease")]
        {
            let response = WorkerResponse::new(10, WorkerResultCode::ProviderCodexHomeUnconfigured);
            send_response(worker.as_fd(), &response, deadline).expect("send unconfigured home");
            let (observed, descriptor) = receive_codex_home_response(parent.as_fd(), 10, deadline)
                .expect("receive unconfigured home");
            assert_eq!(observed, response);
            assert!(descriptor.is_none());
        }
    }

    #[test]
    fn application_commands_and_metadata_round_trip_without_text_frames() {
        let agent_request =
            RequestId::parse("R-00000000-0000-0000-0000-000000000011").expect("agent request id");
        let report_id =
            ReportId::parse("RP-00000000-0000-0000-0000-000000000021").expect("report id");
        let audit = WorkerCommand::application(
            11,
            WorkerApplicationCommand::AuditAppend {
                request_id: agent_request,
                peer_uid: 1001,
                peer_pid: 4242,
                sequence: 1,
                event: AuditEventType::AgentSessionStart,
                outcome: AuditOutcome::Succeeded,
                error: None,
            },
        );
        let encoded = audit.encode().expect("audit frame");
        assert_eq!(encoded.len(), COMMAND_BYTES);
        assert_eq!(encoded[8], 12);
        assert!(!encoded.windows(2).any(|window| window == b"R-"));
        assert_eq!(WorkerCommand::decode(&encoded), Ok(audit.clone()));

        let persist = WorkerCommand::application(
            12,
            WorkerApplicationCommand::ReportPersist {
                report_id: report_id.clone(),
                payload_sha256: [0x5a; 32],
                input_size: 4096,
            },
        );
        let encoded = persist.encode().expect("persist frame");
        assert_eq!(encoded[8], 13);
        assert!(!encoded.windows(3).any(|window| window == b"RP-"));
        assert_eq!(WorkerCommand::decode(&encoded), Ok(persist.clone()));

        let (parent, worker) = pair();
        let (input, _input_writer) = pipe_with(PipeFlags::CLOEXEC).expect("report input pipe");
        let deadline = Instant::now() + Duration::from_secs(1);
        send_command(
            parent.as_fd(),
            persist.clone(),
            Some(input.as_fd()),
            deadline,
        )
        .expect("send report persist");
        assert_eq!(
            receive_command(worker.as_fd(), deadline)
                .expect("receive report persist")
                .0,
            persist
        );
        assert_eq!(
            send_command(parent.as_fd(), audit.clone(), Some(input.as_fd()), deadline),
            Err(InternalWireError::InvalidDescriptors)
        );
        assert_eq!(
            send_command(parent.as_fd(), persist.clone(), None, deadline),
            Err(InternalWireError::InvalidDescriptors)
        );

        let list = WorkerCommand::application(13, WorkerApplicationCommand::ReportList);
        assert_eq!(
            WorkerCommand::decode(&list.encode().expect("list")),
            Ok(list)
        );
        let get = WorkerCommand::application(
            14,
            WorkerApplicationCommand::ReportGet {
                report_id: report_id.clone(),
            },
        );
        assert_eq!(WorkerCommand::decode(&get.encode().expect("get")), Ok(get));

        let summary = WorkerReportSummary {
            report_id,
            envelope_size: 8192,
            envelope_sha256: [0xa5; 32],
        };
        for response in [
            WorkerResponse::audit_appended(21, 1),
            WorkerResponse::report_persisted(22, summary.clone()),
            WorkerResponse::report_list_ready(23, APPLICATION_REPORT_RECORD_BYTES as u64, 1),
            WorkerResponse::report_ready(24, summary),
        ] {
            let encoded = response.encode().expect("application response");
            assert_eq!(encoded.len(), RESPONSE_BYTES);
            assert_eq!(WorkerResponse::decode(&encoded), Ok(response));
        }
    }

    #[test]
    fn report_record_pipe_format_is_fixed_sorted_and_bounded() {
        let reports = [
            WorkerReportSummary {
                report_id: ReportId::parse("RP-00000000-0000-0000-0000-000000000001")
                    .expect("first report"),
                envelope_size: 2,
                envelope_sha256: [1; 32],
            },
            WorkerReportSummary {
                report_id: ReportId::parse("RP-00000000-0000-0000-0000-000000000002")
                    .expect("second report"),
                envelope_size: 3,
                envelope_sha256: [2; 32],
            },
        ];
        let encoded = encode_report_records(&reports).expect("report records");
        assert_eq!(encoded.len(), 2 * APPLICATION_REPORT_RECORD_BYTES);
        assert!(encoded[56..64].iter().all(|byte| *byte == 0));
        let decoded = decode_report_records(&encoded, 2).expect("decode report records");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].report_id(), &reports[0].report_id);
        assert_eq!(decoded[1].envelope_size(), 3);

        let mut reversed = reports;
        reversed.reverse();
        assert_eq!(
            encode_report_records(&reversed),
            Err(InternalWireError::InvalidFrame)
        );
        let mut reserved = encoded;
        reserved[63] = 1;
        assert_eq!(
            decode_report_records(&reserved, 2),
            Err(InternalWireError::InvalidFrame)
        );
    }

    #[test]
    fn canonical_frames_reject_wrong_arity_reserved_bytes_and_correlation() {
        assert_eq!(
            WorkerCommand::unlock(1, 11).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let borrow = WorkerCommand::provider_openai_borrow(1)
            .encode()
            .expect("borrow frame");
        assert_eq!(borrow[8], 10);
        assert_eq!(&borrow[20..22], &[0, 0]);
        let mut noncanonical_borrow = borrow;
        noncanonical_borrow[21] = 1;
        assert_eq!(
            WorkerCommand::decode(&noncanonical_borrow),
            Err(InternalWireError::InvalidFrame)
        );
        #[cfg(feature = "experimental-codex-home-lease")]
        {
            let deadline = Instant::now() + Duration::from_secs(2);
            let home = WorkerCommand::provider_codex_home_lease(1)
                .encode()
                .expect("home frame");
            assert_eq!(home[8], 11);
            assert_eq!(&home[20..22], &[0, 0]);
            assert_eq!(
                send_command(
                    pair().0.as_fd(),
                    WorkerCommand::provider_codex_home_lease(1),
                    Some(read_pipe_for_test().as_fd()),
                    deadline,
                ),
                Err(InternalWireError::InvalidDescriptors)
            );
        }
        assert_eq!(
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowReady).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let encoded_ready = WorkerResponse::provider_borrow_ready(1, 32)
            .encode()
            .expect("canonical ready response");
        assert_eq!(encoded_ready[8], 31);
        assert_eq!(encoded_ready[9], 0);
        assert_eq!(&encoded_ready[10..12], &[0, 32]);
        let encoded_unconfigured =
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowUnconfigured)
                .encode()
                .expect("canonical unconfigured response");
        assert_eq!(encoded_unconfigured[8], 32);
        assert_eq!(&encoded_unconfigured[10..12], &[0, 0]);
        let mut frame = WorkerCommand::probe(1).encode().expect("frame");
        frame[84] = 1;
        assert_eq!(
            WorkerCommand::decode(&frame),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_command = WorkerCommand::probe(1).encode().expect("legacy command");
        legacy_command[..8].copy_from_slice(b"KRVWC001");
        assert_eq!(
            WorkerCommand::decode(&legacy_command),
            Err(InternalWireError::InvalidFrame)
        );
        let response = WorkerResponse::new(9, WorkerResultCode::ProbeLocked);
        let mut encoded = response.encode().expect("response");
        encoded[63] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_response = response.encode().expect("legacy response");
        legacy_response[..8].copy_from_slice(b"KRVWR001");
        assert_eq!(
            WorkerResponse::decode(&legacy_response),
            Err(InternalWireError::InvalidFrame)
        );
        let mut encoded = WorkerResponse::new(9, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        encoded[11] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let mut encoded = WorkerResponse::provider_borrow_ready(9, 32)
            .encode()
            .expect("borrow response");
        encoded[11] = 0;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, worker) = pair();
        let deadline = Instant::now() + Duration::from_secs(2);
        send_response(worker.as_fd(), &response, deadline).expect("send");
        assert_eq!(
            receive_response(parent.as_fd(), 10, deadline),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, _worker) = pair();
        assert_eq!(
            send_command(
                parent.as_fd(),
                WorkerCommand::provider_openai_borrow(11),
                None,
                deadline
            ),
            Err(InternalWireError::InvalidDescriptors)
        );
    }

    #[test]
    fn unlock_io_diagnostic_codes_keep_the_fixed_payload_free_frame() {
        use WorkerResultCode as Result;
        for (code, encoded_code) in [
            (Result::UnlockIoProbe, 35),
            (Result::UnlockIoProbeClassifier, 36),
            (Result::UnlockIoMapperName, 37),
            (Result::UnlockIoUnsupportedPlatform, 38),
            (Result::UnlockIoPrivilegeRequired, 39),
            (Result::UnlockIoInvalidMapperName, 40),
            (Result::UnlockIoClassifierUnavailable, 41),
            (Result::UnlockIoPassphraseUnavailable, 42),
            (Result::UnlockIoUnsupportedFilesystem, 43),
            (Result::UnlockIoUnsafeMountRoot, 44),
            (Result::UnlockIoMountFailed, 45),
            (Result::UnlockIoMountVerificationFailed, 46),
            (Result::UnlockIoSecureStateUnavailable, 47),
            (Result::UnlockIoToolUnavailable, 48),
            (Result::UnlockIoApplicationStore, 49),
            (Result::UnlockIoDeviceId, 50),
        ] {
            let frame = WorkerResponse::new(7, code)
                .encode()
                .expect("canonical diagnostic response");
            assert_eq!(frame.len(), RESPONSE_BYTES);
            assert_eq!(frame[8], encoded_code);
            assert_eq!(&frame[9..12], &[0, 0, 0]);
            assert_eq!(&frame[12..20], &7_u64.to_be_bytes());
            assert!(frame[20..].iter().all(|byte| *byte == 0));
            assert_eq!(
                WorkerResponse::decode(&frame).expect("diagnostic response round trip"),
                WorkerResponse::new(7, code)
            );
        }
        let mut reserved = WorkerResponse::new(7, Result::UnlockIoDeviceId)
            .encode()
            .expect("canonical diagnostic response");
        reserved[8] = 61;
        assert_eq!(
            WorkerResponse::decode(&reserved),
            Err(InternalWireError::InvalidFrame)
        );
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    fn read_pipe_for_test() -> OwnedFd {
        pipe_with(PipeFlags::CLOEXEC).expect("pipe").0
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_response_rejects_missing_or_wrong_owner_descriptors() {
        let (sender, receiver) = pair();
        let response = WorkerResponse::provider_codex_home_ready(41);
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(
            send_codex_home_response(sender.as_fd(), &response, None, deadline),
            Err(InternalWireError::InvalidDescriptors)
        );

        let directory = rustix::fs::open(
            "/tmp",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("temporary directory");
        assert_eq!(
            send_codex_home_response(sender.as_fd(), &response, Some(directory.as_fd()), deadline,),
            Err(InternalWireError::InvalidDescriptors)
        );
        drop(receiver);
    }

    #[test]
    fn debug_and_errors_never_contain_payload_or_descriptor_numbers() {
        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        let debug = format!("{response:?}");
        assert!(debug.contains("KA-"));
        assert!(!InternalWireError::InvalidFrame.to_string().contains('7'));
    }

    #[test]
    fn short_extra_and_timed_out_records_fail_closed() {
        for bytes in [
            &[0_u8; COMMAND_BYTES - 1][..],
            &[0_u8; COMMAND_BYTES + 1][..],
        ] {
            let (sender, receiver) = pair();
            send(&sender, bytes, SendFlags::NOSIGNAL).expect("raw frame");
            assert!(matches!(
                receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
                Err(InternalWireError::InvalidFrame)
            ));
        }
        let (_sender, receiver) = pair();
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::TimedOut)
        ));
    }

    #[test]
    fn duplicate_rights_are_rejected_and_closed() {
        fn descriptor_target(descriptor: BorrowedFd<'_>) -> OsString {
            std::fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                .expect("descriptor target")
                .into_os_string()
        }

        fn target_count(target: &OsString) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("proc fd")
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .filter(|observed| observed.as_os_str() == target.as_os_str())
                .count()
        }

        let (sender, receiver) = pair();
        let (first, first_write) = pipe_with(PipeFlags::CLOEXEC).expect("first pipe");
        let (second, second_write) = pipe_with(PipeFlags::CLOEXEC).expect("second pipe");
        let first_target = descriptor_target(first.as_fd());
        let second_target = descriptor_target(second.as_fd());
        let first_baseline = target_count(&first_target);
        let second_baseline = target_count(&second_target);
        let frame = WorkerCommand::unlock(9, 12).encode().expect("frame");
        let io = [IoSlice::new(&frame)];
        let rights = [first.as_fd(), second.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(&sender, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("send rights"),
            COMMAND_BYTES
        );
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
            Err(InternalWireError::InvalidDescriptors)
        ));
        assert_eq!(target_count(&first_target), first_baseline);
        assert_eq!(target_count(&second_target), second_baseline);
        rustix::io::fcntl_getfd(&first_write).expect("first writer remains owned");
        rustix::io::fcntl_getfd(&second_write).expect("second writer remains owned");
    }

    #[test]
    fn generated_credentials_and_send_backpressure_are_bounded() {
        let (_sender, receiver) = pair();
        rustix::net::sockopt::set_socket_passcred(&receiver, true).expect("passcred");
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::InvalidTransport)
        ));

        let (sender, _receiver) = pair();
        rustix::net::sockopt::set_socket_send_buffer_size(&sender, 1024)
            .expect("small send buffer");
        let frame = WorkerResponse::new(1, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        let mut filled = false;
        let mut unexpected_error = false;
        for _ in 0..10_000 {
            match send(&sender, &frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    filled = true;
                    break;
                }
                Err(_) => {
                    unexpected_error = true;
                    break;
                }
            }
        }
        assert!(!unexpected_error);
        assert!(filled);
        assert_eq!(
            send_response(
                sender.as_fd(),
                &WorkerResponse::new(2, WorkerResultCode::ProbeLocked),
                Instant::now() + Duration::from_millis(20)
            ),
            Err(InternalWireError::TimedOut)
        );
    }
}
