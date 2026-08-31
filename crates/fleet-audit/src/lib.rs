#![forbid(unsafe_code)]
//! Privacy-minimized, signed Fleet audit events and hash-chain checkpoints.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use kernaid_device_identity::{
    DeviceIdentity, SignedReport, device_id_for_public_key, validate_device_id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub const AUDIT_ENVELOPE_SCHEMA: &str = "dev.kernaid.fleet.audit-envelope.v1";
pub const AUDIT_CHECKPOINT_SCHEMA: &str = "dev.kernaid.fleet.audit-checkpoint.v1";
pub const AUDIT_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:audit:v1\0";
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

const SIGNATURE_BYTES: usize = 64;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024;
const MAX_ID_BYTES: usize = 160;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_EVIDENCE_DIGESTS: usize = 64;

/// Closed audit categories. No free-form event name is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    DiagnosticStarted,
    DiagnosticCompleted,
    RepairProposed,
    AuthorizationDecision,
    RepairStarted,
    RepairCompleted,
    RollbackStarted,
    RollbackCompleted,
    PolicyApplied,
}

/// Closed audit outcome set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Pending,
    Started,
    Allowed,
    Succeeded,
    Failed,
    Denied,
    Cancelled,
}

/// Auditable risk values. R4 can only describe a denied authorization event;
/// it is never admitted for repair or rollback execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditRisk {
    R0,
    R1,
    R2,
    R3,
    R4,
}

/// Unsigned event content. Every observation is either a bounded enum/ID or a
/// digest; there is deliberately no raw text field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEventContent {
    pub tenant_id: String,
    pub session_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub previous_event_sha256: Option<String>,
    pub occurred_at: String,
    pub kind: AuditKind,
    pub outcome: AuditOutcome,
    pub risk: Option<AuditRisk>,
    pub action_id: Option<String>,
    pub target_sha256: Option<String>,
    pub report_sha256: Option<String>,
    pub evidence_sha256: Vec<String>,
}

/// Canonical signed event. It contains neither the public key nor private key
/// material; verification requires caller-owned enrollment anchors.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuditEnvelope {
    schema: String,
    tenant_id: String,
    device_id: String,
    session_id: String,
    event_id: String,
    sequence: u64,
    previous_event_sha256: Option<String>,
    occurred_at: String,
    kind: AuditKind,
    outcome: AuditOutcome,
    risk: Option<AuditRisk>,
    action_id: Option<String>,
    target_sha256: Option<String>,
    report_sha256: Option<String>,
    evidence_sha256: Vec<String>,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedAuditEnvelope<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    session_id: &'a str,
    event_id: &'a str,
    sequence: u64,
    previous_event_sha256: &'a Option<String>,
    occurred_at: &'a str,
    kind: AuditKind,
    outcome: AuditOutcome,
    risk: Option<AuditRisk>,
    action_id: &'a Option<String>,
    target_sha256: &'a Option<String>,
    report_sha256: &'a Option<String>,
    evidence_sha256: &'a [String],
}

impl SignedAuditEnvelope {
    /// Sign with the existing device identity. The seed remains inside the
    /// identity/keychain implementation and is never copied into this crate.
    pub fn sign(
        identity: &DeviceIdentity,
        content: AuditEventContent,
    ) -> Result<Self, FleetAuditError> {
        let mut envelope = Self {
            schema: AUDIT_ENVELOPE_SCHEMA.to_owned(),
            tenant_id: content.tenant_id,
            device_id: identity.device_id(),
            session_id: content.session_id,
            event_id: content.event_id,
            sequence: content.sequence,
            previous_event_sha256: content.previous_event_sha256,
            occurred_at: content.occurred_at,
            kind: content.kind,
            outcome: content.outcome,
            risk: content.risk,
            action_id: content.action_id,
            target_sha256: content.target_sha256,
            report_sha256: content.report_sha256,
            evidence_sha256: content.evidence_sha256,
            signature: String::new(),
        };
        envelope.validate_unsigned_fields()?;
        let unsigned = Zeroizing::new(envelope.unsigned_canonical_json()?);
        let audit_payload = audit_signature_payload(unsigned.as_slice())?;
        let report = identity.sign_report(audit_payload.as_slice());
        envelope.signature = URL_SAFE_NO_PAD.encode(report.signature);
        envelope.validate_fields()?;
        Ok(envelope)
    }

    /// Verify with tenant ID, enrolled device ID, and enrolled public key
    /// supplied independently of this event.
    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; 32],
    ) -> Result<VerifiedAuditEnvelope, FleetAuditError> {
        self.validate_fields()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        validate_device_id(expected_device_id)
            .map_err(|_| FleetAuditError::InvalidField("expectedDeviceId"))?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetAuditError::UnexpectedTenant);
        }
        if self.device_id != expected_device_id
            || device_id_for_public_key(enrolled_public_key) != expected_device_id
        {
            return Err(FleetAuditError::UnexpectedDevice);
        }

        let signature = decode_signature(&self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical_json()?);
        let audit_payload = audit_signature_payload(unsigned.as_slice())?;
        let report = SignedReport {
            payload: audit_payload.to_vec(),
            public_key: *enrolled_public_key,
            signature,
        };
        report
            .verify(enrolled_public_key)
            .map_err(|_| FleetAuditError::InvalidSignature)?;
        let canonical = self.export_offline()?;
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        Ok(VerifiedAuditEnvelope {
            envelope: self.clone(),
            digest,
        })
    }

    /// Export canonical bytes suitable for an authenticated or offline
    /// transport.
    pub fn export_offline(&self) -> Result<Vec<u8>, FleetAuditError> {
        self.validate_fields()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_EVENT_BYTES)?;
        Ok(bytes)
    }

    /// Import exact canonical bytes and authenticate against external anchors.
    /// A successful re-export is byte-identical.
    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; 32],
    ) -> Result<VerifiedAuditEnvelope, FleetAuditError> {
        let envelope: Self = import_canonical(bytes, MAX_EVENT_BYTES)?;
        envelope.verify(expected_tenant_id, expected_device_id, enrolled_public_key)
    }

    /// SHA-256 of the complete canonical signed event, used by the next event.
    pub fn event_sha256(&self) -> Result<String, FleetAuditError> {
        Ok(hex_sha256(&Sha256::digest(self.export_offline()?).into()))
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn previous_event_sha256(&self) -> Option<&str> {
        self.previous_event_sha256.as_deref()
    }

    #[must_use]
    pub const fn kind(&self) -> AuditKind {
        self.kind
    }

    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    fn unsigned(&self) -> UnsignedAuditEnvelope<'_> {
        UnsignedAuditEnvelope {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            session_id: &self.session_id,
            event_id: &self.event_id,
            sequence: self.sequence,
            previous_event_sha256: &self.previous_event_sha256,
            occurred_at: &self.occurred_at,
            kind: self.kind,
            outcome: self.outcome,
            risk: self.risk,
            action_id: &self.action_id,
            target_sha256: &self.target_sha256,
            report_sha256: &self.report_sha256,
            evidence_sha256: &self.evidence_sha256,
        }
    }

    fn unsigned_canonical_json(&self) -> Result<Vec<u8>, FleetAuditError> {
        canonical_json(&self.unsigned())
    }

    fn validate_fields(&self) -> Result<(), FleetAuditError> {
        self.validate_unsigned_fields()?;
        decode_signature(&self.signature)?;
        Ok(())
    }

    fn validate_unsigned_fields(&self) -> Result<(), FleetAuditError> {
        if self.schema != AUDIT_ENVELOPE_SCHEMA {
            return Err(FleetAuditError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetAuditError::InvalidField("deviceId"))?;
        validate_identifier("sessionId", &self.session_id)?;
        validate_identifier("eventId", &self.event_id)?;
        validate_sequence_and_chain(self.sequence, self.previous_event_sha256.as_deref())?;
        validate_timestamp(&self.occurred_at)?;
        validate_kind_outcome(self.kind, self.outcome)?;
        validate_action(
            self.kind,
            self.outcome,
            self.risk,
            self.action_id.as_deref(),
        )?;
        validate_optional_sha256("targetSha256", self.target_sha256.as_deref())?;
        validate_optional_sha256("reportSha256", self.report_sha256.as_deref())?;
        validate_evidence_digests(&self.evidence_sha256)
    }
}

impl fmt::Debug for SignedAuditEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuditEnvelope")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("session_id", &self.session_id)
            .field("event_id", &self.event_id)
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("risk", &self.risk)
            .finish_non_exhaustive()
    }
}

/// Authenticated event accepted for hash-chain admission.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedAuditEnvelope {
    envelope: SignedAuditEnvelope,
    digest: [u8; 32],
}

impl VerifiedAuditEnvelope {
    #[must_use]
    pub fn envelope(&self) -> &SignedAuditEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub fn event_sha256(&self) -> String {
        hex_sha256(&self.digest)
    }

    pub fn export_offline(&self) -> Result<Vec<u8>, FleetAuditError> {
        self.envelope.export_offline()
    }
}

impl fmt::Debug for VerifiedAuditEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuditEnvelope")
            .field("event_id", &self.envelope.event_id)
            .field("sequence", &self.envelope.sequence)
            .field("kind", &self.envelope.kind)
            .finish_non_exhaustive()
    }
}

/// Durable tail of one tenant/device/session audit chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditChainCheckpoint {
    schema: String,
    tenant_id: String,
    device_id: String,
    session_id: String,
    last_sequence: u64,
    last_event_sha256: String,
}

impl AuditChainCheckpoint {
    /// Start only from the authenticated first event in a session.
    pub fn start(first: &VerifiedAuditEnvelope) -> Result<Self, FleetAuditError> {
        if first.envelope.sequence != 1 || first.envelope.previous_event_sha256.is_some() {
            return Err(FleetAuditError::InvalidChainStart);
        }
        Ok(Self {
            schema: AUDIT_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: first.envelope.tenant_id.clone(),
            device_id: first.envelope.device_id.clone(),
            session_id: first.envelope.session_id.clone(),
            last_sequence: 1,
            last_event_sha256: first.event_sha256(),
        })
    }

    /// Admit the exact next event, or recognize an exact latest-event replay.
    pub fn admit(
        &mut self,
        event: &VerifiedAuditEnvelope,
    ) -> Result<ChainAdmission, FleetAuditError> {
        self.validate()?;
        if self.tenant_id != event.envelope.tenant_id
            || self.device_id != event.envelope.device_id
            || self.session_id != event.envelope.session_id
        {
            return Err(FleetAuditError::UnexpectedChain);
        }
        let digest = event.event_sha256();
        if event.envelope.sequence == self.last_sequence {
            if digest == self.last_event_sha256 {
                return Ok(ChainAdmission::IdempotentReplay);
            }
            return Err(FleetAuditError::ChainFork);
        }
        let expected_sequence = self
            .last_sequence
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER)
            .ok_or(FleetAuditError::SequenceExhausted)?;
        if event.envelope.sequence != expected_sequence {
            return Err(FleetAuditError::NonContiguousSequence);
        }
        if event.envelope.previous_event_sha256.as_deref() != Some(&self.last_event_sha256) {
            return Err(FleetAuditError::ChainFork);
        }
        self.last_sequence = event.envelope.sequence;
        self.last_event_sha256 = digest;
        Ok(ChainAdmission::Advanced)
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, FleetAuditError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_CHECKPOINT_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, FleetAuditError> {
        let checkpoint: Self = import_canonical(bytes, MAX_CHECKPOINT_BYTES)?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn last_event_sha256(&self) -> &str {
        &self.last_event_sha256
    }

    fn validate(&self) -> Result<(), FleetAuditError> {
        if self.schema != AUDIT_CHECKPOINT_SCHEMA {
            return Err(FleetAuditError::InvalidField("checkpoint.schema"));
        }
        validate_identifier("checkpoint.tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetAuditError::InvalidField("checkpoint.deviceId"))?;
        validate_identifier("checkpoint.sessionId", &self.session_id)?;
        validate_safe_nonzero("checkpoint.lastSequence", self.last_sequence)?;
        validate_sha256("checkpoint.lastEventSha256", &self.last_event_sha256)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAdmission {
    Advanced,
    IdempotentReplay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FleetAuditError {
    InvalidField(&'static str),
    InvalidEventSemantics,
    InvalidJson,
    UnsupportedJsonValue,
    UnsafeInteger,
    NonCanonicalJson,
    EventTooLarge,
    InvalidSignature,
    UnexpectedTenant,
    UnexpectedDevice,
    InvalidChainStart,
    UnexpectedChain,
    NonContiguousSequence,
    ChainFork,
    SequenceExhausted,
}

impl fmt::Display for FleetAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid Fleet audit field: {field}"),
            Self::InvalidEventSemantics => formatter.write_str("invalid Fleet audit semantics"),
            Self::InvalidJson => formatter.write_str("invalid Fleet audit JSON"),
            Self::UnsupportedJsonValue => formatter.write_str("unsupported Fleet audit JSON value"),
            Self::UnsafeInteger => formatter.write_str("unsafe Fleet audit JSON integer"),
            Self::NonCanonicalJson => formatter.write_str("Fleet audit JSON is not canonical"),
            Self::EventTooLarge => formatter.write_str("Fleet audit document is too large"),
            Self::InvalidSignature => formatter.write_str("invalid Fleet audit signature"),
            Self::UnexpectedTenant => formatter.write_str("unexpected Fleet audit tenant"),
            Self::UnexpectedDevice => formatter.write_str("unexpected Fleet audit device"),
            Self::InvalidChainStart => formatter.write_str("invalid Fleet audit chain start"),
            Self::UnexpectedChain => formatter.write_str("unexpected Fleet audit chain"),
            Self::NonContiguousSequence => {
                formatter.write_str("non-contiguous Fleet audit sequence")
            }
            Self::ChainFork => formatter.write_str("Fleet audit chain fork"),
            Self::SequenceExhausted => formatter.write_str("Fleet audit sequence exhausted"),
        }
    }
}

impl std::error::Error for FleetAuditError {}

fn validate_sequence_and_chain(
    sequence: u64,
    previous_event_sha256: Option<&str>,
) -> Result<(), FleetAuditError> {
    validate_safe_nonzero("sequence", sequence)?;
    match (sequence, previous_event_sha256) {
        (1, None) => Ok(()),
        (1, Some(_)) | (_, None) => Err(FleetAuditError::InvalidField("previousEventSha256")),
        (_, Some(digest)) => validate_sha256("previousEventSha256", digest),
    }
}

fn validate_kind_outcome(kind: AuditKind, outcome: AuditOutcome) -> Result<(), FleetAuditError> {
    let valid = match kind {
        AuditKind::DiagnosticStarted | AuditKind::RepairStarted | AuditKind::RollbackStarted => {
            outcome == AuditOutcome::Started
        }
        AuditKind::DiagnosticCompleted
        | AuditKind::RepairCompleted
        | AuditKind::RollbackCompleted => matches!(
            outcome,
            AuditOutcome::Succeeded | AuditOutcome::Failed | AuditOutcome::Cancelled
        ),
        AuditKind::RepairProposed => outcome == AuditOutcome::Pending,
        AuditKind::AuthorizationDecision => {
            matches!(outcome, AuditOutcome::Allowed | AuditOutcome::Denied)
        }
        AuditKind::PolicyApplied => {
            matches!(outcome, AuditOutcome::Succeeded | AuditOutcome::Failed)
        }
    };
    if !valid {
        return Err(FleetAuditError::InvalidEventSemantics);
    }
    Ok(())
}

fn validate_action(
    kind: AuditKind,
    outcome: AuditOutcome,
    risk: Option<AuditRisk>,
    action_id: Option<&str>,
) -> Result<(), FleetAuditError> {
    if let Some(action_id) = action_id {
        validate_identifier("actionId", action_id)?;
    }
    let action_required = matches!(
        kind,
        AuditKind::RepairProposed
            | AuditKind::AuthorizationDecision
            | AuditKind::RepairStarted
            | AuditKind::RepairCompleted
            | AuditKind::RollbackStarted
            | AuditKind::RollbackCompleted
    );
    if action_required && (action_id.is_none() || risk.is_none()) {
        return Err(FleetAuditError::InvalidEventSemantics);
    }
    if risk == Some(AuditRisk::R4)
        && !(kind == AuditKind::AuthorizationDecision && outcome == AuditOutcome::Denied)
    {
        return Err(FleetAuditError::InvalidEventSemantics);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), FleetAuditError> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || DateTime::parse_from_rfc3339(value).is_err()
    {
        return Err(FleetAuditError::InvalidField("occurredAt"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FleetAuditError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(FleetAuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_safe_nonzero(field: &'static str, value: u64) -> Result<(), FleetAuditError> {
    if value == 0 || value > MAX_SAFE_JSON_INTEGER {
        return Err(FleetAuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_optional_sha256(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), FleetAuditError> {
    if let Some(value) = value {
        validate_sha256(field, value)?;
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), FleetAuditError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FleetAuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_evidence_digests(values: &[String]) -> Result<(), FleetAuditError> {
    if values.len() > MAX_EVIDENCE_DIGESTS {
        return Err(FleetAuditError::InvalidField("evidenceSha256"));
    }
    for value in values {
        validate_sha256("evidenceSha256", value)?;
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(FleetAuditError::InvalidField("evidenceSha256"));
    }
    Ok(())
}

fn decode_signature(encoded: &str) -> Result<[u8; SIGNATURE_BYTES], FleetAuditError> {
    if encoded.contains('=') || encoded.len() != 86 {
        return Err(FleetAuditError::InvalidField("signature"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| FleetAuditError::InvalidField("signature"))?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(FleetAuditError::InvalidField("signature"));
    }
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| FleetAuditError::InvalidField("signature"))
}

fn audit_signature_payload(canonical: &[u8]) -> Result<Zeroizing<Vec<u8>>, FleetAuditError> {
    let length = u64::try_from(canonical.len()).map_err(|_| FleetAuditError::EventTooLarge)?;
    let capacity = AUDIT_SIGNATURE_DOMAIN
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(canonical.len()))
        .ok_or(FleetAuditError::EventTooLarge)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
    payload.extend_from_slice(AUDIT_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(canonical);
    Ok(payload)
}

fn hex_sha256(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn validate_size(actual: usize, maximum: usize) -> Result<(), FleetAuditError> {
    if actual == 0 || actual > maximum {
        return Err(FleetAuditError::EventTooLarge);
    }
    Ok(())
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, FleetAuditError>
where
    T: DeserializeOwned + Serialize,
{
    validate_size(bytes.len(), maximum)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FleetAuditError::InvalidJson)?;
    validate_json_value(&value)?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| FleetAuditError::InvalidJson)?;
    if canonical_json(&parsed)? != bytes {
        return Err(FleetAuditError::NonCanonicalJson);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FleetAuditError> {
    let value = serde_json::to_value(value).map_err(|_| FleetAuditError::InvalidJson)?;
    validate_json_value(&value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn validate_json_value(value: &Value) -> Result<(), FleetAuditError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                if value <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetAuditError::UnsafeInteger)
                }
            } else if let Some(value) = number.as_i64() {
                if value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetAuditError::UnsafeInteger)
                }
            } else {
                Err(FleetAuditError::UnsupportedJsonValue)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(values) => values.values().try_for_each(validate_json_value),
    }
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), FleetAuditError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|_| FleetAuditError::InvalidJson)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded =
                    serde_json::to_string(key).map_err(|_| FleetAuditError::InvalidJson)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_value(
                    values.get(key).ok_or(FleetAuditError::InvalidJson)?,
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TENANT: &str = "tenant-europe-1";
    const SESSION: &str = "session-20260831-001";
    const OCCURRED_AT: &str = "2026-08-31T14:15:16Z";
    const ACTION: &str = "linux.fstab.disable-missing-uuid.v1";

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x71; 32]).expect("fixed audit identity")
    }

    fn digest(value: &[u8]) -> String {
        hex_sha256(&Sha256::digest(value).into())
    }

    fn first_content() -> AuditEventContent {
        AuditEventContent {
            tenant_id: TENANT.to_owned(),
            session_id: SESSION.to_owned(),
            event_id: "event-0001".to_owned(),
            sequence: 1,
            previous_event_sha256: None,
            occurred_at: OCCURRED_AT.to_owned(),
            kind: AuditKind::DiagnosticStarted,
            outcome: AuditOutcome::Started,
            risk: Some(AuditRisk::R0),
            action_id: None,
            target_sha256: Some(digest(b"target")),
            report_sha256: None,
            evidence_sha256: Vec::new(),
        }
    }

    fn next_content(
        previous: &SignedAuditEnvelope,
        sequence: u64,
        event_id: &str,
    ) -> AuditEventContent {
        let mut evidence_sha256 = vec![digest(b"evidence-a"), digest(b"evidence-b")];
        evidence_sha256.sort_unstable();
        AuditEventContent {
            tenant_id: TENANT.to_owned(),
            session_id: SESSION.to_owned(),
            event_id: event_id.to_owned(),
            sequence,
            previous_event_sha256: Some(previous.event_sha256().expect("previous digest")),
            occurred_at: OCCURRED_AT.to_owned(),
            kind: AuditKind::DiagnosticCompleted,
            outcome: AuditOutcome::Succeeded,
            risk: Some(AuditRisk::R0),
            action_id: None,
            target_sha256: Some(digest(b"target")),
            report_sha256: Some(digest(b"report")),
            evidence_sha256,
        }
    }

    fn verify(envelope: &SignedAuditEnvelope) -> Result<VerifiedAuditEnvelope, FleetAuditError> {
        let identity = identity();
        envelope.verify(TENANT, &identity.device_id(), &identity.public_key())
    }

    #[test]
    fn signature_external_anchors_and_offline_replay_verify() {
        let identity = identity();
        let signed = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign event");
        let bytes = signed.export_offline().expect("export event");
        let verified = SignedAuditEnvelope::import_offline(
            &bytes,
            TENANT,
            &identity.device_id(),
            &identity.public_key(),
        )
        .expect("import event");
        assert_eq!(verified.envelope().sequence(), 1);
        assert_eq!(verified.export_offline().expect("re-export event"), bytes);
        assert_eq!(
            verified.event_sha256(),
            signed.event_sha256().expect("event digest")
        );
        assert!(
            std::str::from_utf8(&bytes)
                .expect("event UTF-8")
                .starts_with("{\"actionId\":null,\"deviceId\":")
        );
    }

    #[test]
    fn tamper_and_external_anchor_substitution_fail() {
        let identity = identity();
        let signed = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign event");
        let bytes = signed.export_offline().expect("export event");
        let mut value: Value = serde_json::from_slice(&bytes).expect("parse event");
        value["eventId"] = json!("event-tampered");
        let tampered = canonical_json(&value).expect("canonical tamper");
        assert_eq!(
            SignedAuditEnvelope::import_offline(
                &tampered,
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetAuditError::InvalidSignature)
        );

        let other = DeviceIdentity::from_seed(&[0x17; 32]).expect("other identity");
        assert_eq!(
            signed.verify(TENANT, &identity.device_id(), &other.public_key()),
            Err(FleetAuditError::UnexpectedDevice)
        );
        assert_eq!(
            signed.verify(
                "tenant-other",
                &identity.device_id(),
                &identity.public_key()
            ),
            Err(FleetAuditError::UnexpectedTenant)
        );
    }

    #[test]
    fn hash_chain_is_contiguous_and_replay_idempotent() {
        let identity = identity();
        let first = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign first");
        let first_verified = verify(&first).expect("verify first");
        let mut checkpoint = AuditChainCheckpoint::start(&first_verified).expect("start chain");
        assert_eq!(
            checkpoint.admit(&first_verified),
            Ok(ChainAdmission::IdempotentReplay)
        );

        let second = SignedAuditEnvelope::sign(&identity, next_content(&first, 2, "event-0002"))
            .expect("sign second");
        let second_verified = verify(&second).expect("verify second");
        assert_eq!(
            checkpoint.admit(&second_verified),
            Ok(ChainAdmission::Advanced)
        );
        assert_eq!(checkpoint.last_sequence(), 2);

        let gap = SignedAuditEnvelope::sign(&identity, next_content(&second, 4, "event-0004"))
            .expect("sign gap");
        assert_eq!(
            checkpoint.admit(&verify(&gap).expect("verify gap")),
            Err(FleetAuditError::NonContiguousSequence)
        );

        let bytes = checkpoint.export_canonical().expect("export checkpoint");
        let restored = AuditChainCheckpoint::import_canonical(&bytes).expect("import checkpoint");
        assert_eq!(
            restored.export_canonical().expect("re-export checkpoint"),
            bytes
        );
    }

    #[test]
    fn wrong_previous_digest_is_a_chain_fork() {
        let identity = identity();
        let first = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign first");
        let mut checkpoint =
            AuditChainCheckpoint::start(&verify(&first).expect("verify first")).expect("start");
        let mut fork = next_content(&first, 2, "event-fork");
        fork.previous_event_sha256 = Some(digest(b"different previous"));
        let fork = SignedAuditEnvelope::sign(&identity, fork).expect("sign fork");
        assert_eq!(
            checkpoint.admit(&verify(&fork).expect("verify fork")),
            Err(FleetAuditError::ChainFork)
        );
    }

    #[test]
    fn diagnostics_and_rollback_have_closed_representations() {
        let identity = identity();
        let first = SignedAuditEnvelope::sign(&identity, first_content()).expect("diagnostic");
        assert_eq!(first.kind(), AuditKind::DiagnosticStarted);

        let rollback = AuditEventContent {
            kind: AuditKind::RollbackStarted,
            outcome: AuditOutcome::Started,
            risk: Some(AuditRisk::R2),
            action_id: Some("linux.fstab.restore".to_owned()),
            ..next_content(&first, 2, "event-rollback")
        };
        let rollback = SignedAuditEnvelope::sign(&identity, rollback).expect("rollback event");
        assert_eq!(rollback.kind(), AuditKind::RollbackStarted);
        assert_eq!(rollback.outcome(), AuditOutcome::Started);
        verify(&rollback).expect("verify rollback");
    }

    #[test]
    fn r4_can_only_record_a_denied_authorization_not_execution() {
        let identity = identity();
        let first = SignedAuditEnvelope::sign(&identity, first_content()).expect("first");
        let denied = AuditEventContent {
            kind: AuditKind::AuthorizationDecision,
            outcome: AuditOutcome::Denied,
            risk: Some(AuditRisk::R4),
            action_id: Some(ACTION.to_owned()),
            ..next_content(&first, 2, "event-r4-denied")
        };
        SignedAuditEnvelope::sign(&identity, denied).expect("record denied R4");

        let executing = AuditEventContent {
            kind: AuditKind::RepairStarted,
            outcome: AuditOutcome::Started,
            risk: Some(AuditRisk::R4),
            action_id: Some(ACTION.to_owned()),
            ..next_content(&first, 2, "event-r4-execution")
        };
        assert_eq!(
            SignedAuditEnvelope::sign(&identity, executing),
            Err(FleetAuditError::InvalidEventSemantics)
        );
    }

    #[test]
    fn canonical_parser_rejects_unknown_float_unsafe_and_noncanonical_input() {
        let identity = identity();
        let signed = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign event");
        let bytes = signed.export_offline().expect("export event");

        let mut prefixed = b" \n".to_vec();
        prefixed.extend_from_slice(&bytes);
        assert_eq!(
            SignedAuditEnvelope::import_offline(
                &prefixed,
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetAuditError::NonCanonicalJson)
        );

        let mut unknown: Value = serde_json::from_slice(&bytes).expect("parse event");
        unknown["rawLog"] = json!("secret log");
        let unknown = canonical_json(&unknown).expect("canonical unknown");
        assert_eq!(
            SignedAuditEnvelope::import_offline(
                &unknown,
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetAuditError::InvalidJson)
        );

        let unsafe_integer = std::str::from_utf8(&bytes)
            .expect("event UTF-8")
            .replace("\"sequence\":1", "\"sequence\":9007199254740992");
        assert_eq!(
            SignedAuditEnvelope::import_offline(
                unsafe_integer.as_bytes(),
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetAuditError::UnsafeInteger)
        );

        let float = unsafe_integer.replace("9007199254740992", "1.5");
        assert_eq!(
            SignedAuditEnvelope::import_offline(
                float.as_bytes(),
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetAuditError::UnsupportedJsonValue)
        );
    }

    #[test]
    fn wire_has_digests_only_and_never_serializes_seed_or_raw_content() {
        let identity = identity();
        let signed = SignedAuditEnvelope::sign(&identity, first_content()).expect("sign event");
        let bytes = signed.export_offline().expect("export event");
        let text = std::str::from_utf8(&bytes).expect("event UTF-8");
        let seed = [0x71_u8; 32];
        let seed_hex = seed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let seed_base64url = URL_SAFE_NO_PAD.encode(seed);
        for forbidden in [
            "rawLog",
            "message",
            "hostname",
            "username",
            "email",
            "path",
            "credential",
            "reportBody",
            "evidenceBody",
            "privateKey",
            "publicKey",
            "seed",
        ] {
            assert!(!text.contains(forbidden));
        }
        assert!(!text.contains(&seed_hex));
        assert!(!text.contains(&seed_base64url));
        assert!(!format!("{signed:?}").contains(&signed.signature));
        assert!(!format!("{signed:?}").contains(&digest(b"target")));
    }

    #[test]
    fn bounds_chain_shape_and_sorted_digest_rules_fail_closed() {
        let identity = identity();
        let mut invalid_first = first_content();
        invalid_first.previous_event_sha256 = Some(digest(b"impossible previous"));
        assert_eq!(
            SignedAuditEnvelope::sign(&identity, invalid_first),
            Err(FleetAuditError::InvalidField("previousEventSha256"))
        );

        let first = SignedAuditEnvelope::sign(&identity, first_content()).expect("first");
        let mut unsorted = next_content(&first, 2, "event-unsorted");
        unsorted.evidence_sha256.reverse();
        assert_eq!(
            SignedAuditEnvelope::sign(&identity, unsorted),
            Err(FleetAuditError::InvalidField("evidenceSha256"))
        );

        let missing_action = AuditEventContent {
            kind: AuditKind::RepairStarted,
            outcome: AuditOutcome::Started,
            risk: Some(AuditRisk::R2),
            action_id: None,
            ..next_content(&first, 2, "event-no-action")
        };
        assert_eq!(
            SignedAuditEnvelope::sign(&identity, missing_action),
            Err(FleetAuditError::InvalidEventSemantics)
        );
    }

    #[test]
    fn audit_payload_binds_domain_and_big_endian_length() {
        let envelope = SignedAuditEnvelope::sign(&identity(), first_content()).expect("event");
        let unsigned = envelope
            .unsigned_canonical_json()
            .expect("canonical unsigned event");
        let payload = audit_signature_payload(&unsigned).expect("audit payload");
        assert_eq!(
            &payload[..AUDIT_SIGNATURE_DOMAIN.len()],
            AUDIT_SIGNATURE_DOMAIN
        );
        assert_eq!(
            &payload[AUDIT_SIGNATURE_DOMAIN.len()..AUDIT_SIGNATURE_DOMAIN.len() + 8],
            &(unsigned.len() as u64).to_be_bytes()
        );
        assert_eq!(
            &payload[AUDIT_SIGNATURE_DOMAIN.len() + 8..],
            unsigned.as_slice()
        );
    }
}
