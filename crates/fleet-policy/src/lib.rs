#![forbid(unsafe_code)]
//! Signed, offline-capable Fleet policy restrictions.
//!
//! This crate has no broker dependency and creates no mutation authority. It
//! verifies a tenant policy, prevents revision rollback, and intersects Fleet
//! rules with a caller-supplied local safety floor.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeOwned, ser::SerializeMap,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Signed policy schema identifier.
pub const POLICY_BUNDLE_SCHEMA: &str = "dev.kernaid.fleet.policy-bundle.v1";
/// Checkpoint persistence schema identifier.
pub const POLICY_CHECKPOINT_SCHEMA: &str = "dev.kernaid.fleet.policy-checkpoint.v1";
/// Exact signature domain, including its terminal NUL separator.
pub const POLICY_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:policy:v1\0";
/// Largest JSON integer that round-trips exactly across supported clients.
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum accepted retention period.
pub const MAX_RETENTION_DAYS: u16 = 3_650;

const SIGNATURE_BYTES: usize = 64;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024;
const MAX_ID_BYTES: usize = 160;
const MAX_ASSIGNED_DEVICES: usize = 4_096;
const MAX_ACTION_IDS: usize = 1_024;

/// Fleet risk values. R4 is intentionally not representable by this v1 wire
/// contract; a caller maps an unknown or higher local risk to `None` and the
/// evaluator denies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    R0,
    R1,
    R2,
    R3,
}

/// Provider execution modes that Fleet may remove from the local set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Offline,
    OpenaiApi,
    OpenaiCompatible,
    Enterprise,
}

impl ProviderMode {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::OpenaiApi => "openai_api",
            Self::OpenaiCompatible => "openai_compatible",
            Self::Enterprise => "enterprise",
        }
    }
}

/// Device update channel selected by Fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateRing {
    Hold,
    Canary,
    Stable,
}

/// Policy target set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assignments {
    All,
    DeviceIds(Vec<String>),
}

impl Assignments {
    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    #[must_use]
    pub fn device_ids(device_ids: Vec<String>) -> Self {
        Self::DeviceIds(device_ids)
    }

    #[must_use]
    pub fn applies_to(&self, device_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::DeviceIds(device_ids) => device_ids
                .binary_search_by(|candidate| candidate.as_str().cmp(device_id))
                .is_ok(),
        }
    }
}

impl Serialize for Assignments {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::All => map.serialize_entry("all", &true)?,
            Self::DeviceIds(device_ids) => map.serialize_entry("deviceIds", device_ids)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Assignments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireAssignments {
            all: Option<bool>,
            device_ids: Option<Vec<String>>,
        }

        let wire = WireAssignments::deserialize(deserializer)?;
        match (wire.all, wire.device_ids) {
            (Some(true), None) => Ok(Self::All),
            (None, Some(device_ids)) => Ok(Self::DeviceIds(device_ids)),
            _ => Err(de::Error::custom("invalid Fleet policy assignments")),
        }
    }
}

/// Restrictive Fleet rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyRules {
    pub max_risk: RiskLevel,
    pub local_approval_from: RiskLevel,
    pub allowed_action_ids: Vec<String>,
    pub denied_action_ids: Vec<String>,
    pub allow_evidence_upload: bool,
    pub retention_days: u16,
    pub provider_modes: Vec<ProviderMode>,
    pub update_ring: UpdateRing,
    pub emergency_rollback_always_allowed: bool,
}

/// Unsigned policy content supplied to the central signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBundleContent {
    pub tenant_id: String,
    pub policy_id: String,
    pub revision: u64,
    pub issued_at_unix: u64,
    pub not_before_unix: u64,
    pub offline_allowed_until_unix: u64,
    pub expires_at_unix: u64,
    pub assignments: Assignments,
    pub rules: PolicyRules,
}

/// Signed policy wire document. The public key is deliberately absent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPolicyBundle {
    schema: String,
    tenant_id: String,
    policy_id: String,
    revision: u64,
    issued_at_unix: u64,
    not_before_unix: u64,
    offline_allowed_until_unix: u64,
    expires_at_unix: u64,
    assignments: Assignments,
    rules: PolicyRules,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPolicyBundle<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    policy_id: &'a str,
    revision: u64,
    issued_at_unix: u64,
    not_before_unix: u64,
    offline_allowed_until_unix: u64,
    expires_at_unix: u64,
    assignments: &'a Assignments,
    rules: &'a PolicyRules,
}

impl SignedPolicyBundle {
    /// Create a centrally signed bundle. Devices should normally only call
    /// [`Self::import_and_verify`].
    pub fn sign(
        content: PolicyBundleContent,
        signing_key: &SigningKey,
    ) -> Result<Self, FleetPolicyError> {
        let mut bundle = Self {
            schema: POLICY_BUNDLE_SCHEMA.to_owned(),
            tenant_id: content.tenant_id,
            policy_id: content.policy_id,
            revision: content.revision,
            issued_at_unix: content.issued_at_unix,
            not_before_unix: content.not_before_unix,
            offline_allowed_until_unix: content.offline_allowed_until_unix,
            expires_at_unix: content.expires_at_unix,
            assignments: content.assignments,
            rules: content.rules,
            signature: String::new(),
        };
        bundle.validate_unsigned_fields()?;
        let unsigned = Zeroizing::new(bundle.unsigned_canonical_json()?);
        let message = policy_signature_message(unsigned.as_slice())?;
        bundle.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(message.as_slice()).to_bytes());
        bundle.validate_fields()?;
        Ok(bundle)
    }

    /// Verify against an external tenant trust anchor and tenant binding.
    pub fn verify(
        &self,
        trust_anchor: &VerifyingKey,
        expected_tenant_id: &str,
    ) -> Result<VerifiedPolicyBundle, FleetPolicyError> {
        self.validate_fields()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetPolicyError::UnexpectedTenant);
        }
        let signature = decode_signature(&self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical_json()?);
        let message = policy_signature_message(unsigned.as_slice())?;
        trust_anchor
            .verify_strict(message.as_slice(), &Signature::from_bytes(&signature))
            .map_err(|_| FleetPolicyError::InvalidSignature)?;
        let canonical = self.export_canonical()?;
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        Ok(VerifiedPolicyBundle {
            bundle: self.clone(),
            digest,
        })
    }

    /// Serialize exact canonical JSON for online or offline transport.
    pub fn export_canonical(&self) -> Result<Vec<u8>, FleetPolicyError> {
        self.validate_fields()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_POLICY_BYTES)?;
        Ok(bytes)
    }

    /// Parse canonical bytes, reject unknown/unsafe values, and verify with an
    /// external tenant trust anchor.
    pub fn import_and_verify(
        bytes: &[u8],
        trust_anchor: &VerifyingKey,
        expected_tenant_id: &str,
    ) -> Result<VerifiedPolicyBundle, FleetPolicyError> {
        let bundle: Self = import_canonical(bytes, MAX_POLICY_BYTES)?;
        bundle.verify(trust_anchor, expected_tenant_id)
    }

    fn unsigned(&self) -> UnsignedPolicyBundle<'_> {
        UnsignedPolicyBundle {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            policy_id: &self.policy_id,
            revision: self.revision,
            issued_at_unix: self.issued_at_unix,
            not_before_unix: self.not_before_unix,
            offline_allowed_until_unix: self.offline_allowed_until_unix,
            expires_at_unix: self.expires_at_unix,
            assignments: &self.assignments,
            rules: &self.rules,
        }
    }

    fn unsigned_canonical_json(&self) -> Result<Vec<u8>, FleetPolicyError> {
        canonical_json(&self.unsigned())
    }

    fn validate_fields(&self) -> Result<(), FleetPolicyError> {
        self.validate_unsigned_fields()?;
        decode_signature(&self.signature)?;
        Ok(())
    }

    fn validate_unsigned_fields(&self) -> Result<(), FleetPolicyError> {
        if self.schema != POLICY_BUNDLE_SCHEMA {
            return Err(FleetPolicyError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_identifier("policyId", &self.policy_id)?;
        validate_safe_nonzero("revision", self.revision)?;
        validate_safe_nonzero("issuedAtUnix", self.issued_at_unix)?;
        validate_safe_nonzero("notBeforeUnix", self.not_before_unix)?;
        validate_safe_nonzero("offlineAllowedUntilUnix", self.offline_allowed_until_unix)?;
        validate_safe_nonzero("expiresAtUnix", self.expires_at_unix)?;
        if self.issued_at_unix > self.not_before_unix
            || self.not_before_unix > self.offline_allowed_until_unix
            || self.offline_allowed_until_unix > self.expires_at_unix
        {
            return Err(FleetPolicyError::InvalidTimeWindow);
        }
        validate_assignments(&self.assignments)?;
        validate_rules(&self.rules)
    }
}

impl fmt::Debug for SignedPolicyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPolicyBundle")
            .field("tenant_id", &self.tenant_id)
            .field("policy_id", &self.policy_id)
            .field("revision", &self.revision)
            .field("not_before_unix", &self.not_before_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

/// Authenticated policy that may be evaluated or admitted to a checkpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPolicyBundle {
    bundle: SignedPolicyBundle,
    digest: [u8; 32],
}

impl VerifiedPolicyBundle {
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.bundle.tenant_id
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.bundle.policy_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.bundle.revision
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub const fn rules(&self) -> &PolicyRules {
        &self.bundle.rules
    }

    /// Evaluate an action by intersecting Fleet restrictions with local Core
    /// and broker facts. This method grants no execution capability.
    #[must_use]
    pub fn evaluate(&self, request: &PolicyEvaluation<'_>) -> PolicyDecision {
        if request.now_unix == 0
            || request.now_unix > MAX_SAFE_JSON_INTEGER
            || validate_device_id(request.device_id).is_err()
            || validate_identifier("actionId", request.action_id).is_err()
        {
            return PolicyDecision::Denied(DenyReason::InvalidLocalContext);
        }
        if !request.locally_known {
            return PolicyDecision::Denied(DenyReason::UnknownLocalAction);
        }
        if !request.locally_allowed {
            return PolicyDecision::Denied(DenyReason::LocallyDenied);
        }
        let Some(action_risk) = request.action_risk else {
            return PolicyDecision::Denied(DenyReason::UnknownOrUnsupportedRisk);
        };
        if action_risk > request.local_max_risk {
            return PolicyDecision::Denied(DenyReason::ExceedsLocalRiskCeiling);
        }

        match request.operation {
            PolicyOperation::Diagnostic => PolicyDecision::DiagnosticsAllowed,
            PolicyOperation::StartedRollback => PolicyDecision::StartedRollbackAllowed {
                audit_required: true,
            },
            PolicyOperation::NewRepair => self.evaluate_new_repair(request, action_risk),
        }
    }

    fn evaluate_new_repair(
        &self,
        request: &PolicyEvaluation<'_>,
        action_risk: RiskLevel,
    ) -> PolicyDecision {
        if !self.bundle.assignments.applies_to(request.device_id) {
            return PolicyDecision::Denied(DenyReason::DeviceNotAssigned);
        }
        if request.now_unix < self.bundle.not_before_unix {
            return PolicyDecision::Denied(DenyReason::PolicyNotYetValid);
        }
        if request.now_unix >= self.bundle.expires_at_unix {
            return PolicyDecision::Denied(DenyReason::PolicyExpired);
        }
        if request.transport == TransportState::Offline
            && request.now_unix > self.bundle.offline_allowed_until_unix
        {
            return PolicyDecision::Denied(DenyReason::OfflineWindowElapsed);
        }
        if action_risk > self.bundle.rules.max_risk {
            return PolicyDecision::Denied(DenyReason::ExceedsFleetRiskCeiling);
        }
        if contains_sorted(&self.bundle.rules.denied_action_ids, request.action_id) {
            return PolicyDecision::Denied(DenyReason::FleetDeniedAction);
        }
        if !contains_sorted(&self.bundle.rules.allowed_action_ids, request.action_id) {
            return PolicyDecision::Denied(DenyReason::ActionNotFleetAllowed);
        }

        let effective_approval_from = request
            .local_approval_from
            .min(self.bundle.rules.local_approval_from);
        PolicyDecision::NewRepairAllowed {
            local_approval_required: action_risk >= effective_approval_from,
            audit_required: true,
        }
    }

    /// Fleet and local policy must both permit evidence upload.
    #[must_use]
    pub fn evidence_upload_allowed(&self, locally_allowed: bool) -> bool {
        locally_allowed && self.bundle.rules.allow_evidence_upload
    }

    /// Fleet retention can only shorten the local maximum.
    #[must_use]
    pub fn effective_retention_days(&self, local_maximum_days: u16) -> u16 {
        local_maximum_days.min(self.bundle.rules.retention_days)
    }

    /// Fleet and local policy must both permit a provider mode.
    #[must_use]
    pub fn provider_mode_allowed(&self, mode: ProviderMode, locally_allowed: bool) -> bool {
        locally_allowed && self.bundle.rules.provider_modes.contains(&mode)
    }

    #[must_use]
    pub const fn update_ring(&self) -> UpdateRing {
        self.bundle.rules.update_ring
    }
}

impl fmt::Debug for VerifiedPolicyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPolicyBundle")
            .field("tenant_id", &self.bundle.tenant_id)
            .field("policy_id", &self.bundle.policy_id)
            .field("revision", &self.bundle.revision)
            .finish_non_exhaustive()
    }
}

/// Durable anti-rollback state for one tenant policy stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyCheckpoint {
    schema: String,
    tenant_id: String,
    policy_id: String,
    revision: u64,
    bundle_sha256: String,
}

impl PolicyCheckpoint {
    #[must_use]
    pub fn from_verified(policy: &VerifiedPolicyBundle) -> Self {
        Self {
            schema: POLICY_CHECKPOINT_SCHEMA.to_owned(),
            tenant_id: policy.tenant_id().to_owned(),
            policy_id: policy.policy_id().to_owned(),
            revision: policy.revision(),
            bundle_sha256: hex_sha256(policy.digest()),
        }
    }

    /// Admit only a monotonic revision. Equal revision and digest is a safe,
    /// idempotent replay; equal revision with different bytes is rejected.
    pub fn admit(
        &mut self,
        policy: &VerifiedPolicyBundle,
    ) -> Result<CheckpointAdmission, FleetPolicyError> {
        self.validate()?;
        if self.tenant_id != policy.tenant_id() {
            return Err(FleetPolicyError::UnexpectedTenant);
        }
        if self.policy_id != policy.policy_id() {
            return Err(FleetPolicyError::UnexpectedPolicy);
        }
        if policy.revision() < self.revision {
            return Err(FleetPolicyError::RevisionRollback);
        }
        let digest = hex_sha256(policy.digest());
        if policy.revision() == self.revision {
            if digest == self.bundle_sha256 {
                return Ok(CheckpointAdmission::IdempotentReplay);
            }
            return Err(FleetPolicyError::RevisionConflict);
        }

        self.revision = policy.revision();
        self.bundle_sha256 = digest;
        Ok(CheckpointAdmission::Advanced)
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, FleetPolicyError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_CHECKPOINT_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, FleetPolicyError> {
        let checkpoint: Self = import_canonical(bytes, MAX_CHECKPOINT_BYTES)?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn validate(&self) -> Result<(), FleetPolicyError> {
        if self.schema != POLICY_CHECKPOINT_SCHEMA {
            return Err(FleetPolicyError::InvalidField("checkpoint.schema"));
        }
        validate_identifier("checkpoint.tenantId", &self.tenant_id)?;
        validate_identifier("checkpoint.policyId", &self.policy_id)?;
        validate_safe_nonzero("checkpoint.revision", self.revision)?;
        validate_sha256("checkpoint.bundleSha256", &self.bundle_sha256)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAdmission {
    Advanced,
    IdempotentReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    Online,
    Offline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOperation {
    Diagnostic,
    NewRepair,
    StartedRollback,
}

/// Local facts that Fleet is never allowed to override.
pub struct PolicyEvaluation<'a> {
    pub device_id: &'a str,
    pub action_id: &'a str,
    /// `None` represents an unknown risk or a Core risk above R3.
    pub action_risk: Option<RiskLevel>,
    pub local_max_risk: RiskLevel,
    pub local_approval_from: RiskLevel,
    pub locally_known: bool,
    pub locally_allowed: bool,
    pub operation: PolicyOperation,
    pub transport: TransportState,
    pub now_unix: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    DiagnosticsAllowed,
    NewRepairAllowed {
        local_approval_required: bool,
        audit_required: bool,
    },
    StartedRollbackAllowed {
        audit_required: bool,
    },
    Denied(DenyReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    InvalidLocalContext,
    UnknownLocalAction,
    LocallyDenied,
    UnknownOrUnsupportedRisk,
    ExceedsLocalRiskCeiling,
    DeviceNotAssigned,
    PolicyNotYetValid,
    PolicyExpired,
    OfflineWindowElapsed,
    ExceedsFleetRiskCeiling,
    FleetDeniedAction,
    ActionNotFleetAllowed,
}

/// Validation, authenticity, and anti-rollback failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FleetPolicyError {
    InvalidField(&'static str),
    InvalidTimeWindow,
    InvalidJson,
    UnsupportedJsonValue,
    UnsafeInteger,
    NonCanonicalJson,
    BundleTooLarge,
    InvalidSignature,
    UnexpectedTenant,
    UnexpectedPolicy,
    RevisionRollback,
    RevisionConflict,
}

impl fmt::Display for FleetPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid Fleet policy field: {field}"),
            Self::InvalidTimeWindow => formatter.write_str("invalid Fleet policy time window"),
            Self::InvalidJson => formatter.write_str("invalid Fleet policy JSON"),
            Self::UnsupportedJsonValue => {
                formatter.write_str("unsupported Fleet policy JSON value")
            }
            Self::UnsafeInteger => formatter.write_str("unsafe Fleet policy JSON integer"),
            Self::NonCanonicalJson => formatter.write_str("Fleet policy JSON is not canonical"),
            Self::BundleTooLarge => formatter.write_str("Fleet policy document is too large"),
            Self::InvalidSignature => formatter.write_str("invalid Fleet policy signature"),
            Self::UnexpectedTenant => formatter.write_str("unexpected Fleet policy tenant"),
            Self::UnexpectedPolicy => formatter.write_str("unexpected Fleet policy stream"),
            Self::RevisionRollback => formatter.write_str("Fleet policy revision rollback"),
            Self::RevisionConflict => formatter.write_str("conflicting Fleet policy revision"),
        }
    }
}

impl std::error::Error for FleetPolicyError {}

fn validate_assignments(assignments: &Assignments) -> Result<(), FleetPolicyError> {
    match assignments {
        Assignments::All => Ok(()),
        Assignments::DeviceIds(device_ids) => {
            if device_ids.is_empty() || device_ids.len() > MAX_ASSIGNED_DEVICES {
                return Err(FleetPolicyError::InvalidField("assignments.deviceIds"));
            }
            validate_sorted_unique_strings("assignments.deviceIds", device_ids, validate_device_id)
        }
    }
}

fn validate_rules(rules: &PolicyRules) -> Result<(), FleetPolicyError> {
    validate_sorted_unique_strings(
        "rules.allowedActionIds",
        &rules.allowed_action_ids,
        |value| validate_identifier("rules.allowedActionIds", value),
    )?;
    validate_sorted_unique_strings("rules.deniedActionIds", &rules.denied_action_ids, |value| {
        validate_identifier("rules.deniedActionIds", value)
    })?;
    if rules.allowed_action_ids.len() > MAX_ACTION_IDS
        || rules.denied_action_ids.len() > MAX_ACTION_IDS
        || rules
            .allowed_action_ids
            .iter()
            .any(|action| contains_sorted(&rules.denied_action_ids, action))
    {
        return Err(FleetPolicyError::InvalidField("rules.actionIds"));
    }
    if !(1..=MAX_RETENTION_DAYS).contains(&rules.retention_days) {
        return Err(FleetPolicyError::InvalidField("rules.retentionDays"));
    }
    if rules.provider_modes.is_empty()
        || rules.provider_modes.len() > 4
        || rules
            .provider_modes
            .windows(2)
            .any(|pair| pair[0].wire_name() >= pair[1].wire_name())
    {
        return Err(FleetPolicyError::InvalidField("rules.providerModes"));
    }
    if !rules.emergency_rollback_always_allowed {
        return Err(FleetPolicyError::InvalidField(
            "rules.emergencyRollbackAlwaysAllowed",
        ));
    }
    Ok(())
}

fn validate_sorted_unique_strings(
    field: &'static str,
    values: &[String],
    validate: impl Fn(&str) -> Result<(), FleetPolicyError>,
) -> Result<(), FleetPolicyError> {
    for value in values {
        validate(value)?;
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(FleetPolicyError::InvalidField(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FleetPolicyError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(FleetPolicyError::InvalidField(field));
    }
    Ok(())
}

fn validate_device_id(value: &str) -> Result<(), FleetPolicyError> {
    let Some(suffix) = value.strip_prefix("KA-") else {
        return Err(FleetPolicyError::InvalidField("deviceId"));
    };
    if suffix.len() != 24
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FleetPolicyError::InvalidField("deviceId"));
    }
    Ok(())
}

fn validate_safe_nonzero(field: &'static str, value: u64) -> Result<(), FleetPolicyError> {
    if value == 0 || value > MAX_SAFE_JSON_INTEGER {
        return Err(FleetPolicyError::InvalidField(field));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), FleetPolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FleetPolicyError::InvalidField(field));
    }
    Ok(())
}

fn contains_sorted(values: &[String], expected: &str) -> bool {
    values
        .binary_search_by(|candidate| candidate.as_str().cmp(expected))
        .is_ok()
}

fn decode_signature(encoded: &str) -> Result<[u8; SIGNATURE_BYTES], FleetPolicyError> {
    if encoded.contains('=') || encoded.len() != 86 {
        return Err(FleetPolicyError::InvalidField("signature"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| FleetPolicyError::InvalidField("signature"))?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(FleetPolicyError::InvalidField("signature"));
    }
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| FleetPolicyError::InvalidField("signature"))
}

fn policy_signature_message(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, FleetPolicyError> {
    let length = u64::try_from(payload.len()).map_err(|_| FleetPolicyError::BundleTooLarge)?;
    let capacity = POLICY_SIGNATURE_DOMAIN
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(FleetPolicyError::BundleTooLarge)?;
    let mut message = Zeroizing::new(Vec::with_capacity(capacity));
    message.extend_from_slice(POLICY_SIGNATURE_DOMAIN);
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn hex_sha256(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn validate_size(actual: usize, maximum: usize) -> Result<(), FleetPolicyError> {
    if actual == 0 || actual > maximum {
        return Err(FleetPolicyError::BundleTooLarge);
    }
    Ok(())
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, FleetPolicyError>
where
    T: DeserializeOwned + Serialize,
{
    validate_size(bytes.len(), maximum)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FleetPolicyError::InvalidJson)?;
    validate_json_value(&value)?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| FleetPolicyError::InvalidJson)?;
    if canonical_json(&parsed)? != bytes {
        return Err(FleetPolicyError::NonCanonicalJson);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FleetPolicyError> {
    let value = serde_json::to_value(value).map_err(|_| FleetPolicyError::InvalidJson)?;
    validate_json_value(&value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn validate_json_value(value: &Value) -> Result<(), FleetPolicyError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                if value <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetPolicyError::UnsafeInteger)
                }
            } else if let Some(value) = number.as_i64() {
                if value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetPolicyError::UnsafeInteger)
                }
            } else {
                Err(FleetPolicyError::UnsupportedJsonValue)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(values) => values.values().try_for_each(validate_json_value),
    }
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), FleetPolicyError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| FleetPolicyError::InvalidJson)?;
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
                    serde_json::to_string(key).map_err(|_| FleetPolicyError::InvalidJson)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_value(
                    values.get(key).ok_or(FleetPolicyError::InvalidJson)?,
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
    const POLICY: &str = "repair-baseline";
    const DEVICE: &str = "KA-0123456789abcdef01234567";
    const OTHER_DEVICE: &str = "KA-1123456789abcdef01234567";
    const ACTION: &str = "linux.fstab.disable-missing-uuid.v1";
    const DENIED_ACTION: &str = "windows.registry.unsafe.v1";
    const ISSUED: u64 = 1_800_000_000;
    const NOT_BEFORE: u64 = 1_800_000_100;
    const OFFLINE_UNTIL: u64 = 1_800_086_400;
    const EXPIRES: u64 = 1_800_172_800;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x52; 32])
    }

    fn rules() -> PolicyRules {
        PolicyRules {
            max_risk: RiskLevel::R2,
            local_approval_from: RiskLevel::R1,
            allowed_action_ids: vec![ACTION.to_owned(), "system.observe.noop".to_owned()],
            denied_action_ids: vec![DENIED_ACTION.to_owned()],
            allow_evidence_upload: true,
            retention_days: 90,
            provider_modes: vec![
                ProviderMode::Enterprise,
                ProviderMode::Offline,
                ProviderMode::OpenaiApi,
            ],
            update_ring: UpdateRing::Stable,
            emergency_rollback_always_allowed: true,
        }
    }

    fn content(revision: u64) -> PolicyBundleContent {
        PolicyBundleContent {
            tenant_id: TENANT.to_owned(),
            policy_id: POLICY.to_owned(),
            revision,
            issued_at_unix: ISSUED,
            not_before_unix: NOT_BEFORE,
            offline_allowed_until_unix: OFFLINE_UNTIL,
            expires_at_unix: EXPIRES,
            assignments: Assignments::device_ids(vec![DEVICE.to_owned()]),
            rules: rules(),
        }
    }

    fn signed(revision: u64) -> SignedPolicyBundle {
        SignedPolicyBundle::sign(content(revision), &signing_key()).expect("sign policy")
    }

    fn verified(revision: u64) -> VerifiedPolicyBundle {
        signed(revision)
            .verify(&signing_key().verifying_key(), TENANT)
            .expect("verify policy")
    }

    fn evaluation<'a>(operation: PolicyOperation, now_unix: u64) -> PolicyEvaluation<'a> {
        PolicyEvaluation {
            device_id: DEVICE,
            action_id: ACTION,
            action_risk: Some(RiskLevel::R2),
            local_max_risk: RiskLevel::R2,
            local_approval_from: RiskLevel::R2,
            locally_known: true,
            locally_allowed: true,
            operation,
            transport: TransportState::Online,
            now_unix,
        }
    }

    #[test]
    fn signed_bundle_verifies_with_external_anchor_and_canonical_replay() {
        let signed = signed(7);
        let bytes = signed.export_canonical().expect("export policy");
        let verified =
            SignedPolicyBundle::import_and_verify(&bytes, &signing_key().verifying_key(), TENANT)
                .expect("import policy");
        assert_eq!(verified.revision(), 7);
        assert_eq!(
            verified
                .bundle
                .export_canonical()
                .expect("re-export policy"),
            bytes
        );
        let text = std::str::from_utf8(&bytes).expect("policy UTF-8");
        assert!(text.starts_with("{\"assignments\":{\"deviceIds\":"));
        assert!(text.contains("\"emergencyRollbackAlwaysAllowed\":true"));
    }

    #[test]
    fn tamper_wrong_anchor_and_cross_tenant_are_rejected() {
        let bytes = signed(1).export_canonical().expect("export policy");
        let mut value: Value = serde_json::from_slice(&bytes).expect("parse policy");
        value["rules"]["maxRisk"] = json!("R3");
        let tampered = canonical_json(&value).expect("canonical tamper");
        assert_eq!(
            SignedPolicyBundle::import_and_verify(
                &tampered,
                &signing_key().verifying_key(),
                TENANT,
            ),
            Err(FleetPolicyError::InvalidSignature)
        );
        let other_key = SigningKey::from_bytes(&[0x25; 32]);
        assert_eq!(
            SignedPolicyBundle::import_and_verify(&bytes, &other_key.verifying_key(), TENANT),
            Err(FleetPolicyError::InvalidSignature)
        );
        assert_eq!(
            SignedPolicyBundle::import_and_verify(
                &bytes,
                &signing_key().verifying_key(),
                "tenant-other",
            ),
            Err(FleetPolicyError::UnexpectedTenant)
        );
    }

    #[test]
    fn checkpoint_accepts_monotonic_and_idempotent_replay_only() {
        let first = verified(5);
        let mut checkpoint = PolicyCheckpoint::from_verified(&first);
        assert_eq!(
            checkpoint.admit(&first),
            Ok(CheckpointAdmission::IdempotentReplay)
        );
        assert_eq!(
            checkpoint.admit(&verified(4)),
            Err(FleetPolicyError::RevisionRollback)
        );

        let mut conflicting_content = content(5);
        conflicting_content.rules.retention_days = 30;
        let conflicting = SignedPolicyBundle::sign(conflicting_content, &signing_key())
            .expect("sign conflict")
            .verify(&signing_key().verifying_key(), TENANT)
            .expect("verify conflict");
        assert_eq!(
            checkpoint.admit(&conflicting),
            Err(FleetPolicyError::RevisionConflict)
        );
        assert_eq!(
            checkpoint.admit(&verified(6)),
            Ok(CheckpointAdmission::Advanced)
        );
        assert_eq!(checkpoint.revision(), 6);

        let bytes = checkpoint.export_canonical().expect("export checkpoint");
        let replay = PolicyCheckpoint::import_canonical(&bytes).expect("import checkpoint");
        assert_eq!(
            replay.export_canonical().expect("re-export checkpoint"),
            bytes
        );
    }

    #[test]
    fn assignment_is_exact_and_new_repairs_require_it() {
        let policy = verified(1);
        let allowed = evaluation(PolicyOperation::NewRepair, NOT_BEFORE);
        assert_eq!(
            policy.evaluate(&allowed),
            PolicyDecision::NewRepairAllowed {
                local_approval_required: true,
                audit_required: true,
            }
        );
        let mut other = evaluation(PolicyOperation::NewRepair, NOT_BEFORE);
        other.device_id = OTHER_DEVICE;
        assert_eq!(
            policy.evaluate(&other),
            PolicyDecision::Denied(DenyReason::DeviceNotAssigned)
        );

        let mut all_content = content(2);
        all_content.assignments = Assignments::all();
        let all_policy = SignedPolicyBundle::sign(all_content, &signing_key())
            .expect("sign all-device policy")
            .verify(&signing_key().verifying_key(), TENANT)
            .expect("verify all-device policy");
        assert!(matches!(
            all_policy.evaluate(&other),
            PolicyDecision::NewRepairAllowed { .. }
        ));
    }

    #[test]
    fn offline_expiry_closes_new_repairs_but_not_diagnostics_or_started_rollback() {
        let policy = verified(1);
        let mut request = evaluation(PolicyOperation::NewRepair, OFFLINE_UNTIL + 1);
        request.transport = TransportState::Offline;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::OfflineWindowElapsed)
        );

        request.operation = PolicyOperation::Diagnostic;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::DiagnosticsAllowed
        );
        request.operation = PolicyOperation::StartedRollback;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::StartedRollbackAllowed {
                audit_required: true
            }
        );

        request.now_unix = EXPIRES;
        request.operation = PolicyOperation::NewRepair;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::PolicyExpired)
        );
        request.operation = PolicyOperation::Diagnostic;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::DiagnosticsAllowed
        );
    }

    #[test]
    fn fleet_policy_never_expands_local_privilege() {
        let policy = verified(1);
        let mut request = evaluation(PolicyOperation::NewRepair, NOT_BEFORE);
        request.local_max_risk = RiskLevel::R1;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::ExceedsLocalRiskCeiling)
        );

        request.local_max_risk = RiskLevel::R3;
        request.locally_allowed = false;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::LocallyDenied)
        );
        request.locally_allowed = true;
        request.locally_known = false;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::UnknownLocalAction)
        );
        request.locally_known = true;
        request.action_risk = None;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::UnknownOrUnsupportedRisk)
        );

        assert!(!policy.evidence_upload_allowed(false));
        assert!(!policy.provider_mode_allowed(ProviderMode::Enterprise, false));
        assert_eq!(policy.effective_retention_days(30), 30);
    }

    #[test]
    fn fleet_and_local_approval_thresholds_intersect_at_stricter_value() {
        let policy = verified(1);
        let mut request = evaluation(PolicyOperation::NewRepair, NOT_BEFORE);
        request.action_risk = Some(RiskLevel::R1);
        request.local_approval_from = RiskLevel::R3;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::NewRepairAllowed {
                local_approval_required: true,
                audit_required: true,
            }
        );
    }

    #[test]
    fn denied_and_unlisted_actions_fail_closed() {
        let policy = verified(1);
        let mut request = evaluation(PolicyOperation::NewRepair, NOT_BEFORE);
        request.action_id = DENIED_ACTION;
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::FleetDeniedAction)
        );
        request.action_id = "linux.unknown.repair.v1";
        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Denied(DenyReason::ActionNotFleetAllowed)
        );
    }

    #[test]
    fn unsafe_float_unknown_unsorted_and_false_rollback_inputs_are_rejected() {
        let bytes = signed(1).export_canonical().expect("export policy");
        let mut unsafe_integer = std::str::from_utf8(&bytes).expect("policy UTF-8").replace(
            &format!("\"revision\":{}", 1),
            "\"revision\":9007199254740992",
        );
        assert_eq!(
            SignedPolicyBundle::import_and_verify(
                unsafe_integer.as_bytes(),
                &signing_key().verifying_key(),
                TENANT,
            ),
            Err(FleetPolicyError::UnsafeInteger)
        );

        unsafe_integer = unsafe_integer.replace("9007199254740992", "1.5");
        assert_eq!(
            SignedPolicyBundle::import_and_verify(
                unsafe_integer.as_bytes(),
                &signing_key().verifying_key(),
                TENANT,
            ),
            Err(FleetPolicyError::UnsupportedJsonValue)
        );

        let mut unknown: Value = serde_json::from_slice(&bytes).expect("parse policy");
        unknown["grantRawShell"] = json!(true);
        let unknown = canonical_json(&unknown).expect("canonical unknown");
        assert_eq!(
            SignedPolicyBundle::import_and_verify(&unknown, &signing_key().verifying_key(), TENANT,),
            Err(FleetPolicyError::InvalidJson)
        );

        let mut unsorted = content(2);
        unsorted.rules.allowed_action_ids.reverse();
        assert_eq!(
            SignedPolicyBundle::sign(unsorted, &signing_key()),
            Err(FleetPolicyError::InvalidField("rules.allowedActionIds"))
        );
        let mut unsafe_rollback = content(2);
        unsafe_rollback.rules.emergency_rollback_always_allowed = false;
        assert_eq!(
            SignedPolicyBundle::sign(unsafe_rollback, &signing_key()),
            Err(FleetPolicyError::InvalidField(
                "rules.emergencyRollbackAlwaysAllowed"
            ))
        );
    }

    #[test]
    fn signature_message_binds_domain_and_big_endian_length() {
        let bundle = signed(3);
        let unsigned = bundle
            .unsigned_canonical_json()
            .expect("canonical unsigned policy");
        let message = policy_signature_message(&unsigned).expect("signature message");
        assert_eq!(
            &message[..POLICY_SIGNATURE_DOMAIN.len()],
            POLICY_SIGNATURE_DOMAIN
        );
        assert_eq!(
            &message[POLICY_SIGNATURE_DOMAIN.len()..POLICY_SIGNATURE_DOMAIN.len() + 8],
            &(unsigned.len() as u64).to_be_bytes()
        );
        assert_eq!(
            &message[POLICY_SIGNATURE_DOMAIN.len() + 8..],
            unsigned.as_slice()
        );
    }
}
