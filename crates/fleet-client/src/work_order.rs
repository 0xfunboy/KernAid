use super::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, FleetClientError, canonical_json,
    decode_bounded_base64url, decode_fixed_base64url, import_canonical, validate_identifier,
    validate_sha256, validate_timestamp, validate_transfer_size, verify_signature,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kernaid_device_identity::{DeviceIdentity, device_id_for_public_key, validate_device_id};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use zeroize::Zeroizing;

pub const WORK_ORDER_CLAIM_REQUEST_SCHEMA: &str = "dev.kernaid.fleet.work-order-claim-request.v1";
pub const WORK_ORDER_CLAIM_RESPONSE_SCHEMA: &str = "dev.kernaid.fleet.work-order-claim-response.v1";
pub const WORK_ORDER_RESULT_SCHEMA: &str = "dev.kernaid.fleet.work-order-result.v1";
pub const WORK_ORDER_CLAIM_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:work-order-claim:v1\0";
pub const WORK_ORDER_RESULT_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:work-order-result:v1\0";

const MAX_CLAIM_BYTES: usize = 8 * 1024;
const MAX_CLAIM_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_RESULT_BYTES: usize = 8 * 1024;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 64;
const MIN_LEASE_SECONDS: u16 = 30;
const MAX_LEASE_SECONDS: u16 = 900;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorkOrderActionId {
    #[serde(rename = "linux.filesystem.health.v1")]
    LinuxFilesystemHealthV1,
    #[serde(rename = "linux.storage.health.v1")]
    LinuxStorageHealthV1,
    #[serde(rename = "linux.boot-critical-path.v1")]
    LinuxBootCriticalPathV1,
    #[serde(rename = "linux.fstab.disable-missing-uuid.v1")]
    LinuxFstabDisableMissingUuidV1,
}

impl WorkOrderActionId {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::LinuxFilesystemHealthV1 => "linux.filesystem.health.v1",
            Self::LinuxStorageHealthV1 => "linux.storage.health.v1",
            Self::LinuxBootCriticalPathV1 => "linux.boot-critical-path.v1",
            Self::LinuxFstabDisableMissingUuidV1 => "linux.fstab.disable-missing-uuid.v1",
        }
    }

    #[must_use]
    pub const fn metadata(self) -> WorkOrderActionMetadata {
        match self {
            Self::LinuxFilesystemHealthV1
            | Self::LinuxStorageHealthV1
            | Self::LinuxBootCriticalPathV1 => WorkOrderActionMetadata {
                version: 1,
                kind: WorkOrderKind::Diagnosis,
                risk: WorkOrderRisk::R0,
                local_approval_required: false,
                required_feature: WorkOrderRequiredFeature::Fleet,
            },
            Self::LinuxFstabDisableMissingUuidV1 => WorkOrderActionMetadata {
                version: 1,
                kind: WorkOrderKind::Repair,
                risk: WorkOrderRisk::R2,
                local_approval_required: true,
                required_feature: WorkOrderRequiredFeature::EnterpriseRepair,
            },
        }
    }
}

impl fmt::Display for WorkOrderActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

impl FromStr for WorkOrderActionId {
    type Err = FleetClientError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linux.filesystem.health.v1" => Ok(Self::LinuxFilesystemHealthV1),
            "linux.storage.health.v1" => Ok(Self::LinuxStorageHealthV1),
            "linux.boot-critical-path.v1" => Ok(Self::LinuxBootCriticalPathV1),
            "linux.fstab.disable-missing-uuid.v1" => Ok(Self::LinuxFstabDisableMissingUuidV1),
            _ => Err(FleetClientError::InvalidField("actionId")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkOrderKind {
    Diagnosis,
    Repair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum WorkOrderRisk {
    R0,
    R1,
    R2,
    R3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkOrderRequiredFeature {
    Fleet,
    EnterpriseRepair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkOrderActionMetadata {
    pub version: u16,
    pub kind: WorkOrderKind,
    pub risk: WorkOrderRisk,
    pub local_approval_required: bool,
    pub required_feature: WorkOrderRequiredFeature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkOrderResultOutcome {
    Succeeded,
    Failed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LeasedWorkOrderStatus {
    Leased,
}

pub struct WorkOrderClaimRequestInput {
    tenant_id: String,
    issued_at: String,
    nonce: Zeroizing<Vec<u8>>,
    lease_seconds: u16,
}

impl WorkOrderClaimRequestInput {
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        issued_at: impl Into<String>,
        nonce: impl Into<Vec<u8>>,
        lease_seconds: u16,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            issued_at: issued_at.into(),
            nonce: Zeroizing::new(nonce.into()),
            lease_seconds,
        }
    }
}

impl fmt::Debug for WorkOrderClaimRequestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOrderClaimRequestInput")
            .field("tenant_id", &self.tenant_id)
            .field("issued_at", &self.issued_at)
            .field("lease_seconds", &self.lease_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedWorkOrderClaimRequest {
    schema: String,
    tenant_id: String,
    device_id: String,
    issued_at: String,
    nonce: String,
    lease_seconds: u16,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedWorkOrderClaimRequest<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    issued_at: &'a str,
    nonce: &'a str,
    lease_seconds: u16,
}

impl SignedWorkOrderClaimRequest {
    pub fn sign(
        identity: &DeviceIdentity,
        input: WorkOrderClaimRequestInput,
    ) -> Result<Self, FleetClientError> {
        let mut request = Self {
            schema: WORK_ORDER_CLAIM_REQUEST_SCHEMA.to_owned(),
            tenant_id: input.tenant_id,
            device_id: identity.device_id(),
            issued_at: input.issued_at,
            nonce: URL_SAFE_NO_PAD.encode(input.nonce.as_slice()),
            lease_seconds: input.lease_seconds,
            signature: String::new(),
        };
        request.validate_unsigned()?;
        let unsigned = Zeroizing::new(request.unsigned_canonical()?);
        request.signature = URL_SAFE_NO_PAD.encode(
            identity
                .sign_domain_separated_payload(
                    WORK_ORDER_CLAIM_SIGNATURE_DOMAIN,
                    unsigned.as_slice(),
                )
                .map_err(FleetClientError::Identity)?,
        );
        request.validate()?;
        Ok(request)
    }

    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<(), FleetClientError> {
        self.validate()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        validate_device_id(expected_device_id)
            .map_err(|_| FleetClientError::InvalidField("expectedDeviceId"))?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if self.device_id != expected_device_id
            || device_id_for_public_key(enrolled_public_key) != expected_device_id
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let signature =
            decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical()?);
        verify_signature(
            enrolled_public_key,
            WORK_ORDER_CLAIM_SIGNATURE_DOMAIN,
            unsigned.as_slice(),
            &signature,
        )
    }

    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_CLAIM_BYTES)?;
        Ok(bytes)
    }

    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, FleetClientError> {
        let request: Self = import_canonical(bytes, MAX_CLAIM_BYTES)?;
        request.verify(expected_tenant_id, expected_device_id, enrolled_public_key)?;
        Ok(request)
    }

    pub fn import_response(
        &self,
        bytes: &[u8],
    ) -> Result<WorkOrderClaimResponse, FleetClientError> {
        validate_transfer_size(bytes.len(), MAX_CLAIM_RESPONSE_BYTES)?;
        let response: WorkOrderClaimResponse =
            serde_json::from_slice(bytes).map_err(|_| FleetClientError::InvalidJson)?;
        response.validate(self)?;
        Ok(response)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn unsigned(&self) -> UnsignedWorkOrderClaimRequest<'_> {
        UnsignedWorkOrderClaimRequest {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            issued_at: &self.issued_at,
            nonce: &self.nonce,
            lease_seconds: self.lease_seconds,
        }
    }

    fn unsigned_canonical(&self) -> Result<Vec<u8>, FleetClientError> {
        canonical_json(&self.unsigned())
    }

    fn validate(&self) -> Result<(), FleetClientError> {
        self.validate_unsigned()?;
        decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), FleetClientError> {
        if self.schema != WORK_ORDER_CLAIM_REQUEST_SCHEMA {
            return Err(FleetClientError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        validate_timestamp("issuedAt", &self.issued_at)?;
        decode_bounded_base64url("nonce", &self.nonce, MIN_NONCE_BYTES, MAX_NONCE_BYTES)?;
        if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&self.lease_seconds) {
            return Err(FleetClientError::InvalidField("leaseSeconds"));
        }
        Ok(())
    }
}

impl fmt::Debug for SignedWorkOrderClaimRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedWorkOrderClaimRequest")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("issued_at", &self.issued_at)
            .field("lease_seconds", &self.lease_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkOrderServerApproval {
    approved_at: String,
    approved_by_credential_id: String,
}

impl WorkOrderServerApproval {
    #[must_use]
    pub fn approved_at(&self) -> &str {
        &self.approved_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkOrderLease {
    lease_id: String,
    leased_at: String,
    lease_expires_at: String,
}

impl WorkOrderLease {
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub fn leased_at(&self) -> &str {
        &self.leased_at
    }

    #[must_use]
    pub fn lease_expires_at(&self) -> &str {
        &self.lease_expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeasedWorkOrder {
    work_order_id: String,
    target_device_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    kind: WorkOrderKind,
    risk: WorkOrderRisk,
    local_approval_required: bool,
    status: LeasedWorkOrderStatus,
    created_at: String,
    expires_at: String,
    approval: Option<WorkOrderServerApproval>,
    lease: WorkOrderLease,
}

impl LeasedWorkOrder {
    #[must_use]
    pub fn work_order_id(&self) -> &str {
        &self.work_order_id
    }

    #[must_use]
    pub fn target_device_id(&self) -> &str {
        &self.target_device_id
    }

    #[must_use]
    pub const fn action_id(&self) -> WorkOrderActionId {
        self.action_id
    }

    #[must_use]
    pub const fn action_version(&self) -> u16 {
        self.action_version
    }

    #[must_use]
    pub const fn kind(&self) -> WorkOrderKind {
        self.kind
    }

    #[must_use]
    pub const fn risk(&self) -> WorkOrderRisk {
        self.risk
    }

    #[must_use]
    pub const fn local_approval_required(&self) -> bool {
        self.local_approval_required
    }

    #[must_use]
    pub fn approval(&self) -> Option<&WorkOrderServerApproval> {
        self.approval.as_ref()
    }

    #[must_use]
    pub const fn lease(&self) -> &WorkOrderLease {
        &self.lease
    }

    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    fn validate(&self, expected_device_id: &str) -> Result<(), FleetClientError> {
        validate_identifier("workOrderId", &self.work_order_id)?;
        validate_device_id(&self.target_device_id)
            .map_err(|_| FleetClientError::InvalidField("targetDeviceId"))?;
        if self.target_device_id != expected_device_id
            || self.status != LeasedWorkOrderStatus::Leased
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let metadata = self.action_id.metadata();
        if self.action_version != metadata.version
            || self.kind != metadata.kind
            || self.risk != metadata.risk
            || self.local_approval_required != metadata.local_approval_required
        {
            return Err(FleetClientError::InvalidField("workOrder.action"));
        }
        validate_timestamp("createdAt", &self.created_at)?;
        validate_timestamp("expiresAt", &self.expires_at)?;
        validate_identifier("leaseId", &self.lease.lease_id)?;
        validate_timestamp("leasedAt", &self.lease.leased_at)?;
        validate_timestamp("leaseExpiresAt", &self.lease.lease_expires_at)?;
        let created = parse_time("createdAt", &self.created_at)?;
        let expires = parse_time("expiresAt", &self.expires_at)?;
        let leased = parse_time("leasedAt", &self.lease.leased_at)?;
        let lease_expires = parse_time("leaseExpiresAt", &self.lease.lease_expires_at)?;
        if created > leased || leased >= lease_expires || lease_expires > expires {
            return Err(FleetClientError::InvalidField("workOrder.timeWindow"));
        }
        match (&self.approval, self.local_approval_required) {
            (Some(approval), true) => {
                validate_timestamp("approvedAt", &approval.approved_at)?;
                validate_identifier(
                    "approvedByCredentialId",
                    &approval.approved_by_credential_id,
                )?;
                if parse_time("approvedAt", &approval.approved_at)? > leased {
                    return Err(FleetClientError::InvalidField("approval.time"));
                }
            }
            (None, false) => {}
            _ => return Err(FleetClientError::InvalidField("approval")),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkOrderClaimResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    work_order: Option<LeasedWorkOrder>,
    idempotent: bool,
}

impl WorkOrderClaimResponse {
    #[must_use]
    pub fn work_order(&self) -> Option<&LeasedWorkOrder> {
        self.work_order.as_ref()
    }

    #[must_use]
    pub fn into_work_order(self) -> Option<LeasedWorkOrder> {
        self.work_order
    }

    fn validate(&self, request: &SignedWorkOrderClaimRequest) -> Result<(), FleetClientError> {
        if self.schema != WORK_ORDER_CLAIM_RESPONSE_SCHEMA {
            return Err(FleetClientError::InvalidField("response.schema"));
        }
        validate_identifier("response.tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("response.deviceId"))?;
        if self.tenant_id != request.tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if self.device_id != request.device_id {
            return Err(FleetClientError::UnexpectedDevice);
        }
        if let Some(work_order) = &self.work_order {
            work_order.validate(&self.device_id)?;
        }
        Ok(())
    }
}

pub struct WorkOrderResultInput {
    tenant_id: String,
    work_order_id: String,
    lease_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    outcome: WorkOrderResultOutcome,
    completed_at: String,
    result_sha256: String,
}

impl WorkOrderResultInput {
    #[must_use]
    pub fn from_order(
        tenant_id: impl Into<String>,
        order: &LeasedWorkOrder,
        outcome: WorkOrderResultOutcome,
        completed_at: impl Into<String>,
        result_sha256: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            work_order_id: order.work_order_id.clone(),
            lease_id: order.lease.lease_id.clone(),
            action_id: order.action_id,
            action_version: order.action_version,
            outcome,
            completed_at: completed_at.into(),
            result_sha256: result_sha256.into(),
        }
    }
}

impl fmt::Debug for WorkOrderResultInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOrderResultInput")
            .field("work_order_id", &self.work_order_id)
            .field("lease_id", &self.lease_id)
            .field("action_id", &self.action_id)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedWorkOrderResult {
    schema: String,
    tenant_id: String,
    device_id: String,
    work_order_id: String,
    lease_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    outcome: WorkOrderResultOutcome,
    completed_at: String,
    result_sha256: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedWorkOrderResult<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    work_order_id: &'a str,
    lease_id: &'a str,
    action_id: WorkOrderActionId,
    action_version: u16,
    outcome: WorkOrderResultOutcome,
    completed_at: &'a str,
    result_sha256: &'a str,
}

impl SignedWorkOrderResult {
    pub fn sign(
        identity: &DeviceIdentity,
        input: WorkOrderResultInput,
    ) -> Result<Self, FleetClientError> {
        let mut result = Self {
            schema: WORK_ORDER_RESULT_SCHEMA.to_owned(),
            tenant_id: input.tenant_id,
            device_id: identity.device_id(),
            work_order_id: input.work_order_id,
            lease_id: input.lease_id,
            action_id: input.action_id,
            action_version: input.action_version,
            outcome: input.outcome,
            completed_at: input.completed_at,
            result_sha256: input.result_sha256,
            signature: String::new(),
        };
        result.validate_unsigned()?;
        let unsigned = Zeroizing::new(result.unsigned_canonical()?);
        result.signature = URL_SAFE_NO_PAD.encode(
            identity
                .sign_domain_separated_payload(
                    WORK_ORDER_RESULT_SIGNATURE_DOMAIN,
                    unsigned.as_slice(),
                )
                .map_err(FleetClientError::Identity)?,
        );
        result.validate()?;
        Ok(result)
    }

    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<(), FleetClientError> {
        self.validate()?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if self.device_id != expected_device_id
            || device_id_for_public_key(enrolled_public_key) != expected_device_id
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let signature =
            decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical()?);
        verify_signature(
            enrolled_public_key,
            WORK_ORDER_RESULT_SIGNATURE_DOMAIN,
            unsigned.as_slice(),
            &signature,
        )
    }

    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_RESULT_BYTES)?;
        Ok(bytes)
    }

    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, FleetClientError> {
        let result: Self = import_canonical(bytes, MAX_RESULT_BYTES)?;
        result.verify(expected_tenant_id, expected_device_id, enrolled_public_key)?;
        Ok(result)
    }

    #[must_use]
    pub fn work_order_id(&self) -> &str {
        &self.work_order_id
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub const fn outcome(&self) -> WorkOrderResultOutcome {
        self.outcome
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
    pub fn result_sha256(&self) -> &str {
        &self.result_sha256
    }

    fn unsigned(&self) -> UnsignedWorkOrderResult<'_> {
        UnsignedWorkOrderResult {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            work_order_id: &self.work_order_id,
            lease_id: &self.lease_id,
            action_id: self.action_id,
            action_version: self.action_version,
            outcome: self.outcome,
            completed_at: &self.completed_at,
            result_sha256: &self.result_sha256,
        }
    }

    fn unsigned_canonical(&self) -> Result<Vec<u8>, FleetClientError> {
        canonical_json(&self.unsigned())
    }

    fn validate(&self) -> Result<(), FleetClientError> {
        self.validate_unsigned()?;
        decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), FleetClientError> {
        if self.schema != WORK_ORDER_RESULT_SCHEMA {
            return Err(FleetClientError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        validate_identifier("workOrderId", &self.work_order_id)?;
        validate_identifier("leaseId", &self.lease_id)?;
        if self.action_version != self.action_id.metadata().version {
            return Err(FleetClientError::InvalidField("actionVersion"));
        }
        validate_timestamp("completedAt", &self.completed_at)?;
        validate_sha256("resultSha256", &self.result_sha256)
    }
}

impl fmt::Debug for SignedWorkOrderResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedWorkOrderResult")
            .field("work_order_id", &self.work_order_id)
            .field("lease_id", &self.lease_id)
            .field("action_id", &self.action_id)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

fn parse_time(
    field: &'static str,
    value: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, FleetClientError> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|_| FleetClientError::InvalidField(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TENANT: &str = "tenant-europe-1";
    const NOW: &str = "2026-08-31T12:30:45Z";

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity")
    }

    #[test]
    fn claim_and_result_signatures_reject_tamper_and_unknown_actions() {
        let identity = identity();
        let claim = SignedWorkOrderClaimRequest::sign(
            &identity,
            WorkOrderClaimRequestInput::new(TENANT, NOW, vec![0xa5; 32], 300),
        )
        .expect("sign claim");
        let bytes = claim.export_offline().expect("export claim");
        SignedWorkOrderClaimRequest::import_offline(
            &bytes,
            TENANT,
            &identity.device_id(),
            &identity.public_key(),
        )
        .expect("verify claim");

        let response = serde_json::to_vec(&json!({
            "schema": WORK_ORDER_CLAIM_RESPONSE_SCHEMA,
            "tenantId": TENANT,
            "deviceId": identity.device_id(),
            "idempotent": false,
            "workOrder": {
                "workOrderId": "wo_01",
                "targetDeviceId": identity.device_id(),
                "actionId": "linux.filesystem.health.v1",
                "actionVersion": 1,
                "kind": "diagnosis",
                "risk": "R0",
                "localApprovalRequired": false,
                "status": "leased",
                "createdAt": "2026-08-31T12:00:00Z",
                "expiresAt": "2026-08-31T13:00:00Z",
                "approval": null,
                "lease": {
                    "leaseId": "lease_01",
                    "leasedAt": NOW,
                    "leaseExpiresAt": "2026-08-31T12:35:45Z"
                }
            }
        }))
        .expect("response");
        let order = claim
            .import_response(&response)
            .expect("verified response")
            .into_work_order()
            .expect("leased order");
        let result = SignedWorkOrderResult::sign(
            &identity,
            WorkOrderResultInput::from_order(
                TENANT,
                &order,
                WorkOrderResultOutcome::Succeeded,
                "2026-08-31T12:31:45Z",
                "11".repeat(32),
            ),
        )
        .expect("sign result");
        result
            .verify(TENANT, &identity.device_id(), &identity.public_key())
            .expect("verify result");

        let mut unknown: serde_json::Value = serde_json::from_slice(&response).expect("parse");
        unknown["workOrder"]["actionId"] = json!("linux.shell.run.v1");
        assert!(
            claim
                .import_response(&serde_json::to_vec(&unknown).expect("serialize"))
                .is_err()
        );
    }

    #[test]
    fn write_order_requires_exact_catalog_and_organizational_approval() {
        let identity = identity();
        let claim = SignedWorkOrderClaimRequest::sign(
            &identity,
            WorkOrderClaimRequestInput::new(TENANT, NOW, vec![0xa5; 32], 300),
        )
        .expect("sign claim");
        let response = json!({
            "schema": WORK_ORDER_CLAIM_RESPONSE_SCHEMA,
            "tenantId": TENANT,
            "deviceId": identity.device_id(),
            "idempotent": false,
            "workOrder": {
                "workOrderId": "wo_write_01",
                "targetDeviceId": identity.device_id(),
                "actionId": "linux.fstab.disable-missing-uuid.v1",
                "actionVersion": 1,
                "kind": "repair",
                "risk": "R2",
                "localApprovalRequired": true,
                "status": "leased",
                "createdAt": "2026-08-31T12:00:00Z",
                "expiresAt": "2026-08-31T13:00:00Z",
                "approval": null,
                "lease": {
                    "leaseId": "lease_write_01",
                    "leasedAt": NOW,
                    "leaseExpiresAt": "2026-08-31T12:35:45Z"
                }
            }
        });
        assert!(
            claim
                .import_response(&serde_json::to_vec(&response).expect("response"))
                .is_err()
        );
        let mut approved = response;
        approved["workOrder"]["approval"] = json!({
            "approvedAt": "2026-08-31T12:29:45Z",
            "approvedByCredentialId": "cred_01"
        });
        claim
            .import_response(&serde_json::to_vec(&approved).expect("approved response"))
            .expect("approved write order");
    }

    #[test]
    fn unsafe_integer_and_unknown_fields_fail_closed() {
        let identity = identity();
        let claim = SignedWorkOrderClaimRequest::sign(
            &identity,
            WorkOrderClaimRequestInput::new(TENANT, NOW, vec![0xa5; 32], 300),
        )
        .expect("sign claim");
        let mut value: serde_json::Value =
            serde_json::from_slice(&claim.export_offline().expect("export")).expect("parse");
        value["leaseSeconds"] = json!(crate::MAX_SAFE_JSON_INTEGER + 1);
        assert!(
            SignedWorkOrderClaimRequest::import_offline(
                &serde_json::to_vec(&value).expect("serialize"),
                TENANT,
                &identity.device_id(),
                &identity.public_key()
            )
            .is_err()
        );
        value["leaseSeconds"] = json!(300);
        value["command"] = json!("rm -rf /");
        assert!(
            SignedWorkOrderClaimRequest::import_offline(
                &serde_json::to_vec(&value).expect("serialize"),
                TENANT,
                &identity.device_id(),
                &identity.public_key()
            )
            .is_err()
        );
    }
}
