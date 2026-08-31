#![forbid(unsafe_code)]
//! Offline-verifiable commercial entitlements for KernAid.
//!
//! Licensing may disable paid services, but it never disables local
//! diagnostics, report export, or rollback of an already-started repair.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

pub const ENTITLEMENT_SCHEMA: &str = "dev.kernaid.entitlement.v1";
pub const REVOCATIONS_SCHEMA: &str = "dev.kernaid.entitlement-revocations.v1";
const ENTITLEMENT_DOMAIN: &[u8] = b"KERNAID-ENTITLEMENT-V1\0";
const REVOCATIONS_DOMAIN: &[u8] = b"KERNAID-ENTITLEMENT-REVOCATIONS-V1\0";
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Retail,
    Pro,
    Fleet,
    Enterprise,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Audit,
    ConsumerRepair,
    EnterpriseProviders,
    EnterpriseRepair,
    Fleet,
    Policy,
    Updates,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementLimits {
    pub max_tool_devices: u32,
    pub max_technicians: u32,
    pub max_managed_assets: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementClaims {
    pub schema: String,
    pub entitlement_id: String,
    pub tenant_id: String,
    pub sequence: u64,
    pub plan: Plan,
    pub features: Vec<Feature>,
    pub device_ids: Vec<String>,
    pub limits: EntitlementLimits,
    pub issued_at_unix: u64,
    pub not_before_unix: u64,
    pub offline_lease_until_unix: u64,
    pub expires_at_unix: u64,
    pub grace_until_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementEnvelope {
    pub claims: EntitlementClaims,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationClaims {
    pub schema: String,
    pub sequence: u64,
    pub issued_at_unix: u64,
    pub revoked_entitlement_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationEnvelope {
    pub claims: RevocationClaims,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntitlementCheckpoint {
    pub entitlement_id: String,
    pub tenant_id: String,
    pub highest_sequence: u64,
    pub envelope_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationCheckpoint {
    pub highest_sequence: u64,
    pub envelope_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEntitlement {
    pub envelope: EntitlementEnvelope,
    pub envelope_sha256: String,
    pub checkpoint: EntitlementCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRevocations {
    pub envelope: RevocationEnvelope,
    pub envelope_sha256: String,
    pub checkpoint: RevocationCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementState {
    NotYetValid,
    Active,
    RefreshRequired,
    Grace,
    Expired,
    Revoked,
    DeviceNotAssigned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LicensedCapabilities {
    pub state: EntitlementState,
    pub diagnostics: bool,
    pub report_export: bool,
    pub rollback: bool,
    pub consumer_repair: bool,
    pub enterprise_repair: bool,
    pub fleet_sync: bool,
    pub cached_policy: bool,
    pub audit_upload: bool,
    pub updates: bool,
    pub enterprise_providers: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementError {
    DocumentTooLarge,
    InvalidDocument,
    NonCanonicalDocument,
    InvalidClaims,
    InvalidSignature,
    WrongTrustAnchor,
    RollbackDetected,
    SequenceConflict,
    CheckpointMismatch,
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DocumentTooLarge => "entitlement document is too large",
            Self::InvalidDocument => "entitlement document is invalid",
            Self::NonCanonicalDocument => "entitlement document is not canonical",
            Self::InvalidClaims => "entitlement claims are invalid",
            Self::InvalidSignature => "entitlement signature is invalid",
            Self::WrongTrustAnchor => "entitlement trust anchor is invalid",
            Self::RollbackDetected => "entitlement sequence rollback detected",
            Self::SequenceConflict => "entitlement sequence conflicts with retained state",
            Self::CheckpointMismatch => "entitlement checkpoint belongs to another license",
        })
    }
}

impl Error for EntitlementError {}

pub fn sign_entitlement(
    claims: EntitlementClaims,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, EntitlementError> {
    validate_entitlement_claims(&claims)?;
    let claims_bytes = canonical_json(&claims)?;
    let signature = signing_key.sign(&signature_message(ENTITLEMENT_DOMAIN, &claims_bytes));
    canonical_json(&EntitlementEnvelope {
        claims,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

pub fn verify_entitlement(
    document: &[u8],
    trusted_public_key: &[u8; 32],
    checkpoint: Option<&EntitlementCheckpoint>,
) -> Result<VerifiedEntitlement, EntitlementError> {
    let envelope: EntitlementEnvelope = parse_canonical(document)?;
    validate_entitlement_claims(&envelope.claims)?;
    verify_signature(
        ENTITLEMENT_DOMAIN,
        &envelope.claims,
        &envelope.signature,
        trusted_public_key,
    )?;
    let digest = sha256_hex(document);
    let next = next_entitlement_checkpoint(&envelope.claims, &digest, checkpoint)?;
    Ok(VerifiedEntitlement {
        envelope,
        envelope_sha256: digest,
        checkpoint: next,
    })
}

pub fn sign_revocations(
    claims: RevocationClaims,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, EntitlementError> {
    validate_revocation_claims(&claims)?;
    let claims_bytes = canonical_json(&claims)?;
    let signature = signing_key.sign(&signature_message(REVOCATIONS_DOMAIN, &claims_bytes));
    canonical_json(&RevocationEnvelope {
        claims,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

pub fn verify_revocations(
    document: &[u8],
    trusted_public_key: &[u8; 32],
    checkpoint: Option<&RevocationCheckpoint>,
) -> Result<VerifiedRevocations, EntitlementError> {
    let envelope: RevocationEnvelope = parse_canonical(document)?;
    validate_revocation_claims(&envelope.claims)?;
    verify_signature(
        REVOCATIONS_DOMAIN,
        &envelope.claims,
        &envelope.signature,
        trusted_public_key,
    )?;
    let digest = sha256_hex(document);
    let next = next_revocation_checkpoint(&envelope.claims, &digest, checkpoint)?;
    Ok(VerifiedRevocations {
        envelope,
        envelope_sha256: digest,
        checkpoint: next,
    })
}

pub fn capabilities(
    entitlement: &VerifiedEntitlement,
    revocations: Option<&VerifiedRevocations>,
    device_id: &str,
    now_unix: u64,
) -> LicensedCapabilities {
    let claims = &entitlement.envelope.claims;
    let revoked = revocations.is_some_and(|list| {
        list.envelope
            .claims
            .revoked_entitlement_ids
            .binary_search(&claims.entitlement_id)
            .is_ok()
    });
    let assigned = claims
        .device_ids
        .binary_search_by(|candidate| candidate.as_str().cmp(device_id))
        .is_ok();
    let state = if revoked {
        EntitlementState::Revoked
    } else if !assigned {
        EntitlementState::DeviceNotAssigned
    } else if now_unix < claims.not_before_unix {
        EntitlementState::NotYetValid
    } else if now_unix <= claims.offline_lease_until_unix {
        EntitlementState::Active
    } else if now_unix <= claims.expires_at_unix {
        EntitlementState::RefreshRequired
    } else if now_unix <= claims.grace_until_unix {
        EntitlementState::Grace
    } else {
        EntitlementState::Expired
    };

    let repair_window = matches!(
        state,
        EntitlementState::Active | EntitlementState::RefreshRequired | EntitlementState::Grace
    );
    let active = state == EntitlementState::Active;
    let policy_window = repair_window;
    LicensedCapabilities {
        state,
        diagnostics: true,
        report_export: true,
        rollback: true,
        consumer_repair: repair_window && has_feature(claims, Feature::ConsumerRepair),
        enterprise_repair: repair_window && has_feature(claims, Feature::EnterpriseRepair),
        fleet_sync: active && has_feature(claims, Feature::Fleet),
        cached_policy: policy_window && has_feature(claims, Feature::Policy),
        audit_upload: active && has_feature(claims, Feature::Audit),
        updates: active && has_feature(claims, Feature::Updates),
        enterprise_providers: repair_window && has_feature(claims, Feature::EnterpriseProviders),
    }
}

fn has_feature(claims: &EntitlementClaims, feature: Feature) -> bool {
    claims.features.binary_search(&feature).is_ok()
}

fn validate_entitlement_claims(claims: &EntitlementClaims) -> Result<(), EntitlementError> {
    if claims.schema != ENTITLEMENT_SCHEMA
        || !valid_id(&claims.entitlement_id)
        || !valid_id(&claims.tenant_id)
        || !safe_positive(claims.sequence)
        || claims.features.len() > 16
        || claims.device_ids.is_empty()
        || claims.device_ids.len() > 4096
        || claims.limits.max_tool_devices == 0
        || claims.limits.max_technicians == 0
        || claims.limits.max_managed_assets == 0
        || claims.device_ids.len() > claims.limits.max_tool_devices as usize
        || !strictly_sorted(&claims.features)
        || !strictly_sorted(&claims.device_ids)
        || claims.device_ids.iter().any(|device| !valid_id(device))
        || !safe_timestamp(claims.issued_at_unix)
        || !safe_timestamp(claims.not_before_unix)
        || !safe_timestamp(claims.offline_lease_until_unix)
        || !safe_timestamp(claims.expires_at_unix)
        || !safe_timestamp(claims.grace_until_unix)
        || claims.issued_at_unix > claims.not_before_unix
        || claims.not_before_unix > claims.offline_lease_until_unix
        || claims.offline_lease_until_unix > claims.expires_at_unix
        || claims.expires_at_unix > claims.grace_until_unix
    {
        return Err(EntitlementError::InvalidClaims);
    }
    Ok(())
}

fn validate_revocation_claims(claims: &RevocationClaims) -> Result<(), EntitlementError> {
    if claims.schema != REVOCATIONS_SCHEMA
        || !safe_positive(claims.sequence)
        || !safe_timestamp(claims.issued_at_unix)
        || claims.revoked_entitlement_ids.len() > 65_536
        || !strictly_sorted(&claims.revoked_entitlement_ids)
        || claims
            .revoked_entitlement_ids
            .iter()
            .any(|entitlement| !valid_id(entitlement))
    {
        return Err(EntitlementError::InvalidClaims);
    }
    Ok(())
}

fn next_entitlement_checkpoint(
    claims: &EntitlementClaims,
    digest: &str,
    checkpoint: Option<&EntitlementCheckpoint>,
) -> Result<EntitlementCheckpoint, EntitlementError> {
    if let Some(retained) = checkpoint {
        if retained.entitlement_id != claims.entitlement_id
            || retained.tenant_id != claims.tenant_id
        {
            return Err(EntitlementError::CheckpointMismatch);
        }
        if claims.sequence < retained.highest_sequence {
            return Err(EntitlementError::RollbackDetected);
        }
        if claims.sequence == retained.highest_sequence && retained.envelope_sha256 != digest {
            return Err(EntitlementError::SequenceConflict);
        }
    }
    Ok(EntitlementCheckpoint {
        entitlement_id: claims.entitlement_id.clone(),
        tenant_id: claims.tenant_id.clone(),
        highest_sequence: claims.sequence,
        envelope_sha256: digest.to_owned(),
    })
}

fn next_revocation_checkpoint(
    claims: &RevocationClaims,
    digest: &str,
    checkpoint: Option<&RevocationCheckpoint>,
) -> Result<RevocationCheckpoint, EntitlementError> {
    if let Some(retained) = checkpoint {
        if claims.sequence < retained.highest_sequence {
            return Err(EntitlementError::RollbackDetected);
        }
        if claims.sequence == retained.highest_sequence && retained.envelope_sha256 != digest {
            return Err(EntitlementError::SequenceConflict);
        }
    }
    Ok(RevocationCheckpoint {
        highest_sequence: claims.sequence,
        envelope_sha256: digest.to_owned(),
    })
}

fn verify_signature<T: Serialize>(
    domain: &[u8],
    claims: &T,
    encoded_signature: &str,
    trusted_public_key: &[u8; 32],
) -> Result<(), EntitlementError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| EntitlementError::InvalidSignature)?;
    let signature_bytes: [u8; SIGNATURE_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| EntitlementError::InvalidSignature)?;
    if URL_SAFE_NO_PAD.encode(signature_bytes) != encoded_signature {
        return Err(EntitlementError::InvalidSignature);
    }
    let key = VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|_| EntitlementError::WrongTrustAnchor)?;
    let claims_bytes = canonical_json(claims)?;
    key.verify_strict(
        &signature_message(domain, &claims_bytes),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| EntitlementError::InvalidSignature)
}

fn parse_canonical<T>(document: &[u8]) -> Result<T, EntitlementError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(EntitlementError::DocumentTooLarge);
    }
    let parsed = serde_json::from_slice(document).map_err(|_| EntitlementError::InvalidDocument)?;
    if canonical_json(&parsed)?.as_slice() != document {
        return Err(EntitlementError::NonCanonicalDocument);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, EntitlementError> {
    let value = serde_json::to_value(value).map_err(|_| EntitlementError::InvalidDocument)?;
    validate_canonical_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| EntitlementError::InvalidDocument)
}

fn validate_canonical_value(value: &serde_json::Value) -> Result<(), EntitlementError> {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            Ok(())
        }
        serde_json::Value::Number(number) => number
            .as_u64()
            .filter(|integer| *integer <= MAX_SAFE_INTEGER)
            .map(|_| ())
            .ok_or(EntitlementError::InvalidClaims),
        serde_json::Value::Array(items) => {
            for item in items {
                validate_canonical_value(item)?;
            }
            Ok(())
        }
        serde_json::Value::Object(fields) => {
            for value in fields.values() {
                validate_canonical_value(value)?;
            }
            Ok(())
        }
    }
}

fn signature_message(domain: &[u8], canonical_claims: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 8 + canonical_claims.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&(canonical_claims.len() as u64).to_be_bytes());
    message.extend_from_slice(canonical_claims);
    message
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn safe_positive(value: u64) -> bool {
    value > 0 && value <= MAX_SAFE_INTEGER
}

fn safe_timestamp(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_ENTITLEMENT: &str = r#"{"claims":{"deviceIds":["device_alpha","device_beta"],"entitlementId":"ent_acme_001","expiresAtUnix":3000,"features":["audit","enterprise_repair","fleet","policy","updates"],"graceUntilUnix":4000,"issuedAtUnix":1000,"limits":{"maxManagedAssets":5000,"maxTechnicians":16,"maxToolDevices":8},"notBeforeUnix":1000,"offlineLeaseUntilUnix":2000,"plan":"enterprise","schema":"dev.kernaid.entitlement.v1","sequence":1,"tenantId":"tenant_acme"},"signature":"sWOJD4yoB89_MICu3glOpehAV8zeXJKXmI_TwnMDj7aZ0MxgA8C4pGtQUWumOMLEDQJp_ZoAbCbmSRpPWKRuBQ"}"#;
    const FIXTURE_REVOCATIONS: &str = r#"{"claims":{"issuedAtUnix":1400,"revokedEntitlementIds":["ent_acme_001"],"schema":"dev.kernaid.entitlement-revocations.v1","sequence":7},"signature":"mOEmDZRrBVWAlYfPFMTT6ywK3y1_hLn0Dd1cdXVAUdg0UM0fZ7CinsR8OSP02TvlVqrl47vkYOcciAMtBIYgBw"}"#;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn claims(sequence: u64) -> EntitlementClaims {
        EntitlementClaims {
            schema: ENTITLEMENT_SCHEMA.to_owned(),
            entitlement_id: "ent_acme_001".to_owned(),
            tenant_id: "tenant_acme".to_owned(),
            sequence,
            plan: Plan::Enterprise,
            features: vec![
                Feature::Audit,
                Feature::EnterpriseRepair,
                Feature::Fleet,
                Feature::Policy,
                Feature::Updates,
            ],
            device_ids: vec!["device_alpha".to_owned(), "device_beta".to_owned()],
            limits: EntitlementLimits {
                max_tool_devices: 8,
                max_technicians: 16,
                max_managed_assets: 5_000,
            },
            issued_at_unix: 1_000,
            not_before_unix: 1_000,
            offline_lease_until_unix: 2_000,
            expires_at_unix: 3_000,
            grace_until_unix: 4_000,
        }
    }

    fn verified(sequence: u64) -> VerifiedEntitlement {
        let key = signing_key();
        let document = sign_entitlement(claims(sequence), &key).expect("sign fixture entitlement");
        verify_entitlement(&document, &key.verifying_key().to_bytes(), None)
            .expect("verify fixture entitlement")
    }

    #[test]
    fn signed_entitlement_is_canonical_and_verifiable() {
        let key = signing_key();
        let document = sign_entitlement(claims(1), &key).expect("sign entitlement");
        assert_eq!(document, FIXTURE_ENTITLEMENT.as_bytes());
        let verified = verify_entitlement(&document, &key.verifying_key().to_bytes(), None)
            .expect("verify entitlement");
        assert_eq!(verified.envelope.claims.tenant_id, "tenant_acme");
        assert_eq!(verified.checkpoint.highest_sequence, 1);
        assert_eq!(verified.envelope_sha256.len(), 64);
    }

    #[test]
    fn tamper_and_wrong_anchor_are_rejected() {
        let key = signing_key();
        let mut document = sign_entitlement(claims(1), &key).expect("sign entitlement");
        let position = document
            .windows("tenant_acme".len())
            .position(|window| window == b"tenant_acme")
            .expect("tenant marker");
        document[position] = b'T';
        assert_eq!(
            verify_entitlement(&document, &key.verifying_key().to_bytes(), None),
            Err(EntitlementError::InvalidSignature)
        );
        let valid = sign_entitlement(claims(1), &key).expect("sign entitlement");
        let other = SigningKey::from_bytes(&[0x61; 32]);
        assert_eq!(
            verify_entitlement(&valid, &other.verifying_key().to_bytes(), None),
            Err(EntitlementError::InvalidSignature)
        );
    }

    #[test]
    fn noncanonical_and_unknown_documents_are_rejected() {
        let key = signing_key();
        let mut document = sign_entitlement(claims(1), &key).expect("sign entitlement");
        document.push(b'\n');
        assert_eq!(
            verify_entitlement(&document, &key.verifying_key().to_bytes(), None),
            Err(EntitlementError::NonCanonicalDocument)
        );
        let unknown = br#"{"claims":{"extra":true},"signature":"x"}"#;
        assert_eq!(
            verify_entitlement(unknown, &key.verifying_key().to_bytes(), None),
            Err(EntitlementError::InvalidDocument)
        );
    }

    #[test]
    fn checkpoint_rejects_rollback_and_conflicting_replay() {
        let key = signing_key();
        let first = sign_entitlement(claims(2), &key).expect("sign first");
        let retained = verify_entitlement(&first, &key.verifying_key().to_bytes(), None)
            .expect("verify first")
            .checkpoint;
        let older = sign_entitlement(claims(1), &key).expect("sign older");
        assert_eq!(
            verify_entitlement(&older, &key.verifying_key().to_bytes(), Some(&retained)),
            Err(EntitlementError::RollbackDetected)
        );
        let replay = verify_entitlement(&first, &key.verifying_key().to_bytes(), Some(&retained))
            .expect("idempotent exact replay");
        assert_eq!(replay.checkpoint, retained);
        let mut changed = claims(2);
        changed.grace_until_unix += 1;
        let changed = sign_entitlement(changed, &key).expect("sign conflict");
        assert_eq!(
            verify_entitlement(&changed, &key.verifying_key().to_bytes(), Some(&retained)),
            Err(EntitlementError::SequenceConflict)
        );
    }

    #[test]
    fn paid_capabilities_degrade_without_disabling_safety_paths() {
        let entitlement = verified(1);
        let active = capabilities(&entitlement, None, "device_alpha", 1_500);
        assert_eq!(active.state, EntitlementState::Active);
        assert!(active.enterprise_repair && active.fleet_sync && active.updates);

        let refresh = capabilities(&entitlement, None, "device_alpha", 2_500);
        assert_eq!(refresh.state, EntitlementState::RefreshRequired);
        assert!(refresh.enterprise_repair && refresh.cached_policy);
        assert!(!refresh.fleet_sync && !refresh.audit_upload && !refresh.updates);

        let expired = capabilities(&entitlement, None, "device_alpha", 4_001);
        assert_eq!(expired.state, EntitlementState::Expired);
        assert!(expired.diagnostics && expired.report_export && expired.rollback);
        assert!(!expired.enterprise_repair && !expired.fleet_sync && !expired.updates);
    }

    #[test]
    fn device_assignment_is_enforced_but_rollback_remains_available() {
        let entitlement = verified(1);
        let missing = capabilities(&entitlement, None, "device_gamma", 1_500);
        assert_eq!(missing.state, EntitlementState::DeviceNotAssigned);
        assert!(missing.diagnostics && missing.report_export && missing.rollback);
        assert!(!missing.enterprise_repair);
    }

    #[test]
    fn signed_revocation_is_monotonic_and_disables_paid_features() {
        let key = signing_key();
        let document = sign_revocations(
            RevocationClaims {
                schema: REVOCATIONS_SCHEMA.to_owned(),
                sequence: 7,
                issued_at_unix: 1_400,
                revoked_entitlement_ids: vec!["ent_acme_001".to_owned()],
            },
            &key,
        )
        .expect("sign revocations");
        assert_eq!(document, FIXTURE_REVOCATIONS.as_bytes());
        let revoked = verify_revocations(&document, &key.verifying_key().to_bytes(), None)
            .expect("verify revocations");
        let result = capabilities(&verified(1), Some(&revoked), "device_alpha", 1_500);
        assert_eq!(result.state, EntitlementState::Revoked);
        assert!(result.diagnostics && result.report_export && result.rollback);
        assert!(!result.enterprise_repair && !result.fleet_sync);
    }

    #[test]
    fn invalid_order_bounds_and_unsafe_integers_fail_closed() {
        let key = signing_key();
        let mut invalid = claims(1);
        invalid.device_ids.reverse();
        assert_eq!(
            sign_entitlement(invalid, &key),
            Err(EntitlementError::InvalidClaims)
        );
        let mut unsafe_sequence = claims(MAX_SAFE_INTEGER + 1);
        unsafe_sequence.device_ids = vec!["device_alpha".to_owned()];
        assert_eq!(
            sign_entitlement(unsafe_sequence, &key),
            Err(EntitlementError::InvalidClaims)
        );
    }
}
