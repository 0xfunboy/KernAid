//! Closed, path-free protocol values for the Rescue `crypttab` candidate.

use std::fmt;

pub const ACTION_ID: &str = "linux.crypttab.disable-missing-uuid.v1";
pub const RESOURCE_ID: &str = "rescue:selected-linux-root:etc/crypttab";
pub const FINDING_ID: &str = "KA-LNX-P0-012";
pub const FINDING_VERSION: u16 = 1;
pub const EVIDENCE_IDS: [&str; 3] = ["E-LINUX-CRYPTTAB", "E-LINUX-FSTAB", "E-LINUX-LSBLK"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueCrypttabProtocolError {
    InvalidRequestId,
    InvalidSessionId,
    InvalidPlanId,
    InvalidScanFingerprint,
    InvalidTargetId,
    InvalidHash,
    InvalidEvidence,
    InvalidContract,
}

impl fmt::Display for RescueCrypttabProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid closed Rescue crypttab protocol value")
    }
}

impl std::error::Error for RescueCrypttabProtocolError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabPrepareRequest {
    request_id: String,
    session_id: String,
    plan_id: String,
    scan_fingerprint: String,
    target_id: String,
    target_fingerprint: String,
}

impl RescueCrypttabPrepareRequest {
    pub fn new(
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        target_id: impl Into<String>,
        target_fingerprint: impl Into<String>,
    ) -> Result<Self, RescueCrypttabProtocolError> {
        let value = Self {
            request_id: request_id.into(),
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            target_id: target_id.into(),
            target_fingerprint: target_fingerprint.into(),
        };
        if !valid_request_id(&value.request_id) {
            return Err(RescueCrypttabProtocolError::InvalidRequestId);
        }
        if !valid_prefixed_id(&value.session_id, "S-") {
            return Err(RescueCrypttabProtocolError::InvalidSessionId);
        }
        if !valid_prefixed_id(&value.plan_id, "P-") {
            return Err(RescueCrypttabProtocolError::InvalidPlanId);
        }
        if !valid_digest(&value.scan_fingerprint, "scan:") {
            return Err(RescueCrypttabProtocolError::InvalidScanFingerprint);
        }
        if !valid_digest(&value.target_id, "target:") {
            return Err(RescueCrypttabProtocolError::InvalidTargetId);
        }
        if !valid_digest(&value.target_fingerprint, "sha256:") {
            return Err(RescueCrypttabProtocolError::InvalidHash);
        }
        Ok(value)
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabEvidenceBinding {
    evidence_id: String,
    sha256: String,
}

impl RescueCrypttabEvidenceBinding {
    pub fn new(
        evidence_id: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, RescueCrypttabProtocolError> {
        let value = Self {
            evidence_id: evidence_id.into(),
            sha256: sha256.into(),
        };
        if !EVIDENCE_IDS.contains(&value.evidence_id.as_str())
            || !valid_digest(&value.sha256, "sha256:")
        {
            return Err(RescueCrypttabProtocolError::InvalidEvidence);
        }
        Ok(value)
    }
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Audit-only descriptor. It carries no bytes, path, mapper name or write
/// capability and therefore cannot substitute for retained broker authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabPreparedDescriptor {
    request_id: String,
    session_id: String,
    plan_id: String,
    plan_sha256: String,
    scan_fingerprint: String,
    target_id: String,
    target_fingerprint: String,
    before_sha256: String,
    after_sha256: String,
    diff_sha256: String,
    observed_uuid_set_sha256: String,
    fstab_consumer_set_sha256: String,
    evidence: [RescueCrypttabEvidenceBinding; 3],
}

impl RescueCrypttabPreparedDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &RescueCrypttabPrepareRequest,
        plan_sha256: impl Into<String>,
        before_sha256: impl Into<String>,
        after_sha256: impl Into<String>,
        diff_sha256: impl Into<String>,
        observed_uuid_set_sha256: impl Into<String>,
        fstab_consumer_set_sha256: impl Into<String>,
        evidence: [RescueCrypttabEvidenceBinding; 3],
    ) -> Result<Self, RescueCrypttabProtocolError> {
        let value = Self {
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            plan_id: request.plan_id.clone(),
            plan_sha256: plan_sha256.into(),
            scan_fingerprint: request.scan_fingerprint.clone(),
            target_id: request.target_id.clone(),
            target_fingerprint: request.target_fingerprint.clone(),
            before_sha256: before_sha256.into(),
            after_sha256: after_sha256.into(),
            diff_sha256: diff_sha256.into(),
            observed_uuid_set_sha256: observed_uuid_set_sha256.into(),
            fstab_consumer_set_sha256: fstab_consumer_set_sha256.into(),
            evidence,
        };
        if [
            &value.plan_sha256,
            &value.target_fingerprint,
            &value.before_sha256,
            &value.after_sha256,
            &value.diff_sha256,
            &value.observed_uuid_set_sha256,
            &value.fstab_consumer_set_sha256,
        ]
        .into_iter()
        .any(|hash| !valid_digest(hash, "sha256:"))
            || !valid_digest(&value.scan_fingerprint, "scan:")
            || !valid_digest(&value.target_id, "target:")
            || value.before_sha256 == value.after_sha256
            || value
                .evidence
                .iter()
                .map(RescueCrypttabEvidenceBinding::evidence_id)
                .ne(EVIDENCE_IDS)
        {
            return Err(RescueCrypttabProtocolError::InvalidContract);
        }
        Ok(value)
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }
    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }
    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }
    pub fn observed_uuid_set_sha256(&self) -> &str {
        &self.observed_uuid_set_sha256
    }
    pub fn fstab_consumer_set_sha256(&self) -> &str {
        &self.fstab_consumer_set_sha256
    }
    pub fn evidence(&self) -> &[RescueCrypttabEvidenceBinding; 3] {
        &self.evidence
    }
    pub const fn action_id(&self) -> &'static str {
        ACTION_ID
    }
    pub const fn resource_id(&self) -> &'static str {
        RESOURCE_ID
    }
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn valid_request_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 38
        && bytes.starts_with(b"R-")
        && [10, 15, 20, 25].iter().all(|index| bytes[*index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            index < 2
                || [10, 15, 20, 25].contains(&index)
                || byte.is_ascii_digit()
                || matches!(*byte, b'a'..=b'f')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RescueCrypttabPrepareRequest {
        RescueCrypttabPrepareRequest::new(
            "R-01234567-89ab-cdef-0123-456789abcdef",
            "S-crypttab",
            "P-crypttab",
            format!("scan:{}", "1".repeat(64)),
            format!("target:{}", "2".repeat(64)),
            format!("sha256:{}", "3".repeat(64)),
        )
        .expect("valid request")
    }

    #[test]
    fn request_is_path_action_and_bytes_free() {
        let request = request();
        assert_eq!(request.session_id(), "S-crypttab");
        let debug = format!("{request:?}");
        assert!(!debug.contains("/etc"));
        assert!(!debug.contains("linux.crypttab"));
    }

    #[test]
    fn evidence_order_is_closed() {
        let bindings = EVIDENCE_IDS.map(|id| {
            RescueCrypttabEvidenceBinding::new(id, format!("sha256:{}", "4".repeat(64)))
                .expect("binding")
        });
        let descriptor = RescueCrypttabPreparedDescriptor::new(
            &request(),
            format!("sha256:{}", "5".repeat(64)),
            format!("sha256:{}", "6".repeat(64)),
            format!("sha256:{}", "7".repeat(64)),
            format!("sha256:{}", "8".repeat(64)),
            format!("sha256:{}", "9".repeat(64)),
            format!("sha256:{}", "a".repeat(64)),
            bindings,
        )
        .expect("descriptor");
        assert_eq!(descriptor.action_id(), ACTION_ID);
        assert_eq!(descriptor.resource_id(), RESOURCE_ID);
    }
}
