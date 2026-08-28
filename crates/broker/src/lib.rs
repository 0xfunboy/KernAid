#![forbid(unsafe_code)]
use kernaid_protocol::BrokerRequest;

/// Linux-only broker for the explicitly marked disposable `fstab` fixture.
/// Its opt-in Desk bridge remains disconnected from production targets.
#[cfg(all(target_os = "linux", feature = "fixture-repair-lab"))]
pub mod fixture_repair;

/// Linux-only, read-only preflight for the disabled Rescue `fstab` candidate.
/// This module is not registered as a broker action and contains no mutation
/// or filesystem implementation.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_fstab_candidate;

/// Closed, off-default same-boot executor and durable reboot recovery for the
/// sole authorized Phase 1 Rescue mutation.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_fstab_executor;

/// Descriptor-only, detached read-only ext4 observation for the Rescue
/// `fstab` candidate. The module is absent from default broker builds.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_fstab_observer;

/// Real, off-default composition of target acquisition, read-only `fstab`
/// observation and Repair Vault reservation for the candidate preflight.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_fstab_preflight_resolver;

/// Closed bounded local API and single-authority state machine for the gated
/// Rescue repair service.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_repair_service;

/// Production Core/preflight/executor composition behind the closed repair
/// service. It is absent from every default build.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_repair_service_engine;

/// Authenticated systemd-activated local transport for repaird.
#[cfg(all(target_os = "linux", feature = "rescue-fstab-production-candidate"))]
pub mod rescue_repair_service_transport;

/// Linux-only client for the fixed, root-authenticated Rescue repair-vault
/// endpoint. It is opt-in and exposes only the closed repair lifecycle.
#[cfg(all(target_os = "linux", feature = "repair-vault-client"))]
pub mod repair_vault_client;

/// Linux-only client for the root-owned, fixed Rescue target-capability
/// endpoint. It transfers a read-only block descriptor and path-free claims;
/// no normal broker build contains this transport.
#[cfg(all(target_os = "linux", feature = "rescue-target-physical-parent"))]
pub mod target_capability_client;

/// Linux-only, descriptor-bound physical-parent resolver. It is deliberately
/// separate from the default broker and exposes no device pathname.
#[cfg(all(target_os = "linux", feature = "rescue-target-physical-parent"))]
pub mod target_physical_parent;

#[derive(Debug, PartialEq, Eq)]
pub enum BrokerError {
    InvalidRequest,
    UnknownAction,
    StaleTarget,
    NonMonotonicSequence,
}

pub struct ObserveBroker {
    fingerprint: String,
    last_sequence: u64,
}
impl ObserveBroker {
    pub fn new(fingerprint: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            last_sequence: 0,
        }
    }
    pub fn execute(&mut self, request: &BrokerRequest) -> Result<&'static str, BrokerError> {
        if request.action != "system.observe.noop" {
            return Err(BrokerError::UnknownAction);
        }
        if request.session_id.trim().is_empty()
            || request.session_id.len() > 128
            || request.plan_id.trim().is_empty()
            || request.plan_id.len() > 128
            || !valid_fingerprint(&request.target_fingerprint)
        {
            return Err(BrokerError::InvalidRequest);
        }
        if request.target_fingerprint != self.fingerprint {
            return Err(BrokerError::StaleTarget);
        }
        if request.sequence <= self.last_sequence {
            return Err(BrokerError::NonMonotonicSequence);
        }
        self.last_sequence = request.sequence;
        Ok("observed")
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const FINGERPRINT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn request(sequence: u64) -> BrokerRequest {
        BrokerRequest {
            session_id: "S-test".into(),
            plan_id: "P-test".into(),
            approval_id: None,
            target_fingerprint: FINGERPRINT.into(),
            sequence,
            action: "system.observe.noop".into(),
        }
    }

    #[test]
    fn rejects_unknown_actions() {
        let mut b = ObserveBroker::new(FINGERPRINT);
        let mut r = request(1);
        r.action = "shell.exec".into();
        assert_eq!(b.execute(&r), Err(BrokerError::UnknownAction));
    }

    #[test]
    fn rejects_stale_target_and_replayed_sequence() {
        let mut broker = ObserveBroker::new(FINGERPRINT);
        let mut stale = request(1);
        stale.target_fingerprint =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".into();
        assert_eq!(broker.execute(&stale), Err(BrokerError::StaleTarget));
        assert_eq!(broker.execute(&request(1)), Ok("observed"));
        assert_eq!(
            broker.execute(&request(1)),
            Err(BrokerError::NonMonotonicSequence)
        );
    }

    #[test]
    fn rejects_malformed_envelopes() {
        let mut broker = ObserveBroker::new(FINGERPRINT);
        let mut malformed = request(1);
        malformed.session_id.clear();
        assert_eq!(broker.execute(&malformed), Err(BrokerError::InvalidRequest));
        malformed.session_id = "S-test".into();
        malformed.target_fingerprint = "not-a-fingerprint".into();
        assert_eq!(broker.execute(&malformed), Err(BrokerError::InvalidRequest));
    }
}
