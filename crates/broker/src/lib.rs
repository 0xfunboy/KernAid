#![forbid(unsafe_code)]
use kernaid_protocol::BrokerRequest;

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
