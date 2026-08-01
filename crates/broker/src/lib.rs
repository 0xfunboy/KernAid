#![forbid(unsafe_code)]
use kernaid_protocol::BrokerRequest;

#[derive(Debug, PartialEq, Eq)]
pub enum BrokerError {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_actions() {
        let mut b = ObserveBroker::new("fp");
        let r = BrokerRequest {
            session_id: "s".into(),
            approval_id: None,
            target_fingerprint: "fp".into(),
            sequence: 1,
            action: "shell.exec".into(),
        };
        assert_eq!(b.execute(&r), Err(BrokerError::UnknownAction));
    }
}
