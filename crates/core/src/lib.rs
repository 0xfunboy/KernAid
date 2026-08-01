#![forbid(unsafe_code)]
use kernaid_policy::{PolicyError, validate_phase_zero};
use kernaid_protocol::ValidatedPlan;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Observe,
    Diagnose,
    Plan,
    Repair,
    Verify,
    Complete,
}
pub struct Session {
    state: State,
    fingerprint: String,
}
impl Session {
    pub fn new(fingerprint: impl Into<String>) -> Self {
        Self {
            state: State::Observe,
            fingerprint: fingerprint.into(),
        }
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn evidence_complete(&mut self) {
        if self.state == State::Observe {
            self.state = State::Diagnose;
        }
    }
    pub fn stage(&mut self, plan: &ValidatedPlan) -> Result<(), PolicyError> {
        for step in &plan.steps {
            validate_phase_zero(step)?;
        }
        if plan.target_fingerprint != self.fingerprint {
            return Err(PolicyError::MutationDisabled);
        }
        self.state = State::Plan;
        Ok(())
    }
}
