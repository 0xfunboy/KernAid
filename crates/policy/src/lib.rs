#![forbid(unsafe_code)]
use kernaid_protocol::{ActionStep, Risk};

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError { MissingEvidence, MissingValidation, MutationDisabled, MissingBackup, MissingRollback }

pub fn validate_phase_zero(step: &ActionStep) -> Result<(), PolicyError> {
    if step.evidence_ids.is_empty() { return Err(PolicyError::MissingEvidence); }
    if step.validation.trim().is_empty() { return Err(PolicyError::MissingValidation); }
    if step.risk != Risk::R0 { return Err(PolicyError::MutationDisabled); }
    Ok(())
}

pub fn validate_mutation_metadata(step: &ActionStep) -> Result<(), PolicyError> {
    if matches!(step.risk, Risk::R2 | Risk::R3) && step.backup.is_none() { return Err(PolicyError::MissingBackup); }
    if matches!(step.risk, Risk::R1 | Risk::R2 | Risk::R3) && step.rollback.is_none() { return Err(PolicyError::MissingRollback); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(risk: Risk) -> ActionStep { ActionStep { action:"system.observe.noop".into(), risk, target_fingerprint:"sha256:test".into(), evidence_ids:vec!["E-1".into()], preconditions:vec![], backup:None, validation:"evidence.exists".into(), rollback:None } }
    #[test] fn phase_zero_denies_mutation() { assert_eq!(validate_phase_zero(&step(Risk::R2)), Err(PolicyError::MutationDisabled)); }
    #[test] fn observation_is_valid() { assert_eq!(validate_phase_zero(&step(Risk::R0)), Ok(())); }
}
