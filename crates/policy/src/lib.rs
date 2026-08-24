#![forbid(unsafe_code)]
use kernaid_protocol::{ActionStep, Risk};

#[cfg(feature = "fixture-repair-lab")]
use kernaid_protocol::ValidatedPlan;

/// The only mutating action that the disposable fixture lab may admit.
#[cfg(feature = "fixture-repair-lab")]
pub const FIXTURE_FSTAB_ACTION_ID: &str = "linux.fstab.repair-entry.fixture-v1";
/// The action-pack preflight required by the fixture-only plan.
#[cfg(feature = "fixture-repair-lab")]
pub const FIXTURE_FSTAB_PREFLIGHT_ID: &str = "linux.fstab.preflight";
/// The plan-level backup declaration required before the fixture mutation.
#[cfg(feature = "fixture-repair-lab")]
pub const FIXTURE_FSTAB_BACKUP: &str = "required";
/// The action-pack validation required after the fixture mutation.
#[cfg(feature = "fixture-repair-lab")]
pub const FIXTURE_FSTAB_VALIDATION_ID: &str = "linux.boot.validate-fstab";
/// The only rollback action admitted for the fixture mutation.
#[cfg(feature = "fixture-repair-lab")]
pub const FIXTURE_FSTAB_ROLLBACK_ID: &str = "linux.fstab.restore";

#[cfg(feature = "fixture-repair-lab")]
const MAX_FIXTURE_EVIDENCE_IDS: usize = 32;
#[cfg(feature = "fixture-repair-lab")]
const MAX_TYPED_ID_BYTES: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    MissingEvidence,
    MissingValidation,
    MutationDisabled,
    MissingBackup,
    MissingRollback,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixturePlan,
    #[cfg(feature = "fixture-repair-lab")]
    IncoherentTargetFingerprint,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixtureEvidence,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixturePrecondition,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixtureBackup,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixtureValidation,
    #[cfg(feature = "fixture-repair-lab")]
    InvalidFixtureRollback,
}

pub fn validate_phase_zero(step: &ActionStep) -> Result<(), PolicyError> {
    if step.evidence_ids.is_empty() {
        return Err(PolicyError::MissingEvidence);
    }
    if step.validation.trim().is_empty() {
        return Err(PolicyError::MissingValidation);
    }
    if step.risk != Risk::R0 {
        return Err(PolicyError::MutationDisabled);
    }
    Ok(())
}

pub fn validate_mutation_metadata(step: &ActionStep) -> Result<(), PolicyError> {
    if matches!(step.risk, Risk::R2 | Risk::R3) && step.backup.is_none() {
        return Err(PolicyError::MissingBackup);
    }
    if matches!(step.risk, Risk::R1 | Risk::R2 | Risk::R3) && step.rollback.is_none() {
        return Err(PolicyError::MissingRollback);
    }
    Ok(())
}

/// Admit one closed, fixture-only R2 plan.
///
/// This function exists only with the `fixture-repair-lab` feature. It is not
/// a general mutation policy: the plan must contain exactly one compile-time
/// pinned action and every safety declaration must match the fixture action
/// pack exactly. The regular Phase 0 validator remains diagnosis-only.
#[cfg(feature = "fixture-repair-lab")]
pub fn validate_fixture_repair_lab_plan(
    plan: &ValidatedPlan,
    session_target_fingerprint: &str,
) -> Result<(), PolicyError> {
    if !valid_sha256_fingerprint(session_target_fingerprint)
        || plan.target_fingerprint != session_target_fingerprint
    {
        return Err(PolicyError::IncoherentTargetFingerprint);
    }
    let [step] = plan.steps.as_slice() else {
        return Err(PolicyError::InvalidFixturePlan);
    };
    if step.action != FIXTURE_FSTAB_ACTION_ID || step.risk != Risk::R2 {
        return Err(PolicyError::MutationDisabled);
    }
    if step.target_fingerprint != plan.target_fingerprint
        || !valid_sha256_fingerprint(&step.target_fingerprint)
    {
        return Err(PolicyError::IncoherentTargetFingerprint);
    }
    validate_fixture_evidence_ids(&step.evidence_ids)?;
    if step.preconditions.len() != 1 || step.preconditions[0] != FIXTURE_FSTAB_PREFLIGHT_ID {
        return Err(PolicyError::InvalidFixturePrecondition);
    }
    if step.backup.as_deref() != Some(FIXTURE_FSTAB_BACKUP) {
        return Err(PolicyError::InvalidFixtureBackup);
    }
    if step.validation != FIXTURE_FSTAB_VALIDATION_ID {
        return Err(PolicyError::InvalidFixtureValidation);
    }
    if step.rollback.as_deref() != Some(FIXTURE_FSTAB_ROLLBACK_ID) {
        return Err(PolicyError::InvalidFixtureRollback);
    }
    Ok(())
}

#[cfg(feature = "fixture-repair-lab")]
fn validate_fixture_evidence_ids(evidence_ids: &[String]) -> Result<(), PolicyError> {
    if evidence_ids.is_empty() || evidence_ids.len() > MAX_FIXTURE_EVIDENCE_IDS {
        return Err(PolicyError::MissingEvidence);
    }
    if evidence_ids.iter().any(|id| !valid_typed_id(id, "E-")) {
        return Err(PolicyError::InvalidFixtureEvidence);
    }
    let mut canonical = evidence_ids.iter().map(String::as_str).collect::<Vec<_>>();
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyError::InvalidFixtureEvidence);
    }
    Ok(())
}

#[cfg(feature = "fixture-repair-lab")]
fn valid_typed_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= MAX_TYPED_ID_BYTES
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(feature = "fixture-repair-lab")]
fn valid_sha256_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(risk: Risk) -> ActionStep {
        ActionStep {
            action: "system.observe.noop".into(),
            risk,
            target_fingerprint: "sha256:test".into(),
            evidence_ids: vec!["E-1".into()],
            preconditions: vec![],
            backup: None,
            validation: "evidence.exists".into(),
            rollback: None,
        }
    }
    #[test]
    fn phase_zero_denies_mutation() {
        assert_eq!(
            validate_phase_zero(&step(Risk::R2)),
            Err(PolicyError::MutationDisabled)
        );
    }
    #[test]
    fn observation_is_valid() {
        assert_eq!(validate_phase_zero(&step(Risk::R0)), Ok(()));
    }

    #[test]
    fn phase_zero_still_denies_the_fixture_action() {
        let mut fixture = step(Risk::R2);
        fixture.action = "linux.fstab.repair-entry.fixture-v1".into();
        fixture.backup = Some("required".into());
        fixture.rollback = Some("linux.fstab.restore".into());
        assert_eq!(
            validate_phase_zero(&fixture),
            Err(PolicyError::MutationDisabled)
        );
    }

    #[cfg(feature = "fixture-repair-lab")]
    mod fixture_repair_lab {
        use super::*;
        use kernaid_protocol::ValidatedPlan;

        const TARGET: &str =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        fn fixture_plan() -> ValidatedPlan {
            ValidatedPlan {
                plan_id: "P-fixture".into(),
                target_fingerprint: TARGET.into(),
                steps: vec![ActionStep {
                    action: FIXTURE_FSTAB_ACTION_ID.into(),
                    risk: Risk::R2,
                    target_fingerprint: TARGET.into(),
                    evidence_ids: vec!["E-LINUX-FSTAB".into(), "E-LINUX-LSBLK".into()],
                    preconditions: vec![FIXTURE_FSTAB_PREFLIGHT_ID.into()],
                    backup: Some(FIXTURE_FSTAB_BACKUP.into()),
                    validation: FIXTURE_FSTAB_VALIDATION_ID.into(),
                    rollback: Some(FIXTURE_FSTAB_ROLLBACK_ID.into()),
                }],
            }
        }

        #[test]
        fn admits_only_the_exact_fixture_contract() {
            assert_eq!(
                validate_fixture_repair_lab_plan(&fixture_plan(), TARGET),
                Ok(())
            );

            let mut wrong_action = fixture_plan();
            wrong_action.steps[0].action = "linux.fstab.repair-entry".into();
            assert_eq!(
                validate_fixture_repair_lab_plan(&wrong_action, TARGET),
                Err(PolicyError::MutationDisabled)
            );

            let mut wrong_risk = fixture_plan();
            wrong_risk.steps[0].risk = Risk::R3;
            assert_eq!(
                validate_fixture_repair_lab_plan(&wrong_risk, TARGET),
                Err(PolicyError::MutationDisabled)
            );

            let mut extra_action = fixture_plan();
            extra_action.steps.push(extra_action.steps[0].clone());
            assert_eq!(
                validate_fixture_repair_lab_plan(&extra_action, TARGET),
                Err(PolicyError::InvalidFixturePlan)
            );
        }

        #[test]
        fn binds_the_plan_step_and_session_to_one_target() {
            let mut plan_target_changed = fixture_plan();
            plan_target_changed.target_fingerprint = format!("sha256:{}", "2".repeat(64));
            assert_eq!(
                validate_fixture_repair_lab_plan(&plan_target_changed, TARGET),
                Err(PolicyError::IncoherentTargetFingerprint)
            );

            let mut step_target_changed = fixture_plan();
            step_target_changed.steps[0].target_fingerprint = format!("sha256:{}", "2".repeat(64));
            assert_eq!(
                validate_fixture_repair_lab_plan(&step_target_changed, TARGET),
                Err(PolicyError::IncoherentTargetFingerprint)
            );

            assert_eq!(
                validate_fixture_repair_lab_plan(&fixture_plan(), "sha256:fixture"),
                Err(PolicyError::IncoherentTargetFingerprint)
            );
        }

        #[test]
        fn requires_bounded_unique_typed_evidence() {
            let mut absent = fixture_plan();
            absent.steps[0].evidence_ids.clear();
            assert_eq!(
                validate_fixture_repair_lab_plan(&absent, TARGET),
                Err(PolicyError::MissingEvidence)
            );

            let mut duplicate = fixture_plan();
            duplicate.steps[0].evidence_ids = vec!["E-SAME".into(), "E-SAME".into()];
            assert_eq!(
                validate_fixture_repair_lab_plan(&duplicate, TARGET),
                Err(PolicyError::InvalidFixtureEvidence)
            );

            let mut malformed = fixture_plan();
            malformed.steps[0].evidence_ids = vec!["foreign evidence".into()];
            assert_eq!(
                validate_fixture_repair_lab_plan(&malformed, TARGET),
                Err(PolicyError::InvalidFixtureEvidence)
            );
        }

        #[test]
        fn rejects_every_contract_declaration_drift() {
            let mut precondition = fixture_plan();
            precondition.steps[0]
                .preconditions
                .push("target.still_matches".into());
            assert_eq!(
                validate_fixture_repair_lab_plan(&precondition, TARGET),
                Err(PolicyError::InvalidFixturePrecondition)
            );

            let mut backup = fixture_plan();
            backup.steps[0].backup = Some("inherited".into());
            assert_eq!(
                validate_fixture_repair_lab_plan(&backup, TARGET),
                Err(PolicyError::InvalidFixtureBackup)
            );

            let mut validation = fixture_plan();
            validation.steps[0].validation = "evidence.exists".into();
            assert_eq!(
                validate_fixture_repair_lab_plan(&validation, TARGET),
                Err(PolicyError::InvalidFixtureValidation)
            );

            let mut rollback = fixture_plan();
            rollback.steps[0].rollback = None;
            assert_eq!(
                validate_fixture_repair_lab_plan(&rollback, TARGET),
                Err(PolicyError::InvalidFixtureRollback)
            );
        }
    }
}
