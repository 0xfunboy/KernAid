#![forbid(unsafe_code)]
use kernaid_evidence::{
    Evidence,
    linux_snapshot::{
        COLLECTOR as LINUX_SNAPSHOT_COLLECTOR, CONTENT_TYPE as LINUX_SNAPSHOT_CONTENT_TYPE,
        LinuxNormalizedSnapshotEnvelope, SnapshotError,
    },
};
use kernaid_policy::{PolicyError, validate_phase_zero};
use kernaid_protocol::ValidatedPlan;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Observe,
    Diagnose,
    Plan,
    Repair,
    Verify,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    NonLinux,
    LinuxResident,
    LinuxRescue,
}

pub struct Session {
    state: State,
    fingerprint: String,
    mode: SessionMode,
    linux_snapshot: Option<LinuxSnapshotBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSnapshotBinding {
    pub evidence_id: String,
    pub evidence_sha256: String,
    pub snapshot_sha256: String,
    pub target: String,
    pub target_fingerprint: String,
    pub capture_mode: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSnapshotAdmissionError {
    InvalidSessionState,
    InvalidEvidenceBinding,
    InvalidEnvelope(SnapshotError),
    DuplicateSnapshot,
    ModeMismatch,
    IncompleteLinuxCorpus,
    ExplicitLinuxAdmissionRequired,
    UnsupportedLinuxTopology,
}

impl fmt::Display for LinuxSnapshotAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionState => "Linux snapshot admission is outside Observe",
            Self::InvalidEvidenceBinding => "Linux snapshot evidence binding is invalid",
            Self::InvalidEnvelope(_) => "Linux snapshot envelope is invalid",
            Self::DuplicateSnapshot => "Linux snapshot was already admitted",
            Self::ModeMismatch => {
                "Linux snapshot capture does not match the immutable session mode"
            }
            Self::IncompleteLinuxCorpus => "Linux evidence corpus is incomplete",
            Self::ExplicitLinuxAdmissionRequired => {
                "Linux sessions require the explicit snapshot admission transition"
            }
            Self::UnsupportedLinuxTopology => {
                "Linux snapshot declares a multi-filesystem topology unsupported by v1"
            }
        })
    }
}

impl Error for LinuxSnapshotAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEnvelope(error) => Some(error),
            _ => None,
        }
    }
}
impl Session {
    pub fn new(fingerprint: impl Into<String>, mode: SessionMode) -> Self {
        Self {
            state: State::Observe,
            fingerprint: fingerprint.into(),
            mode,
            linux_snapshot: None,
        }
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub const fn mode(&self) -> SessionMode {
        self.mode
    }

    /// Compatibility transition for explicitly non-Linux sessions only.
    pub fn evidence_complete(&mut self) -> Result<(), LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        if self.mode != SessionMode::NonLinux {
            return Err(LinuxSnapshotAdmissionError::ExplicitLinuxAdmissionRequired);
        }
        self.state = State::Diagnose;
        Ok(())
    }

    pub fn admit_linux_snapshot(
        &mut self,
        evidence: &Evidence,
        envelope_bytes: &[u8],
    ) -> Result<&LinuxSnapshotBinding, LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        if self.linux_snapshot.is_some() {
            return Err(LinuxSnapshotAdmissionError::DuplicateSnapshot);
        }
        let envelope = LinuxNormalizedSnapshotEnvelope::parse(envelope_bytes)
            .map_err(LinuxSnapshotAdmissionError::InvalidEnvelope)?;
        if !envelope.snapshot.topology.supported {
            return Err(LinuxSnapshotAdmissionError::UnsupportedLinuxTopology);
        }
        let evidence_hash = format!("{:x}", Sha256::digest(envelope_bytes));
        let (capture_mode, target_valid) = match self.mode {
            SessionMode::LinuxResident if envelope.capture.is_resident() => {
                ("resident", evidence.target == "local-machine")
            }
            SessionMode::LinuxRescue if envelope.capture.is_rescue() => {
                ("rescue", evidence.target == "selected-installed-target")
            }
            SessionMode::NonLinux | SessionMode::LinuxResident | SessionMode::LinuxRescue => {
                return Err(LinuxSnapshotAdmissionError::ModeMismatch);
            }
        };
        if evidence.id.is_empty()
            || evidence.collector != LINUX_SNAPSHOT_COLLECTOR
            || evidence.content_type != LINUX_SNAPSHOT_CONTENT_TYPE
            || !evidence.is_untrusted()
            || !target_valid
            || evidence.sha256 != evidence_hash
            || evidence.blob_ref != format!("sha256:{evidence_hash}")
        {
            return Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding);
        }
        self.linux_snapshot = Some(LinuxSnapshotBinding {
            evidence_id: evidence.id.clone(),
            evidence_sha256: evidence_hash,
            snapshot_sha256: envelope.snapshot_sha256,
            target: evidence.target.clone(),
            target_fingerprint: self.fingerprint.clone(),
            capture_mode,
        });
        Ok(self
            .linux_snapshot
            .as_ref()
            .expect("snapshot binding was inserted"))
    }

    pub fn linux_snapshot_binding(&self) -> Option<&LinuxSnapshotBinding> {
        self.linux_snapshot.as_ref()
    }

    pub fn linux_evidence_complete(
        &mut self,
        evidence: &[Evidence],
    ) -> Result<(), LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        let binding = self
            .linux_snapshot
            .as_ref()
            .ok_or(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)?;
        let snapshot_collector_count = evidence
            .iter()
            .filter(|item| item.collector == LINUX_SNAPSHOT_COLLECTOR)
            .count();
        let bound_snapshot_count = evidence
            .iter()
            .filter(|item| {
                item.id == binding.evidence_id
                    && item.collector == LINUX_SNAPSHOT_COLLECTOR
                    && item.sha256 == binding.evidence_sha256
                    && item.target == binding.target
            })
            .count();
        let evidence_ids = evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect::<HashSet<_>>();
        if snapshot_collector_count != 1
            || bound_snapshot_count != 1
            || evidence_ids.len() != evidence.len()
            || evidence
                .iter()
                .any(|item| item.target != binding.target || !item.is_untrusted())
        {
            return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
        }
        match self.mode {
            SessionMode::LinuxResident => {
                if evidence.len() != LINUX_RESIDENT_REQUIRED_COLLECTORS.len() + 1
                    || evidence.iter().any(|item| {
                        item.collector != LINUX_SNAPSHOT_COLLECTOR
                            && !LINUX_RESIDENT_REQUIRED_COLLECTORS
                                .contains(&item.collector.as_str())
                    })
                    || LINUX_RESIDENT_REQUIRED_COLLECTORS.iter().any(|collector| {
                        evidence
                            .iter()
                            .filter(|item| item.collector == *collector)
                            .count()
                            != 1
                    })
                {
                    return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
                }
            }
            SessionMode::LinuxRescue => {
                if evidence.len() != 1 {
                    return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
                }
            }
            SessionMode::NonLinux => {
                return Err(LinuxSnapshotAdmissionError::ModeMismatch);
            }
        }
        self.state = State::Diagnose;
        Ok(())
    }
    pub fn stage(&mut self, plan: &ValidatedPlan) -> Result<(), PolicyError> {
        if self.state != State::Diagnose {
            return Err(PolicyError::MutationDisabled);
        }
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

pub const LINUX_RESIDENT_P0_COLLECTORS: [&str; 9] = [
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
];

pub const LINUX_RESIDENT_REQUIRED_COLLECTORS: [&str; 10] = [
    "system.hostname",
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
];

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_evidence::linux_snapshot::{
        COLLECTION_SCOPE, LinuxBoot, LinuxConfiguration, LinuxFilesystemTopology,
        LinuxFstabSummary, LinuxNormalizedSnapshot, LinuxNormalizedSnapshotEnvelope,
        LinuxPackageDatabases, LinuxRelease, LinuxSnapshotCapture, SNAPSHOT_SCOPE,
    };
    use kernaid_protocol::{ActionStep, Risk};

    fn envelope(capture: LinuxSnapshotCapture) -> Vec<u8> {
        envelope_with_topology(capture, true)
    }

    fn envelope_with_topology(capture: LinuxSnapshotCapture, supported: bool) -> Vec<u8> {
        LinuxNormalizedSnapshotEnvelope::new(
            capture,
            LinuxNormalizedSnapshot {
                family: "linux".to_owned(),
                scope: SNAPSHOT_SCOPE.to_owned(),
                installation_confirmed: true,
                topology: LinuxFilesystemTopology {
                    collection_scope: COLLECTION_SCOPE.to_owned(),
                    separate_etc_mount_present: !supported,
                    separate_boot_mount_present: false,
                    separate_usr_mount_present: false,
                    separate_var_mount_present: false,
                    relevant_separate_mount_present: !supported,
                    supported,
                },
                release: LinuxRelease {
                    id: Some("fixture".to_owned()),
                    name: None,
                    pretty_name: None,
                    version_id: None,
                    source: "etc-os-release".to_owned(),
                },
                boot: LinuxBoot {
                    directory_present: false,
                    kernel_artifact_count: 0,
                    initramfs_artifact_count: 0,
                    bootloader_directory_count: 0,
                    symlink_artifact_count: 0,
                },
                configuration: LinuxConfiguration {
                    fstab: LinuxFstabSummary {
                        present: false,
                        entry_count: 0,
                        root_entry_present: false,
                        efi_entry_present: false,
                        swap_entry_count: 0,
                        network_entry_count: 0,
                        malformed_line_count: 0,
                    },
                    machine_id_present: false,
                },
                package_databases: LinuxPackageDatabases {
                    dpkg_status_present: false,
                    rpm_database_present: false,
                    pacman_database_present: false,
                },
            },
        )
        .expect("snapshot")
        .canonical_json()
        .expect("canonical envelope")
    }

    fn evidence(target: &str, bytes: &[u8]) -> Evidence {
        let hash = format!("{:x}", Sha256::digest(bytes));
        Evidence {
            id: "E-SNAPSHOT".to_owned(),
            collector: LINUX_SNAPSHOT_COLLECTOR.to_owned(),
            target: target.to_owned(),
            captured_at: "2026-08-20T00:00:00Z".to_owned(),
            content_type: LINUX_SNAPSHOT_CONTENT_TYPE.to_owned(),
            sha256: hash.clone(),
            sensitivity: "system".to_owned(),
            trust: "observed-untrusted".to_owned(),
            summary: "fixture".to_owned(),
            blob_ref: format!("sha256:{hash}"),
        }
    }

    fn resident_corpus(snapshot: Evidence) -> Vec<Evidence> {
        let mut evidence = vec![snapshot];
        evidence.extend(LINUX_RESIDENT_REQUIRED_COLLECTORS.iter().enumerate().map(
            |(index, collector)| Evidence {
                id: format!("E-P0-{index}"),
                collector: (*collector).to_owned(),
                target: "local-machine".to_owned(),
                captured_at: "2026-08-20T00:00:00Z".to_owned(),
                content_type: "text/plain".to_owned(),
                sha256: "1".repeat(64),
                sensitivity: "system".to_owned(),
                trust: "observed-untrusted".to_owned(),
                summary: "fixture".to_owned(),
                blob_ref: format!("sha256:{}", "1".repeat(64)),
            },
        ));
        evidence
    }

    fn r0_plan() -> ValidatedPlan {
        ValidatedPlan {
            plan_id: "P-fixture".to_owned(),
            target_fingerprint: "sha256:fixture".to_owned(),
            steps: vec![ActionStep {
                action: "system.observe.noop".to_owned(),
                risk: Risk::R0,
                target_fingerprint: "sha256:fixture".to_owned(),
                evidence_ids: vec!["E-SNAPSHOT".to_owned()],
                preconditions: vec![],
                backup: None,
                validation: "evidence.exists".to_owned(),
                rollback: None,
            }],
        }
    }

    #[test]
    fn linux_transition_requires_a_hash_and_capture_bound_snapshot() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let snapshot_evidence = evidence("local-machine", &bytes);
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.linux_evidence_complete(&[]),
            Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)
        );
        let binding = session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(binding.capture_mode, "resident");
        assert_eq!(
            session.linux_evidence_complete(std::slice::from_ref(&snapshot_evidence)),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );
        let production_corpus = resident_corpus(snapshot_evidence);
        assert_eq!(production_corpus.len(), 11);
        session
            .linux_evidence_complete(&production_corpus)
            .expect("Linux evidence complete");
        assert_eq!(session.state(), &State::Diagnose);
    }

    #[test]
    fn linux_transition_rejects_foreign_duplicate_and_extra_evidence() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let snapshot_evidence = evidence("local-machine", &bytes);

        let mut foreign = resident_corpus(snapshot_evidence.clone());
        foreign[2].target = "foreign-machine".to_owned();
        let mut foreign_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        foreign_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            foreign_session.linux_evidence_complete(&foreign),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut duplicate_id = resident_corpus(snapshot_evidence.clone());
        duplicate_id[2].id = duplicate_id[0].id.clone();
        let mut duplicate_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        duplicate_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            duplicate_session.linux_evidence_complete(&duplicate_id),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut duplicate_collector = resident_corpus(snapshot_evidence.clone());
        duplicate_collector
            .last_mut()
            .expect("last P0 item")
            .collector = LINUX_RESIDENT_P0_COLLECTORS[0].to_owned();
        let mut duplicate_collector_session =
            Session::new("sha256:fixture", SessionMode::LinuxResident);
        duplicate_collector_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            duplicate_collector_session.linux_evidence_complete(&duplicate_collector),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut extra = resident_corpus(snapshot_evidence.clone());
        let mut extra_item = extra[2].clone();
        extra_item.id = "E-EXTRA".to_owned();
        extra_item.collector = "linux.raw.uncontracted".to_owned();
        extra.push(extra_item);
        let mut extra_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        extra_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            extra_session.linux_evidence_complete(&extra),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let rescue_bytes = envelope(LinuxSnapshotCapture::rescue());
        let rescue_snapshot = evidence("selected-installed-target", &rescue_bytes);
        let mut rescue_extra = vec![rescue_snapshot.clone()];
        let mut extra_item = rescue_snapshot.clone();
        extra_item.id = "E-EXTRA".to_owned();
        extra_item.collector = "linux.raw.uncontracted".to_owned();
        rescue_extra.push(extra_item);
        let mut rescue_session = Session::new("sha256:fixture", SessionMode::LinuxRescue);
        rescue_session
            .admit_linux_snapshot(&rescue_snapshot, &rescue_bytes)
            .expect("admitted snapshot");
        assert_eq!(
            rescue_session.linux_evidence_complete(&rescue_extra),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );
    }

    #[test]
    fn rescue_attestation_cannot_bind_to_a_resident_target() {
        let bytes = envelope(LinuxSnapshotCapture::rescue());
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.admit_linux_snapshot(&evidence("selected-installed-target", &bytes), &bytes),
            Err(LinuxSnapshotAdmissionError::ModeMismatch)
        );
    }

    #[test]
    fn resident_attestation_cannot_bind_to_a_rescue_session() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxRescue);
        assert_eq!(
            session.admit_linux_snapshot(&evidence("local-machine", &bytes), &bytes),
            Err(LinuxSnapshotAdmissionError::ModeMismatch)
        );
    }

    #[test]
    fn unsupported_topology_is_rejected_in_both_linux_modes() {
        for (mode, capture, target) in [
            (
                SessionMode::LinuxResident,
                LinuxSnapshotCapture::resident(),
                "local-machine",
            ),
            (
                SessionMode::LinuxRescue,
                LinuxSnapshotCapture::rescue(),
                "selected-installed-target",
            ),
        ] {
            let bytes = envelope_with_topology(capture, false);
            let mut session = Session::new("sha256:fixture", mode);
            assert_eq!(
                session.admit_linux_snapshot(&evidence(target, &bytes), &bytes),
                Err(LinuxSnapshotAdmissionError::UnsupportedLinuxTopology)
            );
            assert_eq!(session.state(), &State::Observe);
        }
    }

    #[test]
    fn legacy_transition_is_explicitly_non_linux_only() {
        let mut linux = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            linux.evidence_complete(),
            Err(LinuxSnapshotAdmissionError::ExplicitLinuxAdmissionRequired)
        );
        assert_eq!(linux.state(), &State::Observe);

        let mut non_linux = Session::new("sha256:fixture", SessionMode::NonLinux);
        non_linux
            .evidence_complete()
            .expect("non-Linux compatibility");
        assert_eq!(non_linux.state(), &State::Diagnose);
    }

    #[test]
    fn fresh_linux_sessions_cannot_bypass_snapshot_admission_by_staging() {
        for mode in [SessionMode::LinuxResident, SessionMode::LinuxRescue] {
            let mut session = Session::new("sha256:fixture", mode);
            assert_eq!(
                session.stage(&r0_plan()),
                Err(PolicyError::MutationDisabled)
            );
            assert_eq!(session.state(), &State::Observe);
        }
    }

    #[test]
    fn wrapper_hash_tampering_fails_before_admission() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let mut bound = evidence("local-machine", &bytes);
        bound.sha256 = "0".repeat(64);
        bound.blob_ref = format!("sha256:{}", bound.sha256);
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.admit_linux_snapshot(&bound, &bytes),
            Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)
        );
    }
}
