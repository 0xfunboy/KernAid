//! Opt-in Desk bridge for the disposable Linux repair fixture.
//!
//! This module is compiled only with `fixture-repair-lab`. The IPC surface is
//! intentionally closed: callers can supply approval identifiers and the
//! opaque values returned by staging, but never paths, commands, environment
//! variables, action identifiers, or file content.

use kernaid_broker::fixture_repair::{
    FixtureEvidenceBinding, FixtureRepairApproval, FixtureRepairBroker, FixtureRepairConfig,
    FixtureRollbackApproval, StageFixtureRepairRequest, StageFixtureRollbackRequest,
    StagedFixtureRepair, StagedFixtureRollback,
};
use kernaid_device_identity::DeviceIdentity;
use kernaid_linux_pack::{
    action_contract::FIXTURE_ACTION_ID,
    diagnostics::{DiagnosticReport, EvidenceInput, LinuxP0Inputs, diagnose_linux_p0},
};
use kernaid_storage::{
    JOURNAL_KEY_BYTES, JournalAnchor, JournalKey, JournalSecretStore, SecretStoreError,
    SecureJournal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    error::Error,
    fmt, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::State;
use tempfile::TempDir;
use zeroize::Zeroizing;

const FINDING_ID: &str = "KA-LNX-P0-003";
const FINDING_VERSION: u32 = 2;
const MAX_STAGED_PLANS: usize = 32;

const BROKEN_FSTAB: &[u8] = include_bytes!(
    "../../../../packs/linux/fixtures/repair/fstab-missing-device-v1/root/etc/fstab"
);
const DISPOSABLE_MARKER: &[u8] = include_bytes!(
    "../../../../packs/linux/fixtures/repair/fstab-missing-device-v1/root/.kernaid-disposable-fixture"
);
const HEALTHY_LSBLK: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/lsblk.json");
const HEALTHY_READ_ONLY_MOUNTS: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/findmnt-read-only.json");
const HEALTHY_FAILED: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/systemctl-failed.txt");
const HEALTHY_UNIT_STATE: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/systemctl-unit-state.txt");
const HEALTHY_DF: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/df.txt");
const HEALTHY_LINK: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/ip-link.json");
const HEALTHY_ROUTE: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/ip-route.json");
const HEALTHY_DPKG: &[u8] =
    include_bytes!("../../../../packs/linux/fixtures/diagnostics/healthy/dpkg-audit.txt");

#[derive(Debug)]
pub(crate) struct FixtureLabInitError;

impl fmt::Display for FixtureLabInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the isolated fixture repair lab could not be initialized")
    }
}

impl Error for FixtureLabInitError {}

#[derive(Default)]
struct EphemeralJournalSecretStore {
    key: Option<Zeroizing<[u8; JOURNAL_KEY_BYTES]>>,
    anchor: Option<JournalAnchor>,
}

impl JournalSecretStore for EphemeralJournalSecretStore {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        Ok(self
            .key
            .as_ref()
            .map(|key| JournalKey::from_zeroizing(Zeroizing::new(**key))))
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        self.key = Some(Zeroizing::new(*key.expose_secret()));
        Ok(())
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        Ok(self.anchor)
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        self.anchor = Some(*anchor);
        Ok(())
    }
}

struct FixtureLabInner {
    _temporary_root: TempDir,
    fixture_root: PathBuf,
    backup_root: PathBuf,
    journal: SecureJournal<EphemeralJournalSecretStore>,
    identity: DeviceIdentity,
    staged_repairs: HashMap<String, StagedFixtureRepair>,
    staged_rollbacks: HashMap<String, StagedFixtureRollback>,
    completed_repairs: HashMap<String, FixtureLabExecuteResponse>,
    completed_rollbacks: HashMap<String, FixtureLabRollbackExecuteResponse>,
}

pub(crate) struct FixtureRepairLab(Mutex<FixtureLabInner>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureLabStageRequest {
    session_id: String,
    plan_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureLabExecuteRequest {
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_snapshot: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureLabRollbackStageRequest {
    session_id: String,
    plan_id: String,
    repair_approval_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureLabRollbackExecuteRequest {
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_snapshot: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureLabReconcileRequest {
    approval_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabEvidenceSummary {
    id: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabStageResponse {
    session_id: String,
    plan_id: String,
    action_id: &'static str,
    resource_id: &'static str,
    diagnosis_sha256: String,
    finding_id: &'static str,
    finding_version: u32,
    evidence: Vec<FixtureLabEvidenceSummary>,
    target_snapshot: String,
    expected_before_sha256: String,
    expected_after_sha256: String,
    diff_sha256: String,
    backup_locator: String,
    plan_hash: String,
    risk: &'static str,
    backup: &'static str,
    validation: &'static str,
    rollback: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabExecuteResponse {
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    action_id: &'static str,
    resource_id: &'static str,
    risk: &'static str,
    diagnosis_sha256: String,
    finding_id: &'static str,
    finding_version: u32,
    evidence: Vec<FixtureLabEvidenceSummary>,
    target_snapshot: String,
    before_sha256: String,
    after_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    validation_passed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabRollbackStageResponse {
    session_id: String,
    plan_id: String,
    repair_approval_id: String,
    repair_plan_hash: String,
    action_id: &'static str,
    resource_id: &'static str,
    target_snapshot: String,
    installed_sha256: String,
    restored_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    plan_hash: String,
    risk: &'static str,
    validation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabRollbackExecuteResponse {
    repair_approval_id: String,
    rollback_approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    action_id: &'static str,
    resource_id: &'static str,
    risk: &'static str,
    target_snapshot: String,
    replaced_sha256: String,
    restored_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    validation_passed: bool,
    final_state: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabStatusResponse {
    enabled: bool,
    mutation_blocked: bool,
    next_approval_sequence: Option<u64>,
    finding: Option<FixtureLabFindingSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureLabFindingSummary {
    diagnosis_sha256: String,
    finding_id: &'static str,
    finding_version: u32,
    evidence: Vec<FixtureLabEvidenceSummary>,
}

impl FixtureRepairLab {
    pub(crate) fn new() -> Result<Self, FixtureLabInitError> {
        let temporary_root = tempfile::Builder::new()
            .prefix("kernaid-fixture-repair-lab-")
            .tempdir()
            .map_err(|_| FixtureLabInitError)?;
        let fixture_root = temporary_root.path().join("target");
        let backup_root = temporary_root.path().join("backup");
        let fixture_etc = fixture_root.join("etc");
        create_private_directory(&fixture_root)?;
        create_private_directory(&fixture_etc)?;
        create_private_directory(&backup_root)?;
        write_embedded_file(
            &fixture_root.join(".kernaid-disposable-fixture"),
            DISPOSABLE_MARKER,
            0o600,
        )?;
        write_embedded_file(&fixture_etc.join("fstab"), BROKEN_FSTAB, 0o644)?;

        let mut journal = SecureJournal::open(
            &temporary_root.path().join("fixture-repair.db"),
            EphemeralJournalSecretStore::default(),
        )
        .map_err(|_| FixtureLabInitError)?;
        let identity = DeviceIdentity::generate();
        let config = FixtureRepairConfig::new(&fixture_root, &backup_root)
            .map_err(|_| FixtureLabInitError)?;
        FixtureRepairBroker::attach(config, &mut journal, &identity)
            .map_err(|_| FixtureLabInitError)?;

        Ok(Self(Mutex::new(FixtureLabInner {
            _temporary_root: temporary_root,
            fixture_root,
            backup_root,
            journal,
            identity,
            staged_repairs: HashMap::new(),
            staged_rollbacks: HashMap::new(),
            completed_repairs: HashMap::new(),
            completed_rollbacks: HashMap::new(),
        })))
    }

    fn status(&self) -> Result<FixtureLabStatusResponse, String> {
        let mut inner = self.0.lock().map_err(|_| status_error())?;
        let fstab = fs::read(inner.fixture_root.join("etc/fstab")).map_err(|_| status_error())?;
        let finding = fixture_finding(&fstab).map_err(|_| status_error())?.map(
            |(diagnosis_sha256, evidence)| FixtureLabFindingSummary {
                diagnosis_sha256,
                finding_id: FINDING_ID,
                finding_version: FINDING_VERSION,
                evidence: evidence
                    .into_iter()
                    .map(|binding| FixtureLabEvidenceSummary {
                        id: binding.id().to_owned(),
                        sha256: binding.sha256().to_owned(),
                    })
                    .collect(),
            },
        );
        let config = FixtureRepairConfig::new(&inner.fixture_root, &inner.backup_root)
            .map_err(|_| status_error())?;
        let FixtureLabInner {
            journal, identity, ..
        } = &mut *inner;
        let broker =
            FixtureRepairBroker::attach(config, journal, identity).map_err(|_| status_error())?;
        let mutation_blocked = broker.is_mutation_blocked();
        let next_approval_sequence = if mutation_blocked {
            None
        } else {
            Some(
                broker
                    .next_approval_sequence()
                    .map_err(|_| status_error())?,
            )
        };
        Ok(FixtureLabStatusResponse {
            enabled: true,
            mutation_blocked,
            next_approval_sequence,
            finding,
        })
    }

    fn stage(&self, request: FixtureLabStageRequest) -> Result<FixtureLabStageResponse, String> {
        let mut inner = self.0.lock().map_err(|_| stage_error())?;
        if inner.staged_repairs.len() >= MAX_STAGED_PLANS
            || inner.staged_repairs.contains_key(&request.plan_id)
            || inner.staged_rollbacks.contains_key(&request.plan_id)
        {
            return Err(stage_error());
        }

        let fstab = fs::read(inner.fixture_root.join("etc/fstab")).map_err(|_| stage_error())?;
        let (diagnosis_sha256, evidence) = diagnose_fixture(&fstab)?;
        let config = FixtureRepairConfig::new(&inner.fixture_root, &inner.backup_root)
            .map_err(|_| stage_error())?;
        let staged = {
            let FixtureLabInner {
                journal, identity, ..
            } = &mut *inner;
            let broker = FixtureRepairBroker::attach(config, journal, identity)
                .map_err(|_| stage_error())?;
            broker
                .stage(StageFixtureRepairRequest {
                    session_id: &request.session_id,
                    plan_id: &request.plan_id,
                    action_id: FIXTURE_ACTION_ID,
                    diagnosis_sha256: &diagnosis_sha256,
                    finding_id: FINDING_ID,
                    finding_version: FINDING_VERSION,
                    evidence: &evidence,
                })
                .map_err(|_| stage_error())?
        };
        let response = stage_response(&staged);
        inner.staged_repairs.insert(request.plan_id, staged);
        Ok(response)
    }

    fn execute(
        &self,
        request: FixtureLabExecuteRequest,
    ) -> Result<FixtureLabExecuteResponse, String> {
        let mut inner = self.0.lock().map_err(|_| execution_error())?;
        let staged = inner
            .staged_repairs
            .get(&request.plan_id)
            .cloned()
            .ok_or_else(execution_error)?;
        let config = FixtureRepairConfig::new(&inner.fixture_root, &inner.backup_root)
            .map_err(|_| execution_error())?;
        let public_key = inner.identity.public_key();
        let receipt = {
            let FixtureLabInner {
                journal, identity, ..
            } = &mut *inner;
            let mut broker = FixtureRepairBroker::attach(config, journal, identity)
                .map_err(|_| execution_error())?;
            broker
                .execute(
                    &staged,
                    FixtureRepairApproval {
                        approval_id: &request.approval_id,
                        approval_sequence: request.approval_sequence,
                        session_id: &request.session_id,
                        plan_id: &request.plan_id,
                        plan_hash: &request.plan_hash,
                        target_snapshot: &request.target_snapshot,
                    },
                )
                .map_err(|_| execution_error())?
        };
        let payload = receipt.verify(&public_key).map_err(|_| execution_error())?;
        let response = FixtureLabExecuteResponse {
            approval_id: payload.approval_id().to_owned(),
            approval_sequence: payload.approval_sequence(),
            session_id: staged.session_id().to_owned(),
            plan_id: staged.plan_id().to_owned(),
            plan_hash: payload.plan_hash().to_owned(),
            action_id: staged.action_id(),
            resource_id: staged.resource_id(),
            risk: "R2",
            diagnosis_sha256: payload.diagnosis_sha256().to_owned(),
            finding_id: staged.finding_id(),
            finding_version: staged.finding_version(),
            evidence: payload
                .evidence()
                .iter()
                .map(|binding| FixtureLabEvidenceSummary {
                    id: binding.id().to_owned(),
                    sha256: binding.sha256().to_owned(),
                })
                .collect(),
            target_snapshot: staged.target_snapshot().to_owned(),
            before_sha256: payload.before_sha256().to_owned(),
            after_sha256: payload.after_sha256().to_owned(),
            backup_locator: payload.backup_locator().to_owned(),
            backup_sha256: payload.backup_sha256().to_owned(),
            validation_passed: payload.validation_passed(),
        };
        inner.staged_repairs.remove(&request.plan_id);
        inner
            .completed_repairs
            .insert(response.approval_id.clone(), response.clone());
        let installed_fstab =
            fs::read(inner.fixture_root.join("etc/fstab")).map_err(|_| execution_error())?;
        let verification = diagnostic_report(&installed_fstab).map_err(|_| execution_error())?;
        if fixture_finding_present(&verification) {
            return Err(execution_error());
        }
        Ok(response)
    }

    fn reconcile_execute(
        &self,
        request: FixtureLabReconcileRequest,
    ) -> Result<FixtureLabExecuteResponse, String> {
        self.0
            .lock()
            .map_err(|_| execution_error())?
            .completed_repairs
            .get(&request.approval_id)
            .cloned()
            .ok_or_else(execution_error)
    }

    fn stage_rollback(
        &self,
        request: FixtureLabRollbackStageRequest,
    ) -> Result<FixtureLabRollbackStageResponse, String> {
        let mut inner = self.0.lock().map_err(|_| rollback_stage_error())?;
        if inner.staged_rollbacks.len() >= MAX_STAGED_PLANS
            || inner.staged_repairs.contains_key(&request.plan_id)
            || inner.staged_rollbacks.contains_key(&request.plan_id)
        {
            return Err(rollback_stage_error());
        }
        let completed_repair = inner
            .completed_repairs
            .get(&request.repair_approval_id)
            .cloned()
            .ok_or_else(rollback_stage_error)?;
        let config = FixtureRepairConfig::new(&inner.fixture_root, &inner.backup_root)
            .map_err(|_| rollback_stage_error())?;
        let staged = {
            let FixtureLabInner {
                journal, identity, ..
            } = &mut *inner;
            let broker = FixtureRepairBroker::attach(config, journal, identity)
                .map_err(|_| rollback_stage_error())?;
            broker
                .stage_rollback(StageFixtureRollbackRequest {
                    session_id: &request.session_id,
                    plan_id: &request.plan_id,
                    repair_approval_id: &request.repair_approval_id,
                })
                .map_err(|_| rollback_stage_error())?
        };
        let response = rollback_stage_response(&staged, &completed_repair);
        inner.staged_rollbacks.insert(request.plan_id, staged);
        Ok(response)
    }

    fn execute_rollback(
        &self,
        request: FixtureLabRollbackExecuteRequest,
    ) -> Result<FixtureLabRollbackExecuteResponse, String> {
        let mut inner = self.0.lock().map_err(|_| rollback_execution_error())?;
        let staged = inner
            .staged_rollbacks
            .get(&request.plan_id)
            .cloned()
            .ok_or_else(rollback_execution_error)?;
        let completed_repair = inner
            .completed_repairs
            .get(staged.repair_approval_id())
            .cloned()
            .ok_or_else(rollback_execution_error)?;
        let config = FixtureRepairConfig::new(&inner.fixture_root, &inner.backup_root)
            .map_err(|_| rollback_execution_error())?;
        let public_key = inner.identity.public_key();
        let report = {
            let FixtureLabInner {
                journal, identity, ..
            } = &mut *inner;
            let mut broker = FixtureRepairBroker::attach(config, journal, identity)
                .map_err(|_| rollback_execution_error())?;
            broker
                .execute_rollback(
                    &staged,
                    FixtureRollbackApproval {
                        approval_id: &request.approval_id,
                        approval_sequence: request.approval_sequence,
                        session_id: &request.session_id,
                        plan_id: &request.plan_id,
                        plan_hash: &request.plan_hash,
                        target_snapshot: &request.target_snapshot,
                    },
                )
                .map_err(|_| rollback_execution_error())?
        };
        let payload = report
            .verify(&public_key)
            .map_err(|_| rollback_execution_error())?;
        let response = FixtureLabRollbackExecuteResponse {
            repair_approval_id: staged.repair_approval_id().to_owned(),
            rollback_approval_id: payload.rollback_approval_id().to_owned(),
            approval_sequence: request.approval_sequence,
            session_id: staged.session_id().to_owned(),
            plan_id: staged.plan_id().to_owned(),
            plan_hash: staged.plan_hash().to_owned(),
            action_id: staged.action_id(),
            resource_id: staged.resource_id(),
            risk: "R2",
            target_snapshot: staged.target_snapshot().to_owned(),
            replaced_sha256: staged.installed_sha256().to_owned(),
            restored_sha256: payload.restored_sha256().to_owned(),
            backup_locator: staged.backup_locator().to_owned(),
            backup_sha256: completed_repair.backup_sha256,
            validation_passed: true,
            final_state: payload.final_state().to_owned(),
        };
        inner.staged_rollbacks.remove(&request.plan_id);
        inner
            .completed_rollbacks
            .insert(response.rollback_approval_id.clone(), response.clone());
        let restored_fstab = fs::read(inner.fixture_root.join("etc/fstab"))
            .map_err(|_| rollback_execution_error())?;
        if restored_fstab != BROKEN_FSTAB
            || !fixture_finding_present(
                &diagnostic_report(&restored_fstab).map_err(|_| rollback_execution_error())?,
            )
        {
            return Err(rollback_execution_error());
        }
        Ok(response)
    }

    fn reconcile_rollback(
        &self,
        request: FixtureLabReconcileRequest,
    ) -> Result<FixtureLabRollbackExecuteResponse, String> {
        self.0
            .lock()
            .map_err(|_| rollback_execution_error())?
            .completed_rollbacks
            .get(&request.approval_id)
            .cloned()
            .ok_or_else(rollback_execution_error)
    }
}

#[tauri::command]
pub(crate) fn fixture_lab_status(
    state: State<'_, FixtureRepairLab>,
) -> Result<FixtureLabStatusResponse, String> {
    state.status()
}

#[tauri::command]
pub(crate) fn fixture_lab_stage(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabStageRequest,
) -> Result<FixtureLabStageResponse, String> {
    state.stage(request)
}

#[tauri::command]
pub(crate) fn fixture_lab_execute(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabExecuteRequest,
) -> Result<FixtureLabExecuteResponse, String> {
    state.execute(request)
}

#[tauri::command]
pub(crate) fn fixture_lab_reconcile_execute(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabReconcileRequest,
) -> Result<FixtureLabExecuteResponse, String> {
    state.reconcile_execute(request)
}

#[tauri::command]
pub(crate) fn fixture_lab_stage_rollback(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabRollbackStageRequest,
) -> Result<FixtureLabRollbackStageResponse, String> {
    state.stage_rollback(request)
}

#[tauri::command]
pub(crate) fn fixture_lab_execute_rollback(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabRollbackExecuteRequest,
) -> Result<FixtureLabRollbackExecuteResponse, String> {
    state.execute_rollback(request)
}

#[tauri::command]
pub(crate) fn fixture_lab_reconcile_rollback(
    state: State<'_, FixtureRepairLab>,
    request: FixtureLabReconcileRequest,
) -> Result<FixtureLabRollbackExecuteResponse, String> {
    state.reconcile_rollback(request)
}

fn diagnose_fixture(fstab: &[u8]) -> Result<(String, Vec<FixtureEvidenceBinding>), String> {
    fixture_finding(fstab)?.ok_or_else(stage_error)
}

fn fixture_finding(fstab: &[u8]) -> Result<Option<(String, Vec<FixtureEvidenceBinding>)>, String> {
    let report = diagnostic_report(fstab)?;
    let Some(finding) = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == FINDING_ID && finding.rule_version == FINDING_VERSION as u16
        })
        .filter(|finding| finding.evidence_ids == ["E-LINUX-FSTAB", "E-LINUX-LSBLK"])
    else {
        return Ok(None);
    };
    let bindings = finding
        .evidence_ids
        .iter()
        .map(|id| {
            let bytes = match id.as_str() {
                "E-LINUX-FSTAB" => fstab,
                "E-LINUX-LSBLK" => HEALTHY_LSBLK,
                _ => return Err(stage_error()),
            };
            FixtureEvidenceBinding::new(id.clone(), sha256(bytes)).map_err(|_| stage_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnosis = serde_json::to_vec(&report).map_err(|_| stage_error())?;
    Ok(Some((sha256(&diagnosis), bindings)))
}

fn diagnostic_report(fstab: &[u8]) -> Result<DiagnosticReport, String> {
    let evidence = |id, body| EvidenceInput { id, body };
    diagnose_linux_p0(LinuxP0Inputs {
        lsblk_json: evidence("E-LINUX-LSBLK", HEALTHY_LSBLK),
        read_only_mounts_json: evidence("E-LINUX-MOUNTS-READ-ONLY", HEALTHY_READ_ONLY_MOUNTS),
        systemctl_failed: evidence("E-LINUX-SYSTEMD-FAILED", HEALTHY_FAILED),
        systemctl_unit_state: evidence("E-LINUX-SYSTEMD-STATE", HEALTHY_UNIT_STATE),
        fstab: evidence("E-LINUX-FSTAB", fstab),
        df: evidence("E-LINUX-DF", HEALTHY_DF),
        ip_link_json: evidence("E-LINUX-IP-LINK", HEALTHY_LINK),
        ip_route_json: evidence("E-LINUX-IP-ROUTE", HEALTHY_ROUTE),
        dpkg_audit: evidence("E-LINUX-DPKG", HEALTHY_DPKG),
    })
    .map_err(|_| stage_error())
}

fn fixture_finding_present(report: &DiagnosticReport) -> bool {
    report.findings.iter().any(|finding| {
        finding.rule_id == FINDING_ID && finding.rule_version == FINDING_VERSION as u16
    })
}

fn stage_response(staged: &StagedFixtureRepair) -> FixtureLabStageResponse {
    FixtureLabStageResponse {
        session_id: staged.session_id().to_owned(),
        plan_id: staged.plan_id().to_owned(),
        action_id: staged.action_id(),
        resource_id: staged.resource_id(),
        diagnosis_sha256: staged.diagnosis_sha256().to_owned(),
        finding_id: staged.finding_id(),
        finding_version: staged.finding_version(),
        evidence: staged
            .evidence()
            .iter()
            .map(|binding| FixtureLabEvidenceSummary {
                id: binding.id().to_owned(),
                sha256: binding.sha256().to_owned(),
            })
            .collect(),
        target_snapshot: staged.target_snapshot().to_owned(),
        expected_before_sha256: staged.expected_before_sha256().to_owned(),
        expected_after_sha256: staged.expected_after_sha256().to_owned(),
        diff_sha256: staged.diff_sha256().to_owned(),
        backup_locator: staged.backup_locator().to_owned(),
        plan_hash: staged.plan_hash().to_owned(),
        risk: "R2",
        backup: staged.backup_declaration(),
        validation: staged.validation_declaration(),
        rollback: staged.rollback_declaration(),
    }
}

fn rollback_stage_response(
    staged: &StagedFixtureRollback,
    completed_repair: &FixtureLabExecuteResponse,
) -> FixtureLabRollbackStageResponse {
    FixtureLabRollbackStageResponse {
        session_id: staged.session_id().to_owned(),
        plan_id: staged.plan_id().to_owned(),
        repair_approval_id: staged.repair_approval_id().to_owned(),
        repair_plan_hash: completed_repair.plan_hash.clone(),
        action_id: staged.action_id(),
        resource_id: staged.resource_id(),
        target_snapshot: staged.target_snapshot().to_owned(),
        installed_sha256: staged.installed_sha256().to_owned(),
        restored_sha256: staged.restored_sha256().to_owned(),
        backup_locator: staged.backup_locator().to_owned(),
        backup_sha256: completed_repair.backup_sha256.clone(),
        plan_hash: staged.plan_hash().to_owned(),
        risk: "R2",
        validation: staged.validation_declaration(),
    }
}

fn create_private_directory(path: &Path) -> Result<(), FixtureLabInitError> {
    fs::create_dir(path).map_err(|_| FixtureLabInitError)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| FixtureLabInitError)
}

fn write_embedded_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), FixtureLabInitError> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| FixtureLabInitError)?;
    file.write_all(contents).map_err(|_| FixtureLabInitError)?;
    file.sync_all().map_err(|_| FixtureLabInitError)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| FixtureLabInitError)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn stage_error() -> String {
    "fixture-lab-stage-rejected".to_owned()
}

fn status_error() -> String {
    "fixture-lab-status-unavailable".to_owned()
}

fn execution_error() -> String {
    "fixture-lab-execution-rejected".to_owned()
}

fn rollback_stage_error() -> String {
    "fixture-lab-rollback-stage-rejected".to_owned()
}

fn rollback_execution_error() -> String {
    "fixture-lab-rollback-execution-rejected".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_fixture_cycle_repairs_then_restores_embedded_fstab() {
        let lab = FixtureRepairLab::new().expect("initialize isolated fixture lab");
        let status = lab.status().expect("read fixture lab status");
        assert!(status.enabled);
        assert!(!status.mutation_blocked);
        assert_eq!(status.next_approval_sequence, Some(1));
        let finding = status.finding.expect("initial fixture finding");
        assert_eq!(finding.finding_id, FINDING_ID);
        assert_eq!(finding.evidence.len(), 2);
        let stage = lab
            .stage(FixtureLabStageRequest {
                session_id: "S-desk-fixture".to_owned(),
                plan_id: "P-desk-repair".to_owned(),
            })
            .expect("stage repair");
        assert_eq!(stage.action_id, FIXTURE_ACTION_ID);
        assert_eq!(stage.risk, "R2");

        let repair = lab
            .execute(FixtureLabExecuteRequest {
                approval_id: "A-desk-repair".to_owned(),
                approval_sequence: status.next_approval_sequence.expect("repair sequence"),
                session_id: stage.session_id.clone(),
                plan_id: stage.plan_id.clone(),
                plan_hash: stage.plan_hash.clone(),
                target_snapshot: stage.target_snapshot.clone(),
            })
            .expect("execute repair");
        assert!(repair.validation_passed);
        assert_eq!(
            lab.reconcile_execute(FixtureLabReconcileRequest {
                approval_id: repair.approval_id.clone(),
            })
            .expect("reconcile repair")
            .plan_hash,
            repair.plan_hash
        );

        let repaired_status = lab.status().expect("read repaired lab status");
        assert_eq!(repaired_status.next_approval_sequence, Some(2));
        assert!(repaired_status.finding.is_none());

        let rollback = lab
            .stage_rollback(FixtureLabRollbackStageRequest {
                session_id: "S-desk-fixture".to_owned(),
                plan_id: "P-desk-rollback".to_owned(),
                repair_approval_id: repair.approval_id.clone(),
            })
            .expect("stage rollback");
        let completed = lab
            .execute_rollback(FixtureLabRollbackExecuteRequest {
                approval_id: "A-desk-rollback".to_owned(),
                approval_sequence: repaired_status
                    .next_approval_sequence
                    .expect("rollback sequence"),
                session_id: rollback.session_id.clone(),
                plan_id: rollback.plan_id.clone(),
                plan_hash: rollback.plan_hash.clone(),
                target_snapshot: rollback.target_snapshot.clone(),
            })
            .expect("execute rollback");
        assert_eq!(completed.final_state, "rolled-back");
        assert_eq!(
            lab.reconcile_rollback(FixtureLabReconcileRequest {
                approval_id: completed.rollback_approval_id.clone(),
            })
            .expect("reconcile rollback")
            .plan_hash,
            completed.plan_hash
        );

        let restored_status = lab.status().expect("read restored lab status");
        assert!(restored_status.finding.is_some());

        let inner = lab.0.lock().expect("fixture lab lock");
        assert_eq!(
            fs::read(inner.fixture_root.join("etc/fstab")).expect("read restored fixture"),
            BROKEN_FSTAB
        );
        let serialized = serde_json::to_string(&completed).expect("serialize response");
        assert!(!serialized.contains(inner.fixture_root.to_string_lossy().as_ref()));
        assert!(!serialized.contains("UUID=missing-data"));
    }
}
