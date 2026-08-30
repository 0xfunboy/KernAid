use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::LazyLock};

use kernaid_evidence::linux_snapshot::{
    COLLECTOR as LINUX_NORMALIZED_SNAPSHOT_COLLECTOR, LinuxNormalizedSnapshot,
    LinuxNormalizedSnapshotEnvelope,
};

pub const RESCUE_EVIDENCE_COLLECTOR: &str =
    "rescue.installed-target.filesystem-content.read-only.v1";
pub const RESCUE_EVIDENCE_TARGET: &str = "selected-installed-target";
pub const MAX_OBJECTIVE_BYTES: usize = 8 * 1024;
pub const MAX_EVIDENCE_CONTENT_BYTES: usize = 48 * 1024;
pub const PROVIDER_CONTEXT_HASH_DOMAIN: &[u8] = b"KERNAID_RESCUE_OPENAI_PROJECTED_CONTEXT_V1\0";
const MAX_EVIDENCE_SUMMARY_BYTES: usize = 256;
const MAX_DIAGNOSIS_BYTES: usize = 16 * 1024;
const MAX_REQUESTED_EVIDENCE_BYTES: usize = 256;
const MAX_PROPOSAL_ITEMS: usize = 128;

const UNCONFIRMED_DIAGNOSIS: &str = "Il contenuto statico del volume è stato ispezionato in sola lettura, ma i marker consentiti non confermano un'installazione completa. Non viene formulata una diagnosi del sistema.";
const LINUX_FSTAB_DIAGNOSIS: &str = "Il corpus Linux conferma l'installazione e segnala una o più righe fstab malformate. Verificare la configurazione di mount senza eseguire modifiche automatiche.";
const LINUX_KERNEL_DIAGNOSIS: &str = "L'installazione Linux è confermata, ma nel volume ispezionato non è stato osservato alcun artefatto kernel regolare. Il boot può dipendere da un altro volume: serve una verifica read-only della topologia di avvio.";
const LINUX_GENERIC_DIAGNOSIS: &str = "Installazione Linux confermata dal corpus statico read-only. Nei marker consentiti non emerge un'anomalia deterministica; servono controlli mirati prima di proporre modifiche.";
const WINDOWS_PENDING_DIAGNOSIS: &str = "Il corpus Windows conferma l'installazione e mostra marker statici di servicing o riavvio pendente. La causa deve essere verificata con strumenti Windows nativi prima di qualsiasi riparazione.";
const WINDOWS_MISSING_BOOT_CHAIN_DIAGNOSIS: &str = "L'installazione Windows è confermata e l'unica partizione EFI associata è stata ispezionata in sola lettura, ma non contiene BCD, Windows Boot Manager o loader fallback x86-64. La catena di avvio richiede una verifica mirata prima di qualsiasi riparazione.";
const WINDOWS_UNQUALIFIED_BOOT_TOPOLOGY_DIAGNOSIS: &str = "L'installazione Windows è confermata, ma il volume ispezionato non contiene marker boot consentiti e la partizione EFI associata non è stata qualificata univocamente. Non viene dichiarato un guasto: serve una verifica read-only della topologia delle partizioni e del layout di avvio.";
const WINDOWS_GENERIC_DIAGNOSIS: &str = "Installazione Windows confermata dal corpus statico read-only. Nei marker consentiti non emerge un'anomalia deterministica; servono controlli Windows mirati prima di proporre modifiche.";

static PROVIDER_REDACTION_PATTERNS: LazyLock<Result<Vec<Regex>, regex::Error>> = LazyLock::new(
    || {
        [
            r"\b(?:sk|sk-ant)-[A-Za-z0-9_-]{8,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b",
            r"\bAIza[A-Za-z0-9_-]{20,}\b",
            r"(?i)\b(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE)_API_KEY\s*[:=]\s*[^\s]+",
            r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
            r#"(?i)\b(?:https?|ftp)://[^\s<>"']+"#,
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b[0-9a-f]{1,4}::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4}\b",
            r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b",
            r#"(?i)(?:\b[A-Z]:\\|\\\\)[^\s<>"'|]+"#,
            r"(?:/[A-Za-z0-9._~+-]+)+",
            r#"(?i)\b(?:user(?:name)?|account(?:name)?|owner)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._@\\]+"#,
            r#"(?i)\b(?:serial(?:number)?|service[-_\s]*tag|machine[-_\s]*id|product[-_\s]*id|uuid|partuuid|ptuuid|wwn)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._:/\\]+"#,
            r#"(?i)\b(?:host(?:name)?|computername)\b["']?\s*[:=]\s*["']?[-A-Za-z0-9._]+"#,
        ]
        .into_iter()
        .map(Regex::new)
        .collect()
    },
);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosisProposal {
    schema_version: String,
    diagnosis: String,
    confidence: f64,
    evidence_ids: Vec<String>,
    requested_evidence: Vec<String>,
}

impl DiagnosisProposal {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn diagnosis(&self) -> &str {
        &self.diagnosis
    }

    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence_ids
    }

    pub fn requested_evidence(&self) -> &[String] {
        &self.requested_evidence
    }

    pub(crate) fn validate(&self) -> bool {
        let evidence_ids = self.evidence_ids.iter().collect::<HashSet<_>>();
        let requested = self.requested_evidence.iter().collect::<HashSet<_>>();
        self.schema_version == "1.0"
            && bounded_nonempty(&self.diagnosis, MAX_DIAGNOSIS_BYTES)
            && self.confidence.is_finite()
            && (0.0..=1.0).contains(&self.confidence)
            && self.evidence_ids.len() == 1
            && evidence_ids.len() == self.evidence_ids.len()
            && self
                .evidence_ids
                .iter()
                .all(|value| valid_evidence_id(value))
            && self.requested_evidence.len() <= MAX_PROPOSAL_ITEMS
            && requested.len() == self.requested_evidence.len()
            && self
                .requested_evidence
                .iter()
                .all(|value| bounded_nonempty(value, MAX_REQUESTED_EVIDENCE_BYTES))
    }

    fn deterministic(
        diagnosis: &'static str,
        confidence: f64,
        evidence_id: &str,
        requested_evidence: &'static str,
    ) -> Self {
        Self {
            schema_version: "1.0".to_owned(),
            diagnosis: diagnosis.to_owned(),
            confidence,
            evidence_ids: vec![evidence_id.to_owned()],
            requested_evidence: vec![requested_evidence.to_owned()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectedObservation {
    id: String,
    collector: String,
    trust: String,
}

impl ProjectedObservation {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn collector(&self) -> &str {
        &self.collector
    }

    pub fn trust(&self) -> &str {
        &self.trust
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectedProviderContext {
    objective: String,
    deterministic_proposal: DiagnosisProposal,
    observations: Vec<ProjectedObservation>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderContextPreview {
    context: ProjectedProviderContext,
    context_sha256: String,
}

impl ProviderContextPreview {
    pub(crate) fn project(objective: &str, evidence: &[WireEvidence]) -> Result<Self, CorpusError> {
        let context = project_diagnosis(objective, evidence)?;
        Self::from_context(context)
    }

    pub(crate) fn from_context(context: ProjectedProviderContext) -> Result<Self, CorpusError> {
        let canonical = serde_json::to_vec(&context).map_err(|_| CorpusError::Invalid)?;
        let mut digest = Sha256::new();
        digest.update(PROVIDER_CONTEXT_HASH_DOMAIN);
        digest.update(&canonical);
        Ok(Self {
            context,
            context_sha256: format!("sha256:{:x}", digest.finalize()),
        })
    }

    pub fn context(&self) -> &ProjectedProviderContext {
        &self.context
    }

    pub fn context_sha256(&self) -> &str {
        &self.context_sha256
    }

    pub(crate) fn matches(&self, context: &ProjectedProviderContext, digest: &str) -> bool {
        self.context == *context && self.context_sha256 == digest
    }
}

impl ProjectedProviderContext {
    pub fn objective(&self) -> &str {
        &self.objective
    }

    pub fn deterministic_proposal(&self) -> &DiagnosisProposal {
        &self.deterministic_proposal
    }

    pub fn observations(&self) -> &[ProjectedObservation] {
        &self.observations
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WireEvidence {
    schema_version: String,
    id: String,
    collector: String,
    target: String,
    content_type: String,
    trust: String,
    summary: String,
    content: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CorpusError {
    Invalid,
}

pub(crate) fn project_diagnosis(
    objective: &str,
    evidence: &[WireEvidence],
) -> Result<ProjectedProviderContext, CorpusError> {
    if !bounded_nonempty(objective, MAX_OBJECTIVE_BYTES) || evidence.len() != 1 {
        return Err(CorpusError::Invalid);
    }
    let item = evidence.first().ok_or(CorpusError::Invalid)?;
    if item.schema_version != "1.0"
        || !valid_evidence_id(&item.id)
        || !matches!(
            item.collector.as_str(),
            RESCUE_EVIDENCE_COLLECTOR | LINUX_NORMALIZED_SNAPSHOT_COLLECTOR
        )
        || item.target != RESCUE_EVIDENCE_TARGET
        || item.content_type != "application/json"
        || item.trust != "observed-untrusted"
        || item.content.is_empty()
        || item.content.len() > MAX_EVIDENCE_CONTENT_BYTES
        || item.summary.len() > MAX_EVIDENCE_SUMMARY_BYTES
    {
        return Err(CorpusError::Invalid);
    }
    let (deterministic_proposal, expected_summary, observation_collector) =
        if item.collector == LINUX_NORMALIZED_SNAPSHOT_COLLECTOR {
            let envelope = LinuxNormalizedSnapshotEnvelope::parse(item.content.as_bytes())
                .map_err(|_| CorpusError::Invalid)?;
            if !envelope.capture.is_rescue() || !envelope.snapshot.topology.supported {
                return Err(CorpusError::Invalid);
            }
            (
                proposal_from_linux_snapshot(&envelope.snapshot, &item.id),
                linux_snapshot_summary(&envelope.snapshot),
                LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
            )
        } else {
            let corpus = parse_corpus(&item.content)?;
            if matches!(&corpus, RescueCorpus::Linux(_)) {
                return Err(CorpusError::Invalid);
            }
            (
                corpus.proposal(&item.id),
                corpus.summary(),
                RESCUE_EVIDENCE_COLLECTOR,
            )
        };
    if item.summary != expected_summary {
        return Err(CorpusError::Invalid);
    }
    if !deterministic_proposal.validate() {
        return Err(CorpusError::Invalid);
    }
    Ok(ProjectedProviderContext {
        objective: redact_untrusted(objective)?,
        deterministic_proposal,
        observations: vec![ProjectedObservation {
            id: item.id.clone(),
            collector: observation_collector.to_owned(),
            trust: "observed-untrusted".to_owned(),
        }],
    })
}

fn linux_snapshot_summary(snapshot: &LinuxNormalizedSnapshot) -> String {
    if snapshot.installation_confirmed {
        "Snapshot statico Linux rescue acquisito read-only e validato".to_owned()
    } else {
        "Snapshot statico Linux rescue acquisito read-only; installazione non confermata".to_owned()
    }
}

fn proposal_from_linux_snapshot(
    snapshot: &LinuxNormalizedSnapshot,
    evidence_id: &str,
) -> DiagnosisProposal {
    if !snapshot.installation_confirmed {
        return DiagnosisProposal::deterministic(
            UNCONFIRMED_DIAGNOSIS,
            0.2,
            evidence_id,
            "rescue.installed-target.installation-confirmation.read-only.v1",
        );
    }
    if snapshot.configuration.fstab.malformed_line_count > 0 {
        DiagnosisProposal::deterministic(
            LINUX_FSTAB_DIAGNOSIS,
            0.84,
            evidence_id,
            "rescue.linux.fstab.review.read-only.v1",
        )
    } else if snapshot.boot.directory_present && snapshot.boot.kernel_artifact_count == 0 {
        DiagnosisProposal::deterministic(
            LINUX_KERNEL_DIAGNOSIS,
            0.68,
            evidence_id,
            "rescue.linux.boot-layout.read-only.v1",
        )
    } else {
        DiagnosisProposal::deterministic(
            LINUX_GENERIC_DIAGNOSIS,
            0.58,
            evidence_id,
            "rescue.linux.targeted-health.read-only.v1",
        )
    }
}

fn redact_untrusted(input: &str) -> Result<String, CorpusError> {
    let patterns = PROVIDER_REDACTION_PATTERNS
        .as_ref()
        .map_err(|_| CorpusError::Invalid)?;
    let redacted = patterns.iter().fold(input.to_owned(), |value, pattern| {
        pattern.replace_all(&value, "[REDACTED]").into_owned()
    });
    if !bounded_nonempty(&redacted, MAX_OBJECTIVE_BYTES) {
        return Err(CorpusError::Invalid);
    }
    Ok(redacted)
}

fn bounded_nonempty(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(|character| character == '\0')
}

pub(crate) fn valid_evidence_id(value: &str) -> bool {
    value.len() <= 128
        && value.strip_prefix("E-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn parse_corpus(input: &str) -> Result<RescueCorpus, CorpusError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let corpus = RescueCorpus::deserialize(&mut deserializer).map_err(|_| CorpusError::Invalid)?;
    deserializer.end().map_err(|_| CorpusError::Invalid)?;
    corpus.validate()?;
    Ok(corpus)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "family", rename_all = "lowercase")]
enum RescueCorpus {
    Linux(Box<LinuxCorpus>),
    Windows(WindowsCorpus),
}

impl RescueCorpus {
    fn validate(&self) -> Result<(), CorpusError> {
        match self {
            Self::Linux(corpus) => corpus.validate(),
            Self::Windows(corpus) => corpus.validate(),
        }
    }

    fn installation_confirmed(&self) -> bool {
        match self {
            Self::Linux(corpus) => corpus.installation_confirmed,
            Self::Windows(corpus) => corpus.installation_confirmed,
        }
    }

    fn family(&self) -> &'static str {
        match self {
            Self::Linux(_) => "linux",
            Self::Windows(_) => "windows",
        }
    }

    fn summary(&self) -> String {
        if self.installation_confirmed() {
            format!(
                "Corpus statico {} acquisito read-only con cleanup verificato",
                self.family()
            )
        } else {
            format!(
                "Corpus statico {} acquisito read-only; installazione non confermata",
                self.family()
            )
        }
    }

    fn proposal(&self, evidence_id: &str) -> DiagnosisProposal {
        if !self.installation_confirmed() {
            return DiagnosisProposal::deterministic(
                UNCONFIRMED_DIAGNOSIS,
                0.2,
                evidence_id,
                "rescue.installed-target.installation-confirmation.read-only.v1",
            );
        }
        match self {
            Self::Linux(corpus) if corpus.configuration.fstab.malformed_line_count > 0 => {
                DiagnosisProposal::deterministic(
                    LINUX_FSTAB_DIAGNOSIS,
                    0.84,
                    evidence_id,
                    "rescue.linux.fstab.review.read-only.v1",
                )
            }
            Self::Linux(corpus)
                if corpus.boot.directory_present && corpus.boot.kernel_artifact_count == 0 =>
            {
                DiagnosisProposal::deterministic(
                    LINUX_KERNEL_DIAGNOSIS,
                    0.68,
                    evidence_id,
                    "rescue.linux.boot-layout.read-only.v1",
                )
            }
            Self::Linux(_) => DiagnosisProposal::deterministic(
                LINUX_GENERIC_DIAGNOSIS,
                0.58,
                evidence_id,
                "rescue.linux.targeted-health.read-only.v1",
            ),
            Self::Windows(corpus)
                if corpus.servicing.pending_xml_present
                    || corpus.servicing.reboot_pending_marker_present =>
            {
                DiagnosisProposal::deterministic(
                    WINDOWS_PENDING_DIAGNOSIS,
                    0.8,
                    evidence_id,
                    "windows.update.state",
                )
            }
            Self::Windows(corpus)
                if !corpus.boot.boot_manager_present
                    && !corpus.boot.bcd_present
                    && corpus.boot.efi_system_partition.all_markers_absent() =>
            {
                DiagnosisProposal::deterministic(
                    WINDOWS_MISSING_BOOT_CHAIN_DIAGNOSIS,
                    0.76,
                    evidence_id,
                    "rescue.windows.boot-chain.verify.read-only.v1",
                )
            }
            Self::Windows(corpus)
                if !corpus.boot.boot_manager_present
                    && !corpus.boot.bcd_present
                    && !corpus.boot.efi_system_partition.is_inspected() =>
            {
                DiagnosisProposal::deterministic(
                    WINDOWS_UNQUALIFIED_BOOT_TOPOLOGY_DIAGNOSIS,
                    0.46,
                    evidence_id,
                    "rescue.windows.boot-topology.review.read-only.v1",
                )
            }
            Self::Windows(_) => DiagnosisProposal::deterministic(
                WINDOWS_GENERIC_DIAGNOSIS,
                0.58,
                evidence_id,
                "windows.offline.native-follow-up.v1",
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxCorpus {
    installation_confirmed: bool,
    release: LinuxRelease,
    boot: LinuxBoot,
    configuration: LinuxConfiguration,
    #[serde(rename = "packageDatabases")]
    _package_databases: LinuxPackageDatabases,
}

impl LinuxCorpus {
    fn validate(&self) -> Result<(), CorpusError> {
        let release_values = [
            &self.release.id,
            &self.release.name,
            &self.release.pretty_name,
            &self.release.version_id,
        ];
        if release_values.iter().any(|value| !value.valid())
            || !matches!(
                self.release.source.as_str(),
                "etc-os-release" | "usr-lib-os-release" | "absent"
            )
            || (self.release.source == "absent"
                && release_values.iter().any(|value| !value.is_null()))
            || (self.installation_confirmed && self.release.id.is_null())
            || !bounded_integer(self.boot.kernel_artifact_count, 512)
            || !bounded_integer(self.boot.initramfs_artifact_count, 512)
            || !bounded_integer(self.boot.bootloader_directory_count, 3)
            || !bounded_integer(self.boot.symlink_artifact_count, 512)
            || (!self.boot.directory_present
                && (self.boot.kernel_artifact_count != 0
                    || self.boot.initramfs_artifact_count != 0
                    || self.boot.bootloader_directory_count != 0
                    || self.boot.symlink_artifact_count != 0))
            || !bounded_integer(self.configuration.fstab.entry_count, 65_536)
            || self.configuration.fstab.swap_entry_count > self.configuration.fstab.entry_count
            || self.configuration.fstab.network_entry_count > self.configuration.fstab.entry_count
            || !bounded_integer(self.configuration.fstab.malformed_line_count, 65_536)
            || self.configuration.fstab.entry_count + self.configuration.fstab.malformed_line_count
                > 65_536
            || (!self.configuration.fstab.present
                && (self.configuration.fstab.entry_count != 0
                    || self.configuration.fstab.root_entry_present
                    || self.configuration.fstab.efi_entry_present
                    || self.configuration.fstab.swap_entry_count != 0
                    || self.configuration.fstab.network_entry_count != 0
                    || self.configuration.fstab.malformed_line_count != 0))
        {
            return Err(CorpusError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxRelease {
    id: RequiredNullableText,
    name: RequiredNullableText,
    pretty_name: RequiredNullableText,
    version_id: RequiredNullableText,
    source: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxBoot {
    directory_present: bool,
    kernel_artifact_count: u64,
    initramfs_artifact_count: u64,
    bootloader_directory_count: u64,
    symlink_artifact_count: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxConfiguration {
    fstab: LinuxFstab,
    #[serde(rename = "machineIdPresent")]
    _machine_id_present: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxFstab {
    present: bool,
    entry_count: u64,
    root_entry_present: bool,
    efi_entry_present: bool,
    swap_entry_count: u64,
    network_entry_count: u64,
    malformed_line_count: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinuxPackageDatabases {
    #[serde(rename = "dpkgStatusPresent")]
    _dpkg_status_present: bool,
    #[serde(rename = "rpmDatabasePresent")]
    _rpm_database_present: bool,
    #[serde(rename = "pacmanDatabasePresent")]
    _pacman_database_present: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsCorpus {
    installation_confirmed: bool,
    installation_markers: WindowsInstallationMarkers,
    boot: WindowsBoot,
    servicing: WindowsServicing,
}

impl WindowsCorpus {
    fn validate(&self) -> Result<(), CorpusError> {
        let expected = self.installation_markers.windows_directory_present
            && self.installation_markers.system32_directory_present
            && self.installation_markers.kernel_present
            && self.installation_markers.system_hive_present
            && self.installation_markers.software_hive_present;
        if self.installation_confirmed != expected || !self.boot.validate() {
            return Err(CorpusError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsInstallationMarkers {
    windows_directory_present: bool,
    system32_directory_present: bool,
    kernel_present: bool,
    system_hive_present: bool,
    software_hive_present: bool,
    #[serde(rename = "usersDirectoryPresent")]
    _users_directory_present: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsBoot {
    boot_manager_present: bool,
    bcd_present: bool,
    efi_system_partition: WindowsEfiSystemPartition,
}

impl WindowsBoot {
    fn validate(&self) -> bool {
        self.efi_system_partition.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum WindowsEfiSystemPartitionState {
    Inspected,
    NotPresent,
    Ambiguous,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsEfiSystemPartition {
    state: WindowsEfiSystemPartitionState,
    microsoft_boot_manager_present: RequiredNullableBool,
    bcd_present: RequiredNullableBool,
    fallback_bootloader_present: RequiredNullableBool,
}

impl WindowsEfiSystemPartition {
    fn validate(&self) -> bool {
        match self.state {
            WindowsEfiSystemPartitionState::Inspected => [
                &self.microsoft_boot_manager_present,
                &self.bcd_present,
                &self.fallback_bootloader_present,
            ]
            .iter()
            .all(|value| matches!(value, RequiredNullableBool::Bool(_))),
            WindowsEfiSystemPartitionState::NotPresent
            | WindowsEfiSystemPartitionState::Ambiguous
            | WindowsEfiSystemPartitionState::Unsupported => [
                &self.microsoft_boot_manager_present,
                &self.bcd_present,
                &self.fallback_bootloader_present,
            ]
            .iter()
            .all(|value| matches!(value, RequiredNullableBool::Null(()))),
        }
    }

    fn is_inspected(&self) -> bool {
        self.state == WindowsEfiSystemPartitionState::Inspected
    }

    fn all_markers_absent(&self) -> bool {
        self.is_inspected()
            && [
                &self.microsoft_boot_manager_present,
                &self.bcd_present,
                &self.fallback_bootloader_present,
            ]
            .iter()
            .all(|value| matches!(value, RequiredNullableBool::Bool(false)))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsServicing {
    pending_xml_present: bool,
    reboot_pending_marker_present: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RequiredNullableText {
    Text(String),
    Null(()),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RequiredNullableBool {
    Bool(bool),
    Null(()),
}

impl RequiredNullableText {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null(()))
    }

    fn valid(&self) -> bool {
        match self {
            Self::Text(value) => bounded_control_free_text(value, 256),
            Self::Null(()) => true,
        }
    }
}

fn bounded_control_free_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value
            .chars()
            .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

const fn bounded_integer(value: u64, maximum: u64) -> bool {
    value <= maximum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_redaction_matches_the_resident_sensitive_classes() {
        let result =
            redact_untrusted("sk-example-secret alice@example.com 192.0.2.44 /home/alice/file.txt");
        assert!(result.is_ok());
        let redacted = result.as_deref().unwrap_or("");
        assert!(!redacted.contains("sk-example-secret"));
        assert!(!redacted.contains("alice@example.com"));
        assert!(!redacted.contains("192.0.2.44"));
        assert!(!redacted.contains("file.txt"));
    }

    #[test]
    fn provider_redaction_rejects_expansion_beyond_the_objective_limit() {
        let expanding = "/a ".repeat(MAX_OBJECTIVE_BYTES / 3);
        assert!(expanding.len() <= MAX_OBJECTIVE_BYTES);
        assert_eq!(redact_untrusted(&expanding), Err(CorpusError::Invalid));
    }
}
