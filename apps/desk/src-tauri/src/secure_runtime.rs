#![forbid(unsafe_code)]

use fs2::FileExt as _;
use kernaid_device_identity::{
    DeviceIdentity, MAX_SIGNED_REPORT_PAYLOAD_BYTES, SIGNED_REPORT_ENVELOPE_SCHEMA,
};
use kernaid_native_secrets::{
    NativeDeviceIdentityStore, NativeJournalSecretStore, NativeJournalState, NativeSecretError,
};
#[cfg(test)]
use kernaid_storage::JournalError;
use kernaid_storage::{
    JOURNAL_KEY_BYTES, JournalAnchor, JournalKey, JournalSecretStore, SecretStoreError,
    SecureJournal,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    fs::{self, File},
    io,
    path::Path,
    sync::{Mutex, MutexGuard},
};
use tauri::State;
use zeroize::Zeroizing;

#[cfg(unix)]
use rustix::{
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags},
    process,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(not(unix))]
use std::fs::OpenOptions;

const SECRET_NAMESPACE: &str = "resident-v1";
const JOURNAL_FILE_NAME: &str = "audit-v2.sqlite3";
const INSTANCE_LOCK_FILE_NAME: &str = ".resident-v1.lock";
const AUDIT_SCHEMA_VERSION: &str = "1.0";
const IDENTITY_MARKER_TYPE: &str = "device.identity.initialized";
const SIGNED_REPORT_MEDIA_TYPE: &str = "application/vnd.kernaid.signed-report+json";
const MAX_AUDIT_RECORD_BYTES: usize = 64 * 1024;
const MAX_AUDIT_SESSIONS: usize = 128;
const MAX_SESSION_RECORDS: u64 = 4_096;
const MAX_ID_BYTES: usize = 128;
const MAX_ACTION_BYTES: usize = 256;
const MAX_EVIDENCE_IDS: usize = 128;
const MAX_ACTIONS: usize = 64;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeInitError {
    InvalidSecureDirectory,
    InstanceAlreadyRunning,
}

impl fmt::Display for RuntimeInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSecureDirectory => {
                "KernAid cannot establish its private application directory"
            }
            Self::InstanceAlreadyRunning => "another KernAid instance is already running",
        })
    }
}

impl Error for RuntimeInitError {}

type ResidentJournal = SecureJournal<ResidentJournalSecretStore>;

enum ResidentJournalSecretStore {
    Native(NativeJournalSecretStore),
    QualifiedFirstLaunch(QualifiedFirstLaunchSecretStore),
}

#[derive(Default)]
struct QualifiedFirstLaunchSecretStore {
    key: Option<Zeroizing<[u8; JOURNAL_KEY_BYTES]>>,
    anchor: Option<JournalAnchor>,
}

impl JournalSecretStore for ResidentJournalSecretStore {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        match self {
            Self::Native(store) => store.load_key(),
            Self::QualifiedFirstLaunch(store) => Ok(store
                .key
                .as_ref()
                .map(|key| JournalKey::from_zeroizing(Zeroizing::new(**key)))),
        }
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        match self {
            Self::Native(store) => store.store_key(key),
            Self::QualifiedFirstLaunch(store) => {
                store.key = Some(Zeroizing::new(*key.expose_secret()));
                Ok(())
            }
        }
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        match self {
            Self::Native(store) => store.load_anchor(),
            Self::QualifiedFirstLaunch(store) => Ok(store.anchor),
        }
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        match self {
            Self::Native(store) => store.store_anchor(anchor),
            Self::QualifiedFirstLaunch(store) => {
                store.anchor = Some(*anchor);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SecureRuntimeOpenMode {
    Resident,
    QualifiedFirstLaunchProbe,
}

enum AuditRuntimeState {
    Secure {
        journal: Box<ResidentJournal>,
        head: JournalAnchor,
    },
    Unavailable,
    Blocked,
}

enum IdentityRuntimeState {
    Ready(DeviceIdentity),
    Uninitialized(NativeDeviceIdentityStore),
    Unavailable,
    Blocked,
}

struct RuntimeInner {
    audit: AuditRuntimeState,
    identity: IdentityRuntimeState,
    sessions: HashMap<String, NativeAuditSession>,
    persistent_audit_started: bool,
}

pub struct SecureRuntime {
    inner: Mutex<RuntimeInner>,
    _instance_lock: File,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureRuntimeStatus {
    schema_version: &'static str,
    audit: &'static str,
    signing: &'static str,
    persistent_audit_started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditAppendResult {
    journal_sequence: u64,
    journal_entry_hash: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedArtifactResult {
    media_type: &'static str,
    payload_media_type: String,
    container_json: String,
    sha256: String,
    payload_sha256: String,
    envelope_schema: &'static str,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeAuditRecord {
    schema_version: String,
    #[serde(rename = "type")]
    record_type: String,
    session_id: String,
    sequence: u64,
    captured_at: String,
    payload: Value,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSealRequest {
    schema_version: String,
    session_id: String,
    format: String,
    payload_media_type: String,
    body: String,
    payload_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceIdentityMarker {
    schema_version: String,
    #[serde(rename = "type")]
    record_type: String,
    device_id: String,
    public_key_sha256: String,
}

struct NativeAuditSession {
    target_fingerprint: String,
    last_sequence: u64,
    phase: SessionPhase,
    evidence: Vec<EvidenceBinding>,
    diagnoses: Vec<DiagnosisBinding>,
    plans: HashMap<String, PlanBinding>,
    approvals: Vec<ApprovalBinding>,
    executions: Vec<ExecutionBinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionPhase {
    Observe,
    Plan,
    Executing,
    Complete,
    Failed,
}

struct EvidenceBinding {
    evidence_id: String,
    sha256: String,
    sensitivity: String,
    captured_at: String,
}

struct DiagnosisBinding {
    diagnosis_sha256: String,
    confidence: f64,
    evidence_ids: Vec<String>,
    requested_evidence_count: u64,
}

struct PlanBinding {
    risk: String,
    actions: Vec<String>,
}

struct ApprovalBinding {
    approval_id: String,
    plan_id: String,
    approved_at: String,
    approved_by_sha256: String,
}

struct ExecutionBinding {
    plan_id: String,
    event_sequence: u64,
    status: String,
    action: String,
    captured_at: String,
}

enum ValidatedRecordKind {
    SessionStarted {
        target_fingerprint: String,
    },
    Evidence {
        evidence_id: String,
        sha256: String,
        sensitivity: String,
    },
    Diagnosis {
        diagnosis_sha256: String,
        confidence: f64,
        evidence_ids: Vec<String>,
        requested_evidence_count: u64,
    },
    Plan {
        plan_id: String,
        target_fingerprint: String,
        risk: String,
        evidence_ids: Vec<String>,
        actions: Vec<String>,
    },
    Approval {
        approval_id: String,
        plan_id: String,
        target_fingerprint: String,
        approved_at: String,
        approved_by_sha256: String,
    },
    Execution {
        plan_id: String,
        event_sequence: u64,
        status: String,
        action: String,
    },
    Report {
        format: String,
        payload_media_type: String,
        payload_sha256: String,
        verification: String,
    },
}

impl SecureRuntime {
    pub fn open(app_data_directory: &Path) -> Result<Self, RuntimeInitError> {
        Self::open_with_mode(app_data_directory, SecureRuntimeOpenMode::Resident)
    }

    pub(crate) fn open_qualified_first_launch_probe(
        app_data_directory: &Path,
    ) -> Result<Self, RuntimeInitError> {
        Self::open_with_mode(
            app_data_directory,
            SecureRuntimeOpenMode::QualifiedFirstLaunchProbe,
        )
    }

    fn open_with_mode(
        app_data_directory: &Path,
        mode: SecureRuntimeOpenMode,
    ) -> Result<Self, RuntimeInitError> {
        ensure_secure_directory(app_data_directory)?;
        let instance_lock = open_instance_lock(&app_data_directory.join(INSTANCE_LOCK_FILE_NAME))?;
        let journal_path = app_data_directory.join(JOURNAL_FILE_NAME);
        let journal_file_seen = fs::symlink_metadata(&journal_path).is_ok();
        let mut audit = match mode {
            SecureRuntimeOpenMode::Resident => open_audit_state(&journal_path),
            SecureRuntimeOpenMode::QualifiedFirstLaunchProbe => {
                open_qualified_first_launch_audit_state(&journal_path)
            }
        };
        let mut identity = match mode {
            SecureRuntimeOpenMode::Resident => open_identity_state(),
            SecureRuntimeOpenMode::QualifiedFirstLaunchProbe => IdentityRuntimeState::Unavailable,
        };
        let mut persistent_audit_started = matches!(
            &audit,
            AuditRuntimeState::Secure { head, .. } if head.sequence > 0
        ) || (journal_file_seen
            && matches!(&audit, AuditRuntimeState::Blocked));
        match reconcile_identity_continuity(&mut audit, &mut identity) {
            Ok(marker_appended) => persistent_audit_started |= marker_appended,
            Err(()) => {
                audit = AuditRuntimeState::Blocked;
                identity = IdentityRuntimeState::Blocked;
                persistent_audit_started |= journal_file_seen;
            }
        }
        Ok(Self {
            inner: Mutex::new(RuntimeInner {
                audit,
                identity,
                sessions: HashMap::new(),
                persistent_audit_started,
            }),
            _instance_lock: instance_lock,
        })
    }

    pub(crate) fn qualified_first_launch_status(&self) -> Result<SecureRuntimeStatus, String> {
        let inner = lock_runtime(self)?;
        Ok(runtime_status(&inner))
    }
}

impl SecureRuntimeStatus {
    pub(crate) fn is_readable_for_qualified_first_launch(&self) -> bool {
        self.schema_version == AUDIT_SCHEMA_VERSION
            && matches!(self.audit, "secure" | "unavailable")
            && matches!(self.signing, "ready" | "uninitialized" | "unavailable")
            && (self.signing == "ready") == self.device_id.is_some()
    }
}

#[tauri::command]
pub fn secure_runtime_status(
    state: State<'_, SecureRuntime>,
) -> Result<SecureRuntimeStatus, String> {
    let inner = lock_runtime(&state)?;
    Ok(runtime_status(&inner))
}

#[tauri::command]
pub fn initialize_device_identity(
    state: State<'_, SecureRuntime>,
) -> Result<SecureRuntimeStatus, String> {
    let mut inner = lock_runtime(&state)?;
    if !matches!(inner.audit, AuditRuntimeState::Secure { .. }) {
        return Err("L’archivio cifrato deve essere disponibile prima dell’identità.".to_owned());
    }
    let prior = std::mem::replace(&mut inner.identity, IdentityRuntimeState::Blocked);
    let next = match prior {
        IdentityRuntimeState::Ready(identity) => IdentityRuntimeState::Ready(identity),
        IdentityRuntimeState::Uninitialized(mut store) => match store.create_device_identity() {
            Ok(identity) => IdentityRuntimeState::Ready(identity),
            Err(error) => identity_state_after_error(error),
        },
        IdentityRuntimeState::Unavailable => initialize_recovered_identity(),
        IdentityRuntimeState::Blocked => IdentityRuntimeState::Blocked,
    };
    inner.identity = next;
    if matches!(inner.identity, IdentityRuntimeState::Ready(_)) {
        let identity = std::mem::replace(&mut inner.identity, IdentityRuntimeState::Blocked);
        let IdentityRuntimeState::Ready(identity) = identity else {
            unreachable!("identity readiness was checked")
        };
        match ensure_identity_binding(&mut inner.audit, &identity) {
            Ok(marker_appended) => {
                inner.persistent_audit_started |= marker_appended;
                inner.identity = IdentityRuntimeState::Ready(identity);
            }
            Err(()) => {
                inner.persistent_audit_started = true;
                inner.audit = AuditRuntimeState::Blocked;
                inner.sessions.clear();
                return Err(
                    "La continuità dell’identità non è verificabile; riavviare KernAid.".to_owned(),
                );
            }
        }
    }
    match inner.identity {
        IdentityRuntimeState::Ready(_) => Ok(runtime_status(&inner)),
        IdentityRuntimeState::Uninitialized(_) => {
            Err("L’identità del dispositivo non è stata inizializzata.".to_owned())
        }
        IdentityRuntimeState::Unavailable => {
            Err("Il portachiavi del sistema non è disponibile.".to_owned())
        }
        IdentityRuntimeState::Blocked => {
            Err("L’identità sicura richiede un controllo prima di proseguire.".to_owned())
        }
    }
}

#[tauri::command]
pub fn append_audit_record(
    state: State<'_, SecureRuntime>,
    record: NativeAuditRecord,
) -> Result<AuditAppendResult, String> {
    let validated = validate_audit_record(&record)
        .map_err(|()| "Il record di audit non è valido.".to_owned())?;
    if matches!(validated, ValidatedRecordKind::Report { .. }) {
        return Err(
            "Il report deve essere registrato e firmato in un’unica operazione.".to_owned(),
        );
    }
    let encoded = serde_json::to_vec(&record)
        .map_err(|_| "Il record di audit non è serializzabile.".to_owned())?;
    if encoded.len() > MAX_AUDIT_RECORD_BYTES {
        return Err("Il record di audit supera il limite consentito.".to_owned());
    }

    let mut inner = lock_runtime(&state)?;
    if !matches!(inner.identity, IdentityRuntimeState::Ready(_)) {
        return Err("L’identità sicura non è pronta.".to_owned());
    }
    validate_transition(&inner.sessions, &record, &validated)
        .map_err(|()| "La sequenza di audit è stata rifiutata.".to_owned())?;

    let appended = match &mut inner.audit {
        AuditRuntimeState::Secure { journal, head } => journal.append_expected(*head, &encoded),
        AuditRuntimeState::Unavailable => {
            return Err("L’archivio sicuro non è disponibile.".to_owned());
        }
        AuditRuntimeState::Blocked => {
            return Err("L’archivio sicuro è bloccato.".to_owned());
        }
    };
    let appended = match appended {
        Ok(entry) => entry,
        Err(_) => {
            inner.audit = AuditRuntimeState::Blocked;
            inner.sessions.clear();
            return Err("Scrittura audit non riuscita; riavviare KernAid.".to_owned());
        }
    };
    let anchor = JournalAnchor {
        journal_id: current_journal_id(&inner.audit)
            .ok_or_else(|| "L’archivio sicuro è bloccato.".to_owned())?,
        sequence: appended.sequence,
        entry_hash: appended.entry_hash,
    };
    if let AuditRuntimeState::Secure { head, .. } = &mut inner.audit {
        *head = anchor;
    }
    inner.persistent_audit_started = true;
    commit_transition(&mut inner.sessions, &record, validated);
    Ok(AuditAppendResult {
        journal_sequence: anchor.sequence,
        journal_entry_hash: hex_hash(&anchor.entry_hash),
    })
}

#[tauri::command]
pub fn seal_signed_report(
    state: State<'_, SecureRuntime>,
    record: NativeAuditRecord,
    request: NativeSealRequest,
) -> Result<SignedArtifactResult, String> {
    let validated = validate_audit_record(&record)
        .map_err(|()| "Il record di audit del report non è valido.".to_owned())?;
    let ValidatedRecordKind::Report {
        format,
        payload_media_type,
        payload_sha256,
        verification,
    } = &validated
    else {
        return Err("Il record di audit del report non è valido.".to_owned());
    };
    validate_seal_request(&request)
        .map_err(|()| "Il report da firmare non è valido.".to_owned())?;
    if record.session_id != request.session_id
        || format != &request.format
        || payload_media_type != &request.payload_media_type
        || payload_sha256 != &request.payload_sha256
    {
        return Err("Il report non corrisponde al record di audit.".to_owned());
    }
    let payload = request.body.as_bytes();
    let payload_hash = hex_hash(&Sha256::digest(payload).into());
    if payload_hash != request.payload_sha256 {
        return Err("L’impronta del report non corrisponde al contenuto.".to_owned());
    }
    let encoded_record = serde_json::to_vec(&record)
        .map_err(|_| "Il record di audit non è serializzabile.".to_owned())?;
    if encoded_record.len() > MAX_AUDIT_RECORD_BYTES {
        return Err("Il record di audit supera il limite consentito.".to_owned());
    }

    let mut inner = lock_runtime(&state)?;
    validate_transition(&inner.sessions, &record, &validated)
        .map_err(|()| "La sequenza di audit del report è stata rifiutata.".to_owned())?;
    let session = inner
        .sessions
        .get(&request.session_id)
        .ok_or_else(|| "La sessione del report non è disponibile.".to_owned())?;
    validate_json_report(&request.body, &request.session_id, session, verification).map_err(
        |()| "Il contenuto del report non corrisponde alla sessione verificata.".to_owned(),
    )?;

    let expected_public_key = match &inner.identity {
        IdentityRuntimeState::Ready(identity) => identity.public_key(),
        IdentityRuntimeState::Uninitialized(_) => {
            return Err("Inizializzare prima l’identità del dispositivo.".to_owned());
        }
        IdentityRuntimeState::Unavailable => {
            return Err("Il portachiavi del sistema non è disponibile.".to_owned());
        }
        IdentityRuntimeState::Blocked => {
            return Err("L’identità sicura è bloccata.".to_owned());
        }
    };

    let head_check = match &mut inner.audit {
        AuditRuntimeState::Secure { journal, head } => journal.head().map(|actual| (*head, actual)),
        AuditRuntimeState::Unavailable => {
            return Err("L’archivio sicuro non è disponibile.".to_owned());
        }
        AuditRuntimeState::Blocked => {
            return Err("L’archivio sicuro è bloccato.".to_owned());
        }
    };
    let (cached_head, verified_head) = match head_check {
        Ok(heads) => heads,
        Err(_) => {
            inner.audit = AuditRuntimeState::Blocked;
            inner.sessions.clear();
            return Err("Verifica audit non riuscita; riavviare KernAid.".to_owned());
        }
    };
    if cached_head != verified_head {
        inner.audit = AuditRuntimeState::Blocked;
        inner.sessions.clear();
        return Err("Il journal è cambiato fuori dalla sessione; riavviare KernAid.".to_owned());
    }

    let appended = match &mut inner.audit {
        AuditRuntimeState::Secure { journal, head } => {
            journal.append_expected(*head, &encoded_record)
        }
        AuditRuntimeState::Unavailable => {
            return Err("L’archivio sicuro non è disponibile.".to_owned());
        }
        AuditRuntimeState::Blocked => {
            return Err("L’archivio sicuro è bloccato.".to_owned());
        }
    };
    let appended = match appended {
        Ok(entry) => entry,
        Err(_) => {
            inner.audit = AuditRuntimeState::Blocked;
            inner.sessions.clear();
            return Err("Scrittura audit non riuscita; riavviare KernAid.".to_owned());
        }
    };
    let anchor = JournalAnchor {
        journal_id: current_journal_id(&inner.audit)
            .ok_or_else(|| "L’archivio sicuro è bloccato.".to_owned())?,
        sequence: appended.sequence,
        entry_hash: appended.entry_hash,
    };
    if let AuditRuntimeState::Secure { head, .. } = &mut inner.audit {
        *head = anchor;
    }
    inner.persistent_audit_started = true;
    commit_transition(&mut inner.sessions, &record, validated);

    let signed = match &inner.identity {
        IdentityRuntimeState::Ready(identity) => identity.sign_report_envelope(
            payload,
            &request.payload_media_type,
            anchor.sequence,
            &anchor.entry_hash,
        ),
        IdentityRuntimeState::Uninitialized(_)
        | IdentityRuntimeState::Unavailable
        | IdentityRuntimeState::Blocked => unreachable!("identity was checked before append"),
    };
    let envelope = match signed {
        Ok(envelope) => envelope,
        Err(_) => {
            inner.audit = AuditRuntimeState::Blocked;
            inner.sessions.clear();
            return Err("La firma del report non è riuscita; riavviare KernAid.".to_owned());
        }
    };
    let verified_payload = match envelope.verify_zeroizing(&expected_public_key) {
        Ok(payload) => payload,
        Err(_) => {
            inner.audit = AuditRuntimeState::Blocked;
            inner.sessions.clear();
            return Err("La firma del report non è verificabile; riavviare KernAid.".to_owned());
        }
    };
    if verified_payload.as_slice() != payload {
        return Err("La firma del report non è verificabile.".to_owned());
    }
    let container = serde_json::to_string(&envelope)
        .map_err(|_| "Il report firmato non è serializzabile.".to_owned())?;
    let container_sha256 = hex_hash(&Sha256::digest(container.as_bytes()).into());
    Ok(SignedArtifactResult {
        media_type: SIGNED_REPORT_MEDIA_TYPE,
        payload_media_type: request.payload_media_type,
        container_json: container,
        sha256: container_sha256,
        payload_sha256: request.payload_sha256,
        envelope_schema: SIGNED_REPORT_ENVELOPE_SCHEMA,
    })
}

fn ensure_secure_directory(path: &Path) -> Result<(), RuntimeInitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(RuntimeInitError::InvalidSecureDirectory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
        }
        Err(_) => return Err(RuntimeInitError::InvalidSecureDirectory),
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RuntimeInitError::InvalidSecureDirectory);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RuntimeInitError::InvalidSecureDirectory);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != process::getuid().as_raw() {
            return Err(RuntimeInitError::InvalidSecureDirectory);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
        let hardened =
            fs::symlink_metadata(path).map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
        if hardened.mode() & 0o7777 != 0o700 {
            return Err(RuntimeInitError::InvalidSecureDirectory);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_instance_lock(path: &Path) -> Result<File, RuntimeInitError> {
    let fd = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    rfs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
        .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    let descriptor = rfs::fstat(&fd).map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    let named = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    if !FileType::from_raw_mode(descriptor.st_mode).is_file()
        || !FileType::from_raw_mode(named.st_mode).is_file()
        || descriptor.st_dev != named.st_dev
        || descriptor.st_ino != named.st_ino
        || descriptor.st_nlink != 1
        || descriptor.st_uid != process::getuid().as_raw()
        || Mode::from_raw_mode(descriptor.st_mode).as_raw_mode() & 0o7777 != 0o600
    {
        return Err(RuntimeInitError::InvalidSecureDirectory);
    }
    let file = File::from(fd);
    lock_file(file)
}

#[cfg(windows)]
fn open_instance_lock(path: &Path) -> Result<File, RuntimeInitError> {
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    {
        return Err(RuntimeInitError::InvalidSecureDirectory);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RuntimeInitError::InvalidSecureDirectory);
    }
    lock_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_instance_lock(path: &Path) -> Result<File, RuntimeInitError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|_| RuntimeInitError::InvalidSecureDirectory)?;
    lock_file(file)
}

fn lock_file(file: File) -> Result<File, RuntimeInitError> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Err(RuntimeInitError::InstanceAlreadyRunning)
        }
        Err(_) => Err(RuntimeInitError::InvalidSecureDirectory),
    }
}

fn open_audit_state(path: &Path) -> AuditRuntimeState {
    let existed = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return AuditRuntimeState::Blocked,
    };
    let mut store = match NativeJournalSecretStore::open_named(SECRET_NAMESPACE) {
        Ok(store) => store,
        Err(_) if existed => return AuditRuntimeState::Blocked,
        Err(_) => return AuditRuntimeState::Unavailable,
    };
    if !existed {
        match store.inspect_state() {
            Ok(NativeJournalState::Empty) => {}
            Ok(NativeJournalState::Complete | NativeJournalState::Partial) => {
                return AuditRuntimeState::Blocked;
            }
            Err(
                NativeSecretError::BackendUnavailable
                | NativeSecretError::StorageAccessDenied
                | NativeSecretError::UnsupportedPlatform,
            ) => return AuditRuntimeState::Unavailable,
            Err(_) => return AuditRuntimeState::Blocked,
        }
    }
    let mut journal = match SecureJournal::open(path, ResidentJournalSecretStore::Native(store)) {
        Ok(journal) => journal,
        Err(_) => return AuditRuntimeState::Blocked,
    };
    match journal.head() {
        Ok(head) => AuditRuntimeState::Secure {
            journal: Box::new(journal),
            head,
        },
        Err(_) => AuditRuntimeState::Blocked,
    }
}

fn open_qualified_first_launch_audit_state(path: &Path) -> AuditRuntimeState {
    let store = ResidentJournalSecretStore::QualifiedFirstLaunch(
        QualifiedFirstLaunchSecretStore::default(),
    );
    let mut journal = match SecureJournal::open(path, store) {
        Ok(journal) => journal,
        Err(error) => {
            #[cfg(test)]
            eprintln!(
                "KERNAID_QUALIFIED_FIRST_LAUNCH_JOURNAL_FAILURE_V1:{}",
                qualified_first_launch_journal_error_class("open", &error)
            );
            return AuditRuntimeState::Blocked;
        }
    };
    match journal.head() {
        Ok(head) => AuditRuntimeState::Secure {
            journal: Box::new(journal),
            head,
        },
        Err(error) => {
            #[cfg(test)]
            eprintln!(
                "KERNAID_QUALIFIED_FIRST_LAUNCH_JOURNAL_FAILURE_V1:{}",
                qualified_first_launch_journal_error_class("head", &error)
            );
            AuditRuntimeState::Blocked
        }
    }
}

#[cfg(test)]
fn qualified_first_launch_journal_error_class(stage: &'static str, error: &JournalError) -> String {
    let class = match error {
        JournalError::Database(message) => qualified_first_launch_database_error_class(message),
        JournalError::SecretStore(_) => "secret-store",
        JournalError::InvalidPath => "invalid-path",
        JournalError::SymlinkRejected => "symlink",
        JournalError::UnsupportedFormat => "unsupported-format",
        JournalError::MissingKey => "missing-key",
        JournalError::MissingAnchor => "missing-anchor",
        JournalError::SecretStateConflict => "secret-state-conflict",
        JournalError::AuthenticationFailed => "authentication",
        JournalError::CorruptChain => "corrupt-chain",
        JournalError::RollbackDetected => "rollback",
        JournalError::EventTooLarge => "event-too-large",
        JournalError::JournalTooLarge => "journal-too-large",
        JournalError::SequenceOverflow => "sequence-overflow",
        JournalError::EncryptionFailed => "encryption",
        JournalError::ReadLimitExceeded => "read-limit",
        JournalError::UnexpectedHead { .. } => "unexpected-head",
        JournalError::Poisoned => "poisoned",
    };
    format!("{stage}:{class}")
}

#[cfg(test)]
fn qualified_first_launch_database_error_class(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("not authorized") {
        "database-not-authorized"
    } else if message.contains("unable to open") || message.contains("cannot open") {
        "database-open"
    } else if message.contains("disk i/o") || message.contains("disk io") {
        "database-io"
    } else if message.contains("locked") || message.contains("busy") {
        "database-locked"
    } else if message.contains("readonly") || message.contains("read-only") {
        "database-readonly"
    } else if message.contains("misuse") {
        "database-misuse"
    } else if message.contains("unsupported") {
        "database-unsupported"
    } else {
        "database-other"
    }
}

fn open_identity_state() -> IdentityRuntimeState {
    let mut store = match NativeDeviceIdentityStore::open_named(SECRET_NAMESPACE) {
        Ok(store) => store,
        Err(error) => return identity_state_after_error(error),
    };
    match store.load_device_identity() {
        Ok(Some(identity)) => IdentityRuntimeState::Ready(identity),
        Ok(None) => IdentityRuntimeState::Uninitialized(store),
        Err(error) => identity_state_after_error(error),
    }
}

fn initialize_recovered_identity() -> IdentityRuntimeState {
    let mut store = match NativeDeviceIdentityStore::open_named(SECRET_NAMESPACE) {
        Ok(store) => store,
        Err(error) => return identity_state_after_error(error),
    };
    match store.load_device_identity() {
        Ok(Some(identity)) => IdentityRuntimeState::Ready(identity),
        Ok(None) => match store.create_device_identity() {
            Ok(identity) => IdentityRuntimeState::Ready(identity),
            Err(error) => identity_state_after_error(error),
        },
        Err(error) => identity_state_after_error(error),
    }
}

fn reconcile_identity_continuity(
    audit: &mut AuditRuntimeState,
    identity: &mut IdentityRuntimeState,
) -> Result<bool, ()> {
    match audit {
        AuditRuntimeState::Secure { head, .. } if head.sequence == 0 => match identity {
            IdentityRuntimeState::Ready(identity) => ensure_identity_binding(audit, identity),
            IdentityRuntimeState::Uninitialized(_)
            | IdentityRuntimeState::Unavailable
            | IdentityRuntimeState::Blocked => Ok(false),
        },
        AuditRuntimeState::Secure { .. } => match identity {
            IdentityRuntimeState::Ready(identity) => ensure_identity_binding(audit, identity),
            IdentityRuntimeState::Uninitialized(_)
            | IdentityRuntimeState::Unavailable
            | IdentityRuntimeState::Blocked => Err(()),
        },
        AuditRuntimeState::Unavailable => Ok(false),
        AuditRuntimeState::Blocked => Err(()),
    }
}

fn ensure_identity_binding(
    audit: &mut AuditRuntimeState,
    identity: &DeviceIdentity,
) -> Result<bool, ()> {
    let AuditRuntimeState::Secure { journal, head } = audit else {
        return Err(());
    };
    let expected = identity_marker(identity);
    if head.sequence == 0 {
        let encoded = serde_json::to_vec(&expected).map_err(|_| ())?;
        let appended = journal.append_expected(*head, &encoded).map_err(|_| ())?;
        *head = JournalAnchor {
            journal_id: head.journal_id,
            sequence: appended.sequence,
            entry_hash: appended.entry_hash,
        };
        return Ok(true);
    }

    let first = journal.first_entry().map_err(|_| ())?.ok_or(())?;
    if first.sequence != 1 {
        return Err(());
    }
    verify_identity_marker(&first.event, identity)?;
    Ok(false)
}

fn verify_identity_marker(event: &[u8], identity: &DeviceIdentity) -> Result<(), ()> {
    let marker: DeviceIdentityMarker = serde_json::from_slice(event).map_err(|_| ())?;
    let expected = identity_marker(identity);
    if marker.schema_version != expected.schema_version
        || marker.record_type != expected.record_type
        || marker.device_id != expected.device_id
        || marker.public_key_sha256 != expected.public_key_sha256
    {
        return Err(());
    }
    Ok(())
}

fn identity_marker(identity: &DeviceIdentity) -> DeviceIdentityMarker {
    DeviceIdentityMarker {
        schema_version: AUDIT_SCHEMA_VERSION.to_owned(),
        record_type: IDENTITY_MARKER_TYPE.to_owned(),
        device_id: identity.device_id(),
        public_key_sha256: hex_hash(&Sha256::digest(identity.public_key()).into()),
    }
}

fn identity_state_after_error(error: NativeSecretError) -> IdentityRuntimeState {
    match error {
        NativeSecretError::BackendUnavailable
        | NativeSecretError::StorageAccessDenied
        | NativeSecretError::UnsupportedPlatform => IdentityRuntimeState::Unavailable,
        _ => IdentityRuntimeState::Blocked,
    }
}

fn runtime_status(inner: &RuntimeInner) -> SecureRuntimeStatus {
    let audit = match &inner.audit {
        AuditRuntimeState::Secure { .. } => "secure",
        AuditRuntimeState::Unavailable => "unavailable",
        AuditRuntimeState::Blocked => "blocked",
    };
    let (signing, device_id) = match &inner.identity {
        IdentityRuntimeState::Ready(identity) => ("ready", Some(identity.device_id())),
        IdentityRuntimeState::Uninitialized(_) => ("uninitialized", None),
        IdentityRuntimeState::Unavailable => ("unavailable", None),
        IdentityRuntimeState::Blocked => ("blocked", None),
    };
    SecureRuntimeStatus {
        schema_version: AUDIT_SCHEMA_VERSION,
        audit,
        signing,
        persistent_audit_started: inner.persistent_audit_started,
        device_id,
    }
}

fn lock_runtime(state: &SecureRuntime) -> Result<MutexGuard<'_, RuntimeInner>, String> {
    state
        .inner
        .lock()
        .map_err(|_| "Il runtime sicuro non è disponibile; riavviare KernAid.".to_owned())
}

fn current_journal_id(state: &AuditRuntimeState) -> Option<[u8; 16]> {
    match state {
        AuditRuntimeState::Secure { head, .. } => Some(head.journal_id),
        AuditRuntimeState::Unavailable | AuditRuntimeState::Blocked => None,
    }
}

fn validate_audit_record(record: &NativeAuditRecord) -> Result<ValidatedRecordKind, ()> {
    if record.schema_version != AUDIT_SCHEMA_VERSION
        || !valid_identifier(&record.session_id, "S-", MAX_ID_BYTES)
        || record.sequence == 0
        || record.sequence > MAX_SESSION_RECORDS
        || record.captured_at.len() > 40
        || !valid_rfc3339(&record.captured_at)
    {
        return Err(());
    }
    let payload = record.payload.as_object().ok_or(())?;
    match record.record_type.as_str() {
        "session.started" => {
            exact_keys(payload, &["mode", "targetFingerprint"])?;
            let mode = required_string(payload, "mode")?;
            if mode != "resident" {
                return Err(());
            }
            let target_fingerprint = required_string(payload, "targetFingerprint")?;
            if !valid_fingerprint(target_fingerprint) {
                return Err(());
            }
            Ok(ValidatedRecordKind::SessionStarted {
                target_fingerprint: target_fingerprint.to_owned(),
            })
        }
        "evidence" => {
            exact_keys(payload, &["evidenceId", "sha256", "sensitivity"])?;
            let evidence_id = required_string(payload, "evidenceId")?;
            let sensitivity = required_string(payload, "sensitivity")?;
            let sha256 = required_string(payload, "sha256")?;
            if !valid_identifier(evidence_id, "E-", MAX_ID_BYTES)
                || !valid_hash(sha256)
                || !matches!(sensitivity, "public" | "system" | "sensitive")
            {
                return Err(());
            }
            Ok(ValidatedRecordKind::Evidence {
                evidence_id: evidence_id.to_owned(),
                sha256: sha256.to_owned(),
                sensitivity: sensitivity.to_owned(),
            })
        }
        "diagnosis" => {
            exact_keys(
                payload,
                &[
                    "diagnosisSha256",
                    "confidence",
                    "evidenceIds",
                    "requestedEvidenceCount",
                ],
            )?;
            let diagnosis_sha256 = required_string(payload, "diagnosisSha256")?;
            if !valid_hash(diagnosis_sha256) {
                return Err(());
            }
            let confidence = payload
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or(())?;
            let requested_evidence_count = payload
                .get("requestedEvidenceCount")
                .and_then(Value::as_u64)
                .ok_or(())?;
            if !(0.0..=1.0).contains(&confidence) || requested_evidence_count > 128 {
                return Err(());
            }
            Ok(ValidatedRecordKind::Diagnosis {
                diagnosis_sha256: diagnosis_sha256.to_owned(),
                confidence,
                evidence_ids: identifier_array(
                    payload,
                    "evidenceIds",
                    "E-",
                    1,
                    MAX_EVIDENCE_IDS,
                    true,
                    MAX_ID_BYTES,
                )?,
                requested_evidence_count,
            })
        }
        "plan" => {
            exact_keys(
                payload,
                &[
                    "planId",
                    "targetFingerprint",
                    "risk",
                    "evidenceIds",
                    "actions",
                ],
            )?;
            let plan_id = required_string(payload, "planId")?;
            let target_fingerprint = required_string(payload, "targetFingerprint")?;
            let risk = required_string(payload, "risk")?;
            if !valid_identifier(plan_id, "P-", MAX_ID_BYTES)
                || !valid_fingerprint(target_fingerprint)
                || risk != "R0"
            {
                return Err(());
            }
            let actions = string_array(payload, "actions", 1, MAX_ACTIONS, false)?;
            if actions.as_slice() != ["system.observe.noop"]
                || actions
                    .iter()
                    .any(|action| !valid_action(action, MAX_ACTION_BYTES))
            {
                return Err(());
            }
            Ok(ValidatedRecordKind::Plan {
                plan_id: plan_id.to_owned(),
                target_fingerprint: target_fingerprint.to_owned(),
                risk: risk.to_owned(),
                evidence_ids: identifier_array(
                    payload,
                    "evidenceIds",
                    "E-",
                    1,
                    MAX_EVIDENCE_IDS,
                    true,
                    MAX_ID_BYTES,
                )?,
                actions,
            })
        }
        "approval" => {
            exact_keys(
                payload,
                &[
                    "approvalId",
                    "planId",
                    "targetFingerprint",
                    "approvedAt",
                    "approvedBySha256",
                ],
            )?;
            let approval_id = required_string(payload, "approvalId")?;
            let plan_id = required_string(payload, "planId")?;
            let target_fingerprint = required_string(payload, "targetFingerprint")?;
            let approved_at = required_string(payload, "approvedAt")?;
            let approved_by_sha256 = required_string(payload, "approvedBySha256")?;
            if !valid_identifier(approval_id, "A-", MAX_ID_BYTES)
                || !valid_identifier(plan_id, "P-", MAX_ID_BYTES)
                || !valid_fingerprint(target_fingerprint)
                || approved_at.len() > 40
                || !valid_rfc3339(approved_at)
                || !valid_hash(approved_by_sha256)
            {
                return Err(());
            }
            Ok(ValidatedRecordKind::Approval {
                approval_id: approval_id.to_owned(),
                plan_id: plan_id.to_owned(),
                target_fingerprint: target_fingerprint.to_owned(),
                approved_at: approved_at.to_owned(),
                approved_by_sha256: approved_by_sha256.to_owned(),
            })
        }
        "execution" => {
            exact_keys(payload, &["planId", "eventSequence", "status", "action"])?;
            let plan_id = required_string(payload, "planId")?;
            let event_sequence = payload
                .get("eventSequence")
                .and_then(Value::as_u64)
                .ok_or(())?;
            let status = required_string(payload, "status")?;
            let action = required_string(payload, "action")?;
            if !valid_identifier(plan_id, "P-", MAX_ID_BYTES)
                || event_sequence == 0
                || event_sequence > 1_024
                || !matches!(status, "started" | "succeeded" | "failed" | "rolled-back")
                || !valid_action(action, MAX_ACTION_BYTES)
            {
                return Err(());
            }
            Ok(ValidatedRecordKind::Execution {
                plan_id: plan_id.to_owned(),
                event_sequence,
                status: status.to_owned(),
                action: action.to_owned(),
            })
        }
        "report" => {
            exact_keys(
                payload,
                &[
                    "format",
                    "payloadMediaType",
                    "payloadSha256",
                    "verification",
                ],
            )?;
            let format = required_string(payload, "format")?;
            let payload_media_type = required_string(payload, "payloadMediaType")?;
            let payload_sha256 = required_string(payload, "payloadSha256")?;
            if !valid_format_media_type(format, payload_media_type)
                || !valid_hash(payload_sha256)
                || !matches!(
                    required_string(payload, "verification")?,
                    "not-run" | "passed" | "failed"
                )
            {
                return Err(());
            }
            Ok(ValidatedRecordKind::Report {
                format: format.to_owned(),
                payload_media_type: payload_media_type.to_owned(),
                payload_sha256: payload_sha256.to_owned(),
                verification: required_string(payload, "verification")?.to_owned(),
            })
        }
        _ => Err(()),
    }
}

fn validate_transition(
    sessions: &HashMap<String, NativeAuditSession>,
    record: &NativeAuditRecord,
    kind: &ValidatedRecordKind,
) -> Result<(), ()> {
    let Some(session) = sessions.get(&record.session_id) else {
        return match kind {
            ValidatedRecordKind::SessionStarted { .. }
                if record.sequence == 1 && sessions.len() < MAX_AUDIT_SESSIONS =>
            {
                Ok(())
            }
            _ => Err(()),
        };
    };
    if record.sequence != session.last_sequence.checked_add(1).ok_or(())?
        || matches!(kind, ValidatedRecordKind::SessionStarted { .. })
    {
        return Err(());
    }
    match kind {
        ValidatedRecordKind::SessionStarted { .. } => Err(()),
        ValidatedRecordKind::Evidence { evidence_id, .. } => (session.phase
            == SessionPhase::Observe
            && !session
                .evidence
                .iter()
                .any(|binding| binding.evidence_id == *evidence_id))
        .then_some(())
        .ok_or(()),
        ValidatedRecordKind::Diagnosis { evidence_ids, .. } => (session.phase
            == SessionPhase::Observe
            && !session.evidence.is_empty()
            && evidence_ids.iter().all(|id| {
                session
                    .evidence
                    .iter()
                    .any(|binding| binding.evidence_id == *id)
            }))
        .then_some(())
        .ok_or(()),
        ValidatedRecordKind::Plan {
            plan_id,
            target_fingerprint,
            evidence_ids,
            ..
        } => (target_fingerprint == &session.target_fingerprint
            && session.phase == SessionPhase::Observe
            && session
                .diagnoses
                .iter()
                .any(|diagnosis| diagnosis.evidence_ids == *evidence_ids)
            && session.plans.is_empty()
            && !session.plans.contains_key(plan_id)
            && evidence_ids.iter().all(|id| {
                session
                    .evidence
                    .iter()
                    .any(|binding| binding.evidence_id == *id)
            }))
        .then_some(())
        .ok_or(()),
        ValidatedRecordKind::Approval {
            approval_id,
            plan_id,
            target_fingerprint,
            ..
        } => (target_fingerprint == &session.target_fingerprint
            && session.phase == SessionPhase::Plan
            && session.plans.contains_key(plan_id)
            && !session
                .approvals
                .iter()
                .any(|binding| binding.approval_id == *approval_id))
        .then_some(())
        .ok_or(()),
        ValidatedRecordKind::Execution {
            plan_id,
            event_sequence,
            status,
            action,
        } => {
            let Some(plan) = session.plans.get(plan_id) else {
                return Err(());
            };
            if plan.risk != "R0"
                || !plan.actions.iter().any(|planned| planned == action)
                || *event_sequence != session.executions.len() as u64 + 1
            {
                return Err(());
            }
            match status.as_str() {
                "started" => (session.phase == SessionPhase::Plan && session.executions.is_empty())
                    .then_some(())
                    .ok_or(()),
                "succeeded" | "failed" => (session.phase == SessionPhase::Executing
                    && session
                        .executions
                        .last()
                        .is_some_and(|event| event.status == "started"))
                .then_some(())
                .ok_or(()),
                "rolled-back" => Err(()),
                _ => Err(()),
            }
        }
        ValidatedRecordKind::Report { format, .. } => (format == "json"
            && matches!(
                session.phase,
                SessionPhase::Plan | SessionPhase::Complete | SessionPhase::Failed
            ))
        .then_some(())
        .ok_or(()),
    }
}

fn commit_transition(
    sessions: &mut HashMap<String, NativeAuditSession>,
    record: &NativeAuditRecord,
    kind: ValidatedRecordKind,
) {
    if let ValidatedRecordKind::SessionStarted { target_fingerprint } = kind {
        sessions.insert(
            record.session_id.clone(),
            NativeAuditSession {
                target_fingerprint,
                last_sequence: record.sequence,
                phase: SessionPhase::Observe,
                evidence: Vec::new(),
                diagnoses: Vec::new(),
                plans: HashMap::new(),
                approvals: Vec::new(),
                executions: Vec::new(),
            },
        );
        return;
    }
    let Some(session) = sessions.get_mut(&record.session_id) else {
        return;
    };
    session.last_sequence = record.sequence;
    match kind {
        ValidatedRecordKind::Evidence {
            evidence_id,
            sha256,
            sensitivity,
        } => {
            session.evidence.push(EvidenceBinding {
                evidence_id,
                sha256,
                sensitivity,
                captured_at: record.captured_at.clone(),
            });
        }
        ValidatedRecordKind::Diagnosis {
            diagnosis_sha256,
            confidence,
            evidence_ids,
            requested_evidence_count,
        } => {
            session.diagnoses.push(DiagnosisBinding {
                diagnosis_sha256,
                confidence,
                evidence_ids,
                requested_evidence_count,
            });
        }
        ValidatedRecordKind::Plan {
            plan_id,
            risk,
            actions,
            ..
        } => {
            session.plans.insert(plan_id, PlanBinding { risk, actions });
            session.phase = SessionPhase::Plan;
        }
        ValidatedRecordKind::Approval {
            approval_id,
            plan_id,
            approved_at,
            approved_by_sha256,
            ..
        } => {
            session.approvals.push(ApprovalBinding {
                approval_id,
                plan_id,
                approved_at,
                approved_by_sha256,
            });
        }
        ValidatedRecordKind::Execution {
            plan_id,
            event_sequence,
            status,
            action,
        } => {
            session.phase = match status.as_str() {
                "started" => SessionPhase::Executing,
                "succeeded" => SessionPhase::Complete,
                "failed" => SessionPhase::Failed,
                _ => SessionPhase::Failed,
            };
            session.executions.push(ExecutionBinding {
                plan_id,
                event_sequence,
                status,
                action,
                captured_at: record.captured_at.clone(),
            });
        }
        ValidatedRecordKind::SessionStarted { .. } | ValidatedRecordKind::Report { .. } => {}
    }
}

fn validate_seal_request(request: &NativeSealRequest) -> Result<(), ()> {
    if request.schema_version != AUDIT_SCHEMA_VERSION
        || !valid_identifier(&request.session_id, "S-", MAX_ID_BYTES)
        || request.format != "json"
        || request.payload_media_type != "application/json"
        || request.body.is_empty()
        || request.body.len() > MAX_SIGNED_REPORT_PAYLOAD_BYTES
        || !valid_hash(&request.payload_sha256)
    {
        return Err(());
    }
    Ok(())
}

fn validate_json_report(
    body: &str,
    expected_session_id: &str,
    session: &NativeAuditSession,
    audited_verification: &str,
) -> Result<(), ()> {
    let report: Value = serde_json::from_str(body).map_err(|_| ())?;
    let report = report.as_object().ok_or(())?;
    exact_keys(
        report,
        &[
            "schemaVersion",
            "sessionId",
            "targetFingerprint",
            "facts",
            "inferences",
            "decisions",
            "events",
            "verification",
            "unresolvedRisks",
        ],
    )?;
    if required_string(report, "schemaVersion")? != AUDIT_SCHEMA_VERSION
        || required_string(report, "sessionId")? != expected_session_id
        || required_string(report, "targetFingerprint")? != session.target_fingerprint
        || required_string(report, "verification")? != audited_verification
    {
        return Err(());
    }

    let facts = required_array(report, "facts")?;
    if facts.len() != session.evidence.len() {
        return Err(());
    }
    for (value, binding) in facts.iter().zip(&session.evidence) {
        validate_report_evidence(value, binding)?;
    }

    let inferences = required_array(report, "inferences")?;
    if inferences.len() != session.diagnoses.len() {
        return Err(());
    }
    for (value, binding) in inferences.iter().zip(&session.diagnoses) {
        validate_report_diagnosis(value, binding)?;
    }

    let decisions = required_array(report, "decisions")?;
    if decisions.len() != session.approvals.len() {
        return Err(());
    }
    for (value, binding) in decisions.iter().zip(&session.approvals) {
        validate_report_approval(value, binding, &session.target_fingerprint)?;
    }

    let events = required_array(report, "events")?;
    if events.len() != session.executions.len() {
        return Err(());
    }
    for (value, binding) in events.iter().zip(&session.executions) {
        validate_report_execution(value, binding)?;
    }

    let expected_verification = if session
        .executions
        .iter()
        .any(|event| event.status == "failed")
    {
        "failed"
    } else if session
        .executions
        .last()
        .is_some_and(|event| event.status == "succeeded")
    {
        "passed"
    } else {
        "not-run"
    };
    if audited_verification != expected_verification {
        return Err(());
    }

    let risks = required_array(report, "unresolvedRisks")?;
    if risks.len() > 128 {
        return Err(());
    }
    let mut unique_risks = HashSet::with_capacity(risks.len());
    for value in risks {
        let risk = bounded_value_string(value, 0, 8_192)?;
        if !unique_risks.insert(risk) {
            return Err(());
        }
    }
    Ok(())
}

fn validate_report_evidence(value: &Value, binding: &EvidenceBinding) -> Result<(), ()> {
    let item = value.as_object().ok_or(())?;
    exact_keys(
        item,
        &[
            "schemaVersion",
            "id",
            "collector",
            "target",
            "capturedAt",
            "contentType",
            "sha256",
            "sensitivity",
            "trust",
            "summary",
            "blobRef",
        ],
    )?;
    if required_string(item, "schemaVersion")? != AUDIT_SCHEMA_VERSION
        || required_string(item, "id")? != binding.evidence_id
        || required_string(item, "capturedAt")? != binding.captured_at
        || required_string(item, "sha256")? != binding.sha256
        || required_string(item, "sensitivity")? != binding.sensitivity
        || required_string(item, "trust")? != "observed-untrusted"
        || required_string(item, "blobRef")? != format!("sha256:{}", binding.sha256)
    {
        return Err(());
    }
    bounded_field_string(item, "collector", 1, 256)?;
    bounded_field_string(item, "target", 1, 512)?;
    bounded_field_string(item, "contentType", 1, 256)?;
    bounded_field_string(item, "summary", 0, 8_192)?;
    Ok(())
}

fn validate_report_diagnosis(value: &Value, binding: &DiagnosisBinding) -> Result<(), ()> {
    let item = value.as_object().ok_or(())?;
    exact_keys(
        item,
        &[
            "schemaVersion",
            "diagnosis",
            "confidence",
            "evidenceIds",
            "requestedEvidence",
        ],
    )?;
    let diagnosis = bounded_field_string(item, "diagnosis", 1, 16_384)?;
    if required_string(item, "schemaVersion")? != AUDIT_SCHEMA_VERSION
        || hex_hash(&Sha256::digest(diagnosis.as_bytes()).into()) != binding.diagnosis_sha256
        || item
            .get("confidence")
            .and_then(Value::as_f64)
            .is_none_or(|value| value.to_bits() != binding.confidence.to_bits())
    {
        return Err(());
    }
    let evidence_ids = required_array(item, "evidenceIds")?;
    if evidence_ids.len() != binding.evidence_ids.len()
        || evidence_ids
            .iter()
            .zip(&binding.evidence_ids)
            .any(|(value, id)| value.as_str().is_none_or(|candidate| candidate != id))
    {
        return Err(());
    }
    let requested = required_array(item, "requestedEvidence")?;
    if requested.len() as u64 != binding.requested_evidence_count {
        return Err(());
    }
    let mut unique = HashSet::with_capacity(requested.len());
    for value in requested {
        let request = bounded_value_string(value, 0, 256)?;
        if !unique.insert(request) {
            return Err(());
        }
    }
    Ok(())
}

fn validate_report_approval(
    value: &Value,
    binding: &ApprovalBinding,
    target_fingerprint: &str,
) -> Result<(), ()> {
    let item = value.as_object().ok_or(())?;
    exact_keys_with_optional(
        item,
        &[
            "schemaVersion",
            "approvalId",
            "planId",
            "targetFingerprint",
            "approvedAt",
            "approvedBy",
        ],
        &["typedConfirmation"],
    )?;
    let approved_by = bounded_field_string(item, "approvedBy", 1, 256)?;
    if required_string(item, "schemaVersion")? != AUDIT_SCHEMA_VERSION
        || required_string(item, "approvalId")? != binding.approval_id
        || required_string(item, "planId")? != binding.plan_id
        || required_string(item, "targetFingerprint")? != target_fingerprint
        || required_string(item, "approvedAt")? != binding.approved_at
        || hex_hash(&Sha256::digest(approved_by.as_bytes()).into()) != binding.approved_by_sha256
    {
        return Err(());
    }
    if let Some(value) = item.get("typedConfirmation") {
        bounded_value_string(value, 1, 256)?;
    }
    Ok(())
}

fn validate_report_execution(value: &Value, binding: &ExecutionBinding) -> Result<(), ()> {
    let item = value.as_object().ok_or(())?;
    exact_keys(
        item,
        &[
            "schemaVersion",
            "planId",
            "sequence",
            "status",
            "action",
            "message",
            "capturedAt",
        ],
    )?;
    if required_string(item, "schemaVersion")? != AUDIT_SCHEMA_VERSION
        || required_string(item, "planId")? != binding.plan_id
        || item.get("sequence").and_then(Value::as_u64) != Some(binding.event_sequence)
        || required_string(item, "status")? != binding.status
        || required_string(item, "action")? != binding.action
        || required_string(item, "capturedAt")? != binding.captured_at
    {
        return Err(());
    }
    bounded_field_string(item, "message", 0, 8_192)?;
    Ok(())
}

fn required_array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], ()> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(())
}

fn bounded_field_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> Result<&'a str, ()> {
    bounded_value_string(object.get(key).ok_or(())?, minimum, maximum)
}

fn bounded_value_string(value: &Value, minimum: usize, maximum: usize) -> Result<&str, ()> {
    let value = value.as_str().ok_or(())?;
    (value.len() >= minimum && value.len() <= maximum)
        .then_some(value)
        .ok_or(())
}

fn exact_keys_with_optional(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ()> {
    let expected =
        required.len() + usize::from(optional.iter().any(|key| object.contains_key(*key)));
    (object.len() == expected
        && required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())))
    .then_some(())
    .ok_or(())
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<(), ()> {
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then_some(())
        .ok_or(())
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ()> {
    object.get(key).and_then(Value::as_str).ok_or(())
}

fn identifier_array(
    object: &Map<String, Value>,
    key: &str,
    prefix: &str,
    minimum: usize,
    maximum: usize,
    unique: bool,
    maximum_bytes: usize,
) -> Result<Vec<String>, ()> {
    let values = string_array(object, key, minimum, maximum, unique)?;
    if values
        .iter()
        .any(|value| !valid_identifier(value, prefix, maximum_bytes))
    {
        return Err(());
    }
    Ok(values)
}

fn string_array(
    object: &Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
    unique: bool,
) -> Result<Vec<String>, ()> {
    let values = object.get(key).and_then(Value::as_array).ok_or(())?;
    if values.len() < minimum || values.len() > maximum {
        return Err(());
    }
    let strings = values
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    if unique && strings.iter().collect::<HashSet<_>>().len() != strings.len() {
        return Err(());
    }
    Ok(strings)
}

fn valid_identifier(value: &str, prefix: &str, maximum_bytes: usize) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= maximum_bytes
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_action(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hash)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_format_media_type(format: &str, media_type: &str) -> bool {
    matches!(
        (format, media_type),
        ("json", "application/json") | ("markdown", "text/markdown")
    )
}

fn valid_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let Some(year) = decimal(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = decimal(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = decimal(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = decimal(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = decimal(bytes, 14, 2) else {
        return false;
    };
    let Some(second) = decimal(bytes, 17, 2) else {
        return false;
    };
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }

    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == fraction_start {
            return false;
        }
    }
    match bytes.get(cursor) {
        Some(b'Z') => cursor + 1 == bytes.len(),
        Some(b'+') | Some(b'-') => {
            bytes.len() == cursor + 6
                && bytes.get(cursor + 3) == Some(&b':')
                && decimal(bytes, cursor + 1, 2).is_some_and(|offset_hour| offset_hour <= 23)
                && decimal(bytes, cursor + 4, 2).is_some_and(|offset_minute| offset_minute <= 59)
        }
        _ => false,
    }
}

fn decimal(bytes: &[u8], start: usize, length: usize) -> Option<u32> {
    let digits = bytes.get(start..start.checked_add(length)?)?;
    digits.iter().try_fold(0_u32, |value, digit| {
        digit
            .is_ascii_digit()
            .then_some(value * 10 + u32::from(*digit - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn hex_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        path::PathBuf,
        process as std_process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn qualified_first_launch_status_accepts_only_readable_non_blocked_states() {
        let status = |audit, signing, device_id| SecureRuntimeStatus {
            schema_version: AUDIT_SCHEMA_VERSION,
            audit,
            signing,
            persistent_audit_started: false,
            device_id,
        };
        assert!(status("secure", "uninitialized", None).is_readable_for_qualified_first_launch());
        assert!(
            status("unavailable", "unavailable", None).is_readable_for_qualified_first_launch()
        );
        assert!(
            status(
                "secure",
                "ready",
                Some("KA-0123456789abcdef01234567".to_owned())
            )
            .is_readable_for_qualified_first_launch()
        );
        assert!(!status("blocked", "unavailable", None).is_readable_for_qualified_first_launch());
        assert!(!status("secure", "blocked", None).is_readable_for_qualified_first_launch());
        assert!(!status("secure", "ready", None).is_readable_for_qualified_first_launch());
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "kernaid-secure-runtime-{label}-{}-{}",
                std_process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            let created = fs::create_dir(&path);
            assert!(created.is_ok());
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn record(record_type: &str, sequence: u64, payload: Value) -> NativeAuditRecord {
        NativeAuditRecord {
            schema_version: "1.0".to_owned(),
            record_type: record_type.to_owned(),
            session_id: "S-test".to_owned(),
            sequence,
            captured_at: "2026-08-01T00:00:00.000Z".to_owned(),
            payload,
        }
    }

    #[test]
    fn instance_lock_is_exclusive_and_recoverable() {
        let directory = TestDirectory::new("lock");
        let path = directory.0.join("runtime.lock");
        let first = open_instance_lock(&path);
        assert!(first.is_ok());
        assert_eq!(
            open_instance_lock(&path).err(),
            Some(RuntimeInitError::InstanceAlreadyRunning)
        );
        drop(first);
        assert!(open_instance_lock(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn instance_lock_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new("symlink-lock");
        let referent = directory.0.join("referent");
        assert!(fs::write(&referent, b"do not touch").is_ok());
        let link = directory.0.join("runtime.lock");
        assert!(symlink(&referent, &link).is_ok());
        assert_eq!(
            open_instance_lock(&link).err(),
            Some(RuntimeInitError::InvalidSecureDirectory)
        );
        assert_eq!(
            fs::read(referent).ok().as_deref(),
            Some(b"do not touch".as_slice())
        );
    }

    #[test]
    fn audit_contract_is_strict_and_bounded() {
        let start = record(
            "session.started",
            1,
            serde_json::json!({
                "mode": "resident",
                "targetFingerprint": format!("sha256:{}", "a".repeat(64))
            }),
        );
        assert!(matches!(
            validate_audit_record(&start),
            Ok(ValidatedRecordKind::SessionStarted { .. })
        ));
        let mut invalid = start.clone();
        invalid.payload["extra"] = Value::Bool(true);
        assert!(validate_audit_record(&invalid).is_err());
        invalid = start;
        invalid.captured_at = "not-a-date".to_owned();
        assert!(validate_audit_record(&invalid).is_err());
    }

    #[test]
    fn transition_binding_rejects_foreign_evidence_and_targets() {
        let start = record(
            "session.started",
            1,
            serde_json::json!({
                "mode": "resident",
                "targetFingerprint": format!("sha256:{}", "a".repeat(64))
            }),
        );
        let kind = validate_audit_record(&start);
        assert!(kind.is_ok());
        let mut sessions = HashMap::new();
        if let Ok(kind) = kind {
            assert!(validate_transition(&sessions, &start, &kind).is_ok());
            commit_transition(&mut sessions, &start, kind);
        }
        let diagnosis = record(
            "diagnosis",
            2,
            serde_json::json!({
                "diagnosisSha256": "b".repeat(64),
                "confidence": 0.5,
                "evidenceIds": ["E-foreign"],
                "requestedEvidenceCount": 0
            }),
        );
        let diagnosis_kind = validate_audit_record(&diagnosis);
        assert!(diagnosis_kind.is_ok());
        if let Ok(kind) = diagnosis_kind {
            assert!(validate_transition(&sessions, &diagnosis, &kind).is_err());
        }

        let evidence_one = record(
            "evidence",
            2,
            serde_json::json!({
                "evidenceId": "E-1",
                "sha256": "c".repeat(64),
                "sensitivity": "system"
            }),
        );
        let kind = validate_audit_record(&evidence_one).expect("valid first evidence");
        assert!(validate_transition(&sessions, &evidence_one, &kind).is_ok());
        commit_transition(&mut sessions, &evidence_one, kind);

        let bound_diagnosis = record(
            "diagnosis",
            3,
            serde_json::json!({
                "diagnosisSha256": "d".repeat(64),
                "confidence": 0.5,
                "evidenceIds": ["E-1"],
                "requestedEvidenceCount": 0
            }),
        );
        let kind = validate_audit_record(&bound_diagnosis).expect("valid diagnosis");
        assert!(validate_transition(&sessions, &bound_diagnosis, &kind).is_ok());
        commit_transition(&mut sessions, &bound_diagnosis, kind);

        let evidence_two = record(
            "evidence",
            4,
            serde_json::json!({
                "evidenceId": "E-2",
                "sha256": "e".repeat(64),
                "sensitivity": "system"
            }),
        );
        let kind = validate_audit_record(&evidence_two).expect("valid second evidence");
        assert!(validate_transition(&sessions, &evidence_two, &kind).is_ok());
        commit_transition(&mut sessions, &evidence_two, kind);

        let unbound_plan = record(
            "plan",
            5,
            serde_json::json!({
                "planId": "P-unbound",
                "targetFingerprint": format!("sha256:{}", "a".repeat(64)),
                "risk": "R0",
                "evidenceIds": ["E-2"],
                "actions": ["system.observe.noop"]
            }),
        );
        let kind = validate_audit_record(&unbound_plan).expect("valid plan shape");
        assert!(validate_transition(&sessions, &unbound_plan, &kind).is_err());
    }

    #[test]
    fn resident_state_machine_rejects_rescue_and_report_before_plan() {
        let rescue = record(
            "session.started",
            1,
            serde_json::json!({
                "mode": "rescue",
                "targetFingerprint": format!("sha256:{}", "a".repeat(64))
            }),
        );
        assert!(validate_audit_record(&rescue).is_err());

        let start = record(
            "session.started",
            1,
            serde_json::json!({
                "mode": "resident",
                "targetFingerprint": format!("sha256:{}", "a".repeat(64))
            }),
        );
        let mut sessions = HashMap::new();
        let start_kind = validate_audit_record(&start).expect("valid start");
        commit_transition(&mut sessions, &start, start_kind);
        let report = record(
            "report",
            2,
            serde_json::json!({
                "format": "json",
                "payloadMediaType": "application/json",
                "payloadSha256": "b".repeat(64),
                "verification": "not-run"
            }),
        );
        let report_kind = validate_audit_record(&report).expect("valid report record");
        assert!(validate_transition(&sessions, &report, &report_kind).is_err());
    }

    #[test]
    fn typed_report_is_bound_to_the_complete_native_session() {
        let target = format!("sha256:{}", "a".repeat(64));
        let diagnosis = "Filesystem observation only";
        let diagnosis_hash = hex_hash(&Sha256::digest(diagnosis.as_bytes()).into());
        let records = [
            record(
                "session.started",
                1,
                serde_json::json!({"mode": "resident", "targetFingerprint": target.clone()}),
            ),
            record(
                "evidence",
                2,
                serde_json::json!({
                    "evidenceId": "E-1",
                    "sha256": "c".repeat(64),
                    "sensitivity": "system"
                }),
            ),
            record(
                "diagnosis",
                3,
                serde_json::json!({
                    "diagnosisSha256": diagnosis_hash,
                    "confidence": 0.75,
                    "evidenceIds": ["E-1"],
                    "requestedEvidenceCount": 0
                }),
            ),
            record(
                "plan",
                4,
                serde_json::json!({
                    "planId": "P-1",
                    "targetFingerprint": target.clone(),
                    "risk": "R0",
                    "evidenceIds": ["E-1"],
                    "actions": ["system.observe.noop"]
                }),
            ),
        ];
        let mut sessions = HashMap::new();
        for item in records {
            let kind = validate_audit_record(&item).expect("valid transition record");
            assert!(validate_transition(&sessions, &item, &kind).is_ok());
            commit_transition(&mut sessions, &item, kind);
        }
        let body = serde_json::json!({
            "schemaVersion": "1.0",
            "sessionId": "S-test",
            "targetFingerprint": target,
            "facts": [{
                "schemaVersion": "1.0",
                "id": "E-1",
                "collector": "linux.fixture.inventory",
                "target": "fixture:linux-root",
                "capturedAt": "2026-08-01T00:00:00.000Z",
                "contentType": "text/plain",
                "sha256": "c".repeat(64),
                "sensitivity": "system",
                "trust": "observed-untrusted",
                "summary": "Read-only inventory",
                "blobRef": format!("sha256:{}", "c".repeat(64))
            }],
            "inferences": [{
                "schemaVersion": "1.0",
                "diagnosis": diagnosis,
                "confidence": 0.75,
                "evidenceIds": ["E-1"],
                "requestedEvidence": []
            }],
            "decisions": [],
            "events": [],
            "verification": "not-run",
            "unresolvedRisks": ["No mutation was run"]
        });
        let body = serde_json::to_string_pretty(&body).expect("serialize report");
        let session = sessions.get("S-test").expect("session");
        assert!(validate_json_report(&body, "S-test", session, "not-run").is_ok());

        let mut tampered: Value = serde_json::from_str(&body).expect("parse report");
        tampered["targetFingerprint"] = Value::String(format!("sha256:{}", "d".repeat(64)));
        assert!(
            validate_json_report(
                &serde_json::to_string(&tampered).expect("serialize tamper"),
                "S-test",
                session,
                "not-run"
            )
            .is_err()
        );
        tampered = serde_json::from_str(&body).expect("parse report");
        tampered["extra"] = Value::Bool(true);
        assert!(
            validate_json_report(
                &serde_json::to_string(&tampered).expect("serialize extra"),
                "S-test",
                session,
                "not-run"
            )
            .is_err()
        );
    }

    #[test]
    fn seal_request_matches_native_envelope_limit() {
        let request = NativeSealRequest {
            schema_version: "1.0".to_owned(),
            session_id: "S-test".to_owned(),
            format: "json".to_owned(),
            payload_media_type: "application/json".to_owned(),
            body: "x".repeat(MAX_SIGNED_REPORT_PAYLOAD_BYTES),
            payload_sha256: "a".repeat(64),
        };
        assert!(validate_seal_request(&request).is_ok());
        let mut oversized = request;
        oversized.body.push('x');
        assert!(validate_seal_request(&oversized).is_err());
    }

    #[test]
    fn identity_marker_is_strict_and_pinned_to_the_public_key() {
        let first = DeviceIdentity::from_seed(&[7; 32]).expect("first identity");
        let second = DeviceIdentity::from_seed(&[8; 32]).expect("second identity");
        let encoded = serde_json::to_vec(&identity_marker(&first)).expect("marker JSON");
        assert!(verify_identity_marker(&encoded, &first).is_ok());
        assert!(verify_identity_marker(&encoded, &second).is_err());

        let mut ambiguous: Value = serde_json::from_slice(&encoded).expect("marker object");
        ambiguous["extra"] = Value::Bool(true);
        assert!(
            verify_identity_marker(
                &serde_json::to_vec(&ambiguous).expect("ambiguous marker"),
                &first
            )
            .is_err()
        );
    }
}
