#![forbid(unsafe_code)]
//! Durable offline-first delivery and entitlement state for KernAid Fleet.
//!
//! This crate owns queue state, not transport credentials. Callers keep the
//! device identity in the existing secure store and submit the returned exact
//! bytes over their authenticated transport. Commercial documents are verified
//! against a caller-supplied public anchor; failures never close local safety
//! paths such as diagnostics, report export, or rollback.

use kernaid_device_identity::DeviceIdentity;
use kernaid_entitlements::{
    EntitlementCheckpoint, EntitlementError, EntitlementState, LicensedCapabilities,
    RevocationCheckpoint, VerifiedEntitlement, VerifiedRevocations,
    capabilities as licensed_capabilities, verify_entitlement, verify_revocations,
};
use kernaid_fleet_client::{InventoryAsset, MAX_INVENTORY_BATCH_ASSETS, sign_inventory_batch};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const SCHEMA_VERSION: i64 = 2;
const IDENTITY_SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4b41_464c; // "KAFL"
const MAX_QUEUE_ITEMS: u64 = 100_000;
const MAX_BATCH_ITEMS: usize = 256;
const MAX_RETRY_DELAY_SECONDS: u64 = 24 * 60 * 60;
const MAX_ATTEMPTS: u32 = 1_000_000;
const SHA256_BYTES: usize = 32;
const MAX_SIGNED_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_ENTITLEMENT_DOCUMENT_BYTES: usize = 64 * 1024;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// One exact, signed payload ready for authenticated delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingInventory {
    id: u64,
    sequence: u64,
    payload: Vec<u8>,
    payload_sha256: [u8; SHA256_BYTES],
    attempts: u32,
}

/// Result of atomically applying one signed licensing document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntitlementApplyResult {
    idempotent: bool,
}

impl EntitlementApplyResult {
    #[must_use]
    pub const fn idempotent(self) -> bool {
        self.idempotent
    }
}

/// Runtime view of the entitlement boundary. Missing or unverifiable state is
/// explicit and never silently interpreted as a paid license.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FleetEntitlementState {
    TrustAnchorUnavailable,
    Absent,
    Corrupt,
    InvalidClock,
    Licensed(EntitlementState),
}

/// Capability decision consumed by Fleet callers. The three safety paths are
/// intentionally true in every state, including corrupt storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FleetCapabilities {
    pub entitlement_state: FleetEntitlementState,
    pub diagnostics: bool,
    pub report_export: bool,
    pub rollback: bool,
    pub consumer_repair: bool,
    pub enterprise_repair: bool,
    pub fleet_sync: bool,
    pub cached_policy: bool,
    pub audit_upload: bool,
    pub updates: bool,
    pub enterprise_providers: bool,
}

impl FleetCapabilities {
    const fn safe_degraded(entitlement_state: FleetEntitlementState) -> Self {
        Self {
            entitlement_state,
            diagnostics: true,
            report_export: true,
            rollback: true,
            consumer_repair: false,
            enterprise_repair: false,
            fleet_sync: false,
            cached_policy: false,
            audit_upload: false,
            updates: false,
            enterprise_providers: false,
        }
    }

    const fn licensed(capabilities: LicensedCapabilities) -> Self {
        Self {
            entitlement_state: FleetEntitlementState::Licensed(capabilities.state),
            diagnostics: true,
            report_export: true,
            rollback: true,
            consumer_repair: capabilities.consumer_repair,
            enterprise_repair: capabilities.enterprise_repair,
            fleet_sync: capabilities.fleet_sync,
            cached_policy: capabilities.cached_policy,
            audit_upload: capabilities.audit_upload,
            updates: capabilities.updates,
            enterprise_providers: capabilities.enterprise_providers,
        }
    }
}

impl PendingInventory {
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; SHA256_BYTES] {
        &self.payload_sha256
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

impl fmt::Debug for PendingInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingInventory")
            .field("id", &self.id)
            .field("sequence", &self.sequence)
            .field("payload_len", &self.payload.len())
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// Sanitized runtime errors. Payloads, target fingerprints, and paths are not
/// included in display text.
#[derive(Debug)]
pub enum FleetRuntimeError {
    InvalidPath,
    SymlinkRejected,
    InsecurePermissions,
    UnsupportedFormat,
    IdentityMismatch,
    TenantMismatch,
    QueueFull,
    InvalidBatch,
    InvalidClock,
    StaleAcknowledgement,
    SequenceExhausted,
    Signing,
    TrustAnchorRequired,
    Entitlement(EntitlementError),
    Database(rusqlite::Error),
    Io(io::Error),
}

impl fmt::Display for FleetRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "invalid Fleet runtime database path",
            Self::SymlinkRejected => "Fleet runtime database links are not allowed",
            Self::InsecurePermissions => "Fleet runtime database permissions are too broad",
            Self::UnsupportedFormat => "unsupported Fleet runtime database format",
            Self::IdentityMismatch => "Fleet runtime device identity does not match",
            Self::TenantMismatch => "Fleet runtime tenant does not match",
            Self::QueueFull => "Fleet runtime queue is full",
            Self::InvalidBatch => "invalid Fleet runtime batch",
            Self::InvalidClock => "invalid Fleet runtime clock value",
            Self::StaleAcknowledgement => "Fleet runtime acknowledgement is stale",
            Self::SequenceExhausted => "Fleet inventory sequence is exhausted",
            Self::Signing => "Fleet inventory signing failed",
            Self::TrustAnchorRequired => "Fleet entitlement trust anchor is required",
            Self::Entitlement(_) => "Fleet entitlement verification failed",
            Self::Database(_) => "Fleet runtime database operation failed",
            Self::Io(_) => "Fleet runtime filesystem operation failed",
        })
    }
}

impl Error for FleetRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Entitlement(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for FleetRuntimeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<io::Error> for FleetRuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<EntitlementError> for FleetRuntimeError {
    fn from(error: EntitlementError) -> Self {
        Self::Entitlement(error)
    }
}

/// SQLite-backed inventory queue bound to exactly one tenant and device.
///
/// One product-level interprocess lock must cover each instance's lifetime.
pub struct FleetRuntime {
    connection: Connection,
    path: PathBuf,
    tenant_id: String,
    device_id: String,
    entitlement_trust_anchor: Option<[u8; 32]>,
}

impl FleetRuntime {
    /// Open or initialize state for the supplied enrolled identity.
    pub fn open(
        path: &Path,
        tenant_id: &str,
        identity: &DeviceIdentity,
    ) -> Result<Self, FleetRuntimeError> {
        Self::open_internal(path, tenant_id, identity, None)
    }

    /// Open state with an externally pinned vendor entitlement trust anchor.
    /// The public anchor remains process memory only and is never persisted.
    pub fn open_with_entitlement_anchor(
        path: &Path,
        tenant_id: &str,
        identity: &DeviceIdentity,
        entitlement_trust_anchor: &[u8; 32],
    ) -> Result<Self, FleetRuntimeError> {
        Self::open_internal(path, tenant_id, identity, Some(*entitlement_trust_anchor))
    }

    fn open_internal(
        path: &Path,
        tenant_id: &str,
        identity: &DeviceIdentity,
        entitlement_trust_anchor: Option<[u8; 32]>,
    ) -> Result<Self, FleetRuntimeError> {
        validate_public_identifier(tenant_id)?;
        let device_id = identity.device_id();
        prepare_database_path(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
        harden_database_files(path)?;
        initialize_or_validate(&connection, tenant_id, &device_id)?;
        harden_database_files(path)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            tenant_id: tenant_id.to_owned(),
            device_id,
            entitlement_trust_anchor,
        })
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Verify and atomically retain a canonical signed entitlement. The
    /// retained checkpoint rejects lower sequences and conflicting replays.
    pub fn apply_entitlement(
        &mut self,
        document: &[u8],
    ) -> Result<EntitlementApplyResult, FleetRuntimeError> {
        self.ensure_hardened()?;
        let trust_anchor = self
            .entitlement_trust_anchor
            .ok_or(FleetRuntimeError::TrustAnchorRequired)?;
        let tenant_id = self.tenant_id.clone();
        let device_id = self.device_id.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retained = read_entitlement_checkpoint(&transaction)?;
        let verified = verify_entitlement(document, &trust_anchor, retained.as_ref())?;
        validate_entitlement_binding(&verified, &tenant_id, &device_id)?;
        let idempotent = retained.as_ref().is_some_and(|checkpoint| {
            checkpoint.highest_sequence == verified.checkpoint.highest_sequence
                && checkpoint.envelope_sha256 == verified.checkpoint.envelope_sha256
        });
        transaction.execute(
            "INSERT INTO fleet_entitlement_state
             (singleton, document, entitlement_id, tenant_id, highest_sequence,
              envelope_sha256)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
               document = excluded.document,
               entitlement_id = excluded.entitlement_id,
               tenant_id = excluded.tenant_id,
               highest_sequence = excluded.highest_sequence,
               envelope_sha256 = excluded.envelope_sha256",
            params![
                document,
                verified.checkpoint.entitlement_id,
                verified.checkpoint.tenant_id,
                verified.checkpoint.highest_sequence,
                verified.checkpoint.envelope_sha256,
            ],
        )?;
        transaction.commit()?;
        self.ensure_hardened()?;
        Ok(EntitlementApplyResult { idempotent })
    }

    /// Load and re-verify the retained entitlement against the external trust
    /// anchor and the database's monotonic checkpoint.
    pub fn load_entitlement(&self) -> Result<Option<VerifiedEntitlement>, FleetRuntimeError> {
        self.ensure_hardened()?;
        let trust_anchor = self
            .entitlement_trust_anchor
            .ok_or(FleetRuntimeError::TrustAnchorRequired)?;
        let Some(stored) = read_entitlement_document(&self.connection)? else {
            return Ok(None);
        };
        let verified =
            verify_entitlement(&stored.document, &trust_anchor, Some(&stored.checkpoint))?;
        validate_entitlement_binding(&verified, &self.tenant_id, &self.device_id)?;
        Ok(Some(verified))
    }

    /// Verify and atomically retain the signed global revocation list. Its
    /// checkpoint remains independent of the active entitlement revision.
    pub fn apply_revocations(
        &mut self,
        document: &[u8],
    ) -> Result<EntitlementApplyResult, FleetRuntimeError> {
        self.ensure_hardened()?;
        let trust_anchor = self
            .entitlement_trust_anchor
            .ok_or(FleetRuntimeError::TrustAnchorRequired)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retained = read_revocation_checkpoint(&transaction)?;
        let verified = verify_revocations(document, &trust_anchor, retained.as_ref())?;
        let idempotent = retained.as_ref().is_some_and(|checkpoint| {
            checkpoint.highest_sequence == verified.checkpoint.highest_sequence
                && checkpoint.envelope_sha256 == verified.checkpoint.envelope_sha256
        });
        transaction.execute(
            "INSERT INTO fleet_revocation_state
             (singleton, document, highest_sequence, envelope_sha256)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
               document = excluded.document,
               highest_sequence = excluded.highest_sequence,
               envelope_sha256 = excluded.envelope_sha256",
            params![
                document,
                verified.checkpoint.highest_sequence,
                verified.checkpoint.envelope_sha256,
            ],
        )?;
        transaction.commit()?;
        self.ensure_hardened()?;
        Ok(EntitlementApplyResult { idempotent })
    }

    /// Load and re-verify the retained revocation list.
    pub fn load_revocations(&self) -> Result<Option<VerifiedRevocations>, FleetRuntimeError> {
        self.ensure_hardened()?;
        let trust_anchor = self
            .entitlement_trust_anchor
            .ok_or(FleetRuntimeError::TrustAnchorRequired)?;
        let Some(stored) = read_revocation_document(&self.connection)? else {
            return Ok(None);
        };
        Ok(Some(verify_revocations(
            &stored.document,
            &trust_anchor,
            Some(&stored.checkpoint),
        )?))
    }

    /// Resolve current capabilities without allowing licensing state to block
    /// diagnostics, report export, or an already-started rollback. Any missing
    /// trust anchor, document, invalid clock, signature, checkpoint, binding,
    /// or database content fails paid capabilities closed.
    #[must_use]
    pub fn capabilities(&self, now_unix: u64) -> FleetCapabilities {
        if self.entitlement_trust_anchor.is_none() {
            return FleetCapabilities::safe_degraded(FleetEntitlementState::TrustAnchorUnavailable);
        }
        if now_unix > kernaid_fleet_client::MAX_SAFE_JSON_INTEGER {
            return FleetCapabilities::safe_degraded(FleetEntitlementState::InvalidClock);
        }
        let entitlement = match self.load_entitlement() {
            Ok(Some(entitlement)) => entitlement,
            Ok(None) => {
                return FleetCapabilities::safe_degraded(FleetEntitlementState::Absent);
            }
            Err(_) => {
                return FleetCapabilities::safe_degraded(FleetEntitlementState::Corrupt);
            }
        };
        let revocations = match self.load_revocations() {
            Ok(revocations) => revocations,
            Err(_) => {
                return FleetCapabilities::safe_degraded(FleetEntitlementState::Corrupt);
            }
        };
        FleetCapabilities::licensed(licensed_capabilities(
            &entitlement,
            revocations.as_ref(),
            &self.device_id,
            now_unix,
        ))
    }

    /// Sign and durably queue one canonical envelope per asset in one SQLite
    /// transaction. Sequence allocation rolls back with any failed enqueue.
    pub fn queue_inventory(
        &mut self,
        identity: &DeviceIdentity,
        observed_at: &str,
        assets: Vec<InventoryAsset>,
    ) -> Result<Vec<u64>, FleetRuntimeError> {
        self.ensure_hardened()?;
        if identity.device_id() != self.device_id
            || assets.is_empty()
            || assets.len() > MAX_INVENTORY_BATCH_ASSETS
        {
            return Err(
                if assets.is_empty() || assets.len() > MAX_INVENTORY_BATCH_ASSETS {
                    FleetRuntimeError::InvalidBatch
                } else {
                    FleetRuntimeError::IdentityMismatch
                },
            );
        }

        let count = u64::try_from(assets.len()).map_err(|_| FleetRuntimeError::InvalidBatch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let queued: u64 =
            transaction.query_row("SELECT COUNT(*) FROM fleet_inventory_outbox", [], |row| {
                row.get(0)
            })?;
        if queued
            .checked_add(count)
            .is_none_or(|next| next > MAX_QUEUE_ITEMS)
        {
            return Err(FleetRuntimeError::QueueFull);
        }

        let first_sequence: u64 = transaction.query_row(
            "SELECT next_inventory_sequence FROM fleet_runtime_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let next_sequence = first_sequence
            .checked_add(count)
            .ok_or(FleetRuntimeError::SequenceExhausted)?;
        if next_sequence > kernaid_fleet_client::MAX_SAFE_JSON_INTEGER + 1 {
            return Err(FleetRuntimeError::SequenceExhausted);
        }

        let envelopes = sign_inventory_batch(
            identity,
            self.tenant_id.clone(),
            first_sequence,
            observed_at.to_owned(),
            assets,
        )
        .map_err(|_| FleetRuntimeError::Signing)?;

        let mut ids = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            let payload = envelope
                .export_offline()
                .map_err(|_| FleetRuntimeError::Signing)?;
            if payload.is_empty() || payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
                return Err(FleetRuntimeError::Signing);
            }
            let digest: [u8; SHA256_BYTES] = Sha256::digest(&payload).into();
            transaction.execute(
                "INSERT INTO fleet_inventory_outbox
                 (sequence, payload, payload_sha256, attempts, not_before_epoch)
                 VALUES (?1, ?2, ?3, 0, 0)",
                params![envelope.sequence(), payload, digest.as_slice()],
            )?;
            let id = u64::try_from(transaction.last_insert_rowid())
                .map_err(|_| FleetRuntimeError::UnsupportedFormat)?;
            ids.push(id);
        }
        transaction.execute(
            "UPDATE fleet_runtime_identity
             SET next_inventory_sequence = ?1
             WHERE singleton = 1",
            [next_sequence],
        )?;
        transaction.commit()?;
        Ok(ids)
    }

    /// Read a bounded delivery batch without changing retry state.
    pub fn ready_inventory(
        &mut self,
        now_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<PendingInventory>, FleetRuntimeError> {
        self.ensure_hardened()?;
        if now_epoch_seconds > i64::MAX as u64 || limit == 0 || limit > MAX_BATCH_ITEMS {
            return Err(FleetRuntimeError::InvalidBatch);
        }
        let mut statement = self.connection.prepare(
            "SELECT id, sequence, payload, payload_sha256, attempts
             FROM fleet_inventory_outbox
             WHERE not_before_epoch <= ?1
             ORDER BY sequence ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![
                now_epoch_seconds,
                u64::try_from(limit).map_err(|_| FleetRuntimeError::InvalidBatch)?
            ],
            decode_pending,
        )?;
        let mut pending = Vec::with_capacity(limit);
        for row in rows {
            pending.push(row?);
        }
        Ok(pending)
    }

    /// Remove only the exact row previously delivered. The digest prevents a
    /// stale worker from acknowledging a reused or changed row.
    pub fn acknowledge(
        &mut self,
        id: u64,
        payload_sha256: &[u8; SHA256_BYTES],
    ) -> Result<(), FleetRuntimeError> {
        self.ensure_hardened()?;
        let changed = self.connection.execute(
            "DELETE FROM fleet_inventory_outbox WHERE id = ?1 AND payload_sha256 = ?2",
            params![id, payload_sha256.as_slice()],
        )?;
        if changed != 1 {
            return Err(FleetRuntimeError::StaleAcknowledgement);
        }
        Ok(())
    }

    /// Record one transient transport failure and delay the exact row. The
    /// server decides neither queue paths nor transport credentials.
    pub fn record_retry(
        &mut self,
        id: u64,
        payload_sha256: &[u8; SHA256_BYTES],
        now_epoch_seconds: u64,
        retry_delay_seconds: u64,
    ) -> Result<(), FleetRuntimeError> {
        self.ensure_hardened()?;
        if now_epoch_seconds > i64::MAX as u64
            || retry_delay_seconds == 0
            || retry_delay_seconds > MAX_RETRY_DELAY_SECONDS
        {
            return Err(FleetRuntimeError::InvalidClock);
        }
        let not_before = now_epoch_seconds
            .checked_add(retry_delay_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(FleetRuntimeError::InvalidClock)?;
        let changed = self.connection.execute(
            "UPDATE fleet_inventory_outbox
             SET attempts = attempts + 1, not_before_epoch = ?3
             WHERE id = ?1 AND payload_sha256 = ?2 AND attempts < ?4",
            params![id, payload_sha256.as_slice(), not_before, MAX_ATTEMPTS],
        )?;
        if changed != 1 {
            return Err(FleetRuntimeError::StaleAcknowledgement);
        }
        Ok(())
    }

    pub fn pending_count(&self) -> Result<u64, FleetRuntimeError> {
        Ok(self
            .connection
            .query_row("SELECT COUNT(*) FROM fleet_inventory_outbox", [], |row| {
                row.get(0)
            })?)
    }

    fn ensure_hardened(&self) -> Result<(), FleetRuntimeError> {
        inspect_existing_file(&self.path)?;
        harden_database_files(&self.path)
    }
}

fn decode_pending(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingInventory> {
    let id: u64 = row.get(0)?;
    let sequence: u64 = row.get(1)?;
    let payload: Vec<u8> = row.get(2)?;
    let digest: Vec<u8> = row.get(3)?;
    let attempts: u32 = row.get(4)?;
    if payload.is_empty()
        || payload.len() > MAX_SIGNED_PAYLOAD_BYTES
        || digest.len() != SHA256_BYTES
        || attempts > MAX_ATTEMPTS
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let payload_sha256: [u8; SHA256_BYTES] = digest
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if <[u8; SHA256_BYTES]>::from(Sha256::digest(&payload)) != payload_sha256 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(PendingInventory {
        id,
        sequence,
        payload,
        payload_sha256,
        attempts,
    })
}

struct StoredEntitlementDocument {
    document: Vec<u8>,
    checkpoint: EntitlementCheckpoint,
}

struct StoredRevocationDocument {
    document: Vec<u8>,
    checkpoint: RevocationCheckpoint,
}

fn read_entitlement_checkpoint(
    connection: &Connection,
) -> Result<Option<EntitlementCheckpoint>, FleetRuntimeError> {
    Ok(read_entitlement_document(connection)?.map(|stored| stored.checkpoint))
}

fn read_entitlement_document(
    connection: &Connection,
) -> Result<Option<StoredEntitlementDocument>, FleetRuntimeError> {
    let stored: Option<(Vec<u8>, String, String, u64, String)> = connection
        .query_row(
            "SELECT document, entitlement_id, tenant_id, highest_sequence,
                    envelope_sha256
             FROM fleet_entitlement_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((document, entitlement_id, tenant_id, highest_sequence, envelope_sha256)) = stored
    else {
        return Ok(None);
    };
    if document.is_empty()
        || document.len() > MAX_ENTITLEMENT_DOCUMENT_BYTES
        || !valid_entitlement_identifier(&entitlement_id)
        || !valid_entitlement_identifier(&tenant_id)
        || highest_sequence == 0
        || highest_sequence > kernaid_fleet_client::MAX_SAFE_JSON_INTEGER
        || !valid_sha256(&envelope_sha256)
    {
        return Err(FleetRuntimeError::UnsupportedFormat);
    }
    Ok(Some(StoredEntitlementDocument {
        document,
        checkpoint: EntitlementCheckpoint {
            entitlement_id,
            tenant_id,
            highest_sequence,
            envelope_sha256,
        },
    }))
}

fn read_revocation_checkpoint(
    connection: &Connection,
) -> Result<Option<RevocationCheckpoint>, FleetRuntimeError> {
    Ok(read_revocation_document(connection)?.map(|stored| stored.checkpoint))
}

fn read_revocation_document(
    connection: &Connection,
) -> Result<Option<StoredRevocationDocument>, FleetRuntimeError> {
    let stored: Option<(Vec<u8>, u64, String)> = connection
        .query_row(
            "SELECT document, highest_sequence, envelope_sha256
             FROM fleet_revocation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((document, highest_sequence, envelope_sha256)) = stored else {
        return Ok(None);
    };
    if document.is_empty()
        || document.len() > MAX_ENTITLEMENT_DOCUMENT_BYTES
        || highest_sequence == 0
        || highest_sequence > kernaid_fleet_client::MAX_SAFE_JSON_INTEGER
        || !valid_sha256(&envelope_sha256)
    {
        return Err(FleetRuntimeError::UnsupportedFormat);
    }
    Ok(Some(StoredRevocationDocument {
        document,
        checkpoint: RevocationCheckpoint {
            highest_sequence,
            envelope_sha256,
        },
    }))
}

fn validate_entitlement_binding(
    entitlement: &VerifiedEntitlement,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), FleetRuntimeError> {
    let claims = &entitlement.envelope.claims;
    if claims.tenant_id != tenant_id {
        return Err(FleetRuntimeError::TenantMismatch);
    }
    if claims
        .device_ids
        .binary_search_by(|candidate| candidate.as_str().cmp(device_id))
        .is_err()
    {
        return Err(FleetRuntimeError::IdentityMismatch);
    }
    Ok(())
}

fn valid_entitlement_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn initialize_or_validate(
    connection: &Connection,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), FleetRuntimeError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if application_id == 0 && user_version == 0 {
        let existing_objects: u64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if existing_objects != 0 {
            return Err(FleetRuntimeError::UnsupportedFormat);
        }
        connection.execute_batch(
            "BEGIN IMMEDIATE;
         PRAGMA application_id=1262569036;
         PRAGMA user_version=2;
         CREATE TABLE fleet_runtime_identity (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           schema_version INTEGER NOT NULL CHECK(schema_version = 1),
           tenant_id TEXT NOT NULL,
           device_id TEXT NOT NULL,
           next_inventory_sequence INTEGER NOT NULL CHECK(next_inventory_sequence >= 1)
         );
         CREATE TABLE fleet_inventory_outbox (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           sequence INTEGER NOT NULL UNIQUE CHECK(sequence >= 1),
           payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 32768),
           payload_sha256 BLOB NOT NULL UNIQUE CHECK(length(payload_sha256) = 32),
           attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 1000000),
           not_before_epoch INTEGER NOT NULL CHECK(not_before_epoch >= 0)
         );
         CREATE TABLE fleet_entitlement_state (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           document BLOB NOT NULL CHECK(length(document) BETWEEN 1 AND 65536),
           entitlement_id TEXT NOT NULL,
           tenant_id TEXT NOT NULL,
           highest_sequence INTEGER NOT NULL CHECK(highest_sequence BETWEEN 1 AND 9007199254740991),
           envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64)
         );
         CREATE TABLE fleet_revocation_state (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           document BLOB NOT NULL CHECK(length(document) BETWEEN 1 AND 65536),
           highest_sequence INTEGER NOT NULL CHECK(highest_sequence BETWEEN 1 AND 9007199254740991),
           envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64)
         );
         COMMIT;",
        )?;
    } else if application_id != APPLICATION_ID {
        return Err(FleetRuntimeError::UnsupportedFormat);
    } else if user_version == 1 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE fleet_entitlement_state (
               singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
               document BLOB NOT NULL CHECK(length(document) BETWEEN 1 AND 65536),
               entitlement_id TEXT NOT NULL,
               tenant_id TEXT NOT NULL,
               highest_sequence INTEGER NOT NULL CHECK(highest_sequence BETWEEN 1 AND 9007199254740991),
               envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64)
             );
             CREATE TABLE fleet_revocation_state (
               singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
               document BLOB NOT NULL CHECK(length(document) BETWEEN 1 AND 65536),
               highest_sequence INTEGER NOT NULL CHECK(highest_sequence BETWEEN 1 AND 9007199254740991),
               envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64)
             );
             PRAGMA user_version=2;
             COMMIT;",
        )?;
    } else if user_version != SCHEMA_VERSION {
        return Err(FleetRuntimeError::UnsupportedFormat);
    }
    let existing: Option<(i64, String, String)> = connection
        .query_row(
            "SELECT schema_version, tenant_id, device_id
             FROM fleet_runtime_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match existing {
        None => {
            connection.execute(
                "INSERT INTO fleet_runtime_identity
                 (singleton, schema_version, tenant_id, device_id, next_inventory_sequence)
                 VALUES (1, ?1, ?2, ?3, 1)",
                params![IDENTITY_SCHEMA_VERSION, tenant_id, device_id],
            )?;
        }
        Some((version, stored_tenant, stored_device)) => {
            if version != IDENTITY_SCHEMA_VERSION {
                return Err(FleetRuntimeError::UnsupportedFormat);
            }
            if stored_tenant != tenant_id {
                return Err(FleetRuntimeError::TenantMismatch);
            }
            if stored_device != device_id {
                return Err(FleetRuntimeError::IdentityMismatch);
            }
        }
    }
    validate_schema_shape(connection)
}

fn validate_schema_shape(connection: &Connection) -> Result<(), FleetRuntimeError> {
    let identity_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM fleet_runtime_identity", [], |row| {
            row.get(0)
        })?;
    let queue_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM fleet_inventory_outbox", [], |row| {
            row.get(0)
        })?;
    let entitlement_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM fleet_entitlement_state", [], |row| {
            row.get(0)
        })?;
    let revocation_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM fleet_revocation_state", [], |row| {
            row.get(0)
        })?;
    if identity_rows != 1
        || queue_rows > MAX_QUEUE_ITEMS
        || entitlement_rows > 1
        || revocation_rows > 1
    {
        return Err(FleetRuntimeError::UnsupportedFormat);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), FleetRuntimeError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA secure_delete=ON;
         PRAGMA temp_store=MEMORY;
         PRAGMA trusted_schema=OFF;",
    )?;
    Ok(())
}

fn validate_public_identifier(value: &str) -> Result<(), FleetRuntimeError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(FleetRuntimeError::TenantMismatch);
    }
    Ok(())
}

fn prepare_database_path(path: &Path) -> Result<(), FleetRuntimeError> {
    validate_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => inspect_existing_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(path).map(drop)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_parent(path: &Path) -> Result<(), FleetRuntimeError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    reject_link_like(&metadata)?;
    if !metadata.is_dir() {
        return Err(FleetRuntimeError::InvalidPath);
    }
    Ok(())
}

fn inspect_existing_file(path: &Path) -> Result<(), FleetRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    reject_link_like(&metadata)?;
    if !metadata.is_file() {
        return Err(FleetRuntimeError::InvalidPath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(FleetRuntimeError::InsecurePermissions);
    }
    Ok(())
}

fn harden_database_files(path: &Path) -> Result<(), FleetRuntimeError> {
    inspect_existing_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => {
                reject_link_like(&metadata)?;
                if !metadata.is_file() {
                    return Err(FleetRuntimeError::InvalidPath);
                }
                #[cfg(unix)]
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(FleetRuntimeError::InsecurePermissions);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_link_like(metadata: &fs::Metadata) -> Result<(), FleetRuntimeError> {
    if metadata.file_type().is_symlink() {
        return Err(FleetRuntimeError::SymlinkRejected);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(FleetRuntimeError::SymlinkRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kernaid_entitlements::{
        ENTITLEMENT_SCHEMA, EntitlementClaims, EntitlementLimits, Feature, Plan,
        REVOCATIONS_SCHEMA, RevocationClaims, sign_entitlement, sign_revocations,
    };
    use kernaid_fleet_client::{AssetArchitecture, AssetHealth, AssetPlatform, FindingCounts};
    use rand_core::OsRng;
    use tempfile::tempdir;

    fn asset(id: &str) -> InventoryAsset {
        InventoryAsset::new(
            id,
            "ab".repeat(32),
            AssetPlatform::Linux,
            AssetArchitecture::X86_64,
            Some("Debian 13".to_owned()),
            AssetHealth::Healthy,
            FindingCounts::new(0, 0, 2),
            "cd".repeat(32),
        )
    }

    fn entitlement_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn entitlement_claims(tenant_id: &str, device_id: &str, sequence: u64) -> EntitlementClaims {
        EntitlementClaims {
            schema: ENTITLEMENT_SCHEMA.to_owned(),
            entitlement_id: "ent_runtime_001".to_owned(),
            tenant_id: tenant_id.to_owned(),
            sequence,
            plan: Plan::Enterprise,
            features: vec![
                Feature::Audit,
                Feature::EnterpriseRepair,
                Feature::Fleet,
                Feature::Policy,
                Feature::Updates,
            ],
            device_ids: vec![device_id.to_owned()],
            limits: EntitlementLimits {
                max_tool_devices: 4,
                max_technicians: 8,
                max_managed_assets: 1_000,
            },
            issued_at_unix: 1_000,
            not_before_unix: 1_000,
            offline_lease_until_unix: 2_000,
            expires_at_unix: 3_000,
            grace_until_unix: 4_000,
        }
    }

    fn entitlement_document(
        key: &SigningKey,
        tenant_id: &str,
        device_id: &str,
        sequence: u64,
    ) -> Vec<u8> {
        sign_entitlement(entitlement_claims(tenant_id, device_id, sequence), key)
            .expect("sign entitlement fixture")
    }

    fn revocation_document(
        key: &SigningKey,
        sequence: u64,
        revoked_entitlement_ids: Vec<String>,
    ) -> Vec<u8> {
        sign_revocations(
            RevocationClaims {
                schema: REVOCATIONS_SCHEMA.to_owned(),
                sequence,
                issued_at_unix: 1_500,
                revoked_entitlement_ids,
            },
            key,
        )
        .expect("sign revocation fixture")
    }

    fn assert_only_safety_capabilities(capabilities: FleetCapabilities) {
        assert!(capabilities.diagnostics);
        assert!(capabilities.report_export);
        assert!(capabilities.rollback);
        assert!(!capabilities.consumer_repair);
        assert!(!capabilities.enterprise_repair);
        assert!(!capabilities.fleet_sync);
        assert!(!capabilities.cached_policy);
        assert!(!capabilities.audit_upload);
        assert!(!capabilities.updates);
        assert!(!capabilities.enterprise_providers);
    }

    #[test]
    fn queue_survives_reopen_and_acknowledges_exact_payload() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity");
        let mut runtime =
            FleetRuntime::open(&path, "tenant-alpha", &identity).expect("open runtime");
        let ids = runtime
            .queue_inventory(
                &identity,
                "2026-08-31T17:00:00Z",
                vec![asset("asset-a"), asset("asset-b")],
            )
            .expect("queue inventory");
        assert_eq!(ids.len(), 2);
        drop(runtime);

        let mut reopened =
            FleetRuntime::open(&path, "tenant-alpha", &identity).expect("reopen runtime");
        let pending = reopened.ready_inventory(1, 10).expect("ready inventory");
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].sequence(), 1);
        assert_eq!(pending[1].sequence(), 2);
        reopened
            .acknowledge(pending[0].id(), pending[0].payload_sha256())
            .expect("acknowledge exact payload");
        assert_eq!(reopened.pending_count().expect("pending count"), 1);
        assert!(matches!(
            reopened.acknowledge(pending[0].id(), pending[0].payload_sha256()),
            Err(FleetRuntimeError::StaleAcknowledgement)
        ));
    }

    #[test]
    fn retries_are_bounded_and_tenant_identity_are_pinned() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::from_seed(&[0x11; 32]).expect("fixed identity");
        let other = DeviceIdentity::from_seed(&[0x22; 32]).expect("other identity");
        let mut runtime =
            FleetRuntime::open(&path, "tenant-alpha", &identity).expect("open runtime");
        runtime
            .queue_inventory(&identity, "2026-08-31T17:00:00Z", vec![asset("asset-a")])
            .expect("queue inventory");
        let pending = runtime
            .ready_inventory(100, 1)
            .expect("ready inventory")
            .remove(0);
        runtime
            .record_retry(pending.id(), pending.payload_sha256(), 100, 60)
            .expect("record retry");
        assert!(
            runtime
                .ready_inventory(159, 1)
                .expect("not ready")
                .is_empty()
        );
        assert_eq!(
            runtime.ready_inventory(160, 1).expect("ready after delay")[0].attempts(),
            1
        );
        drop(runtime);

        assert!(matches!(
            FleetRuntime::open(&path, "tenant-beta", &identity),
            Err(FleetRuntimeError::TenantMismatch)
        ));
        assert!(matches!(
            FleetRuntime::open(&path, "tenant-alpha", &other),
            Err(FleetRuntimeError::IdentityMismatch)
        ));
    }

    #[test]
    fn v1_state_migrates_and_entitlement_survives_reopen() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::generate();
        let mut legacy =
            FleetRuntime::open(&path, "tenant-alpha", &identity).expect("create runtime");
        legacy
            .queue_inventory(&identity, "2026-08-31T17:00:00Z", vec![asset("asset-a")])
            .expect("retain legacy queue data");
        drop(legacy);

        let connection = Connection::open(&path).expect("open legacy fixture");
        connection
            .execute_batch(
                "DROP TABLE fleet_entitlement_state;
                 DROP TABLE fleet_revocation_state;
                 PRAGMA user_version=1;",
            )
            .expect("restore v1 schema shape");
        drop(connection);

        let key = entitlement_key();
        let anchor = key.verifying_key().to_bytes();
        let document = entitlement_document(&key, "tenant-alpha", &identity.device_id(), 1);
        let mut runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("migrate runtime");
        assert_eq!(runtime.pending_count().expect("legacy queue count"), 1);
        assert!(
            !runtime
                .apply_entitlement(&document)
                .expect("apply entitlement")
                .idempotent()
        );
        assert_eq!(
            runtime.capabilities(1_500).entitlement_state,
            FleetEntitlementState::Licensed(EntitlementState::Active)
        );
        assert!(runtime.capabilities(1_500).enterprise_repair);
        drop(runtime);

        let mut reopened =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("reopen migrated runtime");
        assert_eq!(
            reopened
                .load_entitlement()
                .expect("load entitlement")
                .expect("stored entitlement")
                .checkpoint
                .highest_sequence,
            1
        );
        assert!(
            reopened
                .apply_entitlement(&document)
                .expect("exact replay")
                .idempotent()
        );
    }

    #[test]
    fn revocation_persists_and_disables_every_paid_capability() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::generate();
        let key = entitlement_key();
        let anchor = key.verifying_key().to_bytes();
        let mut runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("open runtime");
        runtime
            .apply_entitlement(&entitlement_document(
                &key,
                "tenant-alpha",
                &identity.device_id(),
                1,
            ))
            .expect("apply entitlement");
        let revocations = revocation_document(&key, 7, vec!["ent_runtime_001".to_owned()]);
        assert!(
            !runtime
                .apply_revocations(&revocations)
                .expect("apply revocation")
                .idempotent()
        );
        assert!(
            runtime
                .apply_revocations(&revocations)
                .expect("replay revocation")
                .idempotent()
        );
        drop(runtime);

        let reopened =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("reopen runtime");
        let capabilities = reopened.capabilities(1_500);
        assert_eq!(
            capabilities.entitlement_state,
            FleetEntitlementState::Licensed(EntitlementState::Revoked)
        );
        assert_only_safety_capabilities(capabilities);
    }

    #[test]
    fn persisted_checkpoints_reject_entitlement_and_revocation_rollback() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::generate();
        let key = entitlement_key();
        let anchor = key.verifying_key().to_bytes();
        let mut runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("open runtime");
        runtime
            .apply_entitlement(&entitlement_document(
                &key,
                "tenant-alpha",
                &identity.device_id(),
                2,
            ))
            .expect("apply sequence two");
        let older = entitlement_document(&key, "tenant-alpha", &identity.device_id(), 1);
        assert!(matches!(
            runtime.apply_entitlement(&older),
            Err(FleetRuntimeError::Entitlement(
                EntitlementError::RollbackDetected
            ))
        ));

        let mut conflict = entitlement_claims("tenant-alpha", &identity.device_id(), 2);
        conflict.grace_until_unix += 1;
        let conflict = sign_entitlement(conflict, &key).expect("sign conflict");
        assert!(matches!(
            runtime.apply_entitlement(&conflict),
            Err(FleetRuntimeError::Entitlement(
                EntitlementError::SequenceConflict
            ))
        ));

        runtime
            .apply_revocations(&revocation_document(&key, 3, vec![]))
            .expect("apply revocation sequence three");
        assert!(matches!(
            runtime.apply_revocations(&revocation_document(&key, 2, vec![])),
            Err(FleetRuntimeError::Entitlement(
                EntitlementError::RollbackDetected
            ))
        ));
    }

    #[test]
    fn entitlement_tenant_and_device_binding_fail_closed() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let key = entitlement_key();
        let anchor = key.verifying_key().to_bytes();
        let mut runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("open runtime");
        assert!(matches!(
            runtime.apply_entitlement(&entitlement_document(
                &key,
                "tenant-beta",
                &identity.device_id(),
                1,
            )),
            Err(FleetRuntimeError::TenantMismatch)
        ));
        assert!(matches!(
            runtime.apply_entitlement(&entitlement_document(
                &key,
                "tenant-alpha",
                &other.device_id(),
                1,
            )),
            Err(FleetRuntimeError::IdentityMismatch)
        ));
        let capabilities = runtime.capabilities(1_500);
        assert_eq!(
            capabilities.entitlement_state,
            FleetEntitlementState::Absent
        );
        assert_only_safety_capabilities(capabilities);
    }

    #[test]
    fn absent_expired_and_corrupt_state_preserve_only_safety_paths() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("fleet.sqlite3");
        let identity = DeviceIdentity::generate();
        let unconfigured =
            FleetRuntime::open(&path, "tenant-alpha", &identity).expect("open unconfigured");
        let capabilities = unconfigured.capabilities(1_500);
        assert_eq!(
            capabilities.entitlement_state,
            FleetEntitlementState::TrustAnchorUnavailable
        );
        assert_only_safety_capabilities(capabilities);
        drop(unconfigured);

        let key = entitlement_key();
        let anchor = key.verifying_key().to_bytes();
        let mut runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("open configured runtime");
        let capabilities = runtime.capabilities(1_500);
        assert_eq!(
            capabilities.entitlement_state,
            FleetEntitlementState::Absent
        );
        assert_only_safety_capabilities(capabilities);
        runtime
            .apply_entitlement(&entitlement_document(
                &key,
                "tenant-alpha",
                &identity.device_id(),
                1,
            ))
            .expect("apply entitlement");
        let expired = runtime.capabilities(4_001);
        assert_eq!(
            expired.entitlement_state,
            FleetEntitlementState::Licensed(EntitlementState::Expired)
        );
        assert_only_safety_capabilities(expired);
        drop(runtime);

        let connection = Connection::open(&path).expect("open corruption fixture");
        connection
            .execute(
                "UPDATE fleet_entitlement_state SET document = ?1 WHERE singleton = 1",
                [b"{}".as_slice()],
            )
            .expect("corrupt retained document");
        drop(connection);
        let runtime =
            FleetRuntime::open_with_entitlement_anchor(&path, "tenant-alpha", &identity, &anchor)
                .expect("reopen corrupt runtime");
        let corrupt = runtime.capabilities(1_500);
        assert_eq!(corrupt.entitlement_state, FleetEntitlementState::Corrupt);
        assert_only_safety_capabilities(corrupt);
        assert_only_safety_capabilities(
            runtime.capabilities(kernaid_fleet_client::MAX_SAFE_JSON_INTEGER + 1),
        );
    }

    #[cfg(unix)]
    #[test]
    fn broad_permissions_and_symlinks_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempdir().expect("temporary directory");
        let identity = DeviceIdentity::from_seed(&[0x33; 32]).expect("fixed identity");
        let path = directory.path().join("fleet.sqlite3");
        let runtime = FleetRuntime::open(&path, "tenant-alpha", &identity).expect("open runtime");
        drop(runtime);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("weaken permissions");
        assert!(matches!(
            FleetRuntime::open(&path, "tenant-alpha", &identity),
            Err(FleetRuntimeError::InsecurePermissions)
        ));

        let target = directory.path().join("target.sqlite3");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .expect("create target");
        let link = directory.path().join("linked.sqlite3");
        symlink(&target, &link).expect("create symlink");
        assert!(matches!(
            FleetRuntime::open(&link, "tenant-alpha", &identity),
            Err(FleetRuntimeError::SymlinkRejected)
        ));
    }
}
