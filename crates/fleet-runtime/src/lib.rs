#![forbid(unsafe_code)]
//! Durable offline-first delivery for signed KernAid Fleet inventory.
//!
//! This crate owns queue state, not transport credentials. Callers keep the
//! device identity in the existing secure store and submit the returned exact
//! bytes over their authenticated transport.

use kernaid_device_identity::DeviceIdentity;
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

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4b41_464c; // "KAFL"
const MAX_QUEUE_ITEMS: u64 = 100_000;
const MAX_BATCH_ITEMS: usize = 256;
const MAX_RETRY_DELAY_SECONDS: u64 = 24 * 60 * 60;
const MAX_ATTEMPTS: u32 = 1_000_000;
const SHA256_BYTES: usize = 32;
const MAX_SIGNED_PAYLOAD_BYTES: usize = 32 * 1024;

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
            Self::Database(_) => "Fleet runtime database operation failed",
            Self::Io(_) => "Fleet runtime filesystem operation failed",
        })
    }
}

impl Error for FleetRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
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

/// SQLite-backed inventory queue bound to exactly one tenant and device.
///
/// One product-level interprocess lock must cover each instance's lifetime.
pub struct FleetRuntime {
    connection: Connection,
    path: PathBuf,
    tenant_id: String,
    device_id: String,
}

impl FleetRuntime {
    /// Open or initialize state for the supplied enrolled identity.
    pub fn open(
        path: &Path,
        tenant_id: &str,
        identity: &DeviceIdentity,
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
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            tenant_id: tenant_id.to_owned(),
            device_id,
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
         PRAGMA user_version=1;
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
         COMMIT;",
        )?;
    } else if application_id != APPLICATION_ID || user_version != SCHEMA_VERSION {
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
                params![SCHEMA_VERSION, tenant_id, device_id],
            )?;
        }
        Some((version, stored_tenant, stored_device)) => {
            if version != SCHEMA_VERSION {
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
    if identity_rows != 1 || queue_rows > MAX_QUEUE_ITEMS {
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
    use kernaid_fleet_client::{AssetArchitecture, AssetHealth, AssetPlatform, FindingCounts};
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
