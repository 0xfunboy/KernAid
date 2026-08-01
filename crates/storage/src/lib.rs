#![forbid(unsafe_code)]
//! Encrypted, append-only SQLite audit journal.
//!
//! SQLite contains only authenticated ciphertext. The encryption key and the
//! last durable journal anchor belong in an operating-system keychain in
//! Resident mode or in the unlocked LUKS2 vault in Rescue mode. This crate
//! deliberately provides no file-backed or plaintext secret-store fallback.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const LEGACY_SCHEMA_VERSION: i64 = 2;
const SCHEMA_VERSION: i64 = 3;
const JOURNAL_ID_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const HASH_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const ZERO_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];
const AAD_DOMAIN: &[u8] = b"KERNAID-SECURE-JOURNAL-AAD-V2\0";
const HASH_DOMAIN: &[u8] = b"KERNAID-SECURE-JOURNAL-ENTRY-V2\0";
const INITIALIZATION_AAD_DOMAIN: &[u8] = b"KERNAID-SECURE-JOURNAL-INIT-AAD-V3\0";
const INITIALIZATION_PLAINTEXT: &[u8] = b"KERNAID-SECURE-JOURNAL-KEY-CHECK-V3\0";
const INITIALIZATION_PENDING: i64 = 0;
const INITIALIZATION_READY: i64 = 1;
const ANCHOR_MAGIC: &[u8; 8] = b"KNAUDV2\0";

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Size of the XChaCha20-Poly1305 key held by a [`JournalSecretStore`].
pub const JOURNAL_KEY_BYTES: usize = 32;
/// Maximum accepted plaintext event size (1 MiB).
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum number of records accepted in one journal.
pub const MAX_JOURNAL_ENTRIES: u64 = 1_000_000;
const MAX_JOURNAL_CIPHERTEXT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_RETURNED_PLAINTEXT_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum record count materialized by [`SecureJournal::entries`].
pub const MAX_RETURNED_ENTRIES: u64 = 10_000;

/// Secret key material returned by a [`JournalSecretStore`].
///
/// The allocation is erased on drop and this type intentionally implements
/// neither `Clone` nor `Debug`. Secret-store implementations may borrow the
/// bytes only long enough to pass them to their native secure-storage API.
pub struct JournalKey(Zeroizing<[u8; JOURNAL_KEY_BYTES]>);

impl JournalKey {
    /// Wrap already-zeroizing key material loaded from secure storage.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; JOURNAL_KEY_BYTES]>) -> Self {
        Self(bytes)
    }

    /// Temporarily expose the key to a secure-storage or crypto backend.
    /// Implementations must never persist these bytes outside secure storage.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; JOURNAL_KEY_BYTES] {
        &self.0
    }

    fn generate() -> Self {
        let mut bytes = Zeroizing::new([0_u8; JOURNAL_KEY_BYTES]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }
}

/// Durable, non-secret checkpoint protected by the secure-store trust boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalAnchor {
    pub journal_id: [u8; JOURNAL_ID_BYTES],
    pub sequence: u64,
    pub entry_hash: [u8; HASH_BYTES],
}

impl JournalAnchor {
    /// Stable size of the versioned binary representation.
    pub const ENCODED_BYTES: usize = 8 + JOURNAL_ID_BYTES + 8 + HASH_BYTES;

    /// Encode an anchor for storage in a keychain value.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::ENCODED_BYTES] {
        let mut encoded = [0_u8; Self::ENCODED_BYTES];
        encoded[..8].copy_from_slice(ANCHOR_MAGIC);
        encoded[8..24].copy_from_slice(&self.journal_id);
        encoded[24..32].copy_from_slice(&self.sequence.to_be_bytes());
        encoded[32..].copy_from_slice(&self.entry_hash);
        encoded
    }

    /// Decode a strictly versioned keychain value.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, AnchorDecodeError> {
        if encoded.len() != Self::ENCODED_BYTES || &encoded[..8] != ANCHOR_MAGIC {
            return Err(AnchorDecodeError);
        }
        let journal_id = encoded[8..24].try_into().map_err(|_| AnchorDecodeError)?;
        let sequence =
            u64::from_be_bytes(encoded[24..32].try_into().map_err(|_| AnchorDecodeError)?);
        let entry_hash = encoded[32..].try_into().map_err(|_| AnchorDecodeError)?;
        Ok(Self {
            journal_id,
            sequence,
            entry_hash,
        })
    }
}

/// Error returned for a malformed versioned anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorDecodeError;

impl fmt::Display for AnchorDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid secure-journal anchor")
    }
}

impl Error for AnchorDecodeError {}

/// Backend error that must not contain key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretStoreError(String);

impl SecretStoreError {
    /// Construct a sanitized backend error. Never include secret values.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SecretStoreError {}

/// Secure persistence required by [`SecureJournal`].
///
/// Implementations are expected to bind both values to the same device and
/// application identity. `load_*` returns `Ok(None)` only when the item truly
/// does not exist; malformed values and unavailable/locked backends are errors.
/// `store_key` must durably create or replace the native secret item before it
/// returns and must never write a plaintext fallback. `store_anchor` must
/// durably and atomically replace the complete anchor value. It is invoked only
/// after the corresponding SQLite commit is durable, so a failed anchor write
/// leaves a recoverable DB-ahead-anchor state. Methods take `&mut self` to
/// support stateful native backends while remaining object-safe.
pub trait JournalSecretStore {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError>;
    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError>;
    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError>;
    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError>;
}

impl<T: JournalSecretStore + ?Sized> JournalSecretStore for Box<T> {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        (**self).load_key()
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        (**self).store_key(key)
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        (**self).load_anchor()
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        (**self).store_anchor(anchor)
    }
}

/// Decrypted record returned only after the complete chain and anchor verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub sequence: u64,
    pub event: Vec<u8>,
    pub previous_hash: [u8; HASH_BYTES],
    pub entry_hash: [u8; HASH_BYTES],
}

#[derive(Debug)]
pub enum JournalError {
    Database(String),
    SecretStore(SecretStoreError),
    InvalidPath,
    SymlinkRejected,
    UnsupportedFormat,
    MissingKey,
    MissingAnchor,
    SecretStateConflict,
    AuthenticationFailed,
    CorruptChain,
    RollbackDetected,
    EventTooLarge,
    JournalTooLarge,
    SequenceOverflow,
    EncryptionFailed,
    ReadLimitExceeded,
    UnexpectedHead {
        expected: JournalAnchor,
        actual: JournalAnchor,
    },
    Poisoned,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(message) => write!(formatter, "journal database error: {message}"),
            Self::SecretStore(error) => write!(formatter, "journal secret-store error: {error}"),
            Self::InvalidPath => formatter.write_str("invalid journal database path"),
            Self::SymlinkRejected => formatter.write_str("journal database symlinks are forbidden"),
            Self::UnsupportedFormat => formatter.write_str("unsupported journal database format"),
            Self::MissingKey => formatter.write_str("journal encryption key is missing"),
            Self::MissingAnchor => formatter.write_str("journal anchor is missing"),
            Self::SecretStateConflict => {
                formatter.write_str("secure state already exists for a new journal")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("journal record authentication failed")
            }
            Self::CorruptChain => formatter.write_str("journal chain is corrupt"),
            Self::RollbackDetected => formatter.write_str("journal rollback was detected"),
            Self::EventTooLarge => formatter.write_str("journal event exceeds the size limit"),
            Self::JournalTooLarge => formatter.write_str("journal exceeds its storage limits"),
            Self::SequenceOverflow => formatter.write_str("journal sequence overflow"),
            Self::EncryptionFailed => formatter.write_str("journal event encryption failed"),
            Self::ReadLimitExceeded => {
                formatter.write_str("decrypted journal read exceeds the memory limit")
            }
            Self::UnexpectedHead { .. } => {
                formatter.write_str("journal head changed before the append")
            }
            Self::Poisoned => {
                formatter.write_str("journal must be reopened after a partial append")
            }
        }
    }
}

impl Error for JournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SecretStore(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for JournalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<SecretStoreError> for JournalError {
    fn from(error: SecretStoreError) -> Self {
        Self::SecretStore(error)
    }
}

/// Encrypted journal coupled to a mandatory native secure store.
///
/// One product-level interprocess lock must cover this value's complete
/// lifetime. SQLite and a separate native secret store cannot jointly provide
/// an atomic cross-process commit for the post-database anchor update.
pub struct SecureJournal<S: JournalSecretStore> {
    connection: Connection,
    secret_store: S,
    cipher: XChaCha20Poly1305,
    journal_id: [u8; JOURNAL_ID_BYTES],
    path: PathBuf,
    trusted_head: JournalAnchor,
    verified_ciphertext_bytes: u64,
    healthy: bool,
}

impl<S: JournalSecretStore> SecureJournal<S> {
    /// Open an existing verified journal or initialize a new one.
    ///
    /// A version-3 database left in its explicit pending state can recover the
    /// narrowly defined crash windows between the durable database creation,
    /// key write, anchor write and final ready marker. A ready database and all
    /// legacy databases still require both secure items and fail closed if
    /// either is absent.
    ///
    /// The caller must hold its product-level interprocess instance lock for
    /// the complete call. SQLite serializes each database phase, but it cannot
    /// atomically serialize two separate native-credential writes with the
    /// database initialization transaction.
    pub fn open(path: &Path, mut secret_store: S) -> Result<Self, JournalError> {
        let path_state = inspect_database_path(path)?;
        if path_state != DatabasePathState::Existing {
            let key = secret_store.load_key()?;
            let anchor = secret_store.load_anchor()?;
            if key.is_some() || anchor.is_some() {
                return Err(JournalError::SecretStateConflict);
            }
            if path_state == DatabasePathState::Missing {
                create_database_file(path)?;
            }
        }

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
        harden_database_files(path)?;

        if path_state != DatabasePathState::Existing || database_is_pristine(&connection)? {
            let key = secret_store.load_key()?;
            let anchor = secret_store.load_anchor()?;
            if key.is_some() || anchor.is_some() {
                return Err(JournalError::SecretStateConflict);
            }
            return initialize_new_journal(connection, secret_store, path);
        }

        let schema = validate_schema(&connection)?;
        let journal_id = load_journal_id(&connection)?;

        if schema == SchemaKind::Recoverable {
            let initialization = load_initialization_record(&connection)?;
            if initialization.state == INITIALIZATION_PENDING {
                return recover_pending_initialization(connection, secret_store, path, journal_id);
            }
            if initialization.state != INITIALIZATION_READY {
                return Err(JournalError::UnsupportedFormat);
            }

            let key = secret_store.load_key()?;
            let anchor = secret_store.load_anchor()?;
            let key = key.ok_or(JournalError::MissingKey)?;
            verify_initialization_key(&key, &journal_id, &initialization)?;
            let cipher = cipher_from_key(&key)?;
            if anchor.is_none() {
                return Err(JournalError::MissingAnchor);
            }
            let mut journal = Self {
                connection,
                secret_store,
                cipher,
                journal_id,
                path: path.to_path_buf(),
                trusted_head: initial_anchor(journal_id),
                verified_ciphertext_bytes: 0,
                healthy: true,
            };
            journal.verify()?;
            return Ok(journal);
        }

        let key = secret_store.load_key()?;
        let anchor = secret_store.load_anchor()?;
        let key = key.ok_or(JournalError::MissingKey)?;
        let cipher = cipher_from_key(&key)?;
        if anchor.is_none() {
            return Err(JournalError::MissingAnchor);
        }
        let mut journal = Self {
            connection,
            secret_store,
            cipher,
            journal_id,
            path: path.to_path_buf(),
            trusted_head: initial_anchor(journal_id),
            verified_ciphertext_bytes: 0,
            healthy: true,
        };
        journal.verify()?;
        Ok(journal)
    }

    /// Append one event and advance the secure anchor after the SQLite commit.
    pub fn append(&mut self, event: &[u8]) -> Result<JournalEntry, JournalError> {
        let expected = self.head()?;
        self.append_expected(expected, event)
    }

    /// Append only if the fully verified journal head still equals `expected`.
    ///
    /// The comparison and append happen under one SQLite immediate transaction,
    /// so callers can safely bind an approval or report to an exact prior head.
    /// A mismatch returns [`JournalError::UnexpectedHead`] without writing a
    /// record or advancing the secure anchor.
    pub fn append_expected(
        &mut self,
        expected: JournalAnchor,
        event: &[u8],
    ) -> Result<JournalEntry, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        if event.len() > MAX_EVENT_BYTES {
            return Err(JournalError::EventTooLarge);
        }
        self.ensure_hardened()?;
        if expected != self.trusted_head {
            return Err(JournalError::UnexpectedHead {
                expected,
                actual: self.trusted_head,
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor = load_required_anchor(&mut self.secret_store)?;
        if anchor.journal_id != self.journal_id {
            return Err(JournalError::RollbackDetected);
        }
        if anchor != expected {
            return Err(JournalError::UnexpectedHead {
                expected,
                actual: anchor,
            });
        }
        validate_expected_head(&transaction, &self.cipher, &self.journal_id, expected)?;

        let sequence = expected
            .sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if sequence > MAX_JOURNAL_ENTRIES {
            return Err(JournalError::JournalTooLarge);
        }

        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let aad = associated_data(&self.journal_id, sequence, &expected.entry_hash);
        let nonce_ref: &XNonce = nonce
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::EncryptionFailed)?;
        let ciphertext = self
            .cipher
            .encrypt(
                nonce_ref,
                Payload {
                    msg: event,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::EncryptionFailed)?;
        let new_ciphertext_bytes = self
            .verified_ciphertext_bytes
            .checked_add(ciphertext.len() as u64)
            .ok_or(JournalError::JournalTooLarge)?;
        if new_ciphertext_bytes > MAX_JOURNAL_CIPHERTEXT_BYTES {
            return Err(JournalError::JournalTooLarge);
        }
        let entry_hash = hash_entry(
            &self.journal_id,
            sequence,
            &expected.entry_hash,
            &nonce,
            &ciphertext,
        );

        transaction.execute(
            "INSERT INTO secure_journal_entries(\
               sequence, nonce, ciphertext, previous_hash, entry_hash\
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sequence,
                nonce.as_slice(),
                ciphertext,
                expected.entry_hash.as_slice(),
                entry_hash.as_slice()
            ],
        )?;
        if let Err(error) = transaction.commit() {
            self.healthy = false;
            return Err(error.into());
        }

        if let Err(error) = harden_database_files(&self.path) {
            self.healthy = false;
            return Err(error);
        }
        let new_anchor = JournalAnchor {
            journal_id: self.journal_id,
            sequence,
            entry_hash,
        };
        if let Err(error) = self.secret_store.store_anchor(&new_anchor) {
            self.healthy = false;
            return Err(error.into());
        }
        self.trusted_head = new_anchor;
        self.verified_ciphertext_bytes = new_ciphertext_bytes;

        Ok(JournalEntry {
            sequence,
            event: event.to_vec(),
            previous_hash: expected.entry_hash,
            entry_hash,
        })
    }

    /// Verify every ciphertext, hash-chain link, sequence and secure anchor.
    ///
    /// If and only if the fully authenticated database is ahead of an anchor
    /// that matches an earlier chain prefix, the anchor is advanced to recover
    /// from a crash between the database commit and secure-store update.
    pub fn verify(&mut self) -> Result<(), JournalError> {
        self.head().map(|_| ())
    }

    /// Return the authenticated journal head without materializing plaintext.
    ///
    /// This performs the same complete verification and safe DB-ahead-anchor
    /// recovery as [`Self::verify`]. The returned anchor is therefore suitable
    /// for binding a signed report to the exact audit-journal state.
    pub fn head(&mut self) -> Result<JournalAnchor, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        self.ensure_hardened()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor = load_required_anchor(&mut self.secret_store)?;
        let scan = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            ScanMode::None,
        )?;
        let anchor_lags = validate_anchor(&anchor, &scan, &self.journal_id)?;
        if anchor_lags {
            let recovered = JournalAnchor {
                journal_id: self.journal_id,
                sequence: scan.head.sequence,
                entry_hash: scan.head.entry_hash,
            };
            if let Err(error) = self.secret_store.store_anchor(&recovered) {
                self.healthy = false;
                return Err(error.into());
            }
        }
        transaction.commit()?;
        let verified_head = JournalAnchor {
            journal_id: self.journal_id,
            sequence: scan.head.sequence,
            entry_hash: scan.head.entry_hash,
        };
        self.trusted_head = verified_head;
        self.verified_ciphertext_bytes = scan.ciphertext_bytes;
        Ok(verified_head)
    }

    /// Return only the first authenticated entry after verifying the complete
    /// chain and secure anchor under one SQLite immediate transaction.
    ///
    /// Later plaintext records are decrypted for authentication and then
    /// discarded immediately; they are never accumulated in memory.
    pub fn first_entry(&mut self) -> Result<Option<JournalEntry>, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        self.ensure_hardened()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor = load_required_anchor(&mut self.secret_store)?;
        let mut scan = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            ScanMode::First,
        )?;
        let anchor_lags = validate_anchor(&anchor, &scan, &self.journal_id)?;
        if anchor_lags {
            let recovered = JournalAnchor {
                journal_id: self.journal_id,
                sequence: scan.head.sequence,
                entry_hash: scan.head.entry_hash,
            };
            if let Err(error) = self.secret_store.store_anchor(&recovered) {
                self.healthy = false;
                return Err(error.into());
            }
        }
        transaction.commit()?;
        self.trusted_head = JournalAnchor {
            journal_id: self.journal_id,
            sequence: scan.head.sequence,
            entry_hash: scan.head.entry_hash,
        };
        self.verified_ciphertext_bytes = scan.ciphertext_bytes;
        Ok(scan.entries.pop())
    }

    /// Return a bounded plaintext snapshot after verification under one SQLite
    /// write lock. Large journals remain verifiable but must not be materialized
    /// wholesale through this convenience API.
    pub fn entries(&mut self) -> Result<Vec<JournalEntry>, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        self.ensure_hardened()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor = load_required_anchor(&mut self.secret_store)?;
        let scan = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            ScanMode::AllBounded,
        )?;
        let anchor_lags = validate_anchor(&anchor, &scan, &self.journal_id)?;
        if anchor_lags {
            let recovered = JournalAnchor {
                journal_id: self.journal_id,
                sequence: scan.head.sequence,
                entry_hash: scan.head.entry_hash,
            };
            if let Err(error) = self.secret_store.store_anchor(&recovered) {
                self.healthy = false;
                return Err(error.into());
            }
        }
        transaction.commit()?;
        self.trusted_head = JournalAnchor {
            journal_id: self.journal_id,
            sequence: scan.head.sequence,
            entry_hash: scan.head.entry_hash,
        };
        self.verified_ciphertext_bytes = scan.ciphertext_bytes;
        Ok(scan.entries)
    }

    fn ensure_hardened(&mut self) -> Result<(), JournalError> {
        if let Err(error) = harden_database_files(&self.path) {
            self.healthy = false;
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaKind {
    Legacy,
    Recoverable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DatabasePathState {
    Missing,
    Empty,
    Existing,
}

struct InitializationRecord {
    state: i64,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

fn initialize_new_journal<S: JournalSecretStore>(
    mut connection: Connection,
    mut secret_store: S,
    path: &Path,
) -> Result<SecureJournal<S>, JournalError> {
    if !database_is_pristine(&connection)? {
        return Err(JournalError::UnsupportedFormat);
    }

    let mut journal_id = [0_u8; JOURNAL_ID_BYTES];
    OsRng.fill_bytes(&mut journal_id);
    let key = JournalKey::generate();
    let cipher = cipher_from_key(&key)?;
    let initialization = create_initialization_record(&key, &journal_id)?;
    initialize_schema(&connection, &journal_id, &initialization)?;
    harden_database_files(path)?;
    maybe_crash_initialization_test("database");

    secret_store.store_key(&key)?;
    maybe_crash_initialization_test("key");
    secret_store.store_anchor(&initial_anchor(journal_id))?;
    maybe_crash_initialization_test("anchor");
    finalize_pending_initialization(&mut connection, &journal_id)?;
    harden_database_files(path)?;
    maybe_crash_initialization_test("ready");

    Ok(SecureJournal {
        connection,
        secret_store,
        cipher,
        journal_id,
        path: path.to_path_buf(),
        trusted_head: initial_anchor(journal_id),
        verified_ciphertext_bytes: 0,
        healthy: true,
    })
}

#[cfg(test)]
fn maybe_crash_initialization_test(boundary: &str) {
    if std::env::var("KERNAID_STORAGE_TEST_CRASH_BOUNDARY").as_deref() == Ok(boundary) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn maybe_crash_initialization_test(_boundary: &str) {}

fn recover_pending_initialization<S: JournalSecretStore>(
    mut connection: Connection,
    mut secret_store: S,
    path: &Path,
    journal_id: [u8; JOURNAL_ID_BYTES],
) -> Result<SecureJournal<S>, JournalError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if validate_schema(&transaction)? != SchemaKind::Recoverable
        || load_journal_id(&transaction)? != journal_id
    {
        return Err(JournalError::UnsupportedFormat);
    }
    let initialization = load_initialization_record(&transaction)?;
    if initialization.state == INITIALIZATION_PENDING {
        if journal_has_entries(&transaction)? {
            return Err(JournalError::SecretStateConflict);
        }
        let key = secret_store.load_key()?;
        let anchor = secret_store.load_anchor()?;
        match (key, anchor) {
            (None, None) => {
                let key = JournalKey::generate();
                let replacement = create_initialization_record(&key, &journal_id)?;
                let changed = transaction.execute(
                    "UPDATE secure_journal_initialization
                     SET nonce = ?1, ciphertext = ?2
                     WHERE singleton = 1 AND state = 0
                       AND NOT EXISTS(SELECT 1 FROM secure_journal_entries)",
                    params![replacement.nonce.as_slice(), replacement.ciphertext],
                )?;
                if changed != 1 {
                    return Err(JournalError::SecretStateConflict);
                }
                transaction.commit()?;
                secret_store.store_key(&key)?;
                secret_store.store_anchor(&initial_anchor(journal_id))?;
            }
            (Some(key), None) => {
                verify_initialization_key(&key, &journal_id, &initialization)?;
                transaction.commit()?;
                secret_store.store_anchor(&initial_anchor(journal_id))?;
            }
            (Some(key), Some(anchor)) => {
                verify_initialization_key(&key, &journal_id, &initialization)?;
                if anchor != initial_anchor(journal_id) {
                    return Err(JournalError::RollbackDetected);
                }
                transaction.commit()?;
            }
            (None, Some(_)) => return Err(JournalError::SecretStateConflict),
        }
    } else if initialization.state == INITIALIZATION_READY {
        transaction.commit()?;
    } else {
        return Err(JournalError::UnsupportedFormat);
    }

    finalize_pending_initialization(&mut connection, &journal_id)?;
    let initialization = load_initialization_record(&connection)?;
    let key = secret_store.load_key()?.ok_or(JournalError::MissingKey)?;
    verify_initialization_key(&key, &journal_id, &initialization)?;
    if secret_store.load_anchor()?.is_none() {
        return Err(JournalError::MissingAnchor);
    }
    let cipher = cipher_from_key(&key)?;
    harden_database_files(path)?;
    let mut journal = SecureJournal {
        connection,
        secret_store,
        cipher,
        journal_id,
        path: path.to_path_buf(),
        trusted_head: initial_anchor(journal_id),
        verified_ciphertext_bytes: 0,
        healthy: true,
    };
    journal.verify()?;
    Ok(journal)
}

fn finalize_pending_initialization(
    connection: &mut Connection,
    journal_id: &[u8; JOURNAL_ID_BYTES],
) -> Result<(), JournalError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if validate_schema(&transaction)? != SchemaKind::Recoverable
        || load_journal_id(&transaction)? != *journal_id
        || journal_has_entries(&transaction)?
    {
        return Err(JournalError::SecretStateConflict);
    }
    let initialization = load_initialization_record(&transaction)?;
    if initialization.state == INITIALIZATION_READY {
        transaction.commit()?;
        return Ok(());
    }
    if initialization.state != INITIALIZATION_PENDING {
        return Err(JournalError::UnsupportedFormat);
    }
    let changed = transaction.execute(
        "UPDATE secure_journal_initialization
         SET state = 1
         WHERE singleton = 1 AND state = 0
           AND NOT EXISTS(SELECT 1 FROM secure_journal_entries)",
        [],
    )?;
    if changed != 1 {
        return Err(JournalError::SecretStateConflict);
    }
    transaction.execute_batch(
        "CREATE TRIGGER secure_journal_initialization_no_update
           BEFORE UPDATE ON secure_journal_initialization
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal initialization'); END;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn initial_anchor(journal_id: [u8; JOURNAL_ID_BYTES]) -> JournalAnchor {
    JournalAnchor {
        journal_id,
        sequence: 0,
        entry_hash: ZERO_HASH,
    }
}

fn database_is_pristine(connection: &Connection) -> Result<bool, JournalError> {
    let object_count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok(object_count == 0 && user_version == 0)
}

fn journal_has_entries(connection: &Connection) -> Result<bool, JournalError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM secure_journal_entries LIMIT 1)",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists != 0)
        .map_err(Into::into)
}

fn initialization_associated_data(journal_id: &[u8; JOURNAL_ID_BYTES]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(INITIALIZATION_AAD_DOMAIN.len() + JOURNAL_ID_BYTES);
    aad.extend_from_slice(INITIALIZATION_AAD_DOMAIN);
    aad.extend_from_slice(journal_id);
    aad
}

fn create_initialization_record(
    key: &JournalKey,
    journal_id: &[u8; JOURNAL_ID_BYTES],
) -> Result<InitializationRecord, JournalError> {
    let cipher = cipher_from_key(key)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ref: &XNonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| JournalError::EncryptionFailed)?;
    let aad = initialization_associated_data(journal_id);
    let ciphertext = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: INITIALIZATION_PLAINTEXT,
                aad: &aad,
            },
        )
        .map_err(|_| JournalError::EncryptionFailed)?;
    Ok(InitializationRecord {
        state: INITIALIZATION_PENDING,
        nonce,
        ciphertext,
    })
}

fn verify_initialization_key(
    key: &JournalKey,
    journal_id: &[u8; JOURNAL_ID_BYTES],
    initialization: &InitializationRecord,
) -> Result<(), JournalError> {
    let cipher = cipher_from_key(key)?;
    let nonce_ref: &XNonce = initialization
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| JournalError::UnsupportedFormat)?;
    let aad = initialization_associated_data(journal_id);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce_ref,
                Payload {
                    msg: &initialization.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::AuthenticationFailed)?,
    );
    if plaintext.as_slice() != INITIALIZATION_PLAINTEXT {
        return Err(JournalError::AuthenticationFailed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ChainHead {
    sequence: u64,
    entry_hash: [u8; HASH_BYTES],
}

struct ChainScan {
    head: ChainHead,
    anchor_prefix_hash: Option<[u8; HASH_BYTES]>,
    ciphertext_bytes: u64,
    entries: Vec<JournalEntry>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    None,
    First,
    AllBounded,
}

fn scan_chain(
    connection: &Connection,
    cipher: &XChaCha20Poly1305,
    journal_id: &[u8; JOURNAL_ID_BYTES],
    anchor_sequence: u64,
    mode: ScanMode,
) -> Result<ChainScan, JournalError> {
    let mut statement = connection.prepare(
        "SELECT sequence, \
                length(nonce), nonce, \
                length(ciphertext), ciphertext, \
                length(previous_hash), previous_hash, \
                length(entry_hash), entry_hash \
         FROM secure_journal_entries ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut expected_sequence = 1_u64;
    let mut expected_previous = ZERO_HASH;
    let mut anchor_prefix_hash = (anchor_sequence == 0).then_some(ZERO_HASH);
    let mut ciphertext_bytes = 0_u64;
    let mut plaintext_bytes = 0_u64;
    let mut entries = Vec::new();

    while let Some(row) = rows.next()? {
        if expected_sequence > MAX_JOURNAL_ENTRIES {
            return Err(JournalError::JournalTooLarge);
        }
        let sequence_raw: i64 = row.get(0)?;
        let sequence = u64::try_from(sequence_raw).map_err(|_| JournalError::CorruptChain)?;
        let nonce_len: i64 = row.get(1)?;
        let ciphertext_len: i64 = row.get(3)?;
        let previous_hash_len: i64 = row.get(5)?;
        let entry_hash_len: i64 = row.get(7)?;
        let max_ciphertext = MAX_EVENT_BYTES
            .checked_add(AEAD_TAG_BYTES)
            .ok_or(JournalError::JournalTooLarge)?;
        if sequence != expected_sequence
            || nonce_len != NONCE_BYTES as i64
            || ciphertext_len < AEAD_TAG_BYTES as i64
            || ciphertext_len > max_ciphertext as i64
            || previous_hash_len != HASH_BYTES as i64
            || entry_hash_len != HASH_BYTES as i64
        {
            return Err(JournalError::CorruptChain);
        }

        let nonce: [u8; NONCE_BYTES] = row
            .get::<_, Vec<u8>>(2)?
            .try_into()
            .map_err(|_| JournalError::CorruptChain)?;
        let ciphertext: Vec<u8> = row.get(4)?;
        let previous_hash: [u8; HASH_BYTES] = row
            .get::<_, Vec<u8>>(6)?
            .try_into()
            .map_err(|_| JournalError::CorruptChain)?;
        let entry_hash: [u8; HASH_BYTES] = row
            .get::<_, Vec<u8>>(8)?
            .try_into()
            .map_err(|_| JournalError::CorruptChain)?;
        if previous_hash != expected_previous
            || entry_hash != hash_entry(journal_id, sequence, &previous_hash, &nonce, &ciphertext)
        {
            return Err(JournalError::CorruptChain);
        }

        let aad = associated_data(journal_id, sequence, &previous_hash);
        let nonce_ref: &XNonce = nonce
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::CorruptChain)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce_ref,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| JournalError::AuthenticationFailed)?,
        );
        if plaintext.len() > MAX_EVENT_BYTES {
            return Err(JournalError::CorruptChain);
        }

        ciphertext_bytes = ciphertext_bytes
            .checked_add(ciphertext.len() as u64)
            .ok_or(JournalError::JournalTooLarge)?;
        plaintext_bytes = plaintext_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(JournalError::JournalTooLarge)?;
        if ciphertext_bytes > MAX_JOURNAL_CIPHERTEXT_BYTES {
            return Err(JournalError::JournalTooLarge);
        }
        if sequence == anchor_sequence {
            anchor_prefix_hash = Some(entry_hash);
        }
        if mode == ScanMode::AllBounded
            && (sequence > MAX_RETURNED_ENTRIES || plaintext_bytes > MAX_RETURNED_PLAINTEXT_BYTES)
        {
            return Err(JournalError::ReadLimitExceeded);
        }
        if mode == ScanMode::AllBounded || (mode == ScanMode::First && sequence == 1) {
            entries.push(JournalEntry {
                sequence,
                event: plaintext.to_vec(),
                previous_hash,
                entry_hash,
            });
        }

        expected_previous = entry_hash;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
    }

    Ok(ChainScan {
        head: ChainHead {
            sequence: expected_sequence - 1,
            entry_hash: expected_previous,
        },
        anchor_prefix_hash,
        ciphertext_bytes,
        entries,
    })
}

fn validate_expected_head(
    connection: &Connection,
    cipher: &XChaCha20Poly1305,
    journal_id: &[u8; JOURNAL_ID_BYTES],
    expected: JournalAnchor,
) -> Result<(), JournalError> {
    if &expected.journal_id != journal_id || load_journal_id(connection)? != *journal_id {
        return Err(JournalError::RollbackDetected);
    }

    let (count_raw, minimum_raw, maximum_raw): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT count(*), min(sequence), max(sequence)
             FROM secure_journal_entries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let count = u64::try_from(count_raw).map_err(|_| JournalError::CorruptChain)?;
    if count > MAX_JOURNAL_ENTRIES {
        return Err(JournalError::JournalTooLarge);
    }

    let actual = match (minimum_raw, maximum_raw) {
        (None, None) if count == 0 => initial_anchor(*journal_id),
        (Some(minimum_raw), Some(maximum_raw)) => {
            let minimum = u64::try_from(minimum_raw).map_err(|_| JournalError::CorruptChain)?;
            let maximum = u64::try_from(maximum_raw).map_err(|_| JournalError::CorruptChain)?;
            if minimum != 1 || maximum != count || maximum > MAX_JOURNAL_ENTRIES {
                return Err(JournalError::CorruptChain);
            }
            let (hash_length, entry_hash): (i64, Vec<u8>) = connection.query_row(
                "SELECT length(entry_hash), entry_hash
                 FROM secure_journal_entries WHERE sequence = ?1",
                [maximum_raw],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if hash_length != HASH_BYTES as i64 {
                return Err(JournalError::CorruptChain);
            }
            JournalAnchor {
                journal_id: *journal_id,
                sequence: maximum,
                entry_hash: entry_hash
                    .try_into()
                    .map_err(|_| JournalError::CorruptChain)?,
            }
        }
        _ => return Err(JournalError::CorruptChain),
    };

    if actual != expected {
        if actual.sequence <= expected.sequence {
            return Err(JournalError::RollbackDetected);
        }
        return Err(JournalError::UnexpectedHead { expected, actual });
    }
    if expected.sequence == 0 {
        if expected.entry_hash != ZERO_HASH {
            return Err(JournalError::RollbackDetected);
        }
        return Ok(());
    }

    type TailRow = (i64, Vec<u8>, i64, Vec<u8>, i64, Vec<u8>, i64, Vec<u8>);
    let (
        nonce_length,
        nonce,
        ciphertext_length,
        ciphertext,
        previous_hash_length,
        previous_hash,
        entry_hash_length,
        entry_hash,
    ): TailRow = connection.query_row(
        "SELECT length(nonce), nonce,
                length(ciphertext), ciphertext,
                length(previous_hash), previous_hash,
                length(entry_hash), entry_hash
         FROM secure_journal_entries WHERE sequence = ?1",
        [i64::try_from(expected.sequence).map_err(|_| JournalError::CorruptChain)?],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let max_ciphertext = MAX_EVENT_BYTES
        .checked_add(AEAD_TAG_BYTES)
        .ok_or(JournalError::JournalTooLarge)?;
    if nonce_length != NONCE_BYTES as i64
        || ciphertext_length < AEAD_TAG_BYTES as i64
        || ciphertext_length > max_ciphertext as i64
        || previous_hash_length != HASH_BYTES as i64
        || entry_hash_length != HASH_BYTES as i64
    {
        return Err(JournalError::CorruptChain);
    }
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| JournalError::CorruptChain)?;
    let previous_hash: [u8; HASH_BYTES] = previous_hash
        .try_into()
        .map_err(|_| JournalError::CorruptChain)?;
    let entry_hash: [u8; HASH_BYTES] = entry_hash
        .try_into()
        .map_err(|_| JournalError::CorruptChain)?;
    if entry_hash != expected.entry_hash
        || entry_hash
            != hash_entry(
                journal_id,
                expected.sequence,
                &previous_hash,
                &nonce,
                &ciphertext,
            )
    {
        return Err(JournalError::CorruptChain);
    }

    let nonce_ref: &XNonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| JournalError::CorruptChain)?;
    let aad = associated_data(journal_id, expected.sequence, &previous_hash);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce_ref,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::AuthenticationFailed)?,
    );
    if plaintext.len() > MAX_EVENT_BYTES {
        return Err(JournalError::CorruptChain);
    }
    Ok(())
}

fn validate_anchor(
    anchor: &JournalAnchor,
    scan: &ChainScan,
    journal_id: &[u8; JOURNAL_ID_BYTES],
) -> Result<bool, JournalError> {
    if &anchor.journal_id != journal_id {
        return Err(JournalError::RollbackDetected);
    }
    if anchor.sequence > scan.head.sequence {
        return Err(JournalError::RollbackDetected);
    }
    if anchor.sequence == scan.head.sequence {
        if anchor.entry_hash != scan.head.entry_hash {
            return Err(JournalError::RollbackDetected);
        }
        return Ok(false);
    }
    if scan.anchor_prefix_hash != Some(anchor.entry_hash) {
        return Err(JournalError::RollbackDetected);
    }
    Ok(true)
}

fn load_required_anchor<S: JournalSecretStore>(
    secret_store: &mut S,
) -> Result<JournalAnchor, JournalError> {
    secret_store
        .load_anchor()?
        .ok_or(JournalError::MissingAnchor)
}

fn cipher_from_key(key: &JournalKey) -> Result<XChaCha20Poly1305, JournalError> {
    XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| JournalError::AuthenticationFailed)
}

fn associated_data(
    journal_id: &[u8; JOURNAL_ID_BYTES],
    sequence: u64,
    previous_hash: &[u8; HASH_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + JOURNAL_ID_BYTES + 8 + HASH_BYTES);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(journal_id);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_hash);
    aad
}

fn hash_entry(
    journal_id: &[u8; JOURNAL_ID_BYTES],
    sequence: u64,
    previous_hash: &[u8; HASH_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> [u8; HASH_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(journal_id);
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(nonce);
    hasher.update((ciphertext.len() as u64).to_be_bytes());
    hasher.update(ciphertext);
    hasher.finalize().into()
}

fn inspect_database_path(path: &Path) -> Result<DatabasePathState, JournalError> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Err(JournalError::InvalidPath);
    }
    validate_parent_directory(path)?;

    let state = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_link_like(&metadata)?;
            if !metadata.is_file() {
                return Err(JournalError::InvalidPath);
            }
            if metadata.len() == 0 {
                DatabasePathState::Empty
            } else {
                DatabasePathState::Existing
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => DatabasePathState::Missing,
        Err(error) => return Err(database_io_error(error)),
    };

    for suffix in ["-wal", "-shm"] {
        let sidecar = database_sidecar(path, suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(metadata) => {
                reject_link_like(&metadata)?;
                if !metadata.is_file() || state != DatabasePathState::Existing {
                    return Err(JournalError::InvalidPath);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(database_io_error(error)),
        }
    }
    Ok(state)
}

fn validate_parent_directory(path: &Path) -> Result<(), JournalError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(database_io_error)?;
    reject_link_like(&parent_metadata)?;
    if !parent_metadata.is_dir() {
        return Err(JournalError::InvalidPath);
    }
    Ok(())
}

fn reject_link_like(metadata: &fs::Metadata) -> Result<(), JournalError> {
    if metadata.file_type().is_symlink() {
        return Err(JournalError::SymlinkRejected);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(JournalError::SymlinkRejected);
    }
    Ok(())
}

fn create_database_file(path: &Path) -> Result<(), JournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).map(drop).map_err(database_io_error)
}

fn configure_connection(connection: &Connection) -> Result<(), JournalError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA secure_delete=ON;
         PRAGMA temp_store=MEMORY;
         PRAGMA trusted_schema=OFF;
         PRAGMA recursive_triggers=ON;",
    )?;
    Ok(())
}

fn initialize_schema(
    connection: &Connection,
    journal_id: &[u8; JOURNAL_ID_BYTES],
    initialization: &InitializationRecord,
) -> Result<(), JournalError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE secure_journal_metadata (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           schema_version INTEGER NOT NULL CHECK(schema_version = 3),
           journal_id BLOB NOT NULL CHECK(length(journal_id) = 16)
         );
         CREATE TABLE secure_journal_entries (
           sequence INTEGER PRIMARY KEY NOT NULL,
           nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 24),
           ciphertext BLOB NOT NULL CHECK(length(ciphertext) >= 16),
           previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
           entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32)
         );
         CREATE TABLE secure_journal_initialization (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           state INTEGER NOT NULL CHECK(state IN (0, 1)),
           nonce BLOB NOT NULL CHECK(length(nonce) = 24),
           ciphertext BLOB NOT NULL CHECK(length(ciphertext) = 52)
         );",
    )?;
    connection.execute(
        "INSERT INTO secure_journal_metadata(singleton, schema_version, journal_id)\
         VALUES (1, ?1, ?2)",
        params![SCHEMA_VERSION, journal_id.as_slice()],
    )?;
    connection.execute(
        "INSERT INTO secure_journal_initialization(singleton, state, nonce, ciphertext)
         VALUES (1, 0, ?1, ?2)",
        params![initialization.nonce.as_slice(), initialization.ciphertext],
    )?;
    connection.execute_batch(
        "CREATE TRIGGER secure_journal_entries_no_update
           BEFORE UPDATE ON secure_journal_entries
           BEGIN SELECT RAISE(ABORT, 'append-only secure journal'); END;
         CREATE TRIGGER secure_journal_entries_no_delete
           BEFORE DELETE ON secure_journal_entries
           BEGIN SELECT RAISE(ABORT, 'append-only secure journal'); END;
         CREATE TRIGGER secure_journal_metadata_no_update
           BEFORE UPDATE ON secure_journal_metadata
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal metadata'); END;
         CREATE TRIGGER secure_journal_metadata_no_delete
           BEFORE DELETE ON secure_journal_metadata
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal metadata'); END;
         CREATE TRIGGER secure_journal_metadata_no_insert
           BEFORE INSERT ON secure_journal_metadata
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal metadata'); END;
         CREATE TRIGGER secure_journal_initialization_no_delete
           BEFORE DELETE ON secure_journal_initialization
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal initialization'); END;
         CREATE TRIGGER secure_journal_initialization_no_insert
           BEFORE INSERT ON secure_journal_initialization
           BEGIN SELECT RAISE(ABORT, 'immutable secure journal initialization'); END;
         PRAGMA user_version=3;
         COMMIT;",
    )?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<SchemaKind, JournalError> {
    let required_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table'
           AND name IN ('secure_journal_metadata', 'secure_journal_entries')",
        [],
        |row| row.get(0),
    )?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if required_tables != 2 || !matches!(user_version, LEGACY_SCHEMA_VERSION | SCHEMA_VERSION) {
        return Err(JournalError::UnsupportedFormat);
    }
    let metadata_rows: i64 =
        connection.query_row("SELECT count(*) FROM secure_journal_metadata", [], |row| {
            row.get(0)
        })?;
    let schema_version: i64 = connection.query_row(
        "SELECT schema_version FROM secure_journal_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if metadata_rows != 1 || schema_version != user_version {
        return Err(JournalError::UnsupportedFormat);
    }
    if schema_version == LEGACY_SCHEMA_VERSION {
        return Ok(SchemaKind::Legacy);
    }
    if schema_version != SCHEMA_VERSION {
        return Err(JournalError::UnsupportedFormat);
    }
    let initialization_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'secure_journal_initialization'",
        [],
        |row| row.get(0),
    )?;
    if initialization_tables != 1 {
        return Err(JournalError::UnsupportedFormat);
    }
    Ok(SchemaKind::Recoverable)
}

fn load_initialization_record(
    connection: &Connection,
) -> Result<InitializationRecord, JournalError> {
    let rows: i64 = connection.query_row(
        "SELECT count(*) FROM secure_journal_initialization",
        [],
        |row| row.get(0),
    )?;
    if rows != 1 {
        return Err(JournalError::UnsupportedFormat);
    }
    let (state, nonce_length, nonce, ciphertext_length, ciphertext): (
        i64,
        i64,
        Vec<u8>,
        i64,
        Vec<u8>,
    ) = connection.query_row(
        "SELECT state, length(nonce), nonce, length(ciphertext), ciphertext
         FROM secure_journal_initialization WHERE singleton = 1",
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
    )?;
    let expected_ciphertext_length = INITIALIZATION_PLAINTEXT
        .len()
        .checked_add(AEAD_TAG_BYTES)
        .ok_or(JournalError::UnsupportedFormat)?;
    if !matches!(state, INITIALIZATION_PENDING | INITIALIZATION_READY)
        || nonce_length != NONCE_BYTES as i64
        || ciphertext_length != expected_ciphertext_length as i64
    {
        return Err(JournalError::UnsupportedFormat);
    }
    let update_guards: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'trigger'
           AND name = 'secure_journal_initialization_no_update'",
        [],
        |row| row.get(0),
    )?;
    if (state == INITIALIZATION_PENDING && update_guards != 0)
        || (state == INITIALIZATION_READY && update_guards != 1)
    {
        return Err(JournalError::UnsupportedFormat);
    }
    Ok(InitializationRecord {
        state,
        nonce: nonce
            .try_into()
            .map_err(|_| JournalError::UnsupportedFormat)?,
        ciphertext,
    })
}

fn load_journal_id(connection: &Connection) -> Result<[u8; JOURNAL_ID_BYTES], JournalError> {
    let (length, journal_id): (i64, Vec<u8>) = connection.query_row(
        "SELECT length(journal_id), journal_id
         FROM secure_journal_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if length != JOURNAL_ID_BYTES as i64 {
        return Err(JournalError::UnsupportedFormat);
    }
    journal_id
        .try_into()
        .map_err(|_| JournalError::UnsupportedFormat)
}

fn harden_database_files(path: &Path) -> Result<(), JournalError> {
    validate_parent_directory(path)?;
    for (candidate, required) in [
        (path.to_path_buf(), true),
        (database_sidecar(path, "-wal"), false),
        (database_sidecar(path, "-shm"), false),
    ] {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                reject_link_like(&metadata)?;
                if !metadata.is_file() {
                    return Err(JournalError::InvalidPath);
                }
                #[cfg(unix)]
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600))
                    .map_err(database_io_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && !required => {}
            Err(error) => return Err(database_io_error(error)),
        }
    }
    Ok(())
}

fn database_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn database_io_error(error: io::Error) -> JournalError {
    JournalError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        io::Write,
        process::{self, Command},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[derive(Default)]
    struct MemorySecrets {
        key: Option<[u8; JOURNAL_KEY_BYTES]>,
        anchor: Option<JournalAnchor>,
        fail_next_key_write: bool,
        fail_next_anchor_write: bool,
    }

    #[derive(Clone, Default)]
    struct MemorySecretStore(Arc<Mutex<MemorySecrets>>);

    impl MemorySecretStore {
        fn clear_key(&self) {
            self.0.lock().expect("lock secrets").key = None;
        }

        fn replace_key(&self, key: [u8; JOURNAL_KEY_BYTES]) {
            self.0.lock().expect("lock secrets").key = Some(key);
        }

        fn clear_anchor(&self) {
            self.0.lock().expect("lock secrets").anchor = None;
        }

        fn clear_all(&self) {
            let mut secrets = self.0.lock().expect("lock secrets");
            secrets.key = None;
            secrets.anchor = None;
        }

        fn anchor(&self) -> JournalAnchor {
            self.0
                .lock()
                .expect("lock secrets")
                .anchor
                .expect("stored anchor")
        }

        fn replace_anchor(&self, anchor: JournalAnchor) {
            self.0.lock().expect("lock secrets").anchor = Some(anchor);
        }

        fn fail_next_anchor_write(&self) {
            self.0.lock().expect("lock secrets").fail_next_anchor_write = true;
        }

        fn fail_next_key_write(&self) {
            self.0.lock().expect("lock secrets").fail_next_key_write = true;
        }
    }

    impl JournalSecretStore for MemorySecretStore {
        fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| SecretStoreError::new("memory store lock failed"))?
                .key
                .map(|key| JournalKey::from_zeroizing(Zeroizing::new(key))))
        }

        fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
            let mut secrets = self
                .0
                .lock()
                .map_err(|_| SecretStoreError::new("memory store lock failed"))?;
            if secrets.fail_next_key_write {
                secrets.fail_next_key_write = false;
                return Err(SecretStoreError::new("injected key failure"));
            }
            secrets.key = Some(*key.expose_secret());
            Ok(())
        }

        fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| SecretStoreError::new("memory store lock failed"))?
                .anchor)
        }

        fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
            let mut secrets = self
                .0
                .lock()
                .map_err(|_| SecretStoreError::new("memory store lock failed"))?;
            if secrets.fail_next_anchor_write {
                secrets.fail_next_anchor_write = false;
                return Err(SecretStoreError::new("injected anchor failure"));
            }
            secrets.anchor = Some(*anchor);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ProcessSecretStore {
        directory: PathBuf,
    }

    impl ProcessSecretStore {
        fn new(directory: PathBuf) -> Self {
            Self { directory }
        }

        fn key_path(&self) -> PathBuf {
            self.directory.join("journal.key")
        }

        fn anchor_path(&self) -> PathBuf {
            self.directory.join("journal.anchor")
        }

        fn load_file(path: &Path) -> Result<Option<Vec<u8>>, SecretStoreError> {
            match fs::read(path) {
                Ok(value) => Ok(Some(value)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(SecretStoreError::new("process secret read failed")),
            }
        }

        fn store_file(&self, path: &Path, value: &[u8]) -> Result<(), SecretStoreError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| SecretStoreError::new("process secret create failed"))?;
            file.write_all(value)
                .map_err(|_| SecretStoreError::new("process secret write failed"))?;
            file.sync_all()
                .map_err(|_| SecretStoreError::new("process secret sync failed"))?;
            #[cfg(unix)]
            fs::File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| SecretStoreError::new("process secret directory sync failed"))?;
            Ok(())
        }
    }

    impl JournalSecretStore for ProcessSecretStore {
        fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
            let Some(value) = Self::load_file(&self.key_path())? else {
                return Ok(None);
            };
            let key: [u8; JOURNAL_KEY_BYTES] = value
                .try_into()
                .map_err(|_| SecretStoreError::new("invalid process journal key"))?;
            Ok(Some(JournalKey::from_zeroizing(Zeroizing::new(key))))
        }

        fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
            self.store_file(&self.key_path(), key.expose_secret())
        }

        fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
            let Some(value) = Self::load_file(&self.anchor_path())? else {
                return Ok(None);
            };
            JournalAnchor::from_bytes(&value)
                .map(Some)
                .map_err(|_| SecretStoreError::new("invalid process journal anchor"))
        }

        fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
            self.store_file(&self.anchor_path(), &anchor.to_bytes())
        }
    }

    fn database_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "kernaid-secure-journal-{name}-{}-{}.sqlite3",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_database(path: &Path) {
        for candidate in [
            path.to_path_buf(),
            database_sidecar(path, "-wal"),
            database_sidecar(path, "-shm"),
        ] {
            let _ = fs::remove_file(candidate);
        }
    }

    fn initialization_state(path: &Path) -> (i64, i64) {
        let connection = Connection::open(path).expect("open initialization database");
        let state = connection
            .query_row(
                "SELECT state FROM secure_journal_initialization WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read initialization state");
        let guard = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'trigger'
                   AND name = 'secure_journal_initialization_no_update'",
                [],
                |row| row.get(0),
            )
            .expect("read initialization guard");
        (state, guard)
    }

    fn create_pending_database(
        path: &Path,
        store: &MemorySecretStore,
        persist_key: bool,
        persist_anchor: bool,
    ) -> ([u8; JOURNAL_ID_BYTES], [u8; JOURNAL_KEY_BYTES]) {
        create_database_file(path).expect("create pending database");
        let connection = Connection::open(path).expect("open pending database");
        configure_connection(&connection).expect("configure pending database");
        let mut journal_id = [0_u8; JOURNAL_ID_BYTES];
        OsRng.fill_bytes(&mut journal_id);
        let key = JournalKey::generate();
        let key_bytes = *key.expose_secret();
        let initialization =
            create_initialization_record(&key, &journal_id).expect("create key check");
        initialize_schema(&connection, &journal_id, &initialization)
            .expect("initialize pending schema");
        if persist_key {
            store.clone().store_key(&key).expect("persist pending key");
        }
        if persist_anchor {
            assert!(
                persist_key,
                "an anchor without its key is not a valid phase"
            );
            store
                .clone()
                .store_anchor(&initial_anchor(journal_id))
                .expect("persist pending anchor");
        }
        drop(connection);
        (journal_id, key_bytes)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn bulk_append_valid_empty_events(journal: &mut SecureJournal<MemorySecretStore>, count: u64) {
        let mut head = ChainHead {
            sequence: 0,
            entry_hash: ZERO_HASH,
        };
        let transaction = journal
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin bulk append");
        for sequence in 1..=count {
            let mut nonce = [0_u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&sequence.to_be_bytes());
            let nonce_ref: &XNonce = nonce.as_slice().try_into().expect("fixed nonce size");
            let aad = associated_data(&journal.journal_id, sequence, &head.entry_hash);
            let ciphertext = journal
                .cipher
                .encrypt(
                    nonce_ref,
                    Payload {
                        msg: b"",
                        aad: &aad,
                    },
                )
                .expect("encrypt empty event");
            let entry_hash = hash_entry(
                &journal.journal_id,
                sequence,
                &head.entry_hash,
                &nonce,
                &ciphertext,
            );
            transaction
                .execute(
                    "INSERT INTO secure_journal_entries(
                       sequence, nonce, ciphertext, previous_hash, entry_hash
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        sequence,
                        nonce.as_slice(),
                        ciphertext,
                        head.entry_hash.as_slice(),
                        entry_hash.as_slice()
                    ],
                )
                .expect("insert valid record");
            head = ChainHead {
                sequence,
                entry_hash,
            };
        }
        transaction.commit().expect("commit bulk append");
        journal
            .secret_store
            .store_anchor(&JournalAnchor {
                journal_id: journal.journal_id,
                sequence: head.sequence,
                entry_hash: head.entry_hash,
            })
            .expect("anchor bulk append");
    }

    fn rewrite_ciphertext_and_public_hash(path: &Path, sequence: u64) {
        let connection = Connection::open(path).expect("open raw database");
        let journal_id: [u8; JOURNAL_ID_BYTES] = connection
            .query_row(
                "SELECT journal_id FROM secure_journal_metadata WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("read journal id")
            .try_into()
            .expect("fixed journal id");
        let (nonce, previous_hash, mut ciphertext): ([u8; NONCE_BYTES], [u8; HASH_BYTES], Vec<u8>) =
            connection
                .query_row(
                    "SELECT nonce, previous_hash, ciphertext
                 FROM secure_journal_entries WHERE sequence = ?1",
                    [sequence],
                    |row| {
                        let nonce = row
                            .get::<_, Vec<u8>>(0)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        let previous_hash = row
                            .get::<_, Vec<u8>>(1)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        Ok((nonce, previous_hash, row.get(2)?))
                    },
                )
                .expect("read encrypted record");
        ciphertext[0] ^= 0x80;
        let rewritten_hash = hash_entry(&journal_id, sequence, &previous_hash, &nonce, &ciphertext);
        connection
            .execute_batch("DROP TRIGGER secure_journal_entries_no_update;")
            .expect("drop update guard");
        connection
            .execute(
                "UPDATE secure_journal_entries
                 SET ciphertext = ?1, entry_hash = ?2 WHERE sequence = ?3",
                params![ciphertext, rewritten_hash.as_slice(), sequence],
            )
            .expect("rewrite ciphertext and public hash");
    }

    #[test]
    fn encrypted_journal_survives_reopen_and_anchor_roundtrips() {
        let path = database_path("roundtrip");
        let store = MemorySecretStore::default();
        {
            let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
            let first = journal.append(b"started").expect("append first");
            let second = journal.append(b"succeeded").expect("append second");
            assert_eq!(first.sequence, 1);
            assert_eq!(second.previous_hash, first.entry_hash);
            assert_eq!(journal.entries().expect("verified entries").len(), 2);
        }

        let anchor = store.anchor();
        assert_eq!(JournalAnchor::from_bytes(&anchor.to_bytes()), Ok(anchor));
        let mut reopened = SecureJournal::open(&path, store).expect("reopen journal");
        let entries = reopened.entries().expect("read entries");
        assert_eq!(entries[0].event, b"started");
        assert_eq!(entries[1].event, b"succeeded");
        remove_database(&path);
    }

    #[test]
    fn first_entry_verifies_every_record_without_materializing_the_tail() {
        let path = database_path("first-entry");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        assert_eq!(journal.first_entry().expect("empty first entry"), None);
        journal.append(b"first").expect("append first");
        journal.append(b"second").expect("append second");
        journal.append(b"third").expect("append third");
        let first = journal
            .first_entry()
            .expect("verify first entry")
            .expect("stored first entry");
        assert_eq!(first.sequence, 1);
        assert_eq!(first.event, b"first");

        rewrite_ciphertext_and_public_hash(&path, 3);
        assert!(matches!(
            journal.first_entry(),
            Err(JournalError::AuthenticationFailed)
        ));
        remove_database(&path);
    }

    #[test]
    fn append_expected_rejects_a_stale_head_without_writing() {
        let path = database_path("expected-head");
        let store = MemorySecretStore::default();
        let mut first_writer =
            SecureJournal::open(&path, store.clone()).expect("open first writer");
        let mut second_writer =
            SecureJournal::open(&path, store.clone()).expect("open second writer");
        let expected = first_writer.head().expect("initial head");
        let appended = first_writer
            .append_expected(expected, b"first writer")
            .expect("append at expected head");
        assert_eq!(appended.sequence, 1);

        let error = second_writer
            .append_expected(expected, b"stale writer")
            .expect_err("stale append must fail");
        assert!(matches!(error, JournalError::UnexpectedHead { .. }));
        if let JournalError::UnexpectedHead {
            expected: rejected,
            actual,
        } = error
        {
            assert_eq!(rejected, expected);
            assert_eq!(actual.sequence, 1);
            assert_eq!(actual.entry_hash, appended.entry_hash);
        }
        assert_eq!(first_writer.entries().expect("read journal").len(), 1);
        remove_database(&path);
    }

    #[test]
    fn append_expected_validates_the_current_tail_before_writing() {
        let path = database_path("expected-tail-tamper");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        let first = journal.append(b"first").expect("append first");
        let expected = store.anchor();
        assert_eq!(expected.entry_hash, first.entry_hash);

        rewrite_ciphertext_and_public_hash(&path, 1);
        assert!(matches!(
            journal.append_expected(expected, b"must not append"),
            Err(JournalError::RollbackDetected)
        ));
        assert_eq!(store.anchor(), expected);
        remove_database(&path);
    }

    #[test]
    fn append_expected_rejects_a_historical_gap_even_when_the_tail_matches() {
        let path = database_path("expected-gap");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal.append(b"first").expect("append first");
        journal.append(b"second").expect("append second");
        let expected = store.anchor();

        let connection = Connection::open(&path).expect("open raw gap database");
        connection
            .execute_batch(
                "DROP TRIGGER secure_journal_entries_no_delete;
                 DELETE FROM secure_journal_entries WHERE sequence = 1;",
            )
            .expect("inject historical gap");
        drop(connection);

        assert!(matches!(
            journal.append_expected(expected, b"must not append"),
            Err(JournalError::CorruptChain)
        ));
        assert_eq!(store.anchor(), expected);
        remove_database(&path);
    }

    #[test]
    fn pending_database_only_and_key_only_states_recover() {
        let database_only_path = database_path("pending-database-only");
        let database_only_store = MemorySecretStore::default();
        database_only_store.fail_next_key_write();
        assert!(matches!(
            SecureJournal::open(&database_only_path, database_only_store.clone()),
            Err(JournalError::SecretStore(_))
        ));
        assert_eq!(initialization_state(&database_only_path), (0, 0));
        let recovered = SecureJournal::open(&database_only_path, database_only_store)
            .expect("recover database-only state");
        assert_eq!(initialization_state(&database_only_path), (1, 1));
        drop(recovered);
        remove_database(&database_only_path);

        let key_only_path = database_path("pending-key-only");
        let key_only_store = MemorySecretStore::default();
        key_only_store.fail_next_anchor_write();
        assert!(matches!(
            SecureJournal::open(&key_only_path, key_only_store.clone()),
            Err(JournalError::SecretStore(_))
        ));
        assert_eq!(initialization_state(&key_only_path), (0, 0));
        let recovered =
            SecureJournal::open(&key_only_path, key_only_store).expect("recover key-only state");
        assert_eq!(initialization_state(&key_only_path), (1, 1));
        drop(recovered);
        remove_database(&key_only_path);
    }

    #[test]
    fn pending_anchor_state_recovers_and_mismatched_key_fails_closed() {
        let anchor_path = database_path("pending-anchor");
        let anchor_store = MemorySecretStore::default();
        create_pending_database(&anchor_path, &anchor_store, true, true);
        assert_eq!(initialization_state(&anchor_path), (0, 0));
        let recovered = SecureJournal::open(&anchor_path, anchor_store)
            .expect("recover anchor-before-ready state");
        assert_eq!(initialization_state(&anchor_path), (1, 1));
        drop(recovered);
        remove_database(&anchor_path);

        let mismatch_path = database_path("pending-key-mismatch");
        let mismatch_store = MemorySecretStore::default();
        create_pending_database(&mismatch_path, &mismatch_store, true, false);
        mismatch_store.replace_key([0x6d; JOURNAL_KEY_BYTES]);
        assert!(matches!(
            SecureJournal::open(&mismatch_path, mismatch_store.clone()),
            Err(JournalError::AuthenticationFailed)
        ));
        assert!(
            mismatch_store
                .0
                .lock()
                .expect("lock secrets")
                .anchor
                .is_none()
        );
        assert_eq!(initialization_state(&mismatch_path), (0, 0));
        remove_database(&mismatch_path);
    }

    #[test]
    fn ready_or_nonempty_databases_never_reinitialize_without_secrets() {
        let ready_path = database_path("ready-missing-all");
        let ready_store = MemorySecretStore::default();
        drop(SecureJournal::open(&ready_path, ready_store.clone()).expect("initialize ready"));
        ready_store.clear_all();
        assert!(matches!(
            SecureJournal::open(&ready_path, ready_store),
            Err(JournalError::MissingKey)
        ));
        assert_eq!(initialization_state(&ready_path), (1, 1));
        remove_database(&ready_path);

        let nonempty_path = database_path("pending-nonempty");
        let nonempty_store = MemorySecretStore::default();
        create_pending_database(&nonempty_path, &nonempty_store, false, false);
        let connection = Connection::open(&nonempty_path).expect("open pending raw database");
        connection
            .execute(
                "INSERT INTO secure_journal_entries(
                   sequence, nonce, ciphertext, previous_hash, entry_hash
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    [1_u8; NONCE_BYTES].as_slice(),
                    [2_u8; AEAD_TAG_BYTES].as_slice(),
                    ZERO_HASH.as_slice(),
                    [3_u8; HASH_BYTES].as_slice()
                ],
            )
            .expect("inject ambiguous pending entry");
        drop(connection);
        assert!(matches!(
            SecureJournal::open(&nonempty_path, nonempty_store),
            Err(JournalError::SecretStateConflict)
        ));
        remove_database(&nonempty_path);
    }

    #[test]
    fn zero_length_database_file_is_a_recoverable_new_state() {
        let path = database_path("zero-length");
        fs::write(&path, []).expect("create empty database file");
        let journal = SecureJournal::open(&path, MemorySecretStore::default())
            .expect("initialize zero-length database");
        assert_eq!(initialization_state(&path), (1, 1));
        drop(journal);
        remove_database(&path);
    }

    #[test]
    fn initialization_recovers_after_real_process_crashes_at_every_boundary() {
        for boundary in ["database", "key", "anchor", "ready"] {
            let directory = env::temp_dir().join(format!(
                "kernaid-storage-crash-{boundary}-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).expect("create crash directory");
            let status = Command::new(env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "tests::initialization_crash_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("KERNAID_STORAGE_TEST_CRASH_DIRECTORY", &directory)
                .env("KERNAID_STORAGE_TEST_CRASH_BOUNDARY", boundary)
                .status()
                .expect("run crash child");
            assert_eq!(status.code(), Some(86), "child did not crash at {boundary}");

            let path = directory.join("journal.sqlite3");
            let store = ProcessSecretStore::new(directory.clone());
            let mut recovered =
                SecureJournal::open(&path, store).expect("recover after crash boundary");
            assert_eq!(recovered.head().expect("recovered head").sequence, 0);
            assert_eq!(initialization_state(&path), (1, 1));
            drop(recovered);

            remove_database(&path);
            let _ = fs::remove_file(directory.join("journal.key"));
            let _ = fs::remove_file(directory.join("journal.anchor"));
            fs::remove_dir(directory).expect("remove crash directory");
        }
    }

    #[test]
    #[ignore = "spawned by initialization_recovers_after_real_process_crashes_at_every_boundary"]
    fn initialization_crash_child() {
        let directory = PathBuf::from(
            env::var_os("KERNAID_STORAGE_TEST_CRASH_DIRECTORY")
                .expect("crash test directory environment"),
        );
        let path = directory.join("journal.sqlite3");
        let store = ProcessSecretStore::new(directory);
        let result = SecureJournal::open(&path, store);
        assert!(result.is_err(), "crash hook did not terminate child");
    }

    #[test]
    fn plaintext_never_appears_in_sqlite_or_wal() {
        let path = database_path("ciphertext");
        let sentinel = b"KERNAID-PLAINTEXT-SENTINEL-8f949ea6";
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store).expect("open journal");
        journal.append(sentinel).expect("append sentinel");

        for candidate in [
            path.clone(),
            database_sidecar(&path, "-wal"),
            database_sidecar(&path, "-shm"),
        ] {
            if let Ok(contents) = fs::read(candidate) {
                assert!(!contains_bytes(&contents, sentinel));
            }
        }
        drop(journal);
        remove_database(&path);
    }

    #[test]
    fn existing_journal_fails_closed_without_key_or_anchor() {
        let missing_key_path = database_path("missing-key");
        let missing_key_store = MemorySecretStore::default();
        drop(
            SecureJournal::open(&missing_key_path, missing_key_store.clone())
                .expect("initialize journal"),
        );
        missing_key_store.clear_key();
        assert!(matches!(
            SecureJournal::open(&missing_key_path, missing_key_store),
            Err(JournalError::MissingKey)
        ));
        remove_database(&missing_key_path);

        let missing_anchor_path = database_path("missing-anchor");
        let missing_anchor_store = MemorySecretStore::default();
        drop(
            SecureJournal::open(&missing_anchor_path, missing_anchor_store.clone())
                .expect("initialize journal"),
        );
        missing_anchor_store.clear_anchor();
        assert!(matches!(
            SecureJournal::open(&missing_anchor_path, missing_anchor_store),
            Err(JournalError::MissingAnchor)
        ));
        remove_database(&missing_anchor_path);
    }

    #[test]
    fn wrong_secure_key_is_rejected() {
        let path = database_path("wrong-key");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal
            .append(b"authenticated event")
            .expect("append event");
        drop(journal);
        store.replace_key([0x5a; JOURNAL_KEY_BYTES]);

        assert!(matches!(
            SecureJournal::open(&path, store),
            Err(JournalError::AuthenticationFailed)
        ));
        remove_database(&path);
    }

    #[test]
    fn ciphertext_rewrite_is_detected() {
        let path = database_path("rewrite");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal.append(b"immutable event").expect("append event");
        drop(journal);

        rewrite_ciphertext_and_public_hash(&path, 1);

        assert!(matches!(
            SecureJournal::open(&path, store),
            Err(JournalError::AuthenticationFailed)
        ));
        remove_database(&path);
    }

    #[test]
    fn truncation_is_detected_against_secure_anchor() {
        let path = database_path("truncation");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal.append(b"first").expect("append first");
        journal.append(b"second").expect("append second");
        drop(journal);

        let connection = Connection::open(&path).expect("open raw database");
        connection
            .execute_batch(
                "DROP TRIGGER secure_journal_entries_no_delete;
                 DELETE FROM secure_journal_entries WHERE sequence = 2;",
            )
            .expect("truncate journal");
        drop(connection);

        assert!(matches!(
            SecureJournal::open(&path, store),
            Err(JournalError::RollbackDetected)
        ));
        remove_database(&path);
    }

    #[test]
    fn anchor_for_another_journal_is_rejected_even_when_empty() {
        let path = database_path("wrong-journal-id");
        let store = MemorySecretStore::default();
        drop(SecureJournal::open(&path, store.clone()).expect("initialize journal"));
        let mut wrong_anchor = store.anchor();
        wrong_anchor.journal_id[0] ^= 0xff;
        store.replace_anchor(wrong_anchor);

        assert!(matches!(
            SecureJournal::open(&path, store),
            Err(JournalError::RollbackDetected)
        ));
        remove_database(&path);
    }

    #[test]
    fn db_ahead_of_anchor_recovers_only_after_full_verification() {
        let path = database_path("anchor-lag");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal.append(b"anchored").expect("append first");
        assert_eq!(store.anchor().sequence, 1);

        store.fail_next_anchor_write();
        assert!(matches!(
            journal.append(b"committed before crash"),
            Err(JournalError::SecretStore(_))
        ));
        assert_eq!(store.anchor().sequence, 1);
        drop(journal);

        let mut recovered = SecureJournal::open(&path, store.clone()).expect("recover journal");
        assert_eq!(store.anchor().sequence, 2);
        assert_eq!(recovered.entries().expect("read recovered").len(), 2);
        remove_database(&path);
    }

    #[test]
    fn tampered_db_ahead_tail_does_not_advance_anchor() {
        let path = database_path("tampered-anchor-lag");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        journal.append(b"anchored").expect("append first");
        store.fail_next_anchor_write();
        assert!(matches!(
            journal.append(b"unanchored tail"),
            Err(JournalError::SecretStore(_))
        ));
        drop(journal);
        assert_eq!(store.anchor().sequence, 1);

        rewrite_ciphertext_and_public_hash(&path, 2);

        assert!(matches!(
            SecureJournal::open(&path, store.clone()),
            Err(JournalError::AuthenticationFailed)
        ));
        assert_eq!(store.anchor().sequence, 1);
        remove_database(&path);
    }

    #[test]
    fn oversized_events_are_rejected_before_encryption() {
        let path = database_path("limit");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store).expect("open journal");
        let oversized = vec![0_u8; MAX_EVENT_BYTES + 1];
        assert!(matches!(
            journal.append(&oversized),
            Err(JournalError::EventTooLarge)
        ));
        assert!(journal.entries().expect("empty journal").is_empty());
        remove_database(&path);
    }

    #[test]
    fn plaintext_snapshot_has_a_record_count_limit() {
        let path = database_path("read-count-limit");
        let store = MemorySecretStore::default();
        let mut journal = SecureJournal::open(&path, store.clone()).expect("open journal");
        bulk_append_valid_empty_events(&mut journal, MAX_RETURNED_ENTRIES + 1);

        assert!(matches!(
            journal.entries(),
            Err(JournalError::ReadLimitExceeded)
        ));
        let first = journal
            .first_entry()
            .expect("first entry remains available")
            .expect("large journal is nonempty");
        assert_eq!(first.sequence, 1);
        assert!(first.event.is_empty());
        let head = journal
            .head()
            .expect("head does not materialize plaintext records");
        assert_eq!(head.sequence, MAX_RETURNED_ENTRIES + 1);
        assert_eq!(head, store.anchor());
        journal.verify().expect("large journal remains verifiable");
        remove_database(&path);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_database_targets_are_rejected() {
        use std::os::unix::fs::symlink;

        let target = database_path("symlink-target");
        let link = database_path("symlink-link");
        fs::write(&target, b"not a database").expect("write target");
        symlink(&target, &link).expect("create symlink");
        assert!(matches!(
            SecureJournal::open(&link, MemorySecretStore::default()),
            Err(JournalError::SymlinkRejected)
        ));
        let _ = fs::remove_file(link);
        let _ = fs::remove_file(target);
    }
}
