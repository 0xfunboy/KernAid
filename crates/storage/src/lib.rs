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

const SCHEMA_VERSION: i64 = 2;
const JOURNAL_ID_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const HASH_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const ZERO_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];
const AAD_DOMAIN: &[u8] = b"KERNAID-SECURE-JOURNAL-AAD-V2\0";
const HASH_DOMAIN: &[u8] = b"KERNAID-SECURE-JOURNAL-ENTRY-V2\0";
const ANCHOR_MAGIC: &[u8; 8] = b"KNAUDV2\0";

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
pub struct SecureJournal<S: JournalSecretStore> {
    connection: Connection,
    secret_store: S,
    cipher: XChaCha20Poly1305,
    journal_id: [u8; JOURNAL_ID_BYTES],
    path: PathBuf,
    healthy: bool,
}

impl<S: JournalSecretStore> SecureJournal<S> {
    /// Open an existing verified journal or initialize a new one.
    ///
    /// An existing database without both secure items always fails closed.
    pub fn open(path: &Path, mut secret_store: S) -> Result<Self, JournalError> {
        let existed = inspect_database_path(path)?;

        if !existed {
            let key_exists = secret_store.load_key()?.is_some();
            let anchor_exists = secret_store.load_anchor()?.is_some();
            if key_exists || anchor_exists {
                return Err(JournalError::SecretStateConflict);
            }
            create_database_file(path)?;
        }

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&connection)?;
        harden_database_files(path)?;

        if existed {
            validate_schema(&connection)?;
            let journal_id = load_journal_id(&connection)?;
            let key = secret_store.load_key()?.ok_or(JournalError::MissingKey)?;
            let cipher = cipher_from_key(&key)?;
            if secret_store.load_anchor()?.is_none() {
                return Err(JournalError::MissingAnchor);
            }
            let mut journal = Self {
                connection,
                secret_store,
                cipher,
                journal_id,
                path: path.to_path_buf(),
                healthy: true,
            };
            journal.verify()?;
            Ok(journal)
        } else {
            let mut journal_id = [0_u8; JOURNAL_ID_BYTES];
            OsRng.fill_bytes(&mut journal_id);
            initialize_schema(&connection, &journal_id)?;
            harden_database_files(path)?;

            let key = JournalKey::generate();
            let cipher = cipher_from_key(&key)?;
            let anchor = JournalAnchor {
                journal_id,
                sequence: 0,
                entry_hash: ZERO_HASH,
            };
            secret_store.store_key(&key)?;
            secret_store.store_anchor(&anchor)?;

            Ok(Self {
                connection,
                secret_store,
                cipher,
                journal_id,
                path: path.to_path_buf(),
                healthy: true,
            })
        }
    }

    /// Append one event and advance the secure anchor after the SQLite commit.
    pub fn append(&mut self, event: &[u8]) -> Result<JournalEntry, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        if event.len() > MAX_EVENT_BYTES {
            return Err(JournalError::EventTooLarge);
        }

        let anchor = load_required_anchor(&mut self.secret_store)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scan = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            false,
        )?;
        validate_anchor(&anchor, &scan, &self.journal_id)?;

        let sequence = scan
            .head
            .sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if sequence > MAX_JOURNAL_ENTRIES {
            return Err(JournalError::JournalTooLarge);
        }

        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let aad = associated_data(&self.journal_id, sequence, &scan.head.entry_hash);
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
        let entry_hash = hash_entry(
            &self.journal_id,
            sequence,
            &scan.head.entry_hash,
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
                scan.head.entry_hash.as_slice(),
                entry_hash.as_slice()
            ],
        )?;
        transaction.commit()?;

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

        Ok(JournalEntry {
            sequence,
            event: event.to_vec(),
            previous_hash: scan.head.entry_hash,
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
        let anchor = load_required_anchor(&mut self.secret_store)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scan = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            false,
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
        Ok(JournalAnchor {
            journal_id: self.journal_id,
            sequence: scan.head.sequence,
            entry_hash: scan.head.entry_hash,
        })
    }

    /// Return a bounded plaintext snapshot after verification under one SQLite
    /// write lock. Large journals remain verifiable but must not be materialized
    /// wholesale through this convenience API.
    pub fn entries(&mut self) -> Result<Vec<JournalEntry>, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        let anchor = load_required_anchor(&mut self.secret_store)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let verified = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            false,
        )?;
        let anchor_lags = validate_anchor(&anchor, &verified, &self.journal_id)?;
        if verified.head.sequence > MAX_RETURNED_ENTRIES
            || verified.plaintext_bytes > MAX_RETURNED_PLAINTEXT_BYTES
        {
            return Err(JournalError::ReadLimitExceeded);
        }

        let materialized = scan_chain(
            &transaction,
            &self.cipher,
            &self.journal_id,
            anchor.sequence,
            true,
        )?;
        if anchor_lags {
            let recovered = JournalAnchor {
                journal_id: self.journal_id,
                sequence: verified.head.sequence,
                entry_hash: verified.head.entry_hash,
            };
            if let Err(error) = self.secret_store.store_anchor(&recovered) {
                self.healthy = false;
                return Err(error.into());
            }
        }
        transaction.commit()?;
        Ok(materialized.entries)
    }
}

#[derive(Clone, Copy)]
struct ChainHead {
    sequence: u64,
    entry_hash: [u8; HASH_BYTES],
}

struct ChainScan {
    head: ChainHead,
    anchor_prefix_hash: Option<[u8; HASH_BYTES]>,
    plaintext_bytes: u64,
    entries: Vec<JournalEntry>,
}

fn scan_chain(
    connection: &Connection,
    cipher: &XChaCha20Poly1305,
    journal_id: &[u8; JOURNAL_ID_BYTES],
    anchor_sequence: u64,
    materialize: bool,
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
        if materialize {
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
        plaintext_bytes,
        entries,
    })
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

fn inspect_database_path(path: &Path) -> Result<bool, JournalError> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Err(JournalError::InvalidPath);
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(database_io_error)?;
    if parent_metadata.file_type().is_symlink() {
        return Err(JournalError::SymlinkRejected);
    }
    if !parent_metadata.is_dir() {
        return Err(JournalError::InvalidPath);
    }

    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(JournalError::SymlinkRejected);
            }
            if !metadata.is_file() {
                return Err(JournalError::InvalidPath);
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(database_io_error(error)),
    };

    for suffix in ["-wal", "-shm"] {
        let sidecar = database_sidecar(path, suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(JournalError::SymlinkRejected);
                }
                if !metadata.is_file() || !existed {
                    return Err(JournalError::InvalidPath);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(database_io_error(error)),
        }
    }
    Ok(existed)
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
) -> Result<(), JournalError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE secure_journal_metadata (
           singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
           schema_version INTEGER NOT NULL CHECK(schema_version = 2),
           journal_id BLOB NOT NULL CHECK(length(journal_id) = 16)
         );
         CREATE TABLE secure_journal_entries (
           sequence INTEGER PRIMARY KEY NOT NULL,
           nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 24),
           ciphertext BLOB NOT NULL CHECK(length(ciphertext) >= 16),
           previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
           entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32)
         );",
    )?;
    connection.execute(
        "INSERT INTO secure_journal_metadata(singleton, schema_version, journal_id)\
         VALUES (1, ?1, ?2)",
        params![SCHEMA_VERSION, journal_id.as_slice()],
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
         PRAGMA user_version=2;
         COMMIT;",
    )?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), JournalError> {
    let required_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table'
           AND name IN ('secure_journal_metadata', 'secure_journal_entries')",
        [],
        |row| row.get(0),
    )?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if required_tables != 2 || user_version != SCHEMA_VERSION {
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
    if metadata_rows != 1 || schema_version != SCHEMA_VERSION {
        return Err(JournalError::UnsupportedFormat);
    }
    Ok(())
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
    for candidate in [
        path.to_path_buf(),
        database_sidecar(path, "-wal"),
        database_sidecar(path, "-shm"),
    ] {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(JournalError::SymlinkRejected);
                }
                if !metadata.is_file() {
                    return Err(JournalError::InvalidPath);
                }
                #[cfg(unix)]
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600))
                    .map_err(database_io_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
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
        env, process,
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
            self.0
                .lock()
                .map_err(|_| SecretStoreError::new("memory store lock failed"))?
                .key = Some(*key.expose_secret());
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
