#![forbid(unsafe_code)]
//! Native secure-state persistence for KernAid Resident mode.
//!
//! Journal encryption material and the Ed25519 device-identity seed are stored
//! only in the operating system's credential store. Values use a versioned,
//! purpose-bound base64url envelope so Linux Secret Service implementations
//! that only preserve UTF-8 values remain interoperable. This crate has no
//! plaintext or file-backed fallback.
//!
//! Device-identity creation must run behind the application's inter-process
//! single-instance lock. Its immediate readback detects missing, altered, and
//! overlapping writes, but a native keyring cannot prevent another process
//! from replacing the item after that verification completes.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kernaid_device_identity::DeviceIdentity;
use kernaid_storage::{
    JOURNAL_KEY_BYTES, JournalAnchor, JournalKey, JournalSecretStore, SecretStoreError,
};
use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use std::{error::Error, fmt, sync::Arc};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "io.github.0xfunboy.KernAid";
#[cfg(target_os = "windows")]
const WINDOWS_TARGET_PREFIX: &str = "KernAid/Resident";
const MIN_NAMESPACE_BYTES: usize = 1;
const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_ENVELOPE_BYTES: usize = 256;
const DEVICE_IDENTITY_SEED_BYTES: usize = 32;
const ENVELOPE_PREFIX: &[u8] = b"kernaid-secret-v1:";

#[cfg(any(target_os = "windows", test))]
use std::collections::HashMap;

/// A bounded namespace separating credentials for different KernAid profiles.
///
/// Namespaces are public identifiers, not secret material. They must start and
/// end with an ASCII alphanumeric character and may otherwise contain ASCII
/// alphanumerics, `.`, `_`, or `-`. Consecutive dots are rejected to avoid
/// confusing or ambiguous native credential names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretNamespace(String);

impl SecretNamespace {
    pub fn parse(value: &str) -> Result<Self, NativeSecretError> {
        if !is_valid_namespace(value) {
            return Err(NativeSecretError::InvalidNamespace);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Sanitized errors from native credential storage.
///
/// The variants deliberately contain no backend messages or stored values:
/// native errors can otherwise include credential names or secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSecretError {
    InvalidNamespace,
    UnsupportedPlatform,
    BackendUnavailable,
    StorageAccessDenied,
    AmbiguousEntry,
    InvalidStoredValue,
    InvalidRequest,
    IdentityAlreadyExists,
    ConcurrentIdentityWrite,
    WriteVerificationFailed,
}

impl fmt::Display for NativeSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNamespace => "invalid native-secret namespace",
            Self::UnsupportedPlatform => "native secure storage is unsupported on this platform",
            Self::BackendUnavailable => "native secure storage is unavailable",
            Self::StorageAccessDenied => "native secure storage is locked or access was denied",
            Self::AmbiguousEntry => "native secure storage contains ambiguous entries",
            Self::InvalidStoredValue => "native secure storage contains an invalid value",
            Self::InvalidRequest => "native secure storage rejected the credential name",
            Self::IdentityAlreadyExists => "a device identity already exists",
            Self::ConcurrentIdentityWrite => "the device identity changed during creation",
            Self::WriteVerificationFailed => "native secure storage did not persist the value",
        })
    }
}

impl Error for NativeSecretError {}

/// OS-keyring implementation of [`JournalSecretStore`].
///
/// Construct this independently from [`NativeDeviceIdentityStore`], then move
/// it into `kernaid_storage::SecureJournal`. A missing item is returned as
/// `None`; a locked, corrupt, or unavailable keyring is always an error.
pub struct NativeJournalSecretStore {
    state: NativeState,
}

impl NativeJournalSecretStore {
    pub fn open(namespace: SecretNamespace) -> Result<Self, NativeSecretError> {
        Ok(Self {
            state: NativeState::new(namespace, Box::new(KeyringBackend::open()?)),
        })
    }

    pub fn open_named(namespace: &str) -> Result<Self, NativeSecretError> {
        Self::open(SecretNamespace::parse(namespace)?)
    }

    #[cfg(test)]
    fn with_backend(namespace: SecretNamespace, backend: Box<dyn SecretBackend>) -> Self {
        Self {
            state: NativeState::new(namespace, backend),
        }
    }
}

impl JournalSecretStore for NativeJournalSecretStore {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        let Some(encoded) = self
            .state
            .load(SecretKind::JournalKey)
            .map_err(to_journal_error)?
        else {
            return Ok(None);
        };
        let decoded = decode_secret(SecretKind::JournalKey, &encoded).map_err(to_journal_error)?;
        let mut key = Zeroizing::new([0_u8; JOURNAL_KEY_BYTES]);
        key.copy_from_slice(&decoded);
        Ok(Some(JournalKey::from_zeroizing(key)))
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        self.state
            .store(SecretKind::JournalKey, key.expose_secret())
            .map_err(to_journal_error)
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        let Some(encoded) = self
            .state
            .load(SecretKind::JournalAnchor)
            .map_err(to_journal_error)?
        else {
            return Ok(None);
        };
        let decoded =
            decode_secret(SecretKind::JournalAnchor, &encoded).map_err(to_journal_error)?;
        JournalAnchor::from_bytes(&decoded)
            .map(Some)
            .map_err(|_| to_journal_error(NativeSecretError::InvalidStoredValue))
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        let encoded_anchor = anchor.to_bytes();
        self.state
            .store(SecretKind::JournalAnchor, &encoded_anchor)
            .map_err(to_journal_error)
    }
}

/// Explicit, fail-closed persistence for the Resident device identity.
///
/// `load_device_identity` never generates a replacement. Call
/// `create_device_identity` only after an explicit first-run decision. Creation
/// refuses to replace an existing or malformed entry and verifies the write by
/// loading it back. The seed is never returned by this API and all temporary
/// seed/envelope buffers are zeroized on drop.
pub struct NativeDeviceIdentityStore {
    state: NativeState,
}

impl NativeDeviceIdentityStore {
    pub fn open(namespace: SecretNamespace) -> Result<Self, NativeSecretError> {
        Ok(Self {
            state: NativeState::new(namespace, Box::new(KeyringBackend::open()?)),
        })
    }

    pub fn open_named(namespace: &str) -> Result<Self, NativeSecretError> {
        Self::open(SecretNamespace::parse(namespace)?)
    }

    /// Load the existing identity. A missing keyring entry is `Ok(None)` and
    /// remains missing; no identity is generated implicitly.
    pub fn load_device_identity(&mut self) -> Result<Option<DeviceIdentity>, NativeSecretError> {
        let Some(encoded) = self.state.load(SecretKind::DeviceIdentitySeed)? else {
            return Ok(None);
        };
        let seed = decode_secret(SecretKind::DeviceIdentitySeed, &encoded)?;
        DeviceIdentity::from_seed(&seed)
            .map(Some)
            .map_err(|_| NativeSecretError::InvalidStoredValue)
    }

    /// Store a caller-created identity only if the credential is absent.
    /// Existing and malformed entries are never overwritten.
    pub fn store_new_device_identity(
        &mut self,
        identity: &DeviceIdentity,
    ) -> Result<(), NativeSecretError> {
        if self.load_device_identity()?.is_some() {
            return Err(NativeSecretError::IdentityAlreadyExists);
        }

        let seed = identity.export_seed_for_encrypted_storage();
        self.state
            .store(SecretKind::DeviceIdentitySeed, seed.as_slice())?;

        let persisted = self
            .load_device_identity()?
            .ok_or(NativeSecretError::WriteVerificationFailed)?;
        if persisted.public_key() != identity.public_key() {
            return Err(NativeSecretError::ConcurrentIdentityWrite);
        }
        Ok(())
    }

    /// Generate and durably store an identity as an explicit first-run action.
    /// There is intentionally no load-or-create operation. The caller must
    /// hold an inter-process single-instance lock for the complete operation;
    /// immediate readback cannot rule out a later write by another process.
    pub fn create_device_identity(&mut self) -> Result<DeviceIdentity, NativeSecretError> {
        if self.load_device_identity()?.is_some() {
            return Err(NativeSecretError::IdentityAlreadyExists);
        }
        let identity = DeviceIdentity::generate();
        self.store_new_device_identity(&identity)?;
        Ok(identity)
    }

    #[cfg(test)]
    fn with_backend(namespace: SecretNamespace, backend: Box<dyn SecretBackend>) -> Self {
        Self {
            state: NativeState::new(namespace, backend),
        }
    }
}

struct NativeState {
    namespace: SecretNamespace,
    backend: Box<dyn SecretBackend>,
}

impl NativeState {
    fn new(namespace: SecretNamespace, backend: Box<dyn SecretBackend>) -> Self {
        Self { namespace, backend }
    }

    fn load(&mut self, kind: SecretKind) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
        self.backend
            .get(&CredentialName::new(&self.namespace, kind))
    }

    fn store(&mut self, kind: SecretKind, value: &[u8]) -> Result<(), NativeSecretError> {
        let envelope = encode_secret(kind, value)?;
        let name = CredentialName::new(&self.namespace, kind);
        self.backend.set(&name, &envelope)?;
        let persisted = self
            .backend
            .get(&name)?
            .ok_or(NativeSecretError::WriteVerificationFailed)?;
        if persisted.as_slice() != envelope.as_slice() {
            return Err(NativeSecretError::WriteVerificationFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretKind {
    JournalKey,
    JournalAnchor,
    DeviceIdentitySeed,
}

impl SecretKind {
    const fn label(self) -> &'static str {
        match self {
            Self::JournalKey => "journal-key-v1",
            Self::JournalAnchor => "journal-anchor-v2",
            Self::DeviceIdentitySeed => "device-identity-seed-v1",
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::JournalKey => JOURNAL_KEY_BYTES,
            Self::JournalAnchor => JournalAnchor::ENCODED_BYTES,
            Self::DeviceIdentitySeed => DEVICE_IDENTITY_SEED_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CredentialName {
    service: &'static str,
    account: String,
    #[cfg(target_os = "windows")]
    windows_target: String,
}

impl CredentialName {
    fn new(namespace: &SecretNamespace, kind: SecretKind) -> Self {
        let account = format!("{}:{}", namespace.as_str(), kind.label());
        Self {
            service: SERVICE_NAME,
            #[cfg(target_os = "windows")]
            windows_target: format!(
                "{WINDOWS_TARGET_PREFIX}/{}/{}",
                namespace.as_str(),
                kind.label()
            ),
            account,
        }
    }
}

trait SecretBackend: Send {
    fn get(
        &mut self,
        name: &CredentialName,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError>;
    fn set(&mut self, name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError>;
}

struct KeyringBackend {
    store: Arc<CredentialStore>,
}

impl KeyringBackend {
    fn open() -> Result<Self, NativeSecretError> {
        Ok(Self {
            store: platform_store()?,
        })
    }

    #[cfg(target_os = "windows")]
    fn entry(&self, name: &CredentialName) -> keyring_core::Result<Entry> {
        let modifiers = HashMap::from([
            ("target", name.windows_target.as_str()),
            ("persistence", "Local"),
        ]);
        self.store
            .build(name.service, &name.account, Some(&modifiers))
    }

    #[cfg(not(target_os = "windows"))]
    fn entry(&self, name: &CredentialName) -> keyring_core::Result<Entry> {
        self.store.build(name.service, &name.account, None)
    }
}

impl SecretBackend for KeyringBackend {
    fn get(
        &mut self,
        name: &CredentialName,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
        let entry = match self.entry(name) {
            Ok(entry) => entry,
            Err(KeyringError::NoEntry) => return Ok(None),
            Err(error) => return Err(sanitize_keyring_error(error)),
        };
        match entry.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(sanitize_keyring_error(error)),
        }
    }

    fn set(&mut self, name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
        self.entry(name)
            .map_err(sanitize_keyring_error)?
            .set_secret(value)
            .map_err(sanitize_keyring_error)
    }
}

#[cfg(target_os = "windows")]
fn platform_store() -> Result<Arc<CredentialStore>, NativeSecretError> {
    let store = windows_native_keyring_store::Store::new().map_err(sanitize_keyring_error)?;
    Ok(store)
}

#[cfg(target_os = "macos")]
fn platform_store() -> Result<Arc<CredentialStore>, NativeSecretError> {
    let store =
        apple_native_keyring_store::keychain::Store::new().map_err(sanitize_keyring_error)?;
    Ok(store)
}

#[cfg(target_os = "linux")]
fn platform_store() -> Result<Arc<CredentialStore>, NativeSecretError> {
    let store = zbus_secret_service_keyring_store::Store::new().map_err(sanitize_keyring_error)?;
    Ok(store)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_store() -> Result<Arc<CredentialStore>, NativeSecretError> {
    Err(NativeSecretError::UnsupportedPlatform)
}

fn sanitize_keyring_error(error: KeyringError) -> NativeSecretError {
    match error {
        KeyringError::NoStorageAccess(_) => NativeSecretError::StorageAccessDenied,
        KeyringError::Ambiguous(_) => NativeSecretError::AmbiguousEntry,
        KeyringError::BadEncoding(_)
        | KeyringError::BadDataFormat(_, _)
        | KeyringError::BadStoreFormat(_) => NativeSecretError::InvalidStoredValue,
        KeyringError::Invalid(_, _) | KeyringError::TooLong(_, _) => {
            NativeSecretError::InvalidRequest
        }
        KeyringError::NoEntry
        | KeyringError::PlatformFailure(_)
        | KeyringError::NoDefaultStore
        | KeyringError::NotSupportedByStore(_) => NativeSecretError::BackendUnavailable,
        _ => NativeSecretError::BackendUnavailable,
    }
}

fn encode_secret(kind: SecretKind, value: &[u8]) -> Result<Zeroizing<Vec<u8>>, NativeSecretError> {
    if value.len() != kind.bytes() {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.encode(value));
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        ENVELOPE_PREFIX.len() + kind.label().len() + 1 + payload.len(),
    ));
    envelope.extend_from_slice(ENVELOPE_PREFIX);
    envelope.extend_from_slice(kind.label().as_bytes());
    envelope.push(b':');
    envelope.extend_from_slice(payload.as_bytes());
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    Ok(envelope)
}

fn decode_secret(
    kind: SecretKind,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NativeSecretError> {
    if envelope.len() > MAX_ENVELOPE_BYTES || !envelope.starts_with(ENVELOPE_PREFIX) {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    let remainder = &envelope[ENVELOPE_PREFIX.len()..];
    let Some(separator) = remainder.iter().position(|byte| *byte == b':') else {
        return Err(NativeSecretError::InvalidStoredValue);
    };
    let (encoded_kind, payload_with_separator) = remainder.split_at(separator);
    let payload = &payload_with_separator[1..];
    if encoded_kind != kind.label().as_bytes() || payload.is_empty() || payload.contains(&b'=') {
        return Err(NativeSecretError::InvalidStoredValue);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map(Zeroizing::new)
        .map_err(|_| NativeSecretError::InvalidStoredValue)?;
    if decoded.len() != kind.bytes() {
        return Err(NativeSecretError::InvalidStoredValue);
    }

    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_bytes() != payload {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    Ok(decoded)
}

fn is_valid_namespace(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(MIN_NAMESPACE_BYTES..=MAX_NAMESPACE_BYTES).contains(&bytes.len()) {
        return false;
    }
    if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !bytes.windows(2).any(|pair| pair == b"..")
}

fn to_journal_error(error: NativeSecretError) -> SecretStoreError {
    SecretStoreError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct MemoryBackend {
        values: Arc<Mutex<HashMap<CredentialName, Vec<u8>>>>,
    }

    impl MemoryBackend {
        fn value(&self, name: &CredentialName) -> Option<Vec<u8>> {
            self.values
                .lock()
                .expect("memory backend lock")
                .get(name)
                .cloned()
        }

        fn replace(&self, name: CredentialName, value: Vec<u8>) {
            self.values
                .lock()
                .expect("memory backend lock")
                .insert(name, value);
        }
    }

    impl SecretBackend for MemoryBackend {
        fn get(
            &mut self,
            name: &CredentialName,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
            Ok(self.value(name).map(Zeroizing::new))
        }

        fn set(&mut self, name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
            self.replace(name.clone(), value.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum FaultyWrite {
        Omit,
        Alter,
    }

    struct FaultyWriteBackend {
        behavior: FaultyWrite,
        value: Option<Vec<u8>>,
    }

    impl FaultyWriteBackend {
        fn new(behavior: FaultyWrite) -> Self {
            Self {
                behavior,
                value: None,
            }
        }
    }

    impl SecretBackend for FaultyWriteBackend {
        fn get(
            &mut self,
            _name: &CredentialName,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
            Ok(self.value.clone().map(Zeroizing::new))
        }

        fn set(&mut self, _name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
            match self.behavior {
                FaultyWrite::Omit => self.value = None,
                FaultyWrite::Alter => {
                    let mut altered = value.to_vec();
                    if let Some(last) = altered.last_mut() {
                        *last ^= 1;
                    }
                    self.value = Some(altered);
                }
            }
            Ok(())
        }
    }

    fn namespace() -> SecretNamespace {
        SecretNamespace::parse("resident-test-01").expect("valid test namespace")
    }

    #[test]
    fn namespace_is_strict_and_bounded() {
        for valid in ["a", "resident-01_lab.eu", "A0"] {
            assert!(SecretNamespace::parse(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "-resident", "resident.", "a..b", "with space", "a/b"] {
            assert!(
                matches!(
                    SecretNamespace::parse(invalid),
                    Err(NativeSecretError::InvalidNamespace)
                ),
                "{invalid}"
            );
        }
        let oversized = "a".repeat(MAX_NAMESPACE_BYTES + 1);
        assert!(matches!(
            SecretNamespace::parse(&oversized),
            Err(NativeSecretError::InvalidNamespace)
        ));
    }

    #[test]
    fn journal_values_roundtrip_through_versioned_base64url() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let mut store =
            NativeJournalSecretStore::with_backend(namespace.clone(), Box::new(backend));
        let key_bytes = Zeroizing::new([0xA5_u8; JOURNAL_KEY_BYTES]);
        let key = JournalKey::from_zeroizing(key_bytes);
        store.store_key(&key).expect("store journal key");

        let persisted = observer
            .value(&CredentialName::new(&namespace, SecretKind::JournalKey))
            .expect("persisted key envelope");
        assert!(persisted.starts_with(b"kernaid-secret-v1:journal-key-v1:"));
        assert!(!persisted.contains(&b'='));
        assert!(!persisted.windows(8).any(|window| window == [0xA5; 8]));

        let loaded = store
            .load_key()
            .expect("load journal key")
            .expect("journal key exists");
        assert_eq!(loaded.expose_secret(), &[0xA5; JOURNAL_KEY_BYTES]);
    }

    #[test]
    fn missing_items_are_none_and_wrong_purpose_is_rejected() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let mut store =
            NativeJournalSecretStore::with_backend(namespace.clone(), Box::new(backend));
        assert!(store.load_key().expect("missing key lookup").is_none());
        assert!(
            store
                .load_anchor()
                .expect("missing anchor lookup")
                .is_none()
        );

        let anchor = JournalAnchor {
            journal_id: [1; 16],
            sequence: 7,
            entry_hash: [2; 32],
        };
        let wrong_envelope = encode_secret(SecretKind::JournalAnchor, &anchor.to_bytes())
            .expect("encode anchor")
            .to_vec();
        observer.replace(
            CredentialName::new(&namespace, SecretKind::JournalKey),
            wrong_envelope,
        );
        assert!(store.load_key().is_err());
    }

    #[test]
    fn journal_write_requires_an_exact_keyring_readback() {
        let key = JournalKey::from_zeroizing(Zeroizing::new([0x5A; JOURNAL_KEY_BYTES]));
        for behavior in [FaultyWrite::Omit, FaultyWrite::Alter] {
            let backend = FaultyWriteBackend::new(behavior);
            let mut store = NativeJournalSecretStore::with_backend(namespace(), Box::new(backend));
            let error = store.store_key(&key).expect_err("faulty write must fail");
            assert_eq!(
                error.to_string(),
                NativeSecretError::WriteVerificationFailed.to_string()
            );
        }
    }

    #[test]
    fn device_identity_requires_explicit_creation_and_is_not_replaced() {
        let backend = MemoryBackend::default();
        let namespace = namespace();
        let mut store =
            NativeDeviceIdentityStore::with_backend(namespace, Box::new(backend.clone()));

        assert!(
            store
                .load_device_identity()
                .expect("missing identity lookup")
                .is_none()
        );
        assert!(
            store
                .load_device_identity()
                .expect("second missing identity lookup")
                .is_none()
        );

        let created = store.create_device_identity().expect("create identity");
        let loaded = store
            .load_device_identity()
            .expect("load identity")
            .expect("identity exists");
        assert_eq!(loaded.public_key(), created.public_key());
        assert!(matches!(
            store.create_device_identity(),
            Err(NativeSecretError::IdentityAlreadyExists)
        ));

        let replacement = DeviceIdentity::generate();
        assert!(matches!(
            store.store_new_device_identity(&replacement),
            Err(NativeSecretError::IdentityAlreadyExists)
        ));
    }

    #[test]
    fn malformed_identity_is_an_error_not_a_first_run_signal() {
        let backend = MemoryBackend::default();
        let namespace = namespace();
        backend.replace(
            CredentialName::new(&namespace, SecretKind::DeviceIdentitySeed),
            b"not-an-envelope".to_vec(),
        );
        let mut store = NativeDeviceIdentityStore::with_backend(namespace, Box::new(backend));
        assert!(matches!(
            store.load_device_identity(),
            Err(NativeSecretError::InvalidStoredValue)
        ));
        assert!(matches!(
            store.create_device_identity(),
            Err(NativeSecretError::InvalidStoredValue)
        ));
    }
}
