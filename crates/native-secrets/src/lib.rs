#![forbid(unsafe_code)]
//! Native secure-state persistence for KernAid Resident mode.
//!
//! Journal encryption material, the Ed25519 device-identity seed, and bounded
//! provider credentials are stored only in the operating system's credential
//! store. Values use versioned, purpose-bound base64url envelopes so Linux
//! Secret Service implementations that only preserve UTF-8 values remain
//! interoperable. This crate has no plaintext or file-backed fallback.
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
const MAX_PROVIDER_ENVELOPE_BYTES: usize = 1024;
const DEVICE_IDENTITY_SEED_BYTES: usize = 32;
const ENVELOPE_PREFIX: &[u8] = b"kernaid-secret-v1:";
const PROVIDER_ENVELOPE_PREFIX: &[u8] = b"kernaid-provider-secret-v1:";
const OPENAI_API_KEY_LABEL: &[u8] = b"openai-api-key-v1";
const MIN_PROVIDER_PROFILE_ID_BYTES: usize = 1;
/// Maximum byte length accepted for a Resident OpenAI API key.
///
/// The conservative 512-byte cross-platform limit leaves the complete
/// purpose-bound base64url envelope below 1 KiB, comfortably within the
/// Windows Credential Manager generic-credential blob limit.
pub const MAX_OPENAI_API_KEY_BYTES: usize = 512;
/// Maximum byte length of a public Resident provider-profile identifier.
pub const MAX_PROVIDER_PROFILE_ID_BYTES: usize = 48;

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

/// Public, non-secret identifier for one OpenAI credential profile.
///
/// Profile identifiers contain only lowercase ASCII letters, digits, and
/// single internal `-` separators. They must start and end with an
/// alphanumeric character. The strict grammar keeps native credential names
/// unambiguous and prevents path-like or backend-specific identifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderProfileId(String);

impl ProviderProfileId {
    pub fn parse(value: &str) -> Result<Self, NativeSecretError> {
        if !is_valid_provider_profile_id(value) {
            return Err(NativeSecretError::InvalidProviderProfile);
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
    InvalidProviderProfile,
    InvalidProviderCredential,
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
            Self::InvalidProviderProfile => "invalid provider-profile identifier",
            Self::InvalidProviderCredential => "invalid provider credential",
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

/// Presence-only state for one Resident provider credential.
///
/// A corrupt or inaccessible item is returned as a sanitized error rather than
/// being collapsed into `Absent` or exposed to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeProviderSecretStatus {
    Absent,
    Configured,
}

/// OS-keyring storage for one profiled OpenAI API key in Resident mode.
///
/// The key is never returned by a public getter. Backend-only consumers can
/// borrow it for the duration of [`Self::with_openai_api_key`]. Configure and
/// logout both verify their result with an immediate readback. Callers should
/// hold the application's inter-process single-instance lock across each
/// operation; a native keyring cannot prevent a later external replacement.
pub struct NativeOpenAiApiKeyStore {
    namespace: SecretNamespace,
    profile: ProviderProfileId,
    backend: Box<dyn SecretBackend>,
}

impl NativeOpenAiApiKeyStore {
    pub fn open(
        namespace: SecretNamespace,
        profile: ProviderProfileId,
    ) -> Result<Self, NativeSecretError> {
        Ok(Self {
            namespace,
            profile,
            backend: Box::new(KeyringBackend::open()?),
        })
    }

    pub fn open_named(namespace: &str, profile: &str) -> Result<Self, NativeSecretError> {
        Self::open(
            SecretNamespace::parse(namespace)?,
            ProviderProfileId::parse(profile)?,
        )
    }

    /// Return only whether the profile has a valid configured credential.
    pub fn status(&mut self) -> Result<NativeProviderSecretStatus, NativeSecretError> {
        Ok(if self.load_openai_api_key()?.is_some() {
            NativeProviderSecretStatus::Configured
        } else {
            NativeProviderSecretStatus::Absent
        })
    }

    /// Replace or create the profile credential and verify the exact envelope.
    ///
    /// The supplied allocation is zeroized on return, including validation and
    /// backend error paths. Accepted credentials are non-empty, visible ASCII
    /// without whitespace or control bytes, and at most
    /// [`MAX_OPENAI_API_KEY_BYTES`] bytes. No provider-prefix assumption is
    /// made.
    pub fn configure(&mut self, api_key: Zeroizing<Vec<u8>>) -> Result<(), NativeSecretError> {
        validate_openai_api_key(&api_key)
            .map_err(|()| NativeSecretError::InvalidProviderCredential)?;
        let envelope = encode_provider_secret(&self.namespace, &self.profile, &api_key)?;
        let name = CredentialName::provider(&self.namespace, &self.profile);
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

    /// Borrow the configured credential inside the Rust backend only.
    ///
    /// The decoded allocation is zeroized immediately after the callback
    /// returns. `Ok(None)` means the profile is not configured. This method is
    /// not a frontend or serialization boundary.
    pub fn with_openai_api_key<T>(
        &mut self,
        use_secret: impl FnOnce(&[u8]) -> T,
    ) -> Result<Option<T>, NativeSecretError> {
        let Some(api_key) = self.load_openai_api_key()? else {
            return Ok(None);
        };
        Ok(Some(use_secret(&api_key)))
    }

    /// Idempotently delete the profile credential and verify its absence.
    pub fn logout(&mut self) -> Result<(), NativeSecretError> {
        let name = CredentialName::provider(&self.namespace, &self.profile);
        self.backend.delete(&name)?;
        if self.backend.get(&name)?.is_some() {
            return Err(NativeSecretError::WriteVerificationFailed);
        }
        Ok(())
    }

    fn load_openai_api_key(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
        let name = CredentialName::provider(&self.namespace, &self.profile);
        let Some(envelope) = self.backend.get(&name)? else {
            return Ok(None);
        };
        decode_provider_secret(&self.namespace, &self.profile, &envelope).map(Some)
    }

    #[cfg(test)]
    fn with_backend(
        namespace: SecretNamespace,
        profile: ProviderProfileId,
        backend: Box<dyn SecretBackend>,
    ) -> Self {
        Self {
            namespace,
            profile,
            backend,
        }
    }
}

/// OS-keyring implementation of [`JournalSecretStore`].
///
/// Construct this independently from [`NativeDeviceIdentityStore`], then move
/// it into `kernaid_storage::SecureJournal`. A missing item is returned as
/// `None`; a locked, corrupt, or unavailable keyring is always an error.
pub struct NativeJournalSecretStore {
    state: NativeState,
}

/// Strict presence state for the journal key and anchor pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeJournalState {
    Empty,
    Complete,
    Partial,
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

    /// Inspect both strictly decoded journal credentials without collapsing
    /// native backend errors into the generic storage trait error.
    pub fn inspect_state(&mut self) -> Result<NativeJournalState, NativeSecretError> {
        let key = self.load_key_native()?;
        let anchor = self.load_anchor_native()?;
        Ok(match (key.is_some(), anchor.is_some()) {
            (false, false) => NativeJournalState::Empty,
            (true, true) => NativeJournalState::Complete,
            _ => NativeJournalState::Partial,
        })
    }

    fn load_key_native(&mut self) -> Result<Option<JournalKey>, NativeSecretError> {
        let Some(encoded) = self.state.load(SecretKind::JournalKey)? else {
            return Ok(None);
        };
        let decoded = decode_secret(SecretKind::JournalKey, &encoded)?;
        let mut key = Zeroizing::new([0_u8; JOURNAL_KEY_BYTES]);
        key.copy_from_slice(&decoded);
        Ok(Some(JournalKey::from_zeroizing(key)))
    }

    fn load_anchor_native(&mut self) -> Result<Option<JournalAnchor>, NativeSecretError> {
        let Some(encoded) = self.state.load(SecretKind::JournalAnchor)? else {
            return Ok(None);
        };
        let decoded = decode_secret(SecretKind::JournalAnchor, &encoded)?;
        JournalAnchor::from_bytes(&decoded)
            .map(Some)
            .map_err(|_| NativeSecretError::InvalidStoredValue)
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
        self.load_key_native().map_err(to_journal_error)
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        self.state
            .store(SecretKind::JournalKey, key.expose_secret())
            .map_err(to_journal_error)
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        self.load_anchor_native().map_err(to_journal_error)
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

    fn provider(namespace: &SecretNamespace, profile: &ProviderProfileId) -> Self {
        let account = format!(
            "{}:provider:openai:{}:api-key-v1",
            namespace.as_str(),
            profile.as_str()
        );
        Self {
            service: SERVICE_NAME,
            #[cfg(target_os = "windows")]
            windows_target: format!(
                "{WINDOWS_TARGET_PREFIX}/{}/provider/openai/{}/api-key-v1",
                namespace.as_str(),
                profile.as_str()
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
    /// Delete is idempotent: a missing credential is successful.
    fn delete(&mut self, name: &CredentialName) -> Result<(), NativeSecretError>;
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

    fn delete(&mut self, name: &CredentialName) -> Result<(), NativeSecretError> {
        let entry = match self.entry(name) {
            Ok(entry) => entry,
            Err(KeyringError::NoEntry) => return Ok(()),
            Err(error) => return Err(sanitize_keyring_error(error)),
        };
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(sanitize_keyring_error(error)),
        }
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

fn encode_provider_secret(
    namespace: &SecretNamespace,
    profile: &ProviderProfileId,
    value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NativeSecretError> {
    validate_openai_api_key(value).map_err(|()| NativeSecretError::InvalidProviderCredential)?;
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.encode(value));
    let prefix = provider_envelope_purpose(namespace, profile);
    let mut envelope = Zeroizing::new(Vec::with_capacity(prefix.len() + payload.len()));
    envelope.extend_from_slice(&prefix);
    envelope.extend_from_slice(payload.as_bytes());
    if envelope.len() > MAX_PROVIDER_ENVELOPE_BYTES {
        return Err(NativeSecretError::InvalidProviderCredential);
    }
    Ok(envelope)
}

fn decode_provider_secret(
    namespace: &SecretNamespace,
    profile: &ProviderProfileId,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NativeSecretError> {
    if envelope.len() > MAX_PROVIDER_ENVELOPE_BYTES {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    let prefix = provider_envelope_purpose(namespace, profile);
    let Some(payload) = envelope.strip_prefix(prefix.as_slice()) else {
        return Err(NativeSecretError::InvalidStoredValue);
    };
    if payload.is_empty() || payload.contains(&b'=') {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map(Zeroizing::new)
        .map_err(|_| NativeSecretError::InvalidStoredValue)?;
    validate_openai_api_key(&decoded).map_err(|()| NativeSecretError::InvalidStoredValue)?;
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_bytes() != payload {
        return Err(NativeSecretError::InvalidStoredValue);
    }
    Ok(decoded)
}

fn provider_envelope_purpose(
    namespace: &SecretNamespace,
    profile: &ProviderProfileId,
) -> Zeroizing<Vec<u8>> {
    let mut prefix = Zeroizing::new(Vec::with_capacity(
        PROVIDER_ENVELOPE_PREFIX.len()
            + namespace.as_str().len()
            + OPENAI_API_KEY_LABEL.len()
            + profile.as_str().len()
            + 3,
    ));
    prefix.extend_from_slice(PROVIDER_ENVELOPE_PREFIX);
    prefix.extend_from_slice(namespace.as_str().as_bytes());
    prefix.push(b':');
    prefix.extend_from_slice(OPENAI_API_KEY_LABEL);
    prefix.push(b':');
    prefix.extend_from_slice(profile.as_str().as_bytes());
    prefix.push(b':');
    prefix
}

fn validate_openai_api_key(value: &[u8]) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > MAX_OPENAI_API_KEY_BYTES
        || !value.iter().all(|byte| matches!(byte, 0x21..=0x7e))
    {
        return Err(());
    }
    Ok(())
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

fn is_valid_provider_profile_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(MIN_PROVIDER_PROFILE_ID_BYTES..=MAX_PROVIDER_PROFILE_ID_BYTES).contains(&bytes.len()) {
        return false;
    }
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
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
        values: Arc<Mutex<HashMap<CredentialName, Zeroizing<Vec<u8>>>>>,
    }

    impl MemoryBackend {
        fn value(&self, name: &CredentialName) -> Option<Zeroizing<Vec<u8>>> {
            self.values
                .lock()
                .expect("memory backend lock")
                .get(name)
                .cloned()
        }

        fn replace(&self, name: CredentialName, value: Zeroizing<Vec<u8>>) {
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
            Ok(self.value(name))
        }

        fn set(&mut self, name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
            self.replace(name.clone(), Zeroizing::new(value.to_vec()));
            Ok(())
        }

        fn delete(&mut self, name: &CredentialName) -> Result<(), NativeSecretError> {
            self.values
                .lock()
                .expect("memory backend lock")
                .remove(name);
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
        value: Option<Zeroizing<Vec<u8>>>,
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
            Ok(self.value.clone())
        }

        fn set(&mut self, _name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
            match self.behavior {
                FaultyWrite::Omit => self.value = None,
                FaultyWrite::Alter => {
                    let mut altered = value.to_vec();
                    if let Some(last) = altered.last_mut() {
                        *last ^= 1;
                    }
                    self.value = Some(Zeroizing::new(altered));
                }
            }
            Ok(())
        }

        fn delete(&mut self, _name: &CredentialName) -> Result<(), NativeSecretError> {
            self.value = None;
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum FaultyDelete {
        Error,
        Retain,
    }

    struct FaultyDeleteBackend {
        behavior: FaultyDelete,
        value: Option<Zeroizing<Vec<u8>>>,
    }

    impl FaultyDeleteBackend {
        fn new(behavior: FaultyDelete) -> Self {
            Self {
                behavior,
                value: None,
            }
        }
    }

    impl SecretBackend for FaultyDeleteBackend {
        fn get(
            &mut self,
            _name: &CredentialName,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
            Ok(self.value.clone())
        }

        fn set(&mut self, _name: &CredentialName, value: &[u8]) -> Result<(), NativeSecretError> {
            self.value = Some(Zeroizing::new(value.to_vec()));
            Ok(())
        }

        fn delete(&mut self, _name: &CredentialName) -> Result<(), NativeSecretError> {
            match self.behavior {
                FaultyDelete::Error => Err(NativeSecretError::StorageAccessDenied),
                FaultyDelete::Retain => Ok(()),
            }
        }
    }

    struct AmbiguousBackend;

    impl SecretBackend for AmbiguousBackend {
        fn get(
            &mut self,
            _name: &CredentialName,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, NativeSecretError> {
            Err(NativeSecretError::AmbiguousEntry)
        }

        fn set(&mut self, _name: &CredentialName, _value: &[u8]) -> Result<(), NativeSecretError> {
            Err(NativeSecretError::AmbiguousEntry)
        }

        fn delete(&mut self, _name: &CredentialName) -> Result<(), NativeSecretError> {
            Err(NativeSecretError::AmbiguousEntry)
        }
    }

    fn namespace() -> SecretNamespace {
        SecretNamespace::parse("resident-test-01").expect("valid test namespace")
    }

    fn profile() -> ProviderProfileId {
        ProviderProfileId::parse("technician-01").expect("valid test profile")
    }

    fn synthetic_api_key(length: usize) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            (0..length)
                .map(|index| b'A' + u8::try_from(index % 26).expect("bounded alphabet index"))
                .collect(),
        )
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
    fn provider_profile_id_is_strict_and_bounded() {
        for valid in ["a", "default", "technician-01", "0"] {
            assert!(ProviderProfileId::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "-profile",
            "profile-",
            "two--separators",
            "Uppercase",
            "under_score",
            "with.dot",
            "with space",
            "a/b",
            "é",
        ] {
            assert!(
                matches!(
                    ProviderProfileId::parse(invalid),
                    Err(NativeSecretError::InvalidProviderProfile)
                ),
                "{invalid}"
            );
        }
        let maximum = "a".repeat(MAX_PROVIDER_PROFILE_ID_BYTES);
        assert!(ProviderProfileId::parse(&maximum).is_ok());
        let oversized = "a".repeat(MAX_PROVIDER_PROFILE_ID_BYTES + 1);
        assert!(matches!(
            ProviderProfileId::parse(&oversized),
            Err(NativeSecretError::InvalidProviderProfile)
        ));
    }

    #[test]
    fn existing_credential_names_and_envelopes_remain_compatible() {
        let namespace = namespace();
        let name = CredentialName::new(&namespace, SecretKind::JournalKey);
        assert_eq!(name.account, "resident-test-01:journal-key-v1");
        #[cfg(target_os = "windows")]
        assert_eq!(
            name.windows_target,
            "KernAid/Resident/resident-test-01/journal-key-v1"
        );

        let value = Zeroizing::new([0x3C_u8; JOURNAL_KEY_BYTES]);
        let envelope = encode_secret(SecretKind::JournalKey, value.as_slice())
            .expect("encode legacy envelope");
        assert!(envelope.starts_with(b"kernaid-secret-v1:journal-key-v1:"));
        assert_eq!(
            decode_secret(SecretKind::JournalKey, &envelope)
                .expect("decode legacy envelope")
                .as_slice(),
            value.as_slice()
        );
    }

    #[test]
    fn profiled_openai_key_roundtrips_without_a_public_value_status() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let profile = profile();
        let name = CredentialName::provider(&namespace, &profile);
        let mut store = NativeOpenAiApiKeyStore::with_backend(
            namespace.clone(),
            profile.clone(),
            Box::new(backend),
        );
        assert_eq!(
            store.status().expect("empty provider status"),
            NativeProviderSecretStatus::Absent
        );

        let expected = synthetic_api_key(96);
        store
            .configure(Zeroizing::new(expected.to_vec()))
            .expect("configure provider credential");
        assert_eq!(
            store.status().expect("configured provider status"),
            NativeProviderSecretStatus::Configured
        );

        assert_eq!(
            name.account,
            "resident-test-01:provider:openai:technician-01:api-key-v1"
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            name.windows_target,
            "KernAid/Resident/resident-test-01/provider/openai/technician-01/api-key-v1"
        );
        let persisted = observer.value(&name).expect("provider envelope exists");
        assert!(persisted.starts_with(
            b"kernaid-provider-secret-v1:resident-test-01:openai-api-key-v1:technician-01:"
        ));
        assert!(persisted.len() <= MAX_PROVIDER_ENVELOPE_BYTES);
        assert!(
            !persisted
                .windows(expected.len())
                .any(|window| window == expected.as_slice())
        );

        let matched = store
            .with_openai_api_key(|loaded| loaded == expected.as_slice())
            .expect("borrow provider credential");
        assert_eq!(matched, Some(true));
    }

    #[test]
    fn openai_key_validation_enforces_boundaries_and_visible_ascii() {
        let backend = MemoryBackend::default();
        let mut store =
            NativeOpenAiApiKeyStore::with_backend(namespace(), profile(), Box::new(backend));
        for length in [1, MAX_OPENAI_API_KEY_BYTES] {
            store
                .configure(synthetic_api_key(length))
                .expect("boundary credential is valid");
        }

        let mut invalid_values = vec![
            Zeroizing::new(Vec::new()),
            synthetic_api_key(MAX_OPENAI_API_KEY_BYTES + 1),
        ];
        for byte in [0x00, 0x09, 0x0a, 0x1f, 0x20, 0x7f, 0x80] {
            invalid_values.push(Zeroizing::new(vec![b'A', byte, b'Z']));
        }
        for invalid in invalid_values {
            assert!(matches!(
                store.configure(invalid),
                Err(NativeSecretError::InvalidProviderCredential)
            ));
        }
        assert_eq!(
            store.status().expect("prior valid value remains"),
            NativeProviderSecretStatus::Configured
        );
    }

    #[test]
    fn provider_envelopes_reject_corruption_and_wrong_purpose() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let first_profile = profile();
        let second_profile =
            ProviderProfileId::parse("technician-02").expect("valid second profile");
        let first_name = CredentialName::provider(&namespace, &first_profile);
        let second_name = CredentialName::provider(&namespace, &second_profile);
        let mut first = NativeOpenAiApiKeyStore::with_backend(
            namespace.clone(),
            first_profile,
            Box::new(backend.clone()),
        );
        first
            .configure(synthetic_api_key(64))
            .expect("configure first profile");
        let first_envelope = observer.value(&first_name).expect("first envelope exists");

        observer.replace(second_name, first_envelope);
        let mut second = NativeOpenAiApiKeyStore::with_backend(
            namespace.clone(),
            second_profile,
            Box::new(backend.clone()),
        );
        assert!(matches!(
            second.status(),
            Err(NativeSecretError::InvalidStoredValue)
        ));

        let wrong_kind = encode_secret(
            SecretKind::JournalKey,
            Zeroizing::new([0x71_u8; JOURNAL_KEY_BYTES]).as_slice(),
        )
        .expect("encode different purpose");
        observer.replace(first_name.clone(), wrong_kind);
        assert!(matches!(
            first.status(),
            Err(NativeSecretError::InvalidStoredValue)
        ));

        observer.replace(
            first_name,
            Zeroizing::new(b"corrupt-provider-envelope".to_vec()),
        );
        assert!(matches!(
            first.with_openai_api_key(|_| ()),
            Err(NativeSecretError::InvalidStoredValue)
        ));
    }

    #[test]
    fn provider_configure_requires_an_exact_keyring_readback() {
        for behavior in [FaultyWrite::Omit, FaultyWrite::Alter] {
            let backend = FaultyWriteBackend::new(behavior);
            let mut store =
                NativeOpenAiApiKeyStore::with_backend(namespace(), profile(), Box::new(backend));
            assert!(matches!(
                store.configure(synthetic_api_key(64)),
                Err(NativeSecretError::WriteVerificationFailed)
            ));
        }
    }

    #[test]
    fn provider_logout_is_idempotent_and_verifies_absence() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let profile = profile();
        let name = CredentialName::provider(&namespace, &profile);
        let mut store =
            NativeOpenAiApiKeyStore::with_backend(namespace, profile, Box::new(backend));

        store.logout().expect("missing credential logout");
        store
            .configure(synthetic_api_key(72))
            .expect("configure before logout");
        assert!(observer.value(&name).is_some());
        store.logout().expect("configured credential logout");
        assert!(observer.value(&name).is_none());
        assert_eq!(
            store.status().expect("status after logout"),
            NativeProviderSecretStatus::Absent
        );
        store.logout().expect("second logout remains successful");
    }

    #[test]
    fn provider_logout_fails_closed_on_delete_error_or_retained_value() {
        for (behavior, expected) in [
            (FaultyDelete::Error, NativeSecretError::StorageAccessDenied),
            (
                FaultyDelete::Retain,
                NativeSecretError::WriteVerificationFailed,
            ),
        ] {
            let mut store = NativeOpenAiApiKeyStore::with_backend(
                namespace(),
                profile(),
                Box::new(FaultyDeleteBackend::new(behavior)),
            );
            let secret = synthetic_api_key(80);
            store
                .configure(Zeroizing::new(secret.to_vec()))
                .expect("configure before faulty delete");
            let error = store.logout().expect_err("faulty delete must fail");
            assert_eq!(error, expected);
            assert!(!error.to_string().contains(profile().as_str()));
            let secret_text = Zeroizing::new(
                String::from_utf8(secret.to_vec()).expect("visible ASCII test value"),
            );
            assert!(!error.to_string().contains(secret_text.as_str()));
        }
    }

    #[test]
    fn provider_status_preserves_ambiguous_backend_errors() {
        let mut store = NativeOpenAiApiKeyStore::with_backend(
            namespace(),
            profile(),
            Box::new(AmbiguousBackend),
        );
        let error = store.status().expect_err("ambiguous lookup must fail");
        assert_eq!(error, NativeSecretError::AmbiguousEntry);
        assert_eq!(
            error.to_string(),
            "native secure storage contains ambiguous entries"
        );
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
    fn journal_state_probe_distinguishes_empty_partial_complete_and_invalid() {
        let backend = MemoryBackend::default();
        let observer = backend.clone();
        let namespace = namespace();
        let mut store =
            NativeJournalSecretStore::with_backend(namespace.clone(), Box::new(backend));
        assert_eq!(
            store.inspect_state().expect("empty probe"),
            NativeJournalState::Empty
        );

        let key = JournalKey::from_zeroizing(Zeroizing::new([0x44; JOURNAL_KEY_BYTES]));
        store.store_key(&key).expect("store key");
        assert_eq!(
            store.inspect_state().expect("partial probe"),
            NativeJournalState::Partial
        );

        let anchor = JournalAnchor {
            journal_id: [3; 16],
            sequence: 0,
            entry_hash: [0; 32],
        };
        store.store_anchor(&anchor).expect("store anchor");
        assert_eq!(
            store.inspect_state().expect("complete probe"),
            NativeJournalState::Complete
        );

        observer.replace(
            CredentialName::new(&namespace, SecretKind::JournalAnchor),
            Zeroizing::new(b"malformed".to_vec()),
        );
        assert!(matches!(
            store.inspect_state(),
            Err(NativeSecretError::InvalidStoredValue)
        ));
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
            Zeroizing::new(wrong_envelope),
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
            Zeroizing::new(b"not-an-envelope".to_vec()),
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
