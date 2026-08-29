//! Feature-gated client for the closed Rescue repair-vault lifecycle.
//!
//! The endpoint is fixed, the peer must be root, and the only wire values are
//! the typed, path-free protocol values from `kernaid-protocol`. Backup bodies
//! travel through bounded one-shot pipes and are never included in `Debug`.

use kernaid_protocol::{
    rescue_repair_vault::{
        RepairBackupBinding, RepairBackupDraft, RepairBackupReleasePayload,
        RepairBackupStatusPayload, RepairFileMetadataV1, RepairReservationId,
        RepairTransactionResolution, RepairTransactionStatusPayload,
        RepairTransactionStatusResultPayload, RepairTransactionStatusSelector,
        RepairVaultLiveIdentityPayload,
    },
    rescue_vault::{ErrorToken, RequestId, Sha256, SuccessPayload},
    rescue_vault_transport::{
        ClientExchangeError, ClientRequest, ClientRequestPayload, ClientResponse,
        ClientResponseOutcome, SeqpacketTransportError, authenticate_root_seqpacket_server,
    },
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{self as rfs, OFlags},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
    pipe::{PipeFlags, pipe_with},
    rand::{GetRandomFlags, getrandom},
};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::{
    fmt::{self, Write as _},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const REPAIR_VAULT_SOCKET: &str = "/run/kernaid-rescue-vault.sock";

/// Sanitized client failures. Variants never retain operating-system errors,
/// paths, request bodies, or backup bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairVaultClientError {
    InvalidInput,
    StateUnavailable,
    Unavailable,
    TimedOut,
    ServerNotRoot,
    InvalidTransport,
    Protocol,
    PipeIoFailed,
    Remote(ErrorToken),
    /// A mutating request may have reached the authenticated server, but no
    /// correlated response was obtained. The caller must reconcile with a
    /// typed status/get request before issuing another mutation.
    ReconciliationRequired,
}

impl fmt::Display for RepairVaultClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid repair-vault input",
            Self::StateUnavailable => "repair-vault state version is unavailable",
            Self::Unavailable => "repair-vault service unavailable",
            Self::TimedOut => "repair-vault deadline expired",
            Self::ServerNotRoot => "repair-vault server is not root",
            Self::InvalidTransport => "invalid repair-vault transport",
            Self::Protocol => "invalid repair-vault protocol exchange",
            Self::PipeIoFailed => "repair-vault pipe transfer failed",
            Self::Remote(_) => "repair-vault request rejected",
            Self::ReconciliationRequired => "repair-vault reconciliation required",
        })
    }
}

impl std::error::Error for RepairVaultClientError {}

/// Public, path-free view of the local state-version guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairVaultClientState {
    NeedsReserveBootstrap,
    Ready { state_version: u64 },
    ReconciliationRequired { last_state_version: u64 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VersionGuard {
    Uninitialized,
    Ready(u64),
    ReconciliationRequired(u64),
}

impl VersionGuard {
    fn public(self) -> RepairVaultClientState {
        match self {
            Self::Uninitialized => RepairVaultClientState::NeedsReserveBootstrap,
            Self::Ready(state_version) => RepairVaultClientState::Ready { state_version },
            Self::ReconciliationRequired(last_state_version) => {
                RepairVaultClientState::ReconciliationRequired { last_state_version }
            }
        }
    }

    fn mutation_version(self) -> Result<u64, RepairVaultClientError> {
        match self {
            Self::Ready(state_version) => Ok(state_version),
            Self::Uninitialized => Err(RepairVaultClientError::StateUnavailable),
            Self::ReconciliationRequired(_) => Err(RepairVaultClientError::ReconciliationRequired),
        }
    }

    fn read_version(self) -> Result<u64, RepairVaultClientError> {
        match self {
            Self::Ready(state_version) | Self::ReconciliationRequired(state_version) => {
                Ok(state_version)
            }
            Self::Uninitialized => Err(RepairVaultClientError::StateUnavailable),
        }
    }

    fn observe_read_version(&mut self, state_version: u64) {
        *self = match self {
            Self::ReconciliationRequired(_) => Self::ReconciliationRequired(state_version),
            Self::Ready(_) => Self::Ready(state_version),
            Self::Uninitialized => Self::Uninitialized,
        };
    }

    fn reconcile(&mut self, state_version: u64) {
        *self = Self::Ready(state_version);
    }

    fn mark_ambiguous(&mut self, last_state_version: u64) {
        *self = Self::ReconciliationRequired(last_state_version);
    }
}

/// Bytes returned by `repair.backup.get` together with the correlated status.
/// The body is deliberately omitted from `Debug`.
pub struct RetrievedRepairBackup {
    status: RepairBackupStatusPayload,
    bytes: RepairBackupBytes,
}

/// Owned backup bytes which are zeroized before their allocation is released.
/// The bytes intentionally have no `Debug` implementation.
pub struct RepairBackupBytes(Zeroizing<Vec<u8>>);

impl RepairBackupBytes {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl RetrievedRepairBackup {
    pub fn status(&self) -> &RepairBackupStatusPayload {
        &self.status
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn into_bytes(self) -> RepairBackupBytes {
        self.bytes
    }
}

impl fmt::Debug for RetrievedRepairBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievedRepairBackup")
            .field("state", &self.status.state())
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Stateful client for the eight operations allowed to the repair-broker role.
///
/// A new client has no trusted state version. Its first `reserve` or reboot
/// `PendingSingleton` transaction lookup uses `expectedStateVersion = 0`; an
/// authenticated `STALE_STATE` supplies the version for one fresh, newly
/// correlated retry. If a reserve response is lost, only the exact same draft
/// may use the retained last version to reconcile it. No other mutation
/// retries.
pub struct RepairVaultClient {
    guard: VersionGuard,
    ambiguous_reserve: Option<RepairBackupDraft>,
}

struct ReserveAttempt<T> {
    state_version: u64,
    outcome: Result<T, RepairVaultClientError>,
}

struct TransactionAttempt<T> {
    state_version: u64,
    outcome: Result<T, RepairVaultClientError>,
}

impl Default for RepairVaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RepairVaultClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepairVaultClient")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl RepairVaultClient {
    pub const fn new() -> Self {
        Self {
            guard: VersionGuard::Uninitialized,
            ambiguous_reserve: None,
        }
    }

    pub fn state(&self) -> RepairVaultClientState {
        self.guard.public()
    }

    pub fn state_version(&self) -> Option<u64> {
        match self.guard {
            VersionGuard::Ready(state_version) => Some(state_version),
            VersionGuard::Uninitialized | VersionGuard::ReconciliationRequired(_) => None,
        }
    }

    fn observe_completed_read(&mut self, state_version: u64) {
        if self.ambiguous_reserve.is_some() {
            self.guard.mark_ambiguous(state_version);
        } else {
            self.guard.reconcile(state_version);
        }
    }

    /// Reserves bounded backup capacity. This is the sole state-version
    /// bootstrap path and the sole mutation which can reconcile an ambiguous
    /// response by presenting the exact same draft again. It accepts at most
    /// one authenticated `STALE_STATE` and retries at the observed version.
    pub fn reserve(
        &mut self,
        draft: &RepairBackupDraft,
        deadline: Instant,
    ) -> Result<RepairBackupStatusPayload, RepairVaultClientError> {
        self.reserve_with_exchange(
            draft,
            deadline,
            |expected_state_version, draft, deadline| {
                let response = exchange_once(
                    expected_state_version,
                    ClientRequestPayload::RepairBackupReserve {
                        draft: draft.clone(),
                    },
                    &[],
                    deadline,
                )?;
                Ok(ReserveAttempt {
                    state_version: response.state_version(),
                    outcome: status_result(&response),
                })
            },
        )
    }

    fn reserve_with_exchange<T, F>(
        &mut self,
        draft: &RepairBackupDraft,
        deadline: Instant,
        mut exchange: F,
    ) -> Result<T, RepairVaultClientError>
    where
        F: FnMut(u64, &RepairBackupDraft, Instant) -> Result<ReserveAttempt<T>, ExchangeFailure>,
    {
        let reconciling_ambiguous_reserve =
            matches!(self.guard, VersionGuard::ReconciliationRequired(_));
        let mut expected_state_version = match self.guard {
            VersionGuard::Uninitialized => 0,
            VersionGuard::Ready(state_version) => state_version,
            VersionGuard::ReconciliationRequired(last_state_version)
                if self.ambiguous_reserve.as_ref() == Some(draft) =>
            {
                last_state_version
            }
            VersionGuard::ReconciliationRequired(_) => {
                return Err(RepairVaultClientError::ReconciliationRequired);
            }
        };

        for attempt in 0..=1 {
            let response = match exchange(expected_state_version, draft, deadline) {
                Ok(response) => response,
                Err(failure) if failure.request_may_have_been_sent => {
                    self.guard.mark_ambiguous(expected_state_version);
                    self.ambiguous_reserve = Some(draft.clone());
                    return Err(RepairVaultClientError::ReconciliationRequired);
                }
                Err(failure) => return Err(failure.error),
            };
            match response.outcome {
                Err(RepairVaultClientError::Remote(ErrorToken::StaleState)) if attempt == 0 => {
                    if response.state_version == expected_state_version {
                        if reconciling_ambiguous_reserve {
                            self.guard.mark_ambiguous(response.state_version);
                        } else {
                            self.guard.reconcile(response.state_version);
                            self.ambiguous_reserve = None;
                        }
                        return Err(RepairVaultClientError::Protocol);
                    }
                    expected_state_version = response.state_version;
                    if reconciling_ambiguous_reserve {
                        self.guard.mark_ambiguous(response.state_version);
                    } else {
                        self.guard.reconcile(response.state_version);
                        self.ambiguous_reserve = None;
                    }
                }
                outcome => {
                    if outcome.is_ok() || !reconciling_ambiguous_reserve {
                        self.guard.reconcile(response.state_version);
                        self.ambiguous_reserve = None;
                    } else {
                        self.guard.mark_ambiguous(response.state_version);
                    }
                    return outcome;
                }
            }
        }
        unreachable!("bounded reserve retry loop always returns")
    }

    /// Persists the exact backup body through a one-shot input pipe.
    ///
    /// Length and digest are checked before the request can be sent. Any
    /// transport failure after send may have mutated the store and therefore
    /// transitions this client to `ReconciliationRequired`.
    pub fn persist(
        &mut self,
        expected: &RepairBackupStatusPayload,
        binding: &RepairBackupBinding,
        metadata: &RepairFileMetadataV1,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<RepairBackupStatusPayload, RepairVaultClientError> {
        let expected_size = usize::try_from(expected.backup_size())
            .map_err(|_| RepairVaultClientError::InvalidInput)?;
        if bytes.len() != expected_size
            || digest(bytes) != expected.expected_backup_sha256().bytes()
        {
            return Err(RepairVaultClientError::InvalidInput);
        }
        let expected_state_version = self.guard.mutation_version()?;
        let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)
            .map_err(|_| RepairVaultClientError::PipeIoFailed)?;
        let payload = ClientRequestPayload::RepairBackupPersist {
            expected: Box::new(expected.clone()),
            binding: binding.clone(),
            metadata: metadata.clone(),
            input_size: expected.backup_size(),
        };

        let (exchange, writer_result) = thread::scope(|scope| {
            let writer = scope.spawn(move || write_exact_pipe(write, bytes, deadline));
            let descriptors = [read.as_fd()];
            let exchange =
                self.mutation_exchange(expected_state_version, payload, &descriptors, deadline);
            drop(read);
            let writer_result = writer
                .join()
                .map_err(|_| RepairVaultClientError::PipeIoFailed)
                .and_then(|result| result);
            (exchange, writer_result)
        });

        let response = exchange?;
        let status = status_result(&response)?;
        // A remote rejection may close the input pipe without consuming it;
        // preserve that authenticated error instead of replacing it with the
        // writer's expected EPIPE. Successful persistence still requires the
        // complete exact-size pipe write.
        writer_result?;
        Ok(status)
    }

    /// Reads the current typed state for one exact reservation. A stale-state
    /// response is safe to retry once because this operation is read-only.
    pub fn status(
        &mut self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> Result<RepairBackupStatusPayload, RepairVaultClientError> {
        let response = self.read_exchange(
            || ClientRequestPayload::RepairBackupStatus {
                expected: Box::new(expected.clone()),
            },
            deadline,
        )?;
        let state_version = response.state_version();
        match status_result(&response) {
            Ok(status) => {
                self.observe_completed_read(state_version);
                Ok(status)
            }
            Err(RepairVaultClientError::Remote(ErrorToken::Absent)) => {
                self.observe_completed_read(state_version);
                Err(RepairVaultClientError::Remote(ErrorToken::Absent))
            }
            Err(error) => {
                self.guard.observe_read_version(state_version);
                Err(error)
            }
        }
    }

    /// Retrieves an exact durable backup through a one-shot output pipe. The
    /// declared length, EOF boundary, and SHA-256 digest are all enforced.
    pub fn get(
        &mut self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> Result<RetrievedRepairBackup, RepairVaultClientError> {
        let mut response = self.read_exchange(
            || ClientRequestPayload::RepairBackupGet {
                expected: Box::new(expected.clone()),
            },
            deadline,
        )?;
        let state_version = response.state_version();
        let status = match response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::RepairBackup(status, _)) => {
                (**status).clone()
            }
            ClientResponseOutcome::Error(ErrorToken::Absent) => {
                self.observe_completed_read(state_version);
                return Err(RepairVaultClientError::Remote(ErrorToken::Absent));
            }
            ClientResponseOutcome::Error(error) => {
                self.guard.observe_read_version(state_version);
                return Err(RepairVaultClientError::Remote(*error));
            }
            ClientResponseOutcome::Success(_) => {
                self.guard.observe_read_version(state_version);
                return Err(RepairVaultClientError::Protocol);
            }
        };
        let descriptor = response
            .take_descriptor()
            .ok_or(RepairVaultClientError::Protocol)?;
        let bytes = read_exact_pipe(descriptor, status.backup_size(), deadline)?;
        if digest(&bytes) != status.expected_backup_sha256().bytes() {
            return Err(RepairVaultClientError::Protocol);
        }
        self.observe_completed_read(state_version);
        Ok(RetrievedRepairBackup {
            status,
            bytes: RepairBackupBytes::new(bytes),
        })
    }

    /// Looks up the singleton unresolved transaction after restart, or one
    /// exact transaction while reconciling a lost mutation response.
    ///
    /// `PendingSingleton` is the only read that can bootstrap a new client at
    /// state version zero. `Exact` requires an already observed version. Both
    /// accept at most one authenticated stale-state response and retry with a
    /// fresh request correlation. A definitive result reconciles a lost
    /// non-reserve mutation, but never clears an ambiguous reserve.
    pub fn transaction_status(
        &mut self,
        selector: &RepairTransactionStatusSelector,
        deadline: Instant,
    ) -> Result<RepairTransactionStatusResultPayload, RepairVaultClientError> {
        self.transaction_status_with_exchange(
            selector,
            deadline,
            |expected_state_version, selector, deadline| {
                let response = exchange_once(
                    expected_state_version,
                    ClientRequestPayload::RepairTransactionStatus {
                        selector: selector.clone(),
                    },
                    &[],
                    deadline,
                )?;
                Ok(TransactionAttempt {
                    state_version: response.state_version(),
                    outcome: transaction_status_result(&response),
                })
            },
        )
    }

    /// Reads freshly attested current-boot Vault parent evidence. A reboot
    /// recovery caller first bootstraps this client's state with the singleton
    /// transaction lookup, then compares this transient identity with the
    /// immutable backup identity and the freshly reacquired target parent.
    pub fn live_identity(
        &mut self,
        deadline: Instant,
    ) -> Result<RepairVaultLiveIdentityPayload, RepairVaultClientError> {
        let response =
            self.read_exchange(|| ClientRequestPayload::RepairVaultLiveParent, deadline)?;
        let state_version = response.state_version();
        match live_identity_result(&response) {
            Ok(identity) => {
                self.observe_completed_read(state_version);
                Ok(identity)
            }
            Err(error) => {
                self.guard.observe_read_version(state_version);
                Err(error)
            }
        }
    }

    fn transaction_status_with_exchange<T, F>(
        &mut self,
        selector: &RepairTransactionStatusSelector,
        deadline: Instant,
        mut exchange: F,
    ) -> Result<T, RepairVaultClientError>
    where
        F: FnMut(
            u64,
            &RepairTransactionStatusSelector,
            Instant,
        ) -> Result<TransactionAttempt<T>, ExchangeFailure>,
    {
        let pending_bootstrap =
            matches!(selector, RepairTransactionStatusSelector::PendingSingleton);
        let mut expected_state_version = if pending_bootstrap {
            match self.guard {
                VersionGuard::Uninitialized => 0,
                VersionGuard::Ready(state_version)
                | VersionGuard::ReconciliationRequired(state_version) => state_version,
            }
        } else {
            self.guard.read_version()?
        };

        for attempt in 0..=1 {
            let response = exchange(expected_state_version, selector, deadline)
                .map_err(|failure| failure.error)?;
            match response.outcome {
                Err(RepairVaultClientError::Remote(ErrorToken::StaleState)) if attempt == 0 => {
                    if response.state_version == expected_state_version {
                        return Err(RepairVaultClientError::Protocol);
                    }
                    expected_state_version = response.state_version;
                    if matches!(self.guard, VersionGuard::Uninitialized) {
                        debug_assert!(pending_bootstrap);
                        self.guard.reconcile(response.state_version);
                    } else {
                        self.guard.observe_read_version(response.state_version);
                    }
                }
                Ok(result) => {
                    self.observe_completed_read(response.state_version);
                    return Ok(result);
                }
                Err(RepairVaultClientError::Remote(ErrorToken::Absent)) => {
                    self.observe_completed_read(response.state_version);
                    return Err(RepairVaultClientError::Remote(ErrorToken::Absent));
                }
                Err(error) => {
                    self.guard.observe_read_version(response.state_version);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded transaction-status retry loop always returns")
    }

    /// Records one closed recovery outcome for an exact unresolved
    /// transaction. This mutation is never repeated automatically. If the
    /// correlated response is lost, the caller must use `transaction_status`
    /// with `RepairTransactionStatusSelector::for_status(expected)`.
    pub fn resolve_transaction(
        &mut self,
        expected: &RepairTransactionStatusPayload,
        resolution: &RepairTransactionResolution,
        deadline: Instant,
    ) -> Result<RepairTransactionStatusPayload, RepairVaultClientError> {
        self.resolve_transaction_with_exchange(|expected_state_version| {
            let response = exchange_once(
                expected_state_version,
                ClientRequestPayload::RepairTransactionResolve {
                    expected: Box::new(expected.clone()),
                    resolution: resolution.clone(),
                },
                &[],
                deadline,
            )?;
            Ok(TransactionAttempt {
                state_version: response.state_version(),
                outcome: transaction_resolve_result(&response),
            })
        })
    }

    fn resolve_transaction_with_exchange<T, F>(
        &mut self,
        exchange: F,
    ) -> Result<T, RepairVaultClientError>
    where
        F: FnOnce(u64) -> Result<TransactionAttempt<T>, ExchangeFailure>,
    {
        let expected_state_version = self.guard.mutation_version()?;
        match exchange(expected_state_version) {
            Ok(response) => {
                self.guard.reconcile(response.state_version);
                self.ambiguous_reserve = None;
                response.outcome
            }
            Err(failure) if failure.request_may_have_been_sent => {
                self.guard.mark_ambiguous(expected_state_version);
                self.ambiguous_reserve = None;
                Err(RepairVaultClientError::ReconciliationRequired)
            }
            Err(failure) => Err(failure.error),
        }
    }

    pub fn cancel(
        &mut self,
        reservation_id: &RepairReservationId,
        draft_binding_sha256: &Sha256,
        deadline: Instant,
    ) -> Result<RepairBackupReleasePayload, RepairVaultClientError> {
        let expected_state_version = self.guard.mutation_version()?;
        let response = self.mutation_exchange(
            expected_state_version,
            ClientRequestPayload::RepairBackupCancel {
                reservation_id: reservation_id.clone(),
                draft_binding_sha256: draft_binding_sha256.clone(),
            },
            &[],
            deadline,
        )?;
        release_result(&response)
    }

    pub fn retire(
        &mut self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> Result<RepairBackupReleasePayload, RepairVaultClientError> {
        let expected_state_version = self.guard.mutation_version()?;
        let response = self.mutation_exchange(
            expected_state_version,
            ClientRequestPayload::RepairBackupRetire {
                expected: Box::new(expected.clone()),
            },
            &[],
            deadline,
        )?;
        release_result(&response)
    }

    fn mutation_exchange(
        &mut self,
        expected_state_version: u64,
        payload: ClientRequestPayload,
        descriptors: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<ClientResponse, RepairVaultClientError> {
        match exchange_once(expected_state_version, payload, descriptors, deadline) {
            Ok(response) => {
                self.guard.reconcile(response.state_version());
                self.ambiguous_reserve = None;
                Ok(response)
            }
            Err(failure) if failure.request_may_have_been_sent => {
                self.guard.mark_ambiguous(expected_state_version);
                self.ambiguous_reserve = None;
                Err(RepairVaultClientError::ReconciliationRequired)
            }
            Err(failure) => Err(failure.error),
        }
    }

    fn read_exchange<F>(
        &mut self,
        mut payload: F,
        deadline: Instant,
    ) -> Result<ClientResponse, RepairVaultClientError>
    where
        F: FnMut() -> ClientRequestPayload,
    {
        let mut expected_state_version = self.guard.read_version()?;
        for attempt in 0..=1 {
            let response = exchange_once(expected_state_version, payload(), &[], deadline)
                .map_err(|failure| failure.error)?;
            if matches!(
                response.outcome(),
                ClientResponseOutcome::Error(ErrorToken::StaleState)
            ) {
                let observed = response.state_version();
                if observed == expected_state_version {
                    return Err(RepairVaultClientError::Protocol);
                }
                self.guard.observe_read_version(observed);
                if attempt == 0 {
                    expected_state_version = observed;
                    continue;
                }
            }
            return Ok(response);
        }
        unreachable!("bounded read retry loop always returns")
    }
}

fn status_result(
    response: &ClientResponse,
) -> Result<RepairBackupStatusPayload, RepairVaultClientError> {
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::RepairBackupStatus(status)) => {
            Ok((**status).clone())
        }
        ClientResponseOutcome::Error(error) => Err(RepairVaultClientError::Remote(*error)),
        ClientResponseOutcome::Success(_) => Err(RepairVaultClientError::Protocol),
    }
}

fn release_result(
    response: &ClientResponse,
) -> Result<RepairBackupReleasePayload, RepairVaultClientError> {
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::RepairBackupReleased(released)) => {
            Ok(released.clone())
        }
        ClientResponseOutcome::Error(error) => Err(RepairVaultClientError::Remote(*error)),
        ClientResponseOutcome::Success(_) => Err(RepairVaultClientError::Protocol),
    }
}

fn transaction_status_result(
    response: &ClientResponse,
) -> Result<RepairTransactionStatusResultPayload, RepairVaultClientError> {
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::RepairTransactionStatus(result)) => {
            Ok((**result).clone())
        }
        ClientResponseOutcome::Error(error) => Err(RepairVaultClientError::Remote(*error)),
        ClientResponseOutcome::Success(_) => Err(RepairVaultClientError::Protocol),
    }
}

fn live_identity_result(
    response: &ClientResponse,
) -> Result<RepairVaultLiveIdentityPayload, RepairVaultClientError> {
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::RepairVaultLiveIdentity(identity)) => {
            Ok(identity.clone())
        }
        ClientResponseOutcome::Error(error) => Err(RepairVaultClientError::Remote(*error)),
        ClientResponseOutcome::Success(_) => Err(RepairVaultClientError::Protocol),
    }
}

fn transaction_resolve_result(
    response: &ClientResponse,
) -> Result<RepairTransactionStatusPayload, RepairVaultClientError> {
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::RepairTransactionResolved(status)) => {
            Ok((**status).clone())
        }
        ClientResponseOutcome::Error(error) => Err(RepairVaultClientError::Remote(*error)),
        ClientResponseOutcome::Success(_) => Err(RepairVaultClientError::Protocol),
    }
}

struct ExchangeFailure {
    error: RepairVaultClientError,
    request_may_have_been_sent: bool,
}

fn exchange_once(
    expected_state_version: u64,
    payload: ClientRequestPayload,
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<ClientResponse, ExchangeFailure> {
    ensure_before(deadline).map_err(definite_failure)?;
    let request_id = fresh_request_id().map_err(definite_failure)?;
    let request = ClientRequest::new(request_id, expected_state_version, payload)
        .map_err(|_| definite_failure(RepairVaultClientError::InvalidInput))?;
    let socket = connect_fixed_endpoint(deadline).map_err(definite_failure)?;
    let server = authenticate_root_seqpacket_server(socket.as_fd()).map_err(|error| {
        definite_failure(match error {
            SeqpacketTransportError::ServerNotRoot => RepairVaultClientError::ServerNotRoot,
            _ => RepairVaultClientError::InvalidTransport,
        })
    })?;
    match server.send_request(&request, descriptors, deadline) {
        Ok(()) => {}
        Err(ClientExchangeError::Request(_)) => {
            return Err(definite_failure(RepairVaultClientError::Protocol));
        }
        Err(error) => {
            return Err(ExchangeFailure {
                error: map_exchange_error(error),
                request_may_have_been_sent: true,
            });
        }
    }
    server
        .receive_response(&request, deadline)
        .map_err(|error| ExchangeFailure {
            error: map_exchange_error(error),
            request_may_have_been_sent: true,
        })
}

fn definite_failure(error: RepairVaultClientError) -> ExchangeFailure {
    ExchangeFailure {
        error,
        request_may_have_been_sent: false,
    }
}

fn map_exchange_error(error: ClientExchangeError) -> RepairVaultClientError {
    match error {
        ClientExchangeError::Request(_) | ClientExchangeError::Response(_) => {
            RepairVaultClientError::Protocol
        }
        ClientExchangeError::Transport(SeqpacketTransportError::TimedOut) => {
            RepairVaultClientError::TimedOut
        }
        ClientExchangeError::Transport(SeqpacketTransportError::ServerNotRoot) => {
            RepairVaultClientError::ServerNotRoot
        }
        ClientExchangeError::Transport(_) => RepairVaultClientError::InvalidTransport,
    }
}

fn connect_fixed_endpoint(deadline: Instant) -> Result<OwnedFd, RepairVaultClientError> {
    ensure_before(deadline)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RepairVaultClientError::Unavailable)?;
    let address = SocketAddrUnix::new(REPAIR_VAULT_SOCKET)
        .map_err(|_| RepairVaultClientError::Unavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| RepairVaultClientError::Unavailable)?
                .map_err(|_| RepairVaultClientError::Unavailable)?;
        }
        Err(_) => return Err(RepairVaultClientError::Unavailable),
    }
    Ok(socket)
}

fn fresh_request_id() -> Result<RequestId, RepairVaultClientError> {
    let mut random = [0_u8; 16];
    let mut offset = 0;
    while offset < random.len() {
        let count = getrandom(&mut random[offset..], GetRandomFlags::NONBLOCK)
            .map_err(|_| RepairVaultClientError::Unavailable)?;
        if count == 0 {
            return Err(RepairVaultClientError::Unavailable);
        }
        offset += count;
    }
    let mut value = String::with_capacity(38);
    value.push_str("R-");
    for (index, byte) in random.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        write!(&mut value, "{byte:02x}").map_err(|_| RepairVaultClientError::Protocol)?;
    }
    RequestId::parse(&value).map_err(|_| RepairVaultClientError::Protocol)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256Hasher::digest(bytes).into()
}

fn write_exact_pipe(
    descriptor: OwnedFd,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), RepairVaultClientError> {
    let mut written = 0_usize;
    while written < bytes.len() {
        ensure_before(deadline)?;
        match rustix::io::write(&descriptor, &bytes[written..]) {
            Ok(0) => return Err(RepairVaultClientError::PipeIoFailed),
            Ok(count) => {
                written = written
                    .checked_add(count)
                    .ok_or(RepairVaultClientError::PipeIoFailed)?;
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor.as_fd(), PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(RepairVaultClientError::PipeIoFailed),
        }
    }
    Ok(())
}

fn read_exact_pipe(
    descriptor: OwnedFd,
    expected_size: u64,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, RepairVaultClientError> {
    let expected = usize::try_from(expected_size)
        .ok()
        .filter(|size| *size > 0)
        .ok_or(RepairVaultClientError::Protocol)?;
    let status =
        rfs::fcntl_getfl(&descriptor).map_err(|_| RepairVaultClientError::InvalidTransport)?;
    if status & OFlags::ACCMODE != OFlags::RDONLY {
        return Err(RepairVaultClientError::InvalidTransport);
    }
    rfs::fcntl_setfl(&descriptor, status | OFlags::NONBLOCK)
        .map_err(|_| RepairVaultClientError::InvalidTransport)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected));
    while bytes.len() < expected {
        ensure_before(deadline)?;
        let mut chunk = Zeroizing::new([0_u8; 8192]);
        let wanted = (expected - bytes.len()).min(chunk.len());
        match rustix::io::read(&descriptor, &mut chunk[..wanted]) {
            Ok(0) => return Err(RepairVaultClientError::PipeIoFailed),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor.as_fd(), PollFlags::IN | PollFlags::HUP, deadline)?;
            }
            Err(_) => return Err(RepairVaultClientError::PipeIoFailed),
        }
    }
    loop {
        ensure_before(deadline)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(&descriptor, &mut extra[..]) {
            Ok(0) => return Ok(bytes),
            Ok(_) => return Err(RepairVaultClientError::Protocol),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor.as_fd(), PollFlags::IN | PollFlags::HUP, deadline)?;
            }
            Err(_) => return Err(RepairVaultClientError::PipeIoFailed),
        }
    }
}

fn ensure_before(deadline: Instant) -> Result<(), RepairVaultClientError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(RepairVaultClientError::TimedOut)
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), RepairVaultClientError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RepairVaultClientError::TimedOut)?;
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(RepairVaultClientError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(RepairVaultClientError::InvalidTransport);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RepairVaultClientError::InvalidTransport),
        }
    }
}

fn duration_to_timespec(duration: Duration) -> Timespec {
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    Timespec {
        tv_sec: seconds,
        tv_nsec: if seconds == i64::MAX {
            999_999_999
        } else {
            i64::from(duration.subsec_nanos())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_protocol::rescue_vault_transport::encode_client_request;

    fn hash(character: char) -> Sha256 {
        Sha256::parse(&character.to_string().repeat(64)).expect("test SHA-256")
    }

    fn draft() -> RepairBackupDraft {
        let metadata = RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata");
        RepairBackupDraft::new(
            "S-test-session",
            "selected-linux-root",
            hash('1'),
            format!("recovery:{}", "4".repeat(64)),
            hash('2'),
            metadata.canonical_sha256(),
            4,
            4096,
        )
        .expect("draft")
    }

    fn different_draft() -> RepairBackupDraft {
        let metadata = RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata");
        RepairBackupDraft::new(
            "S-different-session",
            "selected-linux-root",
            hash('1'),
            format!("recovery:{}", "4".repeat(64)),
            hash('3'),
            metadata.canonical_sha256(),
            4,
            4096,
        )
        .expect("different draft")
    }

    fn ambiguous_reserve_client(draft: &RepairBackupDraft) -> RepairVaultClient {
        let mut client = RepairVaultClient::new();
        client.guard.mark_ambiguous(17);
        client.ambiguous_reserve = Some(draft.clone());
        client
    }

    fn exact_transaction_selector() -> RepairTransactionStatusSelector {
        RepairTransactionStatusSelector::exact(
            RepairReservationId::parse("B-0123456789abcdef0123456789abcdef")
                .expect("reservation ID"),
            hash('9'),
        )
    }

    #[test]
    fn request_codec_remains_typed_and_path_free() {
        let request = ClientRequest::new(
            RequestId::parse("R-12345678-1234-1234-1234-123456789abc").expect("request ID"),
            0,
            ClientRequestPayload::RepairBackupReserve { draft: draft() },
        )
        .expect("request");
        let encoded = encode_client_request(&request, &[]).expect("typed codec");
        let encoded = String::from_utf8(encoded).expect("UTF-8 wire");
        assert!(encoded.contains("repair.backup.reserve"));
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("/etc/"));
        assert!(!encoded.contains("\"path\""));
    }

    #[test]
    fn mutation_ambiguity_closes_the_guard() {
        let mut guard = VersionGuard::Ready(17);
        guard.mark_ambiguous(17);
        assert_eq!(
            guard.public(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 17
            }
        );
        assert_eq!(
            guard.mutation_version(),
            Err(RepairVaultClientError::ReconciliationRequired)
        );
        assert_eq!(guard.read_version(), Ok(17));
    }

    #[test]
    fn read_observation_preserves_uncertainty_until_reconciled() {
        let mut guard = VersionGuard::ReconciliationRequired(17);
        guard.observe_read_version(21);
        assert_eq!(
            guard.public(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 21
            }
        );
        guard.reconcile(21);
        assert_eq!(
            guard.public(),
            RepairVaultClientState::Ready { state_version: 21 }
        );
    }

    #[test]
    fn pending_transaction_status_bootstraps_at_zero_and_retries_one_stale() {
        let mut client = RepairVaultClient::new();
        let selector = RepairTransactionStatusSelector::pending_singleton();
        let mut versions = Vec::new();
        let result = client.transaction_status_with_exchange(
            &selector,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, observed_selector, _| {
                assert_eq!(observed_selector, &selector);
                versions.push(expected_state_version);
                if versions.len() == 1 {
                    Ok(TransactionAttempt {
                        state_version: 19,
                        outcome: Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                    })
                } else {
                    Ok(TransactionAttempt {
                        state_version: 19,
                        outcome: Ok(7_u8),
                    })
                }
            },
        );

        assert_eq!(result, Ok(7));
        assert_eq!(versions, [0, 19]);
        assert_eq!(
            client.state(),
            RepairVaultClientState::Ready { state_version: 19 }
        );
    }

    #[test]
    fn exact_transaction_status_cannot_bootstrap_an_uninitialized_client() {
        let mut client = RepairVaultClient::new();
        let mut exchanged = false;
        let result: Result<u8, _> = client.transaction_status_with_exchange(
            &exact_transaction_selector(),
            Instant::now() + Duration::from_secs(1),
            |_, _, _| {
                exchanged = true;
                Err(definite_failure(RepairVaultClientError::Protocol))
            },
        );

        assert_eq!(result, Err(RepairVaultClientError::StateUnavailable));
        assert!(!exchanged);
    }

    #[test]
    fn lost_resolve_response_is_reconciled_only_by_definitive_exact_status() {
        let mut client = RepairVaultClient {
            guard: VersionGuard::Ready(17),
            ambiguous_reserve: None,
        };
        let mut resolve_attempts = 0;
        let resolve: Result<u8, _> =
            client.resolve_transaction_with_exchange(|expected_state_version| {
                resolve_attempts += 1;
                assert_eq!(expected_state_version, 17);
                Err(ExchangeFailure {
                    error: RepairVaultClientError::TimedOut,
                    request_may_have_been_sent: true,
                })
            });
        assert_eq!(resolve, Err(RepairVaultClientError::ReconciliationRequired));
        assert_eq!(resolve_attempts, 1);
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 17
            }
        );

        let selector = exact_transaction_selector();
        let status = client.transaction_status_with_exchange(
            &selector,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, observed_selector, _| {
                assert_eq!(expected_state_version, 17);
                assert_eq!(observed_selector, &selector);
                Ok(TransactionAttempt {
                    state_version: 18,
                    outcome: Ok(11_u8),
                })
            },
        );
        assert_eq!(status, Ok(11));
        assert_eq!(
            client.state(),
            RepairVaultClientState::Ready { state_version: 18 }
        );
    }

    #[test]
    fn exact_status_refreshes_an_expected_external_mutation_before_resolve() {
        let mut client = RepairVaultClient {
            guard: VersionGuard::Ready(17),
            ambiguous_reserve: None,
        };
        let selector = exact_transaction_selector();
        let mut status_versions = Vec::new();
        let status = client.transaction_status_with_exchange(
            &selector,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, observed_selector, _| {
                assert_eq!(observed_selector, &selector);
                status_versions.push(expected_state_version);
                if status_versions.len() == 1 {
                    Ok(TransactionAttempt {
                        state_version: 19,
                        outcome: Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                    })
                } else {
                    Ok(TransactionAttempt {
                        state_version: 19,
                        outcome: Ok(11_u8),
                    })
                }
            },
        );

        assert_eq!(status, Ok(11));
        assert_eq!(status_versions, [17, 19]);
        assert_eq!(
            client.state(),
            RepairVaultClientState::Ready { state_version: 19 }
        );

        let resolved = client.resolve_transaction_with_exchange(|expected_state_version| {
            assert_eq!(expected_state_version, 19);
            Ok(TransactionAttempt {
                state_version: 20,
                outcome: Ok(12_u8),
            })
        });
        assert_eq!(resolved, Ok(12));
        assert_eq!(
            client.state(),
            RepairVaultClientState::Ready { state_version: 20 }
        );
    }

    #[test]
    fn transaction_status_never_clears_an_unknown_reserve() {
        let original = draft();
        let mut client = ambiguous_reserve_client(&original);
        let selector = exact_transaction_selector();
        let status = client.transaction_status_with_exchange(
            &selector,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, _, _| {
                assert_eq!(expected_state_version, 17);
                Ok(TransactionAttempt {
                    state_version: 23,
                    outcome: Ok(5_u8),
                })
            },
        );

        assert_eq!(status, Ok(5));
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&original));
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 23
            }
        );
    }

    #[test]
    fn unrelated_status_and_get_reads_do_not_clear_an_ambiguous_reserve() {
        let original = draft();
        let different = different_draft();
        let mut client = ambiguous_reserve_client(&original);

        // A successful status and a successful/Absent get both carry useful
        // authenticated versions, but neither proves the lost reserve result.
        client.observe_completed_read(21);
        client.observe_completed_read(24);
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 24
            }
        );
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&original));

        let mut exchanged = false;
        let result: Result<u8, _> = client.reserve_with_exchange(
            &different,
            Instant::now() + Duration::from_secs(1),
            |_, _, _| {
                exchanged = true;
                Err(definite_failure(RepairVaultClientError::Protocol))
            },
        );
        assert_eq!(result, Err(RepairVaultClientError::ReconciliationRequired));
        assert!(!exchanged);
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&original));
    }

    #[test]
    fn ambiguous_reserve_retries_exact_draft_at_one_observed_stale_version() {
        let draft = draft();
        let mut client = ambiguous_reserve_client(&draft);
        let mut versions = Vec::new();
        let result = client.reserve_with_exchange(
            &draft,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, observed_draft, _| {
                assert_eq!(observed_draft, &draft);
                versions.push(expected_state_version);
                if versions.len() == 1 {
                    Ok(ReserveAttempt {
                        state_version: 21,
                        outcome: Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                    })
                } else {
                    Ok(ReserveAttempt {
                        state_version: 22,
                        outcome: Ok(7_u8),
                    })
                }
            },
        );

        assert_eq!(result, Ok(7));
        assert_eq!(versions, [17, 21]);
        assert_eq!(
            client.state(),
            RepairVaultClientState::Ready { state_version: 22 }
        );
        assert!(client.ambiguous_reserve.is_none());
    }

    #[test]
    fn repeated_reserve_response_loss_remains_ambiguous_at_last_version() {
        let draft = draft();
        let mut client = ambiguous_reserve_client(&draft);
        let mut attempts = 0;
        let result: Result<u8, _> = client.reserve_with_exchange(
            &draft,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, _, _| {
                attempts += 1;
                if attempts == 1 {
                    assert_eq!(expected_state_version, 17);
                    Ok(ReserveAttempt {
                        state_version: 21,
                        outcome: Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                    })
                } else {
                    assert_eq!(expected_state_version, 21);
                    Err(ExchangeFailure {
                        error: RepairVaultClientError::TimedOut,
                        request_may_have_been_sent: true,
                    })
                }
            },
        );

        assert_eq!(result, Err(RepairVaultClientError::ReconciliationRequired));
        assert_eq!(attempts, 2);
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 21
            }
        );
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&draft));
    }

    #[test]
    fn ambiguous_reserve_rejects_a_different_draft_without_an_exchange() {
        let original = draft();
        let different = different_draft();
        let mut client = ambiguous_reserve_client(&original);
        let mut exchanged = false;
        let result: Result<u8, _> = client.reserve_with_exchange(
            &different,
            Instant::now() + Duration::from_secs(1),
            |_, _, _| {
                exchanged = true;
                Err(definite_failure(RepairVaultClientError::Protocol))
            },
        );

        assert_eq!(result, Err(RepairVaultClientError::ReconciliationRequired));
        assert!(!exchanged);
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&original));
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 17
            }
        );
    }

    #[test]
    fn reserve_accepts_only_one_stale_response() {
        let draft = draft();
        let mut client = ambiguous_reserve_client(&draft);
        let mut versions = Vec::new();
        let result: Result<u8, _> = client.reserve_with_exchange(
            &draft,
            Instant::now() + Duration::from_secs(1),
            |expected_state_version, _, _| {
                versions.push(expected_state_version);
                Ok(ReserveAttempt {
                    state_version: if versions.len() == 1 { 21 } else { 22 },
                    outcome: Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                })
            },
        );

        assert_eq!(
            result,
            Err(RepairVaultClientError::Remote(ErrorToken::StaleState))
        );
        assert_eq!(versions, [17, 21]);
        assert_eq!(
            client.state(),
            RepairVaultClientState::ReconciliationRequired {
                last_state_version: 22
            }
        );
        assert_eq!(client.ambiguous_reserve.as_ref(), Some(&draft));
    }

    #[test]
    fn pipe_helpers_enforce_exact_body_and_do_not_debug_bytes() {
        let body = b"test";
        let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe");
        let deadline = Instant::now() + Duration::from_secs(1);
        thread::scope(|scope| {
            let writer = scope.spawn(move || write_exact_pipe(write, body, deadline));
            let read_back: Zeroizing<Vec<u8>> = read_exact_pipe(read, 4, deadline).expect("read");
            assert_eq!(read_back.as_slice(), body);
            writer.join().expect("writer thread").expect("write");
        });
        let owned = RepairBackupBytes::new(Zeroizing::new(body.to_vec()));
        assert_eq!(owned.as_slice(), body);
        assert_eq!(owned.len(), body.len());
        assert!(!owned.is_empty());
    }
}
