//! Closed parent/worker transport for the privileged vault lifecycle.
//!
//! The wire is fixed-size binary data. It contains no pathname, secret,
//! command string, diagnostic text, or JSON. The sole permitted descriptor is
//! one anonymous pipe on an `Unlock`, `ProviderOpenAiConfigure`, or dormant
//! `ProviderOpenAiBorrow` command. Borrow carries only the worker's write end;
//! the supervisor retains the read end and never reads credential bytes.

use kernaid_protocol::rescue_vault::{
    MAX_OPENAI_KEY_BYTES, MAX_PASSPHRASE_BYTES, MIN_PASSPHRASE_BYTES,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
    },
};
use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

const COMMAND_MAGIC: &[u8; 8] = b"KRVWC002";
const RESPONSE_MAGIC: &[u8; 8] = b"KRVWR002";
const COMMAND_BYTES: usize = 32;
const RESPONSE_BYTES: usize = 64;
const MAX_RECORD_BYTES: usize = RESPONSE_BYTES;
const DEVICE_ID_OFFSET: usize = 20;
const MAX_DEVICE_ID_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerCommandKind {
    Bootstrap,
    Probe,
    Unlock,
    Lock,
    ProviderStatus,
    ProviderOpenAiConfigure,
    ProviderOpenAiLogout,
    ProviderOpenAiBorrow,
    AttestQuiescent,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkerCommand {
    pub(super) request_id: u64,
    pub(super) kind: WorkerCommandKind,
    pub(super) secret_size: u16,
}

impl WorkerCommand {
    pub(super) fn bootstrap(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Bootstrap,
            secret_size: 0,
        }
    }

    pub(super) fn probe(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Probe,
            secret_size: 0,
        }
    }

    pub(super) fn unlock(request_id: u64, passphrase_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Unlock,
            secret_size: passphrase_size,
        }
    }

    pub(super) fn lock(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Lock,
            secret_size: 0,
        }
    }

    pub(super) fn provider_status(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderStatus,
            secret_size: 0,
        }
    }

    pub(super) fn provider_openai_configure(request_id: u64, api_key_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiConfigure,
            secret_size: api_key_size,
        }
    }

    pub(super) fn provider_openai_logout(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiLogout,
            secret_size: 0,
        }
    }

    pub(super) fn provider_openai_borrow(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiBorrow,
            secret_size: 0,
        }
    }

    pub(super) fn shutdown(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Shutdown,
            secret_size: 0,
        }
    }

    pub(super) fn attest_quiescent(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::AttestQuiescent,
            secret_size: 0,
        }
    }

    fn encode(self) -> Result<[u8; COMMAND_BYTES], InternalWireError> {
        if self.request_id == 0
            || (self.kind == WorkerCommandKind::Unlock && !valid_passphrase_size(self.secret_size))
            || (self.kind == WorkerCommandKind::ProviderOpenAiConfigure
                && !valid_openai_key_size(self.secret_size))
            || (!matches!(
                self.kind,
                WorkerCommandKind::Unlock | WorkerCommandKind::ProviderOpenAiConfigure
            ) && self.secret_size != 0)
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; COMMAND_BYTES];
        bytes[..8].copy_from_slice(COMMAND_MAGIC);
        bytes[8] = match self.kind {
            WorkerCommandKind::Bootstrap => 1,
            WorkerCommandKind::Probe => 2,
            WorkerCommandKind::Unlock => 3,
            WorkerCommandKind::Lock => 4,
            WorkerCommandKind::Shutdown => 5,
            WorkerCommandKind::AttestQuiescent => 6,
            WorkerCommandKind::ProviderStatus => 7,
            WorkerCommandKind::ProviderOpenAiConfigure => 8,
            WorkerCommandKind::ProviderOpenAiLogout => 9,
            WorkerCommandKind::ProviderOpenAiBorrow => 10,
        };
        bytes[16..24].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[24..26].copy_from_slice(&self.secret_size.to_be_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != COMMAND_BYTES
            || &bytes[..8] != COMMAND_MAGIC
            || bytes[9..16].iter().any(|byte| *byte != 0)
            || bytes[26..].iter().any(|byte| *byte != 0)
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let secret_size = u16::from_be_bytes(
            bytes[24..26]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let kind = match bytes[8] {
            1 => WorkerCommandKind::Bootstrap,
            2 => WorkerCommandKind::Probe,
            3 => WorkerCommandKind::Unlock,
            4 => WorkerCommandKind::Lock,
            5 => WorkerCommandKind::Shutdown,
            6 => WorkerCommandKind::AttestQuiescent,
            7 => WorkerCommandKind::ProviderStatus,
            8 => WorkerCommandKind::ProviderOpenAiConfigure,
            9 => WorkerCommandKind::ProviderOpenAiLogout,
            10 => WorkerCommandKind::ProviderOpenAiBorrow,
            _ => return Err(InternalWireError::InvalidFrame),
        };
        let command = Self {
            request_id,
            kind,
            secret_size,
        };
        command.encode()?;
        Ok(command)
    }
}

fn valid_passphrase_size(size: u16) -> bool {
    let size = u64::from(size);
    (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&size)
}

fn valid_openai_key_size(size: u16) -> bool {
    (1..=MAX_OPENAI_KEY_BYTES).contains(&u64::from(size))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerResultCode {
    BootstrapReady,
    ProbeAbsent,
    ProbeUnprovisioned,
    ProbeLocked,
    ProbeProfileMismatch,
    ProbeClassifierUnavailable,
    ProbeIoFailed,
    UnlockSucceeded,
    LockSucceeded,
    ShutdownSucceeded,
    Absent,
    Unprovisioned,
    ProfileMismatch,
    BadPassphrase,
    MediaChanged,
    IoFailed,
    CleanupFailed,
    TimedOut,
    Busy,
    InvalidRequest,
    AttestAbsent,
    AttestUnprovisioned,
    AttestLocked,
    AttestProfileMismatch,
    ProviderStatusUnconfigured,
    ProviderStatusConfigured,
    ProviderConfigureSucceeded,
    ProviderLogoutSucceeded,
    ProviderMutationAborted,
    ProviderStateAmbiguous,
    ProviderBorrowReady,
    ProviderBorrowUnconfigured,
}

impl WorkerResultCode {
    fn encode(self) -> u8 {
        match self {
            Self::BootstrapReady => 1,
            Self::ProbeAbsent => 2,
            Self::ProbeUnprovisioned => 3,
            Self::ProbeLocked => 4,
            Self::ProbeProfileMismatch => 5,
            Self::ProbeClassifierUnavailable => 6,
            Self::ProbeIoFailed => 7,
            Self::UnlockSucceeded => 8,
            Self::LockSucceeded => 9,
            Self::ShutdownSucceeded => 10,
            Self::Absent => 11,
            Self::Unprovisioned => 12,
            Self::ProfileMismatch => 13,
            Self::BadPassphrase => 14,
            Self::MediaChanged => 15,
            Self::IoFailed => 16,
            Self::CleanupFailed => 17,
            Self::TimedOut => 18,
            Self::Busy => 19,
            Self::InvalidRequest => 20,
            Self::AttestAbsent => 21,
            Self::AttestUnprovisioned => 22,
            Self::AttestLocked => 23,
            Self::AttestProfileMismatch => 24,
            Self::ProviderStatusUnconfigured => 25,
            Self::ProviderStatusConfigured => 26,
            Self::ProviderConfigureSucceeded => 27,
            Self::ProviderLogoutSucceeded => 28,
            Self::ProviderMutationAborted => 29,
            Self::ProviderStateAmbiguous => 30,
            Self::ProviderBorrowReady => 31,
            Self::ProviderBorrowUnconfigured => 32,
        }
    }

    fn decode(value: u8) -> Result<Self, InternalWireError> {
        match value {
            1 => Ok(Self::BootstrapReady),
            2 => Ok(Self::ProbeAbsent),
            3 => Ok(Self::ProbeUnprovisioned),
            4 => Ok(Self::ProbeLocked),
            5 => Ok(Self::ProbeProfileMismatch),
            6 => Ok(Self::ProbeClassifierUnavailable),
            7 => Ok(Self::ProbeIoFailed),
            8 => Ok(Self::UnlockSucceeded),
            9 => Ok(Self::LockSucceeded),
            10 => Ok(Self::ShutdownSucceeded),
            11 => Ok(Self::Absent),
            12 => Ok(Self::Unprovisioned),
            13 => Ok(Self::ProfileMismatch),
            14 => Ok(Self::BadPassphrase),
            15 => Ok(Self::MediaChanged),
            16 => Ok(Self::IoFailed),
            17 => Ok(Self::CleanupFailed),
            18 => Ok(Self::TimedOut),
            19 => Ok(Self::Busy),
            20 => Ok(Self::InvalidRequest),
            21 => Ok(Self::AttestAbsent),
            22 => Ok(Self::AttestUnprovisioned),
            23 => Ok(Self::AttestLocked),
            24 => Ok(Self::AttestProfileMismatch),
            25 => Ok(Self::ProviderStatusUnconfigured),
            26 => Ok(Self::ProviderStatusConfigured),
            27 => Ok(Self::ProviderConfigureSucceeded),
            28 => Ok(Self::ProviderLogoutSucceeded),
            29 => Ok(Self::ProviderMutationAborted),
            30 => Ok(Self::ProviderStateAmbiguous),
            31 => Ok(Self::ProviderBorrowReady),
            32 => Ok(Self::ProviderBorrowUnconfigured),
            _ => Err(InternalWireError::InvalidFrame),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerResponse {
    pub(super) request_id: u64,
    pub(super) code: WorkerResultCode,
    pub(super) device_id: Option<String>,
    pub(super) output_size: Option<u16>,
}

impl WorkerResponse {
    pub(super) fn new(request_id: u64, code: WorkerResultCode) -> Self {
        Self {
            request_id,
            code,
            device_id: None,
            output_size: None,
        }
    }

    pub(super) fn unlocked(request_id: u64, device_id: String) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::UnlockSucceeded,
            device_id: Some(device_id),
            output_size: None,
        }
    }

    pub(super) fn provider_borrow_ready(request_id: u64, output_size: u16) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::ProviderBorrowReady,
            device_id: None,
            output_size: Some(output_size),
        }
    }

    fn encode(&self) -> Result<[u8; RESPONSE_BYTES], InternalWireError> {
        if self.request_id == 0
            || (self.code == WorkerResultCode::UnlockSucceeded) != self.device_id.is_some()
            || (self.code == WorkerResultCode::ProviderBorrowReady) != self.output_size.is_some()
            || self
                .output_size
                .is_some_and(|size| !valid_openai_key_size(size))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let device = self.device_id.as_deref().unwrap_or_default().as_bytes();
        if (!device.is_empty() && !valid_device_id(device)) || device.len() > MAX_DEVICE_ID_BYTES {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8] = self.code.encode();
        bytes[9] = u8::try_from(device.len()).map_err(|_| InternalWireError::InvalidFrame)?;
        bytes[10..12].copy_from_slice(&self.output_size.unwrap_or_default().to_be_bytes());
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device.len()].copy_from_slice(device);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != RESPONSE_BYTES || &bytes[..8] != RESPONSE_MAGIC {
            return Err(InternalWireError::InvalidFrame);
        }
        let code = WorkerResultCode::decode(bytes[8])?;
        let device_len = usize::from(bytes[9]);
        let output_size = u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        if device_len > MAX_DEVICE_ID_BYTES
            || bytes[DEVICE_ID_OFFSET + device_len..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let device_id = if device_len == 0 {
            None
        } else {
            let device = &bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device_len];
            if !valid_device_id(device) {
                return Err(InternalWireError::InvalidFrame);
            }
            Some(
                std::str::from_utf8(device)
                    .map_err(|_| InternalWireError::InvalidFrame)?
                    .to_owned(),
            )
        };
        let response = Self {
            request_id,
            code,
            device_id,
            output_size: (output_size != 0).then_some(output_size),
        };
        response.encode()?;
        Ok(response)
    }
}

fn valid_device_id(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .ok()
        .is_some_and(|value| kernaid_device_identity::validate_device_id(value).is_ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InternalWireError {
    InvalidTransport,
    InvalidFrame,
    InvalidDescriptors,
    TimedOut,
    IoFailed,
}

impl fmt::Display for InternalWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransport => "invalid Rescue worker transport",
            Self::InvalidFrame => "invalid Rescue worker frame",
            Self::InvalidDescriptors => "invalid Rescue worker descriptors",
            Self::TimedOut => "Rescue worker transport timed out",
            Self::IoFailed => "Rescue worker transport failed",
        })
    }
}

impl std::error::Error for InternalWireError {}

pub(super) fn send_command(
    socket: BorrowedFd<'_>,
    command: WorkerCommand,
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    let bytes = command.encode()?;
    match (command.kind, descriptor) {
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow,
            Some(descriptor),
        ) => send_record(socket, &bytes, &[descriptor], deadline),
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow,
            None,
        )
        | (_, Some(_)) => Err(InternalWireError::InvalidDescriptors),
        (_, None) => send_record(socket, &bytes, &[], deadline),
    }
}

pub(super) fn receive_command(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(WorkerCommand, Option<OwnedFd>), InternalWireError> {
    let (bytes, mut descriptors) = receive_record(socket, deadline)?;
    let command = WorkerCommand::decode(&bytes)?;
    match (command.kind, descriptors.len()) {
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow,
            1,
        ) => Ok((command, descriptors.pop())),
        (
            WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow,
            _,
        )
        | (_, 1..) => Err(InternalWireError::InvalidDescriptors),
        (_, 0) => Ok((command, None)),
    }
}

pub(super) fn send_response(
    socket: BorrowedFd<'_>,
    response: &WorkerResponse,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    send_record(socket, &response.encode()?, &[], deadline)
}

pub(super) fn receive_response(
    socket: BorrowedFd<'_>,
    expected_request_id: u64,
    deadline: Instant,
) -> Result<WorkerResponse, InternalWireError> {
    let (bytes, descriptors) = receive_record(socket, deadline)?;
    if !descriptors.is_empty() {
        return Err(InternalWireError::InvalidDescriptors);
    }
    let response = WorkerResponse::decode(&bytes)?;
    if response.request_id != expected_request_id {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(response)
}

pub(super) fn validate_control_socket(socket: BorrowedFd<'_>) -> Result<(), InternalWireError> {
    let flags = rustix::io::fcntl_getfd(socket).map_err(|_| InternalWireError::InvalidTransport)?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC)
        || rustix::net::sockopt::socket_domain(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
        || rustix::net::getpeername(socket).is_err()
        || rustix::net::sockopt::socket_passcred(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
    {
        return Err(InternalWireError::InvalidTransport);
    }
    Ok(())
}

fn send_record(
    socket: BorrowedFd<'_>,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES || descriptors.len() > 1 {
        return Err(InternalWireError::InvalidFrame);
    }
    let io = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(InternalWireError::IoFailed);
    }
    loop {
        ensure_deadline(deadline)?;
        match sendmsg(
            socket,
            &io,
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(sent) if sent == bytes.len() => return Ok(()),
            Ok(_) => return Err(InternalWireError::IoFailed),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    }
}

fn receive_record(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    let mut bytes = [0_u8; MAX_RECORD_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = loop {
        ensure_deadline(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    };
    if message
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || message.bytes == 0
        || message.bytes > MAX_RECORD_BYTES
    {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(_) => unexpected = true,
            _ => unexpected = true,
        }
    }
    if unexpected
        || descriptors.len() > 1
        || descriptors.iter().any(|descriptor| {
            rustix::io::fcntl_getfd(descriptor)
                .map(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
                .unwrap_or(true)
        })
    {
        return Err(InternalWireError::InvalidDescriptors);
    }
    Ok((bytes[..message.bytes].to_vec(), descriptors))
}

fn ensure_deadline(deadline: Instant) -> Result<(), InternalWireError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(InternalWireError::TimedOut)
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(InternalWireError::TimedOut)?;
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(InternalWireError::TimedOut),
            Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                return Err(InternalWireError::InvalidTransport);
            }
            Ok(_)
                if descriptors[0]
                    .revents()
                    .intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) =>
            {
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(InternalWireError::IoFailed),
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
    use rustix::{
        net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
            SocketType, send, sendmsg, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        ffi::OsString,
        io::IoSlice,
        mem::MaybeUninit,
        os::fd::{AsFd, AsRawFd},
    };

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    #[test]
    fn closed_command_and_response_round_trip() {
        let (parent, worker) = pair();
        let (read, _write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        let deadline = Instant::now() + Duration::from_secs(2);
        send_command(
            parent.as_fd(),
            WorkerCommand::unlock(7, 12),
            Some(read.as_fd()),
            deadline,
        )
        .expect("send unlock");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::unlock(7, 12));
        assert!(descriptor.is_some());

        let (key_read, _key_write) = pipe_with(PipeFlags::CLOEXEC).expect("key pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_configure(8, 32),
            Some(key_read.as_fd()),
            deadline,
        )
        .expect("send provider configure");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_configure(8, 32));
        assert!(descriptor.is_some());

        let (_borrow_read, borrow_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("borrow pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_borrow(9),
            Some(borrow_write.as_fd()),
            deadline,
        )
        .expect("send provider borrow");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_borrow(9));
        assert!(descriptor.is_some());

        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        send_response(worker.as_fd(), &response, deadline).expect("send response");
        assert_eq!(
            receive_response(parent.as_fd(), 7, deadline).expect("receive response"),
            response
        );

        let response = WorkerResponse::provider_borrow_ready(9, 32);
        send_response(worker.as_fd(), &response, deadline).expect("send borrow response");
        assert_eq!(
            receive_response(parent.as_fd(), 9, deadline).expect("receive borrow response"),
            response
        );
    }

    #[test]
    fn canonical_frames_reject_wrong_arity_reserved_bytes_and_correlation() {
        assert_eq!(
            WorkerCommand::unlock(1, 11).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let borrow = WorkerCommand::provider_openai_borrow(1)
            .encode()
            .expect("borrow frame");
        assert_eq!(borrow[8], 10);
        assert_eq!(&borrow[24..26], &[0, 0]);
        let mut noncanonical_borrow = borrow;
        noncanonical_borrow[25] = 1;
        assert_eq!(
            WorkerCommand::decode(&noncanonical_borrow),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowReady).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let encoded_ready = WorkerResponse::provider_borrow_ready(1, 32)
            .encode()
            .expect("canonical ready response");
        assert_eq!(encoded_ready[8], 31);
        assert_eq!(encoded_ready[9], 0);
        assert_eq!(&encoded_ready[10..12], &[0, 32]);
        let encoded_unconfigured =
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowUnconfigured)
                .encode()
                .expect("canonical unconfigured response");
        assert_eq!(encoded_unconfigured[8], 32);
        assert_eq!(&encoded_unconfigured[10..12], &[0, 0]);
        let mut frame = WorkerCommand::probe(1).encode().expect("frame");
        frame[15] = 1;
        assert_eq!(
            WorkerCommand::decode(&frame),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_command = WorkerCommand::probe(1).encode().expect("legacy command");
        legacy_command[..8].copy_from_slice(b"KRVWC001");
        assert_eq!(
            WorkerCommand::decode(&legacy_command),
            Err(InternalWireError::InvalidFrame)
        );
        let response = WorkerResponse::new(9, WorkerResultCode::ProbeLocked);
        let mut encoded = response.encode().expect("response");
        encoded[63] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_response = response.encode().expect("legacy response");
        legacy_response[..8].copy_from_slice(b"KRVWR001");
        assert_eq!(
            WorkerResponse::decode(&legacy_response),
            Err(InternalWireError::InvalidFrame)
        );
        let mut encoded = WorkerResponse::new(9, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        encoded[11] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let mut encoded = WorkerResponse::provider_borrow_ready(9, 32)
            .encode()
            .expect("borrow response");
        encoded[11] = 0;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, worker) = pair();
        let deadline = Instant::now() + Duration::from_secs(2);
        send_response(worker.as_fd(), &response, deadline).expect("send");
        assert_eq!(
            receive_response(parent.as_fd(), 10, deadline),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, _worker) = pair();
        assert_eq!(
            send_command(
                parent.as_fd(),
                WorkerCommand::provider_openai_borrow(11),
                None,
                deadline
            ),
            Err(InternalWireError::InvalidDescriptors)
        );
    }

    #[test]
    fn debug_and_errors_never_contain_payload_or_descriptor_numbers() {
        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        let debug = format!("{response:?}");
        assert!(debug.contains("KA-"));
        assert!(!InternalWireError::InvalidFrame.to_string().contains('7'));
    }

    #[test]
    fn short_extra_and_timed_out_records_fail_closed() {
        for bytes in [
            &[0_u8; COMMAND_BYTES - 1][..],
            &[0_u8; COMMAND_BYTES + 1][..],
        ] {
            let (sender, receiver) = pair();
            send(&sender, bytes, SendFlags::NOSIGNAL).expect("raw frame");
            assert!(matches!(
                receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
                Err(InternalWireError::InvalidFrame)
            ));
        }
        let (_sender, receiver) = pair();
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::TimedOut)
        ));
    }

    #[test]
    fn duplicate_rights_are_rejected_and_closed() {
        fn descriptor_target(descriptor: BorrowedFd<'_>) -> OsString {
            std::fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                .expect("descriptor target")
                .into_os_string()
        }

        fn target_count(target: &OsString) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("proc fd")
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .filter(|observed| observed.as_os_str() == target.as_os_str())
                .count()
        }

        let (sender, receiver) = pair();
        let (first, first_write) = pipe_with(PipeFlags::CLOEXEC).expect("first pipe");
        let (second, second_write) = pipe_with(PipeFlags::CLOEXEC).expect("second pipe");
        let first_target = descriptor_target(first.as_fd());
        let second_target = descriptor_target(second.as_fd());
        let first_baseline = target_count(&first_target);
        let second_baseline = target_count(&second_target);
        let frame = WorkerCommand::unlock(9, 12).encode().expect("frame");
        let io = [IoSlice::new(&frame)];
        let rights = [first.as_fd(), second.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(&sender, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("send rights"),
            COMMAND_BYTES
        );
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
            Err(InternalWireError::InvalidDescriptors)
        ));
        assert_eq!(target_count(&first_target), first_baseline);
        assert_eq!(target_count(&second_target), second_baseline);
        rustix::io::fcntl_getfd(&first_write).expect("first writer remains owned");
        rustix::io::fcntl_getfd(&second_write).expect("second writer remains owned");
    }

    #[test]
    fn generated_credentials_and_send_backpressure_are_bounded() {
        let (_sender, receiver) = pair();
        rustix::net::sockopt::set_socket_passcred(&receiver, true).expect("passcred");
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::InvalidTransport)
        ));

        let (sender, _receiver) = pair();
        rustix::net::sockopt::set_socket_send_buffer_size(&sender, 1024)
            .expect("small send buffer");
        let frame = WorkerResponse::new(1, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        let mut filled = false;
        let mut unexpected_error = false;
        for _ in 0..10_000 {
            match send(&sender, &frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    filled = true;
                    break;
                }
                Err(_) => {
                    unexpected_error = true;
                    break;
                }
            }
        }
        assert!(!unexpected_error);
        assert!(filled);
        assert_eq!(
            send_response(
                sender.as_fd(),
                &WorkerResponse::new(2, WorkerResultCode::ProbeLocked),
                Instant::now() + Duration::from_millis(20)
            ),
            Err(InternalWireError::TimedOut)
        );
    }
}
