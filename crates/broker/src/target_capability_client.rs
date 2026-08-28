//! Strict client for the root-owned Rescue target capability endpoint.
//!
//! The normal wire request contains only boot-ephemeral opaque identifiers;
//! the recovery request contains only one reboot-stable opaque digest. A
//! successful response carries exactly one read-only block descriptor and
//! fresh path-free identity claims. This module never mounts or writes.

use kernaid_protocol::{
    rescue_vault::RequestId, rescue_vault_transport::authenticate_root_seqpacket_server,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{self as rfs, FileType, OFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, recvmsg,
        sendmsg, socket_with,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

const TARGET_CAPABILITY_SOCKET: &str = "/run/kernaid-rescue-target-capability.sock";
const API_VERSION: &str = "kernaid.dev/rescue-target-capability/v1alpha1";
const ACQUIRE_OPERATION: &str = "target.readonly.acquire";
const RECOVERY_OPERATION: &str = "target.recovery.readonly.acquire";
const CAPABILITY_TYPE: &str = "linux-ext4-direct-leaf-readonly-block-v1";
const DESCRIPTOR_TYPE: &str = "selected-target-block-readonly";
const MAX_FRAME_BYTES: usize = 1_024;
const MAX_OPAQUE_ID_BYTES: usize = 128;

/// Sanitized target-capability failures. No variant can carry peer text, a
/// path, a device number, or raw target metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetCapabilityClientError {
    InvalidRequest,
    Unavailable,
    TimedOut,
    ServerNotRoot,
    InvalidTransport,
    FrameTooLarge,
    InvalidFrame,
    UnexpectedAncillary,
    AncillaryTruncated,
    DescriptorRequired,
    DescriptorForbidden,
    DescriptorCountMismatch,
    DescriptorNotCloseOnExec,
    DescriptorNotReadOnly,
    DescriptorNotBlockDevice,
    CorrelationMismatch,
    ClaimsMismatch,
    TargetRejected(TargetCapabilityErrorToken),
}

impl fmt::Display for TargetCapabilityClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid target capability request",
            Self::Unavailable => "target capability service unavailable",
            Self::TimedOut => "target capability request timed out",
            Self::ServerNotRoot => "target capability server is not root",
            Self::InvalidTransport => "invalid target capability transport",
            Self::FrameTooLarge => "target capability frame exceeds its bound",
            Self::InvalidFrame => "invalid target capability frame",
            Self::UnexpectedAncillary => "unexpected target capability ancillary record",
            Self::AncillaryTruncated => "truncated target capability ancillary record",
            Self::DescriptorRequired => "target capability descriptor required",
            Self::DescriptorForbidden => "target capability descriptor forbidden",
            Self::DescriptorCountMismatch => "target capability descriptor count mismatch",
            Self::DescriptorNotCloseOnExec => "target capability descriptor is inheritable",
            Self::DescriptorNotReadOnly => "target capability descriptor is not read-only",
            Self::DescriptorNotBlockDevice => "target capability descriptor is not a block device",
            Self::CorrelationMismatch => "target capability response correlation mismatch",
            Self::ClaimsMismatch => "target capability response claims mismatch",
            Self::TargetRejected(_) => "target capability request rejected",
        })
    }
}

impl std::error::Error for TargetCapabilityClientError {}

/// Closed error tokens returned by the privileged target resolver.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum TargetCapabilityErrorToken {
    #[serde(rename = "INVALID_REQUEST")]
    InvalidRequest,
    #[serde(rename = "TARGET_UNAVAILABLE")]
    TargetUnavailable,
    #[serde(rename = "TARGET_UNSUPPORTED")]
    TargetUnsupported,
    #[serde(rename = "TARGET_CHANGED")]
    TargetChanged,
    #[serde(rename = "DEVICE_UNAVAILABLE")]
    DeviceUnavailable,
    #[serde(rename = "INTERNAL")]
    Internal,
}

/// Path-free identity claims attached to the held block capability.
///
/// Construction is private: these claims only exist after root-peer,
/// correlation, descriptor-arity and descriptor-kind validation.
pub struct RescueTargetCapabilityClaims {
    request_id: String,
    scan_fingerprint: String,
    target_fingerprint: String,
    target_id: String,
    recovery_fingerprint: String,
}

impl RescueTargetCapabilityClaims {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }

    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn recovery_fingerprint(&self) -> &str {
        &self.recovery_fingerprint
    }
}

impl fmt::Debug for RescueTargetCapabilityClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetCapabilityClaims")
            .field("request_id", &"[opaque]")
            .field("scan_fingerprint", &"[opaque]")
            .field("target_fingerprint", &"[opaque]")
            .field("target_id", &"[opaque]")
            .field("recovery_fingerprint", &"[opaque stable digest]")
            .finish()
    }
}

/// Non-cloneable read-only authority for one selected Rescue target.
///
/// Dropping this value closes the block descriptor. No public API exposes a
/// block-device path or permits replacing the descriptor.
pub struct RescueTargetReadOnlyCapability {
    block: OwnedFd,
    claims: RescueTargetCapabilityClaims,
}

impl RescueTargetReadOnlyCapability {
    pub fn claims(&self) -> &RescueTargetCapabilityClaims {
        &self.claims
    }

    /// Borrows the already validated read-only block capability. This is an
    /// fd-only boundary; no device or filesystem path can be recovered from
    /// the wire protocol.
    pub fn block_descriptor(&self) -> BorrowedFd<'_> {
        self.block.as_fd()
    }
}

impl fmt::Debug for RescueTargetReadOnlyCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetReadOnlyCapability")
            .field("block", &"[owned read-only block capability]")
            .field("claims", &self.claims)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectedCapabilityRequestWire<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    scan_fingerprint: &'a str,
    target_fingerprint: &'a str,
    target_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCapabilityRequestWire<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    recovery_fingerprint: &'a str,
}

#[derive(Deserialize)]
struct OutcomeProbe {
    outcome: CapabilityOutcome,
}

#[derive(Deserialize)]
enum CapabilityOutcome {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorWire {
    #[serde(rename = "type")]
    descriptor_type: String,
    count: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuccessResponseWire {
    api_version: String,
    request_id: String,
    operation: String,
    #[serde(rename = "outcome")]
    _outcome: SuccessOutcome,
    scan_fingerprint: String,
    target_fingerprint: String,
    target_id: String,
    recovery_fingerprint: String,
    capability: String,
    descriptor: DescriptorWire,
}

#[derive(Deserialize)]
enum SuccessOutcome {
    #[serde(rename = "ok")]
    Ok,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorResponseWire {
    api_version: String,
    request_id: String,
    operation: String,
    #[serde(rename = "outcome")]
    _outcome: ErrorOutcome,
    error: TargetCapabilityErrorToken,
}

#[derive(Deserialize)]
enum ErrorOutcome {
    #[serde(rename = "error")]
    Error,
}

struct ReceivedFrame {
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
}

enum ExpectedClaims<'a> {
    Selected {
        scan_fingerprint: &'a str,
        target_fingerprint: &'a str,
        target_id: &'a str,
    },
    Recovery {
        recovery_fingerprint: &'a str,
    },
}

impl ExpectedClaims<'_> {
    fn operation(&self) -> &'static str {
        match self {
            Self::Selected { .. } => ACQUIRE_OPERATION,
            Self::Recovery { .. } => RECOVERY_OPERATION,
        }
    }
}

/// Acquires one target capability from the fixed root-owned endpoint.
///
/// The caller chooses a total monotonic deadline. The endpoint path is fixed
/// and cannot be redirected through this API.
pub fn acquire_rescue_target_capability(
    request_id: &RequestId,
    scan_fingerprint: &str,
    target_fingerprint: &str,
    target_id: &str,
    deadline: Instant,
) -> Result<RescueTargetReadOnlyCapability, TargetCapabilityClientError> {
    validate_request_fields(scan_fingerprint, target_fingerprint, target_id)?;
    ensure_before(deadline)?;
    let connection = connect_fixed_endpoint(deadline)?;
    authenticate_root_seqpacket_server(connection.as_fd()).map_err(|error| match error {
        kernaid_protocol::rescue_vault_transport::SeqpacketTransportError::ServerNotRoot => {
            TargetCapabilityClientError::ServerNotRoot
        }
        _ => TargetCapabilityClientError::InvalidTransport,
    })?;

    let request = SelectedCapabilityRequestWire {
        api_version: API_VERSION,
        request_id: request_id.as_str(),
        operation: ACQUIRE_OPERATION,
        scan_fingerprint,
        target_fingerprint,
        target_id,
    };
    let encoded =
        serde_json::to_vec(&request).map_err(|_| TargetCapabilityClientError::InvalidRequest)?;
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(TargetCapabilityClientError::InvalidRequest);
    }
    send_frame(connection.as_fd(), &encoded, deadline)?;
    let received = receive_frame(connection.as_fd(), deadline)?;
    decode_response(
        received,
        request_id.as_str(),
        ExpectedClaims::Selected {
            scan_fingerprint,
            target_fingerprint,
            target_id,
        },
    )
}

/// Reacquires one target after reboot using only its durable opaque digest.
///
/// Every boot-local claim in the result is freshly produced by the root-owned
/// resolver. No stale scan, target, parent claim, path or device number is
/// accepted from the caller.
pub fn reacquire_rescue_target_capability(
    request_id: &RequestId,
    recovery_fingerprint: &str,
    deadline: Instant,
) -> Result<RescueTargetReadOnlyCapability, TargetCapabilityClientError> {
    validate_recovery_fingerprint(recovery_fingerprint)?;
    ensure_before(deadline)?;
    let connection = connect_fixed_endpoint(deadline)?;
    authenticate_root_seqpacket_server(connection.as_fd()).map_err(|error| match error {
        kernaid_protocol::rescue_vault_transport::SeqpacketTransportError::ServerNotRoot => {
            TargetCapabilityClientError::ServerNotRoot
        }
        _ => TargetCapabilityClientError::InvalidTransport,
    })?;
    let request = RecoveryCapabilityRequestWire {
        api_version: API_VERSION,
        request_id: request_id.as_str(),
        operation: RECOVERY_OPERATION,
        recovery_fingerprint,
    };
    let encoded =
        serde_json::to_vec(&request).map_err(|_| TargetCapabilityClientError::InvalidRequest)?;
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(TargetCapabilityClientError::InvalidRequest);
    }
    send_frame(connection.as_fd(), &encoded, deadline)?;
    let received = receive_frame(connection.as_fd(), deadline)?;
    decode_response(
        received,
        request_id.as_str(),
        ExpectedClaims::Recovery {
            recovery_fingerprint,
        },
    )
}

fn connect_fixed_endpoint(deadline: Instant) -> Result<OwnedFd, TargetCapabilityClientError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| TargetCapabilityClientError::Unavailable)?;
    let address = SocketAddrUnix::new(TARGET_CAPABILITY_SOCKET)
        .map_err(|_| TargetCapabilityClientError::Unavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| TargetCapabilityClientError::Unavailable)?
                .map_err(|_| TargetCapabilityClientError::Unavailable)?;
        }
        Err(_) => return Err(TargetCapabilityClientError::Unavailable),
    }
    Ok(socket)
}

fn validate_request_fields(
    scan_fingerprint: &str,
    target_fingerprint: &str,
    target_id: &str,
) -> Result<(), TargetCapabilityClientError> {
    if !valid_prefixed_hash(scan_fingerprint, "scan:")
        || !valid_prefixed_hash(target_fingerprint, "sha256:")
        || !valid_prefixed_hash(target_id, "target:")
        || target_id.len() > MAX_OPAQUE_ID_BYTES
    {
        return Err(TargetCapabilityClientError::InvalidRequest);
    }
    Ok(())
}

fn validate_recovery_fingerprint(
    recovery_fingerprint: &str,
) -> Result<(), TargetCapabilityClientError> {
    if !valid_prefixed_hash(recovery_fingerprint, "recovery:")
        || recovery_fingerprint.len() > MAX_OPAQUE_ID_BYTES
    {
        return Err(TargetCapabilityClientError::InvalidRequest);
    }
    Ok(())
}

fn send_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), TargetCapabilityClientError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(TargetCapabilityClientError::FrameTooLarge);
    }
    let io = [IoSlice::new(frame)];
    let mut control_space: [MaybeUninit<u8>; 0] = [];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    let sent = loop {
        ensure_before(deadline)?;
        match sendmsg(
            socket,
            &io,
            &mut control,
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        ) {
            Ok(sent) => break sent,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(TargetCapabilityClientError::InvalidTransport),
        }
    };
    if sent != frame.len() {
        return Err(TargetCapabilityClientError::InvalidTransport);
    }
    Ok(())
}

fn receive_frame(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<ReceivedFrame, TargetCapabilityClientError> {
    let mut bytes = vec![0_u8; MAX_FRAME_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    // Capacity for two rights detects an arity violation. Credentials are
    // also representable so they can be explicitly rejected rather than
    // silently accepted; excess control data causes MSG_CTRUNC.
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        ensure_before(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(TargetCapabilityClientError::InvalidTransport),
        }
    };

    // Materialize every delivered right before examining truncation flags so
    // all kernel-installed descriptors are owned and closed on every reject
    // path, including MSG_CTRUNC and an oversized data record.
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(_) => unexpected = true,
            _ => unexpected = true,
        }
    }
    drop(control);
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(TargetCapabilityClientError::AncillaryTruncated);
    }
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > MAX_FRAME_BYTES {
        return Err(TargetCapabilityClientError::FrameTooLarge);
    }
    if message.bytes == 0 {
        return Err(TargetCapabilityClientError::InvalidFrame);
    }
    if unexpected {
        return Err(TargetCapabilityClientError::UnexpectedAncillary);
    }
    if descriptors.len() > 1 {
        return Err(TargetCapabilityClientError::DescriptorCountMismatch);
    }

    bytes.truncate(message.bytes);
    Ok(ReceivedFrame { bytes, descriptors })
}

fn decode_response(
    received: ReceivedFrame,
    request_id: &str,
    expected: ExpectedClaims<'_>,
) -> Result<RescueTargetReadOnlyCapability, TargetCapabilityClientError> {
    let probe: OutcomeProbe = serde_json::from_slice(&received.bytes)
        .map_err(|_| TargetCapabilityClientError::InvalidFrame)?;
    match probe.outcome {
        CapabilityOutcome::Ok => {
            let response: SuccessResponseWire = serde_json::from_slice(&received.bytes)
                .map_err(|_| TargetCapabilityClientError::InvalidFrame)?;
            if response.api_version != API_VERSION
                || response.request_id != request_id
                || response.operation != expected.operation()
            {
                return Err(TargetCapabilityClientError::CorrelationMismatch);
            }
            let claims_match = match expected {
                ExpectedClaims::Selected {
                    scan_fingerprint,
                    target_fingerprint,
                    target_id,
                } => {
                    response.scan_fingerprint == scan_fingerprint
                        && response.target_fingerprint == target_fingerprint
                        && response.target_id == target_id
                        && valid_prefixed_hash(&response.recovery_fingerprint, "recovery:")
                }
                ExpectedClaims::Recovery {
                    recovery_fingerprint,
                } => {
                    response.recovery_fingerprint == recovery_fingerprint
                        && valid_prefixed_hash(&response.scan_fingerprint, "scan:")
                        && valid_prefixed_hash(&response.target_fingerprint, "sha256:")
                        && valid_prefixed_hash(&response.target_id, "target:")
                }
            };
            if !claims_match
                || response.capability != CAPABILITY_TYPE
                || response.descriptor.descriptor_type != DESCRIPTOR_TYPE
                || response.descriptor.count != 1
            {
                return Err(TargetCapabilityClientError::ClaimsMismatch);
            }
            let mut descriptors = received.descriptors;
            let block = match descriptors.len() {
                0 => return Err(TargetCapabilityClientError::DescriptorRequired),
                1 => descriptors
                    .pop()
                    .ok_or(TargetCapabilityClientError::DescriptorRequired)?,
                _ => return Err(TargetCapabilityClientError::DescriptorCountMismatch),
            };
            validate_block_descriptor(block.as_fd())?;
            Ok(RescueTargetReadOnlyCapability {
                block,
                claims: RescueTargetCapabilityClaims {
                    request_id: response.request_id,
                    scan_fingerprint: response.scan_fingerprint,
                    target_fingerprint: response.target_fingerprint,
                    target_id: response.target_id,
                    recovery_fingerprint: response.recovery_fingerprint,
                },
            })
        }
        CapabilityOutcome::Error => {
            let response: ErrorResponseWire = serde_json::from_slice(&received.bytes)
                .map_err(|_| TargetCapabilityClientError::InvalidFrame)?;
            if response.api_version != API_VERSION
                || response.request_id != request_id
                || response.operation != expected.operation()
            {
                return Err(TargetCapabilityClientError::CorrelationMismatch);
            }
            if !received.descriptors.is_empty() {
                return Err(TargetCapabilityClientError::DescriptorForbidden);
            }
            Err(TargetCapabilityClientError::TargetRejected(response.error))
        }
    }
}

fn validate_block_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<(), TargetCapabilityClientError> {
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    if descriptor_flags != rustix::io::FdFlags::CLOEXEC {
        return Err(TargetCapabilityClientError::DescriptorNotCloseOnExec);
    }
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    if status & OFlags::ACCMODE != OFlags::RDONLY {
        return Err(TargetCapabilityClientError::DescriptorNotReadOnly);
    }
    let stat = rfs::fstat(descriptor).map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device() {
        return Err(TargetCapabilityClientError::DescriptorNotBlockDevice);
    }
    Ok(())
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn ensure_before(deadline: Instant) -> Result<(), TargetCapabilityClientError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(TargetCapabilityClientError::TimedOut)
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), TargetCapabilityClientError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TargetCapabilityClientError::TimedOut)?;
        let timeout = duration_to_timespec(remaining);
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(TargetCapabilityClientError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(TargetCapabilityClientError::InvalidTransport);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(TargetCapabilityClientError::InvalidTransport),
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
        fs::{Mode, open},
        net::{SendAncillaryMessage, socketpair},
    };

    const REQUEST_ID: &str = "R-12345678-1234-1234-1234-123456789abc";

    fn scan(character: char) -> String {
        format!("scan:{}", character.to_string().repeat(64))
    }

    fn target(character: char) -> String {
        format!("target:{}", character.to_string().repeat(64))
    }

    fn fingerprint_value(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn recovery(character: char) -> String {
        format!("recovery:{}", character.to_string().repeat(64))
    }

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("seqpacket pair")
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    fn send_raw(socket: BorrowedFd<'_>, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) {
        let io = [IoSlice::new(bytes)];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !descriptors.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(descriptors)));
        }
        assert_eq!(
            sendmsg(socket, &io, &mut control, SendFlags::NOSIGNAL).expect("send frame"),
            bytes.len()
        );
    }

    fn send_many_rights(socket: BorrowedFd<'_>, bytes: &[u8], descriptor: BorrowedFd<'_>) {
        let descriptors = [descriptor; 32];
        let io = [IoSlice::new(bytes)];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(32))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        assert_eq!(
            sendmsg(socket, &io, &mut control, SendFlags::NOSIGNAL).expect("send many rights"),
            bytes.len()
        );
    }

    fn success_frame(
        operation: &str,
        scan_fingerprint: &str,
        target_fingerprint: &str,
        target_id: &str,
        recovery_fingerprint: &str,
    ) -> Vec<u8> {
        format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"operation\":\"{operation}\",\"outcome\":\"ok\",\"scanFingerprint\":\"{scan_fingerprint}\",\"targetFingerprint\":\"{target_fingerprint}\",\"targetId\":\"{target_id}\",\"recoveryFingerprint\":\"{recovery_fingerprint}\",\"capability\":\"{CAPABILITY_TYPE}\",\"descriptor\":{{\"type\":\"{DESCRIPTOR_TYPE}\",\"count\":1}}}}",
        )
        .into_bytes()
    }

    #[test]
    fn request_codec_is_closed_and_path_free() {
        let scan = scan('a');
        let fingerprint = fingerprint_value('c');
        let target = target('b');
        let request = SelectedCapabilityRequestWire {
            api_version: API_VERSION,
            request_id: REQUEST_ID,
            operation: ACQUIRE_OPERATION,
            scan_fingerprint: &scan,
            target_fingerprint: &fingerprint,
            target_id: &target,
        };
        let encoded = serde_json::to_vec(&request).expect("encode request");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("request JSON");
        let object = value.as_object().expect("request object");
        assert_eq!(object.len(), 6);
        assert_eq!(
            object.get("apiVersion").and_then(|value| value.as_str()),
            Some(API_VERSION)
        );
        assert_eq!(
            object.get("requestId").and_then(|value| value.as_str()),
            Some(REQUEST_ID)
        );
        assert_eq!(
            object.get("operation").and_then(|value| value.as_str()),
            Some(ACQUIRE_OPERATION)
        );
        assert_eq!(
            object
                .get("scanFingerprint")
                .and_then(|value| value.as_str()),
            Some(scan.as_str())
        );
        assert_eq!(
            object
                .get("targetFingerprint")
                .and_then(|value| value.as_str()),
            Some(fingerprint.as_str())
        );
        assert_eq!(
            object.get("targetId").and_then(|value| value.as_str()),
            Some(target.as_str())
        );
        assert!(!encoded.windows(5).any(|window| window == b"/dev/"));

        let recovery = recovery('d');
        let request = RecoveryCapabilityRequestWire {
            api_version: API_VERSION,
            request_id: REQUEST_ID,
            operation: RECOVERY_OPERATION,
            recovery_fingerprint: &recovery,
        };
        let encoded = serde_json::to_vec(&request).expect("encode recovery request");
        let object = serde_json::from_slice::<serde_json::Value>(&encoded)
            .expect("recovery JSON")
            .as_object()
            .expect("recovery object")
            .clone();
        assert_eq!(object.len(), 4);
        assert_eq!(
            object
                .get("recoveryFingerprint")
                .and_then(|value| value.as_str()),
            Some(recovery.as_str())
        );
        assert!(!encoded.windows(5).any(|window| window == b"/dev/"));
    }

    #[test]
    fn response_codec_denies_unknown_fields_and_requires_one_descriptor() {
        let scan = scan('a');
        let fingerprint = fingerprint_value('c');
        let target = target('b');
        let recovery = recovery('d');
        let response = success_frame(ACQUIRE_OPERATION, &scan, &fingerprint, &target, &recovery);
        let received = ReceivedFrame {
            bytes: response,
            descriptors: Vec::new(),
        };
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Selected {
                    scan_fingerprint: &scan,
                    target_fingerprint: &fingerprint,
                    target_id: &target,
                },
            )
            .err(),
            Some(TargetCapabilityClientError::DescriptorRequired)
        );

        let received = ReceivedFrame {
            bytes: success_frame(
                ACQUIRE_OPERATION,
                &scan,
                &fingerprint_value('e'),
                &target,
                &recovery,
            ),
            descriptors: Vec::new(),
        };
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Selected {
                    scan_fingerprint: &scan,
                    target_fingerprint: &fingerprint,
                    target_id: &target,
                },
            )
            .err(),
            Some(TargetCapabilityClientError::ClaimsMismatch)
        );

        let mut unknown = success_frame(ACQUIRE_OPERATION, &scan, &fingerprint, &target, &recovery);
        let suffix = b",\"path\":\"/dev/sda\"}";
        unknown.pop();
        unknown.extend_from_slice(suffix);
        let received = ReceivedFrame {
            bytes: unknown,
            descriptors: Vec::new(),
        };
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Selected {
                    scan_fingerprint: &scan,
                    target_fingerprint: &fingerprint,
                    target_id: &target,
                },
            )
            .err(),
            Some(TargetCapabilityClientError::InvalidFrame)
        );
    }

    #[test]
    fn socketpair_rejects_credentials_and_multiple_rights() {
        let (sender, receiver) = pair();
        rustix::net::sockopt::set_socket_passcred(&receiver, true)
            .expect("enable credentials for rejection test");
        send_raw(sender.as_fd(), b"{}", &[]);
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::UnexpectedAncillary)
        );

        let (sender, receiver) = pair();
        let first = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("first descriptor");
        let second = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("second descriptor");
        send_raw(sender.as_fd(), b"{}", &[first.as_fd(), second.as_fd()]);
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::DescriptorCountMismatch)
        );
    }

    #[test]
    fn socketpair_rejects_truncated_frame_and_fd_on_error() {
        let (sender, receiver) = pair();
        send_raw(sender.as_fd(), &vec![b'x'; MAX_FRAME_BYTES + 1], &[]);
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::FrameTooLarge)
        );

        let (sender, receiver) = pair();
        let descriptor =
            open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).expect("descriptor");
        let error = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"operation\":\"{ACQUIRE_OPERATION}\",\"outcome\":\"error\",\"error\":\"TARGET_CHANGED\"}}"
        );
        send_raw(sender.as_fd(), error.as_bytes(), &[descriptor.as_fd()]);
        let received = receive_frame(receiver.as_fd(), deadline()).expect("receive error frame");
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Selected {
                    scan_fingerprint: &scan('a'),
                    target_fingerprint: &fingerprint_value('c'),
                    target_id: &target('b'),
                },
            )
            .err(),
            Some(TargetCapabilityClientError::DescriptorForbidden)
        );
    }

    #[test]
    fn socketpair_rejects_truncated_ancillary_record() {
        let (sender, receiver) = pair();
        let descriptor =
            open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).expect("descriptor");
        send_many_rights(sender.as_fd(), b"{}", descriptor.as_fd());
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::AncillaryTruncated)
        );
    }

    #[test]
    fn rejects_non_block_and_non_read_only_descriptors() {
        let read_only = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("read-only character descriptor");
        assert_eq!(
            validate_block_descriptor(read_only.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotBlockDevice)
        );

        let writable = open("/dev/null", OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("writable descriptor");
        assert_eq!(
            validate_block_descriptor(writable.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotReadOnly)
        );

        let inheritable =
            open("/dev/null", OFlags::RDONLY, Mode::empty()).expect("inheritable descriptor");
        assert_eq!(
            validate_block_descriptor(inheritable.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotCloseOnExec)
        );
    }

    #[test]
    fn validates_only_canonical_opaque_request_ids() {
        assert!(validate_request_fields(&scan('a'), &fingerprint_value('c'), &target('b')).is_ok());
        assert_eq!(
            validate_request_fields("scan:AA", &fingerprint_value('c'), &target('b')),
            Err(TargetCapabilityClientError::InvalidRequest)
        );
        assert_eq!(
            validate_request_fields(&scan('a'), "sha256:AA", &target('b')),
            Err(TargetCapabilityClientError::InvalidRequest)
        );
        assert_eq!(
            validate_request_fields(&scan('a'), &fingerprint_value('c'), "/dev/sda"),
            Err(TargetCapabilityClientError::InvalidRequest)
        );
        assert!(validate_recovery_fingerprint(&recovery('d')).is_ok());
        assert_eq!(
            validate_recovery_fingerprint("recovery:AA"),
            Err(TargetCapabilityClientError::InvalidRequest)
        );
        assert_eq!(
            validate_recovery_fingerprint("/dev/sda2"),
            Err(TargetCapabilityClientError::InvalidRequest)
        );
    }

    #[test]
    fn recovery_response_requires_matching_digest_and_fresh_boot_claims() {
        let scan = scan('a');
        let fingerprint = fingerprint_value('b');
        let target = target('c');
        let expected_recovery = recovery('d');
        let received = ReceivedFrame {
            bytes: success_frame(
                RECOVERY_OPERATION,
                &scan,
                &fingerprint,
                &target,
                &recovery('e'),
            ),
            descriptors: Vec::new(),
        };
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Recovery {
                    recovery_fingerprint: &expected_recovery,
                },
            )
            .err(),
            Some(TargetCapabilityClientError::ClaimsMismatch)
        );

        let received = ReceivedFrame {
            bytes: success_frame(
                RECOVERY_OPERATION,
                "scan:AA",
                &fingerprint,
                &target,
                &expected_recovery,
            ),
            descriptors: Vec::new(),
        };
        assert_eq!(
            decode_response(
                received,
                REQUEST_ID,
                ExpectedClaims::Recovery {
                    recovery_fingerprint: &expected_recovery,
                },
            )
            .err(),
            Some(TargetCapabilityClientError::ClaimsMismatch)
        );
    }
}
