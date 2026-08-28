//! Strict one-shot client for the root-owned Rescue write-mount handoff.
//!
//! The request is derived only from one already durable `Pending` Repair Vault
//! transaction. A successful response transfers exactly one detached writable
//! ext4 mount. Once request transmission is attempted, every non-success is
//! ambiguous because the server may already have consumed the single-use
//! Vault lease; callers must reconcile and must never retry or cancel.

use kernaid_protocol::{
    rescue_repair_vault::{
        RepairBackupState, RepairTransactionPhase, RepairTransactionStatusPayload,
    },
    rescue_vault::RequestId,
    rescue_vault_transport::{SeqpacketTransportError, authenticate_root_seqpacket_server},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags, StatVfsMountFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, recvmsg,
        sendmsg, socket_with,
    },
    rand::{GetRandomFlags, getrandom},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Write as _},
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    time::{Duration, Instant},
};

const TARGET_WRITE_CAPABILITY_SOCKET: &str = "/run/kernaid-rescue-target-write-capability.sock";
const API_VERSION: &str = "kernaid.dev/rescue-target-capability/v1alpha2";
const ACQUIRE_OPERATION: &str = "target.pending.readwrite.acquire";
const CAPABILITY_TYPE: &str = "linux-ext4-direct-leaf-readwrite-mount-v1";
const DESCRIPTOR_TYPE: &str = "selected-target-ext4-mount-readwrite-detached";
const EXT_SUPER_MAGIC: u64 = 0xef53;
const MAX_REQUEST_FRAME_BYTES: usize = 1_024;
const MAX_RESPONSE_FRAME_BYTES: usize = 2_048;

/// Sanitized result vocabulary for the one-shot handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetWriteCapabilityClientError {
    InvalidPending,
    Unavailable,
    TimedOut,
    ServerNotRoot,
    InvalidTransport,
    /// Transmission was attempted. The Vault lease may have been consumed,
    /// so the only safe next operation is typed transaction reconciliation.
    ReconciliationRequired,
}

impl fmt::Display for TargetWriteCapabilityClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPending => "invalid Pending repair transaction",
            Self::Unavailable => "target write capability service unavailable",
            Self::TimedOut => "target write capability deadline expired",
            Self::ServerNotRoot => "target write capability server is not root",
            Self::InvalidTransport => "invalid target write capability transport",
            Self::ReconciliationRequired => "target write capability reconciliation required",
        })
    }
}

impl std::error::Error for TargetWriteCapabilityClientError {}

/// Non-cloneable authority for one exact writable detached mount.
pub struct RescueTargetWriteMountCapability {
    mount: OwnedFd,
    reservation_id: String,
    transaction_binding_sha256: String,
    target_recovery_fingerprint: String,
    lease_binding_sha256: String,
}

impl RescueTargetWriteMountCapability {
    pub(crate) fn mount(&self) -> &OwnedFd {
        &self.mount
    }

    pub(crate) fn revalidate(&self) -> Result<(), TargetWriteCapabilityClientError> {
        validate_write_mount(self.mount.as_fd())
            .map_err(|_| TargetWriteCapabilityClientError::ReconciliationRequired)
    }

    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    pub fn transaction_binding_sha256(&self) -> &str {
        &self.transaction_binding_sha256
    }

    pub fn target_recovery_fingerprint(&self) -> &str {
        &self.target_recovery_fingerprint
    }

    pub fn lease_binding_sha256(&self) -> &str {
        &self.lease_binding_sha256
    }
}

impl fmt::Debug for RescueTargetWriteMountCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetWriteMountCapability")
            .field("mount", &"[owned detached writable ext4 mount]")
            .field("reservation_id", &"[opaque]")
            .field("transaction_binding_sha256", &"[opaque hash]")
            .field("target_recovery_fingerprint", &"[opaque stable digest]")
            .field("lease_binding_sha256", &"[opaque hash]")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcquireRequestWire<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    reservation_id: &'a str,
    transaction_binding_sha256: &'a str,
}

#[derive(Deserialize)]
struct OutcomeProbe {
    outcome: Outcome,
}

#[derive(Deserialize)]
enum Outcome {
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
    reservation_id: String,
    transaction_binding_sha256: String,
    target_recovery_fingerprint: String,
    lease_binding_sha256: String,
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
    error: String,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostSendError {
    Invalid,
    TimedOut,
}

/// Consumes the RPC opportunity for one exact durable Pending transaction.
///
/// This function never retries after request transmission. Any error at or
/// after `sendmsg` is deliberately collapsed to `ReconciliationRequired`.
pub fn acquire_pending_target_write_mount(
    pending: &RepairTransactionStatusPayload,
    deadline: Instant,
) -> Result<RescueTargetWriteMountCapability, TargetWriteCapabilityClientError> {
    let intent = pending
        .backup()
        .execution_intent()
        .ok_or(TargetWriteCapabilityClientError::InvalidPending)?;
    if pending.phase() != RepairTransactionPhase::Pending
        || pending.backup().state() != RepairBackupState::Durable
        || !valid_recovery_fingerprint(intent.target_recovery_fingerprint())
    {
        return Err(TargetWriteCapabilityClientError::InvalidPending);
    }
    let reservation_id = pending.backup().reservation_id().as_str();
    let transaction_binding_sha256 = pending.transaction_binding_sha256().as_str();
    let request_id = fresh_request_id()?;
    let request = AcquireRequestWire {
        api_version: API_VERSION,
        request_id: request_id.as_str(),
        operation: ACQUIRE_OPERATION,
        reservation_id,
        transaction_binding_sha256,
    };
    let encoded = serde_json::to_vec(&request)
        .map_err(|_| TargetWriteCapabilityClientError::InvalidPending)?;
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(TargetWriteCapabilityClientError::InvalidPending);
    }

    ensure_before(deadline)?;
    let socket = connect_fixed_endpoint(deadline)?;
    authenticate_root_seqpacket_server(socket.as_fd()).map_err(|error| match error {
        SeqpacketTransportError::ServerNotRoot => TargetWriteCapabilityClientError::ServerNotRoot,
        _ => TargetWriteCapabilityClientError::InvalidTransport,
    })?;

    // From the first send syscall onward, even a transport failure is
    // ambiguous with a consumed Vault lease. Never retry this request.
    send_frame(socket.as_fd(), &encoded, deadline)
        .map_err(|_| TargetWriteCapabilityClientError::ReconciliationRequired)?;
    let received = receive_frame(socket.as_fd(), deadline)
        .map_err(|_| TargetWriteCapabilityClientError::ReconciliationRequired)?;
    decode_response(
        received,
        request_id.as_str(),
        reservation_id,
        transaction_binding_sha256,
        intent.target_recovery_fingerprint(),
    )
    .map_err(|_| TargetWriteCapabilityClientError::ReconciliationRequired)
}

fn connect_fixed_endpoint(deadline: Instant) -> Result<OwnedFd, TargetWriteCapabilityClientError> {
    ensure_before(deadline)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| TargetWriteCapabilityClientError::Unavailable)?;
    let address = SocketAddrUnix::new(TARGET_WRITE_CAPABILITY_SOCKET)
        .map_err(|_| TargetWriteCapabilityClientError::Unavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| TargetWriteCapabilityClientError::Unavailable)?
                .map_err(|_| TargetWriteCapabilityClientError::Unavailable)?;
        }
        Err(_) => return Err(TargetWriteCapabilityClientError::Unavailable),
    }
    Ok(socket)
}

fn send_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), PostSendError> {
    if frame.is_empty() || frame.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(PostSendError::Invalid);
    }
    ensure_post_send_before(deadline)?;
    let io = [IoSlice::new(frame)];
    let mut control_space: [MaybeUninit<u8>; 0] = [];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    let sent = loop {
        match sendmsg(
            socket,
            &io,
            &mut control,
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        ) {
            Ok(sent) => break sent,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready_post_send(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(PostSendError::Invalid),
        }
    };
    if sent != frame.len() {
        return Err(PostSendError::Invalid);
    }
    Ok(())
}

fn receive_frame(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<ReceivedFrame, PostSendError> {
    let mut bytes = vec![0_u8; MAX_RESPONSE_FRAME_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    // Exactly one FD is allowed. n+1 capacity makes a second FD observable;
    // larger or mixed ancillary input is rejected via MSG_CTRUNC/record checks.
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        ensure_post_send_before(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready_post_send(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(PostSendError::Invalid),
        }
    };

    let mut descriptors = Vec::new();
    let mut rights_records = 0_u8;
    let mut unexpected = false;
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(rights) => {
                rights_records = rights_records.saturating_add(1);
                descriptors.extend(rights);
            }
            RecvAncillaryMessage::ScmCredentials(_) => unexpected = true,
            _ => unexpected = true,
        }
    }
    drop(control);
    if message
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || message.bytes == 0
        || message.bytes > MAX_RESPONSE_FRAME_BYTES
        || unexpected
        || rights_records > 1
        || descriptors.len() > 1
    {
        return Err(PostSendError::Invalid);
    }
    bytes.truncate(message.bytes);
    Ok(ReceivedFrame { bytes, descriptors })
}

fn decode_response(
    received: ReceivedFrame,
    request_id: &str,
    reservation_id: &str,
    transaction_binding_sha256: &str,
    target_recovery_fingerprint: &str,
) -> Result<RescueTargetWriteMountCapability, PostSendError> {
    let probe: OutcomeProbe =
        serde_json::from_slice(&received.bytes).map_err(|_| PostSendError::Invalid)?;
    match probe.outcome {
        Outcome::Ok => {
            let response: SuccessResponseWire =
                serde_json::from_slice(&received.bytes).map_err(|_| PostSendError::Invalid)?;
            if response.api_version != API_VERSION
                || response.request_id != request_id
                || response.operation != ACQUIRE_OPERATION
                || response.reservation_id != reservation_id
                || response.transaction_binding_sha256 != transaction_binding_sha256
                || response.target_recovery_fingerprint != target_recovery_fingerprint
                || response.capability != CAPABILITY_TYPE
                || response.descriptor.descriptor_type != DESCRIPTOR_TYPE
                || response.descriptor.count != 1
                || !valid_raw_sha256(&response.lease_binding_sha256)
                || response
                    .lease_binding_sha256
                    .bytes()
                    .all(|byte| byte == b'0')
            {
                return Err(PostSendError::Invalid);
            }
            let [mount]: [OwnedFd; 1] = received
                .descriptors
                .try_into()
                .map_err(|_| PostSendError::Invalid)?;
            validate_write_mount(mount.as_fd())?;
            Ok(RescueTargetWriteMountCapability {
                mount,
                reservation_id: response.reservation_id,
                transaction_binding_sha256: response.transaction_binding_sha256,
                target_recovery_fingerprint: response.target_recovery_fingerprint,
                lease_binding_sha256: response.lease_binding_sha256,
            })
        }
        Outcome::Error => {
            let response: ErrorResponseWire =
                serde_json::from_slice(&received.bytes).map_err(|_| PostSendError::Invalid)?;
            if response.api_version != API_VERSION
                || response.request_id != request_id
                || response.operation != ACQUIRE_OPERATION
                || response.error.is_empty()
                || response.error.len() > 64
                || !response
                    .error
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
                || !received.descriptors.is_empty()
            {
                return Err(PostSendError::Invalid);
            }
            Err(PostSendError::Invalid)
        }
    }
}

fn validate_write_mount(descriptor: BorrowedFd<'_>) -> Result<(), PostSendError> {
    let stat = rfs::fstat(descriptor).map_err(|_| PostSendError::Invalid)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| PostSendError::Invalid)?;
    let flags = rfs::fstatvfs(descriptor).map_err(|_| PostSendError::Invalid)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| PostSendError::Invalid)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| PostSendError::Invalid)?;
    let required = StatVfsMountFlags::NODEV | StatVfsMountFlags::NOSUID | StatVfsMountFlags::NOEXEC;
    if descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || !status.contains(OFlags::PATH)
        || !FileType::from_raw_mode(stat.st_mode).is_dir()
        || filesystem.f_type as u64 != EXT_SUPER_MAGIC
        || !flags.f_flag.contains(required)
        || flags.f_flag.contains(StatVfsMountFlags::RDONLY)
    {
        return Err(PostSendError::Invalid);
    }
    Ok(())
}

fn valid_raw_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_recovery_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("recovery:")
        .is_some_and(valid_raw_sha256)
}

fn fresh_request_id() -> Result<RequestId, TargetWriteCapabilityClientError> {
    let mut random = [0_u8; 16];
    let mut offset = 0;
    while offset < random.len() {
        let count = getrandom(&mut random[offset..], GetRandomFlags::NONBLOCK)
            .map_err(|_| TargetWriteCapabilityClientError::Unavailable)?;
        if count == 0 {
            return Err(TargetWriteCapabilityClientError::Unavailable);
        }
        offset += count;
    }
    let mut value = String::with_capacity(38);
    value.push_str("R-");
    for (index, byte) in random.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        write!(&mut value, "{byte:02x}")
            .map_err(|_| TargetWriteCapabilityClientError::InvalidTransport)?;
    }
    RequestId::parse(&value).map_err(|_| TargetWriteCapabilityClientError::InvalidTransport)
}

fn ensure_before(deadline: Instant) -> Result<(), TargetWriteCapabilityClientError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(TargetWriteCapabilityClientError::TimedOut)
}

fn ensure_post_send_before(deadline: Instant) -> Result<(), PostSendError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(PostSendError::TimedOut)
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), TargetWriteCapabilityClientError> {
    wait_ready_inner(descriptor, interest, deadline).map_err(|error| match error {
        PostSendError::TimedOut => TargetWriteCapabilityClientError::TimedOut,
        PostSendError::Invalid => TargetWriteCapabilityClientError::InvalidTransport,
    })
}

fn wait_ready_post_send(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), PostSendError> {
    wait_ready_inner(descriptor, interest, deadline)
}

fn wait_ready_inner(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), PostSendError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PostSendError::TimedOut)?;
        let timeout = duration_to_timespec(remaining);
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(PostSendError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(PostSendError::Invalid);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(PostSendError::Invalid),
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
    const RESERVATION_ID: &str = "B-0123456789abcdef0123456789abcdef";

    fn raw_hash(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn recovery(character: char) -> String {
        format!("recovery:{}", raw_hash(character))
    }

    fn success_frame() -> Vec<u8> {
        format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"operation\":\"{ACQUIRE_OPERATION}\",\"outcome\":\"ok\",\"reservationId\":\"{RESERVATION_ID}\",\"transactionBindingSha256\":\"{}\",\"targetRecoveryFingerprint\":\"{}\",\"leaseBindingSha256\":\"{}\",\"capability\":\"{CAPABILITY_TYPE}\",\"descriptor\":{{\"type\":\"{DESCRIPTOR_TYPE}\",\"count\":1}}}}",
            raw_hash('a'),
            recovery('b'),
            raw_hash('c'),
        )
        .into_bytes()
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

    #[test]
    fn request_codec_contains_only_pending_selector() {
        let binding = raw_hash('a');
        let request = AcquireRequestWire {
            api_version: API_VERSION,
            request_id: REQUEST_ID,
            operation: ACQUIRE_OPERATION,
            reservation_id: RESERVATION_ID,
            transaction_binding_sha256: &binding,
        };
        let encoded = serde_json::to_vec(&request).expect("encode request");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("request JSON");
        let object = value.as_object().expect("request object");
        assert_eq!(object.len(), 5);
        assert_eq!(object["reservationId"], RESERVATION_ID);
        assert_eq!(object["transactionBindingSha256"], binding);
        assert!(!object.contains_key("targetPath"));
        assert!(!object.contains_key("mountOptions"));
    }

    #[test]
    fn receiver_materializes_and_rejects_n_plus_one_rights() {
        let (client, server) = pair();
        let descriptor = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("open harmless descriptor");
        send_raw(
            server.as_fd(),
            &success_frame(),
            &[descriptor.as_fd(), descriptor.as_fd()],
        );
        assert!(matches!(
            receive_frame(client.as_fd(), Instant::now() + Duration::from_secs(1)),
            Err(PostSendError::Invalid)
        ));
    }

    #[test]
    fn success_requires_a_real_writable_ext4_mount() {
        let descriptor = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("open harmless descriptor");
        let result = decode_response(
            ReceivedFrame {
                bytes: success_frame(),
                descriptors: vec![descriptor],
            },
            REQUEST_ID,
            RESERVATION_ID,
            &raw_hash('a'),
            &recovery('b'),
        );
        assert_eq!(result.err(), Some(PostSendError::Invalid));
    }

    #[test]
    fn response_unknown_fields_and_claim_drift_are_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&success_frame()).expect("success JSON");
        value["unexpected"] = serde_json::Value::Bool(true);
        let result = decode_response(
            ReceivedFrame {
                bytes: serde_json::to_vec(&value).expect("tampered JSON"),
                descriptors: Vec::new(),
            },
            REQUEST_ID,
            RESERVATION_ID,
            &raw_hash('a'),
            &recovery('b'),
        );
        assert_eq!(result.err(), Some(PostSendError::Invalid));
    }
}
