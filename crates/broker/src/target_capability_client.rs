//! Strict client for the root-owned Rescue target capability endpoint.
//!
//! The normal wire request contains only boot-ephemeral opaque identifiers;
//! the recovery request contains only one reboot-stable opaque digest. A
//! successful response carries one closed, ordered bundle: the selected leaf,
//! its physical parent, a sealed UUID inventory, and a detached read-only ext4
//! mount. This module never opens a device path, mounts, or writes.

use kernaid_protocol::{
    rescue_vault::RequestId, rescue_vault_transport::authenticate_root_seqpacket_server,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{self as rfs, FileType, OFlags, SealFlags, SeekFrom, StatVfsMountFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, recvmsg,
        sendmsg, socket_with,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

const TARGET_CAPABILITY_SOCKET: &str = "/run/kernaid-rescue-target-capability.sock";
const API_VERSION: &str = "kernaid.dev/rescue-target-capability/v1alpha2";
const ACQUIRE_OPERATION: &str = "target.readonly.acquire";
const RECOVERY_OPERATION: &str = "target.recovery.readonly.acquire";
const CAPABILITY_TYPE: &str = "linux-ext4-direct-leaf-readonly-bundle-v2";
const DESCRIPTOR_TYPES: [&str; 4] = [
    "selected-target-block-readonly",
    "physical-parent-block-identity-path",
    "uuid-inventory-memfd-sealed",
    "selected-target-ext4-mount-readonly-detached",
];
const UUID_INVENTORY_SCHEMA: &str = "kernaid.dev/rescue-uuid-inventory/v1";
const MAX_UUID_INVENTORY_ENTRIES: usize = 4_096;
const MAX_UUID_BYTES: usize = 128;
const MAX_UUID_INVENTORY_BYTES: usize = 536_635;
const EXT_SUPER_MAGIC: u64 = 0xef53;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const MAX_REQUEST_FRAME_BYTES: usize = 1_024;
const MAX_RESPONSE_FRAME_BYTES: usize = 2_048;
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
    DescriptorNotNonblocking,
    DescriptorNotBlockDevice,
    InvalidUuidInventoryDescriptor,
    InvalidUuidInventory,
    InvalidDetachedMount,
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
            Self::DescriptorNotNonblocking => "target capability descriptor is not nonblocking",
            Self::DescriptorNotBlockDevice => "target capability descriptor is not a block device",
            Self::InvalidUuidInventoryDescriptor => {
                "invalid target capability UUID inventory descriptor"
            }
            Self::InvalidUuidInventory => "invalid target capability UUID inventory",
            Self::InvalidDetachedMount => "invalid target capability detached mount",
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
    physical_parent: OwnedFd,
    uuid_inventory_descriptor: OwnedFd,
    detached_mount: OwnedFd,
    uuid_inventory: UuidInventory,
    physical_parent_claims: PhysicalParentNumericClaims,
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

    pub(crate) fn physical_parent_descriptor(&self) -> BorrowedFd<'_> {
        self.physical_parent.as_fd()
    }

    pub(crate) fn detached_mount_descriptor(&self) -> BorrowedFd<'_> {
        self.detached_mount.as_fd()
    }

    pub(crate) fn observed_uuids(&self) -> &BTreeSet<String> {
        &self.uuid_inventory.uuids
    }

    pub(crate) const fn physical_parent_claims(&self) -> PhysicalParentNumericClaims {
        self.physical_parent_claims
    }

    pub(crate) fn revalidate_bundle(&self) -> Result<(), TargetCapabilityClientError> {
        let leaf = validate_block_descriptor(self.block.as_fd())?;
        validate_parent_identity_descriptor(
            self.physical_parent.as_fd(),
            self.physical_parent_claims,
        )?;
        validate_uuid_inventory_descriptor(
            self.uuid_inventory_descriptor.as_fd(),
            &self.uuid_inventory.metadata,
            Some(&self.uuid_inventory.uuids),
        )?;
        validate_detached_mount(self.detached_mount.as_fd(), leaf.rdev)
    }
}

impl fmt::Debug for RescueTargetReadOnlyCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetReadOnlyCapability")
            .field("block", &"[owned read-only leaf capability]")
            .field(
                "physical_parent",
                &"[owned parent identity path capability]",
            )
            .field("uuid_inventory", &"[owned sealed inventory capability]")
            .field("detached_mount", &"[owned detached read-only ext4 mount]")
            .field("claims", &self.claims)
            .finish()
    }
}

struct UuidInventory {
    metadata: UuidInventoryMetadataWire,
    uuids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalParentNumericClaims {
    pub(crate) parent_major: u32,
    pub(crate) parent_minor: u32,
    pub(crate) disk_sequence: u64,
    pub(crate) media_sector_count: u64,
    pub(crate) logical_sector_bytes: u64,
    pub(crate) leaf_sector_count: u64,
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
    index: u8,
    #[serde(rename = "type")]
    descriptor_type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UuidInventoryMetadataWire {
    schema: String,
    entry_count: usize,
    byte_length: usize,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UuidInventoryPayloadWire {
    schema: String,
    uuids: Vec<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhysicalParentClaimsWire {
    parent_major: u32,
    parent_minor: u32,
    disk_sequence: u64,
    media_sector_count: u64,
    logical_sector_bytes: u64,
    leaf_sector_count: u64,
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
    descriptors: Vec<DescriptorWire>,
    physical_parent_claims: PhysicalParentClaimsWire,
    uuid_inventory: UuidInventoryMetadataWire,
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
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_FRAME_BYTES {
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
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_FRAME_BYTES {
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
    if frame.is_empty() || frame.len() > MAX_REQUEST_FRAME_BYTES {
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
    let mut bytes = vec![0_u8; MAX_RESPONSE_FRAME_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    // Capacity is deliberately n+1 for the four-FD success contract. A fifth
    // right is materialized and rejected; still larger or mixed ancillary
    // records cause MSG_CTRUNC or the explicit unexpected-record rejection.
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5), ScmCredentials(1))];
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
    let mut rights_records = 0_u8;
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
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(TargetCapabilityClientError::AncillaryTruncated);
    }
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > MAX_RESPONSE_FRAME_BYTES {
        return Err(TargetCapabilityClientError::FrameTooLarge);
    }
    if message.bytes == 0 {
        return Err(TargetCapabilityClientError::InvalidFrame);
    }
    if unexpected || rights_records > 1 {
        return Err(TargetCapabilityClientError::UnexpectedAncillary);
    }
    if descriptors.len() > DESCRIPTOR_TYPES.len() {
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
            let manifest_matches = response.descriptors.len() == DESCRIPTOR_TYPES.len()
                && response
                    .descriptors
                    .iter()
                    .zip(DESCRIPTOR_TYPES)
                    .enumerate()
                    .all(|(index, (descriptor, expected_type))| {
                        descriptor.index == u8::try_from(index).unwrap_or(u8::MAX)
                            && descriptor.descriptor_type == expected_type
                    });
            if !claims_match
                || response.capability != CAPABILITY_TYPE
                || !manifest_matches
                || response.uuid_inventory.schema != UUID_INVENTORY_SCHEMA
            {
                return Err(TargetCapabilityClientError::ClaimsMismatch);
            }
            let physical_parent_claims =
                validate_physical_parent_claims(&response.physical_parent_claims)?;
            if received.descriptors.is_empty() {
                return Err(TargetCapabilityClientError::DescriptorRequired);
            }
            let [
                block,
                physical_parent,
                uuid_inventory_descriptor,
                detached_mount,
            ]: [OwnedFd; 4] = received
                .descriptors
                .try_into()
                .map_err(|_| TargetCapabilityClientError::DescriptorCountMismatch)?;
            let leaf = validate_block_descriptor(block.as_fd())?;
            validate_parent_identity_descriptor(physical_parent.as_fd(), physical_parent_claims)?;
            let uuids = validate_uuid_inventory_descriptor(
                uuid_inventory_descriptor.as_fd(),
                &response.uuid_inventory,
                None,
            )?;
            validate_detached_mount(detached_mount.as_fd(), leaf.rdev)?;
            Ok(RescueTargetReadOnlyCapability {
                block,
                physical_parent,
                uuid_inventory_descriptor,
                detached_mount,
                uuid_inventory: UuidInventory {
                    metadata: response.uuid_inventory,
                    uuids,
                },
                physical_parent_claims,
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

fn validate_physical_parent_claims(
    claims: &PhysicalParentClaimsWire,
) -> Result<PhysicalParentNumericClaims, TargetCapabilityClientError> {
    if claims.disk_sequence == 0
        || claims.media_sector_count == 0
        || claims.leaf_sector_count == 0
        || claims.leaf_sector_count > claims.media_sector_count
        || !(512..=65_536).contains(&claims.logical_sector_bytes)
        || !claims.logical_sector_bytes.is_power_of_two()
        || claims.media_sector_count.checked_mul(512).is_none()
        || claims.leaf_sector_count.checked_mul(512).is_none()
    {
        return Err(TargetCapabilityClientError::ClaimsMismatch);
    }
    Ok(PhysicalParentNumericClaims {
        parent_major: claims.parent_major,
        parent_minor: claims.parent_minor,
        disk_sequence: claims.disk_sequence,
        media_sector_count: claims.media_sector_count,
        logical_sector_bytes: claims.logical_sector_bytes,
        leaf_sector_count: claims.leaf_sector_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockDescriptorSnapshot {
    rdev: u64,
}

fn validate_block_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<BlockDescriptorSnapshot, TargetCapabilityClientError> {
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
    if !status.contains(OFlags::NONBLOCK) {
        return Err(TargetCapabilityClientError::DescriptorNotNonblocking);
    }
    let stat = rfs::fstat(descriptor).map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device() {
        return Err(TargetCapabilityClientError::DescriptorNotBlockDevice);
    }
    Ok(BlockDescriptorSnapshot { rdev: stat.st_rdev })
}

fn validate_parent_identity_descriptor(
    descriptor: BorrowedFd<'_>,
    claims: PhysicalParentNumericClaims,
) -> Result<(), TargetCapabilityClientError> {
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    let stat = rfs::fstat(descriptor).map_err(|_| TargetCapabilityClientError::InvalidTransport)?;
    if descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || !status.contains(OFlags::PATH)
        || !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || rfs::major(stat.st_rdev) != claims.parent_major
        || rfs::minor(stat.st_rdev) != claims.parent_minor
    {
        return Err(TargetCapabilityClientError::ClaimsMismatch);
    }
    Ok(())
}

fn validate_uuid_inventory_descriptor(
    descriptor: BorrowedFd<'_>,
    metadata: &UuidInventoryMetadataWire,
    expected: Option<&BTreeSet<String>>,
) -> Result<BTreeSet<String>, TargetCapabilityClientError> {
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    let stat = rfs::fstat(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    let filesystem = rfs::fstatfs(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    let required_seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
    let seals = rfs::fcntl_get_seals(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    if descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || status & OFlags::ACCMODE != OFlags::RDWR
        || !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_nlink != 0
        || filesystem.f_type as u64 != TMPFS_MAGIC
        || seals != required_seals
        || rfs::seek(descriptor, SeekFrom::Current(0)).ok() != Some(0)
        || metadata.schema != UUID_INVENTORY_SCHEMA
        || !(1..=MAX_UUID_INVENTORY_ENTRIES).contains(&metadata.entry_count)
        || !(1..=MAX_UUID_INVENTORY_BYTES).contains(&metadata.byte_length)
        || usize::try_from(stat.st_size).ok() != Some(metadata.byte_length)
        || !valid_raw_sha256(&metadata.sha256)
    {
        return Err(TargetCapabilityClientError::InvalidUuidInventoryDescriptor);
    }

    let mut bytes = vec![0_u8; metadata.byte_length + 1];
    let read = rustix::io::pread(descriptor, bytes.as_mut_slice(), 0)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventoryDescriptor)?;
    bytes.truncate(read);
    if bytes.len() != metadata.byte_length
        || format!("{:x}", Sha256::digest(&bytes)) != metadata.sha256
    {
        return Err(TargetCapabilityClientError::InvalidUuidInventory);
    }
    validate_uuid_inventory_payload(&bytes, metadata, expected)
}

fn validate_uuid_inventory_payload(
    bytes: &[u8],
    metadata: &UuidInventoryMetadataWire,
    expected: Option<&BTreeSet<String>>,
) -> Result<BTreeSet<String>, TargetCapabilityClientError> {
    let payload: UuidInventoryPayloadWire = serde_json::from_slice(bytes)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventory)?;
    let canonical = serde_json::to_vec(&payload)
        .map_err(|_| TargetCapabilityClientError::InvalidUuidInventory)?;
    if payload.schema != UUID_INVENTORY_SCHEMA
        || canonical != bytes
        || payload.uuids.len() != metadata.entry_count
        || payload.uuids.len() > MAX_UUID_INVENTORY_ENTRIES
        || !payload.uuids.iter().all(|uuid| valid_uuid(uuid))
        || !payload
            .uuids
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(TargetCapabilityClientError::InvalidUuidInventory);
    }
    let uuids = payload.uuids.into_iter().collect::<BTreeSet<_>>();
    if uuids.len() != metadata.entry_count || expected.is_some_and(|expected| expected != &uuids) {
        return Err(TargetCapabilityClientError::InvalidUuidInventory);
    }
    Ok(uuids)
}

fn validate_detached_mount(
    descriptor: BorrowedFd<'_>,
    expected_device: u64,
) -> Result<(), TargetCapabilityClientError> {
    let stat =
        rfs::fstat(descriptor).map_err(|_| TargetCapabilityClientError::InvalidDetachedMount)?;
    let filesystem =
        rfs::fstatfs(descriptor).map_err(|_| TargetCapabilityClientError::InvalidDetachedMount)?;
    let filesystem_flags =
        rfs::fstatvfs(descriptor).map_err(|_| TargetCapabilityClientError::InvalidDetachedMount)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidDetachedMount)?;
    let status = rfs::fcntl_getfl(descriptor)
        .map_err(|_| TargetCapabilityClientError::InvalidDetachedMount)?;
    let required = StatVfsMountFlags::RDONLY
        | StatVfsMountFlags::NODEV
        | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NOEXEC;
    if descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || !status.contains(OFlags::PATH)
        || !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_dev != expected_device
        || filesystem.f_type as u64 != EXT_SUPER_MAGIC
        || !filesystem_flags.f_flag.contains(required)
    {
        return Err(TargetCapabilityClientError::InvalidDetachedMount);
    }
    Ok(())
}

fn valid_uuid(value: &str) -> bool {
    (1..=MAX_UUID_BYTES).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) || byte == b'-')
}

fn valid_raw_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
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
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"operation\":\"{operation}\",\"outcome\":\"ok\",\"scanFingerprint\":\"{scan_fingerprint}\",\"targetFingerprint\":\"{target_fingerprint}\",\"targetId\":\"{target_id}\",\"recoveryFingerprint\":\"{recovery_fingerprint}\",\"capability\":\"{CAPABILITY_TYPE}\",\"descriptors\":[{{\"index\":0,\"type\":\"{}\"}},{{\"index\":1,\"type\":\"{}\"}},{{\"index\":2,\"type\":\"{}\"}},{{\"index\":3,\"type\":\"{}\"}}],\"physicalParentClaims\":{{\"parentMajor\":8,\"parentMinor\":0,\"diskSequence\":77,\"mediaSectorCount\":4096,\"logicalSectorBytes\":512,\"leafSectorCount\":2048}},\"uuidInventory\":{{\"schema\":\"{UUID_INVENTORY_SCHEMA}\",\"entryCount\":1,\"byteLength\":70,\"sha256\":\"{}\"}}}}",
            DESCRIPTOR_TYPES[0],
            DESCRIPTOR_TYPES[1],
            DESCRIPTOR_TYPES[2],
            DESCRIPTOR_TYPES[3],
            "0".repeat(64),
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
    fn response_codec_denies_unknown_fields_and_requires_complete_bundle() {
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
    fn socketpair_rejects_credentials_and_five_rights() {
        let (sender, receiver) = pair();
        rustix::net::sockopt::set_socket_passcred(&receiver, true)
            .expect("enable credentials for rejection test");
        send_raw(sender.as_fd(), b"{}", &[]);
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::UnexpectedAncillary)
        );

        let (sender, receiver) = pair();
        let descriptor =
            open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).expect("descriptor");
        let descriptors = [descriptor.as_fd(); 5];
        send_raw(sender.as_fd(), b"{}", &descriptors);
        assert_eq!(
            receive_frame(receiver.as_fd(), deadline()).err(),
            Some(TargetCapabilityClientError::DescriptorCountMismatch)
        );
    }

    #[test]
    fn socketpair_sets_cloexec_on_all_four_received_rights() {
        let (sender, receiver) = pair();
        let descriptor =
            open("/dev/null", OFlags::RDONLY, Mode::empty()).expect("inheritable descriptor");
        assert_eq!(
            rustix::io::fcntl_getfd(&descriptor).expect("sender flags"),
            rustix::io::FdFlags::empty()
        );
        let descriptors = [descriptor.as_fd(); 4];
        send_raw(sender.as_fd(), b"{}", &descriptors);
        let received = receive_frame(receiver.as_fd(), deadline()).expect("receive four rights");
        assert_eq!(received.descriptors.len(), 4);
        assert!(received.descriptors.iter().all(|descriptor| {
            rustix::io::fcntl_getfd(descriptor).ok() == Some(rustix::io::FdFlags::CLOEXEC)
        }));
    }

    #[test]
    fn socketpair_rejects_truncated_frame_and_fd_on_error() {
        let (sender, receiver) = pair();
        send_raw(
            sender.as_fd(),
            &vec![b'x'; MAX_RESPONSE_FRAME_BYTES + 1],
            &[],
        );
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
        let read_only = open(
            "/dev/null",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("read-only character descriptor");
        assert_eq!(
            validate_block_descriptor(read_only.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotBlockDevice)
        );

        let writable = open(
            "/dev/null",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("writable descriptor");
        assert_eq!(
            validate_block_descriptor(writable.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotReadOnly)
        );

        let inheritable = open(
            "/dev/null",
            OFlags::RDONLY | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("inheritable descriptor");
        assert_eq!(
            validate_block_descriptor(inheritable.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotCloseOnExec)
        );

        let blocking = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("blocking descriptor");
        assert_eq!(
            validate_block_descriptor(blocking.as_fd()),
            Err(TargetCapabilityClientError::DescriptorNotNonblocking)
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

    #[test]
    fn uuid_inventory_payload_requires_canonical_sorted_lowercase_unique_json() {
        let bytes = br#"{"schema":"kernaid.dev/rescue-uuid-inventory/v1","uuids":["aaaa-bbbb","dead-beef"]}"#;
        let metadata = UuidInventoryMetadataWire {
            schema: UUID_INVENTORY_SCHEMA.to_owned(),
            entry_count: 2,
            byte_length: bytes.len(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        assert_eq!(
            validate_uuid_inventory_payload(bytes, &metadata, None).expect("canonical inventory"),
            BTreeSet::from(["aaaa-bbbb".to_owned(), "dead-beef".to_owned()])
        );

        for rejected in [
            br#"{"schema":"kernaid.dev/rescue-uuid-inventory/v1", "uuids":["aaaa-bbbb","dead-beef"]}"#.as_slice(),
            br#"{"schema":"kernaid.dev/rescue-uuid-inventory/v1","uuids":["dead-beef","aaaa-bbbb"]}"#.as_slice(),
            br#"{"schema":"kernaid.dev/rescue-uuid-inventory/v1","uuids":["AAAA-BBBB","dead-beef"]}"#.as_slice(),
            br#"{"schema":"kernaid.dev/rescue-uuid-inventory/v1","uuids":["aaaa-bbbb","aaaa-bbbb"]}"#.as_slice(),
        ] {
            let rejected_metadata = UuidInventoryMetadataWire {
                schema: UUID_INVENTORY_SCHEMA.to_owned(),
                entry_count: 2,
                byte_length: rejected.len(),
                sha256: format!("{:x}", Sha256::digest(rejected)),
            };
            assert_eq!(
                validate_uuid_inventory_payload(rejected, &rejected_metadata, None),
                Err(TargetCapabilityClientError::InvalidUuidInventory)
            );
        }
    }

    #[test]
    fn physical_parent_claims_are_bounded_before_descriptor_admission() {
        let valid = PhysicalParentClaimsWire {
            parent_major: 8,
            parent_minor: 0,
            disk_sequence: 77,
            media_sector_count: 4096,
            logical_sector_bytes: 512,
            leaf_sector_count: 2048,
        };
        assert_eq!(
            validate_physical_parent_claims(&valid).expect("bounded claims"),
            PhysicalParentNumericClaims {
                parent_major: 8,
                parent_minor: 0,
                disk_sequence: 77,
                media_sector_count: 4096,
                logical_sector_bytes: 512,
                leaf_sector_count: 2048,
            }
        );
        for invalid in [
            PhysicalParentClaimsWire {
                disk_sequence: 0,
                ..valid
            },
            PhysicalParentClaimsWire {
                leaf_sector_count: 4097,
                ..valid
            },
            PhysicalParentClaimsWire {
                logical_sector_bytes: 1000,
                ..valid
            },
        ] {
            assert_eq!(
                validate_physical_parent_claims(&invalid),
                Err(TargetCapabilityClientError::ClaimsMismatch)
            );
        }
    }
}
