//! Rescue-only adapter between typed Fleet repair work orders and repaird.
//!
//! Fleet can create an intent but cannot create local write authority. The
//! adapter accepts only four compile-time repair actions, obtains path-free
//! local evidence from repaird, and requires a fresh action-specific Desk
//! approval bound to every relevant digest before the Resident engine can
//! persist an execution.

use super::{
    BoundLocalApproval, LocalExecutionResult, LocalHandoffErrorCode, LocalWorkOrderHandoff,
    PreparedLocalExecution, ResidentWorkOrderError, canonical_json, import_canonical,
    read_private_optional, timestamp_unix, validate_json, write_atomic,
};
#[cfg(feature = "rescue-repair-handoff")]
use kernaid_core::RESCUE_CRYPTTAB_TYPED_CONFIRMATION;
use kernaid_core::RESCUE_FSTAB_TYPED_CONFIRMATION;
use kernaid_fleet_client::{
    LeasedWorkOrder, WorkOrderActionId, WorkOrderKind, WorkOrderResultOutcome, WorkOrderRisk,
};
#[cfg(feature = "rescue-repair-handoff")]
use kernaid_linux_pack::crypttab_candidate_contract::RESOURCE_ID as CRYPTTAB_RESOURCE_ID;
use kernaid_linux_pack::production_candidate_contract::RESOURCE_ID as FSTAB_RESOURCE_ID;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, io,
    path::{Path, PathBuf},
};
#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
use std::{
    io::IoSliceMut,
    mem::MaybeUninit,
    time::{Duration, Instant},
};

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, FileType, OFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketAddrUnix,
        SocketFlags, SocketType, connect, recvmsg, send, socket_with,
    },
};

pub const DESK_API_VERSION: &str = "kernaid.dev/fleet-rescue-repair/v1alpha1";
pub const INTENT_SCHEMA: &str = "dev.kernaid.fleet.rescue-repair-intent.v1";
pub const STATE_SCHEMA: &str = "dev.kernaid.fleet.rescue-repair-adapter-state.v1";
pub const TERMINAL_RECEIPT_SCHEMA: &str = "dev.kernaid.fleet.rescue-repair-terminal-receipt.v1";
pub const REPAIR_SERVICE_API_VERSION: &str = "kernaid.dev/rescue-repair-service/v1alpha1";

const STATE_FILE: &str = "fleet-rescue-repair.cjson";
const STATE_TEMP_FILE: &str = ".fleet-rescue-repair.pending";
const MAX_STATE_BYTES: usize = 32 * 1024;
const MAX_BROKER_FRAME_BYTES: usize = 4 * 1024;
const MAX_LOCAL_APPROVAL_AGE_SECONDS: u64 = 120;
const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:rescue-repair-evidence:v1\0";
const APPROVAL_PROOF_DOMAIN: &[u8] = b"kernaid:fleet:rescue-local-approval:v1\0";
const TERMINAL_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:rescue-terminal-receipt:v1\0";

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
const REPAIR_SOCKET_PATH: &str = "/run/kernaid-rescue-repair.sock";
#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
const REPAIR_BROKER_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(feature = "rescue-repair-handoff")]
const EXT4_RESOURCE_ID: &str = "rescue:selected-linux-filesystem:ext4";
#[cfg(feature = "rescue-repair-handoff")]
const RESOLVER_LINK_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/resolver-link";
#[cfg(feature = "rescue-repair-handoff")]
const EXT4_TYPED_CONFIRMATION: &str = "REPAIR EXT4 OFFLINE";
#[cfg(feature = "rescue-repair-handoff")]
const RESOLVER_LINK_TYPED_CONFIRMATION: &str = "RESTORE RESOLVER LINK";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepairActionContract {
    action_id: WorkOrderActionId,
    resource_id: &'static str,
    prepared_kind: &'static str,
    risk: WorkOrderRisk,
    risk_id: &'static str,
    typed_confirmation: &'static str,
    prepare_operation: &'static str,
    approve_operation: &'static str,
    cancel_operation: &'static str,
}

fn repair_action_contract(action_id: WorkOrderActionId) -> Option<RepairActionContract> {
    match action_id {
        WorkOrderActionId::LinuxFstabDisableMissingUuidV1 => Some(RepairActionContract {
            action_id,
            resource_id: FSTAB_RESOURCE_ID,
            prepared_kind: "fstab-prepared",
            risk: WorkOrderRisk::R2,
            risk_id: "R2",
            typed_confirmation: RESCUE_FSTAB_TYPED_CONFIRMATION,
            prepare_operation: "repair.fstab.prepare",
            approve_operation: "repair.fstab.approve",
            cancel_operation: "repair.fstab.cancel",
        }),
        #[cfg(feature = "rescue-repair-handoff")]
        WorkOrderActionId::LinuxCrypttabDisableMissingUuidV1 => Some(RepairActionContract {
            action_id,
            resource_id: CRYPTTAB_RESOURCE_ID,
            prepared_kind: "crypttab-prepared",
            risk: WorkOrderRisk::R2,
            risk_id: "R2",
            typed_confirmation: RESCUE_CRYPTTAB_TYPED_CONFIRMATION,
            prepare_operation: "repair.crypttab.prepare",
            approve_operation: "repair.crypttab.approve",
            cancel_operation: "repair.crypttab.cancel",
        }),
        #[cfg(feature = "rescue-repair-handoff")]
        WorkOrderActionId::LinuxExt4FsckPreenWithUndoV1 => Some(RepairActionContract {
            action_id,
            resource_id: EXT4_RESOURCE_ID,
            prepared_kind: "ext4-fsck-prepared",
            risk: WorkOrderRisk::R3,
            risk_id: "R3",
            typed_confirmation: EXT4_TYPED_CONFIRMATION,
            prepare_operation: "repair.ext4.prepare",
            approve_operation: "repair.ext4.approve",
            cancel_operation: "repair.ext4.cancel",
        }),
        #[cfg(feature = "rescue-repair-handoff")]
        WorkOrderActionId::LinuxNetworkRestoreResolverLinkV1 => Some(RepairActionContract {
            action_id,
            resource_id: RESOLVER_LINK_RESOURCE_ID,
            prepared_kind: "resolver-link-prepared",
            risk: WorkOrderRisk::R2,
            risk_id: "R2",
            typed_confirmation: RESOLVER_LINK_TYPED_CONFIRMATION,
            prepare_operation: "repair.resolver-link.prepare",
            approve_operation: "repair.resolver-link.approve",
            cancel_operation: "repair.resolver-link.cancel",
        }),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescueAdapterError {
    InvalidRequest,
    UnsupportedAction,
    BindingMismatch,
    ApprovalExpired,
    Busy,
    BrokerUnavailable,
    BrokerProtocol,
    StateCorrupt,
    Io,
}

impl fmt::Display for RescueAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "rescue-fleet-request-invalid",
            Self::UnsupportedAction => "rescue-fleet-action-unsupported",
            Self::BindingMismatch => "rescue-fleet-binding-mismatch",
            Self::ApprovalExpired => "rescue-fleet-approval-expired",
            Self::Busy => "rescue-fleet-busy",
            Self::BrokerUnavailable => "rescue-fleet-broker-unavailable",
            Self::BrokerProtocol => "rescue-fleet-broker-protocol",
            Self::StateCorrupt => "rescue-fleet-state-corrupt",
            Self::Io => "rescue-fleet-state-io",
        })
    }
}

impl std::error::Error for RescueAdapterError {}

impl From<io::Error> for RescueAdapterError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

impl From<ResidentWorkOrderError> for RescueAdapterError {
    fn from(value: ResidentWorkOrderError) -> Self {
        match value {
            ResidentWorkOrderError::Io(_) => Self::Io,
            _ => Self::StateCorrupt,
        }
    }
}

/// Fixed repaird exchange. Implementations must connect only to the existing
/// authenticated local repaird endpoint; the adapter never accepts a socket,
/// path, command, or operation name from Fleet or Desk.
pub trait RescueRepairBroker {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, RescueAdapterError>;
}

/// Production Linux broker for the fixed, systemd-owned Rescue repair API.
///
/// `repaird` authenticates this process through `SO_PEERCRED`; this side also
/// authenticates PID 1 as the owner of the socket-activated connection. No
/// caller-controlled endpoint, framing mode or timeout crosses this boundary.
#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRescueRepairBroker;

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
impl RescueRepairBroker for SystemRescueRepairBroker {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, RescueAdapterError> {
        if request.is_empty()
            || request.len() > MAX_BROKER_FRAME_BYTES
            || maximum_response_bytes == 0
            || maximum_response_bytes > MAX_BROKER_FRAME_BYTES
        {
            return Err(RescueAdapterError::BrokerProtocol);
        }
        let deadline = Instant::now()
            .checked_add(REPAIR_BROKER_TIMEOUT)
            .ok_or(RescueAdapterError::BrokerUnavailable)?;
        let socket = connect_repaird(deadline)?;
        send_repair_frame(socket.as_fd(), request, deadline)?;
        receive_repair_frame(socket.as_fd(), maximum_response_bytes, deadline)
    }
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn connect_repaird(deadline: Instant) -> Result<OwnedFd, RescueAdapterError> {
    let named = validate_named_repair_socket()?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let address = SocketAddrUnix::new(REPAIR_SOCKET_PATH)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_repair_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| RescueAdapterError::BrokerUnavailable)?
                .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
        }
        Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
    }
    authenticate_repaird(socket.as_fd())?;
    // Recheck the named endpoint after connect so a rename race cannot swap
    // the path between the ownership check and the authenticated peer check.
    let rechecked = validate_named_repair_socket()?;
    if named != rechecked {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    Ok(socket)
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn validate_named_repair_socket() -> Result<(u64, u64, u32), RescueAdapterError> {
    let named = rfs::statat(rfs::CWD, REPAIR_SOCKET_PATH, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let run = rfs::statat(rfs::CWD, "/run", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let client_gid = rustix::process::getgid().as_raw();
    if client_gid == 0
        || !FileType::from_raw_mode(named.st_mode).is_socket()
        || named.st_uid != 0
        || named.st_gid != client_gid
        || named.st_nlink != 1
        || named.st_mode & 0o7777 != 0o660
        || !FileType::from_raw_mode(run.st_mode).is_dir()
        || run.st_uid != 0
        || run.st_gid != 0
        || run.st_mode & 0o022 != 0
    {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    Ok((named.st_dev, named.st_ino, named.st_gid))
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn authenticate_repaird(socket: BorrowedFd<'_>) -> Result<(), RescueAdapterError> {
    let descriptor =
        rustix::io::fcntl_getfd(socket).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let status = rfs::fcntl_getfl(socket).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let peer: SocketAddrUnix = rustix::net::getpeername(socket)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        .ok_or(RescueAdapterError::BrokerUnavailable)?
        .try_into()
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let credentials = rustix::net::sockopt::socket_peercred(socket)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    if rustix::net::sockopt::socket_domain(socket)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || peer.path_bytes() != Some(REPAIR_SOCKET_PATH.as_bytes())
        || credentials.pid.as_raw_nonzero().get() != 1
        || credentials.uid.as_raw() != 0
        || credentials.gid.as_raw() != 0
        || rustix::net::sockopt::socket_passcred(socket)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
    {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn send_repair_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), RescueAdapterError> {
    loop {
        ensure_repair_deadline(deadline)?;
        match send(socket, frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) if sent == frame.len() => return Ok(()),
            Ok(_) => return Err(RescueAdapterError::BrokerProtocol),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_repair_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn receive_repair_frame(
    socket: BorrowedFd<'_>,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, RescueAdapterError> {
    let mut bytes = vec![0_u8; maximum + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    // Zero ancillary capacity deliberately converts every cmsg into CTRUNC;
    // the kernel closes any excess SCM_RIGHTS descriptors for us.
    let mut control_space: [MaybeUninit<u8>; 0] = [];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        ensure_repair_deadline(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_repair_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
        }
    };
    if message.bytes == 0
        || message.bytes > maximum
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    bytes.truncate(message.bytes);
    Ok(bytes)
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn ensure_repair_deadline(deadline: Instant) -> Result<(), RescueAdapterError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(RescueAdapterError::BrokerUnavailable)
}

#[cfg(all(target_os = "linux", feature = "rescue-repair-handoff"))]
fn wait_repair_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), RescueAdapterError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RescueAdapterError::BrokerUnavailable)?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(RescueAdapterError::BrokerUnavailable),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(RescueAdapterError::BrokerUnavailable);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescueTargetClaims {
    pub scan_fingerprint: String,
    pub target_fingerprint: String,
    pub target_id: String,
}

impl RescueTargetClaims {
    fn validate(&self) -> Result<(), RescueAdapterError> {
        if !prefixed_hash(&self.scan_fingerprint, "scan:")
            || !prefixed_hash(&self.target_fingerprint, "sha256:")
            || !prefixed_hash(&self.target_id, "target:")
        {
            return Err(RescueAdapterError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RescueIntentState {
    AwaitingTarget,
    Staging,
    AwaitingApproval,
    Approved,
    Executing,
    Canceling,
    Rejected,
    Succeeded,
    Failed,
    ManualReconciliationRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescuePreparedEvidence {
    pub prepared_id: String,
    pub session_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub target_sha256: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub diff_sha256: String,
    pub backup_locator: String,
    pub approval_sequence: u64,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredApproval {
    approval_id: String,
    approval_sequence: u64,
    approved_at: String,
    proof_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescueTerminalReceipt {
    pub schema: String,
    pub device_id: String,
    pub work_order_id: String,
    pub lease_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action_version: u16,
    pub evidence_sha256: String,
    pub outcome: String,
    pub reservation_id: Option<String>,
    pub transaction_binding_sha256: Option<String>,
    pub reboot_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntentRecord {
    work_order_id: String,
    lease_id: String,
    execution_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    risk: WorkOrderRisk,
    leased_at: String,
    lease_expires_at: String,
    state: RescueIntentState,
    broker_prepare_request_id: String,
    broker_approval_request_id: String,
    broker_cancel_request_id: String,
    target: Option<RescueTargetClaims>,
    evidence: Option<RescuePreparedEvidence>,
    local_approval: Option<StoredApproval>,
    terminal_receipt: Option<RescueTerminalReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdapterState {
    schema: String,
    tenant_id: String,
    device_id: String,
    intent: Option<IntentRecord>,
}

/// Bounded, privacy-minimized view rendered by Desk Rescue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescueDeskIntent {
    pub schema: String,
    pub device_id: String,
    pub work_order_id: String,
    pub lease_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action_version: u16,
    pub risk: String,
    pub state: RescueIntentState,
    pub lease_expires_at: String,
    pub evidence: Option<RescuePreparedEvidence>,
    pub confirmation_required: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageIntentRequest {
    pub api_version: String,
    pub operation: String,
    pub device_id: String,
    pub work_order_id: String,
    pub lease_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action_version: u16,
    pub target: RescueTargetClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveIntentRequest {
    pub api_version: String,
    pub operation: String,
    pub device_id: String,
    pub work_order_id: String,
    pub lease_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action_version: u16,
    pub plan_sha256: String,
    pub target_sha256: String,
    pub evidence_sha256: String,
    pub approval_id: String,
    pub approval_sequence: u64,
    pub approved_at: String,
    pub typed_confirmation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RejectIntentRequest {
    pub api_version: String,
    pub operation: String,
    pub device_id: String,
    pub work_order_id: String,
    pub lease_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action_version: u16,
    pub evidence_sha256: String,
}

#[derive(Deserialize)]
struct DeskOperationProbe {
    operation: String,
}

pub struct RescueFleetRepairAdapter<B> {
    directory: PathBuf,
    broker: B,
    state: AdapterState,
}

impl<B: RescueRepairBroker> RescueFleetRepairAdapter<B> {
    pub fn open(
        directory: &Path,
        tenant_id: &str,
        device_id: &str,
        broker: B,
    ) -> Result<Self, RescueAdapterError> {
        super::prepare_private_directory(directory)?;
        super::cleanup_temporary(&directory.join(STATE_TEMP_FILE))?;
        let state = match read_private_optional(&directory.join(STATE_FILE), MAX_STATE_BYTES)? {
            Some(bytes) => import_canonical(&bytes, MAX_STATE_BYTES)?,
            None => AdapterState {
                schema: STATE_SCHEMA.to_owned(),
                tenant_id: tenant_id.to_owned(),
                device_id: device_id.to_owned(),
                intent: None,
            },
        };
        validate_state(&state, tenant_id, device_id)?;
        let adapter = Self {
            directory: directory.to_path_buf(),
            broker,
            state,
        };
        if !directory.join(STATE_FILE).exists() {
            adapter.persist()?;
        }
        Ok(adapter)
    }

    #[must_use]
    pub fn desk_intent(&self) -> Option<RescueDeskIntent> {
        self.state.intent.as_ref().and_then(|intent| {
            let contract = repair_action_contract(intent.action_id)?;
            Some(RescueDeskIntent {
                schema: INTENT_SCHEMA.to_owned(),
                device_id: self.state.device_id.clone(),
                work_order_id: intent.work_order_id.clone(),
                lease_id: intent.lease_id.clone(),
                execution_id: intent.execution_id.clone(),
                action_id: intent.action_id.wire_name().to_owned(),
                action_version: intent.action_version,
                risk: contract.risk_id.to_owned(),
                state: intent.state,
                lease_expires_at: intent.lease_expires_at.clone(),
                evidence: intent.evidence.clone(),
                confirmation_required: matches!(intent.state, RescueIntentState::AwaitingApproval)
                    .then(|| contract.typed_confirmation.to_owned()),
            })
        })
    }

    pub fn export_desk_intent(&self) -> Result<Option<Vec<u8>>, RescueAdapterError> {
        self.desk_intent()
            .map(|intent| canonical_json(&intent).map_err(Into::into))
            .transpose()
    }

    /// Dispatches one bounded canonical Desk POST. The probe selects only one
    /// of the three closed schemas; each selected parser then rejects every
    /// unknown field and the returned intent is canonical JSON.
    pub fn handle_desk_post(
        &mut self,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, RescueAdapterError> {
        if bytes.is_empty() || bytes.len() > MAX_BROKER_FRAME_BYTES {
            return Err(RescueAdapterError::InvalidRequest);
        }
        let probe: DeskOperationProbe =
            serde_json::from_slice(bytes).map_err(|_| RescueAdapterError::InvalidRequest)?;
        let intent = match probe.operation.as_str() {
            "stage" => self.stage_from_json(bytes)?,
            "approve" => self.approve_from_json(bytes, now_unix)?,
            "reject" => self.reject_from_json(bytes)?,
            _ => return Err(RescueAdapterError::InvalidRequest),
        };
        canonical_json(&intent).map_err(Into::into)
    }

    pub fn stage_from_json(
        &mut self,
        bytes: &[u8],
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        let request: StageIntentRequest = import_canonical(bytes, MAX_BROKER_FRAME_BYTES)?;
        self.stage(&request)
    }

    pub fn approve_from_json(
        &mut self,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        let request: ApproveIntentRequest = import_canonical(bytes, MAX_BROKER_FRAME_BYTES)?;
        self.approve(&request, now_unix)
    }

    pub fn reject_from_json(
        &mut self,
        bytes: &[u8],
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        let request: RejectIntentRequest = import_canonical(bytes, MAX_BROKER_FRAME_BYTES)?;
        self.reject(&request)
    }

    pub fn stage(
        &mut self,
        request: &StageIntentRequest,
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        request.target.validate()?;
        let intent = self.intent_matching_request(
            &request.api_version,
            &request.operation,
            "stage",
            &request.device_id,
            &request.work_order_id,
            &request.lease_id,
            &request.execution_id,
            &request.action_id,
            request.action_version,
        )?;
        if !matches!(
            intent.state,
            RescueIntentState::AwaitingTarget | RescueIntentState::Staging
        ) {
            return Err(RescueAdapterError::Busy);
        }
        if let Some(target) = &intent.target {
            if target != &request.target {
                return Err(RescueAdapterError::BindingMismatch);
            }
        } else {
            intent.target = Some(request.target.clone());
        }
        intent.state = RescueIntentState::Staging;
        self.persist()?;
        let prepared = match self.prepare_or_recover() {
            Ok(prepared) => prepared,
            Err(RescueAdapterError::Busy) => {
                return self.desk_intent().ok_or(RescueAdapterError::StateCorrupt);
            }
            Err(error) => return Err(error),
        };
        let intent = self
            .state
            .intent
            .as_mut()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        intent.evidence = Some(prepared);
        intent.state = RescueIntentState::AwaitingApproval;
        self.persist()?;
        self.desk_intent().ok_or(RescueAdapterError::StateCorrupt)
    }

    pub fn approve(
        &mut self,
        request: &ApproveIntentRequest,
        now_unix: u64,
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        let device_id = self.state.device_id.clone();
        let intent = self.intent_matching_request(
            &request.api_version,
            &request.operation,
            "approve",
            &request.device_id,
            &request.work_order_id,
            &request.lease_id,
            &request.execution_id,
            &request.action_id,
            request.action_version,
        )?;
        if intent.state != RescueIntentState::AwaitingApproval {
            return Err(RescueAdapterError::Busy);
        }
        let evidence = intent
            .evidence
            .as_ref()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        let contract = repair_action_contract(intent.action_id)
            .ok_or(RescueAdapterError::UnsupportedAction)?;
        if request.plan_sha256 != evidence.plan_sha256
            || request.target_sha256 != evidence.target_sha256
            || request.evidence_sha256 != evidence.evidence_sha256
            || request.approval_sequence != evidence.approval_sequence
            || request.typed_confirmation != contract.typed_confirmation
            || !fixed_id(&request.approval_id, "A-")
        {
            return Err(RescueAdapterError::BindingMismatch);
        }
        let approved_at =
            timestamp_unix(&request.approved_at).map_err(|_| RescueAdapterError::InvalidRequest)?;
        let leased_at =
            timestamp_unix(&intent.leased_at).map_err(|_| RescueAdapterError::StateCorrupt)?;
        let lease_expires_at = timestamp_unix(&intent.lease_expires_at)
            .map_err(|_| RescueAdapterError::StateCorrupt)?;
        if now_unix == 0
            || approved_at > now_unix
            || approved_at < leased_at
            || approved_at >= lease_expires_at
            || now_unix >= lease_expires_at
            || now_unix.saturating_sub(approved_at) > MAX_LOCAL_APPROVAL_AGE_SECONDS
        {
            return Err(RescueAdapterError::ApprovalExpired);
        }
        let proof_sha256 = approval_proof(&device_id, request)?;
        intent.local_approval = Some(StoredApproval {
            approval_id: request.approval_id.clone(),
            approval_sequence: request.approval_sequence,
            approved_at: request.approved_at.clone(),
            proof_sha256,
        });
        intent.state = RescueIntentState::Approved;
        self.persist()?;
        self.desk_intent().ok_or(RescueAdapterError::StateCorrupt)
    }

    pub fn reject(
        &mut self,
        request: &RejectIntentRequest,
    ) -> Result<RescueDeskIntent, RescueAdapterError> {
        let intent = self.intent_matching_request(
            &request.api_version,
            &request.operation,
            "reject",
            &request.device_id,
            &request.work_order_id,
            &request.lease_id,
            &request.execution_id,
            &request.action_id,
            request.action_version,
        )?;
        let evidence = intent
            .evidence
            .as_ref()
            .ok_or(RescueAdapterError::BindingMismatch)?;
        if request.evidence_sha256 != evidence.evidence_sha256
            || intent.state != RescueIntentState::AwaitingApproval
        {
            return Err(RescueAdapterError::BindingMismatch);
        }
        intent.state = RescueIntentState::Canceling;
        self.persist()?;
        self.cancel_or_recover()?;
        let intent = self
            .state
            .intent
            .as_mut()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        intent.state = RescueIntentState::Rejected;
        self.persist()?;
        self.desk_intent().ok_or(RescueAdapterError::StateCorrupt)
    }

    #[allow(clippy::too_many_arguments)]
    fn intent_matching_request(
        &mut self,
        api_version: &str,
        operation: &str,
        expected_operation: &str,
        device_id: &str,
        work_order_id: &str,
        lease_id: &str,
        execution_id: &str,
        action_id: &str,
        action_version: u16,
    ) -> Result<&mut IntentRecord, RescueAdapterError> {
        if api_version != DESK_API_VERSION
            || operation != expected_operation
            || device_id != self.state.device_id
        {
            return Err(RescueAdapterError::InvalidRequest);
        }
        let requested_action = action_id
            .parse::<WorkOrderActionId>()
            .map_err(|_| RescueAdapterError::UnsupportedAction)?;
        let contract = repair_action_contract(requested_action)
            .ok_or(RescueAdapterError::UnsupportedAction)?;
        if action_version != contract.action_id.metadata().version {
            return Err(RescueAdapterError::InvalidRequest);
        }
        let intent = self
            .state
            .intent
            .as_mut()
            .ok_or(RescueAdapterError::BindingMismatch)?;
        if intent.work_order_id != work_order_id
            || intent.lease_id != lease_id
            || intent.execution_id != execution_id
            || intent.action_id != requested_action
            || intent.action_version != action_version
        {
            return Err(RescueAdapterError::BindingMismatch);
        }
        Ok(intent)
    }

    fn prepare_or_recover(&mut self) -> Result<RescuePreparedEvidence, RescueAdapterError> {
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        let contract = repair_action_contract(intent.action_id)
            .ok_or(RescueAdapterError::UnsupportedAction)?;
        let target = intent
            .target
            .as_ref()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        let status_request = BrokerStatusRequest {
            api_version: REPAIR_SERVICE_API_VERSION,
            request_id: &intent.broker_prepare_request_id,
            operation: "repair.status",
        };
        let response = self
            .broker
            .exchange(&canonical_json(&status_request)?, MAX_BROKER_FRAME_BYTES)?;
        let mut snapshot = parse_broker_response(
            &response,
            &intent.broker_prepare_request_id,
            "repair.status",
        )?;
        if snapshot.state == "idle" {
            let request = BrokerPrepareRequest {
                api_version: REPAIR_SERVICE_API_VERSION,
                request_id: &intent.broker_prepare_request_id,
                operation: contract.prepare_operation,
                target,
            };
            let response = self
                .broker
                .exchange(&canonical_json(&request)?, MAX_BROKER_FRAME_BYTES)?;
            snapshot = parse_broker_response(
                &response,
                &intent.broker_prepare_request_id,
                contract.prepare_operation,
            )?;
        }
        match snapshot.state.as_str() {
            "preparing" => Err(RescueAdapterError::Busy),
            "prepared" => prepared_evidence(&snapshot, target, contract),
            _ => Err(RescueAdapterError::BrokerProtocol),
        }
    }

    fn cancel_or_recover(&mut self) -> Result<(), RescueAdapterError> {
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        let contract = repair_action_contract(intent.action_id)
            .ok_or(RescueAdapterError::UnsupportedAction)?;
        let evidence = intent
            .evidence
            .as_ref()
            .ok_or(RescueAdapterError::StateCorrupt)?;
        let status_request = BrokerStatusRequest {
            api_version: REPAIR_SERVICE_API_VERSION,
            request_id: &intent.broker_cancel_request_id,
            operation: "repair.status",
        };
        let response = self
            .broker
            .exchange(&canonical_json(&status_request)?, MAX_BROKER_FRAME_BYTES)?;
        let mut snapshot =
            parse_broker_response(&response, &intent.broker_cancel_request_id, "repair.status")?;
        if snapshot.state == "prepared" {
            let plan_hash = format!("sha256:{}", evidence.plan_sha256);
            let request = BrokerCancelRequest {
                api_version: REPAIR_SERVICE_API_VERSION,
                request_id: &intent.broker_cancel_request_id,
                operation: contract.cancel_operation,
                prepared_id: &evidence.prepared_id,
                plan_hash: &plan_hash,
            };
            let response = self
                .broker
                .exchange(&canonical_json(&request)?, MAX_BROKER_FRAME_BYTES)?;
            snapshot = parse_broker_response(
                &response,
                &intent.broker_cancel_request_id,
                contract.cancel_operation,
            )?;
        }
        if snapshot.state != "cancelled" {
            return Err(RescueAdapterError::BrokerProtocol);
        }
        Ok(())
    }

    fn retire_expired_intent_before(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<(), RescueAdapterError> {
        let Some(intent) = self.state.intent.as_ref() else {
            return Ok(());
        };
        if intent_matches_order(intent, order, execution_id) {
            return Ok(());
        }
        let lease_expires_at = timestamp_unix(&intent.lease_expires_at)
            .map_err(|_| RescueAdapterError::StateCorrupt)?;
        let next_lease_started_at = timestamp_unix(order.lease().leased_at())
            .map_err(|_| RescueAdapterError::StateCorrupt)?;
        if lease_expires_at > next_lease_started_at {
            return Ok(());
        }

        match intent.state {
            RescueIntentState::AwaitingTarget
            | RescueIntentState::Rejected
            | RescueIntentState::Succeeded
            | RescueIntentState::Failed
            | RescueIntentState::ManualReconciliationRequired => {
                self.state.intent = None;
                self.persist()
            }
            RescueIntentState::Staging => {
                let evidence = self.prepare_or_recover()?;
                let intent = self
                    .state
                    .intent
                    .as_mut()
                    .ok_or(RescueAdapterError::StateCorrupt)?;
                intent.evidence = Some(evidence);
                intent.state = RescueIntentState::Canceling;
                self.persist()?;
                self.cancel_expired_intent()
            }
            RescueIntentState::AwaitingApproval
            | RescueIntentState::Approved
            | RescueIntentState::Canceling => {
                self.state
                    .intent
                    .as_mut()
                    .ok_or(RescueAdapterError::StateCorrupt)?
                    .state = RescueIntentState::Canceling;
                self.persist()?;
                self.cancel_expired_intent()
            }
            // An operation that repaird has already started must be recovered
            // by its original idempotent execution path, never silently
            // replaced by a second write intent.
            RescueIntentState::Executing => Err(RescueAdapterError::Busy),
        }
    }

    fn cancel_expired_intent(&mut self) -> Result<(), RescueAdapterError> {
        self.cancel_or_recover()?;
        self.state.intent = None;
        self.persist()
    }

    fn persist(&self) -> Result<(), RescueAdapterError> {
        validate_state(&self.state, &self.state.tenant_id, &self.state.device_id)?;
        let bytes = canonical_json(&self.state)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(RescueAdapterError::StateCorrupt);
        }
        write_atomic(&self.directory, STATE_FILE, STATE_TEMP_FILE, &bytes)?;
        Ok(())
    }
}

impl<B: RescueRepairBroker> LocalWorkOrderHandoff for RescueFleetRepairAdapter<B> {
    fn prepare(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode> {
        let contract = repair_action_contract(order.action_id())
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        if order.target_device_id() != self.state.device_id
            || order.action_version() != contract.action_id.metadata().version
            || order.kind() != WorkOrderKind::Repair
            || order.risk() != contract.risk
            || !order.local_approval_required()
            || order.approval().is_none()
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        self.retire_expired_intent_before(order, execution_id)
            .map_err(map_local_error)?;
        let replace_terminal = self.state.intent.as_ref().is_some_and(|intent| {
            matches!(
                intent.state,
                RescueIntentState::Rejected
                    | RescueIntentState::Succeeded
                    | RescueIntentState::Failed
                    | RescueIntentState::ManualReconciliationRequired
            ) && !intent_matches_order(intent, order, execution_id)
        });
        if replace_terminal {
            self.state.intent = None;
            self.persist().map_err(map_local_error)?;
        }
        if self.state.intent.is_none() {
            let seed = deterministic_ids(execution_id);
            self.state.intent = Some(IntentRecord {
                work_order_id: order.work_order_id().to_owned(),
                lease_id: order.lease().lease_id().to_owned(),
                execution_id: execution_id.to_owned(),
                action_id: order.action_id(),
                action_version: order.action_version(),
                risk: order.risk(),
                leased_at: order.lease().leased_at().to_owned(),
                lease_expires_at: order.lease().lease_expires_at().to_owned(),
                state: RescueIntentState::AwaitingTarget,
                broker_prepare_request_id: request_id(&seed[0..32]),
                broker_approval_request_id: request_id(&seed[32..64]),
                broker_cancel_request_id: request_id(&sha256_hex(seed.as_bytes())[..32]),
                target: None,
                evidence: None,
                local_approval: None,
                terminal_receipt: None,
            });
            self.persist().map_err(map_local_error)?;
            return Err(LocalHandoffErrorCode::ApprovalPending);
        }
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        if !intent_matches_order(intent, order, execution_id) {
            return Err(LocalHandoffErrorCode::Busy);
        }
        match intent.state {
            RescueIntentState::Rejected => Err(LocalHandoffErrorCode::ApprovalRejected),
            RescueIntentState::Approved => {
                let evidence = intent
                    .evidence
                    .as_ref()
                    .ok_or(LocalHandoffErrorCode::StateMismatch)?;
                let approval = intent
                    .local_approval
                    .as_ref()
                    .ok_or(LocalHandoffErrorCode::StateMismatch)?;
                Ok(PreparedLocalExecution::approved_write(
                    order,
                    execution_id,
                    &evidence.plan_sha256,
                    &evidence.target_sha256,
                    BoundLocalApproval::new(
                        order.work_order_id(),
                        order.lease().lease_id(),
                        order.action_id(),
                        order.action_version(),
                        execution_id,
                        &evidence.plan_sha256,
                        &evidence.target_sha256,
                        approval.approval_sequence,
                        &approval.approved_at,
                        &approval.proof_sha256,
                    ),
                ))
            }
            _ => Err(LocalHandoffErrorCode::ApprovalPending),
        }
    }

    fn execute_or_recover(
        &mut self,
        prepared: &PreparedLocalExecution,
    ) -> Result<LocalExecutionResult, LocalHandoffErrorCode> {
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        if !intent_matches_preparation(intent, prepared) {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        if let Some(receipt) = &intent.terminal_receipt {
            return terminal_local_result(receipt);
        }
        if intent.state == RescueIntentState::Approved {
            self.state
                .intent
                .as_mut()
                .ok_or(LocalHandoffErrorCode::StateMismatch)?
                .state = RescueIntentState::Executing;
            self.persist().map_err(map_local_error)?;
        } else if intent.state != RescueIntentState::Executing {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let intent = self
            .state
            .intent
            .as_ref()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        let contract =
            repair_action_contract(intent.action_id).ok_or(LocalHandoffErrorCode::StateMismatch)?;
        let evidence = intent
            .evidence
            .as_ref()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        let approval = intent
            .local_approval
            .as_ref()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        let status_request = BrokerStatusRequest {
            api_version: REPAIR_SERVICE_API_VERSION,
            request_id: &intent.broker_approval_request_id,
            operation: "repair.status",
        };
        let response = self
            .broker
            .exchange(
                &canonical_json(&status_request).map_err(|error| map_local_error(error.into()))?,
                MAX_BROKER_FRAME_BYTES,
            )
            .map_err(map_local_error)?;
        let mut snapshot = parse_broker_response(
            &response,
            &intent.broker_approval_request_id,
            "repair.status",
        )
        .map_err(map_local_error)?;
        if snapshot.state == "prepared" {
            let plan_hash = format!("sha256:{}", evidence.plan_sha256);
            let request = BrokerApproveRequest {
                api_version: REPAIR_SERVICE_API_VERSION,
                request_id: &intent.broker_approval_request_id,
                operation: contract.approve_operation,
                prepared_id: &evidence.prepared_id,
                session_id: &evidence.session_id,
                plan_id: &evidence.plan_id,
                plan_hash: &plan_hash,
                approval_id: &approval.approval_id,
                approval_sequence: approval.approval_sequence,
                typed_confirmation: contract.typed_confirmation,
            };
            let response = self
                .broker
                .exchange(
                    &canonical_json(&request).map_err(|error| map_local_error(error.into()))?,
                    MAX_BROKER_FRAME_BYTES,
                )
                .map_err(map_local_error)?;
            snapshot = parse_broker_response(
                &response,
                &intent.broker_approval_request_id,
                contract.approve_operation,
            )
            .map_err(map_local_error)?;
        }
        if matches!(snapshot.state.as_str(), "executing" | "prepared") {
            return Err(LocalHandoffErrorCode::Busy);
        }
        let receipt =
            terminal_receipt(&self.state.device_id, intent, &snapshot).map_err(map_local_error)?;
        let outcome = terminal_local_result(&receipt)?;
        let intent = self
            .state
            .intent
            .as_mut()
            .ok_or(LocalHandoffErrorCode::StateMismatch)?;
        intent.state = match outcome.outcome {
            WorkOrderResultOutcome::Succeeded => RescueIntentState::Succeeded,
            WorkOrderResultOutcome::Failed => RescueIntentState::Failed,
            WorkOrderResultOutcome::Rejected => RescueIntentState::ManualReconciliationRequired,
        };
        intent.terminal_receipt = Some(receipt);
        self.persist().map_err(map_local_error)?;
        Ok(outcome)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrokerPrepareRequest<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    target: &'a RescueTargetClaims,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrokerStatusRequest<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrokerApproveRequest<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    prepared_id: &'a str,
    session_id: &'a str,
    plan_id: &'a str,
    plan_hash: &'a str,
    approval_id: &'a str,
    approval_sequence: u64,
    typed_confirmation: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrokerCancelRequest<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'static str,
    prepared_id: &'a str,
    plan_hash: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerSnapshot {
    api_version: String,
    request_id: String,
    operation: String,
    outcome: String,
    state_version: u64,
    state: String,
    detail: Option<BrokerDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum BrokerDetail {
    Prepared(Box<BrokerPreparedDetail>),
    Terminal(BrokerTerminalDetail),
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerPreparedDetail {
    kind: String,
    prepared_id: String,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    before_sha256: String,
    after_sha256: String,
    diff_sha256: String,
    resource_id: String,
    backup_locator: String,
    action_id: String,
    risk: String,
    backup: BrokerBackup,
    next_approval_sequence: u64,
    confirmation_required: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerTerminalDetail {
    kind: String,
    terminal_outcome: String,
    reservation_id: Option<String>,
    transaction_binding_sha256: Option<String>,
    reboot_required: bool,
    prepare_failure_stage: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerBackup {
    state: String,
    vault_distinct: bool,
}

fn parse_broker_response(
    bytes: &[u8],
    expected_request_id: &str,
    expected_operation: &str,
) -> Result<BrokerSnapshot, RescueAdapterError> {
    if bytes.is_empty() || bytes.len() > MAX_BROKER_FRAME_BYTES {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| RescueAdapterError::BrokerProtocol)?;
    validate_json(&value).map_err(|_| RescueAdapterError::BrokerProtocol)?;
    let snapshot: BrokerSnapshot =
        serde_json::from_slice(bytes).map_err(|_| RescueAdapterError::BrokerProtocol)?;
    if snapshot.api_version != REPAIR_SERVICE_API_VERSION
        || snapshot.request_id != expected_request_id
        || snapshot.operation != expected_operation
        || snapshot.outcome != "ok"
        || snapshot.error.is_some()
        || snapshot.state_version == 0
    {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    Ok(snapshot)
}

fn prepared_evidence(
    snapshot: &BrokerSnapshot,
    target: &RescueTargetClaims,
    contract: RepairActionContract,
) -> Result<RescuePreparedEvidence, RescueAdapterError> {
    let Some(BrokerDetail::Prepared(detail)) = snapshot.detail.as_ref() else {
        return Err(RescueAdapterError::BrokerProtocol);
    };
    let prepared = RescuePreparedEvidence {
        prepared_id: detail.prepared_id.clone(),
        session_id: detail.session_id.clone(),
        plan_id: detail.plan_id.clone(),
        plan_sha256: bare_hash(&detail.plan_hash)?,
        target_sha256: bare_hash(&detail.target_fingerprint)?,
        before_sha256: detail.before_sha256.clone(),
        after_sha256: detail.after_sha256.clone(),
        diff_sha256: detail.diff_sha256.clone(),
        backup_locator: detail.backup_locator.clone(),
        approval_sequence: detail.next_approval_sequence,
        evidence_sha256: String::new(),
    };
    if detail.kind != contract.prepared_kind
        || detail.resource_id != contract.resource_id
        || detail.action_id != contract.action_id.wire_name()
        || detail.risk != contract.risk_id
        || detail.confirmation_required != contract.typed_confirmation
        || detail.backup.state != "reserved"
        || !detail.backup.vault_distinct
        || format!("sha256:{}", prepared.target_sha256) != target.target_fingerprint
        || !fixed_id(&prepared.prepared_id, "Q-")
        || !fixed_id(&prepared.session_id, "S-")
        || !fixed_id(&prepared.plan_id, "P-")
        || prepared.approval_sequence == 0
        || !prefixed_hash(&prepared.before_sha256, "sha256:")
        || !prefixed_hash(&prepared.after_sha256, "sha256:")
        || !prefixed_hash(&prepared.diff_sha256, "sha256:")
        || !valid_backup_locator(&prepared.backup_locator)
    {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    let mut prepared = prepared;
    prepared.evidence_sha256 = evidence_digest(&prepared)?;
    Ok(prepared)
}

fn terminal_receipt(
    device_id: &str,
    intent: &IntentRecord,
    snapshot: &BrokerSnapshot,
) -> Result<RescueTerminalReceipt, RescueAdapterError> {
    let Some(BrokerDetail::Terminal(detail)) = snapshot.detail.as_ref() else {
        return Err(RescueAdapterError::BrokerProtocol);
    };
    let evidence = intent
        .evidence
        .as_ref()
        .ok_or(RescueAdapterError::StateCorrupt)?;
    if detail.kind != "terminal"
        || !matches!(
            snapshot.state.as_str(),
            "succeeded" | "restored" | "failed" | "manual-reconciliation-required"
        )
    {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    let outcome = detail.terminal_outcome.clone();
    Ok(RescueTerminalReceipt {
        schema: TERMINAL_RECEIPT_SCHEMA.to_owned(),
        device_id: device_id.to_owned(),
        work_order_id: intent.work_order_id.clone(),
        lease_id: intent.lease_id.clone(),
        execution_id: intent.execution_id.clone(),
        action_id: intent.action_id.wire_name().to_owned(),
        action_version: intent.action_version,
        evidence_sha256: evidence.evidence_sha256.clone(),
        outcome,
        reservation_id: detail.reservation_id.clone(),
        transaction_binding_sha256: detail.transaction_binding_sha256.clone(),
        reboot_required: detail.reboot_required,
    })
}

fn terminal_local_result(
    receipt: &RescueTerminalReceipt,
) -> Result<LocalExecutionResult, LocalHandoffErrorCode> {
    let outcome = match receipt.outcome.as_str() {
        "committed" => WorkOrderResultOutcome::Succeeded,
        "closed-before-unchanged"
        | "closed-before-restored"
        | "rolled-back-original"
        | "failed" => WorkOrderResultOutcome::Failed,
        "manual-reconciliation-required" => WorkOrderResultOutcome::Rejected,
        _ => return Err(LocalHandoffErrorCode::StateMismatch),
    };
    let bytes = canonical_json(receipt).map_err(|error| map_local_error(error.into()))?;
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(LocalExecutionResult::new(
        outcome,
        hex_digest(hasher.finalize()),
    ))
}

fn validate_state(
    state: &AdapterState,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), RescueAdapterError> {
    if state.schema != STATE_SCHEMA
        || state.tenant_id != tenant_id
        || state.device_id != device_id
        || tenant_id.is_empty()
        || device_id.is_empty()
        || tenant_id.len() > 160
        || device_id.len() > 160
    {
        return Err(RescueAdapterError::StateCorrupt);
    }
    if let Some(intent) = &state.intent {
        let contract =
            repair_action_contract(intent.action_id).ok_or(RescueAdapterError::StateCorrupt)?;
        if intent.action_version != contract.action_id.metadata().version
            || intent.risk != contract.risk
            || intent.work_order_id.is_empty()
            || intent.lease_id.is_empty()
            || intent.execution_id.is_empty()
            || !request_id_valid(&intent.broker_prepare_request_id)
            || !request_id_valid(&intent.broker_approval_request_id)
            || !request_id_valid(&intent.broker_cancel_request_id)
            || timestamp_unix(&intent.leased_at).is_err()
            || timestamp_unix(&intent.lease_expires_at).is_err()
            || timestamp_unix(&intent.leased_at).ok()
                >= timestamp_unix(&intent.lease_expires_at).ok()
        {
            return Err(RescueAdapterError::StateCorrupt);
        }
        if let Some(target) = &intent.target {
            target
                .validate()
                .map_err(|_| RescueAdapterError::StateCorrupt)?;
        }
        if intent.state != RescueIntentState::AwaitingTarget && intent.target.is_none() {
            return Err(RescueAdapterError::StateCorrupt);
        }
        if matches!(
            intent.state,
            RescueIntentState::AwaitingApproval
                | RescueIntentState::Approved
                | RescueIntentState::Executing
                | RescueIntentState::Canceling
                | RescueIntentState::Rejected
                | RescueIntentState::Succeeded
                | RescueIntentState::Failed
                | RescueIntentState::ManualReconciliationRequired
        ) && intent.evidence.is_none()
        {
            return Err(RescueAdapterError::StateCorrupt);
        }
        if let Some(evidence) = &intent.evidence {
            if !fixed_id(&evidence.prepared_id, "Q-")
                || !fixed_id(&evidence.session_id, "S-")
                || !fixed_id(&evidence.plan_id, "P-")
                || !lower_hash(&evidence.plan_sha256)
                || !lower_hash(&evidence.target_sha256)
                || !prefixed_hash(&evidence.before_sha256, "sha256:")
                || !prefixed_hash(&evidence.after_sha256, "sha256:")
                || !prefixed_hash(&evidence.diff_sha256, "sha256:")
                || !valid_backup_locator(&evidence.backup_locator)
                || evidence.approval_sequence == 0
                || !lower_hash(&evidence.evidence_sha256)
                || evidence_digest(evidence)? != evidence.evidence_sha256
                || intent.target.as_ref().is_none_or(|target| {
                    target.target_fingerprint != format!("sha256:{}", evidence.target_sha256)
                })
            {
                return Err(RescueAdapterError::StateCorrupt);
            }
        }
        if let Some(approval) = &intent.local_approval {
            if !fixed_id(&approval.approval_id, "A-")
                || approval.approval_sequence == 0
                || !lower_hash(&approval.proof_sha256)
                || timestamp_unix(&approval.approved_at).is_err()
                || intent
                    .evidence
                    .as_ref()
                    .is_none_or(|evidence| evidence.approval_sequence != approval.approval_sequence)
            {
                return Err(RescueAdapterError::StateCorrupt);
            }
        }
        let terminal_state = matches!(
            intent.state,
            RescueIntentState::Succeeded
                | RescueIntentState::Failed
                | RescueIntentState::ManualReconciliationRequired
        );
        if terminal_state != intent.terminal_receipt.is_some() {
            return Err(RescueAdapterError::StateCorrupt);
        }
        if let Some(receipt) = &intent.terminal_receipt {
            if receipt.schema != TERMINAL_RECEIPT_SCHEMA
                || receipt.device_id != device_id
                || receipt.work_order_id != intent.work_order_id
                || receipt.lease_id != intent.lease_id
                || receipt.execution_id != intent.execution_id
                || receipt.action_id != intent.action_id.wire_name()
                || receipt.action_version != intent.action_version
                || !lower_hash(&receipt.evidence_sha256)
                || intent
                    .evidence
                    .as_ref()
                    .is_none_or(|evidence| receipt.evidence_sha256 != evidence.evidence_sha256)
                || !matches!(
                    receipt.outcome.as_str(),
                    "committed"
                        | "closed-before-unchanged"
                        | "closed-before-restored"
                        | "rolled-back-original"
                        | "failed"
                        | "manual-reconciliation-required"
                )
                || receipt
                    .reservation_id
                    .as_ref()
                    .is_some_and(|value| !fixed_id(value, "B-"))
                || receipt
                    .transaction_binding_sha256
                    .as_ref()
                    .is_some_and(|value| !prefixed_hash(value, "sha256:"))
            {
                return Err(RescueAdapterError::StateCorrupt);
            }
        }
        if matches!(
            intent.state,
            RescueIntentState::Approved
                | RescueIntentState::Executing
                | RescueIntentState::Succeeded
                | RescueIntentState::Failed
                | RescueIntentState::ManualReconciliationRequired
        ) && intent.local_approval.is_none()
        {
            return Err(RescueAdapterError::StateCorrupt);
        }
    }
    Ok(())
}

fn intent_matches_order(
    intent: &IntentRecord,
    order: &LeasedWorkOrder,
    execution_id: &str,
) -> bool {
    intent.work_order_id == order.work_order_id()
        && intent.lease_id == order.lease().lease_id()
        && intent.execution_id == execution_id
        && intent.action_id == order.action_id()
        && intent.action_version == order.action_version()
}
fn intent_matches_preparation(intent: &IntentRecord, prepared: &PreparedLocalExecution) -> bool {
    intent.execution_id == prepared.execution_id()
        && intent.action_id == prepared.action_id()
        && intent.action_version == prepared.action_version()
        && intent.evidence.as_ref().is_some_and(|e| {
            e.plan_sha256 == prepared.plan_sha256()
                && e.target_sha256 == prepared.target_sha256()
                && prepared.local_approval().is_some()
        })
}
fn map_local_error(error: RescueAdapterError) -> LocalHandoffErrorCode {
    match error {
        RescueAdapterError::Busy | RescueAdapterError::BrokerUnavailable => {
            LocalHandoffErrorCode::Busy
        }
        RescueAdapterError::BindingMismatch
        | RescueAdapterError::InvalidRequest
        | RescueAdapterError::UnsupportedAction
        | RescueAdapterError::ApprovalExpired
        | RescueAdapterError::BrokerProtocol
        | RescueAdapterError::StateCorrupt
        | RescueAdapterError::Io => LocalHandoffErrorCode::StateMismatch,
    }
}
fn deterministic_ids(execution_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"kernaid:fleet:rescue-broker-requests:v1\0");
    h.update(execution_id.as_bytes());
    let first = hex_digest(h.finalize());
    let mut h = Sha256::new();
    h.update(first.as_bytes());
    format!("{first}{}", hex_digest(h.finalize()))
}
fn request_id(hex: &str) -> String {
    format!(
        "R-{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
fn request_id_valid(value: &str) -> bool {
    value.len() == 38
        && value.starts_with("R-")
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 10 | 15 | 20 | 25) {
                b == b'-'
            } else if i < 2 {
                true
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
fn fixed_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|v| v.len() == 32 && lower_hex(v))
}
fn prefixed_hash(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|v| v.len() == 64 && lower_hex(v))
}
fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn lower_hash(value: &str) -> bool {
    value.len() == 64 && lower_hex(value)
}
fn valid_backup_locator(value: &str) -> bool {
    value
        .strip_prefix("vault://repair/")
        .is_some_and(|identifier| fixed_id(identifier, "B-"))
}
fn bare_hash(value: &str) -> Result<String, RescueAdapterError> {
    value
        .strip_prefix("sha256:")
        .filter(|v| v.len() == 64 && lower_hex(v))
        .map(str::to_owned)
        .ok_or(RescueAdapterError::BrokerProtocol)
}
fn evidence_digest(evidence: &RescuePreparedEvidence) -> Result<String, RescueAdapterError> {
    let mut clone = evidence.clone();
    clone.evidence_sha256.clear();
    let bytes = canonical_json(&clone)?;
    let mut h = Sha256::new();
    h.update(EVIDENCE_DIGEST_DOMAIN);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    Ok(hex_digest(h.finalize()))
}
fn approval_proof(
    device_id: &str,
    request: &ApproveIntentRequest,
) -> Result<String, RescueAdapterError> {
    let bytes = canonical_json(request)?;
    let mut h = Sha256::new();
    h.update(APPROVAL_PROOF_DOMAIN);
    h.update((device_id.len() as u64).to_be_bytes());
    h.update(device_id.as_bytes());
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    Ok(hex_digest(h.finalize()))
}
fn sha256_hex(value: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(value);
    hex_digest(h.finalize())
}
fn hex_digest(value: impl AsRef<[u8]>) -> String {
    let mut out = String::with_capacity(64);
    for byte in value.as_ref() {
        use fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    const DEVICE: &str = "KA-0123456789abcdef01234567";
    const EXECUTION: &str = "exec_0123456789abcdef0123456789abcdef";
    const APPROVED_AT: &str = "2026-08-31T12:30:45Z";
    const NOW_UNIX: u64 = 1_788_179_445;

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum BrokerState {
        Idle,
        Prepared,
        Terminal,
        Cancelled,
    }

    #[derive(Clone)]
    struct MockBroker {
        action_id: WorkOrderActionId,
        reported_action_id: WorkOrderActionId,
        state: Arc<Mutex<BrokerState>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockBroker {
        fn new(action_id: WorkOrderActionId) -> Self {
            Self {
                action_id,
                reported_action_id: action_id,
                state: Arc::new(Mutex::new(BrokerState::Idle)),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        #[cfg(feature = "rescue-repair-handoff")]
        fn reporting(mut self, action_id: WorkOrderActionId) -> Self {
            self.reported_action_id = action_id;
            self
        }

        fn request_count(&self) -> usize {
            self.requests.lock().expect("requests").len()
        }

        fn operations(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("requests")
                .iter()
                .map(|request| {
                    serde_json::from_slice::<Value>(request).expect("request JSON")["operation"]
                        .as_str()
                        .expect("operation")
                        .to_owned()
                })
                .collect()
        }
    }

    impl RescueRepairBroker for MockBroker {
        fn exchange(
            &mut self,
            request: &[u8],
            maximum_response_bytes: usize,
        ) -> Result<Vec<u8>, RescueAdapterError> {
            assert_eq!(maximum_response_bytes, MAX_BROKER_FRAME_BYTES);
            self.requests
                .lock()
                .expect("requests")
                .push(request.to_vec());
            let request: Value =
                serde_json::from_slice(request).map_err(|_| RescueAdapterError::BrokerProtocol)?;
            let operation = request["operation"]
                .as_str()
                .ok_or(RescueAdapterError::BrokerProtocol)?;
            let request_id = request["requestId"]
                .as_str()
                .ok_or(RescueAdapterError::BrokerProtocol)?;
            let contract =
                repair_action_contract(self.action_id).ok_or(RescueAdapterError::BrokerProtocol)?;
            let mut state = self.state.lock().expect("state");
            if operation == "repair.status" {
                // Status recovery is deliberately shared and path-free.
            } else if operation == contract.prepare_operation && *state == BrokerState::Idle {
                *state = BrokerState::Prepared;
            } else if operation == contract.approve_operation && *state == BrokerState::Prepared {
                *state = BrokerState::Terminal;
            } else if operation == contract.cancel_operation && *state == BrokerState::Prepared {
                *state = BrokerState::Cancelled;
            } else {
                return Err(RescueAdapterError::BrokerProtocol);
            }
            let (public_state, detail) = match *state {
                BrokerState::Idle => ("idle", Value::Null),
                BrokerState::Prepared => ("prepared", prepared_detail(self.reported_action_id)),
                BrokerState::Terminal => ("succeeded", terminal_detail("committed")),
                BrokerState::Cancelled => ("cancelled", terminal_detail("cancelled")),
            };
            canonical_json(&json!({
                "apiVersion": REPAIR_SERVICE_API_VERSION,
                "requestId": request_id,
                "operation": operation,
                "outcome": "ok",
                "stateVersion": 7,
                "state": public_state,
                "detail": detail
            }))
            .map_err(Into::into)
        }
    }

    fn prepared_detail(action_id: WorkOrderActionId) -> Value {
        let contract = repair_action_contract(action_id).expect("repair contract");
        json!({
            "kind": contract.prepared_kind,
            "preparedId": format!("Q-{}", "1".repeat(32)),
            "sessionId": format!("S-{}", "2".repeat(32)),
            "planId": format!("P-{}", "3".repeat(32)),
            "planHash": format!("sha256:{}", "4".repeat(64)),
            "targetFingerprint": format!("sha256:{}", "5".repeat(64)),
            "beforeSha256": format!("sha256:{}", "6".repeat(64)),
            "afterSha256": format!("sha256:{}", "7".repeat(64)),
            "diffSha256": format!("sha256:{}", "8".repeat(64)),
            "resourceId": contract.resource_id,
            "backupLocator": format!("vault://repair/B-{}", "9".repeat(32)),
            "actionId": contract.action_id.wire_name(),
            "risk": contract.risk_id,
            "backup": {"state": "reserved", "vaultDistinct": true},
            "nextApprovalSequence": 1,
            "confirmationRequired": contract.typed_confirmation
        })
    }

    fn terminal_detail(outcome: &str) -> Value {
        json!({
            "kind": "terminal",
            "terminalOutcome": outcome,
            "reservationId": format!("B-{}", "9".repeat(32)),
            "transactionBindingSha256": format!("sha256:{}", "a".repeat(64)),
            "rebootRequired": true,
            "prepareFailureStage": null
        })
    }

    fn repair_order(action_id: WorkOrderActionId) -> LeasedWorkOrder {
        let contract = repair_action_contract(action_id).expect("repair contract");
        serde_json::from_value(json!({
            "workOrderId": format!("wo-rescue-{}", action_id.wire_name()),
            "targetDeviceId": DEVICE,
            "actionId": action_id.wire_name(),
            "actionVersion": 1,
            "kind": "repair",
            "risk": contract.risk_id,
            "localApprovalRequired": true,
            "status": "leased",
            "createdAt": "2026-08-31T12:00:00Z",
            "expiresAt": "2026-08-31T13:00:00Z",
            "approval": {
                "approvedAt": "2026-08-31T12:29:00Z",
                "approvedByCredentialId": "credential-1"
            },
            "lease": {
                "leaseId": format!("lease-rescue-{}", action_id.wire_name()),
                "leasedAt": "2026-08-31T12:30:00Z",
                "leaseExpiresAt": "2026-08-31T12:35:00Z"
            }
        }))
        .expect("work order")
    }

    fn successor_order(action_id: WorkOrderActionId) -> LeasedWorkOrder {
        let mut value = serde_json::to_value(repair_order(action_id)).expect("work order JSON");
        value["workOrderId"] = json!(format!("wo-successor-{}", action_id.wire_name()));
        value["createdAt"] = json!("2026-08-31T12:36:00Z");
        value["expiresAt"] = json!("2026-08-31T13:36:00Z");
        value["approval"]["approvedAt"] = json!("2026-08-31T12:35:30Z");
        value["lease"]["leaseId"] = json!(format!("lease-successor-{}", action_id.wire_name()));
        value["lease"]["leasedAt"] = json!("2026-08-31T12:36:00Z");
        value["lease"]["leaseExpiresAt"] = json!("2026-08-31T12:41:00Z");
        serde_json::from_value(value).expect("successor work order")
    }

    fn stage_request(intent: &RescueDeskIntent) -> StageIntentRequest {
        StageIntentRequest {
            api_version: DESK_API_VERSION.to_owned(),
            operation: "stage".to_owned(),
            device_id: intent.device_id.clone(),
            work_order_id: intent.work_order_id.clone(),
            lease_id: intent.lease_id.clone(),
            execution_id: intent.execution_id.clone(),
            action_id: intent.action_id.clone(),
            action_version: intent.action_version,
            target: RescueTargetClaims {
                scan_fingerprint: format!("scan:{}", "b".repeat(64)),
                target_fingerprint: format!("sha256:{}", "5".repeat(64)),
                target_id: format!("target:{}", "c".repeat(64)),
            },
        }
    }

    fn approval_request(intent: &RescueDeskIntent) -> ApproveIntentRequest {
        let evidence = intent.evidence.as_ref().expect("evidence");
        let action_id = intent.action_id.parse().expect("action ID");
        let contract = repair_action_contract(action_id).expect("repair contract");
        ApproveIntentRequest {
            api_version: DESK_API_VERSION.to_owned(),
            operation: "approve".to_owned(),
            device_id: intent.device_id.clone(),
            work_order_id: intent.work_order_id.clone(),
            lease_id: intent.lease_id.clone(),
            execution_id: intent.execution_id.clone(),
            action_id: intent.action_id.clone(),
            action_version: intent.action_version,
            plan_sha256: evidence.plan_sha256.clone(),
            target_sha256: evidence.target_sha256.clone(),
            evidence_sha256: evidence.evidence_sha256.clone(),
            approval_id: format!("A-{}", "d".repeat(32)),
            approval_sequence: evidence.approval_sequence,
            approved_at: APPROVED_AT.to_owned(),
            typed_confirmation: contract.typed_confirmation.to_owned(),
        }
    }

    fn repair_actions() -> Vec<WorkOrderActionId> {
        #[cfg(feature = "rescue-repair-handoff")]
        return vec![
            WorkOrderActionId::LinuxFstabDisableMissingUuidV1,
            WorkOrderActionId::LinuxCrypttabDisableMissingUuidV1,
            WorkOrderActionId::LinuxExt4FsckPreenWithUndoV1,
            WorkOrderActionId::LinuxNetworkRestoreResolverLinkV1,
        ];
        #[cfg(not(feature = "rescue-repair-handoff"))]
        vec![WorkOrderActionId::LinuxFstabDisableMissingUuidV1]
    }

    fn opened(directory: &TempDir, broker: MockBroker) -> RescueFleetRepairAdapter<MockBroker> {
        RescueFleetRepairAdapter::open(&directory.path().join("state"), "tenant-1", DEVICE, broker)
            .expect("adapter")
    }

    #[test]
    fn fleet_intent_requires_fresh_evidence_bound_local_approval_for_each_repair() {
        for action_id in repair_actions() {
            let contract = repair_action_contract(action_id).expect("repair contract");
            let directory = TempDir::new().expect("tempdir");
            let broker = MockBroker::new(action_id);
            let mut adapter = opened(&directory, broker.clone());
            let order = repair_order(action_id);
            assert_eq!(
                adapter.prepare(&order, EXECUTION),
                Err(LocalHandoffErrorCode::ApprovalPending)
            );
            let intent = adapter.desk_intent().expect("intent");
            assert_eq!(intent.state, RescueIntentState::AwaitingTarget);
            assert_eq!(intent.risk, contract.risk_id);
            let staged = adapter.stage(&stage_request(&intent)).expect("staged");
            assert_eq!(staged.state, RescueIntentState::AwaitingApproval);
            assert_eq!(
                staged.confirmation_required.as_deref(),
                Some(contract.typed_confirmation)
            );

            let mut tampered = approval_request(&staged);
            tampered.evidence_sha256 = "0".repeat(64);
            assert_eq!(
                adapter.approve(&tampered, NOW_UNIX),
                Err(RescueAdapterError::BindingMismatch)
            );
            let approved = adapter
                .approve(&approval_request(&staged), NOW_UNIX)
                .expect("approved");
            assert_eq!(approved.state, RescueIntentState::Approved);

            let prepared = adapter.prepare(&order, EXECUTION).expect("preparation");
            let result = adapter
                .execute_or_recover(&prepared)
                .expect("terminal result");
            assert_eq!(result.outcome, WorkOrderResultOutcome::Succeeded);
            assert_eq!(
                broker.operations(),
                [
                    "repair.status",
                    contract.prepare_operation,
                    "repair.status",
                    contract.approve_operation,
                ]
            );
            let calls = broker.request_count();
            let replay = adapter
                .execute_or_recover(&prepared)
                .expect("terminal replay");
            assert_eq!(replay, result);
            assert_eq!(broker.request_count(), calls);
        }
    }

    #[test]
    fn stale_or_cross_device_approval_is_never_authority() {
        let directory = TempDir::new().expect("tempdir");
        let action_id = WorkOrderActionId::LinuxFstabDisableMissingUuidV1;
        let mut adapter = opened(&directory, MockBroker::new(action_id));
        let order = repair_order(action_id);
        let _ = adapter.prepare(&order, EXECUTION);
        let intent = adapter.desk_intent().expect("intent");
        let staged = adapter.stage(&stage_request(&intent)).expect("staged");
        let mut approval = approval_request(&staged);
        approval.device_id = "KA-ffffffffffffffffffffffff".to_owned();
        assert_eq!(
            adapter.approve(&approval, NOW_UNIX),
            Err(RescueAdapterError::InvalidRequest)
        );
        let mut approval = approval_request(&staged);
        approval.approved_at = "2026-08-31T12:25:00Z".to_owned();
        assert_eq!(
            adapter.approve(&approval, NOW_UNIX),
            Err(RescueAdapterError::ApprovalExpired)
        );
        assert_eq!(
            adapter.prepare(&order, EXECUTION),
            Err(LocalHandoffErrorCode::ApprovalPending)
        );

        let at_expiry = timestamp_unix(&staged.lease_expires_at).expect("lease expiry");
        assert_eq!(
            adapter.approve(&approval_request(&staged), at_expiry),
            Err(RescueAdapterError::ApprovalExpired)
        );
    }

    #[test]
    fn expired_unexecuted_intent_is_cancelled_before_successor_is_admitted() {
        let directory = TempDir::new().expect("tempdir");
        let action_id = WorkOrderActionId::LinuxFstabDisableMissingUuidV1;
        let broker = MockBroker::new(action_id);
        let mut adapter = opened(&directory, broker.clone());
        let order = repair_order(action_id);
        assert_eq!(
            adapter.prepare(&order, EXECUTION),
            Err(LocalHandoffErrorCode::ApprovalPending)
        );
        let intent = adapter.desk_intent().expect("intent");
        let staged = adapter.stage(&stage_request(&intent)).expect("staged");
        assert_eq!(staged.state, RescueIntentState::AwaitingApproval);

        let successor = successor_order(action_id);
        let successor_execution = "exec_abcdefabcdefabcdefabcdefabcdefab";
        assert_eq!(
            adapter.prepare(&successor, successor_execution),
            Err(LocalHandoffErrorCode::ApprovalPending)
        );
        let admitted = adapter.desk_intent().expect("successor intent");
        assert_eq!(admitted.work_order_id, successor.work_order_id());
        assert_eq!(admitted.state, RescueIntentState::AwaitingTarget);
        assert_eq!(
            broker.operations(),
            [
                "repair.status",
                repair_action_contract(action_id)
                    .expect("contract")
                    .prepare_operation,
                "repair.status",
                repair_action_contract(action_id)
                    .expect("contract")
                    .cancel_operation,
            ]
        );
    }

    #[test]
    fn explicit_local_rejection_is_durable_and_terminal_for_engine() {
        let directory = TempDir::new().expect("tempdir");
        let action_id = WorkOrderActionId::LinuxFstabDisableMissingUuidV1;
        let broker = MockBroker::new(action_id);
        let mut adapter = opened(&directory, broker);
        let order = repair_order(action_id);
        let _ = adapter.prepare(&order, EXECUTION);
        let intent = adapter.desk_intent().expect("intent");
        let staged = adapter.stage(&stage_request(&intent)).expect("staged");
        let evidence = staged.evidence.as_ref().expect("evidence");
        let rejected = adapter
            .reject(&RejectIntentRequest {
                api_version: DESK_API_VERSION.to_owned(),
                operation: "reject".to_owned(),
                device_id: staged.device_id.clone(),
                work_order_id: staged.work_order_id.clone(),
                lease_id: staged.lease_id.clone(),
                execution_id: staged.execution_id.clone(),
                action_id: staged.action_id.clone(),
                action_version: staged.action_version,
                evidence_sha256: evidence.evidence_sha256.clone(),
            })
            .expect("rejected");
        assert_eq!(rejected.state, RescueIntentState::Rejected);
        drop(adapter);

        let mut reopened = opened(&directory, MockBroker::new(action_id));
        assert_eq!(
            reopened.prepare(&order, EXECUTION),
            Err(LocalHandoffErrorCode::ApprovalRejected)
        );
    }

    #[cfg(feature = "rescue-repair-handoff")]
    #[test]
    fn action_binding_cannot_be_swapped_by_desk_or_broker() {
        let fstab = WorkOrderActionId::LinuxFstabDisableMissingUuidV1;
        let crypttab = WorkOrderActionId::LinuxCrypttabDisableMissingUuidV1;
        let directory = TempDir::new().expect("tempdir");
        let mut adapter = opened(&directory, MockBroker::new(fstab));
        let order = repair_order(fstab);
        let _ = adapter.prepare(&order, EXECUTION);
        let intent = adapter.desk_intent().expect("intent");
        let mut swapped = stage_request(&intent);
        swapped.action_id = crypttab.wire_name().to_owned();
        assert_eq!(
            adapter.stage(&swapped),
            Err(RescueAdapterError::BindingMismatch)
        );

        let staged = adapter.stage(&stage_request(&intent)).expect("staged");
        let mut swapped = approval_request(&staged);
        swapped.action_id = crypttab.wire_name().to_owned();
        swapped.typed_confirmation = repair_action_contract(crypttab)
            .expect("crypttab contract")
            .typed_confirmation
            .to_owned();
        assert_eq!(
            adapter.approve(&swapped, NOW_UNIX),
            Err(RescueAdapterError::BindingMismatch)
        );

        let directory = TempDir::new().expect("tempdir");
        let broker = MockBroker::new(fstab).reporting(crypttab);
        let mut adapter = opened(&directory, broker);
        let _ = adapter.prepare(&order, EXECUTION);
        let intent = adapter.desk_intent().expect("intent");
        assert_eq!(
            adapter.stage(&stage_request(&intent)),
            Err(RescueAdapterError::BrokerProtocol)
        );
    }

    #[test]
    fn desk_json_is_canonical_strict_and_state_contains_no_secret_or_raw_content() {
        let directory = TempDir::new().expect("tempdir");
        let action_id = WorkOrderActionId::LinuxFstabDisableMissingUuidV1;
        let mut adapter = opened(&directory, MockBroker::new(action_id));
        let order = repair_order(action_id);
        let _ = adapter.prepare(&order, EXECUTION);
        let intent = adapter.desk_intent().expect("intent");
        let mut value = serde_json::to_value(stage_request(&intent)).expect("JSON");
        value["command"] = Value::String("rm -rf /".to_owned());
        let bytes = canonical_json(&value).expect("canonical");
        assert_eq!(
            adapter.stage_from_json(&bytes),
            Err(RescueAdapterError::StateCorrupt)
        );
        let state = std::fs::read(directory.path().join("state").join(STATE_FILE)).expect("state");
        assert!(!state.windows(4).any(|window| window == b"seed"));
        assert!(!state.windows(5).any(|window| window == b"token"));
        assert!(!state.windows(7).any(|window| window == b"command"));
        assert!(!state.windows(4).any(|window| window == b"path"));
    }
}
