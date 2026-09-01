//! Authenticated local Desk surface for the Fleet-to-Rescue repair adapter.
//!
//! This service owns one adapter instance and exposes only status and the
//! adapter's three closed Desk operations. It cannot ingest a Fleet work
//! order: only a verified `ResidentWorkOrderEngine` sharing this service may
//! create an intent through `LocalWorkOrderHandoff`.

use crate::rescue::{
    RescueAdapterError, RescueFleetRepairAdapter, RescueRepairBroker, SystemRescueRepairBroker,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, FileType, OFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketAddrUnix,
        SocketFlags, SocketType, accept_with, recvmsg, send,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::IoSliceMut,
    mem::MaybeUninit,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const LOCAL_API_VERSION: &str = "kernaid.dev/fleet-rescue-repair-local/v1";
pub const LOCAL_SOCKET_PATH: &str = "/run/kernaid-fleet-rescue-repair.sock";
pub const LOCAL_SOCKET_FD_NAME: &str = "fleet-rescue-api";
const MAX_LOCAL_REQUEST_BYTES: usize = 8 * 1024;
const MAX_LOCAL_RESPONSE_BYTES: usize = 16 * 1024;
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRequest {
    api_version: String,
    operation: String,
    #[serde(default)]
    request: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSuccess {
    api_version: &'static str,
    operation: String,
    outcome: &'static str,
    intent: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalFailure<'error> {
    api_version: &'static str,
    operation: &'error str,
    outcome: &'static str,
    error: String,
}

/// Stateful local surface intended to live in the same verified Fleet
/// Resident process as its `ResidentWorkOrderEngine`.
pub struct RescueFleetRepairLocalService<B> {
    adapter: Arc<Mutex<RescueFleetRepairAdapter<B>>>,
}

impl<B> Clone for RescueFleetRepairLocalService<B> {
    fn clone(&self) -> Self {
        Self {
            adapter: Arc::clone(&self.adapter),
        }
    }
}

impl<B: RescueRepairBroker> RescueFleetRepairLocalService<B> {
    #[must_use]
    pub fn new(adapter: RescueFleetRepairAdapter<B>) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
        }
    }

    /// Returns the exact shared adapter owned by the local service. A verified
    /// Fleet engine in the same process locks this value only for one
    /// `run_once` call and passes the guard as its `LocalWorkOrderHandoff`.
    #[must_use]
    pub fn shared_adapter(&self) -> Arc<Mutex<RescueFleetRepairAdapter<B>>> {
        Arc::clone(&self.adapter)
    }

    pub fn handle_frame(&self, frame: &[u8]) -> Vec<u8> {
        let request = match parse_local_request(frame) {
            Ok(request) => request,
            Err(error) => return encode_failure("invalid", error),
        };
        let operation = request.operation.clone();
        let mut adapter = match self.adapter.try_lock() {
            Ok(adapter) => adapter,
            Err(std::sync::TryLockError::WouldBlock) => {
                return encode_failure(&operation, RescueAdapterError::Busy);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return encode_failure(&operation, RescueAdapterError::StateCorrupt);
            }
        };
        let result = match operation.as_str() {
            "status" if request.request.is_none() => adapter
                .export_desk_intent()
                .and_then(|intent| encode_success(&operation, intent.as_deref())),
            "submit" => {
                let body = request
                    .request
                    .ok_or(RescueAdapterError::InvalidRequest)
                    .and_then(|value| {
                        serde_json::to_vec(&value).map_err(|_| RescueAdapterError::InvalidRequest)
                    });
                body.and_then(|body| adapter.handle_desk_post(&body, current_unix_time()?))
                    .and_then(|intent| encode_success(&operation, Some(&intent)))
            }
            _ => Err(RescueAdapterError::InvalidRequest),
        };
        result.unwrap_or_else(|error| encode_failure(&operation, error))
    }
}

fn parse_local_request(frame: &[u8]) -> Result<LocalRequest, RescueAdapterError> {
    if frame.is_empty() || frame.len() > MAX_LOCAL_REQUEST_BYTES {
        return Err(RescueAdapterError::InvalidRequest);
    }
    let request: LocalRequest =
        serde_json::from_slice(frame).map_err(|_| RescueAdapterError::InvalidRequest)?;
    if request.api_version != LOCAL_API_VERSION
        || !matches!(request.operation.as_str(), "status" | "submit")
    {
        return Err(RescueAdapterError::InvalidRequest);
    }
    let canonical = serde_json::to_vec(&request_to_value(&request)?)
        .map_err(|_| RescueAdapterError::InvalidRequest)?;
    if canonical != frame {
        return Err(RescueAdapterError::InvalidRequest);
    }
    Ok(request)
}

fn request_to_value(request: &LocalRequest) -> Result<Value, RescueAdapterError> {
    let mut value = serde_json::Map::new();
    value.insert(
        "apiVersion".to_owned(),
        Value::String(request.api_version.clone()),
    );
    value.insert(
        "operation".to_owned(),
        Value::String(request.operation.clone()),
    );
    if let Some(body) = &request.request {
        value.insert("request".to_owned(), body.clone());
    }
    Ok(Value::Object(value))
}

fn current_unix_time() -> Result<u64, RescueAdapterError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RescueAdapterError::ApprovalExpired)?
        .as_secs())
}

fn encode_success(operation: &str, intent: Option<&[u8]>) -> Result<Vec<u8>, RescueAdapterError> {
    let intent = intent
        .map(|bytes| serde_json::from_slice(bytes).map_err(|_| RescueAdapterError::StateCorrupt))
        .transpose()?;
    let encoded = serde_json::to_vec(&LocalSuccess {
        api_version: LOCAL_API_VERSION,
        operation: operation.to_owned(),
        outcome: "ok",
        intent,
    })
    .map_err(|_| RescueAdapterError::StateCorrupt)?;
    if encoded.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(RescueAdapterError::StateCorrupt);
    }
    Ok(encoded)
}

fn encode_failure(operation: &str, error: RescueAdapterError) -> Vec<u8> {
    serde_json::to_vec(&LocalFailure {
        api_version: LOCAL_API_VERSION,
        operation,
        outcome: "error",
        error: error.to_string(),
    })
    .unwrap_or_else(|_| {
        b"{\"apiVersion\":\"kernaid.dev/fleet-rescue-repair-local/v1\",\"error\":\"rescue-fleet-state-corrupt\",\"operation\":\"invalid\",\"outcome\":\"error\"}".to_vec()
    })
}

/// Serves the fixed systemd-activated seqpacket endpoint. The accepted peer
/// must be a distinct non-root process in this service's primary group.
pub fn run_activated_local_service<B: RescueRepairBroker>(
    listener: OwnedFd,
    service: RescueFleetRepairLocalService<B>,
) -> Result<(), RescueAdapterError> {
    let status = rfs::fcntl_getfl(&listener).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    rfs::fcntl_setfl(&listener, status | OFlags::NONBLOCK)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let authorized_gid = validate_listener(listener.as_fd())?;
    let self_uid = rustix::process::geteuid().as_raw();
    if self_uid == 0 {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    loop {
        wait_ready(listener.as_fd(), PollFlags::IN, None)?;
        loop {
            let connection =
                match accept_with(&listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                    Ok(connection) => connection,
                    Err(error) if error == rustix::io::Errno::AGAIN => break,
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
                };
            if authenticate_client(connection.as_fd(), authorized_gid, self_uid).is_err() {
                continue;
            }
            let deadline = Instant::now()
                .checked_add(LOCAL_REQUEST_TIMEOUT)
                .ok_or(RescueAdapterError::BrokerUnavailable)?;
            let Ok(frame) = receive_frame(connection.as_fd(), deadline) else {
                continue;
            };
            let response = service.handle_frame(&frame);
            let _ = send_frame(connection.as_fd(), &response, deadline);
        }
    }
}

fn validate_listener(listener: BorrowedFd<'_>) -> Result<u32, RescueAdapterError> {
    let descriptor =
        rustix::io::fcntl_getfd(listener).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let status = rfs::fcntl_getfl(listener).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let socket_stat = rfs::fstat(listener).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let named = rfs::statat(rfs::CWD, LOCAL_SOCKET_PATH, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let run = rfs::statat(rfs::CWD, "/run", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let authorized_gid = rustix::process::getgid().as_raw();
    let address: SocketAddrUnix = rustix::net::getsockname(listener)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        .try_into()
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    if rustix::net::sockopt::socket_domain(listener)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(listener)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
            != SocketType::SEQPACKET
        || !rustix::net::sockopt::socket_acceptconn(listener)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || !FileType::from_raw_mode(socket_stat.st_mode).is_socket()
        || socket_stat.st_uid != 0
        || !FileType::from_raw_mode(named.st_mode).is_socket()
        || named.st_uid != 0
        || authorized_gid == 0
        || named.st_gid != authorized_gid
        || named.st_nlink != 1
        || named.st_mode & 0o7777 != 0o660
        || !FileType::from_raw_mode(run.st_mode).is_dir()
        || run.st_uid != 0
        || run.st_gid != 0
        || run.st_mode & 0o022 != 0
        || address.path_bytes() != Some(LOCAL_SOCKET_PATH.as_bytes())
    {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    Ok(authorized_gid)
}

fn authenticate_client(
    connection: BorrowedFd<'_>,
    authorized_gid: u32,
    self_uid: u32,
) -> Result<(), RescueAdapterError> {
    let credentials = rustix::net::sockopt::socket_peercred(connection)
        .map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let descriptor =
        rustix::io::fcntl_getfd(connection).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    let status = rfs::fcntl_getfl(connection).map_err(|_| RescueAdapterError::BrokerUnavailable)?;
    if credentials.pid.as_raw_nonzero().get() <= 1
        || credentials.uid.as_raw() == 0
        || credentials.uid.as_raw() == self_uid
        || credentials.gid.as_raw() != authorized_gid
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || rustix::net::sockopt::socket_domain(connection)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(connection)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(connection)
            .map_err(|_| RescueAdapterError::BrokerUnavailable)?
        || rustix::net::getpeername(connection).is_err()
    {
        return Err(RescueAdapterError::BrokerUnavailable);
    }
    Ok(())
}

fn receive_frame(socket: BorrowedFd<'_>, deadline: Instant) -> Result<Vec<u8>, RescueAdapterError> {
    let mut bytes = vec![0_u8; MAX_LOCAL_REQUEST_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut control_space: [MaybeUninit<u8>; 0] = [];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, Some(deadline))?;
            }
            Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
        }
    };
    if message.bytes == 0
        || message.bytes > MAX_LOCAL_REQUEST_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    bytes.truncate(message.bytes);
    Ok(bytes)
}

fn send_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), RescueAdapterError> {
    if frame.is_empty() || frame.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(RescueAdapterError::BrokerProtocol);
    }
    loop {
        match send(socket, frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) if sent == frame.len() => return Ok(()),
            Ok(_) => return Err(RescueAdapterError::BrokerProtocol),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, Some(deadline))?;
            }
            Err(_) => return Err(RescueAdapterError::BrokerUnavailable),
        }
    }
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Option<Instant>,
) -> Result<(), RescueAdapterError> {
    loop {
        let timeout = if let Some(deadline) = deadline {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(RescueAdapterError::BrokerUnavailable)?;
            let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
            Some(Timespec {
                tv_sec: seconds,
                tv_nsec: if seconds == i64::MAX {
                    999_999_999
                } else {
                    i64::from(remaining.subsec_nanos())
                },
            })
        } else {
            None
        };
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, timeout.as_ref()) {
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

pub fn open_system_local_service(
    state_directory: &Path,
    tenant_id: &str,
    device_id: &str,
) -> Result<RescueFleetRepairLocalService<SystemRescueRepairBroker>, RescueAdapterError> {
    RescueFleetRepairAdapter::open(
        state_directory,
        tenant_id,
        device_id,
        SystemRescueRepairBroker,
    )
    .map(RescueFleetRepairLocalService::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalHandoffErrorCode, LocalWorkOrderHandoff};
    use kernaid_fleet_client::LeasedWorkOrder;
    use serde_json::json;

    #[derive(Clone, Copy)]
    struct UnusedBroker;

    impl RescueRepairBroker for UnusedBroker {
        fn exchange(
            &mut self,
            _request: &[u8],
            _maximum_response_bytes: usize,
        ) -> Result<Vec<u8>, RescueAdapterError> {
            Err(RescueAdapterError::BrokerUnavailable)
        }
    }

    #[test]
    fn local_service_exposes_only_canonical_status_or_submit() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let adapter = RescueFleetRepairAdapter::open(
            &directory.path().join("state"),
            "tenant-1",
            "KA-0123456789abcdef01234567",
            UnusedBroker,
        )
        .expect("adapter");
        let service = RescueFleetRepairLocalService::new(adapter);
        let response = service.handle_frame(
            br#"{"apiVersion":"kernaid.dev/fleet-rescue-repair-local/v1","operation":"status"}"#,
        );
        let response: Value = serde_json::from_slice(&response).expect("status response");
        assert_eq!(response["outcome"], "ok");
        assert!(response["intent"].is_null());

        let noncanonical = service.handle_frame(
            br#"{"operation":"status","apiVersion":"kernaid.dev/fleet-rescue-repair-local/v1"}"#,
        );
        let noncanonical: Value = serde_json::from_slice(&noncanonical).expect("failure response");
        assert_eq!(noncanonical["outcome"], "error");
        assert_eq!(noncanonical["error"], "rescue-fleet-request-invalid");

        let forged = service.handle_frame(
            br#"{"apiVersion":"kernaid.dev/fleet-rescue-repair-local/v1","operation":"create-intent","request":{}}"#,
        );
        let forged: Value = serde_json::from_slice(&forged).expect("failure response");
        assert_eq!(forged["outcome"], "error");

        let order: LeasedWorkOrder = serde_json::from_value(json!({
            "workOrderId": "wo-rescue-1",
            "targetDeviceId": "KA-0123456789abcdef01234567",
            "actionId": "linux.fstab.disable-missing-uuid.v1",
            "actionVersion": 1,
            "kind": "repair",
            "risk": "R2",
            "localApprovalRequired": true,
            "status": "leased",
            "createdAt": "2026-09-01T01:00:00Z",
            "expiresAt": "2026-09-01T02:00:00Z",
            "approval": {
                "approvedAt": "2026-09-01T01:00:30Z",
                "approvedByCredentialId": "credential-1"
            },
            "lease": {
                "leaseId": "lease-rescue-1",
                "leasedAt": "2026-09-01T01:01:00Z",
                "leaseExpiresAt": "2026-09-01T01:06:00Z"
            }
        }))
        .expect("leased work order");
        let shared = service.shared_adapter();
        let mut adapter = shared.lock().expect("shared adapter");
        assert_eq!(
            adapter.prepare(&order, "exec_0123456789abcdef0123456789abcdef"),
            Err(LocalHandoffErrorCode::ApprovalPending)
        );
        drop(adapter);
        let status = service.handle_frame(
            br#"{"apiVersion":"kernaid.dev/fleet-rescue-repair-local/v1","operation":"status"}"#,
        );
        let status: Value = serde_json::from_slice(&status).expect("intent status");
        assert_eq!(status["outcome"], "ok");
        assert_eq!(status["intent"]["workOrderId"], "wo-rescue-1");
        assert_eq!(status["intent"]["state"], "awaiting-target");
    }
}
