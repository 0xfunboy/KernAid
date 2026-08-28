//! Validated systemd-activated SOCK_SEQPACKET runtime for repaird.

use crate::rescue_repair_service::{
    REPAIR_SERVICE_MAX_FRAME_BYTES, RepairPreparationEngine, RescueRepairService,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, Mode, OFlags, ResolveFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept_with, recvmsg, send, sendto,
        socket_with,
    },
};
use std::{
    env,
    fs::File,
    io::{IoSliceMut, Read},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::Path,
    time::{Duration, Instant},
};

const SOCKET_PATH: &str = "/run/kernaid-rescue-repair.sock";
const AUTHORIZED_GROUP: &str = "kernaid-repair-client";
const GROUP_FILE: &str = "/etc/group";
const MAX_GROUP_FILE_BYTES: u64 = 64 * 1024;
const STARTUP_RECOVERY_TIMEOUT: Duration = Duration::from_secs(165);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(2);
const READY_PAYLOAD: &[u8] = b"READY=1\nSTATUS=KernAid repair recovery barrier complete";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairServiceRuntimeError {
    InvalidConfiguration,
    InvalidListener,
    RecoveryUnavailable,
    ReadinessUnavailable,
    TransportFailure,
}

impl std::fmt::Display for RepairServiceRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid repair service configuration",
            Self::InvalidListener => "invalid repair service listener",
            Self::RecoveryUnavailable => "repair recovery barrier unavailable",
            Self::ReadinessUnavailable => "repair service readiness unavailable",
            Self::TransportFailure => "repair service transport failure",
        })
    }
}

impl std::error::Error for RepairServiceRuntimeError {}

/// Runs the persistent Accept=no service. The caller must pass the sole FD 3
/// obtained from the systemd activation ownership wrapper.
pub fn run_activated_repair_service<Engine: RepairPreparationEngine>(
    listener: OwnedFd,
    engine: Engine,
) -> Result<(), RepairServiceRuntimeError> {
    let authorized_gid = lookup_authorized_gid()?;
    let self_uid = rustix::process::geteuid().as_raw();
    if self_uid == 0 {
        return Err(RepairServiceRuntimeError::InvalidConfiguration);
    }
    let status =
        rfs::fcntl_getfl(&listener).map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    rfs::fcntl_setfl(&listener, status | OFlags::NONBLOCK)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    validate_listener(listener.as_fd(), authorized_gid)?;

    let recovery_deadline = Instant::now()
        .checked_add(STARTUP_RECOVERY_TIMEOUT)
        .ok_or(RepairServiceRuntimeError::RecoveryUnavailable)?;
    let mut service = RescueRepairService::start(engine, recovery_deadline)
        .map_err(|_| RepairServiceRuntimeError::RecoveryUnavailable)?;
    notify_ready()?;

    loop {
        wait_ready(listener.as_fd(), PollFlags::IN, None)?;
        loop {
            let connection =
                match accept_with(&listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                    Ok(connection) => connection,
                    Err(error) if error == rustix::io::Errno::AGAIN => break,
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(_) => return Err(RepairServiceRuntimeError::TransportFailure),
                };
            if authenticate_peer(connection.as_fd(), authorized_gid, self_uid).is_err() {
                continue;
            }
            let deadline = Instant::now()
                .checked_add(CONNECTION_TIMEOUT)
                .ok_or(RepairServiceRuntimeError::TransportFailure)?;
            let Ok(frame) = receive_frame(connection.as_fd(), deadline) else {
                continue;
            };
            let response = service.handle_frame(&frame);
            let _ = send_frame(connection.as_fd(), &response, deadline);
        }
    }
}

fn validate_listener(
    listener: BorrowedFd<'_>,
    authorized_gid: u32,
) -> Result<(), RepairServiceRuntimeError> {
    let descriptor = rustix::io::fcntl_getfd(listener)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    let status =
        rfs::fcntl_getfl(listener).map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    let socket_stat =
        rfs::fstat(listener).map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    let named = rfs::statat(rfs::CWD, SOCKET_PATH, rfs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    let run = rfs::statat(rfs::CWD, "/run", rfs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    let address: SocketAddrUnix = rustix::net::getsockname(listener)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?
        .try_into()
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?;
    if rustix::net::sockopt::socket_domain(listener)
        .map_err(|_| RepairServiceRuntimeError::InvalidListener)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(listener)
            .map_err(|_| RepairServiceRuntimeError::InvalidListener)?
            != SocketType::SEQPACKET
        || !rustix::net::sockopt::socket_acceptconn(listener)
            .map_err(|_| RepairServiceRuntimeError::InvalidListener)?
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || !FileType::from_raw_mode(socket_stat.st_mode).is_socket()
        || socket_stat.st_uid != 0
        || !FileType::from_raw_mode(named.st_mode).is_socket()
        || named.st_uid != 0
        || named.st_gid != authorized_gid
        || named.st_nlink != 1
        || named.st_mode & 0o7777 != 0o660
        || !FileType::from_raw_mode(run.st_mode).is_dir()
        || run.st_uid != 0
        || run.st_gid != 0
        || run.st_mode & 0o022 != 0
        || address.path_bytes() != Some(SOCKET_PATH.as_bytes())
        || rustix::net::sockopt::socket_passcred(listener)
            .map_err(|_| RepairServiceRuntimeError::InvalidListener)?
    {
        return Err(RepairServiceRuntimeError::InvalidListener);
    }
    Ok(())
}

fn authenticate_peer(
    connection: BorrowedFd<'_>,
    authorized_gid: u32,
    self_uid: u32,
) -> Result<(), RepairServiceRuntimeError> {
    let credentials = rustix::net::sockopt::socket_peercred(connection)
        .map_err(|_| RepairServiceRuntimeError::TransportFailure)?;
    let descriptor = rustix::io::fcntl_getfd(connection)
        .map_err(|_| RepairServiceRuntimeError::TransportFailure)?;
    let status =
        rfs::fcntl_getfl(connection).map_err(|_| RepairServiceRuntimeError::TransportFailure)?;
    if credentials.pid.as_raw_nonzero().get() <= 1
        || credentials.uid.as_raw() == 0
        || credentials.uid.as_raw() == self_uid
        || credentials.gid.as_raw() != authorized_gid
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || rustix::net::sockopt::socket_domain(connection)
            .map_err(|_| RepairServiceRuntimeError::TransportFailure)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(connection)
            .map_err(|_| RepairServiceRuntimeError::TransportFailure)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(connection)
            .map_err(|_| RepairServiceRuntimeError::TransportFailure)?
        || rustix::net::getpeername(connection).is_err()
    {
        return Err(RepairServiceRuntimeError::TransportFailure);
    }
    Ok(())
}

fn receive_frame(
    connection: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<Vec<u8>, RepairServiceRuntimeError> {
    let mut bytes = vec![0_u8; REPAIR_SERVICE_MAX_FRAME_BYTES + 1];
    let mut slices = [IoSliceMut::new(&mut bytes)];
    let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        match recvmsg(
            connection,
            &mut slices,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(connection, PollFlags::IN, Some(deadline))?;
            }
            Err(_) => return Err(RepairServiceRuntimeError::TransportFailure),
        }
    };
    let mut ancillary_present = false;
    let mut received_descriptors = Vec::new();
    for item in control.drain() {
        ancillary_present = true;
        if let RecvAncillaryMessage::ScmRights(rights) = item {
            received_descriptors.extend(rights);
        }
    }
    if message.bytes == 0
        || message.bytes > REPAIR_SERVICE_MAX_FRAME_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || ancillary_present
    {
        return Err(RepairServiceRuntimeError::TransportFailure);
    }
    bytes.truncate(message.bytes);
    Ok(bytes)
}

fn send_frame(
    connection: BorrowedFd<'_>,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), RepairServiceRuntimeError> {
    if bytes.is_empty() || bytes.len() > REPAIR_SERVICE_MAX_FRAME_BYTES {
        return Err(RepairServiceRuntimeError::TransportFailure);
    }
    loop {
        match send(connection, bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) if sent == bytes.len() => return Ok(()),
            Ok(_) => return Err(RepairServiceRuntimeError::TransportFailure),
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(connection, PollFlags::OUT, Some(deadline))?;
            }
            Err(_) => return Err(RepairServiceRuntimeError::TransportFailure),
        }
    }
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Option<Instant>,
) -> Result<(), RepairServiceRuntimeError> {
    loop {
        let timeout = deadline.map(|deadline| {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            Timespec {
                tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(remaining.subsec_nanos()),
            }
        });
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, timeout.as_ref()) {
            Ok(0) => return Err(RepairServiceRuntimeError::TransportFailure),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                    return Err(RepairServiceRuntimeError::TransportFailure);
                }
                if events.contains(interest) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(_) => return Err(RepairServiceRuntimeError::TransportFailure),
        }
    }
}

fn lookup_authorized_gid() -> Result<u32, RepairServiceRuntimeError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        GROUP_FILE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RepairServiceRuntimeError::InvalidConfiguration)?;
    let stat =
        rfs::fstat(&descriptor).map_err(|_| RepairServiceRuntimeError::InvalidConfiguration)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_GROUP_FILE_BYTES
    {
        return Err(RepairServiceRuntimeError::InvalidConfiguration);
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    File::from(descriptor)
        .take(MAX_GROUP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RepairServiceRuntimeError::InvalidConfiguration)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| RepairServiceRuntimeError::InvalidConfiguration)?;
    let mut matches = text.lines().filter_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let gid = fields.next()?;
        let _members = fields.next()?;
        if fields.next().is_some() || name != AUTHORIZED_GROUP {
            return None;
        }
        gid.parse::<u32>().ok().filter(|gid| *gid != 0)
    });
    let gid = matches
        .next()
        .ok_or(RepairServiceRuntimeError::InvalidConfiguration)?;
    if matches.next().is_some() {
        return Err(RepairServiceRuntimeError::InvalidConfiguration);
    }
    Ok(gid)
}

fn notify_ready() -> Result<(), RepairServiceRuntimeError> {
    let value =
        env::var_os("NOTIFY_SOCKET").ok_or(RepairServiceRuntimeError::ReadinessUnavailable)?;
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 108 || bytes.contains(&0) {
        return Err(RepairServiceRuntimeError::ReadinessUnavailable);
    }
    let address = match bytes[0] {
        b'/' => SocketAddrUnix::new(Path::new(&value)),
        b'@' if bytes.len() > 1 => SocketAddrUnix::new_abstract_name(&bytes[1..]),
        _ => return Err(RepairServiceRuntimeError::ReadinessUnavailable),
    }
    .map_err(|_| RepairServiceRuntimeError::ReadinessUnavailable)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RepairServiceRuntimeError::ReadinessUnavailable)?;
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        match sendto(
            &socket,
            READY_PAYLOAD,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            &address,
        ) {
            Ok(sent) if sent == READY_PAYLOAD.len() => return Ok(()),
            Ok(_) => return Err(RepairServiceRuntimeError::ReadinessUnavailable),
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket.as_fd(), PollFlags::OUT, Some(deadline))?;
            }
            Err(_) => return Err(RepairServiceRuntimeError::ReadinessUnavailable),
        }
    }
}
