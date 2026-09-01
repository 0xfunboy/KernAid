//! Purpose-specific Fleet signer backed by the Rescue Vault daemon.
//!
//! The client can request only enrollment, work-order claim, and work-order
//! result envelopes. It pins the public identity independently and verifies
//! every complete signed response before returning it to Fleet code.

use kernaid_fleet_client::{
    EnrollmentRequestInput, FleetClientError, FleetRequestSigner, SignedEnrollmentRequest,
    SignedWorkOrderClaimRequest, SignedWorkOrderResult, WorkOrderClaimRequestInput,
    WorkOrderResultInput,
};
use kernaid_protocol::rescue_vault::{FleetSignedEnvelopePayload, RequestId, SuccessPayload};
use kernaid_protocol::rescue_vault_transport::{
    ClientRequest, ClientRequestPayload, ClientResponseOutcome, authenticate_root_seqpacket_server,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
    pipe::{PipeFlags, pipe_with},
};
use std::{
    fmt::Write as _,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const RESCUE_VAULT_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct VaultFleetSigner {
    device_id: String,
    public_key: [u8; 32],
}

impl VaultFleetSigner {
    pub fn new(device_id: String, public_key: [u8; 32]) -> Result<Self, FleetClientError> {
        if kernaid_device_identity::validate_device_id(&device_id).is_err()
            || kernaid_device_identity::device_id_for_public_key(&public_key) != device_id
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        Ok(Self {
            device_id,
            public_key,
        })
    }

    /// Discover and cryptographically pin the public Vault identity by asking
    /// it to sign one exact enrollment input. This is used only by the
    /// explicit Rescue provisioning command; it neither exports the private
    /// key nor turns the Vault into a generic signing oracle.
    pub fn discover_from_enrollment(
        input: &EnrollmentRequestInput,
    ) -> Result<Self, FleetClientError> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        let status = ClientRequest::new(new_request_id()?, 0, ClientRequestPayload::VaultStatus)
            .map_err(|_| FleetClientError::SignerUnavailable)?;
        let status = exchange(&status, None, deadline)?;
        let state_version = status.state_version();
        let device_id = match status.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(value)) => value
                .device_id()
                .map(str::to_owned)
                .ok_or(FleetClientError::SignerUnavailable)?,
            _ => return Err(FleetClientError::SignerUnavailable),
        };

        let canonical = Zeroizing::new(input.export_signing_input()?);
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(|_| FleetClientError::SignerUnavailable)?;
        write_all(write, &canonical)?;
        let request = ClientRequest::new(
            new_request_id()?,
            state_version,
            ClientRequestPayload::FleetEnrollmentSign {
                input_size: canonical.len() as u64,
            },
        )
        .map_err(|_| FleetClientError::SignerUnavailable)?;
        let response = exchange(&request, Some(read), deadline)?;
        let signed = match response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::FleetSigned(signed))
                if signed.device_id() == device_id
                    && kernaid_device_identity::device_id_for_public_key(signed.public_key())
                        == device_id =>
            {
                signed
            }
            _ => return Err(FleetClientError::SignerUnavailable),
        };
        SignedEnrollmentRequest::import_for_signing_input(
            signed.signed_request(),
            input,
            &device_id,
            signed.public_key(),
        )?;
        Self::new(device_id, *signed.public_key())
    }

    fn exchange(
        &self,
        input: &[u8],
        payload: impl FnOnce(u64) -> ClientRequestPayload,
    ) -> Result<FleetSignedEnvelopePayload, FleetClientError> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        let status = ClientRequest::new(new_request_id()?, 0, ClientRequestPayload::VaultStatus)
            .map_err(|_| FleetClientError::SignerUnavailable)?;
        let status = exchange(&status, None, deadline)?;
        let state_version = status.state_version();
        if !matches!(status.outcome(), ClientResponseOutcome::Success(SuccessPayload::VaultStatus(value)) if value.device_id() == Some(self.device_id.as_str()))
        {
            return Err(FleetClientError::SignerUnavailable);
        }

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(|_| FleetClientError::SignerUnavailable)?;
        write_all(write, input)?;
        let request = ClientRequest::new(
            new_request_id()?,
            state_version,
            payload(input.len() as u64),
        )
        .map_err(|_| FleetClientError::SignerUnavailable)?;
        let response = exchange(&request, Some(read), deadline)?;
        match response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::FleetSigned(signed))
                if signed.device_id() == self.device_id
                    && signed.public_key() == &self.public_key =>
            {
                Ok(signed.clone())
            }
            _ => Err(FleetClientError::SignerUnavailable),
        }
    }
}

impl FleetRequestSigner for VaultFleetSigner {
    fn device_id(&self) -> Result<String, FleetClientError> {
        Ok(self.device_id.clone())
    }

    fn public_key(&self) -> Result<[u8; 32], FleetClientError> {
        Ok(self.public_key)
    }

    fn sign_enrollment(
        &self,
        input: EnrollmentRequestInput,
    ) -> Result<SignedEnrollmentRequest, FleetClientError> {
        let canonical = Zeroizing::new(input.export_signing_input()?);
        let signed = self.exchange(&canonical, |input_size| {
            ClientRequestPayload::FleetEnrollmentSign { input_size }
        })?;
        SignedEnrollmentRequest::import_for_signing_input(
            signed.signed_request(),
            &input,
            &self.device_id,
            &self.public_key,
        )
    }

    fn sign_work_order_claim(
        &self,
        input: WorkOrderClaimRequestInput,
    ) -> Result<SignedWorkOrderClaimRequest, FleetClientError> {
        let canonical = Zeroizing::new(input.export_signing_input()?);
        let signed = self.exchange(&canonical, |input_size| {
            ClientRequestPayload::FleetWorkOrderClaimSign { input_size }
        })?;
        SignedWorkOrderClaimRequest::import_for_signing_input(
            signed.signed_request(),
            &input,
            &self.device_id,
            &self.public_key,
        )
    }

    fn sign_work_order_result(
        &self,
        input: WorkOrderResultInput,
    ) -> Result<SignedWorkOrderResult, FleetClientError> {
        let canonical = Zeroizing::new(input.export_signing_input()?);
        let signed = self.exchange(&canonical, |input_size| {
            ClientRequestPayload::FleetWorkOrderResultSign { input_size }
        })?;
        SignedWorkOrderResult::import_for_signing_input(
            signed.signed_request(),
            &input,
            &self.device_id,
            &self.public_key,
        )
    }
}

fn exchange(
    request: &ClientRequest,
    input: Option<OwnedFd>,
    deadline: Instant,
) -> Result<kernaid_protocol::rescue_vault_transport::ClientResponse, FleetClientError> {
    let socket = connect_vault(deadline)?;
    let authenticated = authenticate_root_seqpacket_server(socket.as_fd())
        .map_err(|_| FleetClientError::SignerUnavailable)?;
    let descriptors = input
        .as_ref()
        .map_or_else(Vec::new, |input| vec![input.as_fd()]);
    authenticated
        .send_request(request, &descriptors, deadline)
        .map_err(|_| FleetClientError::SignerUnavailable)?;
    authenticated
        .receive_response(request, deadline)
        .map_err(|_| FleetClientError::SignerUnavailable)
}

fn connect_vault(deadline: Instant) -> Result<OwnedFd, FleetClientError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| FleetClientError::SignerUnavailable)?;
    let address = SocketAddrUnix::new(RESCUE_VAULT_SOCKET_PATH)
        .map_err(|_| FleetClientError::SignerUnavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| FleetClientError::SignerUnavailable)?
                .map_err(|_| FleetClientError::SignerUnavailable)?;
        }
        Err(_) => return Err(FleetClientError::SignerUnavailable),
    }
    Ok(socket)
}

fn write_all(write: OwnedFd, bytes: &[u8]) -> Result<(), FleetClientError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match rustix::io::write(&write, &bytes[offset..]) {
            Ok(0) => return Err(FleetClientError::SignerUnavailable),
            Ok(written) => offset += written,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(FleetClientError::SignerUnavailable),
        }
    }
    Ok(())
}

fn new_request_id() -> Result<RequestId, FleetClientError> {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut id = String::from("R-");
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        write!(&mut id, "{byte:02x}").map_err(|_| FleetClientError::SignerUnavailable)?;
    }
    RequestId::parse(&id).map_err(|_| FleetClientError::SignerUnavailable)
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), FleetClientError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(FleetClientError::SignerUnavailable)?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(FleetClientError::SignerUnavailable),
            Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                return Err(FleetClientError::SignerUnavailable);
            }
            Ok(_)
                if descriptors[0]
                    .revents()
                    .intersects(interest | PollFlags::ERR) =>
            {
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(FleetClientError::SignerUnavailable),
        }
    }
}
