//! Linux production adapter: external trust anchors, the existing Resident
//! identity, fail-closed Fleet runtime decisions and hardened HTTPS.

use super::*;
use chrono::{SecondsFormat, Utc};
use fs2::FileExt as _;
use kernaid_fleet_policy::{TransportState, UpdateRing as PolicyUpdateRing};
use kernaid_fleet_runtime::FleetRuntime;
use kernaid_native_secrets::NativeDeviceIdentityStore;
use rand_core::{OsRng, RngCore};
use reqwest::{
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE},
    redirect::Policy,
};
use rustix::{
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags},
    process,
};
use std::{
    env,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    thread,
    time::Duration,
};

const UPDATE_PULL_ROUTE: &str = "v1/update-pulls";
const LOCK_FILE: &str = ".resident-update-v1.lock";
const MAX_PUBLIC_FILE_BYTES: usize = 16 * 1024;
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const PROC_CMDLINE: &str = "/proc/cmdline";
const MAX_CMDLINE_BYTES: usize = 16 * 1024;

pub struct HttpsUpdateTransport {
    client: Client,
    base: Url,
    origin: String,
}

impl HttpsUpdateTransport {
    pub fn new(
        endpoint: &str,
        connect_timeout_seconds: u64,
        request_timeout_seconds: u64,
    ) -> Result<Self, ResidentUpdateError> {
        let origin = validate_https_origin(endpoint)?;
        let base = Url::parse(&origin).map_err(|_| ResidentUpdateError::InvalidEndpoint)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(connect_timeout_seconds))
            .timeout(Duration::from_secs(request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Resident-Update/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| ResidentUpdateError::Transport(TransportErrorCode::Protocol))?;
        Ok(Self {
            client,
            base,
            origin,
        })
    }
}

impl ResidentUpdateTransport for HttpsUpdateTransport {
    type ArtifactReader = Response;

    fn origin(&self) -> &str {
        &self.origin
    }

    fn pull_updates(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<UpdatePullTransportResponse, TransportErrorCode> {
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(TransportErrorCode::Protocol);
        }
        let url = self
            .base
            .join(UPDATE_PULL_ROUTE)
            .map_err(|_| TransportErrorCode::InvalidEndpoint)?;
        if url.origin().ascii_serialization() != self.origin {
            return Err(TransportErrorCode::InvalidEndpoint);
        }
        let response = self
            .client
            .post(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(map_reqwest_error)?;
        read_pull_response(response, maximum_response_bytes)
    }

    fn download_artifact(
        &mut self,
        artifact: &ArtifactDescriptor,
    ) -> Result<Self::ArtifactReader, TransportErrorCode> {
        let url = Url::parse(&artifact.url).map_err(|_| TransportErrorCode::InvalidEndpoint)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportErrorCode::InvalidEndpoint);
        }
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/octet-stream")
            .send()
            .map_err(map_reqwest_error)?;
        if response.status().as_u16() != 200 {
            return Err(TransportErrorCode::Protocol);
        }
        let expected = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(TransportErrorCode::Protocol)?;
        if expected != artifact.size_bytes {
            return Err(TransportErrorCode::Protocol);
        }
        Ok(response)
    }
}

pub fn run_from_args() -> Result<(), ResidentUpdateError> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    let config_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or(ResidentUpdateError::InvalidConfig)?;
    let once = match arguments.next() {
        None => false,
        Some(value) if value == "--once" => true,
        Some(_) => return Err(ResidentUpdateError::InvalidConfig),
    };
    if arguments.next().is_some() {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    let config =
        ResidentUpdateConfig::parse(&read_public_bounded(&config_path, MAX_PUBLIC_FILE_BYTES)?)?;
    run_service(config, once)
}

pub fn run_service(config: ResidentUpdateConfig, once: bool) -> Result<(), ResidentUpdateError> {
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(LOCK_FILE))?;
    let update_anchor = read_public_anchor(&config.update_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let mut identity_store = NativeDeviceIdentityStore::open_named(RESIDENT_IDENTITY_NAMESPACE)
        .map_err(|_| ResidentUpdateError::IdentityUnavailable)?;
    let identity = identity_store
        .load_device_identity()
        .map_err(|_| ResidentUpdateError::IdentityUnavailable)?
        .ok_or(ResidentUpdateError::IdentityUnavailable)?;
    let runtime = FleetRuntime::open_with_trust_anchors(
        &config.runtime_state_file,
        &config.tenant_id,
        &identity,
        &entitlement_anchor,
        &policy_anchor,
    )
    .map_err(|_| ResidentUpdateError::RuntimeUnavailable)?;
    let transport = HttpsUpdateTransport::new(
        &config.endpoint,
        config.connect_timeout_seconds,
        config.request_timeout_seconds,
    )?;
    let mut engine = ResidentUpdateEngine::open(
        &config.endpoint,
        &config.tenant_id,
        &config.state_directory,
        &update_anchor,
        transport,
    )?;

    loop {
        let now = Utc::now();
        let now_unix =
            u64::try_from(now.timestamp()).map_err(|_| ResidentUpdateError::ClockUnavailable)?;
        let mut nonce = Zeroizing::new(vec![0_u8; 32]);
        OsRng
            .try_fill_bytes(nonce.as_mut_slice())
            .map_err(|_| ResidentUpdateError::NonceUnavailable)?;
        let update_ring = effective_update_ring(
            &runtime,
            config.update_ring,
            now_unix,
            &identity.device_id(),
        )?;
        let input = UpdateCycleInput {
            issued_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
            now_unix,
            nonce,
            platform: UpdatePlatform::Linux,
            architecture: host_architecture()?,
            update_ring,
            updates_entitled: runtime.capabilities(now_unix).updates,
        };
        let (inactive_target, active_slot) = locally_selected_target(&config)?;
        let mut target = open_inactive_target(inactive_target, active_slot)?;
        let outcome = engine.run_once(&identity, input, &mut target)?;
        print_outcome(&outcome);
        if once || matches!(outcome, UpdateCycleOutcome::Staged(_)) {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(config.interval_seconds));
    }
}

fn locally_selected_target(
    config: &ResidentUpdateConfig,
) -> Result<(&Path, Slot), ResidentUpdateError> {
    match (
        config.inactive_target_file.as_deref(),
        config.active_slot,
        config.slot_a_target_file.as_deref(),
        config.slot_b_target_file.as_deref(),
    ) {
        (Some(path), Some(active_slot), None, None) => Ok((path, active_slot)),
        (None, None, Some(slot_a), Some(slot_b)) => {
            let active_slot = read_active_slot_marker()?;
            Ok((
                match active_slot {
                    Slot::A => slot_b,
                    Slot::B => slot_a,
                },
                active_slot,
            ))
        }
        _ => Err(ResidentUpdateError::InvalidConfig),
    }
}

fn read_active_slot_marker() -> Result<Slot, ResidentUpdateError> {
    let mut bytes = Vec::new();
    File::open(PROC_CMDLINE)?
        .take((MAX_CMDLINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_CMDLINE_BYTES {
        return Err(ResidentUpdateError::InvalidState);
    }
    let cmdline = std::str::from_utf8(&bytes).map_err(|_| ResidentUpdateError::InvalidState)?;
    let mut selected = None;
    for token in cmdline.split_ascii_whitespace() {
        let Some(value) = token.strip_prefix("kernaid.slot=") else {
            continue;
        };
        if selected.is_some() {
            return Err(ResidentUpdateError::InvalidState);
        }
        selected = Some(match value {
            "a" => Slot::A,
            "b" => Slot::B,
            _ => return Err(ResidentUpdateError::InvalidState),
        });
    }
    selected.ok_or(ResidentUpdateError::InvalidState)
}

fn effective_update_ring(
    runtime: &FleetRuntime,
    local: UpdateRing,
    now_unix: u64,
    device_id: &str,
) -> Result<UpdateRing, ResidentUpdateError> {
    let policies = runtime
        .load_policies()
        .map_err(|_| ResidentUpdateError::RuntimeUnavailable)?;
    policies.into_iter().try_fold(local, |effective, policy| {
        if !policy.is_applicable_to(device_id, now_unix, TransportState::Online) {
            return Ok(UpdateRing::Hold);
        }
        Ok(restrict_ring(effective, policy.update_ring()))
    })
}

const fn restrict_ring(local: UpdateRing, policy: PolicyUpdateRing) -> UpdateRing {
    match (local, policy) {
        (UpdateRing::Hold, _) | (_, PolicyUpdateRing::Hold) => UpdateRing::Hold,
        (UpdateRing::Stable, _) | (_, PolicyUpdateRing::Stable) => UpdateRing::Stable,
        (UpdateRing::Canary, PolicyUpdateRing::Canary) => UpdateRing::Canary,
    }
}

fn host_architecture() -> Result<UpdateArchitecture, ResidentUpdateError> {
    match env::consts::ARCH {
        "x86_64" => Ok(UpdateArchitecture::X86_64),
        "aarch64" => Ok(UpdateArchitecture::Aarch64),
        _ => Err(ResidentUpdateError::InvalidContext),
    }
}

fn open_inactive_target(
    path: &Path,
    active_slot: Slot,
) -> Result<PreopenedInactiveTarget, ResidentUpdateError> {
    let fd = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ResidentUpdateError::InvalidState)?;
    let descriptor = rfs::fstat(&fd).map_err(|_| ResidentUpdateError::InvalidState)?;
    let named = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResidentUpdateError::InvalidState)?;
    let descriptor_type = FileType::from_raw_mode(descriptor.st_mode);
    let named_type = FileType::from_raw_mode(named.st_mode);
    if (!descriptor_type.is_file() && !descriptor_type.is_block_device())
        || (!named_type.is_file() && !named_type.is_block_device())
        || descriptor.st_dev != named.st_dev
        || descriptor.st_ino != named.st_ino
        || descriptor.st_nlink != 1
    {
        return Err(ResidentUpdateError::InvalidState);
    }
    PreopenedInactiveTarget::new(File::from(fd), active_slot, active_slot.inactive())
        .map_err(Into::into)
}

fn read_pull_response(
    response: Response,
    maximum_response_bytes: usize,
) -> Result<UpdatePullTransportResponse, TransportErrorCode> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > maximum_response_bytes as u64)
    {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    let status = response.status().as_u16();
    let limit = u64::try_from(maximum_response_bytes)
        .map_err(|_| TransportErrorCode::ResponseTooLarge)?
        .saturating_add(1);
    let mut body = Vec::new();
    response
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|_| TransportErrorCode::Protocol)?;
    if body.len() > maximum_response_bytes {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    Ok(UpdatePullTransportResponse { status, body })
}

fn map_reqwest_error(error: reqwest::Error) -> TransportErrorCode {
    if error.is_timeout() {
        TransportErrorCode::Timeout
    } else if error.is_connect() {
        TransportErrorCode::Connect
    } else if error.is_builder() {
        TransportErrorCode::InvalidEndpoint
    } else {
        TransportErrorCode::Protocol
    }
}

fn read_public_anchor(path: &Path) -> Result<[u8; 32], ResidentUpdateError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let encoded =
        std::str::from_utf8(trim_ascii_line(&bytes).ok_or(ResidentUpdateError::InvalidConfig)?)
            .map_err(|_| ResidentUpdateError::InvalidConfig)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ResidentUpdateError::InvalidConfig)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    decoded
        .try_into()
        .map_err(|_| ResidentUpdateError::InvalidConfig)
}

fn read_public_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ResidentUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), ResidentUpdateError> {
    if !absolute_directory(path) {
        return Err(ResidentUpdateError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(ResidentUpdateError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process::getuid().as_raw()
    {
        return Err(ResidentUpdateError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o7777 != 0o700 {
        return Err(ResidentUpdateError::InvalidState);
    }
    Ok(())
}

fn open_service_lock(path: &Path) -> Result<File, ResidentUpdateError> {
    let fd = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ResidentUpdateError::InvalidState)?;
    let descriptor = rfs::fstat(&fd).map_err(|_| ResidentUpdateError::InvalidState)?;
    let named = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResidentUpdateError::InvalidState)?;
    if !FileType::from_raw_mode(descriptor.st_mode).is_file()
        || !FileType::from_raw_mode(named.st_mode).is_file()
        || descriptor.st_dev != named.st_dev
        || descriptor.st_ino != named.st_ino
        || descriptor.st_nlink != 1
        || descriptor.st_uid != process::getuid().as_raw()
    {
        return Err(ResidentUpdateError::InvalidState);
    }
    rfs::fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|_| ResidentUpdateError::InvalidState)?;
    let file = File::from(fd);
    file.try_lock_exclusive()
        .map_err(|_| ResidentUpdateError::InvalidState)?;
    Ok(file)
}

fn trim_ascii_line(bytes: &[u8]) -> Option<&[u8]> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        None
    } else {
        Some(bytes)
    }
}

fn print_outcome(outcome: &UpdateCycleOutcome) {
    match outcome {
        UpdateCycleOutcome::NoUpdate => {
            println!("KERNAID_FLEET_RESIDENT_UPDATE_V1 status=no-update activation=not-armed")
        }
        UpdateCycleOutcome::Staged(receipt) => println!(
            "KERNAID_FLEET_RESIDENT_UPDATE_V1 status=staged release={} sequence={} target={:?} activation=not-armed",
            receipt.release_id(),
            receipt.sequence(),
            receipt.target_slot()
        ),
        UpdateCycleOutcome::AlreadyStaged(receipt) => println!(
            "KERNAID_FLEET_RESIDENT_UPDATE_V1 status=already-staged release={} sequence={} target={:?} activation=not-armed",
            receipt.release_id(),
            receipt.sequence(),
            receipt.target_slot()
        ),
    }
}
