//! Linux production adapter: Secret Service identity, HTTPS and service loop.

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt as _;
use kernaid_fleet_client::{AssetArchitecture, AssetHealth, AssetPlatform, FindingCounts};
use kernaid_fleet_coordinator::FleetCoordinatorConfig;
use kernaid_native_secrets::NativeDeviceIdentityStore;
use rand_core::{OsRng, RngCore};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName},
    redirect::Policy,
};
use rustix::{
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags},
    process,
};
use sha2::{Digest, Sha256};
use std::{
    env,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

const RECEIPT_HEADER: HeaderName = HeaderName::from_static("x-kernaid-fleet-receipt");
const MAX_RECEIPT_HEADER_BYTES: usize = 8 * 1024;
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_ENROLLMENT_TOKEN_BYTES: usize = 512;
const MAX_MACHINE_ID_BYTES: usize = 256;
const MAX_OS_RELEASE_BYTES: usize = 16 * 1024;
const LOCK_FILE: &str = ".resident-fleet-sync-v1.lock";
const RUNTIME_DB: &str = "runtime-v1.sqlite3";
const COORDINATOR_DB: &str = "coordinator-v1.sqlite3";

pub struct HttpsFleetTransport {
    client: Client,
    base: Url,
    origin: String,
}

impl HttpsFleetTransport {
    pub fn new(
        endpoint: &str,
        connect_timeout_seconds: u64,
        request_timeout_seconds: u64,
    ) -> Result<Self, ResidentSyncError> {
        let mut base = Url::parse(endpoint)
            .map_err(|_| ResidentSyncError::Transport(TransportErrorCode::InvalidEndpoint))?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(base.path(), "" | "/")
        {
            return Err(ResidentSyncError::Transport(
                TransportErrorCode::InvalidEndpoint,
            ));
        }
        base.set_path("/");
        let origin = base.origin().ascii_serialization();
        if !valid_https_origin(&origin) {
            return Err(ResidentSyncError::Transport(
                TransportErrorCode::InvalidEndpoint,
            ));
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(connect_timeout_seconds))
            .timeout(Duration::from_secs(request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Resident/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(map_request_error)?;
        Ok(Self {
            client,
            base,
            origin,
        })
    }
}

impl FleetTransport for HttpsFleetTransport {
    fn origin(&self) -> &str {
        &self.origin
    }

    fn post(
        &mut self,
        route: FleetRoute,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<FleetTransportResponse, TransportErrorCode> {
        if route.path().is_empty() || body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(TransportErrorCode::Protocol);
        }
        let url = self
            .base
            .join(route.path().trim_start_matches('/'))
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
        read_response(response, max_response_bytes)
    }
}

pub struct SystemObservationSource;

impl ResidentObservationSource for SystemObservationSource {
    fn now(&mut self) -> Result<ObservationTime, ResidentSyncError> {
        let now = Utc::now();
        let unix_seconds =
            u64::try_from(now.timestamp()).map_err(|_| ResidentSyncError::ClockUnavailable)?;
        Ok(ObservationTime {
            rfc3339: now.to_rfc3339_opts(SecondsFormat::Secs, true),
            unix_seconds,
        })
    }

    fn nonce(&mut self) -> Result<Vec<u8>, ResidentSyncError> {
        let mut nonce = vec![0_u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ResidentSyncError::NonceUnavailable)?;
        Ok(nonce)
    }

    fn inventory(
        &mut self,
        _identity: &DeviceIdentity,
    ) -> Result<InventoryAsset, ResidentSyncError> {
        let machine_id =
            read_system_public_bounded(Path::new("/etc/machine-id"), MAX_MACHINE_ID_BYTES)?;
        let machine_id =
            trim_ascii_line(&machine_id).ok_or(ResidentSyncError::InventoryUnavailable)?;
        if machine_id.len() < 16
            || machine_id
                .iter()
                .any(|byte| !byte.is_ascii_hexdigit() && *byte != b'-')
        {
            return Err(ResidentSyncError::InventoryUnavailable);
        }
        let mut target_hasher = Sha256::new();
        target_hasher.update(b"kernaid:fleet:linux-resident-target:v1\0");
        target_hasher.update(machine_id);
        let target_fingerprint = hex_digest(&target_hasher.finalize());
        let os_release = linux_os_release()?;
        let architecture = match env::consts::ARCH {
            "x86_64" => AssetArchitecture::X86_64,
            "aarch64" => AssetArchitecture::Aarch64,
            _ => AssetArchitecture::Other,
        };
        let snapshot = serde_json::to_vec(&serde_json::json!({
            "architecture": match architecture {
                AssetArchitecture::X86_64 => "x86_64",
                AssetArchitecture::Aarch64 => "aarch64",
                AssetArchitecture::Other => "other",
            },
            "osRelease": os_release,
            "platform": "linux",
            "targetFingerprint": target_fingerprint
        }))
        .map_err(|_| ResidentSyncError::InventoryUnavailable)?;
        let snapshot_sha256 = hex_digest(&Sha256::digest(snapshot));
        Ok(InventoryAsset::new(
            "resident-self",
            target_fingerprint,
            AssetPlatform::Linux,
            architecture,
            Some(os_release),
            AssetHealth::Unknown,
            FindingCounts::new(0, 0, 0),
            snapshot_sha256,
        ))
    }
}

pub fn run_from_args() -> Result<(), ResidentSyncError> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(ResidentSyncError::InvalidConfig);
    }
    let config_path = arguments.next().ok_or(ResidentSyncError::InvalidConfig)?;
    let once = match arguments.next() {
        None => false,
        Some(value) if value == "--once" => true,
        Some(_) => return Err(ResidentSyncError::InvalidConfig),
    };
    if arguments.next().is_some() {
        return Err(ResidentSyncError::InvalidConfig);
    }
    let config_path = PathBuf::from(config_path);
    let config = load_config(&config_path)?;
    run_service(config, once)
}

pub fn run_service(config: ResidentSyncConfig, once: bool) -> Result<(), ResidentSyncError> {
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(LOCK_FILE))?;
    let service_anchor = read_public_anchor(&config.service_receipt_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let mut identity_store = NativeDeviceIdentityStore::open_named(RESIDENT_IDENTITY_NAMESPACE)
        .map_err(|_| ResidentSyncError::IdentityUnavailable)?;
    let identity = identity_store
        .load_device_identity()
        .map_err(|_| ResidentSyncError::IdentityUnavailable)?
        .ok_or(ResidentSyncError::IdentityUnavailable)?;
    let coordinator = FleetCoordinator::open(
        FleetCoordinatorConfig {
            coordinator_state_path: &config.state_directory.join(COORDINATOR_DB),
            runtime_state_path: &config.state_directory.join(RUNTIME_DB),
            tenant_id: &config.tenant_id,
            service_receipt_anchor: &service_anchor,
            entitlement_anchor: &entitlement_anchor,
            policy_anchor: &policy_anchor,
        },
        &identity,
    )?;
    let transport = HttpsFleetTransport::new(
        &config.endpoint,
        config.connect_timeout_seconds,
        config.request_timeout_seconds,
    )?;
    let mut engine = ResidentSyncEngine::new(
        coordinator,
        identity,
        transport,
        SystemObservationSource,
        &config.state_directory,
        &config.tenant_id,
        config.batch_limit,
        config.retry_delay_seconds,
    )?;

    loop {
        let token = read_optional_enrollment_token(&config.enrollment_token_file)?;
        engine.ensure_enrolled(token.as_deref().map(String::as_str))?;
        if token.is_some() {
            remove_consumed_token(&config.enrollment_token_file)?;
        }
        let summary = engine.run_cycle(None)?;
        println!(
            "KERNAID_FLEET_RESIDENT_SYNC_V1 status=ok inventory={} audit={} policy={} entitlement={}",
            summary.inventory_uploaded,
            summary.audit_uploaded,
            summary.policy_documents,
            summary.entitlement_documents
        );
        if once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(config.interval_seconds));
    }
}

fn read_response(
    response: Response,
    max_response_bytes: usize,
) -> Result<FleetTransportResponse, TransportErrorCode> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    let receipt = response
        .headers()
        .get(&RECEIPT_HEADER)
        .map(decode_receipt_header)
        .transpose()?;
    let status = response.status().as_u16();
    let limit = u64::try_from(max_response_bytes)
        .map_err(|_| TransportErrorCode::ResponseTooLarge)?
        .saturating_add(1);
    let mut body = Vec::new();
    response
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|_| TransportErrorCode::Protocol)?;
    if body.len() > max_response_bytes {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    Ok(FleetTransportResponse {
        status,
        body,
        receipt,
    })
}

fn decode_receipt_header(
    value: &reqwest::header::HeaderValue,
) -> Result<Vec<u8>, TransportErrorCode> {
    let encoded = value.to_str().map_err(|_| TransportErrorCode::Protocol)?;
    if encoded.is_empty() || encoded.len() > MAX_RECEIPT_HEADER_BYTES * 2 {
        return Err(TransportErrorCode::Protocol);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TransportErrorCode::Protocol)?;
    if decoded.len() > MAX_RECEIPT_HEADER_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(TransportErrorCode::Protocol);
    }
    Ok(decoded)
}

fn map_request_error(_error: reqwest::Error) -> ResidentSyncError {
    ResidentSyncError::Transport(TransportErrorCode::Protocol)
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

fn load_config(path: &Path) -> Result<ResidentSyncConfig, ResidentSyncError> {
    let bytes = read_public_bounded(path, MAX_CONFIG_BYTES)?;
    ResidentSyncConfig::parse(&bytes)
}

fn read_public_anchor(path: &Path) -> Result<[u8; 32], ResidentSyncError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let encoded =
        std::str::from_utf8(trim_ascii_line(&bytes).ok_or(ResidentSyncError::InvalidConfig)?)
            .map_err(|_| ResidentSyncError::InvalidConfig)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ResidentSyncError::InvalidConfig)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ResidentSyncError::InvalidConfig);
    }
    decoded
        .try_into()
        .map_err(|_| ResidentSyncError::InvalidConfig)
}

fn read_public_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ResidentSyncError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > limit as u64
    {
        return Err(ResidentSyncError::InvalidConfig);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > limit || bytes.len() as u64 != metadata.len() {
        return Err(ResidentSyncError::InvalidConfig);
    }
    Ok(bytes)
}

fn read_optional_enrollment_token(
    path: &Path,
) -> Result<Option<Zeroizing<String>>, ResidentSyncError> {
    let bytes = match read_private_bounded(path, MAX_ENROLLMENT_TOKEN_BYTES) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(ResidentSyncError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let token = trim_ascii_line(&bytes).ok_or(ResidentSyncError::InvalidConfig)?;
    if token.is_empty()
        || token.len() > MAX_ENROLLMENT_TOKEN_BYTES
        || token
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || byte.is_ascii_whitespace())
    {
        return Err(ResidentSyncError::InvalidConfig);
    }
    let token = String::from_utf8(token.to_vec()).map_err(|_| ResidentSyncError::InvalidConfig)?;
    Ok(Some(Zeroizing::new(token)))
}

fn remove_consumed_token(path: &Path) -> Result<(), ResidentSyncError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(ResidentSyncError::InvalidState),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), ResidentSyncError> {
    if !path.is_absolute() {
        return Err(ResidentSyncError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(ResidentSyncError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process::getuid().as_raw()
    {
        return Err(ResidentSyncError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o7777 != 0o700 {
        return Err(ResidentSyncError::InvalidState);
    }
    Ok(())
}

fn open_service_lock(path: &Path) -> Result<File, ResidentSyncError> {
    let fd = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ResidentSyncError::InvalidState)?;
    let descriptor = rfs::fstat(&fd).map_err(|_| ResidentSyncError::InvalidState)?;
    let named = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResidentSyncError::InvalidState)?;
    if !FileType::from_raw_mode(descriptor.st_mode).is_file()
        || !FileType::from_raw_mode(named.st_mode).is_file()
        || descriptor.st_dev != named.st_dev
        || descriptor.st_ino != named.st_ino
        || descriptor.st_nlink != 1
        || descriptor.st_uid != process::getuid().as_raw()
    {
        return Err(ResidentSyncError::InvalidState);
    }
    rfs::fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|_| ResidentSyncError::InvalidState)?;
    let file = File::from(fd);
    file.try_lock_exclusive()
        .map_err(|_| ResidentSyncError::InvalidState)?;
    Ok(file)
}

fn linux_os_release() -> Result<String, ResidentSyncError> {
    let etc_path = Path::new("/etc/os-release");
    let metadata = fs::symlink_metadata(etc_path)?;
    let release_path = if metadata.file_type().is_symlink() {
        let target = fs::read_link(etc_path)?;
        if target != Path::new("../usr/lib/os-release")
            && target != Path::new("/usr/lib/os-release")
        {
            return Err(ResidentSyncError::InventoryUnavailable);
        }
        Path::new("/usr/lib/os-release")
    } else {
        etc_path
    };
    let bytes = read_system_public_bounded(release_path, MAX_OS_RELEASE_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ResidentSyncError::InventoryUnavailable)?;
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"'))
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(ResidentSyncError::InventoryUnavailable)?;
    if value.chars().any(char::is_control) {
        return Err(ResidentSyncError::InventoryUnavailable);
    }
    Ok(value.to_owned())
}

fn read_system_public_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ResidentSyncError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > limit as u64
    {
        return Err(ResidentSyncError::InventoryUnavailable);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > limit || bytes.len() as u64 != metadata.len() {
        return Err(ResidentSyncError::InventoryUnavailable);
    }
    Ok(bytes)
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

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
