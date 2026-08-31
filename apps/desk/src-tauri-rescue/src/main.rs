#![forbid(unsafe_code)]

use nix::{
    libc,
    sys::socket::{SockType, getsockopt, sockopt},
    unistd::{Group, User, getegid, geteuid, getgid, getgroups, getuid},
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{
    RunEvent, Url, WebviewUrl,
    webview::{NewWindowResponse, WebviewWindowBuilder},
};

const RESCUE_UI_URL: &str = "http://127.0.0.1:4173/";
const STARTUP_DEADLINE: Duration = Duration::from_secs(90);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_PROBE_RESPONSE_BYTES: usize = 16 * 1024;
const X11_SOCKET_PATH: &str = "/tmp/.X11-unix/X0";
const UI_ACCOUNT: &str = "kernaid-rescue-ui";
const UI_HOME: &str = "/run/kernaid-rescue-ui-session/home";
const UI_SHELL: &str = "/usr/sbin/nologin";
const UI_XAUTHORITY: &str = "/run/lightdm/kernaid-rescue-ui/xauthority";
const FAKE_SESSION_BUS: &str = "unix:path=/run/kernaid-rescue-desk-shell/no-session-bus";
const FAKE_SYSTEM_BUS: &str = "unix:path=/run/kernaid-rescue-desk-shell/no-system-bus";
const SANDBOX_STATUS_QEMU: &str = "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied http=loopback x11=connected privileged-fs-sockets=absent nonloopback=denied";
const SANDBOX_STATUS_NORMAL: &str = "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied http=loopback x11=connected privileged-fs-sockets=absent nonloopback=systemd-policy";
const SANDBOX_STATUS_QEMU_NATIVE_PROMPT: &str = "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied http=loopback x11=connected privileged-fs-sockets=native-prompt-vt nonloopback=denied";
const SANDBOX_STATUS_NORMAL_NATIVE_PROMPT: &str = "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied http=loopback x11=connected privileged-fs-sockets=native-prompt-vt nonloopback=systemd-policy";
const WINDOW_STARTUP_STATUS: &str = "KERNAID_RESCUE_TAURI_STARTUP_V1 stage=window";
const QEMU_BASELINE_MARKER_PATH: &str = "/run/kernaid-tauri-network-probe/baseline-v1";
const QEMU_BASELINE_MARKER: &[u8] = b"KERNAID_RESCUE_TAURI_NETWORK_BASELINE_V1 connected=true\n";
const QEMU_NON_LOOPBACK_ADDRESS: [u8; 4] = [192, 0, 2, 1];
const QEMU_NON_LOOPBACK_PORT: u16 = 41_917;
const NATIVE_PROMPT_API_VERSION: &str = "kernaid.dev/rescue-native-prompt/v1alpha1";
const NATIVE_PROMPT_SOCKET_PATH: &str = "/run/kernaid-rescue-native-prompt.sock";
const NATIVE_PROMPT_MAX_FRAME_BYTES: usize = 512;
const NATIVE_PROMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SandboxProbeFailure {
    Http,
    X11,
    HttpAndX11,
    OfflineInspector,
    Vault,
    OpenAiExecutor,
    OpenAiEgress,
    Codex,
    NativePrompt,
    ProbeMode,
    Baseline,
    NonLoopback,
    Identity,
    PidNamespace,
    SessionBus,
    SystemBus,
    WindowStartup,
}

impl SandboxProbeFailure {
    fn status(self) -> &'static str {
        match self {
            Self::Http => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=http",
            Self::X11 => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=x11",
            Self::HttpAndX11 => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=http-x11",
            Self::OfflineInspector => {
                "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-offline-inspector"
            }
            Self::Vault => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-vault",
            Self::OpenAiExecutor => {
                "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-openai-executor"
            }
            Self::OpenAiEgress => {
                "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-openai-egress"
            }
            Self::Codex => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-codex",
            Self::NativePrompt => {
                "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=socket-native-prompt"
            }
            Self::ProbeMode => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=probe-mode",
            Self::Baseline => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=baseline",
            Self::NonLoopback => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=nonloopback",
            Self::Identity => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=identity",
            Self::PidNamespace => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=pidns",
            Self::SessionBus => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=session-bus",
            Self::SystemBus => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=system-bus",
            Self::WindowStartup => "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=window-startup",
        }
    }
}

const PRIVILEGED_SOCKETS: [(&str, SandboxProbeFailure); 6] = [
    (
        "/run/kernaid-offline-inspector.sock",
        SandboxProbeFailure::OfflineInspector,
    ),
    ("/run/kernaid-rescue-vault.sock", SandboxProbeFailure::Vault),
    (
        "/run/kernaid-rescue-openai.sock",
        SandboxProbeFailure::OpenAiExecutor,
    ),
    (
        "/run/kernaid-rescue-openai-egress.sock",
        SandboxProbeFailure::OpenAiEgress,
    ),
    ("/run/kernaid-rescue-codex.sock", SandboxProbeFailure::Codex),
    (
        "/run/dbus/system_bus_socket",
        SandboxProbeFailure::SystemBus,
    ),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NativePromptKind {
    VaultUnlock,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum NativePromptOperation {
    #[serde(rename = "prompt.open-or-focus")]
    OpenOrFocus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePromptRequest {
    api_version: String,
    request_id: String,
    operation: NativePromptOperation,
    kind: NativePromptKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NativePromptOutcome {
    Opened,
    Focused,
    Busy,
    Unavailable,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NativePromptAvailability {
    Available,
    Unavailable,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NativePromptState {
    Idle,
    Active,
    Unavailable,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePromptResponse {
    api_version: String,
    request_id: String,
    outcome: NativePromptOutcome,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePromptStatus {
    api_version: String,
    kind: NativePromptKind,
    availability: NativePromptAvailability,
    prompt_state: NativePromptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePromptTransportError {
    Unavailable,
    Failed,
}

fn valid_native_prompt_request_id(value: &str) -> bool {
    if value.len() != 38 || !value.starts_with("N-") {
        return false;
    }
    value.as_bytes().iter().enumerate().all(|(index, byte)| {
        if matches!(index, 10 | 15 | 20 | 25) {
            *byte == b'-'
        } else if index < 2 {
            true
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        }
    })
}

fn native_prompt_socket_metadata() -> Result<(), NativePromptTransportError> {
    let metadata = fs::symlink_metadata(NATIVE_PROMPT_SOCKET_PATH).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            NativePromptTransportError::Unavailable
        } else {
            NativePromptTransportError::Failed
        }
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != getgid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o660
    {
        return Err(NativePromptTransportError::Failed);
    }
    Ok(())
}

fn connect_native_prompt() -> Result<UnixStream, NativePromptTransportError> {
    native_prompt_socket_metadata()?;
    let stream = UnixStream::connect(NATIVE_PROMPT_SOCKET_PATH).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ) {
            NativePromptTransportError::Unavailable
        } else {
            NativePromptTransportError::Failed
        }
    })?;
    stream
        .set_read_timeout(Some(NATIVE_PROMPT_TIMEOUT))
        .map_err(|_| NativePromptTransportError::Failed)?;
    stream
        .set_write_timeout(Some(NATIVE_PROMPT_TIMEOUT))
        .map_err(|_| NativePromptTransportError::Failed)?;
    let socket_type =
        getsockopt(&stream, sockopt::SockType).map_err(|_| NativePromptTransportError::Failed)?;
    let peer = getsockopt(&stream, sockopt::PeerCredentials)
        .map_err(|_| NativePromptTransportError::Failed)?;
    // This shell runs in a descendant PID namespace. The root systemd socket
    // peer lives in an ancestor namespace, so Linux intentionally translates
    // its PID to zero here. The pinned root-owned socket inode plus root peer
    // credentials authenticate the server side; the broker independently
    // pins and authenticates this client with SO_PEERPIDFD in the ancestor
    // namespace before accepting either operation.
    if socket_type != SockType::Stream || peer.uid() != 0 || peer.gid() != 0 {
        return Err(NativePromptTransportError::Failed);
    }
    Ok(stream)
}

fn read_native_prompt_frame(
    stream: &mut UnixStream,
) -> Result<Vec<u8>, NativePromptTransportError> {
    let mut response = Vec::with_capacity(192);
    stream
        .take(NATIVE_PROMPT_MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .map_err(|_| NativePromptTransportError::Failed)?;
    if response.is_empty() || response.len() > NATIVE_PROMPT_MAX_FRAME_BYTES {
        return Err(NativePromptTransportError::Failed);
    }
    Ok(response)
}

fn relay_native_prompt(
    request: &NativePromptRequest,
) -> Result<NativePromptResponse, NativePromptTransportError> {
    let mut stream = connect_native_prompt()?;
    let encoded = serde_json::to_vec(request).map_err(|_| NativePromptTransportError::Failed)?;
    if encoded.len() > NATIVE_PROMPT_MAX_FRAME_BYTES {
        return Err(NativePromptTransportError::Failed);
    }
    stream
        .write_all(&encoded)
        .map_err(|_| NativePromptTransportError::Failed)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| NativePromptTransportError::Failed)?;
    let response = read_native_prompt_frame(&mut stream)?;
    let response: NativePromptResponse =
        serde_json::from_slice(&response).map_err(|_| NativePromptTransportError::Failed)?;
    if response.api_version != NATIVE_PROMPT_API_VERSION
        || response.request_id != request.request_id
    {
        return Err(NativePromptTransportError::Failed);
    }
    Ok(response)
}

fn relay_native_prompt_status() -> Result<NativePromptStatus, NativePromptTransportError> {
    let mut stream = connect_native_prompt()?;
    // An authenticated empty frame is the broker's fixed, read-only status
    // query. No WebView value or operation crosses this connection.
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| NativePromptTransportError::Failed)?;
    let response = read_native_prompt_frame(&mut stream)?;
    let response: NativePromptStatus =
        serde_json::from_slice(&response).map_err(|_| NativePromptTransportError::Failed)?;
    if response.api_version != NATIVE_PROMPT_API_VERSION
        || response.kind != NativePromptKind::VaultUnlock
        || response.availability != NativePromptAvailability::Available
        || !matches!(
            response.prompt_state,
            NativePromptState::Idle | NativePromptState::Active
        )
    {
        return Err(NativePromptTransportError::Failed);
    }
    Ok(response)
}

fn bootstrap_native_prompt_transport<F>(
    sandbox_status: &str,
    relay: F,
) -> Result<(), SandboxProbeFailure>
where
    F: FnOnce() -> Result<NativePromptStatus, NativePromptTransportError>,
{
    match sandbox_status {
        SANDBOX_STATUS_QEMU_NATIVE_PROMPT | SANDBOX_STATUS_NORMAL_NATIVE_PROMPT => relay()
            .map(|_| ())
            .map_err(|_| SandboxProbeFailure::NativePrompt),
        SANDBOX_STATUS_QEMU | SANDBOX_STATUS_NORMAL => Ok(()),
        _ => Err(SandboxProbeFailure::ProbeMode),
    }
}

#[tauri::command]
fn rescue_native_prompt_status() -> NativePromptStatus {
    match relay_native_prompt_status() {
        Ok(status) => status,
        Err(NativePromptTransportError::Unavailable) => NativePromptStatus {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            kind: NativePromptKind::VaultUnlock,
            availability: NativePromptAvailability::Unavailable,
            prompt_state: NativePromptState::Unavailable,
        },
        Err(NativePromptTransportError::Failed) => NativePromptStatus {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            kind: NativePromptKind::VaultUnlock,
            availability: NativePromptAvailability::Failed,
            prompt_state: NativePromptState::Failed,
        },
    }
}

#[tauri::command]
fn open_rescue_native_prompt(
    request: NativePromptRequest,
) -> Result<NativePromptResponse, &'static str> {
    if request.api_version != NATIVE_PROMPT_API_VERSION
        || request.operation != NativePromptOperation::OpenOrFocus
        || request.kind != NativePromptKind::VaultUnlock
        || !valid_native_prompt_request_id(&request.request_id)
    {
        return Err("invalid-request");
    }
    match relay_native_prompt(&request) {
        Ok(response) => Ok(response),
        Err(NativePromptTransportError::Unavailable) => Ok(NativePromptResponse {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            request_id: request.request_id,
            outcome: NativePromptOutcome::Unavailable,
        }),
        Err(NativePromptTransportError::Failed) => Ok(NativePromptResponse {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            request_id: request.request_id,
            outcome: NativePromptOutcome::Failed,
        }),
    }
}

fn allowed_rescue_navigation(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(4173)
        && url.username().is_empty()
        && url.password().is_none()
}

fn valid_rescue_ui_response(response: &[u8]) -> bool {
    if response.is_empty() || response.len() > MAX_PROBE_RESPONSE_BYTES {
        return false;
    }
    let Ok(response) = std::str::from_utf8(response) else {
        return false;
    };
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    let mut lines = headers.lines();
    if !matches!(lines.next(), Some("HTTP/1.0 200 OK" | "HTTP/1.1 200 OK")) {
        return false;
    }
    let headers: Vec<&str> = lines.collect();
    let header_value = |expected_name: &str| {
        headers.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim_ascii())
        })
    };
    header_value("Content-Security-Policy")
        .is_some_and(|value| value.starts_with("default-src 'none';"))
        && header_value("Content-Type") == Some("text/html")
        && header_value("X-Frame-Options") == Some("DENY")
        && header_value("X-Content-Type-Options") == Some("nosniff")
        && body.contains("<script type=\"module\"")
        && body.contains("./assets/")
        && body.contains("<div id=\"root\"></div>")
}

fn rescue_ui_ready_once() -> bool {
    let rescue_ui_address = SocketAddr::from(([127, 0, 0, 1], 4173));
    let Ok(mut stream) = TcpStream::connect_timeout(&rescue_ui_address, PROBE_TIMEOUT) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream
            .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1:4173\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) if response.len() + length <= MAX_PROBE_RESPONSE_BYTES => {
                response.extend_from_slice(&chunk[..length]);
            }
            Ok(_) | Err(_) => return false,
        }
    }
    valid_rescue_ui_response(&response)
}

fn rescue_x11_ready_once() -> bool {
    UnixStream::connect(X11_SOCKET_PATH).is_ok()
}

fn wait_for_rescue_channels() -> Result<(), SandboxProbeFailure> {
    let started = Instant::now();
    let mut http_ready = false;
    let mut x11_ready = false;
    while started.elapsed() < STARTUP_DEADLINE {
        http_ready = http_ready || rescue_ui_ready_once();
        x11_ready = x11_ready || rescue_x11_ready_once();
        if http_ready && x11_ready {
            return Ok(());
        }
        thread::sleep(PROBE_INTERVAL);
    }
    Err(match (http_ready, x11_ready) {
        (false, false) => SandboxProbeFailure::HttpAndX11,
        (false, true) => SandboxProbeFailure::Http,
        (true, false) => SandboxProbeFailure::X11,
        (true, true) => unreachable!("both channels return before the deadline"),
    })
}

fn privileged_socket_absent(root_alias: &str, path: &str) -> bool {
    let candidate = format!("{root_alias}{path}");
    matches!(
        fs::symlink_metadata(candidate),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    )
}

fn privileged_sockets_absent() -> Result<(), SandboxProbeFailure> {
    // PrivatePIDs makes this process PID 1 and hides every host process.  Probe
    // both proc-root aliases as well as the direct paths so a future mount
    // namespace change cannot silently reintroduce the same-UID /proc escape.
    for (path, failure) in PRIVILEGED_SOCKETS {
        for root_alias in ["", "/proc/1/root", "/proc/self/root"] {
            if !privileged_socket_absent(root_alias, path) {
                return Err(failure);
            }
        }
    }
    Ok(())
}

fn native_prompt_socket_present() -> Result<bool, SandboxProbeFailure> {
    let mut identity: Option<(u64, u64)> = None;
    let mut observed_presence: Option<bool> = None;
    for root_alias in ["", "/proc/1/root", "/proc/self/root"] {
        let candidate = format!("{root_alias}{NATIVE_PROMPT_SOCKET_PATH}");
        match fs::symlink_metadata(candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if observed_presence == Some(true) {
                    return Err(SandboxProbeFailure::NativePrompt);
                }
                observed_presence = Some(false);
            }
            Err(_) => return Err(SandboxProbeFailure::NativePrompt),
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != 0
                    || metadata.gid() != getgid().as_raw()
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o7777 != 0o660
                {
                    return Err(SandboxProbeFailure::NativePrompt);
                }
                let observed = (metadata.dev(), metadata.ino());
                if observed_presence == Some(false)
                    || identity.is_some_and(|expected| expected != observed)
                {
                    return Err(SandboxProbeFailure::NativePrompt);
                }
                identity = Some(observed);
                observed_presence = Some(true);
            }
        }
    }
    Ok(observed_presence == Some(true))
}

fn denied_non_loopback_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied | io::ErrorKind::TimedOut
    )
}

fn non_loopback_denied() -> bool {
    let address = SocketAddr::from((QEMU_NON_LOOPBACK_ADDRESS, QEMU_NON_LOOPBACK_PORT));
    match TcpStream::connect_timeout(&address, PROBE_TIMEOUT) {
        Ok(_) => false,
        Err(error) => denied_non_loopback_error(error.kind()),
    }
}

fn bounded_fixed_file(
    path: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected: &[u8],
) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != expected_mode
        || (metadata.len() != 0 && metadata.len() != expected.len() as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixed marker identity was unsafe",
        ));
    }
    let mut payload = vec![0_u8; expected.len() + 1];
    let length = file.read(&mut payload)?;
    if &payload[..length] != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed marker content was invalid",
        ));
    }
    Ok(())
}

fn qemu_probe_mode() -> Result<bool, SandboxProbeFailure> {
    match fs::symlink_metadata(QEMU_BASELINE_MARKER_PATH) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SandboxProbeFailure::ProbeMode),
        Ok(_) => qemu_baseline_ready()
            .then_some(true)
            .ok_or(SandboxProbeFailure::ProbeMode),
    }
}

fn qemu_baseline_ready() -> bool {
    bounded_fixed_file(QEMU_BASELINE_MARKER_PATH, 0, 0, 0o444, QEMU_BASELINE_MARKER).is_ok()
}

fn isolated_identity_ready() -> bool {
    let uid = getuid();
    let gid = getgid();
    if uid != geteuid() || gid != getegid() || uid.is_root() || uid.as_raw() == 1000 {
        return false;
    }
    let Ok(Some(user)) = User::from_uid(uid) else {
        return false;
    };
    let Ok(Some(group)) = Group::from_gid(gid) else {
        return false;
    };
    if user.name != UI_ACCOUNT
        || group.name != UI_ACCOUNT
        || user.gid != gid
        || user.dir != Path::new(UI_HOME)
        || user.shell != Path::new(UI_SHELL)
    {
        return false;
    }
    let Ok(groups) = getgroups() else {
        return false;
    };
    if groups.iter().any(|supplementary| *supplementary != gid) {
        return false;
    }
    if env::var_os("DISPLAY").as_deref() != Some(OsStr::new(":0"))
        || env::var_os("XAUTHORITY").as_deref() != Some(OsStr::new(UI_XAUTHORITY))
        || env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref() != Some(OsStr::new(FAKE_SESSION_BUS))
        || env::var_os("DBUS_SYSTEM_BUS_ADDRESS").as_deref() != Some(OsStr::new(FAKE_SYSTEM_BUS))
    {
        return false;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(UI_XAUTHORITY)
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    metadata.is_file()
        && metadata.uid() == uid.as_raw()
        && metadata.gid() == gid.as_raw()
        && metadata.nlink() == 1
        && metadata.mode() & 0o7777 == 0o600
        && (1..=64 * 1024).contains(&metadata.len())
}

fn private_pid_namespace_ready() -> bool {
    if std::process::id() != 1 {
        return false;
    }
    let Ok(status) = fs::read("/proc/self/status") else {
        return false;
    };
    if status.len() > 64 * 1024 {
        return false;
    }
    let nspid = status
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(b"NSpid:"));
    if nspid.map(|line| {
        line.split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>()
    }) != Some(vec![b"NSpid:".as_slice(), b"1".as_slice()])
    {
        return false;
    }
    let Ok(executable) = fs::read_link("/proc/1/exe") else {
        return false;
    };
    if executable != Path::new("/usr/bin/kernaid-rescue-desk-shell") {
        return false;
    }
    let Ok(processes) = fs::read_dir("/proc") else {
        return false;
    };
    processes
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit())
        })
        .count()
        == 1
}

fn user_runtime_absent() -> bool {
    let runtime = format!("/run/user/{}", getuid().as_raw());
    ["", "/proc/1/root", "/proc/self/root"]
        .iter()
        .all(|root_alias| {
            let path = format!("{root_alias}{runtime}");
            matches!(
                fs::symlink_metadata(path),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
        })
}

fn attest_rescue_sandbox() -> Result<&'static str, SandboxProbeFailure> {
    if !isolated_identity_ready() {
        return Err(SandboxProbeFailure::Identity);
    }
    if !private_pid_namespace_ready() {
        return Err(SandboxProbeFailure::PidNamespace);
    }
    if !user_runtime_absent() {
        return Err(SandboxProbeFailure::SessionBus);
    }
    wait_for_rescue_channels()?;
    privileged_sockets_absent()?;
    let native_prompt = native_prompt_socket_present()?;
    let qemu_probe = qemu_probe_mode()?;
    if qemu_probe {
        if !qemu_baseline_ready() {
            return Err(SandboxProbeFailure::Baseline);
        }
        if !non_loopback_denied() {
            return Err(SandboxProbeFailure::NonLoopback);
        }
    }
    Ok(match (qemu_probe, native_prompt) {
        (true, false) => SANDBOX_STATUS_QEMU,
        (false, false) => SANDBOX_STATUS_NORMAL,
        (true, true) => SANDBOX_STATUS_QEMU_NATIVE_PROMPT,
        (false, true) => SANDBOX_STATUS_NORMAL_NATIVE_PROMPT,
    })
}

// The QEMU canary is deliberately reachable before this service enters its
// cgroup. A timeout is therefore a negative result from systemd's IP filter,
// not an absent route. Normal boots have no canary and rely on the exact,
// statically verified IPAddressDeny/Allow policy in the unit.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let status = attest_rescue_sandbox().map_err(|failure| {
        let failure_status = failure.status();
        eprintln!("{failure_status}");
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Rescue shell sandbox probe failed",
        )
    })?;
    bootstrap_native_prompt_transport(status, relay_native_prompt_status).map_err(|failure| {
        let failure_status = failure.status();
        eprintln!("{failure_status}");
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Rescue native prompt transport probe failed",
        )
    })?;
    let rescue_url: Url = RESCUE_UI_URL.parse()?;
    // These fixed console lines are diagnostic only. The root-owned checker is
    // the single readiness authority and independently re-attests the process,
    // renderer, window, display, sandbox and live endpoint.
    eprintln!("{status}");
    eprintln!("{WINDOW_STARTUP_STATUS}");
    let window_created = Arc::new(AtomicBool::new(false));
    let setup_window_created = Arc::clone(&window_created);
    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            rescue_native_prompt_status,
            open_rescue_native_prompt
        ])
        .setup(move |app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(rescue_url))
                .title("KernAid Rescue")
                .fullscreen(true)
                .decorations(false)
                .focused(true)
                .incognito(true)
                .devtools(false)
                .zoom_hotkeys_enabled(false)
                .disable_drag_drop_handler()
                .on_navigation(allowed_rescue_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()
                .inspect_err(|_| {
                    let failure_status = SandboxProbeFailure::WindowStartup.status();
                    eprintln!("{failure_status}");
                })?;
            setup_window_created.store(true, Ordering::Release);
            Ok(())
        })
        // The exact loopback origin receives only the closed native-prompt
        // command above. It cannot dispatch Resident, shell or plugin commands.
        .build(tauri::generate_context!())?;
    app.run(move |_, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            if !window_created.load(Ordering::Acquire) {
                // An empty initial config must not win the race against setup().
                // Once setup has built the secured window, a later close is
                // allowed to exit so systemd can restart the full shell.
                api.prevent_exit();
            }
        }
    });
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("KernAid Rescue shell failed closed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "custom-protocol")]
    #[test]
    fn shipping_loopback_ui_is_not_classified_as_a_local_dev_origin() {
        assert!(!tauri::is_dev());
    }

    #[test]
    fn navigation_is_pinned_to_the_exact_loopback_origin() {
        for allowed in [
            "http://127.0.0.1:4173/",
            "http://127.0.0.1:4173/assets/index.js",
            "http://127.0.0.1:4173/api/inventory",
        ] {
            let url: Url = allowed.parse().expect("fixed URL");
            assert!(allowed_rescue_navigation(&url));
        }

        for denied in [
            "https://127.0.0.1:4173/",
            "http://localhost:4173/",
            "http://127.0.0.1:4174/",
            "http://127.0.0.1/",
            "http://user@127.0.0.1:4173/",
            "file:///opt/kernaid/desk/index.html",
            "https://example.invalid/",
        ] {
            let url: Url = denied.parse().expect("fixed URL");
            assert!(!allowed_rescue_navigation(&url));
        }
    }

    #[test]
    fn startup_probe_requires_the_bundle_and_security_headers() {
        let response = b"HTTP/1.0 200 OK\r\n\
Content-Security-Policy: default-src 'none'; script-src 'self'\r\n\
Content-Type: text/html\r\n\
X-Frame-Options: DENY\r\n\
X-Content-Type-Options: nosniff\r\n\
\r\n\
<script type=\"module\" src=\"./assets/index.js\"></script>\
<div id=\"root\"></div>";
        assert!(valid_rescue_ui_response(response));
        for invalid in [
            response
                .as_slice()
                .strip_prefix(b"HTTP/1.0 200 OK\r\n")
                .expect("fixed response has the status line"),
            response
                .as_slice()
                .strip_suffix(b"<div id=\"root\"></div>")
                .expect("fixed response has the root element"),
            &b"HTTP/1.0 200 OK\r\n\r\n<div id=\"root\"></div>"[..],
        ] {
            assert!(!valid_rescue_ui_response(invalid));
        }
        assert!(!valid_rescue_ui_response(&vec![
            b'x';
            MAX_PROBE_RESPONSE_BYTES + 1
        ]));
    }

    #[test]
    fn non_loopback_probe_rejects_absent_routes_and_listeners() {
        assert!(denied_non_loopback_error(io::ErrorKind::PermissionDenied));
        assert!(denied_non_loopback_error(io::ErrorKind::TimedOut));
        assert!(!denied_non_loopback_error(io::ErrorKind::ConnectionRefused));
        assert!(!denied_non_loopback_error(
            io::ErrorKind::NetworkUnreachable
        ));
    }

    #[test]
    fn sandbox_failure_statuses_are_fixed_and_path_free() {
        let failures = [
            SandboxProbeFailure::Http,
            SandboxProbeFailure::X11,
            SandboxProbeFailure::HttpAndX11,
            SandboxProbeFailure::OfflineInspector,
            SandboxProbeFailure::Vault,
            SandboxProbeFailure::OpenAiExecutor,
            SandboxProbeFailure::OpenAiEgress,
            SandboxProbeFailure::Codex,
            SandboxProbeFailure::NativePrompt,
            SandboxProbeFailure::ProbeMode,
            SandboxProbeFailure::Baseline,
            SandboxProbeFailure::NonLoopback,
            SandboxProbeFailure::Identity,
            SandboxProbeFailure::PidNamespace,
            SandboxProbeFailure::SessionBus,
            SandboxProbeFailure::SystemBus,
            SandboxProbeFailure::WindowStartup,
        ];
        for failure in failures {
            let status = failure.status();
            assert!(status.starts_with("KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage="));
            assert!(
                !status
                    .bytes()
                    .any(|byte| matches!(byte, b'/' | b'\n' | b'\r' | 0))
            );
        }
    }

    #[test]
    fn native_prompt_request_id_is_exact_and_lowercase() {
        assert!(valid_native_prompt_request_id(
            "N-01234567-89ab-cdef-0123-456789abcdef"
        ));
        for denied in [
            "01234567-89ab-cdef-0123-456789abcdef",
            "N-01234567-89AB-cdef-0123-456789abcdef",
            "N-01234567-89ab-cdef-0123-456789abcdeg",
            "N-01234567-89ab-cdef-0123-456789abcdef0",
        ] {
            assert!(!valid_native_prompt_request_id(denied));
        }
    }

    #[test]
    fn native_prompt_wire_grammar_has_no_free_form_field() {
        let request = NativePromptRequest {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            request_id: "N-01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            operation: NativePromptOperation::OpenOrFocus,
            kind: NativePromptKind::VaultUnlock,
        };
        assert_eq!(
            serde_json::to_string(&request).expect("serialize fixed request"),
            concat!(
                "{\"apiVersion\":\"kernaid.dev/rescue-native-prompt/v1alpha1\",",
                "\"requestId\":\"N-01234567-89ab-cdef-0123-456789abcdef\",",
                "\"operation\":\"prompt.open-or-focus\",\"kind\":\"vault-unlock\"}"
            )
        );
        assert!(
            serde_json::from_str::<NativePromptRequest>(
                r#"{"apiVersion":"kernaid.dev/rescue-native-prompt/v1alpha1","requestId":"N-01234567-89ab-cdef-0123-456789abcdef","operation":"prompt.open-or-focus","kind":"vault-unlock","path":"/dev/sda"}"#
            )
            .is_err()
        );
        let status = NativePromptStatus {
            api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
            kind: NativePromptKind::VaultUnlock,
            availability: NativePromptAvailability::Available,
            prompt_state: NativePromptState::Idle,
        };
        assert_eq!(
            serde_json::to_string(&status).expect("serialize fixed status"),
            concat!(
                "{\"apiVersion\":\"kernaid.dev/rescue-native-prompt/v1alpha1\",",
                "\"kind\":\"vault-unlock\",\"availability\":\"available\",",
                "\"promptState\":\"idle\"}"
            )
        );
    }

    #[test]
    fn native_prompt_transport_is_bootstrapped_only_for_gated_boots() {
        for sandbox_status in [SANDBOX_STATUS_QEMU, SANDBOX_STATUS_NORMAL] {
            let called = std::cell::Cell::new(false);
            assert_eq!(
                bootstrap_native_prompt_transport(sandbox_status, || {
                    called.set(true);
                    Err(NativePromptTransportError::Failed)
                }),
                Ok(())
            );
            assert!(!called.get());
        }

        for sandbox_status in [
            SANDBOX_STATUS_QEMU_NATIVE_PROMPT,
            SANDBOX_STATUS_NORMAL_NATIVE_PROMPT,
        ] {
            let called = std::cell::Cell::new(false);
            assert_eq!(
                bootstrap_native_prompt_transport(sandbox_status, || {
                    called.set(true);
                    Ok(NativePromptStatus {
                        api_version: NATIVE_PROMPT_API_VERSION.to_owned(),
                        kind: NativePromptKind::VaultUnlock,
                        availability: NativePromptAvailability::Available,
                        prompt_state: NativePromptState::Idle,
                    })
                }),
                Ok(())
            );
            assert!(called.get());
            assert_eq!(
                bootstrap_native_prompt_transport(sandbox_status, || {
                    Err(NativePromptTransportError::Failed)
                }),
                Err(SandboxProbeFailure::NativePrompt)
            );
        }

        assert_eq!(
            bootstrap_native_prompt_transport("invalid", || {
                Err(NativePromptTransportError::Failed)
            }),
            Err(SandboxProbeFailure::ProbeMode)
        );
    }
}
