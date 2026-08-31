#![forbid(unsafe_code)]

#[cfg(all(target_os = "linux", feature = "fixture-repair-lab"))]
mod fixture_repair_lab;
#[cfg(any(target_os = "macos", test))]
mod macos_resident;
mod resident_openai;
mod secure_runtime;
#[cfg(any(target_os = "windows", test))]
mod windows_resident;

#[cfg(all(target_os = "linux", feature = "fixture-repair-lab"))]
use fixture_repair_lab::FixtureRepairLab;
use kernaid_broker::{BrokerError, ObserveBroker};
use kernaid_protocol::BrokerRequest;
use resident_openai::{
    ResidentOpenAiRuntime, resident_openai_cancel, resident_openai_diagnose,
    resident_openai_logout, resident_openai_status,
};
use secure_runtime::{
    SecureRuntime, append_audit_record, initialize_device_identity, seal_signed_report,
    secure_runtime_status,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::{fs::DirBuilderExt, process::CommandExt};
#[cfg(unix)]
use std::process::Child;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU8;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{self, Read},
    path::PathBuf,
    process::{self, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

#[cfg(any(target_os = "linux", test))]
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "windows", test))]
const QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const QUALIFIED_MACOS_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_BROKER_SESSIONS: usize = 1_024;
const QUALIFIED_FIRST_LAUNCH_PROBE_FLAG: &str = "--qualified-first-launch-probe";
const QUALIFIED_FIRST_LAUNCH_OK: &str = "KERNAID_QUALIFIED_FIRST_LAUNCH_PROBE_OK_V1";
const QUALIFIED_FIRST_LAUNCH_FAILED: &str = "KERNAID_QUALIFIED_FIRST_LAUNCH_PROBE_FAILED_V1";
static QUALIFIED_FIRST_LAUNCH_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
const HARDWARE_COLLECTOR_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const HARDWARE_COLLECTOR_IDLE: u8 = 0;
#[cfg(target_os = "linux")]
const HARDWARE_COLLECTOR_RUNNING: u8 = 1;
#[cfg(target_os = "linux")]
const HARDWARE_COLLECTOR_POISONED: u8 = 2;
#[cfg(target_os = "linux")]
static HARDWARE_COLLECTOR_STATE: AtomicU8 = AtomicU8::new(HARDWARE_COLLECTOR_IDLE);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(unix)]
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    collector: &'static str,
    trust: &'static str,
    output: String,
    success: bool,
    truncated: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObserveRequest {
    session_id: String,
    plan_id: String,
    target_fingerprint: String,
    sequence: u64,
    action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeDiagnosticEvidence {
    id: String,
    collector: String,
    content: String,
}

#[derive(Default)]
struct ObserveBrokers(Mutex<HashMap<String, ObserveBroker>>);

#[derive(Default)]
struct BoundedRead {
    bytes: Vec<u8>,
    truncated: bool,
    failed: bool,
}

struct BoundedReader {
    receiver: Receiver<BoundedRead>,
    handle: JoinHandle<()>,
}

fn read_bounded(mut reader: impl Read + Send + 'static, maximum_bytes: usize) -> BoundedReader {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut retained = Vec::with_capacity(maximum_bytes);
        let mut buffer = [0_u8; 8 * 1024];
        let mut truncated = false;
        let mut failed = false;
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(read) => read,
            };
            let remaining = maximum_bytes.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(remaining)]);
            truncated |= read > remaining;
        }
        let _ = sender.send(BoundedRead {
            bytes: retained,
            truncated,
            failed,
        });
    });
    BoundedReader { receiver, handle }
}

fn received_output(reader: Option<&BoundedReader>) -> BoundedRead {
    match reader {
        Some(reader) => reader
            .receiver
            .recv_timeout(PIPE_DRAIN_TIMEOUT)
            .unwrap_or(BoundedRead {
                failed: true,
                ..BoundedRead::default()
            }),
        None => BoundedRead {
            failed: true,
            ..BoundedRead::default()
        },
    }
}

fn finish_reader(reader: Option<BoundedReader>) {
    if let Some(reader) = reader {
        let _ = reader.handle.join();
    }
}

trait ManagedChild {
    fn take_stdout(&mut self) -> Option<ChildStdout>;
    fn take_stderr(&mut self) -> Option<ChildStderr>;
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    fn terminate_tree(&mut self);
}

#[cfg(unix)]
impl ManagedChild for Child {
    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }

    fn terminate_tree(&mut self) {
        let process_group = rustix::process::Pid::from_child(self);
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::TERM);
        let deadline = Instant::now() + TERMINATION_GRACE;
        while Instant::now() < deadline {
            if matches!(Child::try_wait(self), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
        let _ = self.wait();
    }
}

#[cfg(target_os = "windows")]
struct WindowsJobChild(Box<dyn process_wrap::std::ChildWrapper>);

#[cfg(target_os = "windows")]
impl ManagedChild for WindowsJobChild {
    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.0.stdout().take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.0.stderr().take()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.0.try_wait()
    }

    fn terminate_tree(&mut self) {
        // JobObject::start_kill terminates every process in the job; kill then
        // waits for the job to drain so inherited stdout/stderr handles close.
        let _ = self.0.kill();
    }
}

#[cfg(unix)]
fn spawn_managed(mut command: Command) -> io::Result<Box<dyn ManagedChild>> {
    command.spawn().map(|child| Box::new(child) as _)
}

#[cfg(target_os = "windows")]
fn spawn_managed(command: Command) -> io::Result<Box<dyn ManagedChild>> {
    use process_wrap::std::{CommandWrap, JobObject};

    let mut wrapped = CommandWrap::from(command);
    wrapped.wrap(JobObject);
    wrapped
        .spawn()
        .map(|child| Box::new(WindowsJobChild(child)) as _)
}

#[cfg(target_os = "linux")]
fn fixed_command(collector: &'static str, program: &str, args: &[&str]) -> Observation {
    fixed_command_with_policy(collector, program, args, COMMAND_TIMEOUT, None)
}

struct FixedCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedCommandFailure {
    Unavailable,
    TimedOut,
    Truncated,
    ReadFailed,
    InvalidUtf8,
}

impl FixedCommandFailure {
    #[cfg(target_os = "linux")]
    const fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "collector unavailable: command failed",
            Self::TimedOut => "collector unavailable: command timed out",
            Self::Truncated => "collector unavailable: output exceeded the safety limit",
            Self::ReadFailed => "collector unavailable: output could not be read safely",
            Self::InvalidUtf8 => "collector unavailable: output is not valid UTF-8",
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const fn truncated(self) -> bool {
        matches!(self, Self::Truncated)
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacosCollectorFailureReason {
    CommandUnavailable,
    Timeout,
    Truncated,
    ReadFailed,
    InvalidUtf8,
    NonzeroExit,
    StderrNonempty,
    ProjectionInvalid,
    ThreadFailed,
}

#[cfg(any(target_os = "macos", test))]
impl MacosCollectorFailureReason {
    #[cfg(test)]
    const fn token(self) -> &'static str {
        match self {
            Self::CommandUnavailable => "command-unavailable",
            Self::Timeout => "timeout",
            Self::Truncated => "truncated",
            Self::ReadFailed => "read-failed",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::NonzeroExit => "nonzero-exit",
            Self::StderrNonempty => "stderr-nonempty",
            Self::ProjectionInvalid => "projection-invalid",
            Self::ThreadFailed => "thread-failed",
        }
    }
}

#[cfg(any(target_os = "macos", test))]
impl From<FixedCommandFailure> for MacosCollectorFailureReason {
    fn from(failure: FixedCommandFailure) -> Self {
        match failure {
            FixedCommandFailure::Unavailable => Self::CommandUnavailable,
            FixedCommandFailure::TimedOut => Self::Timeout,
            FixedCommandFailure::Truncated => Self::Truncated,
            FixedCommandFailure::ReadFailed => Self::ReadFailed,
            FixedCommandFailure::InvalidUtf8 => Self::InvalidUtf8,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
// Private collector state. Only the fixed token is exposed by the native test
// probe; the public observation schema and its fail-closed output stay intact.
enum MacosCollectorOutcome {
    Success(Observation),
    Failure {
        observation: Observation,
        #[cfg(test)]
        reason: MacosCollectorFailureReason,
    },
}

#[cfg(any(target_os = "macos", test))]
impl MacosCollectorOutcome {
    fn success(collector: &'static str, output: String) -> Self {
        Self::Success(Observation {
            collector,
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        })
    }

    fn failure(collector: &'static str, reason: MacosCollectorFailureReason) -> Self {
        Self::Failure {
            observation: failed_macos_observation(
                collector,
                reason == MacosCollectorFailureReason::Truncated,
            ),
            #[cfg(test)]
            reason,
        }
    }

    #[cfg(test)]
    fn observation(&self) -> &Observation {
        match self {
            Self::Success(observation) | Self::Failure { observation, .. } => observation,
        }
    }

    #[cfg(target_os = "macos")]
    fn into_observation(self) -> Observation {
        match self {
            Self::Success(observation) | Self::Failure { observation, .. } => observation,
        }
    }

    #[cfg(test)]
    fn probe_failure_label(&self) -> Option<String> {
        match self {
            Self::Success(_) => None,
            Self::Failure {
                observation,
                reason,
            } => Some(format!(
                "{}:reason={}:truncated={}",
                observation.collector,
                reason.token(),
                observation.truncated
            )),
        }
    }
}

fn run_fixed_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<FixedCommandOutput, FixedCommandFailure> {
    let mut command = Command::new(program);
    command.args(args).env_clear();
    #[cfg(unix)]
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .process_group(0);
    #[cfg(windows)]
    {
        command.current_dir(r"C:\Windows\System32");
        for (name, value) in windows_resident::WINDOWS_ENVIRONMENT {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_managed(command).map_err(|_| FixedCommandFailure::Unavailable)?;
    let stdout = child
        .take_stdout()
        .map(|reader| read_bounded(reader, maximum_output_bytes));
    let stderr = child
        .take_stderr()
        .map(|reader| read_bounded(reader, maximum_output_bytes));
    let deadline = Instant::now() + timeout;
    let (exit_status, timed_out, wait_failed) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                child.terminate_tree();
                break (None, true, false);
            }
            Err(_) => {
                child.terminate_tree();
                break (None, false, true);
            }
        }
    };
    let output = received_output(stdout.as_ref());
    let error_output = received_output(stderr.as_ref());
    if output.failed || error_output.failed {
        child.terminate_tree();
    }
    finish_reader(stdout);
    finish_reader(stderr);
    if wait_failed {
        return Err(FixedCommandFailure::Unavailable);
    }
    if output.failed || error_output.failed {
        return Err(FixedCommandFailure::ReadFailed);
    }
    if output.truncated || error_output.truncated {
        return Err(FixedCommandFailure::Truncated);
    }
    if timed_out {
        return Err(FixedCommandFailure::TimedOut);
    }
    let stdout = String::from_utf8(output.bytes).map_err(|_| FixedCommandFailure::InvalidUtf8)?;
    let stderr =
        String::from_utf8(error_output.bytes).map_err(|_| FixedCommandFailure::InvalidUtf8)?;
    let exit_code = exit_status
        .and_then(|status| status.code())
        .ok_or(FixedCommandFailure::Unavailable)?;
    Ok(FixedCommandOutput {
        stdout,
        stderr,
        exit_code,
    })
}

#[cfg(target_os = "linux")]
fn fixed_command_with_policy(
    collector: &'static str,
    program: &str,
    args: &[&str],
    timeout: Duration,
    empty_exit_one_output: Option<&'static str>,
) -> Observation {
    match run_fixed_command(program, args, timeout, DEFAULT_MAX_OUTPUT_BYTES) {
        Ok(output) => {
            let empty_no_match = output.exit_code == 1
                && output.stdout.is_empty()
                && output.stderr.is_empty()
                && empty_exit_one_output.is_some();
            let success = output.exit_code == 0 || empty_no_match;
            Observation {
                collector,
                trust: "observed-untrusted",
                output: if empty_no_match {
                    empty_exit_one_output.unwrap_or_default().to_owned()
                } else if success {
                    output.stdout
                } else {
                    "collector unavailable: command failed".to_owned()
                },
                success,
                truncated: false,
            }
        }
        Err(error) => Observation {
            collector,
            trust: "observed-untrusted",
            output: error.message().to_owned(),
            success: false,
            truncated: error.truncated(),
        },
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_fstab() -> Observation {
    let file = match rustix::fs::open(
        "/etc/fstab",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => File::from(descriptor),
        Err(_) => {
            return Observation {
                collector: "linux.fstab",
                trust: "observed-untrusted",
                output: "collector unavailable: fstab could not be opened safely".to_owned(),
                success: false,
                truncated: false,
            };
        }
    };
    let metadata = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            return Observation {
                collector: "linux.fstab",
                trust: "observed-untrusted",
                output: "collector unavailable: fstab is not a regular file".to_owned(),
                success: false,
                truncated: false,
            };
        }
    };
    if metadata.len() > DEFAULT_MAX_OUTPUT_BYTES as u64 {
        return Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output: "collector unavailable: output exceeded the safety limit".to_owned(),
            success: false,
            truncated: true,
        };
    }
    let reader = read_bounded(file, DEFAULT_MAX_OUTPUT_BYTES);
    let bounded = received_output(Some(&reader));
    finish_reader(Some(reader));
    if bounded.truncated || bounded.failed {
        return Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output: if bounded.truncated {
                "collector unavailable: output exceeded the safety limit".to_owned()
            } else {
                "collector unavailable: output could not be read safely".to_owned()
            },
            success: false,
            truncated: bounded.truncated,
        };
    }
    match kernaid_linux_pack::diagnostics::normalize_fstab_for_diagnostics(&bounded.bytes) {
        Ok(output) if output.len() <= DEFAULT_MAX_OUTPUT_BYTES => Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        },
        Ok(_) => Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output: "collector unavailable: normalized output exceeded the safety limit".to_owned(),
            success: false,
            truncated: true,
        },
        Err(_) => Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output: "collector unavailable: fstab is malformed".to_owned(),
            success: false,
            truncated: false,
        },
    }
}

#[cfg(target_os = "windows")]
fn failed_windows_observation(collector: &'static str, truncated: bool) -> Observation {
    Observation {
        collector,
        trust: "observed-untrusted",
        output: "collector unavailable: Windows P0 evidence failed closed".to_owned(),
        success: false,
        truncated,
    }
}

#[cfg(target_os = "windows")]
fn validated_windows_output(collector: &'static str, output: String) -> Observation {
    if windows_resident::validate_projection(collector, &output).is_ok() {
        Observation {
            collector,
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        }
    } else {
        failed_windows_observation(collector, false)
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_powershell(collector: &'static str, script: &'static str) -> Observation {
    let args = [
        windows_resident::POWERSHELL_PREFIX_ARGS[0],
        windows_resident::POWERSHELL_PREFIX_ARGS[1],
        windows_resident::POWERSHELL_PREFIX_ARGS[2],
        windows_resident::POWERSHELL_PREFIX_ARGS[3],
        script,
    ];
    match run_fixed_command(
        windows_resident::POWERSHELL,
        &args,
        windows_resident::POWERSHELL_TIMEOUT,
        QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
    ) {
        Ok(output) if output.exit_code == 0 && output.stderr.trim().is_empty() => {
            validated_windows_output(collector, output.stdout)
        }
        Ok(_) => failed_windows_observation(collector, false),
        Err(error) => failed_windows_observation(collector, error.truncated()),
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_native(
    collector: &'static str,
    program: &'static str,
    args: &[&str],
    timeout: Duration,
    normalize: fn(&str, &str, i32) -> Result<String, ()>,
) -> Observation {
    match run_fixed_command(program, args, timeout, QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES) {
        Ok(output) => match normalize(&output.stdout, &output.stderr, output.exit_code) {
            Ok(normalized) => validated_windows_output(collector, normalized),
            Err(()) => failed_windows_observation(collector, false),
        },
        Err(error) => failed_windows_observation(collector, error.truncated()),
    }
}

#[cfg(target_os = "windows")]
fn boot_native_output(
    result: &Result<FixedCommandOutput, FixedCommandFailure>,
) -> windows_resident::NativeOutput<'_> {
    match result {
        Ok(output) => windows_resident::NativeOutput {
            stdout: &output.stdout,
            exit_code: output.exit_code,
        },
        Err(_) => windows_resident::NativeOutput {
            stdout: "",
            exit_code: -1,
        },
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_boot() -> Observation {
    let (firmware, manager, loaders, default_loader) = thread::scope(|scope| {
        let firmware = scope.spawn(|| {
            run_fixed_command(
                windows_resident::REG,
                &windows_resident::FIRMWARE_REG_ARGS,
                windows_resident::BOOT_TIMEOUT,
                QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
            )
        });
        let manager = scope.spawn(|| {
            run_fixed_command(
                windows_resident::BCDEDIT,
                &windows_resident::BOOT_MANAGER_ARGS,
                windows_resident::BOOT_TIMEOUT,
                QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
            )
        });
        let loaders = scope.spawn(|| {
            run_fixed_command(
                windows_resident::BCDEDIT,
                &windows_resident::OS_LOADER_ARGS,
                windows_resident::BOOT_TIMEOUT,
                QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
            )
        });
        let default_loader = scope.spawn(|| {
            run_fixed_command(
                windows_resident::BCDEDIT,
                &windows_resident::DEFAULT_LOADER_ARGS,
                windows_resident::BOOT_TIMEOUT,
                QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
            )
        });
        (
            firmware
                .join()
                .unwrap_or(Err(FixedCommandFailure::Unavailable)),
            manager
                .join()
                .unwrap_or(Err(FixedCommandFailure::Unavailable)),
            loaders
                .join()
                .unwrap_or(Err(FixedCommandFailure::Unavailable)),
            default_loader
                .join()
                .unwrap_or(Err(FixedCommandFailure::Unavailable)),
        )
    });
    // Native stderr is deliberately not interpreted: localized warning/error
    // text is neither evidence of success nor a schema. Exit status and the
    // fixed ASCII identifiers alone drive the typed projection.
    match windows_resident::normalize_boot(
        boot_native_output(&firmware),
        boot_native_output(&manager),
        boot_native_output(&loaders),
        boot_native_output(&default_loader),
    ) {
        Ok(normalized) => validated_windows_output("windows.boot.state", normalized),
        Err(()) => failed_windows_observation("windows.boot.state", false),
    }
}

#[cfg(target_os = "windows")]
fn windows_identity_from_volumes(volumes: &Observation) -> Observation {
    if !volumes.success || volumes.truncated {
        return failed_windows_observation("windows.storage.identity", volumes.truncated);
    }
    match windows_resident::derive_storage_identity(&volumes.output) {
        Ok(output) => Observation {
            collector: "windows.storage.identity",
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        },
        Err(()) => failed_windows_observation("windows.storage.identity", false),
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_identity() -> Observation {
    let volumes =
        collect_windows_powershell("windows.volumes.state", windows_resident::VOLUMES_SCRIPT);
    windows_identity_from_volumes(&volumes)
}

#[cfg(target_os = "windows")]
fn collect_windows_spec(spec: windows_resident::CollectorSpec) -> Observation {
    match spec.kind {
        windows_resident::CollectorKind::PowerShell(script) => {
            collect_windows_powershell(spec.collector, script)
        }
        windows_resident::CollectorKind::Dism => collect_windows_native(
            spec.collector,
            windows_resident::DISM,
            &windows_resident::DISM_ARGS,
            windows_resident::DISM_TIMEOUT,
            windows_resident::normalize_dism,
        ),
        windows_resident::CollectorKind::SfcNotRunUnqualified => {
            match windows_resident::sfc_not_run_projection() {
                Ok(output) => validated_windows_output(spec.collector, output),
                Err(()) => failed_windows_observation(spec.collector, false),
            }
        }
        windows_resident::CollectorKind::Boot => collect_windows_boot(),
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_p0_observations() -> Vec<Observation> {
    thread::scope(|scope| {
        let handles = windows_resident::COLLECTORS
            .map(|spec| scope.spawn(move || collect_windows_spec(spec)));
        let mut observations = Vec::with_capacity(windows_resident::COLLECTORS.len() + 1);
        for (spec, handle) in windows_resident::COLLECTORS.into_iter().zip(handles) {
            observations.push(
                handle
                    .join()
                    .unwrap_or_else(|_| failed_windows_observation(spec.collector, false)),
            );
        }
        let identity = observations
            .iter()
            .find(|observation| observation.collector == "windows.volumes.state")
            .map(windows_identity_from_volumes)
            .unwrap_or_else(|| failed_windows_observation("windows.storage.identity", false));
        observations.push(identity);
        observations
    })
}

#[tauri::command]
async fn collect_windows_p0_inventory() -> Result<Vec<Observation>, String> {
    #[cfg(target_os = "windows")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let started = Instant::now();
            let observations = collect_windows_p0_observations();
            if started.elapsed() > windows_resident::P0_WALL_CLOCK_BUDGET {
                return Err(
                    "La raccolta Windows ha superato il budget P0 di 150 secondi; nessuna diagnosi è stata formulata."
                        .to_owned(),
                );
            }
            Ok(observations)
        })
        .await
        .map_err(|_| "La raccolta Windows non è stata completata.".to_owned())?
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Il corpus Windows è disponibile solo su sistemi Windows.".to_owned())
    }
}

#[cfg(any(target_os = "macos", test))]
fn failed_macos_observation(collector: &'static str, truncated: bool) -> Observation {
    Observation {
        collector,
        trust: "observed-untrusted",
        output: "collector unavailable: macOS P0 evidence failed closed".to_owned(),
        success: false,
        truncated,
    }
}

#[cfg(target_os = "macos")]
fn validated_macos_output(collector: &'static str, output: String) -> MacosCollectorOutcome {
    if output.len() > QUALIFIED_MACOS_MAX_OUTPUT_BYTES {
        MacosCollectorOutcome::failure(collector, MacosCollectorFailureReason::Truncated)
    } else if macos_resident::validate_projection(collector, &output).is_err() {
        MacosCollectorOutcome::failure(collector, MacosCollectorFailureReason::ProjectionInvalid)
    } else {
        MacosCollectorOutcome::success(collector, output)
    }
}

#[cfg(any(target_os = "macos", test))]
fn complete_macos_command(
    result: Result<FixedCommandOutput, FixedCommandFailure>,
) -> Result<FixedCommandOutput, MacosCollectorFailureReason> {
    let output = result.map_err(MacosCollectorFailureReason::from)?;
    if output.exit_code != 0 {
        Err(MacosCollectorFailureReason::NonzeroExit)
    } else if !output.stderr.trim().is_empty() {
        Err(MacosCollectorFailureReason::StderrNonempty)
    } else {
        Ok(output)
    }
}

#[cfg(any(target_os = "macos", test))]
fn complete_macos_route_command(
    result: Result<FixedCommandOutput, FixedCommandFailure>,
) -> Result<FixedCommandOutput, MacosCollectorFailureReason> {
    let output = result.map_err(MacosCollectorFailureReason::from)?;
    if matches!(output.exit_code, 0 | 1) {
        Ok(output)
    } else {
        Err(MacosCollectorFailureReason::NonzeroExit)
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_system() -> MacosCollectorOutcome {
    let output = complete_macos_command(run_fixed_command(
        macos_resident::SW_VERS,
        &macos_resident::SW_VERS_ARGS,
        macos_resident::STANDARD_TIMEOUT,
        QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
    ));
    match output.and_then(|output| {
        macos_resident::normalize_system_version(&output.stdout)
            .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
    }) {
        Ok(output) => MacosCollectorOutcome::success("macos.system", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.system", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_storage() -> (MacosCollectorOutcome, MacosCollectorOutcome) {
    let result = complete_macos_command(run_fixed_command(
        macos_resident::SYSTEM_PROFILER,
        &macos_resident::SYSTEM_PROFILER_ARGS,
        macos_resident::STORAGE_TIMEOUT,
        QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
    ));
    match result {
        Ok(output) => {
            let storage = match macos_resident::normalize_storage(&output.stdout) {
                Ok(output) => validated_macos_output("macos.storage.inventory", output),
                Err(()) => MacosCollectorOutcome::failure(
                    "macos.storage.inventory",
                    MacosCollectorFailureReason::ProjectionInvalid,
                ),
            };
            let identity = match macos_resident::derive_storage_identity(&output.stdout) {
                Ok(output) => MacosCollectorOutcome::success("macos.storage.identity", output),
                Err(()) => MacosCollectorOutcome::failure(
                    "macos.storage.identity",
                    MacosCollectorFailureReason::ProjectionInvalid,
                ),
            };
            (storage, identity)
        }
        Err(reason) => (
            MacosCollectorOutcome::failure("macos.storage.inventory", reason),
            MacosCollectorOutcome::failure("macos.storage.identity", reason),
        ),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_apfs() -> MacosCollectorOutcome {
    let (list, root) = thread::scope(|scope| {
        let list = scope.spawn(|| {
            complete_macos_command(run_fixed_command(
                macos_resident::DISKUTIL,
                &macos_resident::APFS_LIST_ARGS,
                macos_resident::STANDARD_TIMEOUT,
                QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
            ))
        });
        let root = scope.spawn(|| {
            complete_macos_command(run_fixed_command(
                macos_resident::DISKUTIL,
                &macos_resident::ROOT_INFO_ARGS,
                macos_resident::STANDARD_TIMEOUT,
                QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
            ))
        });
        (
            list.join()
                .unwrap_or(Err(MacosCollectorFailureReason::ThreadFailed)),
            root.join()
                .unwrap_or(Err(MacosCollectorFailureReason::ThreadFailed)),
        )
    });
    let normalized = list.and_then(|list| {
        root.and_then(|root| {
            macos_resident::normalize_apfs(list.stdout.as_bytes(), root.stdout.as_bytes())
                .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
        })
    });
    match normalized {
        Ok(output) => validated_macos_output("macos.apfs.capacity", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.apfs.capacity", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_launchd() -> MacosCollectorOutcome {
    let normalized = complete_macos_command(run_fixed_command(
        macos_resident::LAUNCHCTL,
        &macos_resident::LAUNCHCTL_ARGS,
        macos_resident::STANDARD_TIMEOUT,
        QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
    ))
    .and_then(|output| {
        macos_resident::normalize_launchd_user(&output.stdout)
            .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
    });
    match normalized {
        Ok(output) => validated_macos_output("macos.launchd.state", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.launchd.state", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_network() -> MacosCollectorOutcome {
    let (nwi, route, dns) = thread::scope(|scope| {
        let nwi = scope.spawn(|| {
            complete_macos_command(run_fixed_command(
                macos_resident::SCUTIL,
                &macos_resident::NWI_ARGS,
                macos_resident::STANDARD_TIMEOUT,
                QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
            ))
        });
        let route = scope.spawn(|| {
            complete_macos_route_command(run_fixed_command(
                macos_resident::ROUTE,
                &macos_resident::ROUTE_ARGS,
                macos_resident::STANDARD_TIMEOUT,
                QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
            ))
        });
        let dns = scope.spawn(|| {
            complete_macos_command(run_fixed_command(
                macos_resident::SCUTIL,
                &macos_resident::DNS_ARGS,
                macos_resident::STANDARD_TIMEOUT,
                QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
            ))
        });
        (
            nwi.join()
                .unwrap_or(Err(MacosCollectorFailureReason::ThreadFailed)),
            route
                .join()
                .unwrap_or(Err(MacosCollectorFailureReason::ThreadFailed)),
            dns.join()
                .unwrap_or(Err(MacosCollectorFailureReason::ThreadFailed)),
        )
    });
    let normalized = nwi.and_then(|nwi| {
        dns.and_then(|dns| {
            route.and_then(|route| {
                macos_resident::normalize_network(&nwi.stdout, route.exit_code, &dns.stdout)
                    .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
            })
        })
    });
    match normalized {
        Ok(output) => validated_macos_output("macos.network.state", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.network.state", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_updates() -> MacosCollectorOutcome {
    match macos_resident::updates_unqualified_projection() {
        Ok(output) => validated_macos_output("macos.software-update.state", output),
        Err(()) => MacosCollectorOutcome::failure(
            "macos.software-update.state",
            MacosCollectorFailureReason::ProjectionInvalid,
        ),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_events() -> MacosCollectorOutcome {
    match macos_resident::events_unqualified_projection() {
        Ok(output) => validated_macos_output("macos.system-events.summary", output),
        Err(()) => MacosCollectorOutcome::failure(
            "macos.system-events.summary",
            MacosCollectorFailureReason::ProjectionInvalid,
        ),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_startup() -> MacosCollectorOutcome {
    let normalized = complete_macos_command(run_fixed_command(
        macos_resident::SYSCTL,
        &macos_resident::SAFE_BOOT_ARGS,
        macos_resident::STANDARD_TIMEOUT,
        QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
    ))
    .and_then(|safe_boot| {
        macos_resident::normalize_startup(&safe_boot.stdout)
            .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
    });
    match normalized {
        Ok(output) => validated_macos_output("macos.startup.state", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.startup.state", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_snapshots() -> MacosCollectorOutcome {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid);
    let normalized = now.and_then(|now| {
        complete_macos_command(run_fixed_command(
            macos_resident::TMUTIL,
            &macos_resident::SNAPSHOT_ARGS,
            macos_resident::STANDARD_TIMEOUT,
            QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
        ))
        .and_then(|output| {
            macos_resident::normalize_snapshots(&output.stdout, now)
                .map_err(|_| MacosCollectorFailureReason::ProjectionInvalid)
        })
    });
    match normalized {
        Ok(output) => validated_macos_output("macos.snapshots.inventory", output),
        Err(reason) => MacosCollectorOutcome::failure("macos.snapshots.inventory", reason),
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_identity_outcomes() -> Vec<MacosCollectorOutcome> {
    let (system, (_, identity)) = thread::scope(|scope| {
        let system = scope.spawn(collect_macos_system);
        let storage = scope.spawn(collect_macos_storage);
        (
            system.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.system",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            storage.join().unwrap_or_else(|_| {
                (
                    MacosCollectorOutcome::failure(
                        "macos.storage.inventory",
                        MacosCollectorFailureReason::ThreadFailed,
                    ),
                    MacosCollectorOutcome::failure(
                        "macos.storage.identity",
                        MacosCollectorFailureReason::ThreadFailed,
                    ),
                )
            }),
        )
    });
    vec![system, identity]
}

#[cfg(target_os = "macos")]
fn collect_macos_identity_observations() -> Vec<Observation> {
    collect_macos_identity_outcomes()
        .into_iter()
        .map(MacosCollectorOutcome::into_observation)
        .collect()
}

#[cfg(target_os = "macos")]
fn collect_macos_p0_outcomes() -> Vec<MacosCollectorOutcome> {
    thread::scope(|scope| {
        let system = scope.spawn(collect_macos_system);
        let storage = scope.spawn(collect_macos_storage);
        let apfs = scope.spawn(collect_macos_apfs);
        let launchd = scope.spawn(collect_macos_launchd);
        let network = scope.spawn(collect_macos_network);
        let updates = scope.spawn(collect_macos_updates);
        let events = scope.spawn(collect_macos_events);
        let startup = scope.spawn(collect_macos_startup);
        let snapshots = scope.spawn(collect_macos_snapshots);
        let system = system.join().unwrap_or_else(|_| {
            MacosCollectorOutcome::failure(
                "macos.system",
                MacosCollectorFailureReason::ThreadFailed,
            )
        });
        let (storage, identity) = storage.join().unwrap_or_else(|_| {
            (
                MacosCollectorOutcome::failure(
                    "macos.storage.inventory",
                    MacosCollectorFailureReason::ThreadFailed,
                ),
                MacosCollectorOutcome::failure(
                    "macos.storage.identity",
                    MacosCollectorFailureReason::ThreadFailed,
                ),
            )
        });
        vec![
            system,
            storage,
            apfs.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.apfs.capacity",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            launchd.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.launchd.state",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            network.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.network.state",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            updates.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.software-update.state",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            events.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.system-events.summary",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            startup.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.startup.state",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            snapshots.join().unwrap_or_else(|_| {
                MacosCollectorOutcome::failure(
                    "macos.snapshots.inventory",
                    MacosCollectorFailureReason::ThreadFailed,
                )
            }),
            identity,
        ]
    })
}

#[cfg(target_os = "macos")]
fn collect_macos_p0_observations() -> Vec<Observation> {
    collect_macos_p0_outcomes()
        .into_iter()
        .map(MacosCollectorOutcome::into_observation)
        .collect()
}

#[tauri::command]
async fn collect_macos_p0_inventory() -> Result<Vec<Observation>, String> {
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let started = Instant::now();
            let observations = collect_macos_p0_observations();
            if started.elapsed() > macos_resident::P0_WALL_CLOCK_BUDGET {
                return Err(
                    "La raccolta macOS ha superato il budget P0 di 90 secondi; nessuna diagnosi è stata formulata."
                        .to_owned(),
                );
            }
            Ok(observations)
        })
        .await
        .map_err(|_| "La raccolta macOS non è stata completata.".to_owned())?
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("Il corpus macOS è disponibile solo su sistemi macOS.".to_owned())
    }
}

fn collect_local_inventory_sync() -> Vec<Observation> {
    let mut observations: Vec<Observation> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        observations.push(fixed_command("system.hostname", "/usr/bin/hostname", &[]));
        observations.push(collect_linux_hardware_inventory());
        observations.push(collect_linux_storage_health());
        observations.push(fixed_command(
            "linux.block.inventory",
            "/usr/bin/lsblk",
            &[
                "--json",
                "--bytes",
                "--output",
                "NAME,TYPE,SIZE,RO,FSTYPE,MOUNTPOINTS,SERIAL,WWN,UUID,PARTUUID,PTUUID",
            ],
        ));
        observations.push(fixed_command_with_policy(
            "linux.mounts.read-only",
            "/usr/bin/findmnt",
            &[
                "--json",
                "--list",
                "--options",
                "ro",
                "--output",
                "TARGET,FSTYPE",
            ],
            COMMAND_TIMEOUT,
            Some("{\"filesystems\":[]}"),
        ));
        observations.push(fixed_command(
            "linux.network.links",
            "/usr/sbin/ip",
            &["-json", "link"],
        ));
        observations.push(fixed_command(
            "linux.systemd.failed",
            "/usr/bin/systemctl",
            &["--failed", "--no-pager", "--plain"],
        ));
        observations.push(fixed_command(
            "linux.systemd.state",
            "/usr/bin/systemctl",
            &["show", "--property=SystemState", "--no-pager"],
        ));
        observations.push(collect_linux_fstab());
        observations.push(fixed_command(
            "linux.df",
            "/usr/bin/df",
            &["--block-size=1", "--portability"],
        ));
        observations.push(fixed_command(
            "linux.network.routes",
            "/usr/sbin/ip",
            &["-json", "route"],
        ));
        observations.push(fixed_command(
            "linux.dpkg.audit",
            "/usr/bin/dpkg",
            &["--audit"],
        ));
    }
    #[cfg(target_os = "windows")]
    {
        observations.push(collect_windows_identity());
    }
    #[cfg(target_os = "macos")]
    {
        observations.extend(collect_macos_identity_observations());
    }
    observations
}

#[cfg(target_os = "linux")]
fn collect_linux_hardware_inventory() -> Observation {
    match collect_linux_hardware_inventory_bounded(
        &HARDWARE_COLLECTOR_STATE,
        HARDWARE_COLLECTOR_TIMEOUT,
        kernaid_linux_pack::hardware::collect_current_machine,
    )
    .and_then(|inventory| kernaid_linux_pack::hardware::to_bounded_json(&inventory).map_err(|_| ()))
    {
        Ok(output) => Observation {
            collector: kernaid_linux_pack::hardware::COLLECTOR,
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        },
        Err(_) => Observation {
            collector: kernaid_linux_pack::hardware::COLLECTOR,
            trust: "observed-untrusted",
            output: "collector unavailable: normalized hardware inventory did not complete safely"
                .to_owned(),
            success: false,
            truncated: false,
        },
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_storage_health() -> Observation {
    let snapshot = kernaid_linux_pack::storage_health::collect_current_machine();
    match kernaid_linux_pack::storage_health::to_bounded_json(&snapshot) {
        Ok(output) => Observation {
            collector: kernaid_linux_pack::storage_health::COLLECTOR,
            trust: "observed-untrusted",
            output,
            success: true,
            truncated: false,
        },
        Err(_) => Observation {
            collector: kernaid_linux_pack::storage_health::COLLECTOR,
            trust: "observed-untrusted",
            output: String::new(),
            success: false,
            truncated: false,
        },
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_hardware_inventory_bounded(
    state: &'static AtomicU8,
    timeout: Duration,
    collect: impl FnOnce() -> kernaid_linux_pack::hardware::HardwareInventory + Send + 'static,
) -> Result<kernaid_linux_pack::hardware::HardwareInventory, ()> {
    if state
        .compare_exchange(
            HARDWARE_COLLECTOR_IDLE,
            HARDWARE_COLLECTOR_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(());
    }
    let (sender, receiver) = mpsc::sync_channel(0);
    if thread::Builder::new()
        .name("kernaid-linux-hardware-inventory".to_owned())
        .spawn(move || {
            let inventory = collect();
            let _ = sender.send(inventory);
        })
        .is_err()
    {
        state.store(HARDWARE_COLLECTOR_IDLE, Ordering::Release);
        return Err(());
    }
    match receiver.recv_timeout(timeout) {
        Ok(inventory) => {
            state
                .compare_exchange(
                    HARDWARE_COLLECTOR_RUNNING,
                    HARDWARE_COLLECTOR_IDLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| ())?;
            Ok(inventory)
        }
        Err(_) => {
            let _ = state.compare_exchange(
                HARDWARE_COLLECTOR_RUNNING,
                HARDWARE_COLLECTOR_POISONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            Err(())
        }
    }
}

#[tauri::command]
async fn collect_local_inventory() -> Result<Vec<Observation>, String> {
    tauri::async_runtime::spawn_blocking(collect_local_inventory_sync)
        .await
        .map_err(|_| "L’inventario locale non è stato completato.".to_owned())
}

#[tauri::command]
async fn collect_linux_normalized_snapshot() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let envelope = kernaid_linux_pack::snapshot::collect_current_root_snapshot()
                .map_err(|_| "Lo snapshot Linux normalizzato non è disponibile.".to_owned())?;
            serde_json::to_value(envelope)
                .map_err(|_| "Lo snapshot Linux normalizzato non è serializzabile.".to_owned())
        })
        .await
        .map_err(|_| "Lo snapshot Linux normalizzato non è stato completato.".to_owned())?
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err("Lo snapshot Linux è disponibile solo su sistemi Linux.".to_owned())
    }
}

#[tauri::command]
fn diagnose_linux_p0(evidence: Vec<NativeDiagnosticEvidence>) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        use kernaid_linux_pack::diagnostics::{
            EvidenceInput, LinuxP0Inputs, MAX_INPUT_BYTES, diagnose_linux_p0, proposal_from_report,
        };
        use std::collections::BTreeMap;

        const REQUIRED: [&str; 9] = [
            "linux.block.inventory",
            "linux.mounts.read-only",
            "linux.systemd.failed",
            "linux.systemd.state",
            "linux.fstab",
            "linux.df",
            "linux.network.links",
            "linux.network.routes",
            "linux.dpkg.audit",
        ];
        if evidence.len() != REQUIRED.len() {
            return Err("Il corpus Linux richiede tutte le evidenze P0.".to_owned());
        }
        let mut documents = BTreeMap::new();
        for document in evidence {
            if !REQUIRED.contains(&document.collector.as_str())
                || document.content.len() > MAX_INPUT_BYTES
                || documents
                    .insert(document.collector.clone(), document)
                    .is_some()
            {
                return Err("Le evidenze Linux non sono valide.".to_owned());
            }
        }
        let input = |collector: &str| -> Result<EvidenceInput<'_>, String> {
            let document = documents
                .get(collector)
                .ok_or_else(|| "Le evidenze Linux sono incomplete.".to_owned())?;
            Ok(EvidenceInput {
                id: &document.id,
                body: document.content.as_bytes(),
            })
        };
        let report = diagnose_linux_p0(LinuxP0Inputs {
            lsblk_json: input("linux.block.inventory")?,
            read_only_mounts_json: input("linux.mounts.read-only")?,
            systemctl_failed: input("linux.systemd.failed")?,
            systemctl_unit_state: input("linux.systemd.state")?,
            fstab: input("linux.fstab")?,
            df: input("linux.df")?,
            ip_link_json: input("linux.network.links")?,
            ip_route_json: input("linux.network.routes")?,
            dpkg_audit: input("linux.dpkg.audit")?,
        })
        .map_err(|_| "Una evidenza Linux è malformata o incompleta.".to_owned())?;
        serde_json::to_value(proposal_from_report(&report))
            .map_err(|_| "La diagnosi Linux non è serializzabile.".to_owned())
    }

    #[cfg(not(target_os = "linux"))]
    {
        for document in evidence {
            drop((document.id, document.collector, document.content));
        }
        Err("Il corpus Linux è disponibile solo su sistemi Linux.".to_owned())
    }
}

#[cfg(any(target_os = "macos", test))]
fn diagnose_macos_documents(
    evidence: Vec<NativeDiagnosticEvidence>,
) -> Result<serde_json::Value, String> {
    use kernaid_macos_pack::{
        EvidenceInput, MAX_INPUT_BYTES, MacosP0Inputs, diagnose_macos_p0 as evaluate_macos_p0,
        proposal_from_report,
    };
    use std::collections::BTreeMap;

    if evidence.len() != macos_resident::COLLECTORS.len() {
        return Err("Il corpus macOS richiede tutte le otto evidenze P0.".to_owned());
    }
    let mut documents = BTreeMap::new();
    for document in evidence {
        if !macos_resident::COLLECTORS.contains(&document.collector.as_str())
            || document.content.len() > MAX_INPUT_BYTES
            || documents
                .insert(document.collector.clone(), document)
                .is_some()
        {
            return Err("Le evidenze macOS non sono valide.".to_owned());
        }
    }
    let input = |collector: &str| -> Result<EvidenceInput<'_>, String> {
        let document = documents
            .get(collector)
            .ok_or_else(|| "Le evidenze macOS sono incomplete.".to_owned())?;
        Ok(EvidenceInput {
            id: &document.id,
            body: document.content.as_bytes(),
        })
    };
    let report = evaluate_macos_p0(MacosP0Inputs {
        storage: input("macos.storage.inventory")?,
        apfs: input("macos.apfs.capacity")?,
        launchd: input("macos.launchd.state")?,
        network: input("macos.network.state")?,
        updates: input("macos.software-update.state")?,
        events: input("macos.system-events.summary")?,
        startup: input("macos.startup.state")?,
        snapshots: input("macos.snapshots.inventory")?,
    })
    .map_err(|_| "Una evidenza macOS è malformata o incompleta.".to_owned())?;
    serde_json::to_value(proposal_from_report(&report))
        .map_err(|_| "La diagnosi macOS non è serializzabile.".to_owned())
}

#[tauri::command]
fn diagnose_macos_p0(evidence: Vec<NativeDiagnosticEvidence>) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "macos")]
    {
        diagnose_macos_documents(evidence)
    }

    #[cfg(not(target_os = "macos"))]
    {
        for document in evidence {
            drop((document.id, document.collector, document.content));
        }
        Err("Il corpus macOS è disponibile solo su sistemi macOS.".to_owned())
    }
}

#[cfg(any(target_os = "windows", test))]
fn diagnose_windows_documents(
    evidence: Vec<NativeDiagnosticEvidence>,
) -> Result<serde_json::Value, String> {
    use kernaid_windows_pack::diagnostics::{
        EvidenceInput, MAX_INPUT_BYTES, WindowsP0Inputs,
        diagnose_windows_p0 as evaluate_windows_p0, proposal_from_report,
    };
    use std::collections::BTreeMap;

    if evidence.len() != windows_resident::COLLECTORS.len() {
        return Err("Il corpus Windows richiede tutte le evidenze P0.".to_owned());
    }
    let mut documents = BTreeMap::new();
    for document in evidence {
        if !windows_resident::COLLECTORS
            .iter()
            .any(|spec| spec.collector == document.collector)
            || document.content.len() > MAX_INPUT_BYTES
            || documents
                .insert(document.collector.clone(), document)
                .is_some()
        {
            return Err("Le evidenze Windows non sono valide.".to_owned());
        }
    }
    let input = |collector: &str| -> Result<EvidenceInput<'_>, String> {
        let document = documents
            .get(collector)
            .ok_or_else(|| "Le evidenze Windows sono incomplete.".to_owned())?;
        Ok(EvidenceInput {
            id: &document.id,
            body: document.content.as_bytes(),
        })
    };
    let report = evaluate_windows_p0(WindowsP0Inputs {
        event_log_json: input("windows.event-log.window")?,
        reliability_json: input("windows.reliability.records")?,
        component_store_json: input("windows.component-store.check-health")?,
        sfc_json: input("windows.sfc.verify-only")?,
        update_json: input("windows.update.state")?,
        services_json: input("windows.services.state")?,
        network_json: input("windows.network.state")?,
        drivers_json: input("windows.drivers.state")?,
        bitlocker_json: input("windows.bitlocker.state")?,
        boot_json: input("windows.boot.state")?,
        volumes_json: input("windows.volumes.state")?,
    })
    .map_err(|_| "Una evidenza Windows è malformata o incompleta.".to_owned())?;
    serde_json::to_value(proposal_from_report(&report))
        .map_err(|_| "La diagnosi Windows non è serializzabile.".to_owned())
}

#[tauri::command]
fn diagnose_windows_p0(
    evidence: Vec<NativeDiagnosticEvidence>,
) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "windows")]
    {
        diagnose_windows_documents(evidence)
    }

    #[cfg(not(target_os = "windows"))]
    {
        for document in evidence {
            drop((document.id, document.collector, document.content));
        }
        Err("Il corpus Windows è disponibile solo su sistemi Windows.".to_owned())
    }
}

fn is_identity_observation(collector: &str) -> bool {
    collector.contains("hostname")
        || collector.contains("block.inventory")
        || collector.ends_with(".disks")
        || collector.ends_with(".system")
        || collector.ends_with(".storage.identity")
}

fn inventory_fingerprint(observations: &[Observation]) -> String {
    let mut hasher = Sha256::new();
    let mut first = true;
    for observation in observations
        .iter()
        .filter(|item| is_identity_observation(item.collector))
    {
        if !first {
            hasher.update([0]);
        }
        first = false;
        hasher.update(observation.collector.as_bytes());
        hasher.update([0]);
        hasher.update(observation.output.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn locked_brokers(
    state: &ObserveBrokers,
) -> Result<MutexGuard<'_, HashMap<String, ObserveBroker>>, String> {
    state
        .0
        .lock()
        .map_err(|_| "Il broker locale non è disponibile.".to_owned())
}

fn broker_error(error: BrokerError) -> String {
    match error {
        BrokerError::InvalidRequest => "Richiesta al broker non valida.".to_owned(),
        BrokerError::UnknownAction => "Azione non consentita dal broker locale.".to_owned(),
        BrokerError::StaleTarget => {
            "Il target è cambiato: piano annullato, ripetere la diagnosi.".to_owned()
        }
        BrokerError::NonMonotonicSequence => "Richiesta già eseguita o fuori sequenza.".to_owned(),
    }
}

#[tauri::command]
async fn authorize_observe(
    state: State<'_, ObserveBrokers>,
    request: ObserveRequest,
) -> Result<&'static str, String> {
    let current_fingerprint = tauri::async_runtime::spawn_blocking(|| {
        inventory_fingerprint(&collect_local_inventory_sync())
    })
    .await
    .map_err(|_| "L’identità corrente del target non è disponibile.".to_owned())?;
    let mut brokers = locked_brokers(&state)?;
    authorize_observe_for_fingerprint(&mut brokers, current_fingerprint, request)
}

fn authorize_observe_for_fingerprint(
    brokers: &mut HashMap<String, ObserveBroker>,
    current_fingerprint: String,
    request: ObserveRequest,
) -> Result<&'static str, String> {
    if request.target_fingerprint != current_fingerprint {
        return Err(broker_error(BrokerError::StaleTarget));
    }
    if !brokers.contains_key(&request.session_id) && brokers.len() >= MAX_BROKER_SESSIONS {
        return Err("Limite delle sessioni locali raggiunto; riavviare KernAid.".to_owned());
    }
    let broker = brokers
        .entry(request.session_id.clone())
        .or_insert_with(|| ObserveBroker::new(current_fingerprint));
    broker
        .execute(&BrokerRequest {
            session_id: request.session_id,
            plan_id: request.plan_id,
            approval_id: None,
            target_fingerprint: request.target_fingerprint,
            sequence: request.sequence,
            action: request.action,
        })
        .map_err(broker_error)
}

macro_rules! production_invoke_handler {
    () => {
        tauri::generate_handler![
            collect_local_inventory,
            collect_linux_normalized_snapshot,
            collect_macos_p0_inventory,
            collect_windows_p0_inventory,
            diagnose_linux_p0,
            diagnose_macos_p0,
            diagnose_windows_p0,
            authorize_observe,
            secure_runtime_status,
            initialize_device_identity,
            append_audit_record,
            seal_signed_report,
            resident_openai_status,
            resident_openai_diagnose,
            resident_openai_cancel,
            resident_openai_logout
        ]
    };
}

#[cfg(all(target_os = "linux", feature = "fixture-repair-lab"))]
macro_rules! active_invoke_handler {
    () => {
        tauri::generate_handler![
            collect_local_inventory,
            collect_linux_normalized_snapshot,
            collect_macos_p0_inventory,
            collect_windows_p0_inventory,
            diagnose_linux_p0,
            diagnose_macos_p0,
            diagnose_windows_p0,
            authorize_observe,
            secure_runtime_status,
            initialize_device_identity,
            append_audit_record,
            seal_signed_report,
            resident_openai_status,
            resident_openai_diagnose,
            resident_openai_cancel,
            resident_openai_logout,
            fixture_repair_lab::fixture_lab_status,
            fixture_repair_lab::fixture_lab_stage,
            fixture_repair_lab::fixture_lab_execute,
            fixture_repair_lab::fixture_lab_reconcile_execute,
            fixture_repair_lab::fixture_lab_recover_repair_for_rollback,
            fixture_repair_lab::fixture_lab_stage_rollback,
            fixture_repair_lab::fixture_lab_execute_rollback,
            fixture_repair_lab::fixture_lab_reconcile_rollback
        ]
    };
}

#[cfg(not(all(target_os = "linux", feature = "fixture-repair-lab")))]
macro_rules! active_invoke_handler {
    () => {
        production_invoke_handler!()
    };
}

fn qualified_first_launch_probe_requested(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<bool, ()> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let flag = OsStr::new(QUALIFIED_FIRST_LAUNCH_PROBE_FLAG);
    if arguments.len() == 1 && arguments[0] == flag {
        return Ok(true);
    }
    if arguments.iter().any(|argument| argument == flag) {
        return Err(());
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualifiedFirstLaunchProbeError {
    RepairSurfacePresent,
    PrivateDirectory,
    RuntimeOpen,
    RuntimeStatus,
    RuntimeBlocked,
    Cleanup,
}

fn create_qualified_first_launch_directory() -> Result<PathBuf, QualifiedFirstLaunchProbeError> {
    // macOS commonly exposes its temporary directory through `/var`, which is
    // a symlink to `/private/var`. SQLite's NOFOLLOW open correctly rejects a
    // database path containing that symlink, so resolve only the existing base
    // before atomically creating the private probe directory beneath it.
    let base = fs::canonicalize(std::env::temp_dir())
        .map_err(|_| QualifiedFirstLaunchProbeError::PrivateDirectory)?;
    let process_id = process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| QualifiedFirstLaunchProbeError::PrivateDirectory)?
        .as_nanos();
    let sequence = QUALIFIED_FIRST_LAUNCH_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    for attempt in 0_u8..32 {
        let mut hasher = Sha256::new();
        hasher.update(b"KERNAID_QUALIFIED_FIRST_LAUNCH_DIRECTORY_V1\0");
        hasher.update(process_id.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(sequence.to_le_bytes());
        hasher.update([attempt]);
        let suffix = format!("{:x}", hasher.finalize());
        let path = base.join(format!(".kernaid-qualified-first-launch-{}", &suffix[..32]));
        #[cfg(unix)]
        let created = fs::DirBuilder::new().mode(0o700).create(&path);
        #[cfg(not(unix))]
        let created = fs::create_dir(&path);
        match created {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(QualifiedFirstLaunchProbeError::PrivateDirectory),
        }
    }
    Err(QualifiedFirstLaunchProbeError::PrivateDirectory)
}

fn stable_repair_surface_is_absent() -> bool {
    !cfg!(feature = "fixture-repair-lab")
}

fn run_qualified_first_launch_probe() -> Result<(), QualifiedFirstLaunchProbeError> {
    if !stable_repair_surface_is_absent() {
        return Err(QualifiedFirstLaunchProbeError::RepairSurfacePresent);
    }
    let directory = create_qualified_first_launch_directory()?;
    let result = (|| {
        let runtime = SecureRuntime::open_qualified_first_launch_probe(&directory)
            .map_err(|_| QualifiedFirstLaunchProbeError::RuntimeOpen)?;
        let status = runtime
            .qualified_first_launch_status()
            .map_err(|_| QualifiedFirstLaunchProbeError::RuntimeStatus)?;
        if !status.is_readable_for_qualified_first_launch() {
            return Err(QualifiedFirstLaunchProbeError::RuntimeBlocked);
        }
        drop(runtime);
        Ok(())
    })();
    let cleaned = fs::remove_dir_all(&directory).is_ok();
    result?;
    cleaned
        .then_some(())
        .ok_or(QualifiedFirstLaunchProbeError::Cleanup)
}

fn run_gui() {
    tauri::Builder::default()
        .manage(ObserveBrokers::default())
        .setup(|app| {
            let app_data_directory = app.path().app_data_dir()?;
            let runtime = SecureRuntime::open(&app_data_directory)?;
            app.manage(runtime);
            app.manage(ResidentOpenAiRuntime::open(&app_data_directory));
            #[cfg(all(target_os = "linux", feature = "fixture-repair-lab"))]
            app.manage(FixtureRepairLab::new()?);
            Ok(())
        })
        .invoke_handler(active_invoke_handler!())
        .run(tauri::generate_context!())
        .expect("failed to run KernAid Desk");
}

fn main() {
    match qualified_first_launch_probe_requested(std::env::args_os().skip(1)) {
        Ok(false) => run_gui(),
        Ok(true) => match run_qualified_first_launch_probe() {
            Ok(()) => println!("{QUALIFIED_FIRST_LAUNCH_OK}"),
            Err(_) => {
                eprintln!("{QUALIFIED_FIRST_LAUNCH_FAILED}");
                process::exit(1);
            }
        },
        Err(()) => {
            eprintln!("{QUALIFIED_FIRST_LAUNCH_FAILED}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    const LINUX_SNAPSHOT_GOLDEN: &[u8] = include_bytes!(
        "../../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json"
    );

    #[test]
    fn qualified_first_launch_flag_is_exact_and_standalone() {
        assert_eq!(
            qualified_first_launch_probe_requested(Vec::<OsString>::new()),
            Ok(false)
        );
        assert_eq!(
            qualified_first_launch_probe_requested([OsString::from(
                QUALIFIED_FIRST_LAUNCH_PROBE_FLAG,
            )]),
            Ok(true)
        );
        assert_eq!(
            qualified_first_launch_probe_requested([
                OsString::from(QUALIFIED_FIRST_LAUNCH_PROBE_FLAG),
                OsString::from("unexpected"),
            ]),
            Err(())
        );
        assert_eq!(
            qualified_first_launch_probe_requested([
                OsString::from("unexpected"),
                OsString::from(QUALIFIED_FIRST_LAUNCH_PROBE_FLAG),
            ]),
            Err(())
        );
        assert_eq!(
            qualified_first_launch_probe_requested([OsString::from("--other")]),
            Ok(false)
        );
    }

    #[test]
    fn qualified_first_launch_directory_is_private_and_disposable() {
        let path = create_qualified_first_launch_directory().expect("private probe directory");
        let metadata = fs::symlink_metadata(&path).expect("probe directory metadata");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
        }
        fs::remove_dir(&path).expect("remove empty probe directory");
        assert!(!path.exists());
    }

    #[test]
    fn qualified_first_launch_probe_rejects_repair_feature_builds() {
        assert_eq!(
            stable_repair_surface_is_absent(),
            !cfg!(feature = "fixture-repair-lab")
        );
    }

    #[cfg(not(feature = "fixture-repair-lab"))]
    #[test]
    fn qualified_first_launch_probe_initializes_and_cleans_ephemeral_runtime() {
        run_qualified_first_launch_probe().expect("packaged bootstrap must initialize");
    }

    #[cfg(target_os = "linux")]
    fn linux_snapshot_ipc_request(
        webview: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        body: tauri::ipc::InvokeBody,
    ) -> serde_json::Value {
        tauri::test::get_ipc_response(
            webview,
            tauri::webview::InvokeRequest {
                cmd: "collect_linux_normalized_snapshot".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "tauri://localhost".parse().expect("fixed Tauri URL"),
                body,
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .expect("Resident snapshot IPC command")
        .deserialize()
        .expect("Resident snapshot IPC JSON")
    }

    #[cfg(target_os = "linux")]
    fn linux_inventory_ipc_request(
        webview: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        body: tauri::ipc::InvokeBody,
    ) -> serde_json::Value {
        tauri::test::get_ipc_response(
            webview,
            tauri::webview::InvokeRequest {
                cmd: "collect_local_inventory".into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "tauri://localhost".parse().expect("fixed Tauri URL"),
                body,
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .expect("Resident inventory IPC command")
        .deserialize()
        .expect("Resident inventory IPC JSON")
    }

    #[cfg(target_os = "linux")]
    fn hardware_document_from_ipc(response: &serde_json::Value) -> &str {
        let matches = response
            .as_array()
            .expect("Resident inventory array")
            .iter()
            .filter(|item| item["collector"] == kernaid_linux_pack::hardware::COLLECTOR)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "hardware observation cardinality");
        let observation = matches[0];
        assert_eq!(observation["trust"], "observed-untrusted");
        assert_eq!(observation["success"], true);
        assert_eq!(observation["truncated"], false);
        observation["output"]
            .as_str()
            .expect("normalized hardware document")
    }

    #[cfg(target_os = "linux")]
    fn assert_rootless_single_id_mapping() {
        let mapping =
            std::fs::read_to_string("/proc/self/uid_map").expect("rootless user-namespace UID map");
        let rows = mapping
            .lines()
            .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "the probe requires one rootless UID mapping");
        assert_eq!(rows[0].len(), 3, "the UID mapping must have three fields");
        assert_eq!(rows[0][0], "0", "the namespace UID must be root");
        assert_ne!(rows[0][1], "0", "the outer UID must remain unprivileged");
        assert_eq!(rows[0][2], "1", "the namespace must map one UID only");
    }

    #[cfg(target_os = "linux")]
    fn fixture_hardware_inventory() -> kernaid_linux_pack::hardware::HardwareInventory {
        kernaid_linux_pack::hardware::parse_bounded_json(include_bytes!(
            "../../../../tests/fixtures/linux-hardware-inventory/healthy.v1.json"
        ))
        .expect("fixed hardware fixture")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_hardware_bounded_worker_releases_before_success_handoff() {
        let state: &'static AtomicU8 = Box::leak(Box::new(AtomicU8::new(HARDWARE_COLLECTOR_IDLE)));
        let inventory = collect_linux_hardware_inventory_bounded(
            state,
            Duration::from_secs(1),
            fixture_hardware_inventory,
        )
        .expect("bounded hardware collection");
        assert_eq!(inventory, fixture_hardware_inventory());
        assert_eq!(state.load(Ordering::Acquire), HARDWARE_COLLECTOR_IDLE);

        collect_linux_hardware_inventory_bounded(
            state,
            Duration::from_secs(1),
            fixture_hardware_inventory,
        )
        .expect("immediate bounded hardware recollection");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_hardware_bounded_worker_rejects_concurrent_collection() {
        let state: &'static AtomicU8 = Box::leak(Box::new(AtomicU8::new(HARDWARE_COLLECTOR_IDLE)));
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let first = thread::spawn(move || {
            collect_linux_hardware_inventory_bounded(state, Duration::from_secs(1), move || {
                entered_sender.send(()).expect("worker entry signal");
                release_receiver.recv().expect("worker release signal");
                fixture_hardware_inventory()
            })
        });
        entered_receiver.recv().expect("bounded worker entered");
        assert!(
            collect_linux_hardware_inventory_bounded(
                state,
                Duration::from_millis(10),
                fixture_hardware_inventory,
            )
            .is_err(),
            "a concurrent hardware collection must fail closed",
        );
        assert_eq!(state.load(Ordering::Acquire), HARDWARE_COLLECTOR_RUNNING);
        release_sender.send(()).expect("release bounded worker");
        first
            .join()
            .expect("bounded worker thread")
            .expect("first bounded collection");
        assert_eq!(state.load(Ordering::Acquire), HARDWARE_COLLECTOR_IDLE);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_hardware_bounded_worker_poison_is_permanent_after_timeout() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
        };

        let state: &'static AtomicU8 = Box::leak(Box::new(AtomicU8::new(HARDWARE_COLLECTOR_IDLE)));
        let attempts = Arc::new(AtomicUsize::new(0));
        let worker_attempts = Arc::clone(&attempts);
        assert!(
            collect_linux_hardware_inventory_bounded(state, Duration::from_millis(10), move || {
                worker_attempts.fetch_add(1, AtomicOrdering::AcqRel);
                thread::sleep(Duration::from_millis(100));
                fixture_hardware_inventory()
            },)
            .is_err(),
            "a timed-out hardware collection must fail closed",
        );
        assert_eq!(state.load(Ordering::Acquire), HARDWARE_COLLECTOR_POISONED);
        assert!(
            collect_linux_hardware_inventory_bounded(
                state,
                Duration::from_millis(10),
                fixture_hardware_inventory,
            )
            .is_err(),
            "a poisoned hardware collector must not spawn another worker",
        );
        thread::sleep(Duration::from_millis(120));
        assert_eq!(attempts.load(AtomicOrdering::Acquire), 1);
        assert_eq!(state.load(Ordering::Acquire), HARDWARE_COLLECTOR_POISONED);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run only through the rootless Resident IPC isolation harness"]
    fn resident_linux_snapshot_tauri_ipc_chroot_probe() {
        use rustix::fd::AsFd;
        use sha2::{Digest, Sha256};
        use std::{fs::File, path::Path};

        const HASH_DOMAIN: &[u8] = b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_V1\0";
        const E2E_SEMANTIC_HASH_DOMAIN: &[u8] =
            b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_E2E_SEMANTIC_V1\0";
        const FORBIDDEN_MARKERS: [&str; 4] = [
            "fixture-machine-id-must-never-be-projected",
            "fixture-secret-package-name",
            "UUID=fixture-root",
            "server:/fixture",
        ];

        assert_rootless_single_id_mapping();
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/fixtures/linux-normalized-snapshot/healthy/root");
        let fixture = File::open(&fixture_path).expect("fixed healthy fixture root");
        let fixture_identity = rustix::fs::fstat(fixture.as_fd()).expect("fixture identity");

        let app = tauri::test::mock_builder()
            .invoke_handler(production_invoke_handler!())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("mock Tauri application");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("mock Tauri webview");

        rustix::process::chroot(&fixture_path).expect("rootless fixture chroot");
        rustix::process::chdir("/").expect("fixture working directory");
        let isolated_root = File::open("/").expect("isolated root");
        let isolated_identity =
            rustix::fs::fstat(isolated_root.as_fd()).expect("isolated root identity");
        assert_eq!(
            (isolated_identity.st_dev, isolated_identity.st_ino),
            (fixture_identity.st_dev, fixture_identity.st_ino),
            "the production collector must see the fixed fixture only as /",
        );
        assert!(
            !Path::new("/proc").exists(),
            "the chroot must not expose the host process filesystem",
        );

        let envelope = linux_snapshot_ipc_request(&webview, Default::default());
        let snapshot = envelope
            .get("snapshot")
            .expect("normalized snapshot projection");
        let expected: serde_json::Value =
            serde_json::from_slice(LINUX_SNAPSHOT_GOLDEN).expect("snapshot golden");
        assert_eq!(
            snapshot, &expected,
            "Resident IPC snapshot must match the golden"
        );
        assert_eq!(envelope["capture"]["mode"], "resident");
        assert_eq!(envelope["capture"]["targetScope"], "running-root");
        assert_eq!(envelope["capture"]["callerSuppliedPath"], false);

        let marker_body = serde_json::json!({
            "root": "/outside-root/KERNAID_CALLER_PATH_MARKER_MUST_BE_IGNORED"
        });
        let marker_attempt =
            linux_snapshot_ipc_request(&webview, tauri::ipc::InvokeBody::Json(marker_body));
        assert_eq!(
            marker_attempt, envelope,
            "caller JSON must not influence the parameter-free IPC command",
        );

        let golden_canonical_snapshot = LINUX_SNAPSHOT_GOLDEN
            .strip_suffix(b"\n")
            .unwrap_or(LINUX_SNAPSHOT_GOLDEN);
        let serialized_envelope = serde_json::to_vec(&envelope).expect("snapshot envelope JSON");
        for marker in FORBIDDEN_MARKERS {
            assert!(
                !serialized_envelope
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "raw fixture marker escaped the normalized snapshot",
            );
        }
        assert!(
            !serialized_envelope
                .windows(b"KERNAID_CALLER_PATH_MARKER_MUST_BE_IGNORED".len())
                .any(|window| window == b"KERNAID_CALLER_PATH_MARKER_MUST_BE_IGNORED"),
            "caller marker escaped the parameter-free IPC boundary",
        );
        let native_digest = Sha256::digest([HASH_DOMAIN, golden_canonical_snapshot].concat());
        assert_eq!(
            envelope["snapshotSha256"],
            format!("{native_digest:x}"),
            "the IPC envelope digest must bind the semantic snapshot",
        );
        let mut sorted_snapshot = snapshot.clone();
        sorted_snapshot.sort_all_objects();
        let sorted_snapshot =
            serde_json::to_vec(&sorted_snapshot).expect("sorted semantic snapshot JSON");
        let semantic_digest =
            Sha256::digest([E2E_SEMANTIC_HASH_DOMAIN, sorted_snapshot.as_slice()].concat());
        println!("\nKERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 semantic_sha256={semantic_digest:x}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run only through the Resident production IPC harness"]
    fn resident_linux_hardware_tauri_ipc_probe() {
        use sha2::{Digest, Sha256};

        const HASH_DOMAIN: &[u8] = b"KERNAID_LINUX_HARDWARE_INVENTORY_IPC_V1\0";
        let app = tauri::test::mock_builder()
            .invoke_handler(production_invoke_handler!())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("mock Tauri application");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("mock Tauri webview");

        let response = linux_inventory_ipc_request(&webview, Default::default());
        let output = hardware_document_from_ipc(&response);
        let inventory = kernaid_linux_pack::hardware::parse_bounded_json(output.as_bytes())
            .expect("strict hardware document");
        assert_eq!(
            inventory.cpu.status,
            kernaid_linux_pack::hardware::SourceStatus::Complete
        );
        assert_eq!(
            inventory.memory.status,
            kernaid_linux_pack::hardware::SourceStatus::Complete
        );
        assert!(inventory.cpu.logical_processors.is_some());
        assert!(inventory.memory.total_bytes.is_some());

        let marker_body = serde_json::json!({
            "root": "/outside-root/KERNAID_HARDWARE_CALLER_PATH_MUST_BE_IGNORED"
        });
        let marker_attempt =
            linux_inventory_ipc_request(&webview, tauri::ipc::InvokeBody::Json(marker_body));
        let marker_output = hardware_document_from_ipc(&marker_attempt);
        assert!(
            marker_output == output,
            "caller JSON changed the parameter-free hardware document"
        );
        assert!(!output.contains("KERNAID_HARDWARE_CALLER_PATH_MUST_BE_IGNORED"));

        let digest = Sha256::digest([HASH_DOMAIN, output.as_bytes()].concat());
        println!("\nKERNAID_RESIDENT_LINUX_HARDWARE_IPC_V1 document_sha256={digest:x}");
    }

    fn macos_fixture_evidence() -> Vec<NativeDiagnosticEvidence> {
        let documents = [
            (
                "macos.storage.inventory",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/storage.json"),
            ),
            (
                "macos.apfs.capacity",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/apfs.json"),
            ),
            (
                "macos.launchd.state",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/launchd.json"),
            ),
            (
                "macos.network.state",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/network.json"),
            ),
            (
                "macos.software-update.state",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/updates.json"),
            ),
            (
                "macos.system-events.summary",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/events.json"),
            ),
            (
                "macos.startup.state",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/startup.json"),
            ),
            (
                "macos.snapshots.inventory",
                include_str!("../../../../packs/macos/fixtures/diagnostics/healthy/snapshots.json"),
            ),
        ];
        documents
            .into_iter()
            .enumerate()
            .map(|(index, (collector, content))| NativeDiagnosticEvidence {
                id: format!("E-MACOS-{}", index + 1),
                collector: collector.to_owned(),
                content: content.to_owned(),
            })
            .collect()
    }

    fn windows_fixture_evidence() -> Vec<NativeDiagnosticEvidence> {
        let documents = [
            (
                "windows.event-log.window",
                include_str!(
                    "../../../../packs/windows/fixtures/diagnostics/healthy/event-log.json"
                ),
            ),
            (
                "windows.reliability.records",
                include_str!(
                    "../../../../packs/windows/fixtures/diagnostics/healthy/reliability.json"
                ),
            ),
            (
                "windows.component-store.check-health",
                include_str!(
                    "../../../../packs/windows/fixtures/diagnostics/healthy/component-store.json"
                ),
            ),
            (
                "windows.sfc.verify-only",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/sfc.json"),
            ),
            (
                "windows.update.state",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/update.json"),
            ),
            (
                "windows.services.state",
                include_str!(
                    "../../../../packs/windows/fixtures/diagnostics/healthy/services.json"
                ),
            ),
            (
                "windows.network.state",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/network.json"),
            ),
            (
                "windows.drivers.state",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/drivers.json"),
            ),
            (
                "windows.bitlocker.state",
                include_str!(
                    "../../../../packs/windows/fixtures/diagnostics/healthy/bitlocker.json"
                ),
            ),
            (
                "windows.boot.state",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/boot.json"),
            ),
            (
                "windows.volumes.state",
                include_str!("../../../../packs/windows/fixtures/diagnostics/healthy/volumes.json"),
            ),
        ];
        documents
            .into_iter()
            .enumerate()
            .map(|(index, (collector, content))| NativeDiagnosticEvidence {
                id: format!("E-{}", index + 1),
                collector: collector.to_owned(),
                content: content.to_owned(),
            })
            .collect()
    }

    #[test]
    fn output_limits_are_parameterized_at_both_security_boundaries() {
        for maximum in [
            DEFAULT_MAX_OUTPUT_BYTES,
            QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES,
            QUALIFIED_MACOS_MAX_OUTPUT_BYTES,
        ] {
            let input = vec![b'x'; maximum + 1];
            let reader = read_bounded(std::io::Cursor::new(input), maximum);
            let bounded = received_output(Some(&reader));
            finish_reader(Some(reader));
            assert_eq!(bounded.bytes.len(), maximum);
            assert!(bounded.truncated);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn findmnt_empty_result_is_a_valid_empty_document() {
        let observation = fixed_command_with_policy(
            "test.findmnt-empty",
            "/usr/bin/findmnt",
            &["--json", "--list", "--types", "kernaid-no-such-filesystem"],
            COMMAND_TIMEOUT,
            Some("{\"filesystems\":[]}"),
        );
        assert!(observation.success);
        assert_eq!(observation.output, "{\"filesystems\":[]}");
        assert!(!observation.truncated);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collector_timeout_kills_a_stuck_process() {
        let observation = fixed_command_with_policy(
            "test.timeout",
            "/usr/bin/sleep",
            &["1"],
            Duration::from_millis(20),
            None,
        );
        assert!(!observation.success);
        assert!(observation.output.contains("timed out"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collector_timeout_kills_descendants_holding_output_pipes() {
        let started = Instant::now();
        let observation = fixed_command_with_policy(
            "test.descendant-timeout",
            "/bin/sh",
            &["-c", "sleep 30 & wait"],
            Duration::from_millis(20),
            None,
        );
        assert!(!observation.success);
        assert!(observation.output.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn inventory_fingerprint_matches_the_frontend_canonical_form() {
        let observations = vec![
            Observation {
                collector: "system.hostname",
                trust: "observed-untrusted",
                output: "host\n".into(),
                success: true,
                truncated: false,
            },
            Observation {
                collector: "linux.network.links",
                trust: "observed-untrusted",
                output: "changes are not identity".into(),
                success: true,
                truncated: false,
            },
            Observation {
                collector: "linux.block.inventory",
                trust: "observed-untrusted",
                output: "disks\n".into(),
                success: true,
                truncated: false,
            },
        ];
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(b"system.hostname\0host\n\0linux.block.inventory\0disks\n")
        );
        assert_eq!(inventory_fingerprint(&observations), expected);
    }

    #[test]
    fn a_changed_inventory_has_a_different_fingerprint() {
        let mut observations = vec![Observation {
            collector: "system.hostname",
            trust: "observed-untrusted",
            output: "before\n".into(),
            success: true,
            truncated: false,
        }];
        let before = inventory_fingerprint(&observations);
        observations[0].output = "after\n".into();
        assert_ne!(inventory_fingerprint(&observations), before);
    }

    #[test]
    fn authorization_rechecks_the_current_inventory_on_every_sequence() {
        let before = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let after = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let request = |sequence| ObserveRequest {
            session_id: "S-changing".into(),
            plan_id: "P-changing".into(),
            target_fingerprint: before.into(),
            sequence,
            action: "system.observe.noop".into(),
        };
        let mut brokers = HashMap::new();
        assert_eq!(
            authorize_observe_for_fingerprint(&mut brokers, before.into(), request(1)),
            Ok("observed")
        );
        assert_eq!(
            authorize_observe_for_fingerprint(&mut brokers, after.into(), request(2)),
            Err("Il target è cambiato: piano annullato, ripetere la diagnosi.".into())
        );
    }

    #[test]
    fn resident_windows_diagnosis_preserves_dynamic_evidence_ids() {
        let proposal = diagnose_windows_documents(windows_fixture_evidence())
            .expect("complete Windows evidence must diagnose");
        let ids = proposal["evidenceIds"]
            .as_array()
            .expect("proposal evidence IDs");
        assert_eq!(ids.len(), 11);
        assert_eq!(ids[0], "E-1");
        assert_eq!(ids[10], "E-11");
        assert!(
            !proposal["diagnosis"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("healthy")
        );
    }

    #[test]
    fn resident_windows_diagnosis_rejects_partial_or_duplicate_collectors() {
        let mut partial = windows_fixture_evidence();
        partial.pop();
        assert!(diagnose_windows_documents(partial).is_err());

        let mut duplicate = windows_fixture_evidence();
        duplicate[10].collector = duplicate[9].collector.clone();
        assert!(diagnose_windows_documents(duplicate).is_err());
    }

    #[test]
    fn resident_macos_diagnosis_preserves_dynamic_evidence_ids() {
        let proposal = diagnose_macos_documents(macos_fixture_evidence())
            .expect("complete macOS evidence must diagnose");
        let ids = proposal["evidenceIds"]
            .as_array()
            .expect("proposal evidence IDs");
        assert_eq!(ids.len(), 8);
        assert_eq!(ids[0], "E-MACOS-1");
        assert_eq!(ids[7], "E-MACOS-8");
        assert!(
            proposal["diagnosis"]
                .as_str()
                .unwrap_or_default()
                .contains("not a health certification")
        );
    }

    #[test]
    fn resident_macos_diagnosis_rejects_partial_duplicate_and_unknown_collectors() {
        let mut partial = macos_fixture_evidence();
        partial.pop();
        assert!(diagnose_macos_documents(partial).is_err());

        let mut duplicate = macos_fixture_evidence();
        duplicate[7].collector = duplicate[6].collector.clone();
        assert!(diagnose_macos_documents(duplicate).is_err());

        let mut unknown = macos_fixture_evidence();
        unknown[0].collector = "macos.command.arbitrary".to_owned();
        assert!(diagnose_macos_documents(unknown).is_err());
    }

    #[test]
    fn macos_failure_reason_tokens_are_closed_and_bounded() {
        let reasons = [
            MacosCollectorFailureReason::CommandUnavailable,
            MacosCollectorFailureReason::Timeout,
            MacosCollectorFailureReason::Truncated,
            MacosCollectorFailureReason::ReadFailed,
            MacosCollectorFailureReason::InvalidUtf8,
            MacosCollectorFailureReason::NonzeroExit,
            MacosCollectorFailureReason::StderrNonempty,
            MacosCollectorFailureReason::ProjectionInvalid,
            MacosCollectorFailureReason::ThreadFailed,
        ];
        assert_eq!(
            reasons.map(MacosCollectorFailureReason::token),
            [
                "command-unavailable",
                "timeout",
                "truncated",
                "read-failed",
                "invalid-utf8",
                "nonzero-exit",
                "stderr-nonempty",
                "projection-invalid",
                "thread-failed",
            ]
        );
        for token in reasons.map(MacosCollectorFailureReason::token) {
            assert!(token.len() <= 19);
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
        }
    }

    #[test]
    fn macos_command_failures_have_exact_privacy_safe_classes() {
        for (failure, expected) in [
            (
                FixedCommandFailure::Unavailable,
                MacosCollectorFailureReason::CommandUnavailable,
            ),
            (
                FixedCommandFailure::TimedOut,
                MacosCollectorFailureReason::Timeout,
            ),
            (
                FixedCommandFailure::Truncated,
                MacosCollectorFailureReason::Truncated,
            ),
            (
                FixedCommandFailure::ReadFailed,
                MacosCollectorFailureReason::ReadFailed,
            ),
            (
                FixedCommandFailure::InvalidUtf8,
                MacosCollectorFailureReason::InvalidUtf8,
            ),
        ] {
            assert_eq!(MacosCollectorFailureReason::from(failure), expected);
            assert!(
                matches!(complete_macos_command(Err(failure)), Err(reason) if reason == expected)
            );
        }

        let output = |exit_code, stderr: &str| FixedCommandOutput {
            stdout: "untrusted-observed-value".to_owned(),
            stderr: stderr.to_owned(),
            exit_code,
        };
        assert!(matches!(
            complete_macos_command(Ok(output(9, ""))),
            Err(MacosCollectorFailureReason::NonzeroExit)
        ));
        assert!(matches!(
            complete_macos_command(Ok(output(0, "localized warning"))),
            Err(MacosCollectorFailureReason::StderrNonempty)
        ));
        assert!(complete_macos_command(Ok(output(0, ""))).is_ok());

        // The route collector already treats exit one as its documented
        // no-default-route input and does not interpret localized stderr.
        assert!(complete_macos_route_command(Ok(output(1, "localized warning"))).is_ok());
        assert!(matches!(
            complete_macos_route_command(Ok(output(2, ""))),
            Err(MacosCollectorFailureReason::NonzeroExit)
        ));
    }

    #[test]
    fn macos_probe_labels_exist_only_for_failures_and_never_copy_output() {
        let success =
            MacosCollectorOutcome::success("macos.system", "untrusted-observed-value".to_owned());
        assert!(success.probe_failure_label().is_none());

        let failure = MacosCollectorOutcome::failure(
            "macos.storage.identity",
            MacosCollectorFailureReason::ProjectionInvalid,
        );
        assert_eq!(
            failure.probe_failure_label().as_deref(),
            Some("macos.storage.identity:reason=projection-invalid:truncated=false")
        );
        assert_eq!(
            failure.observation().output,
            "collector unavailable: macOS P0 evidence failed closed"
        );
        assert!(
            !failure
                .probe_failure_label()
                .expect("failure label")
                .contains("untrusted-observed-value")
        );

        let truncated = MacosCollectorOutcome::failure(
            "macos.storage.inventory",
            MacosCollectorFailureReason::Truncated,
        );
        assert_eq!(
            truncated.probe_failure_label().as_deref(),
            Some("macos.storage.inventory:reason=truncated:truncated=true")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resident_macos_native_runtime_probe() {
        use std::collections::BTreeSet;

        let quick = collect_macos_identity_outcomes();
        assert_eq!(quick.len(), 2);
        let quick_failures = quick
            .iter()
            .filter_map(MacosCollectorOutcome::probe_failure_label)
            .collect::<Vec<_>>();
        let observations = collect_macos_p0_outcomes();
        assert_eq!(observations.len(), macos_resident::COLLECTORS.len() + 2);
        let failed_collectors = observations
            .iter()
            .filter_map(MacosCollectorOutcome::probe_failure_label)
            .collect::<Vec<_>>();
        assert!(
            quick_failures.is_empty() && failed_collectors.is_empty(),
            "quick={quick_failures:?};deep={failed_collectors:?}"
        );
        assert_eq!(
            quick
                .iter()
                .map(|item| item.observation().collector)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["macos.storage.identity", "macos.system"])
        );
        let mut expected = macos_resident::COLLECTORS
            .into_iter()
            .collect::<BTreeSet<_>>();
        expected.extend(["macos.storage.identity", "macos.system"]);
        assert_eq!(
            observations
                .iter()
                .map(|item| item.observation().collector)
                .collect::<BTreeSet<_>>(),
            expected
        );

        let quick_identity = quick
            .iter()
            .map(MacosCollectorOutcome::observation)
            .find(|item| item.collector == "macos.storage.identity")
            .expect("quick storage identity");
        let diagnostic_identity = observations
            .iter()
            .map(MacosCollectorOutcome::observation)
            .find(|item| item.collector == "macos.storage.identity")
            .expect("diagnostic storage identity");
        assert!(
            quick_identity.output == diagnostic_identity.output,
            "native macOS storage identity projections differ"
        );

        let evidence = macos_resident::COLLECTORS
            .into_iter()
            .enumerate()
            .map(|(index, collector)| {
                let observation = observations
                    .iter()
                    .map(MacosCollectorOutcome::observation)
                    .find(|item| item.collector == collector)
                    .expect("exact native P0 collector");
                NativeDiagnosticEvidence {
                    id: format!("E-MACOS-NATIVE-{}", index + 1),
                    collector: collector.to_owned(),
                    content: observation.output.clone(),
                }
            })
            .collect();
        assert!(diagnose_macos_documents(evidence).is_ok());
    }
}
