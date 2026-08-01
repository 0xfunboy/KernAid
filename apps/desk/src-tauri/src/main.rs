#![forbid(unsafe_code)]

mod secure_runtime;
mod windows_resident;

use kernaid_broker::{BrokerError, ObserveBroker};
use kernaid_protocol::BrokerRequest;
use secure_runtime::{
    SecureRuntime, append_audit_record, initialize_device_identity, seal_signed_report,
    secure_runtime_status,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::Child;
use std::{
    collections::HashMap,
    io::{self, Read},
    process::{ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Mutex, MutexGuard,
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tauri::{Manager, State};

#[cfg(any(unix, test))]
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "windows", test))]
const QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_BROKER_SESSIONS: usize = 1_024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fixed_command(collector: &'static str, program: &str, args: &[&str]) -> Observation {
    fixed_command_with_policy(collector, program, args, COMMAND_TIMEOUT, None)
}

struct FixedCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[derive(Clone, Copy)]
enum FixedCommandFailure {
    Unavailable,
    TimedOut,
    Truncated,
    ReadFailed,
    InvalidUtf8,
}

impl FixedCommandFailure {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "collector unavailable: command failed",
            Self::TimedOut => "collector unavailable: command timed out",
            Self::Truncated => "collector unavailable: output exceeded the safety limit",
            Self::ReadFailed => "collector unavailable: output could not be read safely",
            Self::InvalidUtf8 => "collector unavailable: output is not valid UTF-8",
        }
    }

    const fn truncated(self) -> bool {
        matches!(self, Self::Truncated)
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

fn collect_local_inventory_sync() -> Vec<Observation> {
    let mut observations: Vec<Observation> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        observations.push(fixed_command("system.hostname", "/usr/bin/hostname", &[]));
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
        observations.push(fixed_command("system.hostname", "/bin/hostname", &[]));
        observations.push(fixed_command("macos.system", "/usr/bin/sw_vers", &[]));
        observations.push(fixed_command(
            "macos.disks",
            "/usr/sbin/diskutil",
            &["list", "-plist"],
        ));
        observations.push(fixed_command(
            "macos.network",
            "/usr/sbin/networksetup",
            &["-listallhardwareports"],
        ));
        observations.push(fixed_command(
            "macos.storage.identity",
            "/usr/sbin/ioreg",
            &["-r", "-c", "IOBlockStorageDevice", "-l"],
        ));
    }
    observations
}

#[tauri::command]
async fn collect_local_inventory() -> Result<Vec<Observation>, String> {
    tauri::async_runtime::spawn_blocking(collect_local_inventory_sync)
        .await
        .map_err(|_| "L’inventario locale non è stato completato.".to_owned())
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

fn main() {
    tauri::Builder::default()
        .manage(ObserveBrokers::default())
        .setup(|app| {
            let app_data_directory = app.path().app_data_dir()?;
            let runtime = SecureRuntime::open(&app_data_directory)?;
            app.manage(runtime);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            collect_local_inventory,
            collect_windows_p0_inventory,
            diagnose_linux_p0,
            diagnose_windows_p0,
            authorize_observe,
            secure_runtime_status,
            initialize_device_identity,
            append_audit_record,
            seal_signed_report
        ])
        .run(tauri::generate_context!())
        .expect("failed to run KernAid Desk");
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for maximum in [DEFAULT_MAX_OUTPUT_BYTES, QUALIFIED_WINDOWS_MAX_OUTPUT_BYTES] {
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
}
