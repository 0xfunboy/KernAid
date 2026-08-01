#![forbid(unsafe_code)]

mod secure_runtime;

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
use std::{
    collections::HashMap,
    io::Read,
    process::{Child, Command, Stdio},
    sync::{
        Mutex, MutexGuard,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{Manager, State};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_BROKER_SESSIONS: usize = 1_024;
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

fn read_bounded(mut reader: impl Read + Send + 'static) -> Receiver<BoundedRead> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(MAX_OUTPUT_BYTES);
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
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(remaining)]);
            truncated |= read > remaining;
        }
        let _ = sender.send(BoundedRead {
            bytes: retained,
            truncated,
            failed,
        });
    });
    receiver
}

fn received_output(receiver: Option<Receiver<BoundedRead>>) -> BoundedRead {
    match receiver {
        Some(receiver) => receiver
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

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let process_group = rustix::process::Pid::from_child(child);
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::TERM);
        let deadline = Instant::now() + TERMINATION_GRACE;
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
}

fn fixed_command(collector: &'static str, program: &str, args: &[&str]) -> Observation {
    fixed_command_with_policy(collector, program, args, COMMAND_TIMEOUT, None)
}

fn fixed_command_with_policy(
    collector: &'static str,
    program: &str,
    args: &[&str],
    timeout: Duration,
    empty_exit_one_output: Option<&'static str>,
) -> Observation {
    let mut command = Command::new(program);
    command.args(args).env_clear();
    #[cfg(unix)]
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .process_group(0);
    #[cfg(windows)]
    command
        .env("SystemRoot", r"C:\Windows")
        .env("WINDIR", r"C:\Windows");
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return Observation {
                collector,
                trust: "observed-untrusted",
                output: format!("collector unavailable: {error}"),
                success: false,
                truncated: false,
            };
        }
    };
    let stdout = child.stdout.take().map(read_bounded);
    let stderr = child.stderr.take().map(read_bounded);
    let deadline = Instant::now() + timeout;
    let (exit_status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                terminate_child(&mut child);
                break (None, true);
            }
            Err(error) => {
                terminate_child(&mut child);
                return Observation {
                    collector,
                    trust: "observed-untrusted",
                    output: format!("collector unavailable: {error}"),
                    success: false,
                    truncated: false,
                };
            }
        }
    };
    let output = received_output(stdout);
    let error_output = received_output(stderr);
    let truncated = output.truncated || error_output.truncated;
    let read_failed = output.failed || error_output.failed;
    if read_failed {
        terminate_child(&mut child);
    }
    let empty_no_match = !timed_out
        && exit_status
            .as_ref()
            .and_then(std::process::ExitStatus::code)
            == Some(1)
        && output.bytes.is_empty()
        && error_output.bytes.is_empty()
        && empty_exit_one_output.is_some();
    let utf8_output = String::from_utf8(output.bytes).ok();
    let command_succeeded = exit_status.as_ref().is_some_and(|status| status.success());
    let success = (command_succeeded || empty_no_match)
        && !truncated
        && !read_failed
        && utf8_output.is_some();
    let safe_output = if empty_no_match {
        empty_exit_one_output.unwrap_or_default().to_owned()
    } else if success {
        utf8_output.unwrap_or_default()
    } else if timed_out {
        "collector unavailable: command timed out".to_owned()
    } else if truncated {
        "collector unavailable: output exceeded the safety limit".to_owned()
    } else if read_failed {
        "collector unavailable: output could not be read safely".to_owned()
    } else if utf8_output.is_none() {
        "collector unavailable: output is not valid UTF-8".to_owned()
    } else {
        "collector unavailable: command failed".to_owned()
    };
    Observation {
        collector,
        trust: "observed-untrusted",
        output: safe_output,
        success,
        truncated,
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
    if metadata.len() > MAX_OUTPUT_BYTES as u64 {
        return Observation {
            collector: "linux.fstab",
            trust: "observed-untrusted",
            output: "collector unavailable: output exceeded the safety limit".to_owned(),
            success: false,
            truncated: true,
        };
    }
    let bounded = received_output(Some(read_bounded(file)));
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
        Ok(output) if output.len() <= MAX_OUTPUT_BYTES => Observation {
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

#[tauri::command]
fn collect_local_inventory() -> Vec<Observation> {
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
        observations.push(fixed_command(
            "system.hostname",
            r"C:\Windows\System32\hostname.exe",
            &[],
        ));
        observations.push(fixed_command(
            "windows.network",
            r"C:\Windows\System32\ipconfig.exe",
            &["/all"],
        ));
        observations.push(fixed_command("windows.disks", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", "Get-Disk | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,Size,IsReadOnly,UniqueId,SerialNumber,Guid,PartitionStyle | ConvertTo-Json -Compress"]));
        observations.push(fixed_command(
            "windows.system",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Environment]::OSVersion.VersionString",
            ],
        ));
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
        return serde_json::to_value(proposal_from_report(&report))
            .map_err(|_| "La diagnosi Linux non è serializzabile.".to_owned());
    }

    #[cfg(not(target_os = "linux"))]
    {
        for document in evidence {
            drop((document.id, document.collector, document.content));
        }
        Err("Il corpus Linux è disponibile solo su sistemi Linux.".to_owned())
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
fn authorize_observe(
    state: State<'_, ObserveBrokers>,
    request: ObserveRequest,
) -> Result<&'static str, String> {
    let current_fingerprint = inventory_fingerprint(&collect_local_inventory());
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
            diagnose_linux_p0,
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
    #[test]
    fn output_is_bounded() {
        let input = vec![b'x'; MAX_OUTPUT_BYTES + 100];
        let bounded = received_output(Some(read_bounded(std::io::Cursor::new(input))));
        assert_eq!(bounded.bytes.len(), MAX_OUTPUT_BYTES);
        assert!(bounded.truncated);
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
}
