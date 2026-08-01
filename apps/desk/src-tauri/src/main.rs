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
use std::{
    collections::HashMap,
    io::Read,
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};
use tauri::{Manager, State};

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_BROKER_SESSIONS: usize = 1_024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    collector: &'static str,
    trust: &'static str,
    output: String,
    success: bool,
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

#[derive(Default)]
struct ObserveBrokers(Mutex<HashMap<String, ObserveBroker>>);

fn bounded_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}

fn read_bounded(mut reader: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(MAX_OUTPUT_BYTES);
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        retained
    })
}

fn joined_output(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    match handle {
        Some(handle) => handle.join().unwrap_or_default(),
        None => Vec::new(),
    }
}

fn fixed_command(collector: &'static str, program: &str, args: &[&str]) -> Observation {
    fixed_command_with_timeout(collector, program, args, COMMAND_TIMEOUT)
}

fn fixed_command_with_timeout(
    collector: &'static str,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Observation {
    let mut child = match Command::new(program)
        .args(args)
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
            };
        }
    };
    let stdout = child.stdout.take().map(read_bounded);
    let stderr = child.stderr.take().map(read_bounded);
    let deadline = Instant::now() + timeout;
    let (success, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.success(), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break (false, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Observation {
                    collector,
                    trust: "observed-untrusted",
                    output: format!("collector unavailable: {error}"),
                    success: false,
                };
            }
        }
    };
    let mut output = joined_output(stdout);
    let error_output = joined_output(stderr);
    if !error_output.is_empty() && output.len() < MAX_OUTPUT_BYTES {
        if !output.is_empty() {
            output.push(b'\n');
        }
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.len());
        output.extend_from_slice(&error_output[..error_output.len().min(remaining)]);
    }
    if timed_out {
        let suffix = b"\ncollector unavailable: command timed out";
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.len());
        output.extend_from_slice(&suffix[..suffix.len().min(remaining)]);
    }
    Observation {
        collector,
        trust: "observed-untrusted",
        output: bounded_utf8(&output),
        success,
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
                "NAME,KNAME,MAJ:MIN,TYPE,SIZE,RO,TRAN,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,WWN,UUID,PARTUUID,PTUUID",
            ],
        ));
        observations.push(fixed_command(
            "linux.network.links",
            "/usr/sbin/ip",
            &["-json", "link"],
        ));
        observations.push(fixed_command(
            "linux.failed.units",
            "/usr/bin/systemctl",
            &["--failed", "--no-pager", "--plain"],
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
        assert_eq!(bounded_utf8(&input).len(), MAX_OUTPUT_BYTES);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collector_timeout_kills_a_stuck_process() {
        let observation = fixed_command_with_timeout(
            "test.timeout",
            "/usr/bin/sleep",
            &["1"],
            Duration::from_millis(20),
        );
        assert!(!observation.success);
        assert!(observation.output.contains("timed out"));
    }

    #[test]
    fn inventory_fingerprint_matches_the_frontend_canonical_form() {
        let observations = vec![
            Observation {
                collector: "system.hostname",
                trust: "observed-untrusted",
                output: "host\n".into(),
                success: true,
            },
            Observation {
                collector: "linux.network.links",
                trust: "observed-untrusted",
                output: "changes are not identity".into(),
                success: true,
            },
            Observation {
                collector: "linux.block.inventory",
                trust: "observed-untrusted",
                output: "disks\n".into(),
                success: true,
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
