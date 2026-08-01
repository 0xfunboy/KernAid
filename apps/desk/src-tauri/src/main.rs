#![forbid(unsafe_code)]

use serde::Serialize;
use std::process::Command;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    collector: &'static str,
    trust: &'static str,
    output: String,
    success: bool,
}

fn bounded_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}

fn fixed_command(collector: &'static str, program: &str, args: &[&str]) -> Observation {
    match Command::new(program).args(args).output() {
        Ok(result) => Observation {
            collector,
            trust: "observed-untrusted",
            output: bounded_utf8(&result.stdout),
            success: result.status.success(),
        },
        Err(error) => Observation {
            collector,
            trust: "observed-untrusted",
            output: format!("collector unavailable: {error}"),
            success: false,
        },
    }
}

#[tauri::command]
fn collect_local_inventory() -> Vec<Observation> {
    let mut observations = vec![fixed_command("system.hostname", "hostname", &[])];
    #[cfg(target_os = "linux")]
    {
        observations.push(fixed_command(
            "linux.block.inventory",
            "lsblk",
            &[
                "--json",
                "--bytes",
                "--output",
                "NAME,TYPE,SIZE,RO,TRAN,FSTYPE,MOUNTPOINTS,MODEL",
            ],
        ));
        observations.push(fixed_command(
            "linux.network.links",
            "ip",
            &["-json", "link"],
        ));
        observations.push(fixed_command(
            "linux.failed.units",
            "systemctl",
            &["--failed", "--no-pager", "--plain"],
        ));
    }
    #[cfg(target_os = "windows")]
    {
        observations.push(fixed_command("windows.system", "cmd", &["/C", "ver"]));
        observations.push(fixed_command("windows.network", "ipconfig", &["/all"]));
        observations.push(fixed_command("windows.disks", "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-Disk | Select-Object Number,FriendlyName,BusType,HealthStatus,OperationalStatus,Size,IsReadOnly | ConvertTo-Json -Compress"]));
    }
    #[cfg(target_os = "macos")]
    {
        observations.push(fixed_command("macos.system", "sw_vers", &[]));
        observations.push(fixed_command(
            "macos.disks",
            "diskutil",
            &["list", "-plist"],
        ));
        observations.push(fixed_command(
            "macos.network",
            "networksetup",
            &["-listallhardwareports"],
        ));
    }
    observations
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![collect_local_inventory])
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
}
