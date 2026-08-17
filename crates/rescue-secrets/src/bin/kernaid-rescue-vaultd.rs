#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use kernaid_rescue_secrets::{run_internal_rescue_vault_worker, run_rescue_vault_daemon};

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let result = match arguments.next() {
        Some(argument) if argument == "--internal-worker" && arguments.next().is_none() => {
            run_internal_rescue_vault_worker()
        }
        None => run_rescue_vault_daemon(),
        Some(_) => Err(kernaid_rescue_secrets::RescueVaultDaemonError::InvalidConfiguration),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kernaid-rescue-vaultd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("kernaid-rescue-vaultd: unsupported platform");
    std::process::ExitCode::FAILURE
}
