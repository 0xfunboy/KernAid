#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use kernaid_rescue_secrets::run_rescue_vault_companion;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run_rescue_vault_companion(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("kernaid-rescue-vaultctl: unsupported platform");
    std::process::ExitCode::FAILURE
}
