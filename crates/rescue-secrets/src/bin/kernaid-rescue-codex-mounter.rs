#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("kernaid-rescue-codex-mounter: invalid Rescue vault daemon configuration");
        return std::process::ExitCode::FAILURE;
    }
    match kernaid_rescue_secrets::run_rescue_codex_mounter() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kernaid-rescue-codex-mounter: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("kernaid-rescue-codex-mounter: unsupported platform");
    std::process::ExitCode::FAILURE
}
