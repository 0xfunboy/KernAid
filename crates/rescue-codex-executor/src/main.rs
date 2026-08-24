#![forbid(unsafe_code)]

#[cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]
fn main() -> std::process::ExitCode {
    match kernaid_rescue_codex_executor::run_socket_activated_once() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(all(target_os = "linux", feature = "experimental-codex-exec")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
