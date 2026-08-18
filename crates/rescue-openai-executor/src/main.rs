#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match kernaid_rescue_openai_executor::run_socket_activated_once() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
