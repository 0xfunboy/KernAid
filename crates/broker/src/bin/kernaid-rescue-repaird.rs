#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use kernaid_broker::{
    rescue_repair_service_engine::ProductionRepairEngine,
    rescue_repair_service_transport::run_activated_repair_service,
};
#[cfg(target_os = "linux")]
use kernaid_linux_systemd::take_single_named_socket;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().is_some() {
        eprintln!("kernaid-rescue-repaird: invalid configuration");
        return std::process::ExitCode::FAILURE;
    }
    let listener = match take_single_named_socket("repair-api") {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("kernaid-rescue-repaird: invalid socket activation");
            return std::process::ExitCode::FAILURE;
        }
    };
    let engine = match ProductionRepairEngine::from_systemd_qualification_credential() {
        Ok(engine) => engine,
        Err(_) => {
            eprintln!("kernaid-rescue-repaird: invalid configuration");
            return std::process::ExitCode::FAILURE;
        }
    };
    match run_activated_repair_service(listener, engine) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kernaid-rescue-repaird: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("kernaid-rescue-repaird: unsupported platform");
    std::process::ExitCode::FAILURE
}
