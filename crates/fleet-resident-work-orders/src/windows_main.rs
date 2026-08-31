#![forbid(unsafe_code)]

#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("KernAid Fleet Resident Windows v1 supports only Windows x86-64");

#[cfg(windows)]
fn main() {
    if let Err(error) = kernaid_fleet_resident_work_orders::windows::run_from_args() {
        eprintln!(
            "KERNAID_FLEET_RESIDENT_WINDOWS_V1 status=failed code={}",
            error.code()
        );
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("KernAid Fleet Resident Windows is available only on Windows x86-64.");
    std::process::exit(2);
}
