#![forbid(unsafe_code)]

#[cfg(all(
    target_os = "macos",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("KernAid Fleet Resident macOS v1 supports only x86-64 and Apple silicon");

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = kernaid_fleet_resident_work_orders::macos::run_from_args() {
        eprintln!(
            "KERNAID_FLEET_RESIDENT_MACOS_V1 status=failed code={}",
            error.code()
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("KernAid Fleet Resident macOS is available only on macOS.");
    std::process::exit(2);
}
