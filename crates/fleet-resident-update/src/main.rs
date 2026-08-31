#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = kernaid_fleet_resident_update::linux::run_from_args() {
        eprintln!(
            "KERNAID_FLEET_RESIDENT_UPDATE_V1 status=error code={}",
            error.code()
        );
        std::process::exit(1);
    }
}
