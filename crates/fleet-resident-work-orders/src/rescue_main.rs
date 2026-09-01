#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = kernaid_fleet_resident_work_orders::rescue_service::run_from_args() {
        eprintln!(
            "KERNAID_FLEET_RESCUE_REPAIR_V1 status=failed code={}",
            error.code()
        );
        std::process::exit(1);
    }
}
