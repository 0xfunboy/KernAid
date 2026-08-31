#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = kernaid_fleet_resident_work_orders::linux::run_from_args() {
        eprintln!(
            "KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=failed code={}",
            error.code()
        );
        std::process::exit(1);
    }
}
