use kernaid_linux_pack::boot_critical_path::{collect_current_machine, to_bounded_json};
use std::io::{self, Write};

fn main() {
    let snapshot = collect_current_machine();
    let output = match to_bounded_json(&snapshot) {
        Ok(output) => output,
        Err(_) => {
            eprintln!("error: normalized boot critical path is unavailable");
            std::process::exit(1);
        }
    };
    if io::stdout().write_all(output.as_bytes()).is_err() {
        std::process::exit(1);
    }
}
