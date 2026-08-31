use kernaid_linux_pack::filesystem_health::{
    collect_current_root, collect_selected, to_bounded_json,
};
use std::{
    env,
    io::{self, Write},
    process,
};

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let snapshot = match arguments.as_slice() {
        [] => collect_current_root(),
        [flag, target_ref, filesystem, major_minor] if flag == "--selected" => {
            match collect_selected(target_ref, filesystem, major_minor) {
                Ok(snapshot) => snapshot,
                Err(_) => fail(),
            }
        }
        _ => fail(),
    };
    let output = to_bounded_json(&snapshot).unwrap_or_else(|_| fail());
    if io::stdout().write_all(output.as_bytes()).is_err() {
        process::exit(1);
    }
}

fn fail() -> ! {
    eprintln!("error: normalized filesystem health is unavailable");
    process::exit(1)
}
