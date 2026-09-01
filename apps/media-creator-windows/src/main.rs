#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod windows_backend;
#[cfg(windows)]
mod wizard;

#[cfg(windows)]
fn main() {
    if let Err(error) = wizard::run() {
        wizard::show_fatal_error(&format!("KernAid Media Creator stopped safely.\n\n{error}"));
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("KernAid Media Creator is available only for Windows x86-64.");
    std::process::exit(2);
}
