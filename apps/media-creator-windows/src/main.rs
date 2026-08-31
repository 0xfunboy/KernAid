#[cfg(windows)]
mod windows_backend;

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_backend::run() {
        eprintln!("KernAid Media Creator stopped safely: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("KernAid Media Creator is available only for Windows x86-64.");
    std::process::exit(2);
}
