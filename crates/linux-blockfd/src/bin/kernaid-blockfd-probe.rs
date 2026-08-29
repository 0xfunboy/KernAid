#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
use std::{io, process::ExitCode};

#[cfg(target_os = "linux")]
fn run() -> io::Result<()> {
    if std::env::args_os().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "arguments are not accepted",
        ));
    }

    let input = io::stdin();
    let properties = kernaid_linux_blockfd::probe(&input)?;
    let output = io::stdout();
    let mut output = output.lock();
    kernaid_linux_blockfd::write_probe(&mut output, properties)
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kernaid-blockfd-probe: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
