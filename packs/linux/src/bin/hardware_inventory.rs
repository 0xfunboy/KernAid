#![forbid(unsafe_code)]

use kernaid_linux_pack::hardware::{collect_current_machine, to_bounded_json};
use std::{env, io::Write, process::ExitCode};

fn run(mut writer: impl Write) -> Result<(), ()> {
    let json = to_bounded_json(&collect_current_machine()).map_err(|_| ())?;
    writer.write_all(json.as_bytes()).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())
}

fn main() -> ExitCode {
    if env::args_os().nth(1).is_some() {
        eprintln!("error: this collector accepts no arguments");
        return ExitCode::from(2);
    }
    match run(std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("error: hardware inventory is unavailable");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_one_bounded_json_line() {
        let mut output = Vec::new();
        run(&mut output).expect("collect current hardware inventory");
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(output.last(), Some(&b'\n'));
        let parsed = kernaid_linux_pack::hardware::parse_bounded_json(&output)
            .expect("parse strict collector JSON");
        assert_eq!(parsed.kind, "linux-hardware-inventory");
    }
}
