#![forbid(unsafe_code)]

use kernaid_linux_pack::snapshot::collect_repository_fixture_snapshot;
use std::{env, io::Write, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(fixture) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        return ExitCode::from(2);
    }
    let Ok(envelope) = collect_repository_fixture_snapshot(&fixture) else {
        return ExitCode::from(3);
    };
    let Ok(encoded) = envelope.canonical_json() else {
        return ExitCode::from(4);
    };
    if std::io::stdout().lock().write_all(&encoded).is_err() {
        return ExitCode::from(5);
    }
    ExitCode::SUCCESS
}
