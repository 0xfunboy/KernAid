#![forbid(unsafe_code)]

use kernaid_device_identity::{
    IdentityError, SignedReportEnvelope, decode_public_key_base64url, device_id_for_public_key,
    validate_device_id,
};
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_ENVELOPE_BYTES: u64 = 2 * 1024 * 1024;
const HELP: &str = "\
Verify a KernAid signed report without revealing its payload.

Usage:
  kernaid-verify-report --device-id KA-<24 lowercase hex> [--public-key <base64url>] <report.json>
  kernaid-verify-report --public-key <canonical unpadded base64url> <report.json>

At least one trust anchor is required. If both are supplied, they must match.
The trusted value must come from enrollment or another authenticated channel,
not from the report being checked. Report input is limited to 2 MiB.
";

#[derive(Debug, PartialEq, Eq)]
enum CliError {
    Usage,
    InvalidTrustAnchor,
    Input,
    OversizedInput,
    InvalidEnvelope,
    Verification,
    Output,
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage | Self::InvalidTrustAnchor => 2,
            Self::Input | Self::OversizedInput => 3,
            Self::InvalidEnvelope => 4,
            Self::Verification => 5,
            Self::Output => 6,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::Usage => "invalid command line; use --help",
            Self::InvalidTrustAnchor => "invalid or conflicting trust anchor",
            Self::Input => "could not safely read the report file",
            Self::OversizedInput => "report file exceeds the 2 MiB limit",
            Self::InvalidEnvelope => "report is not a valid KernAid envelope",
            Self::Verification => "report authenticity verification failed",
            Self::Output => "could not write verification result",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct VerifyArgs {
    input: PathBuf,
    device_id: Option<String>,
    public_key: Option<String>,
}

enum Command {
    Help,
    Version,
    Verify(VerifyArgs),
}

fn parse_args<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = args.into_iter();
    let mut input = None;
    let mut device_id = None;
    let mut public_key = None;
    let mut informational = None;

    while let Some(value) = values.next() {
        if value == "--help" || value == "-h" {
            if informational.replace(Command::Help).is_some() {
                return Err(CliError::Usage);
            }
        } else if value == "--version" || value == "-V" {
            if informational.replace(Command::Version).is_some() {
                return Err(CliError::Usage);
            }
        } else if value == "--device-id" {
            if device_id.is_some() {
                return Err(CliError::Usage);
            }
            device_id = Some(
                values
                    .next()
                    .ok_or(CliError::Usage)?
                    .into_string()
                    .map_err(|_| CliError::InvalidTrustAnchor)?,
            );
        } else if value == "--public-key" {
            if public_key.is_some() {
                return Err(CliError::Usage);
            }
            public_key = Some(
                values
                    .next()
                    .ok_or(CliError::Usage)?
                    .into_string()
                    .map_err(|_| CliError::InvalidTrustAnchor)?,
            );
        } else {
            if value.to_string_lossy().starts_with('-') || input.is_some() {
                return Err(CliError::Usage);
            }
            input = Some(PathBuf::from(value));
        }
    }

    if let Some(command) = informational {
        if input.is_some() || device_id.is_some() || public_key.is_some() {
            return Err(CliError::Usage);
        }
        return Ok(command);
    }
    if device_id.is_none() && public_key.is_none() {
        return Err(CliError::Usage);
    }
    Ok(Command::Verify(VerifyArgs {
        input: input.ok_or(CliError::Usage)?,
        device_id,
        public_key,
    }))
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|_| CliError::Input)?;
    let metadata = file.metadata().map_err(|_| CliError::Input)?;
    if !metadata.is_file() {
        return Err(CliError::Input);
    }
    if metadata.len() > MAX_ENVELOPE_BYTES {
        return Err(CliError::OversizedInput);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::Input)?;
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(CliError::OversizedInput);
    }
    Ok(bytes)
}

fn verify(args: VerifyArgs, output: &mut impl Write) -> Result<(), CliError> {
    let expected_device_id = match args.device_id.as_deref() {
        Some(device_id) => {
            validate_device_id(device_id).map_err(|_| CliError::InvalidTrustAnchor)?;
            Some(device_id)
        }
        None => None,
    };
    let expected_public_key = args
        .public_key
        .as_deref()
        .map(decode_public_key_base64url)
        .transpose()
        .map_err(|_| CliError::InvalidTrustAnchor)?;
    if let (Some(device_id), Some(public_key)) = (expected_device_id, expected_public_key.as_ref())
        && device_id_for_public_key(public_key) != device_id
    {
        return Err(CliError::InvalidTrustAnchor);
    }

    let input = read_bounded_regular_file(&args.input)?;
    let envelope: SignedReportEnvelope =
        serde_json::from_slice(&input).map_err(|_| CliError::InvalidEnvelope)?;
    let payload = envelope
        .verify_with_trust_anchors(expected_device_id, expected_public_key.as_ref())
        .map_err(map_verification_error)?;

    writeln!(
        output,
        "VERIFIED\ndevice-id: {}\njournal-sequence: {}\npayload-sha256: {}\npayload-bytes: {}",
        envelope.device_id,
        envelope.journal_sequence,
        envelope.payload_sha256,
        payload.len()
    )
    .map_err(|_| CliError::Output)
}

fn map_verification_error(_error: IdentityError) -> CliError {
    CliError::Verification
}

fn run<I>(args: I, output: &mut impl Write) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    match parse_args(args)? {
        Command::Help => output
            .write_all(HELP.as_bytes())
            .map_err(|_| CliError::Output),
        Command::Version => writeln!(
            output,
            "kernaid-verify-report {}",
            env!("CARGO_PKG_VERSION")
        )
        .map_err(|_| CliError::Output),
        Command::Verify(args) => verify(args, output),
    }
}

fn main() -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match run(env::args_os().skip(1), &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let stderr = io::stderr();
            let mut diagnostic = stderr.lock();
            let _ = writeln!(diagnostic, "error: {}", error.message());
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_device_identity::DeviceIdentity;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

    struct TempReport(PathBuf);

    impl TempReport {
        fn write(bytes: &[u8]) -> Self {
            let number = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "kernaid-verify-report-test-{}-{number}.json",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("write temporary report");
            Self(path)
        }
    }

    impl Drop for TempReport {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn envelope(identity: &DeviceIdentity) -> SignedReportEnvelope {
        identity
            .sign_report_envelope(
                br#"{"private":"payload must not be printed"}"#,
                "application/json",
                7,
                &[0x55; 32],
            )
            .expect("sign envelope")
    }

    fn invoke(args: Vec<OsString>) -> Result<String, CliError> {
        let mut output = Vec::new();
        run(args, &mut output)?;
        String::from_utf8(output).map_err(|_| CliError::Output)
    }

    #[test]
    fn arguments_require_exactly_one_file_and_at_least_one_anchor() {
        assert!(matches!(parse_args([]), Err(CliError::Usage)));
        assert!(matches!(
            parse_args([OsString::from("report.json")]),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse_args([
                OsString::from("--device-id"),
                OsString::from("KA-0123456789abcdef01234567"),
                OsString::from("--device-id"),
                OsString::from("KA-0123456789abcdef01234567"),
                OsString::from("report.json"),
            ]),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse_args([OsString::from("--unknown"), OsString::from("report.json")]),
            Err(CliError::Usage)
        ));
    }

    #[test]
    fn verified_output_does_not_include_payload() {
        let identity = DeviceIdentity::generate();
        let report = TempReport::write(
            &serde_json::to_vec(&envelope(&identity)).expect("serialize envelope"),
        );
        let output = invoke(vec![
            OsString::from("--device-id"),
            OsString::from(identity.device_id()),
            report.0.clone().into_os_string(),
        ])
        .expect("verify report");

        assert!(output.starts_with("VERIFIED\n"));
        assert!(!output.contains("private"));
        assert!(!output.contains("payload must not be printed"));
    }

    #[test]
    fn tampered_report_is_rejected_with_sanitized_error() {
        let identity = DeviceIdentity::generate();
        let mut signed = envelope(&identity);
        signed.journal_sequence += 1;
        let report = TempReport::write(&serde_json::to_vec(&signed).expect("serialize envelope"));
        let result = invoke(vec![
            OsString::from("--device-id"),
            OsString::from(identity.device_id()),
            report.0.clone().into_os_string(),
        ]);

        assert_eq!(result, Err(CliError::Verification));
        assert_eq!(CliError::Verification.exit_code(), 5);
        assert_eq!(
            CliError::Verification.message(),
            "report authenticity verification failed"
        );
    }

    #[test]
    fn substituted_key_is_not_accepted_from_envelope() {
        let trusted = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let report = TempReport::write(
            &serde_json::to_vec(&envelope(&attacker)).expect("serialize envelope"),
        );

        assert_eq!(
            invoke(vec![
                OsString::from("--device-id"),
                OsString::from(trusted.device_id()),
                report.0.clone().into_os_string(),
            ]),
            Err(CliError::Verification)
        );
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let report = TempReport::write(b"");
        let file = File::options()
            .write(true)
            .open(&report.0)
            .expect("open temporary report");
        file.set_len(MAX_ENVELOPE_BYTES + 1)
            .expect("make sparse oversized report");
        let result = invoke(vec![
            OsString::from("--device-id"),
            OsString::from("KA-0123456789abcdef01234567"),
            report.0.clone().into_os_string(),
        ]);

        assert_eq!(result, Err(CliError::OversizedInput));
        assert_eq!(CliError::OversizedInput.exit_code(), 3);
    }

    #[test]
    fn conflicting_explicit_anchors_are_rejected_before_input() {
        let first = DeviceIdentity::generate();
        let second = DeviceIdentity::generate();
        let result = invoke(vec![
            OsString::from("--device-id"),
            OsString::from(first.device_id()),
            OsString::from("--public-key"),
            OsString::from(envelope(&second).public_key),
            OsString::from("does-not-need-to-exist.json"),
        ]);

        assert_eq!(result, Err(CliError::InvalidTrustAnchor));
        assert_eq!(CliError::InvalidTrustAnchor.exit_code(), 2);
    }
}
