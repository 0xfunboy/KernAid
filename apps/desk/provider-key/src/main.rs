#![forbid(unsafe_code)]

use kernaid_desk_shell::resident_openai_credentials::{
    RESIDENT_PROVIDER_PROFILE, ResidentProviderCredentialStatus, ResidentProviderCredentials,
    default_app_data_directory,
};
use kernaid_native_secrets::NativeProviderKind;
use std::{
    env,
    io::{self, IsTerminal as _},
    process::ExitCode,
};
use zeroize::{Zeroize as _, Zeroizing};

enum Operation {
    Configure,
    Status,
    Logout,
}

struct Arguments {
    operation: Operation,
    provider: NativeProviderKind,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let arguments = parse_arguments(env::args_os().skip(1))?;
    let app_data_directory = default_app_data_directory().map_err(
        |_| "KernAid provider setup could not resolve the private application directory.",
    )?;
    let credentials = ResidentProviderCredentials::open(&app_data_directory, arguments.provider)
        .map_err(|_| "KernAid provider setup could not open the protected credential store. Close KernAid Desk and retry.")?;
    let provider_label = provider_label(arguments.provider);

    match arguments.operation {
        Operation::Status => {
            let status = credentials
                .status()
                .map_err(|_| "KernAid could not verify the provider credential status.")?;
            println!(
                "{provider_label} profile {RESIDENT_PROVIDER_PROFILE}: {}",
                match status {
                    ResidentProviderCredentialStatus::Absent => "absent",
                    ResidentProviderCredentialStatus::Configured => "configured",
                }
            );
        }
        Operation::Logout => {
            credentials
                .logout()
                .map_err(|_| "KernAid could not verify removal of the provider credential.")?;
            println!("{provider_label} profile {RESIDENT_PROVIDER_PROFILE}: absent");
        }
        Operation::Configure => configure(&credentials, arguments.provider)?,
    }
    Ok(())
}

fn configure(
    credentials: &ResidentProviderCredentials,
    provider: NativeProviderKind,
) -> Result<(), &'static str> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(
            "Provider setup requires an interactive native terminal; the key is never accepted through argv, stdin pipes, files, or environment variables.",
        );
    }
    let provider_label = provider_label(provider);
    let mut first = Zeroizing::new(
        rpassword::prompt_password(format!("{provider_label} API key: "))
            .map_err(|_| "KernAid could not read the key from the native terminal.")?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password(format!("Repeat {provider_label} API key: "))
            .map_err(|_| "KernAid could not read the confirmation from the native terminal.")?,
    );
    if first.as_bytes() != second.as_bytes() {
        return Err("The two provider API key entries do not match.");
    }
    let bytes = Zeroizing::new(first.as_bytes().to_vec());
    first.zeroize();
    credentials
        .configure(bytes)
        .map_err(|_| "KernAid rejected or could not verify the provider credential.")?;
    println!("{provider_label} profile {RESIDENT_PROVIDER_PROFILE}: configured");
    Ok(())
}

fn parse_arguments(
    mut values: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Arguments, &'static str> {
    let operation = match values
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("configure") => Operation::Configure,
        Some("status") => Operation::Status,
        Some("logout") => Operation::Logout,
        _ => return Err(usage()),
    };
    let provider = match values.next() {
        None => NativeProviderKind::OpenAi,
        Some(flag) if flag == "--provider" => match values
            .next()
            .and_then(|value| value.into_string().ok())
            .as_deref()
        {
            Some("openai") => NativeProviderKind::OpenAi,
            Some("anthropic") => NativeProviderKind::Anthropic,
            Some("gemini") => NativeProviderKind::Gemini,
            _ => return Err(usage()),
        },
        Some(_) => return Err(usage()),
    };
    if values.next().is_some() {
        return Err(usage());
    }
    Ok(Arguments {
        operation,
        provider,
    })
}

const fn usage() -> &'static str {
    "Usage: kernaid-provider-key <configure|status|logout> [--provider <openai|anthropic|gemini>]"
}

const fn provider_label(provider: NativeProviderKind) -> &'static str {
    match provider {
        NativeProviderKind::OpenAi => "OpenAI",
        NativeProviderKind::Anthropic => "Anthropic",
        NativeProviderKind::Gemini => "Gemini",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn parser_never_accepts_a_credential_argument() {
        assert!(
            parse_arguments(
                ["configure", "--api-key", "synthetic-secret"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        assert!(
            parse_arguments(
                ["configure", "--app-data-dir", "/tmp/alternate"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        assert!(parse_arguments(["configure"].into_iter().map(OsString::from)).is_ok());
        assert!(
            parse_arguments(
                ["configure", "--provider", "anthropic"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_ok()
        );
        assert!(
            parse_arguments(
                ["configure", "--provider", "gemini", "synthetic-secret"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
    }
}
