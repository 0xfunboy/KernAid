#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use kernaid_rescue_secrets::{MapperName, RescueVaultMountManager, VaultUnlockRequest};
    use std::{fmt::Write as _, io, os::fd::AsFd, path::PathBuf};

    const SENTINEL_EVENT: &str = "kernaid-disposable-vault-persistence-v1";
    const ATTESTATION_PREFIX: &str = "KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1";

    enum Mode {
        Initialize,
        Verify,
    }

    struct ProbeAttestation {
        mode: &'static str,
        identity_public_key: String,
    }

    fn encode_public_key(public_key: [u8; 32]) -> Result<String, ()> {
        let mut encoded = String::with_capacity(64);
        for byte in public_key {
            write!(&mut encoded, "{byte:02x}").map_err(|_| ())?;
        }
        Ok(encoded)
    }

    fn run() -> Result<ProbeAttestation, ()> {
        let mut arguments = std::env::args_os().skip(1);
        let Some(device_flag) = arguments.next() else {
            return Err(());
        };
        let Some(device) = arguments.next() else {
            return Err(());
        };
        let Some(mapper_flag) = arguments.next() else {
            return Err(());
        };
        let Some(mapper) = arguments.next() else {
            return Err(());
        };
        let Some(mode_flag) = arguments.next() else {
            return Err(());
        };
        let Some(mode) = arguments.next() else {
            return Err(());
        };
        if arguments.next().is_some()
            || device_flag != "--device"
            || mapper_flag != "--mapper"
            || mode_flag != "--mode"
        {
            return Err(());
        }
        let mode = match mode.to_str() {
            Some("initialize") => Mode::Initialize,
            Some("verify") => Mode::Verify,
            _ => return Err(()),
        };
        let mapper = mapper.into_string().map_err(|_| ())?;
        let mapper = MapperName::parse(&mapper).map_err(|_| ())?;
        let request = VaultUnlockRequest::new(PathBuf::from(device), mapper).map_err(|_| ())?;
        let manager = RescueVaultMountManager::acquire().map_err(|_| ())?;
        let stdin = io::stdin();
        let mounted = manager
            .unlock_from_fd(request, stdin.as_fd())
            .map_err(|_| ())?;
        let attestation = match mode {
            Mode::Initialize => {
                let mut journal = mounted.secrets().open_journal().map_err(|_| ())?;
                if !journal.entries().map_err(|_| ())?.is_empty() {
                    return Err(());
                }
                journal.append(SENTINEL_EVENT.as_bytes()).map_err(|_| ())?;
                let mut identities = mounted.secrets().device_identity_store();
                if identities.load_device_identity().map_err(|_| ())?.is_some() {
                    return Err(());
                }
                let identity = identities.create_device_identity().map_err(|_| ())?;
                ProbeAttestation {
                    mode: "initialize",
                    identity_public_key: encode_public_key(identity.public_key())?,
                }
            }
            Mode::Verify => {
                let mut journal = mounted.secrets().open_journal().map_err(|_| ())?;
                let entries = journal.entries().map_err(|_| ())?;
                if entries.len() != 1 || entries[0].event.as_slice() != SENTINEL_EVENT.as_bytes() {
                    return Err(());
                }
                let identity = mounted
                    .secrets()
                    .device_identity_store()
                    .load_device_identity()
                    .map_err(|_| ())?
                    .ok_or(())?;
                ProbeAttestation {
                    mode: "verify",
                    identity_public_key: encode_public_key(identity.public_key())?,
                }
            }
        };
        mounted.shutdown().map_err(|_| ())?;
        Ok(attestation)
    }

    match run() {
        Ok(attestation) => println!(
            "{ATTESTATION_PREFIX} mode={} sentinel={} identity_public_key={} clean_shutdown=true",
            attestation.mode, SENTINEL_EVENT, attestation.identity_public_key,
        ),
        Err(()) => {
            eprintln!("Rescue vault lifecycle probe failed");
            std::process::exit(2);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Rescue vault lifecycle probe is Linux-only");
    std::process::exit(2);
}
