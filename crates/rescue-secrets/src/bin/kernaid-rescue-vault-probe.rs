#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use kernaid_rescue_secrets::{MapperName, RescueVaultMountManager, VaultUnlockRequest};
    use std::{io, os::fd::AsFd, path::PathBuf};

    const SENTINEL_EVENT: &[u8] = b"kernaid-disposable-vault-persistence-v1";

    enum Mode {
        Initialize,
        Verify,
    }

    fn run() -> Result<(), ()> {
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
        match mode {
            Mode::Initialize => {
                let mut journal = mounted.secrets().open_journal().map_err(|_| ())?;
                if !journal.entries().map_err(|_| ())?.is_empty() {
                    return Err(());
                }
                journal.append(SENTINEL_EVENT).map_err(|_| ())?;
                let mut identities = mounted.secrets().device_identity_store();
                if identities.load_device_identity().map_err(|_| ())?.is_some() {
                    return Err(());
                }
                identities.create_device_identity().map_err(|_| ())?;
            }
            Mode::Verify => {
                let mut journal = mounted.secrets().open_journal().map_err(|_| ())?;
                let entries = journal.entries().map_err(|_| ())?;
                if entries.len() != 1 || entries[0].event.as_slice() != SENTINEL_EVENT {
                    return Err(());
                }
                if mounted
                    .secrets()
                    .device_identity_store()
                    .load_device_identity()
                    .map_err(|_| ())?
                    .is_none()
                {
                    return Err(());
                }
            }
        }
        mounted.shutdown().map_err(|_| ())?;
        Ok(())
    }

    if run().is_ok() {
        println!("PASS: verified Rescue vault lifecycle and persistent state");
    } else {
        eprintln!("Rescue vault lifecycle probe failed");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Rescue vault lifecycle probe is Linux-only");
    std::process::exit(2);
}
