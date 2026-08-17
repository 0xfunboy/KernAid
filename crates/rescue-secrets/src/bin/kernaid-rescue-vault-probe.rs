#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux_probe {
    use kernaid_rescue_secrets::{MapperName, RescueVaultMountManager, VaultUnlockRequest};
    use std::{fmt::Write as _, io, os::fd::AsFd, path::PathBuf};

    const SENTINEL_EVENT: &str = "kernaid-disposable-vault-persistence-v1";
    const ATTESTATION_PREFIX: &str = "KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1";

    enum Mode {
        Initialize,
        Verify,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProbeFailure {
        InvalidArguments,
        InvalidMapperName,
        InvalidRequest(kernaid_rescue_secrets::VaultMountManagerError),
        ManagerAcquire(kernaid_rescue_secrets::VaultMountManagerError),
        Unlock(kernaid_rescue_secrets::VaultMountManagerError),
        InitializeJournalOpen,
        InitializeJournalRead,
        InitializeJournalNotEmpty,
        InitializeJournalAppend,
        InitializeIdentityLoad,
        InitializeIdentityPresent,
        InitializeIdentityCreate,
        VerifyJournalOpen,
        VerifyJournalRead,
        VerifyJournalMismatch,
        VerifyIdentityLoad,
        VerifyIdentityMissing,
        EncodePublicKey,
        Shutdown(kernaid_rescue_secrets::VaultMountManagerError),
    }

    impl ProbeFailure {
        const fn stage(self) -> &'static str {
            match self {
                Self::InvalidArguments => "arguments",
                Self::InvalidMapperName => "mapper",
                Self::InvalidRequest(_) => "request",
                Self::ManagerAcquire(_) => "manager-acquire",
                Self::Unlock(_) => "unlock",
                Self::InitializeJournalOpen => "initialize-journal-open",
                Self::InitializeJournalRead => "initialize-journal-read",
                Self::InitializeJournalNotEmpty => "initialize-journal-state",
                Self::InitializeJournalAppend => "initialize-journal-append",
                Self::InitializeIdentityLoad => "initialize-identity-load",
                Self::InitializeIdentityPresent => "initialize-identity-state",
                Self::InitializeIdentityCreate => "initialize-identity-create",
                Self::VerifyJournalOpen => "verify-journal-open",
                Self::VerifyJournalRead => "verify-journal-read",
                Self::VerifyJournalMismatch => "verify-journal-state",
                Self::VerifyIdentityLoad => "verify-identity-load",
                Self::VerifyIdentityMissing => "verify-identity-state",
                Self::EncodePublicKey => "encode-public-key",
                Self::Shutdown(_) => "shutdown",
            }
        }

        const fn code(self) -> &'static str {
            match self {
                Self::InvalidArguments => "invalid",
                Self::InvalidMapperName => "invalid-name",
                Self::InvalidRequest(error)
                | Self::ManagerAcquire(error)
                | Self::Unlock(error)
                | Self::Shutdown(error) => error.code(),
                Self::InitializeJournalOpen
                | Self::InitializeJournalRead
                | Self::InitializeJournalAppend
                | Self::InitializeIdentityLoad
                | Self::InitializeIdentityCreate
                | Self::VerifyJournalOpen
                | Self::VerifyJournalRead
                | Self::VerifyIdentityLoad => "storage-operation-failed",
                Self::InitializeJournalNotEmpty | Self::InitializeIdentityPresent => {
                    "unexpected-existing-state"
                }
                Self::VerifyJournalMismatch => "sentinel-mismatch",
                Self::VerifyIdentityMissing => "identity-missing",
                Self::EncodePublicKey => "encoding-failed",
            }
        }
    }

    struct ProbeAttestation {
        mode: &'static str,
        identity_public_key: String,
    }

    fn encode_public_key(public_key: [u8; 32]) -> Result<String, ProbeFailure> {
        let mut encoded = String::with_capacity(64);
        for byte in public_key {
            write!(&mut encoded, "{byte:02x}").map_err(|_| ProbeFailure::EncodePublicKey)?;
        }
        Ok(encoded)
    }

    fn run() -> Result<ProbeAttestation, ProbeFailure> {
        let mut arguments = std::env::args_os().skip(1);
        let Some(device_flag) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        let Some(device) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        let Some(mapper_flag) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        let Some(mapper) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        let Some(mode_flag) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        let Some(mode) = arguments.next() else {
            return Err(ProbeFailure::InvalidArguments);
        };
        if arguments.next().is_some()
            || device_flag != "--device"
            || mapper_flag != "--mapper"
            || mode_flag != "--mode"
        {
            return Err(ProbeFailure::InvalidArguments);
        }
        let mode = match mode.to_str() {
            Some("initialize") => Mode::Initialize,
            Some("verify") => Mode::Verify,
            _ => return Err(ProbeFailure::InvalidArguments),
        };
        let mapper = mapper
            .into_string()
            .map_err(|_| ProbeFailure::InvalidMapperName)?;
        let mapper = MapperName::parse(&mapper).map_err(|_| ProbeFailure::InvalidMapperName)?;
        let request = VaultUnlockRequest::new(PathBuf::from(device), mapper)
            .map_err(ProbeFailure::InvalidRequest)?;
        let manager = RescueVaultMountManager::acquire().map_err(ProbeFailure::ManagerAcquire)?;
        let stdin = io::stdin();
        let mounted = manager
            .unlock_from_fd(request, stdin.as_fd())
            .map_err(ProbeFailure::Unlock)?;
        let operation = (|| match mode {
            Mode::Initialize => {
                let mut journal = mounted
                    .secrets()
                    .open_journal()
                    .map_err(|_| ProbeFailure::InitializeJournalOpen)?;
                if !journal
                    .entries()
                    .map_err(|_| ProbeFailure::InitializeJournalRead)?
                    .is_empty()
                {
                    return Err(ProbeFailure::InitializeJournalNotEmpty);
                }
                journal
                    .append(SENTINEL_EVENT.as_bytes())
                    .map_err(|_| ProbeFailure::InitializeJournalAppend)?;
                let mut identities = mounted.secrets().device_identity_store();
                if identities
                    .load_device_identity()
                    .map_err(|_| ProbeFailure::InitializeIdentityLoad)?
                    .is_some()
                {
                    return Err(ProbeFailure::InitializeIdentityPresent);
                }
                let identity = identities
                    .create_device_identity()
                    .map_err(|_| ProbeFailure::InitializeIdentityCreate)?;
                Ok(ProbeAttestation {
                    mode: "initialize",
                    identity_public_key: encode_public_key(identity.public_key())?,
                })
            }
            Mode::Verify => {
                let mut journal = mounted
                    .secrets()
                    .open_journal()
                    .map_err(|_| ProbeFailure::VerifyJournalOpen)?;
                let entries = journal
                    .entries()
                    .map_err(|_| ProbeFailure::VerifyJournalRead)?;
                if entries.len() != 1 || entries[0].event.as_slice() != SENTINEL_EVENT.as_bytes() {
                    return Err(ProbeFailure::VerifyJournalMismatch);
                }
                let identity = mounted
                    .secrets()
                    .device_identity_store()
                    .load_device_identity()
                    .map_err(|_| ProbeFailure::VerifyIdentityLoad)?
                    .ok_or(ProbeFailure::VerifyIdentityMissing)?;
                Ok(ProbeAttestation {
                    mode: "verify",
                    identity_public_key: encode_public_key(identity.public_key())?,
                })
            }
        })();

        // Every successfully mounted lifecycle reaches the verified shutdown
        // path, including an initialize/verify operation failure. Drop remains
        // a last-resort guard, but probe evidence never relies on its ignored
        // cleanup result.
        let shutdown = mounted.shutdown().map_err(ProbeFailure::Shutdown);
        match (operation, shutdown) {
            (_, Err(cleanup_failure)) => Err(cleanup_failure),
            (Err(operation_failure), Ok(())) => Err(operation_failure),
            (Ok(attestation), Ok(())) => Ok(attestation),
        }
    }

    pub(super) fn entrypoint() {
        match run() {
            Ok(attestation) => println!(
                "{ATTESTATION_PREFIX} mode={} sentinel={} identity_public_key={} clean_shutdown=true",
                attestation.mode, SENTINEL_EVENT, attestation.identity_public_key,
            ),
            Err(failure) => {
                eprintln!(
                    "KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1 stage={} code={}",
                    failure.stage(),
                    failure.code()
                );
                std::process::exit(2);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use kernaid_rescue_secrets::VaultMountManagerError;

        #[test]
        fn probe_failure_diagnostics_are_closed_sanitized_tokens() {
            let failures = [
                ProbeFailure::InvalidArguments,
                ProbeFailure::InvalidMapperName,
                ProbeFailure::InvalidRequest(VaultMountManagerError::InvalidBlockDevice),
                ProbeFailure::ManagerAcquire(VaultMountManagerError::ManagerLocked),
                ProbeFailure::Unlock(VaultMountManagerError::MountVerificationFailed),
                ProbeFailure::InitializeJournalOpen,
                ProbeFailure::InitializeJournalRead,
                ProbeFailure::InitializeJournalNotEmpty,
                ProbeFailure::InitializeJournalAppend,
                ProbeFailure::InitializeIdentityLoad,
                ProbeFailure::InitializeIdentityPresent,
                ProbeFailure::InitializeIdentityCreate,
                ProbeFailure::VerifyJournalOpen,
                ProbeFailure::VerifyJournalRead,
                ProbeFailure::VerifyJournalMismatch,
                ProbeFailure::VerifyIdentityLoad,
                ProbeFailure::VerifyIdentityMissing,
                ProbeFailure::EncodePublicKey,
                ProbeFailure::Shutdown(VaultMountManagerError::CleanupFailed),
            ];
            for failure in failures {
                for token in [failure.stage(), failure.code()] {
                    assert!(!token.is_empty());
                    assert!(token.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    }));
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux_probe::entrypoint();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Rescue vault lifecycle probe is Linux-only");
    std::process::exit(2);
}
