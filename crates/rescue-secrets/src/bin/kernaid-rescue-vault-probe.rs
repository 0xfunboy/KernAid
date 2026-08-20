#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux_probe {
    use kernaid_rescue_secrets::{MapperName, RescueVaultMountManager, VaultUnlockRequest};
    use std::{ffi::OsStr, fmt::Write as _, io, os::fd::AsFd, path::PathBuf};

    const JOURNAL_BINDING: &str = "device-identity-bound-v1";
    const ATTESTATION_PREFIX: &str = "KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        Initialize,
        Verify,
        CrashCleanup,
    }

    fn parse_mode(mode: &OsStr) -> Option<Mode> {
        match mode.to_str() {
            Some("initialize") => Some(Mode::Initialize),
            Some("verify") => Some(Mode::Verify),
            Some("crash-cleanup") => Some(Mode::CrashCleanup),
            _ => None,
        }
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
        InitializeIdentityLoad,
        InitializeIdentityPresent,
        InitializeIdentityCreate,
        InitializeApplicationOpen,
        InitializeApplicationMismatch,
        VerifyIdentityLoad,
        VerifyIdentityMissing,
        VerifyApplicationOpen,
        VerifyApplicationMismatch,
        CrashMarkerWrite,
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
                Self::InitializeIdentityLoad => "initialize-identity-load",
                Self::InitializeIdentityPresent => "initialize-identity-state",
                Self::InitializeIdentityCreate => "initialize-identity-create",
                Self::InitializeApplicationOpen => "initialize-application-open",
                Self::InitializeApplicationMismatch => "initialize-application-binding",
                Self::VerifyIdentityLoad => "verify-identity-load",
                Self::VerifyIdentityMissing => "verify-identity-state",
                Self::VerifyApplicationOpen => "verify-application-open",
                Self::VerifyApplicationMismatch => "verify-application-binding",
                Self::CrashMarkerWrite => "crash-marker",
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
                | Self::InitializeIdentityLoad
                | Self::InitializeIdentityCreate
                | Self::InitializeApplicationOpen
                | Self::VerifyIdentityLoad
                | Self::VerifyApplicationOpen => "storage-operation-failed",
                Self::CrashMarkerWrite => "write-failed",
                Self::InitializeJournalNotEmpty | Self::InitializeIdentityPresent => {
                    "unexpected-existing-state"
                }
                Self::InitializeApplicationMismatch | Self::VerifyApplicationMismatch => {
                    "identity-binding-mismatch"
                }
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

    fn emit_crash_marker() -> Result<(), ProbeFailure> {
        use std::io::Write as _;

        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        writeln!(
            stderr,
            "KERNAID_RESCUE_VAULT_PROBE_CRASH_POINT_V1 mode=crash-cleanup unlock_complete=true cleanup=awaiting-sigkill"
        )
        .map_err(|_| ProbeFailure::CrashMarkerWrite)?;
        stderr.flush().map_err(|_| ProbeFailure::CrashMarkerWrite)
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
        let mode = parse_mode(&mode).ok_or(ProbeFailure::InvalidArguments)?;
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
                drop(journal);
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
                let application = mounted
                    .secrets()
                    .open_application_store()
                    .map_err(|_| ProbeFailure::InitializeApplicationOpen)?;
                if application.device_id() != identity.device_id() {
                    return Err(ProbeFailure::InitializeApplicationMismatch);
                }
                Ok(ProbeAttestation {
                    mode: "initialize",
                    identity_public_key: encode_public_key(identity.public_key())?,
                })
            }
            Mode::Verify => {
                let identity = mounted
                    .secrets()
                    .device_identity_store()
                    .load_device_identity()
                    .map_err(|_| ProbeFailure::VerifyIdentityLoad)?
                    .ok_or(ProbeFailure::VerifyIdentityMissing)?;
                let application = mounted
                    .secrets()
                    .open_application_store()
                    .map_err(|_| ProbeFailure::VerifyApplicationOpen)?;
                if application.device_id() != identity.device_id() {
                    return Err(ProbeFailure::VerifyApplicationMismatch);
                }
                Ok(ProbeAttestation {
                    mode: "verify",
                    identity_public_key: encode_public_key(identity.public_key())?,
                })
            }
            Mode::CrashCleanup => {
                // This binary is unavailable without the privileged-probe
                // feature. The disposable integration test runs this branch
                // in a private mount namespace, after deferred mapper removal
                // has been armed by unlock_from_fd. It owns this direct PID,
                // waits for the flushed marker, then sends SIGKILL so Rust
                // Drop cannot run and kernel-owned teardown is tested.
                emit_crash_marker()?;
                loop {
                    std::thread::park();
                }
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
                "{ATTESTATION_PREFIX} mode={} journal_binding={} identity_public_key={} clean_shutdown=true",
                attestation.mode, JOURNAL_BINDING, attestation.identity_public_key,
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
                ProbeFailure::InitializeIdentityLoad,
                ProbeFailure::InitializeIdentityPresent,
                ProbeFailure::InitializeIdentityCreate,
                ProbeFailure::InitializeApplicationOpen,
                ProbeFailure::InitializeApplicationMismatch,
                ProbeFailure::VerifyIdentityLoad,
                ProbeFailure::VerifyIdentityMissing,
                ProbeFailure::VerifyApplicationOpen,
                ProbeFailure::VerifyApplicationMismatch,
                ProbeFailure::CrashMarkerWrite,
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

        #[test]
        fn crash_cleanup_is_an_exact_probe_only_mode() {
            assert_eq!(
                parse_mode(OsStr::new("crash-cleanup")),
                Some(Mode::CrashCleanup)
            );
            assert_eq!(parse_mode(OsStr::new("crash_cleanup")), None);
            assert_eq!(parse_mode(OsStr::new("crash-cleanup-extra")), None);
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
