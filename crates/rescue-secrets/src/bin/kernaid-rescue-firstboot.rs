#![forbid(unsafe_code)]

use kernaid_rescue_secrets::{FirstBootBoundaryError, run_rescue_firstboot};
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return failure(FirstBootBoundaryError::InvalidInvocation);
    }
    match run_rescue_firstboot() {
        Ok(evidence) => {
            println!(
                "KERNAID_RESCUE_FIRSTBOOT_ATTESTATION_V1 state=provisioned verified=true cleanup=complete luks_uuid={} filesystem_uuid={} device_id={}",
                evidence.luks_uuid(),
                evidence.filesystem_uuid(),
                evidence.device_id(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => failure(error),
    }
}

fn failure(error: FirstBootBoundaryError) -> ExitCode {
    eprintln!(
        "KERNAID_RESCUE_FIRSTBOOT_FAILURE_V1 code={} success=false",
        error.code()
    );
    ExitCode::FAILURE
}
