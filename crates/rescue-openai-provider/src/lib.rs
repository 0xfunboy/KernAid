#![forbid(unsafe_code)]

//! Closed, library-only contract for the Rescue OpenAI application plane.
//!
//! This crate does not contain a provider client, credential transport,
//! network access, daemon integration, or a binary. It validates one local
//! wire frame and reduces the untrusted Rescue corpus to a bounded provider
//! projection before returning it to a caller.

mod local_wire;
mod rescue_corpus;

pub use local_wire::{
    API_VERSION, CredentialState, FrameError, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
    ProviderErrorCode, ProviderOperation, ProviderRequest, ProviderResponse, ProviderStatus,
    VaultState, encode_response_frame, parse_request_frame, parse_response_frame,
};
pub use rescue_corpus::{
    DiagnosisProposal, MAX_EVIDENCE_CONTENT_BYTES, MAX_OBJECTIVE_BYTES, ProjectedObservation,
    ProjectedProviderContext, RESCUE_EVIDENCE_COLLECTOR, RESCUE_EVIDENCE_TARGET,
};
