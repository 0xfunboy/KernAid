#![forbid(unsafe_code)]

//! Closed, library-only contract for the Rescue OpenAI application plane.
//!
//! This crate does not contain a provider client, credential transport,
//! network access, daemon integration, or a binary. It validates one local
//! wire frame, reduces the untrusted Rescue corpus to a bounded projection,
//! and provides a credential-free offline codec for a fixed Responses API
//! exchange. The codec performs no HTTP or provider execution.

mod local_wire;
mod openai_wire;
mod rescue_corpus;

pub use kernaid_evidence::linux_snapshot::COLLECTOR as LINUX_NORMALIZED_SNAPSHOT_COLLECTOR;
pub use local_wire::{
    API_VERSION, CredentialState, FrameError, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
    ProviderErrorCode, ProviderOperation, ProviderRequest, ProviderResponse, ProviderStatus,
    VaultState, encode_response_frame, parse_request_frame, parse_response_frame,
};
pub use openai_wire::{
    DecodedOpenAiResponse, MAX_OPENAI_REQUEST_BODY_BYTES, MAX_OPENAI_RESPONSE_BODY_BYTES,
    OPENAI_CONTENT_TYPE, OPENAI_MAX_OUTPUT_TOKENS, OPENAI_MODEL, OPENAI_RESPONSES_METHOD,
    OPENAI_RESPONSES_PATH, OpenAiUsage, OpenAiWireError, PreparedOpenAiExchange,
    decode_openai_response, prepare_openai_exchange,
};
pub use rescue_corpus::{
    DiagnosisProposal, MAX_EVIDENCE_CONTENT_BYTES, MAX_OBJECTIVE_BYTES,
    PROVIDER_CONTEXT_HASH_DOMAIN, ProjectedObservation, ProjectedProviderContext,
    ProviderContextPreview, RESCUE_EVIDENCE_COLLECTOR, RESCUE_EVIDENCE_TARGET,
};
