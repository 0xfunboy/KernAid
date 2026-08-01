#![forbid(unsafe_code)]
//! Device signing will use an encrypted Ed25519 key in Phase 0 persistence work.
pub struct UnsignedReport(pub Vec<u8>);
