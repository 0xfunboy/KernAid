#![forbid(unsafe_code)]

pub mod linux_snapshot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub id: String,
    pub collector: String,
    pub target: String,
    pub captured_at: String,
    pub content_type: String,
    pub sha256: String,
    pub sensitivity: String,
    pub trust: String,
    pub summary: String,
    pub blob_ref: String,
}
impl Evidence {
    pub fn is_untrusted(&self) -> bool {
        self.trust == "observed-untrusted"
    }
}
