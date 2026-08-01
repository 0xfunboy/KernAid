#![forbid(unsafe_code)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Risk {
    R0,
    R1,
    R2,
    R3,
    R4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionStep {
    pub action: String,
    pub risk: Risk,
    pub target_fingerprint: String,
    pub evidence_ids: Vec<String>,
    pub preconditions: Vec<String>,
    pub backup: Option<String>,
    pub validation: String,
    pub rollback: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPlan {
    pub plan_id: String,
    pub target_fingerprint: String,
    pub steps: Vec<ActionStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRequest {
    pub session_id: String,
    pub approval_id: Option<String>,
    pub target_fingerprint: String,
    pub sequence: u64,
    pub action: String,
}
