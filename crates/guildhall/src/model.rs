use serde::{Deserialize, Serialize};
pub const EVENT_SCHEMA: &str = "guildhall-event/1";
pub const UNKNOWN_SCHEMA: &str = "guildhall-unknown/1";
pub const MAX_CONFIDENCE: u16 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    pub observation_id: String,
    pub source_kind: String,
    pub source_identity: String,
    pub native_id: String,
    pub content_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub disposition: String,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asserted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub body_ref: String,
    pub extraction_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Atom {
    pub atom_id: String,
    pub statement: String,
    pub scope: String,
    pub atom_kind: String,
    pub confidence: u16,
    pub provenance: String,
    pub observation_id: String,
    pub source_digest: String,
    pub taints: Vec<String>,
    pub destinations: Vec<String>,
    pub unresolved_uncertainty: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Distortion {
    pub trigger: String,
    pub loss_if_absent: u16,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompanyReference {
    pub company_id: String,
    pub fact_id: String,
    pub semantic_content_digest: String,
    pub digest_alg_version: String,
    pub authority: String,
    pub valid_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub company_criticality: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FactEvent {
    pub schema: String,
    pub event_id: String,
    pub store_kind: String,
    pub authority_id: String,
    pub authority_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub asserted_at: String,
    pub effective_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub disposition: String,
    pub distortion: Distortion,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<CompanyReference>,
    pub authority_snapshot_cursor: String,
    pub confidence: u16,
    pub unresolved_uncertainty: Option<String>,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownEvent {
    pub schema: String,
    pub unknown_id: String,
    pub store_kind: String,
    pub scope: String,
    pub decision_blocked: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub question: String,
    pub closure_evidence: Vec<String>,
    pub status: String,
    pub response_due_at: String,
    pub expiry_policy: String,
    pub distortion: Distortion,
    pub created_at: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentFact {
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub status: String,
    pub disposition: String,
    pub authority_id: String,
    pub authority_scope: String,
    pub effective_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub loss_if_absent: u16,
    pub company_refs: Vec<CompanyReference>,
    pub evidence_refs: Vec<String>,
}
