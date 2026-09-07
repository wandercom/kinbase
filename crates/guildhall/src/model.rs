use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVENT_SCHEMA: &str = "guildhall-event/1";

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
    pub taints: Vec<String>,
    pub destinations: Vec<String>,
    pub unresolved_uncertainty: Option<String>,
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
    pub distortion: Value,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<Value>,
    pub authority_snapshot_cursor: String,
    pub confidence: u16,
    pub unresolved_uncertainty: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentFact {
    pub fact_id: String,
    pub logical_key: String,
    pub statement: String,
    pub status: String,
    pub authority_scope: String,
    pub effective_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
}
