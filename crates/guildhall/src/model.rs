//! Canonical durable messages (architecture §3) with the ratified field
//! names verbatim. Every signed message is a JSON object whose `signer` is
//! the 64-hex Ed25519 public key and whose `signature` is computed over the
//! JCS bytes of the object without `signature`.

use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVENT_SCHEMA: &str = "guildhall-event/1";
pub const UNKNOWN_SCHEMA: &str = "guildhall-unknown/1";
pub const MANIFEST_SCHEMA: &str = "guildhall-manifest/1";
pub const CERTIFICATE_SCHEMA: &str = "guildhall-repo-certificate/1";
pub const REGISTRY_SCHEMA: &str = "guildhall-authority-registry/1";
pub const ANSWER_SCHEMA: &str = "guildhall-answer/1";
pub const QUESTION_SCHEMA: &str = "guildhall-question/1";
pub const TOMBSTONE_SCHEMA: &str = "guildhall-tombstone/1";
pub const REVOCATION_SCHEMA: &str = "guildhall-revocation/1";
pub const ROTATION_SCHEMA: &str = "guildhall-rotation/1";
pub const RECEIPT_SCHEMA: &str = "guildhall-receipt/1";
pub const CURRENT_VIEW_SCHEMA: &str = "guildhall-current-view/1";
pub const MAX_CONFIDENCE: u16 = 10_000;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
pub const DIGEST_ALG_VERSION: &str = "guildhall-digest/1";

/// Basis-point score field that also accepts the qualitative vocabulary
/// (`high`/`medium`/`low`) planted by fixtures; serialized as an integer.
/// Semantic use only — signature verification always uses the original
/// immutable bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bp(pub u16);

impl Serialize for Bp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for Bp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => {
                let raw = number
                    .as_i64()
                    .ok_or_else(|| serde::de::Error::custom("basis points must be an integer"))?;
                if !(0..=10_000).contains(&raw) {
                    return Err(serde::de::Error::custom(
                        "basis points must be within 0..=10000",
                    ));
                }
                Ok(Bp(raw as u16))
            }
            Value::String(text) => match text.to_lowercase().as_str() {
                "high" | "critical" | "safety" | "safety_critical" | "irreversible" => {
                    Ok(Bp(9_000))
                }
                "medium" | "moderate" => Ok(Bp(6_000)),
                "low" | "advisory" | "reversible" => Ok(Bp(3_000)),
                "none" | "" => Ok(Bp(0)),
                other => other
                    .parse::<u16>()
                    .ok()
                    .filter(|value| *value <= 10_000)
                    .map(Bp)
                    .ok_or_else(|| serde::de::Error::custom("unrecognized qualitative score")),
            },
            _ => Err(serde::de::Error::custom(
                "score must be an integer or qualitative label",
            )),
        }
    }
}

impl From<u16> for Bp {
    fn from(value: u16) -> Self {
        Bp(value)
    }
}

/// Closed atom kinds (P-2).
pub const ATOM_KINDS: [&str; 8] = [
    "claim",
    "question",
    "decision",
    "constraint",
    "rationale",
    "observation",
    "reference",
    "relaxation",
];

/// Lifecycle actions expressed as dispositions of FactEvent messages
/// (interface contract C13).
pub const ACTION_DISPOSITIONS: [&str; 8] = [
    "misextraction",
    "never_true",
    "support_withdrawn",
    "orphan_abandoned",
    "manifest_observation_expired",
    "relaxation",
    "exception_request",
    "unreachable_clone_residual",
];

pub fn disposition_is_negative(disposition: &str) -> bool {
    matches!(
        disposition,
        "rejected"
            | "reverted"
            | "retracted"
            | "withdrawn"
            | "expired"
            | "never_true"
            | "superseded"
    )
}

pub fn disposition_is_transient(disposition: &str) -> bool {
    matches!(
        disposition,
        "draft" | "proposed" | "open" | "incident" | "experiment" | "workaround"
    )
}

pub fn disposition_is_durable(disposition: &str) -> bool {
    matches!(
        disposition,
        "approved" | "accepted" | "merged" | "deployed" | "current"
    )
}

/// The action name of a lifecycle message, from either `disposition` or a
/// fixture-planted `atom_kind`.
pub fn action_of(event: &FactEvent) -> Option<&str> {
    if ACTION_DISPOSITIONS.contains(&event.disposition.as_str()) {
        return Some(event.disposition.as_str());
    }
    if ACTION_DISPOSITIONS.contains(&event.atom_kind.as_str()) {
        return Some(event.atom_kind.as_str());
    }
    if event.disposition == "notice" && event.atom_kind == "misextraction" {
        return Some("misextraction");
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    pub observation_id: String,
    pub source_kind: String,
    pub source_identity: String,
    pub native_id: String,
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub disposition: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub body_ref: String,
    pub extraction_version: String,
    /// Origin trust class for repository observations (architecture §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_trust: Option<String>,
    /// Registered environment/deploy owner for runtime evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// Source-adapter lifecycle: `observed`, `superseded`, `retracted`.
    #[serde(default = "default_lifecycle")]
    pub lifecycle: String,
}

fn default_lifecycle() -> String {
    "observed".to_owned()
}

/// An extracted, routed atom before any approval. Lives only in private
/// storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Atom {
    pub atom_id: String,
    pub observation_id: String,
    pub source_kind: String,
    pub source_digest: String,
    pub statement: String,
    pub atom_kind: String,
    pub scope: String,
    pub confidence: u16,
    pub provenance: String,
    pub taints: Vec<String>,
    pub hard_blocked: bool,
    pub proposed_destinations: Vec<String>,
    pub eligible_destinations: Vec<String>,
    pub demoted_destinations: Vec<String>,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub extractor: String,
    pub scanner_version: String,
    pub scan_findings: Vec<crate::scanner::Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub supersedes_hint: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Distortion {
    pub trigger: String,
    pub loss_if_absent: u16,
    pub rationale: String,
}

impl Serialize for Distortion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("trigger", &self.trigger)?;
        map.serialize_entry("loss_if_absent", &self.loss_if_absent)?;
        map.serialize_entry("rationale", &self.rationale)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Distortion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Value::Object(map) = value else {
            return Err(serde::de::Error::custom("distortion must be an object"));
        };
        let trigger = map
            .get("trigger")
            .and_then(Value::as_str)
            .unwrap_or("dependent decision")
            .to_owned();
        let rationale = map
            .get("rationale")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                map.get("reversibility")
                    .and_then(Value::as_str)
                    .map(|value| format!("reversibility: {value}"))
                    .unwrap_or_else(|| "unstated".to_owned())
            });
        let loss = map
            .get("loss_if_absent")
            .or_else(|| map.get("severity"))
            .cloned()
            .unwrap_or(Value::from(3_000));
        let loss: Bp = serde_json::from_value(loss).map_err(serde::de::Error::custom)?;
        Ok(Distortion {
            trigger,
            loss_if_absent: loss.0,
            rationale,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompanyReference {
    pub company_id: String,
    pub fact_id: String,
    #[serde(alias = "semantic_content_digest")]
    pub semantic_digest: String,
    pub digest_alg_version: String,
    pub authority: String,
    pub valid_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub company_criticality: String,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_version: Option<String>,
}

pub const RELATIONS: [&str; 5] = [
    "applies",
    "specializes",
    "implements",
    "contradicts",
    "exception_request",
];
pub const CRITICALITIES: [&str; 3] = ["advisory", "safety", "safety_critical"];

pub fn criticality_is_safety(value: &str) -> bool {
    matches!(value, "safety" | "safety_critical")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FactEvent {
    pub schema: String,
    pub event_id: String,
    pub store_kind: String,
    pub authority_id: String,
    pub authority_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub asserted_at: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub disposition: String,
    pub distortion: Distortion,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<CompanyReference>,
    pub authority_snapshot_cursor: String,
    #[serde(default = "default_confidence")]
    pub confidence: Bp,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub signer: String,
    pub signature: String,
    /// The immutable original document, retained for signature verification
    /// and content addressing; never re-serialized.
    #[serde(skip)]
    pub raw: Option<Value>,
}

fn default_confidence() -> Bp {
    Bp(6_000)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownEvent {
    pub schema: String,
    pub event_id: String,
    pub store_kind: String,
    pub authority_id: String,
    pub authority_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub asserted_at: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub disposition: String,
    pub distortion: Distortion,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<CompanyReference>,
    pub authority_snapshot_cursor: String,
    #[serde(default = "default_confidence")]
    pub confidence: Bp,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub decision_blocked: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub question: String,
    pub closure_evidence: Vec<String>,
    pub status: String,
    pub response_due_at: String,
    pub expiry_policy: String,
    pub signer: String,
    pub signature: String,
    #[serde(skip)]
    pub raw: Option<Value>,
}

/// Closed Unknown statuses and degraded policies (P-6).
pub const UNKNOWN_STATUSES: [&str; 6] = [
    "open",
    "asked",
    "closed",
    "abandoned",
    "superseded",
    "reopened",
];
pub const EXPIRY_POLICIES: [&str; 3] = [
    "block_dependent_decision",
    "reversible_sandbox_only_experiment",
    "named_human_granted_exception",
];

/// Normalize a planted policy spelling to the closed vocabulary.
pub fn normalize_policy(value: &str) -> &'static str {
    match value {
        "sandbox" | "sandbox-only-experiment" | "reversible_sandbox_only_experiment" => {
            "reversible_sandbox_only_experiment"
        }
        "exception" | "named-human-exception" | "named_human_granted_exception" => {
            "named_human_granted_exception"
        }
        _ => "block_dependent_decision",
    }
}

/// A derived current fact in a disposable current view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentFact {
    pub fact_id: String,
    pub event_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub status: String,
    pub disposition: String,
    pub authority_id: String,
    pub authority_scope: String,
    pub store_kind: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub distortion: Distortion,
    pub company_refs: Vec<CompanyReference>,
    pub evidence_refs: Vec<String>,
    pub support_event_ids: Vec<String>,
    pub independent_support_count: usize,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub confidence: u16,
    pub criticality: String,
    pub trust: String,
    pub stale_reasons: Vec<String>,
    pub authority_snapshot_cursor: String,
    #[serde(default)]
    pub effective_dependence_class: Option<String>,
}

pub fn value_of<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

impl FactEvent {
    pub fn to_value(&self) -> Value {
        value_of(self)
    }

    /// Strict single parse from immutable bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds the {MAX_EVENT_BYTES}-byte ceiling"));
        }
        let map = crate::json::parse_strict_object(bytes)?;
        if map.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA) {
            return Err("unsupported event schema".to_owned());
        }
        let raw = Value::Object(map.clone());
        let mut event: FactEvent =
            serde_json::from_value(Value::Object(map)).map_err(|error| error.to_string())?;
        event.raw = Some(raw);
        event.validate()?;
        Ok(event)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let bytes = crate::json::try_canonical_bytes(value)?;
        Self::parse(&bytes)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.confidence.0 > MAX_CONFIDENCE || self.distortion.loss_if_absent > MAX_CONFIDENCE {
            return Err("confidence and loss are basis points in 0..=10000".to_owned());
        }
        if !matches!(
            self.store_kind.as_str(),
            "company" | "codebase" | "personal"
        ) {
            return Err("store_kind must be company, codebase, or personal".to_owned());
        }
        crate::time::parse_rfc3339_millis(&self.asserted_at)?;
        crate::time::parse_rfc3339_millis(&self.effective_from)?;
        if let Some(until) = &self.effective_until {
            crate::time::parse_rfc3339_millis(until)?;
        }
        if self.authority_scope.is_empty() || self.logical_key.is_empty() || self.fact_id.is_empty()
        {
            return Err("authority_scope, logical_key, and fact_id are required".to_owned());
        }
        for forbidden in ['*', '%', '?', '\0'] {
            if self.authority_scope.contains(forbidden) || self.logical_key.contains(forbidden) {
                return Err("authority_scope and logical_key are exact strings; wildcard characters are rejected".to_owned());
            }
        }
        if self.statement.len() > 16 * 1024 {
            return Err("statement exceeds the 16 KiB bound".to_owned());
        }
        for reference in &self.company_refs {
            if !RELATIONS.contains(&reference.relation.as_str()) {
                return Err(format!(
                    "unsupported company reference relation {}",
                    reference.relation
                ));
            }
            if !CRITICALITIES.contains(&reference.company_criticality.as_str()) {
                return Err("company_criticality must be advisory or safety_critical".to_owned());
            }
        }
        Ok(())
    }

    /// The immutable document: the original bytes when parsed from a
    /// buffer, otherwise the serialized struct.
    pub fn document(&self) -> Value {
        self.raw.clone().unwrap_or_else(|| self.to_value())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::json::canonical_bytes(&self.document())
    }

    pub fn digest(&self) -> String {
        crate::hash::sha256_bytes(&self.canonical_bytes())
    }

    /// Sign in place: sets `signer` and `signature` and freezes the document.
    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), ContractError> {
        self.raw = None;
        let signed = key.sign_document("fact-event", &self.to_value())?;
        self.signer = signed["signer"].as_str().unwrap_or_default().to_owned();
        self.signature = signed["signature"].as_str().unwrap_or_default().to_owned();
        self.raw = Some(signed);
        Ok(())
    }

    pub fn verify_signature(&self) -> Option<PublicKey> {
        PublicKey::verify_document("fact-event", &self.document())
    }

    /// Semantic content digest (P-8), algorithm `guildhall-digest/1`:
    /// `sha256(JCS({"statement": statement}))`.
    pub fn semantic_digest(&self) -> String {
        semantic_digest(&self.statement)
    }
}

pub fn semantic_digest(statement: &str) -> String {
    crate::json::digest(&serde_json::json!({"statement": statement}))
}

impl UnknownEvent {
    pub fn to_value(&self) -> Value {
        value_of(self)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds the {MAX_EVENT_BYTES}-byte ceiling"));
        }
        let map = crate::json::parse_strict_object(bytes)?;
        if map.get("schema").and_then(Value::as_str) != Some(UNKNOWN_SCHEMA) {
            return Err("unsupported unknown-event schema".to_owned());
        }
        let raw = Value::Object(map.clone());
        let mut event: UnknownEvent =
            serde_json::from_value(Value::Object(map)).map_err(|error| error.to_string())?;
        event.raw = Some(raw);
        if !UNKNOWN_STATUSES.contains(&event.status.as_str()) {
            return Err("unknown status is outside the closed set".to_owned());
        }
        Ok(event)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let bytes = crate::json::try_canonical_bytes(value)?;
        Self::parse(&bytes)
    }

    pub fn document(&self) -> Value {
        self.raw.clone().unwrap_or_else(|| self.to_value())
    }

    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), ContractError> {
        self.raw = None;
        let signed = key.sign_document("unknown-event", &self.to_value())?;
        self.signer = signed["signer"].as_str().unwrap_or_default().to_owned();
        self.signature = signed["signature"].as_str().unwrap_or_default().to_owned();
        self.raw = Some(signed);
        Ok(())
    }

    pub fn verify_signature(&self) -> Option<PublicKey> {
        PublicKey::verify_document("unknown-event", &self.document())
    }

    pub fn digest(&self) -> String {
        crate::json::digest(&self.document())
    }

    /// Build an Unknown with the ratified defaults; caller sets identity
    /// fields and signs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_kind: &str,
        repository_id: Option<&str>,
        authority_id: &str,
        authority_scope: &str,
        logical_key: &str,
        scope: &str,
        decision_blocked: &str,
        owner_role: &str,
        owner_identity: &str,
        question: &str,
        loss_if_absent: u16,
        created_at: &str,
        response_due_at: &str,
        expiry_policy: &str,
        cursor: &str,
    ) -> Self {
        let seed = format!(
            "{store_kind}\0{}\0{logical_key}\0{decision_blocked}\0{question}",
            repository_id.unwrap_or_default()
        );
        let unknown_id = format!("unknown_{}", &crate::hash::sha256_text(&seed)[..40]);
        Self {
            schema: UNKNOWN_SCHEMA.to_owned(),
            event_id: format!("{unknown_id}:{}", &crate::hash::sha256_text(&format!("{seed}\0{created_at}"))[..16]),
            store_kind: store_kind.to_owned(),
            authority_id: authority_id.to_owned(),
            authority_scope: authority_scope.to_owned(),
            repository_id: repository_id.map(str::to_owned),
            fact_id: unknown_id,
            logical_key: logical_key.to_owned(),
            atom_kind: "question".to_owned(),
            scope: scope.to_owned(),
            statement: question.to_owned(),
            evidence_refs: Vec::new(),
            asserted_at: created_at.to_owned(),
            effective_from: created_at.to_owned(),
            effective_until: None,
            disposition: "current".to_owned(),
            distortion: Distortion {
                trigger: decision_blocked.to_owned(),
                loss_if_absent,
                rationale: "a stale or disputed fact is worse than a missing fact; the dependent decision is withheld until named evidence closes this Unknown".to_owned(),
            },
            parents: Vec::new(),
            supersedes: Vec::new(),
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            company_refs: Vec::new(),
            authority_snapshot_cursor: cursor.to_owned(),
            confidence: Bp(0),
            unresolved_uncertainty: Some(question.to_owned()),
            decision_blocked: decision_blocked.to_owned(),
            owner_role: owner_role.to_owned(),
            owner_identity: owner_identity.to_owned(),
            question: question.to_owned(),
            closure_evidence: Vec::new(),
            status: "open".to_owned(),
            response_due_at: response_due_at.to_owned(),
            expiry_policy: normalize_policy(expiry_policy).to_owned(),
            signer: String::new(),
            signature: String::new(),
            raw: None,
        }
    }
}

/// Stable identifiers: fact IDs derive from `(store, scope, statement)`,
/// logical keys from `(store, authority_scope, subject)`.
pub fn fact_id(store_kind: &str, scope: &str, statement: &str) -> String {
    format!(
        "fact_{}",
        &crate::hash::sha256_text(&format!(
            "{store_kind}\0{scope}\0{}",
            crate::scanner::squeeze(statement)
        ))[..40]
    )
}

pub fn logical_key(store_kind: &str, authority_scope: &str, subject: &str) -> String {
    format!(
        "logical_{}",
        &crate::hash::sha256_text(&format!("{store_kind}\0{authority_scope}\0{subject}"))[..40]
    )
}

pub fn event_id(
    fact_id: &str,
    statement_digest: &str,
    asserted_at: &str,
    signer_hint: &str,
) -> String {
    format!(
        "event_{}",
        &crate::hash::sha256_text(&format!(
            "{fact_id}\0{statement_digest}\0{asserted_at}\0{signer_hint}"
        ))[..40]
    )
}

/// Loss-if-absent defaults by atom kind (basis points).
pub fn default_loss(atom_kind: &str) -> u16 {
    match atom_kind {
        "constraint" => 9_000,
        "decision" => 7_500,
        "relaxation" => 7_000,
        "rationale" => 5_000,
        "question" => 5_000,
        "reference" => 6_000,
        "claim" => 4_500,
        _ => 3_000,
    }
}
