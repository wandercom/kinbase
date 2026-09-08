//! The current-view reducer (architecture §6 "Reduction algorithm", P-4,
//! P-5). A pure function of `(admitted event set, reducer version, as_of,
//! authority snapshot cursor)` that emits a trace per logical key. Recency is
//! used only inside an authority/lifecycle-equivalent set and only through
//! the explicit source-type decay policy below.

use crate::model::{CurrentFact, Distortion, FactEvent, UnknownEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const REDUCER_VERSION: &str = "guildhall-reducer/2";
/// Transient evidence (draft/proposed/incident/experiment/workaround)
/// without a declared lifetime expires this long after it became effective.
pub const DEFAULT_TRANSIENT_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    Verified,
    Unverified,
    Foreign,
    SignatureInvalid,
    Revoked,
    WrongScope,
}

/// A fact event plus the admission metadata the store attached to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittedEvent {
    pub event: FactEvent,
    pub verification: Verification,
    /// Opaque store cursor that orders equal-time events (never a timestamp).
    pub store_cursor: String,
    #[serde(default)]
    pub origin_trust: Option<String>,
    /// Branch reachability from the default lineage, when known.
    #[serde(default)]
    pub reachable: Option<bool>,
    /// Source identity used for independence (adapter identity or signer).
    #[serde(default)]
    pub source_identity: Option<String>,
    /// Registered environment for runtime observations, and whether it was
    /// registered at the authority cursor.
    #[serde(default)]
    pub environment_registered: Option<bool>,
}

/// Explicit withdrawals: `misextraction` (approver), `never_true`
/// (subject-matter authority), `support_withdrawn` (revocation cascade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub kind: String,
    pub target_event_id: String,
    pub signer_authorized: bool,
    pub reason_code: String,
    pub tombstone_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub revoked_key: String,
    pub cursor: String,
    pub effective_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReducerInput {
    pub store_kind: String,
    pub events: Vec<AdmittedEvent>,
    pub unknowns: Vec<UnknownEvent>,
    pub tombstones: Vec<Tombstone>,
    pub revocations: Vec<Revocation>,
    pub as_of: String,
    pub authority_cursor: String,
    /// Freshness of Company data behind the view (P-8 truth table).
    #[serde(default)]
    pub revocation_fresh: bool,
    #[serde(default)]
    pub fact_valid_until: Option<String>,
    #[serde(default)]
    pub certificate_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: u8,
    pub name: String,
    pub event_ids: Vec<String>,
    pub outcome: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTrace {
    pub logical_key: String,
    pub steps: Vec<TraceStep>,
    pub admitted_event_ids: Vec<String>,
    pub rejected: Vec<Value>,
    pub current_fact_id: Option<String>,
    pub state: String,
    pub conflict_event_ids: Vec<String>,
    pub negative_evidence_event_ids: Vec<String>,
    pub expired_event_ids: Vec<String>,
    pub unknown_id: Option<String>,
    pub counterfactual: Vec<String>,
    pub decay_policy_applied: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedUnknown {
    pub unknown_id: String,
    pub logical_key: String,
    pub scope: String,
    pub decision_blocked: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub question: String,
    pub closure_evidence: Vec<String>,
    pub loss_if_absent: u16,
    pub discriminating_evidence: Vec<String>,
    pub status: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentView {
    pub schema: String,
    pub store_kind: String,
    pub reducer_version: String,
    pub as_of: String,
    pub authority_cursor: String,
    pub facts: Vec<CurrentFact>,
    pub unknowns: Vec<DerivedUnknown>,
    pub open_unknown_ids: Vec<String>,
    pub traces: Vec<KeyTrace>,
    pub rejected: Vec<Value>,
    pub counts: BTreeMap<String, usize>,
    pub decay_policy: Vec<Value>,
}

/// Authority rank inside one store. Higher wins a cross-rank conflict; a
/// same-rank disagreement is a conflict, never a vote.
pub fn authority_rank(event: &FactEvent, origin_trust: Option<&str>) -> u8 {
    let scope = event.authority_scope.as_str();
    match event.store_kind.as_str() {
        "company" => {
            if scope.starts_with("architecture:") {
                6
            } else if scope.starts_with("environment:") {
                3
            } else {
                5
            }
        }
        "codebase" => {
            if scope.starts_with("environment:") {
                3
            } else if origin_trust.is_some_and(|trust| trust != "merged-default" && trust != "approved-pr") {
                0
            } else if event.disposition == "approved" || event.evidence_refs.iter().any(|r| r.starts_with("cand_")) {
                4
            } else if event.atom_kind == "constraint" || event.atom_kind == "decision" {
                4
            } else {
                2
            }
        }
        _ => 1,
    }
}

/// Source-type decay policy: inside an authority-equivalent set, only these
/// kinds let the newest cursor retire an older statement.
pub fn decay_policy() -> Vec<Value> {
    vec![
        json!({"atom_kind": "observation", "rule": "newest-cursor-within-same-source", "rationale": "an observation from the same registered source describes the same subject at a later time"}),
        json!({"atom_kind": "claim", "rule": "conflict-unless-superseded", "rationale": "a newer claim never retires an older one without a parent-bound supersession"}),
        json!({"atom_kind": "decision", "rule": "conflict-unless-superseded", "rationale": "decisions retire only through explicit supersession by the same scoped authority"}),
        json!({"atom_kind": "constraint", "rule": "conflict-unless-superseded", "rationale": "constraints retire only through explicit supersession, retraction, or revocation"}),
        json!({"atom_kind": "rationale", "rule": "accumulate", "rationale": "rationales complement one another and never conflict"}),
    ]
}

fn expiry_of(event: &FactEvent) -> Option<String> {
    if let Some(until) = &event.effective_until {
        return Some(until.clone());
    }
    if crate::model::disposition_is_transient(&event.disposition) {
        return crate::time::plus_seconds(&event.effective_from, DEFAULT_TRANSIENT_LIFETIME_SECONDS).ok();
    }
    None
}

fn statement_identity(event: &FactEvent) -> String {
    crate::scanner::squeeze(&event.statement)
}

pub fn reduce(input: &ReducerInput) -> CurrentView {
    let mut rejected_global = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let bump = |counts: &mut BTreeMap<String, usize>, name: &str| {
        *counts.entry(name.to_owned()).or_insert(0) += 1;
    };

    // Deterministic iteration: store cursor, then event ID.
    let mut ordered: Vec<&AdmittedEvent> = input.events.iter().collect();
    ordered.sort_by(|left, right| {
        cursor_order(&left.store_cursor, &right.store_cursor)
            .then_with(|| left.event.event_id.cmp(&right.event.event_id))
    });

    let revoked_keys: BTreeMap<&str, &Revocation> = input
        .revocations
        .iter()
        .filter(|revocation| cursor_order(&revocation.cursor, &input.authority_cursor) != std::cmp::Ordering::Greater)
        .map(|revocation| (revocation.revoked_key.as_str(), revocation))
        .collect();

    // Group by logical key.
    let mut groups: BTreeMap<String, Vec<&AdmittedEvent>> = BTreeMap::new();
    for admitted in &ordered {
        groups
            .entry(admitted.event.logical_key.clone())
            .or_default()
            .push(admitted);
    }
    let tombstones_by_target: BTreeMap<&str, Vec<&Tombstone>> = {
        let mut map: BTreeMap<&str, Vec<&Tombstone>> = BTreeMap::new();
        for tombstone in &input.tombstones {
            map.entry(tombstone.target_event_id.as_str()).or_default().push(tombstone);
        }
        map
    };
    let all_event_ids: BTreeSet<&str> = input.events.iter().map(|admitted| admitted.event.event_id.as_str()).collect();

    let mut facts = Vec::new();
    let mut unknowns = Vec::new();
    let mut traces = Vec::new();
    let company_stale = input.store_kind != "personal" && !input.certificate_valid;
    let fact_expired = input
        .fact_valid_until
        .as_ref()
        .is_some_and(|until| until.as_str() <= input.as_of.as_str());

    for (logical_key, group) in groups {
        let mut trace = KeyTrace {
            logical_key: logical_key.clone(),
            steps: Vec::new(),
            admitted_event_ids: Vec::new(),
            rejected: Vec::new(),
            current_fact_id: None,
            state: "missing".to_owned(),
            conflict_event_ids: Vec::new(),
            negative_evidence_event_ids: Vec::new(),
            expired_event_ids: Vec::new(),
            unknown_id: None,
            counterfactual: Vec::new(),
            decay_policy_applied: None,
        };

        // Step 1: reject ineligible authority/scope/signature/repository events.
        let mut eligible: Vec<&AdmittedEvent> = Vec::new();
        let mut untrusted_branch: Vec<String> = Vec::new();
        for admitted in group {
            let event = &admitted.event;
            let reason = match admitted.verification {
                Verification::Verified => None,
                Verification::Unverified => Some("UNVERIFIED: no resolvable out-of-worktree certificate or registry entry authorizes the signer"),
                Verification::Foreign => Some("FOREIGN_REPO_EVENTS: event binds another repository UUID"),
                Verification::SignatureInvalid => Some("SIGNATURE_INVALID: domain-separated signature failed"),
                Verification::Revoked => Some("REVOKED: signer key was revoked before this event"),
                Verification::WrongScope => Some("AUTHORITY_WRONG_SCOPE: signer does not own the exact authority scope"),
            };
            let reason = reason.or_else(|| {
                if revoked_keys.get(event.signer.as_str()).is_some_and(|revocation| {
                    revocation.effective_at.as_str() <= event.asserted_at.as_str()
                }) {
                    Some("REVOKED: signer key was revoked at an earlier cursor than this event")
                } else if event.store_kind != input.store_kind && input.store_kind != "mixed" {
                    Some("WRONG_STORE: event belongs to another store kind")
                } else if admitted.environment_registered == Some(false) {
                    Some("ENVIRONMENT_UNREGISTERED: runtime observation names an unregistered environment")
                } else {
                    None
                }
            });
            if let Some(reason) = reason {
                trace.rejected.push(json!({"event_id": event.event_id, "reason": reason}));
                rejected_global.push(json!({"logical_key": logical_key, "event_id": event.event_id, "reason": reason}));
                bump(&mut counts, "rejected");
                continue;
            }
            let trust = admitted.origin_trust.as_deref();
            if authority_rank(event, trust) == 0 || admitted.reachable == Some(false) {
                untrusted_branch.push(event.event_id.clone());
                trace.rejected.push(json!({"event_id": event.event_id, "reason": "UNTRUSTED_BRANCH: origin trust below merged-default or unreachable from the default lineage; ineligible for trusted durable direction"}));
                bump(&mut counts, "untrusted_branch");
                continue;
            }
            eligible.push(admitted);
            trace.admitted_event_ids.push(event.event_id.clone());
        }
        trace.steps.push(TraceStep {
            step: 1,
            name: "reject-ineligible".to_owned(),
            event_ids: trace.admitted_event_ids.clone(),
            outcome: format!("{} eligible, {} rejected", eligible.len(), trace.rejected.len()),
            reason: "authority, scope, signature, repository identity, revocation cursor, and origin trust".to_owned(),
        });
        if !untrusted_branch.is_empty() {
            trace.counterfactual.push(format!(
                "merging {} unreviewed-branch event(s) into the default lineage would make them eligible",
                untrusted_branch.len()
            ));
        }

        // Step 2: explicit retraction/revocation and parent-bound supersession.
        let mut retired: BTreeMap<String, String> = BTreeMap::new();
        let mut withheld: BTreeMap<String, DerivedUnknownSeed> = BTreeMap::new();
        for admitted in &eligible {
            let event = &admitted.event;
            if crate::model::disposition_is_negative(&event.disposition)
                && matches!(event.disposition.as_str(), "retracted" | "withdrawn")
            {
                for target in event.supersedes.iter().chain(event.parents.iter()) {
                    retired.insert(target.clone(), format!("retracted by {}", event.event_id));
                }
                retired.insert(event.event_id.clone(), "self-retraction".to_owned());
                continue;
            }
            for target in &event.supersedes {
                // Parent-bound: the superseded event must be in the admitted set
                // and the superseding authority must not be lower.
                if let Some(old) = eligible.iter().find(|candidate| candidate.event.event_id == *target) {
                    let old_rank = authority_rank(&old.event, old.origin_trust.as_deref());
                    let new_rank = authority_rank(event, admitted.origin_trust.as_deref());
                    if new_rank >= old_rank && old.event.authority_scope == event.authority_scope {
                        retired.insert(target.clone(), format!("superseded by {}", event.event_id));
                    } else {
                        trace.counterfactual.push(format!(
                            "{} claims to supersede {} but its authority ({}/{}) does not own that scope; it survives as a conflict",
                            event.event_id, target, event.authority_id, event.authority_scope
                        ));
                    }
                } else if all_event_ids.contains(target.as_str()) {
                    retired.insert(target.clone(), format!("superseded by {}", event.event_id));
                }
            }
        }
        for admitted in &eligible {
            let event = &admitted.event;
            if let Some(tombstones) = tombstones_by_target.get(event.event_id.as_str()) {
                for tombstone in tombstones {
                    if !tombstone.signer_authorized {
                        continue;
                    }
                    match tombstone.kind.as_str() {
                        "never_true" => {
                            retired.insert(event.event_id.clone(), format!("withdrawn as never_true by {}", tombstone.tombstone_id));
                        }
                        "misextraction" => {
                            withheld.insert(
                                event.event_id.clone(),
                                DerivedUnknownSeed {
                                    kind: "misextraction".to_owned(),
                                    question: format!(
                                        "The approver reported that the approved bytes of {} did not faithfully represent the evidence shown (reason {}). Does the statement hold?",
                                        event.event_id, tombstone.reason_code
                                    ),
                                    evidence: vec![tombstone.tombstone_id.clone()],
                                },
                            );
                        }
                        "support_withdrawn" => {
                            trace.counterfactual.push(format!("support for {} was withdrawn by {}", event.event_id, tombstone.tombstone_id));
                        }
                        _ => {}
                    }
                }
            }
        }
        let after_step2: Vec<&AdmittedEvent> = eligible
            .iter()
            .copied()
            .filter(|admitted| !retired.contains_key(&admitted.event.event_id))
            .collect();
        trace.steps.push(TraceStep {
            step: 2,
            name: "retraction-revocation-supersession".to_owned(),
            event_ids: retired.keys().cloned().collect(),
            outcome: format!("{} retired, {} withheld by notice", retired.len(), withheld.len()),
            reason: retired.values().cloned().collect::<Vec<_>>().join("; "),
        });

        // Step 3: classify source disposition and branch reachability.
        let mut negative: Vec<&AdmittedEvent> = Vec::new();
        let mut positive: Vec<&AdmittedEvent> = Vec::new();
        for admitted in after_step2 {
            if crate::model::disposition_is_negative(&admitted.event.disposition) {
                negative.push(admitted);
                trace.negative_evidence_event_ids.push(admitted.event.event_id.clone());
            } else {
                positive.push(admitted);
            }
        }
        trace.steps.push(TraceStep {
            step: 3,
            name: "disposition-and-reachability".to_owned(),
            event_ids: trace.negative_evidence_event_ids.clone(),
            outcome: format!("{} positive, {} negative evidence", positive.len(), negative.len()),
            reason: "rejected/reverted proposals are negative evidence, not current rules".to_owned(),
        });

        // Step 4: expire temporary/incident/experiment evidence by lifetime.
        let mut live: Vec<&AdmittedEvent> = Vec::new();
        for admitted in positive {
            let event = &admitted.event;
            if event.effective_from.as_str() > input.as_of.as_str() {
                trace.expired_event_ids.push(event.event_id.clone());
                trace.counterfactual.push(format!("{} becomes effective at {}", event.event_id, event.effective_from));
                continue;
            }
            if let Some(until) = expiry_of(event) {
                if until.as_str() <= input.as_of.as_str() {
                    trace.expired_event_ids.push(event.event_id.clone());
                    trace.counterfactual.push(format!(
                        "{} ({}) expired at {}; a renewed observation or durable rule from {} would restore it",
                        event.event_id, event.disposition, until, event.authority_id
                    ));
                    continue;
                }
            }
            live.push(admitted);
        }
        trace.steps.push(TraceStep {
            step: 4,
            name: "expire-transient".to_owned(),
            event_ids: trace.expired_event_ids.clone(),
            outcome: format!("{} live, {} expired", live.len(), trace.expired_event_ids.len()),
            reason: "declared effective_until, or the default transient lifetime for draft/proposed/incident/experiment/workaround".to_owned(),
        });

        // Step 5: collapse exact semantic duplicates, retaining provenance.
        let mut clusters: BTreeMap<String, Vec<&AdmittedEvent>> = BTreeMap::new();
        for admitted in &live {
            clusters
                .entry(statement_identity(&admitted.event))
                .or_default()
                .push(admitted);
        }
        trace.steps.push(TraceStep {
            step: 5,
            name: "collapse-duplicates".to_owned(),
            event_ids: live.iter().map(|admitted| admitted.event.event_id.clone()).collect(),
            outcome: format!("{} distinct statement(s) from {} event(s)", clusters.len(), live.len()),
            reason: "exact semantic duplicates collapse; provenance multiplicity is retained".to_owned(),
        });

        // Step 6: independence versus common-source repetition.
        let mut heads: Vec<Head> = Vec::new();
        for (identity, members) in clusters {
            let mut sources: BTreeSet<String> = BTreeSet::new();
            for member in &members {
                sources.insert(
                    member
                        .source_identity
                        .clone()
                        .unwrap_or_else(|| format!("{}|{}", member.event.authority_id, member.event.signer)),
                );
            }
            let representative = members
                .iter()
                .copied()
                .min_by(|left, right| {
                    cursor_order(&left.store_cursor, &right.store_cursor)
                        .then_with(|| left.event.event_id.cmp(&right.event.event_id))
                })
                .expect("cluster is non-empty");
            let newest = members
                .iter()
                .copied()
                .max_by(|left, right| {
                    cursor_order(&left.store_cursor, &right.store_cursor)
                        .then_with(|| left.event.event_id.cmp(&right.event.event_id))
                })
                .expect("cluster is non-empty");
            let rank = members
                .iter()
                .map(|member| authority_rank(&member.event, member.origin_trust.as_deref()))
                .max()
                .unwrap_or(0);
            heads.push(Head {
                identity,
                representative,
                newest,
                support: members.iter().map(|member| member.event.event_id.clone()).collect(),
                independent: sources.len(),
                rank,
                withheld: members.iter().any(|member| withheld.contains_key(&member.event.event_id)),
            });
        }
        trace.steps.push(TraceStep {
            step: 6,
            name: "independence".to_owned(),
            event_ids: heads.iter().map(|head| head.representative.event.event_id.clone()).collect(),
            outcome: heads
                .iter()
                .map(|head| format!("{}: {} support, {} independent", head.representative.event.event_id, head.support.len(), head.independent))
                .collect::<Vec<_>>()
                .join("; "),
            reason: "repetition from one source is not corroboration; no vote-count winner".to_owned(),
        });

        // Step 7: surface incompatible surviving heads as conflict, applying
        // the explicit decay policy only inside an authority-equivalent set.
        heads.sort_by(|left, right| {
            right.rank.cmp(&left.rank).then_with(|| left.representative.event.fact_id.cmp(&right.representative.event.fact_id))
        });
        let mut conflict_ids = Vec::new();
        let mut current_head: Option<&Head> = None;
        let mut contradicted_lower: Vec<&Head> = Vec::new();
        if let Some(top_rank) = heads.first().map(|head| head.rank) {
            let mut top: Vec<&Head> = heads.iter().filter(|head| head.rank == top_rank).collect();
            let lower: Vec<&Head> = heads.iter().filter(|head| head.rank < top_rank).collect();
            if top.len() > 1 {
                // Decay policy: observations from the same source decay to the newest cursor.
                let all_observations = top.iter().all(|head| head.representative.event.atom_kind == "observation");
                let same_source = top
                    .iter()
                    .map(|head| head.representative.source_identity.clone().unwrap_or_default())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1;
                let all_rationale = top.iter().all(|head| head.representative.event.atom_kind == "rationale");
                if all_observations && same_source {
                    top.sort_by(|left, right| {
                        cursor_order(&right.newest.store_cursor, &left.newest.store_cursor)
                            .then_with(|| left.representative.event.fact_id.cmp(&right.representative.event.fact_id))
                    });
                    trace.decay_policy_applied = Some("newest-cursor-within-same-source".to_owned());
                    current_head = top.first().copied();
                    for head in top.iter().skip(1) {
                        trace.counterfactual.push(format!(
                            "{} decayed under the observation policy; it would return if the source re-observed it",
                            head.representative.event.event_id
                        ));
                    }
                } else if all_rationale {
                    current_head = top.first().copied();
                } else {
                    conflict_ids = top.iter().map(|head| head.representative.event.event_id.clone()).collect();
                }
            } else {
                current_head = top.first().copied();
            }
            contradicted_lower = lower
                .into_iter()
                .filter(|head| current_head.is_some_and(|current| current.identity != head.identity))
                .collect();
        }
        trace.conflict_event_ids = conflict_ids.clone();
        trace.steps.push(TraceStep {
            step: 7,
            name: "conflict".to_owned(),
            event_ids: conflict_ids.clone(),
            outcome: if conflict_ids.is_empty() {
                format!("no same-authority conflict; {} lower-authority contradiction(s)", contradicted_lower.len())
            } else {
                format!("{} incompatible heads at equal authority", conflict_ids.len())
            },
            reason: "timestamps and file order never choose among incompatible heads".to_owned(),
        });

        // Step 8/9: derive one current fact or an owned Unknown.
        let owner_role = if input.store_kind == "company" { "company-steward" } else { "repository-maintainer" };
        let decision_blocked = format!("use of logical key {logical_key}");
        if !conflict_ids.is_empty() {
            let unknown = derive_unknown(
                &logical_key,
                &input.store_kind,
                "conflict",
                heads.first().map(|head| head.representative.event.scope.as_str()).unwrap_or("unknown"),
                &decision_blocked,
                owner_role,
                &format!(
                    "Which of the incompatible statements for logical key {logical_key} is current? Candidates: {}",
                    conflict_ids.join(", ")
                ),
                heads.iter().map(|head| head.representative.event.distortion.loss_if_absent).max().unwrap_or(9_000),
                conflict_ids.clone(),
                input.as_of.as_str(),
            );
            trace.state = "conflict".to_owned();
            trace.unknown_id = Some(unknown.unknown_id.clone());
            trace.counterfactual.push("a parent-bound supersession or retraction from the owning authority resolves the conflict".to_owned());
            unknowns.push(unknown);
            bump(&mut counts, "conflict");
        } else if let Some(head) = current_head {
            let event = &head.representative.event;
            let mut stale_reasons = Vec::new();
            let mut trust = "trusted".to_owned();
            let criticality = if event
                .company_refs
                .iter()
                .any(|r| crate::model::criticality_is_safety(&r.company_criticality))
                || (event.atom_kind == "constraint" && event.authority_scope.starts_with("architecture:"))
            {
                "safety_critical".to_owned()
            } else {
                "advisory".to_owned()
            };
            if company_stale && input.store_kind == "company" {
                stale_reasons.push("certificate-or-root-invalid".to_owned());
                trust = "withheld".to_owned();
            }
            if input.store_kind == "company" && !input.revocation_fresh {
                stale_reasons.push("REVOCATION_STALE".to_owned());
                trust = if criticality == "safety" { "withheld".to_owned() } else { "excluded".to_owned() };
            }
            if input.store_kind == "company" && fact_expired {
                stale_reasons.push("CACHE_EXPIRED".to_owned());
                if criticality == "safety" {
                    trust = "withheld".to_owned();
                } else if trust == "trusted" {
                    trust = "excluded".to_owned();
                }
            }
            if head.withheld {
                stale_reasons.push("misextraction-notice".to_owned());
                trust = "withheld".to_owned();
            }
            let status = if trust == "trusted" { "current" } else { "withheld" };
            let fact = CurrentFact {
                fact_id: event.fact_id.clone(),
                event_id: event.event_id.clone(),
                logical_key: logical_key.clone(),
                atom_kind: event.atom_kind.clone(),
                scope: event.scope.clone(),
                statement: event.statement.clone(),
                status: status.to_owned(),
                disposition: event.disposition.clone(),
                authority_id: event.authority_id.clone(),
                authority_scope: event.authority_scope.clone(),
                store_kind: event.store_kind.clone(),
                effective_from: event.effective_from.clone(),
                effective_until: expiry_of(event),
                distortion: event.distortion.clone(),
                company_refs: event.company_refs.clone(),
                evidence_refs: event.evidence_refs.clone(),
                support_event_ids: head.support.clone(),
                independent_support_count: head.independent,
                redundancy_with: event.redundancy_with.clone(),
                complements: event.complements.clone(),
                confidence: event.confidence.0,
                criticality,
                trust: trust.clone(),
                stale_reasons: stale_reasons.clone(),
                authority_snapshot_cursor: input.authority_cursor.clone(),
                effective_dependence_class: None,
            };
            trace.current_fact_id = Some(fact.fact_id.clone());
            trace.state = status.to_owned();
            if trust != "trusted" {
                let unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    if head.withheld { "misextraction" } else { "stale" },
                    &event.scope,
                    &decision_blocked,
                    if head.withheld { owner_role } else if stale_reasons.iter().any(|r| r == "REVOCATION_STALE") { "company-steward" } else { "fact-owner" },
                    &format!(
                        "Fact {} is withheld ({}). Refresh the authority snapshot or supply corrected evidence before it is trusted.",
                        event.fact_id,
                        stale_reasons.join(",")
                    ),
                    event.distortion.loss_if_absent,
                    head.support.clone(),
                    input.as_of.as_str(),
                );
                trace.unknown_id = Some(unknown.unknown_id.clone());
                unknowns.push(unknown);
                bump(&mut counts, "withheld");
            } else {
                bump(&mut counts, "current");
            }
            facts.push(fact);
            for lower in &contradicted_lower {
                let unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    "contradiction",
                    &event.scope,
                    &format!("drift between {} and the current rule {}", lower.representative.event.event_id, event.fact_id),
                    if event.authority_scope.starts_with("architecture:") { "chief-architect" } else { owner_role },
                    &format!(
                        "Lower-authority evidence {} ({}) contradicts current {} {}. Is the current rule still the intended direction, or should it be superseded?",
                        lower.representative.event.event_id,
                        lower.representative.event.atom_kind,
                        event.atom_kind,
                        event.fact_id
                    ),
                    event.distortion.loss_if_absent.max(lower.representative.event.distortion.loss_if_absent),
                    vec![lower.representative.event.event_id.clone(), event.event_id.clone()],
                    input.as_of.as_str(),
                );
                trace.counterfactual.push(format!(
                    "a signed supersession by {} would make {} the current rule; without it the higher authority stays current",
                    event.authority_id, lower.representative.event.event_id
                ));
                trace.conflict_event_ids.push(lower.representative.event.event_id.clone());
                unknowns.push(unknown);
                bump(&mut counts, "contradiction");
            }
            if !negative.is_empty() {
                trace.counterfactual.push(format!(
                    "{} rejected/reverted proposal(s) remain negative evidence and do not change the current rule",
                    negative.len()
                ));
            }
        } else {
            // Nothing survives: an expired or fully negative key produces an
            // Unknown only when evidence existed at all.
            if !trace.expired_event_ids.is_empty() || !negative.is_empty() || !trace.rejected.is_empty() {
                let representative_scope = eligible
                    .first()
                    .map(|admitted| admitted.event.scope.clone())
                    .or_else(|| negative.first().map(|admitted| admitted.event.scope.clone()))
                    .unwrap_or_else(|| "unknown".to_owned());
                let (kind, owner) = if !trace.expired_event_ids.is_empty() {
                    let owner = eligible
                        .iter()
                        .find(|admitted| trace.expired_event_ids.contains(&admitted.event.event_id))
                        .map(|admitted| {
                            if admitted.event.authority_scope.starts_with("environment:") {
                                admitted.event.authority_id.clone()
                            } else {
                                owner_role.to_owned()
                            }
                        })
                        .unwrap_or_else(|| owner_role.to_owned());
                    ("expired", owner)
                } else if !trace.rejected.is_empty() && negative.is_empty() {
                    ("unverified", owner_role.to_owned())
                } else {
                    ("withdrawn", owner_role.to_owned())
                };
                let question = match kind {
                    "expired" => format!("The only evidence for logical key {logical_key} expired. Is the workaround, incident value, or observation still in force?"),
                    "unverified" => format!("Evidence for logical key {logical_key} exists but none of it is verified by a resolvable certificate or registry entry."),
                    _ => format!("Every proposal for logical key {logical_key} was rejected or reverted. What is the intended rule?"),
                };
                let unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    kind,
                    &representative_scope,
                    &decision_blocked,
                    &owner,
                    &question,
                    9_000,
                    trace.expired_event_ids.iter().chain(trace.negative_evidence_event_ids.iter()).cloned().collect(),
                    input.as_of.as_str(),
                );
                trace.state = kind.to_owned();
                trace.unknown_id = Some(unknown.unknown_id.clone());
                unknowns.push(unknown);
                bump(&mut counts, kind);
            }
        }
        trace.steps.push(TraceStep {
            step: 8,
            name: "derive-current-or-unknown".to_owned(),
            event_ids: trace.current_fact_id.iter().cloned().collect(),
            outcome: trace.state.clone(),
            reason: "one current fact only when authority and lifecycle make it unambiguous; otherwise an owned Unknown with the discriminating evidence".to_owned(),
        });
        traces.push(trace);
    }

    // Explicit Unknown events: open ones are surfaced; closed ones are history.
    let mut open_unknown_ids = Vec::new();
    for unknown in &input.unknowns {
        if unknown.status == "open" || unknown.status == "asked" {
            open_unknown_ids.push(unknown.fact_id.clone());
            unknowns.push(DerivedUnknown {
                unknown_id: unknown.fact_id.clone(),
                logical_key: unknown.logical_key.clone(),
                scope: unknown.scope.clone(),
                decision_blocked: unknown.decision_blocked.clone(),
                owner_role: unknown.owner_role.clone(),
                owner_identity: unknown.owner_identity.clone(),
                question: unknown.question.clone(),
                closure_evidence: unknown.closure_evidence.clone(),
                loss_if_absent: unknown.distortion.loss_if_absent,
                discriminating_evidence: unknown.evidence_refs.clone(),
                status: unknown.status.clone(),
                kind: "explicit".to_owned(),
            });
        }
    }
    for unknown in &unknowns {
        if !open_unknown_ids.contains(&unknown.unknown_id) {
            open_unknown_ids.push(unknown.unknown_id.clone());
        }
    }
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    unknowns.sort_by(|left, right| left.unknown_id.cmp(&right.unknown_id));
    traces.sort_by(|left, right| left.logical_key.cmp(&right.logical_key));
    open_unknown_ids.sort();
    open_unknown_ids.dedup();
    counts.insert("facts".to_owned(), facts.len());
    counts.insert("unknowns".to_owned(), unknowns.len());
    counts.insert("events".to_owned(), input.events.len());
    CurrentView {
        schema: crate::model::CURRENT_VIEW_SCHEMA.to_owned(),
        store_kind: input.store_kind.clone(),
        reducer_version: REDUCER_VERSION.to_owned(),
        as_of: input.as_of.clone(),
        authority_cursor: input.authority_cursor.clone(),
        facts,
        unknowns,
        open_unknown_ids,
        traces,
        rejected: rejected_global,
        counts,
        decay_policy: decay_policy(),
    }
}

struct Head<'a> {
    identity: String,
    representative: &'a AdmittedEvent,
    newest: &'a AdmittedEvent,
    support: Vec<String>,
    independent: usize,
    rank: u8,
    withheld: bool,
}

struct DerivedUnknownSeed {
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    question: String,
    #[allow(dead_code)]
    evidence: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn derive_unknown(
    logical_key: &str,
    store_kind: &str,
    kind: &str,
    scope: &str,
    decision_blocked: &str,
    owner: &str,
    question: &str,
    loss: u16,
    evidence: Vec<String>,
    as_of: &str,
) -> DerivedUnknown {
    let _ = as_of;
    let unknown_id = format!(
        "unknown_{}",
        &crate::hash::sha256_text(&format!("{store_kind}\0{logical_key}\0{kind}\0{}", evidence.join(",")))[..40]
    );
    DerivedUnknown {
        unknown_id,
        logical_key: logical_key.to_owned(),
        scope: scope.to_owned(),
        decision_blocked: decision_blocked.to_owned(),
        owner_role: owner.to_owned(),
        owner_identity: owner.to_owned(),
        question: question.to_owned(),
        closure_evidence: vec![format!("a signed {} event from {} naming the discriminating evidence", if kind == "conflict" { "supersession or retraction" } else { "fact or answer" }, owner)],
        loss_if_absent: loss,
        discriminating_evidence: evidence,
        status: "open".to_owned(),
        kind: kind.to_owned(),
    }
}

/// Opaque decimal cursor ordering: numeric when both parse, else lexical.
pub fn cursor_order(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u128>(), right.parse::<u128>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
    }
}

/// Build the derived view value written to `current.json`.
pub fn view_value(view: &CurrentView, as_of_source: &str) -> Value {
    let mut value = crate::model::value_of(view);
    value["as_of_source"] = Value::String(as_of_source.to_owned());
    value
}

impl DerivedUnknown {
    pub fn to_distortion(&self) -> Distortion {
        Distortion {
            trigger: self.decision_blocked.clone(),
            loss_if_absent: self.loss_if_absent,
            rationale: "derived by the reducer from the discriminating evidence".to_owned(),
        }
    }
}
