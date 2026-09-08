//! P-7: deterministic, inspectable set-conditional projection.
//!
//! The selector is deliberately arithmetic-only: every reported term is a
//! signed integer in basis points. It never claims a causal quantity; it is
//! an additive approximation over admitted facts and explicit Unknowns.

use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::CurrentFact;
use crate::reducer::{CurrentView, ReducerInput};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROJECTION_LIMIT: usize = 32;
pub const PROJECTION_BYTE_LIMIT: usize = 128 * 1024;
const TIERS: [(&str, i64, i64); 7] = [
    ("facts_and_unknowns", 0, 100),
    ("summary", 500, 100),
    ("exact_code_span", 1_200, 200),
    ("history_adr", 800, 150),
    ("test_runtime_evidence", 1_500, 200),
    ("authority_answer", 0, 300),
    ("broad_search", 250, 250),
];

#[derive(Debug, Clone)]
pub(crate) struct UnknownOut {
    pub(crate) unknown_id: String,
    pub(crate) logical_key: String,
    pub(crate) scope: String,
    pub(crate) decision_blocked: String,
    pub(crate) owner_role: String,
    pub(crate) owner_identity: String,
    pub(crate) question: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) loss_if_absent: u16,
    pub(crate) status: String,
    pub(crate) kind: String,
}

#[derive(Debug, Clone)]
struct Evaluation {
    marginal_value: i64,
    newly_covered_distortion: i64,
    authority_and_validity_gain: i64,
    complementarity_gain: i64,
    uncertainty_reduction: i64,
    redundancy: i64,
    retrieval_and_residency_cost: i64,
    stale_or_conflict_risk: i64,
    redundancy_basis: String,
}

pub fn run(
    launcher: &Launcher,
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    as_of: &crate::time::AsOf,
    json: bool,
) -> Result<(), ContractError> {
    let mut facts = Vec::new();
    let mut view_unknowns = Vec::new();
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        let view = load_view(launcher, repo, store, as_of)?;
        facts.extend(view.facts);
        view_unknowns.extend(view.unknowns);
    }
    // A closure record is authoritative across stores: the original Unknown
    // remains in append-only history, but no later projection may treat it as
    // still blocking after the signed answer.
    let closed_unknown_ids: BTreeSet<String> = [crate::StoreKind::Company, crate::StoreKind::Codebase]
        .into_iter()
        .filter_map(|store| crate::store::read_records(store, repo, "unknowns.jsonl").ok())
        .flatten()
        .filter(|record| {
            matches!(
                record.get("status").and_then(Value::as_str),
                Some("closed") | Some("superseded")
            )
        })
        .filter_map(|record| {
            record
                .get("fact_id")
                .or_else(|| record.get("unknown_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    view_unknowns.retain(|unknown| !closed_unknown_ids.contains(&unknown.unknown_id));
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    let working: BTreeSet<&str> = working_set.iter().map(String::as_str).collect();
    let candidates: Vec<&CurrentFact> = facts
        .iter()
        .filter(|fact| {
            fact.status == "current"
                && fact.trust == "trusted"
                && fact.stale_reasons.is_empty()
                && !matches!(fact.disposition.as_str(), "disputed" | "expired" | "conflict")
        })
        .collect();
    let unknowns = unknown_outputs(&facts, &view_unknowns);
    let open_unknowns: Vec<_> = unknowns
        .iter()
        .filter(|unknown| unknown.status == "open" || unknown.status == "asked")
        .cloned()
        .collect();

    let mut selected: Vec<CurrentFact> = Vec::new();
    let mut selection_trace = Vec::new();
    let mut sufficiency = false;
    let mut byte_ceiling_hit = false;
    while selected.len() < PROJECTION_LIMIT {
        let mut best: Option<(&CurrentFact, Evaluation)> = None;
        for fact in &candidates {
            if selected.iter().any(|existing| existing.fact_id == fact.fact_id) {
                continue;
            }
            let prospective_json: Vec<Value> = selected
                .iter()
                .chain(std::iter::once(*fact))
                .map(candidate_value)
                .collect();
            let prospective_bytes = crate::json::canonical_text(&Value::Array(prospective_json)).len();
            let evaluation = evaluate(fact, &selected, &working, task, decision);
            if prospective_bytes > PROJECTION_BYTE_LIMIT {
                if evaluation.marginal_value > 0 {
                    byte_ceiling_hit = true;
                }
                continue;
            }
            let replace = best
                .as_ref()
                .map(|(current, current_value)| {
                    evaluation.marginal_value > current_value.marginal_value
                        || (evaluation.marginal_value == current_value.marginal_value && fact.fact_id < current.fact_id)
                })
                .unwrap_or(true);
            if replace {
                best = Some((fact, evaluation));
            }
        }
        let Some((fact, evaluation)) = best else { break };
        if evaluation.marginal_value <= 0 {
            break;
        }
        selection_trace.push(json!({
            "fact_id": fact.fact_id,
            "marginal_value": evaluation.marginal_value,
            "current_set_size": selected.len(),
            "redundancy_basis": evaluation.redundancy_basis,
            "marginal_terms": {
                "newly_covered_distortion": evaluation.newly_covered_distortion,
                "authority_and_validity_gain": evaluation.authority_and_validity_gain,
                "complementarity_gain": evaluation.complementarity_gain,
                "uncertainty_reduction": evaluation.uncertainty_reduction,
                "redundancy": evaluation.redundancy,
                "retrieval_and_residency_cost": evaluation.retrieval_and_residency_cost,
                "stale_or_conflict_risk": evaluation.stale_or_conflict_risk
            }
        }));
        selected.push((*fact).clone());
        if is_authority_answer(fact) && open_unknowns.is_empty() {
            sufficiency = true;
            break;
        }
    }

    let question_id = if open_unknowns.is_empty() {
        None
    } else {
        let evidence: Vec<String> = selected
            .iter()
            .map(|fact| fact.fact_id.clone())
            .chain(open_unknowns.iter().flat_map(|unknown| unknown.evidence.clone()))
            .collect();
        let remaining: Vec<String> = candidates
            .iter()
            .filter_map(|fact| {
                if selected.iter().any(|selected| selected.fact_id == fact.fact_id) {
                    None
                } else {
                    Some(fact.statement.clone())
                }
            })
            .collect();
        let mut raised = None;
        for unknown in open_unknowns.iter().filter(|unknown| unknown.loss_if_absent >= 7_000) {
            if let Some(id) = crate::questions::ensure_question(repo, unknown, decision, &evidence, &remaining)? {
                raised = Some(id);
                break;
            }
        }
        raised
    };

    let stopping_reason = if question_id.is_some() {
        "authority_question_raised"
    } else if sufficiency {
        "sufficiency_predicate_met"
    } else {
        "nonpositive_net_marginal_value"
    };
    let item_ceiling_hit = selected.len() == PROJECTION_LIMIT
        && candidates.iter().any(|fact| {
            !selected.iter().any(|existing| existing.fact_id == fact.fact_id)
                && evaluate(fact, &selected, &working, task, decision).marginal_value > 0
        });
    let omitted_count = if byte_ceiling_hit || item_ceiling_hit {
        candidates.len().saturating_sub(selected.len())
    } else {
        0
    };
    let tier_escalation: Vec<Value> = TIERS
        .iter()
        .map(|(tier, value, cost)| {
            json!({"tier": tier, "estimated_value": value, "estimated_cost": cost, "action": "visited"})
        })
        .collect();
    let selected_values: Vec<Value> = selected.iter().map(candidate_value).collect();
    let projection_bytes = crate::json::canonical_text(&Value::Array(selected_values.clone())).len();
    let company_reference = company_reference(&selected, &facts);
    let recommendation = if open_unknowns.is_empty() {
        selected
            .iter()
            .find(|fact| is_authority_answer(fact))
            .map(|fact| fact.statement.clone())
    } else {
        None
    };
    let degraded_policy = if open_unknowns.is_empty() {
        "block_dependent_decision"
    } else if open_unknowns.iter().any(|unknown| unknown.loss_if_absent >= 7_500) {
        "block_dependent_decision"
    } else {
        "reversible_sandbox_only_experiment"
    };
    let result = json!({
        "decision": decision,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "candidates": candidates.iter().map(|fact| candidate_value(fact)).collect::<Vec<_>>(),
        "selected": selected.iter().map(|fact| json!({"fact_id": fact.fact_id, "logical_key": fact.logical_key})).collect::<Vec<_>>(),
        "selection_trace": selection_trace,
        "tier_escalation": tier_escalation,
        "projection_bytes": projection_bytes,
        "stopping_reason": stopping_reason,
        "unknowns": unknowns.iter().map(unknown_value).collect::<Vec<_>>(),
        "voi_approximation": "additive deterministic basis-point approximation over conditional distortion, authority, complementarity, uncertainty, redundancy, retrieval, and staleness",
        "trusted_recommendation": recommendation,
        "degraded_policy": degraded_policy,
        "company_reference_resolved": company_reference.is_some(),
        "company_statement": company_reference.unwrap_or_default(),
        "projection_state": if open_unknowns.is_empty() { "projected" } else { "withheld" },
        "omitted_count": omitted_count
    });

    let query_record = json!({
        "requested": TIERS.iter().map(|(tier, _, _)| *tier).collect::<Vec<_>>(),
        "returned": candidates.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selected": selected.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "working_set": working_set,
        "resident_at_dependent_edit": working_set,
        "declared_use": decision,
        "stopping_reason": stopping_reason,
        "question_id": question_id,
        "task_outcome": "pending",
        "cost": TIERS.iter().map(|(_, _, cost)| *cost).sum::<i64>(),
        "as_of": as_of.as_of
    });
    launcher.private_store()?.log_query(Some(decision), &query_record)?;

    if json {
        println!("{}", crate::json::canonical_text(&result));
    } else {
        println!("decision: {decision}");
        println!("selected_count: {}", selected.len());
        println!("omitted_count: {omitted_count}");
        println!("stopping_reason: {stopping_reason}");
    }
    Ok(())
}

fn load_view(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
) -> Result<CurrentView, ContractError> {
    let (mut events, unknowns) = crate::corpus::load_store(launcher, repo, store)?;
    if store == crate::StoreKind::Codebase {
        if let Ok(repository) = crate::codebase::Repository::discover(repo) {
            let repository_uuid = repository.uuid_hint().map(str::to_owned);
            events.retain(|admitted| {
                admitted
                    .event
                    .repository_id
                    .as_deref()
                    .map(|bound| repository_uuid.as_deref().is_some_and(|uuid| bound == uuid))
                    .unwrap_or(true)
            });
        }
    }
    let store_name = match store {
        crate::StoreKind::Company => "company",
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Codebase => "codebase",
    };
    let input = ReducerInput {
        store_kind: store_name.to_owned(),
        events,
        unknowns,
        tombstones: Vec::new(),
        revocations: Vec::new(),
        as_of: as_of.as_of.clone(),
        authority_cursor: "0".to_owned(),
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid: true,
    };
    Ok(crate::reducer::reduce(&input))
}

fn candidate_value(fact: &CurrentFact) -> Value {
    json!({
        "logical_key": fact.logical_key,
        "fact_id": fact.fact_id,
        "atom_kind": fact.atom_kind,
        "statement": fact.statement,
        "scope": fact.scope,
        "authority_scope": fact.authority_scope,
        "distortion": fact.distortion,
        "validity": {
            "status": fact.status,
            "effective_from": fact.effective_from,
            "effective_until": fact.effective_until
        },
        "role": fact.authority_id
    })
}

fn unknown_value(unknown: &UnknownOut) -> Value {
    json!({
        "owner_role": unknown.owner_role,
        "owner_identity": unknown.owner_identity,
        "logical_key": unknown.logical_key,
        "reason": if unknown.kind == "explicit" { format!("{}: {}", unknown.status, unknown.question) } else { format!("{}: {}", unknown.status, unknown.kind) }
    })
}

fn unknown_outputs(facts: &[CurrentFact], view_unknowns: &[crate::reducer::DerivedUnknown]) -> Vec<UnknownOut> {
    let mut by_key: BTreeMap<String, UnknownOut> = BTreeMap::new();
    for unknown in view_unknowns {
        if unknown.status != "open" && unknown.status != "asked" {
            continue;
        }
        by_key.insert(
            unknown.logical_key.clone(),
            UnknownOut {
                unknown_id: unknown.unknown_id.clone(),
                logical_key: unknown.logical_key.clone(),
                scope: unknown.scope.clone(),
                decision_blocked: unknown.decision_blocked.clone(),
                owner_role: unknown.owner_role.clone(),
                owner_identity: unknown.owner_identity.clone(),
                question: unknown.question.clone(),
                evidence: unknown.discriminating_evidence.clone(),
                loss_if_absent: unknown.loss_if_absent,
                status: unknown.status.clone(),
                kind: unknown.kind.clone(),
            },
        );
    }
    for fact in facts {
        let ineligible = fact.status != "current"
            || fact.trust != "trusted"
            || !fact.stale_reasons.is_empty()
            || matches!(fact.disposition.as_str(), "disputed" | "expired" | "conflict");
        if ineligible && !by_key.contains_key(&fact.logical_key) {
            let owner_role = if fact.store_kind == "company" { "company-steward" } else { "repository-maintainer" };
            by_key.insert(
                fact.logical_key.clone(),
                UnknownOut {
                    unknown_id: format!("unknown_{}", &fact.fact_id[5.min(fact.fact_id.len())..]),
                    logical_key: fact.logical_key.clone(),
                    scope: fact.scope.clone(),
                    decision_blocked: fact.distortion.trigger.clone(),
                    owner_role: owner_role.to_owned(),
                    owner_identity: fact.authority_id.clone(),
                    question: format!("Fact {} is not selectable; refresh or supersede its evidence.", fact.fact_id),
                    evidence: fact.evidence_refs.clone(),
                    loss_if_absent: fact.distortion.loss_if_absent,
                    status: "open".to_owned(),
                    kind: if fact.stale_reasons.is_empty() { fact.disposition.clone() } else { "stale".to_owned() },
                },
            );
        }
    }
    let mut values: Vec<_> = by_key.into_values().collect();
    values.sort_by(|left, right| right.loss_if_absent.cmp(&left.loss_if_absent).then_with(|| left.unknown_id.cmp(&right.unknown_id)));
    values
}

fn evaluate(
    fact: &CurrentFact,
    selected: &[CurrentFact],
    working: &BTreeSet<&str>,
    task: &str,
    decision: &str,
) -> Evaluation {
    let resident = working.contains(fact.fact_id.as_str());
    let decision_terms = terms(decision);
    let task_terms = terms(task);
    let statement_terms = terms(&fact.statement);
    let decision_overlap = statement_terms.intersection(&decision_terms).count().min(4) as i64;
    let task_overlap = statement_terms.intersection(&task_terms).count().min(4) as i64;
    let relevance = 3_000 + decision_overlap.saturating_mul(1_000) + task_overlap.saturating_mul(500);
    let newly_covered = if resident {
        0
    } else {
        i64::from(fact.distortion.loss_if_absent)
            .saturating_mul(relevance)
            .saturating_div(10_000)
    };
    let authority_gain = if resident {
        0
    } else {
        let base = if fact.authority_scope.starts_with("architecture") || fact.store_kind == "company" { 800 } else { 300 };
        base + (i64::from(fact.confidence) / 20).min(500)
    };
    let complements_selected = selected.iter().any(|existing| {
        fact.complements.contains(&existing.fact_id)
            || existing.complements.contains(&fact.fact_id)
            || complementary_pair(fact, existing, decision)
    });
    let complementarity = if resident { 0 } else if complements_selected { 2_500 } else { 0 };
    let uncertainty = if resident {
        0
    } else {
        (i64::try_from(fact.independent_support_count).unwrap_or(i64::MAX).saturating_mul(250)).min(1_000)
            + if fact.company_refs.is_empty() { 0 } else { 250 }
    };
    let (redundancy, basis) = redundancy(fact, selected);
    let cost = if resident { -25 } else { -250 };
    let stale = 0;
    Evaluation {
        marginal_value: newly_covered + authority_gain + complementarity + uncertainty + redundancy + cost + stale,
        newly_covered_distortion: newly_covered,
        authority_and_validity_gain: authority_gain,
        complementarity_gain: complementarity,
        uncertainty_reduction: uncertainty,
        redundancy,
        retrieval_and_residency_cost: cost,
        stale_or_conflict_risk: stale,
        redundancy_basis: basis,
    }
}

fn complementary_pair(left: &CurrentFact, right: &CurrentFact, decision: &str) -> bool {
    let decision_terms = terms(decision);
    let left_key = terms(&left.logical_key);
    let right_key = terms(&right.logical_key);
    let left_in_decision = !left_key.intersection(&decision_terms).collect::<BTreeSet<_>>().is_empty();
    let right_in_decision = !right_key.intersection(&decision_terms).collect::<BTreeSet<_>>().is_empty();
    let test = |fact: &CurrentFact| matches!(fact.atom_kind.as_str(), "test" | "runtime_trace" | "test_runtime_evidence");
    let rationale = |fact: &CurrentFact| fact.atom_kind == "rationale";
    (test(left) && rationale(right) && left_in_decision && right_in_decision)
        || (rationale(left) && test(right) && left_in_decision && right_in_decision)
}

fn redundancy(fact: &CurrentFact, selected: &[CurrentFact]) -> (i64, String) {
    for existing in selected {
        let explicit = fact.redundancy_with.contains(&existing.fact_id)
            || existing.redundancy_with.contains(&fact.fact_id);
        if explicit {
            return (-8_000, "explicit_edge".to_owned());
        }
        let fact_support: BTreeSet<&str> = fact.support_event_ids.iter().chain(fact.evidence_refs.iter()).map(String::as_str).collect();
        let existing_support: BTreeSet<&str> = existing.support_event_ids.iter().chain(existing.evidence_refs.iter()).map(String::as_str).collect();
        if !fact_support.intersection(&existing_support).collect::<BTreeSet<_>>().is_empty() {
            return (-3_000, "shared_provenance".to_owned());
        }
    }
    let fact_terms = terms(&fact.statement);
    let mut best = (0i64, "none".to_owned());
    for existing in selected {
        let existing_terms = terms(&existing.statement);
        let intersection = fact_terms.intersection(&existing_terms).count() as i64;
        let total = fact_terms.len() as i64 + existing_terms.len() as i64;
        if total == 0 {
            continue;
        }
        let similarity = intersection.saturating_mul(2).saturating_mul(10_000).saturating_div(total);
        if similarity >= 6_000 {
            let penalty = similarity.saturating_mul(5_000).saturating_div(10_000);
            if penalty > best.0 {
                best = (penalty, format!("lexical_similarity:{similarity}"));
            }
        }
    }
    (-best.0, best.1)
}

fn is_authority_answer(fact: &CurrentFact) -> bool {
    fact.store_kind == "company"
        && fact.atom_kind == "decision"
        && fact.evidence_refs.iter().any(|reference| reference.starts_with("answer_"))
}

fn company_reference(selected: &[CurrentFact], all_facts: &[CurrentFact]) -> Option<String> {
    let company_facts: BTreeMap<&str, &CurrentFact> = all_facts
        .iter()
        .filter(|fact| fact.store_kind == "company")
        .map(|fact| (fact.fact_id.as_str(), fact))
        .collect();
    for fact in selected {
        for reference in &fact.company_refs {
            if let Some(company_fact) = company_facts.get(reference.fact_id.as_str()) {
                return Some(company_fact.statement.clone());
            }
        }
    }
    None
}

fn terms(value: &str) -> BTreeSet<String> {
    value
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|part| part.len() > 2)
        .map(str::to_owned)
        .collect()
}
