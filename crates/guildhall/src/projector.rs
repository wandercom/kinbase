use crate::model::CurrentFact;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub const PROJECTION_LIMIT: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionTrace {
    pub selected: Vec<CurrentFact>,
    pub omitted_count: usize,
    pub stopping_reason: String,
    pub marginal_gains: Vec<Value>,
    pub unknown_ids: Vec<String>,
}

pub fn project(facts: &[CurrentFact], working_set: &[String], task: &str, decision: &str, unknown_ids: &[String]) -> ProjectionTrace {
    let known: BTreeSet<&str> = working_set.iter().map(String::as_str).collect();
    let task_terms = terms(task);
    let decision_terms = terms(decision);
    let mut selected: Vec<CurrentFact> = Vec::new();
    let mut selected_kinds = BTreeSet::new();
    let mut marginal_gains = Vec::new();
    let mut omitted = 0;
    let mut candidates: Vec<&CurrentFact> = facts
        .iter()
        .filter(|fact| {
            if known.contains(fact.fact_id.as_str()) || fact.status != "current" {
                omitted += 1;
                false
            } else {
                true
            }
        })
        .collect();
    candidates.sort_by(|left, right| {
        right
            .loss_if_absent
            .cmp(&left.loss_if_absent)
            .then_with(|| left.fact_id.cmp(&right.fact_id))
    });
    for fact in candidates {
        if selected.len() >= PROJECTION_LIMIT {
            omitted += 1;
            continue;
        }
        let mut duplicate = false;
        for existing in &selected {
            if existing.statement.eq_ignore_ascii_case(&fact.statement)
                || existing.logical_key == fact.logical_key
                || existing.fact_id == fact.fact_id
            {
                duplicate = true;
                break;
            }
        }
        if duplicate {
            omitted += 1;
            continue;
        }
        let statement_terms = terms(&fact.statement);
        let task_overlap = statement_terms.intersection(&task_terms).count() as u16;
        let decision_overlap = statement_terms.intersection(&decision_terms).count() as u16;
        let relevance = 4_000 + (task_overlap.saturating_mul(1_000)).min(3_000)
            + (decision_overlap.saturating_mul(1_000)).min(2_000);
        let authority_gain = if fact.authority_scope.starts_with("architecture") { 1_000 } else { 300 };
        let complementarity = if selected_kinds.insert(fact.atom_kind.clone()) { 700 } else { 0 };
        let redundancy = if selected.is_empty() { 0 } else { 150 };
        let cost = 200;
        let marginal = fact.loss_if_absent.saturating_mul(relevance).saturating_div(10_000)
            + authority_gain
            + complementarity
            - redundancy
            - cost;
        if marginal <= 0 {
            omitted += 1;
            continue;
        }
        marginal_gains.push(serde_json::json!({
            "fact_id": fact.fact_id,
            "marginal": marginal,
            "terms": {
                "relevance": relevance,
                "authority_gain": authority_gain,
                "complementarity_gain": complementarity,
                "redundancy_cost": redundancy,
                "retrieval_cost": cost
            }
        }));
        selected.push(fact.clone());
    }
    let selected_count = selected.len();
    ProjectionTrace {
        selected,
        omitted_count: omitted,
        stopping_reason: if selected_count >= PROJECTION_LIMIT {
            "projection limit".to_owned()
        } else {
            "nonpositive marginal gain".to_owned()
        },
        marginal_gains,
        unknown_ids: unknown_ids.to_vec(),
    }
}

fn terms(value: &str) -> BTreeSet<String> {
    value
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|part| part.len() > 2)
        .map(str::to_owned)
        .collect()
}

pub fn run(
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    json: bool,
) -> crate::error::Result<()> {
    let mut facts = Vec::new();
    let mut unknown_ids = Vec::new();
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        let root = crate::store::store_root(store, repo);
        let view_path = root.join("local").join("current.json");
        if let Ok(text) = std::fs::read_to_string(&view_path) {
            if let Ok(view) = serde_json::from_str::<Value>(&text) {
                if let Some(view_facts) = view.get("facts").cloned() {
                    if let Ok(store_facts) = serde_json::from_value::<Vec<CurrentFact>>(view_facts) {
                        facts.extend(store_facts);
                    }
                }
                if let Some(ids) = view.get("unknown_ids").and_then(Value::as_array) {
                    unknown_ids.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
        }
    }
    let trace = project(&facts, working_set, task, decision, &unknown_ids);
    let result = serde_json::json!({
        "decision": decision,
        "selected_count": trace.selected.len(),
        "omitted_count": trace.omitted_count,
        "stopping_reason": trace.stopping_reason,
        "facts": trace.selected,
        "marginal_gains": trace.marginal_gains,
        "unknown_ids": trace.unknown_ids
    });
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("decision: {decision}");
        println!("selected_count: {}", trace.selected.len());
        println!("omitted_count: {}", trace.omitted_count);
        println!("stopping_reason: {}", trace.stopping_reason);
    }
    Ok(())
}
