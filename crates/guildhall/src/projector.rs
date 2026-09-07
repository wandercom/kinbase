use crate::model::CurrentFact;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROJECTION_LIMIT: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionTrace {
    pub selected: Vec<CurrentFact>,
    pub omitted_count: usize,
    pub stopping_reason: String,
    pub marginal_gains: Vec<Value>,
}

pub fn project(facts: &[CurrentFact], working_set: &[String]) -> ProjectionTrace {
    let known: Vec<_> = facts
        .iter()
        .filter(|fact| working_set.contains(&fact.fact_id))
        .collect();
    let mut selected = Vec::new();
    let mut marginal_gains = Vec::new();
    for fact in facts.iter().take(PROJECTION_LIMIT) {
        let duplicate = selected
            .iter()
            .any(|selected: &CurrentFact| selected.statement.eq_ignore_ascii_case(&fact.statement));
        let marginal = if duplicate || known.iter().any(|known| known.fact_id == fact.fact_id) {
            0
        } else if fact.status == "current" {
            80
        } else {
            0
        };
        if marginal > 0 {
            selected.push(fact.clone());
            marginal_gains.push(serde_json::json!({"fact_id": fact.fact_id, "marginal": marginal}));
        }
    }
    ProjectionTrace {
        selected,
        omitted_count: facts.len().saturating_sub(PROJECTION_LIMIT),
        stopping_reason: "nonpositive marginal gain".to_owned(),
        marginal_gains,
    }
}

pub fn run(
    repo: &std::path::Path,
    _task: &str,
    decision: &str,
    working_set: &[String],
    json: bool,
) -> crate::error::Result<()> {
    let view_path = repo.join(".kin/local/current.json");
    let facts: Vec<crate::model::CurrentFact> = if view_path.exists() {
        std::fs::read_to_string(view_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .map(|view: serde_json::Value| view.get("facts").cloned())
            .flatten()
            .map(|facts| serde_json::from_value(facts).unwrap_or_default())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let trace = project(&facts, working_set);
    let result = serde_json::json!({"decision":decision,"selected_count":trace.selected.len(),"omitted_count":trace.omitted_count,"stopping_reason":trace.stopping_reason,"facts":trace.selected});
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
