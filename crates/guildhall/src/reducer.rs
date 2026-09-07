use crate::model::{CurrentFact, FactEvent};
use std::collections::{BTreeMap, BTreeSet};

pub const REDUCER_VERSION: &str = "guildhall-reducer/1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReductionTrace {
    pub facts: Vec<CurrentFact>,
    pub conflict_keys: Vec<String>,
    pub expired_keys: Vec<String>,
    pub retracted_keys: Vec<String>,
    pub superseded_event_ids: Vec<String>,
    pub rejected_event_ids: Vec<String>,
}

pub fn reduce(events: &[FactEvent], as_of: &str) -> Vec<CurrentFact> {
    reduce_with_trace(events, as_of).facts
}

pub fn reduce_with_trace(events: &[FactEvent], as_of: &str) -> ReductionTrace {
    let superseded: BTreeSet<&str> = events
        .iter()
        .flat_map(|event| event.supersedes.iter())
        .map(String::as_str)
        .collect();
    let mut groups: BTreeMap<&str, Vec<&FactEvent>> = BTreeMap::new();
    let mut conflict_keys = Vec::new();
    let mut expired_keys = Vec::new();
    let mut retracted_keys = Vec::new();
    let mut rejected_event_ids = Vec::new();

    for event in events {
        if event.disposition == "retracted" || event.disposition == "revoked" {
            retracted_keys.push(event.logical_key.clone());
            continue;
        }
        if event.disposition == "rejected"
            || event.disposition == "reverted"
            || event.disposition == "failed"
        {
            rejected_event_ids.push(event.event_id.clone());
            continue;
        }
        if event
            .effective_until
            .as_ref()
            .is_some_and(|until| until.as_str() <= as_of)
        {
            expired_keys.push(event.logical_key.clone());
            continue;
        }
        if event.effective_from.as_str() > as_of {
            expired_keys.push(event.logical_key.clone());
            continue;
        }
        groups
            .entry(event.logical_key.as_str())
            .or_default()
            .push(event);
    }

    let mut facts = Vec::new();
    for (logical_key, mut group) in groups {
        group.retain(|event| !superseded.contains(event.event_id.as_str()));
        let mut deduplicated: BTreeMap<&str, &FactEvent> = BTreeMap::new();
        for event in group {
            deduplicated
                .entry(event.statement.as_str())
                .and_modify(|existing| {
                    if event.event_id < existing.event_id {
                        *existing = event;
                    }
                })
                .or_insert(event);
        }
        let mut survivors: Vec<&&FactEvent> = deduplicated.values().collect();
        survivors.sort_by(|left, right| left.event_id.cmp(&right.event_id));
        if survivors.is_empty() {
            continue;
        }
        let conflict = survivors.len() > 1;
        if conflict {
            conflict_keys.push((*logical_key).to_owned());
        }
        let event = *survivors[0];
        facts.push(CurrentFact {
            fact_id: event.fact_id.clone(),
            logical_key: event.logical_key.clone(),
            atom_kind: event.atom_kind.clone(),
            scope: event.scope.clone(),
            statement: event.statement.clone(),
            status: if conflict {
                "conflict".to_owned()
            } else {
                "current".to_owned()
            },
            disposition: event.disposition.clone(),
            authority_id: event.authority_id.clone(),
            authority_scope: event.authority_scope.clone(),
            effective_from: event.effective_from.clone(),
            effective_until: event.effective_until.clone(),
            loss_if_absent: event.distortion.loss_if_absent,
            company_refs: event.company_refs.clone(),
            evidence_refs: event.evidence_refs.clone(),
        });
    }

    conflict_keys.sort();
    expired_keys.sort();
    retracted_keys.sort();
    ReductionTrace {
        facts,
        conflict_keys,
        expired_keys,
        retracted_keys,
        superseded_event_ids: superseded.into_iter().map(str::to_owned).collect(),
        rejected_event_ids,
    }
}
