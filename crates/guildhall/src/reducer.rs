use crate::model::{CurrentFact, FactEvent};

pub const REDUCER_VERSION: &str = "guildhall-reducer/1";

pub fn reduce(events: &[FactEvent], as_of: &str) -> Vec<CurrentFact> {
    let mut result = Vec::new();
    for event in events {
        let expired = event
            .effective_until
            .as_ref()
            .is_some_and(|until| until.as_str() <= as_of);
        let retracted = event.disposition == "retracted" || event.disposition == "revoked";
        if expired || retracted {
            continue;
        }
        result.push(CurrentFact {
            fact_id: event.fact_id.clone(),
            logical_key: event.logical_key.clone(),
            statement: event.statement.clone(),
            status: if event.disposition == "conflict" {
                "conflict".to_owned()
            } else {
                "current".to_owned()
            },
            authority_scope: event.authority_scope.clone(),
            effective_from: event.effective_from.clone(),
            effective_until: event.effective_until.clone(),
        });
    }
    result
}
