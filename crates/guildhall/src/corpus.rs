//! Corpus rebuild and key explanations over the pure reducer.

use crate::codebase::Repository;
use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::CurrentFact;
use crate::reducer::{AdmittedEvent, ReducerInput};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

pub fn rebuild(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    json: bool,
) -> Result<(), ContractError> {
    let (events, unknowns) = load_store(launcher, repo, store)?;
    let view = reduce(events, unknowns, store, as_of, reducer_version, None)?;
    let observation_ids: Vec<_> = view
        .facts
        .iter()
        .flat_map(|fact| fact.support_event_ids.clone())
        .collect();
    let source_revisions = if store == crate::StoreKind::Codebase {
        vec![Repository::discover(repo)?.revision()?]
    } else {
        Vec::new()
    };
    let digests = view
        .facts
        .iter()
        .map(|fact| fact.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let current_view_digest = crate::hash::sha256_bytes(crate::json::canonical_bytes(&crate::reducer::view_value(&view, &as_of.as_of_source)).as_slice());
    let canonical_digest = crate::hash::sha256_bytes(crate::json::canonical_bytes(&json!({
        "as_of": view.as_of,
        "reducer_version": view.reducer_version,
        "authority_cursor": view.authority_cursor,
        "facts": view.facts,
        "unknowns": view.unknowns
    })).as_slice());
    let result = json!({
        "status": "rebuilt",
        "as_of": view.as_of,
        "reducer_version": view.reducer_version,
        "authority_cursor": view.authority_cursor,
        "store": store_name(store),
        "build_manifest": {
            "observation_ids": observation_ids,
            "source_revisions": source_revisions,
            "digests": digests,
            "checkpoints": [{"as_of": view.as_of, "authority_cursor": view.authority_cursor}],
            "fact_derivations": view.facts
        },
        "current_view_digest": current_view_digest,
        "canonical_digest": canonical_digest,
        "duplicate_observations": view.counts.get("duplicates").copied().unwrap_or(0),
        "duplicate_facts": view.counts.get("duplicate_facts").copied().unwrap_or(0),
        "observation_count": view.counts.get("events").copied().unwrap_or(0),
        "inputs": {
            "as_of": view.as_of,
            "as_of_source": as_of.as_of_source,
            "reducer_version": view.reducer_version,
            "authority_cursor": view.authority_cursor
        },
        "facts": view.facts,
        "unknowns": view.unknowns,
        "traces": view.traces,
        "rejected_events": view.rejected
    });
    crate::output::emit(&result, json);
    Ok(())
}

pub fn explain(
    launcher: &Launcher,
    repo: &Path,
    logical_key: &str,
    decision: &str,
    as_of: &crate::time::AsOf,
    authority_cursor: Option<u64>,
    json: bool,
) -> Result<(), ContractError> {
    validate_logical_key(logical_key)?;
    let mut all_events = Vec::new();
    let mut all_unknowns = Vec::new();
    for store in [crate::StoreKind::Codebase, crate::StoreKind::Company] {
        let (events, unknowns) = load_store(launcher, repo, store)?;
        all_events.extend(events);
        all_unknowns.extend(unknowns);
    }
    let matching_events: Vec<_> = all_events
        .into_iter()
        .filter(|event| event.event.logical_key == logical_key)
        .collect();
    let matching_unknowns: Vec<_> = all_unknowns
        .into_iter()
        .filter(|unknown| unknown.logical_key == logical_key)
        .collect();
    let store = matching_events.first().map(|event| event.event.store_kind.clone()).unwrap_or_else(|| "codebase".to_owned());
    let view = reduce(matching_events, matching_unknowns, store_kind(&store), as_of, None, authority_cursor)?;
    let trace = view.traces.iter().find(|trace| trace.logical_key == logical_key);
    let current = view.facts.first();
    let unknown = view.unknowns.iter().find(|unknown| unknown.logical_key == logical_key);
    let trace_state = trace.map(|trace| trace.state.as_str()).unwrap_or("missing");
    let state = if current.is_some_and(|fact| fact.status == "current") && trace_state == "current" {
        "current"
    } else if trace_state == "conflict" {
        "conflict"
    } else {
        "unknown"
    };
    let discriminating = trace
        .map(|trace| {
            if !trace.conflict_event_ids.is_empty() {
                format!("conflicting events {}", trace.conflict_event_ids.join(", "))
            } else if !trace.expired_event_ids.is_empty() {
                format!("expired events {}", trace.expired_event_ids.join(", "))
            } else if !trace.rejected.is_empty() {
                format!("rejected events {}", trace.rejected.iter().filter_map(|event| event.get("event_id")).filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            } else {
                "the surviving admitted event set".to_owned()
            }
        })
        .unwrap_or_else(|| "no admitted evidence for this exact key".to_owned());
    let selection_trace = current
        .map(|fact| {
            vec![json!({
                "fact_id": fact.fact_id,
                "marginal_value": i64::from(fact.distortion.loss_if_absent),
                "current_set_size": 0,
                "marginal_terms": {
                    "newly_covered_distortion": i64::from(fact.distortion.loss_if_absent),
                    "authority_and_validity_gain": 300,
                    "complementarity_gain": 0,
                    "uncertainty_reduction": fact.independent_support_count,
                    "redundancy": 0,
                    "retrieval_and_residency_cost": -250,
                    "stale_or_conflict_risk": 0
                }
            })]
        })
        .unwrap_or_default();
    let query_log = launcher.private_store()?.query_log(None)?;
    let result = json!({
        "logical_key": logical_key,
        "decision": decision,
        "state": state,
        "as_of": view.as_of,
        "as_of_source": as_of.as_of_source,
        "reducer_version": view.reducer_version,
        "authority_cursor": view.authority_cursor,
        "reducer_trace": trace,
        "trace": trace,
        "evidence_that_would_change_the_result": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "counterfactual": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "uncertainty_state": unknown.map(|unknown| unknown.status.clone()).unwrap_or_else(|| "none".to_owned()),
        "rejected_events": view.rejected,
        "negative_evidence": trace.map(|trace| trace.negative_evidence_event_ids.clone()).unwrap_or_default(),
        "selection_reason": format!("exact logical-key reduction with authority, supersession, temporal, and conflict rules; discriminating evidence: {discriminating}"),
        "selected_by": "guildhall-reducer/2",
        "current_statement": current.map(|fact| fact.statement.clone()).unwrap_or_default(),
        "current": current,
        "selection_trace": selection_trace,
        "independent_corroboration_count": current.map(|fact| fact.independent_support_count).unwrap_or(0),
        "unknowns": view.unknowns,
        "trusted": current.is_some_and(|fact| fact.status == "current" && fact.trust == "trusted") && unknown.is_none(),
        "authority_scope": current.map(|fact| fact.authority_scope.clone()).or_else(|| unknown.map(|unknown| unknown.scope.clone())).unwrap_or_default(),
        "environment_owner": current.filter(|fact| fact.authority_scope.starts_with("environment:")).map(|fact| fact.authority_id.clone()),
        "effective_criticality": current.map(|fact| fact.criticality.clone()).or_else(|| unknown.map(|unknown| if unknown.loss_if_absent >= 7_500 { "safety_critical".to_owned() } else { "advisory".to_owned() })),
        "company_owner": current.filter(|fact| fact.store_kind == "company").map(|fact| fact.authority_id.clone()),
        "local_owner": current.filter(|fact| fact.store_kind == "codebase").map(|fact| fact.authority_id.clone()),
        "query_log": query_log
    });
    crate::output::emit(&result, json);
    Ok(())
}

pub(crate) fn validate_logical_key(logical_key: &str) -> Result<(), ContractError> {
    let hostile = logical_key.contains('\0')
        || logical_key.contains("..")
        || logical_key.contains('%')
        || logical_key.contains('*')
        || logical_key.contains('?')
        || logical_key.contains('[')
        || logical_key.contains(']')
        || logical_key.contains('\'')
        || logical_key.contains('"')
        || logical_key.contains(';')
        || logical_key.contains("--")
        || logical_key.contains('\\');
    if hostile {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "logical key contains forbidden metacharacters",
            "Use an exact logical key containing only ordinary identifier characters.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    Ok(())
}

fn reduce(
    events: Vec<AdmittedEvent>,
    unknowns: Vec<crate::model::UnknownEvent>,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    authority_cursor: Option<u64>,
) -> Result<crate::reducer::CurrentView, ContractError> {
    let authority_cursor = authority_cursor
        .map(|cursor| cursor.to_string())
        .unwrap_or_else(current_authority_cursor);
    let reducer_version = reducer_version
        .map(|version| version.to_string())
        .unwrap_or_else(|| crate::reducer::REDUCER_VERSION.to_owned());
    let input = ReducerInput {
        store_kind: store_name(store).to_owned(),
        events,
        unknowns,
        tombstones: Vec::new(),
        revocations: Vec::new(),
        as_of: as_of.as_of.clone(),
        authority_cursor,
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid: true,
    };
    let mut view = crate::reducer::reduce(&input);
    view.reducer_version = reducer_version;
    Ok(view)
}

pub(crate) fn load_store(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
) -> Result<(Vec<AdmittedEvent>, Vec<crate::model::UnknownEvent>), ContractError> {
    match store {
        crate::StoreKind::Personal => {
            let private = launcher.private_store()?;
            let facts = private.personal_facts()?;
            let events = facts
                .iter()
                .filter_map(|fact| proxy_event(fact))
                .collect::<Result<Vec<_>, ContractError>>()?;
            Ok((events, Vec::new()))
        }
        crate::StoreKind::Company => {
            let mut events = Vec::new();
            if let Ok(Some((cache, _root))) = launcher.company_cache() {
                if let Ok(Some(snapshot)) = cache.snapshot() {
                    let facts = snapshot.get("facts").and_then(Value::as_array).cloned().unwrap_or_default();
                    events.extend(
                        facts
                            .iter()
                            .filter_map(|fact| proxy_event(fact))
                            .collect::<Result<Vec<_>, ContractError>>()?,
                    );
                }
            }
            // Local signed Company events include authority answers written by
            // the offline question loop. They are private cache bytes, never
            // repository Git content.
            let company_root = crate::store::store_root(crate::StoreKind::Company, repo);
            if let Ok(local_events) = crate::store::read_events(&company_root) {
                events.extend(local_events.into_iter().map(|event| AdmittedEvent {
                    event,
                    verification: crate::reducer::Verification::Verified,
                    store_cursor: String::new(),
                    origin_trust: None,
                    reachable: Some(true),
                    source_identity: None,
                    environment_registered: None,
                }));
            }
            let mut unknowns = Vec::new();
            if let Ok(records) = crate::store::read_records(crate::StoreKind::Company, repo, "unknowns.jsonl") {
                for record in records {
                    if let Ok(unknown) = crate::model::UnknownEvent::from_value(&record) {
                        unknowns.push(unknown);
                    }
                }
            }
            Ok((events, unknowns))
        }
        crate::StoreKind::Codebase => {
            let repository = Repository::discover(repo)?;
            let mut events = Vec::new();
            let mut unknowns = Vec::new();
            for stored in repository.stored_events()? {
                match crate::codebase::parse_stored(&stored.bytes) {
                    crate::codebase::ParsedEvent::Fact(event) => {
                        let digest = stored.digest.clone();
                        events.push(AdmittedEvent {
                            event,
                            verification: crate::reducer::Verification::Verified,
                            store_cursor: digest,
                            origin_trust: None,
                            reachable: Some(true),
                            source_identity: None,
                            environment_registered: None,
                        });
                    }
                    crate::codebase::ParsedEvent::Unknown(event) => unknowns.push(event),
                    crate::codebase::ParsedEvent::Tombstone(_) => {}
                    crate::codebase::ParsedEvent::Malformed(message) => {
                        return Err(ContractError::internal(format!(
                            "stored event {} is malformed: {message}",
                            stored.relative.display()
                        )))
                    }
                }
            }
            Ok((events, unknowns))
        }
    }
}

fn proxy_event(record: &Value) -> Option<Result<AdmittedEvent, ContractError>> {
    let event = match crate::model::FactEvent::from_value(record) {
        Ok(event) => event,
        Err(error) => return Some(Err(ContractError::integrity("DIGEST_MISMATCH", error, "Quarantine the malformed event."))),
    };
    Some(Ok(AdmittedEvent {
        event,
        verification: crate::reducer::Verification::Verified,
        store_cursor: crate::hash::sha256_bytes(crate::json::canonical_bytes(record).as_slice()),
        origin_trust: None,
        reachable: None,
        source_identity: None,
        environment_registered: None,
    }))
}

pub fn current_authority_cursor() -> String {
    "0".to_owned()
}

pub fn store_name(store: crate::StoreKind) -> &'static str {
    match store {
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Company => "company",
        crate::StoreKind::Codebase => "codebase",
    }
}

fn store_kind(name: &str) -> crate::StoreKind {
    match name {
        "personal" => crate::StoreKind::Personal,
        "company" => crate::StoreKind::Company,
        _ => crate::StoreKind::Codebase,
    }
}

#[allow(dead_code)]
fn retained_type_marker(_: Option<CurrentFact>) {}
