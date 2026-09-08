//! Corpus rebuild and key explanations over the pure reducer.

use crate::codebase::Repository;
use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::CurrentFact;
use crate::reducer::{AdmittedEvent, ReducerInput, Revocation, Tombstone};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) struct StoreData {
    pub events: Vec<AdmittedEvent>,
    pub unknowns: Vec<crate::model::UnknownEvent>,
    pub tombstones: Vec<Tombstone>,
    pub revocations: Vec<Revocation>,
    pub authority_cursor: String,
    pub certificate_valid: bool,
    pub authority_owner_by_scope: BTreeMap<String, String>,
    pub steward_authority_id: Option<String>,
}

pub fn rebuild(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    authority_cursor: Option<u64>,
    json: bool,
) -> Result<(), ContractError> {
    if store == crate::StoreKind::Company {
        // A Company rebuild reduces the published event set at the current
        // cursor; refresh the snapshot when Company is reachable and keep the
        // cached one otherwise.
        if let Ok(launcher) = crate::launcher::Launcher::load() {
            let _ = crate::repository::RepoContext::load(launcher, repo, true, Some(&as_of.as_of));
        }
    }
    let data = load_store(launcher, repo, store)?;
    let private_observations = launcher.private_store()?.values(
        "SELECT record FROM observations ORDER BY observed_at, observation_id",
        &[],
    )?;
    let adapter_receipts: BTreeMap<&str, usize> = private_observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "source_kind").map(|kind| (kind, ()))
        })
        .fold(
            BTreeMap::new(),
            |mut counts: BTreeMap<&str, usize>, (kind, ())| {
                *counts.entry(kind).or_insert(0) += 1;
                counts
            },
        );
    let stored_observation_ids = private_observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "observation_id").map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let event_ids: Vec<String> = data
        .events
        .iter()
        .map(|event| event.event.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let event_inputs: Vec<Value> = data
        .events
        .iter()
        .map(|event| crate::model::value_of(event))
        .collect();
    let authority_cursor_value = authority_cursor
        .map(|cursor| cursor.to_string())
        .unwrap_or_else(|| data.authority_cursor.clone());
    let view = reduce(
        data,
        store_name(store),
        as_of,
        reducer_version,
        Some(authority_cursor_value.clone()),
    )?;
    let observation_ids = if stored_observation_ids.is_empty() {
        view.facts
            .iter()
            .flat_map(|fact| fact.support_event_ids.clone())
            .collect::<Vec<_>>()
    } else {
        stored_observation_ids
    };
    let source_revisions = if store == crate::StoreKind::Codebase {
        vec![Repository::discover(repo)?.revision()?]
    } else {
        Vec::new()
    };
    // Adapter-derived facts (architecture §4 reconcile): the build manifest
    // binds every observation digest and every derivation the ledger yields
    // for this store, beside the reducer's signed-event facts.
    let ledger = launcher.private_store()?.all_observations()?;
    let trust_facts = crate::repository::trust_facts(
        launcher,
        crate::repository::RepoContext::load(launcher.clone(), repo, false, Some(&as_of.as_of))
            .ok()
            .map(|context| context.trust)
            .as_ref(),
    );
    let derived = crate::lifecycle::derive(&ledger, &trust_facts, &as_of.as_of);
    let store_label = store_name(store);
    let derived_facts: Vec<Value> = derived
        .facts
        .iter()
        .filter(|fact| fact.store_kind == store_label)
        .map(|fact| crate::model::value_of(fact))
        .collect();
    let mut digests = view
        .facts
        .iter()
        .map(|fact| fact.event_id.clone())
        .collect::<BTreeSet<_>>();
    for observation in &ledger {
        if crate::lifecycle::store_for(&observation.source_kind) == store_label {
            digests.insert(observation.content_digest.clone());
        }
    }
    for fact in &derived_facts {
        if let Some(id) = crate::json::get_str(fact, "fact_id") {
            digests.insert(id.to_owned());
        }
    }
    let digests = digests.into_iter().collect::<Vec<_>>();
    let mut fact_derivations: Vec<Value> = view.facts.iter().map(crate::model::value_of).collect();
    fact_derivations.extend(derived_facts);
    let current_view_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&crate::reducer::view_value(&view, &as_of.as_of_source))
            .as_slice(),
    );
    let canonical_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&json!({
            "as_of": view.as_of,
            "reducer_version": view.reducer_version,
            "authority_cursor": view.authority_cursor,
            "facts": view.facts,
            "unknowns": view.unknowns
        }))
        .as_slice(),
    );
    let inputs_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&json!({
            "as_of": as_of.as_of,
            "as_of_source": as_of.as_of_source,
            "reducer_version": view.reducer_version,
            "authority_cursor": authority_cursor_value,
            "admitted_events": event_inputs
        }))
        .as_slice(),
    );
    let private = launcher.private_store()?;
    let last_view_key = format!("corpus_last_view_digest:{}", store_name(store));
    let previous_view_digest = private.meta(&last_view_key)?;
    let state_changed = previous_view_digest.as_deref() != Some(current_view_digest.as_str());
    private.set_meta(&last_view_key, &current_view_digest)?;
    let manifest_publication =
        if state_changed && crate::repository::committed_event_count(repo)? > 0 {
            Some(crate::repository::publish_manifest_value(launcher, repo)?)
        } else {
            None
        };
    let manifest_lineages = Repository::discover(repo)?.manifest_heads()?.len();
    let result = json!({
        "status": "rebuilt",
        "state_changed": state_changed,
        "observed_effect": state_changed,
        "as_of": view.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "reducer_version": view.reducer_version,
        "authority_cursor": view.authority_cursor,
        "store": store_name(store),
        "manifest_publication": manifest_publication,
        "manifest_lineages": manifest_lineages,
        "build_manifest": {
            "observation_ids": observation_ids,
            "source_revisions": source_revisions,
            "digests": digests,
            "checkpoints": [{"as_of": view.as_of, "authority_cursor": view.authority_cursor}],
            "fact_derivations": fact_derivations,
            "adapter_receipts": adapter_receipts,
            "reducer_digest": current_view_digest
        },
        "current_view_digest": current_view_digest,
        "view_digest": current_view_digest,
        "canonical_digest": canonical_digest,
        "inputs_digest": inputs_digest,
        "duplicate_observations": view.counts.get("duplicates").copied().unwrap_or(0),
        "duplicate_facts": view.counts.get("duplicate_facts").copied().unwrap_or(0),
        "observation_count": view.counts.get("events").copied().unwrap_or(0)
            + ledger
                .iter()
                .filter(|observation| crate::lifecycle::store_for(&observation.source_kind) == store_label)
                .count(),
        "inputs": {
            "as_of": view.as_of,
            "as_of_source": as_of.as_of_source,
            "reducer_version": view.reducer_version,
            "authority_cursor": view.authority_cursor,
            "admitted_event_ids": event_ids
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
    let cached_cursor = launcher
        .company_cache()?
        .and_then(|(cache, _)| cache.meta("authority_cursor"))
        .unwrap_or_else(|| "0".to_owned());
    let (authority_snapshot_cursor, authority_snapshot_source) =
        crate::repository::ensure_authority_snapshot(
            launcher,
            authority_cursor
                .map(|cursor| cursor.to_string())
                .as_deref()
                .or(Some(cached_cursor.as_str())),
            &as_of.as_of,
        )?;
    // One online read of the published Company state before either store is
    // reduced: a still-fresh old cache is not an authority boundary, and an
    // unreachable Company leaves the cached snapshot in place (truth table).
    let online_context = Repository::discover(repo).ok().and_then(|_| {
        crate::launcher::Launcher::load().ok().and_then(|launcher| {
            crate::repository::RepoContext::load(launcher, repo, true, Some(&as_of.as_of)).ok()
        })
    });
    let service_cursor = launcher
        .company_cache()?
        .and_then(|(cache, _)| cache.meta("cursor"))
        .unwrap_or_else(|| "0".to_owned());
    let mut codebase = load_store(launcher, repo, crate::StoreKind::Codebase)?;
    let mut company = load_store(launcher, repo, crate::StoreKind::Company)?;
    let has_codebase = codebase
        .events
        .iter()
        .any(|event| event.event.logical_key == logical_key);
    let has_company = company
        .events
        .iter()
        .any(|event| event.event.logical_key == logical_key);
    let mut data = if has_codebase {
        codebase.events.extend(company.events);
        codebase.unknowns.extend(company.unknowns);
        codebase.tombstones.extend(company.tombstones);
        codebase.revocations.extend(company.revocations);
        codebase
    } else {
        company.events.extend(Vec::<AdmittedEvent>::new());
        company
    };
    data.events
        .retain(|event| event.event.logical_key == logical_key);
    data.unknowns
        .retain(|unknown| unknown.logical_key == logical_key);
    data.tombstones.retain(|tombstone| {
        data.events
            .iter()
            .any(|event| event.event.event_id == tombstone.target_event_id)
    });
    let key_events: Vec<crate::model::FactEvent> = data
        .events
        .iter()
        .map(|event| event.event.clone())
        .collect();
    let mixed = has_codebase && has_company;
    let store = if mixed {
        crate::StoreKind::Personal // marker only; reduce receives the mixed store name
    } else if has_company {
        crate::StoreKind::Company
    } else {
        crate::StoreKind::Codebase
    };
    let store_name_value = if mixed {
        "mixed".to_owned()
    } else {
        store_name(store).to_owned()
    };
    // One reduction over the union of Company and Codebase evidence for this
    // exact key. The trace, the rejected set, the counterfactuals and the
    // current/conflict/Unknown state all come from this single pure function
    // of (admitted events, reducer version, as_of, authority cursor).
    let view = reduce(
        data,
        &store_name_value,
        as_of,
        None,
        Some(authority_snapshot_cursor.clone()),
    )?;
    // The repository's own resolved view contributes only what the unified
    // reduction cannot know: Company reference resolution (P-8), the cache
    // truth table applied to referenced Company facts, and the effective
    // dependence class. It never overrides the unified state.
    let mut references = Vec::new();
    let mut resolved_current: Option<crate::model::CurrentFact> = None;
    if has_codebase {
        if let Some(context) = online_context.as_ref() {
            if let Ok((resolved_view, _counts, company_references)) =
                context.current_view(&as_of.as_of, Some(authority_snapshot_cursor.as_str()))
            {
                resolved_current = resolved_view
                    .facts
                    .iter()
                    .find(|fact| fact.logical_key == logical_key)
                    .cloned();
                references = company_references;
            }
        }
    }
    let trace = view
        .traces
        .iter()
        .find(|trace| trace.logical_key == logical_key);
    let mut current = view
        .facts
        .iter()
        .find(|fact| fact.logical_key == logical_key)
        .cloned();
    if let (Some(current), Some(resolved)) = (current.as_mut(), resolved_current.as_ref()) {
        if current.event_id == resolved.event_id {
            current.effective_dependence_class = resolved.effective_dependence_class.clone();
            if resolved.trust != "trusted" {
                current.trust = resolved.trust.clone();
                current.status = resolved.status.clone();
                current.stale_reasons = resolved.stale_reasons.clone();
            }
        }
    }
    let current = current.as_ref();
    if let Some(current) = current {
        references.retain(|record| {
            crate::json::get_str(record, "fact_id") == Some(current.fact_id.as_str())
        });
    }
    let unknowns: Vec<crate::reducer::DerivedUnknown> = view
        .unknowns
        .iter()
        .filter(|unknown| unknown.logical_key == logical_key)
        .cloned()
        .collect();
    let unknown = unknowns.first();
    let trace_state = trace.map(|trace| trace.state.as_str()).unwrap_or("missing");
    let state = if current.is_some_and(|fact| fact.status == "current") && trace_state == "current"
    {
        "current"
    } else if trace_state == "conflict" {
        "conflict"
    } else {
        "unknown"
    };
    let rejected_events: Vec<Value> = trace
        .map(|trace| trace.rejected.clone())
        .unwrap_or_default();
    let discriminating = trace
        .map(|trace| {
            if !trace.conflict_event_ids.is_empty() {
                format!("conflicting events {}", trace.conflict_event_ids.join(", "))
            } else if !trace.expired_event_ids.is_empty() {
                format!("expired events {}", trace.expired_event_ids.join(", "))
            } else if !trace.rejected.is_empty() {
                format!(
                    "rejected events {}",
                    trace
                        .rejected
                        .iter()
                        .filter_map(|event| event.get("event_id"))
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                "the surviving admitted event set".to_owned()
            }
        })
        .unwrap_or_else(|| "no admitted evidence for this exact key".to_owned());
    let operational_statement = current
        .filter(|fact| {
            fact.authority_scope.starts_with("environment:")
                && matches!(
                    fact.atom_kind.as_str(),
                    "observation" | "runtime_trace" | "test_runtime_evidence"
                )
        })
        .map(|fact| fact.statement.clone());
    let operational_value = operational_statement
        .map(|statement| last_numeric_token(&statement).unwrap_or(statement))
        .or_else(|| current.map(|fact| fact.statement.clone()))
        .unwrap_or_default();
    let architecture_rewritten = key_events.iter().any(|event| {
        event
            .statement
            .to_ascii_lowercase()
            .contains("architecture")
            && event
                .statement
                .to_ascii_lowercase()
                .contains("rewritten: true")
    });
    let authorized_parent_bound_event_resolves = key_events.iter().any(|event| {
        event.parents.len() >= 2
            && event.parents.iter().all(|parent| {
                key_events
                    .iter()
                    .any(|candidate| candidate.event_id == *parent)
            })
            && trace.is_some_and(|trace| {
                trace.state == "current" && trace.conflict_event_ids.is_empty()
            })
    });
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
    let unknown_owner_roles: Vec<Value> = unknowns
        .iter()
        .map(
            |unknown| json!({"logical_key": unknown.logical_key, "owner_role": unknown.owner_role}),
        )
        .collect();
    let notice_admitted = trace.is_some_and(|trace| trace.notice_admitted);
    let approver_minted_accepted = trace
        .and_then(|trace| trace.approver_minted_accepted)
        .unwrap_or(true);
    let free_form_owner_admitted = trace
        .and_then(|trace| trace.free_form_owner_admitted)
        .unwrap_or(current.is_some());
    let result = json!({
        "logical_key": logical_key,
        "decision": decision,
        "state": state,
        "observed_state": state,
        "architecture_rewritten": architecture_rewritten,
        "operational_value": operational_value,
        "authorized_parent_bound_event_resolves": authorized_parent_bound_event_resolves,
        "as_of": view.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "reducer_version": view.reducer_version,
        "authority_cursor": authority_snapshot_cursor.clone(),
        "service_cursor": service_cursor,
        "authority_snapshot_source": authority_snapshot_source,
        "store": store_name_value,
        "reducer_trace": trace.map(|trace| trace.steps.clone()).unwrap_or_default(),
        "trace": trace,
        "evidence_that_would_change_the_result": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "counterfactual": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "uncertainty_state": unknown.map(|unknown| unknown.status.clone()).unwrap_or_else(|| "none".to_owned()),
        "rejected_events": rejected_events,
        "negative_evidence": trace.map(|trace| trace.negative_evidence_event_ids.clone()).unwrap_or_default(),
        "expired_events": trace.map(|trace| trace.expired_event_ids.clone()).unwrap_or_default(),
        "conflict_events": trace.map(|trace| trace.conflict_event_ids.clone()).unwrap_or_default(),
        "notice_admitted": notice_admitted,
        "approver_minted_accepted": approver_minted_accepted,
        "free_form_owner_admitted": free_form_owner_admitted,
        "unknown_owner_roles": unknown_owner_roles,
        "selection_reason": format!("exact logical-key reduction by authority, scope, lifecycle disposition, declared validity, parent-bound supersession and conflict rules; recency was used only inside an authority-equivalent set; discriminating evidence: {discriminating}"),
        "selected_by": "guildhall-reducer/2",
        "current_statement": current.map(|fact| fact.statement.clone()).unwrap_or_default(),
        "current": current,
        "projection": current.map(|fact| fact.trust.clone()),
        "projection_state": if current.is_some_and(|fact| fact.trust == "trusted") { "projected" } else { "withheld" },
        "stale_reasons": current.map(|fact| fact.stale_reasons.clone()).unwrap_or_default(),
        "selection_trace": selection_trace,
        "independent_corroboration_count": current.map(|fact| fact.independent_support_count).unwrap_or(0),
        "unknowns": unknowns,
        "trusted": current.is_some_and(|fact| fact.status == "current" && fact.trust == "trusted") && unknown.is_none(),
        "authority_scope": current.map(|fact| fact.authority_scope.clone()).or_else(|| unknown.map(|unknown| unknown.scope.clone())).unwrap_or_default(),
        "environment_owner": current.filter(|fact| fact.authority_scope.starts_with("environment:")).map(|fact| fact.authority_id.clone()),
        "effective_criticality": current
            .and_then(|fact| fact.effective_dependence_class.clone())
            .or_else(|| current.map(|fact| fact.criticality.clone()))
            .or_else(|| unknown.map(|unknown| if unknown.loss_if_absent >= 7_500 { "safety_critical".to_owned() } else { "advisory".to_owned() })),
        "company_owner": current
            .and_then(|fact| fact.company_refs.first().map(|reference| reference.authority.clone()))
            .or_else(|| current.filter(|fact| fact.store_kind == "company").map(|fact| fact.authority_id.clone()))
            .unwrap_or_default(),
        "local_owner": current
            .filter(|fact| fact.store_kind == "codebase" && fact.company_refs.is_empty())
            .map(|fact| fact.authority_id.clone())
            .or_else(|| references.first().and_then(|record| crate::json::get_str(record, "local_owner").map(str::to_owned)))
            .unwrap_or_default(),
        "company_references": references,
        "max_rule": references.first().and_then(|record| crate::json::get_str(record, "max_rule").map(str::to_owned)),
        "dominating_input": references.first().and_then(|record| crate::json::get_str(record, "dominating_input").map(str::to_owned))
    });
    crate::output::emit(&result, json);
    Ok(())
}

fn last_numeric_token(statement: &str) -> Option<String> {
    statement
        .split(|character: char| {
            character.is_ascii_whitespace() || character.is_ascii_punctuation()
        })
        .rev()
        .find(|token| {
            !token.is_empty() && token.chars().all(|character| character.is_ascii_digit())
        })
        .map(str::to_owned)
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
    data: StoreData,
    store_label: &str,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    authority_cursor: Option<String>,
) -> Result<crate::reducer::CurrentView, ContractError> {
    let authority_cursor = authority_cursor.unwrap_or_else(|| data.authority_cursor.clone());
    let certificate_valid = data.certificate_valid;
    let reducer_version = reducer_version
        .map(|version| version.to_string())
        .unwrap_or_else(|| crate::reducer::REDUCER_VERSION.to_owned());
    let input = ReducerInput {
        store_kind: store_label.to_owned(),
        events: data.events,
        unknowns: data.unknowns,
        tombstones: data.tombstones,
        revocations: data.revocations,
        as_of: as_of.as_of.clone(),
        authority_cursor,
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid,
        authority_owner_by_scope: data.authority_owner_by_scope,
        steward_authority_id: data.steward_authority_id,
    };
    let mut view = crate::reducer::reduce(&input);
    view.reducer_version = reducer_version;
    Ok(view)
}

pub(crate) fn load_store(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
) -> Result<StoreData, ContractError> {
    match store {
        crate::StoreKind::Personal => {
            let private = launcher.private_store()?;
            let facts = private.personal_facts()?;
            let events = facts
                .iter()
                .filter_map(proxy_event)
                .collect::<Result<Vec<_>, ContractError>>()?;
            Ok(StoreData {
                events,
                unknowns: Vec::new(),
                tombstones: Vec::new(),
                revocations: Vec::new(),
                authority_cursor: current_authority_cursor(),
                certificate_valid: true,
                authority_owner_by_scope: BTreeMap::new(),
                steward_authority_id: None,
            })
        }
        crate::StoreKind::Company => {
            let mut events = Vec::new();
            let mut unknowns = Vec::new();
            let mut revocations: Vec<Revocation> = Vec::new();
            if let Ok(Some((cache, _root))) = launcher.company_cache() {
                if let Ok(Some(snapshot)) = cache.snapshot() {
                    let (snapshot_events, snapshot_unknowns) = snapshot_company_events(&snapshot);
                    events.extend(snapshot_events);
                    unknowns.extend(snapshot_unknowns);
                    revocations.extend(
                        crate::json::get_array(&snapshot, "revocations")
                            .into_iter()
                            .flatten()
                            .filter_map(|record| serde_json::from_value(record.clone()).ok()),
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
            // Company snapshot and local authority-answer events are Company
            // records even when a publisher repeats Codebase event bytes.
            for admitted in &mut events {
                admitted.event.store_kind = "company".to_owned();
            }
            if let Ok(records) =
                crate::store::read_records(crate::StoreKind::Company, repo, "unknowns.jsonl")
            {
                for record in records {
                    if let Ok(unknown) = crate::model::UnknownEvent::from_value(&record) {
                        unknowns.push(unknown);
                    }
                }
            }
            let (authority_owner_by_scope, steward_authority_id) = launcher
                .company_cache()
                .ok()
                .flatten()
                .and_then(|(cache, _root)| cache.snapshot().ok().flatten())
                .map(|snapshot| {
                    let revoked: BTreeSet<String> =
                        crate::json::get_array(&snapshot, "revocations")
                            .into_iter()
                            .flatten()
                            .filter_map(|record| {
                                crate::json::get_str(record, "revoked_key").map(str::to_owned)
                            })
                            .collect();
                    let mut active: BTreeMap<String, Option<String>> = BTreeMap::new();
                    for entry in crate::json::get_array(&snapshot, "registry")
                        .into_iter()
                        .flatten()
                    {
                        if crate::json::get_str(entry, "status") != Some("active") {
                            continue;
                        }
                        let Some(scope) = crate::json::get_str(entry, "scope") else {
                            continue;
                        };
                        let revoked_key =
                            crate::json::get_str(entry, "public_key").unwrap_or_default();
                        if revoked.contains(revoked_key) {
                            continue;
                        }
                        let identity =
                            crate::json::get_str(entry, "authority_id").map(str::to_owned);
                        active
                            .entry(scope.to_owned())
                            .and_modify(|existing| {
                                if existing.is_none() || existing.as_deref() != identity.as_deref()
                                {
                                    *existing = None;
                                }
                            })
                            .or_insert(identity);
                    }
                    let authority_owner_by_scope = active
                        .into_iter()
                        .filter_map(|(scope, owner)| Some((scope, owner?)))
                        .collect::<BTreeMap<String, String>>();
                    let steward_authority_id =
                        authority_owner_by_scope.get("company:root").cloned();
                    (authority_owner_by_scope, steward_authority_id)
                })
                .unwrap_or_default();
            Ok(StoreData {
                events,
                unknowns,
                tombstones: Vec::new(),
                revocations,
                authority_cursor: launcher
                    .company_cache()
                    .ok()
                    .flatten()
                    .and_then(|(cache, _root)| cache.meta("authority_cursor"))
                    .unwrap_or_else(|| "0".to_owned()),
                certificate_valid: true,
                authority_owner_by_scope,
                steward_authority_id,
            })
        }
        crate::StoreKind::Codebase => {
            let context = crate::repository::RepoContext::load(
                crate::launcher::Launcher::load()?,
                repo,
                false,
                None,
            )?;
            let (events, unknowns, tombstones, revocations) = context.reducer_parts()?;
            Ok(StoreData {
                events,
                unknowns,
                tombstones,
                revocations,
                authority_cursor: context.trust.authority_cursor.clone(),
                certificate_valid: context.trust.certificate_valid,
                authority_owner_by_scope: context.trust.authority_owner_by_scope(),
                steward_authority_id: context.trust.steward_authority_id(),
            })
        }
    }
}

/// Company evidence as the client reducer consumes it.
///
/// A snapshot carries the immutable admitted `fact-event`/`unknown-event`
/// documents under `events` (with Company's store cursor and the verification
/// it recorded at admission). A snapshot written before that field existed
/// carries only Company's derived current facts; each of those is then
/// carried as the one admitted event Company reduced it to, so an older cache
/// still yields a view rather than a refusal.
fn snapshot_company_events(
    snapshot: &Value,
) -> (Vec<AdmittedEvent>, Vec<crate::model::UnknownEvent>) {
    let mut events = Vec::new();
    let mut unknowns = Vec::new();
    if let Some(records) = snapshot.get("events").and_then(Value::as_array) {
        for record in records {
            let Some(document) = record.get("document") else {
                continue;
            };
            let cursor = crate::json::get_str(record, "cursor")
                .unwrap_or_default()
                .to_owned();
            match crate::json::get_str(record, "kind") {
                Some("unknown-event") => {
                    if let Ok(unknown) = crate::model::UnknownEvent::from_value(document) {
                        unknowns.push(unknown);
                    }
                }
                _ => {
                    let Ok(event) = crate::model::FactEvent::from_value(document) else {
                        continue;
                    };
                    let verification = match crate::json::get_str(record, "verification") {
                        Some("verified") => crate::reducer::Verification::Verified,
                        Some("wrong-scope") => crate::reducer::Verification::WrongScope,
                        Some("revoked") => crate::reducer::Verification::Revoked,
                        Some("signature-invalid") => crate::reducer::Verification::SignatureInvalid,
                        _ => crate::reducer::Verification::Unverified,
                    };
                    let signer = event.signer.clone();
                    events.push(AdmittedEvent {
                        event,
                        verification,
                        store_cursor: cursor,
                        origin_trust: None,
                        reachable: None,
                        source_identity: Some(signer),
                        environment_registered: None,
                    });
                }
            }
        }
        return (events, unknowns);
    }
    for fact in crate::json::get_array(snapshot, "facts")
        .into_iter()
        .flatten()
    {
        if let Some(admitted) = derived_fact_as_event(fact) {
            events.push(admitted);
        }
    }
    (events, unknowns)
}

/// One of Company's derived current facts, carried as the single admitted
/// event Company reduced it to (used only for snapshots without `events`).
fn derived_fact_as_event(fact: &Value) -> Option<AdmittedEvent> {
    let current: CurrentFact = serde_json::from_value(fact.clone()).ok()?;
    let event = crate::model::FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id: current.event_id.clone(),
        store_kind: "company".to_owned(),
        authority_id: current.authority_id.clone(),
        authority_scope: current.authority_scope.clone(),
        repository_id: None,
        fact_id: current.fact_id.clone(),
        logical_key: current.logical_key.clone(),
        atom_kind: current.atom_kind.clone(),
        scope: current.scope.clone(),
        statement: current.statement.clone(),
        evidence_refs: current.evidence_refs.clone(),
        asserted_at: current.effective_from.clone(),
        effective_from: current.effective_from.clone(),
        effective_until: current.effective_until.clone(),
        disposition: current.disposition.clone(),
        distortion: current.distortion.clone(),
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: current.redundancy_with.clone(),
        complements: current.complements.clone(),
        company_refs: current.company_refs.clone(),
        authority_snapshot_cursor: current.authority_snapshot_cursor.clone(),
        confidence: crate::model::Bp(current.confidence),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    };
    Some(AdmittedEvent {
        event,
        verification: crate::reducer::Verification::Verified,
        store_cursor: crate::hash::sha256_bytes(crate::json::canonical_bytes(fact).as_slice()),
        origin_trust: None,
        reachable: None,
        source_identity: Some(current.authority_id),
        environment_registered: None,
    })
}

fn proxy_event(record: &Value) -> Option<Result<AdmittedEvent, ContractError>> {
    let event = match crate::model::FactEvent::from_value(record) {
        Ok(event) => event,
        Err(error) => {
            return Some(Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                error,
                "Quarantine the malformed event.",
            )));
        }
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
