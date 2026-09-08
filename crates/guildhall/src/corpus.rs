use crate::error::{ContractError, ExitCode};
use crate::model::{Distortion, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn rebuild(
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
    json: bool,
) -> Result<(), ContractError> {
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    let as_of_source = as_of.as_of_source.clone();
    let as_of = as_of.as_of.clone();
    let facts = if store == crate::StoreKind::Personal {
        personal_facts(repo)
    } else {
        let events = crate::store::read_events(&root).map_err(io_error)?;
        let public_key = root.join("local").join("keys").join("ed25519.pub");
        for event in &events {
            if !public_key.exists()
                || !crate::store::verify_event_signature(event, &public_key).map_err(|error| {
                    ContractError::new(
                        "SIGNATURE_INVALID",
                        error,
                        "Quarantine the event and rerun full fsck.",
                        false,
                        ExitCode::IntegrityFailure,
                    )
                })?
            {
                return Err(ContractError::new(
                    "SIGNATURE_INVALID",
                    format!("event {} failed signature verification", event.event_id),
                    "Quarantine the event and repair its named owner key.",
                    false,
                    ExitCode::IntegrityFailure,
                ));
            }
        }
        crate::reducer::reduce_with_trace(&events, &as_of).facts
    };
    let unknowns = if store == crate::StoreKind::Personal {
        Vec::new()
    } else {
        let events = crate::store::read_events(&root).map_err(io_error)?;
        let trace = crate::reducer::reduce_with_trace(&events, &as_of);
        create_reducer_unknowns(store, repo, &trace.conflict_keys, &trace.expired_keys)?
    };
    let view = json!({
        "schema": "guildhall-current-view/1",
        "store": store_name(store),
        "as_of": as_of,
        "as_of_source": as_of_source,
        "reducer_version": crate::reducer::REDUCER_VERSION,
        "facts": facts,
        "unknown_ids": unknowns
    });
    std::fs::write(
        root.join("local").join("current.json"),
        crate::json::canonical_text(&view),
    )
    .map_err(io_error)?;
    let result = json!({
        "status": "rebuilt",
        "store": store_name(store),
        "fact_count": facts.len(),
        "unknown_count": unknowns.len(),
        "as_of": as_of,
        "as_of_source": as_of_source
    });
    print_value(&result, json);
    Ok(())
}

fn personal_facts(repo: &Path) -> Vec<crate::model::CurrentFact> {
    let atoms = crate::store::read_records(crate::StoreKind::Personal, repo, "atoms.jsonl")
        .unwrap_or_default();
    atoms
        .iter()
        .filter_map(|atom| {
            let statement = atom.get("statement").and_then(Value::as_str)?;
            let scope = atom.get("scope").and_then(Value::as_str)?;
            Some(crate::model::CurrentFact {
                fact_id: format!(
                    "fact_{:x}",
                    Sha256::digest(format!("{scope}\0{statement}").as_bytes())
                ),
                logical_key: format!("logical_{:x}", Sha256::digest(scope.as_bytes())),
                atom_kind: atom.get("atom_kind").and_then(Value::as_str)?.to_owned(),
                scope: scope.to_owned(),
                statement: statement.to_owned(),
                status: "current".to_owned(),
                disposition: "personal".to_owned(),
                authority_id: "personal-owner".to_owned(),
                authority_scope: scope.to_owned(),
                effective_from: now_rfc3339_millis(),
                effective_until: None,
                loss_if_absent: 1_000,
                company_refs: Vec::new(),
                evidence_refs: Vec::new(),
            })
        })
        .collect()
}

fn create_reducer_unknowns(
    store: crate::StoreKind,
    repo: &Path,
    conflict_keys: &[String],
    expired_keys: &[String],
) -> Result<Vec<String>, ContractError> {
    let mut ids = Vec::new();
    for logical_key in conflict_keys.iter().chain(expired_keys) {
        let owner_role = if store == crate::StoreKind::Company {
            "company-steward"
        } else {
            "repository-maintainer"
        };
        let unknown_id = format!(
            "unknown_{:x}",
            Sha256::digest(format!("{}\0{}", store_name(store), logical_key).as_bytes())
        );
        ids.push(unknown_id.clone());
        let mut unknown = UnknownEvent {
            schema: crate::model::UNKNOWN_SCHEMA.to_owned(),
            unknown_id,
            store_kind: store_name(store).to_owned(),
            scope: logical_key.clone(),
            decision_blocked: "current-view-reduction".to_owned(),
            owner_role: owner_role.to_owned(),
            owner_identity: owner_role.to_owned(),
            question: format!("Resolve the conflicting or expired evidence for {logical_key}."),
            closure_evidence: Vec::new(),
            status: "open".to_owned(),
            response_due_at: format_rfc3339_millis(Utc::now() + Duration::hours(24)),
            expiry_policy: "block-dependent-decision".to_owned(),
            distortion: Distortion {
                trigger: "current-view reduction".to_owned(),
                loss_if_absent: 9_000,
                rationale: "a stale or disputed fact is worse than a missing fact".to_owned(),
            },
            created_at: now_rfc3339_millis(),
            signer: owner_role.to_owned(),
            signature: String::new(),
        };
        let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
        let mut value = serde_json::to_value(&unknown)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        if let Value::Object(map) = &mut value {
            map.remove("signature");
        }
        let unsigned = crate::json::canonical_text(&value);
        unknown.signature =
            crate::crypto::sign_message("unknown-event", unsigned.as_bytes(), &private_key)?;
        let record = serde_json::to_value(&unknown)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        crate::store::append_record(store, repo, "unknowns.jsonl", &record).map_err(io_error)?;
    }
    Ok(ids)
}

pub fn explain(
    repo: &Path,
    logical_key: &str,
    decision: &str,
    as_of: &crate::time::AsOf,
    json: bool,
) -> Result<(), ContractError> {
    let mut events = Vec::new();
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        let root = crate::store::store_root(store, repo);
        events.extend(crate::store::read_events(&root).unwrap_or_default());
    }
    let matching: Vec<_> = events
        .iter()
        .filter(|event| event.logical_key == logical_key)
        .cloned()
        .collect();
    let trace = crate::reducer::reduce_with_trace(&matching, &as_of.as_of);
    let current = trace.facts.first();
    let result = json!({
        "logical_key": logical_key,
        "decision": decision,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "status": current.map(|fact| fact.status.as_str()).unwrap_or(if matching.is_empty() { "missing" } else { "withdrawn" }),
        "reducer_version": crate::reducer::REDUCER_VERSION,
        "events": matching.iter().map(|event| json!({
            "event_id": event.event_id,
            "fact_id": event.fact_id,
            "store_kind": event.store_kind,
            "disposition": event.disposition,
            "effective_from": event.effective_from,
            "effective_until": event.effective_until,
            "authority_id": event.authority_id,
            "supersedes": event.supersedes
        })).collect::<Vec<_>>(),
        "current": current,
        "conflict": trace.conflict_keys.contains(&logical_key.to_owned()),
        "steps": [
            {"step": "authority-and-scope"},
            {"step": "retraction-and-supersession"},
            {"step": "disposition-and-validity"},
            {"step": "semantic-deduplication"},
            {"step": "conflict-or-current"}
        ]
    });
    print_value(&result, json);
    Ok(())
}

fn store_name(store: crate::StoreKind) -> &'static str {
    crate::ingest::store_name(store)
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string(value).unwrap_or_default());
    } else {
        println!(
            "status: {}",
            value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("rebuilt")
        );
        if let Some(count) = value.get("fact_count").and_then(Value::as_u64) {
            println!("fact_count: {count}");
        }
    }
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        ExitCode::InternalFailure,
    )
}
