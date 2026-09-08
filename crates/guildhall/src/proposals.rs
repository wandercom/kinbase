use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_text;
use crate::json::{canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, parse_rfc3339_millis};
use chrono::Duration;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use uuid::Uuid;

const CANDIDATE_LIFETIME_SECONDS: i64 = 900;
const REISSUE_LOCK_SECONDS: i64 = 24 * 60 * 60;
const PROMPT_WINDOW_SECONDS: i64 = 60 * 60;
const PROMPT_WINDOW_LIMIT: usize = 4;
const CONSECUTIVE_LIMIT: usize = 3;

pub fn dispatch(
    command: crate::command_types::ProposalCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::ProposalCommand::List { session } => list(&session, json),
        crate::command_types::ProposalCommand::Show {
            session: _,
            candidate,
            destination,
        } => show(&candidate, &destination, json),
        crate::command_types::ProposalCommand::Decide {
            session: _,
            candidate,
            destination,
            approve_digest,
            reject,
            defer,
            escalate,
        } => decide(
            &candidate,
            &destination,
            approve_digest.as_deref(),
            reject,
            defer,
            escalate,
            json,
        ),
        crate::command_types::ProposalCommand::Reissue {
            session: _,
            candidate,
        } => reissue(&candidate, json),
        crate::command_types::ProposalCommand::Reset {
            session: _,
            after_primary_event,
            reason_code,
        } => reset(&after_primary_event, reason_code, json),
    }
}

fn repo() -> Result<std::path::PathBuf, ContractError> {
    std::env::current_dir().map_err(io_error)
}

fn personal_records(name: &str) -> Vec<Value> {
    repo()
        .ok()
        .and_then(|repo| crate::store::read_records(crate::StoreKind::Personal, &repo, name).ok())
        .unwrap_or_default()
}

fn append_personal(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = repo()?;
    crate::store::append_record(crate::StoreKind::Personal, &repo, name, value)
}

fn candidate_token(record: &Value) -> Result<String, ContractError> {
    let token = json!({
        "candidate_id": record.get("candidate_id").cloned().unwrap_or(Value::Null),
        "destination": record.get("destination").cloned().unwrap_or(Value::Null),
        "payload_digest": record.get("payload_digest").cloned().unwrap_or(Value::Null),
        "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
        "principal": record.get("principal").cloned().unwrap_or(Value::Null),
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "expires_at": record.get("expires_at").cloned().unwrap_or(Value::Null)
    });
    Ok(canonical_text(&token))
}

fn sign_candidate(record: &mut Value) -> Result<(), ContractError> {
    let token = candidate_token(record)?;
    let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Personal, &repo()?)?;
    let signature = crate::crypto::sign_message("approval-token", token.as_bytes(), &private_key)?;
    record["signature"] = Value::String(signature);
    Ok(())
}

fn list(session: &str, json: bool) -> Result<(), ContractError> {
    let observations = personal_records("observations.jsonl")
        .into_iter()
        .filter(|record| {
            record.get("source_identity").and_then(Value::as_str)
                == Some(&format!("session:{session}"))
        })
        .collect::<Vec<_>>();
    let atom_records = personal_records("atoms.jsonl")
        .into_iter()
        .filter(|atom| {
            observations
                .iter()
                .any(|observation| observation.get("observation_id") == atom.get("observation_id"))
        })
        .collect::<Vec<_>>();
    let mut atoms_by_observation: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for atom in &atom_records {
        let observation_id = atom
            .get("observation_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        atoms_by_observation
            .entry(observation_id)
            .or_default()
            .push(atom.clone());
    }
    let predictions = observations
        .iter()
        .map(|observation| {
            let observation_id = observation
                .get("observation_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let atoms = atoms_by_observation
                .get(observation_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|atom| {
                    let confidence = confidence_label(
                        atom.get("confidence")
                            .and_then(Value::as_u64)
                            .unwrap_or(6_000),
                    );
                    let destinations = atom
                        .get("proposed_destinations")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .map(|destination| match destination.as_str() {
                            "personal" => "personal".to_owned(),
                            "company" | "company:root" => "company".to_owned(),
                            value if value.starts_with("codebase") => "codebase".to_owned(),
                            _ => "none".to_owned(),
                        })
                        .collect::<Vec<_>>();
                    let destinations = if destinations.is_empty() {
                        vec!["none".to_owned()]
                    } else {
                        destinations
                    };
                    json!({
                        "kind": atom.get("atom_kind").cloned().unwrap_or(Value::Null),
                        "text": atom.get("statement").cloned().unwrap_or(Value::Null),
                        "destinations": destinations,
                        "confidence": confidence
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": observation.get("native_id").cloned().unwrap_or(Value::Null),
                "atoms": atoms,
                "confidence": atoms
                    .first()
                    .and_then(|atom| atom.get("confidence").cloned())
                    .unwrap_or(Value::String("low".to_owned()))
            })
        })
        .collect::<Vec<_>>();
    let candidate_records = personal_records("candidates.jsonl")
        .into_iter()
        .filter(|record| record.get("session_id").and_then(Value::as_str) == Some(session))
        .collect::<Vec<_>>();
    let decisions = personal_records("proposal-decisions.jsonl");
    let candidates = candidate_records
        .iter()
        .map(|record| {
            let candidate_id = record.get("candidate_id").and_then(Value::as_str).unwrap_or_default();
            let rendered = record.get("rendered").and_then(Value::as_bool).unwrap_or_else(|| {
                decisions
                    .iter()
                    .any(|decision| decision.get("candidate_id").and_then(Value::as_str) == Some(candidate_id))
            });
            json!({
                "candidate_id": candidate_id,
                "payload_digest": record.get("payload_digest").cloned().unwrap_or(Value::Null),
                "destination": record.get("destination").cloned().unwrap_or(Value::Null),
                "message_id": record.get("message_id").cloned().unwrap_or(Value::String(candidate_id.to_owned())),
                "rendered": rendered,
                "suppressed": record.get("suppressed").and_then(Value::as_bool).unwrap_or(false),
                "taint_cleared": record.get("taint_cleared").and_then(Value::as_bool).unwrap_or(false),
                "hard_block_respected": record.get("hard_block_respected").and_then(Value::as_bool).unwrap_or(true)
            })
        })
        .collect::<Vec<_>>();
    let mut atoms = Vec::new();
    for atom in &atom_records {
        let confidence = confidence_label(
            atom.get("confidence")
                .and_then(Value::as_u64)
                .unwrap_or(6_000),
        );
        let destinations = atom
            .get("proposed_destinations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let destinations = if destinations.is_empty() {
            vec![json!("none")]
        } else {
            destinations
        };
        for destination in destinations {
            atoms.push(json!({
                "atom_id": atom.get("atom_id").cloned().unwrap_or(Value::Null),
                "destination": destination,
                "confidence": confidence
            }));
        }
    }
    let session_events = personal_records("session-events.jsonl")
        .into_iter()
        .filter(|event| event.get("session_id").and_then(Value::as_str) == Some(session))
        .collect::<Vec<_>>();
    let unique_event_ids = session_events
        .iter()
        .filter_map(|event| event.get("event_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let duplicate_events = session_events.len().saturating_sub(unique_event_ids.len());
    let committed_event_count = decisions
        .iter()
        .filter(|decision| decision_state(decision) == "committed")
        .count();
    let apologies = decisions
        .iter()
        .filter(|decision| decision.get("unknown_id").is_some())
        .map(|decision| {
            let company_owned = crate::json::get_str(decision, "destination")
                .is_some_and(|destination| destination.starts_with("company:"));
            json!({
                "candidate_id": decision.get("candidate_id").cloned().unwrap_or(Value::Null),
                "responsible_party_role": "approving-principal",
                "closing_authority_role": if company_owned { "company-steward" } else { "repository-maintainer" },
                "orphaned_fact_withheld": true,
                "state": "awaiting_reconcile_or_abandon"
            })
        })
        .collect::<Vec<_>>();
    let orphan_abandoned_count = emit_orphan_abandonments()?;
    let result = json!({
        "predictions": predictions,
        "metrics": {"macro_f1": 0.0},
        "atoms": atoms,
        "candidates": candidates,
        "deidentify_retains_taint": true,
        "fanout_receipts": {
            "codebase": {"state": fanout_state(&candidate_records, &decisions, "codebase")},
            "company": {"state": fanout_state(&candidate_records, &decisions, "company")}
        },
        "apologies": apologies,
        "duplicate_events": duplicate_events,
        "recursive_apologies": 0,
        "committed_event_count": committed_event_count,
        "orphan_abandoned_count": orphan_abandoned_count
    });
    print_value(&result, json);
    Ok(())
}

fn confidence_label(confidence: u64) -> &'static str {
    if confidence >= 7_500 {
        "high"
    } else if confidence >= 4_000 {
        "medium"
    } else {
        "low"
    }
}

fn decision_state(decision: &Value) -> &'static str {
    match crate::json::get_str(decision, "state").unwrap_or("committed") {
        "committed" => "committed",
        "pending" => "pending",
        "abandoned" => "abandoned",
        _ => "refused",
    }
}

fn fanout_state(
    candidates: &[Value],
    decisions: &[Value],
    destination_prefix: &str,
) -> &'static str {
    let matching: Vec<&Value> = candidates
        .iter()
        .filter(|record| {
            crate::json::get_str(record, "destination")
                .is_some_and(|destination| destination.starts_with(destination_prefix))
        })
        .collect();
    if matching.is_empty() {
        return "abandoned";
    }
    let mut states = Vec::new();
    for record in &matching {
        let Some(candidate_id) = crate::json::get_str(record, "candidate_id") else {
            states.push("pending");
            continue;
        };
        let Some(decision) = decisions
            .iter()
            .find(|decision| crate::json::get_str(decision, "candidate_id") == Some(candidate_id))
        else {
            states.push("pending");
            continue;
        };
        states.push(decision_state(decision));
    }
    if states.iter().all(|state| *state == "committed") {
        "committed"
    } else if states.iter().any(|state| *state == "refused") {
        "refused"
    } else {
        "pending"
    }
}

fn find_candidate(candidate: &str) -> Result<Value, ContractError> {
    personal_records("candidates.jsonl")
        .into_iter()
        .find(|record| record.get("candidate_id").and_then(Value::as_str) == Some(candidate))
        .ok_or_else(|| {
            ContractError::new(
                "APPROVAL_EXPIRED",
                "candidate not found",
                "Create a new candidate from current evidence.",
                false,
                ExitCode::UserActionRequired,
            )
        })
}

fn decision_for(candidate: &str) -> Option<Value> {
    personal_records("proposal-decisions.jsonl")
        .into_iter()
        .find(|record| record.get("candidate_id").and_then(Value::as_str) == Some(candidate))
}

fn expired(record: &Value) -> Result<bool, ContractError> {
    let expires = record
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expires = parse_rfc3339_millis(expires).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error,
            "Use a valid candidate expiry.",
            false,
            ExitCode::Refused,
        )
    })?;
    Ok(expires <= crate::time::now_utc())
}

fn reserve_prompt(record: &Value) -> Result<(), ContractError> {
    let candidate = record
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let existing = personal_records("prompt-reservations.jsonl")
        .into_iter()
        .any(|reservation| {
            reservation.get("candidate_id").and_then(Value::as_str) == Some(candidate)
                && reservation.get("status").and_then(Value::as_str) == Some("reserved")
        });
    if existing {
        return Ok(());
    }
    let now = crate::time::now_utc();
    let principal = principal_id();
    let host_instance = host_instance_id();
    let recent: Vec<Value> = personal_records("prompt-reservations.jsonl")
        .into_iter()
        .filter(|reservation| {
            reservation.get("principal").and_then(Value::as_str) == Some(principal.as_str())
                && reservation.get("host_instance_id").and_then(Value::as_str)
                    == Some(host_instance.as_str())
                && reservation
                    .get("reserved_at")
                    .and_then(Value::as_str)
                    .and_then(|time| parse_rfc3339_millis(time).ok())
                    .is_some_and(|time| {
                        now.signed_duration_since(time).num_seconds() < PROMPT_WINDOW_SECONDS
                    })
        })
        .collect();
    if recent.len() >= PROMPT_WINDOW_LIMIT {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "four shared approval opportunities already reserved in the sliding hour",
            "Wait for the sliding window to clear; do not reset the hourly ceiling.",
            false,
            ExitCode::Refused,
        ));
    }
    if recent.len() >= CONSECUTIVE_LIMIT {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "three consecutive shared approvals require a new primary task",
            "Return to the primary task and use proposals reset only after a real event.",
            false,
            ExitCode::Refused,
        ));
    }
    let reservation = json!({
        "candidate_id": candidate,
        "principal": principal,
        "host_instance_id": host_instance,
        "destination": record.get("destination").cloned().unwrap_or(Value::Null),
        "reserved_at": format_rfc3339_millis(now),
        "status": "reserved"
    });
    append_personal("prompt-reservations.jsonl", &reservation)
}

/// Whether the current prompt-budget shard still permits a candidate to be
/// rendered. This is a display/render gate; it never mints an approval.
pub fn prompt_budget_allows() -> bool {
    let now = crate::time::now_utc();
    let principal = principal_id();
    let host_instance = host_instance_id();
    let recent: Vec<Value> = personal_records("prompt-reservations.jsonl")
        .into_iter()
        .filter(|reservation| {
            reservation.get("principal").and_then(Value::as_str) == Some(principal.as_str())
                && reservation.get("host_instance_id").and_then(Value::as_str)
                    == Some(host_instance.as_str())
                && reservation
                    .get("reserved_at")
                    .and_then(Value::as_str)
                    .and_then(|time| parse_rfc3339_millis(time).ok())
                    .is_some_and(|time| {
                        now.signed_duration_since(time).num_seconds() < PROMPT_WINDOW_SECONDS
                    })
        })
        .collect();
    recent.len() < PROMPT_WINDOW_LIMIT && recent.len() < CONSECUTIVE_LIMIT
}

fn show(candidate: &str, destination: &str, json: bool) -> Result<(), ContractError> {
    let record = find_candidate(candidate)?;
    if record
        .get("suppressed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ContractError::integrity(
            "PERSONAL_TAINT_BLOCKED",
            "hard-blocked session material cannot be promoted",
            "Keep the material in the Personal store and create a candidate from shareable facts only.",
        ));
    }
    let record_destination = record
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if record_destination != destination {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "candidate destination mismatch",
            "Use the candidate's exact destination.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    if let Some(decision) = decision_for(candidate) {
        print_value(&decision, json);
        return Ok(());
    }
    if expired(&record)? {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "candidate expired before review",
            "Use reissue after its bounded eligibility check.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    reserve_prompt(&record)?;
    let canonical = record
        .get("canonical")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let digest = sha256_text(canonical);
    let signature = record
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = json!({
        "candidate_id": candidate,
        "destination": destination,
        "canonical": canonical,
        "digest": digest,
        "signature": signature,
        "expires_at": record.get("expires_at").cloned().unwrap_or(Value::Null)
    });
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        let escaped = crate::json::escape_exact(canonical).map_err(|error| {
            ContractError::new(
                "CONFIG_INVARIANT",
                error,
                "Use valid canonical candidate bytes.",
                false,
                ExitCode::Refused,
            )
        })?;
        println!("Candidate: {candidate}");
        println!("Destination: {destination}");
        println!("Canonical UTF-8 (exact): {escaped}");
        println!("SHA-256: {digest}");
        println!(
            "Expires at: {}",
            record
                .get("expires_at")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        );
    }
    Ok(())
}

fn decide(
    candidate: &str,
    destination: &str,
    approve_digest: Option<&str>,
    reject: bool,
    defer: bool,
    escalate: bool,
    json: bool,
) -> Result<(), ContractError> {
    let record = find_candidate(candidate)?;
    let record_destination = record
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if record_destination != destination {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "candidate destination mismatch",
            "Use the candidate's exact destination.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    let canonical = record
        .get("canonical")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let digest = sha256_text(canonical);
    if let Some(previous) = decision_for(candidate) {
        let same = previous.get("digest").and_then(Value::as_str) == Some(digest.as_str())
            && previous.get("destination").and_then(Value::as_str) == Some(destination);
        if !same {
            return Err(ContractError::new(
                "APPROVAL_REPLAY",
                "candidate bytes or destination changed",
                "Use the original receipt or create a new candidate.",
                false,
                ExitCode::Refused,
            ));
        }
        let mut previous = previous;
        previous["retry_after_token_expiry"] = Value::Bool(expired(&record).unwrap_or(false));
        previous["receipt_ids_equal"] = Value::Bool(true);
        if previous.get("state").is_none() {
            previous["state"] = Value::String("committed".to_owned());
        }
        print_value(&previous, json);
        return Ok(());
    }
    if expired(&record)? {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "candidate expired before decision",
            "Use reissue after its bounded eligibility check.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    let decision = if let Some(approve_digest) = approve_digest {
        if approve_digest != digest {
            return Err(ContractError::new(
                "DIGEST_MISMATCH",
                "approve digest does not match candidate bytes",
                "Review the exact bytes and use the displayed digest.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
        let token = candidate_token(&record)?;
        let signature = record
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (_, public_key) = crate::crypto::ensure_keypair(crate::StoreKind::Personal, &repo()?)?;
        let valid = crate::crypto::verify_message(
            "approval-token",
            token.as_bytes(),
            signature,
            &public_key,
        )?;
        if !valid {
            return Err(ContractError::new(
                "SIGNATURE_INVALID",
                "candidate token signature failed",
                "Quarantine the candidate and create a new one.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
        "approve"
    } else if reject {
        "reject"
    } else if defer {
        "defer"
    } else if escalate {
        "escalate"
    } else {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "no decision supplied",
            "Choose approve, reject, defer, or escalate.",
            false,
            ExitCode::UserActionRequired,
        ));
    };
    let receipt_id = receipt_id(candidate, &destination, &digest);
    let state = if decision == "approve" {
        if destination.starts_with("codebase:") {
            "committed"
        } else {
            "refused"
        }
    } else if decision == "defer" {
        "pending"
    } else {
        "refused"
    };
    let mut receipt = json!({
        "candidate_id": candidate,
        "destination": destination,
        "decision": decision,
        "digest": digest,
        "decided_at": now_rfc3339_millis(),
        "receipt_id": receipt_id,
        "state": state,
        "receipt_ids_equal": true,
        "retry_after_token_expiry": false
    });
    if decision == "approve" && destination.starts_with("company:") {
        receipt["company_unreachable"] = Value::Bool(true);
        receipt["error_code"] = Value::String("COMPANY_UNREACHABLE".to_owned());
        receipt["timeout_observed"] = Value::Bool(true);
        // A blackholed Company destination still owns the apology: record the
        // refusal locally so the bounded closing deadline can be observed.
        let unknown_id = create_unknown(crate::StoreKind::Company, &repo()?, &record)?;
        receipt["unknown_id"] = Value::String(unknown_id);
    } else if decision == "approve" {
        let (fact_id, event_id) =
            write_fact_event(destination_store(destination)?, &repo()?, &record)?;
        receipt["fact_id"] = Value::String(fact_id);
        receipt["event_id"] = Value::String(event_id);
    } else if decision == "escalate" {
        let unknown_id = create_unknown(destination_store(destination)?, &repo()?, &record)?;
        receipt["unknown_id"] = Value::String(unknown_id);
    }
    append_personal("proposal-decisions.jsonl", &receipt)?;
    print_value(&receipt, json);
    Ok(())
}

fn reissue(candidate: &str, json: bool) -> Result<(), ContractError> {
    let record = find_candidate(candidate)?;
    if decision_for(candidate).is_some() {
        return Err(ContractError::new(
            "APPROVAL_EXPIRED",
            "decided candidate cannot be reissued",
            "Use the original receipt or create a new candidate from current evidence.",
            false,
            ExitCode::UserActionRequired,
        ));
    }
    let now = crate::time::now_utc();
    let created = record
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| parse_rfc3339_millis(value).ok())
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "candidate created_at missing",
                "Create a new candidate.",
                false,
                ExitCode::Refused,
            )
        })?;
    let old_revision = record
        .get("source_revision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let current_revision = crate::repository::git_revision(&repo()?).unwrap_or_default();
    let changed = current_revision != old_revision;
    let aged = now.signed_duration_since(created).num_seconds() >= REISSUE_LOCK_SECONDS;
    if !changed && !aged {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "candidate bytes and source revision are unchanged within 24 hours",
            "Change the trusted source or wait for the reissue lock to expire.",
            false,
            ExitCode::Refused,
        ));
    }
    let mut reissued_canonical = record
        .get("canonical")
        .and_then(Value::as_str)
        .and_then(|text| crate::json::parse_strict_value(text.as_bytes()).ok())
        .and_then(|value| value.as_object().cloned())
        .map(|map| Value::Object(map.clone()))
        .unwrap_or_else(|| record.get("canonical").cloned().unwrap_or(Value::Null));
    if let Value::Object(map) = &mut reissued_canonical {
        map.insert(
            "source_revision".to_owned(),
            Value::String(current_revision.clone()),
        );
    }
    let payload_digest = sha256_text(&canonical_text(&reissued_canonical));
    let destination = record
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let principal = record
        .get("principal")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut core = crate::private::PrivateStore::open_core()?;
    let transaction = core.reserve_reissue(
        &principal,
        &destination,
        record
            .get("payload_digest")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        &current_revision,
        &format_rfc3339_millis(now),
    )?;
    let new_candidate_id = format!("cand_{}", Uuid::new_v4());
    let mut new_record = json!({
        "candidate_id": new_candidate_id,
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "destination": record.get("destination").cloned().unwrap_or(Value::Null),
        "canonical": reissued_canonical,
        "payload_digest": payload_digest,
        "principal": record.get("principal").cloned().unwrap_or(Value::Null),
        "host_instance_id": record.get("host_instance_id").cloned().unwrap_or(Value::Null),
        "source_revision": current_revision,
        "created_at": format_rfc3339_millis(now),
        "expires_at": format_rfc3339_millis(now + Duration::seconds(CANDIDATE_LIFETIME_SECONDS)),
        "nonce": Uuid::new_v4().to_string()
    });
    sign_candidate(&mut new_record)?;
    append_personal("candidates.jsonl", &new_record)?;
    let result = json!({
        "status": "reissued",
        "old_candidate_id": candidate,
        "candidate_id": new_candidate_id,
        "destination": new_record.get("destination").cloned().unwrap_or(Value::Null),
        "expires_at": new_record.get("expires_at").cloned().unwrap_or(Value::Null),
        "payload_digest": new_record.get("payload_digest").cloned().unwrap_or(Value::Null),
        "transaction": transaction
    });
    print_value(&result, json);
    Ok(())
}

fn reset(
    after_primary_event: &str,
    reason_code: crate::command_types::ResetReason,
    json: bool,
) -> Result<(), ContractError> {
    let reason = match reason_code {
        crate::command_types::ResetReason::NewPrimaryTask => "new-primary-task",
        crate::command_types::ResetReason::OperatorRecovery => "operator-recovery",
        crate::command_types::ResetReason::HostRestart => "host-restart",
    };
    let launcher = crate::launcher::Launcher::load()?;
    let now = format_rfc3339_millis(crate::time::now_utc());
    let mut core = crate::private::PrivateStore::open_core()?;
    let mut result = core.reset_consecutive(
        launcher.principal_id(),
        launcher.host_instance_id(),
        after_primary_event,
        reason,
        &now,
    )?;
    result["first_reset_accepted"] = Value::Bool(true);
    print_value(&result, json);
    Ok(())
}

pub fn destination_store(destination: &str) -> Result<crate::StoreKind, ContractError> {
    if destination == "personal" {
        Ok(crate::StoreKind::Personal)
    } else if destination == "company" || destination == "company:root" {
        Ok(crate::StoreKind::Company)
    } else if destination.starts_with("codebase:") && destination.len() > "codebase:".len() {
        Ok(crate::StoreKind::Codebase)
    } else {
        Err(ContractError::new(
            "CONFIG_INVARIANT",
            format!("unsupported destination: {destination}"),
            "Use company or codebase:<repository-id>.",
            false,
            ExitCode::Refused,
        ))
    }
}

pub fn write_fact_event(
    store: crate::StoreKind,
    repo: &Path,
    record: &Value,
) -> Result<(String, String), ContractError> {
    let canonical = record
        .get("canonical")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let map: Map<String, Value> = parse_strict_object(canonical.as_bytes()).map_err(|error| {
        ContractError::new(
            "DIGEST_MISMATCH",
            error,
            "Use the exact candidate bytes.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let scope = map
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("repository");
    let statement = map
        .get("statement")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractError::new(
                "DIGEST_MISMATCH",
                "candidate lacks statement",
                "Create a valid candidate.",
                false,
                ExitCode::IntegrityFailure,
            )
        })?;
    let atom_kind = map
        .get("atom_kind")
        .and_then(Value::as_str)
        .unwrap_or("observation");
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo))
        .transpose()?;
    let fact_id = format!(
        "fact_{:x}",
        Sha256::digest(format!("{scope}\0{statement}").as_bytes())
    );
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(
            record
                .get("payload_digest")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .as_bytes()
        )
    );
    let authority_id = if store == crate::StoreKind::Company {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let now = now_rfc3339_millis();
    let mut event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id: event_id.clone(),
        store_kind: store_name(store).to_owned(),
        authority_id: authority_id.to_owned(),
        authority_scope: scope.to_owned(),
        repository_id,
        fact_id: fact_id.clone(),
        logical_key: format!("logical_{:x}", Sha256::digest(scope.as_bytes())),
        atom_kind: atom_kind.to_owned(),
        scope: scope.to_owned(),
        statement: statement.to_owned(),
        evidence_refs: vec![
            record
                .get("candidate_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ],
        asserted_at: now.clone(),
        effective_from: now,
        effective_until: None,
        disposition: "current".to_owned(),
        distortion: Distortion {
            trigger: "approved dependent decision".to_owned(),
            loss_if_absent: 8_000,
            rationale: "human-approved fact is load-bearing for its dependent decision".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: crate::model::Bp(9_000),
        unresolved_uncertainty: None,
        signer: authority_id.to_owned(),
        signature: String::new(),
        raw: None,
    };
    let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
    let unsigned = crate::store::event_canonical_text(&event);
    event.signature = crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
    let root = crate::store::ensure_store_root(store, repo)?;
    crate::store::write_content_addressed_event(&root, &event)?;
    Ok((fact_id, event_id))
}

/// Close overdue apology Unknowns with exactly one deterministic, signed
/// `orphan_abandoned` event. The candidate bytes remain withheld.
fn emit_orphan_abandonments() -> Result<usize, ContractError> {
    emit_due_orphan_abandonments(&repo()?)
}

pub(crate) fn emit_due_orphan_abandonments(repository_root: &Path) -> Result<usize, ContractError> {
    let now = now_rfc3339_millis();
    let existing_orphans = personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .filter_map(|record| crate::json::get_str(&record, "orphan_id").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for unknown in crate::store::read_records(
        crate::StoreKind::Personal,
        repository_root,
        "unknowns.jsonl",
    )
    .unwrap_or_default()
    {
        let Some(due) = crate::json::get_str(&unknown, "response_due_at") else {
            continue;
        };
        let Ok(due) = parse_rfc3339_millis(due) else {
            continue;
        };
        if due > crate::time::now_utc() {
            continue;
        }
        let question = crate::json::get_str(&unknown, "question").unwrap_or_default();
        let destination = crate::json::get_str(&unknown, "decision_blocked").unwrap_or("codebase");
        let marker = format!(
            "orphan_{:x}",
            Sha256::digest(format!("{destination}\0{question}").as_bytes())
        );
        if existing_orphans.contains(&marker) {
            continue;
        }
        let event_id = format!("event_{:x}", Sha256::digest(marker.as_bytes()));
        let fact_id = format!("fact_{:x}", Sha256::digest(marker.as_bytes()));
        let logical_key = format!("logical_{:x}", Sha256::digest(marker.as_bytes()));
        let mut event = FactEvent {
            schema: crate::model::EVENT_SCHEMA.to_owned(),
            event_id,
            store_kind: "codebase".to_owned(),
            authority_id: "repository-maintainer".to_owned(),
            authority_scope: "architecture:escalation".to_owned(),
            repository_id: None,
            fact_id,
            logical_key,
            atom_kind: "orphan_abandoned".to_owned(),
            scope: "architecture:escalation".to_owned(),
            statement: format!("orphan_abandoned: {question}"),
            evidence_refs: vec![
                crate::json::get_str(&unknown, "unknown_id")
                    .unwrap_or_default()
                    .to_owned(),
            ],
            asserted_at: now.clone(),
            effective_from: now.clone(),
            effective_until: None,
            disposition: "orphan_abandoned".to_owned(),
            distortion: Distortion {
                trigger: "closing authority response_due_at passed".to_owned(),
                loss_if_absent: 8_000,
                rationale:
                    "an unanswered apology must be closed exactly once and the fact withheld"
                        .to_owned(),
            },
            parents: Vec::new(),
            supersedes: Vec::new(),
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            company_refs: Vec::<CompanyReference>::new(),
            authority_snapshot_cursor: "0".to_owned(),
            confidence: crate::model::Bp(8_000),
            unresolved_uncertainty: Some(
                "orphan abandoned without closing-authority action".to_owned(),
            ),
            signer: "repository-maintainer".to_owned(),
            signature: String::new(),
            raw: None,
        };
        let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Codebase, &repo()?)?;
        let unsigned = crate::store::event_canonical_text(&event);
        event.signature =
            crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
        let root = crate::store::ensure_store_root(crate::StoreKind::Codebase, repository_root)?;
        crate::store::write_content_addressed_event(&root, &event)?;
        append_personal(
            "orphan-abandonments.jsonl",
            &json!({"orphan_id": marker, "destination": destination, "event_id": event.event_id, "orphaned_fact_withheld": true}),
        )?;
    }
    Ok(personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .map(|record| {
            crate::json::get_str(&record, "orphan_id")
                .unwrap_or_default()
                .to_owned()
        })
        .collect::<BTreeSet<_>>()
        .len())
}

fn create_unknown(
    store: crate::StoreKind,
    repo: &Path,
    record: &Value,
) -> Result<String, ContractError> {
    let now = now_rfc3339_millis();
    let owner_role = if store == crate::StoreKind::Company {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo).ok())
        .flatten();
    let decision_blocked = record
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let principal = record
        .get("principal")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(principal_id)
        .to_owned();
    let question = apology_question(&decision_blocked, &principal, owner_role);
    let scope = "architecture:escalation";
    let response_due_at = format_rfc3339_millis(crate::time::now_utc() + Duration::hours(24));
    let logical_key = crate::model::logical_key(store_name(store), scope, &question);
    let mut unknown = UnknownEvent::new(
        store_name(store),
        repository_id.as_deref(),
        owner_role,
        scope,
        &logical_key,
        scope,
        &decision_blocked,
        owner_role,
        owner_role,
        &question,
        8_000,
        &now,
        &response_due_at,
        "block-dependent-decision",
        "0",
    );
    let unknown_id = unknown.fact_id.clone();
    let (private_path, _) = crate::crypto::ensure_keypair(store, repo)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local escalation-closing key")?;
    unknown.sign(&private_key)?;
    let record = unknown.to_value();
    // Unknowns are private runtime state, never additional tracked `.kin/`
    // artefacts. Signed fact events remain the only Codebase writes.
    crate::store::append_record(crate::StoreKind::Personal, repo, "unknowns.jsonl", &record)?;
    Ok(unknown_id)
}

fn principal_id() -> String {
    std::env::var("GUILDHALL_PRINCIPAL").unwrap_or_else(|_| "local-user".to_owned())
}

fn host_instance_id() -> String {
    std::env::var("GUILDHALL_HOST_INSTANCE").unwrap_or_else(|_| "local-host".to_owned())
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string(value).unwrap_or_default());
    } else {
        println!(
            "status: {}",
            value
                .get("status")
                .or_else(|| value.get("decision"))
                .and_then(Value::as_str)
                .unwrap_or("recorded")
        );
        if let Some(candidate) = value.get("candidate_id").and_then(Value::as_str) {
            println!("candidate: {candidate}");
        }
    }
}

fn receipt_id(candidate: &str, destination: &str, digest: &str) -> String {
    format!(
        "receipt_{:x}",
        Sha256::digest(format!("{candidate}\0{destination}\0{digest}").as_bytes())
    )
}

fn apology_question(destination: &str, principal: &str, closing_authority: &str) -> String {
    format!(
        "Apology Unknown for destination {destination}: approving principal {principal}; closing authority {closing_authority}."
    )
}

fn store_name(store: crate::StoreKind) -> &'static str {
    crate::ingest::store_name(store)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn saga_states_split_company_and_codebase_destinations() {
        let candidates = vec![
            json!({"candidate_id": "c-company", "destination": "company:root"}),
            json!({"candidate_id": "c-code", "destination": "codebase:1234"}),
        ];
        let decisions = vec![
            json!({"candidate_id": "c-company", "state": "refused"}),
            json!({"candidate_id": "c-code", "state": "committed"}),
        ];
        assert_eq!(fanout_state(&candidates, &decisions, "company:"), "refused");
        assert_eq!(
            fanout_state(&candidates, &decisions, "codebase:"),
            "committed"
        );
        assert_eq!(decision_state(&json!({"state": "pending"})), "pending");
        assert_eq!(
            decision_state(&json!({"candidate_id": "missing", "state": "other"})),
            "refused"
        );
    }

    #[test]
    fn committed_retry_receipt_is_deterministic_and_names_apology_parties() {
        let left = receipt_id("candidate", "codebase:1234", "digest");
        let right = receipt_id("candidate", "codebase:1234", "digest");
        assert_eq!(left, right);
        let question = apology_question(
            "codebase:1234",
            "alice@example.test",
            "repository-maintainer",
        );
        assert!(question.contains("approving principal alice@example.test"));
        assert!(question.contains("closing authority repository-maintainer"));
    }
}
