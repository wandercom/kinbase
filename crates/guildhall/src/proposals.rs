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
    launcher: &crate::launcher::Launcher,
    command: crate::command_types::ProposalCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::ProposalCommand::List { session } => list(launcher, &session, json),
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
            launcher,
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
        } => reset(launcher, &after_primary_event, reason_code, json),
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

fn list(
    launcher: &crate::launcher::Launcher,
    session: &str,
    json: bool,
) -> Result<(), ContractError> {
    let repo_root = repo()?;
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
    let session_candidate_ids: BTreeSet<&str> = candidate_records
        .iter()
        .filter_map(|record| crate::json::get_str(record, "candidate_id"))
        .collect();
    let session_decisions: Vec<&Value> = decisions
        .iter()
        .filter(|decision| {
            crate::json::get_str(decision, "candidate_id")
                .is_some_and(|id| session_candidate_ids.contains(id))
        })
        .collect();
    // One committed destination transaction is one content-addressed event,
    // however many retries returned its receipt.
    let committed_event_count = session_decisions
        .iter()
        .filter(|decision| decision_state(decision) == "committed")
        .filter_map(|decision| crate::json::get_str(decision, "receipt_id"))
        .collect::<BTreeSet<_>>()
        .len();
    let orphan_abandoned_count = emit_due_orphan_abandonments(launcher, &repo_root)?;
    let apologies = current_apologies()
        .into_iter()
        .filter(|apology| {
            crate::json::get_str(apology, "candidate_id")
                .is_some_and(|id| session_candidate_ids.contains(id))
                || crate::json::get_str(apology, "committed_candidate_id")
                    .is_some_and(|id| session_candidate_ids.contains(id))
        })
        .map(|apology| {
            json!({
                "apology_id": apology.get("apology_id").cloned().unwrap_or(Value::Null),
                "candidate_id": apology.get("candidate_id").cloned().unwrap_or(Value::Null),
                "failed_destination": apology.get("failed_destination").cloned().unwrap_or(Value::Null),
                "failed_receipt_id": apology.get("failed_receipt_id").cloned().unwrap_or(Value::Null),
                "committed_destination": apology.get("committed_destination").cloned().unwrap_or(Value::Null),
                "committed_candidate_id": apology.get("committed_candidate_id").cloned().unwrap_or(Value::Null),
                "orphaned_event_id": apology.get("orphaned_event_id").cloned().unwrap_or(Value::Null),
                "responsible_party_role": "approving-principal",
                "responsible_party": apology.get("responsible_party").cloned().unwrap_or(Value::Null),
                "closing_authority_role": apology.get("closing_authority_role").cloned().unwrap_or(Value::Null),
                "closing_authority": apology.get("closing_authority").cloned().unwrap_or(Value::Null),
                "orphaned_fact_withheld": true,
                "unknown_id": apology.get("unknown_id").cloned().unwrap_or(Value::Null),
                "response_due_at": apology.get("response_due_at").cloned().unwrap_or(Value::Null),
                "state": apology.get("state").cloned().unwrap_or(Value::String("awaiting_reconcile_or_abandon".to_owned()))
            })
        })
        .collect::<Vec<_>>();
    // An apology whose parent is itself an apology would be recursive; the
    // saga keys apologies by the divergent receipt pair, so none can exist.
    let apology_ids: BTreeSet<&str> = apologies
        .iter()
        .filter_map(|apology| crate::json::get_str(apology, "apology_id"))
        .collect();
    let recursive_apologies = apologies
        .iter()
        .filter(|apology| {
            crate::json::get_str(apology, "failed_receipt_id")
                .is_some_and(|receipt| apology_ids.contains(receipt))
        })
        .count();
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
        "recursive_apologies": recursive_apologies,
        "committed_event_count": committed_event_count,
        "orphan_abandoned_count": orphan_abandoned_count,
        "journal_state": inflight_journal_state(&repo_root)
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

/// The saga receipt state of one destination across the session's decided
/// candidates. Undecided candidates are not transactions and do not vote;
/// a destination with a committed transaction reports it, an attempted but
/// unfinished one is pending, and only refusals leave it refused.
fn fanout_state(
    candidates: &[Value],
    decisions: &[Value],
    destination_prefix: &str,
) -> &'static str {
    let mut states = Vec::new();
    for record in candidates {
        if !crate::json::get_str(record, "destination")
            .is_some_and(|destination| destination.starts_with(destination_prefix))
        {
            continue;
        }
        let Some(candidate_id) = crate::json::get_str(record, "candidate_id") else {
            continue;
        };
        if let Some(decision) = decisions
            .iter()
            .filter(|decision| crate::json::get_str(decision, "candidate_id") == Some(candidate_id))
            .last()
        {
            if crate::json::get_str(decision, "decision") == Some("approve") {
                states.push(decision_state(decision));
            }
        }
    }
    if states.iter().any(|state| *state == "committed") {
        "committed"
    } else if states.iter().any(|state| *state == "pending") {
        "pending"
    } else if states.iter().any(|state| *state == "refused") {
        "refused"
    } else if states.iter().any(|state| *state == "abandoned") {
        "abandoned"
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
    launcher: &crate::launcher::Launcher,
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
    let previous = decision_for(candidate);
    if let Some(previous) = &previous {
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
        // A committed or refused transaction is terminal: the retry returns
        // the stored receipt even after token expiry (architecture §3). A
        // pending destination is retried below through the same saga.
        if decision_state(previous) != "pending"
            || crate::json::get_str(previous, "decision") != Some("approve")
        {
            let mut previous = previous.clone();
            previous["retry_after_token_expiry"] = Value::Bool(expired(&record).unwrap_or(false));
            previous["receipt_ids_equal"] = Value::Bool(true);
            if previous.get("state").is_none() {
                previous["state"] = Value::String("committed".to_owned());
            }
            print_value(&previous, json);
            return Ok(());
        }
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
    let receipt_id = receipt_id(candidate, destination, &digest);
    let mut receipt = json!({
        "candidate_id": candidate,
        "destination": destination,
        "decision": decision,
        "digest": digest,
        "decided_at": now_rfc3339_millis(),
        "receipt_id": receipt_id,
        "state": if decision == "defer" { "pending" } else { "refused" },
        "receipt_ids_equal": true,
        "retry_after_token_expiry": false
    });
    if decision == "approve" {
        let store = destination_store(destination)?;
        match store {
            crate::StoreKind::Codebase => {
                let saga = fanout_saga_result(
                    launcher,
                    &repo()?,
                    &record,
                    destination,
                    &digest,
                    &receipt_id,
                )?;
                merge_receipt(&mut receipt, &saga);
            }
            crate::StoreKind::Company => {
                let saga = fanout_saga_result(
                    launcher,
                    &repo()?,
                    &record,
                    destination,
                    &digest,
                    &receipt_id,
                )?;
                merge_receipt(&mut receipt, &saga);
            }
            crate::StoreKind::Personal => {
                let (fact_id, event_id) = write_fact_event(store, &repo()?, &record)?;
                receipt["fact_id"] = Value::String(fact_id);
                receipt["event_id"] = Value::String(event_id);
                receipt["state"] = Value::String("committed".to_owned());
            }
        }
    } else if decision == "escalate" {
        let unknown_id = create_unknown(destination_store(destination)?, &repo()?, &record)?;
        receipt["unknown_id"] = Value::String(unknown_id);
    }
    if previous.is_none() || decision_state(&receipt) != "pending" {
        append_personal("proposal-decisions.jsonl", &receipt)?;
    }
    print_value(&receipt, json);
    Ok(())
}

fn merge_receipt(receipt: &mut Value, saga: &Value) {
    if let (Value::Object(target), Value::Object(source)) = (receipt, saga) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Fan-out saga: one journaled destination transaction per (candidate,
// destination). Every transition is a durable marker in the destination
// journal (`.kin/local/journal/fanout/<candidate>/<transition>.json`) written
// before its side effect and completed after it, so a restart replays or
// rolls back from the journal; the admission lock serializes competing local
// writers on one repository identity.
// ---------------------------------------------------------------------------

const FANOUT_JOURNAL_SCHEMA: &str = "guildhall-fanout-journal/1";
const APOLOGY_RESPONSE_WINDOW_HOURS: i64 = 24;

/// The closed transition enum of the destination journal (architecture §3:
/// nonce reservation, event append/rename, manifest, receipt, apology).
pub const FANOUT_TRANSITIONS: [(&str, &str); 5] = [
    ("nonce_reservation", "nonce_reserved"),
    ("event_append_rename", "event_appended"),
    ("manifest", "manifest_written"),
    ("receipt", "receipt_written"),
    ("apology", "apology_written"),
];

fn completed_state(transition: &str) -> &'static str {
    FANOUT_TRANSITIONS
        .iter()
        .find(|(name, _)| *name == transition)
        .map(|(_, completed)| *completed)
        .unwrap_or("done")
}

struct FanoutJournal {
    dir: std::path::PathBuf,
    candidate_id: String,
    destination: String,
}

impl FanoutJournal {
    fn open(
        repository: &crate::codebase::Repository,
        candidate_id: &str,
        destination: &str,
    ) -> Result<Self, ContractError> {
        let local = repository.ensure_local()?;
        let dir = local.join("journal").join("fanout").join(candidate_id);
        crate::paths::ensure_private_dir(&dir, "fan-out journal")?;
        Ok(Self {
            dir,
            candidate_id: candidate_id.to_owned(),
            destination: destination.to_owned(),
        })
    }

    fn marker_path(&self, transition: &str) -> std::path::PathBuf {
        self.dir.join(format!("{transition}.json"))
    }

    fn read(&self, transition: &str) -> Option<Value> {
        let bytes = std::fs::read(self.marker_path(transition)).ok()?;
        crate::json::parse_strict_value(&bytes).ok()
    }

    fn state(&self, transition: &str) -> Option<String> {
        self.read(transition)
            .and_then(|marker| crate::json::get_str(&marker, "journal_state").map(str::to_owned))
    }

    fn is_complete(&self, transition: &str) -> bool {
        self.state(transition).as_deref() == Some(completed_state(transition))
    }

    fn is_done(&self) -> bool {
        self.state("done").as_deref() == Some("done")
    }

    /// Durably record a transition state. The marker carries the candidate
    /// identity so a reader can attribute it, and it is fsynced (file and
    /// directory) before the caller proceeds to the next side effect.
    fn write(
        &self,
        transition: &str,
        journal_state: &str,
        extra: Value,
    ) -> Result<Value, ContractError> {
        let mut marker = json!({});
        if let (Value::Object(target), Value::Object(source)) = (&mut marker, extra) {
            for (key, value) in source {
                target.insert(key, value);
            }
        }
        marker["schema"] = Value::String(FANOUT_JOURNAL_SCHEMA.to_owned());
        marker["candidate_id"] = Value::String(self.candidate_id.clone());
        marker["destination"] = Value::String(self.destination.clone());
        marker["transition"] = Value::String(transition.to_owned());
        marker["journal_state"] = Value::String(journal_state.to_owned());
        marker["updated_at"] = Value::String(now_rfc3339_millis());
        crate::paths::write_atomic(
            &self.marker_path(transition),
            &crate::json::canonical_bytes(&marker),
            0o600,
            false,
        )?;
        Ok(marker)
    }

    /// Mark the intent to perform a transition (its side effect may or may
    /// not follow before a crash; replay treats it as not yet done).
    fn begin(&self, transition: &str, extra: Value) -> Result<Value, ContractError> {
        if let Some(existing) = self.read(transition) {
            if crate::json::get_str(&existing, "journal_state") == Some(completed_state(transition))
            {
                return Ok(existing);
            }
            // Preserve the bytes bound at the first attempt so a replay
            // reuses exactly them.
            let mut merged = existing.clone();
            if let (Value::Object(target), Value::Object(source)) = (&mut merged, extra) {
                for (key, value) in source {
                    target.entry(key).or_insert(value);
                }
            }
            let extra = merged;
            return self.write(transition, transition, extra);
        }
        self.write(transition, transition, extra)
    }

    fn complete(&self, transition: &str, extra: Value) -> Result<Value, ContractError> {
        let mut merged = self.read(transition).unwrap_or_else(|| json!({}));
        if let (Value::Object(target), Value::Object(source)) = (&mut merged, extra) {
            for (key, value) in source {
                target.insert(key, value);
            }
        }
        self.write(transition, completed_state(transition), merged)
    }

    fn finish(&self) -> Result<(), ContractError> {
        self.write("done", "done", json!({}))?;
        Ok(())
    }
}

fn fanout_saga_result(
    launcher: &crate::launcher::Launcher,
    repo_root: &Path,
    record: &Value,
    destination: &str,
    payload_digest: &str,
    receipt_id: &str,
) -> Result<Value, ContractError> {
    let repository = crate::codebase::Repository::discover(repo_root)?;
    let repository_uuid = crate::repository::repository_id(repo_root)?;
    if let Some(bound) = destination.strip_prefix("codebase:") {
        if bound != repository_uuid {
            return Err(ContractError::new(
                "APPROVAL_EXPIRED",
                "candidate names a different repository identity than the certified one",
                "Create a candidate for the certified repository identity.",
                false,
                ExitCode::UserActionRequired,
            ));
        }
    }
    let candidate_id = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    // Every transition below is one generation under the exclusive
    // admission lock; the journal carries the transaction between
    // generations, so the lock is never held across a Company round trip
    // and competing local writers retry from the committed generation.
    recover_fanout_journal(&repository, &repository_uuid, Some(candidate_id))?;
    let journal = FanoutJournal::open(&repository, candidate_id, destination)?;
    if destination.starts_with("codebase:") {
        commit_codebase(
            &repository,
            &repository_uuid,
            &journal,
            record,
            payload_digest,
            receipt_id,
        )
    } else {
        commit_company(
            launcher,
            &repository,
            &repository_uuid,
            &journal,
            record,
            payload_digest,
            receipt_id,
        )
    }
}

/// Build the destination event once and bind the approval nonce to its
/// exact bytes in the journal (nonce reservation). A replay reuses the bound
/// bytes, so a retry can never mint a second content-addressed event.
fn reserve_nonce(
    repository: &crate::codebase::Repository,
    journal: &FanoutJournal,
    repository_uuid: &str,
    store: crate::StoreKind,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
) -> Result<(Vec<u8>, Value), ContractError> {
    let bound = journal
        .read("nonce_reservation")
        .and_then(|marker| crate::json::get_str(&marker, "event_canonical").map(str::to_owned));
    let (canonical, event) = match bound {
        Some(canonical) => {
            let event = crate::json::parse_strict_value(canonical.as_bytes()).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!("journaled event bytes are not canonical: {error}"),
                    "Preserve the journal; the bound event bytes are never reinterpreted.",
                )
            })?;
            (canonical, event)
        }
        None => {
            let event = build_destination_event(store, repository_uuid, record)?;
            (canonical_text(&event), event)
        }
    };
    if !journal.is_complete("nonce_reservation") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "nonce_reservation",
            json!({
                "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
                "payload_digest": payload_digest,
                "receipt_id": receipt_id,
                "principal": record.get("principal").cloned().unwrap_or(Value::Null),
                "event_canonical": canonical,
                "event_digest": sha256_text(&canonical),
                "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
                "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
                "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null)
            }),
        )?;
        append_personal(
            "nonce-reservations.jsonl",
            &json!({
                "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
                "candidate_id": journal.candidate_id,
                "destination": journal.destination,
                "payload_digest": payload_digest,
                "receipt_id": receipt_id,
                "event_digest": sha256_text(&canonical)
            }),
        )?;
        journal.complete("nonce_reservation", json!({}))?;
    }
    Ok((canonical.into_bytes(), event))
}

fn commit_codebase(
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    journal: &FanoutJournal,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
) -> Result<Value, ContractError> {
    let (bytes, event) = reserve_nonce(
        repository,
        journal,
        repository_uuid,
        crate::StoreKind::Codebase,
        record,
        payload_digest,
        receipt_id,
    )?;
    let event_digest = crate::hash::sha256_bytes(&bytes);
    let relative = crate::paths::sharded_relative(&event_digest)?;
    let final_path = crate::paths::contained(&repository.kin.join("events"), &relative)?;
    let event_path = format!(".kin/events/{}", relative.to_string_lossy());
    let local = repository.ensure_local()?;
    // event append + atomic rename to the content-addressed path
    if !journal.is_complete("event_append_rename") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "event_append_rename",
            json!({"event_digest": event_digest, "event_path": event_path}),
        )?;
        let staging = local.join("staging");
        crate::paths::ensure_private_dir(&staging, "staging")?;
        let staged = staging.join(format!("{event_digest}.json"));
        crate::paths::write_atomic(&staged, &bytes, 0o600, false)?;
        let created = crate::paths::write_atomic(&final_path, &bytes, 0o644, true)?;
        let _ = std::fs::remove_file(&staged);
        journal.complete("event_append_rename", json!({"created": created}))?;
    }
    // manifest: the destination's local index of admitted digests
    if !journal.is_complete("manifest") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "manifest",
            json!({"index": ".kin/local/guildhall-index.json"}),
        )?;
        repository.update_index_cache()?;
        journal.complete("manifest", json!({}))?;
    }
    // receipt: the destination's own committed receipt
    let receipts_dir = local.join("receipts").join(repository_uuid);
    crate::paths::ensure_private_dir(&receipts_dir, "receipts")?;
    let receipt_path = receipts_dir.join(format!("{event_digest}.json"));
    if !journal.is_complete("receipt") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "receipt",
            json!({"receipt_path": receipt_path.to_string_lossy()}),
        )?;
        if !receipt_path.exists() {
            let receipt = json!({
                "schema": crate::model::RECEIPT_SCHEMA,
                "receipt_id": receipt_id,
                "candidate_id": journal.candidate_id,
                "destination": journal.destination,
                "repository_uuid": repository_uuid,
                "status": "committed",
                "state": "committed",
                "event_digest": event_digest,
                "event_path": event_path,
                "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
                "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
                "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null),
                "payload_digest": payload_digest,
                "committed_at": now_rfc3339_millis()
            });
            crate::paths::write_atomic(
                &receipt_path,
                &crate::json::canonical_bytes(&receipt),
                0o600,
                false,
            )?;
        }
        journal.complete("receipt", json!({}))?;
        journal.finish()?;
    }
    let stored =
        std::fs::read(&receipt_path).map_err(|error| ContractError::io("read receipt", error))?;
    let stored = crate::json::parse_strict_value(&stored).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!("receipt is not canonical JSON: {error}"),
            "Run fsck; the receipt store is corrupt.",
        )
    })?;
    Ok(json!({
        "state": "committed",
        "receipt_id": crate::json::get_str(&stored, "receipt_id").unwrap_or(receipt_id),
        "event_digest": event_digest,
        "event_path": event_path,
        "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
        "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
        "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null),
        "journal_generation": journal.candidate_id
    }))
}

fn commit_company(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    journal: &FanoutJournal,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
) -> Result<Value, ContractError> {
    let (_bytes, event) = reserve_nonce(
        repository,
        journal,
        repository_uuid,
        crate::StoreKind::Company,
        record,
        payload_digest,
        receipt_id,
    )?;
    // A terminal receipt is replayed as-is; a pending one is re-attempted.
    if journal.is_complete("receipt") {
        if let Some(marker) = journal.read("receipt") {
            if matches!(
                crate::json::get_str(&marker, "state"),
                Some("committed") | Some("refused")
            ) {
                journal.finish()?;
                return Ok(receipt_from_marker(&marker, receipt_id));
            }
        }
    }
    // The Company destination runs its own transaction; the client sends
    // the event once per attempt and records the outcome it was given.
    let attempt = match launcher.company() {
        Ok(Some(access)) => match access.client.post_fact(&event) {
            Ok(body) => json!({"state": "committed", "company_receipt": body}),
            Err(error) => json!({
                "state": if error.code == "COMPANY_UNREACHABLE" { "pending" } else { "refused" },
                "error_code": error.code,
                "error_message": error.message,
                "retryable": error.retryable,
                "company_unreachable": error.code == "COMPANY_UNREACHABLE",
                "timeout_observed": error.code == "COMPANY_UNREACHABLE"
            }),
        },
        Ok(None) => json!({
            "state": "refused",
            "error_code": "AUTHORITY_SCOPE_DENIED",
            "error_message": "no Company endpoint is configured for this principal",
            "retryable": false
        }),
        Err(error) => json!({
            "state": "refused",
            "error_code": error.code,
            "error_message": error.message,
            "retryable": error.retryable
        }),
    };
    let state = crate::json::get_str(&attempt, "state")
        .unwrap_or("refused")
        .to_owned();
    let mut apology_ids = Vec::new();
    if state != "committed" {
        // Divergence: another destination of the same source already holds
        // a durable commit that this failure cannot roll back. The
        // approving principal owns the divergence; the committed
        // destination receives the apology Unknown.
        for sibling in committed_siblings(record) {
            let apology_id = apology_id_for(receipt_id, &sibling);
            if !journal.is_complete("apology") || !apology_exists(&apology_id) {
                let _generation = repository.admission_lock(repository_uuid)?;
                journal.begin("apology", json!({"apology_id": apology_id, "committed_receipt_id": sibling.get("receipt_id").cloned().unwrap_or(Value::Null)}))?;
                let unknown_id = write_apology(
                    launcher,
                    repository,
                    repository_uuid,
                    record,
                    receipt_id,
                    &attempt,
                    &sibling,
                    &apology_id,
                )?;
                journal.complete("apology", json!({"unknown_id": unknown_id}))?;
            }
            apology_ids.push(apology_id);
        }
    }
    let _generation = repository.admission_lock(repository_uuid)?;
    journal.begin("receipt", json!({}))?;
    let marker = journal.complete(
        "receipt",
        json!({
            "state": state,
            "attempt": attempt,
            "apology_ids": apology_ids,
            "receipt_id": receipt_id
        }),
    )?;
    if state != "pending" {
        journal.finish()?;
    }
    Ok(receipt_from_marker(&marker, receipt_id))
}

fn receipt_from_marker(marker: &Value, receipt_id: &str) -> Value {
    let mut receipt = json!({
        "state": crate::json::get_str(marker, "state").unwrap_or("pending"),
        "receipt_id": crate::json::get_str(marker, "receipt_id").unwrap_or(receipt_id),
        "apology_ids": marker.get("apology_ids").cloned().unwrap_or_else(|| json!([]))
    });
    if let Some(Value::Object(attempt)) = marker.get("attempt") {
        for (key, value) in attempt {
            if key != "state" {
                receipt[key] = value.clone();
            }
        }
    }
    if let Some(unknown) = marker.get("unknown_id") {
        receipt["unknown_id"] = unknown.clone();
    }
    receipt
}

/// Committed decisions of other destinations for the same source message
/// (the siblings of one fan-out).
fn committed_siblings(record: &Value) -> Vec<Value> {
    let message_id = crate::json::get_str(record, "message_id").unwrap_or_default();
    let session_id = crate::json::get_str(record, "session_id").unwrap_or_default();
    let candidate_id = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    let siblings: Vec<Value> = personal_records("candidates.jsonl")
        .into_iter()
        .filter(|other| {
            crate::json::get_str(other, "message_id") == Some(message_id)
                && crate::json::get_str(other, "session_id") == Some(session_id)
                && crate::json::get_str(other, "candidate_id") != Some(candidate_id)
        })
        .collect();
    let decisions = personal_records("proposal-decisions.jsonl");
    let mut committed = Vec::new();
    for sibling in siblings {
        let sibling_id = crate::json::get_str(&sibling, "candidate_id").unwrap_or_default();
        if let Some(decision) = decisions
            .iter()
            .filter(|decision| crate::json::get_str(decision, "candidate_id") == Some(sibling_id))
            .last()
        {
            if decision_state(decision) == "committed"
                && crate::json::get_str(decision, "decision") == Some("approve")
            {
                committed.push(decision.clone());
            }
        }
    }
    committed
}

fn apology_id_for(failed_receipt_id: &str, committed: &Value) -> String {
    let committed_receipt = crate::json::get_str(committed, "receipt_id").unwrap_or_default();
    format!(
        "apology_{}",
        &crate::hash::sha256_text(&format!("{failed_receipt_id}\0{committed_receipt}"))[..40]
    )
}

fn apology_exists(apology_id: &str) -> bool {
    personal_records("apologies.jsonl")
        .iter()
        .any(|apology| crate::json::get_str(apology, "apology_id") == Some(apology_id))
}

/// The latest state of every apology (append-only records; last wins).
fn current_apologies() -> Vec<Value> {
    let mut latest: BTreeMap<String, Value> = BTreeMap::new();
    for record in personal_records("apologies.jsonl") {
        let Some(id) = crate::json::get_str(&record, "apology_id") else {
            continue;
        };
        let entry = latest
            .entry(id.to_owned())
            .or_insert_with(|| record.clone());
        if let (Value::Object(target), Value::Object(source)) = (entry, &record) {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    latest.into_values().collect()
}

/// Resolve the in-scope closing authority of a destination from the cached
/// authority registry: the repository maintainer for the Codebase, the
/// steward for Company. Unresolved identities stay Unknown-owned by role.
fn closing_authority(
    launcher: &crate::launcher::Launcher,
    destination: &str,
    repository_uuid: &str,
) -> (String, Option<String>) {
    let role = if destination.starts_with("company") {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let scope = if destination.starts_with("company") {
        "company:root".to_owned()
    } else {
        format!("codebase:{repository_uuid}")
    };
    let identity = launcher
        .company_cache()
        .ok()
        .flatten()
        .and_then(|(cache, _)| cache.snapshot().ok().flatten())
        .and_then(|snapshot| {
            crate::json::get_array(&snapshot, "registry").and_then(|entries| {
                let ids: Vec<String> = entries
                    .iter()
                    .filter(|entry| crate::json::get_str(entry, "scope") == Some(scope.as_str()))
                    .filter(|entry| {
                        crate::json::get_str(entry, "status").unwrap_or("active") == "active"
                    })
                    .filter_map(|entry| {
                        crate::json::get_str(entry, "authority_id").map(str::to_owned)
                    })
                    .collect();
                (ids.len() == 1).then(|| ids[0].clone())
            })
        });
    (role.to_owned(), identity)
}

/// Write the apology Unknown for one divergent fan-out into the committed
/// destination's private Unknown store and the saga record. Idempotent per
/// apology id: a replay after a crash writes the same Unknown once.
fn write_apology(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    record: &Value,
    failed_receipt_id: &str,
    attempt: &Value,
    committed: &Value,
    apology_id: &str,
) -> Result<String, ContractError> {
    if let Some(existing) = current_apologies()
        .into_iter()
        .find(|apology| crate::json::get_str(apology, "apology_id") == Some(apology_id))
    {
        // A replay after a crash finds the apology already written: the
        // same Unknown, never a second (recursive) apology.
        return Ok(crate::json::get_str(&existing, "unknown_id")
            .unwrap_or_default()
            .to_owned());
    }
    let committed_destination = crate::json::get_str(committed, "destination")
        .unwrap_or_default()
        .to_owned();
    let failed_destination = crate::json::get_str(record, "destination")
        .unwrap_or_default()
        .to_owned();
    let principal = crate::json::get_str(record, "principal")
        .map(str::to_owned)
        .unwrap_or_else(principal_id);
    let (closing_role, closing_identity) =
        closing_authority(launcher, &committed_destination, repository_uuid);
    let closing_name = closing_identity
        .clone()
        .unwrap_or_else(|| closing_role.clone());
    let now = crate::time::now_utc();
    let response_due_at =
        format_rfc3339_millis(now + Duration::hours(APOLOGY_RESPONSE_WINDOW_HOURS));
    let store = destination_store(&committed_destination)?;
    let question = format!(
        "Apology Unknown for divergent fan-out: destination {failed_destination} failed ({}) after {committed_destination} committed receipt {}. Approving principal {principal} is responsible; closing authority {closing_name} ({closing_role}) must reconcile or abandon by {response_due_at}. The orphaned claim is withheld from trusted use until then.",
        crate::json::get_str(attempt, "error_code").unwrap_or("refused"),
        crate::json::get_str(committed, "receipt_id").unwrap_or_default()
    );
    let scope = "architecture:escalation";
    let logical_key = crate::model::logical_key(store_name(store), scope, apology_id);
    let mut unknown = UnknownEvent::new(
        store_name(store),
        (store == crate::StoreKind::Codebase).then_some(repository_uuid),
        &closing_role,
        scope,
        &logical_key,
        scope,
        &committed_destination,
        &closing_role,
        &closing_name,
        &question,
        8_000,
        &format_rfc3339_millis(now),
        &response_due_at,
        "block-dependent-decision",
        "0",
    );
    unknown.parents = vec![
        crate::json::get_str(committed, "event_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    unknown.evidence_refs = vec![
        failed_receipt_id.to_owned(),
        crate::json::get_str(committed, "receipt_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    let unknown_id = unknown.fact_id.clone();
    let (private_path, _) = crate::crypto::ensure_keypair(store, &repository.root)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local escalation-closing key")?;
    unknown.sign(&private_key)?;
    // Unknowns are private runtime state of the committed destination, never
    // additional tracked `.kin/` artefacts.
    crate::store::append_record(
        crate::StoreKind::Personal,
        &repository.root,
        "unknowns.jsonl",
        &unknown.to_value(),
    )?;
    let apology = json!({
        "apology_id": apology_id,
        "candidate_id": record.get("candidate_id").cloned().unwrap_or(Value::Null),
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "message_id": record.get("message_id").cloned().unwrap_or(Value::Null),
        "failed_destination": failed_destination,
        "failed_receipt_id": failed_receipt_id,
        "failure_code": attempt.get("error_code").cloned().unwrap_or(Value::Null),
        "committed_destination": committed_destination,
        "committed_candidate_id": committed.get("candidate_id").cloned().unwrap_or(Value::Null),
        "committed_receipt_id": committed.get("receipt_id").cloned().unwrap_or(Value::Null),
        "orphaned_event_id": committed.get("event_id").cloned().unwrap_or(Value::Null),
        "orphaned_fact_id": committed.get("fact_id").cloned().unwrap_or(Value::Null),
        "orphaned_logical_key": committed.get("logical_key").cloned().unwrap_or(Value::Null),
        "orphaned_event_digest": committed.get("event_digest").cloned().unwrap_or(Value::Null),
        "repository_uuid": repository_uuid,
        "responsible_party_role": "approving-principal",
        "responsible_party": principal,
        "closing_authority_role": closing_role,
        "closing_authority": closing_name,
        "closing_authority_resolved": closing_identity.is_some(),
        "orphaned_fact_withheld": true,
        "unknown_id": unknown_id,
        "response_due_at": response_due_at,
        "created_at": format_rfc3339_millis(now),
        "state": "awaiting_reconcile_or_abandon"
    });
    append_personal("apologies.jsonl", &apology)?;
    // The pending saga is also visible to the Company cache so `status`
    // counts it among the orphans awaiting reconcile/abandon.
    if let Ok(Some((cache, _))) = launcher.company_cache() {
        let _ = cache.save_saga(
            crate::json::get_str(record, "candidate_id").unwrap_or_default(),
            &apology,
            &format_rfc3339_millis(now),
        );
    }
    Ok(unknown_id)
}

/// Replay every unfinished fan-out saga of this repository under the lock:
/// a transaction whose event bytes are durable completes forward; one that
/// never bound its bytes is rolled back. The candidate being decided now is
/// replayed by its own idempotent transitions.
fn recover_fanout_journal(
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    current_candidate: Option<&str>,
) -> Result<Vec<Value>, ContractError> {
    let root = repository.local_dir().join("journal").join("fanout");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut replayed = Vec::new();
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .map_err(|error| ContractError::io("read fan-out journal", error))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    for dir in entries {
        let candidate_id = dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if current_candidate == Some(candidate_id.as_str()) {
            continue;
        }
        let Some(record) = personal_records("candidates.jsonl")
            .into_iter()
            .find(|record| {
                crate::json::get_str(record, "candidate_id") == Some(candidate_id.as_str())
            })
        else {
            continue;
        };
        let destination = crate::json::get_str(&record, "destination")
            .unwrap_or_default()
            .to_owned();
        let journal = FanoutJournal {
            dir: dir.clone(),
            candidate_id: candidate_id.clone(),
            destination: destination.clone(),
        };
        if journal.is_done() || !destination.starts_with("codebase:") {
            continue;
        }
        let Some(reservation) = journal.read("nonce_reservation") else {
            continue;
        };
        let Some(canonical) = crate::json::get_str(&reservation, "event_canonical") else {
            journal.write(
                "rolled_back",
                "rolled_back",
                json!({"reason": "no event bytes were bound"}),
            )?;
            journal.finish()?;
            replayed.push(json!({"candidate_id": candidate_id, "action": "rolled-back"}));
            continue;
        };
        let digest = sha256_text(canonical);
        let payload_digest = crate::json::get_str(&reservation, "payload_digest")
            .unwrap_or_default()
            .to_owned();
        let receipt_id = crate::json::get_str(&reservation, "receipt_id")
            .unwrap_or_default()
            .to_owned();
        commit_codebase(
            repository,
            repository_uuid,
            &journal,
            &record,
            &payload_digest,
            &receipt_id,
        )?;
        replayed
            .push(json!({"candidate_id": candidate_id, "digest": digest, "action": "completed"}));
    }
    Ok(replayed)
}

/// In-flight fan-out journal markers (for `status`/`fsck`): every marker of
/// a saga that has not reached `done`.
pub fn inflight_journal_state(repo_root: &Path) -> Value {
    let Ok(repository) = crate::codebase::Repository::discover(repo_root) else {
        return json!([]);
    };
    let root = repository.local_dir().join("journal").join("fanout");
    let mut markers = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return json!([]);
    };
    for entry in entries.filter_map(Result::ok) {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let done = std::fs::read(dir.join("done.json"))
            .ok()
            .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok())
            .is_some_and(|marker| crate::json::get_str(&marker, "journal_state") == Some("done"));
        if done {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<std::path::PathBuf> = files
            .filter_map(|file| file.ok().map(|file| file.path()))
            .collect();
        paths.sort();
        for path in paths {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with(".tmp-") || !name.ends_with(".json") {
                continue;
            }
            if let Some(marker) = std::fs::read(&path)
                .ok()
                .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok())
            {
                markers.push(json!({
                    "candidate_id": marker.get("candidate_id").cloned().unwrap_or(Value::Null),
                    "destination": marker.get("destination").cloned().unwrap_or(Value::Null),
                    "transition": marker.get("transition").cloned().unwrap_or(Value::Null),
                    "journal_state": marker.get("journal_state").cloned().unwrap_or(Value::Null),
                    "updated_at": marker.get("updated_at").cloned().unwrap_or(Value::Null)
                }));
            }
        }
    }
    json!(markers)
}

/// Apologies still awaiting reconcile/abandon (the orphans that are not yet
/// terminally closed).
pub fn pending_orphan_count(_repo_root: &Path) -> usize {
    current_apologies()
        .iter()
        .filter(|apology| {
            crate::json::get_str(apology, "state") == Some("awaiting_reconcile_or_abandon")
        })
        .count()
}

/// Saga-authoritative fields for a terminal `orphan_abandoned` event that the
/// destination service emitted: the orphaned claim's saga state (withdrawn)
/// and the unresponsive closing authority. `None` for every other event.
pub fn saga_terminal_event_fields(event_id: &str) -> Option<Value> {
    personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .find(|record| crate::json::get_str(record, "event_id") == Some(event_id))
        .map(|record| {
            json!({
                "fact_state": "withdrawn",
                "saga_state": "abandoned",
                "unresponsive_closing_authority": record.get("unresponsive_closing_authority").cloned().unwrap_or(Value::Null),
                "apology_id": record.get("apology_id").cloned().unwrap_or(Value::Null)
            })
        })
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
    launcher: &crate::launcher::Launcher,
    after_primary_event: &str,
    reason_code: crate::command_types::ResetReason,
    json: bool,
) -> Result<(), ContractError> {
    let reason = match reason_code {
        crate::command_types::ResetReason::NewPrimaryTask => "new-primary-task",
        crate::command_types::ResetReason::OperatorRecovery => "operator-recovery",
        crate::command_types::ResetReason::HostRestart => "host-restart",
    };
    let now = format_rfc3339_millis(crate::time::now_utc());
    let mut core = crate::private::PrivateStore::open_core()?;
    let mut result = core.reset_consecutive(
        launcher.principal_id(),
        launcher.host_instance_id(),
        after_primary_event,
        reason,
        &now,
    )?;
    result["first_reset_accepted"] = Value::Bool(result.get("reset_id").is_some());
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
    let event = build_destination_event(store, "", record)?;
    let fact_id = crate::json::get_str(&event, "fact_id")
        .unwrap_or_default()
        .to_owned();
    let event_id = crate::json::get_str(&event, "event_id")
        .unwrap_or_default()
        .to_owned();
    let parsed = FactEvent::from_value(&event).map_err(|error| {
        ContractError::integrity("DIGEST_MISMATCH", error, "Use the exact candidate bytes.")
    })?;
    let root = crate::store::ensure_store_root(store, repo)?;
    crate::store::write_content_addressed_event(&root, &parsed)?;
    Ok((fact_id, event_id))
}

/// Build and sign the destination event for an approved candidate. The
/// approving principal's local destination key signs it; the event carries
/// the candidate id as evidence and binds the certified repository identity
/// for Codebase.
fn build_destination_event(
    store: crate::StoreKind,
    repository_uuid: &str,
    record: &Value,
) -> Result<Value, ContractError> {
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
    let repository_id = (store == crate::StoreKind::Codebase && !repository_uuid.is_empty())
        .then(|| repository_uuid.to_owned());
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
    let event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id,
        store_kind: store_name(store).to_owned(),
        authority_id: authority_id.to_owned(),
        authority_scope: scope.to_owned(),
        repository_id,
        fact_id,
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
        signer: String::new(),
        signature: String::new(),
        raw: None,
    };
    let repo = repo()?;
    let (private_path, _) = crate::crypto::ensure_keypair(store, &repo)?;
    let key = crate::crypto::PrivateKey::load_or_generate(&private_path, "local destination key")?;
    key.sign_document("fact-event", &event.to_value())
}

/// Close overdue apology Unknowns with exactly one signed `orphan_abandoned`
/// terminal event each, emitted by the committed destination. The orphaned
/// claim stays withdrawn; the saga is closed, never left pending forever.
pub(crate) fn emit_due_orphan_abandonments(
    launcher: &crate::launcher::Launcher,
    repository_root: &Path,
) -> Result<usize, ContractError> {
    let existing: BTreeSet<String> = personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .filter_map(|record| crate::json::get_str(&record, "apology_id").map(str::to_owned))
        .collect();
    let now = crate::time::now_utc();
    let due: Vec<Value> = current_apologies()
        .into_iter()
        .filter(|apology| {
            crate::json::get_str(apology, "state") == Some("awaiting_reconcile_or_abandon")
        })
        .filter(|apology| {
            crate::json::get_str(apology, "response_due_at")
                .and_then(|value| parse_rfc3339_millis(value).ok())
                .is_some_and(|due| due <= now)
        })
        .filter(|apology| {
            crate::json::get_str(apology, "apology_id").is_some_and(|id| !existing.contains(id))
        })
        .collect();
    if due.is_empty() {
        return Ok(existing.len());
    }
    let repository = crate::codebase::Repository::discover(repository_root)?;
    let repository_uuid = crate::repository::repository_id(repository_root).ok();
    let _lock = match &repository_uuid {
        Some(uuid) => Some(repository.admission_lock(uuid)?),
        None => None,
    };
    let now_text = format_rfc3339_millis(now);
    for apology in due {
        let apology_id = crate::json::get_str(&apology, "apology_id")
            .unwrap_or_default()
            .to_owned();
        let committed_destination = crate::json::get_str(&apology, "committed_destination")
            .unwrap_or("codebase")
            .to_owned();
        let store = destination_store(&committed_destination).unwrap_or(crate::StoreKind::Codebase);
        let closing_authority = crate::json::get_str(&apology, "closing_authority")
            .or_else(|| crate::json::get_str(&apology, "closing_authority_role"))
            .unwrap_or("repository-maintainer")
            .to_owned();
        let closing_role = crate::json::get_str(&apology, "closing_authority_role")
            .unwrap_or("repository-maintainer")
            .to_owned();
        let due_at = crate::json::get_str(&apology, "response_due_at")
            .unwrap_or_default()
            .to_owned();
        let orphaned_event_id = crate::json::get_str(&apology, "orphaned_event_id")
            .unwrap_or_default()
            .to_owned();
        let logical_key = crate::json::get_str(&apology, "orphaned_logical_key")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("logical_{:x}", Sha256::digest(apology_id.as_bytes())));
        let fact_id = crate::json::get_str(&apology, "orphaned_fact_id")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("fact_{:x}", Sha256::digest(apology_id.as_bytes())));
        let event_id = format!(
            "event_{:x}",
            Sha256::digest(format!("orphan_abandoned\0{apology_id}").as_bytes())
        );
        let statement = format!(
            "orphan_abandoned: closing authority {closing_authority} ({closing_role}) did not reconcile or abandon apology {apology_id} by {due_at}; the orphaned claim stays withdrawn and the saga is closed"
        );
        let mut document = json!({
            "schema": crate::model::EVENT_SCHEMA,
            "event_id": event_id,
            "store_kind": store_name(store),
            "authority_id": closing_role,
            "authority_scope": "architecture:escalation",
            "fact_id": fact_id,
            "logical_key": logical_key,
            "atom_kind": "observation",
            "scope": "architecture:escalation",
            "statement": statement,
            "evidence_refs": [apology_id.clone(), crate::json::get_str(&apology, "unknown_id").unwrap_or_default()],
            "asserted_at": now_text,
            "effective_from": now_text,
            "disposition": "orphan_abandoned",
            "distortion": {
                "trigger": "closing authority response_due_at passed",
                "loss_if_absent": 8000,
                "rationale": "an unanswered apology must be closed exactly once and the fact withheld"
            },
            "parents": if orphaned_event_id.is_empty() { json!([]) } else { json!([orphaned_event_id]) },
            "supersedes": [],
            "redundancy_with": [],
            "complements": [],
            "company_refs": [],
            "authority_snapshot_cursor": "0",
            "confidence": 8000,
            "unresolved_uncertainty": "orphan abandoned without closing-authority action",
            "unresponsive_closing_authority": closing_authority,
            "apology_id": apology_id,
            "response_due_at": due_at,
            "fact_state": "withdrawn"
        });
        if let (crate::StoreKind::Codebase, Some(uuid)) = (store, &repository_uuid) {
            document["repository_id"] = Value::String(uuid.clone());
        }
        let (private_path, _) = crate::crypto::ensure_keypair(store, repository_root)?;
        let key =
            crate::crypto::PrivateKey::load_or_generate(&private_path, "local destination key")?;
        let signed = key.sign_document("fact-event", &document)?;
        let parsed = FactEvent::from_value(&signed).map_err(|error| {
            ContractError::integrity(
                "DIGEST_MISMATCH",
                error,
                "Preserve the saga record; the terminal event is malformed.",
            )
        })?;
        let root = crate::store::ensure_store_root(store, repository_root)?;
        let (_, digest) = crate::store::write_content_addressed_event(&root, &parsed)?;
        if store == crate::StoreKind::Codebase {
            repository.update_index_cache()?;
        }
        append_personal(
            "orphan-abandonments.jsonl",
            &json!({
                "orphan_id": format!("orphan_{}", &crate::hash::sha256_text(&apology_id)[..40]),
                "apology_id": apology_id,
                "event_id": crate::json::get_str(&signed, "event_id").unwrap_or_default(),
                "event_digest": digest,
                "destination": committed_destination,
                "unresponsive_closing_authority": closing_authority,
                "closing_authority_role": closing_role,
                "orphaned_event_id": orphaned_event_id,
                "fact_state": "withdrawn",
                "orphaned_fact_withheld": true,
                "emitted_at": now_text
            }),
        )?;
        append_personal(
            "apologies.jsonl",
            &json!({"apology_id": apology_id, "state": "abandoned", "abandoned_at": now_text, "orphan_abandoned_event_id": crate::json::get_str(&signed, "event_id").unwrap_or_default()}),
        )?;
        if let Ok(Some((cache, _))) = launcher.company_cache() {
            let mut closed = apology.clone();
            closed["state"] = Value::String("abandoned".to_owned());
            let _ = cache.save_saga(
                crate::json::get_str(&apology, "candidate_id").unwrap_or_default(),
                &closed,
                &now_text,
            );
        }
    }
    Ok(personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .filter_map(|record| crate::json::get_str(&record, "apology_id").map(str::to_owned))
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
            json!({"candidate_id": "c-company", "decision": "approve", "state": "refused"}),
            json!({"candidate_id": "c-code", "decision": "approve", "state": "committed"}),
        ];
        assert_eq!(fanout_state(&candidates, &decisions, "company:"), "refused");
        assert_eq!(
            fanout_state(&candidates, &decisions, "codebase:"),
            "committed"
        );
        // An undecided sibling candidate is not a transaction and does not
        // demote a committed destination to pending.
        let with_undecided = vec![
            json!({"candidate_id": "c-code", "destination": "codebase:1234"}),
            json!({"candidate_id": "c-code-2", "destination": "codebase:1234"}),
        ];
        assert_eq!(
            fanout_state(&with_undecided, &decisions, "codebase:"),
            "committed"
        );
        assert_eq!(fanout_state(&with_undecided, &[], "codebase:"), "pending");
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
