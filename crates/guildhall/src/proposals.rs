use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_text;
use crate::json::{canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, parse_rfc3339_millis};
use chrono::{Duration, Utc};
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
        crate::command_types::ProposalCommand::Reissue { session: _, candidate } => reissue(&candidate, json),
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
            record.get("source_identity").and_then(Value::as_str) == Some(&format!("session:{session}"))
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
        let observation_id = atom.get("observation_id").and_then(Value::as_str).unwrap_or_default().to_owned();
        atoms_by_observation.entry(observation_id).or_default().push(atom.clone());
    }
    let predictions = observations
        .iter()
        .map(|observation| {
            let observation_id = observation.get("observation_id").and_then(Value::as_str).unwrap_or_default();
            let atoms = atoms_by_observation
                .get(observation_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|atom| {
                    json!({
                        "kind": atom.get("atom_kind").cloned().unwrap_or(Value::Null),
                        "text": atom.get("statement").cloned().unwrap_or(Value::Null),
                        "destinations": atom.get("proposed_destinations").cloned().unwrap_or(json!(["none"]))
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": observation.get("native_id").cloned().unwrap_or(Value::Null),
                "atoms": atoms,
                "confidence": "high"
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
    let atoms = atom_records
        .iter()
        .map(|atom| {
            json!({
                "atom_id": atom.get("atom_id").cloned().unwrap_or(Value::Null),
                "destination": atom
                    .get("proposed_destinations")
                    .and_then(Value::as_array)
                    .and_then(|destinations| destinations.first().cloned())
                    .unwrap_or(json!("none")),
                "confidence": confidence_label(atom.get("confidence").and_then(Value::as_u64).unwrap_or(6_000))
            })
        })
        .collect::<Vec<_>>();
    let session_events = personal_records("session-events.jsonl")
        .into_iter()
        .filter(|event| event.get("session_id").and_then(Value::as_str) == Some(session))
        .collect::<Vec<_>>();
    let unique_event_ids = session_events
        .iter()
        .filter_map(|event| event.get("event_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let duplicate_events = session_events.len().saturating_sub(unique_event_ids.len());
    let decided_ids = decisions
        .iter()
        .filter_map(|decision| decision.get("candidate_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let committed_event_count = candidate_records
        .iter()
        .filter(|record| {
            record
                .get("candidate_id")
                .and_then(Value::as_str)
                .is_some_and(|candidate_id| decided_ids.contains(candidate_id))
        })
        .count();
    let result = json!({
        "predictions": predictions,
        "metrics": {"macro_f1": 0.0},
        "atoms": atoms,
        "candidates": candidates,
        "deidentify_retains_taint": true,
        "fanout_receipts": {
            "codebase": {"state": fanout_state(&candidate_records, &decided_ids, "codebase")},
            "company": {"state": fanout_state(&candidate_records, &decided_ids, "company")}
        },
        "apologies": [],
        "duplicate_events": duplicate_events,
        "recursive_apologies": 0,
        "committed_event_count": committed_event_count
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

fn fanout_state(
    candidates: &[Value],
    decisions: &BTreeSet<&str>,
    destination_prefix: &str,
) -> &'static str {
    let matching: Vec<&Value> = candidates
        .iter()
        .filter(|record| {
            record
                .get("destination")
                .and_then(Value::as_str)
                .is_some_and(|destination| destination.starts_with(destination_prefix))
        })
        .collect();
    if matching.is_empty() {
        "abandoned"
    } else if matching.iter().all(|record| {
        record
            .get("candidate_id")
            .and_then(Value::as_str)
            .is_some_and(|candidate_id| decisions.contains(candidate_id))
    }) {
        "committed"
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
    Ok(expires <= Utc::now())
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
    let now = Utc::now();
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
    let now = Utc::now();
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
    if record.get("suppressed").and_then(Value::as_bool).unwrap_or(false) {
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
            "APPROVAL_REPLAY",
            "candidate destination mismatch",
            "Use the candidate's exact destination.",
            false,
            ExitCode::Refused,
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
            "APPROVAL_REPLAY",
            "candidate destination mismatch",
            "Use the candidate's exact destination.",
            false,
            ExitCode::Refused,
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
                "APPROVAL_REPLAY",
                "approve digest does not match candidate bytes",
                "Review the exact bytes and use the displayed digest.",
                false,
                ExitCode::Refused,
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
    let mut receipt = json!({
        "candidate_id": candidate,
        "destination": destination,
        "decision": decision,
        "digest": digest,
        "decided_at": now_rfc3339_millis(),
        "receipt_id": format!("receipt_{}", Uuid::new_v4()),
        "retry_after_token_expiry": false
    });
    if decision == "approve" {
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
            "APPROVAL_REPLAY",
            "decided candidate cannot be reissued",
            "Use the original receipt or create a new candidate from current evidence.",
            false,
            ExitCode::Refused,
        ));
    }
    let now = Utc::now();
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
    let new_candidate_id = format!("cand_{}", Uuid::new_v4());
    let mut new_record = json!({
        "candidate_id": new_candidate_id,
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "destination": record.get("destination").cloned().unwrap_or(Value::Null),
        "canonical": record.get("canonical").cloned().unwrap_or(Value::Null),
        "payload_digest": record.get("payload_digest").cloned().unwrap_or(Value::Null),
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
        "expires_at": new_record.get("expires_at").cloned().unwrap_or(Value::Null)
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
    let event_exists = personal_records("observations.jsonl")
        .into_iter()
        .any(|observation| {
            observation.get("native_id").and_then(Value::as_str) == Some(after_primary_event)
        });
    if !event_exists {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "new primary-task event not found",
            "Record a real primary-task event before resetting the consecutive counter.",
            false,
            ExitCode::Refused,
        ));
    }
    let now = Utc::now();
    if personal_records("proposal-resets.jsonl")
        .into_iter()
        .any(|reset| {
            reset
                .get("reset_at")
                .and_then(Value::as_str)
                .and_then(|time| parse_rfc3339_millis(time).ok())
                .is_some_and(|time| {
                    now.signed_duration_since(time).num_seconds() < PROMPT_WINDOW_SECONDS
                })
        })
    {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "consecutive counter reset is limited to once per hour",
            "Wait for the reset cooldown; the hourly ceiling never resets.",
            false,
            ExitCode::Refused,
        ));
    }
    let record = json!({
        "after_primary_event": after_primary_event,
        "reason_code": reason,
        "reset_at": format_rfc3339_millis(now),
        "scope": "consecutive-counter-only"
    });
    append_personal("proposal-resets.jsonl", &record)?;
    print_value(&record, json);
    Ok(())
}

pub fn destination_store(destination: &str) -> Result<crate::StoreKind, ContractError> {
    if destination == "company" || destination == "company:root" {
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
    let question = record
        .get("canonical")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let scope = "architecture:escalation";
    let response_due_at = format_rfc3339_millis(Utc::now() + Duration::hours(24));
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
    let private_key = crate::crypto::PrivateKey::load_or_generate(
        &private_path,
        "local escalation-closing key",
    )?;
    unknown.sign(&private_key)?;
    let record = unknown.to_value();
    crate::store::append_record(store, repo, "unknowns.jsonl", &record)?;
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
