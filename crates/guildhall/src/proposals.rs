use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_text;
use crate::json::{canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, parse_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
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
            candidate,
            destination,
        } => show(&candidate, &destination, json),
        crate::command_types::ProposalCommand::Decide {
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
        crate::command_types::ProposalCommand::Reissue { candidate } => reissue(&candidate, json),
        crate::command_types::ProposalCommand::Reset {
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
        .and_then(|repo| {
            crate::store::read_records(crate::StoreKind::Personal, &repo, name).ok()
        })
        .unwrap_or_default()
}

fn append_personal(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = repo()?;
    crate::store::append_record(crate::StoreKind::Personal, &repo, name, value).map_err(io_error)
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
    let records: Vec<Value> = personal_records("candidates.jsonl")
        .into_iter()
        .filter(|record| record.get("session_id").and_then(Value::as_str) == Some(session))
        .map(|mut record| {
            record.as_object_mut().map(|map| {
                map.remove("canonical");
                map.remove("signature");
            });
            record
        })
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string(&Value::Array(records)).unwrap_or_default()
        );
    } else {
        println!("session: {session}");
        println!("candidate_count: {}", records.len());
    }
    Ok(())
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
    personal_records("proposal-decisions.jsonl").into_iter().find(|record| {
        record.get("candidate_id").and_then(Value::as_str) == Some(candidate)
    })
}

fn expired(record: &Value) -> Result<bool, ContractError> {
    let expires = record
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expires = parse_rfc3339_millis(expires)
        .map_err(|error| ContractError::new("CONFIG_INVARIANT", error, "Use a valid candidate expiry.", false, ExitCode::Refused))?;
    Ok(expires <= Utc::now())
}

fn reserve_prompt(record: &Value) -> Result<(), ContractError> {
    let candidate = record.get("candidate_id").and_then(Value::as_str).unwrap_or_default();
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
                    .is_some_and(|time| now.signed_duration_since(time).num_seconds() < PROMPT_WINDOW_SECONDS)
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

fn show(candidate: &str, destination: &str, json: bool) -> Result<(), ContractError> {
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
        let escaped = crate::json::escape_exact(canonical)
            .map_err(|error| ContractError::new("CONFIG_INVARIANT", error, "Use valid canonical candidate bytes.", false, ExitCode::Refused))?;
        println!("Candidate: {candidate}");
        println!("Destination: {destination}");
        println!("Canonical UTF-8 (exact): {escaped}");
        println!("SHA-256: {digest}");
        println!(
            "Expires at: {}",
            record.get("expires_at").and_then(Value::as_str).unwrap_or("unknown")
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
        let signature = record.get("signature").and_then(Value::as_str).unwrap_or_default();
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
        "receipt_id": format!("receipt_{}", Uuid::new_v4())
    });
    if decision == "approve" {
        let (fact_id, event_id) = write_fact_event(destination_store(destination)?, &repo()?, &record)?;
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
        .ok_or_else(|| ContractError::new("CONFIG_INVARIANT", "candidate created_at missing", "Create a new candidate.", false, ExitCode::Refused))?;
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
    let event_exists = personal_records("session-events.jsonl").into_iter().any(|event| {
        event.get("event_id").and_then(Value::as_str) == Some(after_primary_event)
            && event.get("event_type").and_then(Value::as_str) == Some("primary-task")
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
    if personal_records("proposal-resets.jsonl").into_iter().any(|reset| {
        reset
            .get("reset_at")
            .and_then(Value::as_str)
            .and_then(|time| parse_rfc3339_millis(time).ok())
            .is_some_and(|time| now.signed_duration_since(time).num_seconds() < PROMPT_WINDOW_SECONDS)
    }) {
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
    if destination == "company" {
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
    let map: Map<String, Value> = parse_strict_object(canonical.as_bytes())
        .map_err(|error| ContractError::new("DIGEST_MISMATCH", error, "Use the exact candidate bytes.", false, ExitCode::IntegrityFailure))?;
    let scope = map.get("scope").and_then(Value::as_str).unwrap_or("repository");
    let statement = map
        .get("statement")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::new("DIGEST_MISMATCH", "candidate lacks statement", "Create a valid candidate.", false, ExitCode::IntegrityFailure))?;
    let atom_kind = map.get("atom_kind").and_then(Value::as_str).unwrap_or("observation");
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo))
        .transpose()?;
    let fact_id = format!(
        "fact_{:x}",
        Sha256::digest(format!("{scope}\0{statement}").as_bytes())
    );
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(record.get("payload_digest").and_then(Value::as_str).unwrap_or_default().as_bytes())
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
        evidence_refs: vec![record
            .get("candidate_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()],
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
        confidence: 9_000,
        unresolved_uncertainty: None,
        signer: authority_id.to_owned(),
        signature: String::new(),
    };
    let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
    let unsigned = crate::store::event_canonical_text(&event);
    event.signature = crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    crate::store::write_content_addressed_event(&root, &event).map_err(io_error)?;
    Ok((fact_id, event_id))
}

fn create_unknown(store: crate::StoreKind, repo: &Path, record: &Value) -> Result<String, ContractError> {
    let unknown_id = format!(
        "unknown_{:x}",
        Sha256::digest(record.get("payload_digest").and_then(Value::as_str).unwrap_or_default().as_bytes())
    );
    let now = now_rfc3339_millis();
    let owner_role = if store == crate::StoreKind::Company {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let mut unknown = UnknownEvent {
        schema: crate::model::UNKNOWN_SCHEMA.to_owned(),
        unknown_id: unknown_id.clone(),
        store_kind: store_name(store).to_owned(),
        scope: "architecture:escalation".to_owned(),
        decision_blocked: record
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        owner_role: owner_role.to_owned(),
        owner_identity: owner_role.to_owned(),
        question: record
            .get("canonical")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        closure_evidence: Vec::new(),
        status: "open".to_owned(),
        response_due_at: format_rfc3339_millis(Utc::now() + Duration::hours(24)),
        expiry_policy: "block-dependent-decision".to_owned(),
        distortion: Distortion {
            trigger: "escalated candidate".to_owned(),
            loss_if_absent: 8_000,
            rationale: "the dependent decision remains blocked until authority closure".to_owned(),
        },
        created_at: now,
        signer: owner_role.to_owned(),
        signature: String::new(),
    };
    let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
    let mut value = serde_json::to_value(&unknown).map_err(|error| ContractError::internal(error.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let unsigned = canonical_text(&value);
    unknown.signature = crate::crypto::sign_message("unknown-event", unsigned.as_bytes(), &private_key)?;
    let record = serde_json::to_value(&unknown).map_err(|error| ContractError::internal(error.to_string()))?;
    crate::store::append_record(store, repo, "unknowns.jsonl", &record).map_err(io_error)?;
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
            value.get("status").or_else(|| value.get("decision")).and_then(Value::as_str).unwrap_or("recorded")
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
