use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::canonical_text;
use crate::model::Observation;
use crate::scanner::hard_blocked;
use crate::time::{format_rfc3339_millis, now_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

pub fn start(repo: &Path, host: crate::HostKind, json: bool) -> Result<(), ContractError> {
    let session_id = format!("session_{}", Uuid::new_v4());
    let host_name = host_name(host);
    let repository_id = crate::repository::repository_id(repo).ok();
    let record = json!({
        "session_id": session_id,
        "host": host_name,
        "repository_id": repository_id,
        "started_at": now_rfc3339_millis(),
        "status": "started"
    });
    append_personal("sessions.jsonl", &record)?;
    let result = json!({
        "session_id": session_id,
        "host": host_name,
        "repository_id": repository_id,
        "status": "started"
    });
    print_value(&result, json);
    Ok(())
}

pub fn observe(session: &str, event: &Path, json: bool) -> Result<(), ContractError> {
    let sessions = personal_records("sessions.jsonl");
    let session_record = sessions
        .into_iter()
        .find(|record| record.get("session_id").and_then(Value::as_str) == Some(session))
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "session not found",
                "Start a session before observing events.",
                false,
                ExitCode::Refused,
            )
        })?;
    let host = session_record
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    let bytes = std::fs::read(event).map_err(io_error)?;
    let event_map: Map<String, Value> =
        crate::json::parse_strict_object(&bytes).map_err(|error| {
            ContractError::new(
                "UNSUPPORTED_HOST_VERSION",
                error,
                "Use a valid native host event.",
                false,
                ExitCode::DegradedSafe,
            )
        })?;
    let event_type = event_map
        .get("event_type")
        .or_else(|| event_map.get("type"))
        .or_else(|| event_map.get("hook_event_name"))
        .and_then(Value::as_str)
        .unwrap_or("observation")
        .to_owned();
    let event_id = event_map
        .get("event_id")
        .or_else(|| event_map.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("event_{}", Uuid::new_v4()));
    let statement = event_map
        .get("statement")
        .or_else(|| event_map.get("message"))
        .or_else(|| event_map.get("prompt"))
        .or_else(|| event_map.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let session_event = json!({
        "session_id": session,
        "event_id": event_id,
        "event_type": event_type,
        "observed_at": now_rfc3339_millis(),
        "event": Value::Object(event_map.clone())
    });
    append_personal("session-events.jsonl", &session_event)?;
    if statement.trim().is_empty() {
        let result = json!({"session_id": session, "event_id": event_id, "status": "observed", "atom_count": 0});
        print_value(&result, json);
        return Ok(());
    }
    let digest = sha256_bytes(statement.as_bytes());
    let source_kind = if host == "claude" {
        "claude_jsonl"
    } else {
        "codex_jsonl"
    };
    let observation_id = format!(
        "obs_{:x}",
        Sha256::digest(format!("{session}\0{event_id}\0{digest}").as_bytes())
    );
    let observation = Observation {
        observation_id: observation_id.clone(),
        source_kind: source_kind.to_owned(),
        source_identity: format!("session:{session}"),
        native_id: event_id.clone(),
        content_digest: digest.clone(),
        repository_id: None,
        revision: None,
        branch: None,
        disposition: "current".to_owned(),
        observed_at: now_rfc3339_millis(),
        asserted_at: None,
        effective_from: None,
        effective_until: None,
        body_ref: format!("sha256:{digest}"),
        extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
    };
    let observation_record = serde_json::to_value(&observation)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    append_personal("observations.jsonl", &observation_record)?;
    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_id = crate::repository::repository_id(&repo).ok();
    let atom = crate::classify::atomize(
        source_kind,
        &event_id,
        &statement,
        event_map
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("host-session"),
        event_map
            .get("confidence")
            .and_then(Value::as_u64)
            .unwrap_or(6_000)
            .min(10_000) as u16,
        &observation_id,
        &digest,
        repository_id.as_deref(),
    );
    let atom_record =
        serde_json::to_value(&atom).map_err(|error| ContractError::internal(error.to_string()))?;
    append_personal("atoms.jsonl", &atom_record)?;
    let destination = event_map.get("destination").and_then(Value::as_str);
    let mut candidate_id = Value::Null;
    let suppressed = hard_blocked(&statement);
    if let Some(destination) = destination {
        if suppressed {
            candidate_id = Value::String(String::new());
        } else {
            candidate_id = Value::String(create_candidate(session, destination, &atom)?);
        }
    }
    let result = json!({
        "session_id": session,
        "event_id": event_id,
        "status": "observed",
        "observation_id": observation_id,
        "atom_id": atom.atom_id,
        "candidate_id": candidate_id,
        "suppressed": suppressed
    });
    print_value(&result, json);
    Ok(())
}

fn create_candidate(
    session: &str,
    destination: &str,
    atom: &crate::model::Atom,
) -> Result<String, ContractError> {
    crate::proposals::destination_store(destination)?;
    let payload = json!({
        "atom_kind": atom.atom_kind,
        "scope": atom.scope,
        "statement": atom.statement
    });
    let canonical = canonical_text(&payload);
    let payload_digest = sha256_text(&canonical);
    let candidate_id = format!("cand_{}", Uuid::new_v4());
    let repo = std::env::current_dir().map_err(io_error)?;
    let mut record = json!({
        "candidate_id": candidate_id,
        "session_id": session,
        "destination": destination,
        "canonical": canonical,
        "payload_digest": payload_digest,
        "principal": std::env::var("GUILDHALL_PRINCIPAL").unwrap_or_else(|_| "local-user".to_owned()),
        "host_instance_id": std::env::var("GUILDHALL_HOST_INSTANCE").unwrap_or_else(|_| "local-host".to_owned()),
        "source_revision": crate::repository::git_revision(&repo).unwrap_or_default(),
        "created_at": now_rfc3339_millis(),
        "expires_at": format_rfc3339_millis(Utc::now() + Duration::seconds(900)),
        "nonce": Uuid::new_v4().to_string()
    });
    let token = json!({
        "candidate_id": record.get("candidate_id"),
        "destination": record.get("destination"),
        "payload_digest": record.get("payload_digest"),
        "nonce": record.get("nonce"),
        "principal": record.get("principal"),
        "session_id": record.get("session_id"),
        "expires_at": record.get("expires_at")
    });
    let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Personal, &repo)?;
    let signature = crate::crypto::sign_message(
        "approval-token",
        canonical_text(&token).as_bytes(),
        &private_key,
    )?;
    record["signature"] = Value::String(signature);
    append_personal("candidates.jsonl", &record)?;
    Ok(candidate_id)
}

pub fn checkpoint(session: &str, json: bool) -> Result<(), ContractError> {
    require_session(session)?;
    let record = json!({
        "session_id": session,
        "checkpoint_id": format!("checkpoint_{}", Uuid::new_v4()),
        "status": "checkpointed",
        "checkpointed_at": now_rfc3339_millis()
    });
    append_personal("session-checkpoints.jsonl", &record)?;
    print_value(&record, json);
    Ok(())
}

pub fn end(session: &str, json: bool) -> Result<(), ContractError> {
    require_session(session)?;
    let record = json!({
        "session_id": session,
        "status": "ended",
        "ended_at": now_rfc3339_millis()
    });
    append_personal("sessions.jsonl", &record)?;
    print_value(&record, json);
    Ok(())
}

fn require_session(session: &str) -> Result<(), ContractError> {
    if personal_records("sessions.jsonl")
        .into_iter()
        .any(|record| {
            record.get("session_id").and_then(Value::as_str) == Some(session)
                && record.get("status").and_then(Value::as_str) != Some("ended")
        })
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "CONFIG_INVARIANT",
            "session not active",
            "Start a session before lifecycle operations.",
            false,
            ExitCode::Refused,
        ))
    }
}

fn personal_records(name: &str) -> Vec<Value> {
    std::env::current_dir()
        .ok()
        .and_then(|repo| crate::store::read_records(crate::StoreKind::Personal, &repo, name).ok())
        .unwrap_or_default()
}

fn append_personal(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::append_record(crate::StoreKind::Personal, &repo, name, value).map_err(io_error)
}

fn host_name(host: crate::HostKind) -> &'static str {
    match host {
        crate::HostKind::Codex => "codex",
        crate::HostKind::Claude => "claude",
    }
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
                .unwrap_or("recorded")
        );
        if let Some(session) = value.get("session_id").and_then(Value::as_str) {
            println!("session: {session}");
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
