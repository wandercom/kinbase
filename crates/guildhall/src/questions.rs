use crate::error::{ContractError, ExitCode};
use crate::json::{canonical_bytes, canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, UnknownEvent};
use crate::scanner::hard_blocked;
use crate::time::{format_rfc3339_millis, now_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

pub fn dispatch(
    command: crate::command_types::QuestionCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::QuestionCommand::List { owner } => list(owner.as_deref(), json),
        crate::command_types::QuestionCommand::Ask { question_id } => ask(&question_id, json),
        crate::command_types::QuestionCommand::Answer {
            question_id,
            answer_file,
            key_file,
        } => answer(&question_id, &answer_file, &key_file, json),
        crate::command_types::QuestionCommand::Status { question_id } => status(&question_id, json),
    }
}

fn repo() -> Result<std::path::PathBuf, ContractError> {
    std::env::current_dir().map_err(io_error)
}

fn company_records(name: &str) -> Vec<Value> {
    repo()
        .ok()
        .and_then(|repo| crate::store::read_records(crate::StoreKind::Company, &repo, name).ok())
        .unwrap_or_default()
}

fn append_company(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = repo()?;
    crate::store::append_record(crate::StoreKind::Company, &repo, name, value).map_err(io_error)
}

fn list(owner: Option<&str>, json: bool) -> Result<(), ContractError> {
    let questions: Vec<Value> = company_records("questions.jsonl")
        .into_iter()
        .filter(|record| {
            owner
                .map(|owner| record.get("authority_id").and_then(Value::as_str) == Some(owner))
                .unwrap_or(true)
        })
        .collect();
    if json {
        println!("{}", canonical_text(&Value::Array(questions)));
    } else {
        println!("question_count: {}", questions.len());
    }
    Ok(())
}

fn find_unknown(question_id: &str) -> Result<Value, ContractError> {
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        if let Ok(record) = company_or_store_unknown(store, question_id) {
            return Ok(record);
        }
    }
    Err(ContractError::new(
        "CONFIG_INVARIANT",
        "Unknown not found",
        "Create the Unknown from a blocked decision before asking authority.",
        false,
        ExitCode::Refused,
    ))
}

fn company_or_store_unknown(store: crate::StoreKind, unknown_id: &str) -> Result<Value, ContractError> {
    let repo = repo()?;
    let records = crate::store::read_records(store, &repo, "unknowns.jsonl").map_err(io_error)?;
    records
        .into_iter()
        .rev()
        .find(|record| record.get("unknown_id").and_then(Value::as_str) == Some(unknown_id))
        .ok_or_else(|| ContractError::new("CONFIG_INVARIANT", "Unknown not found", "Use an existing Unknown ID.", false, ExitCode::Refused))
}

fn scope_kind(scope: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "architecture"
    } else if scope.starts_with("environment:") {
        "environment"
    } else {
        "general"
    }
}

fn active_authority(scope: &str, question_kind: &str) -> Result<Value, ContractError> {
    let entries: Vec<Value> = company_records("authority-registry.jsonl")
        .into_iter()
        .filter(|entry| {
            entry.get("status").and_then(Value::as_str) == Some("active")
                && entry.get("scope").and_then(Value::as_str) == Some(scope)
                && entry.get("question_kind").and_then(Value::as_str) == Some(question_kind)
        })
        .collect();
    if entries.len() > 1 {
        return Err(ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "multiple active authorities overlap the exact scope",
            "The Company steward must repair the registry before guidance is trusted.",
            true,
            ExitCode::DegradedSafe,
        ));
    }
    let entry = entries.into_iter().next().ok_or_else(|| {
        ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "no exact in-scope authority is registered",
            "The Company steward must repair the registry before guidance is trusted.",
            true,
            ExitCode::DegradedSafe,
        )
    })?;
    verify_registry_entry(&entry)?;
    Ok(entry)
}

fn verify_registry_entry(entry: &Value) -> Result<(), ContractError> {
    let signature = entry
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::new("SIGNATURE_INVALID", "authority registry entry lacks signature", "Ask the Company steward to publish a signed registry entry.", false, ExitCode::IntegrityFailure))?;
    let mut unsigned = entry.clone();
    if let Value::Object(map) = &mut unsigned {
        map.remove("signature");
    }
    let repo = repo()?;
    let (_, public_key) = crate::crypto::ensure_keypair(crate::StoreKind::Company, &repo)?;
    if !crate::crypto::verify_message(
        "authority-registry-entry",
        canonical_bytes(&unsigned).as_slice(),
        signature,
        &public_key,
    )? {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            "authority registry signature failed",
            "Quarantine the registry entry and contact the Company steward.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    if entry.get("public_key").and_then(Value::as_str).unwrap_or_default().is_empty() {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "authority public key missing",
            "Publish a base64 Ed25519 public key in the signed registry entry.",
            false,
            ExitCode::Refused,
        ));
    }
    Ok(())
}

fn ask(question_id: &str, json: bool) -> Result<(), ContractError> {
    let unknown = find_unknown(question_id)?;
    let scope = unknown.get("scope").and_then(Value::as_str).unwrap_or_default().to_owned();
    let question_kind = scope_kind(&scope).to_owned();
    let authority = active_authority(&scope, &question_kind)?;
    let authority_id = authority
        .get("authority_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if company_records("questions.jsonl").into_iter().any(|question| {
        question.get("unknown_id").and_then(Value::as_str) == Some(question_id)
    }) {
        let result = json!({"unknown_id": question_id, "status": "already-queued", "authority_id": authority_id});
        print_value(&result, json);
        return Ok(());
    }
    let question_text = unknown
        .get("question")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let question = json!({
        "schema": "guildhall-question/1",
        "question_id": format!("question_{}", Uuid::new_v4()),
        "unknown_id": question_id,
        "authority_id": authority_id,
        "scope": scope,
        "question_kind": question_kind,
        "question": question_text,
        "decision_blocked": unknown.get("decision_blocked").cloned().unwrap_or(Value::Null),
        "status": "queued",
        "created_at": now_rfc3339_millis(),
        "response_due_at": format_rfc3339_millis(Utc::now() + Duration::hours(24)),
        "expiry_policy": "block-dependent-decision"
    });
    append_company("questions.jsonl", &question)?;
    print_value(&question, json);
    Ok(())
}

fn answer(
    question_id: &str,
    answer_file: &Path,
    key_file: &Path,
    json: bool,
) -> Result<(), ContractError> {
    let answer_bytes = std::fs::read(answer_file).map_err(io_error)?;
    let map: Map<String, Value> = parse_strict_object(&answer_bytes)
        .map_err(|error| ContractError::new("CONFIG_INVARIANT", error, "Use a canonical signed answer object.", false, ExitCode::Refused))?;
    let question = company_records("questions.jsonl")
        .into_iter()
        .find(|record| {
            record.get("question_id").and_then(Value::as_str) == Some(question_id)
                || record.get("unknown_id").and_then(Value::as_str) == Some(question_id)
        })
        .ok_or_else(|| ContractError::new("CONFIG_INVARIANT", "question not found", "Ask the Unknown before answering it.", false, ExitCode::Refused))?;
    let scope = question.get("scope").and_then(Value::as_str).unwrap_or_default();
    let authority_id = question.get("authority_id").and_then(Value::as_str).unwrap_or_default();
    let supplied_authority = map.get("authority_id").and_then(Value::as_str).unwrap_or_default();
    if supplied_authority != authority_id {
        return Err(ContractError::new(
            "AUTHORITY_WRONG_SCOPE",
            "answer signer does not own the exact question scope",
            "Route the answer through the registered in-scope authority.",
            false,
            ExitCode::Refused,
        ));
    }
    let authority = active_authority(scope, question.get("question_kind").and_then(Value::as_str).unwrap_or("general"))?;
    if authority.get("authority_id").and_then(Value::as_str) != Some(authority_id) {
        return Err(ContractError::new(
            "AUTHORITY_WRONG_SCOPE",
            "registered authority changed for the exact scope",
            "Close the old question through the Company steward before admitting this answer.",
            false,
            ExitCode::Refused,
        ));
    }
    let answer_text = map
        .get("answer")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::new("CONFIG_INVARIANT", "answer text missing", "Use a canonical answer object.", false, ExitCode::Refused))?;
    if hard_blocked(answer_text) {
        return Err(ContractError::new(
            "PERSONAL_TAINT_BLOCKED",
            "hard-blocking material reached Company admission",
            "Keep the source private and provide a safe minimized answer.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let signature = crate::crypto::sign_message("answer", &answer_bytes, key_file)?;
    let public_key_text = authority
        .get("public_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key_text,
    )
    .map_err(|error| ContractError::new("SIGNATURE_INVALID", error.to_string(), "Use a valid registered public key.", false, ExitCode::IntegrityFailure))?;
    let public_path = repo()?.join(".guildhall-authority.pub");
    std::fs::write(&public_path, decoded).map_err(io_error)?;
    if !crate::crypto::verify_message("answer", &answer_bytes, &signature, &public_path)? {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            "authority answer signature failed",
            "Quarantine the answer and contact the named authority.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let answer_id = format!(
        "answer_{:x}",
        Sha256::digest(format!("{question_id}\0{answer_text}").as_bytes())
    );
    let answer_record = json!({
        "schema": "guildhall-answer/1",
        "answer_id": answer_id,
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "unknown_id": question.get("unknown_id").cloned().unwrap_or(Value::Null),
        "authority_id": authority_id,
        "scope": scope,
        "answer": answer_text,
        "signature": signature,
        "answered_at": now_rfc3339_millis()
    });
    append_company("answers.jsonl", &answer_record)?;
    let (fact_id, event_id) = write_authority_fact(&question, &answer_text, &answer_id, authority_id, scope)?;
    close_unknown(&question, &answer_id)?;
    let result = json!({
        "status": "answered",
        "answer_id": answer_id,
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "unknown_id": question.get("unknown_id").cloned().unwrap_or(Value::Null),
        "fact_id": fact_id,
        "event_id": event_id
    });
    print_value(&result, json);
    Ok(())
}

fn write_authority_fact(
    question: &Value,
    answer_text: &str,
    answer_id: &str,
    authority_id: &str,
    scope: &str,
) -> Result<(String, String), ContractError> {
    let repo = repo()?;
    let fact_id = format!(
        "fact_{:x}",
        Sha256::digest(format!("{scope}\0{answer_text}").as_bytes())
    );
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(format!("{scope}\0{answer_text}\0{answer_id}").as_bytes())
    );
    let now = now_rfc3339_millis();
    let mut event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id: event_id.clone(),
        store_kind: "company".to_owned(),
        authority_id: authority_id.to_owned(),
        authority_scope: scope.to_owned(),
        repository_id: None,
        fact_id: fact_id.clone(),
        logical_key: format!("logical_{:x}", Sha256::digest(scope.as_bytes())),
        atom_kind: "decision".to_owned(),
        scope: scope.to_owned(),
        statement: answer_text.to_owned(),
        evidence_refs: vec![
            question.get("question_id").and_then(Value::as_str).unwrap_or_default().to_owned(),
            answer_id.to_owned(),
        ],
        asserted_at: now.clone(),
        effective_from: now,
        effective_until: None,
        disposition: "current".to_owned(),
        distortion: Distortion {
            trigger: "authority answer".to_owned(),
            loss_if_absent: 9_000,
            rationale: "the registered authority resolved a blocking Unknown".to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: 9_800,
        unresolved_uncertainty: None,
        signer: authority_id.to_owned(),
        signature: String::new(),
    };
    let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, &repo)?;
    let unsigned = crate::store::event_canonical_text(&event);
    event.signature = crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
    let root = crate::store::ensure_store_root(crate::StoreKind::Company, &repo).map_err(io_error)?;
    crate::store::write_content_addressed_event(&root, &event).map_err(io_error)?;
    Ok((fact_id, event_id))
}

fn close_unknown(question: &Value, answer_id: &str) -> Result<(), ContractError> {
    let unknown_id = question
        .get("unknown_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let prior = find_unknown(unknown_id)?;
    let owner_role = prior.get("owner_role").and_then(Value::as_str).unwrap_or("company-steward");
    let scope = prior.get("scope").and_then(Value::as_str).unwrap_or("architecture:company");
    let mut unknown = UnknownEvent {
        schema: crate::model::UNKNOWN_SCHEMA.to_owned(),
        unknown_id: unknown_id.to_owned(),
        store_kind: prior.get("store_kind").and_then(Value::as_str).unwrap_or("company").to_owned(),
        scope: scope.to_owned(),
        decision_blocked: prior.get("decision_blocked").and_then(Value::as_str).unwrap_or("authority answer").to_owned(),
        owner_role: owner_role.to_owned(),
        owner_identity: prior.get("owner_identity").and_then(Value::as_str).unwrap_or(owner_role).to_owned(),
        question: prior.get("question").and_then(Value::as_str).unwrap_or_default().to_owned(),
        closure_evidence: vec![answer_id.to_owned()],
        status: "closed".to_owned(),
        response_due_at: prior.get("response_due_at").and_then(Value::as_str).unwrap_or_default().to_owned(),
        expiry_policy: prior.get("expiry_policy").and_then(Value::as_str).unwrap_or("block-dependent-decision").to_owned(),
        distortion: Distortion {
            trigger: "authority closure".to_owned(),
            loss_if_absent: 0,
            rationale: "the blocking Unknown was closed by a signed authority answer".to_owned(),
        },
        created_at: now_rfc3339_millis(),
        signer: owner_role.to_owned(),
        signature: String::new(),
    };
    let repo = repo()?;
    let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, &repo)?;
    let mut value = serde_json::to_value(&unknown)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    unknown.signature = crate::crypto::sign_message("unknown-event", canonical_text(&value).as_bytes(), &private_key)?;
    let record = serde_json::to_value(&unknown)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    let store_kind = unknown.store_kind.clone();
    let store = if store_kind == "codebase" {
        crate::StoreKind::Codebase
    } else {
        crate::StoreKind::Company
    };
    crate::store::append_record(store, &repo, "unknowns.jsonl", &record).map_err(io_error)?;
    Ok(())
}

fn status(question_id: &str, json: bool) -> Result<(), ContractError> {
    let question = company_records("questions.jsonl").into_iter().find(|record| {
        record.get("question_id").and_then(Value::as_str) == Some(question_id)
            || record.get("unknown_id").and_then(Value::as_str) == Some(question_id)
    });
    let answer = company_records("answers.jsonl").into_iter().find(|record| {
        record.get("question_id").and_then(Value::as_str) == Some(question_id)
            || record.get("unknown_id").and_then(Value::as_str) == Some(question_id)
    });
    let result = json!({
        "question_id": question_id,
        "question": question,
        "answer": answer,
        "status": if answer.is_some() { "answered" } else { "open" }
    });
    print_value(&result, json);
    Ok(())
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!("{}", canonical_text(value));
    } else {
        println!(
            "status: {}",
            value.get("status").and_then(Value::as_str).unwrap_or("recorded")
        );
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
