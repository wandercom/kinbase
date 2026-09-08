use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::canonical_text;
use crate::model::Observation;
use crate::time::{format_rfc3339_millis, now_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use uuid::Uuid;

const SESSION_OBSERVATION_LIMIT: usize = 10_000;
const SESSION_OBSERVATION_KEYS: [&str; 5] = ["id", "role", "text", "observed_at", "source_kind"];

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

/// Record the privacy-minimized observation identity of a host prompt. The
/// body itself is not copied into the observation record; only its digest is
/// retained for reset authorization.
pub fn record_hook_observation(
    host: &str,
    map: &Map<String, Value>,
) -> Result<Option<String>, ContractError> {
    let Some(event_id) = map.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let Some(prompt) = map
        .get("prompt")
        .or_else(|| map.get("text"))
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(None);
    };
    let repo = std::env::current_dir().map_err(io_error)?;
    let digest = sha256_bytes(prompt.as_bytes());
    let observed_at = map
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| crate::time::parse_rfc3339_millis(value).ok())
        .map(crate::time::format_rfc3339_millis)
        .unwrap_or_else(now_rfc3339_millis);
    let observation = Observation {
        observation_id: format!("obs_{:x}", Sha256::digest(format!("hook\0{event_id}\0{digest}").as_bytes())),
        source_kind: if host == "claude" { "claude_jsonl" } else { "codex_jsonl" }.to_owned(),
        source_identity: "hook:UserPromptSubmit".to_owned(),
        native_id: event_id.to_owned(),
        content_digest: digest.clone(),
        repository_id: crate::repository::repository_id(&repo).ok(),
        revision: None,
        branch: None,
        disposition: "current".to_owned(),
        observed_at,
        asserted_at: None,
        effective_from: None,
        effective_until: None,
        body_ref: format!("sha256:{digest}"),
        extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
        origin_trust: None,
        environment_id: None,
        owner_id: None,
        lifecycle: "observed".to_owned(),
    };
    let value = serde_json::to_value(&observation)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    append_personal("observations.jsonl", &value)?;
    Ok(Some(event_id.to_owned()))
}

pub fn observe(
    classifier: Option<&crate::config::SharedClassifier>,
    session: &str,
    event: &Path,
    json: bool,
) -> Result<(), ContractError> {
    let sessions = personal_records("sessions.jsonl");
    sessions
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
    let bytes = std::fs::read(event).map_err(io_error)?;
    let records = parse_session_corpus(&bytes)?;
    if records.len() > SESSION_OBSERVATION_LIMIT {
        return Err(ContractError::limit(
            format!("session observation batch exceeds the {}-line bound", SESSION_OBSERVATION_LIMIT),
            json!({
                "omitted_count": records.len(),
                "line_limit": SESSION_OBSERVATION_LIMIT
            }),
        ));
    }

    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_id = crate::repository::repository_id(&repo).ok();
    let mut observations = Vec::new();
    for record in &records {
        let event_id = record["id"].as_str().unwrap_or_default().to_owned();
        let text = record["text"].as_str().unwrap_or_default().to_owned();
        let observed_at = record["observed_at"].as_str().unwrap_or_default().to_owned();
        let digest = sha256_bytes(text.as_bytes());
        let observation_id = format!(
            "obs_{:x}",
            Sha256::digest(format!("{session}\0{event_id}\0{digest}").as_bytes())
        );
        let observation = Observation {
            observation_id: observation_id.clone(),
            source_kind: "codex_jsonl".to_owned(),
            source_identity: format!("session:{session}"),
            native_id: event_id.clone(),
            content_digest: digest.clone(),
            repository_id: repository_id.clone(),
            revision: None,
            branch: None,
            disposition: "current".to_owned(),
            observed_at: observed_at.clone(),
            asserted_at: None,
            effective_from: None,
            effective_until: None,
            body_ref: format!("sha256:{digest}"),
            extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
            origin_trust: None,
            environment_id: None,
            owner_id: None,
            lifecycle: "observed".to_owned(),
        };
        observations.push((
            observation,
            json!({
                "session_id": session,
                "event_id": event_id,
                "event_type": "observation",
                "observed_at": observed_at,
                "text_digest": digest
            }),
        ));
    }

    let classifier_input = json!({
        "observations": observations
            .iter()
            .map(|(observation, event)| {
                let native_id = event.get("event_id").and_then(Value::as_str).unwrap_or_default();
                json!({
                    "observation_id": observation.observation_id,
                    "source_kind": observation.source_kind,
                    "source_identity": observation.source_identity,
                    "content_digest": observation.content_digest,
                    "observed_at": observation.observed_at,
                    "disposition": observation.disposition,
                    "extraction_version": observation.extraction_version,
                    "body": session_corpus_text(&records, native_id),
                    "scope": "host-session",
                    "confidence": 8_000
                })
            })
            .collect::<Vec<_>>()
    });
    let external_atoms = pinned_classifier_atoms(classifier, &classifier_input)?;

    let mut atom_records = Vec::new();
    let mut candidate_records = Vec::new();
    for (observation, event) in &observations {
        let native_id = event.get("event_id").and_then(Value::as_str).unwrap_or_default();
        let text = session_corpus_text(&records, native_id);
        let mut atoms = Vec::new();
        if let Some(external) = external_atoms.get(&observation.observation_id) {
            for item in external {
                atoms.push(atom_from_classifier(
                    item,
                    native_id,
                    &observation.observation_id,
                    &observation.content_digest,
                    repository_id.as_deref(),
                )?);
            }
        }
        if atoms.is_empty() && classifier.is_none() {
            atoms.push(crate::classify::atomize(
                "codex_jsonl",
                native_id,
                &text,
                "host-session",
                8_000,
                &observation.observation_id,
                &observation.content_digest,
                repository_id.as_deref(),
            ));
        }
        for atom in atoms {
            let suppressed = atom.hard_blocked;
            let destinations: Vec<String> = if suppressed {
                Vec::new()
            } else {
                atom.eligible_destinations
                    .iter()
                    .filter(|destination| destination.as_str() != "personal" && destination.as_str() != "none")
                    .cloned()
                    .collect()
            };
            let destinations = if suppressed && destinations.is_empty() {
                vec![repository_id
                    .as_ref()
                    .map(|id| format!("codebase:{id}"))
                    .unwrap_or_else(|| "company:root".to_owned())]
            } else {
                destinations
            };
            for destination in destinations {
                let destination = if destination == "company" { "company:root".to_owned() } else { destination };
                candidate_records.push(build_candidate(
                    session,
                    &destination,
                    &atom,
                    native_id,
                    crate::proposals::prompt_budget_allows(),
                )?);
            }
            atom_records.push(
                serde_json::to_value(&atom)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
    }

    for (_, event) in &observations {
        append_personal("session-events.jsonl", event)?;
    }
    for (observation, _) in &observations {
        let value = serde_json::to_value(observation)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        append_personal("observations.jsonl", &value)?;
    }
    for atom in &atom_records {
        append_personal("atoms.jsonl", atom)?;
    }
    for candidate in &candidate_records {
        append_personal("candidates.jsonl", candidate)?;
    }

    let result = json!({
        "session_id": session,
        "status": "observed",
        "observation_count": observations.len(),
        "atom_count": atom_records.len(),
        "candidate_count": candidate_records.len(),
        "classifier": {"fingerprint": classifier_fingerprint(classifier)}
    });
    print_value(&result, json);
    Ok(())
}

fn parse_session_corpus(bytes: &[u8]) -> Result<Vec<Map<String, Value>>, ContractError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| host_error(format!("corpus is not valid UTF-8: {}", error.valid_up_to())))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = crate::json::parse_strict_value(line.as_bytes())
            .map_err(|error| host_error(format!("line {}: {error}", index + 1)))?;
        let map = value
            .as_object()
            .cloned()
            .ok_or_else(|| host_error(format!("line {} is not a JSON object", index + 1)))?;
        for key in map.keys() {
            if !SESSION_OBSERVATION_KEYS.contains(&key.as_str()) {
                return Err(host_error(format!("line {} has unknown key `{key}`", index + 1)));
            }
        }
        for key in SESSION_OBSERVATION_KEYS {
            if !map.get(key).is_some_and(Value::is_string) {
                return Err(host_error(format!("line {} field `{key}` must be a string", index + 1)));
            }
        }
        let id = map["id"].as_str().unwrap_or_default();
        if id.is_empty() {
            return Err(host_error(format!("line {} id must be nonempty", index + 1)));
        }
        if !matches!(map["role"].as_str(), Some("user" | "assistant")) {
            return Err(host_error(format!("line {} role must be user or assistant", index + 1)));
        }
        if map["source_kind"].as_str() != Some("codex_jsonl") {
            return Err(host_error(format!("line {} source_kind must be codex_jsonl", index + 1)));
        }
        let observed_at = map["observed_at"].as_str().unwrap_or_default();
        crate::time::parse_rfc3339_millis(observed_at)
            .map_err(|error| host_error(format!("line {} observed_at is invalid: {error}", index + 1)))?;
        records.push(map);
    }
    if records.is_empty() {
        return Err(host_error("session corpus contains no observation objects"));
    }
    Ok(records)
}

fn session_corpus_text(records: &[Map<String, Value>], native_id: &str) -> String {
    records
        .iter()
        .find(|record| record.get("id").and_then(Value::as_str) == Some(native_id))
        .and_then(|record| record.get("text").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

fn pinned_classifier_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    input: &Value,
) -> Result<BTreeMap<String, Vec<Value>>, ContractError> {
    let Some(classifier) = classifier else {
        return Ok(BTreeMap::new());
    };
    let bytes = crate::sandbox::run_verified_executable(
        &classifier.executable,
        &classifier.executable_sha256,
        &classifier.args,
        &crate::json::canonical_bytes(input),
        std::time::Duration::from_secs(classifier.timeout_seconds),
    )?;
    let output = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            format!("classifier output is not strict JSON: {error}"),
            "Repair the pinned classifier; no output was promoted.",
        )
    })?;
    crate::classifier::validate_output(&output)?;
    let mut result: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if let Some(atoms) = output.get("atoms").and_then(Value::as_array) {
        for atom in atoms {
            let observation_id = atom
                .get("observation_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ContractError::integrity(
                        "PROCESSOR_UNAUTHORIZED",
                        "classifier atom has no observation_id",
                        "Repair the pinned classifier; no output was promoted.",
                    )
                })?
                .to_owned();
            result.entry(observation_id).or_default().push(atom.clone());
        }
    }
    Ok(result)
}

fn atom_from_classifier(
    external: &Value,
    native_id: &str,
    observation_id: &str,
    content_digest: &str,
    repository_id: Option<&str>,
) -> Result<crate::model::Atom, ContractError> {
    let text = external
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier atom has no text", "Repair the pinned classifier; no output was promoted."))?;
    let scope = external.get("scope").and_then(Value::as_str).unwrap_or("host-session");
    let confidence = match external.get("confidence").and_then(Value::as_str) {
        Some("high") => 8_000,
        Some("medium") => 6_000,
        _ => 3_000,
    };
    let mut atom = crate::classify::atomize(
        "codex_jsonl",
        native_id,
        text,
        scope,
        confidence,
        observation_id,
        content_digest,
        repository_id,
    );
    if let Some(value) = external.get("atom_id").and_then(Value::as_str) {
        atom.atom_id = value.to_owned();
    }
    if let Some(value) = external.get("atom_kind").and_then(Value::as_str) {
        atom.atom_kind = value.to_owned();
    }
    if let Some(values) = external.get("proposed_destinations").and_then(Value::as_array) {
        let destinations = values
            .iter()
            .filter_map(Value::as_str)
            .map(|value| match value {
                "codebase" => repository_id.map(|id| format!("codebase:{id}")).unwrap_or_else(|| "codebase".to_owned()),
                other => other.to_owned(),
            })
            .collect::<Vec<_>>();
        atom.proposed_destinations = destinations.clone();
        atom.eligible_destinations = destinations;
    }
    if let Some(values) = external.get("taint").and_then(Value::as_array) {
        atom.taints = values.iter().filter_map(Value::as_str).map(str::to_owned).collect();
    }
    if let Some(value) = external.get("unresolved_uncertainty").and_then(Value::as_str) {
        atom.unresolved_uncertainty = (!value.is_empty()).then(|| value.to_owned());
    }
    Ok(atom)
}

fn classifier_fingerprint(classifier: Option<&crate::config::SharedClassifier>) -> String {
    match classifier {
        Some(classifier) => format!(
            "sha256:{}:{}",
            classifier.executable_sha256,
            if classifier.model.starts_with("ollama:") { "ollama" } else { "deterministic" }
        ),
        None => {
            let executable = std::env::current_exe().unwrap_or_else(|_| "guildhall".into());
            let digest = std::fs::read(&executable)
                .map(|bytes| sha256_bytes(&bytes))
                .unwrap_or_default();
            format!("sha256:{digest}:deterministic")
        }
    }
}

fn host_error(message: impl Into<String>) -> ContractError {
    ContractError::degraded(
        "UNSUPPORTED_HOST_VERSION",
        message,
        "Use a JSONL corpus of objects with exactly id, role, text, observed_at, and source_kind.",
    )
}

fn build_candidate(
    session: &str,
    destination: &str,
    atom: &crate::model::Atom,
    message_id: &str,
    rendered: bool,
) -> Result<Value, ContractError> {
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
        "message_id": message_id,
        "destination": destination,
        "canonical": canonical,
        "payload_digest": payload_digest,
        "principal": std::env::var("GUILDHALL_PRINCIPAL").unwrap_or_else(|_| "local-user".to_owned()),
        "host_instance_id": std::env::var("GUILDHALL_HOST_INSTANCE").unwrap_or_else(|_| "local-host".to_owned()),
        "source_revision": crate::repository::git_revision(&repo).unwrap_or_default(),
        "created_at": now_rfc3339_millis(),
        "expires_at": format_rfc3339_millis(Utc::now() + Duration::seconds(900)),
        "nonce": Uuid::new_v4().to_string(),
        "rendered": rendered && !atom.hard_blocked,
        "suppressed": atom.hard_blocked,
        "taint_cleared": !atom.hard_blocked,
        "hard_block_respected": true
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
    Ok(record)
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
    crate::store::append_record(crate::StoreKind::Personal, &repo, name, value)
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
