use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::canonical_text;
use crate::model::Observation;
use crate::time::{format_rfc3339_millis, now_rfc3339_millis};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    let Some(event_id) = map
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
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
        observation_id: format!(
            "obs_{:x}",
            Sha256::digest(format!("hook\0{event_id}\0{digest}").as_bytes())
        ),
        source_kind: if host == "claude" {
            "claude_jsonl"
        } else {
            "codex_jsonl"
        }
        .to_owned(),
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
        origin_trust: Some("uncommitted-worktree".to_owned()),
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
    principal_id: &str,
    host_instance_id: &str,
    session: &str,
    event: &Path,
    json: bool,
) -> Result<(), ContractError> {
    ensure_session_record(session)?;
    let bytes = std::fs::read(event).map_err(io_error)?;
    let records = parse_session_corpus(&bytes)?;
    if records.len() > SESSION_OBSERVATION_LIMIT {
        return Err(ContractError::limit(
            format!(
                "session observation batch exceeds the {}-line bound",
                SESSION_OBSERVATION_LIMIT
            ),
            json!({
                "omitted_count": records.len(),
                "line_limit": SESSION_OBSERVATION_LIMIT
            }),
        ));
    }

    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_id = crate::repository::repository_id(&repo).ok();
    {
        // Prompt-budget resets are authorized by these host-instance events.
        // `INSERT OR IGNORE` keeps repeated observations idempotent.
        let mut core = crate::private::PrivateStore::open_core()?;
        let recorded_at = now_rfc3339_millis();
        for record in &records {
            let event_id = record.get("id").and_then(Value::as_str).unwrap_or_default();
            core.insert_session_event(
                session,
                event_id,
                "primary-task",
                &json!({
                    "session_id": session, "event_id": event_id, "event_type": "primary-task"
                }),
                &recorded_at,
            )?;
        }
    }
    let mut observations = Vec::new();
    for record in &records {
        let event_id = record["id"].as_str().unwrap_or_default().to_owned();
        let text = record["text"].as_str().unwrap_or_default().to_owned();
        let observed_at = record["observed_at"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
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
            origin_trust: Some("uncommitted-worktree".to_owned()),
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

    let classifier_observations = observations
        .iter()
        .map(|(observation, event)| {
            let native_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            json!({
                "observation_id": observation.observation_id,
                "source_kind": observation.source_kind,
                "source_identity": observation.source_identity,
                "content_digest": observation.content_digest,
                "observed_at": observation.observed_at,
                "disposition": observation.disposition,
                "extraction_version": observation.extraction_version,
                "body": crate::classifier::request_body(&session_corpus_text(&records, native_id)),
                "scope": "host-session",
                "confidence": 8_000
            })
        })
        .collect::<Vec<_>>();
    let mut external_atoms: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for batch in crate::classifier::request_batches(classifier_observations)? {
        let batch_atoms = pinned_classifier_atoms(classifier, &batch)?;
        for (observation_id, atoms) in batch_atoms {
            external_atoms
                .entry(observation_id)
                .or_default()
                .extend(atoms);
        }
    }

    let mut atom_records = Vec::new();
    let mut candidate_records = Vec::new();
    for (observation, event) in &observations {
        let native_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
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
        if atoms.is_empty() {
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
            // Hard-blocked material never has a shared candidate, including
            // a Personal candidate: the only reported destination is `none`.
            if atom.hard_blocked {
                atom_records.push(
                    serde_json::to_value(&atom)
                        .map_err(|error| ContractError::internal(error.to_string()))?,
                );
                continue;
            }
            let destinations = atom
                .eligible_destinations
                .iter()
                .filter(|destination| destination.as_str() != "none")
                .cloned()
                .collect::<Vec<_>>();
            for destination in destinations {
                let destination = if destination == "company" {
                    "company:root".to_owned()
                } else {
                    destination
                };
                let mut candidate =
                    build_candidate(session, &destination, &atom, native_id, false)?;
                let rendered =
                    reserve_candidate_prompt(&candidate, principal_id, host_instance_id)?;
                candidate["rendered"] = Value::Bool(rendered);
                candidate["suppressed"] = Value::Bool(!rendered);
                candidate_records.push(candidate);
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

/// A host session token is caller-supplied and opaque.  Record it as active
/// when it has not been seen before so Stop/SessionEnd can checkpoint it.
fn ensure_session_record(session: &str) -> Result<(), ContractError> {
    if personal_records("sessions.jsonl")
        .into_iter()
        .any(|record| {
            record.get("session_id").and_then(Value::as_str) == Some(session)
                && record.get("status").and_then(Value::as_str) != Some("ended")
        })
    {
        return Ok(());
    }
    let repo = std::env::current_dir().map_err(io_error)?;
    let record = json!({
        "session_id": session,
        "host": "codex",
        "repository_id": crate::repository::repository_id(&repo).ok(),
        "started_at": now_rfc3339_millis(),
        "status": "started",
        "caller_supplied": true
    });
    append_personal("sessions.jsonl", &record)
}

/// Reserve one display slot in the private Core shard.  A typed budget
/// refusal means this eligible candidate remains private and suppressed; it
/// is never an observation failure.
fn reserve_candidate_prompt(
    record: &Value,
    principal_id: &str,
    host_instance_id: &str,
) -> Result<bool, ContractError> {
    let candidate_id = record
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let destination = record
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let content_digest = record
        .get("payload_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_revision = record
        .get("source_revision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let principal = principal_id.to_owned();
    let host_instance = host_instance_id.to_owned();
    let now = now_rfc3339_millis();
    let mut core = crate::private::PrivateStore::open_core()?;
    match core.reserve_prompt_slot(
        &principal,
        &host_instance,
        destination,
        candidate_id,
        content_digest,
        source_revision,
        &now,
    ) {
        Ok(_) => {
            core.mark_reservation(candidate_id, "rendered")?;
            Ok(true)
        }
        Err(error) if error.code == "LIMIT_EXCEEDED" => Ok(false),
        Err(error) => Err(error),
    }
}

fn parse_session_corpus(bytes: &[u8]) -> Result<Vec<Map<String, Value>>, ContractError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        host_error(format!(
            "corpus is not valid UTF-8: {}",
            error.valid_up_to()
        ))
    })?;
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
                return Err(host_error(format!(
                    "line {} has unknown key `{key}`",
                    index + 1
                )));
            }
        }
        for key in SESSION_OBSERVATION_KEYS {
            if !map.get(key).is_some_and(Value::is_string) {
                return Err(host_error(format!(
                    "line {} field `{key}` must be a string",
                    index + 1
                )));
            }
        }
        let id = map["id"].as_str().unwrap_or_default();
        if id.is_empty() {
            return Err(host_error(format!(
                "line {} id must be nonempty",
                index + 1
            )));
        }
        if !matches!(map["role"].as_str(), Some("user" | "assistant")) {
            return Err(host_error(format!(
                "line {} role must be user or assistant",
                index + 1
            )));
        }
        if map["source_kind"].as_str() != Some("codex_jsonl") {
            return Err(host_error(format!(
                "line {} source_kind must be codex_jsonl",
                index + 1
            )));
        }
        let observed_at = map["observed_at"].as_str().unwrap_or_default();
        crate::time::parse_rfc3339_millis(observed_at).map_err(|error| {
            host_error(format!(
                "line {} observed_at is invalid: {error}",
                index + 1
            ))
        })?;
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
    let bytes = if let Some(classifier) = classifier {
        crate::sandbox::run_verified_executable(
            &classifier.executable,
            &classifier.executable_sha256,
            &classifier.args,
            &crate::json::canonical_bytes(input),
            std::time::Duration::from_secs(classifier.timeout_seconds),
        )?
    } else {
        // No pinned executable means the product-owned deterministic provider
        // from `classifier --json`; it is replayable and has the same strict
        // output contract as an external provider.
        crate::json::canonical_bytes(&crate::classifier::deterministic(input)?)
    };
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
        .ok_or_else(|| {
            ContractError::integrity(
                "PROCESSOR_UNAUTHORIZED",
                "classifier atom has no text",
                "Repair the pinned classifier; no output was promoted.",
            )
        })?;
    let scope = external
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("host-session");
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
    let external_taints: Vec<crate::scanner::Taint> = external
        .get("taint")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .filter_map(crate::scanner::Taint::parse)
                .collect()
        })
        .unwrap_or_default();
    if let Some(values) = external
        .get("proposed_destinations")
        .and_then(Value::as_array)
    {
        let proposed_destinations = values
            .iter()
            .filter_map(Value::as_str)
            .map(|value| match value {
                "codebase" => repository_id
                    .map(|id| format!("codebase:{id}"))
                    .unwrap_or_else(|| "codebase".to_owned()),
                other => other.to_owned(),
            })
            .collect::<Vec<_>>();
        let taint_boundary = external_taints.iter().any(|taint| {
            taint.hard_block()
                || matches!(
                    taint,
                    crate::scanner::Taint::PersonalSession
                        | crate::scanner::Taint::CompanyConfidential
                )
        });
        let mut proposed_destinations = proposed_destinations;
        let mut eligible_destinations = if atom.hard_blocked || atom.confidence < 6_000 {
            Vec::new()
        } else {
            proposed_destinations.clone()
        };
        if !atom.hard_blocked && atom.confidence >= 6_000 && taint_boundary {
            // Approval-gating taint stays on the private atom and candidate
            // audit record; it does not erase an otherwise eligible, minimized
            // destination that exact-byte human approval may license.
            if !proposed_destinations
                .iter()
                .any(|value| value == "personal")
            {
                proposed_destinations.push("personal".to_owned());
            }
            let eligible_personal = eligible_destinations
                .iter()
                .any(|value| value == "personal");
            if !eligible_personal {
                eligible_destinations.push("personal".to_owned());
            }
        }
        if atom.hard_blocked || atom.confidence < 6_000 {
            proposed_destinations = vec!["none".to_owned()];
        }
        if proposed_destinations.is_empty() {
            proposed_destinations.push("none".to_owned());
        }
        // Predictions may name several P-2 destinations, while eligibility is
        // the privacy boundary: provenance-tainted session bytes never leave
        // Personal even after deidentification.
        atom.proposed_destinations = proposed_destinations;
        atom.eligible_destinations = eligible_destinations;
    }
    if let Some(values) = external.get("taint").and_then(Value::as_array) {
        atom.taints = values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = external
        .get("unresolved_uncertainty")
        .and_then(Value::as_str)
    {
        atom.unresolved_uncertainty = (!value.is_empty()).then(|| value.to_owned());
    }
    Ok(atom)
}

fn classifier_fingerprint(classifier: Option<&crate::config::SharedClassifier>) -> String {
    match classifier {
        Some(classifier) => format!(
            "sha256:{}:{}",
            classifier.executable_sha256,
            if classifier.model.starts_with("ollama:") {
                "ollama"
            } else {
                "deterministic"
            }
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
        "destination": destination,
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
        "rendered": rendered,
        "suppressed": !rendered,
        "taint_cleared": false,
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
    let record = checkpoint_internal(session)?;
    print_value(&record, json);
    Ok(())
}

/// Checkpoint a session without emitting host output.  Stop and SessionEnd
/// use this path so Personal facts survive the host process.
pub fn checkpoint_internal(session: &str) -> Result<Value, ContractError> {
    let observations = personal_records("observations.jsonl")
        .into_iter()
        .filter(|record| {
            record.get("source_identity").and_then(Value::as_str)
                == Some(&format!("session:{session}"))
        })
        .collect::<Vec<_>>();
    let observation_ids = observations
        .iter()
        .filter_map(|record| record.get("observation_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let atoms = personal_records("atoms.jsonl")
        .into_iter()
        .filter(|atom| {
            atom.get("observation_id")
                .and_then(Value::as_str)
                .is_some_and(|id| observation_ids.contains(id))
        })
        .collect::<Vec<_>>();
    let mut core = crate::private::PrivateStore::open_core()?;
    let now = now_rfc3339_millis();
    let mut personal_fact_count = 0;
    for atom in &atoms {
        let personal = atom
            .get("proposed_destinations")
            .and_then(Value::as_array)
            .map(|destinations| {
                destinations
                    .iter()
                    .any(|value| value.as_str() == Some("personal"))
            })
            .unwrap_or(false);
        let hard_blocked = atom
            .get("hard_blocked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !personal || hard_blocked {
            continue;
        }
        let fact = json!({
            "schema": "guildhall-personal-fact/1",
            "fact_id": format!("fact_{}", atom.get("atom_id").and_then(Value::as_str).unwrap_or_default()),
            "logical_key": format!("logical_{}", atom.get("atom_id").and_then(Value::as_str).unwrap_or_default()),
            "session_id": session,
            "atom_id": atom.get("atom_id"),
            "statement": atom.get("statement"),
            "confidence": atom.get("confidence"),
            "status": "current"
        });
        if core.upsert_personal_fact(&fact, &now)? {
            personal_fact_count += 1;
        }
    }
    let record = json!({
        "session_id": session,
        "checkpoint_id": format!("checkpoint_{}", Uuid::new_v4()),
        "status": "checkpointed",
        "checkpointed": true,
        "checkpointed_at": now,
        "observation_count": observations.len(),
        "atom_count": atoms.len(),
        "personal_fact_count": personal_fact_count
    });
    append_personal("session-checkpoints.jsonl", &record)?;
    Ok(record)
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
