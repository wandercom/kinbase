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
        ..Default::default()
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
    let parsed_records = parse_session_corpus(&bytes)?;
    if parsed_records.len() > SESSION_OBSERVATION_LIMIT {
        return Err(ContractError::limit(
            format!(
                "session observation batch exceeds the {}-line bound",
                SESSION_OBSERVATION_LIMIT
            ),
            json!({
                "omitted_count": parsed_records.len(),
                "line_limit": SESSION_OBSERVATION_LIMIT
            }),
        ));
    }

    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_id = crate::repository::repository_id(&repo).ok();
    let proof_clock = now_rfc3339_millis();
    let mut records = Vec::new();
    let mut quarantined_observations = Vec::new();
    for record in records_into_quarantine_or_admitted(parsed_records, &proof_clock)? {
        match record {
            QuarantineDecision::Admitted(record) => records.push(record),
            QuarantineDecision::ClockSkew(record) => {
                let private = crate::private::PrivateStore::open_core()?;
                private.quarantine("CLOCK_SKEW", &record)?;
                quarantined_observations.push(record);
            }
        }
    }
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
            source_kind: record["source_kind"]
                .as_str()
                .unwrap_or("codex_jsonl")
                .to_owned(),
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
            ..Default::default()
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
    let provider = select_provider(classifier);
    let extraction = extract_atoms(classifier, &provider, classifier_observations)?;
    let external_atoms = extraction.atoms;

    let mut atom_records = Vec::new();
    let mut candidate_records = Vec::new();
    let mut knowledge = crate::proposals::KnowledgeLedger::load();
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
            if extraction.abstained.contains(&observation.observation_id)
                || provider.live_model.is_some()
            {
                // The live classifier abstained (timeout, transport failure,
                // or no atoms): the observation stays private at low
                // confidence with destination none. No rule provider guesses
                // in its place inside a pinned live run.
                let mut atom = crate::classify::atomize(
                    "codex_jsonl",
                    native_id,
                    &text,
                    "host-session",
                    3_000,
                    &observation.observation_id,
                    &observation.content_digest,
                    repository_id.as_deref(),
                );
                atom.proposed_destinations = vec!["none".to_owned()];
                atom.eligible_destinations = Vec::new();
                atom.unresolved_uncertainty = Some(
                    "classifier abstained for this observation; no destination was guessed"
                        .to_owned(),
                );
                atoms.push(atom);
            } else {
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
                // P-9: which eligible candidates get the four scarce slots is
                // the product's decision, taken from the material's own
                // authority account and its distortion, before any slot is
                // reserved.
                let payload_digest = crate::json::get_str(&candidate, "payload_digest")
                    .unwrap_or_default()
                    .to_owned();
                let knowledge_key = crate::proposals::knowledge_key(&destination, &atom.statement);
                let byte_only = knowledge.is_byte_only_reissue(&knowledge_key, &payload_digest);
                knowledge.record(&knowledge_key, &payload_digest);
                let priority =
                    crate::proposals::queue_priority(&atom.statement, &atom.atom_kind, byte_only);
                candidate["knowledge_key"] = Value::String(knowledge_key);
                candidate["queue"] = json!({
                    "fresh": priority.fresh,
                    "trust_rank": priority.trust_rank,
                    "accounted_trust_class": priority.trust_class(),
                    "distortion_bp": priority.distortion_bp,
                    "byte_only_reissue": byte_only
                });
                candidate_records.push(candidate);
            }
            atom_records.push(
                serde_json::to_value(&atom)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
    }

    reserve_in_queue_order(&mut candidate_records, principal_id, host_instance_id)?;

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

    let quarantine_count = quarantined_observations.len();
    let result = json!({
        "session_id": session,
        "status": if quarantine_count == 0 { "observed" } else { "quarantined" },
        "code": if quarantine_count == 0 { Value::Null } else { Value::String("CLOCK_SKEW".to_owned()) },
        "disposition": if quarantine_count == 0 { "current" } else { "CLOCK_SKEW" },
        "state": if quarantine_count == 0 { "observed" } else { "CLOCK_SKEW" },
        "observation_count": observations.len(),
        "atom_count": atom_records.len(),
        "candidate_count": candidate_records.len(),
        "quarantine_count": quarantine_count,
        "quarantined_observations": quarantined_observations,
        "classifier": {
            "fingerprint": classifier_fingerprint(classifier, &provider),
            "provider": provider.name(),
            "model": provider.live_model.clone(),
            "configured_model": provider.configured_model.clone(),
            "fallback_from": provider.fallback_from.clone(),
            "fallback_reason": provider.fallback_reason.clone(),
            "abstained_observations": extraction.abstained.len(),
            "requests": extraction.requests,
            "retries": extraction.retries
        }
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

/// What one attempt at a display slot resolved to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotOutcome {
    /// The candidate holds a reserved slot and is rendered.
    Rendered,
    /// Three shared prompts have been surfaced without returning to the
    /// primary task. The refusal itself breaks the run, so the queue may try
    /// again at its head; it never hands the freed slot to a lower-priority
    /// candidate.
    PausedForPrimaryTask,
    /// The four shared slots in this sliding hour are gone. Nothing else can
    /// render until the window clears.
    WindowExhausted,
    /// This candidate alone is ineligible (its digest is inside the reissue
    /// lock); the queue moves on.
    Ineligible,
}

/// Walk the eligible candidates in distortion/authority order and reserve the
/// scarce slots for the highest-priority material (product.md P-9). The
/// records keep their arrival order for reporting; only the *reservation*
/// order is the queue's.
fn reserve_in_queue_order(
    candidates: &mut [Value],
    principal_id: &str,
    host_instance_id: &str,
) -> Result<(), ContractError> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|left, right| {
        let (left_priority, right_priority) = (
            candidate_priority(&candidates[*left]),
            candidate_priority(&candidates[*right]),
        );
        right_priority
            .cmp(&left_priority)
            // Ties resolve on the content-addressed payload digest, never on
            // arrival time: recency is not authority.
            .then_with(|| {
                crate::json::get_str(&candidates[*left], "payload_digest")
                    .cmp(&crate::json::get_str(&candidates[*right], "payload_digest"))
            })
    });
    let mut window_open = true;
    for index in order {
        let mut rendered = false;
        if window_open {
            match reserve_candidate_prompt(&candidates[index], principal_id, host_instance_id)? {
                SlotOutcome::Rendered => rendered = true,
                SlotOutcome::PausedForPrimaryTask => {
                    // The pause does not reorder the queue: this candidate
                    // keeps its place rather than yielding the next slot to a
                    // lower-authority one.
                    match reserve_candidate_prompt(
                        &candidates[index],
                        principal_id,
                        host_instance_id,
                    )? {
                        SlotOutcome::Rendered => rendered = true,
                        SlotOutcome::WindowExhausted => window_open = false,
                        _ => {}
                    }
                }
                SlotOutcome::WindowExhausted => window_open = false,
                SlotOutcome::Ineligible => {}
            }
        }
        candidates[index]["rendered"] = Value::Bool(rendered);
        candidates[index]["suppressed"] = Value::Bool(!rendered);
    }
    Ok(())
}

fn candidate_priority(record: &Value) -> crate::proposals::QueuePriority {
    let queue = record.get("queue");
    crate::proposals::QueuePriority {
        fresh: queue
            .and_then(|queue| queue.get("fresh"))
            .and_then(Value::as_bool)
            .unwrap_or(true),
        trust_rank: queue
            .and_then(|queue| queue.get("trust_rank"))
            .and_then(Value::as_u64)
            .and_then(|rank| u8::try_from(rank).ok())
            .unwrap_or(0),
        distortion_bp: queue
            .and_then(|queue| queue.get("distortion_bp"))
            .and_then(Value::as_i64)
            .unwrap_or(0),
    }
}

/// Reserve one display slot in the private Core shard.  A typed budget
/// refusal means this eligible candidate remains private and suppressed; it
/// is never an observation failure.
fn reserve_candidate_prompt(
    record: &Value,
    principal_id: &str,
    host_instance_id: &str,
) -> Result<SlotOutcome, ContractError> {
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
            Ok(SlotOutcome::Rendered)
        }
        Err(error) if error.code == "LIMIT_EXCEEDED" => Ok(slot_refusal(&error)),
        Err(error) => Err(error),
    }
}

/// Which of the three budget refusals the private store returned. The typed
/// evidence names the ceiling it hit, so the queue never has to guess.
fn slot_refusal(error: &ContractError) -> SlotOutcome {
    let detail = error.detail.as_ref();
    if detail.is_some_and(|detail| detail.get("reserved_in_window").is_some()) {
        return SlotOutcome::WindowExhausted;
    }
    if detail.is_some_and(|detail| detail.get("consecutive").is_some()) {
        return SlotOutcome::PausedForPrimaryTask;
    }
    SlotOutcome::Ineligible
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
        // The host adapter declares which native artefact each line came
        // from.  Any source kind the extractor supports is admissible; an
        // unknown one is a host-version defect, not a silent relabel.
        let source_kind = map["source_kind"].as_str().unwrap_or_default();
        if !crate::classify::source_kind_is_supported(source_kind) {
            return Err(host_error(format!(
                "line {} source_kind `{source_kind}` is not a supported native source",
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

/// Which classifier provider a pinned run actually uses. The configured
/// `model` selects the live Ollama provider (R-11); when Ollama does not
/// serve that model the run falls back to the product's own deterministic
/// rule provider and says so in every receipt, never silently.
#[derive(Debug, Clone)]
pub(crate) struct SelectedProvider {
    pub configured_model: Option<String>,
    pub live_model: Option<String>,
    pub fallback_from: Option<String>,
    pub fallback_reason: Option<String>,
}

impl SelectedProvider {
    fn name(&self) -> &'static str {
        if self.live_model.is_some() {
            "ollama"
        } else {
            "deterministic"
        }
    }
}

fn select_provider(classifier: Option<&crate::config::SharedClassifier>) -> SelectedProvider {
    let configured = classifier
        .map(|classifier| classifier.model.clone())
        .filter(|model| model.starts_with("ollama:"));
    let Some(model) = configured.clone() else {
        return SelectedProvider {
            configured_model: classifier.map(|classifier| classifier.model.clone()),
            live_model: None,
            fallback_from: None,
            fallback_reason: None,
        };
    };
    match crate::classifier::ollama_model_available(model.trim_start_matches("ollama:")) {
        Ok(()) => SelectedProvider {
            configured_model: Some(model.clone()),
            live_model: Some(model),
            fallback_from: None,
            fallback_reason: None,
        },
        Err(reason) => {
            crate::output::diagnostic(
                "classifier-fallback",
                json!({
                    "configured_model": model,
                    "provider": "deterministic",
                    "reason": reason
                }),
            );
            SelectedProvider {
                configured_model: Some(model.clone()),
                live_model: None,
                fallback_from: Some(model),
                fallback_reason: Some(reason),
            }
        }
    }
}

struct Extraction {
    atoms: BTreeMap<String, Vec<Value>>,
    abstained: BTreeSet<String>,
    requests: usize,
    retries: usize,
}

/// Bounded parallelism for live single-observation requests: enough to keep
/// a session batch inside the command budget, few enough that requests are
/// served rather than queued (queue time counts against each request's
/// timeout, so more workers than the provider serves concurrently only
/// manufactures timeouts).
const LIVE_CLASSIFIER_WORKERS: usize = 16;

/// Wall budget for one live extraction pass (the host command itself is
/// bounded at two minutes by its callers; the remainder is for candidate
/// construction and durable writes).
const LIVE_EXTRACTION_BUDGET_SECONDS: u64 = 105;

fn extract_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    observations: Vec<Value>,
) -> Result<Extraction, ContractError> {
    let mut extraction = Extraction {
        atoms: BTreeMap::new(),
        abstained: BTreeSet::new(),
        requests: 0,
        retries: 0,
    };
    if provider.live_model.is_none() {
        for batch in crate::classifier::request_batches(observations)? {
            extraction.requests += 1;
            for (observation_id, atoms) in pinned_classifier_atoms(classifier, provider, &batch)? {
                extraction
                    .atoms
                    .entry(observation_id)
                    .or_default()
                    .extend(atoms);
            }
        }
        return Ok(extraction);
    }
    // A live model answers one observation per request so that one slow
    // answer cannot time out a whole batch; requests run concurrently and a
    // failed request is retried once before the observation abstains.
    let batches: Vec<Value> = observations
        .into_iter()
        .map(|observation| json!({ "observations": [observation] }))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let started = std::time::Instant::now();
    let results: std::sync::Mutex<
        Vec<(
            usize,
            Result<BTreeMap<String, Vec<Value>>, ContractError>,
            usize,
        )>,
    > = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..LIVE_CLASSIFIER_WORKERS.min(batches.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Some(batch) = batches.get(index) else {
                        break;
                    };
                    let mut attempts = 0usize;
                    let outcome = loop {
                        // The session command has a bounded wall budget: a
                        // slow answer is retried while there is time for
                        // another full attempt, and abstains otherwise.
                        let elapsed = started.elapsed().as_secs();
                        if elapsed >= LIVE_EXTRACTION_BUDGET_SECONDS {
                            break Err(ContractError::degraded(
                                "UNKNOWN_OWNER_UNRESOLVED",
                                "classifier wall budget exhausted; extraction abstained",
                                "Reduce the batch or raise classifier.timeout_seconds.",
                            ));
                        }
                        let allowed = if elapsed < LIVE_EXTRACTION_BUDGET_SECONDS / 3 {
                            3
                        } else if elapsed < LIVE_EXTRACTION_BUDGET_SECONDS * 2 / 3 {
                            2
                        } else {
                            1
                        };
                        attempts += 1;
                        match pinned_classifier_atoms(classifier, provider, batch) {
                            Ok(atoms) => break Ok(atoms),
                            Err(error) if attempts < allowed && retryable_extraction(&error) => {
                                continue;
                            }
                            Err(error) => break Err(error),
                        }
                    };
                    if let Ok(mut results) = results.lock() {
                        results.push((index, outcome, attempts));
                    }
                }
            });
        }
    });
    let results = results.into_inner().unwrap_or_default();
    for (index, outcome, attempts) in results {
        extraction.requests += attempts;
        extraction.retries += attempts.saturating_sub(1);
        let observation_id = batches[index]["observations"][0]["observation_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        match outcome {
            Ok(atoms) => {
                let mut any = false;
                for (id, items) in atoms {
                    any = any || !items.is_empty();
                    extraction.atoms.entry(id).or_default().extend(items);
                }
                if !any {
                    extraction.abstained.insert(observation_id);
                }
            }
            Err(error) => {
                if !retryable_extraction(&error) {
                    return Err(error);
                }
                crate::output::diagnostic(
                    "classifier-abstained",
                    json!({"observation_id": observation_id, "code": error.code, "message": error.message}),
                );
                extraction.abstained.insert(observation_id);
            }
        }
    }
    Ok(extraction)
}

/// Transport, timeout, and malformed-answer failures abstain per
/// observation; configuration and authorization failures stop the run.
fn retryable_extraction(error: &ContractError) -> bool {
    matches!(
        error.code.as_str(),
        "COMPANY_UNREACHABLE" | "UNKNOWN_OWNER_UNRESOLVED"
    ) || (error.code == "PROCESSOR_UNAUTHORIZED"
        && (error.message.contains("Ollama") || error.message.contains("classifier output")))
}

fn pinned_classifier_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    input: &Value,
) -> Result<BTreeMap<String, Vec<Value>>, ContractError> {
    let bytes = if let Some(classifier) = classifier {
        // The pinned child selects its provider from explicit arguments: the
        // configured live model, or the deterministic provider after a loud
        // fallback. It never reads the launcher config itself.
        let mut args = classifier.args.clone();
        match &provider.live_model {
            Some(model) => {
                args.push("--model".to_owned());
                args.push(model.clone());
            }
            None => {
                args.push("--provider".to_owned());
                args.push("deterministic".to_owned());
            }
        }
        crate::sandbox::run_verified_executable(
            &classifier.executable,
            &classifier.executable_sha256,
            &args,
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
            // destination that exact-byte human approval may license. The
            // principal's private memory is always an eligible home for a
            // session atom, but that boundary is not the classifier's
            // semantic prediction, so it is not added to the proposal.
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

fn classifier_fingerprint(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
) -> String {
    match classifier {
        Some(classifier) => format!(
            "sha256:{}:{}",
            classifier.executable_sha256,
            match &provider.live_model {
                Some(model) => model.clone(),
                None => "deterministic".to_owned(),
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

enum QuarantineDecision {
    Admitted(Map<String, Value>),
    ClockSkew(Value),
}

fn records_into_quarantine_or_admitted(
    records: Vec<Map<String, Value>>,
    proof_clock: &str,
) -> Result<Vec<QuarantineDecision>, ContractError> {
    let mut output = Vec::new();
    for record in records {
        let event_id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let text = record
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let observed_at = record
            .get("observed_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let source_kind = record
            .get("source_kind")
            .and_then(Value::as_str)
            .unwrap_or("codex_jsonl")
            .to_owned();
        let digest = sha256_bytes(text.as_bytes());
        if let Some((direction, seconds)) =
            crate::time::receipt_clock_skew(&observed_at, proof_clock)
        {
            output.push(QuarantineDecision::ClockSkew(json!({
                "observation_id": format!(
                    "obs_{:x}",
                    Sha256::digest(format!("session\0{event_id}\0{digest}").as_bytes())
                ),
                "source_kind": source_kind,
                "source_identity": "host-session",
                "native_id": event_id,
                "content_digest": digest,
                "field": "observed_at",
                "direction": direction,
                "skew_seconds": seconds,
                "proof_clock": proof_clock,
                "observed_at": observed_at,
                "code": "CLOCK_SKEW",
                "disposition": "CLOCK_SKEW",
                "state": "CLOCK_SKEW",
                "remediation": "owner must supply corrected receipt evidence"
            })));
            continue;
        }
        output.push(QuarantineDecision::Admitted(record));
    }
    Ok(output)
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
    let store = crate::proposals::destination_store(destination)?;
    // P-2: shared proposals are minimized and de-identified. Opaque private
    // codes and the bookkeeping notes that carry them stay in the private
    // atom; the shared payload keeps the knowledge without them.
    let (statement, removed) = if store == crate::StoreKind::Personal {
        (atom.statement.clone(), 0)
    } else {
        deidentify_statement(&atom.statement)
    };
    let payload = json!({
        "destination": destination,
        "atom_kind": atom.atom_kind,
        "scope": atom.scope,
        "statement": statement
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
        "hard_block_respected": true,
        "deidentified_tokens": removed
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

/// Remove opaque identifiers (long hex, base64-like, or digit-dense tokens)
/// from a statement bound for a shared destination, together with a trailing
/// bookkeeping note that only carried such a code. Returns the minimized
/// text and the number of tokens removed.
pub(crate) fn deidentify_statement(statement: &str) -> (String, usize) {
    fn opaque(word: &str) -> bool {
        let core: String = word
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '=' && c != '+' && c != '/')
            .to_owned();
        if core.len() < 16 {
            return false;
        }
        let hex_run = core
            .split(|c: char| !c.is_ascii_hexdigit())
            .map(str::len)
            .max()
            .unwrap_or(0);
        if hex_run >= 12 {
            return true;
        }
        let digits = core.chars().filter(char::is_ascii_digit).count();
        let letters = core.chars().filter(char::is_ascii_alphabetic).count();
        let base64_like = core.len() >= 20
            && core
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
            && digits >= 2
            && letters >= 2
            && (core.ends_with('=')
                || digits >= 4
                || core.chars().any(|c| c.is_ascii_uppercase())
                    && core.chars().any(|c| c.is_ascii_lowercase()));
        base64_like
    }
    let mut removed = 0usize;
    let mut sentences: Vec<String> = Vec::new();
    for sentence in split_sentences_keep(statement) {
        let mut kept: Vec<&str> = Vec::new();
        let mut dropped_here = 0usize;
        for word in sentence.split_whitespace() {
            if opaque(word) {
                dropped_here += 1;
            } else {
                kept.push(word);
            }
        }
        removed += dropped_here;
        let text = kept.join(" ");
        // A note that only carried a code ("Ref <code>", "I logged this as
        // <code>") has nothing left to share once the code is gone.
        let residual_words = text
            .split_whitespace()
            .filter(|w| w.chars().any(char::is_alphanumeric))
            .count();
        if dropped_here > 0 && residual_words <= 5 && !sentences.is_empty() {
            continue;
        }
        if dropped_here > 0 && residual_words == 0 {
            continue;
        }
        sentences.push(text);
    }
    let minimized = sentences.join(" ").trim().to_owned();
    if minimized.is_empty() {
        (statement.to_owned(), 0)
    } else {
        (minimized, removed)
    }
}

/// Sentence split that keeps terminators and never breaks inside a token.
fn split_sentences_keep(text: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = String::new();
    let characters: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        current.push(character);
        if matches!(character, '.' | '!' | '?') {
            let boundary = index + 1 >= characters.len() || characters[index + 1].is_whitespace();
            let previous_is_digit_dot = character == '.'
                && index > 0
                && characters[index - 1].is_ascii_digit()
                && index + 1 < characters.len()
                && characters[index + 1].is_ascii_digit();
            if boundary && !previous_is_digit_dot {
                let trimmed = current.trim().to_owned();
                if !trimmed.is_empty() {
                    output.push(trimmed);
                }
                current.clear();
            }
        }
        index += 1;
    }
    let trimmed = current.trim().to_owned();
    if !trimmed.is_empty() {
        output.push(trimmed);
    }
    output
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

#[cfg(test)]
mod tests {
    use super::deidentify_statement;

    #[test]
    fn shared_payload_drops_opaque_codes_and_their_carrier_note() {
        let (text, removed) = deidentify_statement(
            "The scheduler retries at most three times. Ref kxslot0a1b2c3d4e5f6a7b",
        );
        assert_eq!(text, "The scheduler retries at most three times.");
        assert_eq!(removed, 1);
        let (text, removed) = deidentify_statement(
            "The migration adds the composite index. I logged this as kxticket9f8e7d6c5b4a3921",
        );
        assert_eq!(text, "The migration adds the composite index.");
        assert_eq!(removed, 1);
        let (text, removed) =
            deidentify_statement("My passphrase is a3hkZWFkYmVlZjEyMzQ1Njc4OTAxMg==");
        assert_eq!(text, "My passphrase is");
        assert_eq!(removed, 1);
    }

    #[test]
    fn shared_payload_keeps_ordinary_statements_intact() {
        let statement = "The lookahead window defaults to 15 minutes in scheduler/lookahead.py.";
        assert_eq!(deidentify_statement(statement), (statement.to_owned(), 0));
        let version = "We pinned requests to 2.31 because 2.32 broke the proxy handling.";
        assert_eq!(deidentify_statement(version), (version.to_owned(), 0));
    }
}
