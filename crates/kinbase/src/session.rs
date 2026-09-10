use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::{canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, Observation, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, parse_rfc3339_millis};
use chrono::Duration;
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
                let candidate = build_candidate(
                    session,
                    &destination,
                    &atom,
                    native_id,
                    principal_id,
                    host_instance_id,
                )?;
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

    let launcher = crate::launcher::Launcher::load()?;
    let mut admissions = Vec::new();
    let mut questions = BTreeSet::new();
    for atom in &atom_records {
        if let Some(question) = question_for_unresolved_atom(&repo, atom)? {
            questions.insert(question);
        }
    }
    for candidate in &candidate_records {
        admissions.push(admit_candidate(&launcher, &repo, candidate)?);
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
        "admissions": admissions,
        "questions": questions,
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
const LIVE_EXTRACTION_BUDGET_SECONDS: u64 = 95;

/// The shortest request worth starting. Below this the queue closes rather
/// than spend the tail of the budget on a request that would be killed.
const LIVE_MINIMUM_REQUEST_SECONDS: u64 = 3;

/// How much of the extraction budget is left, or `None` when what remains is
/// too little to finish a request inside it.
fn remaining_budget(started: &std::time::Instant) -> Option<std::time::Duration> {
    let elapsed = started.elapsed().as_secs();
    let remaining = LIVE_EXTRACTION_BUDGET_SECONDS.saturating_sub(elapsed);
    (remaining >= LIVE_MINIMUM_REQUEST_SECONDS).then(|| std::time::Duration::from_secs(remaining))
}

/// The queue closed on its own wall bound. This is a fact about the command's
/// budget, never an observation the model declined to read.
fn budget_closed() -> ContractError {
    ContractError::degraded(
        "UNKNOWN_OWNER_UNRESOLVED",
        "classifier wall budget closed the sample queue",
        "Raise classifier.timeout_seconds or reduce the observation batch.",
    )
}

fn is_budget_closed(error: &ContractError) -> bool {
    error
        .message
        .contains("wall budget closed the sample queue")
}

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
            for (observation_id, atoms) in
                pinned_classifier_atoms(classifier, provider, &batch, None)?
            {
                extraction
                    .atoms
                    .entry(observation_id)
                    .or_default()
                    .extend(atoms);
            }
        }
        return Ok(extraction);
    }
    // Every observation is read `LIVE_BASE_SAMPLES` times and the product
    // decides the answer by self-consistency (below): one draw from a
    // sampling decoder is a draw from the model's distribution, not the
    // model's reading, and P-2 makes the destination set a fact this product
    // owns.
    let started = std::time::Instant::now();
    let mut samples: BTreeMap<String, Vec<Vec<Value>>> = BTreeMap::new();
    let mut taken = 0usize;
    let mut wanted = 0usize;

    let base = live_sample_pass(
        classifier,
        provider,
        &observations,
        LIVE_BASE_SAMPLES,
        &started,
        &mut extraction,
    )?;
    wanted += live_batches(&observations)?.len() * LIVE_BASE_SAMPLES;
    taken += base.0;
    merge_samples(&observations, base.1, &mut samples);

    // A third draw is bought only where the first two disagree --- where a
    // tie would otherwise be settled by rule rather than by evidence --- so
    // the extra requests go to the observations that are actually contested.
    let contested: Vec<Value> = observations
        .iter()
        .filter(|observation| {
            let id = observation["observation_id"].as_str().unwrap_or_default();
            readings_disagree(samples.get(id).map(Vec::as_slice).unwrap_or(&[]))
        })
        .cloned()
        .collect();
    if !contested.is_empty() {
        let tiebreak = live_sample_pass(
            classifier,
            provider,
            &contested,
            LIVE_TIEBREAK_SAMPLES,
            &started,
            &mut extraction,
        )?;
        wanted += live_batches(&contested)?.len() * LIVE_TIEBREAK_SAMPLES;
        taken += tiebreak.0;
        merge_samples(&contested, tiebreak.1, &mut samples);
    }

    if taken < wanted {
        // One line, not one per skipped request: the budget closed and the
        // vote was taken over fewer draws. Saying so is the point --- a
        // quieter answer is still a weaker one.
        crate::output::diagnostic(
            "classifier-budget-closed",
            json!({
                "requests_planned": wanted,
                "requests_taken": taken,
                "observations": observations.len(),
                "contested_observations": contested.len(),
                "budget_seconds": LIVE_EXTRACTION_BUDGET_SECONDS
            }),
        );
    }
    for observation in &observations {
        let observation_id = observation["observation_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let drawn = samples.remove(&observation_id).unwrap_or_default();
        match self_consistent_atoms(&drawn) {
            Some(atoms) if !atoms.is_empty() => {
                extraction
                    .atoms
                    .entry(observation_id)
                    .or_default()
                    .extend(atoms);
            }
            _ => {
                extraction.abstained.insert(observation_id);
            }
        }
    }
    Ok(extraction)
}

/// Group observations into live requests. A request carries a few
/// observations rather than one: the routing instruction is the same for
/// every request and is far larger than an observation, so asking one
/// observation at a time spends most of the wall budget re-sending the
/// instruction. `classifier::request_batches` still splits any group whose
/// bytes exceed the request bound.
fn live_batches(observations: &[Value]) -> Result<Vec<Value>, ContractError> {
    let mut batches = Vec::new();
    for chunk in observations.chunks(LIVE_OBSERVATIONS_PER_REQUEST) {
        for batch in crate::classifier::request_batches(chunk.to_vec())? {
            if batch["observations"]
                .as_array()
                .is_some_and(|values| !values.is_empty())
            {
                batches.push(batch);
            }
        }
    }
    Ok(batches)
}

/// One request's outcome: which batch it answered for, and what came back.
type SampleOutcome = (
    usize,
    Result<BTreeMap<String, Vec<Value>>, ContractError>,
    usize,
);

/// Ask for `samples` more draws of every observation, concurrently, inside
/// the extraction budget. Work is queued sample-major --- every batch is asked
/// once before any is asked twice --- so exhausting the budget costs later
/// *samples*, never a batch's only answer. Returns how many requests were
/// actually taken and their outcomes.
#[allow(clippy::type_complexity)]
fn live_sample_pass(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    observations: &[Value],
    samples: usize,
    started: &std::time::Instant,
    extraction: &mut Extraction,
) -> Result<(usize, Vec<(usize, BTreeMap<String, Vec<Value>>)>), ContractError> {
    let batches = live_batches(observations)?;
    let work = batches.len() * samples;
    if work == 0 {
        return Ok((0, Vec::new()));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let closed = std::sync::atomic::AtomicBool::new(false);
    let results: std::sync::Mutex<Vec<SampleOutcome>> = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..LIVE_CLASSIFIER_WORKERS.min(work) {
            scope.spawn(|| {
                loop {
                    if closed.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let item = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if item >= work {
                        break;
                    }
                    let index = item % batches.len();
                    let Some(batch) = batches.get(index) else {
                        break;
                    };
                    let mut attempts = 0usize;
                    let outcome = loop {
                        // The command answers inside its own wall bound. A
                        // request that could outlive the budget is never
                        // started: the queue closes instead, so the cost of a
                        // slow provider is a later sample, not a request the
                        // caller must wait past its deadline for.
                        let Some(remaining) = remaining_budget(started) else {
                            closed.store(true, std::sync::atomic::Ordering::Relaxed);
                            break Err(budget_closed());
                        };
                        let allowed =
                            if remaining.as_secs() > LIVE_EXTRACTION_BUDGET_SECONDS * 2 / 3 {
                                3
                            } else if remaining.as_secs() > LIVE_EXTRACTION_BUDGET_SECONDS / 3 {
                                2
                            } else {
                                1
                            };
                        attempts += 1;
                        match pinned_classifier_atoms(classifier, provider, batch, Some(remaining))
                        {
                            Ok(atoms) => break Ok(atoms),
                            // Backpressure is not an answer: the provider is
                            // asking us to wait, so it never consumes the
                            // answer-quality retry budget, only the wall
                            // budget. Everything else keeps that budget.
                            Err(error) if provider_backpressure(&error) => {
                                std::thread::sleep(backpressure_pause(attempts));
                                continue;
                            }
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
    let mut outcomes = results.into_inner().unwrap_or_default();
    outcomes.sort_by_key(|(index, _, _)| *index);
    let mut answered = Vec::new();
    let mut taken = 0usize;
    for (index, outcome, attempts) in outcomes {
        extraction.requests += attempts;
        extraction.retries += attempts.saturating_sub(1);
        match outcome {
            Ok(atoms) => {
                taken += 1;
                answered.push((index, atoms));
            }
            Err(error) if is_budget_closed(&error) => {}
            Err(error) => {
                taken += 1;
                // A configuration or authorization defect is not a draw from
                // the model: it stops the run rather than losing one vote.
                if !retryable_extraction(&error) {
                    return Err(error);
                }
                crate::output::diagnostic(
                    "classifier-sample-abstained",
                    json!({"batch": index, "code": error.code, "message": error.message}),
                );
            }
        }
    }
    Ok((taken, answered))
}

/// Fold one pass's answers into the per-observation draws. A batch answer
/// carries every observation it was asked about, so an observation the model
/// omitted contributes an empty draw, which never wins a vote.
fn merge_samples(
    observations: &[Value],
    answered: Vec<(usize, BTreeMap<String, Vec<Value>>)>,
    samples: &mut BTreeMap<String, Vec<Vec<Value>>>,
) {
    let known: BTreeSet<&str> = observations
        .iter()
        .filter_map(|observation| observation["observation_id"].as_str())
        .collect();
    for (_, atoms) in answered {
        for (observation_id, drawn) in atoms {
            if !known.contains(observation_id.as_str()) {
                continue;
            }
            samples.entry(observation_id).or_default().push(drawn);
        }
    }
}

/// Whether the draws taken so far leave the reading contested: fewer than two
/// answered, or the two that answered proposed different destination sets.
fn readings_disagree(drawn: &[Vec<Value>]) -> bool {
    let readings: Vec<Vec<String>> = drawn
        .iter()
        .filter(|atoms| !atoms.is_empty())
        .map(|atoms| sample_destinations(atoms))
        .collect();
    match readings.len() {
        0 | 1 => true,
        _ => readings.iter().any(|reading| *reading != readings[0]),
    }
}

/// How many times a sampling decoder is asked to read every observation. One
/// draw is a sample, not an answer, so two are always taken and compared.
const LIVE_BASE_SAMPLES: usize = 2;

/// How many observations one live request carries. The routing instruction is
/// the same for every request and is far larger than an observation, so a
/// request per observation spends the wall budget re-sending the instruction:
/// measured on this provider, thirty-two observations cost 4.4s one at a time
/// and 1.4s in groups of four. Small enough that one slow answer costs a few
/// observations' draw, never the pass.
const LIVE_OBSERVATIONS_PER_REQUEST: usize = 4;

/// How many further draws a *contested* observation buys --- one, which turns
/// a disagreement into a majority. Uncontested observations pay nothing for
/// it, so the extra requests go where the reading is actually in doubt.
const LIVE_TIEBREAK_SAMPLES: usize = 1;

/// The provider refusing work because too many requests are already in
/// flight. This carries no information about the observation, so it is a wait,
/// never an abstention.
fn provider_backpressure(error: &ContractError) -> bool {
    error.code == "PROCESSOR_UNAUTHORIZED"
        && (error.message.contains("429") || error.message.contains("too many"))
}

/// Bounded, growing pause before re-offering a request the provider pushed
/// back on, so a saturated provider is drained rather than hammered.
fn backpressure_pause(attempts: usize) -> std::time::Duration {
    std::time::Duration::from_millis((100 * attempts.min(10)) as u64)
}

/// The destination set one sample proposed for an observation. This is the
/// unit the vote is taken over: P-2 makes the *set* of destinations the
/// classification, so voting per atom would let two samples that disagree
/// about how to split a message manufacture a third reading neither gave.
fn sample_destinations(atoms: &[Value]) -> Vec<String> {
    let mut destinations: BTreeSet<String> = BTreeSet::new();
    for atom in atoms {
        if let Some(values) = atom.get("proposed_destinations").and_then(Value::as_array) {
            for value in values {
                if let Some(label) = value.as_str() {
                    destinations.insert(label.to_owned());
                }
            }
        }
    }
    destinations.into_iter().collect()
}

/// Decide what the model read by self-consistency over the samples that
/// answered: the modal destination set wins; ties go to the smaller set (the
/// product never invents a destination a tie could not settle) and then to
/// lexicographic order, so the choice is deterministic given the samples. The
/// atoms returned are one sample's own atoms --- the first that proposed the
/// winning set --- never a merge, so every emitted atom is text some sample
/// actually produced.
fn self_consistent_atoms(drawn: &[Vec<Value>]) -> Option<Vec<Value>> {
    let readings: Vec<(Vec<String>, &Vec<Value>)> = drawn
        .iter()
        .filter(|atoms| !atoms.is_empty())
        .map(|atoms| (sample_destinations(atoms), atoms))
        .collect();
    if readings.is_empty() {
        return None;
    }
    let mut votes: BTreeMap<&Vec<String>, usize> = BTreeMap::new();
    for (destinations, _) in &readings {
        *votes.entry(destinations).or_default() += 1;
    }
    let winner = votes
        .into_iter()
        .max_by(|left, right| {
            left.1
                .cmp(&right.1)
                // Ties: the smaller set, then lexicographic order. Both are
                // properties of the reading, so the same samples always
                // decide the same way.
                .then_with(|| right.0.len().cmp(&left.0.len()))
                .then_with(|| right.0.cmp(left.0))
        })
        .map(|(destinations, _)| destinations.clone())?;
    readings
        .into_iter()
        .find(|(destinations, _)| *destinations == winner)
        .map(|(_, atoms)| atoms.clone())
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
    timeout: Option<std::time::Duration>,
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
            // A request is never given more time than the extraction budget
            // has left: the command must answer inside its own bound, and a
            // request that could outlive the budget is not started at all.
            timeout
                .unwrap_or(std::time::Duration::from_secs(classifier.timeout_seconds))
                .min(std::time::Duration::from_secs(classifier.timeout_seconds)),
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
            // Keep taint provenance in the audit record while admitting the
            // minimized evidence to eligible destinations. Personal memory
            // remains an additional home for the original session atom.
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
        // Classifier routing determines the destinations for minimized
        // evidence. Hard-blocked material is never admitted.
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
            let executable = std::env::current_exe().unwrap_or_else(|_| "kinbase".into());
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
    principal_id: &str,
    host_instance_id: &str,
) -> Result<Value, ContractError> {
    let store = destination_store(destination)?;
    // Shared admissions are minimized and de-identified. Opaque private
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
    let candidate_id = format!(
        "cand_{}",
        sha256_text(&format!(
            "{session}\0{message_id}\0{principal_id}\0{destination}\0{payload_digest}"
        ))
    );
    let repo = std::env::current_dir().map_err(io_error)?;
    let record = json!({
        "candidate_id": candidate_id,
        "admission_mode": "automatic",
        "session_id": session,
        "message_id": message_id,
        "destination": destination,
        "canonical": canonical,
        "payload_digest": payload_digest,
        "principal": principal_id,
        "host_instance_id": host_instance_id,
        "source_revision": crate::repository::git_revision(&repo).unwrap_or_default(),
        "created_at": now_rfc3339_millis(),
        "nonce": Uuid::new_v4().to_string(),
        "confidence": atom.confidence,
        "unresolved_uncertainty": atom.unresolved_uncertainty,
        "taint_cleared": false,
        "hard_block_respected": true,
        "deidentified_tokens": removed
    });
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
    // A failed Company delivery or a crash after journaling is retried by the
    // ordinary session lifecycle; there is no proposal command to drain it.
    let mut candidates = BTreeMap::new();
    for candidate in personal_records("candidates.jsonl") {
        if crate::json::get_str(&candidate, "session_id") == Some(session)
            && crate::json::get_str(&candidate, "admission_mode") == Some("automatic")
        {
            let id = crate::json::get_str(&candidate, "candidate_id")
                .unwrap_or_default()
                .to_owned();
            candidates.insert(id, candidate);
        }
    }
    let mut admissions = Vec::new();
    if !candidates.is_empty() {
        let launcher = crate::launcher::Launcher::load()?;
        let repo = std::env::current_dir().map_err(io_error)?;
        for candidate in candidates.values() {
            admissions.push(admit_candidate(&launcher, &repo, candidate)?);
        }
    }
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
    let core = crate::private::PrivateStore::open_core()?;
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
            "schema": "kinbase-personal-fact/1",
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
        "personal_fact_count": personal_fact_count,
        "admissions": admissions
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

#[cfg(test)]
mod consistency_tests {
    use super::*;

    fn atom(observation: &str, text: &str, destination: &str) -> Value {
        json!({
            "atom_id": format!("atom_{text}_{destination}"),
            "observation_id": observation,
            "text": text,
            "proposed_destinations": [destination],
            "confidence": "high"
        })
    }

    #[test]
    fn the_modal_reading_wins_over_a_single_odd_draw() {
        let drawn = vec![
            vec![atom("o1", "the scheduler default", "codebase")],
            vec![atom("o1", "the scheduler default", "personal")],
            vec![atom("o1", "the scheduler default", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["codebase".to_owned()]);
    }

    #[test]
    fn a_tie_takes_the_smaller_set_then_lexicographic_order() {
        let drawn = vec![
            vec![atom("o1", "a", "codebase"), atom("o1", "b", "company")],
            vec![atom("o1", "a", "personal")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["personal".to_owned()]);

        let drawn = vec![
            vec![atom("o1", "a", "personal")],
            vec![atom("o1", "a", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["codebase".to_owned()]);
    }

    #[test]
    fn every_emitted_atom_comes_from_one_sample_never_a_merge() {
        let drawn = vec![
            vec![atom("o1", "first half", "codebase")],
            vec![
                atom("o1", "first half", "codebase"),
                atom("o1", "second half", "codebase"),
            ],
            vec![atom("o1", "first half", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(
            chosen.len(),
            1,
            "the first sample with the winning set is emitted whole"
        );
        assert_eq!(chosen[0]["text"], json!("first half"));
    }

    #[test]
    fn an_observation_no_sample_answered_abstains() {
        assert!(self_consistent_atoms(&[]).is_none());
        assert!(self_consistent_atoms(&[Vec::new()]).is_none());
    }

    #[test]
    fn a_third_draw_is_bought_only_where_the_first_two_disagree() {
        let agree = vec![
            vec![atom("o1", "a", "codebase")],
            vec![atom("o1", "a", "codebase")],
        ];
        assert!(!readings_disagree(&agree));
        let differ = vec![
            vec![atom("o1", "a", "codebase")],
            vec![atom("o1", "a", "personal")],
        ];
        assert!(readings_disagree(&differ));
        // One answer is not a majority either.
        assert!(readings_disagree(&[vec![atom("o1", "a", "codebase")]]));
        assert!(readings_disagree(&[]));
    }
}

// Durable admission transactions, shared by observation and repository recovery.
/// Append the principal's copy of a destination receipt and make it durable
/// (file and directory fsync): receipt finalization is one generation, and
/// the record must survive a crash that follows the destination commit.
fn finalize_principal_receipt(base: &Value, saga: &Value) -> Result<Value, ContractError> {
    let mut receipt = base.clone();
    merge_receipt(&mut receipt, saga);
    let repo_root = repo()?;
    let already = personal_records("proposal-decisions.jsonl")
        .into_iter()
        .any(|record| {
            crate::json::get_str(&record, "candidate_id")
                == crate::json::get_str(&receipt, "candidate_id")
                && crate::json::get_str(&record, "receipt_id")
                    == crate::json::get_str(&receipt, "receipt_id")
                && crate::json::get_str(&record, "state") == crate::json::get_str(&receipt, "state")
        });
    if !already {
        crate::store::append_record(
            crate::StoreKind::Personal,
            &repo_root,
            "proposal-decisions.jsonl",
            &receipt,
        )?;
        let path = crate::store::store_root(crate::StoreKind::Personal, &repo_root)
            .join("proposal-decisions.jsonl");
        if let Ok(file) = std::fs::File::open(&path) {
            let _ = file.sync_all();
        }
        if let Some(parent) = path.parent() {
            if let Ok(directory) = std::fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
    }
    Ok(receipt)
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

const FANOUT_JOURNAL_SCHEMA: &str = "kinbase-fanout-journal/1";
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
    base_receipt: &Value,
) -> Result<Value, ContractError> {
    let repository = crate::codebase::Repository::discover(repo_root)?;
    let repository_uuid = crate::repository::repository_id(repo_root)?;
    if let Some(bound) = destination.strip_prefix("codebase:") {
        if bound != repository_uuid {
            return Err(ContractError::new(
                "AUTHORITY_SCOPE_DENIED",
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
            base_receipt,
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
            base_receipt,
        )
    }
}

/// Build the destination event once and bind the admission nonce to its
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
    base_receipt: &Value,
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
            json!({"index": ".kin/local/kinbase-index.json"}),
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
        // The receipt names exactly the bytes the destination holds: re-read
        // and re-hash the committed event before the receipt is final.
        let committed = std::fs::read(&final_path)
            .map_err(|error| ContractError::io("re-read committed event", error))?;
        if crate::hash::sha256_bytes(&committed) != event_digest {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                "committed event bytes differ from the bound bytes",
                "Run full fsck; the destination journal is inconsistent.",
            ));
        }
        let summary = receipt_summary(
            &receipt_path,
            receipt_id,
            &event_digest,
            &event_path,
            &event,
            journal,
        )?;
        finalize_principal_receipt(base_receipt, &summary)?;
        journal.complete("receipt", json!({}))?;
        journal.finish()?;
    }
    receipt_summary(
        &receipt_path,
        receipt_id,
        &event_digest,
        &event_path,
        &event,
        journal,
    )
}

fn receipt_summary(
    receipt_path: &Path,
    receipt_id: &str,
    event_digest: &str,
    event_path: &str,
    event: &Value,
    journal: &FanoutJournal,
) -> Result<Value, ContractError> {
    let stored =
        std::fs::read(receipt_path).map_err(|error| ContractError::io("read receipt", error))?;
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
    base_receipt: &Value,
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
                let summary = receipt_from_marker(&marker, receipt_id);
                finalize_principal_receipt(base_receipt, &summary)?;
                journal.finish()?;
                return Ok(summary);
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
        // admitting principal owns the divergence; the committed
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
    let summary = receipt_from_marker(&marker, receipt_id);
    finalize_principal_receipt(base_receipt, &summary)?;
    if state != "pending" {
        journal.finish()?;
    }
    Ok(summary)
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
                && matches!(
                    crate::json::get_str(decision, "decision"),
                    Some("approve" | "admit")
                )
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
        "Apology Unknown for divergent fan-out: destination {failed_destination} failed ({}) after {committed_destination} committed receipt {}. Admitting principal {principal} is responsible; closing authority {closing_name} ({closing_role}) must reconcile or abandon by {response_due_at}. The orphaned claim is withheld from trusted use until then.",
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
        "responsible_party_role": "admitting-principal",
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
        // A replayed transaction completes with the principal's receipt copy
        // reconstructed from the bound reservation.
        let base_receipt = json!({
            "candidate_id": candidate_id,
            "destination": destination,
            "decision": "admit",
            "digest": payload_digest,
            "decided_at": now_rfc3339_millis(),
            "receipt_id": receipt_id,
            "state": "committed",
            "receipt_ids_equal": true,
                        "recovered": true
        });
        commit_codebase(
            repository,
            repository_uuid,
            &journal,
            &record,
            &payload_digest,
            &receipt_id,
            &base_receipt,
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

/// Build and sign the destination event for an admitted candidate. The
/// admitting principal's local destination key signs it; the event carries
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
            trigger: "dependent decision uses admitted evidence".to_owned(),
            loss_if_absent: 8_000,
            rationale:
                "extracted evidence requires authority resolution before it becomes direction"
                    .to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: crate::model::Bp(
            record
                .get("confidence")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(10_000) as u16,
        ),
        unresolved_uncertainty: crate::json::get_str(record, "unresolved_uncertainty")
            .map(str::to_owned),
        signer: String::new(),
        signature: String::new(),
        raw: None,
        standing: "present".to_owned(),
        provenance: "unknown".to_owned(),
        governs_paths: Vec::new(),
        anchors: Vec::new(),
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

fn principal_id() -> String {
    std::env::var("KINBASE_PRINCIPAL").unwrap_or_else(|_| "local-user".to_owned())
}

fn receipt_id(candidate: &str, destination: &str, digest: &str) -> String {
    format!(
        "receipt_{:x}",
        Sha256::digest(format!("{candidate}\0{destination}\0{digest}").as_bytes())
    )
}

fn store_name(store: crate::StoreKind) -> &'static str {
    crate::ingest::store_name(store)
}

fn decision_state(decision: &Value) -> &'static str {
    match crate::json::get_str(decision, "state").unwrap_or("committed") {
        "committed" => "committed",
        "pending" => "pending",
        "abandoned" => "abandoned",
        _ => "refused",
    }
}

fn repo() -> Result<std::path::PathBuf, ContractError> {
    std::env::current_dir().map_err(io_error)
}

/// Admit exact candidate bytes without consuming human attention. Destination
/// signatures, content addresses, durable receipts and replay remain mandatory.
fn admit_candidate(
    launcher: &crate::launcher::Launcher,
    repo: &Path,
    record: &Value,
) -> Result<Value, ContractError> {
    let candidate = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    let destination = crate::json::get_str(record, "destination").unwrap_or_default();
    let canonical = crate::json::get_str(record, "canonical").unwrap_or_default();
    let digest = sha256_text(canonical);
    if crate::json::get_str(record, "payload_digest") != Some(digest.as_str()) {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "candidate content address differs from its bytes",
            "Preserve the candidate and inspect its source.",
        ));
    }
    if let Some(previous) = personal_records("proposal-decisions.jsonl")
        .into_iter()
        .rev()
        .find(|receipt| {
            crate::json::get_str(receipt, "candidate_id") == Some(candidate)
                && crate::json::get_str(receipt, "destination") == Some(destination)
                && crate::json::get_str(receipt, "digest") == Some(digest.as_str())
        })
    {
        if matches!(decision_state(&previous), "committed" | "refused") {
            return Ok(previous);
        }
    }
    let receipt_id = receipt_id(candidate, destination, &digest);
    let receipt = json!({
        "candidate_id": candidate,
        "destination": destination,
        "decision": "admit",
        "digest": digest,
        "decided_at": now_rfc3339_millis(),
        "receipt_id": receipt_id,
        "state": "pending"
    });
    match destination_store(destination)? {
        crate::StoreKind::Personal => {
            let (fact_id, event_id) = write_fact_event(crate::StoreKind::Personal, repo, record)?;
            finalize_principal_receipt(
                &receipt,
                &json!({"fact_id": fact_id, "event_id": event_id, "state": "committed"}),
            )
        }
        _ => {
            let saga = fanout_saga_result(
                launcher,
                repo,
                record,
                destination,
                &digest,
                &receipt_id,
                &receipt,
            )?;
            let mut receipt = receipt;
            merge_receipt(&mut receipt, &saga);
            Ok(receipt)
        }
    }
}

/// Route unresolved evidence to one durable question per scope and decision.
/// Repeated sessions reuse the question instead of asking for each byte.
fn question_for_unresolved_atom(
    repo: &Path,
    atom: &Value,
) -> Result<Option<String>, ContractError> {
    if atom.get("hard_blocked").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let scope = crate::json::get_str(atom, "scope").unwrap_or("repository");
    let uncertainty =
        crate::json::get_str(atom, "unresolved_uncertainty").filter(|text| !text.trim().is_empty());
    let shared = atom
        .get("eligible_destinations")
        .and_then(Value::as_array)
        .is_some_and(|destinations| {
            destinations
                .iter()
                .filter_map(Value::as_str)
                .any(|destination| {
                    destination.starts_with("company") || destination.starts_with("codebase:")
                })
        });
    if uncertainty.is_none() && !shared {
        return Ok(None);
    }
    let authority = crate::questions::active_authority_with_repo(
        repo,
        scope,
        crate::questions::scope_kind(scope),
    );
    let owner = match authority {
        Ok(authority) => {
            if uncertainty.is_none() {
                return Ok(None);
            }
            crate::json::get_str(&authority, "authority_id")
                .unwrap_or_default()
                .to_owned()
        }
        Err(error) if error.code == "UNKNOWN_OWNER_UNRESOLVED" => String::new(),
        Err(error) => return Err(error),
    };
    let decision = format!("Resolve direction for {scope}");
    let question = if uncertainty.is_some() {
        format!(
            "Which evidence governs {scope}, and how should the unresolved interpretations be reconciled?"
        )
    } else {
        format!("Who has authority to rule on direction in {scope}?")
    };
    let evidence = vec![
        crate::json::get_str(atom, "atom_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    let unknown = crate::projector::UnknownOut {
        unknown_id: format!("unknown_{}", sha256_text(&format!("{scope}\0{question}"))),
        logical_key: crate::model::logical_key("company", scope, &decision),
        scope: scope.to_owned(),
        decision_blocked: decision.clone(),
        owner_role: if scope.starts_with("architecture:") {
            "chief-architect"
        } else {
            "company-steward"
        }
        .to_owned(),
        owner_identity: owner,
        question,
        evidence: evidence.clone(),
        loss_if_absent: 6_000,
        status: "open".to_owned(),
        kind: "unresolved-evidence".to_owned(),
    };
    let alternatives: Vec<String> = uncertainty.into_iter().map(str::to_owned).collect();
    crate::questions::ensure_question(repo, &unknown, &decision, &evidence, &alternatives)
}
