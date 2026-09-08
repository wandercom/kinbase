//! The product-owned classifier boundary (R-11).
//!
//! `guildhall classifier --json` is the only supported extraction interface.
//! It accepts one canonical observation batch on stdin and emits exactly one
//! JSON document. The deterministic provider is replayable; the Ollama provider
//! fails closed on every transport or contract violation.

use crate::error::{ContractError, ExitCode};
use crate::scanner::{ScanResult, scanner};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const CLASSIFIER_VERSION: &str = "guildhall-classifier/1";
const ALLOWED_KINDS: [&str; 6] = [
    "claim",
    "question",
    "decision",
    "constraint",
    "rationale",
    "observation",
];
const ALLOWED_CONFIDENCE: [&str; 3] = ["high", "medium", "low"];
const ALLOWED_DESTINATIONS: [&str; 4] = ["personal", "company", "codebase", "none"];
pub const CLASSIFIER_REQUEST_LIMIT: usize = 1024 * 1024;
const MAX_CLASSIFIER_INPUT: usize = 8 * 1024 * 1024;

pub fn run(
    provider: Option<&str>,
    model: Option<&str>,
    configured_model: &str,
    json: bool,
) -> Result<(), ContractError> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).map_err(|error| {
        ContractError::invariant(format!("classifier stdin is unreadable: {error}"))
    })?;
    if input.len() > MAX_CLASSIFIER_INPUT {
        return Err(ContractError::limit(
            format!("classifier input exceeds the {MAX_CLASSIFIER_INPUT}-byte bound"),
            json!({"omitted_count": 1}),
        ));
    }
    let document = crate::json::parse_strict_value(&input).map_err(|error| {
        ContractError::invariant(format!(
            "classifier input is not a strict JSON object: {error}"
        ))
    })?;
    let selected_provider = provider.map(str::to_owned).unwrap_or_else(|| {
        if configured_model.starts_with("ollama:")
            || model.is_some_and(|model| model.starts_with("ollama:"))
        {
            "ollama".to_owned()
        } else {
            "deterministic".to_owned()
        }
    });
    let output = match selected_provider.as_str() {
        "deterministic" => deterministic(&document)?,
        "ollama" => {
            let name = model
                .map(|model| model.trim_start_matches("ollama:"))
                .or_else(|| configured_model.strip_prefix("ollama:"))
                .ok_or_else(|| {
                    unauthorized("Ollama provider requires --model or classifier.model")
                })?;
            if name.trim().is_empty() {
                return Err(unauthorized(
                    "Ollama provider requires a nonempty model name",
                ));
            }
            ollama(name.trim(), &document)?
        }
        other => {
            return Err(ContractError::invariant(format!(
                "unsupported classifier provider `{other}`; use deterministic or ollama"
            )));
        }
    };
    if json {
        println!("{}", crate::json::canonical_text(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    }
    Ok(())
}

/// Split classifier input at whole-observation boundaries. A byte-sized cut
/// can split a JSON document and make a well-formed source look like EOF; each
/// emitted request is itself one complete strict JSON object.
pub(crate) fn request_batches(observations: Vec<Value>) -> Result<Vec<Value>, ContractError> {
    if observations.is_empty() {
        return Ok(vec![json!({ "observations": [] })]);
    }
    let mut batches = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    for observation in observations {
        let mut candidate = current.clone();
        candidate.push(observation.clone());
        let request = json!({ "observations": candidate });
        let bytes = crate::json::canonical_bytes(&request).len();
        if bytes <= CLASSIFIER_REQUEST_LIMIT {
            current = candidate;
            continue;
        }
        if !current.is_empty() {
            batches.push(json!({ "observations": current }));
            candidate = vec![observation];
        }
        let bytes = crate::json::canonical_bytes(&json!({ "observations": candidate })).len();
        if bytes > CLASSIFIER_REQUEST_LIMIT {
            return Err(ContractError::limit(
                format!(
                    "a single classifier observation exceeds the {CLASSIFIER_REQUEST_LIMIT}-byte request bound"
                ),
                json!({
                    "omitted_count": 1,
                    "bytes": bytes,
                    "ceiling_bytes": CLASSIFIER_REQUEST_LIMIT
                }),
            ));
        }
        current = candidate;
    }
    if !current.is_empty() {
        batches.push(json!({ "observations": current }));
    }
    Ok(batches)
}

/// Canonical records reject control characters, but native source bodies may
/// contain line breaks. Preserve sentence boundaries at those breaks and make
/// every otherwise-forbidden code point an explicit space so a classifier
/// request can never silently canonicalize to zero bytes.
pub(crate) fn request_body(text: &str) -> String {
    let line_breaks_replaced = text
        .replace("\r\n", ". ")
        .replace('\r', ". ")
        .replace('\n', ". ");
    line_breaks_replaced
        .chars()
        .map(|character| {
            let code = character as u32;
            if code <= 0x1f
                || (0x80..=0x9f).contains(&code)
                || code == 0x61c
                || (0x200e..=0x200f).contains(&code)
                || (0x202a..=0x202e).contains(&code)
                || (0x2066..=0x2069).contains(&code)
                || (0xfdd0..=0xfdef).contains(&code)
                || ((code & 0xfffe) == 0xfffe && code <= 0x10ffff)
            {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub(crate) fn deterministic(document: &Value) -> Result<Value, ContractError> {
    let observations = observations(document)?;
    let mut atoms = Vec::new();
    for observation in observations {
        let map = observation
            .as_object()
            .ok_or_else(|| invariant("each observation must be an object"))?;
        require_observation(map)?;
        let body = map.get("body").and_then(Value::as_str).unwrap_or_default();
        let base = base_confidence(map);
        for sentence in sentences(body) {
            let confidence = if base == "low" {
                "low"
            } else {
                let hedged = sentence_confidence(&sentence);
                if base == "medium" && hedged == "high" {
                    "medium"
                } else {
                    hedged
                }
            };
            atoms.push(atom_from_observation(map, &sentence, confidence, None));
        }
    }
    Ok(json!({
        "classifier_version": CLASSIFIER_VERSION,
        "provider": "deterministic",
        "atoms": atoms
    }))
}

fn ollama(model: &str, document: &Value) -> Result<Value, ContractError> {
    observations(document)?;
    let instruction = r#"Classify each observation into minimal atoms. Return exactly one JSON object with keys classifier_version, provider, atoms. atoms items have exactly atom_id, observation_id, text, atom_kind, scope, confidence, proposed_destinations, taint, provenance, unresolved_uncertainty. One atom is exactly one claim, question, decision, constraint, rationale, or observation. Split mixed-scope messages into separate atoms. Destinations: personal means the principal's private conversational memory; company means organization-wide direction owned by a steward or named authority; codebase means repository-scoped knowledge; none means ambiguous non-facts, temporary suggestions, questions, or hedges. Use confidence low for ambiguity and never guess a shared destination. No markdown or extra keys."#;
    let request = json!({
        "model": model,
        "stream": false,
        "format": "json",
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": crate::json::canonical_text(document)}
        ],
        "options": {"temperature": 0}
    });
    let response = post_ollama(&request)?;
    let parsed: Value = serde_json::from_slice(&response)
        .map_err(|error| unauthorized(format!("Ollama response is not JSON: {error}")))?;
    let candidate = if parsed.get("atoms").is_some() {
        parsed
    } else {
        let content = parsed
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| unauthorized("Ollama response has no strict classifier document"))?;
        serde_json::from_str(content)
            .map_err(|error| unauthorized(format!("Ollama message is not JSON: {error}")))?
    };
    validate_output(&candidate)?;
    Ok(normalize_ollama_output(&candidate, document))
}

fn normalize_ollama_output(candidate: &Value, document: &Value) -> Value {
    let mut model_atoms_by_observation: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    if let Some(atoms) = candidate.get("atoms").and_then(Value::as_array) {
        for atom in atoms {
            if let Some(observation_id) = atom.get("observation_id").and_then(Value::as_str) {
                model_atoms_by_observation
                    .entry(observation_id.to_owned())
                    .or_default()
                    .push(atom);
            }
        }
    }

    let mut atoms = Vec::new();
    let Ok(observations) = observations(document) else {
        return candidate.clone();
    };
    for observation in observations {
        let Some(map) = observation.as_object() else {
            continue;
        };
        let observation_id = map
            .get("observation_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut emitted: BTreeSet<String> = BTreeSet::new();
        let model_atoms = model_atoms_by_observation.get(&observation_id);
        let source_atoms: Vec<(String, &str, Vec<String>)> = model_atoms
            .map(|model_atoms| {
                model_atoms
                    .iter()
                    .filter_map(|atom| {
                        let text = atom.get("text").and_then(Value::as_str)?;
                        let confidence = atom
                            .get("confidence")
                            .and_then(Value::as_str)
                            .unwrap_or("medium");
                        let destinations = atom
                            .get("proposed_destinations")
                            .and_then(Value::as_array)
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .filter(|destination| {
                                        ALLOWED_DESTINATIONS.contains(destination)
                                    })
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        Some((text.to_owned(), confidence, destinations))
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                map.get("body")
                    .and_then(Value::as_str)
                    .map(|body| {
                        sentences(body)
                            .into_iter()
                            .map(|text| (text, "medium", Vec::new()))
                            .collect()
                    })
                    .unwrap_or_default()
            });
        for (source_text, model_confidence, model_destinations) in source_atoms {
            for sentence in sentences(&source_text) {
                if !emitted.insert(sentence.clone()) {
                    continue;
                }
                let sentence_confidence = sentence_confidence(&sentence);
                let confidence = if model_confidence == "low" || is_nonfact_statement(&sentence) {
                    "low"
                } else if model_confidence == "high" {
                    "high"
                } else {
                    sentence_confidence
                };
                let model_destinations: Vec<&str> =
                    model_destinations.iter().map(String::as_str).collect();
                atoms.push(atom_from_observation(
                    map,
                    &sentence,
                    confidence,
                    Some(&model_destinations),
                ));
            }
        }
    }

    json!({
        "classifier_version": candidate.get("classifier_version").cloned().unwrap_or_else(|| json!(CLASSIFIER_VERSION)),
        "provider": "ollama",
        "atoms": atoms
    })
}

fn post_ollama(request: &Value) -> Result<Vec<u8>, ContractError> {
    let body = crate::json::canonical_bytes(request);
    let address = "127.0.0.1:11434"
        .to_socket_addrs()
        .map_err(|error| unreachable(format!("Ollama loopback address is malformed: {error}")))?
        .next()
        .ok_or_else(|| unreachable("Ollama loopback address did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(250))
        .map_err(|error| unreachable(format!("Ollama is unreachable: {error}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let head = format!(
        "POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    stream
        .write_all(&body)
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    stream
        .flush()
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| unauthorized("Ollama returned a malformed HTTP response"))?;
    let header = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| unauthorized("Ollama returned a malformed HTTP status"))?;
    if status != 200 {
        return Err(unauthorized(format!(
            "Ollama returned HTTP status {status}"
        )));
    }
    let mut body = response[split + 4..].to_vec();
    if header.contains("transfer-encoding:chunked") {
        body = decode_chunked(&body)?;
    }
    if body.len() > 4 * 1024 * 1024 {
        return Err(unauthorized("Ollama response exceeds the 4 MiB bound"));
    }
    Ok(body)
}

fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>, ContractError> {
    let mut output = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| unauthorized("Ollama chunked response is malformed"))?;
        let size_text = std::str::from_utf8(&bytes[..end])
            .map_err(|_| unauthorized("Ollama chunk size is malformed"))?;
        let size = usize::from_str_radix(size_text.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| unauthorized("Ollama chunk size is malformed"))?;
        bytes = &bytes[end + 2..];
        if size == 0 {
            break;
        }
        if size > bytes.len() {
            return Err(unauthorized("Ollama chunked response is truncated"));
        }
        output.extend_from_slice(&bytes[..size]);
        if bytes.len() < size + 2 {
            return Err(unauthorized("Ollama chunked response is truncated"));
        }
        bytes = &bytes[size + 2..];
    }
    Ok(output)
}

fn observations(document: &Value) -> Result<&Vec<Value>, ContractError> {
    document
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| invariant("classifier input must contain an observations array"))
}

fn require_observation(map: &Map<String, Value>) -> Result<(), ContractError> {
    for key in [
        "observation_id",
        "source_kind",
        "source_identity",
        "content_digest",
        "observed_at",
        "disposition",
        "extraction_version",
    ] {
        if !map
            .get(key)
            .and_then(Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
        {
            return Err(invariant(format!(
                "classifier observation is missing nonempty string {key}"
            )));
        }
    }
    if map.get("body").and_then(Value::as_str).is_none()
        && map.get("body_ref").and_then(Value::as_str).is_none()
    {
        return Err(invariant(
            "classifier observation must carry body or body_ref",
        ));
    }
    Ok(())
}

fn base_confidence(map: &Map<String, Value>) -> &'static str {
    let explicit = map.get("confidence");
    if let Some(Value::String(value)) = explicit {
        return match value.as_str() {
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "medium",
        };
    }
    if let Some(number) = explicit.and_then(Value::as_f64) {
        if number >= 7000.0 || (number > 0.0 && number <= 1.0 && number >= 0.7) {
            return "high";
        }
        if number >= 4000.0 || (number > 0.0 && number <= 1.0 && number >= 0.4) {
            return "medium";
        }
        return "low";
    }
    match map.get("disposition").and_then(Value::as_str) {
        Some("current") => "high",
        Some("draft") | Some("proposed") | Some("open") => "medium",
        _ => "low",
    }
}

fn sentence_confidence(text: &str) -> &'static str {
    if is_nonfact_statement(text) {
        return "low";
    }
    let lower = text.to_lowercase();
    const HEDGES: [&str; 16] = [
        "maybe",
        "perhaps",
        "possibly",
        "probably",
        "might",
        "could",
        "seems",
        "appears",
        "not sure",
        "unclear",
        "uncertain",
        "i think",
        "we think",
        "as far as i know",
        "not certain",
        "hedged",
    ];
    if HEDGES.iter().any(|hedge| lower.contains(hedge)) {
        "low"
    } else if lower.contains("likely") || lower.contains("should") {
        "medium"
    } else {
        "high"
    }
}

fn is_nonfact_statement(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_lowercase();
    trimmed.ends_with('?')
        || lower.starts_with("what ")
        || lower.starts_with("why ")
        || lower.starts_with("how ")
        || lower.starts_with("should ")
        || lower.contains("maybe")
        || lower.contains("perhaps")
        || lower.contains("possibly")
        || lower.contains("not sure")
        || lower.contains("unclear")
        || lower.contains("uncertain")
        || lower.contains("i think")
        || lower.contains("we think")
        || lower.contains("i suggest")
        || lower.contains("we should")
        || lower.contains("temporary")
        || lower.contains("for now")
}

fn is_company_statement(lower: &str) -> bool {
    [
        "architecture decision",
        "architecture direction",
        "chief architect",
        "company policy",
        "organization",
        "company-wide",
        "corporate",
        "product policy",
        "standard",
        "governance",
        "roadmap",
        "company decision",
        "all teams",
        "every team",
        "named authority",
        "steward",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn is_codebase_statement(lower: &str) -> bool {
    [
        "repository",
        "codebase",
        "code",
        "function",
        "module",
        "test",
        "tests",
        "build",
        "dependency",
        "dependencies",
        "api",
        "schema",
        "migration",
        "service",
        "scheduler",
        "worker",
        "queue",
        "bug",
        "compiler",
        "type",
        "interface",
        "library",
        "branch",
        "commit",
        "deployment",
        "config",
        "configuration",
        "database",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn sentences(body: &str) -> Vec<String> {
    let normalized = body.replace(['\r', '\n'], ". ");
    let mut output = Vec::new();
    let mut current = String::new();
    let mut characters = normalized.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '.' || character == '!' || character == '?' {
            push_sentence(&mut output, &current);
            current.clear();
        } else {
            current.push(character);
        }
    }
    push_sentence(&mut output, &current);
    output
}

fn push_sentence(output: &mut Vec<String>, sentence: &str) {
    let trimmed = sentence.trim();
    if trimmed.chars().any(char::is_alphabetic) {
        output.push(trimmed.to_owned());
    }
}

fn atom_from_observation(
    map: &Map<String, Value>,
    text: &str,
    confidence: &str,
    model_destinations: Option<&[&str]>,
) -> Value {
    let mut atom = atom_from_observation_base(map, text, confidence);
    if confidence == "low" {
        atom["proposed_destinations"] = json!(["none"]);
    } else if let Some(destinations) = model_destinations {
        let destinations: Vec<String> = destinations
            .iter()
            .filter(|destination| ALLOWED_DESTINATIONS.contains(destination))
            .map(|destination| (*destination).to_owned())
            .collect();
        if !destinations.is_empty() {
            atom["proposed_destinations"] = json!(destinations);
        }
    }
    atom
}

fn atom_from_observation_base(map: &Map<String, Value>, text: &str, confidence: &str) -> Value {
    let observation_id = map
        .get("observation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_kind = map
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_identity = map
        .get("source_identity")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let content_digest = map
        .get("content_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope = map
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("unscoped");
    let scan: ScanResult = scanner(text);
    let hard_block = scan.taints.iter().any(|taint| taint.hard_block());
    let mut taints: Vec<String> = scan
        .taints
        .iter()
        .map(|taint| taint.as_str().to_owned())
        .collect();
    if let Some(taint) = crate::classify::provenance_taint(source_kind) {
        let value = taint.as_str().to_owned();
        if !taints.contains(&value) {
            taints.push(value);
        }
    }
    // The classifier reports semantic destinations only.  Session promotion
    // separately records the privacy-eligible host boundary, so a Personal
    // source can yield a multi-destination prediction without claiming that
    // the raw classifier itself emitted the boundary label.
    let mut destinations: Vec<String> = Vec::new();
    let lower = text.to_lowercase();
    if !hard_block && confidence != "low" && !is_nonfact_statement(text) {
        if is_company_statement(&lower) || scope.contains("company") {
            destinations = vec!["company".to_owned()];
        } else if is_codebase_statement(&lower) || scope.contains("repository") {
            destinations = vec!["codebase".to_owned()];
        } else if is_personal_statement(&lower) {
            destinations = vec!["personal".to_owned()];
        }
    }
    if hard_block || confidence == "low" {
        destinations = vec!["none".to_owned()];
    }
    if destinations.is_empty() {
        destinations.push("none".to_owned());
    }
    let atom_id = format!(
        "atom_{:x}",
        Sha256::digest(format!("{observation_id}\0{text}").as_bytes())
    );
    json!({
        "atom_id": atom_id,
        "observation_id": observation_id,
        "text": text,
        "atom_kind": infer_kind(text),
        "scope": scope,
        "confidence": confidence,
        "proposed_destinations": destinations,
        "taint": taints,
        "provenance": {
            "source_kind": source_kind,
            "source_identity": source_identity,
            "content_digest": content_digest
        },
        "unresolved_uncertainty": if confidence == "low" { "low-confidence shared labels were demoted to none" } else { "" }
    })
}

fn is_personal_statement(lower: &str) -> bool {
    [
        " i ",
        "my ",
        " me",
        "myself",
        "yesterday i",
        "last night i",
        "personal anecdote",
        "private atom",
    ]
    .iter()
    .any(|token| lower.starts_with(token.trim_start()) || lower.contains(token))
        || lower.starts_with("i ")
}

fn infer_kind(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    if lower.contains('?')
        || lower.starts_with("what ")
        || lower.starts_with("why ")
        || lower.starts_with("how ")
    {
        "question"
    } else if [
        "must",
        "required",
        "shall",
        "always",
        "never",
        "do not",
        "don't",
        "only",
        "forbid",
        "forbidden",
        "ensure",
    ]
    .iter()
    .any(|token| lower.contains(token))
    {
        "constraint"
    } else if lower.contains("because")
        || lower.contains("rationale")
        || lower.contains("the reason is")
    {
        "rationale"
    } else if [
        "we decided",
        "decision",
        "we choose",
        "we chose",
        "use ",
        "adopt",
        "selected",
        "preferred approach",
        "agreed to",
    ]
    .iter()
    .any(|token| lower.contains(token))
    {
        "decision"
    } else {
        "claim"
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|item| item == value) {
        values.push(value.to_owned());
    }
}

pub fn validate_output(document: &Value) -> Result<(), ContractError> {
    let map = document
        .as_object()
        .ok_or_else(|| unauthorized("classifier output must be an object"))?;
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["atoms", "classifier_version", "provider"] {
        return Err(unauthorized(
            "classifier output keys violate the strict contract",
        ));
    }
    if !["deterministic", "ollama"].contains(
        &map.get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return Err(unauthorized(
            "classifier provider is outside the closed vocabulary",
        ));
    }
    let _ = map
        .get("classifier_version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unauthorized("classifier_version must be a nonempty string"))?;
    let atoms = map
        .get("atoms")
        .and_then(Value::as_array)
        .ok_or_else(|| unauthorized("atoms must be an array"))?;
    for atom in atoms {
        let atom = atom
            .as_object()
            .ok_or_else(|| unauthorized("each atom must be an object"))?;
        let mut keys: Vec<&str> = atom.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if keys
            != [
                "atom_id",
                "atom_kind",
                "confidence",
                "observation_id",
                "proposed_destinations",
                "provenance",
                "scope",
                "taint",
                "text",
                "unresolved_uncertainty",
            ]
        {
            return Err(unauthorized("atom keys violate the strict contract"));
        }
        for key in [
            "atom_id",
            "observation_id",
            "text",
            "scope",
            "unresolved_uncertainty",
        ] {
            if !atom.get(key).map(Value::is_string).unwrap_or(false) {
                return Err(unauthorized(format!("atom.{key} must be a string")));
            }
        }
        if !ALLOWED_KINDS.contains(
            &atom
                .get("atom_kind")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) || !ALLOWED_CONFIDENCE.contains(
            &atom
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(unauthorized(
                "atom atom_kind or confidence is outside the closed vocabulary",
            ));
        }
        let Some(destinations) = atom.get("proposed_destinations").and_then(Value::as_array) else {
            return Err(unauthorized("atom proposed_destinations must be an array"));
        };
        for destination in destinations {
            if !ALLOWED_DESTINATIONS.contains(&destination.as_str().unwrap_or_default()) {
                return Err(unauthorized(
                    "atom destination is outside the closed vocabulary",
                ));
            }
        }
        let Some(taints) = atom.get("taint").and_then(Value::as_array) else {
            return Err(unauthorized("atom taint must be an array"));
        };
        if taints.iter().any(|value| !value.is_string()) {
            return Err(unauthorized("atom taint entries must be strings"));
        }
        let provenance = atom
            .get("provenance")
            .and_then(Value::as_object)
            .ok_or_else(|| unauthorized("atom provenance must be an object"))?;
        let mut provenance_keys: Vec<&str> = provenance.keys().map(String::as_str).collect();
        provenance_keys.sort_unstable();
        if provenance_keys != ["content_digest", "source_identity", "source_kind"] {
            return Err(unauthorized(
                "atom provenance keys violate the strict contract",
            ));
        }
        for value in provenance.values() {
            if !value.is_string() {
                return Err(unauthorized("atom provenance values must be strings"));
            }
        }
    }
    Ok(())
}

fn invariant(message: impl Into<String>) -> ContractError {
    ContractError::invariant(message)
}

fn unauthorized(message: impl Into<String>) -> ContractError {
    ContractError::integrity(
        "PROCESSOR_UNAUTHORIZED",
        message,
        "The classifier response violated its strict contract; no guess was promoted.",
    )
}

fn unreachable(message: impl Into<String>) -> ContractError {
    ContractError::new(
        "COMPANY_UNREACHABLE",
        message,
        "Start or repair the configured local processor; no fallback guess is permitted.",
        true,
        ExitCode::DependencyUnavailable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_provider_routes_mixed_atoms_to_different_destinations() {
        let document = json!({
            "observations": [{
                "observation_id": "obs-mixed",
                "source_kind": "codex_jsonl",
                "source_identity": "source:test",
                "content_digest": "digest",
                "observed_at": "2026-09-08T10:00:00.000Z",
                "disposition": "current",
                "extraction_version": "1",
                "scope": "mixed",
                "body": "I kept my personal notes yesterday. The repository must never commit generated fixtures. Every organization-wide architecture decision must use company review. Maybe we should ask whether this is correct."
            }]
        });
        let output = deterministic(&document).expect("deterministic classifier");
        let atoms = output
            .get("atoms")
            .and_then(Value::as_array)
            .expect("atoms");
        assert_eq!(atoms.len(), 4);
        assert_eq!(
            atoms[0].get("proposed_destinations").unwrap(),
            &json!(["personal"])
        );
        assert_eq!(
            atoms[1].get("proposed_destinations").unwrap(),
            &json!(["codebase"])
        );
        assert_eq!(
            atoms[2].get("proposed_destinations").unwrap(),
            &json!(["company"])
        );
        assert_eq!(
            atoms[3].get("proposed_destinations").unwrap(),
            &json!(["none"])
        );
        assert_eq!(atoms[3].get("confidence").unwrap(), "low");
        assert!(
            atoms
                .iter()
                .any(|atom| atom.get("confidence") == Some(&Value::String("low".to_owned())))
        );
    }
}
