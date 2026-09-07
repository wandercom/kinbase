use crate::classify::{EXTRACTION_VERSION, atomize, source_kind_is_supported};
use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_bytes;
use crate::model::{Atom, CompanyReference, Distortion, FactEvent, Observation};
use crate::scanner::hard_blocked;
use crate::time::{now_rfc3339_millis, parse_rfc3339_millis};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_ITEMS: usize = 10_000;

#[derive(Debug)]
struct NativeRecord {
    native_id: String,
    statement: String,
    scope: String,
    confidence: u16,
    disposition: String,
    asserted_at: Option<String>,
    effective_from: Option<String>,
    effective_until: Option<String>,
}

pub fn ingest(
    repo: &Path,
    source_kind: &str,
    source: &Path,
    checkpoint: Option<&str>,
    json: bool,
) -> Result<(), ContractError> {
    if !source_kind_is_supported(source_kind) {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            format!("unsupported source kind: {source_kind}"),
            "Use one of the ratified source adapter classes.",
            false,
            ExitCode::Refused,
        ));
    }
    let bytes = std::fs::read(source).map_err(io_error)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "source body exceeds 1 MiB",
            "Split the source into bounded adapter batches.",
            false,
            ExitCode::Refused,
        ));
    }
    let records = parse_native(source_kind, &bytes).map_err(|message| {
        ContractError::new(
            "CONFIG_INVARIANT",
            message,
            "Use a valid native source envelope.",
            false,
            ExitCode::Refused,
        )
    })?;
    if records.len() > MAX_ITEMS {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "observation batch exceeds 10,000 items",
            "Use an explicit checkpoint and smaller batches.",
            false,
            ExitCode::Refused,
        ));
    }
    let store = store_for_source(source_kind);
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    if matches!(store, crate::StoreKind::Personal) {
        crate::store::write_private_body(&root, &bytes).map_err(io_error)?;
    }
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo))
        .transpose()?;
    let source_identity = source_identity(source_kind, source);
    let now = now_rfc3339_millis();
    let revision = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::git_revision(repo).ok())
        .flatten();
    let branch = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::git_branch(repo).ok())
        .flatten();
    let trust_class = (store == crate::StoreKind::Codebase)
        .then(|| repository_trust_class(repo, source))
        .unwrap_or("approved-source");
    let mut observation_count = 0;
    let mut atom_count = 0;
    let mut fact_count = 0;
    let mut skipped = 0;
    for record in records {
        let record_bytes = record.statement.as_bytes();
        let digest = sha256_bytes(record_bytes);
        let observation_id = format!(
            "obs_{:x}",
            Sha256::digest(format!("{source_identity}\0{}\0{digest}", record.native_id).as_bytes())
        );
        let observation = Observation {
            observation_id: observation_id.clone(),
            source_kind: source_kind.to_owned(),
            source_identity: source_identity.clone(),
            native_id: record.native_id.clone(),
            content_digest: digest.clone(),
            repository_id: repository_id.clone(),
            revision: revision.clone(),
            branch: branch.clone(),
            disposition: record.disposition.clone(),
            observed_at: now.clone(),
            asserted_at: record.asserted_at.clone(),
            effective_from: record.effective_from.clone(),
            effective_until: record.effective_until.clone(),
            body_ref: format!("sha256:{digest}"),
            extraction_version: EXTRACTION_VERSION.to_owned(),
        };
        let existing = crate::store::read_records(store, repo, "observations.jsonl")
            .unwrap_or_default()
            .into_iter()
            .find(|value| {
                value.get("observation_id").and_then(Value::as_str) == Some(&observation_id)
            });
        if existing.is_some() {
            skipped += 1;
            continue;
        }
        let observation_value = serde_json::to_value(&observation)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        mark_changed_source(
            store,
            repo,
            &source_identity,
            &record.native_id,
            &digest,
            &now,
        )?;
        crate::store::append_record(store, repo, "observations.jsonl", &observation_value)
            .map_err(io_error)?;
        observation_count += 1;
        if hard_blocked(&record.statement) && store != crate::StoreKind::Personal {
            skipped += 1;
            continue;
        }
        let atom = atomize(
            source_kind,
            &record.native_id,
            &record.statement,
            &record.scope,
            record.confidence,
            &observation_id,
            &digest,
            repository_id.as_deref(),
        );
        let atom_value = serde_json::to_value(&atom)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        crate::store::append_record(store, repo, "atoms.jsonl", &atom_value).map_err(io_error)?;
        atom_count += 1;
        let eligible = store != crate::StoreKind::Personal
            && trust_class == "merged-default"
            && record.disposition == "current";
        if eligible {
            write_source_fact_event(
                store,
                repo,
                &atom,
                &observation,
                &record,
                repository_id.as_deref(),
            )?;
            fact_count += 1;
        }
    }
    let result = json!({
        "status": "ingested",
        "adapter": source_kind,
        "observation_count": observation_count,
        "atom_count": atom_count,
        "fact_count": fact_count,
        "idempotent_count": skipped,
        "checkpoint": checkpoint,
        "source_digest": sha256_bytes(&bytes),
        "store": store_name(store)
    });
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("status: ingested");
        println!("adapter: {source_kind}");
        println!("observation_count: {observation_count}");
        println!("atom_count: {atom_count}");
        println!("fact_count: {fact_count}");
        println!("idempotent_count: {skipped}");
        println!("store: {}", store_name(store));
    }
    Ok(())
}

fn parse_native(source_kind: &str, bytes: &[u8]) -> Result<Vec<NativeRecord>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    match source_kind {
        "codex_jsonl" | "claude_jsonl" | "git_history" | "kindex" | "runtime_evidence"
        | "github_export" => parse_json_records(source_kind, text),
        _ => parse_text_lines(source_kind, text),
    }
}

fn parse_json_records(source_kind: &str, text: &str) -> Result<Vec<NativeRecord>, String> {
    let mut records = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        collect_json_value(source_kind, &value, &mut records)?;
        return Ok(records);
    }
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("native JSONL line {}: {error}", index + 1))?;
        collect_json_value(source_kind, &value, &mut records)?;
    }
    Ok(records)
}

fn collect_json_value(
    source_kind: &str,
    value: &Value,
    records: &mut Vec<NativeRecord>,
) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_json_value(source_kind, value, records)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            if is_record_container(map) {
                let native_id = map
                    .get("id")
                    .or_else(|| map.get("number"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("record:{}", records.len() + 1));
                let statement = extract_statement(map).unwrap_or_else(|| canonical_summary(map));
                let disposition = source_disposition(map);
                records.push(NativeRecord {
                    native_id,
                    statement,
                    scope: extract_scope(map).unwrap_or_else(|| default_scope(source_kind)),
                    confidence: source_confidence(source_kind, &disposition),
                    disposition,
                    asserted_at: time_field(
                        map,
                        &["asserted_at", "created_at", "timestamp", "closed_at"],
                    ),
                    effective_from: time_field(map, &["effective_from", "started_at"]),
                    effective_until: time_field(
                        map,
                        &["effective_until", "expires_at", "fresh_until"],
                    ),
                });
                return Ok(());
            }
            for key in [
                "payload", "message", "content", "data", "items", "events", "facts", "nodes",
            ] {
                if let Some(child) = map.get(key) {
                    collect_json_value(source_kind, child, records)?;
                }
            }
            Ok(())
        }
        Value::String(value) => {
            records.push(text_record(source_kind, records.len(), value));
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_record_container(map: &Map<String, Value>) -> bool {
    [
        "message",
        "text",
        "body",
        "statement",
        "summary",
        "title",
        "answer",
        "prompt",
        "output",
        "stdout",
    ]
    .iter()
    .any(|key| map.get(*key).is_some_and(Value::is_string))
        || map.contains_key("state")
}

fn extract_statement(map: &Map<String, Value>) -> Option<String> {
    for key in [
        "statement",
        "message",
        "text",
        "body",
        "summary",
        "title",
        "answer",
        "prompt",
        "output",
        "stdout",
    ] {
        if let Some(Value::String(value)) = map.get(key) {
            return Some(value.clone());
        }
    }
    if let Some(Value::Array(parts)) = map.get("content") {
        let text = parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    None
}

fn canonical_summary(map: &Map<String, Value>) -> String {
    let value = Value::Object(map.clone());
    crate::json::canonical_text(&value)
}

fn source_disposition(map: &Map<String, Value>) -> String {
    let state = map
        .get("state")
        .or_else(|| map.get("status"))
        .or_else(|| map.get("disposition"))
        .and_then(Value::as_str)
        .unwrap_or("current")
        .to_lowercase();
    match state.as_str() {
        "rejected" | "closed" | "reverted" | "failed" => state,
        "merged" | "approved" | "deployed" | "passed" => "current".to_owned(),
        "draft" | "proposed" | "open" | "experiment" | "incident" => state,
        _ => "current".to_owned(),
    }
}

fn parse_text_lines(source_kind: &str, text: &str) -> Result<Vec<NativeRecord>, String> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records.push(text_record(source_kind, index, line));
    }
    Ok(records)
}

fn text_record(source_kind: &str, index: usize, statement: &str) -> NativeRecord {
    let disposition =
        if statement.contains("STATUS: rejected") || statement.contains("STATUS: reverted") {
            "rejected".to_owned()
        } else if statement.contains("STATUS: draft") || statement.contains("STATUS: proposed") {
            "draft".to_owned()
        } else {
            "current".to_owned()
        };
    NativeRecord {
        native_id: format!("line:{}", index + 1),
        statement: statement.trim().to_owned(),
        scope: default_scope(source_kind),
        confidence: source_confidence(source_kind, &disposition),
        disposition,
        asserted_at: None,
        effective_from: None,
        effective_until: None,
    }
}

fn default_scope(source_kind: &str) -> String {
    match source_kind {
        "repo_code" | "repo_tests" | "git_history" | "docs_adr" | "github_export"
        | "runtime_evidence" | "kindex" => "repository".to_owned(),
        "authority_answer" => "architecture:company".to_owned(),
        _ => "host-session".to_owned(),
    }
}

fn extract_scope(map: &Map<String, Value>) -> Option<String> {
    map.get("scope")
        .or_else(|| map.get("authority_scope"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn source_confidence(source_kind: &str, disposition: &str) -> u16 {
    if disposition == "current" {
        match source_kind {
            "authority_answer" => 9_800,
            "github_export" | "git_history" | "runtime_evidence" | "kindex" => 8_000,
            "repo_code" | "repo_tests" | "docs_adr" => 7_000,
            _ => 6_000,
        }
    } else {
        4_000
    }
}

fn time_field(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(value)) = map.get(*key) {
            if parse_rfc3339_millis(value).is_ok() {
                return Some(value.clone());
            }
        }
    }
    None
}

fn mark_changed_source(
    store: crate::StoreKind,
    repo: &Path,
    source_identity: &str,
    native_id: &str,
    digest: &str,
    now: &str,
) -> Result<(), ContractError> {
    let prior = crate::store::read_records(store, repo, "observations.jsonl")
        .unwrap_or_default()
        .into_iter()
        .filter(|value| {
            value.get("source_identity").and_then(Value::as_str) == Some(source_identity)
                && value.get("native_id").and_then(Value::as_str) == Some(native_id)
        })
        .max_by(|left, right| {
            left.get("observed_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    right
                        .get("observed_at")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        });
    if let Some(prior) = prior {
        let prior_digest = prior
            .get("content_digest")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if prior_digest != digest {
            let record = json!({
                "schema": "guildhall-source-lifecycle/1",
                "source_identity": source_identity,
                "native_id": native_id,
                "transition": "superseded",
                "old_content_digest": prior_digest,
                "new_content_digest": digest,
                "observed_at": now
            });
            crate::store::append_record(store, repo, "source-lifecycle.jsonl", &record)
                .map_err(io_error)?;
        }
    }
    Ok(())
}

fn write_source_fact_event(
    store: crate::StoreKind,
    repo: &Path,
    atom: &Atom,
    observation: &Observation,
    record: &NativeRecord,
    repository_id: Option<&str>,
) -> Result<(), ContractError> {
    let logical_key = format!(
        "logical_{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0{}",
                atom.provenance, observation.source_identity, observation.native_id
            )
            .as_bytes()
        )
    );
    let old_event = crate::store::read_events(&crate::store::store_root(store, repo))
        .unwrap_or_default()
        .into_iter()
        .find(|event| event.logical_key == logical_key);
    let fact_id = format!(
        "fact_{:x}",
        Sha256::digest(format!("{}\0{}", atom.scope, atom.statement).as_bytes())
    );
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(
            format!(
                "{logical_key}\0{}\0{}",
                atom.statement, observation.content_digest
            )
            .as_bytes()
        )
    );
    let authority_id = if store == crate::StoreKind::Company {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let signer = authority_id.to_owned();
    let mut event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id,
        store_kind: store_name(store).to_owned(),
        authority_id: authority_id.to_owned(),
        authority_scope: atom.scope.clone(),
        repository_id: repository_id.map(str::to_owned),
        fact_id,
        logical_key,
        atom_kind: atom.atom_kind.clone(),
        scope: atom.scope.clone(),
        statement: atom.statement.clone(),
        evidence_refs: vec![observation.observation_id.clone()],
        asserted_at: observation.observed_at.clone(),
        effective_from: observation
            .effective_from
            .clone()
            .unwrap_or_else(|| observation.observed_at.clone()),
        effective_until: observation.effective_until.clone(),
        disposition: record.disposition.clone(),
        distortion: distortion_for(&atom.atom_kind),
        parents: old_event
            .as_ref()
            .map(|old| old.fact_id.clone())
            .into_iter()
            .collect(),
        supersedes: old_event
            .as_ref()
            .map(|old| old.event_id.clone())
            .into_iter()
            .collect(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: atom.confidence,
        unresolved_uncertainty: atom.unresolved_uncertainty.clone(),
        signer,
        signature: String::new(),
    };
    let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
    let unsigned = crate::store::event_canonical_text(&event);
    event.signature = crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    crate::store::write_content_addressed_event(&root, &event).map_err(io_error)?;
    Ok(())
}

fn distortion_for(atom_kind: &str) -> Distortion {
    let loss = match atom_kind {
        "constraint" => 9_000,
        "decision" => 7_000,
        "question" => 5_000,
        "rationale" => 4_000,
        _ => 3_000,
    };
    Distortion {
        trigger: "dependent decision".to_owned(),
        loss_if_absent: loss,
        rationale: "loss is tied to the dependent decision and atom kind".to_owned(),
    }
}

fn repository_trust_class(repo: &Path, source: &Path) -> &'static str {
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch"])
        .arg(source)
        .current_dir(repo)
        .output()
        .is_ok_and(|output| output.status.success());
    if !tracked {
        return "uncommitted-worktree";
    }
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .arg(source)
        .current_dir(repo)
        .output()
        .is_ok_and(|output| !output.stdout.is_empty());
    if dirty {
        return "uncommitted-worktree";
    }
    let branch = crate::repository::git_branch(repo).unwrap_or_default();
    let default_branch = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .current_dir(repo)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().trim_start_matches("origin/").to_owned())
        .unwrap_or_else(|| "main".to_owned());
    if branch != default_branch {
        "unreviewed-branch"
    } else {
        "merged-default"
    }
}

fn source_identity(source_kind: &str, source: &Path) -> String {
    format!(
        "source:{source_kind}:{:x}",
        Sha256::digest(source.to_string_lossy().as_bytes())
    )
}

pub fn store_for_source(source_kind: &str) -> crate::StoreKind {
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => crate::StoreKind::Personal,
        "company" | "authority_answer" => crate::StoreKind::Company,
        _ => crate::StoreKind::Codebase,
    }
}

pub fn store_name(store: crate::StoreKind) -> &'static str {
    match store {
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Company => "company",
        crate::StoreKind::Codebase => "codebase",
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
