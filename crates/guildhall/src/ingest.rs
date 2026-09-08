use crate::classify::{EXTRACTION_VERSION, atomize, source_kind_is_supported};
use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_bytes;
use crate::model::{Atom, CompanyReference, Distortion, FactEvent, Observation};
use crate::scanner::hard_blocked;
use crate::time::{now_rfc3339_millis, parse_rfc3339_millis};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORY_BYTES: usize = 128 * 1024 * 1024;
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
    classifier: Option<&crate::config::SharedClassifier>,
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
    let repo_canonical = repo.canonicalize().map_err(io_error)?;
    let source_canonical = source.canonicalize().map_err(|error| ContractError::refused(
        "CONFIG_INVARIANT",
        format!("source is unavailable or escapes the repository ({})", error.kind()),
        "Pass a source contained by the repository.",
    ))?;
    if !source_canonical.starts_with(&repo_canonical) {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source escapes the repository root",
            "Pass a source contained by the repository.",
        ));
    }
    let bytes = read_source(source_kind, source)?;
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
    let root = crate::store::ensure_store_root(store, repo)?;
    if matches!(store, crate::StoreKind::Personal) {
        crate::store::write_private_body(&root, &bytes)?;
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
    let prepared = records
        .into_iter()
        .map(|record| {
            let digest = sha256_bytes(record.statement.as_bytes());
            let observation_id = format!(
                "obs_{:x}",
                Sha256::digest(
                    format!("{source_identity}\0{}\0{digest}", record.native_id).as_bytes()
                )
            );
            (record, observation_id, digest)
        })
        .collect::<Vec<_>>();
    let mut classified_atoms = external_classifier_atoms(
        classifier,
        source_kind,
        &source_identity,
        &now,
        &prepared,
    )?;
    let mut observation_count = 0;
    let mut reported_observations = Vec::new();
    let mut derived_facts = Vec::new();
    let mut atom_count = 0;
    let mut fact_count = 0;
    let mut skipped = 0;
    for (record, observation_id, digest) in prepared {
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
            origin_trust: (store == crate::StoreKind::Codebase).then(|| trust_class.to_owned()),
            environment_id: None,
            owner_id: None,
            lifecycle: "observed".to_owned(),
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
        crate::store::append_record(store, repo, "observations.jsonl", &observation_value)?;
        observation_count += 1;
        reported_observations.push(json!({
            "source_kind": source_kind,
            "source_identity": source_identity,
            "content_digest": digest,
            "observed_at": now,
            "disposition": record.disposition,
            "extraction_version": EXTRACTION_VERSION
        }));
        let external_atoms = classified_atoms.remove(&observation_id).unwrap_or_default();
        let mut atoms = Vec::new();
        if external_atoms.is_empty() {
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
            if !(hard_blocked(&record.statement) && store != crate::StoreKind::Personal) {
                atoms.push(atom);
            } else {
                skipped += 1;
            }
        } else {
            for external in external_atoms {
                let text = external.get("text").and_then(Value::as_str).unwrap_or_default();
                if hard_blocked(text) && store != crate::StoreKind::Personal {
                    skipped += 1;
                    continue;
                }
                let mut atom = atomize(
                    source_kind,
                    &record.native_id,
                    text,
                    &record.scope,
                    record.confidence,
                    &observation_id,
                    &digest,
                    repository_id.as_deref(),
                );
                apply_classifier_atom(&mut atom, &external, repository_id.as_deref());
                atoms.push(atom);
            }
        }
        for atom in atoms {
            let atom_value = serde_json::to_value(&atom)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            crate::store::append_record(store, repo, "atoms.jsonl", &atom_value)?;
            atom_count += 1;
            let eligible = store != crate::StoreKind::Personal
                && trust_class == "merged-default"
                && record.disposition == "current";
            if eligible {
                let fact = write_source_fact_event(
                    store,
                    repo,
                    &atom,
                    &observation,
                    &record,
                    repository_id.as_deref(),
                )?;
                if let Some(fact) = fact {
                    derived_facts.push(fact);
                }
                fact_count += 1;
            } else {
                let fact_id = format!(
                    "fact_{:x}",
                    Sha256::digest(format!("{}\0{}", atom.scope, atom.statement).as_bytes())
                );
                derived_facts.push(json!({
                    "fact_id": fact_id,
                    "logical_scope": atom.scope,
                    "atom_kind": atom.atom_kind,
                    "disposition": record.disposition,
                    "admitted": false
                }));
            }
        }
    }
    let result = json!({
        "status": "ingested",
        "adapter": source_kind,
        "source_identity": source_identity,
        "observations": reported_observations,
        "derived_facts": derived_facts,
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

fn read_source(source_kind: &str, source: &Path) -> Result<Vec<u8>, ContractError> {
    let metadata = std::fs::symlink_metadata(source).map_err(io_error)?;
    if metadata.file_type().is_symlink() {
        let target = source.canonicalize().map_err(io_error)?;
        let parent = source.parent().and_then(|parent| parent.canonicalize().ok());
        let inside = parent.is_some_and(|parent| target.starts_with(parent));
        if !inside {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "source symlink escapes the source root",
                "Pass a regular file or a directory contained by the source root.",
            ));
        }
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source symlink traversal is refused",
            "Pass the regular file or directory target directly.",
        ));
    }
    if metadata.is_file() {
        let bytes = read_bounded_file(source, MAX_FILE_BYTES)?;
        return Ok(bytes);
    }
    if !metadata.is_dir() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source is neither a regular file nor a directory",
            "Pass a regular file or directory.",
        ));
    }
    if source_kind == "git_history" && source.join(".git").exists() {
        return git_history_bytes(source);
    }
    let mut root = source.to_path_buf();
    if source_kind == "kindex" && source.join("events").is_dir() {
        root = source.join("events");
    }
    let root_canonical = root.canonicalize().map_err(io_error)?;
    let mut paths = Vec::new();
    collect_regular_files(&root, &root_canonical, &mut paths)?;
    paths.sort();
    let mut bytes = Vec::new();
    for path in paths {
        let file_bytes = read_bounded_file(&path, MAX_FILE_BYTES)?;
        if bytes.len() + file_bytes.len() > MAX_DIRECTORY_BYTES {
            return Err(ContractError::new(
                "LIMIT_EXCEEDED",
                "directory source exceeds the 128 MiB bound",
                "Split the source into bounded adapter batches.",
                false,
                ExitCode::Refused,
            ).with_detail(json!({"omitted_count": 1})));
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&file_bytes);
    }
    Ok(bytes)
}

fn collect_regular_files(
    directory: &Path,
    root: &Path,
    output: &mut Vec<std::path::PathBuf>,
) -> Result<(), ContractError> {
    let mut children = std::fs::read_dir(directory)
        .map_err(io_error)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    children.sort();
    for child in children {
        let metadata = std::fs::symlink_metadata(&child).map_err(io_error)?;
        if metadata.file_type().is_symlink() {
            let target = child.canonicalize().map_err(io_error)?;
            if !target.starts_with(root) {
                return Err(ContractError::refused(
                    "CONFIG_INVARIANT",
                    "directory source contains a symlink that escapes the source root",
                    "Remove the escaping symlink or pass only contained regular files.",
                ));
            }
            continue;
        }
        if metadata.is_dir() {
            if child.file_name().and_then(|name| name.to_str()) == Some(".git") {
                continue;
            }
            collect_regular_files(&child, root, output)?;
        } else if metadata.is_file() {
            output.push(child);
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, ContractError> {
    let metadata = std::fs::metadata(path).map_err(io_error)?;
    if metadata.len() as usize > limit {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            format!("source file exceeds the {}-byte bound", limit),
            "Split the source into bounded adapter batches.",
            false,
            ExitCode::Refused,
        ).with_detail(json!({"omitted_count": 1})));
    }
    std::fs::read(path).map_err(io_error)
}

fn git_history_bytes(source: &Path) -> Result<Vec<u8>, ContractError> {
    let output = std::process::Command::new("git")
        .args(["log", "--all", "--pretty=format:%H%x00%s%x00%b%x00%aI"])
        .current_dir(source)
        .output()
        .map_err(|error| ContractError::new(
            "RUN_INTEGRITY_FAILED",
            format!("git history source is unreadable: {error}"),
            "Check the repository and git installation.",
            false,
            ExitCode::InternalFailure,
        ))?;
    if !output.status.success() {
        return Err(ContractError::new(
            "RUN_INTEGRITY_FAILED",
            format!("git log exited with {}", output.status),
            "Check the repository and retry.",
            false,
            ExitCode::InternalFailure,
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut bytes = Vec::new();
    for commit in text.split('\n') {
        let fields: Vec<&str> = commit.split('\0').collect();
        if fields.len() != 4 {
            continue;
        }
        let record = json!({
            "id": fields[0],
            "message": fields[1],
            "body": fields[2],
            "created_at": fields[3],
            "state": "current"
        });
        bytes.extend_from_slice(crate::json::canonical_bytes(&record).as_slice());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn external_classifier_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    source_kind: &str,
    source_identity: &str,
    now: &str,
    prepared: &[(NativeRecord, String, String)],
) -> Result<BTreeMap<String, Vec<Value>>, ContractError> {
    let Some(classifier) = classifier else {
        return Ok(BTreeMap::new());
    };
    let observations = prepared
        .iter()
        .map(|(record, observation_id, digest)| {
            json!({
                "observation_id": observation_id,
                "source_kind": source_kind,
                "source_identity": source_identity,
                "content_digest": digest,
                "observed_at": now,
                "disposition": record.disposition,
                "extraction_version": EXTRACTION_VERSION,
                "body": record.statement,
                "scope": record.scope,
                "confidence": record.confidence
            })
        })
        .collect::<Vec<_>>();
    let input = json!({"observations": observations});
    let bytes = crate::sandbox::run_verified_executable(
        &classifier.executable,
        &classifier.executable_sha256,
        &classifier.args,
        &crate::json::canonical_bytes(&input),
        std::time::Duration::from_secs(classifier.timeout_seconds),
    )?;
    let output = crate::json::parse_strict_value(&bytes)
        .map_err(|error| ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("classifier output is not strict JSON: {error}"), "Repair the pinned classifier; no output was promoted."))?;
    crate::classifier::validate_output(&output)?;
    let mut result = BTreeMap::new();
    if let Some(atoms) = output.get("atoms").and_then(Value::as_array) {
        for atom in atoms {
            let observation_id = atom
                .get("observation_id")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier atom has no observation_id", "Repair the pinned classifier; no output was promoted."))?
                .to_owned();
            result.entry(observation_id).or_insert_with(Vec::new).push(atom.clone());
        }
    }
    Ok(result)
}

fn apply_classifier_atom(
    atom: &mut Atom,
    external: &Value,
    repository_id: Option<&str>,
) {
    if let Some(value) = external.get("atom_id").and_then(Value::as_str) {
        atom.atom_id = value.to_owned();
    }
    if let Some(value) = external.get("atom_kind").and_then(Value::as_str) {
        atom.atom_kind = value.to_owned();
    }
    if let Some(value) = external.get("confidence").and_then(Value::as_str) {
        atom.confidence = match value {
            "high" => 8_000,
            "medium" => 6_000,
            _ => 3_000,
        };
    }
    if let Some(values) = external.get("proposed_destinations").and_then(Value::as_array) {
        let destinations = values
            .iter()
            .filter_map(|value| value.as_str())
            .map(|value| match value {
                "codebase" => repository_id
                    .map(|id| format!("codebase:{id}"))
                    .unwrap_or_else(|| "codebase".to_owned()),
                other => other.to_owned(),
            })
            .collect::<Vec<_>>();
        atom.proposed_destinations = destinations.clone();
        atom.eligible_destinations = destinations;
    }
    if let Some(values) = external.get("taint").and_then(Value::as_array) {
        atom.taints = values
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = external.get("unresolved_uncertainty").and_then(Value::as_str) {
        atom.unresolved_uncertainty = (!value.is_empty()).then(|| value.to_owned());
    }
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
            crate::store::append_record(store, repo, "source-lifecycle.jsonl", &record)?;
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
) -> Result<Option<Value>, ContractError> {
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
        confidence: crate::model::Bp(atom.confidence),
        unresolved_uncertainty: atom.unresolved_uncertainty.clone(),
        signer,
        signature: String::new(),
        raw: None,
    };
    let (private_key, _) = crate::crypto::ensure_keypair(store, repo)?;
    let unsigned = crate::store::event_canonical_text(&event);
    event.signature = crate::crypto::sign_message("fact-event", unsigned.as_bytes(), &private_key)?;
    let root = crate::store::ensure_store_root(store, repo)?;
    crate::store::write_content_addressed_event(&root, &event)?;
    let fact = json!({
        "fact_id": event.fact_id,
        "logical_scope": event.scope,
        "atom_kind": event.atom_kind,
        "disposition": event.disposition,
        "admitted": true
    });
    Ok(Some(fact))
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
