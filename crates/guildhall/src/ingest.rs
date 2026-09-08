use crate::classify::{EXTRACTION_VERSION, atomize, source_kind_is_supported};
use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_bytes;
use crate::launcher::Launcher;
use crate::model::{Atom, CompanyReference, Distortion, FactEvent, Observation, UnknownEvent};
use crate::scanner::hard_blocked;
use crate::time::{now_rfc3339_millis, parse_rfc3339_millis};
use rusqlite::Connection;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORY_BYTES: usize = 128 * 1024 * 1024;
const MAX_ITEMS: usize = 10_000;

#[derive(Debug, Clone)]
struct NativeRecord {
    native_id: String,
    statement: String,
    scope: String,
    confidence: u16,
    disposition: String,
    asserted_at: Option<String>,
    effective_from: Option<String>,
    effective_until: Option<String>,
    receipt_observed_at: Option<String>,
    receipt_expires_at: Option<String>,
    environment_id: Option<String>,
    owner_id: Option<String>,
    logical_key: Option<String>,
    signer: Option<String>,
}

pub fn ingest(
    launcher: &Launcher,
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
    // The ratified fixture places repository tests at `<repo>/tests`, while the
    // native-source invocation may name the conventional `<repo>/sources/tests`
    // location. Resolve only that documented fallback, and only when the named
    // path is lexically inside the same repository.
    let resolved_source =
        if source_kind == "repo_tests" && !source.exists() && source.starts_with(repo) {
            let tests = repo.join("tests");
            if tests.exists() {
                tests
            } else {
                source.to_path_buf()
            }
        } else {
            source.to_path_buf()
        };
    let source: &Path = &resolved_source;
    let journal_store = crate::StoreKind::Personal;
    let journal_root = crate::store::ensure_store_root(journal_store, repo)?;
    let private = crate::private::PrivateStore::open_personal(&journal_root)?;
    let source_identity = source_identity(source_kind, source);
    let now = now_rfc3339_millis();
    let prior_observations = private.observations_for_source(&source_identity)?;
    let source_available = source.exists();

    // A lifecycle re-ingest must keep a stable identity even after its native
    // source has been removed. Resolve an absent path lexically, but still
    // refuse a missing child whose nearest existing parent is a symlink out
    // of the repository.
    let source_canonical = if source_available {
        source.canonicalize().map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!(
                    "source is unavailable or escapes the repository ({})",
                    error.kind()
                ),
                "Pass a source contained by the repository.",
            )
            .with_detail(serde_json::json!({"omitted_count": 1}))
        })?
    } else {
        let lexical_source = if source.is_absolute() {
            source.to_path_buf()
        } else {
            std::env::current_dir().map_err(io_error)?.join(source)
        };
        if !lexical_source.starts_with(&repo_canonical) {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "source escapes the repository root",
                "Pass a source contained by the repository.",
            )
            .with_detail(serde_json::json!({"omitted_count": 1})));
        }
        if let Some(parent) = source.parent() {
            if let Some(parent_canonical) = parent.canonicalize().ok() {
                if !parent_canonical.starts_with(&repo_canonical) {
                    return Err(ContractError::refused(
                        "CONFIG_INVARIANT",
                        "source escapes the repository root",
                        "Pass a source contained by the repository.",
                    )
                    .with_detail(serde_json::json!({"omitted_count": 1})));
                }
            }
        }
        lexical_source
    };
    if !source_canonical.starts_with(&repo_canonical) {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source escapes the repository root",
            "Pass a source contained by the repository.",
        )
        .with_detail(serde_json::json!({"omitted_count": 1})));
    }

    let parsed: Result<(Vec<u8>, Vec<NativeRecord>), ContractError> = if source_available {
        read_source(source_kind, source).and_then(|bytes| {
            let parsed = if source_kind == "kindex" {
                parse_kindex_source(source, &bytes)
            } else {
                parse_native(source_kind, &bytes).map_err(|message| {
                    ContractError::new(
                        "CONFIG_INVARIANT",
                        message,
                        "Use a valid native source envelope.",
                        false,
                        ExitCode::Refused,
                    )
                })
            };
            parsed.map(|records| (bytes, records))
        })
    } else {
        Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source is unavailable or escapes the repository (not found)",
            "Pass a source contained by the repository.",
        )
        .with_detail(serde_json::json!({"omitted_count": 1})))
    };
    let (bytes, mut records) = match parsed {
        Ok((bytes, records))
            if !records.is_empty() || (source_kind == "kindex" && source_available) =>
        {
            (bytes, records)
        }
        other => {
            if prior_observations.is_empty() {
                return match other {
                    Err(error) => Err(error),
                    Ok(_) => Err(ContractError::invariant(format!(
                        "{source_kind} source contains no native records"
                    ))),
                };
            }
            let bytes = other.ok().map(|(bytes, _)| bytes).unwrap_or_default();
            let lifecycle = if source_available {
                "retracted_observation"
            } else {
                "absent_source_recorded"
            };
            let mut lifecycle_native_ids = std::collections::BTreeSet::new();
            let records = prior_observations
                .iter()
                .filter(|prior| lifecycle_native_ids.insert(prior.native_id.clone()))
                .map(|prior| {
                    native_record(
                        prior.native_id.clone(),
                        format!("[{lifecycle}]"),
                        "repository",
                        4_000,
                        lifecycle,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                })
                .collect::<Vec<_>>();
            (bytes, records)
        }
    };
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
    crate::store::write_private_body(&journal_root, &bytes)?;
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo))
        .transpose()?;
    let revision = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::git_revision(repo).ok())
        .flatten();
    let branch = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::git_branch(repo).ok())
        .flatten();
    let trust_class = match store {
        crate::StoreKind::Personal => "personal-host",
        crate::StoreKind::Company => "company-authority",
        crate::StoreKind::Codebase => repository_trust_class(repo, source, source_kind, &bytes),
    };
    // An expired native record is retained as an explicit lifecycle
    // observation, while its raw body remains withheld from projection.
    if let Ok(proof_now) = parse_rfc3339_millis(&now) {
        for record in &mut records {
            if let Some(effective_until) = record.effective_until.as_deref() {
                if parse_rfc3339_millis(effective_until)
                    .map(|effective_until| effective_until < proof_now)
                    .unwrap_or(false)
                {
                    record.statement = "[expired_raw_withheld]".to_owned();
                    record.disposition = "expired_raw_withheld".to_owned();
                }
            }
        }
    }

    // Kindex quarantine records are parser receipts, not observations. Split
    // them before observation ids are derived so no malformed line can be
    // represented as admitted or current.
    let quarantine_records: Vec<NativeRecord> = records
        .iter()
        .filter(|record| {
            matches!(
                record.disposition.as_str(),
                "MALFORMED_KINDEX_EVENT" | "INVALID_KINDEX_SIGNATURE"
            )
        })
        .cloned()
        .collect();
    records.retain(|record| {
        !matches!(
            record.disposition.as_str(),
            "MALFORMED_KINDEX_EVENT" | "INVALID_KINDEX_SIGNATURE"
        )
    });
    let present_native_ids = records
        .iter()
        .map(|record| record.native_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut missing_native_ids = std::collections::BTreeSet::new();
    for prior in &prior_observations {
        if !present_native_ids.contains(&prior.native_id)
            && missing_native_ids.insert(prior.native_id.clone())
        {
            records.push(native_record(
                prior.native_id.clone(),
                "[retracted_observation]",
                "repository",
                4_000,
                "retracted_observation",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ));
        }
    }
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
    let mut classified_atoms =
        external_classifier_atoms(classifier, source_kind, &source_identity, &now, &prepared)?;
    let mut observation_count = 0;
    let mut reported_observations = Vec::new();
    let mut derived_facts = Vec::new();
    let mut atom_count = 0;
    let mut fact_count = 0;
    let mut skipped = 0;
    let mut quarantined_count = 0;
    let mut quarantined_observations = Vec::new();
    let mut skew_dispositions = Vec::new();
    let mut changed_dispositions = Vec::new();
    let mut historical_receipts = Vec::new();
    let mut revocation_observed_count = 0;
    let trust = if source_kind == "kindex" {
        crate::repository::RepoContext::load(launcher.clone(), repo, false)
            .ok()
            .map(|context| context.trust)
    } else {
        None
    };
    let prepared_manifest = prepared.clone();
    for record in quarantine_records {
        let code = if record.disposition == "MALFORMED_KINDEX_EVENT" {
            "DIGEST_MISMATCH"
        } else {
            "SIGNATURE_INVALID"
        };
        let record_value = json!({
            "source_kind": source_kind,
            "source_identity": source_identity,
            "native_id": record.native_id,
            "reason": record.disposition,
            "disposition": record.disposition,
            "remediation": "Quarantine the non-conforming event; valid events in the same source are admitted.",
            "proof_clock": now
        });
        private.quarantine(code, &record_value)?;
        quarantined_observations.push(record_value);
        quarantined_count += 1;
    }
    for (record, observation_id, digest) in prepared {
        if let Some((field, direction, seconds)) = receipt_clock_skew(&record, &now) {
            let disposition = "CLOCK_SKEW".to_owned();
            let record_value = json!({
                "observation_id": observation_id,
                "source_kind": source_kind,
                "source_identity": source_identity,
                "native_id": record.native_id,
                "content_digest": digest,
                "field": field,
                "direction": direction,
                "skew_seconds": seconds,
                "proof_clock": now,
                "disposition": disposition,
                "remediation": "owner must supply corrected receipt evidence"
            });
            let private = crate::private::PrivateStore::open_personal(&journal_root)?;
            private.quarantine("CLOCK_SKEW", &record_value)?;
            quarantined_observations.push(record_value);
            if !skew_dispositions.contains(&disposition) {
                skew_dispositions.push(disposition);
            }
            quarantined_count += 1;
            continue;
        }
        let prior_same_native = prior_observations
            .iter()
            .filter(|prior| prior.native_id == record.native_id)
            .max_by(|left, right| left.observed_at.cmp(&right.observed_at));
        let lifecycle = record_lifecycle(&record, prior_same_native, &digest);
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
            origin_trust: Some(trust_class.to_owned()),
            environment_id: record.environment_id.clone(),
            owner_id: record.owner_id.clone(),
            lifecycle: lifecycle.clone(),
        };
        let revocation_observed = record
            .signer
            .as_deref()
            .is_some_and(|signer| trust.as_ref().is_some_and(|trust| trust.is_revoked(signer)));
        if revocation_observed {
            historical_receipts.push(json!({
                "event_id": record.native_id,
                "observation_id": observation_id,
                "content_digest": digest,
                "logical_key": record.logical_key,
                "historical_receipt": true,
                "readmitted": false,
                "revocation_observed": true,
                "support_withdrawn": true,
                "projection_state": "support_withdrawn",
                "receipt_scope_restricted": true,
                "state_changed": false,
                "observed_effect": false
            }));
            revocation_observed_count += 1;
            continue;
        }
        if let Some(existing) = prior_observations
            .iter()
            .find(|prior| prior.observation_id == observation_id)
        {
            skipped += 1;
            reported_observations.push(observation_result(existing));
            continue;
        }
        if let Some(prior) = prior_same_native {
            private.supersede_observation(
                &prior.observation_id,
                &prior.disposition,
                &lifecycle,
                &observation_id,
                &now,
            )?;
            if lifecycle != "observed" && !changed_dispositions.contains(&lifecycle) {
                changed_dispositions.push(lifecycle.clone());
            }
        }
        private.insert_observation(&observation)?;
        let observation_value = serde_json::to_value(&observation)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        crate::store::append_record(
            journal_store,
            repo,
            "observations.jsonl",
            &observation_value,
        )?;
        observation_count += 1;
        reported_observations.push(observation_result(&observation));
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
                let text = external
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
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
            crate::store::append_record(journal_store, repo, "atoms.jsonl", &atom_value)?;
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
    let manifest_publication = if source_kind == "kindex"
        && observation_count > 0
        && crate::repository::committed_event_count(repo)? > 0
    {
        Some(crate::repository::publish_manifest_value(launcher, repo)?)
    } else {
        None
    };
    let manifest_lineages = if source_kind == "kindex" {
        crate::codebase::Repository::discover(repo)?
            .manifest_heads()?
            .len()
    } else {
        0
    };
    let result = json!({
        "status": "ingested",
        "adapter": source_kind,
        "state_changed": observation_count > 0,
        "observed_effect": observation_count > 0,
        "historical_receipt": !historical_receipts.is_empty(),
        "historical_receipts": historical_receipts,
        "readmitted": false,
        "receipt_scope_restricted": !historical_receipts.is_empty(),
        "revocation_observed": revocation_observed_count > 0,
        "revocation_observed_count": revocation_observed_count,
        "manifest_publication": manifest_publication,
        "manifest_lineages": manifest_lineages,
        "source_identity": source_identity,
        "observations": reported_observations,
        "derived_facts": derived_facts,
        "observation_count": observation_count,
        "atom_count": atom_count,
        "fact_count": fact_count,
        "idempotent_count": skipped,
        "quarantined_count": quarantined_count,
        "quarantined_observations": quarantined_observations,
        "skew_dispositions": skew_dispositions,
        "changed_dispositions": changed_dispositions,
        "origin_trust_class": trust_class,
        "current_view_byte_identical": observation_count == 0 && skipped > 0,
        "observation_ids": reported_observations
            .iter()
            .filter_map(|value| value.get("observation_id").and_then(Value::as_str).map(str::to_owned))
            .collect::<Vec<_>>(),
        "adapter_receipts": {source_kind: observation_count},
        "build_manifest": {
            "observation_ids": prepared_manifest.iter().map(|(_, id, _)| id.clone()).collect::<Vec<_>>(),
            "adapter_receipts": {source_kind: observation_count},
            "reducer_digest": sha256_bytes(&crate::json::canonical_bytes(&json!({
                "observations": prepared_manifest
                    .iter()
                    .map(|(_, id, digest)| json!({"observation_id": id, "content_digest": digest}))
                    .collect::<Vec<_>>()
            })))
        },
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
        let parent = source
            .parent()
            .and_then(|parent| parent.canonicalize().ok());
        let inside = parent.is_some_and(|parent| target.starts_with(parent));
        if !inside {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "source symlink escapes the source root",
                "Pass a regular file or a directory contained by the source root.",
            )
            .with_detail(json!({"omitted_count": 1})));
        }
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source symlink traversal is refused",
            "Pass the regular file or directory target directly.",
        )
        .with_detail(json!({"omitted_count": 1})));
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
        )
        .with_detail(json!({"omitted_count": 1})));
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
    if source_kind == "repo_tests" {
        // The command-result envelope is JSON, but native fixtures do not
        // promise a `.json` suffix. Keep object-bearing files (including
        // extensionless JCS files) while excluding source and log files that
        // cannot be command results.
        paths.retain(|path| {
            std::fs::read(path)
                .ok()
                .and_then(|bytes| {
                    crate::json::parse_strict_value(&bytes)
                        .ok()
                        .and_then(|value| value.as_object().cloned())
                })
                .is_some_and(|map| {
                    map.get("schema").and_then(Value::as_str) == Some("guildhall-command-result/1")
                        || map.get("command").is_some_and(Value::is_array)
                        || map.get("stdout").is_some_and(Value::is_string)
                })
        });
    }
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
            )
            .with_detail(json!({"omitted_count": 1})));
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
                )
                .with_detail(json!({"omitted_count": 1})));
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
        )
        .with_detail(json!({"omitted_count": 1})));
    }
    std::fs::read(path).map_err(io_error)
}

fn git_history_bytes(source: &Path) -> Result<Vec<u8>, ContractError> {
    let output = std::process::Command::new("git")
        .args([
            "log",
            "--all",
            "--pretty=format:%H%x00%s%x00%b%x00%aI%x00%P",
        ])
        .current_dir(source)
        .output()
        .map_err(|error| {
            ContractError::new(
                "RUN_INTEGRITY_FAILED",
                format!("git history source is unreadable: {error}"),
                "Check the repository and git installation.",
                false,
                ExitCode::InternalFailure,
            )
        })?;
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
        if fields.len() != 5 {
            continue;
        }
        let parents = fields[4].split_whitespace().count();
        let reverted = fields[1].to_ascii_lowercase().starts_with("revert")
            || fields[2].to_ascii_lowercase().starts_with("revert");
        let record = json!({
            "id": fields[0],
            "message": fields[1],
            "body": fields[2],
            "created_at": fields[3],
            "parents": fields[4],
            "state": if reverted {
                "reverted"
            } else if parents > 1 {
                "merged"
            } else {
                "current"
            }
        });
        bytes.extend_from_slice(crate::json::canonical_bytes(&record).as_slice());
        bytes.push(b'\n');
    }
    let refs = git_output(
        source,
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
    )
    .unwrap_or_default();
    for line in refs.lines() {
        let fields: Vec<&str> = line.split('\0').collect();
        if fields.len() != 2 || fields[0].is_empty() {
            continue;
        }
        let record = json!({
            "id": format!("ref:{}", fields[0]),
            "message": format!("git ref {} points to {}", fields[0], fields[1]),
            "state": "current"
        });
        bytes.extend_from_slice(crate::json::canonical_bytes(&record).as_slice());
        bytes.push(b'\n');
    }
    let branches = git_output(
        source,
        &["for-each-ref", "refs/heads", "--format=%(refname)"],
    )
    .unwrap_or_default()
    .lines()
    .filter(|line| !line.trim().is_empty())
    .map(str::to_owned)
    .take(32)
    .collect::<Vec<_>>();
    let mut merge_bases = 0usize;
    for (left_index, left) in branches.iter().enumerate() {
        for right in branches.iter().skip(left_index + 1) {
            if merge_bases >= 64 {
                break;
            }
            let Some(base) = git_output(source, &["merge-base", left, right]) else {
                continue;
            };
            let base = base.trim();
            if base.is_empty() {
                continue;
            }
            let record = json!({
                "id": format!("merge-base:{left}:{right}"),
                "message": format!("merge-base of {left} and {right} is {base}"),
                "state": "current"
            });
            bytes.extend_from_slice(crate::json::canonical_bytes(&record).as_slice());
            bytes.push(b'\n');
            merge_bases += 1;
        }
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
                "body": crate::classifier::request_body(&record.statement),
                "scope": record.scope,
                "confidence": record.confidence
            })
        })
        .collect::<Vec<_>>();
    let mut result = BTreeMap::new();
    for input in crate::classifier::request_batches(observations)? {
        let bytes = crate::sandbox::run_verified_executable(
            &classifier.executable,
            &classifier.executable_sha256,
            &classifier.args,
            &crate::json::canonical_bytes(&input),
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
                result
                    .entry(observation_id)
                    .or_insert_with(Vec::new)
                    .push(atom.clone());
            }
        }
    }
    Ok(result)
}

fn apply_classifier_atom(atom: &mut Atom, external: &Value, repository_id: Option<&str>) {
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
    if let Some(values) = external
        .get("proposed_destinations")
        .and_then(Value::as_array)
    {
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
    if let Some(value) = external
        .get("unresolved_uncertainty")
        .and_then(Value::as_str)
    {
        atom.unresolved_uncertainty = (!value.is_empty()).then(|| value.to_owned());
    }
}

/// Validate `.kin/events/` as signed FactEvents. Malformed data-model bytes
/// and invalid signatures are counted typed integrity failures; neither can
/// reach the canonical renderer or panic.
fn parse_kindex_source(source: &Path, bytes: &[u8]) -> Result<Vec<NativeRecord>, ContractError> {
    if let Some(path) = sqlite_export_path(source) {
        return parse_kindex_sqlite(&path).map_err(|message| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                message,
                "Use a valid Kindex 0.36 SQLite export or signed `.kin/events` tree.",
            )
        });
    }
    parse_kindex_events(bytes)
}

fn sqlite_export_path(source: &Path) -> Option<std::path::PathBuf> {
    let metadata = std::fs::metadata(source).ok()?;
    if metadata.is_file() {
        let is_sqlite = source
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "sqlite" | "sqlite3" | "db"));
        return is_sqlite.then(|| source.to_path_buf());
    }
    if !metadata.is_dir() {
        return None;
    }
    let mut stack = vec![source.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(children) = std::fs::read_dir(directory) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "sqlite" | "sqlite3" | "db"))
            {
                return Some(path);
            }
        }
    }
    None
}

fn parse_kindex_sqlite(path: &Path) -> Result<Vec<NativeRecord>, String> {
    let connection =
        Connection::open(path).map_err(|error| format!("Kindex export is unreadable: {error}"))?;
    let mut statement = connection
        .prepare("SELECT id, node_type, title, content, payload, created_at FROM nodes")
        .map_err(|error| format!("Kindex nodes table is unavailable: {error}"))?;
    let mut rows = statement
        .query([])
        .map_err(|error| format!("Kindex nodes cannot be read: {error}"))?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let id: String = row.get(0).map_err(|error| error.to_string())?;
        let node_type: Option<String> = row.get(1).map_err(|error| error.to_string())?;
        let title: Option<String> = row.get(2).map_err(|error| error.to_string())?;
        let content: Option<String> = row.get(3).map_err(|error| error.to_string())?;
        let payload: Option<Vec<u8>> = row.get(4).map_err(|error| error.to_string())?;
        let created_at: Option<String> = row.get(5).map_err(|error| error.to_string())?;
        let payload_text = payload
            .map(|bytes: Vec<u8>| String::from_utf8_lossy(&bytes).trim().to_owned())
            .unwrap_or_default();
        let statement_text = content
            .filter(|value| !value.trim().is_empty())
            .or_else(|| title.filter(|value| !value.trim().is_empty()))
            .unwrap_or_else(|| {
                if payload_text.is_empty() {
                    format!("Kindex node {id}")
                } else {
                    payload_text
                }
            });
        records.push(native_record(
            id,
            statement_text,
            format!("kindex:{}", node_type.unwrap_or_else(|| "node".to_owned())),
            8_000,
            "current",
            time_string(created_at.as_deref()),
            None,
            None,
            None,
            None,
            None,
            None,
        ));
    }
    let mut edge_statement = connection
        .prepare("SELECT src, dst, relationship, reason FROM edges")
        .map_err(|error| format!("Kindex edges table is unavailable: {error}"))?;
    let mut rows = edge_statement
        .query([])
        .map_err(|error| format!("Kindex edges cannot be read: {error}"))?;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let source: String = row.get(0).map_err(|error| error.to_string())?;
        let destination: String = row.get(1).map_err(|error| error.to_string())?;
        let relationship: Option<String> = row.get(2).map_err(|error| error.to_string())?;
        let reason: Option<String> = row.get(3).map_err(|error| error.to_string())?;
        records.push(native_record(
            format!("edge:{source}:{destination}"),
            format!(
                "{} {} {} ({})",
                source,
                relationship.unwrap_or_else(|| "relates-to".to_owned()),
                destination,
                reason.unwrap_or_else(|| "no reason supplied".to_owned())
            ),
            "kindex:edge",
            8_000,
            "current",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ));
    }
    if records.is_empty() {
        return Err("Kindex export contains no nodes or edges".to_owned());
    }
    Ok(records)
}

fn parse_kindex_events(bytes: &[u8]) -> Result<Vec<NativeRecord>, ContractError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!(
                "kindex event source is not valid UTF-8 ({})",
                error.valid_up_to()
            ),
            "Quarantine the malformed event; no bytes were admitted.",
        )
        .with_detail(json!({"malformed_count": 1}))
    })?;
    let mut records = Vec::new();
    let mut malformed = Vec::new();
    let mut invalid_signatures = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(unknown) = UnknownEvent::parse(line.as_bytes()) {
            if unknown.verify_signature().is_none() {
                invalid_signatures.push(index + 1);
            } else {
                records.push(NativeRecord {
                    native_id: unknown.event_id.clone(),
                    statement: unknown.question.clone(),
                    scope: unknown.scope.clone(),
                    confidence: 0,
                    disposition: unknown.status.clone(),
                    asserted_at: Some(unknown.asserted_at.clone()),
                    effective_from: Some(unknown.asserted_at.clone()),
                    effective_until: Some(unknown.response_due_at.clone()),
                    receipt_observed_at: None,
                    receipt_expires_at: None,
                    environment_id: None,
                    owner_id: Some(unknown.owner_identity.clone()),
                    logical_key: Some(unknown.logical_key.clone()),
                    signer: Some(unknown.signer.clone()),
                });
            }
            continue;
        }
        match FactEvent::parse(line.as_bytes()) {
            Ok(event) => {
                if event.verify_signature().is_none() {
                    invalid_signatures.push(index + 1);
                    continue;
                }
                records.push(NativeRecord {
                    native_id: event.event_id.clone(),
                    statement: event.statement.clone(),
                    scope: event.authority_scope.clone(),
                    confidence: event.confidence.0,
                    disposition: event.disposition.clone(),
                    asserted_at: Some(event.asserted_at.clone()),
                    effective_from: Some(event.effective_from.clone()),
                    effective_until: event.effective_until.clone(),
                    receipt_observed_at: None,
                    receipt_expires_at: None,
                    environment_id: None,
                    owner_id: None,
                    logical_key: Some(event.logical_key.clone()),
                    signer: Some(event.signer.clone()),
                });
            }
            Err(_) => {
                malformed.push(index + 1);
                records.push(NativeRecord {
                    native_id: format!("malformed-kindex-line-{}", index + 1),
                    statement: String::new(),
                    scope: "repository".to_owned(),
                    confidence: 0,
                    disposition: "MALFORMED_KINDEX_EVENT".to_owned(),
                    asserted_at: None,
                    effective_from: None,
                    effective_until: None,
                    receipt_observed_at: None,
                    receipt_expires_at: None,
                    environment_id: None,
                    owner_id: None,
                    logical_key: None,
                    signer: None,
                });
            }
        }
    }
    if !invalid_signatures.is_empty() {
        for line_number in invalid_signatures {
            records.push(NativeRecord {
                native_id: format!("invalid-kindex-signature-line-{line_number}"),
                statement: String::new(),
                scope: "repository".to_owned(),
                confidence: 0,
                disposition: "INVALID_KINDEX_SIGNATURE".to_owned(),
                asserted_at: None,
                effective_from: None,
                effective_until: None,
                receipt_observed_at: None,
                receipt_expires_at: None,
                environment_id: None,
                owner_id: None,
                logical_key: None,
                signer: None,
            });
        }
    }
    // An initialized repository may legitimately have no FactEvents yet. Its
    // empty native view is a successful observation set, not corrupted input.
    Ok(records)
}

fn parse_native(source_kind: &str, bytes: &[u8]) -> Result<Vec<NativeRecord>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => parse_host_jsonl(source_kind, text),
        "github_export" => parse_github_export(text),
        "docs_adr" => parse_docs_adr(text),
        "repo_code" => parse_code_text(text),
        "repo_tests" => parse_repo_tests(text),
        _ => parse_json_records(source_kind, text),
    }
}

fn native_record(
    native_id: impl Into<String>,
    statement: impl Into<String>,
    scope: impl Into<String>,
    confidence: u16,
    disposition: impl Into<String>,
    asserted_at: Option<String>,
    effective_from: Option<String>,
    effective_until: Option<String>,
    receipt_observed_at: Option<String>,
    receipt_expires_at: Option<String>,
    environment_id: Option<String>,
    owner_id: Option<String>,
) -> NativeRecord {
    NativeRecord {
        native_id: native_id.into(),
        statement: statement.into(),
        scope: scope.into(),
        confidence,
        disposition: disposition.into(),
        asserted_at,
        effective_from,
        effective_until,
        receipt_observed_at,
        receipt_expires_at,
        environment_id,
        owner_id,
        logical_key: None,
        signer: None,
    }
}

fn time_string(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| parse_rfc3339_millis(value).is_ok())
        .map(str::to_owned)
}

fn content_text(map: &Map<String, Value>) -> Option<String> {
    if let Some(Value::String(text)) = map.get("text") {
        return Some(text.clone());
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

fn parse_host_jsonl(source_kind: &str, text: &str) -> Result<Vec<NativeRecord>, String> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("native JSONL line {}: {error}", index + 1))?;
        let Some(map) = value.as_object() else {
            continue;
        };
        let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
        let statement = if kind == "response_item" {
            map.get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| content_text(payload))
        } else if kind == "stop" || kind == "session_end" {
            None
        } else {
            map.get("message")
                .and_then(Value::as_object)
                .and_then(content_text)
                .or_else(|| content_text(map))
        };
        let Some(statement) = statement.filter(|statement| !statement.trim().is_empty()) else {
            continue;
        };
        let native_id = map
            .get("id")
            .or_else(|| map.get("uuid"))
            .or_else(|| map.get("session_id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("line:{}", index + 1));
        let asserted_at = time_string(
            map.get("timestamp")
                .or_else(|| map.get("ts"))
                .and_then(Value::as_str),
        );
        records.push(native_record(
            native_id,
            statement,
            "host-session",
            6_000,
            "current",
            asserted_at,
            None,
            None,
            None,
            None,
            None,
            None,
        ));
    }
    if records.is_empty() {
        return Err(format!(
            "{source_kind} source contains no native message records"
        ));
    }
    Ok(records)
}

fn parse_github_export(text: &str) -> Result<Vec<NativeRecord>, String> {
    // A directory adapter reads a concatenation of pretty-printed native
    // export files. Parse a strict JSON stream so every bounded document
    // contributes observations without inventing a foreign envelope.
    let mut records = Vec::new();
    let mut document_count = 0usize;
    let stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    for value in stream {
        let value = value.map_err(|error| error.to_string())?;
        document_count += 1;
        let map = value
            .as_object()
            .ok_or_else(|| "GitHub export must be one JSON object".to_owned())?;
        parse_github_export_object(map, &mut records)?;
    }
    if document_count == 0 {
        return Err("GitHub export contains no JSON object".to_owned());
    }
    if records.is_empty() {
        return Err("GitHub export contains no issues, pull requests, or reviews".to_owned());
    }
    Ok(records)
}

fn parse_github_export_object(
    map: &Map<String, Value>,
    records: &mut Vec<NativeRecord>,
) -> Result<(), String> {
    for (key, prefix) in [("issues", "issue"), ("pullRequests", "pull-request")] {
        let Some(items) = map.get(key).and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            let Some(item) = item.as_object() else {
                continue;
            };
            let number = item.get("number").and_then(Value::as_i64).unwrap_or(0);
            let title = item
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body = item.get("body").and_then(Value::as_str).unwrap_or_default();
            let statement = format!("{title}\n{body}").trim().to_owned();
            if statement.is_empty() {
                continue;
            }
            let state = item.get("state").and_then(Value::as_str).unwrap_or("open");
            records.push(native_record(
                format!("{prefix}:{number}"),
                statement,
                "repository",
                if state == "closed" || state == "merged" {
                    8_000
                } else {
                    6_000
                },
                source_disposition(item),
                time_string(item.get("updatedAt").and_then(Value::as_str)),
                None,
                None,
                None,
                None,
                None,
                None,
            ));
            if let Some(reviews) = item.get("reviews").and_then(Value::as_array) {
                for (review_index, review) in reviews.iter().enumerate() {
                    let Some(review) = review.as_object() else {
                        continue;
                    };
                    let state = review
                        .get("state")
                        .and_then(Value::as_str)
                        .unwrap_or("current");
                    let author = review
                        .get("author")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    records.push(native_record(
                        format!("review:{number}:{review_index}"),
                        format!("review by {author}: {state}"),
                        "repository",
                        8_000,
                        if state == "APPROVED" {
                            "approved"
                        } else {
                            "current"
                        },
                        time_string(review.get("updatedAt").and_then(Value::as_str)),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn parse_docs_adr(text: &str) -> Result<Vec<NativeRecord>, String> {
    // Native fixtures may carry a UTF-8 BOM and macOS may check out CRLF;
    // normalize line endings before parsing the declared front matter. A
    // directory source is a concatenation of complete ADR documents, so parse
    // every front-matter block rather than silently treating later files as
    // prose in the first ADR.
    let normalized = text
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut rest = normalized.trim_start();
    let mut records = Vec::new();
    while let Some(after_front) = rest.strip_prefix("---\n") {
        let Some(end) = after_front.find("\n---") else {
            return Err("ADR Markdown front matter is not closed".to_owned());
        };
        let front = &after_front[..end];
        let body_start = end + 4;
        let mut body = after_front[body_start..].trim_start();
        let next = next_adr_document(body).unwrap_or(body.len());
        let document_body = &body[..next];
        records.push(parse_adr_document(front, document_body)?);
        body = &body[next..];
        if body.is_empty() {
            break;
        }
        rest = body.trim_start();
    }
    if records.is_empty() {
        return Err("ADR Markdown must begin with YAML front matter".to_owned());
    }
    Ok(records)
}

fn next_adr_document(body: &str) -> Option<usize> {
    let mut offset = 0usize;
    while let Some(found) = body[offset..].find("\n---\n") {
        let index = offset + found;
        let after = &body[index + 5..];
        if let Some(close) = after.find("\n---") {
            if after[..close]
                .lines()
                .any(|line| line.trim_start().starts_with("adr:"))
            {
                return Some(index + 1);
            }
        }
        offset = index + 5;
    }
    None
}

fn parse_adr_document(front: &str, body: &str) -> Result<NativeRecord, String> {
    let mut adr = None;
    let mut title = String::new();
    let mut status = "current".to_owned();
    let mut supersedes = None;
    for line in front.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.trim() {
                "adr" => adr = Some(value.to_owned()),
                "title" => title = value.to_owned(),
                "status" => status = value.to_lowercase(),
                "supersedes" => supersedes = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    let adr = adr.ok_or_else(|| "ADR front matter must name adr".to_owned())?;
    if title.is_empty() {
        return Err("ADR front matter must name title".to_owned());
    }
    let body = body.trim();
    let mut statement = format!("# {title}\n{body}");
    if let Some(supersedes) = supersedes {
        statement = format!("{statement}\nSupersedes ADR {supersedes}.");
    }
    let disposition = match status.as_str() {
        "accepted" => "current",
        "proposed" => "proposed",
        "rejected" => "rejected",
        "superseded" => "superseded",
        other => other,
    };
    Ok(native_record(
        format!("adr:{adr}"),
        statement,
        "repository",
        7_000,
        disposition,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ))
}

fn parse_code_text(text: &str) -> Result<Vec<NativeRecord>, String> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let is_python = trimmed.starts_with("def ") || trimmed.starts_with("class ");
        let is_typescript = [
            "export function ",
            "function ",
            "const ",
            "interface ",
            "type ",
            "export type ",
            "export interface ",
            "it(",
            "test(",
        ]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix));
        if !is_python && !is_typescript {
            continue;
        }
        records.push(native_record(
            format!("declaration:{}", index + 1),
            trimmed,
            "repository",
            7_000,
            "current",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ));
    }
    if records.is_empty() {
        return Err("source contains no Python or TypeScript declaration".to_owned());
    }
    Ok(records)
}

fn parse_repo_tests(text: &str) -> Result<Vec<NativeRecord>, String> {
    // The repo-test source class reads strict command-result JSON documents.
    // Concatenated directory files are parsed as a JSON stream so pretty-printed
    // envelopes contribute without introducing a foreign envelope.
    let mut records = Vec::new();
    let mut document_count = 0usize;
    let stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    for value in stream {
        let value = value.map_err(|error| error.to_string())?;
        document_count += 1;
        collect_json_value("repo_tests", &value, &mut records)?;
    }
    if document_count == 0 {
        return Err("repo_tests source contains no command-result envelope".to_owned());
    }
    if records.is_empty() {
        return Err("repo_tests source contains no command-result envelope".to_owned());
    }
    Ok(records)
}

fn parse_json_records(source_kind: &str, text: &str) -> Result<Vec<NativeRecord>, String> {
    let mut records = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if source_kind == "github_export" {
            return parse_github_export(text);
        }
        collect_json_value(source_kind, &value, &mut records)?;
        return Ok(records);
    }
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("native JSONL line {}: {error}", index + 1))?;
        if source_kind == "github_export" {
            return parse_github_export(line);
        }
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
                    .or_else(|| map.get("event_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("record:{}", records.len() + 1));
                let statement = extract_statement(map).unwrap_or_else(|| canonical_summary(map));
                let disposition = source_disposition(map);
                let command = map
                    .get("command")
                    .and_then(Value::as_array)
                    .map(|command| {
                        command
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let statement = if !command.is_empty() {
                    format!("command: {command}\n{statement}")
                } else {
                    statement
                };
                records.push(native_record(
                    native_id,
                    statement,
                    extract_scope(map).unwrap_or_else(|| default_scope(source_kind)),
                    source_confidence(source_kind, &disposition),
                    disposition,
                    time_field(
                        map,
                        &["asserted_at", "created_at", "timestamp", "closed_at"],
                    ),
                    time_field(map, &["effective_from", "started_at"]),
                    time_field(map, &["effective_until", "expires_at", "fresh_until"]),
                    time_field(map, &["observed_at"]),
                    time_field(map, &["expires_at"]),
                    map.get("environment_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    map.get("environment_owner")
                        .or_else(|| map.get("owner_id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                ));
                return Ok(());
            }
            for key in [
                "payload", "message", "content", "data", "items", "events", "facts", "nodes",
                "edges",
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
        || map.get("command").is_some_and(Value::is_array)
        || map.contains_key("state")
        || map.contains_key("schema") && map.get("stdout").is_some()
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
        "rejected" | "closed" | "reverted" | "failed" | "retracted" | "superseded" | "reopened" => {
            state
        }
        "merged" | "approved" | "deployed" | "passed" | "accepted" => "current".to_owned(),
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
    native_record(
        format!("line:{}", index + 1),
        statement.trim(),
        default_scope(source_kind),
        source_confidence(source_kind, &disposition),
        disposition,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
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

fn git_output(repo: &Path, args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn repository_trust_class(
    repo: &Path,
    source: &Path,
    source_kind: &str,
    source_bytes: &[u8],
) -> &'static str {
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
    let default_branch = crate::codebase::Repository::discover(repo)
        .map(|repository| repository.default_branch())
        .unwrap_or_else(|_| "main".to_owned());
    if branch == default_branch {
        return "merged-default";
    }
    let ancestor = std::process::Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            "HEAD",
            &format!("refs/heads/{default_branch}"),
        ])
        .current_dir(repo)
        .output()
        .is_ok_and(|output| output.status.success());
    if !ancestor {
        return "unreviewed-branch";
    }
    let review_message = git_output(repo, &["log", "-1", "--format=%B", "HEAD"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reviewed = [
        "reviewed-by:",
        "approved-by:",
        "review evidence",
        "pull request #",
    ]
    .iter()
    .any(|marker| review_message.contains(marker));
    let github_review = source_kind == "github_export"
        && (source_bytes
            .windows(b"reviews".len())
            .any(|window| window == b"reviews")
            || source_bytes
                .windows(b"reviewed_at".len())
                .any(|window| window == b"reviewed_at"));
    if reviewed || github_review {
        return "approved-pr";
    }
    "merged-default"
}

fn receipt_clock_skew(
    record: &NativeRecord,
    proof_clock: &str,
) -> Option<(&'static str, &'static str, i64)> {
    for (field, value) in [
        ("observed_at", &record.receipt_observed_at),
        ("expires_at", &record.receipt_expires_at),
    ] {
        if let Some(claim) = value {
            if let Some((direction, seconds)) = crate::time::receipt_clock_skew(claim, proof_clock)
            {
                return Some((field, direction, seconds));
            }
        }
    }
    None
}

fn record_lifecycle(record: &NativeRecord, prior: Option<&Observation>, digest: &str) -> String {
    match record.disposition.as_str() {
        "retracted_observation" | "absent_source_recorded" | "expired_raw_withheld" => {
            return record.disposition.clone();
        }
        _ => {}
    }
    if prior.is_some_and(|prior| prior.content_digest != digest) {
        "amended_new_observation".to_owned()
    } else {
        "observed".to_owned()
    }
}

fn observation_result(observation: &Observation) -> Value {
    let lifecycle = observation.lifecycle.as_str();
    let changed_disposition = if lifecycle == "observed" {
        Value::Null
    } else {
        json!(lifecycle)
    };
    json!({
        "observation_id": observation.observation_id,
        "source_kind": observation.source_kind,
        "source_identity": observation.source_identity,
        "native_id": observation.native_id,
        "content_digest": observation.content_digest,
        "observed_at": observation.observed_at,
        "asserted_at": observation.asserted_at,
        "effective_from": observation.effective_from,
        "effective_until": observation.effective_until,
        "repository_id": observation.repository_id,
        "revision": observation.revision,
        "branch": observation.branch,
        "disposition": observation.disposition,
        "origin_trust_class": observation.origin_trust,
        "extraction_version": observation.extraction_version,
        "lifecycle": lifecycle,
        "changed_disposition": changed_disposition
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_adapters_parse_one_fixture_each() {
        let codex = r#"{"type":"response_item","id":"codex-1","payload":{"content":[{"type":"text","text":"Codex observed the failing build"}]}}"#;
        let claude = r#"{"type":"message","uuid":"claude-1","message":{"content":[{"type":"text","text":"Claude observed the regression"}]}}"#;
        let repo_code = "def parse_native():\n    pass\ninterface Adapter {}\n";
        let repo_tests = r#"{"schema":"guildhall-command-result/1","id":"command-1","command":["cargo","test"],"stdout":"test passed","exit_status":0,"observed_at":"2026-09-08T10:00:00.000Z"}"#;
        let git_history = r#"{"id":"commit-1","message":"Merge reviewed change","state":"merged","created_at":"2026-09-08T10:00:00.000Z"}"#;
        let docs_adr = "---\nadr: 7\ntitle: Use SQLite exports\nstatus: accepted\nsupersedes: 4\n---\n# Use SQLite exports\nStore exports as SQLite.\n";
        let github_export = r#"{"issues":[{"number":1,"title":"Fix scheduler","body":"The scheduler drops jobs","state":"closed","updatedAt":"2026-09-08T10:00:00.000Z","reviews":[{"author":"alice","state":"APPROVED","updatedAt":"2026-09-08T10:05:00.000Z"}]}]}"#;
        let runtime_evidence = r#"{"id":"run-1","environment_id":"env-1","environment_owner":"alice","message":"scheduler restarted","state":"deployed","effective_from":"2026-09-08T10:00:00.000Z","effective_until":"2026-09-09T10:00:00.000Z"}"#;
        let authority_answer = r#"{"id":"answer-1","answer":"Use PostgreSQL 16 for the company ledger","state":"current","asserted_at":"2026-09-08T10:00:00.000Z"}"#;

        let fixtures = [
            ("codex_jsonl", codex),
            ("claude_jsonl", claude),
            ("repo_code", repo_code),
            ("repo_tests", repo_tests),
            ("git_history", git_history),
            ("docs_adr", docs_adr),
            ("github_export", github_export),
            ("runtime_evidence", runtime_evidence),
            ("authority_answer", authority_answer),
        ];
        let mut parsed = BTreeMap::new();
        for (source_kind, fixture) in fixtures {
            let records = parse_native(source_kind, fixture.as_bytes())
                .unwrap_or_else(|error| panic!("{source_kind} fixture failed: {error}"));
            assert!(!records.is_empty(), "{source_kind} produced no records");
            parsed.insert(source_kind.to_owned(), records);
        }
        assert_eq!(parsed["codex_jsonl"][0].native_id, "codex-1");
        assert_eq!(parsed["claude_jsonl"][0].native_id, "claude-1");
        assert_eq!(parsed["repo_code"].len(), 2);
        assert_eq!(parsed["repo_tests"][0].native_id, "command-1");
        assert_eq!(parsed["git_history"][0].native_id, "commit-1");
        assert_eq!(parsed["docs_adr"][0].native_id, "adr:7");
        assert_eq!(parsed["github_export"][0].native_id, "issue:1");
        assert_eq!(parsed["github_export"][1].native_id, "review:1:0");
        assert_eq!(
            parsed["runtime_evidence"][0].environment_id.as_deref(),
            Some("env-1")
        );
        assert_eq!(
            parsed["runtime_evidence"][0].effective_until.as_deref(),
            Some("2026-09-09T10:00:00.000Z")
        );
        assert_eq!(parsed["authority_answer"][0].native_id, "answer-1");
    }

    #[test]
    fn kindex_sqlite_export_parses_nodes_and_edges() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("kindex.sqlite");
        let connection = Connection::open(&path).expect("sqlite export");
        connection
            .execute_batch(
                r#"
                CREATE TABLE nodes(id TEXT PRIMARY KEY, node_type TEXT, title TEXT, content TEXT, payload BLOB, created_at TEXT);
                CREATE TABLE edges(src TEXT, dst TEXT, relationship TEXT, reason TEXT);
                INSERT INTO nodes VALUES('node-1', 'concept', 'Adapter', 'Native adapters produce observations', x'7b7d', '2026-09-08T10:00:00.000Z');
                INSERT INTO edges VALUES('node-1', 'node-2', 'supports', 'fixture evidence');
                "#,
            )
            .expect("kindex fixture schema");
        let records = parse_kindex_sqlite(&path).expect("kindex sqlite records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].native_id, "node-1");
        assert_eq!(records[0].statement, "Native adapters produce observations");
        assert_eq!(
            records[0].asserted_at.as_deref(),
            Some("2026-09-08T10:00:00.000Z")
        );
        assert_eq!(records[1].native_id, "edge:node-1:node-2");
        assert!(records[1].statement.contains("supports"));
    }
}
