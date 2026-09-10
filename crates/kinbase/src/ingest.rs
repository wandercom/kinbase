use crate::classify::{EXTRACTION_VERSION, source_kind_is_supported};
use crate::error::{ContractError, ExitCode};
use crate::hash::sha256_bytes;
use crate::launcher::Launcher;
use crate::model::{FactEvent, Observation, UnknownEvent};
use serde_json::{Value, json};
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
    _classifier: Option<&crate::config::SharedClassifier>,
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
    let discovered_repository = crate::codebase::Repository::discover(repo)?;
    let now = crate::repository::recorded_clock(launcher, &discovered_repository)?;
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

    // Scan the native source. A `.kin/` tree is the signed-event intake the
    // reducer owns; every other source is an adapter scan into native units.
    let kin_events_intake = source_kind == "kindex"
        && source_available
        && !crate::lifecycle::is_kindex_sqlite_source(source)
        && (source.join("events").is_dir() || source.is_file());
    let mut quarantine_records: Vec<NativeRecord> = Vec::new();
    let scan = if !source_available {
        if prior_observations.is_empty() {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "source is unavailable or escapes the repository (not found)",
                "Pass a source contained by the repository.",
            )
            .with_detail(serde_json::json!({"omitted_count": 1})));
        }
        crate::lifecycle::SourceScan::default()
    } else if kin_events_intake {
        // Admission is one transaction, and the `.kin/` intake ceiling is the
        // first thing in it: a store already at 10,000 events / 128 MiB refuses
        // new writes before a single event byte is read (architecture §11,
        // verification "Operational limits"). Refusing after the work would
        // make the ceiling unobservable exactly when it binds.
        discovered_repository.check_intake_ceiling(0, 0)?;
        let bytes = read_source(source_kind, source)?;
        let records = parse_kindex_events(&bytes)?;
        let mut scan = crate::lifecycle::SourceScan::default();
        scan.source_digest = sha256_bytes(&bytes);
        scan.bytes_read = bytes.len();
        for record in records {
            if matches!(
                record.disposition.as_str(),
                "MALFORMED_KINDEX_EVENT" | "INVALID_KINDEX_SIGNATURE" | "OVERSIZED_KINDEX_EVENT"
            ) {
                quarantine_records.push(record);
                continue;
            }
            let mut unit = crate::lifecycle::SourceRecord::new(&record.native_id, ".kin/events");
            unit.logical_key = record
                .logical_key
                .clone()
                .unwrap_or_else(|| format!("kindex:{}", record.native_id));
            unit.statement = record.statement.clone();
            unit.atom_kind = "claim".to_owned();
            unit.disposition = record.disposition.clone();
            unit.content = record.statement.as_bytes().to_vec();
            unit.scope = record.scope.clone();
            unit.confidence = record.confidence;
            unit.asserted_at = record.asserted_at.clone();
            unit.effective_from = record.effective_from.clone();
            unit.effective_until = record.effective_until.clone();
            unit.owner_id = record.owner_id.clone();
            unit.signer = record.signer.clone();
            unit.origin = "merged-default".to_owned();
            unit.reducer_owned = true;
            scan.unit_ids.insert(".kin/events".to_owned());
            scan.records.push(unit);
        }
        scan
    } else {
        crate::lifecycle::scan(source_kind, source, &discovered_repository, &now)?
    };
    if scan.records.len() + quarantine_records.len() > MAX_ITEMS {
        let observed = scan.records.len() + quarantine_records.len();
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "observation batch exceeds 10,000 items",
            "Use an explicit checkpoint and smaller batches.",
            false,
            ExitCode::Refused,
        )
        .with_detail(json!({
            "omitted_count": observed,
            "ceiling": MAX_ITEMS,
            "observed_count": observed
        })));
    }
    let store = store_for_source(source_kind);
    let repository_id = (store == crate::StoreKind::Codebase)
        .then(|| crate::repository::repository_id(repo))
        .transpose()?;
    let default_revision = discovered_repository.revision().ok();
    let default_branch = discovered_repository.branch().ok();
    let trust = crate::repository::RepoContext::load(launcher.clone(), repo, false, Some(&now))
        .ok()
        .map(|context| context.trust);

    // -- ceiling stops and parser quarantines -------------------------------
    let mut quarantined_count = 0usize;
    let mut quarantined_observations = Vec::new();
    let mut omitted_count = 0usize;
    for record in quarantine_records {
        let code = match record.disposition.as_str() {
            "MALFORMED_KINDEX_EVENT" => "DIGEST_MISMATCH",
            "OVERSIZED_KINDEX_EVENT" => "LIMIT_EXCEEDED",
            _ => "SIGNATURE_INVALID",
        };
        if code == "LIMIT_EXCEEDED" {
            omitted_count += 1;
        }
        let record_value = json!({
            "source_kind": source_kind,
            "source_identity": source_identity,
            "native_id": record.native_id,
            "reason": record.disposition,
            "disposition": record.disposition,
            "code": code,
            "remediation": if code == "LIMIT_EXCEEDED" {
                "The event exceeds the 64 KiB shared-event ceiling; split or summarize it. Valid events in the same source are admitted."
            } else {
                "Quarantine the non-conforming event; valid events in the same source are admitted."
            },
            "proof_clock": now
        });
        private.quarantine(code, &record_value)?;
        quarantined_observations.push(record_value);
        quarantined_count += 1;
    }

    // -- reconcile the scan with the observation ledger -----------------------
    let mut skew_dispositions = Vec::new();
    let mut changed_dispositions: Vec<Value> = Vec::new();
    let mut historical_receipts = Vec::new();
    let mut revocation_observed_count = 0;
    let mut reported: Vec<Observation> = Vec::new();
    let mut observation_count = 0usize;
    let mut skipped = 0usize;
    let mut present_native_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut renamed_old_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let prior_by_id: BTreeMap<String, Observation> = prior_observations
        .iter()
        .map(|observation| (observation.observation_id.clone(), observation.clone()))
        .collect();
    let mut prior_by_native: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    for observation in &prior_observations {
        prior_by_native
            .entry(observation.native_id.clone())
            .or_default()
            .push(observation.clone());
    }
    let mut present_digests: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for record in &scan.records {
        present_native_ids.insert(record.native_id.clone());
        present_digests.insert(record.content_digest());
    }
    for record in &scan.records {
        let digest = record.content_digest();
        let observation_id = format!(
            "obs_{:x}",
            Sha256::digest(format!("{source_identity}\0{}\0{digest}", record.native_id).as_bytes())
        );
        // R-14: receipt-time claims outside the skew bound are quarantined
        // before any ledger write; historical validity dates are never bounded.
        if let Some(claim) = record.receipt_observed_at.as_deref() {
            if let Some((direction, seconds)) = crate::time::receipt_clock_skew(claim, &now) {
                let disposition = "CLOCK_SKEW".to_owned();
                let record_value = json!({
                    "observation_id": observation_id,
                    "source_kind": source_kind,
                    "source_identity": source_identity,
                    "native_id": record.native_id,
                    "content_digest": digest,
                    "field": "observed_at",
                    "direction": direction,
                    "skew_seconds": seconds,
                    "proof_clock": now,
                    "disposition": disposition,
                    "remediation": "owner must supply corrected receipt evidence"
                });
                private.quarantine("CLOCK_SKEW", &record_value)?;
                quarantined_observations.push(record_value);
                if !skew_dispositions.contains(&disposition) {
                    skew_dispositions.push(disposition);
                }
                quarantined_count += 1;
                continue;
            }
        }
        let revocation_observed = record
            .signer
            .as_deref()
            .is_some_and(|signer| trust.as_ref().is_some_and(|trust| trust.is_revoked(signer)));
        if revocation_observed && record.reducer_owned {
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
        let personal = store == crate::StoreKind::Personal;
        let attributes = if record.attributes.is_empty() {
            None
        } else {
            Some(Value::Object(record.attributes.clone()))
        };
        let fresh = Observation {
            observation_id: observation_id.clone(),
            source_kind: source_kind.to_owned(),
            source_identity: source_identity.clone(),
            native_id: record.native_id.clone(),
            content_digest: digest.clone(),
            repository_id: repository_id.clone(),
            revision: record.revision.clone().or_else(|| default_revision.clone()),
            branch: record.branch.clone().or_else(|| default_branch.clone()),
            disposition: record.disposition.clone(),
            observed_at: now.clone(),
            asserted_at: record.asserted_at.clone(),
            effective_from: record.effective_from.clone(),
            effective_until: record.effective_until.clone(),
            body_ref: format!("sha256:{digest}"),
            extraction_version: EXTRACTION_VERSION.to_owned(),
            origin_trust: Some(record.origin.clone()),
            environment_id: record.environment_id.clone(),
            owner_id: record.owner_id.clone(),
            lifecycle: "observed".to_owned(),
            unit: Some(record.unit_id.clone()),
            statement: (!personal).then(|| record.statement.clone()),
            logical_key: Some(record.logical_key.clone()),
            atom_kind: Some(record.atom_kind.clone()),
            scope: Some(record.scope.clone()),
            signer: record.signer.clone(),
            parents: (!record.parents.is_empty()).then(|| record.parents.clone()),
            attributes,
            raw_withheld: record.raw_expired.then_some(true),
            renamed_from: None,
            receipt_observed_at: record.receipt_observed_at.clone(),
            reducer_owned: record.reducer_owned.then_some(true),
            cursor: None,
        };
        if let Some(existing) = prior_by_id.get(&observation_id) {
            // Re-observed: identity and content are unchanged; provenance
            // (revision, attributes, retention, lifecycle) may have moved.
            let mut merged = existing.clone();
            if fresh.revision != existing.revision {
                merged.revision = fresh.revision.clone();
                merged.branch = fresh.branch.clone();
            }
            merged.attributes = fresh.attributes.clone();
            merged.raw_withheld = fresh.raw_withheld;
            merged.origin_trust = fresh.origin_trust.clone();
            merged.effective_until = fresh.effective_until.clone();
            merged.disposition = fresh.disposition.clone();
            merged.parents = fresh.parents.clone();
            if !record.present && merged.lifecycle == "observed" {
                merged.lifecycle = "absent".to_owned();
            } else if record.present
                && matches!(
                    merged.lifecycle.as_str(),
                    "retracted" | "absent" | "rewritten"
                )
            {
                merged.lifecycle = "observed".to_owned();
                merged.observed_at = now.clone();
            }
            if merged != *existing {
                private.update_observation(&merged)?;
                if merged.lifecycle != existing.lifecycle {
                    let change = json!({
                        "observation_id": merged.observation_id,
                        "new_observation_id": merged.observation_id,
                        "from_disposition": existing.lifecycle,
                        "to_disposition": merged.lifecycle,
                        "observed_at": now
                    });
                    private.audit("disposition-change", &change)?;
                    changed_dispositions.push(change);
                } else {
                    private.audit(
                        "provenance-updated",
                        &json!({"observation_id": merged.observation_id, "revision": merged.revision, "observed_at": now}),
                    )?;
                }
            } else {
                skipped += 1;
            }
            reported.push(merged);
            continue;
        }
        let mut fresh = fresh;
        if !record.present {
            fresh.lifecycle = "absent".to_owned();
        }
        let same_native: Vec<&Observation> = prior_by_native
            .get(&record.native_id)
            .map(|rows| rows.iter().collect())
            .unwrap_or_default();
        if !same_native.is_empty() {
            // Amended: the native record changed content; the previous
            // version becomes history and the transition is explicit.
            for old in same_native.iter().filter(|old| old.lifecycle == "observed") {
                let mut retired = (*old).clone();
                retired.lifecycle = "superseded".to_owned();
                private.update_observation(&retired)?;
                let change = json!({
                    "observation_id": old.observation_id,
                    "new_observation_id": observation_id,
                    "from_disposition": old.disposition,
                    "to_disposition": "amended_new_observation",
                    "observed_at": now
                });
                private.audit("disposition-change", &change)?;
                changed_dispositions.push(change);
            }
        } else if let Some(old) = prior_observations.iter().find(|old| {
            old.lifecycle == "observed"
                && old.content_digest == digest
                && !present_native_ids.contains(&old.native_id)
                && !renamed_old_ids.contains(&old.observation_id)
        }) {
            // Rename: the same bytes reappear under a new native identity
            // while the old identity vanished; provenance moves, nothing is
            // withdrawn.
            let mut retired = old.clone();
            retired.lifecycle = "renamed".to_owned();
            private.update_observation(&retired)?;
            renamed_old_ids.insert(old.observation_id.clone());
            fresh.renamed_from = Some(old.native_id.clone());
            let change = json!({
                "observation_id": old.observation_id,
                "new_observation_id": observation_id,
                "from_disposition": old.disposition,
                "to_disposition": "renamed",
                "observed_at": now
            });
            private.audit("disposition-change", &change)?;
            changed_dispositions.push(change);
        }
        private.insert_observation(&fresh)?;
        observation_count += 1;
        let observation_value = serde_json::to_value(&fresh)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        crate::store::append_record(
            journal_store,
            repo,
            "observations.jsonl",
            &observation_value,
        )?;
        reported.push(fresh);
    }
    // Native identities that vanished: retracted while their unit remains,
    // absent when the unit itself is gone. History stays addressable.
    for (native_id, rows) in &prior_by_native {
        if present_native_ids.contains(native_id) {
            continue;
        }
        for old in rows {
            if old.lifecycle != "observed" {
                continue;
            }
            if renamed_old_ids.contains(&old.observation_id) {
                continue;
            }
            let unit_present = old
                .unit
                .as_deref()
                .is_some_and(|unit| scan.unit_ids.contains(unit))
                && source_available;
            let mut retired = old.clone();
            retired.lifecycle = if unit_present || !source_available {
                if source_available {
                    "retracted"
                } else {
                    "absent"
                }
            } else {
                "absent"
            }
            .to_owned();
            private.update_observation(&retired)?;
            let change = json!({
                "observation_id": old.observation_id,
                "new_observation_id": old.observation_id,
                "from_disposition": old.disposition,
                "to_disposition": if retired.lifecycle == "absent" { "absent_source_recorded" } else { "retracted_observation" },
                "observed_at": now
            });
            private.audit("disposition-change", &change)?;
            changed_dispositions.push(change);
            reported.push(retired);
        }
    }
    if let Some(reason) = &scan.narrowed_view {
        private.audit(
            "narrowed-view",
            &json!({"source_identity": source_identity, "source_kind": source_kind, "reason": reason, "observed_at": now}),
        )?;
    }

    // -- derive facts from the whole ledger ------------------------------------
    let trust_facts = crate::repository::trust_facts(launcher, trust.as_ref());
    let ledger = private.all_observations()?;
    let derived = crate::lifecycle::derive(&ledger, &trust_facts, &now);
    let reported_ids: std::collections::BTreeSet<String> = reported
        .iter()
        .map(|observation| observation.observation_id.clone())
        .collect();
    let reported_observations: Vec<Value> = reported
        .iter()
        .map(|observation| observation_result(observation, &derived))
        .collect();
    let mut derived_facts: Vec<Value> = derived
        .facts
        .iter()
        .filter(|fact| {
            fact.evidence_refs
                .iter()
                .any(|id| reported_ids.contains(id))
        })
        .map(|fact| {
            json!({
                "fact_id": fact.fact_id,
                "logical_key": fact.logical_key,
                "logical_scope": fact.store_kind,
                "atom_kind": fact.atom_kind,
                "disposition": fact.disposition,
                "state": fact.state,
                "evidence_refs": fact.evidence_refs,
                "admitted": fact.state == "current",
                "derived": true
            })
        })
        .collect();
    if derived_facts.is_empty() {
        // Reducer-owned events (`.kin/events`) derive through the reducer;
        // report their fact bindings from the event itself.
        for observation in &reported {
            if observation.reducer_owned == Some(true) {
                derived_facts.push(json!({
                    "fact_id": format!("fact_{:x}", Sha256::digest(format!("{}\0{}", observation.scope.clone().unwrap_or_default(), observation.statement.clone().unwrap_or_default()).as_bytes())),
                    "logical_key": observation.logical_key,
                    "logical_scope": observation.scope,
                    "atom_kind": "claim",
                    "disposition": observation.disposition,
                    "admitted": observation.lifecycle == "observed",
                    "reducer_owned": true
                }));
            }
        }
    }
    let fact_count = derived_facts.len();
    let manifest_publication = if kin_events_intake
        && observation_count > 0
        && crate::repository::committed_event_count(repo)? > 0
    {
        Some(crate::repository::publish_manifest_value(launcher, repo)?)
    } else {
        None
    };
    let manifest_lineages = if source_kind == "kindex" {
        discovered_repository.manifest_heads()?.len()
    } else {
        0
    };
    let adapter_receipt_count = ledger
        .iter()
        .filter(|observation| observation.source_kind == source_kind)
        .count();
    let mut result = json!({
        "status": "ingested",
        "adapter": source_kind,
        "state_changed": observation_count > 0 || !changed_dispositions.is_empty(),
        "observed_effect": observation_count > 0 || !changed_dispositions.is_empty(),
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
        "atom_count": fact_count,
        "fact_count": fact_count,
        "idempotent_count": skipped,
        "quarantined_count": quarantined_count,
        "quarantined_observations": quarantined_observations,
        "skew_dispositions": skew_dispositions,
        "changed_dispositions": changed_dispositions,
        "narrowed_view": scan.narrowed_view,
        "origin_trust_class": reported.first().and_then(|o| o.origin_trust.clone()).unwrap_or_else(|| "merged-default".to_owned()),
        "current_view_byte_identical": observation_count == 0 && changed_dispositions.is_empty(),
        "observation_ids": reported.iter().map(|o| o.observation_id.clone()).collect::<Vec<_>>(),
        "adapter_receipts": {source_kind: adapter_receipt_count},
        "build_manifest": {
            "observation_ids": reported.iter().map(|o| o.observation_id.clone()).collect::<Vec<_>>(),
            "adapter_receipts": {source_kind: adapter_receipt_count},
            "reducer_digest": sha256_bytes(&crate::json::canonical_bytes(&json!({
                "observations": reported.iter().map(|o| json!({"observation_id": o.observation_id, "content_digest": o.content_digest})).collect::<Vec<_>>()
            })))
        },
        "checkpoint": checkpoint,
        "source_digest": scan.source_digest,
        "store": store_name(store),
        "omitted_count": omitted_count
    });
    if omitted_count > 0 {
        // A per-event ceiling stop is reported in the receipt (verification
        // "Operational limits": every ceiling stop reports its omitted count).
        // The admissible remainder of the batch was admitted, so the command
        // succeeds while the stop stays typed.
        let stop = ContractError::limit(
            format!("{omitted_count} shared event(s) exceeded the 64 KiB ceiling and were omitted"),
            json!({"omitted_count": omitted_count, "ceiling_bytes": crate::model::MAX_EVENT_BYTES}),
        );
        result["error"] = crate::output::error_document(&stop)["error"].clone();
        result["ceiling_stops"] = json!([{"ceiling": "shared_event", "omitted_count": omitted_count, "ceiling_bytes": crate::model::MAX_EVENT_BYTES}]);
    }
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("status: ingested");
        println!("adapter: {source_kind}");
        println!("observation_count: {observation_count}");
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
    let mut root = source.to_path_buf();
    if source_kind == "kindex" && source.join("events").is_dir() {
        root = source.join("events");
    }
    let root_canonical = root.canonicalize().map_err(io_error)?;
    let mut paths = Vec::new();
    collect_regular_files(&root, &root_canonical, MAX_ITEMS, &mut paths)?;
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

/// Enumerate the regular files of a directory source, stopping the moment the
/// 10,000-item observation-batch ceiling is passed. The refusal costs one
/// directory walk, never the whole tree and never the bytes.
fn collect_regular_files(
    directory: &Path,
    root: &Path,
    cap: usize,
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
            collect_regular_files(&child, root, cap, output)?;
        } else if metadata.is_file() {
            output.push(child);
            if output.len() > cap {
                return Err(ContractError::new(
                    "LIMIT_EXCEEDED",
                    format!("directory source exceeds the {cap}-item observation batch ceiling"),
                    "Use an explicit checkpoint and smaller batches.",
                    false,
                    ExitCode::Refused,
                )
                .with_detail(json!({
                    "observed_count": output.len(),
                    "observed_count_is_lower_bound": true,
                    "ceiling": cap,
                    "refused_count": output.len(),
                    "omitted_count": output.len()
                })));
            }
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

/// Validate `.kin/events/` as signed FactEvents. Malformed data-model bytes
/// and invalid signatures are counted typed integrity failures; neither can
/// reach the canonical renderer or panic.

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
        if line.len() > crate::model::MAX_EVENT_BYTES {
            // Shared-event ceiling (verification "Operational limits"): the
            // event is a ceiling stop, refused and counted, never truncated.
            records.push(NativeRecord {
                native_id: format!("oversized-kindex-event-line-{}", index + 1),
                statement: String::new(),
                scope: "repository".to_owned(),
                confidence: 0,
                disposition: "OVERSIZED_KINDEX_EVENT".to_owned(),
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

/// Public observation record with the projected lifecycle state (C15).
pub fn observation_result(
    observation: &Observation,
    derived: &crate::lifecycle::DerivedView,
) -> Value {
    let lifecycle = observation.lifecycle.as_str();
    let (state, disposition) = derived
        .observation_states
        .get(&observation.observation_id)
        .cloned()
        .unwrap_or_else(|| match lifecycle {
            "retracted" => ("retracted".to_owned(), "retracted_observation".to_owned()),
            "absent" => ("retracted".to_owned(), "absent_source_recorded".to_owned()),
            "superseded" | "renamed" | "rewritten" => ("stale".to_owned(), "superseded".to_owned()),
            _ => ("current".to_owned(), observation.disposition.clone()),
        });
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
        "unit": observation.unit,
        "logical_key": observation.logical_key,
        "content_digest": observation.content_digest,
        "observed_at": observation.observed_at,
        "asserted_at": observation.asserted_at,
        "effective_from": observation.effective_from,
        "effective_until": observation.effective_until,
        "repository_id": observation.repository_id,
        "revision": observation.revision,
        "branch": observation.branch,
        "disposition": disposition,
        "state": state,
        "observation_state": state,
        "source_disposition": observation.disposition,
        "origin_trust_class": observation.origin_trust,
        "extraction_version": observation.extraction_version,
        "lifecycle": lifecycle,
        "raw_withheld": observation.raw_withheld,
        "renamed_from": observation.renamed_from,
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
