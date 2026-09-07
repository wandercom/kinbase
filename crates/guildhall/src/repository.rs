use crate::error::{ContractError, ExitCode};
use crate::hash::{is_sha256, sha256_bytes};
use crate::json::{canonical_bytes, canonical_text, parse_strict_object};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn issue_certificate(repo: &Path, company: &str, json: bool) -> Result<(), ContractError> {
    let id = repository_uuid_from_git(repo)?;
    let issued_at = crate::time::now_rfc3339_millis();
    let mut certificate = json!({
        "schema": "guildhall-repo-certificate/1",
        "repository_uuid": id,
        "company": company,
        "issued_at": issued_at,
        "fresh_until": crate::time::format_rfc3339_millis(
            crate::time::parse_rfc3339_millis(&issued_at).map_err(|error| ContractError::internal(error))?
                + chrono::Duration::hours(24 * 365)
        ),
        "signer": "company-steward"
    });
    let (private_key, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, repo)?;
    let signature = crate::crypto::sign_message(
        "repo-certificate",
        canonical_text(&certificate).as_bytes(),
        &private_key,
    )?;
    certificate["signature"] = Value::String(signature);
    if json {
        println!(
            "{}",
            serde_json::to_string(&certificate).unwrap_or_default()
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&certificate).unwrap_or_default()
        );
    }
    Ok(())
}

pub fn init(repo: &Path, certificate: &Path, json: bool) -> Result<(), ContractError> {
    let bytes = std::fs::read(certificate).map_err(io_error)?;
    let map: Map<String, Value> = parse_strict_object(&bytes).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error,
            "Use a steward-issued repository certificate.",
            false,
            ExitCode::Refused,
        )
    })?;
    if map.get("schema").and_then(Value::as_str) != Some("guildhall-repo-certificate/1") {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "unsupported repository certificate schema",
            "Use a ratified Company steward certificate.",
            false,
            ExitCode::Refused,
        ));
    }
    let signature = map
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractError::new(
                "SIGNATURE_INVALID",
                "certificate signature missing",
                "Ask the Company steward for a signed certificate.",
                false,
                ExitCode::IntegrityFailure,
            )
        })?
        .to_owned();
    let mut unsigned = map.clone();
    unsigned.remove("signature");
    let company_root = crate::store::store_root(crate::StoreKind::Company, repo);
    let public_key = company_root.join("local").join("keys").join("ed25519.pub");
    if !public_key.exists()
        || !crate::crypto::verify_message(
            "repo-certificate",
            canonical_bytes(&Value::Object(unsigned)).as_slice(),
            &signature,
            &public_key,
        )?
    {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            "repository certificate signature failed",
            "Quarantine the certificate and ask the Company steward for a valid one.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let repository_id = map
        .get("repository_uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "repository UUID missing",
                "Use a steward-issued certificate.",
                false,
                ExitCode::Refused,
            )
        })?;
    let company = map.get("company").and_then(Value::as_str).ok_or_else(|| {
        ContractError::new(
            "CONFIG_INVARIANT",
            "company hint missing",
            "Use a steward-issued certificate.",
            false,
            ExitCode::Refused,
        )
    })?;
    let kin = repo.join(".kin");
    std::fs::create_dir_all(kin.join("events")).map_err(io_error)?;
    std::fs::create_dir_all(kin.join("manifests")).map_err(io_error)?;
    std::fs::create_dir_all(kin.join("local")).map_err(io_error)?;
    let config = json!({
        "schema_version": "guildhall-repo/1",
        "repository_uuid": repository_id,
        "company_hint": company
    });
    std::fs::write(kin.join("config"), canonical_bytes(&config)).map_err(io_error)?;
    let attributes_path = repo.join(".gitattributes");
    let mut attributes = std::fs::read_to_string(&attributes_path).unwrap_or_default();
    if !attributes.contains(".kin/events/**") {
        if !attributes.is_empty() && !attributes.ends_with('\n') {
            attributes.push('\n');
        }
        attributes
            .push_str(".kin/events/** -text -diff -merge\n.kin/manifests/** -text -diff -merge\n");
        std::fs::write(&attributes_path, attributes).map_err(io_error)?;
    }
    let result = json!({"status":"repo-initialized", "repository_uuid":repository_id});
    print_value(&result, json);
    Ok(())
}

pub fn publish_manifest(repo: &Path, json: bool) -> Result<(), ContractError> {
    let repository_id = repository_id(repo)?;
    let branch = git_branch(repo)?;
    let revision = git_revision(repo)?;
    let manifest = crate::store::manifest(
        &repo.join(".kin"),
        &repository_id,
        &branch,
        &revision,
        &crate::time::now_rfc3339_millis(),
    )
    .map_err(io_error)?;
    print_value(&manifest, json);
    Ok(())
}

pub fn status(repo: &Path, json: bool) -> Result<(), ContractError> {
    let config_path = repo.join(".kin").join("config");
    let result = if config_path.exists() {
        let repository_id = repository_id(repo)?;
        let count = crate::store::read_events(&repo.join(".kin"))
            .map(|events| events.len())
            .unwrap_or(0);
        json!({
            "status": "initialized",
            "repository_uuid": repository_id,
            "event_count": count,
            "personal_mounted": false
        })
    } else {
        json!({
            "status": "unverified",
            "repository_uuid": Value::Null,
            "event_count": 0,
            "personal_mounted": false,
            "remediation": "Run guildhall repo issue and repo init with an out-of-tree certificate."
        })
    };
    print_value(&result, json);
    Ok(())
}

pub fn doctor(repo: &Path, host: Option<crate::HostKind>, json: bool) -> Result<(), ContractError> {
    let reservations = std::env::current_dir()
        .ok()
        .and_then(|current| {
            crate::store::read_records(
                crate::StoreKind::Personal,
                &current,
                "prompt-reservations.jsonl",
            )
            .ok()
        })
        .unwrap_or_default();
    let result = json!({
        "capabilities": ["company", "codebase"],
        "personal": {
            "granted": false,
            "environment_variable_present": std::env::var_os("GUILDHALL_PERSONAL_ROOT").is_some()
        },
        "company": {"granted": crate::store::store_root(crate::StoreKind::Company, repo).exists()},
        "codebase": {"granted": repo.join(".kin").join("config").exists()},
        "host": host.map(|host| if host == crate::HostKind::Codex { "codex" } else { "claude" }),
        "host_version_supported": true,
        "prompt_budget": {
            "reserved_count": reservations.len(),
            "sliding_window": "60m",
            "total_limit": 4,
            "consecutive_limit": 3,
            "global_cross_machine_total_known": false
        }
    });
    print_value(&result, json);
    Ok(())
}

pub fn fsck(repo: &Path, full: bool, json: bool) -> Result<(), ContractError> {
    let kin = repo.join(".kin");
    if !kin.join("config").exists() {
        let result = json!({"status":"unverified", "event_count":0, "full":full, "reason":"repo-uninitialized"});
        print_value(&result, json);
        return Ok(());
    }
    let repository_id = repository_id(repo)?;
    let event_files = collect_event_paths(&kin.join("events"))?;
    if event_files.len() > 10_000 {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            "Codebase event count exceeds 10,000",
            "Split the repository history or raise only through a new schema version.",
            false,
            ExitCode::Refused,
        ));
    }
    let public_key = kin.join("local").join("keys").join("ed25519.pub");
    let mut event_count = 0;
    for path in event_files {
        let bytes = std::fs::read(&path).map_err(io_error)?;
        if bytes.len() > 64 * 1024 {
            return Err(ContractError::new(
                "LIMIT_EXCEEDED",
                "event exceeds 64 KiB",
                "Use a smaller atom or new schema version.",
                false,
                ExitCode::Refused,
            ));
        }
        let event = crate::store::parse_event(&bytes).map_err(|error| {
            ContractError::new(
                "SIGNATURE_INVALID",
                error,
                "Quarantine the malformed event and rerun full fsck.",
                false,
                ExitCode::IntegrityFailure,
            )
        })?;
        let canonical = canonical_bytes(
            &serde_json::to_value(&event)
                .map_err(|error| ContractError::internal(error.to_string()))?,
        );
        let digest = sha256_bytes(&canonical);
        let expected = kin
            .join("events")
            .join(format!(
                "{}{}{}",
                &digest[0..2],
                &digest[2..4],
                &digest[4..]
            ))
            .with_extension("json");
        if path != expected || !is_sha256(&digest) {
            return Err(ContractError::new(
                "DIGEST_MISMATCH",
                format!(
                    "event path does not match canonical digest: {}",
                    event.event_id
                ),
                "Run full fsck and repair the content-addressed event tree.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
        if event.store_kind != "codebase"
            || event.repository_id.as_deref() != Some(repository_id.as_str())
        {
            return Err(ContractError::new(
                "FOREIGN_REPO_EVENTS",
                format!("event {} binds another repository or store", event.event_id),
                "Remove foreign events or obtain signed lineage.",
                false,
                ExitCode::Refused,
            ));
        }
        if !public_key.exists()
            || !crate::store::verify_event_signature(&event, &public_key).map_err(|error| {
                ContractError::new(
                    "SIGNATURE_INVALID",
                    error,
                    "Quarantine the event and rerun full fsck.",
                    false,
                    ExitCode::IntegrityFailure,
                )
            })?
        {
            return Err(ContractError::new(
                "SIGNATURE_INVALID",
                format!("event {} signature failed", event.event_id),
                "Quarantine the event and repair its named owner key.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
        event_count += 1;
    }
    let manifests = collect_event_paths(&kin.join("manifests"))?;
    for path in &manifests {
        let bytes = std::fs::read(path).map_err(io_error)?;
        let map = parse_strict_object(&bytes).map_err(|error| {
            ContractError::new(
                "SIGNATURE_INVALID",
                error,
                "Quarantine the malformed manifest.",
                false,
                ExitCode::IntegrityFailure,
            )
        })?;
        if map.get("schema").and_then(Value::as_str) != Some("guildhall-manifest/1") {
            return Err(ContractError::new(
                "SIGNATURE_INVALID",
                "unsupported manifest schema",
                "Quarantine the manifest.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
        let digest = sha256_bytes(&canonical_bytes(&Value::Object(map)));
        let expected = kin
            .join("manifests")
            .join(format!(
                "{}{}{}",
                &digest[0..2],
                &digest[2..4],
                &digest[4..]
            ))
            .with_extension("json");
        if *path != expected {
            return Err(ContractError::new(
                "DIGEST_MISMATCH",
                "manifest path does not match canonical bytes",
                "Republish the manifest from verified events.",
                false,
                ExitCode::IntegrityFailure,
            ));
        }
    }
    let result = json!({"status":"ok", "event_count":event_count, "manifest_count":manifests.len(), "full":full});
    print_value(&result, json);
    Ok(())
}

fn collect_event_paths(path: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let mut output = Vec::new();
    collect_paths(path, &mut output)?;
    output.sort();
    Ok(output)
}

fn collect_paths(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), ContractError> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).map_err(io_error)? {
            collect_paths(&entry.map_err(io_error)?.path(), output)?;
        }
    } else if path.is_file() {
        output.push(path.to_path_buf());
    }
    Ok(())
}

pub fn repository_id(repo: &Path) -> Result<String, ContractError> {
    let config_path = repo.join(".kin").join("config");
    let bytes = std::fs::read(&config_path).map_err(io_error)?;
    let map: Map<String, Value> = parse_strict_object(&bytes).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error,
            "Run repo init first.",
            false,
            ExitCode::Refused,
        )
    })?;
    map.get("repository_uuid")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "repository UUID missing",
                "Run repo init.",
                false,
                ExitCode::Refused,
            )
        })
}

fn repository_uuid_from_git(repo: &Path) -> Result<String, ContractError> {
    let remote = git_output(repo, &["remote", "get-url", "origin"]).unwrap_or_default();
    if remote.is_empty() {
        return Ok(Uuid::new_v4().to_string());
    }
    Ok(format!("repo_{remote}"))
}

pub fn git_revision(repo: &Path) -> Result<String, ContractError> {
    git_output(repo, &["rev-parse", "HEAD"])
}

pub fn git_branch(repo: &Path) -> Result<String, ContractError> {
    git_output(repo, &["rev-parse", "--abbrev-ref", "HEAD"])
}

fn git_output(repo: &Path, args: &[&str]) -> Result<String, ContractError> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(ContractError::new(
            "COMPANY_UNREACHABLE",
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            "Run the command inside a Git worktree or repair Git.",
            true,
            ExitCode::DependencyUnavailable,
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
        if let Some(count) = value.get("event_count").and_then(Value::as_u64) {
            println!("event_count: {count}");
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
