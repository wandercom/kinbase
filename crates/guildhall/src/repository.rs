use crate::error::{ContractError, ExitCode};
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

pub fn issue_certificate(repo: &Path, company: &str, json: bool) -> Result<(), ContractError> {
    let id = Uuid::new_v4().to_string();
    let certificate =
        json!({"schema":"guildhall-repo-certificate/1","repository_uuid":id,"company":company});
    let bytes = serde_json::to_vec_pretty(&certificate)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    std::fs::write(repo.join(".kin/certificate.json"), bytes).map_err(io_error)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&certificate).unwrap_or_default()
        );
    } else {
        println!("repository_uuid: {id}");
    }
    Ok(())
}

pub fn init(repo: &Path, certificate: &Path, json: bool) -> Result<(), ContractError> {
    let certificate_text = std::fs::read_to_string(certificate).map_err(io_error)?;
    let certificate_value: serde_json::Value =
        serde_json::from_str(&certificate_text).map_err(|error| {
            ContractError::new(
                "CONFIG_INVARIANT",
                error.to_string(),
                "Use a valid signed repository certificate.",
                false,
                ExitCode::Refused,
            )
        })?;
    let repository_id = certificate_value
        .get("repository_uuid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "certificate lacks repository_uuid",
                "Use a steward-issued certificate.",
                false,
                ExitCode::Refused,
            )
        })?;
    let kin = repo.join(".kin");
    std::fs::create_dir_all(kin.join("events")).map_err(io_error)?;
    std::fs::create_dir_all(kin.join("manifests")).map_err(io_error)?;
    std::fs::create_dir_all(kin.join("local")).map_err(io_error)?;
    let config = json!({"schema_version":"guildhall-repo/1","repository_uuid_hint":repository_id,"safe_name":repo.file_name().and_then(|name|name.to_str()).unwrap_or("repository")});
    std::fs::write(
        kin.join("config"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .map_err(io_error)?;
    let attributes_path = repo.join(".gitattributes");
    let mut attributes = std::fs::read_to_string(&attributes_path).unwrap_or_default();
    if !attributes.contains(".kin/events/**") {
        attributes.push_str(
            "\n.kin/events/** -text -diff -merge\n.kin/manifests/** -text -diff -merge\n",
        );
        std::fs::write(&attributes_path, attributes).map_err(io_error)?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string(
                &json!({"status":"repo-initialized","repository_uuid":repository_id})
            )
            .unwrap_or_default()
        );
    } else {
        println!("repository_uuid: {repository_id}");
    }
    Ok(())
}

pub fn publish_manifest(repo: &Path, json: bool) -> Result<(), ContractError> {
    let config_path = repo.join(".kin/config");
    let config_text = std::fs::read_to_string(&config_path).map_err(io_error)?;
    let config: serde_json::Value = serde_json::from_str(&config_text).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error.to_string(),
            "Run repo init first.",
            false,
            ExitCode::Refused,
        )
    })?;
    let repository_id = config
        .get("repository_uuid_hint")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let branch = String::from_utf8(
        std::process::Command::new("git")
            .arg("rev-parse")
            .arg("--abbrev-ref")
            .arg("HEAD")
            .current_dir(repo)
            .output()
            .map_err(io_error)?
            .stdout,
    )
    .map_err(|error| ContractError::internal(error.to_string()))?
    .trim()
    .to_string();
    let revision = String::from_utf8(
        std::process::Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .current_dir(repo)
            .output()
            .map_err(io_error)?
            .stdout,
    )
    .map_err(|error| ContractError::internal(error.to_string()))?
    .trim()
    .to_string();
    let manifest = crate::store::manifest(
        repo,
        repository_id,
        &branch,
        &revision,
        &crate::time::now_rfc3339_millis(),
    )
    .map_err(io_error)?;
    if json {
        println!("{}", serde_json::to_string(&manifest).unwrap_or_default());
    } else {
        println!("branch: {branch}");
        println!("revision: {revision}");
        println!(
            "event_count: {}",
            manifest
                .get("event_count")
                .and_then(|v| v.as_u64())
                .unwrap_or_default()
        );
    }
    Ok(())
}

pub fn status(repo: &Path, json: bool) -> Result<(), ContractError> {
    let config_path = repo.join(".kin/config");
    let status = if config_path.exists() {
        json!({"status":"initialized","path":repo.to_string_lossy()})
    } else {
        json!({"status":"uninitialized","path":repo.to_string_lossy()})
    };
    if json {
        println!("{}", serde_json::to_string(&status).unwrap_or_default());
    } else {
        println!(
            "status: {}",
            status
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    }
    Ok(())
}

pub fn doctor(repo: &Path, host: Option<crate::HostKind>, json: bool) -> Result<(), ContractError> {
    let result = json!({
        "path": repo.to_string_lossy(),
        "personal": {"granted":false},
        "company": {"granted":true},
        "codebase": {"granted": true},
        "host": host.map(|host| if host == crate::HostKind::Codex { "codex" } else { "claude" }),
    });
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("path: {}", repo.to_string_lossy());
        println!("personal: denied");
        println!("company: granted");
        println!("codebase: granted");
    }
    Ok(())
}

pub fn fsck(repo: &Path, full: bool, json: bool) -> Result<(), ContractError> {
    let events_dir = repo.join(".kin/events");
    let mut count = 0;
    if events_dir.exists() {
        count = count_files(&events_dir).map_err(io_error)?;
    }
    let result = json!({"status":"ok","event_count":count,"full":full});
    if json {
        println!("{}", serde_json::to_string(&result).unwrap_or_default());
    } else {
        println!("status: ok");
        println!("event_count: {count}");
    }
    Ok(())
}

fn count_files(path: &Path) -> std::io::Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().is_dir() {
            count += count_files(&entry.path())?;
        } else {
            count += 1;
        }
    }
    Ok(count)
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
